from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from threading import Barrier, Event, Lock, Timer, get_ident
from time import monotonic, sleep

import pytest

import archive_analyzer.jobs as jobs_module
from archive_analyzer.discovery import snapshot_file
from archive_analyzer.domain import ArchiveFormat, DiscoveryError, DiscoveryEvent
from archive_analyzer.inspection import InspectionFailure, InspectionResult
from archive_analyzer.jobs import ScanCancelled, ScanService
from archive_analyzer.storage.repository import JobClaimLost, Repository


class FakeInspector:
    def __init__(self) -> None:
        self.calls = 0

    def inspect(self, snapshot) -> InspectionResult:
        self.calls += 1
        return InspectionResult(snapshot.archive_format, (), 0, 0, f"signature-{self.calls}")


@pytest.fixture
def repository(tmp_path: Path) -> Repository:
    value = Repository.open(tmp_path / "index.db")
    try:
        yield value
    finally:
        value.close()


def _events(*paths: Path):
    return [DiscoveryEvent(snapshot=snapshot_file(path)) for path in paths]


def _run_statuses(repository: Repository) -> list[str]:
    return [
        str(row[0])
        for row in repository._connection.execute(  # noqa: SLF001 - inspect persisted state
            "SELECT status FROM scan_runs ORDER BY id"
        )
    ]


def test_unchanged_archive_reuses_cached_index(repository: Repository, tmp_path: Path) -> None:
    archive_path = tmp_path / "book.zip"
    archive_path.write_bytes(b"one")
    inspector = FakeInspector()
    discoverer = lambda root: _events(archive_path)
    service = ScanService(repository, inspector, discoverer=discoverer, workers=1)

    first = service.run(tmp_path)
    second = service.run(tmp_path)

    assert first.indexed_count == 1
    assert second.reused_count == 1
    assert inspector.calls == 1


def test_changed_file_is_reindexed(repository: Repository, tmp_path: Path) -> None:
    archive_path = tmp_path / "book.zip"
    archive_path.write_bytes(b"one")
    inspector = FakeInspector()
    service = ScanService(
        repository, inspector, discoverer=lambda root: _events(archive_path), workers=1
    )
    service.run(tmp_path)
    archive_path.write_bytes(b"two-two")

    summary = service.run(tmp_path)

    assert summary.indexed_count == 1
    assert inspector.calls == 2


def test_incomplete_discovery_does_not_mark_unseen_archive_missing(
    repository: Repository, tmp_path: Path
) -> None:
    archive_path = tmp_path / "book.zip"
    archive_path.write_bytes(b"one")
    ScanService(
        repository,
        FakeInspector(),
        discoverer=lambda root: _events(archive_path),
        workers=1,
    ).run(tmp_path)
    denied = DiscoveryEvent(
        error=DiscoveryError(tmp_path, "ACCESS_DENIED", "Cannot read directory.")
    )

    summary = ScanService(
        repository,
        FakeInspector(),
        discoverer=lambda root: [denied],
        workers=1,
    ).run(tmp_path)

    assert summary.discovery_complete is False
    assert next(repository.report_rows()).state == "INDEXED"


def test_complete_discovery_marks_unseen_archive_missing(
    repository: Repository, tmp_path: Path
) -> None:
    archive_path = tmp_path / "book.zip"
    archive_path.write_bytes(b"one")
    ScanService(
        repository,
        FakeInspector(),
        discoverer=lambda root: _events(archive_path),
        workers=1,
    ).run(tmp_path)

    summary = ScanService(
        repository, FakeInspector(), discoverer=lambda root: [], workers=1
    ).run(tmp_path)

    assert summary.discovery_complete is True
    assert next(repository.report_rows()).state == "MISSING"


def test_file_changed_during_inspection_discards_result(
    repository: Repository, tmp_path: Path
) -> None:
    archive_path = tmp_path / "book.zip"
    archive_path.write_bytes(b"one")

    class ChangingInspector:
        def inspect(self, snapshot) -> InspectionResult:
            archive_path.write_bytes(b"changed while inspecting")
            return InspectionResult(ArchiveFormat.ZIP, (), 0, 0, "must-not-be-stored")

    summary = ScanService(
        repository,
        ChangingInspector(),
        discoverer=lambda root: _events(archive_path),
        workers=1,
    ).run(tmp_path)

    row = next(repository.report_rows())
    assert summary.failed_count == 1
    assert row.state == "FAILED"
    assert row.entry_count is None
    assert row.error_code == "CHANGED_DURING_SCAN"


def test_file_changed_during_failed_inspection_prioritizes_changed_error(
    repository: Repository, tmp_path: Path
) -> None:
    archive_path = tmp_path / "book.zip"
    archive_path.write_bytes(b"one")

    class ChangingFailureInspector:
        def inspect(self, snapshot) -> InspectionResult:
            archive_path.write_bytes(b"changed while failing")
            raise InspectionFailure("CORRUPT_ARCHIVE", "Archive is corrupt.")

    summary = ScanService(
        repository,
        ChangingFailureInspector(),
        discoverer=lambda root: _events(archive_path),
        workers=1,
    ).run(tmp_path)

    assert summary.failed_count == 1
    assert next(repository.report_rows()).error_code == "CHANGED_DURING_SCAN"


def test_one_archive_failure_does_not_stop_other_jobs(
    repository: Repository, tmp_path: Path
) -> None:
    bad = tmp_path / "bad.zip"
    good = tmp_path / "good.zip"
    bad.write_bytes(b"bad")
    good.write_bytes(b"good")

    class MixedInspector:
        def inspect(self, snapshot) -> InspectionResult:
            if snapshot.path == bad:
                raise InspectionFailure("CORRUPT_ARCHIVE", "Archive is corrupt.")
            return InspectionResult(ArchiveFormat.ZIP, (), 0, 0, "good")

    summary = ScanService(
        repository,
        MixedInspector(),
        discoverer=lambda root: _events(bad, good),
        workers=2,
    ).run(tmp_path)

    assert summary.indexed_count == 1
    assert summary.failed_count == 1
    assert {row.state for row in repository.report_rows()} == {"FAILED", "INDEXED"}


def test_encrypted_archive_is_counted_as_skipped(
    repository: Repository, tmp_path: Path
) -> None:
    archive_path = tmp_path / "encrypted.zip"
    archive_path.write_bytes(b"encrypted")

    class EncryptedInspector:
        def inspect(self, snapshot) -> InspectionResult:
            raise InspectionFailure("ENCRYPTED_UNSUPPORTED", "Password required.")

    summary = ScanService(
        repository,
        EncryptedInspector(),
        discoverer=lambda root: _events(archive_path),
        workers=1,
    ).run(tmp_path)

    assert summary.skipped_count == 1
    assert summary.failed_count == 0
    assert next(repository.report_rows()).state == "SKIPPED"


def test_job_submission_is_bounded_by_worker_count(
    repository: Repository, tmp_path: Path
) -> None:
    paths = [tmp_path / f"{number}.zip" for number in range(10)]
    for path in paths:
        path.write_bytes(path.name.encode())
    one_completed = Event()
    state_lock = Lock()
    active = 0
    peak_active = 0
    overconsumed = False

    class BlockingInspector:
        def inspect(self, snapshot) -> InspectionResult:
            nonlocal active, peak_active
            with state_lock:
                active += 1
                peak_active = max(peak_active, active)
            one_completed.wait(timeout=0.1)
            one_completed.set()
            with state_lock:
                active -= 1
            return InspectionResult(snapshot.archive_format, (), 0, 0, snapshot.path.name)

    service = ScanService(
        repository,
        BlockingInspector(),
        discoverer=lambda root: _events(*paths),
        workers=2,
    )
    original_pending_jobs = repository.pending_jobs

    def guarded_pending_jobs(run_id):
        nonlocal overconsumed
        for position, job in enumerate(original_pending_jobs(run_id)):
            if position >= 2 and not one_completed.is_set():
                overconsumed = True
            yield job

    repository.pending_jobs = guarded_pending_jobs

    summary = service.run(tmp_path)

    assert summary.indexed_count == 10
    assert overconsumed is False
    assert peak_active == 2


def test_repository_writes_stay_on_owner_thread(repository: Repository, tmp_path: Path) -> None:
    paths = [tmp_path / f"{number}.zip" for number in range(4)]
    for path in paths:
        path.write_bytes(path.name.encode())
    owner_thread = get_ident()
    write_threads: list[int] = []
    for method_name in ("begin_job", "replace_archive_index", "fail_job"):
        original = getattr(repository, method_name)

        def recording_call(*args, _original=original, **kwargs):
            write_threads.append(get_ident())
            return _original(*args, **kwargs)

        setattr(repository, method_name, recording_call)

    ScanService(
        repository,
        FakeInspector(),
        discoverer=lambda root: _events(*paths),
        workers=2,
    ).run(tmp_path)

    assert write_threads
    assert set(write_threads) == {owner_thread}


def test_slow_discovery_heartbeats_lock_from_owner_thread(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner_thread = get_ident()
    heartbeat_threads: list[int] = []
    original_heartbeat = repository.heartbeat_scan_lock

    def recording_heartbeat(*args, **kwargs):
        heartbeat_threads.append(get_ident())
        return original_heartbeat(*args, **kwargs)

    def slow_discoverer(root):
        sleep(0.05)
        return
        yield  # pragma: no cover - makes this a deliberately empty generator

    repository.heartbeat_scan_lock = recording_heartbeat
    monkeypatch.setattr(jobs_module, "_HEARTBEAT_INTERVAL_SECONDS", 0.01, raising=False)

    ScanService(
        repository,
        FakeInspector(),
        discoverer=slow_discoverer,
        workers=1,
    ).run(tmp_path)

    assert len(heartbeat_threads) >= 2
    assert set(heartbeat_threads) == {owner_thread}


def test_cancel_during_discovery_does_not_wait_for_discovery_to_finish(
    repository: Repository, tmp_path: Path
) -> None:
    cancel_event = Event()
    release_discovery = Event()

    def blocked_discoverer(root):  # type: ignore[no-untyped-def]
        assert release_discovery.wait(5)
        return
        yield  # pragma: no cover - keeps this a generator

    timer = Timer(0.05, cancel_event.set)
    timer.start()
    started_at = monotonic()
    try:
        with pytest.raises(ScanCancelled):
            ScanService(
                repository,
                FakeInspector(),
                discoverer=blocked_discoverer,
                workers=1,
            ).run(tmp_path, cancel_event)
    finally:
        release_discovery.set()
        timer.join(1)

    assert monotonic() - started_at < 1
    assert _run_statuses(repository) == ["INTERRUPTED"]


def test_interrupt_drain_keeps_heartbeating_until_running_worker_finishes(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    interrupt_path = tmp_path / "interrupt.zip"
    slow_path = tmp_path / "slow.zip"
    interrupt_path.write_bytes(b"interrupt")
    slow_path.write_bytes(b"slow")
    slow_started = Event()
    interrupt_raised = Event()
    drain_heartbeats = 0
    original_heartbeat = repository.heartbeat_scan_lock

    def recording_heartbeat(*args, **kwargs):
        nonlocal drain_heartbeats
        if interrupt_raised.is_set():
            drain_heartbeats += 1
        return original_heartbeat(*args, **kwargs)

    class InterruptAndSlowInspector:
        def inspect(self, snapshot) -> InspectionResult:
            if snapshot.path == interrupt_path:
                assert slow_started.wait(timeout=5)
                interrupt_raised.set()
                raise KeyboardInterrupt
            slow_started.set()
            sleep(0.06)
            return InspectionResult(snapshot.archive_format, (), 0, 0, "slow")

    repository.heartbeat_scan_lock = recording_heartbeat
    monkeypatch.setattr(jobs_module, "_HEARTBEAT_INTERVAL_SECONDS", 0.01)

    with pytest.raises(KeyboardInterrupt):
        ScanService(
            repository,
            InterruptAndSlowInspector(),
            discoverer=lambda root: _events(interrupt_path, slow_path),
            workers=2,
        ).run(tmp_path)

    assert drain_heartbeats >= 2


def test_interrupt_drain_heartbeats_at_deadline_during_continuous_completions(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = [tmp_path / name for name in ("interrupt.zip", "one.zip", "two.zip", "three.zip")]
    for path in paths:
        path.write_bytes(path.name.encode())
    all_started = Barrier(4)
    interrupt_raised = Event()
    drain_heartbeats = 0
    original_heartbeat = repository.heartbeat_scan_lock
    delays = {"one.zip": 0.005, "two.zip": 0.01, "three.zip": 0.015}
    fake_clock = 0.0
    real_wait = jobs_module.wait

    def recording_heartbeat(*args, **kwargs):
        nonlocal drain_heartbeats
        if interrupt_raised.is_set():
            drain_heartbeats += 1
        return original_heartbeat(*args, **kwargs)

    def advancing_wait(futures, timeout, return_when):
        nonlocal fake_clock
        done, _ = real_wait(futures, timeout=timeout, return_when=return_when)
        if interrupt_raised.is_set():
            fake_clock += 0.03
        if len(done) > 1:
            done = {next(iter(done))}
        return done, set(futures) - done

    class StaggeredInspector:
        def inspect(self, snapshot) -> InspectionResult:
            all_started.wait(timeout=5)
            if snapshot.path.name == "interrupt.zip":
                interrupt_raised.set()
                raise KeyboardInterrupt
            sleep(delays[snapshot.path.name])
            return InspectionResult(snapshot.archive_format, (), 0, 0, snapshot.path.name)

    repository.heartbeat_scan_lock = recording_heartbeat
    monkeypatch.setattr(jobs_module, "_HEARTBEAT_INTERVAL_SECONDS", 0.05)
    monkeypatch.setattr(jobs_module, "monotonic", lambda: fake_clock, raising=False)
    monkeypatch.setattr(jobs_module, "wait", advancing_wait)

    with pytest.raises(KeyboardInterrupt):
        ScanService(
            repository,
            StaggeredInspector(),
            discoverer=lambda root: _events(*paths),
            workers=4,
        ).run(tmp_path)

    assert drain_heartbeats >= 3


def test_snapshot_outside_root_is_recorded_and_does_not_mark_missing(
    repository: Repository, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    inside = root / "inside.zip"
    outside = tmp_path / "outside.zip"
    inside.write_bytes(b"inside")
    outside.write_bytes(b"outside")
    ScanService(
        repository,
        FakeInspector(),
        discoverer=lambda scan_root: _events(inside),
        workers=1,
    ).run(root)

    summary = ScanService(
        repository,
        FakeInspector(),
        discoverer=lambda scan_root: _events(outside),
        workers=1,
    ).run(root)

    assert summary.discovery_complete is False
    assert summary.discovered_count == 0
    assert [row.path for row in repository.report_rows()] == [inside.absolute()]
    assert next(repository.report_rows()).state == "INDEXED"
    error = repository._connection.execute(  # noqa: SLF001 - inspect persisted state
        "SELECT error_code FROM scan_errors WHERE scan_run_id = ?", (summary.run_id,)
    ).fetchone()
    assert error == ("OUTSIDE_SCAN_ROOT",)


def test_snapshot_with_mismatched_path_key_is_recorded_as_incomplete(
    repository: Repository, tmp_path: Path
) -> None:
    archive_path = tmp_path / "book.zip"
    archive_path.write_bytes(b"book")
    mismatched = replace(snapshot_file(archive_path), path_key="not-the-real-key")

    summary = ScanService(
        repository,
        FakeInspector(),
        discoverer=lambda root: [DiscoveryEvent(snapshot=mismatched)],
        workers=1,
    ).run(tmp_path)

    assert summary.discovery_complete is False
    assert list(repository.report_rows()) == []
    error = repository._connection.execute(  # noqa: SLF001 - inspect persisted state
        "SELECT error_code FROM scan_errors WHERE scan_run_id = ?", (summary.run_id,)
    ).fetchone()
    assert error == ("PATH_KEY_MISMATCH",)


def test_keyboard_interrupt_marks_run_interrupted_and_next_run_reindexes(
    repository: Repository, tmp_path: Path
) -> None:
    archive_path = tmp_path / "book.zip"
    archive_path.write_bytes(b"one")

    class InterruptOnceInspector(FakeInspector):
        def inspect(self, snapshot) -> InspectionResult:
            self.calls += 1
            if self.calls == 1:
                raise KeyboardInterrupt
            return InspectionResult(snapshot.archive_format, (), 0, 0, "recovered")

    inspector = InterruptOnceInspector()
    service = ScanService(
        repository,
        inspector,
        discoverer=lambda root: _events(archive_path),
        workers=1,
    )

    with pytest.raises(KeyboardInterrupt):
        service.run(tmp_path)
    summary = service.run(tmp_path)

    assert _run_statuses(repository) == ["INTERRUPTED", "COMPLETED"]
    assert summary.indexed_count == 1
    assert inspector.calls == 2
    jobs = repository._connection.execute(  # noqa: SLF001 - inspect persisted state
        "SELECT status, attempts FROM analysis_jobs"
    ).fetchall()
    assert jobs == [("SUCCEEDED", 2)]


def test_worker_count_must_be_positive(repository: Repository) -> None:
    with pytest.raises(ValueError, match="workers"):
        ScanService(repository, FakeInspector(), workers=0)


def test_job_claim_loss_aborts_scan_instead_of_reporting_completion(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = tmp_path / "book.zip"
    archive_path.write_bytes(b"book")

    def lose_claim(*args: object, **kwargs: object) -> None:
        raise JobClaimLost("taken over")

    monkeypatch.setattr(repository, "replace_archive_index", lose_claim)

    with pytest.raises(JobClaimLost):
        ScanService(
            repository,
            FakeInspector(),
            discoverer=lambda root: _events(archive_path),
            workers=1,
        ).run(tmp_path)

    assert _run_statuses(repository) != ["COMPLETED"]
