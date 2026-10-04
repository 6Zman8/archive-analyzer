from __future__ import annotations

import shutil
from io import BytesIO
from pathlib import Path
from threading import Event, Lock
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile

import pytest
from PIL import Image

from archive_analyzer.duplicate_jobs import AnalysisCancelled, DuplicateAnalysisService
from archive_analyzer.archive_hashing import sha256_archive
from archive_analyzer.inspection import DispatchingInspector, ZipBackend
from archive_analyzer.inspection.image_reader import ImageReadFailure, ZipImageReader
from archive_analyzer.inspection.sevenzip import SevenZipBackend
from archive_analyzer.jobs import ScanService
from archive_analyzer.matching import match_candidate
from archive_analyzer.paths import normalize_path_key
from archive_analyzer.storage.duplicate_repository import DuplicateRepository
from archive_analyzer.storage.repository import ScanAlreadyRunning
from tests.image_helpers import encoded_gradient, tree_fingerprint


def _png_noise(seed: int, size: tuple[int, int] = (80, 120)) -> bytes:
    image = Image.effect_noise(size, 24 + seed).convert("RGB")
    if seed % 2:
        image = image.transpose(Image.Transpose.ROTATE_90)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _write_zip(
    path: Path,
    pages: tuple[bytes, ...],
    *,
    compression: int = ZIP_DEFLATED,
    comment: bytes = b"",
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(path, "w", compression=compression) as archive:
        archive.comment = comment
        for index, payload in enumerate(pages, 1):
            archive.writestr(f"{index:03d}.png", payload)
    return path


class CountingReader:
    def __init__(self, delegate=None) -> None:  # type: ignore[no-untyped-def]
        self.delegate = delegate or ZipImageReader()
        self.calls = 0
        self._lock = Lock()

    def read(self, snapshot, entry, *, same_path_count=1):  # type: ignore[no-untyped-def]
        with self._lock:
            self.calls += 1
        return self.delegate.read(snapshot, entry, same_path_count=same_path_count)


def _indexed_repository(root: Path, database: Path) -> tuple[DuplicateRepository, int]:
    repository = DuplicateRepository.open(database)
    inspector = DispatchingInspector(
        ZipBackend(), SevenZipBackend(Path("missing-7z-for-zip-only-tests.exe"))
    )
    ScanService(repository, inspector, workers=2).run(root)
    root_id = repository.root_id_for_path_key(normalize_path_key(root))
    assert root_id is not None
    return repository, root_id


@pytest.mark.parametrize(
    ("relation", "expected_field"),
    (
        ("exact_archive", "exact_archive_groups"),
        ("exact_content", "exact_content_groups"),
        ("visual", "visual_variant_groups"),
        ("related", "related_groups"),
    ),
)
def test_end_to_end_finds_each_relation_and_preserves_sources(
    tmp_path: Path, relation: str, expected_field: str
) -> None:
    root = tmp_path / relation
    if relation == "exact_archive":
        first = _write_zip(root / "a.zip", (_png_noise(1), _png_noise(2), _png_noise(3)))
        shutil.copyfile(first, root / "b.zip")
    elif relation == "exact_content":
        pages = (_png_noise(11), _png_noise(12), _png_noise(13))
        _write_zip(root / "a.zip", pages, compression=ZIP_STORED)
        _write_zip(root / "b.zip", pages, compression=ZIP_DEFLATED, comment=b"different")
    elif relation == "visual":
        small = tuple(encoded_gradient("PNG", (160, 240)) for _ in range(3))
        large = tuple(encoded_gradient("JPEG", (320, 480), quality=82) for _ in range(3))
        _write_zip(root / "a.zip", small)
        _write_zip(root / "b.zip", large)
    else:
        shared_first = _png_noise(21)
        shared_last = _png_noise(22)
        _write_zip(
            root / "a.zip",
            (shared_first, _png_noise(31), _png_noise(32), shared_last),
        )
        _write_zip(
            root / "b.zip",
            (shared_first, _png_noise(41), _png_noise(42), shared_last),
        )
    before = tree_fingerprint(root)
    repository, root_id = _indexed_repository(root, tmp_path / f"{relation}.db")
    try:
        summary = DuplicateAnalysisService(repository, CountingReader()).run(root_id, Event())

        assert summary.completed
        assert getattr(summary, expected_field) == 1
        assert summary.candidate_group_count == 1
        assert summary.failed_archives == 0
    finally:
        repository.close()
    assert tree_fingerprint(root) == before


def test_second_run_reuses_all_unchanged_image_reads(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    first = _write_zip(root / "a.zip", tuple(_png_noise(index) for index in range(10)))
    shutil.copyfile(first, root / "b.zip")
    repository, root_id = _indexed_repository(root, tmp_path / "cache.db")
    try:
        first_reader = CountingReader()
        DuplicateAnalysisService(repository, first_reader).run(root_id, Event())
        second_reader = CountingReader()

        summary = DuplicateAnalysisService(repository, second_reader).run(root_id, Event())

        assert summary.completed
        assert first_reader.calls == 20
        assert second_reader.calls == 0
    finally:
        repository.close()


def test_partial_retryable_failure_is_isolated_and_retried_next_run(tmp_path: Path) -> None:
    root = tmp_path / "partial"
    bad = _write_zip(root / "bad.zip", (_png_noise(1),))
    shutil.copyfile(bad, root / "good.zip")
    repository, root_id = _indexed_repository(root, tmp_path / "partial.db")

    class MissingSevenZipForOneArchive(CountingReader):
        def read(self, snapshot, entry, *, same_path_count=1):  # type: ignore[no-untyped-def]
            if snapshot.path.name == "bad.zip":
                with self._lock:
                    self.calls += 1
                raise ImageReadFailure("SEVEN_ZIP_NOT_FOUND", "missing")
            return super().read(snapshot, entry, same_path_count=same_path_count)

    try:
        first = DuplicateAnalysisService(repository, MissingSevenZipForOneArchive()).run(
            root_id, Event()
        )
        second = DuplicateAnalysisService(repository, CountingReader()).run(root_id, Event())

        assert first.completed and first.failed_archives == 1
        assert first.exact_archive_groups == 1
        assert second.completed and second.failed_archives == 0
        assert repository._connection.execute(  # noqa: SLF001 - stable error evidence
            "SELECT COUNT(*) FROM duplicate_analysis_jobs "
            "WHERE last_error_code = 'SEVEN_ZIP_NOT_FOUND'"
        ).fetchone()[0] >= 2
    finally:
        repository.close()


def test_cancelled_run_is_interrupted_and_resumes(tmp_path: Path) -> None:
    root = tmp_path / "cancel"
    _write_zip(root / "a.zip", tuple(_png_noise(index) for index in range(8)))
    _write_zip(root / "b.zip", tuple(_png_noise(index) for index in range(8)))
    repository, root_id = _indexed_repository(root, tmp_path / "cancel.db")
    cancelled = Event()

    class CancellingReader(CountingReader):
        def read(self, snapshot, entry, *, same_path_count=1):  # type: ignore[no-untyped-def]
            payload = super().read(snapshot, entry, same_path_count=same_path_count)
            cancelled.set()
            return payload

    try:
        with pytest.raises(AnalysisCancelled):
            DuplicateAnalysisService(repository, CancellingReader()).run(root_id, cancelled)
        assert repository.latest_duplicate_run_status() == "INTERRUPTED"

        resumed = DuplicateAnalysisService(repository, CountingReader()).run(root_id, Event())

        assert resumed.completed
        assert repository.latest_duplicate_run_status() == "COMPLETED"
    finally:
        repository.close()


def test_unexpected_match_exception_cleans_job_and_lock_then_reuses_full_cache(
    tmp_path: Path,
) -> None:
    root = tmp_path / "exception-cleanup"
    first = _write_zip(root / "a.zip", tuple(_png_noise(index) for index in range(10)))
    shutil.copyfile(first, root / "b.zip")
    repository, root_id = _indexed_repository(root, tmp_path / "exception-cleanup.db")

    def failing_matcher(left, right, seed):  # type: ignore[no-untyped-def]
        raise RuntimeError("matcher exploded")

    try:
        with pytest.raises(RuntimeError, match="matcher exploded"):
            DuplicateAnalysisService(
                repository,
                CountingReader(),
                matcher=failing_matcher,
            ).run(root_id, Event())

        assert repository.latest_duplicate_run_status() == "FAILED"
        assert repository._connection.execute(  # noqa: SLF001 - cleanup evidence
            "SELECT COUNT(*) FROM duplicate_analysis_jobs WHERE status = 'RUNNING'"
        ).fetchone() == (0,)
        assert repository._connection.execute(  # noqa: SLF001 - lock cleanup evidence
            "SELECT COUNT(*) FROM scan_locks"
        ).fetchone() == (0,)

        second_reader = CountingReader()
        resumed = DuplicateAnalysisService(repository, second_reader).run(root_id, Event())

        assert resumed.completed
        assert second_reader.calls == 0
        assert repository._connection.execute(  # noqa: SLF001 - FULL cache evidence
            "SELECT COUNT(*) FROM image_fingerprints WHERE coverage = 'FULL'"
        ).fetchone() == (20,)
    finally:
        repository.close()


def test_scan_lock_blocks_duplicate_analysis(tmp_path: Path) -> None:
    root = tmp_path / "locked"
    _write_zip(root / "a.zip", (_png_noise(1),))
    repository, root_id = _indexed_repository(root, tmp_path / "locked.db")
    repository.acquire_operation_lock("scan", "scan-owner", DuplicateAnalysisService(repository, None)._now())  # noqa: SLF001
    try:
        with pytest.raises(ScanAlreadyRunning):
            DuplicateAnalysisService(repository, CountingReader()).run(root_id, Event())
    finally:
        repository.release_operation_lock("scan-owner")
        repository.close()


def test_source_change_during_reader_creates_no_candidate_relation(tmp_path: Path) -> None:
    root = tmp_path / "changed"
    first = _write_zip(root / "a.zip", (_png_noise(1), _png_noise(2)))
    shutil.copyfile(first, root / "b.zip")
    repository, root_id = _indexed_repository(root, tmp_path / "changed.db")

    class ChangingReader(CountingReader):
        changed = False

        def read(self, snapshot, entry, *, same_path_count=1):  # type: ignore[no-untyped-def]
            payload = super().read(snapshot, entry, same_path_count=same_path_count)
            if snapshot.path.name == "a.zip" and not self.changed:
                snapshot.path.write_bytes(snapshot.path.read_bytes() + b"changed")
                self.changed = True
            return payload

    try:
        summary = DuplicateAnalysisService(repository, ChangingReader()).run(root_id, Event())

        assert summary.completed and summary.failed_archives == 1
        assert summary.candidate_group_count == 0
        assert repository._connection.execute(  # noqa: SLF001 - no stale edge assertion
            "SELECT COUNT(*) FROM candidate_relations"
        ).fetchone() == (0,)
        assert repository._connection.execute(  # noqa: SLF001 - stable failure code assertion
            "SELECT COUNT(*) FROM duplicate_analysis_jobs "
            "WHERE last_error_code = 'CHANGED_DURING_ANALYSIS'"
        ).fetchone()[0] >= 1
    finally:
        repository.close()


def test_source_change_during_group_commit_is_compensated(tmp_path: Path) -> None:
    root = tmp_path / "group-race"
    first = _write_zip(root / "a.zip", (_png_noise(1), _png_noise(2), _png_noise(3)))
    shutil.copyfile(first, root / "b.zip")
    third = _write_zip(root / "c.zip", (_png_noise(11), _png_noise(12), _png_noise(13)))
    shutil.copyfile(third, root / "d.zip")
    repository, root_id = _indexed_repository(root, tmp_path / "group-race.db")
    replacement = 0
    changed_first = False
    changed_third = False

    def change_during_relation_insert(statement: str) -> None:
        nonlocal replacement, changed_first, changed_third
        if statement.startswith("DELETE FROM candidate_relations"):
            replacement += 1
        elif statement.startswith("INSERT INTO candidate_relations") and replacement == 1 and not changed_first:
            first.write_bytes(first.read_bytes() + b"changed during group commit")
            changed_first = True
        elif statement.startswith("INSERT INTO candidate_relations") and replacement == 2 and not changed_third:
            third.write_bytes(third.read_bytes() + b"changed during compensation commit")
            changed_third = True

    repository._connection.set_trace_callback(  # noqa: SLF001 - commit race fixture
        change_during_relation_insert
    )
    try:
        summary = DuplicateAnalysisService(repository, CountingReader()).run(root_id, Event())
        repository._connection.set_trace_callback(None)  # noqa: SLF001

        assert summary.completed and summary.failed_archives == 2
        assert summary.candidate_group_count == 0
        assert replacement >= 3
        assert repository._connection.execute(  # noqa: SLF001 - compensation evidence
            "SELECT COUNT(*) FROM candidate_relations"
        ).fetchone() == (0,)
    finally:
        repository._connection.set_trace_callback(None)  # noqa: SLF001
        repository.close()


def test_hash_read_failure_is_retried_and_recovers_next_run(tmp_path: Path) -> None:
    root = tmp_path / "hash-retry"
    first = _write_zip(root / "a.zip", (_png_noise(1), _png_noise(2)))
    shutil.copyfile(first, root / "b.zip")
    repository, root_id = _indexed_repository(root, tmp_path / "hash-retry.db")
    calls: dict[str, int] = {"a.zip": 0, "b.zip": 0}
    calls_lock = Lock()

    def flaky_hasher(value, cancel_event):  # type: ignore[no-untyped-def]
        with calls_lock:
            calls[value.path.name] += 1
            attempt = calls[value.path.name]
        if value.path.name == "a.zip" and attempt == 1:
            raise OSError("temporary read failure")
        return sha256_archive(value, cancel_event)

    try:
        first_summary = DuplicateAnalysisService(
            repository, CountingReader(), archive_hasher=flaky_hasher
        ).run(root_id, Event())
        second_summary = DuplicateAnalysisService(
            repository, CountingReader(), archive_hasher=flaky_hasher
        ).run(root_id, Event())

        assert first_summary.completed and first_summary.failed_archives == 1
        assert second_summary.completed and second_summary.failed_archives == 0
        assert calls == {"a.zip": 2, "b.zip": 1}
        assert repository._connection.execute(  # noqa: SLF001 - recovered cache evidence
            "SELECT hash_state, error_code FROM archive_fingerprints "
            "JOIN archives ON archives.id = archive_fingerprints.archive_id "
            "WHERE archives.path LIKE '%a.zip'"
        ).fetchone() == ("SUCCEEDED", None)
    finally:
        repository.close()


def test_slow_match_heartbeats_short_lease(tmp_path: Path) -> None:
    from datetime import UTC, datetime
    from threading import Thread
    from time import sleep

    root = tmp_path / "slow-match"
    first = _write_zip(root / "a.zip", (_png_noise(1), _png_noise(2), _png_noise(3)))
    shutil.copyfile(first, root / "b.zip")
    database = tmp_path / "slow-match.db"
    repository, root_id = _indexed_repository(root, database)
    repository.close()
    entered = Event()
    outcomes: list[BaseException | object] = []

    def slow_matcher(left, right, seed):  # type: ignore[no-untyped-def]
        entered.set()
        sleep(1.25)
        return match_candidate(left, right, seed)

    def run_service() -> None:
        worker_repository = DuplicateRepository.open(database)
        try:
            outcomes.append(
                DuplicateAnalysisService(
                    worker_repository,
                    CountingReader(),
                    matcher=slow_matcher,
                    lease_seconds=1,
                    heartbeat_interval_seconds=0.02,
                ).run(root_id, Event())
            )
        except BaseException as error:
            outcomes.append(error)
        finally:
            worker_repository.close()

    worker = Thread(target=run_service)
    worker.start()
    assert entered.wait(5)
    sleep(1.05)
    contender = DuplicateRepository.open(database)
    try:
        with pytest.raises(ScanAlreadyRunning):
            contender.acquire_operation_lock("scan", "contender", datetime.now(UTC))
    finally:
        contender.close()
    worker.join(5)
    assert not worker.is_alive()
    assert len(outcomes) == 1 and not isinstance(outcomes[0], BaseException)


def test_match_cancel_joins_cooperative_worker_before_releasing_lock(tmp_path: Path) -> None:
    from threading import Thread, enumerate as enumerate_threads
    from time import sleep

    root = tmp_path / "cancel-match"
    first = _write_zip(root / "a.zip", (_png_noise(1), _png_noise(2), _png_noise(3)))
    shutil.copyfile(first, root / "b.zip")
    database = tmp_path / "cancel-match.db"
    repository, root_id = _indexed_repository(root, database)
    repository.close()
    entered = Event()
    exited = Event()
    cancelled = Event()
    outcomes: list[BaseException | object] = []

    def blocking_matcher(left, right, seed, *, checkpoint=None):  # type: ignore[no-untyped-def]
        entered.set()
        try:
            while True:
                assert checkpoint is not None
                checkpoint()
                sleep(0.01)
        finally:
            exited.set()

    def run_service() -> None:
        worker_repository = DuplicateRepository.open(database)
        try:
            outcomes.append(
                DuplicateAnalysisService(
                    worker_repository,
                    CountingReader(),
                    matcher=blocking_matcher,
                    heartbeat_interval_seconds=0.01,
                ).run(root_id, cancelled)
            )
        except BaseException as error:
            outcomes.append(error)
        finally:
            worker_repository.close()

    worker = Thread(target=run_service)
    worker.start()
    assert entered.wait(5)
    cancelled.set()
    worker.join(5)

    assert not worker.is_alive()
    assert exited.is_set()
    assert len(outcomes) == 1 and isinstance(outcomes[0], AnalysisCancelled)
    assert not any(
        thread.name.startswith("archive-analyzer-match")
        for thread in enumerate_threads()
    )
    repository = DuplicateRepository.open(database)
    try:
        assert repository.latest_run_status() == "INTERRUPTED"
        assert repository._connection.execute(  # noqa: SLF001 - release-after-join evidence
            "SELECT COUNT(*) FROM scan_locks"
        ).fetchone() == (0,)
    finally:
        repository.close()


def test_group_snapshot_validation_heartbeats_short_lease(tmp_path: Path) -> None:
    from datetime import UTC, datetime
    from threading import Thread
    from time import sleep

    root = tmp_path / "slow-group"
    first = _write_zip(root / "a.zip", (_png_noise(1), _png_noise(2), _png_noise(3)))
    for name in ("b.zip", "c.zip", "d.zip"):
        shutil.copyfile(first, root / name)
    database = tmp_path / "slow-group.db"
    repository, root_id = _indexed_repository(root, database)
    repository.close()
    entered = Event()
    outcomes: list[BaseException | object] = []

    def run_service() -> None:
        worker_repository = DuplicateRepository.open(database)
        service = DuplicateAnalysisService(
            worker_repository,
            CountingReader(),
            lease_seconds=1,
            heartbeat_interval_seconds=0.02,
        )
        original = service._snapshot_is_current  # noqa: SLF001 - delayed stat fixture

        def delayed_snapshot(value):  # type: ignore[no-untyped-def]
            entered.set()
            sleep(0.35)
            return original(value)

        service._snapshot_is_current = delayed_snapshot  # type: ignore[method-assign]  # noqa: SLF001
        try:
            outcomes.append(service.run(root_id, Event()))
        except BaseException as error:
            outcomes.append(error)
        finally:
            worker_repository.close()

    worker = Thread(target=run_service)
    worker.start()
    assert entered.wait(10)
    sleep(1.05)
    contender = DuplicateRepository.open(database)
    try:
        with pytest.raises(ScanAlreadyRunning):
            contender.acquire_operation_lock("scan", "contender", datetime.now(UTC))
    finally:
        contender.close()
    worker.join(10)
    assert not worker.is_alive()
    assert len(outcomes) == 1 and not isinstance(outcomes[0], BaseException)


def test_service_uses_fenced_paths_for_every_analysis_write(tmp_path: Path) -> None:
    root = tmp_path / "fenced-service"
    first = _write_zip(root / "a.zip", tuple(_png_noise(index) for index in range(10)))
    shutil.copyfile(first, root / "b.zip")
    repository, root_id = _indexed_repository(root, tmp_path / "fenced-service.db")
    called: set[str] = set()

    def require_fence(name, original):  # type: ignore[no-untyped-def]
        def wrapped(*args, **kwargs):  # type: ignore[no-untyped-def]
            assert kwargs.get("owner_token")
            assert kwargs.get("now") is not None
            called.add(name)
            return original(*args, **kwargs)

        return wrapped

    for name in (
        "store_archive_fingerprint",
        "store_probe_fingerprints",
        "store_filename_evidence",
        "store_full_fingerprints",
        "replace_candidate_relations",
    ):
        setattr(repository, name, require_fence(name, getattr(repository, name)))
    try:
        summary = DuplicateAnalysisService(repository, CountingReader()).run(root_id, Event())

        assert summary.completed
        assert called == {
            "store_archive_fingerprint",
            "store_probe_fingerprints",
            "store_filename_evidence",
            "store_full_fingerprints",
            "replace_candidate_relations",
        }
    finally:
        repository.close()
