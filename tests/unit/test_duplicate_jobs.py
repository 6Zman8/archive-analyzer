from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread, enumerate as enumerate_threads
from time import sleep
from zipfile import ZipFile

import pytest

from archive_analyzer.duplicate_domain import AnalysisStage, ArchiveAnalysisInput, ImageEntryRef
from archive_analyzer.duplicate_jobs import (
    AnalysisCancelled,
    DuplicateAnalysisService,
    DuplicateSummary,
)
from archive_analyzer.domain import ArchiveFormat
from archive_analyzer.fingerprinting import fingerprint_image
from archive_analyzer.inspection.image_reader import ZipImageReader
from archive_analyzer.storage.duplicate_repository import DuplicateRepository
from archive_analyzer.storage.repository import ScanAlreadyRunning, ScanLockLost
from tests.image_helpers import encoded_gradient


def test_duplicate_service_uses_two_workers_by_default(tmp_path) -> None:
    repository = DuplicateRepository.open(tmp_path / "index.db")
    try:
        service = DuplicateAnalysisService(repository, reader=None)
        assert service.workers == 2
    finally:
        repository.close()


def test_duplicate_service_rejects_non_positive_workers(tmp_path) -> None:
    repository = DuplicateRepository.open(tmp_path / "index.db")
    try:
        with pytest.raises(ValueError, match="workers must be positive"):
            DuplicateAnalysisService(repository, reader=None, workers=0)
    finally:
        repository.close()


def test_duplicate_summary_counts_candidate_groups() -> None:
    summary = DuplicateSummary(1, True, 1, 2, 3, 4, 0)
    assert summary.candidate_group_count == 10


def test_already_cancelled_empty_run_is_recorded_as_interrupted(tmp_path: Path) -> None:
    repository = DuplicateRepository.open(tmp_path / "index.db")
    now = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    connection = repository._connection  # noqa: SLF001 - V0 root fixture
    root_id = connection.execute(
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
        (str(tmp_path), "root", now.isoformat()),
    ).lastrowid
    connection.commit()
    cancelled = Event()
    cancelled.set()
    try:
        with pytest.raises(AnalysisCancelled):
            DuplicateAnalysisService(repository, None, clock=lambda: now).run(
                int(root_id), cancelled
            )

        assert repository.latest_duplicate_run_status() == "INTERRUPTED"
        assert connection.execute(
            "SELECT analyzer_version FROM duplicate_analysis_runs"
        ).fetchone() == (2,)
    finally:
        repository.close()


def test_expired_running_job_is_attached_and_resumed_after_process_restart(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "empty.zip"
    with ZipFile(archive, "w"):
        pass
    stat = archive.stat()
    database = tmp_path / "restart.db"
    first = DuplicateRepository.open(database)
    started = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    first.acquire_operation_lock("duplicate", "crashed-owner", started, lease_seconds=30)
    root_id = first._connection.execute(  # noqa: SLF001 - V0 index fixture
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
        (str(tmp_path), "root", started.isoformat()),
    ).lastrowid
    archive_id = first._connection.execute(  # noqa: SLF001 - V0 index fixture
        "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
        "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
        "VALUES (?, ?, ?, ?, ?, ?, 'INDEXED', ?, ?, 1)",
        (
            root_id,
            str(archive),
            "archive",
            stat.st_size,
            stat.st_mtime_ns,
            ArchiveFormat.ZIP.value,
            started.isoformat(),
            started.isoformat(),
        ),
    ).lastrowid
    first._connection.commit()  # noqa: SLF001
    old_run_id = first.begin_duplicate_run(
        int(root_id),
        analyzer_version=2,
        archive_total=1,
        image_total=0,
        started_at=started,
        owner_token="crashed-owner",
    )
    first.prepare_duplicate_jobs(
        old_run_id,
        AnalysisStage.ARCHIVE_HASH,
        ((str(archive_id), int(archive_id)),),
        now=started,
        owner_token="crashed-owner",
    )
    first.claim_duplicate_job(
        old_run_id,
        AnalysisStage.ARCHIVE_HASH,
        str(archive_id),
        now=started,
        owner_token="crashed-owner",
    )
    first.close()  # Simulate termination without releasing the lease or finishing the job.

    resumed_at = started + timedelta(seconds=31)
    second = DuplicateRepository.open(database)
    try:
        summary = DuplicateAnalysisService(
            second, ZipImageReader(), clock=lambda: resumed_at
        ).run(int(root_id), Event())

        assert summary.completed
        assert second._connection.execute(  # noqa: SLF001 - restart state evidence
            "SELECT status FROM duplicate_analysis_runs WHERE id = ?", (old_run_id,)
        ).fetchone() == ("INTERRUPTED",)
        assert second._connection.execute(  # noqa: SLF001 - reattached job evidence
            "SELECT analysis_run_id, status, attempts FROM duplicate_analysis_jobs"
        ).fetchone() == (summary.run_id, "SKIPPED", 2)
    finally:
        second.close()


def test_v0_takeover_atomically_interrupts_stale_duplicate_run_and_resets_jobs(
    tmp_path: Path,
) -> None:
    database = tmp_path / "v0-takeover.db"
    old = DuplicateRepository.open(database)
    started = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    old.acquire_operation_lock("duplicate", "old-duplicate", started, lease_seconds=1)
    root_id = old._connection.execute(  # noqa: SLF001 - crashed V1 fixture
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, 'root', ?)",
        (str(tmp_path), started.isoformat()),
    ).lastrowid
    old._connection.commit()  # noqa: SLF001
    run_id = old.begin_duplicate_run(
        int(root_id),
        analyzer_version=1,
        archive_total=0,
        image_total=0,
        started_at=started,
        owner_token="old-duplicate",
    )
    old.prepare_duplicate_jobs(
        run_id,
        AnalysisStage.MATCH,
        (("1:2", None),),
        now=started,
        owner_token="old-duplicate",
    )
    old.claim_duplicate_job(
        run_id,
        AnalysisStage.MATCH,
        "1:2",
        now=started,
        owner_token="old-duplicate",
    )
    old.close()

    takeover_at = started + timedelta(seconds=2)
    scan_owner = DuplicateRepository.open(database)
    observer = DuplicateRepository.open(database)
    try:
        scan_owner.acquire_operation_lock(
            "scan", "new-scan", takeover_at, lease_seconds=30
        )

        assert observer._connection.execute(  # noqa: SLF001 - committed atomic state
            "SELECT status, finished_at FROM duplicate_analysis_runs WHERE id = ?",
            (run_id,),
        ).fetchone() == ("INTERRUPTED", takeover_at.isoformat())
        assert observer._connection.execute(  # noqa: SLF001 - committed atomic state
            "SELECT status, started_at FROM duplicate_analysis_jobs WHERE analysis_run_id = ?",
            (run_id,),
        ).fetchone() == ("PENDING", None)
        with pytest.raises(ScanLockLost):
            old = DuplicateRepository.open(database)
            try:
                old.heartbeat_operation_lock("duplicate", "old-duplicate", takeover_at)
            finally:
                old.close()
    finally:
        scan_owner.release_operation_lock("new-scan")
        observer.close()
        scan_owner.close()


def test_full_cache_commit_race_restores_probe_rows(tmp_path: Path) -> None:
    archive = tmp_path / "source.zip"
    archive.write_bytes(b"stable source")
    stat = archive.stat()
    value = ArchiveAnalysisInput(
        archive_id=1,
        path=archive,
        file_size=stat.st_size,
        mtime_ns=stat.st_mtime_ns,
        archive_format=ArchiveFormat.ZIP,
        images=(ImageEntryRef(0, "001.png", None, None),),
    )
    repository = DuplicateRepository.open(tmp_path / "full-race.db")
    now = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    connection = repository._connection  # noqa: SLF001 - V0 fixture and race hook
    root_id = connection.execute(
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
        (str(tmp_path), "root", now.isoformat()),
    ).lastrowid
    connection.execute(
        "INSERT INTO archives(id, scan_root_id, path, path_key, file_size, mtime_ns, "
        "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
        "VALUES (1, ?, ?, 'source', ?, ?, 'ZIP', 'INDEXED', ?, ?, 1)",
        (
            root_id,
            str(archive),
            stat.st_size,
            stat.st_mtime_ns,
            now.isoformat(),
            now.isoformat(),
        ),
    )
    connection.commit()
    fingerprint = fingerprint_image(encoded_gradient("PNG", (10, 10)))
    assert repository.store_probe_fingerprints(
        value,
        analyzer_version=1,
        computed_at=now,
        sha256=None,
        hash_state="NOT_REQUIRED",
        successes=((0, fingerprint),),
        failures=(),
    )
    changed = False

    def change_after_commit(statement: str) -> None:
        nonlocal changed
        if statement == "COMMIT" and not changed:
            archive.write_bytes(b"changed after commit")
            changed = True

    connection.set_trace_callback(change_after_commit)
    try:
        assert not repository.store_full_fingerprints(
            value,
            analyzer_version=1,
            computed_at=now + timedelta(seconds=1),
            successes=((0, fingerprint),),
            failures=(),
        )
        connection.set_trace_callback(None)

        assert connection.execute(
            "SELECT coverage, computed_at FROM image_fingerprints"
        ).fetchone() == ("PROBE", now.isoformat())
    finally:
        connection.set_trace_callback(None)
        repository.close()


def test_expired_owner_cannot_write_cache_or_groups_after_reclaim(tmp_path: Path) -> None:
    database = tmp_path / "fenced.db"
    old = DuplicateRepository.open(database)
    started = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    archive = tmp_path / "source.zip"
    archive.write_bytes(b"source")
    stat = archive.stat()
    old._connection.execute(  # noqa: SLF001 - V0 root fixture
        "INSERT INTO scan_roots(id, path, path_key, created_at) VALUES (1, ?, 'root', ?)",
        (str(tmp_path), started.isoformat()),
    )
    old._connection.execute(  # noqa: SLF001 - V0 archive fixture
        "INSERT INTO archives(id, scan_root_id, path, path_key, file_size, mtime_ns, "
        "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
        "VALUES (1, 1, ?, 'source', ?, ?, 'ZIP', 'INDEXED', ?, ?, 1)",
        (str(archive), stat.st_size, stat.st_mtime_ns, started.isoformat(), started.isoformat()),
    )
    old._connection.commit()  # noqa: SLF001
    value = ArchiveAnalysisInput(
        1,
        archive,
        stat.st_size,
        stat.st_mtime_ns,
        ArchiveFormat.ZIP,
        (),
    )
    old.acquire_operation_lock("duplicate", "old-owner", started, lease_seconds=1)
    old.begin_duplicate_run(
        1,
        analyzer_version=1,
        archive_total=1,
        image_total=0,
        started_at=started,
        owner_token="old-owner",
    )
    reclaimed_at = started + timedelta(seconds=2)
    new = DuplicateRepository.open(database)
    try:
        new.acquire_operation_lock(
            "duplicate", "new-owner", reclaimed_at, lease_seconds=30
        )
        new.begin_duplicate_run(
            1,
            analyzer_version=1,
            archive_total=1,
            image_total=0,
            started_at=reclaimed_at,
            owner_token="new-owner",
        )

        with pytest.raises(ScanLockLost):
            old.store_archive_fingerprint(
                value,
                analyzer_version=1,
                computed_at=reclaimed_at,
                sha256="a" * 64,
                hash_state="SUCCEEDED",
                owner_token="old-owner",
                now=reclaimed_at,
            )
        with pytest.raises(ScanLockLost):
            old.replace_candidate_relations(
                1,
                analyzer_version=1,
                matches=(),
                created_at=reclaimed_at,
                owner_token="old-owner",
                now=reclaimed_at,
            )

        assert new._connection.execute(  # noqa: SLF001 - fenced-write evidence
            "SELECT COUNT(*) FROM archive_fingerprints"
        ).fetchone() == (0,)
        assert new._connection.execute(  # noqa: SLF001 - fenced-group evidence
            "SELECT COUNT(*) FROM candidate_groups"
        ).fetchone() == (0,)
    finally:
        new.release_operation_lock("new-owner")
        new.close()
        old.close()


def test_slow_candidate_build_heartbeats_short_lease(tmp_path: Path) -> None:
    database = tmp_path / "slow-candidate.db"
    repository = DuplicateRepository.open(database)
    now = datetime.now(UTC)
    root_id = repository._connection.execute(  # noqa: SLF001 - empty root fixture
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, 'root', ?)",
        (str(tmp_path), now.isoformat()),
    ).lastrowid
    repository._connection.commit()  # noqa: SLF001
    repository.close()
    started = Event()
    outcome: list[BaseException | object] = []

    def slow_builder(evidence):  # type: ignore[no-untyped-def]
        from archive_analyzer.candidate_index import build_candidate_index

        started.set()
        sleep(1.25)
        return build_candidate_index(evidence)

    def run_service() -> None:
        worker_repository = DuplicateRepository.open(database)
        try:
            outcome.append(
                DuplicateAnalysisService(
                    worker_repository,
                    None,
                    candidate_builder=slow_builder,
                    lease_seconds=1,
                    heartbeat_interval_seconds=0.02,
                ).run(int(root_id), Event())
            )
        except BaseException as error:
            outcome.append(error)
        finally:
            worker_repository.close()

    worker = Thread(target=run_service)
    worker.start()
    assert started.wait(5)
    sleep(1.05)
    contender = DuplicateRepository.open(database)
    try:
        with pytest.raises(ScanAlreadyRunning):
            contender.acquire_operation_lock("scan", "contender", datetime.now(UTC))
    finally:
        contender.close()
    worker.join(5)
    assert not worker.is_alive()
    assert len(outcome) == 1 and not isinstance(outcome[0], BaseException)


def test_archive_hash_skip_loop_heartbeats_short_lease(tmp_path: Path) -> None:
    database = tmp_path / "slow-hash-skip.db"
    repository = DuplicateRepository.open(database)
    now = datetime.now(UTC)
    root_id = repository._connection.execute(  # noqa: SLF001 - V0 index fixture
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, 'root', ?)",
        (str(tmp_path), now.isoformat()),
    ).lastrowid
    archives = []
    for index in range(1, 4):
        archive = tmp_path / f"archive-{index}.zip"
        archive.write_bytes(b"x" * index)
        stat = archive.stat()
        archives.append(
            (
                root_id,
                str(archive),
                archive.name,
                stat.st_size,
                stat.st_mtime_ns,
                now.isoformat(),
                now.isoformat(),
            )
        )
    repository._connection.executemany(  # noqa: SLF001 - V0 index fixture
        "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
        "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
        "VALUES (?, ?, ?, ?, ?, 'ZIP', 'INDEXED', ?, ?, 1)",
        archives,
    )
    repository._connection.commit()  # noqa: SLF001
    original_finish = repository.finish_duplicate_job

    def slow_hash_skip(job_id, **kwargs):  # type: ignore[no-untyped-def]
        original_finish(job_id, **kwargs)
        if kwargs["status"] == "SKIPPED":
            sleep(0.55)

    repository.finish_duplicate_job = slow_hash_skip  # type: ignore[method-assign]
    try:
        summary = DuplicateAnalysisService(
            repository,
            ZipImageReader(),
            lease_seconds=1,
            heartbeat_interval_seconds=0.02,
        ).run(int(root_id), Event())

        assert summary.completed
    finally:
        repository.close()


@pytest.mark.parametrize("delayed_stage", ("input", "evidence"))
def test_slow_owner_side_load_heartbeats_short_lease(
    tmp_path: Path, delayed_stage: str
) -> None:
    database = tmp_path / f"slow-{delayed_stage}.db"
    repository = DuplicateRepository.open(database)
    now = datetime.now(UTC)
    root_id = repository._connection.execute(  # noqa: SLF001 - empty root fixture
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, 'root', ?)",
        (str(tmp_path), now.isoformat()),
    ).lastrowid
    repository._connection.commit()  # noqa: SLF001
    repository.close()
    entered = Event()
    outcome: list[BaseException | object] = []

    def run_service() -> None:
        worker_repository = DuplicateRepository.open(database)
        if delayed_stage == "input":
            original = worker_repository.iter_analysis_input_batches

            def delayed_inputs(*args, checkpoint=None, **kwargs):  # type: ignore[no-untyped-def]
                entered.set()
                for _ in range(7):
                    sleep(0.2)
                    assert checkpoint is not None
                    checkpoint()
                yield from original(*args, checkpoint=checkpoint, **kwargs)

            worker_repository.iter_analysis_input_batches = delayed_inputs  # type: ignore[method-assign]
        else:
            original = worker_repository.load_candidate_evidence

            def delayed_evidence(*args, checkpoint=None, **kwargs):  # type: ignore[no-untyped-def]
                entered.set()
                for _ in range(7):
                    sleep(0.2)
                    assert checkpoint is not None
                    checkpoint()
                return original(*args, checkpoint=checkpoint, **kwargs)

            worker_repository.load_candidate_evidence = delayed_evidence  # type: ignore[method-assign]
        try:
            outcome.append(
                DuplicateAnalysisService(
                    worker_repository,
                    None,
                    lease_seconds=1,
                    heartbeat_interval_seconds=0.02,
                ).run(int(root_id), Event())
            )
        except BaseException as error:
            outcome.append(error)
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
    assert len(outcome) == 1 and not isinstance(outcome[0], BaseException)


def test_duplicate_run_started_at_is_sampled_after_initial_counts(tmp_path: Path) -> None:
    repository = DuplicateRepository.open(tmp_path / "fresh-start.db")
    initial = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    current = [initial]
    root_id = repository._connection.execute(  # noqa: SLF001 - empty root fixture
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, 'root', ?)",
        (str(tmp_path), initial.isoformat()),
    ).lastrowid
    repository._connection.commit()  # noqa: SLF001
    original_counts = repository.analysis_input_counts

    def advancing_counts(root_id):  # type: ignore[no-untyped-def]
        result = original_counts(root_id)
        current[0] = initial + timedelta(seconds=5)
        return result

    repository.analysis_input_counts = advancing_counts  # type: ignore[method-assign]
    try:
        DuplicateAnalysisService(repository, None, clock=lambda: current[0]).run(
            int(root_id), Event()
        )

        assert repository._connection.execute(  # noqa: SLF001 - timestamp regression evidence
            "SELECT started_at FROM duplicate_analysis_runs ORDER BY id DESC LIMIT 1"
        ).fetchone() == ((initial + timedelta(seconds=5)).isoformat(),)
    finally:
        repository.close()


def test_candidate_cancel_joins_cooperative_worker_before_releasing_lock(
    tmp_path: Path,
) -> None:
    database = tmp_path / "candidate-cancel.db"
    repository = DuplicateRepository.open(database)
    now = datetime.now(UTC)
    root_id = repository._connection.execute(  # noqa: SLF001 - empty root fixture
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, 'root', ?)",
        (str(tmp_path), now.isoformat()),
    ).lastrowid
    repository._connection.commit()  # noqa: SLF001
    repository.close()
    entered = Event()
    cancelled = Event()
    exited = Event()
    outcomes: list[BaseException | object] = []

    def blocking_builder(evidence, *, checkpoint=None):  # type: ignore[no-untyped-def]
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
                    None,
                    candidate_builder=blocking_builder,
                    heartbeat_interval_seconds=0.01,
                ).run(int(root_id), cancelled)
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
        thread.name.startswith("archive-analyzer-candidates")
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


def test_scan_lock_lost_reacquires_only_for_failed_run_cleanup(tmp_path: Path) -> None:
    database = tmp_path / "lost-lock.db"
    repository = DuplicateRepository.open(database)
    now = datetime.now(UTC)
    first = tmp_path / "a.zip"
    second = tmp_path / "b.zip"
    first.write_bytes(b"a")
    second.write_bytes(b"b")
    root_id = repository._connection.execute(  # noqa: SLF001 - empty root fixture
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, 'root', ?)",
        (str(tmp_path), now.isoformat()),
    ).lastrowid
    repository._connection.executemany(  # noqa: SLF001 - V0 archive fixtures
        "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
        "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
        "VALUES (?, ?, ?, ?, ?, 'ZIP', 'INDEXED', ?, ?, 1)",
        (
            (
                root_id,
                str(path),
                path.name,
                path.stat().st_size,
                path.stat().st_mtime_ns,
                now.isoformat(),
                now.isoformat(),
            )
            for path in (first, second)
        ),
    )
    repository._connection.commit()  # noqa: SLF001
    repository.close()
    entered = Event()
    release = Event()
    errors: list[BaseException] = []

    def blocking_hasher(value, cancel_event):  # type: ignore[no-untyped-def]
        entered.set()
        release.wait(5)
        return "a" * 64

    def run_service() -> None:
        worker_repository = DuplicateRepository.open(database)
        try:
            DuplicateAnalysisService(
                worker_repository,
                None,
                workers=1,
                archive_hasher=blocking_hasher,
                heartbeat_interval_seconds=0.01,
            ).run(int(root_id), Event())
        except BaseException as error:
            errors.append(error)
        finally:
            worker_repository.close()

    worker = Thread(target=run_service)
    worker.start()
    assert entered.wait(5)
    saboteur = DuplicateRepository.open(database)
    saboteur._connection.execute("DELETE FROM scan_locks")  # noqa: SLF001
    saboteur._connection.commit()  # noqa: SLF001
    saboteur.close()
    worker.join(1)
    release.set()
    worker.join(5)
    assert not worker.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], ScanLockLost)
    repository = DuplicateRepository.open(database)
    try:
        assert repository.latest_run_status() == "FAILED"
        assert repository._connection.execute(  # noqa: SLF001 - job cleanup evidence
            "SELECT COUNT(*) FROM duplicate_analysis_jobs WHERE status = 'RUNNING'"
        ).fetchone() == (0,)
        assert repository._connection.execute(  # noqa: SLF001 - lock cleanup evidence
            "SELECT COUNT(*) FROM scan_locks"
        ).fetchone() == (0,)
    finally:
        repository.close()
