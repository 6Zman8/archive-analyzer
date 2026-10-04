from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread

import pytest

from archive_analyzer.discovery import snapshot_file
from archive_analyzer.inspection import ArchiveEntry, InspectionFailure, InspectionResult
from archive_analyzer.domain import ArchiveFormat, DiscoveryError, EntryKind
from archive_analyzer.jobs import ScanAlreadyRunning, ScanSummary
from archive_analyzer.paths import normalize_path_key
from archive_analyzer.storage.repository import (
    JobClaimLost,
    Repository,
    RunNotActive,
    ScanLockLost,
)


FIXED_NOW = datetime(2026, 8, 26, 3, 0, tzinfo=UTC)
OWNER_TOKEN = "test-owner"


@pytest.fixture
def repository(tmp_path: Path) -> Repository:
    value = Repository.open(tmp_path / "index.db")
    try:
        yield value
    finally:
        value.close()


def _create_pending_job(repository: Repository, tmp_path: Path):
    archive_path = tmp_path / "book.zip"
    archive_path.write_bytes(b"archive")
    repository.acquire_scan_lock(OWNER_TOKEN, FIXED_NOW, lease_seconds=300)
    root_id = repository.get_or_create_root(
        tmp_path,
        normalize_path_key(tmp_path),
        owner_token=OWNER_TOKEN,
        now=FIXED_NOW,
    )
    run_id = repository.start_run(root_id, FIXED_NOW, owner_token=OWNER_TOKEN)
    assert (
        repository.enqueue_or_reuse(
            run_id,
            root_id,
            snapshot_file(archive_path),
            owner_token=OWNER_TOKEN,
            now=FIXED_NOW,
        )
        == "PENDING"
    )
    return run_id, next(repository.pending_jobs(run_id))


def _job_status(repository: Repository, job_id: int) -> tuple[str, int, str | None]:
    row = repository._connection.execute(  # noqa: SLF001 - inspect persisted state
        "SELECT status, attempts, last_error_code FROM analysis_jobs WHERE id = ?", (job_id,)
    ).fetchone()
    assert row is not None
    return str(row[0]), int(row[1]), row[2]


def test_live_scan_lock_cannot_be_stolen(repository: Repository) -> None:
    repository.acquire_scan_lock("first", FIXED_NOW, lease_seconds=30)

    with pytest.raises(ScanAlreadyRunning):
        repository.acquire_scan_lock("second", FIXED_NOW + timedelta(seconds=29))

    repository.heartbeat_scan_lock("first", FIXED_NOW + timedelta(seconds=20))
    with pytest.raises(ScanAlreadyRunning):
        repository.acquire_scan_lock("second", FIXED_NOW + timedelta(seconds=49))


def test_expired_scan_lock_can_be_replaced_but_old_owner_cannot_release_it(
    repository: Repository,
) -> None:
    repository.acquire_scan_lock("first", FIXED_NOW, lease_seconds=30)
    repository.acquire_scan_lock("second", FIXED_NOW + timedelta(seconds=30))

    repository.release_scan_lock("first")
    with pytest.raises(ScanAlreadyRunning):
        repository.acquire_scan_lock("third", FIXED_NOW + timedelta(seconds=31))

    repository.release_scan_lock("second")
    repository.acquire_scan_lock("third", FIXED_NOW + timedelta(seconds=31))


def test_stale_running_job_returns_to_pending(repository: Repository, tmp_path: Path) -> None:
    _, job = _create_pending_job(repository, tmp_path)
    claimed_job = repository.begin_job(
        job.id,
        FIXED_NOW,
        expected_scan_run_id=job.scan_run_id,
        owner_token=OWNER_TOKEN,
    )

    recovered = repository.recover_stale_jobs(
        now=FIXED_NOW + timedelta(minutes=1), owner_token=OWNER_TOKEN
    )

    assert recovered == 1
    assert _job_status(repository, claimed_job.id) == ("PENDING", 1, None)
    claim_token = repository._connection.execute(  # noqa: SLF001 - inspect persisted state
        "SELECT claim_token FROM analysis_jobs WHERE id = ?", (claimed_job.id,)
    ).fetchone()[0]
    assert claim_token is None


def test_replacing_archive_index_is_atomic_and_exposed_in_report(
    repository: Repository, tmp_path: Path
) -> None:
    run_id, job = _create_pending_job(repository, tmp_path)
    job = repository.begin_job(
        job.id,
        FIXED_NOW,
        expected_scan_run_id=job.scan_run_id,
        owner_token=OWNER_TOKEN,
    )
    result = InspectionResult(
        archive_format=ArchiveFormat.ZIP,
        entries=(
            ArchiveEntry(0, "1.jpg", "1.jpg", "1.jpg", 10, 8, "1234abcd", EntryKind.IMAGE, "JPEG"),
        ),
        image_count=1,
        nested_archive_count=0,
        listing_signature="listing-signature",
    )

    repository.replace_archive_index(job, result, FIXED_NOW + timedelta(seconds=1))
    summary = ScanSummary(run_id, 1, 0, 1, 0, 0, True)
    repository.finish_run(
        run_id,
        summary,
        FIXED_NOW + timedelta(seconds=2),
        owner_token=OWNER_TOKEN,
    )

    assert _job_status(repository, job.id) == ("SUCCEEDED", 1, None)
    assert repository.latest_summary() == summary
    row = next(repository.report_rows())
    assert row.path == job.snapshot.path
    assert row.archive_format is ArchiveFormat.ZIP
    assert row.state == "INDEXED"
    assert row.file_size == job.snapshot.size
    assert row.mtime_ns == job.snapshot.mtime_ns
    assert row.entry_count == 1
    assert row.image_count == 1
    assert row.error_code is None


def test_failed_job_records_latest_error_without_aborting_repository(
    repository: Repository, tmp_path: Path
) -> None:
    _, job = _create_pending_job(repository, tmp_path)
    job = repository.begin_job(
        job.id,
        FIXED_NOW,
        expected_scan_run_id=job.scan_run_id,
        owner_token=OWNER_TOKEN,
    )

    repository.fail_job(
        job,
        InspectionFailure("CORRUPT_ARCHIVE", "Archive is corrupt.", "bad header"),
        FIXED_NOW + timedelta(seconds=1),
    )

    assert _job_status(repository, job.id) == ("FAILED", 1, "CORRUPT_ARCHIVE")
    row = next(repository.report_rows())
    assert row.state == "FAILED"
    assert row.error_code == "CORRUPT_ARCHIVE"
    assert row.error_summary == "Archive is corrupt."


def test_entry_insert_failure_rolls_back_archive_and_job_mutations(
    repository: Repository, tmp_path: Path
) -> None:
    _, job = _create_pending_job(repository, tmp_path)
    claimed = repository.begin_job(
        job.id,
        FIXED_NOW,
        expected_scan_run_id=job.scan_run_id,
        owner_token=OWNER_TOKEN,
    )
    duplicate_position_entries = (
        ArchiveEntry(0, "1.jpg", "1.jpg", "1.jpg", 1, 1, "a", EntryKind.IMAGE, "JPEG"),
        ArchiveEntry(0, "2.jpg", "2.jpg", "2.jpg", 1, 1, "b", EntryKind.IMAGE, "JPEG"),
    )

    with pytest.raises(sqlite3.IntegrityError):
        repository.replace_archive_index(
            claimed,
            InspectionResult(
                ArchiveFormat.ZIP,
                duplicate_position_entries,
                2,
                0,
                "must-roll-back",
            ),
            FIXED_NOW + timedelta(seconds=1),
        )

    assert repository._connection.execute(  # noqa: SLF001
        "SELECT COUNT(*) FROM archive_entries WHERE archive_id = ?", (claimed.archive_id,)
    ).fetchone() == (0,)
    assert repository._connection.execute(  # noqa: SLF001
        "SELECT state, entry_count, content_listing_signature FROM archives WHERE id = ?",
        (claimed.archive_id,),
    ).fetchone() == ("PENDING", None, None)
    assert repository._connection.execute(  # noqa: SLF001
        "SELECT status, claim_token FROM analysis_jobs WHERE id = ?", (claimed.id,)
    ).fetchone() == ("RUNNING", claimed.claim_token)


def test_unchanged_indexed_archive_is_reused(repository: Repository, tmp_path: Path) -> None:
    first_run_id, job = _create_pending_job(repository, tmp_path)
    job = repository.begin_job(
        job.id,
        FIXED_NOW,
        expected_scan_run_id=job.scan_run_id,
        owner_token=OWNER_TOKEN,
    )
    repository.replace_archive_index(
        job,
        InspectionResult(ArchiveFormat.ZIP, (), 0, 0, "empty"),
        FIXED_NOW + timedelta(seconds=1),
    )
    repository.finish_run(
        first_run_id,
        ScanSummary(first_run_id, 1, 0, 1, 0, 0, True),
        FIXED_NOW + timedelta(seconds=2),
        owner_token=OWNER_TOKEN,
    )
    second_now = FIXED_NOW + timedelta(minutes=1)
    root_id = repository.get_or_create_root(
        tmp_path,
        normalize_path_key(tmp_path),
        owner_token=OWNER_TOKEN,
        now=second_now,
    )
    second_run_id = repository.start_run(
        root_id, second_now, owner_token=OWNER_TOKEN
    )

    disposition = repository.enqueue_or_reuse(
        second_run_id,
        root_id,
        snapshot_file(job.snapshot.path),
        owner_token=OWNER_TOKEN,
        now=second_now,
    )

    assert disposition == "REUSED"
    assert list(repository.pending_jobs(second_run_id)) == []


def test_expired_owner_cannot_commit_result_after_job_is_reclaimed(tmp_path: Path) -> None:
    db_path = tmp_path / "index.db"
    old_owner = Repository.open(db_path)
    new_owner = Repository.open(db_path)
    try:
        archive_path = tmp_path / "book.zip"
        archive_path.write_bytes(b"archive")
        old_owner.acquire_scan_lock("old-owner", FIXED_NOW, lease_seconds=30)
        root_id = old_owner.get_or_create_root(
            tmp_path,
            normalize_path_key(tmp_path),
            owner_token="old-owner",
            now=FIXED_NOW,
        )
        old_run_id = old_owner.start_run(
            root_id, FIXED_NOW, owner_token="old-owner"
        )
        old_owner.enqueue_or_reuse(
            old_run_id,
            root_id,
            snapshot_file(archive_path),
            owner_token="old-owner",
            now=FIXED_NOW,
        )
        old_job = old_owner.begin_job(
            next(old_owner.pending_jobs(old_run_id)).id,
            FIXED_NOW,
            expected_scan_run_id=old_run_id,
            owner_token="old-owner",
        )

        takeover_at = FIXED_NOW + timedelta(seconds=30)
        new_owner.acquire_scan_lock("new-owner", takeover_at, lease_seconds=30)

        with pytest.raises(JobClaimLost):
            old_owner.replace_archive_index(
                old_job,
                InspectionResult(ArchiveFormat.ZIP, (), 0, 0, "stale-before-recovery"),
                takeover_at,
            )
        with pytest.raises(JobClaimLost):
            old_owner.fail_job(
                old_job,
                InspectionFailure("CORRUPT_ARCHIVE", "Stale failure."),
                takeover_at,
            )
        assert new_owner._connection.execute(  # noqa: SLF001 - inspect persisted state
            "SELECT COUNT(*) FROM scan_errors"
        ).fetchone() == (0,)

        assert new_owner.recover_stale_jobs(takeover_at, owner_token="new-owner") == 1
        new_run_id = new_owner.start_run(
            root_id, takeover_at, owner_token="new-owner"
        )
        new_owner.enqueue_or_reuse(
            new_run_id,
            root_id,
            snapshot_file(archive_path),
            owner_token="new-owner",
            now=takeover_at,
        )

        with pytest.raises(JobClaimLost):
            old_owner.begin_job(
                old_job.id,
                takeover_at,
                expected_scan_run_id=old_run_id,
                owner_token="old-owner",
            )
        with pytest.raises(JobClaimLost):
            old_owner.begin_job(
                old_job.id,
                takeover_at,
                expected_scan_run_id=new_run_id,
                owner_token="old-owner",
            )

        new_job = new_owner.begin_job(
            next(new_owner.pending_jobs(new_run_id)).id,
            takeover_at,
            expected_scan_run_id=new_run_id,
            owner_token="new-owner",
        )

        with pytest.raises(JobClaimLost):
            old_owner.replace_archive_index(
                old_job,
                InspectionResult(ArchiveFormat.ZIP, (), 0, 0, "stale-result"),
                takeover_at + timedelta(seconds=1),
            )

        persisted = new_owner._connection.execute(  # noqa: SLF001 - inspect persisted state
            "SELECT scan_run_id, status, claim_token FROM analysis_jobs WHERE id = ?",
            (new_job.id,),
        ).fetchone()
        assert persisted == (new_run_id, "RUNNING", new_job.claim_token)
        assert next(new_owner.report_rows()).state == "PENDING"
    finally:
        old_owner.close()
        new_owner.close()


def test_new_owner_cannot_claim_pending_job_from_interrupted_run(
    tmp_path: Path,
) -> None:
    database = tmp_path / "index.db"
    archive = tmp_path / "book.zip"
    archive.write_bytes(b"archive")
    old_owner = Repository.open(database)
    new_owner = Repository.open(database)
    try:
        old_owner.acquire_scan_lock("old", FIXED_NOW, lease_seconds=30)
        root_id = old_owner.get_or_create_root(
            tmp_path,
            normalize_path_key(tmp_path),
            owner_token="old",
            now=FIXED_NOW,
        )
        run_id = old_owner.start_run(root_id, FIXED_NOW, owner_token="old")
        old_owner.enqueue_or_reuse(
            run_id,
            root_id,
            snapshot_file(archive),
            owner_token="old",
            now=FIXED_NOW,
        )
        job_id = next(old_owner.pending_jobs(run_id)).id
        takeover_at = FIXED_NOW + timedelta(seconds=30)
        new_owner.acquire_scan_lock("new", takeover_at, lease_seconds=30)
        assert new_owner.recover_stale_jobs(takeover_at, owner_token="new") == 0

        before_run = new_owner._connection.execute(  # noqa: SLF001
            "SELECT status, finished_at FROM scan_runs WHERE id = ?", (run_id,)
        ).fetchone()
        before_job = new_owner._connection.execute(  # noqa: SLF001
            "SELECT status, attempts, claim_token, claim_owner_token FROM analysis_jobs "
            "WHERE id = ?",
            (job_id,),
        ).fetchone()

        with pytest.raises(JobClaimLost):
            new_owner.begin_job(
                job_id,
                takeover_at,
                expected_scan_run_id=run_id,
                owner_token="new",
            )

        assert before_run == ("INTERRUPTED", takeover_at.isoformat())
        assert before_job == ("PENDING", 0, None, None)
        assert new_owner._connection.execute(  # noqa: SLF001
            "SELECT status, finished_at FROM scan_runs WHERE id = ?", (run_id,)
        ).fetchone() == before_run
        assert new_owner._connection.execute(  # noqa: SLF001
            "SELECT status, attempts, claim_token, claim_owner_token FROM analysis_jobs "
            "WHERE id = ?",
            (job_id,),
        ).fetchone() == before_job
    finally:
        old_owner.close()
        new_owner.close()


def test_recovery_finalizes_stale_run_from_terminal_jobs(
    repository: Repository, tmp_path: Path
) -> None:
    paths = [tmp_path / name for name in ("good.zip", "encrypted.zip", "bad.zip")]
    for path in paths:
        path.write_bytes(path.name.encode())
    repository.acquire_scan_lock(OWNER_TOKEN, FIXED_NOW, lease_seconds=300)
    root_id = repository.get_or_create_root(
        tmp_path,
        normalize_path_key(tmp_path),
        owner_token=OWNER_TOKEN,
        now=FIXED_NOW,
    )
    run_id = repository.start_run(root_id, FIXED_NOW, owner_token=OWNER_TOKEN)
    for path in paths:
        repository.enqueue_or_reuse(
            run_id,
            root_id,
            snapshot_file(path),
            owner_token=OWNER_TOKEN,
            now=FIXED_NOW,
        )
    jobs = list(repository.pending_jobs(run_id))
    good = repository.begin_job(
        jobs[0].id,
        FIXED_NOW,
        expected_scan_run_id=run_id,
        owner_token=OWNER_TOKEN,
    )
    encrypted = repository.begin_job(
        jobs[1].id,
        FIXED_NOW,
        expected_scan_run_id=run_id,
        owner_token=OWNER_TOKEN,
    )
    bad = repository.begin_job(
        jobs[2].id,
        FIXED_NOW,
        expected_scan_run_id=run_id,
        owner_token=OWNER_TOKEN,
    )
    repository.replace_archive_index(
        good,
        InspectionResult(ArchiveFormat.ZIP, (), 0, 0, "good"),
        FIXED_NOW + timedelta(seconds=1),
    )
    repository.fail_job(
        encrypted,
        InspectionFailure("ENCRYPTED_UNSUPPORTED", "Password required."),
        FIXED_NOW + timedelta(seconds=1),
    )
    repository.fail_job(
        bad,
        InspectionFailure("CORRUPT_ARCHIVE", "Archive is corrupt."),
        FIXED_NOW + timedelta(seconds=1),
    )

    assert (
        repository.recover_stale_jobs(
            FIXED_NOW + timedelta(minutes=1), owner_token=OWNER_TOKEN
        )
        == 0
    )

    row = repository._connection.execute(  # noqa: SLF001 - inspect persisted state
        "SELECT status, discovered_count, reused_count, indexed_count, skipped_count, "
        "failed_count, finished_at FROM scan_runs WHERE id = ?",
        (run_id,),
    ).fetchone()
    assert row[:6] == ("INTERRUPTED", 3, 0, 1, 1, 1)
    assert row[6] == (FIXED_NOW + timedelta(minutes=1)).isoformat()


def test_recovery_finalizes_stale_running_run_without_jobs(
    repository: Repository, tmp_path: Path
) -> None:
    repository.acquire_scan_lock(OWNER_TOKEN, FIXED_NOW, lease_seconds=300)
    root_id = repository.get_or_create_root(
        tmp_path,
        normalize_path_key(tmp_path),
        owner_token=OWNER_TOKEN,
        now=FIXED_NOW,
    )
    run_id = repository.start_run(root_id, FIXED_NOW, owner_token=OWNER_TOKEN)

    assert (
        repository.recover_stale_jobs(
            FIXED_NOW + timedelta(minutes=1), owner_token=OWNER_TOKEN
        )
        == 0
    )

    row = repository._connection.execute(  # noqa: SLF001 - inspect persisted state
        "SELECT status, discovered_count, reused_count, indexed_count, skipped_count, "
        "failed_count, finished_at FROM scan_runs WHERE id = ?",
        (run_id,),
    ).fetchone()
    assert row[:6] == ("INTERRUPTED", 0, 0, 0, 0, 0)
    assert row[6] == (FIXED_NOW + timedelta(minutes=1)).isoformat()


def test_stale_owner_cannot_overwrite_recovered_run_status(
    repository: Repository, tmp_path: Path
) -> None:
    repository.acquire_scan_lock(OWNER_TOKEN, FIXED_NOW, lease_seconds=300)
    root_id = repository.get_or_create_root(
        tmp_path,
        normalize_path_key(tmp_path),
        owner_token=OWNER_TOKEN,
        now=FIXED_NOW,
    )
    run_id = repository.start_run(root_id, FIXED_NOW, owner_token=OWNER_TOKEN)
    recovered_at = FIXED_NOW + timedelta(minutes=1)
    repository.recover_stale_jobs(recovered_at, owner_token=OWNER_TOKEN)

    with pytest.raises(RunNotActive):
        repository.finish_run(
            run_id,
            ScanSummary(run_id, 99, 0, 99, 0, 0, True),
            recovered_at + timedelta(seconds=1),
            owner_token=OWNER_TOKEN,
        )

    row = repository._connection.execute(  # noqa: SLF001 - inspect persisted state
        "SELECT status, indexed_count, finished_at FROM scan_runs WHERE id = ?", (run_id,)
    ).fetchone()
    assert row == ("INTERRUPTED", 0, recovered_at.isoformat())


def test_stale_owner_cannot_finish_run_after_lock_takeover_before_recovery(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "index.db"
    old_owner = Repository.open(db_path)
    new_owner = Repository.open(db_path)
    try:
        old_owner.acquire_scan_lock("old-owner", FIXED_NOW, lease_seconds=30)
        root_id = old_owner.get_or_create_root(
            tmp_path,
            normalize_path_key(tmp_path),
            owner_token="old-owner",
            now=FIXED_NOW,
        )
        run_id = old_owner.start_run(
            root_id, FIXED_NOW, owner_token="old-owner"
        )
        takeover_at = FIXED_NOW + timedelta(seconds=30)
        new_owner.acquire_scan_lock("new-owner", takeover_at, lease_seconds=30)

        with pytest.raises(ScanLockLost):
            old_owner.finish_run(
                run_id,
                ScanSummary(run_id, 1, 0, 1, 0, 0, True),
                takeover_at,
                owner_token="old-owner",
            )

        row = new_owner._connection.execute(  # noqa: SLF001 - inspect persisted state
            "SELECT status, indexed_count, finished_at FROM scan_runs WHERE id = ?",
            (run_id,),
        ).fetchone()
        assert row == ("RUNNING", 0, None)
    finally:
        old_owner.close()
        new_owner.close()


def test_expired_owner_cannot_revive_lease_with_heartbeat(repository: Repository) -> None:
    repository.acquire_scan_lock(OWNER_TOKEN, FIXED_NOW, lease_seconds=30)

    with pytest.raises(ScanLockLost):
        repository.heartbeat_scan_lock(
            OWNER_TOKEN, FIXED_NOW + timedelta(seconds=30)
        )

    row = repository._connection.execute(  # noqa: SLF001 - inspect persisted state
        "SELECT heartbeat_at FROM scan_locks WHERE owner_token = ?", (OWNER_TOKEN,)
    ).fetchone()
    assert row == (FIXED_NOW.isoformat(),)


def test_takeover_fences_every_stale_discovery_and_run_mutation(tmp_path: Path) -> None:
    db_path = tmp_path / "index.db"
    old_owner = Repository.open(db_path)
    new_owner = Repository.open(db_path)
    try:
        archive = tmp_path / "book.zip"
        archive.write_bytes(b"archive")
        old_owner.acquire_scan_lock("old", FIXED_NOW, lease_seconds=30)
        root_id = old_owner.get_or_create_root(
            tmp_path,
            normalize_path_key(tmp_path),
            owner_token="old",
            now=FIXED_NOW,
        )
        run_id = old_owner.start_run(root_id, FIXED_NOW, owner_token="old")
        old_owner.enqueue_or_reuse(
            run_id,
            root_id,
            snapshot_file(archive),
            owner_token="old",
            now=FIXED_NOW,
        )

        takeover_at = FIXED_NOW + timedelta(seconds=30)
        new_owner.acquire_scan_lock("new", takeover_at, lease_seconds=30)
        assert new_owner.recover_stale_jobs(takeover_at, owner_token="new") == 0

        with pytest.raises(ScanLockLost):
            old_owner.enqueue_or_reuse(
                run_id,
                root_id,
                snapshot_file(archive),
                owner_token="old",
                now=takeover_at,
            )
        with pytest.raises(ScanLockLost):
            old_owner.record_discovery_error(
                run_id,
                DiscoveryError(tmp_path, "ACCESS_DENIED", "denied"),
                takeover_at,
                owner_token="old",
            )
        with pytest.raises(ScanLockLost):
            old_owner.mark_unseen_archives_missing(
                run_id, root_id, owner_token="old", now=takeover_at
            )
        with pytest.raises(ScanLockLost):
            old_owner.get_or_create_root(
                tmp_path / "other",
                normalize_path_key(tmp_path / "other"),
                owner_token="old",
                now=takeover_at,
            )
        with pytest.raises(ScanLockLost):
            old_owner.start_run(root_id, takeover_at, owner_token="old")
        with pytest.raises(ScanLockLost):
            old_owner.recover_stale_jobs(takeover_at, owner_token="old")

        assert new_owner._connection.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM scan_errors"
        ).fetchone() == (0,)
        assert new_owner._connection.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM scan_runs"
        ).fetchone() == (1,)
    finally:
        old_owner.close()
        new_owner.close()


@pytest.mark.parametrize("mutation", ["result", "failure"])
def test_takeover_cannot_interleave_between_claim_validation_and_first_dml(
    tmp_path: Path, mutation: str
) -> None:
    db_path = tmp_path / "index.db"
    archive = tmp_path / "book.zip"
    archive.write_bytes(b"archive")
    old_owner = Repository.open(db_path)
    competitor_started = Event()
    competitor_finished = Event()
    competitor_errors: list[BaseException] = []
    competitor_thread: Thread | None = None
    try:
        old_owner.acquire_scan_lock("old", FIXED_NOW, lease_seconds=60)
        root_id = old_owner.get_or_create_root(
            tmp_path,
            normalize_path_key(tmp_path),
            owner_token="old",
            now=FIXED_NOW,
        )
        run_id = old_owner.start_run(root_id, FIXED_NOW, owner_token="old")
        old_owner.enqueue_or_reuse(
            run_id,
            root_id,
            snapshot_file(archive),
            owner_token="old",
            now=FIXED_NOW,
        )
        job = old_owner.begin_job(
            next(old_owner.pending_jobs(run_id)).id,
            FIXED_NOW,
            expected_scan_run_id=run_id,
            owner_token="old",
        )

        def compete() -> None:
            competitor = Repository.open(db_path)
            try:
                competitor_started.set()
                competitor.acquire_scan_lock(
                    "new", FIXED_NOW + timedelta(seconds=60), lease_seconds=60
                )
            except BaseException as error:
                competitor_errors.append(error)
            finally:
                competitor.close()
                competitor_finished.set()

        triggered = False

        def trace(statement: str) -> None:
            nonlocal competitor_thread, triggered
            if triggered or "SELECT 1 FROM analysis_jobs" not in statement:
                return
            triggered = True
            competitor_thread = Thread(target=compete)
            competitor_thread.start()
            assert competitor_started.wait(timeout=5)
            competitor_finished.wait(timeout=0.05)

        old_owner._connection.set_trace_callback(trace)  # noqa: SLF001
        finished_at = FIXED_NOW + timedelta(seconds=59)
        if mutation == "result":
            old_owner.replace_archive_index(
                job,
                InspectionResult(ArchiveFormat.ZIP, (), 0, 0, "owned-result"),
                finished_at,
            )
        else:
            old_owner.fail_job(
                job,
                InspectionFailure("CORRUPT_ARCHIVE", "owned failure"),
                finished_at,
            )
        old_owner._connection.set_trace_callback(None)  # noqa: SLF001

        assert triggered is True
        assert competitor_finished.wait(timeout=5)
        assert competitor_errors == []
        status = old_owner._connection.execute(  # noqa: SLF001
            "SELECT status FROM analysis_jobs WHERE id = ?", (job.id,)
        ).fetchone()
        assert status == (("SUCCEEDED",) if mutation == "result" else ("FAILED",))
    finally:
        old_owner._connection.set_trace_callback(None)  # noqa: SLF001
        if competitor_thread is not None:
            competitor_thread.join(timeout=5)
        old_owner.close()


def test_expired_result_and_finish_are_both_fenced_without_competitor(
    tmp_path: Path,
) -> None:
    repository = Repository.open(tmp_path / "index.db")
    try:
        archive = tmp_path / "book.zip"
        archive.write_bytes(b"archive")
        repository.acquire_scan_lock(OWNER_TOKEN, FIXED_NOW, lease_seconds=30)
        root_id = repository.get_or_create_root(
            tmp_path,
            normalize_path_key(tmp_path),
            owner_token=OWNER_TOKEN,
            now=FIXED_NOW,
        )
        run_id = repository.start_run(root_id, FIXED_NOW, owner_token=OWNER_TOKEN)
        repository.enqueue_or_reuse(
            run_id,
            root_id,
            snapshot_file(archive),
            owner_token=OWNER_TOKEN,
            now=FIXED_NOW,
        )
        job = repository.begin_job(
            next(repository.pending_jobs(run_id)).id,
            FIXED_NOW,
            expected_scan_run_id=run_id,
            owner_token=OWNER_TOKEN,
        )
        expired_at = FIXED_NOW + timedelta(seconds=30)

        with pytest.raises(JobClaimLost):
            repository.replace_archive_index(
                job,
                InspectionResult(ArchiveFormat.ZIP, (), 0, 0, "expired"),
                expired_at,
            )
        with pytest.raises(ScanLockLost):
            repository.finish_run(
                run_id,
                ScanSummary(run_id, 1, 0, 1, 0, 0, True),
                expired_at,
                owner_token=OWNER_TOKEN,
            )

        assert repository._connection.execute(  # noqa: SLF001
            "SELECT status FROM analysis_jobs WHERE id = ?", (job.id,)
        ).fetchone() == ("RUNNING",)
        assert repository._connection.execute(  # noqa: SLF001
            "SELECT status FROM scan_runs WHERE id = ?", (run_id,)
        ).fetchone() == ("RUNNING",)
    finally:
        repository.close()
