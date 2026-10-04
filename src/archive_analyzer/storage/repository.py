from __future__ import annotations

import os
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Iterator, Literal
from uuid import uuid4

from archive_analyzer.domain import ArchiveFormat, DiscoveryError, FileSnapshot
from archive_analyzer.inspection import InspectionFailure, InspectionResult

if TYPE_CHECKING:
    from archive_analyzer.jobs import ScanSummary


_SCAN_LOCK_KEY = "scan"
LATEST_SCHEMA_VERSION = 9
_SKIPPED_ERROR_CODES = {"ENCRYPTED_UNSUPPORTED", "NESTED_ARCHIVE_SKIPPED"}


class ScanAlreadyRunning(RuntimeError):
    pass


class ScanLockLost(RuntimeError):
    pass


class JobClaimLost(RuntimeError):
    pass


class RunNotActive(RuntimeError):
    pass


class UnsafeDatabaseIdentity(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class PendingJob:
    id: int
    scan_run_id: int
    archive_id: int
    snapshot: FileSnapshot
    claim_token: str | None = None
    owner_token: str | None = None


@dataclass(frozen=True, slots=True)
class ArchiveReportRow:
    path: Path
    archive_format: ArchiveFormat
    state: str
    file_size: int
    mtime_ns: int
    entry_count: int | None
    image_count: int | None
    error_code: str | None
    error_summary: str | None


@dataclass(frozen=True, slots=True)
class ScanProgress:
    run_id: int
    status: str
    total_count: int
    pending_count: int
    running_count: int
    succeeded_count: int
    skipped_count: int
    failed_count: int

    @property
    def processed_count(self) -> int:
        return self.succeeded_count + self.skipped_count + self.failed_count


class Repository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    @classmethod
    def open(cls, db_path: Path) -> Repository:
        validate_sqlite_lexical_identities(db_path)
        database_path = db_path.resolve(strict=False)
        validate_sqlite_lexical_identities(database_path)
        connection = sqlite3.connect(database_path)
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA busy_timeout = 5000")
            repository = cls(connection)
            repository._apply_migrations()
            return repository
        except Exception:
            connection.close()
            raise

    @classmethod
    def open_readonly(cls, db_path: Path) -> Repository:
        validate_sqlite_lexical_identities(db_path)
        database_path = db_path.resolve(strict=False)
        database_uri = f"{database_path.as_uri()}?mode=ro"
        validate_sqlite_lexical_identities(database_path)
        connection = sqlite3.connect(database_uri, uri=True)
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")
            repository = cls(connection)
            if repository.schema_version() != LATEST_SCHEMA_VERSION:
                raise sqlite3.DatabaseError("Unsupported Archive Analyzer database schema.")
            return repository
        except Exception:
            connection.close()
            raise

    def close(self) -> None:
        self._connection.close()

    def get_or_create_root(
        self,
        path: Path,
        path_key: str,
        *,
        owner_token: str,
        now: datetime,
    ) -> int:
        timestamp = now.isoformat()
        with self._owned_write_transaction(owner_token, now):
            self._connection.execute(
                "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?) "
                "ON CONFLICT(path_key) DO UPDATE SET path = excluded.path",
                (str(path.absolute()), path_key, timestamp),
            )
            row = self._connection.execute(
                "SELECT id FROM scan_roots WHERE path_key = ?", (path_key,)
            ).fetchone()
        assert row is not None
        return int(row[0])

    def start_run(
        self, root_id: int, started_at: datetime, *, owner_token: str
    ) -> int:
        with self._owned_write_transaction(owner_token, started_at):
            if self._connection.execute(
                "SELECT 1 FROM scan_roots WHERE id = ?", (root_id,)
            ).fetchone() is None:
                raise ValueError(f"Unknown scan root {root_id}.")
            cursor = self._connection.execute(
                "INSERT INTO scan_runs(scan_root_id, status, started_at) "
                "VALUES (?, 'RUNNING', ?)",
                (root_id, started_at.isoformat()),
            )
        return int(cursor.lastrowid)

    def acquire_scan_lock(
        self, owner_token: str, now: datetime, lease_seconds: int = 30
    ) -> None:
        self.acquire_operation_lock(
            _SCAN_LOCK_KEY, owner_token, now, lease_seconds=lease_seconds
        )

    def acquire_operation_lock(
        self, kind: str, owner_token: str, now: datetime, lease_seconds: int = 30
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            rows = self._connection.execute(
                "SELECT owner_token, heartbeat_at, lease_seconds FROM scan_locks "
                "WHERE owner_token != ?",
                (owner_token,),
            ).fetchall()
            for row in rows:
                heartbeat = datetime.fromisoformat(str(row[1]))
                expires_at = heartbeat.timestamp() + int(row[2])
                if now.timestamp() < expires_at:
                    raise ScanAlreadyRunning("An archive scan is already running.")
            if rows:
                tables = {
                    str(row[0])
                    for row in self._connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table' "
                        "AND name IN ('duplicate_analysis_runs','duplicate_analysis_jobs')"
                    )
                }
                if {
                    "duplicate_analysis_runs",
                    "duplicate_analysis_jobs",
                }.issubset(tables):
                    self._connection.execute(
                        "UPDATE duplicate_analysis_jobs SET status = 'PENDING', "
                        "started_at = NULL, finished_at = NULL "
                        "WHERE status = 'RUNNING' AND analysis_run_id IN ("
                        "SELECT id FROM duplicate_analysis_runs WHERE status = 'RUNNING')"
                    )
                    self._connection.execute(
                        "UPDATE duplicate_analysis_runs SET status = 'INTERRUPTED', "
                        "finished_at = ? WHERE status = 'RUNNING'",
                        (now.isoformat(),),
                    )
                self._connection.execute("DELETE FROM scan_locks")
            self._connection.execute(
                "INSERT INTO scan_locks(db_key, owner_token, heartbeat_at, lease_seconds) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(db_key) DO UPDATE SET owner_token = excluded.owner_token, "
                "heartbeat_at = excluded.heartbeat_at, lease_seconds = excluded.lease_seconds",
                (kind, owner_token, now.isoformat(), lease_seconds),
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def heartbeat_scan_lock(self, owner_token: str, now: datetime) -> None:
        self.heartbeat_operation_lock(_SCAN_LOCK_KEY, owner_token, now)

    def heartbeat_operation_lock(
        self, kind: str, owner_token: str, now: datetime
    ) -> None:
        with self._owned_write_transaction(owner_token, now):
            cursor = self._connection.execute(
                "UPDATE scan_locks SET heartbeat_at = ? "
                "WHERE db_key = ? AND owner_token = ?",
                (now.isoformat(), kind, owner_token),
            )
            if cursor.rowcount != 1:
                raise ScanLockLost("The archive operation lock is no longer owned by this process.")

    def release_scan_lock(self, owner_token: str) -> None:
        self.release_operation_lock(owner_token)

    def release_operation_lock(self, owner_token: str) -> None:
        with self._connection:
            self._connection.execute(
                "DELETE FROM scan_locks WHERE owner_token = ?",
                (owner_token,),
            )

    def recover_stale_jobs(self, now: datetime, *, owner_token: str) -> int:
        with self._owned_write_transaction(owner_token, now):
            self._connection.execute(
                "UPDATE scan_runs AS runs SET status = 'INTERRUPTED', finished_at = ?, "
                "discovered_count = (SELECT COUNT(*) FROM analysis_jobs AS jobs "
                " WHERE jobs.scan_run_id = runs.id), "
                "reused_count = (SELECT COUNT(*) FROM analysis_jobs AS jobs "
                " WHERE jobs.scan_run_id = runs.id AND jobs.status = 'SKIPPED' "
                " AND jobs.last_error_code IS NULL), "
                "indexed_count = (SELECT COUNT(*) FROM analysis_jobs AS jobs "
                " WHERE jobs.scan_run_id = runs.id AND jobs.status = 'SUCCEEDED'), "
                "skipped_count = (SELECT COUNT(*) FROM analysis_jobs AS jobs "
                " WHERE jobs.scan_run_id = runs.id AND jobs.status = 'SKIPPED' "
                " AND jobs.last_error_code IS NOT NULL), "
                "failed_count = (SELECT COUNT(*) FROM analysis_jobs AS jobs "
                " WHERE jobs.scan_run_id = runs.id AND jobs.status = 'FAILED') "
                "WHERE runs.status = 'RUNNING'",
                (now.isoformat(),),
            )
            cursor = self._connection.execute(
                "UPDATE analysis_jobs SET status = 'PENDING', claim_token = NULL, "
                "claim_owner_token = NULL, started_at = NULL, finished_at = NULL "
                "WHERE status = 'RUNNING'"
            )
        return int(cursor.rowcount)

    def enqueue_or_reuse(
        self,
        run_id: int,
        root_id: int,
        snapshot: FileSnapshot,
        *,
        owner_token: str,
        now: datetime,
    ) -> Literal["PENDING", "REUSED"]:
        timestamp = now.isoformat()
        with self._owned_write_transaction(
            owner_token, now, run_id=run_id, root_id=root_id
        ):
            row = self._connection.execute(
                "SELECT id, file_size, mtime_ns, inspector_version, state "
                "FROM archives WHERE scan_root_id = ? AND path_key = ?",
                (root_id, snapshot.path_key),
            ).fetchone()
            if row is None:
                cursor = self._connection.execute(
                    "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
                    "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, 1)",
                    (
                        root_id,
                        str(snapshot.path),
                        snapshot.path_key,
                        snapshot.size,
                        snapshot.mtime_ns,
                        snapshot.archive_format.value,
                        timestamp,
                        timestamp,
                    ),
                )
                archive_id = int(cursor.lastrowid)
                reusable = False
            else:
                archive_id = int(row[0])
                reusable = (
                    int(row[1]) == snapshot.size
                    and int(row[2]) == snapshot.mtime_ns
                    and int(row[3]) == 1
                    and str(row[4]) == "INDEXED"
                )
                if reusable:
                    self._connection.execute(
                        "UPDATE archives SET path = ?, last_seen_at = ? WHERE id = ?",
                        (str(snapshot.path), timestamp, archive_id),
                    )
                else:
                    self._connection.execute(
                        "UPDATE archives SET path = ?, file_size = ?, mtime_ns = ?, "
                        "archive_format = ?, state = 'PENDING', last_seen_at = ?, "
                        "entry_count = NULL, image_count = NULL, "
                        "content_listing_signature = NULL, indexed_at = NULL "
                        "WHERE id = ?",
                        (
                            str(snapshot.path),
                            snapshot.size,
                            snapshot.mtime_ns,
                            snapshot.archive_format.value,
                            timestamp,
                            archive_id,
                        ),
                    )
                    self._connection.execute(
                        "DELETE FROM archive_entries WHERE archive_id = ?", (archive_id,)
                    )
            job_status = "SKIPPED" if reusable else "PENDING"
            resumable = None
            if not reusable:
                resumable = self._connection.execute(
                    "SELECT id FROM analysis_jobs WHERE archive_id = ? "
                    "AND stage = 'QUICK_INDEX' AND status = 'PENDING' "
                    "ORDER BY id LIMIT 1",
                    (archive_id,),
                ).fetchone()
            if resumable is not None:
                self._connection.execute(
                    "UPDATE analysis_jobs SET scan_run_id = ?, created_at = ?, "
                    "claim_token = NULL, claim_owner_token = NULL, started_at = NULL, "
                    "finished_at = NULL, last_error_code = NULL "
                    "WHERE id = ?",
                    (run_id, timestamp, int(resumable[0])),
                )
            else:
                self._connection.execute(
                    "INSERT INTO analysis_jobs(scan_run_id, archive_id, stage, status, "
                    "created_at, started_at, finished_at) "
                    "VALUES (?, ?, 'QUICK_INDEX', ?, ?, ?, ?)",
                    (
                        run_id,
                        archive_id,
                        job_status,
                        timestamp,
                        timestamp if reusable else None,
                        timestamp if reusable else None,
                    ),
                )
        return "REUSED" if reusable else "PENDING"

    def pending_jobs(self, run_id: int) -> Iterator[PendingJob]:
        last_id = 0
        while True:
            row = self._connection.execute(
                "SELECT jobs.id, jobs.scan_run_id, archives.id, archives.path, "
                "archives.path_key, archives.file_size, archives.mtime_ns, "
                "archives.archive_format, jobs.claim_token, jobs.claim_owner_token "
                "FROM analysis_jobs AS jobs "
                "JOIN archives ON archives.id = jobs.archive_id "
                "WHERE jobs.scan_run_id = ? AND jobs.status = 'PENDING' AND jobs.id > ? "
                "ORDER BY jobs.id LIMIT 1",
                (run_id, last_id),
            ).fetchone()
            if row is None:
                return
            last_id = int(row[0])
            yield PendingJob(
                id=last_id,
                scan_run_id=int(row[1]),
                archive_id=int(row[2]),
                snapshot=FileSnapshot(
                    path=Path(str(row[3])),
                    path_key=str(row[4]),
                    size=int(row[5]),
                    mtime_ns=int(row[6]),
                    archive_format=ArchiveFormat(str(row[7])),
                ),
                claim_token=None if row[8] is None else str(row[8]),
                owner_token=None if row[9] is None else str(row[9]),
            )

    def begin_job(
        self,
        job_id: int,
        started_at: datetime,
        *,
        expected_scan_run_id: int,
        owner_token: str,
    ) -> PendingJob:
        claim_token = uuid4().hex
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._require_live_scan_lock(owner_token, started_at)
                self._require_active_run(expected_scan_run_id)
            except (RunNotActive, ScanLockLost) as error:
                raise JobClaimLost(
                    f"Job {job_id} cannot be claimed outside its active scan run."
                ) from error
            cursor = self._connection.execute(
                "UPDATE analysis_jobs SET status = 'RUNNING', attempts = attempts + 1, "
                "claim_token = ?, claim_owner_token = ?, started_at = ?, finished_at = NULL "
                "WHERE id = ? AND scan_run_id = ? AND status = 'PENDING'",
                (
                    claim_token,
                    owner_token,
                    started_at.isoformat(),
                    job_id,
                    expected_scan_run_id,
                ),
            )
            if cursor.rowcount != 1:
                raise JobClaimLost(
                    f"Job {job_id} is not pending in run {expected_scan_run_id}."
                )
            row = self._connection.execute(
                "SELECT jobs.id, jobs.scan_run_id, archives.id, archives.path, "
                "archives.path_key, archives.file_size, archives.mtime_ns, "
                "archives.archive_format, jobs.claim_token, jobs.claim_owner_token "
                "FROM analysis_jobs AS jobs "
                "JOIN archives ON archives.id = jobs.archive_id WHERE jobs.id = ?",
                (job_id,),
            ).fetchone()
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise
        assert row is not None
        return PendingJob(
            id=int(row[0]),
            scan_run_id=int(row[1]),
            archive_id=int(row[2]),
            snapshot=FileSnapshot(
                path=Path(str(row[3])),
                path_key=str(row[4]),
                size=int(row[5]),
                mtime_ns=int(row[6]),
                archive_format=ArchiveFormat(str(row[7])),
            ),
            claim_token=str(row[8]),
            owner_token=None if row[9] is None else str(row[9]),
        )

    def replace_archive_index(
        self, job: PendingJob, result: InspectionResult, finished_at: datetime
    ) -> None:
        finished = finished_at.isoformat()
        if job.owner_token is None:
            raise JobClaimLost(f"Job {job.id} has no scan owner.")
        try:
            with self._owned_write_transaction(
                job.owner_token, finished_at, run_id=job.scan_run_id
            ):
                self._require_active_claim(job, finished_at)
                self._connection.execute(
                    "DELETE FROM archive_entries WHERE archive_id = ?", (job.archive_id,)
                )
                self._connection.executemany(
                    "INSERT INTO archive_entries(archive_id, position, path, normalized_path, "
                    "sort_key, uncompressed_size, compressed_size, crc, entry_kind, "
                    "image_format_hint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        (
                            job.archive_id,
                            entry.position,
                            entry.path,
                            entry.normalized_path,
                            entry.sort_key,
                            entry.uncompressed_size,
                            entry.compressed_size,
                            entry.crc,
                            entry.kind.value,
                            entry.image_format_hint,
                        )
                        for entry in result.entries
                    ),
                )
                self._connection.execute(
                    "UPDATE archives SET archive_format = ?, entry_count = ?, image_count = ?, "
                    "content_listing_signature = ?, state = 'INDEXED', indexed_at = ?, "
                    "inspector_version = 1 WHERE id = ?",
                    (
                        result.archive_format.value,
                        len(result.entries),
                        result.image_count,
                        result.listing_signature,
                        finished,
                        job.archive_id,
                    ),
                )
                cursor = self._connection.execute(
                    "UPDATE analysis_jobs SET status = 'SUCCEEDED', finished_at = ?, "
                    "claim_token = NULL, claim_owner_token = NULL, last_error_code = NULL "
                    "WHERE id = ? AND scan_run_id = ? AND claim_token = ? "
                    "AND claim_owner_token IS ? AND status = 'RUNNING'",
                    (
                        finished,
                        job.id,
                        job.scan_run_id,
                        job.claim_token,
                        job.owner_token,
                    ),
                )
                if cursor.rowcount != 1:
                    raise JobClaimLost(f"Job {job.id} is no longer owned by this scan.")
        except ScanLockLost as error:
            raise JobClaimLost(f"Job {job.id} scan lock ownership was lost.") from error

    def fail_job(
        self, job: PendingJob, failure: InspectionFailure, finished_at: datetime
    ) -> None:
        finished = finished_at.isoformat()
        job_status = "SKIPPED" if failure.code in _SKIPPED_ERROR_CODES else "FAILED"
        archive_state = "SKIPPED" if job_status == "SKIPPED" else "FAILED"
        if job.owner_token is None:
            raise JobClaimLost(f"Job {job.id} has no scan owner.")
        try:
            with self._owned_write_transaction(
                job.owner_token, finished_at, run_id=job.scan_run_id
            ):
                self._require_active_claim(job, finished_at)
                cursor = self._connection.execute(
                    "UPDATE analysis_jobs SET status = ?, claim_token = NULL, "
                    "claim_owner_token = NULL, last_error_code = ?, finished_at = ? "
                    "WHERE id = ? AND scan_run_id = ? AND claim_token = ? "
                    "AND claim_owner_token IS ? AND status = 'RUNNING'",
                    (
                        job_status,
                        failure.code,
                        finished,
                        job.id,
                        job.scan_run_id,
                        job.claim_token,
                        job.owner_token,
                    ),
                )
                if cursor.rowcount != 1:
                    raise JobClaimLost(f"Job {job.id} is no longer owned by this scan.")
                self._connection.execute(
                    "UPDATE archives SET state = ? WHERE id = ?",
                    (archive_state, job.archive_id),
                )
                self._connection.execute(
                    "INSERT INTO scan_errors(scan_run_id, archive_id, error_code, summary, "
                    "detail, occurred_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        job.scan_run_id,
                        job.archive_id,
                        failure.code,
                        failure.summary,
                        failure.detail,
                        finished,
                    ),
                )
        except ScanLockLost as error:
            raise JobClaimLost(f"Job {job.id} scan lock ownership was lost.") from error

    def _require_active_claim(self, job: PendingJob, now: datetime) -> None:
        if job.claim_token is None:
            raise JobClaimLost(f"Job {job.id} has no active claim.")
        row = self._connection.execute(
            "SELECT 1 FROM analysis_jobs WHERE id = ? AND scan_run_id = ? "
            "AND claim_token = ? AND claim_owner_token IS ? AND status = 'RUNNING'",
            (job.id, job.scan_run_id, job.claim_token, job.owner_token),
        ).fetchone()
        if row is None:
            raise JobClaimLost(f"Job {job.id} is no longer owned by this scan.")
        if job.owner_token is not None:
            try:
                self._require_live_scan_lock(job.owner_token, now)
            except ScanLockLost as error:
                raise JobClaimLost(
                    f"Job {job.id} scan lock ownership was lost."
                ) from error

    @contextmanager
    def _owned_write_transaction(
        self,
        owner_token: str,
        now: datetime,
        *,
        run_id: int | None = None,
        root_id: int | None = None,
    ):
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._require_live_scan_lock(owner_token, now)
            if run_id is not None:
                self._require_active_run(run_id, root_id=root_id)
            yield
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def _require_active_run(self, run_id: int, *, root_id: int | None = None) -> None:
        row = self._connection.execute(
            "SELECT scan_root_id, status FROM scan_runs WHERE id = ?", (run_id,)
        ).fetchone()
        if row is None or str(row[1]) != "RUNNING":
            raise RunNotActive(f"Run {run_id} is not active.")
        if root_id is not None and int(row[0]) != root_id:
            raise RunNotActive(f"Run {run_id} does not belong to root {root_id}.")

    def _require_live_scan_lock(self, owner_token: str, now: datetime) -> None:
        lock_row = self._connection.execute(
            "SELECT owner_token, heartbeat_at, lease_seconds FROM scan_locks "
            "WHERE owner_token = ?",
            (owner_token,),
        ).fetchone()
        if lock_row is None or str(lock_row[0]) != owner_token:
            raise ScanLockLost("The archive operation lock is no longer owned by this process.")
        heartbeat = datetime.fromisoformat(str(lock_row[1]))
        if now.timestamp() >= heartbeat.timestamp() + int(lock_row[2]):
            raise ScanLockLost("The archive scan lock lease expired.")

    def record_discovery_error(
        self,
        run_id: int,
        error: DiscoveryError,
        occurred_at: datetime,
        *,
        owner_token: str,
    ) -> None:
        with self._owned_write_transaction(
            owner_token, occurred_at, run_id=run_id
        ):
            self._connection.execute(
                "INSERT INTO scan_errors(scan_run_id, archive_id, entry_path, error_code, "
                "summary, detail, occurred_at) VALUES (?, NULL, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    str(error.path),
                    error.code,
                    error.summary,
                    error.detail,
                    occurred_at.isoformat(),
                ),
            )

    def mark_unseen_archives_missing(
        self,
        run_id: int,
        root_id: int,
        *,
        owner_token: str,
        now: datetime,
    ) -> int:
        with self._owned_write_transaction(
            owner_token, now, run_id=run_id, root_id=root_id
        ):
            cursor = self._connection.execute(
                "UPDATE archives SET state = 'MISSING' WHERE scan_root_id = ? "
                "AND NOT EXISTS (SELECT 1 FROM analysis_jobs WHERE scan_run_id = ? "
                "AND analysis_jobs.archive_id = archives.id)",
                (root_id, run_id),
            )
        return int(cursor.rowcount)

    def finish_run(
        self,
        run_id: int,
        summary: ScanSummary,
        finished_at: datetime,
        *,
        owner_token: str,
        status: str = "COMPLETED",
    ) -> None:
        with self._owned_write_transaction(
            owner_token, finished_at, run_id=run_id
        ):
            cursor = self._connection.execute(
                "UPDATE scan_runs SET status = ?, finished_at = ?, discovery_complete = ?, "
                "discovered_count = ?, reused_count = ?, indexed_count = ?, "
                "skipped_count = ?, failed_count = ? "
                "WHERE id = ? AND status = 'RUNNING'",
                (
                    status,
                    finished_at.isoformat(),
                    int(summary.discovery_complete),
                    summary.discovered_count,
                    summary.reused_count,
                    summary.indexed_count,
                    summary.skipped_count,
                    summary.failed_count,
                    run_id,
                ),
            )
            if cursor.rowcount != 1:
                raise RunNotActive(f"Run {run_id} is not active.")
            self._connection.execute(
                "UPDATE scan_roots SET last_scan_at = ? "
                "WHERE id = (SELECT scan_root_id FROM scan_runs WHERE id = ?)",
                (finished_at.isoformat(), run_id),
            )

    def latest_summary(self) -> ScanSummary | None:
        from archive_analyzer.jobs import ScanSummary

        row = self._connection.execute(
            "SELECT id, discovered_count, reused_count, indexed_count, skipped_count, "
            "failed_count, discovery_complete FROM scan_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        return ScanSummary(
            run_id=int(row[0]),
            discovered_count=int(row[1]),
            reused_count=int(row[2]),
            indexed_count=int(row[3]),
            skipped_count=int(row[4]),
            failed_count=int(row[5]),
            discovery_complete=bool(row[6]),
        )

    def latest_progress(self) -> ScanProgress | None:
        row = self._connection.execute(
            "SELECT id, status FROM scan_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        run_id = int(row[0])
        counts = {
            str(status): int(count)
            for status, count in self._connection.execute(
                "SELECT status, COUNT(*) FROM analysis_jobs "
                "WHERE scan_run_id = ? GROUP BY status",
                (run_id,),
            )
        }
        return ScanProgress(
            run_id=run_id,
            status=str(row[1]),
            total_count=sum(counts.values()),
            pending_count=counts.get("PENDING", 0),
            running_count=counts.get("RUNNING", 0),
            succeeded_count=counts.get("SUCCEEDED", 0),
            skipped_count=counts.get("SKIPPED", 0),
            failed_count=counts.get("FAILED", 0),
        )

    def scan_roots(self) -> Iterator[Path]:
        rows = self._connection.execute("SELECT path FROM scan_roots ORDER BY path_key")
        for row in rows:
            yield Path(str(row[0]))

    def report_rows(self) -> Iterator[ArchiveReportRow]:
        rows = self._connection.execute(
            "SELECT archives.path, archives.archive_format, archives.state, "
            "archives.file_size, archives.mtime_ns, archives.entry_count, "
            "archives.image_count, "
            "(SELECT error_code FROM scan_errors WHERE archive_id = archives.id "
            " ORDER BY id DESC LIMIT 1), "
            "(SELECT summary FROM scan_errors WHERE archive_id = archives.id "
            " ORDER BY id DESC LIMIT 1) "
            "FROM archives ORDER BY archives.path_key"
        )
        for row in rows:
            yield ArchiveReportRow(
                path=Path(str(row[0])),
                archive_format=ArchiveFormat(str(row[1])),
                state=str(row[2]),
                file_size=int(row[3]),
                mtime_ns=int(row[4]),
                entry_count=None if row[5] is None else int(row[5]),
                image_count=None if row[6] is None else int(row[6]),
                error_code=None if row[7] is None else str(row[7]),
                error_summary=None if row[8] is None else str(row[8]),
            )

    def schema_version(self) -> int:
        exists = self._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
        ).fetchone()
        if exists is None:
            return 0
        version = self._connection.execute(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
        ).fetchone()
        return int(version[0])

    def table_names(self) -> set[str]:
        rows = self._connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
        return {str(row[0]) for row in rows}

    def _apply_migrations(self) -> None:
        migrations_dir = Path(__file__).with_name("migrations")
        for migration_path in sorted(migrations_dir.glob("*.sql")):
            version = int(migration_path.stem)
            if version <= self.schema_version():
                continue
            sql = migration_path.read_text(encoding="utf-8")
            applied_at = datetime.now(UTC).isoformat()
            try:
                self._connection.executescript(
                    "BEGIN;\n"
                    f"{sql}\n"
                    "INSERT INTO schema_migrations (version, applied_at) "
                    f"VALUES ({version}, '{applied_at}');\n"
                    "COMMIT;"
                )
            except Exception:
                self._connection.rollback()
                raise


def validate_sqlite_lexical_identities(database_path: Path) -> None:
    candidates = (database_path,) + tuple(
        database_path.parent / f"{database_path.name}{suffix}"
        for suffix in ("-wal", "-shm", "-journal")
    )
    for candidate in candidates:
        try:
            identity = os.lstat(candidate)
        except FileNotFoundError:
            continue
        attributes = getattr(identity, "st_file_attributes", 0)
        is_reparse_point = bool(
            attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
        if (
            stat.S_ISLNK(identity.st_mode)
            or is_reparse_point
            or not stat.S_ISREG(identity.st_mode)
            or identity.st_nlink > 1
        ):
            raise UnsafeDatabaseIdentity(
                f"Unsafe SQLite file identity: {candidate}"
            )
