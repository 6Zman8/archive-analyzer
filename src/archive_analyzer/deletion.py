from __future__ import annotations

import hashlib
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Callable

from archive_analyzer.archive_hashing import AnalysisCancelled
from archive_analyzer.paths import has_reparse_point_in_existing_chain
from archive_analyzer.recycle_bin import recycle_file
from archive_analyzer.storage.duplicate_repository import (
    DeletionItem,
    DuplicateRepository,
    QuarantineEligibilityError,
    QuarantineItem,
)


_HASH_CHUNK_SIZE = 4 * 1024 * 1024


class DeletionSafetyError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class DeletionSummary:
    processed: int


def delete_quarantined_archives(
    repository: DuplicateRepository,
    group_key: str,
    archive_ids: tuple[int, ...],
    cancel_event: Event,
    *,
    clock: Callable[[], datetime] | None = None,
    progress: Callable[[int, int, str], None] | None = None,
) -> DeletionSummary:
    """Recycle only intact, recorded quarantine copies; never fall back to unlink."""

    now = clock or (lambda: datetime.now(UTC))
    normalized_ids = tuple(dict.fromkeys(archive_ids))
    if not normalized_ids:
        raise DeletionSafetyError("NO_SELECTION")
    processed = 0
    for index, archive_id in enumerate(normalized_ids, start=1):
        _check_cancel(cancel_event)
        try:
            item = repository.deletion_candidate(group_key, archive_id)
        except QuarantineEligibilityError as error:
            raise DeletionSafetyError(error.code) from error
        if _path_lexists(item.source_path):
            raise DeletionSafetyError("SOURCE_REAPPEARED")
        _validate_destination(item, cancel_event, progress)
        record = repository.begin_deletion(item, now())
        try:
            _check_cancel(cancel_event)
            if _path_lexists(item.source_path):
                raise DeletionSafetyError("SOURCE_REAPPEARED")
            _validate_file_snapshot(item.destination_path, item.file_size, item.mtime_ns)
            recycle_file(item.destination_path)
        except AnalysisCancelled:
            _mark_failed(repository, record, now, "CANCELLED")
            raise
        except DeletionSafetyError as error:
            _mark_failed(repository, record, now, error.code)
            raise
        except OSError as error:
            _mark_failed(repository, record, now, "FILE_DELETE_FAILED")
            raise DeletionSafetyError("FILE_DELETE_FAILED") from error
        repository.update_deletion_state(record.id, "PENDING", "DELETED", now())
        processed += 1
        if progress is not None:
            progress(index, len(normalized_ids), "files")
    return DeletionSummary(processed)


def reconcile_deletions(
    repository: DuplicateRepository,
    root_id: int,
    cancel_event: Event,
    *,
    clock: Callable[[], datetime] | None = None,
) -> int:
    """Resolve deletion crash windows without ever deleting another file."""

    now = clock or (lambda: datetime.now(UTC))
    reconciled = 0
    for record in repository.pending_deletion_records(root_id):
        _check_cancel(cancel_event)
        if not _path_lexists(record.path):
            repository.update_deletion_state(
                record.id, "PENDING", "DELETED", now()
            )
            reconciled += 1
            continue
        try:
            _validate_record(record, cancel_event)
        except DeletionSafetyError:
            error_code = "DELETION_FILE_CHANGED"
        else:
            error_code = "INTERRUPTED_BEFORE_DELETE"
        repository.update_deletion_state(
            record.id,
            "PENDING",
            "FAILED",
            now(),
            error_code=error_code,
        )
        reconciled += 1
    return reconciled


def _validate_destination(
    item: QuarantineItem,
    cancel_event: Event,
    progress: Callable[[int, int, str], None] | None,
) -> None:
    assert item.sha256 is not None
    _validate_file_snapshot(item.destination_path, item.file_size, item.mtime_ns)
    digest = _sha256_file(
        item.destination_path,
        cancel_event,
        None
        if progress is None
        else lambda current, total: progress(current, total, "delete"),
    )
    _validate_file_snapshot(item.destination_path, item.file_size, item.mtime_ns)
    if digest != item.sha256:
        raise DeletionSafetyError("HASH_MISMATCH")


def _validate_record(record: DeletionItem, cancel_event: Event) -> None:
    _validate_file_snapshot(record.path, record.file_size, record.mtime_ns)
    digest = _sha256_file(record.path, cancel_event, None)
    _validate_file_snapshot(record.path, record.file_size, record.mtime_ns)
    if digest != record.sha256:
        raise DeletionSafetyError("HASH_MISMATCH")


def _validate_file_snapshot(path: Path, size: int, mtime_ns: int) -> None:
    if has_reparse_point_in_existing_chain(path):
        raise DeletionSafetyError("REPARSE_POINT")
    try:
        current = path.lstat()
    except OSError as error:
        raise DeletionSafetyError("QUARANTINE_FILE_MISSING") from error
    if not stat.S_ISREG(current.st_mode) or path.is_symlink():
        raise DeletionSafetyError("QUARANTINE_FILE_NOT_REGULAR")
    if current.st_size != size or current.st_mtime_ns != mtime_ns:
        raise DeletionSafetyError("QUARANTINE_FILE_CHANGED")


def _sha256_file(
    path: Path,
    cancel_event: Event,
    progress: Callable[[int, int], None] | None,
) -> str:
    total = path.stat().st_size
    processed = 0
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while True:
                _check_cancel(cancel_event)
                chunk = stream.read(_HASH_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
                processed += len(chunk)
                if progress is not None:
                    progress(processed, total)
    except AnalysisCancelled:
        raise
    except OSError as error:
        raise DeletionSafetyError("QUARANTINE_FILE_READ_FAILED") from error
    return digest.hexdigest()


def _mark_failed(
    repository: DuplicateRepository,
    record: DeletionItem,
    now: Callable[[], datetime],
    error_code: str,
) -> None:
    current = repository.deletion_record(record.id)
    if current is None or current.state != "PENDING":
        return
    try:
        repository.update_deletion_state(
            record.id,
            "PENDING",
            "FAILED",
            now(),
            error_code=error_code,
        )
    except (QuarantineEligibilityError, ValueError):
        pass


def _check_cancel(cancel_event: Event) -> None:
    if cancel_event.is_set():
        raise AnalysisCancelled


def _path_lexists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


__all__ = [
    "DeletionSafetyError",
    "DeletionSummary",
    "delete_quarantined_archives",
    "reconcile_deletions",
]
