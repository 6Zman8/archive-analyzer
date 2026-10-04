from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Callable
from uuid import uuid4

from archive_analyzer.archive_hashing import AnalysisCancelled
from archive_analyzer.paths import has_reparse_point_in_existing_chain
from archive_analyzer.storage.duplicate_repository import (
    DuplicateRepository,
    QuarantineCandidate,
    QuarantineEligibilityError,
    QuarantineItem,
)


_COPY_CHUNK_SIZE = 4 * 1024 * 1024


class QuarantineSafetyError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class QuarantineSummary:
    processed: int


def quarantine_archives(
    repository: DuplicateRepository,
    group_key: str,
    archive_ids: tuple[int, ...],
    quarantine_root: Path,
    cancel_event: Event,
    *,
    clock: Callable[[], datetime] | None = None,
    progress: Callable[[int, int, str], None] | None = None,
) -> QuarantineSummary:
    now = clock or (lambda: datetime.now(UTC))
    normalized_ids = tuple(dict.fromkeys(archive_ids))
    if not normalized_ids:
        raise QuarantineSafetyError("NO_SELECTION")
    processed = 0
    for index, archive_id in enumerate(normalized_ids, start=1):
        _check_cancel(cancel_event)
        try:
            candidate = repository.quarantine_candidate(group_key, archive_id)
        except QuarantineEligibilityError as error:
            raise QuarantineSafetyError(error.code) from error
        destination = quarantine_destination(candidate, quarantine_root)
        _validate_source(candidate.path, candidate.file_size, candidate.mtime_ns)
        if destination.exists():
            raise QuarantineSafetyError("DESTINATION_EXISTS")
        destination.parent.mkdir(parents=True, exist_ok=True)
        item = repository.create_quarantine_item(candidate, destination, now())
        try:
            digest = _safe_move(
                candidate.path,
                destination,
                candidate.file_size,
                candidate.mtime_ns,
                cancel_event,
                expected_hash=None,
                progress=(
                    None
                    if progress is None
                    else lambda current, total: progress(current, total, "quarantine")
                ),
                pending_hash=lambda value: repository.update_quarantine_status(
                    item.id,
                    "PENDING",
                    "PENDING",
                    now(),
                    sha256_value=value,
                ),
            )
            repository.update_quarantine_status(
                item.id,
                "PENDING",
                "QUARANTINED",
                now(),
                sha256_value=digest,
            )
        except BaseException as error:
            _mark_quarantine_failure(repository, item, now, error)
            raise
        processed += 1
        if progress is not None:
            progress(index, len(normalized_ids), "files")
    return QuarantineSummary(processed)


def restore_archives(
    repository: DuplicateRepository,
    group_key: str,
    archive_ids: tuple[int, ...],
    cancel_event: Event,
    *,
    clock: Callable[[], datetime] | None = None,
    progress: Callable[[int, int, str], None] | None = None,
) -> QuarantineSummary:
    now = clock or (lambda: datetime.now(UTC))
    normalized_ids = tuple(dict.fromkeys(archive_ids))
    if not normalized_ids:
        raise QuarantineSafetyError("NO_SELECTION")
    processed = 0
    for index, archive_id in enumerate(normalized_ids, start=1):
        _check_cancel(cancel_event)
        item = repository.active_quarantine_item(group_key, archive_id)
        if item is None or item.status != "QUARANTINED":
            raise QuarantineSafetyError("NOT_QUARANTINED")
        if item.sha256 is None:
            raise QuarantineSafetyError("QUARANTINE_HASH_MISSING")
        if item.source_path.exists():
            raise QuarantineSafetyError("RESTORE_DESTINATION_EXISTS")
        _validate_source(item.destination_path, item.file_size, item.mtime_ns)
        repository.update_quarantine_status(
            item.id, "QUARANTINED", "RESTORING", now()
        )
        try:
            _safe_move(
                item.destination_path,
                item.source_path,
                item.file_size,
                item.mtime_ns,
                cancel_event,
                expected_hash=item.sha256,
                progress=(
                    None
                    if progress is None
                    else lambda current, total: progress(current, total, "restore")
                ),
            )
            repository.update_quarantine_status(
                item.id, "RESTORING", "RESTORED", now()
            )
        except BaseException as error:
            try:
                repository.update_quarantine_status(
                    item.id,
                    "RESTORING",
                    "QUARANTINED",
                    now(),
                    error_code=_error_code(error),
                )
            except (QuarantineEligibilityError, ValueError):
                pass
            raise
        processed += 1
        if progress is not None:
            progress(index, len(normalized_ids), "files")
    return QuarantineSummary(processed)


def reconcile_quarantine_items(
    repository: DuplicateRepository,
    root_id: int,
    cancel_event: Event,
    *,
    clock: Callable[[], datetime] | None = None,
) -> int:
    """Resolve the narrow crash windows without deleting either ambiguous copy."""

    now = clock or (lambda: datetime.now(UTC))
    reconciled = 0
    for item in repository.active_quarantine_items(root_id):
        _check_cancel(cancel_event)
        if item.status == "QUARANTINED":
            try:
                item.destination_path.stat()
            except FileNotFoundError:
                pass
            except OSError:
                continue
            else:
                continue
            # Removed empty subfolders are different from an unavailable drive/share.
            if not Path(item.source_path.anchor).is_dir() or not Path(item.destination_path.anchor).is_dir():
                continue
            if item.source_path.is_file() and _item_file_matches(item.source_path, item, cancel_event):
                repository.update_quarantine_status(item.id, "QUARANTINED", "RESTORED", now())
            else:
                repository.update_quarantine_status(item.id, "QUARANTINED", "FAILED", now(),
                    error_code="RECOVERY_FILES_MISSING_OR_CHANGED")
            reconciled += 1
            continue
        if item.status not in {"PENDING", "RESTORING"}:
            continue
        source_exists = item.source_path.exists()
        destination_exists = item.destination_path.exists()
        if item.status == "PENDING" and source_exists and destination_exists:
            # A copy may have committed before source removal failed. Keep both
            # copies and the recovery ledger; never pick a copy to delete here.
            repository.update_quarantine_status(
                item.id, "PENDING", "PENDING", now(),
                error_code="RECOVERY_BOTH_COPIES",
            )
            reconciled += 1
            continue
        if item.status == "PENDING" and not source_exists and destination_exists:
            if _item_file_matches(item.destination_path, item, cancel_event):
                repository.update_quarantine_status(
                    item.id, "PENDING", "QUARANTINED", now()
                )
            else:
                repository.update_quarantine_status(
                    item.id,
                    "PENDING",
                    "FAILED",
                    now(),
                    error_code="RECOVERY_DESTINATION_MISMATCH",
                )
            reconciled += 1
            continue
        if item.status == "RESTORING" and source_exists and not destination_exists:
            if _item_file_matches(item.source_path, item, cancel_event):
                repository.update_quarantine_status(
                    item.id, "RESTORING", "RESTORED", now()
                )
            else:
                repository.update_quarantine_status(
                    item.id,
                    "RESTORING",
                    "FAILED",
                    now(),
                    error_code="RECOVERY_SOURCE_MISMATCH",
                )
            reconciled += 1
            continue
        if item.status == "RESTORING" and not source_exists and destination_exists:
            repository.update_quarantine_status(
                item.id,
                "RESTORING",
                "QUARANTINED",
                now(),
                error_code="RESTORE_INTERRUPTED",
            )
            reconciled += 1
            continue
        repository.update_quarantine_status(
            item.id,
            item.status,
            "FAILED",
            now(),
            error_code="RECOVERY_AMBIGUOUS_FILES",
        )
        reconciled += 1
    return reconciled


def quarantine_destination(
    candidate: QuarantineCandidate, quarantine_root: Path
) -> Path:
    for path in (candidate.root_path, candidate.path, Path(quarantine_root)):
        _validate_plain_path(path)
    root = candidate.root_path.resolve(strict=False)
    source = candidate.path.resolve(strict=False)
    base = Path(quarantine_root).resolve(strict=False)
    if _is_within(base, root) or _is_within(root, base):
        raise QuarantineSafetyError("QUARANTINE_ROOT_OVERLAPS_SOURCE")
    try:
        relative = source.relative_to(root)
    except ValueError as error:
        raise QuarantineSafetyError("SOURCE_OUTSIDE_ROOT") from error
    if not root.name:
        raise QuarantineSafetyError("SOURCE_ROOT_NAME_MISSING")
    destination = base / root.name / relative
    _validate_plain_path(destination)
    return destination


def _safe_move(
    source: Path,
    destination: Path,
    expected_size: int,
    expected_mtime_ns: int,
    cancel_event: Event,
    *,
    expected_hash: str | None,
    progress: Callable[[int, int], None] | None,
    pending_hash: Callable[[str], object] | None = None,
) -> str:
    _check_cancel(cancel_event)
    _validate_plain_path(source)
    _validate_plain_path(destination)
    if destination.exists():
        raise QuarantineSafetyError("DESTINATION_EXISTS")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if _same_volume(source, destination):
        digest = _sha256_file(source, cancel_event, progress)
        if expected_hash is not None and digest != expected_hash:
            raise QuarantineSafetyError("HASH_MISMATCH")
        if pending_hash is not None:
            pending_hash(digest)
        _validate_source(source, expected_size, expected_mtime_ns)
        _validate_plain_path(destination)
        _check_cancel(cancel_event)
        try:
            source.rename(destination)
        except FileExistsError as error:
            raise QuarantineSafetyError("DESTINATION_EXISTS") from error
        except OSError as error:
            raise QuarantineSafetyError("FILE_MOVE_FAILED") from error
        return digest
    return _copy_verified_then_remove(
        source,
        destination,
        expected_size,
        expected_mtime_ns,
        cancel_event,
        expected_hash=expected_hash,
        progress=progress,
        pending_hash=pending_hash,
    )


def _copy_verified_then_remove(
    source: Path,
    destination: Path,
    expected_size: int,
    expected_mtime_ns: int,
    cancel_event: Event,
    *,
    expected_hash: str | None,
    progress: Callable[[int, int], None] | None,
    pending_hash: Callable[[str], object] | None,
) -> str:
    temporary = destination.with_name(
        f".{destination.name}.archive-analyzer-{uuid4().hex}.tmp"
    )
    digest = hashlib.sha256()
    copied = 0
    try:
        with source.open("rb") as input_file, temporary.open("xb") as output_file:
            while True:
                _check_cancel(cancel_event)
                chunk = input_file.read(_COPY_CHUNK_SIZE)
                if not chunk:
                    break
                output_file.write(chunk)
                digest.update(chunk)
                copied += len(chunk)
                if progress is not None:
                    progress(copied, expected_size)
            output_file.flush()
            os.fsync(output_file.fileno())
        value = digest.hexdigest()
        if expected_hash is not None and value != expected_hash:
            raise QuarantineSafetyError("HASH_MISMATCH")
        if copied != expected_size:
            raise QuarantineSafetyError("SOURCE_CHANGED")
        if pending_hash is not None:
            pending_hash(value)
        _validate_source(source, expected_size, expected_mtime_ns)
        if _sha256_file(temporary, cancel_event, progress) != value:
            raise QuarantineSafetyError("COPY_VERIFY_FAILED")
        os.utime(temporary, ns=(expected_mtime_ns, expected_mtime_ns))
        _validate_source(source, expected_size, expected_mtime_ns)
        _validate_plain_path(destination)
        _check_cancel(cancel_event)
        if destination.exists():
            raise QuarantineSafetyError("DESTINATION_EXISTS")
        try:
            temporary.rename(destination)
        except FileExistsError as error:
            raise QuarantineSafetyError("DESTINATION_EXISTS") from error
        # The verified copy is now committed. Finish this single move before
        # honoring cancellation at the next file boundary, as for an atomic rename.
        _validate_source(source, expected_size, expected_mtime_ns)
        source.unlink()
        return value
    except AnalysisCancelled:
        raise
    except QuarantineSafetyError:
        raise
    except OSError as error:
        raise QuarantineSafetyError("FILE_MOVE_FAILED") from error
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _sha256_file(
    path: Path,
    cancel_event: Event,
    progress: Callable[[int, int], None] | None,
) -> str:
    total = path.stat().st_size
    processed = 0
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            _check_cancel(cancel_event)
            chunk = stream.read(_COPY_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            processed += len(chunk)
            if progress is not None:
                progress(processed, total)
    return digest.hexdigest()


def _validate_plain_path(path: Path) -> None:
    if has_reparse_point_in_existing_chain(path):
        raise QuarantineSafetyError("REPARSE_POINT")


def _validate_source(path: Path, size: int, mtime_ns: int) -> None:
    _validate_plain_path(path)
    try:
        current = path.stat()
    except OSError as error:
        raise QuarantineSafetyError("SOURCE_MISSING") from error
    if current.st_size != size or current.st_mtime_ns != mtime_ns:
        raise QuarantineSafetyError("SOURCE_CHANGED")


def _item_file_matches(
    path: Path, item: QuarantineItem, cancel_event: Event
) -> bool:
    try:
        stat = path.stat()
        if stat.st_size != item.file_size or stat.st_mtime_ns != item.mtime_ns:
            return False
        return item.sha256 is None or _sha256_file(path, cancel_event, None) == item.sha256
    except OSError:
        return False


def _mark_quarantine_failure(
    repository: DuplicateRepository,
    item: QuarantineItem,
    now: Callable[[], datetime],
    error: BaseException,
) -> None:
    current = repository.quarantine_item(item.id)
    if current is None or current.status != "PENDING":
        return
    try:
        item.destination_path.lstat()
        destination_may_exist = True
    except FileNotFoundError:
        destination_may_exist = False
    except OSError:
        destination_may_exist = True
    # A recorded digest precedes the filesystem commit. Preserve recoverability
    # if that commit may have happened, including final database-write failure.
    status = "PENDING" if current.sha256 and destination_may_exist else "FAILED"
    try:
        repository.update_quarantine_status(
            item.id,
            "PENDING",
            status,
            now(),
            error_code=_error_code(error),
        )
    except (QuarantineEligibilityError, ValueError):
        pass


def _error_code(error: BaseException) -> str:
    if isinstance(error, QuarantineSafetyError):
        return error.code
    if isinstance(error, AnalysisCancelled):
        return "CANCELLED"
    return "UNEXPECTED_ERROR"


def _same_volume(left: Path, right: Path) -> bool:
    return left.resolve(strict=False).anchor.casefold() == right.resolve(
        strict=False
    ).anchor.casefold()


def _is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True


def _check_cancel(cancel_event: Event) -> None:
    if cancel_event.is_set():
        raise AnalysisCancelled


__all__ = [
    "QuarantineSafetyError",
    "QuarantineSummary",
    "quarantine_archives",
    "quarantine_destination",
    "reconcile_quarantine_items",
    "restore_archives",
]
