import hashlib
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from threading import Event
from typing import Callable

from archive_analyzer.domain import FileSnapshot
from archive_analyzer.duplicate_domain import ArchiveAnalysisInput, ProbeFingerprint
from archive_analyzer.fingerprinting import (
    FingerprintFailure,
    ImageFingerprint,
    fingerprint_image,
    probe_positions,
)
from archive_analyzer.inspection.image_reader import ArchiveImageReader, ImageReadFailure
from archive_analyzer.paths import normalize_path_key
from archive_analyzer.storage.duplicate_repository import DuplicateRepository


_HASH_CHUNK_SIZE = 8 * 1024 * 1024
_STABLE_IMAGE_READ_ERRORS = {
    "AMBIGUOUS_ENTRY_NAME",
    "CORRUPT_ARCHIVE",
    "ENCRYPTED_UNSUPPORTED",
    "IMAGE_BYTE_LIMIT",
    "IMAGE_PIXEL_LIMIT",
    "UNSUPPORTED_FORMAT",
}
_RETRYABLE_IMAGE_READ_ERRORS = {
    "ACCESS_DENIED",
    "ARCHIVE_CHANGED",
    "ENTRY_CHANGED",
    "FILE_NOT_FOUND",
    "SEVEN_ZIP_FAILED",
    "SEVEN_ZIP_NOT_FOUND",
}


class AnalysisCancelled(Exception):
    pass


class AnalysisFailure(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ProbeFailure:
    slot: int
    entry_position: int
    error_code: str


@dataclass(frozen=True, slots=True)
class ProbeCacheResult:
    probes: tuple[ProbeFingerprint, ...]
    failures: tuple[ProbeFailure, ...]


def size_collision_targets(inputs: tuple[ArchiveAnalysisInput, ...]) -> tuple[int, ...]:
    counts: dict[int, int] = {}
    for value in inputs:
        counts[value.file_size] = counts.get(value.file_size, 0) + 1
    return tuple(value.archive_id for value in inputs if counts[value.file_size] > 1)


def sha256_archive(
    value: ArchiveAnalysisInput,
    cancel_event: Event,
    chunk_size: int = _HASH_CHUNK_SIZE,
) -> str:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    _require_snapshot(value)
    digest = hashlib.sha256()
    with value.path.open("rb") as stream:
        while True:
            _require_not_cancelled(cancel_event)
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    _require_not_cancelled(cancel_event)
    _require_snapshot(value)
    return digest.hexdigest()


def cache_probe_fingerprints(
    value: ArchiveAnalysisInput,
    reader: ArchiveImageReader,
    repository: DuplicateRepository,
    cancel_event: Event,
    analyzer_version: int,
    computed_at: datetime,
    *,
    owner_token: str | None = None,
    now: datetime | Callable[[], datetime] | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> ProbeCacheResult:
    _require_not_cancelled(cancel_event)
    _require_snapshot(value)
    cached = repository.cached_fingerprints(value, analyzer_version)
    cached_successes = {
        item.entry_position: item.fingerprint for item in cached.image_fingerprints
    } if cached is not None else {}
    cached_failures = {
        entry_position: error_code for entry_position, error_code in cached.image_failures
    } if cached is not None else {}
    snapshot = _file_snapshot(value)
    path_counts = Counter(image.path for image in value.images)
    results: list[ProbeFingerprint] = []
    failures: list[ProbeFailure] = []
    pending_successes: list[tuple[int, ImageFingerprint]] = []
    pending_failures: list[tuple[int, str]] = []
    positions = probe_positions(tuple(image.position for image in value.images))
    for slot, entry_position in enumerate(positions):
        if progress_callback is not None:
            progress_callback(slot, len(positions))
        _require_not_cancelled(cancel_event)
        entry = next(image for image in value.images if image.position == entry_position)
        cached_fingerprint = cached_successes.get(entry_position)
        if cached_fingerprint is not None:
            results.append(_probe_fingerprint(slot, entry_position, cached_fingerprint))
            continue
        if entry_position in cached_failures:
            failures.append(ProbeFailure(slot, entry_position, cached_failures[entry_position]))
            continue
        try:
            payload = reader.read(snapshot, entry, same_path_count=path_counts[entry.path])
            _require_not_cancelled(cancel_event)
            _require_snapshot(value)
            fingerprint = fingerprint_image(payload)
            _require_not_cancelled(cancel_event)
            _require_snapshot(value)
        except ImageReadFailure as error:
            if error.code in _STABLE_IMAGE_READ_ERRORS:
                pending_failures.append((entry_position, error.code))
                failures.append(ProbeFailure(slot, entry_position, error.code))
                continue
            if error.code in _RETRYABLE_IMAGE_READ_ERRORS:
                raise
            raise
        except FingerprintFailure as error:
            pending_failures.append((entry_position, error.code))
            failures.append(ProbeFailure(slot, entry_position, error.code))
            continue

        pending_successes.append((entry_position, fingerprint))
        results.append(_probe_fingerprint(slot, entry_position, fingerprint))

    if progress_callback is not None:
        progress_callback(len(positions), len(positions))
    _require_snapshot(value)
    _require_not_cancelled(cancel_event)
    write_now = now() if callable(now) else now
    if not repository.store_probe_fingerprints(
        value,
        analyzer_version=analyzer_version,
        computed_at=computed_at,
        sha256=None,
        hash_state="NOT_REQUIRED",
        successes=tuple(pending_successes),
        failures=tuple(pending_failures),
        owner_token=owner_token,
        now=write_now,
    ):
        raise AnalysisFailure("CHANGED_DURING_ANALYSIS")
    return ProbeCacheResult(tuple(results), tuple(failures))


def _file_snapshot(value: ArchiveAnalysisInput) -> FileSnapshot:
    return FileSnapshot(
        path=value.path,
        path_key=normalize_path_key(value.path),
        size=value.file_size,
        mtime_ns=value.mtime_ns,
        archive_format=value.archive_format,
    )


def _probe_fingerprint(
    slot: int, entry_position: int, fingerprint: ImageFingerprint
) -> ProbeFingerprint:
    return ProbeFingerprint(
        slot=slot,
        entry_position=entry_position,
        byte_sha256=fingerprint.byte_sha256,
        pixel_sha256=fingerprint.pixel_sha256,
        dhash64=fingerprint.dhash64,
        ahash64=fingerprint.ahash64,
        width=fingerprint.width,
        height=fingerprint.height,
    )


def _require_not_cancelled(cancel_event: Event) -> None:
    if cancel_event.is_set():
        raise AnalysisCancelled


def _require_snapshot(value: ArchiveAnalysisInput) -> None:
    try:
        current = value.path.stat()
    except OSError as error:
        raise AnalysisFailure("CHANGED_DURING_ANALYSIS") from error
    if current.st_size != value.file_size or current.st_mtime_ns != value.mtime_ns:
        raise AnalysisFailure("CHANGED_DURING_ANALYSIS")
