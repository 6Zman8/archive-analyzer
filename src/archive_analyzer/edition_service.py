from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from threading import Event
from typing import Callable

from archive_analyzer.archive_hashing import AnalysisCancelled
from archive_analyzer.domain import FileSnapshot
from archive_analyzer.edition_analysis import (
    EditionProfile,
    compare_editions,
    image_color_score,
    sample_positions,
)
from archive_analyzer.inspection.image_reader import (
    ArchiveImageReader,
    DispatchingImageReader,
    ImageReadFailure,
)
from archive_analyzer.paths import normalize_path_key
from archive_analyzer.storage.duplicate_repository import DuplicateRepository


EDITION_ALGORITHM_VERSION = 1
_DEFAULT_SEVEN_ZIP = Path(r"C:\Program Files\7-Zip\7z.exe")


@dataclass(frozen=True, slots=True)
class EditionAnalysisSummary:
    profiles_processed: int
    relations_processed: int
    failed_profiles: int


def analyze_editions(
    repository: DuplicateRepository,
    root_id: int,
    cancel_event: Event,
    *,
    set_keys: tuple[str, ...] | None = None,
    reader: ArchiveImageReader | None = None,
    clock: Callable[[], datetime] | None = None,
    progress: Callable[[int, int, str], None] | None = None,
) -> EditionAnalysisSummary:
    scope = repository.precision_scope_for_sets(set_keys) if set_keys is not None else None
    image_reader = reader or DispatchingImageReader(
        _DEFAULT_SEVEN_ZIP, timeout_seconds=1800.0
    )
    now = clock or (lambda: datetime.now(UTC))
    inputs = repository.edition_profile_inputs(
        root_id, algorithm_version=EDITION_ALGORITHM_VERSION,
        **({"archive_ids": scope.archive_ids} if scope is not None else {}),
    )
    sample_total = sum(
        len(sample_positions(len(source.value.images))) for source in inputs
    )
    sample_processed = 0
    if progress is not None and sample_total:
        progress(0, sample_total, "profile_pages")
    processed = 0
    failed = 0
    for source in inputs:
        _check_cancel(cancel_event)
        value = source.value
        counts = Counter(entry.path for entry in value.images)
        scores: list[float] = []
        error_code: str | None = None
        snapshot = FileSnapshot(
            path=value.path,
            path_key=normalize_path_key(value.path),
            size=value.file_size,
            mtime_ns=value.mtime_ns,
            archive_format=value.archive_format,
        )
        requests = tuple(
            (value.images[position], counts[value.images[position].path])
            for position in sample_positions(len(value.images))
        )
        read_many = getattr(image_reader, "read_many", None)
        completed_requests = 0
        try:
            if callable(read_many):
                outcomes = read_many(
                    snapshot, requests, cancel_check=lambda: _check_cancel(cancel_event)
                )
            else:
                outcomes = (
                    _read_one(image_reader, snapshot, entry, same_path_count)
                    for entry, same_path_count in requests
                )
            for outcome in outcomes:
                _check_cancel(cancel_event)
                if isinstance(outcome, ImageReadFailure):
                    error_code = outcome.code
                else:
                    try:
                        scores.append(image_color_score(outcome))
                    except (OSError, ValueError):
                        error_code = "EDITION_SAMPLE_FAILED"
                completed_requests += 1
                sample_processed += 1
                if progress is not None:
                    progress(sample_processed, sample_total, "profile_pages")
        except ImageReadFailure as error:
            error_code = error.code
            skipped = len(requests) - completed_requests
            sample_processed += skipped
            if progress is not None and skipped:
                progress(sample_processed, sample_total, "profile_pages")
        if scores:
            profile = EditionProfile(
                archive_id=value.archive_id,
                sample_count=len(scores),
                color_page_ratio=(
                    sum(score >= 0.08 for score in scores) / len(scores)
                ),
                median_color_score=float(median(scores)),
                language_hints=source.language_hints,
            )
        else:
            profile = None
            failed += 1
        if repository.store_edition_profile(
            source,
            profile,
            algorithm_version=EDITION_ALGORITHM_VERSION,
            computed_at=now(),
            error_code=error_code,
        ):
            processed += 1

    relation_inputs = repository.edition_relation_candidates(
        root_id, algorithm_version=EDITION_ALGORITHM_VERSION,
        **({"relation_pairs": scope.relation_pairs} if scope is not None else {}),
    )
    relation_count = 0
    if progress is not None and relation_inputs:
        progress(0, len(relation_inputs), "relations")
    for index, candidate in enumerate(relation_inputs, start=1):
        _check_cancel(cancel_event)
        comparison = compare_editions(
            candidate.left_profile,
            candidate.right_profile,
            candidate.evidence,
        )
        repository.store_edition_relation(
            candidate,
            comparison,
            algorithm_version=EDITION_ALGORITHM_VERSION,
            computed_at=now(),
        )
        relation_count += 1
        if progress is not None:
            progress(index, len(relation_inputs), "relations")
    return EditionAnalysisSummary(processed, relation_count, failed)


def _read_one(
    reader: ArchiveImageReader,
    snapshot: FileSnapshot,
    entry,
    same_path_count: int,
) -> bytes | ImageReadFailure:
    try:
        return reader.read(snapshot, entry, same_path_count=same_path_count)
    except ImageReadFailure as error:
        return error


def _check_cancel(cancel_event: Event) -> None:
    if cancel_event.is_set():
        raise AnalysisCancelled


__all__ = [
    "EDITION_ALGORITHM_VERSION",
    "EditionAnalysisSummary",
    "analyze_editions",
]
