from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from statistics import median

from archive_analyzer.candidate_index import CandidateSeed, DATED_SERIES_TITLE
from archive_analyzer.duplicate_domain import DuplicateRelation
from archive_analyzer.fingerprinting import ImageFingerprint, hamming_distance


_FIXED_OFFSETS = (-2, -1, 0, 1, 2)
_MAX_DHASH_DISTANCE = 6
_MIN_VISUAL_MATCHED_PAGES = 3
_MIN_VISUAL_RATIO = 0.90
_RESOLUTION_AREA_RATIO = 1.15


@dataclass(frozen=True, slots=True)
class ArchiveFingerprintSet:
    """A full-page fingerprint snapshot that is safe to compare.

    Callers must set ``snapshot_stable`` false when the Task 4 cache/promote
    snapshot checks reject the source or when full-page collection failed its
    stability check. Such input deliberately never becomes a duplicate claim.
    """

    archive_id: int
    file_sha256: str | None
    pages: tuple[ImageFingerprint, ...]
    snapshot_stable: bool = True
    stability_error: str | None = None


@dataclass(frozen=True, slots=True)
class CandidateMatch:
    archive_a_id: int
    archive_b_id: int
    relation: DuplicateRelation
    confidence: float
    matched_pages: int
    left_pages: int
    right_pages: int
    reasons: tuple[str, ...]
    recommendation: str


def match_candidate(
    left: ArchiveFingerprintSet,
    right: ArchiveFingerprintSet,
    seed: CandidateSeed,
    *,
    checkpoint: Callable[[], None] | None = None,
) -> CandidateMatch:
    """Classify one pre-selected candidate without searching page pairs.

    Each offset checks only aligned page positions, so the visual step remains
    bounded by five linear scans over the page sequence. Candidate-seed reasons
    are retained verbatim before the deterministic full-page evidence.
    """

    _run_checkpoint(checkpoint)
    left, right = _normalized_sets(left, right)
    _require_seed_for_pair(left, right, seed)
    seed_reasons = seed.reasons

    if not left.snapshot_stable or not right.snapshot_stable:
        return _related(
            left,
            right,
            seed_reasons + _stability_reasons(left, right),
            matched_pages=0,
            confidence=0.0,
        )

    if left.file_sha256 and left.file_sha256 == right.file_sha256:
        return CandidateMatch(
            archive_a_id=left.archive_id,
            archive_b_id=right.archive_id,
            relation=DuplicateRelation.EXACT_ARCHIVE,
            confidence=1.0,
            matched_pages=min(len(left.pages), len(right.pages)),
            left_pages=len(left.pages),
            right_pages=len(right.pages),
            reasons=seed_reasons + ("IDENTICAL_ARCHIVE_SHA256",),
            recommendation="MANUAL_EQUIVALENT_PATHS",
        )

    if _has_identical_pixels_in_order(left.pages, right.pages, checkpoint):
        pairs = tuple(zip(left.pages, right.pages, strict=True))
        recommendation, resolution_reason = _resolution_decision(pairs, checkpoint)
        return CandidateMatch(
            archive_a_id=left.archive_id,
            archive_b_id=right.archive_id,
            relation=DuplicateRelation.EXACT_CONTENT,
            confidence=1.0,
            matched_pages=len(pairs),
            left_pages=len(left.pages),
            right_pages=len(right.pages),
            reasons=seed_reasons + ("ALL_PIXEL_SHA256_IN_ORDER", resolution_reason),
            recommendation=recommendation,
        )

    offset, matched_pairs = _best_fixed_offset(left.pages, right.pages, checkpoint)
    matched_pages = len(matched_pairs)
    largest_count = max(len(left.pages), len(right.pages))
    confidence = matched_pages / largest_count if largest_count else 0.0
    match_reasons = seed_reasons + (
        f"FIXED_OFFSET_{offset}",
        f"MATCHED_PAGES_{matched_pages}_OF_{largest_count}",
    )
    allowed_difference = max(2, math.ceil(largest_count * 0.05))
    if (
        confidence >= _MIN_VISUAL_RATIO
        and abs(len(left.pages) - len(right.pages)) <= allowed_difference
        and matched_pages >= _MIN_VISUAL_MATCHED_PAGES
    ):
        recommendation, resolution_reason = _resolution_decision(
            matched_pairs, checkpoint
        )
        return CandidateMatch(
            archive_a_id=left.archive_id,
            archive_b_id=right.archive_id,
            relation=DuplicateRelation.VISUAL_VARIANT,
            confidence=confidence,
            matched_pages=matched_pages,
            left_pages=len(left.pages),
            right_pages=len(right.pages),
            reasons=match_reasons + (resolution_reason,),
            recommendation=recommendation,
        )
    if DATED_SERIES_TITLE in seed_reasons:
        # Verify common pages by exact decoded pixels, including large cover/section shifts.
        from collections import Counter
        left_pixels = Counter(page.pixel_sha256 for page in left.pages if page.pixel_sha256)
        right_pixels = Counter(page.pixel_sha256 for page in right.pages if page.pixel_sha256)
        common = sum((left_pixels & right_pixels).values())
        smaller = min(len(left.pages), len(right.pages))
        coverage = common / smaller if smaller else 0.0
        if common >= 3 and coverage >= 0.8:
            return _related(left, right, seed_reasons + (
                f"DATED_SERIES_COMMON_{common}_OF_{smaller}",
                f"DATED_SERIES_ADDED_{abs(len(left.pages) - len(right.pages))}",
            ), common, coverage)
    return _related(left, right, match_reasons, matched_pages, confidence)


def _normalized_sets(
    left: ArchiveFingerprintSet, right: ArchiveFingerprintSet
) -> tuple[ArchiveFingerprintSet, ArchiveFingerprintSet]:
    if left.archive_id == right.archive_id:
        raise ValueError("A candidate must contain two different archives.")
    return (left, right) if left.archive_id < right.archive_id else (right, left)


def _require_seed_for_pair(
    left: ArchiveFingerprintSet, right: ArchiveFingerprintSet, seed: CandidateSeed
) -> None:
    if {seed.archive_a_id, seed.archive_b_id} != {left.archive_id, right.archive_id}:
        raise ValueError("Candidate seed endpoints do not match the archive pair.")


def _stability_reasons(
    left: ArchiveFingerprintSet, right: ArchiveFingerprintSet
) -> tuple[str, ...]:
    reasons = ["UNSTABLE_SOURCE_SNAPSHOT"]
    for value in (left, right):
        if not value.snapshot_stable and value.stability_error is not None:
            reasons.append(value.stability_error)
    return tuple(reasons)


def _has_identical_pixels_in_order(
    left: tuple[ImageFingerprint, ...],
    right: tuple[ImageFingerprint, ...],
    checkpoint: Callable[[], None] | None,
) -> bool:
    if not left or len(left) != len(right):
        return False
    for index, (first, second) in enumerate(zip(left, right, strict=True), start=1):
        if first.pixel_sha256 != second.pixel_sha256:
            return False
        if index % 200 == 0:
            _run_checkpoint(checkpoint)
    return True


def _best_fixed_offset(
    left: tuple[ImageFingerprint, ...],
    right: tuple[ImageFingerprint, ...],
    checkpoint: Callable[[], None] | None,
) -> tuple[int, tuple[tuple[ImageFingerprint, ImageFingerprint], ...]]:
    best_offset = 0
    best_pairs: tuple[tuple[ImageFingerprint, ImageFingerprint], ...] = ()
    for offset in _FIXED_OFFSETS:
        _run_checkpoint(checkpoint)
        matched: list[tuple[ImageFingerprint, ImageFingerprint]] = []
        for left_index, left_page in enumerate(left):
            right_index = left_index + offset
            if 0 <= right_index < len(right) and _pages_match(
                left_page, right[right_index]
            ):
                matched.append((left_page, right[right_index]))
            if (left_index + 1) % 200 == 0:
                _run_checkpoint(checkpoint)
        matched_pairs = tuple(matched)
        if (len(matched_pairs), -abs(offset), -offset) > (
            len(best_pairs),
            -abs(best_offset),
            -best_offset,
        ):
            best_offset, best_pairs = offset, matched_pairs
    return best_offset, best_pairs


def _pages_match(left: ImageFingerprint, right: ImageFingerprint) -> bool:
    if left.pixel_sha256 == right.pixel_sha256:
        return True
    try:
        return hamming_distance(left.dhash64, right.dhash64) <= _MAX_DHASH_DISTANCE
    except ValueError:
        return False


def _resolution_decision(
    pairs: tuple[tuple[ImageFingerprint, ImageFingerprint], ...],
    checkpoint: Callable[[], None] | None,
) -> tuple[str, str]:
    if not pairs:
        return "MANUAL", "NO_MATCHED_PAGE_RESOLUTION_EVIDENCE"
    left_areas: list[int] = []
    right_areas: list[int] = []
    for index, (first, second) in enumerate(pairs, start=1):
        left_areas.append(first.width * first.height)
        right_areas.append(second.width * second.height)
        if index % 200 == 0:
            _run_checkpoint(checkpoint)
    left_area = median(left_areas)
    right_area = median(right_areas)
    if left_area >= right_area * _RESOLUTION_AREA_RATIO:
        return "KEEP_LEFT_HIGHER_RESOLUTION", "LEFT_MEDIAN_PIXEL_AREA_AT_LEAST_15_PERCENT_LARGER"
    if right_area >= left_area * _RESOLUTION_AREA_RATIO:
        return "KEEP_RIGHT_HIGHER_RESOLUTION", "RIGHT_MEDIAN_PIXEL_AREA_AT_LEAST_15_PERCENT_LARGER"
    return "MANUAL", "MEDIAN_PIXEL_AREA_DIFFERENCE_BELOW_15_PERCENT"


def _related(
    left: ArchiveFingerprintSet,
    right: ArchiveFingerprintSet,
    reasons: tuple[str, ...],
    matched_pages: int,
    confidence: float,
) -> CandidateMatch:
    return CandidateMatch(
        archive_a_id=left.archive_id,
        archive_b_id=right.archive_id,
        relation=DuplicateRelation.RELATED,
        confidence=confidence,
        matched_pages=matched_pages,
        left_pages=len(left.pages),
        right_pages=len(right.pages),
        reasons=reasons,
        recommendation="MANUAL",
    )


def _run_checkpoint(checkpoint: Callable[[], None] | None) -> None:
    if checkpoint is not None:
        checkpoint()
