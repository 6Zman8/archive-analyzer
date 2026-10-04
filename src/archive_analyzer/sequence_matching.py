from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from math import ceil

from archive_analyzer.fingerprinting import ImageFingerprint, hamming_distance
from archive_analyzer.matching import ArchiveFingerprintSet


_BAND_WIDTHS = (10, 9, 9, 9, 9, 9, 9)
_BAND_OFFSETS = (54, 45, 36, 27, 18, 9, 0)
_MAX_DHASH_DISTANCE = 6
_MAX_BUCKET_PAGES = 200
_MIN_CONTAINED_PAGES = 3
_MIN_CONTAINED_COVERAGE = 0.90
_MIN_PARTIAL_PAGES = 5
_MIN_PARTIAL_COVERAGE = 0.30


class SequenceRelation(StrEnum):
    CONTAINS = "CONTAINS"
    PARTIAL_OVERLAP = "PARTIAL_OVERLAP"


@dataclass(frozen=True, slots=True)
class SequenceMatch:
    archive_a_id: int
    archive_b_id: int
    relation: SequenceRelation
    container_archive_id: int | None
    matched_pairs: tuple[tuple[int, int], ...]
    left_pages: int
    right_pages: int
    left_coverage: float
    right_coverage: float

    @property
    def matched_pages(self) -> int:
        return len(self.matched_pairs)


def match_page_sequences(
    left: ArchiveFingerprintSet,
    right: ArchiveFingerprintSet,
    *,
    checkpoint: Callable[[], None] | None = None,
) -> SequenceMatch | None:
    if left.archive_id == right.archive_id:
        raise ValueError("A sequence comparison requires two archives.")
    if left.archive_id > right.archive_id:
        left, right = right, left
    if not left.snapshot_stable or not right.snapshot_stable:
        return None
    if not left.pages or not right.pages:
        return None

    pairs = align_page_pairs(left.pages, right.pages, checkpoint=checkpoint)
    if not pairs:
        return None
    matched_pages = len(pairs)
    left_coverage = matched_pages / len(left.pages)
    right_coverage = matched_pages / len(right.pages)
    smaller_count = min(len(left.pages), len(right.pages))
    larger_count = max(len(left.pages), len(right.pages))
    smaller_coverage = max(left_coverage, right_coverage)
    similar_length_difference = max(2, ceil(larger_count * 0.05))

    if (
        left_coverage >= _MIN_CONTAINED_COVERAGE
        and right_coverage >= _MIN_CONTAINED_COVERAGE
        and abs(len(left.pages) - len(right.pages)) <= similar_length_difference
    ):
        return None

    if (
        matched_pages >= _MIN_CONTAINED_PAGES
        and smaller_coverage >= _MIN_CONTAINED_COVERAGE
        and larger_count >= smaller_count + 2
    ):
        container_id = (
            left.archive_id
            if len(left.pages) > len(right.pages)
            else right.archive_id
        )
        relation = SequenceRelation.CONTAINS
    elif (
        matched_pages >= _MIN_PARTIAL_PAGES
        and smaller_coverage >= _MIN_PARTIAL_COVERAGE
    ):
        container_id = None
        relation = SequenceRelation.PARTIAL_OVERLAP
    else:
        return None
    return SequenceMatch(
        archive_a_id=left.archive_id,
        archive_b_id=right.archive_id,
        relation=relation,
        container_archive_id=container_id,
        matched_pairs=pairs,
        left_pages=len(left.pages),
        right_pages=len(right.pages),
        left_coverage=left_coverage,
        right_coverage=right_coverage,
    )


def align_page_pairs(
    left: tuple[ImageFingerprint, ...],
    right: tuple[ImageFingerprint, ...],
    *,
    checkpoint: Callable[[], None] | None = None,
) -> tuple[tuple[int, int], ...]:
    """Match pages independently of whether one book contains the other."""
    offsets = _matching_offsets(left, right, checkpoint)
    if not offsets:
        return ()
    return max(
        offsets.items(),
        key=lambda item: (len(item[1]), _pair_density(item[1]), -abs(item[0]), -item[0]),
    )[1]


def _matching_offsets(
    left: tuple[ImageFingerprint, ...],
    right: tuple[ImageFingerprint, ...],
    checkpoint: Callable[[], None] | None,
) -> dict[int, tuple[tuple[int, int], ...]]:
    exact: dict[str, list[int]] = defaultdict(list)
    bands: dict[tuple[int, int], list[int]] = defaultdict(list)
    for right_index, page in enumerate(right):
        exact[page.pixel_sha256].append(right_index)
        for key in _dhash_bands(page.dhash64):
            bands[key].append(right_index)
        if (right_index + 1) % 200 == 0:
            _run_checkpoint(checkpoint)

    matches: dict[int, set[tuple[int, int]]] = defaultdict(set)
    for left_index, page in enumerate(left):
        candidates = set(_bounded(exact.get(page.pixel_sha256, ())))
        for key in _dhash_bands(page.dhash64):
            candidates.update(_bounded(bands.get(key, ())))
        for right_index in candidates:
            if _pages_match(page, right[right_index]):
                matches[right_index - left_index].add((left_index, right_index))
        if (left_index + 1) % 200 == 0:
            _run_checkpoint(checkpoint)
    return {
        offset: tuple(sorted(pairs))
        for offset, pairs in matches.items()
        if pairs
    }


def _bounded(values) -> tuple[int, ...]:  # type: ignore[no-untyped-def]
    values = tuple(values)
    return values if len(values) <= _MAX_BUCKET_PAGES else ()


def _dhash_bands(value: str) -> tuple[tuple[int, int], ...]:
    try:
        bits = int(value, 16)
    except ValueError:
        return ()
    return tuple(
        (index, (bits >> offset) & ((1 << width) - 1))
        for index, (width, offset) in enumerate(
            zip(_BAND_WIDTHS, _BAND_OFFSETS, strict=True)
        )
    )


def _pages_match(left: ImageFingerprint, right: ImageFingerprint) -> bool:
    if left.pixel_sha256 == right.pixel_sha256:
        return True
    try:
        return hamming_distance(left.dhash64, right.dhash64) <= _MAX_DHASH_DISTANCE
    except ValueError:
        return False


def _pair_density(pairs: tuple[tuple[int, int], ...] | set[tuple[int, int]]) -> float:
    ordered = sorted(pairs)
    if not ordered:
        return 0.0
    span = ordered[-1][0] - ordered[0][0] + 1
    return len(ordered) / span


def _run_checkpoint(checkpoint: Callable[[], None] | None) -> None:
    if checkpoint is not None:
        checkpoint()


__all__ = ["SequenceMatch", "SequenceRelation", "match_page_sequences"]
