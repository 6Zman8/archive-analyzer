from __future__ import annotations

import hashlib

import pytest

from archive_analyzer.candidate_index import CandidateSeed
from archive_analyzer.duplicate_domain import DuplicateRelation
from archive_analyzer.fingerprinting import ImageFingerprint
from archive_analyzer.matching import ArchiveFingerprintSet, match_candidate


def fingerprint(
    value: str,
    *,
    dhash: str | None = None,
    area: int = 1_000_000,
) -> ImageFingerprint:
    width = 1_000
    height = area // width
    return ImageFingerprint(
        byte_sha256=f"bytes-{value}",
        pixel_sha256=f"pixels-{value}",
        dhash64=dhash or hashlib.sha256(value.encode()).hexdigest()[:16],
        ahash64="0" * 16,
        width=width,
        height=height,
    )


def page_set(
    archive_id: int,
    values: tuple[str, ...],
    *,
    file_sha256: str | None = None,
    dhashes: tuple[str, ...] | None = None,
    area: int = 1_000_000,
    snapshot_stable: bool = True,
    stability_error: str | None = None,
) -> ArchiveFingerprintSet:
    hashes = dhashes or (None,) * len(values)
    return ArchiveFingerprintSet(
        archive_id=archive_id,
        file_sha256=file_sha256,
        pages=tuple(
            fingerprint(value, dhash=dhash, area=area)
            for value, dhash in zip(values, hashes, strict=True)
        ),
        snapshot_stable=snapshot_stable,
        stability_error=stability_error,
    )


def seed(left: int = 1, right: int = 2) -> CandidateSeed:
    return CandidateSeed(left, right, ("SAME_PIXEL_SHA256",), 1)


def test_identical_file_hash_is_exact_archive_and_preserves_seed_evidence() -> None:
    relation = match_candidate(
        page_set(2, ("a",), file_sha256="a" * 64),
        page_set(1, ("b",), file_sha256="a" * 64),
        CandidateSeed(2, 1, ("SAME_ARCHIVE_SHA256", "LSH_BAND_MATCH"), 2),
    )

    assert relation.archive_a_id == 1
    assert relation.archive_b_id == 2
    assert relation.relation is DuplicateRelation.EXACT_ARCHIVE
    assert relation.confidence == 1.0
    assert relation.recommendation == "MANUAL_EQUIVALENT_PATHS"
    assert relation.reasons[:2] == ("SAME_ARCHIVE_SHA256", "LSH_BAND_MATCH")


def test_identical_pixels_are_exact_content() -> None:
    relation = match_candidate(page_set(1, ("a", "b", "c")), page_set(2, ("a", "b", "c")), seed())

    assert relation.relation is DuplicateRelation.EXACT_CONTENT
    assert relation.confidence == 1.0
    assert relation.matched_pages == 3


def test_recompressed_pages_are_visual_variant_and_recommend_higher_resolution() -> None:
    relation = match_candidate(
        page_set(1, ("a", "b", "c"), dhashes=("0000", "1111", "2222")),
        page_set(2, ("d", "e", "f"), dhashes=("0001", "1110", "2223"), area=2_000_000),
        seed(),
    )

    assert relation.relation is DuplicateRelation.VISUAL_VARIANT
    assert relation.recommendation == "KEEP_RIGHT_HIGHER_RESOLUTION"
    assert relation.matched_pages == 3


@pytest.mark.parametrize(
    ("right_dhash", "expected"),
    (("000000000000003f", DuplicateRelation.VISUAL_VARIANT), ("000000000000007f", DuplicateRelation.RELATED)),
    ids=("distance-six", "distance-seven"),
)
def test_visual_matching_uses_the_dhash_distance_six_boundary(
    right_dhash: str, expected: DuplicateRelation
) -> None:
    relation = match_candidate(
        page_set(1, ("a", "b", "c"), dhashes=("0000000000000000",) * 3),
        page_set(2, ("d", "e", "f"), dhashes=(right_dhash,) * 3),
        seed(),
    )

    assert relation.relation is expected


def test_same_cover_only_is_related_without_recommendation() -> None:
    relation = match_candidate(
        page_set(1, ("cover", "a", "b", "c")),
        page_set(2, ("cover", "d", "e", "f")),
        seed(),
    )

    assert relation.relation is DuplicateRelation.RELATED
    assert relation.recommendation == "MANUAL"
    assert relation.matched_pages == 1


@pytest.mark.parametrize(
    "right_values",
    (("3", "1", "2"), ("2", "1", "3")),
    ids=("reversed", "shuffled"),
)
def test_reordered_pages_are_not_exact_or_variant(right_values: tuple[str, ...]) -> None:
    relation = match_candidate(page_set(1, ("1", "2", "3")), page_set(2, right_values), seed())

    assert relation.relation is DuplicateRelation.RELATED


def test_leading_inserted_page_can_match_at_a_fixed_offset() -> None:
    values = tuple(str(index) for index in range(20))
    relation = match_candidate(
        page_set(1, values),
        page_set(2, ("insert", *values)),
        seed(),
    )

    assert relation.relation is DuplicateRelation.VISUAL_VARIANT
    assert relation.matched_pages == 20
    assert "FIXED_OFFSET_1" in relation.reasons


def test_leading_deleted_pages_can_match_at_a_fixed_offset() -> None:
    values = tuple(str(index) for index in range(20))
    relation = match_candidate(
        page_set(1, ("old-one", "old-two", *values)),
        page_set(2, values),
        seed(),
    )

    assert relation.relation is DuplicateRelation.VISUAL_VARIANT
    assert relation.matched_pages == 20
    assert "FIXED_OFFSET_-2" in relation.reasons


def test_middle_insertion_is_not_matched_by_all_pairs_search() -> None:
    relation = match_candidate(
        page_set(1, tuple(str(index) for index in range(20))),
        page_set(2, tuple([*(str(index) for index in range(10)), "insert", *(str(index) for index in range(10, 20))])),
        seed(),
    )

    assert relation.relation is DuplicateRelation.RELATED
    assert relation.matched_pages == 10


def test_page_count_boundary_rejects_excessive_difference() -> None:
    relation = match_candidate(
        page_set(1, ("a", "b", "c")),
        page_set(2, ("x", "a", "b", "c", "y", "z")),
        seed(),
    )

    assert relation.relation is DuplicateRelation.RELATED


def test_short_archives_require_at_least_three_matched_pages() -> None:
    relation = match_candidate(page_set(1, ("a", "b")), page_set(2, ("x", "a", "b")), seed())

    assert relation.relation is DuplicateRelation.RELATED
    assert relation.matched_pages == 2


def test_unstable_snapshot_is_not_misclassified_as_a_duplicate_relation() -> None:
    relation = match_candidate(
        page_set(1, ("a", "b", "c"), snapshot_stable=False, stability_error="SOURCE_CHANGED"),
        page_set(2, ("a", "b", "c")),
        seed(),
    )

    assert relation.relation is DuplicateRelation.RELATED
    assert relation.recommendation == "MANUAL"
    assert relation.matched_pages == 0
    assert "SOURCE_CHANGED" in relation.reasons


def test_seed_must_describe_the_same_normalized_pair() -> None:
    with pytest.raises(ValueError, match="Candidate seed endpoints"):
        match_candidate(page_set(1, ("a",)), page_set(2, ("a",)), seed(1, 3))


def test_pair_result_is_deterministic_when_input_order_is_reversed() -> None:
    left = page_set(1, ("a", "b", "c"))
    right = page_set(2, ("a", "b", "c"))

    assert match_candidate(left, right, seed()) == match_candidate(right, left, seed(2, 1))


def test_matcher_runs_cooperative_checkpoints() -> None:
    calls = 0

    def cancel() -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("cancelled")

    values = tuple(str(index) for index in range(401))
    with pytest.raises(RuntimeError, match="cancelled"):
        match_candidate(
            page_set(1, values),
            page_set(2, values),
            seed(),
            checkpoint=cancel,
        )
