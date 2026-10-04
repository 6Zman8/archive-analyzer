from __future__ import annotations

from pathlib import Path
from dataclasses import replace

import pytest

from archive_analyzer.precision_analysis import DetectedLanguage, PairDirection
from archive_analyzer.recommendation import (
    CriterionResult,
    PairEvidence,
    RecommendationInput,
    RecommendationStatus,
    compare_pair,
    recommend_candidate_set,
    title_structure_rank,
)


def candidate(
    archive_id: int = 1,
    *,
    area: int | None = 1_000_000,
    size: int | None = 1_000,
    pages: int | None = 20,
    mtime_ns: int | None = 0,
    name: str | None = "[Circle(Artist)] Title (extra).cbz",
    title_rank: int | None = None,
    language: DetectedLanguage = DetectedLanguage.ENGLISH,
    mosaic_rank: int | None = None,
) -> RecommendationInput:
    path = Path(name) if name is not None else Path()
    return RecommendationInput(
        archive_id=archive_id,
        path=path,
        file_size=size,
        page_count=pages,
        mtime_ns=mtime_ns,
        resolution_area=area,
        title_rank=title_rank if title_rank is not None else title_structure_rank(path),
        language=language,
        mosaic_rank=mosaic_rank,
        evidence_sources={},
    )


def evidence_for(*inputs: RecommendationInput, mosaic=PairDirection.TIE, quality=PairDirection.TIE):
    return {
        (left.archive_id, right.archive_id): PairEvidence(
            left_archive_id=left.archive_id,
            right_archive_id=right.archive_id,
            mosaic=mosaic,
            quality=quality,
        )
        for left in inputs
        for right in inputs
        if left.archive_id < right.archive_id
    }


def test_small_numeric_differences_are_ties() -> None:
    left = candidate(size=1_000, area=1_000_000, pages=20, mtime_ns=0)
    right = candidate(2, size=990, area=980_000, pages=20, mtime_ns=2_000_000_000)

    results = compare_pair(left, right, PairEvidence(1, 2, PairDirection.TIE, PairDirection.TIE))

    assert results["size"] is CriterionResult.TIE
    assert results["resolution"] is CriterionResult.TIE
    assert results["mtime"] is CriterionResult.TIE


@pytest.mark.parametrize(
    ("criterion", "left", "right"),
    [
        ("size", candidate(size=1_000), candidate(2, size=1_011)),
        ("resolution", candidate(area=1_000_000), candidate(2, area=1_021_000)),
        ("mtime", candidate(mtime_ns=0), candidate(2, mtime_ns=2_000_000_001)),
    ],
)
def test_just_outside_numeric_boundaries_are_directional(
    criterion: str, left: RecommendationInput, right: RecommendationInput
) -> None:
    result = compare_pair(left, right, PairEvidence(1, 2, PairDirection.TIE, PairDirection.TIE))
    assert result[criterion] is CriterionResult.RIGHT_BETTER


def test_page_count_requires_exact_equality() -> None:
    result = compare_pair(candidate(pages=20), candidate(2, pages=21), PairEvidence(1, 2, PairDirection.TIE, PairDirection.TIE))
    assert result["pages"] is CriterionResult.RIGHT_BETTER


def test_filename_structure_normalizes_nfkc_and_ranks_fallbacks() -> None:
    assert title_structure_rank(Path("［Circle（Artist）］ Title (extra).cbz")) == 3
    assert title_structure_rank(Path("[Circle] Title.cbz")) == 2
    assert title_structure_rank(Path("Title.cbz")) == 1
    assert title_structure_rank(Path("   .cbz")) == 0


def test_language_order_prefers_korean_then_japanese_english_chinese_other() -> None:
    ordered = [
        DetectedLanguage.KOREAN,
        DetectedLanguage.JAPANESE,
        DetectedLanguage.ENGLISH,
        DetectedLanguage.CHINESE,
        DetectedLanguage.OTHER,
    ]
    for index, language in enumerate(ordered[:-1]):
        result = compare_pair(
            candidate(language=language),
            candidate(2, language=ordered[index + 1]),
            PairEvidence(1, 2, PairDirection.TIE, PairDirection.TIE),
        )
        assert result["language"] is CriterionResult.LEFT_BETTER


def test_pair_direction_is_reoriented_to_caller_ids() -> None:
    evidence = PairEvidence(1, 2, PairDirection.LEFT_BETTER, PairDirection.RIGHT_BETTER)
    result = compare_pair(candidate(2), candidate(1), evidence)

    assert result["mosaic"] is CriterionResult.TIE
    assert result["quality"] is CriterionResult.TIE


def test_unknown_precision_evidence_requires_analysis() -> None:
    left, right = candidate(), candidate(2)
    decision = recommend_candidate_set(
        (left, right), evidence_for(left, right, mosaic=PairDirection.UNKNOWN)
    )
    assert decision.status is RecommendationStatus.NONE
    assert all(item.recommendation == "NONE" for item in decision.items)


def test_missing_base_evidence_is_uncertain() -> None:
    left, right = candidate(area=None), candidate(2)
    decision = recommend_candidate_set((left, right), evidence_for(left, right))
    assert decision.status is RecommendationStatus.ANALYSIS_REQUIRED
    assert "resolution" in decision.items[0].reason


def test_unknown_language_requires_analysis() -> None:
    left, right = candidate(language=DetectedLanguage.UNKNOWN), candidate(2)
    decision = recommend_candidate_set((left, right), evidence_for(left, right))
    assert decision.status is RecommendationStatus.ANALYSIS_REQUIRED


def test_page_count_and_resolution_conflict_requires_review() -> None:
    left = candidate(area=2_000_000, pages=20)
    right = candidate(2, area=1_000_000, pages=21)
    decision = recommend_candidate_set((left, right), evidence_for(left, right))

    assert decision.status is RecommendationStatus.NONE
    assert all(item.recommendation == "NONE" for item in decision.items)


def test_exact_content_unknown_language_uses_confirmed_latest_exception() -> None:
    left = candidate(
        name="work.zip",
        mtime_ns=1_700_000_000_000_000_000,
        language=DetectedLanguage.UNKNOWN,
    )
    right = candidate(
        2,
        name="[Circle(Author)] Work (Korean).zip",
        mtime_ns=1_700_000_010_000_000_000,
        language=DetectedLanguage.UNKNOWN,
    )
    evidence = PairEvidence(
        1,
        2,
        PairDirection.UNKNOWN,
        PairDirection.UNKNOWN,
        content_equivalent=True,
    )

    left = replace(left, evidence_sources={'language':'precision_unknown'})
    right = replace(right, evidence_sources={'language':'precision_unknown'})
    decision = recommend_candidate_set((left, right), {(1, 2): evidence})

    assert decision.status is RecommendationStatus.RECOMMENDED
    assert decision.items[1].recommendation == "KEEP"
    assert decision.items[1].criteria["title"] is CriterionResult.LEFT_BETTER
    assert decision.items[1].criteria["mtime"] is CriterionResult.LEFT_BETTER
    assert decision.items[1].criteria["language"] is CriterionResult.TIE
    assert decision.items[1].criteria["mosaic"] is CriterionResult.TIE
    assert decision.items[1].criteria["quality"] is CriterionResult.TIE


def test_filename_mosaic_rank_is_used_only_when_precision_is_unknown() -> None:
    left = candidate(mosaic_rank=3)
    right = candidate(2, mosaic_rank=1)

    fallback = compare_pair(
        left,
        right,
        PairEvidence(1, 2, PairDirection.UNKNOWN, PairDirection.TIE),
    )
    precision = compare_pair(
        left,
        right,
        PairEvidence(1, 2, PairDirection.RIGHT_BETTER, PairDirection.TIE),
    )

    assert fallback["mosaic"] is CriterionResult.LEFT_BETTER
    assert precision["mosaic"] is CriterionResult.LEFT_BETTER


def test_non_transitive_preferences_have_no_unique_winner() -> None:
    left = candidate(area=1_000, size=1_000, mtime_ns=0, title_rank=1)
    middle = candidate(2, area=970, size=1_005, mtime_ns=1_500_000_000, title_rank=1)
    right = candidate(3, area=989, size=990, mtime_ns=3_000_000_000, title_rank=1)
    decision = recommend_candidate_set(
        (left, middle, right), evidence_for(left, middle, right)
    )

    assert decision.status is RecommendationStatus.NONE
    assert all(item.recommendation == "NONE" for item in decision.items)


def test_unique_three_file_dominator_is_keep_and_rest_remove_candidates() -> None:
    winner = candidate(
        area=2_000_000,
        size=2_000,
        pages=21,
        mtime_ns=4_000_000_000,
        title_rank=3,
        language=DetectedLanguage.KOREAN,
    )
    second = candidate(
        2,
        area=1_000_000,
        size=1_000,
        pages=20,
        mtime_ns=0,
        title_rank=2,
        language=DetectedLanguage.ENGLISH,
    )
    third = candidate(
        3,
        area=500_000,
        size=500,
        pages=19,
        mtime_ns=0,
        title_rank=1,
        language=DetectedLanguage.CHINESE,
    )

    decision = recommend_candidate_set(
        (third, winner, second), evidence_for(third, winner, second)
    )

    assert decision.status is RecommendationStatus.RECOMMENDED
    assert [(item.archive_id, item.recommendation) for item in decision.items] == [
        (1, "KEEP"),
        (2, "REMOVE_CANDIDATE"),
        (3, "REMOVE_CANDIDATE"),
    ]


def test_middle_item_exposes_mixed_criteria_against_different_opponents() -> None:
    winner = candidate(
        area=2_000_000,
        size=2_000,
        pages=21,
        mtime_ns=4_000_000_000,
        title_rank=3,
        language=DetectedLanguage.KOREAN,
    )
    middle = candidate(2, title_rank=2, language=DetectedLanguage.ENGLISH)
    third = candidate(3, title_rank=1, language=DetectedLanguage.CHINESE)

    decision = recommend_candidate_set(
        (winner, middle, third), evidence_for(winner, middle, third)
    )
    item = decision.items[1]

    assert item.criteria["title"] is CriterionResult.MIXED
    assert item.criteria["language"] is CriterionResult.MIXED
    assert "mixed:title,language" in item.reason


def test_single_archive_has_no_recommendation() -> None:
    decision = recommend_candidate_set((candidate(),), {})
    assert decision.status is RecommendationStatus.NONE
