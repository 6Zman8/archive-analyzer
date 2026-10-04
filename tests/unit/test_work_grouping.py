from dataclasses import replace
from pathlib import Path

from archive_analyzer.domain import ArchiveFormat
from archive_analyzer.review_viewmodel import GroupRow, MemberRow
from archive_analyzer.work_grouping import filter_and_sort_groups, work_label


def _group(label: str, confidence: float, archive_id: int) -> GroupRow:
    member = MemberRow(
        archive_id=archive_id,
        file_name=f"{label}.cbz",
        path=Path(f"C:/source/{label}.cbz"),
        archive_format=ArchiveFormat.CBZ,
        file_size=100,
        page_count=10,
        representative_resolution=None,
        user_decision=None,
        needs_review=False,
    )
    return GroupRow(
        group_key=f"group-{archive_id}",
        relation_text="확인 필요",
        confidence=confidence,
        reason_text="근거",
        recommended_archive_id=None,
        recommendation_text="자동 보존 추천 없음",
        needs_review=False,
        review_status_text="검토 가능",
        members=(member,),
        edges=(),
        work_label=label,
    )


def test_work_label_preserves_volume_and_all_edition_markers() -> None:
    assert work_label(
        (
            Path("작품 이름 제01권 [컬러판].cbz"),
            Path("작품 이름 vol.2 [흑백판].zip"),
        )
    ) == "[ㅁㅁㅁㅁ(ㅁㅁㅁㅁ)] 작품 이름 제01권 / 작품 이름 vol.2 (컬러판 / 흑백판)"


def test_group_filter_searches_paths_and_sorts_by_confidence() -> None:
    low = _group("작품 가", 0.5, 1)
    high = replace(_group("작품 나", 0.9, 2), relation_text="합본·개별권 포함")

    assert filter_and_sort_groups((low, high), "합본", "confidence") == (high,)
    assert filter_and_sort_groups((low, high), "", "confidence") == (high, low)


def test_group_filter_searches_recommendation_text() -> None:
    group = replace(_group("작품", 0.9, 1), recommendation_text="보존 추천")

    assert filter_and_sort_groups((group,), "보존 추천", "work") == (group,)


def test_full_group_title_combines_all_candidates_and_fills_missing_fields():
    assert work_label((Path("[작가명] 작품명.zip"),
                       Path("[서클명(작가명)] 작품명 (컬러) [번역].cbz"))) == (
        "[서클명(작가명)] 작품명 (컬러 / 번역)"
    )
    assert work_label((Path("[작가명] 작품명.zip"),)) == "[ㅁㅁㅁㅁ(작가명)] 작품명 (ㅁㅁㅁㅁ)"
    assert work_label(()) == "[ㅁㅁㅁㅁ(ㅁㅁㅁㅁ)] ㅁㅁㅁㅁ (ㅁㅁㅁㅁ)"


def test_full_title_keeps_case_punctuation_and_long_names():
    title = "The Long Title: One Two Three Four Five Six Seven Eight Nine!"
    assert work_label((Path(f"[Circle(Author)] {title} (Full Color).zip"),)) == (
        f"[Circle(Author)] {title} (Full Color)"
    )


def test_placeholder_does_not_hide_known_information_or_conflicting_variants():
    assert work_label((Path("[ㅁㅁㅁㅁ(작가)] 작품 (ㅁㅁㅁㅁ).zip"),
                       Path("[서클(작가)] 작품 (컬러).zip"),
                       Path("[서클(작가)] 작품 (흑백).zip"))) == "[서클(작가)] 작품 (컬러 / 흑백)"


def test_event_prefix_and_nested_suffix_are_retained():
    assert work_label((Path("(C100) [Circle(Author)] Book (Series (Extra)) [English].zip"),)) == (
        "[Circle(Author)] Book (C100 / Series (Extra) / English)"
    )
