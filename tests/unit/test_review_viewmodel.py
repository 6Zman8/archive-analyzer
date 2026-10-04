from pathlib import Path

from archive_analyzer.domain import ArchiveFormat
from archive_analyzer.duplicate_domain import DuplicateRelation, ReviewAction
from archive_analyzer.edition_analysis import EditionFlag, EditionKind
from archive_analyzer.filename_normalization import FilenameSignal
from archive_analyzer.review_viewmodel import build_group_view
from archive_analyzer.sequence_matching import SequenceRelation
from archive_analyzer.storage.duplicate_repository import (
    CandidateGroupDetail,
    CandidateGroupMember,
    CandidateRelationRecord,
    RecommendationRecord,
    ReviewGroupDetail,
)


def test_exact_content_view_explains_page_and_resolution_evidence() -> None:
    """Breaks if exact-content evidence is hidden or a keep recommendation is lost."""
    view = build_group_view(
        CandidateGroupDetail(
            group_key="exact-content",
            members=(
                CandidateGroupMember(
                    archive_id=1,
                    path=Path(r"C:\\source\\small.cbz"),
                    file_size=100,
                    mtime_ns=10,
                    archive_format=ArchiveFormat.CBZ,
                    review_action=None,
                    needs_review=False,
                    image_count=3,
                    representative_width=1000,
                    representative_height=1000,
                ),
                CandidateGroupMember(
                    archive_id=2,
                    path=Path(r"C:\\source\\large.cbz"),
                    file_size=200,
                    mtime_ns=20,
                    archive_format=ArchiveFormat.CBZ,
                    review_action=ReviewAction.KEEP,
                    needs_review=False,
                    image_count=3,
                    representative_width=2000,
                    representative_height=1000,
                ),
            ),
            relations=(
                CandidateRelationRecord(
                    archive_a_id=1,
                    archive_b_id=2,
                    relation=DuplicateRelation.EXACT_CONTENT,
                    confidence=1.0,
                    matched_pages=3,
                    left_pages=3,
                    right_pages=3,
                    recommendation="KEEP_RIGHT_HIGHER_RESOLUTION",
                    reasons=(
                        "ALL_PIXEL_SHA256_IN_ORDER",
                        "RIGHT_MEDIAN_PIXEL_AREA_AT_LEAST_15_PERCENT_LARGER",
                    ),
                ),
            ),
            strongest_relation=DuplicateRelation.EXACT_CONTENT,
            confidence=1.0,
            analyzer_version=1,
            needs_review=False,
            recommended_archive_id=2,
        )
    )

    assert view.relation_text == "내용 동일"
    assert "전체 페이지" in view.reason_text
    assert "해상도" in view.reason_text
    assert view.recommended_archive_id is None
    assert view.recommendation_text == "추천 상태를 확인할 수 없음"
    assert view.members[0].file_name == "small.cbz"
    assert view.members[1].representative_resolution == (2000, 1000)
    assert view.members[1].user_decision is ReviewAction.KEEP


def test_related_or_stale_group_has_no_automatic_keep_recommendation() -> None:
    """Breaks if uncertain or stale evidence is presented as an automatic keep choice."""
    related = CandidateGroupDetail(
        group_key="related",
        members=(
            CandidateGroupMember(1, Path("one.cbz"), 1, 1, ArchiveFormat.CBZ, None, False),
            CandidateGroupMember(2, Path("two.cbz"), 1, 1, ArchiveFormat.CBZ, None, True),
        ),
        relations=(
            CandidateRelationRecord(
                1,
                2,
                DuplicateRelation.RELATED,
                0.5,
                1,
                3,
                3,
                "MANUAL",
                ("PROBE_HASH_NEAR",),
            ),
        ),
        strongest_relation=DuplicateRelation.RELATED,
        confidence=0.5,
        analyzer_version=1,
        needs_review=True,
        recommended_archive_id=1,
    )

    view = build_group_view(related)

    assert view.relation_text == "확인 필요"
    assert view.needs_review
    assert view.recommended_archive_id is None
    assert view.recommendation_text == "추천 상태를 확인할 수 없음"
    assert "파일명" not in view.reason_text


def test_exact_archive_view_does_not_choose_a_path_as_the_automatic_keep() -> None:
    """Breaks if equal archive paths receive an arbitrary automatic keep choice."""
    exact_archive = CandidateGroupDetail(
        group_key="exact-archive",
        members=(
            CandidateGroupMember(1, Path("one.cbz"), 1, 1, ArchiveFormat.CBZ, None, False),
            CandidateGroupMember(2, Path("two.cbz"), 1, 1, ArchiveFormat.CBZ, None, False),
        ),
        relations=(
            CandidateRelationRecord(
                1,
                2,
                DuplicateRelation.EXACT_ARCHIVE,
                1.0,
                3,
                3,
                3,
                "KEEP_LEFT_HIGHER_RESOLUTION",
                ("IDENTICAL_ARCHIVE_SHA256",),
            ),
        ),
        strongest_relation=DuplicateRelation.EXACT_ARCHIVE,
        confidence=1.0,
        analyzer_version=1,
        needs_review=False,
        recommended_archive_id=1,
    )

    view = build_group_view(exact_archive)
    assert view.recommended_archive_id is None
    assert view.recommendation_text == "추천 상태를 확인할 수 없음"


def test_mixed_edge_group_keeps_each_direct_relation_with_its_endpoints() -> None:
    """Breaks if A-B evidence is presented as a transitive A-C relation."""
    view = build_group_view(
        CandidateGroupDetail(
            group_key="mixed",
            members=(
                CandidateGroupMember(1, Path("A.cbz"), 1, 1, ArchiveFormat.CBZ, None, False),
                CandidateGroupMember(2, Path("B.cbz"), 1, 1, ArchiveFormat.CBZ, None, False),
                CandidateGroupMember(3, Path("C.cbz"), 1, 1, ArchiveFormat.CBZ, None, False),
            ),
            relations=(
                CandidateRelationRecord(
                    1,
                    2,
                    DuplicateRelation.EXACT_CONTENT,
                    1.0,
                    3,
                    3,
                    3,
                    "KEEP_RIGHT_HIGHER_RESOLUTION",
                    (
                        "ALL_PIXEL_SHA256_IN_ORDER",
                        "RIGHT_MEDIAN_PIXEL_AREA_AT_LEAST_15_PERCENT_LARGER",
                    ),
                ),
                CandidateRelationRecord(
                    2,
                    3,
                    DuplicateRelation.RELATED,
                    0.5,
                    1,
                    3,
                    3,
                    "MANUAL",
                    ("PROBE_HASH_NEAR",),
                ),
            ),
            strongest_relation=DuplicateRelation.EXACT_CONTENT,
            confidence=1.0,
            analyzer_version=1,
            needs_review=False,
            recommended_archive_id=None,
        )
    )

    assert view.relation_text == "후보 그룹 (그룹 내 최강 직접 비교: 내용 동일)"
    assert view.reason_text == "구성원별 직접 비교를 확인하세요."
    assert [(edge.left_archive_id, edge.right_archive_id, edge.relation_text) for edge in view.edges] == [
        (1, 2, "내용 동일"),
        (2, 3, "확인 필요"),
    ]
    assert "2번 파일" in view.edges[0].reason_text
    assert "대표 이미지 지문이 유사" in view.edges[1].reason_text
    assert all(".cbz" not in edge.reason_text for edge in view.edges)
    assert (view.edges[0].left_member_number, view.edges[0].right_member_number) == (1, 2)
    assert (view.edges[1].left_member_number, view.edges[1].right_member_number) == (2, 3)


def test_sequence_relation_shows_container_and_alignment_pairs() -> None:
    view = build_group_view(
        CandidateGroupDetail(
            group_key="contains",
            members=(
                CandidateGroupMember(
                    1, Path("small.cbz"), 10, 1, ArchiveFormat.CBZ, None, False
                ),
                CandidateGroupMember(
                    2, Path("omnibus.cbz"), 20, 2, ArchiveFormat.CBZ, None, False
                ),
            ),
            relations=(
                CandidateRelationRecord(
                    1,
                    2,
                    DuplicateRelation.RELATED,
                    0.8,
                    4,
                    4,
                    8,
                    "MANUAL",
                    ("PROBE_HASH_NEAR",),
                    sequence_relation=SequenceRelation.CONTAINS,
                    container_archive_id=2,
                    matched_pairs=((0, 2), (1, 3), (2, 4), (3, 5)),
                    left_coverage=1.0,
                    right_coverage=0.5,
                ),
            ),
            strongest_relation=DuplicateRelation.RELATED,
            confidence=0.8,
            analyzer_version=2,
            needs_review=False,
            recommended_archive_id=None,
        )
    )

    assert view.relation_text == "합본·개별권 포함"
    assert view.edges[0].relation_text == "합본·개별권 포함"
    assert "2번 파일 안에 1번 파일" in view.edges[0].reason_text
    assert view.edges[0].matched_pairs[0] == (0, 2)


def test_edition_difference_is_visible_and_marks_group_for_preservation() -> None:
    view = build_group_view(
        CandidateGroupDetail(
            group_key="edition",
            members=(
                CandidateGroupMember(
                    1, Path("mono.cbz"), 10, 1, ArchiveFormat.CBZ, None, False
                ),
                CandidateGroupMember(
                    2, Path("color.cbz"), 20, 2, ArchiveFormat.CBZ, None, False
                ),
            ),
            relations=(
                CandidateRelationRecord(
                    1,
                    2,
                    DuplicateRelation.VISUAL_VARIANT,
                    0.9,
                    6,
                    6,
                    6,
                    "MANUAL",
                    ("PROBE_HASH_NEAR",),
                    edition_flags=(EditionFlag.COLOR_MONO,),
                    edition_summary="컬러판·흑백판 차이",
                    preserve_required=True,
                ),
            ),
            strongest_relation=DuplicateRelation.VISUAL_VARIANT,
            confidence=0.9,
            analyzer_version=1,
            needs_review=False,
            recommended_archive_id=None,
        )
    )

    assert view.preserve_required
    assert view.review_status_text == "판본 보존"
    assert view.edges[0].edition_flags == (EditionFlag.COLOR_MONO,)
    assert "컬러판·흑백판" in view.edges[0].reason_text


def test_derived_set_member_numbers_are_stable_and_paths_are_split() -> None:
    view = build_group_view(
        ReviewGroupDetail(
            set_key="color-set",
            source_group_key="source-group",
            edition_kind=EditionKind.FULL_COLOR,
            members=(
                CandidateGroupMember(30, Path(r"C:\\archive\\c.cbz"), 30, 3, ArchiveFormat.CBZ, None, False),
                CandidateGroupMember(10, Path(r"C:\\archive\\a.cbz"), 10, 1, ArchiveFormat.CBZ, None, False),
                CandidateGroupMember(20, Path(r"C:\\archive\\b.cbz"), 20, 2, ArchiveFormat.CBZ, None, False),
            ),
            relations=(),
            recommendation_status="NONE",
        )
    )

    assert [(member.member_number, member.file_name) for member in view.members] == [
        (1, "a.cbz"),
        (2, "b.cbz"),
        (3, "c.cbz"),
    ]
    assert all("번" not in member.file_name for member in view.members)
    assert all(member.directory == Path(r"C:\\archive") for member in view.members)
    assert view.group_key == "color-set"
    assert view.source_group_key == "source-group"


def test_review_and_file_operation_statuses_are_separate() -> None:
    view = build_group_view(
        ReviewGroupDetail(
            set_key="set",
            source_group_key="source",
            edition_kind=EditionKind.MONOCHROME,
            members=(
                CandidateGroupMember(
                    1,
                    Path("one.cbz"),
                    1,
                    1,
                    ArchiveFormat.CBZ,
                    ReviewAction.REMOVE_CANDIDATE,
                    False,
                    quarantine_status="QUARANTINED",
                ),
            ),
            relations=(),
            recommendation_status="RECOMMENDED",
        )
    )

    member = view.members[0]
    assert member.review_status_text == "제거 후보"
    assert member.file_operation_status_text == "격리됨"
    assert view.review_status_text == "제거 후보 1"


def test_recommendation_statuses_have_distinct_honest_korean_text() -> None:
    expected = {
        "UNKNOWN": "추천 상태를 확인할 수 없음",
        "ANALYSIS_REQUIRED": "검토 필요 · 정밀분석 필요",
        "CONFLICT": "검토 필요 · 기준 충돌",
        "NONE": "검토 필요 · 확실한 우위 없음",
    }
    for status, text in expected.items():
        view = build_group_view(
            ReviewGroupDetail(
                set_key=f"set-{status}",
                source_group_key="source",
                edition_kind=EditionKind.FULL_COLOR,
                members=(
                    CandidateGroupMember(1, Path("one.cbz"), 1, 1, ArchiveFormat.CBZ, None, False),
                ),
                relations=(),
                recommendation_status=status,
            )
        )
        assert view.recommendation_text == text


def test_member_evidence_values_show_sources_and_conflicts() -> None:
    filename_korean = FilenameSignal("KOREAN", 0.9, frozenset({"korean"}), False)
    filename_japanese = FilenameSignal("JAPANESE", 0.9, frozenset({"japanese"}), False)
    filename_color = FilenameSignal("FULL_COLOR", 0.9, frozenset({"color"}), False)
    filename_mosaic = FilenameSignal("UNCENSORED", 0.9, frozenset({"uncensored"}), False)
    view = build_group_view(
        ReviewGroupDetail(
            set_key="set",
            source_group_key="source",
            edition_kind=EditionKind.FULL_COLOR,
            members=(
                CandidateGroupMember(
                    1, Path("one Korean color uncensored.cbz"), 1, 1,
                    ArchiveFormat.CBZ, None, False,
                    filename_language=filename_korean,
                    filename_color=filename_color,
                    filename_mosaic=filename_mosaic,
                ),
                CandidateGroupMember(
                    2, Path("two Japanese.cbz"), 1, 1,
                    ArchiveFormat.CBZ, None, False,
                    filename_language=filename_japanese,
                    precision_language="KOREAN",
                    precision_language_confidence=0.95,
                    color_page_ratio=0.8,
                ),
                CandidateGroupMember(
                    3, Path("three.cbz"), 1, 1,
                    ArchiveFormat.CBZ, None, False,
                    filename_language=filename_korean,
                    precision_language="KOREAN",
                    precision_language_confidence=0.95,
                ),
                CandidateGroupMember(
                    4, Path("four color.cbz"), 1, 1,
                    ArchiveFormat.CBZ, None, False,
                    filename_color=filename_color,
                    color_page_ratio=0.30,
                ),
            ),
            relations=(),
            recommendation_status="ANALYSIS_REQUIRED",
        )
    )

    assert view.members[0].language_text == "한국어 (파일명 추정)"
    assert view.members[0].color_text == "풀컬러 (파일명 추정)"
    assert view.members[0].mosaic_text == "무수정 표기 (파일명 추정)"
    assert view.members[1].language_text == "파일명 일본어 / 정밀분석 한국어 (충돌)"
    assert view.members[1].color_text == "풀컬러 (정밀분석 완료)"
    assert view.members[2].language_text == "한국어 (정밀분석)"
    assert view.members[3].color_text == "풀컬러 (파일명 추정)"


def test_direct_relation_rows_do_not_repeat_legacy_edge_recommendation() -> None:
    view = build_group_view(
        CandidateGroupDetail(
            group_key="visual",
            members=(
                CandidateGroupMember(1, Path("one.cbz"), 1, 1, ArchiveFormat.CBZ, None, False),
                CandidateGroupMember(2, Path("two.cbz"), 1, 1, ArchiveFormat.CBZ, None, False),
            ),
            relations=(
                CandidateRelationRecord(
                    1, 2, DuplicateRelation.VISUAL_VARIANT, 0.9, 3, 3, 3,
                    "MANUAL", ("MEDIAN_PIXEL_AREA_DIFFERENCE_BELOW_15_PERCENT",),
                ),
            ),
            strongest_relation=DuplicateRelation.VISUAL_VARIANT,
            confidence=0.9,
            analyzer_version=1,
            needs_review=False,
            recommended_archive_id=None,
        )
    )

    assert "해상도 차이 15% 미만" not in view.recommendation_text
    assert "해상도 차이 15% 미만" not in view.edges[0].recommendation_text


def test_current_set_recommendation_names_dominant_criteria() -> None:
    members = (
        CandidateGroupMember(1, Path("one.cbz"), 100, 1, ArchiveFormat.CBZ, None, False),
        CandidateGroupMember(2, Path("two.cbz"), 100, 10_000_000_001, ArchiveFormat.CBZ, None, False),
    )
    records = (
        RecommendationRecord(
            1, "set", "source", 1, "REMOVE_CANDIDATE", "RECOMMENDED",
            {"title": "RIGHT_BETTER", "mtime": "RIGHT_BETTER"},
            "dominated_by:2", 100, 1,
        ),
        RecommendationRecord(
            2, "set", "source", 2, "KEEP", "RECOMMENDED",
            {"title": "LEFT_BETTER", "mtime": "LEFT_BETTER"},
            "unique_dominator", 100, 10_000_000_001,
        ),
    )

    view = build_group_view(
        ReviewGroupDetail(
            "set", "source", EditionKind.FULL_COLOR, members, (), "RECOMMENDED", records
        )
    )

    assert view.recommended_archive_id == 2
    assert view.recommendation_text == "보존 추천: 2번 파일 (제목 구조·수정 시각 우세)"
    assert view.members[1].recommendation_text == "보존 추천: 제목 구조·수정 시각 우세"
