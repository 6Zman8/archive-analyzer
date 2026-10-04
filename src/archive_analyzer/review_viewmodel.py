from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from archive_analyzer.domain import ArchiveFormat
from archive_analyzer.duplicate_domain import DuplicateRelation, ReviewAction
from archive_analyzer.edition_analysis import EditionFlag, EditionKind
from archive_analyzer.filename_normalization import FilenameSignal
from archive_analyzer.precision_analysis import DetectedLanguage
from archive_analyzer.sequence_matching import SequenceRelation
from archive_analyzer.storage.duplicate_repository import (
    CandidateGroupDetail,
    RecommendationRecord,
    ReviewGroupDetail,
)
from archive_analyzer.work_grouping import work_label


RELATION_LABELS = {
    DuplicateRelation.EXACT_ARCHIVE: "완전히 동일",
    DuplicateRelation.EXACT_CONTENT: "내용 동일",
    DuplicateRelation.VISUAL_VARIANT: "재압축·리사이즈 후보",
    DuplicateRelation.RELATED: "확인 필요",
}


@dataclass(frozen=True, slots=True)
class MemberRow:
    archive_id: int
    file_name: str
    path: Path
    archive_format: ArchiveFormat
    file_size: int
    page_count: int | None
    representative_resolution: tuple[int, int] | None
    user_decision: ReviewAction | None
    needs_review: bool
    mtime_ns: int = 0
    quarantine_item_id: int | None = None
    quarantine_status: str | None = None
    quarantine_path: Path | None = None
    deletion_state: str | None = None
    member_number: int = 0
    directory: Path | None = None
    language_text: str = "정보 없음"
    color_text: str = "정보 없음"
    mosaic_text: str = "정보 없음"
    quality_text: str = "정보 없음"
    review_status_text: str = "미검토"
    file_operation_status_text: str = "원위치"
    recommendation_text: str = "추천 상태를 확인할 수 없음"

    def __post_init__(self) -> None:
        if self.directory is None:
            object.__setattr__(self, "directory", self.path.parent)


@dataclass(frozen=True, slots=True)
class EdgeRow:
    left_archive_id: int
    left_file_name: str
    right_archive_id: int
    right_file_name: str
    relation_text: str
    confidence: float
    reason_text: str
    recommendation: str
    recommendation_text: str
    matched_pages: int
    left_page_count: int
    right_page_count: int
    matched_pairs: tuple[tuple[int, int], ...] = ()
    sequence_relation: SequenceRelation | None = None
    container_archive_id: int | None = None
    left_coverage: float = 0.0
    right_coverage: float = 0.0
    edition_flags: tuple[EditionFlag, ...] = ()
    edition_summary: str | None = None
    preserve_required: bool = False
    left_member_number: int = 0
    right_member_number: int = 0


@dataclass(frozen=True, slots=True)
class GroupRow:
    group_key: str
    relation_text: str
    confidence: float
    reason_text: str
    recommended_archive_id: int | None
    recommendation_text: str
    needs_review: bool
    review_status_text: str
    members: tuple[MemberRow, ...]
    edges: tuple[EdgeRow, ...]
    work_label: str = ""
    preserve_required: bool = False
    source_group_key: str = ""
    set_key: str = ""
    edition_kind: EditionKind | None = None
    recommendation_status: str = "UNKNOWN"
    reviewed_at: str = ""
    quarantined_at: str = ""
    deleted_at: str = ""


def build_group_view(group: CandidateGroupDetail | ReviewGroupDetail) -> GroupRow:
    """Translate one source group or derived edition set into display values."""

    is_derived_set = isinstance(group, ReviewGroupDetail)
    recommendations = (
        {record.archive_id: record for record in group.recommendations}
        if is_derived_set
        else {}
    )
    members = tuple(
        MemberRow(
            archive_id=member.archive_id,
            file_name=member.path.name,
            path=(member.quarantine_path if member.quarantine_status == "QUARANTINED"
                  and member.quarantine_path is not None else member.path),
            archive_format=member.archive_format,
            file_size=member.file_size,
            page_count=member.image_count,
            representative_resolution=(member.representative_width, member.representative_height)
            if member.representative_width is not None and member.representative_height is not None
            else None,
            user_decision=member.review_action,
            needs_review=member.needs_review or member.quarantine_status == "FAILED",
            mtime_ns=member.mtime_ns,
            quarantine_item_id=member.quarantine_item_id,
            quarantine_status=member.quarantine_status,
            quarantine_path=member.quarantine_path,
            deletion_state=member.deletion_state,
            member_number=index,
            directory=(member.quarantine_path.parent if member.quarantine_status == "QUARANTINED"
                       and member.quarantine_path is not None else member.path.parent),
            language_text=_language_evidence_text(member),
            color_text=_color_evidence_text(member),
            mosaic_text=_mosaic_evidence_text(member.filename_mosaic),
            quality_text=_criterion_text(recommendations.get(member.archive_id), "quality"),
            review_status_text=_member_review_status(member),
            file_operation_status_text=_file_operation_status(member),
            recommendation_text=(
                _member_recommendation_text(recommendations.get(member.archive_id), group.recommendation_status)
                if is_derived_set
                else "추천 상태를 확인할 수 없음"
            ),
        )
        for index, member in enumerate(sorted(group.members, key=lambda item: item.archive_id), start=1)
    )
    member_names = {member.archive_id: member.file_name for member in members}
    member_numbers = {
        member.archive_id: index for index, member in enumerate(members, start=1)
    }
    edges = tuple(
        _edge_row(relation, member_names, member_numbers, include_file_names=not is_derived_set)
        for relation in sorted(
            group.relations, key=lambda item: (item.archive_a_id, item.archive_b_id)
        )
    )
    preserve_required = any(edge.preserve_required for edge in edges)
    keep_ids = tuple(record.archive_id for record in group.recommendations if record.recommendation == "KEEP") if is_derived_set else ()
    recommended_archive_id = keep_ids[0] if len(keep_ids) == 1 and group.recommendation_status == "RECOMMENDED" else None
    return GroupRow(
        group_key=group.set_key if is_derived_set else group.group_key,
        relation_text=_group_relation_text(group),
        confidence=max((edge.confidence for edge in edges), default=0.0) if is_derived_set else group.confidence,
        reason_text=(
            edges[0].reason_text
            if len(group.members) == 2 and len(edges) == 1
            else "구성원별 직접 비교를 확인하세요."
        ),
        recommended_archive_id=recommended_archive_id,
        recommendation_text=(
            _derived_group_recommendation_text(
                group.recommendation_status, group.recommendations, member_numbers
            )
            if is_derived_set
            else "추천 상태를 확인할 수 없음"
        ),
        needs_review=(any(member.needs_review or member.review_action is None for member in group.members)
                      if is_derived_set else group.needs_review),
        review_status_text=(_group_review_status(members) if is_derived_set else (
            "재검토 필요" if group.needs_review else "판본 보존" if preserve_required else "검토 가능"
        )),
        members=members,
        edges=edges,
        work_label=work_label(tuple(member.path for member in members)),
        preserve_required=preserve_required,
        source_group_key=group.source_group_key if is_derived_set else group.group_key,
        set_key=group.set_key if is_derived_set else group.group_key,
        edition_kind=group.edition_kind if is_derived_set else None,
        recommendation_status=group.recommendation_status if is_derived_set else "UNKNOWN",
    )


_RELATION_PRIORITY = {
    DuplicateRelation.EXACT_ARCHIVE: 0,
    DuplicateRelation.EXACT_CONTENT: 1,
    DuplicateRelation.VISUAL_VARIANT: 2,
    DuplicateRelation.RELATED: 3,
}


def _member_review_status(member) -> str:
    if member.needs_review or member.quarantine_status == "FAILED":
        return "재검토 필요"
    prefix = "추정 적용 · " if (getattr(member, "review_recommendation_reason", None) or "").startswith("estimated:") else ""
    return prefix + {
        ReviewAction.KEEP: "보존",
        ReviewAction.REMOVE_CANDIDATE: "제거 후보",
        ReviewAction.HOLD: "검토 필요",
    }.get(member.review_action, "미검토")


def _file_operation_status(member) -> str:
    if member.deletion_state == "DELETED":
        return "삭제됨"
    if member.deletion_state == "FAILED":
        return "삭제 실패"
    return {
        "QUARANTINED": "격리됨",
        "PENDING": "격리 진행·복구 대기",
        "RESTORING": "복원 중",
        "FAILED": "파일 위치·격리 확인 필요",
    }.get(member.quarantine_status, "원위치")


def _group_review_status(members: tuple[MemberRow, ...]) -> str:
    labels = ("보존", "제거 후보", "추정 적용 · 보존", "추정 적용 · 제거 후보", "검토 필요", "미검토", "재검토 필요")
    counts = {label: sum(member.review_status_text == label for member in members) for label in labels}
    return " / ".join(f"{label} {count}" for label, count in counts.items() if count)


def _criterion_text(record: RecommendationRecord | None, criterion: str) -> str:
    if record is None:
        return "정보 없음"
    return {
        "LEFT_BETTER": "우세",
        "RIGHT_BETTER": "불리",
        "TIE": "동일",
        "UNKNOWN": "분석 없음",
        "MIXED": "판단 엇갈림",
    }.get(record.criteria.get(criterion, ""), "정보 없음")


_LANGUAGE_LABELS = {
    DetectedLanguage.KOREAN: "한국어",
    DetectedLanguage.JAPANESE: "일본어",
    DetectedLanguage.ENGLISH: "영어",
    DetectedLanguage.CHINESE: "중국어",
    DetectedLanguage.OTHER: "기타 언어",
}


def _detected_language(value: str | None) -> DetectedLanguage:
    try:
        return DetectedLanguage("UNKNOWN" if value is None else value)
    except ValueError:
        return DetectedLanguage.UNKNOWN


def _filename_language(signal: FilenameSignal | None) -> DetectedLanguage:
    if signal is None or signal.conflict or signal.value is None:
        return DetectedLanguage.UNKNOWN
    return _detected_language(signal.value)


def _language_evidence_text(member) -> str:
    precision = _detected_language(member.precision_language)
    filename = _filename_language(member.filename_language)
    if member.filename_language is not None and member.filename_language.conflict:
        return "파일명 언어 표기 충돌"
    if precision is not DetectedLanguage.UNKNOWN and filename is not DetectedLanguage.UNKNOWN:
        if precision is not filename:
            return (
                f"파일명 {_LANGUAGE_LABELS[filename]} / "
                f"정밀분석 {_LANGUAGE_LABELS[precision]} (충돌)"
            )
        return f"{_LANGUAGE_LABELS[precision]} (정밀분석)"
    if precision is not DetectedLanguage.UNKNOWN:
        return f"{_LANGUAGE_LABELS[precision]} (정밀분석)"
    if member.precision_language is not None:
        estimate = _LANGUAGE_LABELS[filename] if filename is not DetectedLanguage.UNKNOWN else "일본어"
        return f"정밀분석 판정 불가 ({estimate} 추정)"
    if filename is not DetectedLanguage.UNKNOWN:
        return f"{_LANGUAGE_LABELS[filename]} (파일명 추정)"
    return "일본어 (추정)"


def _color_evidence_text(member) -> str:
    if member.color_page_ratio is not None:
        if member.color_page_ratio >= 0.50:
            return "풀컬러 (정밀분석 완료)"
        if member.color_page_ratio <= 0.15:
            return "흑백 (정밀분석 완료)"
    signal = member.filename_color
    if signal is None:
        return (
            "혼합·미상 (정밀분석 완료)"
            if member.color_page_ratio is not None
            else "정보 없음"
        )
    if signal.conflict:
        return "파일명 컬러 표기 충돌"
    return {
        "FULL_COLOR": "풀컬러 (파일명 추정)",
        "MONOCHROME": "흑백 (파일명 추정)",
    }.get(signal.value, "정보 없음")


def _mosaic_evidence_text(signal: FilenameSignal | None) -> str:
    if signal is None:
        return "유모 (추정)"
    if signal.conflict:
        return "파일명 모자이크 표기 충돌"
    return {
        "UNCENSORED": "무수정 표기 (파일명 추정)",
        "DECENSORED": "디센서 표기 (파일명 추정)",
        "CENSORED": "검열 표기 (파일명 추정)",
    }.get(signal.value, "유모 (추정)")


def _recommendation_status_text(status: str) -> str:
    return {
        "RECOMMENDED": "추천 완료",
        "UNKNOWN": "추천 상태를 확인할 수 없음",
        "ANALYSIS_REQUIRED": "검토 필요 · 정밀분석 필요",
        "UNCERTAIN": "검토 필요 · 근거 부족",
        "CONFLICT": "검토 필요 · 기준 충돌",
        "NONE": "검토 필요 · 확실한 우위 없음",
    }.get(status, "추천 상태를 확인할 수 없음")


def _member_recommendation_text(record: RecommendationRecord | None, status: str) -> str:
    if status == "RECOMMENDED" and record is not None:
        if "version_" in record.reason:
            action = "보존 추천" if record.recommendation == "KEEP" else "제거 후보 추천"
            return action + " · " + _dominant_criteria_text(record)
        dominant = _dominant_criteria_text(record)
        prefix = "추정 기반 · " if record.reason.startswith("estimated:") else ""
        if record.recommendation == "KEEP":
            return prefix + "보존 추천" + (f": {dominant} 우세" if dominant else "")
        if record.recommendation == "REMOVE_CANDIDATE":
            return prefix + "제거 후보 추천"
        return "추천 없음"
    return _recommendation_missing_text(status, () if record is None else (record,))


def _recommendation_missing_text(status: str, records: tuple[RecommendationRecord, ...]) -> str:
    if status != "RECOMMENDED" and any("version_" in record.reason for record in records):
        return "검토 필요 · 날짜·기간과 페이지 우위 불충족"
    if status != "ANALYSIS_REQUIRED":
        return _recommendation_status_text(status)
    labels = {"language": "언어", "mosaic": "모자이크", "color": "컬러 판본",
              "resolution": "해상도", "size": "용량", "pages": "페이지", "mtime": "수정시각", "title": "제목"}
    missing = set()
    for record in records:
        if "analysis_required:" in record.reason:
            values = record.reason.split("analysis_required:", 1)[1].split(";", 1)[0]
            missing.update(value for value in values.split(",") if value in labels)
    return "검토 필요 · 확인 부족: " + ", ".join(labels[value] for value in sorted(missing)) if missing else _recommendation_status_text(status)


def _derived_group_recommendation_text(
    status: str,
    records: tuple[RecommendationRecord, ...],
    member_numbers: dict[int, int],
) -> str:
    if status != "RECOMMENDED":
        return _recommendation_missing_text(status, records)
    winners = tuple(record for record in records if record.recommendation == "KEEP")
    if len(winners) > 1:
        numbers = ", ".join(str(member_numbers[record.archive_id]) for record in winners if record.archive_id in member_numbers)
        return f"보존 추천: {numbers}번 · 각 파일의 고유 기간 보존"
    winner = next(iter(winners), None)
    if winner is None:
        return "추천 상태를 확인할 수 없음"
    number = member_numbers.get(winner.archive_id)
    dominant = _dominant_criteria_text(winner)
    label = f"{number}번 파일" if number is not None else "보존 파일"
    prefix = "추정 기반 · " if winner.reason.startswith("estimated:") else ""
    return prefix + f"보존 추천: {label}" + (f" ({dominant} 우세)" if dominant else "")


def _dominant_criteria_text(record: RecommendationRecord) -> str:
    if "version_" in record.reason:
        label = ("각 파일의 고유 기간 보존" if "preserve_unique_periods" in record.reason else
                 "기간 포함·페이지 우위" if "version_periods" in record.reason else "최신 날짜·더 많은 페이지")
        if ";date:" in record.reason:
            label += " · " + record.reason.split(";date:", 1)[1].split(";", 1)[0]
        if "date_from_mtime" in record.reason:
            label += " (수정시각 대체)"
        return label
    if "priority:" in record.reason:
        from archive_analyzer.recommendation_policy import LABELS
        keys = record.reason.split("priority:", 1)[1].split(";", 1)[0].split(",")
        return ("내용 동일 쌍은 언어 동급 · " if "identical_content_language_tie" in record.reason else "") + "사용자 순서 " + " > ".join(LABELS[key] for key in keys if key in LABELS)
    if "identical_content_title_latest" in record.reason:
        return "내용 동일 · 제목 형식 우선, 동급이면 최신 파일"
    if "identical_content_latest" in record.reason:
        return "동일 내용의 최신 수정 시각"
    labels = {
        "title": "제목 구조",
        "mtime": "수정 시각",
        "resolution": "대표 해상도",
        "size": "파일 용량",
        "pages": "페이지 수",
        "language": "언어",
        "mosaic": "모자이크",
        "quality": "화질",
    }
    return "·".join(
        labels[key]
        for key in labels
        if record.criteria.get(key) == "LEFT_BETTER"
    )


def _group_relation_text(group: CandidateGroupDetail | ReviewGroupDetail) -> str:
    sequence_relations = {
        relation.sequence_relation
        for relation in group.relations
        if relation.sequence_relation is not None
    }
    if SequenceRelation.CONTAINS in sequence_relations:
        return "합본·개별권 포함"
    if SequenceRelation.PARTIAL_OVERLAP in sequence_relations:
        return "일부 페이지 포함"
    if not group.relations:
        return "단독 후보"
    strongest_relation = (
        min((relation.relation for relation in group.relations), key=lambda value: _RELATION_PRIORITY[value])
        if isinstance(group, ReviewGroupDetail)
        else group.strongest_relation
    )
    label = RELATION_LABELS[strongest_relation]
    if len(group.members) == 2 and len(group.relations) == 1:
        return label
    return f"후보 그룹 (그룹 내 최강 직접 비교: {label})"


def _edge_row(
    relation,
    member_names: dict[int, str],
    member_numbers: dict[int, int],
    *,
    include_file_names: bool,
) -> EdgeRow:
    left_name = member_names.get(relation.archive_a_id, f"archive {relation.archive_a_id}")
    right_name = member_names.get(relation.archive_b_id, f"archive {relation.archive_b_id}")
    left_number = member_numbers.get(relation.archive_a_id, 0)
    right_number = member_numbers.get(relation.archive_b_id, 0)
    left_label = f"{left_number}번 파일" if left_number else "왼쪽 파일"
    right_label = f"{right_number}번 파일" if right_number else "오른쪽 파일"
    evidence = tuple(
        _edge_evidence_text(reason, left_label, right_label)
        for reason in relation.reasons
        if reason in _REASON_TEXT
    )
    sequence_text = _sequence_evidence_text(relation, left_label, right_label)
    base_reason = (
        sequence_text
        if sequence_text is not None
        else " ".join(dict.fromkeys(evidence))
        if evidence
        else "저장된 직접 비교 근거를 검토하세요."
    )
    reason_text = (
        f"{base_reason} 판본 분류: {relation.edition_summary}"
        if relation.edition_summary
        else base_reason
    )
    for reason in relation.reasons:
        if reason.startswith("DATED_SERIES_COMMON_"):
            parts = reason.split("_")
            reason_text += f" 날짜별 갱신판 비교: 작은 파일 {parts[-1]}쪽 중 공통 {parts[-3]}쪽."
        elif reason.startswith("DATED_SERIES_ADDED_"):
            reason_text += f" 페이지 수 차이 {reason.rsplit('_', 1)[-1]}쪽."
    return EdgeRow(
        left_archive_id=relation.archive_a_id,
        left_file_name=left_name if include_file_names else "",
        right_archive_id=relation.archive_b_id,
        right_file_name=right_name if include_file_names else "",
        relation_text=(
            "합본·개별권 포함"
            if relation.sequence_relation is SequenceRelation.CONTAINS
            else (
                "일부 페이지 포함"
                if relation.sequence_relation is SequenceRelation.PARTIAL_OVERLAP
                else RELATION_LABELS[relation.relation]
            )
        ),
        confidence=relation.confidence,
        reason_text=reason_text,
        recommendation=relation.recommendation,
        recommendation_text=_edge_recommendation_text(relation),
        matched_pages=(
            len(relation.matched_pairs)
            if relation.sequence_relation is not None
            else relation.matched_pages
        ),
        left_page_count=relation.left_pages,
        right_page_count=relation.right_pages,
        matched_pairs=relation.matched_pairs,
        sequence_relation=relation.sequence_relation,
        container_archive_id=relation.container_archive_id,
        left_coverage=relation.left_coverage,
        right_coverage=relation.right_coverage,
        edition_flags=relation.edition_flags,
        edition_summary=relation.edition_summary,
        preserve_required=relation.preserve_required,
        left_member_number=left_number,
        right_member_number=right_number,
    )


def _sequence_evidence_text(relation, left_label: str, right_label: str) -> str | None:
    if relation.sequence_relation is SequenceRelation.CONTAINS:
        if relation.container_archive_id == relation.archive_a_id:
            container, contained = left_label, right_label
            contained_pages = relation.right_pages
        else:
            container, contained = right_label, left_label
            contained_pages = relation.left_pages
        return (
            f"{container} 안에 {contained}의 "
            f"{len(relation.matched_pairs)}/{contained_pages} 페이지가 순서대로 포함됩니다."
        )
    if relation.sequence_relation is SequenceRelation.PARTIAL_OVERLAP:
        return (
            f"{left_label}과 {right_label}: "
            f"{len(relation.matched_pairs)}페이지가 같은 순서로 일부 겹칩니다."
        )
    return None


def _edge_evidence_text(reason: str, left_label: str, right_label: str) -> str:
    return _REASON_TEXT[reason].format(
        left_label=left_label, right_label=right_label
    )


def _edge_recommendation_text(relation) -> str:
    if relation.preserve_required:
        return "판본 차이 보존 근거"
    return "직접 관계 근거"


_REASON_TEXT = {
    "DATED_SERIES_TITLE": "날짜·갱신 표기를 제외한 제목이 같은 갱신판 후보입니다.",
    "IDENTICAL_ARCHIVE_SHA256": "압축 파일 SHA-256 값이 같습니다.",
    "ALL_PIXEL_SHA256_IN_ORDER": "전체 페이지의 픽셀 데이터가 순서대로 같습니다.",
    "LEFT_MEDIAN_PIXEL_AREA_AT_LEAST_15_PERCENT_LARGER": "{left_label}의 대표 페이지 해상도가 더 큽니다.",
    "RIGHT_MEDIAN_PIXEL_AREA_AT_LEAST_15_PERCENT_LARGER": "{right_label}의 대표 페이지 해상도가 더 큽니다.",
    "MEDIAN_PIXEL_AREA_DIFFERENCE_BELOW_15_PERCENT": "대표 페이지 해상도 차이가 추천 기준인 15%보다 작습니다.",
    "NO_MATCHED_PAGE_RESOLUTION_EVIDENCE": "대표 페이지 해상도 근거가 부족합니다.",
    "PROBE_HASH_NEAR": "대표 이미지 지문이 유사합니다.",
}
