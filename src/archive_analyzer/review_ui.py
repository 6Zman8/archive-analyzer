from __future__ import annotations

import base64
import ctypes
import sqlite3
import subprocess
import sys
from collections import OrderedDict
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Thread
from typing import Callable
from uuid import UUID

from PIL import Image, ImageOps

from archive_analyzer.archive_hashing import AnalysisCancelled
from archive_analyzer.batch_review import (
    BatchActionPreview,
    BatchActionSummary,
    RecommendationApplyPreview,
    RecommendationApplySummary,
    apply_recommendations,
    batch_delete_quarantined,
    batch_quarantine,
    batch_restore,
    preview_batch_action,
    preview_recommendation_application,
)
from archive_analyzer.deletion import (
    DeletionSafetyError,
    delete_quarantined_archives,
    reconcile_deletions,
)
from archive_analyzer.domain import FileSnapshot
from archive_analyzer.duplicate_domain import ReviewAction
from archive_analyzer.duplicate_reporting import write_candidate_csv
from archive_analyzer.edition_service import analyze_editions
from archive_analyzer.inspection.image_reader import (
    ArchiveImageReader,
    DispatchingImageReader,
    ImageReadFailure,
)
from archive_analyzer.paths import normalize_path_key
from archive_analyzer.precision_service import PrecisionProgress, analyze_precision, refresh_cached_language_decisions
from archive_analyzer.recommendation_service import refresh_recommendations
from archive_analyzer.quarantine import (
    QuarantineSafetyError,
    quarantine_archives,
    reconcile_quarantine_items,
    restore_archives,
)
from archive_analyzer.review_viewmodel import (
    EdgeRow,
    GroupRow,
    MemberRow,
    build_group_view,
)
from archive_analyzer.review_table import (
    ColumnKind,
    ColumnSpec,
    TableState,
    TreeLassoController,
    TreeTableController,
    UiSettingsStore,
)
from archive_analyzer.sequence_analysis import analyze_sequence_relations
from archive_analyzer.shell_context_menu import show_shell_context_menu
from archive_analyzer.storage.duplicate_repository import DuplicateRepository
from archive_analyzer.storage.repository import UnsafeDatabaseIdentity
from archive_analyzer.work_grouping import filter_and_sort_groups
from archive_analyzer.ui_theme import apply_review_theme, action_style
from archive_analyzer.dialogs import OwnedDialogs


_FOLDERID_DOWNLOADS = UUID("374de290-123f-4565-9164-39c4925e467b")
_REVIEW_TITLE = "중복 후보 검토"
_DEFAULT_SEVEN_ZIP = Path(r"C:\Program Files\7-Zip\7z.exe")
@dataclass(frozen=True, slots=True)
class ReviewActionTarget:
    group_key: str
    archive_id: int
    action: ReviewAction


@dataclass(frozen=True, slots=True)
class ReviewWorkResult:
    operation: str
    groups: tuple[GroupRow, ...] | None = None
    output: Path | None = None
    error: BaseException | None = None
    message: str | None = None
    current: int | None = None
    total: int | None = None
    completed: int = 0
    failed: int = 0
    skipped: int = 0
    payload: object | None = None
    partial_groups: bool = False


@dataclass(frozen=True, slots=True)
class _ReviewWork:
    operation: str
    group_key: str | None = None
    archive_ids: tuple[int, ...] = ()
    action: ReviewAction | None = None
    output: Path | None = None
    group_keys: tuple[str, ...] = ()
    directory: Path | None = None


@dataclass(frozen=True, slots=True)
class ThumbnailResult:
    generation: int
    archive_id: int
    image_index: int
    png_data: bytes | None = None
    error: BaseException | None = None


@dataclass(frozen=True, slots=True)
class _ThumbnailWork:
    generation: int
    member: MemberRow
    image_index: int
    slot_size: tuple[int, int]


def fit_preview_size(
    source_size: tuple[int, int],
    slot_size: tuple[int, int],
    allow_upscale: bool = True,
) -> tuple[int, int]:
    """Fit an image in its visible preview slot without changing its ratio."""

    source_width, source_height = source_size
    slot_width, slot_height = slot_size
    if source_width <= 0 or source_height <= 0 or slot_width <= 0 or slot_height <= 0:
        return (1, 1)
    scale = min(slot_width / source_width, slot_height / source_height)
    if not allow_upscale:
        scale = min(scale, 1.0)
    return (
        max(1, round(source_width * scale)),
        max(1, round(source_height * scale)),
    )


def _edge_row_id(edge: EdgeRow, _index: int) -> str:
    return f"edge-{edge.left_archive_id}-{edge.right_archive_id}"


def mouse_wheel_page_offset(delta: int) -> int:
    if delta > 0:
        return -1
    if delta < 0:
        return 1
    return 0


def rectangle_selection_ids(
    rows: tuple[tuple[str, tuple[int, int, int, int]], ...],
    start: tuple[int, int],
    current: tuple[int, int],
) -> tuple[str, ...]:
    left, right = sorted((start[0], current[0]))
    top, bottom = sorted((start[1], current[1]))
    return tuple(
        item_id
        for item_id, (x, y, width, height) in rows
        if x <= right and x + width >= left and y <= bottom and y + height >= top
    )


def _bandiview_candidates() -> tuple[Path, ...]:
    candidates: list[Path] = []
    if sys.platform == "win32":
        import winreg

        app_path = (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\BandiView.exe"
        )
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                with winreg.OpenKey(hive, app_path) as key:
                    value, _ = winreg.QueryValueEx(key, "")
            except OSError:
                continue
            if value:
                candidates.append(Path(str(value).strip('"')))
    candidates.extend(
        (
            Path(r"C:\Program Files\BandiView\BandiView.exe"),
            Path(r"C:\Program Files (x86)\BandiView\BandiView.exe"),
            Path(r"C:\Program Files\Bandisoft\BandiView\BandiView.exe"),
            Path(r"C:\Program Files (x86)\Bandisoft\BandiView\BandiView.exe"),
        )
    )
    return tuple(dict.fromkeys(candidates))


def find_bandiview_executable() -> Path | None:
    return next((path for path in _bandiview_candidates() if path.is_file()), None)


class ExactTextConfirmation:
    """Ask for an exact confirmation phrase without importing Tk at module load."""

    def __init__(
        self,
        parent: object,
        required: str,
        *,
        ask: Callable[..., str | None] | None = None,
    ) -> None:
        if not required:
            raise ValueError("An exact confirmation phrase is required.")
        self.parent = parent
        self.required = required
        self._ask = ask

    def show(self) -> str | None:
        ask = self._ask
        if ask is None:
            from tkinter import simpledialog

            ask = simpledialog.askstring
        return ask(
            _REVIEW_TITLE,
            f"마지막 확인입니다. 아래 칸에 {self.required}를 정확히 입력해 주세요.",
            parent=self.parent,
        )


def selected_review_targets(
    group: GroupRow,
    selected_archive_ids: tuple[int, ...],
    action: ReviewAction,
) -> tuple[ReviewActionTarget, ...]:
    if action not in {
        ReviewAction.KEEP,
        ReviewAction.REMOVE_CANDIDATE,
        ReviewAction.HOLD,
    }:
        raise ValueError("Selected review actions must be KEEP, REMOVE_CANDIDATE or HOLD.")
    current_ids = {member.archive_id for member in group.members}
    selected_ids = tuple(sorted(set(selected_archive_ids)))
    if not selected_ids or any(archive_id not in current_ids for archive_id in selected_ids):
        raise ValueError("Select one or more current candidate members.")
    return tuple(
        ReviewActionTarget(group.group_key, archive_id, action)
        for archive_id in selected_ids
    )


def all_member_review_targets(
    group: GroupRow, action: ReviewAction
) -> tuple[ReviewActionTarget, ...]:
    if action not in {ReviewAction.KEEP, ReviewAction.HOLD}:
        raise ValueError("Group review actions must be KEEP or HOLD.")
    return tuple(
        ReviewActionTarget(group.group_key, member.archive_id, action)
        for member in sorted(group.members, key=lambda item: item.archive_id)
    )


def windows_downloads_folder() -> Path:
    if sys.platform != "win32":
        raise OSError("Windows known folders are unavailable on this platform.")
    folder_id = (ctypes.c_ubyte * 16).from_buffer_copy(_FOLDERID_DOWNLOADS.bytes_le)
    folder_path = ctypes.c_void_p()
    result = ctypes.windll.shell32.SHGetKnownFolderPath(  # type: ignore[attr-defined]
        ctypes.byref(folder_id), 0, None, ctypes.byref(folder_path)
    )
    if result != 0 or folder_path.value is None:
        raise OSError(f"Downloads known folder lookup failed: HRESULT 0x{result & 0xFFFFFFFF:08X}")
    try:
        value = ctypes.wstring_at(folder_path.value)
    finally:
        ctypes.windll.ole32.CoTaskMemFree(folder_path)  # type: ignore[attr-defined]
    if not value:
        raise OSError("Downloads known folder lookup returned an empty path.")
    return Path(value)


def export_initial_directory() -> Path:
    try:
        return windows_downloads_folder()
    except (AttributeError, OSError):
        return Path.home() / "Downloads"


def edge_unmatched_pages(edge: EdgeRow) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
    """Return indexed pages without a stored correspondence, never inferred differences."""
    if not edge.matched_pairs:
        if edge.matched_pages == edge.left_page_count == edge.right_page_count:
            return (), ()
        return None
    left = {pair[0] for pair in edge.matched_pairs}
    right = {pair[1] for pair in edge.matched_pairs}
    return (
        tuple(index for index in range(edge.left_page_count) if index not in left),
        tuple(index for index in range(edge.right_page_count) if index not in right),
    )


def edge_evidence_text(edge: EdgeRow) -> str:
    lines = [
        edge.relation_text,
        f"일치 {edge.matched_pages}쪽 · 왼쪽 전체 {edge.left_page_count}쪽 · 오른쪽 전체 {edge.right_page_count}쪽",
        edge.reason_text,
    ]
    if edge.preserve_required:
        lines.append(f"보존 필요: {edge.edition_summary or edge.recommendation_text}")
    unmatched = edge_unmatched_pages(edge)
    if unmatched is None:
        lines.append("페이지 대응 정보가 없어 차이 후보 위치를 확인할 수 없습니다. 순서·포함 분석 후 다시 확인하세요.")
    else:
        lines.append(f"미대응: 왼쪽 {len(unmatched[0])}쪽 · 오른쪽 {len(unmatched[1])}쪽")
    lines.append("미대응은 내용 차이 확정이 아닙니다. 추가·변형·분석 누락 여부를 이미지로 확인하세요.")
    return "\n\n".join(lines)


def edge_display_values(edge: EdgeRow) -> tuple[str, str, str, str, str, str]:
    pair = (
        f"{edge.left_member_number}번 ↔ {edge.right_member_number}번"
        if edge.left_member_number and edge.right_member_number
        else f"{edge.left_file_name} ↔ {edge.right_file_name}"
    )
    return (
        pair,
        edge.relation_text,
        f"{edge.confidence:.3f}",
        edge.reason_text,
        (
            f"일치 {edge.matched_pages} / {edge.left_page_count} / "
            f"{edge.right_page_count} 페이지"
        ),
        edge.recommendation_text,
    )


def group_display_values(
    index: int, group: GroupRow
) -> tuple[str, str, str, str, str, str]:
    return (
        str(index),
        group.work_label,
        group.relation_text,
        f"{group.confidence:.3f}",
        str(len(group.members)),
        group.review_status_text,
    )


def member_display_values(
    member: MemberRow,
) -> tuple[str, str, str, str, str, str, str]:
    resolution = (
        "-"
        if member.representative_resolution is None
        else f"{member.representative_resolution[0]}x{member.representative_resolution[1]}"
    )
    quarantine_text = {
        "PENDING": "격리 준비",
        "QUARANTINED": "격리됨",
        "RESTORING": "복원 중",
        "RESTORED": "복원됨",
        "FAILED": "격리 실패",
    }.get(member.quarantine_status)
    deletion_text = {
        "PENDING": "삭제 중",
        "DELETED": "제거 완료",
        "FAILED": "삭제 실패",
    }.get(member.deletion_state)
    decision = deletion_text or quarantine_text or (
        "재검토 필요"
        if member.needs_review
        else ("-" if member.user_decision is None else member.user_decision.value)
    )
    return (
        member.file_name,
        str(member.path.parent),
        _file_size_text(member.file_size),
        member.archive_format.value,
        "-" if member.page_count is None else str(member.page_count),
        resolution,
        decision,
    )


def _file_size_text(size: int) -> str:
    if size < 1_024:
        return f"{size:,} B"
    value = float(size)
    unit = "KiB"
    for candidate in ("KiB", "MiB", "GiB", "TiB"):
        unit = candidate
        value /= 1_024
        if value < 1_024 or candidate == "TiB":
            break
    return f"{value:.1f} {unit}"


# The table columns are kept in one place so the UI, sorting/filtering and
# persisted widths cannot drift apart.  ``number`` is a fixed display number;
# it is deliberately not recomputed when a different column is sorted.
GROUP_TABLE_SPECS = (
    ColumnSpec("number", "번호", 55, ColumnKind.NUMBER),
    ColumnSpec("work", "작품", 190, ColumnKind.TEXT),
    ColumnSpec("relation", "관계", 150, ColumnKind.TEXT),
    ColumnSpec("confidence", "신뢰도", 80, ColumnKind.NUMBER),
    ColumnSpec("count", "파일 수", 70, ColumnKind.NUMBER),
    ColumnSpec("status", "검토 상태", 125, ColumnKind.ENUM),
    ColumnSpec("recommendation", "추천 상태", 145, ColumnKind.ENUM),
    ColumnSpec("reviewed_at", "검토 시각", 155, ColumnKind.TEXT),
    ColumnSpec("quarantined_at", "격리·복원 시각", 155, ColumnKind.TEXT),
    ColumnSpec("deleted_at", "휴지통 이동 시각", 155, ColumnKind.TEXT),
)

MEMBER_TABLE_SPECS = (
    ColumnSpec("number", "번호", 55, ColumnKind.NUMBER),
    ColumnSpec("name", "파일명 · 속성", 310, ColumnKind.TEXT),
    ColumnSpec("specs", "용량 · 페이지 / 해상도", 150, ColumnKind.TEXT),
    ColumnSpec("recommendation", "추천", 140, ColumnKind.ENUM),
    ColumnSpec("review", "내 검토", 110, ColumnKind.ENUM),
    ColumnSpec("size", "용량", 90, ColumnKind.NUMBER),
    ColumnSpec("pages", "페이지", 70, ColumnKind.NUMBER),
    ColumnSpec("language", "언어", 170, ColumnKind.ENUM),
    ColumnSpec("resolution", "해상도", 105, ColumnKind.NUMBER),
    ColumnSpec("mtime", "수정 시각", 145, ColumnKind.NUMBER),
    ColumnSpec("color", "컬러", 90, ColumnKind.ENUM),
    ColumnSpec("mosaic", "모자이크", 95, ColumnKind.ENUM),
    ColumnSpec("file_state", "파일 작업", 105, ColumnKind.ENUM),
    ColumnSpec("directory", "경로", 260, ColumnKind.TEXT),
)

EDGE_TABLE_SPECS = (
    ColumnSpec("pair", "비교", 110, ColumnKind.TEXT),
    ColumnSpec("relation", "직접 관계", 130, ColumnKind.TEXT),
    ColumnSpec("confidence", "신뢰도", 80, ColumnKind.NUMBER),
    ColumnSpec("evidence", "근거", 350, ColumnKind.TEXT),
    ColumnSpec("pages", "일치 페이지", 120, ColumnKind.NUMBER),
    ColumnSpec("recommendation", "관계 판정", 180, ColumnKind.ENUM),
)


def _member_table_value(member: MemberRow, spec: ColumnSpec) -> object:
    if spec.key == "number":
        return member.member_number
    if spec.key == "name":
        return f"{member.file_name}\n{member.color_text} · {member.mosaic_text}"
    if spec.key == "specs":
        resolution = " × ".join(map(str, member.representative_resolution)) if member.representative_resolution else "해상도 정보 없음"
        return f"{_file_size_text(member.file_size)} · {member.page_count or 0}쪽\n{resolution}"
    if spec.key == "directory":
        return str(member.directory or member.path.parent)
    if spec.key == "resolution":
        if member.representative_resolution is None:
            return "-"
        width, height = member.representative_resolution
        return f"{width}x{height}"
    if spec.key == "size":
        return _file_size_text(member.file_size)
    if spec.key == "pages":
        return "-" if member.page_count is None else member.page_count
    if spec.key == "mtime":
        if member.mtime_ns <= 0:
            return "-"
        try:
            return datetime.fromtimestamp(member.mtime_ns / 1_000_000_000).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        except (OverflowError, OSError, ValueError):
            return "-"
    if spec.key == "language":
        return member.language_text
    if spec.key == "color":
        return member.color_text
    if spec.key == "mosaic":
        return member.mosaic_text
    if spec.key == "quality":
        return member.quality_text
    if spec.key == "review":
        return member.review_status_text
    if spec.key == "recommendation":
        return member.recommendation_text
    if spec.key == "file_state":
        return member.file_operation_status_text
    return ""


def group_work_tab(group: GroupRow) -> int:
    if any(m.quarantine_status == "FAILED" and m.deletion_state != "DELETED" for m in group.members):
        return 4
    if any(m.quarantine_status == "QUARANTINED" and m.deletion_state != "DELETED" for m in group.members):
        return 2
    if any(m.deletion_state == "DELETED" for m in group.members):
        return 3
    if group.members and all(m.user_decision in {ReviewAction.KEEP, ReviewAction.REMOVE_CANDIDATE} and not m.needs_review for m in group.members):
        return 1
    return 0


def _group_table_value(
    group: GroupRow,
    spec: ColumnSpec,
    numbers: dict[str, int],
) -> object:
    if spec.key == "number":
        return numbers.get(group.group_key, 0)
    if spec.key == "work":
        return group.work_label
    if spec.key == "relation":
        return group.relation_text
    if spec.key == "confidence":
        return group.confidence
    if spec.key == "count":
        return len(group.members)
    if spec.key == "status":
        return group.review_status_text
    if spec.key == "recommendation":
        return group.recommendation_text
    if spec.key in {"reviewed_at", "quarantined_at", "deleted_at"}:
        value = getattr(group, spec.key)
        return datetime.fromisoformat(value).astimezone().strftime("%Y-%m-%d %H:%M:%S") if value else ""
    return ""


def _edge_table_value(edge: EdgeRow, spec: ColumnSpec) -> object:
    if spec.key == "pair":
        return edge_display_values(edge)[0]
    if spec.key == "relation":
        return edge.relation_text
    if spec.key == "confidence":
        return edge.confidence
    if spec.key == "evidence":
        return edge.reason_text
    if spec.key == "pages":
        return edge.matched_pages
    if spec.key == "recommendation":
        return edge.recommendation_text
    return ""


def friendly_review_error(error: BaseException) -> str:
    if isinstance(error, DeletionSafetyError):
        return {
            "NOT_QUARANTINED": "휴지통 이동하려면 먼저 해당 파일을 격리해 주세요.",
            "REMOVE_CANDIDATE_REQUIRED": "먼저 해당 파일을 '제거 후보'로 표시해 주세요.",
            "PRESERVE_REQUIRED": "컬러·번역·편집/검열 차이가 있을 수 있어 이 파일은 삭제할 수 없습니다.",
            "SOURCE_REAPPEARED": "원래 위치에 파일이 다시 생겨 휴지통 이동를 중단했습니다.",
            "QUARANTINE_HASH_MISSING": "격리 당시의 파일 확인값이 없어 휴지통 이동할 수 없습니다.",
            "QUARANTINE_FILE_MISSING": "휴지통 이동할 격리 파일을 찾을 수 없습니다.",
            "QUARANTINE_FILE_NOT_REGULAR": "일반 파일이 아닌 항목은 휴지통 이동할 수 없습니다.",
            "QUARANTINE_FILE_CHANGED": "격리 뒤 파일 크기나 수정 시각이 바뀌어 휴지통 이동를 중단했습니다.",
            "QUARANTINE_FILE_READ_FAILED": "격리 파일의 내용을 확인할 수 없어 휴지통 이동를 중단했습니다.",
            "HASH_MISMATCH": "격리 뒤 파일 내용이 바뀌어 휴지통 이동를 중단했습니다.",
            "DELETION_ALREADY_RECORDED": "이미 휴지통 이동되었거나 삭제 처리 중인 파일입니다.",
            "FILE_DELETE_FAILED": "휴지통으로 이동하지 못했습니다. 파일이 열려 있거나 이 위치에서 휴지통을 사용할 수 없습니다.",
        }.get(error.code, "삭제 안전 조건을 충족하지 않아 휴지통 이동를 중단했습니다.")
    if isinstance(error, QuarantineSafetyError):
        return {
            "REMOVE_CANDIDATE_REQUIRED": "먼저 해당 파일을 '제거 후보'로 표시해 주세요.",
            "PRESERVE_REQUIRED": "컬러·번역·편집/검열 차이가 있을 수 있어 이 파일은 격리할 수 없습니다.",
            "SOURCE_CHANGED": "검사 또는 검토 뒤 파일이 변경되어 격리를 중단했습니다.",
            "SOURCE_MISSING": "이동할 파일을 찾을 수 없습니다.",
            "DESTINATION_EXISTS": "격리 폴더에 같은 경로의 파일이 이미 있어 덮어쓰지 않았습니다.",
            "RESTORE_DESTINATION_EXISTS": "원래 위치에 파일이 이미 있어 덮어쓰지 않았습니다.",
            "NOT_QUARANTINED": "선택한 파일에는 되돌릴 수 있는 격리 기록이 없습니다.",
            "QUARANTINE_ROOT_OVERLAPS_SOURCE": "격리 폴더는 검사 폴더의 안쪽이나 바깥 상위 폴더가 아닌 별도 위치를 선택해 주세요.",
            "HASH_MISMATCH": "파일 내용이 격리 기록과 달라 작업을 중단했습니다.",
            "COPY_VERIFY_FAILED": "복사본 검증에 실패해 원본을 그대로 두었습니다.",
        }.get(error.code, "안전 조건을 충족하지 않아 파일 이동을 중단했습니다.")
    if isinstance(error, UnsafeDatabaseIdentity):
        return "검사 기록 파일의 안전성을 확인할 수 없습니다."
    if isinstance(error, sqlite3.Error):
        return "검토 기록을 저장하거나 읽지 못했습니다. 잠시 후 다시 시도해 주세요."
    if isinstance(error, OSError):
        return "선택한 경로에 접근하거나 파일을 저장하지 못했습니다. 위치와 권한을 확인해 주세요."
    if isinstance(error, ValueError):
        return "후보 정보가 변경되어 작업을 완료하지 못했습니다. 후보 목록을 다시 확인해 주세요."
    return "예기치 않은 오류로 검토 작업을 완료하지 못했습니다. 창을 다시 열어 주세요."


def _precision_progress_message(
    value: PrecisionProgress, *, selected_group_count: int
) -> str:
    if value.phase == "precision_pages":
        position = (
            f"파일 {value.archive_current:,}/{value.archive_total:,} · "
            f"페이지 {value.current:,}/{value.total:,}"
        )
    else:
        position = (
            f"관계 {value.relation_current:,}/{value.relation_total:,} · "
            f"작업 {value.current:,}/{value.total:,}"
        )
    eta = (
        "남은 시간 계산 중"
        if value.eta_seconds is None
        else f"남은 시간 {_duration_text(value.eta_seconds)}"
    )
    parts = [
        f"선택 그룹 {selected_group_count:,}개",
        position,
        f"캐시 {value.cache_hits:,}",
        f"경과 {_duration_text(value.elapsed_seconds)}",
        eta,
    ]
    if value.current_name:
        parts.append(value.current_name)
    return " · ".join(parts)


def _duration_text(value: float) -> str:
    seconds = max(0, int(round(value)))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours:,}시간 {minutes}분 {seconds}초"
    if minutes:
        return f"{minutes:,}분 {seconds}초"
    return f"{seconds:,}초"


class ReviewWorker:
    """Own one review repository and serialize all review work off the Tk thread."""

    def __init__(
        self,
        database: Path,
        source: Path,
        *,
        repository_factory: Callable[[Path], DuplicateRepository] | None = None,
        export_writer: Callable[..., None] | None = None,
        sequence_analyzer: Callable = analyze_sequence_relations,
        edition_analyzer: Callable = analyze_editions,
        precision_analyzer: Callable = analyze_precision,
        recommendation_refresher: Callable = refresh_recommendations,
        quarantine_manager: Callable = quarantine_archives,
        restore_manager: Callable = restore_archives,
        quarantine_reconciler: Callable = reconcile_quarantine_items,
        deletion_manager: Callable = delete_quarantined_archives,
        deletion_reconciler: Callable = reconcile_deletions,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._database = Path(database)
        self._source = Path(source).resolve(strict=False)
        self._repository_factory = repository_factory or DuplicateRepository.open
        self._export_writer = export_writer or write_candidate_csv
        self._sequence_analyzer = sequence_analyzer
        self._edition_analyzer = edition_analyzer
        self._precision_analyzer = precision_analyzer
        self._recommendation_refresher = self._refresh_configured if recommendation_refresher is refresh_recommendations else recommendation_refresher
        self._quarantine_manager = quarantine_manager
        self._restore_manager = restore_manager
        self._quarantine_reconciler = quarantine_reconciler
        self._deletion_manager = deletion_manager
        self._deletion_reconciler = deletion_reconciler
        self._clock = clock or (lambda: datetime.now(UTC))
        self._cancel_event = Event()
        self._requests: Queue[_ReviewWork | None] = Queue()
        self._results: Queue[ReviewWorkResult] = Queue()
        self._thread = Thread(
            target=self._run, name="archive-analyzer-review", daemon=False
        )
        self._started = False
        self._closing = False

    def start(self) -> None:
        if self._started:
            raise RuntimeError("Review worker has already been started.")
        self._started = True
        self._thread.start()

    def submit_load(self) -> None:
        self._submit(_ReviewWork("load"))

    def submit_actions(
        self,
        group_key: str,
        archive_ids: tuple[int, ...],
        action: ReviewAction,
    ) -> None:
        normalized_ids = tuple(sorted(set(archive_ids)))
        if not normalized_ids:
            raise ValueError("At least one archive is required.")
        self._submit(
            _ReviewWork(
                "actions",
                group_key=group_key,
                archive_ids=normalized_ids,
                action=action,
            )
        )

    def submit_group_action(self, group_key: str, action: ReviewAction) -> None:
        if action not in {ReviewAction.KEEP, ReviewAction.HOLD}:
            raise ValueError("Group review actions must be KEEP or HOLD.")
        self._submit(
            _ReviewWork("group_action", group_key=group_key, action=action)
        )

    def submit_batch_group_actions(
        self, group_keys: tuple[str, ...], action: ReviewAction
    ) -> None:
        normalized = tuple(dict.fromkeys(group_keys))
        if not normalized or action not in {ReviewAction.KEEP, ReviewAction.HOLD}:
            raise ValueError("Batch group actions require groups and KEEP or HOLD.")
        self._submit(
            _ReviewWork("batch_group_action", action=action, group_keys=normalized)
        )

    def submit_export(self, output: Path) -> None:
        self._submit(_ReviewWork("export", output=Path(output)))

    def submit_keep_unreviewed(self, group_keys: tuple[str, ...]) -> None:
        if group_keys:
            self._submit(_ReviewWork("keep_unreviewed", group_keys=tuple(dict.fromkeys(group_keys))))

    def submit_sequence_analysis(self, set_keys: tuple[str, ...]) -> None:
        if not set_keys:
            raise ValueError("At least one candidate set is required.")
        self._cancel_event.clear()
        self._submit(_ReviewWork("sequence", group_keys=tuple(dict.fromkeys(set_keys))))

    def submit_edition_analysis(self, set_keys: tuple[str, ...]) -> None:
        if not set_keys:
            raise ValueError("At least one candidate set is required.")
        self._cancel_event.clear()
        self._submit(_ReviewWork("edition", group_keys=tuple(dict.fromkeys(set_keys))))

    def submit_precision_analysis(self, set_keys: tuple[str, ...]) -> None:
        normalized = tuple(dict.fromkeys(str(value) for value in set_keys if str(value)))
        if not normalized:
            raise ValueError("At least one candidate set is required.")
        self._cancel_event.clear()
        self._submit(_ReviewWork("precision", group_keys=normalized))

    def submit_refresh_recommendations(self) -> None:
        self._cancel_event.clear()
        self._submit(_ReviewWork("refresh_recommendations"))

    def submit_apply_recommendations(self, set_keys: tuple[str, ...]) -> None:
        normalized = tuple(dict.fromkeys(str(value) for value in set_keys if str(value)))
        if not normalized:
            raise ValueError("At least one candidate set is required.")
        self._cancel_event.clear()
        self._submit(_ReviewWork("apply_recommendations", group_keys=normalized))

    def submit_group_recovery(self, operation: str, set_keys: tuple[str, ...]) -> None:
        if operation not in {"batch_restore", "reset_reviews"} or not set_keys:
            raise ValueError("A recovery operation and selected groups are required.")
        self._cancel_event.clear()
        self._submit(_ReviewWork(operation, group_keys=tuple(dict.fromkeys(set_keys))))

    def submit_batch_preview(self, set_keys: tuple[str, ...]) -> None:
        normalized = tuple(dict.fromkeys(str(value) for value in set_keys if str(value)))
        if not normalized:
            raise ValueError("At least one candidate set is required.")
        self._submit(_ReviewWork("batch_preview", group_keys=normalized))

    def submit_recommendation_preview(self, set_keys: tuple[str, ...], *, allow_estimates: bool = False) -> None:
        normalized = tuple(dict.fromkeys(str(value) for value in set_keys if str(value)))
        if not normalized:
            raise ValueError("At least one candidate set is required.")
        self._submit(_ReviewWork("estimated_preview" if allow_estimates else "recommendation_preview", group_keys=normalized))

    def submit_batch_quarantine(
        self, set_keys: tuple[str, ...], directory: Path
    ) -> None:
        normalized = tuple(dict.fromkeys(str(value) for value in set_keys if str(value)))
        if not normalized:
            raise ValueError("At least one candidate set is required.")
        self._cancel_event.clear()
        self._submit(
            _ReviewWork("batch_quarantine", group_keys=normalized, directory=Path(directory))
        )

    def submit_batch_delete(self, set_keys: tuple[str, ...]) -> None:
        normalized = tuple(dict.fromkeys(str(value) for value in set_keys if str(value)))
        if not normalized:
            raise ValueError("At least one candidate set is required.")
        self._cancel_event.clear()
        self._submit(_ReviewWork("batch_delete", group_keys=normalized))

    def submit_quarantine(
        self, group_key: str, archive_ids: tuple[int, ...], directory: Path
    ) -> None:
        self._cancel_event.clear()
        self._submit(
            _ReviewWork(
                "quarantine",
                group_key=group_key,
                archive_ids=tuple(dict.fromkeys(archive_ids)),
                directory=Path(directory),
            )
        )

    def submit_restore(self, group_key: str, archive_ids: tuple[int, ...]) -> None:
        self._cancel_event.clear()
        self._submit(
            _ReviewWork(
                "restore",
                group_key=group_key,
                archive_ids=tuple(dict.fromkeys(archive_ids)),
            )
        )

    def submit_delete(self, group_key: str, archive_ids: tuple[int, ...]) -> None:
        self._cancel_event.clear()
        self._submit(
            _ReviewWork(
                "delete",
                group_key=group_key,
                archive_ids=tuple(dict.fromkeys(archive_ids)),
            )
        )

    def cancel_long_operation(self) -> None:
        self._cancel_event.set()

    def poll_result(self) -> ReviewWorkResult | None:
        try:
            return self._results.get_nowait()
        except Empty:
            return None

    def wait_result(self, *, timeout: float | None = None) -> ReviewWorkResult:
        return self._results.get(timeout=timeout)

    def request_close(self) -> None:
        if not self._started or self._closing:
            return
        self._closing = True
        self._cancel_event.set()
        self._requests.put(None)

    def close(self, *, timeout: float | None = None) -> None:
        self.request_close()
        if self._started:
            self._thread.join(timeout)
        if self._thread.is_alive():
            raise TimeoutError("Review worker did not stop before the timeout.")

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def _submit(self, work: _ReviewWork) -> None:
        if not self._started or self._closing:
            raise RuntimeError("Review worker is not accepting work.")
        self._requests.put(work)

    def _report_loading(self, current, total, phase):
        self._results.put(ReviewWorkResult("progress", message=f"{phase}" +
            (f" · {current:,}/{total:,}" if total else " · 진행 중"), current=current, total=total))

    def _refresh_configured(self, repository, root_id, **kwargs):
        from archive_analyzer.recommendation_policy import RecommendationPolicy
        policy = RecommendationPolicy.from_dict(UiSettingsStore().preference("recommendation_policy"))
        return refresh_recommendations(repository, root_id, policy=policy, progress=self._report_loading, **kwargs)

    def _run(self) -> None:
        repository = None
        root_id: int | None = None
        initialization_error: BaseException | None = None
        try:
            try:
                repository = self._repository_factory(self._database)
                root_id = repository.root_id_for_path_key(
                    normalize_path_key(self._source)
                )
                if root_id is None:
                    raise ValueError("Selected scan root is not present in the review database.")
                if isinstance(repository, DuplicateRepository):
                    self._report_loading(0, 0, "격리·복원 기록 확인")
                    self._quarantine_reconciler(
                        repository, root_id, self._cancel_event, clock=self._clock
                    )
                    self._deletion_reconciler(
                        repository, root_id, self._cancel_event, clock=self._clock
                    )
            except BaseException as error:
                initialization_error = error

            while True:
                work = self._requests.get()
                if work is None:
                    return
                if initialization_error is not None:
                    self._results.put(
                        ReviewWorkResult(work.operation, error=initialization_error)
                    )
                    continue
                assert repository is not None and root_id is not None
                try:
                    result = self._perform(repository, root_id, work)
                except BaseException as error:
                    result = ReviewWorkResult(work.operation, error=error)
                self._results.put(result)
        finally:
            if repository is not None:
                repository.close()

    def _perform(
        self, repository: DuplicateRepository, root_id: int, work: _ReviewWork
    ) -> ReviewWorkResult:
        if work.operation == "load":
            if isinstance(repository, DuplicateRepository):
                self._report_loading(0, 0, "저장된 언어 판정 확인")
            if hasattr(repository, "unresolved_precision_profiles"):
                refresh_cached_language_decisions(repository, root_id, self._cancel_event)
            _refresh_recommendations_if_supported(
                self._recommendation_refresher, repository, root_id, self._clock
            )
            return ReviewWorkResult("load", groups=_load_groups(repository, root_id,
                self._report_loading if isinstance(repository, DuplicateRepository) else None))
        if work.operation == "sequence":
            self._sequence_analyzer(
                repository, root_id, self._cancel_event, set_keys=work.group_keys,
                progress=lambda current, total, phase: self._results.put(
                    ReviewWorkResult("progress", message=f"선택 그룹 {len(work.group_keys):,}개 · 새로 분석할 페이지 관계 {current:,}/{total:,} (완료된 관계는 재사용)",
                                     current=current, total=total)
                ),
            )
            self._results.put(ReviewWorkResult("progress", message="페이지 관계 분석 완료 · 추천과 목록을 갱신하는 중입니다..."))
            _refresh_recommendations_if_supported(
                self._recommendation_refresher, repository, root_id, self._clock
            )
            return ReviewWorkResult(
                "sequence", groups=_load_groups(repository, root_id)
            )
        if work.operation == "edition":
            def report_progress(current: int, total: int, phase: str) -> None:
                label = {
                    "profile_pages": "판본 이미지 표본 읽기",
                    "profiles": "판본 표본 분석",
                    "relations": "판본 관계 분류",
                }.get(phase, "판본 분석")
                self._results.put(
                    ReviewWorkResult(
                        "progress",
                        message=f"선택 그룹 {len(work.group_keys):,}개 · {label} {current:,}/{total:,} (완료된 분석은 재사용)",
                        current=current,
                        total=total,
                    )
                )

            self._edition_analyzer(
                repository,
                root_id,
                self._cancel_event,
                set_keys=work.group_keys,
                progress=report_progress,
            )
            self._results.put(ReviewWorkResult("progress", message="판본 분석 완료 · 추천과 목록을 갱신하는 중입니다..."))
            _refresh_recommendations_if_supported(
                self._recommendation_refresher, repository, root_id, self._clock
            )
            return ReviewWorkResult(
                "edition", groups=_load_groups(repository, root_id)
            )
        if work.operation == "precision":
            def report_precision_progress(value: PrecisionProgress) -> None:
                self._results.put(
                    ReviewWorkResult(
                        "progress",
                        message=_precision_progress_message(
                            value, selected_group_count=len(work.group_keys)
                        ),
                        current=value.current,
                        total=value.total,
                    )
                )

            self._precision_analyzer(
                repository,
                root_id,
                self._cancel_event,
                set_keys=work.group_keys,
                clock=self._clock,
                progress=report_precision_progress,
            )
            if hasattr(repository, "edition_profile_inputs"):
                self._results.put(ReviewWorkResult("progress", message="언어 분석 완료 · 추천에 필요한 컬러 판본을 확인하는 중입니다..."))
                self._edition_analyzer(repository, root_id, self._cancel_event, set_keys=work.group_keys,
                    progress=lambda current, total, phase: self._results.put(ReviewWorkResult(
                        "progress", message=f"선택 그룹 {len(work.group_keys):,}개 · 컬러 판본 확인 {current:,}/{total:,} (완료된 분석은 재사용)",
                        current=current, total=total)))
            self._results.put(ReviewWorkResult("progress", message="정밀분석 완료 · 추천과 목록을 갱신하는 중입니다..."))
            _refresh_recommendations_if_supported(
                self._recommendation_refresher, repository, root_id, self._clock
            )
            return ReviewWorkResult(
                "precision", groups=_load_groups(repository, root_id)
            )
        if work.operation == "refresh_recommendations":
            summary = self._recommendation_refresher(
                repository, root_id, clock=self._clock
            )
            return ReviewWorkResult(
                "refresh_recommendations",
                groups=_load_groups(repository, root_id),
                payload=summary,
            )
        if work.operation == "estimated_preview":
            selected = repository.review_candidate_sets_for_keys(work.group_keys)
            self._refresh_configured(repository, root_id,
                affected_group_keys=tuple(dict.fromkeys(item.source_group_key for item in selected)),
                allow_estimates=True, selected_set_keys=work.group_keys, clock=self._clock)
            preview = preview_recommendation_application(repository, work.group_keys)
            return ReviewWorkResult("recommendation_preview", payload=preview,
                                    groups=_load_selected_groups(repository, work.group_keys), partial_groups=True)
        if work.operation == "recommendation_preview":
            preview = preview_recommendation_application(repository, work.group_keys)
            return ReviewWorkResult("recommendation_preview", payload=preview)
        if work.operation == "batch_preview":
            preview = preview_batch_action(repository, work.group_keys)
            return ReviewWorkResult("batch_preview", payload=preview)
        if work.operation == "apply_recommendations":
            summary = apply_recommendations(repository, work.group_keys, self._clock())
            return ReviewWorkResult(
                "apply_recommendations",
                groups=_load_groups(repository, root_id),
                completed=summary.applied,
                failed=summary.failed,
                skipped=summary.skipped,
                payload=summary,
            )
        if work.operation == "keep_unreviewed":
            count = repository.keep_unreviewed_groups(work.group_keys, self._clock())
            return ReviewWorkResult(work.operation, groups=_load_selected_groups(repository, work.group_keys),
                                    partial_groups=True, message=f"미검토 파일 {count:,}개를 보존으로 기록했습니다. 기존 검토는 유지했습니다.")
        if work.operation == "reset_reviews":
            count = repository.reset_review_sets(work.group_keys, self._clock())
            return ReviewWorkResult(work.operation, groups=_load_selected_groups(repository, work.group_keys),
                                    partial_groups=True, message=f"{count:,}개 파일을 검토 필요로 초기화했습니다.")
        if work.operation in {"batch_quarantine", "batch_delete", "batch_restore"}:
            def report_batch_progress(current: int, total: int, phase: str) -> None:
                self._results.put(
                    ReviewWorkResult(
                        "progress",
                        message=f"{phase} {current:,}/{total:,}",
                        current=current,
                        total=total,
                    )
                )

            if work.operation == "batch_quarantine":
                assert work.directory is not None
                summary = batch_quarantine(
                    repository,
                    work.group_keys,
                    work.directory,
                    self._cancel_event,
                    report_batch_progress,
                )
                message = f"일괄 격리 완료: {summary.completed:,}개"
            elif work.operation == "batch_restore":
                summary = batch_restore(repository, work.group_keys, self._cancel_event, report_batch_progress)
                message = f"그룹 격리 복원 완료: {summary.completed:,}개"
            else:
                summary = batch_delete_quarantined(
                    repository,
                    work.group_keys,
                    self._cancel_event,
                    report_batch_progress,
                )
                message = f"일괄 휴지통 이동 완료: {summary.completed:,}개"
            return ReviewWorkResult(
                work.operation,
                groups=_load_groups(repository, root_id),
                message=message,
                completed=summary.completed,
                failed=len(summary.failed),
                skipped=len(summary.skipped),
                payload=summary,
            )
        if work.operation in {"quarantine", "restore", "delete"}:
            assert work.group_key is not None
            detail = repository.review_group_details(work.group_key) if hasattr(repository, "review_group_details") else None
            source_key = getattr(detail, "source_group_key", work.group_key)
            if detail is not None and not set(work.archive_ids) <= {m.archive_id for m in detail.members}:
                raise ValueError("Selected files are not in this candidate set.")
            if not work.archive_ids:
                raise ValueError("At least one archive is required.")

            def report_move_progress(current: int, total: int, phase: str) -> None:
                if phase == "files":
                    message = f"파일 처리 {current:,}/{total:,}"
                else:
                    label = {
                        "quarantine": "격리 파일 확인",
                        "restore": "복원 파일 확인",
                        "delete": "삭제 전 파일 확인",
                    }.get(phase, "파일 확인")
                    message = f"{label} {current:,}/{total:,} 바이트"
                self._results.put(
                    ReviewWorkResult(
                        "progress",
                        message=message,
                        current=current,
                        total=total,
                    )
                )

            if work.operation == "quarantine":
                assert work.directory is not None
                detail = detail or repository.group_details(source_key)
                if detail is None:
                    raise ValueError("Candidate group is no longer available.")
                by_id = {m.archive_id: m for m in detail.members}
                for archive_id in work.archive_ids:
                    member = by_id[archive_id]
                    repository.append_review_action(source_key, archive_id, ReviewAction.REMOVE_CANDIDATE,
                        FileSnapshot(member.path, normalize_path_key(member.path), member.file_size,
                                     member.mtime_ns, member.archive_format), self._clock())
                summary = self._quarantine_manager(
                    repository,
                    source_key,
                    work.archive_ids,
                    work.directory,
                    self._cancel_event,
                    clock=self._clock,
                    progress=report_move_progress,
                )
                message = f"선택한 파일 {summary.processed:,}개를 안전하게 격리했습니다."
            elif work.operation == "restore":
                summary = self._restore_manager(
                    repository,
                    source_key,
                    work.archive_ids,
                    self._cancel_event,
                    clock=self._clock,
                    progress=report_move_progress,
                )
                message = f"선택한 파일 {summary.processed:,}개를 원래 위치로 되돌렸습니다."
            else:
                summary = self._deletion_manager(
                    repository,
                    source_key,
                    work.archive_ids,
                    self._cancel_event,
                    clock=self._clock,
                    progress=report_move_progress,
                )
                message = f"선택한 격리 파일 {summary.processed:,}개를 휴지통 이동했습니다."
            return ReviewWorkResult(
                work.operation,
                groups=_load_groups(repository, root_id),
                message=message,
            )
        if work.operation == "export":
            assert work.output is not None
            self._export_writer(repository, work.output, root_id=root_id)
            return ReviewWorkResult("export", output=work.output)
        if work.operation == "group_action":
            assert work.group_key is not None and work.action is not None
            repository.append_review_action(
                work.group_key, None, work.action, None, self._clock()
            )
            return ReviewWorkResult(
                "group_action", groups=_load_groups(repository, root_id)
            )
        if work.operation == "batch_group_action":
            assert work.action is not None
            for group_key in work.group_keys:
                repository.append_review_action(
                    group_key, None, work.action, None, self._clock()
                )
            return ReviewWorkResult(
                "batch_group_action", groups=_load_groups(repository, root_id)
            )
        if work.operation != "actions":
            raise ValueError(f"Unknown review operation: {work.operation}")
        assert work.group_key is not None and work.action is not None
        detail = (repository.review_group_details(work.group_key)
                  if hasattr(repository, "review_group_details") else None)
        detail = detail or repository.group_details(work.group_key)
        if detail is None:
            raise ValueError("Candidate group is no longer available.")
        members = {member.archive_id: member for member in detail.members}
        if any(archive_id not in members for archive_id in work.archive_ids):
            raise ValueError("Candidate group membership changed. Reload and review again.")
        for archive_id in work.archive_ids:
            member = members[archive_id]
            repository.append_review_action(
                getattr(detail, "source_group_key", work.group_key),
                archive_id,
                work.action,
                FileSnapshot(
                    path=member.path,
                    path_key=normalize_path_key(member.path),
                    size=member.file_size,
                    mtime_ns=member.mtime_ns,
                    archive_format=member.archive_format,
                ),
                self._clock(),
            )
        return ReviewWorkResult(
            "actions", groups=_load_selected_groups(repository, (work.group_key,)), partial_groups=True
        )


def _flow_buttons(frame: object, buttons: list[object]) -> None:
    """Wrap tool buttons at their natural text width without widening the pane."""
    def arrange(_event=None) -> None:
        available = max(1, frame.winfo_width())
        x = y = row_height = 0
        for button in buttons:
            width, height = button.winfo_reqwidth(), button.winfo_reqheight()
            if x and x + width > available:
                x = 0
                y += row_height + 4
                row_height = 0
            button.place(x=x, y=y, width=width, height=height)
            x += width + 6
            row_height = max(row_height, height)
        wanted_height = y + row_height
        if frame.winfo_reqheight() != wanted_height:
            frame.configure(height=wanted_height)
    frame.bind("<Configure>", arrange)


class ThumbnailWorker:
    """Read and resize requested archive covers without blocking the Tk thread."""

    def __init__(
        self, database: Path, reader: ArchiveImageReader | None = None
    ) -> None:
        self._database = Path(database)
        self._reader = reader or DispatchingImageReader(
            _DEFAULT_SEVEN_ZIP, timeout_seconds=10.0
        )
        self._requests: Queue[_ThumbnailWork | None] = Queue()
        self._results: Queue[ThumbnailResult] = Queue()
        self._generation = 0
        # Four bounded decoded pages, not an unbounded archive/image cache.
        self._page_cache: OrderedDict[tuple, Image.Image] = OrderedDict()
        self._closing = False
        self._started = False
        self._thread = Thread(
            target=self._run, name="archive-analyzer-thumbnails", daemon=False
        )

    def start(self) -> None:
        if self._started:
            raise RuntimeError("Thumbnail worker has already been started.")
        self._started = True
        self._thread.start()

    def submit(
        self, requests: tuple[tuple[MemberRow, int, tuple[int, int]], ...]
    ) -> int:
        if not self._started or self._closing:
            raise RuntimeError("Thumbnail worker is not accepting work.")
        self._generation += 1
        generation = self._generation
        for member, image_index, slot_size in requests:
            self._requests.put(
                _ThumbnailWork(generation, member, image_index, slot_size)
            )
        return generation

    def poll_result(self) -> ThumbnailResult | None:
        try:
            return self._results.get_nowait()
        except Empty:
            return None

    def request_close(self) -> None:
        if not self._started or self._closing:
            return
        self._closing = True
        self._requests.put(None)

    def close(self, *, timeout: float | None = None) -> None:
        self.request_close()
        if self._started:
            self._thread.join(timeout)
        if self._thread.is_alive():
            raise TimeoutError("Thumbnail worker did not stop before the timeout.")

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def _run(self) -> None:
        while True:
            work = self._requests.get()
            if work is None or self._closing:
                return
            if work.generation != self._generation:
                continue
            try:
                png_data = self._load(work.member, work.image_index, work.slot_size)
            except BaseException as error:
                result = ThumbnailResult(
                    work.generation,
                    work.member.archive_id,
                    work.image_index,
                    error=error,
                )
            else:
                result = ThumbnailResult(
                    work.generation,
                    work.member.archive_id,
                    work.image_index,
                    png_data=png_data,
                )
            if work.generation == self._generation and not self._closing:
                self._results.put(result)

    def _load(
        self,
        member: MemberRow,
        image_index: int,
        slot_size: tuple[int, int],
    ) -> bytes:
        stat = member.path.stat()
        if (stat.st_size, stat.st_mtime_ns) != (member.file_size, member.mtime_ns):
            raise ValueError("The archive changed since it was indexed.")
        cache_key = (member.archive_id, str(member.path), member.file_size, member.mtime_ns, image_index)
        cached = self._page_cache.get(cache_key)
        if cached is not None:
            self._page_cache.move_to_end(cache_key)
            return self._render(cached, slot_size)
        repository = DuplicateRepository.open_readonly(self._database)
        try:
            preview = repository.preview_image_entry(
                member.archive_id, image_index=image_index
            )
        finally:
            repository.close()
        if preview is None:
            raise ValueError("The archive has no indexed preview image.")
        entry, same_path_count = preview
        payload = self._reader.read(
            FileSnapshot(
                path=member.path,
                path_key=normalize_path_key(member.path),
                size=member.file_size,
                mtime_ns=member.mtime_ns,
                archive_format=member.archive_format,
            ),
            entry,
            same_path_count=same_path_count,
        )
        with Image.open(BytesIO(payload)) as opened:
            image = ImageOps.exif_transpose(opened).convert("RGB")
            image.thumbnail((2048, 2048), Image.Resampling.LANCZOS)
        self._page_cache[cache_key] = image
        while len(self._page_cache) > 4:
            _, evicted = self._page_cache.popitem(last=False)
            evicted.close()
        return self._render(image, slot_size)

    @staticmethod
    def _render(image: Image.Image, slot_size: tuple[int, int]) -> bytes:
        resized = image.resize(fit_preview_size(image.size, slot_size), Image.Resampling.LANCZOS)
        output = BytesIO()
        resized.save(output, format="PNG")
        resized.close()
        return output.getvalue()


def _load_selected_groups(repository, keys) -> tuple[GroupRow, ...]:
    groups = []
    for key in dict.fromkeys(keys):
        detail = repository.review_group_details(key) if hasattr(repository, "review_group_details") else None
        detail = detail or repository.group_details(key)
        if detail is not None:
            groups.append(build_group_view(detail))
    return _with_activity(repository, groups)


def _load_groups(
    repository: DuplicateRepository, root_id: int, progress=None
) -> tuple[GroupRow, ...]:
    return _with_activity(repository, _load_groups_base(repository, root_id, progress))


def _with_activity(repository, groups):
    groups = tuple(groups)
    if not hasattr(repository, "archive_activity"):
        return groups
    activity = repository.archive_activity(tuple({member.archive_id for group in groups for member in group.members}))
    return tuple(replace(group, **{key: max((activity.get(member.archive_id, {}).get(key, "")
        for member in group.members), default="") for key in ("reviewed_at", "quarantined_at", "deleted_at")}) for group in groups)


def _load_groups_base(
    repository: DuplicateRepository, root_id: int, progress=None
) -> tuple[GroupRow, ...]:
    derived_by_source: dict[str, list[GroupRow]] = {}
    if hasattr(repository, "review_candidate_sets") and hasattr(
        repository, "review_group_details"
    ):
        candidates = repository.review_candidate_sets(root_id)
        for index, candidate_set in enumerate(candidates):
            if progress:
                progress(index, len(candidates), "후보 목록 불러오기")
            detail = repository.review_group_details(candidate_set.set_key)
            if detail is not None:
                derived_by_source.setdefault(candidate_set.source_group_key, []).append(
                    build_group_view(detail)
                )
    if hasattr(repository, "candidate_set_generation_group_keys"):
        generated_sources = set(repository.candidate_set_generation_group_keys(root_id))
    elif derived_by_source or (
        hasattr(repository, "has_candidate_set_generations")
        and repository.has_candidate_set_generations(root_id)
    ):
        return tuple(
            group
            for source_groups in derived_by_source.values()
            for group in source_groups
        )
    else:
        generated_sources = set()
    groups = []
    for summary in repository.group_summaries(root_id):
        if summary.group_key in generated_sources:
            groups.extend(derived_by_source.get(summary.group_key, ()))
            continue
        detail = repository.group_details(summary.group_key)
        if detail is not None:
            groups.append(build_group_view(detail))
    return tuple(groups)


def _refresh_recommendations_if_supported(
    refresher: Callable, repository: object, root_id: int, clock: Callable
) -> object | None:
    if not hasattr(repository, "recommendation_source_groups"):
        return None
    return refresher(repository, root_id, clock=clock)


class ReviewWindow:
    def __init__(self, parent, database: Path, source: Path, *, on_close=None) -> None:  # type: ignore[no-untyped-def]
        import tkinter as tk
        from tkinter import filedialog, messagebox, simpledialog, ttk

        self._on_close = on_close
        self._tk = tk
        self._window = tk.Toplevel(parent)
        self._filedialog = OwnedDialogs(filedialog, self._window)
        self._messagebox = OwnedDialogs(messagebox, self._window)
        self._simpledialog = OwnedDialogs(simpledialog, self._window)
        apply_review_theme(self._window)
        self._window.title(_REVIEW_TITLE)
        self._window.geometry("1440x960")
        self._window.minsize(1000, 700)
        self._all_groups: tuple[GroupRow, ...] = ()
        self._groups: tuple[GroupRow, ...] = ()
        self._group_index = 0
        self._closing = False
        self._closed = False
        self._buttons = []
        self._settings_store = UiSettingsStore()
        self._group_numbers: dict[str, int] = {}
        self._group_table: TreeTableController
        self._member_table: TreeTableController
        self._edge_table: TreeTableController
        self._thumbnail_generation = 0
        self._thumbnail_images: dict[int, object] = {}
        self._preview_archive_ids: tuple[int, ...] = ()
        self._preview_page_indices: dict[int, int] = {}
        self._preview_slots: list[tuple[object, object, object]] = []
        self._preview_requested_slot_sizes: tuple[tuple[int, int], ...] = ()
        self._preview_resize_after: object | None = None
        self._member_lasso_start: tuple[int, int] | None = None
        self._status = tk.StringVar(value="중복 후보를 불러오는 중입니다...")
        self._search_text = tk.StringVar(value="")
        self._sort_text = tk.StringVar(value="작품명")
        self._quarantine_text = tk.StringVar(value="격리 폴더: 선택되지 않음")
        saved_quarantine = self._settings_store.preference("quarantine_root")
        self._quarantine_root = Path(saved_quarantine) if saved_quarantine else None
        if self._quarantine_root is not None:
            self._quarantine_text.set(f"격리 폴더: {self._quarantine_root}")
        self._worker = ReviewWorker(database, source)
        self._thumbnail_worker = ThumbnailWorker(database)
        self._commands = {}
        self._bulk_group_buttons = []
        self._default_all_group_buttons = []
        self._visible_action_buttons = []
        self._build_command_menus()

        body = ttk.Frame(self._window, padding=10)
        body.pack(fill="both", expand=True)
        toolbar = ttk.Frame(body)
        toolbar.pack(fill="x", pady=(0, 8))
        self._command_button(toolbar, "검사 화면").pack(side="left")
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=10)
        self._command_button(toolbar, "이미지 정밀분석").pack(side="left")
        self._command_button(toolbar, "추천값 일괄 적용", text="추천 적용").pack(side="left", padx=6)
        self._long_cancel_button = ttk.Button(toolbar, text="작업 중단",
            command=self._cancel_long_operation, state="disabled")
        self._long_cancel_button.pack(side="right")
        panes = ttk.Panedwindow(body, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left = ttk.Frame(panes, padding=(0, 0, 8, 0))
        right = ttk.Frame(panes, padding=(8, 0, 0, 0))
        # Child tables and images must not dictate the initial pane allocation.
        left.configure(width=1)
        right.configure(width=1)
        left.pack_propagate(False)
        right.pack_propagate(False)
        panes.add(left, weight=2)
        panes.add(right, weight=5)

        self._group_tabs = ttk.Notebook(left, height=1)
        for label in ("후보", "검토됨", "격리됨", "휴지통", "문제"):
            self._group_tabs.add(ttk.Frame(self._group_tabs), text=label)
        self._group_tabs.pack(fill="x", pady=(0, 6))
        self._group_tabs.bind("<<NotebookTabChanged>>", self._apply_group_filter)
        search_row = ttk.Frame(left)
        search_row.pack(fill="x", pady=(0, 4))
        ttk.Label(search_row, text="작품 검색").pack(side="left", padx=(0, 8))
        search_entry = ttk.Entry(search_row, textvariable=self._search_text)
        search_entry.pack(side="left", fill="x", expand=True)
        search_entry.bind("<KeyRelease>", self._apply_group_filter)
        sort_row = ttk.Frame(left)
        sort_row.pack(fill="x", pady=(0, 4))
        self._menu_button(sort_row, "목록 설정", self._group_options_menu).pack(side="right", padx=(6, 0))
        ttk.Label(sort_row, text="정렬").pack(side="left", padx=(0, 8))
        sort_box = ttk.Combobox(
            sort_row,
            textvariable=self._sort_text,
            values=("작품명", "신뢰도", "파일 수", "재검토 우선", "최근 작업순", "최근 검토순", "최근 격리·복원순", "최근 휴지통 이동순"),
            state="readonly",
        )
        sort_box.pack(side="left", fill="x", expand=True)
        sort_box.bind(
            "<<ComboboxSelected>>",
            lambda event: self._apply_group_filter(event, reset_table_sort=True),
        )
        group_frame = ttk.Frame(left)
        group_frame.pack(fill="both", expand=True, pady=(4, 0))
        group_frame.columnconfigure(0, weight=1)
        group_frame.rowconfigure(0, weight=1)
        self._group_tree = ttk.Treeview(
            group_frame,
            columns=tuple(spec.key for spec in GROUP_TABLE_SPECS),
            show="headings",
            selectmode="extended",
            height=4,
        )
        group_y = ttk.Scrollbar(group_frame, orient="vertical", command=self._group_tree.yview)
        group_x = ttk.Scrollbar(group_frame, orient="horizontal", command=self._group_tree.xview)
        self._group_tree.configure(yscrollcommand=group_y.set, xscrollcommand=group_x.set)
        self._group_tree.grid(row=0, column=0, sticky="nsew")
        group_y.grid(row=0, column=1, sticky="ns")
        group_x.grid(row=1, column=0, sticky="ew")
        self._group_tree.bind("<<TreeviewSelect>>", self._select_group)
        self._group_lasso_border = tuple(
            tk.Frame(self._group_tree, background="#0078d4") for _ in range(4)
        )
        self._group_table = TreeTableController(
            self._group_tree,
            GROUP_TABLE_SPECS,
            "groups",
            self._settings_store,
            value_getter=lambda group, spec: _group_table_value(
                group, spec, self._group_numbers
            ),
            row_id_getter=lambda group, _index: group.group_key,
            visible_rows_callback=self._on_group_table_visible_rows,
        )
        self._group_table.state = TableState(sort_key="")
        self._group_lasso = TreeLassoController(
            self._group_tree,
            borders=self._group_lasso_border,
            selector=rectangle_selection_ids,
            on_end=self._group_table.save_widths,
        )
        self._group_lasso.bind()
        self._group_table.restore_columns(("number", "work", "count", "recommendation", "status", "relation", "confidence"))
        self._group_tree.bind(
            "<ButtonRelease-1>", self._save_group_widths, add="+"
        )
        group_tools = ttk.Frame(left)
        group_tools.pack(fill="x", pady=(4, 0))
        self._command_button(group_tools, "이전 그룹", text="이전").pack(side="left")
        self._command_button(group_tools, "다음 그룹", text="다음").pack(side="left", padx=4)
        self._group_count_text = tk.StringVar(value="표시 0 · 선택 0")
        ttk.Label(left, textvariable=self._group_count_text).pack(anchor="w", pady=(3, 0))

        self._detail_heading = tk.StringVar(value="파일 (여러 개 선택 가능)")
        member_heading = ttk.Frame(right)
        member_heading.pack(fill="x")
        self._member_details = False
        self._menu_button(member_heading, "표 설정", self._member_options_menu).pack(side="right")
        ttk.Label(member_heading, textvariable=self._detail_heading, width=1).pack(side="left",fill="x",expand=True)
        member_frame = ttk.Frame(right)
        member_frame.pack(fill="x", expand=False, pady=(4, 0))
        member_frame.columnconfigure(0, weight=1)
        member_frame.rowconfigure(0, weight=1)
        self._member_tree = ttk.Treeview(
            member_frame,
            columns=tuple(spec.key for spec in MEMBER_TABLE_SPECS),
            show="headings",
            selectmode="extended",
            height=4,
        )
        member_y = ttk.Scrollbar(member_frame, orient="vertical", command=self._member_tree.yview)
        member_x = ttk.Scrollbar(member_frame, orient="horizontal", command=self._member_tree.xview)
        self._member_tree.configure(yscrollcommand=member_y.set, xscrollcommand=member_x.set)
        self._member_tree.grid(row=0, column=0, sticky="nsew")
        member_y.grid(row=0, column=1, sticky="ns")
        member_x.grid(row=1, column=0, sticky="ew")
        self._member_table = TreeTableController(
            self._member_tree,
            MEMBER_TABLE_SPECS,
            "members",
            self._settings_store,
            value_getter=_member_table_value,
            row_id_getter=lambda member, _index: str(member.archive_id),
            visible_rows_callback=lambda _rows: self._color_recommendations(),
        )
        self._member_tree.configure(style="Members.Treeview")
        self._member_table.restore_columns(("number", "name", "specs", "language", "recommendation", "review", "mtime", "directory"))
        self._member_tree.bind("<<TreeviewSelect>>", self._select_members)
        self._member_tree.bind("<ButtonPress-1>", self._begin_member_lasso)
        self._member_tree.bind("<B1-Motion>", self._drag_member_lasso)
        self._member_tree.bind("<ButtonRelease-1>", self._end_member_lasso)
        self._member_tree.bind("<Button-3>", self._show_member_context_menu)
        self._member_lasso_border = tuple(
            tk.Frame(self._member_tree, background="#0078d4") for _ in range(4)
        )
        file_controls = ttk.Frame(right)
        file_controls.pack(fill="x", pady=(4, 8))
        self._command_button(file_controls, "보존").pack(side="left")
        self._command_button(file_controls, "제거 후보").pack(side="left", padx=6)
        self._menu_button(file_controls, "선택 파일", self._file_actions_menu).pack(side="left")

        preview_frame = ttk.LabelFrame(
            right, text="이미지 비교 · 마우스 휠로 페이지 이동"
        )
        preview_frame.pack(fill="both", expand=True, pady=(0, 10))
        self._preview_frame = preview_frame
        self._preview_cards = []
        self._preview_layout = self._settings_store.preference("preview_layout", "horizontal")
        self._preview_sync = tk.BooleanVar(value=True)
        preview_tools = ttk.Frame(preview_frame)
        preview_tools.grid(row=0, column=0, columnspan=2, sticky="ew")
        self._preview_expanded = False
        self._command_button(preview_tools, "이전 페이지", text="이전 쪽").pack(side="left")
        self._command_button(preview_tools, "다음 페이지", text="다음 쪽").pack(side="left", padx=4)
        ttk.Checkbutton(preview_tools, text="함께 넘기기", variable=self._preview_sync).pack(side="left")
        self._command_button(preview_tools, "확대 / 복귀").pack(side="right")
        self._menu_button(preview_tools, "비교 도구", self._preview_options_menu).pack(side="right", padx=4)
        preview_frame.rowconfigure(1, weight=1)
        for index in range(2):
            preview_frame.columnconfigure(index, weight=1, uniform="preview")
        for index in range(2):
            card = ttk.Frame(preview_frame, padding=6)
            self._preview_cards.append(card)
            card.grid(row=1, column=index, sticky="nsew")
            viewport = ttk.Frame(card, width=1, height=1)
            viewport.pack(fill="both", expand=True)
            image_label = tk.Label(
                viewport,
                text="파일을 선택해 주세요.",
                bg="#202020",
                fg="#f0f0f0",
                compound="top",
                borderwidth=0,
                highlightthickness=0,
            )
            # place prevents PhotoImage requested dimensions feeding back into layout.
            image_label.place(x=0, y=0, relwidth=1, relheight=1)
            image_label.bind(
                "<MouseWheel>",
                lambda event, slot_index=index: self._on_preview_mouse_wheel(
                    slot_index, event
                ),
            )
            image_label.bind(
                "<Configure>",
                lambda event, slot_index=index: self._on_preview_slot_configure(
                    slot_index, event
                ),
            )
            page_label = ttk.Label(card, text="")
            page_label.pack(fill="x", pady=(4, 0))
            name_label = ttk.Label(card, text="", width=1)
            name_label.pack(fill="x", pady=(2, 0))
            self._preview_slots.append((image_label, name_label, page_label))
        self._arrange_previews()

        edge_heading = ttk.Frame(left)
        edge_heading.pack(fill="x")
        ttk.Label(edge_heading, text="직접 비교 관계와 근거").pack(side="left")
        self._edge_summary = tk.StringVar(value="직접 비교 관계를 선택하면 일치 페이지 수가 표시됩니다.")
        summary_label = ttk.Label(left, textvariable=self._edge_summary, wraplength=300)
        summary_label.pack(fill="x")
        summary_label.bind("<Configure>", lambda event: summary_label.configure(wraplength=max(1, event.width)))
        edge_frame = ttk.Frame(left)
        edge_frame.pack(fill="x", expand=False, pady=(4, 0))
        self._edge_widgets = (member_heading, member_frame, file_controls)
        edge_frame.columnconfigure(0, weight=1)
        edge_frame.rowconfigure(0, weight=1)
        self._edge_tree = ttk.Treeview(
            edge_frame,
            columns=tuple(spec.key for spec in EDGE_TABLE_SPECS),
            show="headings",
            selectmode="browse",
            height=4,
        )
        edge_y = ttk.Scrollbar(edge_frame, orient="vertical", command=self._edge_tree.yview)
        edge_x = ttk.Scrollbar(edge_frame, orient="horizontal", command=self._edge_tree.xview)
        self._edge_tree.configure(yscrollcommand=edge_y.set, xscrollcommand=edge_x.set)
        self._edge_tree.grid(row=0, column=0, sticky="nsew")
        edge_y.grid(row=0, column=1, sticky="ns")
        edge_x.grid(row=1, column=0, sticky="ew")
        self._edge_table = TreeTableController(
            self._edge_tree,
            EDGE_TABLE_SPECS,
            "edges",
            self._settings_store,
            value_getter=_edge_table_value,
            row_id_getter=_edge_row_id,
        )
        self._edge_tree.bind("<<TreeviewSelect>>", self._select_edge)
        self._edge_table.restore_columns(("pair", "relation", "evidence"))
        self._menu_button(edge_heading, "관계 설정", self._edge_options_menu).pack(side="right")
        self._edge_tree.column("pair", width=65)
        self._edge_tree.column("relation", width=100)
        self._edge_tree.column("evidence", width=220, stretch=True)
        self._edge_tree.bind("<Double-Button-1>", self._show_edge_evidence)
        self._edge_tree.bind("<ButtonRelease-1>", self._save_edge_widths, add="+")
        self._operation_progress = ttk.Progressbar(
            body, mode="determinate", maximum=1, value=0
        )
        self._operation_progress.pack(fill="x", pady=(0, 4))
        status_label = ttk.Label(body, textvariable=self._status, wraplength=1060)
        status_label.pack(fill="x", anchor="w")
        status_label.bind("<Configure>", lambda event: status_label.configure(wraplength=max(100, event.width)))

        self._external_lasso = None
        self._window.bind("<ButtonPress-1>", self._begin_external_lasso, add="+")
        self._window.bind("<B1-Motion>", self._drag_external_lasso, add="+")
        self._window.bind("<ButtonRelease-1>", self._end_external_lasso, add="+")
        self._member_tree.bind("<Delete>", lambda _event: self._start_quarantine())
        self._window.protocol("WM_DELETE_WINDOW", self._request_close)
        self._worker.start()
        self._thumbnail_worker.start()
        self._worker.submit_load()
        self._set_buttons_enabled(False)
        self._window.after(100, self._poll_worker)

    def _build_command_menus(self) -> None:
        from archive_analyzer.ui_commands import MenuAction

        self._menubar = self._tk.Menu(self._window)
        self._window.configure(menu=self._menubar)

        def menu(label):
            value = self._tk.Menu(self._menubar, tearoff=False)
            self._menubar.add_cascade(label=label, menu=value)
            return value

        def action(parent, label, callback, *, busy=True, group=False, all_groups=False):
            item = MenuAction(parent, label, callback)
            self._commands[label] = item
            if busy:
                self._buttons.append(item)
            if group:
                self._bulk_group_buttons.append(item)
            if all_groups:
                self._default_all_group_buttons.append(item)
            return item

        files = menu("파일")
        action(files, "검사 화면", self._request_close, busy=False)
        action(files, "후보 CSV 내보내기", self._choose_export)
        files.add_separator()
        action(files, "격리 폴더 선택", self._choose_quarantine_directory)
        files.add_command(label=self._quarantine_text.get(), state="disabled")
        location_index = files.index("end")
        files.configure(postcommand=lambda: files.entryconfigure(location_index, label=self._quarantine_text.get()))

        groups = menu("그룹 작업")
        for label, callback in (
            ("추천값 일괄 적용", self._preview_and_apply_recommendations),
            ("추정값 일괄 적용", lambda: self._preview_and_apply_recommendations(allow_estimates=True)),
            ("검토결과 일괄작업", self._preview_batch_actions),
            ("미검토 일괄 보존", self._keep_unreviewed),
        ):
            action(groups, label, callback, group=True, all_groups=True)
        groups.add_separator()
        for label, callback in (
            ("선택 그룹 격리 되돌리기", lambda: self._start_group_recovery("batch_restore")),
            ("선택 그룹 검토 초기화", lambda: self._start_group_recovery("reset_reviews")),
            ("선택 그룹 휴지통 이동", self._start_group_trash),
        ):
            action(groups, label, callback, group=True)
        groups.add_separator()
        action(groups, "이전 그룹", lambda: self._move_group(-1))
        action(groups, "다음 그룹", lambda: self._move_group(1))

        self._file_actions_menu = selected = menu("선택 파일")
        action(selected, "보존", lambda: self._submit_selected(ReviewAction.KEEP))
        action(selected, "제거 후보", lambda: self._submit_selected(ReviewAction.REMOVE_CANDIDATE))
        selected.add_separator()
        action(selected, "탐색기에서 위치 열기", self._reveal_selected_file)
        action(selected, "반디뷰로 열기", self._open_selected_in_bandiview)
        selected.add_separator()
        action(selected, "선택 파일 격리", self._start_quarantine)
        action(selected, "선택 파일 되돌리기", self._start_restore)
        action(selected, "선택 파일 휴지통 이동", self._start_delete)

        analysis = menu("분석")
        action(analysis, "이미지 정밀분석", self._start_precision_analysis, group=True)
        action(analysis, "페이지 포함 관계 분석", self._start_sequence_analysis, group=True)
        action(analysis, "판본 차이 분석", self._start_edition_analysis, group=True)
        analysis.add_separator()
        action(analysis, "추천 기준 설정", self._configure_recommendations, group=True)

        view = menu("보기")
        for attribute, label in (("_group_options_menu", "그룹 목록"),
                                 ("_member_options_menu", "파일 목록"),
                                 ("_edge_options_menu", "비교 관계"),
                                 ("_preview_options_menu", "이미지 비교")):
            child = self._tk.Menu(view, tearoff=False)
            setattr(self, attribute, child)
            view.add_cascade(label=label, menu=child)
        for label, callback in (
            ("그룹 필터", lambda: self._group_table.open_filters(self._window)),
            ("그룹 필터 해제", self._clear_group_filters),
            ("그룹 전체선택", lambda: self._group_table.select_all_visible()),
            ("그룹 표시 열", lambda: self._group_table.choose_columns(self._window)),
        ):
            action(self._group_options_menu, label, callback, busy=False)
        for label, callback in (
            ("요약 / 상세 열", self._toggle_member_columns),
            ("파일 표시 열", lambda: self._member_table.choose_columns(self._window)),
            ("파일 필터", lambda: self._member_table.open_filters(self._window)),
        ):
            action(self._member_options_menu, label, callback, busy=False)
        action(self._edge_options_menu, "관계 표시 열", lambda: self._edge_table.choose_columns(self._window), busy=False)
        action(self._edge_options_menu, "관계 필터", lambda: self._edge_table.open_filters(self._window), busy=False)
        for label, callback in (
            ("차이 후보 페이지", self._show_unmatched_page),
            ("좌우 교환", self._swap_previews),
            ("가로 / 세로 배치", self._toggle_preview_layout),
            ("확대 / 복귀", self._toggle_preview_expand),
            ("이전 페이지", lambda: self._move_preview_page(0, -1)),
            ("다음 페이지", lambda: self._move_preview_page(0, 1)),
        ):
            action(self._preview_options_menu, label, callback, busy=False)
        help_menu = menu("도움말")
        help_menu.add_command(label="기능 위치 안내", command=self._show_command_guide)

    def _command_button(self, parent, name, *, text=None):
        button = self._commands[name].add_button(parent, text=text, style=action_style(name))
        self._visible_action_buttons.append(button)
        return button

    @staticmethod
    def _menu_button(parent, label, menu):
        from tkinter import ttk
        return ttk.Menubutton(parent, text=label, menu=menu, direction="below")

    def _show_command_guide(self):
        self._messagebox.showinfo("기능 위치 안내",
            "그룹 작업: 추천·추정값 적용, 검토결과 일괄작업, 복원·초기화·휴지통\n\n"
            "선택 파일: 보존·제거 후보, 탐색기·반디뷰, 격리·되돌리기·휴지통\n\n"
            "분석: 이미지 정밀분석, 페이지 포함 관계, 판본 차이, 추천 기준 설정\n\n"
            "보기: 목록의 표시 열·필터, 이미지 비교 도구\n\n"
            "파일: 검사 화면, CSV 내보내기, 격리 폴더 선택\n\n"
            "여러 항목 선택: Ctrl/Shift 또는 빈 곳에서 드래그\n"
            "이미지 페이지 이동: 마우스 휠 / 이전 쪽·다음 쪽")

    def request_close(self) -> None:
        self._request_close()

    def _configure_recommendations(self):
        from archive_analyzer.policy_dialog import edit_policy
        from archive_analyzer.recommendation_policy import RecommendationPolicy
        policy = RecommendationPolicy.from_dict(self._settings_store.preference("recommendation_policy"))
        selected = edit_policy(self._window, policy)
        if selected is None:
            return
        self._settings_store.save_preference("recommendation_policy", selected.to_dict())
        self._set_buttons_enabled(False)
        self._status.set("추천 기준 적용 중 · 기존 검토 기록은 유지됩니다.")
        self._worker.submit_refresh_recommendations()

    def _color_recommendations(self) -> None:
        for tree in (self._group_tree, self._member_tree):
            for tag, color in (("keep", "#8de1b6"), ("remove", "#ffbe83"), ("review", "#e2cb83")):
                tree.tag_configure(tag, foreground=color)
            for item_id in tree.get_children():
                values = " ".join(map(str, tree.item(item_id, "values")))
                tag = "keep" if "보존 추천" in values or "추천 완료" in values else "remove" if "제거 후보" in values else "review"
                tree.item(item_id, tags=(tag,))

    def _toggle_member_columns(self) -> None:
        self._member_details = not self._member_details
        self._member_tree.configure(displaycolumns=(tuple(spec.key for spec in MEMBER_TABLE_SPECS if spec.key != "specs")
            if self._member_details else ("number", "name", "specs", "language", "recommendation", "review", "mtime", "directory")))
        self._settings_store.save_preference("members_visible_columns", list(self._member_tree["displaycolumns"]))

    def _show_edge_evidence(self, _event=None) -> None:
        selected = self._edge_tree.selection()
        if selected:
            edge = self._edge_table.row(selected[0])
            if edge is not None:
                self._messagebox.showinfo("직접 비교 관계와 근거", edge_evidence_text(edge), parent=self._window)

    def _show_unmatched_page(self) -> None:
        selection = self._edge_tree.selection()
        edge = None if len(selection) != 1 else self._edge_table.row(selection[0])
        if not isinstance(edge, EdgeRow):
            self._status.set("아래 직접 비교 관계에서 두 파일의 관계를 먼저 선택하세요.")
            return
        unmatched = edge_unmatched_pages(edge)
        if unmatched is None or not any(unmatched):
            self._status.set("페이지 대응 정보가 없습니다. 순서·포함 분석을 먼저 실행하세요." if unmatched is None
                             else "저장된 비교에서 미대응 페이지가 없습니다.")
            return
        members = self._members_for_edge(edge)
        if len(members) != 2:
            return
        left, right = unmatched
        # A side with no unmatched page keeps a nearby matched page for context.
        left = left or (edge.matched_pairs[0][0],)
        right = right or (edge.matched_pairs[0][1],)
        positions = tuple((left[min(index, len(left) - 1)], right[min(index, len(right) - 1)])
                          for index in range(max(len(left), len(right))))
        current = tuple(self._preview_page_indices.get(member.archive_id, 0) for member in members)
        next_index = (positions.index(current) + 1) % len(positions) if current in positions else 0
        self._preview_page_indices = dict(zip((member.archive_id for member in members), positions[next_index]))
        self._request_previews(members, reset_pages=False)
        self._status.set(f"차이 후보 {next_index + 1}/{len(positions)} · 미대응 왼쪽 {len(unmatched[0])}쪽 / 오른쪽 {len(unmatched[1])}쪽. "
                         "양쪽 이미지는 같은 페이지 대응이 아닐 수 있습니다. 미대응이 없는 쪽은 참고 페이지입니다.")

    def _toggle_preview_expand(self) -> None:
        self._preview_expanded = not self._preview_expanded
        for widget in self._edge_widgets:
            if self._preview_expanded:
                widget.pack_forget()
            else:
                widget.pack(fill="x", pady=(4, 0), before=self._preview_frame)

    def _arrange_previews(self) -> None:
        vertical = self._preview_layout == "vertical"
        self._preview_frame.rowconfigure(2, weight=int(vertical))
        self._preview_frame.columnconfigure(1, weight=0 if vertical else 1)
        for index, card in enumerate(self._preview_cards):
            card.grid(row=1 + index if vertical else 1, column=0 if vertical else index,
                      columnspan=2 if vertical else 1, sticky="nsew")

    def _toggle_preview_layout(self) -> None:
        self._preview_layout = "vertical" if self._preview_layout == "horizontal" else "horizontal"
        self._settings_store.save_preference("preview_layout", self._preview_layout)
        self._arrange_previews()

    def _swap_previews(self) -> None:
        group = self._current_group()
        if group is not None:
            by_id = {member.archive_id: member for member in group.members}
            self._request_previews(tuple(by_id[key] for key in reversed(self._preview_archive_ids)
                                         if key in by_id), reset_pages=False)

    def _start_group_trash(self) -> None:
        keys = self._selected_group_keys()
        selected = [group for group in self._groups if group.group_key in keys]
        count = len({member.archive_id for group in selected for member in group.members
                     if member.quarantine_status == "QUARANTINED" and member.deletion_state != "DELETED"})
        if not count:
            self._messagebox.showinfo(_REVIEW_TITLE, "선택 그룹에 휴지통으로 이동할 격리 파일이 없습니다.")
            return
        if not self._messagebox.askyesno(_REVIEW_TITLE,
                f"선택한 {len(keys):,}개 그룹의 격리 파일 {count:,}개를 휴지통으로 이동하시겠습니까?\nWindows 휴지통에서 복원할 수 있습니다."):
            return
        self._set_buttons_enabled(False)
        self._long_cancel_button.configure(state="normal")
        self._status.set("진행 중 · 선택 그룹의 격리 파일을 확인하고 휴지통으로 이동합니다...")
        self._worker.submit_batch_delete(keys)

    def is_alive(self) -> bool:
        return self._worker.is_alive()

    def is_closed(self) -> bool:
        return self._closed

    def _save_group_widths(self, _event=None) -> None:  # type: ignore[no-untyped-def]
        self._group_table.save_widths()

    def _save_edge_widths(self, _event=None) -> None:  # type: ignore[no-untyped-def]
        self._edge_table.save_widths()

    def _current_group(self) -> GroupRow | None:
        if not self._groups:
            return None
        return self._groups[self._group_index]

    def _select_group(self, _event=None) -> None:  # type: ignore[no-untyped-def]
        selection = self._group_tree.selection()
        self._update_group_batch_buttons()
        if not selection:
            return
        group_key = selection[0]
        for index, group in enumerate(self._groups):
            if group.group_key == group_key:
                if self._group_index == index:
                    return
                self._group_index = index
                self._render_group(group)
                return

    def _select_members(self, _event=None) -> None:  # type: ignore[no-untyped-def]
        group = self._current_group()
        if group is None:
            self._request_previews(())
            return
        selected_ids = {
            int(value) for value in self._member_tree.selection()
        }
        members = tuple(
            member for member in group.members if member.archive_id in selected_ids
        )[:2]
        if tuple(member.archive_id for member in members) == self._preview_archive_ids:
            return
        self._request_previews(members)

    def _begin_external_lasso(self, event):
        from types import SimpleNamespace
        if event.widget.winfo_class() not in {"TFrame", "Frame", "TLabel", "Label", "TPanedwindow"}:
            return None
        options = []
        for tree, controller in ((self._group_tree, self._group_lasso),
                                 (self._member_tree, self._member_lasso_controller())):
            x, y = event.x_root - tree.winfo_rootx(), event.y_root - tree.winfo_rooty()
            dx = max(0, -x, x - tree.winfo_width())
            dy = max(0, -y, y - tree.winfo_height())
            if dx + dy <= 80:
                options.append((dx + dy, tree, controller, x, y))
        if not options:
            return None
        _, tree, controller, x, y = min(options, key=lambda item: item[0])
        controller.start = (x, y)
        controller.anchor = ""
        controller.dragging = False
        controller.initial_selection = tuple(tree.selection()) if event.state & 4 else ()
        if not controller.initial_selection:
            tree.selection_remove(tree.selection())
        self._external_lasso = controller
        return "break"

    def _drag_external_lasso(self, event):
        from types import SimpleNamespace
        controller = self._external_lasso
        if controller is None:
            return None
        return controller.drag(SimpleNamespace(x=event.x_root - controller.tree.winfo_rootx(),
                                               y=event.y_root - controller.tree.winfo_rooty()))

    def _end_external_lasso(self, event):
        controller = self._external_lasso
        self._external_lasso = None
        if controller is not None:
            return controller.end(event)
        return None

    def _member_lasso_controller(self) -> TreeLassoController:
        controller = getattr(self, "_member_lasso", None)
        if controller is None:
            controller = TreeLassoController(
                self._member_tree, borders=self._member_lasso_border,
                selector=rectangle_selection_ids,
            )
            self._member_lasso = controller
        return controller

    def _begin_member_lasso(self, event) -> str | None:  # type: ignore[no-untyped-def]
        return self._member_lasso_controller().begin(event)

    def _drag_member_lasso(self, event) -> str | None:  # type: ignore[no-untyped-def]
        return self._member_lasso_controller().drag(event)

    def _end_member_lasso(self, event=None) -> str | None:  # type: ignore[no-untyped-def]
        table = getattr(self, "_member_table", None)
        if table is not None:
            table.save_widths()
        return self._member_lasso_controller().end(event)

    def _show_member_context_menu(self, event) -> str:  # type: ignore[no-untyped-def]
        row = self._member_tree.identify_row(event.y)
        if not row:
            return "break"
        if row not in self._member_tree.selection():
            self._member_tree.selection_set(row)
        group = self._current_group()
        if group is None:
            return "break"
        archive_id = int(row)
        member = next(
            (item for item in group.members if item.archive_id == archive_id), None
        )
        if member is None:
            return "break"
        try:
            show_shell_context_menu(
                member.path,
                int(self._window.winfo_id()),
                int(event.x_root),
                int(event.y_root),
            )
        except (OSError, ValueError) as error:
            self._messagebox.showerror(_REVIEW_TITLE, friendly_review_error(error))
        return "break"

    def _select_edge(self, _event=None) -> None:  # type: ignore[no-untyped-def]
        selection = self._edge_tree.selection()
        edge = None if len(selection) != 1 else self._edge_table.row(selection[0])
        if not isinstance(edge, EdgeRow):
            return
        if hasattr(self, "_edge_summary"):
            self._edge_summary.set(f"일치 {edge.matched_pages}쪽 · 왼쪽 {edge.left_page_count}쪽 / 오른쪽 {edge.right_page_count}쪽"
                                   + (" · 보존 필요" if edge.preserve_required else ""))
        members = self._members_for_edge(edge)
        if len(members) != 2:
            return
        if edge.matched_pairs:
            left_page, right_page = edge.matched_pairs[0]
            self._preview_page_indices = {
                members[0].archive_id: left_page,
                members[1].archive_id: right_page,
            }
        self._member_tree.selection_set(tuple(str(member.archive_id) for member in members))
        self._request_previews(members, reset_pages=not edge.matched_pairs)

    def _members_for_edge(self, edge: EdgeRow) -> tuple[MemberRow, ...]:
        group = self._current_group()
        if group is None:
            return ()
        members_by_id = {member.archive_id: member for member in group.members}
        members = (
            members_by_id.get(edge.left_archive_id),
            members_by_id.get(edge.right_archive_id),
        )
        return tuple(member for member in members if member is not None)

    def _render_groups(self, groups: tuple[GroupRow, ...]) -> None:
        self._all_groups = groups
        self._group_numbers = {
            group.group_key: index for index, group in enumerate(groups, start=1)
        }
        self._apply_group_filter()

    def _show_analysis_menu(self) -> None:
        menu = self._tk.Menu(self._window, tearoff=False)
        for text, command in (
            ("페이지 포함 관계 분석", self._start_sequence_analysis),
            ("판본 차이 분석", self._start_edition_analysis),

        ):
            menu.add_command(label=text, command=command)
        try:
            menu.tk_popup(self._window.winfo_pointerx(), self._window.winfo_pointery())
        finally:
            menu.grab_release()
            menu.destroy()

    def _clear_group_filters(self) -> None:
        self._search_text.set("")
        self._group_table.set_filters({})
        self._apply_group_filter()

    def _apply_group_filter(
        self, _event=None, *, reset_table_sort: bool = False
    ) -> None:  # type: ignore[no-untyped-def]
        previous_key = None
        current = self._current_group()
        if current is not None:
            previous_key = current.group_key
        sort_key = {
            "작품명": "work",
            "신뢰도": "confidence",
            "파일 수": "files",
            "재검토 우선": "status",
        }.get(self._sort_text.get(), "work")
        base_groups = filter_and_sort_groups(
            tuple(group for group in self._all_groups if not hasattr(self, "_group_tabs")
                  or group_work_tab(group) == self._group_tabs.index(self._group_tabs.select())),
            self._search_text.get(), sort_key
        )
        activity_key = {"최근 검토순": "reviewed_at", "최근 격리·복원순": "quarantined_at", "최근 휴지통 이동순": "deleted_at"}.get(self._sort_text.get())
        if activity_key or self._sort_text.get() == "최근 작업순":
            base_groups = tuple(sorted(base_groups, key=lambda group: getattr(group, activity_key)
                if activity_key else max(group.reviewed_at, group.quarantined_at, group.deleted_at), reverse=True))
        # The legacy combobox gives a useful initial ordering.  From there the
        # reusable table controller owns heading sorting and rendering.  An
        # empty sort key preserves this already-filtered order without changing
        # the fixed group numbers shown to the user.
        if reset_table_sort:
            self._group_table.state = TableState(
                sort_key="", filters=self._group_table.state.filters
            )
        self._group_table.set_rows(base_groups)
        self._color_recommendations()
        if hasattr(self, "_group_count_text"):
            self._group_count_text.set(f"표시 {len(self._groups):,}/{len(base_groups):,} · 선택 {len(self._group_tree.selection()):,}")
        if not getattr(self, "_operation_busy", True):
            self._finish_operation()

    def _on_group_table_visible_rows(self, rows: tuple[object, ...]) -> None:
        previous_key = None
        current = self._current_group()
        if current is not None:
            previous_key = current.group_key
        old_keys = [group.group_key for group in self._groups]
        old_index = old_keys.index(previous_key) if previous_key in old_keys else 0
        groups = tuple(row for row in rows if isinstance(row, GroupRow))
        next_key = next((key for key in old_keys[old_index + 1:] if any(g.group_key == key for g in groups)), None)
        if previous_key not in {g.group_key for g in groups}:
            previous_key = next_key or (groups[min(old_index, len(groups)-1)].group_key if groups else None)
        self._groups = groups
        if not groups:
            self._group_index = 0
            self._render_group(None)
            self._status.set(
                "검색 조건에 맞는 후보가 없습니다."
                if self._all_groups
                else "현재 검토할 중복 후보가 없습니다."
            )
            return
        self._group_index = next(
            (
                index
                for index, group in enumerate(groups)
                if group.group_key == previous_key
            ),
            0,
        )
        group = groups[self._group_index]
        if not self._group_tree.selection():
            self._group_tree.selection_set(group.group_key)
        self._group_tree.see(group.group_key)
        self._render_group(group, preserve_preview=previous_key == group.group_key)


    def _render_group(self, group: GroupRow | None, *, preserve_preview: bool = False) -> None:
        if hasattr(self, "_edge_summary"):
            self._edge_summary.set("직접 비교 관계를 선택하면 일치 페이지 수가 표시됩니다.")
        if hasattr(self, "_detail_heading"):
            self._detail_heading.set("파일" if group is None else f"{group.work_label} · 파일 {len(group.members):,}개")
        if group is None:
            self._member_table.set_rows(())
            self._edge_table.set_rows(())
            self._request_previews(())
            return
        self._member_table.set_rows(group.members)
        self._color_recommendations()
        self._edge_table.set_rows(group.edges)
        selected = set(self._member_tree.selection()) if preserve_preview else set()
        initial_members = tuple(member for member in group.members if str(member.archive_id) in selected)[:2] or group.members[:2]
        if initial_members:
            self._member_tree.selection_set(
                tuple(str(member.archive_id) for member in initial_members)
            )
        self._request_previews(initial_members, reset_pages=not preserve_preview)

    def _request_previews(
        self, members: tuple[MemberRow, ...], *, reset_pages: bool = True
    ) -> None:
        members = members[:2]
        self._preview_archive_ids = tuple(member.archive_id for member in members)
        if reset_pages:
            self._preview_page_indices = {
                member.archive_id: 0 for member in members
            }
        else:
            self._preview_page_indices = {
                member.archive_id: min(
                    self._preview_page_indices.get(member.archive_id, 0),
                    max(0, member.page_count - 1),
                )
                for member in members
            }
        if reset_pages:
            self._thumbnail_images.clear()
        requests: list[tuple[MemberRow, int, tuple[int, int]]] = []
        requested_sizes: list[tuple[int, int]] = []
        for index, (image_label, name_label, page_label) in enumerate(
            self._preview_slots
        ):
            if index >= len(members):
                image_label.configure(image="", text="파일을 선택해 주세요.")
                name_label.configure(text="")
                page_label.configure(text="")
                continue
            member = members[index]
            page_index = self._preview_page_indices[member.archive_id]
            slot_size = self._preview_slot_size(image_label)
            requested_sizes.append(slot_size)
            if reset_pages or member.archive_id not in self._thumbnail_images:
                image_label.configure(image="", text="미리보기 불러오는 중...")
            # The filename is already shown in the file table; keep the
            # preview caption focused on its containing directory.
            recommendation = member.recommendation_text
            name_label.configure(foreground="#8de1b6" if "보존 추천" in recommendation else "#ffbe83" if "제거 후보" in recommendation else "#e7edf5")
            name_label.configure(text=f"{'A' if index == 0 else 'B'} · {member.member_number}번 · {member.file_name}\n{member.directory or member.path.parent}")
            page_label.configure(
                text=(
                    "이미지 없음"
                    if member.page_count <= 0
                    else f"{page_index + 1} / {member.page_count} 페이지"
                )
            )
            requests.append((member, page_index, slot_size))
        self._preview_requested_slot_sizes = tuple(requested_sizes)
        self._thumbnail_generation = self._thumbnail_worker.submit(tuple(requests))

    def _preview_slot_size(self, image_label: object) -> tuple[int, int]:
        width = int(getattr(image_label, "winfo_width", lambda: 0)())
        height = int(getattr(image_label, "winfo_height", lambda: 0)())
        return (420, 330) if width <= 1 or height <= 1 else (width, height)

    def _on_preview_slot_configure(self, _slot_index: int, _event: object) -> None:
        if self._closing or not self._preview_archive_ids or self._preview_resize_after is not None:
            return
        self._preview_resize_after = self._window.after(
            150, self._refresh_preview_sizes
        )

    def _refresh_preview_sizes(self) -> None:
        self._preview_resize_after = None
        if self._closing:
            return
        sizes = tuple(
            self._preview_slot_size(self._preview_slots[index][0])
            for index in range(min(len(self._preview_archive_ids), len(self._preview_slots)))
        )
        if len(sizes) != len(self._preview_requested_slot_sizes) or any(
            abs(width - previous_width) >= 8
            or abs(height - previous_height) >= 8
            for (width, height), (previous_width, previous_height) in zip(
                sizes, self._preview_requested_slot_sizes
            )
        ):
            group = self._current_group()
            if group is None:
                return
            members_by_id = {member.archive_id: member for member in group.members}
            members = tuple(
                members_by_id[archive_id]
                for archive_id in self._preview_archive_ids
                if archive_id in members_by_id
            )
            self._request_previews(members, reset_pages=False)

    def _on_preview_mouse_wheel(self, slot_index: int, event) -> str:  # type: ignore[no-untyped-def]
        offset = mouse_wheel_page_offset(int(getattr(event, "delta", 0)))
        if offset:
            self._move_preview_page(slot_index, offset)
        return "break"

    def _move_preview_page(self, slot_index: int, offset: int) -> None:
        if slot_index < 0 or slot_index >= len(self._preview_archive_ids):
            return
        group = self._current_group()
        if group is None:
            return
        members_by_id = {member.archive_id: member for member in group.members}
        archive_id = self._preview_archive_ids[slot_index]
        member = members_by_id.get(archive_id)
        if member is None or member.page_count <= 0:
            return
        current_index = self._preview_page_indices.get(archive_id, 0)
        next_index = min(max(0, current_index + offset), member.page_count - 1)
        if next_index == current_index and not (getattr(self, "_preview_sync", None) is not None and self._preview_sync.get()):
            return
        if getattr(self, "_preview_sync", None) is not None and self._preview_sync.get():
            for visible_id in self._preview_archive_ids:
                target = members_by_id.get(visible_id)
                if target and target.page_count > 0:
                    self._preview_page_indices[visible_id] = min(max(0, self._preview_page_indices.get(visible_id, 0) + offset), target.page_count - 1)
        else:
            self._preview_page_indices[archive_id] = next_index
        visible_members = tuple(
            members_by_id[visible_id]
            for visible_id in self._preview_archive_ids
            if visible_id in members_by_id
        )
        self._request_previews(visible_members, reset_pages=False)

    def _poll_thumbnails(self) -> None:
        while True:
            result = self._thumbnail_worker.poll_result()
            if result is None:
                return
            if result.generation != self._thumbnail_generation:
                continue
            group = self._current_group()
            if group is None:
                continue
            try:
                slot_index = self._preview_archive_ids.index(result.archive_id)
            except ValueError:
                continue
            if self._preview_page_indices.get(result.archive_id) != result.image_index:
                continue
            image_label, _, _ = self._preview_slots[slot_index]
            if result.error is not None or result.png_data is None:
                image_label.configure(image="", text="미리보기를 불러오지 못했습니다.")
                continue
            try:
                image = self._tk.PhotoImage(
                    data=base64.b64encode(result.png_data).decode("ascii")
                )
            except self._tk.TclError:
                image_label.configure(image="", text="미리보기를 표시하지 못했습니다.")
                continue
            self._thumbnail_images[result.archive_id] = image
            image_label.configure(image=image, text="")

    def _selected_member(self) -> MemberRow | None:
        selection = self._member_tree.selection()
        if len(selection) != 1:
            self._messagebox.showinfo(
                _REVIEW_TITLE, "위치를 열 파일을 하나만 선택해 주세요."
            )
            return None
        group = self._current_group()
        if group is None:
            return None
        archive_id = int(selection[0])
        return next(
            (member for member in group.members if member.archive_id == archive_id),
            None,
        )

    def _reveal_selected_file(self) -> None:
        member = self._selected_member()
        if member is None:
            return
        if not member.path.is_file():
            self._messagebox.showerror(_REVIEW_TITLE, "원본 파일을 찾을 수 없습니다.")
            return
        try:
            subprocess.Popen(["explorer.exe", "/select,", str(member.path)])
        except OSError as error:
            self._messagebox.showerror(_REVIEW_TITLE, friendly_review_error(error))

    def _open_selected_in_bandiview(self) -> None:
        member = self._selected_member()
        if member is None:
            return
        if not member.path.is_file():
            self._messagebox.showerror(_REVIEW_TITLE, "원본 파일을 찾을 수 없습니다.")
            return
        executable = find_bandiview_executable()
        if executable is None:
            self._messagebox.showerror(
                _REVIEW_TITLE,
                "반디뷰를 찾을 수 없습니다. 반디뷰가 설치되어 있는지 확인해 주세요.",
            )
            return
        try:
            subprocess.Popen([str(executable), str(member.path)])
        except OSError as error:
            self._messagebox.showerror(_REVIEW_TITLE, friendly_review_error(error))

    def _choose_quarantine_directory(self) -> None:
        selected = self._filedialog.askdirectory(title="격리 폴더 선택", initialdir=str(self._quarantine_root or Path.home()))
        if not selected:
            return
        self._quarantine_root = Path(selected)
        self._settings_store.save_preference("quarantine_root", str(self._quarantine_root))
        self._quarantine_text.set(f"격리 폴더: {self._quarantine_root}")

    def _selected_archive_ids(self) -> tuple[int, ...]:
        return tuple(int(value) for value in self._member_tree.selection())

    def _start_quarantine(self) -> None:
        group = self._current_group()
        if group is None:
            return
        archive_ids = self._selected_archive_ids()
        if not archive_ids:
            self._messagebox.showinfo(_REVIEW_TITLE, "격리할 파일을 하나 이상 선택해 주세요.")
            return
        if self._quarantine_root is None:
            self._messagebox.showinfo(_REVIEW_TITLE, "먼저 격리 폴더를 선택해 주세요.")
            return
        if not self._messagebox.askyesno(
            _REVIEW_TITLE,
            f"선택한 파일 {len(archive_ids):,}개를 격리 폴더로 이동하시겠습니까?\n"
            "원본은 삭제하지 않고 되돌릴 수 있게 기록합니다.",
        ):
            return
        self._set_buttons_enabled(False)
        self._long_cancel_button.configure(state="normal")
        self._status.set("선택한 파일을 검증하고 격리하는 중입니다...")
        self._worker.submit_quarantine(
            group.group_key, archive_ids, self._quarantine_root
        )

    def _start_restore(self) -> None:
        group = self._current_group()
        if group is None:
            return
        archive_ids = self._selected_archive_ids()
        if not archive_ids:
            self._messagebox.showinfo(_REVIEW_TITLE, "되돌릴 파일을 하나 이상 선택해 주세요.")
            return
        if not self._messagebox.askyesno(
            _REVIEW_TITLE,
            f"선택한 파일 {len(archive_ids):,}개를 원래 위치로 되돌리시겠습니까?",
        ):
            return
        self._set_buttons_enabled(False)
        self._long_cancel_button.configure(state="normal")
        self._status.set("격리 파일을 검증하고 원래 위치로 되돌리는 중입니다...")
        self._worker.submit_restore(group.group_key, archive_ids)

    def _start_delete(self) -> None:
        group = self._current_group()
        if group is None:
            return
        archive_ids = self._selected_archive_ids()
        if not archive_ids:
            self._messagebox.showinfo(_REVIEW_TITLE, "휴지통 이동할 파일을 하나 이상 선택해 주세요.")
            return
        if not self._messagebox.askyesno(
            _REVIEW_TITLE,
            f"선택한 격리 파일 {len(archive_ids):,}개를 휴지통 이동하시겠습니까?\n\n"
            "Windows 휴지통에서 복원할 수 있습니다. 원본 위치가 비어 있고 격리 파일이 기록과 "
            "완전히 같을 때만 이동합니다.",
            icon="warning",
        ):
            return
        self._set_buttons_enabled(False)
        self._long_cancel_button.configure(state="normal")
        self._status.set("격리 파일을 다시 검증한 뒤 휴지통 이동하는 중입니다...")
        self._worker.submit_delete(group.group_key, archive_ids)

    def _submit_selected(self, action: ReviewAction) -> None:
        group = self._current_group()
        if group is None:
            return
        try:
            targets = selected_review_targets(
                group,
                tuple(int(value) for value in self._member_tree.selection()),
                action,
            )
        except ValueError:
            self._messagebox.showinfo(_REVIEW_TITLE, "파일을 하나 이상 선택해 주세요.")
            return
        self._submit_targets(targets)

    def _submit_all(self, action: ReviewAction) -> None:
        group = self._current_group()
        if group is None:
            return
        targets = all_member_review_targets(group, action)
        if not targets:
            return
        self._set_buttons_enabled(False)
        self._status.set("검토 의견을 안전하게 기록하는 중입니다...")
        self._worker.submit_group_action(targets[0].group_key, action)

    def _submit_selected_groups(self, action: ReviewAction) -> None:
        group_keys = tuple(self._group_tree.selection())
        if not group_keys:
            self._messagebox.showinfo(_REVIEW_TITLE, "후보 그룹을 하나 이상 선택해 주세요.")
            return
        self._set_buttons_enabled(False)
        self._status.set(
            f"선택한 {len(group_keys):,}개 그룹의 검토 의견을 기록하는 중입니다..."
        )
        self._worker.submit_batch_group_actions(group_keys, action)

    def _selected_group_keys(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(str(value) for value in self._group_tree.selection()))

    def _batch_group_keys(self) -> tuple[str, ...]:
        # Same scope as Select All: current tab and filters, frozen before work starts.
        return self._selected_group_keys() or tuple(str(value) for value in self._group_tree.get_children())

    def _preview_and_apply_recommendations(self, *, allow_estimates: bool = False) -> None:
        set_keys = self._batch_group_keys()
        if not set_keys:
            self._messagebox.showinfo(_REVIEW_TITLE, "추천을 적용할 후보 그룹을 하나 이상 선택해 주세요.")
            return
        self._pending_recommendation_keys = set_keys
        self._pending_estimated_application = allow_estimates
        self._set_buttons_enabled(False)
        self._status.set(f"대상 {len(set_keys):,}개 그룹의 추천 적용을 확인하는 중입니다...")
        if allow_estimates:
            self._worker.submit_recommendation_preview(set_keys, allow_estimates=True)
        else:
            self._worker.submit_recommendation_preview(set_keys)

    def _handle_recommendation_preview(self, preview: object) -> None:
        if not isinstance(preview, RecommendationApplyPreview):
            return
        # ``preview_recommendation_application`` is deliberately called in
        # the worker; this helper only formats the result and asks once.
        if preview.keep + preview.remove == 0:
            self._status.set(
                f"적용할 추천 없음 · 추천 없음 {preview.no_recommendation:,}개 / "
                f"기존 직접 판정 {preview.user_decision_skipped:,}개 / 변경 파일 {preview.changed_snapshot_skipped:,}개. "
                "직접 판정을 다시 적용하려면 선택 그룹 검토 초기화를 먼저 사용하세요."
            )
            self._operation_progress.configure(maximum=1, value=1)
            self._finish_operation()
            return
        if not self._messagebox.askyesno(
            _REVIEW_TITLE,
            f"대상 {len(self._pending_recommendation_keys):,}개 그룹\n" +
            ("제목 기반 추정값을 사용합니다. 언어가 실제 내용과 다를 수 있습니다.\n" if getattr(self, "_pending_estimated_application", False) else "") +
            f"보존 추천 {preview.keep:,}개, 제거 후보 추천 {preview.remove:,}개를 "
            "검토 결과로 적용하시겠습니까?\n"
            f"사용자 판정 생략 {preview.user_decision_skipped:,}개, "
            f"변경 파일 생략 {preview.changed_snapshot_skipped:,}개",
        ):
            self._status.set("취소됨 · 추천값을 적용하지 않았습니다.")
            self._finish_operation()
            return
        self._set_buttons_enabled(False)
        self._status.set("추천값을 검토 결과로 기록하는 중입니다...")
        self._worker.submit_apply_recommendations(self._pending_recommendation_keys)

    def _start_group_recovery(self, operation: str) -> None:
        keys = self._selected_group_keys()
        if not keys:
            return
        label = "격리 파일을 원래 위치로 복원" if operation == "batch_restore" else "검토 결과를 검토 필요로 초기화"
        if not self._messagebox.askyesno(_REVIEW_TITLE, f"선택한 {len(keys):,}개 그룹의 {label}하시겠습니까?\n기존 작업 이력은 보존합니다."):
            return
        self._set_buttons_enabled(False)
        self._status.set(label + " 중입니다...")
        self._long_cancel_button.configure(state="normal")
        self._worker.submit_group_recovery(operation, keys)

    def _keep_unreviewed(self) -> None:
        keys = self._batch_group_keys()
        if not keys:
            self._messagebox.showinfo(_REVIEW_TITLE, "보존 처리할 그룹을 선택해 주세요.")
            return
        self._set_buttons_enabled(False)
        self._status.set(f"대상 {len(keys):,}개 그룹의 미검토 파일을 보존으로 기록하는 중입니다...")
        self._worker.submit_keep_unreviewed(keys)

    def _preview_batch_actions(self) -> None:
        set_keys = self._batch_group_keys()
        if not set_keys:
            self._messagebox.showinfo(_REVIEW_TITLE, "일괄작업할 후보 그룹을 하나 이상 선택해 주세요.")
            return
        self._pending_batch_keys = set_keys
        self._set_buttons_enabled(False)
        self._status.set(f"대상 {len(set_keys):,}개 그룹의 검토 결과를 집계하는 중입니다...")
        self._worker.submit_batch_preview(set_keys)

    def _handle_batch_action_preview(self, preview: object) -> None:
        if not isinstance(preview, BatchActionPreview):
            return
        summary = (
            f"대상 {len(self._pending_batch_keys):,}개 그룹\n"
            f"보존 {preview.keep_count:,}개 ({_file_size_text(preview.keep_bytes)})\n"
            f"검토 필요 {preview.hold_count:,}개 ({_file_size_text(preview.hold_bytes)})\n"
            f"제거 후보 {preview.remove_count:,}개 ({_file_size_text(preview.remove_bytes)})\n"
            f"이미 격리됨 {preview.quarantined_count:,}개 "
            f"({_file_size_text(preview.quarantined_bytes)})"
        )
        if preview.remove_count and self._messagebox.askyesno(
            _REVIEW_TITLE,
            summary + "\n\n제거 후보를 선택한 격리 폴더로 일괄 이동하시겠습니까?",
        ):
            if self._quarantine_root is None:
                self._messagebox.showinfo(_REVIEW_TITLE, "먼저 격리 폴더를 선택해 주세요.")
                self._status.set("대기 · 격리 폴더를 선택한 뒤 다시 실행해 주세요.")
                self._finish_operation()
                return
            self._set_buttons_enabled(False)
            self._long_cancel_button.configure(state="normal")
            self._status.set("제거 후보를 하나씩 검증하고 일괄 격리하는 중입니다...")
            self._worker.submit_batch_quarantine(
                self._pending_batch_keys, self._quarantine_root
            )
            return
        if preview.quarantined_count and self._messagebox.askyesno(
            _REVIEW_TITLE,
            summary + "\n\n이미 격리된 파일만 일괄 휴지통 이동하시겠습니까?",
            icon="warning",
        ):
            self._set_buttons_enabled(False)
            self._long_cancel_button.configure(state="normal")
            self._status.set("격리 파일을 다시 검증하고 일괄 휴지통 이동하는 중입니다...")
            self._worker.submit_batch_delete(self._pending_batch_keys)
            return
        self._status.set("완료 · 검토 결과 집계 확인 · 파일 이동은 실행하지 않았습니다.")
        self._operation_progress.configure(maximum=1, value=1)
        self._finish_operation()

    def _submit_targets(self, targets: tuple[ReviewActionTarget, ...]) -> None:
        if not targets:
            return
        self._set_buttons_enabled(False)
        self._status.set("검토 의견을 안전하게 기록하는 중입니다...")
        self._worker.submit_actions(
            targets[0].group_key,
            tuple(target.archive_id for target in targets),
            targets[0].action,
        )

    def _move_group(self, offset: int) -> None:
        if not self._groups:
            return
        self._group_index = min(
            max(0, self._group_index + offset), len(self._groups) - 1
        )
        group = self._groups[self._group_index]
        self._group_tree.selection_set(group.group_key)
        self._group_tree.see(group.group_key)
        self._render_group(group)

    def _start_sequence_analysis(self) -> None:
        set_keys = self._selected_group_keys()
        if not set_keys:
            self._messagebox.showinfo(_REVIEW_TITLE, "분석할 후보 그룹을 하나 이상 선택해 주세요.")
            return
        self._set_buttons_enabled(False)
        self._long_cancel_button.configure(state="normal")
        self._status.set(
            f"선택한 {len(set_keys):,}개 그룹의 저장된 페이지 지문으로 포함 관계를 분석하는 중입니다..."
        )
        self._operation_progress.configure(maximum=1, value=0)
        self._worker.submit_sequence_analysis(set_keys)

    def _start_edition_analysis(self) -> None:
        set_keys = self._selected_group_keys()
        if not set_keys:
            self._messagebox.showinfo(_REVIEW_TITLE, "분석할 후보 그룹을 하나 이상 선택해 주세요.")
            return
        self._set_buttons_enabled(False)
        self._long_cancel_button.configure(state="normal")
        self._operation_progress.configure(maximum=1, value=0)
        self._status.set(
            f"선택한 {len(set_keys):,}개 그룹에서 파일별 최대 12페이지로 판본 차이를 분석하는 중입니다..."
        )
        self._worker.submit_edition_analysis(set_keys)

    def _start_precision_analysis(self) -> None:
        set_keys = self._selected_group_keys()
        if not set_keys:
            self._messagebox.showinfo(
                _REVIEW_TITLE, "정밀 분석할 후보 그룹을 하나 이상 선택해 주세요."
            )
            return
        self._set_buttons_enabled(False)
        self._long_cancel_button.configure(state="normal")
        self._operation_progress.configure(maximum=1, value=0)
        self._status.set(
            f"선택한 {len(set_keys):,}개 후보 그룹의 이미지를 정밀 분석하는 중입니다..."
        )
        self._worker.submit_precision_analysis(set_keys)

    def _cancel_long_operation(self) -> None:
        self._worker.cancel_long_operation()
        self._status.set("작업 중단을 요청했습니다...")

    def _choose_export(self) -> None:
        selected = self._filedialog.asksaveasfilename(
            title="중복 후보 CSV 저장",
            initialdir=str(export_initial_directory()),
            initialfile="중복후보.csv",
            defaultextension=".csv",
            filetypes=(("CSV 파일", "*.csv"),),
        )
        if not selected:
            return
        self._set_buttons_enabled(False)
        self._status.set("중복 후보 CSV를 저장하는 중입니다...")
        self._worker.submit_export(Path(selected))

    def _poll_worker(self) -> None:
        if self._closing:
            while self._worker.poll_result() is not None:
                pass
            while self._thumbnail_worker.poll_result() is not None:
                pass
            if self._worker.is_alive() or self._thumbnail_worker.is_alive():
                self._window.after(100, self._poll_worker)
                return
            self._worker.close(timeout=0)
            self._thumbnail_worker.close(timeout=0)
            self._window.destroy()
            self._closed = True
            callback = getattr(self, "_on_close", None)
            if callback is not None:
                callback()
            return
        self._poll_thumbnails()
        while True:
            result = self._worker.poll_result()
            if result is None:
                break
            if result.operation == "progress":
                if result.message is not None:
                    self._status.set(result.message)
                if result.total == 0:
                    self._operation_progress.configure(mode="indeterminate")
                    self._operation_progress.start(15)
                elif result.current is not None and result.total is not None:
                    self._operation_progress.stop()
                    self._operation_progress.configure(mode="determinate")
                    self._operation_progress.configure(
                        maximum=max(1, result.total),
                        value=min(result.current, max(1, result.total)),
                    )
                continue
            self._operation_progress.stop()
            self._operation_progress.configure(mode="determinate")
            if result.operation == "recommendation_preview" and result.error is None:
                if result.groups is not None:
                    updates = {group.group_key: group for group in result.groups}
                    self._render_groups(tuple(updates.get(group.group_key, group) for group in self._all_groups))
                self._handle_recommendation_preview(result.payload)
                continue
            if result.operation == "batch_preview" and result.error is None:
                self._handle_batch_action_preview(result.payload)
                continue
            if result.error is not None:
                if isinstance(result.error, AnalysisCancelled):
                    self._status.set(
                        "분석을 중단했습니다. 이미 저장된 결과는 다음 실행에서 재사용됩니다."
                    )
                else:
                    message = friendly_review_error(result.error)
                    self._status.set(message)
                    self._messagebox.showerror(_REVIEW_TITLE, message)
            elif result.groups is not None:
                if result.partial_groups:
                    updates = {group.group_key: group for group in result.groups}
                    self._render_groups(tuple(updates.get(group.group_key, group) for group in self._all_groups))
                else:
                    self._render_groups(result.groups)
            elif result.output is not None:
                self._status.set(f"CSV를 저장했습니다: {result.output}")
            if result.message is not None:
                self._status.set(result.message)
            if result.operation in {
                "apply_recommendations",
                "batch_quarantine",
                "batch_delete",
                "batch_restore",
            } and result.payload is not None:
                self._status.set(
                    f"{result.message or '작업 완료'} · "
                    f"완료 {result.completed:,} / 실패 {result.failed:,} / 생략 {result.skipped:,}"
                )
            if result.error is None:
                self._operation_progress.configure(maximum=1, value=1)
                labels = {"load": "결과 불러오기", "precision": "이미지 정밀분석", "sequence": "페이지 포함관계 분석", "edition": "판본 분석"}
                if result.output is not None:
                    self._status.set(f"완료 · CSV 저장: {result.output}")
                elif not result.message:
                    self._status.set(f"완료 · {labels.get(result.operation, '작업')} · {datetime.now():%H:%M:%S}")
            else:
                self._operation_progress.configure(maximum=1, value=0)
            self._finish_operation()
            self._long_cancel_button.configure(state="disabled")
        self._window.after(100, self._poll_worker)

    def _finish_operation(self) -> None:
        self._set_buttons_enabled(bool(self._groups))
        self._operation_busy = False

    def _set_buttons_enabled(self, enabled: bool) -> None:
        if not enabled and not getattr(self, "_operation_busy", False) and hasattr(self, "_operation_progress"):
            self._operation_progress.configure(maximum=1, value=0)
        self._operation_busy = not enabled
        self._actions_enabled = enabled
        state = "normal" if enabled else "disabled"
        for button in self._buttons:
            button.configure(state=state)
        if enabled:
            self._update_group_batch_buttons()

    def _update_group_batch_buttons(self, _event=None) -> None:  # type: ignore[no-untyped-def]
        if hasattr(self, "_group_count_text"):
            self._group_count_text.set(f"표시 {len(self._groups):,} · 선택 {len(self._group_tree.selection()):,}")
        buttons = getattr(self, "_bulk_group_buttons", ())
        if not buttons:
            return
        tree = getattr(self, "_group_tree", None)
        enabled = getattr(self, "_actions_enabled", True) and bool(getattr(self, "_groups", ())) and tree is not None and bool(
            tree.selection()
        )
        for button in buttons:
            default_all = button in getattr(self, "_default_all_group_buttons", ())
            usable = enabled or (default_all and getattr(self, "_actions_enabled", True) and bool(getattr(self, "_groups", ())))
            button.configure(state="normal" if usable else "disabled")

    def _request_close(self) -> None:
        if self._closing:
            return
        self._closing = True
        pending_resize = getattr(self, "_preview_resize_after", None)
        if pending_resize is not None:
            cancel_after = getattr(self._window, "after_cancel", None)
            if callable(cancel_after):
                try:
                    cancel_after(pending_resize)
                except Exception:
                    pass
            self._preview_resize_after = None
        self._set_buttons_enabled(False)
        cancel_button = getattr(self, "_long_cancel_button", None)
        if cancel_button is not None:
            cancel_button.configure(state="disabled")
        for table_name in ("_group_table", "_member_table", "_edge_table"):
            table = getattr(self, table_name, None)
            if table is not None:
                table.save_widths()
        self._status.set("검토 기록 저장소를 닫는 중입니다...")
        self._worker.request_close()
        self._thumbnail_worker.request_close()


__all__ = [
    "EDGE_TABLE_SPECS",
    "ExactTextConfirmation",
    "GROUP_TABLE_SPECS",
    "MEMBER_TABLE_SPECS",
    "ReviewWindow",
    "ReviewWorker",
    "ReviewWorkResult",
    "all_member_review_targets",
    "edge_display_values",
    "fit_preview_size",
    "export_initial_directory",
    "friendly_review_error",
    "find_bandiview_executable",
    "group_display_values",
    "member_display_values",
    "mouse_wheel_page_offset",
    "rectangle_selection_ids",
    "selected_review_targets",
    "windows_downloads_folder",
]
