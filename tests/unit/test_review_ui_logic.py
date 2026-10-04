from __future__ import annotations

import sqlite3
import sys
from types import SimpleNamespace
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from threading import get_ident

import pytest

import archive_analyzer.review_ui as review_ui
from archive_analyzer.domain import ArchiveFormat
from archive_analyzer.duplicate_domain import DuplicateRelation, ReviewAction
from archive_analyzer.review_ui import (
    ReviewWorker,
    all_member_review_targets,
    export_initial_directory,
    rectangle_selection_ids,
    selected_review_targets,
)
from archive_analyzer.precision_service import PrecisionProgress
from archive_analyzer.review_viewmodel import EdgeRow, GroupRow, MemberRow
from archive_analyzer.storage.duplicate_repository import (
    CandidateGroupDetail,
    CandidateGroupMember,
)


def _group() -> GroupRow:
    members = tuple(
        MemberRow(
            archive_id=archive_id,
            file_name=f"{archive_id}.zip",
            path=Path(f"C:/source/{archive_id}.zip"),
            archive_format=ArchiveFormat.ZIP,
            file_size=archive_id * 100,
            page_count=2,
            representative_resolution=(80, 120),
            user_decision=None,
            needs_review=False,
        )
        for archive_id in (1, 2, 3)
    )
    return GroupRow(
        group_key="group",
        relation_text="후보 그룹",
        confidence=0.9,
        reason_text="구성원별 직접 비교를 확인하세요.",
        recommended_archive_id=None,
        recommendation_text="자동 보존 추천 없음",
        needs_review=False,
        review_status_text="검토 가능",
        members=members,
        edges=(),
    )


def test_selected_actions_target_every_selected_archive() -> None:
    targets = selected_review_targets(
        _group(), (3, 1), ReviewAction.REMOVE_CANDIDATE
    )

    assert [(item.archive_id, item.action) for item in targets] == [
        (1, ReviewAction.REMOVE_CANDIDATE),
        (3, ReviewAction.REMOVE_CANDIDATE),
    ]


def test_selected_hold_targets_only_selected_files() -> None:
    targets = selected_review_targets(_group(), (2, 3), ReviewAction.HOLD)
    assert [target.archive_id for target in targets] == [2, 3]


def test_selection_rectangle_selects_only_intersecting_file_rows() -> None:
    rows = (
        ("1", (0, 20, 500, 20)),
        ("2", (0, 40, 500, 20)),
        ("3", (0, 60, 500, 20)),
    )

    assert rectangle_selection_ids(rows, (250, 85), (100, 35)) == ("1", "2", "3")
    assert rectangle_selection_ids(rows, (250, 85), (100, 65)) == ("3",)
    assert rectangle_selection_ids(rows, (600, 85), (550, 35)) == ()


def test_blank_space_drag_draws_lasso_and_selects_intersecting_rows() -> None:
    selected = []
    removed = []

    class FakeTree:
        @staticmethod
        def identify_region(_x: int, _y: int) -> str:
            return "nothing"

        @staticmethod
        def identify_row(_y: int) -> str:
            return ""

        @staticmethod
        def selection() -> tuple[str, ...]:
            return ("old",)

        @staticmethod
        def selection_remove(values) -> None:  # type: ignore[no-untyped-def]
            removed.append(tuple(values))

        @staticmethod
        def selection_set(values) -> None:  # type: ignore[no-untyped-def]
            selected.append(tuple(values))

        @staticmethod
        def winfo_width() -> int:
            return 500

        @staticmethod
        def winfo_height() -> int:
            return 100

        @staticmethod
        def get_children() -> tuple[str, ...]:
            return ("1", "2")

        @staticmethod
        def bbox(item_id: str) -> tuple[int, int, int, int]:
            return (0, 20 if item_id == "1" else 40, 500, 20)

        @staticmethod
        def yview_scroll(_direction: int, _unit: str) -> None:
            raise AssertionError("in-bounds drag must not scroll")

    class FakeBorder:
        def __init__(self) -> None:
            self.placements = []
            self.hidden = False

        def place(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
            self.placements.append(kwargs)

        def place_forget(self) -> None:
            self.hidden = True

    window = object.__new__(review_ui.ReviewWindow)
    window._member_tree = FakeTree()
    window._member_lasso_start = None
    window._member_lasso_border = tuple(FakeBorder() for _ in range(4))
    start = type("Event", (), {"x": 250, "y": 85})()
    current = type("Event", (), {"x": 100, "y": 35})()

    assert window._begin_member_lasso(start) == "break"
    assert window._drag_member_lasso(current) == "break"
    assert window._end_member_lasso() == "break"

    assert removed[0] == ("old",)
    assert selected == [("1", "2")]
    assert all(border.placements for border in window._member_lasso_border)
    assert all(border.hidden for border in window._member_lasso_border)


def test_right_click_selects_clicked_file_and_opens_native_shell_menu(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = []
    calls = []
    file_path = tmp_path / "book.cbz"
    file_path.write_bytes(b"archive")
    group = _group()
    group = replace(
        group,
        members=(
            group.members[0],
            replace(group.members[1], path=file_path),
            group.members[2],
        ),
    )

    class FakeTree:
        @staticmethod
        def identify_row(_y: int) -> str:
            return "2"

        @staticmethod
        def selection() -> tuple[str, ...]:
            return ("1",)

        @staticmethod
        def selection_set(value) -> None:  # type: ignore[no-untyped-def]
            selected.append(value)

    class FakeWindow:
        @staticmethod
        def winfo_id() -> int:
            return 77

    window = object.__new__(review_ui.ReviewWindow)
    window._groups = (group,)
    window._group_index = 0
    window._member_tree = FakeTree()
    window._window = FakeWindow()
    window._messagebox = object()
    monkeypatch.setattr(
        review_ui,
        "show_shell_context_menu",
        lambda path, hwnd, x, y: calls.append((path, hwnd, x, y)),
    )
    event = type("Event", (), {"y": 10, "x_root": 30, "y_root": 40})()

    assert window._show_member_context_menu(event) == "break"
    assert selected == ["2"]
    assert calls == [(file_path, 77, 30, 40)]


def test_all_member_actions_target_each_current_member() -> None:
    keep_targets = all_member_review_targets(_group(), ReviewAction.KEEP)
    hold_targets = all_member_review_targets(_group(), ReviewAction.HOLD)

    assert [item.archive_id for item in keep_targets] == [1, 2, 3]
    assert [item.action for item in keep_targets] == [ReviewAction.KEEP] * 3
    assert [item.archive_id for item in hold_targets] == [1, 2, 3]
    assert [item.action for item in hold_targets] == [ReviewAction.HOLD] * 3


def test_partial_generations_replace_only_their_source_groups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derived = replace(_group(), group_key="set-a", work_label="derived-a")
    original_b = replace(_group(), group_key="group-b", work_label="original-b")

    class FakeRepository:
        @staticmethod
        def review_candidate_sets(_root_id: int) -> tuple:
            return (
                SimpleNamespace(set_key="set-a", source_group_key="group-a"),
                SimpleNamespace(set_key="legacy-set-b", source_group_key="group-b"),
            )

        @staticmethod
        def review_group_details(set_key: str) -> object:
            return SimpleNamespace(
                view=(
                    derived
                    if set_key == "set-a"
                    else replace(_group(), group_key="legacy-set-b", work_label="legacy-b")
                )
            )

        @staticmethod
        def candidate_set_generation_group_keys(_root_id: int) -> tuple[str, ...]:
            return ("group-a", "group-c")

        @staticmethod
        def group_summaries(_root_id: int) -> tuple:
            return tuple(
                SimpleNamespace(group_key=group_key)
                for group_key in ("group-a", "group-b", "group-c")
            )

        @staticmethod
        def group_details(group_key: str) -> object:
            assert group_key == "group-b"
            return SimpleNamespace(view=original_b)

    monkeypatch.setattr(review_ui, "build_group_view", lambda detail: detail.view)

    assert review_ui._load_groups(FakeRepository(), 7) == (derived, original_b)


def test_edge_display_keeps_direct_pair_relation_and_evidence_visible() -> None:
    edge = EdgeRow(
        left_archive_id=1,
        left_file_name="one.zip",
        right_archive_id=2,
        right_file_name="two.zip",
        relation_text="내용 동일",
        confidence=0.9876,
        reason_text="전체 페이지의 픽셀 데이터가 같습니다.",
        recommendation="NONE",
        recommendation_text="자동 보존 추천 없음",
        matched_pages=7,
        left_page_count=7,
        right_page_count=8,
    )

    assert review_ui.edge_display_values(edge) == (
        "one.zip ↔ two.zip",
        "내용 동일",
        "0.988",
        "전체 페이지의 픽셀 데이터가 같습니다.",
        "일치 7 / 7 / 8 페이지",
        "자동 보존 추천 없음",
    )

    numbered = replace(edge, left_member_number=1, right_member_number=2)
    assert review_ui.edge_display_values(numbered)[0] == "1번 ↔ 2번"


def test_group_and_same_named_member_display_values_remain_distinguishable() -> None:
    group = replace(_group(), work_label="작품 이름")
    first = replace(
        group.members[0],
        file_name="same.zip",
        path=Path("C:/source/edition-a/same.zip"),
        file_size=1_536,
    )
    second = replace(
        group.members[1],
        file_name="same.zip",
        path=Path("C:/source/edition-b/same.zip"),
        file_size=2_048,
    )

    assert review_ui.group_display_values(2, group) == (
        "2",
        "작품 이름",
        "후보 그룹",
        "0.900",
        "3",
        "검토 가능",
    )
    first_values = review_ui.member_display_values(first)
    second_values = review_ui.member_display_values(second)
    assert first_values == (
        "same.zip",
        r"C:\source\edition-a",
        "1.5 KiB",
        "ZIP",
        "2",
        "80x120",
        "-",
    )
    assert second_values[0] == first_values[0]
    assert second_values[1] == r"C:\source\edition-b"
    assert second_values[1] != first_values[1]
    assert second_values[2] == "2.0 KiB"


def test_member_display_shows_quarantine_state_and_current_location() -> None:
    member = replace(
        _group().members[0],
        path=Path("C:/quarantine/source/1.zip"),
        quarantine_status="QUARANTINED",
        quarantine_path=Path("C:/quarantine/source/1.zip"),
    )

    values = review_ui.member_display_values(member)

    assert values[1] == r"C:\quarantine\source"
    assert values[-1] == "격리됨"


def test_member_display_shows_permanent_deletion_over_quarantine_state() -> None:
    member = replace(
        _group().members[0],
        quarantine_status="QUARANTINED",
        deletion_state="DELETED",
    )

    assert review_ui.member_display_values(member)[-1] == "제거 완료"


def test_export_dialog_defaults_to_windows_downloads(monkeypatch) -> None:
    monkeypatch.setattr(
        "archive_analyzer.review_ui.windows_downloads_folder",
        lambda: Path(r"C:\Users\test\Downloads"),
    )

    assert export_initial_directory() == Path(r"C:\Users\test\Downloads")


def test_export_dialog_falls_back_safely(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "archive_analyzer.review_ui.windows_downloads_folder",
        lambda: (_ for _ in ()).throw(OSError("known folder unavailable")),
    )
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    assert export_initial_directory() == tmp_path / "Downloads"


@pytest.mark.parametrize(
    ("delta", "expected_offset"),
    ((120, -1), (-120, 1), (0, 0)),
)
def test_preview_mouse_wheel_uses_up_for_previous_and_down_for_next(
    delta: int, expected_offset: int
) -> None:
    assert review_ui.mouse_wheel_page_offset(delta) == expected_offset


def test_bandiview_lookup_skips_missing_candidates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "BandiView.exe"
    executable.write_bytes(b"executable")
    monkeypatch.setattr(
        review_ui,
        "_bandiview_candidates",
        lambda: (tmp_path / "missing.exe", executable),
    )

    assert review_ui.find_bandiview_executable() == executable


def test_review_worker_serializes_actions_and_export_off_caller_thread(
    tmp_path: Path,
) -> None:
    caller_thread = get_ident()
    calls: list[tuple] = []
    member_paths = (tmp_path / "one.zip", tmp_path / "two.zip")
    members = tuple(
        CandidateGroupMember(
            archive_id=index,
            path=path,
            file_size=100 + index,
            mtime_ns=200 + index,
            archive_format=ArchiveFormat.ZIP,
            review_action=None,
            needs_review=False,
            image_count=2,
            representative_width=80,
            representative_height=120,
        )
        for index, path in enumerate(member_paths, 1)
    )
    detail = CandidateGroupDetail(
        group_key="group",
        members=members,
        relations=(),
        strongest_relation=DuplicateRelation.RELATED,
        confidence=0.5,
        analyzer_version=1,
        needs_review=False,
        recommended_archive_id=None,
    )

    class FakeRepository:
        def root_id_for_path_key(self, path_key: str) -> int:
            calls.append(("root", get_ident(), path_key))
            return 7

        def group_summaries(self, root_id: int) -> tuple:
            calls.append(("summaries", get_ident(), root_id))
            return ()

        def group_details(self, group_key: str) -> CandidateGroupDetail:
            calls.append(("detail", get_ident(), group_key))
            return detail

        def append_review_action(
            self, group_key, archive_id, action, snapshot, created_at
        ) -> int:  # type: ignore[no-untyped-def]
            calls.append(
                (
                    "action",
                    get_ident(),
                    group_key,
                    archive_id,
                    action,
                    None if snapshot is None else snapshot.path,
                    created_at.tzinfo,
                )
            )
            return 0 if archive_id is None else archive_id

        def close(self) -> None:
            calls.append(("close", get_ident()))

    repository = FakeRepository()

    def export_writer(fake_repository, output: Path, *, root_id: int) -> None:
        calls.append(("export", get_ident(), fake_repository, output, root_id))

    worker = ReviewWorker(
        tmp_path / "index.db",
        tmp_path / "source",
        repository_factory=lambda _: repository,
        export_writer=export_writer,
        clock=lambda: datetime(2026, 8, 31, 12, 0, tzinfo=UTC),
    )
    worker.start()
    worker.submit_actions(
        "group", (2, 1), ReviewAction.REMOVE_CANDIDATE
    )
    first = worker.wait_result(timeout=5)
    assert first.error is None
    assert [call[3] for call in calls if call[0] == "action"] == [1, 2]
    assert all(call[1] != caller_thread for call in calls if call[0] == "action")

    worker.submit_group_action("group", ReviewAction.KEEP)
    group_action = worker.wait_result(timeout=5)
    assert group_action.error is None
    assert [call[3] for call in calls if call[0] == "action"] == [1, 2, None]
    assert [call[5] for call in calls if call[0] == "action"][-1] is None

    worker.submit_batch_group_actions(("group-a", "group-b"), ReviewAction.HOLD)
    batch_action = worker.wait_result(timeout=5)
    assert batch_action.error is None
    assert [call[2] for call in calls if call[0] == "action"][-2:] == [
        "group-a",
        "group-b",
    ]

    assert not any(call[0] == "export" for call in calls)
    output = tmp_path / "chosen-by-user.csv"
    worker.submit_export(output)
    second = worker.wait_result(timeout=5)
    assert second.error is None
    assert second.output == output
    assert [call[3] for call in calls if call[0] == "export"] == [output]

    worker.close(timeout=5)

    assert not worker.is_alive()
    assert [call[0] for call in calls].count("close") == 1
    assert calls[-1][0] == "close"
    assert all(call[1] != caller_thread for call in calls if len(call) > 1)


def test_review_worker_reports_edition_progress_before_reloading_groups(
    tmp_path: Path,
) -> None:
    calls = []

    class FakeRepository:
        def root_id_for_path_key(self, _path_key: str) -> int:
            return 7

        def group_summaries(self, root_id: int) -> tuple:
            calls.append(("load", root_id))
            return ()

        def close(self) -> None:
            pass

    def analyze(_repository, root_id, _cancel_event, *, set_keys, progress):  # type: ignore[no-untyped-def]
        assert root_id == 7
        assert set_keys == ("first", "second")
        progress(2, 10, "profiles")
        progress(1, 4, "relations")

    worker = ReviewWorker(
        tmp_path / "index.db",
        tmp_path / "source",
        repository_factory=lambda _: FakeRepository(),
        edition_analyzer=analyze,
    )
    worker.start()
    worker.submit_edition_analysis(("first", "second"))

    first = worker.wait_result(timeout=5)
    second = worker.wait_result(timeout=5)
    refreshing = worker.wait_result(timeout=5)
    done = worker.wait_result(timeout=5)
    worker.close(timeout=5)

    assert (first.operation, first.message) == (
        "progress",
        "선택 그룹 2개 · 판본 표본 분석 2/10 (완료된 분석은 재사용)",
    )
    assert (first.current, first.total) == (2, 10)
    assert (second.operation, second.message) == (
        "progress",
        "선택 그룹 2개 · 판본 관계 분류 1/4 (완료된 분석은 재사용)",
    )
    assert (second.current, second.total) == (1, 4)
    assert refreshing.operation == "progress"
    assert "갱신" in refreshing.message
    assert done.operation == "edition"
    assert done.groups == ()
    assert calls == [("load", 7)]


def test_review_worker_reports_precision_phases_and_can_cancel_immediately(
    tmp_path: Path,
) -> None:
    class FakeRepository:
        def root_id_for_path_key(self, _path_key: str) -> int:
            return 7

        def group_summaries(self, _root_id: int) -> tuple:
            return ()

        def close(self) -> None:
            pass

    received: list[tuple[str, ...]] = []

    def analyze(
        _repository, _root_id, cancel_event, *, set_keys, clock, progress
    ):  # type: ignore[no-untyped-def]
        assert clock() == datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
        received.append(set_keys)
        progress(
            PrecisionProgress(
                "precision_pages", 2, 10, 1, 2, 0, 1, 1, 12.0, 48.0, "a.cbz"
            )
        )
        progress(
            PrecisionProgress(
                "precision_relations", 1, 1, 2, 2, 1, 1, 2, 20.0, 0.0, "a.cbz ↔ b.cbz"
            )
        )
        assert not cancel_event.is_set()

    worker = ReviewWorker(
        tmp_path / "index.db",
        tmp_path / "source",
        repository_factory=lambda _: FakeRepository(),
        precision_analyzer=analyze,
        clock=lambda: datetime(2026, 8, 31, 12, 0, tzinfo=UTC),
    )
    worker.start()
    worker.submit_precision_analysis(("set-a", "set-b"))
    progress_messages = [worker.wait_result(timeout=5).message for _ in range(2)]
    assert "갱신" in worker.wait_result(timeout=5).message
    done = worker.wait_result(timeout=5)
    assert progress_messages == [
        "선택 그룹 2개 · 파일 1/2 · 페이지 2/10 · 캐시 1 · 경과 12초 · 남은 시간 48초 · a.cbz",
        "선택 그룹 2개 · 관계 1/1 · 작업 1/1 · 캐시 2 · 경과 20초 · 남은 시간 0초 · a.cbz ↔ b.cbz",
    ]
    assert done.operation == "precision"
    assert received == [("set-a", "set-b")]
    worker.cancel_long_operation()
    assert worker._cancel_event.is_set()  # noqa: SLF001 - immediate-cancel contract
    worker.close(timeout=5)


def test_review_window_starts_precision_for_selected_groups_and_keeps_cancel_enabled() -> None:
    submitted: list[tuple[str, ...]] = []
    button_states: list[str] = []
    status_updates: list[str] = []

    class FakeWorker:
        @staticmethod
        def submit_precision_analysis(set_keys: tuple[str, ...]) -> None:
            submitted.append(set_keys)

        @staticmethod
        def cancel_long_operation() -> None:
            pass

    class FakeButton:
        @staticmethod
        def configure(**kwargs) -> None:  # type: ignore[no-untyped-def]
            button_states.append(kwargs["state"])

    class FakeProgress:
        @staticmethod
        def configure(**_kwargs) -> None:  # type: ignore[no-untyped-def]
            pass

    class FakeStatus:
        @staticmethod
        def set(value: str) -> None:
            status_updates.append(value)

    window = object.__new__(review_ui.ReviewWindow)
    window._selected_group_keys = lambda: ("set-a", "set-b")  # type: ignore[method-assign]
    window._set_buttons_enabled = lambda _enabled: None  # type: ignore[method-assign]
    window._long_cancel_button = FakeButton()
    window._operation_progress = FakeProgress()
    window._status = FakeStatus()
    window._worker = FakeWorker()

    window._start_precision_analysis()
    window._cancel_long_operation()

    assert submitted == [("set-a", "set-b")]
    assert button_states == ["normal"]
    assert status_updates[-1] == "작업 중단을 요청했습니다..."


def test_review_worker_runs_quarantine_off_thread_and_reports_completion(
    tmp_path: Path,
) -> None:
    calls = []

    class FakeRepository:
        def root_id_for_path_key(self, _path_key: str) -> int:
            return 7

        def group_summaries(self, _root_id: int) -> tuple:
            return ()

        def group_details(self, key):
            from types import SimpleNamespace
            return SimpleNamespace(members=tuple(SimpleNamespace(archive_id=i, path=tmp_path / f"{i}.zip",
                file_size=1, mtime_ns=1, archive_format=__import__("archive_analyzer.domain", fromlist=["ArchiveFormat"]).ArchiveFormat.ZIP) for i in (1, 2)))

        def append_review_action(self, *args):
            pass

        def close(self) -> None:
            pass

    class Summary:
        processed = 2

    def quarantine_manager(
        repository,
        group_key,
        archive_ids,
        directory,
        _cancel_event,
        *,
        clock,
        progress,
    ):  # type: ignore[no-untyped-def]
        calls.append((repository, group_key, archive_ids, directory, get_ident()))
        progress(1, 2, "files")
        return Summary()

    worker = ReviewWorker(
        tmp_path / "index.db",
        tmp_path / "source",
        repository_factory=lambda _: FakeRepository(),
        quarantine_manager=quarantine_manager,
    )
    worker.start()
    worker.submit_quarantine("group", (1, 2), tmp_path / "quarantine")
    progress_result = worker.wait_result(timeout=5)
    done = worker.wait_result(timeout=5)
    worker.close(timeout=5)

    assert progress_result.message == "파일 처리 1/2"
    assert done.operation == "quarantine"
    assert done.message == "선택한 파일 2개를 안전하게 격리했습니다."
    assert calls[0][1:4] == (
        "group",
        (1, 2),
        tmp_path / "quarantine",
    )
    assert calls[0][4] != get_ident()


def test_review_worker_runs_permanent_delete_off_thread_and_reports_completion(
    tmp_path: Path,
) -> None:
    calls = []

    class FakeRepository:
        def root_id_for_path_key(self, _path_key: str) -> int:
            return 7

        def group_summaries(self, _root_id: int) -> tuple:
            return ()

        def close(self) -> None:
            pass

    class Summary:
        processed = 2

    def deletion_manager(
        repository,
        group_key,
        archive_ids,
        _cancel_event,
        *,
        clock,
        progress,
    ):  # type: ignore[no-untyped-def]
        calls.append((repository, group_key, archive_ids, get_ident()))
        progress(1, 2, "delete")
        return Summary()

    worker = ReviewWorker(
        tmp_path / "index.db",
        tmp_path / "source",
        repository_factory=lambda _: FakeRepository(),
        deletion_manager=deletion_manager,
    )
    worker.start()
    worker.submit_delete("group", (1, 2))
    progress_result = worker.wait_result(timeout=5)
    done = worker.wait_result(timeout=5)
    worker.close(timeout=5)

    assert progress_result.message == "삭제 전 파일 확인 1/2 바이트"
    assert done.operation == "delete"
    assert done.message == "선택한 격리 파일 2개를 휴지통 이동했습니다."
    assert calls[0][1:3] == ("group", (1, 2))
    assert calls[0][3] != get_ident()


def test_permanent_delete_ui_requires_both_confirmations() -> None:
    submitted = []
    status_updates = []
    group = _group()

    class FakeMessagebox:
        @staticmethod
        def askyesno(*_args, **_kwargs) -> bool:  # type: ignore[no-untyped-def]
            return True

        @staticmethod
        def showinfo(*_args, **_kwargs) -> None:  # type: ignore[no-untyped-def]
            raise AssertionError("exact confirmation should proceed")

    class FakeSimpledialog:
        @staticmethod
        def askstring(*_args, **_kwargs) -> str:  # type: ignore[no-untyped-def]
            return "영구삭제"

    class FakeWorker:
        @staticmethod
        def submit_delete(group_key: str, archive_ids: tuple[int, ...]) -> None:
            submitted.append((group_key, archive_ids))

    class FakeCancelButton:
        @staticmethod
        def configure(**kwargs) -> None:  # type: ignore[no-untyped-def]
            assert kwargs == {"state": "normal"}

    class FakeStatus:
        @staticmethod
        def set(value: str) -> None:
            status_updates.append(value)

    window = object.__new__(review_ui.ReviewWindow)
    window._groups = (group,)
    window._group_index = 0
    window._selected_archive_ids = lambda: (1, 3)  # type: ignore[method-assign]
    window._messagebox = FakeMessagebox()
    window._simpledialog = FakeSimpledialog()
    window._window = object()
    window._set_buttons_enabled = lambda _enabled: None  # type: ignore[method-assign]
    window._long_cancel_button = FakeCancelButton()
    window._status = FakeStatus()
    window._worker = FakeWorker()

    window._start_delete()

    assert submitted == [("group", (1, 3))]
    assert status_updates == ["격리 파일을 다시 검증한 뒤 휴지통 이동하는 중입니다..."]


def test_review_window_close_joins_after_drain_without_rescheduling() -> None:
    scheduled: list[object] = []
    status_updates: list[str] = []

    class FakeWindow:
        destroyed = False

        def after(self, delay: int, callback) -> None:  # type: ignore[no-untyped-def]
            assert delay == 100
            scheduled.append(callback)

        def destroy(self) -> None:
            self.destroyed = True

    class FakeWorker:
        def __init__(self, *, with_result: bool = True) -> None:
            self.alive = True
            self.requested = 0
            self.close_timeouts: list[float | None] = []
            self.results = (
                [
                    review_ui.ReviewWorkResult(
                        "load", error=sqlite3.OperationalError("secret database path")
                    )
                ]
                if with_result
                else []
            )

        def request_close(self) -> None:
            self.requested += 1

        def poll_result(self):  # type: ignore[no-untyped-def]
            return self.results.pop(0) if self.results else None

        def is_alive(self) -> bool:
            return self.alive

        def close(self, *, timeout: float | None = None) -> None:
            assert not self.alive
            self.close_timeouts.append(timeout)

    class FakeStatus:
        def set(self, value: str) -> None:
            status_updates.append(value)

    class FailingMessagebox:
        def showerror(self, *_args) -> None:  # type: ignore[no-untyped-def]
            raise AssertionError("closing window must ignore pending UI errors")

    window = object.__new__(review_ui.ReviewWindow)
    window._closing = False
    window._closed = False
    window._buttons = []
    window._window = FakeWindow()
    window._worker = FakeWorker()
    window._thumbnail_worker = FakeWorker(with_result=False)
    window._status = FakeStatus()
    window._messagebox = FailingMessagebox()

    window._request_close()
    window._poll_worker()

    assert window._worker.requested == 1
    assert window._thumbnail_worker.requested == 1
    assert len(scheduled) == 1
    assert not window._window.destroyed

    window._worker.alive = False
    window._thumbnail_worker.alive = False
    callback = scheduled.pop()
    callback()

    assert window._worker.close_timeouts == [0]
    assert window._thumbnail_worker.close_timeouts == [0]
    assert window._window.destroyed
    assert window.is_closed()
    assert scheduled == []
    assert status_updates == ["검토 기록 저장소를 닫는 중입니다..."]


def test_selecting_sequence_edge_aligns_the_first_matching_pages() -> None:
    edge = EdgeRow(
        left_archive_id=1,
        left_file_name="1.zip",
        right_archive_id=2,
        right_file_name="2.zip",
        relation_text="합본·개별권 포함",
        confidence=0.9,
        reason_text="포함",
        recommendation="MANUAL",
        recommendation_text="자동 보존 추천 없음",
        matched_pages=2,
        left_page_count=2,
        right_page_count=5,
        matched_pairs=((0, 2), (1, 3)),
    )
    group = replace(_group(), edges=(edge,))
    selected: list[tuple[str, ...]] = []
    requests: list[tuple[tuple[MemberRow, ...], bool]] = []

    class FakeEdgeTree:
        @staticmethod
        def selection() -> tuple[str, ...]:
            return ("edge-1-2",)

    class FakeEdgeTable:
        @staticmethod
        def row(item_id: str) -> EdgeRow | None:
            return edge if item_id == "edge-1-2" else None

    class FakeMemberTree:
        @staticmethod
        def selection_set(values) -> None:  # type: ignore[no-untyped-def]
            selected.append(tuple(values))

    window = object.__new__(review_ui.ReviewWindow)
    window._groups = (group,)
    window._group_index = 0
    window._edge_tree = FakeEdgeTree()
    window._edge_table = FakeEdgeTable()
    window._member_tree = FakeMemberTree()
    window._preview_page_indices = {}
    window._request_previews = (  # type: ignore[method-assign]
        lambda members, reset_pages=True: requests.append((members, reset_pages))
    )

    window._select_edge()

    assert selected == [("1", "2")]
    assert window._preview_page_indices == {1: 0, 2: 2}
    assert requests == [((group.members[0], group.members[1]), False)]


def test_stable_edge_id_selects_same_edge_after_sort() -> None:
    edge = EdgeRow(
        left_archive_id=1,
        left_file_name="1.zip",
        right_archive_id=2,
        right_file_name="2.zip",
        relation_text="유사",
        confidence=0.9,
        reason_text="근거",
        recommendation="MANUAL",
        recommendation_text="자동 보존 추천 없음",
        matched_pages=0,
        left_page_count=2,
        right_page_count=2,
    )

    assert review_ui._edge_row_id(edge, 99) == "edge-1-2"


def test_preview_size_upscales_without_changing_ratio() -> None:
    assert review_ui.fit_preview_size((100, 50), (420, 330), allow_upscale=True) == (420, 210)
    assert review_ui.fit_preview_size((1600, 900), (420, 330), allow_upscale=True) == (420, 236)


def test_review_window_preview_grid_expands_and_tables_keep_fixed_heights(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeWidget:
        def __init__(self, parent=None, **kwargs) -> None:  # type: ignore[no-untyped-def]
            self.parent = parent
            self.kwargs = kwargs
            self.rowconfigure_calls: list[tuple[int, dict[str, object]]] = []

        def pack(self, **_kwargs) -> None:  # type: ignore[no-untyped-def]
            pass

        def pack_propagate(self, _value) -> None:
            pass

        def place(self, **_kwargs) -> None:
            pass

        def grid(self, **_kwargs) -> None:  # type: ignore[no-untyped-def]
            pass

        def bind(self, *_args, **_kwargs) -> None:  # type: ignore[no-untyped-def]
            pass

        def configure(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
            self.kwargs.update(kwargs)

        def column(self, *_args, **_kwargs):
            pass

        def columnconfigure(self, *_args, **_kwargs) -> None:  # type: ignore[no-untyped-def]
            pass

        def rowconfigure(self, index: int, **kwargs) -> None:  # type: ignore[no-untyped-def]
            self.rowconfigure_calls.append((index, kwargs))

        def yview(self, *_args) -> None:  # type: ignore[no-untyped-def]
            pass

        def xview(self, *_args) -> None:  # type: ignore[no-untyped-def]
            pass

        def set(self, *_args) -> None:  # type: ignore[no-untyped-def]
            pass

        def add(self, *_args, **_kwargs) -> None:  # type: ignore[no-untyped-def]
            pass

    class FakeTopLevel(FakeWidget):
        def title(self, _value: str) -> None:
            pass

        def geometry(self, _value: str) -> None:
            pass

        def minsize(self, _width: int, _height: int) -> None:
            pass

        def protocol(self, *_args) -> None:  # type: ignore[no-untyped-def]
            pass

        def after(self, _delay: int, _callback) -> None:  # type: ignore[no-untyped-def]
            pass

    class FakeLabelFrame(FakeWidget):
        instances: list["FakeLabelFrame"] = []

        def __init__(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
            super().__init__(*args, **kwargs)
            self.instances.append(self)

    class FakeTreeview(FakeWidget):
        instances: list["FakeTreeview"] = []

        def __init__(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
            super().__init__(*args, **kwargs)
            self.instances.append(self)

    class FakeStringVar:
        def __init__(self, value: str = "") -> None:
            self.value = value

        def get(self) -> str:
            return self.value

        def set(self, value: str) -> None:
            self.value = value

    class FakeWorker:
        def __init__(self, *_args, **_kwargs) -> None:  # type: ignore[no-untyped-def]
            pass

        def start(self) -> None:
            pass

        def submit_load(self) -> None:
            pass

    class FakeTable:
        def __init__(self, *_args, **_kwargs) -> None:  # type: ignore[no-untyped-def]
            pass

        def bind(self) -> None:
            pass

        def select_all_visible(self):
            pass

        def restore_columns(self, defaults):
            pass

        def save_widths(self) -> None:
            pass

    tkinter = SimpleNamespace(
        Toplevel=FakeTopLevel,
        StringVar=FakeStringVar,
        BooleanVar=FakeStringVar,
        Frame=FakeWidget,
        Label=FakeWidget,
        filedialog=object(),
        messagebox=object(),
        simpledialog=object(),
        ttk=SimpleNamespace(
            Frame=FakeWidget,
            Label=FakeWidget,
            Entry=FakeWidget,
            Combobox=FakeWidget,
            Panedwindow=FakeWidget,
            Notebook=FakeWidget,
            Treeview=FakeTreeview,
            Scrollbar=FakeWidget,
            Button=FakeWidget,
            Checkbutton=FakeWidget,
            LabelFrame=FakeLabelFrame,
            Progressbar=FakeWidget,
        ),
    )
    monkeypatch.setitem(sys.modules, "tkinter", tkinter)
    monkeypatch.setattr(review_ui, "ReviewWorker", FakeWorker)
    monkeypatch.setattr(review_ui, "ThumbnailWorker", FakeWorker)
    monkeypatch.setattr(review_ui, "TreeTableController", FakeTable)
    monkeypatch.setattr(review_ui, "TreeLassoController", FakeTable)
    monkeypatch.setattr(review_ui, "apply_review_theme", lambda _: None)

    window = review_ui.ReviewWindow(object(), Path("index.db"), Path("source"))

    preview = next(frame for frame in FakeLabelFrame.instances if "미리보기" in frame.kwargs["text"])
    assert (1, {"weight": 1}) in preview.rowconfigure_calls
    assert [tree.kwargs["height"] for tree in FakeTreeview.instances] == [4, 4, 4]
    assert window._member_tree is FakeTreeview.instances[1]
    assert window._edge_tree is FakeTreeview.instances[2]


@pytest.mark.parametrize(
    "error",
    (
        sqlite3.OperationalError("secret database path"),
        OSError("secret export path"),
        ValueError("internal group key"),
        RuntimeError("unexpected implementation detail"),
    ),
)
def test_review_friendly_error_hides_raw_technical_details(error: BaseException) -> None:
    message = review_ui.friendly_review_error(error)

    assert "secret" not in message
    assert "internal group key" not in message
    assert "unexpected implementation detail" not in message
