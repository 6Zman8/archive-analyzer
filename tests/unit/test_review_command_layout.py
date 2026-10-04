"""The compact workspace must keep every former action reachable and guarded."""
from dataclasses import replace
import tkinter as tk
from tkinter import ttk

import pytest

from archive_analyzer import review_ui
from archive_analyzer.review_table import UiSettingsStore
from archive_analyzer.review_viewmodel import build_group_view
from tests.unit.test_precision_service import _repository_with_images


@pytest.fixture(scope="module")
def root():
    value = tk.Tk()
    value.withdraw()
    yield value
    value.destroy()


@pytest.fixture
def workspace(root, tmp_path, monkeypatch):
    repository, _, _ = _repository_with_images(tmp_path, (6, 6))
    group = build_group_view(repository.review_group_details("precision-set"))
    repository.close()
    class Idle:
        def __init__(self, *args): pass
        def start(self): pass
        def submit_load(self): pass
        def poll_result(self): return None
    monkeypatch.setattr(review_ui, "ReviewWorker", Idle)
    monkeypatch.setattr(review_ui, "ThumbnailWorker", Idle)
    monkeypatch.setattr(review_ui.ReviewWindow, "_request_previews", lambda *a, **k: None)
    monkeypatch.setattr(review_ui, "UiSettingsStore", lambda: UiSettingsStore(tmp_path / "ui.json"))
    window = review_ui.ReviewWindow(root, tmp_path / "index.db", tmp_path)
    window._window.attributes("-alpha", 0)
    window._window.maxsize(4096, 4096)
    window._render_groups(tuple(replace(group, group_key=f"g{i}", set_key=f"g{i}") for i in range(20)))
    window._finish_operation()
    yield window
    window._window.destroy()


def test_every_former_action_has_a_named_menu_location(workspace):
    required = {
        "검사 화면", "후보 CSV 내보내기", "격리 폴더 선택",
        "추천값 일괄 적용", "추정값 일괄 적용", "검토결과 일괄작업", "미검토 일괄 보존",
        "선택 그룹 휴지통 이동", "선택 그룹 격리 되돌리기", "선택 그룹 검토 초기화",
        "추천 기준 설정", "이미지 정밀분석", "페이지 포함 관계 분석", "판본 차이 분석",
        "보존", "제거 후보", "탐색기에서 위치 열기", "반디뷰로 열기",
        "선택 파일 격리", "선택 파일 되돌리기", "선택 파일 휴지통 이동",
        "그룹 표시 열", "그룹 필터", "그룹 전체선택", "그룹 필터 해제",
        "요약 / 상세 열", "파일 표시 열", "파일 필터", "관계 표시 열", "관계 필터",
        "차이 후보 페이지", "좌우 교환", "확대 / 복귀", "가로 / 세로 배치",
        "이전 그룹", "다음 그룹", "이전 페이지", "다음 페이지",
    }
    assert required <= workspace._commands.keys()
    for name in required:
        action = workspace._commands[name]
        assert action.menu.entrycget(action.index, "label")
        assert action.menu.winfo_exists()


def test_bulk_scope_and_busy_guards_survive_menu_move(workspace):
    workspace._group_tree.selection_remove(*workspace._group_tree.selection())
    workspace._update_group_batch_buttons()
    assert len(workspace._default_all_group_buttons) == 4
    assert all(action.cget("state") == "normal" for action in workspace._default_all_group_buttons)
    assert workspace._commands["이미지 정밀분석"].cget("state") == "disabled"
    assert workspace._commands["선택 그룹 휴지통 이동"].cget("state") == "disabled"
    workspace._group_tree.selection_set("g0")
    workspace._update_group_batch_buttons()
    assert workspace._commands["이미지 정밀분석"].cget("state") == "normal"
    calls = []
    action = workspace._commands["선택 파일 휴지통 이동"]
    action.callback = lambda: calls.append("delete")
    workspace._set_buttons_enabled(False)
    action.invoke()
    action.menu.invoke(action.index)
    assert not calls
    assert all(action.cget("state") == "disabled" for action in workspace._buttons)


def test_small_window_keeps_primary_controls_and_comparison_visible(workspace):
    def walk(parent):
        for child in parent.winfo_children():
            yield child
            yield from walk(child)
    for width, height in ((1000, 700), (1280, 860), (1440, 960)):
        workspace._window.geometry(f"{width}x{height}")
        workspace._window.update()
        visible = [widget for widget in walk(workspace._window)
                   if isinstance(widget, (ttk.Button, ttk.Menubutton)) and widget.winfo_ismapped()]
        assert len(visible) <= 18, [widget.cget("text") for widget in visible]
        for widget in visible:
            assert widget.winfo_x() + widget.winfo_width() <= widget.master.winfo_width() + 1, widget.cget("text")
        assert workspace._preview_slots[0][0].winfo_height() >= 140
        assert workspace._group_tabs.winfo_reqwidth() <= workspace._group_tabs.winfo_width()

