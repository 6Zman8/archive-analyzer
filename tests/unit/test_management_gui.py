from dataclasses import replace
import tkinter as tk
from tkinter import ttk
from archive_analyzer import review_ui
from archive_analyzer.review_table import UiSettingsStore, TableFilter
from archive_analyzer.review_viewmodel import build_group_view
from tests.unit.test_precision_service import _repository_with_images


def test_dense_dark_review_keeps_600_groups_filter_selection_and_four_rows(tmp_path):
    import subprocess, sys
    result = subprocess.run([sys.executable, "-c",
        "import sys,pytest; from pathlib import Path; from tests.unit.test_management_gui import _native_layout; "
        "_native_layout(Path(sys.argv[1]),pytest.MonkeyPatch())", str(tmp_path)],
        capture_output=True, text=True, timeout=40, creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stdout + result.stderr


def _native_layout(tmp_path, monkeypatch):
    repo, _, _ = _repository_with_images(tmp_path, (6, 6))
    group = build_group_view(repo.review_group_details('precision-set'))
    repo.close()
    class Idle:
        def __init__(self,*args): pass
        def start(self): pass
        def submit_load(self): pass
        def poll_result(self): return None
    monkeypatch.setattr(review_ui, 'ReviewWorker', Idle)
    monkeypatch.setattr(review_ui, 'ThumbnailWorker', Idle)
    monkeypatch.setattr(review_ui.ReviewWindow, '_request_previews', lambda *args,**kwargs: None)
    monkeypatch.setattr(review_ui, 'UiSettingsStore', lambda: UiSettingsStore(tmp_path/'ui.json'))
    root=tk.Tk();root.withdraw()
    try:
        window=review_ui.ReviewWindow(root,tmp_path/'index.db',tmp_path)
        window._window.attributes('-alpha',0)
        rows=tuple(replace(group,group_key=f'g{i}',set_key=f'g{i}',work_label=f'작품 {i:03}') for i in range(600))
        window._render_groups(rows)
        root.update()
        assert len(window._group_tree.get_children())==600
        # Require ten usable rows instead of assuming a fixed DPI/font height.
        visible_rows = sum(bool(window._group_tree.bbox(item)) for item in window._group_tree.get_children())
        assert visible_rows >= 10, (window._window.geometry(), visible_rows)
        assert int(window._member_tree.cget('height')) >= 4
        assert int(window._edge_tree.cget('height')) >= 4
        assert 'recommendation' in window._member_tree.cget('columns')
        assert ttk.Style(root).lookup('Treeview','background') == '#20252d'
        window._group_table.set_filters({'work':TableFilter(allowed=frozenset({'작품 010','작품 020'}))})
        assert len(window._group_tree.get_children())==2
        window._group_table.select_all_visible()
        assert len(window._group_tree.selection())==2
        window._group_table.set_filters({})
        assert len(window._group_tree.get_children())==600
        window._group_tabs.select(4);root.update()
        assert len(window._group_tree.get_children())==0
    finally:
        root.destroy()
