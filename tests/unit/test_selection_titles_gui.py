"""Exercise actual Tk bindings in a disposable review window."""
from dataclasses import replace
import tkinter as tk

from archive_analyzer import review_ui
from archive_analyzer.review_table import UiSettingsStore
from archive_analyzer.review_viewmodel import build_group_view
from tests.unit.test_precision_service import _repository_with_images


def test_review_lists_drag_from_rows_blank_space_and_preserve_clicks(tmp_path, monkeypatch):
    repository, _, _ = _repository_with_images(tmp_path, (6, 6))
    group = build_group_view(repository.review_group_details("precision-set"))
    repository.close()

    class IdleWorker:
        def __init__(self, *args): pass
        def start(self): pass
        def submit_load(self): pass
        def poll_result(self): return None

    monkeypatch.setattr(review_ui, "ReviewWorker", IdleWorker)
    monkeypatch.setattr(review_ui, "ThumbnailWorker", IdleWorker)
    monkeypatch.setattr(review_ui.ReviewWindow, "_request_previews", lambda *args, **kwargs: None)
    monkeypatch.setattr(review_ui, "UiSettingsStore", lambda: UiSettingsStore(tmp_path / "ui.json"))
    root = tk.Tk()
    root.withdraw()
    try:
        window = review_ui.ReviewWindow(root, tmp_path / "index.db", tmp_path)
        window._window.attributes("-alpha", 0)
        window._window.attributes("-toolwindow", True)
        window._render_groups(tuple(replace(group, group_key=f"group-{i}", set_key=f"group-{i}") for i in range(4)))
        root.update()
        for tree in (window._group_tree, window._member_tree):
            ids = tree.get_children()
            def point(item):
                x, y, w, h = tree.bbox(item)
                return (40, y + h // 2)
            clock = 10000
            def emit(event, pt, state=0):
                nonlocal clock
                clock += 1000
                tree.event_generate(event, x=pt[0], y=pt[1], state=state, time=clock)
                root.update()
            first, second = point(ids[0]), point(ids[1])
            emit("<ButtonPress-1>", first)
            emit("<B1-Motion>", second, 256)
            emit("<ButtonRelease-1>", second)
            assert tree.selection() == ids[:2]
            # Reverse direction, starting on an already selected row.
            emit("<ButtonPress-1>", second)
            emit("<B1-Motion>", first, 256)
            emit("<ButtonRelease-1>", first)
            assert tree.selection() == ids[:2]
            emit("<ButtonPress-1>", second)
            emit("<ButtonRelease-1>", second)
            assert tree.selection() == (ids[1],)
            emit("<ButtonPress-1>", first, 1)
            emit("<ButtonRelease-1>", first, 1)
            assert tree.selection() == ids[:2]
            # Heading presses must not arm a drag selection.
            emit("<ButtonPress-1>", (40, 5))
            emit("<B1-Motion>", second, 256)
            emit("<ButtonRelease-1>", second)
            assert tree.selection() == ids[:2]
        tree = window._group_tree
        tree.configure(height=10)
        root.update()
        ids = tree.get_children()
        first, last = tree.bbox(ids[0]), tree.bbox(ids[-1])
        blank = (40, last[1] + last[3] + 8)
        tree.event_generate("<ButtonPress-1>", x=blank[0], y=blank[1])
        tree.event_generate("<B1-Motion>", x=40, y=first[1]+5, state=256)
        tree.event_generate("<ButtonRelease-1>", x=40, y=first[1]+5)
        root.update()
        assert tree.selection() == ids
        # Ctrl-drag keeps an existing disjoint selection.
        tree.selection_set(ids[-1])
        tree.event_generate("<ButtonPress-1>", x=40, y=first[1]+5, state=4)
        tree.event_generate("<B1-Motion>", x=40, y=first[1]+first[3]+5, state=260)
        tree.event_generate("<ButtonRelease-1>", x=40, y=first[1]+first[3]+5, state=4)
        root.update()
        assert set(tree.selection()) == {ids[0], ids[1], ids[-1]}
        # Start from surrounding frame space, not the Treeview widget.
        for tree in (window._group_tree, window._member_tree):
            ids = tree.get_children()
            first, second = tree.bbox(ids[0]), tree.bbox(ids[1])
            frame = tree.master
            tree.selection_remove(tree.selection())
            frame.event_generate("<ButtonPress-1>", x=-8, y=first[1]+5, time=100000)
            frame.event_generate("<B1-Motion>", x=40, y=second[1]+5, state=256, time=101000)
            frame.event_generate("<ButtonRelease-1>", x=40, y=second[1]+5, time=102000)
            root.update()
            assert tree.selection() == ids[:2]
        # Worked groups leave the pending tab; switching tabs re-enables actions.
        from archive_analyzer.duplicate_domain import ReviewAction
        completed = replace(group, group_key="done", set_key="done", members=tuple(
            replace(m, user_decision=ReviewAction.KEEP) for m in group.members))
        window._render_groups((completed,))
        window._finish_operation()
        assert not window._groups
        window._group_tabs.select(1)
        root.update()
        assert window._groups == (completed,)
        assert window._actions_enabled
    finally:
        root.destroy()
