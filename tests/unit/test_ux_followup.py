from dataclasses import replace
from pathlib import Path
from threading import Event
from types import SimpleNamespace
import tkinter as tk
from tkinter import font, ttk

import pytest
from archive_analyzer import review_ui, deletion
from archive_analyzer.recommendation import recommend_candidate_set, RecommendationStatus
from archive_analyzer.review_table import UiSettingsStore
from archive_analyzer.review_viewmodel import build_group_view
from tests.unit.test_precision_service import _repository_with_images, FakeReader, FakeOcr, _encoded_page
from tests.unit.test_review_followup_september9 import candidate, evidence_for


def test_title_breaks_ties_before_time_but_content_conflicts_still_block():
    left = replace(candidate(), title_rank=3, mtime_ns=1_000_000_000,
                   evidence_sources={"language": "precision", "mosaic": "unknown", "color": "unknown"})
    right = replace(candidate(2), title_rank=1, mtime_ns=10_000_000_000, evidence_sources=left.evidence_sources)
    result = recommend_candidate_set((left, right), evidence_for(left, right))
    assert result.items[0].recommendation == "KEEP"
    right = replace(right, title_rank=3)
    assert recommend_candidate_set((left, right), evidence_for(left, right)).items[1].recommendation == "KEEP"
    # An older larger file still conflicts with the newer smaller file.
    left = replace(left, file_size=right.file_size * 2)
    assert recommend_candidate_set((left, right), evidence_for(left, right)).status is RecommendationStatus.NONE


def test_image_analysis_default_does_not_compare_mosaic(tmp_path, monkeypatch):
    from archive_analyzer import precision_service
    repo, root_id, _ = _repository_with_images(tmp_path, (4, 4))
    monkeypatch.setattr(precision_service, "_compare_relation", lambda *a, **k: pytest.fail("mosaic images opened"))
    try:
        result = precision_service.analyze_precision(repo, root_id, Event(), set_keys=("precision-set",),
            reader=FakeReader(_encoded_page()), ocr=FakeOcr(("こんにちは日本語の文章です" * 5,) * 8))
        assert result.relations_processed == 0
        assert result.profiles_processed == 2
    finally:
        repo.close()


def test_recycle_failure_preserves_file_and_records_failure(tmp_path, monkeypatch):
    from tests.unit.test_deletion import _quarantined
    repo, key, archive_id, source, destination = _quarantined(tmp_path)
    def refuse(path):
        raise OSError("recycle unavailable")
    monkeypatch.setattr(deletion, "recycle_file", refuse)
    try:
        with pytest.raises(deletion.DeletionSafetyError):
            deletion.delete_quarantined_archives(repo, key, (archive_id,), Event())
        assert destination.is_file() and not source.exists()
        assert repo._connection.execute("SELECT state FROM deletion_records").fetchone() == ("FAILED",)
    finally:
        repo.close()


def test_native_multilingual_layout_navigation_and_preferences(tmp_path):
    # One Tcl interpreter per process, matching the desktop application lifetime.
    import subprocess
    import sys
    result = subprocess.run([sys.executable, "-c",
        "import sys,pytest; from pathlib import Path; from tests.unit.test_ux_followup import _native_check; "
        "_native_check(Path(sys.argv[1]),pytest.MonkeyPatch())", str(tmp_path)],
        capture_output=True, text=True, timeout=40, creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stdout + result.stderr


def _native_check(tmp_path, monkeypatch):
    repo, _, _ = _repository_with_images(tmp_path, (6, 6))
    group = build_group_view(repo.review_group_details("precision-set"))
    repo.close()
    class Idle:
        def __init__(self, *args): pass
        def start(self): pass
        def submit_load(self): pass
        def poll_result(self): return None
    monkeypatch.setattr(review_ui, "ReviewWorker", Idle)
    monkeypatch.setattr(review_ui, "ThumbnailWorker", Idle)
    monkeypatch.setattr(review_ui.ReviewWindow, "_request_previews", lambda *a, **kw: None)
    store = UiSettingsStore(tmp_path / "ui.json")
    store.save_preference("quarantine_root", str(tmp_path / "격리"))
    monkeypatch.setattr(review_ui, "UiSettingsStore", lambda: store)
    root = tk.Tk(); root.withdraw()
    try:
        window = review_ui.ReviewWindow(root, tmp_path / "index.db", tmp_path)
        window._window.attributes("-alpha", 0)
        window._window.maxsize(4096, 4096)
        groups = tuple(replace(group, group_key=f"g{i}", set_key=f"g{i}", work_label=f"{i:03} 한국어 日本語 中文 English") for i in range(600))
        window._render_groups(groups)
        window._finish_operation()
        window._window.geometry("1280x860"); root.update()
        assert font.nametofont("TkDefaultFont", root=root).actual("family").casefold() in {"malgun gothic", "맑은 고딕"}
        assert window._preview_slots[0][0].winfo_height() >= 140
        assert window._quarantine_root == tmp_path / "격리"
        window._group_tree.selection_set("g200"); root.update()
        window._render_groups(tuple(g for g in groups if g.group_key != "g200")); root.update()
        assert window._current_group().group_key == "g201"
        assert window._group_tree.selection() == ("g201",)
        assert ttk.Style(root).map("Horizontal.TScrollbar", "background")[0][-1] == "#191d24"
        window._toggle_preview_layout(); root.update()
        assert store.preference("preview_layout") == "vertical"
        assert window._preview_cards[1].grid_info()["row"] == 2
        window._toggle_preview_layout()
        old_height = window._preview_slots[0][0].winfo_height()
        window._toggle_preview_expand(); root.update()
        assert window._preview_slots[0][0].winfo_height() > old_height
        window._toggle_preview_expand(); root.update()
        window._preview_archive_ids = tuple(m.archive_id for m in group.members)
        window._preview_page_indices = {m.archive_id: 0 for m in group.members}
        window._move_preview_page(0, 1)
        assert set(window._preview_page_indices.values()) == {1}
        window._preview_sync.set(False)
        window._move_preview_page(0, 1)
        assert list(window._preview_page_indices.values()) == [2, 1]
        keys = []
        trash_group = replace(groups[0], members=tuple(replace(m, quarantine_status="QUARANTINED") for m in group.members))
        window._render_groups((trash_group,)); window._group_tabs.select(2); root.update()
        window._messagebox = SimpleNamespace(askyesno=lambda *a, **k: True)
        window._worker.submit_batch_delete = lambda value: keys.append(value)
        window._start_group_trash()
        assert keys == [("g0",)]
    finally:
        root.destroy()
