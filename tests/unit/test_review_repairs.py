"""Focused regression checks using only newly generated files and databases."""
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from threading import Event
import time

from PIL import Image

from archive_analyzer import review_ui
from archive_analyzer.edition_service import analyze_editions
from archive_analyzer.precision_service import analyze_precision
from archive_analyzer.review_table import UiSettingsStore
from archive_analyzer.review_viewmodel import build_group_view
from archive_analyzer.sequence_analysis import analyze_sequence_relations
from archive_analyzer.storage.duplicate_repository import ReviewCandidateSet
from tests.unit.test_precision_service import (
    FakeOcr, FakeReader, _encoded_page, _insert_visual_relation, _repository_with_images,
)


def test_multiple_selected_sets_align_equal_length_books_and_reuse_cache(tmp_path):
    repository, root_id, ids = _repository_with_images(tmp_path, (6,) * 6)
    try:
        connection = repository._connection
        for offset in (0, 2, 4):
            _insert_visual_relation(connection, root_id, ids[offset], ids[offset + 1], 6)
        connection.execute("DELETE FROM sequence_relations")
        connection.commit()
        repository.replace_candidate_sets("precision-group", tuple(
            ReviewCandidateSet(f"set-{i}", "precision-group", "MIXED_OR_UNKNOWN", ids[i * 2:i * 2 + 2])
            for i in range(3)
        ))
        selected = ("set-0", "set-1")
        # The inclusion classifier deliberately returns no inclusion for equal books.
        sequence = analyze_sequence_relations(repository, root_id, Event(), set_keys=selected)
        assert sequence.processed == 2
        assert {row[0] for row in connection.execute("SELECT archive_a_id FROM sequence_relations")} == {ids[0], ids[2]}

        edition = analyze_editions(repository, root_id, Event(), set_keys=selected, reader=FakeReader(_encoded_page()))
        assert edition.profiles_processed == 4
        assert {row[0] for row in connection.execute("SELECT archive_id FROM edition_profiles")} == set(ids[:4])

        first = analyze_precision(repository, root_id, Event(), set_keys=selected,
                                  reader=FakeReader(_encoded_page()), ocr=FakeOcr(), compare_images=True)
        assert first.relations_processed == 2
        rows = connection.execute("SELECT archive_a_id, evidence_json FROM precision_relations").fetchall()
        assert {row[0] for row in rows} == {ids[0], ids[2]}
        assert all("no aligned pages" not in row[1] for row in rows)
        view = build_group_view(repository.review_group_details("set-0"))
        assert view.members[0].mosaic_text == "유모 (추정)"
        assert "내용 기반 모자이크" not in view.edges[0].reason_text

        reader, ocr = FakeReader(_encoded_page()), FakeOcr()
        warm = analyze_precision(repository, root_id, Event(), set_keys=selected, reader=reader, ocr=ocr, compare_images=True)
        assert warm.profiles_processed == warm.relations_processed == reader.calls == ocr.calls == 0
        # Repair only old 'no aligned pages' decisions, retaining the OCR cache.
        connection.execute("UPDATE precision_relations SET evidence_json = '[\"mosaic:no aligned pages\"]'")
        connection.commit()
        repaired = analyze_precision(repository, root_id, Event(), set_keys=selected, reader=reader, ocr=ocr, compare_images=True)
        assert repaired.relations_processed == 2
        assert reader.calls == ocr.calls == 0
    finally:
        repository.close()


def test_real_tk_preview_stays_stable_on_wheel_and_resize(tmp_path, monkeypatch):
    import tkinter as tk
    from tkinter import ttk

    repository, _, _ = _repository_with_images(tmp_path, (6, 6))
    group = build_group_view(repository.review_group_details("precision-set"))
    repository.close()

    class IdleWorker:
        def __init__(self, *args):
            pass
        def start(self):
            pass
        def submit_load(self):
            pass
        def poll_result(self):
            return None

    class PageReader:
        calls = 0
        def read(self, snapshot, entry, *, same_path_count):
            self.calls += 1
            size = ((100, 800), (1600, 80), (32, 32))[entry.position % 3]
            output = BytesIO()
            Image.new("RGB", size, (30, 90, 180)).save(output, format="PNG")
            return output.getvalue()

    reader = PageReader()
    real_thumbnail_worker = review_ui.ThumbnailWorker
    monkeypatch.setattr(review_ui, "ReviewWorker", IdleWorker)
    monkeypatch.setattr(review_ui, "ThumbnailWorker", lambda db: real_thumbnail_worker(db, reader))
    monkeypatch.setattr(review_ui, "UiSettingsStore", lambda: UiSettingsStore(tmp_path / "ui.json"))
    root = tk.Tk()
    root.withdraw()
    window = None

    def pump(seconds=0.65):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            root.update()
            time.sleep(0.01)

    try:
        window = review_ui.ReviewWindow(root, tmp_path / "index.db", tmp_path)
        window._window.attributes("-alpha", 0)
        window._window.attributes("-toolwindow", True)
        window._render_groups((group, replace(group, group_key="second", set_key="second")))
        pump()
        for page in (1, 2, 1):
            current = window._preview_page_indices[group.members[0].archive_id]
            window._move_preview_page(0, page - current)
            pump()
            generation = window._thumbnail_generation
            sizes = tuple(window._preview_slot_size(slot[0]) for slot in window._preview_slots)
            pump()
            assert window._thumbnail_generation == generation, "image geometry caused repeated reloads"
            assert sizes == tuple(window._preview_slot_size(slot[0]) for slot in window._preview_slots)
            assert len(window._thumbnail_images) == 2
        before_resize = reader.calls
        for geometry in ("1000x700", "1400x900", "1280x860"):
            window._window.geometry(geometry)
            pump()
            assert reader.calls == before_resize, "resizing re-extracted archive pages"
            for button in (*window._buttons, window._long_cancel_button):
                assert button.winfo_ismapped(), button.cget("text")
                assert button.winfo_x() + button.winfo_width() <= button.master.winfo_width() + 1, button.cget("text")
        # Four-row file/evidence tables reserve more height than the old two-row layout.
        assert window._preview_slot_size(window._preview_slots[0][0])[1] >= 140
        saved_pages = dict(window._preview_page_indices)
        window._render_groups((group, replace(group, group_key="second", set_key="second")))
        pump()
        assert window._preview_page_indices == saved_pages
        for member, (_, caption, page_label) in zip(group.members, window._preview_slots):
            assert f"{member.member_number}번" in caption.cget("text")
            assert member.file_name in caption.cget("text")
            assert "페이지" in page_label.cget("text")
        for tree in (window._member_tree, window._edge_tree):
            while len(tree.get_children()) < 4:
                tree.insert("", "end", values=("four-row check",))
            pump()
            assert tree.bbox(tree.get_children()[3]), "fourth row is outside the viewport"
        window._group_tree.selection_set((group.group_key, "second"))
        window._group_table.toggle_sort("number")
        assert set(window._selected_group_keys()) == {group.group_key, "second"}
        window._set_buttons_enabled(False)
        window._update_group_batch_buttons()
        assert all(str(button.cget("state")) == "disabled" for button in window._bulk_group_buttons)
    finally:
        if window is not None:
            window._closing = True
            window._thumbnail_worker.close(timeout=15)
        root.destroy()


def test_mosaic_direction_reaches_review_from_image_content_without_title_hint(tmp_path):
    from tests.unit.test_precision_analysis import _clear_page, _pixelate

    repository, root_id, ids = _repository_with_images(tmp_path, (3, 3))
    try:
        connection = repository._connection
        _insert_visual_relation(connection, root_id, *ids, 3)
        connection.execute("DELETE FROM sequence_relations")
        connection.commit()
        class ContentReader:
            def read_many(self, snapshot, requests, *, cancel_check):
                for entry, _ in requests:
                    cancel_check()
                    page = _clear_page(entry.position)
                    if snapshot.path.name == "archive-2.cbz":
                        page = _pixelate(page)
                    output = BytesIO()
                    Image.fromarray(page.astype("uint8")).save(output, format="PNG")
                    yield output.getvalue()
        analyze_precision(repository, root_id, Event(), set_keys=("precision-set",),
                          reader=ContentReader(), ocr=FakeOcr(), compare_images=True)
        view = build_group_view(repository.review_group_details("precision-set"))
        assert view.members[0].mosaic_text == "유모 (추정)"
        assert view.members[1].mosaic_text == "유모 (추정)"
        assert "모자이크" not in view.edges[0].reason_text
        assert all("파일명 추정" not in member.mosaic_text for member in view.members)
    finally:
        repository.close()
