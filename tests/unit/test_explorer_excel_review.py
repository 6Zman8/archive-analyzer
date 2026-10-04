from dataclasses import replace
from pathlib import Path
from zipfile import ZipFile
from io import BytesIO
from datetime import UTC, datetime
from threading import Event

from PIL import Image
from archive_analyzer import review_ui
from archive_analyzer.duplicate_domain import ReviewAction
from archive_analyzer.paths import normalize_path_key
from archive_analyzer.review_viewmodel import build_group_view
from archive_analyzer.review_table import TableFilter, TableState, ColumnSpec, ColumnKind, apply_table_state
from archive_analyzer.recommendation import recommend_candidate_set, PairEvidence
from archive_analyzer.precision_analysis import DetectedLanguage, PairDirection
from tests.unit.test_recommendation import candidate
from tests.unit.test_precision_service import _repository_with_images, _insert_visual_relation


def real_fixture(tmp_path, counts=(4, 5)):
    repository, root_id, ids = _repository_with_images(tmp_path, counts)
    conn = repository._connection
    for archive_id in ids:
        row = conn.execute("SELECT path, image_count FROM archives WHERE id=?", (archive_id,)).fetchone()
        path, count = Path(row[0]), row[1]
        with ZipFile(path, "w") as archive:
            for i in range(count):
                output = BytesIO()
                Image.new("RGB", (48, 64), (i * 30, 80, 140)).save(output, format="PNG")
                archive.writestr(f"{i:03}.png", output.getvalue())
                conn.execute("UPDATE archive_entries SET uncompressed_size=? WHERE archive_id=? AND position=?",
                             (len(output.getvalue()), archive_id, i))
        stat = path.stat()
        conn.execute("UPDATE archives SET path_key=?,file_size=?,mtime_ns=? WHERE id=?",
                     (normalize_path_key(path), stat.st_size, stat.st_mtime_ns, archive_id))
        conn.execute("UPDATE archive_fingerprints SET file_size=?,mtime_ns=? WHERE archive_id=?",
                     (stat.st_size, stat.st_mtime_ns, archive_id))
    conn.commit()
    _insert_visual_relation(conn, root_id, *ids, 4)
    return repository, root_id, ids


def test_derived_review_manual_quarantine_preview_restore_delete(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    repository, root_id, ids = real_fixture(source)
    worker = review_ui.ReviewWorker(source / "index.db", source)
    Work = review_ui._ReviewWork
    try:
        loaded = worker._perform(repository, root_id, Work("load"))
        group = loaded.groups[0]
        assert group.recommended_archive_id is None
        assert group.group_key != group.source_group_key
        reviewed = worker._perform(repository, root_id, Work("actions", group_key=group.group_key,
            archive_ids=(ids[1],), action=ReviewAction.KEEP))
        assert next(m for m in reviewed.groups[0].members if m.archive_id == ids[1]).user_decision is ReviewAction.KEEP
        assert review_ui.group_work_tab(reviewed.groups[0]) == 0
        # Direct quarantine needs no preceding REMOVE_CANDIDATE click.
        moved = worker._perform(repository, root_id, Work("quarantine", group_key=group.group_key,
            archive_ids=(ids[0],), directory=tmp_path / "quarantine"))
        assert review_ui.group_work_tab(moved.groups[0]) == 2
        member = next(m for m in moved.groups[0].members if m.archive_id == ids[0])
        assert member.path == member.quarantine_path and member.path.is_file()
        preview = review_ui.ThumbnailWorker(source / "index.db")._load(member, 0, (200, 200))
        assert Image.open(BytesIO(preview)).size == (150, 200)
        window = object.__new__(review_ui.ReviewWindow)
        window._selected_member = lambda: member
        calls = []
        monkeypatch.setattr(review_ui.subprocess, "Popen", lambda args: calls.append(args))
        monkeypatch.setattr(review_ui, "find_bandiview_executable", lambda: Path("BandiView.exe"))
        window._reveal_selected_file()
        window._open_selected_in_bandiview()
        assert all(str(member.path) in call for call in calls) and len(calls) == 2
        restored = worker._perform(repository, root_id, Work("restore", group_key=group.group_key, archive_ids=(ids[0],)))
        restored_member = next(m for m in restored.groups[0].members if m.archive_id == ids[0])
        assert restored_member.path.is_file() and restored_member.path != member.path
        assert review_ui.group_work_tab(restored.groups[0]) == 1
        worker._perform(repository, root_id, Work("quarantine", group_key=group.group_key,
            archive_ids=(ids[0],), directory=tmp_path / "quarantine"))
        deleted = worker._perform(repository, root_id, Work("delete", group_key=group.group_key, archive_ids=(ids[0],)))
        assert review_ui.group_work_tab(deleted.groups[0]) == 3
        assert not member.path.exists()
        assert next(m for m in deleted.groups[0].members if m.archive_id == ids[1]).path.is_file()
    finally:
        repository.close()


def test_unknown_language_blocks_even_better_korean_metadata():
    left = candidate(language=DetectedLanguage.KOREAN, size=890)
    right = candidate(2, language=DetectedLanguage.UNKNOWN, size=1230)
    evidence = {(1, 2): PairEvidence(1, 2, PairDirection.UNKNOWN, PairDirection.UNKNOWN)}
    result = recommend_candidate_set((left, right), evidence)
    assert result.items[0].recommendation == "NONE"
    better = replace(left, resolution_area=2_000_000, mtime_ns=10_000_000_000)
    assert recommend_candidate_set((better, right), evidence).items[0].recommendation == "NONE"


def test_numeric_checklist_uses_rounded_confidence_and_empty_selection():
    rows = ({"confidence": 0.9123456789}, {"confidence": 0.5432109876})
    specs = (ColumnSpec("confidence", "신뢰도", 80, ColumnKind.NUMBER),)
    assert apply_table_state(rows, specs, TableState(filters={"confidence": TableFilter(allowed=frozenset({"0.912"}))})) == rows[:1]
    assert apply_table_state(rows, specs, TableState(filters={"confidence": TableFilter(exclude_all=True)})) == ()


def test_real_tk_filter_value_selection_reopen_sort_and_bounded_size(tmp_path):
    import tkinter as tk
    from tkinter import ttk
    from archive_analyzer.review_table import TreeTableController, UiSettingsStore
    root = tk.Tk()
    root.attributes("-alpha", 0)
    root.geometry("500x300")
    tree = ttk.Treeview(root, columns=("confidence", "name"), show="headings")
    tree.pack(fill="both", expand=True)
    table = TreeTableController(tree, (
        ColumnSpec("confidence", "신뢰도", 90, ColumnKind.NUMBER),
        ColumnSpec("name", "이름", 200, ColumnKind.TEXT)), "test", UiSettingsStore(tmp_path / "ui.json"))
    table.set_rows(({"confidence": .9123456, "name": "긴 이름 " * 40}, {"confidence": .543219, "name": "짧은 이름"}))
    errors = []
    def descendants(widget):
        result = []
        for child in widget.winfo_children():
            result.append(child)
            result.extend(descendants(child))
        return result
    def interact(action):
        def run():
            dialog = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel))
            try:
                root.update_idletasks()
                assert 360 <= dialog.winfo_width() <= 700
                assert 420 <= dialog.winfo_height() <= 800
                action(descendants(dialog))
            except BaseException as error:
                errors.append(error)
                dialog.destroy()
        root.after(80, run)
    def button(widgets, text):
        return next(w for w in widgets if isinstance(w, ttk.Button) and w.cget("text") == text)
    try:
        root.update()
        def pick(widgets):
            listing = next(w for w in widgets if isinstance(w, ttk.Treeview))
            assert len(listing.get_children()) == 2
            assert {listing.item(i, "text")[2:] for i in listing.get_children()} == {"0.543", "0.912"}
            button(widgets, "전체해제").invoke()
            row = listing.get_children()[1]
            x, y, width, height = listing.bbox(row)
            listing.event_generate("<Button-1>", x=20, y=y+height//2)
            button(widgets, "적용").invoke()
        interact(pick)
        table.open_filters(root, "confidence")
        assert not errors, errors
        assert len(table.visible_rows) == 1
        def reopen(widgets):
            listing = next(w for w in widgets if isinstance(w, ttk.Treeview))
            assert len(listing.get_children()) == 2
            assert sum(listing.item(i, "image")[0] == str(listing._check_images[1]) for i in listing.get_children()) == 1
            button(widgets, "이 열 필터 해제").invoke()
        interact(reopen)
        table.open_filters(root, "confidence")
        assert not errors, errors
        assert len(table.visible_rows) == 2
        interact(lambda widgets: button(widgets, "내림차순 정렬").invoke())
        table.open_filters(root, "confidence")
        assert table.visible_rows[0]["confidence"] > table.visible_rows[1]["confidence"]
        interact(lambda widgets: button(widgets, "취소").invoke())
        table.open_filters(root, "name")
        assert not errors, errors
    finally:
        root.destroy()


def test_precision_updates_recommendation_then_batch_review_and_reload(tmp_path):
    from archive_analyzer.precision_service import analyze_precision
    from tests.unit.test_precision_service import FakeOcr, FakeReader, _encoded_page
    repository, root_id, ids = real_fixture(tmp_path, (4, 4))
    ocr = FakeOcr(("안녕하세요\n오늘도 반갑습니다\n한국어 번역입니다" * 4,) * 4 + ("これは日本語の文章ですこんにちは" * 4,) * 4)
    reader = FakeReader(_encoded_page())
    def analyze(repo, root, cancel, **kwargs):
        return analyze_precision(repo, root, cancel, reader=reader, ocr=ocr, **kwargs)
    worker = review_ui.ReviewWorker(tmp_path / "index.db", tmp_path, precision_analyzer=analyze)
    Work = review_ui._ReviewWork
    try:
        before = worker._perform(repository, root_id, Work("load")).groups[0]
        assert before.recommended_archive_id is None
        after = worker._perform(repository, root_id, Work("precision", group_keys=(before.group_key,))).groups[0]
        assert after.recommended_archive_id == ids[0]
        assert after.recommendation_status == "RECOMMENDED"
        applied = worker._perform(repository, root_id, Work("apply_recommendations", group_keys=(after.group_key,)))
        assert applied.completed == 2 and applied.failed == 0
        assert not applied.groups[0].needs_review
        assert review_ui.group_work_tab(applied.groups[0]) == 1
        calls = (reader.calls, ocr.calls)
        warm = worker._perform(repository, root_id, Work("precision", group_keys=(after.group_key,)))
        assert (reader.calls, ocr.calls) == calls
        assert warm.groups[0].recommended_archive_id == ids[0]
        assert not warm.groups[0].needs_review
        reloaded = worker._perform(repository, root_id, Work("load"))
        assert not reloaded.groups[0].needs_review
    finally:
        repository.close()
