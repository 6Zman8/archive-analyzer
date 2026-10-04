"""Invisible packaged UI check against an explicitly supplied disposable DB."""
import json
import time
from dataclasses import replace
from pathlib import Path


def verify_scan_progress(root, source: Path, data_root: Path) -> dict:
    """Exercise real scanning, worker delivery and native Tk rendering invisibly."""
    from threading import Event, Thread
    from tkinter import StringVar, ttk
    from archive_analyzer.analysis_progress import ProgressMailbox
    from archive_analyzer.desktop import display_analysis_progress, run_analysis
    from archive_analyzer.duplicate_domain import AnalysisStage

    mailbox = ProgressMailbox()
    release = Event()
    errors = []
    observed = {"probe_pages": False, "candidate_fraction": None}
    bar = ttk.Progressbar(root, mode="indeterminate")
    label = StringVar(master=root)

    def publish(event):
        if event.stage is AnalysisStage.PROBE and event.detail.startswith("이 파일의 대표 이미지 1/"):
            observed["probe_pages"] = True
        mailbox.publish(event)
        if event.phase == "비교 자료 읽기" and event.completed == 1 and event.total > 1:
            if not release.wait(15):
                raise RuntimeError("The UI did not receive live candidate progress.")

    def work():
        try:
            run_analysis(source, data_root=data_root, progress_callback=publish)
        except BaseException as error:
            errors.append(error)

    worker = Thread(target=work, name="scan-progress-smoke")
    worker.start()
    try:
        deadline = time.monotonic() + 45
        while worker.is_alive() and time.monotonic() < deadline:
            root.update()
            current = mailbox.latest()
            if current is not None:
                display_analysis_progress(bar, label, current, elapsed=902)
                if current.phase == "비교 자료 읽기" and current.completed == 1 and current.total > 1:
                    assert str(bar["mode"]) == "determinate"
                    assert abs(float(bar["value"]) - 100 / current.total) < 0.001
                    assert f"1/{current.total:,}" in label.get() and "15:02" in label.get()
                    observed["candidate_fraction"] = float(bar["value"])
                    release.set()
            time.sleep(.01)
    finally:
        release.set()
        worker.join(20)
        bar.destroy()
    assert not worker.is_alive(), "scan progress smoke timed out"
    assert not errors, repr(errors)
    assert observed["probe_pages"] and observed["candidate_fraction"] is not None
    return observed


def run(database: Path, source: Path) -> int:
    import tkinter as tk
    from tkinter import font, ttk
    from archive_analyzer import review_ui
    from archive_analyzer.review_table import UiSettingsStore
    from archive_analyzer.ui_theme import checkbox_images
    # Exercise PyInstaller's COM hooks as well as the native Tk runtime.
    import pythoncom
    from win32com.shell import shell
    from win32com.server.policy import DesignatedWrapPolicy
    from win32com.server.exception import COMException

    original_store = review_ui.UiSettingsStore
    review_ui.UiSettingsStore = lambda: UiSettingsStore(database.with_suffix(".ui-test-settings.json"))
    root = tk.Tk()
    root.withdraw()
    scan_progress = verify_scan_progress(root, source, database.parent / "progress-smoke")
    window = review_ui.ReviewWindow(root, database, source)
    window._window.attributes("-alpha", 0)
    window._window.attributes("-toolwindow", True)
    # This explicitly hidden acceptance window must retain the requested test
    # dimensions even on the smaller virtual desktop of a build server.
    window._window.maxsize(4096, 4096)
    report = {}
    try:
        deadline = time.monotonic() + 30
        while window._operation_busy and time.monotonic() < deadline:
            root.update()
            time.sleep(.02)
        assert not window._operation_busy, "review load timed out"
        assert window._all_groups, window._status.get()
        group = window._all_groups[0]
        # Verify the actual Tk button routes stored page correspondences to
        # previews without writing review decisions or touching source archives.
        evidence_edge = next(item for item in group.edges
                             if item.left_page_count >= 2 and item.right_page_count >= 2)
        evidence_edge = replace(evidence_edge, matched_pairs=((0, 0),), matched_pages=1)
        evidence_group = replace(group, edges=(evidence_edge,))
        window._groups = (evidence_group,)
        window._group_index = 0
        window._render_group(evidence_group)
        edge_key = window._edge_tree.get_children()[0]
        window._edge_tree.selection_set(edge_key)
        window._select_edge()
        root.update()
        assert '일치 1쪽' in window._edge_summary.get()
        window._unmatched_button.invoke()
        assert window._preview_page_indices == {
            evidence_edge.left_archive_id: 1, evidence_edge.right_archive_id: 1}
        assert '차이 후보' in window._status.get()
        evidence_navigation = dict(window._preview_page_indices)
        assert {'mtime', 'directory'} <= set(window._member_tree['displaycolumns'])
        for table in (window._member_table, window._group_table, window._edge_table):
            table.choose_columns(window._window)
            dialog = next(child for child in window._window.winfo_children()
                          if isinstance(child, tk.Toplevel) and child.title() == '표시할 열 선택')
            dialog.attributes('-alpha', 0)
            body = dialog.winfo_children()[0]
            boxes = [child for child in body.winfo_children() if isinstance(child, ttk.Checkbutton)]
            assert len(boxes) == len(table.specs)
            # Show all columns and check that saved preferences restore them.
            for box in boxes:
                if not box.instate(['selected']):
                    box.invoke()
            next(child for child in body.winfo_children() if isinstance(child, ttk.Button) and child.cget('text') == '적용').invoke()
            table.tree.configure(displaycolumns=(table.specs[0].key,))
            table.restore_columns((table.specs[0].key,))
            assert tuple(table.tree['displaycolumns']) == tuple(spec.key for spec in table.specs)
        window._render_groups(tuple(replace(group, group_key=f"smoke{i}", set_key=f"smoke{i}",
            reviewed_at=f"2026-09-09T00:{i // 60:02}:{i % 60:02}+00:00",
            work_label=f"{i:03} 한국어 日本語 中文 English") for i in range(600)))
        window._sort_text.set("최근 검토순")
        window._apply_group_filter(reset_table_sort=True)
        assert window._group_tree.get_children()[0] == "smoke599"
        window._finish_operation()
        window._group_tree.selection_remove(*window._group_tree.selection())
        root.update()
        assert len(window._batch_group_keys()) == 600
        assert len(window._default_all_group_buttons) == 4
        assert all(str(button['state']) == 'normal' for button in window._default_all_group_buttons)
        assert window._messagebox.parent is window._window
        from archive_analyzer.dialogs import center_dialog
        import win32api, win32con
        original_geometry = window._window.geometry()
        for monitor, _, _ in win32api.EnumDisplayMonitors():
            left, top, right, bottom = win32api.GetMonitorInfo(monitor)['Work']
            window._window.geometry(f'1000x700+{left+10}+{top+10}')
            root.update()
            dialog = tk.Toplevel(window._window)
            dialog.attributes('-alpha', 0)
            dialog.geometry('360x200')
            center_dialog(dialog, window._window)
            root.update()
            assert int(win32api.MonitorFromWindow(dialog.winfo_id(), win32con.MONITOR_DEFAULTTONEAREST)) == int(win32api.MonitorFromWindow(window._window.winfo_id(), win32con.MONITOR_DEFAULTTONEAREST))
            dialog.destroy()
        window._window.geometry(original_geometry)
        window._window.geometry("1280x860")
        root.update()
        checks = checkbox_images(window._window)
        report = {
            "evidence_navigation": evidence_navigation,
            "scan_progress": scan_progress,
            "font": font.nametofont("TkDefaultFont", root=root).actual("family"),
            "groups": len(window._group_tree.get_children()),
            "file_rows": int(window._member_tree.cget("height")),
            "preview_height": window._preview_slots[0][0].winfo_height(),
            "checkbox_size": [checks[0].width(), checks[0].height()],
            "recycle_com": bool(shell.IID_IFileOperation and pythoncom.CLSCTX_ALL),
            "scrollbar_disabled": ttk.Style(root).map("Horizontal.TScrollbar", "background")[0][-1],
        }
        assert report["groups"] == 600 and report["preview_height"] >= 140
        assert report["font"].casefold() in {"malgun gothic", "맑은 고딕"}
        window._toggle_preview_layout()
        root.update()
        assert window._preview_cards[1].grid_info()["row"] == 2
        report["success"] = True
    finally:
        window.request_close()
        deadline = time.monotonic() + 30
        while not window.is_closed() and time.monotonic() < deadline:
            root.update()
            time.sleep(.02)
        root.destroy()
        review_ui.UiSettingsStore = original_store
        database.with_suffix(".ui-smoke.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0
