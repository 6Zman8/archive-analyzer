import hashlib
import json
import time
import tkinter as tk
from pathlib import Path

import pytest

from archive_analyzer.update_ui import UpdateController
from archive_analyzer.updates import Release


@pytest.fixture(scope="module")
def hidden_root():
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def ui(tmp_path, hidden_root):
    root = hidden_root
    target = tmp_path / "앱.exe"
    target.write_bytes(b"MZold")
    yield root, target, tmp_path / "updates"
    for child in root.winfo_children():
        child.destroy()


def pump_until(root, predicate):
    deadline = time.monotonic() + 5
    while not predicate() and time.monotonic() < deadline:
        root.update()
        time.sleep(.01)
    assert predicate()


def test_worker_updates_tk_and_waits_for_close(ui, monkeypatch):
    root, target, directory = ui
    stage = directory / "transaction"
    stage.mkdir(parents=True)
    source = stage / "ArchiveAnalyzer.exe"
    source.write_bytes(b"MZnew")
    release = Release("2.0.0", "", 5, hashlib.sha256(b"MZnew").hexdigest())
    calls = []
    monkeypatch.setattr("archive_analyzer.update_ui.launch_installer", calls.append)
    controller = UpdateController(root, target=target, directory=directory, enabled=True,
        checker=lambda: release, downloader=lambda *a, **kw: source)
    controller.attach_menu(root, lambda: None)
    controller.attach_status(root)
    controller.check()
    pump_until(root, lambda: controller.pending is not None)
    assert "준비 완료" in controller.status.get()
    assert not calls
    assert target.read_bytes() == b"MZold"
    controller.close()
    controller.close()
    assert len(calls) == 1


def test_disabling_auto_prevents_ready_update_application(ui, monkeypatch):
    root, target, directory = ui
    calls = []
    monkeypatch.setattr("archive_analyzer.update_ui.launch_installer", calls.append)
    controller = UpdateController(root, target=target, directory=directory, enabled=True, checker=lambda: None)
    controller.auto.set(False)
    controller.toggle_auto()
    assert json.loads((directory / "settings.json").read_text())["automatic"] is False
    controller.close()
    assert not calls


def test_source_execution_never_calls_network(ui):
    root, target, directory = ui
    calls = []
    controller = UpdateController(root, target=target, directory=directory, enabled=False,
                                  checker=lambda: calls.append(True))
    controller.check()
    root.update()
    assert not calls
    controller.close()


def test_network_error_is_nonblocking(ui):
    root, target, directory = ui
    def fail():
        raise OSError("offline")
    controller = UpdateController(root, target=target, directory=directory, enabled=True, checker=fail)
    controller.check()
    pump_until(root, lambda: "offline" in controller.status.get())
    assert controller.pending is None
    assert target.read_bytes() == b"MZold"
    controller.close()


def test_update_menu_preserves_workspace_commands_and_is_not_duplicated(ui):
    root, target, directory = ui
    existing = tk.Menu(root, tearoff=False)
    files = tk.Menu(existing, tearoff=False)
    calls = []
    files.add_command(label="검사 화면", command=lambda: calls.append("scanner"))
    existing.add_cascade(label="파일", menu=files)
    root.configure(menu=existing)
    controller = UpdateController(root, target=target, directory=directory, enabled=True, checker=lambda: None)
    controller.attach_menu(root, lambda: None)
    controller.attach_menu(root, lambda: None)
    assert root.nametowidget(root.cget("menu")) is existing
    assert [existing.entrycget(i, "label") for i in range(existing.index("end") + 1)] == ["파일", "업데이트"]
    files.invoke(0)
    assert calls == ["scanner"]
    controller.close()


def test_turning_auto_off_cancels_pending_install_even_when_settings_cannot_save(ui, monkeypatch):
    root, target, directory = ui
    controller = UpdateController(root, target=target, directory=directory, enabled=True, checker=lambda: None)
    controller.pending = object()
    calls = []
    monkeypatch.setattr("archive_analyzer.update_ui.launch_installer", calls.append)
    def disk_full(*args):
        raise OSError("disk full")
    monkeypatch.setattr("archive_analyzer.update_ui.write_json", disk_full)
    controller.auto.set(False)
    controller.toggle_auto()
    assert controller.cancel.is_set()
    assert controller.pending is None
    assert "저장" in controller.status.get()
    controller.close()
    assert not calls


def test_close_finishes_when_helper_and_error_record_both_fail(ui, monkeypatch):
    root, target, directory = ui
    controller = UpdateController(root, target=target, directory=directory, enabled=True, checker=lambda: None)
    controller.pending = object()
    def disk_full(*args):
        raise OSError("disk full")
    monkeypatch.setattr("archive_analyzer.update_ui.launch_installer", disk_full)
    monkeypatch.setattr("archive_analyzer.update_ui.write_json", disk_full)
    controller.close()
    assert controller.closed
    assert controller.cancel.is_set()
    controller.close()
