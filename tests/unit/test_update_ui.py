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
