"""Tk adapter: worker threads publish data; only Tk's thread changes widgets."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from queue import Empty, Queue

from archive_analyzer.update_install import InstallJob, launch_installer
from archive_analyzer.updates import (
    CHECK_INTERVAL, UpdateError, check_release, download_release, file_sha256,
    update_directory, write_json,
)
from archive_analyzer.version import __version__


class UpdateController:
    def __init__(self, root, *, target: Path | None = None, directory: Path | None = None,
                 enabled: bool | None = None, checker=check_release, downloader=download_release):
        import tkinter as tk
        self.root = root
        self.target = (target or Path(sys.executable)).resolve()
        self.supported = bool(getattr(sys, "frozen", False)) if enabled is None else enabled
        self.directory = directory or update_directory(self.target)
        self.checker, self.downloader = checker, downloader
        self.events = Queue()
        self.cancel = threading.Event()
        self.worker = None
        self.pending: InstallJob | None = None
        self.closed = False
        self.after_id = None
        self.auto_id = None
        self.auto = tk.BooleanVar(master=root, value=True)
        self.status = tk.StringVar(master=root, value=f"v{__version__}")
        self._load_preferences()
        self.after_id = root.after(200, self._poll)
        if self.supported:
            self.auto_id = root.after(3000, self._automatic_check)
        else:
            self.status.set(f"v{__version__} · 소스 실행에서는 자동 업데이트가 꺼집니다.")

    def _load_preferences(self):
        try:
            settings = json.loads((self.directory / "settings.json").read_text(encoding="utf-8"))
            self.auto.set(settings.get("automatic", True) is not False)
        except (OSError, ValueError, AttributeError):
            pass
        try:
            report = json.loads((self.directory / "last-result.json").read_text(encoding="utf-8"))
            if report.get("status") != "installed":
                self.status.set("이전 업데이트 미적용 · " + str(report.get("message", "다시 확인해 주세요.")))
            else:
                self.status.set(f"v{__version__} · 업데이트 완료")
        except (OSError, ValueError, AttributeError):
            pass

    def attach_menu(self, window, close):
        import tkinter as tk
        existing = window.cget("menu")
        menu = window.nametowidget(existing) if existing else tk.Menu(window)
        end = menu.index("end")
        for index in range(end + 1 if end is not None else 0):
            if menu.type(index) == "cascade" and menu.entrycget(index, "label") == "업데이트":
                return
        updates = tk.Menu(menu, tearoff=False)
        updates.add_command(label=f"현재 버전: {__version__}", state="disabled")
        updates.add_command(label=self.status.get(), state="disabled")
        updates.configure(postcommand=lambda: updates.entryconfigure(1, label=self.status.get()))
        updates.add_separator()
        updates.add_command(label="업데이트 확인", command=self.check,
                            state="normal" if self.supported else "disabled")
        updates.add_checkbutton(label="자동 확인·다운로드·종료 시 적용", variable=self.auto,
                                command=self.toggle_auto, state="normal" if self.supported else "disabled")
        updates.add_separator()
        updates.add_command(label="프로그램 종료 (준비된 업데이트 적용)", command=close)
        menu.add_cascade(label="업데이트", menu=updates)
        window.configure(menu=menu)

    def attach_status(self, parent):
        from tkinter import ttk
        packed = parent.pack_slaves()
        frame = ttk.Frame(parent, padding=(12, 4))
        frame.pack(side="bottom", fill="x", before=packed[0] if packed else None)
        ttk.Label(frame, textvariable=self.status, wraplength=620).pack(side="left", fill="x", expand=True)
        return frame

    def toggle_auto(self):
        try:
            write_json(self.directory / "settings.json", {"automatic": bool(self.auto.get())})
        except OSError:
            self.status.set("업데이트 설정을 저장하지 못했습니다.")
            return
        if self.auto.get():
            self.check()
        else:
            self.cancel.set()
            self.pending = None
            self.status.set(f"v{__version__} · 자동 업데이트 꺼짐")

    def _automatic_check(self):
        self.auto_id = None
        if self.closed:
            return
        if self.auto.get():
            self.check()
        self.auto_id = self.root.after(CHECK_INTERVAL * 1000, self._automatic_check)

    def check(self):
        if self.closed or not self.supported or (self.worker is not None and self.worker.is_alive()):
            return
        if self.pending is not None:
            self.status.set(f"v{self.pending.version} 준비 완료 · 프로그램을 종료하면 자동 적용됩니다.")
            return
        self.cancel = threading.Event()
        self.status.set(f"v{__version__} · 새 버전 확인 중…")
        self.worker = threading.Thread(target=self._work, name="archive-analyzer-update", daemon=True)
        self.worker.start()

    def _work(self):
        try:
            release = self.checker()
            if self.cancel.is_set():
                return
            if release is None:
                self.events.put(("status", f"v{__version__} · 최신 버전입니다."))
                return
            source = self.downloader(release, self.directory, cancel=self.cancel,
                progress=lambda done, total: self.events.put(("status",
                    f"v{release.version} 받는 중 · {done / total:.0%} ({done // 1048576}/{total // 1048576} MB)")))
            if self.cancel.is_set():
                return
            parents = (os.getpid(), os.getppid()) if getattr(sys, "frozen", False) else ()
            job = InstallJob(self.target, source, release.version, release.sha256,
                             file_sha256(self.target), parents)
            job.write()
            self.events.put(("ready", job))
        except Exception as error:
            self.events.put(("status", f"업데이트 미적용 · {error}"))

    def _drain(self):
        while True:
            try:
                kind, value = self.events.get_nowait()
            except Empty:
                return
            if self.cancel.is_set():
                continue
            if kind == "ready":
                self.pending = value
                self.status.set(f"v{value.version} 준비 완료 · 프로그램을 종료하면 자동 적용됩니다.")
            else:
                self.status.set(value)

    def _poll(self):
        self.after_id = None
        if not self.closed:
            self._drain()
            self.after_id = self.root.after(200, self._poll)

    def close(self):
        """Called only after all analysis/review shutdown guards have succeeded."""
        if self.closed:
            return
        self._drain()
        self.closed = True
        self.cancel.set()
        for handle in (self.after_id, self.auto_id):
            if handle is not None:
                self.root.after_cancel(handle)
        if self.pending is not None:
            try:
                launch_installer(self.pending)
            except Exception as error:
                write_json(self.directory / "last-result.json",
                           {"status": "failed", "message": str(error)})
