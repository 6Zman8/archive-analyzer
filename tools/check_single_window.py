"""Background verification of the scanner -> review -> scanner transition."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import tkinter as tk
from tkinter import ttk

from archive_analyzer import desktop, review_ui


class Idle:
    def __init__(self, *args): pass
    def start(self): pass
    def submit_load(self): pass
    def submit(self, requests): return 1
    def poll_result(self): return None
    def request_close(self): pass
    def is_alive(self): return False
    def close(self, **kwargs): pass


root = tk.Tk()
root.attributes("-alpha", 0)
errors = []
root.report_callback_exception = lambda kind, value, tb: errors.append(value)
stage = 0


def descendants(widget):
    for child in widget.winfo_children():
        yield child
        yield from descendants(child)


def check():
    global stage
    try:
        if stage == 0:
            button = next(w for w in descendants(root) if isinstance(w, ttk.Button) and w.cget("text") == "저장된 결과 열기")
            button.invoke()
            stage = 1
        elif stage == 1:
            assert root.state() == "withdrawn"
            review = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel))
            review.attributes("-alpha", 0)
            command = review.protocol("WM_DELETE_WINDOW")
            review.tk.call(command)
            stage = 2
        elif root.state() != "withdrawn":
            assert not any(isinstance(w, tk.Toplevel) for w in root.winfo_children())
            print("single-window transition verified")
            root.quit()
            return
        root.after(120, check)
    except BaseException as error:
        errors.append(error)
        root.quit()


with TemporaryDirectory() as folder:
    saved = desktop.SavedResult(Path(folder) / "fixture.db", Path(folder), "", 1)
    with patch.object(tk, "Tk", lambda: root), patch.object(desktop, "latest_saved_result", lambda: saved), \
         patch.object(review_ui, "ReviewWorker", Idle), patch.object(review_ui, "ThumbnailWorker", Idle):
        root.after(100, check)
        root.after(8000, lambda: (errors.append(TimeoutError("window transition timed out")), root.quit()))
        desktop.launch_gui()
root.destroy()
assert not errors, errors
