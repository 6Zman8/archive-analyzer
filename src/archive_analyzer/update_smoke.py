"""Opt-in packaged acceptance session in an explicitly isolated directory."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def run(directory: Path) -> int:
    directory = directory.resolve(strict=True)
    if (directory / ".archive-update-test-owned").read_text(encoding="utf-8").strip() != "disposable":
        return 2
    # Only a disposable executable copied directly into the fixture can run here.
    if Path(sys.executable).resolve().parent != directory:
        return 2
    os.environ["LOCALAPPDATA"] = str(directory / "isolated-data")
    import tkinter as tk
    from archive_analyzer.update_ui import UpdateController
    from archive_analyzer.updates import write_json
    from archive_analyzer.version import __version__
    root = tk.Tk()
    root.withdraw()
    controller = UpdateController(root)
    controller.attach_menu(root, lambda: None)
    controller.attach_status(root)
    errors = []
    root.report_callback_exception = lambda *args: errors.append(str(args[1]))
    deadline = time.monotonic() + 240
    try:
        # Let the normal startup timer trigger the real GitHub request.
        while controller.pending is None and time.monotonic() < deadline and not errors:
            root.update()
            time.sleep(.03)
        result = {"from_version": __version__, "ready": controller.pending is not None,
                  "status": controller.status.get(), "errors": errors}
        if controller.pending is not None:
            result.update(to_version=controller.pending.version,
                          transaction=str(controller.pending.source.parent))
        write_json(directory / "session.json", result)
        return 0 if result["ready"] and not errors else 1
    finally:
        controller.close()
        root.destroy()
