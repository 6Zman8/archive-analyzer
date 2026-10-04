import sys
from pathlib import Path


def configure_output():
    # Windowed Python has no console streams. Some dependencies replace them
    # with locale-encoded devnull streams, which fail on Korean paths on an
    # English Windows host. Establish Unicode-safe streams before imports.
    import os
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name)
        if stream is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))
        elif hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")


def main():
    configure_output()
    # Dispatch before importing the desktop, so an updater never opens user data.
    if len(sys.argv) == 3 and sys.argv[1] == "--packaged-update-session":
        from archive_analyzer.update_smoke import run
        return run(Path(sys.argv[2]))
    if len(sys.argv) == 3 and sys.argv[1] == "--apply-update":
        from archive_analyzer.update_install import installer_main
        return installer_main(Path(sys.argv[2]))
    if len(sys.argv) == 3 and sys.argv[1] == "--update-health-check":
        from archive_analyzer.update_install import write_health_report
        return write_health_report(Path(sys.argv[2]))
    from archive_analyzer.desktop import main as desktop_main
    return desktop_main()


if __name__ == "__main__":
    try:
        result = main()
    except Exception:
        # A windowed executable would otherwise open a modal traceback dialog
        # on an unattended build runner. This opt-in path keeps the evidence.
        import os
        import traceback
        diagnostic = os.environ.get("ARCHIVE_ANALYZER_DIAGNOSTIC_LOG")
        if not diagnostic:
            raise
        Path(diagnostic).write_text(traceback.format_exc(), encoding="utf-8")
        result = 1
    raise SystemExit(result)
