import sys
from pathlib import Path


def main():
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
    raise SystemExit(main())
