"""Keep native Tk suites in separate processes to avoid shared Tcl/DPI state."""
import subprocess
import sys
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    files = sorted((root / "tests").rglob("test_*.py"))
    gui, ordinary = [], []
    for path in files:
        text = path.read_text(encoding="utf-8")
        relative = str(path.relative_to(root))
        (gui if any(token in text for token in ("tkinter", "tk.Tk", "Tk()")) else ordinary).append(relative)
    for group in [ordinary, *[[path] for path in gui]]:
        result = subprocess.run([sys.executable, "-m", "pytest", "-q", *group], cwd=root)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
