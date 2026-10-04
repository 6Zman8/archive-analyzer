"""Prepare a monotonically increasing stable version for a GitHub release."""
import argparse
import runpy
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    import sys
    sys.path.insert(0, str(root / "src"))
    from archive_analyzer.updates import version_tuple
    source = root / "src/archive_analyzer/version.py"
    current = runpy.run_path(str(source))["__version__"]
    if args.check:
        if args.version != current:
            raise SystemExit(f"Tag v{args.version} does not match source v{current}")
    else:
        if version_tuple(args.version) <= version_tuple(current):
            raise SystemExit(f"New version must be greater than {current}")
        source.write_text('"""Single application version used by the GUI and release tooling."""\n\n'
                          f'__version__ = "{args.version}"\n', encoding="utf-8")
    print(args.version)


if __name__ == "__main__":
    main()
