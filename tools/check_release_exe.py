"""Verify the packaged health contract and write a distributable checksum."""
import argparse
from pathlib import Path

from archive_analyzer.update_install import health_probe
from archive_analyzer.updates import file_sha256
from archive_analyzer.version import __version__


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    args = parser.parse_args()
    executable = args.executable.resolve(strict=True)
    if not health_probe(executable, __version__):
        raise SystemExit("The executable failed its version/resource/Tk health check.")
    digest = file_sha256(executable)
    executable.with_name("SHA256SUMS.txt").write_text(f"{digest}  {executable.name}\n", encoding="ascii")
    print(f"v{__version__} verified: {digest}")


if __name__ == "__main__":
    main()
