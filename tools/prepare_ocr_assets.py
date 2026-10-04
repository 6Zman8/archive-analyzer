"""Prepare and verify the offline OCR files used by the packaged app.

The files are downloaded only while building the application.  The resulting
manifest and files are copied into the executable; the running application
never uses this script and never contacts the model host.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Mapping
from urllib.request import Request, urlopen


RAPIDOCR_VERSION = "3.9.2"
MAX_ASSET_BYTES = 512 * 1024 * 1024


REQUIRED_ASSETS = (
    {
        "path": "PP-OCRv6_det_tiny.onnx",
        "url": (
            "https://www.modelscope.cn/models/RapidAI/RapidOCR/resolve/"
            "v3.9.2/onnx/PP-OCRv6/det/PP-OCRv6_det_tiny.onnx"
        ),
        "sha256": "f42c0fbd294d95eac1a550e131b277dac97462c8025fa4b6c3cec1b7894bd3d5",
    },
    {
        "path": "ch_PP-OCRv5_rec_mobile.onnx",
        "url": (
            "https://www.modelscope.cn/models/RapidAI/RapidOCR/resolve/"
            "v3.9.2/onnx/PP-OCRv5/rec/ch_PP-OCRv5_rec_mobile.onnx"
        ),
        "sha256": "5825fc7ebf84ae7a412be049820b4d86d77620f204a041697b0494669b1742c5",
    },
    {
        "path": "korean_PP-OCRv5_rec_mobile.onnx",
        "url": (
            "https://www.modelscope.cn/models/RapidAI/RapidOCR/resolve/"
            "v3.9.2/onnx/PP-OCRv5/rec/korean_PP-OCRv5_rec_mobile.onnx"
        ),
        "sha256": "cd6e2ea50f6943ca7271eb8c56a877a5a90720b7047fe9c41a2e541a25773c9b",
    },
    {
        "path": "ppocrv5_dict.txt",
        "url": (
            "https://www.modelscope.cn/models/RapidAI/RapidOCR/resolve/"
            "v3.9.2/paddle/PP-OCRv5/rec/ch_PP-OCRv5_rec_mobile/ppocrv5_dict.txt"
        ),
        "sha256": "d1979e9f794c464c0d2e0b70a7fe14dd978e9dc644c0e71f14158cdf8342af1b",
    },
    {
        "path": "ppocrv5_korean_dict.txt",
        "url": (
            "https://www.modelscope.cn/models/RapidAI/RapidOCR/resolve/"
            "v3.9.2/paddle/PP-OCRv5/rec/korean_PP-OCRv5_rec_mobile/"
            "ppocrv5_korean_dict.txt"
        ),
        "sha256": "a88071c68c01707489baa79ebe0405b7beb5cca229f4fc94cc3ef992328802d7",
    },
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _downloads_root() -> Path:
    return (Path.home() / "Downloads").resolve(strict=False)


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
    except ValueError:
        return False
    return True


def _find_installed_asset(filename: str) -> Path | None:
    spec = importlib.util.find_spec("rapidocr")
    locations = () if spec is None or spec.submodule_search_locations is None else spec.submodule_search_locations
    for location in locations:
        candidate = Path(location).resolve(strict=False) / filename
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
        for candidate in Path(location).rglob(filename):
            if candidate.is_file() and not candidate.is_symlink():
                return candidate
    return None


def _copy_atomic(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"OCR asset appeared during preparation: {destination}")
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = handle.name
        shutil.copyfile(source, temporary)
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _download_atomic(url: str, destination: Path, expected_sha256: str | None) -> None:
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"OCR asset appeared during preparation: {destination}")
    temporary: str | None = None
    digest = hashlib.sha256()
    total = 0
    try:
        request = Request(url, headers={"User-Agent": "ArchiveAnalyzer/1.0"})
        with urlopen(request, timeout=120) as response:
            with tempfile.NamedTemporaryFile(
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary = handle.name
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_ASSET_BYTES:
                        raise RuntimeError(f"OCR asset is unexpectedly large: {url}")
                    digest.update(chunk)
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
        actual = digest.hexdigest()
        if expected_sha256 is not None and actual != expected_sha256:
            raise RuntimeError(
                f"OCR asset hash mismatch: {destination.name} "
                f"(expected {expected_sha256}, got {actual})"
            )
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def verify_assets(root: Path, manifest: Mapping[str, object]) -> None:
    files = manifest.get("files")
    if not isinstance(files, list) or len(files) != len(REQUIRED_ASSETS):
        raise SystemExit("OCR asset manifest has an unexpected file list.")
    expected_names = {str(item["path"]) for item in REQUIRED_ASSETS}
    seen: set[str] = set()
    for item in files:
        if not isinstance(item, Mapping):
            raise SystemExit("OCR asset manifest contains an invalid item.")
        relative = item.get("path")
        recorded_hash = item.get("sha256")
        recorded_size = item.get("size")
        if not isinstance(relative, str) or relative not in expected_names or relative in seen:
            raise SystemExit(f"OCR asset manifest contains an unexpected path: {relative}")
        seen.add(relative)
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"OCR asset is missing: {path}")
        actual_hash = sha256(path)
        if actual_hash != recorded_hash:
            raise SystemExit(f"OCR asset hash mismatch: {path}")
        if not isinstance(recorded_size, int) or path.stat().st_size != recorded_size:
            raise SystemExit(f"OCR asset size mismatch: {path}")
    if seen != expected_names:
        raise SystemExit("OCR asset manifest does not contain every required file.")


def prepare_assets(output: Path) -> Path:
    output = output.resolve(strict=False)
    if _is_within(output, _downloads_root()):
        raise SystemExit("OCR assets must stay in the project build directory, not Downloads.")
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / "manifest.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise SystemExit(f"OCR asset manifest cannot be read: {manifest_path}") from error
        if not isinstance(manifest, Mapping) or manifest.get("rapidocr_version") != RAPIDOCR_VERSION:
            raise SystemExit(f"OCR asset manifest version mismatch: {manifest_path}")
        verify_assets(output, manifest)
        return manifest_path

    for item in REQUIRED_ASSETS:
        destination = output / str(item["path"])
        expected = item["sha256"]
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_file():
                raise SystemExit(f"OCR asset destination is not a regular file: {destination}")
            if expected is not None and sha256(destination) != expected:
                raise SystemExit(f"OCR asset hash mismatch: {destination}")
            if destination.stat().st_size == 0:
                raise SystemExit(f"OCR asset is empty: {destination}")
            continue
        installed = _find_installed_asset(destination.name)
        if installed is not None and (expected is None or sha256(installed) == expected):
            _copy_atomic(installed, destination)
        else:
            try:
                _download_atomic(str(item["url"]), destination, expected)
            except Exception as error:
                raise SystemExit(
                    f"OCR asset download failed for {destination.name}: {error}"
                ) from error
        if not destination.is_file() or destination.stat().st_size == 0:
            raise SystemExit(f"OCR asset preparation produced no file: {destination}")

    files = [
        {
            "path": str(item["path"]),
            "size": (output / str(item["path"])).stat().st_size,
            "sha256": sha256(output / str(item["path"])),
        }
        for item in REQUIRED_ASSETS
    ]
    manifest = {
        "manifest_version": 1,
        "rapidocr_version": RAPIDOCR_VERSION,
        "files": files,
    }
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output,
            prefix=".manifest.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = handle.name
            json.dump(manifest, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, manifest_path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass
    verify_assets(output, manifest)
    return manifest_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "build" / "ocr-assets",
    )
    arguments = parser.parse_args(argv)
    manifest = prepare_assets(arguments.output)
    print(f"OCR_ASSET_MANIFEST={manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
