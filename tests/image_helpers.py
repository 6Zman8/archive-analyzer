import hashlib
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from PIL import Image


def encoded_gradient(format: str, size: tuple[int, int], quality: int = 90) -> bytes:
    image = Image.linear_gradient("L").resize(size, Image.Resampling.LANCZOS).convert("RGB")
    output = BytesIO()
    save_args = {"quality": quality} if format == "JPEG" else {}
    image.save(output, format=format, **save_args)
    return output.getvalue()


def write_image_zip(path: Path, pages: tuple[bytes, ...]) -> Path:
    with ZipFile(path, "w", compression=ZIP_DEFLATED) as archive:
        for index, payload in enumerate(pages, 1):
            archive.writestr(f"{index:03d}.png", payload)
    return path


def file_identity(path: Path) -> tuple[str, int, int]:
    value = path.stat()
    return hashlib.sha256(path.read_bytes()).hexdigest(), value.st_size, value.st_mtime_ns


def tree_fingerprint(root: Path) -> dict[str, tuple[str, int, int]]:
    return {
        str(path.relative_to(root)): file_identity(path)
        for path in sorted(item for item in root.rglob("*") if item.is_file())
    }
