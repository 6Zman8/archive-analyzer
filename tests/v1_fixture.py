from __future__ import annotations

import subprocess
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile

from PIL import Image

from tests.image_helpers import encoded_gradient


SEVEN_ZIP = Path(r"C:\Program Files\7-Zip\7z.exe")


def create_v1_archive_fixture(tmp_path: Path) -> Path:
    assert SEVEN_ZIP.is_file(), f"7-Zip is required for the V1 fixture: {SEVEN_ZIP}"
    root = tmp_path / "한국어 V1 원본 표본"
    root.mkdir()

    exact_pages = tuple(_noise_png(seed) for seed in (11, 12, 13))
    _write_zip(root / "정확 원본.zip", exact_pages, compression=ZIP_STORED)
    _write_zip(
        root / "정확 재압축.zip",
        exact_pages,
        compression=ZIP_DEFLATED,
        comment=b"same content, different archive bytes",
    )

    visual_small = tuple(encoded_gradient("PNG", (160, 240)) for _ in range(3))
    visual_large = tuple(
        encoded_gradient("JPEG", (320, 480), quality=82) for _ in range(3)
    )
    _write_zip(root / "시각 원본.zip", visual_small)
    _write_zip(root / "시각 리사이즈.zip", visual_large)

    _write_zip(
        root / "무관한 자료.zip",
        tuple(_noise_png(seed) for seed in (101, 102, 103)),
    )
    _write_7z(
        root / "실제 무관 표본.7z",
        tmp_path / "7z 입력",
        tuple(_noise_png(seed) for seed in (201, 202, 203)),
    )
    return root


def _noise_png(seed: int) -> bytes:
    image = Image.effect_noise((96, 128), 20 + seed).convert("RGB")
    if seed % 2:
        image = image.transpose(Image.Transpose.ROTATE_90)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _write_zip(
    path: Path,
    pages: tuple[bytes, ...],
    *,
    compression: int = ZIP_DEFLATED,
    comment: bytes = b"",
) -> None:
    with ZipFile(path, "w", compression=compression) as archive:
        archive.comment = comment
        for index, payload in enumerate(pages, 1):
            archive.writestr(f"{index:03d}.png", payload)


def _write_7z(path: Path, staging: Path, pages: tuple[bytes, ...]) -> None:
    staging.mkdir()
    names: list[str] = []
    for index, payload in enumerate(pages, 1):
        name = f"{index:03d}.png"
        (staging / name).write_bytes(payload)
        names.append(name)
    subprocess.run(
        [str(SEVEN_ZIP), "a", "-t7z", str(path.resolve()), *names],
        cwd=staging,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
