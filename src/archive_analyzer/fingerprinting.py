import hashlib
import sys
import warnings
from contextlib import contextmanager
from dataclasses import dataclass
from io import BytesIO
from threading import RLock, local
from typing import Iterator, Sequence

from PIL import Image, ImageOps


MAX_IMAGE_BYTES = 128 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000
_PIL_WARNING_LOCK = RLock()
_PIL_WARNING_STATE = local()


class _PillowWarningsProxy:
    def __getattr__(self, name: str) -> object:
        return getattr(warnings, name)

    def warn(
        self,
        message: str | Warning,
        category: type[Warning] | None = None,
        stacklevel: int = 1,
        source: object | None = None,
        *,
        skip_file_prefixes: tuple[str, ...] = (),
    ) -> None:
        if getattr(_PIL_WARNING_STATE, "raise_warnings", False):
            if isinstance(message, Warning):
                raise message
            raise (category or UserWarning)(message)
        warnings.warn(
            message,
            category,
            stacklevel=stacklevel + 1,
            source=source,
            skip_file_prefixes=skip_file_prefixes,
        )


_PIL_WARNING_PROXY = _PillowWarningsProxy()


def _install_pillow_warning_proxy() -> None:
    Image.init()
    for module_name, module in tuple(sys.modules.items()):
        if module_name.startswith("PIL.") and getattr(module, "warnings", None) is warnings:
            module.warnings = _PIL_WARNING_PROXY


@contextmanager
def _pillow_warnings_as_errors() -> Iterator[None]:
    previous = getattr(_PIL_WARNING_STATE, "raise_warnings", False)
    _PIL_WARNING_STATE.raise_warnings = True
    try:
        yield
    finally:
        _PIL_WARNING_STATE.raise_warnings = previous


_install_pillow_warning_proxy()


@dataclass(frozen=True, slots=True)
class ImageFingerprint:
    byte_sha256: str
    pixel_sha256: str
    dhash64: str
    ahash64: str
    width: int
    height: int


class FingerprintFailure(Exception):
    def __init__(self, code: str, summary: str) -> None:
        super().__init__(f"{code}: {summary}")
        self.code = code
        self.summary = summary


def fingerprint_image(payload: bytes) -> ImageFingerprint:
    if len(payload) > MAX_IMAGE_BYTES:
        raise FingerprintFailure("IMAGE_BYTE_LIMIT", "Image data exceeds the byte limit.")

    try:
        with _PIL_WARNING_LOCK, _pillow_warnings_as_errors():
            _verify_image(payload)
            canonical = _decode_image(payload)
            pixel_digest = hashlib.sha256()
            pixel_digest.update(canonical.width.to_bytes(4, "big"))
            pixel_digest.update(canonical.height.to_bytes(4, "big"))
            pixel_digest.update(canonical.tobytes())
            grayscale = ImageOps.grayscale(canonical)
            result = ImageFingerprint(
                byte_sha256=hashlib.sha256(payload).hexdigest(),
                pixel_sha256=pixel_digest.hexdigest(),
                dhash64=_dhash(grayscale),
                ahash64=_ahash(grayscale),
                width=canonical.width,
                height=canonical.height,
            )
    except FingerprintFailure:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as error:
        raise FingerprintFailure("IMAGE_PIXEL_LIMIT", "Image exceeds the pixel limit.") from error
    except (OSError, ValueError, Warning) as error:
        raise FingerprintFailure("IMAGE_DECODE_FAILED", "Image data cannot be decoded.") from error
    return result


def _verify_image(payload: bytes) -> None:
    with Image.open(BytesIO(payload)) as opened:
        _require_pixel_limit(opened)
        opened.verify()


def _decode_image(payload: bytes) -> Image.Image:
    with Image.open(BytesIO(payload)) as opened:
        _require_pixel_limit(opened)
        canonical = ImageOps.exif_transpose(opened).convert("RGB")
        canonical.load()
        return canonical


def _require_pixel_limit(image: Image.Image) -> None:
    if image.width * image.height > MAX_IMAGE_PIXELS:
        raise FingerprintFailure("IMAGE_PIXEL_LIMIT", "Image exceeds the pixel limit.")


def probe_positions(image_positions: Sequence[int]) -> tuple[int, ...]:
    if not image_positions:
        return ()

    last_index = len(image_positions) - 1
    indices = (0, *(round(last_index * fraction) for fraction in (0.1, 0.25, 0.5, 0.75, 0.9)), last_index)
    return tuple(dict.fromkeys(image_positions[index] for index in indices))


def hamming_distance(left: str, right: str) -> int:
    return (int(left, 16) ^ int(right, 16)).bit_count()


def _dhash(grayscale: Image.Image) -> str:
    resized = grayscale.resize((9, 8), Image.Resampling.LANCZOS)
    value = 0
    for y in range(8):
        for x in range(8):
            value = (value << 1) | (resized.getpixel((x, y)) > resized.getpixel((x + 1, y)))
    return f"{value:016x}"


def _ahash(grayscale: Image.Image) -> str:
    resized = grayscale.resize((8, 8), Image.Resampling.LANCZOS)
    pixels = tuple(resized.getpixel((x, y)) for y in range(8) for x in range(8))
    average = sum(pixels) / len(pixels)
    value = 0
    for pixel in pixels:
        value = (value << 1) | (pixel >= average)
    return f"{value:016x}"
