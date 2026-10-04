import json
import re
import unicodedata

from archive_analyzer.domain import EntryKind


_NATURAL_TOKEN_PATTERN = re.compile(r"(\d+)")
_IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".gif",
    ".bmp",
    ".tif",
    ".tiff",
    ".avif",
    ".jxl",
}
_ARCHIVE_EXTENSIONS = {".zip", ".cbz", ".rar", ".7z"}


def normalize_entry_path(path: str) -> str:
    return unicodedata.normalize("NFC", path).replace("\\", "/").casefold()


def natural_sort_key(path: str) -> tuple[tuple[int, int | str], ...]:
    tokens = _natural_tokens(path)
    return tuple((0, token) if isinstance(token, int) else (1, token) for token in tokens)


def serialize_natural_sort_key(path: str) -> str:
    return json.dumps(_natural_tokens(path), ensure_ascii=False, separators=(",", ":"))


def classify_entry(path: str) -> tuple[EntryKind, str | None]:
    normalized_path = normalize_entry_path(path)
    for extension in _IMAGE_EXTENSIONS:
        if normalized_path.endswith(extension):
            return EntryKind.IMAGE, extension[1:]
    if any(normalized_path.endswith(extension) for extension in _ARCHIVE_EXTENSIONS):
        return EntryKind.NESTED_ARCHIVE, None
    return EntryKind.OTHER, None


def _natural_tokens(path: str) -> list[int | str]:
    normalized = normalize_entry_path(path)
    return [int(token) if token.isdecimal() else token for token in _NATURAL_TOKEN_PATTERN.split(normalized)]
