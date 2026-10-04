import os
import stat
import unicodedata
from pathlib import Path


def normalize_path_key(path: Path) -> str:
    resolved = path.resolve(strict=False)
    normalized = unicodedata.normalize("NFC", str(resolved))
    return normalized.replace("\\", "/").casefold()


def is_path_within(path: Path, root: Path) -> bool:
    candidate = path.resolve(strict=False)
    boundary = root.resolve(strict=False)
    try:
        candidate.relative_to(boundary)
    except ValueError:
        return False
    return True


def has_reparse_point_in_existing_chain(path: Path) -> bool:
    """Return whether any existing lexical component is a symlink/reparse point."""
    lexical = path if path.is_absolute() else Path.cwd() / path
    candidate = Path(lexical.anchor)
    for part in lexical.parts[1:]:
        if part in {"", "."}:
            continue
        if part == "..":
            candidate = candidate.parent
            continue
        candidate /= part
        try:
            value = os.lstat(candidate)
        except (FileNotFoundError, NotADirectoryError):
            continue
        if stat.S_ISLNK(value.st_mode):
            return True
        attributes = getattr(value, "st_file_attributes", 0)
        if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            return True
    return False
