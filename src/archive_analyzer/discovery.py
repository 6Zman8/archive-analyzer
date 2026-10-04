import errno
import os
from pathlib import Path
import stat
from collections.abc import Iterator

from archive_analyzer.domain import ArchiveFormat, DiscoveryError, DiscoveryEvent, FileSnapshot
from archive_analyzer.paths import normalize_path_key


_ARCHIVE_FORMATS = {
    ".zip": ArchiveFormat.ZIP,
    ".cbz": ArchiveFormat.CBZ,
    ".rar": ArchiveFormat.RAR,
    ".7z": ArchiveFormat.SEVEN_ZIP,
}


def snapshot_file(path: Path) -> FileSnapshot:
    archive_format = _ARCHIVE_FORMATS.get(path.suffix.casefold())
    if archive_format is None:
        raise ValueError(f"Unsupported archive format: {path.suffix}")

    file_stat = path.stat()
    return FileSnapshot(
        path=path.absolute(),
        path_key=normalize_path_key(path),
        size=file_stat.st_size,
        mtime_ns=file_stat.st_mtime_ns,
        archive_format=archive_format,
    )


def discover_archives(root: Path) -> Iterator[DiscoveryEvent]:
    root_path = Path(root)
    try:
        if _is_symlink_or_reparse_point(root_path):
            return
    except OSError as error:
        yield _error_event(root_path, error)
        return

    pending = [root_path.absolute()]
    visited: set[str] = set()

    while pending:
        directory = pending.pop()
        try:
            directory_key = normalize_path_key(directory)
        except OSError as error:
            yield _error_event(directory, error)
            continue
        if directory_key in visited:
            continue
        visited.add(directory_key)

        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    try:
                        if entry.is_symlink() or _entry_is_reparse_point(entry):
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(path)
                            continue
                        if path.suffix.casefold() not in _ARCHIVE_FORMATS:
                            continue
                        yield DiscoveryEvent(snapshot=snapshot_file(path))
                    except OSError as error:
                        yield _error_event(path, error)
        except OSError as error:
            yield _error_event(directory, error)


def _is_symlink_or_reparse_point(path: Path) -> bool:
    if path.is_symlink():
        return True
    return _has_reparse_point_attribute(path.lstat())


def _entry_is_reparse_point(entry: os.DirEntry[str]) -> bool:
    return _has_reparse_point_attribute(entry.stat(follow_symlinks=False))


def _has_reparse_point_attribute(file_stat: os.stat_result) -> bool:
    attributes = getattr(file_stat, "st_file_attributes", 0)
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _error_event(path: Path, error: OSError) -> DiscoveryEvent:
    code = _error_code(error)
    return DiscoveryEvent(
        error=DiscoveryError(
            path=path,
            code=code,
            summary=_error_summary(code),
            detail=str(error),
        )
    )


def _error_code(error: OSError) -> str:
    if error.errno in {errno.ENOENT, errno.ENOTDIR}:
        return "FILE_NOT_FOUND"
    if error.errno in {errno.EACCES, errno.EPERM}:
        return "ACCESS_DENIED"
    if error.errno == errno.ENAMETOOLONG:
        return "PATH_TOO_LONG"
    return "DISCOVERY_ERROR"


def _error_summary(code: str) -> str:
    return {
        "FILE_NOT_FOUND": "Path was not found during discovery.",
        "ACCESS_DENIED": "Access was denied during discovery.",
        "PATH_TOO_LONG": "Path is too long to scan.",
        "DISCOVERY_ERROR": "Archive discovery failed for this path.",
    }[code]
