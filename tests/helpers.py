from pathlib import Path

from archive_analyzer.domain import ArchiveFormat, FileSnapshot
from archive_analyzer.paths import normalize_path_key


def snapshot(path: Path, archive_format: ArchiveFormat) -> FileSnapshot:
    value = path.stat()
    return FileSnapshot(
        path=path,
        path_key=normalize_path_key(path),
        size=value.st_size,
        mtime_ns=value.st_mtime_ns,
        archive_format=archive_format,
    )
