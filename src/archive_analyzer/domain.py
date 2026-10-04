from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class ArchiveFormat(StrEnum):
    ZIP = "ZIP"
    CBZ = "CBZ"
    RAR = "RAR"
    SEVEN_ZIP = "7Z"


class EntryKind(StrEnum):
    IMAGE = "IMAGE"
    NESTED_ARCHIVE = "NESTED_ARCHIVE"
    OTHER = "OTHER"
    DIRECTORY = "DIRECTORY"


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    path: Path
    path_key: str
    size: int
    mtime_ns: int
    archive_format: ArchiveFormat


@dataclass(frozen=True, slots=True)
class DiscoveryError:
    path: Path
    code: str
    summary: str
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class DiscoveryEvent:
    snapshot: FileSnapshot | None = None
    error: DiscoveryError | None = None
