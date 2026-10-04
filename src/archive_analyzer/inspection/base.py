from dataclasses import dataclass
from typing import Protocol

from archive_analyzer.domain import ArchiveFormat, EntryKind, FileSnapshot


MAX_ARCHIVE_ENTRIES = 50_000
MAX_LISTING_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ArchiveEntry:
    position: int
    path: str
    normalized_path: str
    sort_key: str
    uncompressed_size: int | None
    compressed_size: int | None
    crc: str | None
    kind: EntryKind
    image_format_hint: str | None


@dataclass(frozen=True, slots=True)
class InspectionResult:
    archive_format: ArchiveFormat
    entries: tuple[ArchiveEntry, ...]
    image_count: int
    nested_archive_count: int
    listing_signature: str


class InspectionFailure(Exception):
    def __init__(self, code: str, summary: str, detail: str | None = None) -> None:
        super().__init__(summary)
        self.code = code
        self.summary = summary
        self.detail = detail


class ArchiveInspector(Protocol):
    def inspect(self, snapshot: FileSnapshot) -> InspectionResult: ...


class DispatchingInspector:
    def __init__(
        self, zip_backend: ArchiveInspector, sevenzip_backend: ArchiveInspector
    ) -> None:
        self._zip_backend = zip_backend
        self._sevenzip_backend = sevenzip_backend

    def inspect(self, snapshot: FileSnapshot) -> InspectionResult:
        if snapshot.archive_format in {ArchiveFormat.ZIP, ArchiveFormat.CBZ}:
            return self._zip_backend.inspect(snapshot)
        if snapshot.archive_format in {ArchiveFormat.RAR, ArchiveFormat.SEVEN_ZIP}:
            return self._sevenzip_backend.inspect(snapshot)
        raise InspectionFailure(
            "UNSUPPORTED_FORMAT",
            "This archive format is not supported for inspection.",
            str(snapshot.archive_format),
        )
