from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from archive_analyzer.domain import ArchiveFormat


class DuplicateRelation(StrEnum):
    EXACT_ARCHIVE = "EXACT_ARCHIVE"
    EXACT_CONTENT = "EXACT_CONTENT"
    VISUAL_VARIANT = "VISUAL_VARIANT"
    RELATED = "RELATED"


class ReviewAction(StrEnum):
    KEEP = "KEEP"
    REMOVE_CANDIDATE = "REMOVE_CANDIDATE"
    HOLD = "HOLD"


class AnalysisStage(StrEnum):
    ARCHIVE_HASH = "ARCHIVE_HASH"
    PROBE = "PROBE"
    CANDIDATE_BUILD = "CANDIDATE_BUILD"
    FULL = "FULL"
    MATCH = "MATCH"
    GROUP = "GROUP"


@dataclass(frozen=True, slots=True)
class ImageEntryRef:
    position: int
    path: str
    uncompressed_size: int | None
    crc: str | None


@dataclass(frozen=True, slots=True)
class ArchiveAnalysisInput:
    archive_id: int
    path: Path
    file_size: int
    mtime_ns: int
    archive_format: ArchiveFormat
    images: tuple[ImageEntryRef, ...]


@dataclass(frozen=True, slots=True)
class DuplicateProgress:
    stage: AnalysisStage
    archive_total: int
    archive_processed: int
    image_total: int
    image_processed: int
    failed_count: int
    candidate_count: int


@dataclass(frozen=True, slots=True)
class ProbeFingerprint:
    slot: int
    entry_position: int
    byte_sha256: str
    pixel_sha256: str
    dhash64: str
    ahash64: str
    width: int
    height: int
