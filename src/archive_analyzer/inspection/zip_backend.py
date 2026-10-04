import hashlib
import struct
import zipfile
from pathlib import Path
from zipfile import BadZipFile, ZipFile, ZipInfo

from archive_analyzer.classification import (
    classify_entry,
    natural_sort_key,
    normalize_entry_path,
    serialize_natural_sort_key,
)
from archive_analyzer.domain import ArchiveFormat, EntryKind, FileSnapshot
from archive_analyzer.inspection.base import (
    MAX_ARCHIVE_ENTRIES,
    MAX_LISTING_BYTES,
    ArchiveEntry,
    InspectionFailure,
    InspectionResult,
)


class ZipBackend:
    def inspect(self, snapshot: FileSnapshot) -> InspectionResult:
        if snapshot.archive_format not in {ArchiveFormat.ZIP, ArchiveFormat.CBZ}:
            raise InspectionFailure(
                "UNSUPPORTED_FORMAT",
                "ZipBackend only supports ZIP and CBZ archives.",
                str(snapshot.archive_format),
            )

        try:
            _preflight_central_directory(snapshot.path)
            with ZipFile(snapshot.path) as archive:
                file_infos = archive.infolist()
        except BadZipFile as error:
            raise InspectionFailure(
                "CORRUPT_ARCHIVE",
                "The ZIP archive cannot be read.",
                str(error),
            ) from error
        except FileNotFoundError as error:
            raise InspectionFailure("FILE_NOT_FOUND", "Archive file was not found.", str(error)) from error
        except PermissionError as error:
            raise InspectionFailure("ACCESS_DENIED", "Archive access was denied.", str(error)) from error

        if any(info.flag_bits & 0x1 for info in file_infos):
            raise InspectionFailure(
                "ENCRYPTED_UNSUPPORTED",
                "Encrypted ZIP archives are not supported.",
            )

        entries = _entries_from_infos(file_infos)
        return InspectionResult(
            archive_format=snapshot.archive_format,
            entries=entries,
            image_count=sum(entry.kind is EntryKind.IMAGE for entry in entries),
            nested_archive_count=sum(entry.kind is EntryKind.NESTED_ARCHIVE for entry in entries),
            listing_signature=listing_signature(entries),
        )


def _entries_from_infos(file_infos: list[ZipInfo]) -> tuple[ArchiveEntry, ...]:
    sortable_infos = [info for info in file_infos if not _is_directory(info)]
    sortable_infos.sort(key=lambda info: natural_sort_key(info.filename))
    return tuple(_archive_entry(position, info) for position, info in enumerate(sortable_infos))


def _preflight_central_directory(path: Path) -> None:
    with path.open("rb") as stream:
        end_record = zipfile._EndRecData(stream)  # type: ignore[attr-defined]
        if not end_record:
            raise BadZipFile("File is not a zip file")
        central_size = int(end_record[zipfile._ECD_SIZE])  # type: ignore[attr-defined]
        central_offset = int(end_record[zipfile._ECD_OFFSET])  # type: ignore[attr-defined]
        if central_size > MAX_LISTING_BYTES:
            raise _archive_limit_failure()
        concatenated_offset = (
            int(end_record[zipfile._ECD_LOCATION])  # type: ignore[attr-defined]
            - central_size
            - central_offset
        )
        if end_record[zipfile._ECD_SIGNATURE] == zipfile.stringEndArchive64:  # type: ignore[attr-defined]
            # Newer Python returns the ZIP64 record location itself; older
            # versions return the following ordinary EOCD. Inspect the actual
            # signature rather than relying on a private API's version semantics.
            stream.seek(int(end_record[zipfile._ECD_LOCATION]))
            signature = stream.read(4)
            if signature == zipfile.stringEndArchive:
                concatenated_offset -= zipfile.sizeEndCentDir64 + zipfile.sizeEndCentDir64Locator
            elif signature != zipfile.stringEndArchive64:
                raise BadZipFile("Invalid ZIP64 end record location")
        start = central_offset + concatenated_offset
        if start < 0:
            raise BadZipFile("Bad offset for central directory")
        stream.seek(start)

        consumed = 0
        central_records = 0
        while consumed < central_size:
            header = stream.read(zipfile.sizeCentralDir)
            if len(header) != zipfile.sizeCentralDir:
                raise BadZipFile("Truncated central directory")
            fields = struct.unpack(zipfile.structCentralDir, header)
            if fields[zipfile._CD_SIGNATURE] != zipfile.stringCentralDir:  # type: ignore[attr-defined]
                raise BadZipFile("Bad magic number for central directory")
            filename_length = int(fields[zipfile._CD_FILENAME_LENGTH])  # type: ignore[attr-defined]
            extra_length = int(fields[zipfile._CD_EXTRA_FIELD_LENGTH])  # type: ignore[attr-defined]
            comment_length = int(fields[zipfile._CD_COMMENT_LENGTH])  # type: ignore[attr-defined]
            record_size = zipfile.sizeCentralDir + filename_length + extra_length + comment_length
            consumed += record_size
            if consumed > central_size:
                raise BadZipFile("Truncated central directory")
            filename = stream.read(filename_length)
            if len(filename) != filename_length:
                raise BadZipFile("Truncated central directory")
            stream.seek(extra_length + comment_length, 1)
            central_records += 1
            if central_records > MAX_ARCHIVE_ENTRIES:
                raise _archive_limit_failure()
        if consumed != central_size:
            raise BadZipFile("Truncated central directory")


def _archive_limit_failure() -> InspectionFailure:
    return InspectionFailure(
        "ARCHIVE_LIMIT_EXCEEDED",
        "Archive listing exceeds the V0 safety limits.",
        f"maximum entries={MAX_ARCHIVE_ENTRIES}; maximum listing bytes={MAX_LISTING_BYTES}",
    )


def _is_directory(info: ZipInfo) -> bool:
    return info.is_dir() or info.filename.endswith(("/", "\\"))


def _archive_entry(position: int, info: ZipInfo) -> ArchiveEntry:
    kind, image_format_hint = classify_entry(info.filename)
    return ArchiveEntry(
        position=position,
        path=info.filename,
        normalized_path=normalize_entry_path(info.filename),
        sort_key=serialize_natural_sort_key(info.filename),
        uncompressed_size=info.file_size,
        compressed_size=info.compress_size,
        crc=None if info.CRC is None else f"{info.CRC:08x}",
        kind=kind,
        image_format_hint=image_format_hint,
    )


def listing_signature(entries: tuple[ArchiveEntry, ...]) -> str:
    fields: list[str] = []
    for entry in entries:
        fields.extend(
            (
                entry.normalized_path,
                _stringify_optional(entry.uncompressed_size),
                _stringify_optional(entry.compressed_size),
                _stringify_optional(entry.crc).casefold(),
                entry.kind.value,
            )
        )
    return hashlib.sha256("\0".join(fields).encode("utf-8")).hexdigest()


def _stringify_optional(value: object | None) -> str:
    return "" if value is None else str(value)
