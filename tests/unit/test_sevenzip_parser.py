from pathlib import Path

import pytest

from archive_analyzer.domain import ArchiveFormat, EntryKind, FileSnapshot
from archive_analyzer.inspection.base import ArchiveEntry, InspectionFailure
import archive_analyzer.inspection.sevenzip as sevenzip_module
from archive_analyzer.inspection.sevenzip import SevenZipBackend, parse_slt_listing
from archive_analyzer.inspection.zip_backend import listing_signature


SLT = """Path = example.7z
Type = 7z
Physical Size = 123

Path = pages/has = sign 2.jpg
Size = 20
Packed Size = 10
CRC = AABBCCDD
Attributes = A
Encrypted = -

Path = pages/
Size = 0
Packed Size = 0
Attributes = D
Encrypted = -

Path = nested.zip
Size = 4
Packed Size = 4
CRC = 11223344
Attributes = A
Encrypted = -
"""


@pytest.mark.parametrize("archive_format", [ArchiveFormat.SEVEN_ZIP, ArchiveFormat.RAR])
def test_parse_slt_listing_classifies_non_header_entries(archive_format: ArchiveFormat) -> None:
    result = parse_slt_listing(SLT, archive_format)

    assert [entry.path for entry in result.entries] == ["nested.zip", "pages/has = sign 2.jpg"]
    assert result.entries[1].uncompressed_size == 20
    assert result.entries[1].compressed_size == 10
    assert result.entries[1].crc == "AABBCCDD"
    assert result.image_count == 1
    assert result.nested_archive_count == 1
    assert result.archive_format is archive_format


def test_parse_slt_listing_rejects_encrypted_entries() -> None:
    listing = """Path = page.jpg
Size = 20
Attributes = A
Encrypted = +
"""

    with pytest.raises(InspectionFailure) as raised:
        parse_slt_listing(listing, ArchiveFormat.RAR)

    assert raised.value.code == "ENCRYPTED_UNSUPPORTED"


def test_parse_slt_listing_returns_empty_result_for_header_only_listing() -> None:
    listing = """Path = empty.7z
Type = 7z
Physical Size = 32
Solid = -
Blocks = 0
"""

    result = parse_slt_listing(listing, ArchiveFormat.SEVEN_ZIP)

    assert result.entries == ()
    assert result.image_count == 0
    assert result.nested_archive_count == 0


def test_parse_slt_listing_accepts_windows_line_endings() -> None:
    result = parse_slt_listing(SLT.replace("\n", "\r\n"), ArchiveFormat.SEVEN_ZIP)

    assert [entry.path for entry in result.entries] == ["nested.zip", "pages/has = sign 2.jpg"]


def test_missing_executable_has_stable_error(tmp_path: Path) -> None:
    backend = SevenZipBackend(tmp_path / "missing-7z.exe")
    fake = FileSnapshot(tmp_path / "a.7z", "a", 0, 0, ArchiveFormat.SEVEN_ZIP)

    with pytest.raises(InspectionFailure) as raised:
        backend.inspect(fake)

    assert raised.value.code == "SEVEN_ZIP_NOT_FOUND"


def test_listing_signature_normalizes_crc_case() -> None:
    upper_crc_entry = ArchiveEntry(
        position=0,
        path="page.jpg",
        normalized_path="page.jpg",
        sort_key='["page.jpg"]',
        uncompressed_size=20,
        compressed_size=10,
        crc="AABBCCDD",
        kind=EntryKind.IMAGE,
        image_format_hint="jpg",
    )
    lower_crc_entry = ArchiveEntry(
        position=0,
        path="page.jpg",
        normalized_path="page.jpg",
        sort_key='["page.jpg"]',
        uncompressed_size=20,
        compressed_size=10,
        crc="aabbccdd",
        kind=EntryKind.IMAGE,
        image_format_hint="jpg",
    )

    assert listing_signature((upper_crc_entry,)) == listing_signature((lower_crc_entry,))


def test_parse_slt_listing_rejects_too_many_non_directory_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    listing = "\n\n".join(
        f"Path = {index}.jpg\nSize = 1\nAttributes = A\nEncrypted = -"
        for index in range(3)
    )
    monkeypatch.setattr(sevenzip_module, "MAX_ARCHIVE_ENTRIES", 2, raising=False)

    with pytest.raises(InspectionFailure) as raised:
        parse_slt_listing(listing, ArchiveFormat.SEVEN_ZIP)

    assert raised.value.code == "ARCHIVE_LIMIT_EXCEEDED"
