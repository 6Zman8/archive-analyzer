from pathlib import Path
from zipfile import ZipFile, ZipInfo

import pytest

import archive_analyzer.inspection.zip_backend as zip_backend
from archive_analyzer.domain import ArchiveFormat
from archive_analyzer.inspection.base import (
    DispatchingInspector,
    InspectionFailure,
    InspectionResult,
)
from archive_analyzer.inspection.zip_backend import ZipBackend
from tests.helpers import snapshot


def test_zip_backend_lists_images_and_nested_archive(tmp_path: Path) -> None:
    path = tmp_path / "book.zip"
    with ZipFile(path, "w") as archive:
        archive.writestr("10.jpg", b"ten")
        archive.writestr("2.png", b"two")
        archive.writestr("notes.txt", b"note")
        archive.writestr("nested.7z", b"not opened")

    result = ZipBackend().inspect(snapshot(path, ArchiveFormat.ZIP))

    assert [entry.path for entry in result.entries] == [
        "2.png",
        "10.jpg",
        "nested.7z",
        "notes.txt",
    ]
    assert result.image_count == 2
    assert result.nested_archive_count == 1


def test_zip_backend_excludes_directories_and_preserves_stable_ties(tmp_path: Path) -> None:
    path = tmp_path / "stable.zip"
    with ZipFile(path, "w") as archive:
        archive.writestr("chapter/", b"")
        archive.writestr("cafe\u0301.jpg", b"first")
        archive.writestr("caf\u00e9.jpg", b"second")

    result = ZipBackend().inspect(snapshot(path, ArchiveFormat.ZIP))

    assert [entry.path for entry in result.entries] == ["cafe\u0301.jpg", "caf\u00e9.jpg"]
    assert [entry.position for entry in result.entries] == [0, 1]
    assert result.entries[0].normalized_path == result.entries[1].normalized_path


def test_zip_backend_rejects_encrypted_archive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "encrypted.zip"
    path.write_bytes(b"placeholder")
    info = ZipInfo("page.jpg")
    info.flag_bits = 0x1

    class FakeZipFile:
        def __init__(self, archive_path: Path) -> None:
            assert archive_path == path

        def __enter__(self) -> "FakeZipFile":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def infolist(self) -> list[ZipInfo]:
            return [info]

        def read(self, *args: object) -> bytes:
            raise AssertionError("entry payload must not be read")

    monkeypatch.setattr(zip_backend, "ZipFile", FakeZipFile)
    monkeypatch.setattr(zip_backend, "_preflight_central_directory", lambda _: None)

    with pytest.raises(InspectionFailure) as caught:
        ZipBackend().inspect(snapshot(path, ArchiveFormat.ZIP))

    assert caught.value.code == "ENCRYPTED_UNSUPPORTED"


def test_zip_backend_preserves_missing_optional_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "missing-metadata.zip"
    path.write_bytes(b"placeholder")
    info = ZipInfo("page.jpg")
    info.file_size = None
    info.compress_size = None
    info.CRC = None

    class FakeZipFile:
        def __init__(self, archive_path: Path) -> None:
            assert archive_path == path

        def __enter__(self) -> "FakeZipFile":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def infolist(self) -> list[ZipInfo]:
            return [info]

    monkeypatch.setattr(zip_backend, "ZipFile", FakeZipFile)
    monkeypatch.setattr(zip_backend, "_preflight_central_directory", lambda _: None)

    first = ZipBackend().inspect(snapshot(path, ArchiveFormat.ZIP))
    second = ZipBackend().inspect(snapshot(path, ArchiveFormat.ZIP))

    assert first.entries[0].uncompressed_size is None
    assert first.entries[0].compressed_size is None
    assert first.entries[0].crc is None
    assert first.listing_signature == second.listing_signature


def test_zip_backend_rejects_corrupt_archive(tmp_path: Path) -> None:
    path = tmp_path / "broken.zip"
    path.write_bytes(b"not a zip file")

    with pytest.raises(InspectionFailure) as caught:
        ZipBackend().inspect(snapshot(path, ArchiveFormat.ZIP))

    assert caught.value.code == "CORRUPT_ARCHIVE"


def test_zip_backend_supports_cbz(tmp_path: Path) -> None:
    path = tmp_path / "book.cbz"
    with ZipFile(path, "w") as archive:
        archive.writestr("1.webp", b"image")

    result = ZipBackend().inspect(snapshot(path, ArchiveFormat.CBZ))

    assert result.archive_format is ArchiveFormat.CBZ
    assert result.image_count == 1


def test_dispatching_inspector_routes_formats_to_injected_backends(tmp_path: Path) -> None:
    path = tmp_path / "book.zip"
    path.write_bytes(b"x")
    expected = InspectionResult(ArchiveFormat.ZIP, (), 0, 0, "signature")

    class StubInspector:
        def __init__(self) -> None:
            self.snapshots = []

        def inspect(self, value: object) -> InspectionResult:
            self.snapshots.append(value)
            return expected

    zip_inspector = StubInspector()
    sevenzip_inspector = StubInspector()
    dispatcher = DispatchingInspector(zip_inspector, sevenzip_inspector)

    assert dispatcher.inspect(snapshot(path, ArchiveFormat.ZIP)) is expected
    assert dispatcher.inspect(snapshot(path, ArchiveFormat.CBZ)) is expected
    assert dispatcher.inspect(snapshot(path, ArchiveFormat.RAR)) is expected
    assert dispatcher.inspect(snapshot(path, ArchiveFormat.SEVEN_ZIP)) is expected
    assert len(zip_inspector.snapshots) == 2
    assert len(sevenzip_inspector.snapshots) == 2


def test_listing_signature_changes_with_listed_metadata(tmp_path: Path) -> None:
    first_path = tmp_path / "first.zip"
    second_path = tmp_path / "second.zip"
    with ZipFile(first_path, "w") as archive:
        archive.writestr("page.jpg", b"one")
    with ZipFile(second_path, "w") as archive:
        archive.writestr("page.jpg", b"two")

    first = ZipBackend().inspect(snapshot(first_path, ArchiveFormat.ZIP))
    second = ZipBackend().inspect(snapshot(second_path, ArchiveFormat.ZIP))

    assert first.listing_signature != second.listing_signature


def test_zip_backend_rejects_entry_limit_before_opening_full_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "too-many.zip"
    with ZipFile(path, "w") as archive:
        for index in range(3):
            archive.writestr(f"{index}.jpg", b"")

    monkeypatch.setattr(zip_backend, "MAX_ARCHIVE_ENTRIES", 2, raising=False)

    class MustNotOpenZipFile:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("full ZipInfo directory must not be built after preflight rejection")

    monkeypatch.setattr(zip_backend, "ZipFile", MustNotOpenZipFile)

    with pytest.raises(InspectionFailure) as caught:
        ZipBackend().inspect(snapshot(path, ArchiveFormat.ZIP))

    assert caught.value.code == "ARCHIVE_LIMIT_EXCEEDED"


def test_zip_backend_rejects_central_directory_byte_limit_before_full_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "oversized-directory.zip"
    with ZipFile(path, "w") as archive:
        archive.writestr(f"{'x' * 200}.jpg", b"")

    monkeypatch.setattr(zip_backend, "MAX_LISTING_BYTES", 64, raising=False)

    class MustNotOpenZipFile:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("full ZipInfo directory must not be built after preflight rejection")

    monkeypatch.setattr(zip_backend, "ZipFile", MustNotOpenZipFile)

    with pytest.raises(InspectionFailure) as caught:
        ZipBackend().inspect(snapshot(path, ArchiveFormat.ZIP))

    assert caught.value.code == "ARCHIVE_LIMIT_EXCEEDED"
