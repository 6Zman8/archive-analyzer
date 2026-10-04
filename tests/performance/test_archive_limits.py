import time
import tracemalloc
from pathlib import Path
from zipfile import ZIP_STORED, ZipFile

import pytest

from archive_analyzer.domain import ArchiveFormat
from archive_analyzer.inspection.base import InspectionFailure
from archive_analyzer.inspection.zip_backend import ZipBackend
from tests.helpers import snapshot


@pytest.mark.timeout(180)
def test_hundred_thousand_entry_zip_is_rejected_with_bounded_memory(tmp_path: Path) -> None:
    archive_path = tmp_path / "hundred-thousand.zip"
    with ZipFile(archive_path, "w", compression=ZIP_STORED) as archive:
        for index in range(100_000):
            archive.writestr(f"{index:06}.jpg", b"")

    tracemalloc.start()
    started = time.perf_counter()
    try:
        with pytest.raises(InspectionFailure) as raised:
            ZipBackend().inspect(snapshot(archive_path, ArchiveFormat.ZIP))
        elapsed_seconds = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert raised.value.code == "ARCHIVE_LIMIT_EXCEEDED"
    print(
        f"ZIP_LIMIT elapsed_seconds={elapsed_seconds:.3f} "
        f"peak_mib={peak / (1024 * 1024):.3f}"
    )
    assert peak < 64 * 1024 * 1024


@pytest.mark.timeout(180)
def test_hundred_thousand_directory_zip_is_rejected_with_bounded_memory(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "hundred-thousand-directories.zip"
    with ZipFile(archive_path, "w", compression=ZIP_STORED) as archive:
        for index in range(100_000):
            archive.writestr(f"{index:06}/", b"")

    tracemalloc.start()
    started = time.perf_counter()
    try:
        with pytest.raises(InspectionFailure) as raised:
            ZipBackend().inspect(snapshot(archive_path, ArchiveFormat.ZIP))
        elapsed_seconds = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert raised.value.code == "ARCHIVE_LIMIT_EXCEEDED"
    print(
        f"ZIP_DIRECTORY_LIMIT elapsed_seconds={elapsed_seconds:.3f} "
        f"peak_mib={peak / (1024 * 1024):.3f}"
    )
    assert peak < 64 * 1024 * 1024
