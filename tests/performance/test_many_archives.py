from __future__ import annotations

import time
import tracemalloc
import zipfile
from pathlib import Path

import pytest

from archive_analyzer.cli import main
from archive_analyzer.storage.repository import Repository


@pytest.mark.timeout(180)
def test_indexes_one_thousand_small_archives_with_bounded_memory(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    for index in range(1_000):
        with zipfile.ZipFile(source / f"book-{index:04}.zip", "w") as archive:
            archive.writestr("001.jpg", b"image")

    database = tmp_path / "index.db"
    tracemalloc.start()
    started = time.perf_counter()
    try:
        assert main(["scan", str(source), "--db", str(database), "--workers", "2"]) == 0
        elapsed_seconds = time.perf_counter() - started
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    repository = Repository.open_readonly(database)
    try:
        summary = repository.latest_summary()
        assert summary is not None
        assert summary.discovered_count == 1_000
        assert summary.indexed_count == 1_000
        assert summary.failed_count == 0
    finally:
        repository.close()

    peak_mib = peak_bytes / (1024 * 1024)
    print(f"PERF elapsed_seconds={elapsed_seconds:.3f} peak_mib={peak_mib:.3f}")
    assert elapsed_seconds < 180
    assert peak_bytes < 256 * 1024 * 1024
