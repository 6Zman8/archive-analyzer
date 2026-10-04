from __future__ import annotations

import hashlib
import subprocess
import zipfile
from pathlib import Path

import pytest

from archive_analyzer.cli import main
from archive_analyzer.storage.repository import Repository


SEVEN_ZIP = Path(r"C:\Program Files\7-Zip\7z.exe")


def _write_zip(path: Path, entries: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)


def _create_7z(path: Path, source: Path, *arguments: str) -> None:
    subprocess.run(
        [str(SEVEN_ZIP), "a", "-t7z", *arguments, str(path), str(source)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )


def _tree_fingerprint(root: Path) -> dict[str, tuple[str, int, int]]:
    result: dict[str, tuple[str, int, int]] = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        value = path.stat()
        result[str(path.relative_to(root))] = (
            hashlib.sha256(path.read_bytes()).hexdigest(),
            value.st_size,
            value.st_mtime_ns,
        )
    return result


@pytest.fixture
def sample_tree(tmp_path: Path) -> Path:
    root = tmp_path / "복사 표본"
    _write_zip(root / "한국어" / "정상.zip", {"001.jpg": b"one", "002.png": b"two"})
    _write_zip(root / "日本語" / "漫画.cbz", {"表紙.webp": b"cover"})
    _write_zip(
        root / "중첩 (표본).zip",
        {"001.jpg": b"outer", "부록/안쪽.zip": b"not opened"},
    )
    (root / "손상.zip").write_bytes(b"not a zip archive")

    seven_zip_source = tmp_path / "7z-source-페이지.jpg"
    seven_zip_source.write_bytes(b"seven zip image")
    _create_7z(root / "日本語" / "七巻.7z", seven_zip_source)
    _create_7z(root / "암호화.7z", seven_zip_source, "-psecret")
    return root


@pytest.mark.skipif(not SEVEN_ZIP.is_file(), reason="7-Zip is not installed")
def test_full_scan_continues_after_failures_and_reuses_unchanged_indexes(
    sample_tree: Path, tmp_path: Path
) -> None:
    database = tmp_path / "archive-index.db"
    before = _tree_fingerprint(sample_tree)

    assert (
        main(
            [
                "scan",
                str(sample_tree),
                "--db",
                str(database),
                "--seven-zip",
                str(SEVEN_ZIP),
                "--workers",
                "2",
            ]
        )
        == 0
    )
    repository = Repository.open_readonly(database)
    try:
        first = repository.latest_summary()
        assert first is not None
        assert (
            first.discovered_count,
            first.reused_count,
            first.indexed_count,
            first.skipped_count,
            first.failed_count,
            first.discovery_complete,
        ) == (6, 0, 4, 1, 1, True)

        rows = {row.path.name: row for row in repository.report_rows()}
        assert rows["정상.zip"].image_count == 2
        assert rows["漫画.cbz"].image_count == 1
        assert rows["七巻.7z"].image_count == 1
        assert rows["손상.zip"].error_code == "CORRUPT_ARCHIVE"
        assert rows["암호화.7z"].error_code == "ENCRYPTED_UNSUPPORTED"
        nested = repository._connection.execute(  # noqa: SLF001 - integration evidence
            "SELECT entry_kind, path FROM archive_entries "
            "WHERE path = '부록/안쪽.zip'"
        ).fetchone()
        assert nested == ("NESTED_ARCHIVE", "부록/안쪽.zip")
    finally:
        repository.close()

    assert _tree_fingerprint(sample_tree) == before

    assert (
        main(
            [
                "scan",
                str(sample_tree),
                "--db",
                str(database),
                "--seven-zip",
                str(SEVEN_ZIP),
                "--workers",
                "2",
            ]
        )
        == 0
    )
    repository = Repository.open_readonly(database)
    try:
        second = repository.latest_summary()
        assert second is not None
        assert second.discovered_count == 6
        assert second.reused_count == first.indexed_count
        assert second.indexed_count == 0
        assert second.skipped_count == 1
        assert second.failed_count == 1
        assert second.discovery_complete is True
    finally:
        repository.close()

    assert _tree_fingerprint(sample_tree) == before
