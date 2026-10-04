from pathlib import Path

import pytest

import archive_analyzer.discovery as discovery
from archive_analyzer.discovery import discover_archives, snapshot_file
from archive_analyzer.domain import ArchiveFormat


class _FakeDirEntry:
    def __init__(self, path: Path, *, is_directory: bool) -> None:
        self.path = str(path)
        self._is_directory = is_directory

    def is_symlink(self) -> bool:
        return False

    def is_dir(self, *, follow_symlinks: bool) -> bool:
        assert not follow_symlinks
        return self._is_directory


class _FakeScandir:
    def __init__(self, entries: list[_FakeDirEntry]) -> None:
        self._entries = entries

    def __enter__(self) -> list[_FakeDirEntry]:
        return self._entries

    def __exit__(self, *args: object) -> None:
        return None


def test_discovery_returns_only_supported_archives(tmp_path: Path) -> None:
    for name in ("a.zip", "b.CBZ", "c.rar", "d.7z", "ignore.txt"):
        (tmp_path / name).write_bytes(b"x")

    events = list(discover_archives(tmp_path))

    names = {event.snapshot.path.name for event in events if event.snapshot is not None}
    assert names == {"a.zip", "b.CBZ", "c.rar", "d.7z"}


def test_discovery_does_not_follow_directory_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "inside.zip").write_bytes(b"x")
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    assert sum(event.snapshot is not None for event in discover_archives(link)) == 0


def test_discovery_does_not_follow_nested_directory_symlink(tmp_path: Path) -> None:
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (target / "inside.zip").write_bytes(b"x")
    link = scan_root / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    assert list(discover_archives(scan_root)) == []


def test_discovery_skips_reparse_point_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(discovery, "_is_symlink_or_reparse_point", lambda path: True)

    assert list(discover_archives(tmp_path)) == []


def test_discovery_skips_reparse_point_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    child = tmp_path / "reparse-directory"
    monkeypatch.setattr(discovery, "_entry_is_reparse_point", lambda entry: True)
    monkeypatch.setattr(
        discovery.os,
        "scandir",
        lambda path: _FakeScandir([_FakeDirEntry(child, is_directory=True)]),
    )

    assert list(discover_archives(tmp_path)) == []


def test_discovery_skips_reparse_point_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "reparse-file.zip"
    archive.write_bytes(b"x")
    monkeypatch.setattr(discovery, "_entry_is_reparse_point", lambda entry: True)
    monkeypatch.setattr(
        discovery.os,
        "scandir",
        lambda path: _FakeScandir([_FakeDirEntry(archive, is_directory=False)]),
    )

    assert list(discover_archives(tmp_path)) == []


def test_snapshot_file_records_case_insensitive_archive_format(tmp_path: Path) -> None:
    archive = tmp_path / "만화.CBZ"
    archive.write_bytes(b"x")

    snapshot = snapshot_file(archive)

    assert snapshot.path == archive
    assert snapshot.size == 1
    assert snapshot.archive_format is ArchiveFormat.CBZ


def test_discovery_emits_error_for_missing_root(tmp_path: Path) -> None:
    events = list(discover_archives(tmp_path / "missing"))

    assert len(events) == 1
    assert events[0].snapshot is None
    assert events[0].error is not None
    assert events[0].error.code == "FILE_NOT_FOUND"
