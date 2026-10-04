import stat
from pathlib import Path
from types import SimpleNamespace

import archive_analyzer.paths as paths_module
from archive_analyzer.paths import (
    has_reparse_point_in_existing_chain,
    is_path_within,
    normalize_path_key,
)


def test_windows_path_key_is_case_insensitive() -> None:
    assert normalize_path_key(Path(r"C:\Data\책.ZIP")) == normalize_path_key(
        Path(r"c:\data\책.zip")
    )


def test_output_must_not_be_inside_scan_root(tmp_path: Path) -> None:
    assert is_path_within(tmp_path / "index.db", tmp_path)
    assert not is_path_within(tmp_path.parent / "index.db", tmp_path)


def test_path_chain_detects_reparse_point_in_existing_ancestor(
    tmp_path: Path, monkeypatch
) -> None:
    requested = tmp_path / "linked-parent" / "nested"
    linked_parent = tmp_path / "linked-parent"
    visited: list[Path] = []

    def fake_lstat(path: Path):
        candidate = Path(path)
        visited.append(candidate)
        attributes = (
            getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            if candidate == linked_parent
            else 0
        )
        return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=attributes)

    monkeypatch.setattr(paths_module.os, "lstat", fake_lstat)

    assert has_reparse_point_in_existing_chain(requested) is True
    assert linked_parent in visited
    assert requested not in visited
