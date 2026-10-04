import json
import os
import sqlite3
import stat
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

import archive_analyzer.cli as cli_module
import archive_analyzer.storage.repository as repository_module
from archive_analyzer.cli import main
from archive_analyzer.domain import ArchiveFormat
from archive_analyzer.paths import normalize_path_key
from archive_analyzer.storage.repository import (
    LATEST_SCHEMA_VERSION,
    Repository,
    UnsafeDatabaseIdentity,
)
from tests.helpers import snapshot


def _indexed_database(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "source"
    root.mkdir()
    archive = root / "book.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("1.jpg", b"image")
    database = tmp_path / "index.db"
    assert main(["scan", str(root), "--db", str(database)]) == 0
    return database, root


def _file_identity(path: Path) -> tuple[bytes, int, int, int]:
    value = path.stat()
    return path.read_bytes(), value.st_size, value.st_mtime_ns, value.st_nlink


def _lstat_identity(path: Path) -> tuple[int, int, int, int]:
    value = os.lstat(path)
    return value.st_mode, value.st_size, value.st_mtime_ns, value.st_nlink


def _create_file_symlink_or_skip(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip(f"file symlink privilege is unavailable: {error}")
        raise


def _hard_link_source_as_sidecar(
    database: Path, source: Path, suffix: str
) -> Path:
    sidecar = database.with_name(f"{database.name}{suffix}")
    if sidecar.exists():
        sidecar.unlink()
    source.write_bytes(f"source identity for {suffix}".encode())
    try:
        os.link(source, sidecar)
    except OSError as error:
        pytest.skip(f"hard links are unavailable: {error}")
    return sidecar


def test_scan_rejects_database_inside_root(tmp_path: Path, capsys) -> None:
    exit_code = main(["scan", str(tmp_path), "--db", str(tmp_path / "index.db")])

    assert exit_code == 2
    assert "스캔 루트 밖" in capsys.readouterr().err


def test_scan_rejects_database_hard_linked_to_source_before_opening(
    tmp_path: Path, capsys
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    source_file = root / "original.zip"
    source_file.write_bytes(b"source bytes that must never become a database")
    database = tmp_path / "index.db"
    try:
        os.link(source_file, database)
    except OSError as error:
        pytest.skip(f"hard links are unavailable: {error}")
    before_source = (source_file.read_bytes(), source_file.stat().st_size, source_file.stat().st_mtime_ns)
    before_database = (database.read_bytes(), database.stat().st_size, database.stat().st_mtime_ns)

    assert main(["scan", str(root), "--db", str(database)]) == 2

    assert "하드 링크" in capsys.readouterr().err
    assert (source_file.read_bytes(), source_file.stat().st_size, source_file.stat().st_mtime_ns) == before_source
    assert (database.read_bytes(), database.stat().st_size, database.stat().st_mtime_ns) == before_database


def test_scan_rejects_hard_linked_shm_before_sqlite_open(
    tmp_path: Path, capsys
) -> None:
    database, root = _indexed_database(tmp_path)
    source = root / "shm-source.bin"
    sidecar = _hard_link_source_as_sidecar(database, source, "-shm")
    before_source = _file_identity(source)
    before_sidecar = _file_identity(sidecar)

    assert main(["scan", str(root), "--db", str(database)]) == 2

    assert "하드 링크" in capsys.readouterr().err
    assert _file_identity(source) == before_source
    assert _file_identity(sidecar) == before_sidecar


@pytest.mark.parametrize("command", ["status", "report"])
def test_read_commands_reject_hard_linked_shm_before_sqlite_open(
    tmp_path: Path, capsys, command: str
) -> None:
    database, root = _indexed_database(tmp_path)
    source = root / f"{command}-shm-source.bin"
    sidecar = _hard_link_source_as_sidecar(database, source, "-shm")
    before_source = _file_identity(source)
    before_sidecar = _file_identity(sidecar)
    arguments = [command, "--db", str(database)]
    if command == "report":
        arguments.extend(
            ["--format", "json", "--output", str(tmp_path / "report.json")]
        )

    assert main(arguments) == 2

    assert "하드 링크" in capsys.readouterr().err
    assert _file_identity(source) == before_source
    assert _file_identity(sidecar) == before_sidecar


def test_status_does_not_delete_hard_linked_wal_alias(
    tmp_path: Path, capsys
) -> None:
    database, root = _indexed_database(tmp_path)
    source = root / "wal-source.bin"
    sidecar = _hard_link_source_as_sidecar(database, source, "-wal")
    before_source = _file_identity(source)
    before_sidecar = _file_identity(sidecar)

    assert main(["status", "--db", str(database)]) == 2

    assert "하드 링크" in capsys.readouterr().err
    assert source.exists() and sidecar.exists()
    assert _file_identity(source) == before_source
    assert _file_identity(sidecar) == before_sidecar


@pytest.mark.parametrize("command", ["scan", "status", "report"])
@pytest.mark.parametrize("suffix", ["", "-wal", "-shm", "-journal"])
def test_commands_reject_lexical_reparse_database_identity_before_connect(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    suffix: str,
) -> None:
    database, root = _indexed_database(tmp_path)
    lexical_hop = tmp_path / "lexical-hop"
    lexical_hop.mkdir()
    requested_database = lexical_hop / ".." / database.name
    unsafe_candidate = requested_database.with_name(
        f"{requested_database.name}{suffix}"
    )
    before_database = _file_identity(database)
    source_archive = root / "book.zip"
    before_source = _file_identity(source_archive)
    real_lstat = os.lstat
    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

    def fake_lstat(path: os.PathLike[str] | str):
        if Path(path) == unsafe_candidate:
            return SimpleNamespace(
                st_mode=stat.S_IFREG,
                st_size=0,
                st_mtime_ns=0,
                st_nlink=1,
                st_file_attributes=reparse_attribute,
            )
        return real_lstat(path)

    monkeypatch.setattr(
        repository_module, "os", SimpleNamespace(lstat=fake_lstat), raising=False
    )
    connect_attempts: list[object] = []

    def reject_connect(*args: object, **kwargs: object):
        connect_attempts.append((args, kwargs))
        raise AssertionError("SQLite connect must not run for an unsafe lexical identity")

    monkeypatch.setattr(repository_module.sqlite3, "connect", reject_connect)
    output = tmp_path / "report.json"
    arguments = [command]
    if command == "scan":
        arguments.extend([str(root), "--db", str(requested_database)])
    else:
        arguments.extend(["--db", str(requested_database)])
        if command == "report":
            arguments.extend(["--format", "json", "--output", str(output)])
    capsys.readouterr()

    assert main(arguments) == 2

    captured = capsys.readouterr()
    assert "SQLite" in captured.err
    assert captured.out == ""
    assert connect_attempts == []
    assert not output.exists()
    assert _file_identity(database) == before_database
    assert _file_identity(source_archive) == before_source


@pytest.mark.parametrize("command", ["scan", "status", "report"])
def test_commands_pass_requested_lexical_database_path_to_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    database, root = _indexed_database(tmp_path)
    lexical_hop = tmp_path / "lexical-hop"
    lexical_hop.mkdir()
    requested_database = lexical_hop / ".." / database.name
    observed_paths: list[Path] = []

    def reject_open(database_path: Path):
        observed_paths.append(database_path)
        raise UnsafeDatabaseIdentity("test stop after observing lexical path")

    if command == "scan":
        monkeypatch.setattr(
            cli_module.Repository, "open", staticmethod(reject_open)
        )
        arguments = ["scan", str(root), "--db", str(requested_database)]
    else:
        monkeypatch.setattr(
            cli_module.Repository, "open_readonly", staticmethod(reject_open)
        )
        arguments = [command, "--db", str(requested_database)]
        if command == "report":
            arguments.extend(
                ["--format", "json", "--output", str(tmp_path / "report.json")]
            )

    assert main(arguments) == 2

    assert observed_paths == [requested_database]


def test_status_rejects_actual_main_database_symlink_before_connect(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, root = _indexed_database(tmp_path)
    alias = tmp_path / "index-alias.db"
    _create_file_symlink_or_skip(alias, database)
    before_database = _file_identity(database)
    before_alias = _file_identity(alias)
    before_alias_link = _lstat_identity(alias)
    before_source = _file_identity(root / "book.zip")
    connect_attempts: list[object] = []

    def reject_connect(*args: object, **kwargs: object):
        connect_attempts.append((args, kwargs))
        raise AssertionError("SQLite connect must not follow a database symlink")

    monkeypatch.setattr(repository_module.sqlite3, "connect", reject_connect)
    capsys.readouterr()

    assert main(["status", "--db", str(alias)]) == 2

    captured = capsys.readouterr()
    assert "SQLite" in captured.err
    assert captured.out == ""
    assert connect_attempts == []
    assert alias.is_symlink()
    assert _file_identity(database) == before_database
    assert _file_identity(alias) == before_alias
    assert _lstat_identity(alias) == before_alias_link
    assert _file_identity(root / "book.zip") == before_source


def test_status_rejects_actual_sidecar_symlink_before_connect(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, root = _indexed_database(tmp_path)
    source = root / "sidecar-source.bin"
    source.write_bytes(b"source bytes behind a SQLite sidecar symlink")
    sidecar = database.with_name(f"{database.name}-shm")
    if sidecar.exists():
        sidecar.unlink()
    _create_file_symlink_or_skip(sidecar, source)
    before_source = _file_identity(source)
    before_alias = _file_identity(sidecar)
    before_alias_link = _lstat_identity(sidecar)
    connect_attempts: list[object] = []

    def reject_connect(*args: object, **kwargs: object):
        connect_attempts.append((args, kwargs))
        raise AssertionError("SQLite connect must not follow a sidecar symlink")

    monkeypatch.setattr(repository_module.sqlite3, "connect", reject_connect)
    capsys.readouterr()

    assert main(["status", "--db", str(database)]) == 2

    captured = capsys.readouterr()
    assert "SQLite" in captured.err
    assert captured.out == ""
    assert connect_attempts == []
    assert sidecar.is_symlink()
    assert _file_identity(source) == before_source
    assert _file_identity(sidecar) == before_alias
    assert _lstat_identity(sidecar) == before_alias_link


def test_scan_rejects_broken_database_symlink_before_connect(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    missing_target = tmp_path / "missing-target.db"
    alias = tmp_path / "broken-index.db"
    _create_file_symlink_or_skip(alias, missing_target)
    before_alias = _lstat_identity(alias)
    connect_attempts: list[object] = []

    def reject_connect(*args: object, **kwargs: object):
        connect_attempts.append((args, kwargs))
        raise AssertionError("SQLite connect must not follow a broken database symlink")

    monkeypatch.setattr(repository_module.sqlite3, "connect", reject_connect)
    assert main(["scan", str(root), "--db", str(alias)]) == 2

    captured = capsys.readouterr()
    assert "SQLite" in captured.err
    assert captured.out == ""
    assert connect_attempts == []
    assert not missing_target.exists()
    assert alias.is_symlink()
    assert _lstat_identity(alias) == before_alias


@pytest.mark.parametrize("command", ["scan", "status", "report"])
def test_commands_reject_mocked_broken_database_symlink_before_missing_check(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    requested_database = tmp_path / "broken-index.db"
    real_lstat = os.lstat

    def fake_lstat(path: os.PathLike[str] | str):
        if Path(path) == requested_database:
            return SimpleNamespace(
                st_mode=stat.S_IFLNK,
                st_size=0,
                st_mtime_ns=0,
                st_nlink=1,
                st_file_attributes=0,
            )
        return real_lstat(path)

    monkeypatch.setattr(
        repository_module, "os", SimpleNamespace(lstat=fake_lstat), raising=False
    )
    connect_attempts: list[object] = []

    def reject_connect(*args: object, **kwargs: object):
        connect_attempts.append((args, kwargs))
        raise AssertionError("SQLite connect must not follow a broken database symlink")

    monkeypatch.setattr(repository_module.sqlite3, "connect", reject_connect)
    output = tmp_path / "report.json"
    arguments = [command]
    if command == "scan":
        arguments.extend([str(root), "--db", str(requested_database)])
    else:
        arguments.extend(["--db", str(requested_database)])
        if command == "report":
            arguments.extend(["--format", "json", "--output", str(output)])

    assert main(arguments) == 2

    captured = capsys.readouterr()
    assert "SQLite" in captured.err
    assert captured.out == ""
    assert connect_attempts == []
    assert not requested_database.exists()
    assert not output.exists()


def test_status_rejects_non_regular_sidecar_before_connect(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _ = _indexed_database(tmp_path)
    sidecar = database.with_name(f"{database.name}-journal")
    sidecar.mkdir()
    before_sidecar = _lstat_identity(sidecar)
    connect_attempts: list[object] = []

    def reject_connect(*args: object, **kwargs: object):
        connect_attempts.append((args, kwargs))
        raise AssertionError("SQLite connect must not receive a non-regular sidecar")

    monkeypatch.setattr(repository_module.sqlite3, "connect", reject_connect)
    capsys.readouterr()

    assert main(["status", "--db", str(database)]) == 2

    captured = capsys.readouterr()
    assert "SQLite" in captured.err
    assert captured.out == ""
    assert connect_attempts == []
    assert sidecar.is_dir()
    assert _lstat_identity(sidecar) == before_sidecar


def test_status_rejects_relative_current_directory_as_non_regular_main_database(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    connect_attempts: list[object] = []

    def reject_connect(*args: object, **kwargs: object):
        connect_attempts.append((args, kwargs))
        raise AssertionError("SQLite connect must not receive a directory as its main DB")

    monkeypatch.setattr(repository_module.sqlite3, "connect", reject_connect)

    assert main(["status", "--db", "."]) == 2

    captured = capsys.readouterr()
    assert "SQLite" in captured.err
    assert captured.out == ""
    assert connect_attempts == []


def test_scan_does_not_run_without_explicit_root(capsys) -> None:
    exit_code = main(["scan"])

    assert exit_code == 2
    assert "ROOT" in capsys.readouterr().err


def test_scan_rejects_worker_count_outside_supported_range(tmp_path: Path, capsys) -> None:
    root = tmp_path / "source"
    root.mkdir()

    exit_code = main(["scan", str(root), "--db", str(tmp_path / "index.db"), "--workers", "9"])

    assert exit_code == 2
    assert "1..8" in capsys.readouterr().err


def test_status_prints_the_latest_scan_summary(tmp_path: Path, capsys) -> None:
    database, _ = _indexed_database(tmp_path)

    assert main(["status", "--db", str(database)]) == 0

    output = capsys.readouterr().out
    assert "discovered=1" in output
    assert "indexed=1" in output


def test_json_report_has_stable_error_codes(tmp_path: Path) -> None:
    database, _ = _indexed_database(tmp_path)
    output = tmp_path / "report.json"

    assert main(["report", "--db", str(database), "--format", "json", "--output", str(output)]) == 0

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["summary"]["failed"] >= 0
    assert all("state" in item for item in payload["archives"])


def test_report_rejects_output_inside_any_stored_scan_root(tmp_path: Path, capsys) -> None:
    database, root = _indexed_database(tmp_path)
    output = root / "report.json"

    assert main(["report", "--db", str(database), "--format", "json", "--output", str(output)]) == 2

    assert "스캔 루트 밖" in capsys.readouterr().err


def test_report_rejects_database_as_output(tmp_path: Path, capsys) -> None:
    database, _ = _indexed_database(tmp_path)

    assert main(["report", "--db", str(database), "--format", "csv", "--output", str(database)]) == 2

    assert "DB 파일과 같을 수 없습니다" in capsys.readouterr().err


def test_report_rejects_hard_link_to_database_before_writing(tmp_path: Path, capsys) -> None:
    database, _ = _indexed_database(tmp_path)
    output = tmp_path / "database-alias.json"
    try:
        os.link(database, output)
    except OSError as error:
        pytest.skip(f"hard links are unavailable: {error}")
    original_bytes = database.read_bytes()

    assert main(["report", "--db", str(database), "--format", "json", "--output", str(output)]) == 2

    assert "DB 파일과 같을 수 없습니다" in capsys.readouterr().err
    assert database.read_bytes() == original_bytes


def test_report_checks_every_stored_scan_root(tmp_path: Path, capsys) -> None:
    database, _ = _indexed_database(tmp_path)
    second_root = tmp_path / "second-source"
    second_root.mkdir()
    repository = Repository.open(database)
    try:
        now = datetime.now(UTC)
        repository.acquire_scan_lock("test-root-writer", now)
        repository.get_or_create_root(
            second_root,
            normalize_path_key(second_root),
            owner_token="test-root-writer",
            now=now,
        )
        repository.release_scan_lock("test-root-writer")
    finally:
        repository.close()

    output = second_root / "report.json"
    assert main(["report", "--db", str(database), "--format", "json", "--output", str(output)]) == 2

    assert "스캔 루트 밖" in capsys.readouterr().err


def test_cli_does_not_leave_connection_locked_after_read_commands(tmp_path: Path) -> None:
    database, _ = _indexed_database(tmp_path)
    output = tmp_path / "report.json"

    assert main(["status", "--db", str(database)]) == 0
    assert main(["report", "--db", str(database), "--format", "json", "--output", str(output)]) == 0

    connection = sqlite3.connect(database)
    try:
        connection.execute("BEGIN EXCLUSIVE")
    finally:
        connection.close()


def test_database_open_failure_uses_a_stable_message_without_traceback(
    tmp_path: Path, capsys
) -> None:
    invalid_database = tmp_path / "invalid.db"
    invalid_database.write_bytes(b"not a sqlite database")

    assert main(["status", "--db", str(invalid_database)]) == 1

    error = capsys.readouterr().err
    assert error == "DB를 열거나 저장할 수 없습니다.\n"
    assert "Traceback" not in error


def test_read_commands_do_not_create_a_missing_database(tmp_path: Path, capsys) -> None:
    database = tmp_path / "missing.db"

    assert main(["status", "--db", str(database)]) == 1
    assert not database.exists()
    assert capsys.readouterr().err == "DB 파일을 찾을 수 없습니다.\n"

    assert (
        main(
            [
                "report",
                "--db",
                str(database),
                "--format",
                "json",
                "--output",
                str(tmp_path / "report.json"),
            ]
        )
        == 1
    )
    assert not database.exists()
    assert capsys.readouterr().err == "DB 파일을 찾을 수 없습니다.\n"


def test_read_commands_do_not_modify_main_database_or_source_archive(tmp_path: Path) -> None:
    database, root = _indexed_database(tmp_path)
    output = tmp_path / "report.json"
    before = database.stat()
    original_bytes = database.read_bytes()
    source_archive = root / "book.zip"
    source_bytes = source_archive.read_bytes()
    source_mtime_ns = source_archive.stat().st_mtime_ns

    assert main(["status", "--db", str(database)]) == 0
    assert main(["report", "--db", str(database), "--format", "json", "--output", str(output)]) == 0

    after = database.stat()
    assert database.read_bytes() == original_bytes
    assert after.st_mtime_ns == before.st_mtime_ns
    assert source_archive.read_bytes() == source_bytes
    assert source_archive.stat().st_mtime_ns == source_mtime_ns


def test_readonly_commands_reject_blank_and_old_schema_databases_without_writes(
    tmp_path: Path, capsys
) -> None:
    blank_database = tmp_path / "blank.db"
    blank_database.write_bytes(b"")
    old_database = tmp_path / "old.db"
    connection = sqlite3.connect(old_database)
    try:
        connection.execute("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY)")
        connection.execute("INSERT INTO schema_migrations(version) VALUES (0)")
        connection.commit()
    finally:
        connection.close()

    for database in (blank_database, old_database):
        before = database.stat()
        original_bytes = database.read_bytes()
        assert main(["status", "--db", str(database)]) == 1

        assert capsys.readouterr().err == "DB를 열거나 저장할 수 없습니다.\n"
        assert database.read_bytes() == original_bytes
        assert database.stat().st_mtime_ns == before.st_mtime_ns


def test_readonly_repository_opens_while_writer_scan_lock_is_active(tmp_path: Path) -> None:
    database, _ = _indexed_database(tmp_path)
    writer = Repository.open(database)
    try:
        writer.acquire_scan_lock("writer", datetime.now(UTC))
        reader = Repository.open_readonly(database)
        try:
            assert reader.schema_version() == LATEST_SCHEMA_VERSION
            assert reader.latest_summary() is not None
        finally:
            reader.close()
    finally:
        writer.release_scan_lock("writer")
        writer.close()


def test_readonly_commands_see_newly_committed_live_wal_data(
    tmp_path: Path, capsys
) -> None:
    database, _ = _indexed_database(tmp_path)
    live_root = tmp_path / "live-root"
    live_root.mkdir()
    live_archive = live_root / "live.zip"
    live_archive.write_bytes(b"live")
    writer = Repository.open(database)
    try:
        now = datetime.now(UTC)
        writer.acquire_scan_lock("live-writer", now)
        root_id = writer.get_or_create_root(
            live_root,
            normalize_path_key(live_root),
            owner_token="live-writer",
            now=now,
        )
        run_id = writer.start_run(root_id, now, owner_token="live-writer")
        writer.enqueue_or_reuse(
            run_id,
            root_id,
            snapshot(live_archive, ArchiveFormat.ZIP),
            owner_token="live-writer",
            now=now,
        )
        wal_path = database.with_name(f"{database.name}-wal")
        assert wal_path.is_file() and wal_path.stat().st_size > 0

        reader = Repository.open_readonly(database)
        try:
            assert reader.latest_summary() is not None
            assert reader.latest_summary().run_id == run_id
            assert live_root in set(reader.scan_roots())
            assert live_archive in {row.path for row in reader.report_rows()}
        finally:
            reader.close()

        assert main(["status", "--db", str(database)]) == 0
        assert f"run={run_id}" in capsys.readouterr().out
        output = tmp_path / "live-report.json"
        assert main(["report", "--db", str(database), "--format", "json", "--output", str(output)]) == 0
        payload = json.loads(output.read_text(encoding="utf-8"))
        assert str(live_archive) in {item["path"] for item in payload["archives"]}
    finally:
        writer.release_scan_lock("live-writer")
        writer.close()


def test_readonly_repository_keeps_one_snapshot_across_writer_checkpoint(tmp_path: Path) -> None:
    database, initial_root = _indexed_database(tmp_path)
    reader = Repository.open_readonly(database)
    try:
        initial_summary = reader.latest_summary()
        assert initial_summary is not None
        assert set(reader.scan_roots()) == {initial_root}

        new_root = tmp_path / "checkpoint-root"
        new_root.mkdir()
        new_archive = new_root / "checkpoint.zip"
        new_archive.write_bytes(b"checkpoint")
        writer = Repository.open(database)
        try:
            now = datetime.now(UTC)
            writer.acquire_scan_lock("checkpoint-writer", now)
            root_id = writer.get_or_create_root(
                new_root,
                normalize_path_key(new_root),
                owner_token="checkpoint-writer",
                now=now,
            )
            run_id = writer.start_run(
                root_id, now, owner_token="checkpoint-writer"
            )
            writer.enqueue_or_reuse(
                run_id,
                root_id,
                snapshot(new_archive, ArchiveFormat.ZIP),
                owner_token="checkpoint-writer",
                now=now,
            )
            writer.release_scan_lock("checkpoint-writer")
        finally:
            writer.close()

        checkpoint = sqlite3.connect(database)
        try:
            checkpoint.execute("PRAGMA busy_timeout = 0")
            checkpoint.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        finally:
            checkpoint.close()

        assert set(reader.scan_roots()) == {initial_root}
        assert new_archive not in {row.path for row in reader.report_rows()}
        assert reader.latest_summary() == initial_summary
    finally:
        reader.close()


def test_cli_report_uses_same_snapshot_for_root_check_and_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _ = _indexed_database(tmp_path)
    new_root = tmp_path / "late-root"
    new_root.mkdir()
    new_archive = new_root / "late.zip"
    new_archive.write_bytes(b"late")
    output = new_root / "report.json"
    real_write_report = cli_module.write_report

    def commit_then_write(repository: Repository, report_output: Path, report_format: str) -> None:
        writer = Repository.open(database)
        try:
            now = datetime.now(UTC)
            writer.acquire_scan_lock("late-writer", now)
            root_id = writer.get_or_create_root(
                new_root,
                normalize_path_key(new_root),
                owner_token="late-writer",
                now=now,
            )
            run_id = writer.start_run(root_id, now, owner_token="late-writer")
            writer.enqueue_or_reuse(
                run_id,
                root_id,
                snapshot(new_archive, ArchiveFormat.ZIP),
                owner_token="late-writer",
                now=now,
            )
            writer.release_scan_lock("late-writer")
        finally:
            writer.close()
        checkpoint = sqlite3.connect(database)
        try:
            checkpoint.execute("PRAGMA busy_timeout = 0")
            checkpoint.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        finally:
            checkpoint.close()
        real_write_report(repository, report_output, report_format)

    monkeypatch.setattr(cli_module, "write_report", commit_then_write)

    assert main(["report", "--db", str(database), "--format", "json", "--output", str(output)]) == 0

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert str(new_archive) not in {item["path"] for item in payload["archives"]}


def test_scan_rejects_lexical_reparse_root_before_resolution(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    monkeypatch.setattr(
        cli_module,
        "has_reparse_point_in_existing_chain",
        lambda _: True,
        raising=False,
    )

    assert main(["scan", str(root), "--db", str(tmp_path / "index.db")]) == 2

    assert "reparse" in capsys.readouterr().err.casefold()


def test_scan_rejects_actual_symlink_in_root_ancestor_chain(tmp_path: Path, capsys) -> None:
    target = tmp_path / "target"
    nested = target / "nested"
    nested.mkdir(parents=True)
    link = tmp_path / "linked-parent"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks are unavailable: {error}")

    assert main(["scan", str(link / "nested"), "--db", str(tmp_path / "index.db")]) == 2

    assert "reparse" in capsys.readouterr().err.casefold()
