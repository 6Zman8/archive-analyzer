import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import archive_analyzer.storage.repository as repository_module
from archive_analyzer.storage.repository import (
    LATEST_SCHEMA_VERSION,
    Repository,
    UnsafeDatabaseIdentity,
)


def test_open_new_database_applies_schema(tmp_path: Path) -> None:
    repository = Repository.open(tmp_path / "index.db")
    try:
        assert repository.schema_version() == LATEST_SCHEMA_VERSION
        names = repository.table_names()
        assert {
            "schema_migrations",
            "scan_roots",
            "scan_runs",
            "archives",
            "archive_entries",
            "analysis_jobs",
            "scan_errors",
            "scan_locks",
        } <= names
        job_columns = {
            str(row[1])
            for row in repository._connection.execute(  # noqa: SLF001 - inspect schema
                "PRAGMA table_info(analysis_jobs)"
            )
        }
        assert "claim_token" in job_columns
    finally:
        repository.close()

    reopened = Repository.open(tmp_path / "index.db")
    try:
        assert reopened.schema_version() == LATEST_SCHEMA_VERSION
    finally:
        reopened.close()


def test_v1_migration_adds_duplicate_analysis_tables(tmp_path: Path) -> None:
    repository = Repository.open(tmp_path / "index.db")
    try:
        assert repository.schema_version() == LATEST_SCHEMA_VERSION
        assert {
            "duplicate_analysis_runs",
            "duplicate_analysis_jobs",
            "archive_fingerprints",
            "image_fingerprints",
            "candidate_relations",
            "candidate_groups",
            "candidate_group_members",
            "review_actions",
        } <= repository.table_names()
        assert "idx_review_actions_archive_id" in {
            str(row[1])
            for row in repository._connection.execute(  # noqa: SLF001 - inspect migration index
                "PRAGMA index_list(review_actions)"
            )
        }
    finally:
        repository.close()


def test_v2_v5_migration_adds_enrichment_and_quarantine_tables(
    tmp_path: Path,
) -> None:
    repository = Repository.open(tmp_path / "index.db")
    try:
        assert repository.schema_version() == LATEST_SCHEMA_VERSION
        assert {
            "sequence_relations",
            "edition_profiles",
            "edition_relations",
            "quarantine_items",
        } <= repository.table_names()
    finally:
        repository.close()


def test_final_deletion_migration_adds_append_only_deletion_records(
    tmp_path: Path,
) -> None:
    repository = Repository.open(tmp_path / "index.db")
    try:
        assert repository.schema_version() == LATEST_SCHEMA_VERSION
        assert "deletion_records" in repository.table_names()
        columns = {
            str(row[1])
            for row in repository._connection.execute(  # noqa: SLF001
                "PRAGMA table_info(deletion_records)"
            )
        }
        assert {"quarantine_item_id", "state", "sha256", "deleted_at"} <= columns
    finally:
        repository.close()


def test_recommendation_migration_adds_derived_tables_without_losing_history(
    tmp_path: Path,
) -> None:
    repository = Repository.open(tmp_path / "index.db")
    try:
        assert repository.schema_version() == LATEST_SCHEMA_VERSION
        assert {
            "precision_profiles",
            "precision_relations",
            "edition_candidate_sets",
            "recommendation_runs",
            "recommendation_items",
            "recommendation_applications",
        } <= repository.table_names()
    finally:
        repository.close()


def test_v7_database_upgrade_adds_filename_tables_without_losing_history(
    tmp_path: Path,
) -> None:
    database = tmp_path / "index.db"
    migrations = Path(repository_module.__file__).with_name("migrations")
    connection = sqlite3.connect(database)
    try:
        for version in range(1, 8):
            connection.executescript(
                (migrations / f"{version:03}.sql").read_text(encoding="utf-8")
            )
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, "2026-09-03T12:00:00+00:00"),
            )
        root_id = connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(tmp_path), "root-key", "2026-09-03T12:00:00+00:00"),
        ).lastrowid
        archive_id = connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
            "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, 'book-key', 42, 7, 'CBZ', 'INDEXED', ?, ?, 1)",
            (
                root_id,
                str(tmp_path / "book.cbz"),
                "2026-09-03T12:00:00+00:00",
                "2026-09-03T12:00:00+00:00",
            ),
        ).lastrowid
        review_id = connection.execute(
            "INSERT INTO review_actions(group_key, archive_id, action, file_size, mtime_ns, created_at) "
            "VALUES ('group-key', ?, 'KEEP', 42, 7, ?)",
            (archive_id, "2026-09-03T12:00:00+00:00"),
        ).lastrowid
        quarantine_id = connection.execute(
            "INSERT INTO quarantine_items(scan_root_id, archive_id, group_key, source_path, "
            "destination_path, file_size, mtime_ns, sha256, status, created_at, updated_at) "
            "VALUES (?, ?, 'group-key', 'source', 'destination', 42, 7, ?, 'QUARANTINED', ?, ?)",
            (root_id, archive_id, "a" * 64, "2026-09-03T12:00:00+00:00", "2026-09-03T12:00:00+00:00"),
        ).lastrowid
        connection.execute(
            "INSERT INTO deletion_records(quarantine_item_id, scan_root_id, archive_id, path, "
            "file_size, mtime_ns, sha256, state, created_at, updated_at, deleted_at) "
            "VALUES (?, ?, ?, 'source', 42, 7, ?, 'DELETED', ?, ?, ?)",
            (
                quarantine_id,
                root_id,
                archive_id,
                "a" * 64,
                "2026-09-03T12:00:00+00:00",
                "2026-09-03T12:00:00+00:00",
                "2026-09-03T12:01:00+00:00",
            ),
        )
        connection.commit()
    finally:
        connection.close()

    repository = Repository.open(database)
    try:
        assert repository.schema_version() == 9
        assert {
            "filename_evidence",
            "edition_candidate_generations",
            "precision_page_cache",
        } <= repository.table_names()
        assert repository._connection.execute(  # noqa: SLF001 - migration retention
            "SELECT id, action FROM review_actions"
        ).fetchall() == [(review_id, "KEEP")]
        assert repository._connection.execute(  # noqa: SLF001 - migration retention
            "SELECT id, status FROM quarantine_items"
        ).fetchall() == [(quarantine_id, "QUARANTINED")]
        assert repository._connection.execute(  # noqa: SLF001 - migration retention
            "SELECT quarantine_item_id, state FROM deletion_records"
        ).fetchall() == [(quarantine_id, "DELETED")]
    finally:
        repository.close()


def test_v6_database_upgrades_then_opens_readonly_at_v8(tmp_path: Path) -> None:
    database = tmp_path / "index.db"
    migrations = Path(repository_module.__file__).with_name("migrations")
    connection = sqlite3.connect(database)
    try:
        for version in range(1, 7):
            connection.executescript((migrations / f"{version:03}.sql").read_text(encoding="utf-8"))
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, "2026-09-02T12:00:00+00:00"),
            )
        connection.commit()
    finally:
        connection.close()

    writable = Repository.open(database)
    try:
        assert writable.schema_version() == 9
    finally:
        writable.close()

    readonly = Repository.open_readonly(database)
    try:
        assert readonly.schema_version() == 9
    finally:
        readonly.close()


def test_open_upgrades_001_database_without_losing_indexed_entries(tmp_path: Path) -> None:
    database = tmp_path / "index.db"
    connection = sqlite3.connect(database)
    try:
        migration = (
            Path(repository_module.__file__).with_name("migrations") / "001.sql"
        )
        connection.executescript(migration.read_text(encoding="utf-8"))
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?)",
            ("2026-08-28T12:00:00+00:00",),
        )
        root_id = connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(tmp_path), "root-key", "2026-08-28T12:00:00+00:00"),
        ).lastrowid
        archive_id = connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
            "archive_format, entry_count, image_count, content_listing_signature, state, "
            "first_seen_at, last_seen_at, indexed_at, inspector_version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'INDEXED', ?, ?, ?, 1)",
            (
                root_id,
                str(tmp_path / "book.cbz"),
                "book-key",
                42,
                7,
                "CBZ",
                1,
                1,
                "listing-signature",
                "2026-08-28T12:00:00+00:00",
                "2026-08-28T12:00:00+00:00",
                "2026-08-28T12:00:00+00:00",
            ),
        ).lastrowid
        connection.execute(
            "INSERT INTO archive_entries(archive_id, position, path, normalized_path, sort_key, "
            "uncompressed_size, compressed_size, crc, entry_kind, image_format_hint) "
            "VALUES (?, 0, 'cover.jpg', 'cover.jpg', 'cover.jpg', 12, 10, 'abc', 'IMAGE', 'JPEG')",
            (archive_id,),
        )
        connection.commit()
    finally:
        connection.close()

    repository = Repository.open(database)
    try:
        assert repository.schema_version() == LATEST_SCHEMA_VERSION
        assert repository._connection.execute(  # noqa: SLF001 - verify V0 retention
            "SELECT path, file_size, mtime_ns, archive_format, state FROM archives"
        ).fetchall() == [(str(tmp_path / "book.cbz"), 42, 7, "CBZ", "INDEXED")]
        assert repository._connection.execute(  # noqa: SLF001 - verify V0 retention
            "SELECT position, path, uncompressed_size, crc, entry_kind FROM archive_entries"
        ).fetchall() == [(0, "cover.jpg", 12, "abc", "IMAGE")]
        assert {"duplicate_analysis_runs", "review_actions"} <= repository.table_names()
    finally:
        repository.close()


def test_open_upgrades_002_database_without_losing_review_history(tmp_path: Path) -> None:
    database = tmp_path / "index.db"
    connection = sqlite3.connect(database)
    try:
        migrations = Path(repository_module.__file__).with_name("migrations")
        connection.executescript((migrations / "001.sql").read_text(encoding="utf-8"))
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?)",
            ("2026-08-28T12:00:00+00:00",),
        )
        connection.executescript((migrations / "002.sql").read_text(encoding="utf-8"))
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (2, ?)",
            ("2026-08-28T12:00:00+00:00",),
        )
        root_id = connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(tmp_path), "root-key", "2026-08-28T12:00:00+00:00"),
        ).lastrowid
        archive_id = connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, archive_format, "
            "state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, 'book-key', 42, 7, 'CBZ', 'INDEXED', ?, ?, 1)",
            (
                root_id,
                str(tmp_path / "book.cbz"),
                "2026-08-28T12:00:00+00:00",
                "2026-08-28T12:00:00+00:00",
            ),
        ).lastrowid
        connection.execute(
            "INSERT INTO review_actions(group_key, archive_id, action, file_size, mtime_ns, created_at) "
            "VALUES ('group-key', ?, 'KEEP', 42, 7, ?)",
            (archive_id, "2026-08-28T12:00:00+00:00"),
        )
        connection.commit()
    finally:
        connection.close()

    repository = Repository.open(database)
    try:
        assert repository.schema_version() == LATEST_SCHEMA_VERSION
        assert repository._connection.execute(  # noqa: SLF001 - append-only history retention
            "SELECT group_key, archive_id, action, file_size, mtime_ns FROM review_actions"
        ).fetchall() == [("group-key", archive_id, "KEEP", 42, 7)]
        assert "idx_review_actions_archive_id" in {
            str(row[1])
            for row in repository._connection.execute(  # noqa: SLF001 - migration result
                "PRAGMA index_list(review_actions)"
            )
        }
    finally:
        repository.close()


@pytest.mark.parametrize("readonly", [False, True])
def test_repository_rechecks_canonical_sidecars_after_resolve_before_connect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, readonly: bool
) -> None:
    database = tmp_path / "index.db"
    repository = Repository.open(database)
    repository.close()
    lexical_hop = tmp_path / "lexical-hop"
    lexical_hop.mkdir()
    requested_database = lexical_hop / ".." / database.name
    canonical_sidecar = database.with_name(f"{database.name}-wal")
    real_lstat = os.lstat
    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

    def fake_lstat(path: os.PathLike[str] | str):
        if Path(path) == canonical_sidecar:
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
        raise AssertionError("connect must follow canonical identity validation")

    monkeypatch.setattr(repository_module.sqlite3, "connect", reject_connect)

    with pytest.raises(UnsafeDatabaseIdentity):
        if readonly:
            Repository.open_readonly(requested_database)
        else:
            Repository.open(requested_database)

    assert connect_attempts == []


def test_wheel_install_applies_packaged_migration(tmp_path: Path) -> None:
    project_root = Path(__file__).parents[2]
    project_copy = tmp_path / "project"
    shutil.copytree(
        project_root,
        project_copy,
        ignore=shutil.ignore_patterns(
            ".git", ".venv", ".pytest_cache", "__pycache__", "*.egg-info", "build", "dist", "work", "releases"
        ),
    )
    wheel_dir = tmp_path / "wheel"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheel_dir),
            str(project_copy),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    wheel_path = next(wheel_dir.glob("archive_analyzer-*.whl"))

    with zipfile.ZipFile(wheel_path) as wheel:
        assert "archive_analyzer/storage/migrations/001.sql" in wheel.namelist()
        assert "archive_analyzer/storage/migrations/002.sql" in wheel.namelist()
        assert "archive_analyzer/storage/migrations/003.sql" in wheel.namelist()
        assert "archive_analyzer/storage/migrations/004.sql" in wheel.namelist()
        assert "archive_analyzer/storage/migrations/005.sql" in wheel.namelist()
        assert "archive_analyzer/storage/migrations/006.sql" in wheel.namelist()
        assert "archive_analyzer/storage/migrations/007.sql" in wheel.namelist()
        assert "archive_analyzer/storage/migrations/008.sql" in wheel.namelist()

    install_dir = tmp_path / "installed"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--target",
            str(install_dir),
            str(wheel_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import sys; "
                f"sys.path.insert(0, {str(install_dir)!r}); "
                "from pathlib import Path; "
                "from archive_analyzer.storage.repository import Repository; "
                "repository = Repository.open(Path('installed.db')); "
                "assert repository.schema_version() == 9; "
                "repository.close()"
            ),
        ],
        check=True,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
