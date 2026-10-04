"""Opt-in test for the onefile executable built by tools/build_windows_exe.ps1.

The default suite deselects ``packaged`` tests. A selected run requires
``ARCHIVE_ANALYZER_PACKAGED_EXE`` and fails, rather than skips, if it is absent.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import json
from pathlib import Path

import pytest

from archive_analyzer.duplicate_domain import DuplicateRelation
from archive_analyzer.recommendation_service import refresh_recommendations
from archive_analyzer.storage.duplicate_repository import DuplicateRepository
from archive_analyzer.paths import normalize_path_key
from tests.image_helpers import tree_fingerprint
from tests.v1_fixture import create_v1_archive_fixture


@pytest.mark.packaged
def test_packaged_v1_analyzes_korean_fixture_without_mutating_sources(
    tmp_path: Path,
) -> None:
    configured = os.environ.get("ARCHIVE_ANALYZER_PACKAGED_EXE")
    assert configured, (
        "ARCHIVE_ANALYZER_PACKAGED_EXE must name the freshly built executable"
    )
    executable = Path(configured)
    assert executable.is_file(), f"Packaged executable does not exist: {executable}"
    source = create_v1_archive_fixture(tmp_path)
    before = tree_fingerprint(source)
    data_root = tmp_path / "한국어 패키지 데이터"

    completed = subprocess.run(
        [
            str(executable),
            "--headless-source",
            str(source),
            "--data-root",
            str(data_root),
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    assert completed.returncode == 0
    databases = tuple((data_root / "databases").glob("*.db"))
    assert len(databases) == 1
    connection = sqlite3.connect(f"{databases[0].as_uri()}?mode=ro", uri=True)
    try:
        assert connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall() == [(1,), (2,), (3,), (4,), (5,), (6,), (7,), (8,), (9,)]
        assert connection.execute(
            "SELECT COUNT(*) FROM archives WHERE state = 'INDEXED'"
        ).fetchone() == (6,)
        assert connection.execute(
            "SELECT status, failed_count FROM duplicate_analysis_runs ORDER BY id DESC LIMIT 1"
        ).fetchone() == ("COMPLETED", 0)
        assert connection.execute("SELECT COUNT(*) FROM candidate_groups").fetchone() == (
            2,
        )
        relation_counts = dict(
            connection.execute(
                "SELECT relation, COUNT(*) FROM candidate_relations GROUP BY relation"
            )
        )
        assert relation_counts.get("EXACT_CONTENT", 0) >= 1
        assert relation_counts.get("VISUAL_VARIANT", 0) >= 1
        assert connection.execute(
            "SELECT COUNT(*) FROM image_fingerprints WHERE state = 'SUCCEEDED'"
        ).fetchone() == (18,)
    finally:
        connection.close()
    assert tree_fingerprint(source) == before

    # Refresh recommendations in the fresh result and select one exact,
    # multi-page set for the precision acceptance path.  This is DB-only.
    repository = DuplicateRepository.open(databases[0])
    try:
        root_id = repository.root_id_for_path_key(normalize_path_key(source))
        assert root_id is not None
        refresh_recommendations(repository, root_id)
        chosen = None
        for candidate in repository.review_candidate_sets(root_id):
            if len(candidate.archive_ids) < 2:
                continue
            detail = repository.review_group_details(candidate.set_key)
            if detail is None or not all(
                member.image_count is not None and member.image_count >= 2
                for member in detail.members
            ):
                continue
            if any(
                relation.relation is DuplicateRelation.EXACT_CONTENT
                for relation in detail.relations
            ):
                chosen = candidate
                break
        if chosen is None:
            pytest.fail("fixture did not produce an exact multi-page candidate set")
        set_key = chosen.set_key
    finally:
        repository.close()

    # Exercise the frozen saved-result path with a copied schema-7 database.
    # Only this temporary copy is downgraded; the freshly produced result and
    # every archive in the fixture remain untouched.  SQLite backup keeps WAL
    # contents in the copied DB instead of copying only the main file.
    legacy = tmp_path / "copied-schema-7.db"
    source_connection = sqlite3.connect(databases[0])
    legacy_connection = sqlite3.connect(legacy)
    try:
        source_connection.backup(legacy_connection)
        for table in (
            "review_reset_actions",
            "precision_page_cache",
            "edition_candidate_generations",
            "filename_evidence",
        ):
            legacy_connection.execute(f"DROP TABLE IF EXISTS {table}")
        legacy_connection.execute("DELETE FROM schema_migrations WHERE version >= 8")
        legacy_connection.commit()
    finally:
        source_connection.close()
        legacy_connection.close()

    smoke = subprocess.run(
        [str(executable), "--packaged-smoke", str(legacy)],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert smoke.returncode == 0, smoke.stdout.decode(errors="replace")
    migrated = sqlite3.connect(f"{legacy.as_uri()}?mode=ro", uri=True)
    try:
        assert migrated.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone() == (9,)
    finally:
        migrated.close()

    review = subprocess.run(
        [str(executable), "--packaged-review-smoke", str(legacy), set_key],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=300,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert review.returncode == 0, (
        review.stdout.decode(errors="replace")
        + review.stderr.decode(errors="replace")
    )
    smoke_report = legacy.with_name(legacy.name + ".review-smoke.json")
    assert smoke_report.is_file()
    summary = json.loads(smoke_report.read_text(encoding="utf-8"))
    assert summary["schema"] == 9
    assert summary["candidate_set"] == set_key
    assert summary["selected_archives"] == 2
    assert summary["cancelled"] is True
    assert summary["stored_pages_before_cancel"] >= 1
    assert summary["resume_archive_reads"] >= 1
    assert summary["resume_cache_hits"] >= 1
    assert summary["warm_archive_reads"] == 0
    assert summary["outside_scope_reads"] == 0
    assert summary["page_cache_rows"] >= 1
    assert summary["precision_profile_rows"] == 2

    checked = sqlite3.connect(f"{legacy.as_uri()}?mode=ro", uri=True)
    try:
        assert checked.execute(
            "SELECT COUNT(*) FROM filename_evidence"
        ).fetchone()[0] >= 6
        assert checked.execute(
            "SELECT COUNT(*) FROM precision_profiles"
        ).fetchone() == (2,)
    finally:
        checked.close()
    assert tree_fingerprint(source) == before

    ui = subprocess.run([str(executable), "--packaged-ui-smoke", str(databases[0]), str(source)],
        capture_output=True, timeout=90, creationflags=subprocess.CREATE_NO_WINDOW)
    assert ui.returncode == 0, ui.stdout.decode(errors="replace") + ui.stderr.decode(errors="replace")
    ui_report = json.loads(databases[0].with_suffix(".ui-smoke.json").read_text(encoding="utf-8"))
    assert ui_report["success"] and ui_report["recycle_com"]
    assert ui_report["groups"] == 600 and ui_report["preview_height"] >= 140
    assert ui_report["scan_progress"]["probe_pages"]
    assert 0 < ui_report["scan_progress"]["candidate_fraction"] < 100
    assert tree_fingerprint(source) == before
