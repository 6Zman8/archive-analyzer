from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from threading import Event

from archive_analyzer.batch_review import (
    apply_recommendations,
    batch_delete_quarantined,
    batch_quarantine,
    preview_batch_action,
    preview_recommendation_application,
)
from archive_analyzer.domain import ArchiveFormat, FileSnapshot
from archive_analyzer.duplicate_domain import ReviewAction
from archive_analyzer.paths import normalize_path_key
from archive_analyzer.storage.duplicate_repository import (
    DuplicateRepository,
    RecommendationRecord,
    ReviewCandidateSet,
)


NOW = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)


def _fixture(tmp_path: Path) -> tuple[DuplicateRepository, int, ReviewCandidateSet]:
    repository = DuplicateRepository.open(tmp_path / "index.db")
    connection = repository._connection  # noqa: SLF001 - compact fixture setup
    root_id = connection.execute(
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
        (str(tmp_path), "batch-root", NOW.isoformat()),
    ).lastrowid
    group_id = connection.execute(
        "INSERT INTO candidate_groups(scan_root_id, group_key, strongest_relation, confidence, analyzer_version, created_at) "
        "VALUES (?, 'group-a', 'EXACT_CONTENT', 1.0, 1, ?)",
        (root_id, NOW.isoformat()),
    ).lastrowid
    members = []
    for archive_id in (1, 2):
        path = tmp_path / f"{archive_id}.cbz"
        path.write_bytes(f"archive-{archive_id}".encode())
        snapshot = path.stat()
        connection.execute(
            "INSERT INTO archives(id, scan_root_id, path, path_key, file_size, mtime_ns, archive_format, image_count, state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, ?, ?, ?, ?, 'CBZ', 3, 'INDEXED', ?, ?, 1)",
            (archive_id, root_id, str(path), normalize_path_key(path), snapshot.st_size, snapshot.st_mtime_ns, NOW.isoformat(), NOW.isoformat()),
        )
        connection.execute(
            "INSERT INTO candidate_group_members(group_id, archive_id) VALUES (?, ?)",
            (group_id, archive_id),
        )
        members.append(snapshot)
    candidate = ReviewCandidateSet("set-a", "group-a", "FULL_COLOR", (1, 2))
    connection.execute(
        "INSERT INTO edition_candidate_sets(set_key, scan_root_id, source_group_key, edition_kind, member_ids_json, input_fingerprint, algorithm_version, computed_at) "
        "VALUES (?, ?, ?, ?, ?, 'batch-fixture', 1, ?)",
        (candidate.set_key, root_id, candidate.source_group_key, candidate.edition_kind, json.dumps(candidate.archive_ids), NOW.isoformat()),
    )
    connection.commit()
    run_id = repository.begin_recommendation_run(root_id, 1, NOW)
    for archive_id, snapshot, recommendation in (
        (1, members[0], "KEEP"),
        (2, members[1], "REMOVE_CANDIDATE"),
    ):
        repository.replace_recommendation_items(
            run_id,
            candidate,
            RecommendationRecord(
                0, candidate.set_key, candidate.source_group_key, archive_id,
                recommendation, "RECOMMENDED", {"fixture": "true"}, "fixture",
                snapshot.st_size, snapshot.st_mtime_ns,
            ),
        )
    repository.finish_recommendation_run(run_id, state="COMPLETED", completed_at=NOW)
    return repository, int(root_id), candidate


def test_preview_counts_recommendations_and_user_skips(tmp_path: Path) -> None:
    repository, _root_id, candidate = _fixture(tmp_path)
    try:
        preview = preview_recommendation_application(repository, (candidate.set_key,))
        assert (preview.keep, preview.remove, preview.no_recommendation) == (1, 1, 0)
        member = repository.group_details(candidate.source_group_key).members[1]  # type: ignore[union-attr]
        repository.append_review_action(
            candidate.source_group_key,
            member.archive_id,
            ReviewAction.HOLD,
            FileSnapshot(
                path=member.path,
                path_key=normalize_path_key(member.path),
                size=member.file_size,
                mtime_ns=member.mtime_ns,
                archive_format=member.archive_format,
            ),
            NOW,
        )
        preview = preview_recommendation_application(repository, (candidate.set_key,))
        assert (preview.keep, preview.remove, preview.user_decision_skipped) == (1, 0, 1)
    finally:
        repository.close()


def test_apply_links_review_action_and_never_moves_files(tmp_path: Path) -> None:
    repository, _root_id, candidate = _fixture(tmp_path)
    try:
        summary = apply_recommendations(repository, (candidate.set_key,), NOW)
        assert summary.applied == 2
        assert summary.failed == 0
        assert repository.latest_review_state("group-a", 1).action is ReviewAction.KEEP
        assert repository.latest_review_state("group-a", 2).action is ReviewAction.REMOVE_CANDIDATE
        assert repository._connection.execute(  # noqa: SLF001 - provenance assertion
            "SELECT COUNT(*) FROM recommendation_applications"
        ).fetchone() == (2,)
        assert (tmp_path / "1.cbz").exists() and (tmp_path / "2.cbz").exists()
    finally:
        repository.close()


def test_bulk_preview_and_apply_ignore_set_removed_from_current_generation(
    tmp_path: Path,
) -> None:
    repository, _root_id, candidate = _fixture(tmp_path)
    try:
        repository.replace_candidate_sets(candidate.source_group_key, (), computed_at=NOW)

        preview = preview_recommendation_application(repository, (candidate.set_key,))
        summary = apply_recommendations(repository, (candidate.set_key,), NOW)

        assert preview.applicable == 0
        assert preview.no_recommendation == 0
        assert summary.applied == 0
        assert summary.skipped == 0
        assert summary.failed == 0
        assert repository._connection.execute(  # noqa: SLF001 - no-write contract
            "SELECT COUNT(*) FROM review_actions"
        ).fetchone() == (0,)
        assert repository._connection.execute(  # noqa: SLF001 - no-write contract
            "SELECT COUNT(*) FROM recommendation_applications"
        ).fetchone() == (0,)
    finally:
        repository.close()


def test_changed_snapshot_is_skipped_without_partial_action(tmp_path: Path) -> None:
    repository, _root_id, candidate = _fixture(tmp_path)
    try:
        path = tmp_path / "2.cbz"
        path.write_bytes(b"changed")
        preview = preview_recommendation_application(repository, (candidate.set_key,))
        assert preview.changed_snapshot_skipped == 1
        summary = apply_recommendations(repository, (candidate.set_key,), NOW)
        assert summary.changed_snapshot_skipped == 1
        assert repository.latest_review_state("group-a", 2).action is None
    finally:
        repository.close()


def test_batch_preview_and_quarantine_keep_review_and_file_state_separate(tmp_path: Path) -> None:
    repository, _root_id, candidate = _fixture(tmp_path)
    isolation = tmp_path.parent / f"{tmp_path.name}-isolation"
    try:
        apply_recommendations(repository, (candidate.set_key,), NOW)
        preview = preview_batch_action(repository, (candidate.set_key,))
        assert (preview.keep_count, preview.remove_count, preview.quarantined_count) == (1, 1, 0)
        summary = batch_quarantine(repository, (candidate.set_key,), isolation, Event())
        assert summary.completed_ids == (2,)
        assert (tmp_path / "1.cbz").exists()
        assert not (tmp_path / "2.cbz").exists()
        assert (isolation / tmp_path.name / "2.cbz").exists()
        refreshed = preview_batch_action(repository, (candidate.set_key,))
        assert refreshed.quarantined_count == 1
        assert refreshed.remove_count == 0
    finally:
        repository.close()


def test_batch_delete_only_targets_already_quarantined_candidate(tmp_path: Path) -> None:
    repository, _root_id, candidate = _fixture(tmp_path)
    isolation = tmp_path.parent / f"{tmp_path.name}-delete-isolation"
    try:
        apply_recommendations(repository, (candidate.set_key,), NOW)
        batch_quarantine(repository, (candidate.set_key,), isolation, Event())
        summary = batch_delete_quarantined(repository, (candidate.set_key,), Event())
        assert summary.completed_ids == (2,)
        assert not (isolation / tmp_path.name / "2.cbz").exists()
        assert (tmp_path / "1.cbz").exists()
    finally:
        repository.close()
