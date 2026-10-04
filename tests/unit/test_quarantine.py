from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from threading import Event

import pytest

import archive_analyzer.quarantine as quarantine_module
from archive_analyzer.archive_hashing import AnalysisCancelled
from archive_analyzer.quarantine import (
    QuarantineSafetyError,
    quarantine_archives,
    reconcile_quarantine_items,
    restore_archives,
)
from archive_analyzer.storage.duplicate_repository import DuplicateRepository


NOW = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)


def _repository(
    tmp_path: Path, *, action: str = "REMOVE_CANDIDATE", preserve: bool = False
) -> tuple[DuplicateRepository, str, int, Path]:
    source_root = tmp_path / "source"
    source = source_root / "series" / "book.cbz"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"archive-payload")
    stat = source.stat()
    repository = DuplicateRepository.open(tmp_path / "index.db")
    connection = repository._connection  # noqa: SLF001 - compact safety fixture
    root_id = connection.execute(
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
        (str(source_root), "source-root", NOW.isoformat()),
    ).lastrowid
    archive_id = connection.execute(
        "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
        "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
        "VALUES (?, ?, 'book', ?, ?, 'CBZ', 'INDEXED', ?, ?, 1)",
        (root_id, str(source), stat.st_size, stat.st_mtime_ns, NOW.isoformat(), NOW.isoformat()),
    ).lastrowid
    group_key = "group"
    group_id = connection.execute(
        "INSERT INTO candidate_groups(scan_root_id, group_key, strongest_relation, confidence, "
        "analyzer_version, created_at) VALUES (?, ?, 'EXACT_CONTENT', 1.0, 1, ?)",
        (root_id, group_key, NOW.isoformat()),
    ).lastrowid
    connection.execute(
        "INSERT INTO candidate_group_members(group_id, archive_id) VALUES (?, ?)",
        (group_id, archive_id),
    )
    connection.execute(
        "INSERT INTO review_actions(group_key, archive_id, action, file_size, mtime_ns, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (group_key, archive_id, action, stat.st_size, stat.st_mtime_ns, NOW.isoformat()),
    )
    if preserve:
        other = source_root / "series" / "color.cbz"
        other.write_bytes(b"other")
        other_stat = other.stat()
        other_id = connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
            "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, 'color', ?, ?, 'CBZ', 'INDEXED', ?, ?, 1)",
            (root_id, str(other), other_stat.st_size, other_stat.st_mtime_ns, NOW.isoformat(), NOW.isoformat()),
        ).lastrowid
        left_id, right_id = sorted((int(archive_id), int(other_id)))
        left_stat, right_stat = (stat, other_stat) if left_id == archive_id else (other_stat, stat)
        connection.execute(
            "INSERT INTO edition_relations(scan_root_id, archive_a_id, archive_b_id, flags_json, "
            "summary, preserve_required, left_file_size, left_mtime_ns, right_file_size, "
            "right_mtime_ns, algorithm_version, computed_at) "
            "VALUES (?, ?, ?, '[\"COLOR_MONO\"]', 'color', 1, ?, ?, ?, ?, 1, ?)",
            (
                root_id,
                left_id,
                right_id,
                left_stat.st_size,
                left_stat.st_mtime_ns,
                right_stat.st_size,
                right_stat.st_mtime_ns,
                NOW.isoformat(),
            ),
        )
    connection.commit()
    return repository, group_key, int(archive_id), source


def test_quarantine_moves_only_reviewed_file_and_restore_returns_it(tmp_path: Path) -> None:
    repository, group_key, archive_id, source = _repository(tmp_path)
    quarantine_root = tmp_path / "quarantine"
    try:
        result = quarantine_archives(
            repository,
            group_key,
            (archive_id,),
            quarantine_root,
            Event(),
            clock=lambda: NOW,
        )

        destination = quarantine_root / "source" / "series" / "book.cbz"
        assert result.processed == 1
        assert not source.exists()
        assert destination.read_bytes() == b"archive-payload"
        assert repository._connection.execute(  # noqa: SLF001 - persisted state contract
            "SELECT status, sha256 FROM quarantine_items"
        ).fetchone()[0] == "QUARANTINED"
        detail = repository.group_details(group_key)
        assert detail is not None
        assert detail.members[0].quarantine_status == "QUARANTINED"
        assert detail.members[0].quarantine_path == destination

        restored = restore_archives(
            repository, group_key, (archive_id,), Event(), clock=lambda: NOW
        )

        assert restored.processed == 1
        assert source.read_bytes() == b"archive-payload"
        assert not destination.exists()
        assert repository._connection.execute(  # noqa: SLF001
            "SELECT status FROM quarantine_items"
        ).fetchone() == ("RESTORED",)
        restored_detail = repository.group_details(group_key)
        assert restored_detail is not None
        assert restored_detail.members[0].quarantine_status == "RESTORED"
    finally:
        repository.close()


def test_quarantine_requires_current_remove_candidate_decision(tmp_path: Path) -> None:
    repository, group_key, archive_id, source = _repository(tmp_path, action="KEEP")
    try:
        with pytest.raises(QuarantineSafetyError, match="REMOVE_CANDIDATE"):
            quarantine_archives(
                repository, group_key, (archive_id,), tmp_path / "quarantine", Event()
            )
        assert source.exists()
    finally:
        repository.close()


def test_explicit_remove_decision_overrides_preservation_advice(tmp_path: Path) -> None:
    repository, group_key, archive_id, source = _repository(tmp_path, preserve=True)
    try:
        summary = quarantine_archives(repository, group_key, (archive_id,), tmp_path / "quarantine", Event())
        assert summary.processed == 1
        assert not source.exists()
        assert repository.active_quarantine_item(group_key, archive_id).destination_path.exists()
    finally:
        repository.close()


def test_quarantine_rejects_changed_source_and_existing_destination(tmp_path: Path) -> None:
    repository, group_key, archive_id, source = _repository(tmp_path)
    quarantine_root = tmp_path / "quarantine"
    destination = quarantine_root / "source" / "series" / "book.cbz"
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"do-not-overwrite")
    try:
        with pytest.raises(QuarantineSafetyError, match="DESTINATION_EXISTS"):
            quarantine_archives(
                repository, group_key, (archive_id,), quarantine_root, Event()
            )
        assert destination.read_bytes() == b"do-not-overwrite"

        destination.unlink()
        source.write_bytes(b"changed-after-review")
        with pytest.raises(QuarantineSafetyError, match="SOURCE_CHANGED"):
            quarantine_archives(
                repository, group_key, (archive_id,), quarantine_root, Event()
            )
        assert source.read_bytes() == b"changed-after-review"
    finally:
        repository.close()


def test_quarantine_honors_an_already_requested_cancellation(tmp_path: Path) -> None:
    repository, group_key, archive_id, source = _repository(tmp_path)
    cancel_event = Event()
    cancel_event.set()
    try:
        with pytest.raises(AnalysisCancelled):
            quarantine_archives(
                repository,
                group_key,
                (archive_id,),
                tmp_path / "quarantine",
                cancel_event,
            )
        assert source.exists()
        assert repository._connection.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM quarantine_items"
        ).fetchone() == (0,)
    finally:
        repository.close()


def test_quarantine_cancels_between_large_file_chunks_without_moving_source(
    tmp_path: Path,
) -> None:
    repository, group_key, archive_id, source = _repository(tmp_path)
    source.write_bytes(b"x" * (5 * 1024 * 1024))
    stat = source.stat()
    repository._connection.execute(  # noqa: SLF001 - enlarge the reviewed fixture
        "UPDATE archives SET file_size = ?, mtime_ns = ? WHERE id = ?",
        (stat.st_size, stat.st_mtime_ns, archive_id),
    )
    repository._connection.execute(  # noqa: SLF001
        "UPDATE review_actions SET file_size = ?, mtime_ns = ? WHERE archive_id = ?",
        (stat.st_size, stat.st_mtime_ns, archive_id),
    )
    repository._connection.commit()  # noqa: SLF001
    cancel_event = Event()

    def cancel_after_first_chunk(_current: int, _total: int, phase: str) -> None:
        if phase == "quarantine":
            cancel_event.set()

    try:
        with pytest.raises(AnalysisCancelled):
            quarantine_archives(
                repository,
                group_key,
                (archive_id,),
                tmp_path / "quarantine",
                cancel_event,
                progress=cancel_after_first_chunk,
            )
        assert source.exists()
        assert repository._connection.execute(  # noqa: SLF001
            "SELECT status, error_code FROM quarantine_items"
        ).fetchone() == ("FAILED", "CANCELLED")
    finally:
        repository.close()


def test_reconcile_marks_a_completed_atomic_move_after_interruption(
    tmp_path: Path,
) -> None:
    repository, group_key, archive_id, source = _repository(tmp_path)
    candidate = repository.quarantine_candidate(group_key, archive_id)
    destination = tmp_path / "quarantine" / "source" / "series" / "book.cbz"
    destination.parent.mkdir(parents=True)
    item = repository.create_quarantine_item(candidate, destination, NOW)
    source.rename(destination)
    try:
        assert reconcile_quarantine_items(
            repository, candidate.root_id, Event(), clock=lambda: NOW
        ) == 1
        assert repository.quarantine_item(item.id).status == "QUARANTINED"  # type: ignore[union-attr]
    finally:
        repository.close()


def test_cross_volume_path_copies_verifies_and_then_removes_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, group_key, archive_id, source = _repository(tmp_path)
    monkeypatch.setattr(quarantine_module, "_same_volume", lambda *_args: False)
    quarantine_root = tmp_path / "quarantine"
    try:
        quarantine_archives(
            repository,
            group_key,
            (archive_id,),
            quarantine_root,
            Event(),
            clock=lambda: NOW,
        )

        destination = quarantine_root / "source" / "series" / "book.cbz"
        assert not source.exists()
        assert destination.read_bytes() == b"archive-payload"
        assert not tuple(destination.parent.glob("*.tmp"))

        restore_archives(
            repository, group_key, (archive_id,), Event(), clock=lambda: NOW
        )
        assert source.read_bytes() == b"archive-payload"
        assert not destination.exists()
    finally:
        repository.close()
