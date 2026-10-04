from __future__ import annotations

import os
from pathlib import Path
from threading import Event

import pytest

from archive_analyzer.archive_hashing import AnalysisCancelled
from archive_analyzer.deletion import (
    DeletionSafetyError,
    delete_quarantined_archives,
    reconcile_deletions,
)
from archive_analyzer.quarantine import quarantine_archives
from tests.unit.test_quarantine import NOW, _repository


def _quarantined(tmp_path: Path):  # type: ignore[no-untyped-def]
    repository, group_key, archive_id, source = _repository(tmp_path)
    quarantine_root = tmp_path / "quarantine"
    quarantine_archives(
        repository,
        group_key,
        (archive_id,),
        quarantine_root,
        Event(),
        clock=lambda: NOW,
    )
    destination = quarantine_root / "source" / "series" / "book.cbz"
    return repository, group_key, archive_id, source, destination


def test_permanent_delete_removes_only_the_verified_quarantine_copy(
    tmp_path: Path,
) -> None:
    repository, group_key, archive_id, source, destination = _quarantined(tmp_path)
    try:
        result = delete_quarantined_archives(
            repository,
            group_key,
            (archive_id,),
            Event(),
            clock=lambda: NOW,
        )

        assert result.processed == 1
        assert not source.exists()
        assert not destination.exists()
        assert repository._connection.execute(  # noqa: SLF001 - deletion ledger contract
            "SELECT state, path, deleted_at FROM deletion_records"
        ).fetchone() == ("DELETED", str(destination), NOW.isoformat())
        assert repository.active_quarantine_item(group_key, archive_id) is None
        detail = repository.group_details(group_key)
        assert detail is not None
        assert detail.members[0].deletion_state == "DELETED"
    finally:
        repository.close()


def test_permanent_delete_refuses_when_original_path_reappears(tmp_path: Path) -> None:
    repository, group_key, archive_id, source, destination = _quarantined(tmp_path)
    source.write_bytes(b"a-new-file-at-the-original-path")
    try:
        with pytest.raises(DeletionSafetyError, match="SOURCE_REAPPEARED"):
            delete_quarantined_archives(
                repository, group_key, (archive_id,), Event(), clock=lambda: NOW
            )
        assert source.exists()
        assert destination.exists()
        assert repository._connection.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM deletion_records"
        ).fetchone() == (0,)
    finally:
        repository.close()


def test_permanent_delete_rechecks_original_path_immediately_before_unlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, group_key, archive_id, source, destination = _quarantined(tmp_path)
    original_begin = repository.begin_deletion

    def begin_and_recreate_source(item, created_at):  # type: ignore[no-untyped-def]
        record = original_begin(item, created_at)
        source.write_bytes(b"reappeared-during-final-check")
        return record

    monkeypatch.setattr(repository, "begin_deletion", begin_and_recreate_source)
    try:
        with pytest.raises(DeletionSafetyError, match="SOURCE_REAPPEARED"):
            delete_quarantined_archives(
                repository, group_key, (archive_id,), Event(), clock=lambda: NOW
            )
        assert source.exists()
        assert destination.exists()
        assert repository._connection.execute(  # noqa: SLF001
            "SELECT state, error_code FROM deletion_records"
        ).fetchone() == ("FAILED", "SOURCE_REAPPEARED")
    finally:
        repository.close()


def test_permanent_delete_refuses_a_tampered_quarantine_copy(tmp_path: Path) -> None:
    repository, group_key, archive_id, _source, destination = _quarantined(tmp_path)
    item = repository.active_quarantine_item(group_key, archive_id)
    assert item is not None
    destination.write_bytes(b"x" * item.file_size)
    os.utime(destination, ns=(item.mtime_ns, item.mtime_ns))
    try:
        with pytest.raises(DeletionSafetyError, match="HASH_MISMATCH"):
            delete_quarantined_archives(
                repository, group_key, (archive_id,), Event(), clock=lambda: NOW
            )
        assert destination.exists()
    finally:
        repository.close()


def test_permanent_delete_honors_cancellation_before_any_record_or_unlink(
    tmp_path: Path,
) -> None:
    repository, group_key, archive_id, _source, destination = _quarantined(tmp_path)
    cancel_event = Event()
    cancel_event.set()
    try:
        with pytest.raises(AnalysisCancelled):
            delete_quarantined_archives(
                repository,
                group_key,
                (archive_id,),
                cancel_event,
                clock=lambda: NOW,
            )
        assert destination.exists()
        assert repository._connection.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM deletion_records"
        ).fetchone() == (0,)
    finally:
        repository.close()


def test_reconcile_records_a_delete_that_finished_before_database_update(
    tmp_path: Path,
) -> None:
    repository, group_key, archive_id, _source, destination = _quarantined(tmp_path)
    item = repository.deletion_candidate(group_key, archive_id)
    record = repository.begin_deletion(item, NOW)
    destination.unlink()
    try:
        assert reconcile_deletions(
            repository, item.root_id, Event(), clock=lambda: NOW
        ) == 1
        assert repository.deletion_record(record.id).state == "DELETED"  # type: ignore[union-attr]
    finally:
        repository.close()
