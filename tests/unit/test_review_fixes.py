from pathlib import Path
from threading import Event
import csv
import pytest
import archive_analyzer.quarantine as qm
from archive_analyzer.quarantine import quarantine_archives, restore_archives, reconcile_quarantine_items, QuarantineSafetyError
from archive_analyzer.duplicate_reporting import write_candidate_csv
from archive_analyzer.review_viewmodel import build_group_view
from tests.unit.test_quarantine import _repository, NOW
from tests.unit.test_duplicate_reporting import _candidate_repository


@pytest.mark.parametrize('restoring', [False, True])
def test_cancel_after_copy_commit_finishes_current_file_consistently(tmp_path, monkeypatch, restoring):
    repository, group, archive_id, source = _repository(tmp_path)
    quarantine_root = tmp_path/'quarantine'
    destination = quarantine_root/'source/series/book.cbz'
    event = Event()
    monkeypatch.setattr(qm, '_same_volume', lambda *args: False)
    if restoring:
        quarantine_archives(repository, group, (archive_id,), quarantine_root, Event(), clock=lambda: NOW)
    real_rename = Path.rename
    target = source if restoring else destination
    def cancel_after_commit(path, new_path):
        result = real_rename(path, new_path)
        if path.name.endswith('.tmp') and Path(new_path) == target:
            event.set()
        return result
    monkeypatch.setattr(Path, 'rename', cancel_after_commit)
    try:
        if restoring:
            result = restore_archives(repository, group, (archive_id,), event, clock=lambda: NOW)
        else:
            result = quarantine_archives(repository, group, (archive_id,), quarantine_root, event, clock=lambda: NOW)
        assert event.is_set()
        assert result.processed == 1
        assert target.read_bytes() == b'archive-payload'
        assert not (destination if restoring else source).exists()
        state = repository._connection.execute('SELECT status FROM quarantine_items').fetchone()[0]
        assert state == ('RESTORED' if restoring else 'QUARANTINED')
    finally:
        repository.close()


def test_failed_source_removal_keeps_both_copies_and_recovery_record(tmp_path, monkeypatch):
    repository, group, archive_id, source = _repository(tmp_path)
    quarantine_root = tmp_path/'quarantine'
    destination = quarantine_root/'source/series/book.cbz'
    monkeypatch.setattr(qm, '_same_volume', lambda *args: False)
    real_unlink = Path.unlink
    def deny_source(path, *args, **kwargs):
        if path == source:
            raise PermissionError('synthetic source locked')
        return real_unlink(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'unlink', deny_source)
    try:
        with pytest.raises(QuarantineSafetyError, match='FILE_MOVE_FAILED'):
            quarantine_archives(repository, group, (archive_id,), quarantine_root, Event(), clock=lambda: NOW)
        item = repository.active_quarantine_item(group, archive_id)
        assert item is not None and item.status == 'PENDING'
        assert source.read_bytes() == destination.read_bytes() == b'archive-payload'
        reconcile_quarantine_items(repository, item.root_id, Event(), clock=lambda: NOW)
        assert repository.active_quarantine_item(group, archive_id).status == 'PENDING'
        assert source.read_bytes() == destination.read_bytes() == b'archive-payload'
        view = build_group_view(repository.group_details(group))
        assert '복구 대기' in view.members[0].file_operation_status_text
        # Simulate an explicit resolution without deleting any test copy.
        source.rename(tmp_path/'retained-original.cbz')
        reconcile_quarantine_items(repository, item.root_id, Event(), clock=lambda: NOW)
        assert repository.active_quarantine_item(group, archive_id).status == 'QUARANTINED'
    finally:
        repository.close()


def test_db_failure_after_completed_move_remains_reconcilable(tmp_path, monkeypatch):
    repository, group, archive_id, source = _repository(tmp_path)
    original = repository.update_quarantine_status
    def fail_final(item_id, expected, status, *args, **kwargs):
        if status == 'QUARANTINED':
            raise OSError('synthetic final ledger write failure')
        return original(item_id, expected, status, *args, **kwargs)
    monkeypatch.setattr(repository, 'update_quarantine_status', fail_final)
    try:
        with pytest.raises(OSError):
            quarantine_archives(repository, group, (archive_id,), tmp_path/'quarantine', Event(), clock=lambda: NOW)
        item = repository.active_quarantine_item(group, archive_id)
        assert item is not None and item.status == 'PENDING'
        monkeypatch.setattr(repository, 'update_quarantine_status', original)
        reconcile_quarantine_items(repository, item.root_id, Event(), clock=lambda: NOW)
        assert repository.active_quarantine_item(group, archive_id).status == 'QUARANTINED'
    finally:
        repository.close()


@pytest.mark.parametrize('name', ['=1+1.cbz', '+name.cbz', '-name.cbz', '@name.cbz', '  =1.cbz', '\t=1.cbz', '\r=1.cbz', '\n=1.cbz'])
def test_candidate_csv_exports_untrusted_names_as_text(tmp_path, name):
    repository, root_id, ids, _ = _candidate_repository(tmp_path)
    try:
        repository._connection.execute('UPDATE archives SET path = ? WHERE id = ?', (str(tmp_path/'root'/name), ids[0]))
        repository._connection.commit()
        output = tmp_path/'candidates.csv'
        write_candidate_csv(repository, output, root_id=root_id)
        with output.open(encoding='utf-8-sig', newline='') as stream:
            row = next(row for row in csv.DictReader(stream) if int(row['archive_id']) == ids[0])
        assert row['file_name'] == "'" + name
        assert row['file_size'] == '10'
        assert row['path'] == str(tmp_path/'root'/name)
        assert row['direct_edges'] == 'B.cbz (2): 내용 동일'
    finally:
        repository.close()
