"""Independent audit regressions: preserve files at mutation boundaries."""
import os
from pathlib import Path
from threading import Event
import pytest
from archive_analyzer import quarantine as qm
from archive_analyzer import deletion as dm
from tests.unit.test_quarantine import _repository, NOW
from tests.unit.test_deletion import _quarantined


def test_cross_volume_change_during_copy_verification_preserves_new_source(tmp_path, monkeypatch):
    repo, group, aid, source = _repository(tmp_path)
    monkeypatch.setattr(qm, '_same_volume', lambda *_: False)
    calls = 0
    def progress(current, total, phase):
        nonlocal calls
        calls += 1
        # First pass copies source, second pass verifies the temporary copy.
        if calls == 2:
            source.write_bytes(b'new-user-content-after-copy')
    try:
        with pytest.raises(qm.QuarantineSafetyError, match='SOURCE_CHANGED'):
            qm.quarantine_archives(repo, group, (aid,), tmp_path/'quarantine', Event(), progress=progress)
        assert source.read_bytes() == b'new-user-content-after-copy'
    finally:
        repo.close()


def _junction(target, link):
    if os.name != 'nt':
        link.symlink_to(target, target_is_directory=True)
    else:
        import _winapi
        _winapi.CreateJunction(str(target), str(link))


def test_quarantine_refuses_redirected_destination_parent(tmp_path):
    repo, group, aid, source = _repository(tmp_path)
    destination = tmp_path/'quarantine'
    destination.mkdir()
    outside = tmp_path/'unrelated-user-folder'
    outside.mkdir()
    _junction(outside, destination/'source')
    try:
        with pytest.raises(qm.QuarantineSafetyError, match='REPARSE'):
            qm.quarantine_archives(repo, group, (aid,), destination, Event())
        assert source.read_bytes() == b'archive-payload'
        assert not tuple(outside.iterdir())
    finally:
        repo.close()


def test_recycle_refuses_parent_replaced_by_junction(tmp_path):
    repo, group, aid, source, destination = _quarantined(tmp_path)
    relocated = tmp_path/'unrelated-user-folder'
    destination.parent.rename(relocated)
    _junction(relocated, destination.parent)
    try:
        with pytest.raises(dm.DeletionSafetyError, match='REPARSE'):
            dm.delete_quarantined_archives(repo, group, (aid,), Event())
        assert (relocated/destination.name).read_bytes() == b'archive-payload'
        assert repo._connection.execute('SELECT COUNT(*) FROM deletion_records').fetchone()[0] == 0
    finally:
        repo.close()


def test_recycle_rechecks_changed_file_after_ledger_write(tmp_path, monkeypatch):
    repo, group, aid, source, destination = _quarantined(tmp_path)
    begin = repo.begin_deletion
    def begin_and_replace(item, now):
        result = begin(item, now)
        destination.write_bytes(b'new-user-content-after-hash')
        return result
    monkeypatch.setattr(repo, 'begin_deletion', begin_and_replace)
    try:
        with pytest.raises(dm.DeletionSafetyError, match='QUARANTINE_FILE_CHANGED'):
            dm.delete_quarantined_archives(repo, group, (aid,), Event())
        assert destination.read_bytes() == b'new-user-content-after-hash'
    finally:
        repo.close()
