from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from archive_analyzer.update_install import InstallJob, apply_update


def make_job(tmp_path):
    target = tmp_path / "프로그램 폴더" / "압축파일 검사기.exe"
    target.parent.mkdir()
    target.write_bytes(b"MZold program")
    data = target.parent / "user-settings.json"
    data.write_bytes(b"user settings must survive")
    stage = tmp_path / "updates" / "transaction"
    stage.mkdir(parents=True)
    source = stage / "ArchiveAnalyzer.exe"
    source.write_bytes(b"MZnew program")
    return InstallJob(target, source, "1.1.0", hashlib.sha256(source.read_bytes()).hexdigest(),
                      hashlib.sha256(target.read_bytes()).hexdigest(), ()), data


def test_replaces_only_executable_keeps_verified_backup(tmp_path):
    job, data = make_job(tmp_path)
    seen = []
    result = apply_update(job, probe=lambda path, version: seen.append(path) or True)
    assert result["status"] == "installed"
    assert job.target.read_bytes() == b"MZnew program"
    assert (job.source.parent / "previous.exe").read_bytes() == b"MZold program"
    assert data.read_bytes() == b"user settings must survive"
    assert job.target in seen


def test_broken_executable_is_rejected_before_replace(tmp_path):
    job, data = make_job(tmp_path)
    result = apply_update(job, probe=lambda path, version: False)
    assert result["status"] == "failed"
    assert job.target.read_bytes() == b"MZold program"


def test_failed_installed_startup_rolls_back(tmp_path):
    job, data = make_job(tmp_path)
    result = apply_update(job, probe=lambda path, version: path != job.target)
    assert result["status"] == "rolled_back"
    assert job.target.read_bytes() == b"MZold program"
    assert data.read_bytes() == b"user settings must survive"


def test_external_replacement_is_not_overwritten(tmp_path):
    job, data = make_job(tmp_path)
    job.target.write_bytes(b"MZsomeone else's newer program")
    result = apply_update(job, probe=lambda path, version: True)
    assert result["status"] == "failed"
    assert job.target.read_bytes() == b"MZsomeone else's newer program"


def test_tampered_staging_rejected(tmp_path):
    job, data = make_job(tmp_path)
    job.source.write_bytes(b"MZtampered")
    result = apply_update(job, probe=lambda path, version: True)
    assert result["status"] == "failed"
    assert job.target.read_bytes() == b"MZold program"


def test_locked_target_preserved(tmp_path, monkeypatch):
    from archive_analyzer import update_install
    job, data = make_job(tmp_path)
    real_replace = update_install.os.replace
    def locked(source, target):
        if Path(target) == job.target:
            raise PermissionError("another instance still running")
        return real_replace(source, target)
    monkeypatch.setattr(update_install.os, "replace", locked)
    result = apply_update(job, probe=lambda path, version: True)
    assert result["status"] == "failed"
    assert job.target.read_bytes() == b"MZold program"


def test_job_roundtrip(tmp_path):
    job, data = make_job(tmp_path)
    path = job.write()
    assert InstallJob.read(path) == job
