from dataclasses import replace
from inspect import signature
from pathlib import Path
from threading import Event

import pytest

from archive_analyzer import desktop
from archive_analyzer.candidate_index import ArchiveEvidence, build_candidate_index
from archive_analyzer.duplicate_domain import AnalysisStage, ProbeFingerprint
from archive_analyzer.duplicate_jobs import AnalysisCancelled, DuplicateAnalysisService
from archive_analyzer.inspection.image_reader import ZipImageReader
from tests.image_helpers import encoded_gradient, tree_fingerprint
from tests.integration.test_duplicate_end_to_end import _indexed_repository, _write_zip


def test_candidate_phase_is_distinct_from_image_reading():
    assert desktop.progress_stage_text(AnalysisStage.CANDIDATE_BUILD) == "3/5 후보 비교 자료 준비"


def test_candidate_index_reports_real_pair_progress_without_changing_results():
    probe = ProbeFingerprint(0, 0, "a" * 64, "b" * 64, "0" * 16, "0" * 16, 80, 120)
    evidence = tuple(
        ArchiveEvidence(i, None, (probe, replace(probe, slot=1, entry_position=1)),
                        frozenset({"same"}), 1, 100, 10, 2)
        for i in range(1, 31)
    )
    expected = build_candidate_index(evidence)
    assert "progress_callback" in signature(build_candidate_index).parameters
    events = []
    assert build_candidate_index(evidence, progress_callback=events.append) == expected
    comparisons = [event for event in events if event.unit == "쌍"]
    assert any(0 < event.completed < event.total for event in comparisons)
    assert any(event.total == 435 and event.completed == 435 for event in comparisons)
    assert all(0 <= event.completed <= event.total for event in events if event.total is not None)


def _fixture(tmp_path: Path):
    source = tmp_path / "검사 원본"
    pages = tuple(encoded_gradient("PNG", (80 + i, 120)) for i in range(10))
    for i in range(3):
        _write_zip(source / f"파일 {i}.zip", pages, comment=b"x" * i)
    repository, root_id = _indexed_repository(source, tmp_path / "analysis.db")
    return source, repository, root_id


def test_cold_and_cached_scans_report_probe_pages_and_candidate_loading(tmp_path):
    source, repository, root_id = _fixture(tmp_path)
    before = tree_fingerprint(source)
    try:
        assert "progress_callback" in signature(DuplicateAnalysisService).parameters
        for _ in range(2):
            events = []
            result = DuplicateAnalysisService(repository, ZipImageReader(), progress_callback=events.append).run(root_id, Event())
            assert result.completed
            probe = [event for event in events if event.stage is AnalysisStage.PROBE]
            assert any(event.detail == "이 파일의 대표 이미지 1/7장" for event in probe)
            assert any(event.detail == "이 파일의 대표 이미지 7/7장" for event in probe)
            assert any(event.completed == 3 and event.total == 3 for event in probe)
            for phase in ("비교 자료 읽기", "비교 자료 유효성 확인"):
                counts = [event.completed for event in events if event.phase == phase]
                assert counts == [0, 1, 2, 3]
            assert any(event.stage is AnalysisStage.FULL and event.total == 3 for event in events)
            assert any(event.stage is AnalysisStage.MATCH and event.completed == event.total > 0 for event in events)
        assert tree_fingerprint(source) == before
    finally:
        repository.close()


def test_candidate_loader_counts_skipped_cache_entries(tmp_path):
    _, repository, root_id = _fixture(tmp_path)
    try:
        assert "progress_callback" in signature(repository.load_candidate_evidence).parameters
        events = []
        assert repository.load_candidate_evidence(root_id, analyzer_version=2, progress_callback=events.append) == ()
        assert [event.completed for event in events if event.phase == "비교 자료 읽기"] == [0, 1, 2, 3]
    finally:
        repository.close()


def test_cancelling_from_loading_progress_preserves_resumable_run(tmp_path):
    _, repository, root_id = _fixture(tmp_path)
    cancel = Event()
    try:
        assert "progress_callback" in signature(DuplicateAnalysisService).parameters
        def progress(event):
            if event.phase == "비교 자료 읽기" and event.completed == 1:
                cancel.set()
        with pytest.raises(AnalysisCancelled):
            DuplicateAnalysisService(repository, ZipImageReader(), progress_callback=progress).run(root_id, cancel)
        assert repository._connection.execute("SELECT status FROM duplicate_analysis_runs ORDER BY id DESC LIMIT 1").fetchone()[0] == "INTERRUPTED"
        assert DuplicateAnalysisService(repository, ZipImageReader()).run(root_id, Event()).completed
    finally:
        repository.close()


def test_scan_progress_bar_uses_measured_fraction_and_no_animation():
    assert hasattr(desktop, "display_analysis_progress")
    from archive_analyzer.analysis_progress import AnalysisProgress, ProgressMailbox
    class Bar:
        def __init__(self):
            self.options = {}
        def configure(self, **kwargs):
            self.options.update(kwargs)
    class Text:
        def set(self, value):
            self.value = value
    bar, text = Bar(), Text()
    mailbox = ProgressMailbox()
    for i in range(501):
        mailbox.publish(AnalysisProgress(AnalysisStage.CANDIDATE_BUILD, "비교 자료 읽기", i, 1000))
    desktop.display_analysis_progress(bar, text, mailbox.latest(), elapsed=902)
    assert bar.options == {"mode": "determinate", "maximum": 100, "value": 50}
    assert "500/1,000" in text.value and "50.0%" in text.value and "15:02" in text.value
    assert "이미지 처리" not in text.value
    mailbox.clear()
    assert mailbox.latest() is None


def test_native_scan_progress_with_real_background_analysis(tmp_path):
    import subprocess
    import sys
    code = """
import json, sys, tkinter as tk
from pathlib import Path
from tests.v1_fixture import create_v1_archive_fixture
from archive_analyzer.ui_smoke import verify_scan_progress
folder = Path(sys.argv[1])
source = create_v1_archive_fixture(folder)
root = tk.Tk()
root.withdraw()
try:
    print(json.dumps(verify_scan_progress(root, source, folder / 'progress-data')))
finally:
    root.destroy()
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path)], capture_output=True, timeout=75,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert b'"probe_pages": true' in result.stdout
