from __future__ import annotations

import os
import sqlite3
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Thread, enumerate as enumerate_threads, get_ident
from types import SimpleNamespace

import pytest

import archive_analyzer.desktop as desktop
import archive_analyzer.storage.repository as repository_module
from archive_analyzer.duplicate_domain import AnalysisStage
from archive_analyzer.duplicate_jobs import AnalysisCancelled
from archive_analyzer.paths import is_path_within, normalize_path_key
from archive_analyzer.storage.duplicate_repository import DuplicateRepository
from archive_analyzer.storage.repository import Repository
from tests.image_helpers import encoded_gradient, tree_fingerprint, write_image_zip


def test_build_analysis_paths_separates_each_selected_folder(tmp_path: Path) -> None:
    first = tmp_path / "첫 번째 폴더"
    second = tmp_path / "두 번째 폴더"
    data_root = tmp_path / "program-data"
    first.mkdir()
    second.mkdir()
    created_at = datetime(2026, 8, 27, 13, 14, 15, 123456, tzinfo=UTC)

    first_paths = desktop.build_analysis_paths(first, data_root, created_at=created_at)
    repeated_paths = desktop.build_analysis_paths(first, data_root, created_at=created_at)
    second_paths = desktop.build_analysis_paths(second, data_root, created_at=created_at)

    assert first_paths == repeated_paths
    assert first_paths.database != second_paths.database
    assert first_paths.database.parent == data_root / "databases"
    assert not is_path_within(first_paths.database, first)


def test_latest_saved_result_upgrades_v3_database_instead_of_hiding_it(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "program-data"
    database = data_root / "databases" / "saved.db"
    source = tmp_path / "기존 검사 폴더"
    source.mkdir()
    _create_completed_v3_database(database, source, candidate_count=544)

    result = desktop.latest_saved_result(data_root=data_root)

    assert result is not None
    assert result.database == database
    assert result.source == source
    assert result.candidate_group_count == 544
    repository = DuplicateRepository.open_readonly(database)
    try:
        assert repository.schema_version() == 9
    finally:
        repository.close()


def test_selected_saved_result_also_upgrades_v3_database(tmp_path: Path) -> None:
    data_root = tmp_path / "program-data"
    source = tmp_path / "선택한 기존 폴더"
    source.mkdir()
    database = desktop.build_analysis_paths(source, data_root).database
    _create_completed_v3_database(database, source, candidate_count=0)

    result = desktop.completed_result(source, data_root=data_root)

    assert result == (database, 0)
    repository = DuplicateRepository.open_readonly(database)
    try:
        assert repository.schema_version() == 9
    finally:
        repository.close()


def test_run_analysis_finds_real_image_candidate_without_csv_or_source_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "검사할 폴더"
    source.mkdir()
    pages = (
        encoded_gradient("PNG", (80, 120)),
        encoded_gradient("PNG", (96, 144)),
    )
    first = write_image_zip(source / "첫 번째.zip", pages)
    shutil.copyfile(first, source / "두 번째.zip")
    before = tree_fingerprint(source)
    opened: list[Path] = []
    monkeypatch.setattr(os, "startfile", lambda path: opened.append(Path(path)))

    result = desktop.run_analysis(
        source, data_root=tmp_path / "program-data", workers=1
    )

    assert result.scan_summary.discovered_count == 2
    assert result.scan_summary.indexed_count == 2
    assert result.duplicate_summary.completed
    assert result.candidate_group_count == 1
    assert result.candidate_group_count == result.duplicate_summary.candidate_group_count
    assert result.database.is_file()
    assert not (tmp_path / "program-data" / "reports").exists()
    assert opened == []
    assert tree_fingerprint(source) == before


def test_run_analysis_closes_v0_repository_before_opening_v1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    events: list[str] = []
    real_repository_open = Repository.open.__func__
    real_duplicate_open = DuplicateRepository.open.__func__

    def open_v0(cls, database: Path):  # type: ignore[no-untyped-def]
        repository = real_repository_open(cls, database)
        original_close = repository.close

        def close() -> None:
            events.append("v0-close")
            original_close()

        repository.close = close  # type: ignore[method-assign]
        events.append("v0-open")
        return repository

    def open_v1(cls, database: Path):  # type: ignore[no-untyped-def]
        events.append("v1-open")
        return real_duplicate_open(cls, database)

    monkeypatch.setattr(Repository, "open", classmethod(open_v0))
    monkeypatch.setattr(DuplicateRepository, "open", classmethod(open_v1))

    result = desktop.run_analysis(
        source, data_root=tmp_path / "program-data", workers=1
    )

    assert events[:3] == ["v0-open", "v0-close", "v1-open"]
    duplicate_repository = DuplicateRepository.open_readonly(result.database)
    try:
        root_id = duplicate_repository.root_id_for_path_key(normalize_path_key(source))
        assert root_id is not None
        assert duplicate_repository.latest_duplicate_run_status() == "COMPLETED"
    finally:
        duplicate_repository.close()


def test_run_analysis_honors_cancel_set_before_v1_starts(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    cancel_event = Event()
    cancel_event.set()

    with pytest.raises(AnalysisCancelled):
        desktop.run_analysis(
            source,
            data_root=tmp_path / "program-data",
            workers=1,
            cancel_event=cancel_event,
        )

    database = desktop.build_analysis_paths(
        source, tmp_path / "program-data"
    ).database
    repository = Repository.open_readonly(database)
    try:
        progress = repository.latest_progress()
        assert progress is not None and progress.status == "INTERRUPTED"
    finally:
        repository.close()


def test_run_analysis_passes_shared_event_for_processing_cancel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    cancel_event = Event()
    entered = Event()
    errors: list[BaseException] = []

    class BlockingDuplicateService:
        def __init__(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
            pass

        def run(self, root_id: int, received_event: Event):
            assert root_id > 0
            assert received_event is cancel_event
            entered.set()
            assert received_event.wait(5)
            raise AnalysisCancelled

    monkeypatch.setattr(desktop, "DuplicateAnalysisService", BlockingDuplicateService)

    def work() -> None:
        try:
            desktop.run_analysis(
                source,
                data_root=tmp_path / "program-data",
                workers=1,
                cancel_event=cancel_event,
            )
        except BaseException as error:
            errors.append(error)

    worker = Thread(target=work)
    worker.start()
    assert entered.wait(5)
    cancel_event.set()
    worker.join(5)

    assert not worker.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], AnalysisCancelled)


@pytest.mark.parametrize(
    ("stage", "expected"),
    (
        (None, "1/5 목록 확인"),
        (AnalysisStage.ARCHIVE_HASH, "2/5 완전 동일 검사"),
        (AnalysisStage.PROBE, "3/5 대표 이미지 검사"),
        (AnalysisStage.CANDIDATE_BUILD, "3/5 후보 비교 자료 준비"),
        (AnalysisStage.FULL, "4/5 후보 정밀 확인"),
        (AnalysisStage.MATCH, "4/5 후보 정밀 확인"),
        (AnalysisStage.GROUP, "5/5 결과 정리"),
    ),
)
def test_progress_stage_text_maps_five_user_steps(
    stage: AnalysisStage | None, expected: str
) -> None:
    assert desktop.progress_stage_text(stage) == expected


def test_cancel_status_is_truthful_during_v0_and_v1() -> None:
    assert desktop.cancel_status_text(duplicate_started=False) == "중단 중"
    assert desktop.cancel_status_text(duplicate_started=True) == "중단 중"


def test_progress_reader_coalesces_and_reads_v0_and_v1_off_caller_thread(
    tmp_path: Path,
) -> None:
    caller_thread = get_ident()
    scan_started = Event()
    release_scan = Event()
    calls: list[tuple[str, int]] = []

    class ScanRepository:
        def latest_progress(self):  # type: ignore[no-untyped-def]
            calls.append(("scan-read", get_ident()))
            scan_started.set()
            assert release_scan.wait(5)
            return SimpleNamespace(processed_count=4, total_count=10)

        def close(self) -> None:
            calls.append(("scan-close", get_ident()))

    class DuplicateRepository:
        def latest_duplicate_progress(self):  # type: ignore[no-untyped-def]
            calls.append(("duplicate-read", get_ident()))
            return SimpleNamespace(
                stage=AnalysisStage.MATCH,
                archive_processed=7,
                candidate_count=12,
                archive_total=9,
                image_processed=70,
                image_total=90,
            )

        def latest_duplicate_run_status(self) -> str:
            return "RUNNING"

        def close(self) -> None:
            calls.append(("duplicate-close", get_ident()))

    reader = desktop.ProgressReader(
        scan_repository_factory=lambda _path: ScanRepository(),
        duplicate_repository_factory=lambda _path: DuplicateRepository(),
    )
    reader.start()

    assert reader.submit(tmp_path / "index.db", duplicate_started=False)
    assert scan_started.wait(5)
    assert not reader.submit(tmp_path / "index.db", duplicate_started=False)
    release_scan.set()
    scan_result = reader.wait_result(timeout=5)
    assert scan_result.snapshot == desktop.ProgressSnapshot(
        duplicate_started=False,
        stage=None,
        archive_processed=4,
        archive_total=10,
        image_processed=0,
        image_total=0,
    )

    assert reader.submit(tmp_path / "index.db", duplicate_started=True)
    duplicate_result = reader.wait_result(timeout=5)
    assert duplicate_result.snapshot == desktop.ProgressSnapshot(
        duplicate_started=True,
        stage=AnalysisStage.MATCH,
        archive_processed=7,
        archive_total=12,
        image_processed=70,
        image_total=90,
    )
    reader.close(timeout=5)

    assert not reader.is_alive()
    assert all(thread_id != caller_thread for _, thread_id in calls)
    assert not any(
        thread.name == "archive-analyzer-progress" and thread.is_alive()
        for thread in enumerate_threads()
    )


def test_progress_reader_absorbs_expected_read_errors(tmp_path: Path) -> None:
    def fail(_path: Path):  # type: ignore[no-untyped-def]
        raise sqlite3.OperationalError("database is busy")

    reader = desktop.ProgressReader(
        scan_repository_factory=fail,
        duplicate_repository_factory=fail,
    )
    reader.start()
    assert reader.submit(tmp_path / "index.db", duplicate_started=False)

    assert reader.wait_result(timeout=5).snapshot is None
    assert reader.is_alive()

    reader.close(timeout=5)
    assert not reader.is_alive()


def test_friendly_error_preserves_selection_help_without_raw_technical_details() -> None:
    selection_message = "선택한 폴더가 존재하지 않습니다."

    assert desktop._friendly_error(desktop.InvalidSelection(selection_message)) == (
        selection_message
    )
    assert "secret path" not in desktop._friendly_error(OSError("secret path"))
    assert "implementation detail" not in desktop._friendly_error(
        RuntimeError("implementation detail")
    )


def test_windowed_headless_main_returns_status_when_console_streams_are_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    success = SimpleNamespace(
        database=tmp_path / "result.db",
        candidate_group_count=2,
        duplicate_summary=SimpleNamespace(failed_archives=0),
    )
    monkeypatch.setattr(desktop, "run_analysis", lambda *args, **kwargs: success)
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)

    assert desktop.main(["--headless-source", str(source)]) == 0

    def fail(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise OSError("expected")

    monkeypatch.setattr(desktop, "run_analysis", fail)
    assert desktop.main(["--headless-source", str(source)]) == 1


def test_packaged_smoke_migrates_a_copied_result_without_opening_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "기록된 원본 경로"
    source.mkdir()
    database = tmp_path / "copied-result.db"
    _create_completed_v3_database(database, source, candidate_count=3)
    monkeypatch.setattr(desktop, "_verify_packaged_ocr_assets", lambda: (True, "assets"))

    assert desktop.main(["--packaged-smoke", str(database)]) == 0

    repository = DuplicateRepository.open_readonly(database)
    try:
        assert repository.schema_version() == 9
    finally:
        repository.close()


def _create_completed_v3_database(
    database: Path, source: Path, *, candidate_count: int
) -> None:
    database.parent.mkdir(parents=True, exist_ok=True)
    migrations = Path(repository_module.__file__).with_name("migrations")
    connection = sqlite3.connect(database)
    try:
        for version in (1, 2, 3):
            connection.executescript(
                (migrations / f"{version:03}.sql").read_text(encoding="utf-8")
            )
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, "2026-09-01T12:00:00+00:00"),
            )
        root_id = connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (
                str(source.resolve(strict=False)),
                normalize_path_key(source),
                "2026-09-01T12:00:00+00:00",
            ),
        ).lastrowid
        connection.execute(
            "INSERT INTO duplicate_analysis_runs("
            "scan_root_id, status, stage, started_at, finished_at, analyzer_version, "
            "candidate_count) VALUES (?, 'COMPLETED', 'GROUP', ?, ?, 1, ?)",
            (
                root_id,
                "2026-09-01T12:00:00+00:00",
                "2026-09-01T13:00:00+00:00",
                candidate_count,
            ),
        )
        connection.commit()
    finally:
        connection.close()
