from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from queue import Empty, Queue
from time import monotonic
from typing import Callable

from archive_analyzer.analysis_progress import AnalysisProgress, ProgressCallback, ProgressMailbox
from archive_analyzer.version import __version__
from archive_analyzer.duplicate_domain import AnalysisStage
from archive_analyzer.duplicate_jobs import (
    AnalysisCancelled,
    DuplicateAnalysisService,
    DuplicateSummary,
)
from archive_analyzer.inspection import (
    DispatchingImageReader,
    DispatchingInspector,
    ZipBackend,
)
from archive_analyzer.inspection.sevenzip import SevenZipBackend
from archive_analyzer.jobs import (
    ScanAlreadyRunning,
    ScanCancelled,
    ScanService,
    ScanSummary,
)
from archive_analyzer.paths import (
    has_reparse_point_in_existing_chain,
    is_path_within,
    normalize_path_key,
)
from archive_analyzer.review_ui import ReviewWindow
from archive_analyzer.recommendation_service import refresh_recommendations
from archive_analyzer.precision_service import analyze_precision
from archive_analyzer.storage.duplicate_repository import DuplicateRepository
from archive_analyzer.storage.repository import (
    LATEST_SCHEMA_VERSION,
    Repository,
    UnsafeDatabaseIdentity,
)


_DEFAULT_SEVEN_ZIP = Path(r"C:\Program Files\7-Zip\7z.exe")
_WINDOW_TITLE = "압축파일 검사기"


class InvalidSelection(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AnalysisPaths:
    database: Path


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    scan_summary: ScanSummary
    duplicate_summary: DuplicateSummary
    database: Path
    candidate_group_count: int


@dataclass(frozen=True, slots=True)
class SavedResult:
    database: Path
    source: Path
    finished_at: str
    candidate_group_count: int


@dataclass(frozen=True, slots=True)
class ProgressSnapshot:
    duplicate_started: bool
    stage: AnalysisStage | None
    archive_processed: int
    archive_total: int
    image_processed: int
    image_total: int


@dataclass(frozen=True, slots=True)
class ProgressReadResult:
    snapshot: ProgressSnapshot | None


@dataclass(frozen=True, slots=True)
class _ProgressRequest:
    database: Path
    duplicate_started: bool


class ProgressReader:
    """Read one coalesced progress snapshot at a time outside the Tk thread."""

    def __init__(
        self,
        *,
        scan_repository_factory: Callable[[Path], object] | None = None,
        duplicate_repository_factory: Callable[[Path], object] | None = None,
    ) -> None:
        self._scan_repository_factory = (
            scan_repository_factory or Repository.open_readonly
        )
        self._duplicate_repository_factory = (
            duplicate_repository_factory or DuplicateRepository.open_readonly
        )
        self._requests: Queue[_ProgressRequest | None] = Queue()
        self._results: Queue[ProgressReadResult] = Queue()
        self._state_lock = threading.Lock()
        self._thread = threading.Thread(
            target=self._run, name="archive-analyzer-progress", daemon=False
        )
        self._started = False
        self._closing = False
        self._in_flight = False

    def start(self) -> None:
        with self._state_lock:
            if self._started:
                raise RuntimeError("Progress reader has already been started.")
            self._started = True
        self._thread.start()

    def submit(self, database: Path, *, duplicate_started: bool) -> bool:
        with self._state_lock:
            if not self._started:
                raise RuntimeError("Progress reader has not been started.")
            if self._closing or self._in_flight:
                return False
            self._in_flight = True
        self._requests.put(_ProgressRequest(Path(database), duplicate_started))
        return True

    def poll_result(self) -> ProgressReadResult | None:
        try:
            result = self._results.get_nowait()
        except Empty:
            return None
        return self._finish_result(result)

    def wait_result(self, *, timeout: float | None = None) -> ProgressReadResult:
        return self._finish_result(self._results.get(timeout=timeout))

    def request_close(self) -> None:
        with self._state_lock:
            if not self._started or self._closing:
                return
            self._closing = True
        self._requests.put(None)

    def close(self, *, timeout: float | None = None) -> None:
        self.request_close()
        if self._started:
            self._thread.join(timeout)
        if self._thread.is_alive():
            raise TimeoutError("Progress reader did not stop before the timeout.")

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def _finish_result(self, result: ProgressReadResult) -> ProgressReadResult:
        with self._state_lock:
            self._in_flight = False
        return result

    def _run(self) -> None:
        while True:
            request = self._requests.get()
            if request is None:
                return
            try:
                snapshot = self._read_snapshot(request)
            except (OSError, sqlite3.Error, UnsafeDatabaseIdentity):
                snapshot = None
            self._results.put(ProgressReadResult(snapshot))

    def _read_snapshot(self, request: _ProgressRequest) -> ProgressSnapshot:
        if request.duplicate_started:
            repository = self._duplicate_repository_factory(request.database)
            try:
                progress = repository.latest_duplicate_progress()  # type: ignore[attr-defined]
                status = repository.latest_duplicate_run_status()  # type: ignore[attr-defined]
            finally:
                repository.close()  # type: ignore[attr-defined]
            if progress is not None and status == "RUNNING":
                return ProgressSnapshot(
                    duplicate_started=True,
                    stage=progress.stage,
                    archive_processed=progress.archive_processed,
                    archive_total=(progress.candidate_count if progress.stage is AnalysisStage.MATCH
                                   else progress.archive_total),
                    image_processed=progress.image_processed,
                    image_total=progress.image_total,
                )
            return ProgressSnapshot(True, AnalysisStage.ARCHIVE_HASH, 0, 0, 0, 0)

        repository = self._scan_repository_factory(request.database)
        try:
            progress = repository.latest_progress()  # type: ignore[attr-defined]
        finally:
            repository.close()  # type: ignore[attr-defined]
        return ProgressSnapshot(
            duplicate_started=False,
            stage=None,
            archive_processed=0 if progress is None else progress.processed_count,
            archive_total=0 if progress is None else progress.total_count,
            image_processed=0,
            image_total=0,
        )


def default_data_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise OSError("Windows 사용자 데이터 폴더를 찾을 수 없습니다.")
    return Path(local_app_data) / "ArchiveAnalyzer"


def build_analysis_paths(
    source: Path,
    data_root: Path,
    *,
    created_at: datetime | None = None,
) -> AnalysisPaths:
    del created_at  # Kept for compatibility with deterministic path callers.
    selected = Path(source).resolve(strict=False)
    if not selected.is_dir():
        raise InvalidSelection("선택한 폴더가 존재하지 않습니다.")
    if has_reparse_point_in_existing_chain(Path(source)):
        raise InvalidSelection("바로가기, 정션 또는 심볼릭 링크 폴더는 검사할 수 없습니다.")

    storage = Path(data_root).resolve(strict=False)
    path_hash = hashlib.sha256(normalize_path_key(selected).encode("utf-8")).hexdigest()
    database = storage / "databases" / f"{path_hash}.db"
    if is_path_within(database, selected):
        raise InvalidSelection(
            "검사 결과를 원본 폴더 밖에 안전하게 저장할 수 없는 위치입니다. "
            "전체 드라이브 대신 압축파일이 든 하위 폴더를 선택해 주세요."
        )
    return AnalysisPaths(database=database)


def run_analysis(
    source: Path,
    *,
    data_root: Path | None = None,
    seven_zip: Path = _DEFAULT_SEVEN_ZIP,
    workers: int = 2,
    cancel_event: threading.Event | None = None,
    phase_callback: Callable[[str], None] | None = None,
    progress_callback: ProgressCallback | None = None,
) -> AnalysisResult:
    requested_source = Path(source)
    selected = requested_source.resolve(strict=False)
    paths = build_analysis_paths(requested_source, data_root or default_data_root())
    paths.database.parent.mkdir(parents=True, exist_ok=True)
    shared_cancel_event = cancel_event or threading.Event()

    if phase_callback is not None:
        phase_callback("scan")
    repository = Repository.open(paths.database)
    try:
        inspector = DispatchingInspector(ZipBackend(), SevenZipBackend(seven_zip))
        try:
            scan_summary = ScanService(repository, inspector, workers=workers).run(
                selected, shared_cancel_event
            )
        except ScanCancelled as error:
            raise AnalysisCancelled from error
    finally:
        repository.close()

    if phase_callback is not None:
        phase_callback("duplicate")
    duplicate_repository = DuplicateRepository.open(paths.database)
    try:
        root_id = duplicate_repository.root_id_for_path_key(normalize_path_key(selected))
        if root_id is None:
            raise RuntimeError("The selected scan root is missing from the analysis database.")
        duplicate_summary = DuplicateAnalysisService(
            duplicate_repository,
            DispatchingImageReader(seven_zip),
            workers=workers,
            progress_callback=progress_callback,
        ).run(root_id, shared_cancel_event)
    finally:
        duplicate_repository.close()

    return AnalysisResult(
        scan_summary=scan_summary,
        duplicate_summary=duplicate_summary,
        database=paths.database,
        candidate_group_count=duplicate_summary.candidate_group_count,
    )


def completed_result(
    source: Path, *, data_root: Path | None = None
) -> tuple[Path, int] | None:
    selected = Path(source).resolve(strict=False)
    paths = build_analysis_paths(source, data_root or default_data_root())
    if not paths.database.is_file():
        return None
    repository = _open_saved_repository(paths.database)
    try:
        root_id = repository.root_id_for_path_key(normalize_path_key(selected))
        if root_id is None or not repository.has_completed_duplicate_run(root_id):
            return None
        return paths.database, len(repository.group_summaries(root_id))
    finally:
        repository.close()


def latest_saved_result(*, data_root: Path | None = None) -> SavedResult | None:
    database_folder = (data_root or default_data_root()) / "databases"
    if not database_folder.is_dir():
        return None

    latest: SavedResult | None = None
    for database in database_folder.glob("*.db"):
        try:
            repository = _open_saved_repository(database)
            try:
                record = repository.latest_completed_result()
            finally:
                repository.close()
        except (OSError, sqlite3.Error, UnsafeDatabaseIdentity):
            continue
        if record is None:
            continue
        source, finished_at, candidate_group_count = record
        result = SavedResult(
            database=database,
            source=Path(source),
            finished_at=finished_at,
            candidate_group_count=candidate_group_count,
        )
        if latest is None or result.finished_at > latest.finished_at:
            latest = result
    return latest


def _open_saved_repository(database: Path) -> DuplicateRepository:
    try:
        return DuplicateRepository.open_readonly(database)
    except sqlite3.DatabaseError:
        upgrader = DuplicateRepository.open(database)
        upgrader.close()
        return DuplicateRepository.open_readonly(database)


def _verify_packaged_ocr_assets() -> tuple[bool, str]:
    """Return whether the frozen application contains every offline OCR file."""

    from archive_analyzer.precision_ocr import bundled_asset_path

    root = bundled_asset_path("ocr")
    manifest_path = root / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False, str(manifest_path)
    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(files, list) or not files:
        return False, str(manifest_path)
    for item in files:
        if not isinstance(item, dict):
            return False, str(manifest_path)
        relative = item.get("path")
        expected = item.get("sha256")
        if not isinstance(relative, str) or not isinstance(expected, str):
            return False, str(manifest_path)
        path = root / relative
        if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            return False, str(path)
    return True, str(root)


def packaged_smoke(database: Path) -> int:
    """Open a copied result DB without scanning its recorded source directory."""

    database = Path(database).resolve(strict=False)
    if not database.is_file():
        print(f"패키지 스모크 DB를 찾을 수 없습니다: {database}")
        return 2
    assets_ok, asset_path = _verify_packaged_ocr_assets()
    if not assets_ok:
        print(f"오프라인 OCR 자원을 확인할 수 없습니다: {asset_path}")
        return 1
    repository: DuplicateRepository | None = None
    try:
        repository = _open_saved_repository(database)
        if repository.schema_version() != LATEST_SCHEMA_VERSION:
            print(
                f"DB schema이 최신이 아닙니다: {repository.schema_version()} "
                f"(필요 {LATEST_SCHEMA_VERSION})"
            )
            return 1
        record = repository.latest_completed_result()
        if record is None:
            print("완료된 저장 결과가 없습니다.")
            return 1
        source, finished_at, candidate_count = record
        root_id = repository.root_id_for_path_key(normalize_path_key(Path(source)))
        if root_id is None:
            print("저장 결과의 검사 루트를 찾을 수 없습니다.")
            return 1
        # These are DB-only reads.  In particular, no archive path is opened.
        group_count = len(repository.group_summaries(root_id))
        print(f"schema={repository.schema_version()}")
        print(f"source={source}")
        print(f"finished_at={finished_at}")
        print(f"candidate_groups={group_count}")
        print(f"recorded_candidate_groups={candidate_count}")
        print(f"ocr_assets={asset_path}")
        return 0
    except (OSError, sqlite3.Error, UnsafeDatabaseIdentity, ValueError) as error:
        print(_friendly_error(error))
        return 1
    finally:
        if repository is not None:
            repository.close()


class _SmokeTrackingReader:
    """Count archive reads during the packaged precision acceptance check."""

    def __init__(self, delegate, allowed_paths: set[Path]) -> None:  # type: ignore[no-untyped-def]
        self._delegate = delegate
        self._allowed_paths = {path.resolve(strict=False) for path in allowed_paths}
        self.archive_paths: list[Path] = []
        self.outside_scope_reads = 0

    def _record(self, snapshot) -> None:  # type: ignore[no-untyped-def]
        path = Path(snapshot.path).resolve(strict=False)
        self.archive_paths.append(path)
        if path not in self._allowed_paths:
            self.outside_scope_reads += 1

    def read(self, snapshot, entry, *, same_path_count: int = 1):  # type: ignore[no-untyped-def]
        self._record(snapshot)
        return self._delegate.read(
            snapshot, entry, same_path_count=same_path_count
        )

    def read_many(self, snapshot, requests, *, cancel_check=None):  # type: ignore[no-untyped-def]
        self._record(snapshot)
        return self._delegate.read_many(
            snapshot, requests, cancel_check=cancel_check
        )


def packaged_review_smoke(database: Path, set_key: str) -> int:
    """Exercise saved-result loading and resumable precision work on a copied DB.

    This deliberately receives only a candidate-set key.  The recorded source
    path is read from the saved result, matching the GUI's ``저장된 결과 열기``
    flow; no folder-selection argument is involved.
    """

    database = Path(database).resolve(strict=False)
    if not database.is_file():
        print(f"패키지 검토 스모크 DB를 찾을 수 없습니다: {database}")
        return 2
    assets_ok, asset_path = _verify_packaged_ocr_assets()
    if not assets_ok:
        print(f"오프라인 OCR 자원을 확인할 수 없습니다: {asset_path}")
        return 1

    repository: DuplicateRepository | None = None
    try:
        repository = DuplicateRepository.open(database)
        if repository.schema_version() != LATEST_SCHEMA_VERSION:
            print(
                f"DB schema이 최신이 아닙니다: {repository.schema_version()} "
                f"(필요 {LATEST_SCHEMA_VERSION})"
            )
            return 1
        saved = repository.latest_completed_result()
        if saved is None:
            print("완료된 저장 결과가 없습니다.")
            return 1
        source, _finished_at, _recorded_count = saved
        root_id = repository.root_id_for_path_key(normalize_path_key(Path(source)))
        if root_id is None:
            print("저장 결과의 검사 루트를 찾을 수 없습니다.")
            return 1

        # Rebuilding is DB-only and makes this acceptance path cover the
        # filename-evidence/current-candidate-set migration as well.
        refresh_recommendations(repository, root_id)
        current_sets = {
            candidate.set_key
            for candidate in repository.review_candidate_sets(root_id)
        }
        if set_key not in current_sets:
            print(f"현재 후보그룹이 아닙니다: {set_key}")
            return 1
        scope = repository.precision_scope_for_sets((set_key,))
        inputs = tuple(
            value
            for batch in repository.iter_analysis_input_batches(
                root_id, archive_ids=scope.archive_ids, include_images=True
            )
            for value in batch
        )
        if len(inputs) < 2 or not all(len(value.images) >= 2 for value in inputs):
            print("검토 스모크에는 두 개 이상의 다중 페이지 후보가 필요합니다.")
            return 1
        allowed_paths = {value.path for value in inputs}

        # Cancel only after the first page cache row is committed.  That makes
        # the following invocation prove real resume behavior rather than just
        # an early pre-flight cancellation.
        cancel_event = threading.Event()
        tracking = _SmokeTrackingReader(
            DispatchingImageReader(
                _DEFAULT_SEVEN_ZIP, timeout_seconds=30 * 60.0
            ),
            allowed_paths,
        )
        original_store_page = repository.store_precision_page
        stored_pages = 0

        def store_and_cancel(record, *, computed_at=None):  # type: ignore[no-untyped-def]
            nonlocal stored_pages
            changed = original_store_page(record, computed_at=computed_at)
            if changed:
                stored_pages += 1
                if stored_pages == 1:
                    cancel_event.set()
            return changed

        repository.store_precision_page = store_and_cancel  # type: ignore[method-assign]
        cancelled = False
        try:
            analyze_precision(
                repository,
                root_id,
                cancel_event,
                set_keys=(set_key,),
                reader=tracking,
            )
        except AnalysisCancelled:
            cancelled = True
        finally:
            repository.store_precision_page = original_store_page  # type: ignore[method-assign]
        if not cancelled or stored_pages < 1:
            print("정밀분석 취소 지점이 페이지 캐시 커밋 뒤에 도달하지 않았습니다.")
            return 1

        resumed_tracking = _SmokeTrackingReader(
            DispatchingImageReader(
                _DEFAULT_SEVEN_ZIP, timeout_seconds=30 * 60.0
            ),
            allowed_paths,
        )
        resumed = analyze_precision(
            repository,
            root_id,
            threading.Event(),
            set_keys=(set_key,),
            reader=resumed_tracking,
        )
        warm_tracking = _SmokeTrackingReader(
            DispatchingImageReader(
                _DEFAULT_SEVEN_ZIP, timeout_seconds=30 * 60.0
            ),
            allowed_paths,
        )
        warm = analyze_precision(
            repository,
            root_id,
            threading.Event(),
            set_keys=(set_key,),
            reader=warm_tracking,
        )
        page_cache_count = int(
            repository._connection.execute(  # noqa: SLF001 - packaged acceptance evidence
                "SELECT COUNT(*) FROM precision_page_cache"
            ).fetchone()[0]
        )
        precision_profile_count = int(
            repository._connection.execute(  # noqa: SLF001 - packaged acceptance evidence
                "SELECT COUNT(*) FROM precision_profiles"
            ).fetchone()[0]
        )
        summary = {
            "schema": repository.schema_version(),
            "candidate_set": set_key,
            "selected_archives": len(inputs),
            "selected_archive_ids": list(scope.archive_ids),
            "cancelled": cancelled,
            "stored_pages_before_cancel": stored_pages,
            "resume_archive_reads": len(resumed_tracking.archive_paths),
            "resume_cache_hits": resumed.page_cache_hits,
            "warm_archive_reads": len(warm_tracking.archive_paths),
            "warm_cache_hits": warm.page_cache_hits,
            "outside_scope_reads": (
                tracking.outside_scope_reads
                + resumed_tracking.outside_scope_reads
                + warm_tracking.outside_scope_reads
            ),
            "page_cache_rows": page_cache_count,
            "precision_profile_rows": precision_profile_count,
            "resume_profiles": resumed.profiles_processed,
            "warm_profiles": warm.profiles_processed,
            "ocr_assets": asset_path,
        }
        summary_json = json.dumps(summary, ensure_ascii=False, sort_keys=True)
        # The onefile GUI build has no console.  Keep the acceptance evidence
        # beside the copied smoke DB so the packaged test can inspect it in
        # either console or windowed mode; this is never the user's DB.
        database.with_name(database.name + ".review-smoke.json").write_text(
            summary_json, encoding="utf-8"
        )
        print("review_smoke=" + summary_json)
        return 0
    except (OSError, sqlite3.Error, UnsafeDatabaseIdentity, ValueError, AnalysisCancelled) as error:
        print(_friendly_error(error))
        return 1
    finally:
        if repository is not None:
            repository.close()


def progress_stage_text(stage: AnalysisStage | None) -> str:
    if stage is None:
        return "1/5 목록 확인"
    if stage is AnalysisStage.ARCHIVE_HASH:
        return "2/5 완전 동일 검사"
    if stage is AnalysisStage.PROBE:
        return "3/5 대표 이미지 검사"
    if stage is AnalysisStage.CANDIDATE_BUILD:
        return "3/5 후보 비교 자료 준비"
    if stage in {AnalysisStage.FULL, AnalysisStage.MATCH}:
        return "4/5 후보 정밀 확인"
    return "5/5 결과 정리"


def cancel_status_text(*, duplicate_started: bool) -> str:
    return "중단 중"


def display_analysis_progress(progress_bar, status_text, progress: AnalysisProgress, *, elapsed: int, cancelling: bool = False) -> None:
    percent = progress.percent
    progress_bar.configure(mode="determinate", maximum=100, value=percent or 0)
    lines = [f"{progress_stage_text(progress.stage)} · 진행 중", progress.phase]
    if progress.total is None:
        lines.append(f"처리 {progress.completed:,} {progress.unit} · 전체 수 확인 중")
    else:
        lines.append(f"현재 작업 {progress.completed:,}/{progress.total:,} {progress.unit} · {percent:.1f}%")
    if progress.detail:
        lines.append(progress.detail)
    if progress.current_item:
        name = progress.current_item.replace("\n", " ").replace("\r", " ")
        lines.append(name if len(name) <= 100 else name[:70] + " … " + name[-25:])
    lines.append(f"경과 {elapsed // 60:02d}:{elapsed % 60:02d}")
    if cancelling:
        lines.insert(0, "중단 중")
    status_text.set("\n".join(lines))


def launch_gui() -> int:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    window = tk.Tk()
    from archive_analyzer.ui_theme import apply_review_theme
    apply_review_theme(window)
    window.title(f"{_WINDOW_TITLE} v{__version__}")
    window.geometry("780x520")
    window.minsize(720, 480)
    from archive_analyzer.update_ui import UpdateController
    updater = UpdateController(window)

    selected_source = tk.StringVar(value="")
    status_text = tk.StringVar(
        value=(
            "이전 검사가 끝났다면 바로 '저장된 결과 열기'를 눌러 주세요.\n"
            "새 검사를 시작할 때만 폴더를 선택합니다."
        )
    )
    running = False
    started_at = 0.0
    active_database: Path | None = None
    active_cancel_event: threading.Event | None = None
    analysis_phase = "idle"
    completion_queue: Queue[tuple[AnalysisResult | None, BaseException | None]] = Queue()
    phase_queue: Queue[str] = Queue()
    progress_mailbox = ProgressMailbox()
    review_windows: list[ReviewWindow] = []

    def open_review(database, source):
        review = ReviewWindow(window, database, source, on_close=window.deiconify)
        # One visible workspace: return to the scanner when review closes.
        review._window.geometry(window.geometry() if window.winfo_width() >= 1000 else "1440x960")
        window.withdraw()
        review_windows.append(review)
        updater.attach_menu(review._window, close_window)
        updater.attach_status(review._window)
        return review
    progress_reader: ProgressReader | None = None
    latest_progress: ProgressSnapshot | None = None
    completion_waiting: tuple[AnalysisResult | None, BaseException | None] | None = None

    body = ttk.Frame(window, padding=24)
    body.pack(fill="both", expand=True)
    ttk.Label(body, text="압축파일 중복 후보 검사", font=("Malgun Gothic", 18, "bold")).pack(
        anchor="w"
    )
    ttk.Label(
        body,
        text="ZIP · CBZ · RAR · 7z의 목록과 이미지 특징을 읽어 중복 후보를 찾습니다.",
    ).pack(anchor="w", pady=(4, 20))

    path_frame = ttk.Frame(body)
    path_frame.pack(fill="x")
    path_entry = ttk.Entry(path_frame, textvariable=selected_source, state="readonly")
    path_entry.pack(side="left", fill="x", expand=True)

    action_frame = ttk.Frame(body)
    action_frame.pack(fill="x", pady=(12, 18))
    progress_bar = ttk.Progressbar(body, mode="determinate", maximum=100)
    progress_bar.pack(fill="x", pady=(0, 16))
    status_label = ttk.Label(body, textvariable=status_text, justify="left", wraplength=700)
    status_label.pack(fill="x", anchor="w")

    def choose_folder() -> None:
        if running:
            return
        chosen = filedialog.askdirectory(title="검사할 압축파일 폴더 선택")
        if chosen:
            selected_source.set(chosen)
            start_button.configure(state="normal")
            saved_results_button.configure(state="normal")
            status_text.set(
                "기존 분석은 '저장된 결과 열기', 새 검사는 '검사 시작'을 눌러 주세요."
            )

    choose_button = ttk.Button(path_frame, text="폴더 선택", command=choose_folder)
    choose_button.pack(side="left", padx=(10, 0))

    def drain_phase_updates() -> None:
        nonlocal analysis_phase
        while True:
            try:
                analysis_phase = phase_queue.get_nowait()
            except Empty:
                return

    def show_progress() -> None:
        nonlocal latest_progress
        if not running:
            return
        drain_phase_updates()
        elapsed = int(monotonic() - started_at)
        duplicate_started = analysis_phase == "duplicate"
        live_progress = progress_mailbox.latest() if duplicate_started else None
        if progress_reader is not None:
            while True:
                result = progress_reader.poll_result()
                if result is None:
                    break
                if result.snapshot is not None:
                    latest_progress = result.snapshot
            if active_database is not None and live_progress is None:
                progress_reader.submit(
                    active_database, duplicate_started=duplicate_started
                )
        snapshot = (
            latest_progress
            if latest_progress is not None
            and latest_progress.duplicate_started == duplicate_started
            else ProgressSnapshot(
                duplicate_started=duplicate_started,
                stage=AnalysisStage.ARCHIVE_HASH if duplicate_started else None,
                archive_processed=0,
                archive_total=0,
                image_processed=0,
                image_total=0,
            )
        )
        display_analysis_progress(
            progress_bar, status_text,
            live_progress or AnalysisProgress(
                snapshot.stage, "검사 대상 확인" if duplicate_started else "압축파일 목록 확인",
                snapshot.archive_processed, snapshot.archive_total or None,
                unit="쌍" if snapshot.stage is AnalysisStage.MATCH else "파일",
            ),
            elapsed=elapsed,
            cancelling=active_cancel_event is not None and active_cancel_event.is_set(),
        )
        window.after(500, show_progress)

    def finish(result: AnalysisResult | None, error: BaseException | None) -> None:
        nonlocal running, active_cancel_event, analysis_phase
        running = False
        active_cancel_event = None
        analysis_phase = "idle"
        choose_button.configure(state="normal")
        start_button.configure(state="normal")
        saved_results_button.configure(state="normal")
        cancel_button.configure(state="disabled")
        if isinstance(error, AnalysisCancelled):
            message = "분석을 안전하게 중단했습니다. 지금까지의 기록은 다음 검사에서 재사용됩니다."
            status_text.set(message)
            messagebox.showinfo(_WINDOW_TITLE, message)
            return
        if error is not None:
            message = _friendly_error(error)
            status_text.set(f"분석을 완료하지 못했습니다.\n{message}")
            messagebox.showerror(_WINDOW_TITLE, message)
            return

        assert result is not None
        progress_bar.configure(value=100)
        scan = result.scan_summary
        duplicate = result.duplicate_summary
        completion = (
            f"분석 완료 · 발견 {scan.discovered_count:,}개 · "
            f"새로 판독 {scan.indexed_count:,}개 · "
            f"이전 결과 재사용 {scan.reused_count:,}개 · "
            f"중복 후보 {result.candidate_group_count:,}개 그룹"
        )
        issue_count = scan.skipped_count + scan.failed_count + duplicate.failed_archives
        if issue_count or not scan.discovery_complete:
            completion += (
                f"\n읽지 못했거나 건너뛴 파일 {issue_count:,}개가 있습니다. "
                "나머지 파일의 분석 결과는 정상적으로 저장됐습니다."
            )
        status_text.set(completion)
        if result.candidate_group_count == 0:
            messagebox.showinfo(_WINDOW_TITLE, "중복 후보가 발견되지 않았습니다")
            return
        try:
            open_review(result.database, Path(selected_source.get()))
        except BaseException as review_error:
            message = _friendly_error(review_error)
            messagebox.showerror(
                _WINDOW_TITLE,
                f"분석은 완료됐지만 후보 검토 창을 열지 못했습니다. {message}",
            )

    def work(source: Path, cancel_event: threading.Event) -> None:
        try:
            result = run_analysis(
                source,
                cancel_event=cancel_event,
                phase_callback=phase_queue.put,
                progress_callback=progress_mailbox.publish,
            )
        except BaseException as error:
            completion_queue.put((None, error))
        else:
            completion_queue.put((result, None))

    def finish_when_progress_reader_closed() -> None:
        nonlocal progress_reader, completion_waiting
        if completion_waiting is None:
            return
        if progress_reader is not None:
            if progress_reader.is_alive():
                window.after(25, finish_when_progress_reader_closed)
                return
            progress_reader.close(timeout=0)
            progress_reader = None
        result, error = completion_waiting
        completion_waiting = None
        finish(result, error)

    def poll_completion() -> None:
        nonlocal completion_waiting
        if not running:
            return
        drain_phase_updates()
        try:
            result, error = completion_queue.get_nowait()
        except Empty:
            window.after(100, poll_completion)
            return
        completion_waiting = (result, error)
        if progress_reader is not None:
            progress_reader.request_close()
        finish_when_progress_reader_closed()

    def start_scan() -> None:
        nonlocal running, started_at, active_database, active_cancel_event
        nonlocal analysis_phase, progress_reader, latest_progress, completion_waiting
        if running:
            return
        source = Path(selected_source.get())
        try:
            preview_paths = build_analysis_paths(source, default_data_root())
        except (InvalidSelection, OSError) as error:
            messagebox.showerror(_WINDOW_TITLE, _friendly_error(error))
            return
        progress_reader = ProgressReader()
        progress_reader.start()
        latest_progress = None
        progress_mailbox.clear()
        completion_waiting = None
        running = True
        started_at = monotonic()
        active_database = preview_paths.database
        active_cancel_event = threading.Event()
        analysis_phase = "scan"
        choose_button.configure(state="disabled")
        start_button.configure(state="disabled")
        saved_results_button.configure(state="disabled")
        cancel_button.configure(state="normal")
        progress_bar.configure(value=0)
        status_text.set(progress_stage_text(None))
        threading.Thread(
            target=work,
            args=(source, active_cancel_event),
            name="archive-analyzer-analysis",
            daemon=False,
        ).start()
        poll_completion()
        show_progress()

    def open_saved_results() -> None:
        if running:
            return
        source_text = selected_source.get().strip()
        try:
            if source_text:
                source = Path(source_text)
                saved = completed_result(source)
                if saved is None:
                    result = None
                else:
                    database, group_count = saved
                    result = SavedResult(database, source, "", group_count)
            else:
                result = latest_saved_result()
        except (InvalidSelection, OSError, sqlite3.Error, UnsafeDatabaseIdentity) as error:
            messagebox.showerror(_WINDOW_TITLE, _friendly_error(error))
            return
        if result is None:
            messagebox.showinfo(_WINDOW_TITLE, "저장된 완료 결과가 없습니다.")
            return
        if result.candidate_group_count == 0:
            messagebox.showinfo(_WINDOW_TITLE, "저장된 분석 결과에 중복 후보가 없습니다.")
            return
        selected_source.set(str(result.source))
        start_button.configure(state="normal")
        try:
            open_review(result.database, result.source)
        except BaseException as error:
            messagebox.showerror(_WINDOW_TITLE, _friendly_error(error))
            return
        status_text.set(
            f"저장된 중복 후보 {result.candidate_group_count:,}개 그룹을 열었습니다.\n"
            f"{result.source}"
        )

    def cancel_analysis() -> None:
        if not running or active_cancel_event is None or active_cancel_event.is_set():
            return
        active_cancel_event.set()
        cancel_button.configure(state="disabled")
        status_text.set(
            cancel_status_text(duplicate_started=analysis_phase == "duplicate")
        )

    start_button = ttk.Button(action_frame, text="검사 시작", command=start_scan)
    start_button.pack(side="left")
    start_button.configure(state="disabled")
    saved_results_button = ttk.Button(
        action_frame, text="저장된 결과 열기", command=open_saved_results
    )
    saved_results_button.pack(side="left", padx=(10, 0))
    cancel_button = ttk.Button(
        action_frame,
        text="분석 중단",
        command=cancel_analysis,
        state="disabled",
    )
    cancel_button.pack(side="left", padx=(10, 0))

    def finish_close() -> None:
        if any(not review.is_closed() for review in review_windows):
            window.after(100, finish_close)
            return
        updater.close()
        window.destroy()

    def close_window() -> None:
        if running:
            messagebox.showinfo(
                _WINDOW_TITLE,
                "분석이 진행 중입니다. '분석 중단'을 누른 뒤 안전하게 중단될 때까지 기다려 주세요.",
            )
            return
        active_reviews = [review for review in review_windows if not review.is_closed()]
        if active_reviews:
            for review in active_reviews:
                review.request_close()
            status_text.set("검토 기록 저장소를 닫는 중입니다...")
            window.after(100, finish_close)
            return
        updater.close()
        window.destroy()

    updater.attach_menu(window, close_window)
    updater.attach_status(window)
    window.protocol("WM_DELETE_WINDOW", close_window)
    window.mainloop()
    return 0


def _friendly_error(error: BaseException) -> str:
    if isinstance(error, AnalysisCancelled):
        return "분석을 안전하게 중단했습니다."
    if isinstance(error, InvalidSelection):
        return str(error)
    if isinstance(error, ScanAlreadyRunning):
        return "같은 폴더의 검사가 이미 실행 중입니다. 기존 검사 창을 확인해 주세요."
    if isinstance(error, UnsafeDatabaseIdentity):
        return "검사 기록 파일의 안전성을 확인할 수 없습니다. 개발자에게 이 화면을 보여 주세요."
    if isinstance(error, sqlite3.Error):
        return "검사 기록을 저장하거나 읽지 못했습니다. 잠시 후 다시 실행해 주세요."
    if isinstance(error, OSError):
        return "폴더나 파일에 접근하지 못했습니다. 경로와 권한을 확인해 주세요."
    return "예기치 않은 오류가 발생했습니다. 프로그램을 다시 실행해 주세요."


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--headless-source", metavar="PATH")
    parser.add_argument("--data-root", metavar="PATH")
    parser.add_argument("--packaged-smoke", metavar="DB")
    parser.add_argument("--packaged-ui-smoke", nargs=2, metavar=("DB", "SOURCE"))
    parser.add_argument(
        "--packaged-review-smoke",
        nargs=2,
        metavar=("DB", "SET_KEY"),
        help="저장 결과 DB와 현재 후보그룹 키로 패키지 검토·재개 경로를 확인합니다.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    if arguments.packaged_ui_smoke is not None:
        from archive_analyzer.ui_smoke import run
        return run(*(Path(value) for value in arguments.packaged_ui_smoke))
    if arguments.packaged_review_smoke is not None:
        if arguments.packaged_smoke is not None or arguments.headless_source is not None:
            print(
                "--packaged-review-smoke는 다른 패키지 스모크 또는 --headless-source와 함께 사용할 수 없습니다."
            )
            return 2
        database, set_key = arguments.packaged_review_smoke
        return packaged_review_smoke(Path(database), set_key)
    if arguments.packaged_smoke is not None:
        if arguments.headless_source is not None:
            print("--packaged-smoke와 --headless-source는 함께 사용할 수 없습니다.")
            return 2
        return packaged_smoke(Path(arguments.packaged_smoke))
    if arguments.headless_source is None:
        return launch_gui()
    try:
        result = run_analysis(
            Path(arguments.headless_source),
            data_root=None if arguments.data_root is None else Path(arguments.data_root),
        )
    except BaseException as error:
        print(_friendly_error(error))
        return 1
    print(f"database={result.database}")
    print(f"candidate_groups={result.candidate_group_count}")
    print(f"failed_archives={result.duplicate_summary.failed_archives}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
