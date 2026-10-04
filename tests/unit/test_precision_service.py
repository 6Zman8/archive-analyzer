from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
import inspect
from io import BytesIO
from pathlib import Path
from threading import Event

import pytest
from PIL import Image
from rapidocr import EngineType, ModelType, OCRVersion, RapidOCR
from rapidocr.main import TextRecOutput

import archive_analyzer.precision_analysis as precision_analysis
import archive_analyzer.precision_service as precision_service
from archive_analyzer.archive_hashing import AnalysisCancelled
from archive_analyzer.precision_ocr import BundledRapidOcrBackend, OcrUnavailable
from archive_analyzer.precision_service import (
    PRECISION_ALGORITHM_VERSION,
    PrecisionProgress,
    analyze_precision,
)
from archive_analyzer.storage.duplicate_repository import (
    DuplicateRepository,
    ReviewCandidateSet,
)


class FakeReader:
    def __init__(self, payload: bytes, *, cancel_event: Event | None = None, cancel_on_call: int | None = None) -> None:
        self.payload = payload
        self.cancel_event = cancel_event
        self.cancel_on_call = cancel_on_call
        self.calls = 0

    def read_many(
        self, _snapshot, requests, *, cancel_check=None
    ) -> Iterator[bytes]:  # type: ignore[no-untyped-def]
        for _request in requests:
            if cancel_check is not None:
                cancel_check()
            self.calls += 1
            if self.cancel_event is not None and self.calls == self.cancel_on_call:
                self.cancel_event.set()
            if cancel_check is not None:
                cancel_check()
            yield self.payload


class FakeOcr:
    def __init__(self, texts: tuple[str, ...] = ("sample text",)) -> None:
        self.texts = texts
        self.calls = 0

    def recognize(
        self, _payload: bytes, *, language_hints: frozenset[str] = frozenset()
    ) -> tuple[str, float]:
        text = self.texts[self.calls % len(self.texts)]
        self.calls += 1
        return text, 0.9


class UnavailableOcr:
    def __init__(self) -> None:
        self.calls = 0

    def recognize(
        self, _payload: bytes, *, language_hints: frozenset[str] = frozenset()
    ) -> tuple[str, float]:
        self.calls += 1
        raise OcrUnavailable("models unavailable")


class PartiallyUnavailableOcr:
    def __init__(self) -> None:
        self.calls = 0

    def recognize(
        self, _payload: bytes, *, language_hints: frozenset[str] = frozenset()
    ) -> tuple[str, float]:
        self.calls += 1
        if self.calls == 3:
            raise OcrUnavailable("backend failed")
        return "안녕하세요\n오늘도 반갑습니다", 0.9


def _analyze_precision(repository, root_id, cancel_event, **kwargs):  # type: ignore[no-untyped-def]
    return analyze_precision(
        repository,
        root_id,
        cancel_event,
        set_keys=("precision-set",),
        **kwargs,
     compare_images=True)


def test_bundled_ocr_refuses_missing_assets_without_fallback(tmp_path: Path) -> None:
    backend = BundledRapidOcrBackend(tmp_path)

    with pytest.raises(OcrUnavailable, match="Bundled OCR assets are missing"):
        backend.recognize(_encoded_page())


def test_bundled_ocr_uses_rapidocr_enum_configuration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for filename in (
        "PP-OCRv6_det_tiny.onnx",
        "ch_PP-OCRv5_rec_mobile.onnx",
        "ppocrv5_dict.txt",
        "korean_PP-OCRv5_rec_mobile.onnx",
        "ppocrv5_korean_dict.txt",
    ):
        (tmp_path / filename).write_bytes(b"test-only")

    seen_params: list[dict[str, object]] = []

    class CapturingRapidOcr:
        def __init__(self, *, params: dict[str, object]) -> None:
            seen_params.append(params)

        def preprocess_img(self, image):  # type: ignore[no-untyped-def]
            return image, {}

        def detect_and_crop(self, image, _record):  # type: ignore[no-untyped-def]
            return [image], object()

        def recognize_txt(self, _images):  # type: ignore[no-untyped-def]
            return type("Result", (), {"txts": (), "scores": ()})()

    import rapidocr

    monkeypatch.setattr(rapidocr, "RapidOCR", CapturingRapidOcr)
    assert BundledRapidOcrBackend(tmp_path).recognize(_encoded_page()) == ("", 0.0)
    assert len(seen_params) == 2
    assert all(params["Det.engine_type"] is EngineType.ONNXRUNTIME for params in seen_params)
    assert all(params["Rec.engine_type"] is EngineType.ONNXRUNTIME for params in seen_params)
    assert all(params["Det.model_type"] is ModelType.TINY for params in seen_params)
    assert all(params["Rec.model_type"] is ModelType.MOBILE for params in seen_params)
    assert all(params["Det.ocr_version"] is OCRVersion.PPOCRV6 for params in seen_params)
    assert all(params["Rec.ocr_version"] is OCRVersion.PPOCRV5 for params in seen_params)
    assert all(params["Global.max_side_len"] == 1600 for params in seen_params)


def test_bundled_ocr_preserves_each_accepted_line(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for filename in (
        "PP-OCRv6_det_tiny.onnx",
        "ch_PP-OCRv5_rec_mobile.onnx",
        "ppocrv5_dict.txt",
        "korean_PP-OCRv5_rec_mobile.onnx",
        "ppocrv5_korean_dict.txt",
    ):
        (tmp_path / filename).write_bytes(b"test-only")

    class LineRapidOcr:
        def __init__(self, *, params: dict[str, object]) -> None:
            self._language = params["Rec.lang_type"]

        def preprocess_img(self, image):  # type: ignore[no-untyped-def]
            return image, {}

        def detect_and_crop(self, image, _record):  # type: ignore[no-untyped-def]
            return [image], object()

        def recognize_txt(self, _images):  # type: ignore[no-untyped-def]
            texts = ("中文", "공통") if self._language == "ch" else ("한국어", "공통")
            return type("Result", (), {"txts": texts, "scores": (0.9, 0.8)})()

    import rapidocr

    monkeypatch.setattr(rapidocr, "RapidOCR", LineRapidOcr)
    assert BundledRapidOcrBackend(tmp_path).recognize(_encoded_page()) == (
        "中文\n공통\n한국어\n공통",
        pytest.approx(0.85),
    )


def test_bundled_ocr_detects_once_and_routes_clear_korean_hint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for filename in (
        "PP-OCRv6_det_tiny.onnx",
        "ch_PP-OCRv5_rec_mobile.onnx",
        "ppocrv5_dict.txt",
        "korean_PP-OCRv5_rec_mobile.onnx",
        "ppocrv5_korean_dict.txt",
    ):
        (tmp_path / filename).write_bytes(b"test-only")
    calls = {"preprocess": 0, "detect": 0, "ch": 0, "korean": 0}

    class RoutingRapidOcr:
        def __init__(self, *, params: dict[str, object]) -> None:
            self.language = str(params["Rec.lang_type"])

        def preprocess_img(self, image):  # type: ignore[no-untyped-def]
            calls["preprocess"] += 1
            return image, {}

        def detect_and_crop(self, image, _record):  # type: ignore[no-untyped-def]
            calls["detect"] += 1
            return [image], object()

        def recognize_txt(self, _images):  # type: ignore[no-untyped-def]
            calls[self.language] += 1
            return type("Result", (), {"txts": (self.language,), "scores": (0.9,)})()

    import rapidocr

    monkeypatch.setattr(rapidocr, "RapidOCR", RoutingRapidOcr)
    backend = BundledRapidOcrBackend(tmp_path)

    assert backend.recognize(
        _encoded_page(), language_hints=frozenset({"KO"})
    )[0] == "korean"
    assert calls == {"preprocess": 1, "detect": 1, "ch": 0, "korean": 1}


def test_bundled_ocr_unknown_language_shares_detection_for_both_recognizers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for filename in (
        "PP-OCRv6_det_tiny.onnx",
        "ch_PP-OCRv5_rec_mobile.onnx",
        "ppocrv5_dict.txt",
        "korean_PP-OCRv5_rec_mobile.onnx",
        "ppocrv5_korean_dict.txt",
    ):
        (tmp_path / filename).write_bytes(b"test-only")
    calls = {"preprocess": 0, "detect": 0, "recognize": 0}

    class SharedDetectionRapidOcr:
        def __init__(self, *, params: dict[str, object]) -> None:
            self.language = str(params["Rec.lang_type"])

        def preprocess_img(self, image):  # type: ignore[no-untyped-def]
            calls["preprocess"] += 1
            return image, {}

        def detect_and_crop(self, image, _record):  # type: ignore[no-untyped-def]
            calls["detect"] += 1
            return [image], object()

        def recognize_txt(self, _images):  # type: ignore[no-untyped-def]
            calls["recognize"] += 1
            return type("Result", (), {"txts": (self.language,), "scores": (0.9,)})()

    import rapidocr

    monkeypatch.setattr(rapidocr, "RapidOCR", SharedDetectionRapidOcr)

    BundledRapidOcrBackend(tmp_path).recognize(_encoded_page())
    assert calls == {"preprocess": 1, "detect": 1, "recognize": 2}


def test_pinned_rapidocr_private_contract_is_available() -> None:
    assert tuple(inspect.signature(RapidOCR.preprocess_img).parameters) == (
        "self",
        "ori_img",
    )
    assert tuple(inspect.signature(RapidOCR.detect_and_crop).parameters) == (
        "self",
        "img",
        "op_record",
    )
    assert tuple(inspect.signature(RapidOCR.recognize_txt).parameters) == (
        "self",
        "img",
    )
    assert {"txts", "scores"} <= set(TextRecOutput.__annotations__)


def test_precision_service_rejects_empty_implicit_root_scope(tmp_path: Path) -> None:
    repository, root_id, _archive_ids = _repository_with_images(tmp_path, (3, 3))
    reader = FakeReader(_encoded_page())
    try:
        with pytest.raises(ValueError, match="candidate set"):
            analyze_precision(
                repository,
                root_id,
                Event(),
                set_keys=(),
                reader=reader,
                ocr=FakeOcr(),
             compare_images=True)
        assert reader.calls == 0
    finally:
        repository.close()


def test_completed_page_cache_prevents_reader_ocr_and_metric_repetition(
    tmp_path: Path,
) -> None:
    repository, root_id, _archive_ids = _repository_with_images(tmp_path, (8, 8))
    first_reader = FakeReader(_encoded_page())
    first_ocr = FakeOcr()
    try:
        _analyze_precision(
            repository, root_id, Event(), reader=first_reader, ocr=first_ocr
        )
        repository._connection.execute(  # noqa: SLF001 - force profile rebuild from page cache
            "DELETE FROM precision_profiles"
        )
        repository._connection.commit()  # noqa: SLF001 - fixture mutation
        second_reader = FakeReader(_encoded_page())
        second_ocr = FakeOcr()

        resumed = _analyze_precision(
            repository, root_id, Event(), reader=second_reader, ocr=second_ocr
        )

        assert first_reader.calls > 0
        assert second_reader.calls == 0
        assert second_ocr.calls == 0
        assert resumed.page_cache_hits > 0
        assert resumed.profiles_processed == 2
    finally:
        repository.close()


def test_precision_service_reuses_completed_snapshots_and_caps_samples(tmp_path: Path) -> None:
    repository, root_id, _archive_ids = _repository_with_images(tmp_path, (15, 15))
    reader = FakeReader(_encoded_page())
    ocr = FakeOcr()
    progress: list[PrecisionProgress] = []
    try:
        first = _analyze_precision(
            repository, root_id, Event(), reader=reader, ocr=ocr, progress=progress.append
        )
        second = _analyze_precision(repository, root_id, Event(), reader=reader, ocr=ocr)

        assert first.profiles_processed == 2
        assert second.profiles_processed == 0
        assert reader.calls == 12
        assert ocr.calls == 12
        assert {item.phase for item in progress} == {
            "precision_pages",
            "precision_relations",
        }
        assert any(
            item.phase == "precision_pages"
            and item.archive_total == 2
            and item.current_name
            for item in progress
        )
        assert progress[-1].current == progress[-1].total
        assert progress[-1].eta_seconds in (0.0, None)
    finally:
        repository.close()


def test_precision_service_preserves_page_lines_for_korean_majority(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_images(tmp_path, (3,))
    ocr = FakeOcr(
        (
            "안녕하세요\n오늘도 반갑습니다",
            "지금 출발합니다\n조심해서 오세요",
            "かなかな\nカナカナ",
        )
    )
    try:
        _analyze_precision(repository, root_id, Event(), reader=FakeReader(_encoded_page()), ocr=ocr)

        row = repository._connection.execute(  # noqa: SLF001 - persisted service contract
            "SELECT language, sample_count FROM precision_profiles WHERE archive_id = ?",
            (archive_ids[0],),
        ).fetchone()
        assert row == ("KOREAN", 3)
    finally:
        repository.close()


def test_precision_service_keeps_completed_file_when_cancelled_and_resumes(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_images(tmp_path, (1, 1))
    cancel_event = Event()
    cancelling_reader = FakeReader(_encoded_page(), cancel_event=cancel_event, cancel_on_call=2)
    try:
        with pytest.raises(AnalysisCancelled):
            _analyze_precision(
                repository,
                root_id,
                cancel_event,
                reader=cancelling_reader,
                ocr=FakeOcr(),
            )

        assert repository.completed_precision_archive_ids(
            root_id, algorithm_version=PRECISION_ALGORITHM_VERSION
        ) == (archive_ids[0],)

        resumed_ocr = FakeOcr()
        resumed = _analyze_precision(
            repository,
            root_id,
            Event(),
            reader=FakeReader(_encoded_page()),
            ocr=resumed_ocr,
        )
        assert resumed.profiles_processed == 1
        assert resumed_ocr.calls == 1
    finally:
        repository.close()


def test_cancelled_run_resumes_from_committed_page_cache(tmp_path: Path) -> None:
    repository, root_id, _archive_ids = _repository_with_images(tmp_path, (8,))
    cancel_event = Event()
    interrupted_reader = FakeReader(
        _encoded_page(), cancel_event=cancel_event, cancel_on_call=3
    )
    try:
        with pytest.raises(AnalysisCancelled):
            _analyze_precision(
                repository,
                root_id,
                cancel_event,
                reader=interrupted_reader,
                ocr=FakeOcr(),
            )

        assert repository._connection.execute(  # noqa: SLF001 - resume contract
            "SELECT COUNT(*) FROM precision_page_cache WHERE state = 'SUCCEEDED'"
        ).fetchone()[0] == 2
        resumed_reader = FakeReader(_encoded_page())
        resumed = _analyze_precision(
            repository,
            root_id,
            Event(),
            reader=resumed_reader,
            ocr=FakeOcr(),
        )

        assert resumed.profiles_processed == 1
        assert resumed.page_cache_hits >= 2
        assert resumed_reader.calls == 4
    finally:
        repository.close()


def test_precision_service_stops_after_ocr_cancellation(tmp_path: Path) -> None:
    repository, root_id, _archive_ids = _repository_with_images(tmp_path, (1,))
    cancel_event = Event()

    class CancellingOcr:
        def recognize(
            self, _payload: bytes, *, language_hints: frozenset[str] = frozenset()
        ) -> tuple[str, float]:
            cancel_event.set()
            return "sample text", 0.9

    try:
        with pytest.raises(AnalysisCancelled):
            _analyze_precision(
                repository,
                root_id,
                cancel_event,
                reader=FakeReader(_encoded_page()),
                ocr=CancellingOcr(),
            )

        assert repository.completed_precision_archive_ids(
            root_id, algorithm_version=PRECISION_ALGORITHM_VERSION
        ) == ()
    finally:
        repository.close()


def test_precision_service_stops_after_profile_metric_cancellation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repository, root_id, _archive_ids = _repository_with_images(tmp_path, (1,))
    cancel_event = Event()
    metric_calls = 0
    original = precision_service.page_quality_metrics

    def cancelling_metric(page):  # type: ignore[no-untyped-def]
        nonlocal metric_calls
        metric_calls += 1
        cancel_event.set()
        return original(page)

    monkeypatch.setattr(precision_service, "page_quality_metrics", cancelling_metric)
    try:
        with pytest.raises(AnalysisCancelled):
            _analyze_precision(
                repository,
                root_id,
                cancel_event,
                reader=FakeReader(_encoded_page()),
                ocr=FakeOcr(),
            )

        assert metric_calls == 1
        assert repository.completed_precision_archive_ids(
            root_id, algorithm_version=PRECISION_ALGORITHM_VERSION
        ) == ()
    finally:
        repository.close()


def test_precision_service_stores_metrics_when_ocr_is_unavailable(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_images(tmp_path, (2,))
    unavailable = UnavailableOcr()
    try:
        summary = _analyze_precision(
            repository,
            root_id,
            Event(),
            reader=FakeReader(_encoded_page()),
            ocr=unavailable,
        )

        row = repository._connection.execute(  # noqa: SLF001 - persisted service contract
            "SELECT state, sample_count, language, error_code, page_metrics_json "
            "FROM precision_profiles WHERE archive_id = ?",
            (archive_ids[0],),
        ).fetchone()
        assert row[:4] == ("SUCCEEDED", 2, "UNKNOWN", "OCR_UNAVAILABLE")
        assert row[4] != "[]"
        assert unavailable.calls == 1
        assert summary.failed_profiles == 0
    finally:
        repository.close()


def test_precision_service_marks_partial_ocr_backend_failure_unknown(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_images(tmp_path, (3,))
    try:
        _analyze_precision(
            repository,
            root_id,
            Event(),
            reader=FakeReader(_encoded_page()),
            ocr=PartiallyUnavailableOcr(),
        )

        assert repository._connection.execute(  # noqa: SLF001 - persisted failure contract
            "SELECT language, language_confidence, error_code FROM precision_profiles "
            "WHERE archive_id = ?",
            (archive_ids[0],),
        ).fetchone() == ("UNKNOWN", 0.0, "OCR_UNAVAILABLE")
    finally:
        repository.close()


def test_precision_relations_use_exact_same_index_fallback_and_cache(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_images(tmp_path, (3, 3))
    connection = repository._connection  # noqa: SLF001 - relation fixture
    connection.execute(
        "INSERT INTO candidate_relations(scan_root_id, archive_a_id, archive_b_id, relation, "
        "confidence, matched_pages, left_pages, right_pages, recommendation, evidence_json, "
        "analyzer_version, created_at) VALUES (?, ?, ?, 'EXACT_CONTENT', 1.0, 3, 3, 3, '', '[]', 1, ?)",
        (root_id, archive_ids[0], archive_ids[1], "2026-09-02T00:00:00+00:00"),
    )
    connection.commit()
    reader = FakeReader(_encoded_page())
    try:
        first = _analyze_precision(repository, root_id, Event(), reader=reader, ocr=FakeOcr())
        first_calls = reader.calls
        second = _analyze_precision(repository, root_id, Event(), reader=reader, ocr=FakeOcr())

        relation = connection.execute(
            "SELECT mosaic_direction, quality_direction FROM precision_relations"
        ).fetchone()
        assert relation == ("TIE", "TIE")
        assert first.relations_processed == 1
        assert second.relations_processed == 0
        assert reader.calls == first_calls
    finally:
        repository.close()


def test_precision_relation_stops_after_first_metric_cancellation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repository, root_id, archive_ids = _repository_with_images(tmp_path, (3, 3))
    connection = repository._connection  # noqa: SLF001 - relation fixture
    try:
        _analyze_precision(
            repository, root_id, Event(), reader=FakeReader(_encoded_page()), ocr=FakeOcr()
        )
        _insert_visual_relation(connection, root_id, archive_ids[0], archive_ids[1], 3)
        connection.execute("DELETE FROM precision_page_cache")
        connection.commit()
        cancel_event = Event()
        metric_calls = 0
        original = precision_analysis.page_quality_metrics

        def cancelling_metric(page):  # type: ignore[no-untyped-def]
            nonlocal metric_calls
            metric_calls += 1
            cancel_event.set()
            return original(page)

        monkeypatch.setattr(precision_analysis, "page_quality_metrics", cancelling_metric)
        monkeypatch.setattr(
            precision_service, "page_quality_metrics", cancelling_metric, raising=False
        )
        with pytest.raises(AnalysisCancelled):
            _analyze_precision(
                repository,
                root_id,
                cancel_event,
                reader=FakeReader(_encoded_page()),
                ocr=FakeOcr(),
            )

        assert metric_calls == 1
        assert connection.execute("SELECT COUNT(*) FROM precision_relations").fetchone()[0] == 0
    finally:
        repository.close()


def test_precision_relation_stops_after_comparison_cancellation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repository, root_id, archive_ids = _repository_with_images(tmp_path, (3, 3))
    connection = repository._connection  # noqa: SLF001 - relation fixture
    try:
        _analyze_precision(
            repository, root_id, Event(), reader=FakeReader(_encoded_page()), ocr=FakeOcr()
        )
        _insert_visual_relation(connection, root_id, archive_ids[0], archive_ids[1], 3)
        cancel_event = Event()
        comparison_calls = 0

        def cancelling_mosaic(_left_metrics, _right_metrics):  # type: ignore[no-untyped-def]
            nonlocal comparison_calls
            comparison_calls += 1
            cancel_event.set()
            return precision_analysis.PairComparison(
                precision_analysis.PairDirection.UNKNOWN, 0.0, ("cancelled",)
            )

        monkeypatch.setattr(
            precision_service, "compare_mosaic_metrics", cancelling_mosaic, raising=False
        )
        with pytest.raises(AnalysisCancelled):
            _analyze_precision(
                repository,
                root_id,
                cancel_event,
                reader=FakeReader(_encoded_page()),
                ocr=FakeOcr(),
            )

        assert comparison_calls == 1
        assert connection.execute("SELECT COUNT(*) FROM precision_relations").fetchone()[0] == 0
    finally:
        repository.close()


def test_precision_relation_cancellation_keeps_completed_pair_and_resumes(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_images(tmp_path, (1, 1, 1))
    connection = repository._connection  # noqa: SLF001 - relation fixture
    try:
        _analyze_precision(
            repository, root_id, Event(), reader=FakeReader(_encoded_page()), ocr=FakeOcr()
        )
        _insert_visual_relation(connection, root_id, archive_ids[0], archive_ids[1], 1)
        _insert_visual_relation(connection, root_id, archive_ids[1], archive_ids[2], 1)
        connection.execute("DELETE FROM precision_page_cache")
        connection.commit()
        cancel_event = Event()

        with pytest.raises(AnalysisCancelled):
            _analyze_precision(
                repository,
                root_id,
                cancel_event,
                reader=FakeReader(
                    _encoded_page(), cancel_event=cancel_event, cancel_on_call=3
                ),
                ocr=FakeOcr(),
            )

        assert connection.execute("SELECT COUNT(*) FROM precision_relations").fetchone()[0] == 1
        resume_reader = FakeReader(_encoded_page())
        resumed = _analyze_precision(
            repository, root_id, Event(), reader=resume_reader, ocr=FakeOcr()
        )
        assert resumed.relations_processed == 1
        assert resume_reader.calls == 1
    finally:
        repository.close()


def _repository_with_images(
    tmp_path: Path, image_counts: tuple[int, ...]
) -> tuple[DuplicateRepository, int, tuple[int, ...]]:
    repository = DuplicateRepository.open(tmp_path / "index.db")
    connection = repository._connection  # noqa: SLF001 - compact service fixture
    root_id = int(
        connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, 'root-key', ?)",
            (str(tmp_path), "2026-09-02T00:00:00+00:00"),
        ).lastrowid
    )
    archive_ids: list[int] = []
    for archive_index, image_count in enumerate(image_counts, start=1):
        path = tmp_path / f"archive-{archive_index}.cbz"
        path.write_bytes(f"archive-{archive_index}".encode())
        stat = path.stat()
        archive_id = int(
            connection.execute(
                "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
                "archive_format, state, image_count, first_seen_at, last_seen_at, inspector_version) "
                "VALUES (?, ?, ?, ?, ?, 'CBZ', 'INDEXED', ?, ?, ?, 1)",
                (
                    root_id,
                    str(path),
                    f"archive-{archive_index}",
                    stat.st_size,
                    stat.st_mtime_ns,
                    image_count,
                    "2026-09-02T00:00:00+00:00",
                    "2026-09-02T00:00:00+00:00",
                ),
            ).lastrowid
        )
        connection.executemany(
            "INSERT INTO archive_entries(archive_id, position, path, normalized_path, sort_key, "
            "uncompressed_size, entry_kind, image_format_hint) "
            "VALUES (?, ?, ?, ?, ?, 10, 'IMAGE', 'PNG')",
            (
                (archive_id, position, f"{position:03}.png", f"{position:03}.png", f"{position:03}.png")
                for position in range(image_count)
            ),
        )
        connection.execute(
            "INSERT INTO archive_fingerprints(archive_id, file_size, mtime_ns, sha256, "
            "hash_state, filename_tokens_json, language_hints_json, analyzer_version, "
            "computed_at) VALUES (?, ?, ?, ?, 'SUCCEEDED', '[]', '[]', 1, ?)",
            (
                archive_id,
                stat.st_size,
                stat.st_mtime_ns,
                f"archive-sha-{archive_id}",
                "2026-09-02T00:00:00+00:00",
            ),
        )
        connection.executemany(
            "INSERT INTO image_fingerprints(archive_id, entry_position, coverage, byte_sha256, "
            "pixel_sha256, dhash64, ahash64, width, height, state, analyzer_version, computed_at) "
            "VALUES (?, ?, 'FULL', ?, ?, '0', '0', 32, 32, 'SUCCEEDED', 1, ?)",
            (
                (
                    archive_id,
                    position,
                    f"byte-{archive_id}-{position}",
                    f"pixel-{archive_id}-{position}",
                    "2026-09-02T00:00:00+00:00",
                )
                for position in range(image_count)
            ),
        )
        archive_ids.append(archive_id)
    connection.commit()
    group_id = connection.execute(
        "INSERT INTO candidate_groups(scan_root_id, group_key, strongest_relation, confidence, "
        "analyzer_version, created_at) VALUES (?, 'precision-group', 'VISUAL_VARIANT', 0.9, 1, ?)",
        (root_id, "2026-09-02T00:00:00+00:00"),
    ).lastrowid
    connection.executemany(
        "INSERT INTO candidate_group_members(group_id, archive_id) VALUES (?, ?)",
        ((group_id, archive_id) for archive_id in archive_ids),
    )
    connection.commit()
    repository.replace_candidate_sets(
        "precision-group",
        (
            ReviewCandidateSet(
                "precision-set", "precision-group", "MIXED_OR_UNKNOWN", tuple(archive_ids)
            ),
        ),
        computed_at=datetime(2026, 9, 2, tzinfo=UTC),
    )
    return repository, root_id, tuple(archive_ids)


def _insert_exact_content_relation(connection, root_id: int, left_id: int, right_id: int) -> None:  # type: ignore[no-untyped-def]
    connection.execute(
        "INSERT INTO candidate_relations(scan_root_id, archive_a_id, archive_b_id, relation, "
        "confidence, matched_pages, left_pages, right_pages, recommendation, evidence_json, "
        "analyzer_version, created_at) VALUES (?, ?, ?, 'EXACT_CONTENT', 1.0, 3, 3, 3, '', '[]', 1, ?)",
        (root_id, left_id, right_id, "2026-09-02T00:00:00+00:00"),
    )
    connection.commit()


def _insert_visual_relation(
    connection, root_id: int, left_id: int, right_id: int, image_count: int
) -> None:  # type: ignore[no-untyped-def]
    left_size, left_mtime = connection.execute(
        "SELECT file_size, mtime_ns FROM archives WHERE id = ?", (left_id,)
    ).fetchone()
    right_size, right_mtime = connection.execute(
        "SELECT file_size, mtime_ns FROM archives WHERE id = ?", (right_id,)
    ).fetchone()
    pairs = ",".join(f"[{position},{position}]" for position in range(image_count))
    connection.execute(
        "INSERT INTO candidate_relations(scan_root_id, archive_a_id, archive_b_id, relation, "
        "confidence, matched_pages, left_pages, right_pages, recommendation, evidence_json, "
        "analyzer_version, created_at) VALUES (?, ?, ?, 'VISUAL_VARIANT', 0.9, ?, ?, ?, "
        "'', '[]', 1, ?)",
        (
            root_id,
            left_id,
            right_id,
            image_count,
            image_count,
            image_count,
            "2026-09-02T00:00:00+00:00",
        ),
    )
    connection.execute(
        "INSERT INTO sequence_relations(scan_root_id, archive_a_id, archive_b_id, relation, "
        "container_archive_id, matched_pages, left_pages, right_pages, left_coverage, "
        "right_coverage, matched_pairs_json, left_file_size, left_mtime_ns, right_file_size, "
        "right_mtime_ns, algorithm_version, computed_at) VALUES (?, ?, ?, 'PARTIAL_OVERLAP', "
        "NULL, ?, ?, ?, 1.0, 1.0, ?, ?, ?, ?, ?, 1, ?)",
        (
            root_id,
            left_id,
            right_id,
            image_count,
            image_count,
            image_count,
            f"[{pairs}]",
            left_size,
            left_mtime,
            right_size,
            right_mtime,
            "2026-09-02T00:00:00+00:00",
        ),
    )
    connection.commit()


def _encoded_page() -> bytes:
    output = BytesIO()
    Image.new("L", (32, 32), 128).save(output, format="PNG")
    return output.getvalue()
