from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from threading import Event
from typing import Callable, Iterator, Sequence

import numpy as np
from PIL import Image, ImageOps

from archive_analyzer.archive_hashing import AnalysisCancelled
from archive_analyzer.domain import FileSnapshot
from archive_analyzer.duplicate_domain import ArchiveAnalysisInput, DuplicateRelation
from archive_analyzer.filename_normalization import normalize_filename_evidence
from archive_analyzer.inspection.image_reader import (
    ArchiveImageReader,
    DispatchingImageReader,
    ImageReadFailure,
)
from archive_analyzer.paths import normalize_path_key
from archive_analyzer.precision_analysis import (
    DetectedLanguage,
    PageLanguageEvidence,
    PageQualityMetrics,
    PairComparison,
    PairDirection,
    adaptive_interior_positions,
    compare_mosaic_metrics,
    compare_quality_metrics,
    detect_language_evidence,
    page_language_evidence,
    page_quality_metrics,
)
from archive_analyzer.precision_ocr import (
    BundledRapidOcrBackend,
    OcrBackend,
    OcrUnavailable,
)
from archive_analyzer.storage.duplicate_repository import (
    DuplicateRepository,
    PrecisionPageRecord,
    PrecisionProfileRecord,
    PrecisionRelationInput,
    PrecisionRelationRecord,
)


PRECISION_ALGORITHM_VERSION = 3
PRECISION_PAGE_CACHE_VERSION = 2  # OCR extraction is unchanged; reuse existing page evidence.
_DEFAULT_SEVEN_ZIP = Path(r"C:\Program Files\7-Zip\7z.exe")
_PRECISION_EXTRACTION_TIMEOUT_SECONDS = 30 * 60.0


@dataclass(frozen=True, slots=True)
class PrecisionAnalysisSummary:
    profiles_processed: int
    relations_processed: int
    failed_profiles: int
    page_cache_hits: int = 0


@dataclass(frozen=True, slots=True)
class PrecisionProgress:
    phase: str
    current: int
    total: int
    archive_current: int
    archive_total: int
    relation_current: int
    relation_total: int
    cache_hits: int
    elapsed_seconds: float
    eta_seconds: float | None
    current_name: str | None


class _PrecisionProgressTracker:
    def __init__(
        self,
        callback: Callable[[PrecisionProgress], None] | None,
        *,
        timer: Callable[[], float] = time.monotonic,
    ) -> None:
        self._callback = callback
        self._timer = timer
        self.phase = "precision_pages"
        self.current = 0
        self.total = 0
        self.archive_current = 0
        self.archive_total = 0
        self.relation_current = 0
        self.relation_total = 0
        self.cache_hits = 0
        self.current_name: str | None = None
        self._run_started_at = timer()
        self._phase_started_at = self._run_started_at

    def begin_phase(
        self,
        phase: str,
        total: int,
        *,
        archive_total: int,
        relation_total: int,
    ) -> None:
        self.phase = phase
        self.current = 0
        self.total = max(0, total)
        self.archive_current = 0 if phase == "precision_pages" else archive_total
        self.archive_total = archive_total
        self.relation_current = 0
        self.relation_total = relation_total
        self.current_name = None
        self._phase_started_at = self._timer()
        self.report()

    def set_context(
        self,
        *,
        archive_current: int | None = None,
        relation_current: int | None = None,
        current_name: str | None = None,
    ) -> None:
        if archive_current is not None:
            self.archive_current = archive_current
        if relation_current is not None:
            self.relation_current = relation_current
        self.current_name = current_name
        self.report()

    def advance(self, amount: int = 1, *, cache_hits: int = 0) -> None:
        self.current += max(0, amount)
        self.cache_hits += max(0, cache_hits)
        if self.current > self.total:
            self.total = self.current
        self.report()

    def finish_phase(self) -> None:
        self.current = self.total
        self.report()

    def report(self) -> None:
        if self._callback is None:
            return
        now = self._timer()
        elapsed = max(0.0, now - self._run_started_at)
        phase_elapsed = max(0.0, now - self._phase_started_at)
        if self.current >= self.total:
            eta: float | None = 0.0
        elif self.current < 2 or phase_elapsed <= 0.0:
            eta = None
        else:
            eta = phase_elapsed * (self.total - self.current) / self.current
        self._callback(
            PrecisionProgress(
                self.phase,
                self.current,
                self.total,
                self.archive_current,
                self.archive_total,
                self.relation_current,
                self.relation_total,
                self.cache_hits,
                elapsed,
                eta,
                self.current_name,
            )
        )


@dataclass(frozen=True, slots=True)
class _PageResult:
    position: int
    language_evidence: PageLanguageEvidence
    ocr_confidence: float
    metrics: PageQualityMetrics


class _PageProcessor:
    """Read, reduce and commit individual pages so interrupted runs can resume."""

    def __init__(
        self,
        *,
        repository: DuplicateRepository,
        reader: ArchiveImageReader,
        ocr: OcrBackend,
        cancel_event: Event,
        clock: Callable[[], datetime],
        fingerprints: dict[tuple[int, int], str],
        progress: _PrecisionProgressTracker,
    ) -> None:
        self._repository = repository
        self._reader = reader
        self._ocr = ocr
        self._cancel_event = cancel_event
        self._clock = clock
        self._fingerprints = fingerprints
        self._progress = progress
        self._cached: dict[str, PrecisionPageRecord] = {}
        self._queried: set[str] = set()
        self._ocr_unavailable = False
        self.page_cache_hits = 0

    def load(
        self,
        source: ArchiveAnalysisInput,
        positions: tuple[int, ...],
        *,
        language_hints: frozenset[str],
        require_ocr: bool,
    ) -> tuple[tuple[_PageResult, ...], str | None]:
        if not positions:
            return (), None
        _check_cancel(self._cancel_event)
        if not _snapshot_is_current(source):
            self._progress.advance(len(positions))
            return (), "SOURCE_CHANGED"

        valid_positions = tuple(
            position for position in positions if 0 <= position < len(source.images)
        )
        invalid_count = len(positions) - len(valid_positions)
        if invalid_count:
            self._progress.advance(invalid_count)

        fingerprints = {
            position: self._fingerprints.get(
                (source.archive_id, source.images[position].position)
            )
            for position in valid_positions
        }
        unseen = tuple(
            dict.fromkeys(
                fingerprint
                for fingerprint in fingerprints.values()
                if fingerprint is not None and fingerprint not in self._queried
            )
        )
        if unseen:
            self._cached.update(
                self._repository.cached_precision_pages(
                    unseen, PRECISION_PAGE_CACHE_VERSION
                )
            )
            self._queried.update(unseen)

        requested_scope = (
            _recognizer_scope(language_hints) if require_ocr else "NONE"
        )
        results: dict[int, _PageResult] = {}
        pending: list[int] = []
        error_code: str | None = "PRECISION_POSITION_INVALID" if invalid_count else None
        for position in valid_positions:
            fingerprint = fingerprints[position]
            cached = None if fingerprint is None else self._cached.get(fingerprint)
            if cached is not None and _cache_is_usable(
                cached,
                requested_scope=requested_scope,
                require_ocr=require_ocr,
                ocr_unavailable=self._ocr_unavailable,
            ):
                assert cached.metrics is not None
                results[position] = _PageResult(
                    position,
                    cached.language_evidence,
                    cached.ocr_confidence,
                    cached.metrics,
                )
                error_code = error_code or cached.error_code
                self.page_cache_hits += 1
                self._progress.advance(cache_hits=1)
            else:
                pending.append(position)

        if pending:
            counts = Counter(entry.path for entry in source.images)
            requests = tuple(
                (
                    source.images[position],
                    counts[source.images[position].path],
                )
                for position in pending
            )
            outcomes = _read_outcomes(
                self._reader,
                _file_snapshot(source),
                requests,
                cancel_event=self._cancel_event,
            )
            for position, outcome in zip(pending, outcomes, strict=False):
                fingerprint = fingerprints[position]
                cached = None if fingerprint is None else self._cached.get(fingerprint)
                if isinstance(outcome, ImageReadFailure):
                    error_code = error_code or outcome.code
                    if cached is not None and cached.metrics is not None:
                        results[position] = _PageResult(
                            position,
                            page_language_evidence(
                                "", recognizer_scope=requested_scope
                            ),
                            0.0,
                            cached.metrics,
                        )
                    self._store_failed(fingerprint, source, outcome.code)
                    self._progress.advance()
                    continue

                effective_hints = language_hints
                evidence_scope = requested_scope
                if (
                    require_ocr
                    and cached is not None
                    and cached.language_evidence.recognizer_scope
                    in {"KO", "GENERAL"}
                    and cached.language_evidence.recognizer_scope != requested_scope
                ):
                    effective_hints = frozenset()
                    evidence_scope = "BOTH"
                evidence = page_language_evidence("", recognizer_scope=evidence_scope)
                confidence = 0.0
                page_error: str | None = None
                if require_ocr:
                    if self._ocr_unavailable:
                        page_error = "OCR_UNAVAILABLE"
                    else:
                        _check_cancel(self._cancel_event)
                        try:
                            text, confidence = self._ocr.recognize(
                                outcome, language_hints=effective_hints
                            )
                        except OcrUnavailable:
                            self._ocr_unavailable = True
                            page_error = "OCR_UNAVAILABLE"
                        else:
                            evidence = page_language_evidence(
                                text, recognizer_scope=evidence_scope
                            )
                        _check_cancel(self._cancel_event)
                metrics = (
                    cached.metrics
                    if cached is not None and cached.metrics is not None
                    else None
                )
                if metrics is None:
                    _check_cancel(self._cancel_event)
                    try:
                        metrics = page_quality_metrics(_normalized_page(outcome))
                    except (OSError, ValueError):
                        page_error = page_error or "PRECISION_SAMPLE_FAILED"
                    _check_cancel(self._cancel_event)
                error_code = error_code or page_error
                if metrics is None:
                    self._store_failed(
                        fingerprint,
                        source,
                        page_error or "PRECISION_SAMPLE_FAILED",
                    )
                    self._progress.advance()
                    continue

                result = _PageResult(position, evidence, confidence, metrics)
                results[position] = result
                self._store_success(
                    fingerprint,
                    source,
                    result,
                    error_code=page_error,
                )
                self._progress.advance()

        return (
            tuple(results[position] for position in valid_positions if position in results),
            error_code,
        )

    def _store_success(
        self,
        fingerprint: str | None,
        source: ArchiveAnalysisInput,
        result: _PageResult,
        *,
        error_code: str | None,
    ) -> None:
        if fingerprint is None or not _snapshot_is_current(source):
            return
        record = PrecisionPageRecord(
            fingerprint,
            PRECISION_PAGE_CACHE_VERSION,
            "SUCCEEDED",
            result.language_evidence,
            result.ocr_confidence,
            result.metrics,
            error_code,
        )
        stored = self._repository.store_precision_page(
            record, computed_at=self._clock()
        )
        if stored:
            self._cached[fingerprint] = record
        self._queried.add(fingerprint)

    def _store_failed(
        self,
        fingerprint: str | None,
        source: ArchiveAnalysisInput,
        error_code: str,
    ) -> None:
        if fingerprint is None or not _snapshot_is_current(source):
            return
        record = PrecisionPageRecord(
            fingerprint,
            PRECISION_PAGE_CACHE_VERSION,
            "FAILED",
            page_language_evidence("", recognizer_scope="NONE"),
            0.0,
            None,
            error_code,
        )
        stored = self._repository.store_precision_page(
            record, computed_at=self._clock()
        )
        existing = self._cached.get(fingerprint)
        if stored and (existing is None or existing.state != "SUCCEEDED"):
            self._cached[fingerprint] = record
        self._queried.add(fingerprint)

def _recognizer_scope(language_hints: frozenset[str]) -> str:
    normalized = {str(value).upper() for value in language_hints}
    korean = bool(normalized & {"KO", "KR", "KOREAN"})
    general = bool(
        normalized
        & {
            "JA",
            "JP",
            "JAPANESE",
            "ZH",
            "CN",
            "CHINESE",
            "EN",
            "ENG",
            "ENGLISH",
        }
    )
    if korean and not general:
        return "KO"
    if general and not korean:
        return "GENERAL"
    return "BOTH"


def _cache_is_usable(
    record: PrecisionPageRecord,
    *,
    requested_scope: str,
    require_ocr: bool,
    ocr_unavailable: bool,
) -> bool:
    if record.state != "SUCCEEDED" or record.metrics is None:
        return False
    if not require_ocr:
        return True
    if record.error_code == "OCR_UNAVAILABLE":
        return ocr_unavailable
    if record.error_code is not None:
        return False
    actual = record.language_evidence.recognizer_scope
    return actual == "BOTH" or actual == requested_scope


def _language_is_clear(
    pages: Sequence[_PageResult], filename_hints: frozenset[str]
) -> bool:
    readable = tuple(
        result.language_evidence
        for result in pages
        if result.language_evidence.readable_character_count >= 6
    )
    if len(readable) < 5:
        return False
    profile = detect_language_evidence(readable, filename_hints)
    if profile.language is DetectedLanguage.UNKNOWN:
        return False
    votes = Counter(
        (
            DetectedLanguage.KOREAN
            if page.korean_dialogue_page
            else page.dominant_script
        )
        for page in readable
    )
    return votes[profile.language] >= 5


def refresh_cached_language_decisions(repository, root_id: int, cancel_event: Event) -> int:
    """Re-evaluate existing sampled evidence without opening archives or running OCR."""
    from dataclasses import replace
    pending = repository.unresolved_precision_profiles(root_id, PRECISION_ALGORITHM_VERSION)
    if not pending:
        return 0
    fingerprints = repository.precision_page_fingerprints(root_id, tuple(record.archive_id for _, record in pending))
    cached = repository.cached_precision_pages(tuple(fingerprints.values()), PRECISION_PAGE_CACHE_VERSION)
    updated = 0
    for path, record in pending:
        _check_cancel(cancel_event)
        pages = []
        for metric in record.page_metrics:
            page = cached.get(fingerprints.get((record.archive_id, int(metric['position']))))
            if page is None or page.error_code or page.state != 'SUCCEEDED':
                break
            pages.append(page.language_evidence)
        if len(pages) != record.sample_count or not pages:
            continue
        decision = detect_language_evidence(pages, normalize_filename_evidence(path).language_hints)
        if decision.language is DetectedLanguage.UNKNOWN:
            continue
        updated += bool(repository.store_precision_profile(replace(record,
            algorithm_version=PRECISION_ALGORITHM_VERSION, language=decision.language.value,
            language_confidence=decision.language_confidence, character_counts=dict(decision.character_counts)),
            computed_at=datetime.now(UTC)))
    return updated


def analyze_precision(
    repository: DuplicateRepository,
    root_id: int,
    cancel_event: Event,
    *,
    set_keys: tuple[str, ...],
    reader: ArchiveImageReader | None = None,
    ocr: OcrBackend | None = None,
    clock: Callable[[], datetime] | None = None,
    progress: Callable[[PrecisionProgress], None] | None = None,
    compare_images: bool = False,
) -> PrecisionAnalysisSummary:
    scope = repository.precision_scope_for_sets(set_keys)
    image_reader = reader or DispatchingImageReader(
        _DEFAULT_SEVEN_ZIP,
        timeout_seconds=_PRECISION_EXTRACTION_TIMEOUT_SECONDS,
    )
    ocr_backend = ocr or BundledRapidOcrBackend()
    now = clock or (lambda: datetime.now(UTC))
    inputs = repository.precision_profile_inputs(
        root_id,
        algorithm_version=PRECISION_ALGORITHM_VERSION,
        archive_ids=scope.archive_ids,
    )
    page_total = sum(
        len(adaptive_interior_positions(len(source.images), 12)) for source in inputs
    )
    progress_tracker = _PrecisionProgressTracker(progress)
    progress_tracker.begin_phase(
        "precision_pages",
        page_total,
        archive_total=len(inputs),
        relation_total=0,
    )

    processor = _PageProcessor(
        repository=repository,
        reader=image_reader,
        ocr=ocr_backend,
        cancel_event=cancel_event,
        clock=now,
        fingerprints=repository.precision_page_fingerprints(root_id, scope.archive_ids),
        progress=progress_tracker,
    )

    profiles_processed = 0
    failed_profiles = 0
    for archive_index, source in enumerate(inputs, start=1):
        _check_cancel(cancel_event)
        progress_tracker.set_context(
            archive_current=archive_index,
            current_name=source.path.name,
        )
        page_results: dict[int, _PageResult] = {}
        attempted: set[int] = set()
        error_code: str | None = None
        maximum_positions = adaptive_interior_positions(len(source.images), 12)
        filename_hints = normalize_filename_evidence(source.path).language_hints
        for limit in (3, 6, 12):
            positions = adaptive_interior_positions(len(source.images), limit)
            pending = tuple(position for position in positions if position not in attempted)
            if pending:
                loaded, load_error = processor.load(
                    source,
                    pending,
                    language_hints=filename_hints,
                    require_ocr=True,
                )
                attempted.update(pending)
                page_results.update({result.position: result for result in loaded})
                error_code = error_code or load_error
            if len(attempted) >= len(maximum_positions):
                break
            if limit == 6 and _language_is_clear(
                tuple(page_results.values()), filename_hints
            ):
                break
        progress_tracker.advance(len(maximum_positions) - len(attempted))

        record = profile_from_pages(
            source,
            tuple(page_results[position] for position in sorted(page_results)),
            error_code=error_code
            or ("NO_IMAGES" if not maximum_positions else None),
        )
        _check_cancel(cancel_event)
        if not _snapshot_is_current(source):
            failed_profiles += 1
            continue
        if repository.store_precision_profile(record, computed_at=now()):
            profiles_processed += 1
            if record.state == "FAILED":
                failed_profiles += 1
        else:
            failed_profiles += 1
    progress_tracker.finish_phase()

    relation_inputs = (
        repository.precision_relation_inputs(
            root_id,
            algorithm_version=PRECISION_ALGORITHM_VERSION,
            relation_pairs=scope.relation_pairs,
            checkpoint=lambda: _check_cancel(cancel_event),
        )
        if scope.relation_pairs and compare_images
        else ()
    )
    relation_page_budgets = tuple(
        _relation_page_budget(candidate) for candidate in relation_inputs
    )
    relation_total = len(relation_inputs)
    progress_tracker.begin_phase(
        "precision_relations",
        sum(relation_page_budgets) + relation_total,
        archive_total=len(inputs),
        relation_total=relation_total,
    )
    relations_processed = 0
    for index, (candidate, page_budget) in enumerate(
        zip(relation_inputs, relation_page_budgets, strict=True), start=1
    ):
        _check_cancel(cancel_event)
        progress_tracker.set_context(
            relation_current=index - 1,
            current_name=f"{candidate.left.path.name} ↔ {candidate.right.path.name}",
        )
        before_pages = progress_tracker.current
        record = _compare_relation(candidate, processor, cancel_event=cancel_event)
        pages_used = progress_tracker.current - before_pages
        progress_tracker.advance(max(0, page_budget - pages_used))
        _check_cancel(cancel_event)
        if _snapshot_is_current(candidate.left) and _snapshot_is_current(candidate.right):
            if repository.store_precision_relation(
                record,
                algorithm_version=PRECISION_ALGORITHM_VERSION,
                computed_at=now(),
            ):
                relations_processed += 1
        progress_tracker.set_context(relation_current=index)
        progress_tracker.advance()
    progress_tracker.finish_phase()
    return PrecisionAnalysisSummary(
        profiles_processed,
        relations_processed,
        failed_profiles,
        page_cache_hits=processor.page_cache_hits,
    )


def profile_from_pages(
    source: ArchiveAnalysisInput,
    page_results: Sequence[_PageResult],
    *,
    error_code: str | None,
) -> PrecisionProfileRecord:
    language = detect_language_evidence(
        tuple(result.language_evidence for result in page_results),
        normalize_filename_evidence(source.path).language_hints,
    )
    language_value = (
        DetectedLanguage.UNKNOWN.value
        if error_code == "OCR_UNAVAILABLE"
        else language.language.value
    )
    language_confidence = (
        0.0 if error_code == "OCR_UNAVAILABLE" else language.language_confidence
    )
    page_metrics = tuple(
        {
            "position": result.position,
            "ocr_confidence": result.ocr_confidence,
            "sharpness": result.metrics.sharpness,
            "jpeg_blockiness": result.metrics.jpeg_blockiness,
            "ringing": result.metrics.ringing,
            "blur": result.metrics.blur,
            "detail": result.metrics.detail,
            "noise": result.metrics.noise,
        }
        for result in page_results
    )
    state = "SUCCEEDED" if page_results else "FAILED"
    return PrecisionProfileRecord(
        archive_id=source.archive_id,
        file_size=source.file_size,
        mtime_ns=source.mtime_ns,
        algorithm_version=PRECISION_ALGORITHM_VERSION,
        state=state,
        sample_count=len(page_results),
        language=language_value,
        language_confidence=language_confidence,
        character_counts=dict(language.character_counts),
        page_metrics=page_metrics,
        error_code=error_code if error_code is not None else (None if page_results else "NO_USABLE_PAGES"),
    )


def _compare_relation(
    candidate: PrecisionRelationInput,
    processor: _PageProcessor,
    *,
    cancel_event: Event,
) -> PrecisionRelationRecord:
    if candidate.relation in {
        DuplicateRelation.EXACT_ARCHIVE,
        DuplicateRelation.EXACT_CONTENT,
    }:
        tied = PairComparison(
            PairDirection.TIE,
            1.0,
            ("exact content requires no visual reread",),
        )
        return _relation_record(candidate, tied, tied)

    maximum_pairs = _sample_pairs(candidate.matched_pairs, limit=12)
    if not maximum_pairs:
        return _relation_record(
            candidate,
            PairComparison(PairDirection.UNKNOWN, 0.0, ("no aligned pages",)),
            PairComparison(PairDirection.UNKNOWN, 0.0, ("no aligned pages",)),
        )
    valid_pairs = tuple(
        pair
        for pair in maximum_pairs
        if 0 <= pair[0] < len(candidate.left.images)
        and 0 <= pair[1] < len(candidate.right.images)
    )
    if not valid_pairs:
        unavailable = PairComparison(
            PairDirection.UNKNOWN, 0.0, ("aligned pages are out of range",)
        )
        return _relation_record(candidate, unavailable, unavailable)

    left_results: dict[int, _PageResult] = {}
    right_results: dict[int, _PageResult] = {}
    attempted_pairs: set[tuple[int, int]] = set()
    selected_pairs: tuple[tuple[int, int], ...] = ()
    for limit in (3, 6, 12):
        selected_pairs = tuple(
            pair
            for pair in _sample_pairs(candidate.matched_pairs, limit=limit)
            if pair in valid_pairs
        )
        new_pairs = tuple(pair for pair in selected_pairs if pair not in attempted_pairs)
        if new_pairs:
            new_left = tuple(dict.fromkeys(pair[0] for pair in new_pairs))
            new_right = tuple(dict.fromkeys(pair[1] for pair in new_pairs))
            loaded_left, _left_error = processor.load(
                candidate.left,
                new_left,
                language_hints=frozenset(),
                require_ocr=False,
            )
            loaded_right, _right_error = processor.load(
                candidate.right,
                new_right,
                language_hints=frozenset(),
                require_ocr=False,
            )
            left_results.update({result.position: result for result in loaded_left})
            right_results.update({result.position: result for result in loaded_right})
            attempted_pairs.update(new_pairs)

        aligned = tuple(
            (left_results[left], right_results[right])
            for left, right in selected_pairs
            if left in left_results and right in right_results
        )
        if len(attempted_pairs) >= len(valid_pairs):
            break
        if limit == 6 and _relation_evidence_is_clear(aligned):
            break

    aligned = tuple(
        (left_results[left], right_results[right])
        for left, right in selected_pairs
        if left in left_results and right in right_results
    )
    left_metrics = [left.metrics for left, _right in aligned]
    right_metrics = [right.metrics for _left, right in aligned]
    if not left_metrics:
        unavailable = PairComparison(
            PairDirection.UNKNOWN, 0.0, ("aligned pages could not be read",)
        )
        return _relation_record(candidate, unavailable, unavailable)

    _check_cancel(cancel_event)
    mosaic = compare_mosaic_metrics(left_metrics, right_metrics)
    _check_cancel(cancel_event)
    quality = compare_quality_metrics(left_metrics, right_metrics)
    _check_cancel(cancel_event)
    return _relation_record(candidate, mosaic, quality)


def _relation_evidence_is_clear(
    aligned: Sequence[tuple[_PageResult, _PageResult]],
) -> bool:
    if len(aligned) < 6:
        return False
    page_directions = tuple(
        compare_quality_metrics((left.metrics,), (right.metrics,)).direction
        for left, right in aligned
    )
    directional = {PairDirection.LEFT_BETTER, PairDirection.RIGHT_BETTER}
    if set(page_directions) not in ({PairDirection.LEFT_BETTER}, {PairDirection.RIGHT_BETTER}):
        return False
    quality = compare_quality_metrics(
        tuple(left.metrics for left, _right in aligned),
        tuple(right.metrics for _left, right in aligned),
    )
    mosaic = compare_mosaic_metrics(
        tuple(left.metrics for left, _right in aligned),
        tuple(right.metrics for _left, right in aligned),
    )
    return (
        quality.direction in directional
        and mosaic.direction == quality.direction == page_directions[0]
    )


def _relation_page_budget(candidate: PrecisionRelationInput) -> int:
    if candidate.relation in {
        DuplicateRelation.EXACT_ARCHIVE,
        DuplicateRelation.EXACT_CONTENT,
    }:
        return 0
    pairs = _sample_pairs(candidate.matched_pairs, limit=12)
    return len({left for left, _right in pairs}) + len(
        {right for _left, right in pairs}
    )


def _relation_record(
    candidate: PrecisionRelationInput,
    mosaic: PairComparison,
    quality: PairComparison,
) -> PrecisionRelationRecord:
    return PrecisionRelationRecord(
        archive_a_id=candidate.left.archive_id,
        archive_b_id=candidate.right.archive_id,
        mosaic_direction=mosaic.direction.value,
        mosaic_confidence=mosaic.confidence,
        quality_direction=quality.direction.value,
        quality_confidence=quality.confidence,
        evidence=tuple(
            [*(f"mosaic:{reason}" for reason in mosaic.reasons), *(f"quality:{reason}" for reason in quality.reasons)]
        ),
    )


def _read_outcomes(
    reader: ArchiveImageReader,
    snapshot: FileSnapshot,
    requests: tuple,
    *,
    cancel_event: Event,
) -> Iterator[bytes | ImageReadFailure]:
    read_many = getattr(reader, "read_many", None)
    _check_cancel(cancel_event)
    outcomes: Iterator[bytes | ImageReadFailure] | None = None
    try:
        if callable(read_many):
            outcomes = iter(
                read_many(
                    snapshot,
                    requests,
                    cancel_check=lambda: _check_cancel(cancel_event),
                )
            )
        else:
            outcomes = iter(
                _read_one(reader, snapshot, entry, same_path_count)
                for entry, same_path_count in requests
            )
    except ImageReadFailure as error:
        outcomes = iter((error,))
    try:
        for _request in requests:
            _check_cancel(cancel_event)
            try:
                outcome = next(outcomes)
            except ImageReadFailure as error:
                outcome = error
                close = getattr(outcomes, "close", None)
                if callable(close):
                    close()
                outcomes = iter(())
            except StopIteration:
                yield ImageReadFailure(
                    "PRECISION_READ_INCOMPLETE",
                    "The archive reader returned too few pages.",
                )
                continue
            _check_cancel(cancel_event)
            yield outcome
    finally:
        close = getattr(outcomes, "close", None)
        if callable(close):
            close()


def _read_one(
    reader: ArchiveImageReader,
    snapshot: FileSnapshot,
    entry,
    same_path_count: int,
) -> bytes | ImageReadFailure:
    try:
        return reader.read(snapshot, entry, same_path_count=same_path_count)
    except ImageReadFailure as error:
        return error


def _normalized_page(payload: bytes) -> np.ndarray:
    with Image.open(BytesIO(payload)) as opened:
        image = ImageOps.exif_transpose(opened).convert("L")
        image = image.resize((512, 512), Image.Resampling.LANCZOS)
        return np.asarray(image, dtype=np.float64) / 255.0


def _sample_pairs(
    pairs: tuple[tuple[int, int], ...], *, limit: int
) -> tuple[tuple[int, int], ...]:
    return tuple(
        pairs[position]
        for position in adaptive_interior_positions(len(pairs), limit)
    )


def _file_snapshot(value: ArchiveAnalysisInput) -> FileSnapshot:
    return FileSnapshot(
        path=value.path,
        path_key=normalize_path_key(value.path),
        size=value.file_size,
        mtime_ns=value.mtime_ns,
        archive_format=value.archive_format,
    )


def _snapshot_is_current(value: ArchiveAnalysisInput) -> bool:
    try:
        current = value.path.stat()
    except (FileNotFoundError, OSError):
        return False
    return current.st_size == value.file_size and current.st_mtime_ns == value.mtime_ns


def _check_cancel(cancel_event: Event) -> None:
    if cancel_event.is_set():
        raise AnalysisCancelled


__all__ = [
    "PRECISION_ALGORITHM_VERSION",
    "PrecisionAnalysisSummary",
    "PrecisionProgress",
    "analyze_precision",
    "profile_from_pages",
]
