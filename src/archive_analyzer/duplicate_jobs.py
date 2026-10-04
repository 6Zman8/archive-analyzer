from __future__ import annotations

from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from inspect import Parameter, signature
from threading import Event
from time import monotonic
from typing import Callable
from uuid import uuid4

from archive_analyzer.analysis_progress import AnalysisProgress, ProgressCallback
from archive_analyzer.archive_hashing import (
    AnalysisCancelled,
    AnalysisFailure,
    cache_probe_fingerprints,
    sha256_archive,
    size_collision_targets,
)
from archive_analyzer.candidate_index import CandidateSeed, build_candidate_index
from archive_analyzer.domain import FileSnapshot
from archive_analyzer.duplicate_domain import AnalysisStage, ArchiveAnalysisInput, DuplicateRelation
from archive_analyzer.filename_normalization import normalize_filename_evidence
from archive_analyzer.fingerprinting import FingerprintFailure, ImageFingerprint, fingerprint_image
from archive_analyzer.inspection.image_reader import ArchiveImageReader, ImageReadFailure
from archive_analyzer.matching import ArchiveFingerprintSet, CandidateMatch, match_candidate
from archive_analyzer.paths import normalize_path_key
from archive_analyzer.storage.duplicate_repository import (
    CachedFingerprints,
    DuplicateJob,
    DuplicateRepository,
)
from archive_analyzer.storage.repository import ScanAlreadyRunning, ScanLockLost


DUPLICATE_ANALYZER_VERSION = 2
_DUPLICATE_LOCK_KIND = "duplicate"
_LOCK_LEASE_SECONDS = 90
_HEARTBEAT_INTERVAL_SECONDS = 10.0
_MATCH_INPUT_BATCH_SIZE = 100
_STABLE_IMAGE_ERRORS = {
    "AMBIGUOUS_ENTRY_NAME",
    "CORRUPT_ARCHIVE",
    "ENCRYPTED_UNSUPPORTED",
    "IMAGE_BYTE_LIMIT",
    "IMAGE_PIXEL_LIMIT",
    "UNSUPPORTED_FORMAT",
}


@dataclass(frozen=True, slots=True)
class DuplicateSummary:
    run_id: int
    completed: bool
    exact_archive_groups: int
    exact_content_groups: int
    visual_variant_groups: int
    related_groups: int
    failed_archives: int

    @property
    def candidate_group_count(self) -> int:
        return (
            self.exact_archive_groups
            + self.exact_content_groups
            + self.visual_variant_groups
            + self.related_groups
        )


@dataclass(frozen=True, slots=True)
class _FullCollection:
    successes: tuple[tuple[int, ImageFingerprint], ...]
    failures: tuple[tuple[int, str], ...]


@dataclass(frozen=True, slots=True)
class _FullState:
    fingerprints: ArchiveFingerprintSet
    complete: bool
    error_code: str | None


@dataclass(slots=True)
class _RunCounters:
    archive_processed: int = 0
    image_processed: int = 0
    candidate_count: int = 0


class _HeartbeatImageReader:
    def __init__(self, service: DuplicateAnalysisService, owner_token: str) -> None:
        self._service = service
        self._owner_token = owner_token

    def read(self, snapshot, entry, *, same_path_count: int = 1) -> bytes:  # type: ignore[no-untyped-def]
        self._service._heartbeat(self._owner_token)
        try:
            return self._service._reader_or_raise().read(
                snapshot, entry, same_path_count=same_path_count
            )
        finally:
            self._service._heartbeat(self._owner_token)


class DuplicateAnalysisService:
    def __init__(
        self,
        repository: DuplicateRepository,
        reader: ArchiveImageReader | None,
        *,
        workers: int = 2,
        analyzer_version: int = DUPLICATE_ANALYZER_VERSION,
        clock: Callable[[], datetime] | None = None,
        candidate_builder: Callable = build_candidate_index,
        matcher: Callable = match_candidate,
        archive_hasher: Callable = sha256_archive,
        lease_seconds: int = _LOCK_LEASE_SECONDS,
        heartbeat_interval_seconds: float | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        if workers <= 0:
            raise ValueError("workers must be positive")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        interval = (
            min(_HEARTBEAT_INTERVAL_SECONDS, lease_seconds / 3)
            if heartbeat_interval_seconds is None
            else heartbeat_interval_seconds
        )
        if interval <= 0:
            raise ValueError("heartbeat_interval_seconds must be positive")
        self._repository = repository
        self._reader = reader
        self._workers = workers
        self._analyzer_version = analyzer_version
        self._clock = clock or (lambda: datetime.now(UTC))
        self._candidate_builder = candidate_builder
        self._matcher = matcher
        self._archive_hasher = archive_hasher
        self._lease_seconds = lease_seconds
        self._heartbeat_interval_seconds = interval
        self._last_heartbeat_monotonic = 0.0
        self._candidate_builder_accepts_checkpoint = _accepts_checkpoint(candidate_builder)
        self._matcher_accepts_checkpoint = _accepts_checkpoint(matcher)
        self._candidate_builder_accepts_progress = _accepts_keyword(candidate_builder, "progress_callback")
        self._progress_callback = progress_callback
        self._archive_total = 0
        self._stage_totals: dict[AnalysisStage, int] = {}

    @property
    def workers(self) -> int:
        return self._workers

    def run(self, root_id: int, cancel_event: Event) -> DuplicateSummary:
        owner_token = uuid4().hex
        acquired_at = self._now()
        self._repository.acquire_operation_lock(
            _DUPLICATE_LOCK_KIND,
            owner_token,
            acquired_at,
            lease_seconds=self._lease_seconds,
        )
        self._last_heartbeat_monotonic = monotonic()
        run_id: int | None = None
        failed_archives: set[int] = set()
        counters = _RunCounters()
        inputs: tuple[ArchiveAnalysisInput, ...] = ()
        try:
            archive_total, image_total = self._repository.analysis_input_counts(root_id)
            self._archive_total = archive_total
            self._stage_totals.clear()
            self._publish(AnalysisStage.ARCHIVE_HASH, "검사 대상 준비", 0, archive_total)
            started_at = self._now()
            run_id = self._repository.begin_duplicate_run(
                root_id,
                analyzer_version=self._analyzer_version,
                archive_total=archive_total,
                image_total=image_total,
                started_at=started_at,
                owner_token=owner_token,
            )
            prepared = []
            for batch in self._repository.iter_analysis_input_batches(
                root_id,
                include_images=False,
                checkpoint=lambda: self._owner_checkpoint(owner_token, cancel_event),
            ):
                prepared.extend(batch)
                self._publish(AnalysisStage.ARCHIVE_HASH, "검사 대상 준비", len(prepared), archive_total)
            inputs = tuple(prepared)
            prepared.clear()
            self._check_cancel(cancel_event)
            self._run_archive_hash_stage(
                run_id, inputs, cancel_event, owner_token, failed_archives, counters
            )
            self._run_probe_stage(
                run_id,
                root_id,
                inputs,
                cancel_event,
                owner_token,
                failed_archives,
                counters,
            )
            seeds = self._build_candidates(
                run_id, root_id, cancel_event, owner_token, failed_archives, counters
            )
            self._run_full_stage(
                run_id,
                root_id,
                inputs,
                seeds,
                cancel_event,
                owner_token,
                failed_archives,
                counters,
            )
            matches = self._run_match_stage(
                run_id,
                root_id,
                inputs,
                seeds,
                cancel_event,
                owner_token,
                failed_archives,
                counters,
            )
            summary = self._store_groups(
                run_id,
                root_id,
                inputs,
                matches,
                cancel_event,
                owner_token,
                failed_archives,
                counters,
            )
            self._check_cancel(cancel_event)
            self._repository.finish_duplicate_run(
                run_id,
                status="COMPLETED",
                archive_processed=len(inputs),
                image_processed=counters.image_processed,
                failed_count=len(failed_archives),
                candidate_count=summary.candidate_group_count,
                finished_at=self._now(),
                owner_token=owner_token,
            )
            return summary
        except AnalysisCancelled:
            if run_id is not None:
                self._interrupt_run(
                    run_id, owner_token, failed_archives, counters, status="INTERRUPTED"
                )
            raise
        except BaseException:
            if run_id is not None:
                self._interrupt_run(
                    run_id, owner_token, failed_archives, counters, status="FAILED"
                )
            raise
        finally:
            self._repository.release_operation_lock(owner_token)

    def _run_archive_hash_stage(
        self,
        run_id: int,
        inputs: tuple[ArchiveAnalysisInput, ...],
        cancel_event: Event,
        owner_token: str,
        failed_archives: set[int],
        counters: _RunCounters,
    ) -> None:
        stage = AnalysisStage.ARCHIVE_HASH
        self._start_stage(run_id, stage, owner_token, failed_archives, counters)
        self._repository.prepare_duplicate_jobs(
            run_id,
            stage,
            tuple((str(value.archive_id), value.archive_id) for value in inputs),
            now=self._now(),
            owner_token=owner_token,
        )
        targets = set(size_collision_targets(inputs))
        pending_hashes: list[ArchiveAnalysisInput] = []
        for value in inputs:
            self._owner_checkpoint(owner_token, cancel_event)
            self._publish(stage, "완전 동일 검사", counters.archive_processed, len(inputs),
                          current_item=value.path.name)
            if value.archive_id not in targets:
                job = self._claim(run_id, stage, str(value.archive_id), owner_token)
                self._finish_job(job, "SKIPPED", None, owner_token)
                counters.archive_processed += 1
                continue
            cached = self._repository.cached_fingerprints(value, self._analyzer_version)
            if cached is not None and cached.hash_state == "SUCCEEDED" and cached.sha256:
                job = self._claim(run_id, stage, str(value.archive_id), owner_token)
                self._finish_job(job, "SKIPPED", None, owner_token)
                counters.archive_processed += 1
                continue
            if cached is not None and cached.hash_state == "FAILED":
                code = self._normalize_error_code(
                    self._archive_cache_error(value.archive_id)
                ) or "HASH_READ_FAILED"
                if code == "HASH_READ_FAILED":
                    pending_hashes.append(value)
                    continue
                job = self._claim(run_id, stage, str(value.archive_id), owner_token)
                self._finish_job(job, "FAILED", code, owner_token)
                failed_archives.add(value.archive_id)
                counters.archive_processed += 1
                continue
            pending_hashes.append(value)

        for offset in range(0, len(pending_hashes), self._workers):
            self._check_cancel(cancel_event)
            batch = pending_hashes[offset : offset + self._workers]
            jobs = {
                value.archive_id: self._claim(
                    run_id, stage, str(value.archive_id), owner_token
                )
                for value in batch
            }
            executor = ThreadPoolExecutor(
                max_workers=self._workers, thread_name_prefix="archive-analyzer-hash"
            )
            completed = False
            try:
                futures = {
                    executor.submit(self._archive_hasher, value, cancel_event): value
                    for value in batch
                }
                self._wait_for_batch(futures, owner_token, cancel_event)
                for future, value in futures.items():
                    try:
                        digest = future.result()
                        self._check_cancel(cancel_event)
                        stored = self._repository.store_archive_fingerprint(
                            value,
                            analyzer_version=self._analyzer_version,
                            computed_at=self._now(),
                            sha256=digest,
                            hash_state="SUCCEEDED",
                            owner_token=owner_token,
                            now=self._now,
                        )
                        if not stored:
                            raise AnalysisFailure("CHANGED_DURING_ANALYSIS")
                    except AnalysisCancelled:
                        self._reset_running(run_id, owner_token)
                        raise
                    except (AnalysisFailure, OSError) as error:
                        code = self._error_code(error)
                        if code == "HASH_READ_FAILED":
                            stored_failure = self._repository.store_archive_fingerprint(
                                value,
                                analyzer_version=self._analyzer_version,
                                computed_at=self._now(),
                                sha256=None,
                                hash_state="FAILED",
                                error_code=code,
                                owner_token=owner_token,
                                now=self._now,
                            )
                            if not stored_failure:
                                code = "CHANGED_DURING_ANALYSIS"
                        self._finish_job(jobs[value.archive_id], "FAILED", code, owner_token)
                        failed_archives.add(value.archive_id)
                    except BaseException:
                        raise
                    else:
                        self._finish_job(jobs[value.archive_id], "SUCCEEDED", None, owner_token)
                    counters.archive_processed += 1
                    self._update_stage(run_id, stage, owner_token, failed_archives, counters)
                completed = True
            finally:
                executor.shutdown(wait=completed, cancel_futures=not completed)
            self._heartbeat(owner_token)
        self._check_cancel(cancel_event)
        self._update_stage(run_id, stage, owner_token, failed_archives, counters)

    def _run_probe_stage(
        self,
        run_id: int,
        root_id: int,
        inputs: tuple[ArchiveAnalysisInput, ...],
        cancel_event: Event,
        owner_token: str,
        failed_archives: set[int],
        counters: _RunCounters,
    ) -> None:
        stage = AnalysisStage.PROBE
        counters.archive_processed = 0
        counters.image_processed = 0
        self._start_stage(run_id, stage, owner_token, failed_archives, counters)
        self._repository.prepare_duplicate_jobs(
            run_id,
            stage,
            tuple((str(value.archive_id), value.archive_id) for value in inputs),
            now=self._now(),
            owner_token=owner_token,
        )
        reader = _HeartbeatImageReader(self, owner_token)
        for batch in self._repository.iter_analysis_input_batches(
            root_id,
            checkpoint=lambda: self._owner_checkpoint(owner_token, cancel_event),
        ):
            for value in batch:
                self._check_cancel(cancel_event)
                job = self._claim(run_id, stage, str(value.archive_id), owner_token)
                try:
                    result = cache_probe_fingerprints(
                        value,
                        reader,
                        self._repository,
                        cancel_event,
                        self._analyzer_version,
                        self._now(),
                        owner_token=owner_token,
                        now=self._now,
                        progress_callback=lambda done, total: self._publish(
                            stage, "대표 이미지 검사", counters.archive_processed, len(inputs),
                            current_item=value.path.name,
                            detail=f"이 파일의 대표 이미지 {done}/{total}장",
                        ),
                    )
                    filename = normalize_filename_evidence(value.path)
                    if not self._repository.store_filename_evidence(
                        value,
                        analyzer_version=self._analyzer_version,
                        filename_tokens=filename.tokens,
                        language_hints=filename.language_hints,
                        owner_token=owner_token,
                        now=self._now,
                    ):
                        raise AnalysisFailure("CHANGED_DURING_ANALYSIS")
                    self._check_cancel(cancel_event)
                except AnalysisCancelled:
                    self._reset_running(run_id, owner_token)
                    raise
                except (AnalysisFailure, ImageReadFailure) as error:
                    code = self._error_code(error)
                    self._finish_job(job, "FAILED", code, owner_token)
                    failed_archives.add(value.archive_id)
                except BaseException:
                    raise
                else:
                    if result.failures:
                        code = self._normalize_error_code(result.failures[0].error_code)
                        self._finish_job(job, "FAILED", code, owner_token)
                        failed_archives.add(value.archive_id)
                    else:
                        self._finish_job(job, "SUCCEEDED", None, owner_token)
                counters.archive_processed += 1
                counters.image_processed += min(7, len(value.images))
                self._update_stage(run_id, stage, owner_token, failed_archives, counters)
                self._heartbeat(owner_token)
        self._check_cancel(cancel_event)

    def _build_candidates(
        self,
        run_id: int,
        root_id: int,
        cancel_event: Event,
        owner_token: str,
        failed_archives: set[int],
        counters: _RunCounters,
    ) -> tuple[CandidateSeed, ...]:
        stage = AnalysisStage.CANDIDATE_BUILD
        counters.archive_processed = 0
        counters.image_processed = 0
        self._start_stage(run_id, stage, owner_token, failed_archives, counters)
        self._check_cancel(cancel_event)
        evidence = self._repository.load_candidate_evidence(
            root_id,
            analyzer_version=self._analyzer_version,
            checkpoint=lambda: self._owner_checkpoint(owner_token, cancel_event),
            progress_callback=self._progress_callback,
        )
        self._check_cancel(cancel_event)
        executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="archive-analyzer-candidates"
        )
        worker_cancel = Event()
        future = executor.submit(
            self._call_candidate_builder,
            evidence,
            cancel_event,
            worker_cancel,
        )
        try:
            self._wait_for_batch({future: None}, owner_token, cancel_event)
            candidate_result = future.result()
        finally:
            worker_cancel.set()
            self._shutdown_executor(executor, {future}, owner_token)
        seeds = candidate_result.seeds
        self._check_cancel(cancel_event)
        counters.archive_processed = len(evidence)
        counters.candidate_count = len(seeds)
        self._update_stage(run_id, stage, owner_token, failed_archives, counters)
        return seeds

    def _run_full_stage(
        self,
        run_id: int,
        root_id: int,
        inputs: tuple[ArchiveAnalysisInput, ...],
        seeds: tuple[CandidateSeed, ...],
        cancel_event: Event,
        owner_token: str,
        failed_archives: set[int],
        counters: _RunCounters,
    ) -> None:
        stage = AnalysisStage.FULL
        counters.archive_processed = 0
        counters.image_processed = 0
        candidate_ids = {
            archive_id
            for seed in seeds
            for archive_id in (seed.archive_a_id, seed.archive_b_id)
        }
        values = tuple(value for value in inputs if value.archive_id in candidate_ids)
        self._stage_totals[stage] = len(values)
        self._start_stage(run_id, stage, owner_token, failed_archives, counters)
        self._repository.prepare_duplicate_jobs(
            run_id,
            stage,
            tuple((str(value.archive_id), value.archive_id) for value in values),
            now=self._now(),
            owner_token=owner_token,
        )
        for input_batch in self._repository.iter_analysis_input_batches(
            root_id,
            archive_ids=tuple(candidate_ids),
            checkpoint=lambda: self._owner_checkpoint(owner_token, cancel_event),
        ):
            for offset in range(0, len(input_batch), self._workers):
                self._run_full_batch(
                    run_id,
                    stage,
                    input_batch[offset : offset + self._workers],
                    cancel_event,
                    owner_token,
                    failed_archives,
                    counters,
                )
        self._check_cancel(cancel_event)
        self._update_stage(run_id, stage, owner_token, failed_archives, counters)

    def _run_full_batch(
        self,
        run_id: int,
        stage: AnalysisStage,
        batch: tuple[ArchiveAnalysisInput, ...],
        cancel_event: Event,
        owner_token: str,
        failed_archives: set[int],
        counters: _RunCounters,
    ) -> None:
        self._check_cancel(cancel_event)
        futures: dict[Future[_FullCollection], tuple[ArchiveAnalysisInput, DuplicateJob]] = {}
        executor = ThreadPoolExecutor(
            max_workers=self._workers, thread_name_prefix="archive-analyzer-full"
        )
        try:
            for value in batch:
                self._check_cancel(cancel_event)
                job = self._claim(run_id, stage, str(value.archive_id), owner_token)
                cached = self._repository.cached_fingerprints(
                    value, self._analyzer_version
                )
                if cached is None:
                    code = "CHANGED_DURING_ANALYSIS"
                    self._finish_job(job, "FAILED", code, owner_token)
                    failed_archives.add(value.archive_id)
                    counters.archive_processed += 1
                    continue
                if self._is_full_cache_complete(value, cached):
                    code = self._first_cached_error(cached)
                    self._finish_job(
                        job, "FAILED" if code else "SKIPPED", code, owner_token
                    )
                    if code:
                        failed_archives.add(value.archive_id)
                    counters.archive_processed += 1
                    counters.image_processed += len(value.images)
                    continue
                future = executor.submit(
                    self._collect_full_fingerprints, value, cached, cancel_event
                )
                futures[future] = (value, job)
            self._wait_for_batch(futures, owner_token, cancel_event)
            for future, (value, job) in futures.items():
                try:
                    collected = future.result()
                    self._check_cancel(cancel_event)
                    if not self._repository.store_full_fingerprints(
                        value,
                        analyzer_version=self._analyzer_version,
                        computed_at=self._now(),
                        successes=collected.successes,
                        failures=collected.failures,
                        owner_token=owner_token,
                        now=self._now,
                    ):
                        raise AnalysisFailure("CHANGED_DURING_ANALYSIS")
                except AnalysisCancelled:
                    self._reset_running(run_id, owner_token)
                    raise
                except (AnalysisFailure, ImageReadFailure) as error:
                    code = self._error_code(error)
                    self._finish_job(job, "FAILED", code, owner_token)
                    failed_archives.add(value.archive_id)
                except BaseException:
                    raise
                else:
                    code = (
                        self._normalize_error_code(collected.failures[0][1])
                        if collected.failures
                        else None
                    )
                    self._finish_job(
                        job, "FAILED" if code else "SUCCEEDED", code, owner_token
                    )
                    if code:
                        failed_archives.add(value.archive_id)
                counters.archive_processed += 1
                counters.image_processed += len(value.images)
                self._update_stage(
                    run_id, stage, owner_token, failed_archives, counters
                )
        finally:
            self._shutdown_executor(executor, set(futures), owner_token)
        self._heartbeat(owner_token)

    def _collect_full_fingerprints(
        self,
        value: ArchiveAnalysisInput,
        cached: CachedFingerprints,
        cancel_event: Event,
    ) -> _FullCollection:
        self._require_snapshot(value)
        cached_successes = {
            item.entry_position: item.fingerprint for item in cached.image_fingerprints
        }
        cached_failures = dict(cached.image_failures)
        path_counts = Counter(image.path for image in value.images)
        successes: list[tuple[int, ImageFingerprint]] = []
        failures: list[tuple[int, str]] = []
        for entry in value.images:
            self._check_cancel(cancel_event)
            if entry.position in cached_successes:
                successes.append((entry.position, cached_successes[entry.position]))
                continue
            if entry.position in cached_failures:
                failures.append((entry.position, cached_failures[entry.position]))
                continue
            try:
                payload = self._reader_or_raise().read(
                    self._file_snapshot(value),
                    entry,
                    same_path_count=path_counts[entry.path],
                )
                self._check_cancel(cancel_event)
                self._require_snapshot(value)
                fingerprint = fingerprint_image(payload)
                self._check_cancel(cancel_event)
                self._require_snapshot(value)
            except ImageReadFailure as error:
                if error.code in _STABLE_IMAGE_ERRORS:
                    failures.append((entry.position, error.code))
                    continue
                raise
            except FingerprintFailure as error:
                failures.append((entry.position, error.code))
                continue
            successes.append((entry.position, fingerprint))
        self._check_cancel(cancel_event)
        self._require_snapshot(value)
        return _FullCollection(tuple(successes), tuple(failures))

    def _run_match_stage(
        self,
        run_id: int,
        root_id: int,
        inputs: tuple[ArchiveAnalysisInput, ...],
        seeds: tuple[CandidateSeed, ...],
        cancel_event: Event,
        owner_token: str,
        failed_archives: set[int],
        counters: _RunCounters,
    ) -> tuple[CandidateMatch, ...]:
        stage = AnalysisStage.MATCH
        self._stage_totals[stage] = len(seeds)
        counters.archive_processed = 0
        counters.image_processed = 0
        self._start_stage(run_id, stage, owner_token, failed_archives, counters)
        self._repository.prepare_duplicate_jobs(
            run_id,
            stage,
            tuple((self._pair_key(seed), None) for seed in seeds),
            now=self._now(),
            owner_token=owner_token,
        )
        matches: list[CandidateMatch] = []
        executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="archive-analyzer-match"
        )
        worker_cancel = Event()
        submitted: set[Future] = set()
        try:
            for offset in range(0, len(seeds), _MATCH_INPUT_BATCH_SIZE):
                seed_batch = seeds[offset : offset + _MATCH_INPUT_BATCH_SIZE]
                archive_ids = tuple(
                    {
                        archive_id
                        for seed in seed_batch
                        for archive_id in (seed.archive_a_id, seed.archive_b_id)
                    }
                )
                states: dict[int, _FullState | None] = {}
                for input_batch in self._repository.iter_analysis_input_batches(
                    root_id,
                    archive_ids=archive_ids,
                    checkpoint=lambda: self._owner_checkpoint(
                        owner_token, cancel_event
                    ),
                ):
                    for value in input_batch:
                        states[value.archive_id] = self._load_full_state(value)
                        self._owner_checkpoint(owner_token, cancel_event)
                for seed in seed_batch:
                    self._check_cancel(cancel_event)
                    self._heartbeat(owner_token)
                    job = self._claim(
                        run_id, stage, self._pair_key(seed), owner_token
                    )
                    left = states.get(seed.archive_a_id)
                    right = states.get(seed.archive_b_id)
                    if left is None or right is None:
                        if left is None:
                            failed_archives.add(seed.archive_a_id)
                        if right is None:
                            failed_archives.add(seed.archive_b_id)
                        self._finish_job(
                            job, "FAILED", "CHANGED_DURING_ANALYSIS", owner_token
                        )
                    else:
                        left_set = left.fingerprints
                        right_set = right.fingerprints
                        exact_archive = bool(
                            left_set.file_sha256
                            and left_set.file_sha256 == right_set.file_sha256
                        )
                        if not exact_archive:
                            if not left.complete or left.error_code:
                                left_set = replace(
                                    left_set,
                                    snapshot_stable=False,
                                    stability_error=(
                                        left.error_code
                                        or "INCOMPLETE_FULL_FINGERPRINTS"
                                    ),
                                )
                            if not right.complete or right.error_code:
                                right_set = replace(
                                    right_set,
                                    snapshot_stable=False,
                                    stability_error=(
                                        right.error_code
                                        or "INCOMPLETE_FULL_FINGERPRINTS"
                                    ),
                                )
                        future = executor.submit(
                            self._call_matcher,
                            left_set,
                            right_set,
                            seed,
                            cancel_event,
                            worker_cancel,
                        )
                        submitted.add(future)
                        try:
                            self._wait_for_batch(
                                {future: None}, owner_token, cancel_event
                            )
                            matches.append(future.result())
                        except AnalysisCancelled:
                            self._reset_running(run_id, owner_token)
                            raise
                        self._check_cancel(cancel_event)
                        self._heartbeat(owner_token)
                        self._finish_job(job, "SUCCEEDED", None, owner_token)
                    counters.archive_processed += 1
                    self._update_stage(
                        run_id, stage, owner_token, failed_archives, counters
                    )
        finally:
            worker_cancel.set()
            self._shutdown_executor(executor, submitted, owner_token)
        self._check_cancel(cancel_event)
        return tuple(matches)

    def _store_groups(
        self,
        run_id: int,
        root_id: int,
        inputs: tuple[ArchiveAnalysisInput, ...],
        matches: tuple[CandidateMatch, ...],
        cancel_event: Event,
        owner_token: str,
        failed_archives: set[int],
        counters: _RunCounters,
    ) -> DuplicateSummary:
        stage = AnalysisStage.GROUP
        counters.archive_processed = 0
        self._start_stage(run_id, stage, owner_token, failed_archives, counters)
        values = {value.archive_id: value for value in inputs}
        changed_archive_ids: set[int] = set()
        while True:
            self._check_cancel(cancel_event)
            self._heartbeat(owner_token)
            changed_archive_ids.update(
                self._changed_archive_ids(
                    matches,
                    values,
                    changed_archive_ids,
                    checkpoint=lambda: self._owner_checkpoint(
                        owner_token, cancel_event
                    ),
                )
            )
            failed_archives.update(changed_archive_ids)
            filtered_matches = tuple(
                match
                for match in matches
                if match.archive_a_id not in changed_archive_ids
                and match.archive_b_id not in changed_archive_ids
            )
            write_now = self._now()
            self._repository.replace_candidate_relations(
                root_id,
                analyzer_version=self._analyzer_version,
                matches=filtered_matches,
                created_at=write_now,
                owner_token=owner_token,
                now=self._now,
            )
            self._check_cancel(cancel_event)
            self._heartbeat(owner_token)
            newly_changed = self._changed_archive_ids(
                matches,
                values,
                changed_archive_ids,
                checkpoint=lambda: self._owner_checkpoint(
                    owner_token, cancel_event
                ),
            )
            if not newly_changed:
                break
            changed_archive_ids.update(newly_changed)
            failed_archives.update(newly_changed)
        groups = self._repository.group_summaries(root_id)
        counts = Counter(group.strongest_relation for group in groups)
        counters.archive_processed = len(inputs)
        counters.candidate_count = len(groups)
        self._update_stage(run_id, stage, owner_token, failed_archives, counters)
        return DuplicateSummary(
            run_id=run_id,
            completed=True,
            exact_archive_groups=counts[DuplicateRelation.EXACT_ARCHIVE],
            exact_content_groups=counts[DuplicateRelation.EXACT_CONTENT],
            visual_variant_groups=counts[DuplicateRelation.VISUAL_VARIANT],
            related_groups=counts[DuplicateRelation.RELATED],
            failed_archives=len(failed_archives),
        )

    def _changed_archive_ids(
        self,
        matches: tuple[CandidateMatch, ...],
        values: dict[int, ArchiveAnalysisInput],
        already_changed: set[int],
        *,
        checkpoint: Callable[[], None] | None = None,
    ) -> set[int]:
        archive_ids = {
            archive_id
            for match in matches
            for archive_id in (match.archive_a_id, match.archive_b_id)
            if archive_id not in already_changed
        }
        changed: set[int] = set()
        for archive_id in archive_ids:
            if checkpoint is not None:
                checkpoint()
            if archive_id not in values or not self._snapshot_is_current(
                values[archive_id]
            ):
                changed.add(archive_id)
        return changed

    def _load_full_state(self, value: ArchiveAnalysisInput) -> _FullState | None:
        cached = self._repository.cached_fingerprints(value, self._analyzer_version)
        if cached is None:
            return None
        pages = tuple(
            item.fingerprint
            for item in sorted(cached.image_fingerprints, key=lambda item: item.entry_position)
        )
        return _FullState(
            fingerprints=ArchiveFingerprintSet(
                archive_id=value.archive_id,
                file_sha256=cached.sha256,
                pages=pages,
            ),
            complete=self._is_full_cache_complete(value, cached),
            error_code=self._first_cached_error(cached),
        )

    def _is_full_cache_complete(
        self, value: ArchiveAnalysisInput, cached: CachedFingerprints
    ) -> bool:
        expected = {image.position for image in value.images}
        return bool(expected) and cached.full_entry_positions == expected

    def _first_cached_error(self, cached: CachedFingerprints) -> str | None:
        if not cached.image_failures:
            return None
        return self._normalize_error_code(cached.image_failures[0][1])

    def _start_stage(
        self,
        run_id: int,
        stage: AnalysisStage,
        owner_token: str,
        failed_archives: set[int],
        counters: _RunCounters,
    ) -> None:
        self._update_stage(run_id, stage, owner_token, failed_archives, counters)
        self._heartbeat(owner_token)

    def _update_stage(
        self,
        run_id: int,
        stage: AnalysisStage,
        owner_token: str,
        failed_archives: set[int],
        counters: _RunCounters,
    ) -> None:
        self._repository.update_duplicate_run(
            run_id,
            stage=stage,
            archive_processed=counters.archive_processed,
            image_processed=counters.image_processed,
            failed_count=len(failed_archives),
            candidate_count=counters.candidate_count,
            now=self._now(),
            owner_token=owner_token,
        )
        if stage is not AnalysisStage.CANDIDATE_BUILD:
            phase = {
                AnalysisStage.ARCHIVE_HASH: "완전 동일 검사",
                AnalysisStage.PROBE: "대표 이미지 검사",
                AnalysisStage.FULL: "후보 파일 이미지 검사",
                AnalysisStage.MATCH: "후보 쌍 정밀 비교",
                AnalysisStage.GROUP: "검사 결과 저장",
            }[stage]
            total = self._stage_totals.get(stage, self._archive_total)
            if stage is AnalysisStage.GROUP and counters.archive_processed == 0:
                total = None
            self._publish(stage, phase, counters.archive_processed, total,
                          unit="쌍" if stage is AnalysisStage.MATCH else "파일")

    def _publish(self, stage, phase, completed, total, unit="파일", current_item="", detail="") -> None:
        if self._progress_callback is not None:
            self._progress_callback(AnalysisProgress(stage, phase, completed, total, unit, current_item, detail))

    def _claim(
        self, run_id: int, stage: AnalysisStage, subject_key: str, owner_token: str
    ) -> DuplicateJob:
        return self._repository.claim_duplicate_job(
            run_id,
            stage,
            subject_key,
            now=self._now(),
            owner_token=owner_token,
        )

    def _finish_job(
        self,
        job: DuplicateJob,
        status: str,
        error_code: str | None,
        owner_token: str,
    ) -> None:
        self._repository.finish_duplicate_job(
            job.id,
            status=status,
            error_code=error_code,
            now=self._now(),
            owner_token=owner_token,
        )

    def _wait_for_batch(
        self,
        futures: dict[Future, object],
        owner_token: str,
        cancel_event: Event,
    ) -> None:
        pending = set(futures)
        while pending:
            _, pending = wait(
                pending, timeout=self._heartbeat_interval_seconds
            )
            self._check_cancel(cancel_event)
            self._heartbeat(owner_token)

    def _call_candidate_builder(
        self,
        evidence,
        cancel_event: Event,
        worker_cancel: Event,
    ):
        checkpoint = lambda: self._worker_checkpoint(cancel_event, worker_cancel)
        kwargs = {}
        if self._candidate_builder_accepts_checkpoint:
            kwargs["checkpoint"] = checkpoint
        if self._candidate_builder_accepts_progress:
            kwargs["progress_callback"] = self._progress_callback
        return self._candidate_builder(evidence, **kwargs)

    def _call_matcher(
        self,
        left: ArchiveFingerprintSet,
        right: ArchiveFingerprintSet,
        seed: CandidateSeed,
        cancel_event: Event,
        worker_cancel: Event,
    ) -> CandidateMatch:
        checkpoint = lambda: self._worker_checkpoint(cancel_event, worker_cancel)
        if self._matcher_accepts_checkpoint:
            return self._matcher(left, right, seed, checkpoint=checkpoint)
        return self._matcher(left, right, seed)

    def _shutdown_executor(
        self,
        executor: ThreadPoolExecutor,
        futures: set[Future],
        owner_token: str,
    ) -> None:
        executor.shutdown(wait=False, cancel_futures=True)
        pending = {future for future in futures if not future.done()}
        heartbeat_error: BaseException | None = None
        try:
            while pending:
                _, pending = wait(
                    pending, timeout=self._heartbeat_interval_seconds
                )
                if heartbeat_error is None:
                    try:
                        self._heartbeat(owner_token)
                    except BaseException as error:
                        heartbeat_error = error
        finally:
            executor.shutdown(wait=True, cancel_futures=True)
        if heartbeat_error is not None:
            raise heartbeat_error

    def _owner_checkpoint(self, owner_token: str, cancel_event: Event) -> None:
        self._check_cancel(cancel_event)
        if (
            monotonic() - self._last_heartbeat_monotonic
            >= self._heartbeat_interval_seconds
        ):
            self._heartbeat(owner_token)

    def _heartbeat(self, owner_token: str) -> None:
        self._repository.heartbeat_operation_lock(
            _DUPLICATE_LOCK_KIND, owner_token, self._now()
        )
        self._last_heartbeat_monotonic = monotonic()

    def _reset_running(self, run_id: int, owner_token: str) -> None:
        self._repository.reset_running_duplicate_jobs(
            run_id, now=self._now(), owner_token=owner_token
        )

    def _interrupt_run(
        self,
        run_id: int,
        owner_token: str,
        failed_archives: set[int],
        counters: _RunCounters,
        *,
        status: str,
    ) -> None:
        try:
            self._reset_running(run_id, owner_token)
            self._repository.finish_duplicate_run(
                run_id,
                status=status,
                archive_processed=counters.archive_processed,
                image_processed=counters.image_processed,
                failed_count=len(failed_archives),
                candidate_count=counters.candidate_count,
                finished_at=self._now(),
                owner_token=owner_token,
            )
        except ScanLockLost:
            try:
                cleanup_now = self._now()
                self._repository.acquire_operation_lock(
                    _DUPLICATE_LOCK_KIND,
                    owner_token,
                    cleanup_now,
                    lease_seconds=self._lease_seconds,
                )
            except ScanAlreadyRunning:
                return
            try:
                self._reset_running(run_id, owner_token)
                self._repository.finish_duplicate_run(
                    run_id,
                    status=status,
                    archive_processed=counters.archive_processed,
                    image_processed=counters.image_processed,
                    failed_count=len(failed_archives),
                    candidate_count=counters.candidate_count,
                    finished_at=self._now(),
                    owner_token=owner_token,
                )
            except (RuntimeError, ScanLockLost):
                return
        except RuntimeError:
            return

    def _archive_cache_error(self, archive_id: int) -> str | None:
        return self._repository.archive_fingerprint_error(archive_id)

    def _reader_or_raise(self) -> ArchiveImageReader:
        if self._reader is None:
            raise ValueError("An archive image reader is required for duplicate analysis.")
        return self._reader

    def _error_code(self, error: BaseException) -> str:
        if isinstance(error, (AnalysisFailure, ImageReadFailure)):
            return self._normalize_error_code(error.code)
        if isinstance(error, PermissionError):
            return "ACCESS_DENIED"
        if isinstance(error, FileNotFoundError):
            return "CHANGED_DURING_ANALYSIS"
        if isinstance(error, OSError):
            return "HASH_READ_FAILED"
        raise TypeError("Unexpected error does not have a stable analysis code.")

    @staticmethod
    def _normalize_error_code(code: str | None) -> str | None:
        if code is None:
            return None
        if code == "IMAGE_DECODE_FAILED":
            return "CORRUPT_IMAGE"
        if code == "ARCHIVE_CHANGED":
            return "CHANGED_DURING_ANALYSIS"
        return code

    @staticmethod
    def _pair_key(seed: CandidateSeed) -> str:
        return f"{seed.archive_a_id}:{seed.archive_b_id}"

    @staticmethod
    def _file_snapshot(value: ArchiveAnalysisInput) -> FileSnapshot:
        return FileSnapshot(
            path=value.path,
            path_key=normalize_path_key(value.path),
            size=value.file_size,
            mtime_ns=value.mtime_ns,
            archive_format=value.archive_format,
        )

    @staticmethod
    def _require_snapshot(value: ArchiveAnalysisInput) -> None:
        try:
            current = value.path.stat()
        except OSError as error:
            raise AnalysisFailure("CHANGED_DURING_ANALYSIS") from error
        if current.st_size != value.file_size or current.st_mtime_ns != value.mtime_ns:
            raise AnalysisFailure("CHANGED_DURING_ANALYSIS")

    @staticmethod
    def _snapshot_is_current(value: ArchiveAnalysisInput) -> bool:
        try:
            current = value.path.stat()
        except OSError:
            return False
        return current.st_size == value.file_size and current.st_mtime_ns == value.mtime_ns

    @staticmethod
    def _check_cancel(cancel_event: Event) -> None:
        if cancel_event.is_set():
            raise AnalysisCancelled

    @staticmethod
    def _worker_checkpoint(cancel_event: Event, worker_cancel: Event) -> None:
        if cancel_event.is_set() or worker_cancel.is_set():
            raise AnalysisCancelled

    def _now(self) -> datetime:
        value = self._clock()
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _accepts_checkpoint(function: Callable) -> bool:
    return _accepts_keyword(function, "checkpoint")


def _accepts_keyword(function: Callable, name: str) -> bool:
    try:
        parameters = signature(function).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        parameter.name == name
        or parameter.kind is Parameter.VAR_KEYWORD
        for parameter in parameters
    )
