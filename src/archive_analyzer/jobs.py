from __future__ import annotations

import errno
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Thread
from time import monotonic
from typing import Callable, Iterable
from uuid import uuid4

from archive_analyzer.discovery import discover_archives
from archive_analyzer.domain import DiscoveryError, DiscoveryEvent, FileSnapshot
from archive_analyzer.inspection import ArchiveInspector, InspectionFailure, InspectionResult
from archive_analyzer.paths import is_path_within, normalize_path_key
from archive_analyzer.storage.repository import (
    JobClaimLost,
    PendingJob,
    Repository,
    RunNotActive,
    ScanAlreadyRunning,
    ScanLockLost,
)


_HEARTBEAT_INTERVAL_SECONDS = 10.0
_CANCEL_POLL_SECONDS = 0.1


class ScanCancelled(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ScanSummary:
    run_id: int
    discovered_count: int
    reused_count: int
    indexed_count: int
    skipped_count: int
    failed_count: int
    discovery_complete: bool


@dataclass(frozen=True, slots=True)
class _WorkerOutcome:
    job: PendingJob
    result: InspectionResult | None = None
    failure: InspectionFailure | None = None


@dataclass(frozen=True, slots=True)
class _DiscoveryFinished:
    error: BaseException | None = None


class ScanService:
    def __init__(
        self,
        repository: Repository,
        inspector: ArchiveInspector,
        discoverer: Callable[[Path], Iterable[DiscoveryEvent]] = discover_archives,
        workers: int = 2,
    ) -> None:
        if workers <= 0:
            raise ValueError("workers must be positive")
        self._repository = repository
        self._inspector = inspector
        self._discoverer = discoverer
        self._workers = workers

    def run(self, root: Path, cancel_event: Event | None = None) -> ScanSummary:
        shared_cancel_event = cancel_event or Event()
        owner_token = uuid4().hex
        now = datetime.now(UTC)
        self._repository.acquire_scan_lock(owner_token, now)
        run_id: int | None = None
        discovered_count = reused_count = indexed_count = skipped_count = failed_count = 0
        processed_counts = [0, 0, 0]
        discovery_complete = True
        try:
            self._repository.recover_stale_jobs(now, owner_token=owner_token)
            root_id = self._repository.get_or_create_root(
                root,
                normalize_path_key(root),
                owner_token=owner_token,
                now=now,
            )
            run_id = self._repository.start_run(
                root_id, now, owner_token=owner_token
            )

            for event in self._discovery_events(
                root, owner_token, shared_cancel_event
            ):
                self._raise_if_cancelled(shared_cancel_event)
                if event.error is not None:
                    discovery_complete = False
                    mutation_now = datetime.now(UTC)
                    self._repository.record_discovery_error(
                        run_id,
                        event.error,
                        mutation_now,
                        owner_token=owner_token,
                    )
                elif event.snapshot is not None:
                    boundary_error = _snapshot_boundary_error(root, event.snapshot)
                    if boundary_error is not None:
                        discovery_complete = False
                        mutation_now = datetime.now(UTC)
                        self._repository.record_discovery_error(
                            run_id,
                            boundary_error,
                            mutation_now,
                            owner_token=owner_token,
                        )
                        continue
                    discovered_count += 1
                    mutation_now = datetime.now(UTC)
                    disposition = self._repository.enqueue_or_reuse(
                        run_id,
                        root_id,
                        event.snapshot,
                        owner_token=owner_token,
                        now=mutation_now,
                    )
                    if disposition == "REUSED":
                        reused_count += 1
                else:
                    raise ValueError("DiscoveryEvent must contain a snapshot or an error.")

            self._raise_if_cancelled(shared_cancel_event)
            self._process_jobs(
                run_id, owner_token, processed_counts, shared_cancel_event
            )
            indexed_count, skipped_count, failed_count = processed_counts
            if discovery_complete:
                self._repository.mark_unseen_archives_missing(
                    run_id,
                    root_id,
                    owner_token=owner_token,
                    now=datetime.now(UTC),
                )
            summary = ScanSummary(
                run_id,
                discovered_count,
                reused_count,
                indexed_count,
                skipped_count,
                failed_count,
                discovery_complete,
            )
            self._repository.heartbeat_scan_lock(owner_token, datetime.now(UTC))
            self._repository.finish_run(
                run_id, summary, datetime.now(UTC), owner_token=owner_token
            )
            return summary
        except (KeyboardInterrupt, ScanCancelled):
            indexed_count, skipped_count, failed_count = processed_counts
            if run_id is not None:
                summary = ScanSummary(
                    run_id,
                    discovered_count,
                    reused_count,
                    indexed_count,
                    skipped_count,
                    failed_count,
                    False,
                )
                self._finish_run_if_owned(
                    owner_token, run_id, summary, status="INTERRUPTED"
                )
            raise
        except BaseException:
            indexed_count, skipped_count, failed_count = processed_counts
            if run_id is not None:
                summary = ScanSummary(
                    run_id,
                    discovered_count,
                    reused_count,
                    indexed_count,
                    skipped_count,
                    failed_count,
                    False,
                )
                self._finish_run_if_owned(
                    owner_token, run_id, summary, status="FAILED"
                )
            raise
        finally:
            self._repository.release_scan_lock(owner_token)

    def _finish_run_if_owned(
        self,
        owner_token: str,
        run_id: int,
        summary: ScanSummary,
        *,
        status: str,
    ) -> None:
        try:
            self._repository.heartbeat_scan_lock(owner_token, datetime.now(UTC))
            self._repository.finish_run(
                run_id,
                summary,
                datetime.now(UTC),
                owner_token=owner_token,
                status=status,
            )
        except (ScanLockLost, RunNotActive):
            return

    def _process_jobs(
        self,
        run_id: int,
        owner_token: str,
        counts: list[int],
        cancel_event: Event,
    ) -> None:
        jobs = iter(self._repository.pending_jobs(run_id))
        executor = ThreadPoolExecutor(max_workers=self._workers)
        futures: dict[Future[_WorkerOutcome], PendingJob] = {}
        interrupted = False
        cancelled = False
        unexpected: BaseException | None = None
        next_heartbeat = monotonic() + _HEARTBEAT_INTERVAL_SECONDS
        try:
            self._fill_worker_slots(
                executor, futures, jobs, owner_token, cancel_event
            )
            while futures and not interrupted and unexpected is None:
                if cancel_event.is_set():
                    cancelled = True
                    break
                done, _ = wait(
                    futures,
                    timeout=min(
                        _CANCEL_POLL_SECONDS, _HEARTBEAT_INTERVAL_SECONDS
                    ),
                    return_when=FIRST_COMPLETED,
                )
                if not done:
                    if monotonic() >= next_heartbeat:
                        self._repository.heartbeat_scan_lock(
                            owner_token, datetime.now(UTC)
                        )
                        next_heartbeat = monotonic() + _HEARTBEAT_INTERVAL_SECONDS
                    continue
                for future in done:
                    futures.pop(future)
                    try:
                        outcome = future.result()
                    except KeyboardInterrupt:
                        interrupted = True
                    except BaseException as error:
                        unexpected = error
                    else:
                        try:
                            self._record_outcome(outcome, counts)
                        except BaseException as error:
                            unexpected = error
                if not interrupted and unexpected is None:
                    self._fill_worker_slots(
                        executor, futures, jobs, owner_token, cancel_event
                    )
                self._repository.heartbeat_scan_lock(owner_token, datetime.now(UTC))
                next_heartbeat = monotonic() + _HEARTBEAT_INTERVAL_SECONDS
        except KeyboardInterrupt:
            interrupted = True
        except ScanCancelled:
            cancelled = True
        finally:
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            lock_lost = False
            next_heartbeat = monotonic() + _HEARTBEAT_INTERVAL_SECONDS
            while futures:
                wait_timeout = (
                    _HEARTBEAT_INTERVAL_SECONDS
                    if lock_lost
                    else max(0.0, next_heartbeat - monotonic())
                )
                done, _ = wait(
                    futures,
                    timeout=wait_timeout,
                    return_when=FIRST_COMPLETED,
                )
                if not lock_lost and monotonic() >= next_heartbeat:
                    try:
                        self._repository.heartbeat_scan_lock(
                            owner_token, datetime.now(UTC)
                        )
                    except BaseException as error:
                        unexpected = unexpected or error
                        lock_lost = True
                    else:
                        next_heartbeat = monotonic() + _HEARTBEAT_INTERVAL_SECONDS
                if not done:
                    continue
                for future in done:
                    futures.pop(future)
                    if future.cancelled():
                        continue
                    try:
                        outcome = future.result()
                    except KeyboardInterrupt:
                        interrupted = True
                    except BaseException as error:
                        unexpected = unexpected or error
                    else:
                        if lock_lost or isinstance(
                            unexpected, (JobClaimLost, ScanLockLost)
                        ):
                            continue
                        try:
                            self._record_outcome(outcome, counts)
                        except BaseException as error:
                            unexpected = unexpected or error
                            if isinstance(error, (JobClaimLost, ScanLockLost)):
                                lock_lost = True
            executor.shutdown(wait=True, cancel_futures=True)
        if interrupted:
            raise KeyboardInterrupt
        if cancelled:
            raise ScanCancelled
        if unexpected is not None:
            raise unexpected

    def _discovery_events(
        self, root: Path, owner_token: str, cancel_event: Event
    ) -> Iterable[DiscoveryEvent]:
        queue: Queue[DiscoveryEvent | _DiscoveryFinished] = Queue(
            maxsize=max(1, self._workers)
        )
        stopped = Event()

        def offer(item: DiscoveryEvent | _DiscoveryFinished) -> bool:
            while not stopped.is_set() and not cancel_event.is_set():
                try:
                    queue.put(
                        item,
                        timeout=min(
                            _CANCEL_POLL_SECONDS, _HEARTBEAT_INTERVAL_SECONDS
                        ),
                    )
                except Full:
                    continue
                return True
            return False

        def produce() -> None:
            try:
                for event in self._discoverer(root):
                    if not offer(event):
                        return
            except BaseException as error:
                offer(_DiscoveryFinished(error))
                return
            offer(_DiscoveryFinished())

        producer = Thread(target=produce, name="archive-discovery", daemon=True)
        producer.start()
        next_heartbeat = monotonic() + _HEARTBEAT_INTERVAL_SECONDS
        try:
            while True:
                self._raise_if_cancelled(cancel_event)
                try:
                    item = queue.get(
                        timeout=min(
                            _CANCEL_POLL_SECONDS, _HEARTBEAT_INTERVAL_SECONDS
                        )
                    )
                except Empty:
                    if monotonic() >= next_heartbeat:
                        self._repository.heartbeat_scan_lock(
                            owner_token, datetime.now(UTC)
                        )
                        next_heartbeat = monotonic() + _HEARTBEAT_INTERVAL_SECONDS
                    continue
                if isinstance(item, _DiscoveryFinished):
                    if item.error is not None:
                        raise item.error
                    return
                yield item
                self._repository.heartbeat_scan_lock(owner_token, datetime.now(UTC))
                next_heartbeat = monotonic() + _HEARTBEAT_INTERVAL_SECONDS
        finally:
            stopped.set()

    def _fill_worker_slots(
        self,
        executor: ThreadPoolExecutor,
        futures: dict[Future[_WorkerOutcome], PendingJob],
        jobs,
        owner_token: str,
        cancel_event: Event,
    ) -> None:
        while len(futures) < self._workers:
            self._raise_if_cancelled(cancel_event)
            try:
                job = next(jobs)
            except StopIteration:
                return
            claimed_job = self._repository.begin_job(
                job.id,
                datetime.now(UTC),
                expected_scan_run_id=job.scan_run_id,
                owner_token=owner_token,
            )
            futures[executor.submit(self._inspect_job, claimed_job)] = claimed_job

    @staticmethod
    def _raise_if_cancelled(cancel_event: Event) -> None:
        if cancel_event.is_set():
            raise ScanCancelled

    def _inspect_job(self, job: PendingJob) -> _WorkerOutcome:
        before_failure = _snapshot_mismatch(job)
        if before_failure is not None:
            return _WorkerOutcome(job, failure=before_failure)
        result: InspectionResult | None = None
        failure: InspectionFailure | None = None
        try:
            result = self._inspector.inspect(job.snapshot)
        except InspectionFailure as error:
            failure = error
        except OSError as error:
            failure = _filesystem_failure(error)
        after_failure = _snapshot_mismatch(job)
        if after_failure is not None:
            return _WorkerOutcome(job, failure=after_failure)
        return _WorkerOutcome(job, result=result, failure=failure)

    def _record_outcome(self, outcome: _WorkerOutcome, counts: list[int]) -> None:
        finished_at = datetime.now(UTC)
        if outcome.failure is None:
            assert outcome.result is not None
            self._repository.replace_archive_index(
                outcome.job, outcome.result, finished_at
            )
            counts[0] += 1
            return
        self._repository.fail_job(outcome.job, outcome.failure, finished_at)
        if outcome.failure is not None:
            if outcome.failure.code in {"ENCRYPTED_UNSUPPORTED", "NESTED_ARCHIVE_SKIPPED"}:
                counts[1] += 1
            else:
                counts[2] += 1


def _snapshot_mismatch(job: PendingJob) -> InspectionFailure | None:
    try:
        value = job.snapshot.path.stat()
    except OSError as error:
        return _filesystem_failure(error)
    if value.st_size != job.snapshot.size or value.st_mtime_ns != job.snapshot.mtime_ns:
        return InspectionFailure(
            "CHANGED_DURING_SCAN",
            "Archive changed while it was being scanned.",
        )
    return None


def _snapshot_boundary_error(
    root: Path, snapshot: FileSnapshot
) -> DiscoveryError | None:
    if not is_path_within(snapshot.path, root):
        return DiscoveryError(
            path=snapshot.path,
            code="OUTSIDE_SCAN_ROOT",
            summary="Discovered archive is outside the requested scan root.",
        )
    actual_path_key = normalize_path_key(snapshot.path)
    if actual_path_key != snapshot.path_key:
        return DiscoveryError(
            path=snapshot.path,
            code="PATH_KEY_MISMATCH",
            summary="Discovered archive path key does not match its path.",
            detail=f"expected={actual_path_key}; received={snapshot.path_key}",
        )
    return None


def _filesystem_failure(error: OSError) -> InspectionFailure:
    if error.errno in {errno.ENOENT, errno.ENOTDIR}:
        return InspectionFailure("FILE_NOT_FOUND", "Archive file was not found.", str(error))
    if error.errno in {errno.EACCES, errno.EPERM}:
        return InspectionFailure("ACCESS_DENIED", "Archive access was denied.", str(error))
    if error.errno == errno.ENAMETOOLONG:
        return InspectionFailure("PATH_TOO_LONG", "Archive path is too long.", str(error))
    return InspectionFailure("ARCHIVE_IO_ERROR", "Archive could not be read.", str(error))


__all__ = ["ScanAlreadyRunning", "ScanCancelled", "ScanService", "ScanSummary"]
