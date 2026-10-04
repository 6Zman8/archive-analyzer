"""Preview and apply saved recommendations without touching archive files."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from archive_analyzer.archive_hashing import AnalysisCancelled
from archive_analyzer.deletion import (
    DeletionSafetyError,
    delete_quarantined_archives,
)
from archive_analyzer.domain import FileSnapshot
from archive_analyzer.duplicate_domain import ReviewAction
from archive_analyzer.paths import normalize_path_key
from archive_analyzer.quarantine import QuarantineSafetyError, quarantine_archives, restore_archives
from archive_analyzer.storage.duplicate_repository import RecommendationRecord


@dataclass(frozen=True, slots=True)
class RecommendationApplyPreview:
    keep: int
    remove: int
    no_recommendation: int
    user_decision_skipped: int
    changed_snapshot_skipped: int

    @property
    def applicable(self) -> int:
        return self.keep + self.remove


@dataclass(frozen=True, slots=True)
class RecommendationApplySummary:
    keep: int
    remove: int
    no_recommendation: int
    user_decision_skipped: int
    changed_snapshot_skipped: int
    failed: int

    @property
    def applied(self) -> int:
        return self.keep + self.remove

    @property
    def skipped(self) -> int:
        return self.no_recommendation + self.user_decision_skipped + self.changed_snapshot_skipped


@dataclass(frozen=True, slots=True)
class BatchActionPreview:
    keep_count: int
    keep_bytes: int
    hold_count: int
    hold_bytes: int
    remove_count: int
    remove_bytes: int
    excluded_by_reason: dict[str, int]
    quarantined_count: int = 0
    quarantined_bytes: int = 0

    def deletion_warning(self) -> str:
        return (
            f"이미 격리된 파일 {self.quarantined_count:,}개를 영구 삭제합니다. "
            "원래 위치의 파일은 삭제하지 않습니다. 계속하시겠습니까?"
        )


@dataclass(frozen=True, slots=True)
class BatchTarget:
    set_key: str
    source_group_key: str
    archive_id: int


@dataclass(frozen=True, slots=True)
class BatchActionItemResult:
    archive_id: int
    state: str
    code: str | None = None

    @property
    def error_code(self) -> str | None:
        return self.code


@dataclass(frozen=True, slots=True)
class BatchActionSummary:
    completed_ids: tuple[int, ...]
    skipped: tuple[BatchActionItemResult, ...]
    failed: tuple[BatchActionItemResult, ...]

    @property
    def completed(self) -> int:
        return len(self.completed_ids)


def _selected_sets(repository, set_keys: Iterable[str]):  # type: ignore[no-untyped-def]
    keys = tuple(dict.fromkeys(str(value) for value in set_keys if str(value)))
    if not keys:
        return ()
    getter = getattr(repository, "review_candidate_sets_for_keys", None)
    if getter is not None:
        return tuple(getter(keys))
    connection = getattr(repository, "_connection", None)
    if connection is None:
        return ()
    placeholders = ",".join("?" for _ in keys)
    rows = connection.execute(
        f"SELECT set_key, source_group_key, edition_kind, member_ids_json "
        f"FROM edition_candidate_sets WHERE set_key IN ({placeholders}) ORDER BY set_key",
        keys,
    ).fetchall()
    from archive_analyzer.storage.duplicate_repository import ReviewCandidateSet

    output = []
    for set_key, source_group_key, edition_kind, member_ids_json in rows:
        try:
            archive_ids = tuple(int(value) for value in json.loads(member_ids_json))
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        output.append(ReviewCandidateSet(str(set_key), str(source_group_key), str(edition_kind), archive_ids))
    return tuple(output)


def _group_members(repository, candidate_set):  # type: ignore[no-untyped-def]
    detail = repository.group_details(candidate_set.source_group_key)
    if detail is None:
        return (), set()
    preserved = {
        archive_id
        for relation in detail.relations
        if relation.preserve_required
        for archive_id in (relation.archive_a_id, relation.archive_b_id)
    }
    wanted = set(candidate_set.archive_ids)
    members = tuple(member for member in detail.members if member.archive_id in wanted)
    return members, preserved


def _batch_entries(repository, set_keys: Iterable[str]):  # type: ignore[no-untyped-def]
    seen: set[int] = set()
    entries = []
    for candidate_set in _selected_sets(repository, set_keys):
        members, preserved = _group_members(repository, candidate_set)
        for member in members:
            if member.archive_id in seen:
                continue
            seen.add(member.archive_id)
            entries.append((candidate_set, member, member.archive_id in preserved))
    return tuple(entries)


def preview_batch_action(
    repository, set_keys: Iterable[str]
) -> BatchActionPreview:  # type: ignore[no-untyped-def]
    keep_count = keep_bytes = hold_count = hold_bytes = 0
    remove_count = remove_bytes = quarantined_count = quarantined_bytes = 0
    excluded: dict[str, int] = {}

    def exclude(reason: str) -> None:
        excluded[reason] = excluded.get(reason, 0) + 1

    for _candidate_set, member, preserved in _batch_entries(repository, set_keys):
        size = int(member.file_size)
        if member.deletion_state == "DELETED":
            exclude("DELETED")
        elif member.needs_review:
            exclude("NEEDS_REVIEW")
        elif member.review_action is ReviewAction.KEEP:
            keep_count += 1
            keep_bytes += size
        elif member.review_action is ReviewAction.HOLD:
            hold_count += 1
            hold_bytes += size
        elif member.review_action is ReviewAction.REMOVE_CANDIDATE:
            if member.quarantine_status == "QUARANTINED":
                quarantined_count += 1
                quarantined_bytes += size
            else:
                remove_count += 1
                remove_bytes += size
        else:
            exclude("UNREVIEWED")
    return BatchActionPreview(
        keep_count,
        keep_bytes,
        hold_count,
        hold_bytes,
        remove_count,
        remove_bytes,
        excluded,
        quarantined_count,
        quarantined_bytes,
    )


def _targets(repository, set_keys: Iterable[str], *, operation: str):  # type: ignore[no-untyped-def]
    output: list[BatchTarget] = []
    seen: set[int] = set()
    for candidate_set, member, preserved in _batch_entries(repository, set_keys):
        if member.archive_id in seen or member.needs_review:
            continue
        if member.review_action is not ReviewAction.REMOVE_CANDIDATE:
            continue
        if operation == "quarantine" and member.quarantine_status == "QUARANTINED":
            continue
        if operation == "delete" and member.quarantine_status != "QUARANTINED":
            continue
        if member.deletion_state == "DELETED":
            continue
        seen.add(member.archive_id)
        output.append(BatchTarget(candidate_set.set_key, candidate_set.source_group_key, member.archive_id))
    return tuple(output)


def _batch_progress(progress, index: int, total: int, phase: str) -> None:  # type: ignore[no-untyped-def]
    if progress is not None:
        progress(index, total, phase)


def batch_restore(repository, set_keys, cancel_event, progress=None) -> BatchActionSummary:
    targets = tuple((candidate, member) for candidate, member, _ in _batch_entries(repository, set_keys)
                    if member.quarantine_status == "QUARANTINED" and member.deletion_state != "DELETED")
    completed, failed = [], []
    for index, (candidate, member) in enumerate(targets, 1):
        _check_cancel(cancel_event)
        try:
            restore_archives(repository, candidate.source_group_key, (member.archive_id,), cancel_event)
        except AnalysisCancelled:
            raise
        except (QuarantineSafetyError, OSError, ValueError) as error:
            failed.append(BatchActionItemResult(member.archive_id, "FAILED", _error_code(error)))
        else:
            completed.append(member.archive_id)
        _batch_progress(progress, index, len(targets), "격리 복원")
    return BatchActionSummary(tuple(completed), (), tuple(failed))


def batch_quarantine(
    repository,
    set_keys: Iterable[str],
    quarantine_root: Path,
    cancel_event,
    progress=None,
) -> BatchActionSummary:  # type: ignore[no-untyped-def]
    targets = _targets(repository, set_keys, operation="quarantine")
    completed: list[int] = []
    skipped: list[BatchActionItemResult] = []
    failed: list[BatchActionItemResult] = []
    for index, target in enumerate(targets, start=1):
        _check_cancel(cancel_event)
        try:
            quarantine_archives(
                repository,
                target.source_group_key,
                (target.archive_id,),
                Path(quarantine_root),
                cancel_event,
            )
        except AnalysisCancelled:
            raise
        except (QuarantineSafetyError, OSError, ValueError) as error:
            failed.append(BatchActionItemResult(target.archive_id, "FAILED", _error_code(error)))
        else:
            completed.append(target.archive_id)
        _batch_progress(progress, index, len(targets), "batch_quarantine")
    return BatchActionSummary(tuple(completed), tuple(skipped), tuple(failed))


def batch_delete_quarantined(
    repository,
    set_keys: Iterable[str],
    cancel_event,
    progress=None,
) -> BatchActionSummary:  # type: ignore[no-untyped-def]
    targets = _targets(repository, set_keys, operation="delete")
    completed: list[int] = []
    skipped: list[BatchActionItemResult] = []
    failed: list[BatchActionItemResult] = []
    for index, target in enumerate(targets, start=1):
        _check_cancel(cancel_event)
        try:
            delete_quarantined_archives(
                repository,
                target.source_group_key,
                (target.archive_id,),
                cancel_event,
            )
        except AnalysisCancelled:
            raise
        except (DeletionSafetyError, OSError, ValueError) as error:
            failed.append(BatchActionItemResult(target.archive_id, "FAILED", _error_code(error)))
        else:
            completed.append(target.archive_id)
        _batch_progress(progress, index, len(targets), "batch_delete")
    return BatchActionSummary(tuple(completed), tuple(skipped), tuple(failed))


def _error_code(error: BaseException) -> str:
    return str(getattr(error, "code", "UNEXPECTED_ERROR"))


def _check_cancel(cancel_event) -> None:  # type: ignore[no-untyped-def]
    if cancel_event.is_set():
        raise AnalysisCancelled


def _records(repository, set_keys: Iterable[str]) -> tuple[RecommendationRecord, ...]:  # type: ignore[no-untyped-def]
    keys = tuple(dict.fromkeys(str(value) for value in set_keys if str(value)))
    if not keys:
        return ()
    records = repository.latest_recommendations(keys)
    # A malformed/old database can contain the same archive in more than one
    # row.  Applying one deterministic record is safer than appending two
    # contradictory actions.
    seen: set[tuple[str, int]] = set()
    output: list[RecommendationRecord] = []
    for record in sorted(records, key=lambda item: (item.set_key, item.archive_id, item.item_id)):
        key = (record.set_key, record.archive_id)
        if key not in seen:
            seen.add(key)
            output.append(record)
    return tuple(output)


def _record_state(repository, record: RecommendationRecord) -> str:  # type: ignore[no-untyped-def]
    if record.status != "RECOMMENDED" or record.recommendation not in {"KEEP", "REMOVE_CANDIDATE"}:
        return "NO_RECOMMENDATION"
    snapshot_checker = getattr(repository, "recommendation_snapshot_matches", None)
    if snapshot_checker is not None and not snapshot_checker(record):
        return "CHANGED_SNAPSHOT_SKIPPED"
    state = repository.latest_review_state(record.source_group_key, record.archive_id)
    if state.needs_review:
        return "CHANGED_SNAPSHOT_SKIPPED"
    if state.action_id is None:
        return "ELIGIBLE"
    application_id = None
    checker = getattr(repository, "recommendation_application_for_action", None)
    if checker is not None:
        application_id = checker(state.action_id)
    if application_id is None and not getattr(repository, "is_review_reset", lambda _: False)(state.action_id):
        return "USER_DECISION_SKIPPED"
    return "ELIGIBLE"


def preview_recommendation_application(
    repository, set_keys: Iterable[str]
) -> RecommendationApplyPreview:  # type: ignore[no-untyped-def]
    counts = {
        "KEEP": 0,
        "REMOVE_CANDIDATE": 0,
        "NO_RECOMMENDATION": 0,
        "USER_DECISION_SKIPPED": 0,
        "CHANGED_SNAPSHOT_SKIPPED": 0,
    }
    for record in _records(repository, set_keys):
        state = _record_state(repository, record)
        if state == "ELIGIBLE":
            counts[record.recommendation] += 1
        elif state == "NO_RECOMMENDATION":
            counts[state] += 1
        else:
            counts[state] += 1
    return RecommendationApplyPreview(
        keep=counts["KEEP"],
        remove=counts["REMOVE_CANDIDATE"],
        no_recommendation=counts["NO_RECOMMENDATION"],
        user_decision_skipped=counts["USER_DECISION_SKIPPED"],
        changed_snapshot_skipped=counts["CHANGED_SNAPSHOT_SKIPPED"],
    )


def _fallback_apply(repository, record: RecommendationRecord, now: datetime) -> str:  # type: ignore[no-untyped-def]
    """Compatibility path for small repository fakes used by integrations."""
    detail = repository.group_details(record.source_group_key)
    if detail is None:
        return "CHANGED_SNAPSHOT_SKIPPED"
    member = next((item for item in detail.members if item.archive_id == record.archive_id), None)
    if member is None or (member.file_size, member.mtime_ns) != (record.file_size, record.mtime_ns):
        return "CHANGED_SNAPSHOT_SKIPPED"
    action = ReviewAction.KEEP if record.recommendation == "KEEP" else ReviewAction.REMOVE_CANDIDATE
    snapshot = FileSnapshot(
        path=member.path,
        path_key=normalize_path_key(member.path),
        size=member.file_size,
        mtime_ns=member.mtime_ns,
        archive_format=member.archive_format,
    )
    repository.append_review_action(record.source_group_key, record.archive_id, action, snapshot, now)
    return "APPLIED"


def apply_recommendations(
    repository, set_keys: Iterable[str], now: datetime
) -> RecommendationApplySummary:  # type: ignore[no-untyped-def]
    keep = remove = no_recommendation = user_skipped = changed_skipped = failed = 0
    apply_one = getattr(repository, "apply_recommendation_item", None)
    for record in _records(repository, set_keys):
        if _record_state(repository, record) == "NO_RECOMMENDATION":
            no_recommendation += 1
            continue
        try:
            outcome = (
                apply_one(record, now)
                if apply_one is not None
                else _fallback_apply(repository, record, now)
            )
        except (OSError, ValueError, RuntimeError):
            failed += 1
            continue
        if outcome == "APPLIED":
            if record.recommendation == "KEEP":
                keep += 1
            else:
                remove += 1
        elif outcome == "USER_DECISION_SKIPPED":
            user_skipped += 1
        elif outcome == "CHANGED_SNAPSHOT_SKIPPED":
            changed_skipped += 1
        elif outcome == "NO_RECOMMENDATION":
            no_recommendation += 1
        elif outcome == "ALREADY_APPLIED":
            # It is already in the desired state; report it as an applied
            # recommendation without creating a duplicate review action.
            if record.recommendation == "KEEP":
                keep += 1
            else:
                remove += 1
        else:
            failed += 1
    return RecommendationApplySummary(
        keep=keep,
        remove=remove,
        no_recommendation=no_recommendation,
        user_decision_skipped=user_skipped,
        changed_snapshot_skipped=changed_skipped,
        failed=failed,
    )


__all__ = [
    "BatchActionItemResult",
    "BatchActionPreview",
    "BatchActionSummary",
    "BatchTarget",
    "RecommendationApplyPreview",
    "RecommendationApplySummary",
    "apply_recommendations",
    "batch_delete_quarantined",
    "batch_quarantine",
    "preview_batch_action",
    "preview_recommendation_application",
]
