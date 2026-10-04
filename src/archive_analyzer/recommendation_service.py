"""Build conservative recommendations from persisted analysis evidence only."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
from typing import Callable

from archive_analyzer.duplicate_domain import DuplicateRelation
from archive_analyzer.edition_analysis import EditionKind, classify_edition
from archive_analyzer.filename_normalization import FilenameSignal
from archive_analyzer.precision_analysis import DetectedLanguage, PairDirection
from archive_analyzer.recommendation import (
    PairEvidence,
    RecommendationDecision,
    RecommendationInput,
    RecommendationItem,
    RecommendationStatus,
    recommend_candidate_set,
    recommend_with_estimates,
)
from archive_analyzer.storage.duplicate_repository import (
    RecommendationRecord,
    RecommendationSourceGroup,
    ReviewCandidateSet,
)


_CRITERIA_VERSION = 8
_SET_ALGORITHM_VERSION = "v2"


@dataclass(frozen=True, slots=True)
class RecommendationRefreshSummary:
    groups_processed: int
    sets_processed: int
    recommended_sets: int
    skipped_sets: int


def refresh_recommendations(
    repository,
    root_id: int,
    *,
    affected_group_keys=None,
    allow_estimates: bool = False,
    selected_set_keys: tuple[str, ...] | None = None,
    clock: Callable[[], datetime] | None = None,
    policy=None,
    progress=None,
) -> RecommendationRefreshSummary:  # type: ignore[no-untyped-def]
    """Refresh requested groups; this module never opens or imports archive readers."""
    now = datetime.now(UTC) if clock is None else clock()
    if progress:
        progress(0, 0, "저장된 제목 정보 확인")
    repository.backfill_filename_evidence(root_id)
    if progress:
        progress(0, 0, "비교 근거 불러오기")
    groups = repository.recommendation_source_groups(root_id, affected_group_keys)
    sets_processed = recommended_sets = skipped_sets = 0
    for index, group in enumerate(groups):
        if progress:
            progress(index, len(groups), "추천 갱신")
        candidate_sets = partition_group(group)
        candidate_sets = repository.replace_candidate_sets(
            group.group_key, candidate_sets, computed_at=now
        ) or candidate_sets
        if selected_set_keys is not None:
            candidate_sets = tuple(candidate for candidate in candidate_sets if candidate.set_key in selected_set_keys)
            if not candidate_sets:
                continue
        sets_processed += len(candidate_sets)
        records = _records_for_group(group, candidate_sets, allow_estimates=allow_estimates, policy=policy)
        fingerprint = _input_fingerprint(group, candidate_sets, records)
        statuses = {
            candidate_set.set_key: record.status for candidate_set, record in records
        }
        recommended_sets += sum(
            status == RecommendationStatus.RECOMMENDED.value
            for status in statuses.values()
        )
        skipped_sets += sum(
            status != RecommendationStatus.RECOMMENDED.value
            for status in statuses.values()
        )
        claim = repository.claim_recommendation_run(
            root_id, _CRITERIA_VERSION, fingerprint, now
        )
        if not claim.created:
            latest = repository.latest_recommendations(tuple(candidate.set_key for candidate in candidate_sets))
            expected = {(record.set_key, record.archive_id): (record.recommendation, record.status, record.criteria, record.reason)
                        for _, record in records}
            actual = {(record.set_key, record.archive_id): (record.recommendation, record.status, record.criteria, record.reason)
                      for record in latest}
            if actual == expected or repository.completed_recommendation_run_for_input(root_id, fingerprint) is None:
                continue
            # A different mode may have superseded this cached run. Preserve its
            # history and publish the current decision as a new run.
            run_id = repository.begin_recommendation_run(root_id, _CRITERIA_VERSION, now)
        else:
            run_id = claim.run_id
        try:
            for candidate_set, record in records:
                repository.replace_recommendation_items(run_id, candidate_set, record)
            repository.finish_recommendation_run(run_id, state="COMPLETED", completed_at=now)
        except Exception:
            repository.finish_recommendation_run(
                run_id, state="FAILED", completed_at=now, error_code="RECOMMENDATION_REFRESH_FAILED"
            )
            raise
    if progress:
        progress(len(groups), len(groups), "추천 갱신 완료")
    return RecommendationRefreshSummary(len(groups), sets_processed, recommended_sets, skipped_sets)


def partition_group(group: RecommendationSourceGroup) -> tuple[ReviewCandidateSet, ...]:
    resolved = {
        member.archive_id: resolve_color_evidence(
            member.color_page_ratio, member.filename_color
        )
        for member in group.members
    }
    archive_ids = tuple(sorted(resolved))
    exact_roots = _exact_content_component_roots(group)
    if (
        len(archive_ids) >= 2
        and len({exact_roots[archive_id] for archive_id in archive_ids}) == 1
    ):
        kinds = set(resolved.values())
        kind = kinds.pop() if len(kinds) == 1 else EditionKind.MIXED_OR_UNKNOWN
        return (_candidate_set(group, kind, archive_ids),)
    if any(value is EditionKind.MIXED_OR_UNKNOWN for value in resolved.values()):
        return (
            (_candidate_set(group, EditionKind.MIXED_OR_UNKNOWN, archive_ids),)
            if len(archive_ids) >= 2
            else ()
        )
    buckets: dict[EditionKind, list[int]] = {}
    for archive_id, kind in resolved.items():
        buckets.setdefault(kind, []).append(archive_id)
    return tuple(
        _candidate_set(group, kind, tuple(sorted(archive_ids)))
        for kind, archive_ids in sorted(
            buckets.items(), key=lambda item: (item[0].value, tuple(sorted(item[1])))
        )
        if len(archive_ids) >= 2
    )


def resolve_language_evidence(
    precision: DetectedLanguage | str | None, filename: FilenameSignal | None
) -> DetectedLanguage:
    measured = _language("UNKNOWN" if precision is None else str(precision))
    filename_value = _language(
        "UNKNOWN" if filename is None or filename.conflict or filename.value is None else filename.value
    )
    if filename is not None and filename.conflict:
        return DetectedLanguage.UNKNOWN
    if measured is DetectedLanguage.UNKNOWN:
        return filename_value
    if filename_value is DetectedLanguage.UNKNOWN:
        return measured
    return measured if measured is filename_value else DetectedLanguage.UNKNOWN


def resolve_color_evidence(
    measured: float | None, filename: FilenameSignal | None
) -> EditionKind:
    if measured is not None:
        measured_kind = classify_edition(measured)
        if measured_kind is not EditionKind.MIXED_OR_UNKNOWN:
            return measured_kind
    if filename is None or filename.conflict or filename.value is None:
        return EditionKind.MIXED_OR_UNKNOWN
    try:
        kind = EditionKind(filename.value)
    except ValueError:
        return EditionKind.MIXED_OR_UNKNOWN
    return (
        kind
        if kind in {EditionKind.FULL_COLOR, EditionKind.MONOCHROME}
        else EditionKind.MIXED_OR_UNKNOWN
    )


def resolve_mosaic_rank(filename: FilenameSignal | None) -> int | None:
    if filename is None or filename.conflict:
        return None
    return {"UNCENSORED": 3, "DECENSORED": 2, "CENSORED": 1}.get(filename.value)


def build_inputs(
    group: RecommendationSourceGroup, candidate_set: ReviewCandidateSet
) -> tuple[RecommendationInput, ...]:
    wanted = set(candidate_set.archive_ids)
    mosaic_sources = {}
    for archive_id in wanted:
        directions = {
            relation.mosaic_direction for relation in group.precision_relations
            if archive_id in (relation.archive_a_id, relation.archive_b_id)
            and relation.archive_a_id in wanted and relation.archive_b_id in wanted
        }
        mosaic_sources[archive_id] = "precision" if directions == {PairDirection.TIE.value} else "unknown"
    return tuple(
        RecommendationInput(
            member.archive_id,
            member.path,
            member.file_size,
            member.page_count,
            member.mtime_ns,
            member.resolution_area,
            member.filename_title_rank,
            resolve_language_evidence(member.language, member.filename_language),
            resolve_mosaic_rank(member.filename_mosaic),
            {
                "language": _language_source(member.language, member.filename_language, analyzed=member.language_analyzed),
                "color": _color_source(member.color_page_ratio, member.filename_color),
                "mosaic": ("conflict" if member.filename_mosaic is not None and member.filename_mosaic.conflict
                           else mosaic_sources[member.archive_id]),
            },
            {EditionKind.FULL_COLOR: 2, EditionKind.MONOCHROME: 1}.get(
                resolve_color_evidence(member.color_page_ratio, member.filename_color)),
        )
        for member in group.members
        if member.archive_id in wanted
    )


def build_pair_evidence(
    group: RecommendationSourceGroup, candidate_set: ReviewCandidateSet
) -> dict[tuple[int, int], PairEvidence]:
    wanted = set(candidate_set.archive_ids)
    exact_roots = _exact_content_component_roots(group)
    bridges: dict[tuple[int, int], list[tuple[PairDirection, PairDirection]]] = {}
    for record in group.precision_relations:
        if record.archive_a_id not in wanted or record.archive_b_id not in wanted:
            continue
        left_root = exact_roots[record.archive_a_id]
        right_root = exact_roots[record.archive_b_id]
        if left_root == right_root:
            continue
        root_pair = _canonical_pair(left_root, right_root)
        bridges.setdefault(root_pair, []).append(
            (
                _orient_direction(_direction(record.mosaic_direction), left_root, root_pair[0]),
                _orient_direction(_direction(record.quality_direction), left_root, root_pair[0]),
            )
        )

    component_evidence = {
        pair: (
            _merge_directions(item[0] for item in values),
            _merge_directions(item[1] for item in values),
        )
        for pair, values in bridges.items()
    }
    relation_pairs = {
        _canonical_pair(record.archive_a_id, record.archive_b_id)
        for record in group.relations
        if record.archive_a_id in wanted and record.archive_b_id in wanted
    }
    ids = tuple(sorted(wanted))
    pairs = relation_pairs | {
        (left, right)
        for index, left in enumerate(ids)
        for right in ids[index + 1 :]
        if exact_roots[left] == exact_roots[right]
        or _canonical_pair(exact_roots[left], exact_roots[right]) in component_evidence
    }
    result: dict[tuple[int, int], PairEvidence] = {}
    for pair in pairs:
        left_root = exact_roots[pair[0]]
        right_root = exact_roots[pair[1]]
        content_equivalent = left_root == right_root
        root_pair = _canonical_pair(left_root, right_root)
        measured = component_evidence.get(root_pair)
        if measured is not None and left_root != root_pair[0]:
            measured = tuple(_reverse_direction(value) for value in measured)
        mosaic, quality = (
            (PairDirection.TIE, PairDirection.TIE)
            if content_equivalent
            else measured or (PairDirection.UNKNOWN, PairDirection.UNKNOWN)
        )
        result[pair] = PairEvidence(
            pair[0],
            pair[1],
            mosaic,
            quality,
            content_equivalent=content_equivalent,
        )
    return result


def _canonical_pair(left: int, right: int) -> tuple[int, int]:
    return (left, right) if left < right else (right, left)


def _orient_direction(
    direction: PairDirection, source_left: int, target_left: int
) -> PairDirection:
    return direction if source_left == target_left else _reverse_direction(direction)


def _reverse_direction(direction: PairDirection) -> PairDirection:
    if direction is PairDirection.LEFT_BETTER:
        return PairDirection.RIGHT_BETTER
    if direction is PairDirection.RIGHT_BETTER:
        return PairDirection.LEFT_BETTER
    return direction


def _merge_directions(directions: Iterable[PairDirection]) -> PairDirection:
    known = {direction for direction in directions if direction is not PairDirection.UNKNOWN}
    return known.pop() if len(known) == 1 else PairDirection.UNKNOWN


def _records_for_group(
    group: RecommendationSourceGroup, candidate_sets: tuple[ReviewCandidateSet, ...], *, allow_estimates: bool = False, policy=None
) -> tuple[tuple[ReviewCandidateSet, RecommendationRecord], ...]:
    members = {member.archive_id: member for member in group.members}
    records: list[tuple[ReviewCandidateSet, RecommendationRecord]] = []
    for candidate_set in candidate_sets:
        evidence = build_pair_evidence(group, candidate_set)
        decision = (recommend_with_estimates if allow_estimates else recommend_candidate_set)(build_inputs(group, candidate_set), evidence, policy=policy)
        for item in decision.items:
            member = members[item.archive_id]
            records.append(
                (
                    candidate_set,
                    RecommendationRecord(
                        0,
                        candidate_set.set_key,
                        candidate_set.source_group_key,
                        item.archive_id,
                        item.recommendation,
                        decision.status.value,
                        {
                            name: value.value if hasattr(value, "value") else str(value)
                            for name, value in item.criteria.items()
                        },
                        item.reason,
                        member.file_size,
                        member.mtime_ns,
                    ),
                )
            )
    return tuple(records)


def _set_key(source_group_key: str, edition_kind: EditionKind, archive_ids: list[int]) -> str:
    payload = f"{source_group_key}|{edition_kind.value}|{sorted(archive_ids)}|{_SET_ALGORITHM_VERSION}"
    return sha256(payload.encode("utf-8")).hexdigest()


def _candidate_set(
    group: RecommendationSourceGroup,
    kind: EditionKind,
    archive_ids: tuple[int, ...],
) -> ReviewCandidateSet:
    return ReviewCandidateSet(
        _set_key(group.group_key, kind, list(archive_ids)),
        group.group_key,
        kind.value,
        archive_ids,
    )


def _all_pairs_content_equivalent(
    candidate_set: ReviewCandidateSet,
    evidence: dict[tuple[int, int], PairEvidence],
) -> bool:
    ids = candidate_set.archive_ids
    return all(
        evidence.get((left, right)) is not None
        and evidence[(left, right)].content_equivalent
        for index, left in enumerate(ids)
        for right in ids[index + 1 :]
    )


def _exact_content_component_roots(
    group: RecommendationSourceGroup,
) -> dict[int, int]:
    parents = {member.archive_id: member.archive_id for member in group.members}

    def find(archive_id: int) -> int:
        while parents[archive_id] != archive_id:
            parents[archive_id] = parents[parents[archive_id]]
            archive_id = parents[archive_id]
        return archive_id

    for relation in group.relations:
        if relation.relation not in {
            DuplicateRelation.EXACT_ARCHIVE,
            DuplicateRelation.EXACT_CONTENT,
        }:
            continue
        if relation.archive_a_id not in parents or relation.archive_b_id not in parents:
            continue
        left = find(relation.archive_a_id)
        right = find(relation.archive_b_id)
        if left != right:
            parents[max(left, right)] = min(left, right)
    return {archive_id: find(archive_id) for archive_id in parents}


def _input_fingerprint(
    group: RecommendationSourceGroup,
    candidate_sets: tuple[ReviewCandidateSet, ...],
    records: tuple[tuple[ReviewCandidateSet, RecommendationRecord], ...],
) -> str:
    payload = {
        "source_group_key": group.group_key,
        "sets": [(item.set_key, item.edition_kind, item.archive_ids) for item in candidate_sets],
        "members": [
            (item.archive_id, item.path_key, item.file_size, item.mtime_ns, item.page_count,
             item.resolution_area, item.color_page_ratio, item.language,
             item.language_confidence, _signal_payload(item.filename_language),
             _signal_payload(item.filename_color), _signal_payload(item.filename_mosaic),
             item.filename_title_rank)
            for item in group.members
        ],
        "precision": [
            (item.archive_a_id, item.archive_b_id, item.mosaic_direction, item.quality_direction)
            for item in group.precision_relations
        ],
        "relations": [
            (item.archive_a_id, item.archive_b_id, item.relation.value,
             item.matched_pages, item.confidence)
            for item in group.relations
        ],
        "records": [
            (candidate.set_key, record.archive_id, record.recommendation, record.status, record.criteria, record.reason)
            for candidate, record in records
        ],
        "version": _CRITERIA_VERSION,
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha256(encoded.encode("utf-8")).hexdigest()


def _language(value: str) -> DetectedLanguage:
    try:
        return DetectedLanguage(value)
    except ValueError:
        return DetectedLanguage.UNKNOWN


def _direction(value: str) -> PairDirection:
    try:
        return PairDirection(value)
    except ValueError:
        return PairDirection.UNKNOWN


def _signal_payload(value: FilenameSignal | None) -> tuple[object, ...] | None:
    if value is None:
        return None
    return value.value, value.confidence, tuple(sorted(value.matched_tokens)), value.conflict


def _language_source(language: str, filename: FilenameSignal | None, *, analyzed: bool = False) -> str:
    precision = _language(language)
    if analyzed and precision is DetectedLanguage.UNKNOWN and not (filename is not None and filename.conflict):
        return "precision_unknown"
    resolved = resolve_language_evidence(precision, filename)
    if resolved is DetectedLanguage.UNKNOWN:
        return "conflict" if precision is not DetectedLanguage.UNKNOWN or (filename is not None and filename.conflict) else "unknown"
    return "precision" if precision is not DetectedLanguage.UNKNOWN else "filename"


def _color_source(measured: float | None, filename: FilenameSignal | None) -> str:
    if (
        measured is not None
        and classify_edition(measured) is not EditionKind.MIXED_OR_UNKNOWN
    ):
        return "measured"
    return (
        "filename"
        if resolve_color_evidence(measured, filename) is not EditionKind.MIXED_OR_UNKNOWN
        else "unknown"
    )
