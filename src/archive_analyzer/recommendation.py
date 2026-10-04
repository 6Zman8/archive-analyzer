"""Conservative, score-free recommendations for an existing candidate set."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
import re
import unicodedata
from collections.abc import Iterable, Mapping

from .precision_analysis import DetectedLanguage, PairDirection


class CriterionResult(StrEnum):
    LEFT_BETTER = "LEFT_BETTER"
    TIE = "TIE"
    RIGHT_BETTER = "RIGHT_BETTER"
    UNKNOWN = "UNKNOWN"
    MIXED = "MIXED"


class RecommendationStatus(StrEnum):
    RECOMMENDED = "RECOMMENDED"
    ANALYSIS_REQUIRED = "ANALYSIS_REQUIRED"
    UNCERTAIN = "UNCERTAIN"
    CONFLICT = "CONFLICT"
    NONE = "NONE"


@dataclass(frozen=True, slots=True)
class RecommendationInput:
    archive_id: int
    path: Path
    file_size: int | None
    page_count: int | None
    mtime_ns: int | None
    resolution_area: int | None
    title_rank: int | None
    language: DetectedLanguage
    mosaic_rank: int | None = None
    evidence_sources: Mapping[str, str] = field(default_factory=dict)
    color_rank: int | None = None


@dataclass(frozen=True, slots=True)
class PairEvidence:
    left_archive_id: int
    right_archive_id: int
    mosaic: PairDirection
    quality: PairDirection
    content_equivalent: bool = False


@dataclass(frozen=True, slots=True)
class RecommendationItem:
    archive_id: int
    recommendation: str
    criteria: Mapping[str, CriterionResult]
    reason: str


@dataclass(frozen=True, slots=True)
class RecommendationDecision:
    status: RecommendationStatus
    items: tuple[RecommendationItem, ...]


LANGUAGE_RANK: Mapping[DetectedLanguage, int] = {
    DetectedLanguage.KOREAN: 5,
    DetectedLanguage.JAPANESE: 4,
    DetectedLanguage.ENGLISH: 3,
    DetectedLanguage.CHINESE: 2,
    DetectedLanguage.OTHER: 1,
}

_CRITERIA = ("resolution", "size", "pages", "mtime", "title", "language", "mosaic", "quality")
_ANALYSIS_CRITERIA = frozenset(("language", "mosaic", "quality"))
_FULL_TITLE = re.compile(r"^\[[^\[\]()]+\s*\([^()]+\)\]\s*\S+")
_PARTIAL_TITLE = re.compile(r"^\[[^\[\]]+\]\s*\S+")


def title_structure_rank(path: Path) -> int:
    """Return the structure rank without attempting to interpret the title."""
    normalized = unicodedata.normalize("NFKC", path.stem)
    if not normalized.strip():
        return 0
    if _FULL_TITLE.match(normalized):
        return 3
    if _PARTIAL_TITLE.match(normalized):
        return 2
    return 1


def same_content_language(left, right, evidence) -> bool:
    if evidence is None or not evidence.content_equivalent:
        return False
    return all(item.evidence_sources.get("language", "precision") == "precision_unknown" or (
        item.evidence_sources.get("language", "precision") == "precision" and item.language is not DetectedLanguage.UNKNOWN
    ) for item in (left, right))


def language_needs_review(left, right, evidence) -> bool:
    return not same_content_language(left, right, evidence) and any(
        item.evidence_sources.get("language", "precision") != "precision" or item.language is DetectedLanguage.UNKNOWN
        for item in (left, right))


def compare_pair(
    left: RecommendationInput,
    right: RecommendationInput,
    evidence: PairEvidence | None,
) -> Mapping[str, CriterionResult]:
    """Compare two inputs, orienting stored pair evidence to this call."""
    results: dict[str, CriterionResult] = {
        "resolution": _numeric_result(left.resolution_area, right.resolution_area, 0.02),
        "size": _numeric_result(left.file_size, right.file_size, 0.01),
        "pages": _page_result(left.page_count, right.page_count),
        "mtime": _mtime_result(left.mtime_ns, right.mtime_ns),
        "title": _rank_result(_input_title_rank(left), _input_title_rank(right)),
        "language": (CriterionResult.TIE if same_content_language(left, right, evidence)
                     else CriterionResult.UNKNOWN if language_needs_review(left, right, evidence)
                     else _language_result(left.language, right.language)),
    }
    # Only explicit filename attributes participate; failed image heuristics do not.
    mosaic = _rank_result(left.mosaic_rank, right.mosaic_rank)
    results["mosaic"] = CriterionResult.TIE if mosaic is CriterionResult.UNKNOWN else mosaic
    results["quality"] = CriterionResult.TIE  # Resolution is the user-facing quality criterion.
    return results


def recommend_with_estimates(inputs, evidence_by_pair, *, policy=None) -> RecommendationDecision:
    original = tuple(inputs)
    resolved = []
    for item in original:
        source = item.evidence_sources
        # Conflicting evidence is not an estimate and must remain unresolved.
        language = (DetectedLanguage.JAPANESE if item.language is DetectedLanguage.UNKNOWN
                    and source.get("language") != "conflict" else item.language)
        guarded_sources = {name: value for name, value in source.items()
                           if (name not in {"language", "mosaic"} and value != "measured") or value == "conflict"}
        resolved.append(replace(item, language=language,
            mosaic_rank=item.mosaic_rank or 1,
            evidence_sources=guarded_sources))
    pairs = {}
    by_id = {item.archive_id: item for item in resolved}
    for key, evidence in evidence_by_pair.items():
        mosaic = evidence.mosaic
        if mosaic is PairDirection.UNKNOWN:
            left, right = by_id[evidence.left_archive_id], by_id[evidence.right_archive_id]
            mosaic = (PairDirection.TIE if left.mosaic_rank == right.mosaic_rank else
                      PairDirection.LEFT_BETTER if left.mosaic_rank > right.mosaic_rank else PairDirection.RIGHT_BETTER)
        pairs[key] = replace(evidence, mosaic=mosaic)
    # Estimated language/mosaic are explicitly opted into; color and missing numeric data remain guarded.
    decision = recommend_candidate_set(resolved, pairs, policy=policy)
    return replace(decision, items=tuple(replace(item, reason="estimated:language,mosaic;" + item.reason)
                                         for item in decision.items))


def recommend_candidate_set(
    inputs: Iterable[RecommendationInput],
    evidence_by_pair: Mapping[object, PairEvidence],
    *, policy=None,
) -> RecommendationDecision:
    """Recommend only a unique Pareto dominator with confirmed evidence."""
    ordered = tuple(sorted(inputs, key=lambda value: value.archive_id))
    if (policy is None or policy.mode != "priority" or "language" in policy.order) and any(
        language_needs_review(left, right, _find_evidence(evidence_by_pair, left.archive_id, right.archive_id))
        for index, left in enumerate(ordered) for right in ordered[index + 1:]
    ):
        return RecommendationDecision(RecommendationStatus.ANALYSIS_REQUIRED, tuple(
            RecommendationItem(item.archive_id, "NONE", {"language": CriterionResult.UNKNOWN}, "analysis_required:language")
            for item in ordered))
    from .version_recommendation import recommend_versions
    version_decision = recommend_versions(ordered, evidence_by_pair)
    if version_decision is not None:
        return version_decision
    if policy is not None and policy.mode == "priority":
        from .recommendation_policy import choose_by_priority
        return choose_by_priority(ordered, evidence_by_pair, policy)
    if len(ordered) <= 1:
        return RecommendationDecision(
            RecommendationStatus.NONE,
            tuple(
                RecommendationItem(value.archive_id, "NONE", {}, "no_unique_dominator")
                for value in ordered
            ),
        )

    identical_latest = None
    if all(
        (evidence := _find_evidence(evidence_by_pair, left.archive_id, right.archive_id)) is not None
        and evidence.content_equivalent
        for index, left in enumerate(ordered) for right in ordered[index + 1:]
    ) and all(item.mtime_ns is not None for item in ordered):
        best_title = max(_input_title_rank(item) or 0 for item in ordered)
        titled = [item for item in ordered if (_input_title_rank(item) or 0) == best_title]
        newest = max(item.mtime_ns for item in titled)
        winners = [item for item in titled if item.mtime_ns == newest]
        if len(winners) == 1:
            identical_latest = winners[0].archive_id

    comparisons: dict[tuple[int, int], Mapping[str, CriterionResult]] = {}
    unknown_criteria: set[str] = set()
    for index, left in enumerate(ordered):
        for right in ordered[index + 1 :]:
            evidence = _find_evidence(evidence_by_pair, left.archive_id, right.archive_id)
            values = compare_pair(left, right, evidence)
            comparisons[(left.archive_id, right.archive_id)] = values
            unknown_criteria.update(
                criterion for criterion, value in values.items() if value is CriterionResult.UNKNOWN
            )

    item_criteria = {
        value.archive_id: _aggregate_criteria(value.archive_id, ordered, comparisons)
        for value in ordered
    }
    if identical_latest is not None:
        return RecommendationDecision(RecommendationStatus.RECOMMENDED, tuple(
            RecommendationItem(item.archive_id, "KEEP" if item.archive_id == identical_latest else "REMOVE_CANDIDATE",
                item_criteria[item.archive_id],
                "identical_content_title_latest" if item.archive_id == identical_latest else f"identical_content_title_latest:{identical_latest}")
            for item in ordered))
    estimated = {"language" for index, left in enumerate(ordered) for right in ordered[index + 1:]
        if language_needs_review(left, right, _find_evidence(evidence_by_pair, left.archive_id, right.archive_id))}
    if estimated or unknown_criteria:
        return RecommendationDecision(
            RecommendationStatus.ANALYSIS_REQUIRED,
            tuple(RecommendationItem(item.archive_id, "NONE", item_criteria[item.archive_id],
                                     "analysis_required:" + ",".join(sorted(unknown_criteria | estimated)))
                  for item in ordered),
        )

    dominators = tuple(
        value.archive_id
        for value in ordered
        if all(
            _find_evidence(evidence_by_pair, value.archive_id, other.archive_id) is not None
            and _dominates(value.archive_id, other.archive_id, comparisons)
            for other in ordered
            if other.archive_id != value.archive_id
        )
    )
    if len(dominators) != 1:
        missing_pairs = any(_find_evidence(evidence_by_pair, left.archive_id, right.archive_id) is None
            for index, left in enumerate(ordered) for right in ordered[index + 1:])
        status = (RecommendationStatus.ANALYSIS_REQUIRED if missing_pairs or unknown_criteria & _ANALYSIS_CRITERIA
                  else RecommendationStatus.UNCERTAIN if unknown_criteria else RecommendationStatus.NONE)
        reason = "no_unique_dominator" if status is RecommendationStatus.NONE else (
            "analysis_required:" if status is RecommendationStatus.ANALYSIS_REQUIRED else "uncertain:") + ",".join(sorted(unknown_criteria))
        return RecommendationDecision(
            status,
            tuple(
                RecommendationItem(
                    value.archive_id,
                    "NONE",
                    item_criteria[value.archive_id],
                    _with_mixed_reason(reason, item_criteria[value.archive_id]),
                )
                for value in ordered
            ),
        )

    winner = dominators[0]
    return RecommendationDecision(
        RecommendationStatus.RECOMMENDED,
        tuple(
            RecommendationItem(
                value.archive_id,
                "KEEP" if value.archive_id == winner else "REMOVE_CANDIDATE",
                item_criteria[value.archive_id],
                _with_mixed_reason(
                    "unique_dominator" if value.archive_id == winner else f"dominated_by:{winner}",
                    item_criteria[value.archive_id],
                ),
            )
            for value in ordered
        ),
    )


def _numeric_result(left: int | None, right: int | None, tie_ratio: float) -> CriterionResult:
    if left is None or right is None or left <= 0 or right <= 0:
        return CriterionResult.UNKNOWN
    ratio = abs(left - right) / max(left, right)
    if ratio <= tie_ratio:
        return CriterionResult.TIE
    return CriterionResult.LEFT_BETTER if left > right else CriterionResult.RIGHT_BETTER


def _page_result(left: int | None, right: int | None) -> CriterionResult:
    if left is None or right is None or left <= 0 or right <= 0:
        return CriterionResult.UNKNOWN
    if left == right:
        return CriterionResult.TIE
    return CriterionResult.LEFT_BETTER if left > right else CriterionResult.RIGHT_BETTER


def _mtime_result(left: int | None, right: int | None) -> CriterionResult:
    if left is None or right is None or left < 0 or right < 0:
        return CriterionResult.UNKNOWN
    if abs(left - right) <= 2_000_000_000:
        return CriterionResult.TIE
    return CriterionResult.LEFT_BETTER if left > right else CriterionResult.RIGHT_BETTER


def _rank_result(left: int | None, right: int | None) -> CriterionResult:
    if left is None or right is None or left <= 0 or right <= 0:
        return CriterionResult.UNKNOWN
    if left == right:
        return CriterionResult.TIE
    return CriterionResult.LEFT_BETTER if left > right else CriterionResult.RIGHT_BETTER


def _input_title_rank(value: RecommendationInput) -> int | None:
    return value.title_rank if value.title_rank is not None else title_structure_rank(value.path)


def _language_rank(language: DetectedLanguage | str | None) -> int | None:
    if language is None:
        return None
    try:
        return LANGUAGE_RANK.get(DetectedLanguage(language))
    except ValueError:
        return None


def _orient_pair_direction(
    direction: PairDirection | str,
    left_id: int,
    right_id: int,
    evidence: PairEvidence | None,
) -> CriterionResult:
    try:
        normalized = PairDirection(direction)
    except ValueError:
        return CriterionResult.UNKNOWN
    if normalized is PairDirection.UNKNOWN:
        return CriterionResult.UNKNOWN
    if normalized is PairDirection.TIE:
        return CriterionResult.TIE
    if evidence is None or {left_id, right_id} != {evidence.left_archive_id, evidence.right_archive_id}:
        return CriterionResult.UNKNOWN
    left_better = normalized is PairDirection.LEFT_BETTER
    if left_id == evidence.left_archive_id:
        return CriterionResult.LEFT_BETTER if left_better else CriterionResult.RIGHT_BETTER
    return CriterionResult.RIGHT_BETTER if left_better else CriterionResult.LEFT_BETTER


def _find_evidence(
    evidence_by_pair: Mapping[object, PairEvidence], left_id: int, right_id: int
) -> PairEvidence | None:
    for key in ((left_id, right_id), (right_id, left_id), frozenset((left_id, right_id))):
        try:
            evidence = evidence_by_pair.get(key)
        except (TypeError, AttributeError):
            evidence = None
        if evidence is not None:
            return evidence
    for evidence in evidence_by_pair.values():
        if not isinstance(evidence, PairEvidence):
            continue
        if {evidence.left_archive_id, evidence.right_archive_id} == {left_id, right_id}:
            return evidence
    return None


def _aggregate_criteria(
    archive_id: int,
    inputs: tuple[RecommendationInput, ...],
    comparisons: Mapping[tuple[int, int], Mapping[str, CriterionResult]],
) -> Mapping[str, CriterionResult]:
    result: dict[str, CriterionResult] = {}
    for criterion in _CRITERIA:
        values = []
        for other in inputs:
            if other.archive_id == archive_id:
                continue
            pair = (min(archive_id, other.archive_id), max(archive_id, other.archive_id))
            value = comparisons[pair][criterion]
            if archive_id != pair[0] and value in (CriterionResult.LEFT_BETTER, CriterionResult.RIGHT_BETTER):
                value = (
                    CriterionResult.RIGHT_BETTER
                    if value is CriterionResult.LEFT_BETTER
                    else CriterionResult.LEFT_BETTER
                )
            values.append(value)
        if any(value is CriterionResult.UNKNOWN for value in values):
            result[criterion] = CriterionResult.UNKNOWN
        else:
            non_ties = {value for value in values if value is not CriterionResult.TIE}
            if len(non_ties) == 1:
                result[criterion] = non_ties.pop()
            elif len(non_ties) > 1:
                result[criterion] = CriterionResult.MIXED
            else:
                result[criterion] = CriterionResult.TIE
    return result


def _with_mixed_reason(reason: str, criteria: Mapping[str, CriterionResult]) -> str:
    mixed = tuple(name for name in _CRITERIA if criteria.get(name) is CriterionResult.MIXED)
    return reason if not mixed else f"{reason};mixed:{','.join(mixed)}"


def _dominates(
    left_id: int,
    right_id: int,
    comparisons: Mapping[tuple[int, int], Mapping[str, CriterionResult]],
) -> bool:
    pair = (min(left_id, right_id), max(left_id, right_id))
    criteria = comparisons[pair]
    better = CriterionResult.LEFT_BETTER if left_id == pair[0] else CriterionResult.RIGHT_BETTER
    core = [value for name, value in criteria.items() if name not in {"title", "mtime"}]
    if not all(value in (CriterionResult.TIE, better) for value in core):
        return False
    # Conflicting content attributes remain unresolved. Title/time only break ties.
    if better in core:
        return all(value in (CriterionResult.TIE, better) for value in criteria.values())
    for name in ("title", "mtime"):
        if criteria[name] is not CriterionResult.TIE:
            return criteria[name] is better
    return False


def _language_result(left: DetectedLanguage, right: DetectedLanguage) -> CriterionResult:
    return _rank_result(_language_rank(left), _language_rank(right))
