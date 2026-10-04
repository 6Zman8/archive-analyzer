"""Persistable user-selected lexicographic recommendation criteria."""
from dataclasses import dataclass

LABELS = {"language": "언어", "pages": "페이지 수", "resolution": "해상도", "size": "용량",
          "mosaic": "모자이크 표기", "color": "컬러", "title": "제목 형식", "mtime": "수정 시각"}
DEFAULT_ORDER = tuple(LABELS)


@dataclass(frozen=True)
class RecommendationPolicy:
    mode: str = "strict"
    order: tuple[str, ...] = DEFAULT_ORDER

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            return cls()
        order = value.get("order", DEFAULT_ORDER)
        if not isinstance(order, (list, tuple)):
            order = DEFAULT_ORDER
        return cls("priority" if value.get("mode") == "priority" else "strict",
                   tuple(dict.fromkeys(key for key in order if key in LABELS)))

    def to_dict(self):
        return {"mode": self.mode, "order": list(self.order)}


def choose_by_priority(inputs, evidence, policy):
    from .recommendation import (compare_pair, CriterionResult as C, RecommendationDecision,
        RecommendationItem, RecommendationStatus as S, _find_evidence, _rank_result, language_needs_review)
    comparisons = {}
    winners = []
    unresolved = set()
    decisive = set()
    for left in inputs:
        beats = True
        for right in inputs:
            if left.archive_id == right.archive_id:
                continue
            pair = _find_evidence(evidence, left.archive_id, right.archive_id)
            if pair is None:
                unresolved.add("pages")
                beats = False
                continue
            values = compare_pair(left, right, pair)
            values["color"] = _rank_result(left.color_rank, right.color_rank)
            comparisons[left.archive_id] = values
            outcome = C.TIE
            for key in policy.order:
                outcome = values[key]
                if key == "language" and language_needs_review(left, right, pair):
                    outcome = C.UNKNOWN
                if outcome is C.UNKNOWN and key in {"mosaic", "color"}:
                    continue
                if outcome is C.UNKNOWN:
                    unresolved.add(key)
                if outcome is not C.TIE:
                    if outcome is C.LEFT_BETTER:
                        decisive.add(key)
                    break
            if outcome is not C.LEFT_BETTER:
                beats = False
        if beats and len(inputs) > 1 and policy.order:
            winners.append(left.archive_id)
    winner = winners[0] if len(winners) == 1 else None
    status = S.RECOMMENDED if winner is not None else S.ANALYSIS_REQUIRED if unresolved else S.NONE
    reason = "priority:" + ",".join(policy.order)
    if any(pair.content_equivalent for pair in evidence.values()):
        reason += ";identical_content_language_tie"
    if winner is None and unresolved:
        reason += ";analysis_required:" + ",".join(sorted(unresolved))
    return RecommendationDecision(status, tuple(RecommendationItem(item.archive_id,
        "KEEP" if item.archive_id == winner else "REMOVE_CANDIDATE" if winner is not None else "NONE",
        comparisons.get(item.archive_id, {}), reason) for item in inputs))
