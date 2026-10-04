"""User-requested rules for same-title dated snapshots and coverage periods."""
from .version_dates import parse_title_dates, with_mtime


def recommend_versions(inputs, evidence):
    from .recommendation import (RecommendationDecision, RecommendationItem,
        RecommendationStatus as S, _find_evidence)
    if len(inputs) < 2:
        return None
    titles = {item.archive_id: parse_title_dates(item.path) for item in inputs}
    if len({value.key for value in titles.values()}) != 1 or not all(value.key for value in titles.values()):
        return None
    if not any(value.span is not None for value in titles.values()):
        return None
    spans = {item.archive_id: with_mtime(titles[item.archive_id], item.mtime_ns) for item in inputs}
    # No fall-through to size/language when dated versions conflict or dates are unavailable.
    if any(span is None for span in spans.values()):
        return RecommendationDecision(S.ANALYSIS_REQUIRED, tuple(RecommendationItem(
            item.archive_id, 'NONE', {}, 'version_dates;analysis_required:mtime') for item in inputs))
    if not any(span.is_range for span in spans.values()) and all(
        (pair := _find_evidence(evidence, left.archive_id, right.archive_id)) is not None and pair.content_equivalent
        for index, left in enumerate(inputs) for right in inputs[index + 1:]
    ):
        return None
    dominates = {item.archive_id: set() for item in inputs}
    roots = {item.archive_id: item.archive_id for item in inputs}
    def root(key):
        while roots[key] != key:
            roots[key] = roots[roots[key]]
            key = roots[key]
        return key
    for pair in evidence.values():
        if pair.left_archive_id in roots and pair.right_archive_id in roots:
            roots[root(pair.right_archive_id)] = root(pair.left_archive_id)
    incomparable = set()
    for index, left in enumerate(inputs):
        a = spans[left.archive_id]
        for right in inputs[index + 1:]:
            b = spans[right.archive_id]
            left_covers = a.start <= b.start and a.end >= b.end
            right_covers = b.start <= a.start and b.end >= a.end
            period = a.is_range or b.is_range
            if period and not left_covers and not right_covers:
                incomparable.add(frozenset((left.archive_id, right.archive_id)))
                continue
            # Adjacent versions form one discovered group. Date/page comparison
            # must also work between its oldest and newest non-adjacent versions.
            if root(left.archive_id) != root(right.archive_id) or left.page_count is None or right.page_count is None:
                continue
            if left.page_count <= 0 or right.page_count <= 0:
                continue
            if period:
                left_better = left_covers and left.page_count >= right.page_count and (not right_covers or left.page_count > right.page_count)
                right_better = right_covers and right.page_count >= left.page_count and (not left_covers or right.page_count > left.page_count)
            else:
                left_better = a.end > b.end and left.page_count > right.page_count
                right_better = b.end > a.end and right.page_count > left.page_count
            if left_better:
                dominates[left.archive_id].add(right.archive_id)
            if right_better:
                dominates[right.archive_id].add(left.archive_id)
    remaining = {item.archive_id for item in inputs} - set().union(*dominates.values())
    # Every removed version must be covered by a kept version's date/page rule.
    removable = set().union(*(dominates[key] for key in remaining))
    complete = len(remaining) == 1 or all(frozenset((left, right)) in incomparable
        for left in remaining for right in remaining if left != right)
    complete = complete and (remaining | removable) == {item.archive_id for item in inputs}
    status = S.RECOMMENDED if complete else S.NONE
    items = []
    for item in inputs:
        span = spans[item.archive_id]
        reason = 'version_periods' if any(value.is_range for value in spans.values()) else 'version_latest_pages'
        if len(remaining) > 1 and complete and item.archive_id in remaining:
            reason += ';preserve_unique_periods'
        reason += f';date:{span.start.isoformat()}~{span.end.isoformat()}'
        if span.inferred:
            reason += ';date_from_mtime'
        items.append(RecommendationItem(item.archive_id,
            'KEEP' if complete and item.archive_id in remaining else 'REMOVE_CANDIDATE' if complete else 'NONE', {}, reason))
    return RecommendationDecision(status, tuple(items))
