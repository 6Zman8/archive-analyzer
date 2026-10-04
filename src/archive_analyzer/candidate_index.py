from __future__ import annotations

import heapq
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from itertools import combinations

from archive_analyzer.analysis_progress import AnalysisProgress, ProgressCallback, track_progress
from archive_analyzer.duplicate_domain import AnalysisStage, ProbeFingerprint


MAX_BUCKET_ARCHIVES = 200
MAX_VISUAL_CANDIDATES_PER_ARCHIVE = 100
MAX_TRACKED_NEIGHBORS_PER_ARCHIVE = 200

SAME_ARCHIVE_SHA256 = "SAME_ARCHIVE_SHA256"
SAME_PIXEL_SHA256 = "SAME_PIXEL_SHA256"
SAME_BYTE_SHA256 = "SAME_BYTE_SHA256"
LSH_BAND_MATCH = "LSH_BAND_MATCH"
SHARED_FILENAME_TOKEN_WITH_VISUAL_HIT = "SHARED_FILENAME_TOKEN_WITH_VISUAL_HIT"
DATED_SERIES_TITLE = "DATED_SERIES_TITLE"

_REASON_ORDER = (
    SAME_ARCHIVE_SHA256,
    SAME_PIXEL_SHA256,
    SAME_BYTE_SHA256,
    LSH_BAND_MATCH,
    SHARED_FILENAME_TOKEN_WITH_VISUAL_HIT,
)
_BAND_WIDTHS = (10, 9, 9, 9, 9, 9, 9)
_BAND_OFFSETS = (54, 45, 36, 27, 18, 9, 0)


@dataclass(frozen=True, slots=True)
class ArchiveEvidence:
    archive_id: int
    file_sha256: str | None
    probes: tuple[ProbeFingerprint, ...]
    filename_tokens: frozenset[str]
    scan_root_id: int
    file_size: int
    mtime_ns: int
    analyzer_version: int
    series_key: str = ""
    series_date: str = ""
    series_versioned: bool = False


@dataclass(frozen=True, slots=True)
class CandidateSeed:
    archive_a_id: int
    archive_b_id: int
    reasons: tuple[str, ...]
    score: int


@dataclass(frozen=True, slots=True)
class CandidateIndexResult:
    seeds: tuple[CandidateSeed, ...]
    discarded_oversized_bucket_count: int
    truncated_candidate_counts: tuple[tuple[int, int], ...]
    signal_observation_count: int
    endpoint_pair_membership_count: int
    peak_endpoint_pair_membership_count: int
    mutual_selected_pair_count: int
    selector_eviction_event_count: int
    selector_rejected_endpoint_observation_count: int


@dataclass(slots=True)
class _PairSignals:
    exact_slots: dict[str, set[int]] = field(default_factory=lambda: defaultdict(set))
    lsh_slots: set[int] = field(default_factory=set)

    @property
    def support_slots(self) -> set[int]:
        return set().union(*self.exact_slots.values(), self.lsh_slots)


@dataclass(slots=True)
class _EndpointTopPairs:
    capacity: int
    pairs: dict[tuple[int, int], tuple[int, ...]] = field(default_factory=dict)
    heap: list[tuple[tuple[int, ...], tuple[int, int]]] = field(default_factory=list)

    def offer(self, pair: tuple[int, int], key: tuple[int, ...]) -> tuple[bool, bool, int]:
        if pair in self.pairs:
            return True, False, 0
        if len(self.pairs) < self.capacity:
            self._add(pair, key)
            return True, False, 1
        worst_pair, worst_key = self._worst()
        if key >= worst_key:
            return False, False, 0
        del self.pairs[worst_pair]
        self._add(pair, key)
        return True, True, 0

    def _add(self, pair: tuple[int, int], key: tuple[int, ...]) -> None:
        self.pairs[pair] = key
        heapq.heappush(self.heap, (tuple(-part for part in key), pair))
        if len(self.heap) > self.capacity * 2:
            self.heap = [(tuple(-part for part in value), item) for item, value in self.pairs.items()]
            heapq.heapify(self.heap)

    def _worst(self) -> tuple[tuple[int, int], tuple[int, ...]]:
        while self.heap:
            _, pair = self.heap[0]
            key = self.pairs.get(pair)
            if key is not None:
                return pair, key
            heapq.heappop(self.heap)
        raise RuntimeError("Endpoint selector lost its membership heap.")


@dataclass(slots=True)
class _SelectionDiagnostics:
    signal_observation_count: int = 0
    endpoint_pair_membership_count: int = 0
    peak_endpoint_pair_membership_count: int = 0
    selector_eviction_event_count: int = 0
    selector_rejected_endpoint_observation_count: int = 0


def generate_candidate_seeds(
    evidence: tuple[ArchiveEvidence, ...],
    *,
    checkpoint: Callable[[], None] | None = None,
) -> tuple[CandidateSeed, ...]:
    return build_candidate_index(evidence, checkpoint=checkpoint).seeds


def build_candidate_index(
    evidence: tuple[ArchiveEvidence, ...],
    *,
    checkpoint: Callable[[], None] | None = None,
    progress_callback: ProgressCallback | None = None,
) -> CandidateIndexResult:
    """Build root-scoped, bounded candidate seeds without all-pairs storage.

    Seven disjoint 9–10-bit bands guarantee at least one shared band for a
    64-bit Hamming distance at most six. The first pass retains each endpoint's
    stable `(rank, pair)` top 200 observations; the second pass regenerates the
    same buckets and aggregates signals only for pairs chosen by *both*
    endpoints. Thus input order cannot evict a previously accumulated signal.
    """

    _run_checkpoint(checkpoint)
    if progress_callback is not None:
        progress_callback(AnalysisProgress(AnalysisStage.CANDIDATE_BUILD, "비교 지표 준비", 0, len(evidence)))
    _require_single_batch(evidence)
    values = _unique_evidence(evidence, checkpoint)
    if not values:
        return CandidateIndexResult((), 0, (), 0, 0, 0, 0, 0, 0)
    root_id = values[0].scan_root_id
    version = values[0].analyzer_version
    sha_by_archive, exact_seeds = _exact_archive_star_seeds(values, checkpoint)
    endpoint_pairs: dict[int, _EndpointTopPairs] = {}
    diagnostics = _SelectionDiagnostics()

    def select(pair: tuple[int, int], _reason: str, _slot: int) -> None:
        diagnostics.signal_observation_count += 1
        key = _stable_pair_key(root_id, version, pair)
        for archive_id in pair:
            selector = endpoint_pairs.setdefault(
                archive_id, _EndpointTopPairs(MAX_TRACKED_NEIGHBORS_PER_ARCHIVE)
            )
            accepted, evicted, membership_delta = selector.offer(pair, key)
            diagnostics.endpoint_pair_membership_count += membership_delta
            diagnostics.peak_endpoint_pair_membership_count = max(
                diagnostics.peak_endpoint_pair_membership_count,
                diagnostics.endpoint_pair_membership_count,
            )
            if evicted:
                diagnostics.selector_eviction_event_count += 1
            if not accepted:
                diagnostics.selector_rejected_endpoint_observation_count += 1

    discarded_buckets = _emit_signal_observations(
        values, sha_by_archive, select, checkpoint, progress_callback, "유사 후보 찾기"
    )
    selected_pairs = _mutually_selected_pairs(endpoint_pairs, checkpoint, progress_callback)
    endpoint_pairs.clear()
    signals = {pair: _PairSignals() for pair in selected_pairs}
    mutual_selected_pair_count = len(selected_pairs)
    selected_pairs.clear()

    def aggregate(pair: tuple[int, int], reason: str, slot: int) -> None:
        value = signals.get(pair)
        if value is None:
            return
        if reason == LSH_BAND_MATCH:
            value.lsh_slots.add(slot)
        else:
            value.exact_slots[reason].add(slot)

    repeated_discarded_buckets = _emit_signal_observations(
        values, sha_by_archive, aggregate, checkpoint, progress_callback, "후보 근거 확인"
    )
    if repeated_discarded_buckets != discarded_buckets:
        raise RuntimeError("Candidate bucket pass was not deterministic.")
    visual, truncated_counts = _visual_candidates(
        values, signals, sha_by_archive, root_id, version, checkpoint, progress_callback
    )
    signals.clear()
    by_pair = {(item.archive_a_id, item.archive_b_id): item for item in (*exact_seeds, *visual)}
    buckets = defaultdict(list)
    for value in values:
        if value.series_key:
            buckets[value.series_key].append(value)
    for bucket in _track(buckets.values(), len(buckets), "날짜별 판본 연결", progress_callback, "제목"):
        _run_checkpoint(checkpoint)
        if len(bucket) < 2 or not any(item.series_versioned for item in bucket):
            continue
        # Adjacent versions keep the work linear even for years of daily updates.
        ordered = sorted(bucket, key=lambda item: (item.series_date, item.mtime_ns, item.archive_id))
        for left, right in zip(ordered, ordered[1:]):
            pair = tuple(sorted((left.archive_id, right.archive_id)))
            previous = by_pair.get(pair)
            reasons = (*previous.reasons, DATED_SERIES_TITLE) if previous else (DATED_SERIES_TITLE,)
            by_pair[pair] = CandidateSeed(*pair, reasons, previous.score if previous else 0)
    seeds = tuple(by_pair[pair] for pair in sorted(by_pair))
    return CandidateIndexResult(
        seeds=seeds,
        discarded_oversized_bucket_count=discarded_buckets,
        truncated_candidate_counts=tuple(sorted(truncated_counts.items())),
        signal_observation_count=diagnostics.signal_observation_count,
        endpoint_pair_membership_count=diagnostics.endpoint_pair_membership_count,
        peak_endpoint_pair_membership_count=diagnostics.peak_endpoint_pair_membership_count,
        mutual_selected_pair_count=mutual_selected_pair_count,
        selector_eviction_event_count=diagnostics.selector_eviction_event_count,
        selector_rejected_endpoint_observation_count=(
            diagnostics.selector_rejected_endpoint_observation_count
        ),
    )


def _unique_evidence(
    values: tuple[ArchiveEvidence, ...], checkpoint: Callable[[], None] | None
) -> tuple[ArchiveEvidence, ...]:
    by_id: dict[int, ArchiveEvidence] = {}
    for index, value in enumerate(values, start=1):
        if value.archive_id > 0 and value.archive_id not in by_id:
            by_id[value.archive_id] = value
        if index % 200 == 0:
            _run_checkpoint(checkpoint)
    return tuple(by_id[archive_id] for archive_id in sorted(by_id))


def _require_single_batch(values: tuple[ArchiveEvidence, ...]) -> None:
    if not values:
        return
    root_id = values[0].scan_root_id
    version = values[0].analyzer_version
    if any(value.scan_root_id != root_id for value in values):
        raise ValueError("Candidate evidence must belong to one scan root.")
    if any(value.analyzer_version != version for value in values):
        raise ValueError("Candidate evidence must belong to one analyzer version.")


def _exact_archive_star_seeds(
    values: tuple[ArchiveEvidence, ...],
    checkpoint: Callable[[], None] | None,
) -> tuple[dict[int, str], tuple[CandidateSeed, ...]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for index, value in enumerate(values, start=1):
        if value.file_sha256:
            groups[value.file_sha256.casefold()].append(value.archive_id)
        if index % 200 == 0:
            _run_checkpoint(checkpoint)
    sha_by_archive: dict[int, str] = {}
    seeds: list[CandidateSeed] = []
    for group_index, (sha256, archive_ids) in enumerate(groups.items(), start=1):
        ordered = sorted(set(archive_ids))
        for archive_index, archive_id in enumerate(ordered, start=1):
            sha_by_archive[archive_id] = sha256
            if archive_index % 200 == 0:
                _run_checkpoint(checkpoint)
        if len(ordered) < 2:
            continue
        for archive_index, archive_id in enumerate(ordered[1:], start=1):
            seeds.append(CandidateSeed(ordered[0], archive_id, (SAME_ARCHIVE_SHA256,), 100))
            if archive_index % 200 == 0:
                _run_checkpoint(checkpoint)
        if group_index % 200 == 0:
            _run_checkpoint(checkpoint)
    return sha_by_archive, tuple(seeds)


def _emit_signal_observations(
    values: tuple[ArchiveEvidence, ...],
    sha_by_archive: dict[int, str],
    consume: Callable[[tuple[int, int], str, int], None],
    checkpoint: Callable[[], None] | None,
    progress_callback: ProgressCallback | None = None,
    phase: str = "후보 비교",
) -> int:
    """Build, emit, and release one (kind, band, slot) bucket at a time."""

    discarded = 0
    slots = tuple(sorted({probe.slot for value in values for probe in value.probes}))
    for slot_index, slot in enumerate(slots, 1):
        _run_checkpoint(checkpoint)
        slot_phase = f"{phase} · 대표 이미지 {slot_index}/{len(slots)}"
        for kind, reason in (("pixel", SAME_PIXEL_SHA256), ("byte", SAME_BYTE_SHA256)):
            discarded += _emit_bucket(
                values, sha_by_archive, slot, kind, None, reason, consume, checkpoint,
                progress_callback, f"{slot_phase} · {'픽셀' if kind == 'pixel' else '원본 데이터'}",
            )
        discarded += _emit_lsh_slot(
            values, sha_by_archive, slot, consume, checkpoint, progress_callback, slot_phase
        )
    return discarded


def _emit_lsh_slot(
    values: tuple[ArchiveEvidence, ...],
    sha_by_archive: dict[int, str],
    slot: int,
    consume: Callable[[tuple[int, int], str, int], None],
    checkpoint: Callable[[], None] | None,
    progress_callback: ProgressCallback | None = None,
    phase: str = "유사 이미지 비교",
) -> int:
    """Emit each pair only once per slot, despite multiple matching bands."""

    seen_pairs: set[int] = set()
    discarded = 0
    for kind in ("dhash", "ahash"):
        for band_index in range(len(_BAND_WIDTHS)):
            _run_checkpoint(checkpoint)
            band_phase = f"{phase} · {'윤곽' if kind == 'dhash' else '명암'} {band_index + 1}/{len(_BAND_WIDTHS)}"
            buckets = _buckets_for(values, slot, kind, band_index, checkpoint, progress_callback, band_phase)
            discarded += sum(len(ids) > MAX_BUCKET_ARCHIVES for ids in buckets.values())
            for pair in _bucket_pairs(buckets, checkpoint, progress_callback, band_phase):
                if _same_archive_sha(pair, sha_by_archive):
                    continue
                packed = _pack_pair(pair)
                if packed in seen_pairs:
                    continue
                seen_pairs.add(packed)
                consume(pair, LSH_BAND_MATCH, slot)
            buckets.clear()
    seen_pairs.clear()
    return discarded


def _emit_bucket(
    values: tuple[ArchiveEvidence, ...],
    sha_by_archive: dict[int, str],
    slot: int,
    kind: str,
    band_index: int | None,
    reason: str,
    consume: Callable[[tuple[int, int], str, int], None],
    checkpoint: Callable[[], None] | None,
    progress_callback: ProgressCallback | None = None,
    phase: str = "동일 이미지 비교",
) -> int:
    buckets = _buckets_for(values, slot, kind, band_index, checkpoint, progress_callback, phase)
    discarded = sum(len(ids) > MAX_BUCKET_ARCHIVES for ids in buckets.values())
    for pair in _bucket_pairs(buckets, checkpoint, progress_callback, phase):
        if not _same_archive_sha(pair, sha_by_archive):
            consume(pair, reason, slot)
    buckets.clear()
    return discarded


def _buckets_for(
    values: tuple[ArchiveEvidence, ...],
    slot: int,
    kind: str,
    band_index: int | None,
    checkpoint: Callable[[], None] | None,
    progress_callback: ProgressCallback | None = None,
    phase: str = "비교 지표",
) -> dict[str | int, list[int]]:
    buckets: dict[str | int, list[int]] = {}
    for index, value in enumerate(_track(values, len(values), f"{phase} · 자료 묶기", progress_callback), start=1):
        for probe in value.probes:
            if probe.slot != slot:
                continue
            fingerprint = _fingerprint_for_kind(probe, kind)
            if band_index is None:
                if not fingerprint:
                    continue
                bucket_key: str | int = fingerprint.casefold()
            else:
                bucket_key = _hash_band(fingerprint, band_index)
                if bucket_key is None:
                    continue
            archive_ids = buckets.setdefault(bucket_key, [])
            if not archive_ids or archive_ids[-1] != value.archive_id:
                archive_ids.append(value.archive_id)
        if index % 200 == 0:
            _run_checkpoint(checkpoint)
    return buckets


def _track(items, total, phase, callback, unit="파일"):
    return track_progress(
        items, total, stage=AnalysisStage.CANDIDATE_BUILD, phase=phase,
        callback=callback, unit=unit, every=200,
    )


def _bucket_pairs(buckets, checkpoint, progress_callback, phase):
    total = sum(len(ids) * (len(ids) - 1) // 2 for ids in buckets.values() if len(ids) <= MAX_BUCKET_ARCHIVES)
    pairs = (pair for ids in buckets.values() if len(ids) <= MAX_BUCKET_ARCHIVES for pair in combinations(ids, 2))
    for index, pair in enumerate(_track(pairs, total, f"{phase} · 후보 쌍 비교", progress_callback, "쌍"), 1):
        yield pair
        if index % 200 == 0:
            _run_checkpoint(checkpoint)


def _pack_pair(pair: tuple[int, int]) -> int:
    return (pair[0] << 32) | pair[1]


def _fingerprint_for_kind(probe: ProbeFingerprint, kind: str) -> str:
    if kind == "pixel":
        return probe.pixel_sha256
    if kind == "byte":
        return probe.byte_sha256
    if kind == "dhash":
        return probe.dhash64
    return probe.ahash64


def _same_archive_sha(pair: tuple[int, int], sha_by_archive: dict[int, str]) -> bool:
    left = sha_by_archive.get(pair[0])
    return left is not None and left == sha_by_archive.get(pair[1])


def _mutually_selected_pairs(
    endpoint_pairs: dict[int, _EndpointTopPairs],
    checkpoint: Callable[[], None] | None,
    progress_callback: ProgressCallback | None = None,
) -> set[tuple[int, int]]:
    selected: set[tuple[int, int]] = set()
    for index, (archive_id, top_pairs) in enumerate(_track(endpoint_pairs.items(), len(endpoint_pairs), "상호 후보 확인", progress_callback), start=1):
        for pair in top_pairs.pairs:
            other_id = pair[1] if pair[0] == archive_id else pair[0]
            if pair in endpoint_pairs[other_id].pairs:
                selected.add(pair)
        if index % 200 == 0:
            _run_checkpoint(checkpoint)
    return selected


def _hash_band(value: str, band_index: int) -> int | None:
    if not _is_hash64(value):
        return None
    number = int(value, 16)
    offset = _BAND_OFFSETS[band_index]
    width = _BAND_WIDTHS[band_index]
    return (number >> offset) & ((1 << width) - 1)


def _is_hash64(value: str) -> bool:
    if len(value) != 16:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _visual_candidates(
    values: tuple[ArchiveEvidence, ...],
    signals: dict[tuple[int, int], _PairSignals],
    sha_by_archive: dict[int, str],
    root_id: int,
    analyzer_version: int,
    checkpoint: Callable[[], None] | None,
    progress_callback: ProgressCallback | None = None,
) -> tuple[list[CandidateSeed], dict[int, int]]:
    tokens_by_id = {value.archive_id: value.filename_tokens for value in values}
    selectors: dict[int, _EndpointTopPairs] = {}
    truncated: dict[int, int] = defaultdict(int)
    for index, (pair, value) in enumerate(_track(signals.items(), len(signals), "후보 근거 종합", progress_callback, "쌍"), start=1):
        if index % 200 == 0:
            _run_checkpoint(checkpoint)
        candidate = _candidate_details(pair, value, sha_by_archive, tokens_by_id)
        if candidate is None:
            continue
        reasons, score = candidate
        key = (-score, *_stable_pair_key(root_id, analyzer_version, pair))
        for archive_id in pair:
            selector = selectors.setdefault(
                archive_id, _EndpointTopPairs(MAX_VISUAL_CANDIDATES_PER_ARCHIVE)
            )
            accepted, _, _ = selector.offer(pair, key)
            if not accepted:
                truncated[archive_id] += 1
    selected_pairs = _mutually_selected_pairs(selectors, checkpoint, progress_callback)
    selectors.clear()
    selected: list[CandidateSeed] = []
    for index, pair in enumerate(_track(sorted(selected_pairs), len(selected_pairs), "비교할 후보 확정", progress_callback, "쌍"), start=1):
        details = _candidate_details(pair, signals[pair], sha_by_archive, tokens_by_id)
        if details is not None:
            selected.append(CandidateSeed(pair[0], pair[1], details[0], details[1]))
        if index % 200 == 0:
            _run_checkpoint(checkpoint)
    selected_pairs.clear()
    return selected, truncated


def _candidate_details(
    pair: tuple[int, int],
    value: _PairSignals,
    sha_by_archive: dict[int, str],
    tokens_by_id: dict[int, frozenset[str]],
) -> tuple[tuple[str, ...], int] | None:
    if _same_archive_sha(pair, sha_by_archive) or len(value.support_slots) < 2:
        return None
    reasons: set[str] = set()
    score = 0
    for reason, points in ((SAME_PIXEL_SHA256, 30), (SAME_BYTE_SHA256, 25)):
        slots = value.exact_slots.get(reason, set())
        if slots:
            reasons.add(reason)
            score += points * len(slots)
    if value.lsh_slots:
        reasons.add(LSH_BAND_MATCH)
        score += 8 * len(value.lsh_slots)
    if _shared_supporting_tokens(tokens_by_id[pair[0]], tokens_by_id[pair[1]]):
        reasons.add(SHARED_FILENAME_TOKEN_WITH_VISUAL_HIT)
        score += 2
    return _ordered_reasons(reasons), score


def _stable_pair_key(
    scan_root_id: int, analyzer_version: int, pair: tuple[int, int]
) -> tuple[int, int, int]:
    value = (
        (scan_root_id * 0x9E3779B185EBCA87)
        ^ (analyzer_version * 0xC2B2AE3D27D4EB4F)
        ^ (pair[0] * 0x165667B19E3779F9)
        ^ (pair[1] * 0x85EBCA77C2B2AE63)
    ) & 0xFFFFFFFFFFFFFFFF
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    rank = value ^ (value >> 31)
    return rank, pair[0], pair[1]


def _shared_supporting_tokens(left: frozenset[str], right: frozenset[str]) -> frozenset[str]:
    return frozenset(token for token in left & right if not _is_generic_filename_token(token))


def _is_generic_filename_token(token: str) -> bool:
    return token.isdigit() or token.startswith(("volume", "chapter"))


def _ordered_reasons(reasons: set[str]) -> tuple[str, ...]:
    return tuple(reason for reason in _REASON_ORDER if reason in reasons)


def _run_checkpoint(checkpoint: Callable[[], None] | None) -> None:
    if checkpoint is not None:
        checkpoint()
