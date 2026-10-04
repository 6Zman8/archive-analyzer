import time
import os
import tracemalloc
from collections import Counter

from archive_analyzer.candidate_index import (
    ArchiveEvidence,
    build_candidate_index,
    generate_candidate_seeds,
)
from archive_analyzer.duplicate_domain import ProbeFingerprint


def test_ten_thousand_common_cover_inputs_are_skipped_without_pair_expansion() -> None:
    common_probe = ProbeFingerprint(
        slot=0,
        entry_position=0,
        byte_sha256="",
        pixel_sha256="",
        dhash64="0000000000000000",
        ahash64="0000000000000000",
        width=100,
        height=100,
    )
    values = tuple(
        ArchiveEvidence(
            archive_id=index,
            file_sha256=None,
            probes=(common_probe,),
            filename_tokens=frozenset(),
            scan_root_id=1,
            file_size=100,
            mtime_ns=10,
            analyzer_version=1,
        )
        for index in range(1, 10_001)
    )

    started = time.perf_counter()
    assert generate_candidate_seeds(values) == ()
    assert time.perf_counter() - started < 5


def test_ten_thousand_valid_buckets_keep_pair_state_and_final_edges_bounded() -> None:
    def grouped_probe(slot: int, group: int) -> ProbeFingerprint:
        fingerprint = f"{group << 54:016x}"
        return ProbeFingerprint(
            slot=slot,
            entry_position=slot,
            byte_sha256="",
            pixel_sha256="",
            dhash64=fingerprint,
            ahash64="",
            width=100,
            height=100,
        )

    values = tuple(
        ArchiveEvidence(
            archive_id=archive_id,
            file_sha256=None,
            probes=(
                grouped_probe(0, archive_id // 10),
                grouped_probe(1, archive_id // 10),
            ),
            filename_tokens=frozenset(),
            scan_root_id=1,
            file_size=100,
            mtime_ns=10,
            analyzer_version=1,
        )
        for archive_id in range(1, 10_001)
    )

    started = time.perf_counter()
    normal_result = build_candidate_index(values)
    normal_elapsed_seconds = time.perf_counter() - started
    del normal_result
    tracemalloc.start()
    started = time.perf_counter()
    try:
        forward = build_candidate_index(values)
        elapsed_seconds = time.perf_counter() - started
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    reverse = build_candidate_index(tuple(reversed(values)))
    endpoint_counts = Counter(
        archive_id
        for seed in forward.seeds
        for archive_id in (seed.archive_a_id, seed.archive_b_id)
    )

    assert forward == reverse
    assert forward.discarded_oversized_bucket_count > 0
    assert forward.signal_observation_count > 0
    assert forward.signal_observation_count <= len(values) * 200 * 7
    assert forward.endpoint_pair_membership_count <= len(values) * 200
    assert forward.peak_endpoint_pair_membership_count <= len(values) * 200
    assert forward.mutual_selected_pair_count <= len(values) * 200 // 2
    assert max(endpoint_counts.values(), default=0) <= 100
    assert normal_elapsed_seconds < 5
    # tracemalloc adds substantial scheduler/allocator overhead on shared CI.
    # Keep the uninstrumented 5-second budget and all memory/pair bounds above.
    assert elapsed_seconds < (30 if os.environ.get("GITHUB_ACTIONS") == "true" else 10)
    assert peak_bytes < 350 * 1024 * 1024
