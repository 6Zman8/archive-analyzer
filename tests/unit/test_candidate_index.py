import pytest

from archive_analyzer.candidate_index import (
    ArchiveEvidence,
    CandidateSeed,
    build_candidate_index,
    generate_candidate_seeds,
)
from archive_analyzer.duplicate_domain import ProbeFingerprint
from archive_analyzer.fingerprinting import hamming_distance


def probe(slot: int, dhash: str, *, pixel: str | None = None, byte: str | None = None) -> ProbeFingerprint:
    return ProbeFingerprint(
        slot=slot,
        entry_position=slot,
        byte_sha256=byte or "",
        pixel_sha256=pixel or "",
        dhash64=dhash,
        ahash64=dhash,
        width=100,
        height=100,
    )


def evidence(
    archive_id: int,
    *,
    file_hash: str | None = None,
    probes: tuple[ProbeFingerprint, ...] = (),
    tokens: frozenset[str] = frozenset(),
    root_id: int = 1,
    file_size: int = 100,
    mtime_ns: int = 10,
    analyzer_version: int = 1,
) -> ArchiveEvidence:
    return ArchiveEvidence(
        archive_id=archive_id,
        file_sha256=file_hash,
        probes=probes,
        filename_tokens=tokens,
        scan_root_id=root_id,
        file_size=file_size,
        mtime_ns=mtime_ns,
        analyzer_version=analyzer_version,
    )


def test_exact_archive_hash_always_creates_star_candidates() -> None:
    seeds = generate_candidate_seeds(
        (evidence(3, file_hash="same"), evidence(1, file_hash="same"), evidence(2, file_hash="same"))
    )

    assert seeds == (
        CandidateSeed(1, 2, ("SAME_ARCHIVE_SHA256",), 100),
        CandidateSeed(1, 3, ("SAME_ARCHIVE_SHA256",), 100),
    )


def test_same_sha_group_emits_only_star_edges_even_with_matching_probes() -> None:
    values = tuple(
        evidence(
            archive_id,
            file_hash="same",
            probes=(probe(0, "0000000000000000"), probe(1, "1111111111111111")),
        )
        for archive_id in (1, 2, 3)
    )

    assert generate_candidate_seeds(values) == (
        CandidateSeed(1, 2, ("SAME_ARCHIVE_SHA256",), 100),
        CandidateSeed(1, 3, ("SAME_ARCHIVE_SHA256",), 100),
    )


def test_two_distinct_probe_hits_create_visual_candidate() -> None:
    left = evidence(1, probes=(probe(0, "0000000000000000"), probe(50, "ffffffffffffffff")))
    right = evidence(2, probes=(probe(0, "0000000000000001"), probe(50, "fffffffffffffffe")))

    assert generate_candidate_seeds((left, right)) == (
        CandidateSeed(1, 2, ("LSH_BAND_MATCH",), 16),
    )


def test_diagnostics_use_actual_observation_and_membership_units() -> None:
    result = build_candidate_index(
        (
            evidence(1, probes=(probe(0, "0000000000000000"), probe(1, "1111111111111111"))),
            evidence(2, probes=(probe(0, "0000000000000000"), probe(1, "1111111111111111"))),
        )
    )

    assert result.signal_observation_count == 2
    assert result.endpoint_pair_membership_count == 2
    assert result.peak_endpoint_pair_membership_count == 2
    assert result.mutual_selected_pair_count == 1
    assert result.selector_eviction_event_count == 0
    assert result.selector_rejected_endpoint_observation_count == 0


def test_hamming_distance_six_or_less_can_share_one_of_seven_lsh_bands_per_slot() -> None:
    left = evidence(
        1,
        probes=(probe(0, "0000000000000000"), probe(1, "0000000000000000")),
    )
    right = evidence(
        2,
        probes=(probe(0, "0001000100010001"), probe(1, "0001000100010001")),
    )

    assert hamming_distance("0000000000000000", "0001000100010001") == 4
    assert generate_candidate_seeds((left, right)) == (
        CandidateSeed(1, 2, ("LSH_BAND_MATCH",), 16),
    )


def test_common_single_cover_does_not_create_quadratic_pairs() -> None:
    values = tuple(evidence(index, probes=(probe(0, "0000000000000000"),)) for index in range(1_000))

    assert generate_candidate_seeds(values) == ()


def test_filename_is_only_supporting_evidence_after_visual_hits() -> None:
    left = evidence(
        1,
        probes=(probe(0, "0000000000000000"), probe(1, "1111111111111111")),
        tokens=frozenset({"title", "author"}),
    )
    right = evidence(
        2,
        probes=(probe(0, "0000000000000001"), probe(1, "1111111111111110")),
        tokens=frozenset({"title", "different"}),
    )

    assert generate_candidate_seeds((left, right)) == (
        CandidateSeed(
            1,
            2,
            ("LSH_BAND_MATCH", "SHARED_FILENAME_TOKEN_WITH_VISUAL_HIT"),
            18,
        ),
    )
    assert generate_candidate_seeds(
        (evidence(1, tokens=frozenset({"title"})), evidence(2, tokens=frozenset({"title"})))
    ) == ()


def test_generic_filename_markers_never_create_or_raise_a_visual_score() -> None:
    left = evidence(
        1,
        probes=(probe(0, "0000000000000000"), probe(1, "1111111111111111")),
        tokens=frozenset({"001", "volume1"}),
    )
    right = evidence(
        2,
        probes=(probe(0, "0000000000000001"), probe(1, "1111111111111110")),
        tokens=frozenset({"001", "volume1"}),
    )

    assert generate_candidate_seeds((left, right)) == (
        CandidateSeed(1, 2, ("LSH_BAND_MATCH",), 16),
    )


def test_duplicate_ids_and_invalid_or_shared_root_evidence_do_not_make_self_pairs() -> None:
    values = (
        evidence(1, probes=(probe(0, "0000000000000000"), probe(1, "1111111111111111"))),
        evidence(1, probes=(probe(0, "0000000000000000"), probe(1, "1111111111111111"))),
    )

    assert generate_candidate_seeds(values) == ()


def test_visual_candidates_are_bounded_to_one_hundred_per_archive() -> None:
    center = evidence(
        1,
        probes=(
            probe(0, "0000000000000000"),
            probe(1, "1111111111111111"),
            probe(2, "2222222222222222"),
            probe(3, "3333333333333333"),
        ),
    )
    first_bucket = tuple(
        evidence(
            archive_id,
            probes=(probe(0, "0000000000000001"), probe(1, "1111111111111110")),
        )
        for archive_id in range(2, 152)
    )
    second_bucket = tuple(
        evidence(
            archive_id,
            probes=(probe(2, "2222222222222223"), probe(3, "3333333333333332")),
        )
        for archive_id in range(152, 302)
    )

    forward = build_candidate_index((center, *first_bucket, *second_bucket))
    reverse = build_candidate_index(tuple(reversed((center, *first_bucket, *second_bucket))))
    seeds = forward.seeds

    assert len([seed for seed in seeds if seed.archive_a_id == 1]) == 100
    assert forward == reverse


def test_mixed_root_or_version_evidence_is_rejected_before_pairing() -> None:
    base = evidence(1)

    with pytest.raises(ValueError, match="scan root"):
        generate_candidate_seeds((base, evidence(2, root_id=2)))
    with pytest.raises(ValueError, match="analyzer version"):
        generate_candidate_seeds((base, evidence(2, analyzer_version=2)))
    with pytest.raises(ValueError, match="scan root"):
        generate_candidate_seeds((base, evidence(1, root_id=2)))


def test_result_reports_bucket_discards_and_input_order_independent_cap_selection() -> None:
    center = evidence(
        1,
        probes=(probe(0, "0000000000000000"), probe(1, "1111111111111111")),
    )
    group = tuple(
        evidence(
            archive_id,
            probes=(probe(0, "0000000000000001"), probe(1, "1111111111111110")),
        )
        for archive_id in range(2, 152)
    )
    oversized = tuple(
        evidence(
            archive_id,
            probes=(probe(2, "aaaaaaaaaaaaaaaa"),),
        )
        for archive_id in range(152, 354)
    )

    forward = build_candidate_index((center, *group, *oversized))
    reverse = build_candidate_index(tuple(reversed((center, *group, *oversized))))

    assert forward == reverse
    assert forward.discarded_oversized_bucket_count > 0
    assert dict(forward.truncated_candidate_counts).get(1, 0) > 0


def test_candidate_builder_runs_cooperative_checkpoints() -> None:
    calls = 0

    def cancel() -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("cancelled")

    with pytest.raises(RuntimeError, match="cancelled"):
        build_candidate_index(
            tuple(evidence(archive_id) for archive_id in range(1, 402)),
            checkpoint=cancel,
        )
