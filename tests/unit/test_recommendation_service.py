from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier, Thread

import pytest

from archive_analyzer.duplicate_domain import DuplicateRelation
from archive_analyzer.edition_analysis import EditionKind, classify_edition
from archive_analyzer.filename_normalization import FilenameSignal
from archive_analyzer.precision_analysis import DetectedLanguage, PairDirection
from archive_analyzer.recommendation_service import (
    _records_for_group,
    build_pair_evidence,
    partition_group,
    refresh_recommendations,
    resolve_color_evidence,
    resolve_language_evidence,
    resolve_mosaic_rank,
)
from archive_analyzer.storage.duplicate_repository import (
    DuplicateRepository,
    PrecisionRelationRecord,
    RecommendationSourceGroup,
    RecommendationSourceMember,
    RecommendationSourceRelation,
)


NOW = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("ratio", "expected"),
    (
        (0.15, EditionKind.MONOCHROME),
        (0.16, EditionKind.MIXED_OR_UNKNOWN),
        (0.49, EditionKind.MIXED_OR_UNKNOWN),
        (0.50, EditionKind.FULL_COLOR),
    ),
)
def test_edition_partition_boundaries(ratio: float, expected: EditionKind) -> None:
    assert classify_edition(ratio) is expected


def test_color_and_monochrome_do_not_leave_singleton_review_sets(tmp_path: Path) -> None:
    repository, root_id = _repository(tmp_path)
    try:
        _seed_group(repository, root_id, "group-a", (0.10, 0.80, 0.60))

        summary = refresh_recommendations(repository, root_id, clock=lambda: NOW)

        sets = repository.review_candidate_sets(root_id)
        assert [(item.edition_kind, item.archive_ids) for item in sets] == [
            ("FULL_COLOR", (2, 3)),
        ]
        assert (summary.groups_processed, summary.sets_processed) == (1, 1)
    finally:
        repository.close()


def test_mixed_or_missing_color_result_has_no_recommendation(tmp_path: Path) -> None:
    repository, root_id = _repository(tmp_path)
    try:
        _seed_group(repository, root_id, "group-a", (0.30, None))

        summary = refresh_recommendations(repository, root_id, clock=lambda: NOW)

        assert {item.status for item in repository.latest_recommendations_for_root(root_id)} == {
            "ANALYSIS_REQUIRED"
        }
        assert {item.recommendation for item in repository.latest_recommendations_for_root(root_id)} == {
            "NONE"
        }
        assert (summary.recommended_sets, summary.skipped_sets) == (0, 1)
    finally:
        repository.close()


def test_exact_content_service_does_not_treat_missing_precision_as_analyzed_unknown(tmp_path: Path) -> None:
    repository, root_id = _repository(tmp_path)
    try:
        _seed_group(repository, root_id, "exact", (None, None))
        connection = repository._connection  # noqa: SLF001 - coherent source fixture
        connection.execute(
            "UPDATE archives SET path = 'work.zip', path_key = 'work', file_size = 1_000, "
            "mtime_ns = 1700000000000000000 WHERE id = 1"
        )
        connection.execute(
            "UPDATE archives SET path = '[Circle(Author)] Work (Korean).zip', "
            "path_key = 'circle-work-korean', file_size = 1_000, "
            "mtime_ns = 1700000010000000000 WHERE id = 2"
        )
        connection.execute(
            "INSERT INTO candidate_relations(scan_root_id, archive_a_id, archive_b_id, relation, "
            "confidence, matched_pages, left_pages, right_pages, recommendation, evidence_json, "
            "analyzer_version, created_at) VALUES (?, 1, 2, 'EXACT_CONTENT', 1.0, 10, 10, 10, "
            "'MANUAL', '[]', 1, ?)",
            (root_id, NOW.isoformat()),
        )
        connection.executemany(
            "INSERT INTO image_fingerprints(archive_id, entry_position, coverage, byte_sha256, "
            "pixel_sha256, dhash64, ahash64, width, height, state, analyzer_version, computed_at) "
            "VALUES (?, 0, 'FULL', 'byte', 'pixel', '0', '0', 1000, 1000, 'SUCCEEDED', 1, ?)",
            ((archive_id, NOW.isoformat()) for archive_id in (1, 2)),
        )
        connection.commit()

        summary = refresh_recommendations(repository, root_id, clock=lambda: NOW)
        records = repository.latest_recommendations_for_root(root_id)

        assert summary.recommended_sets == 0
        assert {record.status for record in records} == {"ANALYSIS_REQUIRED"}
        assert all(record.recommendation == "NONE" for record in records)
    finally:
        repository.close()


def test_singleton_and_missing_precision_are_skipped_not_recommended(tmp_path: Path) -> None:
    repository, root_id = _repository(tmp_path)
    try:
        _seed_group(repository, root_id, "singleton", (0.50,))
        _seed_group(repository, root_id, "needs-precision", (0.50, 0.80), archive_offset=1)

        summary = refresh_recommendations(repository, root_id, clock=lambda: NOW)

        records = repository.latest_recommendations_for_root(root_id)
        assert (summary.recommended_sets, summary.skipped_sets) == (0, 1)
        assert {record.status for record in records} == {"ANALYSIS_REQUIRED"}
        assert {record.recommendation for record in records} == {"NONE"}
    finally:
        repository.close()


def test_partition_never_returns_singleton_sets() -> None:
    assert partition_group(_source_group((0.10, 0.80))) == ()
    sets = partition_group(_source_group((0.80, 0.60, 0.10)))
    assert [item.archive_ids for item in sets] == [(1, 2)]


def test_unknown_member_keeps_one_unresolved_review_set() -> None:
    sets = partition_group(_source_group((0.80, None)))
    assert len(sets) == 1
    assert sets[0].edition_kind == "MIXED_OR_UNKNOWN"
    assert sets[0].archive_ids == (1, 2)


def test_exact_content_star_is_one_transitively_equivalent_recommended_set() -> None:
    group = _exact_star_group()

    candidate_sets = partition_group(group)
    evidence = build_pair_evidence(group, candidate_sets[0])
    records = _records_for_group(group, candidate_sets)

    assert len(candidate_sets) == 1
    assert candidate_sets[0].archive_ids == (1, 2, 3)
    assert evidence[(2, 3)].content_equivalent
    assert {record.status for _, record in records} == {"RECOMMENDED"}
    winner = next(record for _, record in records if record.archive_id == 3)
    assert winner.archive_id == 3
    assert winner.criteria["title"] == "LEFT_BETTER"
    assert winner.criteria["mtime"] == "LEFT_BETTER"


def test_exact_pair_with_opposite_filename_editions_remains_visible() -> None:
    full_color = FilenameSignal("FULL_COLOR", 0.9, frozenset({"fullcolor"}), False)
    mono = FilenameSignal("MONOCHROME", 0.9, frozenset({"bw"}), False)
    star = _exact_star_group(filename_colors=(full_color, mono, None))
    group = RecommendationSourceGroup(
        star.group_key,
        star.analyzer_version,
        star.members[:2],
        (),
        star.relations[:1],
    )

    candidate_sets = partition_group(group)
    records = _records_for_group(group, candidate_sets)

    assert [(candidate.edition_kind, candidate.archive_ids) for candidate in candidate_sets] == [
        ("MIXED_OR_UNKNOWN", (1, 2))
    ]
    assert {record.status for _, record in records} == {"RECOMMENDED"}
    assert [record.archive_id for _, record in records if record.recommendation == "KEEP"] == [2]


def test_exact_content_star_is_not_split_by_conflicting_edition_evidence() -> None:
    full_color = FilenameSignal("FULL_COLOR", 0.9, frozenset({"fullcolor"}), False)
    mono = FilenameSignal("MONOCHROME", 0.9, frozenset({"bw"}), False)
    group = _exact_star_group(
        color_ratios=(None, None, 0.80),
        filename_colors=(full_color, mono, mono),
    )

    candidate_sets = partition_group(group)
    evidence = build_pair_evidence(group, candidate_sets[0])
    records = _records_for_group(group, candidate_sets)

    assert [(candidate.edition_kind, candidate.archive_ids) for candidate in candidate_sets] == [
        ("MIXED_OR_UNKNOWN", (1, 2, 3))
    ]
    assert all(pair.content_equivalent for pair in evidence.values())
    assert {record.status for _, record in records} == {"RECOMMENDED"}
    assert [record.archive_id for _, record in records if record.recommendation == "KEEP"] == [3]


def test_exact_pair_and_same_color_visual_member_stay_visible_but_missing_pair_blocks() -> None:
    group = _exact_pair_with_visual_group()

    candidate_sets = partition_group(group)
    evidence = build_pair_evidence(group, candidate_sets[0])
    records = _records_for_group(group, candidate_sets)

    assert [candidate_set.archive_ids for candidate_set in candidate_sets] == [(1, 2, 3)]
    assert evidence[(1, 2)].content_equivalent
    assert not evidence[(1, 3)].content_equivalent
    assert (2, 3) not in evidence
    assert {record.status for _, record in records} == {"ANALYSIS_REQUIRED"}
    assert {record.recommendation for _, record in records} == {"NONE"}


def test_exact_pair_and_visual_members_can_recommend_with_direct_precision_bridges() -> None:
    from dataclasses import replace
    group = _exact_pair_with_visual_group(visual_count=2, direct_precision=True)
    assert {record.status for _, record in _records_for_group(group, partition_group(group))} == {"RECOMMENDED"}
    # The exact copy also needs a measured mosaic comparison, not inferred metadata.
    group = replace(group, precision_relations=group.precision_relations + (
        PrecisionRelationRecord(1, 2, "TIE", 1.0, "TIE", 1.0, ("measured exact pair",)),
    ))

    candidate_sets = partition_group(group)
    evidence = build_pair_evidence(group, candidate_sets[0])
    records = _records_for_group(group, candidate_sets)

    assert [candidate_set.archive_ids for candidate_set in candidate_sets] == [(1, 2, 3, 4)]
    assert evidence[(1, 2)].content_equivalent
    assert all(pair in evidence for pair in ((1, 3), (1, 4), (2, 3), (2, 4), (3, 4)))
    assert {record.status for _, record in records} == {"RECOMMENDED"}
    assert [record.archive_id for _, record in records if record.recommendation == "KEEP"] == [4]


def test_exact_copy_propagates_reversed_precision_orientation() -> None:
    base = _exact_pair_with_visual_group()
    group = RecommendationSourceGroup(
        base.group_key,
        base.analyzer_version,
        base.members,
        (
            PrecisionRelationRecord(
                3,
                1,
                PairDirection.RIGHT_BETTER.value,
                1.0,
                PairDirection.LEFT_BETTER.value,
                1.0,
                ("reversed direct bridge",),
            ),
        ),
        base.relations,
    )

    candidate_set = partition_group(group)[0]
    evidence = build_pair_evidence(group, candidate_set)

    assert evidence[(1, 3)].mosaic is PairDirection.LEFT_BETTER
    assert evidence[(1, 3)].quality is PairDirection.RIGHT_BETTER
    assert evidence[(2, 3)].mosaic is PairDirection.LEFT_BETTER
    assert evidence[(2, 3)].quality is PairDirection.RIGHT_BETTER


def test_precision_bridge_propagates_across_two_exact_components() -> None:
    base = _exact_pair_with_visual_group(visual_count=2)
    group = RecommendationSourceGroup(
        base.group_key,
        base.analyzer_version,
        base.members,
        (
            PrecisionRelationRecord(
                1,
                3,
                PairDirection.LEFT_BETTER.value,
                1.0,
                PairDirection.RIGHT_BETTER.value,
                1.0,
                ("component bridge",),
            ),
        ),
        (
            RecommendationSourceRelation(1, 2, DuplicateRelation.EXACT_CONTENT, 20, 1.0),
            RecommendationSourceRelation(3, 4, DuplicateRelation.EXACT_CONTENT, 20, 1.0),
            RecommendationSourceRelation(1, 3, DuplicateRelation.VISUAL_VARIANT, 10, 0.9),
        ),
    )

    candidate_set = partition_group(group)[0]
    evidence = build_pair_evidence(group, candidate_set)

    for pair in ((1, 3), (1, 4), (2, 3), (2, 4)):
        assert evidence[pair].mosaic is PairDirection.LEFT_BETTER
        assert evidence[pair].quality is PairDirection.RIGHT_BETTER
    assert evidence[(1, 2)].content_equivalent
    assert evidence[(3, 4)].content_equivalent


def test_conflicting_precision_bridges_across_exact_copy_become_unknown() -> None:
    base = _exact_pair_with_visual_group()
    group = RecommendationSourceGroup(
        base.group_key,
        base.analyzer_version,
        base.members,
        (
            PrecisionRelationRecord(
                1,
                3,
                PairDirection.LEFT_BETTER.value,
                1.0,
                PairDirection.LEFT_BETTER.value,
                1.0,
                ("first bridge",),
            ),
            PrecisionRelationRecord(
                2,
                3,
                PairDirection.RIGHT_BETTER.value,
                1.0,
                PairDirection.RIGHT_BETTER.value,
                1.0,
                ("conflicting bridge",),
            ),
        ),
        base.relations,
    )

    candidate_set = partition_group(group)[0]
    evidence = build_pair_evidence(group, candidate_set)
    records = _records_for_group(group, (candidate_set,))

    assert evidence[(1, 3)].mosaic is PairDirection.UNKNOWN
    assert evidence[(1, 3)].quality is PairDirection.UNKNOWN
    assert evidence[(2, 3)].mosaic is PairDirection.UNKNOWN
    assert evidence[(2, 3)].quality is PairDirection.UNKNOWN
    assert {record.status for _, record in records} == {"RECOMMENDED"}
    assert any(record.recommendation == "KEEP" for _, record in records)


def test_unknown_visual_member_keeps_whole_source_group_unresolved() -> None:
    group = _exact_pair_with_visual_group(unknown_visual=True)

    candidate_sets = partition_group(group)
    records = _records_for_group(group, candidate_sets)

    assert [(candidate.edition_kind, candidate.archive_ids) for candidate in candidate_sets] == [
        ("MIXED_OR_UNKNOWN", (1, 2, 3))
    ]
    assert {record.status for _, record in records} == {"ANALYSIS_REQUIRED"}
    assert {record.recommendation for _, record in records} == {"NONE"}


def test_filename_fallback_resolvers_preserve_measured_and_precision_values() -> None:
    korean = FilenameSignal("KOREAN", 0.9, frozenset({"korean"}), False)
    japanese = FilenameSignal("JAPANESE", 0.9, frozenset({"japanese"}), False)
    full_color = FilenameSignal("FULL_COLOR", 0.9, frozenset({"color"}), False)
    mono = FilenameSignal("MONOCHROME", 0.9, frozenset({"bw"}), False)
    uncensored = FilenameSignal("UNCENSORED", 0.9, frozenset({"uncensored"}), False)

    assert resolve_language_evidence(DetectedLanguage.UNKNOWN, korean) is DetectedLanguage.KOREAN
    assert resolve_language_evidence(DetectedLanguage.KOREAN, korean) is DetectedLanguage.KOREAN
    assert resolve_language_evidence(DetectedLanguage.KOREAN, japanese) is DetectedLanguage.UNKNOWN
    assert resolve_color_evidence(None, full_color) is EditionKind.FULL_COLOR
    assert resolve_color_evidence(0.80, mono) is EditionKind.FULL_COLOR
    assert resolve_color_evidence(0.30, full_color) is EditionKind.FULL_COLOR
    assert resolve_mosaic_rank(uncensored) == 3


def _source_group(ratios: tuple[float | None, ...]) -> RecommendationSourceGroup:
    return RecommendationSourceGroup(
        "source",
        1,
        tuple(
            RecommendationSourceMember(
                archive_id=index,
                path=Path(f"book-{index}.cbz"),
                file_size=100,
                mtime_ns=1_000,
                page_count=10,
                resolution_area=1_000_000,
                color_page_ratio=ratio,
                language="UNKNOWN",
            )
            for index, ratio in enumerate(ratios, start=1)
        ),
        (),
    )


def _exact_star_group(
    *,
    color_ratios: tuple[float | None, float | None, float | None] = (None, None, None),
    filename_colors: tuple[FilenameSignal | None, FilenameSignal | None, FilenameSignal | None] = (
        None,
        None,
        None,
    ),
) -> RecommendationSourceGroup:
    members = [
        RecommendationSourceMember(
            archive_id=1,
            path=Path("work.zip"),
            file_size=1_000,
            mtime_ns=1_700_000_000_000_000_000,
            page_count=20,
            resolution_area=1_000_000,
            color_page_ratio=color_ratios[0],
            language="UNKNOWN",
            language_analyzed=True,
            filename_color=filename_colors[0],
        ),
        RecommendationSourceMember(
            archive_id=2,
            path=Path("[Circle] Work.zip"),
            file_size=1_000,
            mtime_ns=1_700_000_005_000_000_000,
            page_count=20,
            resolution_area=1_000_000,
            color_page_ratio=color_ratios[1],
            language="UNKNOWN",
            language_analyzed=True,
            filename_color=filename_colors[1],
        ),
        RecommendationSourceMember(
            archive_id=3,
            path=Path("[Circle(Author)] Work.zip"),
            file_size=1_000,
            mtime_ns=1_700_000_010_000_000_000,
            page_count=20,
            resolution_area=1_000_000,
            color_page_ratio=color_ratios[2],
            language="UNKNOWN",
            language_analyzed=True,
            filename_color=filename_colors[2],
        ),
    ]
    relations = [
        RecommendationSourceRelation(1, 2, DuplicateRelation.EXACT_CONTENT, 20, 1.0),
        RecommendationSourceRelation(1, 3, DuplicateRelation.EXACT_CONTENT, 20, 1.0),
    ]
    return RecommendationSourceGroup("source", 1, tuple(members), (), tuple(relations))


def _exact_pair_with_visual_group(
    *, visual_count: int = 1, direct_precision: bool = False, unknown_visual: bool = False
) -> RecommendationSourceGroup:
    members = [
        RecommendationSourceMember(
            archive_id=1,
            path=Path("work.zip"),
            file_size=1_000,
            mtime_ns=1_700_000_000_000_000_000,
            page_count=20,
            resolution_area=1_000_000,
            color_page_ratio=0.80,
            language="KOREAN",
        ),
        RecommendationSourceMember(
            archive_id=2,
            path=Path("[Circle] Work.zip"),
            file_size=1_000,
            mtime_ns=1_700_000_005_000_000_000,
            page_count=20,
            resolution_area=1_000_000,
            color_page_ratio=0.80,
            language="KOREAN",
        ),
    ]
    for archive_id in range(3, 3 + visual_count):
        members.append(
            RecommendationSourceMember(
                archive_id=archive_id,
                path=Path(f"[Circle(Author)] Work {archive_id}.zip"),
                file_size=1_000,
                mtime_ns=1_700_000_000_000_000_000 + (archive_id - 1) * 5_000_000_000,
                page_count=20,
                resolution_area=1_000_000,
                color_page_ratio=None if unknown_visual and archive_id == 3 else 0.80,
                language="KOREAN",
            )
        )
    relations = [
        RecommendationSourceRelation(1, 2, DuplicateRelation.EXACT_CONTENT, 20, 1.0),
        *(
            RecommendationSourceRelation(
                1, archive_id, DuplicateRelation.VISUAL_VARIANT, 10, 0.9
            )
            for archive_id in range(3, 3 + visual_count)
        ),
    ]
    if visual_count > 1:
        relations.extend(
            RecommendationSourceRelation(
                archive_id,
                archive_id + 1,
                DuplicateRelation.VISUAL_VARIANT,
                10,
                0.9,
            )
            for archive_id in range(3, 2 + visual_count)
        )
    precision = ()
    if direct_precision:
        precision = tuple(
            PrecisionRelationRecord(
                relation.archive_a_id,
                relation.archive_b_id,
                PairDirection.TIE.value,
                1.0,
                PairDirection.TIE.value,
                1.0,
                ("direct candidate edge",),
            )
            for relation in relations
            if relation.relation is not DuplicateRelation.EXACT_CONTENT
        )
    return RecommendationSourceGroup(
        "source", 1, tuple(members), precision, tuple(relations)
    )


def test_refresh_reuses_completed_input_and_only_touches_affected_group(tmp_path: Path) -> None:
    repository, root_id = _repository(tmp_path)
    try:
        _seed_group(repository, root_id, "group-a", (0.10, 0.80))
        _seed_group(repository, root_id, "group-b", (0.10, 0.80), archive_offset=2)
        refresh_recommendations(repository, root_id, clock=lambda: NOW)
        before_b = repository.recommendation_run_ids_for_group(root_id, "group-b")
        before_count = repository.recommendation_run_count(root_id)

        refresh_recommendations(
            repository, root_id, affected_group_keys=("group-a",), clock=lambda: NOW
        )

        assert repository.recommendation_run_ids_for_group(root_id, "group-b") == before_b
        assert repository.recommendation_run_count(root_id) == before_count
    finally:
        repository.close()


def test_concurrent_identical_refresh_writes_one_run_and_one_item_per_archive(
    tmp_path: Path,
) -> None:
    database = tmp_path / "index.db"
    repository, root_id = _repository(tmp_path)
    try:
        _seed_group(repository, root_id, "group-a", (0.50, 0.80))
    finally:
        repository.close()

    barrier = Barrier(2)
    errors: list[BaseException] = []

    def refresh_in_separate_connection() -> None:
        connection = DuplicateRepository.open(database)
        try:
            barrier.wait()
            refresh_recommendations(connection, root_id, clock=lambda: NOW)
        except BaseException as error:  # noqa: BLE001 - assert worker result below
            errors.append(error)
        finally:
            connection.close()

    workers = [Thread(target=refresh_in_separate_connection) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert errors == []
    verify = DuplicateRepository.open(database)
    try:
        assert verify.recommendation_run_count(root_id) == 1
        assert verify._connection.execute(  # noqa: SLF001 - exact duplicate-write contract
            "SELECT COUNT(*) FROM recommendation_items"
        ).fetchone() == (2,)
    finally:
        verify.close()


def _repository(tmp_path: Path) -> tuple[DuplicateRepository, int]:
    repository = DuplicateRepository.open(tmp_path / "index.db")
    root_id = repository._connection.execute(  # noqa: SLF001 - concise persistence fixture
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
        (str(tmp_path), "root", NOW.isoformat()),
    ).lastrowid
    repository._connection.commit()  # noqa: SLF001 - fixture setup
    return repository, int(root_id)


def _seed_group(
    repository: DuplicateRepository,
    root_id: int,
    group_key: str,
    ratios: tuple[float | None, ...],
    *,
    archive_offset: int = 0,
) -> None:
    connection = repository._connection  # noqa: SLF001 - concise persistence fixture
    group_id = connection.execute(
        "INSERT INTO candidate_groups(scan_root_id, group_key, strongest_relation, confidence, "
        "analyzer_version, created_at) VALUES (?, ?, 'EXACT_CONTENT', 1.0, 1, ?)",
        (root_id, group_key, NOW.isoformat()),
    ).lastrowid
    for index, ratio in enumerate(ratios, start=1):
        archive_id = archive_offset + index
        connection.execute(
            "INSERT INTO archives(id, scan_root_id, path, path_key, file_size, mtime_ns, "
            "archive_format, image_count, state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, ?, ?, ?, ?, 'CBZ', 10, 'INDEXED', ?, ?, 1)",
            (archive_id, root_id, str(Path(f"book-{archive_id}.cbz")), f"book-{archive_id}",
             100 + archive_id, 1_000 + archive_id, NOW.isoformat(), NOW.isoformat()),
        )
        connection.execute(
            "INSERT INTO candidate_group_members(group_id, archive_id) VALUES (?, ?)",
            (group_id, archive_id),
        )
        if ratio is not None:
            connection.execute(
                "INSERT INTO edition_profiles(archive_id, file_size, mtime_ns, sample_count, "
                "color_page_ratio, median_color_score, language_hints_json, state, algorithm_version, computed_at) "
                "VALUES (?, ?, ?, 4, ?, 0.5, '[]', 'SUCCEEDED', 1, ?)",
                (archive_id, 100 + archive_id, 1_000 + archive_id, ratio, NOW.isoformat()),
            )
    connection.commit()
