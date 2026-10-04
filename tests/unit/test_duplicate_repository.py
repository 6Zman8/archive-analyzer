import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Thread

import pytest

from archive_analyzer.domain import ArchiveFormat, FileSnapshot
from archive_analyzer.duplicate_domain import (
    AnalysisStage,
    ArchiveAnalysisInput,
    DuplicateRelation,
    DuplicateProgress,
    ImageEntryRef,
    ReviewAction,
)
from archive_analyzer.edition_analysis import (
    EditionComparison,
    EditionEvidence,
    EditionFlag,
    EditionProfile,
)
from archive_analyzer.fingerprinting import ImageFingerprint, fingerprint_image
from archive_analyzer.matching import ArchiveFingerprintSet, CandidateMatch
from archive_analyzer.precision_analysis import (
    DetectedLanguage,
    PageLanguageEvidence,
    PageQualityMetrics,
)
from archive_analyzer.sequence_matching import SequenceMatch, SequenceRelation
from archive_analyzer.storage.duplicate_repository import (
    DuplicateRepository,
    EditionProfileInput,
    EditionRelationCandidate,
    PrecisionProfileRecord,
    PrecisionPageRecord,
    PrecisionRelationRecord,
    PrecisionScope,
    RecommendationRecord,
    ReviewCandidateSet,
    SequenceAnalysisCandidate,
)
from archive_analyzer.storage.repository import ScanAlreadyRunning
from tests.image_helpers import encoded_gradient


FIXED_NOW = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)


def test_existing_archive_rows_backfill_without_opening_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 1)
    archive_id = archive_ids[0]
    repository._connection.execute(  # noqa: SLF001 - path-only backfill fixture
        "UPDATE archives SET path = ?, path_key = ? WHERE id = ?",
        (str(tmp_path / "Work Korean fullcolor.zip"), "work-korean-fullcolor", archive_id),
    )
    repository._connection.commit()  # noqa: SLF001 - path-only backfill fixture
    monkeypatch.setattr(
        Path,
        "open",
        lambda *_args, **_kwargs: pytest.fail("archive must not be opened"),
    )
    try:
        assert repository.backfill_filename_evidence(root_id) == 1
        saved = repository.filename_evidence_for_archives((archive_id,))[archive_id]
        assert saved.language.value == "KOREAN"
        assert saved.color.value == "FULL_COLOR"
        assert repository.backfill_filename_evidence(root_id) == 0
    finally:
        repository.close()


def test_review_candidate_sets_only_returns_current_group_membership(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    try:
        connection = repository._connection  # noqa: SLF001 - persistence fixture
        group_id = connection.execute(
            "INSERT INTO candidate_groups(scan_root_id, group_key, strongest_relation, confidence, "
            "analyzer_version, created_at) VALUES (?, 'group', 'EXACT_CONTENT', 1.0, 1, ?)",
            (root_id, FIXED_NOW.isoformat()),
        ).lastrowid
        connection.execute(
            "INSERT INTO candidate_group_members(group_id, archive_id) VALUES (?, ?)",
            (group_id, archive_ids[0]),
        )
        connection.commit()
        candidate_set = ReviewCandidateSet("set", "group", "FULL_COLOR", (archive_ids[0],))
        repository.replace_candidate_sets("group", (candidate_set,), computed_at=FIXED_NOW)
        connection.execute(
            "DELETE FROM candidate_group_members WHERE group_id = ? AND archive_id = ?",
            (group_id, archive_ids[0]),
        )
        connection.execute(
            "INSERT INTO candidate_group_members(group_id, archive_id) VALUES (?, ?)",
            (group_id, archive_ids[1]),
        )
        connection.commit()

        assert repository.review_candidate_sets(root_id) == ()
    finally:
        repository.close()


def test_same_timestamp_refresh_exposes_only_current_generation(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    try:
        connection = repository._connection  # noqa: SLF001 - generation fixture
        group_id = connection.execute(
            "INSERT INTO candidate_groups(scan_root_id, group_key, strongest_relation, confidence, "
            "analyzer_version, created_at) VALUES (?, 'group', 'EXACT_CONTENT', 1.0, 1, ?)",
            (root_id, FIXED_NOW.isoformat()),
        ).lastrowid
        connection.executemany(
            "INSERT INTO candidate_group_members(group_id, archive_id) VALUES (?, ?)",
            ((group_id, archive_id) for archive_id in archive_ids),
        )
        connection.commit()
        old_sets = (ReviewCandidateSet("old-set", "group", "FULL_COLOR", archive_ids),)

        repository.replace_candidate_sets("group", old_sets, computed_at=FIXED_NOW)
        repository.replace_candidate_sets("group", (), computed_at=FIXED_NOW)

        assert repository.review_candidate_sets(root_id) == ()
    finally:
        repository.close()


def test_review_candidate_sets_reads_one_consistent_generation_snapshot(tmp_path: Path) -> None:
    database = tmp_path / "index.db"
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    writer = DuplicateRepository.open(database)
    try:
        connection = repository._connection  # noqa: SLF001 - concurrent snapshot fixture
        group_id = connection.execute(
            "INSERT INTO candidate_groups(scan_root_id, group_key, strongest_relation, confidence, "
            "analyzer_version, created_at) VALUES (?, 'group', 'EXACT_CONTENT', 1.0, 1, ?)",
            (root_id, FIXED_NOW.isoformat()),
        ).lastrowid
        connection.execute(
            "INSERT INTO candidate_group_members(group_id, archive_id) VALUES (?, ?)",
            (group_id, archive_ids[0]),
        )
        connection.commit()
        old_set = ReviewCandidateSet("old-set", "group", "FULL_COLOR", (archive_ids[0],))
        new_set = ReviewCandidateSet("new-set", "group", "FULL_COLOR", (archive_ids[1],))
        repository.replace_candidate_sets("group", (old_set,), computed_at=FIXED_NOW)

        mutation_errors: list[BaseException] = []
        mutated = False

        def replace_generation_before_set_read(statement: str) -> None:
            nonlocal mutated
            if mutated or not statement.startswith("SELECT candidate.set_key"):
                return
            mutated = True
            try:
                other = writer._connection  # noqa: SLF001 - concurrent writer fixture
                other.execute("BEGIN IMMEDIATE")
                other.execute("DELETE FROM candidate_group_members WHERE group_id = ?", (group_id,))
                other.execute(
                    "INSERT INTO candidate_group_members(group_id, archive_id) VALUES (?, ?)",
                    (group_id, archive_ids[1]),
                )
                other.execute(
                    "INSERT INTO edition_candidate_sets("
                    "set_key, scan_root_id, source_group_key, edition_kind, member_ids_json, "
                    "input_fingerprint, algorithm_version, computed_at) "
                    "VALUES (?, ?, 'group', 'FULL_COLOR', ?, 'new-input', 2, ?)",
                    (
                        new_set.set_key,
                        root_id,
                        json.dumps(new_set.archive_ids, separators=(",", ":")),
                        FIXED_NOW.replace(minute=1).isoformat(),
                    ),
                )
                other.execute(
                    "UPDATE edition_candidate_generations SET generation_key = 'new-generation', "
                    "set_keys_json = ?, computed_at = ? WHERE source_group_key = 'group'",
                    (
                        json.dumps((new_set.set_key,), separators=(",", ":")),
                        FIXED_NOW.replace(minute=1).isoformat(),
                    ),
                )
                other.commit()
            except BaseException as error:  # pragma: no cover - asserted below
                mutation_errors.append(error)

        connection.set_trace_callback(replace_generation_before_set_read)
        assert repository.review_candidate_sets(root_id) == (old_set,)
        connection.set_trace_callback(None)

        assert mutated
        assert mutation_errors == []
        assert repository.review_candidate_sets(root_id) == (new_set,)
    finally:
        repository._connection.set_trace_callback(None)  # noqa: SLF001 - fixture cleanup
        writer.close()
        repository.close()


def test_review_group_details_uses_only_derived_members_and_source_review_key(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 3)
    try:
        repository.replace_candidate_relations(
            root_id,
            analyzer_version=1,
            matches=(
                _relation(archive_ids[0], archive_ids[1]),
                _relation(archive_ids[1], archive_ids[2]),
            ),
            created_at=FIXED_NOW,
        )
        source_group_key = repository.group_summaries(root_id)[0].group_key
        candidate_set = ReviewCandidateSet(
            "derived-set", source_group_key, "FULL_COLOR", archive_ids[:2]
        )
        other_set = ReviewCandidateSet(
            "other-set", source_group_key, "MONOCHROME", archive_ids[2:]
        )
        repository.replace_candidate_sets(
            source_group_key, (candidate_set, other_set), computed_at=FIXED_NOW
        )
        repository._connection.execute(  # noqa: SLF001 - direct persisted-review fixture
            "INSERT INTO review_actions(group_key, archive_id, action, file_size, mtime_ns, created_at) "
            "VALUES (?, ?, 'KEEP', 10, 7, ?)",
            (source_group_key, archive_ids[0], FIXED_NOW.isoformat()),
        )
        repository._connection.execute(  # noqa: SLF001 - unrelated newer review fixture
            "INSERT INTO review_actions(group_key, archive_id, action, file_size, mtime_ns, created_at) "
            "VALUES ('other-group', ?, 'REMOVE_CANDIDATE', 10, 7, ?)",
            (archive_ids[0], FIXED_NOW.isoformat()),
        )
        repository._connection.commit()

        detail = repository.review_group_details(candidate_set.set_key)

        assert detail is not None
        assert detail.source_group_key == source_group_key
        assert [member.archive_id for member in detail.members] == list(archive_ids[:2])
        assert detail.members[0].review_action is ReviewAction.KEEP
        assert [(item.archive_a_id, item.archive_b_id) for item in detail.relations] == [
            (archive_ids[0], archive_ids[1])
        ]

        repository._connection.execute(  # noqa: SLF001 - malformed derived-row fixture
            "UPDATE edition_candidate_sets SET member_ids_json = '[not-json' WHERE set_key = ?",
            (candidate_set.set_key,),
        )
        repository._connection.commit()
        assert repository.review_group_details(candidate_set.set_key) is None
    finally:
        repository.close()


def test_review_group_details_chunks_large_derived_member_sets(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_many_archives(tmp_path, 901)
    try:
        connection = repository._connection  # noqa: SLF001 - compact large-set fixture
        group_id = connection.execute(
            "INSERT INTO candidate_groups(scan_root_id, group_key, strongest_relation, confidence, "
            "analyzer_version, created_at) VALUES (?, 'large-group', 'EXACT_CONTENT', 1.0, 1, ?)",
            (root_id, FIXED_NOW.isoformat()),
        ).lastrowid
        connection.executemany(
            "INSERT INTO candidate_group_members(group_id, archive_id) VALUES (?, ?)",
            ((group_id, archive_id) for archive_id in archive_ids),
        )
        connection.commit()
        candidate_set = ReviewCandidateSet("large-set", "large-group", "FULL_COLOR", archive_ids)
        repository.replace_candidate_sets("large-group", (candidate_set,), computed_at=FIXED_NOW)

        detail = repository.review_group_details(candidate_set.set_key)

        assert detail is not None
        assert len(detail.members) == 901
    finally:
        repository.close()


def test_scan_and_duplicate_operations_are_mutually_exclusive(tmp_path: Path) -> None:
    repository = DuplicateRepository.open(tmp_path / "index.db")
    try:
        repository.acquire_operation_lock("scan", "scan-owner", FIXED_NOW)
        with pytest.raises(ScanAlreadyRunning):
            repository.acquire_operation_lock("duplicate", "duplicate-owner", FIXED_NOW)
    finally:
        repository.release_operation_lock("scan-owner")
        repository.close()


def test_duplicate_repository_reads_indexed_archive_inputs(tmp_path: Path) -> None:
    repository = DuplicateRepository.open(tmp_path / "index.db")
    try:
        connection = repository._connection  # noqa: SLF001 - create V0 index fixture
        root_id = connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(tmp_path), "root-key", FIXED_NOW.isoformat()),
        ).lastrowid
        archive_id = connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
            "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, ?, ?, ?, ?, 'INDEXED', ?, ?, 1)",
            (root_id, str(tmp_path / "book.cbz"), "book-key", 42, 7, "CBZ", FIXED_NOW.isoformat(), FIXED_NOW.isoformat()),
        ).lastrowid
        connection.executemany(
            "INSERT INTO archive_entries(archive_id, position, path, normalized_path, sort_key, "
            "uncompressed_size, compressed_size, crc, entry_kind, image_format_hint) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                (archive_id, 0, "cover.jpg", "cover.jpg", "cover.jpg", 12, 10, "abc", "IMAGE", "JPEG"),
                (archive_id, 1, "notes.txt", "notes.txt", "notes.txt", 4, 4, None, "OTHER", None),
            ),
        )
        connection.commit()

        assert repository.root_id_for_path_key("root-key") == root_id
        assert repository.analysis_inputs(root_id) == (
            ArchiveAnalysisInput(
                archive_id=archive_id,
                path=tmp_path / "book.cbz",
                file_size=42,
                mtime_ns=7,
                archive_format=ArchiveFormat.CBZ,
                images=(ImageEntryRef(0, "cover.jpg", 12, "abc"),),
            ),
        )
    finally:
        repository.close()


def test_precision_profile_cache_requires_same_snapshot_and_version(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 1)
    try:
        repository.store_precision_profile(
            PrecisionProfileRecord(
                archive_id=archive_ids[0],
                file_size=10,
                mtime_ns=7,
                algorithm_version=1,
                state="SUCCEEDED",
                sample_count=1,
                language="ko",
                language_confidence=1.0,
                character_counts={"hangul": 1},
                page_metrics=(),
                error_code=None,
            )
        )

        assert repository.precision_profile_inputs(
            root_id, algorithm_version=1, archive_ids=archive_ids
        ) == ()
        repository._connection.execute(  # noqa: SLF001 - cache invalidation fixture
            "UPDATE archives SET mtime_ns = 201 WHERE id = ?", (archive_ids[0],)
        )
        assert [
            value.archive_id
            for value in repository.precision_profile_inputs(
                root_id, algorithm_version=1, archive_ids=archive_ids
            )
        ] == [archive_ids[0]]
    finally:
        repository.close()


def test_precision_relation_inputs_use_saved_pairs_and_skip_current_cache(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    connection = repository._connection  # noqa: SLF001 - precision relation fixture
    connection.executemany(
        "INSERT INTO archive_entries(archive_id, position, path, normalized_path, sort_key, "
        "entry_kind) VALUES (?, ?, ?, ?, ?, 'IMAGE')",
        (
            (archive_id, position, f"{position}.png", f"{position}.png", f"{position}.png")
            for archive_id in archive_ids
            for position in range(2)
        ),
    )
    connection.execute(
        "INSERT INTO candidate_relations(scan_root_id, archive_a_id, archive_b_id, relation, "
        "confidence, matched_pages, left_pages, right_pages, recommendation, evidence_json, "
        "analyzer_version, created_at) VALUES (?, ?, ?, 'VISUAL_VARIANT', 0.9, 1, 2, 2, '', '[]', 1, ?)",
        (root_id, archive_ids[0], archive_ids[1], FIXED_NOW.isoformat()),
    )
    connection.execute(
        "INSERT INTO sequence_relations(scan_root_id, archive_a_id, archive_b_id, relation, "
        "container_archive_id, matched_pages, left_pages, right_pages, left_coverage, right_coverage, "
        "matched_pairs_json, left_file_size, left_mtime_ns, right_file_size, right_mtime_ns, "
        "algorithm_version, computed_at) VALUES (?, ?, ?, 'PARTIAL_OVERLAP', NULL, 1, 2, 2, "
        "0.5, 0.5, '[[0,1]]', 10, 7, 11, 8, 1, ?)",
        (root_id, archive_ids[0], archive_ids[1], FIXED_NOW.isoformat()),
    )
    connection.commit()
    for archive_id, file_size, mtime_ns in (
        (archive_ids[0], 10, 7),
        (archive_ids[1], 11, 8),
    ):
        assert repository.store_precision_profile(
            PrecisionProfileRecord(
                archive_id=archive_id,
                file_size=file_size,
                mtime_ns=mtime_ns,
                algorithm_version=1,
                state="SUCCEEDED",
                sample_count=1,
                language="UNKNOWN",
                language_confidence=0.0,
                character_counts={},
                page_metrics=(),
                error_code=None,
            ),
            computed_at=FIXED_NOW,
        )
    try:
        relation_pairs = ((archive_ids[0], archive_ids[1]),)
        candidates = repository.precision_relation_inputs(
            root_id, algorithm_version=1, relation_pairs=relation_pairs
        )

        assert len(candidates) == 1
        assert candidates[0].relation is DuplicateRelation.VISUAL_VARIANT
        assert candidates[0].matched_pairs == ((0, 1),)
        assert repository.completed_precision_archive_ids(
            root_id, algorithm_version=1
        ) == archive_ids

        assert repository.store_precision_relation(
            PrecisionRelationRecord(
                archive_a_id=archive_ids[0],
                archive_b_id=archive_ids[1],
                mosaic_direction="UNKNOWN",
                mosaic_confidence=0.0,
                quality_direction="UNKNOWN",
                quality_confidence=0.0,
                evidence=("saved",),
            ),
            algorithm_version=1,
            computed_at=FIXED_NOW,
        )
        assert repository.precision_relation_inputs(
            root_id, algorithm_version=1, relation_pairs=relation_pairs
        ) == ()
    finally:
        repository.close()


def test_precision_scope_uses_only_requested_current_sets(tmp_path: Path) -> None:
    repository, _root_id, archive_ids = _repository_with_archives(tmp_path, 4)
    first = ReviewCandidateSet("set-a", "group-a", "FULL_COLOR", archive_ids[:2])
    second = ReviewCandidateSet("set-b", "group-b", "MONOCHROME", archive_ids[2:])
    try:
        _insert_recommendation_candidate_set(repository, _root_id, first)
        _insert_recommendation_candidate_set(repository, _root_id, second)

        assert repository.precision_scope_for_sets((first.set_key,)) == PrecisionScope(
            (first.set_key,), archive_ids[:2], ((archive_ids[0], archive_ids[1]),)
        )
        assert repository.precision_scope_for_sets(
            (second.set_key, first.set_key, first.set_key)
        ) == PrecisionScope(
            (first.set_key, second.set_key),
            archive_ids,
            ((archive_ids[0], archive_ids[1]), (archive_ids[2], archive_ids[3])),
        )

        repository.replace_candidate_sets(first.source_group_key, (), computed_at=FIXED_NOW)
        with pytest.raises(ValueError, match="candidate set"):
            repository.precision_scope_for_sets((first.set_key,))
        with pytest.raises(ValueError, match="candidate set"):
            repository.precision_scope_for_sets(("missing",))
        with pytest.raises(ValueError, match="candidate set"):
            repository.precision_scope_for_sets(())
    finally:
        repository.close()


def test_precision_relation_scope_excludes_weak_and_unselected_related_edges(
    tmp_path: Path,
) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 3)
    connection = repository._connection  # noqa: SLF001 - scoped relation fixture
    try:
        for archive_id, file_size, mtime_ns in zip(
            archive_ids, (10, 11, 12), (7, 8, 9), strict=True
        ):
            assert repository.store_precision_profile(
                PrecisionProfileRecord(
                    archive_id,
                    file_size,
                    mtime_ns,
                    2,
                    "SUCCEEDED",
                    1,
                    "UNKNOWN",
                    0.0,
                    {},
                    (),
                    None,
                ),
                computed_at=FIXED_NOW,
            )
        connection.executemany(
            "INSERT INTO candidate_relations(scan_root_id, archive_a_id, archive_b_id, relation, "
            "confidence, matched_pages, left_pages, right_pages, recommendation, evidence_json, "
            "analyzer_version, created_at) VALUES (?, ?, ?, 'RELATED', ?, ?, 2, 2, '', '[]', 1, ?)",
            (
                (root_id, archive_ids[0], archive_ids[1], 0.9, 1, FIXED_NOW.isoformat()),
                (root_id, archive_ids[0], archive_ids[2], 0.5, 2, FIXED_NOW.isoformat()),
                (root_id, archive_ids[1], archive_ids[2], 0.8, 2, FIXED_NOW.isoformat()),
            ),
        )
        connection.commit()

        values = repository.precision_relation_inputs(
            root_id,
            algorithm_version=2,
            relation_pairs=(
                (archive_ids[0], archive_ids[1]),
                (archive_ids[0], archive_ids[2]),
            ),
        )

        assert [(item.left.archive_id, item.right.archive_id) for item in values] == [
            (archive_ids[0], archive_ids[2])
        ]
    finally:
        repository.close()


def test_precision_page_cache_round_trip_preserves_all_derived_metrics(
    tmp_path: Path,
) -> None:
    repository = DuplicateRepository.open(tmp_path / "index.db")
    evidence = PageLanguageEvidence(
        character_counts={"KOREAN": 12, "JAPANESE": 1},
        readable_character_count=13,
        korean_sentence_line_count=2,
        korean_dialogue_page=True,
        kana_present=True,
        dominant_script=DetectedLanguage.KOREAN,
        recognizer_scope="BOTH",
    )
    metrics = PageQualityMetrics(
        1.0,
        2.0,
        3.0,
        4.0,
        5.0,
        6.0,
        (0.1, 0.2, 0.3),
        (0.4, 0.5, 0.6),
    )
    record = PrecisionPageRecord(
        "pixel-a", 2, "SUCCEEDED", evidence, 0.91, metrics, None
    )
    try:
        assert repository.cached_precision_pages(("pixel-a",), 2) == {}
        assert repository.store_precision_page(record, computed_at=FIXED_NOW)
        assert repository.cached_precision_pages(("pixel-a", "pixel-a"), 2) == {
            "pixel-a": record
        }
        assert repository.cached_precision_pages(("pixel-a",), 1) == {}
        weaker = PrecisionPageRecord(
            "pixel-a",
            2,
            "SUCCEEDED",
            PageLanguageEvidence(
                character_counts={"KOREAN": 1},
                readable_character_count=1,
                korean_sentence_line_count=0,
                korean_dialogue_page=False,
                kana_present=False,
                dominant_script=DetectedLanguage.UNKNOWN,
                recognizer_scope="KO",
            ),
            0.5,
            metrics,
            None,
        )
        assert not repository.store_precision_page(weaker, computed_at=FIXED_NOW)
        assert repository.cached_precision_pages(("pixel-a",), 2) == {
            "pixel-a": record
        }
        row = repository._connection.execute(  # noqa: SLF001 - no-raw-text boundary
            "SELECT language_evidence_json, metrics_json FROM precision_page_cache"
        ).fetchone()
        assert row is not None and "번역" not in row[0]
        assert json.loads(row[1])["tile_detail"] == [0.4, 0.5, 0.6]
    finally:
        repository.close()


def test_analysis_input_batches_use_two_queries_per_keyset_batch(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 5)
    connection = repository._connection  # noqa: SLF001 - query-count regression evidence
    connection.executemany(
        "INSERT INTO archive_entries(archive_id, position, path, normalized_path, sort_key, "
        "uncompressed_size, compressed_size, crc, entry_kind, image_format_hint) "
        "VALUES (?, 0, '001.jpg', '001.jpg', '001.jpg', 10, 9, NULL, 'IMAGE', 'JPEG')",
        ((archive_id,) for archive_id in archive_ids),
    )
    connection.commit()
    selects: list[str] = []
    connection.set_trace_callback(
        lambda statement: selects.append(statement)
        if statement.lstrip().upper().startswith("SELECT")
        else None
    )
    try:
        batches = tuple(repository.iter_analysis_input_batches(root_id, batch_size=2))
        connection.set_trace_callback(None)

        assert tuple(len(batch) for batch in batches) == (2, 2, 1)
        archive_queries = [
            statement
            for statement in selects
            if "FROM archives WHERE scan_root_id" in statement
        ]
        entry_queries = [
            statement
            for statement in selects
            if "FROM archive_entries WHERE archive_id IN" in statement
        ]
        assert len(archive_queries) == 4  # Three batches plus the terminating keyset query.
        assert len(entry_queries) == 3
    finally:
        connection.set_trace_callback(None)
        repository.close()


def test_duplicate_repository_reports_latest_duplicate_progress(tmp_path: Path) -> None:
    repository = DuplicateRepository.open(tmp_path / "index.db")
    try:
        connection = repository._connection  # noqa: SLF001 - create V1 progress fixture
        root_id = connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(tmp_path), "root-key", FIXED_NOW.isoformat()),
        ).lastrowid
        connection.execute(
            "INSERT INTO duplicate_analysis_runs(scan_root_id, status, stage, started_at, "
            "analyzer_version, archive_total, archive_processed, image_total, image_processed, "
            "failed_count, candidate_count) VALUES (?, 'RUNNING', 'PROBE', ?, 1, 3, 1, 9, 2, 1, 4)",
            (root_id, FIXED_NOW.isoformat()),
        )
        connection.commit()

        assert repository.latest_duplicate_progress() == DuplicateProgress(
            stage=AnalysisStage.PROBE,
            archive_total=3,
            archive_processed=1,
            image_total=9,
            image_processed=2,
            failed_count=1,
            candidate_count=4,
        )
    finally:
        repository.close()


def test_append_review_action_preserves_every_decision(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    try:
        repository.replace_candidate_relations(
            root_id,
            analyzer_version=1,
            matches=(_relation(archive_ids[0], archive_ids[1]),),
            created_at=FIXED_NOW,
        )
        group_key = repository.group_summaries(root_id)[0].group_key
        archive_snapshot = _snapshot(tmp_path / "archive-1.cbz")

        repository.append_review_action(
            group_key, archive_ids[0], ReviewAction.KEEP, archive_snapshot, FIXED_NOW
        )
        repository.append_review_action(
            group_key,
            archive_ids[0],
            ReviewAction.REMOVE_CANDIDATE,
            archive_snapshot,
            FIXED_NOW,
        )

        assert repository._connection.execute(  # noqa: SLF001 - append-only rows assertion
            "SELECT group_key, archive_id, action, file_size, mtime_ns, created_at "
            "FROM review_actions ORDER BY id"
        ).fetchall() == [
            (group_key, archive_ids[0], "KEEP", 10, 7, FIXED_NOW.isoformat()),
            (
                group_key,
                archive_ids[0],
                "REMOVE_CANDIDATE",
                10,
                7,
                FIXED_NOW.isoformat(),
            ),
        ]
    finally:
        repository.close()


def test_connected_candidates_form_group_but_keep_edge_evidence(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 3)
    try:
        repository.replace_candidate_relations(
            root_id,
            analyzer_version=1,
            matches=(_relation(archive_ids[0], archive_ids[1]), _relation(archive_ids[1], archive_ids[2])),
            created_at=FIXED_NOW,
        )

        groups = repository.rebuild_candidate_groups(root_id, 1, FIXED_NOW)

        assert len(groups) == 1
        detail = repository.group_details(groups[0].group_key)
        assert detail is not None
        assert {item.archive_id for item in detail.members} == set(archive_ids)
        assert {(item.archive_a_id, item.archive_b_id) for item in detail.relations} == {
            (archive_ids[0], archive_ids[1]),
            (archive_ids[1], archive_ids[2]),
        }
    finally:
        repository.close()


def test_weak_related_only_graph_preserves_relations_without_groups(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 3)
    try:
        repository.replace_candidate_relations(
            root_id,
            analyzer_version=2,
            matches=(
                _relation(
                    archive_ids[0],
                    archive_ids[1],
                    relation=DuplicateRelation.RELATED,
                    confidence=0.49,
                    matched_pages=2,
                ),
                _relation(
                    archive_ids[1],
                    archive_ids[2],
                    relation=DuplicateRelation.RELATED,
                    confidence=0.9,
                    matched_pages=1,
                ),
            ),
            created_at=FIXED_NOW,
        )

        assert repository.group_summaries(root_id) == ()
        assert repository._connection.execute(  # noqa: SLF001 - persisted evidence assertion
            "SELECT relation, confidence, matched_pages FROM candidate_relations ORDER BY archive_a_id"
        ).fetchall() == [("RELATED", 0.49, 2), ("RELATED", 0.9, 1)]
    finally:
        repository.close()


def test_weak_related_bridge_does_not_merge_strong_groups(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 4)
    try:
        repository.replace_candidate_relations(
            root_id,
            analyzer_version=2,
            matches=(
                _relation(
                    archive_ids[0], archive_ids[1], relation=DuplicateRelation.EXACT_CONTENT
                ),
                _relation(
                    archive_ids[1],
                    archive_ids[2],
                    relation=DuplicateRelation.RELATED,
                    confidence=0.4,
                    matched_pages=3,
                ),
                _relation(
                    archive_ids[2], archive_ids[3], relation=DuplicateRelation.VISUAL_VARIANT
                ),
            ),
            created_at=FIXED_NOW,
        )

        groups = repository.group_summaries(root_id)
        assert len(groups) == 2
        member_sets = set()
        for group in groups:
            detail = repository.group_details(group.group_key)
            assert detail is not None
            member_sets.add(frozenset(member.archive_id for member in detail.members))
        assert member_sets == {
            frozenset((archive_ids[0], archive_ids[1])),
            frozenset((archive_ids[2], archive_ids[3])),
        }
        assert repository._connection.execute(  # noqa: SLF001 - bridge evidence remains persisted
            "SELECT COUNT(*) FROM candidate_relations"
        ).fetchone() == (3,)
    finally:
        repository.close()


def test_qualifying_related_edge_groups_and_exposes_evidence(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    try:
        repository.replace_candidate_relations(
            root_id,
            analyzer_version=2,
            matches=(
                _relation(
                    archive_ids[0],
                    archive_ids[1],
                    relation=DuplicateRelation.RELATED,
                    confidence=0.5,
                    matched_pages=2,
                ),
            ),
            created_at=FIXED_NOW,
        )

        group = repository.group_summaries(root_id)[0]
        detail = repository.group_details(group.group_key)
        assert group.strongest_relation is DuplicateRelation.RELATED
        assert detail is not None
        assert len(detail.relations) == 1
        assert detail.relations[0].relation is DuplicateRelation.RELATED
        assert detail.relations[0].confidence == 0.5
        assert detail.relations[0].matched_pages == 2
        assert detail.relations[0].recommendation == "MANUAL"
    finally:
        repository.close()


@pytest.mark.parametrize(
    "relation",
    (
        DuplicateRelation.EXACT_ARCHIVE,
        DuplicateRelation.EXACT_CONTENT,
        DuplicateRelation.VISUAL_VARIANT,
    ),
)
def test_strong_relations_still_form_groups(
    tmp_path: Path, relation: DuplicateRelation
) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    try:
        repository.replace_candidate_relations(
            root_id,
            analyzer_version=2,
            matches=(_relation(archive_ids[0], archive_ids[1], relation=relation),),
            created_at=FIXED_NOW,
        )

        groups = repository.group_summaries(root_id)
        assert len(groups) == 1
        assert groups[0].strongest_relation is relation
        assert groups[0].member_count == 2
    finally:
        repository.close()


def test_group_details_include_page_count_and_median_resolution_without_member_queries(tmp_path: Path) -> None:
    """Breaks if review display needs one image query per member or picks a non-median page."""
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    try:
        connection = repository._connection  # noqa: SLF001 - persisted fingerprint fixture
        connection.execute("UPDATE archives SET image_count = 3 WHERE id = ?", (archive_ids[0],))
        connection.execute("UPDATE archives SET image_count = 2 WHERE id = ?", (archive_ids[1],))
        connection.executemany(
            "INSERT INTO image_fingerprints(archive_id, entry_position, coverage, byte_sha256, pixel_sha256, "
            "dhash64, ahash64, width, height, state, analyzer_version, computed_at) "
            "VALUES (?, ?, 'FULL', 'byte', 'pixel', '0', '0', ?, ?, 'SUCCEEDED', 3, ?)",
            (
                (archive_ids[0], 0, 100, 100, FIXED_NOW.isoformat()),
                (archive_ids[0], 1, 300, 100, FIXED_NOW.isoformat()),
                (archive_ids[0], 2, 200, 200, FIXED_NOW.isoformat()),
                (archive_ids[1], 0, 80, 100, FIXED_NOW.isoformat()),
                (archive_ids[1], 1, 100, 100, FIXED_NOW.isoformat()),
            ),
        )
        connection.commit()
        repository.replace_candidate_relations(
            root_id,
            analyzer_version=3,
            matches=(_relation(archive_ids[0], archive_ids[1]),),
            created_at=FIXED_NOW,
        )
        group_key = repository.group_summaries(root_id)[0].group_key
        selects: list[str] = []
        connection.set_trace_callback(selects.append)

        detail = repository.group_details(group_key)

        image_queries = [
            statement for statement in selects
            if "FROM image_fingerprints" in statement and statement.lstrip().upper().startswith(("SELECT", "WITH"))
        ]
        assert detail is not None
        by_id = {member.archive_id: member for member in detail.members}
        assert by_id[archive_ids[0]].image_count == 3
        assert (by_id[archive_ids[0]].representative_width, by_id[archive_ids[0]].representative_height) == (300, 100)
        assert (by_id[archive_ids[1]].representative_width, by_id[archive_ids[1]].representative_height) == (80, 100)
        assert len(image_queries) == 1
    finally:
        repository._connection.set_trace_callback(None)  # noqa: SLF001 - restore tracing
        repository.close()


def test_group_uses_strongest_direct_edge_and_preserves_its_recommendation(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 3)
    try:
        repository.replace_candidate_relations(
            root_id,
            analyzer_version=1,
            matches=(
                _relation(
                    archive_ids[0],
                    archive_ids[1],
                    relation=DuplicateRelation.EXACT_CONTENT,
                    recommendation="KEEP_LEFT_HIGHER_RESOLUTION",
                ),
                _relation(
                    archive_ids[1], archive_ids[2], relation=DuplicateRelation.RELATED, confidence=0.5
                ),
            ),
            created_at=FIXED_NOW,
        )

        group = repository.rebuild_candidate_groups(root_id, 1, FIXED_NOW)[0]
        detail = repository.group_details(group.group_key)

        assert group.strongest_relation is DuplicateRelation.EXACT_CONTENT
        assert detail is not None
        assert detail.recommended_archive_id is None
        assert detail.relations[0].recommendation == "KEEP_LEFT_HIGHER_RESOLUTION"
        assert [item.relation for item in detail.relations] == [
            DuplicateRelation.EXACT_CONTENT,
            DuplicateRelation.RELATED,
        ]
    finally:
        repository.close()


def test_group_key_is_stable_across_analyzer_versions(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    try:
        match = _relation(archive_ids[0], archive_ids[1])
        repository.replace_candidate_relations(root_id, analyzer_version=1, matches=(match,), created_at=FIXED_NOW)
        first = repository.rebuild_candidate_groups(root_id, 1, FIXED_NOW)[0]
        repository.replace_candidate_relations(root_id, analyzer_version=2, matches=(match,), created_at=FIXED_NOW)
        second = repository.rebuild_candidate_groups(root_id, 2, FIXED_NOW)[0]

        assert second.group_key == first.group_key
    finally:
        repository.close()


def test_reanalysis_does_not_overwrite_user_action_and_changed_snapshot_is_stale(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    try:
        match = _relation(archive_ids[0], archive_ids[1])
        repository.replace_candidate_relations(root_id, analyzer_version=1, matches=(match,), created_at=FIXED_NOW)
        group = repository.rebuild_candidate_groups(root_id, 1, FIXED_NOW)[0]
        old_snapshot = _snapshot(tmp_path / "archive-1.cbz", size=10, mtime_ns=7)
        repository.append_review_action(group.group_key, archive_ids[0], ReviewAction.KEEP, old_snapshot, FIXED_NOW)

        repository.replace_candidate_relations(root_id, analyzer_version=2, matches=(match,), created_at=FIXED_NOW)
        repository.rebuild_candidate_groups(root_id, 2, FIXED_NOW)

        assert repository.latest_review_state(group.group_key, archive_ids[0]).action is ReviewAction.KEEP
        assert repository.latest_review_state(
            group.group_key, archive_ids[0], current=_snapshot(tmp_path / "archive-1.cbz", size=11, mtime_ns=7)
        ).needs_review
    finally:
        repository.close()


def test_changed_member_set_marks_new_group_needing_review_and_removes_stale_group(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 3)
    try:
        first_match = _relation(archive_ids[0], archive_ids[1])
        repository.replace_candidate_relations(root_id, analyzer_version=1, matches=(first_match,), created_at=FIXED_NOW)
        old_group = repository.rebuild_candidate_groups(root_id, 1, FIXED_NOW)[0]
        repository.append_review_action(
            old_group.group_key, archive_ids[0], ReviewAction.KEEP, _snapshot(tmp_path / "archive-1.cbz"), FIXED_NOW
        )

        repository.replace_candidate_relations(
            root_id,
            analyzer_version=2,
            matches=(_relation(archive_ids[0], archive_ids[1]), _relation(archive_ids[1], archive_ids[2])),
            created_at=FIXED_NOW,
        )
        groups = repository.rebuild_candidate_groups(root_id, 2, FIXED_NOW)

        assert len(groups) == 1
        assert groups[0].group_key != old_group.group_key
        assert groups[0].needs_review
        assert repository.group_details(old_group.group_key) is None
    finally:
        repository.close()


def test_current_group_actions_clear_reanalysis_review_flag_for_every_member(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 3)
    try:
        repository.replace_candidate_relations(
            root_id, analyzer_version=1, matches=(_relation(archive_ids[0], archive_ids[1]),), created_at=FIXED_NOW
        )
        old_group = repository.group_summaries(root_id)[0]
        repository.append_review_action(old_group.group_key, None, ReviewAction.KEEP, None, FIXED_NOW)

        repository.replace_candidate_relations(
            root_id,
            analyzer_version=2,
            matches=(
                _relation(archive_ids[0], archive_ids[1]),
                _relation(archive_ids[1], archive_ids[2]),
            ),
            created_at=FIXED_NOW,
        )
        new_group = repository.group_summaries(root_id)[0]
        assert new_group.needs_review

        repository.append_review_action(new_group.group_key, None, ReviewAction.KEEP, None, FIXED_NOW)
        summary = repository.group_summaries(root_id)[0]
        detail = repository.group_details(new_group.group_key)

        assert not summary.needs_review
        assert detail is not None
        assert not detail.needs_review
    finally:
        repository.close()


def test_partial_or_stale_current_group_review_actions_stay_needing_review(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    try:
        repository.replace_candidate_relations(
            root_id, analyzer_version=1, matches=(_relation(archive_ids[0], archive_ids[1]),), created_at=FIXED_NOW
        )
        group = repository.group_summaries(root_id)[0]
        repository.append_review_action(
            group.group_key, archive_ids[0], ReviewAction.KEEP, _snapshot(tmp_path / "archive-1.cbz"), FIXED_NOW
        )

        assert repository.group_summaries(root_id)[0].needs_review
        repository._connection.execute(  # noqa: SLF001 - stale historical snapshot fixture
            "INSERT INTO review_actions(group_key, archive_id, action, file_size, mtime_ns, created_at) "
            "VALUES (?, ?, 'KEEP', 9, 7, ?)",
            (group.group_key, archive_ids[0], FIXED_NOW.isoformat()),
        )
        repository._connection.commit()

        assert repository.group_summaries(root_id)[0].needs_review
    finally:
        repository.close()


def test_append_member_review_requires_current_group_member_and_snapshot(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    try:
        repository.replace_candidate_relations(
            root_id, analyzer_version=1, matches=(_relation(archive_ids[0], archive_ids[1]),), created_at=FIXED_NOW
        )
        group = repository.group_summaries(root_id)[0]
        other_root = repository._connection.execute(  # noqa: SLF001 - foreign-root fixture
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(tmp_path / "other"), "other-root", FIXED_NOW.isoformat()),
        ).lastrowid
        other_archive = repository._connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, archive_format, "
            "state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, ?, 10, 7, 'CBZ', 'INDEXED', ?, ?, 1)",
            (other_root, str(tmp_path / "other.cbz"), "other-archive", FIXED_NOW.isoformat(), FIXED_NOW.isoformat()),
        ).lastrowid
        repository._connection.commit()

        cases = (
            ("missing group", "missing-group", archive_ids[0], _snapshot(tmp_path / "archive-1.cbz")),
            ("foreign archive", group.group_key, int(other_archive), _snapshot(tmp_path / "other.cbz")),
            ("stale snapshot", group.group_key, archive_ids[0], _snapshot(tmp_path / "archive-1.cbz", size=11)),
            (
                "wrong path",
                group.group_key,
                archive_ids[0],
                _snapshot(tmp_path / "other-name.cbz", path_key="archive-1"),
            ),
            (
                "wrong path key",
                group.group_key,
                archive_ids[0],
                _snapshot(tmp_path / "archive-1.cbz", path_key="other-key"),
            ),
        )
        for _, group_key, archive_id, snapshot in cases:
            with pytest.raises(ValueError):
                repository.append_review_action(group_key, archive_id, ReviewAction.KEEP, snapshot, FIXED_NOW)

        assert repository._connection.execute("SELECT COUNT(*) FROM review_actions").fetchone() == (0,)
    finally:
        repository.close()


def test_bulk_review_rolls_back_when_any_group_member_is_from_another_root(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    try:
        repository.replace_candidate_relations(
            root_id, analyzer_version=1, matches=(_relation(archive_ids[0], archive_ids[1]),), created_at=FIXED_NOW
        )
        group = repository.group_summaries(root_id)[0]
        group_id = repository._connection.execute(  # noqa: SLF001 - malformed legacy-row fixture
            "SELECT id FROM candidate_groups WHERE group_key = ?", (group.group_key,)
        ).fetchone()[0]
        other_root = repository._connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(tmp_path / "other"), "bulk-other-root", FIXED_NOW.isoformat()),
        ).lastrowid
        foreign_archive = repository._connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, archive_format, "
            "state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, ?, 10, 7, 'CBZ', 'INDEXED', ?, ?, 1)",
            (other_root, str(tmp_path / "bulk-other.cbz"), "bulk-other", FIXED_NOW.isoformat(), FIXED_NOW.isoformat()),
        ).lastrowid
        repository._connection.execute(
            "INSERT INTO candidate_group_members(group_id, archive_id) VALUES (?, ?)",
            (group_id, foreign_archive),
        )
        repository._connection.commit()

        with pytest.raises(ValueError, match="current member"):
            repository.append_review_action(group.group_key, None, ReviewAction.KEEP, None, FIXED_NOW)

        assert repository._connection.execute("SELECT COUNT(*) FROM review_actions").fetchone() == (0,)
    finally:
        repository.close()


def test_relation_replacement_validates_large_star_without_sqlite_variable_limit(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_many_archives(tmp_path, 33_000)
    try:
        repository.replace_candidate_relations(
            root_id,
            analyzer_version=1,
            matches=tuple(_relation(archive_ids[0], archive_id) for archive_id in archive_ids[1:]),
            created_at=FIXED_NOW,
        )

        groups = repository.group_summaries(root_id)

        assert len(groups) == 1
        assert groups[0].member_count == 33_000
    finally:
        repository.close()


def test_keep_all_records_one_current_snapshot_per_group_member(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    try:
        repository.replace_candidate_relations(
            root_id, analyzer_version=1, matches=(_relation(archive_ids[0], archive_ids[1]),), created_at=FIXED_NOW
        )
        group = repository.rebuild_candidate_groups(root_id, 1, FIXED_NOW)[0]

        action_ids = repository.append_review_action(group.group_key, None, ReviewAction.KEEP, None, FIXED_NOW)

        assert len(action_ids) == 2
        assert repository._connection.execute(  # noqa: SLF001 - append-only review assertion
            "SELECT archive_id, action, file_size, mtime_ns FROM review_actions ORDER BY id"
        ).fetchall() == [(archive_ids[0], "KEEP", 10, 7), (archive_ids[1], "KEEP", 11, 8)]
    finally:
        repository.close()


def test_hold_all_records_one_hold_per_group_member(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    try:
        repository.replace_candidate_relations(
            root_id, analyzer_version=1, matches=(_relation(archive_ids[0], archive_ids[1]),), created_at=FIXED_NOW
        )
        group = repository.rebuild_candidate_groups(root_id, 1, FIXED_NOW)[0]

        repository.append_review_action(group.group_key, None, ReviewAction.HOLD, None, FIXED_NOW)

        assert [repository.latest_review_state(group.group_key, archive_id).action for archive_id in archive_ids] == [
            ReviewAction.HOLD,
            ReviewAction.HOLD,
        ]
    finally:
        repository.close()


def test_relation_replacement_rolls_back_without_losing_existing_edges(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    try:
        match = _relation(archive_ids[0], archive_ids[1])
        repository.replace_candidate_relations(root_id, analyzer_version=1, matches=(match,), created_at=FIXED_NOW)

        with pytest.raises(ValueError, match="same scan root"):
            repository.replace_candidate_relations(
                root_id, analyzer_version=1, matches=(_relation(archive_ids[0], 99999),), created_at=FIXED_NOW
            )

        assert repository._connection.execute(  # noqa: SLF001 - transaction rollback assertion
            "SELECT archive_a_id, archive_b_id FROM candidate_relations"
        ).fetchall() == [(archive_ids[0], archive_ids[1])]
    finally:
        repository.close()


def test_candidate_writes_lock_before_validation_and_insert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "index.db"
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    statements: list[str] = []
    repository._connection.set_trace_callback(statements.append)  # noqa: SLF001 - transaction boundary assertion
    original_validate = repository._validate_relation_matches  # noqa: SLF001 - transaction boundary assertion
    original_snapshot = repository._current_review_member_snapshot  # noqa: SLF001 - transaction boundary assertion

    def assert_competing_writer_is_locked() -> None:
        competitor = sqlite3.connect(database)
        try:
            competitor.execute("PRAGMA busy_timeout = 0")
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                competitor.execute("BEGIN IMMEDIATE")
        finally:
            competitor.close()

    def validate_under_write_lock(checked_root: int, matches: tuple[CandidateMatch, ...]) -> None:
        assert repository._connection.in_transaction  # noqa: SLF001 - validation must follow BEGIN IMMEDIATE
        assert_competing_writer_is_locked()
        original_validate(checked_root, matches)

    def snapshot_under_write_lock(group_key: str, archive_id: int) -> FileSnapshot:
        assert repository._connection.in_transaction  # noqa: SLF001 - membership validation follows lock
        assert_competing_writer_is_locked()
        return original_snapshot(group_key, archive_id)

    monkeypatch.setattr(repository, "_validate_relation_matches", validate_under_write_lock)
    monkeypatch.setattr(repository, "_current_review_member_snapshot", snapshot_under_write_lock)
    try:
        repository.replace_candidate_relations(
            root_id,
            analyzer_version=1,
            matches=(_relation(archive_ids[0], archive_ids[1]),),
            created_at=FIXED_NOW,
        )
        group = repository.group_summaries(root_id)[0]
        repository.append_review_action(
            group.group_key,
            archive_ids[0],
            ReviewAction.KEEP,
            _snapshot(tmp_path / "archive-1.cbz"),
            FIXED_NOW,
        )
        repository.append_review_action(group.group_key, None, ReviewAction.HOLD, None, FIXED_NOW)

        begin_statements = [statement for statement in statements if statement.startswith("BEGIN")]
        assert begin_statements == ["BEGIN IMMEDIATE", "BEGIN IMMEDIATE", "BEGIN IMMEDIATE"]
    finally:
        repository._connection.set_trace_callback(None)  # noqa: SLF001 - restore tracing
        repository.close()


def test_group_details_uses_one_snapshot_while_group_is_replaced(tmp_path: Path) -> None:
    database = tmp_path / "index.db"
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 3)
    repository.replace_candidate_relations(
        root_id,
        analyzer_version=1,
        matches=(_relation(archive_ids[0], archive_ids[1]),),
        created_at=FIXED_NOW,
    )
    old_group_key = repository.group_summaries(root_id)[0].group_key
    writer_started = Event()
    writer_finished = Event()
    writer_errors: list[BaseException] = []

    def replace_group() -> None:
        writer = DuplicateRepository.open(database)
        writer._connection.set_trace_callback(  # noqa: SLF001 - synchronize at writer lock attempt
            lambda statement: writer_started.set() if statement == "BEGIN IMMEDIATE" else None
        )
        try:
            writer.replace_candidate_relations(
                root_id,
                analyzer_version=2,
                matches=(
                    _relation(archive_ids[0], archive_ids[1]),
                    _relation(archive_ids[1], archive_ids[2]),
                ),
                created_at=FIXED_NOW,
            )
        except BaseException as error:  # pragma: no cover - surfaced in the main test thread
            writer_errors.append(error)
        finally:
            writer.close()
            writer_finished.set()

    writer_thread: Thread | None = None

    def replace_after_group_header(statement: str) -> None:
        nonlocal writer_thread
        if writer_thread is None and statement.startswith("WITH latest_actions AS"):
            writer_thread = Thread(target=replace_group)
            writer_thread.start()
            assert writer_started.wait(timeout=5)
            assert writer_finished.wait(timeout=5)

    repository._connection.set_trace_callback(replace_after_group_header)  # noqa: SLF001 - force mid-read replacement
    try:
        detail = repository.group_details(old_group_key)
    finally:
        repository._connection.set_trace_callback(None)  # noqa: SLF001 - restore tracing
        if writer_thread is not None:
            writer_thread.join(timeout=5)

    try:
        assert writer_errors == []
        assert detail is not None
        assert {member.archive_id for member in detail.members} == set(archive_ids[:2])
        assert {(relation.archive_a_id, relation.archive_b_id) for relation in detail.relations} == {
            (archive_ids[0], archive_ids[1])
        }
        assert {group.member_count for group in repository.group_summaries(root_id)} == {3}
    finally:
        repository.close()


def test_group_review_reads_use_constant_statement_count_for_16k_members(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_many_archives(tmp_path, 16_000)
    try:
        repository.replace_candidate_relations(
            root_id,
            analyzer_version=1,
            matches=tuple(_relation(archive_ids[0], archive_id) for archive_id in archive_ids[1:]),
            created_at=FIXED_NOW,
        )
        group = repository.group_summaries(root_id)[0]
        repository._connection.executemany(  # noqa: SLF001 - seed append-only history efficiently
            "INSERT INTO review_actions(group_key, archive_id, action, file_size, mtime_ns, created_at) "
            "VALUES (?, ?, 'KEEP', 10, 7, ?)",
            ((group.group_key, archive_id, FIXED_NOW.isoformat()) for archive_id in archive_ids),
        )
        repository._connection.commit()  # noqa: SLF001 - finish history fixture
        statements: list[str] = []
        repository._connection.set_trace_callback(statements.append)  # noqa: SLF001 - N+1 regression assertion

        detail = repository.group_details(group.group_key)
        summary = repository.group_summaries(root_id)
        group_id = repository._connection.execute(  # noqa: SLF001 - private-query regression assertion
            "SELECT id FROM candidate_groups WHERE group_key = ?", (group.group_key,)
        ).fetchone()[0]
        repository._group_needs_review(int(group_id), group.group_key)  # noqa: SLF001 - direct regression target

        selects = [statement for statement in statements if statement.lstrip().upper().startswith(("SELECT", "WITH"))]
        assert detail is not None and len(detail.members) == 16_000
        assert summary[0].member_count == 16_000
        assert len(selects) == 7
        assert all("SELECT MAX(ID)" not in statement.upper() for statement in selects)
    finally:
        repository._connection.set_trace_callback(None)  # noqa: SLF001 - restore tracing
        repository.close()


def test_cached_fingerprints_require_matching_snapshot_and_analyzer_version(tmp_path: Path) -> None:
    archive = tmp_path / "book.cbz"
    archive.write_bytes(b"archive")
    repository = DuplicateRepository.open(tmp_path / "index.db")
    try:
        connection = repository._connection  # noqa: SLF001 - create archive fixture
        root_id = connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(tmp_path), "root-key", FIXED_NOW.isoformat()),
        ).lastrowid
        archive_id = connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
            "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, ?, ?, ?, ?, 'INDEXED', ?, ?, 1)",
            (root_id, str(archive), "book-key", archive.stat().st_size, archive.stat().st_mtime_ns,
             "CBZ", FIXED_NOW.isoformat(), FIXED_NOW.isoformat()),
        ).lastrowid
        connection.commit()
        value = ArchiveAnalysisInput(
            archive_id=archive_id,
            path=archive,
            file_size=archive.stat().st_size,
            mtime_ns=archive.stat().st_mtime_ns,
            archive_format=ArchiveFormat.CBZ,
            images=(ImageEntryRef(0, "001.png", None, None),),
        )
        image = fingerprint_image(encoded_gradient("PNG", (10, 10)))

        assert repository.store_probe_fingerprints(
            value,
            analyzer_version=1,
            computed_at=FIXED_NOW,
            sha256="a" * 64,
            hash_state="SUCCEEDED",
            successes=((0, image),),
            failures=(),
        )

        cached = repository.cached_fingerprints(value, analyzer_version=1)
        assert cached is not None
        assert cached.sha256 == "a" * 64
        assert cached.filename_tokens_json == "[]"
        assert cached.language_hints_json == "[]"
        assert [item.entry_position for item in cached.image_fingerprints] == [0]
        assert repository.cached_fingerprints(value, analyzer_version=2) is None
        assert repository.cached_fingerprints(
            ArchiveAnalysisInput(
                archive_id=archive_id, path=archive, file_size=value.file_size + 1,
                mtime_ns=value.mtime_ns, archive_format=value.archive_format, images=value.images
            ),
            analyzer_version=1,
        ) is None
    finally:
        repository.close()


def test_full_promotion_reuses_probe_fingerprint_without_replacing_it(tmp_path: Path) -> None:
    archive = tmp_path / "book.cbz"
    archive.write_bytes(b"archive")
    repository = DuplicateRepository.open(tmp_path / "index.db")
    try:
        connection = repository._connection  # noqa: SLF001 - create archive fixture
        root_id = connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(tmp_path), "root-key", FIXED_NOW.isoformat()),
        ).lastrowid
        archive_id = connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
            "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, ?, ?, ?, ?, 'INDEXED', ?, ?, 1)",
            (root_id, str(archive), "book-key", archive.stat().st_size, archive.stat().st_mtime_ns,
             "CBZ", FIXED_NOW.isoformat(), FIXED_NOW.isoformat()),
        ).lastrowid
        connection.commit()
        value = ArchiveAnalysisInput(
            archive_id=archive_id,
            path=archive,
            file_size=archive.stat().st_size,
            mtime_ns=archive.stat().st_mtime_ns,
            archive_format=ArchiveFormat.CBZ,
            images=(ImageEntryRef(0, "001.png", None, None),),
        )
        fingerprint = fingerprint_image(encoded_gradient("PNG", (10, 10)))
        assert repository.store_probe_fingerprints(
            value,
            analyzer_version=1,
            computed_at=FIXED_NOW,
            sha256=None,
            hash_state="NOT_REQUIRED",
            successes=((0, fingerprint),),
            failures=(),
        )

        assert repository.promote_image_fingerprint(
            value, entry_position=0, analyzer_version=1, computed_at=FIXED_NOW
        )
        assert repository.cached_fingerprints(value, 1).image_fingerprints[0].fingerprint == fingerprint
        assert connection.execute(
            "SELECT coverage FROM image_fingerprints WHERE archive_id = ? AND entry_position = 0",
            (archive_id,),
        ).fetchone() == ("FULL",)
    finally:
        repository.close()


def test_same_snapshot_and_version_resave_preserves_task5_metadata_and_sha(tmp_path: Path) -> None:
    archive = tmp_path / "book.cbz"
    archive.write_bytes(b"archive")
    repository = DuplicateRepository.open(tmp_path / "index.db")
    try:
        connection = repository._connection  # noqa: SLF001 - create archive fixture
        root_id = connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(tmp_path), "root-key", FIXED_NOW.isoformat()),
        ).lastrowid
        archive_id = connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
            "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, ?, ?, ?, ?, 'INDEXED', ?, ?, 1)",
            (root_id, str(archive), "book-key", archive.stat().st_size, archive.stat().st_mtime_ns,
             "CBZ", FIXED_NOW.isoformat(), FIXED_NOW.isoformat()),
        ).lastrowid
        connection.commit()
        value = ArchiveAnalysisInput(
            archive_id=archive_id,
            path=archive,
            file_size=archive.stat().st_size,
            mtime_ns=archive.stat().st_mtime_ns,
            archive_format=ArchiveFormat.CBZ,
            images=(),
        )
        assert repository.store_probe_fingerprints(
            value,
            analyzer_version=1,
            computed_at=FIXED_NOW,
            sha256="f" * 64,
            hash_state="SUCCEEDED",
            successes=(),
            failures=(),
        )

        # Task 5 owns only the supporting filename evidence columns.
        connection.execute(
            "UPDATE archive_fingerprints SET filename_tokens_json = ?, language_hints_json = ? "
            "WHERE archive_id = ?",
            ('["title"]', '["ko"]', archive_id),
        )
        connection.commit()
        assert repository.store_probe_fingerprints(
            value,
            analyzer_version=1,
            computed_at=FIXED_NOW,
            sha256=None,
            hash_state="NOT_REQUIRED",
            successes=(),
            failures=(),
        )
        cached = repository.cached_fingerprints(value, 1)

        assert cached is not None
        assert cached.sha256 == "f" * 64
        assert cached.filename_tokens_json == '["title"]'
        assert cached.language_hints_json == '["ko"]'
        assert connection.execute(
            "SELECT file_size, mtime_ns FROM archive_fingerprints WHERE archive_id = ?",
            (archive_id,),
        ).fetchone() == (value.file_size, value.mtime_ns)
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("sha256", "hash_state", "error_code"),
    (("a" * 64, "SUCCEEDED", None), (None, "FAILED", "HASH_READ_FAILED")),
    ids=("succeeded", "failed"),
)
def test_probe_bulk_does_not_own_existing_archive_hash_result(
    tmp_path: Path,
    sha256: str | None,
    hash_state: str,
    error_code: str | None,
) -> None:
    repository, connection, value = _open_repository_with_probe(tmp_path)
    try:
        assert repository.store_archive_fingerprint(
            value,
            analyzer_version=1,
            computed_at=FIXED_NOW,
            sha256=sha256,
            hash_state=hash_state,
            error_code=error_code,
        )

        assert repository.store_probe_fingerprints(
            value,
            analyzer_version=1,
            computed_at=FIXED_NOW,
            sha256=None,
            hash_state="NOT_REQUIRED",
            successes=(),
            failures=(),
        )

        assert connection.execute(
            "SELECT sha256, hash_state, error_code FROM archive_fingerprints "
            "WHERE archive_id = ?",
            (value.archive_id,),
        ).fetchone() == (sha256, hash_state, error_code)
    finally:
        repository.close()


def test_snapshot_changed_archive_replaces_sha_and_removes_stale_image_rows(tmp_path: Path) -> None:
    archive = tmp_path / "book.cbz"
    archive.write_bytes(b"old archive")
    repository = DuplicateRepository.open(tmp_path / "index.db")
    try:
        connection = repository._connection  # noqa: SLF001 - create archive fixture
        root_id = connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(tmp_path), "root-key", FIXED_NOW.isoformat()),
        ).lastrowid
        archive_id = connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
            "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, ?, ?, ?, ?, 'INDEXED', ?, ?, 1)",
            (root_id, str(archive), "book-key", archive.stat().st_size, archive.stat().st_mtime_ns,
             "CBZ", FIXED_NOW.isoformat(), FIXED_NOW.isoformat()),
        ).lastrowid
        connection.commit()
        old = ArchiveAnalysisInput(
            archive_id=archive_id, path=archive, file_size=archive.stat().st_size,
            mtime_ns=archive.stat().st_mtime_ns, archive_format=ArchiveFormat.CBZ,
            images=(ImageEntryRef(0, "001.png", None, None), ImageEntryRef(1, "002.png", None, None)),
        )
        image = fingerprint_image(encoded_gradient("PNG", (10, 10)))
        assert repository.store_probe_fingerprints(
            old,
            analyzer_version=1,
            computed_at=FIXED_NOW,
            sha256="a" * 64,
            hash_state="SUCCEEDED",
            successes=((0, image), (1, image)),
            failures=(),
        )
        connection.execute(
            "UPDATE archive_fingerprints SET filename_tokens_json = ?, language_hints_json = ? "
            "WHERE archive_id = ?",
            ('["old"]', '["ko"]', archive_id),
        )
        connection.commit()

        archive.write_bytes(b"new archive with a different snapshot")
        new = ArchiveAnalysisInput(
            archive_id=archive_id, path=archive, file_size=archive.stat().st_size,
            mtime_ns=archive.stat().st_mtime_ns, archive_format=ArchiveFormat.CBZ,
            images=(ImageEntryRef(1, "002.png", None, None),),
        )
        assert repository.store_archive_fingerprint(
            new, analyzer_version=2, computed_at=FIXED_NOW, sha256=None, hash_state="NOT_REQUIRED"
        )

        cached = repository.cached_fingerprints(new, analyzer_version=2)
        assert cached is not None
        assert cached.sha256 is None
        assert cached.filename_tokens_json == "[]"
        assert cached.language_hints_json == "[]"
        assert cached.image_fingerprints == ()
        assert connection.execute(
            "SELECT entry_position FROM image_fingerprints WHERE archive_id = ? ORDER BY entry_position",
            (archive_id,),
        ).fetchall() == []
    finally:
        repository.close()


def test_analyzer_version_change_alone_replaces_snapshot_cache(tmp_path: Path) -> None:
    archive = tmp_path / "book.cbz"
    archive.write_bytes(b"archive")
    repository = DuplicateRepository.open(tmp_path / "index.db")
    try:
        connection = repository._connection  # noqa: SLF001 - create archive fixture
        root_id = connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(tmp_path), "root-key", FIXED_NOW.isoformat()),
        ).lastrowid
        archive_id = connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
            "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, ?, ?, ?, ?, 'INDEXED', ?, ?, 1)",
            (root_id, str(archive), "book-key", archive.stat().st_size, archive.stat().st_mtime_ns,
             "CBZ", FIXED_NOW.isoformat(), FIXED_NOW.isoformat()),
        ).lastrowid
        connection.commit()
        value = ArchiveAnalysisInput(
            archive_id=archive_id, path=archive, file_size=archive.stat().st_size,
            mtime_ns=archive.stat().st_mtime_ns, archive_format=ArchiveFormat.CBZ,
            images=(ImageEntryRef(0, "001.png", None, None),),
        )
        image = fingerprint_image(encoded_gradient("PNG", (10, 10)))
        assert repository.store_probe_fingerprints(
            value,
            analyzer_version=1,
            computed_at=FIXED_NOW,
            sha256="a" * 64,
            hash_state="SUCCEEDED",
            successes=((0, image),),
            failures=(),
        )

        assert repository.store_archive_fingerprint(
            value, analyzer_version=2, computed_at=FIXED_NOW, sha256=None, hash_state="NOT_REQUIRED"
        )
        cached = repository.cached_fingerprints(value, analyzer_version=2)
        assert cached is not None
        assert cached.sha256 is None
        assert cached.image_fingerprints == ()
        assert connection.execute(
            "SELECT * FROM image_fingerprints WHERE archive_id = ?", (archive_id,)
        ).fetchall() == []
    finally:
        repository.close()


def test_bulk_probe_storage_rolls_back_every_row_when_image_insert_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "book.cbz"
    archive.write_bytes(b"archive")
    repository = DuplicateRepository.open(tmp_path / "index.db")
    try:
        connection = repository._connection  # noqa: SLF001 - create archive fixture
        root_id = connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(tmp_path), "root-key", FIXED_NOW.isoformat()),
        ).lastrowid
        archive_id = connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
            "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, ?, ?, ?, ?, 'INDEXED', ?, ?, 1)",
            (root_id, str(archive), "book-key", archive.stat().st_size, archive.stat().st_mtime_ns,
             "CBZ", FIXED_NOW.isoformat(), FIXED_NOW.isoformat()),
        ).lastrowid
        connection.commit()
        value = ArchiveAnalysisInput(
            archive_id=archive_id, path=archive, file_size=archive.stat().st_size,
            mtime_ns=archive.stat().st_mtime_ns, archive_format=ArchiveFormat.CBZ,
            images=(ImageEntryRef(0, "001.png", None, None), ImageEntryRef(1, "002.png", None, None)),
        )
        image = fingerprint_image(encoded_gradient("PNG", (10, 10)))
        original = repository._upsert_image_fingerprint  # noqa: SLF001 - inject DB failure
        calls = 0

        def fail_second_image(*args, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal calls
            calls += 1
            if calls == 2:
                raise sqlite3.IntegrityError("forced image insert failure")
            return original(*args, **kwargs)

        monkeypatch.setattr(repository, "_upsert_image_fingerprint", fail_second_image)
        with pytest.raises(sqlite3.IntegrityError, match="forced image insert failure"):
            repository.store_probe_fingerprints(
                value,
                analyzer_version=1,
                computed_at=FIXED_NOW,
                sha256=None,
                hash_state="NOT_REQUIRED",
                successes=((0, image), (1, image)),
                failures=(),
            )

        assert connection.execute("SELECT * FROM archive_fingerprints").fetchall() == []
        assert connection.execute("SELECT * FROM image_fingerprints").fetchall() == []
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("change_snapshot", "change_version", "preserves_existing"),
    ((False, False, True), (True, False, False), (False, True, False), (True, True, False)),
    ids=(
        "same-snapshot-same-version",
        "changed-snapshot-same-version",
        "same-snapshot-changed-version",
        "changed-snapshot-changed-version",
    ),
)
def test_bulk_upsert_preserves_only_identical_snapshot_and_version(
    tmp_path: Path,
    change_snapshot: bool,
    change_version: bool,
    preserves_existing: bool,
) -> None:
    archive = tmp_path / "book.cbz"
    archive.write_bytes(b"archive")
    repository = DuplicateRepository.open(tmp_path / "index.db")
    try:
        connection = repository._connection  # noqa: SLF001 - create archive fixture
        root_id = connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(tmp_path), "root-key", FIXED_NOW.isoformat()),
        ).lastrowid
        archive_id = connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
            "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, ?, ?, ?, ?, 'INDEXED', ?, ?, 1)",
            (root_id, str(archive), "book-key", archive.stat().st_size, archive.stat().st_mtime_ns,
             "CBZ", FIXED_NOW.isoformat(), FIXED_NOW.isoformat()),
        ).lastrowid
        connection.commit()
        old = ArchiveAnalysisInput(
            archive_id=archive_id, path=archive, file_size=archive.stat().st_size,
            mtime_ns=archive.stat().st_mtime_ns, archive_format=ArchiveFormat.CBZ,
            images=(ImageEntryRef(0, "001.png", None, None),),
        )
        image = fingerprint_image(encoded_gradient("PNG", (10, 10)))
        assert repository.store_probe_fingerprints(
            old, analyzer_version=1, computed_at=FIXED_NOW, sha256="a" * 64,
            hash_state="SUCCEEDED", successes=((0, image),), failures=()
        )
        connection.execute(
            "UPDATE archive_fingerprints SET filename_tokens_json = ?, language_hints_json = ? "
            "WHERE archive_id = ?",
            ('["title"]', '["ko"]', archive_id),
        )
        connection.commit()
        if change_snapshot:
            archive.write_bytes(b"archive with a changed snapshot")
        current = ArchiveAnalysisInput(
            archive_id=archive_id, path=archive, file_size=archive.stat().st_size,
            mtime_ns=archive.stat().st_mtime_ns, archive_format=ArchiveFormat.CBZ,
            images=(),
        )
        version = 2 if change_version else 1

        assert repository.store_probe_fingerprints(
            current, analyzer_version=version, computed_at=FIXED_NOW, sha256=None,
            hash_state="NOT_REQUIRED", successes=(), failures=()
        )

        cached = repository.cached_fingerprints(current, version)
        assert cached is not None
        assert cached.sha256 == ("a" * 64 if preserves_existing else None)
        assert cached.filename_tokens_json == ('["title"]' if preserves_existing else "[]")
        assert cached.language_hints_json == ('["ko"]' if preserves_existing else "[]")
        assert cached.hash_state == ("SUCCEEDED" if preserves_existing else "NOT_REQUIRED")
        assert connection.execute(
            "SELECT error_code FROM archive_fingerprints WHERE archive_id = ?",
            (archive_id,),
        ).fetchone() == (None,)
        assert tuple(item.entry_position for item in cached.image_fingerprints) == (
            (0,) if preserves_existing else ()
        )
    finally:
        repository.close()


def test_bulk_storage_removes_orphan_image_rows_before_writing_new_snapshot(tmp_path: Path) -> None:
    archive = tmp_path / "book.cbz"
    archive.write_bytes(b"archive")
    repository = DuplicateRepository.open(tmp_path / "index.db")
    try:
        connection = repository._connection  # noqa: SLF001 - low-level orphan fixture
        root_id = connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(tmp_path), "root-key", FIXED_NOW.isoformat()),
        ).lastrowid
        archive_id = connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
            "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, ?, ?, ?, ?, 'INDEXED', ?, ?, 1)",
            (root_id, str(archive), "book-key", archive.stat().st_size, archive.stat().st_mtime_ns,
             "CBZ", FIXED_NOW.isoformat(), FIXED_NOW.isoformat()),
        ).lastrowid
        connection.execute(
            "INSERT INTO image_fingerprints(archive_id, entry_position, coverage, state, analyzer_version, computed_at) "
            "VALUES (?, 99, 'PROBE', 'FAILED', 1, ?)",
            (archive_id, FIXED_NOW.isoformat()),
        )
        connection.commit()
        value = ArchiveAnalysisInput(
            archive_id=archive_id, path=archive, file_size=archive.stat().st_size,
            mtime_ns=archive.stat().st_mtime_ns, archive_format=ArchiveFormat.CBZ,
            images=(ImageEntryRef(0, "001.png", None, None),),
        )
        image = fingerprint_image(encoded_gradient("PNG", (10, 10)))

        assert repository.store_probe_fingerprints(
            value, analyzer_version=1, computed_at=FIXED_NOW, sha256=None,
            hash_state="NOT_REQUIRED", successes=((0, image),), failures=()
        )

        assert connection.execute(
            "SELECT entry_position FROM image_fingerprints WHERE archive_id = ? ORDER BY entry_position",
            (archive_id,),
        ).fetchall() == [(0,)]
    finally:
        repository.close()


def test_bulk_storage_rolls_back_when_file_changes_before_commit(tmp_path: Path) -> None:
    archive = tmp_path / "book.cbz"
    archive.write_bytes(b"archive")
    repository = DuplicateRepository.open(tmp_path / "index.db")
    try:
        connection = repository._connection  # noqa: SLF001 - create archive fixture
        root_id = connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(tmp_path), "root-key", FIXED_NOW.isoformat()),
        ).lastrowid
        archive_id = connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
            "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, ?, ?, ?, ?, 'INDEXED', ?, ?, 1)",
            (root_id, str(archive), "book-key", archive.stat().st_size, archive.stat().st_mtime_ns,
             "CBZ", FIXED_NOW.isoformat(), FIXED_NOW.isoformat()),
        ).lastrowid
        connection.commit()
        value = ArchiveAnalysisInput(
            archive_id=archive_id, path=archive, file_size=archive.stat().st_size,
            mtime_ns=archive.stat().st_mtime_ns, archive_format=ArchiveFormat.CBZ,
            images=(ImageEntryRef(0, "001.png", None, None),),
        )
        image = fingerprint_image(encoded_gradient("PNG", (10, 10)))
        changed = False

        def change_source(sql: str) -> None:
            nonlocal changed
            if not changed and sql.startswith("INSERT INTO image_fingerprints"):
                changed = True
                archive.write_bytes(b"changed during transaction")

        connection.set_trace_callback(change_source)
        try:
            assert not repository.store_probe_fingerprints(
                value, analyzer_version=1, computed_at=FIXED_NOW, sha256=None,
                hash_state="NOT_REQUIRED", successes=((0, image),), failures=()
            )
        finally:
            connection.set_trace_callback(None)

        assert changed
        assert connection.execute("SELECT * FROM archive_fingerprints").fetchall() == []
        assert connection.execute("SELECT * FROM image_fingerprints").fetchall() == []
    finally:
        repository.close()


def test_cached_fingerprints_rechecks_snapshot_after_related_selects(tmp_path: Path) -> None:
    repository, connection, value = _open_repository_with_probe(tmp_path)
    try:
        changed_after_archive_select = False

        def change_source(sql: str) -> None:
            nonlocal changed_after_archive_select
            if not changed_after_archive_select and sql.startswith(
                "SELECT entry_position, byte_sha256"
            ):
                changed_after_archive_select = True
                value.path.write_bytes(b"changed after archive SELECT")

        connection.set_trace_callback(change_source)
        try:
            assert repository.cached_fingerprints(value, 1) is None
        finally:
            connection.set_trace_callback(None)

        assert changed_after_archive_select
    finally:
        repository.close()


def _open_repository_with_probe(
    tmp_path: Path,
) -> tuple[DuplicateRepository, sqlite3.Connection, ArchiveAnalysisInput]:
    archive = tmp_path / "book.cbz"
    archive.write_bytes(b"archive")
    repository = DuplicateRepository.open(tmp_path / "index.db")
    connection = repository._connection  # noqa: SLF001 - create archive fixture
    root_id = connection.execute(
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
        (str(tmp_path), "root-key", FIXED_NOW.isoformat()),
    ).lastrowid
    archive_id = connection.execute(
        "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
        "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
        "VALUES (?, ?, ?, ?, ?, ?, 'INDEXED', ?, ?, 1)",
        (
            root_id,
            str(archive),
            "book-key",
            archive.stat().st_size,
            archive.stat().st_mtime_ns,
            "CBZ",
            FIXED_NOW.isoformat(),
            FIXED_NOW.isoformat(),
        ),
    ).lastrowid
    connection.commit()
    value = ArchiveAnalysisInput(
        archive_id=archive_id,
        path=archive,
        file_size=archive.stat().st_size,
        mtime_ns=archive.stat().st_mtime_ns,
        archive_format=ArchiveFormat.CBZ,
        images=(ImageEntryRef(0, "001.png", None, None),),
    )
    image = fingerprint_image(encoded_gradient("PNG", (10, 10)))
    assert repository.store_probe_fingerprints(
        value,
        analyzer_version=1,
        computed_at=FIXED_NOW,
        sha256=None,
        hash_state="NOT_REQUIRED",
        successes=((0, image),),
        failures=(),
    )
    return repository, connection, value


def _repository_with_archives(
    tmp_path: Path, count: int
) -> tuple[DuplicateRepository, int, tuple[int, ...]]:
    repository = DuplicateRepository.open(tmp_path / "index.db")
    connection = repository._connection  # noqa: SLF001 - compact group fixtures
    root_id = connection.execute(
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
        (str(tmp_path), "group-root", FIXED_NOW.isoformat()),
    ).lastrowid
    archive_ids = []
    for index in range(count):
        archive_ids.append(
            connection.execute(
                "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
                "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
                "VALUES (?, ?, ?, ?, ?, 'CBZ', 'INDEXED', ?, ?, 1)",
                (
                    root_id,
                    str(tmp_path / f"archive-{index + 1}.cbz"),
                    f"archive-{index + 1}",
                    10 + index,
                    7 + index,
                    FIXED_NOW.isoformat(),
                    FIXED_NOW.isoformat(),
                ),
            ).lastrowid
        )
    connection.commit()
    return repository, int(root_id), tuple(int(item) for item in archive_ids)


def _repository_with_many_archives(
    tmp_path: Path, count: int
) -> tuple[DuplicateRepository, int, tuple[int, ...]]:
    repository = DuplicateRepository.open(tmp_path / "index.db")
    connection = repository._connection  # noqa: SLF001 - variable-limit fixture
    root_id = connection.execute(
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
        (str(tmp_path), "large-root", FIXED_NOW.isoformat()),
    ).lastrowid
    connection.executemany(
        "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, archive_format, "
        "state, first_seen_at, last_seen_at, inspector_version) "
        "VALUES (?, ?, ?, 10, 7, 'CBZ', 'INDEXED', ?, ?, 1)",
        tuple(
            (
                root_id,
                str(tmp_path / f"archive-{index}.cbz"),
                f"large-archive-{index}",
                FIXED_NOW.isoformat(),
                FIXED_NOW.isoformat(),
            )
            for index in range(count)
        ),
    )
    connection.commit()
    archive_ids = tuple(
        int(row[0])
        for row in connection.execute(
            "SELECT id FROM archives WHERE scan_root_id = ? ORDER BY id", (root_id,)
        )
    )
    return repository, int(root_id), archive_ids


def _insert_recommendation_candidate_set(
    repository: DuplicateRepository,
    root_id: int,
    candidate_set: ReviewCandidateSet,
) -> None:
    connection = repository._connection  # noqa: SLF001 - compact derived-record fixture
    group_id = connection.execute(
        "INSERT INTO candidate_groups(scan_root_id, group_key, strongest_relation, confidence, "
        "analyzer_version, created_at) VALUES (?, ?, 'EXACT_CONTENT', 1.0, 1, ?)",
        (root_id, candidate_set.source_group_key, FIXED_NOW.isoformat()),
    ).lastrowid
    connection.executemany(
        "INSERT INTO candidate_group_members(group_id, archive_id) VALUES (?, ?)",
        ((group_id, archive_id) for archive_id in candidate_set.archive_ids),
    )
    connection.commit()
    repository.replace_candidate_sets(
        candidate_set.source_group_key, (candidate_set,), computed_at=FIXED_NOW
    )


def _recommendation(
    candidate_set: ReviewCandidateSet,
    archive_id: int,
    file_size: int,
    mtime_ns: int,
) -> RecommendationRecord:
    return RecommendationRecord(
        item_id=0,
        set_key=candidate_set.set_key,
        source_group_key=candidate_set.source_group_key,
        archive_id=archive_id,
        recommendation="KEEP",
        status="RECOMMENDED",
        criteria={"fixture": "true"},
        reason="fixture",
        file_size=file_size,
        mtime_ns=mtime_ns,
    )


def test_recommendation_item_rejects_archive_outside_candidate_set_without_partial_write(
    tmp_path: Path,
) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    candidate_set = ReviewCandidateSet("set-1", "group-1", "FULL_COLOR", (archive_ids[0],))
    _insert_recommendation_candidate_set(repository, root_id, candidate_set)
    run_id = repository.begin_recommendation_run(root_id, 1, FIXED_NOW)
    try:
        with pytest.raises(ValueError, match="not in the candidate set"):
            repository.replace_recommendation_items(
                run_id,
                candidate_set,
                _recommendation(candidate_set, archive_ids[1], 11, 8),
            )
        assert repository._connection.execute(  # noqa: SLF001 - persistence contract
            "SELECT COUNT(*) FROM recommendation_items WHERE run_id = ?", (run_id,)
        ).fetchone() == (0,)
    finally:
        repository.close()


def test_recommendation_run_completion_allows_readback(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 1)
    candidate_set = ReviewCandidateSet("set-1", "group-1", "FULL_COLOR", archive_ids)
    _insert_recommendation_candidate_set(repository, root_id, candidate_set)
    run_id = repository.begin_recommendation_run(root_id, 1, FIXED_NOW)
    try:
        repository.replace_recommendation_items(
            run_id, candidate_set, _recommendation(candidate_set, archive_ids[0], 10, 7)
        )
        completed_at = FIXED_NOW.replace(minute=1)
        repository.finish_recommendation_run(
            run_id, state="COMPLETED", completed_at=completed_at
        )
        assert repository.latest_recommendations((candidate_set.set_key,))[0].archive_id == archive_ids[0]
        assert repository._connection.execute(  # noqa: SLF001 - persistence contract
            "SELECT state, completed_at, error_code FROM recommendation_runs WHERE id = ?",
            (run_id,),
        ).fetchone() == ("COMPLETED", completed_at.isoformat(), None)
    finally:
        repository.close()


def test_current_generation_rejects_historical_recommendation_read_and_apply(
    tmp_path: Path,
) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 1)
    connection = repository._connection  # noqa: SLF001 - persisted recommendation fixture
    archive_id = archive_ids[0]
    path = tmp_path / "archive-1.cbz"
    path.write_bytes(b"current archive")
    snapshot = path.stat()
    connection.execute(
        "UPDATE archives SET file_size = ?, mtime_ns = ? WHERE id = ?",
        (snapshot.st_size, snapshot.st_mtime_ns, archive_id),
    )
    group_id = connection.execute(
        "INSERT INTO candidate_groups(scan_root_id, group_key, strongest_relation, confidence, "
        "analyzer_version, created_at) VALUES (?, 'group-1', 'EXACT_CONTENT', 1.0, 1, ?)",
        (root_id, FIXED_NOW.isoformat()),
    ).lastrowid
    connection.execute(
        "INSERT INTO candidate_group_members(group_id, archive_id) VALUES (?, ?)",
        (group_id, archive_id),
    )
    connection.commit()
    candidate_set = ReviewCandidateSet("set-1", "group-1", "FULL_COLOR", (archive_id,))
    repository.replace_candidate_sets("group-1", (candidate_set,), computed_at=FIXED_NOW)
    run_id = repository.begin_recommendation_run(root_id, 1, FIXED_NOW)
    repository.replace_recommendation_items(
        run_id,
        candidate_set,
        _recommendation(candidate_set, archive_id, snapshot.st_size, snapshot.st_mtime_ns),
    )
    repository.finish_recommendation_run(run_id, state="COMPLETED", completed_at=FIXED_NOW)
    recommendation = repository.latest_recommendations((candidate_set.set_key,))[0]
    try:
        repository.replace_candidate_sets("group-1", (), computed_at=FIXED_NOW)

        assert repository.latest_recommendations((candidate_set.set_key,)) == ()
        assert repository.apply_recommendation_item(recommendation, FIXED_NOW) == (
            "CHANGED_SNAPSHOT_SKIPPED"
        )
        assert connection.execute("SELECT COUNT(*) FROM review_actions").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM recommendation_applications").fetchone() == (
            0,
        )
    finally:
        repository.close()


def test_recommendation_snapshot_is_checked_inside_apply_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 1)
    connection = repository._connection  # noqa: SLF001 - transaction boundary assertion
    archive_id = archive_ids[0]
    path = tmp_path / "archive-1.cbz"
    path.write_bytes(b"current archive")
    snapshot = path.stat()
    connection.execute(
        "UPDATE archives SET file_size = ?, mtime_ns = ? WHERE id = ?",
        (snapshot.st_size, snapshot.st_mtime_ns, archive_id),
    )
    connection.commit()
    candidate_set = ReviewCandidateSet("set-1", "group-1", "FULL_COLOR", (archive_id,))
    _insert_recommendation_candidate_set(repository, root_id, candidate_set)
    run_id = repository.begin_recommendation_run(root_id, 1, FIXED_NOW)
    repository.replace_recommendation_items(
        run_id,
        candidate_set,
        _recommendation(candidate_set, archive_id, snapshot.st_size, snapshot.st_mtime_ns),
    )
    repository.finish_recommendation_run(run_id, state="COMPLETED", completed_at=FIXED_NOW)
    recommendation = repository.latest_recommendations((candidate_set.set_key,))[0]
    original_snapshot_matches = repository.recommendation_snapshot_matches
    transaction_states: list[bool] = []

    def snapshot_matches(record: RecommendationRecord) -> bool:
        transaction_states.append(connection.in_transaction)
        return original_snapshot_matches(record)

    monkeypatch.setattr(repository, "recommendation_snapshot_matches", snapshot_matches)
    path.write_bytes(b"changed archive snapshot")
    try:
        assert repository.apply_recommendation_item(recommendation, FIXED_NOW) == (
            "CHANGED_SNAPSHOT_SKIPPED"
        )
        assert transaction_states == [True]
        assert connection.execute("SELECT COUNT(*) FROM review_actions").fetchone() == (0,)
    finally:
        repository.close()


def test_recommendation_run_rejects_illegal_transition(tmp_path: Path) -> None:
    repository, root_id, _archive_ids = _repository_with_archives(tmp_path, 1)
    run_id = repository.begin_recommendation_run(root_id, 1, FIXED_NOW)
    try:
        repository.finish_recommendation_run(
            run_id, state="COMPLETED", completed_at=FIXED_NOW
        )
        with pytest.raises(RuntimeError, match="expected state"):
            repository.finish_recommendation_run(
                run_id, state="FAILED", completed_at=FIXED_NOW, error_code="LATE"
            )
        assert repository._connection.execute(  # noqa: SLF001 - persistence contract
            "SELECT state, error_code FROM recommendation_runs WHERE id = ?", (run_id,)
        ).fetchone() == ("COMPLETED", None)
    finally:
        repository.close()


def test_failed_recommendation_run_records_error_and_completion_timestamp(
    tmp_path: Path,
) -> None:
    repository, root_id, _archive_ids = _repository_with_archives(tmp_path, 1)
    run_id = repository.begin_recommendation_run(root_id, 1, FIXED_NOW)
    try:
        failed_at = FIXED_NOW.replace(minute=2)
        repository.finish_recommendation_run(
            run_id,
            state="FAILED",
            completed_at=failed_at,
            error_code="INPUT_UNAVAILABLE",
        )
        assert repository._connection.execute(  # noqa: SLF001 - persistence contract
            "SELECT state, completed_at, error_code FROM recommendation_runs WHERE id = ?",
            (run_id,),
        ).fetchone() == ("FAILED", failed_at.isoformat(), "INPUT_UNAVAILABLE")
    finally:
        repository.close()


def test_recommendation_run_claim_reuses_completed_or_running_and_retries_failed_input(
    tmp_path: Path,
) -> None:
    repository, root_id, _archive_ids = _repository_with_archives(tmp_path, 1)
    try:
        first = repository.claim_recommendation_run(root_id, 1, "same-input", FIXED_NOW)
        second = repository.claim_recommendation_run(root_id, 1, "same-input", FIXED_NOW)

        assert first.created
        assert not second.created
        assert second.run_id == first.run_id
        repository.finish_recommendation_run(
            first.run_id, state="COMPLETED", completed_at=FIXED_NOW
        )
        completed = repository.claim_recommendation_run(root_id, 1, "same-input", FIXED_NOW)

        assert not completed.created
        assert completed.run_id == first.run_id
        assert repository.recommendation_run_count(root_id) == 1

        failed = repository.claim_recommendation_run(root_id, 1, "retry-input", FIXED_NOW)
        repository.finish_recommendation_run(
            failed.run_id,
            state="FAILED",
            completed_at=FIXED_NOW,
            error_code="TEST_FAILURE",
        )
        retry = repository.claim_recommendation_run(root_id, 1, "retry-input", FIXED_NOW)

        assert failed.created and retry.created
        assert retry.run_id != failed.run_id
    finally:
        repository.close()


def _relation(
    archive_a_id: int,
    archive_b_id: int,
    *,
    relation: DuplicateRelation = DuplicateRelation.EXACT_CONTENT,
    confidence: float = 1.0,
    matched_pages: int = 3,
    recommendation: str = "MANUAL",
) -> CandidateMatch:
    return CandidateMatch(
        archive_a_id=archive_a_id,
        archive_b_id=archive_b_id,
        relation=relation,
        confidence=confidence,
        matched_pages=matched_pages,
        left_pages=3,
        right_pages=3,
        reasons=("ALL_PIXEL_SHA256_IN_ORDER",),
        recommendation=recommendation,
    )


def test_preview_image_entry_loads_the_requested_image_page(tmp_path: Path) -> None:
    repository, _root_id, archive_ids = _repository_with_archives(tmp_path, 1)
    archive_id = archive_ids[0]
    connection = repository._connection  # noqa: SLF001 - compact preview fixture
    connection.executemany(
        "INSERT INTO archive_entries("
        "archive_id, position, path, normalized_path, sort_key, entry_kind"
        ") VALUES (?, ?, ?, ?, ?, 'IMAGE')",
        (
            (archive_id, 3, "003.jpg", "003.jpg", "003.jpg"),
            (archive_id, 7, "007.jpg", "007.jpg", "007.jpg"),
        ),
    )
    connection.commit()
    try:
        first = repository.preview_image_entry(archive_id, image_index=0)
        second = repository.preview_image_entry(archive_id, image_index=1)

        assert first is not None and first[0].path == "003.jpg"
        assert second is not None and second[0].path == "007.jpg"
        assert repository.preview_image_entry(archive_id, image_index=2) is None
    finally:
        repository.close()


def test_sequence_result_is_saved_with_source_snapshots(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    left_path = tmp_path / "archive-1.cbz"
    right_path = tmp_path / "archive-2.cbz"
    left_path.write_bytes(b"l" * 10)
    right_path.write_bytes(b"r" * 11)
    left_stat = left_path.stat()
    right_stat = right_path.stat()
    repository._connection.executemany(  # noqa: SLF001 - align source fixtures
        "UPDATE archives SET file_size = ?, mtime_ns = ? WHERE id = ?",
        (
            (left_stat.st_size, left_stat.st_mtime_ns, archive_ids[0]),
            (right_stat.st_size, right_stat.st_mtime_ns, archive_ids[1]),
        ),
    )
    repository._connection.commit()  # noqa: SLF001 - fixture setup
    left = ArchiveAnalysisInput(
        archive_ids[0], left_path, left_stat.st_size, left_stat.st_mtime_ns,
        ArchiveFormat.CBZ, ()
    )
    right = ArchiveAnalysisInput(
        archive_ids[1], right_path, right_stat.st_size, right_stat.st_mtime_ns,
        ArchiveFormat.CBZ, ()
    )
    page = ImageFingerprint("b", "p", "0" * 16, "0" * 16, 100, 200)
    candidate = SequenceAnalysisCandidate(
        root_id=int(root_id),
        analyzer_version=2,
        left=left,
        right=right,
        left_fingerprints=ArchiveFingerprintSet(left.archive_id, None, (page,)),
        right_fingerprints=ArchiveFingerprintSet(right.archive_id, None, (page, page, page)),
    )
    match = SequenceMatch(
        archive_a_id=left.archive_id,
        archive_b_id=right.archive_id,
        relation=SequenceRelation.CONTAINS,
        container_archive_id=right.archive_id,
        matched_pairs=((0, 1),),
        left_pages=1,
        right_pages=3,
        left_coverage=1.0,
        right_coverage=1 / 3,
    )
    try:
        assert repository.store_sequence_result(
            candidate,
            match,
            algorithm_version=1,
            computed_at=FIXED_NOW,
        )
        assert repository._connection.execute(  # noqa: SLF001 - persistence contract
            "SELECT relation, container_archive_id, matched_pairs_json, "
            "left_file_size, right_file_size FROM sequence_relations"
        ).fetchall() == [("CONTAINS", right.archive_id, "[[0,1]]", 10, 11)]
    finally:
        repository.close()


def test_sequence_analysis_skips_weak_related_evidence_edges(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 3)
    connection = repository._connection  # noqa: SLF001 - compact sequence fixture
    for archive_id, path in zip(
        archive_ids,
        (tmp_path / "archive-1.cbz", tmp_path / "archive-2.cbz", tmp_path / "archive-3.cbz"),
        strict=True,
    ):
        path.write_bytes(bytes([archive_id]) * 10)
        stat = path.stat()
        connection.execute(
            "UPDATE archives SET file_size = ?, mtime_ns = ?, image_count = 2 WHERE id = ?",
            (stat.st_size, stat.st_mtime_ns, archive_id),
        )
        connection.execute(
            "INSERT INTO archive_fingerprints(archive_id, file_size, mtime_ns, sha256, "
            "hash_state, filename_tokens_json, language_hints_json, analyzer_version, computed_at) "
            "VALUES (?, ?, ?, NULL, 'NOT_REQUIRED', '[]', '[]', 2, ?)",
            (archive_id, stat.st_size, stat.st_mtime_ns, FIXED_NOW.isoformat()),
        )
        for position in range(2):
            connection.execute(
                "INSERT INTO image_fingerprints(archive_id, entry_position, coverage, "
                "byte_sha256, pixel_sha256, dhash64, ahash64, width, height, state, "
                "analyzer_version, computed_at) "
                "VALUES (?, ?, 'FULL', ?, ?, ?, ?, 100, 200, 'SUCCEEDED', 2, ?)",
                (
                    archive_id,
                    position,
                    f"byte-{archive_id}-{position}",
                    f"pixel-{archive_id}-{position}",
                    f"{archive_id * 10 + position:016x}",
                    f"{archive_id * 10 + position:016x}",
                    FIXED_NOW.isoformat(),
                ),
            )
    for right_id, matched_pages, confidence in (
        (archive_ids[1], 2, 0.5),
        (archive_ids[2], 1, 0.1),
    ):
        connection.execute(
            "INSERT INTO candidate_relations(scan_root_id, archive_a_id, archive_b_id, "
            "relation, confidence, matched_pages, left_pages, right_pages, recommendation, "
            "evidence_json, analyzer_version, created_at) "
            "VALUES (?, ?, ?, 'RELATED', ?, ?, 2, 2, 'MANUAL', '[]', 2, ?)",
            (
                root_id,
                archive_ids[0],
                right_id,
                confidence,
                matched_pages,
                FIXED_NOW.isoformat(),
            ),
        )
    connection.commit()
    try:
        candidates = repository.sequence_analysis_candidates(
            root_id, algorithm_version=1
        )

        assert [
            (item.left.archive_id, item.right.archive_id) for item in candidates
        ] == [(archive_ids[0], archive_ids[1])]
    finally:
        repository.close()


def test_edition_profile_is_saved_with_current_file_snapshot(tmp_path: Path) -> None:
    repository, _root_id, archive_ids = _repository_with_archives(tmp_path, 1)
    path = tmp_path / "archive-1.cbz"
    path.write_bytes(b"archive")
    stat = path.stat()
    repository._connection.execute(  # noqa: SLF001 - align source fixture
        "UPDATE archives SET file_size = ?, mtime_ns = ? WHERE id = ?",
        (stat.st_size, stat.st_mtime_ns, archive_ids[0]),
    )
    repository._connection.commit()  # noqa: SLF001 - fixture setup
    value = ArchiveAnalysisInput(
        archive_ids[0], path, stat.st_size, stat.st_mtime_ns, ArchiveFormat.CBZ, ()
    )
    profile_input = EditionProfileInput(value, frozenset({"ko"}))
    profile = EditionProfile(archive_ids[0], 6, 1.0, 0.8, frozenset({"ko"}))
    try:
        assert repository.store_edition_profile(
            profile_input,
            profile,
            algorithm_version=1,
            computed_at=FIXED_NOW,
        )
        assert repository._connection.execute(  # noqa: SLF001 - persistence contract
            "SELECT sample_count, color_page_ratio, language_hints_json, state "
            "FROM edition_profiles"
        ).fetchall() == [(6, 1.0, '["ko"]', "SUCCEEDED")]
    finally:
        repository.close()


def test_current_edition_relation_is_loaded_with_group_details(tmp_path: Path) -> None:
    repository, root_id, archive_ids = _repository_with_archives(tmp_path, 2)
    try:
        repository.replace_candidate_relations(
            root_id,
            analyzer_version=1,
            matches=(
                _relation(
                    archive_ids[0],
                    archive_ids[1],
                    relation=DuplicateRelation.VISUAL_VARIANT,
                ),
            ),
            created_at=FIXED_NOW,
        )
        candidate = EditionRelationCandidate(
            root_id=root_id,
            archive_a_id=archive_ids[0],
            archive_b_id=archive_ids[1],
            left_file_size=10,
            left_mtime_ns=7,
            right_file_size=11,
            right_mtime_ns=8,
            left_profile=EditionProfile(archive_ids[0], 6, 0.0, 0.0, frozenset()),
            right_profile=EditionProfile(archive_ids[1], 6, 1.0, 1.0, frozenset()),
            evidence=EditionEvidence(
                DuplicateRelation.VISUAL_VARIANT,
                3,
                3,
                3,
                ("PROBE_HASH_NEAR",),
                "MANUAL",
                10,
                11,
            ),
        )
        repository.store_edition_relation(
            candidate,
            EditionComparison(
                (EditionFlag.COLOR_MONO,), True, "컬러판·흑백판 차이"
            ),
            algorithm_version=1,
            computed_at=FIXED_NOW,
        )

        group = repository.group_summaries(root_id)[0]
        detail = repository.group_details(group.group_key)

        assert detail is not None
        assert detail.relations[0].edition_flags == (EditionFlag.COLOR_MONO,)
        assert detail.relations[0].preserve_required
        assert detail.relations[0].edition_summary == "컬러판·흑백판 차이"
    finally:
        repository.close()


def _snapshot(
    path: Path,
    *,
    path_key: str | None = None,
    size: int = 10,
    mtime_ns: int = 7,
) -> FileSnapshot:
    return FileSnapshot(
        path=path,
        path_key=path.stem if path_key is None else path_key,
        size=size,
        mtime_ns=mtime_ns,
        archive_format=ArchiveFormat.CBZ,
    )


def test_promote_rejects_archive_fingerprint_from_wrong_snapshot(tmp_path: Path) -> None:
    repository, connection, old = _open_repository_with_probe(tmp_path)
    try:
        old.path.write_bytes(b"archive new snapshot")
        changed = ArchiveAnalysisInput(
            archive_id=old.archive_id,
            path=old.path,
            file_size=old.path.stat().st_size,
            mtime_ns=old.path.stat().st_mtime_ns,
            archive_format=old.archive_format,
            images=old.images,
        )
        assert not repository.promote_image_fingerprint(
            changed, entry_position=0, analyzer_version=1, computed_at=FIXED_NOW
        )
        assert connection.execute(
            "SELECT coverage FROM image_fingerprints WHERE archive_id = ? AND entry_position = 0",
            (old.archive_id,),
        ).fetchone() == ("PROBE",)
    finally:
        repository.close()


def test_promote_rejects_archive_fingerprint_from_wrong_analyzer_version(tmp_path: Path) -> None:
    repository, connection, value = _open_repository_with_probe(tmp_path)
    try:
        connection.execute(
            "INSERT INTO image_fingerprints("
            "archive_id, entry_position, coverage, byte_sha256, pixel_sha256, dhash64, ahash64, "
            "width, height, state, error_code, analyzer_version, computed_at"
            ") SELECT archive_id, entry_position, coverage, byte_sha256, pixel_sha256, dhash64, "
            "ahash64, width, height, state, error_code, 2, computed_at "
            "FROM image_fingerprints WHERE archive_id = ? AND entry_position = 0 "
            "AND analyzer_version = 1",
            (value.archive_id,),
        )
        connection.commit()

        assert not repository.promote_image_fingerprint(
            value, entry_position=0, analyzer_version=2, computed_at=FIXED_NOW
        )
        assert connection.execute(
            "SELECT coverage FROM image_fingerprints WHERE archive_id = ? "
            "AND entry_position = 0 AND analyzer_version = 2",
            (value.archive_id,),
        ).fetchone() == ("PROBE",)
    finally:
        repository.close()


def test_promote_rolls_back_when_file_changes_before_commit(tmp_path: Path) -> None:
    repository, connection, value = _open_repository_with_probe(tmp_path)
    try:
        changed_during_update = False

        def change_source(sql: str) -> None:
            nonlocal changed_during_update
            if not changed_during_update and sql.startswith("UPDATE image_fingerprints"):
                changed_during_update = True
                value.path.write_bytes(b"changed while promoting")

        connection.set_trace_callback(change_source)
        try:
            assert not repository.promote_image_fingerprint(
                value, entry_position=0, analyzer_version=1, computed_at=FIXED_NOW
            )
        finally:
            connection.set_trace_callback(None)

        assert changed_during_update
        assert connection.execute(
            "SELECT coverage FROM image_fingerprints WHERE archive_id = ? AND entry_position = 0",
            (value.archive_id,),
        ).fetchone() == ("PROBE",)
    finally:
        repository.close()


def test_promote_compensates_when_file_changes_during_commit(tmp_path: Path) -> None:
    repository, connection, value = _open_repository_with_probe(tmp_path)
    try:
        changed_during_commit = False

        def change_source(sql: str) -> None:
            nonlocal changed_during_commit
            if not changed_during_commit and sql == "COMMIT":
                changed_during_commit = True
                value.path.write_bytes(b"changed during commit")

        connection.set_trace_callback(change_source)
        try:
            assert not repository.promote_image_fingerprint(
                value, entry_position=0, analyzer_version=1, computed_at=FIXED_NOW
            )
        finally:
            connection.set_trace_callback(None)

        assert changed_during_commit
        assert connection.execute(
            "SELECT coverage FROM image_fingerprints WHERE archive_id = ? AND entry_position = 0",
            (value.archive_id,),
        ).fetchone() == ("PROBE",)
        assert repository.cached_fingerprints(value, 1) is None
    finally:
        repository.close()


def test_filename_evidence_update_preserves_matching_snapshot_hash_and_image_cache(
    tmp_path: Path,
) -> None:
    repository, connection, value = _open_repository_with_probe(tmp_path)
    try:
        connection.execute(
            "UPDATE archive_fingerprints SET sha256 = ?, hash_state = 'SUCCEEDED' WHERE archive_id = ?",
            ("a" * 64, value.archive_id),
        )
        connection.commit()

        assert repository.store_filename_evidence(
            value,
            analyzer_version=1,
            filename_tokens=frozenset({"title", "author"}),
            language_hints=frozenset({"ko"}),
        )

        cached = repository.cached_fingerprints(value, 1)
        assert cached is not None
        assert cached.sha256 == "a" * 64
        assert cached.hash_state == "SUCCEEDED"
        assert cached.filename_tokens_json == '["author","title"]'
        assert cached.language_hints_json == '["ko"]'
        assert tuple(item.entry_position for item in cached.image_fingerprints) == (0,)

        value.path.write_bytes(b"changed snapshot")
        assert not repository.store_filename_evidence(
            value,
            analyzer_version=1,
            filename_tokens=frozenset({"new"}),
            language_hints=frozenset(),
        )
    finally:
        repository.close()


def test_filename_evidence_update_compensates_when_source_changes_during_commit(
    tmp_path: Path,
) -> None:
    repository, connection, value = _open_repository_with_probe(tmp_path)
    changed_during_commit = False

    def change_source(sql: str) -> None:
        nonlocal changed_during_commit
        if not changed_during_commit and sql == "COMMIT":
            changed_during_commit = True
            value.path.write_bytes(b"changed during commit")

    try:
        connection.set_trace_callback(change_source)
        try:
            assert not repository.store_filename_evidence(
                value,
                analyzer_version=1,
                filename_tokens=frozenset({"new"}),
                language_hints=frozenset({"ko"}),
            )
        finally:
            connection.set_trace_callback(None)

        assert changed_during_commit
        assert connection.execute(
            "SELECT filename_tokens_json, language_hints_json FROM archive_fingerprints "
            "WHERE archive_id = ?",
            (value.archive_id,),
        ).fetchone() == ("[]", "[]")
        root_id = connection.execute(
            "SELECT scan_root_id FROM archives WHERE id = ?", (value.archive_id,)
        ).fetchone()[0]
        assert repository.load_candidate_evidence(int(root_id), analyzer_version=1) == ()
    finally:
        repository.close()


def test_candidate_evidence_loader_returns_only_current_root_version_cache(tmp_path: Path) -> None:
    repository, connection, value = _open_repository_with_probe(tmp_path)
    try:
        root_id = connection.execute(
            "SELECT scan_root_id FROM archives WHERE id = ?", (value.archive_id,)
        ).fetchone()[0]
        connection.execute(
            "INSERT INTO archive_entries("
            "archive_id, position, path, normalized_path, sort_key, entry_kind"
            ") VALUES (?, 0, '001.png', '001.png', '001.png', 'IMAGE')",
            (value.archive_id,),
        )
        connection.commit()
        assert repository.store_filename_evidence(
            value,
            analyzer_version=1,
            filename_tokens=frozenset({"title"}),
            language_hints=frozenset({"ko"}),
        )

        evidence = repository.load_candidate_evidence(int(root_id), analyzer_version=1)

        assert len(evidence) == 1
        loaded = evidence[0]
        assert loaded.archive_id == value.archive_id
        assert loaded.scan_root_id == root_id
        assert loaded.file_size == value.file_size
        assert loaded.mtime_ns == value.mtime_ns
        assert loaded.analyzer_version == 1
        assert loaded.filename_tokens == frozenset({"title"})
        assert tuple(probe.slot for probe in loaded.probes) == (0,)
        assert loaded.probes[0].entry_position == 0
        assert repository.load_candidate_evidence(int(root_id), analyzer_version=2) == ()

        value.path.write_bytes(b"stale")
        assert repository.load_candidate_evidence(int(root_id), analyzer_version=1) == ()
    finally:
        repository.close()


@pytest.mark.parametrize("mutation", ("file", "root", "version"))
def test_candidate_evidence_loader_final_pass_excludes_first_row_changed_during_second_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    repository, connection, first = _open_repository_with_probe(tmp_path)
    try:
        root_id = connection.execute(
            "SELECT scan_root_id FROM archives WHERE id = ?", (first.archive_id,)
        ).fetchone()[0]
        second_path = tmp_path / "second.cbz"
        second_path.write_bytes(b"second archive")
        second_id = connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, "
            "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
            "VALUES (?, ?, ?, ?, ?, 'CBZ', 'INDEXED', ?, ?, 1)",
            (
                root_id,
                str(second_path),
                "second-key",
                second_path.stat().st_size,
                second_path.stat().st_mtime_ns,
                FIXED_NOW.isoformat(),
                FIXED_NOW.isoformat(),
            ),
        ).lastrowid
        connection.commit()
        second = ArchiveAnalysisInput(
            archive_id=second_id,
            path=second_path,
            file_size=second_path.stat().st_size,
            mtime_ns=second_path.stat().st_mtime_ns,
            archive_format=ArchiveFormat.CBZ,
            images=(),
        )
        assert repository.store_probe_fingerprints(
            second,
            analyzer_version=1,
            computed_at=FIXED_NOW,
            sha256=None,
            hash_state="NOT_REQUIRED",
            successes=(),
            failures=(),
        )
        original = repository._candidate_database_identity_matches  # noqa: SLF001 - final-pass race
        calls = 0

        def mutate_while_checking_second(
            value: ArchiveAnalysisInput, checked_root_id: int, analyzer_version: int
        ):
            nonlocal calls
            calls += 1
            if value.archive_id == second_id:
                if mutation == "file":
                    first.path.write_bytes(b"first changed during second row")
                elif mutation == "root":
                    other_root = connection.execute(
                        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
                        (str(tmp_path / "other"), "other-root", FIXED_NOW.isoformat()),
                    ).lastrowid
                    connection.execute(
                        "UPDATE archives SET scan_root_id = ? WHERE id = ?",
                        (other_root, first.archive_id),
                    )
                    connection.commit()
                else:
                    connection.execute(
                        "UPDATE archive_fingerprints SET analyzer_version = 2 WHERE archive_id = ?",
                        (first.archive_id,),
                    )
                    connection.commit()
            return original(value, checked_root_id, analyzer_version)

        monkeypatch.setattr(
            repository, "_candidate_database_identity_matches", mutate_while_checking_second
        )
        loaded = repository.load_candidate_evidence(int(root_id), analyzer_version=1)

        assert calls == 2
        assert tuple(item.archive_id for item in loaded) == (second_id,)
    finally:
        repository.close()
