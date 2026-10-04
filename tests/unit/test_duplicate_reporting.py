import csv
from datetime import UTC, datetime
from pathlib import Path

import pytest

from archive_analyzer.domain import ArchiveFormat
from archive_analyzer.duplicate_domain import DuplicateRelation
from archive_analyzer.duplicate_reporting import write_candidate_csv
from archive_analyzer.matching import CandidateMatch
from archive_analyzer.storage.duplicate_repository import DuplicateRepository


NOW = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)


def test_candidate_csv_contains_requested_root_candidates_only(tmp_path: Path) -> None:
    """Breaks if export includes another root or anything outside a candidate group."""
    repository, root_id, candidate_ids, foreign_id = _candidate_repository(tmp_path)
    output = tmp_path / "중복 후보.csv"
    try:
        write_candidate_csv(repository, output, root_id=root_id)
    finally:
        repository.close()

    assert output.read_bytes().startswith(b"\xef\xbb\xbf")
    with output.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert {row["group_key"] for row in rows} == {"candidate-group"}
    assert {int(row["archive_id"]) for row in rows} == set(candidate_ids)
    assert str(foreign_id) not in {row["archive_id"] for row in rows}
    assert [row["path"] for row in rows] == sorted(row["path"] for row in rows)


def test_candidate_csv_write_failure_preserves_existing_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Breaks if a partial export replaces the user's previous CSV."""
    repository, root_id, _, _ = _candidate_repository(tmp_path)
    output = tmp_path / "중복 후보.csv"
    output.write_text("previous export", encoding="utf-8")

    def fail_writerows(self, rows) -> None:
        raise OSError("simulated CSV failure")

    monkeypatch.setattr(csv.DictWriter, "writerows", fail_writerows)
    try:
        with pytest.raises(OSError, match="simulated CSV failure"):
            write_candidate_csv(repository, output, root_id=root_id)
    finally:
        repository.close()

    assert output.read_text(encoding="utf-8") == "previous export"
    assert list(tmp_path.glob("*.tmp")) == []


def test_candidate_csv_skips_disappeared_group_and_writes_header_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Breaks if a replaced group aborts export or leaves stale member rows."""
    repository = DuplicateRepository.open(tmp_path / "index.db")
    output = tmp_path / "empty.csv"
    monkeypatch.setattr(repository, "group_summaries", lambda root_id: ())
    try:
        write_candidate_csv(repository, output, root_id=123)
    finally:
        repository.close()

    with output.open("r", encoding="utf-8-sig", newline="") as stream:
        assert list(csv.DictReader(stream)) == []


def test_candidate_csv_lists_only_each_members_actual_direct_edges(tmp_path: Path) -> None:
    """Breaks if C is exported as directly content-identical to unconnected A."""
    repository, root_id, candidate_ids, _ = _candidate_repository(tmp_path)
    connection = repository._connection  # noqa: SLF001 - extend persisted group fixture
    third_id = _insert_archive(connection, root_id, tmp_path / "root" / "C.cbz", "c")
    connection.commit()
    repository.replace_candidate_relations(
        root_id,
        analyzer_version=1,
        matches=(
            CandidateMatch(
                candidate_ids[0],
                candidate_ids[1],
                DuplicateRelation.EXACT_CONTENT,
                1.0,
                2,
                2,
                2,
                ("ALL_PIXEL_SHA256_IN_ORDER",),
                "MANUAL",
            ),
            CandidateMatch(
                candidate_ids[1],
                third_id,
                DuplicateRelation.RELATED,
                0.5,
                2,
                2,
                2,
                ("PROBE_HASH_NEAR",),
                "MANUAL",
            ),
        ),
        created_at=NOW,
    )
    output = tmp_path / "mixed.csv"
    try:
        write_candidate_csv(repository, output, root_id=root_id)
    finally:
        repository.close()

    with output.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = {int(row["archive_id"]): row for row in csv.DictReader(stream)}
    assert rows[candidate_ids[0]]["direct_edges"] == "B.cbz (2): 내용 동일"
    assert rows[third_id]["direct_edges"] == "B.cbz (2): 확인 필요"
    assert "A.cbz" not in rows[third_id]["direct_edges"]
    assert rows[third_id]["relation"] == "후보 그룹 (그룹 내 최강 직접 비교: 내용 동일)"


def _candidate_repository(tmp_path: Path) -> tuple[DuplicateRepository, int, tuple[int, int], int]:
    repository = DuplicateRepository.open(tmp_path / "index.db")
    connection = repository._connection  # noqa: SLF001 - compact persisted candidate fixture
    root_id = _insert_root(connection, tmp_path / "root", "root")
    other_root_id = _insert_root(connection, tmp_path / "other", "other")
    candidate_ids = (
        _insert_archive(connection, root_id, tmp_path / "root" / "A.cbz", "a"),
        _insert_archive(connection, root_id, tmp_path / "root" / "B.cbz", "b"),
    )
    foreign_id = _insert_archive(connection, other_root_id, tmp_path / "other" / "foreign.cbz", "foreign")
    connection.commit()
    group_id = connection.execute(
        "INSERT INTO candidate_groups(scan_root_id, group_key, strongest_relation, confidence, analyzer_version, created_at) "
        "VALUES (?, 'candidate-group', 'EXACT_CONTENT', 1.0, 1, ?)",
        (root_id, NOW.isoformat()),
    ).lastrowid
    connection.executemany(
        "INSERT INTO candidate_group_members(group_id, archive_id) VALUES (?, ?)",
        ((group_id, archive_id) for archive_id in candidate_ids),
    )
    connection.execute(
        "INSERT INTO candidate_relations(scan_root_id, archive_a_id, archive_b_id, relation, confidence, matched_pages, "
        "left_pages, right_pages, recommendation, evidence_json, analyzer_version, created_at) "
        "VALUES (?, ?, ?, 'EXACT_CONTENT', 1.0, 2, 2, 2, 'MANUAL', '[\"ALL_PIXEL_SHA256_IN_ORDER\"]', 1, ?)",
        (root_id, *candidate_ids, NOW.isoformat()),
    )
    connection.commit()
    return repository, root_id, candidate_ids, foreign_id


def _insert_root(connection, path: Path, key: str) -> int:
    return int(
        connection.execute(
            "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
            (str(path), key, NOW.isoformat()),
        ).lastrowid
    )


def _insert_archive(connection, root_id: int, path: Path, key: str) -> int:
    return int(
        connection.execute(
            "INSERT INTO archives(scan_root_id, path, path_key, file_size, mtime_ns, archive_format, state, "
            "first_seen_at, last_seen_at, inspector_version, image_count) "
            "VALUES (?, ?, ?, 10, 7, 'CBZ', 'INDEXED', ?, ?, 1, 2)",
            (root_id, str(path), key, NOW.isoformat(), NOW.isoformat()),
        ).lastrowid
    )
