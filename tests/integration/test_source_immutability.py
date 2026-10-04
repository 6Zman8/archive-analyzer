from __future__ import annotations

import hashlib
from threading import Event
import zipfile
from pathlib import Path

import pytest

from archive_analyzer.cli import main
from archive_analyzer.desktop import run_analysis
from archive_analyzer.duplicate_domain import DuplicateRelation
from archive_analyzer.inspection import DispatchingImageReader, InspectionResult, ZipBackend
from archive_analyzer.jobs import ScanService
from archive_analyzer.paths import normalize_path_key
from archive_analyzer.precision_service import analyze_precision
from archive_analyzer.recommendation_service import refresh_recommendations
from archive_analyzer.storage.duplicate_repository import DuplicateRepository
from archive_analyzer.storage.repository import Repository
from tests.v1_fixture import SEVEN_ZIP, create_v1_archive_fixture


def tree_fingerprint(root: Path) -> dict[str, tuple[str, int, int]]:
    result: dict[str, tuple[str, int, int]] = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        value = path.stat()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        result[str(path.relative_to(root))] = (digest, value.st_size, value.st_mtime_ns)
    return result


def _write_zip(path: Path, name: str) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(name, b"image")


def test_cli_scan_leaves_every_source_file_unchanged(tmp_path: Path) -> None:
    root = tmp_path / "읽기 전용 표본"
    root.mkdir()
    _write_zip(root / "한글.zip", "001.jpg")
    _write_zip(root / "日本語.cbz", "一.webp")
    before = tree_fingerprint(root)

    database = tmp_path / "index.db"
    assert main(["scan", str(root), "--db", str(database), "--workers", "2"]) == 0
    assert main(["scan", str(root), "--db", str(database), "--workers", "2"]) == 0

    assert tree_fingerprint(root) == before


def test_v1_analysis_finds_two_candidate_groups_and_preserves_all_archives(
    tmp_path: Path,
) -> None:
    root = create_v1_archive_fixture(tmp_path)
    before = tree_fingerprint(root)

    result = run_analysis(
        root,
        data_root=tmp_path / "한국어 V1 데이터",
        seven_zip=SEVEN_ZIP,
        workers=2,
    )

    assert result.scan_summary.discovered_count == 6
    assert result.scan_summary.failed_count == 0
    assert result.duplicate_summary.failed_archives == 0
    assert result.candidate_group_count == 2
    repository = DuplicateRepository.open_readonly(result.database)
    try:
        relation_counts = {
            DuplicateRelation(row[0]): int(row[1])
            for row in repository._connection.execute(  # noqa: SLF001 - release evidence
                "SELECT relation, COUNT(*) FROM candidate_relations GROUP BY relation"
            )
        }
    finally:
        repository.close()
    assert relation_counts.get(DuplicateRelation.EXACT_CONTENT, 0) >= 1
    assert relation_counts.get(DuplicateRelation.VISUAL_VARIANT, 0) >= 1
    assert tree_fingerprint(root) == before


def test_precision_review_keeps_source_archives_unchanged(tmp_path: Path) -> None:
    root = create_v1_archive_fixture(tmp_path)
    before = tree_fingerprint(root)
    result = run_analysis(
        root,
        data_root=tmp_path / "정밀분석 데이터",
        seven_zip=SEVEN_ZIP,
        workers=1,
    )

    class FixedOcr:
        def recognize(self, _payload: bytes, *, language_hints=frozenset()):  # type: ignore[no-untyped-def]
            return "테스트 대사", 0.95

    repository = DuplicateRepository.open(result.database)
    try:
        root_id = repository.root_id_for_path_key(normalize_path_key(root))
        assert root_id is not None
        refresh_recommendations(repository, root_id)
        selected = None
        for candidate in repository.review_candidate_sets(root_id):
            if len(candidate.archive_ids) < 2:
                continue
            detail = repository.review_group_details(candidate.set_key)
            if detail is None or not all(
                member.image_count is not None and member.image_count >= 2
                for member in detail.members
            ):
                continue
            if any(
                relation.relation is DuplicateRelation.EXACT_CONTENT
                for relation in detail.relations
            ):
                selected = candidate
                break
        assert selected is not None
        precision = analyze_precision(
            repository,
            root_id,
            Event(),
            set_keys=(selected.set_key,),
            reader=DispatchingImageReader(SEVEN_ZIP),
            ocr=FixedOcr(),
        )
        assert precision.profiles_processed == 2
    finally:
        repository.close()

    assert tree_fingerprint(root) == before


def test_interrupted_work_is_resumed_and_completed_on_the_next_run(tmp_path: Path) -> None:
    root = tmp_path / "resume-source"
    root.mkdir()
    _write_zip(root / "one.zip", "001.jpg")
    _write_zip(root / "two.zip", "002.jpg")
    _write_zip(root / "three.zip", "003.jpg")
    database = tmp_path / "resume.db"
    repository = Repository.open(database)

    class InterruptAfterWorkBegins:
        def __init__(self) -> None:
            self.calls = 0
            self.backend = ZipBackend()

        def inspect(self, snapshot) -> InspectionResult:
            self.calls += 1
            if self.calls == 2:
                raise KeyboardInterrupt
            return self.backend.inspect(snapshot)

    interrupter = InterruptAfterWorkBegins()
    try:
        with pytest.raises(KeyboardInterrupt):
            ScanService(repository, interrupter, workers=1).run(root)

        interrupted = repository.latest_summary()
        assert interrupted is not None
        assert interrupted.discovery_complete is False
        assert interrupter.calls == 2
        assert repository._connection.execute(  # noqa: SLF001 - integration evidence
            "SELECT status FROM scan_runs WHERE id = ?", (interrupted.run_id,)
        ).fetchone() == ("INTERRUPTED",)

        resumed = ScanService(repository, ZipBackend(), workers=1).run(root)

        assert resumed.discovered_count == 3
        assert resumed.indexed_count == 2
        assert resumed.reused_count == 1
        assert resumed.failed_count == 0
        assert repository._connection.execute(  # noqa: SLF001 - integration evidence
            "SELECT COUNT(*) FROM analysis_jobs WHERE status IN ('PENDING', 'RUNNING')"
        ).fetchone() == (0,)
        assert repository._connection.execute(  # noqa: SLF001 - integration evidence
            "SELECT COUNT(*) FROM archives WHERE state = 'INDEXED'"
        ).fetchone() == (3,)
    finally:
        repository.close()
