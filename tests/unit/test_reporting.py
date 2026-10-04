import csv
import json
from pathlib import Path

import pytest

import archive_analyzer.reporting as reporting_module
from archive_analyzer.domain import ArchiveFormat, DiscoveryEvent
from archive_analyzer.inspection import InspectionFailure, InspectionResult
from archive_analyzer.jobs import ScanService
from archive_analyzer.reporting import write_report
from archive_analyzer.storage.repository import Repository
from tests.helpers import snapshot


class _Inspector:
    def inspect(self, file_snapshot) -> InspectionResult:
        if file_snapshot.path.name == "broken.zip":
            raise InspectionFailure("CORRUPT_ARCHIVE", "Archive is corrupt.")
        return InspectionResult(file_snapshot.archive_format, (), 0, 0, "listing")


def _indexed_repository(tmp_path: Path) -> Repository:
    root = tmp_path / "source"
    root.mkdir()
    first = root / "Z.zip"
    second = root / "broken.zip"
    first.write_bytes(b"ok")
    second.write_bytes(b"bad")
    repository = Repository.open(tmp_path / "index.db")
    ScanService(
        repository,
        _Inspector(),
        discoverer=lambda _: [
            DiscoveryEvent(snapshot=snapshot(first, ArchiveFormat.ZIP)),
            DiscoveryEvent(snapshot=snapshot(second, ArchiveFormat.ZIP)),
        ],
        workers=1,
    ).run(root)
    return repository


def test_json_report_uses_path_key_order_and_excludes_diagnostic_details(tmp_path: Path) -> None:
    repository = _indexed_repository(tmp_path)
    output = tmp_path / "report.json"
    try:
        write_report(repository, output, "json")
    finally:
        repository.close()

    payload = json.loads(output.read_text(encoding="utf-8"))

    assert payload["summary"] == {
        "total": 2,
        "indexed": 1,
        "failed": 1,
        "skipped": 0,
        "missing": 0,
        "pending": 0,
    }
    assert [Path(item["path"]).name for item in payload["archives"]] == [
        "broken.zip",
        "Z.zip",
    ]
    assert payload["archives"][0]["error_code"] == "CORRUPT_ARCHIVE"
    assert "detail" not in payload["archives"][0]


def test_csv_report_is_utf8_bom_and_has_the_same_rows(tmp_path: Path) -> None:
    repository = _indexed_repository(tmp_path)
    output = tmp_path / "report.csv"
    try:
        write_report(repository, output, "csv")
    finally:
        repository.close()

    assert output.read_bytes().startswith(b"\xef\xbb\xbf")
    with output.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert [row["path"].rsplit("\\", 1)[-1] for row in rows] == ["broken.zip", "Z.zip"]
    assert rows[0]["error_code"] == "CORRUPT_ARCHIVE"


def test_report_write_failure_preserves_existing_output_and_cleans_temp_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _indexed_repository(tmp_path)
    output = tmp_path / "report.json"
    output.write_text("previous report", encoding="utf-8")

    def fail_json_dump(*args, **kwargs) -> None:
        raise OSError("simulated write failure")

    monkeypatch.setattr(reporting_module.json, "dump", fail_json_dump)
    try:
        with pytest.raises(OSError, match="simulated write failure"):
            write_report(repository, output, "json")
    finally:
        repository.close()

    assert output.read_text(encoding="utf-8") == "previous report"
    assert list(tmp_path.glob("*.tmp")) == []
