from __future__ import annotations

import csv
import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Literal

from archive_analyzer.storage.repository import ArchiveReportRow, Repository


ReportFormat = Literal["csv", "json"]

_CSV_FIELDS = (
    "path",
    "archive_format",
    "state",
    "image_count",
    "entry_count",
    "file_size",
    "mtime_ns",
    "error_code",
    "error_summary",
)


def write_report(repository: Repository, output: Path, format: ReportFormat) -> None:
    rows = [_report_record(row) for row in repository.report_rows()]
    if format not in {"csv", "json"}:
        raise ValueError(f"Unsupported report format: {format}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    temporary_output = Path(temporary_name)
    try:
        encoding = "utf-8-sig" if format == "csv" else "utf-8"
        with os.fdopen(descriptor, "w", encoding=encoding, newline="") as stream:
            if format == "csv":
                _write_csv(stream, rows)
            else:
                _write_json(stream, rows)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_output, output)
    except BaseException:
        temporary_output.unlink(missing_ok=True)
        raise


def _report_record(row: ArchiveReportRow) -> dict[str, object | None]:
    return {
        "path": str(row.path),
        "archive_format": row.archive_format.value,
        "state": row.state,
        "image_count": row.image_count,
        "entry_count": row.entry_count,
        "file_size": row.file_size,
        "mtime_ns": row.mtime_ns,
        "error_code": row.error_code,
        "error_summary": row.error_summary,
    }


def _write_csv(stream, rows: list[dict[str, object | None]]) -> None:
    writer = csv.DictWriter(stream, fieldnames=_CSV_FIELDS)
    writer.writeheader()
    writer.writerows(rows)


def _write_json(stream, rows: list[dict[str, object | None]]) -> None:
    state_counts = Counter(str(row["state"]).casefold() for row in rows)
    payload = {
        "summary": {
            "total": len(rows),
            "indexed": state_counts["indexed"],
            "failed": state_counts["failed"],
            "skipped": state_counts["skipped"],
            "missing": state_counts["missing"],
            "pending": state_counts["pending"],
        },
        "archives": rows,
    }
    json.dump(payload, stream, ensure_ascii=False, indent=2)
    stream.write("\n")
