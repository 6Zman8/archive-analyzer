from __future__ import annotations

import csv
import os
import tempfile
from pathlib import Path

from archive_analyzer.review_viewmodel import GroupRow, build_group_view
from archive_analyzer.storage.duplicate_repository import DuplicateRepository


_CSV_FIELDS = (
    "group_key",
    "relation",
    "confidence",
    "reason",
    "recommendation",
    "review_status",
    "archive_id",
    "file_name",
    "path",
    "archive_format",
    "file_size",
    "page_count",
    "representative_resolution",
    "user_decision",
    "direct_edges",
    "direct_edge_evidence",
)


def write_candidate_csv(repository: DuplicateRepository, output: Path, *, root_id: int) -> None:
    """Write the selected root's current candidate members only when requested."""

    rows = []
    for summary in sorted(repository.group_summaries(root_id), key=lambda item: item.group_key):
        detail = repository.group_details(summary.group_key)
        if detail is not None:
            rows.extend(_csv_rows(build_group_view(detail)))
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    temporary_output = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=_CSV_FIELDS)
            writer.writeheader()
            writer.writerows(
                {key: _spreadsheet_text(value) for key, value in row.items()}
                for row in rows
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_output, output)
    except BaseException:
        temporary_output.unlink(missing_ok=True)
        raise


def _spreadsheet_text(value: object) -> object:
    """Keep external text from becoming a spreadsheet formula; retain DB originals."""
    if isinstance(value, str) and (
        value.startswith(("\t", "\r", "\n"))
        or value.lstrip().startswith(("=", "+", "-", "@"))
    ):
        return "'" + value
    return value


def _csv_rows(group: GroupRow) -> tuple[dict[str, object | None], ...]:
    return tuple(
        {
            "group_key": group.group_key,
            "relation": group.relation_text,
            "confidence": group.confidence,
            "reason": group.reason_text,
            "recommendation": group.recommendation_text,
            "review_status": group.review_status_text,
            "archive_id": member.archive_id,
            "file_name": member.file_name,
            "path": str(member.path),
            "archive_format": member.archive_format.value,
            "file_size": member.file_size,
            "page_count": member.page_count,
            "representative_resolution": (
                None
                if member.representative_resolution is None
                else f"{member.representative_resolution[0]}x{member.representative_resolution[1]}"
            ),
            "user_decision": None if member.user_decision is None else member.user_decision.value,
            "direct_edges": _direct_edge_summary(group, member.archive_id),
            "direct_edge_evidence": _direct_edge_evidence(group, member.archive_id),
        }
        for member in sorted(group.members, key=lambda item: (str(item.path).casefold(), item.archive_id))
    )


def _direct_edge_summary(group: GroupRow, archive_id: int) -> str:
    values = []
    for edge in group.edges:
        if edge.left_archive_id == archive_id:
            values.append(f"{edge.right_file_name} ({edge.right_archive_id}): {edge.relation_text}")
        elif edge.right_archive_id == archive_id:
            values.append(f"{edge.left_file_name} ({edge.left_archive_id}): {edge.relation_text}")
    return "; ".join(values)


def _direct_edge_evidence(group: GroupRow, archive_id: int) -> str:
    return "; ".join(
        " | ".join(
            (
                f"{edge.left_file_name} ({edge.left_archive_id}) ↔ {edge.right_file_name} ({edge.right_archive_id})",
                edge.relation_text,
                f"신뢰도 {edge.confidence:.6f}",
                edge.reason_text,
                edge.recommendation_text,
                f"일치 {edge.matched_pages}/{edge.left_page_count}/{edge.right_page_count} 페이지",
            )
        )
        for edge in group.edges
        if archive_id in {edge.left_archive_id, edge.right_archive_id}
    )
