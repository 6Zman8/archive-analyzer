from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Event
from typing import Callable

from archive_analyzer.archive_hashing import AnalysisCancelled
from archive_analyzer.sequence_matching import match_page_sequences
from archive_analyzer.storage.duplicate_repository import DuplicateRepository


SEQUENCE_ALGORITHM_VERSION = 1


@dataclass(frozen=True, slots=True)
class SequenceAnalysisSummary:
    processed: int


def analyze_sequence_relations(
    repository: DuplicateRepository,
    root_id: int,
    cancel_event: Event,
    *,
    set_keys: tuple[str, ...] | None = None,
    progress: Callable[[int, int, str], None] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> SequenceAnalysisSummary:
    now = clock or (lambda: datetime.now(UTC))
    scope = repository.precision_scope_for_sets(set_keys) if set_keys is not None else None
    candidates = repository.sequence_analysis_candidates(
        root_id, algorithm_version=SEQUENCE_ALGORITHM_VERSION,
        **({"relation_pairs": scope.relation_pairs} if scope is not None else {}),
    )
    processed = 0

    def checkpoint() -> None:
        if cancel_event.is_set():
            raise AnalysisCancelled

    if progress is not None:
        progress(0, len(candidates), "sequence")
    for index, candidate in enumerate(candidates, start=1):
        checkpoint()
        match = match_page_sequences(
            candidate.left_fingerprints,
            candidate.right_fingerprints,
            checkpoint=checkpoint,
        )
        if repository.store_sequence_result(
            candidate,
            match,
            algorithm_version=SEQUENCE_ALGORITHM_VERSION,
            computed_at=now(),
        ):
            processed += 1
        if progress is not None:
            progress(index, len(candidates), "sequence")
    return SequenceAnalysisSummary(processed=processed)


__all__ = [
    "SEQUENCE_ALGORITHM_VERSION",
    "SequenceAnalysisSummary",
    "analyze_sequence_relations",
]
