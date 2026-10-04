"""Measured, transient progress; never queues UI work or writes from workers."""

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from threading import Lock
from typing import TypeVar

from archive_analyzer.duplicate_domain import AnalysisStage


@dataclass(frozen=True, slots=True)
class AnalysisProgress:
    stage: AnalysisStage | None
    phase: str
    completed: int
    total: int | None
    unit: str = "파일"
    current_item: str = ""
    detail: str = ""

    @property
    def percent(self) -> float | None:
        if self.total is None:
            return None
        if self.total == 0:
            return 100.0
        return min(100.0, max(0.0, 100 * self.completed / self.total))


ProgressCallback = Callable[[AnalysisProgress], None]
_T = TypeVar("_T")


def track_progress(
    items: Iterable[_T], total: int, *, stage: AnalysisStage,
    phase: str, callback: ProgressCallback | None, unit: str = "파일", every: int = 1,
) -> Iterator[_T]:
    """Count completed work, including skipped items, without materializing it."""
    if callback is None:
        yield from items
        return
    callback(AnalysisProgress(stage, phase, 0, total, unit))
    completed = 0
    for completed, item in enumerate(items, 1):
        yield item
        if completed % every == 0:
            callback(AnalysisProgress(stage, phase, completed, total, unit))
    if completed % every:
        callback(AnalysisProgress(stage, phase, completed, total, unit))


class ProgressMailbox:
    """Single latest snapshot shared by analysis workers and the Tk thread."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._latest: AnalysisProgress | None = None

    def publish(self, value: AnalysisProgress) -> None:
        with self._lock:
            self._latest = value

    def latest(self) -> AnalysisProgress | None:
        with self._lock:
            return self._latest

    def clear(self) -> None:
        with self._lock:
            self._latest = None
