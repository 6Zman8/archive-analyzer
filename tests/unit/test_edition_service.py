from __future__ import annotations

from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from threading import Event

import pytest
from PIL import Image

from archive_analyzer.archive_hashing import AnalysisCancelled
from archive_analyzer.domain import ArchiveFormat
from archive_analyzer.duplicate_domain import ArchiveAnalysisInput, ImageEntryRef
from archive_analyzer.edition_service import analyze_editions
from archive_analyzer.storage.duplicate_repository import EditionProfileInput


def _png() -> bytes:
    output = BytesIO()
    Image.new("RGB", (16, 16), (220, 40, 30)).save(output, format="PNG")
    return output.getvalue()


def _source(tmp_path: Path, page_count: int = 30) -> EditionProfileInput:
    path = tmp_path / "sample.cbz"
    path.write_bytes(b"archive")
    stat = path.stat()
    return EditionProfileInput(
        ArchiveAnalysisInput(
            1,
            path,
            stat.st_size,
            stat.st_mtime_ns,
            ArchiveFormat.CBZ,
            tuple(
                ImageEntryRef(index, f"{index:03}.png", None, None)
                for index in range(page_count)
            ),
        ),
        frozenset({"ko"}),
    )


class _Repository:
    def __init__(self, source: EditionProfileInput) -> None:
        self.source = source
        self.saved = []

    def edition_profile_inputs(self, _root_id: int, *, algorithm_version: int):
        assert algorithm_version == 1
        return (self.source,)

    def store_edition_profile(self, source, profile, **kwargs):  # type: ignore[no-untyped-def]
        self.saved.append((source, profile, kwargs))
        return True

    def edition_relation_candidates(self, _root_id: int, *, algorithm_version: int):
        assert algorithm_version == 1
        return ()


class _Reader:
    def __init__(self, cancel_event: Event | None = None) -> None:
        self.positions: list[int] = []
        self.cancel_event = cancel_event

    def read(self, _snapshot, entry, *, same_path_count: int):  # type: ignore[no-untyped-def]
        assert same_path_count == 1
        self.positions.append(entry.position)
        if self.cancel_event is not None and len(self.positions) == 3:
            self.cancel_event.set()
        return _png()


def test_edition_service_samples_at_most_twelve_pages_and_reports_progress(
    tmp_path: Path,
) -> None:
    repository = _Repository(_source(tmp_path))
    reader = _Reader()
    progress = []

    result = analyze_editions(
        repository, 7, Event(), reader=reader, progress=lambda *args: progress.append(args)
    )

    assert len(reader.positions) == 12
    assert reader.positions[0] == 0
    assert reader.positions[-1] == 29
    assert result.profiles_processed == 1
    assert repository.saved[0][1].color_page_ratio == 1.0
    assert progress[0] == (0, 12, "profile_pages")
    assert progress[-1] == (12, 12, "profile_pages")
    assert len(progress) == 13


def test_edition_service_uses_batch_reader_to_avoid_reopening_zip_per_page(
    tmp_path: Path,
) -> None:
    repository = _Repository(_source(tmp_path))

    class BatchReader(_Reader):
        def __init__(self) -> None:
            super().__init__()
            self.batch_calls = 0

        def read_many(self, _snapshot, requests, *, cancel_check):  # type: ignore[no-untyped-def]
            self.batch_calls += 1
            for entry, same_path_count in requests:
                cancel_check()
                assert same_path_count == 1
                self.positions.append(entry.position)
                yield _png()

    reader = BatchReader()

    analyze_editions(repository, 7, Event(), reader=reader)

    assert reader.batch_calls == 1
    assert len(reader.positions) == 12


def test_edition_service_stops_between_individual_page_reads(tmp_path: Path) -> None:
    cancel_event = Event()
    repository = _Repository(_source(tmp_path))
    reader = _Reader(cancel_event)

    with pytest.raises(AnalysisCancelled):
        analyze_editions(repository, 7, cancel_event, reader=reader)

    assert len(reader.positions) == 3
    assert repository.saved == []
