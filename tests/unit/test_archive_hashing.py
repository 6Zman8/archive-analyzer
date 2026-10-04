from datetime import UTC, datetime, timedelta
from threading import Event
from pathlib import Path

import pytest

from archive_analyzer.archive_hashing import (
    AnalysisCancelled,
    AnalysisFailure,
    ProbeCacheResult,
    ProbeFailure,
    cache_probe_fingerprints,
    sha256_archive,
    size_collision_targets,
)
from archive_analyzer.domain import ArchiveFormat
from archive_analyzer.duplicate_domain import ArchiveAnalysisInput, ImageEntryRef
from archive_analyzer.inspection.image_reader import ImageReadFailure
from archive_analyzer.storage.duplicate_repository import DuplicateRepository
from tests.image_helpers import encoded_gradient


FIXED_NOW = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
ANALYZER_VERSION = 1


def archive_input(
    archive_id: int,
    *,
    path: Path | None = None,
    size: int = 1,
    mtime_ns: int = 1,
    images: tuple[ImageEntryRef, ...] = (),
) -> ArchiveAnalysisInput:
    return ArchiveAnalysisInput(
        archive_id=archive_id,
        path=path or Path(f"archive-{archive_id}.zip"),
        file_size=size,
        mtime_ns=mtime_ns,
        archive_format=ArchiveFormat.ZIP,
        images=images,
    )


def repository_for(value: ArchiveAnalysisInput, tmp_path: Path) -> DuplicateRepository:
    repository = DuplicateRepository.open(tmp_path / "index.db")
    connection = repository._connection  # noqa: SLF001 - create V0 index fixture
    root_id = connection.execute(
        "INSERT INTO scan_roots(path, path_key, created_at) VALUES (?, ?, ?)",
        (str(tmp_path), "root-key", FIXED_NOW.isoformat()),
    ).lastrowid
    connection.execute(
        "INSERT INTO archives(id, scan_root_id, path, path_key, file_size, mtime_ns, "
        "archive_format, state, first_seen_at, last_seen_at, inspector_version) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 'INDEXED', ?, ?, 1)",
        (
            value.archive_id,
            root_id,
            str(value.path),
            f"archive-{value.archive_id}",
            value.file_size,
            value.mtime_ns,
            value.archive_format.value,
            FIXED_NOW.isoformat(),
            FIXED_NOW.isoformat(),
        ),
    )
    connection.commit()
    return repository


def test_only_size_collisions_are_selected_for_full_file_hash() -> None:
    inputs = (
        archive_input(1, size=10),
        archive_input(2, size=20),
        archive_input(3, size=20),
        archive_input(4, size=30),
    )

    assert size_collision_targets(inputs) == (2, 3)


def test_sha256_archive_honors_cancellation(tmp_path: Path) -> None:
    path = tmp_path / "archive.zip"
    path.write_bytes(b"a" * (9 * 1024 * 1024))
    cancelled = Event()
    cancelled.set()

    with pytest.raises(AnalysisCancelled):
        sha256_archive(
            archive_input(1, path=path, size=path.stat().st_size, mtime_ns=path.stat().st_mtime_ns),
            cancelled,
        )


@pytest.mark.parametrize("chunk_size", (0, -1))
def test_sha256_archive_requires_positive_chunk_size(tmp_path: Path, chunk_size: int) -> None:
    path = tmp_path / "archive.zip"
    path.write_bytes(b"archive")
    value = archive_input(
        1,
        path=path,
        size=path.stat().st_size,
        mtime_ns=path.stat().st_mtime_ns,
    )

    with pytest.raises(ValueError, match="chunk_size must be positive"):
        sha256_archive(value, Event(), chunk_size=chunk_size)


def test_sha256_archive_rejects_source_changed_during_analysis(tmp_path: Path) -> None:
    path = tmp_path / "archive.zip"
    path.write_bytes(b"original")
    value = archive_input(1, path=path, size=path.stat().st_size, mtime_ns=path.stat().st_mtime_ns)
    path.write_bytes(b"changed")

    with pytest.raises(AnalysisFailure) as raised:
        sha256_archive(value, Event())

    assert raised.value.code == "CHANGED_DURING_ANALYSIS"


class _Reader:
    def __init__(self, payloads: dict[int, bytes], failures: dict[int, ImageReadFailure] | None = None) -> None:
        self.payloads = payloads
        self.failures = failures or {}
        self.calls: list[tuple[int, int]] = []

    def read(self, snapshot, entry: ImageEntryRef, *, same_path_count: int = 1) -> bytes:  # type: ignore[no-untyped-def]
        self.calls.append((entry.position, same_path_count))
        if entry.position in self.failures:
            raise self.failures[entry.position]
        return self.payloads[entry.position]


def test_cache_probe_fingerprints_honors_entry_cancellation_with_no_images(
    tmp_path: Path,
) -> None:
    path = tmp_path / "archive.zip"
    path.write_bytes(b"archive")
    value = archive_input(
        1,
        path=path,
        size=path.stat().st_size,
        mtime_ns=path.stat().st_mtime_ns,
    )
    repository = repository_for(value, tmp_path)
    cancelled = Event()
    cancelled.set()
    try:
        with pytest.raises(AnalysisCancelled):
            cache_probe_fingerprints(
                value, _Reader({}), repository, cancelled, ANALYZER_VERSION, FIXED_NOW
            )

        assert repository.cached_fingerprints(value, ANALYZER_VERSION) is None
    finally:
        repository.close()


def test_cache_probe_fingerprints_honors_cancellation_before_all_cache_hit_bulk(
    tmp_path: Path,
) -> None:
    path = tmp_path / "archive.zip"
    path.write_bytes(b"archive")
    value = archive_input(
        1,
        path=path,
        size=path.stat().st_size,
        mtime_ns=path.stat().st_mtime_ns,
        images=(ImageEntryRef(0, "001.png", None, None),),
    )
    repository = repository_for(value, tmp_path)
    initial_reader = _Reader({0: encoded_gradient("PNG", (10, 10))})

    class CancelBeforeBulk(Event):
        def __init__(self) -> None:
            super().__init__()
            self.checks = 0

        def is_set(self) -> bool:
            self.checks += 1
            if self.checks == 3:
                self.set()
            return super().is_set()

    try:
        cache_probe_fingerprints(
            value, initial_reader, repository, Event(), ANALYZER_VERSION, FIXED_NOW
        )
        cached_reader = _Reader({})
        cancelled = CancelBeforeBulk()

        with pytest.raises(AnalysisCancelled):
            cache_probe_fingerprints(
                value,
                cached_reader,
                repository,
                cancelled,
                ANALYZER_VERSION,
                FIXED_NOW + timedelta(seconds=1),
            )

        assert cached_reader.calls == []
        assert repository._connection.execute(  # noqa: SLF001 - verify no cache write
            "SELECT computed_at FROM archive_fingerprints WHERE archive_id = ?",
            (value.archive_id,),
        ).fetchone() == (FIXED_NOW.isoformat(),)
    finally:
        repository.close()


def test_cache_probe_fingerprints_selects_at_most_seven_and_records_stable_errors(
    tmp_path: Path,
) -> None:
    path = tmp_path / "archive.zip"
    path.write_bytes(b"archive")
    images = tuple(ImageEntryRef(index, f"{index:03d}.png", None, None) for index in range(10))
    value = archive_input(
        1,
        path=path,
        size=path.stat().st_size,
        mtime_ns=path.stat().st_mtime_ns,
        images=images,
    )
    reader = _Reader(
        {index: encoded_gradient("PNG", (10, 10)) for index in range(10)},
        {5: ImageReadFailure("CORRUPT_ARCHIVE", "cannot read")},
    )
    repository = repository_for(value, tmp_path)
    try:
        result = cache_probe_fingerprints(
            value, reader, repository, Event(), ANALYZER_VERSION, FIXED_NOW
        )

        assert isinstance(result, ProbeCacheResult)
        assert [fingerprint.entry_position for fingerprint in result.probes] == [0, 1, 2, 4, 7, 8, 9]
        assert result.failures == ()
        assert reader.calls == [(0, 1), (1, 1), (2, 1), (4, 1), (7, 1), (8, 1), (9, 1)]
        assert repository.cached_fingerprints(value, ANALYZER_VERSION).image_failures == ()
    finally:
        repository.close()


def test_cache_probe_fingerprints_stores_stable_error_for_selected_image(tmp_path: Path) -> None:
    path = tmp_path / "archive.zip"
    path.write_bytes(b"archive")
    images = (ImageEntryRef(0, "001.png", None, None),)
    value = archive_input(
        1,
        path=path,
        size=path.stat().st_size,
        mtime_ns=path.stat().st_mtime_ns,
        images=images,
    )
    reader = _Reader({}, {0: ImageReadFailure("CORRUPT_ARCHIVE", "cannot read")})
    repository = repository_for(value, tmp_path)
    try:
        result = cache_probe_fingerprints(
            value, reader, repository, Event(), ANALYZER_VERSION, FIXED_NOW
        )

        cached = repository.cached_fingerprints(value, ANALYZER_VERSION)
        assert cached is not None
        assert cached.image_fingerprints == ()
        assert cached.image_failures == ((0, "CORRUPT_ARCHIVE"),)
        assert result == ProbeCacheResult((), (ProbeFailure(0, 0, "CORRUPT_ARCHIVE"),))
    finally:
        repository.close()


@pytest.mark.parametrize(
    "code",
    (
        "AMBIGUOUS_ENTRY_NAME",
        "CORRUPT_ARCHIVE",
        "ENCRYPTED_UNSUPPORTED",
        "IMAGE_BYTE_LIMIT",
        "IMAGE_PIXEL_LIMIT",
        "UNSUPPORTED_FORMAT",
    ),
)
def test_cache_probe_fingerprints_returns_each_stable_reader_error(tmp_path: Path, code: str) -> None:
    path = tmp_path / "archive.zip"
    path.write_bytes(b"archive")
    value = archive_input(
        1,
        path=path,
        size=path.stat().st_size,
        mtime_ns=path.stat().st_mtime_ns,
        images=(ImageEntryRef(0, "001.png", None, None),),
    )
    repository = repository_for(value, tmp_path)
    try:
        result = cache_probe_fingerprints(
            value,
            _Reader({}, {0: ImageReadFailure(code, "stable")}),
            repository,
            Event(),
            ANALYZER_VERSION,
            FIXED_NOW,
        )

        assert result == ProbeCacheResult((), (ProbeFailure(0, 0, code),))
        assert repository.cached_fingerprints(value, ANALYZER_VERSION).image_failures == ((0, code),)
    finally:
        repository.close()


@pytest.mark.parametrize(
    "code",
    (
        "ACCESS_DENIED",
        "ARCHIVE_CHANGED",
        "ENTRY_CHANGED",
        "FILE_NOT_FOUND",
        "SEVEN_ZIP_FAILED",
        "SEVEN_ZIP_NOT_FOUND",
    ),
)
def test_cache_probe_fingerprints_propagates_retryable_reader_errors(
    tmp_path: Path, code: str
) -> None:
    path = tmp_path / "archive.zip"
    path.write_bytes(b"archive")
    value = archive_input(
        1,
        path=path,
        size=path.stat().st_size,
        mtime_ns=path.stat().st_mtime_ns,
        images=(ImageEntryRef(0, "001.png", None, None),),
    )
    repository = repository_for(value, tmp_path)
    reader = _Reader({}, {0: ImageReadFailure(code, "retryable")})
    try:
        with pytest.raises(ImageReadFailure) as raised:
            cache_probe_fingerprints(
                value, reader, repository, Event(), ANALYZER_VERSION, FIXED_NOW
            )

        assert raised.value.code == code
        assert repository.cached_fingerprints(value, ANALYZER_VERSION) is None
    finally:
        repository.close()


def test_cache_probe_fingerprints_propagates_unexpected_reader_error(tmp_path: Path) -> None:
    path = tmp_path / "archive.zip"
    path.write_bytes(b"archive")
    value = archive_input(
        1,
        path=path,
        size=path.stat().st_size,
        mtime_ns=path.stat().st_mtime_ns,
        images=(ImageEntryRef(0, "001.png", None, None),),
    )
    repository = repository_for(value, tmp_path)

    class UnexpectedReader(_Reader):
        def read(self, snapshot, entry: ImageEntryRef, *, same_path_count: int = 1) -> bytes:  # type: ignore[no-untyped-def]
            raise RuntimeError("unexpected reader failure")

    try:
        with pytest.raises(RuntimeError, match="unexpected reader failure"):
            cache_probe_fingerprints(
                value, UnexpectedReader({}), repository, Event(), ANALYZER_VERSION, FIXED_NOW
            )

        assert repository.cached_fingerprints(value, ANALYZER_VERSION) is None
    finally:
        repository.close()


def test_cache_probe_fingerprints_does_not_store_when_source_changes(tmp_path: Path) -> None:
    path = tmp_path / "archive.zip"
    path.write_bytes(b"archive")
    value = archive_input(
        1,
        path=path,
        size=path.stat().st_size,
        mtime_ns=path.stat().st_mtime_ns,
        images=(ImageEntryRef(0, "001.png", None, None),),
    )
    repository = repository_for(value, tmp_path)

    class ChangingReader(_Reader):
        def read(self, snapshot, entry: ImageEntryRef, *, same_path_count: int = 1) -> bytes:  # type: ignore[no-untyped-def]
            path.write_bytes(b"changed archive")
            return encoded_gradient("PNG", (10, 10))

    try:
        with pytest.raises(AnalysisFailure, match="CHANGED_DURING_ANALYSIS"):
            cache_probe_fingerprints(
                value, ChangingReader({}), repository, Event(), ANALYZER_VERSION, FIXED_NOW
            )

        assert repository.cached_fingerprints(value, ANALYZER_VERSION) is None
    finally:
        repository.close()
