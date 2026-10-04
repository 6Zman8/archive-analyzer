import hashlib
import io
import subprocess
import threading
import zlib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

import archive_analyzer.inspection.image_reader as image_reader
from archive_analyzer.archive_hashing import AnalysisCancelled
from archive_analyzer.domain import ArchiveFormat
from archive_analyzer.duplicate_domain import ImageEntryRef
from archive_analyzer.inspection.image_reader import (
    DispatchingImageReader,
    ImageReadFailure,
    SevenZipImageReader,
    ZipImageReader,
)
from tests.helpers import snapshot
from tests.image_helpers import encoded_gradient, file_identity


DEFAULT_SEVEN_ZIP = Path(r"C:\Program Files\7-Zip\7z.exe")


def test_zip_reader_reads_selected_duplicate_name_by_position(tmp_path: Path) -> None:
    archive = tmp_path / "sample.zip"
    with ZipFile(archive, "w", compression=ZIP_DEFLATED) as writer:
        writer.writestr("001.jpg", b"first")
        writer.writestr("001.jpg", b"second")

    assert ZipImageReader().read(
        snapshot(archive, ArchiveFormat.ZIP),
        ImageEntryRef(1, "001.jpg", 6, None),
        same_path_count=2,
    ) == b"second"


def test_zip_batch_reader_opens_archive_once_for_all_sample_pages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "sample.zip"
    with ZipFile(archive, "w", compression=ZIP_DEFLATED) as writer:
        writer.writestr("001.jpg", b"first")
        writer.writestr("002.jpg", b"second")
    real_zip_file = image_reader.ZipFile
    open_count = 0

    def counting_zip_file(*args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal open_count
        open_count += 1
        return real_zip_file(*args, **kwargs)

    monkeypatch.setattr(image_reader, "ZipFile", counting_zip_file)

    results = tuple(
        ZipImageReader().read_many(
            snapshot(archive, ArchiveFormat.ZIP),
            (
                (ImageEntryRef(0, "001.jpg", 5, None), 1),
                (ImageEntryRef(1, "002.jpg", 6, None), 1),
            ),
        )
    )

    assert results == (b"first", b"second")
    assert open_count == 1


@pytest.mark.skipif(not DEFAULT_SEVEN_ZIP.is_file(), reason="7-Zip is not installed")
def test_sevenzip_batch_reader_extracts_three_entries_with_one_process(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    payloads = tuple(f"page-{index}".encode() for index in range(3))
    for index, payload in enumerate(payloads):
        (source / f"{index:03}.png").write_bytes(payload)
    archive = tmp_path / "book.7z"
    subprocess.run(
        [str(DEFAULT_SEVEN_ZIP), "a", "-t7z", str(archive), str(source / "*")],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    before = file_identity(archive)
    calls: list[list[str]] = []

    def process_runner(command, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(command)
        return subprocess.Popen(command, **kwargs)

    requests = tuple(
        (
            ImageEntryRef(
                index,
                f"{index:03}.png",
                len(payload),
                f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}",
            ),
            1,
        )
        for index, payload in enumerate(payloads)
    )

    result = tuple(
        SevenZipImageReader(
            DEFAULT_SEVEN_ZIP, process_runner=process_runner
        ).read_many(snapshot(archive, ArchiveFormat.SEVEN_ZIP), requests)
    )

    assert result == payloads
    assert len(calls) == 1
    assert file_identity(archive) == before


def test_sevenzip_batch_cancel_terminates_process_and_removes_private_temp(
    tmp_path: Path,
) -> None:
    executable, archive_snapshot = _fake_sevenzip_snapshot(tmp_path)
    released = threading.Event()
    process = _GracefulTerminateProcess(io.BytesIO(), io.BytesIO(), released)
    temp_roots: list[Path] = []

    def process_runner(command, **_kwargs):  # type: ignore[no-untyped-def]
        temp_roots.extend(
            Path(argument[2:]) for argument in command if argument.startswith("-o")
        )
        return process

    cancel_checks = 0

    def cancel() -> None:
        nonlocal cancel_checks
        cancel_checks += 1
        if cancel_checks >= 2:
            raise AnalysisCancelled

    with pytest.raises(AnalysisCancelled):
        tuple(
            SevenZipImageReader(
                executable, process_runner=process_runner
            ).read_many(
                archive_snapshot,
                ((ImageEntryRef(0, "001.png", 4, None), 1),),
                cancel_check=cancel,
            )
        )

    assert process.operations == ["terminate", "wait"]
    assert temp_roots and all(not root.exists() for root in temp_roots)


def test_sevenzip_batch_rejects_unsafe_entry_before_starting_process(
    tmp_path: Path,
) -> None:
    executable, archive_snapshot = _fake_sevenzip_snapshot(tmp_path)
    calls = 0

    def process_runner(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        raise AssertionError("unsafe entries must be rejected before process start")

    with pytest.raises(ImageReadFailure) as raised:
        tuple(
            SevenZipImageReader(
                executable, process_runner=process_runner
            ).read_many(
                archive_snapshot,
                ((ImageEntryRef(0, "../escape.png", 4, None), 1),),
            )
        )

    assert raised.value.code == "UNSAFE_ENTRY_PATH"
    assert calls == 0


def test_reader_never_changes_archive(tmp_path: Path) -> None:
    archive = tmp_path / "sample.zip"
    with ZipFile(archive, "w", compression=ZIP_DEFLATED) as writer:
        writer.writestr("001.png", encoded_gradient("PNG", (10, 10)))
    before = file_identity(archive)

    assert DispatchingImageReader(DEFAULT_SEVEN_ZIP).read(
        snapshot(archive, ArchiveFormat.ZIP), ImageEntryRef(0, "001.png", None, None)
    )

    assert file_identity(archive) == before


def test_zip_reader_stops_above_byte_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = tmp_path / "large.zip"
    with ZipFile(archive, "w") as writer:
        writer.writestr("1.jpg", b"12345")
    monkeypatch.setattr(image_reader, "MAX_IMAGE_BYTES", 4)

    with pytest.raises(ImageReadFailure) as raised:
        ZipImageReader().read(
            snapshot(archive, ArchiveFormat.ZIP), ImageEntryRef(0, "1.jpg", 5, None)
        )

    assert raised.value.code == "IMAGE_BYTE_LIMIT"


def test_zip_reader_reports_corrupt_compressed_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "corrupt-entry.zip"
    with ZipFile(archive, "w") as writer:
        writer.writestr("1.jpg", b"image")

    def fail_decompression(stream: object) -> bytes:
        raise zlib.error("invalid stored block lengths")

    monkeypatch.setattr(image_reader, "_read_bounded", fail_decompression)
    with pytest.raises(ImageReadFailure) as raised:
        ZipImageReader().read(
            snapshot(archive, ArchiveFormat.ZIP), ImageEntryRef(0, "1.jpg", 5, None)
        )

    assert raised.value.code == "CORRUPT_ARCHIVE"


def test_zip_reader_stops_when_actual_stream_exceeds_declared_allowed_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "large.zip"
    archive.write_bytes(b"placeholder")
    monkeypatch.setattr(image_reader, "MAX_IMAGE_BYTES", 4)

    class DeclaredInfo:
        filename = "1.jpg"
        file_size = 4
        CRC = None
        flag_bits = 0
        is_dir = staticmethod(lambda: False)

    class FakeZipFile:
        def __init__(self, path: Path) -> None:
            assert path == archive

        def __enter__(self) -> "FakeZipFile":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def infolist(self) -> list[DeclaredInfo]:
            return [DeclaredInfo()]

        def open(self, info: DeclaredInfo) -> io.BytesIO:
            assert info.filename == "1.jpg"
            return io.BytesIO(b"12345")

    monkeypatch.setattr(image_reader, "ZipFile", FakeZipFile)
    with pytest.raises(ImageReadFailure) as raised:
        ZipImageReader().read(
            snapshot(archive, ArchiveFormat.ZIP), ImageEntryRef(0, "1.jpg", 4, None)
        )

    assert raised.value.code == "IMAGE_BYTE_LIMIT"


def test_zip_reader_rejects_encrypted_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = tmp_path / "encrypted.zip"
    archive.write_bytes(b"placeholder")

    class EncryptedInfo:
        filename = "1.jpg"
        file_size = 1
        CRC = 1
        flag_bits = 1
        is_dir = staticmethod(lambda: False)

    class FakeZipFile:
        def __init__(self, path: Path) -> None:
            assert path == archive

        def __enter__(self) -> "FakeZipFile":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def infolist(self) -> list[EncryptedInfo]:
            return [EncryptedInfo()]

    monkeypatch.setattr(image_reader, "ZipFile", FakeZipFile)
    with pytest.raises(ImageReadFailure) as raised:
        ZipImageReader().read(
            snapshot(archive, ArchiveFormat.ZIP), ImageEntryRef(0, "1.jpg", 1, "00000001")
        )

    assert raised.value.code == "ENCRYPTED_UNSUPPORTED"


def test_zip_reader_rejects_changed_entry(tmp_path: Path) -> None:
    archive = tmp_path / "changed.zip"
    with ZipFile(archive, "w") as writer:
        writer.writestr("renamed.jpg", b"image")

    with pytest.raises(ImageReadFailure) as raised:
        ZipImageReader().read(
            snapshot(archive, ArchiveFormat.ZIP), ImageEntryRef(0, "1.jpg", 5, None)
        )

    assert raised.value.code == "ENTRY_CHANGED"


def test_zip_reader_rejects_changed_archive_snapshot(tmp_path: Path) -> None:
    archive = tmp_path / "changed.zip"
    with ZipFile(archive, "w") as writer:
        writer.writestr("1.jpg", b"image")
    old_snapshot = snapshot(archive, ArchiveFormat.ZIP)
    archive.write_bytes(archive.read_bytes() + b"changed")

    with pytest.raises(ImageReadFailure) as raised:
        ZipImageReader().read(old_snapshot, ImageEntryRef(0, "1.jpg", 5, None))

    assert raised.value.code == "ARCHIVE_CHANGED"


def test_sevenzip_reader_rejects_duplicate_entry_path_before_starting_process(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "book.7z"
    archive.write_bytes(b"placeholder")

    with pytest.raises(ImageReadFailure) as raised:
        SevenZipImageReader(DEFAULT_SEVEN_ZIP).read(
            snapshot(archive, ArchiveFormat.SEVEN_ZIP),
            ImageEntryRef(0, "1.jpg", None, None),
            same_path_count=2,
        )

    assert raised.value.code == "AMBIGUOUS_ENTRY_NAME"


def test_sevenzip_reader_reports_missing_executable(tmp_path: Path) -> None:
    archive = tmp_path / "book.7z"
    archive.write_bytes(b"placeholder")

    with pytest.raises(ImageReadFailure) as raised:
        SevenZipImageReader(tmp_path / "missing-7z.exe").read(
            snapshot(archive, ArchiveFormat.SEVEN_ZIP),
            ImageEntryRef(0, "1.jpg", None, None),
        )

    assert raised.value.code == "SEVEN_ZIP_NOT_FOUND"


def test_sevenzip_reader_uses_literal_entry_argv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = tmp_path / "7z.exe"
    executable.write_bytes(b"placeholder")
    archive = tmp_path / "book.7z"
    archive.write_bytes(b"placeholder")
    entry = ImageEntryRef(0, "-@name*?.jpg", 4, None)
    captured: list[list[str]] = []

    def run(command: list[str], *, timeout_seconds: float) -> tuple[int, bytes, str]:
        captured.append(command)
        assert timeout_seconds == 60.0
        return 0, b"data", ""

    monkeypatch.setattr(image_reader, "_run_selected_entry_process", run)
    assert SevenZipImageReader(executable).read(
        snapshot(archive, ArchiveFormat.SEVEN_ZIP), entry
    ) == b"data"
    assert captured == [
        [
            str(executable),
            "x",
            "-so",
            "-bd",
            "-bb0",
            "-y",
            "-spd",
            "--",
            str(archive),
            entry.path,
        ]
    ]


class _CompletedProcess:
    def __init__(self, stdout: io.RawIOBase, stderr: io.RawIOBase, returncode: int) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self._final_returncode = returncode
        self.returncode: int | None = None
        self.wait_calls = 0

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls += 1
        if self.returncode is None:
            self.returncode = self._final_returncode
        return self.returncode


class _GracefulTerminateProcess(_CompletedProcess):
    def __init__(self, stdout: io.RawIOBase, stderr: io.RawIOBase, released: threading.Event) -> None:
        super().__init__(stdout, stderr, 0)
        self.released = released
        self.operations: list[str] = []

    def terminate(self) -> None:
        self.operations.append("terminate")
        self.returncode = -15
        self.released.set()

    def kill(self) -> None:
        self.operations.append("kill")
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        self.operations.append("wait")
        return super().wait(timeout)


class _ForceKillProcess(_CompletedProcess):
    def __init__(self, stdout: io.RawIOBase, stderr: io.RawIOBase, returncode: int) -> None:
        super().__init__(stdout, stderr, returncode)
        self.operations: list[str] = []

    def terminate(self) -> None:
        self.operations.append("terminate")

    def kill(self) -> None:
        self.operations.append("kill")
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        self.operations.append("wait")
        if self.returncode is None:
            raise subprocess.TimeoutExpired([], timeout)
        return self.returncode


class _StartedThread:
    def __init__(self, target: object, name: str) -> None:
        self._target = target
        self.name = name
        self.started = False
        self.join_calls = 0

    def start(self) -> None:
        self.started = True
        assert callable(self._target)
        self._target()

    def join(self, timeout: float | None = None) -> None:
        assert self.started
        self.join_calls += 1


class _StartFailingThread:
    def __init__(self, name: str) -> None:
        self.name = name
        self.join_calls = 0

    def start(self) -> None:
        raise RuntimeError(f"{self.name} start failed")

    def join(self, timeout: float | None = None) -> None:
        self.join_calls += 1
        raise RuntimeError("cannot join thread before it is started")


def _fake_sevenzip_snapshot(tmp_path: Path) -> tuple[Path, object]:
    executable = tmp_path / "7z.exe"
    executable.write_bytes(b"placeholder")
    archive = tmp_path / "book.7z"
    archive.write_bytes(b"placeholder")
    return executable, snapshot(archive, ArchiveFormat.SEVEN_ZIP)


def test_sevenzip_reader_converts_first_thread_start_failure_and_reaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, archive_snapshot = _fake_sevenzip_snapshot(tmp_path)
    released = threading.Event()
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    process = _GracefulTerminateProcess(stdout, stderr, released)
    output_thread = _StartFailingThread("archive-analyzer-7zip-image")
    error_thread = _StartFailingThread("archive-analyzer-7zip-errors")
    threads = iter((output_thread, error_thread))
    monkeypatch.setattr(image_reader.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(image_reader.threading, "Thread", lambda **kwargs: next(threads))

    with pytest.raises(ImageReadFailure) as raised:
        SevenZipImageReader(executable).read(
            archive_snapshot, ImageEntryRef(0, "1.jpg", None, None)
        )

    assert raised.value.code == "SEVEN_ZIP_FAILED"
    assert process.operations == ["terminate", "wait"]
    assert stdout.closed and stderr.closed
    assert output_thread.join_calls == 0
    assert error_thread.join_calls == 0


def test_sevenzip_reader_converts_second_thread_start_failure_and_reaps_started_thread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, archive_snapshot = _fake_sevenzip_snapshot(tmp_path)
    released = threading.Event()
    stdout = io.BytesIO(b"data")
    stderr = io.BytesIO()
    process = _GracefulTerminateProcess(stdout, stderr, released)
    output_thread = _StartedThread(None, "archive-analyzer-7zip-image")
    error_thread = _StartFailingThread("archive-analyzer-7zip-errors")
    threads = iter((output_thread, error_thread))

    def make_thread(**kwargs: object) -> _StartedThread | _StartFailingThread:
        thread = next(threads)
        if isinstance(thread, _StartedThread):
            thread._target = kwargs["target"]
        return thread

    monkeypatch.setattr(image_reader.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(image_reader.threading, "Thread", make_thread)

    with pytest.raises(ImageReadFailure) as raised:
        SevenZipImageReader(executable).read(
            archive_snapshot, ImageEntryRef(0, "1.jpg", None, None)
        )

    assert raised.value.code == "SEVEN_ZIP_FAILED"
    assert process.operations == ["terminate", "wait"]
    assert stdout.closed and stderr.closed
    assert output_thread.join_calls == 1
    assert error_thread.join_calls == 0


def test_sevenzip_reader_stops_oversized_stdout_and_reaps_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, archive_snapshot = _fake_sevenzip_snapshot(tmp_path)
    process = _ForceKillProcess(io.BytesIO(b"12345"), io.BytesIO(), 0)
    monkeypatch.setattr(image_reader, "MAX_IMAGE_BYTES", 4)
    monkeypatch.setattr(image_reader, "_READ_CHUNK_BYTES", 2)
    monkeypatch.setattr(image_reader.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(ImageReadFailure) as raised:
        SevenZipImageReader(executable).read(
            archive_snapshot, ImageEntryRef(0, "1.jpg", None, None)
        )

    assert raised.value.code == "IMAGE_BYTE_LIMIT"
    assert process.operations == ["terminate", "wait", "kill", "wait"]


def test_sevenzip_reader_reaps_process_after_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, archive_snapshot = _fake_sevenzip_snapshot(tmp_path)
    released = threading.Event()

    class BlockingStream(io.RawIOBase):
        def read(self, size: int = -1) -> bytes:
            released.wait(timeout=5)
            return b""

        def close(self) -> None:
            released.set()
            super().close()

    stdout = BlockingStream()
    stderr = io.BytesIO()
    process = _GracefulTerminateProcess(stdout, stderr, released)
    monkeypatch.setattr(image_reader.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(ImageReadFailure) as raised:
        SevenZipImageReader(executable, timeout_seconds=0.01).read(
            archive_snapshot, ImageEntryRef(0, "1.jpg", None, None)
        )

    assert raised.value.code == "SEVEN_ZIP_FAILED"
    assert process.operations == ["terminate", "wait"]
    assert stdout.closed
    assert stderr.closed
    assert not any(
        thread.name in {"archive-analyzer-7zip-image", "archive-analyzer-7zip-errors"}
        and thread.is_alive()
        for thread in threading.enumerate()
    )


def test_sevenzip_reader_force_kills_process_after_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, archive_snapshot = _fake_sevenzip_snapshot(tmp_path)
    released = threading.Event()

    class BlockingStream(io.RawIOBase):
        def read(self, size: int = -1) -> bytes:
            released.wait(timeout=5)
            return b""

        def close(self) -> None:
            released.set()
            super().close()

    process = _ForceKillProcess(BlockingStream(), io.BytesIO(), 0)
    monkeypatch.setattr(image_reader.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(ImageReadFailure) as raised:
        SevenZipImageReader(executable, timeout_seconds=0.01).read(
            archive_snapshot, ImageEntryRef(0, "1.jpg", None, None)
        )

    assert raised.value.code == "SEVEN_ZIP_FAILED"
    assert process.operations == ["terminate", "wait", "kill", "wait"]
    assert process.stdout.closed
    assert process.stderr.closed


def test_sevenzip_reader_bounds_stderr_detail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable, archive_snapshot = _fake_sevenzip_snapshot(tmp_path)
    process = _CompletedProcess(io.BytesIO(b"data"), io.BytesIO(b"x" * 9_000), 1)
    monkeypatch.setattr(image_reader.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(ImageReadFailure) as raised:
        SevenZipImageReader(executable).read(
            archive_snapshot, ImageEntryRef(0, "1.jpg", 4, None)
        )

    assert raised.value.code == "SEVEN_ZIP_FAILED"
    assert len(raised.value.detail or "") == 8_192


@pytest.mark.parametrize(
    ("entry", "payload"),
    [
        (ImageEntryRef(0, "1.jpg", 3, None), b"data"),
        (ImageEntryRef(0, "1.jpg", 4, "0x00000000"), b"data"),
    ],
)
def test_sevenzip_reader_rejects_payload_metadata_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entry: ImageEntryRef,
    payload: bytes,
) -> None:
    executable, archive_snapshot = _fake_sevenzip_snapshot(tmp_path)
    process = _CompletedProcess(io.BytesIO(payload), io.BytesIO(), 0)
    monkeypatch.setattr(image_reader.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(ImageReadFailure) as raised:
        SevenZipImageReader(executable).read(archive_snapshot, entry)

    assert raised.value.code == "ENTRY_CHANGED"


@pytest.mark.skipif(not DEFAULT_SEVEN_ZIP.is_file(), reason="7-Zip is not installed")
@pytest.mark.parametrize("entry_path", ("-dash.jpg", "@at.jpg", "star*.jpg", "query?.jpg"))
def test_sevenzip_reader_reads_literal_special_entry_name(tmp_path: Path, entry_path: str) -> None:
    payload = f"payload:{entry_path}".encode()
    archive = tmp_path / "special.7z"
    subprocess.run(
        [str(DEFAULT_SEVEN_ZIP), "a", "-t7z", str(archive), f"-si{entry_path}"],
        check=True,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    assert SevenZipImageReader(DEFAULT_SEVEN_ZIP).read(
        snapshot(archive, ArchiveFormat.SEVEN_ZIP),
        ImageEntryRef(0, entry_path, len(payload), f"0x{zlib.crc32(payload):08X}"),
    ) == payload


@pytest.mark.skipif(not DEFAULT_SEVEN_ZIP.is_file(), reason="7-Zip is not installed")
def test_sevenzip_reader_reads_only_selected_entry_without_changing_archive(tmp_path: Path) -> None:
    source = tmp_path / "page.jpg"
    payload = encoded_gradient("JPEG", (10, 10))
    source.write_bytes(payload)
    archive = tmp_path / "book.7z"
    import subprocess

    subprocess.run(
        [str(DEFAULT_SEVEN_ZIP), "a", "-t7z", str(archive), str(source)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    before = file_identity(archive)

    result = SevenZipImageReader(DEFAULT_SEVEN_ZIP).read(
        snapshot(archive, ArchiveFormat.SEVEN_ZIP),
        ImageEntryRef(0, "page.jpg", len(payload), None),
    )

    assert hashlib.sha256(result).hexdigest() == hashlib.sha256(payload).hexdigest()
    assert file_identity(archive) == before


@pytest.mark.skipif(not DEFAULT_SEVEN_ZIP.is_file(), reason="7-Zip is not installed")
def test_sevenzip_reader_rejects_missing_indexed_entry(tmp_path: Path) -> None:
    source = tmp_path / "page.jpg"
    source.write_bytes(b"image")
    archive = tmp_path / "book.7z"
    import subprocess

    subprocess.run(
        [str(DEFAULT_SEVEN_ZIP), "a", "-t7z", str(archive), str(source)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    with pytest.raises(ImageReadFailure) as raised:
        SevenZipImageReader(DEFAULT_SEVEN_ZIP).read(
            snapshot(archive, ArchiveFormat.SEVEN_ZIP),
            ImageEntryRef(0, "missing.jpg", None, None),
        )

    assert raised.value.code == "ENTRY_CHANGED"


@pytest.mark.skipif(not DEFAULT_SEVEN_ZIP.is_file(), reason="7-Zip is not installed")
def test_sevenzip_reader_rejects_encrypted_archive(tmp_path: Path) -> None:
    source = tmp_path / "page.jpg"
    source.write_bytes(b"image")
    archive = tmp_path / "encrypted.7z"
    import subprocess

    subprocess.run(
        [str(DEFAULT_SEVEN_ZIP), "a", "-t7z", "-psecret", str(archive), str(source)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    with pytest.raises(ImageReadFailure) as raised:
        SevenZipImageReader(DEFAULT_SEVEN_ZIP).read(
            snapshot(archive, ArchiveFormat.SEVEN_ZIP),
            ImageEntryRef(0, "page.jpg", 5, None),
        )

    assert raised.value.code == "ENCRYPTED_UNSUPPORTED"
