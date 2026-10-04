import hashlib
import io
from pathlib import Path
import subprocess
import threading

import pytest

import archive_analyzer.inspection.sevenzip as sevenzip
from archive_analyzer.domain import ArchiveFormat
from archive_analyzer.inspection.base import InspectionFailure
from archive_analyzer.inspection.sevenzip import SevenZipBackend
from tests.helpers import snapshot


SEVEN_ZIP = Path(r"C:\Program Files\7-Zip\7z.exe")


class _FakeProcess:
    def __init__(self, output: bytes, returncode: int) -> None:
        self.stdout = io.BytesIO(output)
        self._final_returncode = returncode
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False
        self.wait_calls = 0

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls += 1
        if self.returncode is None:
            self.returncode = self._final_returncode
        return self.returncode


def _stub_popen(
    monkeypatch: pytest.MonkeyPatch, output: str, returncode: int
) -> _FakeProcess:
    process = _FakeProcess(output.encode("utf-8"), returncode)

    def popen(*args: object, **kwargs: object) -> _FakeProcess:
        assert kwargs["stdout"] is subprocess.PIPE
        assert kwargs["stderr"] is subprocess.STDOUT
        return process

    monkeypatch.setattr(sevenzip.subprocess, "Popen", popen)
    return process


@pytest.mark.skipif(not SEVEN_ZIP.is_file(), reason="7-Zip is not installed")
def test_sevenzip_backend_lists_7z_contents_without_changing_source(tmp_path: Path) -> None:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "page = 2.jpg").write_bytes(b"two")
    (source_dir / "10.png").write_bytes(b"ten")
    (source_dir / "nested.zip").write_bytes(b"not opened")
    archive_path = tmp_path / "book.7z"
    source_state_before = {
        path.name: (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_size, path.stat().st_mtime_ns)
        for path in source_dir.iterdir()
    }

    subprocess.run(
        [str(SEVEN_ZIP), "a", "-t7z", str(archive_path), str(source_dir / "*")],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    result = SevenZipBackend(SEVEN_ZIP).inspect(snapshot(archive_path, ArchiveFormat.SEVEN_ZIP))

    assert [entry.path for entry in result.entries] == ["10.png", "nested.zip", "page = 2.jpg"]
    assert result.image_count == 2
    assert result.nested_archive_count == 1
    source_state_after = {
        path.name: (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_size, path.stat().st_mtime_ns)
        for path in source_dir.iterdir()
    }
    assert source_state_after == source_state_before


@pytest.mark.skipif(not SEVEN_ZIP.is_file(), reason="7-Zip is not installed")
def test_sevenzip_backend_rejects_encrypted_7z_archive(tmp_path: Path) -> None:
    source_path = tmp_path / "page.jpg"
    source_path.write_bytes(b"image")
    archive_path = tmp_path / "encrypted.7z"
    subprocess.run(
        [str(SEVEN_ZIP), "a", "-t7z", "-psecret", str(archive_path), str(source_path)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    with pytest.raises(InspectionFailure) as raised:
        SevenZipBackend(SEVEN_ZIP).inspect(snapshot(archive_path, ArchiveFormat.SEVEN_ZIP))

    assert raised.value.code == "ENCRYPTED_UNSUPPORTED"


@pytest.mark.skipif(not SEVEN_ZIP.is_file(), reason="7-Zip is not installed")
def test_sevenzip_backend_marks_corrupt_7z_archive(tmp_path: Path) -> None:
    archive_path = tmp_path / "corrupt.7z"
    archive_path.write_bytes(b"not an archive")

    with pytest.raises(InspectionFailure) as raised:
        SevenZipBackend(SEVEN_ZIP).inspect(snapshot(archive_path, ArchiveFormat.SEVEN_ZIP))

    assert raised.value.code == "CORRUPT_ARCHIVE"


def test_sevenzip_backend_bounds_os_error_detail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "7z.exe"
    executable.write_bytes(b"placeholder")
    archive_path = tmp_path / "book.7z"
    archive_path.write_bytes(b"placeholder")

    def raise_os_error(*args: object, **kwargs: object) -> None:
        raise OSError("x" * 9_000)

    monkeypatch.setattr(sevenzip.subprocess, "Popen", raise_os_error)

    with pytest.raises(InspectionFailure) as raised:
        SevenZipBackend(executable).inspect(snapshot(archive_path, ArchiveFormat.SEVEN_ZIP))

    assert raised.value.code == "SEVEN_ZIP_FAILED"
    assert len(raised.value.detail or "") == 8_192


@pytest.mark.parametrize("returncode", [1, 7, 8, 255])
def test_sevenzip_backend_maps_7zip_failure_exit_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, returncode: int
) -> None:
    executable = tmp_path / "7z.exe"
    executable.write_bytes(b"placeholder")
    archive_path = tmp_path / "book.7z"
    archive_path.write_bytes(b"placeholder")
    process = _stub_popen(monkeypatch, "diagnostic", returncode)

    with pytest.raises(InspectionFailure) as raised:
        SevenZipBackend(executable).inspect(snapshot(archive_path, ArchiveFormat.SEVEN_ZIP))

    assert raised.value.code == "SEVEN_ZIP_FAILED"
    assert process.wait_calls >= 1


def test_sevenzip_backend_maps_timeout_to_stable_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "7z.exe"
    executable.write_bytes(b"placeholder")
    archive_path = tmp_path / "book.7z"
    archive_path.write_bytes(b"placeholder")

    released = threading.Event()

    class BlockingOutput:
        def __init__(self) -> None:
            self.first_read = True

        def read(self, size: int = -1) -> bytes:
            if self.first_read:
                self.first_read = False
                return b"diagnostic"
            released.wait(timeout=5)
            return b""

        def close(self) -> None:
            released.set()

    class BlockingProcess(_FakeProcess):
        def __init__(self) -> None:
            super().__init__(b"", 0)
            self.stdout = BlockingOutput()

        def terminate(self) -> None:
            super().terminate()
            released.set()

    process = BlockingProcess()

    monkeypatch.setattr(sevenzip.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(InspectionFailure) as raised:
        SevenZipBackend(executable, timeout_seconds=0.01).inspect(
            snapshot(archive_path, ArchiveFormat.SEVEN_ZIP)
        )

    assert raised.value.code == "SEVEN_ZIP_FAILED"
    assert raised.value.detail == "diagnostic"
    assert process.terminated
    assert process.wait_calls >= 1


def test_sevenzip_backend_prioritizes_slt_encryption_over_returncode_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "7z.exe"
    executable.write_bytes(b"placeholder")
    archive_path = tmp_path / "book.7z"
    archive_path.write_bytes(b"placeholder")
    listing = "Path = page.jpg\nSize = 20\nEncrypted = +\n"
    process = _stub_popen(monkeypatch, listing, 2)

    with pytest.raises(InspectionFailure) as raised:
        SevenZipBackend(executable).inspect(snapshot(archive_path, ArchiveFormat.SEVEN_ZIP))

    assert raised.value.code == "ENCRYPTED_UNSUPPORTED"
    assert raised.value.detail == listing
    assert process.wait_calls >= 1


def test_sevenzip_backend_includes_bounded_detail_for_successful_encrypted_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "7z.exe"
    executable.write_bytes(b"placeholder")
    archive_path = tmp_path / "book.7z"
    archive_path.write_bytes(b"placeholder")
    listing = "Encrypted = +\n" + "x" * 9_000
    process = _stub_popen(monkeypatch, listing, 0)

    with pytest.raises(InspectionFailure) as raised:
        SevenZipBackend(executable).inspect(snapshot(archive_path, ArchiveFormat.SEVEN_ZIP))

    assert raised.value.code == "ENCRYPTED_UNSUPPORTED"
    assert len(raised.value.detail or "") == 8_192
    assert process.wait_calls >= 1


def test_sevenzip_backend_reaps_process_before_parser_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "7z.exe"
    executable.write_bytes(b"placeholder")
    archive_path = tmp_path / "book.7z"
    archive_path.write_bytes(b"placeholder")
    listing = (
        "Path = first.jpg\nSize = 1\n\n"
        "Path = second.jpg\nSize = 1\n"
    )
    monkeypatch.setattr(sevenzip, "MAX_ARCHIVE_ENTRIES", 1, raising=False)
    process = _stub_popen(monkeypatch, listing, 0)

    with pytest.raises(InspectionFailure) as raised:
        SevenZipBackend(executable).inspect(
            snapshot(archive_path, ArchiveFormat.SEVEN_ZIP)
        )

    assert raised.value.code == "ARCHIVE_LIMIT_EXCEEDED"
    assert process.wait_calls >= 1
    assert process.poll() == 0


def test_sevenzip_backend_rejects_oversized_streamed_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "7z.exe"
    executable.write_bytes(b"placeholder")
    archive_path = tmp_path / "book.7z"
    archive_path.write_bytes(b"placeholder")
    monkeypatch.setattr(sevenzip, "MAX_LISTING_BYTES", 1_024, raising=False)
    monkeypatch.setattr(sevenzip, "_PROCESS_READ_CHUNK_BYTES", 128, raising=False)

    class GeneratedOutput(io.RawIOBase):
        def __init__(self, total_bytes: int) -> None:
            self.remaining = total_bytes
            self.bytes_read = 0

        def read(self, size: int = -1) -> bytes:
            if self.remaining == 0:
                return b""
            requested = self.remaining if size < 0 else min(size, self.remaining)
            self.remaining -= requested
            self.bytes_read += requested
            return b"x" * requested

    class FakeProcess:
        def __init__(self) -> None:
            self.stdout = GeneratedOutput(40 * 1024 * 1024)
            self.returncode: int | None = None
            self.terminated = False
            self.killed = False
            self.wait_calls = 0

        def poll(self) -> int | None:
            return self.returncode

        def terminate(self) -> None:
            self.terminated = True

        def kill(self) -> None:
            self.killed = True
            self.returncode = -9

        def wait(self, timeout: float | None = None) -> int:
            self.wait_calls += 1
            if self.returncode is None:
                raise subprocess.TimeoutExpired([], timeout)
            return self.returncode

    process = FakeProcess()

    def popen(*args: object, **kwargs: object) -> FakeProcess:
        assert kwargs["stdout"] is subprocess.PIPE
        assert kwargs["stderr"] is subprocess.STDOUT
        return process

    monkeypatch.setattr(sevenzip.subprocess, "Popen", popen)
    monkeypatch.setattr(
        sevenzip.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("listing output must not use subprocess.run"),
    )

    with pytest.raises(InspectionFailure) as raised:
        SevenZipBackend(executable).inspect(snapshot(archive_path, ArchiveFormat.SEVEN_ZIP))

    assert raised.value.code == "ARCHIVE_LIMIT_EXCEEDED"
    assert process.terminated and process.killed
    assert process.wait_calls >= 1
    assert process.stdout.bytes_read <= 1_024 + 128
    print(
        "SEVEN_ZIP_STREAM_LIMIT "
        f"cap_bytes=1024 bytes_read={process.stdout.bytes_read} "
        f"terminated={process.terminated} killed={process.killed} "
        f"wait_calls={process.wait_calls}"
    )
