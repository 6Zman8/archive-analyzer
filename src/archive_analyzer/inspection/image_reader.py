import subprocess
import threading
import time
import zlib
from pathlib import Path, PurePosixPath, PureWindowsPath
from tempfile import TemporaryDirectory
from typing import BinaryIO, Callable, Iterator, Protocol
from zipfile import BadZipFile, ZipFile, ZipInfo

from archive_analyzer.classification import natural_sort_key
from archive_analyzer.domain import ArchiveFormat, FileSnapshot
from archive_analyzer.duplicate_domain import ImageEntryRef


MAX_IMAGE_BYTES = 128 * 1024 * 1024
_READ_CHUNK_BYTES = 1024 * 1024
_PROCESS_POLL_SECONDS = 0.05
_PROCESS_STOP_GRACE_SECONDS = 1.0
_MAX_ERROR_DETAIL_LENGTH = 8_192
_ENCRYPTION_MARKERS = (
    "wrong password",
    "encrypted archive",
    "enter password",
    "break signaled",
)


class ImageReadFailure(Exception):
    def __init__(self, code: str, summary: str, detail: str | None = None) -> None:
        super().__init__(f"{code}: {summary}")
        self.code = code
        self.summary = summary
        self.detail = detail


class ArchiveImageReader(Protocol):
    def read(
        self,
        snapshot: FileSnapshot,
        entry: ImageEntryRef,
        *,
        same_path_count: int = 1,
    ) -> bytes: ...

    def read_many(
        self,
        snapshot: FileSnapshot,
        requests: tuple[tuple[ImageEntryRef, int], ...],
        *,
        cancel_check: Callable[[], None] | None = None,
    ) -> Iterator[bytes | ImageReadFailure]: ...


class ZipImageReader:
    def read(
        self,
        snapshot: FileSnapshot,
        entry: ImageEntryRef,
        *,
        same_path_count: int = 1,
    ) -> bytes:
        if snapshot.archive_format not in {ArchiveFormat.ZIP, ArchiveFormat.CBZ}:
            raise ImageReadFailure(
                "UNSUPPORTED_FORMAT",
                "ZipImageReader only supports ZIP and CBZ archives.",
            )
        _require_unchanged_snapshot(snapshot)
        try:
            with ZipFile(snapshot.path) as archive:
                info = _zip_info_at_position(archive.infolist(), entry.position)
                _require_matching_zip_entry(info, entry)
                if info.flag_bits & 0x1:
                    raise ImageReadFailure(
                        "ENCRYPTED_UNSUPPORTED",
                        "Encrypted ZIP entries are not supported.",
                    )
                if info.file_size > MAX_IMAGE_BYTES:
                    raise _image_limit_failure()
                with archive.open(info) as stream:
                    payload = _read_bounded(stream)
        except ImageReadFailure:
            raise
        except (BadZipFile, zlib.error) as error:
            raise ImageReadFailure(
                "CORRUPT_ARCHIVE", "The ZIP archive cannot be read.", str(error)
            ) from error
        except FileNotFoundError as error:
            raise ImageReadFailure("FILE_NOT_FOUND", "Archive file was not found.", str(error)) from error
        except PermissionError as error:
            raise ImageReadFailure("ACCESS_DENIED", "Archive access was denied.", str(error)) from error
        except RuntimeError as error:
            if _signals_encryption(str(error)):
                raise ImageReadFailure(
                    "ENCRYPTED_UNSUPPORTED", "Encrypted ZIP entries are not supported."
                ) from error
            raise ImageReadFailure("CORRUPT_ARCHIVE", "The ZIP archive cannot be read.", str(error)) from error
        _require_unchanged_snapshot(snapshot)
        return payload

    def read_many(
        self,
        snapshot: FileSnapshot,
        requests: tuple[tuple[ImageEntryRef, int], ...],
        *,
        cancel_check: Callable[[], None] | None = None,
    ) -> Iterator[bytes | ImageReadFailure]:
        if snapshot.archive_format not in {ArchiveFormat.ZIP, ArchiveFormat.CBZ}:
            raise ImageReadFailure(
                "UNSUPPORTED_FORMAT",
                "ZipImageReader only supports ZIP and CBZ archives.",
            )
        _require_unchanged_snapshot(snapshot)
        try:
            with ZipFile(snapshot.path) as archive:
                infos = [info for info in archive.infolist() if not _is_directory(info)]
                infos.sort(key=lambda info: natural_sort_key(info.filename))
                for entry, _same_path_count in requests:
                    _run_cancel_check(cancel_check)
                    try:
                        info = _zip_info_from_sorted(infos, entry.position)
                        _require_matching_zip_entry(info, entry)
                        if info.flag_bits & 0x1:
                            raise ImageReadFailure(
                                "ENCRYPTED_UNSUPPORTED",
                                "Encrypted ZIP entries are not supported.",
                            )
                        if info.file_size > MAX_IMAGE_BYTES:
                            raise _image_limit_failure()
                        with archive.open(info) as stream:
                            payload = _read_bounded(stream)
                        _run_cancel_check(cancel_check)
                        yield payload
                    except ImageReadFailure as error:
                        yield error
        except ImageReadFailure:
            raise
        except (BadZipFile, zlib.error) as error:
            raise ImageReadFailure(
                "CORRUPT_ARCHIVE", "The ZIP archive cannot be read.", str(error)
            ) from error
        except FileNotFoundError as error:
            raise ImageReadFailure(
                "FILE_NOT_FOUND", "Archive file was not found.", str(error)
            ) from error
        except PermissionError as error:
            raise ImageReadFailure(
                "ACCESS_DENIED", "Archive access was denied.", str(error)
            ) from error
        except RuntimeError as error:
            if _signals_encryption(str(error)):
                raise ImageReadFailure(
                    "ENCRYPTED_UNSUPPORTED", "Encrypted ZIP entries are not supported."
                ) from error
            raise ImageReadFailure(
                "CORRUPT_ARCHIVE", "The ZIP archive cannot be read.", str(error)
            ) from error
        _require_unchanged_snapshot(snapshot)


class SevenZipImageReader:
    def __init__(
        self,
        executable: Path,
        timeout_seconds: float = 60.0,
        *,
        process_runner: Callable[..., object] | None = None,
    ) -> None:
        self.executable = executable
        self.timeout_seconds = timeout_seconds
        self._process_runner = process_runner or subprocess.Popen

    def read(
        self,
        snapshot: FileSnapshot,
        entry: ImageEntryRef,
        *,
        same_path_count: int = 1,
    ) -> bytes:
        if snapshot.archive_format not in {ArchiveFormat.RAR, ArchiveFormat.SEVEN_ZIP}:
            raise ImageReadFailure(
                "UNSUPPORTED_FORMAT",
                "SevenZipImageReader only supports RAR and 7z archives.",
            )
        if same_path_count != 1:
            raise ImageReadFailure(
                "AMBIGUOUS_ENTRY_NAME",
                "7-Zip cannot safely select a duplicate entry name.",
            )
        _require_unchanged_snapshot(snapshot)
        if not self.executable.is_file():
            raise ImageReadFailure(
                "SEVEN_ZIP_NOT_FOUND",
                "7-Zip executable was not found.",
                str(self.executable)[:_MAX_ERROR_DETAIL_LENGTH],
            )
        if entry.uncompressed_size is not None and entry.uncompressed_size > MAX_IMAGE_BYTES:
            raise _image_limit_failure()

        command = [
            str(self.executable),
            "x",
            "-so",
            "-bd",
            "-bb0",
            "-y",
            "-spd",
            "--",
            str(snapshot.path),
            entry.path,
        ]
        returncode, payload, diagnostics = _run_selected_entry_process(
            command, timeout_seconds=self.timeout_seconds
        )
        if _signals_encryption(diagnostics):
            raise ImageReadFailure(
                "ENCRYPTED_UNSUPPORTED",
                "Encrypted archives are not supported.",
                _bounded_detail(diagnostics),
            )
        if returncode == 2:
            raise ImageReadFailure(
                "CORRUPT_ARCHIVE",
                "The archive cannot be read by 7-Zip.",
                _bounded_detail(diagnostics),
            )
        if returncode != 0:
            raise ImageReadFailure(
                "SEVEN_ZIP_FAILED",
                "7-Zip image extraction failed.",
                _bounded_detail(diagnostics),
            )
        _require_matching_payload_metadata(payload, entry)
        if not payload:
            raise ImageReadFailure(
                "ENTRY_CHANGED",
                "The indexed archive entry is no longer available.",
                _bounded_detail(diagnostics),
            )
        _require_unchanged_snapshot(snapshot)
        return payload

    def read_many(
        self,
        snapshot: FileSnapshot,
        requests: tuple[tuple[ImageEntryRef, int], ...],
        *,
        cancel_check: Callable[[], None] | None = None,
    ) -> Iterator[bytes | ImageReadFailure]:
        if snapshot.archive_format not in {ArchiveFormat.RAR, ArchiveFormat.SEVEN_ZIP}:
            raise ImageReadFailure(
                "UNSUPPORTED_FORMAT",
                "SevenZipImageReader only supports RAR and 7z archives.",
            )
        if not requests:
            return
        _require_unchanged_snapshot(snapshot)
        if not self.executable.is_file():
            raise ImageReadFailure(
                "SEVEN_ZIP_NOT_FOUND",
                "7-Zip executable was not found.",
                str(self.executable)[:_MAX_ERROR_DETAIL_LENGTH],
            )

        selected: list[tuple[ImageEntryRef, tuple[str, ...]]] = []
        normalized_paths: set[str] = set()
        for entry, same_path_count in requests:
            if same_path_count != 1:
                raise ImageReadFailure(
                    "AMBIGUOUS_ENTRY_NAME",
                    "7-Zip cannot safely select a duplicate entry name.",
                )
            if (
                entry.uncompressed_size is not None
                and entry.uncompressed_size > MAX_IMAGE_BYTES
            ):
                raise _image_limit_failure()
            parts, normalized = _safe_extraction_parts(entry.path)
            if normalized in normalized_paths:
                raise ImageReadFailure(
                    "AMBIGUOUS_ENTRY_NAME",
                    "7-Zip cannot safely select a duplicate entry name.",
                )
            normalized_paths.add(normalized)
            selected.append((entry, parts))

        _run_cancel_check(cancel_check)
        with TemporaryDirectory(prefix="archive-analyzer-pages-") as temporary:
            temporary_root = Path(temporary).resolve()
            command = [
                str(self.executable),
                "x",
                "-bd",
                "-bb0",
                "-y",
                "-spe",
                "-spd",
                f"-o{temporary_root}",
                "--",
                str(snapshot.path),
                *(entry.path for entry, _parts in selected),
            ]
            returncode, diagnostics = _run_extraction_process(
                command,
                timeout_seconds=self.timeout_seconds,
                cancel_check=cancel_check,
                process_runner=self._process_runner,
            )
            if _signals_encryption(diagnostics):
                raise ImageReadFailure(
                    "ENCRYPTED_UNSUPPORTED",
                    "Encrypted archives are not supported.",
                    _bounded_detail(diagnostics),
                )
            if returncode == 2:
                raise ImageReadFailure(
                    "CORRUPT_ARCHIVE",
                    "The archive cannot be read by 7-Zip.",
                    _bounded_detail(diagnostics),
                )
            if returncode != 0:
                raise ImageReadFailure(
                    "SEVEN_ZIP_FAILED",
                    "7-Zip image extraction failed.",
                    _bounded_detail(diagnostics),
                )

            _require_unchanged_snapshot(snapshot)
            for entry, parts in selected:
                _run_cancel_check(cancel_check)
                output_path = temporary_root.joinpath(*parts).resolve(strict=False)
                if not output_path.is_relative_to(temporary_root):
                    raise ImageReadFailure(
                        "UNSAFE_ENTRY_PATH",
                        "The archive entry path is not safe to extract.",
                    )
                try:
                    if not output_path.is_file():
                        raise ImageReadFailure(
                            "ENTRY_CHANGED",
                            "The indexed archive entry is no longer available.",
                        )
                    if output_path.stat().st_size > MAX_IMAGE_BYTES:
                        raise _image_limit_failure()
                    with output_path.open("rb") as stream:
                        payload = _read_bounded(stream)
                    _require_matching_payload_metadata(payload, entry)
                except ImageReadFailure as error:
                    yield error
                    continue
                except FileNotFoundError:
                    yield ImageReadFailure(
                        "ENTRY_CHANGED",
                        "The indexed archive entry is no longer available.",
                    )
                    continue
                except PermissionError as error:
                    yield ImageReadFailure(
                        "ACCESS_DENIED",
                        "Extracted image access was denied.",
                        _bounded_detail(str(error)),
                    )
                    continue
                _run_cancel_check(cancel_check)
                yield payload


class DispatchingImageReader:
    def __init__(self, seven_zip: Path, timeout_seconds: float = 60.0) -> None:
        self._zip_reader = ZipImageReader()
        self._sevenzip_reader = SevenZipImageReader(seven_zip, timeout_seconds)

    def read(
        self,
        snapshot: FileSnapshot,
        entry: ImageEntryRef,
        *,
        same_path_count: int = 1,
    ) -> bytes:
        if snapshot.archive_format in {ArchiveFormat.ZIP, ArchiveFormat.CBZ}:
            return self._zip_reader.read(snapshot, entry, same_path_count=same_path_count)
        if snapshot.archive_format in {ArchiveFormat.RAR, ArchiveFormat.SEVEN_ZIP}:
            return self._sevenzip_reader.read(snapshot, entry, same_path_count=same_path_count)
        raise ImageReadFailure(
            "UNSUPPORTED_FORMAT",
            "This archive format is not supported for image reading.",
        )

    def read_many(
        self,
        snapshot: FileSnapshot,
        requests: tuple[tuple[ImageEntryRef, int], ...],
        *,
        cancel_check: Callable[[], None] | None = None,
    ) -> Iterator[bytes | ImageReadFailure]:
        if snapshot.archive_format in {ArchiveFormat.ZIP, ArchiveFormat.CBZ}:
            return self._zip_reader.read_many(
                snapshot, requests, cancel_check=cancel_check
            )
        if snapshot.archive_format in {ArchiveFormat.RAR, ArchiveFormat.SEVEN_ZIP}:
            return self._sevenzip_reader.read_many(
                snapshot, requests, cancel_check=cancel_check
            )
        raise ImageReadFailure(
            "UNSUPPORTED_FORMAT",
            "This archive format is not supported for image reading.",
        )


def _safe_extraction_parts(value: str) -> tuple[tuple[str, ...], str]:
    if not value or "\x00" in value:
        raise ImageReadFailure(
            "UNSAFE_ENTRY_PATH", "The archive entry path is not safe to extract."
        )
    windows = PureWindowsPath(value)
    posix = PurePosixPath(value.replace("\\", "/"))
    if windows.drive or windows.root or posix.is_absolute():
        raise ImageReadFailure(
            "UNSAFE_ENTRY_PATH", "The archive entry path is not safe to extract."
        )
    parts = tuple(part for part in value.replace("\\", "/").split("/") if part)
    if (
        not parts
        or any(part in {".", ".."} for part in parts)
        or any(":" in part for part in parts)
    ):
        raise ImageReadFailure(
            "UNSAFE_ENTRY_PATH", "The archive entry path is not safe to extract."
        )
    return parts, "/".join(part.casefold() for part in parts)


def _run_cancel_check(cancel_check: Callable[[], None] | None) -> None:
    if cancel_check is not None:
        cancel_check()


def _run_extraction_process(
    command: list[str],
    *,
    timeout_seconds: float,
    cancel_check: Callable[[], None] | None,
    process_runner: Callable[..., object],
) -> tuple[int, str]:
    try:
        process = process_runner(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except FileNotFoundError as error:
        raise ImageReadFailure(
            "SEVEN_ZIP_NOT_FOUND", "7-Zip executable was not found.", str(error)
        ) from error
    except OSError as error:
        raise ImageReadFailure(
            "SEVEN_ZIP_FAILED",
            "7-Zip image extraction failed.",
            _bounded_detail(str(error)),
        ) from error

    output = getattr(process, "stdout", None)
    if output is None:
        _stop_and_reap(process)  # type: ignore[arg-type]
        raise ImageReadFailure(
            "SEVEN_ZIP_FAILED", "7-Zip image extraction produced no diagnostics stream."
        )
    diagnostics = bytearray()
    output_finished = threading.Event()
    read_errors: list[BaseException] = []

    def read_output() -> None:
        try:
            while True:
                chunk = output.read(_READ_CHUNK_BYTES)
                if not chunk:
                    return
                remaining = _MAX_ERROR_DETAIL_LENGTH - len(diagnostics)
                if remaining > 0:
                    diagnostics.extend(chunk[:remaining])
        except BaseException as error:
            read_errors.append(error)
        finally:
            output_finished.set()

    output_thread = threading.Thread(
        target=read_output,
        name="archive-analyzer-7zip-batch-output",
        daemon=True,
    )
    output_thread_started = False
    try:
        try:
            output_thread.start()
            output_thread_started = True
        except RuntimeError as error:
            raise ImageReadFailure(
                "SEVEN_ZIP_FAILED",
                "7-Zip image extraction failed to start.",
                _bounded_detail(str(error)),
            ) from error
        deadline = time.monotonic() + timeout_seconds
        returncode: int | None = None
        while returncode is None:
            _run_cancel_check(cancel_check)
            returncode = process.poll()  # type: ignore[attr-defined]
            if returncode is not None:
                break
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise ImageReadFailure(
                    "SEVEN_ZIP_FAILED",
                    "7-Zip image extraction timed out.",
                    _bounded_bytes_detail(diagnostics),
                )
            output_finished.wait(
                timeout=min(_PROCESS_POLL_SECONDS, remaining_seconds)
            )
        _run_cancel_check(cancel_check)
        remaining_seconds = max(0.0, deadline - time.monotonic())
        if not output_finished.wait(timeout=remaining_seconds):
            raise ImageReadFailure(
                "SEVEN_ZIP_FAILED",
                "7-Zip image extraction timed out.",
                _bounded_bytes_detail(diagnostics),
            )
        if read_errors:
            raise ImageReadFailure(
                "SEVEN_ZIP_FAILED",
                "7-Zip image extraction failed.",
                _bounded_detail(str(read_errors[0])),
            ) from read_errors[0]
        return int(returncode), _bounded_bytes_detail(diagnostics)
    finally:
        if process.poll() is None:  # type: ignore[attr-defined]
            _stop_and_reap(process)  # type: ignore[arg-type]
        try:
            output.close()
        except OSError:
            pass
        if output_thread_started:
            output_thread.join(timeout=_PROCESS_STOP_GRACE_SECONDS)


def _require_unchanged_snapshot(snapshot: FileSnapshot) -> None:
    try:
        current = snapshot.path.stat()
    except FileNotFoundError as error:
        raise ImageReadFailure("FILE_NOT_FOUND", "Archive file was not found.", str(error)) from error
    except PermissionError as error:
        raise ImageReadFailure("ACCESS_DENIED", "Archive access was denied.", str(error)) from error
    if current.st_size != snapshot.size or current.st_mtime_ns != snapshot.mtime_ns:
        raise ImageReadFailure(
            "ARCHIVE_CHANGED",
            "Archive changed since it was indexed.",
        )


def _zip_info_at_position(infos: list[ZipInfo], position: int) -> ZipInfo:
    entries = [info for info in infos if not _is_directory(info)]
    entries.sort(key=lambda info: natural_sort_key(info.filename))
    return _zip_info_from_sorted(entries, position)


def _zip_info_from_sorted(entries: list[ZipInfo], position: int) -> ZipInfo:
    if position < 0:
        raise ImageReadFailure(
            "ENTRY_CHANGED", "The indexed archive entry is no longer available."
        )
    try:
        return entries[position]
    except IndexError as error:
        raise ImageReadFailure(
            "ENTRY_CHANGED", "The indexed archive entry is no longer available."
        ) from error


def _is_directory(info: ZipInfo) -> bool:
    return info.is_dir() or info.filename.endswith(("/", "\\"))


def _require_matching_zip_entry(info: ZipInfo, entry: ImageEntryRef) -> None:
    actual_crc = None if info.CRC is None else f"{info.CRC:08x}"
    if (
        info.filename != entry.path
        or (entry.uncompressed_size is not None and info.file_size != entry.uncompressed_size)
        or not _crc_matches(actual_crc, entry.crc)
    ):
        raise ImageReadFailure("ENTRY_CHANGED", "The indexed archive entry changed.")


def _require_matching_payload_metadata(payload: bytes, entry: ImageEntryRef) -> None:
    actual_crc = f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}"
    if (
        entry.uncompressed_size is not None and len(payload) != entry.uncompressed_size
    ) or not _crc_matches(actual_crc, entry.crc):
        raise ImageReadFailure("ENTRY_CHANGED", "The indexed archive entry changed.")


def _crc_matches(actual: str | None, expected: str | None) -> bool:
    if expected is None:
        return True
    normalized_expected = _normalize_crc(expected)
    return normalized_expected is not None and actual == normalized_expected


def _normalize_crc(value: str) -> str | None:
    hexadecimal = value.strip()
    if hexadecimal.casefold().startswith("0x"):
        hexadecimal = hexadecimal[2:]
    if not hexadecimal or len(hexadecimal) > 8:
        return None
    if any(character not in "0123456789abcdefABCDEF" for character in hexadecimal):
        return None
    return f"{int(hexadecimal, 16):08x}"


def _read_bounded(stream: BinaryIO) -> bytes:
    payload = bytearray()
    while len(payload) <= MAX_IMAGE_BYTES:
        chunk = stream.read(min(_READ_CHUNK_BYTES, MAX_IMAGE_BYTES + 1 - len(payload)))
        if not chunk:
            return bytes(payload)
        payload.extend(chunk)
    raise _image_limit_failure()


def _run_selected_entry_process(
    command: list[str], *, timeout_seconds: float
) -> tuple[int, bytes, str]:
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except FileNotFoundError as error:
        raise ImageReadFailure(
            "SEVEN_ZIP_NOT_FOUND", "7-Zip executable was not found.", str(error)
        ) from error
    except OSError as error:
        raise ImageReadFailure(
            "SEVEN_ZIP_FAILED", "7-Zip image extraction failed.", _bounded_detail(str(error))
        ) from error

    stdout = process.stdout
    stderr = process.stderr
    assert stdout is not None
    assert stderr is not None
    payload = bytearray()
    diagnostics = bytearray()
    output_finished = threading.Event()
    error_finished = threading.Event()
    limit_exceeded = threading.Event()
    read_errors: list[BaseException] = []

    def read_output() -> None:
        try:
            while True:
                remaining = MAX_IMAGE_BYTES + 1 - len(payload)
                if remaining <= 0:
                    limit_exceeded.set()
                    return
                chunk = stdout.read(min(_READ_CHUNK_BYTES, remaining))
                if not chunk:
                    return
                payload.extend(chunk)
                if len(payload) > MAX_IMAGE_BYTES:
                    limit_exceeded.set()
                    return
        except BaseException as error:
            read_errors.append(error)
        finally:
            output_finished.set()

    def read_error() -> None:
        try:
            while True:
                chunk = stderr.read(_READ_CHUNK_BYTES)
                if not chunk:
                    return
                remaining = _MAX_ERROR_DETAIL_LENGTH - len(diagnostics)
                if remaining > 0:
                    diagnostics.extend(chunk[:remaining])
        except BaseException as error:
            read_errors.append(error)
        finally:
            error_finished.set()

    output_thread = threading.Thread(target=read_output, name="archive-analyzer-7zip-image", daemon=True)
    error_thread = threading.Thread(target=read_error, name="archive-analyzer-7zip-errors", daemon=True)
    output_thread_started = False
    error_thread_started = False
    try:
        try:
            output_thread.start()
            output_thread_started = True
        except RuntimeError as error:
            raise ImageReadFailure(
                "SEVEN_ZIP_FAILED",
                "7-Zip image extraction failed to start.",
                _bounded_detail(str(error)),
            ) from error
        try:
            error_thread.start()
            error_thread_started = True
        except RuntimeError as error:
            raise ImageReadFailure(
                "SEVEN_ZIP_FAILED",
                "7-Zip image extraction failed to start.",
                _bounded_detail(str(error)),
            ) from error
        deadline = time.monotonic() + timeout_seconds
        while not (output_finished.is_set() and error_finished.is_set()):
            if limit_exceeded.is_set():
                _stop_and_reap(process)
                raise _image_limit_failure()
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                _stop_and_reap(process)
                raise ImageReadFailure(
                    "SEVEN_ZIP_FAILED",
                    "7-Zip image extraction timed out.",
                    _bounded_bytes_detail(diagnostics),
                )
            output_finished.wait(timeout=min(_PROCESS_POLL_SECONDS, remaining_seconds))
            error_finished.wait(timeout=0)
        if limit_exceeded.is_set():
            _stop_and_reap(process)
            raise _image_limit_failure()
        if read_errors:
            _stop_and_reap(process)
            raise ImageReadFailure(
                "SEVEN_ZIP_FAILED",
                "7-Zip image extraction failed.",
                _bounded_detail(str(read_errors[0])),
            ) from read_errors[0]
        try:
            returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            _stop_and_reap(process)
            raise ImageReadFailure(
                "SEVEN_ZIP_FAILED",
                "7-Zip image extraction timed out.",
                _bounded_bytes_detail(diagnostics),
            ) from error
        return returncode, bytes(payload), _bounded_bytes_detail(diagnostics)
    finally:
        if process.poll() is None:
            _stop_and_reap(process)
        for stream in (stdout, stderr):
            try:
                stream.close()
            except OSError:
                pass
        if output_thread_started:
            output_thread.join(timeout=_PROCESS_STOP_GRACE_SECONDS)
        if error_thread_started:
            error_thread.join(timeout=_PROCESS_STOP_GRACE_SECONDS)


def _stop_and_reap(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            process.terminate()
        except OSError:
            pass
    try:
        process.wait(timeout=_PROCESS_STOP_GRACE_SECONDS)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=_PROCESS_STOP_GRACE_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _image_limit_failure() -> ImageReadFailure:
    return ImageReadFailure("IMAGE_BYTE_LIMIT", "Image data exceeds the byte limit.")


def _signals_encryption(value: str) -> bool:
    lowered = value.casefold()
    return any(marker in lowered for marker in _ENCRYPTION_MARKERS)


def _bounded_detail(value: str) -> str:
    return value[:_MAX_ERROR_DETAIL_LENGTH]


def _bounded_bytes_detail(value: bytearray) -> str:
    return bytes(value).decode("utf-8", errors="replace")
