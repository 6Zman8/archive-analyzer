import io
import subprocess
import threading
import time
from pathlib import Path

from archive_analyzer.classification import (
    classify_entry,
    natural_sort_key,
    normalize_entry_path,
    serialize_natural_sort_key,
)
from archive_analyzer.domain import ArchiveFormat, EntryKind, FileSnapshot
from archive_analyzer.inspection.base import (
    MAX_ARCHIVE_ENTRIES,
    MAX_LISTING_BYTES,
    ArchiveEntry,
    InspectionFailure,
    InspectionResult,
)
from archive_analyzer.inspection.zip_backend import listing_signature


_MAX_ERROR_DETAIL_LENGTH = 8_192
_ENCRYPTION_MARKERS = ("wrong password", "encrypted archive", "enter password")
_PROCESS_READ_CHUNK_BYTES = 64 * 1024
_PROCESS_POLL_SECONDS = 0.05
_PROCESS_STOP_GRACE_SECONDS = 1.0


class SevenZipBackend:
    def __init__(
        self,
        executable: Path,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def inspect(self, snapshot: FileSnapshot) -> InspectionResult:
        if snapshot.archive_format not in {ArchiveFormat.RAR, ArchiveFormat.SEVEN_ZIP}:
            raise InspectionFailure(
                "UNSUPPORTED_FORMAT",
                "SevenZipBackend only supports RAR and 7z archives.",
                str(snapshot.archive_format),
            )
        if not self.executable.is_file():
            raise InspectionFailure(
                "SEVEN_ZIP_NOT_FOUND",
                "7-Zip executable was not found.",
                _bounded_detail(str(self.executable)),
            )

        command = [
            str(self.executable),
            "l",
            "-slt",
            "-ba",
            "-sccUTF-8",
            "-p-",
            "--",
            str(snapshot.path),
        ]
        returncode, output = _run_listing_process(
            command, timeout_seconds=self.timeout_seconds
        )

        if _signals_encryption(output):
            raise InspectionFailure(
                "ENCRYPTED_UNSUPPORTED",
                "Encrypted archives are not supported.",
                _bounded_detail(output),
            )
        if returncode == 2:
            raise InspectionFailure(
                "CORRUPT_ARCHIVE",
                "The archive cannot be read by 7-Zip.",
                _bounded_detail(output),
            )
        if returncode != 0:
            raise InspectionFailure(
                "SEVEN_ZIP_FAILED",
                "7-Zip inspection failed.",
                _bounded_detail(output),
            )

        return parse_slt_listing(output, snapshot.archive_format)


def parse_slt_listing(text: str, archive_format: ArchiveFormat) -> InspectionResult:
    if len(text.encode("utf-8")) > MAX_LISTING_BYTES:
        raise _archive_limit_failure()
    entries: list[dict[str, object]] = []
    record: dict[str, str] = {}
    for raw_line in io.StringIO(text):
        line = raw_line.rstrip("\r\n")
        if line:
            if " = " in line:
                key, value = line.split(" = ", 1)
                record[key] = value
            continue
        _append_record_entry(record, entries)
        record = {}
    _append_record_entry(record, entries)
    entries.sort(key=lambda entry: natural_sort_key(str(entry["path"])))
    positioned_entries = tuple(
        ArchiveEntry(position=index, **entry) for index, entry in enumerate(entries)
    )
    return InspectionResult(
        archive_format=archive_format,
        entries=positioned_entries,
        image_count=sum(entry.kind is EntryKind.IMAGE for entry in positioned_entries),
        nested_archive_count=sum(
            entry.kind is EntryKind.NESTED_ARCHIVE for entry in positioned_entries
        ),
        listing_signature=listing_signature(positioned_entries),
    )


def _append_record_entry(
    record: dict[str, str], entries: list[dict[str, object]]
) -> None:
    if record.get("Encrypted") == "+":
        raise InspectionFailure(
            "ENCRYPTED_UNSUPPORTED",
            "Encrypted archives are not supported.",
        )
    if not _is_entry_record(record):
        return
    entry = _entry_from_record(record)
    if entry is None:
        return
    entries.append(entry)
    if len(entries) > MAX_ARCHIVE_ENTRIES:
        raise _archive_limit_failure()


def _run_listing_process(
    command: list[str], *, timeout_seconds: float
) -> tuple[int, str]:
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except FileNotFoundError as error:
        raise InspectionFailure(
            "SEVEN_ZIP_NOT_FOUND",
            "7-Zip executable was not found.",
            _bounded_detail(str(error)),
        ) from error
    except OSError as error:
        raise InspectionFailure(
            "SEVEN_ZIP_FAILED", "7-Zip inspection failed.", _bounded_detail(str(error))
        ) from error

    output_stream = process.stdout
    assert output_stream is not None
    captured = bytearray()
    read_finished = threading.Event()
    limit_exceeded = threading.Event()
    read_errors: list[BaseException] = []

    def read_output() -> None:
        try:
            while True:
                chunk = output_stream.read(_PROCESS_READ_CHUNK_BYTES)
                if not chunk:
                    return
                remaining = MAX_LISTING_BYTES + 1 - len(captured)
                if remaining > 0:
                    captured.extend(chunk[:remaining])
                if len(captured) > MAX_LISTING_BYTES:
                    limit_exceeded.set()
                    return
        except BaseException as error:
            read_errors.append(error)
        finally:
            read_finished.set()

    reader = threading.Thread(
        target=read_output, name="archive-analyzer-7zip-output", daemon=True
    )
    try:
        reader.start()
    except RuntimeError as error:
        _stop_and_reap(process)
        output_stream.close()
        raise InspectionFailure(
            "SEVEN_ZIP_FAILED",
            "7-Zip inspection failed.",
            _bounded_detail(str(error)),
        ) from error
    deadline = time.monotonic() + timeout_seconds
    try:
        while not read_finished.is_set():
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                _stop_and_reap(process)
                reader.join(timeout=_PROCESS_STOP_GRACE_SECONDS)
                raise InspectionFailure(
                    "SEVEN_ZIP_FAILED",
                    "7-Zip inspection timed out.",
                    _bounded_bytes_detail(captured),
                )
            read_finished.wait(
                timeout=min(_PROCESS_POLL_SECONDS, remaining_seconds)
            )

        if limit_exceeded.is_set():
            _stop_and_reap(process)
            reader.join(timeout=_PROCESS_STOP_GRACE_SECONDS)
            raise _archive_limit_failure()
        if read_errors:
            _stop_and_reap(process)
            reader.join(timeout=_PROCESS_STOP_GRACE_SECONDS)
            raise InspectionFailure(
                "SEVEN_ZIP_FAILED",
                "7-Zip inspection failed.",
                _bounded_detail(str(read_errors[0])),
            ) from read_errors[0]

        remaining_seconds = max(0.0, deadline - time.monotonic())
        try:
            returncode = process.wait(timeout=remaining_seconds)
        except subprocess.TimeoutExpired as error:
            _stop_and_reap(process)
            reader.join(timeout=_PROCESS_STOP_GRACE_SECONDS)
            raise InspectionFailure(
                "SEVEN_ZIP_FAILED",
                "7-Zip inspection timed out.",
                _bounded_bytes_detail(captured),
            ) from error
        return returncode, bytes(captured).decode("utf-8", errors="replace")
    finally:
        if process.poll() is None:
            _stop_and_reap(process)
        reader.join(timeout=_PROCESS_STOP_GRACE_SECONDS)
        try:
            output_stream.close()
        except OSError:
            pass
        reader.join(timeout=_PROCESS_STOP_GRACE_SECONDS)


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


def _bounded_bytes_detail(value: bytearray) -> str:
    return bytes(value[:_MAX_ERROR_DETAIL_LENGTH]).decode("utf-8", errors="replace")


def _archive_limit_failure() -> InspectionFailure:
    return InspectionFailure(
        "ARCHIVE_LIMIT_EXCEEDED",
        "Archive listing exceeds the V0 safety limits.",
        f"maximum entries={MAX_ARCHIVE_ENTRIES}; maximum listing bytes={MAX_LISTING_BYTES}",
    )


def _is_entry_record(record: dict[str, str]) -> bool:
    return "Path" in record and "Size" in record


def _entry_from_record(record: dict[str, str]) -> dict[str, object] | None:
    path = record["Path"]
    if _is_directory(record, path):
        return None
    kind, image_format_hint = classify_entry(path)
    return {
        "path": path,
        "normalized_path": normalize_entry_path(path),
        "sort_key": serialize_natural_sort_key(path),
        "uncompressed_size": _parse_optional_integer(record.get("Size")),
        "compressed_size": _parse_optional_integer(record.get("Packed Size")),
        "crc": _parse_optional_string(record.get("CRC")),
        "kind": kind,
        "image_format_hint": image_format_hint,
    }


def _is_directory(record: dict[str, str], path: str) -> bool:
    return path.endswith(("/", "\\")) or record.get("Folder") == "+" or "D" in record.get(
        "Attributes", ""
    )


def _parse_optional_integer(value: str | None) -> int | None:
    if value is None or not value.isdecimal():
        return None
    return int(value)


def _parse_optional_string(value: str | None) -> str | None:
    return None if value in {None, "", "-"} else value


def _signals_encryption(output: str) -> bool:
    lowered_output = output.casefold()
    return any(marker in lowered_output for marker in _ENCRYPTION_MARKERS) or any(
        line.strip().casefold() == "encrypted = +" for line in output.splitlines()
    )


def _bounded_detail(value: str) -> str:
    return value[:_MAX_ERROR_DETAIL_LENGTH]
