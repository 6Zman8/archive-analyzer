"""Separate-process EXE replacement; never opens a user's database."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from archive_analyzer.paths import has_reparse_point_in_existing_chain
from archive_analyzer.updates import ASSET_NAME, UpdateError, file_sha256, version_tuple, write_json


@dataclass(frozen=True)
class InstallJob:
    target: Path
    source: Path
    version: str
    sha256: str
    old_sha256: str
    parent_pids: tuple[int, ...]

    def write(self) -> Path:
        path = self.source.parent / "install.json"
        value = asdict(self)
        value.update(target=str(self.target), source=str(self.source))
        write_json(path, value)
        return path

    @classmethod
    def read(cls, path: Path) -> InstallJob:
        if path.stat().st_size > 16384:
            raise UpdateError("업데이트 작업 정보가 너무 큽니다.")
        value = json.loads(path.read_text(encoding="utf-8"))
        job = cls(Path(value["target"]), Path(value["source"]), value["version"],
                  value["sha256"], value["old_sha256"], tuple(value["parent_pids"]))
        if job.source != path.absolute().parent / ASSET_NAME:
            raise UpdateError("업데이트 파일 경로가 올바르지 않습니다.")
        job.validate()
        return job

    def validate(self) -> None:
        import re
        version_tuple(self.version)
        if (not self.source.is_absolute() or not self.target.is_absolute()
                or self.source.name != ASSET_NAME or self.target.suffix.lower() != ".exe"
                or self.source.parent == self.target.parent
                or has_reparse_point_in_existing_chain(self.source)
                or has_reparse_point_in_existing_chain(self.target)
                or not all(isinstance(h, str) and re.fullmatch("[0-9a-f]{64}", h)
                           for h in (self.sha256, self.old_sha256))
                or len(self.parent_pids) > 2
                or not all(type(pid) is int and 0 < pid < 2**32 for pid in self.parent_pids)):
            raise UpdateError("업데이트 경로 또는 검증 정보가 올바르지 않습니다.")


def subprocess_options() -> dict:
    options = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
               "stderr": subprocess.DEVNULL,
               "env": {**os.environ, "PYINSTALLER_RESET_ENVIRONMENT": "1"}}
    if os.name == "nt":
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0
        options.update(creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=startup)
    return options


def health_probe(executable: Path, version: str) -> bool:
    with tempfile.TemporaryDirectory(prefix="archive-update-probe-") as directory:
        report = Path(directory) / "health.json"
        try:
            result = subprocess.run([str(executable), "--update-health-check", str(report)],
                                    timeout=120, **subprocess_options())
            data = json.loads(report.read_text(encoding="utf-8"))
            return result.returncode == 0 and data == {"version": version, "healthy": True}
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return False


def write_health_report(path: Path) -> int:
    from archive_analyzer.version import __version__
    from archive_analyzer.desktop import _verify_packaged_ocr_assets
    from archive_analyzer.storage.repository import LATEST_SCHEMA_VERSION
    import tkinter as tk
    root = tk.Tk()
    root.withdraw()
    try:
        root.update_idletasks()
        assets_ok, _ = _verify_packaged_ocr_assets()
        migrations = Path(__file__).parent / "storage" / "migrations"
        healthy = assets_ok and all((migrations / f"{i:03d}.sql").is_file()
                                    for i in range(1, LATEST_SCHEMA_VERSION + 1))
        write_json(path, {"version": __version__, "healthy": bool(healthy)})
        return 0 if healthy else 1
    finally:
        root.destroy()


def wait_for_parents(pids: tuple[int, ...], timeout: int = 300) -> None:
    if not pids:
        return
    if os.name != "nt":
        raise UpdateError("자동 교체는 Windows에서만 지원합니다.")
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    deadline = time.monotonic() + timeout
    # Handles remain tied to the original processes even when a PID is reused.
    handles = []
    try:
        for pid in pids:
            handle = kernel.OpenProcess(0x00100000, False, pid)
            if not handle:
                if ctypes.get_last_error() != 87:  # ERROR_INVALID_PARAMETER: exited
                    raise UpdateError("실행 중인 프로그램의 종료를 확인하지 못했습니다.")
            else:
                handles.append(handle)
        for handle in handles:
            remaining = max(0, int((deadline - time.monotonic()) * 1000))
            if kernel.WaitForSingleObject(handle, remaining) != 0:
                raise UpdateError("프로그램이 아직 실행 중입니다. 다음에 다시 업데이트해 주세요.")
    finally:
        for handle in handles:
            kernel.CloseHandle(handle)


def _copy_exclusive(source: Path, target: Path) -> None:
    with source.open("rb") as incoming, target.open("xb") as output:
        shutil.copyfileobj(incoming, output, 1024 * 1024)
        output.flush()
        os.fsync(output.fileno())


def apply_update(job: InstallJob, *, probe: Callable[[Path, str], bool] = health_probe) -> dict:
    stage = job.source.parent
    backup = stage / "previous.exe"
    incoming: Path | None = None
    replaced = False
    result = {"version": job.version, "status": "failed", "message": ""}
    try:
        job.validate()
        wait_for_parents(job.parent_pids)
        if file_sha256(job.source) != job.sha256 or file_sha256(job.target) != job.old_sha256:
            raise UpdateError("실행파일이 바뀌어 업데이트를 적용하지 않았습니다.")
        if not probe(job.source, job.version):
            raise UpdateError("새 프로그램의 기동 검사에 실패했습니다.")
        handle, name = tempfile.mkstemp(prefix=".archive-update-", suffix=".exe", dir=job.target.parent)
        os.close(handle)
        incoming = Path(name)
        shutil.copyfile(job.source, incoming)
        if file_sha256(incoming) != job.sha256:
            raise UpdateError("복사한 업데이트 파일 검증에 실패했습니다.")
        _copy_exclusive(job.target, backup)
        if file_sha256(backup) != job.old_sha256 or file_sha256(job.target) != job.old_sha256:
            raise UpdateError("기존 프로그램이 변경되어 교체를 중단했습니다.")
        os.replace(incoming, job.target)
        replaced = True
        if not probe(job.target, job.version):
            raise UpdateError("교체한 프로그램을 시작하지 못해 이전 버전으로 복구했습니다.")
        result.update(status="installed", message=f"v{job.version} 업데이트가 적용되었습니다.")
    except Exception as error:
        result["message"] = str(error)
        if replaced:
            try:
                if file_sha256(job.target) != job.sha256 or file_sha256(backup) != job.old_sha256:
                    raise UpdateError("파일 변경 감지: 보존한 백업을 수동 확인해야 합니다.")
                assert incoming is not None
                shutil.copyfile(backup, incoming)
                os.replace(incoming, job.target)
                result["status"] = "rolled_back"
            except Exception as rollback_error:
                result.update(status="recovery_required", message=f"{error} / 복구: {rollback_error}")
    finally:
        if incoming is not None:
            incoming.unlink(missing_ok=True)
    write_json(stage / "result.json", result)
    write_json(stage.parent / "last-result.json", result)
    return result


def launch_installer(job: InstallJob) -> None:
    job.validate()
    helper = job.source.parent / "updater.exe"
    if not helper.exists():
        _copy_exclusive(job.target, helper)
    if file_sha256(helper) != job.old_sha256:
        raise UpdateError("업데이트 도우미 파일을 검증하지 못했습니다.")
    path = job.write()
    subprocess.Popen([str(helper), "--apply-update", str(path)], **subprocess_options())


def installer_main(path: Path) -> int:
    try:
        job = InstallJob.read(path)
        result = apply_update(job)
        return 0 if result["status"] == "installed" else 1
    except Exception as error:
        # Keep diagnostics beside this explicitly supplied transaction, never the DB.
        try:
            write_json(path.parent / "result.json", {"status": "failed", "message": str(error)})
        except OSError:
            pass
        return 1
