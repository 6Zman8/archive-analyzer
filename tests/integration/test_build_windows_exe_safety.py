"""Regression tests for the Windows packaging script's safety gates."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "build_windows_exe.ps1"
PROJECT_PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"


def _run_script(*args: str) -> subprocess.CompletedProcess[str]:
    quoted = "'" + str(SCRIPT).replace("'", "''") + "' "
    quoted += " ".join(value if index % 2 == 0 else "'" + value.replace("'", "''") + "'" for index, value in enumerate(args))
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-Command",
            "[Console]::OutputEncoding = [Text.UTF8Encoding]::new(); & " + quoted,
        ],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=30,
        env=os.environ.copy(),
    )


def test_build_script_requires_current_migrations_and_bundled_ocr_assets() -> None:
    script = SCRIPT.read_text(encoding="utf-8-sig")
    assert '"006"' in script
    assert '"007"' in script
    assert '"008"' in script
    assert "prepare_ocr_assets.py" in script
    assert "ocr-assets" in script
    assert "archive_analyzer/ocr" in script
    assert "--collect-all rapidocr" in script
    assert "--collect-all onnxruntime" in script


def test_rejects_filesystem_root_before_running_or_cleaning_it(tmp_path: Path) -> None:
    # This interpreter must not be reached: it exits during preflight so the
    # unfixed script cannot proceed to Remove-Item C:\Windows.
    fake_python = tmp_path / "preflight-fails.cmd"
    fake_python.write_text("@echo off\r\nexit /b 1\r\n", encoding="ascii")

    result = _run_script(
        "-Python",
        str(fake_python),
        "-DistPath",
        str(tmp_path / "dist"),
        "-WorkPath",
        "C:\\",
        "-SpecPath",
        str(tmp_path / "spec"),
        "-Name",
        "Windows",
    )

    assert result.returncode != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "C:\\" in combined or "root" in combined.lower()


def test_rejects_global_python_override_before_build(tmp_path: Path) -> None:
    global_python = Path(os.environ.get("WINDIR", "C:\\Windows")) / "py.exe"
    if not global_python.is_file():
        global_python = Path("C:\\Python313\\python.exe")
    if global_python.resolve() == PROJECT_PYTHON.resolve() or not global_python.is_file():
        # The assertion still exercises the override contract with an existing
        # non-project interpreter whenever one is available on the machine.
        global_python = Path(os.environ["ComSpec"])

    result = _run_script(
        "-Python",
        str(global_python),
        "-DistPath",
        str(tmp_path / "dist"),
        "-WorkPath",
        str(ROOT / "build" / tmp_path.name / "work"),
        "-SpecPath",
        str(tmp_path / "spec"),
    )

    assert result.returncode != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert ".venv" in combined or "프로젝트 Python" in combined


def test_rejects_protected_directory_descendant_before_preflight(tmp_path: Path) -> None:
    fake_python = tmp_path / "preflight-fails.cmd"
    fake_python.write_text("@echo off\r\nexit /b 1\r\n", encoding="ascii")
    protected_descendant = Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32"

    result = _run_script(
        "-Python",
        str(fake_python),
        "-DistPath",
        str(tmp_path / "dist"),
        "-WorkPath",
        str(protected_descendant),
        "-SpecPath",
        str(tmp_path / "spec"),
        "-Name",
        "task11-system-descendant",
    )

    assert result.returncode != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "System32" in combined or "시스템" in combined


def test_shared_root_marker_cannot_authorize_different_existing_child(tmp_path: Path) -> None:
    work_root = tmp_path / "work"
    first_build = work_root / "first-name"
    second_build = work_root / "second-name"
    first_build.mkdir(parents=True)
    (work_root / ".archive-analyzer-build-owned").write_text("legacy marker", encoding="ascii")
    second_build.mkdir()
    sentinel = second_build / "must-survive.txt"
    sentinel.write_text("sentinel", encoding="ascii")

    result = _run_script(
        "-DistPath",
        str(tmp_path / "dist"),
        "-WorkPath",
        str(work_root),
        "-SpecPath",
        str(tmp_path / "spec"),
        "-Name",
        "second-name",
    )

    assert result.returncode != 0
    assert sentinel.read_text(encoding="ascii") == "sentinel"
    combined = (result.stdout or "") + (result.stderr or "")
    assert "소유권" in combined or "marker" in combined.lower()


def test_rejects_project_build_root_itself_before_python_validation(tmp_path: Path) -> None:
    result = _run_script(
        "-Python",
        str(Path(os.environ["ComSpec"])),
        "-DistPath",
        str(tmp_path / "dist"),
        "-WorkPath",
        str(ROOT / "build"),
        "-SpecPath",
        str(tmp_path / "spec"),
    )

    assert result.returncode != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "하위" in combined or "descendant" in combined.lower()


def test_rejects_windows_temp_root_itself_before_python_validation(tmp_path: Path) -> None:
    temp_root = Path(os.environ.get("TEMP", str(tmp_path))).resolve()
    result = _run_script(
        "-Python",
        str(Path(os.environ["ComSpec"])),
        "-DistPath",
        str(tmp_path / "dist"),
        "-WorkPath",
        str(temp_root),
        "-SpecPath",
        str(tmp_path / "spec"),
    )

    assert result.returncode != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "하위" in combined or "descendant" in combined.lower()
