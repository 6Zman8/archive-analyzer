"""Run a real older EXE through GitHub discovery/download/close/apply in a fixture."""
import argparse
import ctypes
import json
import shutil
import subprocess
import time
from pathlib import Path

from archive_analyzer.update_install import health_probe, subprocess_options
from archive_analyzer.updates import file_sha256, write_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("old_exe", type=Path)
    parser.add_argument("expected_exe", type=Path)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    (directory / ".archive-update-test-owned").write_text("disposable", encoding="utf-8")
    target = directory / "압축파일 검사기.exe"
    shutil.copyfile(args.old_exe, target)
    settings = directory / "settings-to-preserve.json"
    settings.write_text('{"user":"preserve"}', encoding="utf-8")
    database = directory / "inspection-to-preserve.db"
    import sqlite3
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE inspection(value TEXT)")
        connection.execute("INSERT INTO inspection VALUES ('preserve')")
    preserved = {str(path): file_sha256(path) for path in (settings, database)}
    foreground = ctypes.windll.user32.GetForegroundWindow()
    completed = subprocess.run([str(target), "--packaged-update-session", str(directory)],
                               timeout=300, **subprocess_options())
    session = json.loads((directory / "session.json").read_text(encoding="utf-8"))
    assert completed.returncode == 0 and session["ready"], session
    transaction = Path(session["transaction"])
    result_path = transaction / "result.json"
    deadline = time.monotonic() + 300
    while not result_path.exists() and time.monotonic() < deadline:
        time.sleep(.5)
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert result["status"] == "installed", result
    expected_hash = file_sha256(args.expected_exe)
    assert file_sha256(target) == expected_hash
    assert file_sha256(transaction / "previous.exe") == file_sha256(args.old_exe)
    assert health_probe(target, session["to_version"])
    assert all(file_sha256(Path(path)) == digest for path, digest in preserved.items())
    report = {**session, "install": result, "expected_sha256": expected_hash,
              "installed_sha256": file_sha256(target), "settings_and_db_preserved": True,
              "foreground_unchanged": foreground == ctypes.windll.user32.GetForegroundWindow()}
    write_json(directory / "acceptance.json", report)
    print(json.dumps(report, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
