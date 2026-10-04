from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

from archive_analyzer.inspection import DispatchingInspector, ZipBackend
from archive_analyzer.inspection.sevenzip import SevenZipBackend
from archive_analyzer.jobs import ScanAlreadyRunning, ScanService
from archive_analyzer.paths import has_reparse_point_in_existing_chain, is_path_within
from archive_analyzer.reporting import ReportFormat, write_report
from archive_analyzer.storage.repository import (
    Repository,
    UnsafeDatabaseIdentity,
    validate_sqlite_lexical_identities,
)


_DEFAULT_SEVEN_ZIP = Path(r"C:\Program Files\7-Zip\7z.exe")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as error:
        return int(error.code)

    try:
        if arguments.command == "scan":
            return _scan(arguments)
        if arguments.command == "status":
            return _status(arguments)
        if arguments.command == "report":
            return _report(arguments)
    except KeyboardInterrupt:
        print("스캔이 중단되었습니다. 다음 scan에서 재개할 수 있습니다.", file=sys.stderr)
        return 130
    except ScanAlreadyRunning:
        print("다른 scan이 이미 실행 중입니다.", file=sys.stderr)
        return 1
    except UnsafeDatabaseIdentity:
        print(
            "DB 또는 SQLite sidecar는 symlink, reparse point, 여러 하드 링크 또는 "
            "일반 파일이 아닌 경로일 수 없습니다.",
            file=sys.stderr,
        )
        return 2
    except sqlite3.Error:
        print("DB를 열거나 저장할 수 없습니다.", file=sys.stderr)
        return 1
    except OSError:
        print("파일 시스템 경로에 접근할 수 없습니다.", file=sys.stderr)
        return 1
    except ValueError:
        print("잘못된 실행 값입니다.", file=sys.stderr)
        return 1
    except Exception:
        print("실행 중 예기치 않은 오류가 발생했습니다.", file=sys.stderr)
        return 1
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="archive-analyzer")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan")
    scan.add_argument("root", metavar="ROOT")
    scan.add_argument("--db", metavar="PATH", required=True)
    scan.add_argument("--seven-zip", metavar="PATH", default=str(_DEFAULT_SEVEN_ZIP))
    scan.add_argument("--workers", type=_worker_count, default=2, metavar="1..8")

    status = commands.add_parser("status")
    status.add_argument("--db", metavar="PATH", required=True)

    report = commands.add_parser("report")
    report.add_argument("--db", metavar="PATH", required=True)
    report.add_argument("--format", choices=("csv", "json"), required=True)
    report.add_argument("--output", metavar="PATH", required=True)
    return parser


def _worker_count(value: str) -> int:
    try:
        workers = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("workers must be in the range 1..8") from error
    if not 1 <= workers <= 8:
        raise argparse.ArgumentTypeError("workers must be in the range 1..8")
    return workers


def _scan(arguments: argparse.Namespace) -> int:
    requested_root = Path(arguments.root)
    if has_reparse_point_in_existing_chain(requested_root):
        return _usage_error("ROOT는 reparse point, junction 또는 symlink일 수 없습니다.")
    root = requested_root.resolve(strict=False)
    requested_database = Path(arguments.db)
    validate_sqlite_lexical_identities(requested_database)
    database = requested_database.resolve(strict=False)
    if not root.is_dir():
        return _usage_error("ROOT는 존재하는 디렉터리여야 합니다.")
    if is_path_within(database, root):
        return _usage_error("DB 경로는 스캔 루트 밖에 있어야 합니다.")
    repository = Repository.open(requested_database)
    try:
        inspector = DispatchingInspector(
            ZipBackend(),
            SevenZipBackend(Path(arguments.seven_zip)),
        )
        summary = ScanService(repository, inspector, workers=arguments.workers).run(root)
    finally:
        repository.close()
    print(
        "scan complete: "
        f"discovered={summary.discovered_count} reused={summary.reused_count} "
        f"indexed={summary.indexed_count} skipped={summary.skipped_count} "
        f"failed={summary.failed_count}"
    )
    return 0


def _status(arguments: argparse.Namespace) -> int:
    requested_database = Path(arguments.db)
    validate_sqlite_lexical_identities(requested_database)
    database = requested_database.resolve(strict=False)
    if not database.is_file():
        return _database_not_found()
    repository = Repository.open_readonly(requested_database)
    try:
        summary = repository.latest_summary()
    finally:
        repository.close()
    if summary is None:
        print("No scan runs recorded.")
        return 0
    print(
        f"run={summary.run_id} discovered={summary.discovered_count} "
        f"reused={summary.reused_count} indexed={summary.indexed_count} "
        f"skipped={summary.skipped_count} failed={summary.failed_count} "
        f"discovery_complete={str(summary.discovery_complete).lower()}"
    )
    return 0


def _report(arguments: argparse.Namespace) -> int:
    requested_database = Path(arguments.db)
    database = requested_database.resolve(strict=False)
    output = Path(arguments.output).resolve(strict=False)
    if output.exists():
        try:
            if os.path.samefile(output, database):
                return _usage_error("보고서 출력은 DB 파일과 같을 수 없습니다.")
        except OSError:
            return _usage_error("보고서 출력 파일의 안전성을 확인할 수 없습니다.")
    if output == database:
        return _usage_error("보고서 출력은 DB 파일과 같을 수 없습니다.")
    validate_sqlite_lexical_identities(requested_database)
    if not database.is_file():
        return _database_not_found()

    repository = Repository.open_readonly(requested_database)
    try:
        for root in repository.scan_roots():
            if is_path_within(output, root):
                return _usage_error("보고서 출력은 모든 스캔 루트 밖에 있어야 합니다.")
        write_report(repository, output, arguments.format)
    finally:
        repository.close()
    print(f"report written: {output}")
    return 0


def _usage_error(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


def _database_not_found() -> int:
    print("DB 파일을 찾을 수 없습니다.", file=sys.stderr)
    return 1
