"""Unauthenticated, bounded GitHub release discovery and verified downloads."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from archive_analyzer.version import __version__

REPOSITORY = "6Zman8/archive-analyzer"
ASSET_NAME = "ArchiveAnalyzer.exe"
API_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
MAX_BYTES = 512 * 1024 * 1024
MAX_JSON_BYTES = 1024 * 1024
CHECK_INTERVAL = 6 * 60 * 60


class UpdateError(Exception):
    """An update could not be verified; the running app remains usable."""


class _GitHubRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        if (parsed.scheme != "https" or parsed.username or parsed.password
                or parsed.port not in (None, 443)
                or parsed.hostname not in {"github.com", "api.github.com",
                                           "release-assets.githubusercontent.com",
                                           "objects.githubusercontent.com"}):
            raise UpdateError("GitHub 이외의 다운로드 경로를 거부했습니다.")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def open_github(request, *, timeout=20):
    return build_opener(_GitHubRedirects()).open(request, timeout=timeout)


def version_tuple(version: str) -> tuple[int, int, int]:
    if not isinstance(version, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})", version):
        raise UpdateError("정식 버전 번호가 올바르지 않습니다.")
    return tuple(int(value) for value in version.split("."))


@dataclass(frozen=True)
class Release:
    version: str
    url: str
    size: int
    sha256: str


def parse_release(document: dict, current_version: str = __version__) -> Release | None:
    if not isinstance(document, dict):
        raise UpdateError("GitHub 버전 정보를 읽을 수 없습니다.")
    if document.get("draft") is not False or document.get("prerelease") is not False:
        return None
    tag = document.get("tag_name", "")
    if not isinstance(tag, str) or not tag.startswith("v"):
        raise UpdateError("정식 릴리스 태그가 올바르지 않습니다.")
    version = tag[1:]
    if version_tuple(version) <= version_tuple(current_version):
        return None
    assets = document.get("assets")
    if not isinstance(assets, list):
        raise UpdateError("배포 파일 목록이 없습니다.")
    found = [asset for asset in assets if isinstance(asset, dict) and asset.get("name") == ASSET_NAME]
    if len(found) != 1:
        raise UpdateError("Windows 배포 파일을 찾을 수 없습니다.")
    asset = found[0]
    size, digest = asset.get("size"), asset.get("digest")
    expected_url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{ASSET_NAME}"
    if (asset.get("state") != "uploaded" or type(size) is not int or not 2 <= size <= MAX_BYTES
            or not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest)
            or asset.get("browser_download_url") != expected_url):
        raise UpdateError("배포 파일의 출처·크기·검증 정보를 확인할 수 없습니다.")
    return Release(version, expected_url, size, digest[7:].lower())


def request_for(url: str) -> Request:
    return Request(url, headers={"User-Agent": f"ArchiveAnalyzer/{__version__}",
                                "Accept": "application/vnd.github+json" if url == API_URL else "application/octet-stream"})


def check_release(current_version: str = __version__, *, opener=open_github) -> Release | None:
    try:
        with opener(request_for(API_URL), timeout=20) as response:
            payload = response.read(MAX_JSON_BYTES + 1)
        if len(payload) > MAX_JSON_BYTES:
            raise UpdateError("GitHub 응답이 너무 큽니다.")
        return parse_release(json.loads(payload), current_version)
    except HTTPError as error:
        if error.code == 404:
            return None
        if error.code in (403, 429):
            raise UpdateError("GitHub 요청 한도에 도달했습니다. 나중에 다시 확인합니다.") from error
        raise UpdateError("GitHub에 연결할 수 없습니다. 나중에 다시 확인합니다.") from error
    except (URLError, OSError, ValueError) as error:
        raise UpdateError("버전 확인에 실패했습니다. 인터넷 연결 후 다시 확인해 주세요.") from error


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download_release(release: Release, directory: Path, *, opener=open_github,
                     progress: Callable[[int, int], None] | None = None,
                     cancel: threading.Event | None = None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f"v{release.version}-", dir=directory))
    partial = stage / (ASSET_NAME + ".part")
    target = stage / ASSET_NAME
    try:
        done = 0
        digest = hashlib.sha256()
        with opener(request_for(release.url), timeout=20) as response, partial.open("xb") as output:
            while True:
                if cancel is not None and cancel.is_set():
                    raise UpdateError("업데이트 다운로드를 중단했습니다.")
                block = response.read(1024 * 1024)
                if not block:
                    break
                done += len(block)
                if done > release.size:
                    raise UpdateError("다운로드 크기가 배포 정보와 다릅니다.")
                output.write(block)
                digest.update(block)
                if progress is not None:
                    progress(done, release.size)
            output.flush()
            os.fsync(output.fileno())
        if done != release.size or digest.hexdigest() != release.sha256:
            raise UpdateError("다운로드 검증에 실패했습니다. 기존 프로그램을 유지합니다.")
        with partial.open("rb") as stream:
            if stream.read(2) != b"MZ":
                raise UpdateError("Windows 실행파일이 아닙니다.")
        os.replace(partial, target)
        return target
    except (OSError, URLError) as error:
        raise UpdateError("다운로드에 실패했습니다. 인터넷 연결과 저장공간을 확인해 주세요.") from error
    finally:
        partial.unlink(missing_ok=True)
        if not target.exists():
            stage.rmdir()


def update_directory(target: Path) -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        raise UpdateError("Windows 사용자 데이터 폴더를 찾을 수 없습니다.")
    key = hashlib.sha256(str(target.resolve()).casefold().encode("utf-8")).hexdigest()[:16]
    return Path(base) / "ArchiveAnalyzer" / "updates" / key


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Unique sibling avoids concurrent instances trampling a shared temp file.
    handle, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)
