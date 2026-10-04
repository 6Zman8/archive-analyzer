from __future__ import annotations

import hashlib
import io
from dataclasses import replace
from pathlib import Path

import pytest

from archive_analyzer.updates import (
    ASSET_NAME, REPOSITORY, Release, UpdateError, download_release,
    parse_release, version_tuple,
)


PAYLOAD = b"MZ" + b"new executable" * 100


def release_document(version="1.2.0"):
    return {
        "tag_name": "v" + version, "draft": False, "prerelease": False,
        "assets": [{"name": ASSET_NAME, "state": "uploaded", "size": len(PAYLOAD),
                    "digest": "sha256:" + hashlib.sha256(PAYLOAD).hexdigest(),
                    "browser_download_url": f"https://github.com/{REPOSITORY}/releases/download/v{version}/{ASSET_NAME}"}],
    }


def test_semantic_order_and_no_downgrade():
    assert version_tuple("1.10.0") > version_tuple("1.9.9")
    assert parse_release(release_document(), "1.1.0").version == "1.2.0"
    assert parse_release(release_document(), "1.2.0") is None
    assert parse_release(release_document(), "2.0.0") is None


@pytest.mark.parametrize("tag", ["1.0", "1.2.0-beta", "v1.2.0", "01.2.0", "1.0.0/evil"])
def test_invalid_version_rejected(tag):
    with pytest.raises(UpdateError):
        version_tuple(tag)


@pytest.mark.parametrize("key", ["draft", "prerelease"])
def test_unpublished_versions_ignored(key):
    document = release_document()
    document[key] = True
    assert parse_release(document, "1.0.0") is None


@pytest.mark.parametrize("change", [
    {"digest": None}, {"digest": "sha256:" + "x" * 64}, {"size": -1},
    {"size": 2**40}, {"browser_download_url": "http://github.com/file.exe"},
    {"browser_download_url": "https://github.com/other/repo/releases/download/v1.2.0/ArchiveAnalyzer.exe"},
    {"browser_download_url": "https://evil.invalid/ArchiveAnalyzer.exe"},
])
def test_invalid_asset_rejected(change):
    document = release_document()
    document["assets"][0].update(change)
    with pytest.raises(UpdateError):
        parse_release(document, "1.0.0")


def test_missing_asset_rejected():
    document = release_document()
    document["assets"] = []
    with pytest.raises(UpdateError):
        parse_release(document, "1.0.0")


def test_download_validates_and_reports_actual_progress(tmp_path):
    release = parse_release(release_document(), "1.0.0")
    events = []
    result = download_release(release, tmp_path, opener=lambda request, **kw: io.BytesIO(PAYLOAD),
                              progress=lambda done, total: events.append((done, total)))
    assert result.read_bytes() == PAYLOAD
    assert events[-1] == (len(PAYLOAD), len(PAYLOAD))


@pytest.mark.parametrize("body", [PAYLOAD[:-1], PAYLOAD + b"extra", b"MZ" + b"x" * (len(PAYLOAD)-2)])
def test_bad_download_never_becomes_ready(tmp_path, body):
    release = parse_release(release_document(), "1.0.0")
    with pytest.raises(UpdateError):
        download_release(release, tmp_path, opener=lambda request, **kw: io.BytesIO(body))
    assert not list(tmp_path.rglob("*.exe"))
    assert not list(tmp_path.rglob("*.part"))


def test_cancelled_download_removed(tmp_path):
    import threading
    cancel = threading.Event()
    cancel.set()
    release = parse_release(release_document(), "1.0.0")
    with pytest.raises(UpdateError):
        download_release(release, tmp_path, opener=lambda request, **kw: io.BytesIO(PAYLOAD), cancel=cancel)
    assert not list(tmp_path.rglob("*.exe"))
