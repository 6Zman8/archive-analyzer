from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Any


_EDITION_MARKERS = {
    "컬러",
    "컬러판",
    "color",
    "colour",
    "흑백",
    "흑백판",
    "bw",
    "번역",
    "번역판",
    "무삭제",
    "검열",
    "검열판",
    "모자이크",
    "고화질",
    "저화질",
    "리사이즈",
    "resize",
    "resized",
    "scan",
    "scanned",
    "한국어",
    "일본어",
    "영어",
    "kor",
    "kr",
    "jp",
    "jpn",
    "eng",
}


_UNKNOWN = "ㅁㅁㅁㅁ"
_BRACKET_PART = re.compile(r"\[[^\[\]]*\]|\((?:[^()]|\([^()]*\))*\)")


def _known(value: str) -> str:
    value = value.strip()
    return "" if value.casefold() in {"", "알수없음", "알 수 없음", "unknown", _UNKNOWN, "?"} else value


def _unique(values: list[str]) -> list[str]:
    output: dict[str, str] = {}
    for value in values:
        if known := _known(value):
            output.setdefault(known.casefold(), known)
    return list(output.values())


def work_label(paths: tuple[Path, ...]) -> str:
    """Build a display-only full title from metadata in every candidate name.

    A lone leading [name] follows the usual author-only filename convention.
    Multiple values describe the group, not attributes shared by every file.
    """
    circles: list[str] = []
    authors: list[str] = []
    attributes: list[str] = []
    titles: list[str] = []
    for path in paths:
        stem = unicodedata.normalize("NFC", path.stem).translate(
            str.maketrans("［］（）", "[]()")
        )
        parts = tuple(_BRACKET_PART.finditer(stem))
        creator_found = False
        for part in parts:
            content = part.group()[1:-1].strip()
            prefix = not _BRACKET_PART.sub("", stem[:part.start()]).strip()
            if prefix and part.group().startswith("[") and not creator_found:
                creator = re.fullmatch(r"(.*?)\((.*?)\)", content)
                if creator:
                    circles.append(creator[1])
                    authors.append(creator[2])
                    creator_found = True
                    continue
                if content.casefold() not in _EDITION_MARKERS:
                    authors.append(content)
                    creator_found = True
                    continue
            attributes.append(content)
        title = " ".join(_BRACKET_PART.sub(" ", stem).split())
        if title:
            titles.append(title)
    circle = " / ".join(_unique(circles)) or _UNKNOWN
    author = " / ".join(_unique(authors)) or _UNKNOWN
    title = " / ".join(_unique(titles)) or _UNKNOWN
    attrs = " / ".join(_unique(attributes)) or _UNKNOWN
    return f"[{circle}({author})] {title} ({attrs})"


def filter_and_sort_groups(
    groups: tuple[Any, ...], query: str, sort_key: str
) -> tuple[Any, ...]:
    normalized_query = unicodedata.normalize("NFKC", query).casefold().strip()
    filtered = tuple(
        group
        for group in groups
        if not normalized_query or normalized_query in _search_text(group)
    )
    if sort_key == "confidence":
        key = lambda group: (-group.confidence, group.work_label.casefold(), group.group_key)
    elif sort_key == "files":
        key = lambda group: (-len(group.members), group.work_label.casefold(), group.group_key)
    elif sort_key == "status":
        key = lambda group: (-int(group.needs_review), group.work_label.casefold(), group.group_key)
    else:
        key = lambda group: (group.work_label.casefold(), -group.confidence, group.group_key)
    return tuple(sorted(filtered, key=key))


def _search_text(group: Any) -> str:
    values = [
        group.work_label,
        group.relation_text,
        group.review_status_text,
        group.recommendation_text,
    ]
    for member in group.members:
        values.extend((member.file_name, str(member.path)))
    return unicodedata.normalize("NFKC", " ".join(values)).casefold()


__all__ = ["filter_and_sort_groups", "work_label"]
