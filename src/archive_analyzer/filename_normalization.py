from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from archive_analyzer.version_dates import parse_title_dates

from archive_analyzer.recommendation import title_structure_rank


_BRACKETS = str.maketrans({character: " " for character in "()[]{}<>（）［］【】〔〕〈〉《》"})

def dated_series_identity(path: Path) -> tuple[str, str, bool]:
    value = parse_title_dates(path)
    return value.key, value.span.end.isoformat() if value.span else "", value.versioned
_LANGUAGE_HINTS = {
    "korean": "ko", "korea": "ko", "kor": "ko", "kr": "ko", "한국어": "ko", "한글": "ko",
    "japanese": "ja", "japan": "ja", "jpn": "ja", "jp": "ja", "일본어": "ja", "日本語": "ja",
    "english": "en", "eng": "en", "영어": "en",
    "chinese": "zh", "chs": "zh", "cht": "zh", "zh": "zh", "중국어": "zh", "简体": "zh", "繁體": "zh",
}
_LANGUAGE_MARKERS = (
    (("korean",), "KOREAN", 0.90), (("korea",), "KOREAN", 0.60), (("kor",), "KOREAN", 0.90), (("kr",), "KOREAN", 0.90), (("한국어",), "KOREAN", 0.90), (("한글",), "KOREAN", 0.90),
    (("japanese",), "JAPANESE", 0.90), (("japan",), "JAPANESE", 0.90), (("jpn",), "JAPANESE", 0.90), (("jp",), "JAPANESE", 0.90), (("일본어",), "JAPANESE", 0.90), (("日本語",), "JAPANESE", 0.90),
    (("english",), "ENGLISH", 0.90), (("eng",), "ENGLISH", 0.90), (("영어",), "ENGLISH", 0.90),
    (("chinese",), "CHINESE", 0.90), (("chs",), "CHINESE", 0.90), (("cht",), "CHINESE", 0.90), (("zh",), "CHINESE", 0.90), (("중국어",), "CHINESE", 0.90), (("简体",), "CHINESE", 0.90), (("繁體",), "CHINESE", 0.90),
)
_COLOR_MARKERS = (
    (("fullcolor",), "FULL_COLOR", 0.90), (("full", "color"), "FULL_COLOR", 0.90), (("fullcolour",), "FULL_COLOR", 0.90), (("full", "colour"), "FULL_COLOR", 0.90), (("color",), "FULL_COLOR", 0.90), (("colour",), "FULL_COLOR", 0.90), (("풀컬러",), "FULL_COLOR", 0.90), (("컬러",), "FULL_COLOR", 0.90),
    (("monochrome",), "MONOCHROME", 0.90), (("grayscale",), "MONOCHROME", 0.90), (("greyscale",), "MONOCHROME", 0.90), (("black", "white"), "MONOCHROME", 0.90), (("bw",), "MONOCHROME", 0.90), (("흑백",), "MONOCHROME", 0.90),
)
_MOSAIC_MARKERS = (
    (("uncensored",), "UNCENSORED", 0.90), (("uncensord",), "UNCENSORED", 0.90), (("uncensor",), "UNCENSORED", 0.90), (("no", "mosaic"), "UNCENSORED", 0.90), (("노모",), "UNCENSORED", 0.90), (("무수정",), "UNCENSORED", 0.90),
    (("decensored",), "DECENSORED", 0.90), (("decensord",), "DECENSORED", 0.90), (("decensor",), "DECENSORED", 0.90), (("디센서",), "DECENSORED", 0.90), (("모자이크", "제거"), "DECENSORED", 0.90),
    (("censored",), "CENSORED", 0.90), (("censord",), "CENSORED", 0.90), (("mosaic",), "CENSORED", 0.90), (("검열",), "CENSORED", 0.90), (("모자이크",), "CENSORED", 0.90),
)
_EDITION_MARKERS = frozenset({"scan", "scanned", "스캔", "resize", "resized", "리사이즈"})
_VOLUME_MARKERS = (
    re.compile(r"(?:제|第)?\s*0*(\d+)\s*(?:권|卷|巻)(?!\w)"),
    re.compile(r"(?:vol(?:ume)?|v)\.?\s*0*(\d+)(?!\w)"),
)
_CHAPTER_MARKERS = (
    re.compile(r"(?:제|第)?\s*0*(\d+)\s*(?:화|話)(?!\w)"),
    re.compile(r"(?:ch(?:apter)?|화)\.?\s*0*(\d+)(?!\w)"),
)


@dataclass(frozen=True, slots=True)
class FilenameSignal:
    value: str | None
    confidence: float
    matched_tokens: frozenset[str]
    conflict: bool


@dataclass(frozen=True, slots=True)
class FilenameEvidence:
    tokens: frozenset[str]
    language_hints: frozenset[str]
    language: FilenameSignal
    color: FilenameSignal
    mosaic: FilenameSignal
    title_rank: int


def normalize_filename_evidence(path: Path) -> FilenameEvidence:
    """Return conservative filename evidence for candidate ranking only.

    The filename never creates a candidate by itself.  It is normalized only
    to make a visual candidate easier for a reviewer to recognize.
    """

    stem = unicodedata.normalize("NFKC", path.stem).casefold()
    normalized = stem.translate(_BRACKETS).replace("_", " ").replace("-", " ")
    normalized = _normalize_numbered_markers(normalized)
    pieces = tuple(_unicode_alphanumeric_tokens(normalized))
    language = _signal_for(pieces, _LANGUAGE_MARKERS)
    color = _signal_for(pieces, _COLOR_MARKERS)
    mosaic = _signal_for(pieces, _MOSAIC_MARKERS)
    title_pieces = set(pieces) - color.matched_tokens - mosaic.matched_tokens - _EDITION_MARKERS
    if language.value is None and not language.conflict and any(
        "가" <= char <= "힣" for piece in title_pieces for char in piece
    ):
        language = FilenameSignal("KOREAN", 0.60, frozenset({"hangul-title"}), False)
    hints = frozenset(_LANGUAGE_HINTS[piece] for piece in pieces if piece in _LANGUAGE_HINTS)
    tokens = frozenset(
        piece
        for piece in pieces
        if piece not in _LANGUAGE_HINTS and piece not in _EDITION_MARKERS
    )
    return FilenameEvidence(tokens, hints, language, color, mosaic, title_structure_rank(path))


def language_hints_for_signal(signal: FilenameSignal) -> frozenset[str]:
    """Reconstruct legacy language hints from persisted source tokens."""

    return frozenset(
        _LANGUAGE_HINTS[token] for token in signal.matched_tokens if token in _LANGUAGE_HINTS
    )


def _signal_for(
    pieces: tuple[str, ...], markers: tuple[tuple[tuple[str, ...], str, float], ...]
) -> FilenameSignal:
    matches: dict[str, tuple[float, set[str]]] = {}
    consumed: set[int] = set()
    for index in range(len(pieces)):
        if index in consumed:
            continue
        for marker, value, confidence in markers:
            if pieces[index : index + len(marker)] != marker:
                continue
            if any(position in consumed for position in range(index, index + len(marker))):
                continue
            existing = matches.setdefault(value, (confidence, set()))
            existing[1].update(marker)
            if confidence > existing[0]:
                matches[value] = (confidence, existing[1])
            consumed.update(range(index, index + len(marker)))
            break
    if not matches:
        return FilenameSignal(None, 0.0, frozenset(), False)
    tokens = frozenset(token for _, matched in matches.values() for token in matched)
    if len(matches) != 1:
        return FilenameSignal(None, 0.0, tokens, True)
    value, (confidence, matched) = next(iter(matches.items()))
    return FilenameSignal(value, confidence, frozenset(matched), False)


def _unicode_alphanumeric_tokens(value: str) -> tuple[str, ...]:
    tokens: list[str] = []
    current: list[str] = []
    for character in value:
        if character.isalnum():
            current.append(character)
        elif current:
            tokens.append("".join(current))
            current.clear()
    if current:
        tokens.append("".join(current))
    return tuple(tokens)


def _normalize_numbered_markers(value: str) -> str:
    for marker in _VOLUME_MARKERS:
        value = marker.sub(lambda match: f" volume{int(match.group(1))} ", value)
    for marker in _CHAPTER_MARKERS:
        value = marker.sub(lambda match: f" chapter{int(match.group(1))} ", value)
    return value
