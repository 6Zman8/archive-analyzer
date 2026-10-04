"""Conservative text-language and normalized-page quality comparisons."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping, Sequence

import numpy as np


class DetectedLanguage(StrEnum):
    KOREAN = "KOREAN"
    JAPANESE = "JAPANESE"
    ENGLISH = "ENGLISH"
    CHINESE = "CHINESE"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class PairDirection(StrEnum):
    LEFT_BETTER = "LEFT_BETTER"
    TIE = "TIE"
    RIGHT_BETTER = "RIGHT_BETTER"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class PageQualityMetrics:
    sharpness: float
    jpeg_blockiness: float
    ringing: float
    blur: float
    detail: float
    noise: float
    tile_blockiness: tuple[float, ...]
    tile_detail: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class PageLanguageEvidence:
    """Persistable OCR-derived signals for one page, without retaining its text."""

    character_counts: Mapping[str, int]
    readable_character_count: int
    korean_sentence_line_count: int
    korean_dialogue_page: bool
    kana_present: bool
    dominant_script: DetectedLanguage
    recognizer_scope: str = "BOTH"


@dataclass(frozen=True, slots=True)
class PrecisionProfile:
    language: DetectedLanguage
    language_confidence: float
    character_counts: Mapping[str, int]
    pages: tuple[PageQualityMetrics, ...]


@dataclass(frozen=True, slots=True)
class PairComparison:
    direction: PairDirection
    confidence: float
    reasons: tuple[str, ...]


_FILENAME_LANGUAGES = {
    "KO": DetectedLanguage.KOREAN,
    "KR": DetectedLanguage.KOREAN,
    "KOREAN": DetectedLanguage.KOREAN,
    "JA": DetectedLanguage.JAPANESE,
    "JP": DetectedLanguage.JAPANESE,
    "JAPANESE": DetectedLanguage.JAPANESE,
    "ZH": DetectedLanguage.CHINESE,
    "CN": DetectedLanguage.CHINESE,
    "CHINESE": DetectedLanguage.CHINESE,
    "EN": DetectedLanguage.ENGLISH,
    "ENG": DetectedLanguage.ENGLISH,
    "ENGLISH": DetectedLanguage.ENGLISH,
}
_QUALITY_DIRECTIONS = (
    ("sharpness", False),
    ("jpeg_blockiness", True),
    ("ringing", True),
    ("blur", True),
    ("detail", False),
    ("noise", True),
)
_SUPPORTED_SCRIPT_LANGUAGES = (
    DetectedLanguage.KOREAN,
    DetectedLanguage.JAPANESE,
    DetectedLanguage.CHINESE,
    DetectedLanguage.ENGLISH,
)


def page_language_evidence(
    text: str, *, recognizer_scope: str = "BOTH"
) -> PageLanguageEvidence:
    """Reduce one OCR result to the only signals precision analysis needs."""
    counts = _character_counts(text)
    sentence_lines = sum(_is_korean_dialogue_line(line) for line in text.splitlines())
    return PageLanguageEvidence(
        character_counts=MappingProxyType(counts),
        readable_character_count=_supported_character_count(counts),
        korean_sentence_line_count=sentence_lines,
        korean_dialogue_page=sentence_lines >= 2,
        kana_present=counts[DetectedLanguage.JAPANESE.value] > 0,
        dominant_script=_resolve_language(counts),
        recognizer_scope=recognizer_scope,
    )


def detect_language_evidence(
    pages: Sequence[PageLanguageEvidence], filename_hints: frozenset[str]
) -> PrecisionProfile:
    """Detect one supported language from persistable per-page evidence."""
    counts = {
        language.value: sum(page.character_counts.get(language.value, 0) for page in pages)
        for language in (
            DetectedLanguage.KOREAN,
            DetectedLanguage.JAPANESE,
            DetectedLanguage.CHINESE,
            DetectedLanguage.ENGLISH,
            DetectedLanguage.OTHER,
        )
    }
    language = _multi_page_korean_language_evidence(pages, counts)
    if language is None:
        language = _resolve_language(counts)
    hints = {_FILENAME_LANGUAGES[hint.upper()] for hint in filename_hints if hint.upper() in _FILENAME_LANGUAGES}
    if language is not DetectedLanguage.UNKNOWN and hints and (len(hints) != 1 or language not in hints):
        language = DetectedLanguage.UNKNOWN

    total = sum(counts.values())
    confidence = counts.get(language.value, 0) / total if language is not DetectedLanguage.UNKNOWN and total else 0.0
    return PrecisionProfile(
        language=language,
        language_confidence=confidence,
        character_counts=MappingProxyType(counts),
        pages=(),
    )


def detect_language(texts: Sequence[str], filename_hints: frozenset[str]) -> PrecisionProfile:
    """Compatibility wrapper for callers that still hold transient OCR text."""
    return detect_language_evidence(
        tuple(page_language_evidence(text) for text in texts), filename_hints
    )


def adaptive_interior_positions(page_count: int, limit: int) -> tuple[int, ...]:
    """Choose a deterministic nested sample, excluding covers when practical."""
    if page_count <= 0 or limit <= 0:
        return ()
    candidates = list(range(1, page_count - 1)) if page_count >= 5 else list(range(page_count))
    wanted = min(limit, len(candidates))
    if wanted == len(candidates):
        return tuple(candidates)

    center = (candidates[0] + candidates[-1]) / 2
    selected: list[int] = []
    remaining = set(candidates)
    while len(selected) < wanted:
        if not selected:
            chosen = min(remaining, key=lambda value: (abs(value - center), value))
        else:
            chosen = min(
                remaining,
                key=lambda value: (
                    -min(abs(value - prior) for prior in selected),
                    abs(value - center),
                    value,
                ),
            )
        selected.append(chosen)
        remaining.remove(chosen)
    return tuple(sorted(selected))


def _character_counts(text: str) -> dict[str, int]:
    return {
        DetectedLanguage.KOREAN.value: sum(_is_korean(character) for character in text),
        DetectedLanguage.JAPANESE.value: sum(_is_japanese_kana(character) for character in text),
        DetectedLanguage.CHINESE.value: sum(_is_han(character) for character in text),
        DetectedLanguage.ENGLISH.value: sum(character.isascii() and character.isalpha() for character in text),
        DetectedLanguage.OTHER.value: sum(_is_other_letter(character) for character in text),
    }


def page_quality_metrics(payload: np.ndarray) -> PageQualityMetrics:
    """Measure one in-memory, normalized 512 by 512 grayscale page."""
    image = _normalized_canvas(payload)
    horizontal, vertical = _gradients(image)
    gradient_energy = float(np.mean(horizontal**2) + np.mean(vertical**2))
    laplacian = image[1:-1, :-2] + image[1:-1, 2:] + image[:-2, 1:-1] + image[2:, 1:-1] - 4 * image[1:-1, 1:-1]
    local_variance = _local_variance(image)
    return PageQualityMetrics(
        sharpness=float(np.var(laplacian)),
        jpeg_blockiness=_blockiness(horizontal, vertical),
        ringing=_ringing(image, horizontal, vertical),
        blur=1.0 / max(gradient_energy, 1e-9),
        detail=float(np.mean(local_variance)),
        noise=_noise(image, horizontal, vertical),
        tile_blockiness=tuple(
            _tile_metrics(image[row : row + 64, column : column + 64])[0]
            for row in range(0, 449, 32)
            for column in range(0, 449, 32)
        ),
        tile_detail=tuple(
            _tile_metrics(image[row : row + 64, column : column + 64])[1]
            for row in range(0, 449, 32)
            for column in range(0, 449, 32)
        ),
    )


def compare_quality(left_pages: Sequence[np.ndarray], right_pages: Sequence[np.ndarray]) -> PairComparison:
    """Return a direction only when all aggregate quality metrics agree."""
    compared = min(len(left_pages), len(right_pages))
    return compare_quality_metrics(
        tuple(page_quality_metrics(page) for page in left_pages[:compared]),
        tuple(page_quality_metrics(page) for page in right_pages[:compared]),
    )


def compare_quality_metrics(
    left_pages: Sequence[PageQualityMetrics], right_pages: Sequence[PageQualityMetrics]
) -> PairComparison:
    """Compare already measured page quality without recalculating page metrics."""
    compared = min(len(left_pages), len(right_pages))
    if not compared:
        return PairComparison(PairDirection.UNKNOWN, 0.0, ("no corresponding pages",))
    left = _mean_quality(tuple(left_pages[:compared]))
    right = _mean_quality(tuple(right_pages[:compared]))
    directions = tuple(
        (name, relative_direction(getattr(left, name), getattr(right, name), lower_is_better=lower_is_better))
        for name, lower_is_better in _QUALITY_DIRECTIONS
    )
    non_ties = {direction for _, direction in directions if direction is not PairDirection.TIE}
    reasons = tuple(f"{name}={direction.value}" for name, direction in directions)
    if not non_ties:
        return PairComparison(PairDirection.TIE, 1.0, reasons)
    if len(non_ties) != 1:
        return PairComparison(PairDirection.UNKNOWN, 0.0, reasons)
    return PairComparison(non_ties.pop(), 1.0, reasons)


def compare_mosaic(left_pages: Sequence[np.ndarray], right_pages: Sequence[np.ndarray]) -> PairComparison:
    """Look for repeated 8-pixel block artifacts with a matching detail loss."""
    compared = min(len(left_pages), len(right_pages))
    return compare_mosaic_metrics(
        tuple(page_quality_metrics(page) for page in left_pages[:compared]),
        tuple(page_quality_metrics(page) for page in right_pages[:compared]),
    )


def compare_mosaic_metrics(
    left_pages: Sequence[PageQualityMetrics], right_pages: Sequence[PageQualityMetrics]
) -> PairComparison:
    """Compare precomputed mosaic evidence without recalculating page metrics."""
    compared = min(len(left_pages), len(right_pages))
    if compared < 3:
        return PairComparison(PairDirection.UNKNOWN, 0.0, ("fewer than three compared pages",))
    votes = tuple(
        _mosaic_page_vote(left, right)
        for left, right in zip(left_pages[:compared], right_pages[:compared], strict=True)
    )
    left_votes = votes.count(PairDirection.LEFT_BETTER)
    right_votes = votes.count(PairDirection.RIGHT_BETTER)
    directional_votes = left_votes + right_votes
    confidence = directional_votes / compared
    if left_votes and right_votes:
        return PairComparison(PairDirection.UNKNOWN, confidence, ("opposing page votes",))
    if confidence < 0.70:
        return PairComparison(PairDirection.UNKNOWN, confidence, ("insufficient directional page votes",))
    direction = PairDirection.LEFT_BETTER if left_votes else PairDirection.RIGHT_BETTER
    return PairComparison(direction, confidence, (f"{directional_votes} of {compared} pages agree",))


def relative_direction(left: float, right: float, *, lower_is_better: bool) -> PairDirection:
    scale = max(abs(left), abs(right), 1e-9)
    if abs(left - right) / scale <= 0.03:
        return PairDirection.TIE
    better_left = left < right if lower_is_better else left > right
    return PairDirection.LEFT_BETTER if better_left else PairDirection.RIGHT_BETTER


def _multi_page_korean_language_evidence(
    pages: Sequence[PageLanguageEvidence], counts: Mapping[str, int]
) -> DetectedLanguage | None:
    readable_pages = tuple(
        page for page in pages if page.readable_character_count >= 6
    )
    if len(readable_pages) < 2:
        return None
    korean_dialogue_pages = sum(page.korean_dialogue_page for page in readable_pages)
    if korean_dialogue_pages > len(readable_pages) / 2:
        return DetectedLanguage.KOREAN
    kana_pages = sum(page.character_counts.get(DetectedLanguage.JAPANESE.value, 0) >= 6
                     for page in readable_pages)
    if (not korean_dialogue_pages and kana_pages >= 3
            and kana_pages > len(readable_pages) / 2
            and counts[DetectedLanguage.JAPANESE.value] >= 30
            and counts[DetectedLanguage.KOREAN.value] <= _supported_character_count(counts) * 0.02):
        return DetectedLanguage.JAPANESE
    if counts[DetectedLanguage.KOREAN.value]:
        return DetectedLanguage.UNKNOWN
    return None


def _is_korean_dialogue_page(page: str) -> bool:
    return sum(_is_korean_dialogue_line(line) for line in page.splitlines()) >= 2


def _is_korean_dialogue_line(line: str) -> bool:
    counts = _character_counts(line)
    supported = _supported_character_count(counts)
    syllables = sum(_is_hangul_syllable(character) for character in line)
    return bool(
        supported
        and syllables >= 3
        and counts[DetectedLanguage.KOREAN.value] / supported >= 0.5
    )


def _supported_character_count(counts: Mapping[str, int]) -> int:
    return sum(counts[language.value] for language in _SUPPORTED_SCRIPT_LANGUAGES)


def _resolve_language(counts: Mapping[str, int]) -> DetectedLanguage:
    if counts[DetectedLanguage.JAPANESE.value]:
        return DetectedLanguage.JAPANESE

    candidates = tuple(
        (language, counts[language.value])
        for language, minimum in (
            (DetectedLanguage.KOREAN, 2),
            (DetectedLanguage.CHINESE, 2),
            (DetectedLanguage.ENGLISH, 4),
            (DetectedLanguage.OTHER, 4),
        )
        if counts[language.value] >= minimum
    )
    if not candidates:
        return DetectedLanguage.UNKNOWN
    language, amount = max(candidates, key=lambda candidate: candidate[1])
    other_amount = max((count for candidate, count in candidates if candidate is not language), default=0)
    if other_amount and amount < other_amount * 1.5:
        return DetectedLanguage.UNKNOWN
    return language


def _is_korean(character: str) -> bool:
    code = ord(character)
    return 0x1100 <= code <= 0x11FF or 0x3130 <= code <= 0x318F or 0xAC00 <= code <= 0xD7AF


def _is_hangul_syllable(character: str) -> bool:
    return 0xAC00 <= ord(character) <= 0xD7A3


def _is_japanese_kana(character: str) -> bool:
    code = ord(character)
    return (
        0x3041 <= code <= 0x3096 and code not in (0x309B, 0x309C)
    ) or 0x30A1 <= code <= 0x30FA or 0x31F0 <= code <= 0x31FF or (
        0xFF66 <= code <= 0xFF9D and code != 0xFF70
    )


def _is_han(character: str) -> bool:
    code = ord(character)
    return 0x3400 <= code <= 0x4DBF or 0x4E00 <= code <= 0x9FFF


def _is_other_letter(character: str) -> bool:
    return character.isalpha() and not (
        character.isascii() or _is_korean(character) or _is_japanese_kana(character) or _is_han(character)
    )


def _normalized_canvas(payload: np.ndarray) -> np.ndarray:
    image = np.asarray(payload, dtype=np.float64)
    if image.shape != (512, 512):
        raise ValueError("page payload must be a 512x512 grayscale array")
    if not np.isfinite(image).all():
        raise ValueError("page payload must contain only finite values")
    return image


def _gradients(image: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    return np.abs(np.diff(image, axis=1)), np.abs(np.diff(image, axis=0))


def _blockiness(horizontal: np.ndarray, vertical: np.ndarray) -> float:
    boundary = np.concatenate((horizontal[:, 7::8].ravel(), vertical[7::8, :].ravel()))
    interior = np.concatenate((np.delete(horizontal, np.s_[7::8], axis=1).ravel(), np.delete(vertical, np.s_[7::8], axis=0).ravel()))
    return float(np.mean(boundary) / max(float(np.mean(interior)), 1e-9))


def _local_variance(image: np.ndarray) -> np.ndarray:
    rows, columns = image.shape
    return image.reshape(rows // 8, 8, columns // 8, 8).var(axis=(1, 3))


def _ringing(image: np.ndarray, horizontal: np.ndarray, vertical: np.ndarray) -> float:
    residual = image[1:-1, 1:-1] - (image[1:-1, :-2] + image[1:-1, 2:] + image[:-2, 1:-1] + image[2:, 1:-1]) / 4
    gradient = np.maximum(horizontal[1:-1, :-1], vertical[:-1, 1:-1])
    strong_edge = gradient > np.percentile(gradient, 90)
    alternating = np.zeros_like(residual, dtype=bool)
    horizontal_sign_change = residual[:, 1:] * residual[:, :-1] < 0
    vertical_sign_change = residual[1:, :] * residual[:-1, :] < 0
    alternating[:, 1:] |= horizontal_sign_change
    alternating[:, :-1] |= horizontal_sign_change
    alternating[1:, :] |= vertical_sign_change
    alternating[:-1, :] |= vertical_sign_change
    return float(np.mean(alternating[strong_edge])) if strong_edge.any() else 0.0


def _noise(image: np.ndarray, horizontal: np.ndarray, vertical: np.ndarray) -> float:
    center = image[1:-1, 1:-1]
    smooth = (image[1:-1, :-2] + image[1:-1, 2:] + image[:-2, 1:-1] + image[2:, 1:-1]) / 4
    gradient = np.maximum(horizontal[1:-1, :-1], vertical[:-1, 1:-1])
    quiet = gradient <= np.percentile(gradient, 75)
    return float(np.mean(np.abs(center[quiet] - smooth[quiet]))) if quiet.any() else 0.0


def _tile_metrics(tile: np.ndarray) -> tuple[float, float]:
    horizontal, vertical = _gradients(tile)
    return _blockiness(horizontal, vertical), float(np.mean(_local_variance(tile)))


def _mean_quality(pages: tuple[PageQualityMetrics, ...]) -> PageQualityMetrics:
    return PageQualityMetrics(
        **{
            name: float(np.mean([getattr(page, name) for page in pages]))
            for name, _ in _QUALITY_DIRECTIONS
        },
        tile_blockiness=(),
        tile_detail=(),
    )


def _mosaic_page_vote(left: PageQualityMetrics, right: PageQualityMetrics) -> PairDirection:
    left_tiles = sum(
        _mosaic_tile_supports(left_blockiness, left_detail, right_blockiness, right_detail)
        for left_blockiness, left_detail, right_blockiness, right_detail in zip(
            left.tile_blockiness, left.tile_detail, right.tile_blockiness, right.tile_detail, strict=True
        )
    )
    right_tiles = sum(
        _mosaic_tile_supports(right_blockiness, right_detail, left_blockiness, left_detail)
        for left_blockiness, left_detail, right_blockiness, right_detail in zip(
            left.tile_blockiness, left.tile_detail, right.tile_blockiness, right.tile_detail, strict=True
        )
    )
    if left_tiles >= 2 and not right_tiles:
        return PairDirection.LEFT_BETTER
    if right_tiles >= 2 and not left_tiles:
        return PairDirection.RIGHT_BETTER
    return PairDirection.UNKNOWN


def _mosaic_tile_supports(
    better_blockiness: float, better_detail: float, worse_blockiness: float, worse_detail: float
) -> bool:
    boundary_advantage = (worse_blockiness - better_blockiness) / max(abs(better_blockiness), 1e-9)
    detail_ratio = worse_detail / max(abs(better_detail), 1e-9)
    return boundary_advantage >= 0.25 and detail_ratio <= 0.70
