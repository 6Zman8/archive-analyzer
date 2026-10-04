from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from io import BytesIO

from PIL import Image, ImageOps

from archive_analyzer.duplicate_domain import DuplicateRelation


class EditionFlag(StrEnum):
    COLOR_MONO = "COLOR_MONO"
    TRANSLATION = "TRANSLATION"
    EDIT_OR_CENSORSHIP = "EDIT_OR_CENSORSHIP"
    QUALITY = "QUALITY"


class EditionKind(StrEnum):
    FULL_COLOR = "FULL_COLOR"
    MONOCHROME = "MONOCHROME"
    MIXED_OR_UNKNOWN = "MIXED_OR_UNKNOWN"


def classify_edition(color_page_ratio: float | None) -> EditionKind:
    """Classify only the two safely comparable edition families."""
    if color_page_ratio is None:
        return EditionKind.MIXED_OR_UNKNOWN
    if color_page_ratio >= 0.50:
        return EditionKind.FULL_COLOR
    if color_page_ratio <= 0.15:
        return EditionKind.MONOCHROME
    return EditionKind.MIXED_OR_UNKNOWN


@dataclass(frozen=True, slots=True)
class EditionProfile:
    archive_id: int
    sample_count: int
    color_page_ratio: float
    median_color_score: float
    language_hints: frozenset[str]


@dataclass(frozen=True, slots=True)
class EditionEvidence:
    relation: DuplicateRelation
    matched_pages: int
    left_pages: int
    right_pages: int
    reasons: tuple[str, ...]
    recommendation: str
    left_file_size: int
    right_file_size: int


@dataclass(frozen=True, slots=True)
class EditionComparison:
    flags: tuple[EditionFlag, ...]
    preserve_required: bool
    summary: str


def image_color_score(payload: bytes) -> float:
    with Image.open(BytesIO(payload)) as opened:
        image = ImageOps.exif_transpose(opened).convert("RGB")
        image.thumbnail((128, 128), Image.Resampling.BILINEAR)
        pixels = tuple(image.get_flattened_data())
    if not pixels:
        return 0.0
    colorful = sum(1 for red, green, blue in pixels if max(red, green, blue) - min(red, green, blue) >= 16)
    return colorful / len(pixels)


def sample_positions(page_count: int, *, limit: int = 12) -> tuple[int, ...]:
    if page_count <= 0 or limit <= 0:
        return ()
    if page_count <= limit:
        return tuple(range(page_count))
    return tuple(
        dict.fromkeys(
            round(index * (page_count - 1) / (limit - 1))
            for index in range(limit)
        )
    )


def compare_editions(
    left: EditionProfile,
    right: EditionProfile,
    evidence: EditionEvidence,
) -> EditionComparison:
    flags: list[EditionFlag] = []
    color_difference = (
        left.color_page_ratio <= 0.15 and right.color_page_ratio >= 0.50
    ) or (
        right.color_page_ratio <= 0.15 and left.color_page_ratio >= 0.50
    )
    if color_difference:
        flags.append(EditionFlag.COLOR_MONO)
    if (
        left.language_hints
        and right.language_hints
        and left.language_hints.isdisjoint(right.language_hints)
    ):
        flags.append(EditionFlag.TRANSLATION)
    if (
        not flags
        and evidence.relation
        in {DuplicateRelation.VISUAL_VARIANT, DuplicateRelation.RELATED}
        and evidence.matched_pages >= 3
    ):
        flags.append(EditionFlag.EDIT_OR_CENSORSHIP)
    if any("MEDIAN_PIXEL_AREA_AT_LEAST_15_PERCENT_LARGER" in reason for reason in evidence.reasons):
        flags.append(EditionFlag.QUALITY)
    ordered = tuple(dict.fromkeys(flags))
    preserve_required = any(
        flag
        in {
            EditionFlag.COLOR_MONO,
            EditionFlag.TRANSLATION,
            EditionFlag.EDIT_OR_CENSORSHIP,
        }
        for flag in ordered
    )
    labels = {
        EditionFlag.COLOR_MONO: "컬러판·흑백판 차이",
        EditionFlag.TRANSLATION: "번역판 언어 차이",
        EditionFlag.EDIT_OR_CENSORSHIP: "번역·편집·검열·모자이크 차이 가능성",
        EditionFlag.QUALITY: "해상도·압축 품질 차이",
    }
    summary = (
        ", ".join(labels[flag] for flag in ordered)
        if ordered
        else "표본에서 뚜렷한 판본 차이를 찾지 못했습니다."
    )
    return EditionComparison(ordered, preserve_required, summary)


__all__ = [
    "EditionComparison",
    "EditionEvidence",
    "EditionFlag",
    "EditionKind",
    "EditionProfile",
    "classify_edition",
    "compare_editions",
    "image_color_score",
    "sample_positions",
]
