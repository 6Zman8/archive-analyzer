from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pytest

import archive_analyzer.precision_analysis as precision_analysis
from archive_analyzer.precision_analysis import (
    DetectedLanguage,
    PairDirection,
    adaptive_interior_positions,
    compare_mosaic,
    compare_quality,
    detect_language,
    detect_language_evidence,
    page_language_evidence,
)


@pytest.mark.parametrize(
    ("texts", "expected"),
    [
        (("이것은 한국어입니다",), DetectedLanguage.KOREAN),
        (("これは日本語です",), DetectedLanguage.JAPANESE),
        (("这是中文",), DetectedLanguage.CHINESE),
        (("translated edition",), DetectedLanguage.ENGLISH),
    ],
)
def test_detect_language_uses_unicode_script_counts(
    texts: tuple[str, ...], expected: DetectedLanguage
) -> None:
    assert detect_language(texts, frozenset()).language is expected


def test_filename_and_ocr_conflict_is_unknown() -> None:
    result = detect_language(("한국어 본문",), frozenset({"JA"}))
    assert result.language is DetectedLanguage.UNKNOWN


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("이것은 한국어 본문입니다 Volume", DetectedLanguage.KOREAN),
        ("これは日本語 Edition", DetectedLanguage.JAPANESE),
        ("한국어 본문 English", DetectedLanguage.UNKNOWN),
    ],
)
def test_detect_language_requires_clear_script_dominance(
    text: str, expected: DetectedLanguage
) -> None:
    assert detect_language((text,), frozenset()).language is expected


def test_korean_translation_requires_majority_of_dialogue_pages() -> None:
    pages = (
        "번역된 대사가 있습니다\n여기도 한국어 문장입니다\nドン",
        "오늘도 좋은 날입니다\n다음 장면으로 갑니다\n作者後記",
        "한국어 대화가 이어집니다\n마지막 문장도 번역됨\nBOOK INFO",
        "表紙 タイトル 作品情報 作者",
        "あとがき STAFF INFORMATION",
    )
    assert detect_language(pages, frozenset()).language is DetectedLanguage.KOREAN


def test_korean_total_characters_without_page_majority_is_unknown() -> None:
    pages = (
        "긴 한국어 문장이 한 페이지에만 몰려 있습니다\n두 번째 한국어 문장도 이 페이지뿐입니다",
        "これは日本語です",
        "日本語の本文です",
    )
    assert detect_language(pages, frozenset()).language is DetectedLanguage.UNKNOWN


def test_equal_korean_dialogue_page_count_is_unknown() -> None:
    pages = (
        "한국어 대사가 있습니다\n여기도 한국어 문장입니다",
        "오늘도 좋은 날입니다\n다음 장면으로 갑니다",
        "これは日本語です\n次の場面です",
        "日本語の本文です\n続きます",
    )
    assert detect_language(pages, frozenset()).language is DetectedLanguage.UNKNOWN


def test_two_readable_pages_without_two_korean_dialogue_lines_are_unknown() -> None:
    pages = (
        "한국어 대사가 있습니다\n12345",
        "번역된 내용입니다\n67890",
    )
    assert detect_language(pages, frozenset()).language is DetectedLanguage.UNKNOWN


def test_japanese_punctuation_without_kana_is_unknown() -> None:
    assert detect_language(("・ー",), frozenset()).language is DetectedLanguage.UNKNOWN


def test_other_script_does_not_reduce_korean_dialogue_line_ratio() -> None:
    pages = (
        "한국어 대사가 있습니다 абвгдежзийк\n여기도 한국어 문장입니다 абвгдежзийк",
        "오늘도 좋은 날입니다 абвгдежзийк\n다음 장면으로 갑니다 абвгдежзийк",
    )
    assert detect_language(pages, frozenset()).language is DetectedLanguage.KOREAN


def test_other_script_only_pages_do_not_expand_readable_page_denominator() -> None:
    pages = (
        "한국어 대사가 있습니다\n여기도 한국어 문장입니다",
        "오늘도 좋은 날입니다\n다음 장면으로 갑니다",
        "한글어 абвгдежзийк",
        "한글어 абвгдежзийк",
    )
    assert detect_language(pages, frozenset()).language is DetectedLanguage.KOREAN


def test_katakana_phonetic_extension_is_japanese_evidence() -> None:
    assert detect_language(("ㇰ",), frozenset()).language is DetectedLanguage.JAPANESE


def test_page_language_evidence_reproduces_text_detection_without_raw_text() -> None:
    texts = (
        "번역된 대사가 있습니다\n여기도 한국어 문장입니다\nドン",
        "오늘도 좋은 날입니다\n다음 장면으로 갑니다\n作者後記",
        "表紙 タイトル 作品情報 作者",
    )
    evidence = tuple(page_language_evidence(text, recognizer_scope="BOTH") for text in texts)

    assert detect_language_evidence(evidence, frozenset()) == detect_language(
        texts, frozenset()
    )
    assert evidence[0].korean_dialogue_page
    assert evidence[0].korean_sentence_line_count == 2
    assert evidence[0].kana_present
    assert evidence[0].recognizer_scope == "BOTH"
    assert not hasattr(evidence[0], "text")


def test_adaptive_interior_positions_are_nested_and_skip_covers() -> None:
    first = adaptive_interior_positions(30, 3)
    second = adaptive_interior_positions(30, 6)
    third = adaptive_interior_positions(30, 12)

    assert len(first) == 3
    assert len(second) == 6
    assert len(third) == 12
    assert set(first) < set(second) < set(third)
    assert 0 not in third
    assert 29 not in third


@pytest.mark.parametrize(
    ("page_count", "expected"),
    [
        (0, ()),
        (1, (0,)),
        (2, (0, 1)),
        (4, (0, 1, 2, 3)),
        (5, (1, 2, 3)),
    ],
)
def test_adaptive_interior_positions_handle_small_archives(
    page_count: int, expected: tuple[int, ...]
) -> None:
    assert adaptive_interior_positions(page_count, 12) == expected


@dataclass(frozen=True)
class ImagePairPages:
    clear: tuple[np.ndarray, ...]
    pixelated: tuple[np.ndarray, ...]


def _clear_page(seed: int) -> np.ndarray:
    rows, columns = np.indices((512, 512))
    return (
        128
        + 50 * np.sin((columns + seed * 13) / 8.7)
        + 40 * np.cos((rows - seed * 7) / 12.1)
        + 25 * np.sin((rows + columns) / 5.3)
    ).clip(0, 255).astype(np.float32)


def _pixelate(page: np.ndarray) -> np.ndarray:
    blocks = page.reshape(64, 8, 64, 8).mean(axis=(1, 3))
    return np.repeat(np.repeat(blocks, 8, axis=0), 8, axis=1)


@pytest.fixture
def image_pair_pages() -> ImagePairPages:
    clear = tuple(_clear_page(seed) for seed in range(3))
    return ImagePairPages(clear=clear, pixelated=tuple(_pixelate(page) for page in clear))


@pytest.fixture
def noisy_pair_pages() -> tuple[tuple[np.ndarray, ...], tuple[np.ndarray, ...]]:
    pages = tuple(_clear_page(seed) for seed in range(3))
    generator = np.random.default_rng(21)
    noisy = tuple((page + generator.normal(0, 7, page.shape)).clip(0, 255) for page in pages)
    return pages, noisy


@pytest.fixture
def sharp_but_blocky_pair_pages() -> tuple[tuple[np.ndarray, ...], tuple[np.ndarray, ...]]:
    rows, columns = np.indices((512, 512))
    sharp = (((rows // 8 + columns // 8) % 2) * 255).astype(np.float32)
    smooth = _clear_page(4)
    return (sharp,) * 3, (smooth,) * 3


def test_mosaic_requires_repeated_one_way_block_and_detail_evidence(
    image_pair_pages: ImagePairPages,
) -> None:
    result = compare_mosaic(image_pair_pages.clear, image_pair_pages.pixelated)
    assert result.direction is PairDirection.LEFT_BETTER
    assert result.confidence >= 0.70


def test_jpeg_noise_without_local_detail_advantage_stays_unknown(
    noisy_pair_pages: tuple[tuple[np.ndarray, ...], tuple[np.ndarray, ...]],
) -> None:
    assert compare_mosaic(*noisy_pair_pages).direction is PairDirection.UNKNOWN


def test_quality_conflict_stays_unknown(
    sharp_but_blocky_pair_pages: tuple[tuple[np.ndarray, ...], tuple[np.ndarray, ...]],
) -> None:
    assert compare_quality(*sharp_but_blocky_pair_pages).direction is PairDirection.UNKNOWN


def test_precomputed_metrics_match_existing_page_comparisons(
    image_pair_pages: ImagePairPages,
) -> None:
    left_metrics = tuple(
        precision_analysis.page_quality_metrics(page) for page in image_pair_pages.clear
    )
    right_metrics = tuple(
        precision_analysis.page_quality_metrics(page)
        for page in image_pair_pages.pixelated
    )

    assert precision_analysis.compare_mosaic_metrics(
        left_metrics, right_metrics
    ) == compare_mosaic(image_pair_pages.clear, image_pair_pages.pixelated)
    assert precision_analysis.compare_quality_metrics(
        left_metrics, right_metrics
    ) == compare_quality(image_pair_pages.clear, image_pair_pages.pixelated)


def test_page_comparisons_only_measure_aligned_pages(
    image_pair_pages: ImagePairPages, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0
    original = precision_analysis.page_quality_metrics

    def counting_metric(page: np.ndarray):
        nonlocal calls
        calls += 1
        return original(page)

    monkeypatch.setattr(precision_analysis, "page_quality_metrics", counting_metric)
    left_pages = image_pair_pages.clear + (image_pair_pages.clear[0],)

    compare_mosaic(left_pages, image_pair_pages.pixelated)
    assert calls == 6
    calls = 0
    compare_quality(left_pages, image_pair_pages.pixelated)
    assert calls == 6
