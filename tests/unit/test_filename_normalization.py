from pathlib import Path

import pytest

from archive_analyzer.filename_normalization import normalize_filename_evidence


def test_filename_order_and_separators_produce_same_supporting_tokens() -> None:
    left = normalize_filename_evidence(
        Path("(C105) [ABC (Tanaka)] Example Title [Korean].zip")
    )
    right = normalize_filename_evidence(Path("Tanaka - ABC_Example-Title_KR.zip"))

    assert {"abc", "tanaka", "example", "title"} <= left.tokens & right.tokens
    assert "ko" in left.language_hints & right.language_hints


def test_unicode_brackets_volume_and_scan_markers_are_normalized() -> None:
    value = normalize_filename_evidence(
        Path("［ＡＢＣ］ 작품명 (제3권) [화05] 일본어 스캔 리사이즈.cbz")
    )

    assert {"abc", "작품명", "volume3", "chapter5"} <= value.tokens
    assert value.language_hints == frozenset({"ja"})
    assert "스캔" not in value.tokens
    assert "리사이즈" not in value.tokens


def test_volume_and_chapter_markers_share_a_canonical_token() -> None:
    korean = normalize_filename_evidence(Path("Example 제03권 화05.zip"))
    western = normalize_filename_evidence(Path("Example Vol. 3 Chapter 5.zip"))

    assert {"example", "volume3", "chapter5"} <= korean.tokens & western.tokens


def test_language_labels_are_hints_not_title_tokens() -> None:
    value = normalize_filename_evidence(Path("Title 한국어 Japanese English Kor JPN ENG.rar"))

    assert value.tokens == frozenset({"title"})
    assert value.language_hints == frozenset({"ko", "ja", "en"})


@pytest.mark.parametrize(
    ("name", "language", "color", "mosaic"),
    [
        ("[Circle] Work Korean fullcolor uncensored.zip", "KOREAN", "FULL_COLOR", "UNCENSORED"),
        ("Work Korea decensord.cbz", "KOREAN", None, "DECENSORED"),
        ("Work chs censord.7z", "CHINESE", None, "CENSORED"),
        ("Work 흑백 모자이크.rar", None, "MONOCHROME", "CENSORED"),
    ],
)
def test_filename_signals_keep_value_source_tokens_and_common_misspellings(
    name: str, language: str | None, color: str | None, mosaic: str | None
) -> None:
    evidence = normalize_filename_evidence(Path(name))

    assert evidence.language.value == language
    assert evidence.color.value == color
    assert evidence.mosaic.value == mosaic
    assert evidence.language.matched_tokens or language is None


def test_conflicting_filename_signals_are_unknown() -> None:
    evidence = normalize_filename_evidence(
        Path("work korean japanese fullcolor monochrome.zip")
    )

    assert evidence.language.conflict is True
    assert evidence.language.value is None
    assert evidence.color.conflict is True
    assert evidence.color.value is None


def test_collapsed_filename_phrases_do_not_conflict_with_their_component_tokens() -> None:
    color = normalize_filename_evidence(Path("work full color no mosaic.zip"))
    mono = normalize_filename_evidence(Path("work black white 모자이크 제거.zip"))

    assert color.color.value == "FULL_COLOR"
    assert color.mosaic.value == "UNCENSORED"
    assert mono.color.value == "MONOCHROME"
    assert mono.mosaic.value == "DECENSORED"
