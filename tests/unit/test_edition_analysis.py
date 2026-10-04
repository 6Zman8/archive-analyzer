from io import BytesIO

from PIL import Image

from archive_analyzer.duplicate_domain import DuplicateRelation
from archive_analyzer.edition_analysis import (
    EditionEvidence,
    EditionFlag,
    EditionProfile,
    compare_editions,
    image_color_score,
    sample_positions,
)


def _image(color: tuple[int, int, int]) -> bytes:
    output = BytesIO()
    Image.new("RGB", (32, 32), color).save(output, format="PNG")
    return output.getvalue()


def _profile(
    archive_id: int,
    color_ratio: float,
    hints: frozenset[str] = frozenset(),
) -> EditionProfile:
    return EditionProfile(archive_id, 6, color_ratio, color_ratio, hints)


def _evidence(
    relation: DuplicateRelation = DuplicateRelation.VISUAL_VARIANT,
    reasons: tuple[str, ...] = (),
) -> EditionEvidence:
    return EditionEvidence(relation, 6, 6, 6, reasons, "MANUAL", 100, 100)


def test_color_score_separates_grayscale_from_color() -> None:
    assert image_color_score(_image((120, 120, 120))) == 0.0
    assert image_color_score(_image((220, 30, 20))) > 0.5


def test_sample_positions_limits_large_archives_evenly() -> None:
    positions = sample_positions(100, limit=12)

    assert len(positions) == 12
    assert positions[0] == 0
    assert positions[-1] == 99


def test_color_and_language_differences_require_preservation() -> None:
    result = compare_editions(
        _profile(1, 0.0, frozenset({"ja"})),
        _profile(2, 1.0, frozenset({"ko"})),
        _evidence(),
    )

    assert result.flags == (EditionFlag.COLOR_MONO, EditionFlag.TRANSLATION)
    assert result.preserve_required


def test_similar_layout_with_changed_pixels_marks_edit_or_censorship_possible() -> None:
    result = compare_editions(
        _profile(1, 0.0),
        _profile(2, 0.0),
        _evidence(DuplicateRelation.VISUAL_VARIANT),
    )

    assert result.flags == (EditionFlag.EDIT_OR_CENSORSHIP,)
    assert result.preserve_required
    assert "가능성" in result.summary


def test_resolution_difference_alone_never_auto_removes_a_version() -> None:
    result = compare_editions(
        _profile(1, 0.0),
        _profile(2, 0.0),
        _evidence(
            DuplicateRelation.EXACT_CONTENT,
            ("RIGHT_MEDIAN_PIXEL_AREA_AT_LEAST_15_PERCENT_LARGER",),
        ),
    )

    assert result.flags == (EditionFlag.QUALITY,)
    assert not result.preserve_required
