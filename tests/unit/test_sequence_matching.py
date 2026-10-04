import hashlib

from archive_analyzer.fingerprinting import ImageFingerprint
from archive_analyzer.matching import ArchiveFingerprintSet
from archive_analyzer.sequence_matching import SequenceRelation, match_page_sequences


def _page(value: int) -> ImageFingerprint:
    digest = hashlib.sha256(str(value).encode("ascii")).hexdigest()
    perceptual = digest[:16]
    return ImageFingerprint(
        byte_sha256=digest,
        pixel_sha256=digest,
        dhash64=perceptual,
        ahash64=perceptual,
        width=1000,
        height=1500,
    )


def _archive(archive_id: int, values: tuple[int, ...]) -> ArchiveFingerprintSet:
    return ArchiveFingerprintSet(
        archive_id=archive_id,
        file_sha256=None,
        pages=tuple(_page(value) for value in values),
    )


def test_sequence_match_finds_volume_inside_later_omnibus_offset() -> None:
    result = match_page_sequences(
        _archive(1, (10, 11, 12, 13)),
        _archive(2, (1, 2, 10, 11, 12, 13, 20)),
    )

    assert result is not None
    assert result.relation is SequenceRelation.CONTAINS
    assert result.container_archive_id == 2
    assert result.matched_pairs == ((0, 2), (1, 3), (2, 4), (3, 5))
    assert result.left_coverage == 1.0
    assert result.right_coverage == 4 / 7


def test_sequence_match_preserves_container_direction_after_id_ordering() -> None:
    result = match_page_sequences(
        _archive(9, (30, 31, 32)),
        _archive(3, (1, 30, 31, 32, 40)),
    )

    assert result is not None
    assert (result.archive_a_id, result.archive_b_id) == (3, 9)
    assert result.container_archive_id == 3
    assert result.matched_pairs == ((1, 0), (2, 1), (3, 2))


def test_sequence_match_marks_meaningful_partial_overlap() -> None:
    result = match_page_sequences(
        _archive(1, tuple(range(10))),
        _archive(2, (5, 6, 7, 8, 9, 20, 21, 22, 23, 24)),
    )

    assert result is not None
    assert result.relation is SequenceRelation.PARTIAL_OVERLAP
    assert result.matched_pages == 5
    assert result.matched_pairs == ((5, 0), (6, 1), (7, 2), (8, 3), (9, 4))


def test_sequence_match_rejects_unrelated_or_too_short_overlap() -> None:
    assert match_page_sequences(
        _archive(1, (1, 2, 3, 4, 5)),
        _archive(2, (4, 5, 20, 21, 22)),
    ) is None


def test_sequence_match_leaves_same_length_duplicate_to_existing_relation() -> None:
    assert match_page_sequences(
        _archive(1, (1, 2, 3, 4, 5)),
        _archive(2, (1, 2, 3, 4, 5)),
    ) is None
