from archive_analyzer.classification import (
    classify_entry,
    natural_sort_key,
    serialize_natural_sort_key,
)
from archive_analyzer.domain import EntryKind


def test_natural_sort_orders_numeric_pages() -> None:
    assert sorted(["10.jpg", "2.jpg", "1.jpg"], key=natural_sort_key) == [
        "1.jpg",
        "2.jpg",
        "10.jpg",
    ]


def test_natural_sort_normalizes_unicode_and_casefolds_text() -> None:
    assert natural_sort_key("Caf\u00e9/\ud398\uc774\uc9c02.JPG") == natural_sort_key(
        "cafe\u0301/\ud398\uc774\uc9c02.jpg"
    )


def test_serialized_natural_sort_key_is_compact_json() -> None:
    assert serialize_natural_sort_key("page 12.jpg") == '["page ",12,".jpg"]'


def test_classify_entry_recognizes_images_and_nested_archives() -> None:
    assert classify_entry("cover.JPEG") == (EntryKind.IMAGE, "jpeg")
    assert classify_entry("inside/book.CBZ") == (EntryKind.NESTED_ARCHIVE, None)
    assert classify_entry("notes.txt") == (EntryKind.OTHER, None)
