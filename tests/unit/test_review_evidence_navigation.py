from dataclasses import replace
from types import SimpleNamespace

from archive_analyzer import review_ui
from archive_analyzer.review_viewmodel import EdgeRow


def edge(**changes):
    return replace(EdgeRow(1, 'a.zip', 2, 'b.zip', '일부 페이지 포함', .9,
        '일부 페이지가 겹칩니다.', 'MANUAL_REVIEW', '직접 관계 근거', 2, 4, 3,
        matched_pairs=((0, 0), (2, 1))), **changes)


def test_unmatched_indices_follow_alignment_not_same_page_numbers():
    assert review_ui.edge_unmatched_pages(edge()) == ((1, 3), (2,))


def test_absent_alignment_is_unknown_not_all_pages_different():
    assert review_ui.edge_unmatched_pages(edge(matched_pairs=())) is None


def test_fully_matched_without_alignment_has_no_unmatched_pages():
    assert review_ui.edge_unmatched_pages(edge(matched_pairs=(), matched_pages=4,
        left_page_count=4, right_page_count=4)) == ((), ())


def test_preserve_reason_and_explicit_denominators_in_evidence():
    text = review_ui.edge_evidence_text(edge(preserve_required=True,
        edition_summary='번역판 차이'))
    assert '일치 2쪽' in text and '왼쪽 전체 4쪽' in text and '오른쪽 전체 3쪽' in text
    assert '보존 필요' in text and '번역판 차이' in text
    assert '내용 차이 확정' in text


def test_navigation_cycles_actual_unmatched_pages_without_changing_review():
    selected = edge()
    window = object.__new__(review_ui.ReviewWindow)
    window._edge_tree = SimpleNamespace(selection=lambda: ('edge',))
    window._edge_table = SimpleNamespace(row=lambda _key: selected)
    window._members_for_edge = lambda _edge: (SimpleNamespace(archive_id=1), SimpleNamespace(archive_id=2))
    window._preview_page_indices = {1: 0, 2: 0}
    calls = []
    window._request_previews = lambda members, reset_pages: calls.append((dict(window._preview_page_indices), reset_pages))
    window._status = SimpleNamespace(set=lambda text: None)
    window._show_unmatched_page()
    window._show_unmatched_page()
    window._show_unmatched_page()
    assert calls == [({1: 1, 2: 2}, False), ({1: 3, 2: 2}, False), ({1: 1, 2: 2}, False)]
