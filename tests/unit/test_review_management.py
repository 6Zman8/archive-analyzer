from dataclasses import replace
from archive_analyzer.precision_analysis import detect_language, DetectedLanguage
from archive_analyzer.review_ui import group_work_tab
from archive_analyzer.review_viewmodel import build_group_view, _language_evidence_text
from tests.unit.test_explorer_excel_review import real_fixture


def test_japanese_dialogue_with_sparse_hangul_ocr_noise():
    pages = tuple(('これは日本語の本文です。今日はいい天気ですね。' * 5) + ('가' if i == 0 else '') for i in range(6))
    assert detect_language(pages, frozenset()).language is DetectedLanguage.JAPANESE


def test_missing_file_group_has_dedicated_tab(tmp_path):
    repo, root, ids = real_fixture(tmp_path)
    try:
        from archive_analyzer.recommendation_service import refresh_recommendations
        refresh_recommendations(repo, root)
        key = repo.review_candidate_sets(root)[0].set_key
        group = build_group_view(repo.review_group_details(key))
        group = replace(group, members=(replace(group.members[0], quarantine_status='FAILED'), *group.members[1:]))
        assert group_work_tab(group) == 4
    finally:
        repo.close()


def test_analyzed_unknown_does_not_look_unanalyzed(tmp_path):
    repo, root, ids = real_fixture(tmp_path)
    try:
        member = repo.group_details('precision-group').members[0]
        assert '판정 불가' in _language_evidence_text(replace(member, precision_language='UNKNOWN'))
        assert '정밀분석' in _language_evidence_text(replace(member, precision_language='UNKNOWN'))
    finally:
        repo.close()


def test_cached_language_upgrade_reuses_v2_pages_without_archive_reads(tmp_path):
    from threading import Event
    from archive_analyzer import precision_service
    from tests.unit.test_precision_service import _repository_with_images, FakeReader, FakeOcr, _encoded_page
    repo, root, ids = _repository_with_images(tmp_path, (6, 6))
    try:
        reader = FakeReader(_encoded_page())
        ocr = FakeOcr(('これは日本語の本文です。今日はいい天気ですね。'*5 + '가',))
        precision_service.analyze_precision(repo, root, Event(), set_keys=('precision-set',),reader=reader,ocr=ocr)
        repo._connection.execute("UPDATE precision_profiles SET algorithm_version=2,language='UNKNOWN',language_confidence=0")
        repo._connection.commit()
        before=(reader.calls,ocr.calls)
        assert precision_service.refresh_cached_language_decisions(repo,root,Event()) == 2
        assert (reader.calls,ocr.calls)==before
        assert repo._connection.execute('SELECT language FROM precision_profiles WHERE algorithm_version=3').fetchall()==[('JAPANESE',),('JAPANESE',)]
        assert precision_service.refresh_cached_language_decisions(repo,root,Event())==0
    finally:
        repo.close()
