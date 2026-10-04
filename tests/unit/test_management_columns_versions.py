from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from archive_analyzer.candidate_index import build_candidate_index, CandidateSeed, DATED_SERIES_TITLE
from archive_analyzer.filename_normalization import dated_series_identity
from archive_analyzer.matching import match_candidate
from archive_analyzer.duplicate_domain import ReviewAction
from tests.unit.test_candidate_index import evidence
from tests.unit.test_matching import page_set


def test_dated_versions_include_undated_and_preserve_chapters():
    names = ('[Author] Story.zip', '[Author] Story [2024-01-01].zip', '[Author] Story 20240229 ongoing.zip')
    identities = [dated_series_identity(Path(name)) for name in names]
    assert len({item[0] for item in identities}) == 1
    assert dated_series_identity(Path('Story 20240230.zip'))[2] is False
    assert dated_series_identity(Path('Story 12.zip'))[0] != dated_series_identity(Path('Story 13.zip'))[0]
    inputs = tuple(replace(evidence(i + 1), series_key=key, series_date=date, series_versioned=versioned)
                   for i, (key, date, versioned) in enumerate(identities))
    seeds = build_candidate_index(inputs).seeds
    assert len(seeds) == 2
    assert all(DATED_SERIES_TITLE in seed.reasons for seed in seeds)
    assert build_candidate_index(tuple(reversed(inputs))).seeds == seeds


def test_large_update_verified_with_common_pixels_but_title_alone_is_not_duplicate():
    seed = CandidateSeed(1, 2, (DATED_SERIES_TITLE,), 0)
    original = page_set(1, ('a', 'b', 'c', 'd'))
    expanded = page_set(2, tuple(str(i) for i in range(12)) + ('a', 'b', 'c', 'd'))
    match = match_candidate(original, expanded, seed)
    assert match.matched_pages == 4 and match.confidence == 1.0
    assert match.relation.value == 'RELATED'
    assert 'DATED_SERIES_ADDED_12' in match.reasons
    unrelated = match_candidate(original, page_set(2, ('w', 'x', 'y', 'z')), seed)
    assert unrelated.matched_pages == 0


def test_keep_only_unreviewed_and_activity_survives_reload(tmp_path):
    from tests.unit.test_explorer_excel_review import real_fixture
    from archive_analyzer.review_ui import ReviewWorker, _ReviewWork, _load_groups
    repo, root, ids = real_fixture(tmp_path, (4, 4))
    worker = ReviewWorker(tmp_path / 'index.db', tmp_path)
    now = datetime.now(UTC)
    try:
        group = worker._perform(repo, root, _ReviewWork('load')).groups[0]
        worker._perform(repo, root, _ReviewWork('actions', group_key=group.group_key,
            archive_ids=(ids[0],), action=ReviewAction.REMOVE_CANDIDATE))
        assert repo.keep_unreviewed_groups((group.group_key,), now + timedelta(seconds=5)) == 1
        assert repo.keep_unreviewed_groups((group.group_key,), now + timedelta(seconds=6)) == 0
        loaded = _load_groups(repo, root)[0]
        decisions = {member.archive_id: member.user_decision for member in loaded.members}
        assert decisions == {ids[0]: ReviewAction.REMOVE_CANDIDATE, ids[1]: ReviewAction.KEEP}
        assert datetime.fromisoformat(loaded.reviewed_at) == now + timedelta(seconds=5)
    finally:
        repo.close()


def test_undetermined_precision_retains_title_estimate_for_priority_application(tmp_path):
    from tests.unit.test_explorer_excel_review import real_fixture
    from archive_analyzer.recommendation_service import refresh_recommendations
    from archive_analyzer.recommendation_policy import RecommendationPolicy
    from archive_analyzer.batch_review import preview_recommendation_application, apply_recommendations
    from archive_analyzer.paths import normalize_path_key
    repo, root, ids = real_fixture(tmp_path, (4, 4))
    try:
        for archive_id, language in zip(ids, ('Korean', 'Japanese')):
            old = Path(repo._connection.execute('SELECT path FROM archives WHERE id=?', (archive_id,)).fetchone()[0])
            new = old.with_name(f'Story [{language}].cbz')
            old.rename(new)
            repo._connection.execute('UPDATE archives SET path=?,path_key=? WHERE id=?', (str(new), normalize_path_key(new), archive_id))
        repo._connection.commit()
        policy = RecommendationPolicy('priority', ('language',))
        refresh_recommendations(repo, root, policy=policy)
        keys = tuple(item.set_key for item in repo.review_candidate_sets(root))
        from threading import Event
        from archive_analyzer.precision_service import analyze_precision
        from tests.unit.test_precision_service import FakeReader, FakeOcr, _encoded_page
        from archive_analyzer.review_viewmodel import build_group_view
        analyze_precision(repo, root, Event(), set_keys=keys, reader=FakeReader(_encoded_page()), ocr=FakeOcr(('',)))
        group = build_group_view(repo.review_group_details(keys[0]))
        assert any('정밀분석 판정 불가 (한국어 추정)' == member.language_text for member in group.members)
        assert all(item.recommendation == 'NONE' for item in repo.latest_recommendations(keys))
        refresh_recommendations(repo, root, allow_estimates=True, selected_set_keys=keys, policy=policy)
        preview = preview_recommendation_application(repo, keys)
        assert (preview.keep, preview.remove) == (1, 1)
        assert apply_recommendations(repo, keys, datetime.now(UTC)).applied == 2
    finally:
        repo.close()


def test_initial_scan_detects_large_dated_update_and_rescan_drops_missing_history(tmp_path, monkeypatch):
    from threading import Event
    from tests.integration.test_duplicate_end_to_end import _write_zip, _png_noise, _indexed_repository, CountingReader
    from archive_analyzer.duplicate_jobs import DuplicateAnalysisService
    from archive_analyzer.quarantine import quarantine_archives
    from archive_analyzer.deletion import delete_quarantined_archives
    from archive_analyzer.jobs import ScanService
    from archive_analyzer.inspection import ZipBackend
    from archive_analyzer import deletion
    from archive_analyzer.review_ui import _load_groups
    root_path = tmp_path / 'source'
    common = tuple(_png_noise(i) for i in range(4))
    _write_zip(root_path / 'Story 2024-01-01.zip', common)
    _write_zip(root_path / 'Story 2024-02-01.zip', tuple(_png_noise(i + 20) for i in range(12)) + common)
    repo, root = _indexed_repository(root_path, tmp_path / 'index.db')
    try:
        result = DuplicateAnalysisService(repo, CountingReader()).run(root, Event())
        assert result.candidate_group_count == 1
        group = repo.group_details(repo.group_summaries(root)[0].group_key)
        assert any('DATED_SERIES_COMMON_4_OF_4' in relation.reasons for relation in group.relations)
        target = group.members[0].archive_id
        from archive_analyzer.domain import FileSnapshot
        from archive_analyzer.paths import normalize_path_key
        member = group.members[0]
        repo.append_review_action(group.group_key, target, ReviewAction.REMOVE_CANDIDATE,
            FileSnapshot(member.path, normalize_path_key(member.path), member.file_size, member.mtime_ns, member.archive_format), datetime.now(UTC))
        quarantine_archives(repo, group.group_key, (target,), tmp_path / 'quarantine', Event())
        from archive_analyzer.review_ui import group_work_tab
        quarantined = _load_groups(repo, root)[0]
        assert quarantined.quarantined_at and group_work_tab(quarantined) == 2
        # The test consumes only its disposable file, never the user's recycle bin.
        monkeypatch.setattr(deletion, 'recycle_file', lambda path: Path(path).unlink())
        delete_quarantined_archives(repo, group.group_key, (target,), Event())
        deleted = _load_groups(repo, root)[0]
        assert deleted.deleted_at and group_work_tab(deleted) == 3
        assert repo._connection.execute("SELECT COUNT(*) FROM deletion_records WHERE state='DELETED'").fetchone()[0] == 1
        ScanService(repo, ZipBackend(), workers=1).run(root_path)
        DuplicateAnalysisService(repo, CountingReader()).run(root, Event())
        assert _load_groups(repo, root) == ()
        assert repo._connection.execute("SELECT COUNT(*) FROM deletion_records WHERE state='DELETED'").fetchone()[0] == 1
    finally:
        repo.close()
