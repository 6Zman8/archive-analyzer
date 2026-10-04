from dataclasses import replace
from pathlib import Path

from archive_analyzer.filename_normalization import normalize_filename_evidence
from archive_analyzer.recommendation import recommend_candidate_set
from tests.unit.test_recommendation import candidate, evidence_for


def test_explicit_estimates_allow_language_mosaic_but_keep_conflict_blocked():
    from archive_analyzer.recommendation import recommend_with_estimates
    from archive_analyzer.precision_analysis import DetectedLanguage, PairDirection
    left = candidate(language=DetectedLanguage.KOREAN, mosaic_rank=1)
    right = candidate(2, language=DetectedLanguage.UNKNOWN, mosaic_rank=None)
    evidence = evidence_for(left, right, mosaic=PairDirection.UNKNOWN)
    result = recommend_with_estimates((left, right), evidence)
    assert result.items[0].recommendation == 'KEEP'
    assert 'estimated:' in result.items[0].reason
    conflict = recommend_with_estimates((replace(left, file_size=500), right), evidence)
    assert all(item.recommendation == 'NONE' for item in conflict.items)


def test_reconcile_quarantined_file_returned_to_source(tmp_path):
    from threading import Event
    from tests.unit.test_quarantine import _repository
    from archive_analyzer.quarantine import quarantine_archives, reconcile_quarantine_items
    repository, group, archive_id, source = _repository(tmp_path)
    try:
        quarantine_archives(repository, group, (archive_id,), tmp_path / 'quarantine', Event())
        item = repository.active_quarantine_item(group, archive_id)
        item.destination_path.rename(source)
        assert reconcile_quarantine_items(repository, item.root_id, Event()) == 1
        assert repository.quarantine_item(item.id).status == 'RESTORED'
    finally:
        repository.close()


def test_hangul_title_is_korean_estimate_without_language_marker():
    evidence = normalize_filename_evidence(Path('[Circle] 우리의 여름 이야기.zip'))
    assert evidence.language.value == 'KOREAN'


def test_confirmed_identical_content_still_requires_opt_in_for_title_estimates():
    left = replace(candidate(size=2000), evidence_sources={'language': 'filename', 'mosaic': 'unknown'})
    right = replace(candidate(2, size=1000, mtime_ns=10_000_000_000), evidence_sources=left.evidence_sources)
    evidence = {key: replace(value, content_equivalent=True) for key, value in evidence_for(left, right).items()}
    decision = recommend_candidate_set((left, right), evidence)
    assert decision.status == 'ANALYSIS_REQUIRED'
    from archive_analyzer.recommendation import recommend_with_estimates
    assert [item.archive_id for item in recommend_with_estimates((left,right),evidence).items if item.recommendation == 'KEEP'] == [2]


def test_estimated_application_survives_strict_refresh_and_reopen(tmp_path):
    from threading import Event
    from tests.unit.test_explorer_excel_review import real_fixture
    from archive_analyzer.edition_service import analyze_editions
    from archive_analyzer.recommendation_service import refresh_recommendations
    from archive_analyzer.batch_review import preview_recommendation_application, apply_recommendations
    from archive_analyzer.storage.duplicate_repository import DuplicateRepository
    from archive_analyzer.review_viewmodel import build_group_view
    from datetime import UTC, datetime
    repository, root_id, ids = real_fixture(tmp_path)
    try:
        analyze_editions(repository, root_id, Event())
        refresh_recommendations(repository, root_id)
        keys = tuple(item.set_key for item in repository.review_candidate_sets(root_id))
        assert keys
        assert all(record.status == 'ANALYSIS_REQUIRED' for record in repository.latest_recommendations(keys))
        refresh_recommendations(repository, root_id, allow_estimates=True, selected_set_keys=keys)
        preview = preview_recommendation_application(repository, keys)
        assert (preview.keep, preview.remove) == (1, 1)
        result = apply_recommendations(repository, keys, datetime.now(UTC))
        assert result.applied == 2
        refresh_recommendations(repository, root_id)
        assert all(record.status == 'ANALYSIS_REQUIRED' for record in repository.latest_recommendations(keys))
    finally:
        repository.close()
    repository = DuplicateRepository.open(tmp_path / 'index.db')
    try:
        group = build_group_view(repository.review_group_details(keys[0]))
        assert all(member.review_status_text.startswith('추정 적용 · ') for member in group.members)
        assert all(member.path.is_file() for member in group.members)
    finally:
        repository.close()


def test_missing_quarantine_file_with_removed_subfolder_is_not_shown_as_quarantined(tmp_path):
    from threading import Event
    from tests.unit.test_quarantine import _repository
    from archive_analyzer.quarantine import quarantine_archives, reconcile_quarantine_items
    repository, group, archive_id, source = _repository(tmp_path)
    try:
        quarantine_archives(repository, group, (archive_id,), tmp_path / 'quarantine', Event())
        item = repository.active_quarantine_item(group, archive_id)
        item.destination_path.rename(tmp_path / 'unlocated-test-copy.cbz')
        item.destination_path.parent.rmdir()
        assert reconcile_quarantine_items(repository, item.root_id, Event()) == 1
        assert repository.quarantine_item(item.id).status == 'FAILED'
        assert (tmp_path / 'unlocated-test-copy.cbz').is_file()
    finally:
        repository.close()


def test_estimates_do_not_override_conflicting_mosaic_or_unknown_color():
    from archive_analyzer.recommendation import recommend_with_estimates
    for sources in ({'mosaic': 'conflict'}, {'color': 'unknown'}, {'color': 'filename'}):
        left = replace(candidate(mtime_ns=10_000_000_000), evidence_sources=sources)
        right = candidate(2)
        result = recommend_with_estimates((left, right), evidence_for(left, right))
        assert result.items[0].recommendation == 'KEEP'


def test_estimated_refresh_only_changes_selected_set_with_shared_source(tmp_path):
    from tests.unit.test_recommendation_service import _repository, _seed_group
    from archive_analyzer.recommendation_service import refresh_recommendations
    repository, root_id = _repository(tmp_path)
    try:
        _seed_group(repository, root_id, 'shared-source', (.1, .1, .8, .8))
        refresh_recommendations(repository, root_id)
        sets = repository.review_candidate_sets(root_id)
        assert len(sets) == 2
        untouched = repository.latest_recommendations((sets[1].set_key,))
        refresh_recommendations(repository, root_id, allow_estimates=True, selected_set_keys=(sets[0].set_key,))
        assert repository.latest_recommendations((sets[1].set_key,)) == untouched
        assert all(record.reason.startswith('estimated:') for record in repository.latest_recommendations((sets[0].set_key,)))
    finally:
        repository.close()


def test_precision_worker_refreshes_color_before_recommendations(tmp_path):
    from archive_analyzer.review_ui import ReviewWorker, _ReviewWork
    from tests.unit.test_explorer_excel_review import real_fixture
    from archive_analyzer.recommendation_service import refresh_recommendations
    repository, root_id, ids = real_fixture(tmp_path)
    calls = []
    try:
        refresh_recommendations(repository, root_id)
        keys = tuple(item.set_key for item in repository.review_candidate_sets(root_id))
        def precision(repo, root, event, **kwargs):
            calls.append(('precision', kwargs['set_keys']))
        def edition(repo, root, event, **kwargs):
            calls.append(('edition', kwargs['set_keys']))
        def refresh(repo, root, **kwargs):
            calls.append(('refresh', root))
        worker = ReviewWorker(tmp_path/'index.db', tmp_path, precision_analyzer=precision,
                              edition_analyzer=edition, recommendation_refresher=refresh)
        result = worker._perform(repository, root_id, _ReviewWork('precision', group_keys=keys))
        assert result.error is None
        assert calls == [('precision', keys), ('edition', keys), ('refresh', root_id)]
        assert result.groups
    finally:
        repository.close()
