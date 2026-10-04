from dataclasses import replace
from threading import Event

import pytest

from archive_analyzer import review_ui, batch_review
from archive_analyzer.precision_analysis import DetectedLanguage
from archive_analyzer.recommendation import recommend_candidate_set, RecommendationStatus
from tests.unit.test_recommendation import candidate, evidence_for
from tests.unit.test_batch_review import _fixture, NOW


@pytest.mark.parametrize('changes', [
    {'size': 2000, 'mtime_ns': 0},
    {'pages': 30, 'language': DetectedLanguage.JAPANESE},
    {'area': None},
    {'language': DetectedLanguage.UNKNOWN},
])
def test_conflict_or_unknown_never_recommends(changes):
    left = candidate(**changes)
    right = candidate(2, mtime_ns=10_000_000_000, language=DetectedLanguage.KOREAN)
    decision = recommend_candidate_set((left, right), evidence_for(left, right))
    assert decision.status is not RecommendationStatus.RECOMMENDED
    assert all(item.recommendation == 'NONE' for item in decision.items)


def test_estimated_language_blocks_even_exact_content():
    left = replace(candidate(size=2000), evidence_sources={'language': 'filename'})
    right = candidate(2)
    evidence = {key: replace(value, content_equivalent=True) for key, value in evidence_for(left, right).items()}
    result = recommend_candidate_set((left, right), evidence)
    assert result.status is RecommendationStatus.ANALYSIS_REQUIRED


def test_exact_content_with_unmeasured_mosaic_never_recommends():
    sources = {'language': 'precision', 'color': 'measured', 'mosaic': 'unknown'}
    left, right = replace(candidate(size=2000), evidence_sources=sources), replace(candidate(2), evidence_sources=sources)
    evidence = {key: replace(value, content_equivalent=True) for key, value in evidence_for(left, right).items()}
    assert recommend_candidate_set((left, right), evidence).status is RecommendationStatus.RECOMMENDED


def test_group_reset_preserves_history_and_allows_reapply(tmp_path):
    repo, _, selected = _fixture(tmp_path)
    try:
        assert batch_review.apply_recommendations(repo, (selected.set_key,), NOW).applied == 2
        previous = repo._connection.execute('SELECT COUNT(*) FROM review_actions').fetchone()[0]
        repo.reset_review_sets((selected.set_key,), NOW)
        assert repo._connection.execute('SELECT COUNT(*) FROM review_actions').fetchone()[0] == previous + 2
        assert batch_review.preview_recommendation_application(repo, (selected.set_key,)).applicable == 2
        assert batch_review.apply_recommendations(repo, (selected.set_key,), NOW).applied == 2
    finally:
        repo.close()


def test_group_restore_after_reset_preserves_contents(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    repo, _, selected = _fixture(source)
    try:
        before = (source / '2.cbz').read_bytes()
        batch_review.apply_recommendations(repo, (selected.set_key,), NOW)
        assert batch_review.batch_quarantine(repo, (selected.set_key,), tmp_path / 'quarantine', Event()).completed == 1
        repo.reset_review_sets((selected.set_key,), NOW)
        assert batch_review.batch_restore(repo, (selected.set_key,), Event()).completed == 1
        assert (source / '2.cbz').read_bytes() == before
        assert batch_review.batch_restore(repo, (selected.set_key,), Event()).completed == 0
    finally:
        repo.close()


def test_single_review_does_not_reload_unrelated_groups(tmp_path, monkeypatch):
    repo, root_id, selected = _fixture(tmp_path)
    try:
        worker = review_ui.ReviewWorker(tmp_path / 'index.db', tmp_path)
        monkeypatch.setattr(review_ui, '_load_groups', lambda *args: pytest.fail('full group reload'))
        result = worker._perform(repo, root_id, review_ui._ReviewWork(
            'actions', group_key=selected.set_key, archive_ids=(1,), action=review_ui.ReviewAction.KEEP))
        assert result.partial_groups
        assert result.groups[0].members[0].user_decision is review_ui.ReviewAction.KEEP
    finally:
        repo.close()


def test_large_table_updates_only_changed_row_and_keeps_selection(tmp_path, monkeypatch):
    import tkinter as tk
    from tkinter import ttk
    from archive_analyzer.review_table import TreeTableController, UiSettingsStore
    from tests.unit.test_review_table import Row, SPECS
    root = tk.Tk()
    root.withdraw()
    try:
        tree = ttk.Treeview(root, columns=tuple(spec.key for spec in SPECS), show='headings')
        table = TreeTableController(tree, settings_key='speed', specs=SPECS,
            store=UiSettingsStore(tmp_path / 'ui.json'),
            row_id_getter=lambda row, index: row.number,
            value_getter=lambda row, spec: getattr(row, spec.key))
        rows = tuple(Row(i, f'file-{i}', 0.9, 20, '보존') for i in range(10000))
        table.set_rows(rows)
        tree.selection_set('5000')
        monkeypatch.setattr(tree, 'delete', lambda *args: pytest.fail('unchanged rows deleted'))
        monkeypatch.setattr(tree, 'insert', lambda *args, **kwargs: pytest.fail('unchanged rows inserted'))
        table.set_rows(tuple(replace(row, review='검토 필요') if row.number == 5000 else row for row in rows))
        assert tree.selection() == ('5000',)
        assert tree.item('5000', 'values')[-1] == '검토 필요'
    finally:
        root.destroy()
