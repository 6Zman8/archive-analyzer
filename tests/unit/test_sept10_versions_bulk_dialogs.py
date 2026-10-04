from dataclasses import replace
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from archive_analyzer.recommendation import recommend_candidate_set, PairEvidence
from archive_analyzer.recommendation_policy import RecommendationPolicy
from archive_analyzer.precision_analysis import DetectedLanguage as L, PairDirection as D
from archive_analyzer.version_dates import parse_title_dates
from tests.unit.test_recommendation import candidate, evidence_for


def version(i, name, pages=20, **kwargs):
    return candidate(i, name=name + '.zip', pages=pages, **kwargs)


def pairs(items, identical=False):
    return {(a.archive_id, b.archive_id): PairEvidence(a.archive_id, b.archive_id, D.UNKNOWN, D.UNKNOWN, identical)
            for i, a in enumerate(items) for b in items[i+1:]}


def recommend(items):
    return recommend_candidate_set(items, pairs(items), policy=RecommendationPolicy('priority', ('language', 'size')))


@pytest.mark.parametrize('name', ['Story 2024-01-01~2024-12-31', 'Story 20240101-20241231',
    'Story 2024.01 to 2024.12', 'Story 2024년 1월 1일부터2024년 12월 31일'])
def test_period_title_parse(name):
    value = parse_title_dates(Path(name + '.zip'))
    assert value.key == 'story'
    assert value.span.start.isoformat() == '2024-01-01'
    assert value.span.end.isoformat() == '2024-12-31'
    assert value.span.is_range


def test_newer_snapshot_requires_more_pages_overrides_lower_size():
    a = version(1, '[Author] Story 2024-01-01', size=5000, language=L.KOREAN)
    b = version(2, '[Author] Story 2024-02-01', pages=30, size=1000, language=L.KOREAN)
    assert [item.recommendation for item in recommend((a,b)).items] == ['REMOVE_CANDIDATE','KEEP']
    assert all(item.recommendation == 'NONE' for item in recommend((a,replace(b,page_count=15))).items)
    assert all(item.recommendation == 'NONE' for item in recommend((a,replace(b,page_count=20))).items)
    other = replace(b, path=Path('[Other] Story 2024-02-01.zip'))
    assert not any('version_latest_pages' in item.reason for item in recommend((a,other)).items)


def test_period_superset_and_incomparable_periods_support_multiple_keeps():
    a = version(1, 'Story 2024-01-01~2024-06-30')
    b = version(2, 'Story 2024-01-01~2024-12-31', pages=30)
    assert [i.recommendation for i in recommend((a,b)).items] == ['REMOVE_CANDIDATE','KEEP']
    assert [i.recommendation for i in recommend_candidate_set((a,b),pairs((a,b),True)).items] == ['REMOVE_CANDIDATE','KEEP']
    assert recommend((a, replace(b,page_count=10))).status == 'NONE'
    c = version(3, 'Story 2024-05-01~2025-01-31', pages=28)
    result = recommend((a,b,c))
    assert [i.recommendation for i in result.items] == ['REMOVE_CANDIDATE','KEEP','KEEP']
    assert 'preserve_unique_periods' in result.items[1].reason
    d = version(4, 'Story 2025-02-01~2025-03-31', pages=8)
    assert all(i.recommendation == 'KEEP' for i in recommend((b,d)).items)


def test_adjacent_version_chain_recommends_newest_more_complete_file():
    items = (version(1,'Story 2024-01-01',pages=10), version(2,'Story 2024-02-01',pages=20),
             version(3,'Story 2024-03-01',pages=30))
    evidence = pairs(items)
    del evidence[(1,3)]
    result = recommend_candidate_set(items,evidence)
    assert [i.recommendation for i in result.items] == ['REMOVE_CANDIDATE','REMOVE_CANDIDATE','KEEP']


def test_undated_counterpart_uses_local_modified_date():
    a = version(1, 'Story 2024-01-01')
    b = version(2, 'Story', pages=30, mtime_ns=int(datetime(2024,2,1).timestamp()*1e9))
    result = recommend((a,b))
    assert result.items[1].recommendation == 'KEEP'
    assert 'date:2024-02-01~2024-02-01;date_from_mtime' in result.items[1].reason
    assert recommend((a,replace(b,mtime_ns=None))).status == 'ANALYSIS_REQUIRED'


def test_year_ranges_are_periods_but_single_year_and_invalid_dates_are_not_removed():
    value = parse_title_dates(Path('Story 2023~2024.zip'))
    assert value.key == 'story' and value.span.start.isoformat() == '2023-01-01'
    assert value.span.end.isoformat() == '2024-12-31'
    assert parse_title_dates(Path('Story 2024.zip')).span is None
    assert parse_title_dates(Path('Story 2024-02-30.zip')).span is None
    assert parse_title_dates(Path('Story 20240100.zip')).span is None


def test_identical_content_ignores_language_in_priority_comparison_only_for_that_pair():
    a = replace(candidate(1, language=L.UNKNOWN, mtime_ns=0), evidence_sources={'language':'precision_unknown'})
    b = replace(candidate(2, language=L.KOREAN, mtime_ns=10_000_000_000), evidence_sources={'language':'precision'})
    policy = RecommendationPolicy('priority', ('language','mtime'))
    result = recommend_candidate_set((a,b),pairs((a,b),True),policy=policy)
    assert [i.recommendation for i in result.items] == ['REMOVE_CANDIDATE','KEEP']
    assert all(i.criteria['language'] == 'TIE' for i in result.items)
    assert recommend_candidate_set((a,b),pairs((a,b)),policy=policy).status == 'ANALYSIS_REQUIRED'


def test_multiple_keep_recommendations_persist_display_and_apply(tmp_path):
    from datetime import UTC
    from tests.unit.test_explorer_excel_review import real_fixture
    from archive_analyzer.paths import normalize_path_key
    from archive_analyzer.recommendation_service import refresh_recommendations
    from archive_analyzer.review_viewmodel import build_group_view
    from archive_analyzer.batch_review import preview_recommendation_application, apply_recommendations
    repo, root, ids = real_fixture(tmp_path, (4,4))
    try:
        for archive_id, name in zip(ids, ('Story 2024-01-01~2024-06-30.zip','Story 2024-05-01~2024-12-31.zip')):
            old = Path(repo._connection.execute('SELECT path FROM archives WHERE id=?',(archive_id,)).fetchone()[0])
            new = old.with_name(name); old.rename(new)
            repo._connection.execute('UPDATE archives SET path=?,path_key=? WHERE id=?',(str(new),normalize_path_key(new),archive_id))
        repo._connection.commit()
        refresh_recommendations(repo,root,allow_estimates=True)
        keys = tuple(i.set_key for i in repo.review_candidate_sets(root))
        group = build_group_view(repo.review_group_details(keys[0]))
        assert group.recommended_archive_id is None
        assert '1, 2번' in group.recommendation_text
        assert all('보존 추천' in m.recommendation_text for m in group.members)
        preview = preview_recommendation_application(repo, keys)
        assert (preview.keep,preview.remove) == (2,0)
        assert apply_recommendations(repo,keys,datetime.now(UTC)).applied == 2
        assert all(m.review_action.value == 'KEEP' for m in repo.review_group_details(keys[0]).members)
    finally:
        repo.close()


@pytest.mark.parametrize('operation', ('recommended','estimated','batch','keep'))
def test_four_bulk_buttons_use_visible_rows_when_selection_empty(operation):
    from archive_analyzer.review_ui import ReviewWindow
    window = object.__new__(ReviewWindow)
    chosen = []
    window._group_tree = SimpleNamespace(selection=lambda: chosen, get_children=lambda: ('visible2','visible1'))
    calls=[]
    window._worker = SimpleNamespace(submit_recommendation_preview=lambda *a,**k:calls.append((a,k)),
        submit_batch_preview=lambda *a,**k:calls.append((a,k)), submit_keep_unreviewed=lambda *a,**k:calls.append((a,k)))
    window._status = SimpleNamespace(set=lambda value: None)
    window._set_buttons_enabled = lambda value: None
    def act():
        if operation in {'recommended','estimated'}:
            window._preview_and_apply_recommendations(allow_estimates=operation=='estimated')
        elif operation == 'batch': window._preview_batch_actions()
        else: window._keep_unreviewed()
    act()
    assert calls[-1][0][0] == ('visible2','visible1')
    chosen.append('visible1'); act()
    assert calls[-1][0][0] == ('visible1',)


def test_dialog_calls_always_have_review_owner():
    from archive_analyzer.dialogs import OwnedDialogs
    owner=object();calls=[]
    module=SimpleNamespace(askyesno=lambda *a,**k:calls.append((a,k)))
    OwnedDialogs(module,owner).askyesno('title','message')
    assert calls[0][1]['parent'] is owner


def test_native_dialogs_follow_each_monitor_and_bulk_buttons_are_available(tmp_path):
    import subprocess,sys
    result=subprocess.run([sys.executable,'-c',
        'import sys;from pathlib import Path;from tests.unit.test_sept10_versions_bulk_dialogs import _native;_native(Path(sys.argv[1]))',str(tmp_path)],
        capture_output=True,text=True,timeout=35,creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0,result.stdout+result.stderr


def _native(tmp_path):
    import tkinter as tk
    from tkinter import ttk
    import win32api,win32con
    from archive_analyzer import review_ui
    from archive_analyzer.dialogs import center_dialog
    from archive_analyzer.review_table import UiSettingsStore
    from archive_analyzer.review_viewmodel import build_group_view
    from tests.unit.test_precision_service import _repository_with_images
    repo,_,_= _repository_with_images(tmp_path,(4,4))
    group=build_group_view(repo.review_group_details('precision-set'));repo.close()
    class Idle:
        def __init__(self,*a):pass
        def start(self):pass
        def submit_load(self):pass
        def poll_result(self):return None
    review_ui.ReviewWorker=review_ui.ThumbnailWorker=Idle
    review_ui.UiSettingsStore=lambda:UiSettingsStore(tmp_path/'settings.json')
    review_ui.ReviewWindow._request_previews=lambda *a,**k:None
    root=tk.Tk();root.withdraw()
    try:
        window=review_ui.ReviewWindow(root,tmp_path/'index.db',tmp_path)
        window._window.attributes('-alpha',0)
        window._render_groups((group,));window._finish_operation();root.update()
        window._group_tree.selection_remove(*window._group_tree.selection());root.update()
        assert len(window._default_all_group_buttons)==4
        assert all(str(b.cget('state'))=='normal' for b in window._default_all_group_buttons)
        assert window._messagebox.parent is window._window
        for monitor,_,_ in win32api.EnumDisplayMonitors():
            left,top,right,bottom=win32api.GetMonitorInfo(monitor)['Work']
            window._window.geometry(f'1000x700+{left+10}+{top+10}');root.update()
            dialog=tk.Toplevel(window._window);dialog.attributes('-alpha',0);dialog.geometry('360x200')
            center_dialog(dialog,window._window);root.update()
            actual=win32api.MonitorFromWindow(dialog.winfo_id(),win32con.MONITOR_DEFAULTTONEAREST)
            expected=win32api.MonitorFromWindow(window._window.winfo_id(),win32con.MONITOR_DEFAULTTONEAREST)
            assert int(actual)==int(expected), (window._window.geometry(),dialog.geometry(),win32api.GetMonitorInfo(actual),win32api.GetMonitorInfo(expected))
            dialog.destroy()
    finally:root.destroy()
