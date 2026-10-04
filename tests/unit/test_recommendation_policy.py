from dataclasses import replace
from pathlib import Path
from archive_analyzer.recommendation import recommend_candidate_set, recommend_with_estimates
from archive_analyzer.recommendation_policy import RecommendationPolicy as Policy
from archive_analyzer.precision_analysis import DetectedLanguage as L
from tests.unit.test_recommendation import candidate, evidence_for


def test_korean_and_size_conflict_follows_order_and_exclusions():
    left = candidate(language=L.KOREAN, size=890)
    right = candidate(2, language=L.JAPANESE, size=1230)
    evidence = evidence_for(left, right)
    for order, winner in ((('language','size'), 1), (('size','language'), 2), (('language',), 1), (('size',), 2)):
        result = recommend_candidate_set((left,right), evidence, policy=Policy('priority',order))
        assert [item.archive_id for item in result.items if item.recommendation=='KEEP'] == [winner]
        assert 'priority:' in result.items[0].reason
    assert all(item.recommendation=='NONE' for item in recommend_candidate_set((left,right),evidence,policy=Policy('priority',())).items)


def test_missing_lower_priority_does_not_block_decisive_higher_priority():
    left = candidate(language=L.KOREAN, size=None)
    right = candidate(2, language=L.JAPANESE)
    evidence=evidence_for(left,right)
    assert recommend_candidate_set((left,right),evidence,policy=Policy('priority',('language','size'))).items[0].recommendation=='KEEP'
    assert recommend_candidate_set((left,right),evidence,policy=Policy('priority',('size','language'))).status=='ANALYSIS_REQUIRED'
    left=replace(left,evidence_sources={'language':'filename'})
    assert recommend_candidate_set((left,right),evidence,policy=Policy('priority',('language',))).status=='ANALYSIS_REQUIRED'
    assert recommend_with_estimates((left,right),evidence,policy=Policy('priority',('language',))).items[0].recommendation=='KEEP'


def test_identical_content_obeys_custom_order_and_ties_do_not_pick_id():
    left=candidate(mtime_ns=0,title_rank=3)
    right=candidate(2,mtime_ns=10_000_000_000,title_rank=1)
    evidence={key:replace(pair,content_equivalent=True) for key,pair in evidence_for(left,right).items()}
    assert recommend_candidate_set((left,right),evidence,policy=Policy('priority',('mtime','title'))).items[1].recommendation=='KEEP'
    assert recommend_candidate_set((left,right),evidence,policy=Policy('priority',('title','mtime'))).items[0].recommendation=='KEEP'
    assert recommend_candidate_set((left,right),evidence,policy=Policy('priority',('pages',))).status=='NONE'


def test_backfill_reuses_current_names_and_recomputes_changed_snapshot(tmp_path,monkeypatch):
    from tests.unit.test_precision_service import _repository_with_images
    from archive_analyzer.storage import duplicate_repository as module
    repo,root,ids=_repository_with_images(tmp_path,(3,3))
    try:
        assert repo.backfill_filename_evidence(root)==2
        original=module.normalize_filename_evidence
        calls=[]
        monkeypatch.setattr(module,'normalize_filename_evidence',lambda path:(calls.append(path),original(path))[1])
        assert repo.backfill_filename_evidence(root)==0
        assert calls==[]
        repo._connection.execute('UPDATE archives SET file_size=file_size+1 WHERE id=?',(ids[0],))
        repo._connection.commit()
        assert repo.backfill_filename_evidence(root)==1 and len(calls)==1
        assert len(repo.filename_evidence_for_archives(ids))==2
    finally:
        repo.close()


def test_policy_roundtrip_and_invalid_values():
    policy=Policy('priority',('size','language'))
    assert Policy.from_dict(policy.to_dict())==policy
    assert Policy.from_dict({'mode':'priority','order':['size','size','bogus']}).order==('size',)


def test_refresh_persists_changed_policy_and_warm_cache(tmp_path):
    from tests.unit.test_explorer_excel_review import real_fixture
    from archive_analyzer.recommendation_service import refresh_recommendations
    repo,root,ids=real_fixture(tmp_path,(4,4))
    try:
        repo._connection.execute('UPDATE archives SET file_size=1000+id*100,mtime_ns=id*10000000000')
        repo._connection.commit()
        events=[]
        policy=Policy('priority',('size',))
        refresh_recommendations(repo,root,policy=policy,progress=lambda *args:events.append(args))
        first=repo.latest_recommendations_for_root(root)
        assert [r.archive_id for r in first if r.recommendation=='KEEP']==[max(ids)]
        runs=repo._connection.execute('SELECT COUNT(*) FROM recommendation_runs').fetchone()[0]
        refresh_recommendations(repo,root,policy=policy)
        assert repo._connection.execute('SELECT COUNT(*) FROM recommendation_runs').fetchone()[0]==runs
        refresh_recommendations(repo,root,policy=Policy('priority',()))
        assert all(r.recommendation=='NONE' for r in repo.latest_recommendations_for_root(root))
        assert any(total>0 for _,total,_ in events)
    finally: repo.close()


def test_native_policy_dialog_order_toggle_save(tmp_path):
    import subprocess,sys
    result=subprocess.run([sys.executable,'-c',
        'from tests.unit.test_recommendation_policy import _dialog_check; _dialog_check()'],
        capture_output=True,text=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode==0,result.stdout+result.stderr


def _dialog_check():
    import tkinter as tk
    from tkinter import ttk
    from archive_analyzer.policy_dialog import edit_policy
    root=tk.Tk();root.withdraw()
    failures=[]
    def children(widget):
        for child in widget.winfo_children():
            yield child
            yield from children(child)
    def interact():
        dialog=next(w for w in root.winfo_children() if isinstance(w,tk.Toplevel))
        dialog.attributes('-alpha',0)
        try:
            widgets=list(children(dialog))
            tree=next(w for w in widgets if isinstance(w,ttk.Treeview))
            def button(name): return next(w for w in widgets if isinstance(w,ttk.Button) and w.cget('text')==name)
            next(w for w in widgets if isinstance(w,ttk.Radiobutton) and w.cget('value')=='priority').invoke()
            tree.selection_set('size')
            for _ in range(3): button('위로').invoke()
            tree.selection_set('language');button('고려 / 제외').invoke()
            button('저장하고 추천 갱신').invoke()
        except BaseException as error:
            failures.append(error);dialog.destroy()
    root.after(100,interact)
    try:
        result=edit_policy(root,Policy())
        assert not failures,failures
        assert result.mode=='priority' and result.order[0]=='size' and 'language' not in result.order
    finally: root.destroy()
