from dataclasses import replace
from pathlib import Path
from threading import Event

from archive_analyzer.recommendation import recommend_candidate_set, recommend_with_estimates
from archive_analyzer.recommendation_policy import RecommendationPolicy
from tests.unit.test_recommendation import candidate, evidence_for


def test_title_estimate_never_uses_inconclusive_analysis_exception():
    a=replace(candidate(),evidence_sources={'language':'filename'})
    b=replace(candidate(2,mtime_ns=10_000_000_000),evidence_sources={'language':'filename'})
    evidence={key:replace(value,content_equivalent=True) for key,value in evidence_for(a,b).items()}
    for policy in (None,RecommendationPolicy('priority',('language','mtime'))):
        assert recommend_candidate_set((a,b),evidence,policy=policy).status == 'ANALYSIS_REQUIRED'
        assert recommend_with_estimates((a,b),evidence,policy=policy).status == 'RECOMMENDED'
        measured=(replace(a,evidence_sources={'language':'precision_unknown'}),replace(b,evidence_sources={'language':'precision_unknown'}))
        assert recommend_candidate_set(measured,evidence,policy=policy).status == 'RECOMMENDED'


def test_actual_inconclusive_profile_is_distinct_from_no_analysis(tmp_path):
    from tests.unit.test_explorer_excel_review import real_fixture
    from tests.unit.test_precision_service import FakeReader, FakeOcr, _encoded_page
    from archive_analyzer.precision_service import analyze_precision
    from archive_analyzer.recommendation_service import refresh_recommendations, build_inputs, partition_group
    repo,root,ids=real_fixture(tmp_path,(4,4))
    try:
        import os
        row=repo._connection.execute('SELECT path,mtime_ns FROM archives WHERE id=?',(ids[1],)).fetchone()
        path=Path(row[0]);new_time=row[1]+10_000_000_000
        os.utime(path,ns=(path.stat().st_atime_ns,new_time))
        repo._connection.execute('UPDATE archives SET mtime_ns=? WHERE id=?',(new_time,ids[1]))
        repo._connection.execute('UPDATE archive_fingerprints SET mtime_ns=? WHERE archive_id=?',(new_time,ids[1]))
        repo._connection.execute("UPDATE candidate_relations SET relation='EXACT_CONTENT'")
        repo._connection.commit()
        policy=RecommendationPolicy('priority',('language','title','mtime'))
        refresh_recommendations(repo,root,policy=policy)
        source=repo.recommendation_source_groups(root)[0]
        assert not any(item.language_analyzed for item in source.members)
        assert all(item.recommendation=='NONE' for item in repo.latest_recommendations_for_root(root))
        keys=tuple(s.set_key for s in repo.review_candidate_sets(root))
        analyze_precision(repo,root,Event(),set_keys=keys,reader=FakeReader(_encoded_page()),ocr=FakeOcr(('',)))
        source=repo.recommendation_source_groups(root)[0]
        assert all(item.language_analyzed for item in source.members)
        inputs=build_inputs(source,partition_group(source)[0])
        assert all(item.evidence_sources['language']=='precision_unknown' for item in inputs)
        refresh_recommendations(repo,root,policy=policy)
        assert any(item.recommendation=='KEEP' for item in repo.latest_recommendations_for_root(root))
    finally:repo.close()
