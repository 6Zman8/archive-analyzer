"""Read-only timings against an existing database; never opens source archives."""
from pathlib import Path
import sqlite3
import time
import json
import sys
from archive_analyzer.storage.duplicate_repository import DuplicateRepository
from archive_analyzer.filename_normalization import normalize_filename_evidence
from archive_analyzer.review_ui import _load_groups

path=Path(sys.argv[1])
connection=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
connection.execute('PRAGMA query_only=ON')
repo=DuplicateRepository(connection)
root=connection.execute('SELECT id FROM scan_roots LIMIT 1').fetchone()[0]
report={}
started=time.perf_counter()
paths=connection.execute('SELECT path FROM archives WHERE scan_root_id=?',(root,)).fetchall()
for row in paths: normalize_filename_evidence(Path(row[0]))
report['archives']=len(paths)
report['old_title_reparse_seconds']=round(time.perf_counter()-started,3)
started=time.perf_counter()
cached=connection.execute('SELECT COUNT(*) FROM archives a WHERE a.scan_root_id=? AND NOT EXISTS (SELECT 1 FROM filename_evidence e WHERE e.archive_id=a.id AND e.file_size=a.file_size AND e.mtime_ns=a.mtime_ns AND e.path_key=a.path_key AND e.algorithm_version=1)',(root,)).fetchone()[0]
report['cached_lookup_seconds']=round(time.perf_counter()-started,3)
report['missing_old_cache']=cached
started=time.perf_counter()
groups=_load_groups(repo,root)
report['list_seconds']=round(time.perf_counter()-started,3)
report['groups']=len(groups)
print(json.dumps(report))
connection.close()
