import json
from contextlib import contextmanager
from hashlib import sha256
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Iterator, Mapping

from archive_analyzer.analysis_progress import ProgressCallback, track_progress
from archive_analyzer.candidate_index import ArchiveEvidence
from archive_analyzer.domain import ArchiveFormat, FileSnapshot
from archive_analyzer.duplicate_domain import (
    AnalysisStage,
    ArchiveAnalysisInput,
    DuplicateRelation,
    DuplicateProgress,
    ImageEntryRef,
    ProbeFingerprint,
    ReviewAction,
)
from archive_analyzer.fingerprinting import ImageFingerprint, probe_positions
from archive_analyzer.filename_normalization import (
    FilenameEvidence,
    FilenameSignal,
    language_hints_for_signal,
    normalize_filename_evidence,
)
from archive_analyzer.edition_analysis import (
    EditionComparison,
    EditionEvidence,
    EditionFlag,
    EditionKind,
    EditionProfile,
)
from archive_analyzer.matching import ArchiveFingerprintSet, CandidateMatch
from archive_analyzer.precision_analysis import (
    DetectedLanguage,
    PageLanguageEvidence,
    PageQualityMetrics,
)
from archive_analyzer.sequence_matching import SequenceMatch, SequenceRelation
from archive_analyzer.storage.repository import Repository


_ARCHIVE_VALIDATION_CHUNK_SIZE = 900
_ANALYSIS_INPUT_BATCH_SIZE = 200
_RECOMMENDATION_SET_ALGORITHM_VERSION = 2


@dataclass(frozen=True, slots=True)
class CachedImageFingerprint:
    entry_position: int
    fingerprint: ImageFingerprint


@dataclass(frozen=True, slots=True)
class CachedFingerprints:
    sha256: str | None
    hash_state: str
    filename_tokens_json: str
    language_hints_json: str
    image_fingerprints: tuple[CachedImageFingerprint, ...]
    image_failures: tuple[tuple[int, str], ...]
    full_entry_positions: frozenset[int]


@dataclass(frozen=True, slots=True)
class DuplicateJob:
    id: int
    analysis_run_id: int
    archive_id: int | None
    stage: AnalysisStage
    subject_key: str
    status: str
    attempts: int
    last_error_code: str | None


@dataclass(frozen=True, slots=True)
class CandidateRelationRecord:
    archive_a_id: int
    archive_b_id: int
    relation: DuplicateRelation
    confidence: float
    matched_pages: int
    left_pages: int
    right_pages: int
    recommendation: str
    reasons: tuple[str, ...]
    sequence_relation: SequenceRelation | None = None
    container_archive_id: int | None = None
    matched_pairs: tuple[tuple[int, int], ...] = ()
    left_coverage: float = 0.0
    right_coverage: float = 0.0
    edition_flags: tuple[EditionFlag, ...] = ()
    edition_summary: str | None = None
    preserve_required: bool = False


@dataclass(frozen=True, slots=True)
class CandidateGroupMember:
    archive_id: int
    path: Path
    file_size: int
    mtime_ns: int
    archive_format: ArchiveFormat
    review_action: ReviewAction | None
    needs_review: bool
    image_count: int | None = None
    representative_width: int | None = None
    representative_height: int | None = None
    quarantine_item_id: int | None = None
    quarantine_status: str | None = None
    quarantine_path: Path | None = None
    deletion_state: str | None = None
    filename_language: FilenameSignal | None = None
    filename_color: FilenameSignal | None = None
    filename_mosaic: FilenameSignal | None = None
    precision_language: str | None = None
    precision_language_confidence: float | None = None
    color_page_ratio: float | None = None
    review_recommendation_reason: str | None = None


@dataclass(frozen=True, slots=True)
class CandidateGroupSummary:
    group_key: str
    member_count: int
    strongest_relation: DuplicateRelation
    confidence: float
    analyzer_version: int
    needs_review: bool


@dataclass(frozen=True, slots=True)
class CandidateGroupDetail:
    group_key: str
    members: tuple[CandidateGroupMember, ...]
    relations: tuple[CandidateRelationRecord, ...]
    strongest_relation: DuplicateRelation
    confidence: float
    analyzer_version: int
    needs_review: bool
    recommended_archive_id: int | None


@dataclass(frozen=True, slots=True)
class ReviewGroupDetail:
    """One derived edition set, kept separate from its source graph group."""

    set_key: str
    source_group_key: str
    edition_kind: EditionKind
    members: tuple[CandidateGroupMember, ...]
    relations: tuple[CandidateRelationRecord, ...]
    recommendation_status: str
    recommendations: tuple["RecommendationRecord", ...] = ()
    precision_relations: tuple["PrecisionRelationRecord", ...] = ()


@dataclass(frozen=True, slots=True)
class ReviewState:
    action: ReviewAction | None
    needs_review: bool
    action_id: int | None


@dataclass(frozen=True, slots=True)
class SequenceAnalysisCandidate:
    root_id: int
    analyzer_version: int
    left: ArchiveAnalysisInput
    right: ArchiveAnalysisInput
    left_fingerprints: ArchiveFingerprintSet
    right_fingerprints: ArchiveFingerprintSet


@dataclass(frozen=True, slots=True)
class EditionProfileInput:
    value: ArchiveAnalysisInput
    language_hints: frozenset[str]


@dataclass(frozen=True, slots=True)
class EditionRelationCandidate:
    root_id: int
    archive_a_id: int
    archive_b_id: int
    left_file_size: int
    left_mtime_ns: int
    right_file_size: int
    right_mtime_ns: int
    left_profile: EditionProfile
    right_profile: EditionProfile
    evidence: EditionEvidence


@dataclass(frozen=True, slots=True)
class ReviewCandidateSet:
    set_key: str
    source_group_key: str
    edition_kind: str
    archive_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class PrecisionScope:
    set_keys: tuple[str, ...]
    archive_ids: tuple[int, ...]
    relation_pairs: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class PrecisionPageRecord:
    pixel_sha256: str
    algorithm_version: int
    state: str
    language_evidence: PageLanguageEvidence
    ocr_confidence: float
    metrics: PageQualityMetrics | None
    error_code: str | None


@dataclass(frozen=True, slots=True)
class PrecisionProfileRecord:
    archive_id: int
    file_size: int
    mtime_ns: int
    algorithm_version: int
    state: str
    sample_count: int
    language: str
    language_confidence: float
    character_counts: Mapping[str, int]
    page_metrics: tuple[Mapping[str, object], ...]
    error_code: str | None


@dataclass(frozen=True, slots=True)
class PrecisionRelationInput:
    left: ArchiveAnalysisInput
    right: ArchiveAnalysisInput
    relation: DuplicateRelation
    matched_pairs: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class PrecisionRelationRecord:
    archive_a_id: int
    archive_b_id: int
    mosaic_direction: str
    mosaic_confidence: float
    quality_direction: str
    quality_confidence: float
    evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RecommendationRecord:
    item_id: int
    set_key: str
    source_group_key: str
    archive_id: int
    recommendation: str
    status: str
    criteria: Mapping[str, str]
    reason: str
    file_size: int
    mtime_ns: int


@dataclass(frozen=True, slots=True)
class RecommendationRunClaim:
    run_id: int
    created: bool


@dataclass(frozen=True, slots=True)
class RecommendationSourceMember:
    archive_id: int
    path: Path
    file_size: int
    mtime_ns: int
    page_count: int | None
    resolution_area: int | None
    color_page_ratio: float | None
    language: str
    path_key: str = ""
    language_confidence: float = 0.0
    filename_language: FilenameSignal | None = None
    filename_color: FilenameSignal | None = None
    filename_mosaic: FilenameSignal | None = None
    filename_title_rank: int | None = None
    language_analyzed: bool = False


@dataclass(frozen=True, slots=True)
class RecommendationSourceRelation:
    archive_a_id: int
    archive_b_id: int
    relation: DuplicateRelation
    matched_pages: int
    confidence: float


@dataclass(frozen=True, slots=True)
class RecommendationSourceGroup:
    group_key: str
    analyzer_version: int
    members: tuple[RecommendationSourceMember, ...]
    precision_relations: tuple[PrecisionRelationRecord, ...]
    relations: tuple[RecommendationSourceRelation, ...] = ()


@dataclass(frozen=True, slots=True)
class QuarantineCandidate:
    root_id: int
    root_path: Path
    group_key: str
    archive_id: int
    path: Path
    file_size: int
    mtime_ns: int
    archive_format: ArchiveFormat


@dataclass(frozen=True, slots=True)
class QuarantineItem:
    id: int
    root_id: int
    archive_id: int
    group_key: str
    source_path: Path
    destination_path: Path
    file_size: int
    mtime_ns: int
    sha256: str | None
    status: str
    error_code: str | None


@dataclass(frozen=True, slots=True)
class DeletionItem:
    id: int
    quarantine_item_id: int
    root_id: int
    archive_id: int
    path: Path
    file_size: int
    mtime_ns: int
    sha256: str
    state: str
    error_code: str | None


class QuarantineEligibilityError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DuplicateRepository(Repository):
    def backfill_filename_evidence(
        self, root_id: int, *, algorithm_version: int = 2
    ) -> int:
        """Persist evidence derived solely from archive path strings."""

        rows = self._connection.execute(
            "SELECT a.id, a.path, a.path_key, a.file_size, a.mtime_ns FROM archives a "
            "WHERE a.scan_root_id = ? AND NOT EXISTS (SELECT 1 FROM filename_evidence e "
            "WHERE e.archive_id=a.id AND e.file_size=a.file_size AND e.mtime_ns=a.mtime_ns "
            "AND e.path_key=a.path_key AND e.algorithm_version=?)",
            (root_id, algorithm_version),
        ).fetchall()
        changed = 0
        computed_at = datetime.now(UTC).isoformat()
        with self._connection:
            for row in rows:
                evidence = normalize_filename_evidence(Path(str(row[1])))
                cursor = self._connection.execute(
                    "INSERT INTO filename_evidence(archive_id, file_size, mtime_ns, path_key, "
                    "algorithm_version, tokens_json, language_json, color_json, mosaic_json, "
                    "title_rank, computed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(archive_id, file_size, mtime_ns, path_key, algorithm_version) "
                    "DO UPDATE SET tokens_json = excluded.tokens_json, "
                    "language_json = excluded.language_json, color_json = excluded.color_json, "
                    "mosaic_json = excluded.mosaic_json, title_rank = excluded.title_rank, "
                    "computed_at = excluded.computed_at "
                    "WHERE filename_evidence.tokens_json != excluded.tokens_json "
                    "OR filename_evidence.language_json != excluded.language_json "
                    "OR filename_evidence.color_json != excluded.color_json "
                    "OR filename_evidence.mosaic_json != excluded.mosaic_json "
                    "OR filename_evidence.title_rank != excluded.title_rank",
                    (
                        int(row[0]),
                        int(row[3]),
                        int(row[4]),
                        str(row[2]),
                        algorithm_version,
                        _stable_json(evidence.tokens),
                        _filename_signal_json(evidence.language),
                        _filename_signal_json(evidence.color),
                        _filename_signal_json(evidence.mosaic),
                        evidence.title_rank,
                        computed_at,
                    ),
                )
                changed += cursor.rowcount
        return changed

    def filename_evidence_for_archives(
        self, archive_ids: tuple[int, ...], *, algorithm_version: int = 2
    ) -> dict[int, FilenameEvidence]:
        """Load evidence matching each archive's current DB snapshot."""

        values: dict[int, FilenameEvidence] = {}
        for start in range(0, len(archive_ids), _ARCHIVE_VALIDATION_CHUNK_SIZE):
            ids = archive_ids[start : start + _ARCHIVE_VALIDATION_CHUNK_SIZE]
            if not ids:
                continue
            placeholders = ", ".join("?" for _ in ids)
            rows = self._connection.execute(
                "SELECT evidence.archive_id, evidence.tokens_json, evidence.language_json, "
                "evidence.color_json, evidence.mosaic_json, evidence.title_rank "
                "FROM filename_evidence AS evidence JOIN archives AS archives "
                "ON archives.id = evidence.archive_id AND archives.file_size = evidence.file_size "
                "AND archives.mtime_ns = evidence.mtime_ns AND archives.path_key = evidence.path_key "
                f"WHERE evidence.algorithm_version = ? AND evidence.archive_id IN ({placeholders})",
                (algorithm_version, *ids),
            ).fetchall()
            for row in rows:
                language = _filename_signal_from_json(str(row[2]))
                values[int(row[0])] = FilenameEvidence(
                    tokens=frozenset(json.loads(str(row[1]))),
                    language_hints=language_hints_for_signal(language),
                    language=language,
                    color=_filename_signal_from_json(str(row[3])),
                    mosaic=_filename_signal_from_json(str(row[4])),
                    title_rank=int(row[5]),
                )
        return values

    def root_id_for_path_key(self, path_key: str) -> int | None:
        row = self._connection.execute(
            "SELECT id FROM scan_roots WHERE path_key = ?", (path_key,)
        ).fetchone()
        return None if row is None else int(row[0])

    def analysis_input_counts(self, root_id: int) -> tuple[int, int]:
        row = self._connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(COALESCE(image_count, 0)), 0) "
            "FROM archives WHERE scan_root_id = ? AND state = 'INDEXED'",
            (root_id,),
        ).fetchone()
        assert row is not None
        return int(row[0]), int(row[1])

    def iter_analysis_input_batches(
        self,
        root_id: int,
        *,
        batch_size: int = _ANALYSIS_INPUT_BATCH_SIZE,
        archive_ids: tuple[int, ...] | None = None,
        include_images: bool = True,
        checkpoint: Callable[[], None] | None = None,
    ) -> Iterator[tuple[ArchiveAnalysisInput, ...]]:
        """Yield indexed inputs with bounded rows and no per-archive entry query."""

        if batch_size <= 0 or batch_size > _ARCHIVE_VALIDATION_CHUNK_SIZE:
            raise ValueError(
                f"batch_size must be between 1 and {_ARCHIVE_VALIDATION_CHUNK_SIZE}"
            )
        if archive_ids is None:
            last_archive_id = 0
            while True:
                _run_checkpoint(checkpoint)
                rows = self._connection.execute(
                    "SELECT id, path, file_size, mtime_ns, archive_format "
                    "FROM archives WHERE scan_root_id = ? AND state = 'INDEXED' "
                    "AND id > ? ORDER BY id LIMIT ?",
                    (root_id, last_archive_id, batch_size),
                ).fetchall()
                _run_checkpoint(checkpoint)
                if not rows:
                    return
                yield self._analysis_input_batch(rows, include_images, checkpoint)
                last_archive_id = int(rows[-1][0])
            return

        normalized_ids = tuple(sorted({int(value) for value in archive_ids if value > 0}))
        for offset in range(0, len(normalized_ids), batch_size):
            _run_checkpoint(checkpoint)
            selected_ids = normalized_ids[offset : offset + batch_size]
            placeholders = ",".join("?" for _ in selected_ids)
            rows = self._connection.execute(
                "SELECT id, path, file_size, mtime_ns, archive_format FROM archives "
                f"WHERE scan_root_id = ? AND state = 'INDEXED' AND id IN ({placeholders}) "
                "ORDER BY id",
                (root_id, *selected_ids),
            ).fetchall()
            _run_checkpoint(checkpoint)
            if rows:
                yield self._analysis_input_batch(rows, include_images, checkpoint)

    def _analysis_input_batch(
        self,
        rows: list[tuple],
        include_images: bool,
        checkpoint: Callable[[], None] | None,
    ) -> tuple[ArchiveAnalysisInput, ...]:
        images_by_archive: dict[int, list[ImageEntryRef]] = {
            int(row[0]): [] for row in rows
        }
        if include_images:
            archive_ids = tuple(images_by_archive)
            placeholders = ",".join("?" for _ in archive_ids)
            image_rows = self._connection.execute(
                "SELECT archive_id, position, path, uncompressed_size, crc "
                "FROM archive_entries WHERE archive_id IN ("
                f"{placeholders}) AND entry_kind = 'IMAGE' ORDER BY archive_id, position",
                archive_ids,
            )
            for index, (archive_id, position, entry_path, size, crc) in enumerate(
                image_rows, start=1
            ):
                images_by_archive[int(archive_id)].append(
                    ImageEntryRef(
                        position=int(position),
                        path=str(entry_path),
                        uncompressed_size=None if size is None else int(size),
                        crc=None if crc is None else str(crc),
                    )
                )
                if index % _ANALYSIS_INPUT_BATCH_SIZE == 0:
                    _run_checkpoint(checkpoint)
            _run_checkpoint(checkpoint)
        return tuple(
            ArchiveAnalysisInput(
                archive_id=int(archive_id),
                path=Path(str(path)),
                file_size=int(file_size),
                mtime_ns=int(mtime_ns),
                archive_format=ArchiveFormat(str(archive_format)),
                images=tuple(images_by_archive[int(archive_id)]),
            )
            for archive_id, path, file_size, mtime_ns, archive_format in rows
        )

    def analysis_inputs(self, root_id: int) -> tuple[ArchiveAnalysisInput, ...]:
        return tuple(
            value
            for batch in self.iter_analysis_input_batches(root_id)
            for value in batch
        )

    def latest_duplicate_progress(self) -> DuplicateProgress | None:
        row = self._connection.execute(
            "SELECT stage, archive_total, archive_processed, image_total, image_processed, "
            "failed_count, candidate_count FROM duplicate_analysis_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        return DuplicateProgress(
            stage=AnalysisStage(str(row[0])),
            archive_total=int(row[1]),
            archive_processed=int(row[2]),
            image_total=int(row[3]),
            image_processed=int(row[4]),
            failed_count=int(row[5]),
            candidate_count=int(row[6]),
        )

    def latest_duplicate_run_status(self) -> str | None:
        row = self._connection.execute(
            "SELECT status FROM duplicate_analysis_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return None if row is None else str(row[0])

    def has_completed_duplicate_run(self, root_id: int) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM duplicate_analysis_runs "
            "WHERE scan_root_id = ? AND status = 'COMPLETED' LIMIT 1",
            (root_id,),
        ).fetchone()
        return row is not None

    def preview_image_entry(
        self, archive_id: int, *, image_index: int = 0
    ) -> tuple[ImageEntryRef, int] | None:
        if image_index < 0:
            raise ValueError("Preview image index must not be negative.")
        row = self._connection.execute(
            "SELECT entry.position, entry.path, entry.uncompressed_size, entry.crc, "
            "(SELECT COUNT(*) FROM archive_entries AS duplicate_entry "
            "WHERE duplicate_entry.archive_id = entry.archive_id "
            "AND duplicate_entry.path = entry.path) "
            "FROM archive_entries AS entry "
            "WHERE entry.archive_id = ? AND entry.entry_kind = 'IMAGE' "
            "ORDER BY entry.position LIMIT 1 OFFSET ?",
            (archive_id, image_index),
        ).fetchone()
        if row is None:
            return None
        position, entry_path, uncompressed_size, crc, same_path_count = row
        return (
            ImageEntryRef(
                position=int(position),
                path=str(entry_path),
                uncompressed_size=(
                    None if uncompressed_size is None else int(uncompressed_size)
                ),
                crc=None if crc is None else str(crc),
            ),
            int(same_path_count),
        )

    def sequence_analysis_candidates(
        self, root_id: int, *, algorithm_version: int,
        relation_pairs: tuple[tuple[int, int], ...] | None = None,
    ) -> tuple[SequenceAnalysisCandidate, ...]:
        version_row = self._connection.execute(
            "SELECT MAX(analyzer_version) FROM candidate_relations WHERE scan_root_id = ?",
            (root_id,),
        ).fetchone()
        if version_row is None or version_row[0] is None:
            return ()
        analyzer_version = int(version_row[0])
        rows = self._connection.execute(
            "SELECT relation.archive_a_id, relation.archive_b_id, "
            "left_archive.path, left_archive.file_size, left_archive.mtime_ns, "
            "left_archive.archive_format, left_archive.image_count, "
            "right_archive.path, right_archive.file_size, right_archive.mtime_ns, "
            "right_archive.archive_format, right_archive.image_count, "
            "cached.left_file_size, cached.left_mtime_ns, "
            "cached.right_file_size, cached.right_mtime_ns "
            "FROM candidate_relations AS relation "
            "JOIN archives AS left_archive ON left_archive.id = relation.archive_a_id "
            "JOIN archives AS right_archive ON right_archive.id = relation.archive_b_id "
            "LEFT JOIN sequence_relations AS cached "
            "ON cached.archive_a_id = relation.archive_a_id "
            "AND cached.archive_b_id = relation.archive_b_id "
            "AND cached.algorithm_version = ? "
            "WHERE relation.scan_root_id = ? AND relation.analyzer_version = ? "
            "AND (relation.relation != 'RELATED' "
            "OR (relation.matched_pages >= 2 AND relation.confidence >= 0.5)) "
            "ORDER BY relation.archive_a_id, relation.archive_b_id",
            (algorithm_version, root_id, analyzer_version),
        ).fetchall()
        fingerprint_cache: dict[int, ArchiveFingerprintSet | None] = {}
        input_cache: dict[int, ArchiveAnalysisInput | None] = {}

        def load_archive(
            archive_id: int,
            path: str,
            file_size: int,
            mtime_ns: int,
            archive_format: str,
            image_count: int | None,
        ) -> tuple[ArchiveAnalysisInput, ArchiveFingerprintSet] | None:
            if archive_id not in input_cache:
                value = ArchiveAnalysisInput(
                    archive_id=archive_id,
                    path=Path(path),
                    file_size=file_size,
                    mtime_ns=mtime_ns,
                    archive_format=ArchiveFormat(archive_format),
                    images=(),
                )
                input_cache[archive_id] = value if _snapshot_matches(value) else None
            value = input_cache[archive_id]
            if value is None or image_count is None or image_count <= 0:
                return None
            if archive_id not in fingerprint_cache:
                fingerprint_rows = self._connection.execute(
                    "SELECT image.byte_sha256, image.pixel_sha256, image.dhash64, "
                    "image.ahash64, image.width, image.height, archive.sha256 "
                    "FROM image_fingerprints AS image "
                    "JOIN archive_fingerprints AS archive ON archive.archive_id = image.archive_id "
                    "AND archive.analyzer_version = image.analyzer_version "
                    "WHERE image.archive_id = ? AND image.analyzer_version = ? "
                    "AND image.coverage = 'FULL' AND image.state = 'SUCCEEDED' "
                    "ORDER BY image.entry_position",
                    (archive_id, analyzer_version),
                ).fetchall()
                if len(fingerprint_rows) != image_count:
                    fingerprint_cache[archive_id] = None
                else:
                    fingerprint_cache[archive_id] = ArchiveFingerprintSet(
                        archive_id=archive_id,
                        file_sha256=(
                            None
                            if not fingerprint_rows or fingerprint_rows[0][6] is None
                            else str(fingerprint_rows[0][6])
                        ),
                        pages=tuple(
                            ImageFingerprint(
                                byte_sha256=str(row[0]),
                                pixel_sha256=str(row[1]),
                                dhash64=str(row[2]),
                                ahash64=str(row[3]),
                                width=int(row[4]),
                                height=int(row[5]),
                            )
                            for row in fingerprint_rows
                        ),
                    )
            fingerprints = fingerprint_cache[archive_id]
            return None if fingerprints is None else (value, fingerprints)

        wanted_pairs = None if relation_pairs is None else set(relation_pairs)
        candidates: list[SequenceAnalysisCandidate] = []
        for row in rows:
            if wanted_pairs is not None and (int(row[0]), int(row[1])) not in wanted_pairs:
                continue
            (
                left_id,
                right_id,
                left_path,
                left_size,
                left_mtime,
                left_format,
                left_count,
                right_path,
                right_size,
                right_mtime,
                right_format,
                right_count,
                cached_left_size,
                cached_left_mtime,
                cached_right_size,
                cached_right_mtime,
            ) = row
            if (
                cached_left_size is not None
                and (int(cached_left_size), int(cached_left_mtime))
                == (int(left_size), int(left_mtime))
                and (int(cached_right_size), int(cached_right_mtime))
                == (int(right_size), int(right_mtime))
            ):
                continue
            left_value = load_archive(
                int(left_id),
                str(left_path),
                int(left_size),
                int(left_mtime),
                str(left_format),
                None if left_count is None else int(left_count),
            )
            right_value = load_archive(
                int(right_id),
                str(right_path),
                int(right_size),
                int(right_mtime),
                str(right_format),
                None if right_count is None else int(right_count),
            )
            if left_value is None or right_value is None:
                continue
            candidates.append(
                SequenceAnalysisCandidate(
                    root_id=root_id,
                    analyzer_version=analyzer_version,
                    left=left_value[0],
                    right=right_value[0],
                    left_fingerprints=left_value[1],
                    right_fingerprints=right_value[1],
                )
            )
        return tuple(candidates)

    def store_sequence_result(
        self,
        candidate: SequenceAnalysisCandidate,
        match: SequenceMatch | None,
        *,
        algorithm_version: int,
        computed_at: datetime,
    ) -> bool:
        pair = (candidate.left.archive_id, candidate.right.archive_id)
        if pair[0] >= pair[1]:
            raise ValueError("Sequence candidates must use ascending archive ids.")
        if match is not None and (match.archive_a_id, match.archive_b_id) != pair:
            raise ValueError("Sequence match endpoints changed.")
        if not (_snapshot_matches(candidate.left) and _snapshot_matches(candidate.right)):
            return False
        relation = "NONE" if match is None else match.relation.value
        matched_pairs = () if match is None else match.matched_pairs
        with _immediate_transaction(self._connection):
            rows = self._connection.execute(
                "SELECT id, file_size, mtime_ns FROM archives "
                "WHERE scan_root_id = ? AND id IN (?, ?) ORDER BY id",
                (candidate.root_id, pair[0], pair[1]),
            ).fetchall()
            expected = (
                (pair[0], candidate.left.file_size, candidate.left.mtime_ns),
                (pair[1], candidate.right.file_size, candidate.right.mtime_ns),
            )
            if tuple((int(row[0]), int(row[1]), int(row[2])) for row in rows) != expected:
                return False
            self._connection.execute(
                "INSERT INTO sequence_relations("
                "scan_root_id, archive_a_id, archive_b_id, relation, container_archive_id, "
                "matched_pages, left_pages, right_pages, left_coverage, right_coverage, "
                "matched_pairs_json, left_file_size, left_mtime_ns, right_file_size, "
                "right_mtime_ns, algorithm_version, computed_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(archive_a_id, archive_b_id, algorithm_version) DO UPDATE SET "
                "relation = excluded.relation, container_archive_id = excluded.container_archive_id, "
                "matched_pages = excluded.matched_pages, left_pages = excluded.left_pages, "
                "right_pages = excluded.right_pages, left_coverage = excluded.left_coverage, "
                "right_coverage = excluded.right_coverage, matched_pairs_json = excluded.matched_pairs_json, "
                "left_file_size = excluded.left_file_size, left_mtime_ns = excluded.left_mtime_ns, "
                "right_file_size = excluded.right_file_size, right_mtime_ns = excluded.right_mtime_ns, "
                "computed_at = excluded.computed_at",
                (
                    candidate.root_id,
                    pair[0],
                    pair[1],
                    relation,
                    None if match is None else match.container_archive_id,
                    len(matched_pairs),
                    len(candidate.left_fingerprints.pages),
                    len(candidate.right_fingerprints.pages),
                    0.0 if match is None else match.left_coverage,
                    0.0 if match is None else match.right_coverage,
                    _stable_json_pairs(matched_pairs),
                    candidate.left.file_size,
                    candidate.left.mtime_ns,
                    candidate.right.file_size,
                    candidate.right.mtime_ns,
                    algorithm_version,
                    computed_at.isoformat(),
                ),
            )
        return _snapshot_matches(candidate.left) and _snapshot_matches(candidate.right)

    def store_edition_profile(
        self,
        source: EditionProfileInput,
        profile: EditionProfile | None,
        *,
        algorithm_version: int,
        computed_at: datetime,
        error_code: str | None = None,
    ) -> bool:
        value = source.value
        if profile is not None and profile.archive_id != value.archive_id:
            raise ValueError("Edition profile archive changed.")
        if not _snapshot_matches(value):
            return False
        with _immediate_transaction(self._connection):
            row = self._connection.execute(
                "SELECT file_size, mtime_ns FROM archives WHERE id = ?",
                (value.archive_id,),
            ).fetchone()
            if row is None or (int(row[0]), int(row[1])) != (
                value.file_size,
                value.mtime_ns,
            ):
                return False
            self._connection.execute(
                "INSERT INTO edition_profiles("
                "archive_id, file_size, mtime_ns, sample_count, color_page_ratio, "
                "median_color_score, language_hints_json, state, algorithm_version, "
                "computed_at, error_code"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(archive_id) DO UPDATE SET "
                "file_size = excluded.file_size, mtime_ns = excluded.mtime_ns, "
                "sample_count = excluded.sample_count, color_page_ratio = excluded.color_page_ratio, "
                "median_color_score = excluded.median_color_score, "
                "language_hints_json = excluded.language_hints_json, state = excluded.state, "
                "algorithm_version = excluded.algorithm_version, computed_at = excluded.computed_at, "
                "error_code = excluded.error_code",
                (
                    value.archive_id,
                    value.file_size,
                    value.mtime_ns,
                    0 if profile is None else profile.sample_count,
                    None if profile is None else profile.color_page_ratio,
                    None if profile is None else profile.median_color_score,
                    _stable_json(source.language_hints),
                    "FAILED" if profile is None else "SUCCEEDED",
                    algorithm_version,
                    computed_at.isoformat(),
                    error_code,
                ),
            )
        return _snapshot_matches(value)

    def edition_profile_inputs(
        self, root_id: int, *, algorithm_version: int,
        archive_ids: tuple[int, ...] | None = None,
    ) -> tuple[EditionProfileInput, ...]:
        rows = self._connection.execute(
            "SELECT DISTINCT archive.id, archive.path, archive.file_size, archive.mtime_ns, "
            "archive.archive_format, fingerprint.language_hints_json, groups.analyzer_version, "
            "profile.file_size, profile.mtime_ns, profile.algorithm_version "
            "FROM candidate_groups AS groups "
            "JOIN candidate_group_members AS member ON member.group_id = groups.id "
            "JOIN archives AS archive ON archive.id = member.archive_id "
            "LEFT JOIN archive_fingerprints AS fingerprint "
            "ON fingerprint.archive_id = archive.id "
            "AND fingerprint.analyzer_version = groups.analyzer_version "
            "LEFT JOIN edition_profiles AS profile ON profile.archive_id = archive.id "
            "WHERE groups.scan_root_id = ? ORDER BY archive.id",
            (root_id,),
        ).fetchall()
        wanted_ids = None if archive_ids is None else set(archive_ids)
        values: list[EditionProfileInput] = []
        for (
            archive_id,
            path,
            file_size,
            mtime_ns,
            archive_format,
            language_hints_json,
            _analyzer_version,
            profile_size,
            profile_mtime,
            profile_version,
        ) in rows:
            if wanted_ids is not None and int(archive_id) not in wanted_ids:
                continue
            if (
                profile_version is not None
                and int(profile_version) == algorithm_version
                and (int(profile_size), int(profile_mtime))
                == (int(file_size), int(mtime_ns))
            ):
                continue
            image_rows = self._connection.execute(
                "SELECT position, path, uncompressed_size, crc "
                "FROM archive_entries WHERE archive_id = ? AND entry_kind = 'IMAGE' "
                "ORDER BY position",
                (archive_id,),
            ).fetchall()
            value = ArchiveAnalysisInput(
                archive_id=int(archive_id),
                path=Path(str(path)),
                file_size=int(file_size),
                mtime_ns=int(mtime_ns),
                archive_format=ArchiveFormat(str(archive_format)),
                images=tuple(
                    ImageEntryRef(
                        position=int(position),
                        path=str(entry_path),
                        uncompressed_size=(
                            None if uncompressed_size is None else int(uncompressed_size)
                        ),
                        crc=None if crc is None else str(crc),
                    )
                    for position, entry_path, uncompressed_size, crc in image_rows
                ),
            )
            if not value.images or not _snapshot_matches(value):
                continue
            hints = (
                frozenset()
                if language_hints_json is None
                else (_json_string_set(str(language_hints_json)) or frozenset())
            )
            values.append(EditionProfileInput(value, hints))
        return tuple(values)

    def edition_relation_candidates(
        self, root_id: int, *, algorithm_version: int,
        relation_pairs: tuple[tuple[int, int], ...] | None = None,
    ) -> tuple[EditionRelationCandidate, ...]:
        version_row = self._connection.execute(
            "SELECT MAX(analyzer_version) FROM candidate_relations WHERE scan_root_id = ?",
            (root_id,),
        ).fetchone()
        if version_row is None or version_row[0] is None:
            return ()
        analyzer_version = int(version_row[0])
        rows = self._connection.execute(
            "SELECT relation.archive_a_id, relation.archive_b_id, relation.relation, "
            "relation.matched_pages, relation.left_pages, relation.right_pages, "
            "relation.recommendation, relation.evidence_json, "
            "left_archive.file_size, left_archive.mtime_ns, right_archive.file_size, "
            "right_archive.mtime_ns, left_profile.sample_count, left_profile.color_page_ratio, "
            "left_profile.median_color_score, left_profile.language_hints_json, "
            "right_profile.sample_count, right_profile.color_page_ratio, "
            "right_profile.median_color_score, right_profile.language_hints_json, "
            "cached.left_file_size, cached.left_mtime_ns, cached.right_file_size, cached.right_mtime_ns "
            "FROM candidate_relations AS relation "
            "JOIN archives AS left_archive ON left_archive.id = relation.archive_a_id "
            "JOIN archives AS right_archive ON right_archive.id = relation.archive_b_id "
            "JOIN edition_profiles AS left_profile ON left_profile.archive_id = relation.archive_a_id "
            "AND left_profile.state = 'SUCCEEDED' AND left_profile.algorithm_version = ? "
            "AND left_profile.file_size = left_archive.file_size AND left_profile.mtime_ns = left_archive.mtime_ns "
            "JOIN edition_profiles AS right_profile ON right_profile.archive_id = relation.archive_b_id "
            "AND right_profile.state = 'SUCCEEDED' AND right_profile.algorithm_version = ? "
            "AND right_profile.file_size = right_archive.file_size AND right_profile.mtime_ns = right_archive.mtime_ns "
            "LEFT JOIN edition_relations AS cached ON cached.archive_a_id = relation.archive_a_id "
            "AND cached.archive_b_id = relation.archive_b_id AND cached.algorithm_version = ? "
            "WHERE relation.scan_root_id = ? AND relation.analyzer_version = ? "
            "AND (relation.relation != 'RELATED' "
            "OR (relation.matched_pages >= 2 AND relation.confidence >= 0.5)) "
            "ORDER BY relation.archive_a_id, relation.archive_b_id",
            (
                algorithm_version,
                algorithm_version,
                algorithm_version,
                root_id,
                analyzer_version,
            ),
        ).fetchall()
        wanted_pairs = None if relation_pairs is None else set(relation_pairs)
        values: list[EditionRelationCandidate] = []
        for row in rows:
            if wanted_pairs is not None and (int(row[0]), int(row[1])) not in wanted_pairs:
                continue
            (
                left_id, right_id, relation, matched_pages, left_pages, right_pages,
                recommendation, evidence_json, left_size, left_mtime, right_size,
                right_mtime, left_samples, left_color_ratio, left_color_score,
                left_hints, right_samples, right_color_ratio, right_color_score,
                right_hints, cached_left_size, cached_left_mtime, cached_right_size,
                cached_right_mtime,
            ) = row
            if (
                cached_left_size is not None
                and (int(cached_left_size), int(cached_left_mtime))
                == (int(left_size), int(left_mtime))
                and (int(cached_right_size), int(cached_right_mtime))
                == (int(right_size), int(right_mtime))
            ):
                continue
            values.append(
                EditionRelationCandidate(
                    root_id=root_id,
                    archive_a_id=int(left_id),
                    archive_b_id=int(right_id),
                    left_file_size=int(left_size),
                    left_mtime_ns=int(left_mtime),
                    right_file_size=int(right_size),
                    right_mtime_ns=int(right_mtime),
                    left_profile=EditionProfile(
                        int(left_id), int(left_samples), float(left_color_ratio),
                        float(left_color_score), _json_string_set(str(left_hints)) or frozenset()
                    ),
                    right_profile=EditionProfile(
                        int(right_id), int(right_samples), float(right_color_ratio),
                        float(right_color_score), _json_string_set(str(right_hints)) or frozenset()
                    ),
                    evidence=EditionEvidence(
                        DuplicateRelation(str(relation)), int(matched_pages), int(left_pages),
                        int(right_pages), _json_string_tuple(str(evidence_json)),
                        str(recommendation), int(left_size), int(right_size)
                    ),
                )
            )
        return tuple(values)

    def store_edition_relation(
        self,
        candidate: EditionRelationCandidate,
        comparison: EditionComparison,
        *,
        algorithm_version: int,
        computed_at: datetime,
    ) -> None:
        self._connection.execute(
            "INSERT INTO edition_relations("
            "scan_root_id, archive_a_id, archive_b_id, flags_json, summary, preserve_required, "
            "left_file_size, left_mtime_ns, right_file_size, right_mtime_ns, algorithm_version, computed_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(archive_a_id, archive_b_id, algorithm_version) DO UPDATE SET "
            "flags_json = excluded.flags_json, summary = excluded.summary, "
            "preserve_required = excluded.preserve_required, left_file_size = excluded.left_file_size, "
            "left_mtime_ns = excluded.left_mtime_ns, right_file_size = excluded.right_file_size, "
            "right_mtime_ns = excluded.right_mtime_ns, computed_at = excluded.computed_at",
            (
                candidate.root_id,
                candidate.archive_a_id,
                candidate.archive_b_id,
                _stable_json_strings(tuple(flag.value for flag in comparison.flags)),
                comparison.summary,
                int(comparison.preserve_required),
                candidate.left_file_size,
                candidate.left_mtime_ns,
                candidate.right_file_size,
                candidate.right_mtime_ns,
                algorithm_version,
                computed_at.isoformat(),
            ),
        )
        self._connection.commit()

    def precision_profile_inputs(
        self,
        root_id: int,
        *,
        algorithm_version: int,
        archive_ids: tuple[int, ...],
    ) -> tuple[ArchiveAnalysisInput, ...]:
        selected = tuple(sorted({int(value) for value in archive_ids if int(value) > 0}))
        if not selected:
            raise ValueError("Precision analysis requires a current candidate set.")
        found: set[int] = set()
        completed: set[int] = set()
        for offset in range(0, len(selected), _ARCHIVE_VALIDATION_CHUNK_SIZE):
            chunk = selected[offset : offset + _ARCHIVE_VALIDATION_CHUNK_SIZE]
            placeholders = ",".join("?" for _ in chunk)
            rows = self._connection.execute(
                "SELECT a.id, p.archive_id FROM archives AS a LEFT JOIN precision_profiles AS p "
                "ON p.archive_id = a.id AND p.file_size = a.file_size "
                "AND p.mtime_ns = a.mtime_ns AND p.algorithm_version = ? "
                f"WHERE a.scan_root_id = ? AND a.state = 'INDEXED' AND a.id IN ({placeholders})",
                (algorithm_version, root_id, *chunk),
            ).fetchall()
            found.update(int(row[0]) for row in rows)
            completed.update(int(row[0]) for row in rows if row[1] is not None)
        if found != set(selected):
            raise ValueError("Precision candidate set does not belong to this scan root.")
        pending = tuple(value for value in selected if value not in completed)
        return tuple(
            value
            for batch in self.iter_analysis_input_batches(root_id, archive_ids=pending)
            for value in batch
        )

    def completed_precision_archive_ids(
        self, root_id: int, *, algorithm_version: int
    ) -> tuple[int, ...]:
        rows = self._connection.execute(
            "SELECT a.id FROM archives AS a JOIN precision_profiles AS p ON p.archive_id = a.id "
            "AND p.file_size = a.file_size AND p.mtime_ns = a.mtime_ns "
            "AND p.algorithm_version = ? WHERE a.scan_root_id = ? AND a.state = 'INDEXED' "
            "ORDER BY a.id",
            (algorithm_version, root_id),
        ).fetchall()
        return tuple(int(row[0]) for row in rows)

    def precision_relation_inputs(
        self,
        root_id: int,
        *,
        algorithm_version: int,
        relation_pairs: tuple[tuple[int, int], ...],
        checkpoint: Callable[[], None] | None = None,
    ) -> tuple[PrecisionRelationInput, ...]:
        allowed_pairs = tuple(
            sorted(
                {
                    (min(int(left), int(right)), max(int(left), int(right)))
                    for left, right in relation_pairs
                    if int(left) > 0 and int(right) > 0 and int(left) != int(right)
                }
            )
        )
        if not allowed_pairs:
            raise ValueError("Precision analysis requires candidate set relation pairs.")
        version_row = self._connection.execute(
            "SELECT MAX(analyzer_version) FROM candidate_relations WHERE scan_root_id = ?",
            (root_id,),
        ).fetchone()
        if version_row is None or version_row[0] is None:
            return ()
        rows: list[tuple] = []
        for offset in range(0, len(allowed_pairs), 300):
            chunk = allowed_pairs[offset : offset + 300]
            requested = ",".join("(?, ?)" for _ in chunk)
            rows.extend(
                self._connection.execute(
                    "WITH requested(archive_a_id, archive_b_id) AS (VALUES "
                    f"{requested}) "
                    "SELECT relation.archive_a_id, relation.archive_b_id, relation.relation, "
                    "sequence.matched_pairs_json FROM requested "
                    "JOIN candidate_relations AS relation "
                    "ON relation.archive_a_id = requested.archive_a_id "
                    "AND relation.archive_b_id = requested.archive_b_id "
                    "JOIN archives AS left_archive ON left_archive.id = relation.archive_a_id "
                    "JOIN archives AS right_archive ON right_archive.id = relation.archive_b_id "
                    "JOIN precision_profiles AS left_profile ON left_profile.archive_id = left_archive.id "
                    "AND left_profile.file_size = left_archive.file_size "
                    "AND left_profile.mtime_ns = left_archive.mtime_ns "
                    "AND left_profile.algorithm_version = ? "
                    "JOIN precision_profiles AS right_profile ON right_profile.archive_id = right_archive.id "
                    "AND right_profile.file_size = right_archive.file_size "
                    "AND right_profile.mtime_ns = right_archive.mtime_ns "
                    "AND right_profile.algorithm_version = ? "
                    "LEFT JOIN sequence_relations AS sequence "
                    "ON sequence.archive_a_id = relation.archive_a_id "
                    "AND sequence.archive_b_id = relation.archive_b_id "
                    "AND sequence.left_file_size = left_archive.file_size "
                    "AND sequence.left_mtime_ns = left_archive.mtime_ns "
                    "AND sequence.right_file_size = right_archive.file_size "
                    "AND sequence.right_mtime_ns = right_archive.mtime_ns "
                    "AND sequence.algorithm_version = ("
                    "SELECT MAX(candidate_sequence.algorithm_version) "
                    "FROM sequence_relations AS candidate_sequence "
                    "WHERE candidate_sequence.archive_a_id = relation.archive_a_id "
                    "AND candidate_sequence.archive_b_id = relation.archive_b_id) "
                    "LEFT JOIN precision_relations AS cached "
                    "ON cached.archive_a_id = relation.archive_a_id "
                    "AND cached.archive_b_id = relation.archive_b_id "
                    "AND cached.left_file_size = left_archive.file_size "
                    "AND cached.left_mtime_ns = left_archive.mtime_ns "
                    "AND cached.right_file_size = right_archive.file_size "
                    "AND cached.right_mtime_ns = right_archive.mtime_ns "
                    "AND cached.algorithm_version = ? "
                    "WHERE relation.scan_root_id = ? AND relation.analyzer_version = ? "
                    "AND (relation.relation != 'RELATED' OR "
                    "(relation.matched_pages >= 2 AND relation.confidence >= 0.5)) "
                    "AND (cached.archive_a_id IS NULL OR "
                    "cached.evidence_json LIKE '%no aligned pages%')",
                    (
                        *(value for pair in chunk for value in pair),
                        algorithm_version,
                        algorithm_version,
                        algorithm_version,
                        root_id,
                        int(version_row[0]),
                    ),
                ).fetchall()
            )
        if not rows:
            return ()
        selected_ids = tuple(sorted({int(value) for row in rows for value in row[:2]}))
        inputs = {
            value.archive_id: value
            for batch in self.iter_analysis_input_batches(root_id, archive_ids=selected_ids)
            for value in batch
        }
        candidates: list[PrecisionRelationInput] = []
        fingerprints: dict[int, tuple[ImageFingerprint, ...]] = {}

        def page_fingerprints(source: ArchiveAnalysisInput) -> tuple[ImageFingerprint, ...]:
            if source.archive_id not in fingerprints:
                pages = self._connection.execute(
                    "SELECT image.byte_sha256, image.pixel_sha256, image.dhash64, "
                    "image.ahash64, image.width, image.height FROM image_fingerprints AS image "
                    "JOIN archive_fingerprints AS archive ON archive.archive_id = image.archive_id "
                    "AND archive.analyzer_version = image.analyzer_version "
                    "WHERE image.archive_id = ? AND image.analyzer_version = ? "
                    "AND archive.file_size = ? AND archive.mtime_ns = ? "
                    "AND image.coverage = 'FULL' AND image.state = 'SUCCEEDED' "
                    "ORDER BY image.entry_position",
                    (source.archive_id, int(version_row[0]), source.file_size, source.mtime_ns),
                ).fetchall()
                fingerprints[source.archive_id] = (
                    tuple(ImageFingerprint(str(a), str(b), str(c), str(d), int(w), int(h))
                          for a, b, c, d, w, h in pages)
                    if len(pages) == len(source.images) else ()
                )
            return fingerprints[source.archive_id]

        for archive_a_id, archive_b_id, relation, matched_pairs_json in sorted(rows):
            if checkpoint is not None:
                checkpoint()
            left = inputs.get(int(archive_a_id))
            right = inputs.get(int(archive_b_id))
            if left is None or right is None:
                continue
            matched_pairs = () if matched_pairs_json is None else _json_int_pairs(str(matched_pairs_json))
            if not matched_pairs and relation not in {"EXACT_ARCHIVE", "EXACT_CONTENT"}:
                from archive_analyzer.sequence_matching import align_page_pairs

                matched_pairs = align_page_pairs(
                    page_fingerprints(left), page_fingerprints(right), checkpoint=checkpoint
                )
            candidates.append(
                PrecisionRelationInput(
                    left=left,
                    right=right,
                    relation=DuplicateRelation(str(relation)),
                    matched_pairs=matched_pairs,
                )
            )
        return tuple(candidates)

    def precision_page_fingerprints(
        self, root_id: int, archive_ids: tuple[int, ...]
    ) -> dict[tuple[int, int], str]:
        selected = tuple(sorted({int(value) for value in archive_ids if int(value) > 0}))
        values: dict[tuple[int, int], str] = {}
        for offset in range(0, len(selected), _ARCHIVE_VALIDATION_CHUNK_SIZE):
            chunk = selected[offset : offset + _ARCHIVE_VALIDATION_CHUNK_SIZE]
            if not chunk:
                continue
            placeholders = ",".join("?" for _ in chunk)
            rows = self._connection.execute(
                "SELECT image.archive_id, image.entry_position, image.pixel_sha256 "
                "FROM image_fingerprints AS image "
                "JOIN archive_fingerprints AS archive_fp "
                "ON archive_fp.archive_id = image.archive_id "
                "AND archive_fp.analyzer_version = image.analyzer_version "
                "JOIN archives AS archive ON archive.id = image.archive_id "
                "WHERE archive.scan_root_id = ? "
                f"AND archive.id IN ({placeholders}) "
                "AND archive.state = 'INDEXED' "
                "AND archive_fp.file_size = archive.file_size "
                "AND archive_fp.mtime_ns = archive.mtime_ns "
                "AND image.coverage = 'FULL' AND image.state = 'SUCCEEDED' "
                "AND image.pixel_sha256 IS NOT NULL",
                (root_id, *chunk),
            ).fetchall()
            values.update(
                {
                    (int(archive_id), int(entry_position)): str(pixel_sha256)
                    for archive_id, entry_position, pixel_sha256 in rows
                }
            )
        return values

    def unresolved_precision_profiles(self, root_id: int, before_version: int):
        rows = self._connection.execute(
            "SELECT a.path,p.archive_id,p.file_size,p.mtime_ns,p.algorithm_version,p.state,"
            "p.sample_count,p.language,p.language_confidence,p.character_counts_json,p.page_metrics_json,p.error_code "
            "FROM precision_profiles p JOIN archives a ON a.id=p.archive_id "
            "WHERE a.scan_root_id=? AND p.file_size=a.file_size AND p.mtime_ns=a.mtime_ns "
            "AND p.language='UNKNOWN' AND p.state='SUCCEEDED' AND p.error_code IS NULL "
            "AND p.algorithm_version=(SELECT MAX(n.algorithm_version) FROM precision_profiles n "
            "WHERE n.archive_id=a.id AND n.file_size=a.file_size AND n.mtime_ns=a.mtime_ns) "
            "AND p.algorithm_version < ?", (root_id, before_version)).fetchall()
        return tuple((Path(path), PrecisionProfileRecord(aid,size,mtime,version,state,count,language,
            confidence,json.loads(counts),tuple(json.loads(metrics)),error))
            for path,aid,size,mtime,version,state,count,language,confidence,counts,metrics,error in rows)

    def cached_precision_pages(
        self, pixel_sha256_values: tuple[str, ...], algorithm_version: int
    ) -> dict[str, PrecisionPageRecord]:
        selected = tuple(sorted({str(value) for value in pixel_sha256_values if str(value)}))
        values: dict[str, PrecisionPageRecord] = {}
        for offset in range(0, len(selected), _ARCHIVE_VALIDATION_CHUNK_SIZE):
            chunk = selected[offset : offset + _ARCHIVE_VALIDATION_CHUNK_SIZE]
            if not chunk:
                continue
            placeholders = ",".join("?" for _ in chunk)
            rows = self._connection.execute(
                "SELECT pixel_sha256, state, language_evidence_json, ocr_confidence, "
                "metrics_json, error_code FROM precision_page_cache "
                f"WHERE algorithm_version = ? AND pixel_sha256 IN ({placeholders})",
                (algorithm_version, *chunk),
            ).fetchall()
            for pixel_sha256, state, language_json, confidence, metrics_json, error_code in rows:
                values[str(pixel_sha256)] = PrecisionPageRecord(
                    str(pixel_sha256),
                    algorithm_version,
                    str(state),
                    _page_language_evidence_from_json(str(language_json)),
                    float(confidence),
                    _page_quality_metrics_from_json(str(metrics_json)),
                    None if error_code is None else str(error_code),
                )
        return values

    def store_precision_page(
        self,
        record: PrecisionPageRecord,
        *,
        computed_at: datetime | None = None,
    ) -> bool:
        if not record.pixel_sha256 or record.algorithm_version <= 0:
            raise ValueError("Precision page cache requires a fingerprint and version.")
        if record.state not in {"SUCCEEDED", "FAILED"}:
            raise ValueError("Unknown precision page state.")
        if record.state == "SUCCEEDED" and record.metrics is None:
            raise ValueError("Successful precision page cache requires metrics.")
        timestamp = _derived_timestamp(computed_at, None)
        with _immediate_transaction(self._connection):
            existing = self._connection.execute(
                "SELECT state, language_evidence_json, error_code FROM precision_page_cache "
                "WHERE pixel_sha256 = ? AND algorithm_version = ?",
                (record.pixel_sha256, record.algorithm_version),
            ).fetchone()
            if existing is not None and str(existing[0]) == "SUCCEEDED":
                old = _page_language_evidence_from_json(str(existing[1]))
                old_valid = (
                    existing[2] is None and _recognizer_scope_rank(old.recognizer_scope) > 0
                )
                new_valid = (
                    record.error_code is None
                    and _recognizer_scope_rank(record.language_evidence.recognizer_scope) > 0
                )
                if (
                    record.state == "FAILED"
                    or (old_valid and not new_valid)
                    or (
                        old_valid == new_valid
                        and _recognizer_scope_rank(old.recognizer_scope)
                        > _recognizer_scope_rank(record.language_evidence.recognizer_scope)
                    )
                ):
                    return False
            self._connection.execute(
                "INSERT INTO precision_page_cache(pixel_sha256, algorithm_version, state, "
                "language_evidence_json, ocr_confidence, metrics_json, error_code, computed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(pixel_sha256, algorithm_version) DO UPDATE SET "
                "state = excluded.state, language_evidence_json = excluded.language_evidence_json, "
                "ocr_confidence = excluded.ocr_confidence, metrics_json = excluded.metrics_json, "
                "error_code = excluded.error_code, computed_at = excluded.computed_at",
                (
                    record.pixel_sha256,
                    record.algorithm_version,
                    record.state,
                    _page_language_evidence_json(record.language_evidence),
                    record.ocr_confidence,
                    _page_quality_metrics_json(record.metrics),
                    record.error_code,
                    timestamp.isoformat(),
                ),
            )
        return True

    def store_precision_profile(
        self,
        record: PrecisionProfileRecord,
        *,
        computed_at: datetime | None = None,
        owner_token: str | None = None,
        now: datetime | Callable[[], datetime] | None = None,
    ) -> bool:
        if record.state not in {"SUCCEEDED", "FAILED"}:
            raise ValueError("Unknown precision profile state.")
        if record.sample_count < 0:
            raise ValueError("Precision profile sample_count must not be negative.")
        if any(not isinstance(key, str) or not isinstance(value, int)
               for key, value in record.character_counts.items()):
            raise ValueError("Precision profile character counts must map strings to integers.")
        timestamp = _derived_timestamp(computed_at, now)
        with self._analysis_write_transaction(owner_token, now, immediate=True):
            row = self._connection.execute(
                "SELECT file_size, mtime_ns FROM archives WHERE id = ?",
                (record.archive_id,),
            ).fetchone()
            if row is None or (int(row[0]), int(row[1])) != (
                record.file_size,
                record.mtime_ns,
            ):
                return False
            self._connection.execute(
                "INSERT INTO precision_profiles("
                "archive_id, file_size, mtime_ns, algorithm_version, state, sample_count, "
                "language, language_confidence, character_counts_json, page_metrics_json, "
                "error_code, computed_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(archive_id, file_size, mtime_ns, algorithm_version) DO UPDATE SET "
                "state = excluded.state, sample_count = excluded.sample_count, "
                "language = excluded.language, language_confidence = excluded.language_confidence, "
                "character_counts_json = excluded.character_counts_json, "
                "page_metrics_json = excluded.page_metrics_json, error_code = excluded.error_code, "
                "computed_at = excluded.computed_at",
                (
                    record.archive_id,
                    record.file_size,
                    record.mtime_ns,
                    record.algorithm_version,
                    record.state,
                    record.sample_count,
                    record.language,
                    record.language_confidence,
                    _stable_json_mapping(record.character_counts),
                    _stable_json_page_metrics(record.page_metrics),
                    record.error_code,
                    timestamp.isoformat(),
                ),
            )
        return True

    def store_precision_relation(
        self,
        record: PrecisionRelationRecord,
        *,
        algorithm_version: int | None = None,
        computed_at: datetime | None = None,
        owner_token: str | None = None,
        now: datetime | Callable[[], datetime] | None = None,
    ) -> bool:
        if record.archive_a_id >= record.archive_b_id:
            raise ValueError("Precision relation archive IDs must be in ascending order.")
        timestamp = _derived_timestamp(computed_at, now)
        with self._analysis_write_transaction(owner_token, now, immediate=True):
            rows = self._connection.execute(
                "SELECT id, scan_root_id, file_size, mtime_ns FROM archives "
                "WHERE id IN (?, ?) ORDER BY id",
                (record.archive_a_id, record.archive_b_id),
            ).fetchall()
            if len(rows) != 2 or int(rows[0][1]) != int(rows[1][1]):
                return False
            selected_version = algorithm_version
            if selected_version is None:
                version_row = self._connection.execute(
                    "SELECT MAX(left_profile.algorithm_version) "
                    "FROM precision_profiles AS left_profile "
                    "JOIN precision_profiles AS right_profile "
                    "ON right_profile.algorithm_version = left_profile.algorithm_version "
                    "WHERE left_profile.archive_id = ? AND right_profile.archive_id = ? "
                    "AND left_profile.file_size = ? AND left_profile.mtime_ns = ? "
                    "AND right_profile.file_size = ? AND right_profile.mtime_ns = ?",
                    (
                        record.archive_a_id,
                        record.archive_b_id,
                        int(rows[0][2]),
                        int(rows[0][3]),
                        int(rows[1][2]),
                        int(rows[1][3]),
                    ),
                ).fetchone()
                if version_row is None or version_row[0] is None:
                    return False
                selected_version = int(version_row[0])
            self._connection.execute(
                "INSERT INTO precision_relations("
                "scan_root_id, archive_a_id, archive_b_id, left_file_size, left_mtime_ns, "
                "right_file_size, right_mtime_ns, algorithm_version, mosaic_direction, "
                "mosaic_confidence, quality_direction, quality_confidence, evidence_json, computed_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(archive_a_id, archive_b_id, left_file_size, left_mtime_ns, "
                "right_file_size, right_mtime_ns, algorithm_version) DO UPDATE SET "
                "mosaic_direction = excluded.mosaic_direction, "
                "mosaic_confidence = excluded.mosaic_confidence, "
                "quality_direction = excluded.quality_direction, "
                "quality_confidence = excluded.quality_confidence, evidence_json = excluded.evidence_json, "
                "computed_at = excluded.computed_at",
                (
                    int(rows[0][1]),
                    record.archive_a_id,
                    record.archive_b_id,
                    int(rows[0][2]),
                    int(rows[0][3]),
                    int(rows[1][2]),
                    int(rows[1][3]),
                    selected_version,
                    record.mosaic_direction,
                    record.mosaic_confidence,
                    record.quality_direction,
                    record.quality_confidence,
                    _stable_json_strings(record.evidence),
                    timestamp.isoformat(),
                ),
            )
        return True

    def replace_candidate_sets(
        self,
        source_group_key: str,
        sets: tuple[ReviewCandidateSet, ...],
        *,
        computed_at: datetime | None = None,
        owner_token: str | None = None,
        now: datetime | Callable[[], datetime] | None = None,
    ) -> tuple[ReviewCandidateSet, ...]:
        timestamp = _derived_timestamp(computed_at, now)
        with self._analysis_write_transaction(owner_token, now, immediate=True):
            group = self._connection.execute(
                "SELECT id, scan_root_id, analyzer_version FROM candidate_groups "
                "WHERE group_key = ?",
                (source_group_key,),
            ).fetchone()
            if group is None:
                raise ValueError("Unknown current candidate group.")
            group_id, root_id, algorithm_version = (int(value) for value in group)
            member_ids = {
                int(row[0])
                for row in self._connection.execute(
                    "SELECT archive_id FROM candidate_group_members WHERE group_id = ?",
                    (group_id,),
                )
            }
            stored_sets = []
            for candidate_set in sets:
                stored_key = self._store_candidate_set(
                    candidate_set,
                    source_group_key,
                    root_id,
                    algorithm_version,
                    member_ids,
                    timestamp,
                )
                stored_sets.append(replace(candidate_set, set_key=stored_key))
            sets = tuple(stored_sets)
            descriptor = tuple(
                (item.set_key, item.edition_kind, tuple(item.archive_ids))
                for item in sorted(sets, key=lambda value: value.set_key)
            )
            generation_key = sha256(
                _stable_json_mapping({"sets": descriptor, "version": 2}).encode("utf-8")
            ).hexdigest()
            self._connection.execute(
                "INSERT INTO edition_candidate_generations("
                "source_group_key, scan_root_id, generation_key, set_keys_json, computed_at"
                ") VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(source_group_key) DO UPDATE SET "
                "scan_root_id = excluded.scan_root_id, generation_key = excluded.generation_key, "
                "set_keys_json = excluded.set_keys_json, computed_at = excluded.computed_at",
                (
                    source_group_key,
                    root_id,
                    generation_key,
                    _stable_json_strings(tuple(item[0] for item in descriptor)),
                    timestamp.isoformat(),
                ),
            )
        return sets

    def recommendation_source_groups(
        self, root_id: int, affected_group_keys: tuple[str, ...] | None = None
    ) -> tuple[RecommendationSourceGroup, ...]:
        """Load current membership and saved evidence without opening archives."""
        keys = None if affected_group_keys is None else tuple(sorted(set(affected_group_keys)))
        if keys == ():
            return ()
        where = "WHERE groups.scan_root_id = ?"
        arguments: tuple[object, ...] = (root_id,)
        if keys is not None:
            placeholders = ",".join("?" for _ in keys)
            where += f" AND groups.group_key IN ({placeholders})"
            arguments += keys
        groups = self._connection.execute(
            "SELECT groups.id, groups.group_key, groups.analyzer_version FROM candidate_groups AS groups "
            + where + " ORDER BY groups.group_key",
            arguments,
        ).fetchall()
        values: list[RecommendationSourceGroup] = []
        for group_id, group_key, analyzer_version in groups:
            rows = self._connection.execute(
                "SELECT archive.id, archive.path, archive.file_size, archive.mtime_ns, "
                "archive.image_count, profile.color_page_ratio, precision.language, "
                "archive.path_key, precision.language_confidence, evidence.language_json, "
                "evidence.color_json, evidence.mosaic_json, evidence.title_rank "
                "FROM candidate_group_members AS member "
                "JOIN archives AS archive ON archive.id = member.archive_id "
                "LEFT JOIN edition_profiles AS profile ON profile.archive_id = archive.id "
                "AND profile.file_size = archive.file_size AND profile.mtime_ns = archive.mtime_ns "
                "AND profile.state = 'SUCCEEDED' AND profile.algorithm_version = ("
                "SELECT MAX(current_profile.algorithm_version) FROM edition_profiles AS current_profile "
                "WHERE current_profile.archive_id = archive.id AND current_profile.file_size = archive.file_size "
                "AND current_profile.mtime_ns = archive.mtime_ns AND current_profile.state = 'SUCCEEDED') "
                "LEFT JOIN precision_profiles AS precision ON precision.archive_id = archive.id "
                "AND precision.file_size = archive.file_size AND precision.mtime_ns = archive.mtime_ns "
                "AND precision.state = 'SUCCEEDED' AND precision.algorithm_version = ("
                "SELECT MAX(current_precision.algorithm_version) FROM precision_profiles AS current_precision "
                "WHERE current_precision.archive_id = archive.id AND current_precision.file_size = archive.file_size "
                "AND current_precision.mtime_ns = archive.mtime_ns AND current_precision.state = 'SUCCEEDED') "
                "LEFT JOIN filename_evidence AS evidence ON evidence.archive_id = archive.id "
                "AND evidence.file_size = archive.file_size AND evidence.mtime_ns = archive.mtime_ns "
                "AND evidence.path_key = archive.path_key AND evidence.algorithm_version = 2 "
                "WHERE member.group_id = ? AND archive.scan_root_id = ? ORDER BY archive.id",
                (int(group_id), root_id),
            ).fetchall()
            image_rows = self._connection.execute(
                "SELECT image.archive_id, image.entry_position, image.width, image.height "
                "FROM image_fingerprints AS image JOIN candidate_group_members AS member "
                "ON member.archive_id = image.archive_id WHERE member.group_id = ? "
                "AND image.analyzer_version = ? AND image.state = 'SUCCEEDED' "
                "AND image.width IS NOT NULL AND image.height IS NOT NULL "
                "ORDER BY image.archive_id, image.width * image.height, image.entry_position",
                (int(group_id), int(analyzer_version)),
            ).fetchall()
            representative_dimensions = _representative_dimensions(image_rows)
            members = tuple(
                RecommendationSourceMember(
                    archive_id=int(archive_id), path=Path(str(path)), file_size=int(file_size),
                    mtime_ns=int(mtime_ns), page_count=None if image_count is None else int(image_count),
                    resolution_area=(
                        None
                        if int(archive_id) not in representative_dimensions
                        else representative_dimensions[int(archive_id)][0]
                        * representative_dimensions[int(archive_id)][1]
                    ),
                    color_page_ratio=None if ratio is None else float(ratio),
                    language="UNKNOWN" if language is None else str(language),
                    language_analyzed=language is not None,
                    path_key=str(path_key),
                    language_confidence=(
                        0.0 if language_confidence is None else float(language_confidence)
                    ),
                    filename_language=(
                        None if filename_language is None else _filename_signal_from_json(str(filename_language))
                    ),
                    filename_color=(
                        None if filename_color is None else _filename_signal_from_json(str(filename_color))
                    ),
                    filename_mosaic=(
                        None if filename_mosaic is None else _filename_signal_from_json(str(filename_mosaic))
                    ),
                    filename_title_rank=None if title_rank is None else int(title_rank),
                )
                for (
                    archive_id, path, file_size, mtime_ns, image_count, ratio, language,
                    path_key, language_confidence, filename_language, filename_color,
                    filename_mosaic, title_rank,
                ) in rows
            )
            values.append(RecommendationSourceGroup(
                str(group_key), int(analyzer_version), members,
                self._recommendation_precision_relations(root_id, tuple(member.archive_id for member in members)),
                self._recommendation_source_relations(
                    root_id,
                    int(analyzer_version),
                    tuple(member.archive_id for member in members),
                ),
            ))
        return tuple(values)

    def _recommendation_precision_relations(
        self, root_id: int, member_ids: tuple[int, ...]
    ) -> tuple[PrecisionRelationRecord, ...]:
        if len(member_ids) < 2:
            return ()
        placeholders = ",".join("?" for _ in member_ids)
        rows = self._connection.execute(
            "SELECT relation.archive_a_id, relation.archive_b_id, relation.mosaic_direction, "
            "relation.mosaic_confidence, relation.quality_direction, relation.quality_confidence, "
            "relation.evidence_json FROM precision_relations AS relation "
            "JOIN archives AS left_archive ON left_archive.id = relation.archive_a_id "
            "JOIN archives AS right_archive ON right_archive.id = relation.archive_b_id "
            "AND relation.left_file_size = left_archive.file_size "
            "AND relation.left_mtime_ns = left_archive.mtime_ns "
            "AND relation.right_file_size = right_archive.file_size "
            "AND relation.right_mtime_ns = right_archive.mtime_ns "
            "JOIN precision_profiles AS left_profile ON left_profile.archive_id = left_archive.id "
            "AND left_profile.file_size = left_archive.file_size AND left_profile.mtime_ns = left_archive.mtime_ns "
            "AND left_profile.algorithm_version = relation.algorithm_version AND left_profile.state = 'SUCCEEDED' "
            "JOIN precision_profiles AS right_profile ON right_profile.archive_id = right_archive.id "
            "AND right_profile.file_size = right_archive.file_size AND right_profile.mtime_ns = right_archive.mtime_ns "
            "AND right_profile.algorithm_version = relation.algorithm_version AND right_profile.state = 'SUCCEEDED' "
            f"WHERE relation.scan_root_id = ? AND relation.archive_a_id IN ({placeholders}) "
            f"AND relation.archive_b_id IN ({placeholders}) "
            "AND relation.algorithm_version = ("
            "SELECT MAX(current_relation.algorithm_version) FROM precision_relations AS current_relation "
            "WHERE current_relation.scan_root_id = relation.scan_root_id "
            "AND current_relation.archive_a_id = relation.archive_a_id "
            "AND current_relation.archive_b_id = relation.archive_b_id) "
            "ORDER BY relation.archive_a_id, relation.archive_b_id",
            (root_id, *member_ids, *member_ids),
        ).fetchall()
        return tuple(
            PrecisionRelationRecord(int(left_id), int(right_id), str(mosaic), float(mosaic_confidence),
                str(quality), float(quality_confidence), _json_string_tuple(str(evidence)))
            for left_id, right_id, mosaic, mosaic_confidence, quality, quality_confidence, evidence in rows
        )

    def _recommendation_source_relations(
        self,
        root_id: int,
        analyzer_version: int,
        member_ids: tuple[int, ...],
    ) -> tuple[RecommendationSourceRelation, ...]:
        if len(member_ids) < 2:
            return ()
        placeholders = ",".join("?" for _ in member_ids)
        rows = self._connection.execute(
            "SELECT archive_a_id, archive_b_id, relation, matched_pages, confidence "
            "FROM candidate_relations WHERE scan_root_id = ? AND analyzer_version = ? "
            f"AND archive_a_id IN ({placeholders}) AND archive_b_id IN ({placeholders}) "
            "ORDER BY archive_a_id, archive_b_id",
            (root_id, analyzer_version, *member_ids, *member_ids),
        ).fetchall()
        return tuple(
            RecommendationSourceRelation(
                int(left), int(right), DuplicateRelation(str(relation)), int(matched), float(confidence)
            )
            for left, right, relation, matched, confidence in rows
        )

    def review_candidate_sets(self, root_id: int) -> tuple[ReviewCandidateSet, ...]:
        with _read_snapshot(self._connection):
            return self._review_candidate_sets(root_id)

    def _review_candidate_sets(
        self, root_id: int, set_keys: tuple[str, ...] | None = None
    ) -> tuple[ReviewCandidateSet, ...]:
        if set_keys == ():
            return ()
        key_filter = "" if set_keys is None else " AND candidate.set_key IN (" + ",".join("?" for _ in set_keys) + ")"
        generation_rows = self._connection.execute(
            "SELECT source_group_key, set_keys_json FROM edition_candidate_generations "
            "WHERE scan_root_id = ?",
            (root_id,),
        ).fetchall()
        generations = {
            str(group_key): _json_string_tuple(str(set_keys_json))
            for group_key, set_keys_json in generation_rows
        }
        rows = self._connection.execute(
            "SELECT candidate.set_key, candidate.source_group_key, candidate.edition_kind, candidate.member_ids_json, candidate.computed_at "
            "FROM edition_candidate_sets AS candidate JOIN candidate_groups AS groups "
            "ON groups.group_key = candidate.source_group_key AND groups.scan_root_id = candidate.scan_root_id "
            "WHERE candidate.scan_root_id = ?" + key_filter +
            " ORDER BY candidate.source_group_key, candidate.edition_kind, candidate.set_key",
            (root_id, *(set_keys or ())),
        ).fetchall()
        values: list[ReviewCandidateSet] = []
        for set_key, group_key, edition_kind, member_ids_json, computed_at in rows:
            archive_ids = _json_ints(str(member_ids_json))
            current = tuple(int(row[0]) for row in self._connection.execute(
                "SELECT member.archive_id FROM candidate_group_members AS member JOIN candidate_groups AS groups "
                "ON groups.id = member.group_id WHERE groups.group_key = ? AND groups.scan_root_id = ? "
                "ORDER BY member.archive_id", (str(group_key), root_id)
            ))
            if str(group_key) in generations:
                if (
                    str(set_key) in generations[str(group_key)]
                    and archive_ids is not None
                    and set(archive_ids) <= set(current)
                ):
                    values.append(
                        ReviewCandidateSet(
                            str(set_key), str(group_key), str(edition_kind), archive_ids
                        )
                    )
                continue
            latest = self._connection.execute(
                "SELECT MAX(computed_at) FROM edition_candidate_sets "
                "WHERE scan_root_id = ? AND source_group_key = ?", (root_id, str(group_key))
            ).fetchone()
            latest_members = tuple(
                _json_ints(str(row[0]))
                for row in self._connection.execute(
                    "SELECT member_ids_json FROM edition_candidate_sets WHERE scan_root_id = ? "
                    "AND source_group_key = ? AND computed_at = ?",
                    (root_id, str(group_key), None if latest is None else latest[0]),
                )
            )
            if (
                archive_ids is not None
                and latest is not None and computed_at == latest[0]
                and all(item is not None for item in latest_members)
                and set().union(*(set(item) for item in latest_members if item is not None)) == set(current)
            ):
                values.append(ReviewCandidateSet(str(set_key), str(group_key), str(edition_kind), archive_ids))
        return tuple(values)

    def review_candidate_sets_for_keys(
        self, set_keys: tuple[str, ...]
    ) -> tuple[ReviewCandidateSet, ...]:
        """Return only current derived sets named by the caller."""
        keys = tuple(dict.fromkeys(str(value) for value in set_keys if str(value)))
        if not keys:
            return ()
        with _read_snapshot(self._connection):
            placeholders = ",".join("?" for _ in keys)
            root_rows = self._connection.execute(
                f"SELECT DISTINCT scan_root_id FROM edition_candidate_sets WHERE set_key IN ({placeholders})",
                keys,
            ).fetchall()
            wanted = set(keys)
            values: list[ReviewCandidateSet] = []
            for (root_id,) in root_rows:
                values.extend(
                    item
                    for item in self._review_candidate_sets(int(root_id), keys)
                    if item.set_key in wanted
                )
        return tuple(sorted(values, key=lambda item: item.set_key))

    def precision_scope_for_sets(self, set_keys: tuple[str, ...]) -> PrecisionScope:
        keys = tuple(sorted({str(value) for value in set_keys if str(value)}))
        if not keys:
            raise ValueError("Precision analysis requires at least one current candidate set.")
        with _read_snapshot(self._connection):
            candidate_sets = self.review_candidate_sets_for_keys(keys)
            if tuple(item.set_key for item in candidate_sets) != keys:
                raise ValueError("Precision analysis candidate set is missing or stale.")
            placeholders = ",".join("?" for _ in keys)
            roots = {
                int(row[0])
                for row in self._connection.execute(
                    f"SELECT DISTINCT scan_root_id FROM edition_candidate_sets "
                    f"WHERE set_key IN ({placeholders})",
                    keys,
                )
            }
            if len(roots) != 1:
                raise ValueError("Precision candidate sets must belong to one scan root.")
            archive_ids = tuple(
                sorted({archive_id for item in candidate_sets for archive_id in item.archive_ids})
            )
            relation_pairs = tuple(
                sorted(
                    {
                        (min(left, right), max(left, right))
                        for item in candidate_sets
                        for index, left in enumerate(item.archive_ids)
                        for right in item.archive_ids[index + 1 :]
                        if left != right
                    }
                )
            )
            if not archive_ids:
                raise ValueError("Precision analysis candidate set has no current members.")
            return PrecisionScope(keys, archive_ids, relation_pairs)

    def candidate_set_generation_group_keys(self, root_id: int) -> tuple[str, ...]:
        with _read_snapshot(self._connection):
            return tuple(
                str(row[0])
                for row in self._connection.execute(
                    "SELECT source_group_key FROM edition_candidate_generations "
                    "WHERE scan_root_id = ? ORDER BY source_group_key",
                    (root_id,),
                )
            )

    def has_candidate_set_generations(self, root_id: int) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM edition_candidate_generations WHERE scan_root_id = ? LIMIT 1",
            (root_id,),
        ).fetchone()
        return row is not None

    def completed_recommendation_run_for_input(self, root_id: int, input_fingerprint: str) -> int | None:
        row = self._connection.execute(
            "SELECT id FROM recommendation_runs WHERE scan_root_id = ? AND input_fingerprint = ? "
            "AND state = 'COMPLETED' ORDER BY id DESC LIMIT 1", (root_id, input_fingerprint)
        ).fetchone()
        return None if row is None else int(row[0])

    def claim_recommendation_run(
        self,
        root_id: int,
        criteria_version: int,
        input_fingerprint: str,
        started_at: datetime,
    ) -> RecommendationRunClaim:
        """Atomically reuse terminal/running work or create the one new run."""
        with self._analysis_write_transaction(None, None, immediate=True):
            if self._connection.execute(
                "SELECT 1 FROM scan_roots WHERE id = ?", (root_id,)
            ).fetchone() is None:
                raise ValueError("Unknown scan root.")
            existing = self._connection.execute(
                "SELECT id FROM recommendation_runs WHERE scan_root_id = ? "
                "AND input_fingerprint = ? AND state IN ('RUNNING', 'COMPLETED') "
                "ORDER BY CASE state WHEN 'COMPLETED' THEN 0 ELSE 1 END, id DESC LIMIT 1",
                (root_id, input_fingerprint),
            ).fetchone()
            if existing is not None:
                return RecommendationRunClaim(int(existing[0]), False)
            cursor = self._connection.execute(
                "INSERT INTO recommendation_runs(scan_root_id, criteria_version, input_fingerprint, state, started_at) "
                "VALUES (?, ?, ?, 'RUNNING', ?)",
                (root_id, criteria_version, input_fingerprint, started_at.isoformat()),
            )
        return RecommendationRunClaim(int(cursor.lastrowid), True)

    def begin_recommendation_run(
        self,
        root_id: int,
        criteria_version: int,
        started_at: datetime,
        *,
        owner_token: str | None = None,
        now: datetime | Callable[[], datetime] | None = None,
        input_fingerprint: str | None = None,
    ) -> int:
        transaction_now = started_at if owner_token is not None and now is None else now
        with self._analysis_write_transaction(owner_token, transaction_now, immediate=True):
            if self._connection.execute(
                "SELECT 1 FROM scan_roots WHERE id = ?", (root_id,)
            ).fetchone() is None:
                raise ValueError("Unknown scan root.")
            cursor = self._connection.execute(
                "INSERT INTO recommendation_runs(scan_root_id, criteria_version, input_fingerprint, state, started_at) "
                "VALUES (?, ?, ?, 'RUNNING', ?)",
                (root_id, criteria_version, input_fingerprint, started_at.isoformat()),
            )
        return int(cursor.lastrowid)

    def finish_recommendation_run(
        self,
        run_id: int,
        *,
        state: str,
        completed_at: datetime,
        error_code: str | None = None,
        expected_state: str = "RUNNING",
        owner_token: str | None = None,
        now: datetime | Callable[[], datetime] | None = None,
    ) -> None:
        if expected_state != "RUNNING":
            raise ValueError("Recommendation runs may only transition from RUNNING.")
        if state not in {"COMPLETED", "FAILED"}:
            raise ValueError("Unsupported recommendation run state.")
        if state == "FAILED" and not error_code:
            raise ValueError("Failed recommendation runs require an error code.")
        if state == "COMPLETED" and error_code is not None:
            raise ValueError("Completed recommendation runs cannot have an error code.")
        transaction_now = completed_at if owner_token is not None and now is None else now
        with self._analysis_write_transaction(owner_token, transaction_now, immediate=True):
            cursor = self._connection.execute(
                "UPDATE recommendation_runs SET state = ?, completed_at = ?, error_code = ? "
                "WHERE id = ? AND state = ?",
                (state, completed_at.isoformat(), error_code, run_id, expected_state),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("Recommendation run is not in the expected state.")

    def replace_recommendation_items(
        self,
        run_id: int,
        candidate_set: ReviewCandidateSet,
        decision: RecommendationRecord,
        *,
        owner_token: str | None = None,
        now: datetime | Callable[[], datetime] | None = None,
    ) -> RecommendationRecord:
        if decision.set_key != candidate_set.set_key:
            raise ValueError("Recommendation decision set changed.")
        if decision.source_group_key != candidate_set.source_group_key:
            raise ValueError("Recommendation decision source group changed.")
        if decision.archive_id not in candidate_set.archive_ids:
            raise ValueError("Recommendation decision archive is not in the candidate set.")
        if decision.recommendation not in {"KEEP", "REMOVE_CANDIDATE", "NONE"}:
            raise ValueError("Unknown recommendation.")
        if not decision.status:
            raise ValueError("Recommendation status is required.")
        criteria_json = _stable_json_mapping(decision.criteria)
        with self._analysis_write_transaction(owner_token, now, immediate=True):
            run = self._connection.execute(
                "SELECT scan_root_id FROM recommendation_runs WHERE id = ? AND state = 'RUNNING'",
                (run_id,),
            ).fetchone()
            candidate = self._connection.execute(
                "SELECT scan_root_id, source_group_key FROM edition_candidate_sets WHERE set_key = ?",
                (candidate_set.set_key,),
            ).fetchone()
            archive = self._connection.execute(
                "SELECT scan_root_id, file_size, mtime_ns FROM archives WHERE id = ?",
                (decision.archive_id,),
            ).fetchone()
            if run is None or candidate is None or archive is None:
                raise ValueError("Recommendation inputs are no longer current.")
            if (
                int(run[0]) != int(candidate[0])
                or str(candidate[1]) != candidate_set.source_group_key
                or int(archive[0]) != int(run[0])
                or (int(archive[1]), int(archive[2]))
                != (decision.file_size, decision.mtime_ns)
            ):
                raise ValueError("Recommendation inputs are no longer current.")
            application = self._connection.execute(
                "SELECT 1 FROM recommendation_applications AS application "
                "JOIN recommendation_items AS item ON item.id = application.recommendation_item_id "
                "WHERE item.run_id = ? AND item.set_key = ? AND item.archive_id = ?",
                (run_id, candidate_set.set_key, decision.archive_id),
            ).fetchone()
            if application is not None:
                raise ValueError("An applied recommendation item cannot be replaced.")
            self._connection.execute(
                "INSERT INTO recommendation_items("
                "run_id, set_key, source_group_key, archive_id, recommendation, status, criteria_json, "
                "reason, file_size, mtime_ns"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(run_id, set_key, archive_id) DO UPDATE SET "
                "source_group_key = excluded.source_group_key, recommendation = excluded.recommendation, "
                "status = excluded.status, criteria_json = excluded.criteria_json, reason = excluded.reason, "
                "file_size = excluded.file_size, mtime_ns = excluded.mtime_ns",
                (
                    run_id,
                    candidate_set.set_key,
                    candidate_set.source_group_key,
                    decision.archive_id,
                    decision.recommendation,
                    decision.status,
                    criteria_json,
                    decision.reason,
                    decision.file_size,
                    decision.mtime_ns,
                ),
            )
            row = self._connection.execute(
                "SELECT id FROM recommendation_items WHERE run_id = ? AND set_key = ? AND archive_id = ?",
                (run_id, candidate_set.set_key, decision.archive_id),
            ).fetchone()
        assert row is not None
        return RecommendationRecord(
            item_id=int(row[0]),
            set_key=decision.set_key,
            source_group_key=decision.source_group_key,
            archive_id=decision.archive_id,
            recommendation=decision.recommendation,
            status=decision.status,
            criteria=dict(decision.criteria),
            reason=decision.reason,
            file_size=decision.file_size,
            mtime_ns=decision.mtime_ns,
        )

    def latest_recommendations(
        self, set_keys: tuple[str, ...]
    ) -> tuple[RecommendationRecord, ...]:
        keys = tuple(dict.fromkeys(str(value) for value in set_keys if str(value)))
        if not keys:
            return ()
        with _read_snapshot(self._connection):
            current_keys = tuple(
                item.set_key for item in self.review_candidate_sets_for_keys(keys)
            )
            return self._recommendation_records_for_keys(current_keys)

    def latest_recommendations_for_root(self, root_id: int) -> tuple[RecommendationRecord, ...]:
        return self.latest_recommendations(tuple(item.set_key for item in self.review_candidate_sets(root_id)))

    def recommendation_snapshot_matches(self, recommendation: RecommendationRecord) -> bool:
        """Verify both the indexed and on-disk snapshot before applying a recommendation."""
        row = self._connection.execute(
            "SELECT archive.path, archive.file_size, archive.mtime_ns, groups.group_key "
            "FROM candidate_groups AS groups "
            "JOIN candidate_group_members AS member ON member.group_id = groups.id "
            "JOIN archives AS archive ON archive.id = member.archive_id "
            "WHERE groups.group_key = ? AND member.archive_id = ?",
            (recommendation.source_group_key, recommendation.archive_id),
        ).fetchone()
        if row is None or (int(row[1]), int(row[2])) != (
            recommendation.file_size,
            recommendation.mtime_ns,
        ):
            return False
        try:
            snapshot = Path(str(row[0])).stat()
        except OSError:
            return False
        return (snapshot.st_size, snapshot.st_mtime_ns) == (
            recommendation.file_size,
            recommendation.mtime_ns,
        )

    def apply_recommendation_item(
        self, recommendation: RecommendationRecord, applied_at: datetime
    ) -> str:
        """Append one recommendation-backed review action atomically.

        The return value is a small, stable outcome vocabulary used by the
        batch layer.  A direct user action is never overwritten; an older
        recommendation application may be refreshed when the current action
        is still the same verified snapshot.
        """
        if recommendation.recommendation not in {"KEEP", "REMOVE_CANDIDATE"}:
            return "NO_RECOMMENDATION"
        with _immediate_transaction(self._connection):
            if not self.recommendation_snapshot_matches(recommendation):
                return "CHANGED_SNAPSHOT_SKIPPED"
            candidate_set = next(
                iter(self.review_candidate_sets_for_keys((recommendation.set_key,))),
                None,
            )
            if (
                candidate_set is None
                or candidate_set.source_group_key != recommendation.source_group_key
                or recommendation.archive_id not in candidate_set.archive_ids
            ):
                return "CHANGED_SNAPSHOT_SKIPPED"
            current = self._connection.execute(
                "SELECT archive.file_size, archive.mtime_ns, groups.group_key "
                "FROM candidate_groups AS groups "
                "JOIN candidate_group_members AS member ON member.group_id = groups.id "
                "JOIN archives AS archive ON archive.id = member.archive_id "
                "WHERE groups.group_key = ? AND member.archive_id = ?",
                (recommendation.source_group_key, recommendation.archive_id),
            ).fetchone()
            if current is None:
                return "CHANGED_SNAPSHOT_SKIPPED"
            current_size, current_mtime = int(current[0]), int(current[1])
            if (current_size, current_mtime) != (
                recommendation.file_size,
                recommendation.mtime_ns,
            ):
                return "CHANGED_SNAPSHOT_SKIPPED"
            latest = self._connection.execute(
                "SELECT id, group_key, file_size, mtime_ns FROM review_actions "
                "WHERE archive_id = ? ORDER BY id DESC LIMIT 1",
                (recommendation.archive_id,),
            ).fetchone()
            if latest is not None:
                latest_id, latest_group, latest_size, latest_mtime = latest
                if str(latest_group) != recommendation.source_group_key:
                    return "USER_DECISION_SKIPPED"
                if (int(latest_size), int(latest_mtime)) != (
                    current_size,
                    current_mtime,
                ):
                    return "CHANGED_SNAPSHOT_SKIPPED"
                application = self._connection.execute(
                    "SELECT recommendation_item_id FROM recommendation_applications "
                    "WHERE review_action_id = ?",
                    (int(latest_id),),
                ).fetchone()
                if application is None and not self.is_review_reset(int(latest_id)):
                    return "USER_DECISION_SKIPPED"
                if application is not None and int(application[0]) == recommendation.item_id:
                    return "ALREADY_APPLIED"
            action = (
                ReviewAction.KEEP
                if recommendation.recommendation == "KEEP"
                else ReviewAction.REMOVE_CANDIDATE
            )
            cursor = self._insert_review_action(
                recommendation.source_group_key,
                recommendation.archive_id,
                action,
                current_size,
                current_mtime,
                applied_at,
            )
            action_id = cursor.lastrowid
            if action_id is None:
                raise RuntimeError("Recommendation review action was not created.")
            self._connection.execute(
                "INSERT INTO recommendation_applications("
                "review_action_id, recommendation_item_id, applied_at) VALUES (?, ?, ?)",
                (int(action_id), recommendation.item_id, applied_at.isoformat()),
            )
            return "APPLIED"

    def is_review_reset(self, action_id: int) -> bool:
        return self._connection.execute(
            "SELECT 1 FROM review_reset_actions WHERE review_action_id = ?", (action_id,)
        ).fetchone() is not None

    def archive_activity(self, archive_ids) -> dict[int, dict[str, str]]:
        result: dict[int, dict[str, str]] = {}
        ids = tuple(dict.fromkeys(archive_ids))
        for offset in range(0, len(ids), 500):
            batch = ids[offset:offset + 500]
            placeholders = ",".join("?" for _ in batch)
            for table, column, key, condition in (
                ("review_actions", "created_at", "reviewed_at", ""),
                ("quarantine_items", "updated_at", "quarantined_at", " AND status IN ('QUARANTINED','RESTORED')"),
                ("deletion_records", "deleted_at", "deleted_at", " AND state = 'DELETED'"),
            ):
                for archive_id, timestamp in self._connection.execute(
                    f"SELECT archive_id, MAX({column}) FROM {table} WHERE archive_id IN ({placeholders}){condition} GROUP BY archive_id", batch
                ):
                    result.setdefault(int(archive_id), {})[key] = str(timestamp or "")
        return result

    def keep_unreviewed_groups(self, group_keys, created_at: datetime) -> int:
        seen = set()
        with _immediate_transaction(self._connection):
            for key in dict.fromkeys(group_keys):
                detail = self.review_group_details(key) or self.group_details(key)
                if detail is None:
                    continue
                source_key = getattr(detail, "source_group_key", key)
                for member in detail.members:
                    if member.archive_id in seen or member.deletion_state == "DELETED" or member.quarantine_status in {"PENDING", "QUARANTINED", "RESTORING", "FAILED"}:
                        continue
                    if member.review_action is not None and not member.needs_review:
                        continue
                    current = self._current_review_member_snapshot(source_key, member.archive_id)
                    self._insert_review_action(source_key, member.archive_id, ReviewAction.KEEP,
                        current.size, current.mtime_ns, created_at)
                    seen.add(member.archive_id)
        return len(seen)

    def reset_review_sets(self, set_keys, created_at: datetime) -> int:
        candidates = self.review_candidate_sets_for_keys(tuple(set_keys))
        seen = set()
        with _immediate_transaction(self._connection):
            for candidate in candidates:
                for archive_id in candidate.archive_ids:
                    if archive_id in seen:
                        continue
                    current = self._current_review_member_snapshot(candidate.source_group_key, archive_id)
                    cursor = self._insert_review_action(candidate.source_group_key, archive_id,
                        ReviewAction.HOLD, current.size, current.mtime_ns, created_at)
                    self._connection.execute(
                        "INSERT INTO review_reset_actions(review_action_id) VALUES (?)", (cursor.lastrowid,))
                    seen.add(archive_id)
        return len(seen)

    def recommendation_application_for_action(self, action_id: int) -> int | None:
        row = self._connection.execute(
            "SELECT recommendation_item_id FROM recommendation_applications "
            "WHERE review_action_id = ?",
            (int(action_id),),
        ).fetchone()
        return None if row is None else int(row[0])

    def recommendation_run_ids_for_group(self, root_id: int, source_group_key: str) -> tuple[int, ...]:
        rows = self._connection.execute(
            "SELECT DISTINCT run.id FROM recommendation_runs AS run "
            "JOIN recommendation_items AS item ON item.run_id = run.id "
            "WHERE run.scan_root_id = ? AND item.source_group_key = ? ORDER BY run.id",
            (root_id, source_group_key),
        ).fetchall()
        return tuple(int(row[0]) for row in rows)

    def recommendation_run_count(self, root_id: int) -> int:
        row = self._connection.execute(
            "SELECT COUNT(*) FROM recommendation_runs WHERE scan_root_id = ?", (root_id,)
        ).fetchone()
        assert row is not None
        return int(row[0])

    def _store_candidate_set(
        self,
        candidate_set: ReviewCandidateSet,
        source_group_key: str,
        root_id: int,
        algorithm_version: int,
        member_ids: set[int],
        computed_at: datetime,
    ) -> str:
        if candidate_set.source_group_key != source_group_key:
            raise ValueError("Candidate set source group changed.")
        if candidate_set.edition_kind not in {
            "FULL_COLOR",
            "MONOCHROME",
            "MIXED_OR_UNKNOWN",
        }:
            raise ValueError("Unknown edition candidate set kind.")
        archive_ids = tuple(candidate_set.archive_ids)
        if not archive_ids or archive_ids != tuple(sorted(set(archive_ids))):
            raise ValueError("Candidate set archive IDs must be sorted and unique.")
        if not set(archive_ids) <= member_ids:
            raise ValueError("Candidate set archives must belong to the current candidate group.")
        fingerprint = _candidate_set_input_fingerprint(
            source_group_key, candidate_set.edition_kind, archive_ids, _RECOMMENDATION_SET_ALGORITHM_VERSION
        )
        existing = self._connection.execute(
            "SELECT input_fingerprint, algorithm_version FROM edition_candidate_sets "
            "WHERE set_key = ?",
            (candidate_set.set_key,),
        ).fetchone()
        if existing is not None and (str(existing[0]), int(existing[1])) != (
            fingerprint,
            _RECOMMENDATION_SET_ALGORITHM_VERSION,
        ):
            raise ValueError("Candidate set key cannot be reused for different inputs.")
        self._connection.execute(
            "INSERT INTO edition_candidate_sets("
            "set_key, scan_root_id, source_group_key, edition_kind, member_ids_json, "
            "input_fingerprint, algorithm_version, computed_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(source_group_key, edition_kind, input_fingerprint, algorithm_version) "
            "DO UPDATE SET computed_at = excluded.computed_at",
            (
                candidate_set.set_key,
                root_id,
                source_group_key,
                candidate_set.edition_kind,
                _stable_json_ints(archive_ids),
                fingerprint,
                _RECOMMENDATION_SET_ALGORITHM_VERSION,
                computed_at.isoformat(),
            ),
        )
        row = self._connection.execute(
            "SELECT set_key FROM edition_candidate_sets WHERE source_group_key = ? "
            "AND edition_kind = ? AND input_fingerprint = ? AND algorithm_version = ?",
            (source_group_key, candidate_set.edition_kind, fingerprint, _RECOMMENDATION_SET_ALGORITHM_VERSION),
        ).fetchone()
        assert row is not None
        return str(row[0])

    def _recommendation_records_for_keys(
        self, set_keys: tuple[str, ...]
    ) -> tuple[RecommendationRecord, ...]:
        records: list[RecommendationRecord] = []
        for start in range(0, len(set_keys), _ARCHIVE_VALIDATION_CHUNK_SIZE):
            chunk = set_keys[start : start + _ARCHIVE_VALIDATION_CHUNK_SIZE]
            placeholders = ",".join("?" for _ in chunk)
            rows = self._connection.execute(
                "SELECT item.id, item.set_key, item.source_group_key, item.archive_id, "
                "item.recommendation, item.status, item.criteria_json, item.reason, "
                "item.file_size, item.mtime_ns "
                "FROM recommendation_items AS item "
                "JOIN recommendation_runs AS run ON run.id = item.run_id "
                "JOIN ("
                "SELECT latest_item.set_key, MAX(latest_run.id) AS run_id "
                "FROM recommendation_items AS latest_item "
                "JOIN recommendation_runs AS latest_run ON latest_run.id = latest_item.run_id "
                f"WHERE latest_run.state = 'COMPLETED' AND latest_item.set_key IN ({placeholders}) "
                "GROUP BY latest_item.set_key"
                ") AS latest ON latest.set_key = item.set_key AND latest.run_id = item.run_id "
                "WHERE run.state = 'COMPLETED' "
                "ORDER BY item.set_key, item.archive_id",
                chunk,
            ).fetchall()
            records.extend(_recommendation_record_from_row(row) for row in rows)
        return tuple(sorted(records, key=lambda record: (record.set_key, record.archive_id)))

    def latest_completed_result(self) -> tuple[str, str, int] | None:
        row = self._connection.execute(
            "SELECT roots.path, runs.finished_at, runs.candidate_count "
            "FROM duplicate_analysis_runs AS runs "
            "JOIN scan_roots AS roots ON roots.id = runs.scan_root_id "
            "WHERE runs.status = 'COMPLETED' AND runs.finished_at IS NOT NULL "
            "ORDER BY runs.finished_at DESC, runs.id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        return str(row[0]), str(row[1]), int(row[2])

    def latest_run_status(self) -> str | None:
        return self.latest_duplicate_run_status()

    def begin_duplicate_run(
        self,
        root_id: int,
        *,
        analyzer_version: int,
        archive_total: int,
        image_total: int,
        started_at: datetime,
        owner_token: str,
    ) -> int:
        """Start a run and attach resumable pending work from the latest run.

        Acquiring the common operation lock proves that any previous owner is
        gone or its lease expired.  A claimed job from that owner is therefore
        safe to return to PENDING before it is attached to this run.
        """

        with self._owned_write_transaction(owner_token, started_at):
            if self._connection.execute(
                "SELECT 1 FROM scan_roots WHERE id = ?", (root_id,)
            ).fetchone() is None:
                raise ValueError(f"Unknown scan root {root_id}.")
            previous = self._connection.execute(
                "SELECT id FROM duplicate_analysis_runs "
                "WHERE scan_root_id = ? AND analyzer_version = ? "
                "AND status IN ('RUNNING','INTERRUPTED','FAILED') "
                "ORDER BY id DESC LIMIT 1",
                (root_id, analyzer_version),
            ).fetchone()
            self._connection.execute(
                "UPDATE duplicate_analysis_runs SET status = 'INTERRUPTED', finished_at = ? "
                "WHERE status = 'RUNNING'",
                (started_at.isoformat(),),
            )
            if previous is not None:
                previous_run_id = int(previous[0])
                self._connection.execute(
                    "UPDATE duplicate_analysis_jobs SET status = 'PENDING', started_at = NULL "
                    "WHERE analysis_run_id = ? AND status = 'RUNNING'",
                    (previous_run_id,),
                )
            cursor = self._connection.execute(
                "INSERT INTO duplicate_analysis_runs("
                "scan_root_id, status, stage, started_at, analyzer_version, archive_total, "
                "image_total) VALUES (?, 'RUNNING', 'ARCHIVE_HASH', ?, ?, ?, ?)",
                (
                    root_id,
                    started_at.isoformat(),
                    analyzer_version,
                    archive_total,
                    image_total,
                ),
            )
            run_id = int(cursor.lastrowid)
            if previous is not None:
                self._connection.execute(
                    "UPDATE duplicate_analysis_jobs SET analysis_run_id = ? "
                    "WHERE analysis_run_id = ? AND status = 'PENDING'",
                    (run_id, int(previous[0])),
                )
        return run_id

    def prepare_duplicate_jobs(
        self,
        run_id: int,
        stage: AnalysisStage,
        subjects: tuple[tuple[str, int | None], ...],
        *,
        now: datetime,
        owner_token: str,
    ) -> None:
        if stage not in {
            AnalysisStage.ARCHIVE_HASH,
            AnalysisStage.PROBE,
            AnalysisStage.FULL,
            AnalysisStage.MATCH,
        }:
            raise ValueError(f"Stage {stage.value} does not have archive jobs.")
        unique_subjects = tuple(dict.fromkeys(subjects))
        subject_keys = {subject_key for subject_key, _ in unique_subjects}
        with self._owned_write_transaction(owner_token, now):
            self._require_duplicate_run_active(run_id)
            obsolete = self._connection.execute(
                "SELECT id, subject_key FROM duplicate_analysis_jobs "
                "WHERE analysis_run_id = ? AND stage = ? AND status = 'PENDING'",
                (run_id, stage.value),
            ).fetchall()
            self._connection.executemany(
                "DELETE FROM duplicate_analysis_jobs WHERE id = ?",
                tuple((int(job_id),) for job_id, key in obsolete if str(key) not in subject_keys),
            )
            self._connection.executemany(
                "INSERT INTO duplicate_analysis_jobs("
                "analysis_run_id, archive_id, stage, subject_key, status, created_at"
                ") VALUES (?, ?, ?, ?, 'PENDING', ?) "
                "ON CONFLICT(analysis_run_id, stage, subject_key) DO NOTHING",
                tuple(
                    (run_id, archive_id, stage.value, subject_key, now.isoformat())
                    for subject_key, archive_id in unique_subjects
                ),
            )

    def claim_duplicate_job(
        self,
        run_id: int,
        stage: AnalysisStage,
        subject_key: str,
        *,
        now: datetime,
        owner_token: str,
    ) -> DuplicateJob:
        with self._owned_write_transaction(owner_token, now):
            self._require_duplicate_run_active(run_id)
            cursor = self._connection.execute(
                "UPDATE duplicate_analysis_jobs SET status = 'RUNNING', attempts = attempts + 1, "
                "started_at = ?, finished_at = NULL, last_error_code = NULL "
                "WHERE analysis_run_id = ? AND stage = ? AND subject_key = ? "
                "AND status = 'PENDING'",
                (now.isoformat(), run_id, stage.value, subject_key),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("Duplicate analysis job is not pending.")
            row = self._connection.execute(
                "SELECT id, analysis_run_id, archive_id, stage, subject_key, status, attempts, "
                "last_error_code FROM duplicate_analysis_jobs "
                "WHERE analysis_run_id = ? AND stage = ? AND subject_key = ?",
                (run_id, stage.value, subject_key),
            ).fetchone()
        assert row is not None
        return _duplicate_job(row)

    def archive_fingerprint_error(self, archive_id: int) -> str | None:
        row = self._connection.execute(
            "SELECT error_code FROM archive_fingerprints WHERE archive_id = ?",
            (archive_id,),
        ).fetchone()
        return None if row is None or row[0] is None else str(row[0])

    def finish_duplicate_job(
        self,
        job_id: int,
        *,
        status: str,
        error_code: str | None,
        now: datetime,
        owner_token: str,
    ) -> None:
        if status not in {"SUCCEEDED", "SKIPPED", "FAILED"}:
            raise ValueError("Unsupported duplicate job terminal status.")
        with self._owned_write_transaction(owner_token, now):
            cursor = self._connection.execute(
                "UPDATE duplicate_analysis_jobs SET status = ?, last_error_code = ?, "
                "finished_at = ? WHERE id = ? AND status = 'RUNNING'",
                (status, error_code, now.isoformat(), job_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("Duplicate analysis job is no longer running.")

    def reset_running_duplicate_jobs(
        self, run_id: int, *, now: datetime, owner_token: str
    ) -> int:
        with self._owned_write_transaction(owner_token, now):
            cursor = self._connection.execute(
                "UPDATE duplicate_analysis_jobs SET status = 'PENDING', started_at = NULL "
                "WHERE analysis_run_id = ? AND status = 'RUNNING'",
                (run_id,),
            )
        return int(cursor.rowcount)

    def update_duplicate_run(
        self,
        run_id: int,
        *,
        stage: AnalysisStage,
        archive_processed: int,
        image_processed: int,
        failed_count: int,
        candidate_count: int,
        now: datetime,
        owner_token: str,
    ) -> None:
        with self._owned_write_transaction(owner_token, now):
            cursor = self._connection.execute(
                "UPDATE duplicate_analysis_runs SET stage = ?, archive_processed = ?, "
                "image_processed = ?, failed_count = ?, candidate_count = ? "
                "WHERE id = ? AND status = 'RUNNING'",
                (
                    stage.value,
                    archive_processed,
                    image_processed,
                    failed_count,
                    candidate_count,
                    run_id,
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("Duplicate analysis run is not active.")

    def finish_duplicate_run(
        self,
        run_id: int,
        *,
        status: str,
        archive_processed: int,
        image_processed: int,
        failed_count: int,
        candidate_count: int,
        finished_at: datetime,
        owner_token: str,
    ) -> None:
        if status not in {"COMPLETED", "INTERRUPTED", "FAILED"}:
            raise ValueError("Unsupported duplicate run status.")
        with self._owned_write_transaction(owner_token, finished_at):
            cursor = self._connection.execute(
                "UPDATE duplicate_analysis_runs SET status = ?, finished_at = ?, "
                "archive_processed = ?, image_processed = ?, failed_count = ?, "
                "candidate_count = ? WHERE id = ? AND status = 'RUNNING'",
                (
                    status,
                    finished_at.isoformat(),
                    archive_processed,
                    image_processed,
                    failed_count,
                    candidate_count,
                    run_id,
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("Duplicate analysis run is not active.")

    def _require_duplicate_run_active(self, run_id: int) -> None:
        if self._connection.execute(
            "SELECT 1 FROM duplicate_analysis_runs WHERE id = ? AND status = 'RUNNING'",
            (run_id,),
        ).fetchone() is None:
            raise RuntimeError("Duplicate analysis run is not active.")

    @contextmanager
    def _analysis_write_transaction(
        self,
        owner_token: str | None,
        now: datetime | Callable[[], datetime] | None,
        *,
        immediate: bool = False,
    ) -> Iterator[None]:
        if (owner_token is None) != (now is None):
            raise ValueError("owner_token and now must be provided together.")
        if owner_token is not None and now is not None:
            write_now = now() if callable(now) else now
            with self._owned_write_transaction(owner_token, write_now):
                yield
            return
        transaction = (
            _immediate_transaction(self._connection)
            if immediate
            else self._connection
        )
        with transaction:
            yield

    def store_archive_fingerprint(
        self,
        value: ArchiveAnalysisInput,
        *,
        analyzer_version: int,
        computed_at: datetime,
        sha256: str | None,
        hash_state: str,
        error_code: str | None = None,
        owner_token: str | None = None,
        now: datetime | Callable[[], datetime] | None = None,
    ) -> bool:
        if not _snapshot_matches(value):
            return False
        try:
            with self._analysis_write_transaction(owner_token, now):
                self._delete_stale_snapshot_rows(value, analyzer_version)
                self._upsert_archive_fingerprint(
                    value, analyzer_version, computed_at, sha256, hash_state, error_code
                )
                _require_current_snapshot(value)
        except _SnapshotChanged:
            return False
        return True

    def store_probe_fingerprints(
        self,
        value: ArchiveAnalysisInput,
        *,
        analyzer_version: int,
        computed_at: datetime,
        sha256: str | None,
        hash_state: str,
        successes: tuple[tuple[int, ImageFingerprint], ...],
        failures: tuple[tuple[int, str], ...],
        error_code: str | None = None,
        owner_token: str | None = None,
        now: datetime | Callable[[], datetime] | None = None,
    ) -> bool:
        if not _snapshot_matches(value):
            return False
        try:
            with self._analysis_write_transaction(owner_token, now):
                self._delete_stale_snapshot_rows(value, analyzer_version)
                for entry_position, fingerprint in successes:
                    self._upsert_image_fingerprint(
                        value,
                        entry_position=entry_position,
                        coverage="PROBE",
                        analyzer_version=analyzer_version,
                        computed_at=computed_at,
                        fingerprint=fingerprint,
                    )
                for entry_position, failure_code in failures:
                    self._upsert_image_fingerprint(
                        value,
                        entry_position=entry_position,
                        coverage="PROBE",
                        analyzer_version=analyzer_version,
                        computed_at=computed_at,
                        error_code=failure_code,
                    )
                self._upsert_archive_fingerprint(
                    value,
                    analyzer_version,
                    computed_at,
                    sha256,
                    hash_state,
                    error_code,
                    preserve_hash_result=hash_state == "NOT_REQUIRED",
                )
                _require_current_snapshot(value)
        except _SnapshotChanged:
            return False
        return True

    def cached_fingerprints(
        self, value: ArchiveAnalysisInput, analyzer_version: int
    ) -> CachedFingerprints | None:
        if not _snapshot_matches(value):
            return None
        row = self._connection.execute(
            "SELECT sha256, hash_state, filename_tokens_json, language_hints_json "
            "FROM archive_fingerprints WHERE archive_id = ? AND file_size = ? AND mtime_ns = ? "
            "AND analyzer_version = ?",
            (value.archive_id, value.file_size, value.mtime_ns, analyzer_version),
        ).fetchone()
        if row is None:
            return None
        image_rows = self._connection.execute(
            "SELECT entry_position, byte_sha256, pixel_sha256, dhash64, ahash64, width, height, "
            "state, error_code, coverage FROM image_fingerprints "
            "WHERE archive_id = ? AND analyzer_version = ? AND coverage IN ('PROBE', 'FULL') "
            "ORDER BY entry_position",
            (value.archive_id, analyzer_version),
        ).fetchall()
        successes = tuple(
            CachedImageFingerprint(
                entry_position=int(entry_position),
                fingerprint=ImageFingerprint(
                    byte_sha256=str(byte_sha256),
                    pixel_sha256=str(pixel_sha256),
                    dhash64=str(dhash64),
                    ahash64=str(ahash64),
                    width=int(width),
                    height=int(height),
                ),
            )
            for entry_position, byte_sha256, pixel_sha256, dhash64, ahash64, width, height, state, _, _ in image_rows
            if state == "SUCCEEDED"
        )
        failures = tuple(
            (int(entry_position), str(error_code))
            for entry_position, _, _, _, _, _, _, state, error_code, _ in image_rows
            if state == "FAILED" and error_code is not None
        )
        full_entry_positions = frozenset(
            int(entry_position)
            for entry_position, _, _, _, _, _, _, _, _, coverage in image_rows
            if coverage == "FULL"
        )
        if not _snapshot_matches(value):
            return None
        return CachedFingerprints(
            sha256=None if row[0] is None else str(row[0]),
            hash_state=str(row[1]),
            filename_tokens_json=str(row[2]),
            language_hints_json=str(row[3]),
            image_fingerprints=successes,
            image_failures=failures,
            full_entry_positions=full_entry_positions,
        )

    def store_full_fingerprints(
        self,
        value: ArchiveAnalysisInput,
        *,
        analyzer_version: int,
        computed_at: datetime,
        successes: tuple[tuple[int, ImageFingerprint], ...],
        failures: tuple[tuple[int, str], ...],
        owner_token: str | None = None,
        now: datetime | Callable[[], datetime] | None = None,
    ) -> bool:
        """Atomically store complete-page coverage for one stable archive."""

        if not _snapshot_matches(value):
            return False
        expected_positions = {image.position for image in value.images}
        supplied_positions = {position for position, _ in successes} | {
            position for position, _ in failures
        }
        if supplied_positions != expected_positions or len(supplied_positions) != (
            len(successes) + len(failures)
        ):
            raise ValueError("FULL fingerprints must cover each indexed image exactly once.")
        previous_rows = ()
        try:
            with self._analysis_write_transaction(
                owner_token, now, immediate=True
            ):
                parent = self._connection.execute(
                    "SELECT 1 FROM archive_fingerprints WHERE archive_id = ? "
                    "AND file_size = ? AND mtime_ns = ? AND analyzer_version = ?",
                    (value.archive_id, value.file_size, value.mtime_ns, analyzer_version),
                ).fetchone()
                if parent is None:
                    return False
                previous_rows = tuple(
                    self._connection.execute(
                        "SELECT archive_id, entry_position, coverage, byte_sha256, pixel_sha256, "
                        "dhash64, ahash64, width, height, state, error_code, analyzer_version, "
                        "computed_at FROM image_fingerprints WHERE archive_id = ? "
                        "AND analyzer_version = ? ORDER BY entry_position",
                        (value.archive_id, analyzer_version),
                    ).fetchall()
                )
                for entry_position, fingerprint in successes:
                    self._upsert_image_fingerprint(
                        value,
                        entry_position=entry_position,
                        coverage="FULL",
                        analyzer_version=analyzer_version,
                        computed_at=computed_at,
                        fingerprint=fingerprint,
                    )
                for entry_position, error_code in failures:
                    self._upsert_image_fingerprint(
                        value,
                        entry_position=entry_position,
                        coverage="FULL",
                        analyzer_version=analyzer_version,
                        computed_at=computed_at,
                        error_code=error_code,
                    )
                _require_current_snapshot(value)
        except _SnapshotChanged:
            return False
        if _snapshot_matches(value):
            return True
        with self._analysis_write_transaction(owner_token, now, immediate=True):
            parent = self._connection.execute(
                "SELECT 1 FROM archive_fingerprints WHERE archive_id = ? "
                "AND file_size = ? AND mtime_ns = ? AND analyzer_version = ?",
                (value.archive_id, value.file_size, value.mtime_ns, analyzer_version),
            ).fetchone()
            current_rows = self._connection.execute(
                "SELECT entry_position, computed_at FROM image_fingerprints "
                "WHERE archive_id = ? AND analyzer_version = ?",
                (value.archive_id, analyzer_version),
            ).fetchall()
            if parent is None or {
                int(position) for position, computed_at_value in current_rows
                if str(computed_at_value) == computed_at.isoformat()
            } != supplied_positions:
                return False
            self._connection.execute(
                "DELETE FROM image_fingerprints WHERE archive_id = ? AND analyzer_version = ?",
                (value.archive_id, analyzer_version),
            )
            self._connection.executemany(
                "INSERT INTO image_fingerprints("
                "archive_id, entry_position, coverage, byte_sha256, pixel_sha256, dhash64, "
                "ahash64, width, height, state, error_code, analyzer_version, computed_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                previous_rows,
            )
        return False

    def store_filename_evidence(
        self,
        value: ArchiveAnalysisInput,
        *,
        analyzer_version: int,
        filename_tokens: frozenset[str],
        language_hints: frozenset[str],
        owner_token: str | None = None,
        now: datetime | Callable[[], datetime] | None = None,
    ) -> bool:
        """Store supporting filename evidence without replacing fingerprint state.

        This intentionally uses the same snapshot/version boundary as the
        fingerprint cache.  It does not upsert an archive row: creating or
        replacing one here could discard a SHA result or its probe cache.
        """

        if not _snapshot_matches(value):
            return False
        tokens_json = _stable_json(filename_tokens)
        hints_json = _stable_json(language_hints)
        previous: tuple[str, str] | None = None
        try:
            with self._analysis_write_transaction(owner_token, now):
                row = self._connection.execute(
                    "SELECT filename_tokens_json, language_hints_json FROM archive_fingerprints "
                    "WHERE archive_id = ? AND file_size = ? AND mtime_ns = ? "
                    "AND analyzer_version = ?",
                    (value.archive_id, value.file_size, value.mtime_ns, analyzer_version),
                ).fetchone()
                previous = None if row is None else (str(row[0]), str(row[1]))
                cursor = self._connection.execute(
                    "UPDATE archive_fingerprints SET filename_tokens_json = ?, "
                    "language_hints_json = ? WHERE archive_id = ? AND file_size = ? "
                    "AND mtime_ns = ? AND analyzer_version = ?",
                    (
                        tokens_json,
                        hints_json,
                        value.archive_id,
                        value.file_size,
                        value.mtime_ns,
                        analyzer_version,
                    ),
                )
                _require_current_snapshot(value)
        except _SnapshotChanged:
            return False
        if cursor.rowcount != 1:
            return False
        if _snapshot_matches(value):
            return True
        if previous is not None:
            with self._analysis_write_transaction(owner_token, now):
                self._connection.execute(
                    "UPDATE archive_fingerprints SET filename_tokens_json = ?, "
                    "language_hints_json = ? WHERE archive_id = ? AND file_size = ? "
                    "AND mtime_ns = ? AND analyzer_version = ? AND filename_tokens_json = ? "
                    "AND language_hints_json = ?",
                    (
                        previous[0],
                        previous[1],
                        value.archive_id,
                        value.file_size,
                        value.mtime_ns,
                        analyzer_version,
                        tokens_json,
                        hints_json,
                    ),
                )
        return False

    def load_candidate_evidence(
        self,
        root_id: int,
        *,
        analyzer_version: int,
        checkpoint: Callable[[], None] | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> tuple[ArchiveEvidence, ...]:
        """Load only current, same-root/version fingerprint cache rows.

        Candidate services must use this method rather than raw fingerprint SQL.
        The caller holds the duplicate-operation lock while loading. After
        materializing rows, this loader walks them in reverse order and, for
        each item, re-reads joined DB identity and immediately stats its source.
        Each DB query sees SQLite's committed state at that query. External
        files have no cross-process lock: a source changed after its final
        reverse-pass stat needs a later caller-side recheck before mutation
        (analysis itself is read-only; V5 quarantine performs that recheck).
        """

        values: list[tuple[ArchiveAnalysisInput, ArchiveEvidence]] = []
        total = self.analysis_input_counts(root_id)[0] if progress_callback else 0
        inputs = (
            value for batch in self.iter_analysis_input_batches(root_id, checkpoint=checkpoint)
            for value in batch
        )
        for value in track_progress(
            inputs, total, stage=AnalysisStage.CANDIDATE_BUILD,
            phase="비교 자료 읽기", callback=progress_callback,
        ):
            _run_checkpoint(checkpoint)
            cached = self.cached_fingerprints(value, analyzer_version)
            if cached is None or not _snapshot_matches(value):
                continue
            tokens = _json_string_set(cached.filename_tokens_json)
            if tokens is None or _json_string_set(cached.language_hints_json) is None:
                continue
            selected_positions = probe_positions(
                tuple(image.position for image in value.images)
            )
            slots_by_position = {
                position: slot for slot, position in enumerate(selected_positions)
            }
            probes = tuple(
                ProbeFingerprint(
                    slot=slots_by_position[item.entry_position],
                    entry_position=item.entry_position,
                    byte_sha256=item.fingerprint.byte_sha256,
                    pixel_sha256=item.fingerprint.pixel_sha256,
                    dhash64=item.fingerprint.dhash64,
                    ahash64=item.fingerprint.ahash64,
                    width=item.fingerprint.width,
                    height=item.fingerprint.height,
                )
                for item in cached.image_fingerprints
                if item.entry_position in slots_by_position
            )
            if not _snapshot_matches(value):
                continue
            from archive_analyzer.filename_normalization import dated_series_identity
            series_key, series_date, series_versioned = dated_series_identity(value.path)
            values.append(
                (
                    replace(value, images=()),
                    ArchiveEvidence(
                        archive_id=value.archive_id,
                        file_sha256=cached.sha256,
                        probes=probes,
                        filename_tokens=tokens,
                        scan_root_id=root_id,
                        file_size=value.file_size,
                        mtime_ns=value.mtime_ns,
                        analyzer_version=analyzer_version,
                        series_key=series_key,
                        series_date=series_date,
                        series_versioned=series_versioned,
                    ),
                )
            )
        values = self._final_reverse_candidate_validation(
            values, root_id, analyzer_version, checkpoint=checkpoint,
            progress_callback=progress_callback,
        )
        return tuple(evidence for _, evidence in values)

    def _final_reverse_candidate_validation(
        self,
        values: list[tuple[ArchiveAnalysisInput, ArchiveEvidence]],
        root_id: int,
        analyzer_version: int,
        *,
        checkpoint: Callable[[], None] | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> list[tuple[ArchiveAnalysisInput, ArchiveEvidence]]:
        """Bind each final DB identity check to its source stat, newest item first."""

        validated: list[tuple[ArchiveAnalysisInput, ArchiveEvidence]] = []
        for value, evidence in track_progress(
            reversed(values), len(values), stage=AnalysisStage.CANDIDATE_BUILD,
            phase="비교 자료 유효성 확인", callback=progress_callback,
        ):
            _run_checkpoint(checkpoint)
            if not self._candidate_database_identity_matches(value, root_id, analyzer_version):
                continue
            if _snapshot_matches(value):
                validated.append((value, evidence))
        validated.reverse()
        return validated

    def _candidate_database_identity_matches(
        self, value: ArchiveAnalysisInput, root_id: int, analyzer_version: int
    ) -> bool:
        row = self._connection.execute(
            "SELECT a.scan_root_id, a.file_size, a.mtime_ns, a.state, "
            "f.file_size, f.mtime_ns, f.analyzer_version "
            "FROM archives AS a JOIN archive_fingerprints AS f ON f.archive_id = a.id "
            "WHERE a.id = ?",
            (value.archive_id,),
        ).fetchone()
        if row is None:
            return False
        db_root_id, file_size, mtime_ns, state, fp_size, fp_mtime_ns, version = row
        return (
            int(db_root_id) == root_id
            and str(state) == "INDEXED"
            and int(file_size) == value.file_size
            and int(mtime_ns) == value.mtime_ns
            and int(fp_size) == value.file_size
            and int(fp_mtime_ns) == value.mtime_ns
            and int(version) == analyzer_version
        )


    def promote_image_fingerprint(
        self,
        value: ArchiveAnalysisInput,
        *,
        entry_position: int,
        analyzer_version: int,
        computed_at: datetime,
        owner_token: str | None = None,
        now: datetime | Callable[[], datetime] | None = None,
    ) -> bool:
        if not _snapshot_matches(value):
            return False
        try:
            with self._analysis_write_transaction(owner_token, now):
                cursor = self._connection.execute(
                    "UPDATE image_fingerprints SET coverage = 'FULL', computed_at = ? "
                    "WHERE archive_id = ? AND entry_position = ? AND analyzer_version = ? "
                    "AND coverage = 'PROBE' AND state = 'SUCCEEDED' "
                    "AND EXISTS ("
                    "SELECT 1 FROM archive_fingerprints WHERE archive_id = ? "
                    "AND file_size = ? AND mtime_ns = ? AND analyzer_version = ?"
                    ")",
                    (
                        computed_at.isoformat(),
                        value.archive_id,
                        entry_position,
                        analyzer_version,
                        value.archive_id,
                        value.file_size,
                        value.mtime_ns,
                        analyzer_version,
                    ),
                )
                _require_current_snapshot(value)
        except _SnapshotChanged:
            return False
        if cursor.rowcount != 1:
            return False
        if _snapshot_matches(value):
            return True
        with self._analysis_write_transaction(owner_token, now):
            self._connection.execute(
                "UPDATE image_fingerprints SET coverage = 'PROBE' "
                "WHERE archive_id = ? AND entry_position = ? AND analyzer_version = ? "
                "AND coverage = 'FULL' AND state = 'SUCCEEDED' AND computed_at = ? "
                "AND EXISTS ("
                "SELECT 1 FROM archive_fingerprints WHERE archive_id = ? "
                "AND file_size = ? AND mtime_ns = ? AND analyzer_version = ?"
                ")",
                (
                    value.archive_id,
                    entry_position,
                    analyzer_version,
                    computed_at.isoformat(),
                    value.archive_id,
                    value.file_size,
                    value.mtime_ns,
                    analyzer_version,
                ),
            )
        return False

    def _delete_stale_snapshot_rows(
        self, value: ArchiveAnalysisInput, analyzer_version: int
    ) -> None:
        row = self._connection.execute(
            "SELECT file_size, mtime_ns, analyzer_version FROM archive_fingerprints "
            "WHERE archive_id = ?",
            (value.archive_id,),
        ).fetchone()
        if row is None:
            self._connection.execute(
                "DELETE FROM image_fingerprints WHERE archive_id = ?", (value.archive_id,)
            )
            return
        if (int(row[0]), int(row[1]), int(row[2])) == (
            value.file_size,
            value.mtime_ns,
            analyzer_version,
        ):
            return
        self._connection.execute(
            "DELETE FROM image_fingerprints WHERE archive_id = ?", (value.archive_id,)
        )
        self._connection.execute(
            "DELETE FROM archive_fingerprints WHERE archive_id = ?", (value.archive_id,)
        )

    def _upsert_archive_fingerprint(
        self,
        value: ArchiveAnalysisInput,
        analyzer_version: int,
        computed_at: datetime,
        sha256: str | None,
        hash_state: str,
        error_code: str | None,
        *,
        preserve_hash_result: bool = False,
    ) -> None:
        if hash_state not in {"NOT_REQUIRED", "SUCCEEDED", "FAILED"}:
            raise ValueError("Unsupported archive hash state.")
        self._connection.execute(
            "INSERT INTO archive_fingerprints("
            "archive_id, file_size, mtime_ns, sha256, hash_state, filename_tokens_json, "
            "language_hints_json, analyzer_version, computed_at, error_code"
            ") VALUES (?, ?, ?, ?, ?, '[]', '[]', ?, ?, ?) "
            "ON CONFLICT(archive_id) DO UPDATE SET "
            "file_size = excluded.file_size, mtime_ns = excluded.mtime_ns, "
            "sha256 = CASE WHEN ? THEN archive_fingerprints.sha256 "
            "ELSE COALESCE(excluded.sha256, archive_fingerprints.sha256) END, "
            "hash_state = CASE "
            "WHEN ? THEN archive_fingerprints.hash_state "
            "WHEN excluded.hash_state = 'NOT_REQUIRED' "
            "AND archive_fingerprints.sha256 IS NOT NULL THEN archive_fingerprints.hash_state "
            "ELSE excluded.hash_state END, "
            "analyzer_version = excluded.analyzer_version, computed_at = excluded.computed_at, "
            "error_code = CASE WHEN ? THEN archive_fingerprints.error_code "
            "ELSE excluded.error_code END",
            (
                value.archive_id,
                value.file_size,
                value.mtime_ns,
                sha256,
                hash_state,
                analyzer_version,
                computed_at.isoformat(),
                error_code,
                preserve_hash_result,
                preserve_hash_result,
                preserve_hash_result,
            ),
        )

    def _upsert_image_fingerprint(
        self,
        value: ArchiveAnalysisInput,
        *,
        entry_position: int,
        coverage: str,
        analyzer_version: int,
        computed_at: datetime,
        fingerprint: ImageFingerprint | None = None,
        error_code: str | None = None,
    ) -> None:
        self._connection.execute(
            "INSERT INTO image_fingerprints("
            "archive_id, entry_position, coverage, byte_sha256, pixel_sha256, dhash64, ahash64, "
            "width, height, state, error_code, analyzer_version, computed_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(archive_id, entry_position, analyzer_version) DO UPDATE SET "
            "coverage = CASE WHEN image_fingerprints.coverage = 'FULL' THEN 'FULL' "
            "ELSE excluded.coverage END, "
            "byte_sha256 = COALESCE(excluded.byte_sha256, image_fingerprints.byte_sha256), "
            "pixel_sha256 = COALESCE(excluded.pixel_sha256, image_fingerprints.pixel_sha256), "
            "dhash64 = COALESCE(excluded.dhash64, image_fingerprints.dhash64), "
            "ahash64 = COALESCE(excluded.ahash64, image_fingerprints.ahash64), "
            "width = COALESCE(excluded.width, image_fingerprints.width), "
            "height = COALESCE(excluded.height, image_fingerprints.height), "
            "state = excluded.state, error_code = excluded.error_code, "
            "computed_at = excluded.computed_at",
            (
                value.archive_id,
                entry_position,
                coverage,
                None if fingerprint is None else fingerprint.byte_sha256,
                None if fingerprint is None else fingerprint.pixel_sha256,
                None if fingerprint is None else fingerprint.dhash64,
                None if fingerprint is None else fingerprint.ahash64,
                None if fingerprint is None else fingerprint.width,
                None if fingerprint is None else fingerprint.height,
                "SUCCEEDED" if fingerprint is not None else "FAILED",
                error_code,
                analyzer_version,
                computed_at.isoformat(),
            ),
        )

    def replace_candidate_relations(
        self,
        root_id: int,
        *,
        analyzer_version: int,
        matches: tuple[CandidateMatch, ...],
        created_at: datetime,
        owner_token: str | None = None,
        now: datetime | Callable[[], datetime] | None = None,
    ) -> None:
        """Atomically replace one root/version's automatic relation graph.

        Review actions intentionally live outside this replacement boundary.
        Rebuilding groups in the same transaction means a completed analysis
        never exposes new edges with members from the previous graph.
        """

        normalized = tuple(matches)
        with self._analysis_write_transaction(owner_token, now, immediate=True):
            self._validate_relation_matches(root_id, normalized)
            self._connection.execute(
                "DELETE FROM candidate_relations WHERE scan_root_id = ? AND analyzer_version = ?",
                (root_id, analyzer_version),
            )
            self._connection.executemany(
                "INSERT INTO candidate_relations("
                "scan_root_id, archive_a_id, archive_b_id, relation, confidence, matched_pages, "
                "left_pages, right_pages, recommendation, evidence_json, analyzer_version, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(
                    (
                        root_id,
                        match.archive_a_id,
                        match.archive_b_id,
                        match.relation.value,
                        match.confidence,
                        match.matched_pages,
                        match.left_pages,
                        match.right_pages,
                        match.recommendation,
                        _stable_json_strings(match.reasons),
                        analyzer_version,
                        created_at.isoformat(),
                    )
                    for match in normalized
                ),
            )
            self._rebuild_candidate_groups_in_transaction(root_id, analyzer_version, created_at)

    def rebuild_candidate_groups(
        self,
        root_id: int,
        analyzer_version: int,
        created_at: datetime,
        *,
        owner_token: str | None = None,
        now: datetime | Callable[[], datetime] | None = None,
    ) -> tuple[CandidateGroupSummary, ...]:
        """Rebuild UI groups from the saved edge graph without pair expansion."""

        with self._analysis_write_transaction(owner_token, now, immediate=True):
            self._rebuild_candidate_groups_in_transaction(root_id, analyzer_version, created_at)
        return self.group_summaries(root_id)

    def group_summaries(self, root_id: int) -> tuple[CandidateGroupSummary, ...]:
        rows = self._connection.execute(
            "WITH current_members AS ("
            "SELECT g.id AS group_id, g.group_key, a.id AS archive_id, a.file_size, a.mtime_ns "
            "FROM candidate_groups AS g "
            "JOIN candidate_group_members AS member ON member.group_id = g.id "
            "JOIN archives AS a ON a.id = member.archive_id "
            "WHERE g.scan_root_id = ?"
            "), latest_actions AS ("
            "SELECT action.archive_id, action.group_key, action.file_size, action.mtime_ns, "
            "ROW_NUMBER() OVER (PARTITION BY action.archive_id ORDER BY action.id DESC) AS row_number "
            "FROM review_actions AS action "
            "JOIN (SELECT DISTINCT archive_id FROM current_members) AS member_ids "
            "ON member_ids.archive_id = action.archive_id"
            "), member_status AS ("
            "SELECT current_members.group_id, current_members.group_key, "
            "CASE WHEN latest_actions.archive_id IS NULL THEN 0 ELSE 1 END AS has_action, "
            "CASE WHEN latest_actions.group_key = current_members.group_key "
            "AND latest_actions.file_size = current_members.file_size "
            "AND latest_actions.mtime_ns = current_members.mtime_ns THEN 1 ELSE 0 END AS is_current "
            "FROM current_members LEFT JOIN latest_actions "
            "ON latest_actions.archive_id = current_members.archive_id "
            "AND latest_actions.row_number = 1"
            ") "
            "SELECT g.group_key, g.strongest_relation, g.confidence, g.analyzer_version, "
            "COUNT(member_status.group_id), MAX(member_status.has_action) "
            "AND NOT MIN(member_status.is_current) "
            "FROM candidate_groups AS g JOIN member_status ON member_status.group_id = g.id "
            "GROUP BY g.id ORDER BY g.group_key",
            (root_id,),
        ).fetchall()
        return tuple(
            CandidateGroupSummary(
                group_key=str(group_key),
                member_count=int(member_count),
                strongest_relation=DuplicateRelation(str(strongest_relation)),
                confidence=float(confidence),
                analyzer_version=int(analyzer_version),
                needs_review=bool(needs_review),
            )
            for group_key, strongest_relation, confidence, analyzer_version, member_count, needs_review in rows
        )

    def review_group_details(self, set_key: str) -> ReviewGroupDetail | None:
        """Load one current derived set without widening it to its source group."""

        with _read_snapshot(self._connection):
            candidate = self._connection.execute(
                "SELECT candidate.source_group_key, candidate.edition_kind, candidate.member_ids_json, "
                "groups.id, groups.scan_root_id, groups.analyzer_version "
                "FROM edition_candidate_sets AS candidate JOIN candidate_groups AS groups "
                "ON groups.group_key = candidate.source_group_key "
                "AND groups.scan_root_id = candidate.scan_root_id WHERE candidate.set_key = ?",
                (set_key,),
            ).fetchone()
            if candidate is None:
                return None
            source_group_key, edition_kind, member_ids_json, group_id, root_id, analyzer_version = candidate
            member_ids = _json_ints(str(member_ids_json))
            try:
                kind = EditionKind(str(edition_kind))
            except ValueError:
                return None
            if member_ids is None or not member_ids:
                return None
            if set_key not in {
                candidate_set.set_key
                for candidate_set in self.review_candidate_sets_for_keys((set_key,))
            }:
                return None
            current_ids = {
                int(row[0])
                for row in self._connection.execute(
                    "SELECT archive_id FROM candidate_group_members WHERE group_id = ?",
                    (int(group_id),),
                )
            }
            if not set(member_ids) <= current_ids:
                return None

            member_rows: list[tuple[object, ...]] = []
            image_rows: list[tuple[object, ...]] = []
            relation_rows: list[tuple[object, ...]] = []
            for start in range(0, len(member_ids), _ARCHIVE_VALIDATION_CHUNK_SIZE):
                chunk = member_ids[start : start + _ARCHIVE_VALIDATION_CHUNK_SIZE]
                placeholders = ",".join("?" for _ in chunk)
                selected_ids = ",".join("(?)" for _ in chunk)
                member_rows.extend(self._connection.execute(
                    "WITH selected_ids(archive_id) AS (VALUES " + selected_ids + "), latest_actions AS ("
                    "SELECT action.id, action.archive_id, action.group_key, action.action, "
                    "action.file_size, action.mtime_ns, "
                    "ROW_NUMBER() OVER (PARTITION BY action.archive_id ORDER BY action.id DESC) AS row_number "
                    "FROM review_actions AS action JOIN selected_ids "
                    "ON selected_ids.archive_id = action.archive_id WHERE action.group_key = ?"
                    ") "
                    "SELECT archive.id, archive.path, archive.file_size, archive.mtime_ns, archive.archive_format, "
                    "archive.image_count, latest_actions.id, latest_actions.group_key, latest_actions.action, "
                    "latest_actions.file_size, latest_actions.mtime_ns, quarantine.id, quarantine.status, "
                    "quarantine.destination_path, deletion.state, "
                    "(SELECT evidence.language_json FROM filename_evidence AS evidence "
                    "WHERE evidence.archive_id = archive.id AND evidence.file_size = archive.file_size "
                    "AND evidence.mtime_ns = archive.mtime_ns AND evidence.path_key = archive.path_key "
                    "AND evidence.algorithm_version = 2), "
                    "(SELECT evidence.color_json FROM filename_evidence AS evidence "
                    "WHERE evidence.archive_id = archive.id AND evidence.file_size = archive.file_size "
                    "AND evidence.mtime_ns = archive.mtime_ns AND evidence.path_key = archive.path_key "
                    "AND evidence.algorithm_version = 2), "
                    "(SELECT evidence.mosaic_json FROM filename_evidence AS evidence "
                    "WHERE evidence.archive_id = archive.id AND evidence.file_size = archive.file_size "
                    "AND evidence.mtime_ns = archive.mtime_ns AND evidence.path_key = archive.path_key "
                    "AND evidence.algorithm_version = 2), "
                    "(SELECT precision.language FROM precision_profiles AS precision "
                    "WHERE precision.archive_id = archive.id AND precision.file_size = archive.file_size "
                    "AND precision.mtime_ns = archive.mtime_ns AND precision.state = 'SUCCEEDED' "
                    "ORDER BY precision.algorithm_version DESC LIMIT 1), "
                    "(SELECT precision.language_confidence FROM precision_profiles AS precision "
                    "WHERE precision.archive_id = archive.id AND precision.file_size = archive.file_size "
                    "AND precision.mtime_ns = archive.mtime_ns AND precision.state = 'SUCCEEDED' "
                    "ORDER BY precision.algorithm_version DESC LIMIT 1), "
                    "(SELECT profile.color_page_ratio FROM edition_profiles AS profile "
                    "WHERE profile.archive_id = archive.id AND profile.file_size = archive.file_size "
                    "AND profile.mtime_ns = archive.mtime_ns AND profile.state = 'SUCCEEDED' "
                    "ORDER BY profile.algorithm_version DESC LIMIT 1), "
                    "(SELECT item.reason FROM recommendation_applications AS application "
                    "JOIN recommendation_items AS item ON item.id = application.recommendation_item_id "
                    "WHERE application.review_action_id = latest_actions.id) FROM archives AS archive "
                    "LEFT JOIN latest_actions ON latest_actions.archive_id = archive.id "
                    "AND latest_actions.row_number = 1 "
                    "LEFT JOIN quarantine_items AS quarantine ON quarantine.id = ("
                    "SELECT latest_quarantine.id FROM quarantine_items AS latest_quarantine "
                    "WHERE latest_quarantine.archive_id = archive.id ORDER BY latest_quarantine.id DESC LIMIT 1) "
                    "LEFT JOIN deletion_records AS deletion ON deletion.quarantine_item_id = quarantine.id "
                    "JOIN selected_ids ON selected_ids.archive_id = archive.id "
                    "WHERE archive.scan_root_id = ? ORDER BY archive.id",
                    (*chunk, str(source_group_key), int(root_id)),
                ).fetchall())
                image_rows.extend(self._connection.execute(
                    "SELECT archive_id, entry_position, width, height FROM image_fingerprints "
                    f"WHERE archive_id IN ({placeholders}) AND analyzer_version = ? AND state = 'SUCCEEDED' "
                    "AND width IS NOT NULL AND height IS NOT NULL "
                    "ORDER BY archive_id, width * height, entry_position",
                    (*chunk, int(analyzer_version)),
                ).fetchall())
                relation_rows.extend(self._connection.execute(
                    "SELECT relation.archive_a_id, relation.archive_b_id, relation.relation, relation.confidence, "
                    "relation.matched_pages, relation.left_pages, relation.right_pages, relation.recommendation, "
                    "relation.evidence_json, sequence.relation, sequence.container_archive_id, "
                    "sequence.matched_pairs_json, sequence.left_coverage, sequence.right_coverage, "
                    "edition.flags_json, edition.summary, edition.preserve_required "
                    "FROM candidate_relations AS relation "
                    "LEFT JOIN sequence_relations AS sequence ON sequence.archive_a_id = relation.archive_a_id "
                    "AND sequence.archive_b_id = relation.archive_b_id AND sequence.algorithm_version = 1 "
                    "AND sequence.relation != 'NONE' "
                    "AND sequence.left_file_size = (SELECT file_size FROM archives WHERE id = relation.archive_a_id) "
                    "AND sequence.left_mtime_ns = (SELECT mtime_ns FROM archives WHERE id = relation.archive_a_id) "
                    "AND sequence.right_file_size = (SELECT file_size FROM archives WHERE id = relation.archive_b_id) "
                    "AND sequence.right_mtime_ns = (SELECT mtime_ns FROM archives WHERE id = relation.archive_b_id) "
                    "LEFT JOIN edition_relations AS edition ON edition.archive_a_id = relation.archive_a_id "
                    "AND edition.archive_b_id = relation.archive_b_id AND edition.algorithm_version = 1 "
                    "AND edition.left_file_size = (SELECT file_size FROM archives WHERE id = relation.archive_a_id) "
                    "AND edition.left_mtime_ns = (SELECT mtime_ns FROM archives WHERE id = relation.archive_a_id) "
                    "AND edition.right_file_size = (SELECT file_size FROM archives WHERE id = relation.archive_b_id) "
                    "AND edition.right_mtime_ns = (SELECT mtime_ns FROM archives WHERE id = relation.archive_b_id) "
                    f"WHERE relation.scan_root_id = ? AND relation.analyzer_version = ? AND relation.archive_a_id IN ({placeholders}) "
                    "ORDER BY relation.archive_a_id, relation.archive_b_id",
                    (int(root_id), int(analyzer_version), *chunk),
                ).fetchall())

        if {int(row[0]) for row in member_rows} != set(member_ids):
            return None
        member_rows.sort(key=lambda row: int(row[0]))
        representative_dimensions = _representative_dimensions(image_rows)
        members = tuple(
            CandidateGroupMember(
                archive_id=int(archive_id), path=Path(str(path)), file_size=int(file_size),
                mtime_ns=int(mtime_ns), archive_format=ArchiveFormat(str(archive_format)),
                review_action=(ReviewAction(str(latest_action)) if latest_action_id is not None
                               and (int(action_size), int(action_mtime_ns)) == (int(file_size), int(mtime_ns))
                               else None),
                needs_review=(latest_action_id is not None and (
                    (int(action_size), int(action_mtime_ns)) != (int(file_size), int(mtime_ns))
                )),
                image_count=None if image_count is None else int(image_count),
                representative_width=representative_dimensions.get(int(archive_id), (None, None))[0],
                representative_height=representative_dimensions.get(int(archive_id), (None, None))[1],
                quarantine_item_id=None if quarantine_item_id is None else int(quarantine_item_id),
                quarantine_status=None if quarantine_status is None else str(quarantine_status),
                quarantine_path=None if quarantine_path is None else Path(str(quarantine_path)),
                deletion_state=None if deletion_state is None else str(deletion_state),
                filename_language=(
                    None if filename_language is None else _filename_signal_from_json(str(filename_language))
                ),
                filename_color=(
                    None if filename_color is None else _filename_signal_from_json(str(filename_color))
                ),
                filename_mosaic=(
                    None if filename_mosaic is None else _filename_signal_from_json(str(filename_mosaic))
                ),
                precision_language=None if precision_language is None else str(precision_language),
                precision_language_confidence=(
                    None if precision_confidence is None else float(precision_confidence)
                ),
                color_page_ratio=None if color_ratio is None else float(color_ratio),
                review_recommendation_reason=None if review_reason is None else str(review_reason),
            )
            for (
                archive_id, path, file_size, mtime_ns, archive_format, image_count,
                latest_action_id, action_group_key, latest_action, action_size, action_mtime_ns,
                quarantine_item_id, quarantine_status, quarantine_path, deletion_state,
                filename_language, filename_color, filename_mosaic, precision_language,
                precision_confidence, color_ratio, review_reason,
            ) in member_rows
        )
        wanted_ids = set(member_ids)
        relations = tuple(
            _candidate_relation_record(row)
            for row in relation_rows
            if int(row[0]) in wanted_ids and int(row[1]) in wanted_ids
        )
        records = tuple(
            record for record in self.latest_recommendations((set_key,))
            if record.source_group_key == str(source_group_key)
            and record.archive_id in wanted_ids
            and any((member.archive_id, member.file_size, member.mtime_ns) ==
                    (record.archive_id, record.file_size, record.mtime_ns) for member in members)
        )
        recommendation_status = (
            next(iter({record.status for record in records}))
            if len(records) == len(members) and len({record.status for record in records}) == 1
            else "UNKNOWN"
        )
        return ReviewGroupDetail(
            set_key=set_key,
            source_group_key=str(source_group_key),
            edition_kind=kind,
            members=members,
            relations=relations,
            recommendation_status=recommendation_status,
            recommendations=records,
            precision_relations=self._recommendation_precision_relations(
                int(root_id), tuple(member.archive_id for member in members)
            ),
        )

    def group_details(self, group_key: str) -> CandidateGroupDetail | None:
        with _read_snapshot(self._connection):
            group = self._connection.execute(
                "SELECT id, strongest_relation, confidence, analyzer_version FROM candidate_groups "
                "WHERE group_key = ?",
                (group_key,),
            ).fetchone()
            if group is None:
                return None
            group_id, strongest_relation, confidence, analyzer_version = group
            member_rows = self._connection.execute(
                "WITH latest_actions AS ("
                "SELECT action.id, action.archive_id, action.group_key, action.action, "
                "action.file_size, action.mtime_ns, "
                "ROW_NUMBER() OVER (PARTITION BY action.archive_id ORDER BY action.id DESC) AS row_number "
                "FROM review_actions AS action "
                "JOIN candidate_group_members AS member ON member.archive_id = action.archive_id "
                "WHERE member.group_id = ?"
                ") "
                "SELECT a.id, a.path, a.file_size, a.mtime_ns, a.archive_format, a.image_count, "
                "latest_actions.id, latest_actions.group_key, latest_actions.action, "
                "latest_actions.file_size, latest_actions.mtime_ns, quarantine.id, "
                "quarantine.status, quarantine.destination_path, deletion.state, "
                "(SELECT evidence.language_json FROM filename_evidence AS evidence "
                "WHERE evidence.archive_id = a.id AND evidence.file_size = a.file_size "
                "AND evidence.mtime_ns = a.mtime_ns AND evidence.path_key = a.path_key "
                "AND evidence.algorithm_version = 2), "
                "(SELECT evidence.color_json FROM filename_evidence AS evidence "
                "WHERE evidence.archive_id = a.id AND evidence.file_size = a.file_size "
                "AND evidence.mtime_ns = a.mtime_ns AND evidence.path_key = a.path_key "
                "AND evidence.algorithm_version = 2), "
                "(SELECT evidence.mosaic_json FROM filename_evidence AS evidence "
                "WHERE evidence.archive_id = a.id AND evidence.file_size = a.file_size "
                "AND evidence.mtime_ns = a.mtime_ns AND evidence.path_key = a.path_key "
                "AND evidence.algorithm_version = 2), "
                "(SELECT precision.language FROM precision_profiles AS precision "
                "WHERE precision.archive_id = a.id AND precision.file_size = a.file_size "
                "AND precision.mtime_ns = a.mtime_ns AND precision.state = 'SUCCEEDED' "
                "ORDER BY precision.algorithm_version DESC LIMIT 1), "
                "(SELECT precision.language_confidence FROM precision_profiles AS precision "
                "WHERE precision.archive_id = a.id AND precision.file_size = a.file_size "
                "AND precision.mtime_ns = a.mtime_ns AND precision.state = 'SUCCEEDED' "
                "ORDER BY precision.algorithm_version DESC LIMIT 1), "
                "(SELECT profile.color_page_ratio FROM edition_profiles AS profile "
                "WHERE profile.archive_id = a.id AND profile.file_size = a.file_size "
                "AND profile.mtime_ns = a.mtime_ns AND profile.state = 'SUCCEEDED' "
                "ORDER BY profile.algorithm_version DESC LIMIT 1), "
                "(SELECT item.reason FROM recommendation_applications AS application "
                "JOIN recommendation_items AS item ON item.id = application.recommendation_item_id "
                "WHERE application.review_action_id = latest_actions.id) "
                "FROM candidate_group_members AS member JOIN archives AS a ON a.id = member.archive_id "
                "LEFT JOIN latest_actions ON latest_actions.archive_id = a.id "
                "AND latest_actions.row_number = 1 "
                "LEFT JOIN quarantine_items AS quarantine ON quarantine.id = ("
                "SELECT latest_quarantine.id FROM quarantine_items AS latest_quarantine "
                "WHERE latest_quarantine.archive_id = a.id ORDER BY latest_quarantine.id DESC LIMIT 1"
                ") "
                "LEFT JOIN deletion_records AS deletion "
                "ON deletion.quarantine_item_id = quarantine.id "
                "WHERE member.group_id = ? ORDER BY a.id",
                (group_id, group_id),
            ).fetchall()
            image_rows = self._connection.execute(
                "SELECT fingerprint.archive_id, fingerprint.entry_position, fingerprint.width, fingerprint.height "
                "FROM image_fingerprints AS fingerprint "
                "JOIN candidate_group_members AS member ON member.archive_id = fingerprint.archive_id "
                "WHERE member.group_id = ? AND fingerprint.analyzer_version = ? "
                "AND fingerprint.state = 'SUCCEEDED' "
                "AND fingerprint.width IS NOT NULL AND fingerprint.height IS NOT NULL "
                "ORDER BY fingerprint.archive_id, fingerprint.width * fingerprint.height, fingerprint.entry_position",
                (group_id, analyzer_version),
            ).fetchall()
            relation_rows = self._connection.execute(
                "SELECT relation.archive_a_id, relation.archive_b_id, relation.relation, relation.confidence, "
                "relation.matched_pages, relation.left_pages, relation.right_pages, relation.recommendation, "
                "relation.evidence_json, sequence.relation, sequence.container_archive_id, "
                "sequence.matched_pairs_json, sequence.left_coverage, sequence.right_coverage, "
                "edition.flags_json, edition.summary, edition.preserve_required "
                "FROM candidate_group_members AS left_member "
                "CROSS JOIN candidate_relations AS relation "
                "INDEXED BY sqlite_autoindex_candidate_relations_1 "
                "JOIN candidate_group_members AS right_member "
                "ON right_member.group_id = ? AND right_member.archive_id = relation.archive_b_id "
                "LEFT JOIN sequence_relations AS sequence "
                "ON sequence.archive_a_id = relation.archive_a_id "
                "AND sequence.archive_b_id = relation.archive_b_id "
                "AND sequence.algorithm_version = 1 "
                "AND sequence.relation != 'NONE' "
                "AND sequence.left_file_size = (SELECT file_size FROM archives WHERE id = relation.archive_a_id) "
                "AND sequence.left_mtime_ns = (SELECT mtime_ns FROM archives WHERE id = relation.archive_a_id) "
                "AND sequence.right_file_size = (SELECT file_size FROM archives WHERE id = relation.archive_b_id) "
                "AND sequence.right_mtime_ns = (SELECT mtime_ns FROM archives WHERE id = relation.archive_b_id) "
                "LEFT JOIN edition_relations AS edition "
                "ON edition.archive_a_id = relation.archive_a_id "
                "AND edition.archive_b_id = relation.archive_b_id "
                "AND edition.algorithm_version = 1 "
                "AND edition.left_file_size = (SELECT file_size FROM archives WHERE id = relation.archive_a_id) "
                "AND edition.left_mtime_ns = (SELECT mtime_ns FROM archives WHERE id = relation.archive_a_id) "
                "AND edition.right_file_size = (SELECT file_size FROM archives WHERE id = relation.archive_b_id) "
                "AND edition.right_mtime_ns = (SELECT mtime_ns FROM archives WHERE id = relation.archive_b_id) "
                "WHERE left_member.group_id = ? "
                "AND relation.archive_a_id = left_member.archive_id "
                "AND relation.scan_root_id = (SELECT scan_root_id FROM candidate_groups WHERE id = ?) "
                "AND relation.analyzer_version = ? ORDER BY relation.archive_a_id, relation.archive_b_id",
                (group_id, group_id, group_id, analyzer_version),
            ).fetchall()
        relations = tuple(
            CandidateRelationRecord(
                archive_a_id=int(archive_a_id),
                archive_b_id=int(archive_b_id),
                relation=DuplicateRelation(str(relation)),
                confidence=float(relation_confidence),
                matched_pages=int(matched_pages),
                left_pages=int(left_pages),
                right_pages=int(right_pages),
                recommendation=str(recommendation),
                reasons=_json_string_tuple(str(evidence_json)),
                sequence_relation=(
                    None
                    if sequence_relation is None
                    else SequenceRelation(str(sequence_relation))
                ),
                container_archive_id=(
                    None if container_archive_id is None else int(container_archive_id)
                ),
                matched_pairs=(
                    ()
                    if matched_pairs_json is None
                    else _json_int_pairs(str(matched_pairs_json))
                ),
                left_coverage=0.0 if left_coverage is None else float(left_coverage),
                right_coverage=0.0 if right_coverage is None else float(right_coverage),
                edition_flags=(
                    ()
                    if edition_flags_json is None
                    else tuple(
                        EditionFlag(value)
                        for value in _json_string_tuple(str(edition_flags_json))
                    )
                ),
                edition_summary=(
                    None if edition_summary is None else str(edition_summary)
                ),
                preserve_required=bool(preserve_required),
            )
            for (
                archive_a_id,
                archive_b_id,
                relation,
                relation_confidence,
                matched_pages,
                left_pages,
                right_pages,
                recommendation,
                evidence_json,
                sequence_relation,
                container_archive_id,
                matched_pairs_json,
                left_coverage,
                right_coverage,
                edition_flags_json,
                edition_summary,
                preserve_required,
            ) in relation_rows
        )
        representative_dimensions = _representative_dimensions(image_rows)
        members = tuple(
            CandidateGroupMember(
                archive_id=int(archive_id),
                path=Path(str(path)),
                file_size=int(file_size),
                mtime_ns=int(mtime_ns),
                archive_format=ArchiveFormat(str(archive_format)),
                review_action=(
                    ReviewAction(str(latest_action))
                    if latest_action_id is not None and str(action_group_key) == group_key
                    else None
                ),
                needs_review=(
                    latest_action_id is not None
                    and (
                        str(action_group_key) != group_key
                        or (int(action_size), int(action_mtime_ns))
                        != (int(file_size), int(mtime_ns))
                    )
                ),
                image_count=None if image_count is None else int(image_count),
                representative_width=representative_dimensions.get(int(archive_id), (None, None))[0],
                representative_height=representative_dimensions.get(int(archive_id), (None, None))[1],
                quarantine_item_id=(
                    None if quarantine_item_id is None else int(quarantine_item_id)
                ),
                quarantine_status=(
                    None if quarantine_status is None else str(quarantine_status)
                ),
                quarantine_path=(
                    None if quarantine_path is None else Path(str(quarantine_path))
                ),
                deletion_state=(
                    None if deletion_state is None else str(deletion_state)
                ),
                filename_language=(
                    None if filename_language is None else _filename_signal_from_json(str(filename_language))
                ),
                filename_color=(
                    None if filename_color is None else _filename_signal_from_json(str(filename_color))
                ),
                filename_mosaic=(
                    None if filename_mosaic is None else _filename_signal_from_json(str(filename_mosaic))
                ),
                precision_language=None if precision_language is None else str(precision_language),
                precision_language_confidence=(
                    None if precision_confidence is None else float(precision_confidence)
                ),
                color_page_ratio=None if color_ratio is None else float(color_ratio),
                review_recommendation_reason=None if review_reason is None else str(review_reason),
            )
            for (
                archive_id,
                path,
                file_size,
                mtime_ns,
                archive_format,
                image_count,
                latest_action_id,
                action_group_key,
                latest_action,
                action_size,
                action_mtime_ns,
                quarantine_item_id,
                quarantine_status,
                quarantine_path,
                deletion_state,
                filename_language,
                filename_color,
                filename_mosaic,
                precision_language,
                precision_confidence,
                color_ratio,
                review_reason,
            ) in member_rows
        )
        needs_review = bool(members) and any(
            member.review_action is not None or member.needs_review for member in members
        ) and any(member.needs_review or member.review_action is None for member in members)
        return CandidateGroupDetail(
            group_key=group_key,
            members=members,
            relations=relations,
            strongest_relation=DuplicateRelation(str(strongest_relation)),
            confidence=float(confidence),
            analyzer_version=int(analyzer_version),
            needs_review=needs_review,
            recommended_archive_id=None if needs_review else _recommended_archive_id(relations),
        )

    def latest_review_state(
        self,
        group_key: str,
        archive_id: int,
        *,
        current: FileSnapshot | None = None,
    ) -> ReviewState:
        row = self._connection.execute(
            "SELECT id, group_key, action, file_size, mtime_ns FROM review_actions "
            "WHERE archive_id = ? ORDER BY id DESC LIMIT 1",
            (archive_id,),
        ).fetchone()
        if row is None:
            return ReviewState(action=None, needs_review=False, action_id=None)
        action_id, action_group_key, action, reviewed_size, reviewed_mtime_ns = row
        if current is None:
            current_row = self._connection.execute(
                "SELECT file_size, mtime_ns FROM archives WHERE id = ?", (archive_id,)
            ).fetchone()
            needs_review = current_row is None or (
                int(current_row[0]), int(current_row[1])
            ) != (int(reviewed_size), int(reviewed_mtime_ns))
        else:
            needs_review = (current.size, current.mtime_ns) != (
                int(reviewed_size),
                int(reviewed_mtime_ns),
            )
        return ReviewState(
            action=ReviewAction(str(action)) if str(action_group_key) == group_key else None,
            needs_review=needs_review or str(action_group_key) != group_key,
            action_id=int(action_id),
        )

    def quarantine_candidate(
        self, group_key: str, archive_id: int
    ) -> QuarantineCandidate:
        row = self._connection.execute(
            "SELECT root.id, root.path, archive.path, archive.file_size, archive.mtime_ns, "
            "archive.archive_format, action.group_key, action.action, action.file_size, "
            "action.mtime_ns "
            "FROM candidate_groups AS groups "
            "JOIN scan_roots AS root ON root.id = groups.scan_root_id "
            "JOIN candidate_group_members AS member ON member.group_id = groups.id "
            "JOIN archives AS archive ON archive.id = member.archive_id "
            "LEFT JOIN review_actions AS action ON action.id = ("
            "SELECT latest.id FROM review_actions AS latest "
            "WHERE latest.archive_id = archive.id ORDER BY latest.id DESC LIMIT 1"
            ") WHERE groups.group_key = ? AND archive.id = ?",
            (group_key, archive_id),
        ).fetchone()
        if row is None:
            raise QuarantineEligibilityError("CANDIDATE_NOT_FOUND")
        (
            root_id,
            root_path,
            source_path,
            file_size,
            mtime_ns,
            archive_format,
            action_group_key,
            action,
            action_size,
            action_mtime,
        ) = row
        if (
            action != ReviewAction.REMOVE_CANDIDATE.value
            or action_group_key != group_key
            or action_size is None
            or (int(action_size), int(action_mtime))
            != (int(file_size), int(mtime_ns))
        ):
            raise QuarantineEligibilityError("REMOVE_CANDIDATE_REQUIRED")
        active = self._connection.execute(
            "SELECT 1 FROM quarantine_items WHERE archive_id = ? "
            "AND status IN ('PENDING','QUARANTINED','RESTORING') LIMIT 1",
            (archive_id,),
        ).fetchone()
        if active is not None:
            raise QuarantineEligibilityError("ACTIVE_QUARANTINE_EXISTS")
        return QuarantineCandidate(
            root_id=int(root_id),
            root_path=Path(str(root_path)),
            group_key=group_key,
            archive_id=archive_id,
            path=Path(str(source_path)),
            file_size=int(file_size),
            mtime_ns=int(mtime_ns),
            archive_format=ArchiveFormat(str(archive_format)),
        )

    def create_quarantine_item(
        self,
        candidate: QuarantineCandidate,
        destination_path: Path,
        created_at: datetime,
    ) -> QuarantineItem:
        with _immediate_transaction(self._connection):
            current = self.quarantine_candidate(
                candidate.group_key, candidate.archive_id
            )
            if current != candidate:
                raise QuarantineEligibilityError("CANDIDATE_CHANGED")
            item_id = self._connection.execute(
                "INSERT INTO quarantine_items("
                "scan_root_id, archive_id, group_key, source_path, destination_path, "
                "file_size, mtime_ns, status, created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)",
                (
                    candidate.root_id,
                    candidate.archive_id,
                    candidate.group_key,
                    str(candidate.path),
                    str(destination_path),
                    candidate.file_size,
                    candidate.mtime_ns,
                    created_at.isoformat(),
                    created_at.isoformat(),
                ),
            ).lastrowid
        assert item_id is not None
        item = self.quarantine_item(int(item_id))
        assert item is not None
        return item

    def quarantine_item(self, item_id: int) -> QuarantineItem | None:
        row = self._connection.execute(
            "SELECT id, scan_root_id, archive_id, group_key, source_path, destination_path, "
            "file_size, mtime_ns, sha256, status, error_code "
            "FROM quarantine_items WHERE id = ?",
            (item_id,),
        ).fetchone()
        return None if row is None else _quarantine_item(row)

    def active_quarantine_item(
        self, group_key: str, archive_id: int
    ) -> QuarantineItem | None:
        row = self._connection.execute(
            "SELECT id, scan_root_id, archive_id, group_key, source_path, destination_path, "
            "file_size, mtime_ns, sha256, status, error_code "
            "FROM quarantine_items WHERE group_key = ? AND archive_id = ? "
            "AND status IN ('PENDING','QUARANTINED','RESTORING') "
            "AND NOT EXISTS (SELECT 1 FROM deletion_records AS deletion "
            "WHERE deletion.quarantine_item_id = quarantine_items.id "
            "AND deletion.state IN ('PENDING','DELETED')) "
            "ORDER BY id DESC LIMIT 1",
            (group_key, archive_id),
        ).fetchone()
        return None if row is None else _quarantine_item(row)

    def active_quarantine_items(self, root_id: int) -> tuple[QuarantineItem, ...]:
        rows = self._connection.execute(
            "SELECT id, scan_root_id, archive_id, group_key, source_path, destination_path, "
            "file_size, mtime_ns, sha256, status, error_code "
            "FROM quarantine_items WHERE scan_root_id = ? "
            "AND status IN ('PENDING','QUARANTINED','RESTORING') "
            "AND NOT EXISTS (SELECT 1 FROM deletion_records AS deletion WHERE deletion.quarantine_item_id = quarantine_items.id) ORDER BY id",
            (root_id,),
        ).fetchall()
        return tuple(_quarantine_item(row) for row in rows)

    def update_quarantine_status(
        self,
        item_id: int,
        expected_status: str,
        status: str,
        updated_at: datetime,
        *,
        sha256_value: str | None = None,
        error_code: str | None = None,
    ) -> QuarantineItem:
        allowed = {"PENDING", "QUARANTINED", "RESTORING", "RESTORED", "FAILED"}
        if expected_status not in allowed or status not in allowed:
            raise ValueError("Unknown quarantine status.")
        with _immediate_transaction(self._connection):
            cursor = self._connection.execute(
                "UPDATE quarantine_items SET status = ?, sha256 = COALESCE(?, sha256), "
                "error_code = ?, updated_at = ? WHERE id = ? AND status = ?",
                (
                    status,
                    sha256_value,
                    error_code,
                    updated_at.isoformat(),
                    item_id,
                    expected_status,
                ),
            )
            if cursor.rowcount != 1:
                raise QuarantineEligibilityError("QUARANTINE_STATE_CHANGED")
        item = self.quarantine_item(item_id)
        assert item is not None
        return item

    def deletion_candidate(self, group_key: str, archive_id: int) -> QuarantineItem:
        row = self._connection.execute(
            "SELECT quarantine.id, quarantine.scan_root_id, quarantine.archive_id, "
            "quarantine.group_key, quarantine.source_path, quarantine.destination_path, "
            "quarantine.file_size, quarantine.mtime_ns, quarantine.sha256, "
            "quarantine.status, quarantine.error_code, archive.file_size, "
            "archive.mtime_ns, deletion.state "
            "FROM quarantine_items AS quarantine "
            "JOIN archives AS archive ON archive.id = quarantine.archive_id "
            "LEFT JOIN deletion_records AS deletion "
            "ON deletion.quarantine_item_id = quarantine.id "
            "WHERE quarantine.group_key = ? AND quarantine.archive_id = ? "
            "AND quarantine.status = 'QUARANTINED' "
            "ORDER BY quarantine.id DESC LIMIT 1",
            (group_key, archive_id),
        ).fetchone()
        if row is None:
            raise QuarantineEligibilityError("NOT_QUARANTINED")
        item = _quarantine_item(row[:11])
        archive_size, archive_mtime_ns, deletion_state = row[11:]
        if item.sha256 is None:
            raise QuarantineEligibilityError("QUARANTINE_HASH_MISSING")
        if (item.file_size, item.mtime_ns) != (
            int(archive_size),
            int(archive_mtime_ns),
        ):
            raise QuarantineEligibilityError("CANDIDATE_CHANGED")
        if deletion_state in {"PENDING", "DELETED"}:
            raise QuarantineEligibilityError("DELETION_ALREADY_RECORDED")
        state = self.latest_review_state(group_key, archive_id)
        if state.action is not ReviewAction.REMOVE_CANDIDATE or state.needs_review:
            raise QuarantineEligibilityError("REMOVE_CANDIDATE_REQUIRED")
        return item

    def begin_deletion(
        self, item: QuarantineItem, created_at: datetime
    ) -> DeletionItem:
        assert item.sha256 is not None
        with _immediate_transaction(self._connection):
            current = self.deletion_candidate(item.group_key, item.archive_id)
            if current != item:
                raise QuarantineEligibilityError("CANDIDATE_CHANGED")
            existing = self._connection.execute(
                "SELECT id, state FROM deletion_records WHERE quarantine_item_id = ?",
                (item.id,),
            ).fetchone()
            if existing is None:
                record_id = self._connection.execute(
                    "INSERT INTO deletion_records("
                    "quarantine_item_id, scan_root_id, archive_id, path, file_size, "
                    "mtime_ns, sha256, state, created_at, updated_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)",
                    (
                        item.id,
                        item.root_id,
                        item.archive_id,
                        str(item.destination_path),
                        item.file_size,
                        item.mtime_ns,
                        item.sha256,
                        created_at.isoformat(),
                        created_at.isoformat(),
                    ),
                ).lastrowid
            else:
                record_id, state = existing
                if str(state) != "FAILED":
                    raise QuarantineEligibilityError("DELETION_ALREADY_RECORDED")
                cursor = self._connection.execute(
                    "UPDATE deletion_records SET state = 'PENDING', error_code = NULL, "
                    "updated_at = ?, deleted_at = NULL WHERE id = ? AND state = 'FAILED'",
                    (created_at.isoformat(), int(record_id)),
                )
                if cursor.rowcount != 1:
                    raise QuarantineEligibilityError("DELETION_STATE_CHANGED")
        assert record_id is not None
        record = self.deletion_record(int(record_id))
        assert record is not None
        return record

    def deletion_record(self, record_id: int) -> DeletionItem | None:
        row = self._connection.execute(
            "SELECT id, quarantine_item_id, scan_root_id, archive_id, path, file_size, "
            "mtime_ns, sha256, state, error_code FROM deletion_records WHERE id = ?",
            (record_id,),
        ).fetchone()
        return None if row is None else _deletion_item(row)

    def pending_deletion_records(self, root_id: int) -> tuple[DeletionItem, ...]:
        rows = self._connection.execute(
            "SELECT id, quarantine_item_id, scan_root_id, archive_id, path, file_size, "
            "mtime_ns, sha256, state, error_code FROM deletion_records "
            "WHERE scan_root_id = ? AND state = 'PENDING' ORDER BY id",
            (root_id,),
        ).fetchall()
        return tuple(_deletion_item(row) for row in rows)

    def update_deletion_state(
        self,
        record_id: int,
        expected_state: str,
        state: str,
        updated_at: datetime,
        *,
        error_code: str | None = None,
    ) -> DeletionItem:
        allowed = {"PENDING", "DELETED", "FAILED"}
        if expected_state not in allowed or state not in allowed:
            raise ValueError("Unknown deletion state.")
        with _immediate_transaction(self._connection):
            cursor = self._connection.execute(
                "UPDATE deletion_records SET state = ?, error_code = ?, updated_at = ?, "
                "deleted_at = CASE WHEN ? = 'DELETED' THEN ? ELSE NULL END "
                "WHERE id = ? AND state = ?",
                (
                    state,
                    error_code,
                    updated_at.isoformat(),
                    state,
                    updated_at.isoformat(),
                    record_id,
                    expected_state,
                ),
            )
            if cursor.rowcount != 1:
                raise QuarantineEligibilityError("DELETION_STATE_CHANGED")
        record = self.deletion_record(record_id)
        assert record is not None
        return record

    def _validate_relation_matches(
        self, root_id: int, matches: tuple[CandidateMatch, ...]
    ) -> None:
        pairs: set[tuple[int, int]] = set()
        archive_ids: set[int] = set()
        for match in matches:
            if match.archive_a_id >= match.archive_b_id:
                raise ValueError("Candidate relation archive IDs must be in ascending order.")
            pair = (match.archive_a_id, match.archive_b_id)
            if pair in pairs:
                raise ValueError("Candidate relation pairs must be unique.")
            pairs.add(pair)
            archive_ids.update(pair)
        if not archive_ids:
            return
        rows = []
        sorted_archive_ids = tuple(sorted(archive_ids))
        for start in range(0, len(sorted_archive_ids), _ARCHIVE_VALIDATION_CHUNK_SIZE):
            chunk = sorted_archive_ids[start : start + _ARCHIVE_VALIDATION_CHUNK_SIZE]
            placeholders = ", ".join("?" for _ in chunk)
            rows.extend(
                self._connection.execute(
                    f"SELECT id, scan_root_id FROM archives WHERE id IN ({placeholders})", chunk
                ).fetchall()
            )
        if len(rows) != len(archive_ids) or any(int(row[1]) != root_id for row in rows):
            raise ValueError("Candidate relation archives must belong to the same scan root.")

    def _rebuild_candidate_groups_in_transaction(
        self, root_id: int, analyzer_version: int, created_at: datetime
    ) -> None:
        rows = self._connection.execute(
            "SELECT archive_a_id, archive_b_id, relation, confidence, matched_pages "
            "FROM candidate_relations "
            "WHERE scan_root_id = ? AND analyzer_version = ? ORDER BY archive_a_id, archive_b_id",
            (root_id, analyzer_version),
        ).fetchall()
        components = _connected_components(rows)
        self._connection.execute("DELETE FROM candidate_groups WHERE scan_root_id = ?", (root_id,))
        for archive_ids, edges in components:
            strongest_relation, confidence = _strongest_edge(edges)
            group_key = _candidate_group_key(root_id, archive_ids)
            group_id = self._connection.execute(
                "INSERT INTO candidate_groups("
                "scan_root_id, group_key, strongest_relation, confidence, analyzer_version, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?)",
                (root_id, group_key, strongest_relation.value, confidence, analyzer_version, created_at.isoformat()),
            ).lastrowid
            self._connection.executemany(
                "INSERT INTO candidate_group_members(group_id, archive_id) VALUES (?, ?)",
                tuple((group_id, archive_id) for archive_id in archive_ids),
            )

    def _group_needs_review(self, group_id: int, group_key: str) -> bool:
        row = self._connection.execute(
            "WITH current_members AS ("
            "SELECT member.archive_id, archive.file_size, archive.mtime_ns "
            "FROM candidate_group_members AS member JOIN archives AS archive "
            "ON archive.id = member.archive_id WHERE member.group_id = ?"
            "), latest_actions AS ("
            "SELECT action.archive_id, action.group_key, action.file_size, action.mtime_ns, "
            "ROW_NUMBER() OVER (PARTITION BY action.archive_id ORDER BY action.id DESC) AS row_number "
            "FROM review_actions AS action JOIN current_members "
            "ON current_members.archive_id = action.archive_id"
            ") "
            "SELECT MAX(CASE WHEN latest_actions.archive_id IS NULL THEN 0 ELSE 1 END) "
            "AND NOT MIN(CASE WHEN latest_actions.group_key = ? "
            "AND latest_actions.file_size = current_members.file_size "
            "AND latest_actions.mtime_ns = current_members.mtime_ns THEN 1 ELSE 0 END) "
            "FROM current_members LEFT JOIN latest_actions "
            "ON latest_actions.archive_id = current_members.archive_id "
            "AND latest_actions.row_number = 1",
            (group_id, group_key),
        ).fetchone()
        return bool(row[0])

    def append_review_action(
        self,
        group_key: str,
        archive_id: int | None,
        action: ReviewAction,
        snapshot: FileSnapshot | None,
        created_at: datetime,
    ) -> int | tuple[int, ...]:
        if archive_id is None:
            if snapshot is not None:
                raise ValueError("A group review action does not accept one shared snapshot.")
            if action not in {ReviewAction.KEEP, ReviewAction.HOLD}:
                raise ValueError("A group review action must be KEEP or HOLD.")
            with _immediate_transaction(self._connection):
                members = self._connection.execute(
                    "SELECT member.archive_id FROM candidate_groups AS group_row "
                    "JOIN candidate_group_members AS member ON member.group_id = group_row.id "
                    "WHERE group_row.group_key = ? ORDER BY member.archive_id",
                    (group_key,),
                ).fetchall()
                if not members:
                    raise ValueError("Candidate group has no current members.")
                action_ids = []
                for (member_id,) in members:
                    current = self._current_review_member_snapshot(
                        group_key, int(member_id)
                    )
                    cursor = self._insert_review_action(
                        group_key, int(member_id), action, current.size, current.mtime_ns, created_at
                    )
                    action_ids.append(int(cursor.lastrowid))
            return tuple(action_ids)
        if snapshot is None:
            raise ValueError("A member review action requires its file snapshot.")
        with _immediate_transaction(self._connection):
            current = self._current_review_member_snapshot(group_key, archive_id)
            if snapshot != current:
                raise ValueError("Review snapshot no longer matches the current archive index.")
            cursor = self._insert_review_action(
                group_key, archive_id, action, current.size, current.mtime_ns, created_at
            )
        return int(cursor.lastrowid)

    def _current_review_member_snapshot(self, group_key: str, archive_id: int) -> FileSnapshot:
        row = self._connection.execute(
            "SELECT archive.path, archive.path_key, archive.file_size, archive.mtime_ns, archive.archive_format "
            "FROM candidate_groups AS group_row "
            "JOIN candidate_group_members AS member ON member.group_id = group_row.id "
            "JOIN archives AS archive ON archive.id = member.archive_id "
            "WHERE group_row.group_key = ? AND member.archive_id = ? "
            "AND archive.scan_root_id = group_row.scan_root_id",
            (group_key, archive_id),
        ).fetchone()
        if row is None:
            raise ValueError("Archive is not a current member of the candidate group.")
        path, path_key, file_size, mtime_ns, archive_format = row
        return FileSnapshot(
            path=Path(str(path)),
            path_key=str(path_key),
            size=int(file_size),
            mtime_ns=int(mtime_ns),
            archive_format=ArchiveFormat(str(archive_format)),
        )

    def _insert_review_action(
        self,
        group_key: str,
        archive_id: int,
        action: ReviewAction,
        file_size: int,
        mtime_ns: int,
        created_at: datetime,
    ):
        return self._connection.execute(
            "INSERT INTO review_actions("
            "group_key, archive_id, action, file_size, mtime_ns, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?)",
            (group_key, archive_id, action.value, file_size, mtime_ns, created_at.isoformat()),
        )


def _snapshot_matches(value: ArchiveAnalysisInput) -> bool:
    try:
        current = value.path.stat()
    except OSError:
        return False
    return current.st_size == value.file_size and current.st_mtime_ns == value.mtime_ns


def _quarantine_item(row) -> QuarantineItem:  # type: ignore[no-untyped-def]
    return QuarantineItem(
        id=int(row[0]),
        root_id=int(row[1]),
        archive_id=int(row[2]),
        group_key=str(row[3]),
        source_path=Path(str(row[4])),
        destination_path=Path(str(row[5])),
        file_size=int(row[6]),
        mtime_ns=int(row[7]),
        sha256=None if row[8] is None else str(row[8]),
        status=str(row[9]),
        error_code=None if row[10] is None else str(row[10]),
    )


def _deletion_item(row) -> DeletionItem:  # type: ignore[no-untyped-def]
    return DeletionItem(
        id=int(row[0]),
        quarantine_item_id=int(row[1]),
        root_id=int(row[2]),
        archive_id=int(row[3]),
        path=Path(str(row[4])),
        file_size=int(row[5]),
        mtime_ns=int(row[6]),
        sha256=str(row[7]),
        state=str(row[8]),
        error_code=None if row[9] is None else str(row[9]),
    )


def _run_checkpoint(checkpoint: Callable[[], None] | None) -> None:
    if checkpoint is not None:
        checkpoint()


def _duplicate_job(row) -> DuplicateJob:
    return DuplicateJob(
        id=int(row[0]),
        analysis_run_id=int(row[1]),
        archive_id=None if row[2] is None else int(row[2]),
        stage=AnalysisStage(str(row[3])),
        subject_key=str(row[4]),
        status=str(row[5]),
        attempts=int(row[6]),
        last_error_code=None if row[7] is None else str(row[7]),
    )


@contextmanager
def _immediate_transaction(connection) -> Iterator[None]:
    if connection.in_transaction:
        raise RuntimeError("A candidate write transaction is already active.")
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield
    except Exception:
        connection.rollback()
        raise
    else:
        connection.commit()


@contextmanager
def _read_snapshot(connection) -> Iterator[None]:
    if connection.in_transaction:
        yield
        return
    connection.execute("BEGIN")
    try:
        yield
    except Exception:
        connection.rollback()
        raise
    else:
        connection.commit()


class _SnapshotChanged(Exception):
    pass


def _require_current_snapshot(value: ArchiveAnalysisInput) -> None:
    if not _snapshot_matches(value):
        raise _SnapshotChanged


def _stable_json(values: frozenset[str]) -> str:
    return json.dumps(sorted(values), ensure_ascii=False, separators=(",", ":"))


def _filename_signal_json(signal: FilenameSignal) -> str:
    return _stable_json_mapping(
        {
            "confidence": signal.confidence,
            "conflict": signal.conflict,
            "matched_tokens": sorted(signal.matched_tokens),
            "value": signal.value,
        }
    )


def _filename_signal_from_json(value: str) -> FilenameSignal:
    decoded = json.loads(value)
    return FilenameSignal(
        value=decoded["value"],
        confidence=float(decoded["confidence"]),
        matched_tokens=frozenset(decoded["matched_tokens"]),
        conflict=bool(decoded["conflict"]),
    )


def _stable_json_strings(values: tuple[str, ...]) -> str:
    return json.dumps(list(values), ensure_ascii=False, separators=(",", ":"))


def _stable_json_pairs(values: tuple[tuple[int, int], ...]) -> str:
    return json.dumps(values, ensure_ascii=False, separators=(",", ":"))


def _stable_json_ints(values: tuple[int, ...]) -> str:
    return json.dumps(values, ensure_ascii=False, separators=(",", ":"))


def _stable_json_mapping(values: Mapping[str, object]) -> str:
    if not all(isinstance(key, str) for key in values):
        raise ValueError("JSON object keys must be strings.")
    return json.dumps(values, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _stable_json_page_metrics(values: tuple[Mapping[str, object], ...]) -> str:
    if not all(isinstance(value, Mapping) for value in values):
        raise ValueError("Precision profile page metrics must be JSON objects.")
    return json.dumps(values, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _page_language_evidence_json(value: PageLanguageEvidence) -> str:
    return _stable_json_mapping(
        {
            "character_counts": dict(value.character_counts),
            "dominant_script": value.dominant_script.value,
            "kana_present": value.kana_present,
            "korean_dialogue_page": value.korean_dialogue_page,
            "korean_sentence_line_count": value.korean_sentence_line_count,
            "readable_character_count": value.readable_character_count,
            "recognizer_scope": value.recognizer_scope,
        }
    )


def _page_language_evidence_from_json(value: str) -> PageLanguageEvidence:
    decoded = json.loads(value)
    counts = decoded.get("character_counts", {})
    if not isinstance(counts, dict):
        counts = {}
    try:
        dominant = DetectedLanguage(str(decoded.get("dominant_script", "UNKNOWN")))
    except ValueError:
        dominant = DetectedLanguage.UNKNOWN
    return PageLanguageEvidence(
        character_counts={str(key): int(amount) for key, amount in counts.items()},
        readable_character_count=int(decoded.get("readable_character_count", 0)),
        korean_sentence_line_count=int(decoded.get("korean_sentence_line_count", 0)),
        korean_dialogue_page=bool(decoded.get("korean_dialogue_page", False)),
        kana_present=bool(decoded.get("kana_present", False)),
        dominant_script=dominant,
        recognizer_scope=str(decoded.get("recognizer_scope", "BOTH")),
    )


def _page_quality_metrics_json(value: PageQualityMetrics | None) -> str:
    if value is None:
        return "{}"
    return _stable_json_mapping(
        {
            "blur": value.blur,
            "detail": value.detail,
            "jpeg_blockiness": value.jpeg_blockiness,
            "noise": value.noise,
            "ringing": value.ringing,
            "sharpness": value.sharpness,
            "tile_blockiness": value.tile_blockiness,
            "tile_detail": value.tile_detail,
        }
    )


def _page_quality_metrics_from_json(value: str) -> PageQualityMetrics | None:
    decoded = json.loads(value)
    if not decoded:
        return None
    return PageQualityMetrics(
        sharpness=float(decoded["sharpness"]),
        jpeg_blockiness=float(decoded["jpeg_blockiness"]),
        ringing=float(decoded["ringing"]),
        blur=float(decoded["blur"]),
        detail=float(decoded["detail"]),
        noise=float(decoded["noise"]),
        tile_blockiness=tuple(float(item) for item in decoded["tile_blockiness"]),
        tile_detail=tuple(float(item) for item in decoded["tile_detail"]),
    )


def _recognizer_scope_rank(value: str) -> int:
    return 2 if value == "BOTH" else 1 if value in {"KO", "GENERAL"} else 0


def _derived_timestamp(
    computed_at: datetime | None, now: datetime | Callable[[], datetime] | None
) -> datetime:
    if computed_at is not None:
        return computed_at
    if now is None:
        return datetime.now(UTC)
    return now() if callable(now) else now


def _candidate_set_input_fingerprint(
    source_group_key: str,
    edition_kind: str,
    archive_ids: tuple[int, ...],
    algorithm_version: int,
) -> str:
    payload = _stable_json_mapping(
        {
            "algorithm_version": algorithm_version,
            "archive_ids": archive_ids,
            "edition_kind": edition_kind,
            "source_group_key": source_group_key,
        }
    )
    return sha256(payload.encode("utf-8")).hexdigest()


def _recommendation_record_from_row(row: tuple[object, ...]) -> RecommendationRecord:
    (
        item_id,
        set_key,
        source_group_key,
        archive_id,
        recommendation,
        status,
        criteria_json,
        reason,
        file_size,
        mtime_ns,
    ) = row
    recommendation_value = str(recommendation)
    if recommendation_value not in {"KEEP", "REMOVE_CANDIDATE", "NONE"}:
        raise ValueError("Stored recommendation has an unknown value.")
    criteria = _json_string_mapping(str(criteria_json))
    if criteria is None:
        raise ValueError("Stored recommendation criteria are invalid.")
    status_value = str(status)
    if not status_value:
        raise ValueError("Stored recommendation status is invalid.")
    return RecommendationRecord(
        item_id=int(item_id),
        set_key=str(set_key),
        source_group_key=str(source_group_key),
        archive_id=int(archive_id),
        recommendation=recommendation_value,
        status=status_value,
        criteria=criteria,
        reason=str(reason),
        file_size=int(file_size),
        mtime_ns=int(mtime_ns),
    )


def _candidate_relation_record(row: tuple[object, ...]) -> CandidateRelationRecord:
    (
        archive_a_id,
        archive_b_id,
        relation,
        relation_confidence,
        matched_pages,
        left_pages,
        right_pages,
        recommendation,
        evidence_json,
        sequence_relation,
        container_archive_id,
        matched_pairs_json,
        left_coverage,
        right_coverage,
        edition_flags_json,
        edition_summary,
        preserve_required,
    ) = row
    return CandidateRelationRecord(
        archive_a_id=int(archive_a_id),
        archive_b_id=int(archive_b_id),
        relation=DuplicateRelation(str(relation)),
        confidence=float(relation_confidence),
        matched_pages=int(matched_pages),
        left_pages=int(left_pages),
        right_pages=int(right_pages),
        recommendation=str(recommendation),
        reasons=_json_string_tuple(str(evidence_json)),
        sequence_relation=(None if sequence_relation is None else SequenceRelation(str(sequence_relation))),
        container_archive_id=(None if container_archive_id is None else int(container_archive_id)),
        matched_pairs=(() if matched_pairs_json is None else _json_int_pairs(str(matched_pairs_json))),
        left_coverage=0.0 if left_coverage is None else float(left_coverage),
        right_coverage=0.0 if right_coverage is None else float(right_coverage),
        edition_flags=(
            () if edition_flags_json is None else tuple(
                EditionFlag(value) for value in _json_string_tuple(str(edition_flags_json))
            )
        ),
        edition_summary=None if edition_summary is None else str(edition_summary),
        preserve_required=bool(preserve_required),
    )


def _json_string_set(value: str) -> frozenset[str] | None:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        return None
    return frozenset(parsed)


def _json_string_tuple(value: str) -> tuple[str, ...]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return ()
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        return ()
    return tuple(parsed)


def _json_ints(value: str) -> tuple[int, ...] | None:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, list) or not all(isinstance(item, int) for item in parsed):
        return None
    values = tuple(parsed)
    return values if values == tuple(sorted(set(values))) else None


def _json_string_mapping(value: str) -> dict[str, str] | None:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in parsed.items()
    ):
        return None
    return dict(parsed)


def _json_int_pairs(value: str) -> tuple[tuple[int, int], ...]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return ()
    if not isinstance(parsed, list):
        return ()
    pairs: list[tuple[int, int]] = []
    for item in parsed:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not all(isinstance(part, int) and part >= 0 for part in item)
        ):
            return ()
        pairs.append((item[0], item[1]))
    return tuple(pairs)


def _candidate_group_key(root_id: int, archive_ids: tuple[int, ...]) -> str:
    members = ",".join(str(archive_id) for archive_id in archive_ids)
    return sha256(f"{root_id}:{members}".encode("utf-8")).hexdigest()


def _connected_components(
    rows: list[tuple[int, int, str, float, int]],
) -> tuple[tuple[tuple[int, ...], tuple[tuple[int, int, DuplicateRelation, float], ...]], ...]:
    parent: dict[int, int] = {}

    def find(archive_id: int) -> int:
        parent.setdefault(archive_id, archive_id)
        while parent[archive_id] != archive_id:
            parent[archive_id] = parent[parent[archive_id]]
            archive_id = parent[archive_id]
        return archive_id

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    edges = tuple(
        (
            int(left),
            int(right),
            DuplicateRelation(str(relation)),
            float(confidence),
            int(matched_pages),
        )
        for left, right, relation, confidence, matched_pages in rows
    )
    for left, right, relation, confidence, matched_pages in edges:
        if relation is not DuplicateRelation.RELATED or (
            matched_pages >= 2 and confidence >= 0.5
        ):
            union(left, right)
    components: dict[int, list[int]] = {}
    for archive_id in parent:
        components.setdefault(find(archive_id), []).append(archive_id)
    grouped_edges: dict[int, list[tuple[int, int, DuplicateRelation, float]]] = {
        component: [] for component in components
    }
    for left, right, relation, confidence, _ in edges:
        if left in parent and right in parent and find(left) == find(right):
            grouped_edges[find(left)].append((left, right, relation, confidence))
    return tuple(
        (
            tuple(sorted(members)),
            tuple(sorted(grouped_edges[component], key=lambda edge: (edge[0], edge[1]))),
        )
        for component, members in sorted(components.items(), key=lambda item: min(item[1]))
    )


_RELATION_PRIORITY = {
    DuplicateRelation.EXACT_ARCHIVE: 0,
    DuplicateRelation.EXACT_CONTENT: 1,
    DuplicateRelation.VISUAL_VARIANT: 2,
    DuplicateRelation.RELATED: 3,
}


def _strongest_edge(
    edges: tuple[tuple[int, int, DuplicateRelation, float], ...],
) -> tuple[DuplicateRelation, float]:
    relation = min((edge[2] for edge in edges), key=lambda value: _RELATION_PRIORITY[value])
    return relation, max(edge[3] for edge in edges if edge[2] is relation)


def _recommended_archive_id(relations: tuple[CandidateRelationRecord, ...]) -> int | None:
    recommendations = []
    for relation in relations:
        if relation.recommendation == "KEEP_LEFT_HIGHER_RESOLUTION":
            recommendations.append(relation.archive_a_id)
        elif relation.recommendation == "KEEP_RIGHT_HIGHER_RESOLUTION":
            recommendations.append(relation.archive_b_id)
        else:
            return None
    return recommendations[0] if recommendations and len(set(recommendations)) == 1 else None


def _representative_dimensions(rows: list[tuple]) -> dict[int, tuple[int, int]]:
    values: dict[int, list[tuple[int, int, int, int]]] = {}
    for archive_id, entry_position, width, height in rows:
        values.setdefault(int(archive_id), []).append(
            (int(width) * int(height), int(entry_position), int(width), int(height))
        )
    return {
        archive_id: (pages[(len(pages) - 1) // 2][2], pages[(len(pages) - 1) // 2][3])
        for archive_id, pages in values.items()
    }
