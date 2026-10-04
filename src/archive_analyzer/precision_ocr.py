from __future__ import annotations

import sys
from io import BytesIO
from pathlib import Path
from statistics import median
from threading import RLock
from typing import Protocol

import numpy as np
from PIL import Image, ImageOps


_MODEL_FILES = (
    "PP-OCRv6_det_tiny.onnx",
    "ch_PP-OCRv5_rec_mobile.onnx",
    "ppocrv5_dict.txt",
    "korean_PP-OCRv5_rec_mobile.onnx",
    "ppocrv5_korean_dict.txt",
)
_MINIMUM_TEXT_SCORE = 0.60


class OcrUnavailable(RuntimeError):
    pass


class OcrBackend(Protocol):
    def recognize(
        self, payload: bytes, *, language_hints: frozenset[str] = frozenset()
    ) -> tuple[str, float]: ...


class BundledRapidOcrBackend:
    """Lazy RapidOCR adapter that only opens explicitly bundled model files."""

    def __init__(self, asset_root: Path | None = None) -> None:
        self._asset_root = asset_root or bundled_asset_path("ocr")
        self._engines: tuple[object, object] | None = None
        self._lock = RLock()

    def recognize(
        self, payload: bytes, *, language_hints: frozenset[str] = frozenset()
    ) -> tuple[str, float]:
        try:
            with Image.open(BytesIO(payload)) as opened:
                image = np.asarray(ImageOps.exif_transpose(opened).convert("RGB"))
            with self._lock:
                engines = self._ensure_engines()
                detector = engines[0]
                prepared, operation = detector.preprocess_img(image)
                try:
                    crops, _detection = detector.detect_and_crop(prepared, operation)
                except Exception as error:
                    from rapidocr.main import RapidOCRError

                    if isinstance(error, RapidOCRError):
                        return "", 0.0
                    raise
                if not crops:
                    return "", 0.0
                candidates: list[tuple[str, float]] = []
                for index in _recognizer_indexes(language_hints):
                    result = engines[index].recognize_txt(crops)
                    texts = () if result.txts is None else result.txts
                    scores = () if result.scores is None else result.scores
                    for text, score in zip(texts, scores, strict=False):
                        normalized = str(text).strip()
                        confidence = float(score)
                        if normalized and confidence >= _MINIMUM_TEXT_SCORE:
                            candidates.append((normalized, confidence))
        except OcrUnavailable:
            raise
        except Exception as error:
            raise OcrUnavailable(str(error)) from error
        if not candidates:
            return "", 0.0
        return "\n".join(text for text, _confidence in candidates), float(
            median(confidence for _text, confidence in candidates)
        )

    def _ensure_engines(self) -> tuple[object, object]:
        if self._engines is not None:
            return self._engines
        missing = tuple(
            filename for filename in _MODEL_FILES if not (self._asset_root / filename).is_file()
        )
        if missing:
            raise OcrUnavailable(f"Bundled OCR assets are missing: {', '.join(missing)}")
        try:
            from rapidocr import EngineType, ModelType, OCRVersion, RapidOCR
            from rapidocr.main import CalRecBoxes, LoadImage, TextDetector, TextRecognizer

            # RapidOCR 3.9.2 initializes its classifier even when disabled.  Omitting
            # it here prevents the library's default-model download path entirely.
            class OfflineRapidOCR(RapidOCR):
                def _initialize(self, cfg) -> None:
                    self.text_score = cfg.Global.text_score
                    self.min_height = cfg.Global.min_height
                    self.width_height_ratio = cfg.Global.width_height_ratio
                    self.use_det = cfg.Global.use_det
                    cfg.Det.engine_cfg = cfg.EngineConfig[cfg.Det.engine_type.value]
                    cfg.Det.model_root_dir = None
                    self.text_det = TextDetector(cfg.Det)
                    self.use_cls = False
                    self.text_cls = None
                    self.use_rec = cfg.Global.use_rec
                    cfg.Rec.engine_cfg = cfg.EngineConfig[cfg.Rec.engine_type.value]
                    cfg.Rec.font_path = cfg.Global.font_path
                    cfg.Rec.model_root_dir = None
                    self.text_rec = TextRecognizer(cfg.Rec)
                    self.load_img = LoadImage()
                    self.max_side_len = cfg.Global.max_side_len
                    self.min_side_len = cfg.Global.min_side_len
                    self.cal_rec_boxes = CalRecBoxes()
                    self.return_word_box = cfg.Global.return_word_box
                    self.return_single_char_box = cfg.Global.return_single_char_box
                    self.cfg = cfg

            common = {
                "Global.use_cls": False,
                "Global.text_score": _MINIMUM_TEXT_SCORE,
                "Global.max_side_len": 1600,
                "Det.engine_type": EngineType.ONNXRUNTIME,
                "Det.lang_type": "ch",
                "Det.model_type": ModelType.TINY,
                "Det.ocr_version": OCRVersion.PPOCRV6,
                "Det.model_path": str(self._asset_root / "PP-OCRv6_det_tiny.onnx"),
                "Rec.engine_type": EngineType.ONNXRUNTIME,
                "Rec.model_type": ModelType.MOBILE,
                "Rec.ocr_version": OCRVersion.PPOCRV5,
            }
            self._engines = (
                OfflineRapidOCR(
                    params=common
                    | {
                        "Rec.lang_type": "ch",
                        "Rec.model_path": str(
                            self._asset_root / "ch_PP-OCRv5_rec_mobile.onnx"
                        ),
                        "Rec.rec_keys_path": str(self._asset_root / "ppocrv5_dict.txt"),
                    }
                ),
                OfflineRapidOCR(
                    params=common
                    | {
                        "Rec.lang_type": "korean",
                        "Rec.model_path": str(
                            self._asset_root / "korean_PP-OCRv5_rec_mobile.onnx"
                        ),
                        "Rec.rec_keys_path": str(
                            self._asset_root / "ppocrv5_korean_dict.txt"
                        ),
                    }
                ),
            )
        except Exception as error:
            raise OcrUnavailable(str(error)) from error
        return self._engines


def _recognizer_indexes(language_hints: frozenset[str]) -> tuple[int, ...]:
    normalized = {str(value).upper() for value in language_hints}
    korean = bool(normalized & {"KO", "KR", "KOREAN"})
    general = bool(
        normalized
        & {"JA", "JP", "JAPANESE", "ZH", "CN", "CHINESE", "EN", "ENG", "ENGLISH"}
    )
    if korean and not general:
        return (1,)
    if general and not korean:
        return (0,)
    return (0, 1)


def bundled_asset_path(name: str) -> Path:
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root is not None:
        # PyInstaller keeps our files below ``archive_analyzer/<name>``.  The
        # direct fallback also accepts older local builds that used ``<name>``.
        package_path = Path(frozen_root) / "archive_analyzer" / name
        if package_path.is_dir():
            return package_path
        return Path(frozen_root) / name
    return Path(__file__).resolve().parents[2] / "build" / f"{name}-assets"


__all__ = ["BundledRapidOcrBackend", "OcrBackend", "OcrUnavailable", "bundled_asset_path"]
