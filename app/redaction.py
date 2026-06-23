"""Local-only PII redaction: deterministic rules, Privacy Filter, then Chinese NER."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from threading import Lock
from typing import Any


class LocalRedactionError(ValueError):
    """The local redaction runtime or model could not be used safely."""


@dataclass(frozen=True)
class LocalRedactorOptions:
    privacy_filter_path: Path
    chinese_ner_path: Path | None
    device: str
    min_score: float


@dataclass(frozen=True)
class RedactionResult:
    text: str
    regex_spans: int
    model_spans: int


@dataclass(frozen=True)
class KeywordRule:
    phrase: str
    replacement: str
    fuzzy: bool = False


_REGEX_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\b(?:authorization\s*:\s*bearer\s+)?(?:sk|rk|pk|api)[_-][A-Za-z0-9._~+/=-]{16,}\b"), "[SECRET]"),
    (re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"), "[EMAIL]"),
    (re.compile(r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)"), "[PHONE]"),
    (re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)"), "[ID]"),
    (re.compile(r"(?<!\d)(?:\d[ -]?){15,18}\d(?!\d)"), "[ACCOUNT]"),
    (re.compile(r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])"), "[IP]"),
)

_LABEL_PLACEHOLDERS = {
    "account_number": "[ACCOUNT]",
    "address": "[ADDRESS]",
    "date": "[DATE]",
    "email": "[EMAIL]",
    "person": "[PERSON]",
    "phone": "[PHONE]",
    "secret": "[SECRET]",
    "url": "[URL]",
}


def local_redactor_runtime_error() -> str | None:
    """Check imports only; model weights are loaded lazily on the first request."""
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
    except ImportError:
        return "Local redaction requires the installed torch and transformers dependencies"
    return None


def _replace_regex(text: str) -> tuple[str, int]:
    result = text
    replacements = 0
    for pattern, placeholder in _REGEX_RULES:
        result, count = pattern.subn(placeholder, result)
        replacements += count
    return result, replacements


def _keyword_pattern(phrase: str, fuzzy: bool) -> re.Pattern[str]:
    if not fuzzy:
        return re.compile(re.escape(phrase), re.IGNORECASE)
    characters = [character for character in phrase if not character.isspace() and character not in "._-"]
    if not characters:
        raise LocalRedactionError("Keyword phrase must contain a visible character")
    return re.compile(r"[\s._-]*".join(re.escape(character) for character in characters), re.IGNORECASE)


def _replace_keywords(text: str, keyword_rules: tuple[KeywordRule, ...]) -> tuple[str, int]:
    result = text
    replacements = 0
    for rule in sorted(keyword_rules, key=lambda item: len(item.phrase), reverse=True):
        if not rule.phrase.strip():
            continue
        result, count = _keyword_pattern(rule.phrase.strip(), rule.fuzzy).subn(rule.replacement, result)
        replacements += count
    return result, replacements


def _placeholder_for_label(value: object) -> str | None:
    normalized = str(value or "").casefold()
    normalized = normalized.removeprefix("b-").removeprefix("i-").removeprefix("e-").removeprefix("s-")
    if "person" in normalized or normalized in {"per", "name"}:
        return _LABEL_PLACEHOLDERS["person"]
    if "address" in normalized or normalized in {"loc", "location", "address"}:
        return _LABEL_PLACEHOLDERS["address"]
    if "account" in normalized or "card" in normalized or "id" == normalized:
        return _LABEL_PLACEHOLDERS["account_number"]
    for label, placeholder in _LABEL_PLACEHOLDERS.items():
        if label in normalized:
            return placeholder
    return None


def _apply_model_spans(text: str, predictions: list[dict[str, Any]], min_score: float) -> tuple[str, int]:
    spans: list[tuple[int, int, str]] = []
    for prediction in predictions:
        placeholder = _placeholder_for_label(prediction.get("entity_group") or prediction.get("entity"))
        score = prediction.get("score")
        start, end = prediction.get("start"), prediction.get("end")
        if (
            not placeholder
            or not isinstance(score, (int, float))
            or score < min_score
            or not isinstance(start, int)
            or not isinstance(end, int)
            or start < 0
            or end <= start
            or end > len(text)
        ):
            continue
        spans.append((start, end, placeholder))
    if not spans:
        return text, 0
    spans.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    output: list[str] = []
    cursor = 0
    accepted = 0
    for start, end, placeholder in spans:
        if start < cursor:
            continue
        output.extend((text[cursor:start], placeholder))
        cursor = end
        accepted += 1
    output.append(text[cursor:])
    return "".join(output), accepted


def _pipeline_device(device: str) -> tuple[int, dict[str, Any]]:
    try:
        import torch
    except ImportError as exc:  # Defensive; the caller normally checks this first.
        raise LocalRedactionError("torch is unavailable") from exc
    if device == "cpu":
        return -1, {"torch_dtype": torch.float32}
    matched = re.fullmatch(r"cuda(?::(\d+))?", device)
    if not matched or not torch.cuda.is_available():
        raise LocalRedactionError("LOCAL_REDACTOR_DEVICE must be cpu or an available cuda[:index] device")
    return int(matched.group(1) or 0), {"torch_dtype": torch.float16}


class LocalPIIRedactor:
    """Thread-safe wrapper around local token-classification pipelines."""

    def __init__(self, options: LocalRedactorOptions) -> None:
        runtime_error = local_redactor_runtime_error()
        if runtime_error:
            raise LocalRedactionError(runtime_error)
        try:
            from transformers import pipeline

            device, model_kwargs = _pipeline_device(options.device)
            common = {
                "task": "token-classification",
                "device": device,
                "aggregation_strategy": "simple",
                "model_kwargs": {"local_files_only": True, **model_kwargs},
            }
            self._privacy_filter = pipeline(model=str(options.privacy_filter_path), tokenizer=str(options.privacy_filter_path), **common)
            self._chinese_ner = (
                pipeline(model=str(options.chinese_ner_path), tokenizer=str(options.chinese_ner_path), **common)
                if options.chinese_ner_path
                else None
            )
        except LocalRedactionError:
            raise
        except Exception as exc:
            raise LocalRedactionError(f"Could not load local redaction model: {exc}") from exc
        self._options = options
        self._lock = Lock()

    def redact(self, text: str, keyword_rules: tuple[KeywordRule, ...] = ()) -> RedactionResult:
        regex_text, regex_spans = _replace_regex(text)
        regex_text, keyword_spans = _replace_keywords(regex_text, keyword_rules)
        try:
            with self._lock:
                privacy_predictions = self._privacy_filter(regex_text)
            redacted, privacy_spans = _apply_model_spans(regex_text, privacy_predictions, self._options.min_score)
            ner_spans = 0
            if self._chinese_ner:
                with self._lock:
                    ner_predictions = self._chinese_ner(redacted)
                redacted, ner_spans = _apply_model_spans(redacted, ner_predictions, self._options.min_score)
            return RedactionResult(text=redacted, regex_spans=regex_spans + keyword_spans, model_spans=privacy_spans + ner_spans)
        except LocalRedactionError:
            raise
        except Exception as exc:
            raise LocalRedactionError(f"Local redaction inference failed: {exc}") from exc


_redactors_lock = Lock()


@lru_cache(maxsize=4)
def _redactor(options: LocalRedactorOptions) -> LocalPIIRedactor:
    with _redactors_lock:
        return LocalPIIRedactor(options)


def local_redact(
    options: LocalRedactorOptions,
    text: str,
    keyword_rules: tuple[KeywordRule, ...] = (),
) -> RedactionResult:
    """Mask PII locally. No provider endpoint or model download is used at runtime."""
    return _redactor(options).redact(text, keyword_rules)
