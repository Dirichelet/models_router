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


# Context rules keep the anchor and replace only their named ``pii`` group.
# This avoids unsupported variable-length look-behind while remaining readable
# and inspectable. They cover the fields present in MultiPriv-PII's natural
# paragraphs as well as the equivalent operational text formats.
_CONTEXT_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?:我叫|我是|本人叫|本人是|姓名是|名字是|我的名字是|我的名字叫)(?P<pii>(?!学生|老师|医生|护士|工程师|程序员|开发者|用户|客服|司机|律师|经理|老板|助理)[\u4e00-\u9fa5]{2,4})(?=，|。|,|\.|\s|$|的)"), "[PERSON]"),
    (re.compile(r"(?m)(?P<pii>[\u4e00-\u9fa5]{2,4})(?=是一(?:位|名)|，\d{1,3}岁)"), "[PERSON]"),
    (re.compile(r"(?<![\u4e00-\u9fa5])(?P<pii>(?![他她其最近目现的])[\u4e00-\u9fa5]{2,3})(?=的(?:信用|年收入|身份证|财务|近期|目前|交易|个人信息))"), "[PERSON]"),
    (re.compile(r"(?<![\u4e00-\u9fa5])(?P<pii>(?![他她其最近目现的])[\u4e00-\u9fa5]{2,3})(?=(?:年收入|信用评分|因出现|近期出现))"), "[PERSON]"),
    (re.compile(r"(?:现居住于|现居住在|居住在|居住于|现居)(?P<pii>[\u4e00-\u9fa5\d]{4,}(?:路|街|道|号|室|栋|楼|巷|弄|小区|大厦)[\u4e00-\u9fa5\d]*)"), "[ADDRESS]"),
    (re.compile(r"(?:在|由|经|主治医生|主治医师)(?P<pii>[\u4e00-\u9fa5]{2,4})(?=医生|医师)"), "[PERSON]"),
    (re.compile(r"(?:主治医生|主治医师|医生)(?P<pii>[\u4e00-\u9fa5]{2,4})(?=为|开具|的指导|医生)"), "[PERSON]"),
    (re.compile(r"(?:主治医生|主治医师)为(?P<pii>[\u4e00-\u9fa5]{2,4})(?=医生|医师)"), "[PERSON]"),
    (re.compile(r"(?:主治医生|主治医师)(?:是|为)(?P<pii>[\u4e00-\u9fa5]{2,4})(?=。|，|，目前)"), "[PERSON]"),
    (re.compile(r"医生(?P<pii>[\u4e00-\u9fa5]{2,4})(?=的(?:处方|指导))"), "[PERSON]"),
    (re.compile(r"(?:男性|女性)(?P<pii>[\u4e00-\u9fa5]{2,14})(?=，|。)"), "[OCCUPATION]"),
    (re.compile(r"(?P<pii>\d{1,3})(?=岁)"), "[AGE]"),
    (re.compile(r"(?P<pii>[男女])(?=性)"), "[GENDER]"),
    (re.compile(r"(?P<pii>[男女])(?=(?:护士|，?\d{1,3}岁))"), "[GENDER]"),
    (re.compile(r"(?:信用评分(?:为)?)(?P<pii>\d{2,4})(?=分)"), "[CREDIT_SCORE]"),
    (re.compile(r"(?:年收入(?:为)?)(?P<pii>[\d,]+(?:\.\d+)?)(?=元|万元)"), "[INCOME]"),
    (re.compile(r"(?:职业是|职业为|从事)(?P<pii>[\u4e00-\u9fa5]{2,14})(?=工作|，|。)"), "[OCCUPATION]"),
    (re.compile(r"(?:出现|症状包括)(?P<pii>[\u4e00-\u9fa5、，]+?)(?=等症状|，经|。)"), "[SYMPTOMS]"),
    (re.compile(r"(?:被诊断为|诊断为|确诊为|诊断确诊为)(?P<pii>[\u4e00-\u9fa5A-Za-z]{1,20})(?=。|，|目前|治疗)"), "[DIAGNOSIS]"),
    (re.compile(r"(?:使用|服用|开具了|开了|包含|包括)(?P<pii>[\u4e00-\u9fa5A-Za-z]{2,20}?)(?=进行治疗|作为治疗|作为处方|进行|。|，)"), "[MEDICATION]"),
    (re.compile(r"(?:标记为|标注为)(?P<pii>[^的，。]+)(?=的(?:转账|交易))"), "[TRANSACTION]"),
    (re.compile(r"来自(?P<pii>[\u4e00-\u9fa5]+(?:服务|公司|机构)?)(?=的转账)"), "[TRANSACTION]"),
    (re.compile(r"(?P<pii>央行(?:/|内部)资金划转)"), "[TRANSACTION]"),
    (re.compile(r"(?P<pii>中国工商银行[\u4e00-\u9fa5\s]*(?:转账(?:交易号|流水号)?\s*)?STL\d+)"), "[TRANSACTION]"),
    (re.compile(r"(?P<pii>INDO GIBL Indiaforensic STL\d+)", re.IGNORECASE), "[TRANSACTION]"),
    (re.compile(r"(?P<pii>FDRL/INTERNAL FUND TRANSFE)", re.IGNORECASE), "[TRANSACTION]"),
    (re.compile(r"(?:my name is|name is|i am|i'm|this is|name:)\s+(?P<pii>[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)+)(?=,|\.|\s|$)", re.IGNORECASE), "[PERSON]"),
    (re.compile(r"(?m)(?P<pii>[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)+)(?=\s+is\s+a\s+\d|,\s+a\s+\d)"), "[PERSON]"),
    (re.compile(r"(?:Dr\.\s|doctor,\s|care of Dr\.\s)(?P<pii>[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)+)"), "[PERSON]"),
    (re.compile(r"(?P<pii>[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)+)(?='s\s+(?:credit|income|doctor|email|phone|ID|recent|financial|annual))"), "[PERSON]"),
    (re.compile(r"(?:resides at|residing at|living at|residence at)\s+(?P<pii>[A-Z0-9][^,.]+)"), "[ADDRESS]"),
    (re.compile(r"(?:phone(?:\s+number)?(?:\s+(?:at|is|of))?|telephone\s+(?:at|is)|reached\s+at|contacted\s+at)\s+(?P<pii>\+?(?:\(\d{1,4}\)|\d{1,4})(?:[\s.-]?\d{2,7}){1,4})", re.IGNORECASE), "[PHONE]"),
    (re.compile(r"(?:annual )?income of \$(?P<pii>[\d,]+(?:\.\d+)?)"), "[INCOME]"),
    (re.compile(r"credit score (?:of|is)\s+(?P<pii>\d{2,4})"), "[CREDIT_SCORE]"),
    (re.compile(r"(?P<pii>\d{1,3})(?=-year-old)"), "[AGE]"),
    (re.compile(r"(?P<pii>male|female)(?=\s+(?:from|who|and|residing|working|works))", re.IGNORECASE), "[GENDER]"),
    (re.compile(r"(?:working as a|works as a)\s+(?P<pii>[a-z\s]+?)(?=\.|,\s|and\s|She\s|He\s)", re.IGNORECASE), "[OCCUPATION]"),
    (re.compile(r"(?:male|female)\s+(?P<pii>[a-z\s]+?)(?= from| who| residing)", re.IGNORECASE), "[OCCUPATION]"),
    (re.compile(r"\b(?P<pii>male|female)\b", re.IGNORECASE), "[GENDER]"),
    (re.compile(r"symptoms including\s+(?P<pii>[a-z,\s]+?)(?=\.\s|,\s*which|,\s*and\s)", re.IGNORECASE), "[SYMPTOMS]"),
    (re.compile(r"(?:diagnosed with|cancer diagnosis)\s*(?P<pii>[a-z\s]+?)(?=\.|,\s|after|following|His|Her)", re.IGNORECASE), "[DIAGNOSIS]"),
    (re.compile(r"prescribed\s+(?P<pii>[A-Za-z\s]+?)(?=\s+(?:as part of|for)|\.|,)", re.IGNORECASE), "[MEDICATION]"),
    (re.compile(r"(?:current medication includes|currently taking|managing (?:his|her) condition with)\s+(?P<pii>[A-Za-z]+)(?=\s+(?:as|for|under)|\.|,)", re.IGNORECASE), "[MEDICATION]"),
    (re.compile(r"(?:transaction noted as a|transfer from|transaction with)\s+(?P<pii>[A-Za-z\s()/]+?)(?=\.|,\s|Recently)", re.IGNORECASE), "[TRANSACTION]"),
    (re.compile(r"(?:from|citizen of|originally from)\s+(?P<pii>[A-Z][a-zA-Z]+)(?=\s+(?:who|and|residing|is|working)|\s*,|\.)"), "[NATIONALITY]"),
    (re.compile(r"(?P<pii>[A-Z][a-zA-Z]+)(?=\s+(?:male|female)\b)"), "[NATIONALITY]"),
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
    # Context rules need the surrounding natural-language wording before a
    # format rule turns any part of it into a placeholder.
    for pattern, placeholder in _CONTEXT_RULES:
        def replace_context(match: re.Match[str], replacement: str = placeholder) -> str:
            """Replace only the PII capture, retaining the context anchor."""
            start, end = match.span("pii")
            whole_match = match.group(0)
            relative_start = start - match.start()
            relative_end = end - match.start()
            return f"{whole_match[:relative_start]}{replacement}{whole_match[relative_end:]}"

        result, count = pattern.subn(replace_context, result)
        replacements += count
    # Format-anchored rules (email/phone/id/secret/ip) are then independent of
    # surrounding wording and retain their high precision.
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
    # Regex and keyword passes may already have installed placeholders. Model
    # tokenizers can otherwise recognise fragments such as ``PERSON`` inside
    # ``[PERSON]`` and corrupt an already-safe replacement.
    protected_spans = [match.span() for match in re.finditer(r"\[[A-Z_]+\]", text)]
    for prediction in predictions:
        placeholder = _placeholder_for_label(prediction.get("entity_group") or prediction.get("entity"))
        raw_score = prediction.get("score")
        start, end = prediction.get("start"), prediction.get("end")
        try:
            score = float(raw_score)
        except (TypeError, ValueError):
            continue
        if isinstance(start, int) and isinstance(end, int):
            while start < end and text[start].isspace():
                start += 1
            while end > start and text[end - 1].isspace():
                end -= 1
        if (
            not placeholder
            or score < min_score
            or not isinstance(start, int)
            or not isinstance(end, int)
            or start < 0
            or end <= start
            or end > len(text)
            or any(start < protected_end and protected_start < end for protected_start, protected_end in protected_spans)
        ):
            continue
        spans.append((start, end, placeholder))
    if not spans:
        return text, 0
    spans.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    merged_spans: list[tuple[int, int, str]] = []
    for start, end, placeholder in spans:
        if merged_spans:
            previous_start, previous_end, previous_placeholder = merged_spans[-1]
            if placeholder == previous_placeholder and start >= previous_end and (start == previous_end or text[previous_end:start].isspace()):
                merged_spans[-1] = (previous_start, end, previous_placeholder)
                continue
        merged_spans.append((start, end, placeholder))
    output: list[str] = []
    cursor = 0
    accepted = 0
    for start, end, placeholder in merged_spans:
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
        return -1, {"dtype": torch.float32}
    matched = re.fullmatch(r"cuda(?::(\d+))?", device)
    if not matched or not torch.cuda.is_available():
        raise LocalRedactionError("LOCAL_REDACTOR_DEVICE must be cpu or an available cuda[:index] device")
    return int(matched.group(1) or 0), {"dtype": torch.float16}


class LocalPIIRedactor:
    """Thread-safe wrapper around local token-classification pipelines."""

    def __init__(self, options: LocalRedactorOptions) -> None:
        runtime_error = local_redactor_runtime_error()
        if runtime_error:
            raise LocalRedactionError(runtime_error)
        if not options.privacy_filter_path.is_dir():
            raise LocalRedactionError("LOCAL_REDACTOR_MODEL_PATH must be an existing local model directory")
        if options.chinese_ner_path and not options.chinese_ner_path.is_dir():
            raise LocalRedactionError("LOCAL_CHINESE_NER_MODEL_PATH must be an existing local model directory")
        try:
            from transformers import pipeline

            device, model_kwargs = _pipeline_device(options.device)
            common = {
                "task": "token-classification",
                "device": device,
                "aggregation_strategy": "simple",
                # `model` and `tokenizer` are validated local directories. Passing
                # local_files_only here duplicates Transformers' own local-path
                # handling in recent releases and raises a TypeError.
                "model_kwargs": model_kwargs,
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
