"""Evaluate local deterministic redaction against MultiPriv-PII.

The evaluation uses the repository's natural-language records together with
their structured PII fields. It is value-level: an expected value is recalled
only when its source text no longer occurs in the redacted paragraph. Precision
is calculated from the exact replacement spans emitted by the regex pipeline,
not from a count of ``[PLACEHOLDER]`` strings. This avoids treating two
structured fields covered by one replacement (for example, a formatted phone
number) as a false positive.

The dataset is cached locally under ``tests/.multipriv-cache`` and is excluded
from git. Run with ``uv run python tests/eval_redaction.py``. The process exits
non-zero unless precision, recall, and F1 all meet the configured threshold.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.redaction import _CONTEXT_RULES, _REGEX_RULES, _replace_regex  # noqa: E402


CACHE_DIR = Path(__file__).resolve().parent / ".multipriv-cache"
DATASETS = {
    "zh": "https://raw.githubusercontent.com/CyberChangAn/MultiPriv-PII/main/LLM/data_person_1000_zh.json",
    "en": "https://raw.githubusercontent.com/CyberChangAn/MultiPriv-PII/main/LLM/data_person_1000.json",
}
PII_FIELDS = (
    "name",
    "location",
    "idCardNumbers",
    "emailAddress",
    "phoneNumbers",
    "symptoms",
    "diagnosticOutcome",
    "medicationDetails",
    "doctor",
    "transactionDetails",
    "creditScore",
    "income",
    "occupation",
    "age",
    "gender",
    "nationality",
)


@dataclass(frozen=True)
class GroundTruth:
    field: str
    start: int
    end: int


@dataclass(frozen=True)
class Replacement:
    start: int
    end: int
    placeholder: str


@dataclass(frozen=True)
class Metrics:
    precision: float
    recall: float
    f1: float
    expected: int
    recalled: int
    replacements: int
    true_positive_replacements: int


def _download(language: str, *, allow_download: bool) -> list[dict[str, Any]]:
    path = CACHE_DIR / f"{language}_data.json"
    if not path.exists():
        if not allow_download:
            raise FileNotFoundError(f"Missing benchmark cache: {path}. Re-run without --offline.")
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        print(f"Downloading MultiPriv-PII {language} data ...", file=sys.stderr)
        urllib.request.urlretrieve(DATASETS[language], path)
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _normalized_with_positions(text: str) -> tuple[str, list[int]]:
    """Normalize harmless formatting differences while retaining source indexes."""
    normalized: list[str] = []
    positions: list[int] = []
    for index, character in enumerate(text):
        if not character.isalnum() or character == "和":
            continue
        normalized.append(character.casefold())
        positions.append(index)
    return "".join(normalized), positions


def _value_variants(value: object, field: str) -> tuple[str, ...]:
    raw = str(value).strip()
    variants = [raw]
    if field == "income":
        try:
            amount = float(raw.replace(",", ""))
        except ValueError:
            pass
        else:
            variants.extend(
                (
                    f"{amount / 10_000:g}万元",
                    f"{amount:,.2f}".rstrip("0").rstrip("."),
                    f"{amount:g}",
                )
            )
    return tuple(dict.fromkeys(item for item in variants if item))


def _find_value_span(paragraph: str, value: object, field: str) -> tuple[int, int] | None:
    normalized_paragraph, positions = _normalized_with_positions(paragraph)
    for variant in _value_variants(value, field):
        normalized_value, _ = _normalized_with_positions(variant)
        if not normalized_value:
            continue
        offset = normalized_paragraph.find(normalized_value)
        if offset >= 0:
            return positions[offset], positions[offset + len(normalized_value) - 1] + 1
    return None


def _ground_truth(record: dict[str, Any]) -> tuple[GroundTruth, ...]:
    paragraph = str(record.get("naturalParagraph") or "")
    truths: list[GroundTruth] = []
    for field in PII_FIELDS:
        value = record.get(field)
        if value is None:
            continue
        span = _find_value_span(paragraph, value, field)
        if span:
            truths.append(GroundTruth(field=field, start=span[0], end=span[1]))
    return tuple(truths)


def _replace_range(
    text: str,
    origins: list[int | None],
    start: int,
    end: int,
    replacement: str,
    operations: list[Replacement],
) -> tuple[str, list[int | None]]:
    covered = [origin for origin in origins[start:end] if origin is not None]
    if covered:
        operations.append(Replacement(start=min(covered), end=max(covered) + 1, placeholder=replacement))
    return text[:start] + replacement + text[end:], origins[:start] + [None] * len(replacement) + origins[end:]


def _redact_regex_with_trace(text: str) -> tuple[str, tuple[Replacement, ...]]:
    """Run the production rule order while retaining original replacement spans."""
    result = text
    origins: list[int | None] = list(range(len(text)))
    operations: list[Replacement] = []

    for pattern, placeholder in _CONTEXT_RULES:
        for match in reversed(list(pattern.finditer(result))):
            start, end = match.span("pii")
            result, origins = _replace_range(result, origins, start, end, placeholder, operations)
    for pattern, placeholder in _REGEX_RULES:
        for match in reversed(list(pattern.finditer(result))):
            result, origins = _replace_range(result, origins, match.start(), match.end(), placeholder, operations)

    production_result, _ = _replace_regex(text)
    if result != production_result:
        raise RuntimeError("Evaluation trace drifted from app.redaction._replace_regex")
    return result, tuple(operations)


def _overlaps(first_start: int, first_end: int, second_start: int, second_end: int) -> bool:
    return first_start < second_end and second_start < first_end


def _evaluate(records: Iterable[dict[str, Any]]) -> tuple[Metrics, dict[str, tuple[int, int]]]:
    expected = recalled = replacements = true_positive_replacements = 0
    per_field: dict[str, list[int]] = {}

    for record in records:
        paragraph = str(record.get("naturalParagraph") or "")
        if not paragraph:
            continue
        redacted, operations = _redact_regex_with_trace(paragraph)
        truths = _ground_truth(record)
        replacements += len(operations)

        for truth in truths:
            field_stat = per_field.setdefault(truth.field, [0, 0])
            expected += 1
            field_stat[0] += 1
            source_value = paragraph[truth.start : truth.end]
            if source_value not in redacted:
                recalled += 1
                field_stat[1] += 1

        for operation in operations:
            if any(_overlaps(operation.start, operation.end, truth.start, truth.end) for truth in truths):
                true_positive_replacements += 1

    precision = true_positive_replacements / replacements if replacements else 0.0
    recall = recalled / expected if expected else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return (
        Metrics(
            precision=precision,
            recall=recall,
            f1=f1,
            expected=expected,
            recalled=recalled,
            replacements=replacements,
            true_positive_replacements=true_positive_replacements,
        ),
        {field: (counts[0], counts[1]) for field, counts in per_field.items()},
    )


def _combine(metrics: Iterable[Metrics]) -> Metrics:
    values = tuple(metrics)
    expected = sum(value.expected for value in values)
    recalled = sum(value.recalled for value in values)
    replacements = sum(value.replacements for value in values)
    true_positives = sum(value.true_positive_replacements for value in values)
    precision = true_positives / replacements if replacements else 0.0
    recall = recalled / expected if expected else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return Metrics(precision, recall, f1, expected, recalled, replacements, true_positives)


def _print_metrics(label: str, metrics: Metrics, fields: dict[str, tuple[int, int]]) -> None:
    print(f"\n{label}")
    print(f"  precision={metrics.precision:.4f}  recall={metrics.recall:.4f}  f1={metrics.f1:.4f}")
    print(
        "  expected={expected} recalled={recalled} replacements={replacements} true_positive_replacements={true_positives}".format(
            expected=metrics.expected,
            recalled=metrics.recalled,
            replacements=metrics.replacements,
            true_positives=metrics.true_positive_replacements,
        )
    )
    print("  Per-field recall:")
    for field, (total, covered) in sorted(fields.items(), key=lambda item: item[1][1] / item[1][0]):
        print(f"    {field:25s} recall={covered / total:.3f}  n={total}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threshold", type=float, default=0.85, help="minimum P/R/F1 gate (default: 0.85)")
    parser.add_argument("--offline", action="store_true", help="fail instead of downloading a missing benchmark cache")
    args = parser.parse_args()
    if not 0 < args.threshold <= 1:
        parser.error("--threshold must be in (0, 1]")

    metrics_by_language: list[Metrics] = []
    for language, label in (("zh", "Chinese"), ("en", "English")):
        metrics, fields = _evaluate(_download(language, allow_download=not args.offline))
        _print_metrics(label, metrics, fields)
        metrics_by_language.append(metrics)

    combined = _combine(metrics_by_language)
    print("\nCombined MultiPriv-PII")
    print(f"  precision={combined.precision:.4f}  recall={combined.recall:.4f}  f1={combined.f1:.4f}")
    passed = min(combined.precision, combined.recall, combined.f1) >= args.threshold
    print(f"  gate={'PASS' if passed else 'FAIL'}  threshold={args.threshold:.2f}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
