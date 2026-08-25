"""Detection and redaction engine."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable

from ..config import CustomRule, SanitizerConfig
from ..models import Detection
from ..session import PlaceholderSession


@dataclass(frozen=True)
class PatternRule:
    category: str
    pattern: re.Pattern[str]
    confidence: float
    validator: Callable[[str], bool] | None = None
    normalize: Callable[[str], str] | None = None


def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _iban_ok(value: str) -> bool:
    compact = re.sub(r"[\s-]+", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    return int(numeric) % 97 == 1


def _mykad_ok(value: str) -> bool:
    m = re.fullmatch(r"(\d{6})-?(\d{2})-?(\d{4})", value.strip())
    if not m:
        return False
    yymmdd, pb, _ = m.groups()
    yy, mm, dd = int(yymmdd[:2]), int(yymmdd[2:4]), int(yymmdd[4:6])
    if not (1 <= mm <= 12 and 1 <= dd <= 31):
        return False
    if not (1 <= int(pb) <= 99):
        return False
    # yy is kept for shape validation only
    _ = yy
    return True


SECRET_RULES: list[PatternRule] = [
    PatternRule(
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            re.MULTILINE,
        ),
        0.99,
    ),
    PatternRule(
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        0.98,
    ),
    PatternRule(
        "API_KEY",
        re.compile(
            r"\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}"
            r"|ghp_[A-Za-z0-9]{20,}"
            r"|github_pat_[A-Za-z0-9_]{20,}"
            r"|xox[baprs]-[A-Za-z0-9-]{10,}"
            r"|AKIA[0-9A-Z]{16}"
            r"|AIza[0-9A-Za-z_-]{20,}"
            r"|xai-[A-Za-z0-9_-]{20,}"
            r"|hf_[A-Za-z0-9]{20,}"
            r"|ntn_[A-Za-z0-9]{20,})\b"
        ),
        0.98,
    ),
    PatternRule(
        "PASSWORD",
        re.compile(
            r"(?i)(?:password|passwd|pwd|secret|client_secret)\s*[:=]\s*[\"']?([^\s\"']{6,})",
        ),
        0.92,
        normalize=lambda m: m,  # full match replaced via group handling below
    ),
    PatternRule(
        "AUTH_HEADER",
        re.compile(r"(?i)(Authorization\s*:\s*(?:Bearer|Basic)\s+)(\S+)"),
        0.97,
    ),
    PatternRule(
        "DB_URL",
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s\"']+",
        ),
        0.95,
    ),
]

PII_RULES: list[PatternRule] = [
    PatternRule(
        "EMAIL",
        # \w includes Unicode letters so non-ASCII local parts are covered
        re.compile(r"(?<!\w)[\w.%+-]+@[\w.-]+\.\w{2,}\b", re.UNICODE),
        0.99,
    ),
    PatternRule(
        "MYKAD",
        re.compile(r"\b\d{6}-?\d{2}-?\d{4}\b"),
        0.95,
        validator=_mykad_ok,
    ),
    PatternRule(
        "IBAN",
        re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b"),
        0.96,
        validator=_iban_ok,
    ),
    PatternRule(
        "CREDIT_CARD",
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        0.94,
        validator=lambda v: _luhn_ok(v) and len(re.sub(r"\D", "", v)) >= 13,
    ),
    PatternRule(
        "PHONE",
        re.compile(
            r"(?<!\w)(?:\+60[\s-]?(?:1[0-9]|[3-9])[\s-]?\d{3,4}[\s-]?\d{3,4}"
            r"|0(?:1[0-9]|[3-9]\d)[\s-]?\d{3,4}[\s-]?\d{3,4}"
            r"|\+[1-9]\d{7,14})(?!\w)"
        ),
        0.90,
    ),
]

CONFIDENTIAL_RULES: list[PatternRule] = [
    PatternRule(
        "AMOUNT",
        re.compile(r"(?i)\b(?:RM|MYR)\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?\b|\b(?:RM|MYR)\s?\d+(?:\.\d{2})?\b"),
        0.88,
    ),
    PatternRule(
        "ACCOUNT_NUMBER",
        re.compile(r"(?i)\b(?:account|acct|a/c)[\s#:.-]*(\d{8,20})\b"),
        0.86,
    ),
]

STRICT_RULES: list[PatternRule] = [
    PatternRule(
        "INTERNAL_URL",
        re.compile(r"\bhttps?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|[\w.-]+\.internal)(?::\d+)?(?:/[^\s\"']*)?"),
        0.87,
    ),
    PatternRule(
        "LONG_NUMBER",
        re.compile(r"\b\d{10,}\b"),
        0.86,
    ),
]


def _mode_rules(mode: str) -> list[PatternRule]:
    if mode == "off":
        return []
    rules = list(SECRET_RULES)
    if mode in ("pii", "confidential", "strict"):
        rules.extend(PII_RULES)
    if mode in ("confidential", "strict"):
        rules.extend(CONFIDENTIAL_RULES)
    if mode == "strict":
        rules.extend(STRICT_RULES)
    return rules


def _password_span(match: re.Match[str]) -> tuple[int, int, str]:
    # Replace only the value portion when group 1 exists
    if match.lastindex and match.lastindex >= 1 and match.group(1):
        return match.start(1), match.end(1), match.group(1)
    return match.start(), match.end(), match.group(0)


def _auth_span(match: re.Match[str]) -> tuple[int, int, str]:
    if match.lastindex and match.lastindex >= 2:
        return match.start(2), match.end(2), match.group(2)
    return match.start(), match.end(), match.group(0)


def _account_span(match: re.Match[str]) -> tuple[int, int, str]:
    if match.lastindex and match.lastindex >= 1:
        return match.start(1), match.end(1), match.group(1)
    return match.start(), match.end(), match.group(0)


_SPECIAL_SPANS = {
    "PASSWORD": _password_span,
    "AUTH_HEADER": _auth_span,
    "ACCOUNT_NUMBER": _account_span,
}


@dataclass
class _Hit:
    start: int
    end: int
    category: str
    value: str
    confidence: float
    fixed_replacement: str | None = None


def _collect_custom_hits(text: str, rules: Iterable[CustomRule], threshold: float) -> list[_Hit]:
    hits: list[_Hit] = []
    for rule in rules:
        if rule.confidence < threshold:
            continue
        try:
            pattern = re.compile(rule.pattern)
        except re.error:
            continue
        for m in pattern.finditer(text):
            hits.append(
                _Hit(
                    start=m.start(),
                    end=m.end(),
                    category=rule.name.upper().replace(" ", "_"),
                    value=m.group(0),
                    confidence=rule.confidence,
                    fixed_replacement=rule.replacement,
                )
            )
    return hits


def _collect_pattern_hits(text: str, rules: Iterable[PatternRule], threshold: float) -> list[_Hit]:
    hits: list[_Hit] = []
    for rule in rules:
        if rule.confidence < threshold:
            continue
        for m in rule.pattern.finditer(text):
            span_fn = _SPECIAL_SPANS.get(rule.category)
            if span_fn:
                start, end, value = span_fn(m)
            else:
                start, end, value = m.start(), m.end(), m.group(0)
            if rule.validator and not rule.validator(value):
                continue
            hits.append(
                _Hit(
                    start=start,
                    end=end,
                    category=rule.category,
                    value=value,
                    confidence=rule.confidence,
                )
            )
    return hits


def _resolve_overlaps(hits: list[_Hit]) -> list[_Hit]:
    """Prefer longer spans, then earlier start, then higher confidence."""
    sorted_hits = sorted(hits, key=lambda h: (-(h.end - h.start), h.start, -h.confidence))
    chosen: list[_Hit] = []
    occupied: list[tuple[int, int]] = []
    for hit in sorted_hits:
        if any(not (hit.end <= a or hit.start >= b) for a, b in occupied):
            continue
        chosen.append(hit)
        occupied.append((hit.start, hit.end))
    return sorted(chosen, key=lambda h: h.start)


def redact_text(
    text: str,
    config: SanitizerConfig,
    session: PlaceholderSession | None = None,
) -> tuple[str, list[Detection]]:
    """Apply custom rules then mode detectors. Returns sanitized text + detections."""
    if config.mode == "off" or not text:
        return text, []

    session = session or PlaceholderSession()
    threshold = config.confidence_threshold

    # Precedence: custom rules first (collected together), then mode detectors.
    # Overlap resolution prefers longer matches.
    hits = _collect_custom_hits(text, config.custom_rules, threshold)
    hits.extend(_collect_pattern_hits(text, _mode_rules(config.mode), threshold))
    resolved = _resolve_overlaps(hits)

    detections: list[Detection] = []
    parts: list[str] = []
    cursor = 0
    for hit in resolved:
        if hit.fixed_replacement is not None:
            placeholder = hit.fixed_replacement
        else:
            placeholder = session.placeholder_for(hit.category, hit.value)
        parts.append(text[cursor : hit.start])
        parts.append(placeholder)
        detections.append(
            Detection(
                category=hit.category,
                start=hit.start,
                end=hit.end,
                confidence=hit.confidence,
                placeholder=placeholder,
            )
        )
        cursor = hit.end
    parts.append(text[cursor:])
    return "".join(parts), detections
