"""Configuration for document sanitization."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MODES = ("off", "secrets_only", "pii", "confidential", "strict")

DEFAULT_MODE = "pii"
DEFAULT_CONFIDENCE = 0.85
DEFAULT_MAX_FILE_SIZE_MB = 25
DEFAULT_MAX_TEXT_LENGTH = 2_000_000

ARCHIVE_EXTENSIONS = frozenset({".zip", ".tar", ".gz", ".tgz", ".tar.gz", ".7z", ".rar"})


@dataclass
class CustomRule:
    name: str
    pattern: str
    replacement: str
    confidence: float = 0.99


@dataclass
class SanitizerConfig:
    mode: str = DEFAULT_MODE
    confidence_threshold: float = DEFAULT_CONFIDENCE
    max_file_size_mb: float = DEFAULT_MAX_FILE_SIZE_MB
    max_text_length: int = DEFAULT_MAX_TEXT_LENGTH
    custom_rules: list[CustomRule] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"Invalid mode {self.mode!r}; expected one of {MODES}")
        if not 0.0 <= self.confidence_threshold <= 1.0:
            raise ValueError("confidence_threshold must be between 0 and 1")


def load_custom_rules(path: str | Path) -> list[CustomRule]:
    """Load custom rules from a YAML file."""
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("PyYAML is required to load custom rules") from exc

    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    rules_raw = data.get("custom_rules") or data.get("rules") or []
    rules: list[CustomRule] = []
    for item in rules_raw:
        rules.append(
            CustomRule(
                name=str(item["name"]),
                pattern=str(item["pattern"]),
                replacement=str(item.get("replacement") or f"[{str(item['name']).upper()}]"),
                confidence=float(item.get("confidence", 0.99)),
            )
        )
    return rules


def config_from_mapping(data: dict[str, Any] | None) -> SanitizerConfig:
    data = data or {}
    rules = []
    for item in data.get("custom_rules") or []:
        if isinstance(item, CustomRule):
            rules.append(item)
        else:
            rules.append(
                CustomRule(
                    name=str(item["name"]),
                    pattern=str(item["pattern"]),
                    replacement=str(item.get("replacement") or f"[{str(item['name']).upper()}]"),
                    confidence=float(item.get("confidence", 0.99)),
                )
            )
    return SanitizerConfig(
        mode=str(data.get("mode", DEFAULT_MODE)),
        confidence_threshold=float(data.get("confidence_threshold", DEFAULT_CONFIDENCE)),
        max_file_size_mb=float(data.get("max_file_size_mb", DEFAULT_MAX_FILE_SIZE_MB)),
        max_text_length=int(data.get("max_text_length", DEFAULT_MAX_TEXT_LENGTH)),
        custom_rules=rules,
    )
