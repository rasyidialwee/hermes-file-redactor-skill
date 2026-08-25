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

# Categories users can enable/disable via config or CLI.
KNOWN_CATEGORIES = frozenset(
    {
        "PRIVATE_KEY",
        "JWT",
        "API_KEY",
        "PASSWORD",
        "AUTH_HEADER",
        "DB_URL",
        "EMAIL",
        "MYKAD",
        "IBAN",
        "CREDIT_CARD",
        "PHONE",
        "NAME",
        "AMOUNT",
        "ACCOUNT_NUMBER",
        "INTERNAL_URL",
        "LONG_NUMBER",
    }
)

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
    # If non-empty: only these built-in categories run (plus custom_rules always).
    enable_categories: list[str] = field(default_factory=list)
    # Always skipped even if mode would include them.
    disable_categories: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"Invalid mode {self.mode!r}; expected one of {MODES}")
        if not 0.0 <= self.confidence_threshold <= 1.0:
            raise ValueError("confidence_threshold must be between 0 and 1")
        self.enable_categories = [c.upper() for c in self.enable_categories]
        self.disable_categories = [c.upper() for c in self.disable_categories]

    def category_allowed(self, category: str) -> bool:
        cat = category.upper()
        if cat in self.disable_categories:
            return False
        if self.enable_categories and cat not in self.enable_categories:
            return False
        return True


def _parse_custom_rules(rules_raw: list[Any]) -> list[CustomRule]:
    rules: list[CustomRule] = []
    for item in rules_raw or []:
        if isinstance(item, CustomRule):
            rules.append(item)
            continue
        rules.append(
            CustomRule(
                name=str(item["name"]),
                pattern=str(item["pattern"]),
                replacement=str(item.get("replacement") or f"[{str(item['name']).upper()}]"),
                confidence=float(item.get("confidence", 0.99)),
            )
        )
    return rules


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [p.strip() for p in value.split(",") if p.strip()]
    return [str(x).strip() for x in value if str(x).strip()]


def load_custom_rules(path: str | Path) -> list[CustomRule]:
    """Load custom_rules from a YAML file (legacy helper)."""
    data = _load_yaml(path)
    return _parse_custom_rules(data.get("custom_rules") or data.get("rules") or [])


def load_config_file(path: str | Path) -> SanitizerConfig:
    """Load a full sanitizer config YAML (mode, categories, custom_rules, …)."""
    data = _load_yaml(path)
    # Allow either top-level keys or nested under document_sanitization
    if "document_sanitization" in data and isinstance(data["document_sanitization"], dict):
        data = data["document_sanitization"]
    return config_from_mapping(data)


def _load_yaml(path: str | Path) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("PyYAML is required to load config") from exc
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def config_from_mapping(data: dict[str, Any] | None) -> SanitizerConfig:
    data = data or {}
    return SanitizerConfig(
        mode=str(data.get("mode", DEFAULT_MODE)),
        confidence_threshold=float(data.get("confidence_threshold", DEFAULT_CONFIDENCE)),
        max_file_size_mb=float(data.get("max_file_size_mb", DEFAULT_MAX_FILE_SIZE_MB)),
        max_text_length=int(data.get("max_text_length", DEFAULT_MAX_TEXT_LENGTH)),
        custom_rules=_parse_custom_rules(data.get("custom_rules") or data.get("rules") or []),
        enable_categories=_as_str_list(data.get("enable_categories") or data.get("enable")),
        disable_categories=_as_str_list(data.get("disable_categories") or data.get("disable")),
    )
