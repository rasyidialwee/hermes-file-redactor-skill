"""Public sanitize API."""

from __future__ import annotations

from pathlib import Path

from .adapters import (
    ArchiveNotSupportedError,
    FileTooLargeError,
    UnsupportedFormatError,
    extract_document,
    sanitize_extracted,
)
from .config import SanitizerConfig, config_from_mapping
from .logging_util import log_sanitization_result
from .models import SanitizationResult
from .session import PlaceholderSession


def sanitize(
    file_path: str | Path,
    mode: str | None = None,
    *,
    config: SanitizerConfig | dict | None = None,
) -> SanitizationResult:
    """Sanitize a local file. Never modifies the original.

    Returns SanitizationResult without original sensitive values or mappings.
    """
    path = Path(file_path)
    cfg = _resolve_config(mode, config)
    session = PlaceholderSession()
    file_name = path.name

    if cfg.mode == "off":
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            content = ""
        result = SanitizationResult(
            content=content,
            detections=[],
            warnings=["mode=off; no document sanitization applied"],
            sanitized=False,
            mode=cfg.mode,
            file_name=file_name,
        )
        log_sanitization_result(result)
        session.clear()
        return result

    try:
        original_stat = path.stat()
        extracted = extract_document(path, cfg)
        content, detections, warnings = sanitize_extracted(extracted, cfg, session)
        # Integrity: original untouched
        after = path.stat()
        if (after.st_mtime_ns, after.st_size) != (original_stat.st_mtime_ns, original_stat.st_size):
            warnings.append("Original file metadata changed unexpectedly during sanitization")
        result = SanitizationResult(
            content=content,
            detections=detections,
            warnings=warnings,
            sanitized=True,
            mode=cfg.mode,
            file_name=file_name,
            metadata={
                "block_original_bytes": extracted.block_original_bytes,
                "content_type": extracted.content_type,
            },
        )
    except (UnsupportedFormatError, FileTooLargeError, ArchiveNotSupportedError, FileNotFoundError) as exc:
        result = SanitizationResult(
            content="",
            detections=[],
            warnings=[str(exc)],
            sanitized=False,
            mode=cfg.mode,
            file_name=file_name,
            metadata={"error": type(exc).__name__},
        )
    finally:
        session.clear()

    log_sanitization_result(result)
    return result


def sanitize_text(
    text: str,
    mode: str | None = None,
    *,
    config: SanitizerConfig | dict | None = None,
) -> SanitizationResult:
    """Sanitize an in-memory text blob."""
    from .detectors import redact_text

    cfg = _resolve_config(mode, config)
    session = PlaceholderSession()
    if cfg.mode == "off":
        result = SanitizationResult(content=text, sanitized=False, mode="off", warnings=["mode=off"])
        session.clear()
        return result
    if len(text) > cfg.max_text_length:
        result = SanitizationResult(
            content="",
            sanitized=False,
            mode=cfg.mode,
            warnings=[f"Text exceeds max_text_length={cfg.max_text_length}"],
            metadata={"error": "FileTooLargeError"},
        )
        session.clear()
        log_sanitization_result(result)
        return result
    content, detections = redact_text(text, cfg, session)
    result = SanitizationResult(
        content=content,
        detections=detections,
        sanitized=True,
        mode=cfg.mode,
    )
    session.clear()
    log_sanitization_result(result)
    return result


def _resolve_config(mode: str | None, config: SanitizerConfig | dict | None) -> SanitizerConfig:
    if isinstance(config, SanitizerConfig):
        cfg = config
    elif isinstance(config, dict):
        cfg = config_from_mapping(config)
    else:
        cfg = SanitizerConfig()
    if mode is not None:
        cfg = SanitizerConfig(
            mode=mode,
            confidence_threshold=cfg.confidence_threshold,
            max_file_size_mb=cfg.max_file_size_mb,
            max_text_length=cfg.max_text_length,
            custom_rules=list(cfg.custom_rules),
        )
    return cfg
