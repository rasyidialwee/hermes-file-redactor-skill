"""Safe logging — never log original values or mappings."""

from __future__ import annotations

import logging

from .models import SanitizationResult

logger = logging.getLogger("document_sanitizer")


def log_sanitization_result(result: SanitizationResult) -> None:
    categories = ",".join(result.categories) if result.categories else "none"
    logger.info(
        "Document sanitized: file=%s mode=%s detections=%s categories=%s",
        result.file_name or "(text)",
        result.mode,
        result.detection_count,
        categories,
    )
    for warning in result.warnings:
        logger.warning("Document sanitization warning: file=%s detail=%s", result.file_name or "(text)", warning)
