"""Hermes plugin: rewrite tool results through the local document-sanitize service.

Expects the sanitizer at http://127.0.0.1:8765 (typically via ``docker compose up``).

Config (``~/.hermes/config.yaml``)::

    plugins:
      enabled:
        - document-sanitizer
      document_sanitizer:
        service_url: http://127.0.0.1:8765
        enforce: true
        mode: pii
        tools:
          - read_file
          - vision_analyze
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("hermes.plugin.document_sanitizer")

DEFAULT_SERVICE_URL = "http://127.0.0.1:8765"
DEFAULT_TOOLS = ("read_file", "vision_analyze")
FAIL_CLOSED_MSG = (
    "Document sanitization required but service unavailable. "
    "Start with: docker compose up -d  (or document-sanitize serve)"
)

VISION_TOOLS = frozenset({"vision_analyze", "vision", "analyze_image"})
FILE_TOOLS = frozenset({"read_file", "Read", "read_path", "search_files"})
TEXT_TOOLS = frozenset({"terminal", "execute_code"})


def _load_yaml_config() -> dict[str, Any]:
    hermes_home = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
    cfg_path = hermes_home / "config.yaml"
    if not cfg_path.is_file():
        return {}
    try:
        import yaml
    except ImportError:
        return {}
    try:
        data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _plugin_settings(cfg: dict[str, Any]) -> dict[str, Any]:
    plugins = cfg.get("plugins") or {}
    if not isinstance(plugins, dict):
        plugins = {}
    block = plugins.get("document_sanitizer") or plugins.get("document-sanitizer") or {}
    if not isinstance(block, dict):
        block = {}

    skills = cfg.get("skills") or {}
    skill_cfg: dict[str, Any] = {}
    if isinstance(skills, dict):
        nested = skills.get("config") or {}
        if isinstance(nested, dict):
            raw = nested.get("document_sanitization") or {}
            if isinstance(raw, dict):
                skill_cfg = raw

    return {
        "service_url": block.get("service_url")
        or os.environ.get("DOCUMENT_SANITIZER_URL")
        or DEFAULT_SERVICE_URL,
        "enforce": block.get("enforce", True),
        "mode": block.get("mode") or skill_cfg.get("mode") or "pii",
        "tools": block.get("tools") or list(DEFAULT_TOOLS),
        "confidence_threshold": block.get("confidence_threshold")
        or skill_cfg.get("confidence_threshold"),
        "max_file_size_mb": block.get("max_file_size_mb") or skill_cfg.get("max_file_size_mb"),
    }


def _assert_local_url(url: str) -> None:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError(f"service_url must be loopback, got {url!r}")


def _http_json(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 120.0,
) -> dict[str, Any]:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
    return json.loads(body) if body else {}


def _health_ok(service_url: str) -> bool:
    try:
        _assert_local_url(service_url)
        out = _http_json("GET", f"{service_url.rstrip('/')}/health", timeout=5.0)
        return out.get("status") == "ok"
    except Exception as exc:
        logger.debug("sanitize service health failed: %s", exc)
        return False


def _sanitize_path(service_url: str, path: str, mode: str) -> dict[str, Any]:
    return _http_json(
        "POST",
        f"{service_url.rstrip('/')}/v1/sanitize",
        {"path": path, "mode": mode},
    )


def _sanitize_text(service_url: str, text: str, mode: str) -> dict[str, Any]:
    return _http_json(
        "POST",
        f"{service_url.rstrip('/')}/v1/sanitize/text",
        {"text": text, "mode": mode},
    )


def _extract_path(args: Any) -> str | None:
    if not isinstance(args, dict):
        return None
    for key in ("path", "file_path", "filepath", "file", "filename"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def _format_sanitized_payload(data: dict[str, Any], *, source: str) -> str:
    warnings = data.get("warnings") or []
    cats = data.get("categories") or []
    header_bits = [
        f"[document-sanitizer] source={source}",
        f"sanitized={data.get('sanitized')}",
        f"mode={data.get('mode')}",
        f"detections={data.get('detection_count', 0)}",
    ]
    if cats:
        header_bits.append(f"categories={','.join(cats)}")
    lines = [" | ".join(header_bits)]
    for w in warnings:
        lines.append(f"warning: {w}")
    lines.append("")
    lines.append(data.get("content") or "")
    return "\n".join(lines)


def _fail_closed(reason: str) -> str:
    return json.dumps(
        {"success": False, "error": FAIL_CLOSED_MSG, "detail": reason}
    )


def make_transform(settings: dict[str, Any]):
    service_url = str(settings["service_url"]).rstrip("/")
    enforce = bool(settings.get("enforce", True))
    mode = str(settings.get("mode") or "pii")
    tools = {str(t) for t in (settings.get("tools") or DEFAULT_TOOLS)}

    def transform_tool_result(**kwargs: Any) -> str | None:
        tool_name = kwargs.get("tool_name") or kwargs.get("function_name") or ""
        args = kwargs.get("args") or kwargs.get("params") or {}
        result = kwargs.get("result")
        if result is None:
            return None
        if not isinstance(result, str):
            result = str(result)

        if mode == "off" or not enforce:
            return None
        if tool_name not in tools:
            return None

        try:
            _assert_local_url(service_url)
        except ValueError as exc:
            return _fail_closed(str(exc))

        if not _health_ok(service_url):
            return _fail_closed("health check failed — is docker compose up?")

        if tool_name in VISION_TOOLS:
            path = _extract_path(args)
            if path:
                try:
                    data = _sanitize_path(service_url, path, mode)
                    if data.get("sanitized") is False and not data.get("content"):
                        warnings = data.get("warnings") or ["sanitization failed"]
                        return _fail_closed("; ".join(str(w) for w in warnings))
                    return _format_sanitized_payload(data, source=f"vision:{path}")
                except (
                    urllib.error.URLError,
                    urllib.error.HTTPError,
                    TimeoutError,
                    OSError,
                    json.JSONDecodeError,
                ) as exc:
                    return _fail_closed(f"vision sanitize failed: {exc}")
            return _fail_closed(
                "vision_analyze blocked while document sanitization is enforced; "
                "pass an image path so the local service can OCR+sanitize "
                "(Docker must mount that path, usually $HOME)"
            )

        if tool_name in FILE_TOOLS:
            path = _extract_path(args)
            # Prefer path-based sanitize so PDF/DOCX/XLSX/OCR adapters run in the
            # container (Hermes read_file often returns weak/binary text for those).
            if path:
                try:
                    data = _sanitize_path(service_url, path, mode)
                    if data.get("sanitized") is False and not data.get("content"):
                        # Path missing in container (outside mounted HOME) → try tool text.
                        if result.strip():
                            data = _sanitize_text(service_url, result, mode)
                            return _format_sanitized_payload(
                                data, source=f"fallback-text:{path}"
                            )
                        warnings = data.get("warnings") or ["sanitization failed"]
                        return _fail_closed("; ".join(str(w) for w in warnings))
                    return _format_sanitized_payload(data, source=path)
                except (
                    urllib.error.URLError,
                    urllib.error.HTTPError,
                    TimeoutError,
                    OSError,
                    json.JSONDecodeError,
                ) as exc:
                    if result.strip():
                        try:
                            data = _sanitize_text(service_url, result, mode)
                            return _format_sanitized_payload(
                                data, source=f"fallback-text:{path}"
                            )
                        except Exception:
                            pass
                    return _fail_closed(f"path sanitize failed: {exc}")
            if result.strip():
                try:
                    data = _sanitize_text(service_url, result, mode)
                    return _format_sanitized_payload(data, source=f"tool:{tool_name}")
                except (
                    urllib.error.URLError,
                    urllib.error.HTTPError,
                    TimeoutError,
                    OSError,
                    json.JSONDecodeError,
                ) as exc:
                    return _fail_closed(f"text sanitize failed: {exc}")
            return None

        if tool_name in TEXT_TOOLS:
            if not result.strip():
                return None
            try:
                data = _sanitize_text(service_url, result, mode)
                return _format_sanitized_payload(data, source=f"tool:{tool_name}")
            except (
                urllib.error.URLError,
                urllib.error.HTTPError,
                TimeoutError,
                OSError,
                json.JSONDecodeError,
            ) as exc:
                return _fail_closed(f"text sanitize failed: {exc}")

        return None

    return transform_tool_result


def register(ctx: Any) -> None:
    cfg = _load_yaml_config()
    settings = _plugin_settings(cfg)
    ctx.register_hook("transform_tool_result", make_transform(settings))
    logger.info(
        "document-sanitizer plugin registered enforce=%s mode=%s url=%s tools=%s",
        settings.get("enforce"),
        settings.get("mode"),
        settings.get("service_url"),
        settings.get("tools"),
    )
