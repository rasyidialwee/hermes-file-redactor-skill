"""Local-only HTTP sanitize service. One-way; never exposes mappings."""

from __future__ import annotations

import os
import threading
from typing import Any, Dict, Optional

from .api import sanitize, sanitize_text
from .config import MODES, SanitizerConfig, config_from_mapping
from .models import SanitizationResult

_stats_lock = threading.Lock()
_stats: Dict[str, Any] = {"requests": 0, "categories": {}}


def _record_stats(result: SanitizationResult) -> None:
    with _stats_lock:
        _stats["requests"] += 1
        cats: Dict[str, int] = _stats["categories"]
        for cat in result.categories:
            cats[cat] = cats.get(cat, 0) + 1


def result_to_response(result: SanitizationResult) -> Dict[str, Any]:
    """Public JSON shape: content + metadata, never originals or mappings."""
    return {
        "content": result.content,
        "sanitized": result.sanitized,
        "mode": result.mode,
        "warnings": list(result.warnings),
        "detection_count": result.detection_count,
        "categories": list(result.categories),
        "file_name": result.file_name,
        "metadata": dict(result.metadata),
    }


def get_stats() -> Dict[str, Any]:
    with _stats_lock:
        return {"requests": _stats["requests"], "categories": dict(_stats["categories"])}


def reset_stats() -> None:
    with _stats_lock:
        _stats["requests"] = 0
        _stats["categories"] = {}


def _resolve_mode_config(
    mode: Optional[str], config: Optional[Dict[str, Any]]
) -> SanitizerConfig:
    cfg = config_from_mapping(config) if config else SanitizerConfig()
    if mode is not None:
        if mode not in MODES:
            raise ValueError(f"Invalid mode {mode!r}; expected one of {MODES}")
        cfg = SanitizerConfig(
            mode=mode,
            confidence_threshold=cfg.confidence_threshold,
            max_file_size_mb=cfg.max_file_size_mb,
            max_text_length=cfg.max_text_length,
            custom_rules=list(cfg.custom_rules),
            enable_categories=list(cfg.enable_categories),
            disable_categories=list(cfg.disable_categories),
        )
    return cfg


def create_app():
    """Build FastAPI app. Lazy-import so base install stays light."""
    import tempfile
    from pathlib import Path

    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

    app = FastAPI(
        title="Hermes Document Sanitizer",
        description=(
            "Local-only one-way document sanitizer. "
            "Does not expose placeholder ↔ original mappings."
        ),
        version="0.1.0",
    )
    static_dir = Path(__file__).resolve().parent / "static"

    @app.get("/")
    async def ui():
        page = static_dir / "ui.html"
        if page.is_file():
            return FileResponse(page, media_type="text/html; charset=utf-8")
        return HTMLResponse("<p>UI missing. Rebuild the image / reinstall the package.</p>", status_code=500)

    @app.get("/health")
    async def health():
        return JSONResponse({"status": "ok"})

    @app.get("/v1/stats")
    async def stats():
        return JSONResponse(get_stats())

    async def sanitize_path(request: Request):
        data = await request.json()
        if not isinstance(data, dict) or not data.get("path"):
            raise HTTPException(status_code=422, detail="path is required")
        try:
            cfg = _resolve_mode_config(data.get("mode"), data.get("config"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        result = sanitize(str(data["path"]), config=cfg)
        _record_stats(result)
        return JSONResponse(result_to_response(result))

    async def sanitize_text_endpoint(request: Request):
        data = await request.json()
        if not isinstance(data, dict) or "text" not in data:
            raise HTTPException(status_code=422, detail="text is required")
        try:
            cfg = _resolve_mode_config(data.get("mode"), data.get("config"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        result = sanitize_text(str(data["text"]), config=cfg)
        _record_stats(result)
        return JSONResponse(result_to_response(result))

    async def sanitize_upload(request: Request):
        """Multipart upload for the local preview UI. Writes a temp file, then sanitizes."""
        form = await request.form()
        upload = form.get("file")
        if upload is None or not hasattr(upload, "filename"):
            raise HTTPException(status_code=422, detail="file is required")
        mode = form.get("mode") or "pii"
        if hasattr(mode, "strip"):
            mode = str(mode).strip() or "pii"
        try:
            cfg = _resolve_mode_config(mode, None)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        filename = Path(str(upload.filename or "upload.bin")).name or "upload.bin"
        suffix = Path(filename).suffix
        tmp_path: Optional[Path] = None
        try:
            data = await upload.read()
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(data)
                tmp_path = Path(tmp.name)
            # Keep a stable display name in the result
            result = sanitize(tmp_path, config=cfg)
            # Override file_name for UI (temp names are opaque)
            result.file_name = filename
            _record_stats(result)
            return JSONResponse(result_to_response(result))
        finally:
            if tmp_path is not None:
                try:
                    tmp_path.unlink(missing_ok=True)
                except OSError:
                    pass

    # Force real annotations so FastAPI injects Request (avoids __future__ forward-ref bug).
    sanitize_path.__annotations__ = {"request": Request, "return": Any}
    sanitize_text_endpoint.__annotations__ = {"request": Request, "return": Any}
    sanitize_upload.__annotations__ = {"request": Request, "return": Any}

    app.add_api_route("/v1/sanitize", sanitize_path, methods=["POST"])
    app.add_api_route("/v1/sanitize/text", sanitize_text_endpoint, methods=["POST"])
    app.add_api_route("/v1/sanitize/upload", sanitize_upload, methods=["POST"])
    return app


def validate_bind_host(host: str, *, allow_docker_bind: bool = False) -> str:
    """Refuse non-loopback binds unless running inside Docker (published to 127.0.0.1)."""
    loopback = {"127.0.0.1", "localhost", "::1"}
    docker_ok = {"0.0.0.0", "::"}
    if host in loopback:
        return host
    if allow_docker_bind and host in docker_ok:
        return host
    raise ValueError(
        f"Refuse to bind to {host!r}; use 127.0.0.1 locally, or "
        f"--docker (0.0.0.0) only when published as 127.0.0.1:8765 via compose."
    )


def in_docker() -> bool:
    return (
        os.environ.get("DOCUMENT_SANITIZER_DOCKER", "").lower() in {"1", "true", "yes"}
        or os.path.exists("/.dockerenv")
    )


def run_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    docker: bool = False,
) -> None:
    allow = docker or in_docker()
    if allow and host in {"127.0.0.1", "localhost"}:
        # Inside container, loopback-only would not accept published port traffic.
        host = "0.0.0.0"
    validate_bind_host(host, allow_docker_bind=allow)
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Server extras required: pip install 'hermes-file-redactor[server]'"
        ) from exc
    uvicorn.run(create_app(), host=host, port=port, log_level="info")
