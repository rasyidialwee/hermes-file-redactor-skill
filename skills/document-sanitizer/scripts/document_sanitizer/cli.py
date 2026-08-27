"""CLI for document sanitization. Never prints originals by default."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .api import sanitize
from .config import (
    KNOWN_CATEGORIES,
    MODES,
    SanitizerConfig,
    load_config_file,
    load_custom_rules,
)


def _split_cats(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [p.strip().upper() for p in raw.split(",") if p.strip()]


def _build_sanitize_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="document-sanitize",
        description="Sanitize a local document for LLM use. Original file is never modified.",
    )
    p.add_argument("path", type=Path, nargs="?", help="Path to the document")
    p.add_argument("--mode", choices=MODES, default=None)
    p.add_argument("--config", type=Path)
    p.add_argument("--confidence-threshold", type=float, default=None)
    p.add_argument("--custom-rules", type=Path)
    p.add_argument("--enable", type=str, default=None)
    p.add_argument("--disable", type=str, default=None)
    p.add_argument("--list-categories", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--show-original", action="store_true")
    return p


def _build_serve_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="document-sanitize serve",
        description="Run sanitize HTTP service (prefer: docker compose up).",
    )
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument(
        "--docker",
        action="store_true",
        help="Allow 0.0.0.0 bind for container use (compose must publish 127.0.0.1 only)",
    )
    return p


def _build_improve_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="document-sanitize improve")
    p.add_argument("--cycles", type=int, default=1)
    p.add_argument("--verbose", action="store_true")
    return p


def _cmd_serve(argv: list[str]) -> int:
    args = _build_serve_parser().parse_args(argv)
    from .server import run_server, validate_bind_host

    host = args.host
    if args.docker and host in {"127.0.0.1", "localhost"}:
        host = "0.0.0.0"
    try:
        validate_bind_host(host, allow_docker_bind=args.docker)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    run_server(host=host, port=args.port, docker=args.docker)
    return 0


def _cmd_improve(argv: list[str]) -> int:
    args = _build_improve_parser().parse_args(argv)
    try:
        from fixtures.documents import ALL_FIXTURES  # type: ignore
    except ImportError:
        root = Path(__file__).resolve().parents[4]
        tests = root / "tests"
        if str(tests) not in sys.path:
            sys.path.insert(0, str(tests))
        try:
            from fixtures.documents import ALL_FIXTURES  # type: ignore
        except ImportError:
            print("Could not load tests/fixtures/documents.py", file=sys.stderr)
            return 2

    from .improve import run_improve

    _, clean = run_improve(ALL_FIXTURES, cycles=args.cycles, verbose=args.verbose)
    return 0 if clean else 1


def _cmd_sanitize(argv: list[str]) -> int:
    args = _build_sanitize_parser().parse_args(argv)

    if args.list_categories:
        print("Known categories:")
        for cat in sorted(KNOWN_CATEGORIES):
            print(f"  {cat}")
        return 0

    if args.path is None:
        _build_sanitize_parser().error("path is required (unless --list-categories)")

    config = load_config_file(args.config) if args.config else SanitizerConfig()
    if args.mode is not None:
        config.mode = args.mode
    if args.confidence_threshold is not None:
        config.confidence_threshold = args.confidence_threshold
    if args.enable is not None:
        config.enable_categories = _split_cats(args.enable)
    if args.disable is not None:
        config.disable_categories = list(
            dict.fromkeys(config.disable_categories + _split_cats(args.disable))
        )
    if args.custom_rules:
        config.custom_rules = list(config.custom_rules) + load_custom_rules(args.custom_rules)

    config = SanitizerConfig(
        mode=config.mode,
        confidence_threshold=config.confidence_threshold,
        max_file_size_mb=config.max_file_size_mb,
        max_text_length=config.max_text_length,
        custom_rules=list(config.custom_rules),
        enable_categories=list(config.enable_categories),
        disable_categories=list(config.disable_categories),
    )

    result = sanitize(args.path, config=config)

    if args.show_original:
        print("WARNING: --show-original may expose sensitive information.", file=sys.stderr)
        try:
            original = args.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            original = "<unable to read as text>"
        print("=== ORIGINAL (debug) ===")
        print(original)
        print("=== END ORIGINAL ===\n")

    if args.json:
        print(
            json.dumps(
                {
                    "file": result.file_name,
                    "mode": result.mode,
                    "sanitized": result.sanitized,
                    "detections": result.detection_count,
                    "categories": result.categories,
                    "warnings": result.warnings,
                    "metadata": result.metadata,
                    "content": result.content,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(f"Document: {result.file_name}")
        print(f"Mode: {result.mode}")
        print(f"Detections: {result.detection_count}")
        if result.categories:
            print(f"Categories: {', '.join(result.categories)}")
        if result.warnings:
            print("Warnings:")
            for w in result.warnings:
                print(f"  - {w}")
        print()
        print("Sanitized content:")
        print()
        print(result.content)

    return 0 if result.sanitized or result.mode == "off" else 2


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "serve":
        return _cmd_serve(argv[1:])
    if argv and argv[0] == "improve":
        return _cmd_improve(argv[1:])
    if argv and argv[0] in ("-h", "--help"):
        print(
            "usage: document-sanitize {serve,improve} ... | document-sanitize PATH [options]\n"
            "\n"
            "Commands:\n"
            "  serve     Run HTTP sanitize service (prefer docker compose up)\n"
            "  improve   Run fixture improve loop (leaks / false positives)\n"
            "\n"
            "Default: sanitize a local file.\n"
        )
        return 0
    return _cmd_sanitize(argv)


def build_parser() -> argparse.ArgumentParser:
    return _build_sanitize_parser()


if __name__ == "__main__":
    raise SystemExit(main())
