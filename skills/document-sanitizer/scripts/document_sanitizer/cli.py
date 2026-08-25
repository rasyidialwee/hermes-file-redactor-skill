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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="document-sanitize",
        description="Sanitize a local document for LLM use. Original file is never modified.",
    )
    p.add_argument("path", type=Path, nargs="?", help="Path to the document")
    p.add_argument(
        "--mode",
        choices=MODES,
        default=None,
        help="Sanitization mode (default: pii, or value from --config)",
    )
    p.add_argument(
        "--config",
        type=Path,
        help="YAML config file (mode, enable/disable categories, custom_rules)",
    )
    p.add_argument(
        "--confidence-threshold",
        type=float,
        default=None,
        help="Minimum detector confidence (default: 0.85)",
    )
    p.add_argument(
        "--custom-rules",
        type=Path,
        help="YAML file with custom_rules list (merged with --config rules)",
    )
    p.add_argument(
        "--enable",
        type=str,
        default=None,
        help=(
            "Comma-separated categories to run ONLY "
            f"(e.g. NAME,MYKAD,EMAIL). Known: {', '.join(sorted(KNOWN_CATEGORIES))}"
        ),
    )
    p.add_argument(
        "--disable",
        type=str,
        default=None,
        help="Comma-separated categories to skip (e.g. PHONE,AMOUNT)",
    )
    p.add_argument(
        "--list-categories",
        action="store_true",
        help="Print known detector categories and exit",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON (content + metadata; no original values)",
    )
    p.add_argument(
        "--show-original",
        action="store_true",
        help="DANGEROUS: also print original file text. Opt-in debug only.",
    )
    return p


def _split_cats(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [p.strip().upper() for p in raw.split(",") if p.strip()]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_categories:
        print("Known categories:")
        for cat in sorted(KNOWN_CATEGORIES):
            print(f"  {cat}")
        return 0

    if args.path is None:
        build_parser().error("path is required (unless --list-categories)")

    config = load_config_file(args.config) if args.config else SanitizerConfig()

    if args.mode is not None:
        config.mode = args.mode
    if args.confidence_threshold is not None:
        config.confidence_threshold = args.confidence_threshold
    if args.enable is not None:
        config.enable_categories = _split_cats(args.enable)
    if args.disable is not None:
        # merge with any disables from config file
        config.disable_categories = list(
            dict.fromkeys(config.disable_categories + _split_cats(args.disable))
        )
    if args.custom_rules:
        config.custom_rules = list(config.custom_rules) + load_custom_rules(args.custom_rules)

    # Re-validate after mutations
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
        print(
            "WARNING: --show-original may expose sensitive information.",
            file=sys.stderr,
        )
        try:
            original = args.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            original = "<unable to read as text>"
        print("=== ORIGINAL (debug) ===")
        print(original)
        print("=== END ORIGINAL ===\n")

    if args.json:
        payload = {
            "file": result.file_name,
            "mode": result.mode,
            "sanitized": result.sanitized,
            "detections": result.detection_count,
            "categories": result.categories,
            "warnings": result.warnings,
            "metadata": result.metadata,
            "content": result.content,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
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


if __name__ == "__main__":
    raise SystemExit(main())
