"""CLI for document sanitization. Never prints originals by default."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .api import sanitize
from .config import MODES, load_custom_rules, SanitizerConfig


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="document-sanitize",
        description="Sanitize a local document for LLM use. Original file is never modified.",
    )
    p.add_argument("path", type=Path, help="Path to the document")
    p.add_argument(
        "--mode",
        choices=MODES,
        default="pii",
        help="Sanitization mode (default: pii)",
    )
    p.add_argument(
        "--confidence-threshold",
        type=float,
        default=0.85,
        help="Minimum detector confidence (default: 0.85)",
    )
    p.add_argument(
        "--custom-rules",
        type=Path,
        help="YAML file with custom_rules list",
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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    custom = load_custom_rules(args.custom_rules) if args.custom_rules else []
    config = SanitizerConfig(
        mode=args.mode,
        confidence_threshold=args.confidence_threshold,
        custom_rules=custom,
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
