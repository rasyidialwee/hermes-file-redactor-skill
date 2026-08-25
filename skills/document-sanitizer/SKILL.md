---
name: document-sanitizer
description: Sanitize local documents before LLM context.
version: 0.1.0
author: rasyidialwee
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [Security, Privacy, Redaction, PII, Documents]
    category: security
    config:
      - key: document_sanitization.mode
        description: Sanitization mode (off, secrets_only, pii, confidential, strict)
        default: "pii"
        prompt: Document sanitization mode
      - key: document_sanitization.confidence_threshold
        description: Minimum detector confidence from 0 to 1
        default: "0.85"
        prompt: Confidence threshold
      - key: document_sanitization.max_file_size_mb
        description: Maximum file size in megabytes
        default: "25"
        prompt: Max file size (MB)
---

# Document Sanitizer Skill

Sanitize local files before their contents reach the model. Complements Hermes `security.redact_secrets`. Does not replace it. Original files are never modified.

**This skill is cooperative.** It cannot intercept `read_file`, `terminal`, `execute_code`, `@file:`, or vision. Follow the procedure below or unsanitized content can leak.

## When to Use

- User asks to sanitize, redact, anonymize, or scrub a document before analysis
- Task involves invoices, contracts, HR files, customer exports, ID scans, or logs with PII
- Mode is `pii` / `confidential` / `strict` and a local file must enter context

Don't use for: encrypting secrets for later recovery; replacing Hermes core secret redaction; claiming full DLP without sandboxing.

## Prerequisites

- Python 3.11+
- Skill scripts at `${HERMES_SKILL_DIR}/scripts/`
- Optional PDF: `pip install pypdf`
- Optional OCR: install Tesseract + `pip install Pillow pytesseract`

For configuration details see `references/configuration.md`. For bypasses see `references/threat-model.md`.

## How to Run

```bash
terminal(command="python \"${HERMES_SKILL_DIR}/scripts/sanitize.py\" \"/path/to/file\" --mode pii", timeout=120)
```

Custom rules:

```bash
terminal(command="python \"${HERMES_SKILL_DIR}/scripts/sanitize.py\" \"/path/to/file\" --mode pii --custom-rules \"${HERMES_SKILL_DIR}/templates/custom_rules.yaml\"", timeout=120)
```

Standalone after `pip install .`:

```bash
document-sanitize /path/to/file --mode pii
```

## Procedure

1. Resolve mode from skill config (`document_sanitization.mode`, default `pii`) or the user request. Completion: mode is one of `off|secrets_only|pii|confidential|strict`.
2. Run `sanitize.py` on the file via `terminal`. Do **not** use `read_file`, `search_files`, `cat`, `type`, `grep`, or `execute_code` on the original first. Completion: command exits; stdout shows sanitized content or a fail-closed warning.
3. Use **only** the sanitizer stdout (or `--json` `content` field) in further reasoning. Completion: no original sensitive values appear in your tool calls.
4. If warnings include `[UNSANITIZED_IMAGE_CONTENT]` or OCR/PDF dependency errors, tell the user and stop rather than reading the raw file. Completion: user is informed; raw file not loaded.
5. For images in `pii` / `confidential` / `strict`: never call `vision_analyze` or attach original image bytes. Use OCR text from the sanitizer only. Completion: no multimodal image part for the original.
6. Never use `@file:path` on sensitive documents while this skill is active. Completion: no `@file:` expansion of the source.
7. Never print, log, or invent placeholder mappings (`[EMAIL_001] = ...`). Completion: mappings absent from replies.

## Quick Reference

| Mode | What it redacts |
|------|-----------------|
| `off` | Nothing |
| `secrets_only` | API keys, JWT, PEM, passwords, auth headers, DB URLs |
| `pii` | + email, phone (incl. MY), MyKad, IBAN, credit cards |
| `confidential` | + RM/MYR amounts, account-like numbers |
| `strict` | + internal URLs, long numbers; hard image-byte block |

Names with BIN/BINTI/A/P/A/L are redacted in `pii` mode as `[NAME_001]`. Other names need custom rules (see `templates/custom_rules.yaml`). Use `--config`, `--enable`, or `--disable` to choose categories before a run.

## Pitfalls

- Hermes Hub only installs files referenced from this skill. Keep using `${HERMES_SKILL_DIR}/scripts/sanitize.py` so the package tree is included.
- Archives (`.zip`/`.tar`/`.gz`) fail closed — extract first.
- `read_file` on `.docx`/`.xlsx` bypasses this skill; always prefer `sanitize.py`.
- `--show-original` is debug-only and unsafe; never use it in normal agent runs.
- Missing Tesseract → image sanitization fails closed (good); do not fall back to raw pixels.

## Verification

- Original file size/mtime unchanged after a run
- Sanitizer output contains placeholders, not raw emails/phones/keys from the fixture
- Logs never contain original values (only counts/categories)
- Unsupported formats produce `sanitized=false` and empty content, not raw bytes

Engine modules (Hub must copy with the skill):

- `scripts/sanitize.py`
- `scripts/document_sanitizer/` (api, adapters, detectors, config, models, session, cli, logging_util)
- `references/threat-model.md`
- `references/configuration.md`
- `templates/custom_rules.yaml`
- `templates/sanitize.config.yaml`
