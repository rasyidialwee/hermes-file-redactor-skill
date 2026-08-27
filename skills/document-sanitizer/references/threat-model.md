# Threat model — Document Sanitizer

## Goal

Prevent sensitive content from local documents/images from entering LLM context.

```text
Original document
      ↓
Local sanitizer (CLI skill · or Docker service on 127.0.0.1:8765)
      ↓
Typed placeholders [EMAIL_001] …  (one-way; session cleared)
      ↓
LLM context
```

## Enforcement modes

| Mode | Protection |
|------|------------|
| **Skill only** (cooperative) | Safe only if the agent runs `sanitize.py` and does not bypass |
| **Docker service + Hermes plugin** | `read_file` / `vision_analyze` (configured tools) rewritten in-path via `transform_tool_result`; fail-closed if service down |

## Protected

- Sanitizer stdout / service JSON for supported formats
- Original files never modified
- Placeholder ↔ original mappings never returned (API, logs, plugin)
- Fail-closed on unsupported formats, archives, oversized files, missing OCR
- Docker: host publish bound to `127.0.0.1` only; container may listen on `0.0.0.0` internally
- Write-only `/v1/stats` (counts/categories only)

## Not protected (remaining gaps)

| Bypass | Why |
|--------|-----|
| `@file:` user message expansion | Hermes inlines raw text before tools/plugin |
| `execute_code` `open(...)` | Arbitrary reads unless tool is listed + text-sanitized |
| Agent ignoring skill (no plugin) | Cooperative control only |
| Names / street addresses (non BIN/BINTI) | Weak regex coverage |
| OCR mistakes | Missed text in images/PDFs |
| Archives | Fail closed; extract first |
| Compromised host / Docker escape | Out of scope |

With plugin **enabled** and service **up**, these skill-era bypasses are closed for listed tools:

- `read_file` / `search_files` (when listed)
- `vision_analyze` (blocked or OCR+sanitize via path)

## Secret redaction vs document sanitization

| | Hermes `agent/redact.py` | This project |
|--|--------------------------|--------------|
| Layer | Core tool/log output | Document/image pre-context |
| Focus | Credentials / tokens | Documents + PII + custom rules |
| Enforcement | Automatic | Skill (opt-in) and/or plugin (enforce) |

This project does **not** disable or weaken Hermes secret redaction.

## Logging / audit policy

Allowed: `file=… mode=… detections=N categories=EMAIL,PHONE` and `/v1/stats` aggregates.

Forbidden: original values, mappings, reverse-lookup HTTP APIs.

## Improve loop

`document-sanitize improve` runs fixtures and reports **leaks** / **false positives**. Coverage is a test result, not a marketing claim.
