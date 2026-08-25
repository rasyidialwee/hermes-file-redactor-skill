# Threat model — Document Sanitizer

## Goal

Prevent sensitive content from local documents from entering LLM context when the agent follows this skill.

```text
Original document
      ↓
Document extraction (read-only)
      ↓
Sensitive-data detection (local regex / structure)
      ↓
Sanitization (typed placeholders)
      ↓
LLM context  ← only sanitized text should arrive via this skill
```

## Protected (when the agent follows the skill)

- Sanitizer stdout for supported formats
- Original files never modified
- Placeholder ↔ original mappings never returned in results or default logs
- Fail-closed on unsupported formats, archives, oversized files, missing OCR
- Secrets + configured PII detectors as implemented

## Not protected (skill limitation)

| Bypass | Why |
|--------|-----|
| `read_file` / `search_files` | Hermes tools return content without this sanitizer |
| `terminal` (`cat`, `type`, `grep`) | Only Hermes secret redaction applies |
| `execute_code` `open(...)` | Arbitrary reads → stdout |
| `@file:` user message expansion | Inlines raw text; may skip even secret redaction |
| `vision_analyze` / image attachments | Raw pixels reach multimodal models |
| Tool-result spill re-read | Large outputs may be re-opened from disk |
| Agent ignoring the skill | Cooperative control only |
| Names / street addresses | Not auto-detected in v1 |
| OCR mistakes | Missed text in images/PDFs |
| Archives | Not supported; must extract manually |

## Secret redaction vs document sanitization

| | Hermes `agent/redact.py` | This skill |
|--|--------------------------|------------|
| Layer | Core tool/log output | Pre-read document workflow |
| Default | On (`security.redact_secrets`) | Opt-in via skill use |
| Focus | Credentials / tokens | Documents + PII + custom rules |
| Enforcement | Automatic | Agent must run `sanitize.py` |

This skill does **not** disable or weaken Hermes secret redaction.

## Future harder enforcement

A Hermes core hook in `agent/tool_executor.py` (before `make_tool_result_message`) plus `@file` / vision gating would be required for enforced DLP. Out of scope for this skill repo.

## Logging policy

Allowed: `file=… mode=… detections=N categories=EMAIL,PHONE`

Forbidden: original values, mappings, sample PII in log lines.
