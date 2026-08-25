# Hermes Document Sanitizer

A **Hermes Agent skill** that sanitizes local documents before their contents reach an LLM. It removes or anonymizes sensitive information (secrets, PII, confidential business data) while preserving useful structure.

This complements Hermes’s built-in secret redactor (`security.redact_secrets`). It does **not** replace it.

---

## What this does

| Layer | Hermes core (`agent/redact.py`) | This skill |
|-------|----------------------------------|------------|
| Scope | API keys, JWTs, passwords, tokens | Documents: emails, phones, MyKad, IBAN, cards, RM amounts, custom patterns |
| When | Automatic on tool output | Agent runs the sanitizer **before** sharing file content |
| Formats | Any text | `.txt`, `.md`, `.json`, `.yaml`, `.csv`, `.xml`, `.docx`, `.xlsx`, `.pdf`, images (OCR) |
| Enforcement | Core hook | Cooperative — agent must follow the skill |

**Modes:** `off` · `secrets_only` · `pii` (default) · `confidential` · `strict`

Replacements use typed placeholders (`[EMAIL_001]`, `[MYKAD_001]`, …) with stable IDs within one run. Original files are never modified.

---

## Install (Hermes Skills Hub)

```bash
# Add this repo as a tap (replace with your GitHub user/org)
hermes skills tap add <your-github-user>/hermes-file-redactor

# Install the skill
hermes skills install <your-github-user>/hermes-file-redactor/document-sanitizer

# New session so Hermes reloads skills
hermes chat
```

In chat:

```text
/document-sanitizer
```

Or: *“Use the document-sanitizer skill on invoice.pdf”*

### Configure (optional)

```yaml
# ~/.hermes/config.yaml
skills:
  config:
    document_sanitization:
      mode: pii
      confidence_threshold: 0.85
      max_file_size_mb: 25
```

```bash
hermes config set skills.config.document_sanitization.mode pii
```

---

## Install (standalone CLI)

```bash
cd hermes-file-redactor
pip install .

# Optional extras
pip install ".[pdf]"    # PDF extraction
pip install ".[ocr]"    # image OCR (also needs system Tesseract)
pip install ".[dev]"    # pytest + extras

document-sanitize path/to/invoice.txt --mode pii
```

Without installing, from the skill scripts directory:

```bash
python skills/document-sanitizer/scripts/sanitize.py path/to/file.txt --mode pii
```

---

## Quick example

```bash
echo "Contact jane@example.com or +60123456789" > sample.txt
document-sanitize sample.txt --mode pii
```

Expected shape:

```text
Document: sample.txt
Mode: pii
Detections: 2
Categories: EMAIL, PHONE

Sanitized content:

Contact [EMAIL_001] or [PHONE_001]
```

---

## Limitations

A skill **cannot** intercept Hermes tools at the LLM boundary. If the agent uses `read_file`, `cat`, `@file:`, or `vision_analyze` on a sensitive file, content can still leak.

Names and street addresses are **not** auto-detected — use custom rules (`skills/document-sanitizer/templates/custom_rules.yaml`).

Archives (`.zip`/`.tar`/`.gz`) fail closed. Extract files first.

See [skills/document-sanitizer/references/threat-model.md](skills/document-sanitizer/references/threat-model.md).

---

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

Layout:

```text
skills/document-sanitizer/
  SKILL.md
  scripts/sanitize.py
  scripts/document_sanitizer/   # library + CLI
  references/
  templates/
tests/
```

---

## License

MIT
