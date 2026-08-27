# Hermes Document Sanitizer

Sanitize local documents/images before their contents reach an LLM. Complements Hermes `security.redact_secrets`; does **not** replace it.

**Two layers:**

| Layer | Role |
|-------|------|
| **Skill** (cooperative) | Agent runs `sanitize.py` when asked |
| **Docker service + Hermes plugin** (enforced) | Rewrites `read_file` / `vision_analyze` results via `http://127.0.0.1:8765` |

One-way placeholders only (`[EMAIL_001]`…). No reverse vault.

---

## Quick start (enforced path)

```bash
# 1. Local sanitizer container (loopback only)
docker compose up -d --build
curl -s http://127.0.0.1:8765/health

# 2. Install Hermes plugin
mkdir -p ~/.hermes/plugins
cp -R plugins/document-sanitizer ~/.hermes/plugins/document-sanitizer
```

Enable in `~/.hermes/config.yaml` — see [plugin-setup.md](skills/document-sanitizer/references/plugin-setup.md).

---

## What this does

| Layer | Hermes core (`agent/redact.py`) | This project |
|-------|----------------------------------|--------------|
| Scope | API keys, JWTs, passwords, tokens | Documents: emails, phones, MyKad, IBAN, cards, RM amounts, custom patterns |
| When | Automatic on tool/log output | Skill (cooperative) **or** plugin (in-path) |
| Formats | Any text | `.txt`, `.md`, `.json`, `.yaml`, `.csv`, `.xml`, `.docx`, `.xlsx`, `.pdf`, images (OCR) |

**Modes:** `off` · `secrets_only` · `pii` (default) · `confidential` · `strict`

Original files are never modified.

---

## Install (Hermes Skills Hub)

```bash
hermes skills tap add <your-github-user>/hermes-file-redactor
hermes skills install <your-github-user>/hermes-file-redactor/document-sanitizer
hermes chat
```

```text
/document-sanitizer
```

Or: *“Use the document-sanitizer skill on invoice.pdf”*

When the **plugin is active**, `read_file` / `vision_analyze` are auto-sanitized; the skill remains useful for explicit runs and CLI.

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

---

## Install (standalone CLI)

```bash
cd hermes-file-redactor
pip install .
pip install ".[pdf]"     # PDF
pip install ".[ocr]"     # image OCR (+ system Tesseract)
pip install ".[server]"  # local serve without Docker
pip install ".[dev]"     # pytest + server extras

document-sanitize path/to/invoice.txt --mode pii
document-sanitize improve --cycles 1
```

---

## Docker service API

| Endpoint | Purpose |
|----------|---------|
| `GET /` | Local upload + preview UI |
| `GET /health` | Liveness |
| `POST /v1/sanitize` | `{ "path": "/abs/path", "mode": "pii" }` (Hermes; needs `$HOME` mount) |
| `POST /v1/sanitize/text` | `{ "text": "...", "mode": "pii" }` |
| `POST /v1/sanitize/upload` | Multipart file upload (preview UI) |
| `GET /v1/stats` | Request counts + category tallies (no reverse lookup) |

`$HOME` and `/tmp` are mounted read-only so Hermes absolute paths work. Docker Desktop will prompt to share your home — **approve for Hermes**. Preview UI works via upload either way.

---

## Limitations

Without the plugin: a skill **cannot** intercept Hermes tools — `read_file` / `@file:` / vision can still leak.

With the plugin: `@file:` expansion and arbitrary `execute_code` reads remain open (Hermes core gaps).

See [threat-model.md](skills/document-sanitizer/references/threat-model.md) and [plugin-setup.md](skills/document-sanitizer/references/plugin-setup.md).

---

## Development

```bash
pip install -e ".[dev]"
pytest -q
document-sanitize improve --cycles 1
```

```text
skills/document-sanitizer/   # skill + library + HTTP server
plugins/document-sanitizer/  # Hermes enforcement plugin
Dockerfile / docker-compose.yml
tests/
```

---

## License

MIT
