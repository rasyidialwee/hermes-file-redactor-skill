# Plugin + Docker setup

Enforce document sanitization in Hermes by running the sanitizer as a **local Docker service** and installing the Hermes plugin that rewrites tool results before they reach the model.

## Architecture

```text
Hermes tool (read_file / vision_analyze)
        ↓
document-sanitizer plugin (transform_tool_result)
        ↓
http://127.0.0.1:8765  ← Docker publishes only loopback
        ↓
sanitized text → model provider
```

One-way only: placeholders like `[EMAIL_001]`. No reverse vault.

## 1. Start the sanitizer (Docker)

From this repo:

```bash
docker compose up -d --build
curl -s http://127.0.0.1:8765/health
# {"status":"ok"}
```

**Docker Desktop will ask to share your home directory** — approve it. Hermes sends absolute paths like `/Users/you/invoice.pdf`; the container needs the same path (read-only) so PDF/DOCX/OCR extraction works. Without that share, path-based sanitize fails for files under `$HOME`.

Compose publishes **`127.0.0.1:8765` only**.

### Local preview (before Hermes)

Open **http://127.0.0.1:8765/** — upload a file, pick a mode, compare original vs sanitized. Upload does not depend on the home mount (bytes go in the request).

Stop:

```bash
docker compose down
```

Fallback without Docker (dev only):

```bash
pip install ".[server,pdf,ocr]"
document-sanitize serve --host 127.0.0.1 --port 8765
```

## 2. Install the Hermes plugin

```bash
mkdir -p ~/.hermes/plugins
cp -R plugins/document-sanitizer ~/.hermes/plugins/document-sanitizer
```

Enable in `~/.hermes/config.yaml`:

```yaml
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

skills:
  config:
    document_sanitization:
      mode: pii
      confidence_threshold: 0.85
```

Restart Hermes so plugins reload.

## 3. Verify

With the container healthy, ask Hermes to `read_file` a text file containing a fake email. The tool result should show `[EMAIL_001]` (and a `[document-sanitizer]` header), not the raw address.

If the container is down and `enforce: true`, the plugin **fail-closes** (error JSON) instead of passing raw content.

## Write-only stats

```bash
curl -s http://127.0.0.1:8765/v1/stats
# {"requests":N,"categories":{"EMAIL":…}}
```

No endpoint returns original ↔ placeholder mappings.

## Remaining gaps (not covered by this plugin)

- `@file:` user-message expansion
- Arbitrary `execute_code` / `open(...)` reads

See [threat-model.md](threat-model.md).
