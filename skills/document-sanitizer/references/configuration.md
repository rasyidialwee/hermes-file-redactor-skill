# Configuration

## Hermes skill config

Stored under `skills.config` in `~/.hermes/config.yaml`:

```yaml
skills:
  config:
    document_sanitization:
      mode: pii
      confidence_threshold: 0.85
      max_file_size_mb: 25
```

CLI:

```bash
hermes config set skills.config.document_sanitization.mode pii
```

Do **not** put these settings under Hermes top-level `security:` or `privacy:` — those keys mean something else (`redact_secrets`, gateway ID hashing).

## Modes

| Mode | Behavior |
|------|----------|
| `off` | Pass-through (skill still preferred over raw reads for discipline) |
| `secrets_only` | API keys, JWT, PEM, passwords, auth headers, DB URLs |
| `pii` | + email, phone (E.164 + Malaysian), MyKad, IBAN, Luhn cards, **NAME (BIN/BINTI/A/P/A/L)** |
| `confidential` | + `RM`/`MYR` amounts, account-like numbers |
| `strict` | + internal URLs, long digit runs; never forward original image bytes |

Default: `pii`.

Western-style names without BIN/BINTI/A/P/A/L are **not** guessed — list them in `custom_rules`.

## Choose what to sanitize

### Config file

```bash
python scripts/sanitize.py yourfile.txt --config templates/sanitize.config.yaml
```

```yaml
mode: pii
enable_categories: []          # empty = all categories for the mode
disable_categories:
  - PHONE
custom_rules:
  - name: person
    pattern: "John Smith"
    replacement: "[NAME]"
```

### CLI flags

```bash
# Only MyKad + Malay names
python scripts/sanitize.py yourfile.txt --enable NAME,MYKAD

# Everything in pii mode except phones
python scripts/sanitize.py yourfile.txt --mode pii --disable PHONE

# List built-in categories
python scripts/sanitize.py --list-categories
```

`custom_rules` always run, even when `enable_categories` is set.

## Confidence

Each detector has a fixed confidence. Hits below `confidence_threshold` (default `0.85`) are skipped.

## Custom rules

YAML file (see `templates/custom_rules.yaml`):

```yaml
custom_rules:
  - name: customer_id
    pattern: "CUS-[0-9]{6}"
    replacement: "[CUSTOMER_ID]"
```

### Precedence

1. Fail-closed checks (size, type, archives)
2. Custom rules + built-in detectors (overlap: longer match wins, then earlier start)
3. Custom fixed `replacement` strings are used as-is (not session-numbered) unless you include an ID in the template

## Limits

- `max_file_size_mb` (default 25)
- `max_text_length` (default 2_000_000 characters after extract)

## CLI flags

```bash
python scripts/sanitize.py PATH --mode pii
python scripts/sanitize.py PATH --custom-rules templates/custom_rules.yaml
python scripts/sanitize.py PATH --json
# Debug only — exposes sensitive data:
python scripts/sanitize.py PATH --show-original
```
