# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

# OCR support for image sanitization (optional at runtime if unused)
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY skills/document-sanitizer/scripts ./skills/document-sanitizer/scripts

RUN pip install --no-cache-dir ".[server,pdf,ocr]"

ENV DOCUMENT_SANITIZER_DOCKER=1
ENV PORT=8765

# Listen on all interfaces inside the container; compose binds host to 127.0.0.1 only.
EXPOSE 8765
CMD ["document-sanitize", "serve", "--docker", "--port", "8765"]
