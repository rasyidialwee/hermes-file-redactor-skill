"""Document format adapters — extract text without modifying originals."""

from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET

from ..config import ARCHIVE_EXTENSIONS, SanitizerConfig
from ..detectors import redact_text
from ..models import Detection
from ..session import PlaceholderSession

TEXT_EXTENSIONS = frozenset({".txt", ".md", ".log", ".csv", ".json", ".yaml", ".yml", ".xml"})
DOCX_EXT = ".docx"
XLSX_EXT = ".xlsx"
PDF_EXT = ".pdf"
IMAGE_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".webp"})

SUPPORTED_EXTENSIONS = TEXT_EXTENSIONS | {DOCX_EXT, XLSX_EXT, PDF_EXT} | IMAGE_EXTENSIONS


@dataclass
class ExtractedDocument:
    text: str
    warnings: list[str] = field(default_factory=list)
    content_type: str = "text"
    block_original_bytes: bool = False


class UnsupportedFormatError(ValueError):
    pass


class FileTooLargeError(ValueError):
    pass


class ArchiveNotSupportedError(ValueError):
    pass


def _ext(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".tar.gz"):
        return ".tar.gz"
    return path.suffix.lower()


def check_path_limits(path: Path, config: SanitizerConfig) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Not a file: {path}")
    size = path.stat().st_size
    max_bytes = int(config.max_file_size_mb * 1024 * 1024)
    if size > max_bytes:
        raise FileTooLargeError(f"File exceeds max_file_size_mb={config.max_file_size_mb}")
    ext = _ext(path)
    if ext in ARCHIVE_EXTENSIONS or path.name.lower().endswith(".tar.gz"):
        raise ArchiveNotSupportedError(
            "Archives (.zip/.tar/.gz) are not supported in v1; extract files first"
        )
    if ext not in SUPPORTED_EXTENSIONS:
        raise UnsupportedFormatError(
            f"Unsupported format {ext!r}; refuse to send raw contents (fail closed)"
        )


def extract_document(path: Path, config: SanitizerConfig) -> ExtractedDocument:
    check_path_limits(path, config)
    ext = _ext(path)
    if ext in {".txt", ".md", ".log"}:
        text = path.read_text(encoding="utf-8", errors="replace")
        return ExtractedDocument(text=text, content_type="text")
    if ext == ".json":
        return _extract_json(path)
    if ext in {".yaml", ".yml"}:
        return _extract_yaml(path)
    if ext == ".xml":
        return _extract_xml(path)
    if ext == ".csv":
        return _extract_csv(path)
    if ext == DOCX_EXT:
        return _extract_docx(path)
    if ext == XLSX_EXT:
        return _extract_xlsx(path)
    if ext == PDF_EXT:
        return _extract_pdf(path)
    if ext in IMAGE_EXTENSIONS:
        return _extract_image(path, config)
    raise UnsupportedFormatError(f"Unsupported format {ext!r}")


def sanitize_extracted(
    extracted: ExtractedDocument,
    config: SanitizerConfig,
    session: PlaceholderSession,
) -> tuple[str, list[Detection], list[str]]:
    warnings = list(extracted.warnings)
    if len(extracted.text) > config.max_text_length:
        raise FileTooLargeError(f"Extracted text exceeds max_text_length={config.max_text_length}")

    if extracted.content_type == "json":
        return _sanitize_json_text(extracted.text, config, session, warnings)
    if extracted.content_type == "yaml":
        return _sanitize_yaml_text(extracted.text, config, session, warnings)
    if extracted.content_type == "xml":
        return _sanitize_xml_text(extracted.text, config, session, warnings)
    if extracted.content_type == "csv":
        return _sanitize_csv_text(extracted.text, config, session, warnings)

    content, detections = redact_text(extracted.text, config, session)
    return content, detections, warnings


def _walk_sanitize(obj, config: SanitizerConfig, session: PlaceholderSession, detections: list[Detection]):
    if isinstance(obj, dict):
        return {k: _walk_sanitize(v, config, session, detections) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk_sanitize(v, config, session, detections) for v in obj]
    if isinstance(obj, str):
        text, dets = redact_text(obj, config, session)
        detections.extend(dets)
        return text
    return obj


def _sanitize_json_text(text, config, session, warnings):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        content, detections = redact_text(text, config, session)
        warnings.append("Malformed JSON; sanitized as plain text")
        return content, detections, warnings
    detections: list[Detection] = []
    sanitized = _walk_sanitize(data, config, session, detections)
    return json.dumps(sanitized, indent=2, ensure_ascii=False), detections, warnings


def _sanitize_yaml_text(text, config, session, warnings):
    try:
        import yaml
    except ImportError:
        content, detections = redact_text(text, config, session)
        warnings.append("PyYAML missing; sanitized YAML as plain text")
        return content, detections, warnings
    try:
        data = yaml.safe_load(text)
    except Exception:
        content, detections = redact_text(text, config, session)
        warnings.append("Malformed YAML; sanitized as plain text")
        return content, detections, warnings
    detections: list[Detection] = []
    sanitized = _walk_sanitize(data, config, session, detections)
    return yaml.safe_dump(sanitized, sort_keys=False, allow_unicode=True), detections, warnings


def _sanitize_xml_text(text, config, session, warnings):
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        content, detections = redact_text(text, config, session)
        warnings.append("Malformed XML; sanitized as plain text")
        return content, detections, warnings
    detections: list[Detection] = []

    def walk(elem: ET.Element) -> None:
        if elem.text:
            elem.text, dets = redact_text(elem.text, config, session)
            detections.extend(dets)
        if elem.tail:
            elem.tail, dets = redact_text(elem.tail, config, session)
            detections.extend(dets)
        for key, val in list(elem.attrib.items()):
            new_val, dets = redact_text(val, config, session)
            elem.attrib[key] = new_val
            detections.extend(dets)
        for child in elem:
            walk(child)

    walk(root)
    return ET.tostring(root, encoding="unicode"), detections, warnings


def _sanitize_csv_text(text, config, session, warnings):
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    detections: list[Detection] = []
    out = io.StringIO()
    writer = csv.writer(out)
    for row in rows:
        new_row = []
        for cell in row:
            sanitized, dets = redact_text(cell, config, session)
            detections.extend(dets)
            new_row.append(sanitized)
        writer.writerow(new_row)
    return out.getvalue(), detections, warnings


def _extract_json(path: Path) -> ExtractedDocument:
    return ExtractedDocument(text=path.read_text(encoding="utf-8", errors="replace"), content_type="json")


def _extract_yaml(path: Path) -> ExtractedDocument:
    return ExtractedDocument(text=path.read_text(encoding="utf-8", errors="replace"), content_type="yaml")


def _extract_xml(path: Path) -> ExtractedDocument:
    return ExtractedDocument(text=path.read_text(encoding="utf-8", errors="replace"), content_type="xml")


def _extract_csv(path: Path) -> ExtractedDocument:
    return ExtractedDocument(text=path.read_text(encoding="utf-8", errors="replace"), content_type="csv")


_NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
}


def _extract_docx(path: Path) -> ExtractedDocument:
    warnings: list[str] = []
    paragraphs: list[str] = []
    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
        if any(n.startswith("word/media/") for n in names):
            warnings.append("[UNSANITIZED_IMAGE_CONTENT] embedded images were not OCR'd")
        xml = zf.read("word/document.xml")
    root = ET.fromstring(xml)
    for para in root.findall(".//w:p", _NS):
        texts = [t.text or "" for t in para.findall(".//w:t", _NS)]
        line = "".join(texts).strip()
        if line:
            paragraphs.append(line)
    body = "\n\n".join(paragraphs)
    if warnings:
        body = body + "\n\n" + "\n".join(warnings)
    return ExtractedDocument(text=body, warnings=warnings, content_type="text")


def _col_letter(n: int) -> str:
    s = ""
    while n:
        n, rem = divmod(n - 1, 26)
        s = chr(65 + rem) + s
    return s


def _extract_xlsx(path: Path) -> ExtractedDocument:
    warnings: list[str] = []
    lines: list[str] = []
    with zipfile.ZipFile(path) as zf:
        shared: list[str] = []
        if "xl/sharedStrings.xml" in zf.namelist():
            ss_root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
            for si in ss_root.findall("main:si", _NS):
                texts = [t.text or "" for t in si.findall(".//main:t", _NS)]
                shared.append("".join(texts))
        sheet_files = sorted(
            n for n in zf.namelist() if re.match(r"xl/worksheets/sheet\d+\.xml", n)
        )
        for idx, sheet_name in enumerate(sheet_files, start=1):
            lines.append(f"## Sheet {idx}")
            root = ET.fromstring(zf.read(sheet_name))
            for row in root.findall("main:sheetData/main:row", _NS):
                cells: list[str] = []
                for cell in row.findall("main:c", _NS):
                    ref = cell.attrib.get("r", "")
                    cell_type = cell.attrib.get("t")
                    v = cell.find("main:v", _NS)
                    f = cell.find("main:f", _NS)
                    value = ""
                    if f is not None and f.text:
                        value = f"={f.text}"
                    elif v is not None and v.text is not None:
                        if cell_type == "s":
                            try:
                                value = shared[int(v.text)]
                            except (IndexError, ValueError):
                                value = v.text
                        else:
                            value = v.text
                    cells.append(f"{ref}:{value}" if ref else value)
                if cells:
                    lines.append(" | ".join(cells))
    return ExtractedDocument(text="\n".join(lines), warnings=warnings, content_type="text")


def _extract_pdf(path: Path) -> ExtractedDocument:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise UnsupportedFormatError(
            "PDF support requires pypdf. Install with: pip install 'hermes-file-redactor[pdf]'"
        ) from exc
    warnings: list[str] = []
    reader = PdfReader(str(path))
    pages: list[str] = []
    for i, page in enumerate(reader.pages, start=1):
        try:
            text = page.extract_text() or ""
        except Exception:
            text = ""
            warnings.append(f"Failed to extract text from PDF page {i}")
        if text.strip():
            pages.append(text)
        # Heuristic: presence of XObject images
        if "/XObject" in (page.get("/Resources") or {}):
            warnings.append("[UNSANITIZED_IMAGE_CONTENT] PDF may contain embedded images")
    body = "\n\n".join(pages)
    # de-dupe image warnings
    uniq = []
    for w in warnings:
        if w not in uniq:
            uniq.append(w)
    if any("UNSANITIZED_IMAGE" in w for w in uniq):
        body = body + "\n\n[UNSANITIZED_IMAGE_CONTENT]"
    return ExtractedDocument(text=body, warnings=uniq, content_type="text")


def _extract_image(path: Path, config: SanitizerConfig) -> ExtractedDocument:
    block = config.mode in ("pii", "confidential", "strict")
    try:
        from PIL import Image
        import pytesseract
    except ImportError as exc:
        raise UnsupportedFormatError(
            "Image OCR requires Pillow and pytesseract. "
            "Install with: pip install 'hermes-file-redactor[ocr]' and install Tesseract"
        ) from exc
    try:
        image = Image.open(path)
        text = pytesseract.image_to_string(image) or ""
    except Exception as exc:
        raise UnsupportedFormatError(
            f"OCR failed or Tesseract missing; refusing to send original image bytes ({exc})"
        ) from exc
    warnings = []
    if block:
        warnings.append("Original image bytes must not be sent to the model in this mode")
    if config.mode == "strict":
        warnings.append("strict mode: do not forward original image bytes even if OCR is clean")
    if not text.strip():
        text = "[UNSANITIZED_IMAGE_CONTENT]"
        warnings.append("OCR produced no text; image content not safely sanitizable")
    return ExtractedDocument(
        text=text,
        warnings=warnings,
        content_type="text",
        block_original_bytes=block or config.mode == "strict",
    )
