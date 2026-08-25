"""Tests for document sanitizer — no real PII in assertions beyond synthetic fixtures."""

from __future__ import annotations

import io
import json
import logging
import zipfile
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring

import pytest

from document_sanitizer import sanitize, sanitize_text
from document_sanitizer.config import CustomRule, SanitizerConfig
from document_sanitizer.session import PlaceholderSession


@pytest.fixture
def tmp_file(tmp_path: Path):
    def _make(name: str, content: str | bytes) -> Path:
        path = tmp_path / name
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    return _make


class TestSecrets:
    def test_api_key(self):
        text = "key=sk-abcdefghijklmnopqrstuvwxyz123456"
        r = sanitize_text(text, mode="secrets_only")
        assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in r.content
        assert "API_KEY" in r.categories

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepartgoeshere"
        r = sanitize_text(f"token {jwt}", mode="secrets_only")
        assert jwt not in r.content
        assert "JWT" in r.categories

    def test_private_key(self):
        pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----"
        r = sanitize_text(pem, mode="secrets_only")
        assert "MIIEvQIBADANBg" not in r.content
        assert "PRIVATE_KEY" in r.categories

    def test_password_assignment(self):
        r = sanitize_text('password: "hunter2secret"', mode="secrets_only")
        assert "hunter2secret" not in r.content
        assert "PASSWORD" in r.categories

    def test_auth_header(self):
        r = sanitize_text("Authorization: Bearer abcdefghijklmnop", mode="secrets_only")
        assert "abcdefghijklmnop" not in r.content
        assert "AUTH_HEADER" in r.categories

    def test_db_url(self):
        url = "postgres://user:secretpass@db.example.com:5432/app"
        r = sanitize_text(url, mode="secrets_only")
        assert "secretpass" not in r.content
        assert "DB_URL" in r.categories


class TestPII:
    def test_email(self):
        r = sanitize_text("Contact jane.doe@example.com please", mode="pii")
        assert "jane.doe@example.com" not in r.content
        assert "[EMAIL_001]" in r.content

    def test_email_stable_id(self):
        r = sanitize_text("a@x.com and a@x.com again", mode="pii")
        assert r.content.count("[EMAIL_001]") == 2
        assert "[EMAIL_002]" not in r.content

    def test_malaysian_phone(self):
        r = sanitize_text("Call +60 12-345 6789 now", mode="pii")
        assert "345 6789" not in r.content or "[PHONE_" in r.content
        assert "PHONE" in r.categories

    def test_mykad(self):
        r = sanitize_text("IC 900101-14-5678", mode="pii")
        assert "900101-14-5678" not in r.content
        assert "MYKAD" in r.categories

    def test_iban(self):
        # Valid IBAN checksum for GB82 WEST 1234 5698 7654 32
        iban = "GB82WEST12345698765432"
        r = sanitize_text(f"pay {iban}", mode="pii")
        assert iban not in r.content
        assert "IBAN" in r.categories

    def test_credit_card_luhn(self):
        # Visa test number
        cc = "4111111111111111"
        r = sanitize_text(f"card {cc}", mode="pii")
        assert cc not in r.content
        assert "CREDIT_CARD" in r.categories

    def test_invalid_luhn_kept(self):
        bad = "4111111111111112"
        r = sanitize_text(f"card {bad}", mode="pii")
        assert bad in r.content

    def test_names_not_auto_redacted(self):
        prose = "Ahmad bin Ali met Siti Nurhaliza in Kuala Lumpur on 2024-01-15."
        r = sanitize_text(prose, mode="pii")
        assert "Ahmad bin Ali" in r.content
        assert "Siti Nurhaliza" in r.content


class TestConfidential:
    def test_rm_amount_not_in_pii(self):
        r = sanitize_text("Salary RM 5,000.00", mode="pii")
        assert "RM 5,000.00" in r.content

    def test_rm_amount_in_confidential(self):
        r = sanitize_text("Salary RM 5,000.00", mode="confidential")
        assert "RM 5,000.00" not in r.content
        assert "AMOUNT" in r.categories
        assert "[AMOUNT_001]" in r.content


class TestStructured:
    def test_json_preserves_structure(self, tmp_file):
        data = {"name": "keep", "email": "a@b.com", "order_id": "ORD-12345"}
        path = tmp_file("data.json", json.dumps(data))
        r = sanitize(path, mode="pii")
        assert r.sanitized
        out = json.loads(r.content)
        assert out["order_id"] == "ORD-12345"
        assert out["email"] == "[EMAIL_001]"
        assert out["name"] == "keep"

    def test_yaml(self, tmp_file):
        path = tmp_file("c.yaml", "email: user@example.com\nid: 1\n")
        r = sanitize(path, mode="pii")
        assert "user@example.com" not in r.content
        assert "id: 1" in r.content or "id: 1\n" in r.content

    def test_csv(self, tmp_file):
        path = tmp_file("t.csv", "email,id\na@b.com,1\n")
        r = sanitize(path, mode="pii")
        assert "a@b.com" not in r.content
        assert "[EMAIL_001]" in r.content
        assert "id" in r.content

    def test_xml(self, tmp_file):
        path = tmp_file("x.xml", "<user><email>a@b.com</email></user>")
        r = sanitize(path, mode="pii")
        assert "a@b.com" not in r.content
        assert "[EMAIL_001]" in r.content


class TestCustomRules:
    def test_custom_rule(self):
        cfg = SanitizerConfig(
            mode="pii",
            custom_rules=[CustomRule("customer_id", r"CUS-\d{6}", "[CUSTOMER_ID]")],
        )
        r = sanitize_text("id CUS-123456 ok", config=cfg)
        assert "CUS-123456" not in r.content
        assert "[CUSTOMER_ID]" in r.content


class TestModes:
    def test_off(self):
        r = sanitize_text("a@b.com", mode="off")
        assert r.content == "a@b.com"
        assert not r.sanitized

    def test_secrets_only_skips_email(self):
        r = sanitize_text("a@b.com", mode="secrets_only")
        assert "a@b.com" in r.content


class TestFailClosed:
    def test_archive(self, tmp_file):
        path = tmp_file("a.zip", b"PK\x03\x04fake")
        r = sanitize(path, mode="pii")
        assert not r.sanitized
        assert r.content == ""
        assert any("Archive" in w or "archive" in w.lower() for w in r.warnings)

    def test_unknown_binary(self, tmp_file):
        path = tmp_file("x.bin", b"\x00\x01\x02\x03")
        r = sanitize(path, mode="pii")
        assert not r.sanitized
        assert r.content == ""

    def test_oversized(self, tmp_file):
        path = tmp_file("big.txt", "a@b.com")
        cfg = SanitizerConfig(mode="pii", max_file_size_mb=0.0000001)
        r = sanitize(path, config=cfg)
        assert not r.sanitized


class TestSecurityProperties:
    def test_original_untouched(self, tmp_file):
        path = tmp_file("f.txt", "mail a@b.com")
        before = path.read_bytes()
        sanitize(path, mode="pii")
        assert path.read_bytes() == before

    def test_no_mapping_in_result(self, tmp_file):
        path = tmp_file("f.txt", "mail a@b.com")
        r = sanitize(path, mode="pii")
        blob = json.dumps(r.__dict__, default=str)
        assert "a@b.com" not in blob
        assert "value_to_placeholder" not in blob

    def test_logs_have_no_pii(self, tmp_file, caplog):
        path = tmp_file("f.txt", "mail secret.person@example.com")
        with caplog.at_level(logging.INFO, logger="document_sanitizer"):
            sanitize(path, mode="pii")
        joined = " ".join(rec.getMessage() for rec in caplog.records)
        assert "secret.person@example.com" not in joined
        assert "detections=" in joined


class TestSession:
    def test_placeholder_session_clears(self):
        s = PlaceholderSession()
        a = s.placeholder_for("EMAIL", "a@b.com")
        assert a == "[EMAIL_001]"
        s.clear()
        b = s.placeholder_for("EMAIL", "a@b.com")
        assert b == "[EMAIL_001]"


def _minimal_docx(paragraphs: list[str]) -> bytes:
    ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    document = Element(f"{{{ns}}}document")
    body = SubElement(document, f"{{{ns}}}body")
    for text in paragraphs:
        p = SubElement(body, f"{{{ns}}}p")
        r = SubElement(p, f"{{{ns}}}r")
        t = SubElement(r, f"{{{ns}}}t")
        t.text = text
    content_types = (
        b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"""
        b"""<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">"""
        b"""<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>"""
        b"""<Default Extension="xml" ContentType="application/xml"/>"""
        b"""<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>"""
        b"""</Types>"""
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr(
            "_rels/.rels",
            b"""<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"""
            b"""<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>""",
        )
        zf.writestr("word/document.xml", tostring(document, encoding="utf-8"))
    return buf.getvalue()


def _minimal_xlsx(cell_value: str) -> bytes:
    ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    ss = Element(f"{{{ns}}}sst", attrib={"count": "1", "uniqueCount": "1"})
    si = SubElement(ss, f"{{{ns}}}si")
    t = SubElement(si, f"{{{ns}}}t")
    t.text = cell_value
    sheet = Element(f"{{{ns}}}worksheet")
    sd = SubElement(sheet, f"{{{ns}}}sheetData")
    row = SubElement(sd, f"{{{ns}}}row", attrib={"r": "1"})
    c = SubElement(row, f"{{{ns}}}c", attrib={"r": "A1", "t": "s"})
    v = SubElement(c, f"{{{ns}}}v")
    v.text = "0"
    content_types = (
        b"""<?xml version="1.0" encoding="UTF-8"?>"""
        b"""<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">"""
        b"""<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>"""
        b"""<Default Extension="xml" ContentType="application/xml"/>"""
        b"""<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>"""
        b"""<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>"""
        b"""<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>"""
        b"""</Types>"""
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr(
            "_rels/.rels",
            b"""<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"""
            b"""<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>""",
        )
        zf.writestr(
            "xl/workbook.xml",
            b"""<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" """
            b"""xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">"""
            b"""<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>""",
        )
        zf.writestr(
            "xl/_rels/workbook.xml.rels",
            b"""<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"""
            b"""<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>"""
            b"""<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>"""
            b"""</Relationships>""",
        )
        zf.writestr("xl/sharedStrings.xml", tostring(ss, encoding="utf-8"))
        zf.writestr("xl/worksheets/sheet1.xml", tostring(sheet, encoding="utf-8"))
    return buf.getvalue()


class TestOffice:
    def test_docx(self, tmp_file):
        path = tmp_file("d.docx", _minimal_docx(["Email a@b.com"]))
        r = sanitize(path, mode="pii")
        assert r.sanitized
        assert "a@b.com" not in r.content
        assert "[EMAIL_001]" in r.content

    def test_xlsx(self, tmp_file):
        path = tmp_file("s.xlsx", _minimal_xlsx("a@b.com"))
        r = sanitize(path, mode="pii")
        assert r.sanitized
        assert "a@b.com" not in r.content
        assert "[EMAIL_001]" in r.content


class TestUnicode:
    def test_unicode_prose(self):
        text = "你好 Ahmad — email test@例子.com is wrong tld but 测试@example.com ok"
        r = sanitize_text(text, mode="pii")
        assert "测试@example.com" not in r.content
        assert "你好" in r.content
