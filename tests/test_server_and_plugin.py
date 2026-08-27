"""Tests for local sanitize HTTP service, Docker bind rules, and plugin."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from document_sanitizer.improve import DocumentFixture, evaluate_fixture, run_improve
from document_sanitizer.server import (
    get_stats,
    reset_stats,
    result_to_response,
    validate_bind_host,
)


def test_validate_bind_host_allows_loopback():
    assert validate_bind_host("127.0.0.1") == "127.0.0.1"
    assert validate_bind_host("localhost") == "localhost"


def test_validate_bind_host_rejects_non_local():
    with pytest.raises(ValueError, match="Refuse to bind"):
        validate_bind_host("0.0.0.0")
    with pytest.raises(ValueError, match="Refuse to bind"):
        validate_bind_host("192.168.1.10")


def test_validate_bind_host_docker_allows_all_interfaces():
    assert validate_bind_host("0.0.0.0", allow_docker_bind=True) == "0.0.0.0"


def test_result_to_response_has_no_mappings():
    from document_sanitizer.api import sanitize_text

    r = sanitize_text("email me at a@b.co", mode="pii")
    payload = result_to_response(r)
    assert "a@b.co" not in payload["content"]
    assert "mapping" not in payload
    assert "detections" not in payload
    assert "detection_count" in payload
    assert "a@b.co" not in str(payload)


@pytest.fixture
def client():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from document_sanitizer.server import create_app

    reset_stats()
    with TestClient(create_app()) as c:
        yield c
    reset_stats()


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_sanitize_text_endpoint(client):
    r = client.post(
        "/v1/sanitize/text",
        json={"text": "Contact jane@example.com", "mode": "pii"},
    )
    assert r.status_code == 200
    data = r.json()
    assert "jane@example.com" not in data["content"]
    assert "[EMAIL_" in data["content"]
    assert data["sanitized"] is True
    assert "EMAIL" in data["categories"]


def test_sanitize_path_endpoint(client, tmp_path: Path):
    path = tmp_path / "note.txt"
    path.write_text("phone +60123456789", encoding="utf-8")
    r = client.post("/v1/sanitize", json={"path": str(path), "mode": "pii"})
    assert r.status_code == 200
    data = r.json()
    assert "+60123456789" not in data["content"]
    assert data["file_name"] == "note.txt"


def test_stats_write_only(client):
    client.post("/v1/sanitize/text", json={"text": "a@b.co", "mode": "pii"})
    r = client.get("/v1/stats")
    assert r.status_code == 200
    data = r.json()
    assert data["requests"] >= 1
    assert "EMAIL" in data["categories"]
    assert "vault" not in data
    assert "mappings" not in data
    assert get_stats()["requests"] >= 1


def test_invalid_mode(client):
    r = client.post("/v1/sanitize/text", json={"text": "hi", "mode": "nope"})
    assert r.status_code == 400


def test_improve_fixture_clean():
    fixture = DocumentFixture(
        name="email_only",
        text="write to demo@example.org please",
        must_redact=["demo@example.org"],
        safe_to_keep=["write", "please"],
        mode="pii",
    )
    report = evaluate_fixture(fixture)
    assert report.ok, (report.leaks, report.false_positives)


def test_run_improve_shipped_fixtures():
    from fixtures.documents import ALL_FIXTURES

    reports, clean = run_improve(ALL_FIXTURES, cycles=1, verbose=False)
    assert len(reports) == len(ALL_FIXTURES)
    assert clean, [(r.name, r.leaks, r.false_positives) for r in reports if not r.ok]


def _load_plugin():
    plugin_dir = Path(__file__).resolve().parents[1] / "plugins" / "document-sanitizer"
    spec = importlib.util.spec_from_file_location(
        "doc_sanitizer_plugin",
        plugin_dir / "__init__.py",
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_plugin_transform_read_file(tmp_path: Path, monkeypatch):
    mod = _load_plugin()
    path = tmp_path / "secret.txt"
    path.write_text("email leak@example.com", encoding="utf-8")

    def fake_http(method, url, payload=None, timeout=120.0):
        if url.endswith("/health"):
            return {"status": "ok"}
        if url.endswith("/v1/sanitize"):
            from document_sanitizer.api import sanitize
            from document_sanitizer.server import result_to_response

            return result_to_response(sanitize(payload["path"], mode=payload.get("mode")))
        raise AssertionError(url)

    monkeypatch.setattr(mod, "_http_json", fake_http)
    monkeypatch.setattr(mod, "_health_ok", lambda url: True)

    transform = mod.make_transform(
        {
            "service_url": "http://127.0.0.1:8765",
            "enforce": True,
            "mode": "pii",
            "tools": ["read_file", "vision_analyze"],
        }
    )
    out = transform(
        tool_name="read_file",
        args={"path": str(path)},
        result="email leak@example.com",
    )
    assert out is not None
    assert "leak@example.com" not in out
    assert "[EMAIL_" in out


def test_plugin_fail_closed_when_down(monkeypatch):
    mod = _load_plugin()
    monkeypatch.setattr(mod, "_health_ok", lambda url: False)
    transform = mod.make_transform(
        {
            "service_url": "http://127.0.0.1:8765",
            "enforce": True,
            "mode": "pii",
            "tools": ["read_file"],
        }
    )
    out = transform(tool_name="read_file", args={"path": "/tmp/x"}, result="raw")
    assert out is not None
    assert "service unavailable" in out


def test_ui_page(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Document Sanitizer" in r.text
    assert "/v1/sanitize/upload" in r.text


def test_sanitize_upload(client):
    files = {"file": ("note.txt", b"email leak@example.com\n", "text/plain")}
    r = client.post("/v1/sanitize/upload", files=files, data={"mode": "pii"})
    assert r.status_code == 200
    data = r.json()
    assert data["file_name"] == "note.txt"
    assert "leak@example.com" not in data["content"]
    assert "[EMAIL_" in data["content"]
