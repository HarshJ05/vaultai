import importlib

import pytest
from fastapi.testclient import TestClient

SID = "admin-test-session-1"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_DB", str(tmp_path / "admin.db"))
    monkeypatch.setenv("ADMIN_USERNAME", "boss")
    monkeypatch.setenv("ADMIN_PASSWORD", "correct horse battery")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    import vaultai.api as api
    importlib.reload(api)
    c = TestClient(api.app)
    c.post("/api/redact", json={"session_id": SID, "text": "Call Priya Sharma on 9123456780"})
    return c


def login(c, pw="correct horse battery"):
    return c.post("/api/admin/login", json={"username": "boss", "password": pw})


def test_admin_routes_need_login(client):
    for path in ["/api/admin/me", "/api/admin/vault", "/api/admin/audit"]:
        assert client.get(path).status_code == 401
    assert client.post("/api/admin/reveal", json={"id": 1}).status_code == 401


def test_wrong_password_rejected_and_logged(client):
    assert login(client, "nope").status_code == 401
    login(client)
    events = [e["event"] for e in client.get("/api/admin/audit").json()["events"]]
    assert "admin_login_failed" in events and "admin_login" in events


def test_lockout_after_five_failures(client):
    for _ in range(5):
        login(client, "wrong")
    r = login(client)                       # even the right password is refused while locked
    assert r.status_code == 429


def test_vault_list_is_masked_and_reveal_is_audited(client):
    login(client)
    entries = client.get("/api/admin/vault").json()["entries"]
    phone = next(e for e in entries if e["pii_type"] == "PHONE")
    assert "9123456780" not in phone["masked"] and phone["masked"].endswith("6780")
    r = client.post("/api/admin/reveal", json={"id": phone["id"]}).json()
    assert r["value"] == "9123456780"
    audit = client.get("/api/admin/audit").json()["events"]
    assert any(e["event"] == "admin_revealed" and "boss" in e["detail"] for e in audit)


def test_search_by_real_value_without_type(client):
    login(client)
    hits = client.get("/api/admin/vault", params={"q": "+91 91234 56780"}).json()["entries"]
    assert len(hits) == 1 and hits[0]["pii_type"] == "PHONE"


def test_admin_delete_and_logout(client):
    login(client)
    eid = client.get("/api/admin/vault").json()["entries"][0]["id"]
    assert client.post("/api/admin/delete", json={"id": eid}).json()["ok"]
    client.post("/api/admin/logout")
    assert client.get("/api/admin/me").status_code == 401


def test_public_audit_needs_a_session(client):
    assert client.get("/api/audit").status_code == 422
    assert client.get("/api/audit", params={"session_id": SID}).status_code == 200
