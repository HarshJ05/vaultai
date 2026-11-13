import importlib
import re
import sqlite3

import pytest
from fastapi.testclient import TestClient

from vaultai.detector import PIIDetector
from vaultai.vault import Vault, normalise

SID = "test-session-0001"
TOKEN = re.compile(r"^\[\[V_[A-Z0-9]{8}\]\]$")


@pytest.fixture()
def vault():
    return Vault(":memory:")


# ---- vault -------------------------------------------------------------------------
def test_tokens_are_random_and_reveal_no_type(vault):
    a = vault.tokenize(SID, "PHONE", "98765 43210")
    b = vault.tokenize(SID, "PHONE", "+91-9876543210")   # same number, other format
    c = vault.tokenize(SID, "PHONE", "9123456780")
    assert TOKEN.match(a) and TOKEN.match(c)
    assert a == b and a != c
    assert "PHONE" not in a


def test_tokens_differ_between_sessions(vault):
    assert vault.tokenize(SID, "EMAIL", "a@b.com") != vault.tokenize("other-session-01", "EMAIL", "a@b.com")


def test_typed_style_still_available():
    v = Vault(":memory:", token_style="typed")
    assert v.tokenize(SID, "PHONE", "9876543210") == "<PHONE_1>"
    assert v.tokenize(SID, "PHONE", "9123456780") == "<PHONE_2>"


def test_sessions_are_isolated(vault):
    tok = vault.tokenize(SID, "EMAIL", "a@b.com")
    assert vault.restore("other-session-01", tok)[0] == "[REDACTED]"


def test_values_are_encrypted_at_rest(tmp_path):
    db = tmp_path / "v.db"
    Vault(db).tokenize(SID, "PAN", "ABCPM1234K")
    raw = sqlite3.connect(db).execute("SELECT ciphertext, fingerprint FROM vault").fetchone()
    assert b"ABCPM1234K" not in raw[0] and "ABCPM1234K" not in raw[1]


def test_redact_and_restore_roundtrip(vault):
    det = PIIDetector()
    text = "My name is Rohan Mehta, call me on 98765 43210."
    redacted, _ = vault.redact(SID, text, det.detect(text))
    assert "Rohan" not in redacted and "98765" not in redacted
    assert vault.restore(SID, redacted)[0] == text


def test_restore_tolerates_llm_formatting_slips(vault):
    tok = vault.tokenize(SID, "PERSON", "Priya Sharma")
    code = tok[4:-2]
    text = f"Hello {tok}, [V_{code}] and [[ V_{code} ]]"
    assert vault.restore(SID, text)[0] == "Hello Priya Sharma, Priya Sharma and Priya Sharma"


def test_erasure_by_value_across_sessions(vault):
    tok = vault.tokenize(SID, "PHONE", "9876543210")
    vault.tokenize("second-session-1", "PHONE", "+91 98765 43210")
    assert vault.erase_value("98765-43210", "test") == 2          # no type needed
    assert vault.restore(SID, tok)[0] == "[REDACTED]"
    assert any(e["event"] == "erased" for e in vault.audit_log())


def test_consent_lifecycle(vault):
    assert vault.consent_status(SID)["state"] == "none"
    vault.grant_consent(SID, 5, "test")
    assert vault.consent_status(SID)["state"] == "active"
    vault.withdraw_consent(SID)
    assert vault.consent_status(SID)["state"] == "withdrawn"


def test_retention_purge():
    v = Vault(":memory:", retention_minutes=0)
    v.tokenize(SID, "EMAIL", "x@y.com")
    assert v.purge_expired() == 1


def test_normalise():
    assert normalise("PHONE", "+91 98765-43210") == "9876543210"
    assert normalise("PAN", "abcpm 1234k") == "ABCPM1234K"


# ---- API ---------------------------------------------------------------------------
@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_DB", str(tmp_path / "api.db"))
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    import vaultai.api as api
    importlib.reload(api)
    return TestClient(api.app)


def test_chat_requires_consent(client):
    r = client.post("/api/chat", json={"session_id": SID, "text": "Call 9876543210"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "consent_required"


def test_chat_end_to_end_demo_mode(client):
    client.post("/api/consent", json={"session_id": SID, "minutes": 5})
    r = client.post("/api/chat", json={"session_id": SID, "text": "Call Priya Sharma on 9123456780"}).json()
    assert "9123456780" not in r["redacted_prompt"] and "Priya" not in r["redacted_prompt"]
    assert re.search(r"\[\[V_[A-Z0-9]{8}\]\]", r["redacted_prompt"])
    assert "9123456780" in r["reply"]          # restored for the user
    assert r["llm_mode"] == "demo"


def test_vault_endpoint_never_returns_values(client):
    client.post("/api/redact", json={"session_id": SID, "text": "PAN ABCPM1234K"})
    body = client.get(f"/api/vault/{SID}").text
    assert "ABCPM1234K" not in body and "[[V_" in body


def test_erase_endpoint(client):
    client.post("/api/redact", json={"session_id": SID, "text": "mail me at a.b@gmail.com"})
    assert client.post("/api/erase", json={"value": "A.B@gmail.com"}).json()["erased"] == 1
    assert client.post("/api/erase", json={"pii_type": "NOPE", "value": "x"}).status_code == 400


def test_cross_border_rules(client):
    client.post("/api/consent", json={"session_id": SID, "minutes": 5})
    body = {"session_id": SID, "text": "Call 9876543210", "framework": "GDPR", "region": "SG"}
    r = client.post("/api/chat", json=body)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "transfer_blocked"
    assert client.post("/api/chat", json={**body, "safeguards": True}).status_code == 200
    assert client.post("/api/chat", json={**body, "region": "UK"}).status_code == 200      # adequacy
    assert client.post("/api/chat", json={**body, "framework": "DPDP"}).status_code == 200


def test_stats(client):
    client.post("/api/consent", json={"session_id": SID, "minutes": 5})
    client.post("/api/chat", json={"session_id": SID, "text": "Call Priya Sharma on 9123456780", "region": "IN"})
    s = client.get(f"/api/stats/{SID}").json()
    assert s["tokens_in_vault"] == 2 and s["messages_sent"] == 1 and s["values_restored"] >= 1
