"""FastAPI app: the privacy gateway in front of the LLM.

Flow for /api/chat:
  consent check -> detect PII -> encrypt + tokenize -> send redacted text to LLM
  -> restore placeholders in the reply -> return every stage so the UI can show it.
"""
from __future__ import annotations

import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .admin import AdminAuth
from .detector import PIIDetector
from .llm import LLMClient, LLMError
from .policy import COMPLIANCE_NOTES, PII_TYPES, REGIONS, risk_score, transfer_check
from .vault import Vault

STATIC = Path(__file__).parent / "static"

detector = PIIDetector(threshold=float(os.environ.get("PII_THRESHOLD", "0.5")))
# On Vercel only /tmp is writable, and it is cleared when an instance is recycled,
# so the hosted demo's vault is temporary. Locally or in Docker it persists in data/.
DEFAULT_DB = "/tmp/vaultai/vault.db" if os.environ.get("VERCEL") else "data/vault.db"
vault = Vault(os.environ.get("VAULT_DB", DEFAULT_DB),
              retention_minutes=int(os.environ.get("RETENTION_MINUTES", str(60 * 24))))
llm = LLMClient()
admin_auth = AdminAuth()
ADMIN_COOKIE = "vaultai_admin"

@asynccontextmanager
async def lifespan(_app):
    vault.purge_expired()          # apply the retention policy on every start
    yield


app = FastAPI(title="VaultAI", version="2.0", lifespan=lifespan,
              description="Detects and tokenizes PII before prompts reach an LLM.")
app.mount("/static", StaticFiles(directory=STATIC), name="static")

DEFAULT_SKIP = {code for code, t in PII_TYPES.items() if not t.redact_default}


# ---- request models --------------------------------------------------------------
class TextIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    skip_types: Optional[list[str]] = None   # PII types the user chose not to redact


class SessionTextIn(TextIn):
    session_id: str = Field(min_length=8, max_length=64)


class ChatIn(SessionTextIn):
    framework: Literal["DPDP", "GDPR"] = "DPDP"
    region: str = "US"              # where the AI model's server is
    safeguards: bool = False        # SCCs / DPF certification in place with the AI provider


class RestoreIn(BaseModel):
    session_id: str = Field(min_length=8, max_length=64)
    text: str = Field(min_length=1, max_length=20000)


class ConsentIn(BaseModel):
    session_id: str = Field(min_length=8, max_length=64)
    minutes: int = Field(ge=1, le=24 * 60)
    purpose: str = Field(default="AI assistant conversation", max_length=200)


class EraseIn(BaseModel):
    value: str = Field(min_length=1, max_length=200)
    pii_type: Optional[str] = None   # optional: erase is type-agnostic by default
    reason: str = Field(default="", max_length=300)


class EraseSessionIn(BaseModel):
    session_id: str = Field(min_length=8, max_length=64)
    reason: str = Field(default="", max_length=300)


# ---- helpers ---------------------------------------------------------------------
def _detect(text: str, skip: Optional[list[str]]):
    skip_set = DEFAULT_SKIP if skip is None else set(skip)
    entities = detector.detect(text)
    to_redact = [e for e in entities if e.type not in skip_set]
    return entities, to_redact


def _entity_view(entities, redacted_set):
    out = []
    for e in entities:
        d = e.to_dict()
        d["label"] = PII_TYPES[e.type].label if e.type in PII_TYPES else e.type
        d["category"] = PII_TYPES[e.type].category if e.type in PII_TYPES else "Other"
        d["redacted"] = e in redacted_set
        out.append(d)
    return out


# ---- routes ----------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "llm_mode": llm.mode, "token_style": vault.token_style, "model": llm.model if llm.mode == "gemini" else None,
            "ner": detector.use_ner,
            "pii_types": {c: {"label": t.label, "category": t.category, "risk": t.risk,
                              "redact_default": t.redact_default} for c, t in PII_TYPES.items()},
            "notes": COMPLIANCE_NOTES,
            "regions": {k: v["label"] for k, v in REGIONS.items()}}


@app.get("/api/transfer-check")
def transfer(region: str, framework: Literal["DPDP", "GDPR"] = "DPDP", safeguards: bool = False):
    return transfer_check(region, framework, safeguards)


@app.get("/api/stats/{session_id}")
def stats(session_id: str):
    events = vault.audit_log(session_id, 5000)
    count = lambda name: sum(e["event"] == name for e in events)  # noqa: E731
    return {"tokens_in_vault": len(vault.session_entries(session_id)),
            "items_tokenized": count("tokenized"),
            "values_restored": count("restored"),
            "messages_sent": count("sent_to_llm"),
            "blocked": count("blocked_no_consent") + count("blocked_transfer"),
            "audit_events": len(events)}


@app.get("/api/lineage/{session_id}")
def lineage(session_id: str):
    """Life story of every token in a session, oldest event first:
    tokenized -> restored ... -> erased. Built from the audit log; never shows values."""
    entries = {e["placeholder"]: e for e in vault.session_entries(session_id)}
    events = list(reversed(vault.audit_log(session_id, 5000)))
    tokens: dict[str, dict] = {}
    for ev in events:
        ph = ev["placeholder"]
        if not ph:
            continue
        t = tokens.setdefault(ph, {"token": ph, "events": [], "in_vault": ph in entries,
                                   "expires_at": entries.get(ph, {}).get("expires_at")})
        t["events"].append({"event": ev["event"], "ts": ev["ts"], "detail": ev["detail"]})
    return {"tokens": list(tokens.values())}


@app.post("/api/scan")
def scan(body: TextIn):
    """Detect only. Nothing is stored."""
    entities, to_redact = _detect(body.text, body.skip_types)
    return {"entities": _entity_view(entities, to_redact),
            "risk": risk_score([e.type for e in to_redact])}


@app.post("/api/redact")
def redact(body: SessionTextIn):
    entities, to_redact = _detect(body.text, body.skip_types)
    redacted, mapping = vault.redact(body.session_id, body.text, to_redact)
    return {"redacted": redacted, "mapping": mapping, "entities": _entity_view(entities, to_redact),
            "risk": risk_score([e.type for e in to_redact])}


@app.post("/api/chat")
def chat(body: ChatIn):
    consent = vault.consent_status(body.session_id)
    if consent["state"] != "active":
        vault.log("blocked_no_consent", body.session_id, detail=f"{body.framework}; consent {consent['state']}")
        raise HTTPException(403, detail={
            "code": "consent_required",
            "message": f"Consent is {consent['state']}. Under {body.framework} personal data is only "
                       "processed with valid consent. Grant consent to continue.",
        })
    xfer = transfer_check(body.region, body.framework, body.safeguards)
    if not xfer["allowed"]:
        vault.log("blocked_transfer", body.session_id, detail=f"{body.framework}; region {body.region}")
        raise HTTPException(403, detail={"code": "transfer_blocked", "message": xfer["basis"]})
    vault.purge_expired()
    ms = lambda t0: round((time.perf_counter() - t0) * 1000, 1)  # noqa: E731
    t = time.perf_counter()
    entities, to_redact = _detect(body.text, body.skip_types)
    t_detect = ms(t)
    t = time.perf_counter()
    redacted, mapping = vault.redact(body.session_id, body.text, to_redact)
    t_vault = ms(t)
    vault.log("sent_to_llm", body.session_id,
              detail=f"{len(mapping)} tokens; region {body.region}; mode={llm.mode}")
    t = time.perf_counter()
    try:
        raw_reply = llm.complete(redacted)
    except LLMError as e:
        vault.log("llm_error", body.session_id, detail=str(e)[:200])
        raise HTTPException(502, detail={"code": "llm_error", "message": str(e)})
    t_llm = ms(t)
    t = time.perf_counter()
    segments, used = vault.restore_segments(body.session_id, raw_reply, actor="chat")
    t_restore = ms(t)
    restored = "".join(s["text"] for s in segments)
    return {
        "reply_segments": segments,
        "entities": _entity_view(entities, to_redact),
        "risk": risk_score([e.type for e in to_redact]),
        "redacted_prompt": redacted,
        "mapping": mapping,
        "llm_reply_raw": raw_reply,
        "reply": restored,
        "restored_placeholders": used,
        "llm_mode": llm.mode,
        "llm_model": llm.last_model,
        "transfer": xfer,
        "timings_ms": {"detect": t_detect, "tokenize": t_vault, "llm": t_llm, "restore": t_restore},
    }


@app.post("/api/restore")
def restore(body: RestoreIn):
    text, used = vault.restore(body.session_id, body.text, actor="api")
    return {"text": text, "restored_placeholders": used}


@app.get("/api/consent/{session_id}")
def consent_get(session_id: str):
    return vault.consent_status(session_id)


@app.post("/api/consent")
def consent_grant(body: ConsentIn):
    return vault.grant_consent(body.session_id, body.minutes, body.purpose)


@app.delete("/api/consent/{session_id}")
def consent_withdraw(session_id: str):
    return vault.withdraw_consent(session_id)


@app.post("/api/erase")
def erase(body: EraseIn):
    if body.pii_type is not None and body.pii_type not in PII_TYPES:
        raise HTTPException(400, detail={"code": "bad_type", "message": f"Unknown PII type {body.pii_type}"})
    n = vault.erase_value(body.value, body.reason, body.pii_type)
    return {"erased": n}


@app.post("/api/erase-session")
def erase_session(body: EraseSessionIn):
    return {"erased": vault.erase_session(body.session_id, body.reason)}


@app.get("/api/vault/{session_id}")
def vault_entries(session_id: str):
    """Placeholders and metadata for a session. Never returns decrypted values."""
    return {"entries": vault.session_entries(session_id)}


@app.get("/api/audit")
def audit(session_id: str, limit: int = 100):
    """Audit log for ONE session. The log across all sessions is admin-only (/api/admin/audit)."""
    return {"events": vault.audit_log(session_id, min(limit, 500))}


# ---- admin console ---------------------------------------------------------------
class AdminLoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=200)


class AdminEntryIn(BaseModel):
    id: int
    reason: str = Field(default="", max_length=300)


def require_admin(request: Request) -> str:
    name = admin_auth.check(request.cookies.get(ADMIN_COOKIE))
    if not name:
        raise HTTPException(401, detail={"code": "admin_required", "message": "Admin login required."})
    return name


@app.post("/api/admin/login")
def admin_login(body: AdminLoginIn, request: Request, response: Response):
    client = request.client.host if request.client else "unknown"
    wait = admin_auth.locked_for(client)
    if wait:
        raise HTTPException(429, detail={"code": "locked", "message": f"Too many attempts. Try again in {wait // 60 + 1} min."})
    token = admin_auth.login(body.username, body.password, client)
    if not token:
        vault.log("admin_login_failed", detail=f"username '{body.username[:32]}' from {client}")
        raise HTTPException(401, detail={"code": "bad_login", "message": "Wrong username or password."})
    vault.log("admin_login", detail=f"'{admin_auth.username}' from {client}")
    response.set_cookie(ADMIN_COOKIE, token, httponly=True, samesite="strict", max_age=30 * 60, path="/api/admin")
    return {"username": admin_auth.username}


@app.post("/api/admin/logout")
def admin_logout(request: Request, response: Response):
    admin_auth.logout(request.cookies.get(ADMIN_COOKIE))
    response.delete_cookie(ADMIN_COOKIE, path="/api/admin")
    return {"ok": True}


@app.get("/api/admin/me")
def admin_me(admin: str = Depends(require_admin)):
    return {"username": admin}


@app.get("/api/admin/vault")
def admin_vault(q: str = "", admin: str = Depends(require_admin)):
    """Every token across all sessions, values masked. Search by token, session, type or real value."""
    entries = vault.admin_entries(q[:200])
    for e in entries:
        e["label"] = PII_TYPES[e["pii_type"]].label if e["pii_type"] in PII_TYPES else e["pii_type"]
    return {"entries": entries}


@app.post("/api/admin/reveal")
def admin_reveal(body: AdminEntryIn, admin: str = Depends(require_admin)):
    r = vault.admin_reveal(body.id, admin)
    if r is None:
        raise HTTPException(404, detail={"code": "not_found", "message": "Entry not found (erased or expired)."})
    return r


@app.post("/api/admin/delete")
def admin_delete(body: AdminEntryIn, admin: str = Depends(require_admin)):
    if not vault.admin_delete(body.id, admin, body.reason):
        raise HTTPException(404, detail={"code": "not_found", "message": "Entry not found."})
    return {"ok": True}


@app.get("/api/admin/audit")
def admin_audit(limit: int = 300, admin: str = Depends(require_admin)):
    return {"events": vault.audit_log(None, min(limit, 1000))}
