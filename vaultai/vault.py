"""Encrypted, reversible token vault.

How it works, in one paragraph:
  When PII is found, the real value is encrypted (Fernet = AES-128-CBC + HMAC-SHA256)
  and stored in SQLite. The text sent to the LLM gets an opaque random token such as
  [[V_8F3K2Q9X]] instead. The token reveals nothing, not even what kind of data it
  replaced. A keyed fingerprint (HMAC-SHA256 of the value) is stored next to it, so:
    * the same value in the same conversation always gets the same token,
      which keeps the LLM's reasoning consistent ("[[V_A1]] called [[V_B2]]");
    * we can find and erase every copy of a value (right to erasure) WITHOUT
      decrypting anything and without storing the value in plain text.
  When the LLM replies, placeholders are swapped back for the decrypted values.
  Every action is written to an append-only audit log.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet

from .detector import Entity

# Opaque tokens: [[V_8F3K2Q9X]]. 8 characters from an alphabet without look-alikes
# (no 0/O, 1/I/L), so 30^8 = 656 billion possible tokens per session.
TOKEN_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ2345679"
TOKEN_LEN = 8
# Tolerant on the way back: LLMs sometimes drop a bracket or add spaces.
OPAQUE_RE = r"\[{1,2}\s*V_([A-Z0-9]{%d})\s*\]{1,2}" % TOKEN_LEN
# Optional "typed" style (<PHONE_1>) for when the LLM needs to know the kind of data.
TYPED_RE = r"[<\[]\s*([A-Z][A-Z_]*?_\d+)\s*[>\]]"
PLACEHOLDER_RE = re.compile(f"{OPAQUE_RE}|{TYPED_RE}")


def _canonical(m: re.Match) -> str:
    return f"[[V_{m.group(1)}]]" if m.group(1) else f"<{m.group(2)}>"

SCHEMA = """
CREATE TABLE IF NOT EXISTS vault (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL,
    placeholder  TEXT NOT NULL,
    pii_type     TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    ciphertext   BLOB NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    UNIQUE (session_id, placeholder),
    UNIQUE (session_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_vault_fp ON vault (fingerprint);

CREATE TABLE IF NOT EXISTS consent (
    session_id   TEXT PRIMARY KEY,
    purpose      TEXT NOT NULL,
    granted_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    withdrawn    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    session_id   TEXT,
    event        TEXT NOT NULL,
    pii_type     TEXT,
    placeholder  TEXT,
    detail       TEXT
);
"""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def normalise(pii_type: str, value: str) -> str:
    """Make '98765 43210', '+91-9876543210' and '9876543210' fingerprint the same."""
    v = value.strip()
    if pii_type in {"PHONE", "AADHAAR", "CREDIT_CARD", "BANK_ACCOUNT", "PIN_CODE"}:
        digits = "".join(ch for ch in v if ch.isdigit())
        if pii_type == "PHONE" and len(digits) > 10:
            digits = digits[-10:]
        return digits
    if pii_type in {"EMAIL", "UPI_ID"}:
        return v.lower()
    if pii_type in {"PAN", "IFSC", "GSTIN", "PASSPORT", "VOTER_ID", "VEHICLE_REG"}:
        return re.sub(r"[\s-]", "", v.upper())
    return " ".join(v.split()).lower()


class Vault:
    def __init__(self, db_path: str | Path = "data/vault.db", enc_key: Optional[bytes] = None,
                 hmac_key: Optional[bytes] = None, retention_minutes: int = 60 * 24,
                 token_style: Optional[str] = None):
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        enc_key = enc_key or os.environ.get("VAULT_ENC_KEY", "").encode() or None
        hmac_key = hmac_key or os.environ.get("VAULT_HMAC_KEY", "").encode() or None
        if not enc_key or not hmac_key:
            enc_key, hmac_key = self._dev_keys(enc_key, hmac_key)
        self._fernet = Fernet(enc_key)
        self._hmac_key = hmac_key
        self.retention = timedelta(minutes=retention_minutes)
        self.token_style = (token_style or os.environ.get("TOKEN_STYLE", "opaque")).lower()
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)

    # ---- keys -------------------------------------------------------------------
    def _dev_keys(self, enc_key, hmac_key):
        """Local development only: keep generated keys in a file next to the DB.
        In production both keys come from environment variables / a secrets manager."""
        if self.db_path == ":memory:":
            return enc_key or Fernet.generate_key(), hmac_key or os.urandom(32).hex().encode()
        key_file = Path(self.db_path).with_suffix(".keys")
        if key_file.exists():
            e, h = key_file.read_text().split("\n")[:2]
        else:
            e, h = Fernet.generate_key().decode(), os.urandom(32).hex()
            key_file.write_text(f"{e}\n{h}\n")
            key_file.chmod(0o600)
        return enc_key or e.encode(), hmac_key or h.encode()

    def fingerprint(self, pii_type: str, value: str) -> str:
        msg = f"{pii_type}|{normalise(pii_type, value)}".encode()
        return hmac.new(self._hmac_key, msg, hashlib.sha256).hexdigest()

    # ---- audit ------------------------------------------------------------------
    def log(self, event: str, session_id: Optional[str] = None, pii_type: Optional[str] = None,
            placeholder: Optional[str] = None, detail: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit (ts, session_id, event, pii_type, placeholder, detail) VALUES (?,?,?,?,?,?)",
                (_iso(_now()), session_id, event, pii_type, placeholder, detail))
            self._conn.commit()

    def audit_log(self, session_id: Optional[str] = None, limit: int = 100) -> list[dict]:
        q = "SELECT * FROM audit"
        args: tuple = ()
        if session_id:
            q += " WHERE session_id = ?"
            args = (session_id,)
        q += " ORDER BY id DESC LIMIT ?"
        return [dict(r) for r in self._conn.execute(q, args + (limit,))]

    # ---- tokenize ---------------------------------------------------------------
    def _new_placeholder(self, session_id: str, pii_type: str) -> str:
        if self.token_style == "typed":
            n = self._conn.execute(
                "SELECT COUNT(*) FROM vault WHERE session_id=? AND pii_type=?",
                (session_id, pii_type)).fetchone()[0] + 1
            return f"<{pii_type}_{n}>"
        while True:  # random, so the token carries no information about the value or its type
            tok = "[[V_" + "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(TOKEN_LEN)) + "]]"
            if not self._conn.execute("SELECT 1 FROM vault WHERE session_id=? AND placeholder=?",
                                      (session_id, tok)).fetchone():
                return tok

    def tokenize(self, session_id: str, pii_type: str, value: str) -> str:
        """Return the token for this value, creating an encrypted entry if new."""
        fp = self.fingerprint(pii_type, value)
        with self._lock:
            row = self._conn.execute(
                "SELECT placeholder FROM vault WHERE session_id=? AND fingerprint=?",
                (session_id, fp)).fetchone()
            if row:
                return row["placeholder"]
            placeholder = self._new_placeholder(session_id, pii_type)
            now = _now()
            self._conn.execute(
                "INSERT INTO vault (session_id, placeholder, pii_type, fingerprint, ciphertext, created_at, expires_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (session_id, placeholder, pii_type, fp, self._fernet.encrypt(value.encode()),
                 _iso(now), _iso(now + self.retention)))
            self._conn.commit()
        self.log("tokenized", session_id, pii_type, placeholder)
        return placeholder

    def redact(self, session_id: str, text: str, entities: list[Entity]) -> tuple[str, list[dict]]:
        """Replace each entity span with its placeholder. Works right-to-left so the
        character offsets of earlier entities stay valid while we edit the string."""
        mapping = []
        out = text
        for e in sorted(entities, key=lambda e: e.start, reverse=True):
            ph = self.tokenize(session_id, e.type, e.text)
            out = out[:e.start] + ph + out[e.end:]
            mapping.append({"placeholder": ph, "type": e.type, "start": e.start, "end": e.end})
        return out, list(reversed(mapping))

    # ---- restore ----------------------------------------------------------------
    def restore_segments(self, session_id: str, text: str, actor: str = "user") -> tuple[list[dict], list[str]]:
        """Split `text` into plain pieces and restored pieces. Unknown, expired or
        erased placeholders become a visible [REDACTED] marker, never a guess.
        Segments let the UI highlight exactly which words came out of the vault."""
        rows = {r["placeholder"]: r for r in self._conn.execute(
            "SELECT placeholder, pii_type, ciphertext, expires_at FROM vault WHERE session_id=?",
            (session_id,))}
        now = _iso(_now())
        segments: list[dict] = []
        restored: set[str] = set()
        pos = 0
        for m in PLACEHOLDER_RE.finditer(text):
            if m.start() > pos:
                segments.append({"text": text[pos:m.start()]})
            ph = _canonical(m)
            r = rows.get(ph)
            if r is None or r["expires_at"] <= now:
                segments.append({"text": "[REDACTED]", "placeholder": ph, "status": "missing"})
            else:
                segments.append({"text": self._fernet.decrypt(r["ciphertext"]).decode(),
                                 "placeholder": ph, "type": r["pii_type"], "status": "restored"})
                restored.add(ph)
            pos = m.end()
        if pos < len(text):
            segments.append({"text": text[pos:]})
        for ph in sorted(restored):
            self.log("restored", session_id, rows[ph]["pii_type"], ph, f"by {actor}")
        return segments, sorted(restored)

    def restore(self, session_id: str, text: str, actor: str = "user") -> tuple[str, list[str]]:
        """Swap placeholders in `text` back to real values."""
        segments, used = self.restore_segments(session_id, text, actor)
        return "".join(s["text"] for s in segments), used

    def session_entries(self, session_id: str) -> list[dict]:
        """Metadata only (never the decrypted value)."""
        return [dict(r) for r in self._conn.execute(
            "SELECT placeholder, pii_type, created_at, expires_at FROM vault WHERE session_id=? ORDER BY id",
            (session_id,))]

    # ---- erasure & retention --------------------------------------------------------
    def erase_value(self, value: str, reason: str = "", pii_type: Optional[str] = None) -> int:
        """Right to erasure: delete every stored copy of this value across all sessions.
        The person asking doesn't need to say what kind of data it is: we compute the
        fingerprint the value would have under every type and delete all matches.
        Found through the keyed fingerprint, so nothing has to be decrypted."""
        from .policy import PII_TYPES
        types = [pii_type] if pii_type else list(PII_TYPES)
        fps = list({self.fingerprint(t, value) for t in types})
        marks = ",".join("?" * len(fps))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT session_id, placeholder, pii_type FROM vault WHERE fingerprint IN ({marks})",
                fps).fetchall()
            self._conn.execute(f"DELETE FROM vault WHERE fingerprint IN ({marks})", fps)
            self._conn.commit()
        for r in rows:
            self.log("erased", r["session_id"], r["pii_type"], r["placeholder"], reason or "erasure request")
        if not rows:
            self.log("erase_not_found", None, None, None, reason or "erasure request")
        return len(rows)

    def erase_session(self, session_id: str, reason: str = "") -> int:
        with self._lock:
            n = self._conn.execute("DELETE FROM vault WHERE session_id=?", (session_id,)).rowcount
            self._conn.commit()
        self.log("session_erased", session_id, None, None, f"{n} entries; {reason}".strip("; "))
        return n

    def purge_expired(self) -> int:
        with self._lock:
            n = self._conn.execute("DELETE FROM vault WHERE expires_at <= ?", (_iso(_now()),)).rowcount
            self._conn.commit()
        if n:
            self.log("retention_purge", None, None, None, f"{n} expired entries deleted")
        return n

    # ---- consent ------------------------------------------------------------------
    def grant_consent(self, session_id: str, minutes: int, purpose: str) -> dict:
        now = _now()
        with self._lock:
            self._conn.execute(
                "INSERT INTO consent (session_id, purpose, granted_at, expires_at, withdrawn) VALUES (?,?,?,?,0)"
                " ON CONFLICT(session_id) DO UPDATE SET purpose=excluded.purpose,"
                " granted_at=excluded.granted_at, expires_at=excluded.expires_at, withdrawn=0",
                (session_id, purpose, _iso(now), _iso(now + timedelta(minutes=minutes))))
            self._conn.commit()
        self.log("consent_granted", session_id, detail=f"{minutes} min for '{purpose}'")
        return self.consent_status(session_id)

    def withdraw_consent(self, session_id: str) -> dict:
        with self._lock:
            self._conn.execute("UPDATE consent SET withdrawn=1 WHERE session_id=?", (session_id,))
            self._conn.commit()
        self.log("consent_withdrawn", session_id)
        return self.consent_status(session_id)

    def consent_status(self, session_id: str) -> dict:
        r = self._conn.execute("SELECT * FROM consent WHERE session_id=?", (session_id,)).fetchone()
        if r is None:
            return {"state": "none", "seconds_left": 0, "purpose": None}
        if r["withdrawn"]:
            return {"state": "withdrawn", "seconds_left": 0, "purpose": r["purpose"]}
        left = (datetime.fromisoformat(r["expires_at"]) - _now()).total_seconds()
        if left <= 0:
            return {"state": "expired", "seconds_left": 0, "purpose": r["purpose"]}
        return {"state": "active", "seconds_left": int(left), "purpose": r["purpose"]}

    # ---- admin console ---------------------------------------------------------------
    def admin_entries(self, query: str = "", limit: int = 500) -> list[dict]:
        """All vault entries across sessions, with values MASKED.
        `query` matches a token, a session id, a data type, or a real value. A real value
        is matched through its fingerprint, so searching never decrypts the whole vault."""
        sql = "SELECT id, session_id, placeholder, pii_type, ciphertext, created_at, expires_at FROM vault"
        args: list = []
        q = query.strip()
        if q:
            from .policy import PII_TYPES
            fps = list({self.fingerprint(t, q) for t in PII_TYPES})
            like = f"%{q.upper()}%"
            sql += (" WHERE UPPER(placeholder) LIKE ? OR UPPER(session_id) LIKE ? OR pii_type = ?"
                    f" OR fingerprint IN ({','.join('?' * len(fps))})")
            args = [like, like, q.upper().replace(" ", "_"), *fps]
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        out = []
        for r in self._conn.execute(sql, args):
            value = self._fernet.decrypt(r["ciphertext"]).decode()
            out.append({"id": r["id"], "session_id": r["session_id"], "token": r["placeholder"],
                        "pii_type": r["pii_type"], "masked": mask(r["pii_type"], value),
                        "created_at": r["created_at"], "expires_at": r["expires_at"]})
        return out

    def admin_reveal(self, entry_id: int, admin: str) -> Optional[dict]:
        """Decrypt one entry for an admin. Every reveal is written to the audit log."""
        r = self._conn.execute("SELECT session_id, placeholder, pii_type, ciphertext FROM vault WHERE id=?",
                               (entry_id,)).fetchone()
        if r is None:
            return None
        self.log("admin_revealed", r["session_id"], r["pii_type"], r["placeholder"], f"by admin '{admin}'")
        return {"id": entry_id, "token": r["placeholder"], "value": self._fernet.decrypt(r["ciphertext"]).decode()}

    def admin_delete(self, entry_id: int, admin: str, reason: str = "") -> bool:
        with self._lock:
            r = self._conn.execute("SELECT session_id, placeholder, pii_type FROM vault WHERE id=?",
                                   (entry_id,)).fetchone()
            if r is None:
                return False
            self._conn.execute("DELETE FROM vault WHERE id=?", (entry_id,))
            self._conn.commit()
        self.log("erased", r["session_id"], r["pii_type"], r["placeholder"],
                 f"by admin '{admin}'" + (f"; {reason}" if reason else ""))
        return True


def mask(pii_type: str, value: str) -> str:
    """Show just enough to recognise a record without exposing it."""
    v = value.strip()
    if pii_type == "EMAIL" and "@" in v:
        user, dom = v.split("@", 1)
        return f"{user[:1]}{'•' * max(2, len(user) - 1)}@{dom}"
    if pii_type == "UPI_ID" and "@" in v:
        user, psp = v.split("@", 1)
        return f"{user[:1]}{'•' * max(2, len(user) - 1)}@{psp}"
    digits = sum(ch.isdigit() for ch in v)
    if digits >= 6:                      # numbers: keep only the last 4 digits
        keep, seen, out = 4, 0, []
        for ch in reversed(v):
            if ch.isdigit():
                seen += 1
                out.append(ch if seen <= keep else "•")
            else:
                out.append(ch)
        return "".join(reversed(out))
    if pii_type in {"PERSON", "LOCATION", "ORGANIZATION"}:
        return " ".join(w[:1] + "•" * max(2, len(w) - 1) for w in v.split())
    return v[:2] + "•" * max(3, len(v) - 3) + v[-1:] if len(v) > 4 else "•" * len(v)
