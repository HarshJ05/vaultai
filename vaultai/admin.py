"""Admin login for the vault console.

* The password is never stored, only an scrypt hash (with a random salt) kept in memory.
* Credentials come from ADMIN_USERNAME / ADMIN_PASSWORD. If no password is set, a random
  one is generated at start-up and printed once in the terminal (local development only).
* A successful login gets a random session token (sent as an HttpOnly cookie) that
  expires after 30 minutes of inactivity.
* 5 wrong passwords from the same address within 10 minutes lock that address for 5 minutes.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time

SESSION_SECONDS = 30 * 60
MAX_FAILS, FAIL_WINDOW, LOCK_SECONDS = 5, 10 * 60, 5 * 60


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)


class AdminAuth:
    def __init__(self, username: str | None = None, password: str | None = None):
        self.username = username or os.environ.get("ADMIN_USERNAME", "admin")
        password = password or os.environ.get("ADMIN_PASSWORD", "")
        self.generated_password = None
        if not password:
            password = secrets.token_urlsafe(12)
            self.generated_password = password
            print("\n" + "=" * 64 +
                  f"\n  VaultAI admin console\n  username: {self.username}\n  password: {password}"
                  "\n  (set ADMIN_USERNAME / ADMIN_PASSWORD in .env to choose your own)\n" + "=" * 64 + "\n",
                  flush=True)
        self._salt = secrets.token_bytes(16)
        self._hash = _hash(password, self._salt)
        self._sessions: dict[str, tuple[str, float]] = {}
        self._fails: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    # ---- login ------------------------------------------------------------------
    def locked_for(self, client: str) -> int:
        return max(0, int(self._locked_until.get(client, 0) - time.time()))

    def login(self, username: str, password: str, client: str) -> str | None:
        """Return a session token, or None for a bad login."""
        if self.locked_for(client):
            return None
        # compare both fields in constant time, and always hash, so timing reveals nothing
        ok_pw = hmac.compare_digest(_hash(password, self._salt), self._hash)
        ok_user = hmac.compare_digest(username.encode(), self.username.encode())
        with self._lock:
            if ok_pw and ok_user:
                self._fails.pop(client, None)
                token = secrets.token_urlsafe(32)
                self._sessions[token] = (self.username, time.time() + SESSION_SECONDS)
                return token
            now = time.time()
            recent = [t for t in self._fails.get(client, []) if now - t < FAIL_WINDOW] + [now]
            self._fails[client] = recent
            if len(recent) >= MAX_FAILS:
                self._locked_until[client] = now + LOCK_SECONDS
                self._fails[client] = []
            return None

    def check(self, token: str | None) -> str | None:
        """Return the admin's username for a valid session token (and extend it)."""
        if not token:
            return None
        with self._lock:
            entry = self._sessions.get(token)
            if not entry or entry[1] < time.time():
                self._sessions.pop(token, None)
                return None
            self._sessions[token] = (entry[0], time.time() + SESSION_SECONDS)
            return entry[0]

    def logout(self, token: str | None) -> None:
        with self._lock:
            self._sessions.pop(token or "", None)
