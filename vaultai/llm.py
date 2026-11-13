"""LLM client. Only ever receives redacted text.

With GEMINI_API_KEY set, it calls Google's Gemini API. Without a key it runs in a
clearly labelled demo mode so the whole privacy flow can still be tried end to end.
"""
from __future__ import annotations

import os
import re
import time

import httpx

SYSTEM_PROMPT = (
    "You are a helpful assistant inside a privacy gateway. Personal details in the user's "
    "message have been replaced with tokens such as [[V_8F3K2Q9X]]. Each token stands for one "
    "private value (a name, number, address or similar). Treat it as that value. When you refer "
    "to one, copy the token exactly, including both pairs of square brackets. Never ask for, "
    "guess or describe the real values."
)

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


class LLMError(RuntimeError):
    pass


# Status codes worth retrying: rate limit, server error, overloaded, timeout.
RETRYABLE = {429, 500, 502, 503, 504}


class LLMClient:
    """Gemini client with retries and model fallback.

    Free-tier models get overloaded (HTTP 503) or rate-limited (429) at busy times. Instead of
    failing, each model is retried with a short backoff; if it stays busy, or the model name is
    retired (404), the next model in GEMINI_FALLBACK_MODELS is tried. The redacted prompt is the
    only thing ever sent, whichever model answers.
    """

    def __init__(self, api_key: str | None = None, model: str | None = None, timeout: float = 30,
                 fallbacks: list[str] | None = None, retries: int = 2, backoff: float = 1.0):
        self.api_key = api_key if api_key is not None else os.environ.get("GEMINI_API_KEY", "")
        self.model = model or os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")
        env_fb = os.environ.get("GEMINI_FALLBACK_MODELS", "gemini-3.5-flash,gemini-3.5-flash-lite")
        fb = fallbacks if fallbacks is not None else [m.strip() for m in env_fb.split(",") if m.strip()]
        self.models = [self.model] + [m for m in fb if m != self.model]
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.last_model: str | None = None     # which model actually answered

    @property
    def mode(self) -> str:
        return "gemini" if self.api_key else "demo"

    def complete(self, redacted_prompt: str) -> str:
        if not self.api_key:
            self.last_model = "demo"
            return self._demo_reply(redacted_prompt)
        body = {
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": redacted_prompt}]}],
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 800},
        }
        errors = []
        for model in self.models:
            for attempt in range(self.retries + 1):
                try:
                    r = httpx.post(GEMINI_URL.format(model=model), json=body,
                                   headers={"x-goog-api-key": self.api_key}, timeout=self.timeout)
                except httpx.HTTPError as e:
                    errors.append(f"{model}: network error ({type(e).__name__})")
                    status = 503
                else:
                    status = r.status_code
                    if status == 200:
                        self.last_model = model
                        return self._text(r)
                    errors.append(f"{model}: {status}")
                    if status in (400, 401, 403):          # bad key / bad request: no point retrying
                        raise LLMError(f"Gemini returned {status}: {r.text[:300]}")
                if status == 404 or status not in RETRYABLE:
                    break                                   # model retired/unknown: try the next model
                if attempt < self.retries:
                    time.sleep(self.backoff * (2 ** attempt))   # 1 s, 2 s
        raise LLMError("All Gemini models are busy or unavailable right now (" + "; ".join(errors[-4:]) +
                       "). Your data stayed protected. Please try again in a minute.")

    @staticmethod
    def _text(r) -> str:
        try:
            parts = r.json()["candidates"][0]["content"]["parts"]
            return "".join(p.get("text", "") for p in parts).strip()
        except (KeyError, IndexError, ValueError) as e:
            raise LLMError("Gemini returned no text (possibly blocked by safety filters).") from e

    @staticmethod
    def _demo_reply(prompt: str) -> str:
        """Deterministic stand-in reply that echoes the placeholders it received, so the
        restore step can be demonstrated without an API key."""
        placeholders = list(dict.fromkeys(re.findall(r"\[\[V_[A-Z0-9]+\]\]|<[A-Z_]+_\d+>", prompt)))
        if not placeholders:
            return ("[Demo mode: no API key set] Your message contained no personal data, "
                    "so it could be sent to the model unchanged.")
        listed = ", ".join(placeholders)
        return ("[Demo mode: no API key set] Got it. I received your request with these "
                f"protected details: {listed}. I can act on them without ever seeing the real values, "
                f"for example: 'Noted, I will follow up with {placeholders[0]}.'")
