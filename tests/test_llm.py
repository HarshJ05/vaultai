import httpx
import pytest

from vaultai import llm as llm_mod
from vaultai.llm import LLMClient, LLMError


class FakeResp:
    def __init__(self, status, text="hi [[V_ABCDEFGH]]"):
        self.status_code = status
        self.text = "{}" if status == 200 else '{"error": "busy"}'
        self._text = text

    def json(self):
        return {"candidates": [{"content": {"parts": [{"text": self._text}]}}]}


def fake_post(script):
    """script: list of status codes returned in order; records which model was called."""
    calls = []

    def post(url, **kw):
        calls.append(url.split("/models/")[1].split(":")[0])
        return FakeResp(script.pop(0))
    return post, calls


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(llm_mod.time, "sleep", lambda s: None)


def client():
    return LLMClient(api_key="k", model="m1", fallbacks=["m2"], retries=2)


def test_retries_then_succeeds(monkeypatch):
    post, calls = fake_post([503, 503, 200])
    monkeypatch.setattr(httpx, "post", post)
    c = client()
    assert c.complete("x") == "hi [[V_ABCDEFGH]]"
    assert calls == ["m1", "m1", "m1"] and c.last_model == "m1"


def test_falls_back_when_model_stays_busy(monkeypatch):
    post, calls = fake_post([503, 503, 503, 200])
    monkeypatch.setattr(httpx, "post", post)
    c = client()
    c.complete("x")
    assert calls == ["m1", "m1", "m1", "m2"] and c.last_model == "m2"


def test_retired_model_skips_straight_to_fallback(monkeypatch):
    post, calls = fake_post([404, 200])
    monkeypatch.setattr(httpx, "post", post)
    c = client()
    c.complete("x")
    assert calls == ["m1", "m2"]


def test_bad_key_fails_fast(monkeypatch):
    post, calls = fake_post([400])
    monkeypatch.setattr(httpx, "post", post)
    with pytest.raises(LLMError):
        client().complete("x")
    assert calls == ["m1"]


def test_all_busy_gives_friendly_error(monkeypatch):
    post, _ = fake_post([503] * 6)
    monkeypatch.setattr(httpx, "post", post)
    with pytest.raises(LLMError, match="try again"):
        client().complete("x")
