"""Entry point for hosting platforms (e.g. Vercel) that look for an `app` in app.py.
Locally, run: uvicorn vaultai.api:app --reload"""
from vaultai.api import app  # noqa: F401
