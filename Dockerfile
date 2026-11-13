FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 VAULT_DB=/app/data/vault.db

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vaultai ./vaultai

# Run as a non-root user; only /app/data is writable.
RUN useradd --create-home vault && mkdir -p /app/data && chown vault /app/data
USER vault

EXPOSE 8000
# Hosts such as Render or Railway set $PORT; default to 8000 locally.
CMD ["sh", "-c", "uvicorn vaultai.api:app --host 0.0.0.0 --port ${PORT:-8000}"]
