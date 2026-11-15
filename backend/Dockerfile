FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Playwright's Chromium + its OS-level dependencies (fonts, codecs, etc.),
# needed by the Application-Layer Recon module. Adds real time/size to the
# image build -- only actually used if "recon" is enabled in Settings.
RUN playwright install --with-deps chromium

COPY . .

EXPOSE 8420

HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=10 \
    CMD curl -sf http://127.0.0.1:8420/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8420"]
