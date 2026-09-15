FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    yara libyara-dev ca-certificates tini iptables \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10001 sandbox
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod 0755 /app/entrypoint.sh

USER sandbox
RUN python -m playwright install chromium
COPY --chown=sandbox:sandbox src/ /app/src/
COPY --chown=sandbox:sandbox rules/ /app/rules/

VOLUME ["/downloads"]
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SANDBOX_TIMEOUT_MS=25000 \
    SANDBOX_MAX_CONCURRENCY=4 \
    SANDBOX_MAX_DOWNLOAD_BYTES=26214400 \
    SANDBOX_APPLY_IPTABLES=1

EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
