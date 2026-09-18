FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml requirements-server.txt requirements-ml.txt ./
COPY src ./src

RUN pip install --upgrade pip \
    && pip install -r requirements-server.txt \
    && pip install -r requirements-ml.txt \
    && pip install .

RUN useradd --create-home --uid 10001 cyclothone \
    && chown -R cyclothone:cyclothone /app
USER cyclothone

EXPOSE 8000

CMD ["uvicorn", "cyclothone.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
