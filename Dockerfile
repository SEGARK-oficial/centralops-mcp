FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src/ ./src/

ENV PYTHONPATH=/app/src

RUN useradd -r -u 10001 -g root -s /usr/sbin/nologin -d /app appuser \
    && chown -R 10001:0 /app
USER 10001

HEALTHCHECK NONE

ENTRYPOINT ["python", "-m", "centralops_mcp"]
