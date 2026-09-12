# Multi stage so the runtime image carries the virtualenv and the model, not the
# build toolchain. Nothing is fetched at container start: the model is baked in,
# so a cold start cannot fail on a network hiccup.

FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libgomp1 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir ".[waf]"


FROM python:3.12-slim AS runtime

# libgomp is LightGBM's OpenMP runtime. Without it the booster will not import.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgomp1 curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 mlwaf

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY --chown=mlwaf:mlwaf src ./src
COPY --chown=mlwaf:mlwaf models/model.joblib ./models/model.joblib

# The decision log is written at runtime, so the directory has to belong to the
# unprivileged user rather than root.
RUN mkdir -p /app/data && chown mlwaf:mlwaf /app/data

USER mlwaf
EXPOSE 8080

ENV WAF_HOST=0.0.0.0 \
    WAF_PORT=8080 \
    WAF_DB_PATH=/app/data/waf.db \
    WAF_FEEDBACK_PATH=/app/data/feedback.jsonl \
    WAF_MODEL_PATH=/app/models/model.joblib

# Readiness, not liveness: the container is unhealthy until the model is warm.
HEALTHCHECK --interval=10s --timeout=3s --start-period=40s --retries=5 \
  CMD curl -fsS "http://127.0.0.1:${WAF_PORT}/_waf/readyz" || exit 1

CMD ["python", "-m", "mlwaf.waf.app"]
