# syntax=docker/dockerfile:1
#
# SkyRecon runtime image.
#
#   docker build -t skyrecon .                              # core, ~180 MB
#   docker build --build-arg WITH_ML=1 -t skyrecon:ml .     # + Isolation Forest
#   docker build --build-arg WITH_POSTGRES=1 -t skyrecon .  # + psycopg driver
#
# The core image deliberately excludes numpy and scikit-learn: without them the
# anomaly detector uses a pure-Python z-score baseline and the API is identical.

# ── build stage ──────────────────────────────────────────────────────────
# Wheels are built once, with a compiler present, then thrown away.
FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

ARG WITH_ML=0
ARG WITH_POSTGRES=0

WORKDIR /wheels
COPY requirements.txt requirements-ml.txt requirements-postgres.txt ./
RUN pip wheel --wheel-dir /wheels -r requirements.txt \
 && if [ "$WITH_ML" = "1" ]; then \
      pip wheel --wheel-dir /wheels -r requirements-ml.txt; fi \
 && if [ "$WITH_POSTGRES" = "1" ]; then \
      pip wheel --wheel-dir /wheels -r requirements-postgres.txt; fi


# ── runtime stage ────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    SKYRECON_ENV=production \
    SKYRECON_DATABASE_URL=sqlite:////data/skyrecon.db

# curl is the healthcheck and the GeoIP fetch below; gzip unpacks it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl gzip \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 --shell /usr/sbin/nologin skyrecon

# ── GeoIP / ASN databases ────────────────────────────────────────────────
# DB-IP City Lite + ASN Lite (CC BY 4.0, https://db-ip.com/db/lite.php) — no
# API key, no signup, fetched once here so app/geoip.py never touches the
# network at runtime. Tries this month then the two before it, since a new
# file is only published a few days into each month. Failure is non-fatal:
# the image still builds and enrichment just runs without that field.
RUN mkdir -p /srv/geoip \
 && ( fetch() { \
        for i in 0 1 2; do \
          m=$(date -d "-$i month" +%Y-%m); \
          url="https://download.db-ip.com/free/dbip-$1-lite-$m.mmdb.gz"; \
          echo "GeoIP: trying $url"; \
          if curl -fsSL "$url" -o "/tmp/$1.mmdb.gz"; then \
            gunzip -c "/tmp/$1.mmdb.gz" > "/srv/geoip/dbip-$1-lite.mmdb" \
            && rm "/tmp/$1.mmdb.gz" && echo "GeoIP: $1 database installed" && return 0; \
          fi; \
        done; \
        echo "GeoIP: $1 download failed, continuing without it"; \
      }; \
      fetch city; fetch asn )

WORKDIR /srv

ARG WITH_ML=0
ARG WITH_POSTGRES=0

COPY --from=build /wheels /wheels
COPY requirements.txt requirements-ml.txt requirements-postgres.txt ./
RUN pip install --no-index --find-links=/wheels -r requirements.txt \
 && if [ "$WITH_ML" = "1" ]; then \
      pip install --no-index --find-links=/wheels -r requirements-ml.txt; fi \
 && if [ "$WITH_POSTGRES" = "1" ]; then \
      pip install --no-index --find-links=/wheels -r requirements-postgres.txt; fi \
 && rm -rf /wheels

COPY app ./app
COPY seed.py ./seed.py

# The database lives on a volume, so rebuilding the image never destroys data
# and the container filesystem itself can stay read-only.
RUN mkdir -p /data && chown -R skyrecon:skyrecon /data /srv

USER skyrecon

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=4s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

# One worker per container: the rate limiter and the anomaly model hold process
# state. Scale out with replicas behind a load balancer, not with --workers.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header"]
