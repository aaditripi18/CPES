# CPES research dashboard. The private lab corpora are NOT in the image
# (.dockerignore); mount them read-only if you have them:
#
#   docker build -t cpes-dashboard .
#   docker run --rm -p 127.0.0.1:8790:8790 cpes-dashboard
#
# Public samples and SigmaHQ rules (scripts/fetch_external.py) are not
# redistributed in the image either; mount them read-only for the incidents demo:
#
#   docker run --rm -p 127.0.0.1:8790:8790 -v "$PWD/external:/app/external:ro" cpes-dashboard
#   docker run --rm -p 127.0.0.1:8790:8790 \
#     -v "$PWD/analysis:/app/analysis:ro" \
#     -v "$PWD/Claude outputs:/app/Claude outputs:ro" cpes-dashboard
#
# Publish to 127.0.0.1 only: the lab corpora identify the lab host and account.

FROM node:22.11.0-bookworm-slim AS web
WORKDIR /web
COPY dashboard/web/package.json dashboard/web/package-lock.json ./
RUN npm ci
COPY dashboard/web/ ./
RUN npm run build

FROM python:3.12.8-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 CPES_DASHBOARD_DATA=/data
WORKDIR /app
COPY requirements.txt reqs/core.txt
COPY dashboard/requirements.txt reqs/dashboard.txt
RUN pip install --no-cache-dir -r reqs/core.txt -r reqs/dashboard.txt
COPY cpes/ cpes/
COPY configs/ configs/
COPY evaluation/ evaluation/
COPY examples/ examples/
COPY docs/ docs/
COPY demo/ demo/
COPY pyproject.toml README.md ./
COPY dashboard/ dashboard/
COPY --from=web /web/dist dashboard/web/dist
RUN useradd --create-home cpes && mkdir -p /data && chown cpes /data
USER cpes
VOLUME /data
EXPOSE 8790
CMD ["python", "dashboard/run_server.py", "--host", "0.0.0.0", "--port", "8790"]
