# syntax=docker/dockerfile:1

FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[server,s3,oidc]"


FROM python:3.12-slim

# Pin and verify Trivy. Override with --build-arg TRIVY_VERSION=x.y.z.
ARG TRIVY_VERSION=0.69.3
ARG TARGETARCH
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    case "${TARGETARCH:-amd64}" in \
      amd64) arch=64bit ;; \
      arm64) arch=ARM64 ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"; \
    tarball="trivy_${TRIVY_VERSION}_Linux-${arch}.tar.gz"; \
    cd /tmp; \
    curl -fsSLO "${base}/${tarball}"; \
    curl -fsSLO "${base}/trivy_${TRIVY_VERSION}_checksums.txt"; \
    grep " ${tarball}\$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "${tarball}" -C /usr/local/bin trivy; \
    rm -f /tmp/trivy_*; \
    apt-get purge -y --auto-remove curl; \
    rm -rf /var/lib/apt/lists/*; \
    trivy --version

COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links /wheels "trivy-scanner-api[server,s3,oidc]" \
    && rm -rf /wheels

RUN useradd --system --uid 10001 --create-home --home-dir /home/scanner scanner \
    && mkdir -p /var/cache/trivy /data/reports \
    && chown -R scanner:scanner /var/cache/trivy /data

ENV PYTHONUNBUFFERED=1 \
    TRIVY_CACHE_DIR=/var/cache/trivy \
    STORAGE_BACKEND=local \
    LOCAL_STORAGE_PATH=/data/reports

USER scanner
WORKDIR /home/scanner
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=5)"]

CMD ["trivy-scanner-server"]
