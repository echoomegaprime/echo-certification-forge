FROM python:3.12.16-alpine3.24@sha256:a61cbd76a882645de7f91423329fe43a67eed60d7da24f9e5331414bb3618b20

ARG SOURCE_REVISION=unknown
ARG IMAGE_VARIANT=unknown
ARG ADMISSION_POLICY_ID=p4.custody.production.v1
ARG ATTESTATION_KEY_ID=unknown
LABEL org.opencontainers.image.title="Echo Certification Forge Custody" \
      org.opencontainers.image.description="Purpose-built append-only evidence custody service image" \
      org.opencontainers.image.source="https://github.com/echoomegaprime/echo-certification-forge" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.base.name="python:3.12.16-alpine3.24" \
      org.opencontainers.image.base.digest="sha256:a61cbd76a882645de7f91423329fe43a67eed60d7da24f9e5331414bb3618b20" \
      echo.certforge.image.role="custody" \
      echo.certforge.image.variant="${IMAGE_VARIANT}" \
      echo.certforge.admission.policy="${ADMISSION_POLICY_ID}" \
      echo.certforge.attestation.key_id="${ATTESTATION_KEY_ID}" \
      echo.certforge.image.schema="1.2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/echo \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    ECHO_CERTFORGE_P3_MODE=custody

COPY images/requirements.lock /tmp/requirements.lock
# Exact Alpine package fix; keep this pin until a scanned base incorporates it.
RUN apk add --no-cache --upgrade krb5-libs=1.22.3-r0 \
    && python -m pip install --root-user-action=ignore --no-cache-dir --require-hashes --no-deps -r /tmp/requirements.lock \
    && rm -f /tmp/requirements.lock \
    && addgroup -S -g 65532 certforge \
    && adduser -S -D -H -u 65532 -G certforge -s /sbin/nologin certforge \
    && mkdir -p /opt/echo /state /run/certforge \
    && find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec chmod a-s {} + \
    && chown -R 65532:65532 /opt/echo /state /run/certforge

COPY --chown=65532:65532 src/echo_certification_forge /opt/echo/echo_certification_forge
COPY --chown=65532:65532 pyproject.toml images/requirements.lock /opt/echo/echo_certification_forge/runtime_data/

WORKDIR /state
USER 65532:65532

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"]

CMD ["uvicorn", "echo_certification_forge.p3_runtime:app", "--host", "127.0.0.1", "--port", "8080", "--no-access-log"]
