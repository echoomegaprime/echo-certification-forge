FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df

ARG SOURCE_REVISION=unknown
ARG IMAGE_VARIANT=unknown
ARG ADMISSION_POLICY_ID=p4.worker.production.v1
ARG ATTESTATION_KEY_ID=unknown
LABEL org.opencontainers.image.title="Echo Certification Forge Worker" \
      org.opencontainers.image.description="Purpose-built tenant-scoped control-plane worker image" \
      org.opencontainers.image.source="https://github.com/ECHO-OMEGA-PRIME/echo-certification-forge" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.base.name="python:3.12-alpine" \
      org.opencontainers.image.base.digest="sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df" \
      echo.certforge.image.role="worker" \
      echo.certforge.image.variant="${IMAGE_VARIANT}" \
      echo.certforge.admission.policy="${ADMISSION_POLICY_ID}" \
      echo.certforge.attestation.key_id="${ATTESTATION_KEY_ID}" \
      echo.certforge.image.schema="1.2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/echo \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    ECHO_CERTFORGE_DB=/state/certforge.sqlite3 \
    ECHO_CERTFORGE_EVIDENCE_ROOT=/state/evidence \
    ECHO_CERTFORGE_POLICY=/opt/echo/policies/mandatory-rules.v1.json \
    ECHO_CERTFORGE_TRUSTED_KEYS=/state/trusted-public-keys

COPY images/requirements.lock /tmp/requirements.lock
RUN python -m pip install --root-user-action=ignore --require-hashes --no-deps -r /tmp/requirements.lock \
    && rm -f /tmp/requirements.lock \
    && addgroup -S -g 65532 certforge \
    && adduser -S -D -H -u 65532 -G certforge -s /sbin/nologin certforge \
    && mkdir -p /opt/echo /state /run/certforge \
    && find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec chmod a-s {} + \
    && chown -R 65532:65532 /opt/echo /state /run/certforge

COPY --chown=65532:65532 src/echo_certification_forge /opt/echo/echo_certification_forge
COPY --chown=65532:65532 policies /opt/echo/policies

WORKDIR /state
USER 65532:65532

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"]

CMD ["uvicorn", "echo_certification_forge.app:app", "--host", "127.0.0.1", "--port", "8080", "--no-access-log"]
