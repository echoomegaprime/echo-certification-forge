FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df

ARG SOURCE_REVISION=unknown
ARG IMAGE_VARIANT=unknown
ARG ADMISSION_POLICY_ID=p4.signer.production.v1
ARG ATTESTATION_KEY_ID=unknown
LABEL org.opencontainers.image.title="Echo Certification Forge Verdict Signer" \
      org.opencontainers.image.description="Purpose-built isolated verdict-signing image for Certification Forge" \
      org.opencontainers.image.source="https://github.com/ECHO-OMEGA-PRIME/echo-certification-forge" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.base.name="python:3.12-alpine" \
      org.opencontainers.image.base.digest="sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df" \
      echo.certforge.image.role="signer" \
      echo.certforge.image.variant="${IMAGE_VARIANT}" \
      echo.certforge.admission.policy="${ADMISSION_POLICY_ID}" \
      echo.certforge.attestation.key_id="${ATTESTATION_KEY_ID}" \
      echo.certforge.image.schema="1.2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/echo \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

COPY images/requirements.lock /tmp/requirements.lock
RUN python -m pip install --root-user-action=ignore --no-cache-dir --require-hashes --no-deps -r /tmp/requirements.lock \
    && rm -f /tmp/requirements.lock \
    && addgroup -S -g 65532 certforge \
    && adduser -S -D -H -u 65532 -G certforge -s /sbin/nologin certforge \
    && mkdir -p /opt/echo /input /output /work \
    && find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec chmod a-s {} + \
    && chown -R 65532:65532 /opt/echo /input /output /work

COPY --chown=65532:65532 src/echo_certification_forge /opt/echo/echo_certification_forge

WORKDIR /work
USER 65532:65532

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["python", "-c", "import echo_certification_forge.signer_cli"]

ENTRYPOINT ["python", "-m", "echo_certification_forge.signer_cli"]
