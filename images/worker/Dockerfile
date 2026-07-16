FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.title="Echo Certification Forge Worker" \
      org.opencontainers.image.description="Purpose-built tenant-scoped control-plane worker image" \
      org.opencontainers.image.source="https://github.com/ECHO-OMEGA-PRIME/echo-certification-forge" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.base.name="python:3.12-slim-bookworm" \
      org.opencontainers.image.base.digest="sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b" \
      echo.certforge.image.role="worker" \
      echo.certforge.image.schema="1.1.0"

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
    && groupadd --gid 65532 certforge \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin certforge \
    && mkdir -p /opt/echo /state /run/certforge \
    && find / -xdev -type f -perm /6000 -exec chmod a-s {} + \
    && chown -R 65532:65532 /opt/echo /state /run/certforge

COPY --chown=65532:65532 src/echo_certification_forge /opt/echo/echo_certification_forge
COPY --chown=65532:65532 policies /opt/echo/policies

WORKDIR /state
USER 65532:65532

CMD ["uvicorn", "echo_certification_forge.app:app", "--host", "127.0.0.1", "--port", "8080", "--no-access-log"]
