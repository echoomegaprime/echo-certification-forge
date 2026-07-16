FROM python:3.12.10-slim-bookworm@sha256:fd95fa221297a88e1cf49c55ec1828edd7c5a428187e67b5d1805692d11588db

ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.title="Echo Certification Forge Runner" \
      org.opencontainers.image.description="Purpose-built non-root execution image for isolated Certification Forge runs" \
      org.opencontainers.image.source="https://github.com/ECHO-OMEGA-PRIME/echo-certification-forge" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.base.name="python:3.12.10-slim-bookworm" \
      org.opencontainers.image.base.digest="sha256:fd95fa221297a88e1cf49c55ec1828edd7c5a428187e67b5d1805692d11588db" \
      echo.certforge.image.role="runner" \
      echo.certforge.image.schema="1.0.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/echo \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

COPY images/requirements.lock /tmp/requirements.lock
RUN python -m pip install --require-hashes --no-deps -r /tmp/requirements.lock \
    && rm -f /tmp/requirements.lock \
    && groupadd --gid 65532 certforge \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin certforge \
    && mkdir -p /opt/echo /workspace \
    && chown -R 65532:65532 /opt/echo /workspace

COPY --chown=65532:65532 src/echo_certification_forge /opt/echo/echo_certification_forge

WORKDIR /workspace
USER 65532:65532

CMD ["python", "-c", "import echo_certification_forge; print('echo-certforge-runner-ready')"]
