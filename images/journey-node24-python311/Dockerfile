# Official linux/amd64 manifests resolved through the scoped owner on 2026-10-09.
# No target code, package installation, credentials, or mutable base references.
FROM node:24.19.0-bookworm-slim@sha256:e5a8dee7bc1e6a215d224a7ef8206f7e77271bc3cabd5febf2beafac0674f174 AS node
FROM python:3.11-slim-bookworm@sha256:8a00ecb83ed9d0864dfd102a1bdb2067fda907ceb30bb86d09da9ee558b19590
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/lib/x86_64-linux-gnu/libstdc++.so.6* /usr/lib/x86_64-linux-gnu/
COPY --from=node /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 /usr/lib/x86_64-linux-gnu/
ENV ECHO_TEST_PYTHON=/usr/local/bin/python3 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONIOENCODING=utf-8
RUN node -e "if (process.version !== 'v24.19.0') process.exit(1)" \
    && python3 -c "import sys; assert sys.version_info[:2] == (3, 11)"
USER 65534:65534
WORKDIR /work
ENTRYPOINT []
CMD ["node", "--version"]
