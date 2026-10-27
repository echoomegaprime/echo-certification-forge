# Official linux/amd64 manifests resolved through the scoped owner on 2026-10-09.
# No target code, package installation, credentials, or mutable base references.
FROM node:24.19.0-trixie-slim@sha256:db4f733c26868756bae92ac764d7e99bf31809ce7db886ed525960fe7d544601 AS node
FROM python:3.11-slim-trixie@sha256:e529028263dbe6910a2d96f7d2b8f5266385e917fd45d286ef166977c094a51e
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/lib/x86_64-linux-gnu/libstdc++.so.6* /usr/lib/x86_64-linux-gnu/
COPY --from=node /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 /usr/lib/x86_64-linux-gnu/
ENV ECHO_TEST_PYTHON=/usr/local/bin/python3 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONIOENCODING=utf-8
RUN --network=none python3 -m pip uninstall --yes pip setuptools wheel \
    && python3 -c "import pathlib,shutil,sysconfig; shutil.rmtree(pathlib.Path(sysconfig.get_path('stdlib'))/'ensurepip'/'_bundled')" \
    && node -e "if (process.version !== 'v24.19.0') process.exit(1)" \
    && python3 -c "import sys; assert sys.version_info[:2] == (3, 11)"
USER 65534:65534
WORKDIR /work
ENTRYPOINT []
CMD ["node", "--version"]
