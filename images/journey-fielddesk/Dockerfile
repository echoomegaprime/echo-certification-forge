# Dependency-only FieldDesk journey candidate; no target application or credentials.
# Exact materials are committed separately from the target source and recipe commit.
FROM docker.io/library/node:24.22.1-trixie-slim@sha256:c8c4a7483bb04544293c82a3eecc3081c37ff5dfedcaf819d60e6e4aaad35b12 AS node_runtime
FROM docker.io/library/python:3.12-slim-trixie@sha256:1148dbb014615300fa7e713b2f94f550c0d1c69780c0805f84f093ceee34dd0b AS dependencies
COPY requirements.lock materials.json verify_materials.py /tmp/fielddesk-inputs/
COPY frontend-dependencies.tar.gz /tmp/fielddesk-inputs/frontend-dependencies.tar.gz
COPY wheelhouse/ /tmp/fielddesk-inputs/wheelhouse/
RUN --network=none python3 -I -S /tmp/fielddesk-inputs/verify_materials.py /tmp/fielddesk-inputs /opt/fielddesk \
    && PIP_CONFIG_FILE=/dev/null python3 -m pip --isolated install --no-index --find-links=/tmp/fielddesk-inputs/wheelhouse --no-input --no-cache-dir --disable-pip-version-check --only-binary=:all: --no-deps --no-compile --require-hashes -r /tmp/fielddesk-inputs/requirements.lock \
    && python3 -m pip check \
    && python3 -m pip uninstall --yes pip setuptools wheel
FROM docker.io/library/python:3.12-slim-trixie@sha256:1148dbb014615300fa7e713b2f94f550c0d1c69780c0805f84f093ceee34dd0b
ARG RECIPE_COMMIT
ARG QUALIFICATION_TASK_ID
LABEL org.opencontainers.image.source="https://github.com/echoomegaprime/echo-certification-forge" \
      org.opencontainers.image.revision="$RECIPE_COMMIT" \
      echo.task.id="$QUALIFICATION_TASK_ID" \
      echo.fielddesk.dependency_source="290658c4be634af6dd308021d1946f737032c3cf" \
      echo.evidence.class="unsigned-task-owned-qualification-asset"
COPY --from=node_runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=node_runtime /usr/lib/x86_64-linux-gnu/libstdc++.so.6* /usr/lib/x86_64-linux-gnu/
COPY --from=node_runtime /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 /usr/lib/x86_64-linux-gnu/
RUN --network=none python3 -I -S -c 'import os,re,sys; assert re.fullmatch("[0-9a-f]{40}",os.environ.get("RECIPE_COMMIT","")); assert sys.version_info[:3] == (3,12,16)' \
    && node -e 'if(process.version!=="v24.22.1") process.exit(1)' \
    && python3 -m pip uninstall --yes pip setuptools wheel \
    && python3 -I -S -c 'import pathlib,shutil,sysconfig; p=pathlib.Path(sysconfig.get_path("stdlib"))/"ensurepip"/"_bundled"; shutil.rmtree(p)'
COPY --from=dependencies /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=dependencies /opt/fielddesk/ /opt/fielddesk/
COPY requirements.lock materials.json /usr/local/share/fielddesk-journey/
COPY runtime_probe.py /usr/local/libexec/fielddesk-runtime-probe.py
ENV PYTHONIOENCODING=utf-8 PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONNOUSERSITE=1 ECHO_TEST_PYTHON=/usr/local/bin/python3
USER 65534:65534
WORKDIR /work
ENTRYPOINT []
CMD ["python3", "--version"]
