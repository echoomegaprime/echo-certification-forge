# Unsigned dependency-only candidate; no target source is baked into the image.
# Reuses the existing CertForge dual-runtime layout and supported exact pair.
# RECIPE_COMMIT must be the actual committed CertForge recipe source at build.
FROM docker.io/library/node:24.22.1-trixie-slim@sha256:c8c4a7483bb04544293c82a3eecc3081c37ff5dfedcaf819d60e6e4aaad35b12 AS node_runtime
FROM docker.io/library/python:3.12-slim-trixie@sha256:1148dbb014615300fa7e713b2f94f550c0d1c69780c0805f84f093ceee34dd0b
ARG QUALIFICATION_TASK_ID
ARG RECIPE_COMMIT
LABEL echo.task.id="${QUALIFICATION_TASK_ID}" \
      org.opencontainers.image.source="https://github.com/echoomegaprime/echo-certification-forge" \
      org.opencontainers.image.revision="${RECIPE_COMMIT}" \
      echo.foreman.target_source="cd088e2e07c756b8bc195ce3d1fa6253d845983f" \
      echo.evidence.class="unsigned-task-owned-qualification-asset"
COPY --from=node_runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=node_runtime /usr/lib/x86_64-linux-gnu/libstdc++.so.6* /usr/lib/x86_64-linux-gnu/
COPY --from=node_runtime /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 /usr/lib/x86_64-linux-gnu/
ENV PYTHONIOENCODING=utf-8 PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONNOUSERSITE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY requirements.lock /tmp/foreman-requirements.lock
RUN python3 -I -S -c 'import os,re; assert re.fullmatch("[0-9a-f]{40}",os.environ.get("RECIPE_COMMIT","")), "actual_recipe_commit_required"' \
    && python3 -I -S -c 'from pathlib import Path; import json; root=Path('"'"'/sys/fs/cgroup'"'"'); v2=(root/'"'"'memory.max'"'"').is_file(); mem=(root/'"'"'memory.max'"'"' if v2 else root/'"'"'memory/memory.limit_in_bytes'"'"').read_text().strip(); swap=(root/'"'"'memory.swap.max'"'"' if v2 else root/'"'"'memory/memory.memsw.limit_in_bytes'"'"').read_text().strip(); cpu=(root/'"'"'cpu.max'"'"').read_text().strip() if v2 else (root/'"'"'cpu/cpu.cfs_quota_us'"'"').read_text().strip()+'"'"' '"'"'+(root/'"'"'cpu/cpu.cfs_period_us'"'"').read_text().strip(); print(json.dumps({'"'"'actual_build_cgroup_v2'"'"':v2,'"'"'memory'"'"':mem,'"'"'swap'"'"':swap,'"'"'cpu'"'"':cpu}),flush=True); assert mem=='"'"'805306368'"'"' and swap==('"'"'0'"'"' if v2 else '"'"'805306368'"'"') and cpu=='"'"'200000 100000'"'"'' \
    && PIP_CONFIG_FILE=/dev/null python3 -m pip --isolated install --no-input --no-cache-dir --disable-pip-version-check --only-binary=:all: --no-deps --no-compile --require-hashes --index-url https://pypi.org/simple -r /tmp/foreman-requirements.lock \
    && python3 -m pip check \
    && rm /tmp/foreman-requirements.lock
COPY runtime_probe.py /usr/local/libexec/foreman-runtime-probe.py
USER 65534:65534
RUN python3 -I -S /usr/local/libexec/foreman-runtime-probe.py
WORKDIR /work
ENTRYPOINT []
CMD ["python3", "--version"]
