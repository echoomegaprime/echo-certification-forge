"""Report the actual sealed FieldDesk dependency runtime inside a restricted container."""
from __future__ import annotations
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import sysconfig

def main() -> int:
    material_path = Path("/usr/local/share/fielddesk-journey/materials.json")
    raw = material_path.read_bytes()
    materials = json.loads(raw)
    lock = Path("/usr/local/share/fielddesk-journey/requirements.lock").read_bytes()
    assert hashlib.sha256(lock).hexdigest() == materials["python_requirements_sha256"]
    normalize = lambda s: re.sub(r"[-_.]+", "-", s).lower()
    expected = {}
    for line in lock.decode("utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^ ]+) --hash=sha256:[0-9a-f]{64}", line)
        assert match is not None, "sealed_requirement_format"
        expected[normalize(match[1])] = match[2]
    installed = {normalize(d.metadata["Name"]): d.version
                 for d in importlib.metadata.distributions(path=[sysconfig.get_path("purelib")])}
    assert len(expected) == 27 and all(installed.get(k) == v for k, v in expected.items())
    node = subprocess.run(["/usr/local/bin/node", "--version"], capture_output=True,
                          text=True, check=True, timeout=5,
                          env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}).stdout.strip()
    assert node == "v24.22.1" and sys.version_info[:3] == (3, 12, 16)
    assert os.geteuid() == 65534 and os.getegid() == 65534
    mounts = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()]
    readonly = any(row[4] == "/" and "ro" in row[5].split(",") for row in mounts)
    network_disabled = sorted(p.name for p in Path("/sys/class/net").iterdir()) == ["lo"]
    assert readonly and network_disabled and sys.stdout.encoding.lower().replace("-", "") == "utf8"
    dependency_bytes = Path("/opt/fielddesk/dependencies.json").read_bytes()
    assert hashlib.sha256(dependency_bytes).hexdigest() == materials["dependencies_manifest_sha256"]
    assert json.loads(dependency_bytes) == {"version": 1, "inputs": materials["inputs"]}
    print(json.dumps({"node_version": node[1:], "python_version": ".".join(map(str, sys.version_info[:3])),
                      "uid": os.geteuid(), "gid": os.getegid(), "read_only_root": readonly,
                      "network_disabled": network_disabled, "utf8": True,
                      "python_package_count": len(expected), "python_packages": expected,
                      "dependency_source_commit": materials["dependency_source_commit"],
                      "dependency_input_count": len(materials["inputs"]),
                      "materials_sha256": hashlib.sha256(raw).hexdigest()}, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
