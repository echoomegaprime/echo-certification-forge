"""Measure the real dual runtime; never issue security/admission assertions.

Library-first searches 77cdc9dd-89df-4677-9c5b-5d0431eaa6d3 and
29e81b06-698d-47ab-8020-121bed24916e returned no matching function. Version
checks adapt deploy/certforge/verify_toolchain.py from ECF ae416cbf; ELF
inventory covers this recipe's copied Node binary and matching runtime files.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys


def parse_ldd(text):
    """Refuse missing/unknown entries rather than invent an ELF closure."""
    if not isinstance(text, str) or len(text) > 65536:
        raise RuntimeError("elf_inventory_size")
    paths = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        if re.fullmatch(r"\s*linux-vdso\.so\.1\s+\(0x[0-9a-fA-F]+\)\s*", line):
            continue
        match = re.fullmatch(r"\s*(?:\S+\s+=>\s+)?(/[^\s()]+)\s+\(0x[0-9a-fA-F]+\)\s*", line)
        if not match:
            raise RuntimeError("unresolved_or_unknown_elf_dependency")
        paths.add(match.group(1))
        if len(paths) > 64:
            raise RuntimeError("elf_inventory_count")
    if not paths:
        raise RuntimeError("elf_inventory_empty")
    return tuple(sorted(paths))


def validate_versions(node, python, implementation, libc):
    expected = {"node": "24.22.1", "openssl": "3.5.9", "undici": "7.30.1"}
    if (not isinstance(node, dict) or any(node.get(key) != value for key, value in expected.items())
            or python != "3.12.16" or implementation != "CPython" or libc != ("glibc", "2.41")):
        raise RuntimeError("runtime_version_mismatch")


def file_record(filename):
    path = Path(filename).resolve(strict=True)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 512 * 1024**2 or stream.read(4) != b"\x7fELF":
            raise RuntimeError("runtime_file_not_bounded_elf")
        stream.seek(0)
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        raise RuntimeError("runtime_file_changed")
    return {"observed_path": filename, "resolved_path": str(path), "bytes": before.st_size, "sha256": digest}


def measure_runtime():
    if os.getuid() != 65534 or shutil.which("npm") is not None:
        raise RuntimeError("nonroot_without_npm_required")
    node = "/usr/local/bin/node"
    binaries = {"node": file_record(node), "CPython": file_record(sys.executable)}
    result = subprocess.run([node, "-p", "JSON.stringify(process.versions)"],
                            capture_output=True, text=True, check=True, timeout=10)
    if len(result.stdout) > 65536:
        raise RuntimeError("node_inventory_size")
    versions = json.loads(result.stdout)
    validate_versions(versions, platform.python_version(), platform.python_implementation(), platform.libc_ver())
    closure = {}
    dependencies = {}
    for name, filename in (("node", node), ("CPython", sys.executable)):
        result = subprocess.run(["ldd", filename], capture_output=True, text=True, check=True, timeout=10)
        dependencies[name] = list(parse_ldd(result.stdout))
        for dependency in dependencies[name]:
            closure[dependency] = file_record(dependency)
    return {"ok": True, "evidence_class": "MEASURED_RUNTIME_AND_ELF_INVENTORY",
            "uid": os.getuid(), "node_components": versions, "python": platform.python_version(),
            "implementation": platform.python_implementation(), "libc": platform.libc_ver(),
            "npm_present": False, "binaries": binaries, "elf_dependencies": dependencies,
            "elf_files": closure, "qualified_security_scan": False, "admitted": False}


if __name__ == "__main__":
    try:
        print(json.dumps(measure_runtime(), sort_keys=True))
    except (OSError, RuntimeError, ValueError, TypeError, subprocess.SubprocessError):
        print(json.dumps({"ok": False, "error": "runtime_inventory_failed", "admitted": False}))
        raise SystemExit(1)
