"""Structural drift guards; actual archive/cold-load proof is external evidence."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from echo_certification_forge.sandbox import DEFAULT_IMAGE

ROOT = Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def test_offline_default_binds_public_recipe_and_distinct_content_identities():
    data = json.loads((ROOT / "images/sandbox/runtime-input.json").read_text())
    assert DIGEST.fullmatch(DEFAULT_IMAGE)
    assert data["reference"] == DEFAULT_IMAGE
    assert data["identity_kind"] == "docker_local_image_id"
    assert data["identity_object_media_type"] == "application/vnd.oci.image.index.v1+json"
    identity = data["image_identity"]
    assert identity["oci_index_digest"] == DEFAULT_IMAGE
    named = [identity[k] for k in ("oci_index_digest", "platform_manifest_digest", "config_digest")]
    assert all(DIGEST.fullmatch(value) for value in named)
    assert len(set(named)) == 3
    recipe = data["recipe"]
    actual = (ROOT / recipe["path"]).read_bytes()
    assert hashlib.sha256(actual).hexdigest() == recipe["sha256"]
    assert actual == (f'FROM {recipe["upstream_reference"]}\n'
                      f'RUN apk add --no-cache --upgrade {recipe["os_package_upgrade"]}\n').encode()
    assert recipe["os_package_upgrade"] == "krb5-libs=1.22.3-r0"
    for role in ("runner", "custody", "anchor", "signer", "worker", "verifier"):
        assert (ROOT / f"images/{role}/Dockerfile").read_text().splitlines()[0] == (
            "FROM " + recipe["upstream_reference"])
    blobs = data["archive"]["blobs"]
    assert data["archive"]["blob_count"] == len(blobs)
    assert data["archive"]["bytes"] > 0
    assert re.fullmatch(r"[0-9a-f]{64}", data["archive"]["sha256"])
    assert all(DIGEST.fullmatch(key) and type(size) is int and size > 0
               for key, size in blobs.items())
    assert all(value in blobs for value in named)
    layers = identity["layers"]
    diffs = identity["rootfs_diff_ids"]
    assert len(layers) == len(diffs) > 0
    for layer in layers:
        assert layer["size"] == blobs[layer["digest"]]
    assert all(DIGEST.fullmatch(value) for value in diffs)
    chain = diffs[0]
    for value in diffs[1:]:
        chain = "sha256:" + hashlib.sha256(f"{chain} {value}".encode()).hexdigest()
    assert chain == identity["rootfs_chain_id"]
    assert data["production_admission"] == "NOT_GRANTED"
    qualification = data["qualification"]
    assert qualification["scan_by_full_local_id"] == DEFAULT_IMAGE
    assert type(qualification["scanner_exit_code"]) is int
    assert qualification["scanner_exit_code"] == 0
    assert qualification["critical_count"] == qualification["high_count"] == 0
    assert qualification["verified_absent_before_load"] is True
    assert qualification["post_cold_runtime_passed"] is True
    assert qualification["missing_local_id_fail_closed"] is True
    cold = qualification["cold_import_preserves_identity"]
    assert set(cold) == {
        "all_unrelated_container_ids_preserved", "all_unrelated_image_ids_preserved",
        "archive_unchanged", "exact_full_image_id_restored", "same_config",
        "same_oci_descriptor_restored", "same_rootfs_diff_ids",
    }
    assert all(value is True for value in cold.values())
