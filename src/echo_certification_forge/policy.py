"""Versioned mandatory-rule manifest loading and validation."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import require_identifier, sha256_json


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    id: str
    severity: str
    mandatory: bool
    conditional_allowed: bool
    minimum_evidence: int
    description: str


@dataclass(frozen=True, slots=True)
class RuleManifest:
    schema_version: str
    manifest_id: str
    release_policy: str
    verdict_ttl_seconds: int
    rules: tuple[RuleDefinition, ...]
    digest: str

    @classmethod
    def load(cls, path: Path) -> "RuleManifest":
        raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        manifest_id = require_identifier(str(raw["manifest_id"]), "manifest_id")
        release_policy = require_identifier(str(raw["release_policy"]), "release_policy")
        ttl = int(raw["verdict_ttl_seconds"])
        if ttl <= 0:
            raise ValueError("verdict_ttl_seconds must be positive")
        definitions: list[RuleDefinition] = []
        seen: set[str] = set()
        for item in raw["rules"]:
            rule_id = require_identifier(str(item["id"]), "rule.id")
            if rule_id in seen:
                raise ValueError(f"duplicate rule id: {rule_id}")
            seen.add(rule_id)
            minimum = int(item["minimum_evidence"])
            if minimum < 1:
                raise ValueError(f"rule {rule_id} must require at least one evidence artifact")
            definitions.append(
                RuleDefinition(
                    id=rule_id,
                    severity=str(item["severity"]),
                    mandatory=bool(item["mandatory"]),
                    conditional_allowed=bool(item["conditional_allowed"]),
                    minimum_evidence=minimum,
                    description=str(item["description"]),
                )
            )
        if not definitions:
            raise ValueError("manifest must contain rules")
        return cls(
            schema_version=str(raw["schema_version"]),
            manifest_id=manifest_id,
            release_policy=release_policy,
            verdict_ttl_seconds=ttl,
            rules=tuple(definitions),
            digest=sha256_json(raw),
        )
