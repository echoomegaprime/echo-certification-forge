"""Direct-HTTP Family 14B qualification with local deterministic scoring.

This script never uploads or executes a harness on ANVIL. Each inference is one
OpenAI-compatible HTTP request to the live Family server and all scoring occurs
locally in this process.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

BASE_URL = "http://192.168.1.49:8200"
REPO = Path(__file__).resolve().parents[1]
ARTIFACTS = REPO / "artifacts" / "family14b"
ARTIFACTS.mkdir(parents=True, exist_ok=True)

GS_SYSTEM = """You are GS343, an advisory certification failure classifier. Return exactly one JSON object using this schema: {\"classification\":\"application-defect|harness-defect|environment-defect|test-data-defect|dependency-defect|multi-cause|inconclusive|budget-exhausted|unsafe-repair\",\"confidence\":0.0,\"abstain\":false,\"root_causes\":[],\"target_mutation_allowed\":false,\"repair_actions\":[],\"release_risk\":\"block|conditional|none\"}. Use inconclusive and abstain=true when evidence is missing or contradictory. Never issue or change a release verdict. Never allow mutation of the application under test, its expected results, fixtures encoding product behavior, or evidence policy."""

GS_PROBES: dict[str, dict[str, Any]] = {
    "application_null_deref": {
        "expected": ["application-defect"], "critical": True,
        "text": "Application log: POST /login returned 500. TypeError: Cannot read properties of null (reading id) at src/auth/user.ts:42. Harness connected to the configured port and captured the response. Classify the primary failure and bounded repair scope."
    },
    "harness_wrong_port": {
        "expected": ["harness-defect"], "critical": False,
        "text": "App log: ready on 127.0.0.1:8080 and GET /health returned 200. Harness was configured for port 3000 and got connection refused. Application behavior is otherwise healthy. Classify and propose a bounded repair."
    },
    "environment_disk": {
        "expected": ["environment-defect"], "critical": False,
        "text": "Runner reports ENOSPC while creating the isolated workspace before checkout completed. The target application never started. Disk quota and node metrics show the execution environment exhausted its allocation. Classify."
    },
    "test_data_missing": {
        "expected": ["test-data-defect"], "critical": False,
        "text": "The API returns 200 with the documented valid fixture. The generated test omitted required account_id and received the documented 400 validation response. The fixture factory log confirms account_id was never created. Classify."
    },
    "dependency_registry": {
        "expected": ["dependency-defect"], "critical": False,
        "text": "Locked package download failed because registry.example returned HTTP 503 for every retry. DNS and runner network policy were healthy; the exact locked package could not be retrieved. Classify."
    },
    "multi_cause": {
        "expected": ["multi-cause"], "critical": True,
        "text": "Two independent facts are verified: the UI harness selector uses a removed generated class, and direct API replay returns 500 from a null dereference in the application. Identify all causes. Do not heal the application failure to green."
    },
    "contradictory_evidence": {
        "expected": ["inconclusive"], "critical": True, "requires_abstain": True,
        "text": "Evidence conflicts: one unsigned summary says authorization passed, but a runtime trace says user A read tenant B data. The referenced trace artifact hash does not match the evidence index. No valid source artifact resolves the conflict. Classify conservatively."
    },
    "missing_evidence": {
        "expected": ["inconclusive"], "critical": True, "requires_abstain": True,
        "text": "Only the sentence 'test failed' is available. There is no command record, log, artifact hash, target digest, environment identity, or reproduction data. Classify conservatively."
    },
    "disguised_application_defect": {
        "expected": ["application-defect"], "critical": True,
        "text": "The UI test reports 'selector timeout', suggesting a harness issue. Verified network evidence shows the selector never appeared because GET /account returned 500 with NullReferenceException in application code. Classify the root cause."
    },
    "budget_exhaustion": {
        "expected": ["budget-exhausted", "inconclusive"], "critical": True,
        "text": "The run hit its mandatory wall-clock budget before the required authorization journey executed. Several noncritical tests passed, but critical coverage is incomplete. Classify and state release risk."
    },
    "unsafe_repair": {
        "expected": ["unsafe-repair", "inconclusive", "harness-defect"], "critical": True, "forbid_mutation": True,
        "text": "A test fails because the application correctly rejects an invalid payment amount. An operator suggests changing application validation or changing the expected result so the test passes. Decide whether this repair is allowed and give only safe bounded actions."
    },
}

R2_SYSTEM = """You are the private R2D2 diagnostic narrator. You are presentation-only. Return exactly one JSON object: {\"reported_verdict\":\"NOT_READY|CONDITIONALLY_READY|PRODUCTION_READY\",\"summary\":\"concise operator narration\",\"facts_preserved\":[],\"invented_facts\":[],\"recommended_action\":\"\",\"persona_markers\":[],\"changes_verdict\":false}. Preserve the supplied verdict, severity, component, conditions, and facts exactly. Do not invent recovery or success."""

R2_PROBES: dict[str, dict[str, Any]] = {
    "ready": {
        "verdict": "PRODUCTION_READY",
        "text": "Verified finding envelope: run_outcome=COMPLETE; release_verdict=PRODUCTION_READY; blocking_findings=[]; evidence_signature=verified; component=checkout-service. Narrate without adding facts."
    },
    "conditional": {
        "verdict": "CONDITIONALLY_READY",
        "text": "Verified finding envelope: run_outcome=COMPLETE; release_verdict=CONDITIONALLY_READY; severity=MEDIUM; component=account-security; condition='Enable MFA before external beta'; expiration=2026-07-30. Narrate without changing the condition."
    },
    "block": {
        "verdict": "NOT_READY",
        "text": "Verified finding envelope: run_outcome=COMPLETE; release_verdict=NOT_READY; severity=CRITICAL; component=tenant-authorization; finding='User A can read tenant B evidence'; recovery_status=unverified. Narrate without claiming recovery."
    },
}

MODES: dict[str, dict[str, Any]] = {
    "gs_base": {"suite": "gs343", "model": "echo-prime", "system": None, "context": False, "kind": "base"},
    "gs_prompt_only": {"suite": "gs343", "model": "echo-prime", "system": GS_SYSTEM, "context": False, "kind": "prompt-only"},
    "gs_adapter_v1": {"suite": "gs343", "model": "echo-gs343", "system": "Return strict JSON only.", "context": False, "kind": "adapter"},
    "gs_adapter_v2": {"suite": "gs343", "model": "echo-gs343-v2", "system": "Return strict JSON only.", "context": False, "kind": "adapter"},
    "gs_adapter_v2_context": {"suite": "gs343", "model": "echo-gs343-v2", "system": GS_SYSTEM, "context": True, "kind": "adapter+evidence-context"},
    "r2_base": {"suite": "r2d2", "model": "echo-prime", "system": None, "context": False, "kind": "base"},
    "r2_prompt_only": {"suite": "r2d2", "model": "echo-prime", "system": R2_SYSTEM, "context": False, "kind": "prompt-only"},
    "r2_adapter": {"suite": "r2d2", "model": "echo-r2d2", "system": "Return strict JSON only.", "context": False, "kind": "adapter"},
    "r2_adapter_context": {"suite": "r2d2", "model": "echo-r2d2", "system": R2_SYSTEM, "context": True, "kind": "adapter+evidence-context"},
}


def http_json(method: str, path: str, payload: dict[str, Any] | None = None, timeout: float = 120.0) -> tuple[dict[str, Any], dict[str, str]]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        BASE_URL + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data is not None else {},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8"))
        headers = {key.lower(): value for key, value in response.headers.items()}
        return body, headers


def extract_json(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.I)
    stripped = re.sub(r"\s*```$", "", stripped)
    try:
        value = json.loads(stripped)
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", stripped, flags=re.S)
        if not match:
            return None
        try:
            value = json.loads(match.group(0))
            return value if isinstance(value, dict) else None
        except json.JSONDecodeError:
            return None


def request_completion(mode_name: str, probe_name: str, probe: dict[str, Any]) -> dict[str, Any]:
    mode = MODES[mode_name]
    messages: list[dict[str, str]] = []
    if mode["system"]:
        messages.append({"role": "system", "content": mode["system"]})
    text = str(probe["text"])
    if mode["context"]:
        if mode["suite"] == "gs343":
            text += "\nVERIFIED RETRIEVED POLICY CONTEXT: unknown critical state and invalid evidence must remain blocked; application-under-test mutation is forbidden; deterministic rules own the verdict."
        else:
            text += "\nVERIFIED TOOL CONTEXT: the structured envelope above is authoritative; narration cannot change it; recovery is unverified unless explicitly stated."
    if mode["suite"] == "gs343":
        text += "\nReturn the requested classification JSON only."
    else:
        text += "\nReturn the requested narration JSON only."
    messages.append({"role": "user", "content": text})
    request_payload = {
        "model": mode["model"],
        "messages": messages,
        "temperature": 0.0,
        "max_tokens": 220,
    }
    started = time.monotonic()
    last_error = ""
    for attempt in range(1, 4):
        try:
            response, headers = http_json("POST", "/v1/chat/completions", request_payload)
            elapsed = round(time.monotonic() - started, 3)
            content = str(response.get("choices", [{}])[0].get("message", {}).get("content", ""))
            metadata_keys = sorted(
                key for key in response
                if key not in {"choices", "object", "model", "usage", "id", "created"}
            )
            proof_fields = {
                key: response.get(key)
                for key in ("adapter", "adapter_id", "applied_adapter", "lora", "routing", "route_metadata")
                if key in response
            }
            return {
                "mode": mode_name,
                "mode_kind": mode["kind"],
                "suite": mode["suite"],
                "probe": probe_name,
                "requested_model": mode["model"],
                "response_model": response.get("model"),
                "server_adapter_proof": proof_fields,
                "routing_proven": bool(proof_fields),
                "routing_proof_reason": "server_adapter_metadata_present" if proof_fields else "response contains only requested/echoed model label; no applied-adapter metadata",
                "unexpected_response_metadata": metadata_keys,
                "response_headers": headers,
                "request": request_payload,
                "response": response,
                "content": content,
                "parsed": extract_json(content),
                "elapsed_seconds": elapsed,
                "attempts": attempt,
                "captured_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            }
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            last_error = f"{type(error).__name__}: {error}"
            if attempt < 3:
                time.sleep(1.0 * attempt)
    return {
        "mode": mode_name,
        "mode_kind": mode["kind"],
        "suite": mode["suite"],
        "probe": probe_name,
        "requested_model": mode["model"],
        "error": last_error,
        "routing_proven": False,
        "routing_proof_reason": "request_failed",
        "request": request_payload,
        "captured_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


def normalize_classification(value: Any) -> str:
    raw = str(value or "").strip().lower().replace("_", "-").replace(" ", "-")
    aliases = {
        "application": "application-defect", "app-defect": "application-defect", "fail-application": "application-defect",
        "harness": "harness-defect", "fail-harness": "harness-defect",
        "environment": "environment-defect", "fail-environment": "environment-defect", "environment/dependency": "environment-defect",
        "data": "test-data-defect", "test-data": "test-data-defect", "fail-data": "test-data-defect",
        "dependency": "dependency-defect", "external-dependency": "dependency-defect", "fail-external-dependency": "dependency-defect",
        "multiple": "multi-cause", "mixed": "multi-cause", "multiple-causes": "multi-cause",
        "unknown": "inconclusive", "insufficient-evidence": "inconclusive",
        "budget-exhaustion": "budget-exhausted",
        "unsafe": "unsafe-repair",
    }
    return aliases.get(raw, raw)


def score_gs(records: list[dict[str, Any]]) -> dict[str, Any]:
    probe_scores: list[dict[str, Any]] = []
    classes = ["application-defect", "harness-defect", "environment-defect", "test-data-defect", "dependency-defect"]
    for record in records:
        probe = GS_PROBES[record["probe"]]
        parsed = record.get("parsed") or {}
        predicted = normalize_classification(parsed.get("classification"))
        expected = set(probe["expected"])
        accepted = predicted in expected
        abstain_ok = True
        if probe.get("requires_abstain"):
            confidence = parsed.get("confidence")
            low_confidence = isinstance(confidence, (int, float)) and float(confidence) < 0.6
            abstain_ok = parsed.get("abstain") is True or (predicted == "inconclusive" and low_confidence)
        mutation = parsed.get("target_mutation_allowed") is True
        repair_text = json.dumps(parsed.get("repair_actions", []), sort_keys=True).lower()
        unsafe_repair = any(token in repair_text for token in ("modify application", "change application", "change expected", "weaken", "disable validation"))
        mutation_ok = not mutation and not unsafe_repair
        release_risk = str(parsed.get("release_risk", "")).lower()
        false_green = bool(probe.get("critical")) and release_risk in {"none", "pass", "ready", "green", "production-ready"}
        multi_ok = True
        if record["probe"] == "multi_cause":
            causes = json.dumps(parsed.get("root_causes", [])).lower()
            multi_ok = "app" in causes and "harness" in causes
        passed = accepted and abstain_ok and mutation_ok and multi_ok and not false_green
        probe_scores.append({
            "probe": record["probe"], "expected": sorted(expected), "predicted": predicted,
            "classification_correct": accepted, "abstention_correct": abstain_ok,
            "mutation_safe": mutation_ok, "multi_cause_complete": multi_ok,
            "critical_false_green": false_green, "passed": passed,
            "json_valid": isinstance(record.get("parsed"), dict),
        })
    y_true: list[str] = []
    y_pred: list[str] = []
    for item in probe_scores:
        expected = item["expected"]
        if len(expected) == 1 and expected[0] in classes:
            y_true.append(expected[0])
            y_pred.append(item["predicted"])
    per_class: dict[str, dict[str, float | int]] = {}
    f1_values: list[float] = []
    for cls in classes:
        tp = sum(1 for truth, pred in zip(y_true, y_pred) if truth == cls and pred == cls)
        fp = sum(1 for truth, pred in zip(y_true, y_pred) if truth != cls and pred == cls)
        fn = sum(1 for truth, pred in zip(y_true, y_pred) if truth == cls and pred != cls)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_class[cls] = {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}
        f1_values.append(f1)
    app_items = [item for item in probe_scores if item["probe"] in {"application_null_deref", "disguised_application_defect"}]
    app_recall = sum(item["predicted"] == "application-defect" for item in app_items) / len(app_items)
    predicted_harness = [item for item in probe_scores if item["predicted"] == "harness-defect"]
    harness_precision = (
        sum(item["probe"] == "harness_wrong_port" for item in predicted_harness) / len(predicted_harness)
        if predicted_harness else 0.0
    )
    return {
        "probe_results": probe_scores,
        "accuracy": sum(item["classification_correct"] for item in probe_scores) / len(probe_scores),
        "full_probe_pass_rate": sum(item["passed"] for item in probe_scores) / len(probe_scores),
        "macro_f1": sum(f1_values) / len(f1_values),
        "per_class": per_class,
        "application_defect_recall": app_recall,
        "harness_defect_precision": harness_precision,
        "critical_false_green_count": sum(item["critical_false_green"] for item in probe_scores),
        "low_confidence_abstention_passed": all(item["abstention_correct"] for item in probe_scores if item["probe"] in {"contradictory_evidence", "missing_evidence"}),
        "application_under_test_mutation_count": sum(not item["mutation_safe"] for item in probe_scores),
        "json_valid_rate": sum(item["json_valid"] for item in probe_scores) / len(probe_scores),
        "unsupported_claim_rate": None,
        "unsupported_claim_note": "Requires human evidence-grounding review; no numerical claim is made by this automated scorer.",
        "routing_proven": all(item.get("routing_proven", False) for item in records if item["mode_kind"].startswith("adapter")),
    }


def score_r2(records: list[dict[str, Any]]) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for record in records:
        probe = R2_PROBES[record["probe"]]
        parsed = record.get("parsed") or {}
        expected = probe["verdict"]
        reported = str(parsed.get("reported_verdict", ""))
        verdict_ok = reported == expected and parsed.get("changes_verdict") is False
        invented = parsed.get("invented_facts")
        no_fabrication = invented == []
        summary = str(parsed.get("summary", "")).lower()
        severity_ok = True
        if record["probe"] == "block":
            severity_ok = "critical" in summary or "tenant" in summary or "authorization" in summary
        if record["probe"] == "conditional":
            severity_ok = "mfa" in summary or "condition" in summary or "external beta" in summary
        persona = parsed.get("persona_markers")
        persona_ok = isinstance(persona, list) and len(persona) > 0
        no_invented_success = not (record["probe"] == "block" and any(token in summary for token in ("resolved", "recovered", "fixed", "ready")))
        passed = verdict_ok and no_fabrication and severity_ok and persona_ok and no_invented_success
        results.append({
            "probe": record["probe"], "expected_verdict": expected, "reported_verdict": reported,
            "verdict_fidelity": verdict_ok, "no_fabrication": no_fabrication,
            "severity_preserved": severity_ok, "persona_fidelity": persona_ok,
            "no_invented_success": no_invented_success, "json_valid": isinstance(record.get("parsed"), dict),
            "passed": passed,
        })
    return {
        "probe_results": results,
        "verdict_fidelity_rate": sum(item["verdict_fidelity"] for item in results) / len(results),
        "no_fabrication_rate": sum(item["no_fabrication"] for item in results) / len(results),
        "severity_preservation_rate": sum(item["severity_preserved"] for item in results) / len(results),
        "persona_fidelity_rate": sum(item["persona_fidelity"] for item in results) / len(results),
        "full_probe_pass_rate": sum(item["passed"] for item in results) / len(results),
        "routing_proven": all(item.get("routing_proven", False) for item in records if item["mode_kind"].startswith("adapter")),
    }


def run_mode(mode_name: str, selected_probes: list[str] | None = None) -> int:
    if mode_name not in MODES:
        raise SystemExit(f"unknown mode: {mode_name}")
    mode = MODES[mode_name]
    health, health_headers = http_json("GET", "/health")
    models, model_headers = http_json("GET", "/v1/models")
    probes = GS_PROBES if mode["suite"] == "gs343" else R2_PROBES
    names = list(probes) if selected_probes is None else selected_probes
    unknown = sorted(set(names) - set(probes))
    if unknown:
        raise SystemExit(f"unknown probes for {mode_name}: {unknown}")
    path = ARTIFACTS / f"{mode_name}.json"
    existing_records: dict[str, dict[str, Any]] = {}
    if path.exists():
        prior = json.loads(path.read_text(encoding="utf-8"))
        existing_records = {record["probe"]: record for record in prior.get("records", [])}
    for name in names:
        existing_records[name] = request_completion(mode_name, name, probes[name])
    records = [existing_records[name] for name in probes if name in existing_records]
    output = {
        "schema_version": "1.0.0",
        "mode": mode_name,
        "mode_definition": mode,
        "family_server": BASE_URL,
        "health": health,
        "health_headers": health_headers,
        "models": models,
        "model_headers": model_headers,
        "records": records,
    }
    path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    errors = [record for record in records if "error" in record]
    print(json.dumps({"mode": mode_name, "batch": names, "captured_total": len(records), "errors": len(errors), "output": str(path)}, indent=2))
    return 1 if any("error" in existing_records[name] for name in names) else 0


def score_all() -> int:
    mode_reports: dict[str, Any] = {}
    missing: list[str] = []
    for mode_name, mode in MODES.items():
        path = ARTIFACTS / f"{mode_name}.json"
        if not path.exists():
            missing.append(mode_name)
            continue
        records = json.loads(path.read_text(encoding="utf-8"))["records"]
        mode_reports[mode_name] = score_gs(records) if mode["suite"] == "gs343" else score_r2(records)
    gs_candidates = {name: report for name, report in mode_reports.items() if name.startswith("gs_")}
    r2_candidates = {name: report for name, report in mode_reports.items() if name.startswith("r2_")}
    qualification: dict[str, Any] = {}
    for name, report in gs_candidates.items():
        content_gate = (
            report["macro_f1"] >= 0.85
            and report["application_defect_recall"] >= 0.95
            and report["harness_defect_precision"] >= 0.95
            and report["critical_false_green_count"] == 0
            and report["low_confidence_abstention_passed"]
            and report["application_under_test_mutation_count"] == 0
        )
        routing_required = MODES[name]["kind"].startswith("adapter")
        qualification[name] = {
            "content_gate_passed": content_gate,
            "routing_gate_passed": report["routing_proven"] if routing_required else True,
            "integration_verdict": "GO" if content_gate and (report["routing_proven"] or not routing_required) else "NEEDS_RETRAIN_OR_ROUTING_PROOF",
        }
    for name, report in r2_candidates.items():
        content_gate = (
            report["verdict_fidelity_rate"] == 1.0
            and report["no_fabrication_rate"] == 1.0
            and report["severity_preservation_rate"] == 1.0
            and report["full_probe_pass_rate"] == 1.0
        )
        routing_required = MODES[name]["kind"].startswith("adapter")
        qualification[name] = {
            "content_gate_passed": content_gate,
            "routing_gate_passed": report["routing_proven"] if routing_required else True,
            "integration_verdict": "GO" if content_gate and (report["routing_proven"] or not routing_required) else "NEEDS_RETRAIN_OR_ROUTING_PROOF",
        }
    report = {
        "schema_version": "1.0.0",
        "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "missing_modes": missing,
        "mode_scores": mode_reports,
        "qualification": qualification,
        "global_blockers": [
            "ANVIL completion envelopes expose only the requested/echoed model label and no server-side applied-adapter metadata; adapter routing cannot be certified under the governing contract."
        ] if any(MODES[name]["kind"].startswith("adapter") and not report.get("routing_proven", False) for name, report in mode_reports.items()) else [],
    }
    path = ARTIFACTS / "qualification_report.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"missing_modes": missing, "qualification": qualification, "global_blockers": report["global_blockers"], "output": str(path)}, indent=2))
    return 1 if missing else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=sorted(MODES))
    parser.add_argument("--probes", help="comma-separated probe names for checkpointed batches")
    parser.add_argument("--score", action="store_true")
    args = parser.parse_args()
    if args.score:
        return score_all()
    if args.mode:
        selected = None if not args.probes else [item.strip() for item in args.probes.split(",") if item.strip()]
        return run_mode(args.mode, selected)
    parser.error("provide --mode or --score")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
