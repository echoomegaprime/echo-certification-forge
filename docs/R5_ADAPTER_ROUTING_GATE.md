# R5 — Family 14B Adapter Routing Provenance

## Status

`BLOCK` until the live ANVIL Family server returns a trusted signed routing receipt for every enabled `CERTIFIED` persona and passes the unloaded-adapter negative controls. A requested or echoed model label is not routing proof.

## Trust boundaries

- `personality_registry` owns persona-to-adapter identity, version, digest, maturity, and enabled state.
- ANVIL reads actual active PEFT/LoRA state immediately before and after generation.
- ANVIL holds a dedicated Ed25519 routing-attestation key. It is not a verdict-signing key.
- Certification Forge holds only trusted public routing keys.
- The independent R5 verifier replays every receipt and is the only component allowed to emit `[R5 COMPLETE]`.

## Server integration

Import `integrations/anvil/family_routing_receipts.py` into `/home/anvil/echo_prime_serve/serve_echo_family.py`.

For a persona request:

1. Resolve the exact enabled registry row.
2. Acquire the sole generation slot and record its lease ID.
3. Activate the requested adapter.
4. Read the actual active adapter ID from the live PEFT model object.
5. Compute or load the immutable adapter artifact SHA-256 from the mounted artifact, not the request.
6. Call `persona_receipt(...)`. Any identity mismatch must abort before returning generated text.
7. Attach the signed envelope as top-level `routing_receipt` in the OpenAI-compatible response.

For an explicit `echo-prime` request, call `base_receipt(...)`. It refuses to sign while any adapter is active.

For an unloaded or inactive persona adapter, do not generate. Return HTTP 409 or 503 with `adapter_not_active_response(...)`. Silent base fallback is prohibited.

## Negative-control administration

The test-only administration surface is direct HTTP and requires an exclusive short-lived maintenance lease:

- `POST /admin/adapter-routing/lease`
- `POST /admin/adapters/{adapter_id}/unload`
- `POST /admin/adapters/{adapter_id}/load`

The lease must drain the queue, block concurrent production inference, be append-only audited, expire automatically, and guarantee adapter reload plus health recheck. These endpoints must not expose generic shell execution.

## Acceptance

```powershell
python .\scripts\r5_adapter_routing_gate.py `
  --family-url 'http://192.168.1.49:8200' `
  --registry-snapshot .\artifacts\r5\personality-registry.json `
  --trust-store .\config\routing-public-keys `
  --output-dir .\artifacts\r5 `
  --positive-repetitions 3 `
  --retry-attempts 6 `
  --run-slot-contention-control `
  --run-unloaded-negative-control `
  --admin-url 'http://192.168.1.49:8200'
```

The administration bearer token is read only from `ECHO_FAMILY_ADMIN_TOKEN`; it must not be written to the report.

```powershell
python .\scripts\verify_r5_adapter_routing.py `
  --report .\artifacts\r5\r5_adapter_routing_report.json `
  --registry-snapshot .\artifacts\r5\personality-registry.json `
  --trust-store .\config\routing-public-keys `
  --output-dir .\artifacts\r5\verified `
  --source-commit '<exact commit SHA>' `
  --p4-completion-commit '51e406587a82e69ca12b5f1f850dfbb4a57721e9' `
  --harness-digest '<sha256>' `
  --policy-digest '<sha256>' `
  --verifier-build-digest '<sha256>' `
  --require-slot-contention `
  --require-unloaded-controls `
  --signing-key-pem '<isolated verifier key path>'
```

The angle-bracket values are supplied from immutable build/evidence records at execution time; they are not configuration defaults.

## Mandatory predicates

- Every enabled `CERTIFIED` registry persona has at least three successful signed receipts.
- Receipt adapter ID, artifact digest, adapter version, and registry revision match the signed snapshot.
- Actual active adapter list contains exactly the requested adapter.
- `fallback_used=false` for every persona response.
- Explicit base control proves no adapter is active.
- Unloaded adapter returns `ADAPTER_NOT_ACTIVE` with a signed failure receipt.
- One-slot contention produces success plus bounded queue/backpressure, never base fallback.
- Every adapter is reloaded and health-checked after negative controls.
- Independent verification has zero failures.

Until every predicate passes, `run_outcome=INCONCLUSIVE`, `release_verdict=NOT_READY`, and no completion marker is issued.
