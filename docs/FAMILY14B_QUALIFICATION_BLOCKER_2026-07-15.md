# Family 14B Qualification Blocker — 2026-07-15

## Scope

The qualification contract requires direct HTTP requests to the ANVIL Family server and requires server-side evidence proving which adapter was actually applied. The requested model label alone is not accepted as routing proof.

## Confirmed live state

- Endpoint: `http://192.168.1.49:8200`
- `GET /health`: reachable with `status=ok`.
- `GET /v1/models`: exposed `echo-prime`, `echo-gs343`, `echo-gs343-v2`, and `echo-r2d2` among the loaded family.
- A direct `POST /v1/chat/completions` request for `echo-gs343` returned HTTP 200 and a usable diagnostic response.
- The response envelope contained `model`, `object`, and `choices` only. Response headers contained ordinary HTTP metadata only. It did **not** contain `adapter`, `adapter_id`, `applied_adapter`, LoRA identity, routing metadata, adapter digest, or another server-side proof field.

## Routing gate

**Result: BLOCKED.**

The response's `model: echo-gs343` value is consistent with the requested label but does not prove that the adapter was applied rather than echoed or silently routed to base. No adapter may receive a GO verdict until the server emits verifiable applied-adapter metadata or an equivalent independently queryable routing record tied to the completion.

## Capacity blocker

The server exposes one inference slot and a maximum waiting queue of four. During this pass, a connector timeout left requests active server-side. The exact client process was identified and terminated without touching unrelated processes, but ANVIL continued to report active/queued work from other or already-accepted requests. Observed snapshots included:

- `in_flight=1`, `queued=3`, `rejected=103`, `completed=215`
- `in_flight=1`, `queued=1`, `rejected=109`, `completed=217`
- `in_flight=1`, `queued=2`, `rejected=110`, `completed=221`
- `in_flight=1`, `queued=3`, `rejected=117`, `completed=222`

A checkpointed base-model batch received HTTP 503 for both selected probes. Those responses are preserved in `artifacts/family14b/gs_base.json` and are infrastructure failures, not model scores.

## Implemented qualification harness

`scripts/qualify_family_adapters.py` now runs the production P5 candidate-versus-incumbent gate against the unchanged 240-row GS343 and R2D2 held-out eval ledgers. It uses one direct HTTP completion per model and row, checkpoints every cryptographically verified response receipt, re-verifies checkpoints on resume, scores locally, and blocks unless each candidate passes its hard gates and reaches at least `1.05 * incumbent composite`.

Routing is proven from the Family server's Ed25519 routing receipt bound to the exact request, challenge, response content, adapter digest, and a pinned public attestation. Requested/echoed model names are not accepted as proof. The harness never changes aliases or service configuration and always leaves the whole-product `release_verdict` at `NOT_READY`.

Pending corrective-candidate qualification command:

```powershell
python scripts/qualify_family_adapters.py `
  --trusted-attestation artifacts/family14b/<current-r5-run>/attestation.json `
  --gs-candidate-model <corrective-gs-model> `
  --gs-incumbent-model <current-gs-model> `
  --r2-candidate-model <corrective-r2-model> `
  --r2-incumbent-model <current-r2-model> `
  --gs-candidate-sha256 <trusted-corrective-gs-artifact-sha256> `
  --gs-incumbent-sha256 <trusted-current-gs-artifact-sha256> `
  --r2-candidate-sha256 <trusted-corrective-r2-artifact-sha256> `
  --r2-incumbent-sha256 <trusted-current-r2-artifact-sha256> `
  --output-directory artifacts/p5/qualification/<run-id>
```

Reuse the same output directory to resume; successfully checkpointed rows are verified and skipped. A changed eval digest, model set, attestation, or inference configuration requires a new output directory.

The four artifact digests are mandatory operator trust inputs. Obtain them from the independently verified adapter artifact manifests or the expected identities used by the successful R5 controls, never from the completion response being qualified. The harness binds these pins into its state, checkpoint, report, and every routing-receipt verification; a label match or merely different candidate/incumbent digests cannot pass.

Bundle construction does not trust the qualification summary. It verifies the content-addressed evidence manifest, re-verifies all 960 signed response receipts, requires 960 matching deterministic score rows across the four adapter/role aliases, and recomputes hard gates plus the `1.05` promotion ratio before creating adapter records.

## Discovery note

Repository-required live discovery was attempted before implementation. The Arcanum search capability was unavailable in the live registry, and `echo.functions.search` returned a gateway timeout/502 after 30 seconds. The implementation therefore reuses the repository's direct-HTTP and local-scoring design from the prior `scripts/qualify_family_adapters.py`, the strict held-out schema/validation helpers in `src/echo_certification_forge/p5_corpus.py`, and the Ed25519 routing-receipt verification contract in `src/echo_certification_forge/family_r5.py`.

## Current adapter verdicts

| Requested model | Content score | Routing proof | Integration verdict |
|---|---:|---:|---|
| `echo-gs343` | Not completed due server saturation | Missing | NEEDS ROUTING PROOF |
| `echo-gs343-v2` | Not completed due server saturation | Missing | NEEDS ROUTING PROOF |
| `echo-r2d2` | Not completed due server saturation | Missing | NEEDS ROUTING PROOF |
| `echo-prime` baseline | Initial batch rejected with HTTP 503 | Not applicable | INCOMPLETE |

No accuracy, F1, recall, precision, unsupported-claim, or narration-fidelity number is claimed from incomplete inference.

## Required recovery

1. Drain or reset only the Family server's accepted inference queue through an authorized service operation; do not reboot network-stranded ANVIL.
2. Add response metadata such as applied adapter ID/version/digest and base-fallback state, signed or tied to a server request ID.
3. Run the checkpointed corpus one probe per request.
4. Score locally and enforce all project thresholds before enabling an adapter.
