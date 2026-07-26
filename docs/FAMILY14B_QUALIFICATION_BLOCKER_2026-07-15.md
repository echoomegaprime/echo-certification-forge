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

`scripts/qualify_family_adapters.py` now runs the production P5 candidate-versus-incumbent gate against the unchanged 240-row GS343 and R2D2 held-out eval ledgers: 960 response rows across the four candidate/incumbent model-role aliases. It uses one direct HTTP completion per model and row, checkpoints every cryptographically verified response receipt, re-verifies checkpoints on resume, scores locally, and blocks unless each candidate passes its hard gates and reaches at least `1.05 * incumbent composite`.

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

`scripts/build_p5_adapter_bundle.py` additionally requires operator-supplied qualification and R5 Ed25519 public-key/key-id pins plus all four artifact SHA-256 pins. These inputs must come from the independent release trust store, not from the qualification/R5 package. Their aggregate digest is recorded in the adapter acceptance report; self-keyed packages and cross-family alias/digest reuse are rejected.

The run worker loads an independent trusted adapter registry from `--adapter-registry` or `ECHO_CERTFORGE_ADAPTER_REGISTRY`; it never trusts a public key or policy shipped beside the bundle. The registry pins the runner key, policy ID/digest, and qualification/R5 trust-root digests, all of which are signed into the bundle payload. Production bundle construction accepts only complete `echo.certification-forge.p5-qualification/v2` evidence. V2 binds the exact semantic scorer and deterministic output-contract implementation digests into the qualification state, permits faithful paraphrase and prompt-authoritative facts, and applies only policy-owned normalization: target mutation always remains prohibited, GS343 release risk may only become more restrictive, and R2D2 persona markers may be canonicalized without changing its verdict. Raw signed responses and normalized-output digests are both preserved in the sealed score ledger. Each R5 source must be the canonical full-run package with the complete Merkle-bound manifest, positive probes, wrong-active and unloaded negative controls, full-mode verification bundle, and every signed receipt.

Production launchers use `mandatory-rules.v2.json` and require the adapter bundle, policy, and independent registry; v1 or missing-adapter operation is available only through the explicit non-production compatibility switch. External trust pins now cover all four aliases plus the exact server build, registry snapshot/revision, and base-model identity. Every R5 run uses an operator-chosen run ID and nonce bound into every signed receipt challenge, report, manifest, and R5 trust digest; mixed-run splices and attestation `requested_models` values other than exactly the four pinned aliases are rejected.

The production adapter response is a reusable, registry-pinned qualified identity source, not a replayable certification-run response. The worker verifies its exact registry digest, loads the independent adapter-runner signing key, and deterministically signs a new response bound to the freshly allocated certification `run_id` and tenant before execution. The deploy gate and SDK launcher require that protected signing-key path; caller-supplied paths are not accepted.

The R5 SDK verifier now requires exactly four semantically correct signed controls (both positive probes plus wrong-active and unloaded), the externally selected run ID/nonce in every challenge, distinct request IDs, and exact status/error/model/digest semantics. Async R5 submission reserves the request digest atomically before SSH launch, treats only exact retries as idempotent, records conflicts, and persists launch failures. Production workers also pin the exact v2 manifest digest and persist each per-run rebound response into the evidence chain before verdict signing, binding its SHA-256 into the environment identity.

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
