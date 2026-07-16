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

`scripts/qualify_family_adapters.py` implements direct-HTTP-only, locally scored comparisons for:

1. base Family 14B;
2. base plus system prompt;
3. LoRA adapter request;
4. adapter plus verified evidence/tool context.

The GS343 corpus covers application, harness, environment, test-data, dependency, multi-cause, contradictory evidence, missing evidence, disguised application defect, budget exhaustion, and unsafe-repair cases. The R2D2 corpus covers READY, CONDITIONAL, and BLOCK narration fidelity. The harness records raw requests/responses, scoring inputs, queue state, and the routing-proof decision.

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
