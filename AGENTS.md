# Certification Forge Agent Contract

This repository implements the deterministic Echo Certification Forge release authority.

## Governing order

1. `docs/PROJECT_CONTRACT.md`
2. `docs/SPEC.md`
3. `policies/mandatory-rules.v1.json`
4. Tests and executable acceptance evidence

## Mandatory behavior

- Default every run to `NOT_READY` until verified evidence proves otherwise.
- Keep `run_outcome` separate from `release_verdict`.
- Bind verdicts to immutable target, environment, policy, evidence, and signing identities.
- Treat GS343 and every LLM as advisory; deterministic rules alone issue verdicts.
- Never run customer code in the control plane or developer workstation.
- Never place private signing keys in workers, evidence, logs, model context, or client applications.
- Preserve tenant isolation on every read and write.
- Do not weaken tests or mutate target code to obtain a pass.
- Do not mark a phase complete without reproducible acceptance evidence and a scoped commit.

## Required local checks

```powershell
python -m pytest -q
python scripts/p1_acceptance.py
```
