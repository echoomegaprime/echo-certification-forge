# Full-history secret scan

Local evidence only. GitHub Actions is disabled account-wide (ticket #4663295);
this report is not a hosted-CI result.

## Command

```powershell
python scripts/full_history_secret_scan.py
```

Machine-readable output: `artifacts/full_history_secret_scan.json`.

## Result

- Tool: gitleaks 8.24.3 (`--log-opts --all --redact`) plus a local unique-blob equivalent
- Scope: every commit reachable from remote-tracking refs (278 commits, 22 refs, 1227 unique blobs)
- Blocking findings (private-key blocks, GitHub tokens, AWS access keys outside fixtures): **0**
- Redacted detector hits: 86, all informational or review
- Review hit in product code: `src/echo_certification_forge/anchor.py` field name `_private_key` (type annotation, not key material)
- Informational hits: test peppers, fixture PEM *headers* split across concatenations, and historical artifact JSON

No secret material is stored in the report. Previews are `[REDACTED]`.
