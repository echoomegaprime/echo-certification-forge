# Account Continuity Bridge production acceptance collector

`scripts/hammer_account_bridge_attestor.py` is an operator collector for the reviewed
ACB candidate `def1828001c354bcf89f7d32bc987d6eba520cb6`, PR 4, branch
`agent/grok47-provider-recovery-20261003`, plugin version
`1.1.0+codex.20261003120504`. It is not a subscriber endpoint or a generic signer.
Changing the candidate requires source review and new evidence. Policy, trust
roots and target source are not changed by this collector.

## Source provenance

Recovered through scoped SDK reads from HAMMER's historical operator workspace:
`C:/Users/bobmc/tmp/echo-account-continuity-attest-20260902T173258Z-33cd2522/hammer_account_bridge_attestor.py`.
Its exact recovered SHA256 was
`9451710e9ec0323b7784411720fd76214268a2a7fa64da28d97a80fcae922ef4`.
The SDK's text scrubber replaced the harmless Python keyword `password=None)`;
restoring that literal reproduced the independently measured complete source hash.
No key bytes were retrieved. The old temporary workspace had no Git provenance;
this repository establishes reviewed source ownership from this import onward.

The historical owner was `HAMMER\bobmc`; its existing collector identity is
`ed25519:59de9be507b39b291ee13c4a57378ec6`. The collector requires that identity;
it does not generate keys or enroll public keys. Current trust admission must be
verified independently by the operator before use.

## Execution and custody

Run only as the existing HAMMER collector owner. Inputs must come from the
authorized QUENCH acceptance and hosted-app readback, outside the candidate
repository. Required `--quench-evidence-sha256` and `--revision-receipt-sha256`
bind the actual owner-retrieved JSON bytes; these hashes are custody checks,
not proof that an arbitrary caller's JSON is authentic. Never populate successful
fields by assertion or copy the synthetic test fixtures into operational evidence.

The collector verifies a transferred Git bundle, exact head, branch, ancestry and
clean checkout. It runs three independent passes of 91 HAMMER-safe assertions,
three router concurrency/lock negative controls, and three critical journeys.
DPAPI-dependent core/bridge assertions must pass on QUENCH's real native install;
they are explicitly not represented as executed on HAMMER. The complete QUENCH
suite has 119 named assertions. Secret scanning must pass on both hosts.

This operator path is only for the reviewed first-party ECHO candidate. It must
not be repurposed to execute arbitrary customer code under the key-owning user.
Customer targets continue to require dedicated isolated runners and separate
signing authority. Key material is never sent to target commands. Source children
and the temporary checkout finish before the operator loads the existing key.
The key must be outside the collector workspace, bundle and evidence inputs.
Outputs are three distinct new paths; existing files are never replaced.

## QUENCH evidence v2

The JSON object schema is `echo.account-continuity.quench-evidence.v2`:

| Field | Required evidence |
|---|---|
| `host`, `observed_at` | QUENCH; actual zoned observation time, no more than one hour old |
| `source_commit`, `installed_cache_commit`, `remote_branch_commit`, `pull_request_head_commit` | Each independently read back as the exact candidate SHA |
| `branch`, `pull_request`, `installed_version` | Exact branch above, integer 4, exact plugin version above |
| `installation_scope` | Explicit `isolated_canary` or `production`; production signing requires `production` |
| `installed_manifest_sha256` | Hash of the measured installed file manifest whose files were compared to the candidate |
| `native_plugin_enabled`, `fresh_native_session` | Both verified true through actual native plugin/session readback |
| `iterations`, `assertions_passed_per_iteration`, `critical_journeys` | 3, `[119,119,119]`, three actual `PASS` results |
| `test_runs` | Three rows: numbered `iteration`, actual `observed_at`, exact `source_commit`, `total=119`, complete suite counts, `critical_journey=PASS`, and real `router_concurrency` output |
| `live_runs` | Three distinct nonce/session rows from actual installed bridge execution, as described below |
| `status_runs` | Three actual non-spending installed MCP observations with time/source binding |
| `gitleaks_exact_tree`, `codex_mcp_config` | Actual `PASS` exact-tree scan and `ok` native MCP config readback |
| `private_key_exported`, `credentials_in_evidence` | False, supported by the execution boundary and sanitized artifact inspection |

The suite count mapping is `repository_policy:8`, `account_continuity_core:6`,
`provider_auth_monitor:18`, `provider_content_import:9`, `multiprovider_mcp:35`,
`account_continuity_bridge:22`, `provider_registry:21`.

Every router row must be the real `Test-RouterConcurrency.mjs` result:
`ok=true`, `concurrent_requests=12`, `concurrent_processes=8`, and
`contended_lock_preserved=true`. This is additional acceptance, not included in
the 119 named assertions.

Every live row requires `exact_canary_match=true`, `selected_provider=forge-qwen`,
`selected_outcome=success`, `provenance=LIVE_PROVIDER_BRIDGE`,
`credential_copied_or_exposed=false`, equal valid `canary_sha256` and
`response_sha256`, actual `model` and `session_id`, exact `source_commit`,
`governance=PASS`, and actual `observed_at`. Nonces and session IDs must be distinct.
The inherited Qwen route is preserved. A canary is one bounded no-tools/no-files
turn through the installed MCP route with a fresh unique expected token, followed
by exact response readback. Use the existing governed prompt builder; no bypass
or direct substitute API establishes installed bridge acceptance.

Every status row requires `status_nonspending=true`,
`server_name=account_continuity_multiprovider_mcp`, `server_version=0.5.0`,
`provider_count=7`, `tool_count=17`, exact source SHA and actual observation time.
The 26 critical-journey surfaces include nine PowerShell actions; they are not
the native MCP tool count. The actual source/native inventory has 17 MCP tools.
Every nested observation must be current and timezone-aware.

`isolated_canary` means a real official native installation in a new task-owned
Codex home with the same tests, live calls, negative controls and installed-byte
readback. It is not a workspace test. The evidence validator preserves that scope,
but the production collector rejects it before hosted collection, source execution,
private-key access or signing. Its input remains unsigned canary evidence and the
release remains NOT_READY. The generic production policy does not inspect this
scope itself, so a documentation disclaimer cannot enforce the boundary. Only
measured `production` installation evidence may enter production signing. Scope,
custody hashes and every source timestamp are revalidated immediately before key
access so long HAMMER test runs cannot refresh expired QUENCH observations.

## Hosted receipt and invocation

`--revision-receipt` is an actual Certification Forge GitHub App revision receipt
readback, not a GitHub Actions CI document. It must have app identity
`certification-forge`, exact repository/SHA, a valid observed receipt chain and
one succeeded receipt matching `--hosted-delivery-id`. Its result must bind the
exact acquired target/environment, initial `COMPLETE`/`NOT_READY` certification,
`production_e2e_valid=false`, positive check-run identity and custody hash.
The standalone strict run alone does not supply this hosted-app receipt.

```powershell
& '<HAMMER python>' scripts/hammer_account_bridge_attestor.py `
  --bundle '<exact-source.bundle>' --base-commit '<reviewed-base-SHA>' `
  --source-commit def1828001c354bcf89f7d32bc987d6eba520cb6 `
  --target-identity-digest '<acquired-target-digest>' `
  --environment-identity-digest '<current-worker-environment-digest>' `
  --revision-receipt '<owner-readback.json>' --revision-receipt-sha256 '<measured-hash>' `
  --hosted-delivery-id '<matching-delivery>' `
  --quench-evidence '<measured-quench.json>' --quench-evidence-sha256 '<measured-hash>' `
  --private-key '<existing-owner-held-key-path>' `
  --python '<HAMMER python>' --pwsh '<HAMMER pwsh>' --node '<HAMMER node>' `
  --gitleaks '<verified-binary>' --workspace-root '<isolated-workspace>' `
  --quench-address '<measured-address>' --quench-management-port '<measured-port>' `
  --output '<new-envelope.json>' --public-key-output '<new-public.pem>' `
  --report-output '<new-report.json>'
```

This command signs only after every real acceptance gate completes. Source tests
do not execute it against production or existing keys. The operator separately
verifies the returned signature and exact binding, then admits the envelope via
the root-owned atomic transfer described in `OPERATIONS.md`. The collector has
no remote admission/deployment code. A new idempotent strict run consumes fresh
evidence; existing terminal runs and their signed verdicts remain unchanged.
