# FieldDesk issuer recovery — November 13, 2026

## Objective and custody
Restore evidence-producing certification for FieldDesk https://github.com/echoomegaprime/fielddesk/pull/12 at 290658c4be634af6dd308021d1946f737032c3cf. This issuer repair starts from canonical echoomegaprime/echo-certification-forge main 4f7d99e2dd4422f3d81cf5b709581be963f5818a on agent/builder-fielddesk-issuer-recovery-20261113. Existing QUENCH issuer worktrees, local modifications and historical artifacts were inventoried and preserved. No running source, database, certificate or protected policy is edited in place.

Source-only role intent: Builder; loaded Complete Builds and God Mode workflows, Account Continuity doorway, global/repository instructions and governing contracts. MEGA not needed: existing capabilities and project tests cover this repair. This is not a claim of a new server role/scope grant or release approval.

## Observed failure
FieldDesk issuer run cert_8e78c2bb040953431f7cbebde8b8b1ae5ef09012 ended INFRA_FAILED / NOT_READY. Its current authorized SDK status, evidence index and bounded hash-verified artifact read succeed; the earlier missing diagnostic-read permission is superseded. Findings are empty and no verdict is available.

Dispatcher journal recorded sqlite3.OperationalError database is locked at 2026-11-14T02:49:40.592Z: dispatch_worker.dispatch_once -> run_worker.run -> executor.execute (adapter-record collection) -> EvidenceStore.append_artifact, INSERT at deployed line635. Dispatcher subsequently restarted. Logs correlate with the failed run's timing but do not identify the lock holder.

The SDK service separately completed an existing restart. The readiness helper timed out at180s; actual cold readiness took196.319s. This task did not restart it or modify scopes. Collection-level SDK calls still lost responses. One governed rerun request used stable key fielddesk-290658c-sdk-recovered-20261113; its retry returned409 run_materialization_state_conflict. No new rerun key or manual production-row mutation is used.

## Repair queue
| Item | Completion criterion | State |
| --- | --- | --- |
| Evidence append | Independent writers serialize chain allocation/publication; contention bounded; loser cannot alter winner; tenant/hash/append-only rules intact | Focused regression verified; full validation pending |
| Terminal rerun replay | Exact terminal RELEASED replay returns original child with no new usage/dispatch; active/cross-tenant/binding guards intact | Focused regression verified; full validation pending |
| Heartbeat cleanup | Unexpected executor failure always stops renewal, preserves exception and owned cleanup, permits normal fenced lease recovery | Focused regression verified; full validation pending |
| Source validation | Focused/full tests, P1/P6/P7, independent review, clean staged secret scan, pushed exact head and draft PR | Pending |
| Release integration | Reconcile with existing deployed-ancestry/recovery PR64/65 and current release owner; renewed exact-source checks and governed staged acceptance | Pending; no promotion authorized by a fixture pass |
| FieldDesk production | Final data freeze/reconciliation, rollback, exact hostname authenticated gateway, trusted collector evidence, issuer approvals and device/provider acceptance | Pending |

## Source invariants
EvidenceStore previously read the chain tail and published bytes before obtaining its metadata write transaction. The repair must lock before identity/tail/publication and never retry a stale descriptor or overwrite another invocation's artifact. Subscriber code already recognizes a RELEASED terminal replay but later rejects it via a BOUND-only state check. Permit only that already-validated replay; never relax active EXECUTING/STARTED fencing. Executor failures must not leave a renewing heartbeat behind.

## Existing release work
Existing PR64/65 and their independent review, security, ancestry and two-phase policy gates remain separate. This branch must not overwrite them or replace the installed issuer from an unreconciled tree. Private keys and tenant/customer records never enter this branch. Keep all signed evidence immutable and leave failed runs available for audit.

## FieldDesk acceptance already observed
Exact-head GitHub Linux/Windows CI passed (160 Linux backend,168 Windows backend+8subtests);102 frontend workflows, types, builds and HTTP/SQLite integration pass. Fresh private actual-browser staging verified synthetic login, UI-to-canonical-store write, Sample isolation, restart persistence, desktop/mobile navigation, denied unauthenticated API/workspace/assets, zero JS exceptions and SQLite integrity. Browser report SHA256 cdfcc7fdfb011938feb565a11fdfc183036c10419f205ed0b784d00126058368. These are synthetic private checks, not production attestations.

Android build at290658c verified v2/v3 signature, same development signing identity, package com.echo.fielddesk version2/1.1-launcher, zero requested permissions. APK SHA256 eac6a52d3074734a680c1c2f3910030c8883208bb6191638c9547203c5198d4e. No device is connected; no install/settings changes occurred.

Hostname diagnosis: no exact fielddesk.echo-op.com ingress, so wildcard rule63 routes to a different service returning404. After release gates, route the exact hostname through authenticated FastAPI8792; never expose Node8794. Preserve the legacy hostname and exact config snapshot for rollback.

## Focused repair verification
Evidence regression baseline reproduced three failures; repaired evidence/verdict/read-surface suite34passed, including9newcases. Terminal-replay baseline1failed2passed; repaired new+existingrerun suite4passed. Heartbeat baseline3failed1passed; repaired suite4passed. Independent peer review found no material blocker in evidence/subscriber repairs; heartbeatdiff independently inspected. Broader exact-source validation and hosted CI remain pending. No live row, artifact, signing key or verdict was altered.

## Broad local validation and exact-head CI
Initial code head216694d5158649c746faa299a015f0a8dc74a832: compile passed;641 full-suite cases passed,2skipped,one unchanged Windows symlink fixture failed withWinError1314(required privilege absent);80.72% branch coverage exceeds unchanged80% gate. P1,P6,P7 fixture acceptance passed. Do not weaken the symlink check or claim a fully passing Windows suite. Linux hosted acceptance must exercise the real supported boundary.

Port the exact existing PR62 CI/CodeQL workflow blobdadb8efe9431bde7770f592e34a8617738044fe2 from9417dc5a06159291384d11f569a2ffdb5b15c108: pin checkout/setup/artifact/CodeQL action revisions, verify actual checkout equals PRhead, preserve full tests/coverage/P1/P6/P7 and add exact-head Python analysis. Only CodeQL gets security-events write; no deployment permission. Existing source and review branches remain unchanged. Await fresh checks on the resulting new head.

Review limits: ambiguous commit errors preserve bytes for reconciliation; filesystem identity-check/unlink assumes service-controlled directories. An in-flight heartbeat blocked in SQLite can briefly outlive the2s join, but the stop-event prevents further renewal cycles. No claim of instantaneous blocked-I/O cleanup.
