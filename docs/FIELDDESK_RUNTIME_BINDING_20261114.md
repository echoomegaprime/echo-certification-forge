# FieldDesk exact-runtime integration — November14,2026

## Objective and source custody
Finish FieldDesk's actual source journey through a measured, dependency-complete runtime,
while retaining the current issuer's security/evidence fixes. Work is isolated on the
agent branch rooted at b4780cd633ff242554473013ae3d1f45cf5c193b. That root's CI/P4 evidence
belongs to that root, not to the resulting changed source. Full exact-head validation and
independent release admission remain required after the integration is committed.

The functional lineage is PR31 (measured environment and governed journey admission),
PR36 (project-bound source/dependencies), the isolated PR37 resource fix3b1ddaa8, and
PR38 (literal pinned-platform parser). Preserve current DEFAULT061deb/pull-never,
all six patched role recipes, authenticated fresh vendor definitions, EvidenceStore
serialization/publication, terminal replay, full-lifetime heartbeat cleanup and fenced
claim recovery. Do not import the unrelated Foreman recipe or overwrite newer P4 logic.

Issuer writer ownership is disjoint: measured profile/worker/dispatcher; API/app/intake;
shared subscriber/sandbox/contracts/packaging; and regression tests. Only the root owns
integration commits, push and metadata. No source signer authority is implied.

## Existing artifact versus actual missing implementation
Historical public profile:
/home/forge/fielddesk-staging/runtime-repair-20261027/fielddesk-runtime-profile.json
SHA256053a08714fd0a81015b9509b9997fca3984f6dee7baf654dad7d6301d907ec54.
It binds old FieldDesk e4aa9b6, image85be3ef1,2GiB and120s; a real offline journey passed
122backend cases in40.479s. Those are historical observations. The old image and its
two pinned base references are not present in the current FORGE image store.

The current b478 issuer had no runtime_identity/runtime_admission integration, exposed
fixed environment labels, and its dispatcher constructed only the generic512MiB sandbox.
The live catalog read returned echo.certforge.runtime_environment UNREGISTERED among
15,501records. An SDK contract file is not a live capability registration. Source,
matching API/worker/dispatcher, generated SDK registration and paired App admission are
all needed; this is not merely a missing owner signature on a current valid profile.

## FieldDesk source and dependency commitment
Current application target is a6fc58034b74f9a8bc440d41e6dc97462653e694,
published as FieldDesk PR13 over PR12. It updates the proposed live/CI Node pin to22.23.4,
refreshes the legacy bootstrap defaults and adds exact-head checkout/readback.
Backend/frontend/Android application trees and all six dependency inputs remain byte-identical.

The public dependency material keeps its actual origin290658c4be634af6dd308021d1946f737032c3cf.
Its hashes are reusable only as the same immutable dependency input. The new application
revision requires a fresh exact source/profile/environment binding and verdict; neither
the old source label nor its failed request may be rewritten to claim that acceptance.

| Input | SHA256 |
| --- | --- |
| frontend/package.json | 0eedf4c01872062c1e17f1a196c626b767f8be1717de1422e05c19356e54e7e8 |
| frontend/pnpm-lock.yaml | c1cf616256e559343ce421101ea43cf5635f8c3ba75baef97477e5a68ac9a4cc |
| frontend/pnpm-workspace.yaml | 4a69dc93a75ff4a33f54c2853d5317c8e7374faab592f3472b5164257bff8066 |
| frontend/.npmrc | a3909ac0447c469fda12c57374993be70f47ce73e49fd3124678c7c047f2214d |
| backend/requirements.txt | 986335d9561613e765504417fb313890baa19b74432d2227f95198609e4fadfd |
| deploy/certification/requirements.lock | 89859f38a37ef3b71413ba124fb393d83c322b2fd97319d15517170520eda0a4 |

The entrypoint is python3 -B scripts/certforge_journey.py. It checks actual prerequisite
modules, Node>=22.13.0 and exact dependency seal, copies source into a disposable
workspace, and runs all four steps: frontend workflows; production build; real runtime
identity/restart; and full selected backend authentication/migration tests with a strict
no-skips JUnit check. It makes no network installations or production/provider calls.
A host smoke test or the generic Python-only DEFAULT cannot substitute for it.

## Separate journey and live runtimes
The existing journey admission model permits Node24.22.1/Python3.12.16 and its original
legacy pair; it does not admit Node22.23.1 by implication. Prefer the already supported
new pair for a new explicitly versioned FieldDesk dependency-image candidate. Build its
sealed dependencies from the exact six inputs, then actually run the complete a6fc580 source
journey under the intended2GiB/no-swap/oneCPU/128PID/64MiB tmpfs/nonroot/read-only/no-network
profile. Record actual versions, immutable index/manifest/config/rootfs relationships,
archive/provenance/SBOM, two independent builds, scanner and current Node-core reports,
negative seal/source/resource controls and explicit owned-container absence.

Do not reinterpret the existing Node22 Dockerfile or its old profile as an admitted
Node24 build. A separate canonical recipe/material packet and owner-reviewed selection
are required. Any use of Node22 through this sealer would need an explicit strict
version-pair contract change and its own qualification/tests; no raw signing workaround.

The proposed LIVE FieldDesk application proposes Node22.23.4 in deploy/HOSTING.md and the
prepared deployment bundle. Its actual Node/FastAPI/SQLite private smoke and browser
tests are separate evidence. Production collector evidence must bind the actual deployed
runtime/artifact; a successful source journey under Node24 does not claim that evidence.

## Authenticated API and paired App
The resolver uses existing subscriber RUN_READ authorization, requires active project
access, accepts bounded exact journey and paired project/target, and returns strict nine
environment components plus the canonical submit declaration. It neither executes code,
reserves quota, creates a run, chooses caller-provided resources nor creates projects.
Wrong tenant/project/source/dependencies and changed measured inputs fail before execution.

Paired AppPR13 source1b7e5d203660a1a0b358c9bcda1a40540b64765c already sends the selected
existing project and identical source target. The isolated validation worktree is
D:/ECHO_OMEGA_PRIME/01_WORKSPACES/active/fielddesk-certforge-app-runtime-20261114 on
agent/fielddesk-app-runtime-integration-20261114. Canonical main47c0e3b9dc0465c6eb52b644c87c5e01b40ac0e3
and the installed App are preserved. Fresh isolated validation of exact1b7 source passed:
declared uv sync,257full real-pytest cases with5existing POSIX-only Windows skips,
compilation, and the offline journey165passed/0failed/0skipped across7suites in43.33s.
The offline journey explicitly reports pytest_shim:true and network/broker/GitHub doubles;
it is not live staging or full POSIX acceptance. JUnit confirms262cases,5skips,0failures,
0errors. Logs and the hash receipt are under the task artifact directory
D:/ECHO_OMEGA_PRIME/08_ARTIFACTS/fielddesk-certapp-runtime-20261114.
The initial full run reached100% but hit a shared Windows pytest-current cleanup
permission failure; its original log remains. The unchanged source passed with a
task-private basetemp. No product-code patch was needed or made.

Operator-owned repository/project mappings must come from authenticated owner readbacks.
The App default-environment pin is refreshed from the actual installed measured profile;
its optional global image pin must agree or remain intentionally unconfigured. Never
synthesize these values, expand identity scopes, create a project from model-generated
IDs or replace a failed resolver with a fixed-label declaration.

## Intake, rollout and rollback
1. Preserve the original failed run, its evidence and partial rerun key
fielddesk-290658c-sdk-recovered-20261113. Use the existing governed read/recovery path to
account for uncertain or terminal work; no production-row edit, identity rewrite or
automatic retry under changed code.
2. Finish exact-source checks for the integrated issuer, current whole-product packet,
actual dependency image qualification and existing-owner image/profile/source admission.
The source-bound public profile selects only exact tenant/project/repository/source,
journey/dependency/image/resource commitments. A public JSON profile is configuration,
not a new signer or proof of admission.
3. Stage the matching API, dispatcher, worker, generated SDK schema/capability and paired
App as one versioned unit. Verify authenticated resolver→same persisted worker profile,
actual Docker invocation/resources, post-acquisition source/dependency checks, transaction
boundary and negative/recovery behavior. Keep unrelated tenants/repositories restricted.
4. Only after old-request reconciliation and admission resolve a fresh exact declaration
and perform explicitly versioned NEW intake with a new idempotency key. Preserve old
records unchanged; changed source/profile/environment cannot reuse an old verdict or
frozen App checkpoint.
5. Hold App workers during any rollout/rollback, preserving the COMPLETE SQLite ledger,
submission intents, continuation budgets and receipt chains. Old/new App binaries may
not share the ledger concurrently. Unknown submission intents remain held.
6. Preserve prior issuer release/public profile/SDK contract/App release/configuration
together. A v1-only binary cannot consume a v2 profile. After acknowledged writes,
snapshot and reconcile rather than restoring stale database bytes. Retain queue
identities, claims, leases, evidence and revocation state; never rewrite commitments to
make the old binary accept new work.
7. Obtain fresh frozen cloud/legacy/memory/conversation/attachment exports and explicit
owner mapping before real FieldDesk migration. The current loader refuses attachment
references; if actual data has them, implement and verify migration instead of dropping
references. Capacity, duplicate consent, in-progress conversations and retry guards remain
release checks. No empty fixture is a final customer snapshot.
8. Finish requested-host authentication, actual rollback, genuine production collector
and dual-issuer proofs, physical Pixel/browser/session/upgrade and controlled provider
acceptance. Current missing device/cloud access is not repaired by source tests.

The global GitHub-first queue at echo-github-autonomy#19 still says FIRST MIGRATION:
FINISHER and requires owner coordination. This source/private work does not reorder that
queue or claim global production rollout authority. Preserve that coordination item;
the issue is not an observed machine-enforced block on independent source qualification.

## Verification state
Source integration is in progress and uncommitted at this checkpoint. Private FieldDesk
deployment smoke, old runtime bindings and b478 source/P4 results retain their exact
original identities. All resulting-head CI, measured runtime/API/App integration, negative
controls, current P4 and independently signed readiness still require fresh evidence.
No live service, SDK registration, scope, trust, key, ingress, customer/provider/device
setting or installed queue was changed by this source work.
