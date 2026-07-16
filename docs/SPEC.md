# ECHO Certification Forge Documentation

> Vendored from the canonical PDF source for reproducible implementation. Page markers preserve source-page provenance.
> Source SHA-256: `09cd016d775095b0f543e62717a41455deb17f54ee187039f05ac47d147b1e78`
> Source pages: `76`


<!-- SOURCE_PAGE: 1 -->

ECHO CERTIFICATION FORGE
Autonomous Application Testing, Verification, and Release-
Certification Platform
Repository:ECHO-OMEGA-PRIME/echo-certification-forge
Primary service:cert.echo-op.com
Product class: Autonomous QA, security verification, and software release certification
Default verdict:BLOCK
Core rule: No application receives READY without reproducible, evidence-backed proof.
1. Mission
ECHO Certification Forge accepts a repository, archive, local directory, container image, deployed URL, MCP
endpoint, SDK package, or CLI artifact and autonomously determines whether it is ready for release.
The forge must:
Discover the application architecture without requiring a manually authored test plan.
Select and configure the correct stack adapters.
construct missing test infrastructure when necessary.
Build and run the real application in an isolated environment.
Exercise critical user journeys and system behaviors.
distinguish application defects from harness, environment, data, and dependency failures.
collect tamper-evident evidence.
issue exactly one final verdict:
BLOCK
CONDITIONAL
READY
register the certification result with the ECHO build and memory systems.
prevent uncertified builds from reaching production.
The forge is not a wrapper around pytest, Playwright, or CI pipelines. It is an autonomous release
authority.
1. 
2. 
3. 
4. 
5. 
6. 
7. 
8. 
9. 
10. 
11. 
12. 
13. 
1


<!-- SOURCE_PAGE: 2 -->

2. Non-Negotiable Operating Principles
2.1 Default deny
A certification run starts in BLOCK.
The application must earn a less restrictive verdict through successful evidence collection.
Absence of evidence is not success.
Unknown critical state is a blocking condition.
2.2 Evidence over assertion
The following are not accepted as proof of readiness:
source code exists;
compilation succeeds;
the developer says the feature works;
a test suite reports green without coverage of critical journeys;
an endpoint returns HTTP 200;
a UI opens;
an AI model claims the application appears correct.
Every material claim must reference collected evidence.
2.3 Real execution
The forge must execute the actual application wherever technically possible.
Static inspection alone cannot produce READY.
Static-only certification must be labeled as incomplete and normally result in CONDITIONAL or BLOCK.
2.4 Observable-state synchronization
Tests must wait for observable state changes.
Prohibited synchronization patterns:
sleep(5)
wait 10 seconds
• 
• 
• 
• 
• 
• 
• 
2


<!-- SOURCE_PAGE: 3 -->

Start-Sleep -Seconds 20
fixed timeout before checking
Required patterns include:
process health state;
port availability;
DOM condition;
API response predicate;
file creation;
log event;
database state;
window visibility;
service readiness probe;
message queue event;
protocol handshake.
Timeouts remain mandatory as maximum bounds, but timeouts are not synchronization mechanisms.
2.5 Process ownership
The harness may terminate only resources it launched or explicitly reserved.
Every launched process, container , account, database, browser profile, port, temporary file, and service
must be recorded in the cleanup manifest.
2.6 Reproducibility
Every certification must record enough information to reproduce the run:
source commit;
branch;
dirty working-tree state;
dependency lockfiles;
tool versions;
environment variables, with secrets redacted;
operating-system image;
container image digests;
adapter versions;
generated test versions;
model routing configuration;
run seed;
execution commands;
configuration hashes.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
3


<!-- SOURCE_PAGE: 4 -->

2.7 One final verdict
Each run produces one authoritative verdict.
Individual adapters may emit findings and component statuses, but they do not issue independent release
verdicts.
3. Supported Input Classes
The intake system must normalize all targets into a common CertificationTarget.
3.1 Source targets
local filesystem path;
Git repository URL;
GitHub repository and commit;
Git branch;
pull request;
uploaded archive;
monorepo subdirectory.
3.2 Runtime targets
public URL;
internal URL accessible through an execution node;
REST endpoint;
GraphQL endpoint;
WebSocket endpoint;
MCP endpoint;
container image;
Docker Compose project;
executable;
installer;
packaged Electron application;
Python package;
npm package;
Rust crate;
Go module;
SDK artifact.
3.3 Combined targets
The strongest certification mode accepts both source and runtime targets:
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
4


<!-- SOURCE_PAGE: 5 -->

source:
repository: https://example/repository.git
commit: abc123
runtime:
url: https://staging.example.com
deployment:
container_image: registry.example.com/app@sha256:...
This allows source analysis, build verification, deployed-environment verification, and artifact-to-source
traceability.
4. Certification Modes
4.1 Full certification
Runs discovery, build, static analysis, unit tests, integration tests, E2E tests, security checks, accessibility
checks, packaging tests, evidence verification, and verdict calculation.
4.2 Incremental certification
Runs only affected adapters and journeys based on:
changed files;
dependency graph;
prior certification result;
test-impact analysis;
risk policy.
Incremental certification cannot produce READY unless policy permits reuse of valid evidence from a prior
full certification.
4.3 Runtime-only certification
Tests a deployed application without source access.
Possible verdicts:
BLOCK
CONDITIONAL
READY_RUNTIME_ONLY
• 
• 
• 
• 
• 
• 
• 
• 
5


<!-- SOURCE_PAGE: 6 -->

Externally, READY_RUNTIME_ONLY should normally be represented as CONDITIONAL unless a product
policy explicitly allows runtime-only readiness.
4.4 Source-only certification
Inspects and builds source without validating the deployed runtime.
This cannot normally produce unrestricted READY.
4.5 Security-focused certification
Prioritizes:
dependency vulnerabilities;
authentication;
authorization;
secrets;
injection testing;
fuzzing;
security headers;
insecure configuration;
privilege boundaries.
4.6 Release-gate certification
Runs under deployment-pipeline authority and returns a machine-readable pass/fail decision.
5. High-Level Architecture
                         ┌─────────────────────────┐
                         │     Intake Gateway      │
                         │ repo · URL · artifact   │
                         └────────────┬────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │   Certification API     │
                         │ auth · policy · queue   │
                         └────────────┬────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │     Orchestrator        │
                         │ state machine · leases  │
                         └───────┬─────────┬───────┘
• 
• 
• 
• 
• 
• 
• 
• 
• 
6


<!-- SOURCE_PAGE: 7 -->

│         │
                   ┌─────────────▼──┐   ┌──▼────────────────┐
                   │ Discovery      │   │ Intelligence      │
                   │ Engine         │   │ Coordinator       │
                   └────────┬───────┘   └────────┬──────────┘
                            │                    │
                   ┌────────▼────────────────────▼──────────┐
                   │           Adapter Planner              │
                   │ stack selection · dependency graph     │
                   └─────────────────┬──────────────────────┘
                                     │
                    ┌────────────────▼────────────────┐
                    │       Isolated Run Harness      │
                    │ workspace · profiles · services│
                    └────────┬───────────────┬────────┘
                             │               │
              ┌──────────────▼─────┐   ┌────▼────────────────┐
              │ Adapter Workers    │   │ ShadowGlass /       │
              │ build/test/security│   │ Windows API / Mobile│
              └──────────────┬─────┘   └────┬────────────────┘
                             │               │
                    ┌────────▼───────────────▼────────┐
                    │       Evidence Collector        │
                    │ logs · screenshots · traces     │
                    └────────────────┬─────────────────┘
                                     │
                    ┌────────────────▼─────────────────┐
                    │ Finding Classification Engine    │
                    │ app · harness · env · dependency │
                    └────────────────┬─────────────────┘
                                     │
                    ┌────────────────▼─────────────────┐
                    │       Verdict Authority          │
                    │ BLOCK · CONDITIONAL · READY      │
                    └─────────┬───────────────┬────────┘
                              │               │
                    ┌─────────▼──────┐ ┌──────▼─────────────┐
                    │ Dashboard/API  │ │ Build Gate / Brain │
                    └────────────────┘ └────────────────────┘
7


<!-- SOURCE_PAGE: 8 -->

6. Major Platform Planes
6.1 Control plane
Responsible for:
intake;
authentication;
authorization;
tenant isolation;
target registration;
queue management;
policy selection;
run orchestration;
worker leasing;
cancellation;
retries;
verdict publication;
deployment-gate response.
6.2 Execution plane
Responsible for:
isolated workspaces;
repository checkout;
artifact retrieval;
dependency installation;
application launch;
test execution;
browser automation;
desktop automation;
mobile automation;
container orchestration;
resource cleanup.
6.3 Intelligence plane
Responsible for:
architecture inference;
missing-test generation;
test-plan generation;
failure classification;
harness repair;
defect deduplication;
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
8


<!-- SOURCE_PAGE: 9 -->

risk evaluation;
verdict review;
disagreement arbitration.
6.4 Evidence plane
Responsible for:
artifact storage;
log normalization;
screenshots;
video;
traces;
network captures;
coverage reports;
accessibility reports;
vulnerability reports;
evidence hashes;
chain-of-custody metadata.
6.5 Presentation plane
Responsible for:
live dashboard;
certification history;
finding review;
evidence inspection;
rerun controls;
policy management;
JSON and PDF reports;
release badges;
API and webhook output.
7. Recommended Technology Baseline
The design must not depend on one implementation language, but the control plane should use a stable,
strongly typed core.
7.1 Control-plane recommendation
Primary option: Python 3.12+ with FastAPI, Pydantic, SQLAlchemy, and Temporal or a durable internal state
machine.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
9


<!-- SOURCE_PAGE: 10 -->

Reasons:
strong integration with AI and test tooling;
mature process orchestration;
straightforward adapter development;
existing ECHO Python infrastructure;
broad SDK availability.
7.2 Dashboard
React or Next.js;
TypeScript strict mode;
server-sent events or WebSockets for live status;
accessible component system;
evidence viewer;
trace timeline;
filterable findings table.
7.3 Persistence
PostgreSQL for authoritative metadata;
Redis for transient coordination, rate limits, and worker heartbeats;
S3-compatible object storage for evidence;
optional ClickHouse or OpenSearch for high-volume logs and analytics.
7.4 Worker packaging
OCI containers for Linux stack adapters;
dedicated Windows worker service for Electron, packaged desktop applications, installers, and
Windows API automation;
dedicated mobile workers or device farm for Appium;
restricted network profiles per certification policy.
7.5 Queue and orchestration
Recommended priority:
Temporal for durable workflow execution;
PostgreSQL-backed internal state machine for initial implementation;
Redis queue only for worker dispatch, not authoritative workflow state.
The certification state must survive service restarts.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
1. 
2. 
3. 
10


<!-- SOURCE_PAGE: 11 -->

8. Repository Layout
echo-certification-forge/
├── README.md
├── SPEC.md
├── SECURITY.md
├── CONTRIBUTING.md
├── LICENSE
├── pyproject.toml
├── package.json
├── pnpm-workspace.yaml
├── docker-compose.dev.yml
├── Makefile
├── forge.ps1
├── forge.sh
│
├── apps/
│   ├── api/
│   │   ├── main.py
│   │   ├── routes/
│   │   ├── auth/
│   │   ├── schemas/
│   │   └── dependencies/
│   ├── orchestrator/
│   │   ├── workflows/
│   │   ├── state_machine/
│   │   ├── scheduling/
│   │   └── recovery/
│   ├── worker-linux/
│   ├── worker-windows/
│   ├── worker-mobile/
│   ├── dashboard/
│   └── cli/
│
├── packages/
│   ├── core/
│   │   ├── models/
│   │   ├── enums/
│   │   ├── errors/
│   │   └── policy/
│   ├── discovery/
│   ├── adapter-sdk/
│   ├── adapter-registry/
│   ├── harness/
│   ├── evidence/
11


<!-- SOURCE_PAGE: 12 -->

│   ├── verdict/
│   ├── intelligence/
│   ├── reporting/
│   ├── security/
│   ├── observability/
│   └── integrations/
│
├── adapters/
│   ├── python/
│   ├── javascript/
│   ├── typescript/
│   ├── web/
│   ├── electron/
│   ├── windows-desktop/
│   ├── mobile/
│   ├── api/
│   ├── go/
│   ├── rust/
│   ├── containers/
│   ├── compose/
│   ├── cli/
│   ├── library/
│   ├── mcp/
│   └── sdk/
│
├── policies/
│   ├── default.yaml
│   ├── release-strict.yaml
│   ├── security-critical.yaml
│   ├── runtime-only.yaml
│   └── adapter-minimums/
│
├── prompts/
│   ├── master-e2e-certification.md
│   ├── architecture-discovery.md
│   ├── missing-test-author.md
│   ├── failure-classifier.md
│   ├── harness-repair.md
│   ├── verdict-reviewer.md
│   └── report-writer.md
│
├── schemas/
│   ├── certification-target.schema.json
│   ├── discovery-manifest.schema.json
│   ├── execution-plan.schema.json
│   ├── finding.schema.json
12


<!-- SOURCE_PAGE: 13 -->

│   ├── evidence.schema.json
│   ├── verdict.schema.json
│   └── adapter-manifest.schema.json
│
├── migrations/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── contract/
│   ├── e2e/
│   ├── adversarial/
│   ├── fixtures/
│   └── golden-repositories/
│
├── infrastructure/
│   ├── docker/
│   ├── kubernetes/
│   ├── windows-service/
│   ├── terraform/
│   └── monitoring/
│
├── scripts/
│   ├── bootstrap/
│   ├── migration/
│   ├── local-dev/
│   └── release/
│
└── docs/
    ├── architecture/
    ├── adapter-authoring/
    ├── operations/
    ├── threat-model/
    ├── verdict-policy/
    └── product/
9. Core Domain Objects
9.1 CertificationRun
id: cert_01J...
target_id: target_01J...
tenant_id: tenant_01J...
status: EXECUTING
13


<!-- SOURCE_PAGE: 14 -->

verdict: null
mode: FULL
policy_id: release-strict
source_commit: abc123
requested_by: user_or_service
created_at: timestamp
started_at: timestamp
completed_at: null
execution_environment:
worker_id: worker-win-03
os: windows-11
architecture: amd64
image_digest: sha256:...
9.2 CertificationTarget
id: target_01J...
type: repository
source:
provider: github
repository: organization/project
ref: main
commit: abc123
runtime:
url: https://staging.example.com
secrets_profile: staging-readonly
metadata:
product: example-app
release_candidate: 2.4.0-rc3
9.3 DiscoveryManifest
languages:
- name: TypeScript
confidence: 0.99
evidence:
- package.json
- tsconfig.json
frameworks:
- name: Next.js
version_constraint: 15.x
confidence: 0.98
14


<!-- SOURCE_PAGE: 15 -->

application_types:
- type: web
confidence: 0.97
- type: api
confidence: 0.81
build_systems:
- pnpm
- next
test_frameworks:
- vitest
- playwright
entry_points:
- command: pnpm dev
purpose: development
- command: pnpm build
purpose: build
- command: pnpm start
purpose: production
services:
- name: web
- name: postgres
- name: redis
risk_signals:
- authentication
- payments
- file_upload
9.4 ExecutionPlan
The execution plan must be generated before adapters run.
stages:
- id: source_integrity
adapters:
- source-git-integrity
- id: dependency_install
adapters:
- javascript-pnpm-install
- id: static_verification
15


<!-- SOURCE_PAGE: 16 -->

adapters:
- typescript-compiler
- eslint
- secret-scanner
- id: test_execution
adapters:
- vitest
- playwright-web
- id: security
adapters:
- npm-audit
- web-security-headers
- auth-matrix
- id: verdict
adapters:
- finding-classifier
- verdict-authority
9.5 Finding
id: finding_01J...
run_id: cert_01J...
source_adapter: playwright-web
title: Anonymous user can access administrator export
severity: CRITICAL
category: AUTHORIZATION
classification: APPLICATION
confidence: 0.99
reproducible: true
status: OPEN
blocks_release: true
evidence_ids:
- evidence_01J...
reproduction:
preconditions:
- clean browser profile
steps:
- navigate to /admin/export
- observe HTTP 200
expected: redirect or HTTP 403
actual: data export downloaded
16


<!-- SOURCE_PAGE: 17 -->

9.6 EvidenceArtifact
id: evidence_01J...
run_id: cert_01J...
finding_id: finding_01J...
type: screenshot
path: runs/cert_01J/evidence/screenshots/admin-export.png
sha256: ...
created_at: timestamp
collector: shadowglass
redaction_status: COMPLETE
metadata:
viewport: 1440x900
browser: chromium
9.7 Verdict
run_id: cert_01J...
verdict: BLOCK
policy: release-strict
reasons:
- critical authorization defect
- required payment journey not completed
blocking_findings:
- finding_01J...
conditional_requirements: []
evidence_summary:
total_artifacts: 174
verified_hashes: 174
issued_at: timestamp
issued_by: verdict-authority-v1
review_lanes:
primary: BLOCK
verifier: BLOCK
swarm_consensus: BLOCK
10. Certification State Machine
CREATED
  ↓
QUEUED
17


<!-- SOURCE_PAGE: 18 -->

↓
ACQUIRING_TARGET
  ↓
DISCOVERING
  ↓
PLANNING
  ↓
PROVISIONING
  ↓
BUILDING
  ↓
STARTING_APPLICATION
  ↓
VERIFYING_READINESS
  ↓
EXECUTING_TESTS
  ↓
COLLECTING_EVIDENCE
  ↓
CLASSIFYING_FINDINGS
  ↓
CALCULATING_VERDICT
  ↓
FINALIZING_REPORT
  ↓
REGISTERING_RESULT
  ↓
COMPLETED
Exceptional states:
CANCEL_REQUESTED
CANCELLING
CANCELLED
RETRY_PENDING
HARNESS_REPAIR
ENVIRONMENT_RECOVERY
CLEANUP_PENDING
CLEANUP_FAILED
INFRASTRUCTURE_FAILURE
Every state transition must be persisted with:
prior state;
next state;
• 
• 
18


<!-- SOURCE_PAGE: 19 -->

timestamp;
triggering actor;
reason;
attempt number;
workflow version.
A service restart must resume the run from the last durable checkpoint.
11. Discovery Engine
11.1 Objective
Convert an unknown repository or runtime into a normalized architecture model with confidence scores
and evidence.
11.2 Discovery stages
Stage A: source inventory
Collect:
file tree;
file sizes;
language distribution;
binary files;
generated files;
lockfiles;
package manifests;
build scripts;
CI files;
Dockerfiles;
Compose files;
infrastructure files;
environment templates;
test files;
documentation;
entry points.
Stage B: deterministic detectors
Detectors must recognize:
Signal Inference
pyproject.toml Python project
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
19


<!-- SOURCE_PAGE: 20 -->

Signal Inference
pytest.ini pytest
package.json Node ecosystem
tsconfig.json TypeScript
next.config.* Next.js
electron-builder.* Electron packaging
Cargo.toml Rust
go.mod Go
docker-compose.* multi-service system
openapi.* OpenAPI service
mcp.json or MCP server codeMCP target
Android Gradle files Android
Xcode project iOS
tauri.conf.* Tauri desktop
*.sln or *.csproj .NET
pom.xml Maven/Java
build.gradle Gradle
CMakeLists.txt C/C++ CMake
Stage C: semantic architecture inspection
The intelligence layer reviews:
package scripts;
source imports;
route definitions;
service boundaries;
authentication flows;
database access;
external dependencies;
UI navigation;
privileged operations;
payment or financial logic;
data export;
file upload;
administrator functions.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
20


<!-- SOURCE_PAGE: 21 -->

Stage D: runtime probing
For URLs or running services:
TLS inspection;
DNS resolution;
redirect chain;
response headers;
robots and metadata;
HTML framework signals;
API endpoint discovery;
OpenAPI discovery;
WebSocket discovery;
authentication surface;
browser console events.
Stage E: confidence reconciliation
Each inference receives:
confidence score;
supporting evidence;
conflicting evidence;
source detector;
last verification time.
Low-confidence critical inferences must trigger additional inspection.
11.3 Discovery output requirements
The discovery engine must output:
application type;
language set;
framework set;
build system;
package manager;
test frameworks;
likely build command;
likely run command;
likely production command;
service dependency graph;
entry points;
testable user surfaces;
critical-risk features;
selected adapters;
unresolved questions.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
21


<!-- SOURCE_PAGE: 22 -->

11.4 Discovery acceptance tests
The golden repository suite must include:
Python CLI;
Python API;
Django web application;
React SPA;
Next.js full-stack app;
Electron application;
Go API;
Rust CLI;
Docker Compose application;
MCP server;
TypeScript SDK;
polyglot monorepo.
Acceptance threshold:
correct primary application type;
correct primary language;
correct build system;
correct package manager;
correct test framework where present;
no unsupported assumptions silently treated as facts;
all low-confidence critical discoveries marked unresolved.
12. Adapter Registry
12.1 Adapter philosophy
An adapter is a versioned, declarative capability package.
An adapter must not directly control the global certification verdict.
It emits:
capabilities;
prerequisites;
execution requests;
observations;
evidence;
findings;
health status.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
22


<!-- SOURCE_PAGE: 23 -->

12.2 Adapter manifest
id: python.pytest
version: 1.0.0
display_name: Python pytest Adapter
supported_targets:
- python
capabilities:
- test.unit
- test.integration
requires:
commands:
- python
files_any:
- pyproject.toml
- pytest.ini
execution:
default_timeout_seconds: 1800
network_policy: restricted
evidence_types:
- junit
- stdout
- stderr
- coverage
finding_categories:
- TEST_FAILURE
- COVERAGE_GAP
12.3 Adapter lifecycle
detect
→ validate_prerequisites
→ plan
→ provision
→ execute
→ observe
→ collect_evidence
→ normalize_findings
→ cleanup
23


<!-- SOURCE_PAGE: 24 -->

12.4 Adapter interface
classCertificationAdapter(Protocol):
manifest: AdapterManifest
asyncdefdetect(self, context: DiscoveryContext) ->DetectionResult:
...
asyncdefplan(self, context: PlanningContext) ->AdapterPlan:
...
asyncdefprovision(self, context: RunContext) ->ProvisionResult:
...
asyncdefexecute(self, context: RunContext) ->ExecutionResult:
...
asyncdefcollect(self, context: RunContext) ->EvidenceBundle:
...
asyncdefcleanup(self, context: RunContext) ->CleanupResult:
...
12.5 Mandatory adapter behaviors
Every adapter must:
produce structured output;
redact secrets;
honor cancellation;
enforce maximum runtime;
record command lines;
record tool versions;
register child processes;
register generated files;
avoid modifying source unless operating in a generated-test workspace;
emit deterministic exit categories;
produce cleanup entries;
identify unsupported conditions.
12.6 Exit categories
Adapters return one of:
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
24


<!-- SOURCE_PAGE: 25 -->

PASS
FAIL_APPLICATION
FAIL_HARNESS
FAIL_ENVIRONMENT
FAIL_DATA
FAIL_EXTERNAL_DEPENDENCY
UNSUPPORTED
INCONCLUSIVE
CANCELLED
This initial category may later be revised by the intelligence classifier .
13. Stack Adapter Requirements
13.1 Python adapter family
Capabilities:
interpreter detection;
virtual-environment creation;
dependency installation;
lockfile verification;
compileall;
pytest;
coverage;
pip check;
Ruff;
mypy;
Bandit;
packaging validation;
wheel build;
import smoke tests.
Minimum sequence:
detect Python version
→ create isolated virtual environment
→ install locked dependencies
→ verify package consistency
→ compile source
→ run lint
→ run typing
→ run security checks
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
25


<!-- SOURCE_PAGE: 26 -->

→ run tests
→ build package
→ install built package
→ execute import/CLI smoke
Potential blockers:
syntax failure;
dependency conflict;
failing required tests;
critical Bandit issue with credible exploit path;
built package cannot be installed;
package imports from source tree but not installed artifact.
13.2 JavaScript and TypeScript adapter family
Capabilities:
npm, pnpm, Yarn, or Bun detection;
frozen-lockfile installation;
TypeScript compilation;
ESLint;
Jest;
Vitest;
Playwright;
package audit;
package build;
production start test;
published-package validation.
Required protections:
no silent lockfile rewriting;
no lifecycle scripts outside policy;
package-manager cache isolation;
generated test workspace separate from application source.
13.3 Web adapter family
Capabilities:
route discovery;
browser smoke;
critical user journeys;
responsive viewports;
keyboard navigation;
axe accessibility;
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
26


<!-- SOURCE_PAGE: 27 -->

Lighthouse;
CSP and security headers;
cookie policy;
TLS checks;
broken-link checks;
browser console and network failure capture;
authentication and authorization matrix;
session expiration;
form validation;
upload/download verification.
Required viewports:
desktop standard;
desktop wide;
tablet;
mobile narrow;
mobile standard.
The policy may add application-specific viewports.
13.4 Electron and desktop adapter family
Capabilities:
Electron development launch;
_electron Playwright automation;
production package build;
packaged executable launch;
clean-profile run;
installer validation;
application window discovery;
Windows API interaction;
menu, tray, dialog, and file-picker testing;
crash and hang detection;
uninstall behavior;
update mechanism tests;
registry and filesystem impact review.
Required distinction:
development application behavior;
packaged application behavior;
installed application behavior .
Passing development-mode tests does not prove the packaged application is valid.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
1. 
2. 
3. 
27


<!-- SOURCE_PAGE: 28 -->

13.5 Mobile adapter family
Capabilities:
Android emulator/device;
iOS simulator/device where available;
Appium;
install;
launch;
permission flows;
rotation;
background/foreground;
deep links;
network loss;
upgrade path;
uninstall and data cleanup.
The adapter must record:
device model;
OS version;
screen resolution;
app package identifier;
build artifact hash.
13.6 API adapter family
Capabilities:
OpenAPI or GraphQL schema inspection;
endpoint discovery;
schema validation;
positive and negative tests;
authentication matrix;
authorization matrix;
input-boundary tests;
rate-limit checks;
idempotency tests;
fuzzing;
pagination;
concurrency;
error-schema validation;
state-transition tests.
Critical authorization tests must validate ownership boundaries:
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
28


<!-- SOURCE_PAGE: 29 -->

user A cannot read user B
user A cannot modify user B
standard user cannot perform administrator action
anonymous user cannot access protected data
revoked token cannot continue operating
13.7 Go adapter family
Capabilities:
go mod download;
go mod verify;
go build;
go test;
race detector where feasible;
go vet;
staticcheck when configured;
govulncheck;
binary smoke test.
13.8 Rust adapter family
Capabilities:
toolchain detection;
cargo check;
cargo build;
cargo test;
cargo clippy;
formatting validation;
cargo audit;
release build;
installed binary or library smoke test.
13.9 Container adapter family
Capabilities:
Dockerfile validation;
image build;
image digest capture;
vulnerability scan;
non-root validation;
health-check validation;
exposed-port analysis;
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
29


<!-- SOURCE_PAGE: 30 -->

secret leakage review;
image-size reporting;
startup and shutdown behavior;
read-only filesystem mode where supported.
13.10 Multi-service and Compose adapter family
Capabilities:
dependency graph;
isolated Compose project name;
dynamic port allocation;
service readiness;
health checks;
migration execution;
smoke tests;
degraded dependency behavior;
teardown;
volume cleanup.
The harness must never issue broad commands such as:
docker stop $(docker ps -q)
docker system prune -af
taskkill /F /IM node.exe
It must target only registered resources.
13.11 CLI adapter family
Capabilities:
executable discovery;
--help;
--version;
expected exit codes;
invalid argument behavior;
stdin/stdout/stderr contracts;
JSON output validation;
signal handling;
configuration precedence;
filesystem side effects;
shell compatibility.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
30


<!-- SOURCE_PAGE: 31 -->

13.12 Library and SDK adapter family
Capabilities:
clean consumer project generation;
package installation from built artifact;
documented import examples;
API-surface validation;
semantic-version comparison;
backward compatibility;
typed declarations;
example execution;
error behavior;
authentication handling.
13.13 MCP adapter family
Capabilities:
transport detection;
protocol initialization;
capability negotiation;
tool listing;
resource listing;
prompt listing;
schema validation;
tool invocation;
invalid request behavior;
timeout behavior;
authorization scopes;
write-tier restrictions;
SDK capability gates;
response-shape validation;
concurrency;
cancellation;
cleanup.
MCP tier gates should include:
SEARCH
READ
WRITE
SDK_INVOKE
ADMIN
The forge must verify that lower-tier credentials cannot invoke higher-tier operations.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
31


<!-- SOURCE_PAGE: 32 -->

14. Isolated Harness
14.1 Run workspace
Every run receives a unique workspace:
runs/<run-id>/
├── source/
├── generated-tests/
├── build/
├── runtime/
├── profiles/
├── databases/
├── accounts/
├── logs/
├── evidence/
├── reports/
├── manifests/
└── cleanup/
14.2 Isolation levels
Level 1: process isolation
Used for low-risk local tooling.
Level 2: container isolation
Default for Linux-compatible applications.
Level 3: virtual-machine isolation
Required for:
untrusted native executables;
installers;
kernel-sensitive software;
privileged operations;
malware-risk targets;
high-assurance desktop testing.
• 
• 
• 
• 
• 
• 
32


<!-- SOURCE_PAGE: 33 -->

Level 4: dedicated physical or ephemeral device
Required for selected mobile and hardware-integrated certification.
14.3 Resource allocator
The harness allocates:
ports;
workspace;
CPU quota;
memory quota;
disk quota;
container namespace;
network namespace;
browser profile;
database schema or instance;
application account;
temporary email address;
test phone number where supported.
14.4 Cleanup manifest
run_id: cert_01J...
resources:
- type: process
id: 18444
ownership_token: ...
cleanup_action: terminate_process_tree
- type: docker_compose_project
id: cert_01J
cleanup_action: compose_down_with_volumes
- type: directory
id: runs/cert_01J/runtime
cleanup_action: remove_directory
- type: database
id: cert_01J
cleanup_action: drop_database
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
33


<!-- SOURCE_PAGE: 34 -->

14.5 Resource ownership verification
Before terminating a process, verify:
process ID;
launch timestamp;
executable path;
parent process;
ownership token;
run ID association.
PID alone is insufficient because process identifiers may be reused.
14.6 Readiness subsystem
Readiness probes must support:
HTTP predicate;
TCP connection;
process state;
log regex;
file existence;
database query;
DOM selector;
desktop window;
MCP handshake;
custom adapter probe.
Example:
readiness:
type: http
url: http://127.0.0.1:${PORT}/health
success:
status: 200
json_path: $.status
equals: ready
timeout_seconds: 90
poll_interval_ms: 250
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
34


<!-- SOURCE_PAGE: 35 -->

15. Generated Test Infrastructure
15.1 Purpose
When test coverage is absent or insufficient, the intelligence plane creates tests in a separate generated-
test workspace.
It must not claim the application is untestable solely because developers failed to create tests.
15.2 Test generation inputs
discovery manifest;
source architecture;
route map;
API schema;
UI component map;
product documentation;
existing tests;
risk features;
prior defects;
deployment configuration.
15.3 Test generation outputs
test plan;
generated source files;
fixtures;
data factories;
environment configuration;
expected observations;
required evidence list;
cleanup steps.
15.4 Generated test rules
Generated tests must:
be reviewable;
include a provenance record;
identify the generating model and prompt version;
remain separate from application source by default;
avoid weakening application configuration;
avoid mocking the exact behavior being certified;
assert outcomes, not implementation trivia;
be executed against the real application.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
35


<!-- SOURCE_PAGE: 36 -->

15.5 Generated-test confidence
Generated tests receive confidence grades:
HIGH
MEDIUM
LOW
Low-confidence tests cannot independently justify READY.
15.6 Harness repair boundary
The intelligence layer may repair:
incorrect selectors;
invalid test setup;
missing fixture generation;
bad launch commands;
environment-path errors;
test cleanup defects;
race conditions caused by harness synchronization.
It may not silently modify the application to make a failing test pass.
Application patches must be separately proposed and recorded as remediation artifacts.
16. Intelligence Layer
16.1 Lane structure
The model fleet should use independent roles rather than one model performing every task.
Discovery lane
Determines architecture, risk surfaces, user journeys, and missing information.
Test-author lane
Builds missing tests and test infrastructure.
Execution analyst lane
Reviews raw execution output and identifies anomalous behavior .
• 
• 
• 
• 
• 
• 
• 
36


<!-- SOURCE_PAGE: 37 -->

Failure classifier lane
Classifies failures as:
application;
harness;
environment;
test data;
external dependency;
policy;
inconclusive.
Harness verifier lane
Attempts to reproduce and repair suspected harness failures.
Security reviewer lane
Reviews authentication, authorization, injection, secrets, dependency, and configuration risk.
Release verifier lane
Independently reviews the evidence and proposed verdict.
Swarm judgment lane
Resolves difficult disagreements and ambiguous release risk.
16.2 Model assignment
Model names must be configuration, not hardcoded platform assumptions.
Example:
lanes:
discovery:
primary: fable
verifier: sol
test_author:
primary: codex
verifier: sol
failure_classifier:
primary: sol
verifier: fable
• 
• 
• 
• 
• 
• 
• 
37


<!-- SOURCE_PAGE: 38 -->

release_authority:
primary: sol
verifier: fable
escalation: swarm
16.3 Structured model responses
Models must return schema-validated JSON.
Free-form prose cannot directly drive privileged execution.
Example:
{
"classification": "FAIL_HARNESS",
"confidence": 0.91,
"reasoning_summary": "The selector references a generated class name...",
"recommended_action": "replace_selector",
"allowed_scope": ["generated-tests/login.spec.ts"],
"evidence_ids": ["evidence_123"]
}
16.4 Execution safety
AI-generated commands must pass through:
schema validation;
policy validation;
path allowlist;
command allowlist or risk classifier;
secret redaction;
resource-limit injection;
execution sandbox.
16.5 Disagreement handling
When model lanes disagree:
gather missing evidence;
rerun the smallest relevant test;
request independent classification;
compare evidence references;
escalate to swarm judgment;
• 
• 
• 
• 
• 
• 
• 
1. 
2. 
3. 
4. 
5. 
38


<!-- SOURCE_PAGE: 39 -->

prefer the more restrictive verdict if uncertainty remains.
16.6 Intelligence audit record
Record:
model identifier;
provider;
model version;
prompt version;
input evidence IDs;
output schema;
confidence;
token usage;
latency;
retry history;
final accepted decision.
17. Evidence System
17.1 Evidence categories
source inventory;
build logs;
compiler output;
dependency reports;
static-analysis reports;
test output;
screenshots;
video;
browser console;
browser network trace;
desktop window state;
process state;
container logs;
database state;
API requests and responses;
accessibility reports;
performance profiles;
security scans;
coverage;
generated tests;
cleanup results.
6. 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
39


<!-- SOURCE_PAGE: 40 -->

17.2 Evidence directory
evidence/
├── source/
├── build/
├── static-analysis/
├── tests/
├── browser/
│   ├── screenshots/
│   ├── video/
│   ├── console/
│   └── traces/
├── desktop/
├── api/
├── security/
├── accessibility/
├── performance/
├── cleanup/
└── index.json
17.3 Evidence index
Each artifact must include:
artifact ID;
run ID;
originating adapter;
timestamp;
MIME type;
size;
SHA-256;
redaction status;
related finding;
source command;
source process;
retention policy.
17.4 Tamper evidence
At finalization:
hash every evidence artifact;
generate a sorted evidence manifest;
hash the manifest;
sign the manifest with the forge signing key;
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
1. 
2. 
3. 
4. 
40


<!-- SOURCE_PAGE: 41 -->

store signature metadata;
include manifest hash in the verdict.
17.5 Redaction
Redaction must detect:
access tokens;
API keys;
passwords;
cookies;
authorization headers;
private keys;
connection strings;
personal data identified by policy.
Original unredacted evidence should not be retained unless explicitly required and protected by a higher-
security policy.
17.6 Evidence sufficiency
A test result is insufficient when:
no command record exists;
no artifact hash exists;
output was truncated without a full artifact;
the target version cannot be identified;
the test ran against a different artifact;
the environment cannot be identified;
the result cannot be reproduced.
18. Failure Classification
18.1 Classes
APPLICATION
The product behavior is defective.
Examples:
crash;
wrong output;
unauthorized access;
5. 
6. 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
41


<!-- SOURCE_PAGE: 42 -->

broken user journey;
invalid package;
application memory leak.
HARNESS
The certification infrastructure is defective.
Examples:
incorrect selector;
wrong launch argument;
fixture creation failure;
harness race condition;
unsupported test assumption.
ENVIRONMENT
The execution node or environment prevented valid testing.
Examples:
missing system dependency;
insufficient disk;
unavailable emulator;
worker corruption;
certificate store failure unrelated to target.
DATA
Required test data was missing, malformed, or invalid.
EXTERNAL_DEPENDENCY
A third-party service failed or was unavailable.
POLICY
A policy requirement could not be satisfied.
INCONCLUSIVE
Evidence does not support a reliable classification.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
42


<!-- SOURCE_PAGE: 43 -->

18.2 Classification workflow
failure observed
→ capture raw evidence
→ deterministic signature matching
→ primary model classification
→ verifier classification
→ targeted rerun
→ final classification
18.3 Retry policy
Retries are permitted only when:
failure is classified as harness, environment, data, external dependency, or inconclusive;
retry conditions differ materially;
maximum attempts are enforced;
each retry is recorded.
Application failures should not be repeatedly rerun solely to obtain a passing result.
18.4 Flaky behavior
A test is flaky when identical conditions produce inconsistent outcomes.
Flakiness is itself a release risk.
A flaky critical-path test should normally block release until the underlying instability is resolved or explicitly
waived by policy.
19. Finding Severity
19.1 Critical
Examples:
remote code execution;
authentication bypass;
cross-tenant data access;
destructive data corruption;
secret disclosure;
installer or updater compromise;
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
43


<!-- SOURCE_PAGE: 44 -->

application unusable for primary purpose.
Default effect: BLOCK.
19.2 High
Examples:
major user journey fails;
privilege escalation;
persistent crash;
data loss under normal operation;
broken production package;
severe accessibility barrier in required workflow.
Default effect: BLOCK.
19.3 Medium
Examples:
secondary workflow defect;
recoverable functional error;
material usability defect;
significant performance degradation;
incomplete error handling.
Default effect: policy-dependent.
19.4 Low
Examples:
cosmetic issue;
minor documentation mismatch;
noncritical warning;
low-impact accessibility issue.
Default effect: does not independently block.
19.5 Informational
Observation without confirmed defect.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
44


<!-- SOURCE_PAGE: 45 -->

20. Verdict Engine
20.1 Verdict meanings
BLOCK
The application must not be released.
Issued when:
critical or blocking high-severity defect exists;
required certification stage failed;
application could not be built;
application could not be launched;
primary user journey failed;
evidence integrity failed;
target identity is uncertain;
cleanup risk remains;
critical verification is inconclusive;
required security gate failed.
CONDITIONAL
Release may proceed only under explicitly documented conditions.
Issued when:
only accepted noncritical findings remain;
an external dependency prevented a noncritical verification;
runtime-only or source-only certification lacks full scope;
a temporary waiver exists;
a limited release mode mitigates the defect;
evidence is sufficient for restricted use but not unrestricted readiness.
Every conditional verdict must include:
exact conditions;
owner;
expiration;
prohibited deployment scope;
required follow-up certification.
READY
The tested artifact is approved under the specified policy and scope.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
45


<!-- SOURCE_PAGE: 46 -->

READY applies only to:
the exact commit;
the exact built artifact;
the exact dependency state;
the exact certification policy;
the recorded deployment class.
Any material artifact change invalidates the verdict.
20.2 Hard blocking rules
hard_blocks:
- critical_findings > 0
- unresolved_high_findings > 0
- build_status != PASS
- primary_journey_status != PASS
- evidence_manifest_valid != true
- cleanup_status not in [PASS, ACCEPTED]
- target_identity_verified != true
- required_adapter_inconclusive == true
20.3 Policy-driven conditions
conditional_rules:
- medium_findings <= 3
- accessibility_score >= 90
- coverage_line >= 80
- dependency_high_vulnerabilities == 0
- performance_regression_percent <= 10
These are examples. Policy values must be configuration.
20.4 Verdict calculation stages
validate evidence integrity;
validate target identity;
enforce hard blockers;
calculate policy gates;
evaluate unresolved uncertainty;
generate proposed verdict;
independent verifier review;
swarm escalation if required;
sign and publish final verdict.
• 
• 
• 
• 
• 
1. 
2. 
3. 
4. 
5. 
6. 
7. 
8. 
9. 
46


<!-- SOURCE_PAGE: 47 -->

20.5 Waivers
Waivers must never silently convert failures into passes.
A waiver record requires:
finding ID;
approver;
reason;
scope;
expiration;
compensating control;
affected release;
required remediation.
A waived blocking finding results in CONDITIONAL, not unrestricted READY, unless an explicit high-
authority policy states otherwise.
21. Critical Journey Generation
21.1 Journey sources
Critical journeys are derived from:
documentation;
routes;
UI navigation;
API schemas;
application roles;
analytics definitions;
existing tests;
source inspection;
deployment purpose;
user-supplied requirements.
21.2 Standard web journeys
Where applicable:
anonymous landing;
account creation;
login;
logout;
password reset;
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
47


<!-- SOURCE_PAGE: 48 -->

profile modification;
primary create/read/update/delete flow;
administrator flow;
payment flow;
file upload;
export;
session expiration;
permission denial.
21.3 Journey record
id: journey.authentication.login
criticality: REQUIRED
actors:
- standard_user
preconditions:
- verified test account
steps:
- open login page
- submit valid credentials
- await authenticated navigation state
assertions:
- session established
- protected route accessible
- no console errors
evidence:
- screenshot
- network trace
- session-state record
21.4 Journey completeness
The forge must identify untested critical capabilities and create a coverage-gap finding.
A passing test suite with untested primary behavior cannot produce READY.
22. Security Verification
22.1 Source security
secret scanning;
dependency vulnerability scanning;
insecure API usage;
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
48


<!-- SOURCE_PAGE: 49 -->

dangerous deserialization;
command execution;
path traversal;
weak cryptography;
debug configuration;
production secret exposure.
22.2 Runtime security
TLS configuration;
security headers;
cookie flags;
authentication;
authorization;
session management;
CORS;
CSRF;
rate limits;
input validation;
error leakage;
file upload controls.
22.3 Infrastructure security
container user;
privileged mode;
host mounts;
writable root filesystem;
exposed management ports;
network policy;
secret injection;
image provenance.
22.4 Forge self-protection
Targets must be treated as hostile.
Controls include:
sandbox execution;
restricted outbound networking;
no host credential exposure;
short-lived credentials;
worker reimaging;
execution quotas;
syscall restrictions where available;
untrusted artifact scanning;
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
49


<!-- SOURCE_PAGE: 50 -->

signed worker binaries;
control-plane separation.
23. Accessibility Verification
Required checks for user-facing applications:
automated axe scan;
keyboard-only navigation;
focus visibility;
focus order;
form labels;
error association;
color contrast;
landmark structure;
accessible names;
modal focus trapping;
screen-size behavior .
Automated tools do not establish complete accessibility compliance.
Critical user journeys must include selected manual or intelligent semantic review.
24. Performance and Reliability
24.1 Performance checks
application startup;
page load;
API latency;
bundle size;
memory consumption;
CPU behavior;
database query count where observable;
throughput;
regression against baseline.
24.2 Reliability checks
restart behavior;
service dependency loss;
network interruption;
invalid configuration;
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
50


<!-- SOURCE_PAGE: 51 -->

empty database;
corrupted user input;
repeated execution;
concurrent operations;
cleanup after failure.
24.3 Baselines
Baselines must be tied to:
prior certified release;
hardware class;
environment;
dataset;
test scenario.
Performance comparisons across materially different environments must be labeled inconclusive.
25. Reporting
25.1 Human report structure
certification identity;
final verdict;
scope;
target identity;
executive summary;
blocking findings;
conditional requirements;
test coverage;
security results;
accessibility results;
performance results;
environment details;
evidence index;
reproduction commands;
cleanup status;
model review record;
signature and manifest hash.
25.2 Machine-readable report
{
"schema_version": "1.0",
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
1. 
2. 
3. 
4. 
5. 
6. 
7. 
8. 
9. 
10. 
11. 
12. 
13. 
14. 
15. 
16. 
17. 
51


<!-- SOURCE_PAGE: 52 -->

"run_id": "cert_01J...",
"verdict": "BLOCK",
"target": {
"repository": "organization/project",
"commit": "abc123",
"artifact_sha256": "..."
},
"blocking_findings": [],
"conditional_requirements": [],
"report_url": "https://cert.echo-op.com/runs/cert_01J...",
"evidence_manifest_sha256": "...",
"issued_at": "..."
}
25.3 Release badge
Badge states:
Certification: BLOCKED
Certification: CONDITIONAL
Certification: READY
Certification: EXPIRED
Certification: SUPERSEDED
25.4 Build-log and brain registration
Each completed certification must register:
run ID;
target;
commit;
verdict;
findings summary;
evidence manifest;
adapters used;
generated tests;
execution environment;
model judgment summary;
report location;
rerun command.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
52


<!-- SOURCE_PAGE: 53 -->

26. Dashboard Requirements
26.1 Main views
Certification queue
queued;
running;
blocked;
awaiting resources;
completed;
cancelled.
Live run view
current state;
stage timeline;
active adapter;
worker;
elapsed runtime;
resource use;
live normalized logs;
current findings;
screenshots;
cancellation control.
Verdict view
final verdict;
scope;
blocking defects;
conditional requirements;
evidence sufficiency;
model consensus;
signed manifest.
Finding view
severity;
classification;
reproduction;
expected behavior;
actual behavior;
evidence;
related findings;
history;
waiver state.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
53


<!-- SOURCE_PAGE: 54 -->

Evidence explorer
artifact preview;
hash verification;
source adapter;
related command;
related test;
download permissions;
redaction status.
Adapter registry
installed adapters;
versions;
health;
supported capabilities;
policy approval;
test status.
Policy management
required stages;
severity gates;
coverage thresholds;
security thresholds;
timeout limits;
allowed waivers;
retention.
26.2 Dashboard security
tenant isolation;
role-based access;
signed URLs for evidence;
evidence redaction;
immutable verdict history;
audit log;
protected administrative actions.
27. API Surface
27.1 Certification creation
POST /v1/certifications
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
54


<!-- SOURCE_PAGE: 55 -->

{
"target": {
"type": "repository",
"repository": "https://...",
"ref": "main"
},
"mode": "FULL",
"policy": "release-strict"
}
27.2 Certification status
GET /v1/certifications/{run_id}
27.3 Evidence
GET /v1/certifications/{run_id}/evidence
27.4 Findings
GET /v1/certifications/{run_id}/findings
27.5 Cancellation
POST /v1/certifications/{run_id}/cancel
27.6 Rerun
POST /v1/certifications/{run_id}/rerun
Rerun options:
{
"scope": "FAILED_ONLY",
"reuse_valid_evidence": true,
55


<!-- SOURCE_PAGE: 56 -->

"policy": "release-strict"
}
27.7 Release gate
POST /v1/release-gates/evaluate
Response:
{
"allowed": false,
"verdict": "BLOCK",
"run_id": "cert_01J...",
"reason": "Critical authorization defect"
}
28. Command-Line Interface
Primary command:
echo-cert certify <target>
Examples:
echo-cert certify .
echo-cert certify https://github.com/org/repo
echo-cert certify https://staging.example.com
echo-cert certify image://registry.example.com/app:2.4.0
echo-cert certify mcp://localhost:8080
Required commands:
echo-cert discover
echo-cert certify
echo-cert status
echo-cert findings
echo-cert evidence
echo-cert report
echo-cert rerun
56


<!-- SOURCE_PAGE: 57 -->

echo-cert cancel
echo-cert adapters
echo-cert policies
echo-cert verify-report
A completed run must output one reproducible rerun command.
29. Autonomous Queue and Release Gate
29.1 Event sources
Certification can be triggered by:
Git push;
pull request;
release candidate;
build completion;
container publication;
deployment to staging;
scheduled re-certification;
manual request;
API call;
ECHO build registration.
29.2 Queue priorities
P0 emergency security release
P1 production release candidate
P2 pull request
P3 scheduled certification
P4 exploratory certification
29.3 Deduplication
Runs may be deduplicated when all are identical:
source commit;
artifact digest;
policy;
adapter versions;
environment profile;
secrets profile version;
generated-test revision.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
57


<!-- SOURCE_PAGE: 58 -->

29.4 Deployment gate
Production deployment requires:
verdict == READY
AND artifact_digest == certified_artifact_digest
AND certification_not_expired
AND certification_not_revoked
AND policy == required_release_policy
29.5 Certification invalidation
A certification becomes invalid when:
artifact changes;
dependencies change;
critical vulnerability is newly identified;
policy changes materially;
environment target changes beyond approved scope;
evidence integrity fails;
verdict is revoked.
30. Phase-Gated Build Methodology
Every phase must end with:
working code;
automated tests;
real acceptance scenario;
evidence artifacts;
Git tag or immutable commit;
phase certification by the forge’s current capabilities.
No phase is complete because files were created.
31. Phase P0 — Foundation and Discovery
Objective
Create the repository, core schemas, CLI, API skeleton, state machine, target acquisition, and deterministic
discovery engine.
• 
• 
• 
• 
• 
• 
• 
1. 
2. 
3. 
4. 
5. 
6. 
58


<!-- SOURCE_PAGE: 59 -->

Deliverables
repository structure;
SPEC.md;
common domain models;
certification run IDs;
target acquisition;
Git checkout;
source inventory;
deterministic stack detectors;
discovery manifest;
initial CLI;
initial API;
PostgreSQL schema;
evidence directory initialization.
Required implementation tasks
define JSON schemas;
implement target normalization;
implement repository checkout;
capture commit and dirty state;
build file inventory;
implement language detectors;
implement framework detectors;
implement application-type inference;
implement confidence scoring;
persist discovery results;
expose discovery through CLI and API.
P0 acceptance repositories
Python CLI;
TypeScript web app;
Electron app;
Go API;
Rust CLI;
Compose multi-service app;
MCP server;
polyglot monorepo.
P0 exit gate
The command:
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
1. 
2. 
3. 
4. 
5. 
6. 
7. 
8. 
9. 
10. 
11. 
• 
• 
• 
• 
• 
• 
• 
• 
59


<!-- SOURCE_PAGE: 60 -->

echo-cert discover <target>
must produce a schema-valid discovery manifest containing correct primary stack, application type, build
system, test frameworks, and entry points for the golden repository suite.
32. Phase P1 — Adapter Registry
Objective
Create the adapter SDK, registry, planner , and initial stack adapters.
Initial mandatory adapters
source integrity;
Python compile;
pytest;
pip check;
Ruff;
mypy;
Bandit;
npm/pnpm install;
TypeScript compile;
ESLint;
Jest/Vitest;
Playwright web;
npm audit;
Go build/test/vet;
Rust build/test/clippy;
Docker build;
Compose startup;
API schema and smoke;
MCP handshake.
Required implementation tasks
define adapter manifest;
implement adapter discovery;
implement version resolution;
implement prerequisite validation;
implement adapter planner;
implement command runner;
implement normalized adapter results;
implement adapter contract tests;
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
1. 
2. 
3. 
4. 
5. 
6. 
7. 
8. 
60


<!-- SOURCE_PAGE: 61 -->

add adapter health command;
create adapter authoring documentation.
P1 acceptance test
For each golden repository:
select correct adapters;
reject irrelevant adapters;
execute adapter lifecycle;
produce structured results;
capture commands and tool versions;
create cleanup entries;
preserve source integrity.
P1 exit gate
At least one representative target from every initial stack must complete deterministic build and test
execution through the common adapter interface.
33. Phase P2 — Isolated Harness
Objective
Provide safe, reproducible, isolated application execution.
Deliverables
run workspace manager;
port allocator;
process registry;
container namespace;
disposable browser profiles;
test databases;
account fixture manager;
readiness probes;
cancellation;
cleanup engine;
Windows worker foundation.
Required implementation tasks
create ownership tokens;
register process trees;
9. 
10. 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
1. 
2. 
61


<!-- SOURCE_PAGE: 62 -->

implement process-safe termination;
implement dynamic port allocation;
implement environment redaction;
implement container isolation;
implement browser-profile isolation;
implement database lifecycle;
implement account lifecycle;
implement observable readiness;
implement failure-safe cleanup;
implement cleanup verification.
P2 adversarial acceptance tests
unrelated Node process remains alive;
unrelated browser remains alive;
unrelated Docker project remains intact;
cancelled run cleans its own resources;
crashed worker is recovered;
reused PID is not terminated;
failed Compose startup is cleaned;
locked file produces cleanup failure finding;
no fixed sleep is required for readiness.
P2 exit gate
The harness must run multiple certifications concurrently without resource collision and without
terminating or modifying unrelated resources.
34. Phase P3 — Evidence, Classification, and
Verdict
Objective
Create the authoritative evidence chain and verdict engine.
Deliverables
evidence collector;
evidence index;
hashing;
redaction;
finding model;
severity normalization;
3. 
4. 
5. 
6. 
7. 
8. 
9. 
10. 
11. 
12. 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
62


<!-- SOURCE_PAGE: 63 -->

failure classification;
verdict policy;
signed report;
JSON output.
Required implementation tasks
normalize logs;
store full artifacts;
compute SHA-256;
implement evidence relationships;
create finding normalization;
implement classification workflow;
implement retry constraints;
implement hard-block rules;
implement conditional rules;
implement waiver records;
implement manifest signing;
implement report verification command.
P3 acceptance scenarios
Scenario A: known application defect
Expected: BLOCK.
Scenario B: broken harness selector
Expected:
classify as harness;
repair generated test;
rerun;
no false application defect.
Scenario C: missing external dependency
Expected:
classify external dependency;
preserve evidence;
apply policy;
produce CONDITIONAL or BLOCK.
• 
• 
• 
• 
1. 
2. 
3. 
4. 
5. 
6. 
7. 
8. 
9. 
10. 
11. 
12. 
• 
• 
• 
• 
• 
• 
• 
• 
63


<!-- SOURCE_PAGE: 64 -->

Scenario D: evidence tampering
Expected:
manifest verification fails;
verdict invalidated;
release blocked.
P3 exit gate
The same evidence set must always produce the same deterministic policy result, subject to explicitly
versioned intelligence judgments.
35. Phase P4 — Intelligence Layer
Objective
Enable autonomous architecture reasoning, test generation, harness repair , failure classification, and
independent verdict review.
Deliverables
lane router;
prompt registry;
model-provider abstraction;
structured response validator;
test-generation system;
harness repair system;
classification arbitration;
swarm escalation;
intelligence audit records.
Required implementation tasks
define lane contracts;
define model routing configuration;
version prompts;
require evidence references;
validate JSON output;
restrict generated command execution;
implement generated-test workspace;
implement test provenance;
implement verifier lane;
implement disagreement escalation;
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
1. 
2. 
3. 
4. 
5. 
6. 
7. 
8. 
9. 
10. 
64


<!-- SOURCE_PAGE: 65 -->

implement confidence thresholds;
implement cost and token controls.
P4 acceptance scenarios
repository with no tests;
repository with misleading tests;
incorrect launch command;
flaky UI selector;
ambiguous application/environment failure;
missing critical authorization test;
conflicting model verdicts.
P4 exit gate
The intelligence layer must create and execute missing tests, repair harness-only defects, and preserve real
application failures without modifying application source.
36. Phase P5 — Dashboard and Reporting
Objective
Expose certification operations and evidence through cert.echo-op.com.
Deliverables
authentication;
certification queue;
live run timeline;
findings;
evidence explorer;
verdict view;
reports;
adapter status;
policy view;
audit log.
Required implementation tasks
build dashboard application;
implement live event stream;
implement evidence previews;
implement finding filtering;
implement report rendering;
11. 
12. 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
1. 
2. 
3. 
4. 
5. 
65


<!-- SOURCE_PAGE: 66 -->

implement signed report verification;
implement role-based access;
implement tenant separation;
implement run cancellation;
implement rerun controls.
P5 acceptance test
A user must be able to:
submit a target;
observe discovery;
observe adapter execution;
inspect live findings;
inspect screenshots and logs;
receive one verdict;
verify the evidence manifest;
launch a rerun.
37. Phase P6 — Autonomous Queue and
Deployment Gate
Objective
Make certification mandatory in the release process.
Deliverables
Git provider integration;
build webhook;
container registry webhook;
queue priorities;
run deduplication;
deployment gate;
certification expiration;
revocation;
release status checks.
Required implementation tasks
receive source-control events;
map events to certification targets;
verify webhook signatures;
6. 
7. 
8. 
9. 
10. 
1. 
2. 
3. 
4. 
5. 
6. 
7. 
8. 
• 
• 
• 
• 
• 
• 
• 
• 
• 
1. 
2. 
3. 
66


<!-- SOURCE_PAGE: 67 -->

deduplicate runs;
attach certification to commit;
attach certification to artifact digest;
return deployment decision;
block mismatched artifacts;
expire or revoke verdicts;
register results with ECHO build systems.
P6 acceptance test
A production deployment using an uncertified artifact must fail.
A deployment using a different digest from the certified artifact must fail.
A valid, unexpired READY artifact under the required policy must pass.
38. Phase P7 — Productization
Objective
Convert the forge into a commercial certification platform.
Deliverables
organizations;
projects;
users;
roles;
plans;
quotas;
metering;
billing integration;
retention policies;
API keys;
private workers;
white-label reports;
customer policy packs.
Product units
Possible metering units:
certification runs;
worker minutes;
4. 
5. 
6. 
7. 
8. 
9. 
10. 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
67


<!-- SOURCE_PAGE: 68 -->

browser minutes;
mobile-device minutes;
model tokens;
evidence storage;
retained history;
concurrent runs;
private worker nodes.
Commercial tiers
Developer
limited repositories;
shared workers;
basic report;
short evidence retention.
Professional
concurrent runs;
full evidence;
security adapters;
release gates;
longer retention.
Enterprise
private workers;
custom policies;
SSO;
audit exports;
customer-managed keys;
dedicated retention;
on-premises or hybrid execution.
Sovereign
local-only execution;
no external source transfer;
customer-controlled model routing;
customer-controlled evidence storage;
customer-controlled signing keys.
39. Forge Self-Certification
The ECHO Certification Forge must certify itself.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
68


<!-- SOURCE_PAGE: 69 -->

Required self-tests
API unit tests;
state-machine tests;
adapter contract tests;
worker integration tests;
dashboard E2E tests;
process-ownership adversarial tests;
evidence tamper tests;
tenant-isolation tests;
release-gate tests;
prompt-injection tests;
malicious repository tests;
cleanup failure tests;
crash recovery tests.
Bootstrap policy
Before the complete forge exists, each phase is certified by the capabilities currently implemented.
After P3, all future forge releases require a signed forge-generated verdict.
40. Testing Strategy
40.1 Unit tests
Cover:
schemas;
policy rules;
severity mapping;
state transitions;
adapter planning;
path validation;
command validation;
hashing;
redaction.
40.2 Contract tests
Every adapter must pass the common adapter contract suite.
Every model lane must pass structured-output contract tests.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
69


<!-- SOURCE_PAGE: 70 -->

Every API endpoint must pass schema compatibility tests.
40.3 Integration tests
Cover:
API to orchestrator;
orchestrator to worker;
worker to evidence store;
evidence to verdict;
dashboard to live event stream;
deployment gate to certification record.
40.4 End-to-end tests
Use golden repositories with known expected verdicts.
40.5 Adversarial tests
Targets must include:
infinite process;
fork bomb simulation under safe limits;
massive log output;
secret-printing test application;
malicious package scripts;
path traversal;
symlink escape;
deceptive green test suite;
unstable application;
unauthorized data access;
cleanup resistance.
40.6 Mutation tests
Introduce controlled defects and confirm the forge detects them.
Examples:
remove authorization check;
break production build;
disable required field validation;
introduce high-severity dependency;
break keyboard navigation;
alter API response schema.
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
70


<!-- SOURCE_PAGE: 71 -->

41. Observability
41.1 Metrics
certifications requested;
queue depth;
queue latency;
run duration;
stage duration;
adapter duration;
adapter failure rate;
worker utilization;
cleanup failures;
evidence volume;
model token usage;
verdict distribution;
flaky test rate;
false-classification corrections;
rerun rate.
41.2 Logs
All logs require:
run ID;
stage ID;
adapter ID;
worker ID;
trace ID;
severity;
structured event name.
41.3 Traces
Trace:
API intake
→ orchestration
→ worker lease
→ target acquisition
→ adapter execution
→ evidence upload
→ classification
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
71


<!-- SOURCE_PAGE: 72 -->

→ verdict
→ report publication
41.4 Alerts
Alert on:
queue backlog;
worker loss;
cleanup failure;
evidence upload failure;
verdict-signing failure;
database unavailability;
tenant-boundary violation;
repeated harness regression;
release-gate bypass attempt.
42. Reliability Targets
Initial operational targets:
durable run state after service restart;
no loss of completed evidence metadata;
idempotent workflow transitions;
idempotent evidence registration;
worker heartbeat and lease expiration;
retry-safe adapter execution;
deterministic cleanup attempts;
signed verdict publication only after successful finalization.
A run may fail, but its state must not become ambiguous.
43. Security Threat Model
Primary threats
malicious repository code;
dependency-install scripts;
credential exfiltration;
container escape;
path traversal;
symlink escape;
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
72


<!-- SOURCE_PAGE: 73 -->

model prompt injection;
forged evidence;
forged verdict;
cross-tenant evidence access;
worker impersonation;
webhook spoofing;
release-gate bypass.
Required defenses
short-lived worker credentials;
separate control and execution networks;
outbound network policy;
immutable worker images;
worker attestation where available;
signed adapter packages;
signed verdicts;
strict target path handling;
prompt-injection isolation;
evidence hash verification;
role-based access;
complete audit trail.
44. Configuration and Policy Versioning
Every run must pin:
forge version;
policy version;
adapter versions;
prompt versions;
model route version;
worker image;
schema versions;
report renderer version.
Configuration changes must not retroactively alter completed verdicts.
45. Definition of Done
A feature is complete only when:
implementation exists;
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
1. 
73


<!-- SOURCE_PAGE: 74 -->

schema is defined;
unit tests pass;
contract tests pass;
integration test exists;
failure behavior is tested;
evidence is collected;
cleanup is verified;
documentation is updated;
the phase acceptance scenario passes;
the result is committed;
the forge issues the expected verdict.
46. Initial Implementation Order
The recommended construction sequence is:
1. Domain schemas and run identity
2. Durable state machine
3. Target acquisition
4. Deterministic discovery
5. Adapter SDK
6. Python and JS/TS adapters
7. Process registry and cleanup
8. Evidence index and hashing
9. Finding normalization
10. Verdict policy
11. Web and API adapters
12. Container and Compose adapters
13. MCP/SDK/CLI adapters
14. Windows and Electron worker
15. Intelligence lanes
16. Dashboard
17. Deployment gate
18. Productization
Do not begin with the dashboard. The dashboard must display authoritative execution data produced by
the underlying certification system.
2. 
3. 
4. 
5. 
6. 
7. 
8. 
9. 
10. 
11. 
12. 
74


<!-- SOURCE_PAGE: 75 -->

47. First Production Milestone
The first usable release should certify these target classes:
Python application;
JavaScript or TypeScript application;
web application;
REST API;
Docker or Compose application;
MCP server;
CLI or SDK package.
It must provide:
discovery;
build;
test execution;
security checks;
web journey testing;
isolated processes;
evidence capture;
signed JSON report;
BLOCK, CONDITIONAL, or READY;
one-command rerun.
Electron, native desktop, and mobile certification follow after the core execution and evidence model is
proven.
48. Master Acceptance Scenario
The final system acceptance test must use a deliberately imperfect multi-service application containing:
TypeScript web frontend;
Python API;
PostgreSQL;
Redis;
Docker Compose;
authentication;
administrator role;
file upload;
REST schema;
MCP endpoint;
CLI utility;
missing tests;
one harness trap;
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
• 
75


<!-- SOURCE_PAGE: 76 -->

one environment trap;
one authorization defect;
one accessibility defect;
one vulnerable dependency;
one packaging defect.
The forge must:
discover every service;
construct an execution plan;
start the system in isolation;
create disposable accounts and data;
author missing tests;
repair the harness trap;
classify the environment trap correctly;
detect the authorization defect;
detect the accessibility defect;
identify the vulnerable dependency;
detect the packaging defect;
collect evidence;
clean all owned resources;
issue BLOCK;
produce a signed report;
register the result;
provide one rerun command.
The master acceptance scenario is the proof that ECHO Certification Forge is an autonomous certification
authority rather than a collection of test scripts.
49. Final Product Standard
ECHO Certification Forge is production-ready when it can accept an unfamiliar target, determine what it is,
decide how it must be tested, create missing test capability, execute the real system safely, distinguish
product defects from certification defects, preserve verifiable evidence, clean its resources, and make a
conservative release decision without manual orchestration.
The final authority remains evidence.
No evidence, no readiness.
Unknown critical behavior , no release.
Uncertified artifact, no deployment.
• 
• 
• 
• 
• 
1. 
2. 
3. 
4. 
5. 
6. 
7. 
8. 
9. 
10. 
11. 
12. 
13. 
14. 
15. 
16. 
17. 
76
