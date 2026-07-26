-- Register the 12 safe-core and 15 hardened-administration Echo Desktop
-- operator-facing echo.certforge.* SDK capabilities as
-- handler_kind='http' proxies to the live
-- echo-certforge.service on FORGE :8309. Idempotent (ON CONFLICT DO UPDATE).
--
-- Tenant model: the SDK gate is the sovereign control plane, so every gate invocation operates as
-- one canonical tenant. static_headers injects X-Tenant-ID='echo-sovereign' on the tenant-scoped
-- safe-core caps (the service is tenant-scoped via that header). Administrative caps resolve
-- the subscriber owner key server-side from Vault through sdk_invoke.py's vault: header
-- convention; the credential is never stored in this registry or returned to the caller.
-- Path params ({run_id}) resolve via
-- args_mode='path' in routers/sdk_invoke.py::_dispatch_router. Health carries no tenant.
--
-- health_status starts 'unknown' — registration does NOT prove health. Each cap is flipped to
-- 'green' ONLY after a real invocation through POST :8000/sdk/invoke succeeds (see verify step).
--
-- Apply on FORGE:  PGPASSWORD=echo psql -h localhost -U echo -d echo -f register_certforge_caps.sql
--             then FULL restart:  sudo systemctl restart echo-workers   (preload caches the registry)

INSERT INTO arcanum_sdk.sdk_capabilities
  (id, description, handler_kind, target_url, target_method, args_mode, target_node,
   input_schema_json, required_scope, danger_tier, static_headers, default_timeout_seconds,
   lifecycle_status, health_status)
VALUES
  ('echo.certforge.health',
   'Certification Forge: service health — status, version, custody/anchor/signing posture. No tenant, no side effects.',
   'http', 'http://127.0.0.1:8309/healthz', 'GET', 'query', 'forge',
   '{"type":"object","required":["command"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64}},"additionalProperties":false}'::jsonb,
   'certforge.read', 0, '{}'::jsonb, 10, 'active', 'unknown'),

  ('echo.certforge.list_runs',
   'Certification Forge: list tenant-scoped certification runs with state, outcome, verdict, and immutable identities.',
   'http', 'http://127.0.0.1:8309/v1/certifications', 'GET', 'query', 'forge',
   '{"type":"object","required":["command"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64}},"additionalProperties":false}'::jsonb,
   'certforge.read', 0, '{"X-Tenant-ID":"echo-sovereign"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.submit',
   'Certification Forge: submit a certification run for a target under a policy. Idempotency-Key bound; default-deny NOT_READY at intake.',
   'http', 'http://127.0.0.1:8309/v1/certifications', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["tenant_id","target","environment","policy_version","idempotency_key"],"properties":{"tenant_id":{"type":"string"},"target":{"type":"object"},"environment":{"type":"object"},"policy_version":{"type":"string"},"idempotency_key":{"type":"string","minLength":8}}}'::jsonb,
   'certforge.submit', 1, '{"X-Tenant-ID":"echo-sovereign"}'::jsonb, 30, 'active', 'unknown'),

  ('echo.certforge.status',
   'Certification Forge: get a certification run record (state, outcome, release_verdict, identity digests).',
   'http', 'http://127.0.0.1:8309/v1/certifications/{run_id}', 'GET', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string"}}}'::jsonb,
   'certforge.read', 0, '{"X-Tenant-ID":"echo-sovereign"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.cancel',
   'Certification Forge: cancel a certification run. Fail-closed — 409 once past the cancellable window; never re-opens a terminal run.',
   'http', 'http://127.0.0.1:8309/v1/certifications/{run_id}/cancel', 'POST', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string"}}}'::jsonb,
   'certforge.cancel', 1, '{"X-Tenant-ID":"echo-sovereign"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.findings',
   'Certification Forge: list findings for a run (severity, blocks_release, evidence refs).',
   'http', 'http://127.0.0.1:8309/v1/certifications/{run_id}/findings', 'GET', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string"}}}'::jsonb,
   'certforge.read', 0, '{"X-Tenant-ID":"echo-sovereign"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.evidence',
   'Certification Forge: redacted evidence index for a run (metadata only — never raw content or secrets).',
   'http', 'http://127.0.0.1:8309/v1/certifications/{run_id}/evidence', 'GET', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string"}}}'::jsonb,
   'certforge.read', 1, '{"X-Tenant-ID":"echo-sovereign"}'::jsonb, 20, 'active', 'unknown'),

  ('echo.certforge.verify',
   'Certification Forge: re-verify a run''s evidence manifest (Merkle + append-only chain). Detects tamper.',
   'http', 'http://127.0.0.1:8309/v1/certifications/{run_id}/verify', 'POST', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string"}}}'::jsonb,
   'certforge.read', 0, '{"X-Tenant-ID":"echo-sovereign"}'::jsonb, 30, 'active', 'unknown'),

  ('echo.certforge.verdict',
   'Certification Forge: get the signed verdict envelope for a run (or 404 verdict_not_available).',
   'http', 'http://127.0.0.1:8309/v1/certifications/{run_id}/verdict', 'GET', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string"}}}'::jsonb,
   'certforge.read', 0, '{"X-Tenant-ID":"echo-sovereign"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.verify_verdict',
   'Certification Forge: independently verify the stored signed verdict against the trusted public-key registry.',
   'http', 'http://127.0.0.1:8309/v1/certifications/{run_id}/verdict/verify', 'GET', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string"}}}'::jsonb,
   'certforge.read', 0, '{"X-Tenant-ID":"echo-sovereign"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.deploy_gate',
   'Certification Forge: evaluate a release/deploy gate — exact-identity, signature, evidence, and lifecycle checks. Elevated (tier 2).',
   'http', 'http://127.0.0.1:8309/v1/release-gates/evaluate', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["run_id","target_identity_digest","environment_identity_digest","rule_manifest_digest"],"properties":{"run_id":{"type":"string"},"target_identity_digest":{"type":"string"},"environment_identity_digest":{"type":"string"},"rule_manifest_digest":{"type":"string"}}}'::jsonb,
   'certforge.deploy_gate', 2, '{"X-Tenant-ID":"echo-sovereign"}'::jsonb, 30, 'active', 'unknown'),

  ('echo.certforge.admin.audit',
   'Certification Forge administration: read the tenant-scoped immutable subscriber audit log. Subscriber credentials are resolved only inside the SDK gate.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/audit', 'GET', 'query', 'forge',
   '{"type":"object","required":["command"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64},"limit":{"type":"integer","minimum":1,"maximum":500}},"additionalProperties":false}'::jsonb,
   'certforge.admin.read', 1, '{"X-CertForge-API-Key":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.telemetry',
   'Certification Forge: tenant-scoped queue, state-machine, quota, budget, authenticated worker/adapter health, and fail-closed quarantine telemetry.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/telemetry', 'GET', 'query', 'forge',
   '{"type":"object","required":["command"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64}},"additionalProperties":false}'::jsonb,
   'certforge.read', 0, '{"X-CertForge-API-Key":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.admin.evidence_artifact',
   'Certification Forge administration: retrieve one tenant-owned, release-safe evidence artifact after server-side size and SHA-256 verification. Response is bounded to 5 MiB raw and audited. Subscriber credentials are resolved only inside the SDK gate.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/certifications/{run_id}/evidence/{artifact_id}', 'GET', 'path', 'forge',
   '{"type":"object","required":["command","run_id","artifact_id"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64},"run_id":{"type":"string","minLength":1,"maxLength":128},"artifact_id":{"type":"string","minLength":1,"maxLength":128}},"additionalProperties":false}'::jsonb,
   'certforge.admin.read', 1, '{"X-CertForge-API-Key":"vault:certforge.desktop_admin_api_key"}'::jsonb, 30, 'active', 'unknown'),

  ('echo.certforge.admin.legal_hold_create',
   'Certification Forge administration: create an audited legal hold for one owned run or the tenant. Tier-2 HMAC and Desktop reauthentication are required.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/legal-holds', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["command","hold_id","reason"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64},"hold_id":{"type":"string","minLength":1,"maxLength":128},"run_id":{"type":["string","null"],"minLength":1,"maxLength":128},"reason":{"type":"string","minLength":1,"maxLength":2048}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-CertForge-API-Key":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.admin.legal_hold_release',
   'Certification Forge administration: release one tenant-owned legal hold. Tier-2 HMAC and Desktop reauthentication are required.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/legal-holds/{hold_id}', 'DELETE', 'path', 'forge',
   '{"type":"object","required":["command","hold_id"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64},"hold_id":{"type":"string","minLength":1,"maxLength":128}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-CertForge-API-Key":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.admin.rerun',
   'Certification Forge administration: create a new queued certification run with immutable lineage to one terminal tenant-owned source run. Original evidence and verdict records are never copied or changed. Tier-2 HMAC and Desktop reauthentication are required.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/certifications/{run_id}/rerun', 'POST', 'path', 'forge',
   '{"type":"object","required":["command","run_id","idempotency_key"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64},"run_id":{"type":"string","minLength":1,"maxLength":128},"idempotency_key":{"type":"string","minLength":8,"maxLength":128}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-CertForge-API-Key":"vault:certforge.desktop_admin_api_key"}'::jsonb, 30, 'active', 'unknown'),

  ('echo.certforge.admin.lifecycle',
   'Certification Forge administration: append an immutable revocation, invalidation, or supersession event to an owned verdict. Tier-2 HMAC and Desktop reauthentication are required.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/certifications/{run_id}/lifecycle', 'POST', 'path', 'forge',
   '{"type":"object","required":["command","run_id","event_type","reason"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64},"run_id":{"type":"string","minLength":1,"maxLength":128},"event_type":{"type":"string","enum":["REVOKED","INVALIDATED","SUPERSEDED"]},"reason":{"type":"string","minLength":1,"maxLength":2048},"replacement_run_id":{"type":["string","null"],"minLength":1,"maxLength":128}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-CertForge-API-Key":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'green'),

  ('echo.certforge.admin.publish',
   'Certification Forge administration: publish public-only verification material for a current production-ready verdict. Tier-2 HMAC and Desktop reauthentication are required.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/certifications/{run_id}/publish', 'POST', 'path', 'forge',
   '{"type":"object","required":["command","run_id"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64},"run_id":{"type":"string","minLength":1,"maxLength":128}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-CertForge-API-Key":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.admin.quarantine',
   'Certification Forge administration: quarantine one authenticated runner or adapter, removing it from eligible capacity/execution without deleting telemetry. Tier-2 HMAC and Desktop reauthentication are required.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/operational-quarantines', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["command","subject_type","subject_id","reason"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64},"subject_type":{"type":"string","enum":["runner","adapter"]},"subject_id":{"type":"string","minLength":1,"maxLength":128},"reason":{"type":"string","minLength":8,"maxLength":2048}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-CertForge-API-Key":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'green'),

  ('echo.certforge.admin.quarantine_release',
   'Certification Forge administration: release one active runner or adapter quarantine after verification while retaining immutable audit history. Tier-2 HMAC and Desktop reauthentication are required.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/operational-quarantines/{subject_type}/{subject_id}/release', 'POST', 'path', 'forge',
   '{"type":"object","required":["command","subject_type","subject_id","reason"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64},"subject_type":{"type":"string","enum":["runner","adapter"]},"subject_id":{"type":"string","minLength":1,"maxLength":128},"reason":{"type":"string","minLength":8,"maxLength":2048}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-CertForge-API-Key":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'green'),

  ('echo.certforge.admin.key_rotation_status',
   'Certification Forge administration: list bounded public-key rotation metadata and proof state. Private key material is never accepted or returned.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/operational-key-rotations', 'GET', 'query', 'forge',
   '{"type":"object","required":["command"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64}},"additionalProperties":false}'::jsonb,
   'certforge.admin.read', 1, '{"X-CertForge-API-Key":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.admin.key_rotation_begin',
   'Certification Forge administration: begin a bounded tenant-scoped Ed25519 public-key overlap. The old key remains trusted only during the bounded proof window; no private material is accepted.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/operational-key-rotations', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["command","old_key_id","new_public_key_pem","reason"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64},"old_key_id":{"type":"string","minLength":1,"maxLength":128},"new_public_key_pem":{"type":"string","minLength":80,"maxLength":8192},"overlap_seconds":{"type":"integer","minimum":60,"maximum":86400,"default":3600},"reason":{"type":"string","minLength":8,"maxLength":2048}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-CertForge-API-Key":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.admin.key_rotation_finalize',
   'Certification Forge administration: retire the old operational key only after a report authenticated by the new key proves possession. Tier-2 HMAC and Desktop reauthentication are required.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/operational-key-rotations/{rotation_id}/finalize', 'POST', 'path', 'forge',
   '{"type":"object","required":["command","rotation_id"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64},"rotation_id":{"type":"string","minLength":1,"maxLength":128}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-CertForge-API-Key":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.admin.runner_enroll',
   'Certification Forge administration: durably enroll a previously authenticated runner by pinning its runner key and worker image SHA-256, then enforce enrollment for the tenant.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/runner-enrollments', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["command","runner_id"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64},"runner_id":{"type":"string","minLength":1,"maxLength":128}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-CertForge-API-Key":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.admin.runner_enrollment_revoke',
   'Certification Forge administration: revoke one active durable runner enrollment and remove its capacity eligibility while retaining telemetry and audit history.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/runner-enrollments/{runner_id}/revoke', 'POST', 'path', 'forge',
   '{"type":"object","required":["command","runner_id","reason"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64},"runner_id":{"type":"string","minLength":1,"maxLength":128},"reason":{"type":"string","minLength":8,"maxLength":2048}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-CertForge-API-Key":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.admin.adapter_maturity_remediate',
   'Certification Forge administration: atomically quarantine every authenticated non-STABLE adapter so only stable identities remain execution eligible.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/adapter-maturity/remediate', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["command","reason"],"properties":{"command":{"type":"string","minLength":1,"maxLength":64},"reason":{"type":"string","minLength":8,"maxLength":2048}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-CertForge-API-Key":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown')

ON CONFLICT (id) DO UPDATE SET
  description = EXCLUDED.description,
  handler_kind = EXCLUDED.handler_kind,
  target_url = EXCLUDED.target_url,
  target_method = EXCLUDED.target_method,
  args_mode = EXCLUDED.args_mode,
  target_node = EXCLUDED.target_node,
  input_schema_json = EXCLUDED.input_schema_json,
  required_scope = EXCLUDED.required_scope,
  danger_tier = EXCLUDED.danger_tier,
  static_headers = EXCLUDED.static_headers,
  default_timeout_seconds = EXCLUDED.default_timeout_seconds,
  lifecycle_status = 'active',
  updated_at = now();

-- Promoted only after the Desktop live acceptance completed a disposable
-- submit -> REVOKED -> audited -> cancel journey through the signed SDK path.
UPDATE arcanum_sdk.sdk_capabilities
SET health_status = 'green', updated_at = now()
WHERE id = 'echo.certforge.admin.lifecycle';

-- Promoted only after a real tenant-owned COMPLETE artifact crossed the SDK,
-- decoded to its declared size, matched its SHA-256 locally, and produced an
-- evidence.download audit record without exposing subscriber credentials.
UPDATE arcanum_sdk.sdk_capabilities
SET health_status = 'green', updated_at = now()
WHERE id = 'echo.certforge.admin.evidence_artifact';

-- Promoted only after the tenant-scoped telemetry crossed the live SDK path
-- with bounded timelines and explicit UNKNOWN/UNAVAILABLE source truth.
UPDATE arcanum_sdk.sdk_capabilities
SET health_status = 'green', updated_at = now()
WHERE id = 'echo.certforge.telemetry';

-- Promoted only after a real terminal source produced one distinct queued
-- NOT_READY run through the signed Desktop path; idempotent replay returned
-- the same run, lineage was visible, and the source projection stayed exact.
UPDATE arcanum_sdk.sdk_capabilities
SET health_status = 'green', updated_at = now()
WHERE id = 'echo.certforge.admin.rerun';
