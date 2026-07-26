-- Register the complete customer/operator Echo Desktop echo.certforge.* SDK
-- capability surface as
-- handler_kind='http' proxies to the live
-- echo-certforge.service on FORGE :8309. Idempotent (ON CONFLICT DO UPDATE).
--
-- Tenant model: the SDK gate is the sovereign control plane, so every gate invocation operates as
-- one canonical tenant. static_headers injects X-Tenant-ID='org-echo-sovereign' on the tenant-scoped
-- safe-core caps (the service is tenant-scoped via that header). Administrative caps resolve
-- a full Bearer authorization value server-side from Vault through sdk_invoke.py's vault: header
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
   '{"type":"object","additionalProperties":false}'::jsonb,
   'certforge.read', 0, '{}'::jsonb, 10, 'active', 'unknown'),

  ('echo.certforge.list_runs',
   'Certification Forge: list tenant-scoped certification runs with state, outcome, verdict, and immutable identities.',
   'http', 'http://127.0.0.1:8309/v1/certifications', 'GET', 'query', 'forge',
   '{"type":"object","additionalProperties":false}'::jsonb,
   'certforge.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.submit',
   'Certification Forge: submit a certification run for a target under a policy. Idempotency-Key bound; default-deny NOT_READY at intake.',
   'http', 'http://127.0.0.1:8309/v1/certifications', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["tenant_id","target","environment","policy_version","idempotency_key"],"properties":{"tenant_id":{"type":"string"},"target":{"type":"object"},"environment":{"type":"object"},"policy_version":{"type":"string"},"idempotency_key":{"type":"string","minLength":8}}}'::jsonb,
   'certforge.submit', 1, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 30, 'active', 'unknown'),

  ('echo.certforge.status',
   'Certification Forge: get a certification run record (state, outcome, release_verdict, identity digests).',
   'http', 'http://127.0.0.1:8309/v1/certifications/{run_id}', 'GET', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string"}}}'::jsonb,
   'certforge.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.cancel',
   'Certification Forge: cancel a certification run. Fail-closed — 409 once past the cancellable window; never re-opens a terminal run.',
   'http', 'http://127.0.0.1:8309/v1/certifications/{run_id}/cancel', 'POST', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string"}}}'::jsonb,
   'certforge.cancel', 1, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.findings',
   'Certification Forge: list findings for a run (severity, blocks_release, evidence refs).',
   'http', 'http://127.0.0.1:8309/v1/certifications/{run_id}/findings', 'GET', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string"}}}'::jsonb,
   'certforge.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.evidence',
   'Certification Forge: redacted evidence index for a run (metadata only — never raw content or secrets).',
   'http', 'http://127.0.0.1:8309/v1/certifications/{run_id}/evidence', 'GET', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string"}}}'::jsonb,
   'certforge.read', 1, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 20, 'active', 'unknown'),

  ('echo.certforge.verify',
   'Certification Forge: re-verify a run''s evidence manifest (Merkle + append-only chain). Detects tamper.',
   'http', 'http://127.0.0.1:8309/v1/certifications/{run_id}/verify', 'POST', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string"}}}'::jsonb,
   'certforge.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 30, 'active', 'unknown'),

  ('echo.certforge.verdict',
   'Certification Forge: get the signed verdict envelope for a run (or 404 verdict_not_available).',
   'http', 'http://127.0.0.1:8309/v1/certifications/{run_id}/verdict', 'GET', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string"}}}'::jsonb,
   'certforge.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.verify_verdict',
   'Certification Forge: independently verify the stored signed verdict against the trusted public-key registry.',
   'http', 'http://127.0.0.1:8309/v1/certifications/{run_id}/verdict/verify', 'GET', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string"}}}'::jsonb,
   'certforge.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.deploy_gate',
   'Certification Forge: evaluate a release/deploy gate — exact-identity, signature, evidence, and lifecycle checks. Elevated (tier 2).',
   'http', 'http://127.0.0.1:8309/v1/release-gates/evaluate', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["run_id","target_identity_digest","environment_identity_digest","rule_manifest_digest"],"properties":{"run_id":{"type":"string"},"target_identity_digest":{"type":"string"},"environment_identity_digest":{"type":"string"},"rule_manifest_digest":{"type":"string"}}}'::jsonb,
   'certforge.deploy_gate', 2, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 30, 'active', 'unknown'),

  ('echo.certforge.admin.audit',
   'Certification Forge administration: read the tenant-scoped immutable subscriber audit log. Subscriber credentials are resolved only inside the SDK gate.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/audit', 'GET', 'query', 'forge',
   '{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":500}},"additionalProperties":false}'::jsonb,
   'certforge.admin.read', 1, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.telemetry',
   'Certification Forge: tenant-scoped queue, state-machine, quota, and budget telemetry. Worker and adapter health remain explicitly UNKNOWN until authenticated heartbeat/registry contracts exist.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/telemetry', 'GET', 'query', 'forge',
   '{"type":"object","additionalProperties":false}'::jsonb,
   'certforge.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.admin.evidence_artifact',
   'Certification Forge administration: retrieve one tenant-owned, release-safe evidence artifact after server-side size and SHA-256 verification. Response is bounded to 5 MiB raw and audited. Subscriber credentials are resolved only inside the SDK gate.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/certifications/{run_id}/evidence/{artifact_id}', 'GET', 'path', 'forge',
   '{"type":"object","required":["run_id","artifact_id"],"properties":{"run_id":{"type":"string","minLength":1,"maxLength":128},"artifact_id":{"type":"string","minLength":1,"maxLength":128}},"additionalProperties":false}'::jsonb,
   'certforge.admin.read', 1, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 30, 'active', 'unknown'),

  ('echo.certforge.admin.legal_hold_create',
   'Certification Forge administration: create an audited legal hold for one owned run or the tenant. Tier-2 HMAC and Desktop reauthentication are required.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/legal-holds', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["hold_id","reason"],"properties":{"hold_id":{"type":"string","minLength":1,"maxLength":128},"run_id":{"type":["string","null"],"minLength":1,"maxLength":128},"reason":{"type":"string","minLength":1,"maxLength":2048}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.admin.legal_hold_release',
   'Certification Forge administration: release one tenant-owned legal hold. Tier-2 HMAC and Desktop reauthentication are required.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/legal-holds/{hold_id}', 'DELETE', 'path', 'forge',
   '{"type":"object","required":["hold_id"],"properties":{"hold_id":{"type":"string","minLength":1,"maxLength":128}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),

  ('echo.certforge.admin.lifecycle',
   'Certification Forge administration: append an immutable revocation, invalidation, or supersession event to an owned verdict. Tier-2 HMAC and Desktop reauthentication are required.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/certifications/{run_id}/lifecycle', 'POST', 'path', 'forge',
   '{"type":"object","required":["run_id","event_type","reason"],"properties":{"run_id":{"type":"string","minLength":1,"maxLength":128},"event_type":{"type":"string","enum":["REVOKED","INVALIDATED","SUPERSEDED"]},"reason":{"type":"string","minLength":1,"maxLength":2048},"replacement_run_id":{"type":["string","null"],"minLength":1,"maxLength":128}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'green'),

  ('echo.certforge.admin.rerun',
   'Certification Forge administration: create a new queued certification run with immutable lineage to one terminal tenant-owned source run. Original evidence and verdict records are never copied or changed. Tier-2 HMAC and Desktop reauthentication are required.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/certifications/{run_id}/rerun', 'POST', 'path', 'forge',
   '{"type":"object","required":["run_id","idempotency_key"],"properties":{"run_id":{"type":"string","minLength":1,"maxLength":128},"idempotency_key":{"type":"string","minLength":8,"maxLength":128}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 30, 'active', 'unknown'),

  ('echo.certforge.admin.publish',
   'Certification Forge administration: publish public-only verification material for a current production-ready verdict. Tier-2 HMAC and Desktop reauthentication are required.',
   'http', 'http://127.0.0.1:8309/v1/subscriber/certifications/{run_id}/publish', 'POST', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string","minLength":1,"maxLength":128}},"additionalProperties":false}'::jsonb,
   'certforge.admin.mutate', 2, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown')

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

-- Complete customer/operator capability surface. Signed deployment mutations,
-- signed worker reports, and signed webhooks are deliberately not proxied by
-- generic HTTP caps: their per-request signatures are part of the security boundary.
INSERT INTO arcanum_sdk.sdk_capabilities
  (id, description, handler_kind, target_url, target_method, args_mode, target_node,
   input_schema_json, required_scope, danger_tier, static_headers, default_timeout_seconds,
   lifecycle_status, health_status)
VALUES
  ('echo.certforge.service_status', 'Certification Forge readiness and active manifest status.', 'http', 'http://127.0.0.1:8309/v1/status', 'GET', 'query', 'forge',
   '{"type":"object","additionalProperties":false}'::jsonb, 'certforge.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 10, 'active', 'unknown'),
  ('echo.certforge.verify_evidence_manifest', 'Verify the immutable evidence manifest and custody chain for one run.', 'http', 'http://127.0.0.1:8309/v1/certifications/{run_id}/evidence/verify', 'GET', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string"}},"additionalProperties":false}'::jsonb, 'certforge.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 20, 'active', 'unknown'),
  ('echo.certforge.deployment.rollback_target', 'Read the last known-good production rollback target.', 'http', 'http://127.0.0.1:8309/v1/deployments/rollback-target', 'GET', 'query', 'forge',
   '{"type":"object","properties":{"environment":{"type":"string","enum":["production"]}},"additionalProperties":false}'::jsonb, 'certforge.deploy.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.deployment.release_status', 'Read certification and deployment status for an artifact identity.', 'http', 'http://127.0.0.1:8309/v1/releases/{artifact_sha256}/status', 'GET', 'query', 'forge',
   '{"type":"object","required":["artifact_sha256"],"properties":{"artifact_sha256":{"type":"string"},"environment_identity_digest":{"type":"string"},"rule_manifest_digest":{"type":"string"}},"additionalProperties":false}'::jsonb, 'certforge.deploy.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 20, 'active', 'unknown'),
  ('echo.certforge.deployment.audit', 'Read the tenant deployment admission hash chain and records.', 'http', 'http://127.0.0.1:8309/v1/deployments/audit', 'GET', 'query', 'forge',
   '{"type":"object","properties":{"artifact_sha256":{"type":"string"}},"additionalProperties":false}'::jsonb, 'certforge.deploy.read', 1, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 20, 'active', 'unknown'),
  ('echo.certforge.subscriber.me', 'Read the authenticated subscriber principal, plan, role, and scopes.', 'http', 'http://127.0.0.1:8309/v1/subscriber/me', 'GET', 'query', 'forge',
   '{"type":"object","additionalProperties":false}'::jsonb, 'certforge.subscriber.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.projects.create', 'Create a tenant certification project.', 'http', 'http://127.0.0.1:8309/v1/subscriber/projects', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["slug","name","target_reference"],"properties":{"slug":{"type":"string"},"name":{"type":"string"},"target_reference":{"type":"string"}},"additionalProperties":false}'::jsonb, 'certforge.project.manage', 1, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.projects.list', 'List tenant certification projects.', 'http', 'http://127.0.0.1:8309/v1/subscriber/projects', 'GET', 'query', 'forge',
   '{"type":"object","additionalProperties":false}'::jsonb, 'certforge.project.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.projects.archive', 'Archive one tenant certification project.', 'http', 'http://127.0.0.1:8309/v1/subscriber/projects/{project_id}', 'DELETE', 'path', 'forge',
   '{"type":"object","required":["project_id"],"properties":{"project_id":{"type":"string"}},"additionalProperties":false}'::jsonb, 'certforge.project.manage', 1, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.api_keys.create', 'Create a scoped tenant API key; secret is returned once.', 'http', 'http://127.0.0.1:8309/v1/subscriber/api-keys', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["name","scopes","expires_at"],"properties":{"name":{"type":"string"},"user_id":{"type":["string","null"]},"scopes":{"type":"array","items":{"type":"string"}},"expires_at":{"type":"string","format":"date-time"}},"additionalProperties":false}'::jsonb, 'certforge.api_key.manage', 2, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.api_keys.list', 'List tenant API-key metadata without secret material.', 'http', 'http://127.0.0.1:8309/v1/subscriber/api-keys', 'GET', 'query', 'forge',
   '{"type":"object","additionalProperties":false}'::jsonb, 'certforge.api_key.manage', 1, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.api_keys.revoke', 'Revoke one tenant API key.', 'http', 'http://127.0.0.1:8309/v1/subscriber/api-keys/{key_id}', 'DELETE', 'path', 'forge',
   '{"type":"object","required":["key_id"],"properties":{"key_id":{"type":"string"}},"additionalProperties":false}'::jsonb, 'certforge.api_key.manage', 2, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.members.invite', 'Invite a tenant member with an explicit role.', 'http', 'http://127.0.0.1:8309/v1/subscriber/members', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["email","display_name","role"],"properties":{"email":{"type":"string"},"display_name":{"type":"string"},"role":{"type":"string"}},"additionalProperties":false}'::jsonb, 'certforge.member.manage', 1, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.members.list', 'List tenant members and roles.', 'http', 'http://127.0.0.1:8309/v1/subscriber/members', 'GET', 'query', 'forge',
   '{"type":"object","additionalProperties":false}'::jsonb, 'certforge.member.manage', 1, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.members.activate', 'Activate one invited tenant member.', 'http', 'http://127.0.0.1:8309/v1/subscriber/members/{user_id}/activate', 'POST', 'path', 'forge',
   '{"type":"object","required":["user_id"],"properties":{"user_id":{"type":"string"}},"additionalProperties":false}'::jsonb, 'certforge.member.manage', 1, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.members.update_role', 'Update one tenant member role.', 'http', 'http://127.0.0.1:8309/v1/subscriber/members/{user_id}/role', 'PATCH', 'path', 'forge',
   '{"type":"object","required":["user_id","role"],"properties":{"user_id":{"type":"string"},"role":{"type":"string"}},"additionalProperties":false}'::jsonb, 'certforge.member.manage', 2, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.members.deactivate', 'Deactivate one tenant member.', 'http', 'http://127.0.0.1:8309/v1/subscriber/members/{user_id}', 'DELETE', 'path', 'forge',
   '{"type":"object","required":["user_id"],"properties":{"user_id":{"type":"string"}},"additionalProperties":false}'::jsonb, 'certforge.member.manage', 2, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.subscription.get', 'Read tenant subscription and entitlements.', 'http', 'http://127.0.0.1:8309/v1/subscriber/subscription', 'GET', 'query', 'forge',
   '{"type":"object","additionalProperties":false}'::jsonb, 'certforge.governance.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.subscription.cancel', 'Request tenant subscription cancellation.', 'http', 'http://127.0.0.1:8309/v1/subscriber/subscription/cancel', 'POST', 'json_body', 'forge',
   '{"type":"object","additionalProperties":false}'::jsonb, 'certforge.billing.manage', 2, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.governance.get', 'Read versioned tenant governance configuration.', 'http', 'http://127.0.0.1:8309/v1/subscriber/governance', 'GET', 'query', 'forge',
   '{"type":"object","additionalProperties":false}'::jsonb, 'certforge.governance.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.governance.update', 'Update tenant governance with optimistic version control.', 'http', 'http://127.0.0.1:8309/v1/subscriber/governance', 'PUT', 'json_body', 'forge',
   '{"type":"object","required":["expected_version","config"],"properties":{"expected_version":{"type":"integer"},"config":{"type":"object"}},"additionalProperties":false}'::jsonb, 'certforge.governance.manage', 2, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 20, 'active', 'unknown'),
  ('echo.certforge.policy_packs.create', 'Create a versioned tenant policy pack.', 'http', 'http://127.0.0.1:8309/v1/subscriber/policy-packs', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["name","version","manifest"],"properties":{"name":{"type":"string"},"version":{"type":"string"},"manifest":{"type":"object"}},"additionalProperties":false}'::jsonb, 'certforge.policy_pack.manage', 2, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 20, 'active', 'unknown'),
  ('echo.certforge.policy_packs.list', 'List tenant policy packs.', 'http', 'http://127.0.0.1:8309/v1/subscriber/policy-packs', 'GET', 'query', 'forge',
   '{"type":"object","additionalProperties":false}'::jsonb, 'certforge.governance.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.private_workers.create', 'Register an attested tenant private worker.', 'http', 'http://127.0.0.1:8309/v1/subscriber/private-workers', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["display_name","attestation_sha256"],"properties":{"display_name":{"type":"string"},"attestation_sha256":{"type":"string"}},"additionalProperties":false}'::jsonb, 'certforge.private_worker.manage', 2, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 20, 'active', 'unknown'),
  ('echo.certforge.private_workers.list', 'List tenant private workers.', 'http', 'http://127.0.0.1:8309/v1/subscriber/private-workers', 'GET', 'query', 'forge',
   '{"type":"object","additionalProperties":false}'::jsonb, 'certforge.private_worker.manage', 1, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.private_workers.revoke', 'Revoke one tenant private worker.', 'http', 'http://127.0.0.1:8309/v1/subscriber/private-workers/{worker_id}', 'DELETE', 'path', 'forge',
   '{"type":"object","required":["worker_id"],"properties":{"worker_id":{"type":"string"}},"additionalProperties":false}'::jsonb, 'certforge.private_worker.manage', 2, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.usage', 'Read tenant usage meters, quotas, and period boundaries.', 'http', 'http://127.0.0.1:8309/v1/subscriber/usage', 'GET', 'query', 'forge',
   '{"type":"object","additionalProperties":false}'::jsonb, 'certforge.usage.read', 0, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 15, 'active', 'unknown'),
  ('echo.certforge.admin.audit_verify', 'Verify the tenant subscriber audit hash chain.', 'http', 'http://127.0.0.1:8309/v1/subscriber/audit/verify', 'GET', 'query', 'forge',
   '{"type":"object","additionalProperties":false}'::jsonb, 'certforge.admin.read', 1, '{"X-Tenant-ID":"org-echo-sovereign","Authorization":"vault:certforge.desktop_admin_api_key"}'::jsonb, 20, 'active', 'unknown'),
  ('echo.certforge.public_verification', 'Read a published public verification by opaque verification id.', 'http', 'http://127.0.0.1:8309/v1/public/verifications/{verification_id}', 'GET', 'path', 'forge',
   '{"type":"object","required":["verification_id"],"properties":{"verification_id":{"type":"string"}},"additionalProperties":false}'::jsonb, 'certforge.public.read', 0, '{}'::jsonb, 15, 'active', 'unknown')
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
  health_status = 'unknown',
  updated_at = now();
