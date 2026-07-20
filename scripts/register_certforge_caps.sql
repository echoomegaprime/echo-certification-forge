-- Register the 9 echo.certforge.* SDK capabilities as handler_kind='http' proxies to the live
-- echo-certforge.service on FORGE :8309. Idempotent (ON CONFLICT DO UPDATE).
--
-- Tenant model: the SDK gate is the sovereign control plane, so every gate invocation operates as
-- one canonical tenant. static_headers injects X-Tenant-ID='echo-sovereign' on the tenant-scoped
-- caps (the service is tenant-scoped via that header). Path params ({run_id}) resolve via
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

  ('echo.certforge.deploy_gate',
   'Certification Forge: evaluate a release/deploy gate — exact-identity, signature, evidence, and lifecycle checks. Elevated (tier 2).',
   'http', 'http://127.0.0.1:8309/v1/release-gates/evaluate', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["run_id","target_identity_digest","environment_identity_digest","rule_manifest_digest"],"properties":{"run_id":{"type":"string"},"target_identity_digest":{"type":"string"},"environment_identity_digest":{"type":"string"},"rule_manifest_digest":{"type":"string"}}}'::jsonb,
   'certforge.deploy_gate', 2, '{"X-Tenant-ID":"echo-sovereign"}'::jsonb, 30, 'active', 'unknown')

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
