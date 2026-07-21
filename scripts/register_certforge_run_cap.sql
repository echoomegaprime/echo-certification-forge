-- Register echo.certforge.run (handler_kind=router -> loopback to the additive certforge_run_router).
-- Triggers a full sandboxed certification of an (untrusted) target; sovereign auth enforced in-router.
-- Poll with echo.certforge.status. Idempotent UPSERT. FULL restart echo-workers after applying.
INSERT INTO arcanum_sdk.sdk_capabilities
  (id, description, handler_kind, target_url, target_method, args_mode, target_node,
   input_schema_json, required_scope, danger_tier, default_timeout_seconds,
   lifecycle_status, health_status)
VALUES
  ('echo.certforge.run',
   'Certification Forge: certify an (untrusted) target end-to-end. Acquires the target (hooks off), scans it, runs its critical journey inside an ISOLATED Docker sandbox (no host escape), issues a signed verdict. Returns a run_id immediately; poll with echo.certforge.status.',
   'router', '/sdk/certification-forge/run', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["target"],"additionalProperties":false,"properties":{"target":{"type":"object","required":["type"],"properties":{"type":{"enum":["git","local"]},"url":{"type":"string"},"path":{"type":"string"},"ref":{"type":"string"}}},"journey":{"type":"array","items":{"type":"string"}},"policy_version":{"type":"string"}}}'::jsonb,
   'tier:1', 1, 30, 'active', 'unknown')
ON CONFLICT (id) DO UPDATE SET
  description=EXCLUDED.description, handler_kind=EXCLUDED.handler_kind, target_url=EXCLUDED.target_url,
  target_method=EXCLUDED.target_method, args_mode=EXCLUDED.args_mode, target_node=EXCLUDED.target_node,
  input_schema_json=EXCLUDED.input_schema_json, required_scope=EXCLUDED.required_scope,
  danger_tier=EXCLUDED.danger_tier, lifecycle_status='active', updated_at=now();
