-- Register echo.certforge.run (handler_kind=router -> loopback to the additive certforge_run_router).
-- Confirms an existing governed subscriber dispatch; sovereign auth enforced in-router.
-- Poll with echo.certforge.status. Idempotent UPSERT. FULL restart echo-workers after applying.
INSERT INTO arcanum_sdk.sdk_capabilities
  (id, description, handler_kind, target_url, target_method, args_mode, target_node,
   input_schema_json, required_scope, danger_tier, default_timeout_seconds,
   lifecycle_status, health_status)
VALUES
  ('echo.certforge.run',
   'Certification Forge: confirm an existing tenant-governed subscriber run for the always-on sandbox dispatcher. Intake owns identity, metering, target validation, and the transactional outbox; this cap never creates or bypasses them.',
   'router', '/sdk/certification-forge/run', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["command","run_id","tenant"],"additionalProperties":false,"properties":{"command":{"type":"string","minLength":1,"maxLength":64},"run_id":{"type":"string","pattern":"^[A-Za-z0-9._-]{1,128}$"},"tenant":{"type":"string","pattern":"^[A-Za-z0-9._-]{1,128}$"}}}'::jsonb,
   'tier:1', 1, 30, 'active', 'unknown')
ON CONFLICT (id) DO UPDATE SET
  description=EXCLUDED.description, handler_kind=EXCLUDED.handler_kind, target_url=EXCLUDED.target_url,
  target_method=EXCLUDED.target_method, args_mode=EXCLUDED.args_mode, target_node=EXCLUDED.target_node,
  input_schema_json=EXCLUDED.input_schema_json, required_scope=EXCLUDED.required_scope,
  danger_tier=EXCLUDED.danger_tier, lifecycle_status='active', updated_at=now();
