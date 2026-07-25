-- Register the R5 async submit/poll caps (handler_kind='router' -> loopback to the additive
-- certforge_r5_async_router). Sovereign auth + Action-Broker grant are enforced IN the router, so
-- no tenant/static headers. Idempotent UPSERT. FULL restart echo-workers after applying.

INSERT INTO arcanum_sdk.sdk_capabilities
  (id, description, handler_kind, target_url, target_method, args_mode, target_node,
   input_schema_json, required_scope, danger_tier, default_timeout_seconds,
   lifecycle_status, health_status)
VALUES
  ('echo.certforge.r5.submit_async',
   'Certification Forge R5: launch a NON-BLOCKING negative-control run (detached on ANVIL); returns a run_id immediately. Poll with echo.certforge.r5.status. dry_run=false is the full 4x-14B run.',
   'router', '/sdk/certification-forge/r5/submit-async', 'POST', 'json_body', 'forge',
   '{"type":"object","required":["expected_server_build_digest","expected_registry_snapshot_digest","expected_registry_revision","expected_signing_key_id","expected_base_model_digest","expected_base_model_revision","expected_gs343_digest","expected_r2d2_digest","evidence_run_id","evidence_run_nonce"],"properties":{"expected_server_build_digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},"expected_registry_snapshot_digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},"expected_registry_revision":{"type":"string"},"expected_signing_key_id":{"type":"string"},"expected_base_model_digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},"expected_base_model_revision":{"type":"string"},"expected_gs343_digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},"expected_r2d2_digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},"evidence_run_id":{"type":"string","pattern":"^[A-Za-z0-9._-]{1,64}$"},"evidence_run_nonce":{"type":"string","minLength":16,"maxLength":128},"dry_run":{"type":"boolean"}}}'::jsonb,
   'tier:1', 1, 30, 'active', 'unknown'),

  ('echo.certforge.r5.status',
   'Certification Forge R5: poll a non-blocking R5 run by run_id. Returns RUNNING, or COMPLETE/FAILED with the FORGE-re-verified result when the ANVIL run finishes.',
   'router', '/sdk/certification-forge/r5/status/{run_id}', 'GET', 'path', 'forge',
   '{"type":"object","required":["run_id"],"properties":{"run_id":{"type":"string","pattern":"^[A-Za-z0-9._-]{1,64}$"}}}'::jsonb,
   'tier:1', 1, 30, 'active', 'unknown')

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
  default_timeout_seconds = EXCLUDED.default_timeout_seconds,
  lifecycle_status = 'active',
  updated_at = now();
