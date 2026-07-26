-- Certification Forge R5 Family-14B negative-control capability.
-- Registration does not prove health/runnability. Keep health_status=unknown
-- until the cap is invoked through /sdk/invoke and its evidence is verified.

INSERT INTO arcanum_sdk.sdk_capabilities
  (id, description, handler_kind, target_url, target_method, args_mode, target_node,
   input_schema_json, required_scope, rate_cost, danger_tier, schema_version,
   is_builtin, lifecycle_status, health_status, created_at, updated_at)
VALUES
  (
    'echo.certification_forge.r5.run_negative_controls',
    'Certification Forge: run fixed GS343 wrong-active and unloaded-adapter R5 controls; dry_run performs read-only identity preflight.',
    'router',
    '/sdk/certification-forge/r5/run-negative-controls',
    'POST',
    'json_body',
    'forge',
    '{
      "type":"object",
      "additionalProperties":false,
      "required":[
        "command",
        "expected_server_build_digest",
        "expected_registry_snapshot_digest",
        "expected_registry_revision",
        "expected_signing_key_id",
        "expected_base_model_digest",
        "expected_base_model_revision",
        "expected_gs343_digest",
        "expected_r2d2_digest",
        "evidence_run_id",
        "evidence_run_nonce"
      ],
      "properties":{
        "command":{"type":"string","minLength":1,"maxLength":64},
        "expected_server_build_digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},
        "expected_registry_snapshot_digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},
        "expected_registry_revision":{"type":"string","pattern":"^[0-9a-fA-F]{6,128}$"},
        "expected_signing_key_id":{"type":"string","pattern":"^ed25519:[0-9a-f]{32}$"},
        "expected_base_model_digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},
        "expected_base_model_revision":{"type":"string","pattern":"^[0-9a-fA-F]{6,128}$"},
        "expected_gs343_digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},
        "expected_r2d2_digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},
        "evidence_run_id":{"type":"string","pattern":"^[A-Za-z0-9._-]{1,64}$"},
        "evidence_run_nonce":{"type":"string","minLength":16,"maxLength":128},
        "dry_run":{"type":"boolean","default":true}
      }
    }'::jsonb,
    'tier:1',
    2,
    1,
    1,
    false,
    'active',
    'unknown',
    now(),
    now()
  )
ON CONFLICT (id) DO UPDATE SET
  description = EXCLUDED.description,
  handler_kind = EXCLUDED.handler_kind,
  target_url = EXCLUDED.target_url,
  target_method = EXCLUDED.target_method,
  args_mode = EXCLUDED.args_mode,
  target_node = EXCLUDED.target_node,
  input_schema_json = EXCLUDED.input_schema_json,
  required_scope = EXCLUDED.required_scope,
  rate_cost = EXCLUDED.rate_cost,
  danger_tier = EXCLUDED.danger_tier,
  schema_version = EXCLUDED.schema_version,
  is_builtin = EXCLUDED.is_builtin,
  lifecycle_status = 'active',
  updated_at = now();

SELECT id, handler_kind, target_url, required_scope, danger_tier,
       lifecycle_status, health_status
  FROM arcanum_sdk.sdk_capabilities
 WHERE id = 'echo.certification_forge.r5.run_negative_controls';
