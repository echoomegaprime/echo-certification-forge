-- Action-Broker grant store — the fail-closed enable/expiry/audit switch for
-- governed, scoped remote operations. The grant IDENTITY (agent/task/scope) is
-- fixed in the capability code; this table decides whether that identity is
-- currently permitted. No row (or inactive/expired) => the capability refuses.
CREATE TABLE IF NOT EXISTS arcanum_sdk.action_broker_grants (
    id          bigserial PRIMARY KEY,
    agent       text        NOT NULL,
    task        text        NOT NULL,
    scope       text        NOT NULL,
    active      boolean     NOT NULL DEFAULT true,
    expires_at  timestamptz,
    note        text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent, task, scope)
);

COMMENT ON TABLE arcanum_sdk.action_broker_grants IS
  'Fail-closed scoped-operation grants. Capability code carries the fixed grant identity; a matching active, unexpired row authorises it.';

-- The single grant that authorises the R5 Family-14B negative-control run.
INSERT INTO arcanum_sdk.action_broker_grants (agent, task, scope, active, note)
VALUES ('chatgpt-echo-connector', 'echo-certification-forge-r5', 'exec.shell', true,
        'R5 Family-14B negative-control certification; loopback-only operator on ANVIL (echo.certification_forge.r5.run_negative_controls)')
ON CONFLICT (agent, task, scope)
    DO UPDATE SET active = EXCLUDED.active, note = EXCLUDED.note, updated_at = now();
