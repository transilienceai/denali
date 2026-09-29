-- One immutable audit/idempotency record for each gateway governance action.
CREATE TABLE gateway_governance_action (
    tenant_id uuid NOT NULL REFERENCES denali_tenant (id),
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
    request_hash text NOT NULL,
    actor_user_id text NOT NULL,
    asset_id uuid NOT NULL,
    result jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, idempotency_key)
);

CREATE INDEX gateway_governance_action_asset_idx
    ON gateway_governance_action (tenant_id, asset_id, created_at DESC);
