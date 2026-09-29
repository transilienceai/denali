-- Immutable idempotency/audit records for gateway-originated manual response decisions.
CREATE TABLE gateway_runtime_response_action (
    tenant_id uuid NOT NULL REFERENCES denali_tenant (id),
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
    request_hash text NOT NULL,
    actor_user_id text NOT NULL,
    action_kind text NOT NULL CHECK (action_kind IN ('request', 'review')),
    detection_id uuid NOT NULL,
    response_id uuid,
    result jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, idempotency_key)
);

CREATE INDEX gateway_runtime_response_action_detection_idx
    ON gateway_runtime_response_action (tenant_id, detection_id, created_at DESC);
