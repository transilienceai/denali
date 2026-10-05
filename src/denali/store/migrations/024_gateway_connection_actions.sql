-- Claims are committed before provider/setup side effects. An interrupted claim is
-- never automatically retried. Raw request bodies, completion codes, state-bearing
-- setup links, credentials and provider payloads are never stored in this ledger.
CREATE TABLE gateway_connection_action (
    tenant_id uuid NOT NULL REFERENCES denali_tenant (id),
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
    request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    actor_user_id text NOT NULL,
    action_kind text NOT NULL CHECK (action_kind IN (
        'create', 'setup-launch', 'setup-complete', 'disable', 'delete',
        'shared-create', 'shared-attach', 'shared-disable', 'shared-validate', 'shared-probe'
    )),
    connection_id uuid,
    state text NOT NULL DEFAULT 'claimed' CHECK (state IN ('claimed', 'completed', 'failed')),
    status_code integer CHECK (status_code BETWEEN 200 AND 599),
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    PRIMARY KEY (tenant_id, idempotency_key),
    CHECK ((state = 'claimed') = (completed_at IS NULL)),
    CHECK ((state = 'claimed') = (status_code IS NULL))
);

CREATE INDEX gateway_connection_action_target_idx
    ON gateway_connection_action (tenant_id, connection_id, created_at DESC);
