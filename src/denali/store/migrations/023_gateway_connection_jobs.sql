-- Immutable, tenant-scoped idempotency and audit for gateway-started Denali jobs.
-- The referenced validation/collection jobs retain their existing durable lifecycle.
CREATE TABLE gateway_connection_job_action (
    -- Keep identifiers after connection/tenant cleanup for an immutable audit.
    tenant_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
    request_hash text NOT NULL,
    actor_user_id text NOT NULL,
    connection_id uuid NOT NULL,
    job_type text NOT NULL CHECK (job_type IN ('validation', 'collection')),
    collection_kind text,
    job_id uuid NOT NULL,
    result jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, idempotency_key),
    CONSTRAINT gateway_connection_job_action_kind_check CHECK (
        (job_type = 'validation' AND collection_kind IS NULL)
        OR (job_type = 'collection' AND collection_kind IS NOT NULL)
    )
);

CREATE INDEX gateway_connection_job_action_target_idx
    ON gateway_connection_job_action
    (tenant_id, connection_id, job_type, collection_kind, created_at DESC);
