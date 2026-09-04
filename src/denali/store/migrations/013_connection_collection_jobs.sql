CREATE TABLE IF NOT EXISTS connection_collection_job (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               uuid NOT NULL,
    connection_id           uuid NOT NULL,
    collection_kind         text NOT NULL CHECK (
        collection_kind IN ('entra_ai')
    ),
    state                   text NOT NULL DEFAULT 'queued' CHECK (
        state IN ('queued', 'running', 'succeeded', 'failed')
    ),
    attempt_count           integer NOT NULL DEFAULT 0,
    modal_call_id           text,
    result                  jsonb,
    error_summary           text,
    created_at              timestamptz NOT NULL DEFAULT now(),
    started_at              timestamptz,
    completed_at            timestamptz,
    lease_expires_at        timestamptz,
    CONSTRAINT connection_collection_job_tenant_connection_fk
        FOREIGN KEY (tenant_id, connection_id)
        REFERENCES provider_connection (tenant_id, id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS connection_collection_job_active_idx
    ON connection_collection_job (tenant_id, connection_id, collection_kind)
    WHERE state IN ('queued', 'running');

CREATE INDEX IF NOT EXISTS connection_collection_job_status_idx
    ON connection_collection_job (tenant_id, connection_id, collection_kind, created_at DESC);
