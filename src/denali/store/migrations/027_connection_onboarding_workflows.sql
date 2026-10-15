CREATE TABLE IF NOT EXISTS connection_onboarding_workflow (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES denali_tenant(id),
    request_id uuid NOT NULL,
    connection_id uuid,
    provider text NOT NULL CHECK (provider = 'github'),
    management_source text NOT NULL CHECK (management_source = 'platform'),
    stage text NOT NULL CHECK (stage IN ('external_authorization', 'select_repositories', 'attention_required')),
    status text NOT NULL CHECK (status IN ('in_progress', 'returned', 'failed')),
    return_state_sha256 text NOT NULL CHECK (return_state_sha256 ~ '^[a-f0-9]{64}$'),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    error_code text CHECK (error_code IS NULL OR error_code IN ('setup_unavailable', 'authorization_failed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider, request_id),
    UNIQUE (return_state_sha256),
    FOREIGN KEY (tenant_id, connection_id) REFERENCES provider_connection(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS connection_onboarding_workflow_tenant_idx
    ON connection_onboarding_workflow (tenant_id, created_at DESC);
