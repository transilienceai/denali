ALTER TABLE activity_event
    ADD COLUMN IF NOT EXISTS session_key text,
    ADD COLUMN IF NOT EXISTS span_uid text,
    ADD COLUMN IF NOT EXISTS parent_span_uid text,
    ADD COLUMN IF NOT EXISTS completed_at timestamptz,
    ADD COLUMN IF NOT EXISTS duration_ms double precision,
    ADD COLUMN IF NOT EXISTS telemetry_convention text,
    ADD COLUMN IF NOT EXISTS content_policy text NOT NULL DEFAULT 'metadata_only';

ALTER TABLE activity_event
    DROP CONSTRAINT IF EXISTS activity_event_runtime_span_check;

ALTER TABLE activity_event
    ADD CONSTRAINT activity_event_runtime_span_check CHECK (
        (completed_at IS NULL OR completed_at >= occurred_at)
        AND (
            duration_ms IS NULL OR (
                duration_ms >= 0
                AND duration_ms <> 'NaN'::double precision
                AND duration_ms <> 'Infinity'::double precision
            )
        )
        AND content_policy IN ('metadata_only', 'redacted', 'explicit_content')
    );

CREATE INDEX IF NOT EXISTS activity_event_tenant_session_idx
    ON activity_event (tenant_id, session_key, occurred_at, id)
    WHERE session_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS activity_event_tenant_trace_idx
    ON activity_event (tenant_id, provider, connection_id, trace_uid, occurred_at, id)
    WHERE trace_uid IS NOT NULL;

CREATE INDEX IF NOT EXISTS activity_event_tenant_span_idx
    ON activity_event (tenant_id, trace_uid, span_uid)
    WHERE trace_uid IS NOT NULL AND span_uid IS NOT NULL;

ALTER TABLE connection_collection_job
    DROP CONSTRAINT IF EXISTS connection_collection_job_collection_kind_check;

ALTER TABLE connection_collection_job
    ADD CONSTRAINT connection_collection_job_collection_kind_check
    CHECK (
        collection_kind IN (
            'entra_ai',
            'aws_deployments',
            'aws_agent_runtime',
            'azure_deployments',
            'gcp_deployments',
            'github_source',
            'azure_repos_source',
            'google_workspace_ai'
        )
    );

CREATE UNIQUE INDEX IF NOT EXISTS runtime_detection_tenant_id_id_idx
    ON runtime_detection (tenant_id, id);

CREATE TABLE IF NOT EXISTS runtime_response_request (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    detection_id uuid NOT NULL,
    target_asset_id uuid,
    action_type text NOT NULL CHECK (action_type IN (
        'preserve_and_investigate',
        'disable_agent_runtime',
        'revoke_tool_access',
        'block_model',
        'rotate_execution_identity'
    )),
    justification text NOT NULL CHECK (char_length(justification) BETWEEN 1 AND 2000),
    state text NOT NULL DEFAULT 'awaiting_approval' CHECK (
        state IN ('awaiting_approval', 'approved', 'rejected', 'cancelled')
    ),
    execution_mode text NOT NULL DEFAULT 'manual' CHECK (execution_mode = 'manual'),
    requested_by text NOT NULL,
    reviewed_by text,
    review_note text,
    requested_at timestamptz NOT NULL DEFAULT now(),
    reviewed_at timestamptz,
    CHECK (
        (state = 'awaiting_approval' AND reviewed_by IS NULL AND reviewed_at IS NULL)
        OR (state <> 'awaiting_approval' AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL)
    ),
    CONSTRAINT runtime_response_request_tenant_detection_fk
        FOREIGN KEY (tenant_id, detection_id)
        REFERENCES runtime_detection (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT runtime_response_request_tenant_asset_fk
        FOREIGN KEY (tenant_id, target_asset_id)
        REFERENCES asset (tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS runtime_response_request_tenant_detection_idx
    ON runtime_response_request (tenant_id, detection_id, requested_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS runtime_response_request_active_idx
    ON runtime_response_request (
        tenant_id, detection_id, action_type, COALESCE(target_asset_id, detection_id)
    )
    WHERE state = 'awaiting_approval';
