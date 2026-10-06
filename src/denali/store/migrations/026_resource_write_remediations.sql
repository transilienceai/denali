CREATE UNIQUE INDEX IF NOT EXISTS finding_tenant_id_id_idx ON finding(tenant_id, id);

CREATE TABLE resource_write_preview (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES denali_tenant(id) ON DELETE CASCADE,
    clerk_org_id text NOT NULL CHECK (clerk_org_id ~ '^org_[A-Za-z0-9]+$'),
    finding_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('github.guardrail_draft_pr', 'aws.tighten_bedrock_inline_policy')),
    actor_user_id text NOT NULL CHECK (actor_user_id ~ '^user_[A-Za-z0-9]+$'),
    parameters jsonb NOT NULL,
    plan jsonb NOT NULL,
    preview_sha256 text NOT NULL CHECK (preview_sha256 ~ '^[0-9a-f]{64}$'),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, finding_id) REFERENCES finding(tenant_id, id),
    UNIQUE (tenant_id, id)
);

CREATE TABLE resource_write_request (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES denali_tenant(id) ON DELETE CASCADE,
    preview_id uuid NOT NULL UNIQUE,
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9_-]{8,128}$'),
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    justification text NOT NULL CHECK (length(justification) BETWEEN 1 AND 2000),
    actor_user_id text NOT NULL,
    reviewer_user_id text,
    review_note text,
    state text NOT NULL DEFAULT 'pending_review' CHECK (state IN (
        'pending_review', 'approved', 'rejected', 'running', 'succeeded', 'failed', 'needs_manual_resolution')),
    phase text NOT NULL DEFAULT 'not_started' CHECK (phase IN ('not_started', 'provider_attempted', 'finished')),
    grant_id uuid NOT NULL,
    lease_nonce uuid,
    lease_expires_at timestamptz,
    provider_attempted_at timestamptz,
    result jsonb,
    error_code text,
    modal_call_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, preview_id) REFERENCES resource_write_preview(tenant_id, id),
    CHECK (reviewer_user_id IS NULL OR reviewer_user_id <> actor_user_id),
    UNIQUE (tenant_id, idempotency_key),
    UNIQUE (tenant_id, id)
);
-- Prevent our own overlapping write jobs for the same explicitly opted-in grant.
CREATE UNIQUE INDEX resource_write_request_active_grant_idx
    ON resource_write_request(tenant_id, grant_id)
    WHERE state IN ('approved', 'running', 'needs_manual_resolution');

CREATE TABLE resource_write_audit_event (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL,
    request_id uuid NOT NULL,
    event_type text NOT NULL,
    actor_user_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, request_id) REFERENCES resource_write_request(tenant_id, id)
);

-- Preview bytes and request identity cannot drift after consent, even through
-- another runtime SQL caller. State/result fields remain updateable by worker.
CREATE FUNCTION deny_resource_preview_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'resource remediation preview is immutable';
END;
$$;
CREATE TRIGGER resource_preview_immutable BEFORE UPDATE ON resource_write_preview
    FOR EACH ROW EXECUTE FUNCTION deny_resource_preview_update();

CREATE FUNCTION guard_resource_request_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id, NEW.tenant_id, NEW.preview_id, NEW.idempotency_key,
           NEW.request_sha256, NEW.justification, NEW.actor_user_id, NEW.grant_id, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_id, OLD.preview_id, OLD.idempotency_key,
           OLD.request_sha256, OLD.justification, OLD.actor_user_id, OLD.grant_id, OLD.created_at)
    THEN
        RAISE EXCEPTION 'resource remediation request identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER resource_request_identity_immutable BEFORE UPDATE ON resource_write_request
    FOR EACH ROW EXECUTE FUNCTION guard_resource_request_identity();

CREATE TRIGGER resource_write_audit_append_only BEFORE UPDATE OR DELETE ON resource_write_audit_event
    FOR EACH ROW EXECUTE FUNCTION deny_resource_preview_update();
