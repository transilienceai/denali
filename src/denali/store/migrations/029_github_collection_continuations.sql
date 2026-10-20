-- Metadata-only, resumable GitHub source jobs. No tokens or source blobs belong here.
ALTER TABLE connection_collection_job
    ADD COLUMN checkpoint jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(checkpoint) = 'object'),
    ADD COLUMN continuation_count integer NOT NULL DEFAULT 0 CHECK (continuation_count >= 0),
    ADD COLUMN retry_count integer NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    ADD COLUMN available_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();

CREATE INDEX connection_collection_job_github_resume_idx
    ON connection_collection_job (available_at, updated_at, id)
    WHERE collection_kind = 'github_source' AND state IN ('queued', 'running');
