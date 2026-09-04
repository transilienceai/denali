ALTER TABLE connection_collection_job
    DROP CONSTRAINT IF EXISTS connection_collection_job_collection_kind_check;

ALTER TABLE connection_collection_job
    ADD CONSTRAINT connection_collection_job_collection_kind_check
    CHECK (
        collection_kind IN (
            'entra_ai',
            'aws_deployments',
            'azure_deployments',
            'gcp_deployments',
            'github_source'
        )
    );
