ALTER TABLE connection_onboarding_workflow
    DROP CONSTRAINT connection_onboarding_workflow_provider_check;
ALTER TABLE connection_onboarding_workflow
    ADD CONSTRAINT connection_onboarding_workflow_provider_check
    CHECK (provider IN ('github', 'azure_repos'));
ALTER TABLE connection_onboarding_workflow ADD COLUMN platform_connection_id uuid;
