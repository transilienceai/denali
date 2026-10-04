-- Azure model deployment names are only exact within a Foundry project.
-- Rewrite retained metadata-only runtime references before independent inventory
-- resolves them; do not change already-linked historical entities.

UPDATE activity_entity entity
SET asset_natural_key = lower(event.attributes->>'microsoft.foundry.project.id')
                        || '/model-deployments/'
                        || lower(event.attributes->>'gen_ai.request.model')
FROM activity_event event
WHERE entity.tenant_id = event.tenant_id
  AND entity.activity_id = event.id
  AND entity.asset_id IS NULL
  AND entity.role = 'model'
  AND entity.asset_kind = 'ai_model'
  AND event.provider = 'azure_foundry'
  AND event.attributes->>'microsoft.foundry.project.id' IS NOT NULL
  AND event.attributes->>'gen_ai.request.model' IS NOT NULL;
