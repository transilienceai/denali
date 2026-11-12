-- Resolve exact runtime entity references when authoritative inventory arrives later.
--
-- Activity ingestion deliberately does not manufacture inventory assets.  Runtime
-- telemetry can therefore precede the control-plane observation that establishes
-- the referenced asset.  Keep the provider-native natural key so a later inventory
-- transaction can complete the tenant-scoped link.

CREATE INDEX IF NOT EXISTS activity_entity_unresolved_asset_ref_idx
    ON activity_entity (tenant_id, asset_kind, asset_natural_key)
    WHERE asset_id IS NULL
      AND asset_kind IS NOT NULL
      AND asset_natural_key IS NOT NULL;

UPDATE activity_entity entity
SET asset_id = asset.id
FROM asset
WHERE entity.asset_id IS NULL
  AND entity.asset_kind IS NOT NULL
  AND entity.asset_natural_key IS NOT NULL
  AND asset.tenant_id = entity.tenant_id
  AND asset.kind = entity.asset_kind
  AND asset.natural_key = entity.asset_natural_key;
