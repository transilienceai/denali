-- Strengthen evidence references without moving, repairing, or deleting rows.
-- This migration is transactional. A historical tenant mismatch aborts the whole
-- migration; an operator must investigate it rather than silently losing evidence.
-- Keep local Compose tenants valid: this does not require a Clerk registry row.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

CREATE UNIQUE INDEX IF NOT EXISTS activity_event_tenant_id_id_idx
    ON activity_event (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS relationship_assertion_tenant_id_id_idx
    ON relationship_assertion (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS issue_tenant_id_id_idx
    ON issue (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS vulnerability_tenant_id_id_idx
    ON vulnerability (tenant_id, id);

DO $$
DECLARE
    reference record;
    mismatched boolean;
    delete_clause text;
BEGIN
    -- Fixed, reviewed list: do not infer new relationships from a live catalog.
    -- Existing asset/finding/runtime_detection tenant+ID indexes were added by
    -- earlier migrations. Preserve every original CASCADE/RESTRICT/SET NULL action.
    FOR reference IN
        SELECT * FROM (VALUES
            ('asset_assertion', 'asset_id', 'asset', 'CASCADE', 'asset_assertion_asset_id_fkey', 'asset_assertion_tenant_asset_fk'),
            ('relationship_assertion', 'source_asset_id', 'asset', 'CASCADE', 'relationship_assertion_source_asset_id_fkey', 'relationship_assertion_tenant_source_fk'),
            ('relationship_assertion', 'target_asset_id', 'asset', 'CASCADE', 'relationship_assertion_target_asset_id_fkey', 'relationship_assertion_tenant_target_fk'),
            ('relationship_assertion', 'principal_asset_id', 'asset', 'SET NULL', 'relationship_assertion_principal_asset_id_fkey', 'relationship_assertion_tenant_principal_fk'),
            ('relationship_assertion', 'agent_asset_id', 'asset', 'SET NULL', 'relationship_assertion_agent_asset_id_fkey', 'relationship_assertion_tenant_agent_fk'),
            ('finding_resource', 'finding_id', 'finding', 'CASCADE', 'finding_resource_finding_id_fkey', 'finding_resource_tenant_finding_fk'),
            ('finding_compliance', 'finding_id', 'finding', 'CASCADE', 'finding_compliance_finding_id_fkey', 'finding_compliance_tenant_finding_fk'),
            ('finding_observation', 'finding_id', 'finding', 'CASCADE', 'finding_observation_finding_id_fkey', 'finding_observation_tenant_finding_fk'),
            ('issue_finding', 'issue_id', 'issue', 'CASCADE', 'issue_finding_issue_id_fkey', 'issue_finding_tenant_issue_fk'),
            ('issue_finding', 'finding_id', 'finding', 'RESTRICT', 'issue_finding_finding_id_fkey', 'issue_finding_tenant_finding_fk'),
            ('issue_path_node', 'issue_id', 'issue', 'CASCADE', 'issue_path_node_issue_id_fkey', 'issue_path_node_tenant_issue_fk'),
            ('issue_path_node', 'asset_id', 'asset', 'RESTRICT', 'issue_path_node_asset_id_fkey', 'issue_path_node_tenant_asset_fk'),
            ('issue_path_edge', 'issue_id', 'issue', 'CASCADE', 'issue_path_edge_issue_id_fkey', 'issue_path_edge_tenant_issue_fk'),
            ('issue_path_edge', 'relationship_id', 'relationship_assertion', 'RESTRICT', 'issue_path_edge_relationship_id_fkey', 'issue_path_edge_tenant_relationship_fk'),
            ('vulnerability', 'component_asset_id', 'asset', 'SET NULL', 'vulnerability_component_asset_id_fkey', 'vulnerability_tenant_component_fk'),
            ('vulnerability', 'target_asset_id', 'asset', 'SET NULL', 'vulnerability_target_asset_id_fkey', 'vulnerability_tenant_target_fk'),
            ('vulnerability_observation', 'vulnerability_id', 'vulnerability', 'CASCADE', 'vulnerability_observation_vulnerability_id_fkey', 'vulnerability_observation_tenant_vulnerability_fk'),
            ('vulnerability_scan', 'target_asset_id', 'asset', 'SET NULL', 'vulnerability_scan_target_asset_id_fkey', 'vulnerability_scan_tenant_target_fk'),
            ('activity_entity', 'activity_id', 'activity_event', 'CASCADE', 'activity_entity_activity_id_fkey', 'activity_entity_tenant_activity_fk'),
            ('activity_entity', 'asset_id', 'asset', 'SET NULL', 'activity_entity_asset_id_fkey', 'activity_entity_tenant_asset_fk'),
            ('runtime_detection_activity', 'detection_id', 'runtime_detection', 'CASCADE', 'runtime_detection_activity_detection_id_fkey', 'runtime_detection_activity_tenant_detection_fk'),
            ('runtime_detection_activity', 'activity_id', 'activity_event', 'RESTRICT', 'runtime_detection_activity_activity_id_fkey', 'runtime_detection_activity_tenant_activity_fk'),
            ('runtime_detection_asset', 'detection_id', 'runtime_detection', 'CASCADE', 'runtime_detection_asset_detection_id_fkey', 'runtime_detection_asset_tenant_detection_fk'),
            ('runtime_detection_asset', 'asset_id', 'asset', 'RESTRICT', 'runtime_detection_asset_asset_id_fkey', 'runtime_detection_asset_tenant_asset_fk'),
            ('issue_detection', 'issue_id', 'issue', 'CASCADE', 'issue_detection_issue_id_fkey', 'issue_detection_tenant_issue_fk'),
            ('issue_detection', 'detection_id', 'runtime_detection', 'RESTRICT', 'issue_detection_detection_id_fkey', 'issue_detection_tenant_detection_fk'),
            ('issue_activity', 'issue_id', 'issue', 'CASCADE', 'issue_activity_issue_id_fkey', 'issue_activity_tenant_issue_fk'),
            ('issue_activity', 'activity_id', 'activity_event', 'RESTRICT', 'issue_activity_activity_id_fkey', 'issue_activity_tenant_activity_fk')
        ) AS references_to_harden(child_table, child_column, parent_table, delete_action,
                                  old_constraint, new_constraint)
    LOOP
        EXECUTE format(
            'SELECT EXISTS (SELECT 1 FROM %I child JOIN %I parent ON child.%I = parent.id '
            'WHERE child.tenant_id <> parent.tenant_id)',
            reference.child_table, reference.parent_table, reference.child_column
        ) INTO mismatched;
        IF mismatched THEN
            -- Report only the fixed schema location, never evidence or row values.
            RAISE EXCEPTION 'Tenant reference mismatch in %.%; migration stopped without repair',
                reference.child_table, reference.child_column USING ERRCODE = '23503';
        END IF;

        delete_clause := reference.delete_action;
        IF delete_clause = 'SET NULL' THEN
            -- PostgreSQL 16+ column-list syntax preserves the non-null tenant_id.
            delete_clause := format('SET NULL (%I)', reference.child_column);
        END IF;
        BEGIN
            EXECUTE format(
                'ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (tenant_id, %I) '
                'REFERENCES %I (tenant_id, id) ON DELETE %s NOT VALID',
                reference.child_table, reference.new_constraint, reference.child_column,
                reference.parent_table, delete_clause
            );
            EXECUTE format('ALTER TABLE %I VALIDATE CONSTRAINT %I',
                           reference.child_table, reference.new_constraint);
        EXCEPTION WHEN foreign_key_violation THEN
            -- A legacy writer can race the preflight before ALTER obtains its
            -- lock. Never leak PostgreSQL's row-value DETAIL from validation.
            RAISE EXCEPTION 'Tenant reference validation failed in %.%; migration stopped without repair',
                reference.child_table, reference.child_column USING ERRCODE = '23503';
        END;
        -- Retain the old constraint until its stronger replacement is validated.
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I',
                       reference.child_table, reference.old_constraint);
    END LOOP;
END
$$;

-- Migration 012 normally supplies this stronger reference, but its historical
-- conname-only guard could observe a same-named constraint in another schema.
-- Check the actual target relation and parent/key identity before removing the
-- redundant ID-only reference. Do not edit the already-applied migration 012.
DO $$
DECLARE
    child_table oid := 'connection_validation'::regclass;
    parent_table oid := 'provider_connection'::regclass;
    existing_constraint record;
    child_keys smallint[];
    parent_keys smallint[];
BEGIN
    child_keys := ARRAY[
        (SELECT attnum FROM pg_attribute WHERE attrelid = child_table AND attname = 'tenant_id'),
        (SELECT attnum FROM pg_attribute WHERE attrelid = child_table AND attname = 'connection_id')
    ];
    parent_keys := ARRAY[
        (SELECT attnum FROM pg_attribute WHERE attrelid = parent_table AND attname = 'tenant_id'),
        (SELECT attnum FROM pg_attribute WHERE attrelid = parent_table AND attname = 'id')
    ];
    SELECT * INTO existing_constraint FROM pg_constraint
        WHERE conrelid = child_table AND conname = 'connection_validation_tenant_connection_fk';
    IF NOT FOUND THEN
        ALTER TABLE connection_validation
            ADD CONSTRAINT connection_validation_tenant_connection_fk
            FOREIGN KEY (tenant_id, connection_id)
            REFERENCES provider_connection (tenant_id, id) ON DELETE CASCADE NOT VALID;
    ELSIF existing_constraint.contype IS DISTINCT FROM 'f'
       OR existing_constraint.confrelid IS DISTINCT FROM parent_table
       OR existing_constraint.conkey IS DISTINCT FROM child_keys
       OR existing_constraint.confkey IS DISTINCT FROM parent_keys
       OR existing_constraint.confdeltype IS DISTINCT FROM 'c'
       OR existing_constraint.confupdtype IS DISTINCT FROM 'a'
       OR existing_constraint.confmatchtype IS DISTINCT FROM 's'
       OR existing_constraint.condeferrable IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'Unexpected tenant connection reference; migration stopped without repair'
            USING ERRCODE = '23503';
    END IF;
    ALTER TABLE connection_validation
        VALIDATE CONSTRAINT connection_validation_tenant_connection_fk;
    ALTER TABLE connection_validation
        DROP CONSTRAINT connection_validation_connection_id_fkey;
EXCEPTION WHEN foreign_key_violation THEN
    RAISE EXCEPTION 'Tenant reference validation failed in connection_validation.connection_id; migration stopped without repair'
        USING ERRCODE = '23503';
END
$$;
