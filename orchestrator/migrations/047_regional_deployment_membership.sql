-- A region can contain several explicitly adopted application deployments.
-- Startup replays migrations, including 046; replace only its old constraints.
DO $$
DECLARE old_constraint RECORD;
BEGIN
    FOR old_constraint IN
        SELECT c.conname FROM pg_constraint c
        WHERE c.conrelid='regional_application_update_targets'::regclass
          AND ((c.contype='u' AND c.conkey=ARRAY[
                  (SELECT attnum FROM pg_attribute WHERE attrelid=c.conrelid AND attname='parent_operation_id'),
                  (SELECT attnum FROM pg_attribute WHERE attrelid=c.conrelid AND attname='region')])
            OR (c.contype='f' AND c.confrelid='external_service_bindings'::regclass
                AND cardinality(c.conkey)=2))
    LOOP
        EXECUTE format('ALTER TABLE regional_application_update_targets DROP CONSTRAINT %I',old_constraint.conname);
    END LOOP;
    IF (SELECT cardinality(conkey) FROM pg_constraint
        WHERE conrelid='external_service_bindings'::regclass AND contype='p')=2 THEN
        ALTER TABLE external_service_bindings DROP CONSTRAINT external_service_bindings_pkey;
        ALTER TABLE external_service_bindings ADD PRIMARY KEY(service_id,region,deployment_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='regional_application_update_targets'::regclass
          AND conname='regional_target_deployment_binding') THEN
        ALTER TABLE regional_application_update_targets
            ADD CONSTRAINT regional_target_deployment_binding
            FOREIGN KEY(service_id,region,deployment_id)
            REFERENCES external_service_bindings(service_id,region,deployment_id);
    END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS regional_target_deployment_unique
    ON regional_application_update_targets(parent_operation_id,region,deployment_id);
