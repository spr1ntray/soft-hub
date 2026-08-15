ALTER TABLE runs
ADD COLUMN catalog_sections_json TEXT NOT NULL DEFAULT '["general"]';

WITH run_manifest_snapshots AS (
    SELECT
        r.id AS run_id,
        COALESCE(
            v.manifest_json,
            CASE WHEN m.version = r.module_version THEN m.manifest_json END
        ) AS manifest_json
    FROM runs AS r
    JOIN modules AS m ON m.id = r.module_id
    LEFT JOIN module_versions AS v
        ON v.module_id = r.module_id
       AND v.version = r.module_version
)
UPDATE runs
SET catalog_sections_json = COALESCE(
    (
        SELECT CASE
            WHEN NOT json_valid(v.manifest_json)
                THEN '["general"]'
            WHEN json_type(v.manifest_json, '$.catalog.sections') = 'array'
                 AND json_array_length(v.manifest_json, '$.catalog.sections') = 1
                 AND json_extract(v.manifest_json, '$.catalog.sections[0]')
                     IN ('general', 'nft', 'testnet')
                THEN CASE json_extract(v.manifest_json, '$.catalog.sections[0]')
                    WHEN 'nft' THEN '["nft"]'
                    WHEN 'testnet' THEN '["testnet"]'
                    ELSE '["general"]'
                END
            WHEN json_type(v.manifest_json, '$.catalog.sections') = 'array'
                 AND json_array_length(v.manifest_json, '$.catalog.sections') = 2
                 AND EXISTS (
                     SELECT 1 FROM json_each(v.manifest_json, '$.catalog.sections')
                     WHERE value = 'nft'
                 )
                 AND EXISTS (
                     SELECT 1 FROM json_each(v.manifest_json, '$.catalog.sections')
                     WHERE value = 'testnet'
                 )
                THEN '["nft","testnet"]'
            WHEN (
                     json_extract(v.manifest_json, '$.permissions.financial_risk') = 'testnet'
                     OR EXISTS (
                         SELECT 1
                         FROM json_each(v.manifest_json, '$.actions') AS action
                         WHERE CASE
                             WHEN action.type = 'object'
                                 THEN json_extract(action.value, '$.risk')
                             ELSE NULL
                         END = 'testnet_write'
                     )
                 )
                THEN '["testnet"]'
            ELSE '["general"]'
        END
        FROM run_manifest_snapshots AS v
        WHERE v.run_id = runs.id
        LIMIT 1
    ),
    '["general"]'
);
