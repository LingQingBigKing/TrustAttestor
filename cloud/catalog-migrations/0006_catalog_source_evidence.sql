-- Public catalogs, firmware dumps, community fingerprints, and hardware
-- specifications are evidence sources, not verdict baselines. Keep their raw
-- normalized facts auditable and promote only through baseline_candidates.
CREATE TABLE IF NOT EXISTS catalog_source_snapshots (
  snapshot_id TEXT PRIMARY KEY CHECK (length(snapshot_id) = 64),
  source_id TEXT NOT NULL,
  source_kind TEXT NOT NULL CHECK (source_kind IN (
    'GOOGLE_PLAY_CSV',
    'FIRMWARE_PROPS',
    'PIF_JSON',
    'HARDWARE_SPEC_CSV'
  )),
  authority TEXT NOT NULL CHECK (authority IN (
    'GOOGLE_PLAY_CATALOG',
    'FIRMWARE_DUMP',
    'COMMUNITY_FINGERPRINT',
    'OEM_PRODUCT_PAGE',
    'HARDWARE_SPEC',
    'BENCHMARK_DATABASE'
  )),
  source_uri TEXT NOT NULL,
  title TEXT NOT NULL,
  content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
  collected_at TEXT NOT NULL,
  parser_version TEXT NOT NULL,
  record_count INTEGER NOT NULL CHECK (record_count >= 0),
  metadata_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'STAGED'
    CHECK (status IN ('STAGED', 'IMPORTED', 'RETIRED')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (source_id, content_sha256)
);

CREATE INDEX IF NOT EXISTS idx_catalog_source_snapshots_review
  ON catalog_source_snapshots(status, source_kind, collected_at);

CREATE TABLE IF NOT EXISTS catalog_source_facts (
  snapshot_id TEXT NOT NULL,
  fact_id TEXT NOT NULL CHECK (length(fact_id) = 64),
  entity_key TEXT NOT NULL CHECK (length(entity_key) = 64),
  record_ref TEXT NOT NULL,
  oem_norm TEXT NOT NULL DEFAULT '',
  marketing_name_norm TEXT NOT NULL DEFAULT '',
  device_norm TEXT NOT NULL DEFAULT '',
  model_norm TEXT NOT NULL DEFAULT '',
  product_norm TEXT NOT NULL DEFAULT '',
  sku_norm TEXT NOT NULL DEFAULT '',
  brand_norm TEXT NOT NULL DEFAULT '',
  manufacturer_norm TEXT NOT NULL DEFAULT '',
  board_platform_norm TEXT NOT NULL DEFAULT '',
  soc_alias_norm TEXT NOT NULL DEFAULT '',
  fingerprint_norm TEXT NOT NULL DEFAULT '',
  security_patch_norm TEXT NOT NULL DEFAULT '',
  supported_abis_norm TEXT NOT NULL DEFAULT '',
  values_json TEXT NOT NULL,
  raw_sha256 TEXT NOT NULL CHECK (length(raw_sha256) = 64),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (snapshot_id, fact_id),
  FOREIGN KEY (snapshot_id)
    REFERENCES catalog_source_snapshots(snapshot_id) ON DELETE RESTRICT,
  CHECK (
    device_norm <> '' OR model_norm <> '' OR fingerprint_norm <> '' OR
    board_platform_norm <> '' OR soc_alias_norm <> ''
  )
);

CREATE INDEX IF NOT EXISTS idx_catalog_source_facts_device_model
  ON catalog_source_facts(device_norm, model_norm, snapshot_id);

CREATE INDEX IF NOT EXISTS idx_catalog_source_facts_model
  ON catalog_source_facts(model_norm, snapshot_id);

CREATE INDEX IF NOT EXISTS idx_catalog_source_facts_fingerprint
  ON catalog_source_facts(fingerprint_norm, snapshot_id)
  WHERE fingerprint_norm <> '';

CREATE INDEX IF NOT EXISTS idx_catalog_source_facts_entity
  ON catalog_source_facts(entity_key, snapshot_id);

CREATE TABLE IF NOT EXISTS catalog_aggregation_runs (
  run_id TEXT PRIMARY KEY CHECK (length(run_id) = 64),
  dataset_id TEXT NOT NULL,
  candidate_manifest_sha256 TEXT NOT NULL CHECK (length(candidate_manifest_sha256) = 64),
  source_snapshot_count INTEGER NOT NULL CHECK (source_snapshot_count >= 1),
  fact_count INTEGER NOT NULL CHECK (fact_count >= 0),
  candidate_count INTEGER NOT NULL CHECK (candidate_count >= 0),
  unresolved_fact_count INTEGER NOT NULL CHECK (unresolved_fact_count >= 0),
  conflict_count INTEGER NOT NULL CHECK (conflict_count >= 0),
  policy TEXT NOT NULL CHECK (policy = 'CANDIDATE_ONLY'),
  receipt_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

