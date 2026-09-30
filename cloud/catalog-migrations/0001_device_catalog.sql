CREATE TABLE IF NOT EXISTS catalog_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_catalog (
  device_norm TEXT NOT NULL,
  model_norm TEXT NOT NULL,
  name TEXT NOT NULL,
  device TEXT NOT NULL,
  model TEXT NOT NULL,
  PRIMARY KEY (device_norm, model_norm)
);

CREATE INDEX IF NOT EXISTS idx_device_catalog_device
  ON device_catalog(device_norm);

CREATE INDEX IF NOT EXISTS idx_device_catalog_model
  ON device_catalog(model_norm);

CREATE TABLE IF NOT EXISTS soc_catalog (
  query_key TEXT NOT NULL,
  query_key_norm TEXT NOT NULL,
  query_key_compact TEXT NOT NULL,
  identity_id TEXT NOT NULL,
  canonical_id TEXT NOT NULL,
  vendor TEXT NOT NULL,
  vendor_norm TEXT NOT NULL,
  name TEXT NOT NULL,
  fab TEXT NOT NULL,
  cpu TEXT NOT NULL,
  memory TEXT NOT NULL,
  bandwidth TEXT NOT NULL,
  channels TEXT NOT NULL,
  PRIMARY KEY (query_key_norm, query_key)
);

CREATE INDEX IF NOT EXISTS idx_soc_catalog_query_norm
  ON soc_catalog(query_key_norm);

CREATE INDEX IF NOT EXISTS idx_soc_catalog_query_compact
  ON soc_catalog(query_key_compact);

CREATE INDEX IF NOT EXISTS idx_soc_catalog_identity
  ON soc_catalog(identity_id);
