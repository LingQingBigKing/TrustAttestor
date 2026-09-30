ALTER TABLE baseline_import_batches
  ADD COLUMN soc_rows INTEGER NOT NULL DEFAULT 0 CHECK (soc_rows >= 0);

-- Hardware metadata and model-to-SoC bindings intentionally have independent
-- publication states. A reviewed device variant can therefore be useful even
-- while its SoC mapping is still unknown or under review.
CREATE TABLE IF NOT EXISTS device_hardware_variant_baselines (
  batch_id TEXT NOT NULL,
  variant_id TEXT NOT NULL,
  device_norm TEXT NOT NULL,
  model_norm TEXT NOT NULL,
  product_norm TEXT NOT NULL,
  sku_norm TEXT NOT NULL DEFAULT '',
  brand_norm TEXT NOT NULL,
  manufacturer_norm TEXT NOT NULL,
  board_platform_norm TEXT NOT NULL,
  fingerprint_prefix_norm TEXT NOT NULL,
  source TEXT NOT NULL,
  confidence TEXT NOT NULL CHECK (confidence IN ('OFFICIAL', 'VERIFIED', 'COMMUNITY')),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (batch_id, variant_id),
  FOREIGN KEY (batch_id) REFERENCES baseline_import_batches(batch_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_device_hardware_variant_baselines_lookup
  ON device_hardware_variant_baselines(batch_id, active, device_norm, model_norm);

CREATE TABLE IF NOT EXISTS device_soc_baselines (
  batch_id TEXT NOT NULL,
  variant_id TEXT NOT NULL,
  soc_identity_id TEXT NOT NULL CHECK (length(soc_identity_id) = 32),
  source TEXT NOT NULL,
  confidence TEXT NOT NULL CHECK (confidence IN ('OFFICIAL', 'VERIFIED', 'COMMUNITY')),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (batch_id, variant_id, soc_identity_id),
  FOREIGN KEY (batch_id, variant_id)
    REFERENCES device_hardware_variant_baselines(batch_id, variant_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_device_soc_baselines_lookup
  ON device_soc_baselines(batch_id, active, variant_id, soc_identity_id);

-- Preserve every previously published baseline while moving the verdict path
-- to the split schema. The legacy table remains for offline import compatibility.
INSERT OR IGNORE INTO device_hardware_variant_baselines (
  batch_id, variant_id, device_norm, model_norm, product_norm, sku_norm,
  brand_norm, manufacturer_norm, board_platform_norm, fingerprint_prefix_norm,
  source, confidence, active, created_at, updated_at
)
SELECT batch_id, variant_id, device_norm, model_norm, product_norm, sku_norm,
       brand_norm, manufacturer_norm, board_platform_norm, fingerprint_prefix_norm,
       source, confidence, active, created_at, updated_at
  FROM device_variant_baselines;

INSERT OR IGNORE INTO device_soc_baselines (
  batch_id, variant_id, soc_identity_id, source, confidence, active,
  created_at, updated_at
)
SELECT batch_id, variant_id, soc_identity_id, source, confidence, active,
       created_at, updated_at
  FROM device_variant_baselines;

UPDATE baseline_import_batches
   SET soc_rows = (
     SELECT COUNT(*)
       FROM device_soc_baselines AS soc
      WHERE soc.batch_id = baseline_import_batches.batch_id
   );
