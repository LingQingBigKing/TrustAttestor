CREATE TABLE IF NOT EXISTS baseline_import_batches (
  batch_id TEXT PRIMARY KEY,
  dataset_version TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256) = 64),
  hardware_rows INTEGER NOT NULL CHECK (hardware_rows >= 0),
  firmware_rows INTEGER NOT NULL CHECK (firmware_rows >= 0),
  source_summary TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('STAGING', 'PUBLISHED', 'RETIRED')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  published_at TEXT
);

CREATE TABLE IF NOT EXISTS baseline_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS device_variant_baselines (
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
  soc_identity_id TEXT NOT NULL CHECK (length(soc_identity_id) = 32),
  source TEXT NOT NULL,
  confidence TEXT NOT NULL CHECK (confidence IN ('OFFICIAL', 'VERIFIED', 'COMMUNITY')),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (batch_id, variant_id),
  FOREIGN KEY (batch_id) REFERENCES baseline_import_batches(batch_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_device_variant_baselines_lookup
  ON device_variant_baselines(batch_id, active, device_norm, model_norm);

CREATE INDEX IF NOT EXISTS idx_device_variant_baselines_soc
  ON device_variant_baselines(batch_id, active, soc_identity_id);

CREATE TABLE IF NOT EXISTS firmware_kernel_baselines (
  batch_id TEXT NOT NULL,
  baseline_id TEXT NOT NULL,
  variant_id TEXT NOT NULL,
  sdk_min INTEGER NOT NULL,
  sdk_max INTEGER NOT NULL,
  os_release_norm TEXT NOT NULL,
  build_id_prefix_norm TEXT NOT NULL DEFAULT '',
  fingerprint_prefix_norm TEXT NOT NULL DEFAULT '',
  security_patch_min_norm TEXT NOT NULL DEFAULT '',
  security_patch_max_norm TEXT NOT NULL DEFAULT '',
  kernel_family_norm TEXT NOT NULL DEFAULT '',
  kernel_release_prefix_norm TEXT NOT NULL DEFAULT '',
  build_version_contains_norm TEXT NOT NULL DEFAULT '',
  machine_norm TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL,
  confidence TEXT NOT NULL CHECK (confidence IN ('OFFICIAL', 'VERIFIED', 'COMMUNITY')),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (batch_id, baseline_id),
  FOREIGN KEY (batch_id, variant_id)
    REFERENCES device_variant_baselines(batch_id, variant_id) ON DELETE RESTRICT,
  CHECK (sdk_min >= 1 AND sdk_max >= sdk_min),
  CHECK (kernel_family_norm <> '' OR kernel_release_prefix_norm <> '' OR build_version_contains_norm <> '' OR machine_norm <> ''),
  CHECK (security_patch_min_norm = '' OR security_patch_max_norm = '' OR security_patch_min_norm <= security_patch_max_norm)
);

CREATE INDEX IF NOT EXISTS idx_firmware_kernel_baselines_lookup
  ON firmware_kernel_baselines(batch_id, active, variant_id, sdk_min, sdk_max);

CREATE TABLE IF NOT EXISTS baseline_candidates (
  candidate_id TEXT PRIMARY KEY,
  candidate_kind TEXT NOT NULL CHECK (candidate_kind IN ('DEVICE_VARIANT', 'FIRMWARE_KERNEL')),
  payload_json TEXT NOT NULL,
  evidence_sha256 TEXT NOT NULL CHECK (length(evidence_sha256) = 64),
  observation_count INTEGER NOT NULL DEFAULT 1 CHECK (observation_count >= 1),
  distinct_source_count INTEGER NOT NULL DEFAULT 1 CHECK (distinct_source_count >= 1),
  state TEXT NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'APPROVED', 'REJECTED')),
  first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reviewed_at TEXT,
  review_note TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_baseline_candidates_review
  ON baseline_candidates(state, candidate_kind, last_seen_at);
