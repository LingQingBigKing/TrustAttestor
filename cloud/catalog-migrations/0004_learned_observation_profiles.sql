CREATE TABLE IF NOT EXISTS learned_observation_profiles (
  profile_hash TEXT PRIMARY KEY CHECK (length(profile_hash) = 64),
  firmware_key TEXT NOT NULL CHECK (length(firmware_key) = 64),
  profile_json TEXT NOT NULL,
  device_norm TEXT NOT NULL,
  model_norm TEXT NOT NULL,
  product_norm TEXT NOT NULL,
  sku_norm TEXT NOT NULL DEFAULT '',
  manufacturer_norm TEXT NOT NULL,
  brand_norm TEXT NOT NULL,
  board_platform_norm TEXT NOT NULL,
  fingerprint_norm TEXT NOT NULL,
  soc_model_norm TEXT NOT NULL DEFAULT '',
  soc_manufacturer_norm TEXT NOT NULL DEFAULT '',
  hardware_norm TEXT NOT NULL DEFAULT '',
  os_release_norm TEXT NOT NULL,
  sdk INTEGER,
  security_patch_norm TEXT NOT NULL,
  tee_os_version TEXT NOT NULL,
  tee_os_patch_level TEXT NOT NULL,
  tee_vendor_patch_level TEXT NOT NULL DEFAULT '',
  tee_boot_patch_level TEXT NOT NULL DEFAULT '',
  consensus_state TEXT NOT NULL DEFAULT 'LEARNING'
    CHECK (consensus_state IN ('LEARNING', 'TRUSTED', 'CONFLICT', 'REVOKED')),
  review_state TEXT NOT NULL DEFAULT 'PENDING'
    CHECK (review_state IN ('PENDING', 'APPROVED', 'REJECTED')),
  observation_count INTEGER NOT NULL DEFAULT 1 CHECK (observation_count >= 1),
  distinct_source_count INTEGER NOT NULL DEFAULT 0 CHECK (distinct_source_count >= 0),
  first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reviewed_at TEXT,
  review_note TEXT NOT NULL DEFAULT '',
  CHECK (soc_model_norm <> '' OR hardware_norm <> '')
);

CREATE INDEX IF NOT EXISTS idx_learned_observation_firmware
  ON learned_observation_profiles(firmware_key, review_state, consensus_state, distinct_source_count);

CREATE INDEX IF NOT EXISTS idx_learned_observation_device
  ON learned_observation_profiles(device_norm, model_norm, consensus_state, last_seen_at);

CREATE INDEX IF NOT EXISTS idx_learned_observation_review
  ON learned_observation_profiles(review_state, consensus_state, last_seen_at);

CREATE TABLE IF NOT EXISTS learned_observation_sources (
  profile_hash TEXT NOT NULL,
  source_key_hash TEXT NOT NULL CHECK (length(source_key_hash) = 64),
  observation_count INTEGER NOT NULL DEFAULT 1 CHECK (observation_count >= 1),
  first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (profile_hash, source_key_hash),
  FOREIGN KEY (profile_hash)
    REFERENCES learned_observation_profiles(profile_hash) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_learned_observation_source_retention
  ON learned_observation_sources(last_seen_at, profile_hash);
