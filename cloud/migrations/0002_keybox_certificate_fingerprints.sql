CREATE TABLE IF NOT EXISTS keybox_blacklist_imports (
  batch_id TEXT PRIMARY KEY
    CHECK (length(batch_id) BETWEEN 8 AND 80),
  input_sha256 TEXT NOT NULL UNIQUE
    CHECK (input_sha256 = lower(input_sha256))
    CHECK (input_sha256 NOT GLOB '*[^0-9a-f]*')
    CHECK (length(input_sha256) = 64),
  artifact_sha256 TEXT
    CHECK (artifact_sha256 IS NULL OR (
      artifact_sha256 = lower(artifact_sha256)
      AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'
      AND length(artifact_sha256) = 64
    )),
  source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 256),
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
  feature_count INTEGER NOT NULL CHECK (feature_count BETWEEN 1 AND 1000000),
  imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS leaked_keybox_certificates (
  certificate_sha256 TEXT PRIMARY KEY
    CHECK (certificate_sha256 = lower(certificate_sha256))
    CHECK (certificate_sha256 NOT GLOB '*[^0-9a-f]*')
    CHECK (length(certificate_sha256) = 64),
  serial_number TEXT NOT NULL
    CHECK (serial_number = lower(serial_number))
    CHECK (serial_number NOT GLOB '*[^0-9a-f]*')
    CHECK (length(serial_number) BETWEEN 1 AND 128),
  issuer_spki_sha256 TEXT
    CHECK (issuer_spki_sha256 IS NULL OR (
      issuer_spki_sha256 = lower(issuer_spki_sha256)
      AND issuer_spki_sha256 NOT GLOB '*[^0-9a-f]*'
      AND length(issuer_spki_sha256) = 64
    )),
  source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 256),
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
  first_seen_at TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  import_batch_id TEXT NOT NULL REFERENCES keybox_blacklist_imports(batch_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_leaked_keybox_certificates_serial_issuer
  ON leaked_keybox_certificates(serial_number, issuer_spki_sha256)
  WHERE issuer_spki_sha256 IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_leaked_keybox_certificates_active_hash
  ON leaked_keybox_certificates(active, certificate_sha256);

CREATE INDEX IF NOT EXISTS idx_leaked_keybox_certificates_active_serial_issuer
  ON leaked_keybox_certificates(active, serial_number, issuer_spki_sha256);

CREATE TABLE IF NOT EXISTS keybox_blacklist_evidence (
  certificate_sha256 TEXT NOT NULL REFERENCES leaked_keybox_certificates(certificate_sha256),
  batch_id TEXT NOT NULL REFERENCES keybox_blacklist_imports(batch_id),
  source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 256),
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
  first_seen_at TEXT,
  recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (certificate_sha256, batch_id)
);
