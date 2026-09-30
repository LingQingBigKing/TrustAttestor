CREATE TABLE IF NOT EXISTS google_attestation_revocation_syncs (
  sync_id TEXT PRIMARY KEY CHECK (length(sync_id) BETWEEN 8 AND 80),
  source_url TEXT NOT NULL CHECK (length(source_url) BETWEEN 1 AND 512),
  started_at TEXT NOT NULL,
  completed_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('APPLYING', 'SUCCESS', 'FAILED')),
  source_last_modified TEXT,
  cache_control TEXT,
  cache_max_age_seconds INTEGER,
  payload_sha256 TEXT
    CHECK (payload_sha256 IS NULL OR (
      payload_sha256 = lower(payload_sha256)
      AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
      AND length(payload_sha256) = 64
    )),
  entry_count INTEGER NOT NULL DEFAULT 0 CHECK (entry_count >= 0),
  revoked_count INTEGER NOT NULL DEFAULT 0 CHECK (revoked_count >= 0),
  suspended_count INTEGER NOT NULL DEFAULT 0 CHECK (suspended_count >= 0),
  removed_certificate_count INTEGER NOT NULL DEFAULT 0 CHECK (removed_certificate_count >= 0),
  removed_serial_count INTEGER NOT NULL DEFAULT 0 CHECK (removed_serial_count >= 0),
  error TEXT CHECK (error IS NULL OR length(error) <= 1024)
);

CREATE INDEX IF NOT EXISTS idx_google_attestation_revocation_syncs_status
  ON google_attestation_revocation_syncs(status, started_at);

CREATE TABLE IF NOT EXISTS google_attestation_revocations (
  serial_number TEXT PRIMARY KEY
    CHECK (serial_number = lower(serial_number))
    CHECK (serial_number NOT GLOB '*[^0-9a-f]*')
    CHECK (length(serial_number) BETWEEN 1 AND 128),
  status TEXT NOT NULL CHECK (status IN ('REVOKED', 'SUSPENDED')),
  expires_on TEXT CHECK (expires_on IS NULL OR length(expires_on) = 10),
  reason TEXT CHECK (reason IS NULL OR reason IN (
    'UNSPECIFIED', 'KEY_COMPROMISE', 'CA_COMPROMISE', 'SUPERSEDED', 'SOFTWARE_FLAW'
  )),
  comment TEXT CHECK (comment IS NULL OR length(comment) <= 140),
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  seen_in_sync_id TEXT NOT NULL REFERENCES google_attestation_revocation_syncs(sync_id),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_google_attestation_revocations_active
  ON google_attestation_revocations(active, serial_number, status);

CREATE TABLE IF NOT EXISTS google_attestation_revocation_state (
  singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
  last_sync_id TEXT NOT NULL REFERENCES google_attestation_revocation_syncs(sync_id),
  last_successful_sync_at TEXT NOT NULL,
  stale_after TEXT NOT NULL,
  source_last_modified TEXT,
  cache_control TEXT,
  cache_max_age_seconds INTEGER NOT NULL CHECK (cache_max_age_seconds >= 0),
  payload_sha256 TEXT NOT NULL
    CHECK (payload_sha256 = lower(payload_sha256))
    CHECK (payload_sha256 NOT GLOB '*[^0-9a-f]*')
    CHECK (length(payload_sha256) = 64),
  entry_count INTEGER NOT NULL CHECK (entry_count >= 0),
  revoked_count INTEGER NOT NULL CHECK (revoked_count >= 0),
  suspended_count INTEGER NOT NULL CHECK (suspended_count >= 0)
);

CREATE TABLE IF NOT EXISTS revoked_keybox_certificate_archive (
  certificate_sha256 TEXT PRIMARY KEY
    CHECK (certificate_sha256 = lower(certificate_sha256))
    CHECK (certificate_sha256 NOT GLOB '*[^0-9a-f]*')
    CHECK (length(certificate_sha256) = 64),
  serial_number TEXT NOT NULL,
  issuer_spki_sha256 TEXT,
  blacklist_source TEXT NOT NULL,
  blacklist_reason TEXT NOT NULL,
  blacklist_first_seen_at TEXT,
  import_batch_id TEXT NOT NULL,
  google_status TEXT NOT NULL CHECK (google_status = 'REVOKED'),
  google_reason TEXT,
  google_comment TEXT,
  google_expires_on TEXT,
  google_sync_id TEXT NOT NULL,
  archived_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_revoked_keybox_certificate_archive_serial
  ON revoked_keybox_certificate_archive(serial_number, archived_at);

CREATE TABLE IF NOT EXISTS revoked_keybox_serial_archive (
  serial_number TEXT PRIMARY KEY,
  blacklist_source TEXT NOT NULL,
  blacklist_reason TEXT NOT NULL,
  blacklist_first_seen_at TEXT,
  google_status TEXT NOT NULL CHECK (google_status = 'REVOKED'),
  google_reason TEXT,
  google_comment TEXT,
  google_expires_on TEXT,
  google_sync_id TEXT NOT NULL,
  archived_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
