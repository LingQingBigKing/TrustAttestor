CREATE TABLE IF NOT EXISTS leaked_keybox_serials (
  serial_number TEXT PRIMARY KEY
    CHECK (serial_number = lower(serial_number))
    CHECK (serial_number NOT GLOB '*[^0-9a-f]*')
    CHECK (length(serial_number) BETWEEN 1 AND 128),
  source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 256),
  reason TEXT NOT NULL DEFAULT '已确认泄露的 Keybox' CHECK (length(reason) BETWEEN 1 AND 1024),
  first_seen_at TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_leaked_keybox_serials_active
  ON leaked_keybox_serials(active, serial_number);
