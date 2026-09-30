-- Add a privacy-preserving network diversity signal to passive observations.
-- The raw client address is never stored; the Worker stores only a keyed,
-- month-scoped HMAC pseudonym supplied by the queue producer.
ALTER TABLE learned_observation_profiles
  ADD COLUMN distinct_network_count INTEGER NOT NULL DEFAULT 0
  CHECK (distinct_network_count >= 0);

CREATE TABLE IF NOT EXISTS learned_observation_networks (
  profile_hash TEXT NOT NULL,
  network_key_hash TEXT NOT NULL CHECK (length(network_key_hash) = 64),
  observation_count INTEGER NOT NULL DEFAULT 1 CHECK (observation_count >= 1),
  first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (profile_hash, network_key_hash),
  FOREIGN KEY (profile_hash)
    REFERENCES learned_observation_profiles(profile_hash) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_learned_observation_network_retention
  ON learned_observation_networks(last_seen_at, profile_hash);
