CREATE TABLE IF NOT EXISTS kernel_risk_signatures (
  signature_id TEXT PRIMARY KEY,
  match_field TEXT NOT NULL CHECK (match_field IN ('release', 'build_version', 'machine', 'any')),
  needle_norm TEXT NOT NULL CHECK (length(needle_norm) BETWEEN 1 AND 256),
  status TEXT NOT NULL CHECK (status IN ('DETECTED', 'WARNING')),
  severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  title TEXT NOT NULL,
  reason TEXT NOT NULL,
  source TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_kernel_risk_signatures_active
  ON kernel_risk_signatures(active, signature_id);

CREATE TABLE IF NOT EXISTS kernel_device_baselines (
  baseline_id TEXT PRIMARY KEY,
  device_norm TEXT NOT NULL,
  model_norm TEXT NOT NULL DEFAULT '',
  sdk_min INTEGER,
  sdk_max INTEGER,
  release_prefix_norm TEXT NOT NULL DEFAULT '',
  build_version_contains_norm TEXT NOT NULL DEFAULT '',
  machine_norm TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK (sdk_min IS NULL OR sdk_max IS NULL OR sdk_min <= sdk_max),
  CHECK (release_prefix_norm <> '' OR build_version_contains_norm <> '' OR machine_norm <> '')
);

CREATE INDEX IF NOT EXISTS idx_kernel_device_baselines_lookup
  ON kernel_device_baselines(active, device_norm, model_norm, sdk_min, sdk_max);

CREATE TABLE IF NOT EXISTS device_hardware_baselines (
  baseline_id TEXT PRIMARY KEY,
  device_norm TEXT NOT NULL,
  model_norm TEXT NOT NULL DEFAULT '',
  manufacturer_norm TEXT NOT NULL DEFAULT '',
  brand_norm TEXT NOT NULL DEFAULT '',
  product_norm TEXT NOT NULL DEFAULT '',
  sku_norm TEXT NOT NULL DEFAULT '',
  board_platform_norm TEXT NOT NULL DEFAULT '',
  soc_model_norm TEXT NOT NULL DEFAULT '',
  soc_manufacturer_norm TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_device_hardware_baselines_lookup
  ON device_hardware_baselines(active, device_norm, model_norm);

INSERT INTO kernel_risk_signatures
  (signature_id, match_field, needle_norm, status, severity, title, reason, source)
VALUES
  ('build-github-actions', 'build_version', 'github-actions', 'DETECTED', 'HIGH', '内核构建环境命中自动化托管特征', '构建标识包含 github-actions，不符合当前官方内核构建基线', 'TrustAttestor ruleset v4'),
  ('build-wsl', 'build_version', 'wsl', 'DETECTED', 'HIGH', '内核构建环境命中 WSL 特征', '构建标识包含 wsl，疑似第三方本地构建环境', 'TrustAttestor ruleset v4'),
  ('build-dirty', 'any', 'dirty', 'WARNING', 'MEDIUM', '内核指纹包含 dirty 标记', 'dirty 可能表示存在未提交修改，证据较弱，仅警告', 'TrustAttestor ruleset v4'),
  ('build-custom', 'any', 'custom', 'WARNING', 'MEDIUM', '内核指纹包含 custom 标记', 'custom 可能来自第三方或厂商自定义构建，证据较弱，仅警告', 'TrustAttestor ruleset v4')
ON CONFLICT(signature_id) DO UPDATE SET
  match_field = excluded.match_field,
  needle_norm = excluded.needle_norm,
  status = excluded.status,
  severity = excluded.severity,
  title = excluded.title,
  reason = excluded.reason,
  source = excluded.source,
  active = 1,
  updated_at = CURRENT_TIMESTAMP;
