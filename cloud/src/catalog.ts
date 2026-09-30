import type { CloudFinding, Env } from "./types";

const MAX_EXAMPLES = 6;

export interface DeviceRow {
  name: string;
  device: string;
  model: string;
  mapping_count?: number;
}

export interface SocRow {
  query_key: string;
  identity_id: string;
  canonical_id: string;
  vendor: string;
  vendor_norm: string;
  name: string;
  fab: string;
  cpu: string;
  memory: string;
  bandwidth: string;
  channels: string;
}

export interface NativeIdentityEvidence {
  model: string;
  device: string;
  board: string;
  product: string;
  manufacturer: string;
  brand: string;
  sku: string;
  hardware: string;
  boardPlatform: string;
  socManufacturer: string;
  socModel: string;
  fingerprint: string;
}

export interface DeviceLookup {
  exact?: DeviceRow;
  byDevice: DeviceRow[];
  byModel: DeviceRow[];
}

export interface SocCandidateMatch {
  source: "socModel" | "hardware" | "boardPlatform" | "board";
  value: string;
  rows: SocRow[];
}

type BaselineConfidence = "OFFICIAL" | "VERIFIED" | "COMMUNITY";

export interface DeviceHardwareBaselineRow {
  variant_id: string;
  manufacturer_norm: string;
  brand_norm: string;
  product_norm: string;
  sku_norm: string;
  board_platform_norm: string;
  fingerprint_prefix_norm: string;
  source: string;
  confidence: BaselineConfidence;
}

function finding(
  status: CloudFinding["status"],
  severity: CloudFinding["severity"],
  probeId: string,
  title: string,
  evidence: string
): CloudFinding {
  return { status, severity, probeId, title, evidence };
}

export function normalizeCatalogValue(value: string): string {
  return value.normalize("NFKC").trim().toLowerCase().replace(/\s+/gu, " ");
}

function compactCatalogValue(value: string): string {
  return normalizeCatalogValue(value).replace(/[^a-z0-9]+/gu, "");
}

function isPlaceholder(value: string): boolean {
  return ["", "unknown", "generic", "android", "null", "n/a", "na", "default"].includes(
    normalizeCatalogValue(value)
  );
}

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function text(value: unknown, maxLength = 512): string {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

export function extractNativeIdentityEvidence(value: Record<string, unknown>): NativeIdentityEvidence {
  const device = record(value.device);
  const processor = record(value.processor);
  const os = record(value.os);
  return {
    model: text(device.model),
    device: text(device.device),
    board: text(device.board),
    product: text(device.product),
    manufacturer: text(device.manufacturer),
    brand: text(device.brand),
    sku: text(device.sku),
    hardware: text(processor.hardware),
    boardPlatform: text(processor.boardPlatform),
    socManufacturer: text(processor.socManufacturer),
    socModel: text(processor.socModel),
    fingerprint: text(os.fingerprint, 1024)
  };
}

function uniqueExamples(rows: DeviceRow[], field: "device" | "model"): string[] {
  return [...new Set(rows.map((row) => row[field]).filter(Boolean))].slice(0, MAX_EXAMPLES);
}

export function classifyDeviceIdentity(
  evidence: NativeIdentityEvidence,
  lookup: DeviceLookup
): CloudFinding {
  if (isPlaceholder(evidence.device) || isPlaceholder(evidence.model)) {
    return finding(
      "UNAVAILABLE",
      "INFO",
      "cloud.device.catalog_consistency",
      "设备型号目录核验不可用",
      `Build.DEVICE=${evidence.device || "<empty>"}，Build.MODEL=${evidence.model || "<empty>"}；字段为空或属于泛化占位值。`
    );
  }
  if (lookup.exact !== undefined) {
    return finding(
      "CLEAN",
      "INFO",
      "cloud.device.catalog_consistency",
      "设备型号组合已收录",
      `Build.DEVICE=${evidence.device} 与 Build.MODEL=${evidence.model} 精确匹配目录记录${lookup.exact.name ? `（${lookup.exact.name}）` : ""}。`
    );
  }

  const deviceKnown = lookup.byDevice.length > 0;
  const modelKnown = lookup.byModel.length > 0;
  if (deviceKnown && modelKnown) {
    const expectedModels = uniqueExamples(lookup.byDevice, "model").join("、");
    const expectedDevices = uniqueExamples(lookup.byModel, "device").join("、");
    return finding(
      "WARNING",
      "MEDIUM",
      "cloud.device.catalog_consistency",
      "设备代号与型号组合冲突",
      `Build.DEVICE=${evidence.device} 与 Build.MODEL=${evidence.model} 均可独立识别，但目录中不存在该组合；该代号对应型号示例：${expectedModels || "无"}；该型号对应代号示例：${expectedDevices || "无"}。`
    );
  }
  if (deviceKnown) {
    return finding(
      "WARNING",
      "MEDIUM",
      "cloud.device.catalog_consistency",
      "设备代号已识别但型号未收录",
      `Build.DEVICE=${evidence.device} 已命中目录，但 Build.MODEL=${evidence.model} 未收录于该代号；可能是新变体、ROM 自定义或目录尚未更新。`
    );
  }
  if (modelKnown) {
    return finding(
      "WARNING",
      "MEDIUM",
      "cloud.device.catalog_consistency",
      "设备型号已识别但代号未收录",
      `Build.MODEL=${evidence.model} 已命中目录，但 Build.DEVICE=${evidence.device} 未收录于该型号；可能是区域变体、ROM 自定义或目录尚未更新。`
    );
  }
  return finding(
    "UNAVAILABLE",
    "INFO",
    "cloud.device.catalog_consistency",
    "设备型号不在当前目录中",
    `Build.DEVICE=${evidence.device}，Build.MODEL=${evidence.model} 均未命中目录；未知设备不会直接判定为异常。`
  );
}

function vendorFamily(value: string): string {
  const normalized = normalizeCatalogValue(value).replace(/[®™]/gu, "");
  const aliases: Array<[string, string[]]> = [
    ["qualcomm", ["qualcomm", "qti"]],
    ["mediatek", ["mediatek", "mtk"]],
    ["samsung", ["samsung", "slsi", "s.lsi", "exynos"]],
    ["hisilicon", ["hisilicon", "huawei", "kirin"]],
    ["unisoc", ["unisoc", "spreadtrum"]],
    ["rockchip", ["rockchip"]],
    ["google", ["google", "tensor"]],
    ["broadcom", ["broadcom", "broadcomm"]],
    ["nvidia", ["nvidia"]],
    ["intel", ["intel"]],
    ["allwinner", ["allwinner"]],
    ["amlogic", ["amlogic"]],
    ["xiaomi", ["xiaomi"]]
  ];
  return aliases.find(([, names]) => names.some((name) => normalized.includes(name)))?.[0] ?? "";
}

function bestSocRow(rows: SocRow[]): SocRow {
  return [...rows].sort((left, right) => {
    const score = (row: SocRow) => [row.vendor, row.name, row.fab, row.cpu, row.memory, row.bandwidth, row.channels]
      .filter(Boolean).length;
    return score(right) - score(left);
  })[0]!;
}

function identities(rows: SocRow[]): Map<string, SocRow[]> {
  const result = new Map<string, SocRow[]>();
  for (const row of rows) result.set(row.identity_id, [...(result.get(row.identity_id) ?? []), row]);
  return result;
}

export function classifySocIdentity(
  evidence: NativeIdentityEvidence,
  candidates: SocCandidateMatch[]
): CloudFinding {
  const matched = candidates.filter((candidate) => candidate.rows.length > 0);
  if (matched.length === 0) {
    return finding(
      "UNAVAILABLE",
      "INFO",
      "cloud.soc.catalog_consistency",
      "SoC 标识不在当前目录中",
      `ro.soc.model=${evidence.socModel || "<empty>"}，ro.hardware=${evidence.hardware || "<empty>"}，board=${evidence.board || "<empty>"}；未命中不会直接判定为异常。`
    );
  }

  const ambiguous = matched.filter((candidate) => identities(candidate.rows).size > 1);
  if (ambiguous.length > 0) {
    return finding(
      "WARNING",
      "MEDIUM",
      "cloud.soc.catalog_consistency",
      "SoC 标识在目录中存在歧义",
      ambiguous.map((candidate) => `${candidate.source}=${candidate.value}`).join("；") + " 对应多个芯片身份，无法作异常判定。"
    );
  }

  const resolved = matched.map((candidate) => ({
    ...candidate,
    row: bestSocRow(candidate.rows),
    identityId: candidate.rows[0]!.identity_id
  }));
  const strong = resolved.filter((candidate) => candidate.source !== "board");
  const strongIdentities = new Set(strong.map((candidate) => candidate.identityId));
  if (strongIdentities.size > 1) {
    return finding(
      "WARNING",
      "MEDIUM",
      "cloud.soc.catalog_consistency",
      "SoC 型号与硬件平台标识冲突",
      strong.map((candidate) => `${candidate.source}=${candidate.value}→${candidate.row.vendor} ${candidate.row.name}`).join("；")
    );
  }

  const selected = strong.find((candidate) => candidate.source === "socModel")
    ?? strong.find((candidate) => candidate.source === "hardware")
    ?? strong.find((candidate) => candidate.source === "boardPlatform")
    ?? resolved[0]!;
  const expectedVendor = vendorFamily(selected.row.vendor);
  const reportedVendor = vendorFamily(evidence.socManufacturer);
  if (expectedVendor && reportedVendor && expectedVendor !== reportedVendor) {
    return finding(
      "WARNING",
      "MEDIUM",
      "cloud.soc.catalog_consistency",
      "SoC 厂商与芯片标识冲突",
      `${selected.source}=${selected.value} 对应 ${selected.row.vendor} ${selected.row.name}，但 ro.soc.manufacturer=${evidence.socManufacturer}。`
    );
  }
  if (evidence.socManufacturer && expectedVendor && !reportedVendor) {
    return finding(
      "WARNING",
      "LOW",
      "cloud.soc.catalog_consistency",
      "SoC 厂商名称无法标准化",
      `${selected.source}=${selected.value} 对应 ${selected.row.vendor} ${selected.row.name}，但无法可靠解释 ro.soc.manufacturer=${evidence.socManufacturer}。`
    );
  }
  if (selected.source === "board") {
    return finding(
      "WARNING",
      "LOW",
      "cloud.soc.catalog_consistency",
      "仅通过主板代号识别 SoC",
      `board=${selected.value} 命中 ${selected.row.vendor} ${selected.row.name}，缺少更可靠的 ro.soc.model/ro.hardware 命中。`
    );
  }
  if (evidence.socModel && !resolved.some((candidate) => candidate.source === "socModel")) {
    return finding(
      "WARNING",
      "MEDIUM",
      "cloud.soc.catalog_consistency",
      "SoC 型号未收录但平台代号已识别",
      `ro.soc.model=${evidence.socModel} 未命中；${selected.source}=${selected.value} 对应 ${selected.row.vendor} ${selected.row.name}。`
    );
  }
  return finding(
    "CLEAN",
    "INFO",
    "cloud.soc.catalog_consistency",
    "SoC 标识内部一致",
    `${selected.source}=${selected.value} 对应 ${selected.row.vendor} ${selected.row.name}${selected.row.fab ? `（${selected.row.fab}）` : ""}${evidence.socManufacturer ? `；ro.soc.manufacturer=${evidence.socManufacturer}` : ""}。`
  );
}

function confidenceStatus(rows: Array<{ confidence: BaselineConfidence }>): Pick<CloudFinding, "status" | "severity"> {
  return rows.some((row) => row.confidence !== "COMMUNITY")
    ? { status: "DETECTED", severity: "HIGH" }
    : { status: "WARNING", severity: "MEDIUM" };
}

export function classifyHardwareBaseline(
  evidence: NativeIdentityEvidence,
  hardwareBaselines: DeviceHardwareBaselineRow[],
  exactDeviceCatalogMatch = false
): CloudFinding[] {
  if (hardwareBaselines.length === 0) {
    // An exact device/model catalog hit is already the base device identity result. Do not emit
    // another unavailable matrix item merely because no manually reviewed hardware row exists.
    if (exactDeviceCatalogMatch) return [];
    return [finding(
      "UNAVAILABLE", "INFO", "cloud.device.hardware_matrix",
      "当前机型暂无已发布硬件基线",
      `device=${evidence.device || "<empty>"}，model=${evidence.model || "<empty>"}；未知机型不会直接判定为异常。`
    )];
  }
  const actual = {
    manufacturer_norm: normalizeCatalogValue(evidence.manufacturer),
    brand_norm: normalizeCatalogValue(evidence.brand),
    product_norm: normalizeCatalogValue(evidence.product),
    sku_norm: normalizeCatalogValue(evidence.sku),
    board_platform_norm: normalizeCatalogValue(evidence.boardPlatform),
    fingerprint_prefix_norm: normalizeCatalogValue(evidence.fingerprint)
  };
  const fields = [
    "manufacturer_norm", "brand_norm", "product_norm", "sku_norm", "board_platform_norm"
  ] as const;
  const requiredFields = [
    "manufacturer_norm", "brand_norm", "product_norm", "board_platform_norm"
  ] as const;
  const missing: string[] = requiredFields.filter((field) => !actual[field]);
  const actualFingerprint = actual.fingerprint_prefix_norm;
  if (!actualFingerprint) missing.push("fingerprint_prefix_norm");
  if (missing.length > 0) {
    return [finding(
      "UNAVAILABLE", "INFO", "cloud.device.hardware_matrix",
      "设备硬件矩阵证据不完整",
      `缺少字段：${missing.join("、")}；缺失数据不会直接判定为异常。`
    )];
  }
  const metadataMatches = hardwareBaselines.filter((row) => fields.every((field) => {
    const expected = normalizeCatalogValue(String(row[field] ?? ""));
    return !expected || expected === actual[field];
  }) && actualFingerprint.startsWith(normalizeCatalogValue(row.fingerprint_prefix_norm)));
  if (metadataMatches.length === 0) {
    if (!actual.sku_norm && hardwareBaselines.every((row) => Boolean(row.sku_norm))) {
      return [finding(
        "UNAVAILABLE", "INFO", "cloud.device.hardware_matrix",
        "设备变体 SKU 证据缺失",
        "已发布基线均要求 SKU 才能区分硬件变体；缺失字段不会直接判定为异常。"
      )];
    }
    const policy = confidenceStatus(hardwareBaselines);
    const observed = [
      `manufacturer=${evidence.manufacturer}`,
      `brand=${evidence.brand}`,
      `product=${evidence.product}`,
      `sku=${evidence.sku}`,
      `boardPlatform=${evidence.boardPlatform}`,
      `fingerprint=${evidence.fingerprint}`
    ].join("；");
    return [finding(
      policy.status, policy.severity, "cloud.device.hardware_matrix",
      "设备指纹或厂商元数据偏离机型基线",
      `${observed}；未匹配 ${hardwareBaselines.length} 条已发布硬件变体。`
    )];
  }
  const matchedVariants = metadataMatches.map((row) => row.variant_id).join("、");
  return [finding(
    "CLEAN", "INFO", "cloud.device.hardware_matrix",
    "设备指纹与厂商元数据匹配",
    `variant=${matchedVariants}；已匹配品牌、产品、制造商、平台与 Build Fingerprint 前缀。`
  )];
}

async function ensureCatalogReady(env: Env): Promise<void> {
  const result = await env.DEVICE_CATALOG_DB.prepare(
    "SELECT key, value FROM catalog_metadata WHERE key IN ('catalog_status', 'catalog_version')"
  ).all<{ key: string; value: string }>();
  const metadata = new Map(result.results.map((row) => [row.key, row.value]));
  if (!result.success || metadata.get("catalog_status") !== "ready" || metadata.get("catalog_version") !== env.CATALOG_VERSION) {
    throw new Error("设备识别目录未就绪或版本不匹配");
  }
}

async function lookupDevice(env: Env, evidence: NativeIdentityEvidence): Promise<DeviceLookup> {
  const deviceNorm = normalizeCatalogValue(evidence.device);
  const modelNorm = normalizeCatalogValue(evidence.model);
  const [exact, byDevice, byModel] = await Promise.all([
    env.DEVICE_CATALOG_DB.prepare(
      "SELECT name, device, model FROM device_catalog WHERE device_norm = ? AND model_norm = ? LIMIT 1"
    ).bind(deviceNorm, modelNorm).first<DeviceRow>(),
    env.DEVICE_CATALOG_DB.prepare(
      "SELECT name, device, model, COUNT(*) OVER () AS mapping_count FROM device_catalog WHERE device_norm = ? ORDER BY model_norm LIMIT 8"
    ).bind(deviceNorm).all<DeviceRow>(),
    env.DEVICE_CATALOG_DB.prepare(
      "SELECT name, device, model, COUNT(*) OVER () AS mapping_count FROM device_catalog WHERE model_norm = ? ORDER BY device_norm LIMIT 8"
    ).bind(modelNorm).all<DeviceRow>()
  ]);
  return {
    ...(exact === null ? {} : { exact }),
    byDevice: byDevice.results,
    byModel: byModel.results
  };
}

async function lookupSocCandidate(
  env: Env,
  source: SocCandidateMatch["source"],
  value: string
): Promise<SocCandidateMatch> {
  const normalized = normalizeCatalogValue(value);
  const compact = compactCatalogValue(value);
  const result = await env.DEVICE_CATALOG_DB.prepare(
    `SELECT query_key, identity_id, canonical_id, vendor, vendor_norm, name, fab, cpu, memory, bandwidth, channels
       FROM soc_catalog
      WHERE query_key_norm = ? OR query_key_compact = ?
      ORDER BY query_key
      LIMIT 16`
  ).bind(normalized, compact).all<SocRow>();
  return { source, value, rows: result.results };
}

async function lookupHardwareBaselines(
  env: Env,
  evidence: NativeIdentityEvidence
): Promise<DeviceHardwareBaselineRow[]> {
  if (isPlaceholder(evidence.device) || isPlaceholder(evidence.model)) return [];
  const result = await env.DEVICE_CATALOG_DB.prepare(
    `SELECT baseline.variant_id, baseline.manufacturer_norm, baseline.brand_norm,
            baseline.product_norm, baseline.sku_norm, baseline.board_platform_norm,
            baseline.fingerprint_prefix_norm, baseline.source, baseline.confidence
       FROM device_hardware_variant_baselines AS baseline
       JOIN baseline_metadata AS metadata
         ON metadata.key = 'active_batch_id' AND metadata.value = baseline.batch_id
       JOIN baseline_import_batches AS batch
         ON batch.batch_id = baseline.batch_id AND batch.status = 'PUBLISHED'
      WHERE baseline.active = 1
        AND baseline.device_norm = ?
        AND baseline.model_norm = ?
      ORDER BY baseline.variant_id
      LIMIT 64`
  ).bind(
    normalizeCatalogValue(evidence.device),
    normalizeCatalogValue(evidence.model)
  ).all<DeviceHardwareBaselineRow>();
  if (!result.success) throw new Error("设备硬件矩阵基线读取失败");
  return result.results;
}

export async function evaluateDeviceCatalog(
  env: Env,
  nativeEvidence: Record<string, unknown>
): Promise<CloudFinding[]> {
  const evidence = extractNativeIdentityEvidence(nativeEvidence);
  try {
    await ensureCatalogReady(env);
    const sourceValues: Array<[SocCandidateMatch["source"], string]> = [
      ["socModel", evidence.socModel],
      ["hardware", evidence.hardware],
      ["boardPlatform", evidence.boardPlatform],
      ["board", evidence.board]
    ];
    const [deviceLookup, hardwareBaselines, candidates] = await Promise.all([
      lookupDevice(env, evidence),
      lookupHardwareBaselines(env, evidence),
      Promise.all(
        sourceValues.filter(([, value]) => !isPlaceholder(value)).map(([source, value]) =>
          lookupSocCandidate(env, source, value)
        )
      )
    ]);
    const deviceFinding = classifyDeviceIdentity(evidence, deviceLookup);
    return [
      deviceFinding,
      classifySocIdentity(evidence, candidates),
      ...classifyHardwareBaseline(
        evidence,
        hardwareBaselines,
        deviceLookup.exact !== undefined
      )
    ];
  } catch (error) {
    const reason = error instanceof Error ? error.message : "目录数据库查询失败";
    return [
      finding("UNAVAILABLE", "INFO", "cloud.device.catalog_consistency", "设备型号目录暂时不可用", `${reason}；本次不会判定设备异常。`),
      finding("UNAVAILABLE", "INFO", "cloud.soc.catalog_consistency", "SoC 目录暂时不可用", `${reason}；本次不会判定设备异常。`),
      finding("UNAVAILABLE", "INFO", "cloud.device.hardware_matrix", "设备硬件矩阵暂时不可用", `${reason}；本次不会判定设备异常。`)
    ];
  }
}
