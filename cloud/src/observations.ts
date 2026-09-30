import { createHash, createHmac } from "node:crypto";
import { canonicalize } from "./canonical-json";
import type { NativeDeviceEvidence } from "./evidence";
import type {
  AttestationCertificateIdentity,
  AttestationRecord,
  CloudFinding,
  Env
} from "./types";

const OBSERVATION_SCHEMA = "trustattestor.learned-observation/v1" as const;
const REQUIRED_LEARNING_GATES = new Set([
  "cloud.keybox.serial_blacklist",
  "cloud.tee.os_version_consistency",
  "cloud.tee.patch_consistency",
  "cloud.attestation.root_of_trust",
  "cloud.build.fingerprint_consistency",
  "cloud.kernel.risk_signatures"
]);
const FALLBACK_PROBES = new Set([
  "cloud.device.hardware_matrix"
]);

export interface ObservationProfile {
  device: string;
  model: string;
  product: string;
  sku: string;
  manufacturer: string;
  brand: string;
  boardPlatform: string;
  fingerprint: string;
  socModel: string;
  socManufacturer: string;
  hardware: string;
  osRelease: string;
  sdk: number | null;
  securityPatch: string;
  teeOsVersion: string;
  teeOsPatchLevel: string;
  teeVendorPatchLevel: string;
  teeBootPatchLevel: string;
}

export interface ObservationMessage {
  schema: typeof OBSERVATION_SCHEMA;
  observedAt: string;
  firmwareKey: string;
  profileHash: string;
  sourceKeyHash: string;
  networkKeyHash: string;
  profile: ObservationProfile;
}

export interface LearnedObservationRow {
  profile_hash: string;
  consensus_state: "LEARNING" | "TRUSTED" | "CONFLICT" | "REVOKED";
  review_state: "PENDING" | "APPROVED" | "REJECTED";
  distinct_source_count: number;
  distinct_network_count?: number;
  observation_count: number;
}

export type LearnedConsensus =
  | { kind: "EXACT_TRUSTED"; sourceCount: number; observationCount: number }
  | { kind: "TRUSTED_MISMATCH"; sourceCount: number; observationCount: number }
  | { kind: "LEARNING"; sourceCount: number; observationCount: number }
  | { kind: "NONE" }
  | { kind: "UNAVAILABLE"; reason: string };

class ObservationValidationError extends Error {}

function normalize(value: string, maximum = 1024): string {
  return value.normalize("NFKC").trim().toLowerCase().replace(/\s+/gu, " ").slice(0, maximum);
}

function hashCanonical(value: object): string {
  return createHash("sha256").update(canonicalize(value), "utf8").digest("hex");
}

function bigintText(value: bigint | undefined): string {
  return value === undefined ? "" : value.toString();
}

function observationSourceKey(identities: AttestationCertificateIdentity[]): string {
  const leaf = identities[0];
  if (leaf === undefined) return "";
  const material = leaf.certificateSha256;
  if (!/^[0-9a-f]{64}$/u.test(material)) return "";
  return createHash("sha256")
    .update(`trustattestor.observation-source/v1\0${material}`, "utf8")
    .digest("hex");
}

function observationNetworkKey(networkAddress: string | undefined, networkSecret: string | undefined): string {
  if (!networkAddress || !networkSecret) return "";
  return createHmac("sha256", networkSecret)
    .update(`trustattestor.observation-network/v1\0${networkAddress}`, "utf8")
    .digest("hex");
}

function firmwareIdentity(profile: ObservationProfile): object {
  return {
    device: profile.device,
    model: profile.model,
    sku: profile.sku,
    fingerprint: profile.fingerprint
  };
}

function requiredProfileFieldsPresent(profile: ObservationProfile): boolean {
  return [
    profile.device,
    profile.model,
    profile.product,
    profile.manufacturer,
    profile.brand,
    profile.boardPlatform,
    profile.fingerprint,
    profile.osRelease,
    profile.securityPatch,
    profile.teeOsVersion,
    profile.teeOsPatchLevel
  ].every(Boolean) && Boolean(profile.socModel || profile.hardware);
}

export function createObservationMessage(
  evidence: NativeDeviceEvidence,
  record: AttestationRecord,
  identities: AttestationCertificateIdentity[],
  observedAt = new Date(),
  context: { networkAddress?: string; networkSecret?: string } = {}
): ObservationMessage | null {
  const sourceKeyHash = observationSourceKey(identities);
  const profile: ObservationProfile = {
    device: normalize(evidence.device.device),
    model: normalize(evidence.device.model),
    product: normalize(evidence.device.product),
    sku: normalize(evidence.device.sku),
    manufacturer: normalize(evidence.device.manufacturer),
    brand: normalize(evidence.device.brand),
    boardPlatform: normalize(evidence.processor.boardPlatform),
    fingerprint: normalize(evidence.os.fingerprint, 2048),
    socModel: normalize(evidence.processor.socModel),
    socManufacturer: normalize(evidence.processor.socManufacturer),
    hardware: normalize(evidence.processor.hardware),
    osRelease: normalize(evidence.os.release),
    sdk: evidence.os.sdk,
    securityPatch: normalize(evidence.os.securityPatch),
    teeOsVersion: bigintText(record.osVersion),
    teeOsPatchLevel: bigintText(record.osPatchLevel),
    teeVendorPatchLevel: bigintText(record.vendorPatchLevel),
    teeBootPatchLevel: bigintText(record.bootPatchLevel)
  };
  if (!sourceKeyHash || !requiredProfileFieldsPresent(profile)
    || record.deviceLocked !== true || record.verifiedBootState !== 0) return null;
  const timestamp = observedAt.toISOString();
  return {
    schema: OBSERVATION_SCHEMA,
    observedAt: timestamp,
    firmwareKey: hashCanonical(firmwareIdentity(profile)),
    profileHash: hashCanonical(profile),
    sourceKeyHash,
    networkKeyHash: observationNetworkKey(context.networkAddress, context.networkSecret),
    profile
  };
}

export function isEligibleForLearning(findings: CloudFinding[]): boolean {
  const byProbe = new Map(findings.map((finding) => [finding.probeId, finding]));
  return findings.every((finding) => ["CLEAN", "UNAVAILABLE"].includes(finding.status))
    && [...REQUIRED_LEARNING_GATES].every((probeId) => byProbe.get(probeId)?.status === "CLEAN");
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ObservationValidationError("observation message must be an object");
  }
  return value as Record<string, unknown>;
}

function text(value: unknown, field: string, maximum = 2048): string {
  if (typeof value !== "string" || value.length > maximum) {
    throw new ObservationValidationError(`${field} must be a bounded string`);
  }
  return value;
}

function hash(value: unknown, field: string): string {
  const result = text(value, field, 64);
  if (!/^[0-9a-f]{64}$/u.test(result)) throw new ObservationValidationError(`${field} must be SHA-256`);
  return result;
}

function validateProfile(value: unknown): ObservationProfile {
  const input = record(value);
  const sdk = input.sdk;
  if (sdk !== null && (!Number.isSafeInteger(sdk) || Number(sdk) < 1 || Number(sdk) > 100)) {
    throw new ObservationValidationError("profile.sdk is invalid");
  }
  const profile: ObservationProfile = {
    device: text(input.device, "profile.device"),
    model: text(input.model, "profile.model"),
    product: text(input.product, "profile.product"),
    sku: text(input.sku, "profile.sku"),
    manufacturer: text(input.manufacturer, "profile.manufacturer"),
    brand: text(input.brand, "profile.brand"),
    boardPlatform: text(input.boardPlatform, "profile.boardPlatform"),
    fingerprint: text(input.fingerprint, "profile.fingerprint"),
    socModel: text(input.socModel, "profile.socModel"),
    socManufacturer: text(input.socManufacturer, "profile.socManufacturer"),
    hardware: text(input.hardware, "profile.hardware"),
    osRelease: text(input.osRelease, "profile.osRelease"),
    sdk: sdk === null ? null : Number(sdk),
    securityPatch: text(input.securityPatch, "profile.securityPatch"),
    teeOsVersion: text(input.teeOsVersion, "profile.teeOsVersion"),
    teeOsPatchLevel: text(input.teeOsPatchLevel, "profile.teeOsPatchLevel"),
    teeVendorPatchLevel: text(input.teeVendorPatchLevel, "profile.teeVendorPatchLevel"),
    teeBootPatchLevel: text(input.teeBootPatchLevel, "profile.teeBootPatchLevel")
  };
  if (!requiredProfileFieldsPresent(profile)) throw new ObservationValidationError("profile is incomplete");
  return profile;
}

export function validateObservationMessage(value: unknown): ObservationMessage {
  const input = record(value);
  if (input.schema !== OBSERVATION_SCHEMA) throw new ObservationValidationError("unsupported observation schema");
  const profile = validateProfile(input.profile);
  const observedAt = text(input.observedAt, "observedAt", 64);
  if (!Number.isFinite(Date.parse(observedAt))) throw new ObservationValidationError("observedAt is invalid");
  const message: ObservationMessage = {
    schema: OBSERVATION_SCHEMA,
    observedAt,
    firmwareKey: hash(input.firmwareKey, "firmwareKey"),
    profileHash: hash(input.profileHash, "profileHash"),
    sourceKeyHash: hash(input.sourceKeyHash, "sourceKeyHash"),
    networkKeyHash: input.networkKeyHash === undefined || input.networkKeyHash === ""
      ? ""
      : hash(input.networkKeyHash, "networkKeyHash"),
    profile
  };
  if (message.profileHash !== hashCanonical(profile)) throw new ObservationValidationError("profileHash mismatch");
  if (message.firmwareKey !== hashCanonical(firmwareIdentity(profile))) {
    throw new ObservationValidationError("firmwareKey mismatch");
  }
  return message;
}

function configuredInteger(value: string, field: string, minimum: number, maximum: number): number {
  if (!/^[0-9]+$/u.test(value)) throw new Error(`${field} must be an integer`);
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < minimum || result > maximum) {
    throw new Error(`${field} is out of range`);
  }
  return result;
}

export function classifyLearnedConsensus(
  message: ObservationMessage,
  rows: LearnedObservationRow[]
): LearnedConsensus {
  const trusted = rows.filter((row) =>
    row.review_state === "APPROVED" && row.consensus_state === "TRUSTED"
  );
  const exact = trusted.find((row) => row.profile_hash === message.profileHash);
  if (exact !== undefined) {
    return {
      kind: "EXACT_TRUSTED",
      sourceCount: exact.distinct_source_count,
      observationCount: exact.observation_count
    };
  }
  if (trusted.length > 0) {
    const strongest = [...trusted].sort((left, right) =>
      right.distinct_source_count - left.distinct_source_count
      || right.observation_count - left.observation_count
    )[0]!;
    return {
      kind: "TRUSTED_MISMATCH",
      sourceCount: strongest.distinct_source_count,
      observationCount: strongest.observation_count
    };
  }
  const learning = rows.find((row) => row.profile_hash === message.profileHash);
  return learning === undefined
    ? { kind: "NONE" }
    : {
        kind: "LEARNING",
        sourceCount: learning.distinct_source_count,
        observationCount: learning.observation_count
      };
}

export async function evaluateLearnedConsensus(
  env: Env,
  message: ObservationMessage | null
): Promise<LearnedConsensus> {
  if (message === null) return { kind: "NONE" };
  try {
    const result = await env.DEVICE_CATALOG_DB.prepare(
      `SELECT profile_hash, consensus_state, review_state,
              distinct_source_count, observation_count
         FROM learned_observation_profiles
        WHERE firmware_key = ?
          AND review_state <> 'REJECTED'
        ORDER BY distinct_source_count DESC, observation_count DESC
        LIMIT 32`
    ).bind(message.firmwareKey).all<LearnedObservationRow>();
    if (!result.success) throw new Error("learned observation query failed");
    return classifyLearnedConsensus(message, result.results);
  } catch (error) {
    return {
      kind: "UNAVAILABLE",
      reason: error instanceof Error ? error.message : "learned observation database unavailable"
    };
  }
}

function learnedCleanFinding(original: CloudFinding, consensus: Extract<LearnedConsensus, { kind: "EXACT_TRUSTED" }>): CloudFinding {
  const evidence = `已匹配经审核的可信观测画像；去重证明叶证书=${consensus.sourceCount}，累计观测=${consensus.observationCount}。观测数据只扩展正常覆盖，不用于生成 DETECTED。`;
  if (original.probeId === "cloud.device.hardware_matrix") {
    return { ...original, status: "CLEAN", severity: "INFO", title: "设备指纹与厂商元数据匹配", evidence };
  }
  return { ...original, status: "CLEAN", severity: "INFO", title: "设备指纹与厂商元数据匹配", evidence };
}

export function applyLearnedConsensusFallback(
  findings: CloudFinding[],
  consensus: LearnedConsensus
): CloudFinding[] {
  if (consensus.kind === "EXACT_TRUSTED") {
    return findings.map((item) =>
      item.status === "UNAVAILABLE" && FALLBACK_PROBES.has(item.probeId)
        ? learnedCleanFinding(item, consensus)
        : item
    );
  }
  if (consensus.kind !== "TRUSTED_MISMATCH") return findings;
  return [
    ...findings,
    {
      status: "WARNING",
      severity: "MEDIUM",
      probeId: "cloud.observation.consensus",
      title: "设备画像偏离可信观测共识",
      evidence: `同一 device/model/SKU/fingerprint 已存在可信画像，但当前设备元数据或 SoC 组合不同；可信画像独立来源=${consensus.sourceCount}，累计观测=${consensus.observationCount}。学习数据不会直接判定异常。`
    }
  ];
}

export async function enqueueObservation(env: Env, message: ObservationMessage): Promise<void> {
  await env.OBSERVATION_QUEUE.send(message, { contentType: "json" });
}

async function persistObservation(env: Env, message: ObservationMessage): Promise<void> {
  const minimumSources = configuredInteger(env.OBSERVATION_MIN_SOURCES, "OBSERVATION_MIN_SOURCES", 2, 100);
  const minimumNetworks = configuredInteger(env.OBSERVATION_MIN_NETWORKS, "OBSERVATION_MIN_NETWORKS", 2, 100);
  const profile = message.profile;
  const profileJson = canonicalize(profile);
  const statements = [
    env.DEVICE_CATALOG_DB.prepare(
      `INSERT INTO learned_observation_profiles
        (profile_hash, firmware_key, profile_json, device_norm, model_norm,
         product_norm, sku_norm, manufacturer_norm, brand_norm,
         board_platform_norm, fingerprint_norm, soc_model_norm,
         soc_manufacturer_norm, hardware_norm, os_release_norm, sdk,
         security_patch_norm,
         tee_os_version, tee_os_patch_level, tee_vendor_patch_level,
         tee_boot_patch_level, first_seen_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(profile_hash) DO UPDATE SET
         observation_count = learned_observation_profiles.observation_count + 1,
         last_seen_at = CASE
           WHEN excluded.last_seen_at > learned_observation_profiles.last_seen_at THEN excluded.last_seen_at
           ELSE learned_observation_profiles.last_seen_at
         END`
    ).bind(
      message.profileHash, message.firmwareKey, profileJson, profile.device,
      profile.model, profile.product, profile.sku, profile.manufacturer,
      profile.brand, profile.boardPlatform, profile.fingerprint,
      profile.socModel, profile.socManufacturer, profile.hardware,
      profile.osRelease, profile.sdk, profile.securityPatch, profile.teeOsVersion,
      profile.teeOsPatchLevel, profile.teeVendorPatchLevel,
      profile.teeBootPatchLevel, message.observedAt, message.observedAt
    ),
    env.DEVICE_CATALOG_DB.prepare(
      `INSERT INTO learned_observation_sources
        (profile_hash, source_key_hash, first_seen_at, last_seen_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(profile_hash, source_key_hash) DO UPDATE SET
         observation_count = learned_observation_sources.observation_count + 1,
         last_seen_at = CASE
           WHEN excluded.last_seen_at > learned_observation_sources.last_seen_at THEN excluded.last_seen_at
           ELSE learned_observation_sources.last_seen_at
         END`
    ).bind(message.profileHash, message.sourceKeyHash, message.observedAt, message.observedAt),
    ...(message.networkKeyHash
      ? [env.DEVICE_CATALOG_DB.prepare(
        `INSERT INTO learned_observation_networks
          (profile_hash, network_key_hash, first_seen_at, last_seen_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(profile_hash, network_key_hash) DO UPDATE SET
           observation_count = learned_observation_networks.observation_count + 1,
           last_seen_at = CASE
             WHEN excluded.last_seen_at > learned_observation_networks.last_seen_at THEN excluded.last_seen_at
             ELSE learned_observation_networks.last_seen_at
           END`
      ).bind(message.profileHash, message.networkKeyHash, message.observedAt, message.observedAt)]
      : []),
    env.DEVICE_CATALOG_DB.prepare(
      `UPDATE learned_observation_profiles
          SET distinct_source_count = (
            SELECT COUNT(*) FROM learned_observation_sources
             WHERE learned_observation_sources.profile_hash = learned_observation_profiles.profile_hash
          )
        WHERE profile_hash = ?`
    ).bind(message.profileHash),
    ...(message.networkKeyHash
      ? [env.DEVICE_CATALOG_DB.prepare(
        `UPDATE learned_observation_profiles
            SET distinct_network_count = (
              SELECT COUNT(*) FROM learned_observation_networks
               WHERE learned_observation_networks.profile_hash = learned_observation_profiles.profile_hash
            )
          WHERE profile_hash = ?`
      ).bind(message.profileHash)]
      : []),
    env.DEVICE_CATALOG_DB.prepare(
      `UPDATE learned_observation_profiles
          SET consensus_state = CASE
            WHEN review_state = 'APPROVED' THEN 'TRUSTED'
            WHEN review_state = 'REJECTED' THEN 'REVOKED'
            WHEN (
              SELECT COUNT(*) FROM learned_observation_profiles AS peer
               WHERE peer.firmware_key = learned_observation_profiles.firmware_key
                 AND peer.review_state <> 'REJECTED'
                 AND (peer.review_state = 'APPROVED' OR (
                   peer.distinct_source_count >= ? AND peer.distinct_network_count >= ?
                 ))
            ) > 1 THEN 'CONFLICT'
            ELSE 'LEARNING'
          END
        WHERE firmware_key = ?`
    ).bind(minimumSources, minimumNetworks, message.firmwareKey)
  ];
  await env.DEVICE_CATALOG_DB.batch(statements);
}

export async function consumeObservationBatch(
  batch: MessageBatch<ObservationMessage>,
  env: Env
): Promise<void> {
  for (const queueMessage of batch.messages) {
    try {
      const message = validateObservationMessage(queueMessage.body);
      await persistObservation(env, message);
      queueMessage.ack();
    } catch (error) {
      const details = error instanceof Error ? error.message : String(error);
      console.error(JSON.stringify({
        message: "observation queue processing failed",
        queueMessageId: queueMessage.id,
        attempts: queueMessage.attempts,
        error: details
      }));
      if (error instanceof ObservationValidationError) queueMessage.ack();
      else queueMessage.retry({ delaySeconds: Math.min(300, 5 * 2 ** Math.min(queueMessage.attempts, 6)) });
    }
  }
}

export async function pruneLearnedObservations(env: Env): Promise<void> {
  const minimumSources = configuredInteger(env.OBSERVATION_MIN_SOURCES, "OBSERVATION_MIN_SOURCES", 2, 100);
  const minimumNetworks = configuredInteger(env.OBSERVATION_MIN_NETWORKS, "OBSERVATION_MIN_NETWORKS", 2, 100);
  const retentionDays = configuredInteger(env.OBSERVATION_RETENTION_DAYS, "OBSERVATION_RETENTION_DAYS", 30, 730);
  const retention = `-${retentionDays} days`;
  await env.DEVICE_CATALOG_DB.batch([
    env.DEVICE_CATALOG_DB.prepare(
      "DELETE FROM learned_observation_sources WHERE last_seen_at < datetime('now', ?)"
    ).bind(retention),
    env.DEVICE_CATALOG_DB.prepare(
      "DELETE FROM learned_observation_networks WHERE last_seen_at < datetime('now', ?)"
    ).bind(retention),
    env.DEVICE_CATALOG_DB.prepare(
      `UPDATE learned_observation_profiles
          SET distinct_source_count = (
            SELECT COUNT(*) FROM learned_observation_sources
             WHERE learned_observation_sources.profile_hash = learned_observation_profiles.profile_hash
          )`
    ),
    env.DEVICE_CATALOG_DB.prepare(
      `UPDATE learned_observation_profiles
          SET distinct_network_count = (
            SELECT COUNT(*) FROM learned_observation_networks
             WHERE learned_observation_networks.profile_hash = learned_observation_profiles.profile_hash
          )`
    ),
    env.DEVICE_CATALOG_DB.prepare(
      `UPDATE learned_observation_profiles
          SET consensus_state = CASE
            WHEN review_state = 'APPROVED' THEN 'TRUSTED'
            WHEN review_state = 'REJECTED' THEN 'REVOKED'
            WHEN (
              SELECT COUNT(*) FROM learned_observation_profiles AS peer
               WHERE peer.firmware_key = learned_observation_profiles.firmware_key
                 AND peer.review_state <> 'REJECTED'
                 AND (peer.review_state = 'APPROVED' OR (
                   peer.distinct_source_count >= ? AND peer.distinct_network_count >= ?
                 ))
            ) > 1 THEN 'CONFLICT'
            ELSE 'LEARNING'
          END`
    ).bind(minimumSources, minimumNetworks),
    env.DEVICE_CATALOG_DB.prepare(
      `DELETE FROM learned_observation_profiles
        WHERE review_state = 'PENDING'
          AND distinct_source_count = 0
          AND last_seen_at < datetime('now', ?)`
    ).bind(retention)
  ]);
}
