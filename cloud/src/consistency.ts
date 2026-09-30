import { createHash } from "node:crypto";
import type { NativeDeviceEvidence } from "./evidence";
import type { AttestationRecord, CloudFinding } from "./types";

const MONTH_MILLIS = 31 * 24 * 60 * 60 * 1000;
const SIX_MONTHS_MILLIS = 183 * 24 * 60 * 60 * 1000;

function finding(
  status: CloudFinding["status"],
  severity: CloudFinding["severity"],
  probeId: string,
  title: string,
  evidence: string
): CloudFinding {
  return { status, severity, probeId, title, evidence };
}

function attestedOsVersion(value: bigint | undefined): { raw: string; major: number; minor: number; patch: number } | null {
  if (value === undefined || value <= 0n || value > 9_999_999n) return null;
  const numeric = Number(value);
  return {
    raw: value.toString(),
    major: Math.floor(numeric / 10_000),
    minor: Math.floor(numeric / 100) % 100,
    patch: numeric % 100
  };
}

function releaseVersion(value: string): { major: number; minor: number; patch: number } | null {
  const match = value.trim().match(/^(\d{1,3})(?:\.(\d{1,3}))?(?:\.(\d{1,3}))?/u);
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2] ?? "0"),
    patch: Number(match[3] ?? "0")
  };
}

function patchMonth(value: bigint | undefined): { text: string; index: number } | null {
  if (value === undefined) return null;
  const raw = value.toString();
  if (!/^\d{6}(?:\d{2})?$/u.test(raw)) return null;
  const year = Number(raw.slice(0, 4));
  const month = Number(raw.slice(4, 6));
  if (year < 2000 || year > 2200 || month < 1 || month > 12) return null;
  return { text: raw, index: year * 12 + month };
}

function propertyPatchMonth(value: string): { text: string; index: number; time: number } | null {
  const match = value.match(/^(\d{4})-(\d{2})(?:-(\d{2}))?$/u);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3] ?? "1");
  const time = Date.UTC(year, month - 1, day);
  if (year < 2000 || year > 2200 || month < 1 || month > 12 || day < 1 || day > 31 || !Number.isFinite(time)) {
    return null;
  }
  const roundTrip = new Date(time);
  if (roundTrip.getUTCFullYear() !== year || roundTrip.getUTCMonth() !== month - 1 || roundTrip.getUTCDate() !== day) {
    return null;
  }
  return { text: value, index: year * 12 + month, time };
}

function epochMillis(seconds: number | null): number | null {
  if (seconds === null || seconds < 946_684_800 || seconds > 7_258_118_400) return null;
  return seconds * 1000;
}

function normalizeHex(value: string): string {
  const normalized = value.trim().replace(/[:\s]/gu, "").toLowerCase();
  return /^[0-9a-f]+$/u.test(normalized) ? normalized.replace(/^0+(?=[0-9a-f])/u, "") : "";
}

function byteHex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex").replace(/^0+(?=[0-9a-f])/u, "");
}

function verifiedBootStateName(state: number | undefined): string {
  return state === 0 ? "VERIFIED"
    : state === 1 ? "SELF_SIGNED"
      : state === 2 ? "UNVERIFIED"
        : state === 3 ? "FAILED"
          : "UNKNOWN";
}

export function evaluateTeePlatformConsistency(
  record: AttestationRecord,
  evidence: NativeDeviceEvidence
): CloudFinding {
  const attested = attestedOsVersion(record.osVersion);
  const userspace = releaseVersion(evidence.os.release);
  if (attested === null || userspace === null) {
    return finding(
      "UNAVAILABLE", "INFO", "cloud.tee.os_version_consistency",
      "TEE 与用户态系统版本暂无法对照",
      `Attestation.osVersion=${record.osVersion?.toString() ?? "<missing>"}；ro.build.version.release=${evidence.os.release || "<missing>"}。`
    );
  }
  if (attested.major !== userspace.major || attested.minor !== userspace.minor) {
    return finding(
      "DETECTED", "CRITICAL", "cloud.tee.os_version_consistency",
      "TEE 系统版本与用户态声明冲突",
      `Attestation.osVersion=${attested.raw}（Android ${attested.major}.${attested.minor}.${attested.patch}），ro.build.version.release=${evidence.os.release}；硬件证明与用户态版本不一致。`
    );
  }
  return finding(
    "CLEAN", "INFO", "cloud.tee.os_version_consistency",
    "TEE 系统版本与用户态声明一致",
    `Attestation.osVersion=${attested.raw}，ro.build.version.release=${evidence.os.release}。`
  );
}

export function evaluateTeePatchConsistency(
  record: AttestationRecord,
  evidence: NativeDeviceEvidence
): CloudFinding {
  const comparisons: string[] = [];
  const contradictions: string[] = [];
  const compare = (label: string, attested: ReturnType<typeof patchMonth>, property: ReturnType<typeof propertyPatchMonth>) => {
    if (attested === null || property === null) return;
    const delta = Math.abs(attested.index - property.index);
    comparisons.push(`${label}:TEE=${attested.text},Userspace=${property.text}`);
    if (delta > 1) contradictions.push(`${label} 相差 ${delta} 个月`);
  };
  compare("OS Patch", patchMonth(record.osPatchLevel), propertyPatchMonth(evidence.os.securityPatch));
  compare("Vendor Patch", patchMonth(record.vendorPatchLevel), propertyPatchMonth(evidence.os.vendorSecurityPatch));

  const bootPatch = patchMonth(record.bootPatchLevel);
  const bootBuild = epochMillis(evidence.os.bootImageBuildTimeUtc);
  if (bootPatch !== null && bootBuild !== null) {
    const date = new Date(bootBuild);
    const bootBuildIndex = date.getUTCFullYear() * 12 + date.getUTCMonth() + 1;
    const delta = Math.abs(bootPatch.index - bootBuildIndex);
    comparisons.push(`Boot Patch:TEE=${bootPatch.text},bootimage.build.date.utc=${evidence.os.bootImageBuildTimeUtc}`);
    if (delta > 2) contradictions.push(`Boot Patch 与 Boot 镜像构建时间相差 ${delta} 个月`);
  }

  if (contradictions.length > 0) {
    return finding(
      "DETECTED", "HIGH", "cloud.tee.patch_consistency",
      "TEE 补丁级别与用户态/镜像时间冲突",
      `${contradictions.join("；")}。${comparisons.join("；")}；疑似旧 Keybox 或属性伪造。`
    );
  }
  if (comparisons.length === 0) {
    return finding(
      "UNAVAILABLE", "INFO", "cloud.tee.patch_consistency",
      "TEE 补丁级别交叉校验不可用",
      "缺少可成对比较的 OS/Vendor/Boot 补丁与用户态时间字段，本次不会判定异常。"
    );
  }
  return finding(
    "CLEAN", "INFO", "cloud.tee.patch_consistency",
    "TEE 补丁级别与用户态时间一致",
    `${comparisons.join("；")}；可用字段均在容差范围内。`
  );
}

export function evaluateRootOfTrustConsistency(
  record: AttestationRecord,
  evidence: NativeDeviceEvidence
): CloudFinding {
  const stateName = verifiedBootStateName(record.verifiedBootState);
  if (record.deviceLocked === undefined || record.verifiedBootState === undefined) {
    return finding(
      "UNAVAILABLE", "INFO", "cloud.attestation.root_of_trust",
      "Root of Trust 字段不可用",
      `deviceLocked=${String(record.deviceLocked)}，verifiedBootState=${stateName}；本次不会判定异常。`
    );
  }

  const contradictions: string[] = [];
  const deviceState = evidence.boot.vbmetaDeviceState.toLowerCase();
  if (deviceState === "locked" && !record.deviceLocked) contradictions.push("用户态声称 locked，但 TEE 为 unlocked");
  if (deviceState === "unlocked" && record.deviceLocked) contradictions.push("用户态声称 unlocked，但 TEE 为 locked");

  const flashLocked = evidence.boot.flashLocked.toLowerCase();
  if (["0", "false"].includes(flashLocked) && record.deviceLocked) contradictions.push("ro.boot.flash.locked=0，但 TEE 为 locked");
  if (["1", "true"].includes(flashLocked) && !record.deviceLocked) contradictions.push("ro.boot.flash.locked=1，但 TEE 为 unlocked");

  const stateByColor: Record<string, number> = { green: 0, yellow: 1, orange: 2, red: 3 };
  const propertyState = stateByColor[evidence.boot.verifiedBootState.toLowerCase()];
  if (propertyState !== undefined && propertyState !== record.verifiedBootState) {
    contradictions.push(`ro.boot.verifiedbootstate=${evidence.boot.verifiedBootState} 与 TEE=${stateName} 不一致`);
  }

  if (record.verifiedBootHash !== undefined && evidence.boot.vbmetaDigest) {
    const teeHash = byteHex(record.verifiedBootHash);
    const propertyHash = normalizeHex(evidence.boot.vbmetaDigest);
    if (propertyHash && teeHash && propertyHash !== teeHash) contradictions.push("VBMeta Digest 与 TEE verifiedBootHash 不一致");
  }

  const bootKeyEvidence = record.verifiedBootKey === undefined
    ? "verifiedBootKey=<missing>"
    : `verifiedBootKeySha256=${createHash("sha256").update(record.verifiedBootKey).digest("hex")}`;
  const detail = `deviceLocked=${record.deviceLocked}，verifiedBootState=${stateName}，${bootKeyEvidence}`;
  if (contradictions.length > 0 || !record.deviceLocked || [2, 3].includes(record.verifiedBootState)) {
    const hardware = !record.deviceLocked || [2, 3].includes(record.verifiedBootState)
      ? "硬件启动状态未满足锁定且 Verified 的策略"
      : "";
    return finding(
      "DETECTED", "CRITICAL", "cloud.attestation.root_of_trust",
      "Root of Trust 与可信启动状态异常",
      [hardware, ...contradictions, detail].filter(Boolean).join("；")
    );
  }
  if (record.verifiedBootState === 1) {
    return finding(
      "WARNING", "HIGH", "cloud.attestation.root_of_trust",
      "Root of Trust 使用自签名启动密钥",
      `${detail}；SELF_SIGNED 可能来自受控自定义 AVB 密钥，不直接计入异常。`
    );
  }
  return finding(
    "CLEAN", "INFO", "cloud.attestation.root_of_trust",
    "Root of Trust 锁定状态与启动验证通过",
    `${detail}；可用用户态启动属性未发现冲突。`
  );
}

interface FingerprintParts {
  brand: string;
  product: string;
  device: string;
  release: string;
  buildId: string;
  incremental: string;
  buildType: string;
  tags: string;
}

function parseFingerprint(value: string): FingerprintParts | null {
  const sections = value.split(":");
  if (sections.length !== 3) return null;
  const identity = sections[0]!.split("/");
  const build = sections[1]!.split("/");
  const variant = sections[2]!.split("/");
  if (identity.length !== 3 || build.length !== 3 || variant.length !== 2
    || [...identity, ...build, ...variant].some((part) => !part)) return null;
  return {
    brand: identity[0]!, product: identity[1]!, device: identity[2]!,
    release: build[0]!, buildId: build[1]!, incremental: build[2]!,
    buildType: variant[0]!, tags: variant[1]!
  };
}

export function evaluateBuildFingerprintConsistency(evidence: NativeDeviceEvidence): CloudFinding {
  const fingerprint = parseFingerprint(evidence.os.fingerprint);
  if (fingerprint === null) {
    return finding(
      evidence.os.fingerprint ? "WARNING" : "UNAVAILABLE",
      evidence.os.fingerprint ? "MEDIUM" : "INFO",
      "cloud.build.fingerprint_consistency",
      evidence.os.fingerprint ? "Build Fingerprint 结构不符合规范" : "Build Fingerprint 不可用",
      evidence.os.fingerprint || "ro.build.fingerprint 为空，本次不会判定异常。"
    );
  }

  const expected: Array<[keyof FingerprintParts, string]> = [
    ["brand", evidence.device.brand], ["product", evidence.device.product],
    ["device", evidence.device.device], ["release", evidence.os.release],
    ["buildType", evidence.os.buildType], ["tags", evidence.os.buildTags]
  ];
  const differences = expected.filter(([field, property]) => property && fingerprint[field] !== property)
    .map(([field, property]) => `${field}:fingerprint=${fingerprint[field]},property=${property}`);
  const incrementalCandidates = Array.from(new Set([
    evidence.os.incremental,
    ...(evidence.os.incrementalCandidates ?? [])
  ].map((value) => value.trim()).filter(Boolean)));
  if (incrementalCandidates.length > 0 && !incrementalCandidates.includes(fingerprint.incremental)) {
    differences.push(
      `incremental:fingerprint=${fingerprint.incremental},properties=${incrementalCandidates.join("|")}`
    );
  }
  if (differences.length > 0) {
    return finding(
      "WARNING", "MEDIUM", "cloud.build.fingerprint_consistency",
      "Build Fingerprint 与 SystemProperties 脱节",
      differences.join("；")
    );
  }
  const missing = expected.filter(([, property]) => !property).map(([field]) => field);
  if (incrementalCandidates.length === 0) missing.push("incremental");
  if (missing.length > 0) {
    return finding(
      "UNAVAILABLE", "INFO", "cloud.build.fingerprint_consistency",
      "Build Fingerprint 交叉校验字段不完整",
      `缺少属性：${missing.join("、")}；已提供字段未发现冲突。`
    );
  }
  return finding(
    "CLEAN", "INFO", "cloud.build.fingerprint_consistency",
    "Build Fingerprint 解构字段一致",
    "BRAND/PRODUCT/DEVICE、RELEASE、INCREMENTAL（任一候选属性）、TYPE/TAGS 均与独立 SystemProperties 一致；ID 不参与判定。"
  );
}

const MONTHS: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11
};

function kernelBuildTime(value: string): number | null {
  const match = value.match(/\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(?:[A-Z]{2,5}\s+)?(\d{4})\b/u);
  if (!match) return null;
  const month = MONTHS[match[1]!];
  if (month === undefined) return null;
  return Date.UTC(Number(match[6]), month, Number(match[2]), Number(match[3]), Number(match[4]), Number(match[5]));
}

export function evaluateBuildTimelineConsistency(evidence: NativeDeviceEvidence): CloudFinding {
  const checks: string[] = [];
  const contradictions: string[] = [];
  const systemBuild = epochMillis(evidence.os.buildTimeUtc);
  const systemPatch = propertyPatchMonth(evidence.os.securityPatch);
  if (systemBuild !== null && systemPatch !== null) {
    checks.push(`systemBuild=${evidence.os.buildTimeUtc},securityPatch=${evidence.os.securityPatch}`);
    if (systemPatch.time - systemBuild > MONTH_MILLIS) contradictions.push("系统安全补丁日期超前于系统构建时间超过 31 天");
  }
  const vendorBuild = epochMillis(evidence.os.vendorBuildTimeUtc);
  const vendorPatch = propertyPatchMonth(evidence.os.vendorSecurityPatch);
  if (vendorBuild !== null && vendorPatch !== null) {
    checks.push(`vendorBuild=${evidence.os.vendorBuildTimeUtc},vendorPatch=${evidence.os.vendorSecurityPatch}`);
    if (vendorPatch.time - vendorBuild > MONTH_MILLIS) contradictions.push("Vendor 补丁日期超前于 Vendor 构建时间超过 31 天");
  }
  const parsedKernelTime = kernelBuildTime(evidence.kernel.buildVersion);
  if (systemBuild !== null && parsedKernelTime !== null) {
    checks.push(`kernelBuild=${new Date(parsedKernelTime).toISOString()}`);
    if (parsedKernelTime - systemBuild > SIX_MONTHS_MILLIS) contradictions.push("内核构建时间比系统镜像晚超过 183 天");
  }
  if (contradictions.length > 0) {
    return finding(
      "WARNING", "MEDIUM", "cloud.build.timeline_consistency",
      "系统、补丁与内核构建时序冲突",
      `${contradictions.join("；")}。${checks.join("；")}`
    );
  }
  if (checks.length === 0) {
    return finding(
      "UNAVAILABLE", "INFO", "cloud.build.timeline_consistency",
      "构建时序交叉校验不可用",
      "缺少可解析的构建时间、补丁日期或 uname 内核构建时间，本次不会判定异常。"
    );
  }
  return finding(
    "CLEAN", "INFO", "cloud.build.timeline_consistency",
    "系统、补丁与内核构建时序合理",
    checks.join("；")
  );
}

export function evaluateLocalEvidenceConsistency(
  record: AttestationRecord,
  evidence: NativeDeviceEvidence
): CloudFinding[] {
  return [
    evaluateTeePlatformConsistency(record, evidence),
    evaluateTeePatchConsistency(record, evidence),
    evaluateRootOfTrustConsistency(record, evidence),
    evaluateBuildFingerprintConsistency(evidence),
    evaluateBuildTimelineConsistency(evidence)
  ];
}
