import type { NativeDeviceEvidence } from "./evidence";
import type { CloudFinding, Env } from "./types";

interface KernelRiskSignatureRow {
  signature_id: string;
  match_field: "release" | "build_version" | "machine" | "any";
  needle_norm: string;
  status: "DETECTED" | "WARNING";
  severity: CloudFinding["severity"];
  title: string;
  reason: string;
  source: string;
}

interface AndroidKernelPolicy {
  standardFamilies: readonly string[];
  legacyUpgradeFamilies: readonly string[];
  source: string;
}

const ANDROID_KERNEL_POLICIES: Readonly<Record<number, AndroidKernelPolicy>> = {
  8: { standardFamilies: ["3.18", "4.4"], legacyUpgradeFamilies: [], source: "Android 8 历史 LTS 范围" },
  9: { standardFamilies: ["4.4", "4.9", "4.14"], legacyUpgradeFamilies: ["3.18"], source: "Android 9 历史 LTS 范围" },
  10: { standardFamilies: ["4.9", "4.14", "4.19"], legacyUpgradeFamilies: ["4.4"], source: "Android 10 历史 LTS 范围" },
  11: { standardFamilies: ["4.14", "4.19", "5.4"], legacyUpgradeFamilies: ["4.9"], source: "Android 11 历史 LTS 范围" },
  12: { standardFamilies: ["5.10"], legacyUpgradeFamilies: ["4.14", "4.19", "5.4"], source: "AOSP Android Common Kernel 兼容矩阵" },
  13: { standardFamilies: ["5.10", "5.15"], legacyUpgradeFamilies: ["4.14", "4.19", "5.4"], source: "AOSP Android Common Kernel 兼容矩阵" },
  14: { standardFamilies: ["5.10", "5.15", "6.1"], legacyUpgradeFamilies: ["4.19", "5.4"], source: "AOSP Android Common Kernel 兼容矩阵" },
  15: { standardFamilies: ["5.10", "5.15", "6.1", "6.6"], legacyUpgradeFamilies: ["4.19", "5.4"], source: "AOSP Android Common Kernel 兼容矩阵" },
  16: { standardFamilies: ["5.10", "5.15", "6.1", "6.6", "6.12"], legacyUpgradeFamilies: ["5.4"], source: "AOSP Android Common Kernel 兼容矩阵" },
  17: { standardFamilies: ["5.10", "5.15", "6.1", "6.6", "6.12", "6.18"], legacyUpgradeFamilies: [], source: "AOSP Android Common Kernel 兼容矩阵" }
};

function finding(
  status: CloudFinding["status"],
  severity: CloudFinding["severity"],
  probeId: string,
  title: string,
  evidence: string
): CloudFinding {
  return { status, severity, probeId, title, evidence };
}

function normalize(value: string): string {
  return value.normalize("NFKC").trim().toLowerCase().replace(/\s+/gu, " ");
}

function severityWeight(value: CloudFinding["severity"]): number {
  return { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[value];
}

function signatureValue(row: KernelRiskSignatureRow, evidence: NativeDeviceEvidence): string {
  if (row.match_field === "release") return evidence.kernel.release;
  if (row.match_field === "build_version") return evidence.kernel.buildVersion;
  if (row.match_field === "machine") return evidence.kernel.machine;
  return `${evidence.kernel.release}\n${evidence.kernel.buildVersion}\n${evidence.kernel.machine}`;
}

function androidMajorFromSdk(sdk: number | null): number | null {
  if (sdk === null) return null;
  if (sdk === 26 || sdk === 27) return 8;
  return ({
    28: 9,
    29: 10,
    30: 11,
    31: 12,
    32: 12,
    33: 13,
    34: 14,
    35: 15,
    36: 16,
    37: 17
  } as Readonly<Record<number, number>>)[sdk] ?? null;
}

function androidMajorFromRelease(release: string): number | null {
  const match = /^(\d{1,2})(?:\.|$)/u.exec(release.trim());
  if (match === null) return null;
  const major = Number(match[1]);
  return Number.isSafeInteger(major) ? major : null;
}

function kernelFamily(release: string): string | null {
  const match = /^(\d+)\.(\d+)(?:[.\-+]|$)/u.exec(release.trim());
  return match === null ? null : `${Number(match[1])}.${Number(match[2])}`;
}

export function classifyKernelRiskSignatures(
  evidence: NativeDeviceEvidence,
  signatures: KernelRiskSignatureRow[]
): CloudFinding {
  if (!evidence.kernel.release && !evidence.kernel.buildVersion && !evidence.kernel.machine) {
    return finding(
      "UNAVAILABLE", "INFO", "cloud.kernel.risk_signatures",
      "内核风险特征校验不可用",
      "项目现有 uname 内核字段为空；未读取 /proc/version，本次不会判定异常。"
    );
  }
  const matches = signatures.filter((row) => {
    const needle = normalize(row.needle_norm);
    return Boolean(needle) && normalize(signatureValue(row, evidence)).includes(needle);
  }).sort((left, right) => {
    const statusDelta = Number(right.status === "DETECTED") - Number(left.status === "DETECTED");
    return statusDelta || severityWeight(right.severity) - severityWeight(left.severity);
  });
  if (matches.length === 0) {
    return finding(
      "CLEAN", "INFO", "cloud.kernel.risk_signatures",
      "内核指纹未命中云端风险特征库",
      `已使用项目现有 uname 字段匹配 ${signatures.length} 条启用规则；规则可在 D1 中独立更新。`
    );
  }
  const strongest = matches[0]!;
  return finding(
    strongest.status,
    strongest.severity,
    "cloud.kernel.risk_signatures",
    strongest.title,
    matches.map((row) => `规则=${row.signature_id}；字段=${row.match_field}；来源=${row.source}；原因=${row.reason}`).join(" | ")
  );
}

export function classifyAndroidKernelCompatibility(evidence: NativeDeviceEvidence): CloudFinding {
  const releaseMajor = androidMajorFromRelease(evidence.os.release);
  const sdkMajor = androidMajorFromSdk(evidence.os.sdk);
  if (releaseMajor !== null && sdkMajor !== null && releaseMajor !== sdkMajor) {
    return finding(
      "WARNING", "MEDIUM", "cloud.kernel.android_compatibility",
      "Android 版本声明不一致，无法可靠推断内核范围",
      `release=${evidence.os.release}，sdk=${String(evidence.os.sdk)}（对应 Android ${sdkMajor}）；版本声明冲突只标记可疑，不直接计入异常。`
    );
  }
  const androidMajor = releaseMajor ?? sdkMajor;
  if (androidMajor === null || ANDROID_KERNEL_POLICIES[androidMajor] === undefined) {
    return finding(
      "UNAVAILABLE", "INFO", "cloud.kernel.android_compatibility",
      "当前 Android 版本暂无通用内核规则",
      `release=${evidence.os.release || "<empty>"}，sdk=${evidence.os.sdk === null ? "<empty>" : String(evidence.os.sdk)}；未覆盖版本不会判定异常。`
    );
  }
  const family = kernelFamily(evidence.kernel.release);
  if (family === null) {
    return finding(
      "UNAVAILABLE", "INFO", "cloud.kernel.android_compatibility",
      "内核版本无法解析",
      `uname.release=${evidence.kernel.release || "<empty>"}；仅使用项目现有内核采集结果，未读取 /proc/version。`
    );
  }
  const policy = ANDROID_KERNEL_POLICIES[androidMajor]!;
  if (policy.standardFamilies.includes(family)) {
    return finding(
      "CLEAN", "INFO", "cloud.kernel.android_compatibility",
      "内核版本与 Android 版本兼容",
      `Android ${androidMajor}，kernel=${family}；匹配 ${policy.source}：${policy.standardFamilies.join("、")}。`
    );
  }
  if (policy.legacyUpgradeFamilies.includes(family)) {
    return finding(
      "CLEAN", "INFO", "cloud.kernel.android_compatibility",
      "内核版本符合旧设备升级兼容范围",
      `Android ${androidMajor}，kernel=${family}；当前系统版本不能反推出设备首发版本，已按旧设备官方升级路径宽松接受。`
    );
  }
  const expected = [...policy.standardFamilies, ...policy.legacyUpgradeFamilies];
  return finding(
    "WARNING", "MEDIUM", "cloud.kernel.android_compatibility",
    "内核版本与 Android 版本组合需复核",
    `Android ${androidMajor}，kernel=${family}，常见合理范围=${expected.join("、")}；通用版本推断不能证明机型首发版本，因此仅标记 WARNING。`
  );
}

async function loadRiskSignatures(env: Env): Promise<KernelRiskSignatureRow[]> {
  const result = await env.DEVICE_CATALOG_DB.prepare(
    `SELECT signature_id, match_field, needle_norm, status, severity, title, reason, source
       FROM kernel_risk_signatures
      WHERE active = 1
      ORDER BY signature_id
      LIMIT 256`
  ).all<KernelRiskSignatureRow>();
  if (!result.success) throw new Error("内核风险规则读取失败");
  return result.results;
}

export async function evaluateKernelPolicy(
  env: Env,
  evidence: NativeDeviceEvidence
): Promise<CloudFinding[]> {
  const compatibility = classifyAndroidKernelCompatibility(evidence);
  try {
    const signatures = await loadRiskSignatures(env);
    return [classifyKernelRiskSignatures(evidence, signatures), compatibility];
  } catch (error) {
    const reason = error instanceof Error ? error.message : "云端内核规则数据库查询失败";
    return [
      finding(
        "UNAVAILABLE", "INFO", "cloud.kernel.risk_signatures",
        "内核风险特征库暂时不可用",
        `${reason}；本次不会判定设备异常。`
      ),
      compatibility
    ];
  }
}
