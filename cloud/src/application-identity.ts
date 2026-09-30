import type { AttestationRecord, CloudFinding } from "./types";

/** Exact package/signature sets approved from release signing records, never from a request. */
export interface TrustedApplicationIdentity {
  packageNames: readonly string[];
  // Rotation alternatives are separate sets. Do not union the whole signing history.
  // A shared UID or simultaneous multiple signers may require a set with several digests.
  signerDigestSets: readonly (readonly string[])[];
}

/** Read release signer digests from a deployment secret. */
export function trustedApplicationIdentitiesFromEnv(
  packageName: string,
  encoded: string | undefined
): readonly TrustedApplicationIdentity[] {
  if (!packageName || !encoded?.trim()) return [];
  const signerDigestSets = encoded.split(";").map((state) => state.split(",").map((digest) => digest.trim()));
  if (signerDigestSets.some((set) => set.length === 0 || set.some((digest) => !/^[0-9a-f]{64}$/iu.test(digest)))) {
    return [];
  }
  return [{ packageNames: [packageName], signerDigestSets }];
}

function result(status: CloudFinding["status"], title: string, evidence: string): CloudFinding {
  return { status, severity: status === "WARNING" ? "MEDIUM" : "INFO",
    probeId: "cloud.attestation.application_identity", title, evidence };
}

function sameSet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && new Set(left).size === left.length
    && new Set(right).size === right.length && left.every((entry) => right.includes(entry));
}

/** Call only after the chain, hardware level, signature and server challenge have been verified. */
export function evaluateAttestationApplicationIdentity(
  record: AttestationRecord,
  allowedPackage: string,
  identities: readonly TrustedApplicationIdentity[] = []
): CloudFinding {
  if (!allowedPackage || record.applicationId === undefined) {
    return result("UNAVAILABLE", "证明中的应用身份暂时不可用",
      record.applicationIdError ?? "应用身份字段或服务器包名策略缺失；未验证应用来源。");
  }
  const application = record.applicationId;
  const packages = application.packages.map((entry) => entry.name);
  if (!packages.includes(allowedPackage)) {
    return result("WARNING", "证明中的应用包名未通过校验",
      `证明不包含服务器允许的包名 ${allowedPackage}；未验证应用来源，不据此判定设备篡改。`);
  }
  const policies = identities.filter((identity) => identity.packageNames.includes(allowedPackage));
  if (policies.length === 0) {
    return result("UNAVAILABLE", "应用签名信任策略尚未配置", "包名存在，但服务器没有受信签名集合；未验证应用来源。");
  }
  const matchingPackages = policies.filter((identity) => sameSet(identity.packageNames, packages));
  if (matchingPackages.length === 0) {
    return result("WARNING", "证明中的同 UID 应用集合未获批准",
      "包名集合与受信策略不同；可能涉及同 UID 安装变化，未验证应用来源，不据此判定设备篡改。");
  }
  const digestSets = matchingPackages.flatMap((identity) => identity.signerDigestSets);
  if (digestSets.length === 0 || digestSets.some((set) => set.length === 0
      || new Set(set).size !== set.length || set.some((digest) => !/^[0-9a-f]{64}$/u.test(digest)))) {
    return result("UNAVAILABLE", "应用签名信任策略不可用", "受信签名集合缺失或格式错误；未验证应用来源。");
  }
  if (!digestSets.some((set) => sameSet(set, application.signatureDigests))) {
    return result("WARNING", "证明中的应用签名未通过校验",
      "签名摘要集合不匹配服务器批准的发布签名或轮换状态；未验证应用来源，不据此判定设备篡改。");
  }
  return result("CLEAN", "证明中的应用来源校验通过", "同 UID 包名集合与签名证书摘要集合均匹配服务器受信策略。");
}
