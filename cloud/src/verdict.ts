import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { canonicalize } from "./canonical-json";
import { encodeBase64 } from "./encoding";
import { withFindingPresentation } from "./presentation";
import type { CloudFinding, CloudVerdict, Env, SignedVerdictResponse } from "./types";

function verdictPrivateKeyPem(env: Env): string {
  const pem = env.VERDICT_PRIVATE_KEY.replace(/\\n/g, "\n");
  const key = createPrivateKey(pem);
  const details = key.asymmetricKeyDetails;
  const curve = details?.namedCurve?.toLowerCase();
  if (key.asymmetricKeyType !== "ec" || !["prime256v1", "secp256r1", "p-256"].includes(curve ?? "")) {
    throw new Error("VERDICT_PRIVATE_KEY must be an EC P-256 private key");
  }
  return pem;
}

export function exportVerdictPublicKey(env: Env): string {
  const publicKey = createPublicKey(verdictPrivateKeyPem(env)).export({ type: "spki", format: "der" });
  return encodeBase64(publicKey);
}

const STATUS_RANK: Record<CloudFinding["status"], number> = {
  CLEAN: 0,
  UNAVAILABLE: 1,
  WARNING: 2,
  DETECTED: 3
};

const SEVERITY_RANK: Record<CloudFinding["severity"], number> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4
};

export function aggregateFindings(findings: CloudFinding[]): CloudFinding {
  if (findings.length === 0) {
    return {
      status: "UNAVAILABLE",
      severity: "INFO",
      probeId: "cloud.attestation.verdict",
      title: "云端风险评估不可用",
      evidence: "服务器未产生任何可验证的规则结果。"
    };
  }
  const actionable = findings.filter((finding) =>
    finding.status === "DETECTED" || finding.status === "WARNING"
  );
  const completed = findings.filter((finding) => finding.status === "CLEAN");
  const unavailable = findings.filter((finding) => finding.status === "UNAVAILABLE");
  if (actionable.length === 0 && completed.length > 0) {
    return {
      status: "CLEAN",
      severity: "INFO",
      probeId: "cloud.attestation.verdict",
      title: "云端风险评估通过",
      evidence: findings.map((finding) => `${finding.probeId}：${finding.title}`).join("；")
    };
  }
  if (actionable.length === 0) {
    if (unavailable.length === 1) return unavailable[0]!;
    return {
      status: "UNAVAILABLE",
      severity: "INFO",
      probeId: "cloud.attestation.aggregate",
      title: "全部云端规则均不可用",
      evidence: unavailable.map((item) => `[${item.probeId}] ${item.title}：${item.evidence}`).join("\n")
    };
  }
  const sorted = [...actionable].sort((left, right) =>
    STATUS_RANK[right.status] - STATUS_RANK[left.status]
      || SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity]
  );
  if (actionable.length === 1) return sorted[0]!;
  const strongest = sorted[0]!;
  return {
    status: strongest.status,
    severity: strongest.severity,
    probeId: "cloud.attestation.aggregate",
    title: strongest.status === "DETECTED"
      ? `云端确认 ${actionable.filter((item) => item.status === "DETECTED").length} 项异常`
      : "云端返回多项需关注证据",
    evidence: sorted.map((item) => `[${item.probeId}] ${item.title}：${item.evidence}`).join("\n")
  };
}

export function signVerdict(
  env: Env,
  challengeId: string,
  finding: CloudFinding,
  findings: CloudFinding[] = [finding],
  debug = false
): SignedVerdictResponse {
  const presentedFinding = withFindingPresentation(finding, debug);
  const returnedFindings = (debug
    ? findings
    : findings.filter((item) => item.status === "DETECTED" || item.status === "UNAVAILABLE"))
    .map((item) => withFindingPresentation(item, debug));
  const verdict: CloudVerdict = {
    challengeId,
    verdictId: crypto.randomUUID(),
    issuedAt: new Date().toISOString(),
    rulesetVersion: Number(env.RULESET_VERSION),
    ...presentedFinding,
    ...(returnedFindings.length === 0 ? {} : { findings: returnedFindings })
  };
  const signature = sign("sha256", Buffer.from(canonicalize(verdict), "utf8"), {
    // Cloudflare's node:crypto compatibility layer rejects PrivateKeyObject here.
    // Pass the already validated PEM input so production and Node use the same path.
    key: verdictPrivateKeyPem(env),
    dsaEncoding: "der"
  });
  return {
    schema: "trustattestor.verdict/v1",
    verdict,
    signature: {
      algorithm: "ECDSA_P256_SHA256",
      keyId: env.VERDICT_KEY_ID,
      value: encodeBase64(signature)
    }
  };
}
