import type { X509Certificate } from "node:crypto";
import { findX509Extension, hasX509SubjectAttribute } from "./der";
import { equalBytes } from "./encoding";
import { GOOGLE_FACTORY_ROOT_SPKI, GOOGLE_ROOT_SPKI } from "./roots";
import type { CloudFinding } from "./types";

const PROVISIONING_INFO_OID = "1.3.6.1.4.1.11129.2.1.30";

export interface AttestationTimeEvidence {
  trustedGoogleRoot: boolean;
  legacyFactoryRoot: boolean;
  factoryProvisioned: boolean;
  rkp: boolean;
  periods: readonly { notBefore: number; notAfter: number }[];
}

function result(status: CloudFinding["status"], title: string, evidence: string): CloudFinding {
  return { status, severity: status === "WARNING" ? "MEDIUM" : "INFO",
    probeId: "cloud.attestation.certificate_validity", title, evidence };
}

/** Date policy only: signatures/anchor and revocation remain separate mandatory checks. */
export function evaluateCertificateTimePolicy(
  evidence: AttestationTimeEvidence,
  revocationStatus: CloudFinding["status"],
  now: number
): CloudFinding {
  if (!evidence.trustedGoogleRoot || !Number.isFinite(now) || evidence.periods.length === 0
      || evidence.periods.some((period) => !Number.isFinite(period.notBefore)
        || !Number.isFinite(period.notAfter) || period.notBefore > period.notAfter)) {
    return result("UNAVAILABLE", "证明证书有效期暂时无法验证", "可信根、服务器时间或证书日期不可用。");
  }
  const future = evidence.periods.findIndex((period) => now < period.notBefore);
  if (future >= 0) {
    return result("WARNING", "证明链包含尚未生效的 CA 证书",
      `CA 路径索引 ${future} 尚未生效；证明时间条件未满足，不据此判定设备篡改。`);
  }
  const expired = evidence.periods.findIndex((period) => now > period.notAfter);
  if (expired < 0) return result("CLEAN", "证明证书有效期校验通过", "服务器时间位于证明 CA 路径的有效期内；目标叶证书日期不用于信任判定。");
  if (!evidence.legacyFactoryRoot || !evidence.factoryProvisioned || evidence.rkp) {
    return result("WARNING", "证明链包含过期证书",
      `CA 路径索引 ${expired} 已过期；RKP 或未确认的 factory 根体系不能使用旧 factory 过期豁免。`);
  }
  if (revocationStatus !== "CLEAN") {
    return result("UNAVAILABLE", "旧 factory 证书过期豁免条件未满足",
      "链已锚定指定旧 factory 根，但尚未取得当前未吊销结论；本次不声明过期证书受信。");
  }
  return result("CLEAN", "旧 factory 证明适用官方过期政策",
    "已锚定指定旧 Google factory 根及 factory 中间证书结构，未发现 RKP provisioning 标记，当前吊销检查通过；依官方政策保留信任。");
}

/** Accepts only a chain already verified by verifyAndroidAttestation. */
export function evaluateAttestationCertificateValidity(
  certificates: readonly X509Certificate[],
  revocation: CloudFinding,
  now = Date.now()
): CloudFinding {
  try {
    const root = certificates.at(-1);
    if (root === undefined || certificates.length < 2) {
      return result("UNAVAILABLE", "证明证书有效期暂时无法验证", "已验证的完整证明链不可用。");
    }
    const spki = Buffer.from(root.publicKey.export({ type: "spki", format: "der" }));
    const timeEvidence: AttestationTimeEvidence = {
      trustedGoogleRoot: GOOGLE_ROOT_SPKI.some((trusted) => equalBytes(trusted, spki)),
      legacyFactoryRoot: equalBytes(GOOGLE_FACTORY_ROOT_SPKI, spki),
      // Official verifier identifies factory provisioning by SERIALNUMBER in the
      // intermediate immediately below the trust anchor. This is never an anchor test.
      factoryProvisioned: certificates.length >= 3
        && hasX509SubjectAttribute(certificates[certificates.length - 2]!.raw, "2.5.4.5"),
      // Presence, even if an optional CBOR value is not understood, disables the exemption.
      rkp: certificates.some((certificate) => findX509Extension(certificate.raw, PROVISIONING_INFO_OID) !== undefined),
      // The target date is chosen by the app and affected by device clock skew;
      // the root is a trust anchor, not a CertPath entry. Match the official
      // verifier's CA-only validity checks (BasicChecker.verifyValidity).
      periods: certificates.slice(1, -1).map((certificate) => ({
        notBefore: Date.parse(certificate.validFrom),
        notAfter: Date.parse(certificate.validTo)
      }))
    };
    const revocationStatus = revocation.probeId === "cloud.attestation.google_revocation"
      ? revocation.status : "UNAVAILABLE";
    return evaluateCertificateTimePolicy(timeEvidence, revocationStatus, now);
  } catch {
    return result("UNAVAILABLE", "证明证书有效期暂时无法验证", "无法确定证书日期或 provisioning 来源，未授予过期豁免。");
  }
}
