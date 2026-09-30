import { createHash, verify, X509Certificate } from "node:crypto";
import { canonicalize } from "./canonical-json";
import {
  findX509Extension,
  hasX509SubjectAttributeValue,
  inspectX509SubjectRdnSequence,
  parseAndroidAttestationExtension
} from "./der";
import { decodeBase64, equalBytes } from "./encoding";
import { GOOGLE_ROOT_SPKI } from "./roots";
import type {
  AttestationRecord,
  AttestationCertificateIdentity,
  CloudAttestationRequest,
  CloudFinding,
  NativeCloudProof
} from "./types";

const ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17";
const COMMON_NAME_OID = "2.5.4.3";
const TITLE_OID = "2.5.4.12";
const MAX_CERTIFICATES = 8;
const MAX_CERTIFICATE_BYTES = 32_768;

export interface VerifiedAttestation {
  certificates: X509Certificate[];
  serialNumbers: string[];
  certificateIdentities: AttestationCertificateIdentity[];
  certificateEncodingFindings: CloudFinding[];
  record: AttestationRecord;
  summary: string;
}

export type AttestationVerification =
  | { ok: true; value: VerifiedAttestation }
  | { ok: false; finding: CloudFinding };

function finding(
  status: CloudFinding["status"],
  severity: CloudFinding["severity"],
  probeId: string,
  title: string,
  evidence: string
): CloudFinding {
  return { status, severity, probeId, title, evidence };
}

function validateProofShape(proof: NativeCloudProof): void {
  if (proof.schema !== "trustattestor.native-cloud-proof/v1") throw new Error("证明协议版本不受支持");
  if (proof.signatureAlgorithm !== "SHA256withECDSA") throw new Error("设备签名算法不受支持");
  if (proof.signedPayload !== "SHA256(canonical-core)") throw new Error("设备签名载荷类型不受支持");
  if (!Array.isArray(proof.certificateChain) || proof.certificateChain.length < 2 || proof.certificateChain.length > MAX_CERTIFICATES) {
    throw new Error("设备证书链长度无效");
  }
}

function isGoogleTrustAnchor(certificate: X509Certificate): boolean {
  const spki = Buffer.from(certificate.publicKey.export({ type: "spki", format: "der" }));
  return GOOGLE_ROOT_SPKI.some((trusted) => equalBytes(spki, trusted));
}

function isP256(certificate: X509Certificate): boolean {
  const key = certificate.publicKey;
  if (key.asymmetricKeyType !== "ec") return false;
  const curve = key.asymmetricKeyDetails?.namedCurve?.toLowerCase();
  return curve === "prime256v1" || curve === "secp256r1" || curve === "p-256";
}

function verifyCertificateChain(certificates: X509Certificate[]): CloudFinding | undefined {
  const root = certificates.at(-1)!;
  if (!isGoogleTrustAnchor(root)) {
    return finding(
      "WARNING",
      "MEDIUM",
      "cloud.attestation.trust_anchor",
      "证明链不是 Google 信任根",
      `根证书主题：${root.subject || "未知"}；当前首版不将非 Google/OEM 链直接判为异常。`
    );
  }
  for (let index = 0; index < certificates.length - 1; index += 1) {
    const child = certificates[index]!;
    const issuer = certificates[index + 1]!;
    if (!child.checkIssued(issuer) || !child.verify(issuer.publicKey)) {
      return finding(
        "DETECTED",
        "CRITICAL",
        "cloud.attestation.certificate_chain",
        "设备证明证书链签名无效",
        `证书链第 ${index + 1} 层无法由其声明的签发者验证。`
      );
    }
  }
  if (!root.verify(root.publicKey)) {
    return finding(
      "DETECTED",
      "CRITICAL",
      "cloud.attestation.certificate_chain",
      "Google 证明根证书自签名无效",
      "证书链根节点与内置 Google 信任锚公钥匹配，但自签名校验失败。"
    );
  }
  return undefined;
}

function findAttestationRecord(certificates: X509Certificate[]): AttestationRecord {
  for (let index = certificates.length - 2; index >= 0; index -= 1) {
    const certificate = certificates[index]!;
    const extension = findX509Extension(certificate.raw, ATTESTATION_EXTENSION_OID);
    if (extension !== undefined) return parseAndroidAttestationExtension(extension);
  }
  throw new Error("证书链中没有 Android Key Attestation 扩展");
}

function formatPatch(value: bigint | undefined): string {
  if (value === undefined) return "unknown";
  const text = value.toString();
  if (text.length === 6) return `${text.slice(0, 4)}-${text.slice(4, 6)}`;
  if (text.length === 8) return `${text.slice(0, 4)}-${text.slice(4, 6)}-${text.slice(6, 8)}`;
  return text;
}

function evaluateCertificateSubjectRdnOrder(certificates: X509Certificate[]): CloudFinding[] {
  const reversed: Array<{
    index: number;
    profileId: string;
    actualOids: string[];
    expectedOids: string[];
  }> = [];
  // Index 0 is the attested leaf and the final index is the trust anchor.
  // This generator fingerprint is intentionally scoped to TEE intermediate
  // CAs so ordinary leaf/root names and StrongBox profiles cannot trigger it.
  for (let index = 1; index < certificates.length - 1; index += 1) {
    const certificate = certificates[index]!;
    if (!certificate.ca) continue;
    try {
      const isTee = hasX509SubjectAttributeValue(certificate.raw, TITLE_OID, "TEE")
        || hasX509SubjectAttributeValue(certificate.raw, COMMON_NAME_OID, "TEE");
      if (!isTee) continue;
      const inspection = inspectX509SubjectRdnSequence(certificate.raw);
      if (
        inspection.classification === "REVERSED"
        && inspection.profileId !== undefined
        && inspection.expectedOids !== undefined
      ) {
        reversed.push({
          index,
          profileId: inspection.profileId,
          actualOids: inspection.actualOids,
          expectedOids: inspection.expectedOids
        });
      }
    } catch {
      // The certificate has already passed the runtime X.509 parser. This
      // optional structural fingerprint must fail closed as not-applicable,
      // never turn a parser compatibility issue into a device anomaly.
    }
  }
  if (reversed.length === 0) return [];
  const details = reversed.map((item) =>
    `索引 ${item.index}(${item.profileId})：实际=[${item.actualOids.join(", ")}]，` +
    `预期=[${item.expectedOids.join(", ")}]`
  ).join("；");
  return [finding(
    "DETECTED",
    "HIGH",
    "cloud.attestation.subject_rdn_order",
    "证书编码序列异常",
    `TEE 中间 CA 的 Subject 原始 DER RDNSequence 与已审核模板完整逆序：${details}；` +
      "疑似用户态 X.509 库重构证明证书。"
  )];
}

function sha256Hex(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export function resolveSignedCore(request: CloudAttestationRequest): string {
  if (request.canonicalCore === undefined) return canonicalize(request.core);
  const parsed = JSON.parse(request.canonicalCore) as unknown;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("canonicalCore 必须编码一个 JSON 对象");
  }
  if (canonicalize(parsed) !== canonicalize(request.core)) {
    throw new Error("canonicalCore 与已解析的 core 语义不一致");
  }
  return request.canonicalCore;
}

export function verifyAndroidAttestation(request: CloudAttestationRequest): AttestationVerification {
  try {
    validateProofShape(request.proof);
    const certificates = request.proof.certificateChain.map((encoded) =>
      new X509Certificate(decodeBase64(encoded, MAX_CERTIFICATE_BYTES))
    );
    const chainFinding = verifyCertificateChain(certificates);
    if (chainFinding !== undefined) return { ok: false, finding: chainFinding };

    const leaf = certificates[0]!;
    if (!isP256(leaf)) {
      return {
        ok: false,
        finding: finding(
          "UNAVAILABLE",
          "INFO",
          "cloud.attestation.device_key",
          "设备证明密钥算法暂不支持",
          "当前协议仅支持由 AndroidKeyStore 生成的 P-256 EC 证明密钥。"
        )
      };
    }

    const canonicalCore = resolveSignedCore(request);
    const digest = createHash("sha256").update(canonicalCore, "utf8").digest();
    const signature = decodeBase64(request.proof.signature, 512);
    if (!verify("sha256", digest, leaf.publicKey, signature)) {
      return {
        ok: false,
        finding: finding(
          "UNAVAILABLE",
          "INFO",
          "cloud.attestation.payload_signature",
          "设备证明载荷签名无法验证",
          "canonical-core 摘要未能通过证书链叶子公钥验证，本次不会判定设备异常。"
        )
      };
    }

    const record = findAttestationRecord(certificates);
    const expectedNonce = decodeBase64(request.core.nonce, 64);
    if (!equalBytes(record.challenge, expectedNonce)) {
      return {
        ok: false,
        finding: finding(
          "DETECTED",
          "CRITICAL",
          "cloud.attestation.challenge_binding",
          "设备证明未绑定本次云端挑战",
          "Android Key Attestation 扩展内的 challenge 与本次一次性 nonce 不一致。"
        )
      };
    }

    if (![1, 2].includes(record.attestationSecurityLevel) || ![1, 2].includes(record.keyMintSecurityLevel)) {
      return {
        ok: false,
        finding: finding(
          "WARNING",
          "MEDIUM",
          "cloud.attestation.security_level",
          "设备证明未达到硬件安全级别",
          `attestationSecurityLevel=${record.attestationSecurityLevel}，keyMintSecurityLevel=${record.keyMintSecurityLevel}。`
        )
      };
    }

    const certificateIdentities = certificates.slice(0, -1).map((certificate, index) => {
      const issuer = certificates[index + 1]!;
      return {
        serialNumber: certificate.serialNumber,
        certificateSha256: sha256Hex(certificate.raw),
        issuerSpkiSha256: sha256Hex(
          Buffer.from(issuer.publicKey.export({ type: "spki", format: "der" }))
        )
      };
    });
    const serialNumbers = certificateIdentities.map((identity) => identity.serialNumber);
    return {
      ok: true,
      value: {
        certificates,
        serialNumbers,
        certificateIdentities,
        certificateEncodingFindings: evaluateCertificateSubjectRdnOrder(certificates),
        record,
        summary: [
          `证书链 ${certificates.length} 节`,
          `RootOfTrust locked=${String(record.deviceLocked)} state=${String(record.verifiedBootState)}`,
          `OS patch ${formatPatch(record.osPatchLevel)}`,
          `Vendor patch ${formatPatch(record.vendorPatchLevel)}`,
          `Boot patch ${formatPatch(record.bootPatchLevel)}`
        ].join("；")
      }
    };
  } catch (error) {
    return {
      ok: false,
      finding: finding(
        "UNAVAILABLE",
        "INFO",
        "cloud.attestation.verification",
        "设备证明暂时无法验证",
        error instanceof Error ? error.message : "未知验证错误"
      )
    };
  }
}
