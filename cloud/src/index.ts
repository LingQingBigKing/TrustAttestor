import { findBlacklistedCertificates } from "./blacklist";
import { evaluateDeviceCatalog } from "./catalog";
import { evaluateLocalEvidenceConsistency } from "./consistency";
import { extractNativeDeviceEvidence } from "./evidence";
import { evaluateKernelPolicy } from "./kernel-policy";
import {
  applyLearnedConsensusFallback,
  consumeObservationBatch,
  createObservationMessage,
  enqueueObservation,
  evaluateLearnedConsensus,
  isEligibleForLearning,
  pruneLearnedObservations,
  type ObservationMessage
} from "./observations";
import {
  evaluateGoogleAttestationRevocation,
  syncGoogleAttestationRevocations
} from "./revocation";
import { ChallengeStore, consumeChallenge, persistChallenge } from "./challenge";
import { encodeBase64 } from "./encoding";
import { verifyAndroidAttestation } from "./attestation";
import { evaluateAttestationApplicationIdentity, trustedApplicationIdentitiesFromEnv } from "./application-identity";
import { evaluateAttestationCertificateValidity } from "./attestation-validity";
import { aggregateAttestationFindings } from "./attestation-policy";
import type {
  AttestationCertificateIdentity,
  ChallengeRequest,
  CloudAttestationRequest,
  CloudChallenge,
  CloudFinding,
  Env,
  NativeCloudProof,
  StoredChallenge
} from "./types";
import { exportVerdictPublicKey, signVerdict } from "./verdict";

export { ChallengeStore };

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=31536000; includeSubDomains"
};
const MAX_REQUEST_BYTES = 1_048_576;
const CHALLENGE_TTL_MS = 120_000;

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: JSON_HEADERS });
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

async function readJson(request: Request): Promise<unknown> {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.startsWith("application/json")) throw new Error("Content-Type 必须为 application/json");
  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BYTES) throw new Error("请求体过大");
  const body = await request.text();
  if (new TextEncoder().encode(body).byteLength > MAX_REQUEST_BYTES) throw new Error("请求体过大");
  return JSON.parse(body) as unknown;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} 必须为对象`);
  return value as Record<string, unknown>;
}

function string(value: unknown, label: string, maxLength = 256): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) throw new Error(`${label} 无效`);
  return value;
}

function integer(value: unknown, label: string, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < min || Number(value) > max) throw new Error(`${label} 无效`);
  return Number(value);
}

function optionalBoolean(value: unknown, label: string): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") throw new Error(`${label} 无效`);
  return value;
}

function parseChallengeRequest(value: unknown, env: Env): ChallengeRequest {
  const input = record(value, "challenge request");
  if (input.schema !== "trustattestor.challenge-request/v1") throw new Error("挑战协议版本不受支持");
  const packageName = string(input.package, "package", 160);
  if (packageName !== env.ALLOWED_PACKAGE) throw new Error("应用包名不受支持");
  return {
    schema: "trustattestor.challenge-request/v1",
    package: packageName,
    sdk: integer(input.sdk, "sdk", 27, 100)
  };
}

function parseAttestationRequest(value: unknown): CloudAttestationRequest {
  const input = record(value, "attestation request");
  if (input.schema !== "trustattestor.cloud-request/v1") throw new Error("云证明协议版本不受支持");
  const canonicalCore = input.canonicalCore === undefined
    ? undefined
    : string(input.canonicalCore, "canonicalCore", MAX_REQUEST_BYTES);
  const coreInput = canonicalCore === undefined
    ? record(input.core, "core")
    : record(JSON.parse(canonicalCore), "canonicalCore");
  if (coreInput.schema !== "trustattestor.cloud-request/v1") throw new Error("core 协议版本不受支持");
  const debug = optionalBoolean(coreInput.debug, "debug");
  const core = {
    ...coreInput,
    schema: "trustattestor.cloud-request/v1" as const,
    challengeId: string(coreInput.challengeId, "challengeId", 128),
    nonce: string(coreInput.nonce, "nonce", 128),
    challengeExpiresAt: string(coreInput.challengeExpiresAt, "challengeExpiresAt", 64),
    rulesetVersion: integer(coreInput.rulesetVersion, "rulesetVersion", 1, 2_147_483_647),
    ...(debug === undefined ? {} : { debug }),
    localReport: record(coreInput.localReport, "localReport"),
    nativeDeviceEvidence: record(coreInput.nativeDeviceEvidence, "nativeDeviceEvidence")
  };
  const proofInput = record(input.proof, "proof");
  const proof: NativeCloudProof = {
    schema: string(proofInput.schema, "proof.schema", 80) as NativeCloudProof["schema"],
    signatureAlgorithm: string(proofInput.signatureAlgorithm, "proof.signatureAlgorithm", 64) as NativeCloudProof["signatureAlgorithm"],
    signedPayload: string(proofInput.signedPayload, "proof.signedPayload", 80) as NativeCloudProof["signedPayload"],
    signature: string(proofInput.signature, "proof.signature", 1024),
    certificateChain: Array.isArray(proofInput.certificateChain)
      ? proofInput.certificateChain.map((entry) => string(entry, "proof.certificateChain[]", 65_536))
      : (() => { throw new Error("proof.certificateChain 必须为数组"); })()
  };
  return {
    schema: "trustattestor.cloud-request/v1",
    ...(canonicalCore === undefined ? {} : { canonicalCore }),
    core,
    proof
  };
}

async function createChallenge(request: Request, env: Env): Promise<Response> {
  const input = parseChallengeRequest(await readJson(request), env);
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + CHALLENGE_TTL_MS);
  const nonce = new Uint8Array(32);
  crypto.getRandomValues(nonce);
  const challenge: CloudChallenge = {
    schema: "trustattestor.challenge/v1",
    challengeId: crypto.randomUUID(),
    nonce: encodeBase64(nonce),
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    rulesetVersion: integer(Number(env.RULESET_VERSION), "RULESET_VERSION", 1, 2_147_483_647),
    serverKeyId: string(env.VERDICT_KEY_ID, "VERDICT_KEY_ID", 128)
  };
  const stored: StoredChallenge = { ...challenge, packageName: input.package, sdk: input.sdk, used: false };
  await persistChallenge(env, stored);
  return json(challenge);
}

async function evaluateKeyboxBlacklist(
  env: Env,
  certificateIdentities: AttestationCertificateIdentity[]
): Promise<CloudFinding> {
  try {
    const lookup = await findBlacklistedCertificates(env, certificateIdentities);
    if (lookup.confirmedMatches.length > 0) {
      const details = lookup.confirmedMatches.map((match) =>
        `匹配=${match.matchStrength}；SerialNumber=${match.serialNumber}；证书SHA-256=${match.certificateSha256}；来源=${match.source}；原因=${match.reason}`
      ).join(" | ");
      return finding(
        "DETECTED",
        "CRITICAL",
        "cloud.keybox.serial_blacklist",
        "检测到已泄露的 Keybox",
        `证书强指纹命中云端泄露 Keybox 黑名单：${details}`
      );
    }
    if (lookup.serialOnlyMatches.length > 0) {
      const details = lookup.serialOnlyMatches.map((match) =>
        `SerialNumber=${match.serialNumber}；来源=${match.source}；原因=${match.reason}`
      ).join(" | ");
      return finding(
        "WARNING",
        "MEDIUM",
        "cloud.keybox.serial_blacklist",
        "Keybox 序列号命中记录仍需强指纹确认",
        `仅 SerialNumber 命中旧版黑名单，不计入异常；等待证书 SHA-256 或 SerialNumber+Issuer SPKI 复核：${details}`
      );
    }
    return finding(
      "CLEAN",
      "INFO",
      "cloud.keybox.serial_blacklist",
      "未命中已收录 Keybox 泄露名单",
      `已核验 ${certificateIdentities.length} 个非根证书强指纹，未发现黑名单命中。`
    );
  } catch {
    return finding(
      "UNAVAILABLE",
      "INFO",
      "cloud.keybox.serial_blacklist",
      "Keybox 黑名单暂时不可用",
      "云端数据库查询失败，本次不会判定设备异常。"
    );
  }
}

async function attest(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  let parsed: CloudAttestationRequest;
  try {
    parsed = parseAttestationRequest(await readJson(request));
  } catch (error) {
    return json({ error: "INVALID_REQUEST", message: error instanceof Error ? error.message : "请求无效" }, 400);
  }
  const challenge: CloudChallenge = {
    schema: "trustattestor.challenge/v1",
    challengeId: parsed.core.challengeId,
    nonce: parsed.core.nonce,
    issuedAt: "",
    expiresAt: parsed.core.challengeExpiresAt,
    rulesetVersion: parsed.core.rulesetVersion,
    serverKeyId: env.VERDICT_KEY_ID
  };
  let allowDebugDetails = false;
  const signedVerdictResponse = (
    result: CloudFinding,
    findings: CloudFinding[] = [result]
  ): Response => json(signVerdict(
    env,
    challenge.challengeId,
    result,
    findings,
    allowDebugDetails
  ));

  let consumed;
  try {
    consumed = await consumeChallenge(env, challenge);
  } catch {
    return signedVerdictResponse(finding(
      "UNAVAILABLE", "INFO", "cloud.challenge.storage", "云端挑战状态不可用", "一次性挑战存储当前无法访问，请稍后重试。"
    ));
  }
  if (!consumed.ok) {
    const mismatch = consumed.reason === "MISMATCH";
    return signedVerdictResponse(finding(
      mismatch ? "DETECTED" : "UNAVAILABLE",
      mismatch ? "CRITICAL" : "INFO",
      "cloud.challenge.binding",
      mismatch ? "云端挑战参数被篡改" : "云端挑战已失效",
      mismatch ? "nonce、有效期或规则版本与服务器签发记录不一致。" : `挑战状态：${consumed.reason ?? "UNKNOWN"}。`
    ));
  }

  const verification = verifyAndroidAttestation(parsed);
  if (!verification.ok) return signedVerdictResponse(verification.finding);
  allowDebugDetails = parsed.core.debug === true;

  const deviceEvidence = extractNativeDeviceEvidence(parsed.core.nativeDeviceEvidence);
  const consistencyFindings = evaluateLocalEvidenceConsistency(
    verification.value.record,
    deviceEvidence
  );
  const networkAddress = request.headers.get("CF-Connecting-IP");
  const observationMessage = createObservationMessage(
    deviceEvidence,
    verification.value.record,
    verification.value.certificateIdentities,
    new Date(),
    {
      ...(networkAddress ? { networkAddress } : {}),
      networkSecret: env.OBSERVATION_NETWORK_KEY
    }
  );
  const certificateSerialNumbers = verification.value.certificates.map((certificate) => certificate.serialNumber);
  const [revocationFinding, keyboxFinding, catalogFindings, kernelFindings, learnedConsensus] = await Promise.all([
    evaluateGoogleAttestationRevocation(env, certificateSerialNumbers),
    evaluateKeyboxBlacklist(env, verification.value.certificateIdentities),
    evaluateDeviceCatalog(env, parsed.core.nativeDeviceEvidence),
    evaluateKernelPolicy(env, deviceEvidence),
    evaluateLearnedConsensus(env, observationMessage)
  ]);
  const certificateValidity = evaluateAttestationCertificateValidity(verification.value.certificates, revocationFinding);
  const applicationIdentity = evaluateAttestationApplicationIdentity(
    verification.value.record,
    env.ALLOWED_PACKAGE,
    trustedApplicationIdentitiesFromEnv(env.ALLOWED_PACKAGE, env.TRUSTED_SIGNER_DIGESTS)
  );
  const findings = applyLearnedConsensusFallback([
    revocationFinding,
    certificateValidity,
    applicationIdentity,
    keyboxFinding,
    ...verification.value.certificateEncodingFindings,
    ...catalogFindings,
    ...consistencyFindings,
    ...kernelFindings
  ], learnedConsensus);
  if (observationMessage !== null && certificateValidity.status === "CLEAN"
      && applicationIdentity.status === "CLEAN" && isEligibleForLearning(findings)) {
    ctx.waitUntil(enqueueObservation(env, observationMessage).catch((error: unknown) => {
      console.error(JSON.stringify({
        message: "trusted observation enqueue failed",
        profileHash: observationMessage.profileHash,
        error: error instanceof Error ? error.message : String(error)
      }));
    }));
  }
  const aggregate = aggregateAttestationFindings(findings);
  if (aggregate.status === "CLEAN") {
    aggregate.evidence += `；${verification.value.summary}。`;
  }
  return signedVerdictResponse(aggregate, findings);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (request.method === "GET" && url.pathname === "/") {
        return json({
          schema: "trustattestor.cloud-service/v1",
          status: "READY",
          rulesetVersion: Number(env.RULESET_VERSION),
          checks: [
            "cloud.attestation.google_revocation",
            "cloud.attestation.application_identity",
            "cloud.attestation.certificate_validity",
            "cloud.attestation.subject_rdn_order",
            "cloud.keybox.serial_blacklist",
            "cloud.device.catalog_consistency",
            "cloud.soc.catalog_consistency",
            "cloud.device.hardware_matrix",
            "cloud.tee.os_version_consistency",
            "cloud.tee.patch_consistency",
            "cloud.attestation.root_of_trust",
            "cloud.build.fingerprint_consistency",
            "cloud.build.timeline_consistency",
            "cloud.kernel.risk_signatures",
            "cloud.kernel.android_compatibility",
            "cloud.observation.consensus"
          ]
        });
      }
      if (request.method === "GET" && url.pathname === "/v1/public-key") {
        return json({
          schema: "trustattestor.verdict-key/v1",
          algorithm: "ECDSA_P256_SHA256",
          keyId: env.VERDICT_KEY_ID,
          publicKey: exportVerdictPublicKey(env)
        });
      }
      if (request.method === "POST" && url.pathname === "/v1/challenges") return await createChallenge(request, env);
      if (request.method === "POST" && url.pathname === "/v1/attest") return await attest(request, env, ctx);
      if (["/v1/challenges", "/v1/attest"].includes(url.pathname)) return json({ error: "METHOD_NOT_ALLOWED" }, 405);
      return json({ error: "NOT_FOUND" }, 404);
    } catch (error) {
      return json({ error: "SERVICE_UNAVAILABLE", message: error instanceof Error ? error.message : "服务暂不可用" }, 503);
    }
  },
  async queue(batch: MessageBatch<ObservationMessage>, env: Env): Promise<void> {
    await consumeObservationBatch(batch, env);
  },
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    const [revocationSync, observationRetention] = await Promise.allSettled([
      syncGoogleAttestationRevocations(env),
      pruneLearnedObservations(env)
    ]);
    if (revocationSync.status === "fulfilled") {
      console.log(JSON.stringify({
        message: "Google attestation revocation sync completed",
        ...revocationSync.value
      }));
    } else {
      console.error(JSON.stringify({
        message: "Google attestation revocation sync failed",
        error: revocationSync.reason instanceof Error
          ? revocationSync.reason.message
          : String(revocationSync.reason)
      }));
    }
    if (observationRetention.status === "rejected") {
      console.error(JSON.stringify({
        message: "trusted observation retention failed",
        error: observationRetention.reason instanceof Error
          ? observationRetention.reason.message
          : String(observationRetention.reason)
      }));
    }
    if (revocationSync.status === "rejected" || observationRetention.status === "rejected") {
      throw new Error("One or more scheduled maintenance jobs failed");
    }
  }
} satisfies ExportedHandler<Env, ObservationMessage>;
