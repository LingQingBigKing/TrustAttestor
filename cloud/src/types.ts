export type FindingStatus = "CLEAN" | "DETECTED" | "WARNING" | "UNAVAILABLE";
export type FindingSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type Env = Cloudflare.Env;

export interface ChallengeRequest {
  schema: "trustattestor.challenge-request/v1";
  package: string;
  sdk: number;
}

export interface CloudChallenge {
  schema: "trustattestor.challenge/v1";
  challengeId: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  rulesetVersion: number;
  serverKeyId: string;
}

export interface StoredChallenge extends CloudChallenge {
  packageName: string;
  sdk: number;
  used: boolean;
}

export interface NativeCloudProof {
  schema: "trustattestor.native-cloud-proof/v1";
  signatureAlgorithm: "SHA256withECDSA";
  signedPayload: "SHA256(canonical-core)";
  signature: string;
  certificateChain: string[];
  certificatePatchLevels?: unknown;
}

export interface CloudRequestCore {
  schema: "trustattestor.cloud-request/v1";
  challengeId: string;
  nonce: string;
  challengeExpiresAt: string;
  rulesetVersion: number;
  debug?: boolean;
  localReport: Record<string, unknown>;
  nativeDeviceEvidence: Record<string, unknown>;
}

export interface CloudAttestationRequest {
  schema: "trustattestor.cloud-request/v1";
  canonicalCore?: string;
  core: CloudRequestCore;
  proof: NativeCloudProof;
}

export interface CloudFinding {
  status: FindingStatus;
  severity: FindingSeverity;
  probeId: string;
  title: string;
  evidence: string;
  presentation?: CloudFindingPresentation;
}

export interface CloudFindingLocalizedText {
  title: string;
  evidence: string;
}

export interface CloudFindingPresentation {
  schema: "trustattestor.finding-presentation/v1";
  "zh-CN": CloudFindingLocalizedText;
  "en-US": CloudFindingLocalizedText;
}

export interface CloudVerdict extends CloudFinding {
  challengeId: string;
  verdictId: string;
  issuedAt: string;
  rulesetVersion: number;
  findings?: CloudFinding[];
}

export interface KeyboxBlacklistMatch {
  serialNumber: string;
  certificateSha256: string | null;
  issuerSpkiSha256: string | null;
  source: string;
  reason: string;
  firstSeenAt: string | null;
  matchStrength: "CERTIFICATE_SHA256" | "SERIAL_ISSUER" | "SERIAL_ONLY";
}

export interface AttestationCertificateIdentity {
  serialNumber: string;
  certificateSha256: string;
  issuerSpkiSha256: string;
}

export interface KeyboxBlacklistLookup {
  confirmedMatches: KeyboxBlacklistMatch[];
  serialOnlyMatches: KeyboxBlacklistMatch[];
}

export interface SignedVerdictResponse {
  schema: "trustattestor.verdict/v1";
  verdict: CloudVerdict;
  signature: {
    algorithm: "ECDSA_P256_SHA256";
    keyId: string;
    value: string;
  };
}

export interface AttestationRecord {
  attestationVersion: bigint;
  attestationSecurityLevel: number;
  keyMintVersion: bigint;
  keyMintSecurityLevel: number;
  challenge: Uint8Array;
  applicationId?: AttestationApplicationId;
  applicationIdError?: string;
  osVersion?: bigint;
  osPatchLevel?: bigint;
  vendorPatchLevel?: bigint;
  bootPatchLevel?: bigint;
  verifiedBootKey?: Uint8Array;
  deviceLocked?: boolean;
  verifiedBootState?: number;
  verifiedBootHash?: Uint8Array;
}

export interface AttestationApplicationId {
  packages: { name: string; version: bigint }[];
  signatureDigests: string[];
}
