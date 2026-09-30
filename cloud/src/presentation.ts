import type {
  CloudFinding,
  CloudFindingLocalizedText,
  CloudFindingPresentation,
  FindingStatus
} from "./types";

const PRESENTATION_SCHEMA = "trustattestor.finding-presentation/v1";
const MAX_TITLE_LENGTH = 128;
const MAX_EVIDENCE_LENGTH = 4096;

const PROBE_NAMES: Record<string, string> = {
  "cloud.attestation.aggregate": "Cloud aggregate risk assessment",
  "cloud.attestation.certificate_chain": "Attestation certificate chain",
  "cloud.attestation.certificate_validity": "Attestation certificate validity",
  "cloud.attestation.application_identity": "Attested application identity",
  "cloud.attestation.challenge_binding": "Attestation challenge binding",
  "cloud.attestation.device_key": "Attested device key",
  "cloud.attestation.google_revocation": "Google attestation revocation check",
  "cloud.attestation.payload_signature": "Attestation payload signature",
  "cloud.attestation.root_of_trust": "Hardware Root of Trust",
  "cloud.attestation.security_level": "Attestation security level",
  "cloud.attestation.subject_rdn_order": "Certificate encoding order",
  "cloud.attestation.trust_anchor": "Attestation trust anchor",
  "cloud.attestation.verdict": "Cloud attestation verdict",
  "cloud.attestation.verification": "Android key attestation verification",
  "cloud.build.fingerprint_consistency": "Build fingerprint consistency",
  "cloud.build.timeline_consistency": "Build timeline consistency",
  "cloud.challenge.binding": "One-time cloud challenge binding",
  "cloud.challenge.storage": "Cloud challenge storage",
  "cloud.device.catalog_consistency": "Device catalog consistency",
  "cloud.device.hardware_matrix": "Device fingerprint and vendor metadata",
  "cloud.kernel.android_compatibility": "Android kernel compatibility",
  "cloud.kernel.risk_signatures": "Kernel risk-signature check",
  "cloud.keybox.serial_blacklist": "Leaked Keybox blacklist",
  "cloud.observation.consensus": "Trusted device observation consensus",
  "cloud.soc.catalog_consistency": "SoC catalog consistency",
  "cloud.tee.os_version_consistency": "TEE and userspace OS version consistency",
  "cloud.tee.patch_consistency": "TEE and userspace patch consistency"
};

const TITLE_OVERRIDES: Record<string, string> = {
  "cloud.attestation.google_revocation:CLEAN": "Certificate is not revoked by Google",
  "cloud.attestation.google_revocation:DETECTED": "Certificate has been revoked by Google",
  "cloud.attestation.subject_rdn_order:DETECTED": "Certificate encoding order anomaly",
  "cloud.attestation.verdict:CLEAN": "Cloud risk assessment passed",
  "cloud.attestation.aggregate:CLEAN": "Cloud aggregate risk assessment passed",
  "cloud.device.catalog_consistency:CLEAN": "Device fingerprint matches vendor metadata",
  "cloud.device.hardware_matrix:CLEAN": "Device fingerprint matches vendor metadata",
  "cloud.soc.catalog_consistency:CLEAN": "SoC identity and platform specification verified",
  "cloud.kernel.android_compatibility:CLEAN": "Kernel version is compatible with the Android version",
  "cloud.kernel.risk_signatures:CLEAN": "Kernel build metadata does not match a risk signature",
  "cloud.keybox.serial_blacklist:CLEAN": "No match in the recorded leaked Keybox list",
  "cloud.keybox.serial_blacklist:DETECTED": "Known leaked Keybox detected",
  "cloud.keybox.serial_blacklist:WARNING": "Keybox serial requires strong-fingerprint confirmation",
  "cloud.observation.consensus:CLEAN": "Device observations are consistent"
};

function cleanTitle(value: string, fallback: string): string {
  const normalized = value.trim().replace(/[\u0000-\u001f\u007f]+/gu, " ").trim();
  return (normalized || fallback).slice(0, MAX_TITLE_LENGTH);
}

function cleanEvidence(value: string): string {
  return value.replaceAll("\u0000", "").trim().slice(0, MAX_EVIDENCE_LENGTH);
}

function localizedText(title: string, evidence: string, fallbackTitle: string): CloudFindingLocalizedText {
  return {
    title: cleanTitle(title, fallbackTitle),
    evidence: cleanEvidence(evidence)
  };
}

function genericEnglishTitle(probeId: string, status: FindingStatus): string {
  const name = PROBE_NAMES[probeId] ?? `Cloud rule ${probeId}`;
  if (status === "CLEAN") return `${name} passed`;
  if (status === "DETECTED") return `${name} detected an anomaly`;
  if (status === "WARNING") return `${name} requires attention`;
  return `${name} is unavailable`;
}

function englishTitle(finding: CloudFinding): string {
  return TITLE_OVERRIDES[`${finding.probeId}:${finding.status}`]
    ?? genericEnglishTitle(finding.probeId, finding.status);
}

function englishEvidence(finding: CloudFinding): string {
  if (finding.status === "CLEAN") {
    return `The signed server rule ${finding.probeId} completed without a policy violation.`;
  }
  if (finding.status === "DETECTED") {
    return `The signed server rule ${finding.probeId} confirmed a cryptographic or policy violation.`;
  }
  if (finding.status === "WARNING") {
    return `The signed server rule ${finding.probeId} returned suspicious but non-conclusive evidence.`;
  }
  return `The signed server rule ${finding.probeId} could not complete; this is not counted as an anomaly.`;
}

function sanitizePresentation(
  presentation: CloudFindingPresentation,
  includeEvidence: boolean
): CloudFindingPresentation {
  return {
    schema: PRESENTATION_SCHEMA,
    "zh-CN": localizedText(
      presentation["zh-CN"].title,
      includeEvidence ? presentation["zh-CN"].evidence : "",
      "云端检测结果"
    ),
    "en-US": localizedText(
      presentation["en-US"].title,
      includeEvidence ? presentation["en-US"].evidence : "",
      "Cloud attestation result"
    )
  };
}

/** Adds bounded bilingual UI copy before the verdict is canonicalized and signed. */
export function withFindingPresentation(
  finding: CloudFinding,
  includeEvidence: boolean
): CloudFinding {
  if (finding.presentation !== undefined) {
    return {
      ...finding,
      evidence: includeEvidence ? cleanEvidence(finding.evidence) : "",
      presentation: sanitizePresentation(finding.presentation, includeEvidence)
    };
  }
  const presentation: CloudFindingPresentation = {
    schema: PRESENTATION_SCHEMA,
    "zh-CN": localizedText(
      finding.title,
      includeEvidence ? finding.evidence : "",
      "云端检测结果"
    ),
    "en-US": localizedText(
      englishTitle(finding),
      includeEvidence ? englishEvidence(finding) : "",
      "Cloud attestation result"
    )
  };
  return {
    ...finding,
    evidence: includeEvidence ? cleanEvidence(finding.evidence) : "",
    presentation
  };
}
