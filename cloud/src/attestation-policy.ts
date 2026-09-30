import { aggregateFindings } from "./verdict";
import type { CloudFinding } from "./types";

const REQUIRED_PROOF_FINDINGS = [
  "cloud.attestation.google_revocation",
  "cloud.attestation.application_identity",
  "cloud.attestation.certificate_validity"
] as const;

/** /v1/attest requires revocation, application and time evidence before an overall pass. */
export function aggregateAttestationFindings(findings: CloudFinding[]): CloudFinding {
  const aggregate = aggregateFindings(findings);
  if (aggregate.status !== "CLEAN") return aggregate;
  const incomplete = REQUIRED_PROOF_FINDINGS.filter((probeId) => {
    const matches = findings.filter((item) => item.probeId === probeId);
    return matches.length !== 1 || matches[0]!.status !== "CLEAN";
  });
  if (incomplete.length === 0) return aggregate;
  return {
    status: "UNAVAILABLE", severity: "INFO", probeId: "cloud.attestation.verdict",
    title: "云端证明校验未完成",
    evidence: `必需证明校验尚未完成：${incomplete.join(", ")}；保留其他规则结果，本次不声明完整通过。`
  };
}
