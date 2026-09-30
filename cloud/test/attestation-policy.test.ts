import { describe, expect, it } from "vitest";
import { aggregateAttestationFindings } from "../src/attestation-policy";
import type { CloudFinding } from "../src/types";

const finding = (probeId: string, status: CloudFinding["status"] = "CLEAN"): CloudFinding => ({
  probeId, status, severity: status === "DETECTED" ? "HIGH" : "INFO", title: probeId, evidence: ""
});
const identity = "cloud.attestation.application_identity";
const validity = "cloud.attestation.certificate_validity";
const revocation = "cloud.attestation.google_revocation";

describe("attestation completion gates", () => {
  it("passes only when all required proof checks complete", () => {
    expect(aggregateAttestationFindings([finding(identity), finding(validity), finding(revocation), finding("other")]).status).toBe("CLEAN");
  });
  it("does not hide an unavailable identity or date behind another clean rule", () => {
    expect(aggregateAttestationFindings([finding(identity, "UNAVAILABLE"), finding(validity), finding(revocation), finding("other")]).status).toBe("UNAVAILABLE");
    expect(aggregateAttestationFindings([finding(identity), finding(validity, "UNAVAILABLE"), finding(revocation), finding("other")]).status).toBe("UNAVAILABLE");
    expect(aggregateAttestationFindings([finding(identity), finding(validity), finding(revocation, "UNAVAILABLE"), finding("other")]).status).toBe("UNAVAILABLE");
    expect(aggregateAttestationFindings([finding(identity), finding(validity)]).status).toBe("UNAVAILABLE");
    expect(aggregateAttestationFindings([finding("other")]).status).toBe("UNAVAILABLE");
  });
  it("retains warnings and detected anomalies even if proof evidence is incomplete", () => {
    expect(aggregateAttestationFindings([finding(identity, "WARNING"), finding(validity, "UNAVAILABLE")]).status).toBe("WARNING");
    expect(aggregateAttestationFindings([finding(identity, "UNAVAILABLE"), finding("revoked", "DETECTED")]).status).toBe("DETECTED");
  });
});
