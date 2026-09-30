import { X509Certificate } from "node:crypto";
import { describe, expect, it } from "vitest";
import { evaluateAttestationCertificateValidity, evaluateCertificateTimePolicy } from "../src/attestation-validity";
import type { AttestationTimeEvidence } from "../src/attestation-validity";
import { GOOGLE_ROOT_CERTIFICATES } from "../src/roots";
import type { CloudFinding } from "../src/types";

const now = Date.parse("2026-09-12T00:00:00Z");
const day = 86_400_000;
const normal: AttestationTimeEvidence = {
  trustedGoogleRoot: true, legacyFactoryRoot: true, factoryProvisioned: true, rkp: false,
  periods: [{ notBefore: now - day, notAfter: now + day }]
};
const expired: AttestationTimeEvidence = { ...normal, periods: [{ notBefore: now - 2 * day, notAfter: now - day }] };

describe("Google factory and RKP certificate time policy", () => {
  it("accepts current validity including both boundary instants", () => {
    for (const at of [now - day, now, now + day]) {
      expect(evaluateCertificateTimePolicy(normal, "CLEAN", at).status).toBe("CLEAN");
    }
  });

  it("exempts expired legacy factory chains only after a current clean revocation result", () => {
    expect(evaluateCertificateTimePolicy(expired, "CLEAN", now).status).toBe("CLEAN");
    for (const status of ["UNAVAILABLE", "WARNING", "DETECTED"] as const) {
      expect(evaluateCertificateTimePolicy(expired, status, now).status).toBe("UNAVAILABLE");
    }
  });

  it("does not exempt RKP under a legacy root or any chain under a new root", () => {
    expect(evaluateCertificateTimePolicy({ ...expired, rkp: true }, "CLEAN", now).status).toBe("WARNING");
    expect(evaluateCertificateTimePolicy({ ...expired, legacyFactoryRoot: false }, "CLEAN", now).status).toBe("WARNING");
    expect(evaluateCertificateTimePolicy({ ...expired, factoryProvisioned: false }, "CLEAN", now).status).toBe("WARNING");
  });

  it("does not grant an exemption by claiming factory without a trusted root", () => {
    expect(evaluateCertificateTimePolicy({ ...expired, trustedGoogleRoot: false }, "CLEAN", now).status).toBe("UNAVAILABLE");
  });

  it("reports future and invalid dates separately from expiration", () => {
    expect(evaluateCertificateTimePolicy({ ...normal, periods: [{ notBefore: now + day, notAfter: now + 2 * day }] }, "CLEAN", now).status).toBe("WARNING");
    expect(evaluateCertificateTimePolicy({ ...normal, periods: [{ notBefore: now, notAfter: now - day }] }, "CLEAN", now).status).toBe("UNAVAILABLE");
    expect(evaluateCertificateTimePolicy(normal, "CLEAN", NaN).status).toBe("UNAVAILABLE");
  });

  it("checks every CA path node", () => {
    const withExpiredIntermediate = { ...normal, rkp: true, periods: [...normal.periods, ...expired.periods] };
    expect(evaluateCertificateTimePolicy(withExpiredIntermediate, "CLEAN", now).status).toBe("WARNING");
  });

  it("classifies the actual baked-in roots by SPKI rather than supplied names", () => {
    const revocation: CloudFinding = { status: "CLEAN", severity: "INFO", probeId: "cloud.attestation.google_revocation", title: "", evidence: "" };
    // The date wrapper consumes already-verified chain certificates; duplicate roots here
    // isolate its real X.509/SPKI/date parsing, without pretending to test chain validation.
    const factory = new X509Certificate(GOOGLE_ROOT_CERTIFICATES[0]!.raw);
    const rkpRoot = new X509Certificate(GOOGLE_ROOT_CERTIFICATES[1]!.raw);
    const later = Date.parse("2050-01-01T00:00:00Z");
    expect(evaluateAttestationCertificateValidity([factory, factory, factory], revocation, later).status).toBe("CLEAN");
    expect(evaluateAttestationCertificateValidity([rkpRoot, rkpRoot, rkpRoot], revocation, later).status).toBe("WARNING");
    expect(evaluateAttestationCertificateValidity([factory, factory, factory], { ...revocation, probeId: "other" }, later).status).toBe("UNAVAILABLE");
    // In 2040 the target here is expired but the CA is valid; target dates do not
    // establish proof freshness, which remains bound to the server's nonce.
    expect(evaluateAttestationCertificateValidity([rkpRoot, factory, factory], revocation, Date.parse("2040-01-01T00:00:00Z")).status).toBe("CLEAN");
  });
});
