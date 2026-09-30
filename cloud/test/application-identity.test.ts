import { describe, expect, it } from "vitest";
import { evaluateAttestationApplicationIdentity, trustedApplicationIdentitiesFromEnv } from "../src/application-identity";
import type { TrustedApplicationIdentity } from "../src/application-identity";
import type { AttestationRecord } from "../src/types";
import { aggregateFindings } from "../src/verdict";

const packageName = "com.example.app";
const oldSigner = "11".repeat(32);
const newSigner = "22".repeat(32);
const peerSigner = "33".repeat(32);
const policy: TrustedApplicationIdentity[] = [{
  packageNames: [packageName], signerDigestSets: [[oldSigner], [newSigner]]
}];

function record(packages = [packageName], signatureDigests = [oldSigner]): AttestationRecord {
  return {
    attestationVersion: 400n, keyMintVersion: 400n, attestationSecurityLevel: 1, keyMintSecurityLevel: 1,
    challenge: new Uint8Array([1]),
    applicationId: { packages: packages.map((name) => ({ name, version: 14n })), signatureDigests }
  };
}

describe("server-approved attestation application identity", () => {
  it("accepts each explicitly approved rotation state without accepting their union", () => {
    expect(evaluateAttestationApplicationIdentity(record(), packageName, policy).status).toBe("CLEAN");
    expect(evaluateAttestationApplicationIdentity(record([packageName], [newSigner]), packageName, policy).status).toBe("CLEAN");
    expect(evaluateAttestationApplicationIdentity(record([packageName], [oldSigner, newSigner]), packageName, policy).status).toBe("WARNING");
  });

  it("requires the complete simultaneously approved signer set", () => {
    const multiSigner = [{ packageNames: [packageName], signerDigestSets: [[oldSigner, peerSigner]] }];
    expect(evaluateAttestationApplicationIdentity(record([packageName], [peerSigner, oldSigner]), packageName, multiSigner).status).toBe("CLEAN");
    expect(evaluateAttestationApplicationIdentity(record(), packageName, multiSigner).status).toBe("WARNING");
  });

  it("accepts approved shared UID packages and signer unions independent of order", () => {
    const sharedUid = [{ packageNames: [packageName, "com.example.peer"], signerDigestSets: [[oldSigner, peerSigner]] }];
    const shared = record(["com.example.peer", packageName], [peerSigner, oldSigner]);
    expect(evaluateAttestationApplicationIdentity(shared, packageName, sharedUid).status).toBe("CLEAN");
    expect(evaluateAttestationApplicationIdentity(shared, packageName, policy).status).toBe("WARNING");
    expect(evaluateAttestationApplicationIdentity(record(["com.example.peer"]), packageName, sharedUid).status).toBe("WARNING");
  });

  it("does not accept a matching signature for another package", () => {
    expect(evaluateAttestationApplicationIdentity(record(["com.example.other"]), packageName, policy).status).toBe("WARNING");
  });

  it("does not turn missing fields or incomplete server configuration into an anomaly or a pass", () => {
    const missing = record();
    delete missing.applicationId;
    expect(evaluateAttestationApplicationIdentity(missing, packageName, policy).status).toBe("UNAVAILABLE");
    expect(evaluateAttestationApplicationIdentity(record(), packageName, []).status).toBe("UNAVAILABLE");
    expect(evaluateAttestationApplicationIdentity(record(), packageName, [{ packageNames: [packageName], signerDigestSets: [["invalid"]] }]).status).toBe("UNAVAILABLE");
  });

  it("does not accept duplicate identities as sets", () => {
    expect(evaluateAttestationApplicationIdentity(record([packageName, packageName]), packageName, policy).status).toBe("WARNING");
    expect(evaluateAttestationApplicationIdentity(record([packageName], [oldSigner, oldSigner]), packageName, policy).status).toBe("WARNING");
  });

  it("uses the independently verified release signer and has no debug-request bypass", () => {
    const release = trustedApplicationIdentitiesFromEnv(packageName, `${oldSigner};${newSigner}`)[0]!;
    expect(evaluateAttestationApplicationIdentity(record([...release.packageNames], [...release.signerDigestSets[0]!]), release.packageNames[0]!, [release]).status).toBe("CLEAN");
    const unapproved = evaluateAttestationApplicationIdentity(record([...release.packageNames], [peerSigner]), release.packageNames[0]!, [release]);
    expect(unapproved.status).toBe("WARNING");
    expect(aggregateFindings([unapproved, {
      status: "CLEAN", severity: "INFO", probeId: "other", title: "Other check passed", evidence: ""
    }]).status).toBe("WARNING");
  });

  it("does not load release signer material from malformed deployment input", () => {
    expect(trustedApplicationIdentitiesFromEnv(packageName, "not-a-digest")).toEqual([]);
    expect(trustedApplicationIdentitiesFromEnv(packageName, "")).toEqual([]);
  });
});
