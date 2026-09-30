import { describe, expect, it } from "vitest";
import { resolveSignedCore } from "../src/attestation";
import type { CloudAttestationRequest, CloudRequestCore } from "../src/types";

const core: CloudRequestCore = {
  schema: "trustattestor.cloud-request/v1",
  challengeId: "challenge-123",
  nonce: "bm9uY2U=",
  challengeExpiresAt: "2026-08-22T18:30:00.000Z",
  rulesetVersion: 2,
  localReport: { elapsedSeconds: 1 },
  nativeDeviceEvidence: {}
};

function request(
  canonicalCore?: string,
  requestCore: CloudRequestCore = core
): CloudAttestationRequest {
  return {
    schema: "trustattestor.cloud-request/v1",
    ...(canonicalCore === undefined ? {} : { canonicalCore }),
    core: requestCore,
    proof: {
      schema: "trustattestor.native-cloud-proof/v1",
      signatureAlgorithm: "SHA256withECDSA",
      signedPayload: "SHA256(canonical-core)",
      signature: "AA==",
      certificateChain: []
    }
  };
}

describe("signed canonical core", () => {
  it("preserves the exact Android number spelling used for the signature", () => {
    const canonicalCore = [
      "{\"challengeExpiresAt\":\"2026-08-22T18:30:00.000Z\"",
      ",\"challengeId\":\"challenge-123\"",
      ",\"localReport\":{\"elapsedSeconds\":1.0}",
      ",\"nativeDeviceEvidence\":{}",
      ",\"nonce\":\"bm9uY2U=\"",
      ",\"rulesetVersion\":2",
      ",\"schema\":\"trustattestor.cloud-request/v1\"}"
    ].join("");
    expect(resolveSignedCore(request(canonicalCore))).toBe(canonicalCore);
  });

  it("rejects a signed text whose parsed meaning differs from core", () => {
    const mismatched = JSON.stringify({ ...core, nonce: "dGFtcGVyZWQ=" });
    expect(() => resolveSignedCore(request(mismatched))).toThrow("语义不一致");
  });

  it("preserves an explicit signed debug marker", () => {
    const debugCore: CloudRequestCore = { ...core, debug: true };
    const canonicalCore = JSON.stringify(debugCore);
    expect(resolveSignedCore(request(canonicalCore, debugCore))).toBe(canonicalCore);
  });

  it("keeps compatibility with object-only v1 requests", () => {
    expect(JSON.parse(resolveSignedCore(request()))).toEqual(core);
  });
});
