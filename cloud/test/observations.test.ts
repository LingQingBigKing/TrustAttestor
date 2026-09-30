import { describe, expect, it } from "vitest";
import type { NativeDeviceEvidence } from "../src/evidence";
import {
  applyLearnedConsensusFallback,
  classifyLearnedConsensus,
  createObservationMessage,
  isEligibleForLearning,
  validateObservationMessage
} from "../src/observations";
import type { AttestationCertificateIdentity, AttestationRecord, CloudFinding } from "../src/types";

function evidence(): NativeDeviceEvidence {
  return {
    schema: "trustattestor.native-device/v1",
    device: {
      model: "Pixel 10 Pro", product: "blazer", device: "blazer", board: "blazer",
      manufacturer: "Google", brand: "google", sku: "global"
    },
    os: {
      release: "15", releaseOrCodename: "15", sdk: 35, buildId: "AP4A.250105.002",
      incremental: "12345678", securityPatch: "2025-01-05", vendorSecurityPatch: "2025-01-05",
      buildTime: "", buildTimeUtc: 1_736_899_200, vendorBuildTimeUtc: 1_736_899_200,
      bootImageBuildTimeUtc: 1_736_899_200, buildType: "user", buildTags: "release-keys",
      instructionSet: "arm64-v8a",
      fingerprint: "google/blazer/blazer:15/AP4A.250105.002/12345678:user/release-keys"
    },
    processor: {
      hardware: "tensor g5", boardPlatform: "laguna", socManufacturer: "Google",
      socModel: "Tensor G5", supportedAbis: ["arm64-v8a"], supportedAbis32: [], supportedAbis64: ["arm64-v8a"]
    },
    kernel: { release: "6.1.99-android15", buildVersion: "private build banner", machine: "aarch64" },
    boot: {
      vbmetaDeviceState: "locked", verifiedBootState: "green", flashLocked: "1",
      verityMode: "enforcing", vbmetaDigest: "bb"
    }
  };
}

function attestation(): AttestationRecord {
  return {
    attestationVersion: 400n, attestationSecurityLevel: 1,
    keyMintVersion: 400n, keyMintSecurityLevel: 1,
    challenge: new Uint8Array([1]), osVersion: 150000n, osPatchLevel: 202501n,
    vendorPatchLevel: 20250105n, bootPatchLevel: 20250105n,
    deviceLocked: true, verifiedBootState: 0
  };
}

const identities: AttestationCertificateIdentity[] = [{
  serialNumber: "01",
  certificateSha256: "a".repeat(64),
  issuerSpkiSha256: "b".repeat(64)
}];

function finding(probeId: string, status: CloudFinding["status"] = "CLEAN"): CloudFinding {
  return { probeId, status, severity: status === "CLEAN" ? "INFO" : "MEDIUM", title: probeId, evidence: "fixture" };
}

function learningGates(): CloudFinding[] {
  return [
    "cloud.keybox.serial_blacklist",
    "cloud.tee.os_version_consistency",
    "cloud.tee.patch_consistency",
    "cloud.attestation.root_of_trust",
    "cloud.build.fingerprint_consistency",
    "cloud.kernel.risk_signatures"
  ].map((probeId) => finding(probeId));
}

describe("trusted observation messages", () => {
  it("normalizes profiles and derives stable hashes", () => {
    const first = createObservationMessage(evidence(), attestation(), identities, new Date("2026-08-23T00:00:00Z"));
    const secondEvidence = evidence();
    secondEvidence.device.manufacturer = "  GOOGLE ";
    const second = createObservationMessage(secondEvidence, attestation(), identities, new Date("2026-08-24T00:00:00Z"));
    expect(first).not.toBeNull();
    expect(second?.profileHash).toBe(first?.profileHash);
    expect(second?.firmwareKey).toBe(first?.firmwareKey);
    expect(second?.sourceKeyHash).toBe(first?.sourceKeyHash);
    expect(first?.profile).not.toHaveProperty("kernelRelease");
    expect(first?.profile).not.toHaveProperty("kernelMachine");
  });

  it("rejects incomplete profiles and tampered hashes", () => {
    const incomplete = evidence();
    incomplete.device.product = "";
    expect(createObservationMessage(incomplete, attestation(), identities)).toBeNull();
    const message = createObservationMessage(evidence(), attestation(), identities)!;
    expect(() => validateObservationMessage({ ...message, profileHash: "0".repeat(64) })).toThrow(/profileHash/u);
  });

  it("only emits passive observations from a locked green Root of Trust", () => {
    const unlocked = attestation();
    unlocked.deviceLocked = false;
    expect(createObservationMessage(evidence(), unlocked, identities)).toBeNull();
    const yellow = attestation();
    yellow.verifiedBootState = 1;
    expect(createObservationMessage(evidence(), yellow, identities)).toBeNull();
  });

  it("stores only a keyed network HMAC pseudonym", () => {
    const first = createObservationMessage(
      evidence(), attestation(), identities, new Date("2026-08-23T00:00:00Z"),
      { networkAddress: "203.0.113.10", networkSecret: "test-secret" }
    );
    const sameMonth = createObservationMessage(
      evidence(), attestation(), identities, new Date("2026-08-31T00:00:00Z"),
      { networkAddress: "203.0.113.10", networkSecret: "test-secret" }
    );
    const nextMonth = createObservationMessage(
      evidence(), attestation(), identities, new Date("2026-09-01T00:00:00Z"),
      { networkAddress: "203.0.113.10", networkSecret: "test-secret" }
    );
    const otherNetwork = createObservationMessage(
      evidence(), attestation(), identities, new Date("2026-08-23T00:00:00Z"),
      { networkAddress: "203.0.113.11", networkSecret: "test-secret" }
    );
    expect(first?.networkKeyHash).toMatch(/^[0-9a-f]{64}$/u);
    expect(sameMonth?.networkKeyHash).toBe(first?.networkKeyHash);
    expect(nextMonth?.networkKeyHash).toBe(first?.networkKeyHash);
    expect(otherNetwork?.networkKeyHash).not.toBe(first?.networkKeyHash);
  });

  it("requires every cryptographic and low-risk learning gate to be clean", () => {
    expect(isEligibleForLearning(learningGates())).toBe(true);
    expect(isEligibleForLearning([
      ...learningGates().filter((item) => item.probeId !== "cloud.keybox.serial_blacklist"),
      finding("cloud.keybox.serial_blacklist", "UNAVAILABLE")
    ])).toBe(false);
    expect(isEligibleForLearning([
      ...learningGates(),
      finding("cloud.device.catalog_consistency", "WARNING")
    ])).toBe(false);
  });
});

describe("learned consensus safety policy", () => {
  const message = createObservationMessage(evidence(), attestation(), identities)!;

  it("recognizes an exact trusted profile and a different trusted profile", () => {
    expect(classifyLearnedConsensus(message, [{
      profile_hash: message.profileHash, consensus_state: "TRUSTED", review_state: "APPROVED",
      distinct_source_count: 5, observation_count: 8
    }]).kind).toBe("EXACT_TRUSTED");
    expect(classifyLearnedConsensus(message, [{
      profile_hash: "c".repeat(64), consensus_state: "TRUSTED", review_state: "APPROVED",
      distinct_source_count: 7, observation_count: 10
    }]).kind).toBe("TRUSTED_MISMATCH");
  });

  it("never trusts an unreviewed profile solely because it has many observations", () => {
    expect(classifyLearnedConsensus(message, [{
      profile_hash: message.profileHash, consensus_state: "TRUSTED", review_state: "PENDING",
      distinct_source_count: 1000, observation_count: 2000
    }]).kind).toBe("LEARNING");
  });

  it("only upgrades targeted unavailable probes and never overrides stronger findings", () => {
    const results = applyLearnedConsensusFallback([
      finding("cloud.device.hardware_matrix", "UNAVAILABLE"),
      finding("cloud.soc.catalog_consistency", "DETECTED"),
      finding("cloud.kernel.android_compatibility", "WARNING"),
      finding("cloud.keybox.serial_blacklist", "UNAVAILABLE")
    ], { kind: "EXACT_TRUSTED", sourceCount: 5, observationCount: 12 });
    expect(results.map((item) => item.status)).toEqual(["CLEAN", "DETECTED", "WARNING", "UNAVAILABLE"]);
  });

  it("represents a learned mismatch as warning only", () => {
    const results = applyLearnedConsensusFallback(
      [finding("cloud.device.hardware_matrix", "UNAVAILABLE")],
      { kind: "TRUSTED_MISMATCH", sourceCount: 6, observationCount: 9 }
    );
    expect(results.at(-1)).toMatchObject({ probeId: "cloud.observation.consensus", status: "WARNING" });
    expect(results.some((item) => item.status === "DETECTED")).toBe(false);
  });
});
