import { describe, expect, it } from "vitest";
import {
  evaluateBuildFingerprintConsistency,
  evaluateBuildTimelineConsistency,
  evaluateRootOfTrustConsistency,
  evaluateTeePatchConsistency,
  evaluateTeePlatformConsistency
} from "../src/consistency";
import type { NativeDeviceEvidence } from "../src/evidence";
import type { AttestationRecord } from "../src/types";

function evidence(): NativeDeviceEvidence {
  return {
    schema: "trustattestor.native-device/v1",
    device: {
      model: "Pixel 10 Pro", product: "blazer", device: "blazer", board: "blazer",
      manufacturer: "Google", brand: "google", sku: ""
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
    kernel: {
      release: "6.1.99-android15", buildVersion: "#1 SMP PREEMPT Fri Jan 10 12:00:00 UTC 2025", machine: "aarch64"
    },
    boot: {
      vbmetaDeviceState: "locked", verifiedBootState: "green", flashLocked: "1",
      verityMode: "enforcing", vbmetaDigest: "bb"
    }
  };
}

function attestation(): AttestationRecord {
  return {
    attestationVersion: 400n,
    attestationSecurityLevel: 1,
    keyMintVersion: 400n,
    keyMintSecurityLevel: 1,
    challenge: new Uint8Array([1]),
    osVersion: 150000n,
    osPatchLevel: 202501n,
    vendorPatchLevel: 20250105n,
    bootPatchLevel: 20250105n,
    verifiedBootKey: new Uint8Array([0xaa]),
    deviceLocked: true,
    verifiedBootState: 0,
    verifiedBootHash: new Uint8Array([0xbb])
  };
}

describe("TEE and userspace consistency", () => {
  it("detects an old attested OS behind a modern userspace claim", () => {
    const result = evaluateTeePlatformConsistency({ ...attestation(), osVersion: 90000n }, evidence());
    expect(result.status).toBe("DETECTED");
  });

  it("detects a stale attested patch level", () => {
    const result = evaluateTeePatchConsistency({ ...attestation(), osPatchLevel: 202001n }, evidence());
    expect(result.status).toBe("DETECTED");
  });

  it("detects an unlocked TEE state even if properties claim locked", () => {
    const result = evaluateRootOfTrustConsistency({ ...attestation(), deviceLocked: false }, evidence());
    expect(result.status).toBe("DETECTED");
  });
});
describe("userspace and build chronology consistency", () => {
  it("accepts a fully synchronized fingerprint", () => {
    expect(evaluateBuildFingerprintConsistency(evidence()).status).toBe("CLEAN");
  });

  it("accepts an alternate OEM incremental property and ignores build ID", () => {
    const input = evidence();
    input.os.buildId = "OEM-OTA-ID";
    input.os.incremental = "OEM-INTERNAL-VERSION";
    input.os.incrementalCandidates = ["OEM-INTERNAL-VERSION", "12345678"];
    expect(evaluateBuildFingerprintConsistency(input).status).toBe("CLEAN");
  });

  it("warns when no incremental property matches", () => {
    const input = evidence();
    input.os.incremental = "OEM-INTERNAL-VERSION";
    input.os.incrementalCandidates = ["another-version"];
    expect(evaluateBuildFingerprintConsistency(input).status).toBe("WARNING");
  });

  it("reports unavailable when no incremental property is provided", () => {
    const input = evidence();
    input.os.incremental = "";
    input.os.incrementalCandidates = [];
    expect(evaluateBuildFingerprintConsistency(input).status).toBe("UNAVAILABLE");
  });

  it("warns for a model-independent userspace fingerprint mismatch", () => {
    const input = evidence();
    input.device.brand = "not-google";
    expect(evaluateBuildFingerprintConsistency(input).status).toBe("WARNING");
  });

  it("warns for a heuristic kernel timestamp mismatch", () => {
    const input = evidence();
    input.kernel.buildVersion = "#1 SMP PREEMPT Fri Jan 10 12:00:00 UTC 2026";
    expect(evaluateBuildTimelineConsistency(input).status).toBe("WARNING");
  });
});
