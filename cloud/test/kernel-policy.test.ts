import { describe, expect, it } from "vitest";
import type { NativeDeviceEvidence } from "../src/evidence";
import { classifyAndroidKernelCompatibility, classifyKernelRiskSignatures } from "../src/kernel-policy";

const evidence = {
  device: { device: "blazer", model: "Pixel 10 Pro" },
  os: {
    sdk: 35,
    release: "15",
    buildId: "AP4A.250105.002",
    fingerprint: "google/blazer/blazer:15/AP4A.250105.002/123456:user/release-keys",
    securityPatch: "2025-01-05"
  },
  kernel: {
    release: "6.1.99-android15",
    buildVersion: "#1 SMP PREEMPT Fri Jan 10 12:00:00 UTC 2025",
    machine: "aarch64"
  }
} as NativeDeviceEvidence;

describe("D1-backed kernel risk policy", () => {
  it("matches a cloud risk signature without reading proc/version", () => {
    const input = structuredClone(evidence);
    input.kernel.buildVersion += " github-actions";
    const result = classifyKernelRiskSignatures(input, [{
      signature_id: "test-github",
      match_field: "build_version",
      needle_norm: "github-actions",
      status: "DETECTED",
      severity: "HIGH",
      title: "risk",
      reason: "test",
      source: "test"
    }]);
    expect(result.status).toBe("DETECTED");
  });

  it("treats dirty as warning when configured that way", () => {
    const input = structuredClone(evidence);
    input.kernel.release += "-dirty";
    const result = classifyKernelRiskSignatures(input, [{
      signature_id: "test-dirty",
      match_field: "any",
      needle_norm: "dirty",
      status: "WARNING",
      severity: "MEDIUM",
      title: "dirty",
      reason: "test",
      source: "test"
    }]);
    expect(result.status).toBe("WARNING");
  });
});

describe("Android-version kernel compatibility", () => {
  it("accepts an Android 15 kernel from the AOSP compatibility matrix", () => {
    expect(classifyAndroidKernelCompatibility(evidence).status).toBe("CLEAN");
  });

  it("accepts a plausible legacy kernel retained through an OS upgrade", () => {
    const input = structuredClone(evidence);
    input.kernel.release = "5.4.289-vendor";
    const result = classifyAndroidKernelCompatibility(input);
    expect(result.status).toBe("CLEAN");
    expect(result.title).toContain("旧设备升级");
  });

  it("warns instead of detecting when a kernel falls outside the common range", () => {
    const input = structuredClone(evidence);
    input.kernel.release = "4.14.336-custom";
    expect(classifyAndroidKernelCompatibility(input)).toMatchObject({
      probeId: "cloud.kernel.android_compatibility",
      status: "WARNING",
      severity: "MEDIUM"
    });
  });

  it("warns when a newer GKI branch is paired with an older Android release", () => {
    const input = structuredClone(evidence);
    input.os.release = "14";
    input.os.sdk = 34;
    input.kernel.release = "6.6.77-android15";
    expect(classifyAndroidKernelCompatibility(input).status).toBe("WARNING");
  });

  it("accepts Android 17 with the new 6.18 family", () => {
    const input = structuredClone(evidence);
    input.os.release = "17";
    input.os.sdk = 37;
    input.kernel.release = "6.18.21-android17";
    expect(classifyAndroidKernelCompatibility(input).status).toBe("CLEAN");
  });

  it("warns when release and SDK identify different Android versions", () => {
    const input = structuredClone(evidence);
    input.os.release = "14";
    expect(classifyAndroidKernelCompatibility(input).status).toBe("WARNING");
  });

  it("keeps an unparseable kernel unavailable", () => {
    const input = structuredClone(evidence);
    input.kernel.release = "unknown";
    expect(classifyAndroidKernelCompatibility(input).status).toBe("UNAVAILABLE");
  });

  it("keeps an uncovered future Android release unavailable", () => {
    const input = structuredClone(evidence);
    input.os.release = "18";
    input.os.sdk = 38;
    expect(classifyAndroidKernelCompatibility(input).status).toBe("UNAVAILABLE");
  });
});
