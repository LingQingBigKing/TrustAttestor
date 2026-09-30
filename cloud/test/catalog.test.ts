import { describe, expect, it } from "vitest";
import {
  classifyDeviceIdentity,
  classifyHardwareBaseline,
  classifySocIdentity,
  normalizeCatalogValue,
  type DeviceHardwareBaselineRow,
  type NativeIdentityEvidence,
  type SocRow
} from "../src/catalog";

const evidence: NativeIdentityEvidence = {
  model: "Pixel 10 Pro",
  device: "blazer",
  board: "blazer",
  product: "blazer",
  manufacturer: "Google",
  brand: "google",
  sku: "",
  hardware: "tensor g5",
  boardPlatform: "laguna",
  socManufacturer: "Google",
  socModel: "Tensor G5",
  fingerprint: "google/blazer/blazer:15/AP4A.250105.002/123456:user/release-keys"
};

function socRow(identity: string, vendor: string, name: string): SocRow {
  return {
    query_key: name,
    identity_id: identity,
    canonical_id: `${identity}-spec`,
    vendor,
    vendor_norm: vendor.toLowerCase(),
    name,
    fab: "3 nm",
    cpu: "",
    memory: "",
    bandwidth: "",
    channels: ""
  };
}

describe("device catalog policy", () => {
  it("normalizes Unicode and whitespace like the importer", () => {
    expect(normalizeCatalogValue("  ＳＭ８２５０\n")).toBe("sm8250");
  });

  it("accepts an exact device/model pair", () => {
    const result = classifyDeviceIdentity(evidence, {
      exact: { name: "Pixel 10 Pro", device: "blazer", model: "Pixel 10 Pro" },
      byDevice: [],
      byModel: []
    });
    expect(result.status).toBe("CLEAN");
    expect(result.title).toBe("设备型号组合已收录");
  });

  it("warns when two userspace identifiers form an unknown pair", () => {
    const result = classifyDeviceIdentity(evidence, {
      byDevice: [{ name: "Pixel 10 Pro", device: "blazer", model: "Pixel 10 Pro" }],
      byModel: [{ name: "Other", device: "other_device", model: "Pixel 10 Pro" }]
    });
    expect(result.status).toBe("WARNING");
    expect(result.probeId).toBe("cloud.device.catalog_consistency");
  });

  it("does not treat an entirely unknown device as an anomaly", () => {
    const result = classifyDeviceIdentity(evidence, { byDevice: [], byModel: [] });
    expect(result.status).toBe("UNAVAILABLE");
  });
});

describe("SoC catalog policy", () => {
  it("accepts aliases that resolve to the same chip identity", () => {
    const row = socRow("tensor-g5", "Google", "Tensor G5");
    const result = classifySocIdentity(evidence, [
      { source: "socModel", value: "Tensor G5", rows: [row] },
      { source: "hardware", value: "tensor g5", rows: [{ ...row, query_key: "laguna" }] }
    ]);
    expect(result.status).toBe("CLEAN");
    expect(result.title).toBe("SoC 标识内部一致");
  });

  it("warns for conflicting userspace SoC identifiers", () => {
    const result = classifySocIdentity(evidence, [
      { source: "socModel", value: "Tensor G5", rows: [socRow("tensor-g5", "Google", "Tensor G5")] },
      { source: "hardware", value: "SM8650", rows: [socRow("sm8650", "Qualcomm®", "Snapdragon 8 Gen 3")] }
    ]);
    expect(result.status).toBe("WARNING");
  });

  it("warns for a recognized userspace vendor mismatch", () => {
    const result = classifySocIdentity(
      { ...evidence, socManufacturer: "MediaTek", hardware: "" },
      [{ source: "socModel", value: "Tensor G5", rows: [socRow("tensor-g5", "Google", "Tensor G5")] }]
    );
    expect(result.status).toBe("WARNING");
    expect(result.title).toContain("厂商");
  });
});

const variant: DeviceHardwareBaselineRow = {
  variant_id: "blazer-global",
  manufacturer_norm: "google",
  brand_norm: "google",
  product_norm: "blazer",
  sku_norm: "",
  board_platform_norm: "laguna",
  fingerprint_prefix_norm: "google/blazer/blazer:",
  source: "official fixture",
  confidence: "OFFICIAL"
};

describe("published device variant policy", () => {
  it("keeps missing formal baselines unavailable", () => {
    const results = classifyHardwareBaseline(evidence, []);
    expect(results.map((item) => item.status)).toEqual(["UNAVAILABLE"]);
    expect(results.some((item) => item.probeId === "cloud.device.soc_matrix")).toBe(false);
  });

  it("uses an exact device catalog match as the base hardware result", () => {
    const results = classifyHardwareBaseline(evidence, [], true);
    expect(results).toEqual([]);
  });

  it("keeps a matched hardware baseline clean without a device-to-SoC rule", () => {
    const results = classifyHardwareBaseline(evidence, [variant]);
    expect(results.map((item) => item.status)).toEqual(["CLEAN"]);
    expect(results[0]?.title).toBe("设备指纹与厂商元数据匹配");
    expect(results.some((item) => item.probeId === "cloud.device.soc_matrix")).toBe(false);
  });

  it("detects an official vendor metadata mismatch", () => {
    const results = classifyHardwareBaseline(
      { ...evidence, manufacturer: "Other Vendor" },
      [variant]
    );
    expect(results[0]?.status).toBe("DETECTED");
  });

  it("keeps a community-only mismatch at warning", () => {
    const results = classifyHardwareBaseline(
      { ...evidence, boardPlatform: "other" },
      [{ ...variant, confidence: "COMMUNITY" }]
    );
    expect(results[0]?.status).toBe("WARNING");
  });

  it("keeps a missing required SKU unavailable", () => {
    const results = classifyHardwareBaseline(
      evidence,
      [{ ...variant, sku_norm: "global" }]
    );
    expect(results[0]?.status).toBe("UNAVAILABLE");
  });
});
