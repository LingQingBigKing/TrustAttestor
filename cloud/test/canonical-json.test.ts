import { describe, expect, it } from "vitest";
import { canonicalize } from "../src/canonical-json";

describe("canonicalize", () => {
  it("sorts object keys recursively while preserving array order", () => {
    expect(canonicalize({ z: 1, a: { y: true, b: [3, "x"] } })).toBe(
      '{"a":{"b":[3,"x"],"y":true},"z":1}'
    );
  });

  it("uses Android org.json forward-slash escaping", () => {
    expect(canonicalize({ evidence: "BRAND/PRODUCT/DEVICE", "probe/id": "a/b" })).toBe(
      '{"evidence":"BRAND\\/PRODUCT\\/DEVICE","probe\\/id":"a\\/b"}'
    );
  });

  it("rejects values that Android JSON cannot sign stably", () => {
    expect(() => canonicalize({ value: Number.NaN })).toThrow("Non-finite");
    expect(() => canonicalize({ value: -0 })).toThrow("Negative zero");
    expect(() => canonicalize({ value: undefined })).toThrow("Undefined");
  });
});
