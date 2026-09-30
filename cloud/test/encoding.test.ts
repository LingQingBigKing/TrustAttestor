import { describe, expect, it } from "vitest";
import { decodeBase64, encodeBase64, equalBytes } from "../src/encoding";

describe("strict Base64 codec", () => {
  it("round-trips standard and URL-safe encodings", () => {
    const input = Uint8Array.from([0, 1, 2, 250, 251, 252]);
    expect(equalBytes(decodeBase64(encodeBase64(input)), input)).toBe(true);
    expect(equalBytes(decodeBase64("AAEC-vv8"), input)).toBe(true);
  });

  it("rejects malformed or oversized input", () => {
    expect(() => decodeBase64("***")).toThrow("Invalid Base64");
    expect(() => decodeBase64("AAEC", 2)).toThrow("size limit");
  });
});
