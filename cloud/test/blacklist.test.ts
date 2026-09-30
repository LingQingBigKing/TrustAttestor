import { describe, expect, it } from "vitest";
import { findBlacklistedCertificates, normalizeSerialNumber, normalizeSha256 } from "../src/blacklist";
import type { Env } from "../src/types";

function mockEnv(confirmedResults: unknown[], serialResults: unknown[], queries: string[] = []): Env {
  const database = {
    prepare(query: string) {
      queries.push(query);
      return {
        bind() {
          return {
            async all() {
              return {
                success: true,
                results: query.includes("leaked_keybox_certificates") ? confirmedResults : serialResults
              };
            }
          };
        }
      };
    }
  } as unknown as D1Database;
  return { KEYBOX_DB: database } as Env;
}

describe("keybox serial normalization", () => {
  it("normalizes Node and database serial formats", () => {
    expect(normalizeSerialNumber("00:AB:01:20")).toBe("ab0120");
    expect(normalizeSerialNumber("0000")).toBe("0");
  });

  it("rejects empty and implausibly long serials", () => {
    expect(() => normalizeSerialNumber("::")).toThrow("Invalid");
    expect(() => normalizeSerialNumber("a".repeat(129))).toThrow("Invalid");
  });

  it("accepts only complete lowercase-normalized SHA-256 fingerprints", () => {
    expect(normalizeSha256("A".repeat(64))).toBe("a".repeat(64));
    expect(() => normalizeSha256("a".repeat(63))).toThrow("SHA-256");
    expect(() => normalizeSha256("z".repeat(64))).toThrow("SHA-256");
  });

  it("treats an exact certificate digest as a confirmed match", async () => {
    const certificateSha256 = "a".repeat(64);
    const issuerSpkiSha256 = "b".repeat(64);
    const result = await findBlacklistedCertificates(mockEnv([{
      serial_number: "ab",
      certificate_sha256: certificateSha256,
      issuer_spki_sha256: issuerSpkiSha256,
      source: "test",
      reason: "confirmed",
      first_seen_at: null
    }], []), [{ serialNumber: "00AB", certificateSha256, issuerSpkiSha256 }]);

    expect(result.confirmedMatches).toHaveLength(1);
    expect(result.confirmedMatches[0]?.matchStrength).toBe("CERTIFICATE_SHA256");
    expect(result.serialOnlyMatches).toHaveLength(0);
  });

  it("keeps legacy serial-only records warning-only", async () => {
    const result = await findBlacklistedCertificates(mockEnv([], [{
      serial_number: "ab",
      source: "legacy",
      reason: "serial only",
      first_seen_at: null
    }]), [{
      serialNumber: "AB",
      certificateSha256: "a".repeat(64),
      issuerSpkiSha256: "b".repeat(64)
    }]);

    expect(result.confirmedMatches).toHaveLength(0);
    expect(result.serialOnlyMatches[0]?.matchStrength).toBe("SERIAL_ONLY");
  });

  it("excludes certificates already promoted to Google's revoked list", async () => {
    const queries: string[] = [];
    await findBlacklistedCertificates(mockEnv([], [], queries), [{
      serialNumber: "AB",
      certificateSha256: "a".repeat(64),
      issuerSpkiSha256: "b".repeat(64)
    }]);

    expect(queries).toHaveLength(2);
    expect(queries.every((query) => query.includes("google_attestation_revocations"))).toBe(true);
    expect(queries.every((query) => query.includes("status = 'REVOKED'"))).toBe(true);
  });
});
