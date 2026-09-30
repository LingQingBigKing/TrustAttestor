import { describe, expect, it } from "vitest";
import {
  evaluateGoogleAttestationRevocation,
  parseCacheMaxAgeSeconds,
  parseGoogleRevocationFeed
} from "../src/revocation";
import type { Env } from "../src/types";

interface MockRevocationRow {
  serial_number: string;
  status: "REVOKED" | "SUSPENDED";
  expires_on: string | null;
  reason: string | null;
  comment: string | null;
  last_seen_at: string;
}

function mockEnv(matches: MockRevocationRow[], staleAfter: string | null): Env {
  const database = {
    prepare(query: string) {
      return {
        bind() {
          return {
            async all() {
              return { success: true, results: matches };
            }
          };
        },
        async first() {
          if (!query.includes("google_attestation_revocation_state") || staleAfter === null) return null;
          return {
            last_sync_id: "sync-1",
            last_successful_sync_at: "2026-08-24T00:00:00.000Z",
            stale_after: staleAfter,
            entry_count: 1738,
            revoked_count: 1738,
            suspended_count: 0
          };
        }
      };
    }
  } as unknown as D1Database;
  return { KEYBOX_DB: database } as Env;
}

function row(status: "REVOKED" | "SUSPENDED"): MockRevocationRow {
  return {
    serial_number: "ab",
    status,
    expires_on: null,
    reason: status === "REVOKED" ? "KEY_COMPROMISE" : "SOFTWARE_FLAW",
    comment: null,
    last_seen_at: "2026-08-24T00:00:00.000Z"
  };
}

describe("Google attestation revocation feed", () => {
  it("strictly parses the documented Google schema", () => {
    const feed = parseGoogleRevocationFeed({
      entries: {
        "2c8cdddfd5e03bfc": {
          status: "REVOKED",
          expires: "2030-01-02",
          reason: "KEY_COMPROMISE",
          comment: "confirmed"
        },
        ab: { status: "SUSPENDED", reason: "SOFTWARE_FLAW" }
      }
    });
    expect(feed.entries).toHaveLength(2);
    expect(feed.revokedCount).toBe(1);
    expect(feed.suspendedCount).toBe(1);
    expect(feed.entries[0]?.serialNumber).toBe("2c8cdddfd5e03bfc");
  });

  it("rejects invalid serials, statuses and unexpected fields", () => {
    expect(() => parseGoogleRevocationFeed({ entries: { "00ab": { status: "REVOKED" } } })).toThrow("invalid serial");
    expect(() => parseGoogleRevocationFeed({ entries: { ab: { status: "VALID" } } })).toThrow("invalid status");
    expect(() => parseGoogleRevocationFeed({ entries: { ab: { status: "REVOKED", extra: true } } })).toThrow("unsupported");
  });

  it("rejects an empty feed to prevent accidental mass removal", () => {
    expect(() => parseGoogleRevocationFeed({ entries: {} })).toThrow("safety boundary");
  });

  it("honors max-age while using a safe default", () => {
    expect(parseCacheMaxAgeSeconds("public, max-age=86400")).toBe(86_400);
    expect(parseCacheMaxAgeSeconds(null)).toBe(86_400);
    expect(parseCacheMaxAgeSeconds("public, max-age=99999999")).toBe(2_592_000);
  });
});

describe("Google attestation revocation verdict", () => {
  it("returns DETECTED for an official REVOKED match even if the snapshot is stale", async () => {
    const finding = await evaluateGoogleAttestationRevocation(
      mockEnv([row("REVOKED")], "2020-01-01T00:00:00.000Z"),
      ["00AB"]
    );
    expect(finding.status).toBe("DETECTED");
    expect(finding.probeId).toBe("cloud.attestation.google_revocation");
  });

  it("returns WARNING for an official SUSPENDED match", async () => {
    const finding = await evaluateGoogleAttestationRevocation(
      mockEnv([row("SUSPENDED")], "2099-01-01T00:00:00.000Z"),
      ["AB"]
    );
    expect(finding.status).toBe("WARNING");
  });

  it("returns CLEAN only when a fresh snapshot has no match", async () => {
    const finding = await evaluateGoogleAttestationRevocation(
      mockEnv([], "2099-01-01T00:00:00.000Z"),
      ["AB"]
    );
    expect(finding.status).toBe("CLEAN");
  });

  it("returns UNAVAILABLE when an empty lookup depends on a stale snapshot", async () => {
    const finding = await evaluateGoogleAttestationRevocation(
      mockEnv([], "2020-01-01T00:00:00.000Z"),
      ["AB"]
    );
    expect(finding.status).toBe("UNAVAILABLE");
  });
});
