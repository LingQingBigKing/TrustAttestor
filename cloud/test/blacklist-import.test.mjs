import { describe, expect, it } from "vitest";
import { buildBlacklistImport } from "../scripts/build-blacklist-sql.mjs";
import {
  featuresTsvToCsv,
  KEYBOX_FEATURE_TSV_COLUMNS
} from "../scripts/update-keybox-blacklist.mjs";

const certificate = "a".repeat(64);
const issuer = "b".repeat(64);

function csv(rows) {
  return [
    "serial_number,certificate_sha256,issuer_spki_sha256,source,reason,first_seen_at,active",
    ...rows,
    ""
  ].join("\n");
}

function featureTsv(rows) {
  return [KEYBOX_FEATURE_TSV_COLUMNS.join("\t"), ...rows, ""].join("\n");
}

const tsvOptions = {
  active: 1,
  firstSeenAt: "2026-08-24T00:00:00Z",
  reason: "confirmed leak",
  source: "test-source"
};

describe("keybox blacklist import", () => {
  it("builds an auditable strong-fingerprint upsert", () => {
    const result = buildBlacklistImport(csv([
      `00AB,${certificate.toUpperCase()},${issuer.toUpperCase()},leak-source,confirmed leak,2026-08-23T00:00:00Z,1`
    ]), { artifactSha256: "c".repeat(64) });

    expect(result.summary.featureCount).toBe(1);
    expect(result.summary.artifactSha256).toBe("c".repeat(64));
    expect(result.sql).toContain("INSERT INTO keybox_blacklist_imports");
    expect(result.sql).toContain("INSERT INTO leaked_keybox_certificates");
    expect(result.sql).toContain("INSERT INTO keybox_blacklist_evidence");
    expect(result.sql).toContain("google_attestation_revocations");
    expect(result.sql).toContain("status='REVOKED'");
    expect(result.sql).toContain("'ab'");
    expect(result.sql).toContain(`'${certificate}'`);
    expect(result.summary.certificateFeatures).toEqual([{
      certificateSha256: certificate,
      serialNumber: "ab"
    }]);
  });

  it("deduplicates the same certificate and keeps a verified issuer fingerprint", () => {
    const result = buildBlacklistImport(csv([
      `01,${certificate},,source,reason,2026-08-23T00:00:00Z,1`,
      `01,${certificate},${issuer},source,reason,2026-08-23T00:00:00Z,1`
    ]));
    expect(result.summary.featureCount).toBe(1);
    expect(result.sql).toContain(`'${issuer}'`);
  });

  it("rejects conflicting identities for the same certificate", () => {
    expect(() => buildBlacklistImport(csv([
      `01,${certificate},${issuer},source,reason,2026-08-23T00:00:00Z,1`,
      `02,${certificate},${issuer},source,reason,2026-08-23T00:00:00Z,1`
    ]))).toThrow("Conflicting serial");
  });

  it("accepts exactly one feature for every declared Key", () => {
    const converted = featuresTsvToCsv(featureTsv([
      `01\t${certificate}\t${issuer}\t1\t1\t1\t2\tkeybox.xml`,
      `02\t${"c".repeat(64)}\t${issuer}\t1\t1\t2\t2\tkeybox.xml`
    ]), tsvOptions);
    const result = buildBlacklistImport(converted);
    expect(result.summary.featureCount).toBe(2);
  });

  it("rejects a duplicate feature for one Key", () => {
    expect(() => featuresTsvToCsv(featureTsv([
      `01\t${certificate}\t${issuer}\t1\t1\t1\t1\tkeybox.xml`,
      `02\t${"c".repeat(64)}\t${issuer}\t1\t1\t1\t1\tkeybox.xml`
    ]), tsvOptions)).toThrow("duplicate Key 1");
  });

  it("rejects a partial Keybox feature set", () => {
    expect(() => featuresTsvToCsv(featureTsv([
      `01\t${certificate}\t${issuer}\t1\t1\t1\t2\tkeybox.xml`
    ]), tsvOptions)).toThrow("does not contain every declared Key");
  });

  it("rejects legacy TSV without structural metadata", () => {
    expect(() => featuresTsvToCsv(
      `01\t${certificate}\t${issuer}\t1\tkeybox.xml\n`,
      tsvOptions
    )).toThrow("TSV header must be");
  });
});
