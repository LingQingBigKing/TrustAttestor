import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const BLACKLIST_COLUMNS = [
  "serial_number",
  "certificate_sha256",
  "issuer_spki_sha256",
  "source",
  "reason",
  "first_seen_at",
  "active"
];

export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === '"' && text[index + 1] === '"') {
        field += '"';
        index += 1;
      } else if (character === '"') {
        quoted = false;
      } else {
        field += character;
      }
    } else if (character === '"') {
      quoted = true;
    } else if (character === ",") {
      row.push(field);
      field = "";
    } else if (character === "\n") {
      row.push(field.replace(/\r$/, ""));
      if (row.some((value) => value.length > 0)) rows.push(row);
      row = [];
      field = "";
    } else {
      field += character;
    }
  }
  if (quoted) throw new Error("CSV contains an unterminated quoted field");
  row.push(field.replace(/\r$/, ""));
  if (row.some((value) => value.length > 0)) rows.push(row);
  return rows;
}

export function normalizeSerial(value) {
  const serial = value.replace(/[^0-9a-f]/gi, "").toLowerCase().replace(/^0+(?=[0-9a-f])/, "");
  if (!/^[0-9a-f]{1,128}$/.test(serial)) throw new Error(`Invalid serial number: ${value}`);
  return serial;
}

export function normalizeSha256(value, { optional = false } = {}) {
  const fingerprint = value.trim().toLowerCase();
  if (optional && fingerprint === "") return null;
  if (!/^[0-9a-f]{64}$/.test(fingerprint)) throw new Error(`Invalid SHA-256 fingerprint: ${value}`);
  return fingerprint;
}

function sqlString(value) {
  return `'${value.replaceAll("'", "''")}'`;
}

function firstSeenUpdateSql() {
  return `CASE
    WHEN leaked_keybox_certificates.first_seen_at IS NULL THEN excluded.first_seen_at
    WHEN excluded.first_seen_at IS NULL THEN leaked_keybox_certificates.first_seen_at
    WHEN excluded.first_seen_at < leaked_keybox_certificates.first_seen_at THEN excluded.first_seen_at
    ELSE leaked_keybox_certificates.first_seen_at
  END`;
}

function parseFeatures(csvText) {
  const rows = parseCsv(csvText);
  const header = rows.shift();
  if (!header || BLACKLIST_COLUMNS.some((name, index) => header[index]?.trim() !== name)) {
    throw new Error(`CSV header must be: ${BLACKLIST_COLUMNS.join(",")}`);
  }

  const features = new Map();
  for (const [index, values] of rows.entries()) {
    if (values.length !== BLACKLIST_COLUMNS.length) {
      throw new Error(`CSV row ${index + 2} has the wrong number of fields`);
    }
    const [rawSerial, rawCertificate, rawIssuer, rawSource, rawReason, rawFirstSeen, rawActive] =
      values.map((value) => value.trim());
    const feature = {
      serialNumber: normalizeSerial(rawSerial),
      certificateSha256: normalizeSha256(rawCertificate),
      issuerSpkiSha256: normalizeSha256(rawIssuer, { optional: true }),
      source: rawSource,
      reason: rawReason,
      firstSeenAt: rawFirstSeen || null,
      active: rawActive === "1" ? 1 : rawActive === "0" ? 0 : null
    };
    if (!feature.source || feature.source.length > 256) throw new Error(`CSV row ${index + 2} has invalid source`);
    if (!feature.reason || feature.reason.length > 1024) throw new Error(`CSV row ${index + 2} has invalid reason`);
    if (feature.active === null) throw new Error(`CSV row ${index + 2} active must be 0 or 1`);
    if (feature.firstSeenAt !== null && Number.isNaN(Date.parse(feature.firstSeenAt))) {
      throw new Error(`CSV row ${index + 2} first_seen_at is not a valid timestamp`);
    }

    const existing = features.get(feature.certificateSha256);
    if (existing !== undefined) {
      if (existing.serialNumber !== feature.serialNumber) {
        throw new Error(`Conflicting serial numbers for certificate ${feature.certificateSha256}`);
      }
      if (
        existing.issuerSpkiSha256 !== null
        && feature.issuerSpkiSha256 !== null
        && existing.issuerSpkiSha256 !== feature.issuerSpkiSha256
      ) {
        throw new Error(`Conflicting issuer fingerprints for certificate ${feature.certificateSha256}`);
      }
      if (existing.issuerSpkiSha256 === null && feature.issuerSpkiSha256 !== null) {
        existing.issuerSpkiSha256 = feature.issuerSpkiSha256;
      }
      continue;
    }
    features.set(feature.certificateSha256, feature);
  }
  if (features.size === 0) throw new Error("CSV contains no blacklist features");
  return [...features.values()].sort((left, right) =>
    left.certificateSha256.localeCompare(right.certificateSha256)
  );
}

export function buildBlacklistImport(csvText, { artifactSha256 = null } = {}) {
  const features = parseFeatures(csvText);
  const inputSha256 = createHash("sha256").update(csvText, "utf8").digest("hex");
  const normalizedArtifact = artifactSha256 === null ? null : normalizeSha256(artifactSha256);
  const batchId = `kb-${inputSha256.slice(0, 24)}`;
  const sources = [...new Set(features.map((feature) => feature.source))];
  const reasons = [...new Set(features.map((feature) => feature.reason))];
  const batchSource = sources.length === 1 ? sources[0] : `mixed:${sources.length}`;
  const batchReason = reasons.length === 1 ? reasons[0] : `mixed:${reasons.length}`;
  const statements = [
    `INSERT INTO keybox_blacklist_imports (batch_id, input_sha256, artifact_sha256, source, reason, feature_count) VALUES (${sqlString(batchId)}, ${sqlString(inputSha256)}, ${normalizedArtifact === null ? "NULL" : sqlString(normalizedArtifact)}, ${sqlString(batchSource)}, ${sqlString(batchReason)}, ${features.length}) ON CONFLICT(batch_id) DO NOTHING;`
  ];

  for (const feature of features) {
    const firstSeen = feature.firstSeenAt === null ? "NULL" : sqlString(feature.firstSeenAt);
    const issuer = feature.issuerSpkiSha256 === null ? "NULL" : sqlString(feature.issuerSpkiSha256);
    const revocationGuard = `NOT EXISTS (SELECT 1 FROM google_attestation_revocations WHERE active=1 AND status='REVOKED' AND serial_number=${sqlString(feature.serialNumber)})`;
    statements.push(
      `INSERT INTO leaked_keybox_certificates (certificate_sha256, serial_number, issuer_spki_sha256, source, reason, first_seen_at, active, import_batch_id) SELECT ${sqlString(feature.certificateSha256)}, ${sqlString(feature.serialNumber)}, ${issuer}, ${sqlString(feature.source)}, ${sqlString(feature.reason)}, ${firstSeen}, ${feature.active}, ${sqlString(batchId)} WHERE ${revocationGuard} ON CONFLICT(certificate_sha256) DO UPDATE SET serial_number=excluded.serial_number, issuer_spki_sha256=COALESCE(leaked_keybox_certificates.issuer_spki_sha256, excluded.issuer_spki_sha256), source=excluded.source, reason=excluded.reason, first_seen_at=${firstSeenUpdateSql()}, active=excluded.active, import_batch_id=excluded.import_batch_id, updated_at=CURRENT_TIMESTAMP WHERE NOT EXISTS (SELECT 1 FROM google_attestation_revocations WHERE active=1 AND status='REVOKED' AND serial_number=excluded.serial_number);`,
      `INSERT INTO keybox_blacklist_evidence (certificate_sha256, batch_id, source, reason, first_seen_at) SELECT ${sqlString(feature.certificateSha256)}, ${sqlString(batchId)}, ${sqlString(feature.source)}, ${sqlString(feature.reason)}, ${firstSeen} WHERE EXISTS (SELECT 1 FROM leaked_keybox_certificates WHERE certificate_sha256=${sqlString(feature.certificateSha256)}) ON CONFLICT(certificate_sha256, batch_id) DO NOTHING;`
    );
  }

  const sql = `${statements.join("\n")}\n`;
  return {
    sql,
    summary: {
      batchId,
      inputSha256,
      artifactSha256: normalizedArtifact,
      featureCount: features.length,
      sqlSha256: createHash("sha256").update(sql, "utf8").digest("hex"),
      certificateSha256: features.map((feature) => feature.certificateSha256),
      certificateFeatures: features.map((feature) => ({
        certificateSha256: feature.certificateSha256,
        serialNumber: feature.serialNumber
      }))
    }
  };
}

function parseArguments(argumentsAfterScript) {
  const positional = [];
  let artifactSha256 = null;
  for (let index = 0; index < argumentsAfterScript.length; index += 1) {
    const argument = argumentsAfterScript[index];
    if (argument === "--") continue;
    if (argument === "--artifact-sha256") {
      artifactSha256 = argumentsAfterScript[index + 1] ?? "";
      index += 1;
    } else {
      positional.push(argument);
    }
  }
  if (positional.length !== 2) {
    throw new Error("Usage: node scripts/build-blacklist-sql.mjs <input.csv> <output.sql> [--artifact-sha256 HASH]");
  }
  return { inputPath: positional[0], outputPath: positional[1], artifactSha256 };
}

function main() {
  const { inputPath, outputPath, artifactSha256 } = parseArguments(process.argv.slice(2));
  const result = buildBlacklistImport(readFileSync(inputPath, "utf8"), { artifactSha256 });
  writeFileSync(outputPath, result.sql, { encoding: "utf8", flag: "wx" });
  console.log(JSON.stringify({ output: outputPath, ...result.summary }, null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
