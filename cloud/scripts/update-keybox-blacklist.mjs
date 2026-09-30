import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildBlacklistImport } from "./build-blacklist-sql.mjs";

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_DATABASE = "trustattestor-keybox-blacklist";
export const KEYBOX_FEATURE_TSV_COLUMNS = [
  "serial_number",
  "certificate_sha256",
  "issuer_spki_sha256",
  "keybox_index",
  "keybox_count",
  "key_index",
  "key_count",
  "source_file"
];

function usage() {
  return [
    "Usage:",
    "  node scripts/update-keybox-blacklist.mjs --input FEATURES.tsv --source SOURCE --reason REASON [options]",
    "  node scripts/update-keybox-blacklist.mjs --input FEATURES.csv [options]",
    "",
    "Options:",
    "  --apply                    Apply pending migrations and update production D1.",
    "  --first-seen ISO_TIME      Observation timestamp for TSV input (default: now).",
    "  --artifact-sha256 HASH     SHA-256 of the original ZIP/keybox artifact.",
    "  --database NAME            D1 database name (default: trustattestor-keybox-blacklist).",
    "  --receipt PATH             Write an audit receipt to a new JSON file.",
    "  --sql-output PATH          Write the generated SQL to a new file.",
    "  --recovery-timestamp TIME  Also record a Time Travel bookmark for TIME.",
    "  --inactive                 Import TSV features with active=0.",
    "  -h, --help                 Show this help text.",
    "",
    "Without --apply the command is a validation-only dry run."
  ].join("\n");
}

function parseArguments(argumentsAfterScript) {
  const options = {
    apply: false,
    active: 1,
    artifactSha256: null,
    database: DEFAULT_DATABASE,
    firstSeenAt: new Date().toISOString(),
    inputPath: "",
    reason: "",
    recoveryTimestamp: "",
    receiptPath: "",
    sqlOutputPath: "",
    source: ""
  };
  for (let index = 0; index < argumentsAfterScript.length; index += 1) {
    const argument = argumentsAfterScript[index];
    if (argument === "--apply") options.apply = true;
    else if (argument === "--inactive") options.active = 0;
    else if (argument === "-h" || argument === "--help") return { help: true, options };
    else if (["--input", "--source", "--reason", "--first-seen", "--artifact-sha256", "--database", "--receipt", "--sql-output", "--recovery-timestamp"].includes(argument)) {
      const value = argumentsAfterScript[index + 1];
      if (value === undefined || value === "") throw new Error(`${argument} requires a value`);
      index += 1;
      if (argument === "--input") options.inputPath = value;
      else if (argument === "--source") options.source = value;
      else if (argument === "--reason") options.reason = value;
      else if (argument === "--first-seen") options.firstSeenAt = value;
      else if (argument === "--artifact-sha256") options.artifactSha256 = value;
      else if (argument === "--database") options.database = value;
      else if (argument === "--receipt") options.receiptPath = value;
      else if (argument === "--sql-output") options.sqlOutputPath = value;
      else options.recoveryTimestamp = value;
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  if (!options.inputPath) throw new Error("--input is required");
  return { help: false, options };
}

function csvField(value) {
  const text = String(value);
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

export function featuresTsvToCsv(text, options) {
  if (!options.source || !options.reason) {
    throw new Error("--source and --reason are required for TSV feature input");
  }
  if (Number.isNaN(Date.parse(options.firstSeenAt))) throw new Error("--first-seen is not a valid timestamp");
  const lines = text.split(/\r?\n/).filter((line) => line.trim() !== "");
  const header = lines.shift()?.split("\t") ?? [];
  if (
    header.length !== KEYBOX_FEATURE_TSV_COLUMNS.length
    || KEYBOX_FEATURE_TSV_COLUMNS.some((name, index) => header[index] !== name)
  ) {
    throw new Error(`TSV header must be: ${KEYBOX_FEATURE_TSV_COLUMNS.join("\\t")}`);
  }

  const rows = [];
  const sources = new Map();
  for (const [index, rawLine] of lines.entries()) {
    const fields = rawLine.split("\t");
    if (fields.length !== KEYBOX_FEATURE_TSV_COLUMNS.length) {
      throw new Error(`TSV line ${index + 2} must contain ${KEYBOX_FEATURE_TSV_COLUMNS.length} fields`);
    }
    const [
      serialNumber,
      certificateSha256,
      issuerSpkiSha256,
      rawKeyboxIndex,
      rawKeyboxCount,
      rawKeyIndex,
      rawKeyCount,
      sourceFile
    ] = fields;
    if (!sourceFile) throw new Error(`TSV line ${index + 2} has an empty source_file`);
    for (const [name, value] of [
      ["keybox_index", rawKeyboxIndex],
      ["keybox_count", rawKeyboxCount],
      ["key_index", rawKeyIndex],
      ["key_count", rawKeyCount]
    ]) {
      if (!/^[1-9][0-9]{0,5}$/.test(value)) {
        throw new Error(`TSV line ${index + 2} has an invalid ${name}`);
      }
    }
    const keyboxIndex = Number(rawKeyboxIndex);
    const keyboxCount = Number(rawKeyboxCount);
    const keyIndex = Number(rawKeyIndex);
    const keyCount = Number(rawKeyCount);
    if (keyboxIndex > keyboxCount) throw new Error(`TSV line ${index + 2} keybox_index exceeds keybox_count`);
    if (keyIndex > keyCount) throw new Error(`TSV line ${index + 2} key_index exceeds key_count`);

    let sourceState = sources.get(sourceFile);
    if (sourceState === undefined) {
      sourceState = { keyboxCount, keyboxes: new Map() };
      sources.set(sourceFile, sourceState);
    } else if (sourceState.keyboxCount !== keyboxCount) {
      throw new Error(`TSV source ${sourceFile} has inconsistent keybox_count values`);
    }
    let keyboxState = sourceState.keyboxes.get(keyboxIndex);
    if (keyboxState === undefined) {
      keyboxState = { keyCount, keys: new Set() };
      sourceState.keyboxes.set(keyboxIndex, keyboxState);
    } else if (keyboxState.keyCount !== keyCount) {
      throw new Error(`TSV source ${sourceFile} Keybox ${keyboxIndex} has inconsistent key_count values`);
    }
    if (keyboxState.keys.has(keyIndex)) {
      throw new Error(`TSV source ${sourceFile} Keybox ${keyboxIndex} contains duplicate Key ${keyIndex}`);
    }
    keyboxState.keys.add(keyIndex);

    rows.push([
      serialNumber,
      certificateSha256,
      issuerSpkiSha256,
      options.source,
      options.reason,
      options.firstSeenAt,
      String(options.active)
    ].map(csvField).join(","));
  }
  if (rows.length === 0) throw new Error("TSV input contains no features");
  for (const [sourceFile, sourceState] of sources) {
    if (sourceState.keyboxes.size !== sourceState.keyboxCount) {
      throw new Error(`TSV source ${sourceFile} does not contain every declared Keybox`);
    }
    for (let keyboxIndex = 1; keyboxIndex <= sourceState.keyboxCount; keyboxIndex += 1) {
      const keyboxState = sourceState.keyboxes.get(keyboxIndex);
      if (keyboxState === undefined) throw new Error(`TSV source ${sourceFile} is missing Keybox ${keyboxIndex}`);
      if (keyboxState.keys.size !== keyboxState.keyCount) {
        throw new Error(`TSV source ${sourceFile} Keybox ${keyboxIndex} does not contain every declared Key`);
      }
      for (let keyIndex = 1; keyIndex <= keyboxState.keyCount; keyIndex += 1) {
        if (!keyboxState.keys.has(keyIndex)) {
          throw new Error(`TSV source ${sourceFile} Keybox ${keyboxIndex} is missing Key ${keyIndex}`);
        }
      }
    }
  }
  return [
    "serial_number,certificate_sha256,issuer_spki_sha256,source,reason,first_seen_at,active",
    ...rows,
    ""
  ].join("\n");
}

function wranglerPath() {
  const candidate = resolve(PROJECT_ROOT, "node_modules", "wrangler", "bin", "wrangler.js");
  if (!existsSync(candidate)) throw new Error("Wrangler is not installed; run pnpm install first");
  return candidate;
}

function runWrangler(argumentsAfterCommand, operationDirectory) {
  const logDirectory = resolve(operationDirectory, "wrangler-logs");
  mkdirSync(logDirectory, { recursive: true });
  const result = spawnSync(process.execPath, [wranglerPath(), ...argumentsAfterCommand], {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
    env: {
      ...process.env,
      CI: "true",
      WRANGLER_LOG_PATH: logDirectory
    },
    maxBuffer: 32 * 1024 * 1024
  });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) {
    throw new Error([
      `Wrangler failed (${argumentsAfterCommand.join(" ")})`,
      result.stdout.trim(),
      result.stderr.trim()
    ].filter(Boolean).join("\n"));
  }
  return { stdout: result.stdout.trim(), stderr: result.stderr.trim() };
}

function parseJsonText(text) {
  const trimmed = text.trim();
  if (!trimmed) return undefined;
  try {
    return JSON.parse(trimmed);
  } catch {
    const candidates = [];
    const arrayStart = trimmed.indexOf("[");
    const arrayEnd = trimmed.lastIndexOf("]");
    if (arrayStart >= 0 && arrayEnd > arrayStart) candidates.push(trimmed.slice(arrayStart, arrayEnd + 1));
    const objectStart = trimmed.indexOf("{");
    const objectEnd = trimmed.lastIndexOf("}");
    if (objectStart >= 0 && objectEnd > objectStart) candidates.push(trimmed.slice(objectStart, objectEnd + 1));
    for (const candidate of candidates) {
      try {
        return JSON.parse(candidate);
      } catch {
        // Continue looking for a complete JSON value in the other output stream.
      }
    }
  }
  return undefined;
}

function parseWranglerJson(result, label) {
  for (const text of [result.stdout, result.stderr, `${result.stdout}\n${result.stderr}`]) {
    const parsed = parseJsonText(text);
    if (parsed !== undefined) return parsed;
  }
  throw new Error(`${label} did not return valid JSON`);
}

function collectResultRows(value) {
  if (Array.isArray(value)) return value.flatMap(collectResultRows);
  if (value === null || typeof value !== "object") return [];
  if (Array.isArray(value.results)) return value.results;
  return Object.values(value).flatMap(collectResultRows);
}

function verificationSql(certificateFeatures) {
  const values = certificateFeatures
    .map((feature) => `('${feature.certificateSha256}','${feature.serialNumber}')`)
    .join(",");
  return `WITH requested(certificate_sha256, serial_number) AS (VALUES ${values}) SELECT requested.certificate_sha256 AS requested_certificate_sha256, requested.serial_number AS requested_serial_number, blacklist.certificate_sha256, blacklist.issuer_spki_sha256, blacklist.source, blacklist.reason, blacklist.active, blacklist.import_batch_id, revocations.status AS revocation_status, revocations.reason AS revocation_reason FROM requested LEFT JOIN leaked_keybox_certificates AS blacklist ON blacklist.certificate_sha256=requested.certificate_sha256 LEFT JOIN google_attestation_revocations AS revocations ON revocations.serial_number=requested.serial_number AND revocations.active=1 AND revocations.status='REVOKED' ORDER BY requested.certificate_sha256;`;
}

function chunks(values, size) {
  const result = [];
  for (let index = 0; index < values.length; index += size) result.push(values.slice(index, index + size));
  return result;
}

function writeReceipt(path, receipt) {
  if (!path) return;
  const parent = dirname(resolve(path));
  if (!existsSync(parent)) throw new Error(`Receipt directory does not exist: ${parent}`);
  writeFileSync(path, `${JSON.stringify(receipt, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
}

function main() {
  const parsed = parseArguments(process.argv.slice(2));
  if (parsed.help) {
    console.log(usage());
    return;
  }
  const options = parsed.options;
  const inputText = readFileSync(options.inputPath, "utf8");
  const csvText = extname(options.inputPath).toLowerCase() === ".csv"
    ? inputText
    : featuresTsvToCsv(inputText, options);
  const built = buildBlacklistImport(csvText, { artifactSha256: options.artifactSha256 });
  if (options.sqlOutputPath) {
    const sqlParent = dirname(resolve(options.sqlOutputPath));
    if (!existsSync(sqlParent)) throw new Error(`SQL output directory does not exist: ${sqlParent}`);
    writeFileSync(options.sqlOutputPath, built.sql, { encoding: "utf8", flag: "wx" });
  }
  const operationDirectory = mkdtempSync(resolve(tmpdir(), "trustattestor-keybox-update-"));
  try {
    const sqlPath = resolve(operationDirectory, "keybox-blacklist.sql");
    writeFileSync(sqlPath, built.sql, { encoding: "utf8", flag: "wx" });
    const receipt = {
      schema: "trustattestor.keybox-blacklist-update/v1",
      mode: options.apply ? "APPLY" : "DRY_RUN",
      database: options.database,
      generatedAt: new Date().toISOString(),
      ...built.summary
    };

    if (!options.apply) {
      writeReceipt(options.receiptPath, receipt);
      console.log(JSON.stringify(receipt, null, 2));
      return;
    }

    if (options.recoveryTimestamp) {
      const recovery = runWrangler([
        "d1", "time-travel", "info", options.database,
        "--timestamp", options.recoveryTimestamp, "--json"
      ], operationDirectory);
      receipt.timeTravelRecovery = parseWranglerJson(recovery, "Time Travel recovery info");
    }
    const timeTravel = runWrangler([
      "d1", "time-travel", "info", options.database, "--json"
    ], operationDirectory);
    receipt.timeTravelBefore = parseWranglerJson(timeTravel, "Time Travel info");

    runWrangler([
      "d1", "migrations", "apply", options.database, "--remote"
    ], operationDirectory);
    const importResult = runWrangler([
      "d1", "execute", options.database, "--remote", "--file", sqlPath, "--yes", "--json"
    ], operationDirectory);
    receipt.importResult = parseWranglerJson(importResult, "D1 import");

    const verificationRows = [];
    for (const certificateFeatures of chunks(built.summary.certificateFeatures, 50)) {
      const verificationResult = runWrangler([
        "d1", "execute", options.database, "--remote", "--command",
        verificationSql(certificateFeatures), "--json"
      ], operationDirectory);
      const verificationJson = parseWranglerJson(verificationResult, "D1 verification");
      verificationRows.push(...collectResultRows(verificationJson));
    }
    const verifiedHashes = new Set(verificationRows
      .filter((row) => row !== null && typeof row === "object" && (
        row.active === 1 || row.revocation_status === "REVOKED"
      ))
      .map((row) => row.requested_certificate_sha256));
    const missing = built.summary.certificateSha256.filter((hash) => !verifiedHashes.has(hash));
    if (missing.length > 0) throw new Error(`D1 verification failed for: ${missing.join(", ")}`);
    receipt.verifiedAt = new Date().toISOString();
    receipt.verifiedRows = verificationRows;
    writeReceipt(options.receiptPath, receipt);
    console.log(JSON.stringify(receipt, null, 2));
  } finally {
    rmSync(operationDirectory, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
