import { normalizeSerialNumber } from "./blacklist";
import type { CloudFinding, Env } from "./types";

export const GOOGLE_ATTESTATION_REVOCATION_URL = "https://android.googleapis.com/attestation/status";

const MAX_FEED_BYTES = 1_048_576;
const MAX_FEED_ENTRIES = 50_000;
const UPSERT_CHUNK_SIZE = 500;
const DEFAULT_CACHE_MAX_AGE_SECONDS = 86_400;
const MINIMUM_STALE_AFTER_SECONDS = 172_800;
const MAX_CACHE_MAX_AGE_SECONDS = 2_592_000;

export type GoogleRevocationStatus = "REVOKED" | "SUSPENDED";
export type GoogleRevocationReason =
  | "UNSPECIFIED"
  | "KEY_COMPROMISE"
  | "CA_COMPROMISE"
  | "SUPERSEDED"
  | "SOFTWARE_FLAW";

export interface GoogleRevocationEntry {
  serialNumber: string;
  status: GoogleRevocationStatus;
  expiresOn: string | null;
  reason: GoogleRevocationReason | null;
  comment: string | null;
}

export interface GoogleRevocationFeed {
  entries: GoogleRevocationEntry[];
  revokedCount: number;
  suspendedCount: number;
}

export interface GoogleRevocationSyncResult {
  syncId: string;
  entryCount: number;
  revokedCount: number;
  suspendedCount: number;
  removedCertificateCount: number;
  removedSerialCount: number;
  payloadSha256: string;
}

interface GoogleRevocationRow {
  serial_number: string;
  status: GoogleRevocationStatus;
  expires_on: string | null;
  reason: GoogleRevocationReason | null;
  comment: string | null;
  last_seen_at: string;
}

interface GoogleRevocationStateRow {
  last_sync_id: string;
  last_successful_sync_at: string;
  stale_after: string;
  entry_count: number;
  revoked_count: number;
  suspended_count: number;
}

interface CountRow {
  count: number;
}

interface GoogleRevocationLookup {
  matches: GoogleRevocationRow[];
  state: GoogleRevocationStateRow | null;
  fresh: boolean;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function validatePropertyNames(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const unexpected = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unexpected.length > 0) throw new Error(`${label} contains unsupported properties: ${unexpected.join(",")}`);
}

function validIsoDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

export function parseGoogleRevocationFeed(value: unknown): GoogleRevocationFeed {
  const root = record(value, "Google revocation feed");
  validatePropertyNames(root, ["entries"], "Google revocation feed");
  const rawEntries = record(root.entries, "Google revocation feed entries");
  const serialEntries = Object.entries(rawEntries);
  if (serialEntries.length === 0 || serialEntries.length > MAX_FEED_ENTRIES) {
    throw new Error("Google revocation feed entry count is outside the safety boundary");
  }

  const entries = serialEntries.map(([serialNumber, rawEntry]) => {
    if (!/^[a-f1-9][a-f0-9]*$/.test(serialNumber) || serialNumber.length > 128) {
      throw new Error(`Google revocation feed contains an invalid serial: ${serialNumber}`);
    }
    const entry = record(rawEntry, `Google revocation entry ${serialNumber}`);
    validatePropertyNames(entry, ["status", "expires", "reason", "comment"], `Google revocation entry ${serialNumber}`);
    if (entry.status !== "REVOKED" && entry.status !== "SUSPENDED") {
      throw new Error(`Google revocation entry ${serialNumber} has an invalid status`);
    }
    const expiresOn = entry.expires === undefined ? null : entry.expires;
    if (expiresOn !== null && (typeof expiresOn !== "string" || !validIsoDate(expiresOn))) {
      throw new Error(`Google revocation entry ${serialNumber} has an invalid expires date`);
    }
    const reason = entry.reason === undefined ? null : entry.reason;
    if (
      reason !== null
      && reason !== "UNSPECIFIED"
      && reason !== "KEY_COMPROMISE"
      && reason !== "CA_COMPROMISE"
      && reason !== "SUPERSEDED"
      && reason !== "SOFTWARE_FLAW"
    ) {
      throw new Error(`Google revocation entry ${serialNumber} has an invalid reason`);
    }
    const comment = entry.comment === undefined ? null : entry.comment;
    if (comment !== null && (typeof comment !== "string" || comment.length > 140)) {
      throw new Error(`Google revocation entry ${serialNumber} has an invalid comment`);
    }
    return {
      serialNumber,
      status: entry.status,
      expiresOn,
      reason,
      comment
    } satisfies GoogleRevocationEntry;
  }).sort((left, right) => left.serialNumber.localeCompare(right.serialNumber));

  return {
    entries,
    revokedCount: entries.filter((entry) => entry.status === "REVOKED").length,
    suspendedCount: entries.filter((entry) => entry.status === "SUSPENDED").length
  };
}

export function parseCacheMaxAgeSeconds(cacheControl: string | null): number {
  const match = cacheControl?.match(/(?:^|,)\s*max-age\s*=\s*"?(\d+)"?/i);
  if (match === undefined || match === null) return DEFAULT_CACHE_MAX_AGE_SECONDS;
  const parsed = Number(match[1]);
  if (!Number.isSafeInteger(parsed) || parsed < 0) return DEFAULT_CACHE_MAX_AGE_SECONDS;
  return Math.min(parsed, MAX_CACHE_MAX_AGE_SECONDS);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function chunks<T>(values: T[], size: number): T[][] {
  const result: T[][] = [];
  for (let index = 0; index < values.length; index += size) result.push(values.slice(index, index + size));
  return result;
}

async function getRevocationState(env: Env): Promise<GoogleRevocationStateRow | null> {
  return await env.KEYBOX_DB.prepare(
    `SELECT last_sync_id, last_successful_sync_at, stale_after,
            entry_count, revoked_count, suspended_count
       FROM google_attestation_revocation_state
      WHERE singleton_id = 1`
  ).first<GoogleRevocationStateRow>();
}

function assertPlausibleFeedSize(previous: GoogleRevocationStateRow | null, current: GoogleRevocationFeed): void {
  if (previous === null || previous.entry_count < 100) return;
  if (current.entries.length < Math.floor(previous.entry_count * 0.75)) {
    throw new Error(
      `Google revocation feed shrank unexpectedly (${previous.entry_count} -> ${current.entries.length})`
    );
  }
}

const UPSERT_REVOCATIONS_SQL = `
  INSERT INTO google_attestation_revocations
    (serial_number, status, expires_on, reason, comment,
     first_seen_at, last_seen_at, seen_in_sync_id, active)
  SELECT json_extract(value, '$.serialNumber'),
         json_extract(value, '$.status'),
         json_extract(value, '$.expiresOn'),
         json_extract(value, '$.reason'),
         json_extract(value, '$.comment'),
         ?2, ?2, ?3, 1
    FROM json_each(?1)
   WHERE 1
  ON CONFLICT(serial_number) DO UPDATE SET
    status=excluded.status,
    expires_on=excluded.expires_on,
    reason=excluded.reason,
    comment=excluded.comment,
    last_seen_at=excluded.last_seen_at,
    seen_in_sync_id=excluded.seen_in_sync_id,
    active=1`;

async function countRows(env: Env, table: "certificates" | "serials", syncId: string): Promise<number> {
  const source = table === "certificates" ? "leaked_keybox_certificates" : "leaked_keybox_serials";
  const row = await env.KEYBOX_DB.prepare(
    `SELECT COUNT(*) AS count
       FROM ${source} AS blacklist
       JOIN google_attestation_revocations AS revocations
         ON revocations.serial_number = blacklist.serial_number
      WHERE revocations.active = 1
        AND revocations.status = 'REVOKED'
        AND revocations.seen_in_sync_id = ?1`
  ).bind(syncId).first<CountRow>();
  return row?.count ?? 0;
}

async function finalizeSync(
  env: Env,
  syncId: string,
  feed: GoogleRevocationFeed,
  fetchedAt: string,
  staleAfter: string,
  cacheControl: string | null,
  cacheMaxAgeSeconds: number,
  sourceLastModified: string | null,
  payloadSha256: string,
  removedCertificateCount: number,
  removedSerialCount: number
): Promise<void> {
  const statements = [
    env.KEYBOX_DB.prepare(`
      INSERT INTO revoked_keybox_certificate_archive
        (certificate_sha256, serial_number, issuer_spki_sha256,
         blacklist_source, blacklist_reason, blacklist_first_seen_at, import_batch_id,
         google_status, google_reason, google_comment, google_expires_on, google_sync_id)
      SELECT blacklist.certificate_sha256, blacklist.serial_number, blacklist.issuer_spki_sha256,
             blacklist.source, blacklist.reason, blacklist.first_seen_at, blacklist.import_batch_id,
             revocations.status, revocations.reason, revocations.comment, revocations.expires_on, ?1
        FROM leaked_keybox_certificates AS blacklist
        JOIN google_attestation_revocations AS revocations
          ON revocations.serial_number = blacklist.serial_number
       WHERE revocations.active = 1
         AND revocations.status = 'REVOKED'
         AND revocations.seen_in_sync_id = ?1
      ON CONFLICT(certificate_sha256) DO UPDATE SET
        google_status=excluded.google_status,
        google_reason=excluded.google_reason,
        google_comment=excluded.google_comment,
        google_expires_on=excluded.google_expires_on,
        google_sync_id=excluded.google_sync_id,
        archived_at=CURRENT_TIMESTAMP
    `).bind(syncId),
    env.KEYBOX_DB.prepare(`
      DELETE FROM keybox_blacklist_evidence
       WHERE certificate_sha256 IN (
         SELECT blacklist.certificate_sha256
           FROM leaked_keybox_certificates AS blacklist
           JOIN google_attestation_revocations AS revocations
             ON revocations.serial_number = blacklist.serial_number
          WHERE revocations.active = 1
            AND revocations.status = 'REVOKED'
            AND revocations.seen_in_sync_id = ?1
       )
    `).bind(syncId),
    env.KEYBOX_DB.prepare(`
      DELETE FROM leaked_keybox_certificates
       WHERE serial_number IN (
         SELECT serial_number FROM google_attestation_revocations
          WHERE active = 1 AND status = 'REVOKED' AND seen_in_sync_id = ?1
       )
    `).bind(syncId),
    env.KEYBOX_DB.prepare(`
      INSERT INTO revoked_keybox_serial_archive
        (serial_number, blacklist_source, blacklist_reason, blacklist_first_seen_at,
         google_status, google_reason, google_comment, google_expires_on, google_sync_id)
      SELECT blacklist.serial_number, blacklist.source, blacklist.reason, blacklist.first_seen_at,
             revocations.status, revocations.reason, revocations.comment, revocations.expires_on, ?1
        FROM leaked_keybox_serials AS blacklist
        JOIN google_attestation_revocations AS revocations
          ON revocations.serial_number = blacklist.serial_number
       WHERE revocations.active = 1
         AND revocations.status = 'REVOKED'
         AND revocations.seen_in_sync_id = ?1
      ON CONFLICT(serial_number) DO UPDATE SET
        google_status=excluded.google_status,
        google_reason=excluded.google_reason,
        google_comment=excluded.google_comment,
        google_expires_on=excluded.google_expires_on,
        google_sync_id=excluded.google_sync_id,
        archived_at=CURRENT_TIMESTAMP
    `).bind(syncId),
    env.KEYBOX_DB.prepare(`
      DELETE FROM leaked_keybox_serials
       WHERE serial_number IN (
         SELECT serial_number FROM google_attestation_revocations
          WHERE active = 1 AND status = 'REVOKED' AND seen_in_sync_id = ?1
       )
    `).bind(syncId),
    env.KEYBOX_DB.prepare(
      `UPDATE google_attestation_revocations SET active = 0 WHERE seen_in_sync_id <> ?1`
    ).bind(syncId),
    env.KEYBOX_DB.prepare(`
      UPDATE google_attestation_revocation_syncs
         SET status = 'SUCCESS', completed_at = ?2,
             removed_certificate_count = ?3, removed_serial_count = ?4
       WHERE sync_id = ?1
    `).bind(syncId, fetchedAt, removedCertificateCount, removedSerialCount),
    env.KEYBOX_DB.prepare(`
      INSERT INTO google_attestation_revocation_state
        (singleton_id, last_sync_id, last_successful_sync_at, stale_after,
         source_last_modified, cache_control, cache_max_age_seconds, payload_sha256,
         entry_count, revoked_count, suspended_count)
      VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
      ON CONFLICT(singleton_id) DO UPDATE SET
        last_sync_id=excluded.last_sync_id,
        last_successful_sync_at=excluded.last_successful_sync_at,
        stale_after=excluded.stale_after,
        source_last_modified=excluded.source_last_modified,
        cache_control=excluded.cache_control,
        cache_max_age_seconds=excluded.cache_max_age_seconds,
        payload_sha256=excluded.payload_sha256,
        entry_count=excluded.entry_count,
        revoked_count=excluded.revoked_count,
        suspended_count=excluded.suspended_count
    `).bind(
      syncId,
      fetchedAt,
      staleAfter,
      sourceLastModified,
      cacheControl,
      cacheMaxAgeSeconds,
      payloadSha256,
      feed.entries.length,
      feed.revokedCount,
      feed.suspendedCount
    )
  ];
  const results = await env.KEYBOX_DB.batch(statements);
  if (results.some((result) => !result.success)) throw new Error("Google revocation finalization failed");
}

export async function syncGoogleAttestationRevocations(
  env: Env,
  fetcher: typeof fetch = fetch
): Promise<GoogleRevocationSyncResult> {
  const syncId = crypto.randomUUID();
  const startedAt = new Date().toISOString();
  let syncRowCreated = false;
  try {
    const startResult = await env.KEYBOX_DB.prepare(`
      INSERT INTO google_attestation_revocation_syncs
        (sync_id, source_url, started_at, status)
      VALUES (?1, ?2, ?3, 'APPLYING')
    `).bind(syncId, GOOGLE_ATTESTATION_REVOCATION_URL, startedAt).run();
    if (!startResult.success) throw new Error("Could not create Google revocation sync audit row");
    syncRowCreated = true;

    const response = await fetcher(GOOGLE_ATTESTATION_REVOCATION_URL, {
      headers: { accept: "application/json" },
      redirect: "manual",
      signal: AbortSignal.timeout(30_000)
    });
    if (response.status !== 200) throw new Error(`Google revocation endpoint returned HTTP ${response.status}`);
    const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
    if (!contentType.startsWith("application/json")) throw new Error("Google revocation endpoint returned a non-JSON response");
    const declaredLength = Number(response.headers.get("content-length") ?? "0");
    if (Number.isFinite(declaredLength) && declaredLength > MAX_FEED_BYTES) {
      throw new Error("Google revocation response exceeded the size limit");
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength === 0 || bytes.byteLength > MAX_FEED_BYTES) {
      throw new Error("Google revocation response size is outside the safety boundary");
    }
    const payloadSha256 = bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const feed = parseGoogleRevocationFeed(JSON.parse(decoded) as unknown);
    const previousState = await getRevocationState(env);
    assertPlausibleFeedSize(previousState, feed);

    const fetchedAt = new Date().toISOString();
    const cacheControl = response.headers.get("cache-control")?.slice(0, 512) ?? null;
    const sourceLastModified = response.headers.get("last-modified")?.slice(0, 128) ?? null;
    const cacheMaxAgeSeconds = parseCacheMaxAgeSeconds(cacheControl);
    const staleAfterSeconds = Math.max(cacheMaxAgeSeconds * 2, MINIMUM_STALE_AFTER_SECONDS);
    const staleAfter = new Date(Date.parse(fetchedAt) + staleAfterSeconds * 1000).toISOString();
    const auditResult = await env.KEYBOX_DB.prepare(`
      UPDATE google_attestation_revocation_syncs
         SET source_last_modified = ?2, cache_control = ?3, cache_max_age_seconds = ?4,
             payload_sha256 = ?5, entry_count = ?6, revoked_count = ?7, suspended_count = ?8
       WHERE sync_id = ?1
    `).bind(
      syncId,
      sourceLastModified,
      cacheControl,
      cacheMaxAgeSeconds,
      payloadSha256,
      feed.entries.length,
      feed.revokedCount,
      feed.suspendedCount
    ).run();
    if (!auditResult.success) throw new Error("Could not update Google revocation sync audit row");

    for (const entryChunk of chunks(feed.entries, UPSERT_CHUNK_SIZE)) {
      const result = await env.KEYBOX_DB.prepare(UPSERT_REVOCATIONS_SQL)
        .bind(JSON.stringify(entryChunk), fetchedAt, syncId)
        .run();
      if (!result.success) throw new Error("Google revocation entry upsert failed");
    }

    const [removedCertificateCount, removedSerialCount] = await Promise.all([
      countRows(env, "certificates", syncId),
      countRows(env, "serials", syncId)
    ]);
    await finalizeSync(
      env,
      syncId,
      feed,
      fetchedAt,
      staleAfter,
      cacheControl,
      cacheMaxAgeSeconds,
      sourceLastModified,
      payloadSha256,
      removedCertificateCount,
      removedSerialCount
    );
    return {
      syncId,
      entryCount: feed.entries.length,
      revokedCount: feed.revokedCount,
      suspendedCount: feed.suspendedCount,
      removedCertificateCount,
      removedSerialCount,
      payloadSha256
    };
  } catch (error) {
    if (syncRowCreated) {
      const message = (error instanceof Error ? error.message : String(error)).slice(0, 1024);
      try {
        await env.KEYBOX_DB.prepare(`
          UPDATE google_attestation_revocation_syncs
             SET status = 'FAILED', completed_at = ?2, error = ?3
           WHERE sync_id = ?1
        `).bind(syncId, new Date().toISOString(), message).run();
      } catch (auditError) {
        console.error(JSON.stringify({
          message: "Google revocation failure audit write failed",
          syncId,
          error: auditError instanceof Error ? auditError.message : String(auditError)
        }));
      }
    }
    throw error;
  }
}

async function findGoogleRevocations(env: Env, serialNumbers: string[]): Promise<GoogleRevocationLookup> {
  const normalized = [...new Set(serialNumbers.map(normalizeSerialNumber))];
  const matchesPromise = normalized.length === 0
    ? Promise.resolve({ success: true, results: [] as GoogleRevocationRow[] })
    : env.KEYBOX_DB.prepare(`
        SELECT serial_number, status, expires_on, reason, comment, last_seen_at
          FROM google_attestation_revocations
         WHERE active = 1
           AND serial_number IN (SELECT value FROM json_each(?1))
         ORDER BY serial_number
      `).bind(JSON.stringify(normalized)).all<GoogleRevocationRow>();
  const [matchesResult, state] = await Promise.all([matchesPromise, getRevocationState(env)]);
  if (!matchesResult.success) throw new Error("Google revocation lookup failed");
  const staleAfter = state === null ? Number.NaN : Date.parse(state.stale_after);
  return {
    matches: matchesResult.results,
    state,
    fresh: Number.isFinite(staleAfter) && staleAfter > Date.now()
  };
}

function finding(
  status: CloudFinding["status"],
  severity: CloudFinding["severity"],
  probeId: string,
  title: string,
  evidence: string
): CloudFinding {
  return { status, severity, probeId, title, evidence };
}

function matchDetails(matches: GoogleRevocationRow[]): string {
  return matches.map((match) => [
    `SerialNumber=${match.serial_number}`,
    `状态=${match.status}`,
    `原因=${match.reason ?? "UNSPECIFIED"}`,
    ...(match.expires_on === null ? [] : [`证书到期=${match.expires_on}`])
  ].join("；")).join(" | ");
}

export async function evaluateGoogleAttestationRevocation(
  env: Env,
  serialNumbers: string[]
): Promise<CloudFinding> {
  try {
    const lookup = await findGoogleRevocations(env, serialNumbers);
    const revoked = lookup.matches.filter((match) => match.status === "REVOKED");
    if (revoked.length > 0) {
      return finding(
        "DETECTED",
        "CRITICAL",
        "cloud.attestation.google_revocation",
        "Google 已吊销证明证书",
        `证书链命中 Google 官方吊销列表：${matchDetails(revoked)}`
      );
    }
    const suspended = lookup.matches.filter((match) => match.status === "SUSPENDED");
    if (suspended.length > 0) {
      return finding(
        "WARNING",
        "HIGH",
        "cloud.attestation.google_revocation",
        "Google 已暂停证明证书",
        `证书链命中 Google 官方暂停列表：${matchDetails(suspended)}`
      );
    }
    if (lookup.state === null || !lookup.fresh) {
      return finding(
        "UNAVAILABLE",
        "INFO",
        "cloud.attestation.google_revocation",
        "Google 吊销状态暂时不可用",
        lookup.state === null
          ? "Google 官方吊销库尚未完成首次同步，本次不会判定设备异常。"
          : `Google 官方吊销库已过期；最后成功同步时间=${lookup.state.last_successful_sync_at}。`
      );
    }
    return finding(
      "CLEAN",
      "INFO",
      "cloud.attestation.google_revocation",
      "Google 吊销证书库校验通过",
      `已核验 ${serialNumbers.length} 节证书；吊销库 ${lookup.state.entry_count} 条，最后同步=${lookup.state.last_successful_sync_at}。`
    );
  } catch {
    return finding(
      "UNAVAILABLE",
      "INFO",
      "cloud.attestation.google_revocation",
      "Google 吊销状态暂时不可用",
      "Google 官方吊销库查询失败，本次不会判定设备异常。"
    );
  }
}
