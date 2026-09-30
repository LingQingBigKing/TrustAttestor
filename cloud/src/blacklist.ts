import type {
  AttestationCertificateIdentity,
  Env,
  KeyboxBlacklistLookup,
  KeyboxBlacklistMatch
} from "./types";

interface CertificateBlacklistRow {
  serial_number: string;
  certificate_sha256: string;
  issuer_spki_sha256: string | null;
  source: string;
  reason: string;
  first_seen_at: string | null;
}

interface SerialBlacklistRow {
  serial_number: string;
  source: string;
  reason: string;
  first_seen_at: string | null;
}

export function normalizeSerialNumber(value: string): string {
  const hexadecimal = value.replace(/[^0-9a-f]/gi, "").toLowerCase().replace(/^0+(?=[0-9a-f])/, "");
  if (hexadecimal.length === 0 || hexadecimal.length > 128) {
    throw new Error("Invalid certificate serial number");
  }
  return hexadecimal;
}

export function normalizeSha256(value: string): string {
  const hexadecimal = value.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hexadecimal)) throw new Error("Invalid SHA-256 fingerprint");
  return hexadecimal;
}

function normalizeIdentities(identities: AttestationCertificateIdentity[]): AttestationCertificateIdentity[] {
  const unique = new Map<string, AttestationCertificateIdentity>();
  for (const identity of identities) {
    const normalized = {
      serialNumber: normalizeSerialNumber(identity.serialNumber),
      certificateSha256: normalizeSha256(identity.certificateSha256),
      issuerSpkiSha256: normalizeSha256(identity.issuerSpkiSha256)
    };
    unique.set(normalized.certificateSha256, normalized);
  }
  return [...unique.values()];
}

function matchStrength(
  row: CertificateBlacklistRow,
  identities: AttestationCertificateIdentity[]
): KeyboxBlacklistMatch["matchStrength"] {
  if (identities.some((identity) => identity.certificateSha256 === row.certificate_sha256)) {
    return "CERTIFICATE_SHA256";
  }
  return "SERIAL_ISSUER";
}

export async function findBlacklistedCertificates(
  env: Env,
  certificateIdentities: AttestationCertificateIdentity[]
): Promise<KeyboxBlacklistLookup> {
  const identities = normalizeIdentities(certificateIdentities);
  if (identities.length === 0) return { confirmedMatches: [], serialOnlyMatches: [] };

  const certificatePlaceholders = identities.map(() => "?").join(",");
  const serialIssuerClauses = identities.map(() => "(serial_number = ? AND issuer_spki_sha256 = ?)").join(" OR ");
  const certificateParameters = identities.map((identity) => identity.certificateSha256);
  const serialIssuerParameters = identities.flatMap((identity) => [identity.serialNumber, identity.issuerSpkiSha256]);
  const serials = [...new Set(identities.map((identity) => identity.serialNumber))];
  const serialPlaceholders = serials.map(() => "?").join(",");

  const [confirmedResult, serialResult] = await Promise.all([
    env.KEYBOX_DB.prepare(
      `SELECT serial_number, certificate_sha256, issuer_spki_sha256, source, reason, first_seen_at
         FROM leaked_keybox_certificates
        WHERE active = 1
          AND NOT EXISTS (
            SELECT 1
              FROM google_attestation_revocations AS revocations
             WHERE revocations.active = 1
               AND revocations.status = 'REVOKED'
               AND revocations.serial_number = leaked_keybox_certificates.serial_number
          )
          AND (certificate_sha256 IN (${certificatePlaceholders}) OR ${serialIssuerClauses})
        ORDER BY serial_number, certificate_sha256`
    ).bind(...certificateParameters, ...serialIssuerParameters).all<CertificateBlacklistRow>(),
    env.KEYBOX_DB.prepare(
      `SELECT serial_number, source, reason, first_seen_at
         FROM leaked_keybox_serials
        WHERE active = 1
          AND NOT EXISTS (
            SELECT 1
              FROM google_attestation_revocations AS revocations
             WHERE revocations.active = 1
               AND revocations.status = 'REVOKED'
               AND revocations.serial_number = leaked_keybox_serials.serial_number
          )
          AND serial_number IN (${serialPlaceholders})
        ORDER BY serial_number`
    ).bind(...serials).all<SerialBlacklistRow>()
  ]);

  if (!confirmedResult.success || !serialResult.success) throw new Error("Keybox blacklist query failed");
  const confirmedMatches = confirmedResult.results.map((row) => ({
    serialNumber: row.serial_number,
    certificateSha256: row.certificate_sha256,
    issuerSpkiSha256: row.issuer_spki_sha256,
    source: row.source,
    reason: row.reason,
    firstSeenAt: row.first_seen_at,
    matchStrength: matchStrength(row, identities)
  } satisfies KeyboxBlacklistMatch));
  const confirmedSerials = new Set(confirmedMatches.map((match) => match.serialNumber));
  const serialOnlyMatches = serialResult.results
    .filter((row) => !confirmedSerials.has(row.serial_number))
    .map((row) => ({
      serialNumber: row.serial_number,
      certificateSha256: null,
      issuerSpkiSha256: null,
      source: row.source,
      reason: row.reason,
      firstSeenAt: row.first_seen_at,
      matchStrength: "SERIAL_ONLY"
    } satisfies KeyboxBlacklistMatch));
  return { confirmedMatches, serialOnlyMatches };
}
