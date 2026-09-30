import { timingSafeEqual } from "node:crypto";

export function decodeBase64(value: string, maxBytes = 1_048_576): Uint8Array {
  if (typeof value !== "string") throw new Error("Base64 value must be a string");
  const normalized = value
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) throw new Error("Invalid Base64 data");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const decoded = Buffer.from(padded, "base64");
  if (decoded.byteLength > maxBytes) throw new Error("Decoded data exceeds the size limit");
  const canonicalInput = normalized.replace(/=+$/, "");
  const canonicalOutput = decoded.toString("base64").replace(/=+$/, "");
  if (canonicalInput !== canonicalOutput) throw new Error("Non-canonical Base64 data");
  return decoded;
}
export function encodeBase64(value: Uint8Array): string {
  return Buffer.from(value).toString("base64");
}

export function encodeBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && timingSafeEqual(left, right);
}

export function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

export function asString(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string`);
  const result = value.trim();
  if (result.length === 0 || result.length > maxLength) throw new Error(`${label} is invalid`);
  return result;
}

export function asInteger(value: unknown, label: string, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) {
    throw new Error(`${label} is invalid`);
  }
  return value as number;
}
