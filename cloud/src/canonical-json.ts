/**
 * Canonical profile shared with the Android client: object keys are sorted by
 * Java/Unicode code-unit order, arrays preserve order, and JSON strings use
 * Android org.json escaping (including escaping every forward slash).
 */
function androidJsonQuote(value: string): string {
  return JSON.stringify(value).replace(/\//gu, "\\/");
}

export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return androidJsonQuote(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Non-finite number in canonical JSON");
    if (Object.is(value, -0)) throw new Error("Negative zero is not supported");
    return value.toString();
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const entries = Object.keys(record)
      .sort()
      .map((key) => {
        const child = record[key];
        if (child === undefined) throw new Error("Undefined value in canonical JSON");
        return `${androidJsonQuote(key)}:${canonicalize(child)}`;
      });
    return `{${entries.join(",")}}`;
  }
  throw new Error(`Unsupported canonical JSON type: ${typeof value}`);
}
