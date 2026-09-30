import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { CloudFinding, Env } from "../src/types";
import { decodeBase64 } from "../src/encoding";
import { aggregateFindings, exportVerdictPublicKey, signVerdict } from "../src/verdict";

function androidCanonicalize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value).replace(/\//gu, "\\/");
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return value.toString();
  if (Array.isArray(value)) return `[${value.map(androidCanonicalize).join(",")}]`;
  if (typeof value === "object") {
    const item = value as Record<string, unknown>;
    return `{${Object.keys(item).sort().map((key) =>
      `${JSON.stringify(key).replace(/\//gu, "\\/")}:${androidCanonicalize(item[key])}`
    ).join(",")}}`;
  }
  throw new Error("unsupported test value");
}

describe("signed cloud verdict", () => {
  it("uses the public key and canonical string format expected by Android", () => {
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const privatePem = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const env = {
      VERDICT_PRIVATE_KEY: privatePem,
      VERDICT_KEY_ID: "test-key-1",
      RULESET_VERSION: "1"
    } as Env;
    const finding: CloudFinding = {
      status: "DETECTED",
      severity: "CRITICAL",
      probeId: "cloud.keybox.serial_blacklist",
      title: "检测到已泄露的 Keybox",
      evidence: "BRAND/PRODUCT/DEVICE"
    };
    const response = signVerdict(env, "challenge-123", finding, [finding], true);
    const publicKey = createPublicKey({
      key: Buffer.from(decodeBase64(exportVerdictPublicKey(env))),
      type: "spki",
      format: "der"
    });
    expect(response.verdict.findings).toHaveLength(1);
    expect(response.verdict.findings?.[0]).toMatchObject(finding);
    expect(response.verdict.findings?.[0]?.presentation?.["zh-CN"].title)
      .toBe("检测到已泄露的 Keybox");
    expect(response.verdict.findings?.[0]?.presentation?.["en-US"].title)
      .toBe("Known leaked Keybox detected");
    expect(verify(
      "sha256",
      Buffer.from(androidCanonicalize(response.verdict), "utf8"),
      publicKey,
      Buffer.from(decodeBase64(response.signature.value))
    )).toBe(true);
  });

  it("prioritizes detected findings while preserving every rule result", () => {
    const clean: CloudFinding = {
      status: "CLEAN",
      severity: "INFO",
      probeId: "cloud.keybox.serial_blacklist",
      title: "Keybox clean",
      evidence: "none"
    };
    const warning: CloudFinding = {
      status: "WARNING",
      severity: "MEDIUM",
      probeId: "cloud.device.catalog_consistency",
      title: "Device uncertain",
      evidence: "one-sided match"
    };
    const detected: CloudFinding = {
      status: "DETECTED",
      severity: "HIGH",
      probeId: "cloud.soc.catalog_consistency",
      title: "SoC conflict",
      evidence: "vendor mismatch"
    };
    const aggregate = aggregateFindings([clean, warning, detected]);
    expect(aggregate.status).toBe("DETECTED");
    expect(aggregate.evidence).toContain("cloud.soc.catalog_consistency");
    expect(aggregate.evidence).toContain("cloud.device.catalog_consistency");
  });

  it("redacts release evidence and returns detected or unavailable rule titles", () => {
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const env = {
      VERDICT_PRIVATE_KEY: pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      VERDICT_KEY_ID: "test-key-1",
      RULESET_VERSION: "1"
    } as Env;
    const clean: CloudFinding = {
      status: "CLEAN",
      severity: "INFO",
      probeId: "cloud.keybox.serial_blacklist",
      title: "未命中已收录 Keybox 泄露名单",
      evidence: "clean evidence"
    };
    const warning: CloudFinding = {
      status: "WARNING",
      severity: "MEDIUM",
      probeId: "cloud.device.catalog_consistency",
      title: "设备信息需要复核",
      evidence: "warning evidence"
    };
    const detected: CloudFinding = {
      status: "DETECTED",
      severity: "HIGH",
      probeId: "cloud.attestation.subject_rdn_order",
      title: "证书编码序列异常",
      evidence: "sensitive evidence"
    };
    const unavailable: CloudFinding = {
      status: "UNAVAILABLE",
      severity: "INFO",
      probeId: "cloud.tee.patch_consistency",
      title: "TEE 补丁级别交叉校验不可用",
      evidence: "missing optional fields"
    };
    const aggregate = aggregateFindings([clean, warning, detected, unavailable]);
    const response = signVerdict(
      env,
      "challenge-release",
      aggregate,
      [clean, warning, detected, unavailable],
      false
    );

    expect(response.verdict.evidence).toBe("");
    expect(response.verdict.presentation?.["zh-CN"].evidence).toBe("");
    expect(response.verdict.findings).toHaveLength(2);
    expect(response.verdict.findings?.map((finding) => finding.status))
      .toEqual(["DETECTED", "UNAVAILABLE"]);
    expect(response.verdict.findings?.every((finding) => finding.evidence === "")).toBe(true);
    expect(response.verdict.findings?.every((finding) =>
      finding.presentation?.["en-US"].evidence === ""
    )).toBe(true);
  });

  it("keeps a clean aggregate when optional rules are unavailable", () => {
    const clean: CloudFinding = {
      status: "CLEAN",
      severity: "INFO",
      probeId: "cloud.keybox.serial_blacklist",
      title: "Keybox clean",
      evidence: "none"
    };
    const unavailable: CloudFinding = {
      status: "UNAVAILABLE",
      severity: "INFO",
      probeId: "cloud.device.hardware_matrix",
      title: "No reviewed model baseline",
      evidence: "optional coverage missing"
    };
    expect(aggregateFindings([clean, unavailable]).status).toBe("CLEAN");
  });

  it("is unavailable only when no cloud rule completed", () => {
    const unavailable: CloudFinding = {
      status: "UNAVAILABLE",
      severity: "INFO",
      probeId: "cloud.challenge.storage",
      title: "Storage unavailable",
      evidence: "temporary failure"
    };
    expect(aggregateFindings([unavailable]).status).toBe("UNAVAILABLE");
  });

  it("returns all rule details and evidence for a signed debug request", () => {
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const env = {
      VERDICT_PRIVATE_KEY: pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      VERDICT_KEY_ID: "test-key-1",
      RULESET_VERSION: "1"
    } as Env;
    const findings: CloudFinding[] = [
      {
        status: "CLEAN",
        severity: "INFO",
        probeId: "cloud.keybox.serial_blacklist",
        title: "未命中已收录 Keybox 泄露名单",
        evidence: "clean evidence"
      },
      {
        status: "WARNING",
        severity: "MEDIUM",
        probeId: "cloud.device.catalog_consistency",
        title: "设备信息需要复核",
        evidence: "warning evidence"
      }
    ];
    const aggregate = aggregateFindings(findings);
    const response = signVerdict(env, "challenge-debug", aggregate, findings, true);

    expect(response.verdict.evidence).not.toBe("");
    expect(response.verdict.findings).toHaveLength(2);
    expect(response.verdict.findings?.map((finding) => finding.evidence))
      .toEqual(["clean evidence", "warning evidence"]);
  });

  it("omits release details when no detected finding exists", () => {
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const env = {
      VERDICT_PRIVATE_KEY: pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      VERDICT_KEY_ID: "test-key-1",
      RULESET_VERSION: "1"
    } as Env;
    const clean: CloudFinding = {
      status: "CLEAN",
      severity: "INFO",
      probeId: "cloud.keybox.serial_blacklist",
      title: "未命中已收录 Keybox 泄露名单",
      evidence: "release-only evidence"
    };
    const aggregate = aggregateFindings([clean]);
    const response = signVerdict(env, "challenge-release-clean", aggregate, [clean]);

    expect(response.verdict.status).toBe("CLEAN");
    expect(response.verdict.evidence).toBe("");
    expect(response.verdict.findings).toBeUndefined();
    expect(response.verdict.presentation?.["zh-CN"].title).toBe("云端风险评估通过");
    expect(response.verdict.presentation?.["zh-CN"].evidence).toBe("");
  });
});
