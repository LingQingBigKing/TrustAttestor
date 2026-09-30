import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const BASH = process.env.KEYBOX_TEST_BASH || "bash";
const OPENSSL = process.env.KEYBOX_TEST_OPENSSL || "openssl";
const BASH_AVAILABLE = spawnSync(BASH, ["--version"], { encoding: "utf8" }).status === 0;

function run(command, argumentsAfterCommand, options = {}) {
  return spawnSync(command, argumentsAfterCommand, {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
    ...options
  });
}

function requireCommand(command, versionArguments) {
  const result = run(command, versionArguments);
  if (result.error !== undefined || result.status !== 0) {
    throw new Error(`Required test command is unavailable: ${command}`);
  }
}

function createCertificate(directory, name, serial) {
  const keyPath = resolve(directory, `${name}.key.pem`);
  const certificatePath = resolve(directory, `${name}.cert.pem`);
  const result = run(OPENSSL, [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-subj", `/CN=${name}`,
    "-set_serial", `0x${serial}`,
    "-keyout", keyPath,
    "-out", certificatePath
  ]);
  if (result.error !== undefined || result.status !== 0) {
    throw new Error(`OpenSSL could not create test certificate ${name}: ${result.stderr}`);
  }
  return readFileSync(certificatePath, "utf8").trim();
}

function chain(certificate) {
  return [
    "      <CertificateChain>",
    "        <NumberOfCertificates>2</NumberOfCertificates>",
    `        <Certificate format=\"pem\">${certificate}</Certificate>`,
    `        <Certificate format=\"pem\">${certificate}</Certificate>`,
    "      </CertificateChain>"
  ].join("\n");
}

describe("Termux keybox leaf extractor", () => {
  it.skipIf(!BASH_AVAILABLE)("emits one leaf per Key and rejects a mismatched chain count", () => {
    requireCommand(OPENSSL, ["version"]);
    const temporaryDirectory = mkdtempSync(resolve(PROJECT_ROOT, ".keybox-extractor-test-"));
    try {
      const firstCertificate = createCertificate(temporaryDirectory, "first-key", "11");
      const secondCertificate = createCertificate(temporaryDirectory, "second-key", "22");
      const xml = [
        "<AndroidAttestation>",
        "  <NumberOfKeyboxes>1</NumberOfKeyboxes>",
        "  <Keybox DeviceID=\"test\">",
        "    <Key algorithm=\"ecdsa\">",
        chain(firstCertificate),
        "    </Key>",
        "    <Key algorithm=\"rsa\">",
        chain(secondCertificate),
        "    </Key>",
        "  </Keybox>",
        "</AndroidAttestation>",
        ""
      ].join("\n");
      const xmlPath = resolve(temporaryDirectory, "two-keys.xml");
      writeFileSync(xmlPath, xml, "utf8");
      const relativeXmlPath = relative(PROJECT_ROOT, xmlPath).replaceAll("\\", "/");
      const extracted = run(BASH, ["scripts/extract-keybox-serials.sh", "--features", relativeXmlPath]);
      expect(extracted.status, extracted.stderr).toBe(0);
      const lines = extracted.stdout.trim().split(/\r?\n/);
      expect(lines[0]).toBe(
        "serial_number\tcertificate_sha256\tissuer_spki_sha256\tkeybox_index\tkeybox_count\tkey_index\tkey_count\tsource_file"
      );
      const fields = lines.slice(1).map((line) => line.split("\t"));
      expect(fields).toHaveLength(2);
      expect(fields.map((row) => row[0])).toEqual(["11", "22"]);
      expect(fields.map((row) => row.slice(3, 7))).toEqual([
        ["1", "1", "1", "2"],
        ["1", "1", "2", "2"]
      ]);

      const invalidPath = resolve(temporaryDirectory, "invalid-count.xml");
      writeFileSync(invalidPath, xml.replace(
        "<NumberOfCertificates>2</NumberOfCertificates>",
        "<NumberOfCertificates>3</NumberOfCertificates>"
      ), "utf8");
      const relativeInvalidPath = relative(PROJECT_ROOT, invalidPath).replaceAll("\\", "/");
      const rejected = run(BASH, ["scripts/extract-keybox-serials.sh", "--features", relativeInvalidPath]);
      expect(rejected.status).not.toBe(0);
      expect(rejected.stdout).toBe("");
      expect(rejected.stderr).toContain("invalid Keybox structure");
    } finally {
      rmSync(temporaryDirectory, { recursive: true, force: true });
    }
  });
});
