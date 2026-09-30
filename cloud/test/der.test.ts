import { describe, expect, it } from "vitest";
import {
  hasX509SubjectAttributeValue,
  inspectX509SubjectRdnOrder,
  inspectX509SubjectRdnSequence,
  parseAndroidAttestationExtension,
  parseAttestationApplicationId
} from "../src/der";

function length(value: number): number[] {
  if (value < 128) return [value];
  const bytes: number[] = [];
  for (let remaining = value; remaining > 0; remaining >>>= 8) bytes.unshift(remaining & 0xff);
  return [0x80 | bytes.length, ...bytes];
}

function tlv(tag: number[], value: number[]): number[] {
  return [...tag, ...length(value.length), ...value];
}

function integer(value: number, tag = 0x02): number[] {
  const bytes: number[] = [];
  for (let remaining = value; remaining > 0; remaining >>>= 8) bytes.unshift(remaining & 0xff);
  if (bytes.length === 0) bytes.push(0);
  if ((bytes[0]! & 0x80) !== 0) bytes.unshift(0);
  return tlv([tag], bytes);
}

function sequence(...children: number[][]): number[] {
  return tlv([0x30], children.flat());
}

function set(...children: number[][]): number[] {
  return tlv([0x31], children.flat());
}

function oid(...bytes: number[]): number[] {
  return tlv([0x06], bytes);
}

function subjectAttribute(oidBytes: number[], value: string): number[] {
  return set(sequence(oid(...oidBytes), tlv([0x0c], [...new TextEncoder().encode(value)])));
}

function certificateWithSubject(subject: number[], includeVersion = true): Uint8Array {
  const signatureAlgorithm = sequence(oid(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02));
  const version = tlv([0xa0], integer(2));
  const tbs = sequence(
    ...(includeVersion ? [version] : []),
    integer(1),
    signatureAlgorithm,
    sequence(),
    sequence(),
    subject,
    sequence()
  );
  return Uint8Array.from(sequence(tbs, signatureAlgorithm, tlv([0x03], [0x00])));
}

function explicit(tag: number, child: number[]): number[] {
  const tagParts: number[] = [];
  let current = tag;
  do {
    tagParts.unshift(current & 0x7f);
    current >>>= 7;
  } while (current > 0);
  for (let index = 0; index < tagParts.length - 1; index += 1) tagParts[index] = tagParts[index]! | 0x80;
  return tlv([0xbf, ...tagParts], child);
}

describe("Android attestation DER parser", () => {
  it("extracts challenge, Root of Trust, and patch levels", () => {
    const challenge = [1, 3, 3, 7];
    const rootOfTrust = sequence(
      tlv([0x04], [0xaa]),
      tlv([0x01], [0xff]),
      integer(0, 0x0a),
      tlv([0x04], [0xbb])
    );
    const hardware = sequence(
      explicit(704, rootOfTrust),
      explicit(705, integer(160000)),
      explicit(706, integer(202608)),
      explicit(718, integer(20260805)),
      explicit(719, integer(20260705))
    );
    const encoded = Uint8Array.from(sequence(
      integer(400),
      integer(1, 0x0a),
      integer(400),
      integer(2, 0x0a),
      tlv([0x04], challenge),
      tlv([0x04], []),
      sequence(),
      hardware
    ));
    const result = parseAndroidAttestationExtension(encoded);
    expect([...result.challenge]).toEqual(challenge);
    expect(result.attestationSecurityLevel).toBe(1);
    expect(result.keyMintSecurityLevel).toBe(2);
    expect(result.deviceLocked).toBe(true);
    expect(result.verifiedBootState).toBe(0);
    expect([...result.verifiedBootKey!]).toEqual([0xaa]);
    expect([...result.verifiedBootHash!]).toEqual([0xbb]);
    expect(result.osPatchLevel).toBe(202608n);
    expect(result.vendorPatchLevel).toBe(20260805n);
    expect(result.bootPatchLevel).toBe(20260705n);
  });
});

describe("X.509 Subject DER RDN order", () => {
  const title = subjectAttribute([0x55, 0x04, 0x0c], "TEE");
  const serialNumber = subjectAttribute([0x55, 0x04, 0x05], "0123456789");
  const commonName = subjectAttribute([0x55, 0x04, 0x03], "TEE");
  const country = subjectAttribute([0x55, 0x04, 0x06], "CN");
  const locality = subjectAttribute([0x55, 0x04, 0x07], "Shenzhen");
  const state = subjectAttribute([0x55, 0x04, 0x08], "Guangdong");
  const organization = subjectAttribute([0x55, 0x04, 0x0a], "Vendor");
  const organizationalUnit = subjectAttribute([0x55, 0x04, 0x0b], "Attestation");

  it("accepts the raw Title then SerialNumber order", () => {
    const certificate = certificateWithSubject(sequence(title, serialNumber));
    expect(inspectX509SubjectRdnOrder(certificate)).toBe("TITLE_THEN_SERIAL_NUMBER");
  });

  it("detects the reversed SerialNumber then Title order", () => {
    const certificate = certificateWithSubject(sequence(serialNumber, title));
    expect(inspectX509SubjectRdnOrder(certificate)).toBe("SERIAL_NUMBER_THEN_TITLE");
  });

  it("supports v1 certificates without an explicit version field", () => {
    const certificate = certificateWithSubject(sequence(title, serialNumber), false);
    expect(inspectX509SubjectRdnOrder(certificate)).toBe("TITLE_THEN_SERIAL_NUMBER");
  });

  it("does not classify other Subject shapes", () => {
    const leafCommonName = subjectAttribute([0x55, 0x04, 0x03], "Android Keystore Key");
    const certificate = certificateWithSubject(sequence(leafCommonName));
    expect(inspectX509SubjectRdnOrder(certificate)).toBe("NOT_APPLICABLE");
  });

  const reviewedProfiles: Array<[string, number[][]]> = [
    ["tee-title-serial", [title, serialNumber]],
    ["c-o-cn", [country, organization, commonName]],
    ["c-o-ou-cn", [country, organization, organizationalUnit, commonName]],
    ["c-st-o-ou-cn", [country, state, organization, organizationalUnit, commonName]],
    ["c-st-l-o-ou-cn", [country, state, locality, organization, organizationalUnit, commonName]],
    ["o-ou-cn", [organization, organizationalUnit, commonName]],
    ["c-o-ou-title-serial", [country, organization, organizationalUnit, title, serialNumber]]
  ];

  for (const [profileId, attributes] of reviewedProfiles) {
    it(`accepts reviewed profile ${profileId}`, () => {
      const result = inspectX509SubjectRdnSequence(certificateWithSubject(sequence(...attributes)));
      expect(result.classification).toBe("EXPECTED");
      expect(result.profileId).toBe(profileId);
    });

    it(`detects the complete reversal of ${profileId}`, () => {
      const reversed = [...attributes].reverse();
      const result = inspectX509SubjectRdnSequence(certificateWithSubject(sequence(...reversed)));
      expect(result.classification).toBe("REVERSED");
      expect(result.profileId).toBe(profileId);
    });
  }

  it("does not classify an arbitrary permutation as a reversal", () => {
    const certificate = certificateWithSubject(sequence(country, organizationalUnit, organization, commonName));
    expect(inspectX509SubjectRdnSequence(certificate).classification).toBe("NOT_APPLICABLE");
  });

  it("matches the TEE marker by decoded directory-string value", () => {
    const certificate = certificateWithSubject(sequence(country, organization, commonName));
    expect(hasX509SubjectAttributeValue(certificate, "2.5.4.3", "TEE")).toBe(true);
    expect(hasX509SubjectAttributeValue(certificate, "2.5.4.3", "StrongBox")).toBe(false);
  });
});

describe("AttestationApplicationId DER parsing", () => {
  const signer = Array(32).fill(0x11) as number[];
  const secondSigner = Array(32).fill(0x22) as number[];
  const packageInfo = (name: string, version: number) => sequence(tlv([4], [...new TextEncoder().encode(name)]), integer(version));
  const application = sequence(set(packageInfo("com.example.app", 14), packageInfo("com.example.peer", 7)),
    set(tlv([4], signer), tlv([4], secondSigner)));
  const authorization = (value: number[]) => explicit(709, tlv([4], value));
  const extension = (software: number[], hardware = sequence()) => Uint8Array.from(sequence(
    integer(400), integer(1, 0x0a), integer(400), integer(1, 0x0a),
    tlv([4], [1, 2, 3]), tlv([4], []), software, hardware
  ));

  it("preserves all shared UID packages, versions and signing certificate digests", () => {
    const parsed = parseAndroidAttestationExtension(extension(sequence(authorization(application))));
    expect(parsed.applicationId?.packages).toEqual([{ name: "com.example.app", version: 14n }, { name: "com.example.peer", version: 7n }]);
    expect(parsed.applicationId?.signatureDigests).toEqual(["11".repeat(32), "22".repeat(32)]);
    expect(parsed.applicationIdError).toBeUndefined();
  });

  it("does not silently overwrite conflicting enforcement lists", () => {
    const other = sequence(set(packageInfo("com.example.other", 1)), set(tlv([4], signer)));
    const parsed = parseAndroidAttestationExtension(extension(sequence(authorization(application)), sequence(authorization(other))));
    expect(parsed.applicationId).toBeUndefined();
    expect(parsed.applicationIdError).toContain("Conflicting");
    expect([...parsed.challenge]).toEqual([1, 2, 3]);
  });

  it("rejects duplicate authorizations without losing other attestation fields", () => {
    const parsed = parseAndroidAttestationExtension(extension(sequence(authorization(application), authorization(application))));
    expect(parsed.applicationId).toBeUndefined();
    expect(parsed.applicationIdError).toContain("Duplicate");
    expect(parsed.keyMintSecurityLevel).toBe(1);
  });

  it("preserves missing identity as unavailable rather than inventing a value", () => {
    const parsed = parseAndroidAttestationExtension(extension(sequence()));
    expect(parsed.applicationId).toBeUndefined();
    expect(parsed.applicationIdError).toBeUndefined();
  });

  it("rejects wrong digest sizes, duplicate packages and trailing data", () => {
    const wrongDigest = sequence(set(packageInfo("com.example.app", 1)), set(tlv([4], [1, 2])));
    expect(() => parseAttestationApplicationId(Uint8Array.from(wrongDigest))).toThrow("SHA-256");
    const duplicatePackage = sequence(set(packageInfo("com.example.app", 1), packageInfo("com.example.app", 2)), set(tlv([4], signer)));
    expect(() => parseAttestationApplicationId(Uint8Array.from(duplicatePackage))).toThrow("Duplicate");
    expect(() => parseAttestationApplicationId(Uint8Array.from([...application, 0]))).toThrow();
  });

  it("does not accept constructed integers or primitive explicit identity tags", () => {
    const badVersion = sequence(set(sequence(tlv([4], [...new TextEncoder().encode("com.example.app")]),
      tlv([0x22], [1]))), set(tlv([4], signer)));
    expect(() => parseAttestationApplicationId(Uint8Array.from(badVersion))).toThrow();
    const primitive = authorization(application);
    primitive[0] = primitive[0]! & ~0x20;
    const parsed = parseAndroidAttestationExtension(extension(sequence(primitive)));
    expect(parsed.applicationId).toBeUndefined();
    expect(parsed.applicationIdError).toContain("explicit");
    expect([...parsed.challenge]).toEqual([1, 2, 3]);
  });
});
