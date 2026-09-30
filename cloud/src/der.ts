import type { AttestationApplicationId, AttestationRecord } from "./types";

export interface DerNode {
  tagClass: number;
  constructed: boolean;
  tagNumber: number;
  start: number;
  valueStart: number;
  valueEnd: number;
  end: number;
}

const UNIVERSAL = 0;
const CONTEXT_SPECIFIC = 2;
const COMMON_NAME_OID = "2.5.4.3";
const COUNTRY_NAME_OID = "2.5.4.6";
const LOCALITY_NAME_OID = "2.5.4.7";
const STATE_OR_PROVINCE_NAME_OID = "2.5.4.8";
const ORGANIZATION_NAME_OID = "2.5.4.10";
const ORGANIZATIONAL_UNIT_NAME_OID = "2.5.4.11";
const TITLE_OID = "2.5.4.12";
const SERIAL_NUMBER_OID = "2.5.4.5";

interface X509SubjectRdnProfile {
  id: string;
  expectedOids: readonly string[];
}

const X509_SUBJECT_RDN_PROFILES: readonly X509SubjectRdnProfile[] = [
  { id: "tee-title-serial", expectedOids: [TITLE_OID, SERIAL_NUMBER_OID] },
  { id: "c-o-cn", expectedOids: [COUNTRY_NAME_OID, ORGANIZATION_NAME_OID, COMMON_NAME_OID] },
  {
    id: "c-o-ou-cn",
    expectedOids: [COUNTRY_NAME_OID, ORGANIZATION_NAME_OID, ORGANIZATIONAL_UNIT_NAME_OID, COMMON_NAME_OID]
  },
  {
    id: "c-st-o-ou-cn",
    expectedOids: [
      COUNTRY_NAME_OID,
      STATE_OR_PROVINCE_NAME_OID,
      ORGANIZATION_NAME_OID,
      ORGANIZATIONAL_UNIT_NAME_OID,
      COMMON_NAME_OID
    ]
  },
  {
    id: "c-st-l-o-ou-cn",
    expectedOids: [
      COUNTRY_NAME_OID,
      STATE_OR_PROVINCE_NAME_OID,
      LOCALITY_NAME_OID,
      ORGANIZATION_NAME_OID,
      ORGANIZATIONAL_UNIT_NAME_OID,
      COMMON_NAME_OID
    ]
  },
  {
    id: "o-ou-cn",
    expectedOids: [ORGANIZATION_NAME_OID, ORGANIZATIONAL_UNIT_NAME_OID, COMMON_NAME_OID]
  },
  {
    id: "c-o-ou-title-serial",
    expectedOids: [
      COUNTRY_NAME_OID,
      ORGANIZATION_NAME_OID,
      ORGANIZATIONAL_UNIT_NAME_OID,
      TITLE_OID,
      SERIAL_NUMBER_OID
    ]
  }
];

export type X509SubjectRdnOrder =
  | "TITLE_THEN_SERIAL_NUMBER"
  | "SERIAL_NUMBER_THEN_TITLE"
  | "NOT_APPLICABLE";

export interface X509SubjectRdnSequenceInspection {
  classification: "EXPECTED" | "REVERSED" | "NOT_APPLICABLE";
  actualOids: string[];
  expectedOids?: string[];
  profileId?: string;
}

export function readDerNode(data: Uint8Array, start: number, limit = data.byteLength): DerNode {
  if (!Number.isSafeInteger(start) || start < 0 || start >= limit || limit > data.byteLength) {
    throw new Error("Invalid DER node offset");
  }
  let cursor = start;
  const first = data[cursor++];
  if (first === undefined) throw new Error("Truncated DER tag");
  const tagClass = first >>> 6;
  const constructed = (first & 0x20) !== 0;
  let tagNumber = first & 0x1f;
  if (tagNumber === 0x1f) {
    tagNumber = 0;
    let completed = false;
    for (let count = 0; count < 5 && cursor < limit; count += 1) {
      const part = data[cursor++];
      if (part === undefined || tagNumber > 0x1ffffff) throw new Error("Invalid DER high tag");
      tagNumber = tagNumber * 128 + (part & 0x7f);
      if ((part & 0x80) === 0) {
        completed = true;
        break;
      }
    }
    if (!completed) throw new Error("Truncated DER high tag");
  }
  const lengthByte = data[cursor++];
  if (lengthByte === undefined) throw new Error("Truncated DER length");
  let length = lengthByte;
  if ((lengthByte & 0x80) !== 0) {
    const count = lengthByte & 0x7f;
    if (count === 0 || count > 4 || cursor + count > limit) {
      throw new Error("Unsupported DER length");
    }
    length = 0;
    for (let index = 0; index < count; index += 1) {
      const part = data[cursor++];
      if (part === undefined) throw new Error("Truncated DER length");
      length = length * 256 + part;
    }
  }
  const valueEnd = cursor + length;
  if (!Number.isSafeInteger(valueEnd) || valueEnd > limit) throw new Error("DER value exceeds bounds");
  return {
    tagClass,
    constructed,
    tagNumber,
    start,
    valueStart: cursor,
    valueEnd,
    end: valueEnd
  };
}

export function derChildren(data: Uint8Array, parent: DerNode): DerNode[] {
  const children: DerNode[] = [];
  let cursor = parent.valueStart;
  while (cursor < parent.valueEnd) {
    const child = readDerNode(data, cursor, parent.valueEnd);
    children.push(child);
    cursor = child.end;
  }
  if (cursor !== parent.valueEnd) throw new Error("DER child boundary mismatch");
  return children;
}

function decodeOid(data: Uint8Array, node: DerNode): string {
  if (node.tagClass !== UNIVERSAL || node.tagNumber !== 6) throw new Error("Expected DER OID");
  const values: number[] = [];
  let value = 0;
  let active = false;
  for (let cursor = node.valueStart; cursor < node.valueEnd; cursor += 1) {
    const part = data[cursor];
    if (part === undefined || value > 0x1ffffff) throw new Error("Invalid DER OID");
    value = value * 128 + (part & 0x7f);
    active = true;
    if ((part & 0x80) === 0) {
      values.push(value);
      value = 0;
      active = false;
    }
  }
  if (active || values.length === 0) throw new Error("Truncated DER OID");
  const first = values.shift()!;
  const firstArc = Math.min(Math.floor(first / 40), 2);
  return [firstArc, first - firstArc * 40, ...values].join(".");
}

function singleValuedRdnOid(data: Uint8Array, rdn: DerNode): string | undefined {
  if (rdn.tagClass !== UNIVERSAL || rdn.tagNumber !== 17 || !rdn.constructed) return undefined;
  const rdnValues = derChildren(data, rdn);
  if (rdnValues.length !== 1) return undefined;
  const attribute = rdnValues[0]!;
  if (attribute.tagClass !== UNIVERSAL || attribute.tagNumber !== 16 || !attribute.constructed) {
    return undefined;
  }
  const attributeFields = derChildren(data, attribute);
  if (attributeFields.length !== 2) return undefined;
  const oid = attributeFields[0]!;
  if (oid.tagClass !== UNIVERSAL || oid.tagNumber !== 6) return undefined;
  return decodeOid(data, oid);
}

function x509NameNode(certificateDer: Uint8Array, field: "issuer" | "subject"): DerNode {
  const certificate = readDerNode(certificateDer, 0);
  if (
    certificate.tagClass !== UNIVERSAL ||
    certificate.tagNumber !== 16 ||
    !certificate.constructed ||
    certificate.end !== certificateDer.length
  ) {
    throw new Error("Invalid X.509 certificate structure");
  }
  const certificateChildren = derChildren(certificateDer, certificate);
  const tbs = certificateChildren[0];
  if (tbs === undefined || tbs.tagClass !== UNIVERSAL || tbs.tagNumber !== 16 || !tbs.constructed) {
    throw new Error("Invalid X.509 TBSCertificate structure");
  }
  const tbsFields = derChildren(certificateDer, tbs);
  const hasExplicitVersion = tbsFields[0]?.tagClass === CONTEXT_SPECIFIC && tbsFields[0]?.tagNumber === 0;
  const offset = hasExplicitVersion ? 1 : 0;
  const name = tbsFields[offset + (field === "issuer" ? 2 : 4)];
  if (name === undefined || name.tagClass !== UNIVERSAL || name.tagNumber !== 16 || !name.constructed) {
    throw new Error(`Invalid X.509 ${field} structure`);
  }
  return name;
}

function equalOidSequence(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((oid, index) => oid === right[index]);
}

function singleValuedX509NameOids(certificateDer: Uint8Array, field: "issuer" | "subject"): string[] | undefined {
  const oids: string[] = [];
  for (const rdn of derChildren(certificateDer, x509NameNode(certificateDer, field))) {
    const oid = singleValuedRdnOid(certificateDer, rdn);
    if (oid === undefined) return undefined;
    oids.push(oid);
  }
  return oids;
}

/**
 * Matches reviewed raw-DER Subject RDNSequence profiles. A reversal is only
 * reported when the complete sequence is the exact reverse of one profile;
 * arbitrary reordering and multi-valued RDNs remain not applicable.
 */
export function inspectX509SubjectRdnSequence(certificateDer: Uint8Array): X509SubjectRdnSequenceInspection {
  const actualOids = singleValuedX509NameOids(certificateDer, "subject");
  if (actualOids === undefined) return { classification: "NOT_APPLICABLE", actualOids: [] };
  for (const profile of X509_SUBJECT_RDN_PROFILES) {
    if (equalOidSequence(actualOids, profile.expectedOids)) {
      return {
        classification: "EXPECTED",
        actualOids,
        expectedOids: [...profile.expectedOids],
        profileId: profile.id
      };
    }
    const reversed = [...profile.expectedOids].reverse();
    if (equalOidSequence(actualOids, reversed)) {
      return {
        classification: "REVERSED",
        actualOids,
        expectedOids: [...profile.expectedOids],
        profileId: profile.id
      };
    }
  }
  return { classification: "NOT_APPLICABLE", actualOids };
}

export function inspectX509SubjectRdnOrder(certificateDer: Uint8Array): X509SubjectRdnOrder {
  const rdns = derChildren(certificateDer, x509NameNode(certificateDer, "subject"));
  if (rdns.length !== 2) return "NOT_APPLICABLE";
  const firstOid = singleValuedRdnOid(certificateDer, rdns[0]!);
  const secondOid = singleValuedRdnOid(certificateDer, rdns[1]!);
  if (firstOid === TITLE_OID && secondOid === SERIAL_NUMBER_OID) {
    return "TITLE_THEN_SERIAL_NUMBER";
  }
  if (firstOid === SERIAL_NUMBER_OID && secondOid === TITLE_OID) {
    return "SERIAL_NUMBER_THEN_TITLE";
  }
  return "NOT_APPLICABLE";
}

function decodeDirectoryString(data: Uint8Array, node: DerNode): string | undefined {
  if (node.tagClass !== UNIVERSAL || node.constructed) return undefined;
  const bytes = data.subarray(node.valueStart, node.valueEnd);
  if (node.tagNumber === 12) {
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      return undefined;
    }
  }
  if ([19, 20, 22, 26].includes(node.tagNumber)) {
    if ([...bytes].some((value) => value > 0x7f)) return undefined;
    return String.fromCharCode(...bytes);
  }
  if (node.tagNumber === 30) {
    if (bytes.length % 2 !== 0) return undefined;
    let result = "";
    for (let index = 0; index < bytes.length; index += 2) {
      result += String.fromCharCode((bytes[index]! << 8) | bytes[index + 1]!);
    }
    return result;
  }
  return undefined;
}

function normalizeDirectoryString(value: string): string {
  return value.trim().replace(/\s+/g, " ").toLowerCase();
}

export function hasX509SubjectAttributeValue(
  certificateDer: Uint8Array,
  expectedOid: string,
  expectedValue: string
): boolean {
  const normalizedExpected = normalizeDirectoryString(expectedValue);
  return derChildren(certificateDer, x509NameNode(certificateDer, "subject")).some((rdn) => {
    if (rdn.tagClass !== UNIVERSAL || rdn.tagNumber !== 17 || !rdn.constructed) return false;
    return derChildren(certificateDer, rdn).some((attribute) => {
      if (attribute.tagClass !== UNIVERSAL || attribute.tagNumber !== 16 || !attribute.constructed) return false;
      const fields = derChildren(certificateDer, attribute);
      if (fields.length !== 2 || decodeOid(certificateDer, fields[0]!) !== expectedOid) return false;
      const value = decodeDirectoryString(certificateDer, fields[1]!);
      return value !== undefined && normalizeDirectoryString(value) === normalizedExpected;
    });
  });
}

/** Structural classification only; callers must first validate the chain and trust anchor. */
export function hasX509SubjectAttribute(certificateDer: Uint8Array, expectedOid: string): boolean {
  const subject = x509NameNode(certificateDer, "subject");
  return derChildren(certificateDer, subject).some((rdn) => {
    if (rdn.tagClass !== UNIVERSAL || rdn.tagNumber !== 17 || !rdn.constructed) {
      throw new Error("Invalid X.509 RDN");
    }
    return derChildren(certificateDer, rdn).some((attribute) => {
      const oid = derChildren(certificateDer, attribute)[0];
      return oid !== undefined && decodeOid(certificateDer, oid) === expectedOid;
    });
  });
}

function integerValue(data: Uint8Array, node: DerNode): bigint {
  if (node.tagClass !== UNIVERSAL || (node.tagNumber !== 2 && node.tagNumber !== 10)) {
    throw new Error("Expected DER integer");
  }
  if (node.valueStart === node.valueEnd) throw new Error("Empty DER integer");
  if ((data[node.valueStart]! & 0x80) !== 0) throw new Error("Negative DER integer is unsupported");
  let value = 0n;
  for (let cursor = node.valueStart; cursor < node.valueEnd; cursor += 1) {
    value = value * 256n + BigInt(data[cursor]!);
  }
  return value;
}

function explicitValue(data: Uint8Array, node: DerNode): DerNode {
  const children = derChildren(data, node);
  if (children.length !== 1) throw new Error("Invalid explicit DER value");
  return children[0]!;
}

function findContext(children: DerNode[], tagNumber: number): DerNode | undefined {
  return children.find((node) => node.tagClass === CONTEXT_SPECIFIC && node.tagNumber === tagNumber);
}

function optionalExplicitInteger(
  data: Uint8Array,
  children: DerNode[],
  tagNumber: number
): bigint | undefined {
  const node = findContext(children, tagNumber);
  return node === undefined ? undefined : integerValue(data, explicitValue(data, node));
}

export function findX509Extension(
  certificateDer: Uint8Array,
  expectedOid: string
): Uint8Array | undefined {
  const certificate = readDerNode(certificateDer, 0);
  const certificateChildren = derChildren(certificateDer, certificate);
  const tbs = certificateChildren[0];
  if (tbs === undefined || tbs.tagClass !== UNIVERSAL || tbs.tagNumber !== 16) {
    throw new Error("Invalid X.509 certificate structure");
  }
  const extensionsContainer = findContext(derChildren(certificateDer, tbs), 3);
  if (extensionsContainer === undefined) return undefined;
  const extensionSequences = derChildren(certificateDer, explicitValue(certificateDer, extensionsContainer));
  for (const extension of extensionSequences) {
    const fields = derChildren(certificateDer, extension);
    const oid = fields[0];
    if (oid === undefined || decodeOid(certificateDer, oid) !== expectedOid) continue;
    const octet = fields.find(
      (field, index) => index > 0 && field.tagClass === UNIVERSAL && field.tagNumber === 4
    );
    if (octet === undefined) throw new Error("X.509 extension has no value");
    return certificateDer.slice(octet.valueStart, octet.valueEnd);
  }
  return undefined;
}

/** Parses the nested OCTET STRING payload, preserving the whole shared-UID identity. */
export function parseAttestationApplicationId(encoded: Uint8Array): AttestationApplicationId {
  if (encoded.length > 16_384) throw new Error("AttestationApplicationId exceeds bounds");
  const description = readDerNode(encoded, 0);
  if (description.tagClass !== UNIVERSAL || description.tagNumber !== 16 || !description.constructed
      || description.end !== encoded.length) throw new Error("Invalid AttestationApplicationId sequence");
  const fields = derChildren(encoded, description);
  if (fields.length !== 2 || fields.some((node) =>
    node.tagClass !== UNIVERSAL || node.tagNumber !== 17 || !node.constructed
  )) throw new Error("Invalid AttestationApplicationId sets");
  const packageNodes = derChildren(encoded, fields[0]!);
  const digestNodes = derChildren(encoded, fields[1]!);
  if (packageNodes.length < 1 || packageNodes.length > 64 || digestNodes.length < 1 || digestNodes.length > 32) {
    throw new Error("Invalid AttestationApplicationId set sizes");
  }
  const packages = packageNodes.map((node) => {
    if (node.tagClass !== UNIVERSAL || node.tagNumber !== 16 || !node.constructed) {
      throw new Error("Invalid AttestationPackageInfo sequence");
    }
    const values = derChildren(encoded, node);
    const nameNode = values[0];
    const versionNode = values[1];
    if (values.length !== 2 || nameNode?.tagClass !== UNIVERSAL || nameNode.tagNumber !== 4
        || nameNode.constructed || versionNode?.tagClass !== UNIVERSAL || versionNode.tagNumber !== 2
        || versionNode.constructed) {
      throw new Error("Invalid AttestationPackageInfo fields");
    }
    const name = new TextDecoder("utf-8", { fatal: true }).decode(encoded.slice(nameNode.valueStart, nameNode.valueEnd));
    if (name.length > 255 || !/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*$/u.test(name)) {
      throw new Error("Invalid attested package name");
    }
    return { name, version: integerValue(encoded, versionNode) };
  });
  const signatureDigests = digestNodes.map((node) => {
    if (node.tagClass !== UNIVERSAL || node.tagNumber !== 4 || node.constructed
        || node.valueEnd - node.valueStart !== 32) throw new Error("Invalid app signing certificate SHA-256");
    return [...encoded.slice(node.valueStart, node.valueEnd)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  });
  if (new Set(packages.map((entry) => entry.name)).size !== packages.length
      || new Set(signatureDigests).size !== signatureDigests.length) {
    throw new Error("Duplicate AttestationApplicationId entries");
  }
  return { packages, signatureDigests };
}

function applicationIdFields(data: Uint8Array, software: DerNode, hardware: DerNode):
    Pick<AttestationRecord, "applicationId" | "applicationIdError"> {
  try {
    const values = [software, hardware].flatMap((list) => {
      if (list.tagClass !== UNIVERSAL || list.tagNumber !== 16 || !list.constructed) {
        throw new Error("Invalid attestation authorization list");
      }
      const tags = derChildren(data, list).filter((node) =>
        node.tagClass === CONTEXT_SPECIFIC && node.tagNumber === 709
      );
      if (tags.length > 1) throw new Error("Duplicate application identity authorization");
      return tags.map((node) => {
        if (!node.constructed) throw new Error("Invalid explicit application identity authorization");
        const value = explicitValue(data, node);
        if (value.tagClass !== UNIVERSAL || value.tagNumber !== 4 || value.constructed) {
          throw new Error("Invalid application identity authorization");
        }
        return data.slice(value.valueStart, value.valueEnd);
      });
    });
    if (values.length === 0) return {};
    if (values.length === 2 && (values[0]!.length !== values[1]!.length
        || values[0]!.some((byte, index) => byte !== values[1]![index]))) {
      throw new Error("Conflicting software and hardware application identities");
    }
    return { applicationId: parseAttestationApplicationId(values[0]!) };
  } catch (error) {
    // An optional-field parsing failure must not erase already available boot/challenge evidence.
    return { applicationIdError: error instanceof Error ? error.message : "Application identity parsing failed" };
  }
}

export function parseAndroidAttestationExtension(extensionDer: Uint8Array): AttestationRecord {
  const description = readDerNode(extensionDer, 0);
  if (description.tagClass !== UNIVERSAL || description.tagNumber !== 16 || description.end !== extensionDer.length) {
    throw new Error("Invalid Android attestation extension");
  }
  const fields = derChildren(extensionDer, description);
  if (fields.length < 8) throw new Error("Truncated Android attestation extension");
  const challengeNode = fields[4]!;
  if (challengeNode.tagClass !== UNIVERSAL || challengeNode.tagNumber !== 4) {
    throw new Error("Invalid Android attestation challenge");
  }
  const hardware = fields[7]!;
  const hardwareFields = derChildren(extensionDer, hardware);
  const rootOfTrustNode = findContext(hardwareFields, 704);

  let deviceLocked: boolean | undefined;
  let verifiedBootState: number | undefined;
  let verifiedBootKey: Uint8Array | undefined;
  let verifiedBootHash: Uint8Array | undefined;
  if (rootOfTrustNode !== undefined) {
    const rootSequence = explicitValue(extensionDer, rootOfTrustNode);
    const rootFields = derChildren(extensionDer, rootSequence);
    const bootKeyNode = rootFields[0];
    const lockedNode = rootFields[1];
    const bootStateNode = rootFields[2];
    const bootHashNode = rootFields[3];
    if (bootKeyNode !== undefined && bootKeyNode.tagClass === UNIVERSAL && bootKeyNode.tagNumber === 4) {
      verifiedBootKey = extensionDer.slice(bootKeyNode.valueStart, bootKeyNode.valueEnd);
    }
    if (lockedNode !== undefined && lockedNode.tagClass === UNIVERSAL && lockedNode.tagNumber === 1) {
      deviceLocked = extensionDer[lockedNode.valueStart] !== 0;
    }
    if (bootStateNode !== undefined) {
      const state = integerValue(extensionDer, bootStateNode);
      if (state <= BigInt(Number.MAX_SAFE_INTEGER)) verifiedBootState = Number(state);
    }
    if (bootHashNode !== undefined && bootHashNode.tagClass === UNIVERSAL && bootHashNode.tagNumber === 4) {
      verifiedBootHash = extensionDer.slice(bootHashNode.valueStart, bootHashNode.valueEnd);
    }
  }

  const osVersion = optionalExplicitInteger(extensionDer, hardwareFields, 705);
  const osPatchLevel = optionalExplicitInteger(extensionDer, hardwareFields, 706);
  const vendorPatchLevel = optionalExplicitInteger(extensionDer, hardwareFields, 718);
  const bootPatchLevel = optionalExplicitInteger(extensionDer, hardwareFields, 719);
  return {
    attestationVersion: integerValue(extensionDer, fields[0]!),
    attestationSecurityLevel: Number(integerValue(extensionDer, fields[1]!)),
    keyMintVersion: integerValue(extensionDer, fields[2]!),
    keyMintSecurityLevel: Number(integerValue(extensionDer, fields[3]!)),
    challenge: extensionDer.slice(challengeNode.valueStart, challengeNode.valueEnd),
    ...applicationIdFields(extensionDer, fields[6]!, hardware),
    ...(osVersion === undefined ? {} : { osVersion }),
    ...(osPatchLevel === undefined ? {} : { osPatchLevel }),
    ...(vendorPatchLevel === undefined ? {} : { vendorPatchLevel }),
    ...(bootPatchLevel === undefined ? {} : { bootPatchLevel }),
    ...(verifiedBootKey === undefined ? {} : { verifiedBootKey }),
    ...(deviceLocked === undefined ? {} : { deviceLocked }),
    ...(verifiedBootState === undefined ? {} : { verifiedBootState }),
    ...(verifiedBootHash === undefined ? {} : { verifiedBootHash })
  };
}
