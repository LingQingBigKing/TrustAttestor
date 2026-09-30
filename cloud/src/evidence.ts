export interface NativeDeviceEvidence {
  schema: string;
  device: {
    model: string;
    product: string;
    device: string;
    board: string;
    manufacturer: string;
    brand: string;
    sku: string;
  };
  os: {
    release: string;
    releaseOrCodename: string;
    sdk: number | null;
    buildId: string;
    incremental: string;
    incrementalCandidates?: string[];
    securityPatch: string;
    vendorSecurityPatch: string;
    buildTime: string;
    buildTimeUtc: number | null;
    vendorBuildTimeUtc: number | null;
    bootImageBuildTimeUtc: number | null;
    buildType: string;
    buildTags: string;
    instructionSet: string;
    fingerprint: string;
  };
  processor: {
    hardware: string;
    boardPlatform: string;
    socManufacturer: string;
    socModel: string;
    supportedAbis: string[];
    supportedAbis32: string[];
    supportedAbis64: string[];
  };
  kernel: {
    release: string;
    buildVersion: string;
    machine: string;
  };
  boot: {
    vbmetaDeviceState: string;
    verifiedBootState: string;
    flashLocked: string;
    verityMode: string;
    vbmetaDigest: string;
  };
}

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function text(value: unknown, maxLength = 512): string {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

function integerText(value: unknown): number | null {
  const normalized = text(value, 32);
  if (!/^[0-9]{1,16}$/.test(normalized)) return null;
  const parsed = Number(normalized);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function textArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => text(entry, 128)).filter(Boolean).slice(0, 64);
}

export function extractNativeDeviceEvidence(value: Record<string, unknown>): NativeDeviceEvidence {
  const device = record(value.device);
  const os = record(value.os);
  const processor = record(value.processor);
  const kernel = record(value.kernel);
  const boot = record(value.boot);
  return {
    schema: text(value.schema, 80),
    device: {
      model: text(device.model),
      product: text(device.product),
      device: text(device.device),
      board: text(device.board),
      manufacturer: text(device.manufacturer),
      brand: text(device.brand),
      sku: text(device.sku)
    },
    os: {
      release: text(os.release),
      releaseOrCodename: text(os.releaseOrCodename),
      sdk: integerText(os.sdk),
      buildId: text(os.buildId),
      incremental: text(os.incremental),
      incrementalCandidates: textArray(os.incrementalCandidates),
      securityPatch: text(os.securityPatch),
      vendorSecurityPatch: text(os.vendorSecurityPatch),
      buildTime: text(os.buildTime),
      buildTimeUtc: integerText(os.buildTimeUtc),
      vendorBuildTimeUtc: integerText(os.vendorBuildTimeUtc),
      bootImageBuildTimeUtc: integerText(os.bootImageBuildTimeUtc),
      buildType: text(os.buildType),
      buildTags: text(os.buildTags),
      instructionSet: text(os.instructionSet),
      fingerprint: text(os.fingerprint, 1024)
    },
    processor: {
      hardware: text(processor.hardware),
      boardPlatform: text(processor.boardPlatform),
      socManufacturer: text(processor.socManufacturer),
      socModel: text(processor.socModel),
      supportedAbis: textArray(processor.supportedAbis),
      supportedAbis32: textArray(processor.supportedAbis32),
      supportedAbis64: textArray(processor.supportedAbis64)
    },
    kernel: {
      release: text(kernel.release, 1024),
      buildVersion: text(kernel.buildVersion, 2048),
      machine: text(kernel.machine, 256)
    },
    boot: {
      vbmetaDeviceState: text(boot.vbmetaDeviceState),
      verifiedBootState: text(boot.verifiedBootState),
      flashLocked: text(boot.flashLocked),
      verityMode: text(boot.verityMode),
      vbmetaDigest: text(boot.vbmetaDigest, 256)
    }
  };
}
