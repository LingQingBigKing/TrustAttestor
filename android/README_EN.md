# TrustAttestor

[简体中文](README.md) · [Cloud backend](../cloud/) · [MIT License](../LICENSE)

TrustAttestor is an open-source Android device trust diagnostics tool for security research, device self-checks, and risk-analysis support. It combines Android Key Attestation, KeyMint/Keystore behavior, system integrity, runtime evidence, and optional cloud verification into an explainable layered report.

The current client is **v1.5** (versionCode 15), supports Android 8.1 / API 27 and later, and targets `arm64-v8a`.

> A result describes only the evidence observable by this implementation. It is not a substitute for professional forensics, a vendor security statement, or a complete risk policy. ROM differences, missing privileges, and system load may make individual probes unavailable.

## Detection layers

| Layer | Scope | Examples |
| --- | --- | --- |
| L0 | Hardware attestation | X.509 chain, Root of Trust, authorization lists, KeyMint/Keystore behavior |
| L1 | System integrity | APK/native identity, SELinux, injection and hook evidence, mapping consistency |
| L2 | Device environment | Isolated processes, mount topology, TEE simulation, anomalous package-directory traversal |
| L3 | Optional cloud attestation | Revocation, leaked keyboxes, attestation consistency, device catalog and kernel policy |

Findings use stable `probeId` values and four states: `CLEAN`, `DETECTED`, `WARNING`, and `UNAVAILABLE`. Only `DETECTED` is counted as an anomaly. `UNAVAILABLE` means the probe could not produce complete evidence; it is neither a pass nor a detection.

## Repository layout

| Path | Purpose |
| --- | --- |
| `app/` | Android app, Material UI, JNI entry points, and native checks |
| `dex/` | Key Attestation, KeyMint/Keystore probes, certificate parsing, and host tests |
| `stub/` | Minimal stubs for hidden Android platform APIs |
| `TrustAttestor-UI/` | Standalone UI preview and synchronization tools |
| `app/src/main/cpp/checker/` | Native detector implementation |

`app/src/main/cpp/external/fmt` is a Git submodule.

## Build

Requirements:

- JDK 17
- Android SDK Platform 35
- Android Build Tools 35.0.0 and 35.0.1
- Android NDK 27.2.12479018
- CMake from the Android SDK

```bash
git clone --recurse-submodules https://github.com/LingQingBigKing/TrustAttestor.git
cd TrustAttestor/android
./gradlew :dex:check
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug
```

On Windows, use `gradlew.bat`. A release build requires your own signing key. Copy `keystore.properties.example` to the ignored `keystore.properties`, fill in the values, and run:

```bash
./gradlew :app:assembleRelease
```

The custom Skidfuscator, LSParanoid, and OLLVM integrations have been removed. Debug and Release use the standard Android Gradle Plugin R8/D8 pipeline and do not read an external obfuscator checkout, so a clean clone has a reproducible build path.

## Cloud attestation

L3 runs only after the user enables it and accepts the disclosure. The client creates a one-time attestation challenge and accepts a verdict only after verifying the server's P-256 signature locally. Protocol details and self-hosting instructions are in the repository's [cloud/](../cloud/) directory.

## Privacy and security

- L0–L2 run locally on the device.
- L3 is optional and sends the certificate chain, signed report, and device metadata required for verification.
- Release builds do not expose full debug evidence.
- Signing keys, Cloudflare secrets, `.dev.vars`, `keystore.properties`, and real device reports must never be committed.
- Please report vulnerabilities through a private GitHub Security Advisory and do not attach secrets or identifiable device data to public issues.

Third-party code and references include AOSP, [KeyAttestation](https://github.com/vvb2060/KeyAttestation), LSPosed components, fmt, and musl. Their own licenses continue to apply.

## License

Project-owned code is released under the [MIT License](../LICENSE). Third-party components remain under their respective licenses.
