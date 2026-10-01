# TrustAttestor Android

[Project home](../README_EN.md) · [Cloud backend](../cloud/README_EN.md) · [MIT License](../LICENSE) · [Telegram @TrustAttestor](https://t.me/TrustAttestor)

TrustAttestor Android is the local scanning client. It collects evidence from Android Key Attestation, KeyMint/Keystore, system integrity, mount/process state, and controlled native probes. Each check keeps a stable `probeId`, state, evidence, and availability reason.

The current client is **v1.5** (`versionCode 15`), supports Android 8.1 / API 27 and later, and release builds target `arm64-v8a`.

> Results describe evidence observable by this implementation on the current device and system. OEM KeyMint behavior, ROM, kernel, permissions, and load can make probes unavailable. `UNAVAILABLE` is neither an anomaly nor a pass.

## Result states

| State | Meaning |
| --- | --- |
| `CLEAN` | The probe completed and found none of its defined anomaly evidence |
| `DETECTED` | The rule found repeatable, explainable evidence that meets its threshold |
| `WARNING` | A signal needs attention but is not strong enough to classify as an anomaly |
| `UNAVAILABLE` | Unsupported platform, missing permission, timeout, interface failure, or incomplete evidence |

Only `DETECTED` contributes to the anomaly count. A failed or unsupported probe must remain `UNAVAILABLE`.

## Detection areas

### Device environment

The native checker reads system calls, `/proc`, mount information, properties, and controlled child-process behavior:

- bootloader/VBMeta properties, encryption state, debug ramdisk, hidden ext4 loop images, and mount remnants;
- `su`, BusyBox, Shizuku, GameGuardian, ADB-root, KernelSU/APatch driver or UAPI traces, and Zygisk-related mount/process evidence;
- package-directory traversal observation using inotify on the current app's safe installed-APK parent directory, including directory opens/access, named-child noise, queue overflow, and watch loss;
- mount source/target/filesystem, propagation and peer-group relationships, namespace differences, and incFS/vendor-layout compatibility gates;
- property-area consistency, `/proc` access chains/timing, kernel identity (`uname`/`/proc`/Java), process reaping, executable mappings, and runtime injection paths;
- TeeSim/RS-Soter endpoints and service/policy traces, without treating an absent optional service as proof of tampering.

Example IDs include `device.root.kernelsu`, `device.root.kernelsu.throne_hunt`, `system.mount.peer_group`, `system.mount.inconsistent`, `system.readproc.tricky_store`, and `device.kernel.identity_spoofing`.

### System integrity

This layer checks more than well-known root paths:

- APK package/code/resource paths, signing-block structure, mapping inode, native identity, and runtime loader paths;
- SELinux enforcing state, policy views and status channels, `system_server` executable memory, and Magisk/KernelSU/APatch/LSPosed/Xposed/Zygisk policy traces;
- App Zygote and isolated-process service/interface/Binder boundaries, process start/reap behavior, and authorization-chain availability;
- executable anonymous memory, runtime injection, system-server hooks, Sui/superuser services, and LSPosed bridges.

Example IDs include `system.selinux.permissive`, `system.selinux.kernelsu_policy`, `system.app_zygote.process`, `system.app_zygote.sepolicy`, `system.permission.boundary`, and `system.runtime.injection_path`.

### Hardware attestation

The client creates temporary keys for each invocation and cleans them up. It does not inspect user-owned key material:

- X.509 chain, trust anchor, signature graph, validity, leaf constraints, application identity, signing lineage, patch levels, KeyMint/Keymaster version, and security level;
- Root of Trust fields (`deviceLocked`, verified boot state/key, and VBMeta digest) compared with `ro.boot.*` and build properties;
- capability-gated Device Properties differential checks with challenge, ordinary-key control, retry, and repeatability rules;
- AttestKey chain structure and Keystore2 `KEY_ID` descriptor delegation, including incomplete/negative key IDs, delegated signing output, service substitution, and source consistency;
- challenge/authorization boundary probes, StrongBox-vs-TEE differentials, user-auth metadata/policy, and key metadata/security-level checks;
- RSA-PSS/OAEP, AES-GCM/CBC, HMAC, ECDH/ECDSA legal round trips, chunking, AAD/tag integrity, digest/padding constraints, and negative inputs;
- Keystore ledger/state machine, alias isolation, cross-signing, certificate-record round trips, Binder locality, interface tokens, single-use policy, read-path timing, and same-device timing controls;
- repeatable KeyMint/TEE parameter fingerprints, distinguishing actual constraint conflicts from ProviderException, resource contention, or insufficient samples.

Example IDs include `hardware.attestation.device_properties`, `hardware.attestation.root_of_trust_state`, `hardware.attestation.attest_key_descriptor_delegation`, `hardware.attestation.strongbox_differential`, `hardware.attestation.user_auth_policy`, `hardware.attestation.parameter_fingerprint`, `hardware.attestation.teesim_parameter_fingerprint`, `hardware.attestation.keystore_ledger`, and `hardware.attestation.keystore_timing`.

### Optional cloud attestation (L3)

After consent, the client creates a one-time challenge, sends only the data required by the configured service, and verifies the returned P-256 signature locally. The service verifies the chain, challenge, application identity, revocation/Keybox rules, TEE intermediate-CA RDN encoding profiles, device/build consistency, kernel policy, and reviewed observation consensus. Missing data or policy returns `UNAVAILABLE`, not an automatic anomaly. See [`../cloud/README_EN.md`](../cloud/README_EN.md).

## Source layout

```text
android/
├─ app/                         # Android app, UI, JNI, and native checker
│  └─ src/main/cpp/checker/     # Native system, mount, process, and environment probes
├─ dex/                         # Key Attestation, Keystore2, certificate, and host tests
├─ stub/                        # Minimal hidden-platform API stubs
└─ TrustAttestor-UI/            # UI-only preview application
```

`app/src/main/cpp/external/fmt` is a Git submodule. Clone with `--recurse-submodules` or run `git submodule update --init --recursive`.

## Compatibility and build

Requirements: JDK 17, Android SDK Platform 35, Build Tools 35.0.0 (the DEX flow also reads the 35.0.1 `d8.jar`), NDK 27.2.12479018, and SDK CMake. Configure `android/local.properties` with your SDK path:

```properties
sdk.dir=/absolute/path/to/Android/Sdk
```

```bash
./gradlew :dex:check
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug
```

On Windows use `gradlew.bat`. Release builds require your own JKS and ignored `keystore.properties`, copied from `keystore.properties.example`. Keep signing files, APKs, DEX, and logs outside the repository.

The project uses the standard Android Gradle Plugin R8/D8 pipeline. Skidfuscator, LSParanoid, OLLVM, and detector-embedded anti-debug configuration have been removed. The standalone anti-debug example is not part of this client.

## UI preview and privacy

`TrustAttestor-UI` is a standalone UI/text/animation preview. It does not load the native detector, access production services, or perform real device checks; see [`TrustAttestor-UI/README.md`](TrustAttestor-UI/README.md).

L0–L2 run locally. L3 is opt-in. Do not commit signing keys, `.dev.vars`, Cloudflare private keys, real Keyboxes, or identifiable device reports. Report security issues privately through GitHub Security Advisory.

## License

Project-owned code is released under the [MIT License](../LICENSE). AOSP, KeyAttestation, fmt, musl, and other third-party code retain their own licenses.
