# TrustAttestor

[简体中文](README.md) · [MIT License](LICENSE)

TrustAttestor is an open-source Android trust diagnostics project for security research, device self-checks, and risk-analysis support. The client and cloud verifier share one repository:

| Directory | Contents |
| --- | --- |
| [`android/`](android/README_EN.md) | Android client, native detector, KeyMint/Keystore probes, and UI preview |
| [`cloud/`](cloud/README.md) | Cloudflare Workers attestation, revocation/Keybox rules, catalog, and tests |

The client is **v1.5**, supports Android 8.1 / API 27 and later, and targets `arm64-v8a`. Results summarize observable evidence, not an absolute security guarantee. An unavailable probe is neither a detection nor a pass.

```bash
git clone --recurse-submodules https://github.com/LingQingBigKing/TrustAttestor.git
cd TrustAttestor/android
./gradlew :dex:check
./gradlew :app:assembleDebug
```

Use `gradlew.bat` on Windows. See the [Android documentation](android/README_EN.md) for requirements and release signing. See the [cloud documentation](cloud/README.md) for development, deployment, and protocol details.

Custom obfuscator integrations and detector self-protection anti-debug code have been removed. Android uses standard R8/D8. The independent anti-debug sample is not part of this repository or the client build.

Signing keys, local SDK settings, Cloudflare secrets, actual Keyboxes, and real device reports must not be committed. Please report vulnerabilities privately through GitHub Security Advisory.

Project-owned code is released under the [MIT License](LICENSE). Third-party components remain under their respective licenses.
