# TrustAttestor

[简体中文](README.md) · [Android client](android/README_EN.md) · [Cloud backend](cloud/README_EN.md) · [MIT License](LICENSE) · [Telegram @TrustAttestor](https://t.me/TrustAttestor)

TrustAttestor is an Android device-trust diagnostics project for security research, device self-checks, and risk-analysis support. It keeps hardware attestation, system integrity, runtime environment, and optional cloud verification as separate evidence sources instead of reducing a device to a black-box “safe/unsafe” score.

## Two components

| Directory | Purpose |
| --- | --- |
| [`android/`](android/README_EN.md) | Local scan, Key Attestation, KeyMint/Keystore probes, native checks, and result presentation |
| [`cloud/`](cloud/README_EN.md) | Optional Cloudflare Workers verifier, revocation/Keybox rules, device catalog, and tests |

## Quick start

```bash
git clone --recurse-submodules https://github.com/LingQingBigKing/TrustAttestor.git
cd TrustAttestor/android
./gradlew :dex:check
./gradlew :app:assembleDebug
```

Use `gradlew.bat` on Windows. Android requirements and release signing are documented in the [Android README](android/README_EN.md). Cloud development starts with:

```bash
cd cloud
corepack enable
pnpm install
pnpm run check
```

Read the [Cloud README](cloud/README_EN.md) before deploying an instance with your own Cloudflare account, databases, domain, and Secrets.

## Result semantics

Both local and cloud reports use `CLEAN`, `DETECTED`, `WARNING`, and `UNAVAILABLE`. Only `DETECTED` contributes to the anomaly count. `UNAVAILABLE` means that the platform, permissions, timing, interface, or evidence was insufficient; it is neither a detection nor a pass.

## Privacy and project boundaries

- L0–L2 run locally by default; L3 cloud attestation runs only after explicit user consent.
- The client verifies the cloud P-256 signature locally before accepting a verdict.
- Do not commit JKS files, `keystore.properties`, `local.properties`, Cloudflare Secrets, real Keyboxes, complete device reports, or personal data.
- Keep APK, DEX, CMake/Gradle output, and logs outside the repository. Ignore rules and the `pre-push` guard reject common artifacts.
- The project does not claim to detect every modified environment and does not return an official Google Play Integrity API verdict.

For updates, follow [Telegram @TrustAttestor](https://t.me/TrustAttestor). Please report security issues privately through GitHub Security Advisory.

## License

Project-owned code is released under the [MIT License](LICENSE). Third-party components and submodules retain their own licenses.
