# TrustAttestor Cloud

[Project home](../README_EN.md) · [Android client](../android/README_EN.md) · [MIT License](../LICENSE) · [Telegram @TrustAttestor](https://t.me/TrustAttestor)

TrustAttestor Cloud is the optional L3 verifier for the Android client. It runs on Cloudflare Workers, validates the attestation chain, one-time challenge, application identity, and authorized device evidence, then returns a P-256-signed structured verdict.

Self-hosting requires your own Cloudflare account, D1 databases, Durable Object, queues, domain, signing keys, and reviewed data sources. Production private keys, real Keyboxes, reports, and database exports are not part of this repository.

## What the service checks

An `/v1/attest` request is evaluated in these boundaries:

1. A short-lived, single-use challenge is bound to the package, SDK, and ruleset (the current implementation uses a 120-second lifetime).
2. The canonical report and trusted client-signature digest are validated.
3. The Android certificate chain, attestation extension, trust anchor, P-256 requirement, and certificate validity are checked.
4. Package name, same-UID package set, and signing digests are compared with the configured application policy.
5. Root of Trust, Android/TEE versions, patch levels, build fingerprint, build timeline, and kernel evidence are compared across sources.
6. Google revocation data and reviewed leaked-Keybox fingerprints are evaluated; a weak serial-only match is not treated as a high-confidence anomaly.
7. Subject DER RDN order is checked only for recognized TEE intermediate CAs, never for arbitrary CAs, leaves, or roots; multiple reviewed profiles and their reverse order are supported.
8. Device catalog, same-report platform/SoC consistency, kernel risk signatures, Android/kernel compatibility, and reviewed observation consensus are evaluated.
9. Findings are aggregated and signed as `CLEAN`, `DETECTED`, `WARNING`, or `UNAVAILABLE`.

There is no single device-model-to-SoC verdict baseline. `cloud.soc.catalog_consistency` compares SoC/platform fields already present in the same report; missing catalog data does not automatically become an anomaly.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Health, ruleset version, and service metadata |
| `GET` | `/v1/public-key` | Client verification public key |
| `POST` | `/v1/challenges` | Create a one-time challenge |
| `POST` | `/v1/attest` | Verify evidence and return a signed verdict |

Request bodies are limited to 1 MiB. Responses use `no-store` and security headers. Production logs must not contain the request body, certificate chain, or local report.

## Verdict states and ruleset

`CLEAN` means a rule completed without its defined anomaly evidence; `DETECTED` means the rule found qualifying evidence; `WARNING` means evidence is incomplete or lower confidence; and `UNAVAILABLE` means that data, policy, parsing, or service capability was insufficient. Unknown devices and missing policy must remain conservative.

The public ruleset is currently **13**. It includes certificate revocation/validity, Keybox fingerprints, TEE intermediate-CA RDN profiles, application identity, Root of Trust/build/TEE consistency, device catalog, same-report SoC consistency, kernel policy, and reviewed observation consensus.

## Stack and layout

- TypeScript, Cloudflare Workers, and Wrangler
- Durable Objects for challenge lifecycle and single-use consumption
- D1 for Keybox/revocation data, device catalog, and policy
- Queues and Cron Triggers for observation aggregation and maintenance
- Vitest and Python `unittest` for rules, DER parsing, and data generators

```text
cloud/
├─ src/                 # Worker, verification, verdict, and rules
├─ test/                # TypeScript and Python tests
├─ migrations/          # Keybox/revocation D1 migrations
├─ catalog-migrations/  # Device catalog, policy, and observation migrations
├─ scripts/             # Keybox, catalog, candidate, and public-data tools
└─ data/                # Examples or reviewed non-sensitive inputs
```

## Local development

Requirements: Node.js LTS, pnpm 11, and Python 3.10+.

```bash
cd TrustAttestor/cloud
corepack enable
pnpm install
pnpm run check
```

Common commands:

```bash
pnpm run dev
pnpm run typecheck
pnpm run test
pnpm run generate-types
pnpm run deploy:dry-run
```

`pnpm run check` validates Wrangler bindings, TypeScript, Vitest, and the baseline, candidate, domestic-catalog, and public-source aggregation tests.

## Deployment and Secrets

`wrangler.jsonc` declares the Worker, Durable Object, two D1 databases, observation queue/dead-letter queue, and Cron trigger. Create those resources in your account and replace database IDs, domains, package policy, and ruleset variables before deployment.

Set Secrets with Wrangler rather than writing them into configuration. See the [Cloudflare Secrets documentation](https://developers.cloudflare.com/workers/configuration/secrets/).

```bash
wrangler secret put VERDICT_PRIVATE_KEY
wrangler secret put OBSERVATION_NETWORK_KEY
wrangler secret put TRUSTED_SIGNER_DIGESTS
```

- `VERDICT_PRIVATE_KEY`: P-256 key used to sign cloud verdicts.
- `OBSERVATION_NETWORK_KEY`: server key used to irreversibly group observation networks.
- `TRUSTED_SIGNER_DIGESTS`: trusted client release-signature digests.

For local development, use the ignored `.dev.vars` file with non-production values. Review database migrations before applying them; code deployment and D1 changes are separate operations:

```bash
wrangler d1 migrations apply trustattestor-keybox-blacklist --remote
wrangler d1 migrations apply trustattestor-device-catalog --remote
pnpm run deploy:dry-run
pnpm run deploy
```

See the [Cloudflare D1 migrations documentation](https://developers.cloudflare.com/d1/reference/migrations/) for the migration workflow.

## Keybox and catalog data

Keybox tooling reads authorized certificate PEM input and extracts leaf-certificate features; it must never output or copy a Keybox private key. Review source, leaf selection, certificate SHA-256, issuer SPKI, and SQL before import:

```bash
bash scripts/extract-keybox-serials.sh --features path/to/keybox.xml > keybox-features.tsv
pnpm blacklist:update -- --input keybox-features.tsv --source source-label --reason "confirmed leaked keybox" --sql-output review.sql
```

Catalog and observation data require reviewable sources. A single report, unreviewed cluster, or user-space-only field is not a strong anomaly baseline. Real Keyboxes, production SQL, reports, snapshots, and update receipts must not be committed.

## Privacy and security

- Do not log `/v1/attest` request bodies, full certificate chains, or local reports.
- Challenges must be short-lived, single-use, and bound to package, SDK, and ruleset.
- Missing policy or data returns `UNAVAILABLE`; it does not silently allow or reject a device.
- Never commit Cloudflare private keys, `.dev.vars`, real Keyboxes, production exports, or personal data.
- Report security issues privately through GitHub Security Advisory.

## License

Project-owned code is released under the [MIT License](../LICENSE). Cloudflare Workers, Wrangler, and other dependencies retain their own licenses.
