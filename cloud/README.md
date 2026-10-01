# TrustAttestor Cloud

[返回项目主页](../README.md) · [Android 客户端](../android/README.md) · [MIT License](../LICENSE) · [Telegram 频道 @TrustAttestor](https://t.me/TrustAttestor)

TrustAttestor Cloud 是 Android 客户端可选的 L3 证明后端，运行在 Cloudflare Workers 上。它不替代本地检测，而是对客户端提交的证明链、一次性 challenge、应用身份和经授权的设备证据做服务端验证，并返回带 P-256 签名的结构化裁决。

自建实例必须使用自己的 Cloudflare 账号、D1 数据库、Durable Object、Queue、域名、签名密钥和数据来源。公开仓库不包含生产私钥、真实 Keybox、设备报告或数据库导出。

## 具体检查内容

一次 `/v1/attest` 请求会按以下边界执行：

1. **Challenge 绑定**：为包名、SDK 和规则版本签发短期、单次消费 challenge；当前实现的有效期为 120 秒。
2. **客户端签名**：校验 canonical report、challenge 绑定和受信客户端签名摘要。
3. **证书链**：检查 Android Key Attestation 扩展、证书链签名、Google/OEM 信任锚、P-256 要求和证书有效期。
4. **应用身份**：核对证明中的包名、同 UID 包集合和签名摘要是否满足服务器配置的信任集合。
5. **Root of Trust 与版本**：比较 Root of Trust、Android/TEE 版本、补丁级别、Build Fingerprint、构建时间线和内核信息的来源间一致性。
6. **吊销与 Keybox**：检查 Google 吊销数据和经审核的 Keybox 强特征；只命中弱序列号时不直接给出高置信异常。
7. **证书编码序列**：只检查链中非叶、非根且可识别为 TEE 的中间 CA；将 Subject 原始 DER `RDNSequence` 与已审核的多个格式及其逆序进行比较。
8. **设备与内核策略**：检查设备目录、同一报告中的平台/SoC 属性一致性、内核风险特征和 Android/内核兼容性。
9. **结果签名**：将各项 finding 汇总为 `CLEAN`、`DETECTED`、`WARNING` 或 `UNAVAILABLE` 后签名返回。

云端没有“设备型号 → SoC”的单一裁决基线；`cloud.soc.catalog_consistency` 只比较同一报告里已有的 SoC/平台字段，缺少目录或证据不会自动判异常。

## API

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| `GET` | `/` | 健康状态、规则版本和服务元数据 |
| `GET` | `/v1/public-key` | 返回客户端用于验签的云端公钥 |
| `POST` | `/v1/challenges` | 签发一次性 challenge |
| `POST` | `/v1/attest` | 验证证明并返回签名裁决 |

请求体上限为 1 MiB，响应使用 `no-store` 和 `nosniff` 等安全头。请求正文包含证书和设备元数据，生产日志不应记录正文。

## 规则状态

| 状态 | 服务端含义 |
| --- | --- |
| `CLEAN` | 规则完成且没有发现该规则定义的异常 |
| `DETECTED` | 规则完成并发现满足条件的证据 |
| `WARNING` | 有线索但强度或来源不足以给出异常结论 |
| `UNAVAILABLE` | 数据源、策略、解析、网络或服务能力不足 |

当前公开规则集版本为 **13**。规则必须可解释、可复核，并在未知设备、数据缺失或策略未配置时保持保守状态。

## 技术栈与目录

- TypeScript、Cloudflare Workers、Wrangler
- Durable Objects：challenge 生命周期和单次消费
- D1：Keybox/吊销数据、设备目录和策略
- Queues 与 Cron Triggers：观测聚合和维护任务
- Vitest 与 Python `unittest`：规则、DER 解析和数据生成器测试

```text
cloud/
├─ src/                 # Worker、证明验证、裁决和规则
├─ test/                # TypeScript 与 Python 测试
├─ migrations/          # Keybox/吊销 D1 迁移
├─ catalog-migrations/  # 设备目录、策略和观测迁移
├─ scripts/             # Keybox、目录、候选基线和公开数据工具
└─ data/                # 示例或已审核的非敏感输入
```

## 本地开发

需要 Node.js LTS、pnpm 11 和 Python 3.10+：

```bash
cd TrustAttestor/cloud
corepack enable
pnpm install
pnpm run check
```

常用命令：

```bash
pnpm run dev
pnpm run typecheck
pnpm run test
pnpm run generate-types
pnpm run deploy:dry-run
```

`pnpm run check` 会检查 Wrangler bindings、TypeScript、Vitest 以及 baseline、candidate、国内设备目录和公开来源聚合测试。

## 部署与 Secrets

`wrangler.jsonc` 定义 Worker、Durable Object、两个 D1、观测 Queue、死信 Queue 和 Cron。部署前在自己的 Cloudflare 账号创建资源，并替换数据库 ID、域名、应用包名和规则变量。

Cloudflare Secrets 应通过 Wrangler 设置，而不是写入 `wrangler.jsonc` 或 Git。Workers 官方文档也要求使用 CLI 管理 Secrets，而不是把密钥放入配置文件（见 [Cloudflare Secrets 文档](https://developers.cloudflare.com/workers/configuration/secrets/)）。

```bash
wrangler secret put VERDICT_PRIVATE_KEY
wrangler secret put OBSERVATION_NETWORK_KEY
wrangler secret put TRUSTED_SIGNER_DIGESTS
```

- `VERDICT_PRIVATE_KEY`：签署云端裁决的 P-256 私钥。
- `OBSERVATION_NETWORK_KEY`：对观测来源做不可逆分组的服务端密钥。
- `TRUSTED_SIGNER_DIGESTS`：受信客户端发布签名摘要，支持轮换值。

本地开发可使用被 `.gitignore` 排除的 `.dev.vars`，但不得放入生产值。迁移和代码发布应分开审核：

```bash
wrangler d1 migrations apply trustattestor-keybox-blacklist --remote
wrangler d1 migrations apply trustattestor-device-catalog --remote
pnpm run deploy:dry-run
pnpm run deploy
```

D1 migration 文件应按 Cloudflare 的迁移流程审查后应用；代码部署成功不代表数据库迁移已经完成（参见 [D1 migrations 文档](https://developers.cloudflare.com/d1/reference/migrations/)）。

## Keybox 与目录数据

Keybox 工具只读取授权的证书 PEM，提取叶证书特征，不应输出或复制 Keybox 私钥。导入前必须审核来源、叶证书选择、证书 SHA-256、issuer SPKI 和 SQL：

```bash
bash scripts/extract-keybox-serials.sh --features path/to/keybox.xml > keybox-features.tsv
pnpm blacklist:update -- --input keybox-features.tsv --source source-label --reason "confirmed leaked keybox" --sql-output review.sql
```

设备目录、候选基线和观测聚合也必须有可复核来源。单台报告、未审核聚类或仅用户态字段不能直接升级为强异常基线。示例工具：

```bash
pnpm run catalog:sql -- --help
pnpm run baseline:sql -- --help
pnpm run candidate:sql -- --help
pnpm run sources:aggregate -- --help
```

真实 Keybox、生产 SQL、数据库快照、设备报告和更新回执不得提交到仓库。

## 隐私与安全

- 不记录 `/v1/attest` 请求正文、完整证书链或本地报告。
- challenge 必须短期、单次消费，并绑定包名、SDK 和规则版本。
- 数据源、签名策略或解析能力缺失时返回 `UNAVAILABLE`，不默认放行，也不默认判异常。
- 不要提交 Cloudflare 私钥、`.dev.vars`、真实 Keybox、生产数据导出或个人数据。
- 安全问题请通过 GitHub Security Advisory 私下报告。

## 许可证

项目自有代码以 [MIT License](../LICENSE) 开源；Cloudflare Workers、Wrangler 和其他第三方依赖继续遵循各自许可证。
