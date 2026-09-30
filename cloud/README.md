# TrustAttestor Cloud

[Android client](../android/) · [MIT License](../LICENSE)

TrustAttestor Cloud 是 TrustAttestor 的 L3 云端证明后端。它运行于 Cloudflare Workers，验证 Android 硬件证明、一次性挑战和客户端签名，查询 D1 中的吊销/Keybox/设备策略数据，并返回由 P-256 密钥签名的结构化裁决。

生产接口、数据库 ID 和发布签名摘要属于部署方配置，不写入公开源码；当前规则集版本为 **13**。公开源码不包含生产私钥、真实设备报告或发布证书摘要。

> 本仓库提供可审计的验证逻辑与自建基础设施配置。部署自己的实例时必须使用自己的密钥、数据库和域名；不要把生产 Secrets 写入 Git、日志或 Issue。

## 验证流程

一次完整请求经过以下步骤：

1. 为指定应用签发两分钟有效、只能消费一次的 Durable Object challenge。
2. 使用证明叶证书验证 canonical report 签名，并校验 challenge 绑定。
3. 验证完整 Android Key Attestation 证书链及证明 challenge。
4. 解析 KeyMint/Keymaster、AuthorizationList、Root of Trust 和应用身份。
5. 执行吊销、Keybox、证书编码、设备/构建/内核一致性等独立规则。
6. 汇总为 `CLEAN`、`DETECTED`、`WARNING` 或 `UNAVAILABLE`，并签名返回裁决及中英文展示数据。

服务端返回结果仍需由 Android 客户端使用内置公钥验签。数据库或可选规则不可用不会伪装成异常。

## Ruleset 13

主要规则包括：

- `cloud.attestation.google_revocation`：对已验证链中的证书检查 Google Android Attestation 吊销状态。
- `cloud.keybox.serial_blacklist`：使用证书 SHA-256 或 SerialNumber + Issuer SPKI 等强身份匹配泄露 Keybox；仅序列号命中只产生警告。
- `cloud.attestation.subject_rdn_order`：只检查非叶、非根且标识为 TEE 的 CA，匹配已审核 Subject RDN 模板的完整逆序，不把任意排列直接判异常。
- `cloud.attestation.application_identity`：检查证明中的应用包名、版本和签名身份。
- `cloud.attestation.certificate_validity`：检查证明链证书有效期与证明类型约束。
- `cloud.device.catalog_consistency`：核对签名报告中的 `Build.DEVICE` / `Build.MODEL` 与设备目录。
- `cloud.soc.catalog_consistency`：对 `ro.soc.model`、`ro.hardware`、board platform 与厂商信息做来源间一致性检查。
- `cloud.tee.*` / `cloud.build.*`：比较 TEE 与用户态版本、补丁等级、Root of Trust、指纹和构建时间线。
- `cloud.device.hardware_matrix`：只使用已审核并发布的设备变体基线；未知设备不会被推断为异常。
- `cloud.kernel.risk_signatures` / `cloud.kernel.android_compatibility`：应用可更新的内核风险规则和保守的 Android/内核兼容检查。
- `cloud.observation.consensus`：在满足来源数量与网络多样性门槛后，为已审核观测提供共识辅助。

这里没有“设备型号 → SoC”的裁决基线。历史 `device_soc_baselines` 只为迁移和导入兼容保留，不参与设备判定；`cloud.soc.catalog_consistency` 只检查同一报告中多个 SoC/平台属性是否互相一致。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/` | 健康状态与当前规则元数据 |
| `GET` | `/v1/public-key` | 裁决验签公钥 |
| `POST` | `/v1/challenges` | 签发一次性 challenge |
| `POST` | `/v1/attest` | 验证证明并返回签名裁决 |

请求体上限为 1 MiB，响应设置 `no-store`。生产环境不应记录请求正文，因为证明中包含证书和设备元数据。

## 技术栈与目录

- TypeScript、Cloudflare Workers、Wrangler
- Durable Objects：一次性 challenge
- D1：Keybox/吊销数据与设备目录、策略和观测聚合
- Queues：可信观测的异步聚合
- Cron Triggers：维护任务
- Vitest 与 Python `unittest`：规则、DER 解析和数据生成器测试

| 路径 | 内容 |
| --- | --- |
| `src/` | Worker、证明验证、裁决和规则实现 |
| `test/` | TypeScript 与 Python 测试 |
| `migrations/` | Keybox/吊销 D1 迁移 |
| `catalog-migrations/` | 设备目录、策略和观测 D1 迁移 |
| `scripts/` | Keybox、目录、候选基线与公开数据处理工具 |
| `data/` | 仅提交示例或已审核的非敏感输入；真实导出默认被忽略 |

## 本地开发

需要 Node.js LTS、pnpm 11 和 Python 3.10+。

```bash
git clone --recurse-submodules https://github.com/LingQingBigKing/TrustAttestor.git
cd TrustAttestor/cloud
corepack enable
pnpm install
pnpm run check
pnpm run deploy:dry-run
```

常用命令：

```bash
pnpm run dev
pnpm run typecheck
pnpm run test
pnpm run generate-types
```

`pnpm run check` 会检查 Wrangler bindings、TypeScript、Vitest 和所有 Python 数据生成器测试。

## Cloudflare 配置

`wrangler.jsonc` 声明两个 D1 数据库、一个 Durable Object、观测队列、死信队列和定时任务。部署前在自己的 Cloudflare 账号中创建对应资源并替换数据库 ID、域名与公开配置。

必须通过 Wrangler Secret 配置：

```bash
wrangler secret put VERDICT_PRIVATE_KEY
wrangler secret put OBSERVATION_NETWORK_KEY
wrangler secret put TRUSTED_SIGNER_DIGESTS
```

- `VERDICT_PRIVATE_KEY`：签署云端裁决的 P-256 私钥。
- `OBSERVATION_NETWORK_KEY`：对网络来源做不可逆分组的服务端密钥。
- `TRUSTED_SIGNER_DIGESTS`：受信客户端发布签名摘要；多个轮换状态用 `;` 分隔，同一状态的并行签名用 `,` 分隔。

将 `wrangler.jsonc` 中的数据库 ID、域名和应用包名替换为自己的部署值后再发布。缺少或格式错误的签名摘要会让应用来源检测返回 `UNAVAILABLE`，不会默认放行。

本地开发可使用被 `.gitignore` 排除的 `.dev.vars`。不要提交任何真实值。

首次部署或数据库结构更新时，先审核再应用迁移：

```bash
wrangler d1 migrations apply trustattestor-keybox-blacklist --remote
wrangler d1 migrations apply trustattestor-device-catalog --remote
pnpm run deploy:dry-run
pnpm run deploy
```

代码部署与生产 D1 数据变更是独立操作；自动部署不能替代迁移审查。

## Keybox 黑名单维护

提取工具只读取证书 PEM，不输出或复制 Keybox 私钥。推荐先生成特征并审核 SQL：

```bash
bash scripts/extract-keybox-serials.sh --features path/to/keybox.xml > keybox-features.tsv
pnpm blacklist:update -- --input keybox-features.tsv --source source-label --reason "confirmed leaked keybox" --sql-output review.sql
```

确认来源、叶证书选择和强指纹后再由维护者应用。不要把真实 Keybox、私钥、生产 SQL 导出或更新回执提交到仓库。

## 设备目录与观测数据

目录和候选数据必须携带可复核来源。单台报告、仅用户态属性或未审核聚类不能直接升级为强异常基线。相关工具包括：

```bash
pnpm run catalog:sql -- --help
pnpm run baseline:sql -- --help
pnpm run candidate:sql -- --help
pnpm run sources:aggregate -- --help
```

示例输入保存在 `data/*.example.*`；实际数据库快照、CSV/TSV/JSON 导出和生成 SQL 默认被忽略。

## 安全与隐私

- 不记录 `/v1/attest` 请求正文、完整证书链或本地报告。
- challenge 必须短期、单次消费并绑定包名、SDK 与规则版本。
- Release 请求只返回裁决所需的有限信息；详细证据仅用于通过证明验证的 Debug 请求。
- 新规则应优先失败为 `UNAVAILABLE` 或 `WARNING`，只有可重复、可解释且经过审核的证据才能返回 `DETECTED`。
- 安全问题请使用 GitHub Security Advisory 私下报告，不要在公开 Issue 中发布私钥、Keybox 或真实设备报告。

## 许可证

项目以 [MIT License](../LICENSE) 开源。
