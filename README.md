# TrustAttestor

[English](README_EN.md) · [Android 客户端](android/README.md) · [Cloud 后端](cloud/README.md) · [MIT License](LICENSE) · [Telegram 频道 @TrustAttestor](https://t.me/TrustAttestor)

TrustAttestor 是一个 Android 设备可信度诊断项目。它将硬件证明、系统完整性、运行环境和可选的云端校验分开采集，并为每个检测项保留状态、证据和限制条件。它不是一个只输出“安全/不安全”的黑盒评分器。

## 两个组成部分

| 目录 | 作用 | 适合阅读 |
| --- | --- | --- |
| [`android/`](android/README.md) | 本地扫描、Key Attestation、KeyMint/Keystore 探针、Native 检测和结果展示 | 客户端构建、检测原理、结果解释 |
| [`cloud/`](cloud/README.md) | 可选的 Cloudflare Workers 证明服务、吊销/Keybox 规则和设备目录 | API、自建部署、规则和数据维护 |

## 快速开始

```bash
git clone --recurse-submodules https://github.com/LingQingBigKing/TrustAttestor.git
cd TrustAttestor/android
./gradlew :dex:check
./gradlew :app:assembleDebug
```

Windows 使用 `gradlew.bat`。Android 的 JDK、SDK、NDK、CMake 和 Release 签名配置见 [Android README](android/README.md)。

云端开发：

```bash
cd cloud
corepack enable
pnpm install
pnpm run check
```

部署自己的 Cloudflare 实例前，请阅读 [Cloud README](cloud/README.md)，使用自己的账号、数据库、域名和 Secrets。

## 检测结果的共同语义

本地和云端报告都使用四种状态：

| 状态 | 含义 |
| --- | --- |
| `CLEAN` | 检测已完成，当前规则未发现异常证据 |
| `DETECTED` | 发现满足规则、可解释且应进一步查看的异常证据 |
| `WARNING` | 有线索需要关注，但证据不足以直接判定异常 |
| `UNAVAILABLE` | 不支持、权限不足、超时、接口失败或证据不完整 |

只有 `DETECTED` 计入异常。`UNAVAILABLE` 不是异常，也不是通过；厂商实现、ROM、内核、系统负载和权限差异都可能使某些探针不可用。

## 隐私、构建和安全

- Android 的 L0–L2 检测默认在本地运行；云端 L3 只有在用户明确同意后才启用。
- 云端请求包含完成证明所需的证书链和设备/构建元数据；客户端在本地验证服务器 P-256 签名。
- 不要提交 JKS、`keystore.properties`、`local.properties`、Cloudflare Secrets、真实 Keybox、完整设备报告或个人数据。
- APK、DEX、CMake/Gradle 输出和日志应保存在仓库外；仓库的 `.gitignore` 与 `pre-push` 检查会拦截常见构建产物。
- 项目不保证发现所有修改环境，也不返回官方 Google Play Integrity API 结论。

## 继续阅读与交流

- [Android 检测项、架构、构建和本地隐私](android/README.md)
- [Cloud API、规则、部署和数据维护](cloud/README.md)
- [Telegram 频道 @TrustAttestor](https://t.me/TrustAttestor)

安全问题请通过 GitHub Security Advisory 私下报告，不要在公开 Issue 或频道中附带私钥、真实 Keybox 或可识别设备数据。

## 许可证

项目自有代码以 [MIT License](LICENSE) 开源。第三方组件、子模块和引用代码继续遵循其各自目录或上游项目的许可证。
