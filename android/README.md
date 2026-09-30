# TrustAttestor

[English](README_EN.md) · [Cloud backend](../cloud/) · [MIT License](../LICENSE)

TrustAttestor 是一款面向 Android 安全研究、设备自检与风控辅助分析的开源设备可信度检测工具。它把 Android Key Attestation、KeyMint/Keystore、系统完整性、运行环境和可选的云端校验组合成可解释的分层报告，而不是只输出一个无法追溯的分数。

当前客户端版本为 **v1.5**（versionCode 15），最低支持 Android 8.1（API 27），仅构建 `arm64-v8a`。

> 检测结果只代表当前实现能够观察到的证据，不能替代专业取证、厂商安全结论或服务端风控策略。ROM 差异、权限限制和系统负载都可能使部分探针不可用。

## 功能概览

TrustAttestor 按 L0–L3 展示检测结果：

| 层级 | 范围 | 示例 |
| --- | --- | --- |
| L0 | 硬件证明 | X.509 证明链、Root of Trust、授权列表、KeyMint/Keystore 行为与状态 |
| L1 | 系统完整性 | APK/Native 身份、SELinux、注入与 Hook 痕迹、映射一致性 |
| L2 | 设备环境 | 隔离进程、运行环境、挂载关系、TEE 模拟和异常包目录遍历行为 |
| L3 | 云端证明（可选） | 证书吊销、泄露 Keybox、证明一致性、设备目录与内核策略 |

主要特性：

- 解析 Android Key Attestation 与 EAT 证明，并展示证书链、授权列表和安全级别。
- 对 Device Properties、AttestKey、StrongBox、用户认证、KeyMint 参数和 Keystore 状态执行能力感知的差分检查。
- 检查 Root of Trust 与系统属性之间的矛盾，区分异常、警告和环境不可用。
- 提供 Native 完整性、Frida/Hook、SELinux、挂载拓扑、隔离进程和 TEE 模拟相关探针。
- 使用同设备相对对照和重复性约束执行 Keystore 时序检查，避免使用跨设备固定延迟阈值。
- 支持中英文界面、结构化证据、JSON 报告导出和独立 UI 预览工程。
- 用户明确开启后，可调用独立的 TrustAttestor Cloud 完成 L3 签名裁决。

## 结果语义

每个检测项都使用稳定的 `probeId` 和四种状态：

| 状态 | 含义 |
| --- | --- |
| `CLEAN` | 当前证据未发现异常 |
| `DETECTED` | 发现满足规则的异常证据 |
| `WARNING` | 发现需要关注、但不足以直接判异常的证据 |
| `UNAVAILABLE` | 平台不支持、权限不足、接口失败或证据不完整 |

只有 `DETECTED` 计入异常。`UNAVAILABLE` 不等同于设备异常，也不能被当作通过。

## 仓库结构

| 路径 | 内容 |
| --- | --- |
| `app/` | Android 应用、Material 界面、JNI 入口和 Native 检测 |
| `dex/` | Key Attestation、KeyMint/Keystore 探针、证书解析和宿主测试 |
| `stub/` | 编译隐藏 Android 平台接口所需的最小桩定义 |
| `TrustAttestor-UI/` | 可独立构建的 UI 预览与同步工具，不执行真实检测 |
| `app/src/main/cpp/checker/` | 拆分后的 Native 检测实现 |

`app/src/main/cpp/external/fmt` 是 Git submodule。克隆时请初始化子模块。

## 构建环境

- JDK 17
- Android SDK Platform 35
- Android Build Tools 35.0.0（DEX 工具链还会读取 35.0.1 的 `d8.jar`）
- Android NDK 27.2.12479018
- CMake（由 Android SDK 安装）

```bash
git clone --recurse-submodules https://github.com/LingQingBigKing/TrustAttestor.git
cd TrustAttestor/android
```

用 Android Studio 打开项目，或在本机 `local.properties` 中配置 SDK：

```properties
sdk.dir=/absolute/path/to/Android/Sdk
```

Windows：

```powershell
.\gradlew.bat :dex:check
.\gradlew.bat :app:testDebugUnitTest
.\gradlew.bat :app:assembleDebug
```

macOS / Linux：

```bash
./gradlew :dex:check
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug
```

Release 构建需要自己的 JKS。复制 `keystore.properties.example` 为 `keystore.properties` 并填写本机值；该文件已被 Git 忽略：

```properties
androidStoreFile=/absolute/path/to/release-signing.jks
androidStorePassword=...
androidKeyAlias=...
androidKeyPassword=...
```

然后执行：

```powershell
.\gradlew.bat :app:assembleRelease
```

### 编译与字节码处理

项目已移除 Skidfuscator、LSParanoid 和 OLLVM 等自定义混淆配置。Debug 与 Release 均使用 Android Gradle Plugin 自带的标准 R8/D8 流程，不读取开发者工作站上的外部混淆器目录；这使得干净克隆可以复现构建。

## 云端证明

客户端默认配置的公开接口为 `https://api.lingqing.ltd`。L3 仅在用户主动启用并确认数据说明后运行。客户端会生成一次性挑战证明，并在本地验证云端 P-256 签名后才接受裁决。

后端源码、协议和自建说明见仓库内的 [cloud/](../cloud/) 目录。自建后端时可通过 Gradle 属性替换接口和验证公钥：

```properties
trustAttestorCloudUrl=https://your-worker.example
trustAttestorCloudVerdictPublicKey=<base64-spki>
```

## UI 预览工程

`TrustAttestor-UI` 不声明网络权限，不加载 Native 检测库，也不会访问生产服务。它用于在 Android Studio 中独立开发界面、文案、动画和报告展示。同步方法和边界见其目录内的 `README.md`。

## 隐私与安全

- L0–L2 在设备本地运行。
- L3 是可选功能；提交内容限于完成证明所需的证书链、签名报告和设备元数据。
- Release 不返回或展示完整调试证据。
- 仓库不应包含签名密钥、Cloudflare 私钥、`.dev.vars`、`keystore.properties` 或真实设备报告。
- 如发现安全问题，请优先通过 GitHub Security Advisory 私下报告，避免在公开 Issue 中附带密钥、证书私钥或可识别设备的数据。

## 参与开发

提交修改前请至少运行与变更相关的单元测试和 Gradle 检查。检测规则应保持保守、可复现并提供可解释证据；平台不支持和瞬态失败应返回 `UNAVAILABLE`，不得直接升级为异常。

项目包含或参考 AOSP、[KeyAttestation](https://github.com/vvb2060/KeyAttestation)、LSPosed 组件、fmt 与 musl。第三方代码继续遵循各自目录或上游项目的许可证。

## 许可证

项目自有代码以 [MIT License](../LICENSE) 开源。第三方组件不因本许可证而改变其原有许可。
