# TrustAttestor Android

[返回项目主页](../README.md) · [Cloud 后端](../cloud/README.md) · [MIT License](../LICENSE) · [Telegram 频道 @TrustAttestor](https://t.me/TrustAttestor)

TrustAttestor Android 是本项目的本地扫描客户端。它不把一次 API 调用当作“真相”，而是对多个独立来源做能力感知的采集、交叉验证和相对对照，并在 UI 中保留检测项的 `probeId`、状态、证据和失败原因。

当前客户端版本为 **v1.5**（`versionCode 15`），最低支持 Android 8.1（API 27），Release 发布构建目标为 `arm64-v8a`。

> 检测结果只描述当前设备、当前系统和当前实现能够观察到的证据。ROM、厂商 KeyMint、内核、权限、系统负载和第三方服务差异都可能使探针不可用。`UNAVAILABLE` 不等于异常，也不等于通过。

## 检测结果

每个检测项使用稳定的 `probeId` 和四种状态：

| 状态 | 含义 |
| --- | --- |
| `CLEAN` | 探针执行完成，当前规则没有发现异常证据 |
| `DETECTED` | 发现满足规则的异常证据；详情中应包含观测值或失败边界 |
| `WARNING` | 有线索需要关注，但证据不足以直接判定异常 |
| `UNAVAILABLE` | 平台不支持、权限不足、超时、接口错误或证据不完整 |

只有 `DETECTED` 计入异常统计。检测失败、接口不支持和不完整证据必须保持为 `UNAVAILABLE`，不能为了让摘要“看起来完成”而升级为异常。

## 四个检测板块

### 1. 设备环境

这一板块由 Native checker 直接读取系统调用、`/proc`、挂载信息、系统属性和受控子进程行为，关注用户态隐藏和运行环境改变：

- **启动与存储状态**：读取 bootloader/VBMeta 属性，检查解锁、AVB 属性缺失、数据分区未加密、debug ramdisk 和隐藏 ext4 loop 镜像等线索。
- **Root 与工具痕迹**：检查 `su`、BusyBox、Shizuku、GameGuardian、ADB root 等已知路径或属性；这些是线索，不单独等价于完整 Root 结论。
- **KernelSU/APatch/ZYGISK**：检查 KernelSU 驱动 FD/UAPI、KSU/APatch 挂载源、`/sys/module/kernelsu` 等路径，以及 Zygisk 隔离/附加行为和相关 mount 残留。
- **包目录遍历观察**：从当前应用自身的已安装 APK `sourceDir` 解析包目录，使用 inotify 观察目录打开、访问、命名子项噪声、watch 丢失和队列溢出。该项只在路径合法且位于受支持的已安装应用根目录时运行；发现符合恢复扫描特征的异常遍历才返回 `DETECTED`，路径不支持或观察失败返回 `UNAVAILABLE`。
- **挂载与 namespace**：比较 mountinfo 的 source/target/filesystem、挂载传播关系、peer group、周边路径和子进程看到的挂载视图；incFS、厂商布局和正常安装目录差异必须先满足兼容条件，不能仅因存在不同挂载类型就判异常。
- **系统属性与 proc 读取**：对 property area/layout、持久化可疑属性、`/proc` 访问链、读取时序和 namespace mismatch 做一致性检查。
- **内核与进程行为**：比较 `uname`、`/proc` 和 Java `os.version` 的内核身份，检查受控 fork/ptrace、进程回收、匿名可执行内存、映射 inode 和运行时注入路径。
- **TEE 模拟与相关服务**：检查 TeeSim/RS Soter 管理协议、控制 socket、策略/SELinux 线索和已知服务端点；缺少服务不能直接作为异常。

相关 `probeId` 示例：`device.bootloader.unlocked`、`device.root.kernelsu`、`device.root.kernelsu.throne_hunt`、`system.mount.peer_group`、`system.mount.inconsistent`、`system.readproc.tricky_store`、`system.readproc.teesim_rs_daemon`、`device.kernel.identity_spoofing`。

### 2. 系统完整性

这一板块检查应用自身及系统强制访问边界，而不是只查几个 Root 文件：

- 校验 APK 的包名、代码/资源路径、安装来源路径和签名块结构，检查应用身份、映射 inode、运行时加载路径和 Native 完整性。
- 检查 SELinux enforcing 状态、策略视图、AV decision/status 通道、`system_server` execmem、AOSP su、Magisk/KernelSU/APatch/LSPosed/Xposed/ZYGISK Next 等策略线索。
- 检查 App Zygote/隔离进程服务、接口 token、Binder/服务边界和进程启动/回收行为；隔离探针的授权链读取失败会明确标记为不可用，不伪装成通过。
- 检查可执行匿名内存、运行时注入路径、系统服务 Hook、Sui/superuser/LSPosed bridge 等环境证据。

相关 `probeId` 示例：`system.selinux.permissive`、`system.selinux.kernelsu_policy`、`system.selinux.teesim_keystore_policy`、`system.app_zygote.process`、`system.app_zygote.sepolicy`、`system.permission.boundary`、`system.runtime.injection_path`、`system.service.system_server_hook`。

### 3. 硬件证明

这一板块通过 Android Keystore/KeyMint 公共 API、Keystore2 Binder 和临时密钥完成硬件能力与证明结构检查。所有密钥都由本次调用生成并在结束时清理，不读取用户已有密钥材料：

- **证书链和 Root of Trust**：解析 X.509 链、Google/OEM 信任锚、签名链、证书有效期、叶证书约束、应用身份、签名 lineage、补丁级别、KeyMint/Keymaster 版本和安全级别。
- **Root of Trust 与系统属性**：比较证书中的 deviceLocked、verifiedBootState、verifiedBootKey、VBMeta digest 等与 `ro.boot.*` / Build 属性；不把“TEE 与系统属性不一致”隐藏成笼统的硬件异常。
- **Device Properties**：在声明能力且满足 SDK 条件时，生成带挑战和普通对照密钥，检查返回的设备属性是否完整、是否可重复；ProviderException、缺少能力或两次失败属于不可用，不能直接当作伪造证据。
- **AttestKey 与 KeyDescriptor**：检查 AttestKey 链结构、KEY_ID 描述符、委派签名密钥、keyId 正负/缺失、服务替代和来源一致性。Keystore2 返回的明确服务错误会保留在证据中。
- **强约束与负向输入**：使用无挑战、超大挑战、空挑战、非法授权组合和单次使用场景，检查 KeyMint 是否拒绝不允许的参数以及拒绝是否可重复。
- **StrongBox 与硬件后端差分**：在设备声明 StrongBox 时比较 TEE/StrongBox 的能力、链和安全级别；不支持 StrongBox 时返回能力不可用，而不是异常。
- **用户认证与元数据**：检查授权列表、用户认证类型/超时、per-use 认证、KeyInfo 安全级别和密钥元数据是否与生成参数一致。
- **算法和操作约束**：对 RSA-PSS/OAEP、AES-GCM/CBC、HMAC、ECDH/ECDSA 等做合法往返、分段输入、AAD/tag 完整性、摘要/填充和共享秘密对照；合法控制样本失败时不升级为硬件异常。
- **Keystore 状态与时序**：检查状态机/账本、别名隔离、交叉签名、证书记录 round-trip、Binder locality、接口 token、单次策略和读取路径。时序项使用同设备重复采样、普通密钥负对照和稳定性约束；样本不足、方向不稳定或超时为 `UNAVAILABLE`。
- **TEE/KeyMint 参数指纹**：比较可重复的参数/能力组合和返回结构，区分真正的约束冲突、ProviderException 与单次资源竞争，避免把正常设备的能力差异判为异常。

相关 `probeId` 示例：`hardware.attestation.device_properties`、`hardware.attestation.root_of_trust_state`、`hardware.attestation.attest_key_descriptor_delegation`、`hardware.attestation.strongbox_differential`、`hardware.attestation.user_auth_policy`、`hardware.attestation.keymint_boundary`、`hardware.attestation.parameter_fingerprint`、`hardware.attestation.teesim_parameter_fingerprint`、`hardware.attestation.keystore_ledger`、`hardware.attestation.keystore_timing`。

### 4. 云端证明（L3，可选）

用户同意并开启后，客户端生成一次性 challenge，将完成证明所需的数据发送到配置的 TrustAttestor Cloud，并在本地验证服务器 P-256 签名。云端会：

- 验证 Android 证明证书链、challenge、应用包名/签名身份和证书有效期。
- 查询 Google 吊销数据以及经审核的泄露 Keybox 特征。
- 只对识别为 TEE 中间 CA 的 Subject 原始 DER `RDNSequence` 检查已审核格式及逆序关系；不会对任意 CA 或叶/根证书套用该规则。
- 检查设备目录、构建/TEE 版本、补丁级别、Root of Trust、内核兼容性和多来源观测共识。
- 在规则、数据源或网络不可用时返回 `UNAVAILABLE`，不默认判异常。

云端规则和请求字段见 [`../cloud/README.md`](../cloud/README.md)。

## 仓库结构

```text
android/
├─ app/                         # Android 应用、UI、JNI 入口和 Native checker
│  └─ src/main/cpp/checker/     # 分拆的系统、挂载、进程和环境检测
├─ dex/                         # Key Attestation、Keystore2、证书与 host 回归测试
├─ stub/                        # 隐藏 Android 平台接口的最小编译桩
└─ TrustAttestor-UI/            # 不执行真实检测的独立 UI 预览工程
```

`app/src/main/cpp/external/fmt` 是 Git submodule。克隆时使用 `--recurse-submodules`，或执行 `git submodule update --init --recursive`。

## 兼容性与构建

需要 JDK 17、Android SDK Platform 35、Build Tools 35.0.0（DEX 流程还会读取 35.0.1 的 `d8.jar`）、NDK 27.2.12479018 和 SDK 提供的 CMake。先在 `android/local.properties` 配置 SDK：

```properties
sdk.dir=/absolute/path/to/Android/Sdk
```

Debug：

```bash
./gradlew :dex:check
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug
```

Windows 使用 `gradlew.bat`。Release 需要自己的 JKS；将 `keystore.properties.example` 复制为被忽略的 `keystore.properties`，填入本机路径和密码后执行 `:app:assembleRelease`。不要把签名文件或 APK 放入仓库。

项目使用 Android Gradle Plugin 自带的标准 R8/D8 流程；Skidfuscator、LSParanoid、OLLVM 和检测器内嵌反调试配置已移除。独立反调试示例不属于此客户端，也不会被编译或加载。

## UI 预览工程

`TrustAttestor-UI` 只用于界面、文案、动画和报告展示，不加载 Native 检测库，不访问生产服务，也不执行真实设备检测。详见 [`TrustAttestor-UI/README.md`](TrustAttestor-UI/README.md)。

## 隐私和贡献规则

- L0–L2 默认在设备本地运行；L3 只有在用户主动启用并接受说明后运行。
- 不上传签名私钥、完整 Keybox 或与证明无关的个人数据。
- 不要提交 `keystore.properties`、`local.properties`、`.dev.vars`、Cloudflare 私钥、真实设备报告和本地构建目录。
- 新检测项必须说明证据来源、误报边界、不可用条件和测试方式；不能用固定跨设备延迟阈值替代同设备对照。
- 安全问题请通过 GitHub Security Advisory 私下报告。

## 许可证

项目自有代码以 [MIT License](../LICENSE) 开源。AOSP、KeyAttestation、fmt、musl 和其他第三方代码继续遵循各自许可证。
