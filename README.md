# TrustAttestor

[English](README_EN.md) · [MIT License](LICENSE)

TrustAttestor 是面向 Android 安全研究、设备自检与风控辅助分析的开源可信度检测项目。客户端和云端验证服务位于同一个仓库的不同目录。

| 目录 | 内容 |
| --- | --- |
| [`android/`](android/README.md) | Android 客户端、Native 检测器、KeyMint/Keystore 探针和 UI 预览 |
| [`cloud/`](cloud/README.md) | Cloudflare Workers 云端证明、吊销/Keybox 规则、设备目录与测试 |

客户端当前版本为 **v1.5**，支持 Android 8.1（API 27）及以上，仅构建 `arm64-v8a`。检测结果是可观察证据的汇总，不代表绝对安全结论；平台不支持或探针不可用不应被当作异常或通过。

## 快速开始

```bash
git clone --recurse-submodules https://github.com/LingQingBigKing/TrustAttestor.git
cd TrustAttestor/android
./gradlew :dex:check
./gradlew :app:assembleDebug
```

Windows 使用 `gradlew.bat`。需要 JDK 17、SDK Platform 35、Build Tools 35.0.0/35.0.1、NDK 27.2.12479018 和 CMake。Release 使用开发者自己的 JKS；详细配置见 [Android 文档](android/README.md)。

云端开发（从仓库根目录执行）：

```bash
cd cloud
corepack enable
pnpm install
pnpm run check
```

部署与协议说明见 [云端文档](cloud/README.md)。部署自建实例必须使用自己的密钥、数据库和域名。

## 构建与隐私

自定义混淆器配置和检测器内的自保护反调试逻辑已经移除。Android 使用标准 R8/D8 工具链；独立反调试示例不包含在本仓库，也不会被客户端编译或加载。

不要提交签名密钥、调试 keystore、`keystore.properties`、`local.properties`、Cloudflare 私钥、`.dev.vars`、真实 Keybox 或设备报告。安全问题请通过 GitHub Security Advisory 私下报告，避免在公开 Issue 中附带敏感材料。

## 许可证

项目自有代码以 [MIT License](LICENSE) 开源。第三方组件继续遵循各自目录或上游项目的许可证。
