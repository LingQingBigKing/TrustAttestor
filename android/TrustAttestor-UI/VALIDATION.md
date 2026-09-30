# 提取验证

日期：2026-09-12。来源为 TA 当时的本地工作区，包含此前的 UI 和文案修改，不是 Git HEAD 的旧版快照。

## 已完成

- 独立 `:app:assembleDebug :app:assembleRelease --offline` 成功；Release 构建附带的 `lintVitalRelease` 通过。
- 源码 ZIP 解压到新目录后，未复制 `local.properties`，仅指定本机 SDK/JDK 和依赖缓存，再次独立执行 `:app:assembleRelease --offline` 成功（58 秒）。
- 13 个模拟场景的 **403 项 Kotlin 断言通过**：状态与异常计数、不可用不计异常、进度范围、证书示例、云端开始/结束、动画过程中保留展开和关于页状态。
- 同步工具 **20 项测试通过**：默认只读、push/pull、冲突整批拒写、新文件、目标单改保护、备份/基线、失败回滚和路径检查。
- 对真实 TA 执行只读同步检查，结果为 `No changes`；未执行同步写入。
- 三组兼容快照与主项目一致：UI 数据模型、finding 数据/解析模型、报告序列化协议。
- Release APK 签名校验通过，签名为 Android Debug；安装包名 `com.lingqing.trustattestor.uipreview`，启动入口为场景选择页。
- APK 未包含 `.so`，Manifest 未请求 INTERNET 权限，也未注册原检测服务。

已核对完整 TA 的 2,092 个原源码与配置文件，其 SHA-256 在本次提取前后保持一致；61 个共享 UI/资源文件与原文件逐字节一致。同步工具只在你显式使用 `--apply` 时写入所指定工程。

## 验证边界

- 尚未进行模拟器或实机 UI 操作、截图核验；安装后仍需检查不同屏幕、字体大小、系统版本和语言下的布局。
- 额外执行 `lintDebug` 时，离线缓存缺少 AndroidTest 配置中的 `kotlin-stdlib-jdk8:1.8.20`、`androidx.collection:collection:1.1.0` 等依赖，未完成全量 Lint。联网后可运行 `./gradlew :app:lintDebug`；未为绕过检查而修改 Lint 规则。
- 预览 Release 复现 `BuildConfig.DEBUG=false` 的显示规则，但没有生产混淆、签名校验或真实检测引擎；UI 合回 TA 后仍需构建和检查正式应用。
- UI 数据模型与报告协议是快照。主项目协议改变后，先运行 `tools/check_contract.py`，再人工更新预览兼容层。
