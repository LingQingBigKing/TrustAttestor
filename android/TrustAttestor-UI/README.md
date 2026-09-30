# TrustAttestor UI

从 TA 当前工作区提取的独立 Android 界面工程。可以单独在 Android Studio 打开、编译和安装，也可以移动到其他目录或独立仓库维护。Gradle 构建不依赖父目录中的 TA。

首页、关于页、致谢轮播、协议弹窗、动画、自定义拓扑视图、中英文、图标和主题共 **76 个文件**按原样提取。原 TA 的检测代码与构建配置未修改。

## 开始使用

1. 在 Android Studio 中打开**本目录**，而非父级 TA 工程。
2. 使用 JDK 17，安装 Android SDK Platform 35；SDK 路径由 Android Studio 配置，或写入本机 `local.properties`。无需安装 NDK/CMake。
3. 运行 `app`。应用名为 **TA UI Preview**，包名为 `com.lingqing.trustattestor.uipreview`，可与正式 TA 共存。

命令行构建（Windows）：

```powershell
.\gradlew.bat :app:assembleDebug :app:assembleRelease
```

macOS/Linux 使用 `chmod +x gradlew`、`./gradlew`。依赖已缓存时可增加 `--offline`。工程使用 Gradle 8.10.2、AGP 8.7.2、Kotlin 2.0.21，与提取时的主项目版本一致。

输出为 `app/build/outputs/apk/debug/app-debug.apk` 和 `app/build/outputs/apk/release/app-release.apk`。两种构建都使用本机开发签名；`release` 设置 `BuildConfig.DEBUG=false`，用于检查正式版的证据折叠/文案规则，不使用 TA 的生产签名或混淆流程。

## 预览方式

启动后选择一个场景，再进入原 TA 界面。点击首页右上角 **UI Preview 1.0** 返回场景选择。可勾选“预览首次使用协议”，反复检查阅读计时、滚动和确认按钮。

提供 13 个场景：正常、异常、不可用、警告、扫描中定格、完整扫描动画、等待检测、云端通过/异常/警告/不可用/验证中、长文案。证书详情使用三段示例证书文本。

关于页的语言切换、协议弹窗和首页的导出流程保留；吊销列表按钮与云端开关使用本地延时模拟。云端与设备结果都是示例，预览应用不执行设备检测、不请求服务器。应用未声明 INTERNET 权限，也没有 Native 库、检测服务或 App Zygote。关于页的外部链接仍会按点击行为交给浏览器/邮件应用打开。

导出的报告来自模拟状态，其中应用包名和设备信息里的 `UI PREVIEW — SYNTHETIC DATA` 可识别其来源。它仅用于测试展示和导出，不能作为设备检测报告。

## 日常维护位置

| 内容 | 路径（相对本工程） |
| --- | --- |
| 首页与检测卡片、证据、证书详情 | `app/src/main/java/com/lingqing/trustattestor/ui/HomeFragment.kt` |
| 关于页与语言选择 | `app/src/main/java/com/lingqing/trustattestor/ui/AboutFragment.kt` |
| 致谢名单数据与轮播绑定 | `app/src/main/java/com/lingqing/trustattestor/ui/AcknowledgementsAdapter.kt` |
| 致谢头像资源 | `app/src/main/res/drawable-nodpi/` |
| 主页面、导航、首次使用协议门槛 | `app/src/main/java/com/lingqing/trustattestor/MainActivity.kt` |
| 动画、拓扑视图、协议文案 | `app/src/main/java/com/lingqing/trustattestor/ui/` |
| 检测项中英文文案 | `app/src/main/java/com/lingqing/trustattestor/FindingTextCatalog.kt` |
| XML 布局、颜色、主题、图标 | `app/src/main/res/` |
| 通用中英文字符串 | `app/src/main/res/values/strings.xml`、`values-en/strings.xml` |
| 模拟场景与示例证据 | `app/src/preview/java/com/lingqing/trustattestor/preview/PreviewFixtures.kt` |

`src/main` 存放可回同步的界面源文件（Manifest 除外），`src/preview` 存放预览专用适配代码。ViewBinding 类由构建生成，不需要维护。保留原 `namespace` 是为了让 UI 的 `R`、binding 和自定义 View 类名与 TA 一致；实际安装身份由独立的 `applicationId` 决定。

## 将 UI 修改同步回 TA

Python 3.10+，在本工程根目录执行。以下路径请替换为你的 TA `android` 目录。

先查看差异，**默认只读**：

```powershell
python tools/sync_ui.py --target "<path-to-TrustAttestor>/android"
```

确认差异后应用：

```powershell
python tools/sync_ui.py --target "<path-to-TrustAttestor>/android" --apply
```

从 TA 拉回界面修改：

```powershell
python tools/sync_ui.py --target "<path-to-TrustAttestor>/android" --direction pull
python tools/sync_ui.py --target "<path-to-TrustAttestor>/android" --direction pull --apply
```

工具根据 `ui-sync-manifest.json` 的共同基线比较两边内容，仅复制发生变化的白名单文件。若双方对同一文件做了不同修改，会拒绝整批写入并显示差异，需先人工合并；仅接收端修改的文件会保留。每次写入前，接收工程的 `build/ui-sync-backups/` 会保存旧文件、旧基线和恢复记录。写入失败会尝试回滚。

允许回同步：`MainActivity.kt`、`AppLanguage.kt`、`CloudDisclosure.kt`、`FindingTextCatalog.kt`、`ui/**/*.kt` 及 `app/src/main/res/`。在这些目录新建组件/资源也能同步。**删除、重命名需手工处理两边对应文件和基线条目**；工具不会自动删除或恢复缺失文件。

不要删除或重建同步基线来跳过冲突。UI 新增依赖时，两边的 Gradle 依赖需手工同步；资源 ID 重命名还应检查主工程非 UI 文件中的引用。同步后仍需在完整 TA 工程构建，验证与真实检测数据的接入。

## UI 与检测的接口边界

预览 `MainViewModel` 保留当前界面使用的 `uiState: StateFlow<UiState>` 和五个动作：

```kotlin
startIfNeeded(context: Context)
toggleStep(index: Int)
setCloudAttestationEnabled(context: Context, enabled: Boolean)
fetchRevocationList(context: Context)
consumeToast()
```

真实实现仍在 TA 的 `MainViewModel.kt`。界面维护通常只需要编辑 `src/main`，模拟数据和交互行为则编辑 `src/preview`。

`src/preview` 中的 `UiModels.kt`、`FindingModels.kt` 是当前数据结构的快照；`ForensicReportCodec.kt` 是导出/云端报告协议的兼容快照。它们和预览 ViewModel、启动入口、Manifest、Gradle 文件均**不会回同步**。如果更改字段或 UI 回调，应同时人工更新 TA 对应接口。可运行以下检查识别主工程数据契约的变化：

```powershell
python tools/check_contract.py --target "<path-to-TrustAttestor>/android"
```

文案修改应保留 `probeId`、`messageKey` 和状态语义；报告协议的 schema 或字段变化需要在完整项目单独维护。

## 检查

```powershell
python -m unittest discover -s tools -p "test_sync_ui.py"
python tools/test_fixtures.py
```

模拟场景测试直接编译当前 Kotlin 场景与数据模型，无需设备。它读取第一次 Android 构建后缓存的 Kotlin 编译器，使用 `JAVA_HOME` 和 `GRADLE_USER_HOME`；也可显式传入 `--java-home`、`--gradle-home`。

首次交付验证及局限见 [VALIDATION.md](VALIDATION.md)。
