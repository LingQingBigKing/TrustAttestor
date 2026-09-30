package com.lingqing.trustattestor

import android.content.Context

/**
 * The only owner of user-facing Finding copy.
 *
 * Native findings contain stable probe IDs, state, severity and structured
 * parameters only. Locale changes therefore never depend on native wording.
 */
object FindingTextCatalog {
    private data class Copy(val zh: String, val en: String)

    private fun isEnglish(context: Context): Boolean =
        context.resources.configuration.locales[0].language.equals("en", true)

    fun localize(context: Context, finding: NativeFinding): NativeFinding {
        val key = finding.messageKey.ifBlank { finding.probeId }
        val copy = copies[key] ?: unavailableCopy(key) ?: cloudCopy(key, finding.status)
        val english = isEnglish(context)
        val serverTitle = if (english) finding.serverTitleEn else finding.serverTitleZh
        val serverEvidence = if (english) finding.serverEvidenceEn else finding.serverEvidenceZh
        val title = when {
            finding.layer == MainViewModel.CLOUD_LAYER && serverTitle.isNotBlank() -> serverTitle
            copy != null -> if (english) copy.en else copy.zh
            finding.status == FindingStatus.CLEAN -> cleanSummary(finding.layer, english)
            finding.status == FindingStatus.UNAVAILABLE -> if (english) {
                "This probe is unavailable on the current device"
            } else {
                "当前设备无法完成此项检测"
            }
            finding.title.isNotBlank() && !key.startsWith("native.") -> finding.title
            else -> if (english) "Unrecognized native anomaly" else "检测到未识别的原生异常"
        }
        val evidence = if (BuildConfig.DEBUG) {
            serverEvidence.ifBlank { finding.evidence }
        } else {
            ""
        }
        return finding.copy(title = title, evidence = evidence, messageKey = key)
    }

    fun layerTitle(context: Context, layer: Int): String {
        val en = isEnglish(context)
        return when (layer) {
            0 -> if (en) "Device environment" else "设备环境"
            1 -> if (en) "System integrity" else "系统完整性"
            2 -> if (en) "Hardware attestation" else "硬件证明"
            3 -> if (en) "Cloud attestation" else "云端证明"
            else -> if (en) "Integrity check" else "完整性检测"
        }
    }

    fun cleanSummary(context: Context, layer: Int): String =
        cleanSummary(layer, isEnglish(context))

    fun eventText(context: Context, code: String): String {
        val en = isEnglish(context)
        val copy = eventCopies[code]
        if (copy != null) return if (en) copy.en else copy.zh
        if (code.startsWith("progress.hardware.probe.")) {
            return if (en) "Running hardware anti-forgery probes…" else "正在运行硬件抗伪造探针…"
        }
        return when {
            code.startsWith("error.") -> if (en) {
                "The scan could not complete normally"
            } else {
                "检测流程未能正常完成"
            }
            code.startsWith("progress.") -> if (en) "Running integrity checks…" else "正在执行完整性检测…"
            else -> code
        }
    }

    private fun cleanSummary(layer: Int, en: Boolean): String = when (layer) {
        0 -> if (en) "No device environment anomaly found" else "设备环境检测暂未发现异常"
        1 -> if (en) "No system integrity anomaly found" else "系统完整性检测暂未发现异常"
        2 -> if (en) "No hardware attestation anomaly found" else "硬件证明检测暂未发现异常"
        3 -> if (en) "No cloud attestation anomaly found" else "云端检测暂未发现异常"
        else -> if (en) "No anomaly found" else "检测暂未发现异常"
    }

    private fun unavailableCopy(key: String): Copy? {
        if (!key.endsWith(".unavailable")) return null
        val baseKey = key.removeSuffix(".unavailable")
        unavailableProbeNames[baseKey]?.let { name ->
            return Copy("${name.zh}未完成", "${name.en} did not complete")
        }
        val base = copies[baseKey] ?: return null
        // A base title often describes the abnormal outcome (for example, "policy bypass").
        // Lead with the unavailable state so a failed probe cannot read like a confirmed finding.
        return Copy(
            "检测未完成（对应项目：${base.zh}）",
            "Check did not complete (probe: ${base.en})"
        )
    }

    private val unavailableProbeNames: Map<String, Copy> = mapOf(
        "hardware.attestation.attest_key_descriptor_delegation" to Copy(
            "AttestKey KeyDescriptor 直接委派检测",
            "Direct AttestKey KeyDescriptor delegation check"
        ),
        "hardware.attestation.cross_sign" to Copy("AttestKey 交叉签名检测", "AttestKey cross-sign check"),
        "hardware.attestation.certificate_graph" to Copy("AttestKey 证书图谱检测", "AttestKey certificate-graph check"),
        "hardware.attestation.trap_probe" to Copy("Attestation 陷阱探针", "Attestation trap probe"),
        "hardware.attestation.keystore_state_machine" to Copy("Keystore 状态机检测", "Keystore state-machine check"),
        "hardware.attestation.alias_cross_talk" to Copy("密钥别名串扰检测", "Key alias cross-talk check"),
        "hardware.attestation.challenge_replay" to Copy("Challenge 重放检测", "Challenge replay check"),
        "hardware.attestation.null_challenge" to Copy("空 Challenge 负向检测", "Null-challenge negative check"),
        "hardware.attestation.negative_probe" to Copy("AttestKey 负向探针", "AttestKey negative probe"),
        "hardware.attestation.leaf_constraints" to Copy("叶子证书约束检测", "Leaf-certificate constraint check"),
        "hardware.attestation.application_id" to Copy("AttestationApplicationId 检测", "AttestationApplicationId check"),
        "hardware.attestation.key_metadata" to Copy("KeyMetadata 授权一致性检测", "KeyMetadata authorization check"),
        "hardware.attestation.imported_key" to Copy("导入密钥证明检测", "Imported-key attestation check"),
        "hardware.attestation.patch_level" to Copy("硬件证明补丁级别检测", "Attested patch-level check"),
        "hardware.attestation.user_auth_policy" to Copy("用户认证策略检测", "User-authentication policy check"),
        "hardware.attestation.single_use_policy" to Copy("单次使用密钥策略检测", "Single-use key policy check"),
        "hardware.attestation.future_validity_policy" to Copy("密钥未来生效策略检测", "Future-validity key policy check"),
        "hardware.attestation.unique_id_permission" to Copy("Unique-ID 证明权限检测", "Unique-ID attestation permission check"),
        "hardware.attestation.user_auth_metadata" to Copy("用户认证授权列表检测", "User-authentication metadata check"),
        "hardware.attestation.signing_lineage" to Copy("AttestationApplicationId 签名链检测", "AttestationApplicationId signing-lineage check"),
        "hardware.attestation.operation_semantics" to Copy("KeyMint 操作授权语义检测", "KeyMint operation-semantic check"),
        "hardware.attestation.device_properties" to Copy("硬件 Device Properties 检测", "Hardware Device Properties check"),
        "hardware.attestation.algorithm_differential" to Copy("RSA / EC Attestation 差分检测", "RSA / EC Attestation differential check"),
        "hardware.attestation.strongbox_differential" to Copy("StrongBox 证明差分检测", "StrongBox attestation differential check"),
        "hardware.attestation.keymint_boundary" to Copy("KeyMint 功能约束检测", "KeyMint boundary check"),
        "hardware.attestation.rsa_conformance" to Copy("RSA 约束检测", "RSA conformance check"),
        "hardware.attestation.hmac_conformance" to Copy("HMAC 结果检测", "HMAC conformance check"),
        "hardware.attestation.ecdh_conformance" to Copy("ECDH 协商检测", "ECDH conformance check"),
        "hardware.attestation.aes_conformance" to Copy("AES 约束检测", "AES conformance check"),
        "hardware.attestation.entry_semantics" to Copy("Keystore 条目语义检测", "Keystore entry-semantic check"),
        "hardware.attestation.main_binding" to Copy("主证明请求绑定检测", "Primary-attestation binding check"),
        "hardware.attestation.operation_isolation" to Copy("密码运算隔离检测", "Cryptographic-operation isolation check")
    )

    private fun MutableMap<String, Copy>.finding(id: String, zh: String, en: String) {
        put(id, Copy(zh, en))
    }

    private val copies: Map<String, Copy> = buildMap {
        finding("layer.0.summary", "设备环境检测暂未发现异常", "No device environment anomaly found")
        finding("layer.1.summary", "系统完整性检测暂未发现异常", "No system integrity anomaly found")
        finding("layer.2.summary", "硬件证明检测暂未发现异常", "No hardware attestation anomaly found")
        finding("hardware.attestation.unavailable", "硬件证明服务不可用", "Hardware attestation service unavailable")

        finding("device.environment.abnormal", "设备环境状态异常", "Abnormal device environment state")
        finding("device.environment.surrounding_suspicious", "设备周边运行环境可疑", "Suspicious surrounding runtime environment")
        finding("device.bootloader.unlocked", "Bootloader 处于解锁状态", "Bootloader is unlocked")
        finding("device.root.zygisk_mount", "检测到 Zygisk 或 /adb/modules 挂载痕迹", "Zygisk or /adb/modules mount trace detected")
        finding("device.root.su", "检测到 su 或 root shell 痕迹", "su or root shell trace detected")
        finding("device.rom.third_party", "检测到第三方 ROM 或 sepolicy 痕迹", "Third-party ROM or sepolicy trace detected")
        finding("device.adb.trace", "检测到 ADB 调试痕迹", "ADB debugging trace detected")
        finding("device.vbmeta.property", "vbmeta 系统属性异常", "Abnormal vbmeta system properties")
        finding("device.encryption.data_unencrypted", "数据分区未加密", "Data partition is not encrypted")
        finding("device.tool.busybox", "检测到 BusyBox 痕迹", "BusyBox trace detected")
        finding("device.tool.shizuku", "检测到 Shizuku 痕迹", "Shizuku trace detected")
        finding("device.tool.gameguardian", "检测到 GameGuardian 痕迹", "GameGuardian trace detected")
        finding("device.root.kernelsu", "检测到 KernelSU 痕迹", "KernelSU trace detected")
        finding("device.root.kernelsu.throne_hunt", "检测到 KernelSU 包目录追踪行为", "KernelSU package-directory throne hunt detected")
        finding("device.root.kernelsu.throne_hunt.unavailable", "KernelSU 包目录追踪检测未完成", "KernelSU package-directory throne-hunt check did not complete")
        finding("device.root.kernelsu.uapi", "检测到 KernelSU 内核 UAPI", "KernelSU kernel UAPI detected")
        finding("device.root.kernelsu.late_load", "检测到 KernelSU late-load 越狱模式", "KernelSU late-load jailbreak mode detected")
        finding("device.property.persistent_suspicious", "检测到可疑持久化系统属性", "Suspicious persistent system property detected")
        finding("device.proc.access_timing", "/proc 访问时序异常", "Abnormal /proc access timing")
        finding("device.proc.access_chain", "procfs 时间戳或进程访问链路异常", "Abnormal procfs timestamp or process access path")
        finding("device.mount.residue", "检测到可疑挂载残留", "Suspicious mount residue detected")
        finding("device.mount.debug_ramdisk", "debug_ramdisk 挂载异常", "Abnormal debug_ramdisk mount")
        finding("device.odex.inline_parameter", "检测到可疑 odex 内联参数", "Suspicious odex inline parameter detected")
        finding("device.zygisk.hiding_timing", "Zygisk 隐藏或进程访问时序异常", "Zygisk hiding or process access timing anomaly")
        finding("device.path.existence_hiding", "检测到路径存在性隐藏痕迹", "Path existence hiding trace detected")
        finding("device.kernel.identity_spoofing", "检测到内核信息伪装", "Kernel information spoofing detected")
        finding("device.zygisk.detected", "检测到 Zygisk", "Zygisk detected")
        finding("device.mount.hidden_ext4_loop", "检测到隐藏的 ext4 loop 镜像", "Hidden ext4 loop image detected")

        finding("system.readproc.mount_trace", "检测到全局挂载痕迹", "Global mount trace detected")
        finding("system.readproc.namespace_mismatch", "挂载命名空间视图不匹配", "Mount namespace view mismatch")
        finding("system.readproc.zygisk_next_daemon", "检测到 ZygiskNext 守护进程", "ZygiskNext daemon detected")
        finding("system.readproc.lsposed_daemon", "检测到 LSPosed 守护进程", "LSPosed daemon detected")
        finding("system.readproc.tricky_store", "检测到 TrickyStore 进程特征", "TrickyStore process signature detected")
        finding("system.readproc.teesim_rs_daemon", "检测到 TEESimulator-RS 守护进程", "TEESimulator-RS daemon detected")
        finding("system.readproc.teesim_rs_hook", "检测到 TEESimulator-RS Hook 特征", "TEESimulator-RS hook signature detected")
        finding("system.permission.boundary", "权限边界行为异常", "Abnormal permission-boundary behavior")
        finding("system.mount.inconsistent", "挂载状态不一致", "Inconsistent mount state")
        finding("system.property.area", "系统属性区域布局异常", "Abnormal system property area layout")
        finding("system.property.value", "检测到系统属性值篡改痕迹", "System property value tampering trace detected")
        finding("system.memory.mapping_inode", "内存映射与 inode 身份不一致", "Memory mapping and inode identity mismatch")
        finding("system.memory.executable_anonymous", "检测到可执行匿名内存映射", "Executable anonymous memory mapping detected")
        finding("system.runtime.injection_path", "检测到 NativeBridge、注入或运行链路篡改", "NativeBridge, injection, or runtime path tampering detected")
        finding("system.service.system_server_hook", "检测到 system_server Hook 痕迹", "system_server hook trace detected")
        finding("system.service.lsposed_bridge", "LSPosed 或 LSBridge 服务链路异常", "Abnormal LSPosed or LSBridge service path")
        finding("system.service.sui", "Sui 服务链路异常", "Abnormal Sui service path")
        finding("system.service.superuser", "SuperUser 服务链路异常", "Abnormal SuperUser service path")
        finding("system.teesim.admin_protocol", "检测到 TEESimulator 协议服务", "TEESimulator protocol service detected")
        finding("system.teesim.control_socket", "检测到 TEESimulator 控制 Socket", "TEESimulator control socket detected")
        finding("system.teesim.rs_soter_protocol", "检测到 TEESimulator-RS SOTER 伪造协议", "TEESimulator-RS SOTER forgery protocol detected")
        finding("system.selinux.permissive", "SELinux 处于 Permissive 模式", "SELinux is in permissive mode")
        finding("system.selinux.system_server_execmem", "检测到 system_server execmem 策略规则", "system_server execmem policy rule detected")
        finding("system.selinux.aosp_su_transition", "user 构建中存在 AOSP su 域转换规则", "AOSP su domain transition exists in a user build")
        finding("system.selinux.adb_root_domain", "检测到 adb_root SELinux 域", "adb_root SELinux domain detected")
        finding("system.selinux.magisk_policy", "检测到 Magisk SELinux 策略特征", "Magisk SELinux policy signature detected")
        finding("system.selinux.kernelsu_policy", "检测到 KernelSU SELinux 策略特征", "KernelSU SELinux policy signature detected")
        finding("system.selinux.lsposed_policy", "检测到 LSPosed SELinux 策略特征", "LSPosed SELinux policy signature detected")
        finding("system.selinux.xposed_policy", "检测到 Xposed SELinux 策略特征", "Xposed SELinux policy signature detected")
        finding("system.selinux.zygisk_next_policy", "检测到 ZygiskNext SELinux 策略特征", "ZygiskNext SELinux policy signature detected")
        finding("system.selinux.status_not_enforcing", "SELinux 状态通道显示未强制执行", "SELinux status channel reports non-enforcing mode")
        finding("system.selinux.deny_unknown_disabled", "SELinux deny_unknown 已关闭", "SELinux deny_unknown is disabled")
        finding("system.selinux.policy_load_count", "SELinux 策略加载计数异常", "Abnormal SELinux policy load count")
        finding("system.selinux.av_decision_sequence", "SELinux AV 决策序列异常", "Abnormal SELinux AV decision sequence")
        finding("system.selinux.apatch_policy", "检测到 APatch SELinux 策略特征", "APatch SELinux policy signature detected")
        finding("system.selinux.userspace_query", "SELinux 用户态查询通道结果不一致", "Inconsistent SELinux userspace query results")
        finding("system.selinux.access_oracle", "SELinux 权限查询违反系统策略不变量", "SELinux access query violates system policy invariants")
        finding("system.selinux.status_channel", "SELinux 状态多通道结果不一致", "Inconsistent SELinux status across channels")
        finding("system.selinux.policy_view", "SELinux 原始策略与 context 查询结果不一致", "Raw SELinux policy and context query results disagree")
        finding("system.selinux.teesim_keystore_policy", "检测到 TEESimulator-RS SELinux 策略特征", "TEESimulator-RS SELinux policy signature detected")
        finding("system.mount.peer_group", "挂载链路或 peer group 异常", "Abnormal mount path or peer group")
        finding("system.mount.surrounding_path", "mount id 或周边挂载链路可疑", "Suspicious mount ID or surrounding mount path")

        finding("hardware.attestation.main_chain_service_substitution", "主证书链服务被替换", "Main certificate-chain service substitution")
        finding("hardware.attestation.attest_key_service_substitution", "AttestKey 证书链服务被替换", "AttestKey chain service substitution")
        finding("hardware.attestation.attest_key_chain_unavailable", "AttestKey 证书链不可用", "AttestKey certificate chain unavailable")
        finding("hardware.attestation.main_chain_structure", "主证书链结构异常", "Main certificate-chain structure anomaly")
        finding("hardware.attestation.attest_key_chain_structure", "AttestKey 证书链结构异常", "AttestKey certificate chain structure anomaly")
        finding("hardware.attestation.keybox_subject", "命中 Keybox 证书主题特征", "Keybox certificate subject detected")
        finding("hardware.attestation.root_of_trust_missing", "RootOfTrust 记录缺失", "RootOfTrust record missing")
        finding("hardware.attestation.vbmeta_digest", "VBMeta 摘要不匹配", "VBMeta digest mismatch")
        finding("hardware.attestation.verified_boot_state", "Verified Boot 状态不匹配", "Verified Boot state mismatch")
        finding("hardware.attestation.key_info_hardware_backing", "KeyInfo 未由安全硬件支持", "KeyInfo is not hardware-backed")
        finding("hardware.attestation.key_info_validation", "KeyInfo 验证异常", "KeyInfo validation error")
        finding("hardware.attestation.embedded_attest_key_substitution", "内嵌 AttestKey 被替换", "Embedded AttestKey substitution")
        finding("hardware.attestation.oversized_challenge", "异常超长 Challenge 被接受", "Oversized challenge was accepted")
        finding(
            "hardware.attestation.attest_key_descriptor_delegation",
            "AttestKey KeyDescriptor 直接委派异常",
            "Direct AttestKey KeyDescriptor delegation anomaly"
        )
        finding("hardware.attestation.cross_sign", "AttestKey 交叉签名不匹配", "AttestKey cross-sign mismatch")
        finding("hardware.attestation.certificate_graph", "AttestKey 证书图谱异常", "AttestKey certificate graph anomaly")
        finding("hardware.attestation.trap_probe", "命中 Attestation 陷阱探针", "Attestation trap probe hit")
        finding("hardware.attestation.keystore_state_machine", "Keystore 状态机异常", "Keystore state-machine anomaly")
        finding("hardware.attestation.alias_cross_talk", "密钥别名出现串扰", "Key alias cross-talk anomaly")
        finding("hardware.attestation.challenge_replay", "Challenge 重放行为异常", "Challenge replay anomaly")
        finding("hardware.attestation.null_challenge", "空 Challenge 被接受", "Null challenge was accepted")
        finding("hardware.attestation.negative_probe", "AttestKey 负向探针被绕过", "AttestKey negative probe bypass")
        finding("hardware.attestation.leaf_constraints", "叶子证书约束异常", "Leaf certificate constraints anomaly")
        finding("hardware.attestation.application_id", "AttestationApplicationId 不匹配", "AttestationApplicationId mismatch")
        finding("hardware.attestation.keystore_timing", "Keystore 时序分布异常", "Keystore timing distribution anomaly")
        finding("hardware.attestation.keystore_timing.unavailable", "Keystore 时序侧信道检测未完成", "Keystore timing side-channel check did not complete")
        finding("hardware.attestation.key_metadata", "KeyMetadata 安全级别或授权信息异常", "KeyMetadata security-level or authorization anomaly")
        finding("hardware.attestation.imported_key", "导入密钥异常获得硬件证明", "Imported key unexpectedly became attested")
        finding("hardware.attestation.patch_level", "硬件证明补丁级别相互矛盾", "Attested patch levels contradict each other")
        finding("hardware.attestation.user_auth_policy", "用户认证策略被绕过", "User authentication policy bypass")
        finding("hardware.attestation.single_use_policy", "单次使用密钥策略被绕过", "Single-use key policy bypass")
        finding("hardware.attestation.future_validity_policy", "密钥未来生效策略被绕过", "Future-validity key policy bypass")
        finding("hardware.attestation.runtime", "Key Attestation 运行时异常", "Key Attestation runtime error")
        finding("hardware.attestation.unique_id_permission", "Unique-ID 证明权限被绕过", "Unique-ID attestation permission bypass")
        finding("hardware.attestation.user_auth_metadata", "用户认证授权列表异常", "User-authentication authorization list anomaly")
        finding("hardware.attestation.signing_lineage", "AttestationApplicationId 签名链异常", "AttestationApplicationId signing-lineage anomaly")
        finding("hardware.attestation.operation_semantics", "KeyMint 操作授权语义异常", "KeyMint operation authorization semantic anomaly")
        finding("hardware.attestation.rsa_conformance", "RSA 签名或解密约束异常", "RSA signature or decryption conformance anomaly")
        finding("hardware.attestation.hmac_conformance", "HMAC 消息认证结果异常", "HMAC result mismatch")
        finding("hardware.attestation.ecdh_conformance", "ECDH 密钥协商结果异常", "ECDH shared-secret mismatch")
        finding("hardware.attestation.aes_conformance", "AES 运算或参数约束异常", "AES operation or parameter conformance anomaly")
        finding("hardware.attestation.entry_semantics", "Keystore 条目类型或替换状态异常", "Keystore entry type or replacement anomaly")
        finding("hardware.attestation.main_binding", "主证明与本次密钥请求不一致", "Primary attestation does not bind to this key request")
        finding("hardware.attestation.operation_isolation", "密码运算对象或消息隔离异常", "Cryptographic operation or message isolation anomaly")
        finding("hardware.attestation.isolated_chain", "隔离进程返回的证明链不一致", "Attestation chain differs in the isolated process")
        finding("hardware.attestation.chain_read_stability", "同一密钥的完整证明链读取结果不一致", "Full attestation chain differs across reads of the same key")
        finding("hardware.attestation.certificate_round_trip", "原证书链回写后密钥记录不一致", "Key record changed after reinstalling its original certificate chain")
        finding("hardware.attestation.binder_locality", "Keystore 返回了当前进程的本地 Binder 对象", "Keystore returned a Binder object local to this process")
        finding("hardware.attestation.interface_token_dispatch", "错误接口令牌被分发到 Keystore maintenance 事务", "A wrong interface token was dispatched to a Keystore maintenance transaction")
        finding("hardware.attestation.parameter_fingerprint", "KeyMint 参数错误画像命中软件转发特征", "KeyMint parameter-error profile matches software forwarding")
        finding("hardware.attestation.teesim_parameter_fingerprint", "TeeSim 参数不变量被违反", "TeeSim parameter invariant was violated")
        finding("hardware.attestation.reply_lag", "证明密钥在生成调用返回前持续提前可见", "Attested keys became persistently visible before generation returned")
        finding("hardware.attestation.read_path_timing", "证明密钥原始读取路径出现稳定额外延迟", "Attested-key raw reads show stable additional latency")
        finding("hardware.attestation.key_id_consistency", "APP 与 KEY_ID 两条读取路径返回不一致记录", "APP and KEY_ID read paths returned inconsistent key records")
        finding("hardware.attestation.keystore_ledger", "Keystore 删除与条目计数状态不一致", "Keystore deletion and entry-ledger state are inconsistent")
        finding("hardware.attestation.chain_read_stability.unavailable", "完整证明链一致性检测未完成", "Full-chain consistency check did not complete")
        finding("hardware.attestation.certificate_round_trip.unavailable", "原证书链回写一致性检测未完成", "Certificate round-trip consistency check did not complete")
        finding("hardware.attestation.isolated_chain.api_unavailable", "隔离证明链检测需要 Android 16 公开共享接口", "Isolated chain check requires the Android 16 public sharing API")
        finding("hardware.attestation.isolated_chain.access_unavailable", "系统无法完成隔离进程的授权证明链读取", "System could not complete the isolated process's granted chain read")
        finding("hardware.attestation.isolated_chain.transport_unavailable", "隔离证明链检测通信或等待未完成", "Isolated chain communication or wait did not complete")
        finding("hardware.attestation.isolated_chain.evidence_unavailable", "隔离证明链对照数据不完整或发生变化", "Isolated chain comparison data was incomplete or changed")
        finding("hardware.attestation.isolated_chain.cleanup_incomplete", "隔离证明链检测资源清理未完成", "Isolated chain check resource cleanup did not complete")
        finding("hardware.attestation.isolated_chain.not_run", "隔离证明链检测未执行完成", "Isolated chain check did not run to completion")
        finding("hardware.attestation.metadata_security_level.unavailable", "KeyMetadata securityLevel 范围检测未完成", "KeyMetadata securityLevel range check did not complete")
        finding("hardware.attestation.binder_locality.unavailable", "Keystore Binder 本地性检测未完成", "Keystore Binder-locality check did not complete")
        finding("hardware.attestation.interface_token_dispatch.unavailable", "错误接口令牌分发检测未完成", "Wrong-interface-token dispatch check did not complete")
        finding("hardware.attestation.parameter_fingerprint.unavailable", "KeyMint 参数指纹检测未完成", "KeyMint parameter-fingerprint check did not complete")
        finding("hardware.attestation.teesim_parameter_fingerprint.unavailable", "TeeSim 参数指纹检测未完成", "TeeSim parameter-fingerprint check did not complete")
        finding("hardware.attestation.reply_lag.unavailable", "证明回复时差检测未完成", "Attestation reply-lag check did not complete")
        finding("hardware.attestation.read_path_timing.unavailable", "原始读取路径时序检测未完成", "Raw read-path timing check did not complete")
        finding("hardware.attestation.key_id_consistency.unavailable", "KEY_ID 跨路径一致性检测未完成", "KEY_ID cross-path consistency check did not complete")
        finding("hardware.attestation.keystore_ledger.unavailable", "Keystore 状态账本检测未完成", "Keystore state-ledger check did not complete")
        finding("hardware.attestation.probe_status.unavailable", "硬件证明探针状态读取失败", "Hardware-attestation probe status could not be read")

        finding("hardware.attestation.device_properties", "硬件 Device Properties 与 Build.* 不一致", "Hardware Device Properties disagree with Build.*")
        finding("hardware.attestation.algorithm_differential", "RSA / EC Attestation 画像不一致", "RSA and EC Attestation profiles disagree")
        finding("hardware.attestation.strongbox_differential", "StrongBox 证明安全级别异常", "Abnormal StrongBox attestation security level")
        finding("hardware.attestation.keymint_boundary", "KeyMint 功能约束未被 Attestation 回显", "KeyMint feature constraints missing from Attestation")
        finding("hardware.attestation.certificate_validity", "Attestation 证书链有效期异常", "Attestation certificate validity anomaly")
        finding("hardware.attestation.build_fingerprint", "Build Fingerprint 与系统属性不一致", "Build fingerprint disagrees with system properties")
        finding("hardware.attestation.unknown", "未知硬件证明异常", "Unknown hardware attestation anomaly")
        finding("hardware.attestation.key_tampered", "Attestation 密钥疑似被篡改", "Attestation key appears to be tampered")
        finding("hardware.attestation.flow_incomplete", "硬件证明流程未完成", "Hardware attestation flow did not complete")
        finding("hardware.attestation.aosp_test_key", "检测到 AOSP 测试密钥", "AOSP test key detected")
        finding("hardware.attestation.unknown_key_source", "检测到未知来源的 Attestation 密钥", "Unknown Attestation key source detected")
        finding("hardware.attestation.vbmeta_hash", "硬件证明中的 vbmeta 哈希不一致", "Attested vbmeta hash mismatch")
        finding("hardware.attestation.root_of_trust_state", "RootOfTrust 与系统状态不一致", "RootOfTrust disagrees with system state")
        finding("hardware.attestation.result_anomaly", "硬件证明结果异常", "Hardware attestation result anomaly")

        finding("runtime.system_properties.init", "系统属性探针不可用", "System property probe unavailable")
        finding("runtime.soinfo.page_chain", "soinfo 页面链路探针不可用", "soinfo page-chain probe unavailable")
        finding("runtime.soinfo.traversal", "soinfo 遍历未完整执行", "soinfo traversal did not complete")
        finding("runtime.native_bridge.symbol", "NativeBridgeError 符号探针不可用", "NativeBridgeError symbol probe unavailable")
        finding("runtime.android_runtime.entry_symbol", "AndroidRuntime 入口符号探针不可用", "AndroidRuntime entry-symbol probe unavailable")
        finding("runtime.android_runtime.instance", "AndroidRuntime 实例探针不可用", "AndroidRuntime instance probe unavailable")
        finding("runtime.java_vm.arguments", "JavaVM 启动参数探针不可用", "JavaVM startup-argument probe unavailable")
        finding("system.property.area_layout", "系统属性区域布局无法校准", "System property area layout could not be calibrated")
        finding("system.mount.probe.pipe", "挂载信息探针管道不可用", "Mount-information probe pipe unavailable")
        finding("system.mount.probe.fork", "挂载信息探针进程不可用", "Mount-information probe unavailable")
        finding("system.mount.probe.timeout", "挂载信息探针响应超时", "Mount-information probe timed out")
        finding("system.mount.probe.reap", "挂载信息探针进程回收超时", "Mount-information probe cleanup timed out")
        finding("system.mount.probe.buffer", "挂载信息缓冲区无法读取", "Mount-information buffer could not be read")
        finding("hardware.attestation.verification", "硬件证明校验过程不可用", "Hardware attestation verification unavailable")
        finding("device.apatch.page_fault", "APatch 页面故障探针不可用", "APatch page-fault probe unavailable")
        finding("system.app_zygote.service", "AppZygote 隔离服务不可用", "AppZygote isolated service unavailable")
        finding("system.app_zygote.interface", "AppZygote 隔离服务接口不可用", "AppZygote isolated-service interface unavailable")
        finding("system.app_zygote.call", "AppZygote 隔离进程调用失败", "AppZygote isolated-process call failed")
        finding("system.app_zygote.incomplete", "AppZygote 检测未完整执行", "AppZygote scan did not complete")
        finding("system.app_zygote.process", "AppZygote 隔离进程探针不可用", "AppZygote isolated-process probe unavailable")
        finding("system.app_zygote.sepolicy", "AppZygote SELinux 策略探针不可用", "AppZygote SELinux policy probe unavailable")
        finding("device.timing.transaction_fork", "事务速率探针不可用", "Transaction-rate probe unavailable")
        finding("device.process_access.reap", "进程访问探针回收超时", "Process-access probe cleanup timed out")
    }

    private val cloudCopies = mapOf(
        "cloud.keybox.serial_blacklist" to Copy("命中已收录的 Keybox 泄露名单", "Known leaked Keybox serial detected"),
        "cloud.device.hardware_matrix" to Copy("设备指纹与厂商元数据不匹配", "Device fingerprint and vendor metadata mismatch"),
        "cloud.device.soc_matrix" to Copy("SoC 标识与设备型号不匹配", "SoC identity and device model mismatch"),
        "cloud.soc.catalog_consistency" to Copy("SoC 标识与平台规范不一致", "SoC identity and platform specification mismatch"),
        "cloud.device.catalog_consistency" to Copy("设备型号与厂商目录不一致", "Device model and vendor catalog mismatch"),
        "cloud.attestation.google_revocation" to Copy("证书已被 Google 吊销", "Certificate has been revoked by Google"),
        "cloud.attestation.subject_rdn_order" to Copy("证书编码序列异常", "Certificate encoding order anomaly"),
        "cloud.kernel.android_compatibility" to Copy("内核版本与 Android 版本不兼容", "Kernel version is incompatible with the Android version"),
        "cloud.kernel.risk_signatures" to Copy("内核构建信息命中风险特征", "Kernel build metadata matches a risk signature"),
        "cloud.observation.consensus" to Copy("设备观测数据缺少可信共识", "Device observations lack trusted consensus"),
        "cloud.attestation.verdict" to Copy("云端证明裁决异常", "Cloud attestation verdict anomaly"),
        "cloud.attestation.aggregate" to Copy("云端综合风险评估异常", "Cloud aggregate risk assessment anomaly"),
        "cloud.attestation.transport" to Copy("云端证明不可用", "Cloud attestation unavailable")
    )

    private val cloudCleanCopies = mapOf(
        "cloud.keybox.serial_blacklist" to Copy("未命中已收录 Keybox 泄露名单", "No match in the recorded leaked Keybox list"),
        "cloud.device.hardware_matrix" to Copy("设备指纹与厂商元数据匹配", "Device fingerprint matches vendor metadata"),
        "cloud.device.catalog_consistency" to Copy("设备指纹与厂商元数据匹配", "Device fingerprint matches vendor metadata"),
        "cloud.device.soc_matrix" to Copy("SoC 标识与平台规范校验通过", "SoC identity and platform specification verified"),
        "cloud.soc.catalog_consistency" to Copy("SoC 标识与平台规范校验通过", "SoC identity and platform specification verified"),
        "cloud.attestation.google_revocation" to Copy("证书未被 Google 吊销", "Certificate is not revoked by Google"),
        "cloud.kernel.android_compatibility" to Copy("内核版本与 Android 版本兼容", "Kernel version is compatible with the Android version"),
        "cloud.kernel.risk_signatures" to Copy("内核构建信息未命中风险特征", "Kernel build metadata does not match a risk signature"),
        "cloud.observation.consensus" to Copy("设备观测数据一致", "Device observations are consistent"),
        "cloud.attestation.verdict" to Copy("云端证明校验通过", "Cloud attestation verified"),
        "cloud.attestation.aggregate" to Copy("云端综合风险评估通过", "Cloud aggregate risk assessment passed")
    )

    private fun cloudCopy(key: String, status: FindingStatus): Copy? =
        if (status == FindingStatus.CLEAN) cloudCleanCopies[key] ?: cloudCopies[key] else cloudCopies[key]

    private val eventCopies = mapOf(
        "step.init" to Copy("初始化检测环境", "Initialize scan environment"),
        "step.device" to Copy("设备环境", "Device environment"),
        "step.system" to Copy("系统完整性", "System integrity"),
        "step.hardware" to Copy("硬件证明", "Hardware attestation"),
        "progress.init.prepare" to Copy("正在准备运行环境…", "Preparing runtime environment…"),
        "progress.init.services" to Copy("正在初始化系统服务探针…", "Initializing system service probes…"),
        "progress.init.components" to Copy("正在加载检测组件…", "Loading scan components…"),
        "progress.init.ready" to Copy("基础检测环境已就绪", "Base scan environment is ready"),
        "progress.device.mount_namespace" to Copy("正在检查挂载命名空间…", "Checking mount namespaces…"),
        "progress.device.process_access" to Copy("正在检查进程访问边界…", "Checking process access boundaries…"),
        "progress.device.kernel_patch" to Copy("正在检查内核补丁框架…", "Checking kernel patch frameworks…"),
        "progress.device.environment" to Copy("正在检查设备环境…", "Checking the device environment…"),
        "progress.device.complete" to Copy("设备环境检测完成", "Device environment scan complete"),
        "progress.system.zygote" to Copy("正在检查隔离进程与 Zygote…", "Checking isolated processes and Zygote…"),
        "progress.system.collect" to Copy("正在汇总系统完整性信号…", "Collecting system integrity signals…"),
        "progress.system.teesim" to Copy("正在检查 TEE 模拟器协议…", "Checking TEE simulator protocols…"),
        "progress.system.complete" to Copy("系统完整性检测完成", "System integrity scan complete"),
        "progress.hardware.connect_keystore" to Copy("正在连接 Android Keystore…", "Connecting to Android Keystore…"),
        "progress.hardware.chain_integrity" to Copy("正在检查证明链路完整性…", "Checking attestation-chain integrity…"),
        "progress.hardware.generate_attest_key" to Copy("正在生成硬件 AttestKey…", "Generating hardware AttestKey…"),
        "progress.hardware.generate_attestation_key" to Copy("正在生成硬件证明密钥…", "Generating hardware attestation key…"),
        "progress.hardware.generate_business_key" to Copy("正在生成业务证明密钥…", "Generating attested business key…"),
        "progress.hardware.read_chain" to Copy("正在读取硬件证书链…", "Reading hardware certificate chain…"),
        "progress.hardware.parse_root_of_trust" to Copy("正在解析证书链与 RootOfTrust…", "Parsing certificate chain and RootOfTrust…"),
        "progress.hardware.active_probes" to Copy("正在运行主动抗伪造探针…", "Running active anti-forgery probes…"),
        "progress.hardware.probe.isolated_chain" to Copy("正在核对隔离进程的证明链…", "Comparing the isolated process attestation chain…"),
        "progress.hardware.probe.certificate_record" to Copy("正在核对完整证明链与证书回写一致性…", "Checking full-chain reads and certificate round-trip consistency…"),
        "progress.hardware.probe.metadata_security_level" to Copy("正在核对 KeyMetadata 安全级别枚举…", "Checking KeyMetadata security-level values…"),
        "progress.hardware.probe.attest_key_descriptor_delegation" to Copy(
            "正在核对 AttestKey KeyDescriptor 直接委派…",
            "Checking direct AttestKey KeyDescriptor delegation…"
        ),
        "progress.hardware.probe.binder_locality" to Copy("正在核对 Keystore Binder 本地性…", "Checking Keystore Binder locality…"),
        "progress.hardware.probe.reply_lag" to Copy("正在测量密钥可见与生成回复时差…", "Measuring key visibility against generation replies…"),
        "progress.hardware.probe.read_path_timing" to Copy("正在校准原始密钥读取路径时序…", "Calibrating raw key-read timing…"),
        "progress.hardware.probe.interface_token_dispatch" to Copy("正在检查错误接口令牌分发…", "Checking wrong-interface-token dispatch…"),
        "progress.hardware.probe.parameter_fingerprint" to Copy("正在检查 KeyMint 参数指纹…", "Checking the KeyMint parameter fingerprint…"),
        "progress.hardware.probe.teesim_parameter_fingerprint" to Copy("正在检查 TeeSim 参数不变量…", "Checking TeeSim parameter invariants…"),
        "progress.hardware.probe.key_id_consistency" to Copy("正在核对 APP 与 KEY_ID 读取路径…", "Comparing APP and KEY_ID read paths…"),
        "progress.hardware.probe.keystore_ledger" to Copy("正在核对 Keystore 状态账本…", "Checking the Keystore state ledger…"),
        "progress.hardware.boundary" to Copy("正在执行硬件证明边界对照…", "Running hardware attestation boundary checks…"),
        "progress.hardware.summarize" to Copy("正在汇总硬件证明结果…", "Summarizing hardware attestation results…"),
        "progress.hardware.complete" to Copy("硬件证明校验完成", "Hardware attestation complete"),
        "scan.finished" to Copy("检测已完成", "Scan complete"),
        "error.runtime.integrity" to Copy("运行时完整性校验失败", "Runtime integrity verification failed"),
        "error.init.dependencies" to Copy("检测依赖初始化失败", "Failed to initialize scan dependencies"),
        "error.init.native" to Copy("原生检测组件初始化失败", "Failed to initialize native scan components"),
        "error.step.execution" to Copy("检测项执行失败", "A scan step failed to execute"),
        "error.hardware.execution" to Copy("硬件证明执行失败", "Hardware attestation execution failed"),
        "error.hardware.unavailable" to Copy("当前设备无法完成硬件证明", "Hardware attestation is unavailable on this device"),
        "error.result.finalize" to Copy("检测结果汇总失败", "Failed to finalize scan results")
    )
}
