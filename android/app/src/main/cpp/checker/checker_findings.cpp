#include <algorithm>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

#include "checker_internal.h"
#include "logging.h"

// Detection-result normalization only. Native code emits stable identifiers,
// status, severity and machine-readable parameters. User-facing copy belongs
// exclusively to FindingTextCatalog on the Kotlin side.

namespace {

struct FindingRule {
    uint64_t mask;
    const char* probeId;
};

void AddFinding(std::vector<NativeFinding>& findings, NativeFinding finding) {
    const auto duplicate = std::find_if(findings.begin(), findings.end(), [&](const auto& item) {
        return item.probeId == finding.probeId && item.status == finding.status;
    });
    if (duplicate == findings.end()) findings.emplace_back(std::move(finding));
}

std::string MaskData(uint64_t mask) {
    return fmt::format("{{\"mask\":\"0x{:x}\"}}", mask);
}

void AddDetected(
        std::vector<NativeFinding>& findings,
        int layer,
        FindingSeverity severity,
        std::string_view probe_id,
        std::string data_json = "{}") {
    AddFinding(findings, {std::string(probe_id), layer, FindingStatus::Detected,
                          severity, std::move(data_json)});
}

void AddWarning(
        std::vector<NativeFinding>& findings,
        int layer,
        FindingSeverity severity,
        std::string_view probe_id,
        std::string data_json = "{}") {
    AddFinding(findings, {std::string(probe_id), layer, FindingStatus::Warning,
                          severity, std::move(data_json)});
}

std::string EscapeJsonString(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size() + 2);
    for (const unsigned char ch : value) {
        switch (ch) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (ch < 0x20) escaped += fmt::format("\\u{:04x}", ch);
                else escaped.push_back(static_cast<char>(ch));
        }
    }
    return escaped;
}

std::string UnavailableData(const UnavailableProbe& probe) {
    if (probe.stage.empty() && probe.detail.empty() && probe.metrics.empty() &&
        probe.errorNumber == 0) {
        return "{}";
    }

    std::string data = "{";
    bool needs_comma = false;
    const auto add_string = [&](std::string_view name, std::string_view value) {
        if (value.empty()) return;
        if (needs_comma) data += ',';
        data += fmt::format("\"{}\":\"{}\"", name, EscapeJsonString(value));
        needs_comma = true;
    };
    add_string("stage", probe.stage);
    if (needs_comma) data += ',';
    data += fmt::format("\"errno\":{}", probe.errorNumber);
    needs_comma = true;
    add_string("detail", probe.detail);
    if (!probe.metrics.empty()) {
        if (needs_comma) data += ',';
        data += "\"counts\":{";
        for (size_t i = 0; i < probe.metrics.size(); ++i) {
            if (i != 0) data += ',';
            data += fmt::format("\"{}\":{}",
                                EscapeJsonString(probe.metrics[i].name),
                                probe.metrics[i].value);
        }
        data += '}';
    }
    data += '}';
    return data;
}

void AddRules(
        std::vector<NativeFinding>& findings,
        int layer,
        FindingSeverity severity,
        uint64_t value,
        std::initializer_list<FindingRule> rules) {
    for (const auto& rule : rules) {
        if ((value & rule.mask) != 0) {
            AddDetected(findings, layer, severity, rule.probeId, MaskData(rule.mask));
        }
    }
}

void AddUnavailable(std::vector<NativeFinding>& findings, int layer) {
    for (const auto& probe : sUnavailableProbes) {
        if (probe.layer != layer) continue;
        AddFinding(findings, {probe.probeId, layer, FindingStatus::Unavailable,
                              FindingSeverity::Info, UnavailableData(probe)});
    }
}

std::vector<NativeFinding> BuildDeviceFindings(
        const RiskSnapshot& before,
        const RiskSnapshot& after) {
    constexpr int layer = 0;
    constexpr FindingSeverity severity = FindingSeverity::High;
    std::vector<NativeFinding> findings;
    const uint32_t conventional = after.conventionalTests & ~before.conventionalTests;
    const uint32_t hidden = after.futileHide & ~before.futileHide;
    const uint32_t kernelsu = after.kernelSuProbe & ~before.kernelSuProbe;

    if (after.abnormalEnvironment && !before.abnormalEnvironment) {
        AddDetected(findings, layer, severity, "device.environment.abnormal");
    }
    if (after.surroundingSuspicious && !before.surroundingSuspicious) {
        AddDetected(findings, layer, severity, "device.environment.surrounding_suspicious");
    }
    AddRules(findings, layer, severity, conventional, {
            {1u << 0, "device.bootloader.unlocked"},
            {1u << 1, "device.root.zygisk_mount"},
            {1u << 2, "device.root.su"},
            {1u << 4, "device.rom.third_party"},
            {1u << 5, "device.adb.trace"},
            {1u << 6, "device.vbmeta.property"},
            {1u << 7, "device.encryption.data_unencrypted"},
            {1u << 8, "device.tool.busybox"},
            {1u << 9, "device.tool.shizuku"},
            {1u << 10, "device.tool.gameguardian"},
            {1u << 11, "device.root.kernelsu"},
            {1u << 12, "device.property.persistent_suspicious"},
    });
    if ((kernelsu & kernelsu_probe::kDetectedMask) != 0) {
        AddDetected(findings, layer, severity, "device.root.kernelsu.uapi",
                    fmt::format("{{\"version\":{},\"flags\":\"0x{:x}\",\"uapiVersion\":{},\"probeMask\":\"0x{:x}\"}}",
                                after.kernelSuVersion, after.kernelSuFlags,
                                after.kernelSuUapiVersion, after.kernelSuProbe));
        if ((after.kernelSuFlags & (1u << 2)) != 0) {
            AddDetected(findings, layer, severity, "device.root.kernelsu.late_load",
                        fmt::format("{{\"version\":{},\"flags\":\"0x{:x}\"}}",
                                    after.kernelSuVersion, after.kernelSuFlags));
        }
    }
    if (after.throneHuntDetected && !before.throneHuntDetected) {
        AddDetected(findings, layer, severity,
                    "device.root.kernelsu.throne_hunt",
                    fmt::format(
                            "{{\"baselineOpen\":{},\"baselineAccess\":{},"
                            "\"finalOpen\":{},\"finalAccess\":{},"
                            "\"finalRaw\":{},\"finalInvalid\":{}}}",
                            after.throneHuntBaselineOpen, after.throneHuntBaselineAccess,
                            after.throneHuntFinalOpen, after.throneHuntFinalAccess,
                            after.throneHuntFinalRaw, after.throneHuntFinalInvalid));
    }
    AddRules(findings, layer, severity, hidden, {
            {1u << 1, "device.proc.access_timing"},
            {1u << 2, "device.proc.access_chain"},
            {1u << 3, "device.mount.residue"},
            {1u << 4, "device.mount.debug_ramdisk"},
            {1u << 5, "device.odex.inline_parameter"},
            {1u << 6, "device.zygisk.hiding_timing"},
            {1u << 7, "device.path.existence_hiding"},
            {1u << 8, "device.kernel.identity_spoofing"},
            {1u << 9, "device.zygisk.detected"},
            {1u << 10, "device.mount.hidden_ext4_loop"},
    });
    AddUnavailable(findings, layer);
    return findings;
}

std::vector<NativeFinding> BuildSystemFindings(
        const RiskSnapshot& before,
        const RiskSnapshot& after) {
    constexpr int layer = 1;
    constexpr FindingSeverity severity = FindingSeverity::High;
    std::vector<NativeFinding> findings;
    const uint8_t injection = static_cast<uint8_t>(after.foundInjection & ~before.foundInjection);
    const uint8_t bridge = static_cast<uint8_t>(after.evilBridge & ~before.evilBridge);
    const uint32_t dirty = after.dirtySepolicy & ~before.dirtySepolicy;
    const uint32_t read_proc = (after.readProc & ~before.readProc) & kReadProcFindingMask;
    const uint8_t tee = static_cast<uint8_t>(after.teeSimulator & ~before.teeSimulator);

    AddRules(findings, layer, severity, read_proc, {
            {READPROC_MOUNT_TRACE, "system.readproc.mount_trace"},
            {READPROC_NAMESPACE_VIEW_MISMATCH, "system.readproc.namespace_mismatch"},
            {READPROC_ZN_DAEMON, "system.readproc.zygisk_next_daemon"},
            {READPROC_LSPD, "system.readproc.lsposed_daemon"},
            {READPROC_TRICKY_STORE, "system.readproc.tricky_store"},
            {READPROC_TEESIM_RS_DAEMON, "system.readproc.teesim_rs_daemon"},
            {READPROC_TEESIM_RS_HOOK, "system.readproc.teesim_rs_hook"},
    });
    if (after.foundPermissionLoophole && !before.foundPermissionLoophole) {
        AddDetected(findings, layer, severity, "system.permission.boundary");
    }
    if (after.inconsistentMount && !before.inconsistentMount) {
        AddDetected(findings, layer, severity, "system.mount.inconsistent");
    }
    if (after.propertyAreaModified > before.propertyAreaModified) {
        AddDetected(findings, layer, severity, "system.property.area",
                    fmt::format("{{\"count\":{}}}", after.propertyAreaModified));
    }
    if (after.propertyItemModified > before.propertyItemModified) {
        AddDetected(findings, layer, severity, "system.property.value",
                    fmt::format("{{\"count\":{}}}", after.propertyItemModified));
    }
    AddRules(findings, layer, severity, injection, {
            {1, "system.memory.mapping_inode"},
            {2, "system.memory.executable_anonymous"},
            {4, "system.runtime.injection_path"},
    });
    AddRules(findings, layer, severity, bridge, {
            {1, "system.service.system_server_hook"},
            {2, "system.service.lsposed_bridge"},
            {4, "system.service.sui"},
            {8, "system.service.superuser"},
    });
    AddRules(findings, layer, severity, tee, {
            {teesim_probe::ADMIN_PROTOCOL, "system.teesim.admin_protocol"},
            {teesim_probe::CONTROL_SOCKET, "system.teesim.control_socket"},
            {teesim_probe::RS_SOTER_PROTOCOL, "system.teesim.rs_soter_protocol"},
    });
    AddRules(findings, layer, severity, dirty, {
            {APP_ZYGOTE_SELINUX_PERMISSIVE, "system.selinux.permissive"},
            {APP_ZYGOTE_SYSTEM_SERVER_EXECMEM, "system.selinux.system_server_execmem"},
            {APP_ZYGOTE_AOSP_SU, "system.selinux.aosp_su_transition"},
            {APP_ZYGOTE_ADB_ROOT, "system.selinux.adb_root_domain"},
            {APP_ZYGOTE_MAGISK_POLICY, "system.selinux.magisk_policy"},
            {APP_ZYGOTE_KERNEL_SU_POLICY, "system.selinux.kernelsu_policy"},
            {APP_ZYGOTE_LSPOSED_POLICY, "system.selinux.lsposed_policy"},
            {APP_ZYGOTE_XPOSED_POLICY, "system.selinux.xposed_policy"},
            {APP_ZYGOTE_ZYGISK_NEXT_POLICY, "system.selinux.zygisk_next_policy"},
            {APP_ZYGOTE_STATUS_NOT_ENFORCING, "system.selinux.status_not_enforcing"},
            {APP_ZYGOTE_DENY_UNKNOWN_DISABLED, "system.selinux.deny_unknown_disabled"},
            {APP_ZYGOTE_POLICYLOAD_ANOMALY, "system.selinux.policy_load_count"},
            {APP_ZYGOTE_AVD_SEQUENCE_ANOMALY, "system.selinux.av_decision_sequence"},
            {APP_ZYGOTE_APATCH_POLICY, "system.selinux.apatch_policy"},
            {APP_ZYGOTE_USERSPACE_QUERY_TAMPERED, "system.selinux.userspace_query"},
            {APP_ZYGOTE_ACCESS_ORACLE_TAMPERED, "system.selinux.access_oracle"},
            {APP_ZYGOTE_STATUS_CHANNEL_TAMPERED, "system.selinux.status_channel"},
            {APP_ZYGOTE_POLICY_VIEW_TAMPERED, "system.selinux.policy_view"},
            {APP_ZYGOTE_TEESIM_KEYSTORE_POLICY, "system.selinux.teesim_keystore_policy"},
    });
    if (after.abnormalEnvironment && !before.abnormalEnvironment) {
        AddDetected(findings, layer, severity, "system.mount.peer_group");
    }
    if (after.surroundingSuspicious && !before.surroundingSuspicious) {
        AddDetected(findings, layer, severity, "system.mount.surrounding_path");
    }
    AddUnavailable(findings, layer);
    return findings;
}

std::vector<NativeFinding> BuildHardwareFindings(
        const RiskSnapshot& before,
        const RiskSnapshot& after) {
    constexpr int layer = 2;
    constexpr FindingSeverity severity = FindingSeverity::Critical;
    std::vector<NativeFinding> findings;
    const uint8_t key = static_cast<uint8_t>(after.abnormalKey & ~before.abnormalKey);
    const uint64_t probes = after.keyAttestationFlags & ~before.keyAttestationFlags;
    const uint32_t conventional = after.conventionalTests & ~before.conventionalTests;

    AddRules(findings, layer, severity, probes, {
            {1ULL << 0, "hardware.attestation.main_chain_service_substitution"},
            {1ULL << 1, "hardware.attestation.attest_key_service_substitution"},
            {1ULL << 2, "hardware.attestation.attest_key_chain_unavailable"},
            {1ULL << 3, "hardware.attestation.main_chain_structure"},
            {1ULL << 4, "hardware.attestation.attest_key_chain_structure"},
            {1ULL << 5, "hardware.attestation.keybox_subject"},
            {1ULL << 6, "hardware.attestation.root_of_trust_missing"},
            {1ULL << 7, "hardware.attestation.vbmeta_digest"},
            {KEY_ATTEST_VERIFIED_BOOT_STATE, "hardware.attestation.verified_boot_state"},
            {1ULL << 9, "hardware.attestation.key_info_hardware_backing"},
            {1ULL << 10, "hardware.attestation.key_info_validation"},
            {1ULL << 11, "hardware.attestation.embedded_attest_key_substitution"},
            {1ULL << 12, "hardware.attestation.oversized_challenge"},
            {KEY_ATTEST_ATTEST_KEY_DESCRIPTOR_DELEGATION,
             "hardware.attestation.attest_key_descriptor_delegation"},
            {KEY_ATTEST_TRUST_VALIDATION, "hardware.attestation.trust_validation"},
            {KEY_ATTEST_SECURITY_LEVEL, "hardware.attestation.security_level"},
            {1ULL << 16, "hardware.attestation.cross_sign"},
            {1ULL << 17, "hardware.attestation.certificate_graph"},
            {1ULL << 18, "hardware.attestation.trap_probe"},
            {1ULL << 19, "hardware.attestation.keystore_state_machine"},
            {1ULL << 20, "hardware.attestation.alias_cross_talk"},
            {1ULL << 21, "hardware.attestation.challenge_replay"},
            {1ULL << 22, "hardware.attestation.null_challenge"},
            {1ULL << 23, "hardware.attestation.negative_probe"},
            {1ULL << 24, "hardware.attestation.leaf_constraints"},
            {1ULL << 25, "hardware.attestation.application_id"},
            {1ULL << 26, "hardware.attestation.keystore_timing"},
            {1ULL << 27, "hardware.attestation.key_metadata"},
            {1ULL << 28, "hardware.attestation.imported_key"},
            {1ULL << 29, "hardware.attestation.patch_level"},
            {1ULL << 30, "hardware.attestation.user_auth_policy"},
            {1ULL << 31, "hardware.attestation.single_use_policy"},
            {1ULL << 32, "hardware.attestation.future_validity_policy"},
            {1ULL << 33, "hardware.attestation.runtime"},
            {1ULL << 34, "hardware.attestation.unique_id_permission"},
            {KEY_ATTEST_USER_AUTH_METADATA, "hardware.attestation.user_auth_metadata"},
            {KEY_ATTEST_SIGNING_LINEAGE, "hardware.attestation.signing_lineage"},
            {KEY_ATTEST_OPERATION_SEMANTICS, "hardware.attestation.operation_semantics"},
            {KEY_ATTEST_DEVICE_PROPERTIES, "hardware.attestation.device_properties"},
            {KEY_ATTEST_ALGORITHM_DIFFERENTIAL, "hardware.attestation.algorithm_differential"},
            {KEY_ATTEST_STRONGBOX_DIFFERENTIAL, "hardware.attestation.strongbox_differential"},
            {KEY_ATTEST_KEYMINT_BOUNDARY, "hardware.attestation.keymint_boundary"},
            {KEY_ATTEST_CERT_VALIDITY, "hardware.attestation.certificate_validity"},
            {KEY_ATTEST_BUILD_FINGERPRINT, "hardware.attestation.build_fingerprint"},
            {KEY_ATTEST_RSA_CONFORMANCE, "hardware.attestation.rsa_conformance"},
            {KEY_ATTEST_HMAC_CONFORMANCE, "hardware.attestation.hmac_conformance"},
            {KEY_ATTEST_ECDH_CONFORMANCE, "hardware.attestation.ecdh_conformance"},
            {KEY_ATTEST_AES_CONFORMANCE, "hardware.attestation.aes_conformance"},
            {KEY_ATTEST_ENTRY_SEMANTICS, "hardware.attestation.entry_semantics"},
            {KEY_ATTEST_MAIN_BINDING, "hardware.attestation.main_binding"},
            {KEY_ATTEST_OPERATION_ISOLATION, "hardware.attestation.operation_isolation"},
            {KEY_ATTEST_ISOLATED_CHAIN, "hardware.attestation.isolated_chain"},
            {KEY_ATTEST_CHAIN_READ_STABILITY, "hardware.attestation.chain_read_stability"},
            {KEY_ATTEST_CERTIFICATE_ROUND_TRIP, "hardware.attestation.certificate_round_trip"},
            {KEY_ATTEST_BINDER_LOCALITY, "hardware.attestation.binder_locality"},
            {KEY_ATTEST_INTERFACE_TOKEN_DISPATCH, "hardware.attestation.interface_token_dispatch"},
            {KEY_ATTEST_PARAMETER_FINGERPRINT, "hardware.attestation.parameter_fingerprint"},
            {KEY_ATTEST_TEESIM_PARAMETER_FINGERPRINT, "hardware.attestation.teesim_parameter_fingerprint"},
            {KEY_ATTEST_REPLY_LAG, "hardware.attestation.reply_lag"},
            {KEY_ATTEST_READ_PATH_TIMING, "hardware.attestation.read_path_timing"},
            {KEY_ATTEST_KEY_ID_CONSISTENCY, "hardware.attestation.key_id_consistency"},
            {KEY_ATTEST_KEYSTORE_LEDGER, "hardware.attestation.keystore_ledger"},

            {1ULL << 62, "hardware.attestation.unknown"},
    });
    if ((key & 1) != 0 && probes == 0) {
        AddDetected(findings, layer, severity, "hardware.attestation.key_tampered");
    }
    AddRules(findings, layer, severity, key, {
            {32, "hardware.attestation.flow_incomplete"},
            {2, "hardware.attestation.aosp_test_key"},
            {4, "hardware.attestation.unknown_key_source"},
            {8, "hardware.attestation.vbmeta_hash"},
            {16, "hardware.attestation.root_of_trust_state"},
    });
    // Keep the aggregate result only for genuinely unclassified legacy
    // failures. A specific probe flag must always win in the user interface.
    if ((conventional & (1u << 3)) != 0 && key == 0 && probes == 0) {
        AddDetected(findings, layer, severity, "hardware.attestation.result_anomaly");
    }
    AddUnavailable(findings, layer);
    return findings;
}

}  // namespace

RiskSnapshot CaptureRiskSnapshot() {
    return {sFoundPermissionLoophole, sAbnormalEnvironment, sSurroundingSuspicious,
            sInconsistentMount, sPropertyAreaModified, sPropertyItemModified,
            sFoundInjection, sEvilBridge, sFutileHide, sConventionalTests,
            sDirtySepolicy, sKernelSuProbe, sKernelSuVersion, sKernelSuFlags,
            sKernelSuUapiVersion, sThroneHuntAvailable, sThroneHuntDetected,
            sThroneHuntBaselineOpen, sThroneHuntBaselineAccess,
            sThroneHuntFinalOpen, sThroneHuntFinalAccess,
            sThroneHuntFinalRaw, sThroneHuntFinalInvalid,
            sTeeSimulator, sReadProc,
            sAbnormalKey, sKeyAttestationFlags, sUnavailableProbes.size()};
}

std::vector<NativeFinding> BuildStepFindings(
        int nativeStep,
        const RiskSnapshot& before,
        const RiskSnapshot& after) {
    int layer = 0;
    std::vector<NativeFinding> findings;
    if (nativeStep == 1) {
        findings = BuildDeviceFindings(before, after);
    } else if (nativeStep == 2) {
        layer = 1;
        findings = BuildSystemFindings(before, after);
    } else {
        layer = 2;
        findings = BuildHardwareFindings(before, after);
    }
    if (findings.empty()) {
        AddFinding(findings, {fmt::format("layer.{}.summary", layer), layer,
                              FindingStatus::Clean, FindingSeverity::Info, "{}"});
    }
    return findings;
}

std::vector<NativeFinding> BuildAllVisibleFindings() {
    const RiskSnapshot empty{};
    const auto current = CaptureRiskSnapshot();
    std::vector<NativeFinding> findings;
    for (int nativeStep = 1; nativeStep <= 3; ++nativeStep) {
        auto step = BuildStepFindings(nativeStep, empty, current);
        findings.insert(findings.end(), step.begin(), step.end());
    }
    return findings;
}
