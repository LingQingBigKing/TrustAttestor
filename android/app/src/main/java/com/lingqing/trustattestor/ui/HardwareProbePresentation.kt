package com.lingqing.trustattestor.ui

import java.util.Locale

/**
 * Gives legacy bit-based KeyAttestation diagnostics the same stable identity as native findings.
 *
 * Debug builds receive both a structured native finding and a detailed DEX diagnostic for the
 * same probe.  Keeping the mapping here lets the UI merge those two records without depending on
 * localized display text.
 */
internal object HardwareProbePresentation {
    private data class FlagSpec(
        val flag: Long,
        val fallbackLabel: String,
        val detectedProbeId: String,
        val unavailableProbeId: String? = null
    )

    val fallbackLabels: List<Pair<Long, String>>
        get() = FLAG_SPECS.map { it.flag to it.fallbackLabel }

    fun identify(
        row: EvidenceRow,
        structuredProbeIds: Set<String> = emptySet()
    ): EvidenceRow {
        val existingId = row.probeId
        if (existingId != null && !existingId.startsWith(LEGACY_FLAG_PREFIX)) return row

        val flag = parseLegacyFlag(existingId)
            ?: FLAG_SPECS.firstOrNull { spec ->
                spec.fallbackLabel.equals(row.label.trim(), ignoreCase = true)
            }?.flag
            ?: timingFlagForLegacyLabel(row.label)
            ?: return row
        return identifyFlag(row, flag, structuredProbeIds)
    }

    fun identifyFlag(
        row: EvidenceRow,
        flag: Long,
        structuredProbeIds: Set<String> = emptySet()
    ): EvidenceRow {
        val spec = SPECS_BY_FLAG[flag]
        val canonicalId = when {
            spec == null -> null
            row.status != EvidenceStatus.UNAVAILABLE -> spec.detectedProbeId
            flag == METADATA_FLAG -> metadataUnavailableId(row, structuredProbeIds)
            flag == ISOLATED_CHAIN_FLAG -> isolatedChainUnavailableId(structuredProbeIds)
            else -> spec.unavailableProbeId
        }
        return row.copy(probeId = canonicalId ?: legacyFlagId(flag))
    }

    fun merge(rows: List<EvidenceRow>): List<EvidenceRow> {
        val structuredProbeIds = rows.mapNotNull { row ->
            row.probeId?.takeUnless { it.startsWith(LEGACY_FLAG_PREFIX) }
        }.toSet()
        val merged = linkedMapOf<String, EvidenceRow>()
        rows.forEach { source ->
            val row = identify(source, structuredProbeIds)
            val key = mergeIdentity(row)
            val current = merged[key]
            if (current == null) {
                merged[key] = row
                return@forEach
            }

            // Structured rows are added first. On equal status keep their localized, concise label,
            // while accumulating every detailed Debug payload as evidence beneath that one row.
            val preferred = if (outcomeRank(row.status) > outcomeRank(current.status)) row else current
            val evidence = linkedSetOf<String>().apply {
                current.evidence.trim().takeIf(String::isNotEmpty)?.let(::add)
                row.evidence.trim().takeIf(String::isNotEmpty)?.let(::add)
                if (current.label != preferred.label &&
                    !containsEvidenceLine(current.evidence, current.label)
                ) add(current.label)
                if (row.label != preferred.label && !containsEvidenceLine(row.evidence, row.label)) {
                    add(row.label)
                }
            }.joinToString("\n")
            merged[key] = preferred.copy(evidence = evidence)
        }
        return merged.values.toList()
    }

    private fun mergeIdentity(row: EvidenceRow): String {
        val probeId = row.probeId
        if (probeId != null) {
            // A structured native result uses `<probe>.unavailable`, while its detailed Debug
            // diagnostic uses `<probe>`. They describe one probe run and belong in one row.
            return probeId.removeSuffix(".unavailable")
        }
        return row.label
            .trim()
            .lowercase(Locale.ROOT)
            .replace(Regex("\\s+"), " ")
    }

    private fun containsEvidenceLine(evidence: String, label: String): Boolean =
        evidence.lineSequence().any { it.trim() == label.trim() }

    private fun metadataUnavailableId(
        row: EvidenceRow,
        structuredProbeIds: Set<String>
    ): String {
        val normalized = buildString {
            append(row.label)
            append('\n')
            append(row.evidence)
        }.lowercase(Locale.ROOT)
        val describesSecurityLevel = normalized.contains("m.metadata_security_level") ||
            normalized.contains("securitylevel") ||
            normalized.contains("security level") ||
            normalized.contains("安全级别")
        val describesAuthorization = normalized.contains("authorization") ||
            normalized.contains("authorizations") ||
            normalized.contains("授权一致性") ||
            normalized.contains("授权列表") ||
            normalized.contains("证书扩展")

        return when {
            describesSecurityLevel -> METADATA_SECURITY_LEVEL_UNAVAILABLE
            describesAuthorization -> KEY_METADATA_UNAVAILABLE
            METADATA_SECURITY_LEVEL_UNAVAILABLE in structuredProbeIds &&
                KEY_METADATA_UNAVAILABLE !in structuredProbeIds -> METADATA_SECURITY_LEVEL_UNAVAILABLE
            KEY_METADATA_UNAVAILABLE in structuredProbeIds &&
                METADATA_SECURITY_LEVEL_UNAVAILABLE !in structuredProbeIds -> KEY_METADATA_UNAVAILABLE
            else -> KEY_METADATA_UNAVAILABLE
        }
    }

    private fun isolatedChainUnavailableId(structuredProbeIds: Set<String>): String? {
        val candidates = structuredProbeIds.filter { id ->
            id.startsWith("hardware.attestation.isolated_chain.") && id.endsWith("_unavailable") ||
                id.startsWith("hardware.attestation.isolated_chain.") && id.endsWith(".unavailable") ||
                id == "hardware.attestation.isolated_chain.not_run" ||
                id == "hardware.attestation.isolated_chain.cleanup_incomplete"
        }
        return candidates.singleOrNull()
    }

    private fun parseLegacyFlag(probeId: String?): Long? {
        if (probeId == null || !probeId.startsWith(LEGACY_FLAG_PREFIX)) return null
        return runCatching {
            java.lang.Long.parseUnsignedLong(probeId.removePrefix(LEGACY_FLAG_PREFIX), 16)
        }.getOrNull()
    }

    private fun timingFlagForLegacyLabel(label: String): Long? =
        if (label.contains("Keystore", ignoreCase = true) &&
            (label.contains("timing", ignoreCase = true) ||
                label.contains("时序侧信道") ||
                label.contains("时序分布"))
        ) TIMING_FLAG else null

    private fun legacyFlagId(flag: Long): String =
        "$LEGACY_FLAG_PREFIX${java.lang.Long.toUnsignedString(flag, 16)}"

    private fun outcomeRank(status: EvidenceStatus): Int = when (status) {
        EvidenceStatus.DETECTED -> 4
        EvidenceStatus.UNAVAILABLE -> 3
        EvidenceStatus.WARNING -> 2
        EvidenceStatus.VERIFIED -> 1
        else -> 0
    }

    private const val LEGACY_FLAG_PREFIX = "hardware.flag.0x"
    private const val KEY_METADATA_UNAVAILABLE = "hardware.attestation.key_metadata.unavailable"
    private const val METADATA_SECURITY_LEVEL_UNAVAILABLE =
        "hardware.attestation.metadata_security_level.unavailable"
    private val TIMING_FLAG = 1L shl 26
    private val METADATA_FLAG = 1L shl 27
    private val ISOLATED_CHAIN_FLAG = 1L shl 51

    private fun spec(
        bit: Int,
        label: String,
        id: String,
        unavailable: Boolean = false
    ) = FlagSpec(
        flag = 1L shl bit,
        fallbackLabel = label,
        detectedProbeId = "hardware.attestation.$id",
        unavailableProbeId = if (unavailable) "hardware.attestation.$id.unavailable" else null
    )

    private val FLAG_SPECS = listOf(
        spec(0, "Main certificate chain service substitution", "main_chain_service_substitution"),
        spec(1, "AttestKey chain service substitution", "attest_key_service_substitution"),
        spec(2, "AttestKey certificate chain unavailable", "attest_key_chain_unavailable"),
        spec(3, "Main certificate chain structure anomaly", "main_chain_structure"),
        spec(4, "AttestKey chain structure anomaly", "attest_key_chain_structure"),
        spec(5, "Keybox certificate subject", "keybox_subject"),
        spec(6, "RootOfTrust record missing", "root_of_trust_missing"),
        spec(7, "VBMeta digest mismatch", "vbmeta_digest"),
        spec(8, "Abnormal RootOfTrust lock or Verified Boot state", "verified_boot_state"),
        spec(9, "KeyInfo not hardware-backed", "key_info_hardware_backing"),
        spec(10, "KeyInfo validation error", "key_info_validation"),
        spec(11, "Embedded AttestKey substitution", "embedded_attest_key_substitution"),
        spec(12, "Oversized challenge accepted", "oversized_challenge"),
        spec(
            13,
            "Direct AttestKey KeyDescriptor delegation anomaly",
            "attest_key_descriptor_delegation",
            unavailable = true
        ),
        spec(14, "Attestation trust validation failed", "trust_validation"),
        spec(15, "Attestation hardware security level anomaly", "security_level"),
        spec(16, "AttestKey cross-sign mismatch", "cross_sign", unavailable = true),
        spec(17, "AttestKey graph anomaly", "certificate_graph", unavailable = true),
        spec(18, "Attestation trap probe hit", "trap_probe", unavailable = true),
        spec(19, "Keystore state machine anomaly", "keystore_state_machine", unavailable = true),
        spec(20, "Alias cross-talk anomaly", "alias_cross_talk", unavailable = true),
        spec(21, "Challenge replay anomaly", "challenge_replay", unavailable = true),
        spec(22, "Null challenge accepted", "null_challenge", unavailable = true),
        spec(23, "AttestKey negative probe bypass", "negative_probe", unavailable = true),
        spec(24, "Leaf certificate constraints anomaly", "leaf_constraints", unavailable = true),
        spec(25, "AttestationApplicationId mismatch", "application_id", unavailable = true),
        spec(26, "Keystore timing distribution anomaly", "keystore_timing", unavailable = true),
        spec(27, "KeyMetadata authorization mismatch", "key_metadata", unavailable = true),
        spec(28, "Imported key became attested", "imported_key", unavailable = true),
        spec(29, "Patch level contradiction", "patch_level", unavailable = true),
        spec(30, "User authentication policy bypass", "user_auth_policy", unavailable = true),
        spec(31, "Single-use key policy bypass", "single_use_policy", unavailable = true),
        spec(32, "Future validity policy bypass", "future_validity_policy", unavailable = true),
        spec(33, "Key Attestation runtime error", "runtime"),
        spec(34, "Unique-ID attestation permission bypass", "unique_id_permission", unavailable = true),
        spec(35, "User-auth metadata anomaly", "user_auth_metadata", unavailable = true),
        spec(36, "Signing-lineage anomaly", "signing_lineage", unavailable = true),
        spec(37, "KeyMint operation-semantic anomaly", "operation_semantics", unavailable = true),
        spec(38, "Device-properties mismatch", "device_properties", unavailable = true),
        spec(39, "RSA / EC attestation differential", "algorithm_differential", unavailable = true),
        spec(40, "StrongBox differential anomaly", "strongbox_differential", unavailable = true),
        spec(41, "KeyMint boundary anomaly", "keymint_boundary", unavailable = true),
        spec(42, "Attestation certificate validity anomaly", "certificate_validity"),
        spec(43, "Build fingerprint mismatch", "build_fingerprint"),
        spec(44, "RSA conformance anomaly", "rsa_conformance", unavailable = true),
        spec(45, "HMAC conformance anomaly", "hmac_conformance", unavailable = true),
        spec(46, "ECDH conformance anomaly", "ecdh_conformance", unavailable = true),
        spec(47, "AES conformance anomaly", "aes_conformance", unavailable = true),
        spec(48, "Keystore entry-semantic anomaly", "entry_semantics", unavailable = true),
        spec(49, "Primary attestation binding anomaly", "main_binding", unavailable = true),
        spec(50, "Cryptographic operation isolation anomaly", "operation_isolation", unavailable = true),
        spec(51, "Isolated-process chain mismatch", "isolated_chain"),
        spec(52, "Full attestation chain read inconsistency", "chain_read_stability", unavailable = true),
        spec(53, "Original certificate chain round-trip inconsistency", "certificate_round_trip", unavailable = true),
        spec(54, "Keystore Binder locality anomaly", "binder_locality", unavailable = true),
        spec(55, "Wrong interface-token dispatch", "interface_token_dispatch", unavailable = true),
        spec(56, "KeyMint parameter fingerprint anomaly", "parameter_fingerprint", unavailable = true),
        spec(57, "TeeSim parameter invariant violation", "teesim_parameter_fingerprint", unavailable = true),
        spec(58, "Attestation reply-lag anomaly", "reply_lag", unavailable = true),
        spec(59, "Raw read-path timing anomaly", "read_path_timing", unavailable = true),
        spec(60, "APP / KEY_ID record inconsistency", "key_id_consistency", unavailable = true),
        spec(61, "Keystore state-ledger inconsistency", "keystore_ledger", unavailable = true),
        spec(62, "Unknown hardware attestation anomaly", "unknown")
    )

    private val SPECS_BY_FLAG = FLAG_SPECS.associateBy(FlagSpec::flag)
}
