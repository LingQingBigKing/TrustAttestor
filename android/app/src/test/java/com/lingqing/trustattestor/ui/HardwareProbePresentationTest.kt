package com.lingqing.trustattestor.ui

/** Run main on the host JDK; no Android runtime or JUnit dependency is required. */
object HardwareProbePresentationTest {
    private var assertions = 0

    @JvmStatic
    fun main(args: Array<String>) {
        descriptorDelegationFlagUsesCanonicalId()
        rootOfTrustFlagsUseCanonicalIds()
        baseVerdictFlagsUseSpecificCanonicalIds()
        devicePropertiesFailureFlagUsesDetectedId()
        devicePropertiesUnavailableDoesNotHideVerifiedBootDetection()
        newProbeFlagsUseCanonicalIds()
        metadataUnavailableRowsRemainDistinct()
        structuredAndDetailedRowsMergeWithoutLosingEvidence()
        repeatedTimingWarningsMergeByCanonicalId()
        timingUnavailableAndNoiseDetailMergeAsOneProbe()
        println("HardwareProbePresentationTest: $assertions assertions passed")
    }

    private fun descriptorDelegationFlagUsesCanonicalId() {
        val flag = 1L shl 13
        val detectedId = "hardware.attestation.attest_key_descriptor_delegation"
        val unavailableId = "$detectedId.unavailable"

        val detected = HardwareProbePresentation.identifyFlag(
            EvidenceRow("direct delegation failed", EvidenceStatus.DETECTED),
            flag
        )
        check(detected.probeId == detectedId, "descriptor delegation detected id")

        val unavailable = HardwareProbePresentation.identifyFlag(
            EvidenceRow("direct delegation unavailable", EvidenceStatus.UNAVAILABLE),
            flag
        )
        check(unavailable.probeId == unavailableId, "descriptor delegation unavailable id")

        val merged = HardwareProbePresentation.merge(
            listOf(
                EvidenceRow(
                    "AttestKey KeyDescriptor 直接委派异常",
                    EvidenceStatus.DETECTED,
                    probeId = detectedId
                ),
                detected.copy(evidence = "InvalidAlgorithmParameterException: Invalid attestKeyAlias")
            )
        )
        check(merged.size == 1, "descriptor delegation structured and detailed rows merge")
        check(merged.single().probeId == detectedId, "descriptor delegation canonical id retained")
        check(merged.single().evidence.contains("Invalid attestKeyAlias"),
            "descriptor delegation detail retained")
    }

    private fun rootOfTrustFlagsUseCanonicalIds() {
        val vbmetaDigest = HardwareProbePresentation.identifyFlag(
            EvidenceRow("VBMeta digest mismatch", EvidenceStatus.DETECTED),
            1L shl 7
        )
        check(
            vbmetaDigest.probeId == "hardware.attestation.vbmeta_digest",
            "VBMeta digest canonical id"
        )

        val verifiedBootState = HardwareProbePresentation.identifyFlag(
            EvidenceRow("Verified Boot state mismatch", EvidenceStatus.DETECTED),
            1L shl 8
        )
        check(
            verifiedBootState.probeId == "hardware.attestation.verified_boot_state",
            "Verified Boot state canonical id"
        )
    }

    private fun baseVerdictFlagsUseSpecificCanonicalIds() {
        val trust = HardwareProbePresentation.identifyFlag(
            EvidenceRow("trust validation failed", EvidenceStatus.DETECTED),
            1L shl 14
        )
        check(
            trust.probeId == "hardware.attestation.trust_validation",
            "trust-validation canonical id"
        )

        val securityLevel = HardwareProbePresentation.identifyFlag(
            EvidenceRow("security level anomaly", EvidenceStatus.DETECTED),
            1L shl 15
        )
        check(
            securityLevel.probeId == "hardware.attestation.security_level",
            "security-level canonical id"
        )
    }

    private fun devicePropertiesUnavailableDoesNotHideVerifiedBootDetection() {
        val devicePropertiesId = "hardware.attestation.device_properties.unavailable"
        val verifiedBootId = "hardware.attestation.verified_boot_state"
        val rows = HardwareProbePresentation.merge(
            listOf(
                EvidenceRow(
                    "硬件 Device Properties 检测未完成",
                    EvidenceStatus.UNAVAILABLE,
                    probeId = devicePropertiesId
                ),
                HardwareProbePresentation.identifyFlag(
                    EvidenceRow(
                        "Verified Boot state mismatch",
                        EvidenceStatus.DETECTED,
                        evidence = "RootOfTrust 与系统属性状态不一致"
                    ),
                    1L shl 8,
                    setOf(devicePropertiesId)
                )
            )
        )

        check(rows.size == 2, "Device Properties unavailable and Verified Boot detected remain distinct")
        check(rows.any { it.probeId == devicePropertiesId }, "Device Properties unavailable retained")
        check(
            rows.any { it.probeId == verifiedBootId && it.status == EvidenceStatus.DETECTED },
            "Verified Boot detected retained"
        )
        check(rows.any { it.status == EvidenceStatus.DETECTED }, "merged results retain detected outcome")
    }

    private fun devicePropertiesFailureFlagUsesDetectedId() {
        val detected = HardwareProbePresentation.identifyFlag(
            EvidenceRow(
                "Device Properties request path differs from baseline",
                EvidenceStatus.DETECTED
            ),
            1L shl 38
        )
        check(
            detected.probeId == "hardware.attestation.device_properties",
            "isolated Device Properties failure uses the detected id"
        )
        check(
            detected.status == EvidenceStatus.DETECTED,
            "isolated Device Properties failure remains detected"
        )
    }

    private fun newProbeFlagsUseCanonicalIds() {
        val ids = listOf(
            "binder_locality",
            "interface_token_dispatch",
            "parameter_fingerprint",
            "teesim_parameter_fingerprint",
            "reply_lag",
            "read_path_timing",
            "key_id_consistency",
            "keystore_ledger"
        )
        ids.forEachIndexed { index, id ->
            val flag = 1L shl (54 + index)
            val detected = HardwareProbePresentation.identifyFlag(
                EvidenceRow("debug", EvidenceStatus.DETECTED),
                flag
            )
            check(detected.probeId == "hardware.attestation.$id", "detected id for bit ${54 + index}")

            val unavailable = HardwareProbePresentation.identifyFlag(
                EvidenceRow("debug", EvidenceStatus.UNAVAILABLE),
                flag
            )
            check(
                unavailable.probeId == "hardware.attestation.$id.unavailable",
                "unavailable id for bit ${54 + index}"
            )
        }
    }

    private fun metadataUnavailableRowsRemainDistinct() {
        val flag = 1L shl 27
        val securityLevel = HardwareProbePresentation.identifyFlag(
            EvidenceRow(
                "M.metadata_security_level: KeyMetadata securityLevel unavailable",
                EvidenceStatus.UNAVAILABLE
            ),
            flag,
            setOf(
                "hardware.attestation.metadata_security_level.unavailable",
                "hardware.attestation.key_metadata.unavailable"
            )
        )
        check(
            securityLevel.probeId == "hardware.attestation.metadata_security_level.unavailable",
            "M securityLevel identity"
        )

        val authorization = HardwareProbePresentation.identifyFlag(
            EvidenceRow("KeyMetadata 授权一致性探针需要 Keystore2", EvidenceStatus.UNAVAILABLE),
            flag,
            setOf(
                "hardware.attestation.metadata_security_level.unavailable",
                "hardware.attestation.key_metadata.unavailable"
            )
        )
        check(
            authorization.probeId == "hardware.attestation.key_metadata.unavailable",
            "legacy metadata-authorization identity"
        )
    }

    private fun structuredAndDetailedRowsMergeWithoutLosingEvidence() {
        val detectedId = "hardware.attestation.interface_token_dispatch"
        val detectedRows = HardwareProbePresentation.merge(
            listOf(
                EvidenceRow("错误接口令牌分发异常", EvidenceStatus.DETECTED, probeId = detectedId),
                HardwareProbePresentation.identifyFlag(
                    EvidenceRow(
                        "U transaction accepted",
                        EvidenceStatus.DETECTED,
                        evidence = "U transaction accepted\ntransaction=42"
                    ),
                    1L shl 55,
                    setOf(detectedId)
                )
            )
        )
        check(detectedRows.size == 1, "detected structured and flag rows merge")
        check(detectedRows.single().probeId == detectedId, "detected canonical id retained")
        check(detectedRows.single().evidence.contains("transaction=42"), "detected detail retained")

        val id = "hardware.attestation.parameter_fingerprint.unavailable"
        val structured = EvidenceRow(
            label = "KeyMint 参数指纹检测未完成",
            status = EvidenceStatus.UNAVAILABLE,
            probeId = id
        )
        val detail = HardwareProbePresentation.identifyFlag(
            EvidenceRow(
                label = "F probe timed out",
                status = EvidenceStatus.UNAVAILABLE,
                evidence = "F probe timed out\nTimeoutException\n  at probe.worker"
            ),
            1L shl 56,
            setOf(id)
        )
        val rows = HardwareProbePresentation.merge(listOf(structured, detail))
        check(rows.size == 1, "one merged result")
        check(rows.single().label == structured.label, "structured localized label retained")
        check(rows.single().status == EvidenceStatus.UNAVAILABLE, "unavailable status retained")
        check(rows.single().evidence.contains("TimeoutException"), "detailed cause retained")
        check(rows.single().evidence.contains("probe.worker"), "detailed stack retained")
    }

    private fun repeatedTimingWarningsMergeByCanonicalId() {
        val rows = HardwareProbePresentation.merge(
            listOf(
                EvidenceRow(
                    "Keystore 时序受系统噪声影响，不作异常判定",
                    EvidenceStatus.WARNING,
                    evidence = "batch=1",
                    probeId = "hardware.flag.0x4000000"
                ),
                EvidenceRow(
                    "Keystore 时序受批次顺序影响，不作异常判定",
                    EvidenceStatus.WARNING,
                    evidence = "batch=2",
                    probeId = "hardware.flag.0x4000000"
                )
            )
        )
        check(rows.size == 1, "timing warnings merge into one row")
        check(
            rows.single().probeId == "hardware.attestation.keystore_timing",
            "timing warning canonical id retained"
        )
        check(rows.single().evidence.contains("batch=1"), "first timing detail retained")
        check(rows.single().evidence.contains("batch=2"), "second timing detail retained")
    }

    private fun timingUnavailableAndNoiseDetailMergeAsOneProbe() {
        val structured = EvidenceRow(
            label = "Keystore 时序侧信道检测未完成",
            status = EvidenceStatus.UNAVAILABLE,
            probeId = "hardware.attestation.keystore_timing.unavailable"
        )
        val detail = EvidenceRow(
            label = "Keystore 时序受系统噪声影响，不作异常判定",
            status = EvidenceStatus.WARNING,
            evidence = "quality=batch order did not repeat",
            probeId = "hardware.flag.0x4000000"
        )

        val rows = HardwareProbePresentation.merge(listOf(structured, detail))
        check(rows.size == 1, "timing unavailable and noise detail merge into one row")
        check(rows.single().status == EvidenceStatus.UNAVAILABLE, "stronger timing status retained")
        check(
            rows.single().probeId == "hardware.attestation.keystore_timing.unavailable",
            "structured timing identity retained"
        )
        check(rows.single().evidence.contains("系统噪声"), "noise explanation retained")
        check(rows.single().evidence.contains("batch order"), "noise evidence retained")
    }

    private fun check(value: Boolean, description: String) {
        assertions++
        if (!value) throw AssertionError(description)
    }
}
