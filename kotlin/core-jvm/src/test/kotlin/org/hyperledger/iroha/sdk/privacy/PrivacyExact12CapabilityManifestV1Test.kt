// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.privacy

import java.nio.charset.StandardCharsets
import org.hyperledger.iroha.sdk.core.model.NetworkId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame

class PrivacyExact12CapabilityManifestV1Test {
    @Test
    fun decodedArchivesNeverGrantAdmissionIncludingClaimedQualifiedRows() {
        val protocol = PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1
        for (manifest in listOf(
            parseInspection(inspection()),
            parseInspection(inspection(mapOf(protocol to qualifiedAvailableRow()), qualification())),
        )) {
            val error = assertFailsWith<IllegalArgumentException> {
                PrivacyExact12CapabilityAdmissionV1.requireExact12CapabilityTupleV1(manifest, protocol)
            }
            assertEquals(
                "Exact12 admission requires an authenticated Torii response; decoded archives are inspection-only",
                error.message,
            )
        }
    }

    @Test
    fun deploymentRequiresAnExactCanonicalNetworkIdentity() {
        val qualified = inspection(qualification = qualification())
        val literal = NetworkId.fromBytes(ByteArray(32) { 0xD1.toByte() }).literal
        val parsed = parseInspection(qualified)
        assertEquals(literal, parsed.qualification!!.deploymentQualification.networkId.literal)
        for (invalid in listOf("kotlin-test-network", literal.lowercase(), "")) {
            assertFailsWith<IllegalArgumentException> {
                parseInspection(qualified.replace(literal, invalid))
            }
        }
    }
    @Test
    fun pendingTighteningAcceptsNextBlockAndRejectsInvalidSnapshotHeights() {
        val protocol = PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1
        val cases = listOf(
            listOf("42", "43", "42", "true"),
            listOf("42", "44", "42", "true"),
            listOf("42", "44", "43", "true"),
            listOf("18446744073709551614", "18446744073709551615", "18446744073709551614", "true"),
            listOf("-1", "43", "42", "false"),
            listOf("0", "43", "42", "false"),
            listOf("42", "-1", "42", "false"),
            listOf("42", "0", "42", "false"),
            listOf("42", "42", "42", "false"),
            listOf("42", "41", "42", "false"),
            listOf("43", "44", "42", "false"),
            listOf("42", "43", "43", "false"),
            listOf("42", "43", "44", "false"),
            listOf("18446744073709551615", "18446744073709551615", "18446744073709551615", "false"),
            listOf("18446744073709551615", "18446744073709551616", "18446744073709551615", "false"),
            listOf("18446744073709551616", "18446744073709551617", "42", "false"),
        )
        for (consensus in listOf(true, false)) {
            for ((scheduled, effective, committed, accepted) in cases) {
                val next = if (consensus) consensusLimits().replace("2048", "1024") else
                    """{"protocol":"${protocol.canonicalLabel}","limits":{"max_anonymity_set_size":32,"max_recipient_count":8}}"""
                val pending = """{"scheduled_at_height":$scheduled,"effective_at_height":$effective,"next_limits":$next}"""
                var input = inspection(mapOf(protocol to availableRow(
                    "missing-production-qualification", activeLifecycle(),
                ))).replace("\"committed_height\":42", "\"committed_height\":$committed")
                val field = if (consensus) "pending_tightening" else "pending_protocol_limits_tightening"
                input = input.replace("\"$field\":null", "\"$field\":$pending")
                if (accepted == "true") {
                    val manifest = parseInspection(input)
                    assertEquals(committed.toBigInteger(), manifest.committedHeight)
                    val parsedSchedule = if (consensus) {
                        manifest.consensusPolicy.pendingTightening?.let {
                            it.scheduledAtHeight to it.effectiveAtHeight
                        }
                    } else {
                        manifest.rowFor(protocol).activation?.pendingProtocolLimitsTightening?.let {
                            it.scheduledAtHeight to it.effectiveAtHeight
                        }
                    }
                    assertEquals(scheduled.toBigInteger() to effective.toBigInteger(), parsedSchedule)
                    assertFailsWith<IllegalArgumentException> {
                        PrivacyExact12CapabilityAdmissionV1.requireExact12CapabilityTupleV1(manifest, protocol)
                    }
                } else {
                    assertFailsWith<IllegalArgumentException> { parseInspection(input) }
                }
            }
        }
    }

    @Test
    fun parsesSevenFieldRowsAndPreservesCanonicalManifestState() {
        val manifest = parseInspection(inspection())

        assertEquals(PrivacyExact12CapabilityManifestV1.VERSION, manifest.version)
        assertEquals(42.toBigInteger(), manifest.committedHeight)
        assertEquals(2048, manifest.consensusPolicy.currentLimits.retainedRootCount)
        assertEquals(PrivacyProtocolIdV1.values().toList(), manifest.protocols.map { it.protocolId })
        assertEquals(7, exactRowKeys().size)
        assertNull(manifest.qualification)

        val readiness = assertIs<PrivacyCapabilityReadinessV1.Unavailable>(
            manifest.protocols.first().readiness,
        )
        val reason = assertIs<PrivacyCapabilityUnavailableReasonV1.CompiledProfile>(
            readiness.reason,
        )
        assertEquals(
            PrivacyCompiledProfileUnavailableReasonV1.ENGINE_UNAVAILABLE,
            reason.failure.reason,
        )
        assertNull(manifest.protocols.first().activation)
        assertFalse(manifest.protocols.first().isNetworkAvailable())
    }

    @Test
    fun readinessUsesOnlyClosedEvidenceDerivedReasons() {
        val cases = listOf(
            availableRow("not-registered", null) to PrivacyCapabilityUnavailableReasonV1.NotRegistered,
            availableRow("proposed", proposedLifecycle()) to PrivacyCapabilityUnavailableReasonV1.Proposed,
            availableRow("suspended", suspendedLifecycle()) to PrivacyCapabilityUnavailableReasonV1.Suspended,
            availableRow("retired", retiredLifecycle()) to PrivacyCapabilityUnavailableReasonV1.Retired,
            availableRow("missing-production-qualification", activeLifecycle()) to
                PrivacyCapabilityUnavailableReasonV1.MissingProductionQualification,
        )

        for ((row, expectedReason) in cases) {
            val manifest = parseInspection(
                inspection(mapOf(PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1 to row)),
            )
            val readiness = assertIs<PrivacyCapabilityReadinessV1.Unavailable>(
                manifest.rowFor(PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1).readiness,
            )
            assertSame(expectedReason, readiness.reason)
        }

        val active = parseInspection(
            inspection(
                mapOf(
                    PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1 to
                        availableRow("missing-production-qualification", activeLifecycle()),
                ),
            ),
        ).rowFor(PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1)
        assertFalse(active.isNetworkAvailable())
    }

    @Test
    fun proposedRemainsPendingUntilExplicitActivationAtEveryCommittedHeight() {
        val protocol = PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1
        for (committedHeight in listOf("1", "42", "18446744073709551615")) {
            val candidate = inspection(mapOf(protocol to availableRow("proposed", proposedLifecycle())))
                .replace("\"committed_height\":42", "\"committed_height\":$committedHeight")
            val row = parseInspection(candidate).rowFor(protocol)
            assertSame(
                PrivacyCapabilityUnavailableReasonV1.Proposed,
                assertIs<PrivacyCapabilityReadinessV1.Unavailable>(row.readiness).reason,
            )
            assertEquals(PrivacyProtocolLifecycleStateV1.PROPOSED, row.activation!!.lifecycle.state)
            assertFalse(row.isNetworkAvailable())
            assertFailsWith<IllegalArgumentException> {
                parseInspection(candidate.replace(
                    unavailableReadiness("proposed"),
                    unavailableReadiness("missing-production-qualification"),
                ))
            }
        }
    }

    @Test
    fun sameHeightActivationRetainsQualificationAndHistoryRequirements() {
        val protocol = PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1
        for ((state, since, reason) in listOf(
            Triple("active", 1, "missing-production-qualification"),
            Triple("suspended", 2, "suspended"),
            Triple("retired", 2, "retired"),
        )) {
            val lifecycle = """{"state":"$state","record":{"proposed_at_height":1,"activated_at_height":1,"state_since_height":$since}}"""
            val row = parseInspection(
                inspection(mapOf(protocol to availableRow(reason, lifecycle))),
            ).rowFor(protocol)
            assertEquals(1.toBigInteger(), row.activation!!.lifecycle.activatedAtHeight)
            assertIs<PrivacyCapabilityReadinessV1.Unavailable>(row.readiness)
            assertFalse(row.isNetworkAvailable())
        }
    }

    @Test
    fun rejectsRemovedScheduleAndReversedOrFutureLifecycleHistory() {
        val protocol = PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1
        val cases = listOf(
            "proposed" to """{"proposed_at_height":1,"activate_at_height":100}""",
            "proposed" to """{}""",
            "proposed" to """{"proposed_at_height":0}""",
            "proposed" to """{"proposed_at_height":43}""",
            "active" to """{"proposed_at_height":2,"activated_at_height":1,"state_since_height":2}""",
            "active" to """{"proposed_at_height":1,"activated_at_height":2,"state_since_height":1}""",
            "active" to """{"proposed_at_height":1,"activated_at_height":43,"state_since_height":43}""",
            "suspended" to """{"proposed_at_height":1,"activated_at_height":1,"state_since_height":1}""",
            "retired" to """{"proposed_at_height":1,"activated_at_height":1,"state_since_height":1}""",
            "retired" to """{"proposed_at_height":1,"activated_at_height":null,"state_since_height":1}""",
        )
        for ((state, record) in cases) {
            val lifecycle = """{"state":"$state","record":$record}"""
            val reason = if (state == "active") "missing-production-qualification" else state
            assertFailsWith<IllegalArgumentException>("hostile lifecycle: $lifecycle") {
                parseInspection(inspection(mapOf(protocol to availableRow(reason, lifecycle))))
            }
        }
    }

    @Test
    fun rejectsPreHardCutRowReadinessAndActivationShapes() {
        val canonical = inspection()
        val readiness = compiledUnavailableReadiness()
        val hostile = listOf(
            canonical.replaceFirst(
                "\"activation\":null}",
                "\"activation\":null,\"activation_state\":{\"activation_state\":\"not-registered\",\"detail\":null}}",
            ),
            canonical.replaceFirst(
                "\"activation\":null}",
                "\"activation\":null,\"limitation\":null}",
            ),
            canonical.replaceFirst(readiness, "{\"readiness\":\"available\",\"detail\":null}"),
            canonical.replaceFirst(
                readiness,
                "{\"readiness\":\"available-experimental\",\"detail\":null}",
            ),
            inspection(
                mapOf(
                    PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1 to
                        availableRow("missing-production-qualification", activeLifecycle()),
                ),
            ).replaceFirst(
                "\"pending_protocol_limits_tightening\":null}",
                "\"pending_protocol_limits_tightening\":null,\"production_qualification\":null}",
            ),
            canonical.replaceFirst("\"qualification\":null,", ""),
        )

        hostile.forEachIndexed { index, candidate ->
            assertFailsWith<IllegalArgumentException>("pre-hard-cut shape $index must fail") {
                parseInspection(candidate)
            }
        }
    }

    @Test
    fun activeWithoutQualificationCannotClaimProductionReadiness() {
        val row = availableRow("missing-production-qualification", activeLifecycle())
        val forged = row.replace(
            unavailableReadiness("missing-production-qualification"),
            "{\"readiness\":\"production-qualified\",\"detail\":null}",
        )

        assertFailsWith<IllegalArgumentException> {
            parseInspection(
                inspection(mapOf(PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1 to forged)),
            )
        }
    }

    @Test
    fun singletonQualificationAloneDerivesProductionAndInvalidReadiness() {
        val protocol = PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1
        val qualified = parseInspection(
            inspection(
                mapOf(protocol to qualifiedAvailableRow()),
                qualification(pgcActivationHeight = 2, convergenceHeight = 3),
            ),
        )
        assertIs<PrivacyExact12QualificationRecordV1>(qualified.qualification)
        assertIs<PrivacyCapabilityReadinessV1.ProductionQualified>(
            qualified.rowFor(protocol).readiness,
        )

        val invalid = parseInspection(
            inspection(
                mapOf(
                    protocol to availableRow(
                        "invalid-production-qualification",
                        activeLifecycle(),
                    ),
                ),
                qualification(pgcActivationHeight = 4, convergenceHeight = 5),
            ),
        )
        val invalidReadiness = assertIs<PrivacyCapabilityReadinessV1.Unavailable>(
            invalid.rowFor(protocol).readiness,
        )
        assertSame(
            PrivacyCapabilityUnavailableReasonV1.InvalidProductionQualification,
            invalidReadiness.reason,
        )

        assertFailsWith<IllegalArgumentException> {
            parseInspection(
                inspection(
                    mapOf(protocol to qualifiedAvailableRow()),
                    qualification(pgcActivationHeight = 4, convergenceHeight = 5),
                ),
            )
        }
    }

    private fun parseInspection(value: String): PrivacyExact12CapabilityManifestV1 =
        PrivacyExact12CapabilityManifestInspectionV1.parse(
            byteArrayOf(1),
            value.toByteArray(StandardCharsets.UTF_8),
        )

    private fun inspection(
        overrides: Map<PrivacyProtocolIdV1, String> = emptyMap(),
        qualification: String? = null,
    ): String {
        val rows = PrivacyProtocolIdV1.values().joinToString(",") { protocol ->
            overrides[protocol] ?: unavailableRow(protocol)
        }
        val matches = PrivacyProtocolIdV1.values().joinToString(",") { "false" }
        return """{"manifest":{"version":1,"committed_height":42,"consensus_policy":{"current_limits":${consensusLimits()},"pending_tightening":null},"qualification":${qualification ?: "null"},"protocols":[$rows],"manifest_digest":${bytes(9, 32)}},"local_compiled_tuple_matches":[$matches]}"""
    }

    private fun unavailableRow(protocol: PrivacyProtocolIdV1): String =
        """{"protocol_id":${protocolTag(protocol)},"operation_schema":{"operation_schema":"${expectedOperationSchema(protocol).canonicalLabel}","value":null},"execution_mode":{"execution_mode":"${expectedExecutionMode(protocol).canonicalLabel}","value":null},"privacy_feature_mask":${expectedFeatureMask(protocol)},"compiled_profile":${compiledUnavailable()},"readiness":${compiledUnavailableReadiness()},"activation":null}"""

    private fun availableRow(reason: String, lifecycle: String?): String {
        val protocol = PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1
        val profile = profileFields(protocol)
        val activation = lifecycle?.let {
            "{$profile,\"lifecycle\":$it,\"pending_protocol_limits_tightening\":null}"
        } ?: "null"
        return """{"protocol_id":${protocolTag(protocol)},"operation_schema":{"operation_schema":"${expectedOperationSchema(protocol).canonicalLabel}","value":null},"execution_mode":{"execution_mode":"${expectedExecutionMode(protocol).canonicalLabel}","value":null},"privacy_feature_mask":${expectedFeatureMask(protocol)},"compiled_profile":{"status":"available","value":{$profile}},"readiness":${unavailableReadiness(reason)},"activation":$activation}"""
    }

    private fun qualifiedAvailableRow(): String {
        val protocol = PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1
        val profile = profileFields(protocol)
        val activation = "{$profile,\"lifecycle\":${activeLifecycle()}," +
            "\"pending_protocol_limits_tightening\":null}"
        return """{"protocol_id":${protocolTag(protocol)},"operation_schema":{"operation_schema":"${expectedOperationSchema(protocol).canonicalLabel}","value":null},"execution_mode":{"execution_mode":"${expectedExecutionMode(protocol).canonicalLabel}","value":null},"privacy_feature_mask":${expectedFeatureMask(protocol)},"compiled_profile":{"status":"available","value":{$profile}},"readiness":{"readiness":"production-qualified","detail":null},"activation":$activation}"""
    }

    private fun profileFields(protocol: PrivacyProtocolIdV1): String =
        """"protocol_id":${protocolTag(protocol)},"proof_system_id":{"proof_system":"${protocol.expectedProofSystem.canonicalLabel}","value":null},"engine_id":{"engine":"${protocol.expectedEngine.canonicalLabel}","value":null},"parameter_id":${bytes(1, 32)},"parameter_digest":${bytes(2, 32)},"verifier_digest":${bytes(3, 32)},"statement_schema_digest":${bytes(4, 32)},"engine_manifest_digest":${bytes(5, 32)},"protocol_limits":{"protocol":"${protocol.canonicalLabel}","limits":{"max_anonymity_set_size":64,"max_recipient_count":8}}"""

    private fun compiledUnavailable(): String =
        """{"status":"unavailable","value":{"reason":"engine-unavailable","detail":null}}"""

    private fun compiledUnavailableReadiness(): String =
        """{"readiness":"unavailable","detail":{"reason":"compiled-profile","detail":{"reason":"engine-unavailable","detail":null}}}"""

    private fun unavailableReadiness(reason: String): String =
        """{"readiness":"unavailable","detail":{"reason":"$reason","detail":null}}"""

    private fun protocolTag(protocol: PrivacyProtocolIdV1): String =
        """{"protocol":"${protocol.canonicalLabel}","value":null}"""

    private fun proposedLifecycle(): String =
        """{"state":"proposed","record":{"proposed_at_height":1}}"""

    private fun activeLifecycle(): String =
        """{"state":"active","record":{"proposed_at_height":1,"activated_at_height":2,"state_since_height":2}}"""

    private fun suspendedLifecycle(): String =
        """{"state":"suspended","record":{"proposed_at_height":1,"activated_at_height":2,"state_since_height":3}}"""

    private fun retiredLifecycle(): String =
        """{"state":"retired","record":{"proposed_at_height":1,"activated_at_height":2,"state_since_height":3}}"""

    private fun exactRowKeys(): Set<String> = setOf(
        "protocol_id",
        "operation_schema",
        "execution_mode",
        "privacy_feature_mask",
        "compiled_profile",
        "readiness",
        "activation",
    )

    private fun qualification(pgcActivationHeight: Int = 2, convergenceHeight: Int = 3): String {
        val releaseDigest = bytes(177, 32)
        val bindings = PrivacyProtocolIdV1.values().joinToString(",") { protocol ->
            releaseBinding(protocol)
        }
        val activations = PrivacyProtocolIdV1.values().joinToString(",") { protocol ->
            val height = if (protocol == PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1) {
                pgcActivationHeight
            } else {
                2
            }
            """{"protocol_id":${protocolTag(protocol)},"activation_height":$height}"""
        }
        val release = """{"version":1,"catalog_id":"iroha-privacy-exact12-v1","catalog_commitment":${catalogCommitment()},"source":{"source_tree_digest":${bytes(161, 32)},"source_tree_clean":true,"toolchain_id":"kotlin-test-toolchain","toolchain_digest":${bytes(162, 32)},"cargo_lock_digest":${bytes(163, 32)}},"abi_version":1,"abi_hash":${bytes(164, 32)},"syscall_list_digest":${bytes(165, 32)},"executables":[],"protocols":[$bindings],"stage_receipts":[],"proof_artifacts":[],"sdk_packages":[],"hardware_results":[],"release_artifact_set_digest":${bytes(166, 32)},"audits":[],"audit_bundle_digest":${bytes(226, 32)},"release_signatures":[],"manifest_digest":$releaseDigest}"""
        val deployment = """{"version":1,"chain_id":"kotlin-test-chain","network_id":"${NetworkId.fromBytes(ByteArray(32) { 0xD1.toByte() }).literal}","genesis_hash":${bytes(209, 32)},"release_manifest_digest":$releaseDigest,"activation_transaction_digest":${bytes(209, 32)},"activations":[$activations],"validator_roster_digest":${bytes(210, 32)},"endpoint_version":"v1","convergence_height":$convergenceHeight,"converged_state_digest":${bytes(211, 32)},"validator_canaries":[],"validator_signatures":[],"qualification_digest":${bytes(228, 32)}}"""
        return """{"release_manifest":$release,"deployment_qualification":$deployment}"""
    }

    private fun releaseBinding(protocol: PrivacyProtocolIdV1): String {
        val index = protocol.ordinal
        val parameterId = if (index == 1) 1 else 10 + index
        val parameterDigest = if (index == 1) 2 else 30 + index
        val verifierDigest = if (index == 1) 3 else 50 + index
        val statementDigest = if (index == 1) 4 else 70 + index
        val engineDigest = if (index == 1) 5 else 90 + index
        val claim = """{"catalog_commitment":${catalogCommitment()},"protocol_id":${protocolTag(protocol)},"security_model":{"security_model":"${expectedSecurityModelV1(protocol).canonicalLabel}","value":null},"target_security_bits":128,"achieved_security_bits":128,"parameter_digest":${bytes(parameterDigest, 32)},"verifier_digest":${bytes(verifierDigest, 32)},"reduction_digest":${bytes(120 + index, 32)},"audit_bundle_digest":${bytes(226, 32)}}"""
        return """{"protocol_id":${protocolTag(protocol)},"proof_system_id":{"proof_system":"${protocol.expectedProofSystem.canonicalLabel}","value":null},"engine_id":{"engine":"${protocol.expectedEngine.canonicalLabel}","value":null},"parameter_id":${bytes(parameterId, 32)},"parameter_digest":${bytes(parameterDigest, 32)},"verifier_digest":${bytes(verifierDigest, 32)},"statement_schema_digest":${bytes(statementDigest, 32)},"engine_manifest_digest":${bytes(engineDigest, 32)},"security_claim":$claim,"security_claim_digest":${bytes(140 + index, 32)}}"""
    }

    private fun catalogCommitment(): String {
        val hex = "e037f13904a0307c00db15d85cfb406bd79772d20144a949" +
            "def0f3fda78e342e747f65787cbfbffac94f11c369e2bbff"
        return hex.chunked(2).map { it.toInt(16) }.joinToString(",", "[", "]")
    }

    private fun bytes(value: Int, count: Int): String =
        List(count) { value }.joinToString(",", "[", "]")

    private fun consensusLimits(): String =
        """{"max_actions_per_transaction":1,"max_actions_per_block":2,"max_proof_bytes_per_action":9437184,"max_action_bytes":9699840,"max_privacy_bytes_per_transaction":9699840,"max_privacy_bytes_per_block":16711680,"max_statement_and_encrypted_output_bytes_per_transaction":262144,"max_nullifiers_per_action":8,"max_commitments_per_action":8,"retained_root_count":2048}"""
}
