package org.hyperledger.iroha.sdk.client

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.address.AssetDefinitionIdEncoder
import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.hyperledger.iroha.sdk.norito.CRC64
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.testing.TestEd25519Keys

class ParliamentApiV1Test {
    private val attemptId = "ab".repeat(32)
    private val proposalId = "cd".repeat(32)

    @Test
    fun sharedFixturePinsEveryPublicTransitionAutomaticOutcomeAndResultRoot() {
        val fixture = objectValue(Files.readAllBytes(fixturePath()))
        assertEquals("iroha.governance.parliament.api_fixture.v1", fixture["schema"])
        assertEquals(1L, fixture["api_version"])

        val routes = fixture["routes"] as Map<*, *>
        assertEquals(setOf("attempt_draft", "attempt_read", "transition_draft"), routes.keys)
        assertEquals(ParliamentApiV1.ATTEMPT_DRAFT_PATH, routes["attempt_draft"])
        assertEquals(ParliamentApiV1.ATTEMPT_READ_PATH, routes["attempt_read"])
        assertEquals(ParliamentApiV1.TRANSITION_DRAFT_PATH, routes["transition_draft"])
        val wireIds = fixture["wire_ids"] as Map<*, *>
        assertEquals(ParliamentApiV1.ATTEMPT_CREATE_WIRE_ID, wireIds["attempt_create"])
        assertEquals(ParliamentApiV1.TRANSITION_SUBMIT_WIRE_ID, wireIds["transition_submit"])
        assertEquals(ParliamentApiV1.PROPOSAL_KINDS, fixture["proposal_kinds"])
        assertEquals(
            ParliamentApiV1.CONTRACT_LIFECYCLE_ACTIONS,
            fixture["contract_lifecycle_actions"],
        )
        val limits = fixture["limits"] as Map<*, *>
        assertEquals(setOf("attempt_state_bytes", "governance_attempt_sequence_max"), limits.keys)
        assertEquals(ParliamentApiV1.MAX_STATE_BYTES, (limits["attempt_state_bytes"] as Number).toInt())
        assertEquals(
            ParliamentApiV1.MAX_GOVERNANCE_ATTEMPT_RETRIES,
            (limits["governance_attempt_sequence_max"] as Number).toInt(),
        )

        val transitions = fixture["public_transitions"] as List<*>
        assertEquals(13, transitions.size)
        assertEquals(ParliamentApiV1.PUBLIC_TRANSITIONS.size, transitions.size)
        ParliamentApiV1.PUBLIC_TRANSITIONS.zip(transitions).forEach { (layout, raw) ->
            val entry = raw as Map<*, *>
            assertEquals(layout.noritoIndex, (entry["norito_index"] as Number).toInt())
            assertEquals(layout.noritoIndex.toString(16).padStart(2, '0'), entry["norito_prefix_hex"])
            assertEquals(layout.jsonTag, entry["json_tag"])
            assertEquals(
                if (layout.jsonPayloadRequired) "required" else "forbidden",
                entry["json_payload"],
            )
            assertEquals(layout.eventKindIndex, (entry["event_kind_index"] as Number).toInt())

            val transitionJson = if (layout.jsonPayloadRequired) {
                """{"transition":"${layout.jsonTag}","payload":{}}"""
                    .toByteArray(StandardCharsets.UTF_8)
            } else {
                """{"transition":"${layout.jsonTag}"}"""
                    .toByteArray(StandardCharsets.UTF_8)
            }
            ParliamentApiV1.transitionDraftRequestJson(attemptId, transitionJson)
        }

        val outcomes = fixture["automatic_execution_outcomes"] as List<*>
        assertEquals(ParliamentApiV1.AUTOMATIC_EXECUTION_OUTCOMES.size, outcomes.size)
        ParliamentApiV1.AUTOMATIC_EXECUTION_OUTCOMES.zip(outcomes).forEach { (layout, raw) ->
            val entry = raw as Map<*, *>
            assertEquals(layout.noritoIndex, (entry["norito_index"] as Number).toInt())
            assertEquals(layout.jsonTag, entry["json_tag"])
            assertEquals(layout.eventKind, entry["event_kind"])
            assertEquals(layout.eventKindIndex, (entry["event_kind_index"] as Number).toInt())
        }

        val domains = fixture["digest_domains"] as Map<*, *>
        assertEquals(ParliamentApiV1.PUBLIC_TRANSITION_DIGEST_DOMAIN, domains["public_transition"])
        assertEquals(
            ParliamentApiV1.AUTOMATIC_OUTCOME_DIGEST_DOMAIN,
            domains["automatic_execution_outcome"],
        )
        val fixtureRootDomains = (fixture["certificate_result_roots"] as List<*>)
            .associate { raw ->
                val entry = raw as Map<*, *>
                entry["name"] as String to entry["domain"] as? String
            }
        assertEquals(4, fixtureRootDomains.size)
        assertEquals(ParliamentApiV1.CERTIFICATE_RESULT_ROOT_DOMAINS, fixtureRootDomains)

        val binding = fixture["certificate_body_binding"] as Map<*, *>
        assertEquals(
            ParliamentApiV1.CERTIFICATE_BODY_BINDING_NORITO_FIELDS,
            binding["norito_field_order"],
        )
        val publicFinding = binding["public_nonbinding_body"] as Map<*, *>
        assertEquals(
            ParliamentApiV1.PUBLIC_FINDING_CERTIFICATE_NORITO_FIELDS,
            publicFinding["public_finding_norito_field_order"],
        )
        assertEquals("ceil(2 * original_seats / 3)", publicFinding["quorum"])
        assertEquals(
            "strictly increasing distinct nonzero assignment ids",
            publicFinding["endorsing_assignments"],
        )
        assertEquals("endorsing_assignments.length == quorum", publicFinding["endorsements"])
        val privateJury = binding["private_jury"] as Map<*, *>
        assertEquals("forbidden", privateJury["public_finding"])
        assertEquals("ballot.tally.original_seats", privateJury["original_seats"])
        val noResultKinds = fixture["no_result_kinds"] as List<*>
        assertEquals(5, noResultKinds.size)
        assertEquals(
            ParliamentApiV1.NO_RESULT_KINDS.map { it.jsonTag },
            noResultKinds.map { (it as Map<*, *>)["json_tag"] },
        )
        assertEquals(
            ParliamentApiV1.NO_RESULT_KINDS.map { it.noritoIndex },
            noResultKinds.map { ((it as Map<*, *>)["norito_index"] as Number).toInt() },
        )
        val bodyState = fixture["attempt_read_body_state"] as Map<*, *>
        assertEquals(ParliamentApiV1.BODY_STATE_FIELDS, bodyState["json_fields"])
        assertEquals(ParliamentApiV1.CANONICAL_BODY_ORDER, fixture["canonical_body_order"])
        assertEquals(
            "strictly increasing subset of canonical_body_order",
            (fixture["attempt_read_body_presentation"] as Map<*, *>)["subset_rule"],
        )
    }

    @Test
    fun attemptBuilderAdmitsExactlyTheTenFirstReleaseProposalKinds() {
        ParliamentApiV1.PROPOSAL_KINDS.forEach { kind ->
            val request = objectValue(
                ParliamentApiV1.attemptDraftRequestJson(
                    proposal(kind),
                    0,
                ),
            )
            assertEquals(kind, (request["proposal"] as Map<*, *>)["kind"])
        }
        assertEquals(10, ParliamentApiV1.PROPOSAL_KINDS.size)

        val fullU64Policy = validProposal("ValidationFeePolicy")
        @Suppress("UNCHECKED_CAST")
        val fullU64PolicyValue =
            (fullU64Policy["payload"] as MutableMap<String, Any?>)["policy"] as MutableMap<String, Any?>
        fullU64PolicyValue["policy_version"] = "18446744073709551615"
        fullU64PolicyValue["previous_policy_hash"] = "01".repeat(32)
        ParliamentApiV1.Proposal.fromJson(encode(fullU64Policy))

        listOf(
            "ProposeDeployContract",
            "EnactReferendum",
            "FinalizeReferendum",
            "deploy_contract",
            "runtimeUpgrade",
            "Unknown",
        ).forEach { kind ->
            assertFailsWith<IllegalArgumentException>("accepted retired or unknown tag $kind") {
                ParliamentApiV1.Proposal.fromJson(
                    bytes("""{"kind":"$kind","payload":{}}"""),
                )
            }
        }
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.Proposal.fromJson(
                bytes("""{"proposal_kind":"RuntimeUpgrade","payload":{}}"""),
            )
        }
    }

    @Test
    fun contractLifecycleActionInventoryIsClosed() {
        ParliamentApiV1.CONTRACT_LIFECYCLE_ACTIONS.forEach { action ->
            val proposal = validProposal("ContractLifecycleGovernance")
            @Suppress("UNCHECKED_CAST")
            val payload = proposal["payload"] as MutableMap<String, Any?>
            val actionPayload: Any? = when (action) {
                "Activate" -> linkedMapOf(
                    "code_hash" to "11".repeat(32),
                    "abi_hash" to "22".repeat(32),
                    "abi_version" to 1,
                    "manifest_provenance" to null,
                )
                "Deactivate" -> linkedMapOf("expected_code_hash" to "11".repeat(32))
                "OfferOwnership" -> linkedMapOf("new_owner" to account(5))
                "CancelOwnershipOffer", "AcceptParliamentOwnership" -> null
                "CompleteEmergencyHoldRetrospective" -> linkedMapOf(
                    "hold_proposal_content_id" to List(32) { 0x51 },
                    "hold_governance_attempt_id" to List(32) { 0x52 },
                    "incident_digest" to List(32) { 0x53 },
                    "retrospective_finding_root" to List(32) { 0x54 },
                )
                else -> error("unsupported fixture action $action")
            }
            payload["action"] = linkedMapOf("action" to action, "payload" to actionPayload)
            ParliamentApiV1.Proposal.fromJson(encode(proposal))
        }

        val proposal = validProposal("ContractLifecycleGovernance")
        @Suppress("UNCHECKED_CAST")
        val payload = proposal["payload"] as MutableMap<String, Any?>
        payload["action"] = linkedMapOf("action" to "Unknown", "payload" to null)
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.Proposal.fromJson(encode(proposal))
        }
    }

    @Test
    fun sccpRouteGovernanceAdmitsOnlyTheClosedProposalEnvelope() {
        fun sccpProposal(edit: (MutableMap<String, Any?>) -> Unit): ByteArray {
            val proposal = validProposal("SccpRouteGovernance")
            @Suppress("UNCHECKED_CAST")
            val payload = proposal["payload"] as MutableMap<String, Any?>
            @Suppress("UNCHECKED_CAST")
            val sccp = payload["proposal"] as MutableMap<String, Any?>
            edit(sccp)
            return encode(proposal)
        }
        fun subject(subject: String, key: Any?): MutableMap<String, Any?> = linkedMapOf(
            "base_revisions" to listOf(
                linkedMapOf(
                    "subject" to linkedMapOf("subject" to subject, "key" to key),
                    "revision" to 0,
                ),
            ),
        )

        listOf(
            subject("parameters", null),
            subject("light_client", bscMainnet()),
            subject("forgery_hold", bscMainnet()),
        ).forEach { replacement ->
            ParliamentApiV1.Proposal.fromJson(sccpProposal { it.putAll(replacement) })
        }

        // Native typed bodies and exact action-to-subject coverage remain separate.
        // Every current tag must survive the canonical SDK's closed envelope decoder.
        for (action in listOf(
            "register_route", "activate_revision", "switch_revision", "deactivate_outbound",
            "retire_revision", "remove_staged", "release_stranded", "set_taira_paused",
            "set_destination_paused", "initialize_light_client", "install_trusted_checkpoint",
            "freeze_light_client", "set_parameters", "activate_light_client_profile",
            "attest_deployment_progress", "quarantine_revision", "open_reconciliation",
            "set_fast_pause_suspended",
        )) {
            ParliamentApiV1.Proposal.fromJson(sccpProposal {
                it["actions"] = listOf(linkedMapOf("action" to action, "payload" to linkedMapOf<String, Any?>()))
            })
            for (payload in listOf(null, emptyList<Any?>(), "object", true, 0)) {
                assertFailsWith<IllegalArgumentException>("accepted $action with payload $payload") {
                    ParliamentApiV1.Proposal.fromJson(sccpProposal {
                        it["actions"] = listOf(linkedMapOf("action" to action, "payload" to payload))
                    })
                }
            }
            for (entry in listOf(
                linkedMapOf("action" to action),
                linkedMapOf("action" to action, "payload" to linkedMapOf<String, Any?>(), "extra" to 0),
            )) {
                assertFailsWith<IllegalArgumentException>("accepted action envelope $entry") {
                    ParliamentApiV1.Proposal.fromJson(sccpProposal { it["actions"] = listOf(entry) })
                }
            }
        }
        for (kind in listOf("route", "route_control", "light_client", "forgery_hold", "fast_hold", "fast_pause_control")) {
            for (network in listOf("ethereum_mainnet", "bsc_mainnet", "ton_mainnet")) {
                ParliamentApiV1.Proposal.fromJson(sccpProposal {
                    it.putAll(subject(kind, linkedMapOf("network" to network, "profile" to null)))
                })
            }
            for (key in listOf(
                null, "ea0130", emptyMap<String, Any?>(),
                linkedMapOf("network" to "sora_taira", "profile" to null),
                linkedMapOf("network" to "tron_mainnet", "profile" to null),
                linkedMapOf("network" to "bsc_mainnet", "profile" to "default"),
                linkedMapOf("network" to "bsc_mainnet"),
                linkedMapOf("network" to "bsc_mainnet", "profile" to null, "extra" to 0),
            )) {
                assertFailsWith<IllegalArgumentException>("accepted $kind coordinate $key") {
                    ParliamentApiV1.Proposal.fromJson(sccpProposal { it.putAll(subject(kind, key)) })
                }
            }
            for (coordinate in listOf(
                linkedMapOf("subject" to kind),
                linkedMapOf("subject" to kind, "key" to bscMainnet(), "extra" to 0),
            )) {
                assertFailsWith<IllegalArgumentException>("accepted subject envelope $coordinate") {
                    ParliamentApiV1.Proposal.fromJson(sccpProposal {
                        it["base_revisions"] = listOf(linkedMapOf("subject" to coordinate, "revision" to 0))
                    })
                }
            }
        }

        val rejected = listOf<(MutableMap<String, Any?>) -> Unit>(
            { it["anchor"] = null },
            { it.remove("base_revisions") },
            { it["base_revisions"] = emptyList<Any?>() },
            { it["actions"] = emptyList<Any?>() },
            { proposal ->
                val action = (proposal["actions"] as List<*>).single()
                proposal["actions"] = List(17) { action }
            },
            { it.putAll(subject("sora_taira", bscMainnet())) },
            { it.putAll(subject("parameters", bscMainnet())) },
            {
                it.putAll(
                    subject(
                        "light_client",
                        linkedMapOf("network" to "tron_mainnet", "profile" to null),
                    ),
                )
            },
            { it.putAll(subject("bridge_key_fault", "ea0130" + "ab".repeat(48))) },
            { it.putAll(subject("bridge_key_fault", "ea0130" + "AB".repeat(48))) },
            {
                it.putAll(
                    subject(
                        "route",
                        linkedMapOf("network" to "sora_taira", "profile" to null),
                    ),
                )
            },
            {
                it["actions"] = listOf(
                    linkedMapOf("action" to "Remove", "payload" to linkedMapOf<String, Any?>()),
                )
            },
            {
                it["actions"] = listOf(
                    linkedMapOf("action" to "clear_bridge_key_fault", "payload" to linkedMapOf<String, Any?>()),
                )
            },
            {
                it["actions"] = listOf(
                    linkedMapOf("action" to "freeze_light_client", "payload" to null),
                )
            },
        )
        rejected.forEachIndexed { index, edit ->
            assertFailsWith<IllegalArgumentException>("accepted SCCP proposal mutation $index") {
                ParliamentApiV1.Proposal.fromJson(sccpProposal(edit))
            }
        }
        assertFailsWith<IllegalArgumentException>("accepted the anchor payload") {
            val proposal = validProposal("SccpRouteGovernance")
            proposal["payload"] = linkedMapOf(
                "anchor" to linkedMapOf(
                    "network_id" to networkId(),
                    "action" to linkedMapOf<String, Any?>(),
                ),
            )
            ParliamentApiV1.Proposal.fromJson(encode(proposal))
        }
    }

    @Test
    fun effectSensitiveProposalsRequireExactOperator() {
        listOf("DeployContract", "RuntimeUpgrade", "ContractLifecycleGovernance").forEach { kind ->
            val valid = validProposal(kind)
            ParliamentApiV1.Proposal.fromJson(encode(valid))

            @Suppress("UNCHECKED_CAST")
            val payload = valid["payload"] as MutableMap<String, Any?>
            payload.remove("proposal_operator")
            assertFailsWith<IllegalArgumentException>("accepted missing operator for $kind") {
                ParliamentApiV1.Proposal.fromJson(encode(valid))
            }
            payload["proposal_operator"] = "not-an-account"
            assertFailsWith<IllegalArgumentException>("accepted malformed operator for $kind") {
                ParliamentApiV1.Proposal.fromJson(encode(valid))
            }
        }
    }

    @Test
    fun contractLifecycleUnitActionsRequireExplicitNullPayload() {
        listOf("CancelOwnershipOffer", "AcceptParliamentOwnership").forEach { action ->
            val proposal = validProposal("ContractLifecycleGovernance")
            @Suppress("UNCHECKED_CAST")
            val payload = proposal["payload"] as MutableMap<String, Any?>
            payload["action"] = linkedMapOf("action" to action, "payload" to null)
            ParliamentApiV1.Proposal.fromJson(encode(proposal))

            @Suppress("UNCHECKED_CAST")
            (payload["action"] as MutableMap<String, Any?>).remove("payload")
            assertFailsWith<IllegalArgumentException> {
                ParliamentApiV1.Proposal.fromJson(encode(proposal))
            }
        }
    }

    @Test
    fun globalDataTriggerPermissionRequiresExactAccountAndClosedUnitAction() {
        listOf("grant", "revoke").forEach { action ->
            val proposal = validProposal("GlobalDataTriggerPermissionGovernance")
            @Suppress("UNCHECKED_CAST")
            val payload = proposal["payload"] as MutableMap<String, Any?>
            payload["action"] = linkedMapOf("action" to action, "value" to null)
            ParliamentApiV1.Proposal.fromJson(encode(proposal))
        }

        val malformed = validProposal("GlobalDataTriggerPermissionGovernance")
        @Suppress("UNCHECKED_CAST")
        val action =
            ((malformed["payload"] as MutableMap<String, Any?>)["action"] as MutableMap<String, Any?>)
        action["value"] = emptyMap<String, Any?>()
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.Proposal.fromJson(encode(malformed))
        }
        action["value"] = null
        action["action"] = "delegate"
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.Proposal.fromJson(encode(malformed))
        }
    }

    @Test
    fun retiredKagemushaProposalKindsCannotEnterAttemptDrafts() {
        listOf(
            "KagemushaVerifierPolicyInstall",
            "KagemushaVerifierReleaseInstall",
            "KagemushaVerifierReleaseActivate",
            "KagemushaVerifierReleaseRetire",
        ).forEach { kind ->
            assertTrue(kind !in ParliamentApiV1.PROPOSAL_KINDS)
            listOf(null, emptyMap<String, Any?>(), mapOf("proposal_operator" to "invalid")).forEach { payload ->
                val error = assertFailsWith<IllegalArgumentException>("accepted retired proposal $kind") {
                    ParliamentApiV1.Proposal.fromJson(encode(linkedMapOf("kind" to kind, "payload" to payload)))
                }
                assertEquals("proposal.kind is unknown or retired", error.message)
            }
        }
    }

    @Test
    fun attemptDraftSequenceAcceptsSixteenAndRejectsSeventeen() {
        val accepted = objectValue(
            ParliamentApiV1.attemptDraftRequestJson(
                proposal("RuntimeUpgrade"),
                ParliamentApiV1.MAX_GOVERNANCE_ATTEMPT_RETRIES.toLong(),
            ),
        )
        assertEquals(
            ParliamentApiV1.MAX_GOVERNANCE_ATTEMPT_RETRIES.toLong(),
            accepted["attempt_sequence"],
        )
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.attemptDraftRequestJson(
                proposal("RuntimeUpgrade"),
                ParliamentApiV1.MAX_GOVERNANCE_ATTEMPT_RETRIES.toLong() + 1,
            )
        }
    }

    @Test
    fun proposalAdmissionRejectsMissingUnknownAndMalformedNestedFields() {
        val runtime = validProposal("RuntimeUpgrade")
        @Suppress("UNCHECKED_CAST")
        val manifest = (runtime["payload"] as MutableMap<String, Any?>)["manifest"] as MutableMap<String, Any?>
        manifest.remove("provenance")
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.Proposal.fromJson(encode(runtime))
        }

        val provider = validProposal("SorafsProviderGovernance")
        @Suppress("UNCHECKED_CAST")
        val action = ((provider["payload"] as MutableMap<String, Any?>)["action"] as MutableMap<String, Any?>)
        action["legacy_owner"] = account(9)
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.Proposal.fromJson(encode(provider))
        }

        val malformedProvider = validProposal("SorafsProviderGovernance")
        @Suppress("UNCHECKED_CAST")
        val providerValue = (((malformedProvider["payload"] as MutableMap<String, Any?>)["action"] as MutableMap<String, Any?>)["value"] as MutableMap<String, Any?>)
        providerValue["provider_id"] = List(32) { 1 }
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.Proposal.fromJson(encode(malformedProvider))
        }

        val malformedAccount = validProposal("MusubiRegistryGovernance")
        @Suppress("UNCHECKED_CAST")
        val musubiValue = (((malformedAccount["payload"] as MutableMap<String, Any?>)["value"] as MutableMap<String, Any?>))
        musubiValue["owners"] = listOf("alice@legacy")
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.Proposal.fromJson(encode(malformedAccount))
        }

        val zeroRetrospective = validProposal("ContractLifecycleGovernance")
        @Suppress("UNCHECKED_CAST")
        val retrospectivePayload =
            (((zeroRetrospective["payload"] as MutableMap<String, Any?>)["action"] as MutableMap<String, Any?>)["payload"] as MutableMap<String, Any?>)
        retrospectivePayload["retrospective_finding_root"] = List(32) { 0 }
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.Proposal.fromJson(encode(zeroRetrospective))
        }

        val excessiveHold = validProposal("ContractEmergencyHold")
        @Suppress("UNCHECKED_CAST")
        val holdPayload = excessiveHold["payload"] as MutableMap<String, Any?>
        holdPayload["duration_blocks"] = 3_601
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.Proposal.fromJson(encode(excessiveHold))
        }

        val impreciseHeight = validProposal("RuntimeUpgrade")
        @Suppress("UNCHECKED_CAST")
        val impreciseManifest = (impreciseHeight["payload"] as MutableMap<String, Any?>)["manifest"] as MutableMap<String, Any?>
        impreciseManifest["start_height"] = BigInteger("9007199254740992")
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.Proposal.fromJson(encode(impreciseHeight))
        }
    }

    @Test
    fun initialSortitionDraftUsesOnlyTheEnclosingAttempt() {
        val layout = ParliamentApiV1.PUBLIC_TRANSITIONS.single {
            it.jsonTag == "RegisterInitialSortition"
        }
        assertEquals(12, layout.noritoIndex)
        assertEquals(15, layout.eventKindIndex)
        assertEquals(false, layout.jsonPayloadRequired)
        val transition = bytes("""{"transition":"RegisterInitialSortition"}""")
        val request = objectValue(ParliamentApiV1.transitionDraftRequestJson(attemptId, transition))
        assertEquals(setOf("version", "governance_attempt_id", "transition"), request.keys)
        assertEquals(1L, request["version"])
        assertEquals(attemptId, request["governance_attempt_id"])
        assertEquals(mapOf("transition" to "RegisterInitialSortition"), request["transition"])
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.transitionDraftRequestJson("00".repeat(32), transition)
        }
        for (payload in listOf("null", "{}", "{\"target_seats\":1}")) {
            assertFailsWith<IllegalArgumentException>("unit intent accepted payload $payload") {
                ParliamentApiV1.transitionDraftRequestJson(
                    attemptId,
                    bytes("""{"transition":"RegisterInitialSortition","payload":$payload}"""),
                )
            }
        }
        for (field in listOf(
            "candidates", "candidate_root", "candidate_count", "target_seats",
            "request_height", "pulse_height", "beacon_session_id", "body",
            "body_election_attempt_id", "sequence",
        )) {
            assertFailsWith<IllegalArgumentException>("unit intent accepted caller field $field") {
                ParliamentApiV1.transitionDraftRequestJson(
                    attemptId,
                    bytes("""{"transition":"RegisterInitialSortition","$field":"caller selected"}"""),
                )
            }
        }
    }

    @Test
    fun transitionBuilderRejectsRemovedOutcomeTagsAndPayloadAliases() {
        for (tag in listOf(
            "ConstructCertificate",
            "MarkEnacted",
            "MarkSuperseded",
            "MarkExecutionFailed",
            "PlainBallotFallback",
        )) {
            assertFailsWith<IllegalArgumentException>("accepted removed or unknown tag $tag") {
                ParliamentApiV1.transitionDraftRequestJson(
                    attemptId,
                    bytes("""{"transition":"$tag","payload":{}}"""),
                )
            }
        }
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.transitionDraftRequestJson(
                attemptId,
                bytes("""{"transition":"CompleteQualification","payload":{}}"""),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.transitionDraftRequestJson(
                attemptId,
                bytes("""{"transition":"EscalateRisk"}"""),
            )
        }
    }

    @Test
    fun requestBuildersExposeOnlyCanonicalV1FieldsAndRoutes() {
        val attempt = objectValue(ParliamentApiV1.attemptDraftRequestJson(proposal("RuntimeUpgrade"), 7))
        assertEquals(setOf("version", "proposal", "attempt_sequence"), attempt.keys)
        assertEquals(1L, attempt["version"])
        assertEquals(7L, attempt["attempt_sequence"])

        val transition = bytes("""{"transition":"CompleteQualification"}""")
        val draft = objectValue(
            ParliamentApiV1.transitionDraftRequestJson(attemptId, transition),
        )
        assertEquals(
            setOf("version", "governance_attempt_id", "transition"),
            draft.keys,
        )
        assertEquals(attemptId, draft["governance_attempt_id"])
        assertEquals(
            "/v1/gov/parliament/attempts/$attemptId",
            ParliamentApiV1.attemptReadPath(attemptId),
        )

        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.transitionDraftRequestJson(
                attemptId,
                bytes("""{"transition":"CompleteQualification","authority":"alice"}"""),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.attemptReadPath(attemptId.uppercase())
        }
    }

    @Test
    fun strictDraftParsersBindVersionIdentifiersDigestAndWireIds() {
        val attemptResponse = linkedMapOf<String, Any?>(
            "version" to 1,
            "proposal_content_id" to proposalId,
            "governance_attempt_id" to attemptId,
            "tx_instructions" to listOf(
                mapOf(
                    "wire_id" to ParliamentApiV1.ATTEMPT_CREATE_WIRE_ID,
                    "payload_hex" to "0102",
                ),
            ),
        )
        val parsedAttempt = ParliamentApiV1.parseAttemptDraftResponse(
            encode(attemptResponse),
            proposalId,
            attemptId,
        )
        assertEquals(attemptId, parsedAttempt.governanceAttemptId)

        val digest = ByteArray(32) { 0x55.toByte() }
        val transitionResponse = linkedMapOf<String, Any?>(
            "version" to 1,
            "governance_attempt_id" to attemptId,
            "transition_kind" to mapOf("kind" to "CompleteQualification"),
            "transition_digest" to digest.map { it.toInt() and 0xff },
            "tx_instructions" to listOf(
                mapOf(
                    "wire_id" to ParliamentApiV1.TRANSITION_SUBMIT_WIRE_ID,
                    "payload_hex" to "0304",
                ),
            ),
        )
        val parsedTransition = ParliamentApiV1.parseTransitionDraftResponse(
            encode(transitionResponse),
            attemptId,
            "CompleteQualification",
            digest,
        )
        assertContentEquals(digest, parsedTransition.transitionDigest)

        val wrongVersion = LinkedHashMap(attemptResponse)
        wrongVersion["version"] = 2
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseAttemptDraftResponse(
                encode(wrongVersion),
                proposalId,
                attemptId,
            )
        }
        val unknown = LinkedHashMap(attemptResponse)
        unknown["private_key"] = "secret"
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseAttemptDraftResponse(encode(unknown), proposalId, attemptId)
        }
    }

    @Test
    fun readParserRejectsAliasesAndOversizedOrMismatchedState() {
        val response = certifiedReadResponse(listOf("rules-committee", "agenda-council"))
        val parsed = ParliamentApiV1.parseAttemptReadResponse(encode(response), attemptId)
        assertEquals("9", parsed.currentHeight)
        assertEquals(listOf("rules-committee", "agenda-council"), parsed.requiredBodyOrder)
        assertEquals("rules-committee", parsed.bodyStates.first().body)
        assertEquals(listOf("rules-committee", "agenda-council"), parsed.certificateBodyOrder)
        assertEquals(
            listOf(
                listOf("60".repeat(32), "61".repeat(32)),
                listOf("62".repeat(32), "63".repeat(32)),
            ),
            parsed.publicFindingBindings.map { it.endorsingAssignments },
        )

        val canonicalOrder = LinkedHashMap(response)
        @Suppress("UNCHECKED_CAST")
        val canonicalAttempt = LinkedHashMap(response["attempt"] as Map<String, Any?>)
        canonicalAttempt["stage"] = mapOf("stage" to "Qualification")
        canonicalAttempt["status"] = mapOf("status" to "Active")
        canonicalOrder["attempt"] = canonicalAttempt
        canonicalOrder["certificate"] = null
        canonicalOrder["required_bodies"] = ParliamentApiV1.CANONICAL_BODY_ORDER.map { body ->
            mapOf(
                "body" to body,
                "decision_mode" to mapOf(
                    "mode" to if (body == "policy-jury" || body == "confirmation-jury") {
                        "HiddenBindingBallot"
                    } else {
                        "PublicFinding"
                    },
                ),
            )
        }
        canonicalOrder["body_states"] = ParliamentApiV1.CANONICAL_BODY_ORDER.map { body ->
            linkedMapOf<String, Any?>(
                "body" to body,
                "body_instance_id" to null,
                "status" to null,
                "public_finding_opened_at_height" to null,
                "public_finding_phase_blocks" to null,
                "public_finding_deadline_height" to null,
                "no_result_kind" to null,
                "no_result_height" to null,
            )
        }
        val canonicalParsed = ParliamentApiV1.parseAttemptReadResponse(
            encode(canonicalOrder),
            attemptId,
        )
        assertEquals(ParliamentApiV1.CANONICAL_BODY_ORDER, canonicalParsed.requiredBodyOrder)
        assertEquals(
            ParliamentApiV1.CANONICAL_BODY_ORDER,
            canonicalParsed.bodyStates.map { it.body },
        )
        assertEquals(emptyList(), canonicalParsed.certificateBodyOrder)

        val reordered = LinkedHashMap(canonicalOrder)
        @Suppress("UNCHECKED_CAST")
        val reorderedRequired =
            (canonicalOrder["required_bodies"] as List<Map<String, Any?>>).toMutableList()
        val first = reorderedRequired[0]
        reorderedRequired[0] = reorderedRequired[1]
        reorderedRequired[1] = first
        reordered["required_bodies"] = reorderedRequired
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseAttemptReadResponse(encode(reordered), attemptId)
        }

        val alias = LinkedHashMap(response)
        alias["statePayloadHex"] = alias.remove("state_payload_hex")
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseAttemptReadResponse(encode(alias), attemptId)
        }
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseAttemptReadResponse(encode(response), "66".repeat(32))
        }

        val barePayload = LinkedHashMap(response)
        barePayload["state_payload_hex"] = "0102"
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseAttemptReadResponse(encode(barePayload), attemptId)
        }

        val badChecksum = LinkedHashMap(response)
        val tampered = stateFrame().also { it[it.lastIndex] = (it.last() + 1).toByte() }
        badChecksum["state_payload_hex"] = tampered.toHex()
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseAttemptReadResponse(encode(badChecksum), attemptId)
        }

        val wrongDeadline = LinkedHashMap(response)
        @Suppress("UNCHECKED_CAST")
        val wrongStates = (response["body_states"] as List<Map<String, Any?>>)
            .map { LinkedHashMap(it) }
        wrongStates[0]["public_finding_deadline_height"] = 9
        wrongDeadline["body_states"] = wrongStates
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseAttemptReadResponse(encode(wrongDeadline), attemptId)
        }

        assertEquals(8, ParliamentApiV1.BODY_STATE_FIELDS.size)
        val unknownField = LinkedHashMap(response)
        @Suppress("UNCHECKED_CAST")
        val unknownFieldStates = (response["body_states"] as List<Map<String, Any?>>)
            .map { LinkedHashMap(it) }
        unknownFieldStates[0]["unexpected"] = null
        unknownField["body_states"] = unknownFieldStates
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseAttemptReadResponse(encode(unknownField), attemptId)
        }
        val missingField = LinkedHashMap(response)
        @Suppress("UNCHECKED_CAST")
        val missingFieldStates = (response["body_states"] as List<Map<String, Any?>>)
            .map { LinkedHashMap(it) }
        missingFieldStates[0].remove("no_result_height")
        missingField["body_states"] = missingFieldStates
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseAttemptReadResponse(encode(missingField), attemptId)
        }

        val unsorted = LinkedHashMap(response)
        @Suppress("UNCHECKED_CAST")
        val certificate = LinkedHashMap(response["certificate"] as Map<String, Any?>)
        @Suppress("UNCHECKED_CAST")
        val bindings = (certificate["body_bindings"] as List<Map<String, Any?>>)
            .map { LinkedHashMap(it) }
        @Suppress("UNCHECKED_CAST")
        val finding = LinkedHashMap(bindings[0]["public_finding"] as Map<String, Any?>)
        finding["endorsing_assignments"] = listOf("61".repeat(32), "60".repeat(32))
        bindings[0]["public_finding"] = finding
        certificate["body_bindings"] = bindings
        unsorted["certificate"] = certificate
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseAttemptReadResponse(encode(unsorted), attemptId)
        }

        fun forgedCertificateResponse(
            mutate: (
                MutableMap<String, Any?>,
                MutableMap<String, Any?>,
                MutableMap<String, Any?>,
            ) -> Unit,
        ): MutableMap<String, Any?> {
            val forged = LinkedHashMap(response)
            @Suppress("UNCHECKED_CAST")
            val forgedCertificate = LinkedHashMap(
                response["certificate"] as Map<String, Any?>,
            )
            @Suppress("UNCHECKED_CAST")
            val forgedBindings = (forgedCertificate["body_bindings"] as List<Map<String, Any?>>)
                .map { LinkedHashMap(it) }
            val forgedBinding = forgedBindings[0]
            @Suppress("UNCHECKED_CAST")
            val forgedRequest = LinkedHashMap(
                forgedBinding["sortition_request"] as Map<String, Any?>,
            )
            forgedBinding["sortition_request"] = forgedRequest
            forgedCertificate["body_bindings"] = forgedBindings
            forged["certificate"] = forgedCertificate
            mutate(forgedCertificate, forgedBinding, forgedRequest)
            return forged
        }

        for (forged in listOf(
            forgedCertificateResponse { certificate, _, _ ->
                certificate["proposal_content_id"] = "ee".repeat(32)
            },
            forgedCertificateResponse { certificate, _, _ ->
                certificate["governance_attempt_sequence"] = 1
            },
            forgedCertificateResponse { certificate, _, _ ->
                certificate["risk_tier"] = mapOf("tier" to "Emergency")
            },
            forgedCertificateResponse { certificate, _, _ ->
                certificate["policy_version"] = 2
            },
            forgedCertificateResponse { certificate, _, _ ->
                certificate["enact_at_height"] = 8
            },
            forgedCertificateResponse { certificate, _, _ ->
                certificate["certified_at_height"] = 7
            },
            forgedCertificateResponse { _, _, request ->
                request["beacon_session_id"] = "ee".repeat(32)
            },
            forgedCertificateResponse { _, _, request ->
                request["request_height"] = 0
            },
            forgedCertificateResponse { _, binding, _ ->
                binding["election_attempt_sequence"] = 17
            },
            forgedCertificateResponse { _, binding, _ ->
                binding["original_seats"] = 4
            },
            forgedCertificateResponse { _, binding, _ ->
                binding["original_seats"] = ParliamentApiV1.MAX_BODY_TARGET_SEATS + 1
            },
            forgedCertificateResponse { _, binding, _ ->
                binding["ballot"] = linkedMapOf<String, Any?>()
            },
        )) {
            assertFailsWith<IllegalArgumentException> {
                ParliamentApiV1.parseAttemptReadResponse(encode(forged), attemptId)
            }
        }

        val largeElectorate = forgedCertificateResponse { _, _, request ->
            request["candidate_count"] = 1_001
        }
        ParliamentApiV1.parseAttemptReadResponse(encode(largeElectorate), attemptId)

        val zeroHeadVersion = forgedCertificateResponse { certificate, _, _ ->
            certificate["expected_head"] = mapOf(
                "state" to "Present",
                "head" to mapOf(
                    "subject_id" to List(32) { 0x55 },
                    "version" to 0,
                    "head_root" to List(32) { 0x55 },
                ),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseAttemptReadResponse(encode(zeroHeadVersion), attemptId)
        }

        val wrongMode = certifiedReadResponse(listOf("rules-committee"))
        wrongMode["required_bodies"] = listOf(
            mapOf(
                "body" to "rules-committee",
                "decision_mode" to mapOf("mode" to "HiddenBindingBallot"),
            ),
        )
        assertEquals(
            "required_bodies[0] uses the wrong decision protocol",
            assertFailsWith<IllegalArgumentException> {
                ParliamentApiV1.parseAttemptReadResponse(encode(wrongMode), attemptId)
            }.message,
        )
    }

    @Test
    fun bodyStateNoResultKindsFollowTheClosedInventoryAndDecisionProtocol() {
        val publicKinds = setOf("PublicFindingQuorumUnreachable", "PublicFindingDeadlineExpired")
        assertEquals(5, ParliamentApiV1.NO_RESULT_KINDS.size)
        fun response(publicKind: String?, privateKind: String?): ByteArray {
            val read = certifiedReadResponse(listOf("rules-committee", "policy-jury"))
            read["certificate"] = null
            @Suppress("UNCHECKED_CAST")
            val states = (read["body_states"] as List<Map<String, Any?>>).map { LinkedHashMap(it) }
            listOf(publicKind, privateKind).forEachIndexed { index, kind ->
                if (kind != null) {
                    states[index]["status"] = mapOf("status" to "NoResult")
                    states[index]["no_result_kind"] = mapOf("reason" to kind)
                    states[index]["no_result_height"] = 5
                }
            }
            read["body_states"] = states
            return encode(read)
        }

        for (layout in ParliamentApiV1.NO_RESULT_KINDS) {
            val tag = layout.jsonTag
            val onPublicBody = tag in publicKinds
            val admitted = ParliamentApiV1.parseAttemptReadResponse(
                if (onPublicBody) response(tag, null) else response(null, tag),
                attemptId,
            )
            val noResult = admitted.bodyStates.single { it.noResultKind != null }
            assertEquals(tag, noResult.noResultKind)
            assertEquals("5", noResult.noResultHeight)
            assertEquals(if (onPublicBody) "rules-committee" else "policy-jury", noResult.body)
            assertFailsWith<IllegalArgumentException>("accepted $tag on the wrong decision protocol") {
                ParliamentApiV1.parseAttemptReadResponse(
                    if (onPublicBody) response(null, tag) else response(tag, null),
                    attemptId,
                )
            }
        }
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseAttemptReadResponse(response("UnknownNoResultKind", null), attemptId)
        }
    }

    @Test
    fun certificateWithAPrivateJuryBindingIsRejectedUntilTheAnonymousBallotBindingIsSupported() {
        // Public-only pipelines parse; a private-jury body binding is withheld, whatever it carries.
        val publicOnly = certifiedReadResponse(listOf("rules-committee", "agenda-council"))
        ParliamentApiV1.parseAttemptReadResponse(encode(publicOnly), attemptId)

        for ((bodies, index) in listOf(
            listOf("policy-jury") to 0,
            listOf("rules-committee", "policy-jury") to 1,
            listOf("rules-committee", "agenda-council", "confirmation-jury") to 2,
            listOf("rules-committee", "policy-jury", "confirmation-jury") to 1,
        )) {
            for (ballot in listOf<Any?>(null, linkedMapOf<String, Any?>())) {
                val response = certifiedReadResponse(bodies)
                @Suppress("UNCHECKED_CAST")
                val certificate = response["certificate"] as Map<String, Any?>
                @Suppress("UNCHECKED_CAST")
                val binding = (certificate["body_bindings"] as List<MutableMap<String, Any?>>)[index]
                binding["ballot"] = ballot
                val failure = assertFailsWith<IllegalArgumentException>("accepted $bodies") {
                    ParliamentApiV1.parseAttemptReadResponse(encode(response), attemptId)
                }
                assertEquals(
                    "certificate.body_bindings[$index] private-jury result binding is not " +
                        "admitted until the anonymous-ballot result binding is supported",
                    failure.message,
                )
            }
        }

        // The attempt itself stays readable while its private bodies are still pending.
        val pending = certifiedReadResponse(listOf("rules-committee", "policy-jury"))
        pending["certificate"] = null
        assertEquals(
            listOf("rules-committee", "policy-jury"),
            ParliamentApiV1.parseAttemptReadResponse(encode(pending), attemptId).requiredBodyOrder,
        )
    }

    /**
     * Certified attempt read over [bodies], a strictly increasing subset of the canonical body
     * order whose results all land at height 8. A public body carries a public-finding binding;
     * a private body carries neither a public finding nor a ballot binding.
     */
    private fun certifiedReadResponse(bodies: List<String>): MutableMap<String, Any?> {
        val root = List(32) { 0x55 }
        fun id(seed: Int, index: Int): String = "%02x".format(seed + index).repeat(32)
        val requiredBodies = ArrayList<Any?>()
        val bodyStates = ArrayList<Any?>()
        val bindings = ArrayList<Any?>()
        bodies.forEachIndexed { index, body ->
            val isPrivate = body == "policy-jury" || body == "confirmation-jury"
            requiredBodies += mapOf(
                "body" to body,
                "decision_mode" to mapOf(
                    "mode" to if (isPrivate) "HiddenBindingBallot" else "PublicFinding",
                ),
            )
            bodyStates += linkedMapOf<String, Any?>(
                "body" to body,
                "body_instance_id" to id(0x10, index),
                "status" to mapOf("status" to "Approved"),
                "public_finding_opened_at_height" to if (isPrivate) null else 1,
                "public_finding_phase_blocks" to if (isPrivate) null else 7,
                "public_finding_deadline_height" to if (isPrivate) null else 8,
                "no_result_kind" to null,
                "no_result_height" to null,
            )
            bindings += linkedMapOf<String, Any?>(
                "body_instance_id" to id(0x10, index),
                "election_attempt_id" to id(0x20, index),
                "election_attempt_sequence" to 0,
                "sortition_request_id" to id(0x30, index),
                "sortition_request" to linkedMapOf<String, Any?>(
                    "id" to id(0x30, index),
                    "governance_attempt_id" to attemptId,
                    "body_election_attempt_id" to id(0x20, index),
                    "body" to body,
                    "candidate_root" to root,
                    "candidate_count" to 3,
                    "target_seats" to 3,
                    "request_height" to 1,
                    "pulse_height" to 2,
                    "beacon_session_id" to id(0x40, index),
                ),
                "body" to body,
                "original_seats" to 3,
                "beacon_session_id" to id(0x40, index),
                "beacon_pulse_id" to id(0x50, index),
                "roster_root" to root,
                "assignment_root" to root,
                "result_root" to root,
                "result_height" to 8,
                "public_finding" to if (isPrivate) {
                    null
                } else {
                    linkedMapOf<String, Any?>(
                        "endorsement_root" to root,
                        "endorsing_assignments" to listOf(id(0x60, 2 * index), id(0x61, 2 * index)),
                        "endorsements" to 2,
                        "quorum" to 2,
                    )
                },
                "ballot" to null,
            )
        }
        return linkedMapOf<String, Any?>(
            "version" to 1,
            "current_height" to 9,
            "attempt" to mapOf(
                "id" to attemptId,
                "proposal_content_id" to proposalId,
                "sequence" to 0,
                "risk_tier" to mapOf("tier" to "Standard"),
                "stage" to mapOf("stage" to "Rules"),
                "status" to mapOf("status" to "Certified"),
            ),
            "policy_version" to 1,
            "required_bodies" to requiredBodies,
            "body_states" to bodyStates,
            "certificate" to linkedMapOf<String, Any?>(
                "proposal_content_id" to proposalId,
                "governance_attempt_id" to attemptId,
                "governance_attempt_sequence" to 0,
                "risk_tier" to mapOf("tier" to "Standard"),
                "body_bindings" to bindings,
                "policy_version" to 1,
                "effect_preimage_hash" to root,
                "expected_head" to mapOf("state" to "Absent", "head" to mapOf("subject_id" to root)),
                "certified_at_height" to 8,
                "enact_at_height" to 10,
            ),
            "terminal_height" to null,
            "superseding_head" to null,
            "execution_failure_root" to null,
            "state_payload_hex" to stateFrameHex(),
        )
    }

    private fun proposal(kind: String): ParliamentApiV1.Proposal =
        ParliamentApiV1.Proposal.fromJson(encode(validProposal(kind)))

    private fun validProposal(kind: String): MutableMap<String, Any?> {
        val payload: MutableMap<String, Any?> = when (kind) {
            "DeployContract" -> linkedMapOf(
                "proposal_operator" to account(1),
                "contract_address" to CONTRACT_ADDRESS,
                "code_hash" to "11".repeat(32),
                "abi_hash" to "22".repeat(32),
                "abi_version" to 1,
                "manifest_provenance" to null,
            )
            "RuntimeUpgrade" -> linkedMapOf(
                "proposal_operator" to account(1),
                "manifest" to linkedMapOf(
                    "name" to "runtime-v1",
                    "description" to "first release runtime",
                    "abi_version" to 1,
                    "abi_hash" to List(32) { 1 },
                    "added_syscalls" to emptyList<Any?>(),
                    "added_pointer_types" to emptyList<Any?>(),
                    "start_height" to 10,
                    "end_height" to 20,
                    "sbom_digests" to emptyList<Any?>(),
                    "slsa_attestation" to "",
                    "provenance" to emptyList<Any?>(),
                ),
            )
            "SccpRouteGovernance" -> linkedMapOf(
                "proposal" to linkedMapOf(
                    "network_id" to networkId(),
                    "base_revisions" to listOf(
                        linkedMapOf(
                            "subject" to linkedMapOf(
                                "subject" to "route",
                                "key" to bscMainnet(),
                            ),
                            "revision" to 1,
                        ),
                    ),
                    "actions" to listOf(
                        linkedMapOf(
                            "action" to "remove_staged",
                            "payload" to linkedMapOf(
                                "network" to bscMainnet(),
                                "revision" to 1,
                            ),
                        ),
                    ),
                ),
            )
            "ValidationFeePolicy" -> linkedMapOf(
                "proposal_operator" to account(1),
                "policy" to monthlyFeePolicy(),
            )
            "ValidationFeePayoutLifecycle" -> linkedMapOf(
                "proposal_operator" to account(1),
                "payout_binding" to payoutBinding(),
            )
            "MusubiRegistryGovernance" -> linkedMapOf(
                "kind" to "RecoverPackageOwners",
                "value" to linkedMapOf(
                    "package" to linkedMapOf(
                        "home_dataspace" to 7,
                        "scope" to linkedMapOf("kind" to "DataspaceRoot", "value" to null),
                        "name" to listOf("wallet-core"),
                    ),
                    "owners" to listOf(account(2)),
                    "expected_revision" to 1,
                ),
            )
            "SorafsProviderGovernance" -> linkedMapOf(
                "action" to linkedMapOf(
                    "action" to "establish",
                    "value" to linkedMapOf(
                        "provider_id" to listOf(List(32) { 0x45 }),
                        "owner" to account(3),
                    ),
                ),
            )
            "ContractLifecycleGovernance" -> linkedMapOf(
                "proposal_operator" to account(1),
                "contract_address" to CONTRACT_ADDRESS,
                "expected_revision" to 3,
                "action" to linkedMapOf(
                    "action" to "CompleteEmergencyHoldRetrospective",
                    "payload" to linkedMapOf(
                        "hold_proposal_content_id" to List(32) { 0x51 },
                        "hold_governance_attempt_id" to List(32) { 0x52 },
                        "incident_digest" to List(32) { 0x53 },
                        "retrospective_finding_root" to List(32) { 0x54 },
                    ),
                ),
            )
            "ContractEmergencyHold" -> linkedMapOf(
                "contract_address" to CONTRACT_ADDRESS,
                "expected_revision" to 2,
                "expected_code_hash" to "33".repeat(32),
                "incident_digest" to List(32) { 0x55 },
                "reason" to "contain active exploit",
                "duration_blocks" to 3_600,
            )
            "GlobalDataTriggerPermissionGovernance" -> linkedMapOf(
                "authority" to account(4),
                "action" to linkedMapOf("action" to "grant", "value" to null),
            )
            else -> error("unsupported fixture kind $kind")
        }
        return linkedMapOf("kind" to kind, "payload" to payload)
    }

    private fun monthlyFeePolicy(): MutableMap<String, Any?> = linkedMapOf(
        "schema_version" to 1,
        "network_id" to networkId(),
        "policy_version" to "1",
        "previous_policy_hash" to null,
        "ds_asset_id" to asset(1),
        "ds_scale" to 2,
        "retail_schedule" to linkedMapOf(
            "included_payments" to 50, "overage_minor" to 10,
            "maintenance_tiers" to listOf(0 to 100,50000 to 200,250000 to 300,1000000 to 500,5000000 to 1000).map {
                linkedMapOf("minimum_average_balance_minor" to it.first,"monthly_fee_minor" to it.second)
            },
        ),
        "effective_from_ms" to 1788181200000L,
        "notice_published_at_ms" to 1785502800000L,
        "fee" to "0.1",
        "treasury_account_id" to account(2),
        "charging_mode" to linkedMapOf("charging_mode" to "RETAIL_MONTHLY_ALLOWANCE", "value" to null),
        "exemption_classes" to listOf("TREASURY_PAYOUT"),
        "reward_custody" to payoutBinding().filterKeys { it in setOf("contract_address","treasury_account_id","ds_asset_id","xor_asset_id","reward_pool_account_id","validator_lane_id") },
    )

    private fun payoutBinding(): MutableMap<String, Any?> = linkedMapOf(
        "contract_address" to CONTRACT_ADDRESS, "code_hash" to "31".repeat(32),
        "entrypoint" to "autonomous_validation_fee_tick", "treasury_account_id" to account(2),
        "ds_asset_id" to asset(1), "xor_asset_id" to asset(2),
        "pool_contract_address" to CONTRACT_ADDRESS, "pool_code_hash" to "33".repeat(32),
        "pool_vault_account_id" to account(3), "reward_pool_account_id" to account(4),
        "reference_feed_id" to listOf("sbd_xor"), "reference_feed_config_version" to 1,
        "reference_provider_accounts" to (5..9).map { account(it) },
        "max_sbd_per_attempt_minor" to 1000, "max_sbd_per_day_minor" to 100000,
        "min_interval_ms" to 60000, "max_source_age_ms" to 300000, "max_slippage_bps" to 100,
        "validator_lane_id" to 1, "min_reward_claim_xor_minor" to 1,
    )

    private fun bscMainnet(): MutableMap<String, Any?> =
        linkedMapOf("network" to "bsc_mainnet", "profile" to null)

    private fun account(seed: Int): String =
        AccountAddress.fromAccount(TestEd25519Keys.publicKey(seed), "ed25519")
            .toI105(AccountAddress.DEFAULT_I105_DISCRIMINANT)

    private fun asset(seed: Int): String {
        val bytes = ByteArray(16) { (seed + it).toByte() }
        bytes[6] = ((bytes[6].toInt() and 0x0f) or 0x40).toByte()
        bytes[8] = ((bytes[8].toInt() and 0x3f) or 0x80).toByte()
        return AssetDefinitionIdEncoder.encodeFromBytes(bytes)
    }

    private fun networkId(): String =
        NetworkId.fromBytes(ByteArray(32) { 0x23 }.also { it[31] = 0x25 }).literal

    private fun encode(value: Map<String, Any?>): ByteArray =
        JsonEncoder.encode(value).toByteArray(StandardCharsets.UTF_8)

    private fun bytes(value: String): ByteArray = value.toByteArray(StandardCharsets.UTF_8)

    private fun stateFrame(): ByteArray {
        val payload = byteArrayOf(1, 2)
        val header = NoritoHeader(
            ByteArray(16) { 3 },
            payload.size,
            CRC64.compute(payload),
            0,
            NoritoHeader.COMPRESSION_NONE,
        )
        return header.encode() + payload
    }

    private fun stateFrameHex(): String = stateFrame().toHex()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun fixturePath(): Path {
        var current: Path? = Paths.get("").toAbsolutePath()
        while (current != null) {
            val candidate = current.resolve("fixtures/governance/parliament_api_v1.json")
            if (Files.isRegularFile(candidate)) return candidate
            current = current.parent
        }
        error("fixtures/governance/parliament_api_v1.json was not found")
    }

    @Suppress("UNCHECKED_CAST")
    private fun objectValue(bytes: ByteArray): Map<String, Any?> =
        JsonParser.parse(String(bytes, StandardCharsets.UTF_8)) as Map<String, Any?>

    companion object {
        private const val CONTRACT_ADDRESS =
            "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
    }
}
