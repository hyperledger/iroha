package org.hyperledger.iroha.sdk.client

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.MessageDigest
import java.util.Base64
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
        assertEquals(ParliamentApiV1.ATTEMPT_DRAFT_PATH, routes["attempt_draft"])
        assertEquals(ParliamentApiV1.ATTEMPT_READ_PATH, routes["attempt_read"])
        assertEquals(
            ParliamentApiV1.TIMED_OVN_CASTING_CONTEXT_READ_PATH,
            routes["timed_ovn_casting_context_read"],
        )
        assertEquals(
            ParliamentApiV1.TIMED_OVN_CASTING_PROOF_PATH,
            routes["timed_ovn_casting_proof"],
        )
        assertEquals(
            ParliamentApiV1.TLE_RELEASE_CONTEXT_READ_PATH,
            routes["tle_release_context_read"],
        )
        assertEquals(ParliamentApiV1.TLE_PARTIAL_RELEASE_PATH, routes["tle_partial_release"])
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
        assertEquals(ParliamentApiV1.MAX_STATE_BYTES, (limits["attempt_state_bytes"] as Number).toInt())
        assertEquals(
            ParliamentApiV1.TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS,
            (limits["timed_ovn_ballot_chunk_max_records"] as Number).toInt(),
        )
        assertEquals(
            ParliamentApiV1.MAX_TIMED_OVN_CORPUS_ENTRIES,
            (limits["timed_ovn_corpus_entries"] as Number).toInt(),
        )
        assertEquals(
            ParliamentApiV1.TIMED_OVN_CASTING_PROOF_REQUEST_BYTES,
            (limits["timed_ovn_casting_proof_request_bytes"] as Number).toInt(),
        )
        assertEquals(
            ParliamentApiV1.MAX_TIMED_OVN_CASTING_PROOF_RESPONSE_BYTES,
            (limits["timed_ovn_casting_proof_response_bytes"] as Number).toInt(),
        )
        assertEquals(
            ParliamentApiV1.MAX_TIMED_OVN_CASTING_PROOF_FINALITY_PROOFS,
            (limits["timed_ovn_casting_proof_finality_entries"] as Number).toInt(),
        )
        val nativeWallet = fixture["timed_ovn_native_wallet"] as Map<*, *>
        assertEquals(
            ParliamentApiV1.TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA,
            nativeWallet["request_norito_schema"],
        )
        assertEquals(
            ParliamentApiV1.TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA,
            nativeWallet["response_norito_schema"],
        )
        assertEquals(
            ParliamentApiV1.TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_HASH_HEX,
            nativeWallet["casting_proof_request_schema_hash_hex"],
        )
        assertEquals(
            ParliamentApiV1.TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX,
            nativeWallet["casting_proof_response_schema_hash_hex"],
        )
        assertEquals(
            ParliamentApiV1.TIMED_OVN_CASTING_PROOF_REQUEST_VERSION,
            (nativeWallet["casting_proof_request_version"] as Number).toInt(),
        )
        assertEquals(
            ParliamentApiV1.TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS,
            (nativeWallet["casting_proof_request_flags"] as Number).toInt(),
        )
        assertEquals(
            ParliamentApiV1.TIMED_OVN_CASTING_PROOF_REQUEST_PAYLOAD_ALIGNMENT,
            (nativeWallet["casting_proof_request_payload_alignment"] as Number).toInt(),
        )
        assertEquals(
            ParliamentApiV1.TIMED_OVN_CASTING_PROOF_REQUEST_PADDING_BYTES,
            (nativeWallet["casting_proof_request_padding_bytes"] as Number).toInt(),
        )
        val castingGolden = nativeWallet["casting_proof_request_golden"] as Map<*, *>
        assertEquals(
            ParliamentApiV1.TIMED_OVN_CASTING_PROOF_REQUEST_BYTES,
            (castingGolden["frame_bytes"] as Number).toInt(),
        )
        assertContentEquals(
            decodeHex(castingGolden["frame_hex"] as String),
            ParliamentApiV1.timedOvnCastingProofRequestNorito(
                BigInteger.valueOf((castingGolden["trusted_checkpoint_height"] as Number).toLong()),
            ),
        )

        val transitions = fixture["public_transitions"] as List<*>
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

            val transitionJson = if (layout.jsonTag == "FreezeTimedOvnCorpus") {
                freezeTimedOvnTransition(1)
            } else if (layout.jsonPayloadRequired) {
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
        val release = fixture["tle_release_context"] as Map<*, *>
        assertEquals(
            listOf(
                "version", "key_session_id", "network_id", "roster_hash", "committee_size",
                "threshold", "generator_h", "generator_v", "qualified_dealers",
                "qualified_dealer_commitments", "dkg_event_hash", "group_public_key",
                "public_shares", "transcript_hash",
            ),
            release["transcript_public_state_fields"],
        )
        val partial = fixture["tle_partial_release"] as Map<*, *>
        assertEquals(9, (partial["response_fields"] as List<*>).size)
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
            subject("bridge_key_fault", "ea0130" + "AB".repeat(48)),
        ).forEach { replacement ->
            ParliamentApiV1.Proposal.fromJson(sccpProposal { it.putAll(replacement) })
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
            { it.putAll(subject("bridge_key_fault", "ea0130" + "ab".repeat(48))) },
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
        assertEquals(21, layout.noritoIndex)
        assertEquals(24, layout.eventKindIndex)
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
    fun timedOvnCorpusTransitionPreflightsOneThrough32RecordsPerChunk() {
        for (count in listOf(1, ParliamentApiV1.TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS)) {
            ParliamentApiV1.transitionDraftRequestJson(
                attemptId,
                freezeTimedOvnTransition(count),
            )
        }
        for (count in listOf(0, ParliamentApiV1.TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS + 1)) {
            assertFailsWith<IllegalArgumentException> {
                ParliamentApiV1.transitionDraftRequestJson(
                    attemptId,
                    freezeTimedOvnTransition(count),
                )
            }
        }
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.transitionDraftRequestJson(
                attemptId,
                freezeTimedOvnTransition(1, ParliamentApiV1.TIMED_OVN_BALLOT_RECORD_BYTES - 1),
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
        val ballotId = "33".repeat(32)
        assertEquals(
            "/v1/gov/parliament/ballots/$ballotId/casting-context",
            ParliamentApiV1.timedOvnCastingContextReadPath(ballotId),
        )
        assertEquals(
            "/v1/gov/parliament/ballots/$ballotId/casting-proof",
            ParliamentApiV1.timedOvnCastingProofPath(ballotId),
        )
        assertEquals(
            "/v1/gov/parliament/ballots/$ballotId/release-context",
            ParliamentApiV1.tleReleaseContextReadPath(ballotId),
        )
        assertEquals(
            "/v1/gov/parliament/ballots/$ballotId/partial-release",
            ParliamentApiV1.tlePartialReleasePath(ballotId),
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
    fun castingProofNoritoPinsU64GoldenAndRejectsNoncanonicalResponses() {
        val golden = decodeHex(
            "4e5254300000adccf322a5fcf43040e20bea238f55f3000c00000000000000" +
                "dfab61022cefc29f02020100081100000000000000",
        )
        assertContentEquals(
            golden,
            ParliamentApiV1.timedOvnCastingProofRequestNorito(BigInteger.valueOf(17)),
        )
        assertContentEquals(
            golden,
            ParliamentTimedOvnCastingProofRequestV1(17).toNoritoBytes(),
        )
        val maximum = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)
        val maximumFrame = ParliamentApiV1.timedOvnCastingProofRequestNorito(maximum)
        assertContentEquals(ByteArray(8) { 0xff.toByte() }, maximumFrame.copyOfRange(44, 52))
        for (height in listOf(BigInteger.ZERO, BigInteger.valueOf(-1), BigInteger.ONE.shiftLeft(64))) {
            assertFailsWith<IllegalArgumentException> {
                ParliamentApiV1.timedOvnCastingProofRequestNorito(height)
            }
        }

        val payload = byteArrayOf(2, 1, 0, 1)
        val header = NoritoHeader(
            decodeHex(ParliamentApiV1.TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX),
            payload.size,
            CRC64.compute(payload),
            NoritoHeader.COMPACT_LEN,
            NoritoHeader.COMPRESSION_NONE,
        )
        val canonical = header.encode() + payload
        val parsed = ParliamentApiV1.parseTimedOvnCastingProofResponse(canonical)
        assertContentEquals(canonical, parsed.canonicalNorito())
        assertContentEquals(payload, parsed.payload())
        parsed.canonicalNorito()[0] = 0
        parsed.payload()[0] = 0
        assertContentEquals(canonical, parsed.canonicalNorito())
        assertContentEquals(payload, parsed.payload())

        val wrongSchema = NoritoHeader(
            ByteArray(16) { 7 },
            payload.size,
            CRC64.compute(payload),
            NoritoHeader.COMPACT_LEN,
            NoritoHeader.COMPRESSION_NONE,
        ).encode() + payload
        val badChecksum = canonical.copyOf().also { it[it.lastIndex] = (it.last() + 1).toByte() }
        val compressed = canonical.copyOf().also { it[22] = 1 }
        val padded = header.encode() + byteArrayOf(0) + payload
        val wrongFlags = NoritoHeader(
            decodeHex(ParliamentApiV1.TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX),
            payload.size,
            CRC64.compute(payload),
            0,
            NoritoHeader.COMPRESSION_NONE,
        ).encode() + payload
        for (hostile in listOf(wrongSchema, badChecksum, compressed, padded, wrongFlags)) {
            assertFailsWith<IllegalArgumentException> {
                ParliamentApiV1.parseTimedOvnCastingProofResponse(hostile)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseTimedOvnCastingProofResponse(
                ByteArray(ParliamentApiV1.MAX_TIMED_OVN_CASTING_PROOF_RESPONSE_BYTES + 1),
            )
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
        val root = List(32) { 0x55 }
        val id1 = "01".repeat(32)
        val id2 = "02".repeat(32)
        val publicOnlyResponse = linkedMapOf<String, Any?>(
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
            "required_bodies" to listOf(
                mapOf(
                    "body" to "rules-committee",
                    "decision_mode" to mapOf("mode" to "PublicFinding"),
                ),
            ),
            "body_states" to listOf(
                linkedMapOf(
                    "body" to "rules-committee",
                    "body_instance_id" to id1,
                    "status" to mapOf("status" to "Approved"),
                    "public_finding_opened_at_height" to 1,
                    "public_finding_phase_blocks" to 7,
                    "public_finding_deadline_height" to 8,
                    "no_result_kind" to null,
                    "no_result_height" to null,
                    "timed_ovn_progress" to null,
                ),
            ),
            "certificate" to linkedMapOf(
                "proposal_content_id" to proposalId,
                "governance_attempt_id" to attemptId,
                "governance_attempt_sequence" to 0,
                "risk_tier" to mapOf("tier" to "Standard"),
                "body_bindings" to listOf(
                    linkedMapOf(
                        "body_instance_id" to id1,
                        "election_attempt_id" to id2,
                        "election_attempt_sequence" to 0,
                        "sortition_request_id" to "03".repeat(32),
                        "sortition_request" to linkedMapOf(
                            "id" to "03".repeat(32),
                            "governance_attempt_id" to attemptId,
                            "body_election_attempt_id" to id2,
                            "body" to "rules-committee",
                            "candidate_root" to root,
                            "candidate_count" to 3,
                            "target_seats" to 3,
                            "request_height" to 1,
                            "pulse_height" to 2,
                            "beacon_session_id" to "04".repeat(32),
                        ),
                        "body" to "rules-committee",
                        "original_seats" to 3,
                        "beacon_session_id" to "04".repeat(32),
                        "beacon_pulse_id" to "05".repeat(32),
                        "roster_root" to root,
                        "assignment_root" to root,
                        "result_root" to root,
                        "result_height" to 8,
                        "public_finding" to linkedMapOf(
                            "endorsement_root" to root,
                            "endorsing_assignments" to listOf("11".repeat(32), "12".repeat(32)),
                            "endorsements" to 2,
                            "quorum" to 2,
                        ),
                        "ballot" to null,
                    ),
                ),
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

        fun policyJuryResponse(): MutableMap<String, Any?> {
            val hidden = LinkedHashMap(publicOnlyResponse)
            @Suppress("UNCHECKED_CAST")
            val certificate = LinkedHashMap(
                publicOnlyResponse["certificate"] as Map<String, Any?>,
            )
            @Suppress("UNCHECKED_CAST")
            val bindings = (certificate["body_bindings"] as List<Map<String, Any?>>)
                .map { LinkedHashMap(it) }
            val binding = bindings.single()
            binding["body_instance_id"] = "06".repeat(32)
            binding["election_attempt_id"] = "07".repeat(32)
            binding["sortition_request_id"] = "08".repeat(32)
            binding["body"] = "policy-jury"
            binding["beacon_session_id"] = "09".repeat(32)
            binding["beacon_pulse_id"] = "0a".repeat(32)
            @Suppress("UNCHECKED_CAST")
            val request = LinkedHashMap(
                binding["sortition_request"] as Map<String, Any?>,
            )
            request["id"] = "08".repeat(32)
            request["body_election_attempt_id"] = "07".repeat(32)
            request["body"] = "policy-jury"
            request["beacon_session_id"] = "09".repeat(32)
            binding["sortition_request"] = request
            binding["public_finding"] = null
            binding["ballot"] = linkedMapOf(
                "ballot_attempt_id" to "21".repeat(32),
                "ballot_attempt_sequence" to 0,
                "tle_session_id" to "22".repeat(32),
                "tle_key_session_id" to "23".repeat(32),
                "registration_root" to root,
                "dropout_root" to root,
                "survivor_root" to root,
                "corpus_root" to root,
                "no_recovery_root" to root,
                "timed_commitment_root" to root,
                "release_beacon_session_id" to "24".repeat(32),
                "registered_at_height" to 1,
                "registration_close_height" to 5,
                "survivor_freeze_height" to 8,
                "commitment_close_height" to 9,
                "registration_closed_at_height" to 5,
                "survivors_frozen_at_height" to 8,
                "commitment_closed_at_height" to 9,
                "max_ballot_retries" to 16,
                "max_corpus_entries" to 3,
                "release_height" to 10,
                "opening_deadline_height" to 13,
                "release_pulse_id" to "25".repeat(32),
                "opening_height" to 11,
                "opening_root" to root,
                "tally" to linkedMapOf(
                    "original_seats" to 3,
                    "accepted_ballots" to 3,
                    "aye" to 2,
                    "nay" to 1,
                    "abstain" to 0,
                ),
                "outcome" to mapOf("outcome" to "Approved"),
            )
            binding["result_height"] = 12
            certificate["body_bindings"] = bindings
            certificate["certified_at_height"] = 12
            certificate["enact_at_height"] = 14
            hidden["certificate"] = certificate
            hidden["required_bodies"] = listOf(
                mapOf(
                    "body" to "policy-jury",
                    "decision_mode" to mapOf("mode" to "HiddenBindingBallot"),
                ),
            )
            @Suppress("UNCHECKED_CAST")
            val hiddenStates = (publicOnlyResponse["body_states"] as List<Map<String, Any?>>)
                .map { LinkedHashMap(it) }
            hiddenStates.single()["body"] = "policy-jury"
            hiddenStates.single()["body_instance_id"] = "06".repeat(32)
            hiddenStates.single()["public_finding_opened_at_height"] = null
            hiddenStates.single()["public_finding_phase_blocks"] = null
            hiddenStates.single()["public_finding_deadline_height"] = null
            hiddenStates.single()["timed_ovn_progress"] = linkedMapOf(
                "ballot_attempt_id" to "21".repeat(32),
                "status" to mapOf("status" to "Finalized"),
                "frozen_survivor_count" to 3,
                "accepted_ballot_prefix_count" to 3,
            )
            hidden["body_states"] = hiddenStates
            hidden["current_height"] = 13
            return hidden
        }

        fun certifiedResponse(): MutableMap<String, Any?> {
            val certified = LinkedHashMap(publicOnlyResponse)
            val policy = policyJuryResponse()
            @Suppress("UNCHECKED_CAST")
            certified["required_bodies"] =
                (publicOnlyResponse["required_bodies"] as List<Map<String, Any?>>) +
                    (policy["required_bodies"] as List<Map<String, Any?>>)
            @Suppress("UNCHECKED_CAST")
            certified["body_states"] =
                (publicOnlyResponse["body_states"] as List<Map<String, Any?>>) +
                    (policy["body_states"] as List<Map<String, Any?>>)
            @Suppress("UNCHECKED_CAST")
            val certificate = LinkedHashMap(
                publicOnlyResponse["certificate"] as Map<String, Any?>,
            )
            @Suppress("UNCHECKED_CAST")
            certificate["body_bindings"] =
                (certificate["body_bindings"] as List<Map<String, Any?>>) +
                    ((policy["certificate"] as Map<String, Any?>)["body_bindings"]
                        as List<Map<String, Any?>>)
            certificate["certified_at_height"] = 12
            certificate["enact_at_height"] = 14
            certified["certificate"] = certificate
            certified["current_height"] = 13
            return certified
        }

        val response = certifiedResponse()
        val parsed = ParliamentApiV1.parseAttemptReadResponse(encode(response), attemptId)
        assertEquals("13", parsed.currentHeight)
        assertEquals(listOf("rules-committee", "policy-jury"), parsed.requiredBodyOrder)
        assertEquals("rules-committee", parsed.bodyStates.first().body)
        assertEquals(listOf("rules-committee", "policy-jury"), parsed.certificateBodyOrder)
        assertEquals(
            listOf("11".repeat(32), "12".repeat(32)),
            parsed.publicFindingBindings.single().endorsingAssignments,
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
                "timed_ovn_progress" to null,
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

        val unsorted = LinkedHashMap(response)
        @Suppress("UNCHECKED_CAST")
        val certificate = LinkedHashMap(response["certificate"] as Map<String, Any?>)
        @Suppress("UNCHECKED_CAST")
        val bindings = (certificate["body_bindings"] as List<Map<String, Any?>>)
            .map { LinkedHashMap(it) }
        @Suppress("UNCHECKED_CAST")
        val finding = LinkedHashMap(bindings[0]["public_finding"] as Map<String, Any?>)
        finding["endorsing_assignments"] = listOf("12".repeat(32), "11".repeat(32))
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

        val wrongMode = LinkedHashMap(response)
        wrongMode["required_bodies"] = listOf(
            mapOf(
                "body" to "rules-committee",
                "decision_mode" to mapOf("mode" to "HiddenBindingBallot"),
            ),
        )
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseAttemptReadResponse(encode(wrongMode), attemptId)
        }

        fun hiddenBallotResponse(): MutableMap<String, Any?> = policyJuryResponse()

        val parsedHidden = ParliamentApiV1.parseAttemptReadResponse(encode(hiddenBallotResponse()), attemptId)
        assertEquals(3, parsedHidden.bodyStates.single().timedOvnProgress?.acceptedBallotPrefixCount)
        for (mutate in listOf<(MutableMap<String, Any?>) -> Unit>(
            { it["ballot_attempt_sequence"] = 17 },
            { it["max_corpus_entries"] = 2 },
            { it["registration_close_height"] = 4 },
            { it["survivor_freeze_height"] = 7 },
            {
                @Suppress("UNCHECKED_CAST")
                val tally = LinkedHashMap(it["tally"] as Map<String, Any?>)
                tally["abstain"] = 1
                it["tally"] = tally
            },
            { it["outcome"] = mapOf("outcome" to "Rejected") },
        )) {
            val forged = hiddenBallotResponse()
            @Suppress("UNCHECKED_CAST")
            val forgedCertificate = forged["certificate"] as Map<String, Any?>
            @Suppress("UNCHECKED_CAST")
            val forgedBinding = (forgedCertificate["body_bindings"] as List<Map<String, Any?>>)[0]
            @Suppress("UNCHECKED_CAST")
            val ballot = LinkedHashMap(forgedBinding["ballot"] as Map<String, Any?>)
            mutate(ballot)
            (forgedBinding as MutableMap<String, Any?>)["ballot"] = ballot
            assertFailsWith<IllegalArgumentException> {
                ParliamentApiV1.parseAttemptReadResponse(encode(forged), attemptId)
            }
        }

        val partial = hiddenBallotResponse()
        partial["certificate"] = null
        @Suppress("UNCHECKED_CAST")
        val partialStates = (partial["body_states"] as List<Map<String, Any?>>)
            .map { LinkedHashMap(it) }
        partialStates[0]["timed_ovn_progress"] = linkedMapOf(
            "ballot_attempt_id" to "21".repeat(32),
            "status" to mapOf("status" to "TimedCommitment"),
            "frozen_survivor_count" to 3,
            "accepted_ballot_prefix_count" to 1,
        )
        partial["body_states"] = partialStates
        assertEquals(
            1,
            ParliamentApiV1.parseAttemptReadResponse(encode(partial), attemptId)
                .bodyStates.single().timedOvnProgress?.acceptedBallotPrefixCount,
        )

        @Suppress("UNCHECKED_CAST")
        val progress = LinkedHashMap(
            partialStates[0]["timed_ovn_progress"] as Map<String, Any?>,
        )
        progress["accepted_ballot_prefix_count"] = 3
        partialStates[0]["timed_ovn_progress"] = progress
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseAttemptReadResponse(encode(partial), attemptId)
        }

        progress["accepted_ballot_prefix_count"] = 1
        progress["ballot_records"] = emptyList<Any>()
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseAttemptReadResponse(encode(partial), attemptId)
        }
    }

    @Test
    fun releaseContextRequiresCompleteTranscriptAndBindsEveryPartial() {
        val ballotId = "33".repeat(32)
        val response = tleReleaseContextResponse()
        val context = ParliamentApiV1.parseTleReleaseContextResponse(encode(response), ballotId)
        assertEquals(4, context.keySession.publicShares.size)
        assertEquals(2, context.keySession.qualifiedDealerCommitments.size)

        val partial = tlePartialReleaseResponse(response)
        val parsedPartial = ParliamentApiV1.parseTlePartialReleaseResponse(
            encode(partial),
            context.keySession.keySessionId,
            context.identityDigest,
            context.keySession.committeeSize,
        )
        assertEquals(1, parsedPartial.participantIndex)

        val missingShare = tleReleaseContextResponse()
        @Suppress("UNCHECKED_CAST")
        val missingSession = LinkedHashMap(missingShare["tle_key_session"] as Map<String, Any?>)
        @Suppress("UNCHECKED_CAST")
        val shares = (missingSession["public_shares"] as List<Any?>).dropLast(1)
        missingSession["public_shares"] = shares
        missingShare["tle_key_session"] = missingSession
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseTleReleaseContextResponse(encode(missingShare), ballotId)
        }

        val wrongDigest = tleReleaseContextResponse()
        wrongDigest["identity_digest"] = List(32) { if (it == 0) 1 else 0x88 }
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseTleReleaseContextResponse(encode(wrongDigest), ballotId)
        }

        val crossBound = tlePartialReleaseResponse(response)
        crossBound["key_session_id"] = "77".repeat(32)
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseTlePartialReleaseResponse(
                encode(crossBound),
                context.keySession.keySessionId,
                context.identityDigest,
                4,
            )
        }
    }

    @Test
    fun castingContextRequiresExactPhaseCorpusAndCanonicalArchive() {
        val release = tleReleaseContextResponse()
        @Suppress("UNCHECKED_CAST")
        val keySession = release["tle_key_session"] as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val releaseIdentity = release["release_identity"] as Map<String, Any?>
        val ballotId = release["ballot_attempt_id"] as String
        val response = linkedMapOf<String, Any?>(
            "version" to 1,
            "current_height" to 20,
            "phase" to "Registered",
            "session" to linkedMapOf(
                "network_id" to keySession["network_id"],
                "proposal_content_id" to proposalId,
                "governance_attempt_id" to attemptId,
                "body_instance_id" to release["body_instance_id"],
                "ballot_attempt_id" to ballotId,
                "parameter_hash" to releaseIdentity["parameter_hash"],
                "tle_key_session_id" to keySession["key_session_id"],
                "tle_key_transcript_hash" to keySession["transcript_hash"],
                "tle_master_public_key" to keySession["group_public_key"],
            ),
            "registration_opened_at_finalized_height" to 10,
            "target_finalized_height" to 40,
            "tle_key_session" to keySession,
            "registration_records_hex" to listOf(ByteArray(3_624) { 0x41 }.toHex()),
            "survivor_participant_hashes" to null,
            "release_identity" to null,
            "archive_norito_base64" to Base64.getEncoder().encodeToString("NRT0".toByteArray()),
        )
        val parsed = ParliamentApiV1.parseTimedOvnCastingContextResponse(
            encode(response),
            ballotId,
        )
        assertEquals(ParliamentTimedOvnCastingPhaseV1.Registered, parsed.phase)
        assertEquals(3_624, parsed.registrationRecordsHex.single().length / 2)

        response["phase"] = "SurvivorsFrozen"
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseTimedOvnCastingContextResponse(encode(response), ballotId)
        }
        response["survivor_participant_hashes"] = emptyList<List<Int>>()
        response["release_identity"] = releaseIdentity
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseTimedOvnCastingContextResponse(encode(response), ballotId)
        }
        response["phase"] = "Registered"
        response["survivor_participant_hashes"] = null
        response["release_identity"] = null
        response["archive_norito_base64"] = "TlJUMA"
        assertFailsWith<IllegalArgumentException> {
            ParliamentApiV1.parseTimedOvnCastingContextResponse(encode(response), ballotId)
        }
    }

    private fun tleReleaseContextResponse(): LinkedHashMap<String, Any?> {
        val ballotId = "33".repeat(32)
        val bodyId = "22".repeat(32)
        val keySessionId = "44".repeat(32)
        val survivorRoot = List(32) { 0x61 }
        val noRecoveryRoot = List(32) { 0x62 }
        val parameterHash = List(32) { 0x63 }
        val identityPayload = ByteArrayOutputStream().apply {
            append("iroha.parliament.tle.identity-payload.v1\u0000".toByteArray(StandardCharsets.UTF_8))
            append(u16(1))
            append(attemptId.hexBytes())
            append(bodyId.hexBytes())
            append(ballotId.hexBytes())
            append(survivorRoot.toBytes())
            append(noRecoveryRoot.toBytes())
            append(u64(40))
            append(parameterHash.toBytes())
        }.toByteArray()
        assertEquals(243, identityPayload.size)
        val keySession = linkedMapOf<String, Any?>(
            "version" to 1,
            "key_session_id" to keySessionId,
            "network_id" to List(32) { 0x45 },
            "roster_hash" to List(32) { 0x46 },
            "committee_size" to 4,
            "threshold" to 2,
            "generator_h" to List(96) { 0x47 },
            "generator_v" to List(96) { 0x48 },
            "qualified_dealers" to listOf(1, 2),
            "qualified_dealer_commitments" to listOf(1, 2).map { dealer ->
                linkedMapOf<String, Any?>(
                    "dealer_index" to dealer,
                    "coefficient_commitments" to listOf(
                        List(96) { 0x50 + dealer },
                        List(96) { 0x60 + dealer },
                    ),
                    "constant_pok_commitment" to List(96) { 0x70 + dealer },
                    "constant_pok_response" to List(32) { 0x80 + dealer },
                )
            },
            "dkg_event_hash" to List(32) { 0x49 },
            "group_public_key" to List(96) { 0x4a },
            "public_shares" to listOf(1, 2, 3, 4).map { index ->
                linkedMapOf<String, Any?>(
                    "index" to index,
                    "participant_hash" to List(32) { 0x20 + index },
                    "public_key_share" to List(96) { 0x30 + index },
                )
            },
            "transcript_hash" to List(32) { 0x4b },
        )
        val framed = ByteArrayOutputStream().apply {
            append("iroha.threshold-bls.message.v1\u0000".toByteArray(StandardCharsets.UTF_8))
            append("iroha.threshold-bls.session.v1\u0000".toByteArray(StandardCharsets.UTF_8))
            append(u16(1))
            write(2)
            append((keySession["network_id"] as List<Int>).toBytes())
            append(keySessionId.hexBytes())
            append((keySession["roster_hash"] as List<Int>).toBytes())
            append(u16(4))
            append(u16(2))
            append(u32(identityPayload.size))
            append(identityPayload)
        }.toByteArray()
        return linkedMapOf(
            "version" to 1,
            "current_height" to 42,
            "ballot_attempt_id" to ballotId,
            "governance_attempt_id" to attemptId,
            "body_instance_id" to bodyId,
            "status" to mapOf("status" to "Opening"),
            "release_height" to 40,
            "opening_deadline_height" to 45,
            "tle_key_session" to keySession,
            "release_identity" to linkedMapOf(
                "tle_key_session_id" to keySessionId,
                "governance_attempt_id" to attemptId,
                "body_instance_id" to bodyId,
                "ballot_attempt_id" to ballotId,
                "survivor_corpus_root" to survivorRoot,
                "no_recovery_root" to noRecoveryRoot,
                "target_finalized_height" to 40,
                "parameter_hash" to parameterHash,
            ),
            "identity_digest" to MessageDigest.getInstance("SHA-256").digest(framed)
                .map { it.toInt() and 0xff },
            "identity_payload_hex" to identityPayload.toHex(),
        )
    }

    private fun tlePartialReleaseResponse(
        context: Map<String, Any?>,
    ): LinkedHashMap<String, Any?> {
        @Suppress("UNCHECKED_CAST")
        val session = context["tle_key_session"] as Map<String, Any?>
        return linkedMapOf(
            "key_session_id" to session["key_session_id"],
            "identity_digest" to context["identity_digest"],
            "participant_index" to 1,
            "sigma" to List(48) { 0x91 },
            "proof_x" to List(96) { 0x92 },
            "proof_y" to List(48) { 0x93 },
            "z_s" to List(32) { 0x94 },
            "z_r" to List(32) { 0x95 },
            "z_u" to List(32) { 0x96 },
        )
    }

    private fun ByteArrayOutputStream.append(bytes: ByteArray) {
        write(bytes, 0, bytes.size)
    }

    private fun List<Int>.toBytes(): ByteArray = ByteArray(size) { this[it].toByte() }

    private fun String.hexBytes(): ByteArray = ByteArray(length / 2) { index ->
        substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }

    private fun u16(value: Int): ByteArray = byteArrayOf(
        (value ushr 8).toByte(),
        value.toByte(),
    )

    private fun u32(value: Int): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte(),
    )

    private fun u64(value: Long): ByteArray = ByteArray(8) { offset ->
        (value ushr (8 * (7 - offset))).toByte()
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

    private fun freezeTimedOvnTransition(
        recordCount: Int,
        recordBytes: Int = ParliamentApiV1.TIMED_OVN_BALLOT_RECORD_BYTES,
    ): ByteArray = encode(
        linkedMapOf(
            "transition" to "FreezeTimedOvnCorpus",
            "payload" to linkedMapOf(
                "ballot_attempt_id" to "44".repeat(32),
                "ballot_records" to List(recordCount) { List(recordBytes) { 1 } },
            ),
        ),
    )

    private fun bytes(value: String): ByteArray = value.toByteArray(StandardCharsets.UTF_8)

    private fun decodeHex(value: String): ByteArray = ByteArray(value.length / 2) { index ->
        value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }

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
