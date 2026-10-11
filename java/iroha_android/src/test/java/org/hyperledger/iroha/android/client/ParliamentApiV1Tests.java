package org.hyperledger.iroha.android.client;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import org.hyperledger.iroha.android.address.AccountAddress;
import org.hyperledger.iroha.android.address.AssetDefinitionIdEncoder;
import org.hyperledger.iroha.android.model.NetworkId;
import org.hyperledger.iroha.android.testing.TestEd25519Keys;
import org.hyperledger.iroha.norito.CRC64;
import org.hyperledger.iroha.norito.NoritoHeader;
import org.hyperledger.iroha.sdk.client.ParliamentTimedOvnCastingProofResponseV1;
import org.junit.Test;

/** Kotlin-mirror parity tests for the strict Parliament V1 HTTP contract. */
public final class ParliamentApiV1Tests {
  private static final String ATTEMPT_ID = "ab".repeat(32);
  private static final String PROPOSAL_ID = "cd".repeat(32);
  private static final String CONTRACT_ADDRESS =
      "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";

  @Test
  public void sharedFixturePinsEveryPublicTransitionAutomaticOutcomeAndResultRoot()
      throws Exception {
    final Map<String, Object> fixture = objectValue(Files.readAllBytes(fixturePath()));
    assertEquals("iroha.governance.parliament.api_fixture.v1", fixture.get("schema"));
    assertEquals(1L, fixture.get("api_version"));

    final Map<String, Object> routes = objectValue(fixture.get("routes"));
    assertEquals(ParliamentApiV1.ATTEMPT_DRAFT_PATH, routes.get("attempt_draft"));
    assertEquals(ParliamentApiV1.ATTEMPT_READ_PATH, routes.get("attempt_read"));
    assertEquals(
        ParliamentApiV1.TIMED_OVN_CASTING_CONTEXT_READ_PATH,
        routes.get("timed_ovn_casting_context_read"));
    assertEquals(
        ParliamentApiV1.TIMED_OVN_CASTING_PROOF_PATH,
        routes.get("timed_ovn_casting_proof"));
    assertEquals(
        ParliamentApiV1.TLE_RELEASE_CONTEXT_READ_PATH,
        routes.get("tle_release_context_read"));
    assertEquals(
        ParliamentApiV1.TLE_PARTIAL_RELEASE_PATH, routes.get("tle_partial_release"));
    assertEquals(ParliamentApiV1.TRANSITION_DRAFT_PATH, routes.get("transition_draft"));
    final Map<String, Object> wireIds = objectValue(fixture.get("wire_ids"));
    assertEquals(ParliamentApiV1.ATTEMPT_CREATE_WIRE_ID, wireIds.get("attempt_create"));
    assertEquals(ParliamentApiV1.TRANSITION_SUBMIT_WIRE_ID, wireIds.get("transition_submit"));
    assertEquals(org.hyperledger.iroha.sdk.client.ParliamentApiV1.PROPOSAL_KINDS, fixture.get("proposal_kinds"));
    assertEquals(
        ParliamentApiV1.CONTRACT_LIFECYCLE_ACTIONS,
        fixture.get("contract_lifecycle_actions"));
    final Map<String, Object> limits = objectValue(fixture.get("limits"));
    assertEquals(
        ParliamentApiV1.MAX_STATE_BYTES,
        ((Number) limits.get("attempt_state_bytes")).intValue());
    assertEquals(
        ParliamentApiV1.TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS,
        ((Number) limits.get("timed_ovn_ballot_chunk_max_records")).intValue());
    assertEquals(
        ParliamentApiV1.MAX_TIMED_OVN_CORPUS_ENTRIES,
        ((Number) limits.get("timed_ovn_corpus_entries")).intValue());
    assertEquals(
        ParliamentApiV1.TIMED_OVN_CASTING_PROOF_REQUEST_BYTES,
        ((Number) limits.get("timed_ovn_casting_proof_request_bytes")).intValue());
    assertEquals(
        ParliamentApiV1.MAX_TIMED_OVN_CASTING_PROOF_RESPONSE_BYTES,
        ((Number) limits.get("timed_ovn_casting_proof_response_bytes")).intValue());
    assertEquals(
        ParliamentApiV1.MAX_TIMED_OVN_CASTING_PROOF_FINALITY_PROOFS,
        ((Number) limits.get("timed_ovn_casting_proof_finality_entries")).intValue());
    final Map<String, Object> nativeWallet =
        objectValue(fixture.get("timed_ovn_native_wallet"));
    assertEquals(
        ParliamentApiV1.TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA,
        nativeWallet.get("request_norito_schema"));
    assertEquals(
        ParliamentApiV1.TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA,
        nativeWallet.get("response_norito_schema"));
    assertEquals(
        ParliamentApiV1.TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_HASH_HEX,
        nativeWallet.get("casting_proof_request_schema_hash_hex"));
    assertEquals(
        ParliamentApiV1.TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX,
        nativeWallet.get("casting_proof_response_schema_hash_hex"));
    assertEquals(
        ParliamentApiV1.TIMED_OVN_CASTING_PROOF_REQUEST_VERSION,
        ((Number) nativeWallet.get("casting_proof_request_version")).intValue());
    assertEquals(
        ParliamentApiV1.TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS,
        ((Number) nativeWallet.get("casting_proof_request_flags")).intValue());
    assertEquals(
        ParliamentApiV1.TIMED_OVN_CASTING_PROOF_REQUEST_PAYLOAD_ALIGNMENT,
        ((Number) nativeWallet.get("casting_proof_request_payload_alignment")).intValue());
    assertEquals(
        ParliamentApiV1.TIMED_OVN_CASTING_PROOF_REQUEST_PADDING_BYTES,
        ((Number) nativeWallet.get("casting_proof_request_padding_bytes")).intValue());
    final Map<String, Object> castingGolden =
        objectValue(nativeWallet.get("casting_proof_request_golden"));
    assertEquals(
        ParliamentApiV1.TIMED_OVN_CASTING_PROOF_REQUEST_BYTES,
        ((Number) castingGolden.get("frame_bytes")).intValue());
    assertArrayEquals(
        decodeTestHex((String) castingGolden.get("frame_hex")),
        ParliamentApiV1.timedOvnCastingProofRequestNorito(
            BigInteger.valueOf(
                ((Number) castingGolden.get("trusted_checkpoint_height")).longValue())));

    final List<?> transitions = (List<?>) fixture.get("public_transitions");
    assertEquals(ParliamentApiV1.PUBLIC_TRANSITIONS.size(), transitions.size());
    for (int i = 0; i < transitions.size(); i++) {
      final ParliamentApiV1.TransitionLayout layout =
          ParliamentApiV1.PUBLIC_TRANSITIONS.get(i);
      final Map<String, Object> entry = objectValue(transitions.get(i));
      assertEquals(layout.noritoIndex, ((Number) entry.get("norito_index")).intValue());
      assertEquals(String.format("%02x", layout.noritoIndex), entry.get("norito_prefix_hex"));
      assertEquals(layout.jsonTag, entry.get("json_tag"));
      assertEquals(
          layout.jsonPayloadRequired ? "required" : "forbidden",
          entry.get("json_payload"));
      assertEquals(layout.eventKindIndex, ((Number) entry.get("event_kind_index")).intValue());

      final String transitionJson =
          layout.jsonPayloadRequired
              ? "{\"transition\":\"" + layout.jsonTag + "\",\"payload\":{}}"
              : "{\"transition\":\"" + layout.jsonTag + "\"}";
      ParliamentApiV1.transitionDraftRequestJson(
          ATTEMPT_ID,
          layout.jsonTag.equals("FreezeTimedOvnCorpus")
              ? freezeTimedOvnTransition(1, ParliamentApiV1.TIMED_OVN_BALLOT_RECORD_BYTES)
              : bytes(transitionJson));
    }

    final List<?> outcomes = (List<?>) fixture.get("automatic_execution_outcomes");
    assertEquals(ParliamentApiV1.AUTOMATIC_EXECUTION_OUTCOMES.size(), outcomes.size());
    for (int i = 0; i < outcomes.size(); i++) {
      final ParliamentApiV1.AutomaticOutcomeLayout layout =
          ParliamentApiV1.AUTOMATIC_EXECUTION_OUTCOMES.get(i);
      final Map<String, Object> entry = objectValue(outcomes.get(i));
      assertEquals(layout.noritoIndex, ((Number) entry.get("norito_index")).intValue());
      assertEquals(layout.jsonTag, entry.get("json_tag"));
      assertEquals(layout.eventKind, entry.get("event_kind"));
      assertEquals(layout.eventKindIndex, ((Number) entry.get("event_kind_index")).intValue());
    }

    final Map<String, Object> digestDomains = objectValue(fixture.get("digest_domains"));
    assertEquals(
        ParliamentApiV1.PUBLIC_TRANSITION_DIGEST_DOMAIN,
        digestDomains.get("public_transition"));
    assertEquals(
        ParliamentApiV1.AUTOMATIC_OUTCOME_DIGEST_DOMAIN,
        digestDomains.get("automatic_execution_outcome"));
    final Map<String, String> fixtureRootDomains = new LinkedHashMap<>();
    for (final Object raw : (List<?>) fixture.get("certificate_result_roots")) {
      final Map<String, Object> entry = objectValue(raw);
      fixtureRootDomains.put((String) entry.get("name"), (String) entry.get("domain"));
    }
    assertEquals(ParliamentApiV1.CERTIFICATE_RESULT_ROOT_DOMAINS, fixtureRootDomains);

    final Map<String, Object> binding = objectValue(fixture.get("certificate_body_binding"));
    assertEquals(
        ParliamentApiV1.CERTIFICATE_BODY_BINDING_NORITO_FIELDS,
        binding.get("norito_field_order"));
    final Map<String, Object> publicFinding =
        objectValue(binding.get("public_nonbinding_body"));
    assertEquals(
        ParliamentApiV1.PUBLIC_FINDING_CERTIFICATE_NORITO_FIELDS,
        publicFinding.get("public_finding_norito_field_order"));
    assertEquals("ceil(2 * original_seats / 3)", publicFinding.get("quorum"));
    assertEquals(
        "strictly increasing distinct nonzero assignment ids",
        publicFinding.get("endorsing_assignments"));
    assertEquals("endorsing_assignments.length == quorum", publicFinding.get("endorsements"));
    final Map<String, Object> privateJury = objectValue(binding.get("private_jury"));
    assertEquals("forbidden", privateJury.get("public_finding"));
    assertEquals("ballot.tally.original_seats", privateJury.get("original_seats"));
    final List<?> noResultKinds = (List<?>) fixture.get("no_result_kinds");
    assertEquals(ParliamentApiV1.NO_RESULT_KINDS.size(), noResultKinds.size());
    for (int i = 0; i < noResultKinds.size(); i++) {
      final Map<String, Object> fixtureKind = objectValue(noResultKinds.get(i));
      assertEquals(
          ParliamentApiV1.NO_RESULT_KINDS.get(i).jsonTag,
          fixtureKind.get("json_tag"));
      assertEquals(
          ParliamentApiV1.NO_RESULT_KINDS.get(i).noritoIndex,
          ((Number) fixtureKind.get("norito_index")).intValue());
    }
    assertEquals(
        ParliamentApiV1.BODY_STATE_FIELDS,
        objectValue(fixture.get("attempt_read_body_state")).get("json_fields"));
    assertEquals(ParliamentApiV1.CANONICAL_BODY_ORDER, fixture.get("canonical_body_order"));
    assertEquals(
        "strictly increasing subset of canonical_body_order",
        objectValue(fixture.get("attempt_read_body_presentation")).get("subset_rule"));
    assertEquals(
        List.of(
            "version",
            "key_session_id",
            "network_id",
            "roster_hash",
            "committee_size",
            "threshold",
            "generator_h",
            "generator_v",
            "qualified_dealers",
            "qualified_dealer_commitments",
            "dkg_event_hash",
            "group_public_key",
            "public_shares",
            "transcript_hash"),
        objectValue(fixture.get("tle_release_context")).get("transcript_public_state_fields"));
    assertEquals(
        9,
        ((List<?>) objectValue(fixture.get("tle_partial_release")).get("response_fields")).size());
  }

  @Test
  public void attemptBuilderAdmitsExactlyTheTenFirstReleaseProposalKinds() throws Exception {
    for (final String kind : org.hyperledger.iroha.sdk.client.ParliamentApiV1.PROPOSAL_KINDS) {
      final Map<String, Object> request =
          objectValue(
              org.hyperledger.iroha.sdk.client.ParliamentApiV1.attemptDraftRequestJson(
                  proposal(kind), 0));
      assertEquals(kind, objectValue(request.get("proposal")).get("kind"));
    }
    assertEquals(10, org.hyperledger.iroha.sdk.client.ParliamentApiV1.PROPOSAL_KINDS.size());

    final Map<String, Object> fullU64Policy = validProposal("ValidationFeePolicy");
    final Map<String, Object> fullU64PolicyValue =
        objectValue(objectValue(fullU64Policy.get("payload")).get("policy"));
    fullU64PolicyValue.put("policy_version", "18446744073709551615");
    fullU64PolicyValue.put("previous_policy_hash", repeatedNumbers(32, 1));
    fullU64PolicyValue.put("effective_from_height", "18446744073709551615");
    org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(fullU64Policy));

    for (final String kind :
        List.of(
            "ProposeDeployContract",
            "EnactReferendum",
            "FinalizeReferendum",
            "deploy_contract",
            "runtimeUpgrade",
            "Unknown",
            "KagemushaVerifierPolicyInstall",
            "KagemushaVerifierReleaseInstall",
            "KagemushaVerifierReleaseActivate",
            "KagemushaVerifierReleaseRetire")) {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              org.hyperledger.iroha.sdk.client.ParliamentApiV1.attemptDraftRequestJson(
                  org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(
                      bytes("{\"kind\":\"" + kind + "\",\"payload\":{}}")),
                  0));
    }
    assertThrows(
        IllegalArgumentException.class,
        () ->
            org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(
                bytes("{\"proposal_kind\":\"RuntimeUpgrade\",\"payload\":{}}")));
  }

  @Test
  public void contractLifecycleActionInventoryIsClosed() {
    for (final String action : ParliamentApiV1.CONTRACT_LIFECYCLE_ACTIONS) {
      final Map<String, Object> proposal = validProposal("ContractLifecycleGovernance");
      final Object actionPayload;
      switch (action) {
        case "Activate" ->
            actionPayload =
                map(
                    "code_hash", "11".repeat(32),
                    "abi_hash", "22".repeat(32),
                    "abi_version", 1,
                    "manifest_provenance", null);
        case "Deactivate" ->
            actionPayload = map("expected_code_hash", "11".repeat(32));
        case "OfferOwnership" -> actionPayload = map("new_owner", account(5));
        case "CancelOwnershipOffer", "AcceptParliamentOwnership" -> actionPayload = null;
        case "CompleteEmergencyHoldRetrospective" ->
            actionPayload =
                map(
                    "hold_proposal_content_id", repeatedNumbers(32, 0x51),
                    "hold_governance_attempt_id", repeatedNumbers(32, 0x52),
                    "incident_digest", repeatedNumbers(32, 0x53),
                    "retrospective_finding_root", repeatedNumbers(32, 0x54));
        default -> throw new AssertionError("unsupported fixture action " + action);
      }
      objectValue(proposal.get("payload"))
          .put("action", map("action", action, "payload", actionPayload));
      org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(proposal));
    }

    final Map<String, Object> proposal = validProposal("ContractLifecycleGovernance");
    objectValue(proposal.get("payload"))
        .put("action", map("action", "Unknown", "payload", null));
    assertThrows(
        IllegalArgumentException.class,
        () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(proposal)));
  }

  @Test
  public void sccpRouteGovernanceAdmitsOnlyTheClosedProposalEnvelope() {
    for (final Map<String, Object> subject :
        List.of(
            sccpSubject("parameters", null),
            sccpSubject("light_client", bscMainnet()),
            sccpSubject("bridge_key_fault", "ea0130" + "AB".repeat(48)))) {
      org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(
          sccpProposal(proposal -> proposal.put("base_revisions", List.of(subject))));
    }

    final List<Consumer<Map<String, Object>>> rejected =
        List.of(
            proposal -> proposal.put("anchor", null),
            proposal -> proposal.remove("base_revisions"),
            proposal -> proposal.put("base_revisions", List.of()),
            proposal -> proposal.put("actions", List.of()),
            proposal ->
                proposal.put(
                    "actions",
                    Collections.nCopies(17, ((List<?>) proposal.get("actions")).get(0))),
            proposal ->
                proposal.put(
                    "base_revisions", List.of(sccpSubject("sora_taira", bscMainnet()))),
            proposal ->
                proposal.put(
                    "base_revisions", List.of(sccpSubject("parameters", bscMainnet()))),
            proposal ->
                proposal.put(
                    "base_revisions",
                    List.of(sccpSubject("bridge_key_fault", "ea0130" + "ab".repeat(48)))),
            proposal ->
                proposal.put(
                    "base_revisions",
                    List.of(
                        sccpSubject(
                            "route", map("network", "sora_taira", "profile", null)))),
            proposal ->
                proposal.put("actions", List.of(map("action", "Remove", "payload", map()))),
            proposal ->
                proposal.put(
                    "actions", List.of(map("action", "freeze_light_client", "payload", null))));
    for (final Consumer<Map<String, Object>> edit : rejected) {
      final byte[] encoded = sccpProposal(edit);
      assertThrows(
          IllegalArgumentException.class, () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encoded));
    }

    final Map<String, Object> anchorProposal = validProposal("SccpRouteGovernance");
    anchorProposal.put(
        "payload", map("anchor", map("network_id", networkId(), "action", map())));
    assertThrows(
        IllegalArgumentException.class,
        () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(anchorProposal)));
  }

  @Test
  public void effectSensitiveProposalsRequireExactOperator() {
    for (final String kind :
        List.of("DeployContract", "RuntimeUpgrade", "ContractLifecycleGovernance")) {
      final Map<String, Object> valid = validProposal(kind);
      org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(valid));

      final Map<String, Object> payload = objectValue(valid.get("payload"));
      payload.remove("proposal_operator");
      assertThrows(
          IllegalArgumentException.class,
          () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(valid)));
      payload.put("proposal_operator", "not-an-account");
      assertThrows(
          IllegalArgumentException.class,
          () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(valid)));
    }
  }

  @Test
  public void contractLifecycleUnitActionsRequireExplicitNullPayload() {
    for (final String action :
        List.of("CancelOwnershipOffer", "AcceptParliamentOwnership")) {
      final Map<String, Object> proposal = validProposal("ContractLifecycleGovernance");
      final Map<String, Object> payload = objectValue(proposal.get("payload"));
      payload.put("action", map("action", action, "payload", null));
      org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(proposal));

      objectValue(payload.get("action")).remove("payload");
      assertThrows(
          IllegalArgumentException.class,
          () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(proposal)));
    }
  }

  @Test
  public void globalDataTriggerPermissionRequiresExactAccountAndClosedUnitAction() {
    for (final String action : Arrays.asList("grant", "revoke")) {
      final Map<String, Object> proposal =
          validProposal("GlobalDataTriggerPermissionGovernance");
      objectValue(proposal.get("payload"))
          .put("action", map("action", action, "value", null));
      org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(proposal));
    }

    final Map<String, Object> malformed =
        validProposal("GlobalDataTriggerPermissionGovernance");
    final Map<String, Object> action =
        objectValue(objectValue(malformed.get("payload")).get("action"));
    action.put("value", new java.util.LinkedHashMap<String, Object>());
    assertThrows(
        IllegalArgumentException.class,
        () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(malformed)));
    action.put("value", null);
    action.put("action", "delegate");
    assertThrows(
        IllegalArgumentException.class,
        () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(malformed)));
  }

  @Test
  public void attemptDraftSequenceAcceptsSixteenAndRejectsSeventeen() {
    final Map<String, Object> accepted =
        objectValue(
            org.hyperledger.iroha.sdk.client.ParliamentApiV1.attemptDraftRequestJson(
                proposal("RuntimeUpgrade"),
                ParliamentApiV1.MAX_GOVERNANCE_ATTEMPT_RETRIES));
    assertEquals(
        (long) ParliamentApiV1.MAX_GOVERNANCE_ATTEMPT_RETRIES,
        accepted.get("attempt_sequence"));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            org.hyperledger.iroha.sdk.client.ParliamentApiV1.attemptDraftRequestJson(
                proposal("RuntimeUpgrade"),
                (long) ParliamentApiV1.MAX_GOVERNANCE_ATTEMPT_RETRIES + 1L));
  }

  @Test
  public void proposalAdmissionRejectsMissingUnknownAndMalformedNestedFields() {
    final Map<String, Object> runtime = validProposal("RuntimeUpgrade");
    objectValue(objectValue(runtime.get("payload")).get("manifest")).remove("provenance");
    assertThrows(
        IllegalArgumentException.class,
        () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(runtime)));

    final Map<String, Object> provider = validProposal("SorafsProviderGovernance");
    objectValue(objectValue(provider.get("payload")).get("action"))
        .put("legacy_owner", account(9));
    assertThrows(
        IllegalArgumentException.class,
        () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(provider)));

    final Map<String, Object> malformedProvider =
        validProposal("SorafsProviderGovernance");
    objectValue(
            objectValue(objectValue(malformedProvider.get("payload")).get("action"))
                .get("value"))
        .put("provider_id", repeatedNumbers(32, 1));
    assertThrows(
        IllegalArgumentException.class,
        () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(malformedProvider)));

    final Map<String, Object> malformedAccount =
        validProposal("MusubiRegistryGovernance");
    objectValue(objectValue(malformedAccount.get("payload")).get("value"))
        .put("owners", Arrays.asList("alice@legacy"));
    assertThrows(
        IllegalArgumentException.class,
        () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(malformedAccount)));

    final Map<String, Object> zeroRetrospective =
        validProposal("ContractLifecycleGovernance");
    objectValue(
            objectValue(objectValue(zeroRetrospective.get("payload")).get("action"))
                .get("payload"))
        .put("retrospective_finding_root", repeatedNumbers(32, 0));
    assertThrows(
        IllegalArgumentException.class,
        () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(zeroRetrospective)));

    final Map<String, Object> excessiveHold = validProposal("ContractEmergencyHold");
    objectValue(excessiveHold.get("payload")).put("duration_blocks", 3_601);
    assertThrows(
        IllegalArgumentException.class,
        () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(excessiveHold)));

    final Map<String, Object> impreciseHeight = validProposal("RuntimeUpgrade");
    objectValue(objectValue(impreciseHeight.get("payload")).get("manifest"))
        .put("start_height", new BigInteger("9007199254740992"));
    assertThrows(
        IllegalArgumentException.class,
        () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(impreciseHeight)));
  }

  @Test
  public void transitionBuilderRejectsRemovedOutcomeTagsAndPayloadAliases() {
    for (final String tag :
        List.of(
            "ConstructCertificate",
            "MarkEnacted",
            "MarkSuperseded",
            "MarkExecutionFailed",
            "PlainBallotFallback")) {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              ParliamentApiV1.transitionDraftRequestJson(
                  ATTEMPT_ID,
                  bytes("{\"transition\":\"" + tag + "\",\"payload\":{}}")));
    }
    assertThrows(
        IllegalArgumentException.class,
        () ->
            ParliamentApiV1.transitionDraftRequestJson(
                ATTEMPT_ID,
                bytes("{\"transition\":\"CompleteQualification\",\"payload\":{}}")));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            ParliamentApiV1.transitionDraftRequestJson(
                ATTEMPT_ID, bytes("{\"transition\":\"EscalateRisk\"}")));
  }

  @Test
  public void timedOvnCorpusTransitionPreflightsOneThrough32RecordsPerChunk() {
    for (final int count :
        List.of(1, ParliamentApiV1.TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS)) {
      ParliamentApiV1.transitionDraftRequestJson(
          ATTEMPT_ID,
          freezeTimedOvnTransition(count, ParliamentApiV1.TIMED_OVN_BALLOT_RECORD_BYTES));
    }
    for (final int count :
        List.of(0, ParliamentApiV1.TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS + 1)) {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              ParliamentApiV1.transitionDraftRequestJson(
                  ATTEMPT_ID,
                  freezeTimedOvnTransition(
                      count, ParliamentApiV1.TIMED_OVN_BALLOT_RECORD_BYTES)));
    }
    assertThrows(
        IllegalArgumentException.class,
        () ->
            ParliamentApiV1.transitionDraftRequestJson(
                ATTEMPT_ID,
                freezeTimedOvnTransition(
                    1, ParliamentApiV1.TIMED_OVN_BALLOT_RECORD_BYTES - 1)));
  }

  @Test
  public void requestBuildersExposeOnlyCanonicalFieldsAndRoutes() {
    final Map<String, Object> attempt =
        objectValue(
            org.hyperledger.iroha.sdk.client.ParliamentApiV1.attemptDraftRequestJson(
                proposal("RuntimeUpgrade"), 7));
    assertEquals(Set.of("version", "proposal", "attempt_sequence"), attempt.keySet());
    assertEquals(1L, attempt.get("version"));
    assertEquals(7L, attempt.get("attempt_sequence"));

    final Map<String, Object> transition =
        objectValue(
            ParliamentApiV1.transitionDraftRequestJson(
                ATTEMPT_ID, bytes("{\"transition\":\"CompleteQualification\"}")));
    assertEquals(
        Set.of("version", "governance_attempt_id", "transition"), transition.keySet());
    assertEquals(ATTEMPT_ID, transition.get("governance_attempt_id"));
    assertEquals(
        "/v1/gov/parliament/attempts/" + ATTEMPT_ID,
        ParliamentApiV1.attemptReadPath(ATTEMPT_ID));
    final String ballotId = "33".repeat(32);
    assertEquals(
        "/v1/gov/parliament/ballots/" + ballotId + "/casting-context",
        ParliamentApiV1.timedOvnCastingContextReadPath(ballotId));
    assertEquals(
        "/v1/gov/parliament/ballots/" + ballotId + "/casting-proof",
        ParliamentApiV1.timedOvnCastingProofPath(ballotId));
    assertEquals(
        "/v1/gov/parliament/ballots/" + ballotId + "/release-context",
        ParliamentApiV1.tleReleaseContextReadPath(ballotId));
    assertEquals(
        "/v1/gov/parliament/ballots/" + ballotId + "/partial-release",
        ParliamentApiV1.tlePartialReleasePath(ballotId));

    assertThrows(
        IllegalArgumentException.class,
        () ->
            ParliamentApiV1.transitionDraftRequestJson(
                ATTEMPT_ID,
                bytes(
                    "{\"transition\":\"CompleteQualification\",\"authority\":\"alice\"}")));
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.attemptReadPath(ATTEMPT_ID.toUpperCase()));
  }

  @Test
  public void castingProofNoritoPinsU64GoldenAndRejectsNoncanonicalResponses() {
    final byte[] golden =
        decodeTestHex(
            "4e5254300000adccf322a5fcf43040e20bea238f55f3000c00000000000000"
                + "dfab61022cefc29f02020100081100000000000000");
    assertArrayEquals(
        golden,
        ParliamentApiV1.timedOvnCastingProofRequestNorito(BigInteger.valueOf(17L)));
    assertArrayEquals(
        golden, new ParliamentApiV1.TimedOvnCastingProofRequest(17L).toNoritoBytes());
    final BigInteger maximum = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
    final byte[] maximumFrame =
        ParliamentApiV1.timedOvnCastingProofRequestNorito(maximum);
    final byte[] maximumHeightBytes = new byte[8];
    Arrays.fill(maximumHeightBytes, (byte) 0xff);
    assertArrayEquals(
        maximumHeightBytes, Arrays.copyOfRange(maximumFrame, 44, 52));
    for (final BigInteger height :
        Arrays.asList(BigInteger.ZERO, BigInteger.valueOf(-1L), BigInteger.ONE.shiftLeft(64))) {
      assertThrows(
          IllegalArgumentException.class,
          () -> ParliamentApiV1.timedOvnCastingProofRequestNorito(height));
    }

    final byte[] payload = new byte[] {2, 1, 0, 1};
    final NoritoHeader header =
        new NoritoHeader(
            decodeTestHex(ParliamentApiV1.TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX),
            payload.length,
            CRC64.compute(payload),
            NoritoHeader.COMPACT_LEN,
            NoritoHeader.COMPRESSION_NONE);
    final byte[] canonical = concat(header.encode(), payload);
    final ParliamentTimedOvnCastingProofResponseV1 parsed =
        org.hyperledger.iroha.sdk.client.ParliamentApiV1.parseTimedOvnCastingProofResponse(canonical);
    assertArrayEquals(canonical, parsed.canonicalNorito());
    assertArrayEquals(payload, parsed.payload());
    parsed.canonicalNorito()[0] = 0;
    parsed.payload()[0] = 0;
    assertArrayEquals(canonical, parsed.canonicalNorito());
    assertArrayEquals(payload, parsed.payload());

    final byte[] wrongSchema =
        concat(
            new NoritoHeader(
                    repeatedBytes(16, 7),
                    payload.length,
                    CRC64.compute(payload),
                    NoritoHeader.COMPACT_LEN,
                    NoritoHeader.COMPRESSION_NONE)
                .encode(),
            payload);
    final byte[] badChecksum = canonical.clone();
    badChecksum[badChecksum.length - 1]++;
    final byte[] compressed = canonical.clone();
    compressed[22] = 1;
    final byte[] padded = concat(header.encode(), new byte[] {0}, payload);
    final byte[] wrongFlags =
        concat(
            new NoritoHeader(
                    decodeTestHex(
                        ParliamentApiV1.TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX),
                    payload.length,
                    CRC64.compute(payload),
                    0,
                    NoritoHeader.COMPRESSION_NONE)
                .encode(),
            payload);
    for (final byte[] hostile :
        Arrays.asList(wrongSchema, badChecksum, compressed, padded, wrongFlags)) {
      assertThrows(
          IllegalArgumentException.class,
          () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.parseTimedOvnCastingProofResponse(hostile));
    }
    assertThrows(
        IllegalArgumentException.class,
        () ->
            org.hyperledger.iroha.sdk.client.ParliamentApiV1.parseTimedOvnCastingProofResponse(
                new byte[ParliamentApiV1.MAX_TIMED_OVN_CASTING_PROOF_RESPONSE_BYTES + 1]));
  }

  @Test
  public void strictDraftParsersBindVersionIdentifiersDigestAndWireIds() {
    final Map<String, Object> attemptResponse = new LinkedHashMap<>();
    attemptResponse.put("version", 1);
    attemptResponse.put("proposal_content_id", PROPOSAL_ID);
    attemptResponse.put("governance_attempt_id", ATTEMPT_ID);
    attemptResponse.put(
        "tx_instructions",
        List.of(
            instruction(ParliamentApiV1.ATTEMPT_CREATE_WIRE_ID, "0102")));
    final ParliamentApiV1.AttemptDraftResponse parsedAttempt =
        ParliamentApiV1.parseAttemptDraftResponse(
            encode(attemptResponse), PROPOSAL_ID, ATTEMPT_ID);
    assertEquals(ATTEMPT_ID, parsedAttempt.governanceAttemptId);

    final byte[] digest = new byte[32];
    java.util.Arrays.fill(digest, (byte) 0x55);
    final List<Integer> digestJson = new ArrayList<>();
    for (final byte value : digest) digestJson.add(value & 0xff);
    final Map<String, Object> transitionResponse = new LinkedHashMap<>();
    transitionResponse.put("version", 1);
    transitionResponse.put("governance_attempt_id", ATTEMPT_ID);
    transitionResponse.put("transition_kind", Map.of("kind", "CompleteQualification"));
    transitionResponse.put("transition_digest", digestJson);
    transitionResponse.put(
        "tx_instructions",
        List.of(
            instruction(ParliamentApiV1.TRANSITION_SUBMIT_WIRE_ID, "0304")));
    final ParliamentApiV1.TransitionDraftResponse parsedTransition =
        ParliamentApiV1.parseTransitionDraftResponse(
            encode(transitionResponse), ATTEMPT_ID, "CompleteQualification", digest);
    assertArrayEquals(digest, parsedTransition.transitionDigest);

    final Map<String, Object> wrongVersion = new LinkedHashMap<>(attemptResponse);
    wrongVersion.put("version", 2);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            ParliamentApiV1.parseAttemptDraftResponse(
                encode(wrongVersion), PROPOSAL_ID, ATTEMPT_ID));
    final Map<String, Object> unknown = new LinkedHashMap<>(attemptResponse);
    unknown.put("private_key", "secret");
    assertThrows(
        IllegalArgumentException.class,
        () ->
            ParliamentApiV1.parseAttemptDraftResponse(
                encode(unknown), PROPOSAL_ID, ATTEMPT_ID));
  }

  @Test
  public void readParserRejectsAliasesAndMismatchedState() {
    final Map<String, Object> response = readResponse();
    final ParliamentApiV1.AttemptReadResponse parsed =
        ParliamentApiV1.parseAttemptReadResponse(encode(response), ATTEMPT_ID);
    assertEquals("13", parsed.currentHeight);
    assertEquals(List.of("rules-committee", "policy-jury"), parsed.requiredBodyOrder);
    assertEquals("rules-committee", parsed.bodyStates.get(0).body);
    assertEquals(List.of("rules-committee", "policy-jury"), parsed.certificateBodyOrder);
    assertEquals(
        List.of("11".repeat(32), "12".repeat(32)),
        parsed.publicFindingBindings.get(0).endorsingAssignments);

    final Map<String, Object> canonicalOrder = new LinkedHashMap<>(response);
    final Map<String, Object> canonicalAttempt =
        new LinkedHashMap<>(objectValue(response.get("attempt")));
    canonicalAttempt.put("stage", Map.of("stage", "Qualification"));
    canonicalAttempt.put("status", Map.of("status", "Active"));
    canonicalOrder.put("attempt", canonicalAttempt);
    canonicalOrder.put("certificate", null);
    final List<Map<String, Object>> requiredBodies = new ArrayList<>();
    final List<Map<String, Object>> bodyStates = new ArrayList<>();
    for (final String body : ParliamentApiV1.CANONICAL_BODY_ORDER) {
      requiredBodies.add(
          Map.of(
              "body",
              body,
              "decision_mode",
              Map.of(
                  "mode",
                  body.equals("policy-jury") || body.equals("confirmation-jury")
                      ? "HiddenBindingBallot"
                      : "PublicFinding")));
      final Map<String, Object> state = new LinkedHashMap<>();
      state.put("body", body);
      state.put("body_instance_id", null);
      state.put("status", null);
      state.put("public_finding_opened_at_height", null);
      state.put("public_finding_phase_blocks", null);
      state.put("public_finding_deadline_height", null);
      state.put("no_result_kind", null);
      state.put("no_result_height", null);
      state.put("timed_ovn_progress", null);
      bodyStates.add(state);
    }
    canonicalOrder.put("required_bodies", requiredBodies);
    canonicalOrder.put("body_states", bodyStates);
    final ParliamentApiV1.AttemptReadResponse canonicalParsed =
        ParliamentApiV1.parseAttemptReadResponse(encode(canonicalOrder), ATTEMPT_ID);
    assertEquals(ParliamentApiV1.CANONICAL_BODY_ORDER, canonicalParsed.requiredBodyOrder);
    assertEquals(
        ParliamentApiV1.CANONICAL_BODY_ORDER,
        canonicalParsed.bodyStates.stream().map(state -> state.body).toList());
    assertEquals(List.of(), canonicalParsed.certificateBodyOrder);

    final Map<String, Object> reordered = new LinkedHashMap<>(canonicalOrder);
    final List<Map<String, Object>> reorderedRequired = new ArrayList<>(requiredBodies);
    Collections.swap(reorderedRequired, 0, 1);
    reordered.put("required_bodies", reorderedRequired);
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(reordered), ATTEMPT_ID));

    final Map<String, Object> alias = new LinkedHashMap<>(response);
    alias.put("statePayloadHex", alias.remove("state_payload_hex"));
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(alias), ATTEMPT_ID));
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(response), "66".repeat(32)));

    final Map<String, Object> barePayload = new LinkedHashMap<>(response);
    barePayload.put("state_payload_hex", "0102");
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(barePayload), ATTEMPT_ID));

    final Map<String, Object> badChecksum = new LinkedHashMap<>(response);
    final byte[] tampered = stateFrame();
    tampered[tampered.length - 1]++;
    badChecksum.put("state_payload_hex", toHex(tampered));
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(badChecksum), ATTEMPT_ID));

    final Map<String, Object> wrongDeadline = readResponse();
    final List<Map<String, Object>> states = maps(wrongDeadline.get("body_states"));
    states.get(0).put("public_finding_deadline_height", 9);
    wrongDeadline.put("body_states", states);
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(wrongDeadline), ATTEMPT_ID));

    final Map<String, Object> unsorted = readResponse();
    final Map<String, Object> certificate = objectValue(unsorted.get("certificate"));
    final List<Map<String, Object>> bindings = maps(certificate.get("body_bindings"));
    final Map<String, Object> finding = objectValue(bindings.get(0).get("public_finding"));
    finding.put("endorsing_assignments", List.of("12".repeat(32), "11".repeat(32)));
    bindings.get(0).put("public_finding", finding);
    certificate.put("body_bindings", bindings);
    unsorted.put("certificate", certificate);
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(unsorted), ATTEMPT_ID));

    assertCertificateMutationRejected(
        certificateValue -> certificateValue.put("proposal_content_id", "ee".repeat(32)));
    assertCertificateMutationRejected(
        certificateValue -> certificateValue.put("governance_attempt_sequence", 1));
    assertCertificateMutationRejected(
        certificateValue -> certificateValue.put("risk_tier", Map.of("tier", "Emergency")));
    assertCertificateMutationRejected(
        certificateValue -> certificateValue.put("policy_version", 2));
    assertCertificateMutationRejected(
        certificateValue -> certificateValue.put("enact_at_height", 8));
    assertCertificateMutationRejected(
        certificateValue -> certificateValue.put("certified_at_height", 13));
    assertCertificateMutationRejected(
        certificateValue -> {
          final Map<String, Object> bindingValue =
              maps(certificateValue.get("body_bindings")).get(0);
          final Map<String, Object> request =
              new LinkedHashMap<>(objectValue(bindingValue.get("sortition_request")));
          request.put("beacon_session_id", "ee".repeat(32));
          bindingValue.put("sortition_request", request);
          certificateValue.put("body_bindings", List.of(bindingValue));
        });
    assertCertificateMutationRejected(
        certificateValue -> {
          final Map<String, Object> bindingValue =
              maps(certificateValue.get("body_bindings")).get(0);
          final Map<String, Object> request =
              new LinkedHashMap<>(objectValue(bindingValue.get("sortition_request")));
          request.put("request_height", 0);
          bindingValue.put("sortition_request", request);
          certificateValue.put("body_bindings", List.of(bindingValue));
        });
    assertCertificateMutationRejected(
        certificateValue -> {
          final Map<String, Object> bindingValue =
              maps(certificateValue.get("body_bindings")).get(0);
          bindingValue.put("election_attempt_sequence", 17);
          certificateValue.put("body_bindings", List.of(bindingValue));
        });

    final Map<String, Object> largeElectorate = readResponse();
    final Map<String, Object> largeCertificate = objectValue(largeElectorate.get("certificate"));
    final List<Map<String, Object>> largeBindings =
        maps(largeCertificate.get("body_bindings"));
    final Map<String, Object> largeBinding = largeBindings.get(0);
    final Map<String, Object> largeRequest =
        new LinkedHashMap<>(objectValue(largeBinding.get("sortition_request")));
    largeRequest.put("candidate_count", 1_001);
    largeBinding.put("sortition_request", largeRequest);
    largeCertificate.put("body_bindings", largeBindings);
    ParliamentApiV1.parseAttemptReadResponse(encode(largeElectorate), ATTEMPT_ID);

    largeRequest.put("candidate_count", 4_294_967_295L);
    ParliamentApiV1.parseAttemptReadResponse(encode(largeElectorate), ATTEMPT_ID);
    largeRequest.put("candidate_count", 4_294_967_296L);
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(largeElectorate), ATTEMPT_ID));

    assertCertificateMutationRejected(
        certificateValue -> {
          final Map<String, Object> bindingValue =
              maps(certificateValue.get("body_bindings")).get(0);
          bindingValue.put("original_seats", 4);
          certificateValue.put("body_bindings", List.of(bindingValue));
        });
    assertCertificateMutationRejected(
        certificateValue ->
            certificateValue.put(
                "expected_head",
                Map.of(
                    "state",
                    "Present",
                    "head",
                    Map.of(
                        "subject_id", byteValues(32, 0x55),
                        "version", 0,
                        "head_root", byteValues(32, 0x55)))));

    assertThrows(
        IllegalArgumentException.class,
        () ->
            ParliamentApiV1.parseAttemptReadResponse(
                encode(publicOnlyReadResponse()), ATTEMPT_ID));

    final Map<String, Object> wrongProjectionPolicy = readResponse();
    wrongProjectionPolicy.put("policy_version", 2);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            ParliamentApiV1.parseAttemptReadResponse(
                encode(wrongProjectionPolicy), ATTEMPT_ID));

    final Map<String, Object> excessiveAttemptRetry = readResponse();
    final Map<String, Object> retryAttempt =
        new LinkedHashMap<>(objectValue(excessiveAttemptRetry.get("attempt")));
    retryAttempt.put("sequence", 17);
    excessiveAttemptRetry.put("attempt", retryAttempt);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            ParliamentApiV1.parseAttemptReadResponse(
                encode(excessiveAttemptRetry), ATTEMPT_ID));

    final Map<String, Object> wrongMode = readResponse();
    wrongMode.put(
        "required_bodies",
        List.of(
            Map.of(
                "body", "rules-committee",
                "decision_mode", Map.of("mode", "HiddenBindingBallot"))));
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(wrongMode), ATTEMPT_ID));

    ParliamentApiV1.parseAttemptReadResponse(encode(hiddenBallotResponse()), ATTEMPT_ID);
    assertHiddenBallotMutationRejected(ballot -> ballot.put("ballot_attempt_sequence", 17));
    assertHiddenBallotMutationRejected(ballot -> ballot.put("max_corpus_entries", 2));
    assertHiddenBallotMutationRejected(ballot -> ballot.put("registration_close_height", 4));
    assertHiddenBallotMutationRejected(ballot -> ballot.put("survivor_freeze_height", 7));
    assertHiddenBallotMutationRejected(
        ballot -> {
          final Map<String, Object> tally =
              new LinkedHashMap<>(objectValue(ballot.get("tally")));
          tally.put("abstain", 1);
          ballot.put("tally", tally);
        });
    assertHiddenBallotMutationRejected(
        ballot -> ballot.put("outcome", Map.of("outcome", "Rejected")));

    ParliamentApiV1.parseAttemptReadResponse(encode(confirmationBallotResponse()), ATTEMPT_ID);
    ParliamentApiV1.parseAttemptReadResponse(
        encode(confirmationBallotResponse(1, 49, 50)), ATTEMPT_ID);
    assertConfirmationMutationRejected(
        (policy, confirmation) -> confirmation.put("beacon_pulse_id", policy.get("beacon_pulse_id")));
    assertConfirmationMutationRejected(
        (policy, confirmation) -> {
          confirmation.put("election_attempt_sequence", 0);
          final Map<String, Object> request =
              new LinkedHashMap<>(objectValue(confirmation.get("sortition_request")));
          request.put("request_height", 49);
          request.put("pulse_height", 50);
          confirmation.put("sortition_request", request);
        });
    assertConfirmationMutationRejected(
        (policy, confirmation) -> {
          confirmation.put("election_attempt_sequence", 1);
          final Map<String, Object> request =
              new LinkedHashMap<>(objectValue(confirmation.get("sortition_request")));
          request.put("request_height", 48);
          request.put("pulse_height", 49);
          confirmation.put("sortition_request", request);
        });
    final Map<String, Object> missingConfirmation = confirmationBallotResponse();
    final Map<String, Object> missingCertificate =
        objectValue(missingConfirmation.get("certificate"));
    missingCertificate.put(
        "body_bindings", List.of(maps(missingCertificate.get("body_bindings")).get(0)));
    missingCertificate.put("certified_at_height", 48);
    missingCertificate.put("enact_at_height", 50);
    missingConfirmation.put("certificate", missingCertificate);
    missingConfirmation.put(
        "required_bodies", List.of(maps(missingConfirmation.get("required_bodies")).get(0)));
    missingConfirmation.put(
        "body_states", List.of(maps(missingConfirmation.get("body_states")).get(0)));
    missingConfirmation.put("current_height", 49);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            ParliamentApiV1.parseAttemptReadResponse(
                encode(missingConfirmation), ATTEMPT_ID));
    assertConfirmationMutationRejected(
        (policy, confirmation) -> {
          final Map<String, Object> ballot =
              new LinkedHashMap<>(objectValue(policy.get("ballot")));
          final Map<String, Object> tally =
              new LinkedHashMap<>(objectValue(ballot.get("tally")));
          tally.put("aye", 15);
          tally.put("nay", 6);
          ballot.put("tally", tally);
          policy.put("ballot", ballot);
        });

    final Map<String, Object> partial = hiddenBallotResponse();
    partial.put("certificate", null);
    final Map<String, Object> partialState = maps(partial.get("body_states")).get(0);
    partialState.put(
        "timed_ovn_progress",
        map(
            "ballot_attempt_id", "21".repeat(32),
            "status", Map.of("status", "TimedCommitment"),
            "frozen_survivor_count", 3,
            "accepted_ballot_prefix_count", 1));
    partial.put("body_states", List.of(partialState));
    final ParliamentApiV1.AttemptReadResponse partialParsed =
        ParliamentApiV1.parseAttemptReadResponse(encode(partial), ATTEMPT_ID);
    assertEquals(
        1,
        partialParsed.bodyStates.get(0).timedOvnProgress.acceptedBallotPrefixCount.intValue());

    final Map<String, Object> fullDuringCommitment = new LinkedHashMap<>(partial);
    final Map<String, Object> fullState = maps(fullDuringCommitment.get("body_states")).get(0);
    final Map<String, Object> fullProgress =
        new LinkedHashMap<>(objectValue(fullState.get("timed_ovn_progress")));
    fullProgress.put("accepted_ballot_prefix_count", 3);
    fullState.put("timed_ovn_progress", fullProgress);
    fullDuringCommitment.put("body_states", List.of(fullState));
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(fullDuringCommitment), ATTEMPT_ID));

    final Map<String, Object> leaked = hiddenBallotResponse();
    final Map<String, Object> leakedState = maps(leaked.get("body_states")).get(0);
    final Map<String, Object> leakedProgress =
        new LinkedHashMap<>(objectValue(leakedState.get("timed_ovn_progress")));
    leakedProgress.put("ballot_records", List.of());
    leakedState.put("timed_ovn_progress", leakedProgress);
    leaked.put("body_states", List.of(leakedState));
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(leaked), ATTEMPT_ID));
  }

  @Test
  public void releaseContextRequiresCompleteTranscriptAndBindsEveryPartial() throws Exception {
    final String ballotId = "33".repeat(32);
    final Map<String, Object> response = tleReleaseContextResponse();
    final ParliamentApiV1.TleReleaseContextResponse context =
        ParliamentApiV1.parseTleReleaseContextResponse(encode(response), ballotId);
    assertEquals(4, context.keySession.publicShares.size());
    assertEquals(2, context.keySession.qualifiedDealerCommitments.size());

    final Map<String, Object> partial = tlePartialReleaseResponse(response);
    final ParliamentApiV1.TlePartialReleaseShare parsedPartial =
        ParliamentApiV1.parseTlePartialReleaseResponse(
            encode(partial),
            context.keySession.keySessionId,
            context.identityDigest,
            context.keySession.committeeSize);
    assertEquals(1, parsedPartial.participantIndex);

    final Map<String, Object> missingShare = tleReleaseContextResponse();
    final Map<String, Object> missingSession =
        new LinkedHashMap<>(objectValue(missingShare.get("tle_key_session")));
    final List<?> shares = (List<?>) missingSession.get("public_shares");
    missingSession.put("public_shares", new ArrayList<>(shares.subList(0, shares.size() - 1)));
    missingShare.put("tle_key_session", missingSession);
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseTleReleaseContextResponse(encode(missingShare), ballotId));

    final Map<String, Object> wrongDigest = tleReleaseContextResponse();
    final List<Integer> wrongDigestBytes = byteValues(32, 0x88);
    wrongDigestBytes.set(0, 1);
    wrongDigest.put("identity_digest", wrongDigestBytes);
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseTleReleaseContextResponse(encode(wrongDigest), ballotId));

    final Map<String, Object> crossBound = tlePartialReleaseResponse(response);
    crossBound.put("key_session_id", "77".repeat(32));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            ParliamentApiV1.parseTlePartialReleaseResponse(
                encode(crossBound),
                context.keySession.keySessionId,
            context.identityDigest,
            4));
  }

  @Test
  public void castingContextRequiresExactPublicCorpusAndCanonicalArchive() throws Exception {
    final String ballotId = "33".repeat(32);
    final Map<String, Object> response = timedOvnCastingContextResponse();
    final ParliamentApiV1.TimedOvnCastingContextResponse context =
        ParliamentApiV1.parseTimedOvnCastingContextResponse(encode(response), ballotId);
    assertEquals(ParliamentApiV1.TimedOvnCastingPhase.Registered, context.phase);
    assertEquals(1, context.registrationRecordsHex.size());
    assertArrayEquals(bytes("NRT0"), context.archiveNorito);

    final Map<String, Object> unknown = new LinkedHashMap<>(response);
    unknown.put("seed", byteValues(32, 0x11));
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseTimedOvnCastingContextResponse(encode(unknown), ballotId));

    final Map<String, Object> emptyClosed = new LinkedHashMap<>(response);
    emptyClosed.put("phase", "RegistrationClosed");
    emptyClosed.put("registration_records_hex", List.of());
    assertThrows(
        IllegalArgumentException.class,
        () ->
            ParliamentApiV1.parseTimedOvnCastingContextResponse(
                encode(emptyClosed), ballotId));

    final Map<String, Object> emptyFrozen = new LinkedHashMap<>(response);
    emptyFrozen.put("phase", "SurvivorsFrozen");
    emptyFrozen.put("survivor_participant_hashes", List.of());
    emptyFrozen.put(
        "release_identity", tleReleaseContextResponse().get("release_identity"));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            ParliamentApiV1.parseTimedOvnCastingContextResponse(
                encode(emptyFrozen), ballotId));

    final Map<String, Object> noncanonicalArchive = new LinkedHashMap<>(response);
    noncanonicalArchive.put("archive_norito_base64", "TlJUMA");
    assertThrows(
        IllegalArgumentException.class,
        () ->
            ParliamentApiV1.parseTimedOvnCastingContextResponse(
                encode(noncanonicalArchive), ballotId));
  }

  private static Map<String, Object> tleReleaseContextResponse() throws Exception {
    final String ballotId = "33".repeat(32);
    final String bodyId = "22".repeat(32);
    final String keySessionId = "44".repeat(32);
    final List<Integer> survivorRoot = byteValues(32, 0x61);
    final List<Integer> noRecoveryRoot = byteValues(32, 0x62);
    final List<Integer> parameterHash = byteValues(32, 0x63);

    final ByteArrayOutputStream identity = new ByteArrayOutputStream();
    append(identity, bytes("iroha.parliament.tle.identity-payload.v1\0"));
    append(identity, u16(1));
    append(identity, hexBytes(ATTEMPT_ID));
    append(identity, hexBytes(bodyId));
    append(identity, hexBytes(ballotId));
    append(identity, bytesOf(survivorRoot));
    append(identity, bytesOf(noRecoveryRoot));
    append(identity, u64(40));
    append(identity, bytesOf(parameterHash));
    final byte[] identityPayload = identity.toByteArray();
    assertEquals(243, identityPayload.length);

    final Map<String, Object> keySession = new LinkedHashMap<>();
    keySession.put("version", 1);
    keySession.put("key_session_id", keySessionId);
    keySession.put("network_id", byteValues(32, 0x45));
    keySession.put("roster_hash", byteValues(32, 0x46));
    keySession.put("committee_size", 4);
    keySession.put("threshold", 2);
    keySession.put("generator_h", byteValues(96, 0x47));
    keySession.put("generator_v", byteValues(96, 0x48));
    keySession.put("qualified_dealers", List.of(1, 2));
    final List<Map<String, Object>> dealers = new ArrayList<>();
    for (final int dealerIndex : List.of(1, 2)) {
      final Map<String, Object> dealer = new LinkedHashMap<>();
      dealer.put("dealer_index", dealerIndex);
      dealer.put(
          "coefficient_commitments",
          List.of(
              byteValues(96, 0x50 + dealerIndex),
              byteValues(96, 0x60 + dealerIndex)));
      dealer.put("constant_pok_commitment", byteValues(96, 0x70 + dealerIndex));
      dealer.put("constant_pok_response", byteValues(32, 0x80 + dealerIndex));
      dealers.add(dealer);
    }
    keySession.put("qualified_dealer_commitments", dealers);
    keySession.put("dkg_event_hash", byteValues(32, 0x49));
    keySession.put("group_public_key", byteValues(96, 0x4a));
    final List<Map<String, Object>> publicShares = new ArrayList<>();
    for (int index = 1; index <= 4; index++) {
      final Map<String, Object> share = new LinkedHashMap<>();
      share.put("index", index);
      share.put("participant_hash", byteValues(32, 0x20 + index));
      share.put("public_key_share", byteValues(96, 0x30 + index));
      publicShares.add(share);
    }
    keySession.put("public_shares", publicShares);
    keySession.put("transcript_hash", byteValues(32, 0x4b));

    final ByteArrayOutputStream framed = new ByteArrayOutputStream();
    append(framed, bytes("iroha.threshold-bls.message.v1\0"));
    append(framed, bytes("iroha.threshold-bls.session.v1\0"));
    append(framed, u16(1));
    framed.write(2);
    append(framed, bytesOf((List<?>) keySession.get("network_id")));
    append(framed, hexBytes(keySessionId));
    append(framed, bytesOf((List<?>) keySession.get("roster_hash")));
    append(framed, u16(4));
    append(framed, u16(2));
    append(framed, u32(identityPayload.length));
    append(framed, identityPayload);

    final Map<String, Object> releaseIdentity = new LinkedHashMap<>();
    releaseIdentity.put("tle_key_session_id", keySessionId);
    releaseIdentity.put("governance_attempt_id", ATTEMPT_ID);
    releaseIdentity.put("body_instance_id", bodyId);
    releaseIdentity.put("ballot_attempt_id", ballotId);
    releaseIdentity.put("survivor_corpus_root", survivorRoot);
    releaseIdentity.put("no_recovery_root", noRecoveryRoot);
    releaseIdentity.put("target_finalized_height", 40);
    releaseIdentity.put("parameter_hash", parameterHash);

    final Map<String, Object> response = new LinkedHashMap<>();
    response.put("version", 1);
    response.put("current_height", 42);
    response.put("ballot_attempt_id", ballotId);
    response.put("governance_attempt_id", ATTEMPT_ID);
    response.put("body_instance_id", bodyId);
    response.put("status", Map.of("status", "Opening"));
    response.put("release_height", 40);
    response.put("opening_deadline_height", 45);
    response.put("tle_key_session", keySession);
    response.put("release_identity", releaseIdentity);
    response.put(
        "identity_digest",
        byteValues(MessageDigest.getInstance("SHA-256").digest(framed.toByteArray())));
    response.put("identity_payload_hex", toHex(identityPayload));
    return response;
  }

  private static Map<String, Object> tlePartialReleaseResponse(
      final Map<String, Object> context) {
    final Map<String, Object> session = objectValue(context.get("tle_key_session"));
    final Map<String, Object> response = new LinkedHashMap<>();
    response.put("key_session_id", session.get("key_session_id"));
    response.put("identity_digest", context.get("identity_digest"));
    response.put("participant_index", 1);
    response.put("sigma", byteValues(48, 0x91));
    response.put("proof_x", byteValues(96, 0x92));
    response.put("proof_y", byteValues(48, 0x93));
    response.put("z_s", byteValues(32, 0x94));
    response.put("z_r", byteValues(32, 0x95));
    response.put("z_u", byteValues(32, 0x96));
    return response;
  }

  private static Map<String, Object> timedOvnCastingContextResponse() throws Exception {
    final Map<String, Object> release = tleReleaseContextResponse();
    final Map<String, Object> keySession = objectValue(release.get("tle_key_session"));
    final Map<String, Object> identity = objectValue(release.get("release_identity"));

    final Map<String, Object> session = new LinkedHashMap<>();
    session.put("network_id", keySession.get("network_id"));
    session.put("proposal_content_id", PROPOSAL_ID);
    session.put("governance_attempt_id", ATTEMPT_ID);
    session.put("body_instance_id", release.get("body_instance_id"));
    session.put("ballot_attempt_id", release.get("ballot_attempt_id"));
    session.put("parameter_hash", identity.get("parameter_hash"));
    session.put("tle_key_session_id", keySession.get("key_session_id"));
    session.put("tle_key_transcript_hash", keySession.get("transcript_hash"));
    session.put("tle_master_public_key", keySession.get("group_public_key"));

    final Map<String, Object> response = new LinkedHashMap<>();
    response.put("version", 1);
    response.put("current_height", 30);
    response.put("phase", "Registered");
    response.put("session", session);
    response.put("registration_opened_at_finalized_height", 20);
    response.put("target_finalized_height", 40);
    response.put("tle_key_session", keySession);
    response.put("registration_records_hex", List.of("81".repeat(3_624)));
    response.put("survivor_participant_hashes", null);
    response.put("release_identity", null);
    response.put(
        "archive_norito_base64",
        Base64.getEncoder().encodeToString(bytes("NRT0")));
    return response;
  }

  private static Map<String, Object> readResponse() {
    final Map<String, Object> response = publicOnlyReadResponse();
    final Map<String, Object> policyResponse = hiddenBallotResponse();
    final List<Map<String, Object>> requiredBodies = new ArrayList<>();
    requiredBodies.addAll(maps(response.get("required_bodies")));
    requiredBodies.addAll(maps(policyResponse.get("required_bodies")));
    response.put("required_bodies", requiredBodies);
    final List<Map<String, Object>> bodyStates = new ArrayList<>();
    bodyStates.addAll(maps(response.get("body_states")));
    bodyStates.addAll(maps(policyResponse.get("body_states")));
    response.put("body_states", bodyStates);
    final Map<String, Object> certificate = objectValue(response.get("certificate"));
    final List<Map<String, Object>> bindings = new ArrayList<>();
    bindings.addAll(maps(certificate.get("body_bindings")));
    bindings.addAll(
        maps(objectValue(policyResponse.get("certificate")).get("body_bindings")));
    certificate.put("body_bindings", bindings);
    certificate.put("certified_at_height", 12);
    certificate.put("enact_at_height", 14);
    response.put("certificate", certificate);
    response.put("current_height", 13);
    return response;
  }

  private static Map<String, Object> publicOnlyReadResponse() {
    final List<Integer> root = new ArrayList<>();
    for (int i = 0; i < 32; i++) root.add(0x55);
    final String id1 = "01".repeat(32);
    final String id2 = "02".repeat(32);
    final Map<String, Object> bodyState = new LinkedHashMap<>();
    bodyState.put("body", "rules-committee");
    bodyState.put("body_instance_id", id1);
    bodyState.put("status", Map.of("status", "Approved"));
    bodyState.put("public_finding_opened_at_height", 1);
    bodyState.put("public_finding_phase_blocks", 7);
    bodyState.put("public_finding_deadline_height", 8);
    bodyState.put("no_result_kind", null);
    bodyState.put("no_result_height", null);
    bodyState.put("timed_ovn_progress", null);

    final Map<String, Object> publicFinding = new LinkedHashMap<>();
    publicFinding.put("endorsement_root", root);
    publicFinding.put("endorsing_assignments", List.of("11".repeat(32), "12".repeat(32)));
    publicFinding.put("endorsements", 2);
    publicFinding.put("quorum", 2);

    final Map<String, Object> binding = new LinkedHashMap<>();
    binding.put("body_instance_id", id1);
    binding.put("election_attempt_id", id2);
    binding.put("election_attempt_sequence", 0);
    binding.put("sortition_request_id", "03".repeat(32));
    binding.put(
        "sortition_request",
        Map.of(
            "id", "03".repeat(32),
            "governance_attempt_id", ATTEMPT_ID,
            "body_election_attempt_id", id2,
            "body", "rules-committee",
            "candidate_root", root,
            "candidate_count", 3,
            "target_seats", 3,
            "request_height", 1,
            "pulse_height", 2,
            "beacon_session_id", "04".repeat(32)));
    binding.put("body", "rules-committee");
    binding.put("original_seats", 3);
    binding.put("beacon_session_id", "04".repeat(32));
    binding.put("beacon_pulse_id", "05".repeat(32));
    binding.put("roster_root", root);
    binding.put("assignment_root", root);
    binding.put("result_root", root);
    binding.put("result_height", 8);
    binding.put("public_finding", publicFinding);
    binding.put("ballot", null);

    final Map<String, Object> certificate = new LinkedHashMap<>();
    certificate.put("proposal_content_id", PROPOSAL_ID);
    certificate.put("governance_attempt_id", ATTEMPT_ID);
    certificate.put("governance_attempt_sequence", 0);
    certificate.put("risk_tier", Map.of("tier", "Standard"));
    certificate.put("body_bindings", List.of(binding));
    certificate.put("policy_version", 1);
    certificate.put("effect_preimage_hash", root);
    certificate.put(
        "expected_head", Map.of("state", "Absent", "head", Map.of("subject_id", root)));
    certificate.put("certified_at_height", 8);
    certificate.put("enact_at_height", 10);

    final Map<String, Object> response = new LinkedHashMap<>();
    response.put("version", 1);
    response.put("current_height", 9);
    response.put(
        "attempt",
        Map.of(
            "id", ATTEMPT_ID,
            "proposal_content_id", PROPOSAL_ID,
            "sequence", 0,
            "risk_tier", Map.of("tier", "Standard"),
            "stage", Map.of("stage", "Rules"),
            "status", Map.of("status", "Certified")));
    response.put("policy_version", 1);
    response.put(
        "required_bodies",
        List.of(
            Map.of(
                "body", "rules-committee",
                "decision_mode", Map.of("mode", "PublicFinding"))));
    response.put("body_states", List.of(bodyState));
    response.put("certificate", certificate);
    response.put("terminal_height", null);
    response.put("superseding_head", null);
    response.put("execution_failure_root", null);
    response.put("state_payload_hex", stateFrameHex());
    return response;
  }

  private static void assertCertificateMutationRejected(
      final Consumer<Map<String, Object>> mutation) {
    final Map<String, Object> response = readResponse();
    final Map<String, Object> certificate = objectValue(response.get("certificate"));
    mutation.accept(certificate);
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(response), ATTEMPT_ID));
  }

  private static void assertHiddenBallotMutationRejected(
      final Consumer<Map<String, Object>> mutation) {
    final Map<String, Object> response = hiddenBallotResponse();
    final Map<String, Object> certificate = objectValue(response.get("certificate"));
    final Map<String, Object> binding = maps(certificate.get("body_bindings")).get(0);
    final Map<String, Object> ballot =
        new LinkedHashMap<>(objectValue(binding.get("ballot")));
    mutation.accept(ballot);
    binding.put("ballot", ballot);
    certificate.put("body_bindings", List.of(binding));
    response.put("certificate", certificate);
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(response), ATTEMPT_ID));
  }

  private static void assertConfirmationMutationRejected(
      final BiConsumer<Map<String, Object>, Map<String, Object>> mutation) {
    final Map<String, Object> response = confirmationBallotResponse();
    final Map<String, Object> certificate = objectValue(response.get("certificate"));
    final List<Map<String, Object>> bindings = maps(certificate.get("body_bindings"));
    mutation.accept(bindings.get(0), bindings.get(1));
    certificate.put("body_bindings", bindings);
    response.put("certificate", certificate);
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(response), ATTEMPT_ID));
  }

  private static Map<String, Object> confirmationBallotResponse() {
    return confirmationBallotResponse(0, 48, 49);
  }

  private static Map<String, Object> confirmationBallotResponse(
      final int confirmationElectionSequence,
      final int confirmationRequestHeight,
      final int confirmationPulseHeight) {
    final Map<String, Object> response = hiddenBallotResponse();
    final Map<String, Object> policyState = maps(response.get("body_states")).get(0);
    policyState.put(
        "timed_ovn_progress",
        map(
            "ballot_attempt_id", "21".repeat(32),
            "status", Map.of("status", "Finalized"),
            "frozen_survivor_count", 21,
            "accepted_ballot_prefix_count", 21));

    final Map<String, Object> certificate = objectValue(response.get("certificate"));
    final Map<String, Object> policy = maps(certificate.get("body_bindings")).get(0);
    policy.put("original_seats", 21);
    policy.put("result_height", 48);
    final Map<String, Object> policyRequest =
        new LinkedHashMap<>(objectValue(policy.get("sortition_request")));
    policyRequest.put("candidate_count", 21);
    policyRequest.put("target_seats", 21);
    policy.put("sortition_request", policyRequest);
    final Map<String, Object> policyBallot =
        new LinkedHashMap<>(objectValue(policy.get("ballot")));
    policyBallot.put("max_corpus_entries", 21);
    policyBallot.put("registration_close_height", 23);
    policyBallot.put("survivor_freeze_height", 44);
    policyBallot.put("commitment_close_height", 45);
    policyBallot.put("registration_closed_at_height", 23);
    policyBallot.put("survivors_frozen_at_height", 44);
    policyBallot.put("commitment_closed_at_height", 45);
    policyBallot.put("release_height", 46);
    policyBallot.put("opening_deadline_height", 50);
    policyBallot.put("opening_height", 47);
    policyBallot.put(
        "tally",
        map(
            "original_seats", 21,
            "accepted_ballots", 21,
            "aye", 11,
            "nay", 10,
            "abstain", 0));
    policy.put("ballot", policyBallot);

    final Map<String, Object> confirmation = new LinkedHashMap<>(policy);
    confirmation.put("body_instance_id", "31".repeat(32));
    confirmation.put("election_attempt_id", "32".repeat(32));
    confirmation.put("election_attempt_sequence", confirmationElectionSequence);
    confirmation.put("sortition_request_id", "33".repeat(32));
    confirmation.put("body", "confirmation-jury");
    confirmation.put("beacon_session_id", "34".repeat(32));
    confirmation.put("beacon_pulse_id", "35".repeat(32));
    confirmation.put("result_height", 98);
    final Map<String, Object> confirmationRequest = new LinkedHashMap<>(policyRequest);
    confirmationRequest.put("id", "33".repeat(32));
    confirmationRequest.put("body_election_attempt_id", "32".repeat(32));
    confirmationRequest.put("body", "confirmation-jury");
    confirmationRequest.put("request_height", confirmationRequestHeight);
    confirmationRequest.put("pulse_height", confirmationPulseHeight);
    confirmationRequest.put("beacon_session_id", "34".repeat(32));
    confirmation.put("sortition_request", confirmationRequest);
    final Map<String, Object> confirmationBallot = new LinkedHashMap<>(policyBallot);
    confirmationBallot.put("ballot_attempt_id", "36".repeat(32));
    confirmationBallot.put("tle_session_id", "37".repeat(32));
    confirmationBallot.put("tle_key_session_id", "38".repeat(32));
    confirmationBallot.put("release_beacon_session_id", "39".repeat(32));
    confirmationBallot.put("registered_at_height", 50);
    confirmationBallot.put("registration_close_height", 72);
    confirmationBallot.put("survivor_freeze_height", 93);
    confirmationBallot.put("commitment_close_height", 94);
    confirmationBallot.put("registration_closed_at_height", 72);
    confirmationBallot.put("survivors_frozen_at_height", 93);
    confirmationBallot.put("commitment_closed_at_height", 94);
    confirmationBallot.put("release_height", 95);
    confirmationBallot.put("opening_deadline_height", 99);
    confirmationBallot.put("release_pulse_id", "3a".repeat(32));
    confirmationBallot.put("opening_height", 96);
    confirmation.put("ballot", confirmationBallot);

    final Map<String, Object> confirmationState = new LinkedHashMap<>(policyState);
    confirmationState.put("body", "confirmation-jury");
    confirmationState.put("body_instance_id", "31".repeat(32));
    confirmationState.put(
        "timed_ovn_progress",
        map(
            "ballot_attempt_id", "36".repeat(32),
            "status", Map.of("status", "Finalized"),
            "frozen_survivor_count", 21,
            "accepted_ballot_prefix_count", 21));
    response.put(
        "required_bodies",
        List.of(
            Map.of(
                "body", "policy-jury",
                "decision_mode", Map.of("mode", "HiddenBindingBallot")),
            Map.of(
                "body", "confirmation-jury",
                "decision_mode", Map.of("mode", "HiddenBindingBallot"))));
    response.put("body_states", List.of(policyState, confirmationState));
    certificate.put("body_bindings", List.of(policy, confirmation));
    certificate.put("certified_at_height", 98);
    certificate.put("enact_at_height", 100);
    response.put("certificate", certificate);
    response.put("current_height", 99);
    return response;
  }

  private static Map<String, Object> hiddenBallotResponse() {
    final Map<String, Object> response = publicOnlyReadResponse();
    response.put(
        "required_bodies",
        List.of(
            Map.of(
                "body", "policy-jury",
                "decision_mode", Map.of("mode", "HiddenBindingBallot"))));
    final Map<String, Object> bodyState = maps(response.get("body_states")).get(0);
    bodyState.put("body", "policy-jury");
    bodyState.put("body_instance_id", "06".repeat(32));
    bodyState.put("public_finding_opened_at_height", null);
    bodyState.put("public_finding_phase_blocks", null);
    bodyState.put("public_finding_deadline_height", null);
    bodyState.put(
        "timed_ovn_progress",
        map(
            "ballot_attempt_id", "21".repeat(32),
            "status", Map.of("status", "Finalized"),
            "frozen_survivor_count", 3,
            "accepted_ballot_prefix_count", 3));
    response.put("body_states", List.of(bodyState));

    final Map<String, Object> certificate = objectValue(response.get("certificate"));
    final Map<String, Object> binding = maps(certificate.get("body_bindings")).get(0);
    binding.put("body", "policy-jury");
    binding.put("body_instance_id", "06".repeat(32));
    binding.put("election_attempt_id", "07".repeat(32));
    binding.put("sortition_request_id", "08".repeat(32));
    binding.put("beacon_session_id", "09".repeat(32));
    binding.put("beacon_pulse_id", "0a".repeat(32));
    final Map<String, Object> request =
        new LinkedHashMap<>(objectValue(binding.get("sortition_request")));
    request.put("id", "08".repeat(32));
    request.put("body_election_attempt_id", "07".repeat(32));
    request.put("body", "policy-jury");
    request.put("beacon_session_id", "09".repeat(32));
    binding.put("sortition_request", request);
    binding.put("public_finding", null);
    @SuppressWarnings("unchecked")
    final List<Integer> root = (List<Integer>) binding.get("roster_root");
    final Map<String, Object> tally = new LinkedHashMap<>();
    tally.put("original_seats", 3);
    tally.put("accepted_ballots", 3);
    tally.put("aye", 2);
    tally.put("nay", 1);
    tally.put("abstain", 0);
    final Map<String, Object> ballot = new LinkedHashMap<>();
    ballot.put("ballot_attempt_id", "21".repeat(32));
    ballot.put("ballot_attempt_sequence", 0);
    ballot.put("tle_session_id", "22".repeat(32));
    ballot.put("tle_key_session_id", "23".repeat(32));
    ballot.put("registration_root", root);
    ballot.put("dropout_root", root);
    ballot.put("survivor_root", root);
    ballot.put("corpus_root", root);
    ballot.put("no_recovery_root", root);
    ballot.put("timed_commitment_root", root);
    ballot.put("release_beacon_session_id", "24".repeat(32));
    ballot.put("registered_at_height", 1);
    ballot.put("registration_close_height", 5);
    ballot.put("survivor_freeze_height", 8);
    ballot.put("commitment_close_height", 9);
    ballot.put("registration_closed_at_height", 5);
    ballot.put("survivors_frozen_at_height", 8);
    ballot.put("commitment_closed_at_height", 9);
    ballot.put("max_ballot_retries", 16);
    ballot.put("max_corpus_entries", 3);
    ballot.put("release_height", 10);
    ballot.put("opening_deadline_height", 13);
    ballot.put("release_pulse_id", "25".repeat(32));
    ballot.put("opening_height", 11);
    ballot.put("opening_root", root);
    ballot.put("tally", tally);
    ballot.put("outcome", Map.of("outcome", "Approved"));
    binding.put("ballot", ballot);
    binding.put("result_height", 12);
    certificate.put("body_bindings", List.of(binding));
    certificate.put("certified_at_height", 12);
    certificate.put("enact_at_height", 14);
    response.put("certificate", certificate);
    response.put("current_height", 13);
    return response;
  }

  private static byte[] stateFrame() {
    final byte[] payload = new byte[] {1, 2};
    final NoritoHeader header =
        new NoritoHeader(
            filled(16, (byte) 3),
            payload.length,
            CRC64.compute(payload),
            0,
            NoritoHeader.COMPRESSION_NONE);
    final byte[] headerBytes = header.encode();
    final byte[] frame = Arrays.copyOf(headerBytes, headerBytes.length + payload.length);
    System.arraycopy(payload, 0, frame, headerBytes.length, payload.length);
    return frame;
  }

  private static String stateFrameHex() {
    return toHex(stateFrame());
  }

  private static byte[] filled(final int length, final byte value) {
    final byte[] bytes = new byte[length];
    Arrays.fill(bytes, value);
    return bytes;
  }

  private static List<Integer> byteValues(final int length, final int value) {
    final List<Integer> values = new ArrayList<>(length);
    for (int index = 0; index < length; index++) values.add(value & 0xff);
    return values;
  }

  private static List<Integer> byteValues(final byte[] bytes) {
    final List<Integer> values = new ArrayList<>(bytes.length);
    for (final byte value : bytes) values.add(value & 0xff);
    return values;
  }

  private static byte[] bytesOf(final List<?> values) {
    final byte[] bytes = new byte[values.size()];
    for (int index = 0; index < values.size(); index++) {
      bytes[index] = (byte) ((Number) values.get(index)).intValue();
    }
    return bytes;
  }

  private static byte[] hexBytes(final String value) {
    final byte[] bytes = new byte[value.length() / 2];
    for (int index = 0; index < bytes.length; index++) {
      bytes[index] =
          (byte) Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16);
    }
    return bytes;
  }

  private static byte[] u16(final int value) {
    return new byte[] {(byte) (value >>> 8), (byte) value};
  }

  private static byte[] u32(final int value) {
    return new byte[] {
      (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value
    };
  }

  private static byte[] u64(final long value) {
    final byte[] bytes = new byte[8];
    for (int index = 0; index < bytes.length; index++) {
      bytes[index] = (byte) (value >>> (8 * (7 - index)));
    }
    return bytes;
  }

  private static void append(final ByteArrayOutputStream output, final byte[] value) {
    output.write(value, 0, value.length);
  }

  private static String toHex(final byte[] bytes) {
    final StringBuilder out = new StringBuilder(bytes.length * 2);
    for (final byte value : bytes) out.append(String.format("%02x", value & 0xff));
    return out.toString();
  }

  private static Map<String, Object> instruction(
      final String wireId, final String payloadHex) {
    final Map<String, Object> value = new LinkedHashMap<>();
    value.put("wire_id", wireId);
    value.put("payload_hex", payloadHex);
    return value;
  }

  private static org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal proposal(final String kind) {
    return org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(encode(validProposal(kind)));
  }

  private static Map<String, Object> validProposal(final String kind) {
    final Map<String, Object> payload;
    switch (kind) {
      case "DeployContract" ->
          payload =
              map(
                  "proposal_operator", account(1),
                  "contract_address", CONTRACT_ADDRESS,
                  "code_hash", "11".repeat(32),
                  "abi_hash", "22".repeat(32),
                  "abi_version", 1,
                  "manifest_provenance", null);
      case "RuntimeUpgrade" ->
          payload =
              map(
                  "proposal_operator", account(1),
                  "manifest",
                  map(
                      "name", "runtime-v1",
                      "description", "first release runtime",
                      "abi_version", 1,
                      "abi_hash", repeatedNumbers(32, 1),
                      "added_syscalls", new ArrayList<Object>(),
                      "added_pointer_types", new ArrayList<Object>(),
                      "start_height", 10,
                      "end_height", 20,
                      "sbom_digests", new ArrayList<Object>(),
                      "slsa_attestation", "",
                      "provenance", new ArrayList<Object>()));
      case "SccpRouteGovernance" ->
          payload =
              map(
                  "proposal",
                  map(
                      "network_id", networkId(),
                      "base_revisions",
                      List.of(
                          map(
                              "subject", map("subject", "route", "key", bscMainnet()),
                              "revision", 1)),
                      "actions",
                      List.of(
                          map(
                              "action", "remove_staged",
                              "payload", map("network", bscMainnet(), "revision", 1)))));
      case "ValidationFeePolicy" ->
          payload =
              map(
                  "proposal_operator", account(1),
                  "policy", disabledFeePolicy(),
                  "payout_lifecycle_proposal_id", null);
      case "ValidationFeePayoutLifecycle" ->
          payload =
              map(
                  "proposal_operator", account(1),
                  "payout_binding", payoutBinding());
      case "MusubiRegistryGovernance" ->
          payload =
              map(
                  "kind", "RecoverPackageOwners",
                  "value",
                  map(
                      "package",
                      map(
                          "home_dataspace", 7,
                          "scope", map("kind", "DataspaceRoot", "value", null),
                          "name", Arrays.asList("wallet-core")),
                      "owners", Arrays.asList(account(2)),
                      "expected_revision", 1));
      case "SorafsProviderGovernance" ->
          payload =
              map(
                  "action",
                  map(
                      "action", "establish",
                      "value",
                      map(
                          "provider_id", Arrays.asList(repeatedNumbers(32, 0x45)),
                          "owner", account(3))));
      case "ContractLifecycleGovernance" ->
          payload =
              map(
                  "proposal_operator", account(1),
                  "contract_address", CONTRACT_ADDRESS,
                  "expected_revision", 3,
                  "action",
                  map(
                      "action", "CompleteEmergencyHoldRetrospective",
                      "payload",
                      map(
                          "hold_proposal_content_id", repeatedNumbers(32, 0x51),
                          "hold_governance_attempt_id", repeatedNumbers(32, 0x52),
                          "incident_digest", repeatedNumbers(32, 0x53),
                          "retrospective_finding_root", repeatedNumbers(32, 0x54))));
      case "ContractEmergencyHold" ->
          payload =
              map(
                  "contract_address", CONTRACT_ADDRESS,
                  "expected_revision", 2,
                  "expected_code_hash", "33".repeat(32),
                  "incident_digest", repeatedNumbers(32, 0x55),
                  "reason", "contain active exploit",
                  "duration_blocks", 3_600);
      case "GlobalDataTriggerPermissionGovernance" ->
          payload =
              map(
                  "authority", account(4),
                  "action", map("action", "grant", "value", null));
      default -> throw new AssertionError("unsupported fixture kind " + kind);
    }
    return map("kind", kind, "payload", payload);
  }

  private static Map<String, Object> disabledFeePolicy() {
    return map(
        "schema_version", 1,
        "network_id", networkId(),
        "policy_version", "1",
        "previous_policy_hash", null,
        "ds_asset_id", asset(1),
        "ds_scale", 2,
        "fee", "0",
        "treasury_account_id", account(2),
        "charging_mode", map("charging_mode", "DISABLED", "value", null),
        "effective_from_height", "10",
        "expires_after_height", null,
        "exemption_classes", new ArrayList<Object>(),
        "treasury_payout_binding", null);
  }

  private static Map<String, Object> payoutBinding() {
    final List<Object> recipients = new ArrayList<>();
    for (int seed = 4; seed <= 7; seed++) {
      recipients.add(map("account_id", account(seed), "share", "0.25"));
    }
    return map(
        "contract_address", CONTRACT_ADDRESS,
        "code_hash", repeatedNumbers(32, 0x31),
        "entrypoint", "autonomous_validation_fee_tick",
        "treasury_account_id", account(2),
        "ds_asset_id", asset(1),
        "xor_asset_id", asset(2),
        "pool_vault_account_id", account(3),
        "batch_ds", "10",
        "min_xor_out", "4",
        "max_xor_out", "100",
        "recipients", recipients);
  }

  private static byte[] sccpProposal(final Consumer<Map<String, Object>> edit) {
    final Map<String, Object> proposal = validProposal("SccpRouteGovernance");
    edit.accept(objectValue(objectValue(proposal.get("payload")).get("proposal")));
    return encode(proposal);
  }

  private static Map<String, Object> sccpSubject(final String subject, final Object key) {
    return map("subject", map("subject", subject, "key", key), "revision", 0);
  }

  private static Map<String, Object> bscMainnet() {
    return map("network", "bsc_mainnet", "profile", null);
  }

  private static String account(final int seed) {
    try {
      return AccountAddress.fromAccount(TestEd25519Keys.publicKey(seed), "ed25519")
          .toI105(AccountAddress.DEFAULT_I105_DISCRIMINANT);
    } catch (final AccountAddress.AccountAddressException ex) {
      throw new AssertionError(ex);
    }
  }

  private static String asset(final int seed) {
    final byte[] bytes = new byte[16];
    for (int index = 0; index < bytes.length; index++) bytes[index] = (byte) (seed + index);
    bytes[6] = (byte) ((bytes[6] & 0x0f) | 0x40);
    bytes[8] = (byte) ((bytes[8] & 0x3f) | 0x80);
    return AssetDefinitionIdEncoder.encodeFromBytes(bytes);
  }

  private static String networkId() {
    final byte[] bytes = new byte[32];
    Arrays.fill(bytes, (byte) 0x23);
    bytes[31] = 0x25;
    return NetworkId.fromBytes(bytes).literal();
  }

  private static List<Object> repeatedNumbers(final int size, final int value) {
    final List<Object> result = new ArrayList<>();
    for (int index = 0; index < size; index++) result.add(value);
    return result;
  }

  private static byte[] freezeTimedOvnTransition(
      final int recordCount, final int recordBytes) {
    final List<Object> records = new ArrayList<>();
    for (int index = 0; index < recordCount; index++) {
      records.add(repeatedNumbers(recordBytes, 1));
    }
    return encode(
        map(
            "transition",
            "FreezeTimedOvnCorpus",
            "payload",
            map(
                "ballot_attempt_id",
                "44".repeat(32),
                "ballot_records",
                records)));
  }

  private static Map<String, Object> map(final Object... entries) {
    if ((entries.length & 1) != 0) throw new AssertionError("map entries must be paired");
    final Map<String, Object> result = new LinkedHashMap<>();
    for (int index = 0; index < entries.length; index += 2) {
      result.put((String) entries[index], entries[index + 1]);
    }
    return result;
  }

  private static byte[] encode(final Map<String, Object> value) {
    return JsonEncoder.encode(value).getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] bytes(final String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] decodeTestHex(final String value) {
    final byte[] decoded = new byte[value.length() / 2];
    for (int index = 0; index < decoded.length; index++) {
      decoded[index] =
          (byte) Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16);
    }
    return decoded;
  }

  private static byte[] repeatedBytes(final int count, final int value) {
    final byte[] bytes = new byte[count];
    Arrays.fill(bytes, (byte) value);
    return bytes;
  }

  private static byte[] concat(final byte[]... parts) {
    final ByteArrayOutputStream output = new ByteArrayOutputStream();
    for (final byte[] part : parts) {
      output.write(part, 0, part.length);
    }
    return output.toByteArray();
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> objectValue(final byte[] bytes) {
    return (Map<String, Object>) JsonParser.parse(new String(bytes, StandardCharsets.UTF_8));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> objectValue(final Object value) {
    return (Map<String, Object>) value;
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> maps(final Object value) {
    final List<Map<String, Object>> copied = new ArrayList<>();
    for (final Object entry : (List<Object>) value) {
      copied.add(new LinkedHashMap<>(objectValue(entry)));
    }
    return copied;
  }

  private static Path fixturePath() {
    Path current = Paths.get("").toAbsolutePath();
    while (current != null) {
      final Path candidate = current.resolve("fixtures/governance/parliament_api_v1.json");
      if (Files.isRegularFile(candidate)) return candidate;
      current = current.getParent();
    }
    throw new AssertionError("fixtures/governance/parliament_api_v1.json was not found");
  }
}
