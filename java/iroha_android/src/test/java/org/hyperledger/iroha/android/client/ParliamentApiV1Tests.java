package org.hyperledger.iroha.android.client;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.hyperledger.iroha.android.address.AccountAddress;
import org.hyperledger.iroha.android.address.AssetDefinitionIdEncoder;
import org.hyperledger.iroha.android.model.NetworkId;
import org.hyperledger.iroha.android.testing.TestEd25519Keys;
import org.hyperledger.iroha.norito.CRC64;
import org.hyperledger.iroha.norito.NoritoHeader;
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
    assertEquals(
        Set.of("attempt_draft", "attempt_read", "transition_draft"), routes.keySet());
    assertEquals(ParliamentApiV1.ATTEMPT_DRAFT_PATH, routes.get("attempt_draft"));
    assertEquals(ParliamentApiV1.ATTEMPT_READ_PATH, routes.get("attempt_read"));
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
        Set.of("attempt_state_bytes", "governance_attempt_sequence_max"), limits.keySet());
    assertEquals(
        ParliamentApiV1.MAX_GOVERNANCE_ATTEMPT_RETRIES,
        ((Number) limits.get("governance_attempt_sequence_max")).intValue());

    final List<?> transitions = (List<?>) fixture.get("public_transitions");
    assertEquals(13, transitions.size());
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
      ParliamentApiV1.transitionDraftRequestJson(ATTEMPT_ID, bytes(transitionJson));
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
    assertEquals(4, fixtureRootDomains.size());
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
    assertEquals(5, noResultKinds.size());
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
            sccpSubject("forgery_hold", bscMainnet()))) {
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
                    List.of(
                        sccpSubject(
                            "light_client", map("network", "tron_mainnet", "profile", null)))),
            proposal ->
                proposal.put(
                    "base_revisions",
                    List.of(sccpSubject("bridge_key_fault", "ea0130" + "ab".repeat(48)))),
            proposal ->
                proposal.put(
                    "base_revisions",
                    List.of(sccpSubject("bridge_key_fault", "ea0130" + "AB".repeat(48)))),
            proposal ->
                proposal.put(
                    "base_revisions",
                    List.of(
                        sccpSubject(
                            "route", map("network", "sora_taira", "profile", null)))),
            proposal ->
                proposal.put("actions", List.of(map("action", "Remove", "payload", map()))),
            proposal ->
                proposal.put("actions", List.of(map("action", "clear_bridge_key_fault", "payload", map()))),
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
  public void sccpCurrentEnvelopeTagsAndSubjectCoordinatesUseCanonicalKotlin() {
    // This Java consumer exercises Kotlin's declared envelope contract; native typed
    // action bodies and exact action-to-subject coverage retain their separate owner.
    for (final String action : List.of(
        "register_route", "activate_revision", "switch_revision", "deactivate_outbound",
        "retire_revision", "remove_staged", "release_stranded", "set_taira_paused",
        "set_destination_paused", "initialize_light_client", "install_trusted_checkpoint",
        "freeze_light_client", "set_parameters", "activate_light_client_profile",
        "attest_deployment_progress", "quarantine_revision", "open_reconciliation",
        "set_fast_pause_suspended")) {
      org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(
          sccpProposal(proposal -> proposal.put(
              "actions", List.of(map("action", action, "payload", map())))));
      for (final Object payload : Arrays.asList(null, List.of(), "object", true, 0)) {
        assertThrows(
            "accepted " + action + " with payload " + payload,
            IllegalArgumentException.class,
            () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(
                sccpProposal(proposal -> proposal.put(
                    "actions", List.of(map("action", action, "payload", payload))))));
      }
      for (final Map<String, Object> entry : List.of(
          map("action", action), map("action", action, "payload", map(), "extra", 0))) {
        assertThrows(
            "accepted action envelope " + entry,
            IllegalArgumentException.class,
            () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(
                sccpProposal(proposal -> proposal.put("actions", List.of(entry)))));
      }
    }
    for (final String subject : List.of(
        "route", "route_control", "light_client", "forgery_hold", "fast_hold", "fast_pause_control")) {
      for (final String network : List.of("ethereum_mainnet", "bsc_mainnet", "ton_mainnet")) {
        org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(
            sccpProposal(proposal -> proposal.put(
                "base_revisions", List.of(sccpSubject(subject, map("network", network, "profile", null))))));
      }
      for (final Object key : Arrays.asList(
          null, "ea0130", map(),
          map("network", "sora_taira", "profile", null),
          map("network", "tron_mainnet", "profile", null),
          map("network", "bsc_mainnet", "profile", "default"),
          map("network", "bsc_mainnet"),
          map("network", "bsc_mainnet", "profile", null, "extra", 0))) {
        assertThrows(
            "accepted " + subject + " coordinate " + key,
            IllegalArgumentException.class,
            () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(
                sccpProposal(proposal -> proposal.put(
                    "base_revisions", List.of(sccpSubject(subject, key))))));
      }
      for (final Map<String, Object> coordinate : List.of(
          map("subject", subject), map("subject", subject, "key", bscMainnet(), "extra", 0))) {
        assertThrows(
            "accepted subject envelope " + coordinate,
            IllegalArgumentException.class,
            () -> org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal.fromJson(
                sccpProposal(proposal -> proposal.put(
                    "base_revisions", List.of(map("subject", coordinate, "revision", 0))))));
      }
    }
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
    assertEquals("9", parsed.currentHeight);
    assertEquals(List.of("rules-committee", "agenda-council"), parsed.requiredBodyOrder);
    assertEquals("rules-committee", parsed.bodyStates.get(0).body);
    assertEquals(List.of("rules-committee", "agenda-council"), parsed.certificateBodyOrder);
    assertEquals(
        List.of("60".repeat(32), "61".repeat(32)),
        parsed.publicFindingBindings.get(0).endorsingAssignments);
    assertEquals(
        List.of("62".repeat(32), "63".repeat(32)),
        parsed.publicFindingBindings.get(1).endorsingAssignments);

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

    assertEquals(8, ParliamentApiV1.BODY_STATE_FIELDS.size());
    final Map<String, Object> unknownField = readResponse();
    final List<Map<String, Object>> unknownFieldStates = maps(unknownField.get("body_states"));
    unknownFieldStates.get(0).put("unexpected", null);
    unknownField.put("body_states", unknownFieldStates);
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(unknownField), ATTEMPT_ID));
    final Map<String, Object> missingField = readResponse();
    final List<Map<String, Object>> missingFieldStates = maps(missingField.get("body_states"));
    missingFieldStates.get(0).remove("no_result_height");
    missingField.put("body_states", missingFieldStates);
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(missingField), ATTEMPT_ID));

    final Map<String, Object> unsorted = readResponse();
    final Map<String, Object> certificate = objectValue(unsorted.get("certificate"));
    final List<Map<String, Object>> bindings = maps(certificate.get("body_bindings"));
    final Map<String, Object> finding = objectValue(bindings.get(0).get("public_finding"));
    finding.put("endorsing_assignments", List.of("61".repeat(32), "60".repeat(32)));
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
        certificateValue -> certificateValue.put("certified_at_height", 7));
    assertSortitionRequestMutationRejected(
        request -> request.put("beacon_session_id", "ee".repeat(32)));
    assertSortitionRequestMutationRejected(request -> request.put("request_height", 0));
    assertBindingMutationRejected(binding -> binding.put("election_attempt_sequence", 17));
    assertBindingMutationRejected(binding -> binding.put("original_seats", 4));
    assertBindingMutationRejected(
        binding -> binding.put("original_seats", ParliamentApiV1.MAX_BODY_TARGET_SEATS + 1));
    assertBindingMutationRejected(binding -> binding.put("ballot", new LinkedHashMap<>()));

    final Map<String, Object> largeElectorate = readResponse();
    final Map<String, Object> largeCertificate = objectValue(largeElectorate.get("certificate"));
    final List<Map<String, Object>> largeBindings =
        maps(largeCertificate.get("body_bindings"));
    final Map<String, Object> largeBinding = largeBindings.get(0);
    final Map<String, Object> largeRequest =
        new LinkedHashMap<>(objectValue(largeBinding.get("sortition_request")));
    largeBinding.put("sortition_request", largeRequest);
    largeCertificate.put("body_bindings", largeBindings);
    largeRequest.put("candidate_count", 1_001);
    ParliamentApiV1.parseAttemptReadResponse(encode(largeElectorate), ATTEMPT_ID);

    largeRequest.put("candidate_count", 4_294_967_295L);
    ParliamentApiV1.parseAttemptReadResponse(encode(largeElectorate), ATTEMPT_ID);
    largeRequest.put("candidate_count", 4_294_967_296L);
    assertThrows(
        IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptReadResponse(encode(largeElectorate), ATTEMPT_ID));

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

    ParliamentApiV1.parseAttemptReadResponse(
        encode(readResponse(List.of("rules-committee"))), ATTEMPT_ID);

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

    final Map<String, Object> wrongMode = readResponse(List.of("rules-committee"));
    wrongMode.put(
        "required_bodies",
        List.of(
            Map.of(
                "body", "rules-committee",
                "decision_mode", Map.of("mode", "HiddenBindingBallot"))));
    assertEquals(
        "required_bodies[0] uses the wrong decision protocol",
        assertThrows(
                IllegalArgumentException.class,
                () -> ParliamentApiV1.parseAttemptReadResponse(encode(wrongMode), ATTEMPT_ID))
            .getMessage());
  }

  @Test
  public void bodyStateNoResultKindsFollowTheClosedInventoryAndDecisionProtocol() {
    final Set<String> publicKinds =
        Set.of("PublicFindingQuorumUnreachable", "PublicFindingDeadlineExpired");
    assertEquals(5, ParliamentApiV1.NO_RESULT_KINDS.size());
    for (final ParliamentApiV1.NoResultKindLayout layout : ParliamentApiV1.NO_RESULT_KINDS) {
      final String tag = layout.jsonTag;
      final boolean onPublicBody = publicKinds.contains(tag);
      final ParliamentApiV1.AttemptReadResponse admitted =
          ParliamentApiV1.parseAttemptReadResponse(
              onPublicBody ? noResultResponse(tag, null) : noResultResponse(null, tag),
              ATTEMPT_ID);
      final List<ParliamentApiV1.BodyStateProjection> withNoResult = new ArrayList<>();
      for (final ParliamentApiV1.BodyStateProjection state : admitted.bodyStates) {
        if (state.noResultKind != null) withNoResult.add(state);
      }
      assertEquals(1, withNoResult.size());
      final ParliamentApiV1.BodyStateProjection noResult = withNoResult.get(0);
      assertEquals(tag, noResult.noResultKind);
      assertEquals("5", noResult.noResultHeight);
      assertEquals(onPublicBody ? "rules-committee" : "policy-jury", noResult.body);
      assertThrows(
          IllegalArgumentException.class,
          () ->
              ParliamentApiV1.parseAttemptReadResponse(
                  onPublicBody ? noResultResponse(null, tag) : noResultResponse(tag, null),
                  ATTEMPT_ID));
    }
    assertThrows(
        IllegalArgumentException.class,
        () ->
            ParliamentApiV1.parseAttemptReadResponse(
                noResultResponse("UnknownNoResultKind", null), ATTEMPT_ID));
  }

  @Test
  public void
      certificateWithAPrivateJuryBindingIsRejectedUntilTheAnonymousBallotBindingIsSupported() {
    // Public-only pipelines parse; a private-jury body binding is withheld, whatever it carries.
    ParliamentApiV1.parseAttemptReadResponse(
        encode(readResponse(List.of("rules-committee", "agenda-council"))), ATTEMPT_ID);

    final List<List<String>> pipelines =
        List.of(
            List.of("policy-jury"),
            List.of("rules-committee", "policy-jury"),
            List.of("rules-committee", "agenda-council", "confirmation-jury"),
            List.of("rules-committee", "policy-jury", "confirmation-jury"));
    final List<Integer> firstPrivateIndexes = List.of(0, 1, 2, 1);
    for (int pipeline = 0; pipeline < pipelines.size(); pipeline++) {
      final int index = firstPrivateIndexes.get(pipeline);
      for (final Object ballot : new Object[] {null, new LinkedHashMap<String, Object>()}) {
        final Map<String, Object> response = readResponse(pipelines.get(pipeline));
        final Map<String, Object> certificate = objectValue(response.get("certificate"));
        final List<Map<String, Object>> bindings = maps(certificate.get("body_bindings"));
        bindings.get(index).put("ballot", ballot);
        certificate.put("body_bindings", bindings);
        final IllegalArgumentException failure =
            assertThrows(
                IllegalArgumentException.class,
                () -> ParliamentApiV1.parseAttemptReadResponse(encode(response), ATTEMPT_ID));
        assertEquals(
            "certificate.body_bindings["
                + index
                + "] private-jury result binding is not admitted until the anonymous-ballot"
                + " result binding is supported",
            failure.getMessage());
      }
    }

    // The attempt itself stays readable while its private bodies are still pending.
    final Map<String, Object> pending = readResponse(List.of("rules-committee", "policy-jury"));
    pending.put("certificate", null);
    assertEquals(
        List.of("rules-committee", "policy-jury"),
        ParliamentApiV1.parseAttemptReadResponse(encode(pending), ATTEMPT_ID).requiredBodyOrder);
  }

  private static Map<String, Object> readResponse() {
    return readResponse(List.of("rules-committee", "agenda-council"));
  }

  /**
   * Certified attempt read over {@code bodies}, a strictly increasing subset of the canonical body
   * order whose results all land at height 8. A public body carries a public-finding binding; a
   * private body carries neither a public finding nor a ballot binding.
   */
  private static Map<String, Object> readResponse(final List<String> bodies) {
    final List<Integer> root = byteValues(32, 0x55);
    final List<Object> requiredBodies = new ArrayList<>();
    final List<Object> bodyStates = new ArrayList<>();
    final List<Object> bindings = new ArrayList<>();
    for (int index = 0; index < bodies.size(); index++) {
      final String body = bodies.get(index);
      final boolean isPrivate = body.equals("policy-jury") || body.equals("confirmation-jury");
      requiredBodies.add(
          map(
              "body", body,
              "decision_mode",
              Map.of("mode", isPrivate ? "HiddenBindingBallot" : "PublicFinding")));
      bodyStates.add(
          map(
              "body", body,
              "body_instance_id", id(0x10, index),
              "status", Map.of("status", "Approved"),
              "public_finding_opened_at_height", isPrivate ? null : 1,
              "public_finding_phase_blocks", isPrivate ? null : 7,
              "public_finding_deadline_height", isPrivate ? null : 8,
              "no_result_kind", null,
              "no_result_height", null));
      bindings.add(
          map(
              "body_instance_id", id(0x10, index),
              "election_attempt_id", id(0x20, index),
              "election_attempt_sequence", 0,
              "sortition_request_id", id(0x30, index),
              "sortition_request",
              map(
                  "id", id(0x30, index),
                  "governance_attempt_id", ATTEMPT_ID,
                  "body_election_attempt_id", id(0x20, index),
                  "body", body,
                  "candidate_root", root,
                  "candidate_count", 3,
                  "target_seats", 3,
                  "request_height", 1,
                  "pulse_height", 2,
                  "beacon_session_id", id(0x40, index)),
              "body", body,
              "original_seats", 3,
              "beacon_session_id", id(0x40, index),
              "beacon_pulse_id", id(0x50, index),
              "roster_root", root,
              "assignment_root", root,
              "result_root", root,
              "result_height", 8,
              "public_finding",
              isPrivate
                  ? null
                  : map(
                      "endorsement_root", root,
                      "endorsing_assignments",
                      List.of(id(0x60, 2 * index), id(0x61, 2 * index)),
                      "endorsements", 2,
                      "quorum", 2),
              "ballot", null));
    }
    return map(
        "version", 1,
        "current_height", 9,
        "attempt",
        map(
            "id", ATTEMPT_ID,
            "proposal_content_id", PROPOSAL_ID,
            "sequence", 0,
            "risk_tier", Map.of("tier", "Standard"),
            "stage", Map.of("stage", "Rules"),
            "status", Map.of("status", "Certified")),
        "policy_version", 1,
        "required_bodies", requiredBodies,
        "body_states", bodyStates,
        "certificate",
        map(
            "proposal_content_id", PROPOSAL_ID,
            "governance_attempt_id", ATTEMPT_ID,
            "governance_attempt_sequence", 0,
            "risk_tier", Map.of("tier", "Standard"),
            "body_bindings", bindings,
            "policy_version", 1,
            "effect_preimage_hash", root,
            "expected_head", Map.of("state", "Absent", "head", Map.of("subject_id", root)),
            "certified_at_height", 8,
            "enact_at_height", 10),
        "terminal_height", null,
        "superseding_head", null,
        "execution_failure_root", null,
        "state_payload_hex", stateFrameHex());
  }

  private static byte[] noResultResponse(final String publicKind, final String privateKind) {
    final Map<String, Object> read = readResponse(List.of("rules-committee", "policy-jury"));
    read.put("certificate", null);
    final List<Map<String, Object>> states = maps(read.get("body_states"));
    final String[] kinds = {publicKind, privateKind};
    for (int index = 0; index < kinds.length; index++) {
      if (kinds[index] != null) {
        states.get(index).put("status", Map.of("status", "NoResult"));
        states.get(index).put("no_result_kind", Map.of("reason", kinds[index]));
        states.get(index).put("no_result_height", 5);
      }
    }
    read.put("body_states", states);
    return encode(read);
  }

  private static String id(final int seed, final int index) {
    return String.format("%02x", seed + index).repeat(32);
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

  private static void assertBindingMutationRejected(
      final Consumer<Map<String, Object>> mutation) {
    assertCertificateMutationRejected(
        certificate -> {
          final List<Map<String, Object>> bindings = maps(certificate.get("body_bindings"));
          mutation.accept(bindings.get(0));
          certificate.put("body_bindings", bindings);
        });
  }

  private static void assertSortitionRequestMutationRejected(
      final Consumer<Map<String, Object>> mutation) {
    assertBindingMutationRejected(
        binding -> {
          final Map<String, Object> request =
              new LinkedHashMap<>(objectValue(binding.get("sortition_request")));
          mutation.accept(request);
          binding.put("sortition_request", request);
        });
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
