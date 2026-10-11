package org.hyperledger.iroha.sdk.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Java consumers use Kotlin-owned Parliament proposal admission and draft models directly. */
final class ParliamentApiV1JavaConsumerTest {
  private static final String ATTEMPT_ID = repeat("ab", 32);
  private static final String PROPOSAL_ID = repeat("cd", 32);
  private static final String CONTRACT_ADDRESS =
      "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";

  @Test
  void proposalValidationAndAttemptDraftKeepTheClosedFirstReleaseShape() {
    ParliamentApiV1.Proposal proposal = ParliamentApiV1.Proposal.fromJson(encode(holdProposal()));
    assertEquals("ContractEmergencyHold", proposal.getKind());

    Map<String, Object> draft = objectValue(ParliamentApiV1.attemptDraftRequestJson(
        proposal, ParliamentApiV1.MAX_GOVERNANCE_ATTEMPT_RETRIES));
    assertEquals(new HashSet<>(Arrays.asList("version", "proposal", "attempt_sequence")),
        draft.keySet());
    assertEquals(1L, draft.get("version"));
    assertEquals(16L, draft.get("attempt_sequence"));
    assertEquals("ContractEmergencyHold", objectValue(draft.get("proposal")).get("kind"));
    assertThrows(IllegalArgumentException.class,
        () -> ParliamentApiV1.attemptDraftRequestJson(proposal, 17));

    Map<String, Object> missingReason = holdProposal();
    objectValue(missingReason.get("payload")).remove("reason");
    assertThrows(IllegalArgumentException.class,
        () -> ParliamentApiV1.Proposal.fromJson(encode(missingReason)));
    Map<String, Object> extraField = holdProposal();
    objectValue(extraField.get("payload")).put("private_key", "secret");
    assertThrows(IllegalArgumentException.class,
        () -> ParliamentApiV1.Proposal.fromJson(encode(extraField)));
    Map<String, Object> excessiveHold = holdProposal();
    objectValue(excessiveHold.get("payload")).put("duration_blocks", 3_601);
    assertThrows(IllegalArgumentException.class,
        () -> ParliamentApiV1.Proposal.fromJson(encode(excessiveHold)));
    assertThrows(IllegalArgumentException.class,
        () -> ParliamentApiV1.Proposal.fromJson(bytes(
            "{\"kind\":\"ProposeDeployContract\",\"payload\":{}}")));
    assertThrows(IllegalArgumentException.class,
        () -> ParliamentApiV1.Proposal.fromJson(new byte[] {(byte) 0xc3, (byte) 0x28}));
  }

  @Test
  void retiredKagemushaProposalKindsAreRejectedByTheKotlinParser() {
    for (String kind : Arrays.asList(
        "KagemushaVerifierPolicyInstall",
        "KagemushaVerifierReleaseInstall",
        "KagemushaVerifierReleaseActivate",
        "KagemushaVerifierReleaseRetire")) {
      for (Object payload : Arrays.asList(null, Collections.emptyMap(),
          map("proposal_operator", "invalid"))) {
        assertEquals("proposal.kind is unknown or retired",
            assertThrows(IllegalArgumentException.class,
                () -> ParliamentApiV1.Proposal.fromJson(encode(map(
                    "kind", kind, "payload", payload)))).getMessage());
      }
    }
  }

  @Test
  void draftResponseUsesKotlinModelsAndRejectsForeignOrExtendedWireData() {
    Map<String, Object> response = map(
        "version", 1,
        "proposal_content_id", PROPOSAL_ID,
        "governance_attempt_id", ATTEMPT_ID,
        "tx_instructions", Collections.singletonList(map(
            "wire_id", ParliamentApiV1.ATTEMPT_CREATE_WIRE_ID,
            "payload_hex", "0102")));
    ParliamentAttemptDraftResponseV1 parsed = ParliamentApiV1.parseAttemptDraftResponse(
        encode(response), PROPOSAL_ID, ATTEMPT_ID);
    ParliamentInstructionDraftV1 instruction = parsed.getInstruction();
    assertEquals(PROPOSAL_ID, parsed.getProposalContentId());
    assertEquals(ATTEMPT_ID, parsed.getGovernanceAttemptId());
    assertEquals(ParliamentApiV1.ATTEMPT_CREATE_WIRE_ID, instruction.getWireId());
    assertEquals("0102", instruction.getPayloadHex());
    assertEquals("/v1/gov/parliament/attempts/" + ATTEMPT_ID,
        ParliamentApiV1.attemptReadPath(ATTEMPT_ID));
    assertThrows(IllegalArgumentException.class,
        () -> ParliamentApiV1.attemptReadPath(ATTEMPT_ID.toUpperCase(Locale.ROOT)));
    assertThrows(IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptDraftResponse(
            encode(response), repeat("ee", 32), ATTEMPT_ID));

    Map<String, Object> wrongVersion = new LinkedHashMap<>(response);
    wrongVersion.put("version", 2);
    assertThrows(IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptDraftResponse(
            encode(wrongVersion), PROPOSAL_ID, ATTEMPT_ID));
    Map<String, Object> unknown = new LinkedHashMap<>(response);
    unknown.put("private_key", "secret");
    assertThrows(IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptDraftResponse(
            encode(unknown), PROPOSAL_ID, ATTEMPT_ID));
    Map<String, Object> wrongWireId = new LinkedHashMap<>(response);
    wrongWireId.put("tx_instructions", Collections.singletonList(map(
        "wire_id", ParliamentApiV1.TRANSITION_SUBMIT_WIRE_ID,
        "payload_hex", "0102")));
    assertThrows(IllegalArgumentException.class,
        () -> ParliamentApiV1.parseAttemptDraftResponse(
            encode(wrongWireId), PROPOSAL_ID, ATTEMPT_ID));
  }

  private static Map<String, Object> holdProposal() {
    return map("kind", "ContractEmergencyHold", "payload", map(
        "contract_address", CONTRACT_ADDRESS,
        "expected_revision", 2,
        "expected_code_hash", repeat("33", 32),
        "incident_digest", Collections.nCopies(32, 0x55),
        "reason", "contain active exploit",
        "duration_blocks", 3_600));
  }

  private static Map<String, Object> map(Object... entries) {
    if (entries.length % 2 != 0) throw new AssertionError("map entries must be paired");
    Map<String, Object> value = new LinkedHashMap<>();
    for (int index = 0; index < entries.length; index += 2) {
      value.put((String) entries[index], entries[index + 1]);
    }
    return value;
  }

  private static byte[] encode(Map<String, Object> value) {
    return bytes(JsonEncoder.encode(value));
  }

  private static byte[] bytes(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> objectValue(byte[] value) {
    return objectValue(JsonParser.parse(new String(value, StandardCharsets.UTF_8)));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> objectValue(Object value) {
    return (Map<String, Object>) value;
  }

  private static String repeat(String value, int count) {
    StringBuilder result = new StringBuilder(value.length() * count);
    for (int index = 0; index < count; index++) result.append(value);
    return result.toString();
  }
}
