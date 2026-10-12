package org.hyperledger.iroha.sdk.tx.norito;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import org.hyperledger.iroha.sdk.client.ClientConfig;
import org.hyperledger.iroha.sdk.client.HttpClientTransport;
import org.hyperledger.iroha.sdk.client.HttpTransportExecutor;
import org.hyperledger.iroha.sdk.client.IrohaClient;
import org.hyperledger.iroha.sdk.client.JsonParser;
import org.hyperledger.iroha.sdk.client.MultisigProposeRequest;
import org.hyperledger.iroha.sdk.client.transport.TransportRequest;
import org.hyperledger.iroha.sdk.client.transport.TransportResponse;
import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent;
import org.hyperledger.iroha.sdk.core.model.InstructionBox;
import org.hyperledger.iroha.sdk.core.model.JsonValue;
import org.junit.jupiter.api.Test;

/** Java consumers call the canonical Kotlin owner; these are DATA controls, not money admission. */
final class CanonicalMultisigJavaConsumerTest {
  private static final String BASE_POINT = "58" + repeat("66", 31);

  private static byte[] instruction() throws Exception {
    return NoritoJavaCodecAdapter.encodeInstructionBox(InstructionBox.fromWirePayload(
        "iroha.custom", InstructionBatchHashFixture.bytes("custom_instruction_frame_hex")));
  }

  private static MultisigProposeRequest request(byte[] instruction, String publicKey, JsonValue assessment) {
    return new MultisigProposeRequest(null, "controller@bank", "signer-fixture", "0707070707070707070707070707070707070707070707070707070707070707",
        Collections.singletonList(instruction), publicKey, null, 123L,
        FeePaymentIntent.authority(Collections.emptyList(), 7L), "invoice 42", assessment);
  }

  @Test
  void canonicalJsonRetainsOwnedInstructionsAndExactFeeIntentWithoutRetiredFields() throws Exception {
    byte[] original = instruction();
    byte[] expected = original.clone();
    MultisigProposeRequest request = request(original, null, null);
    Arrays.fill(original, (byte) 0);
    Arrays.fill(request.getInstructions().get(0), (byte) 0);
    byte[] first = request.canonicalToriiJsonBytes();
    @SuppressWarnings("unchecked")
    Map<String, Object> payload = (Map<String, Object>) JsonParser.parse(new String(first, StandardCharsets.UTF_8));
    assertEquals("controller@bank", payload.get("multisig_account_alias"));
    assertEquals("signer-fixture", payload.get("signer_account_id"));
    assertEquals("0707070707070707070707070707070707070707070707070707070707070707", payload.get("proposal_nonce"));
    assertEquals(123L, ((Number) payload.get("creation_time_ms")).longValue());
    assertEquals("invoice 42", payload.get("memo"));
    assertEquals(Collections.singletonList(Base64.getEncoder().encodeToString(expected)), payload.get("instructions"));
    @SuppressWarnings("unchecked")
    Map<String, Object> fee = (Map<String, Object>) payload.get("fee_payment");
    @SuppressWarnings("unchecked")
    Map<String, Object> feeValue = (Map<String, Object>) fee.get("value");
    assertEquals("authority", fee.get("payer"));
    assertEquals(7L, ((Number) feeValue.get("gas_limit")).longValue());
    assertEquals(Collections.emptyList(), feeValue.get("charge_limits"));
    for (String name : Arrays.asList("validation_fee_policy_version", "validation_fee_policy_hash",
        "validation_fee_hijiri_fee_quote_hash", "validation_fee_instruction_index", "validation_fee_transfer_entry_index")) {
      assertFalse(payload.containsKey(name), name);
    }
    Arrays.fill(first, (byte) 0);
    assertArrayEquals(expected, request.getInstructions().get(0));
    assertEquals(payload, JsonParser.parse(new String(request.canonicalToriiJsonBytes(), StandardCharsets.UTF_8)));
  }

  @Test
  void canonicalPublicKeyNormalizationAndIdentityRefusalRemainAvailableToJava() throws Exception {
    MultisigProposeRequest normalized = request(instruction(), " 0X" + BASE_POINT.toUpperCase(java.util.Locale.ROOT) + " ", null);
    @SuppressWarnings("unchecked")
    Map<String, Object> payload = (Map<String, Object>) JsonParser.parse(new String(normalized.canonicalToriiJsonBytes(), StandardCharsets.UTF_8));
    assertEquals(BASE_POINT, payload.get("public_key_hex"));
    MultisigProposeRequest identity = request(instruction(), "01" + repeat("00", 31), null);
    assertThrows(IllegalArgumentException.class, identity::canonicalToriiJsonBytes);
  }

  @Test
  void assessmentUsesExactUtf8ObjectBoundWithoutGrantingNativeAdmission() throws Exception {
    byte[] instruction = instruction();
    JsonValue exact = JsonValue.parse("{\"x\":\"" + repeat("a", 4088) + "\"}");
    assertEquals(4096, exact.getCanonicalJson().getBytes(StandardCharsets.UTF_8).length);
    assertEquals(exact, request(instruction, null, exact).getValidationFeeAssessment());
    JsonValue tooLarge = JsonValue.parse("{\"x\":\"" + repeat("a", 4089) + "\"}");
    assertEquals(4097, tooLarge.getCanonicalJson().getBytes(StandardCharsets.UTF_8).length);
    assertThrows(IllegalArgumentException.class, () -> request(instruction, null, tooLarge));
    JsonValue utf8TooLarge = JsonValue.parse("{\"x\":\"" + repeat("\u00e9", 2045) + "\"}");
    assertTrue(utf8TooLarge.getCanonicalJson().length() < 4096);
    assertTrue(utf8TooLarge.getCanonicalJson().getBytes(StandardCharsets.UTF_8).length > 4096);
    assertThrows(IllegalArgumentException.class, () -> request(instruction, null, utf8TooLarge));
    for (String invalid : Arrays.asList("null", "[]", "0", "\"object\"")) {
      assertThrows(IllegalArgumentException.class, () -> request(instruction, null, JsonValue.parse(invalid)));
    }
  }

  @Test
  void ambiguousSelectorsAndEmptyInstructionsRefuseAtCanonicalConstructor() throws Exception {
    byte[] instruction = instruction();
    FeePaymentIntent fee = FeePaymentIntent.authority(Collections.emptyList());
    assertThrows(IllegalArgumentException.class, () -> new MultisigProposeRequest(
        "account-fixture", "controller@bank", "signer-fixture", "0707070707070707070707070707070707070707070707070707070707070707", Collections.singletonList(instruction), null, null, null, fee, null, null));
    assertThrows(IllegalArgumentException.class, () -> new MultisigProposeRequest(
        null, null, "signer-fixture", "0707070707070707070707070707070707070707070707070707070707070707", Collections.singletonList(instruction), null, null, null, fee, null, null));
    assertThrows(IllegalArgumentException.class, () -> new MultisigProposeRequest(
        null, "controller@bank", "signer-fixture", "0707070707070707070707070707070707070707070707070707070707070707", Collections.emptyList(), null, null, null, fee, null, null));
    assertThrows(IllegalArgumentException.class, () -> request(new byte[0], null, null));
  }

  @Test
  void realCanonicalTransportRequiresTrustedSigningContextBeforeDispatch() throws Exception {
    AtomicInteger dispatches = new AtomicInteger();
    HttpTransportExecutor executor = new HttpTransportExecutor() {
      @Override public CompletableFuture<TransportResponse> execute(TransportRequest request) {
        dispatches.incrementAndGet();
        throw new AssertionError("unconfigured signing context reached dispatch");
      }
      @Override public void close() {}
    };
    IrohaClient client = new HttpClientTransport(executor, ClientConfig.builder().build());
    MultisigProposeRequest request = request(instruction(), null, null);
    assertThrows(IllegalStateException.class, () -> client.proposeMultisig(request));
    assertEquals(0, dispatches.get());
  }

  @Test
  void typedInstructionFactoryRemainsAvailableToJava() throws Exception {
    InstructionBox original = InstructionBox.fromWirePayload(
        "iroha.custom", InstructionBatchHashFixture.bytes("custom_instruction_frame_hex"));
    FeePaymentIntent fee = FeePaymentIntent.authority(Collections.emptyList(), 7L);
    MultisigProposeRequest request = MultisigProposeRequest.fromInstructionBoxes(
        null, "controller@bank", "signer-fixture", "0707070707070707070707070707070707070707070707070707070707070707", Collections.singletonList(original),
        null, null, 123L, fee, "invoice 42", null);
    byte[] expected = NoritoJavaCodecAdapter.encodeInstructionBox(original);
    assertArrayEquals(expected, request.getInstructions().get(0));
    assertEquals(fee, request.getFeePayment());
    assertEquals("invoice 42", request.getMemo());
    @SuppressWarnings("unchecked")
    Map<String, Object> payload = (Map<String, Object>) JsonParser.parse(
        new String(request.canonicalToriiJsonBytes(), StandardCharsets.UTF_8));
    assertEquals(Collections.singletonList(Base64.getEncoder().encodeToString(expected)),
        payload.get("instructions"));
  }

  private static String repeat(String value, int count) {
    StringBuilder result = new StringBuilder(value.length() * count);
    for (int index = 0; index < count; index++) result.append(value);
    return result.toString();
  }
}
