package org.hyperledger.iroha.sdk.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** Java consumers share Kotlin's exact32 opaque-output execution response contract. */
final class RamLfeExecuteJavaConsumerTest {
  @Test
  void parsesOpaqueOutputAndReceiptWithoutInventingAPlaintextOpening() {
    String json = HttpClientTransportTestSupportKt.ramLfeExecuteResponseJson();
    RamLfeExecuteResponse response = RamLfeJsonParser.parseExecuteResponse(
        json.getBytes(StandardCharsets.UTF_8));
    assertEquals("identifier_lookup_retail", response.programId);
    assertEquals(HttpClientTransportTestSupportKt.currentOwnerExecuteResponseField("opaque_output"), response.opaqueOutputHex);
    assertEquals(1_735_000_000_000L, response.executedAtMs);
    assertEquals(HttpClientTransportTestSupportKt.currentOwnerExecuteResponseField("program_id_canonical"), response.programIdCanonicalHex);
    assertTrue(response.receipt.containsKey("payload"));
  }

  @Test
  void rejectsRetiredOpeningEvenWhenTheRemainingResponseIsValid() {
    String json = HttpClientTransportTestSupportKt.ramLfeExecuteResponseJson();
    String changed = json.replaceFirst("\\{", "{\"output_opening\":{},");
    IllegalStateException error = assertThrows(IllegalStateException.class,
        () -> RamLfeJsonParser.parseExecuteResponse(changed.getBytes(StandardCharsets.UTF_8)));
    assertTrue(error.getMessage().contains("ram-lfe execute response.output_opening"));
  }

  @Test
  void rejectsRetiredAndUnknownBackendAndModeTags() {
    String json = HttpClientTransportTestSupportKt.ramLfeExecuteResponseJson();
    for (String backend : new String[] {
        "bfv-affine-sha3-256-v1", "bfv-programmed-sha3-256-v1", "unknown"}) {
      String changed = json.replace("\"backend\": \"hkdf-sha3-512-prf-v1\"",
          "\"backend\": \"" + backend + "\"");
      assertTrue(!changed.equals(json));
      IllegalStateException error = assertThrows(IllegalStateException.class,
          () -> RamLfeJsonParser.parseExecuteResponse(changed.getBytes(StandardCharsets.UTF_8)));
      assertTrue(error.getMessage().contains("ram-lfe execute response.backend"));
    }
    for (String mode : new String[] {"unknown", "ivm-proved"}) {
      String changed = json.replace("\"verification_mode\": \"signed\"",
          "\"verification_mode\": \"" + mode + "\"");
      assertTrue(!changed.equals(json));
      IllegalStateException error = assertThrows(IllegalStateException.class,
          () -> RamLfeJsonParser.parseExecuteResponse(changed.getBytes(StandardCharsets.UTF_8)));
      assertTrue(error.getMessage().contains("ram-lfe execute response.verification_mode"));
    }
  }

  @Test
  void kotlinOwnerFactoriesRejectRetiredInputAndRequireExactNonce() {
    String nonce = String.join("", java.util.Collections.nCopies(32, "12"));
    RamLfeExecuteRequest request = RamLfeExecuteRequest.ownerInput("private@example.org", nonce);
    assertEquals("private@example.org", request.normalizedInput);
    assertEquals(nonce, request.inputNonceHex);
    assertThrows(IllegalArgumentException.class, () -> RamLfeExecuteRequest.ownerInput("private@example.org", "abcd"));
    assertThrows(IllegalArgumentException.class, () -> RamLfeExecuteRequest.ownerInput("", nonce));
  }
}
