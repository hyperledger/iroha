package org.hyperledger.iroha.sdk.client;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Collections;
import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent;
import org.hyperledger.iroha.sdk.core.model.JsonValue;
import org.hyperledger.iroha.sdk.validationfee.RetailFeeAssessmentBridge;
import org.junit.jupiter.api.Test;
import org.hyperledger.iroha.sdk.address.AccountAddress;
import org.hyperledger.iroha.sdk.testing.TestEd25519Keys;

/** Java consumers retain the reviewed assessment through the canonical Kotlin model. */
final class RetailFeeJavaConsumerTest {
  @Test
  void operationBoundsRejectBeforeLoadingNative() {
    assertThrows(IllegalArgumentException.class,
        () -> RetailFeeAssessmentBridge.intentHashV1(new byte[262_145]));
    assertThrows(IllegalArgumentException.class,
        () -> RetailFeeAssessmentBridge.assessmentMarkerV1(new byte[4_097]));
    assertThrows(IllegalArgumentException.class,
        () -> RetailFeeAssessmentBridge.decodeAssessmentV1(new byte[4_097]));
    assertThrows(IllegalArgumentException.class,
        () -> RetailFeeAssessmentBridge.intentHashV1(new byte[0]));
    assertThrows(IllegalArgumentException.class,
        () -> RetailFeeAssessmentBridge.assessmentMarkerV1(new byte[0]));
    assertThrows(IllegalArgumentException.class,
        () -> RetailFeeAssessmentBridge.decodeAssessmentV1(new byte[0]));
  }
  @Test
  void includedAssessmentAndInstructionSnapshotSurviveJavaCallerMutation() throws Exception {
    byte[] instruction = new byte[] {1, 2, 3};
    JsonValue assessment = JsonValue.parse("{\"fee_minor\":0,\"policy_revision\":2,\"retail_enrolled\":true}");
    MultisigProposeRequest request = new MultisigProposeRequest(
        account(), "signer-fixture", "0707070707070707070707070707070707070707070707070707070707070707", Collections.singletonList(instruction),
        null, null, 123L, FeePaymentIntent.authority(Collections.emptyList()), null, assessment);
    instruction[0] = 9;
    request.getInstructions().get(0)[1] = 9;
    assertArrayEquals(new byte[] {1, 2, 3}, request.getInstructions().get(0));
    assertEquals(assessment, request.getValidationFeeAssessment());
    assertTrue(request.getValidationFeeAssessment().getCanonicalJson().contains("\"fee_minor\":0"));
    assertThrows(IllegalArgumentException.class, () -> new MultisigProposeRequest(
        account(), "signer-fixture", "0707070707070707070707070707070707070707070707070707070707070707", Collections.singletonList(instruction),
        null, null, 123L, FeePaymentIntent.authority(Collections.emptyList()), null, JsonValue.number(0)));
  }
  private static String account() throws Exception {
    return AccountAddress.fromAccount(TestEd25519Keys.publicKey(0x37), "ed25519")
        .toI105(AccountAddress.DEFAULT_I105_DISCRIMINANT);
  }

}
