// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.core.model.instructions;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Collections;
import org.junit.jupiter.api.Test;

/** Java consumers use the canonical Kotlin owner-qualified settlement API. */
final class BilateralSettlementJavaTest {
  private static final String ALICE =
      "sorauﾛ1NｲﾘｳdPBeｼRoｸQ2ﾔgｼQqeｶﾍｽﾁhRW2ｺｿZ9ﾕｦUﾅRX5NJYH53";
  private static final String BOB =
      "sorauﾛ1P58ﾊt2MaｺxhpﾄｽﾅｲｼKヰkDﾑｱjｴｴ9GFﾉﾌkrｽRzﾑﾌxKBMEBH";

  @Test
  void javaRetainsTypedIdentityAndTheExactConsent() {
    BilateralSettlementInstructions.SettlementId id =
        new BilateralSettlementInstructions.SettlementId(ALICE, "java-payment");
    assertEquals(id, BilateralSettlementInstructions.SettlementId.parse(id.toString()));
    assertEquals(ALICE, id.getOwner());
    assertEquals("java-payment", id.getReference());
    assertThrows(
        IllegalArgumentException.class,
        () -> BilateralSettlementInstructions.SettlementId.parse("java-payment"));
    BilateralSettlementInstructions.SettlementLeg delivery =
        new BilateralSettlementInstructions.SettlementLeg(
            "7cgpbDVabB1g8uax9JkhGckEHwfe", "10", ALICE, BOB, Collections.emptyMap());
    BilateralSettlementInstructions.SettlementLeg payment =
        new BilateralSettlementInstructions.SettlementLeg(
            "4eaant86faGEgeH21U4qTTfpvwSb", "20", BOB, ALICE, Collections.emptyMap());
    BilateralSettlementInstructions.Dvp first =
        new BilateralSettlementInstructions.Dvp(
            id,
            delivery,
            payment,
            BilateralSettlementInstructions.ExecutionOrder.DELIVERY_THEN_PAYMENT,
            Collections.emptyMap());
    BilateralSettlementInstructions.Dvp resumed =
        new BilateralSettlementInstructions.Dvp(
            BilateralSettlementInstructions.SettlementId.parse(id.toString()),
            delivery,
            payment,
            BilateralSettlementInstructions.ExecutionOrder.DELIVERY_THEN_PAYMENT,
            Collections.emptyMap());
    assertEquals(id, first.getSettlementId());
    assertArrayEquals(first.canonicalInstructionBytes(), resumed.canonicalInstructionBytes());
    assertArrayEquals(first.intentHash(), resumed.intentHash());
  }
}
