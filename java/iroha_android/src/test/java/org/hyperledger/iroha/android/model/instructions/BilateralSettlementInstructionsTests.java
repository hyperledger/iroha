// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.android.model.instructions;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Properties;
import org.hyperledger.iroha.android.address.AccountAddress;
import org.hyperledger.iroha.android.model.InstructionBox;

/** Shared Rust-wire parity and invariant tests for typed bilateral settlement construction. */
public final class BilateralSettlementInstructionsTests {
  private static final String ALICE =
      "sorauﾛ1NｲﾘｳdPBeｼRoｸQ2ﾔgｼQqeｶﾍｽﾁhRW2ｺｿZ9ﾕｦUﾅRX5NJYH53";
  private static final String BOB =
      "sorauﾛ1P58ﾊt2MaｺxhpﾄｽﾅｲｼKヰkDﾑｱjｴｴ9GFﾉﾌkrｽRzﾑﾌxKBMEBH";
  private static final String BOND = "7cgpbDVabB1g8uax9JkhGckEHwfe";
  private static final String USD = "4eaant86faGEgeH21U4qTTfpvwSb";
  private static final String EUR = "5n4HJrqdiJkuFTa2Kmx2DvXnBkos";
  private static final String REPO_INITIATOR = ALICE;
  private static final String REPO_COUNTERPARTY = BOB;
  private static final String REPO_CUSTODIAN =
      "sorauﾛ1Q3ﾘヰｴﾀknﾀﾏｾｳﾚﾒﾎvﾘEPｶﾉPmｼMﾘｱﾂSNFsｶヱeﾒyヰﾜPD63RA";

  private BilateralSettlementInstructionsTests() {}

  public static void main(final String[] args) throws Exception {
    dvpAndPvpMatchSharedRustCompatibleFixtures();
    repoAndReverseMatchSharedRustFixturesAndConsentHashes();
    constructorsRejectAmbiguousOrUnsafeEconomicTerms();
    System.out.println("[IrohaAndroid] Bilateral settlement instruction tests passed.");
  }

  private static void dvpAndPvpMatchSharedRustCompatibleFixtures() throws Exception {
    final Properties fixtures = fixtures();
    final BilateralSettlementInstructions.Dvp dvp = dvp();
    final BilateralSettlementInstructions.Pvp pvp = pvp();

    assertWireFixture(
        dvp.toInstructionBox(), "iroha.settlement", fixtures.getProperty("dvp.payload_base64"));
    assert java.util.Arrays.equals(
        hex(fixtures.getProperty("dvp.intent_hash_hex")), dvp.intentHash());
    assert "ALL_OR_NOTHING".equals(dvp.toArguments().get("atomicity"));

    assertWireFixture(
        pvp.toInstructionBox(), "iroha.settlement", fixtures.getProperty("pvp.payload_base64"));
    assert java.util.Arrays.equals(
        hex(fixtures.getProperty("pvp.intent_hash_hex")), pvp.intentHash());
    assert "ALL_OR_NOTHING".equals(pvp.toArguments().get("atomicity"));
  }

  private static void repoAndReverseMatchSharedRustFixturesAndConsentHashes()
      throws Exception {
    final Properties fixtures = fixtures();
    final BilateralSettlementInstructions.Repo repo = repo();

    assertWireFixture(
        repo.toInstructionBox(), "iroha.repo", fixtures.getProperty("repo.payload_base64"));
    assert "daily_repo".equals(repo.settlementId());
    assert java.util.Arrays.equals(
        hex(fixtures.getProperty("repo.initiation_intent_hash_hex")),
        repo.initiationIntentHash());
    assert java.util.Arrays.equals(
        hex(fixtures.getProperty("repo.maturity_intent_hash_hex")),
        repo.maturityIntentHash());
    assertWireFixture(
        new BilateralSettlementInstructions.ReverseRepo("daily_repo").toInstructionBox(),
        "iroha.repo",
        fixtures.getProperty("reverse_repo.payload_base64"));
  }

  private static void constructorsRejectAmbiguousOrUnsafeEconomicTerms()
      throws Exception {
    final String sameControllerOtherDiscriminant =
        AccountAddress.fromI105(ALICE, null).toI105(1);
    expectIllegalArgument(
        () ->
            new BilateralSettlementInstructions.SettlementLeg(
                BOND, "1", ALICE, sameControllerOtherDiscriminant));
    expectIllegalArgument(
        () -> new BilateralSettlementInstructions.SettlementLeg(BOND, "0", ALICE, BOB));
    expectIllegalArgument(
        () ->
            new BilateralSettlementInstructions.Dvp(
                "not_reciprocal",
                new BilateralSettlementInstructions.SettlementLeg(BOND, "1", ALICE, BOB),
                new BilateralSettlementInstructions.SettlementLeg(USD, "1", ALICE, BOB),
                BilateralSettlementInstructions.ExecutionOrder.DELIVERY_THEN_PAYMENT));
    expectIllegalArgument(() -> new BilateralSettlementInstructions.RepoGovernance(10_001, 1, false));
    expectIllegalArgument(
        () ->
            new BilateralSettlementInstructions.Repo(
                "repo",
                ALICE,
                BOB,
                ALICE,
                new BilateralSettlementInstructions.RepoCashLeg(USD, "1"),
                new BilateralSettlementInstructions.RepoCollateralLeg(BOND, "1"),
                0,
                1,
                new BilateralSettlementInstructions.RepoGovernance(0, 0, false)));
  }

  private static BilateralSettlementInstructions.Dvp dvp() {
    return new BilateralSettlementInstructions.Dvp(
        "dvp_trade_1",
        new BilateralSettlementInstructions.SettlementLeg(BOND, "1000", ALICE, BOB),
        new BilateralSettlementInstructions.SettlementLeg(USD, "1005", BOB, ALICE),
        BilateralSettlementInstructions.ExecutionOrder.DELIVERY_THEN_PAYMENT);
  }

  private static BilateralSettlementInstructions.Pvp pvp() {
    return new BilateralSettlementInstructions.Pvp(
        "pvp_fx_1",
        new BilateralSettlementInstructions.SettlementLeg(USD, "1000", ALICE, BOB),
        new BilateralSettlementInstructions.SettlementLeg(EUR, "920", BOB, ALICE),
        BilateralSettlementInstructions.ExecutionOrder.PAYMENT_THEN_DELIVERY);
  }

  private static BilateralSettlementInstructions.Repo repo() {
    return new BilateralSettlementInstructions.Repo(
        "daily_repo",
        REPO_INITIATOR,
        REPO_COUNTERPARTY,
        REPO_CUSTODIAN,
        new BilateralSettlementInstructions.RepoCashLeg(USD, "1000"),
        new BilateralSettlementInstructions.RepoCollateralLeg(BOND, "1100"),
        250,
        1_735_086_400_000L,
        new BilateralSettlementInstructions.RepoGovernance(1_500, 86_400, false));
  }

  private static void assertWireFixture(
      final InstructionBox box, final String wireName, final String encoded) {
    assert box.payload() instanceof InstructionBox.WirePayload;
    final InstructionBox.WirePayload wire = (InstructionBox.WirePayload) box.payload();
    assert wireName.equals(wire.wireName());
    assert java.util.Arrays.equals(Base64.getDecoder().decode(encoded), wire.payloadBytes());
  }

  private static Properties fixtures() throws Exception {
    Path cursor = Paths.get("").toAbsolutePath();
    while (cursor != null) {
      final Path candidate =
          cursor.resolve("fixtures/norito_rpc/bilateral_settlement_sdk_wire.properties");
      if (Files.isRegularFile(candidate)) {
        final Properties properties = new Properties();
        try (InputStream input = Files.newInputStream(candidate)) {
          properties.load(input);
        }
        return properties;
      }
      cursor = cursor.getParent();
    }
    throw new IllegalStateException("missing shared bilateral settlement wire fixture");
  }

  private static byte[] hex(final String value) {
    final byte[] bytes = new byte[value.length() / 2];
    for (int index = 0; index < bytes.length; index++) {
      bytes[index] = (byte) Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16);
    }
    return bytes;
  }

  private static void expectIllegalArgument(final CheckedRunnable operation) {
    boolean threw = false;
    try {
      operation.run();
    } catch (final IllegalArgumentException expected) {
      threw = true;
    } catch (final Exception unexpected) {
      throw new AssertionError(unexpected);
    }
    assert threw : "expected IllegalArgumentException";
  }

  private interface CheckedRunnable {
    void run() throws Exception;
  }
}
