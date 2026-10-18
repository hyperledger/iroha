package org.hyperledger.iroha.sdk.sorafs;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Tag;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Map;
import org.hyperledger.iroha.sdk.client.JsonNumbers;
import org.hyperledger.iroha.sdk.client.JsonParser;

/** Java callers exercise the canonical Kotlin bridge against the shared native fixtures. */
@Tag("host-native")
public final class SorafsReferenceValidatorsJavaConsumerTest {
  private static final String MAX_SCALED_XOR =
      "6703903964971298549787012499102923063739682910296196688861780721860882015"
          + "036773488400937149083451713845015929093243025426876941405973284973216824"
          + ".503042047";
  private static final long REFERENCE_FIXTURE_GENERATED_AT_UNIX = 1_700_001_234L;
  private static final FixtureBundleProfile[] REFERENCE_BUNDLE_PROFILES = {
    profile(
        "bundle_heterogeneous_positive_validation_outcome_v1.json",
        1_700_000_001L,
        input(
            SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
            "replication_order/order_v1.to"),
        input(SorafsFixtureBundlePayloadKind.PDP_COMMITMENT, "pdp/commitment_v1.to"),
        input(SorafsFixtureBundlePayloadKind.PDP_CHALLENGE, "pdp/challenge_v1.to"),
        input(SorafsFixtureBundlePayloadKind.PDP_PROOF, "pdp/proof_v1.to"),
        input(SorafsFixtureBundlePayloadKind.POR_CHALLENGE, "por/challenge_v1.to"),
        input(SorafsFixtureBundlePayloadKind.POR_PROOF, "por/proof_v1.to"),
        input(SorafsFixtureBundlePayloadKind.POTR_RECEIPT, "potr/receipt_v1.to"),
        input(SorafsFixtureBundlePayloadKind.REPAIR_TASK_RECORD, "repair/task_v1.to"),
        input(
            SorafsFixtureBundlePayloadKind.ORDERBOOK_ORDER_REQUEST,
            "orderbook/order_request_v1.to"),
        input(
            SorafsFixtureBundlePayloadKind.ORDERBOOK_ORDER_CANCEL,
            "orderbook/order_cancel_v1.to"),
        input(
            SorafsFixtureBundlePayloadKind.ORDERBOOK_TRADE_EVENT,
            "orderbook/trade_event_v1.to"),
        input(
            SorafsFixtureBundlePayloadKind.ORDERBOOK_SETTLEMENT_CHANNEL,
            "orderbook/settlement_channel_v1.to"),
        input(
            SorafsFixtureBundlePayloadKind.ORDERBOOK_SETTLEMENT_RECEIPT,
            "orderbook/settlement_receipt_v1.to")),
    profile(
        "bundle_orderbook_bad_signature_negative_validation_outcome_v1.json",
        1_700_000_001L,
        input(
            SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
            "replication_order/order_v1.to"),
        input(SorafsFixtureBundlePayloadKind.POR_CHALLENGE, "por/challenge_v1.to"),
        input(SorafsFixtureBundlePayloadKind.POR_PROOF, "por/proof_v1.to"),
        input(
            SorafsFixtureBundlePayloadKind.ORDERBOOK_ORDER_REQUEST,
            "orderbook/negative/order_request_bad_signature_v1.to")),
    profile(
        "bundle_orderbook_trailing_bytes_negative_validation_outcome_v1.json",
        1_700_000_001L,
        input(
            SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
            "replication_order/order_v1.to"),
        input(SorafsFixtureBundlePayloadKind.POR_CHALLENGE, "por/challenge_v1.to"),
        input(SorafsFixtureBundlePayloadKind.POR_PROOF, "por/proof_v1.to"),
        input(
            SorafsFixtureBundlePayloadKind.ORDERBOOK_ORDER_REQUEST,
            "orderbook/negative/order_request_trailing_bytes_v1.to")),
    profile(
        "bundle_pdp_duplicate_hot_leaf_negative_validation_outcome_v1.json",
        1_700_000_001L,
        input(
            SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
            "replication_order/order_v1.to"),
        input(SorafsFixtureBundlePayloadKind.PDP_COMMITMENT, "pdp/commitment_v1.to"),
        input(
            SorafsFixtureBundlePayloadKind.PDP_CHALLENGE,
            "pdp/negative/duplicate_hot_leaf_challenge_v1.to")),
    profile(
        "bundle_pdp_missing_signature_negative_validation_outcome_v1.json",
        1_700_000_001L,
        input(
            SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
            "replication_order/order_v1.to"),
        input(SorafsFixtureBundlePayloadKind.PDP_COMMITMENT, "pdp/commitment_v1.to"),
        input(SorafsFixtureBundlePayloadKind.PDP_CHALLENGE, "pdp/challenge_v1.to"),
        input(
            SorafsFixtureBundlePayloadKind.PDP_PROOF,
            "pdp/negative/missing_signature_proof_v1.to")),
    profile(
        "bundle_pdp_wrong_provider_negative_validation_outcome_v1.json",
        1_700_000_001L,
        input(
            SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
            "replication_order/order_v1.to"),
        input(SorafsFixtureBundlePayloadKind.PDP_COMMITMENT, "pdp/commitment_v1.to"),
        input(SorafsFixtureBundlePayloadKind.PDP_CHALLENGE, "pdp/challenge_v1.to"),
        input(
            SorafsFixtureBundlePayloadKind.PDP_PROOF,
            "pdp/negative/wrong_provider_proof_v1.to")),
    profile(
        "bundle_repair_manifest_mismatch_negative_validation_outcome_v1.json",
        1_700_000_001L,
        // The outcome names only the offender; the order establishes the expected digest.
        input(
            SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
            "replication_order/order_v1.to"),
        input(
            SorafsFixtureBundlePayloadKind.REPAIR_TASK_RECORD,
            "repair/negative/task_manifest_mismatch_v1.to")),
    profile(
        "bundle_repair_provider_unassigned_negative_validation_outcome_v1.json",
        1_700_000_001L,
        input(
            SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
            "replication_order/order_v1.to"),
        input(
            SorafsFixtureBundlePayloadKind.REPAIR_TASK_RECORD,
            "repair/negative/task_provider_unassigned_v1.to")),
    profile(
        "bundle_routing_admission_positive_validation_outcome_v1.json",
        300L,
        input(
            SorafsFixtureBundlePayloadKind.PROVIDER_ADVERT,
            "provider_admission/advert_v1.to"),
        input(
            SorafsFixtureBundlePayloadKind.PROVIDER_ADMISSION_ENVELOPE,
            "provider_admission/envelope_v1.to"))
  };


  private static final class FixtureBundleInputSpec {
    private final SorafsFixtureBundlePayloadKind kind;
    private final String path;

    private FixtureBundleInputSpec(
        final SorafsFixtureBundlePayloadKind kind, final String path) {
      this.kind = kind;
      this.path = path;
    }
  }

  private static final class FixtureBundleProfile {
    private final String outcomePath;
    private final long nowUnix;
    private final FixtureBundleInputSpec[] inputs;

    private FixtureBundleProfile(
        final String outcomePath,
        final long nowUnix,
        final FixtureBundleInputSpec[] inputs) {
      this.outcomePath = outcomePath;
      this.nowUnix = nowUnix;
      this.inputs = inputs.clone();
    }
  }



  @Test
  void exposesBridgeSelectors() {
    assertTrue(SorafsOrderbookPayloadKind.ORDER_REQUEST.bridgeCode == 1);
    for (final SorafsOrderbookPayloadKind kind : SorafsOrderbookPayloadKind.values()) {
      assertTrue(kind.bridgeCode != 6);
      assertTrue(!"orderbook-runtime-snapshot.to".equals(kind.defaultLabel));
    }
    assertTrue(SorafsOrderbookPayloadKind.ORDER_REQUEST.isUserSignedPayload);
    assertTrue(!SorafsOrderbookPayloadKind.TRADE_EVENT.isUserSignedPayload);
    assertTrue(SorafsPdpPayloadKind.COMMITMENT.bridgeCode == 1);
    assertTrue(SorafsPdpPayloadKind.PROOF.bridgeCode == 3);
    final String[] fixtureLabels = {
      "provider-advert.to",
      "provider-admission-envelope.to",
      "replication-order.to",
      "por-challenge.to",
      "por-proof.to",
      "potr-receipt.to",
      "repair-evidence.to",
      "repair-report.to",
      "repair-task-record.to",
      "repair-slash-proposal.to",
      "repair-task-event.to",
      "orderbook-order-request.to",
      "orderbook-order-cancel.to",
      "orderbook-trade-event.to",
      "orderbook-settlement-channel.to",
      "orderbook-settlement-receipt.to",
      "pdp-commitment.to",
      "pdp-challenge.to",
      "pdp-proof.to",
    };
    final SorafsFixtureBundlePayloadKind[] fixtureKinds =
        SorafsFixtureBundlePayloadKind.values();
    assertTrue(fixtureKinds.length == fixtureLabels.length);
    for (int index = 0; index < fixtureKinds.length; index++) {
      assertTrue(fixtureKinds[index].bridgeCode == index + 1);
      assertTrue(fixtureKinds[index].defaultLabel.equals(fixtureLabels[index]));
    }
    assertTrue(SorafsPopPayloadKind.CREDENTIAL.bridgeCode == 1);
    assertTrue(SorafsPopPayloadKind.MEMBERSHIP_PROOF.bridgeCode == 6);
    assertTrue(SorafsPopPayloadKind.ISSUED_CREDENTIAL_BUNDLE.bridgeCode == 7);
    assertTrue(SorafsHedgingPayloadKind.PRICE_FEED.bridgeCode == 1);
    assertTrue(SorafsHedgingPayloadKind.BILLING_STATEMENT.bridgeCode == 4);
    assertTrue(SorafsOrderbookSide.BID.bridgeCode == 1);
    assertTrue(SorafsOrderbookTier.ARCHIVE.bridgeCode == 3);
    assertTrue(SorafsOrderbookCancelReason.REPLACED.bridgeCode == 4);
    assertTrue(SorafsReferenceValidators.REQUIRED_BRIDGE_ABI_VERSION == 30);
    // Internal ABI/symbol admission predicates remain covered by SorafsReferenceValidatorsTest.
    assertTrue(SorafsReferenceValidators.ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1 == 256);
    assertTrue(SorafsReferenceValidators.GOVERNANCE_DAG_MAX_BLOCKS_V1 == 64);
    assertTrue(SorafsReferenceValidators.GOVERNANCE_DAG_CID_BYTES_V1 == 32);
    assertTrue(SorafsReferenceValidators.REFERENCE_MAX_INPUT_BYTES_V1 == 67_108_864);
    assertTrue(SorafsReferenceValidators.REFERENCE_MAX_LABEL_BYTES_V1 == 1_024);
    assertTrue(SorafsReferenceValidators.FIXTURE_BUNDLE_MAX_PAYLOADS_V1 == 64);
  }

  @Test
  void fixtureBundleInputSnapshotsPayloadBytes() {
    final byte[] source = {1, 2, 3};
    final SorafsFixtureBundlePayloadInput input =
        new SorafsFixtureBundlePayloadInput(
            SorafsFixtureBundlePayloadKind.POR_PROOF, source, null);
    source[0] = 9;
    final byte[] detached = input.noritoBytes();
    assertTrue(detached[0] == 1);
    detached[0] = 8;
    assertTrue(input.noritoBytes()[0] == 1);
  }

  @Test
  void boundsFixtureBundleBeforeNativeDispatch() {
    boolean emptyThrew = false;
    try {
      SorafsReferenceValidators.validateFixtureBundleJson(
          java.util.Collections.<SorafsFixtureBundlePayloadInput>emptyList(), 1L, 1L);
    } catch (final IllegalArgumentException ex) {
      emptyThrew = ex.getMessage() != null && ex.getMessage().contains("1..64");
    }
    assertTrue(emptyThrew, String.valueOf("empty fixture bundles must be rejected"));

    final SorafsFixtureBundlePayloadInput item =
        new SorafsFixtureBundlePayloadInput(
            SorafsFixtureBundlePayloadKind.POR_PROOF, new byte[] {0}, null);
    final SorafsFixtureBundlePayloadInput[] tooMany =
        new SorafsFixtureBundlePayloadInput[
            SorafsReferenceValidators.FIXTURE_BUNDLE_MAX_PAYLOADS_V1 + 1];
    Arrays.fill(tooMany, item);
    boolean tooManyThrew = false;
    try {
      SorafsReferenceValidators.validateFixtureBundleJson(
          Arrays.asList(tooMany), 1L, 1L);
    } catch (final IllegalArgumentException ex) {
      tooManyThrew = ex.getMessage() != null && ex.getMessage().contains("1..64");
    }
    assertTrue(tooManyThrew, String.valueOf("oversized fixture bundles must be rejected"));
  }

  @Test
  void boundsGovernanceLogNodeCidBeforeNativeDispatch() {
    for (final int invalidLength : new int[] {0, 31, 33}) {
      boolean threw = false;
      try {
        SorafsReferenceValidators.validateGovernanceLogNodeJson(
            new byte[0], null, new byte[invalidLength], 1L);
      } catch (final IllegalArgumentException ex) {
        threw =
            ex.getMessage() != null
                && ex.getMessage().contains("exactly 32 bytes");
      }
      assertTrue(threw, String.valueOf("invalid governance log node CID length must be rejected"));
    }
  }

  @Test
  void rejectsGeneratedAtBeforeNativeDispatch() {
    boolean threw = false;
    try {
      SorafsReferenceValidators.validateOrderbookPayloadJson(
          SorafsOrderbookPayloadKind.ORDER_REQUEST, new byte[0], null, -1L);
    } catch (final IllegalArgumentException ex) {
      threw = ex.getMessage() != null && ex.getMessage().contains("generatedAtUnix");
    }
    assertTrue(threw, String.valueOf("generatedAtUnix should be validated before native dispatch"));
  }

  @Test
  void rejectsBlankLabelBeforeNativeDispatch() {
    boolean threw = false;
    try {
      SorafsReferenceValidators.validateHedgingPayloadJson(
          SorafsHedgingPayloadKind.PRICE_FEED, new byte[0], " ", 1L);
    } catch (final IllegalArgumentException ex) {
      threw = ex.getMessage() != null && ex.getMessage().contains("label");
    }
    assertTrue(threw, String.valueOf("label should be validated before native dispatch"));
  }

  @Test
  void rejectsMalformedUnicodeFixtureLabelBeforeNativeDispatch() {
    boolean threw = false;
    try {
      SorafsReferenceValidators.validateFixtureBundleJson(
          Arrays.asList(
              new SorafsFixtureBundlePayloadInput(
                  SorafsFixtureBundlePayloadKind.POR_PROOF,
                  new byte[] {0},
                  "\uD800")),
          1L,
          1L);
    } catch (final IllegalArgumentException ex) {
      threw = ex.getMessage() != null && ex.getMessage().contains("valid Unicode");
    }
    assertTrue(threw, String.valueOf("ill-formed UTF-16 labels should be rejected before native dispatch"));
  }

  @Test
  void boundsGovernanceDagInputsBeforeNativeDispatch() {
    boolean emptyChainThrew = false;
    try {
      SorafsReferenceValidators.validateGovernanceDagHeadChainJson(
          new byte[0], Arrays.asList(new byte[0][]), null, null, 1L);
    } catch (final IllegalArgumentException ex) {
      emptyChainThrew = ex.getMessage() != null && ex.getMessage().contains("1..64");
    }
    assertTrue(emptyChainThrew, String.valueOf("empty governance DAG chains must be rejected"));

    boolean tooManyBlocksThrew = false;
    try {
      SorafsReferenceValidators.validateGovernanceDagHeadChainJson(
          new byte[0], Arrays.asList(new byte[65][]), null, null, 1L);
    } catch (final IllegalArgumentException ex) {
      tooManyBlocksThrew = ex.getMessage() != null && ex.getMessage().contains("1..64");
    }
    assertTrue(tooManyBlocksThrew, String.valueOf("oversized governance DAG chains must be rejected"));

    boolean mismatchedLabelsThrew = false;
    try {
      SorafsReferenceValidators.validateGovernanceDagHeadChainJson(
          new byte[0], Arrays.asList(new byte[][] {new byte[0]}), null, Arrays.asList(new String[0]), 1L);
    } catch (final IllegalArgumentException ex) {
      mismatchedLabelsThrew =
          ex.getMessage() != null && ex.getMessage().contains("blockLabels");
    }
    assertTrue(mismatchedLabelsThrew, String.valueOf("governance DAG block labels must align with blocks"));

    boolean oversizedLabelThrew = false;
    try {
      SorafsReferenceValidators.validateGovernanceDagBlockJson(
          new byte[0], decimalOnes(1_025), null, 1L);
    } catch (final IllegalArgumentException ex) {
      oversizedLabelThrew = ex.getMessage() != null && ex.getMessage().contains("1024");
    }
    assertTrue(oversizedLabelThrew, String.valueOf("oversized governance DAG labels must be rejected"));

    boolean controlLabelThrew = false;
    try {
      SorafsReferenceValidators.validateGovernanceDagBlockJson(
          new byte[0], "bad\u0001label", null, 1L);
    } catch (final IllegalArgumentException ex) {
      controlLabelThrew =
          ex.getMessage() != null && ex.getMessage().contains("control characters");
    }
    assertTrue(controlLabelThrew, String.valueOf("governance DAG labels with controls must be rejected"));

    for (final int invalidLength : new int[] {0, 31, 33}) {
      boolean invalidExpectedCidThrew = false;
      try {
        SorafsReferenceValidators.validateGovernanceDagBlockJson(
            new byte[0], null, new byte[invalidLength], 1L);
      } catch (final IllegalArgumentException ex) {
        invalidExpectedCidThrew =
            ex.getMessage() != null && ex.getMessage().contains("exactly 32 bytes");
      }
      assertTrue(invalidExpectedCidThrew, String.valueOf("non-canonical expected CID lengths must be rejected"));
    }
  }

  @Test
  void rejectsNonSignableOrderbookPayloadBeforeNativeDispatch() {
    boolean threw = false;
    try {
      SorafsReferenceValidators.signOrderbookPayload(
          SorafsOrderbookPayloadKind.TRADE_EVENT, new byte[0], repeatedKey(0xB7));
    } catch (final IllegalArgumentException ex) {
      threw = ex.getMessage() != null && ex.getMessage().contains("cannot be signed");
    }
    assertTrue(threw, String.valueOf("non-signable payloads should be rejected before native dispatch"));
  }

  @Test
  void rejectsBadSigningKeyBeforeNativeDispatch() {
    boolean threw = false;
    try {
      SorafsReferenceValidators.signOrderbookPayload(
          SorafsOrderbookPayloadKind.ORDER_REQUEST, new byte[0], new byte[32]);
    } catch (final IllegalArgumentException ex) {
      threw = ex.getMessage() != null && ex.getMessage().contains("privateKey");
    }
    assertTrue(threw, String.valueOf("bad signing keys should be rejected before native dispatch"));
  }

  @Test
  void rejectsInvalidOrderIdDerivationInputsBeforeNativeDispatch() {
    boolean emptyOwnerThrew = false;
    try {
      SorafsReferenceValidators.deriveOrderbookOrderId(new byte[0], 7L);
    } catch (final IllegalArgumentException ex) {
      emptyOwnerThrew = ex.getMessage() != null && ex.getMessage().contains("ownerAccount");
    }
    assertTrue(emptyOwnerThrew, String.valueOf("empty owner must be rejected before native dispatch"));

    boolean zeroNonceThrew = false;
    try {
      SorafsReferenceValidators.deriveOrderbookOrderId(new byte[] {1}, 0L);
    } catch (final IllegalArgumentException ex) {
      zeroNonceThrew = ex.getMessage() != null && ex.getMessage().contains("nonce");
    }
    assertTrue(zeroNonceThrew, String.valueOf("zero nonce must be rejected before native dispatch"));
  }

  @Test
  void rejectsOversizedOrderbookOwnerAccountsBeforeNativeDispatch() {
    final byte[] oversized =
        new byte[SorafsReferenceValidators.ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1 + 1];
    java.util.Arrays.fill(oversized, (byte) 0x45);

    boolean deriveThrew = false;
    try {
      SorafsReferenceValidators.deriveOrderbookOrderId(oversized, 7L);
    } catch (final IllegalArgumentException ex) {
      deriveThrew = ex.getMessage() != null && ex.getMessage().contains("at most 256 bytes");
    }
    assertTrue(deriveThrew, String.valueOf("oversized derivation owner must be rejected before native dispatch"));

    boolean requestThrew = false;
    try {
      SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
          SorafsOrderbookSide.BID,
          SorafsOrderbookTier.HOT,
          "1",
          1L,
          oversized,
          new byte[0],
          1L,
          7L,
          0,
          0,
          repeatedKey(0xB7));
    } catch (final IllegalArgumentException ex) {
      requestThrew = ex.getMessage() != null && ex.getMessage().contains("at most 256 bytes");
    }
    assertTrue(requestThrew, String.valueOf("oversized request owner must be rejected before native dispatch"));

    boolean cancelThrew = false;
    try {
      SorafsReferenceValidators.buildSignedOrderbookOrderCancel(
          repeated(0x11),
          oversized,
          SorafsOrderbookCancelReason.OWNER_REQUESTED,
          8L,
          repeatedKey(0xB7));
    } catch (final IllegalArgumentException ex) {
      cancelThrew = ex.getMessage() != null && ex.getMessage().contains("at most 256 bytes");
    }
    assertTrue(cancelThrew, String.valueOf("oversized cancel owner must be rejected before native dispatch"));
  }

  @Test
  void rejectsOrderbookOrderRequestFieldsBeforeNativeDispatch() {
    boolean threw = false;
    try {
      SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
          new byte[31],
          SorafsOrderbookSide.BID,
          SorafsOrderbookTier.HOT,
          "42",
          7L,
          new byte[] {1},
          new byte[0],
          123L,
          1L,
          0,
          25,
          repeatedKey(0xB7));
    } catch (final IllegalArgumentException ex) {
      threw = ex.getMessage() != null && ex.getMessage().contains("orderId");
    }
    assertTrue(threw, String.valueOf("order request fields should be validated before native dispatch"));
  }

  @Test
  void rejectsOrderbookSettlementReceiptFieldsBeforeNativeDispatch() {
    boolean threw = false;
    try {
      SorafsReferenceValidators.buildSignedOrderbookSettlementReceipt(
          repeated(0x21),
          repeated(0x22),
          repeated(0x23),
          0L,
          64L,
          repeated(0x24),
          64L,
          "not-a-decimal",
          "10",
          "1",
          123L,
          repeatedKey(0xB7));
    } catch (final IllegalArgumentException ex) {
      threw = ex.getMessage() != null && ex.getMessage().contains("xorDebited");
    }
    assertTrue(threw, String.valueOf("settlement receipt fields should be validated before native dispatch"));
  }

  @Test
  void rejectsNoncanonicalXorQuantitiesBeforeNativeDispatch() {
    assertTrue(MAX_SCALED_XOR.length() == 155);
    for (final String value : Arrays.asList(new String[] {"1.0", "0.0000000001", decimalOnes(156)})) {
      boolean threw = false;
      try {
        SorafsReferenceValidators.buildSignedOrderbookSettlementReceipt(
            repeated(0x21),
            repeated(0x22),
            repeated(0x23),
            0L,
            64L,
            repeated(0x24),
            64L,
            value,
            "0",
            "0",
            123L,
            repeatedKey(0xB7));
      } catch (final IllegalArgumentException ex) {
        threw = ex.getMessage() != null && ex.getMessage().contains("xorDebited");
      }
      assertTrue(threw, String.valueOf("noncanonical XOR quantity should be rejected before native dispatch"));
    }
  }

  @Test
  void popMembershipStructuralFixturesRequirePresentationBinding() throws IOException {
    requireNativeBridge();
    // These are native structural checks, not cryptographic recipient authorization.
    final String[][] profiles = {
      {"pop_membership_current_v1", "Ok", "SFS-OK-000"},
      {"pop_membership_missing_binding_v1", "Error", "SFS-NORITO-001"},
      {"pop_membership_zero_binding_v1", "Error", "SFS-VAL-001"},
    };
    for (final String[] profile : profiles) {
      final String name = profile[0];
      final String outcome = SorafsReferenceValidators.validatePopPayloadJson(
          SorafsPopPayloadKind.MEMBERSHIP_PROOF,
          fixture("sorafs_manifest", "reference_sdk", name + ".to"),
          name + ".to",
          123L);
      final Map<?, ?> fields = (Map<?, ?>) JsonParser.parse(outcome);
      assertTrue(profile[1].equals(fields.get("status")), name);
      assertTrue(profile[2].equals(fields.get("code")), name);
      assertTrue(fixtureText(
              "sorafs_manifest", "reference_sdk", name + "_validation_outcome.json")
          .equals(outcome), name);
    }
  }

  @Test
  void validatesOrderbookFixtureWhenNativeBridgeIsAvailable() throws IOException {
    requireNativeBridge();
    final byte[] payload =
        fixture("sorafs_manifest", "orderbook", "order_request_v1.to");
    final String json =
        SorafsReferenceValidators.validateOrderbookPayloadJson(
            SorafsOrderbookPayloadKind.ORDER_REQUEST,
            payload,
            "order_request_v1.to",
            123L);
    assertTrue(fixtureText(
            "sorafs_manifest",
            "orderbook",
            "order_request_validation_outcome_v1.json")
        .equals(json), String.valueOf(json));

    for (final String name :
        Arrays.asList(new String[] {"order_request_bad_signature", "order_request_trailing_bytes"})) {
      final String outcome =
          SorafsReferenceValidators.validateOrderbookPayloadJson(
              SorafsOrderbookPayloadKind.ORDER_REQUEST,
              fixture(
                  "sorafs_manifest",
                  "orderbook",
                  "negative",
                  name + "_v1.to"),
              name + "_v1.to",
              123L);
      assertTrue(fixtureText(
              "sorafs_manifest",
              "orderbook",
              "negative",
              name + "_validation_outcome_v1.json")
          .equals(outcome), String.valueOf(name + ": " + outcome));
    }
  }

  @Test
  void validatesEveryPdpOutcomeFixtureWhenNativeBridgeIsAvailable()
      throws IOException {
    requireNativeBridge();
    final byte[] commitment =
        fixture("sorafs_manifest", "pdp", "commitment_v1.to");
    final byte[] challenge =
        fixture("sorafs_manifest", "pdp", "challenge_v1.to");
    final byte[] proof =
        fixture("sorafs_manifest", "pdp", "proof_v1.to");
    final String bundle =
        SorafsReferenceValidators.validatePdpBundleJson(
            commitment,
            challenge,
            proof,
            "commitment_v1.to",
            "challenge_v1.to",
            "proof_v1.to",
            123L);
    assertTrue(fixtureText(
            "sorafs_manifest",
            "pdp",
            "bundle_validation_outcome_v1.json")
        .equals(bundle), String.valueOf(bundle));

    final String[] singleNames = {
      "duplicate_hot_leaf_challenge", "missing_signature_proof"
    };
    final SorafsPdpPayloadKind[] singleKinds = {
      SorafsPdpPayloadKind.CHALLENGE, SorafsPdpPayloadKind.PROOF
    };
    for (int index = 0; index < singleNames.length; index++) {
      final String name = singleNames[index];
      final String outcome =
          SorafsReferenceValidators.validatePdpPayloadJson(
              singleKinds[index],
              fixture("sorafs_manifest", "pdp", "negative", name + "_v1.to"),
              name + "_v1.to",
              123L);
      assertPdpOutcome(name, outcome);
    }

    for (final String name :
        Arrays.asList(new String[] {"late_proof", "wrong_manifest_proof", "wrong_provider_proof"})) {
      final String outcome =
          SorafsReferenceValidators.validatePdpChallengeProofJson(
              challenge,
              fixture("sorafs_manifest", "pdp", "negative", name + "_v1.to"),
              "challenge_v1.to",
              name + "_v1.to",
              123L);
      assertPdpOutcome(name, outcome);
    }

    for (final String name :
        Arrays.asList(new String[] {
          "missing_hot_leaf_path_proof",
          "missing_segment_path_proof",
          "wrong_path_proof"
        })) {
      final String outcome =
          SorafsReferenceValidators.validatePdpBundleJson(
              commitment,
              challenge,
              fixture("sorafs_manifest", "pdp", "negative", name + "_v1.to"),
              "commitment_v1.to",
              "challenge_v1.to",
              name + "_v1.to",
              123L);
      assertPdpOutcome(name, outcome);
    }
  }

  @SuppressWarnings("unchecked")
  @Test
  void validatesAppealFinanceCancelAssetLockProfiles() throws IOException {
    requireNativeBridge();
    final String[][] profiles = {
      {"cancel_asset_lock_v1.to", "Ok", "SFS-OK-000", "validation"},
      {
        "negative/cancel_asset_lock_legacy_missing_expected_v1.to",
        "Error",
        "SFS-NORITO-001",
        "norito"
      },
      {
        "negative/cancel_asset_lock_zero_expected_v1.to",
        "Error",
        "SFS-VAL-001",
        "validation"
      },
    };
    for (final String[] profile : profiles) {
      final String path = profile[0];
      final String label = path.substring(path.lastIndexOf('/') + 1);
      final String outcome =
          SorafsReferenceValidators.validateAppealFinanceCancelAssetLockJson(
              sorafsFixture("appeal_finance/" + path),
              label,
              123L);
      final Map<String, Object> fields = (Map<String, Object>) JsonParser.parse(outcome);
      assertTrue(profile[1].equals(fields.get("status")), String.valueOf(path + ": " + outcome));
      assertTrue(profile[2].equals(fields.get("code")), String.valueOf(path + ": " + outcome));
      assertTrue(profile[3].equals(fields.get("category")), String.valueOf(path + ": " + outcome));
      assertTrue(JsonNumbers.INSTANCE.asLong(fields.get("version"), "version") == 1L, String.valueOf(path + ": " + outcome));
      assertTrue(JsonNumbers.INSTANCE.asLong(fields.get("generated_at"), "generated_at") == 123L, String.valueOf(path + ": " + outcome));
      assertTrue(outcome.contains("\"sorafs.reference.appeal_finance\""), String.valueOf(path + ": " + outcome));
    }

    final String[][] exactProfiles = {
      {
        "cancel_asset_lock_v1.to",
        "appeal_finance_cancel_asset_lock_positive_validation_outcome_v1.json"
      },
      {
        "negative/cancel_asset_lock_zero_expected_v1.to",
        "appeal_finance_cancel_asset_lock_zero_expected_negative_validation_outcome_v1.json"
      },
    };
    for (final String[] profile : exactProfiles) {
      final String path = profile[0];
      final String label = path.substring(path.lastIndexOf('/') + 1);
      final String outcome =
          SorafsReferenceValidators.validateAppealFinanceCancelAssetLockJson(
              sorafsFixture("appeal_finance/" + path),
              label,
              123L);
      assertTrue(new String(
                  fixture("sorafs_manifest", "reference_sdk", profile[1]),
                  StandardCharsets.UTF_8)
              .equals(outcome), String.valueOf(path + ": " + outcome));
    }
  }

  @SuppressWarnings("unchecked")
  @Test
  void validatesLinkedFixtureBundleWhenNativeBridgeIsAvailable()
      throws IOException {
    requireNativeBridge();
    final String outcome =
        SorafsReferenceValidators.validateFixtureBundleJson(
            Arrays.asList(
                new SorafsFixtureBundlePayloadInput(
                    SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
                    fixture("sorafs_manifest", "replication_order", "order_v1.to"),
                    "replication-order.to"),
                new SorafsFixtureBundlePayloadInput(
                    SorafsFixtureBundlePayloadKind.POR_PROOF,
                    fixture("sorafs_manifest", "por", "proof_v1.to"),
                    "por-proof.to")),
            1_700_000_001L,
            1_700_001_238L);
    final Map<String, Object> fields = (Map<String, Object>) JsonParser.parse(outcome);
    assertTrue("Ok".equals(fields.get("status")), String.valueOf(outcome));
    assertTrue("SFS-OK-000".equals(fields.get("code")), String.valueOf(outcome));
    assertTrue(JsonNumbers.INSTANCE.asLong(fields.get("generated_at"), "generated_at") == 1_700_001_238L, String.valueOf(outcome));
  }

  @Test
  void validatesEveryReferenceSdkBundleOutcomeByteForByte()
      throws IOException {
    requireNativeBridge();
    assertTrue(REFERENCE_BUNDLE_PROFILES.length == 9);
    String previousOutcomePath = null;
    for (final FixtureBundleProfile profile : REFERENCE_BUNDLE_PROFILES) {
      if (previousOutcomePath != null) {
        assertTrue(previousOutcomePath.compareTo(profile.outcomePath) < 0, String.valueOf("reference SDK bundle profile table must remain sorted"));
      }
      previousOutcomePath = profile.outcomePath;

      final SorafsFixtureBundlePayloadInput[] payloads =
          new SorafsFixtureBundlePayloadInput[profile.inputs.length];
      for (int index = 0; index < profile.inputs.length; index++) {
        final FixtureBundleInputSpec input = profile.inputs[index];
        payloads[index] =
            new SorafsFixtureBundlePayloadInput(
                input.kind, sorafsFixture(input.path), input.path);
      }
      final String actual =
          SorafsReferenceValidators.validateFixtureBundleJson(
              Arrays.asList(payloads),
              profile.nowUnix,
              REFERENCE_FIXTURE_GENERATED_AT_UNIX);
      final byte[] expected =
          fixture(
              "sorafs_manifest",
              "reference_sdk",
              profile.outcomePath);
      assertTrue(Arrays.equals(expected, actual.getBytes(StandardCharsets.UTF_8)), String.valueOf(profile.outcomePath + ": " + actual));
    }
  }

  @Test
  void validatesModerationGovernanceLogNodeOutcomeByteForByte()
      throws IOException {
    requireNativeBridge();
    final String actual =
        SorafsReferenceValidators.validateGovernanceLogNodeJson(
            fixture("sorafs_manifest", "moderation", "governance_node_v1.to"),
            "moderation/governance_node_v1.to",
            decodeHex(
                "4dd7d8901fd8fdd78ce9edd0456fa1dc"
                    + "6bb072709ddc762e43116013c15ff20c"),
            REFERENCE_FIXTURE_GENERATED_AT_UNIX);
    assertTrue(Arrays.equals(
            fixture(
                "sorafs_manifest",
                "moderation",
                "governance_node_validation_outcome_v1.json"),
            actual.getBytes(StandardCharsets.UTF_8)), String.valueOf(actual));
  }

  @Test
  void validatesGovernanceDagFixturesAndNegativeVectorsWhenNativeBridgeIsAvailable()
      throws IOException {
    requireNativeBridge();
    final byte[] first =
        fixture("sorafs_manifest", "governance", "dag_block_0_v1.to");
    final byte[] second =
        fixture("sorafs_manifest", "governance", "dag_block_1_v1.to");
    final byte[] head =
        fixture("sorafs_manifest", "governance", "dag_head_v1.to");

    final String blockOutcome =
        SorafsReferenceValidators.validateGovernanceDagBlockJson(
            first, "dag_block_0_v1.to", null, 123L);
    assertTrue(new String(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_block_validation_outcome_v1.json"),
            StandardCharsets.UTF_8)
        .equals(blockOutcome), String.valueOf(blockOutcome));

    final byte[] wrongCid = new byte[32];
    java.util.Arrays.fill(wrongCid, (byte) 0x7F);
    final String cidMismatch =
        SorafsReferenceValidators.validateGovernanceDagBlockJson(
            first, null, wrongCid, 123L);
    assertTrue(new String(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_block_cid_mismatch_validation_outcome_v1.json"),
            StandardCharsets.UTF_8)
        .equals(cidMismatch), String.valueOf(cidMismatch));

    final String headOutcome =
        SorafsReferenceValidators.validateGovernanceDagHeadChainJson(
            head,
            Arrays.asList(new byte[][] {first, second}),
            "dag_head_v1.to",
            Arrays.asList(new String[] {"dag_block_0_v1.to", "dag_block_1_v1.to"}),
            123L);
    final String goldenOutcome =
        new String(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_head_validation_outcome_v1.json"),
            StandardCharsets.UTF_8);
    assertTrue(goldenOutcome.equals(headOutcome), String.valueOf(headOutcome));

    final String reordered =
        SorafsReferenceValidators.validateGovernanceDagHeadChainJson(
            head, Arrays.asList(new byte[][] {second, first}), null, null, 123L);
    assertTrue(new String(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_head_reordered_validation_outcome_v1.json"),
            StandardCharsets.UTF_8)
        .equals(reordered), String.valueOf(reordered));

    final String blockSignatureOutcome =
        SorafsReferenceValidators.validateGovernanceDagBlockJson(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_block_bad_signature_v1.to"),
            "dag_block_bad_signature_v1.to",
            null,
            123L);
    assertTrue(new String(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_block_bad_signature_validation_outcome_v1.json"),
            StandardCharsets.UTF_8)
        .equals(blockSignatureOutcome), String.valueOf(blockSignatureOutcome));

    final String trailingBytesOutcome =
        SorafsReferenceValidators.validateGovernanceDagBlockJson(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_block_trailing_bytes_v1.to"),
            "dag_block_trailing_bytes_v1.to",
            null,
            123L);
    assertTrue(new String(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_block_trailing_bytes_validation_outcome_v1.json"),
            StandardCharsets.UTF_8)
        .equals(trailingBytesOutcome), String.valueOf(trailingBytesOutcome));

    final String headSignatureOutcome =
        SorafsReferenceValidators.validateGovernanceDagHeadChainJson(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_head_bad_signature_v1.to"),
            Arrays.asList(new byte[][] {first, second}),
            "dag_head_bad_signature_v1.to",
            Arrays.asList(new String[] {"dag_block_0_v1.to", "dag_block_1_v1.to"}),
            123L);
    assertTrue(new String(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_head_bad_signature_validation_outcome_v1.json"),
            StandardCharsets.UTF_8)
        .equals(headSignatureOutcome), String.valueOf(headSignatureOutcome));

    final String predecessorOutcome =
        SorafsReferenceValidators.validateGovernanceDagHeadChainJson(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_head_bad_predecessor_v1.to"),
            Arrays.asList(new byte[][] {
              first,
              fixture(
                  "sorafs_manifest",
                  "governance",
                  "dag_block_1_bad_predecessor_v1.to")
            }),
            "dag_head_bad_predecessor_v1.to",
            Arrays.asList(new String[] {
              "dag_block_0_v1.to",
              "dag_block_1_bad_predecessor_v1.to"
            }),
            123L);
    assertTrue(new String(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_head_bad_predecessor_validation_outcome_v1.json"),
            StandardCharsets.UTF_8)
        .equals(predecessorOutcome), String.valueOf(predecessorOutcome));
  }

  private static void requireNativeBridge() {
    if (!SorafsReferenceValidators.isNativeAvailable()) {
      throw new AssertionError(
          "ABI-30 connect_norito_bridge with all SoraFS reference symbols is required.");
    }
  }

  @SuppressWarnings("unchecked")
  @Test
  void signsOrderbookFixtureWhenNativeBridgeIsAvailable() throws IOException {
    requireNativeBridge();
    final byte[] payload =
        fixture("sorafs_manifest", "orderbook", "order_request_v1.to");
    final byte[] signed =
        SorafsReferenceValidators.signOrderbookPayload(
            SorafsOrderbookPayloadKind.ORDER_REQUEST, payload, repeatedKey(0xB8));
    assertTrue(signed.length > 0, String.valueOf("signed payload should be returned"));
    assertTrue(!java.util.Arrays.equals(signed, payload), String.valueOf("signature should change encoded payload"));
    final String outcome =
        SorafsReferenceValidators.validateOrderbookPayloadJson(
            SorafsOrderbookPayloadKind.ORDER_REQUEST,
            signed,
            "order_request_resigned_v1.to",
            123L);
    final Map<String, Object> fields = (Map<String, Object>) JsonParser.parse(outcome);
    assertTrue("Ok".equals(fields.get("status")), String.valueOf(outcome));
    assertTrue("SFS-OK-000".equals(fields.get("code")), String.valueOf(outcome));
  }

  @Test
  void derivesCanonicalOrderIdWhenNativeBridgeIsAvailable() {
    requireNativeBridge();
    final byte[] owner = "buyer@sora".getBytes(StandardCharsets.UTF_8);
    final byte[] orderId = SorafsReferenceValidators.deriveOrderbookOrderId(owner, 7L);
    assertTrue("9d91ad7700ca0c4762e031f9231aa38dd4502c6048c6ffa31d365e3c4e080b69"
        .equals(toHex(orderId)));
    assertTrue(!java.util.Arrays.equals(
        orderId, SorafsReferenceValidators.deriveOrderbookOrderId(owner, 8L)));
    assertTrue(!java.util.Arrays.equals(
        orderId,
        SorafsReferenceValidators.deriveOrderbookOrderId(
            "provider@sora".getBytes(StandardCharsets.UTF_8), 7L)));

    final byte[] maximumOwner =
        new byte[SorafsReferenceValidators.ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1];
    java.util.Arrays.fill(maximumOwner, (byte) 0x45);
    final byte[] maximumOwnerOrderId =
        SorafsReferenceValidators.deriveOrderbookOrderId(maximumOwner, 9L);
    final byte[] maximumOwnerOrder =
        SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
            SorafsOrderbookSide.BID,
            SorafsOrderbookTier.HOT,
            "1",
            1L,
            maximumOwner,
            new byte[0],
            1_800_000_000L,
            9L,
            0,
            0,
            repeatedKey(0xB7));
    final String maximumOwnerOrderOutcome =
        SorafsReferenceValidators.validateOrderbookPayloadJson(
            SorafsOrderbookPayloadKind.ORDER_REQUEST, maximumOwnerOrder, null, 123L);
    assertTrue(maximumOwnerOrderOutcome.contains("\"status\": \"Ok\""), String.valueOf(maximumOwnerOrderOutcome));
    final byte[] maximumOwnerCancel =
        SorafsReferenceValidators.buildSignedOrderbookOrderCancel(
            maximumOwnerOrderId,
            maximumOwner,
            SorafsOrderbookCancelReason.OWNER_REQUESTED,
            10L,
            repeatedKey(0xB7));
    final String maximumOwnerCancelOutcome =
        SorafsReferenceValidators.validateOrderbookPayloadJson(
            SorafsOrderbookPayloadKind.ORDER_CANCEL, maximumOwnerCancel, null, 123L);
    assertTrue(maximumOwnerCancelOutcome.contains("\"status\": \"Ok\""), String.valueOf(maximumOwnerCancelOutcome));

    final byte[] signed =
        SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
            SorafsOrderbookSide.BID,
            SorafsOrderbookTier.HOT,
            MAX_SCALED_XOR,
            64L,
            owner,
            new byte[0],
            1_800_000_000L,
            7L,
            10,
            15,
            repeatedKey(0xB7));
    final String outcome =
        SorafsReferenceValidators.validateOrderbookPayloadJson(
            SorafsOrderbookPayloadKind.ORDER_REQUEST, signed, null, 123L);
    assertTrue(outcome.contains("\"status\": \"Ok\""), String.valueOf(outcome));

    final byte[] ask =
        SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
            SorafsOrderbookSide.ASK,
            SorafsOrderbookTier.HOT,
            "1.25",
            4L,
            owner,
            repeated(0x72),
            1_800_000_000L,
            8L,
            10,
            15,
            repeatedKey(0xB7));
    final String askOutcome =
        SorafsReferenceValidators.validateOrderbookPayloadJson(
            SorafsOrderbookPayloadKind.ORDER_REQUEST, ask, null, 123L);
    assertTrue(askOutcome.contains("\"status\": \"Ok\""), String.valueOf(askOutcome));

    boolean bidProviderThrew = false;
    try {
      SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
          SorafsOrderbookSide.BID,
          SorafsOrderbookTier.HOT,
          "1",
          1L,
          owner,
          repeated(0x72),
          1_800_000_000L,
          17L,
          0,
          0,
          repeatedKey(0xB7));
    } catch (final IllegalArgumentException error) {
      bidProviderThrew =
          error.getMessage() != null && error.getMessage().contains("absent or empty");
    }
    assertTrue(bidProviderThrew, String.valueOf("bid provider binding must be rejected"));

    boolean askProviderThrew = false;
    try {
      SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
          SorafsOrderbookSide.ASK,
          SorafsOrderbookTier.HOT,
          "1",
          1L,
          owner,
          new byte[0],
          1_800_000_000L,
          17L,
          0,
          0,
          repeatedKey(0xB7));
    } catch (final IllegalArgumentException error) {
      askProviderThrew =
          error.getMessage() != null && error.getMessage().contains("providerId");
    }
    assertTrue(askProviderThrew, String.valueOf("ask without exact provider binding must be rejected"));

    boolean threw = false;
    try {
      SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
          repeated(0x11),
          SorafsOrderbookSide.BID,
          SorafsOrderbookTier.HOT,
          "0.000000001",
          64L,
          owner,
          new byte[0],
          1_800_000_000L,
          7L,
          10,
          15,
          repeatedKey(0xB7));
    } catch (final IllegalArgumentException error) {
      threw =
          error.getMessage() != null
              && error.getMessage().contains("canonical owner-and-nonce derivation");
    }
    assertTrue(threw, String.valueOf("noncanonical explicit order id must be rejected"));
  }

  private static byte[] repeatedKey(final int value) {
    return repeated(value);
  }

  private static FixtureBundleInputSpec input(
      final SorafsFixtureBundlePayloadKind kind, final String path) {
    return new FixtureBundleInputSpec(kind, path);
  }

  private static FixtureBundleProfile profile(
      final String outcomePath,
      final long nowUnix,
      final FixtureBundleInputSpec... inputs) {
    return new FixtureBundleProfile(outcomePath, nowUnix, inputs);
  }

  private static byte[] sorafsFixture(final String relativePath) throws IOException {
    return fixture(("sorafs_manifest/" + relativePath).split("/"));
  }

  private static byte[] decodeHex(final String value) {
    if ((value.length() & 1) != 0) {
      throw new IllegalArgumentException("hex value must contain an even number of digits");
    }
    final byte[] output = new byte[value.length() / 2];
    for (int index = 0; index < output.length; index++) {
      final int high = Character.digit(value.charAt(index * 2), 16);
      final int low = Character.digit(value.charAt(index * 2 + 1), 16);
      if (high < 0 || low < 0) {
        throw new IllegalArgumentException("hex value contains a non-hex digit");
      }
      output[index] = (byte) ((high << 4) | low);
    }
    return output;
  }

  private static String decimalOnes(final int length) {
    final char[] digits = new char[length];
    java.util.Arrays.fill(digits, '1');
    return new String(digits);
  }

  private static byte[] repeated(final int value) {
    final byte[] key = new byte[32];
    java.util.Arrays.fill(key, (byte) value);
    return key;
  }

  private static String toHex(final byte[] bytes) {
    final char[] alphabet = "0123456789abcdef".toCharArray();
    final char[] output = new char[bytes.length * 2];
    for (int index = 0; index < bytes.length; index++) {
      final int value = bytes[index] & 0xFF;
      output[index * 2] = alphabet[value >>> 4];
      output[index * 2 + 1] = alphabet[value & 0x0F];
    }
    return new String(output);
  }

  private static void assertPdpOutcome(final String name, final String actual)
      throws IOException {
    final String expected =
        fixtureText(
            "sorafs_manifest",
            "pdp",
            "negative",
            name + "_validation_outcome_v1.json");
    assertTrue(expected.equals(actual), String.valueOf(name + ": " + actual));
  }

  private static String fixtureText(final String... parts) throws IOException {
    return new String(fixture(parts), StandardCharsets.UTF_8);
  }

  private static byte[] fixture(final String... parts) throws IOException {
    Path relative = Paths.get("fixtures");
    for (final String part : parts) {
      relative = relative.resolve(part);
    }
    // The package qualification producer supplies its private, hash-bound
    // snapshot. Missing snapshot files must never fall through to checkout data.
    final String snapshot = System.getProperty("iroha.sorafs.fixtureRoot");
    if (snapshot != null) {
      final Path root = Paths.get(snapshot).toAbsolutePath().normalize();
      final Path candidate = root.resolve(relative).normalize();
      if (!candidate.startsWith(root)) {
        throw new IOException("fixture escapes the captured root");
      }
      return Files.readAllBytes(candidate);
    }
    final Path cwd = Paths.get(System.getProperty("user.dir")).toAbsolutePath();
    final Path[] candidates =
        new Path[] {
          cwd.resolve(relative),
          cwd.resolve("..").resolve(relative),
          cwd.resolve("..").resolve("..").resolve(relative),
          cwd.resolve("..").resolve("..").resolve("..").resolve(relative)
        };
    for (final Path candidate : candidates) {
      final Path normalized = candidate.toAbsolutePath().normalize();
      if (Files.exists(normalized)) {
        return Files.readAllBytes(normalized);
      }
    }
    throw new IOException("missing fixture " + relative);
  }
}
