// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.android.model.instructions;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.hyperledger.iroha.android.address.AccountIdLiteral;
import org.hyperledger.iroha.android.crypto.Blake2b;
import org.hyperledger.iroha.android.model.InstructionBox;
import org.hyperledger.iroha.android.model.JsonValue;
import org.hyperledger.iroha.android.numeric.NumericV1;
import org.hyperledger.iroha.norito.NoritoAdapters;
import org.hyperledger.iroha.norito.NoritoCodec;
import org.hyperledger.iroha.norito.NoritoDecoder;
import org.hyperledger.iroha.norito.NoritoEncoder;
import org.hyperledger.iroha.norito.NoritoHeader;
import org.hyperledger.iroha.norito.TypeAdapter;

/**
 * Typed, first-release constructors for bilateral DvP/PvP and repo instructions.
 *
 * <p>Partial settlement is deliberately not represented: both settlement variants always encode
 * {@code SettlementAtomicity::AllOrNothing}. Every constructor validates the same static economic
 * invariants enforced by core before producing consent-bound canonical Norito bytes.
 */
public final class BilateralSettlementInstructions {
  private static final BigInteger U64_MAX = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

  private BilateralSettlementInstructions() {}

  /** Ordering used for the two legs of an atomic settlement. */
  public enum ExecutionOrder {
    /** Deliver the first asset before applying the reciprocal payment. */
    DELIVERY_THEN_PAYMENT(0L),
    /** Apply the payment leg before delivering the reciprocal asset. */
    PAYMENT_THEN_DELIVERY(1L);

    private final long wireTag;

    ExecutionOrder(final long wireTag) {
      this.wireTag = wireTag;
    }
  }

  /** One exact debit and credit leg in a bilateral settlement. */
  public static final class SettlementLeg {
    private final String assetDefinitionId;
    private final String quantity;
    private final String from;
    private final String to;
    private final Map<String, JsonValue> metadata;

    /** Constructs and validates an exact settlement leg. */
    public SettlementLeg(
        final String assetDefinitionId,
        final String quantity,
        final String from,
        final String to,
        final Map<String, JsonValue> metadata) {
      this.assetDefinitionId =
          requireAssetDefinitionId(assetDefinitionId, "assetDefinitionId");
      this.quantity = requirePositiveQuantity(quantity, "quantity");
      this.from = AccountIdLiteral.requireCanonicalI105Address(from, "from");
      this.to = AccountIdLiteral.requireCanonicalI105Address(to, "to");
      this.metadata = immutableMetadata(metadata);
      if (sameAccount(this.from, this.to)) {
        throw new IllegalArgumentException(
            "settlement leg sender and recipient must be distinct accounts");
      }
    }

    /** Constructs a leg without metadata. */
    public SettlementLeg(
        final String assetDefinitionId,
        final String quantity,
        final String from,
        final String to) {
      this(assetDefinitionId, quantity, from, to, Collections.emptyMap());
    }

    /** Constructs a leg from a lossless validated quantity. */
    public SettlementLeg(
        final String assetDefinitionId,
        final NumericV1.QuantityValue quantity,
        final String from,
        final String to,
        final Map<String, JsonValue> metadata) {
      this(
          assetDefinitionId,
          Objects.requireNonNull(quantity, "quantity").toString(),
          from,
          to,
          metadata);
    }

    /** Constructs a leg from a lossless validated quantity without metadata. */
    public SettlementLeg(
        final String assetDefinitionId,
        final NumericV1.QuantityValue quantity,
        final String from,
        final String to) {
      this(assetDefinitionId, quantity, from, to, Collections.emptyMap());
    }

    public String assetDefinitionId() {
      return assetDefinitionId;
    }

    public String quantity() {
      return quantity;
    }

    public String from() {
      return from;
    }

    public String to() {
      return to;
    }

    public Map<String, JsonValue> metadata() {
      return metadata;
    }
  }

  /** Atomic delivery-versus-payment instruction. */
  public static final class Dvp implements InstructionTemplate {
    private final String settlementId;
    private final SettlementLeg deliveryLeg;
    private final SettlementLeg paymentLeg;
    private final ExecutionOrder order;
    private final Map<String, JsonValue> metadata;
    private final Map<String, String> arguments;

    /** Constructs an exact all-or-nothing DvP instruction. */
    public Dvp(
        final String settlementId,
        final SettlementLeg deliveryLeg,
        final SettlementLeg paymentLeg,
        final ExecutionOrder order,
        final Map<String, JsonValue> metadata) {
      this.settlementId = requireName(settlementId, "settlementId");
      this.deliveryLeg = Objects.requireNonNull(deliveryLeg, "deliveryLeg");
      this.paymentLeg = Objects.requireNonNull(paymentLeg, "paymentLeg");
      this.order = Objects.requireNonNull(order, "order");
      this.metadata = immutableMetadata(metadata);
      requireReciprocalLegs(deliveryLeg, paymentLeg, "DvP");
      final LinkedHashMap<String, String> args = new LinkedHashMap<>();
      args.put("settlement_id", this.settlementId);
      args.put("delivery_asset_definition_id", deliveryLeg.assetDefinitionId());
      args.put("payment_asset_definition_id", paymentLeg.assetDefinitionId());
      args.put("order", order.name());
      args.put("atomicity", "ALL_OR_NOTHING");
      this.arguments = Collections.unmodifiableMap(args);
    }

    /** Constructs a DvP instruction with empty metadata. */
    public Dvp(
        final String settlementId,
        final SettlementLeg deliveryLeg,
        final SettlementLeg paymentLeg,
        final ExecutionOrder order) {
      this(settlementId, deliveryLeg, paymentLeg, order, Collections.emptyMap());
    }

    /** Constructs a DvP instruction with delivery-first ordering and empty metadata. */
    public Dvp(
        final String settlementId,
        final SettlementLeg deliveryLeg,
        final SettlementLeg paymentLeg) {
      this(
          settlementId,
          deliveryLeg,
          paymentLeg,
          ExecutionOrder.DELIVERY_THEN_PAYMENT,
          Collections.emptyMap());
    }

    public String settlementId() {
      return settlementId;
    }

    public SettlementLeg deliveryLeg() {
      return deliveryLeg;
    }

    public SettlementLeg paymentLeg() {
      return paymentLeg;
    }

    public ExecutionOrder order() {
      return order;
    }

    public Map<String, JsonValue> metadata() {
      return metadata;
    }

    @Override
    public InstructionKind kind() {
      return InstructionKind.CUSTOM;
    }

    @Override
    public Map<String, String> toArguments() {
      return arguments;
    }

    @Override
    public InstructionBox toInstructionBox() {
      return Wire.encodeDvp(this);
    }

    /** Returns the bare canonical {@code DvpIsi} bytes covered by counterparty consent. */
    public byte[] canonicalInstructionBytes() {
      return Wire.encodeDvpConcrete(this);
    }

    /** Returns the marked Blake2b-256 exact-intent hash required by CanExecuteSettlement. */
    public byte[] intentHash() {
      return Wire.dvpIntentHash(this);
    }
  }

  /** Atomic payment-versus-payment instruction. */
  public static final class Pvp implements InstructionTemplate {
    private final String settlementId;
    private final SettlementLeg primaryLeg;
    private final SettlementLeg counterLeg;
    private final ExecutionOrder order;
    private final Map<String, JsonValue> metadata;
    private final Map<String, String> arguments;

    /** Constructs an exact all-or-nothing PvP instruction. */
    public Pvp(
        final String settlementId,
        final SettlementLeg primaryLeg,
        final SettlementLeg counterLeg,
        final ExecutionOrder order,
        final Map<String, JsonValue> metadata) {
      this.settlementId = requireName(settlementId, "settlementId");
      this.primaryLeg = Objects.requireNonNull(primaryLeg, "primaryLeg");
      this.counterLeg = Objects.requireNonNull(counterLeg, "counterLeg");
      this.order = Objects.requireNonNull(order, "order");
      this.metadata = immutableMetadata(metadata);
      requireReciprocalLegs(primaryLeg, counterLeg, "PvP");
      final LinkedHashMap<String, String> args = new LinkedHashMap<>();
      args.put("settlement_id", this.settlementId);
      args.put("primary_asset_definition_id", primaryLeg.assetDefinitionId());
      args.put("counter_asset_definition_id", counterLeg.assetDefinitionId());
      args.put("order", order.name());
      args.put("atomicity", "ALL_OR_NOTHING");
      this.arguments = Collections.unmodifiableMap(args);
    }

    /** Constructs a PvP instruction with empty metadata. */
    public Pvp(
        final String settlementId,
        final SettlementLeg primaryLeg,
        final SettlementLeg counterLeg,
        final ExecutionOrder order) {
      this(settlementId, primaryLeg, counterLeg, order, Collections.emptyMap());
    }

    /** Constructs a PvP instruction with payment-first ordering and empty metadata. */
    public Pvp(
        final String settlementId,
        final SettlementLeg primaryLeg,
        final SettlementLeg counterLeg) {
      this(
          settlementId,
          primaryLeg,
          counterLeg,
          ExecutionOrder.PAYMENT_THEN_DELIVERY,
          Collections.emptyMap());
    }

    public String settlementId() {
      return settlementId;
    }

    public SettlementLeg primaryLeg() {
      return primaryLeg;
    }

    public SettlementLeg counterLeg() {
      return counterLeg;
    }

    public ExecutionOrder order() {
      return order;
    }

    public Map<String, JsonValue> metadata() {
      return metadata;
    }

    @Override
    public InstructionKind kind() {
      return InstructionKind.CUSTOM;
    }

    @Override
    public Map<String, String> toArguments() {
      return arguments;
    }

    @Override
    public InstructionBox toInstructionBox() {
      return Wire.encodePvp(this);
    }

    /** Returns the bare canonical {@code PvpIsi} bytes covered by counterparty consent. */
    public byte[] canonicalInstructionBytes() {
      return Wire.encodePvpConcrete(this);
    }

    /** Returns the marked Blake2b-256 exact-intent hash required by CanExecuteSettlement. */
    public byte[] intentHash() {
      return Wire.pvpIntentHash(this);
    }
  }

  /** Immutable exact cash terms for a repo agreement. */
  public static final class RepoCashLeg {
    private final String assetDefinitionId;
    private final String quantity;

    /** Constructs exact cash terms. */
    public RepoCashLeg(final String assetDefinitionId, final String quantity) {
      this.assetDefinitionId =
          requireAssetDefinitionId(assetDefinitionId, "cashLeg.assetDefinitionId");
      this.quantity = requirePositiveQuantity(quantity, "cashLeg.quantity");
    }

    /** Constructs cash terms from a lossless validated quantity. */
    public RepoCashLeg(
        final String assetDefinitionId, final NumericV1.QuantityValue quantity) {
      this(assetDefinitionId, Objects.requireNonNull(quantity, "quantity").toString());
    }

    public String assetDefinitionId() {
      return assetDefinitionId;
    }

    public String quantity() {
      return quantity;
    }
  }

  /** Immutable exact collateral terms for a repo agreement. */
  public static final class RepoCollateralLeg {
    private final String assetDefinitionId;
    private final String quantity;
    private final Map<String, JsonValue> metadata;

    /** Constructs exact collateral terms. */
    public RepoCollateralLeg(
        final String assetDefinitionId,
        final String quantity,
        final Map<String, JsonValue> metadata) {
      this.assetDefinitionId =
          requireAssetDefinitionId(assetDefinitionId, "collateralLeg.assetDefinitionId");
      this.quantity = requirePositiveQuantity(quantity, "collateralLeg.quantity");
      this.metadata = immutableMetadata(metadata);
    }

    /** Constructs collateral terms without metadata. */
    public RepoCollateralLeg(final String assetDefinitionId, final String quantity) {
      this(assetDefinitionId, quantity, Collections.emptyMap());
    }

    /** Constructs collateral terms from a lossless validated quantity. */
    public RepoCollateralLeg(
        final String assetDefinitionId,
        final NumericV1.QuantityValue quantity,
        final Map<String, JsonValue> metadata) {
      this(
          assetDefinitionId,
          Objects.requireNonNull(quantity, "quantity").toString(),
          metadata);
    }

    /** Constructs collateral terms from a lossless validated quantity without metadata. */
    public RepoCollateralLeg(
        final String assetDefinitionId, final NumericV1.QuantityValue quantity) {
      this(assetDefinitionId, quantity, Collections.emptyMap());
    }

    public String assetDefinitionId() {
      return assetDefinitionId;
    }

    public String quantity() {
      return quantity;
    }

    public Map<String, JsonValue> metadata() {
      return metadata;
    }
  }

  /** Governance terms fixed for the lifetime of a repo agreement. */
  public static final class RepoGovernance {
    private final int haircutBps;
    private final BigInteger marginFrequencySecs;
    private final boolean allowEarlyRepayment;

    /**
     * Constructs exact governance terms over the full unsigned wire range.
     *
     * <p>{@code allowEarlyRepayment} is bound into both consent hashes; when set, only the
     * initiator (cash borrower) may settle before maturity with interest accrued to the committed
     * block time.
     */
    public RepoGovernance(
        final int haircutBps,
        final BigInteger marginFrequencySecs,
        final boolean allowEarlyRepayment) {
      this.haircutBps = requireU16(haircutBps, "haircutBps");
      if (this.haircutBps > 10_000) {
        throw new IllegalArgumentException("haircutBps must not exceed 10000");
      }
      this.marginFrequencySecs = requireU64(marginFrequencySecs, "marginFrequencySecs");
      this.allowEarlyRepayment = allowEarlyRepayment;
    }

    /** Convenience constructor for non-negative signed-long cadence values. */
    public RepoGovernance(
        final int haircutBps, final long marginFrequencySecs, final boolean allowEarlyRepayment) {
      this(
          haircutBps,
          requireNonNegativeLong(marginFrequencySecs, "marginFrequencySecs"),
          allowEarlyRepayment);
    }

    public int haircutBps() {
      return haircutBps;
    }

    public BigInteger marginFrequencySecs() {
      return marginFrequencySecs;
    }

    public boolean allowEarlyRepayment() {
      return allowEarlyRepayment;
    }
  }

  /** Atomic repo-open instruction with complete, consent-bound economic terms. */
  public static final class Repo implements InstructionTemplate {
    private final String agreementId;
    private final String initiator;
    private final String counterparty;
    private final String custodian;
    private final RepoCashLeg cashLeg;
    private final RepoCollateralLeg collateralLeg;
    private final int rateBps;
    private final BigInteger maturityTimestampMs;
    private final RepoGovernance governance;
    private final Map<String, String> arguments;

    /** Constructs exact repo terms over the full unsigned wire range. */
    public Repo(
        final String agreementId,
        final String initiator,
        final String counterparty,
        final String custodian,
        final RepoCashLeg cashLeg,
        final RepoCollateralLeg collateralLeg,
        final int rateBps,
        final BigInteger maturityTimestampMs,
        final RepoGovernance governance) {
      this.agreementId = requireName(agreementId, "agreementId");
      this.initiator =
          AccountIdLiteral.requireCanonicalI105Address(initiator, "initiator");
      this.counterparty =
          AccountIdLiteral.requireCanonicalI105Address(counterparty, "counterparty");
      this.custodian =
          custodian == null
              ? null
              : AccountIdLiteral.requireCanonicalI105Address(custodian, "custodian");
      this.cashLeg = Objects.requireNonNull(cashLeg, "cashLeg");
      this.collateralLeg = Objects.requireNonNull(collateralLeg, "collateralLeg");
      this.rateBps = requireU16(rateBps, "rateBps");
      this.maturityTimestampMs = requireU64(maturityTimestampMs, "maturityTimestampMs");
      if (this.maturityTimestampMs.signum() == 0) {
        throw new IllegalArgumentException("maturityTimestampMs must be positive");
      }
      this.governance = Objects.requireNonNull(governance, "governance");
      if (sameAccount(this.initiator, this.counterparty)) {
        throw new IllegalArgumentException(
            "repo initiator and counterparty must be distinct accounts");
      }
      if (this.custodian != null
          && (sameAccount(this.custodian, this.initiator)
              || sameAccount(this.custodian, this.counterparty))) {
        throw new IllegalArgumentException(
            "repo custodian must be distinct from both counterparties");
      }
      if (cashLeg.assetDefinitionId().equals(collateralLeg.assetDefinitionId())) {
        throw new IllegalArgumentException(
            "repo cash and collateral must use distinct asset definitions");
      }
      final LinkedHashMap<String, String> args = new LinkedHashMap<>();
      args.put("agreement_id", this.agreementId);
      args.put("initiator", this.initiator);
      args.put("counterparty", this.counterparty);
      args.put("custodian", this.custodian == null ? "" : this.custodian);
      args.put("cash_asset_definition_id", cashLeg.assetDefinitionId());
      args.put("collateral_asset_definition_id", collateralLeg.assetDefinitionId());
      args.put("rate_bps", Integer.toString(this.rateBps));
      args.put("maturity_timestamp_ms", this.maturityTimestampMs.toString());
      this.arguments = Collections.unmodifiableMap(args);
    }

    /** Convenience constructor for non-negative signed-long maturity timestamps. */
    public Repo(
        final String agreementId,
        final String initiator,
        final String counterparty,
        final String custodian,
        final RepoCashLeg cashLeg,
        final RepoCollateralLeg collateralLeg,
        final int rateBps,
        final long maturityTimestampMs,
        final RepoGovernance governance) {
      this(
          agreementId,
          initiator,
          counterparty,
          custodian,
          cashLeg,
          collateralLeg,
          rateBps,
          requireNonNegativeLong(maturityTimestampMs, "maturityTimestampMs"),
          governance);
    }

    public String agreementId() {
      return agreementId;
    }

    public String initiator() {
      return initiator;
    }

    public String counterparty() {
      return counterparty;
    }

    public String custodian() {
      return custodian;
    }

    public RepoCashLeg cashLeg() {
      return cashLeg;
    }

    public RepoCollateralLeg collateralLeg() {
      return collateralLeg;
    }

    public int rateBps() {
      return rateBps;
    }

    public BigInteger maturityTimestampMs() {
      return maturityTimestampMs;
    }

    public RepoGovernance governance() {
      return governance;
    }

    @Override
    public InstructionKind kind() {
      return InstructionKind.CUSTOM;
    }

    @Override
    public Map<String, String> toArguments() {
      return arguments;
    }

    @Override
    public InstructionBox toInstructionBox() {
      return Wire.encodeRepo(this);
    }

    /** Returns the bare canonical {@code RepoIsi} bytes covered by both repo consents. */
    public byte[] canonicalInstructionBytes() {
      return Wire.encodeRepoConcrete(this);
    }

    /** Returns the one-shot settlement id used by both repo permission grants. */
    public String settlementId() {
      return agreementId;
    }

    /** Returns the exact hash authorizing the counterparty cash debit at repo initiation. */
    public byte[] initiationIntentHash() {
      return Wire.repoInitiationIntentHash(this);
    }

    /** Returns the exact hash authorizing release of the collateral balance at maturity. */
    public byte[] maturityIntentHash() {
      return Wire.repoMaturityIntentHash(this);
    }
  }

  /** ID-only, fixed-maturity reverse-repo settlement instruction. */
  public static final class ReverseRepo implements InstructionTemplate {
    private final String agreementId;
    private final Map<String, String> arguments;

    /** Constructs a fixed-maturity settlement request for an existing agreement. */
    public ReverseRepo(final String agreementId) {
      this.agreementId = requireName(agreementId, "agreementId");
      this.arguments = Collections.singletonMap("agreement_id", this.agreementId);
    }

    public String agreementId() {
      return agreementId;
    }

    @Override
    public InstructionKind kind() {
      return InstructionKind.CUSTOM;
    }

    @Override
    public Map<String, String> toArguments() {
      return arguments;
    }

    @Override
    public InstructionBox toInstructionBox() {
      return Wire.encodeReverseRepo(this);
    }
  }

  private static void requireReciprocalLegs(
      final SettlementLeg first, final SettlementLeg second, final String label) {
    if (!sameAccount(first.from(), second.to()) || !sameAccount(first.to(), second.from())) {
      throw new IllegalArgumentException(
          label
              + " legs must exchange assets between the same two accounts in opposite directions");
    }
    if (first.assetDefinitionId().equals(second.assetDefinitionId())) {
      throw new IllegalArgumentException(label + " legs must use distinct asset definitions");
    }
  }

  private static boolean sameAccount(final String left, final String right) {
    return Arrays.equals(
        TransferWirePayloadEncoder.encodeAccountIdPayload(left),
        TransferWirePayloadEncoder.encodeAccountIdPayload(right));
  }

  private static String requireAssetDefinitionId(final String value, final String field) {
    try {
      TransferWirePayloadEncoder.encodeAssetDefinitionIdPayload(
          Objects.requireNonNull(value, field));
    } catch (final IllegalArgumentException ex) {
      throw new IllegalArgumentException(
          field + " must be a canonical Base58 AssetDefinitionId", ex);
    }
    return value;
  }

  private static String requirePositiveQuantity(final String value, final String field) {
    final NumericV1.QuantityValue parsed;
    try {
      parsed = NumericV1.QuantityValue.parseCanonical(Objects.requireNonNull(value, field));
    } catch (final IllegalArgumentException ex) {
      throw new IllegalArgumentException(
          field + " must be a canonically spelled V1 quantity", ex);
    }
    if (parsed.mantissa().signum() <= 0) {
      throw new IllegalArgumentException(field + " must be positive");
    }
    return parsed.toString();
  }

  private static Map<String, JsonValue> immutableMetadata(
      final Map<String, JsonValue> value) {
    Objects.requireNonNull(value, "metadata");
    final LinkedHashMap<String, JsonValue> copy = new LinkedHashMap<>();
    for (final Map.Entry<String, JsonValue> entry : value.entrySet()) {
      final String key = requireName(entry.getKey(), "metadata key");
      final JsonValue json = Objects.requireNonNull(entry.getValue(), "metadata value");
      final String raw = json.canonicalJson();
      if (raw.isEmpty() || !raw.equals(raw.trim())) {
        throw new IllegalArgumentException(
            "metadata value for '" + key + "' must be an exact non-empty JSON literal");
      }
      copy.put(key, json);
    }
    return Collections.unmodifiableMap(copy);
  }

  private static String requireName(final String value, final String field) {
    Objects.requireNonNull(value, field);
    final byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
    if (value.isEmpty() || encoded.length > 255) {
      throw new IllegalArgumentException(field + " must contain 1..255 UTF-8 bytes");
    }
    if (!Normalizer.isNormalized(value, Normalizer.Form.NFC)) {
      throw new IllegalArgumentException(field + " must use NFC form");
    }
    for (int offset = 0; offset < value.length(); ) {
      final int codePoint = value.codePointAt(offset);
      if (Character.getType(codePoint) == Character.SURROGATE) {
        throw new IllegalArgumentException(field + " must contain valid Unicode scalar values");
      }
      if (Character.isISOControl(codePoint) || Character.isWhitespace(codePoint)) {
        throw new IllegalArgumentException(field + " must not contain controls or whitespace");
      }
      if (isBidiControl(codePoint)) {
        throw new IllegalArgumentException(field + " must not contain bidirectional controls");
      }
      if (codePoint == '@' || codePoint == '#' || codePoint == '$') {
        throw new IllegalArgumentException(field + " contains a reserved identifier separator");
      }
      offset += Character.charCount(codePoint);
    }
    return value;
  }

  private static boolean isBidiControl(final int codePoint) {
    return codePoint == 0x061C
        || codePoint == 0x200E
        || codePoint == 0x200F
        || (codePoint >= 0x202A && codePoint <= 0x202E)
        || (codePoint >= 0x2066 && codePoint <= 0x2069);
  }

  private static int requireU16(final int value, final String field) {
    if (value < 0 || value > 0xFFFF) {
      throw new IllegalArgumentException(field + " must fit u16");
    }
    return value;
  }

  private static BigInteger requireU64(final BigInteger value, final String field) {
    Objects.requireNonNull(value, field);
    if (value.signum() < 0 || value.compareTo(U64_MAX) > 0) {
      throw new IllegalArgumentException(field + " must fit u64");
    }
    return value;
  }

  private static BigInteger requireNonNegativeLong(final long value, final String field) {
    if (value < 0L) {
      throw new IllegalArgumentException(field + " must be non-negative");
    }
    return BigInteger.valueOf(value);
  }

  private static final class Wire {
    private static final String SETTLEMENT_WIRE_NAME = "iroha.settlement";
    private static final String SETTLEMENT_SCHEMA =
        "iroha_data_model::isi::settlement::SettlementInstructionBox";
    private static final String REPO_WIRE_NAME = "iroha.repo";
    private static final String REPO_SCHEMA =
        "iroha_data_model::isi::repo::RepoInstructionBox";
    private static final byte[] DVP_INTENT_DOMAIN =
        "iroha:settlement:dvp-intent:v1\0".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PVP_INTENT_DOMAIN =
        "iroha:settlement:pvp-intent:v1\0".getBytes(StandardCharsets.UTF_8);
    private static final byte[] REPO_INITIATION_INTENT_DOMAIN =
        "iroha:repo:initiation-intent:v1\0".getBytes(StandardCharsets.UTF_8);
    private static final byte[] REPO_MATURITY_INTENT_DOMAIN =
        "iroha:repo:maturity-intent:v1\0".getBytes(StandardCharsets.UTF_8);
    private static final TypeAdapter<Long> U16 = NoritoAdapters.uint(16);
    private static final TypeAdapter<Long> U32 = NoritoAdapters.uint(32);
    private static final TypeAdapter<String> STRING = NoritoAdapters.stringAdapter();
    private static final TypeAdapter<Boolean> BOOL = NoritoAdapters.boolAdapter();
    private static final RawAdapter RAW_ADAPTER = new RawAdapter();
    private static final TypeAdapter<Optional<byte[]>> OPTIONAL_RAW =
        NoritoAdapters.option(RAW_ADAPTER);
    private static final MetadataAdapter METADATA = new MetadataAdapter();

    private Wire() {}

    private static InstructionBox encodeDvp(final Dvp value) {
      return InstructionBox.fromWirePayload(
          SETTLEMENT_WIRE_NAME, NoritoCodec.encode(value, SETTLEMENT_SCHEMA, new DvpBoxAdapter()));
    }

    private static InstructionBox encodePvp(final Pvp value) {
      return InstructionBox.fromWirePayload(
          SETTLEMENT_WIRE_NAME, NoritoCodec.encode(value, SETTLEMENT_SCHEMA, new PvpBoxAdapter()));
    }

    private static InstructionBox encodeRepo(final Repo value) {
      return InstructionBox.fromWirePayload(
          REPO_WIRE_NAME, NoritoCodec.encode(value, REPO_SCHEMA, new RepoBoxAdapter()));
    }

    private static InstructionBox encodeReverseRepo(final ReverseRepo value) {
      return InstructionBox.fromWirePayload(
          REPO_WIRE_NAME,
          NoritoCodec.encode(value, REPO_SCHEMA, new ReverseRepoBoxAdapter()));
    }

    private static byte[] encodeDvpConcrete(final Dvp value) {
      return bare(encoder -> encodeDvpStruct(encoder, value));
    }

    private static byte[] encodePvpConcrete(final Pvp value) {
      return bare(encoder -> encodePvpStruct(encoder, value));
    }

    private static byte[] encodeRepoConcrete(final Repo value) {
      return bare(encoder -> encodeRepoStruct(encoder, value));
    }

    private static byte[] dvpIntentHash(final Dvp value) {
      return markedHash(DVP_INTENT_DOMAIN, encodeDvpConcrete(value));
    }

    private static byte[] pvpIntentHash(final Pvp value) {
      return markedHash(PVP_INTENT_DOMAIN, encodePvpConcrete(value));
    }

    private static byte[] repoInitiationIntentHash(final Repo value) {
      return markedHash(REPO_INITIATION_INTENT_DOMAIN, encodeRepoConcrete(value));
    }

    private static byte[] repoMaturityIntentHash(final Repo value) {
      return markedHash(REPO_MATURITY_INTENT_DOMAIN, encodeRepoConcrete(value));
    }

    private static final class DvpBoxAdapter implements TypeAdapter<Dvp> {
      @Override
      public void encode(final NoritoEncoder encoder, final Dvp value) {
        U32.encode(encoder, 0L);
        sizedRaw(encoder, encodeDvpConcrete(value));
      }

      @Override
      public Dvp decode(final NoritoDecoder decoder) {
        throw unsupportedDecode();
      }
    }

    private static final class PvpBoxAdapter implements TypeAdapter<Pvp> {
      @Override
      public void encode(final NoritoEncoder encoder, final Pvp value) {
        U32.encode(encoder, 1L);
        sizedRaw(encoder, encodePvpConcrete(value));
      }

      @Override
      public Pvp decode(final NoritoDecoder decoder) {
        throw unsupportedDecode();
      }
    }

    private static final class RepoBoxAdapter implements TypeAdapter<Repo> {
      @Override
      public void encode(final NoritoEncoder encoder, final Repo value) {
        U32.encode(encoder, 0L);
        sizedRaw(encoder, encodeRepoConcrete(value));
      }

      @Override
      public Repo decode(final NoritoDecoder decoder) {
        throw unsupportedDecode();
      }
    }

    private static final class ReverseRepoBoxAdapter implements TypeAdapter<ReverseRepo> {
      @Override
      public void encode(final NoritoEncoder encoder, final ReverseRepo value) {
        U32.encode(encoder, 1L);
        sizedRaw(
            encoder,
            bare(child -> sizedRaw(child, encodeNameId(value.agreementId()))));
      }

      @Override
      public ReverseRepo decode(final NoritoDecoder decoder) {
        throw unsupportedDecode();
      }
    }

    private static void encodeDvpStruct(final NoritoEncoder encoder, final Dvp value) {
      sizedRaw(encoder, encodeNameId(value.settlementId()));
      sizedRaw(encoder, encodeSettlementLeg(value.deliveryLeg()));
      sizedRaw(encoder, encodeSettlementLeg(value.paymentLeg()));
      sizedRaw(encoder, encodePlan(value.order()));
      sized(encoder, METADATA, value.metadata());
    }

    private static void encodePvpStruct(final NoritoEncoder encoder, final Pvp value) {
      sizedRaw(encoder, encodeNameId(value.settlementId()));
      sizedRaw(encoder, encodeSettlementLeg(value.primaryLeg()));
      sizedRaw(encoder, encodeSettlementLeg(value.counterLeg()));
      sizedRaw(encoder, encodePlan(value.order()));
      sized(encoder, METADATA, value.metadata());
    }

    private static byte[] encodeSettlementLeg(final SettlementLeg value) {
      return bare(
          encoder -> {
            sizedRaw(
                encoder,
                TransferWirePayloadEncoder.encodeAssetDefinitionIdPayload(
                    value.assetDefinitionId()));
            sizedRaw(
                encoder, TransferWirePayloadEncoder.encodeQuantityPayload(value.quantity()));
            sizedRaw(
                encoder, TransferWirePayloadEncoder.encodeAccountIdPayload(value.from()));
            sizedRaw(encoder, TransferWirePayloadEncoder.encodeAccountIdPayload(value.to()));
            sized(encoder, METADATA, value.metadata());
          });
    }

    private static byte[] encodePlan(final ExecutionOrder order) {
      return bare(
          encoder -> {
            sized(encoder, U32, order.wireTag);
            sized(encoder, U32, 0L);
          });
    }

    private static void encodeRepoStruct(final NoritoEncoder encoder, final Repo value) {
      sizedRaw(encoder, encodeNameId(value.agreementId()));
      sizedRaw(encoder, TransferWirePayloadEncoder.encodeAccountIdPayload(value.initiator()));
      sizedRaw(encoder, TransferWirePayloadEncoder.encodeAccountIdPayload(value.counterparty()));
      final byte[] custodian =
          value.custodian() == null
              ? null
              : TransferWirePayloadEncoder.encodeAccountIdPayload(value.custodian());
      sized(encoder, OPTIONAL_RAW, Optional.ofNullable(custodian));
      sizedRaw(encoder, encodeRepoCashLeg(value.cashLeg()));
      sizedRaw(encoder, encodeRepoCollateralLeg(value.collateralLeg()));
      sized(encoder, U16, (long) value.rateBps());
      sized(encoder, U64Adapter.INSTANCE, value.maturityTimestampMs());
      sizedRaw(encoder, encodeRepoGovernance(value.governance()));
    }

    private static byte[] encodeRepoCashLeg(final RepoCashLeg value) {
      return bare(
          encoder -> {
            sizedRaw(
                encoder,
                TransferWirePayloadEncoder.encodeAssetDefinitionIdPayload(
                    value.assetDefinitionId()));
            sizedRaw(
                encoder, TransferWirePayloadEncoder.encodeQuantityPayload(value.quantity()));
          });
    }

    private static byte[] encodeRepoCollateralLeg(final RepoCollateralLeg value) {
      return bare(
          encoder -> {
            sizedRaw(
                encoder,
                TransferWirePayloadEncoder.encodeAssetDefinitionIdPayload(
                    value.assetDefinitionId()));
            sizedRaw(
                encoder, TransferWirePayloadEncoder.encodeQuantityPayload(value.quantity()));
            sized(encoder, METADATA, value.metadata());
          });
    }

    private static byte[] encodeRepoGovernance(final RepoGovernance value) {
      return bare(
          encoder -> {
            sized(encoder, U16, (long) value.haircutBps());
            sized(encoder, U64Adapter.INSTANCE, value.marginFrequencySecs());
            sized(encoder, BOOL, value.allowEarlyRepayment());
          });
    }

    private static byte[] encodeNameId(final String value) {
      return bare(encoder -> sized(encoder, STRING, value));
    }

    private static final class RawAdapter implements TypeAdapter<byte[]> {
      @Override
      public void encode(final NoritoEncoder encoder, final byte[] value) {
        encoder.writeBytes(value);
      }

      @Override
      public byte[] decode(final NoritoDecoder decoder) {
        throw unsupportedDecode();
      }
    }

    private enum U64Adapter implements TypeAdapter<BigInteger> {
      INSTANCE;

      @Override
      public void encode(final NoritoEncoder encoder, final BigInteger value) {
        encoder.writeUInt(value.longValue(), 64);
      }

      @Override
      public BigInteger decode(final NoritoDecoder decoder) {
        throw unsupportedDecode();
      }
    }

    private static final class MetadataEntry {
      private final String key;
      private final JsonValue value;

      private MetadataEntry(final String key, final JsonValue value) {
        this.key = key;
        this.value = value;
      }
    }

    private static final class MetadataAdapter
        implements TypeAdapter<Map<String, JsonValue>> {
      private final TypeAdapter<List<MetadataEntry>> sequence =
          NoritoAdapters.sequence(new MetadataEntryAdapter());

      @Override
      public void encode(
          final NoritoEncoder encoder, final Map<String, JsonValue> value) {
        final List<String> keys = new ArrayList<>(value.keySet());
        keys.sort(Wire::compareUtf8);
        final List<MetadataEntry> entries = new ArrayList<>(keys.size());
        for (final String key : keys) {
          entries.add(new MetadataEntry(key, value.get(key)));
        }
        sequence.encode(encoder, entries);
      }

      @Override
      public Map<String, JsonValue> decode(final NoritoDecoder decoder) {
        throw unsupportedDecode();
      }
    }

    private static final class MetadataEntryAdapter implements TypeAdapter<MetadataEntry> {
      @Override
      public void encode(final NoritoEncoder encoder, final MetadataEntry value) {
        sized(encoder, STRING, value.key);
        sized(encoder, STRING, value.value.canonicalJson());
      }

      @Override
      public MetadataEntry decode(final NoritoDecoder decoder) {
        throw unsupportedDecode();
      }
    }

    private interface EncoderBody {
      void encode(NoritoEncoder encoder);
    }

    private static byte[] bare(final EncoderBody body) {
      final NoritoEncoder encoder = new NoritoEncoder(NoritoCodec.DEFAULT_FLAGS);
      body.encode(encoder);
      return encoder.toByteArray();
    }

    private static <T> void sized(
        final NoritoEncoder encoder, final TypeAdapter<T> adapter, final T value) {
      final NoritoEncoder child = encoder.childEncoder();
      adapter.encode(child, value);
      sizedRaw(encoder, child.toByteArray());
    }

    private static void sizedRaw(final NoritoEncoder encoder, final byte[] payload) {
      encoder.writeLength(
          payload.length, (encoder.flags() & NoritoHeader.COMPACT_LEN) != 0);
      encoder.writeBytes(payload);
    }

    private static byte[] markedHash(final byte[] domain, final byte[] concrete) {
      final byte[] preimage = Arrays.copyOf(domain, domain.length + concrete.length);
      System.arraycopy(concrete, 0, preimage, domain.length, concrete.length);
      final byte[] hash = Blake2b.digest256(preimage);
      hash[hash.length - 1] |= 1;
      return hash;
    }

    private static int compareUtf8(final String left, final String right) {
      final byte[] leftBytes = left.getBytes(StandardCharsets.UTF_8);
      final byte[] rightBytes = right.getBytes(StandardCharsets.UTF_8);
      final int common = Math.min(leftBytes.length, rightBytes.length);
      for (int index = 0; index < common; index++) {
        final int comparison = (leftBytes[index] & 0xFF) - (rightBytes[index] & 0xFF);
        if (comparison != 0) {
          return comparison;
        }
      }
      return leftBytes.length - rightBytes.length;
    }

    private static UnsupportedOperationException unsupportedDecode() {
      return new UnsupportedOperationException(
          "bilateral settlement instruction decoding is not exposed");
    }
  }
}
