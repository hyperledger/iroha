package org.hyperledger.iroha.android.sorafs;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Java view of the SoraFS reference validators in {@code connect_norito_bridge}.
 *
 * <p>The bridge exports its JNI entry points only for the Kotlin SDK class {@link
 * org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators}; the duplicate {@code
 * org.hyperledger.iroha.android} exports are retired. This class keeps the Java argument checks
 * and exceptions, then delegates every native call to the Kotlin owner.
 */
public final class SorafsReferenceValidators {
  private static final String LIBRARY_NAME = "connect_norito_bridge";
  public static final int REQUIRED_BRIDGE_ABI_VERSION = 30;
  /** Canonical maximum byte length for a V1 orderbook owner account. */
  public static final int ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1 = 256;
  /** Maximum complete-root or checkpoint-tail window accepted by one head validation. */
  public static final int GOVERNANCE_DAG_MAX_BLOCKS_V1 = 64;
  /** Canonical byte length for every Governance DAG CID. */
  public static final int GOVERNANCE_DAG_CID_BYTES_V1 = 32;
  /** Maximum aggregate payload, CID, and label bytes accepted by one reference call. */
  public static final int REFERENCE_MAX_INPUT_BYTES_V1 = 67_108_864;
  /** Maximum UTF-8 bytes accepted for one diagnostic input label. */
  public static final int REFERENCE_MAX_LABEL_BYTES_V1 = 1_024;
  /** Maximum payload count accepted by one fixture-bundle call. */
  public static final int FIXTURE_BUNDLE_MAX_PAYLOADS_V1 = 64;

  private SorafsReferenceValidators() {}

  /** Returns true when the exact first-release native bridge is present. */
  public static boolean isNativeAvailable() {
    return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
        .isNativeAvailable();
  }

  static boolean isBridgeAbiSupported(final int abiVersion) {
    return abiVersion == REQUIRED_BRIDGE_ABI_VERSION;
  }

  static boolean isGovernanceDagBridgeSupported(
      final int abiVersion, final boolean hasSymbols) {
    return isBridgeAbiSupported(abiVersion) && hasSymbols;
  }

  static boolean isFixtureBundleBridgeSupported(
      final int abiVersion, final boolean hasSymbols) {
    return isBridgeAbiSupported(abiVersion) && hasSymbols;
  }

  static boolean isGovernanceLogNodeBridgeSupported(
      final int abiVersion, final boolean hasSymbols) {
    return isBridgeAbiSupported(abiVersion) && hasSymbols;
  }

  static boolean isAppealFinanceBridgeSupported(
      final int abiVersion, final boolean hasSymbols) {
    return isBridgeAbiSupported(abiVersion) && hasSymbols;
  }

  public static String validateOrderbookPayloadJson(
      final SorafsOrderbookPayloadKind kind, final byte[] noritoBytes) {
    return validateOrderbookPayloadJson(kind, noritoBytes, null, currentEpochSeconds());
  }

  public static String validateOrderbookPayloadJson(
      final SorafsOrderbookPayloadKind kind, final byte[] noritoBytes, final String label) {
    return validateOrderbookPayloadJson(kind, noritoBytes, label, currentEpochSeconds());
  }

  public static String validateOrderbookPayloadJson(
      final SorafsOrderbookPayloadKind kind,
      final byte[] noritoBytes,
      final String label,
      final long generatedAtUnix) {
    requireGeneratedAt(generatedAtUnix);
    final SorafsOrderbookPayloadKind selected = requireKind(kind, "kind");
    final byte[] payload = requirePayload(noritoBytes, "noritoBytes");
    labelBytes(label, selected.defaultLabel());
    requireNative();
    return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
        .validateOrderbookPayloadJson(
            kotlin(selected), payload, label, generatedAtUnix);
  }

  public static String validatePopPayloadJson(
      final SorafsPopPayloadKind kind, final byte[] noritoBytes) {
    return validatePopPayloadJson(kind, noritoBytes, null, currentEpochSeconds());
  }

  public static String validatePopPayloadJson(
      final SorafsPopPayloadKind kind, final byte[] noritoBytes, final String label) {
    return validatePopPayloadJson(kind, noritoBytes, label, currentEpochSeconds());
  }

  public static String validatePopPayloadJson(
      final SorafsPopPayloadKind kind,
      final byte[] noritoBytes,
      final String label,
      final long generatedAtUnix) {
    requireGeneratedAt(generatedAtUnix);
    final SorafsPopPayloadKind selected = requireKind(kind, "kind");
    final byte[] payload = requirePayload(noritoBytes, "noritoBytes");
    labelBytes(label, selected.defaultLabel());
    requireNative();
    return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
        .validatePopPayloadJson(
            kotlin(selected), payload, label, generatedAtUnix);
  }

  public static String validateHedgingPayloadJson(
      final SorafsHedgingPayloadKind kind, final byte[] noritoBytes) {
    return validateHedgingPayloadJson(kind, noritoBytes, null, currentEpochSeconds());
  }

  public static String validateHedgingPayloadJson(
      final SorafsHedgingPayloadKind kind, final byte[] noritoBytes, final String label) {
    return validateHedgingPayloadJson(kind, noritoBytes, label, currentEpochSeconds());
  }

  public static String validateHedgingPayloadJson(
      final SorafsHedgingPayloadKind kind,
      final byte[] noritoBytes,
      final String label,
      final long generatedAtUnix) {
    requireGeneratedAt(generatedAtUnix);
    final SorafsHedgingPayloadKind selected = requireKind(kind, "kind");
    final byte[] payload = requirePayload(noritoBytes, "noritoBytes");
    labelBytes(label, selected.defaultLabel());
    requireNative();
    return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
        .validateHedgingPayloadJson(
            kotlin(selected), payload, label, generatedAtUnix);
  }

  /** Validates one canonical appeal-finance {@code CancelAssetLock} V1 payload. */
  public static String validateAppealFinanceCancelAssetLockJson(final byte[] noritoBytes) {
    return validateAppealFinanceCancelAssetLockJson(
        noritoBytes, null, currentEpochSeconds());
  }

  /**
   * Validates one canonical appeal-finance {@code CancelAssetLock} V1 payload with a label.
   */
  public static String validateAppealFinanceCancelAssetLockJson(
      final byte[] noritoBytes, final String label) {
    return validateAppealFinanceCancelAssetLockJson(
        noritoBytes, label, currentEpochSeconds());
  }

  /**
   * Validates one canonical appeal-finance {@code CancelAssetLock} V1 payload with a
   * caller-bound outcome timestamp.
   */
  public static String validateAppealFinanceCancelAssetLockJson(
      final byte[] noritoBytes, final String label, final long generatedAtUnix) {
    requireGeneratedAt(generatedAtUnix);
    final byte[] payload = requireReferencePayload(noritoBytes, "noritoBytes");
    final byte[] labelPayload = labelBytes(label, "cancel_asset_lock_v1.to");
    requireAggregateReferenceBytes(payload.length, labelPayload.length);
    requireNative();
    return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
        .validateAppealFinanceCancelAssetLockJson(
            payload, label, generatedAtUnix);
  }

  /** Validate a bounded heterogeneous fixture bundle and canonical cross-links. */
  public static String validateFixtureBundleJson(
      final List<SorafsFixtureBundlePayloadInput> payloads) {
    final long now = currentEpochSeconds();
    return validateFixtureBundleJson(payloads, now, now);
  }

  /** Validate a bounded heterogeneous fixture bundle with caller-bound timestamps. */
  public static String validateFixtureBundleJson(
      final List<SorafsFixtureBundlePayloadInput> payloads,
      final long nowUnix,
      final long generatedAtUnix) {
    if (payloads == null
        || payloads.isEmpty()
        || payloads.size() > FIXTURE_BUNDLE_MAX_PAYLOADS_V1) {
      throw new IllegalArgumentException(
          "payloads must contain 1.." + FIXTURE_BUNDLE_MAX_PAYLOADS_V1 + " entries");
    }
    requireGeneratedAt(nowUnix);
    requireGeneratedAt(generatedAtUnix);
    final List<org.hyperledger.iroha.sdk.sorafs.SorafsFixtureBundlePayloadInput> inputs =
        new ArrayList<>(payloads.size());
    long aggregateBytes = 0;
    for (int index = 0; index < payloads.size(); index++) {
      final SorafsFixtureBundlePayloadInput input = payloads.get(index);
      if (input == null) {
        throw new IllegalArgumentException("payloads[" + index + "] must be provided");
      }
      final byte[] payload =
          requireReferencePayload(input.noritoBytes(), "payloads[" + index + "].noritoBytes");
      final byte[] label = labelBytes(input.label(), input.kind().defaultLabel());
      aggregateBytes += (long) payload.length + label.length;
      if (aggregateBytes > REFERENCE_MAX_INPUT_BYTES_V1) {
        throw new IllegalArgumentException(
            "fixture-bundle inputs exceed "
                + REFERENCE_MAX_INPUT_BYTES_V1
                + " aggregate bytes");
      }
      inputs.add(
          new org.hyperledger.iroha.sdk.sorafs.SorafsFixtureBundlePayloadInput(
              kotlin(input.kind()),
              payload,
              input.label()));
    }
    requireNative();
    return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
        .validateFixtureBundleJson(inputs, nowUnix, generatedAtUnix);
  }

  /** Validates one canonical signed {@code GovernanceLogNodeV1} against its expected node CID. */
  public static String validateGovernanceLogNodeJson(
      final byte[] noritoBytes, final byte[] expectedNodeCid) {
    return validateGovernanceLogNodeJson(
        noritoBytes, null, expectedNodeCid, currentEpochSeconds());
  }

  /** Validates one canonical signed {@code GovernanceLogNodeV1} against its expected node CID. */
  public static String validateGovernanceLogNodeJson(
      final byte[] noritoBytes,
      final String label,
      final byte[] expectedNodeCid,
      final long generatedAtUnix) {
    requireGeneratedAt(generatedAtUnix);
    final byte[] payload = requireReferencePayload(noritoBytes, "noritoBytes");
    final byte[] labelPayload = labelBytes(label, "governance.to");
    if (expectedNodeCid == null
        || expectedNodeCid.length != GOVERNANCE_DAG_CID_BYTES_V1) {
      throw new IllegalArgumentException(
          "expectedNodeCid must contain exactly "
              + GOVERNANCE_DAG_CID_BYTES_V1
              + " bytes");
    }
    final byte[] expectedCid = expectedNodeCid.clone();
    requireAggregateReferenceBytes(payload.length, labelPayload.length, expectedCid.length);
    requireNative();
    return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
        .validateGovernanceLogNodeJson(
            payload, label, expectedCid, generatedAtUnix);
  }

  /**
   * Validates one canonical {@code GovernanceDagBlockV1} without an external CID check.
   *
   * <p>The native validator always recomputes and validates the CID embedded in the block.
   */
  public static String validateGovernanceDagBlockJson(final byte[] noritoBytes) {
    return validateGovernanceDagBlockJson(
        noritoBytes, null, null, currentEpochSeconds());
  }

  /** Validates one canonical {@code GovernanceDagBlockV1}. */
  public static String validateGovernanceDagBlockJson(
      final byte[] noritoBytes,
      final String label,
      final byte[] expectedBlockCid,
      final long generatedAtUnix) {
    requireGeneratedAt(generatedAtUnix);
    final byte[] payload = requireReferencePayload(noritoBytes, "noritoBytes");
    final byte[] labelPayload = labelBytes(label, "governance-dag-block.to");
    final byte[] expectedCid;
    if (expectedBlockCid == null) {
      expectedCid = new byte[0];
    } else {
      if (expectedBlockCid.length != GOVERNANCE_DAG_CID_BYTES_V1) {
        throw new IllegalArgumentException(
            "expectedBlockCid must contain exactly "
                + GOVERNANCE_DAG_CID_BYTES_V1
                + " bytes");
      }
      expectedCid = expectedBlockCid.clone();
    }
    requireAggregateReferenceBytes(payload.length, labelPayload.length, expectedCid.length);
    requireNative();
    return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
        .validateGovernanceDagBlockJson(
            payload, label, expectedBlockCid == null ? null : expectedCid, generatedAtUnix);
  }

  /**
   * Validates one signed {@code GovernanceDagHeadV1} against either a complete root-to-head
   * history or its signed checkpoint-anchored tail.
   */
  public static String validateGovernanceDagHeadChainJson(
      final byte[] head, final byte[][] blocks) {
    return validateGovernanceDagHeadChainJson(
        head, blocks, null, null, currentEpochSeconds());
  }

  /**
   * Validates one signed {@code GovernanceDagHeadV1} against a complete root history or exact
   * checkpoint-anchored tail.
   *
   * <p>When supplied, {@code blockLabels} must contain exactly one label per block.
   */
  public static String validateGovernanceDagHeadChainJson(
      final byte[] head,
      final byte[][] blocks,
      final String headLabel,
      final String[] blockLabels,
      final long generatedAtUnix) {
    requireGeneratedAt(generatedAtUnix);
    if (blocks == null) {
      throw new IllegalArgumentException("blocks must be provided");
    }
    if (blocks.length == 0 || blocks.length > GOVERNANCE_DAG_MAX_BLOCKS_V1) {
      throw new IllegalArgumentException(
          "blocks must contain 1.." + GOVERNANCE_DAG_MAX_BLOCKS_V1 + " entries");
    }
    if (blockLabels != null && blockLabels.length != blocks.length) {
      throw new IllegalArgumentException(
          "blockLabels must contain exactly one entry per block");
    }
    final byte[] headPayload = requireReferencePayload(head, "head");
    final byte[] headLabelPayload = labelBytes(headLabel, "governance-dag-head.to");
    final byte[][] blockPayloads = new byte[blocks.length][];
    final byte[][] blockLabelPayloads = new byte[blocks.length][];
    long aggregateBytes = (long) headPayload.length + headLabelPayload.length;
    for (int index = 0; index < blocks.length; index++) {
      blockPayloads[index] = requireReferencePayload(blocks[index], "blocks[" + index + "]");
      blockLabelPayloads[index] =
          labelBytes(
              blockLabels == null ? null : blockLabels[index],
              "governance-dag-block-" + index + ".to");
      aggregateBytes +=
          (long) blockPayloads[index].length + blockLabelPayloads[index].length;
      if (aggregateBytes > REFERENCE_MAX_INPUT_BYTES_V1) {
        throw new IllegalArgumentException(
            "governance DAG head-chain inputs exceed "
                + REFERENCE_MAX_INPUT_BYTES_V1
                + " aggregate bytes");
      }
    }
    requireNative();
    return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
        .validateGovernanceDagHeadChainJson(
            headPayload,
            Arrays.asList(blockPayloads),
            headLabel,
            blockLabels == null ? null : Arrays.asList(blockLabels),
            generatedAtUnix);
  }

  public static byte[] signOrderbookPayload(
      final SorafsOrderbookPayloadKind kind, final byte[] noritoBytes, final byte[] privateKey) {
    final SorafsOrderbookPayloadKind selected = requireUserSignedOrderbookKind(kind);
    final byte[] payload = requirePayload(noritoBytes, "noritoBytes");
    final byte[] key = requirePrivateKey(privateKey);
    try {
      requireNative();
      return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
          .signOrderbookPayload(
              kotlin(selected), payload, key);
    } finally {
      Arrays.fill(key, (byte) 0);
    }
  }

  /** Derive the canonical V1 order id from owner-account bytes and nonce. */
  public static byte[] deriveOrderbookOrderId(final byte[] ownerAccount, final long nonce) {
    final byte[] ownerBytes = requireNonEmptyBytes(ownerAccount, "ownerAccount");
    requirePositive(nonce, "nonce");
    requireNative();
    final byte[] orderId = org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
        .deriveOrderbookOrderId(ownerBytes, nonce);
    if (orderId.length != 32) {
      throw new IllegalStateException(
          "SoraFS orderbook order id derivation returned a non-32-byte identifier");
    }
    return orderId;
  }

  public static byte[] buildSignedOrderbookOrderRequest(
      final SorafsOrderbookSide side,
      final SorafsOrderbookTier tier,
      final String pricePerGib,
      final long quantityGib,
      final byte[] ownerAccount,
      final byte[] providerId,
      final long expiryUnix,
      final long nonce,
      final int makerFeeBps,
      final int takerFeeBps,
      final byte[] privateKey) {
    return buildSignedOrderbookOrderRequest(
        side,
        tier,
        pricePerGib,
        quantityGib,
        quantityGib,
        ownerAccount,
        providerId,
        expiryUnix,
        nonce,
        makerFeeBps,
        takerFeeBps,
        privateKey);
  }

  public static byte[] buildSignedOrderbookOrderRequest(
      final SorafsOrderbookSide side,
      final SorafsOrderbookTier tier,
      final String pricePerGib,
      final long quantityGib,
      final long remainingGib,
      final byte[] ownerAccount,
      final byte[] providerId,
      final long expiryUnix,
      final long nonce,
      final int makerFeeBps,
      final int takerFeeBps,
      final byte[] privateKey) {
    return buildSignedOrderbookOrderRequest(
        deriveOrderbookOrderId(ownerAccount, nonce),
        side,
        tier,
        pricePerGib,
        quantityGib,
        remainingGib,
        ownerAccount,
        providerId,
        expiryUnix,
        nonce,
        makerFeeBps,
        takerFeeBps,
        privateKey);
  }

  public static byte[] buildSignedOrderbookOrderRequest(
      final byte[] orderId,
      final SorafsOrderbookSide side,
      final SorafsOrderbookTier tier,
      final String pricePerGib,
      final long quantityGib,
      final byte[] ownerAccount,
      final byte[] providerId,
      final long expiryUnix,
      final long nonce,
      final int makerFeeBps,
      final int takerFeeBps,
      final byte[] privateKey) {
    return buildSignedOrderbookOrderRequest(
        orderId,
        side,
        tier,
        pricePerGib,
        quantityGib,
        quantityGib,
        ownerAccount,
        providerId,
        expiryUnix,
        nonce,
        makerFeeBps,
        takerFeeBps,
        privateKey);
  }

  public static byte[] buildSignedOrderbookOrderRequest(
      final byte[] orderId,
      final SorafsOrderbookSide side,
      final SorafsOrderbookTier tier,
      final String pricePerGib,
      final long quantityGib,
      final long remainingGib,
      final byte[] ownerAccount,
      final byte[] providerId,
      final long expiryUnix,
      final long nonce,
      final int makerFeeBps,
      final int takerFeeBps,
      final byte[] privateKey) {
    final byte[] orderIdBytes = requireFixed32(orderId, "orderId");
    final SorafsOrderbookSide selectedSide = requireKind(side, "side");
    final SorafsOrderbookTier selectedTier = requireKind(tier, "tier");
    xorQuantityBytes(pricePerGib, "pricePerGib", true);
    requirePositive(quantityGib, "quantityGib");
    requirePositive(remainingGib, "remainingGib");
    final byte[] ownerBytes = requireNonEmptyBytes(ownerAccount, "ownerAccount");
    requireProviderId(selectedSide, providerId);
    requirePositive(expiryUnix, "expiryUnix");
    requirePositive(nonce, "nonce");
    final byte[] canonicalOrderId = deriveOrderbookOrderId(ownerBytes, nonce);
    if (!Arrays.equals(orderIdBytes, canonicalOrderId)) {
      throw new IllegalArgumentException(
          "orderId must equal the canonical owner-and-nonce derivation");
    }
    final int makerFee = requireFeeBps(makerFeeBps, "makerFeeBps");
    final int takerFee = requireFeeBps(takerFeeBps, "takerFeeBps");
    final byte[] key = requirePrivateKey(privateKey);
    try {
      requireNative();
      return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
          .buildSignedOrderbookOrderRequest(
              orderIdBytes,
              kotlin(selectedSide),
              kotlin(selectedTier),
              pricePerGib,
              quantityGib,
              ownerBytes,
              providerId,
              expiryUnix,
              nonce,
              makerFee,
              takerFee,
              key,
              remainingGib);
    } finally {
      Arrays.fill(key, (byte) 0);
    }
  }

  public static byte[] buildSignedOrderbookOrderCancel(
      final byte[] orderId,
      final byte[] ownerAccount,
      final SorafsOrderbookCancelReason reason,
      final long nonce,
      final byte[] privateKey) {
    final byte[] orderIdBytes = requireFixed32(orderId, "orderId");
    final byte[] ownerBytes = requireNonEmptyBytes(ownerAccount, "ownerAccount");
    final SorafsOrderbookCancelReason selectedReason = requireKind(reason, "reason");
    requirePositive(nonce, "nonce");
    final byte[] key = requirePrivateKey(privateKey);
    try {
      requireNative();
      return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
          .buildSignedOrderbookOrderCancel(
              orderIdBytes,
              ownerBytes,
              kotlin(selectedReason),
              nonce,
              key);
    } finally {
      Arrays.fill(key, (byte) 0);
    }
  }

  public static byte[] buildSignedOrderbookSettlementReceipt(
      final byte[] receiptId,
      final byte[] channelId,
      final byte[] tradeId,
      final long rangeStart,
      final long rangeEnd,
      final byte[] chunkHash,
      final long bytesDelivered,
      final String xorDebited,
      final String providerCredit,
      final String feeAmount,
      final long issuedAtUnix,
      final byte[] privateKey) {
    final byte[] receiptIdBytes = requireFixed32(receiptId, "receiptId");
    final byte[] channelIdBytes = requireFixed32(channelId, "channelId");
    final byte[] tradeIdBytes = requireFixed32(tradeId, "tradeId");
    requireNonNegative(rangeStart, "rangeStart");
    requirePositive(rangeEnd, "rangeEnd");
    final byte[] chunkHashBytes = requireFixed32(chunkHash, "chunkHash");
    requirePositive(bytesDelivered, "bytesDelivered");
    xorQuantityBytes(xorDebited, "xorDebited", true);
    xorQuantityBytes(providerCredit, "providerCredit", false);
    xorQuantityBytes(feeAmount, "feeAmount", false);
    requirePositive(issuedAtUnix, "issuedAtUnix");
    final byte[] key = requirePrivateKey(privateKey);
    try {
      requireNative();
      return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
          .buildSignedOrderbookSettlementReceipt(
              receiptIdBytes,
              channelIdBytes,
              tradeIdBytes,
              rangeStart,
              rangeEnd,
              chunkHashBytes,
              bytesDelivered,
              xorDebited,
              providerCredit,
              feeAmount,
              issuedAtUnix,
              key);
    } finally {
      Arrays.fill(key, (byte) 0);
    }
  }

  public static String validatePdpPayloadJson(
      final SorafsPdpPayloadKind kind, final byte[] noritoBytes) {
    return validatePdpPayloadJson(kind, noritoBytes, null, currentEpochSeconds());
  }

  public static String validatePdpPayloadJson(
      final SorafsPdpPayloadKind kind, final byte[] noritoBytes, final String label) {
    return validatePdpPayloadJson(kind, noritoBytes, label, currentEpochSeconds());
  }

  public static String validatePdpPayloadJson(
      final SorafsPdpPayloadKind kind,
      final byte[] noritoBytes,
      final String label,
      final long generatedAtUnix) {
    requireGeneratedAt(generatedAtUnix);
    final SorafsPdpPayloadKind selected = requireKind(kind, "kind");
    final byte[] payload = requirePayload(noritoBytes, "noritoBytes");
    labelBytes(label, selected.defaultLabel());
    requireNative();
    return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
        .validatePdpPayloadJson(
            kotlin(selected), payload, label, generatedAtUnix);
  }

  public static String validatePdpCommitmentChallengeJson(
      final byte[] commitment, final byte[] challenge) {
    return validatePdpCommitmentChallengeJson(
        commitment, challenge, null, null, currentEpochSeconds());
  }

  public static String validatePdpCommitmentChallengeJson(
      final byte[] commitment,
      final byte[] challenge,
      final String commitmentLabel,
      final String challengeLabel,
      final long generatedAtUnix) {
    requireGeneratedAt(generatedAtUnix);
    final byte[] commitmentPayload = requirePayload(commitment, "commitment");
    labelBytes(commitmentLabel, SorafsPdpPayloadKind.COMMITMENT.defaultLabel());
    final byte[] challengePayload = requirePayload(challenge, "challenge");
    labelBytes(challengeLabel, SorafsPdpPayloadKind.CHALLENGE.defaultLabel());
    requireNative();
    return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
        .validatePdpCommitmentChallengeJson(
            commitmentPayload, challengePayload, commitmentLabel, challengeLabel, generatedAtUnix);
  }

  public static String validatePdpChallengeProofJson(
      final byte[] challenge, final byte[] proof) {
    return validatePdpChallengeProofJson(challenge, proof, null, null, currentEpochSeconds());
  }

  public static String validatePdpChallengeProofJson(
      final byte[] challenge,
      final byte[] proof,
      final String challengeLabel,
      final String proofLabel,
      final long generatedAtUnix) {
    requireGeneratedAt(generatedAtUnix);
    final byte[] challengePayload = requirePayload(challenge, "challenge");
    labelBytes(challengeLabel, SorafsPdpPayloadKind.CHALLENGE.defaultLabel());
    final byte[] proofPayload = requirePayload(proof, "proof");
    labelBytes(proofLabel, SorafsPdpPayloadKind.PROOF.defaultLabel());
    requireNative();
    return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
        .validatePdpChallengeProofJson(
            challengePayload, proofPayload, challengeLabel, proofLabel, generatedAtUnix);
  }

  public static String validatePdpBundleJson(
      final byte[] commitment, final byte[] challenge, final byte[] proof) {
    return validatePdpBundleJson(
        commitment, challenge, proof, null, null, null, currentEpochSeconds());
  }

  public static String validatePdpBundleJson(
      final byte[] commitment,
      final byte[] challenge,
      final byte[] proof,
      final String commitmentLabel,
      final String challengeLabel,
      final String proofLabel,
      final long generatedAtUnix) {
    requireGeneratedAt(generatedAtUnix);
    final byte[] commitmentPayload = requirePayload(commitment, "commitment");
    labelBytes(commitmentLabel, SorafsPdpPayloadKind.COMMITMENT.defaultLabel());
    final byte[] challengePayload = requirePayload(challenge, "challenge");
    labelBytes(challengeLabel, SorafsPdpPayloadKind.CHALLENGE.defaultLabel());
    final byte[] proofPayload = requirePayload(proof, "proof");
    labelBytes(proofLabel, SorafsPdpPayloadKind.PROOF.defaultLabel());
    requireNative();
    return org.hyperledger.iroha.sdk.sorafs.SorafsReferenceValidators
        .validatePdpBundleJson(
            commitmentPayload,
            challengePayload,
            proofPayload,
            commitmentLabel,
            challengeLabel,
            proofLabel,
            generatedAtUnix);
  }

  private static long currentEpochSeconds() {
    return System.currentTimeMillis() / 1000L;
  }

  private static void requireGeneratedAt(final long generatedAtUnix) {
    if (generatedAtUnix < 0L) {
      throw new IllegalArgumentException("generatedAtUnix must be non-negative");
    }
  }

  private static void requireNative() {
    if (!isNativeAvailable()) {
      throw new IllegalStateException(LIBRARY_NAME + " is not available in this runtime");
    }
  }

  private static <T> T requireKind(final T kind, final String field) {
    if (kind == null) {
      throw new IllegalArgumentException(field + " must be provided");
    }
    return kind;
  }

  private static SorafsOrderbookPayloadKind requireUserSignedOrderbookKind(
      final SorafsOrderbookPayloadKind kind) {
    final SorafsOrderbookPayloadKind selected = requireKind(kind, "kind");
    if (!selected.isUserSignedPayload()) {
      throw new IllegalArgumentException(
          "orderbook payload kind " + selected.name() + " cannot be signed");
    }
    return selected;
  }

  private static byte[] requirePayload(final byte[] payload, final String field) {
    if (payload == null) {
      throw new IllegalArgumentException(field + " must be provided");
    }
    return payload.clone();
  }

  private static byte[] requireReferencePayload(final byte[] payload, final String field) {
    final byte[] bytes = requirePayload(payload, field);
    if (bytes.length > REFERENCE_MAX_INPUT_BYTES_V1) {
      throw new IllegalArgumentException(
          field + " must be at most " + REFERENCE_MAX_INPUT_BYTES_V1 + " bytes");
    }
    return bytes;
  }

  private static void requireAggregateReferenceBytes(final int... sizes) {
    long aggregateBytes = 0L;
    for (final int size : sizes) {
      aggregateBytes += size;
    }
    if (aggregateBytes > REFERENCE_MAX_INPUT_BYTES_V1) {
      throw new IllegalArgumentException(
          "reference inputs exceed " + REFERENCE_MAX_INPUT_BYTES_V1 + " aggregate bytes");
    }
  }

  private static byte[] requirePrivateKey(final byte[] privateKey) {
    if (privateKey == null) {
      throw new IllegalArgumentException("privateKey must be provided");
    }
    if (privateKey.length != 32) {
      throw new IllegalArgumentException("privateKey must be 32 bytes");
    }
    boolean nonZero = false;
    for (final byte value : privateKey) {
      if (value != 0) {
        nonZero = true;
        break;
      }
    }
    if (!nonZero) {
      throw new IllegalArgumentException("privateKey must not be all zero");
    }
    return privateKey.clone();
  }

  private static byte[] requireFixed32(final byte[] payload, final String field) {
    if (payload == null) {
      throw new IllegalArgumentException(field + " must be provided");
    }
    if (payload.length != 32) {
      throw new IllegalArgumentException(field + " must be 32 bytes");
    }
    return payload.clone();
  }

  private static byte[] requireProviderId(
      final SorafsOrderbookSide side, final byte[] providerId) {
    if (side == SorafsOrderbookSide.BID) {
      if (providerId != null && providerId.length != 0) {
        throw new IllegalArgumentException(
            "providerId must be absent or empty for bid orders");
      }
      return new byte[0];
    }
    final byte[] provider = requireFixed32(providerId, "providerId");
    boolean nonZero = false;
    for (final byte value : provider) {
      if (value != 0) {
        nonZero = true;
        break;
      }
    }
    if (!nonZero) {
      throw new IllegalArgumentException("providerId must not be all zero");
    }
    return provider;
  }

  private static byte[] requireNonEmptyBytes(final byte[] payload, final String field) {
    if (payload == null) {
      throw new IllegalArgumentException(field + " must be provided");
    }
    if (payload.length == 0) {
      throw new IllegalArgumentException(field + " must not be empty");
    }
    if (payload.length > ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1) {
      throw new IllegalArgumentException(
          field + " must be at most " + ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1 + " bytes");
    }
    return payload.clone();
  }

  private static void requireNonNegative(final long value, final String field) {
    if (value < 0L) {
      throw new IllegalArgumentException(field + " must be non-negative");
    }
  }

  private static void requirePositive(final long value, final String field) {
    if (value <= 0L) {
      throw new IllegalArgumentException(field + " must be greater than zero");
    }
  }

  private static int requireFeeBps(final int value, final String field) {
    if (value < 0 || value > 0xFFFF) {
      throw new IllegalArgumentException(field + " must fit in u16 basis points");
    }
    return value;
  }

  private static byte[] xorQuantityBytes(
      final String value, final String field, final boolean positive) {
    if (value == null) {
      throw new IllegalArgumentException(field + " must be provided");
    }
    if (value.length() > 155) {
      throw new IllegalArgumentException(field + " exceeds the canonical XOR quantity text bound");
    }
    if (!value.matches("(0|[1-9][0-9]*)(?:\\.([0-9]*[1-9]))?")) {
      throw new IllegalArgumentException(
          field + " must be a canonical non-negative XOR quantity");
    }
    final int decimalIndex = value.indexOf('.');
    final String integer = decimalIndex < 0 ? value : value.substring(0, decimalIndex);
    final String fractional = decimalIndex < 0 ? "" : value.substring(decimalIndex + 1);
    if (fractional.length() > 9) {
      throw new IllegalArgumentException(
          field + " must have at most 9 fractional decimal places");
    }
    final BigInteger mantissa = new BigInteger(integer + fractional);
    final BigInteger maximum = BigInteger.ONE.shiftLeft(511).subtract(BigInteger.ONE);
    if (mantissa.compareTo(maximum) > 0) {
      throw new IllegalArgumentException(field + " exceeds the 512-bit signed quantity domain");
    }
    if (positive && mantissa.signum() == 0) {
      throw new IllegalArgumentException(field + " must be greater than zero");
    }
    return value.getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] labelBytes(final String label, final String fallback) {
    final String value = label == null ? fallback : label;
    if (hasUnpairedSurrogate(value)) {
      throw new IllegalArgumentException("label must be valid Unicode text");
    }
    if (value.codePoints().allMatch(SorafsReferenceValidators::isUnicodeWhitespace)) {
      throw new IllegalArgumentException("label must not be blank");
    }
    if (isUnicodeWhitespace(value.codePointAt(0))
        || isUnicodeWhitespace(value.codePointBefore(value.length()))) {
      throw new IllegalArgumentException("label must not contain surrounding whitespace");
    }
    if (value.codePoints().anyMatch(Character::isISOControl)) {
      throw new IllegalArgumentException("label must not contain control characters");
    }
    final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
    if (bytes.length > REFERENCE_MAX_LABEL_BYTES_V1) {
      throw new IllegalArgumentException(
          "label must be at most " + REFERENCE_MAX_LABEL_BYTES_V1 + " UTF-8 bytes");
    }
    return bytes;
  }

  private static boolean hasUnpairedSurrogate(final String value) {
    for (int index = 0; index < value.length(); index++) {
      final char character = value.charAt(index);
      if (Character.isHighSurrogate(character)) {
        if (index + 1 >= value.length()
            || !Character.isLowSurrogate(value.charAt(index + 1))) {
          return true;
        }
        index++;
      } else if (Character.isLowSurrogate(character)) {
        return true;
      }
    }
    return false;
  }

  private static boolean isUnicodeWhitespace(final int codePoint) {
    return Character.isWhitespace(codePoint) || Character.isSpaceChar(codePoint);
  }

  // The same-named Kotlin enum constants; both SDKs declare identical SoraFS enums.
  private static org.hyperledger.iroha.sdk.sorafs.SorafsOrderbookPayloadKind kotlin(
      final SorafsOrderbookPayloadKind value) {
    return org.hyperledger.iroha.sdk.sorafs.SorafsOrderbookPayloadKind.valueOf(value.name());
  }

  private static org.hyperledger.iroha.sdk.sorafs.SorafsPopPayloadKind kotlin(
      final SorafsPopPayloadKind value) {
    return org.hyperledger.iroha.sdk.sorafs.SorafsPopPayloadKind.valueOf(value.name());
  }

  private static org.hyperledger.iroha.sdk.sorafs.SorafsHedgingPayloadKind kotlin(
      final SorafsHedgingPayloadKind value) {
    return org.hyperledger.iroha.sdk.sorafs.SorafsHedgingPayloadKind.valueOf(value.name());
  }

  private static org.hyperledger.iroha.sdk.sorafs.SorafsPdpPayloadKind kotlin(
      final SorafsPdpPayloadKind value) {
    return org.hyperledger.iroha.sdk.sorafs.SorafsPdpPayloadKind.valueOf(value.name());
  }

  private static org.hyperledger.iroha.sdk.sorafs.SorafsFixtureBundlePayloadKind kotlin(
      final SorafsFixtureBundlePayloadKind value) {
    return org.hyperledger.iroha.sdk.sorafs.SorafsFixtureBundlePayloadKind.valueOf(value.name());
  }

  private static org.hyperledger.iroha.sdk.sorafs.SorafsOrderbookSide kotlin(
      final SorafsOrderbookSide value) {
    return org.hyperledger.iroha.sdk.sorafs.SorafsOrderbookSide.valueOf(value.name());
  }

  private static org.hyperledger.iroha.sdk.sorafs.SorafsOrderbookTier kotlin(
      final SorafsOrderbookTier value) {
    return org.hyperledger.iroha.sdk.sorafs.SorafsOrderbookTier.valueOf(value.name());
  }

  private static org.hyperledger.iroha.sdk.sorafs.SorafsOrderbookCancelReason kotlin(
      final SorafsOrderbookCancelReason value) {
    return org.hyperledger.iroha.sdk.sorafs.SorafsOrderbookCancelReason.valueOf(value.name());
  }
}
