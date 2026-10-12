package org.hyperledger.iroha.sdk.sorafs

import java.math.BigInteger
import java.nio.charset.StandardCharsets

/** Orderbook payload kind accepted by the Rust-backed SoraFS reference validator. */
enum class SorafsOrderbookPayloadKind(
    @JvmField val bridgeCode: Int,
    @JvmField val defaultLabel: String,
    @JvmField val isUserSignedPayload: Boolean,
) {
    ORDER_REQUEST(1, "order-request.to", true),
    ORDER_CANCEL(2, "order-cancel.to", true),
    TRADE_EVENT(3, "trade-event.to", false),
    SETTLEMENT_CHANNEL(4, "settlement-channel.to", false),
    SETTLEMENT_RECEIPT(5, "settlement-receipt.to", true),
}

/** PDP payload kind accepted by the Rust-backed SoraFS reference validator. */
enum class SorafsPdpPayloadKind(
    @JvmField val bridgeCode: Int,
    @JvmField val defaultLabel: String,
) {
    COMMITMENT(1, "commitment.to"),
    CHALLENGE(2, "challenge.to"),
    PROOF(3, "proof.to"),
}

/** Payload kind accepted by heterogeneous SoraFS fixture-bundle validation. */
enum class SorafsFixtureBundlePayloadKind(
    @JvmField val bridgeCode: Int,
    @JvmField val defaultLabel: String,
) {
    PROVIDER_ADVERT(1, "provider-advert.to"),
    PROVIDER_ADMISSION_ENVELOPE(2, "provider-admission-envelope.to"),
    REPLICATION_ORDER(3, "replication-order.to"),
    POR_CHALLENGE(4, "por-challenge.to"),
    POR_PROOF(5, "por-proof.to"),
    POTR_RECEIPT(6, "potr-receipt.to"),
    REPAIR_EVIDENCE(7, "repair-evidence.to"),
    REPAIR_REPORT(8, "repair-report.to"),
    REPAIR_TASK_RECORD(9, "repair-task-record.to"),
    REPAIR_SLASH_PROPOSAL(10, "repair-slash-proposal.to"),
    REPAIR_TASK_EVENT(11, "repair-task-event.to"),
    ORDERBOOK_ORDER_REQUEST(12, "orderbook-order-request.to"),
    ORDERBOOK_ORDER_CANCEL(13, "orderbook-order-cancel.to"),
    ORDERBOOK_TRADE_EVENT(14, "orderbook-trade-event.to"),
    ORDERBOOK_SETTLEMENT_CHANNEL(15, "orderbook-settlement-channel.to"),
    ORDERBOOK_SETTLEMENT_RECEIPT(16, "orderbook-settlement-receipt.to"),
    PDP_COMMITMENT(17, "pdp-commitment.to"),
    PDP_CHALLENGE(18, "pdp-challenge.to"),
    PDP_PROOF(19, "pdp-proof.to"),
}

/** Immutable typed input for heterogeneous fixture-bundle validation. */
class SorafsFixtureBundlePayloadInput(
    @JvmField val kind: SorafsFixtureBundlePayloadKind,
    noritoBytes: ByteArray,
    @JvmField val label: String? = null,
) {
    private val payload = noritoBytes.copyOf()

    /** Return a detached copy of the canonical Norito payload bytes. */
    fun noritoBytes(): ByteArray = payload.copyOf()
}

/** PoP payload kind accepted by the Rust-backed SoraFS reference validator. */
enum class SorafsPopPayloadKind(
    @JvmField val bridgeCode: Int,
    @JvmField val defaultLabel: String,
) {
    CREDENTIAL(1, "pop-credential.to"),
    COMMITMENT_ROOT(2, "pop-commitment-root.to"),
    REVOCATION_LIST(3, "pop-revocation-list.to"),
    ENROLLMENT_REQUEST(4, "pop-enrollment-request.to"),
    RENEWAL_REQUEST(5, "pop-renewal-request.to"),
    MEMBERSHIP_PROOF(6, "pop-membership-proof.to"),
    ISSUED_CREDENTIAL_BUNDLE(7, "pop-issued-credential-bundle.to"),
}

/** Hedging and billing payload kind accepted by the Rust-backed SoraFS reference validator. */
enum class SorafsHedgingPayloadKind(
    @JvmField val bridgeCode: Int,
    @JvmField val defaultLabel: String,
) {
    PRICE_FEED(1, "hedging-price-feed.to"),
    REFERENCE_PRICE_DECISION(2, "hedging-reference-price-decision.to"),
    BILLING_LINE_ITEM(3, "billing-line-item.to"),
    BILLING_STATEMENT(4, "billing-statement.to"),
}

/** Side selector for field-level SoraFS orderbook order builders. */
enum class SorafsOrderbookSide(@JvmField val bridgeCode: Int) {
    BID(1),
    ASK(2),
}

/** Storage tier selector for field-level SoraFS orderbook order builders. */
enum class SorafsOrderbookTier(@JvmField val bridgeCode: Int) {
    HOT(1),
    WARM(2),
    ARCHIVE(3),
}

/** Cancellation reason selector for field-level SoraFS orderbook cancel builders. */
enum class SorafsOrderbookCancelReason(@JvmField val bridgeCode: Int) {
    OWNER_REQUESTED(1),
    EXPIRED(2),
    GOVERNANCE(3),
    REPLACED(4),
}

/** Thin JVM/JNI wrapper around the SoraFS reference validators in `connect_norito_bridge`. */
class SorafsReferenceValidators private constructor() {
    companion object {
        private const val LIBRARY_NAME = "connect_norito_bridge"
        const val REQUIRED_BRIDGE_ABI_VERSION: Int = 29
        /** Canonical maximum byte length for a V1 orderbook owner account. */
        const val ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1: Int = 256
        /** Maximum complete-root or checkpoint-tail window accepted by one head validation. */
        const val GOVERNANCE_DAG_MAX_BLOCKS_V1: Int = 64
        /** Canonical byte length for every Governance DAG CID. */
        const val GOVERNANCE_DAG_CID_BYTES_V1: Int = 32
        /** Maximum aggregate payload, CID, and label bytes accepted by one reference call. */
        const val REFERENCE_MAX_INPUT_BYTES_V1: Int = 67_108_864
        /** Maximum UTF-8 bytes accepted for one diagnostic input label. */
        const val REFERENCE_MAX_LABEL_BYTES_V1: Int = 1_024
        /** Maximum payload count accepted by one fixture-bundle call. */
        const val FIXTURE_BUNDLE_MAX_PAYLOADS_V1: Int = 64
        private val nativeAvailable: Boolean = loadLibrary()

        @JvmStatic
        fun isNativeAvailable(): Boolean = nativeAvailable

        internal fun isBridgeAbiSupported(version: Int): Boolean =
            version == REQUIRED_BRIDGE_ABI_VERSION

        internal fun isGovernanceDagBridgeSupported(version: Int, hasSymbols: Boolean): Boolean =
            isBridgeAbiSupported(version) && hasSymbols

        internal fun isFixtureBundleBridgeSupported(version: Int, hasSymbols: Boolean): Boolean =
            isBridgeAbiSupported(version) && hasSymbols

        internal fun isGovernanceLogNodeBridgeSupported(
            version: Int,
            hasSymbols: Boolean,
        ): Boolean = isBridgeAbiSupported(version) && hasSymbols

        internal fun isAppealFinanceBridgeSupported(
            version: Int,
            hasSymbols: Boolean,
        ): Boolean = isBridgeAbiSupported(version) && hasSymbols

        @JvmStatic
        @JvmOverloads
        fun validateOrderbookPayloadJson(
            kind: SorafsOrderbookPayloadKind,
            noritoBytes: ByteArray,
            label: String? = null,
            generatedAtUnix: Long = currentEpochSeconds(),
        ): String {
            requireGeneratedAt(generatedAtUnix)
            val payload = noritoBytes.copyOf()
            val labelBytes = labelBytes(label, kind.defaultLabel)
            requireNative()
            return requireJsonOutput(
                nativeValidateOrderbookPayloadJson(
                    kind.bridgeCode,
                    payload,
                    labelBytes,
                    generatedAtUnix,
                ),
                "SoraFS orderbook validation",
            )
        }

        /**
         * Validates canonical PoP wire shape and metadata through the native validator.
         * Membership proof results do not verify Halo2, authorize a recipient, or consume nullifiers.
         */
        @JvmStatic
        @JvmOverloads
        fun validatePopPayloadJson(
            kind: SorafsPopPayloadKind,
            noritoBytes: ByteArray,
            label: String? = null,
            generatedAtUnix: Long = currentEpochSeconds(),
        ): String {
            requireGeneratedAt(generatedAtUnix)
            val payload = noritoBytes.copyOf()
            val labelBytes = labelBytes(label, kind.defaultLabel)
            requireNative()
            return requireJsonOutput(
                nativeValidatePopPayloadJson(
                    kind.bridgeCode,
                    payload,
                    labelBytes,
                    generatedAtUnix,
                ),
                "SoraFS PoP validation",
            )
        }

        @JvmStatic
        @JvmOverloads
        fun validateHedgingPayloadJson(
            kind: SorafsHedgingPayloadKind,
            noritoBytes: ByteArray,
            label: String? = null,
            generatedAtUnix: Long = currentEpochSeconds(),
        ): String {
            requireGeneratedAt(generatedAtUnix)
            val payload = noritoBytes.copyOf()
            val labelBytes = labelBytes(label, kind.defaultLabel)
            requireNative()
            return requireJsonOutput(
                nativeValidateHedgingPayloadJson(
                    kind.bridgeCode,
                    payload,
                    labelBytes,
                    generatedAtUnix,
                ),
                "SoraFS hedging validation",
            )
        }

        /** Validate one canonical appeal-finance `CancelAssetLock` V1 payload. */
        @JvmStatic
        @JvmOverloads
        fun validateAppealFinanceCancelAssetLockJson(
            noritoBytes: ByteArray,
            label: String? = null,
            generatedAtUnix: Long = currentEpochSeconds(),
        ): String {
            requireGeneratedAt(generatedAtUnix)
            val payload = boundedReferencePayload(noritoBytes, "noritoBytes")
            val labelBytes = labelBytes(label, "cancel_asset_lock_v1.to")
            requireAggregateReferenceBytes(payload.size, labelBytes.size)
            requireNative()
            return requireJsonOutput(
                nativeValidateAppealFinanceCancelAssetLockJson(
                    payload,
                    labelBytes,
                    generatedAtUnix,
                ),
                "SoraFS appeal-finance CancelAssetLock validation",
            )
        }

        /** Validate a bounded heterogeneous fixture bundle and canonical cross-links. */
        @JvmStatic
        @JvmOverloads
        fun validateFixtureBundleJson(
            payloads: List<SorafsFixtureBundlePayloadInput>,
            nowUnix: Long = currentEpochSeconds(),
            generatedAtUnix: Long = nowUnix,
        ): String {
            require(payloads.size in 1..FIXTURE_BUNDLE_MAX_PAYLOADS_V1) {
                "payloads must contain 1..$FIXTURE_BUNDLE_MAX_PAYLOADS_V1 entries"
            }
            requireGeneratedAt(nowUnix)
            requireGeneratedAt(generatedAtUnix)
            val kinds = ByteArray(payloads.size)
            val nativePayloads = Array(payloads.size) { ByteArray(0) }
            val labels = Array(payloads.size) { ByteArray(0) }
            var aggregateBytes = 0L
            payloads.forEachIndexed { index, input ->
                kinds[index] = input.kind.bridgeCode.toByte()
                nativePayloads[index] =
                    boundedReferencePayload(input.noritoBytes(), "payloads[$index].noritoBytes")
                labels[index] = labelBytes(input.label, input.kind.defaultLabel)
                aggregateBytes += nativePayloads[index].size.toLong() + labels[index].size.toLong()
                require(aggregateBytes <= REFERENCE_MAX_INPUT_BYTES_V1.toLong()) {
                    "fixture-bundle inputs exceed $REFERENCE_MAX_INPUT_BYTES_V1 aggregate bytes"
                }
            }
            requireNative()
            return requireJsonOutput(
                nativeValidateFixtureBundleJson(
                    kinds,
                    nativePayloads,
                    labels,
                    nowUnix,
                    generatedAtUnix,
                ),
                "SoraFS fixture-bundle validation",
            )
        }

        /** Validate one canonical signed `GovernanceLogNodeV1` against its expected node CID. */
        @JvmStatic
        fun validateGovernanceLogNodeJson(
            noritoBytes: ByteArray,
            expectedNodeCid: ByteArray,
        ): String =
            validateGovernanceLogNodeJson(
                noritoBytes,
                null,
                expectedNodeCid,
                currentEpochSeconds(),
            )

        /** Validate one canonical signed `GovernanceLogNodeV1` against its expected node CID. */
        @JvmStatic
        @JvmOverloads
        fun validateGovernanceLogNodeJson(
            noritoBytes: ByteArray,
            label: String?,
            expectedNodeCid: ByteArray,
            generatedAtUnix: Long = currentEpochSeconds(),
        ): String {
            requireGeneratedAt(generatedAtUnix)
            val payload = boundedReferencePayload(noritoBytes, "noritoBytes")
            val labelBytes = labelBytes(label, "governance.to")
            require(expectedNodeCid.size == GOVERNANCE_DAG_CID_BYTES_V1) {
                "expectedNodeCid must contain exactly $GOVERNANCE_DAG_CID_BYTES_V1 bytes"
            }
            val expectedCid = expectedNodeCid.copyOf()
            requireAggregateReferenceBytes(payload.size, labelBytes.size, expectedCid.size)
            requireNative()
            return requireJsonOutput(
                nativeValidateGovernanceLogNodeJson(
                    payload,
                    labelBytes,
                    expectedCid,
                    generatedAtUnix,
                ),
                "SoraFS governance log node validation",
            )
        }

        /**
         * Validate one canonical `GovernanceDagBlockV1`.
         *
         * Passing `expectedBlockCid = null` omits the external CID equality check; the native
         * validator still recomputes and validates the CID embedded in the block.
         */
        @JvmStatic
        @JvmOverloads
        fun validateGovernanceDagBlockJson(
            noritoBytes: ByteArray,
            label: String? = null,
            expectedBlockCid: ByteArray? = null,
            generatedAtUnix: Long = currentEpochSeconds(),
        ): String {
            requireGeneratedAt(generatedAtUnix)
            val payload = boundedReferencePayload(noritoBytes, "noritoBytes")
            val labelBytes = labelBytes(label, "governance-dag-block.to")
            val expectedCid =
                expectedBlockCid?.let {
                    require(it.size == GOVERNANCE_DAG_CID_BYTES_V1) {
                        "expectedBlockCid must contain exactly $GOVERNANCE_DAG_CID_BYTES_V1 bytes"
                    }
                    it.copyOf()
                } ?: ByteArray(0)
            requireAggregateReferenceBytes(payload.size, labelBytes.size, expectedCid.size)
            requireNative()
            return requireJsonOutput(
                nativeValidateGovernanceDagBlockJson(
                    payload,
                    labelBytes,
                    expectedCid,
                    generatedAtUnix,
                ),
                "SoraFS governance DAG block validation",
            )
        }

        /**
         * Validate one signed `GovernanceDagHeadV1` against either a complete root-to-head
         * history or its signed checkpoint-anchored tail.
         *
         * When supplied, `blockLabels` must contain exactly one label per block.
         */
        @JvmStatic
        @JvmOverloads
        fun validateGovernanceDagHeadChainJson(
            head: ByteArray,
            blocks: List<ByteArray>,
            headLabel: String? = null,
            blockLabels: List<String?>? = null,
            generatedAtUnix: Long = currentEpochSeconds(),
        ): String {
            requireGeneratedAt(generatedAtUnix)
            require(blocks.size in 1..GOVERNANCE_DAG_MAX_BLOCKS_V1) {
                "blocks must contain 1..$GOVERNANCE_DAG_MAX_BLOCKS_V1 entries"
            }
            require(blockLabels == null || blockLabels.size == blocks.size) {
                "blockLabels must contain exactly one entry per block"
            }
            val headPayload = boundedReferencePayload(head, "head")
            val headLabelBytes = labelBytes(headLabel, "governance-dag-head.to")
            val blockPayloads = Array(blocks.size) { index ->
                boundedReferencePayload(blocks[index], "blocks[$index]")
            }
            val blockLabelPayloads = Array(blocks.size) { index ->
                labelBytes(blockLabels?.get(index), "governance-dag-block-$index.to")
            }
            var aggregateBytes = headPayload.size.toLong() + headLabelBytes.size.toLong()
            for (index in blockPayloads.indices) {
                aggregateBytes +=
                    blockPayloads[index].size.toLong() + blockLabelPayloads[index].size.toLong()
                require(aggregateBytes <= REFERENCE_MAX_INPUT_BYTES_V1.toLong()) {
                    "governance DAG head-chain inputs exceed $REFERENCE_MAX_INPUT_BYTES_V1 aggregate bytes"
                }
            }
            requireNative()
            return requireJsonOutput(
                nativeValidateGovernanceDagHeadChainJson(
                    headPayload,
                    headLabelBytes,
                    blockPayloads,
                    blockLabelPayloads,
                    generatedAtUnix,
                ),
                "SoraFS governance DAG head-chain validation",
            )
        }

        @JvmStatic
        fun signOrderbookPayload(
            kind: SorafsOrderbookPayloadKind,
            noritoBytes: ByteArray,
            privateKey: ByteArray,
        ): ByteArray {
            val selected = requireUserSignedOrderbookKind(kind)
            val payload = noritoBytes.copyOf()
            val key = requirePrivateKey(privateKey)
            try {
                requireNative()
                return requireBytesOutput(
                    nativeSignOrderbookPayload(selected.bridgeCode, payload, key),
                    "SoraFS orderbook signing",
                )
            } finally {
                key.fill(0)
            }
        }

        /** Derive the canonical V1 order id from owner-account bytes and nonce. */
        @JvmStatic
        fun deriveOrderbookOrderId(ownerAccount: ByteArray, nonce: Long): ByteArray {
            val ownerBytes = requireNonEmptyBytes(ownerAccount, "ownerAccount")
            requirePositive(nonce, "nonce")
            requireNative()
            val orderId = requireBytesOutput(
                nativeDeriveOrderbookOrderId(ownerBytes, nonce),
                "SoraFS orderbook order id derivation",
            )
            check(orderId.size == 32) {
                "SoraFS orderbook order id derivation returned a non-32-byte identifier"
            }
            return orderId
        }

        /** Build and sign an order request with its canonical derived order id. */
        @JvmStatic
        @JvmOverloads
        fun buildSignedOrderbookOrderRequest(
            side: SorafsOrderbookSide,
            tier: SorafsOrderbookTier,
            pricePerGib: String,
            quantityGib: Long,
            ownerAccount: ByteArray,
            providerId: ByteArray?,
            expiryUnix: Long,
            nonce: Long,
            makerFeeBps: Int,
            takerFeeBps: Int,
            privateKey: ByteArray,
            remainingGib: Long = quantityGib,
        ): ByteArray =
            buildSignedOrderbookOrderRequest(
                deriveOrderbookOrderId(ownerAccount, nonce),
                side,
                tier,
                pricePerGib,
                quantityGib,
                ownerAccount,
                providerId,
                expiryUnix,
                nonce,
                makerFeeBps,
                takerFeeBps,
                privateKey,
                remainingGib,
            )

        @JvmStatic
        @JvmOverloads
        fun buildSignedOrderbookOrderRequest(
            orderId: ByteArray,
            side: SorafsOrderbookSide,
            tier: SorafsOrderbookTier,
            pricePerGib: String,
            quantityGib: Long,
            ownerAccount: ByteArray,
            providerId: ByteArray?,
            expiryUnix: Long,
            nonce: Long,
            makerFeeBps: Int,
            takerFeeBps: Int,
            privateKey: ByteArray,
            remainingGib: Long = quantityGib,
        ): ByteArray {
            val orderIdBytes = requireFixed32(orderId, "orderId")
            val ownerBytes = requireNonEmptyBytes(ownerAccount, "ownerAccount")
            val providerBytes = requireProviderId(side, providerId)
            val priceBytes = xorQuantityBytes(pricePerGib, "pricePerGib", positive = true)
            requirePositive(quantityGib, "quantityGib")
            requirePositive(remainingGib, "remainingGib")
            requirePositive(expiryUnix, "expiryUnix")
            requirePositive(nonce, "nonce")
            val canonicalOrderId = deriveOrderbookOrderId(ownerBytes, nonce)
            require(orderIdBytes.contentEquals(canonicalOrderId)) {
                "orderId must equal the canonical owner-and-nonce derivation"
            }
            val makerFee = requireFeeBps(makerFeeBps, "makerFeeBps")
            val takerFee = requireFeeBps(takerFeeBps, "takerFeeBps")
            val key = requirePrivateKey(privateKey)
            try {
                requireNative()
                return requireBytesOutput(
                    nativeBuildSignedOrderbookOrderRequest(
                        orderIdBytes,
                        side.bridgeCode,
                        tier.bridgeCode,
                        priceBytes,
                        quantityGib,
                        remainingGib,
                        ownerBytes,
                        providerBytes,
                        expiryUnix,
                        nonce,
                        makerFee,
                        takerFee,
                        key,
                    ),
                    "SoraFS orderbook order request builder",
                )
            } finally {
                key.fill(0)
            }
        }

        @JvmStatic
        fun buildSignedOrderbookOrderCancel(
            orderId: ByteArray,
            ownerAccount: ByteArray,
            reason: SorafsOrderbookCancelReason,
            nonce: Long,
            privateKey: ByteArray,
        ): ByteArray {
            val orderIdBytes = requireFixed32(orderId, "orderId")
            val ownerBytes = requireNonEmptyBytes(ownerAccount, "ownerAccount")
            requirePositive(nonce, "nonce")
            val key = requirePrivateKey(privateKey)
            try {
                requireNative()
                return requireBytesOutput(
                    nativeBuildSignedOrderbookOrderCancel(
                        orderIdBytes,
                        ownerBytes,
                        reason.bridgeCode,
                        nonce,
                        key,
                    ),
                    "SoraFS orderbook cancel builder",
                )
            } finally {
                key.fill(0)
            }
        }

        @JvmStatic
        fun buildSignedOrderbookSettlementReceipt(
            receiptId: ByteArray,
            channelId: ByteArray,
            tradeId: ByteArray,
            rangeStart: Long,
            rangeEnd: Long,
            chunkHash: ByteArray,
            bytesDelivered: Long,
            xorDebited: String,
            providerCredit: String,
            feeAmount: String,
            issuedAtUnix: Long,
            privateKey: ByteArray,
        ): ByteArray {
            val receiptIdBytes = requireFixed32(receiptId, "receiptId")
            val channelIdBytes = requireFixed32(channelId, "channelId")
            val tradeIdBytes = requireFixed32(tradeId, "tradeId")
            requireNonNegative(rangeStart, "rangeStart")
            requirePositive(rangeEnd, "rangeEnd")
            val chunkHashBytes = requireFixed32(chunkHash, "chunkHash")
            requirePositive(bytesDelivered, "bytesDelivered")
            val debitBytes = xorQuantityBytes(xorDebited, "xorDebited", positive = true)
            val creditBytes = xorQuantityBytes(providerCredit, "providerCredit", positive = false)
            val feeBytes = xorQuantityBytes(feeAmount, "feeAmount", positive = false)
            requirePositive(issuedAtUnix, "issuedAtUnix")
            val key = requirePrivateKey(privateKey)
            try {
                requireNative()
                return requireBytesOutput(
                    nativeBuildSignedOrderbookSettlementReceipt(
                        receiptIdBytes,
                        channelIdBytes,
                        tradeIdBytes,
                        rangeStart,
                        rangeEnd,
                        chunkHashBytes,
                        bytesDelivered,
                        debitBytes,
                        creditBytes,
                        feeBytes,
                        issuedAtUnix,
                        key,
                    ),
                    "SoraFS orderbook settlement receipt builder",
                )
            } finally {
                key.fill(0)
            }
        }

        @JvmStatic
        @JvmOverloads
        fun validatePdpPayloadJson(
            kind: SorafsPdpPayloadKind,
            noritoBytes: ByteArray,
            label: String? = null,
            generatedAtUnix: Long = currentEpochSeconds(),
        ): String {
            requireGeneratedAt(generatedAtUnix)
            val payload = noritoBytes.copyOf()
            val labelBytes = labelBytes(label, kind.defaultLabel)
            requireNative()
            return requireJsonOutput(
                nativeValidatePdpPayloadJson(
                    kind.bridgeCode,
                    payload,
                    labelBytes,
                    generatedAtUnix,
                ),
                "SoraFS PDP validation",
            )
        }

        @JvmStatic
        @JvmOverloads
        fun validatePdpCommitmentChallengeJson(
            commitment: ByteArray,
            challenge: ByteArray,
            commitmentLabel: String? = null,
            challengeLabel: String? = null,
            generatedAtUnix: Long = currentEpochSeconds(),
        ): String {
            requireGeneratedAt(generatedAtUnix)
            val commitmentPayload = commitment.copyOf()
            val commitmentLabelBytes = labelBytes(commitmentLabel, SorafsPdpPayloadKind.COMMITMENT.defaultLabel)
            val challengePayload = challenge.copyOf()
            val challengeLabelBytes = labelBytes(challengeLabel, SorafsPdpPayloadKind.CHALLENGE.defaultLabel)
            requireNative()
            return requireJsonOutput(
                nativeValidatePdpCommitmentChallengeJson(
                    commitmentPayload,
                    commitmentLabelBytes,
                    challengePayload,
                    challengeLabelBytes,
                    generatedAtUnix,
                ),
                "SoraFS PDP commitment/challenge validation",
            )
        }

        @JvmStatic
        @JvmOverloads
        fun validatePdpChallengeProofJson(
            challenge: ByteArray,
            proof: ByteArray,
            challengeLabel: String? = null,
            proofLabel: String? = null,
            generatedAtUnix: Long = currentEpochSeconds(),
        ): String {
            requireGeneratedAt(generatedAtUnix)
            val challengePayload = challenge.copyOf()
            val challengeLabelBytes = labelBytes(challengeLabel, SorafsPdpPayloadKind.CHALLENGE.defaultLabel)
            val proofPayload = proof.copyOf()
            val proofLabelBytes = labelBytes(proofLabel, SorafsPdpPayloadKind.PROOF.defaultLabel)
            requireNative()
            return requireJsonOutput(
                nativeValidatePdpChallengeProofJson(
                    challengePayload,
                    challengeLabelBytes,
                    proofPayload,
                    proofLabelBytes,
                    generatedAtUnix,
                ),
                "SoraFS PDP challenge/proof validation",
            )
        }

        @JvmStatic
        @JvmOverloads
        fun validatePdpBundleJson(
            commitment: ByteArray,
            challenge: ByteArray,
            proof: ByteArray,
            commitmentLabel: String? = null,
            challengeLabel: String? = null,
            proofLabel: String? = null,
            generatedAtUnix: Long = currentEpochSeconds(),
        ): String {
            requireGeneratedAt(generatedAtUnix)
            val commitmentPayload = commitment.copyOf()
            val commitmentLabelBytes = labelBytes(commitmentLabel, SorafsPdpPayloadKind.COMMITMENT.defaultLabel)
            val challengePayload = challenge.copyOf()
            val challengeLabelBytes = labelBytes(challengeLabel, SorafsPdpPayloadKind.CHALLENGE.defaultLabel)
            val proofPayload = proof.copyOf()
            val proofLabelBytes = labelBytes(proofLabel, SorafsPdpPayloadKind.PROOF.defaultLabel)
            requireNative()
            return requireJsonOutput(
                nativeValidatePdpBundleJson(
                    commitmentPayload,
                    commitmentLabelBytes,
                    challengePayload,
                    challengeLabelBytes,
                    proofPayload,
                    proofLabelBytes,
                    generatedAtUnix,
                ),
                "SoraFS PDP bundle validation",
            )
        }

        private fun currentEpochSeconds(): Long = System.currentTimeMillis() / 1000L

        private fun requireGeneratedAt(generatedAtUnix: Long) {
            require(generatedAtUnix >= 0L) { "generatedAtUnix must be non-negative" }
        }

        private fun requireNative() {
            check(nativeAvailable) { "$LIBRARY_NAME is not available in this runtime" }
        }

        private fun requireUserSignedOrderbookKind(kind: SorafsOrderbookPayloadKind): SorafsOrderbookPayloadKind {
            require(kind.isUserSignedPayload) { "orderbook payload kind ${kind.name} cannot be signed" }
            return kind
        }

        private fun requirePrivateKey(privateKey: ByteArray): ByteArray {
            require(privateKey.size == 32) { "privateKey must be 32 bytes" }
            require(privateKey.any { byte -> byte.toInt() != 0 }) { "privateKey must not be all zero" }
            return privateKey.copyOf()
        }

        private fun requireFixed32(bytes: ByteArray, field: String): ByteArray {
            require(bytes.size == 32) { "$field must be 32 bytes" }
            return bytes.copyOf()
        }

        private fun requireProviderId(
            side: SorafsOrderbookSide,
            providerId: ByteArray?,
        ): ByteArray {
            if (side == SorafsOrderbookSide.BID) {
                require(providerId == null || providerId.isEmpty()) {
                    "providerId must be absent or empty for bid orders"
                }
                return ByteArray(0)
            }
            require(providerId != null && providerId.size == 32) {
                "providerId must be exactly 32 bytes for ask orders"
            }
            require(providerId.any { it.toInt() != 0 }) {
                "providerId must not be all zero"
            }
            return providerId.copyOf()
        }

        private fun requireNonEmptyBytes(bytes: ByteArray, field: String): ByteArray {
            require(bytes.isNotEmpty()) { "$field must not be empty" }
            require(bytes.size <= ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1) {
                "$field must be at most $ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1 bytes"
            }
            return bytes.copyOf()
        }

        private fun requireNonNegative(value: Long, field: String) {
            require(value >= 0L) { "$field must be non-negative" }
        }

        private fun requirePositive(value: Long, field: String) {
            require(value > 0L) { "$field must be greater than zero" }
        }

        private fun requireFeeBps(value: Int, field: String): Int {
            require(value in 0..0xFFFF) { "$field must fit in u16 basis points" }
            return value
        }

        private fun xorQuantityBytes(value: String, field: String, positive: Boolean): ByteArray {
            require(value.length <= 155) { "$field exceeds the canonical XOR quantity text bound" }
            val match = Regex("^(0|[1-9][0-9]*)(?:\\.([0-9]*[1-9]))?$").matchEntire(value)
            require(match != null) { "$field must be a canonical non-negative XOR quantity" }
            val fractional = match.groupValues[2]
            require(fractional.length <= 9) { "$field must have at most 9 fractional decimal places" }
            val mantissa = BigInteger(match.groupValues[1] + fractional)
            require(mantissa <= BigInteger.ONE.shiftLeft(511).subtract(BigInteger.ONE)) {
                "$field exceeds the 512-bit signed quantity domain"
            }
            if (positive) require(mantissa.signum() > 0) { "$field must be greater than zero" }
            return value.toByteArray(StandardCharsets.UTF_8)
        }

        private fun labelBytes(label: String?, fallback: String): ByteArray {
            val value = label ?: fallback
            require(!hasUnpairedSurrogate(value)) {
                "label must be valid Unicode text"
            }
            require(value.isNotBlank()) { "label must not be blank" }
            require(value.trim() == value) { "label must not contain surrounding whitespace" }
            require(value.none(Char::isISOControl)) {
                "label must not contain control characters"
            }
            val bytes = value.toByteArray(StandardCharsets.UTF_8)
            require(bytes.size <= REFERENCE_MAX_LABEL_BYTES_V1) {
                "label must be at most $REFERENCE_MAX_LABEL_BYTES_V1 UTF-8 bytes"
            }
            return bytes
        }

        private fun hasUnpairedSurrogate(value: String): Boolean {
            var index = 0
            while (index < value.length) {
                val character = value[index]
                when {
                    Character.isHighSurrogate(character) -> {
                        if (
                            index + 1 >= value.length ||
                            !Character.isLowSurrogate(value[index + 1])
                        ) {
                            return true
                        }
                        index += 2
                    }

                    Character.isLowSurrogate(character) -> return true
                    else -> index += 1
                }
            }
            return false
        }

        private fun boundedReferencePayload(payload: ByteArray, field: String): ByteArray {
            require(payload.size <= REFERENCE_MAX_INPUT_BYTES_V1) {
                "$field must be at most $REFERENCE_MAX_INPUT_BYTES_V1 bytes"
            }
            return payload.copyOf()
        }

        private fun requireAggregateReferenceBytes(vararg sizes: Int) {
            val aggregateBytes = sizes.fold(0L) { total, size -> total + size.toLong() }
            require(aggregateBytes <= REFERENCE_MAX_INPUT_BYTES_V1.toLong()) {
                "reference inputs exceed $REFERENCE_MAX_INPUT_BYTES_V1 aggregate bytes"
            }
        }

        private fun requireJsonOutput(output: ByteArray?, context: String): String {
            check(output != null) { "$context returned no outcome JSON" }
            check(output.isNotEmpty()) { "$context returned empty outcome JSON" }
            val json = String(output, StandardCharsets.UTF_8)
            check(json.trimStart().startsWith("{")) { "$context returned malformed outcome JSON" }
            return json
        }

        private fun requireBytesOutput(output: ByteArray?, context: String): ByteArray {
            check(output != null) { "$context returned no bytes" }
            check(output.isNotEmpty()) { "$context returned empty bytes" }
            return output.copyOf()
        }

        private fun loadLibrary(): Boolean =
            try {
                System.loadLibrary(LIBRARY_NAME)
                val abiVersion = nativeBridgeAbiVersion()
                isGovernanceDagBridgeSupported(
                    abiVersion,
                    nativeHasGovernanceDagSymbols(),
                ) &&
                    isFixtureBundleBridgeSupported(
                        abiVersion,
                        nativeHasFixtureBundleSymbols(),
                    ) &&
                    isGovernanceLogNodeBridgeSupported(
                        abiVersion,
                        nativeHasGovernanceLogNodeSymbols(),
                    ) &&
                    isAppealFinanceBridgeSupported(
                        abiVersion,
                        nativeHasAppealFinanceSymbols(),
                    )
            } catch (_: UnsatisfiedLinkError) {
                false
            } catch (_: SecurityException) {
                false
            }

        @JvmStatic
        private external fun nativeBridgeAbiVersion(): Int

        @JvmStatic
        private external fun nativeHasGovernanceDagSymbols(): Boolean

        @JvmStatic
        private external fun nativeHasFixtureBundleSymbols(): Boolean

        @JvmStatic
        private external fun nativeHasGovernanceLogNodeSymbols(): Boolean

        @JvmStatic
        private external fun nativeHasAppealFinanceSymbols(): Boolean

        @JvmStatic
        private external fun nativeValidateOrderbookPayloadJson(
            kind: Int,
            payload: ByteArray,
            label: ByteArray,
            generatedAtUnix: Long,
        ): ByteArray?

        @JvmStatic
        private external fun nativeValidatePopPayloadJson(
            kind: Int,
            payload: ByteArray,
            label: ByteArray,
            generatedAtUnix: Long,
        ): ByteArray?

        @JvmStatic
        private external fun nativeValidateHedgingPayloadJson(
            kind: Int,
            payload: ByteArray,
            label: ByteArray,
            generatedAtUnix: Long,
        ): ByteArray?

        @JvmStatic
        private external fun nativeValidateAppealFinanceCancelAssetLockJson(
            payload: ByteArray,
            label: ByteArray,
            generatedAtUnix: Long,
        ): ByteArray?

        @JvmStatic
        private external fun nativeValidateFixtureBundleJson(
            kinds: ByteArray,
            payloads: Array<ByteArray>,
            labels: Array<ByteArray>,
            nowUnix: Long,
            generatedAtUnix: Long,
        ): ByteArray?

        @JvmStatic
        private external fun nativeValidateGovernanceLogNodeJson(
            payload: ByteArray,
            label: ByteArray,
            expectedNodeCid: ByteArray,
            generatedAtUnix: Long,
        ): ByteArray?

        @JvmStatic
        private external fun nativeValidateGovernanceDagBlockJson(
            payload: ByteArray,
            label: ByteArray,
            expectedBlockCid: ByteArray,
            generatedAtUnix: Long,
        ): ByteArray?

        @JvmStatic
        private external fun nativeValidateGovernanceDagHeadChainJson(
            head: ByteArray,
            headLabel: ByteArray,
            blocks: Array<ByteArray>,
            blockLabels: Array<ByteArray>,
            generatedAtUnix: Long,
        ): ByteArray?

        @JvmStatic
        private external fun nativeSignOrderbookPayload(
            kind: Int,
            payload: ByteArray,
            privateKey: ByteArray,
        ): ByteArray?

        @JvmStatic
        private external fun nativeDeriveOrderbookOrderId(
            ownerAccount: ByteArray,
            nonce: Long,
        ): ByteArray?

        @JvmStatic
        private external fun nativeBuildSignedOrderbookOrderRequest(
            orderId: ByteArray,
            side: Int,
            tier: Int,
            pricePerGib: ByteArray,
            quantityGib: Long,
            remainingGib: Long,
            ownerAccount: ByteArray,
            providerId: ByteArray,
            expiryUnix: Long,
            nonce: Long,
            makerFeeBps: Int,
            takerFeeBps: Int,
            privateKey: ByteArray,
        ): ByteArray?

        @JvmStatic
        private external fun nativeBuildSignedOrderbookOrderCancel(
            orderId: ByteArray,
            ownerAccount: ByteArray,
            reason: Int,
            nonce: Long,
            privateKey: ByteArray,
        ): ByteArray?

        @JvmStatic
        private external fun nativeBuildSignedOrderbookSettlementReceipt(
            receiptId: ByteArray,
            channelId: ByteArray,
            tradeId: ByteArray,
            rangeStart: Long,
            rangeEnd: Long,
            chunkHash: ByteArray,
            bytesDelivered: Long,
            xorDebited: ByteArray,
            providerCredit: ByteArray,
            feeAmount: ByteArray,
            issuedAtUnix: Long,
            privateKey: ByteArray,
        ): ByteArray?

        @JvmStatic
        private external fun nativeValidatePdpPayloadJson(
            kind: Int,
            payload: ByteArray,
            label: ByteArray,
            generatedAtUnix: Long,
        ): ByteArray?

        @JvmStatic
        private external fun nativeValidatePdpCommitmentChallengeJson(
            commitment: ByteArray,
            commitmentLabel: ByteArray,
            challenge: ByteArray,
            challengeLabel: ByteArray,
            generatedAtUnix: Long,
        ): ByteArray?

        @JvmStatic
        private external fun nativeValidatePdpChallengeProofJson(
            challenge: ByteArray,
            challengeLabel: ByteArray,
            proof: ByteArray,
            proofLabel: ByteArray,
            generatedAtUnix: Long,
        ): ByteArray?

        @JvmStatic
        private external fun nativeValidatePdpBundleJson(
            commitment: ByteArray,
            commitmentLabel: ByteArray,
            challenge: ByteArray,
            challengeLabel: ByteArray,
            proof: ByteArray,
            proofLabel: ByteArray,
            generatedAtUnix: Long,
        ): ByteArray?
    }
}
