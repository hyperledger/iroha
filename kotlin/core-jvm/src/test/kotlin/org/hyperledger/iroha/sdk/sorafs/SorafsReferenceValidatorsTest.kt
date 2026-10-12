package org.hyperledger.iroha.sdk.sorafs

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SorafsReferenceValidatorsTest {
    private data class FixtureBundleInputSpec(
        val kind: SorafsFixtureBundlePayloadKind,
        val path: String,
    )

    private data class FixtureBundleProfile(
        val outcomePath: String,
        val nowUnix: Long,
        val inputs: List<FixtureBundleInputSpec>,
    )

    private val referenceFixtureGeneratedAtUnix = 1_700_001_234L
    private val referenceBundleProfiles =
        listOf(
            FixtureBundleProfile(
                "bundle_heterogeneous_positive_validation_outcome_v1.json",
                1_700_000_001L,
                listOf(
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
                        "replication_order/order_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.PDP_COMMITMENT,
                        "pdp/commitment_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.PDP_CHALLENGE,
                        "pdp/challenge_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.PDP_PROOF,
                        "pdp/proof_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.POR_CHALLENGE,
                        "por/challenge_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.POR_PROOF,
                        "por/proof_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.POTR_RECEIPT,
                        "potr/receipt_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.REPAIR_TASK_RECORD,
                        "repair/task_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.ORDERBOOK_ORDER_REQUEST,
                        "orderbook/order_request_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.ORDERBOOK_ORDER_CANCEL,
                        "orderbook/order_cancel_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.ORDERBOOK_TRADE_EVENT,
                        "orderbook/trade_event_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.ORDERBOOK_SETTLEMENT_CHANNEL,
                        "orderbook/settlement_channel_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.ORDERBOOK_SETTLEMENT_RECEIPT,
                        "orderbook/settlement_receipt_v1.to",
                    ),
                ),
            ),
            FixtureBundleProfile(
                "bundle_orderbook_bad_signature_negative_validation_outcome_v1.json",
                1_700_000_001L,
                listOf(
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
                        "replication_order/order_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.POR_CHALLENGE,
                        "por/challenge_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.POR_PROOF,
                        "por/proof_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.ORDERBOOK_ORDER_REQUEST,
                        "orderbook/negative/order_request_bad_signature_v1.to",
                    ),
                ),
            ),
            FixtureBundleProfile(
                "bundle_orderbook_trailing_bytes_negative_validation_outcome_v1.json",
                1_700_000_001L,
                listOf(
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
                        "replication_order/order_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.POR_CHALLENGE,
                        "por/challenge_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.POR_PROOF,
                        "por/proof_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.ORDERBOOK_ORDER_REQUEST,
                        "orderbook/negative/order_request_trailing_bytes_v1.to",
                    ),
                ),
            ),
            FixtureBundleProfile(
                "bundle_pdp_duplicate_hot_leaf_negative_validation_outcome_v1.json",
                1_700_000_001L,
                listOf(
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
                        "replication_order/order_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.PDP_COMMITMENT,
                        "pdp/commitment_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.PDP_CHALLENGE,
                        "pdp/negative/duplicate_hot_leaf_challenge_v1.to",
                    ),
                ),
            ),
            FixtureBundleProfile(
                "bundle_pdp_missing_signature_negative_validation_outcome_v1.json",
                1_700_000_001L,
                listOf(
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
                        "replication_order/order_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.PDP_COMMITMENT,
                        "pdp/commitment_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.PDP_CHALLENGE,
                        "pdp/challenge_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.PDP_PROOF,
                        "pdp/negative/missing_signature_proof_v1.to",
                    ),
                ),
            ),
            FixtureBundleProfile(
                "bundle_pdp_wrong_provider_negative_validation_outcome_v1.json",
                1_700_000_001L,
                listOf(
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
                        "replication_order/order_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.PDP_COMMITMENT,
                        "pdp/commitment_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.PDP_CHALLENGE,
                        "pdp/challenge_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.PDP_PROOF,
                        "pdp/negative/wrong_provider_proof_v1.to",
                    ),
                ),
            ),
            FixtureBundleProfile(
                "bundle_repair_manifest_mismatch_negative_validation_outcome_v1.json",
                1_700_000_001L,
                // The outcome names only the offender; the order establishes the expected digest.
                listOf(
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
                        "replication_order/order_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.REPAIR_TASK_RECORD,
                        "repair/negative/task_manifest_mismatch_v1.to",
                    ),
                ),
            ),
            FixtureBundleProfile(
                "bundle_repair_provider_unassigned_negative_validation_outcome_v1.json",
                1_700_000_001L,
                listOf(
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
                        "replication_order/order_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.REPAIR_TASK_RECORD,
                        "repair/negative/task_provider_unassigned_v1.to",
                    ),
                ),
            ),
            FixtureBundleProfile(
                "bundle_routing_admission_positive_validation_outcome_v1.json",
                300L,
                listOf(
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.PROVIDER_ADVERT,
                        "provider_admission/advert_v1.to",
                    ),
                    FixtureBundleInputSpec(
                        SorafsFixtureBundlePayloadKind.PROVIDER_ADMISSION_ENVELOPE,
                        "provider_admission/envelope_v1.to",
                    ),
                ),
            ),
        )

    private val maxScaledXor =
        "6703903964971298549787012499102923063739682910296196688861780721860882015" +
            "036773488400937149083451713845015929093243025426876941405973284973216824" +
            ".503042047"

    @Test
    fun exposesBridgeSelectors() {
        assertEquals(1, SorafsOrderbookPayloadKind.ORDER_REQUEST.bridgeCode)
        assertTrue(SorafsOrderbookPayloadKind.values().none { it.bridgeCode == 6 })
        assertTrue(
            SorafsOrderbookPayloadKind.values().none {
                it.defaultLabel == "orderbook-runtime-snapshot.to"
            },
        )
        assertTrue(SorafsOrderbookPayloadKind.ORDER_REQUEST.isUserSignedPayload)
        assertTrue(!SorafsOrderbookPayloadKind.TRADE_EVENT.isUserSignedPayload)
        assertEquals(1, SorafsPdpPayloadKind.COMMITMENT.bridgeCode)
        assertEquals(3, SorafsPdpPayloadKind.PROOF.bridgeCode)
        assertEquals(
            (1..19).toList(),
            SorafsFixtureBundlePayloadKind.values().map { it.bridgeCode },
        )
        assertEquals(
            listOf(
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
            ),
            SorafsFixtureBundlePayloadKind.values().map { it.defaultLabel },
        )
        assertEquals(1, SorafsPopPayloadKind.CREDENTIAL.bridgeCode)
        assertEquals(6, SorafsPopPayloadKind.MEMBERSHIP_PROOF.bridgeCode)
        assertEquals(7, SorafsPopPayloadKind.ISSUED_CREDENTIAL_BUNDLE.bridgeCode)
        assertEquals(1, SorafsHedgingPayloadKind.PRICE_FEED.bridgeCode)
        assertEquals(4, SorafsHedgingPayloadKind.BILLING_STATEMENT.bridgeCode)
        assertEquals(1, SorafsOrderbookSide.BID.bridgeCode)
        assertEquals(3, SorafsOrderbookTier.ARCHIVE.bridgeCode)
        assertEquals(4, SorafsOrderbookCancelReason.REPLACED.bridgeCode)
        assertEquals(29, SorafsReferenceValidators.REQUIRED_BRIDGE_ABI_VERSION)
        assertTrue(!SorafsReferenceValidators.isBridgeAbiSupported(20))
        assertTrue(!SorafsReferenceValidators.isBridgeAbiSupported(23))
        assertTrue(!SorafsReferenceValidators.isBridgeAbiSupported(24))
        assertTrue(SorafsReferenceValidators.isBridgeAbiSupported(29))
        assertTrue(!SorafsReferenceValidators.isBridgeAbiSupported(22))
        assertTrue(!SorafsReferenceValidators.isBridgeAbiSupported(21))
        assertTrue(!SorafsReferenceValidators.isGovernanceDagBridgeSupported(29, false))
        assertTrue(SorafsReferenceValidators.isGovernanceDagBridgeSupported(29, true))
        assertTrue(!SorafsReferenceValidators.isGovernanceDagBridgeSupported(27, true))
        assertTrue(!SorafsReferenceValidators.isGovernanceDagBridgeSupported(28, true))
        assertTrue(!SorafsReferenceValidators.isFixtureBundleBridgeSupported(29, false))
        assertTrue(SorafsReferenceValidators.isFixtureBundleBridgeSupported(29, true))
        assertTrue(!SorafsReferenceValidators.isFixtureBundleBridgeSupported(27, true))
        assertTrue(!SorafsReferenceValidators.isFixtureBundleBridgeSupported(28, true))
        assertTrue(!SorafsReferenceValidators.isGovernanceLogNodeBridgeSupported(29, false))
        assertTrue(SorafsReferenceValidators.isGovernanceLogNodeBridgeSupported(29, true))
        assertTrue(!SorafsReferenceValidators.isGovernanceLogNodeBridgeSupported(27, true))
        assertTrue(!SorafsReferenceValidators.isGovernanceLogNodeBridgeSupported(28, true))
        assertTrue(!SorafsReferenceValidators.isAppealFinanceBridgeSupported(29, false))
        assertTrue(SorafsReferenceValidators.isAppealFinanceBridgeSupported(29, true))
        assertTrue(!SorafsReferenceValidators.isAppealFinanceBridgeSupported(27, true))
        assertTrue(!SorafsReferenceValidators.isAppealFinanceBridgeSupported(28, true))
        assertEquals(64, SorafsReferenceValidators.GOVERNANCE_DAG_MAX_BLOCKS_V1)
        assertEquals(32, SorafsReferenceValidators.GOVERNANCE_DAG_CID_BYTES_V1)
        assertEquals(67_108_864, SorafsReferenceValidators.REFERENCE_MAX_INPUT_BYTES_V1)
        assertEquals(1_024, SorafsReferenceValidators.REFERENCE_MAX_LABEL_BYTES_V1)
        assertEquals(64, SorafsReferenceValidators.FIXTURE_BUNDLE_MAX_PAYLOADS_V1)
    }

    @Test
    fun boundsFixtureBundleBeforeNativeDispatch() {
        val empty = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.validateFixtureBundleJson(emptyList(), nowUnix = 1)
        }
        assertTrue(empty.message.orEmpty().contains("1..64"))

        val item =
            SorafsFixtureBundlePayloadInput(
                SorafsFixtureBundlePayloadKind.POR_PROOF,
                ByteArray(1),
            )
        val tooMany = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.validateFixtureBundleJson(
                List(SorafsReferenceValidators.FIXTURE_BUNDLE_MAX_PAYLOADS_V1 + 1) { item },
                nowUnix = 1,
            )
        }
        assertTrue(tooMany.message.orEmpty().contains("1..64"))
    }

    @Test
    fun fixtureBundleInputSnapshotsPayloadBytes() {
        val source = byteArrayOf(1, 2, 3)
        val input =
            SorafsFixtureBundlePayloadInput(
                SorafsFixtureBundlePayloadKind.POR_PROOF,
                source,
            )
        source[0] = 9
        val detached = input.noritoBytes()
        assertEquals(1, detached[0].toInt())
        detached[0] = 8
        assertEquals(1, input.noritoBytes()[0].toInt())
    }

    @Test
    fun rejectsMalformedUnicodeFixtureLabelBeforeNativeDispatch() {
        val input =
            SorafsFixtureBundlePayloadInput(
                SorafsFixtureBundlePayloadKind.POR_PROOF,
                ByteArray(1),
                label = "\uD800",
            )
        val error = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.validateFixtureBundleJson(
                listOf(input),
                nowUnix = 1,
            )
        }
        assertTrue(error.message.orEmpty().contains("valid Unicode"))
    }

    @Test
    fun boundsGovernanceLogNodeCidBeforeNativeDispatch() {
        for (invalidCid in listOf(ByteArray(0), ByteArray(31), ByteArray(33))) {
            val error = assertThrows(IllegalArgumentException::class.java) {
                SorafsReferenceValidators.validateGovernanceLogNodeJson(
                    noritoBytes = ByteArray(0),
                    label = null,
                    expectedNodeCid = invalidCid,
                    generatedAtUnix = 1,
                )
            }
            assertTrue(error.message.orEmpty().contains("exactly 32 bytes"))
        }
    }

    @Test
    fun rejectsGeneratedAtBeforeNativeDispatch() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.validateOrderbookPayloadJson(
                SorafsOrderbookPayloadKind.ORDER_REQUEST,
                ByteArray(0),
                generatedAtUnix = -1,
            )
        }
        assertTrue(error.message.orEmpty().contains("generatedAtUnix"))
    }

    @Test
    fun rejectsBlankLabelBeforeNativeDispatch() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.validateHedgingPayloadJson(
                SorafsHedgingPayloadKind.PRICE_FEED,
                ByteArray(0),
                label = " ",
                generatedAtUnix = 1,
            )
        }
        assertTrue(error.message.orEmpty().contains("label"))
    }

    @Test
    fun boundsGovernanceDagInputsBeforeNativeDispatch() {
        val emptyChain = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.validateGovernanceDagHeadChainJson(
                head = ByteArray(0),
                blocks = emptyList(),
                generatedAtUnix = 1,
            )
        }
        assertTrue(emptyChain.message.orEmpty().contains("1..64"))

        val tooManyBlocks = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.validateGovernanceDagHeadChainJson(
                head = ByteArray(0),
                blocks = List(65) { ByteArray(0) },
                generatedAtUnix = 1,
            )
        }
        assertTrue(tooManyBlocks.message.orEmpty().contains("1..64"))

        val mismatchedLabels = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.validateGovernanceDagHeadChainJson(
                head = ByteArray(0),
                blocks = listOf(ByteArray(0)),
                blockLabels = emptyList(),
                generatedAtUnix = 1,
            )
        }
        assertTrue(mismatchedLabels.message.orEmpty().contains("blockLabels"))

        val oversizedLabel = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.validateGovernanceDagBlockJson(
                noritoBytes = ByteArray(0),
                label = "x".repeat(1_025),
                generatedAtUnix = 1,
            )
        }
        assertTrue(oversizedLabel.message.orEmpty().contains("1024"))

        val controlLabel = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.validateGovernanceDagBlockJson(
                noritoBytes = ByteArray(0),
                label = "bad\u0001label",
                generatedAtUnix = 1,
            )
        }
        assertTrue(controlLabel.message.orEmpty().contains("control characters"))

        for (invalidCid in listOf(ByteArray(0), ByteArray(31), ByteArray(33))) {
            val invalidExpectedCid = assertThrows(IllegalArgumentException::class.java) {
                SorafsReferenceValidators.validateGovernanceDagBlockJson(
                    noritoBytes = ByteArray(0),
                    expectedBlockCid = invalidCid,
                    generatedAtUnix = 1,
                )
            }
            assertTrue(invalidExpectedCid.message.orEmpty().contains("exactly 32 bytes"))
        }
    }

    @Test
    fun rejectsNonSignableOrderbookPayloadBeforeNativeDispatch() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.signOrderbookPayload(
                SorafsOrderbookPayloadKind.TRADE_EVENT,
                ByteArray(0),
                ByteArray(32) { 0xB7.toByte() },
            )
        }
        assertTrue(error.message.orEmpty().contains("cannot be signed"))
    }

    @Test
    fun rejectsBadSigningKeyBeforeNativeDispatch() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.signOrderbookPayload(
                SorafsOrderbookPayloadKind.ORDER_REQUEST,
                ByteArray(0),
                ByteArray(32),
            )
        }
        assertTrue(error.message.orEmpty().contains("privateKey"))
    }

    @Test
    fun rejectsInvalidOrderIdDerivationInputsBeforeNativeDispatch() {
        val emptyOwner = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.deriveOrderbookOrderId(ByteArray(0), 7)
        }
        assertTrue(emptyOwner.message.orEmpty().contains("ownerAccount"))

        val zeroNonce = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.deriveOrderbookOrderId(byteArrayOf(1), 0)
        }
        assertTrue(zeroNonce.message.orEmpty().contains("nonce"))
    }

    @Test
    fun rejectsOversizedOrderbookOwnerAccountsBeforeNativeDispatch() {
        assertEquals(256, SorafsReferenceValidators.ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1)
        val oversized = ByteArray(
            SorafsReferenceValidators.ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1 + 1,
        ) { 0x45 }
        val deriveError = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.deriveOrderbookOrderId(oversized, 7)
        }
        assertTrue(deriveError.message.orEmpty().contains("at most 256 bytes"))

        val requestError = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
                side = SorafsOrderbookSide.BID,
                tier = SorafsOrderbookTier.HOT,
                pricePerGib = "1",
                quantityGib = 1,
                ownerAccount = oversized,
                providerId = null,
                expiryUnix = 1,
                nonce = 7,
                makerFeeBps = 0,
                takerFeeBps = 0,
                privateKey = ByteArray(32) { 0xB7.toByte() },
            )
        }
        assertTrue(requestError.message.orEmpty().contains("at most 256 bytes"))

        val cancelError = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.buildSignedOrderbookOrderCancel(
                orderId = ByteArray(32) { 0x11 },
                ownerAccount = oversized,
                reason = SorafsOrderbookCancelReason.OWNER_REQUESTED,
                nonce = 8,
                privateKey = ByteArray(32) { 0xB7.toByte() },
            )
        }
        assertTrue(cancelError.message.orEmpty().contains("at most 256 bytes"))
    }

    @Test
    fun rejectsOrderbookOrderRequestFieldsBeforeNativeDispatch() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
                orderId = ByteArray(31) { 0x11.toByte() },
                side = SorafsOrderbookSide.BID,
                tier = SorafsOrderbookTier.HOT,
                pricePerGib = "42",
                quantityGib = 7,
                ownerAccount = byteArrayOf(0x01),
                providerId = null,
                expiryUnix = 123,
                nonce = 1,
                makerFeeBps = 0,
                takerFeeBps = 25,
                privateKey = ByteArray(32) { 0xB7.toByte() },
            )
        }
        assertTrue(error.message.orEmpty().contains("orderId"))
    }

    @Test
    fun rejectsOrderbookSettlementReceiptFieldsBeforeNativeDispatch() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.buildSignedOrderbookSettlementReceipt(
                receiptId = ByteArray(32) { 0x21.toByte() },
                channelId = ByteArray(32) { 0x22.toByte() },
                tradeId = ByteArray(32) { 0x23.toByte() },
                rangeStart = 0,
                rangeEnd = 64,
                chunkHash = ByteArray(32) { 0x24.toByte() },
                bytesDelivered = 64,
                xorDebited = "not-a-decimal",
                providerCredit = "10",
                feeAmount = "1",
                issuedAtUnix = 123,
                privateKey = ByteArray(32) { 0xB7.toByte() },
            )
        }
        assertTrue(error.message.orEmpty().contains("xorDebited"))
    }

    @Test
    fun rejectsNoncanonicalOrOverprecisionXorQuantitiesBeforeNativeDispatch() {
        assertEquals(155, maxScaledXor.length)
        for (value in listOf("1.0", "0.0000000001", "1".repeat(156))) {
            val error = assertThrows(IllegalArgumentException::class.java) {
                SorafsReferenceValidators.buildSignedOrderbookSettlementReceipt(
                    receiptId = ByteArray(32) { 0x21.toByte() },
                    channelId = ByteArray(32) { 0x22.toByte() },
                    tradeId = ByteArray(32) { 0x23.toByte() },
                    rangeStart = 0,
                    rangeEnd = 64,
                    chunkHash = ByteArray(32) { 0x24.toByte() },
                    bytesDelivered = 64,
                    xorDebited = value,
                    providerCredit = "0",
                    feeAmount = "0",
                    issuedAtUnix = 123,
                    privateKey = ByteArray(32) { 0xB7.toByte() },
                )
            }
            assertTrue(error.message.orEmpty().contains("xorDebited"))
        }
    }

    @Test
    fun popMembershipStructuralFixturesRequirePresentationBinding() {
        requireNativeBridge()
        // These shared fixtures exercise native structural validation, not Halo2 authorization.
        val profiles = listOf(
            Triple("pop_membership_current_v1", "Ok", "SFS-OK-000"),
            Triple("pop_membership_missing_binding_v1", "Error", "SFS-NORITO-001"),
            Triple("pop_membership_zero_binding_v1", "Error", "SFS-VAL-001"),
        )
        for ((name, status, code) in profiles) {
            val outcome = SorafsReferenceValidators.validatePopPayloadJson(
                SorafsPopPayloadKind.MEMBERSHIP_PROOF,
                fixture("sorafs_manifest", "reference_sdk", "$name.to"),
                label = "$name.to",
                generatedAtUnix = 123,
            )
            val fields = Json.parseToJsonElement(outcome).jsonObject
            assertEquals(status, fields.getValue("status").jsonPrimitive.content, name)
            assertEquals(code, fields.getValue("code").jsonPrimitive.content, name)
            assertEquals(
                fixture("sorafs_manifest", "reference_sdk", "${name}_validation_outcome.json")
                    .toString(Charsets.UTF_8),
                outcome,
                name,
            )
        }
    }

    @Test
    fun validatesOrderbookFixtureWhenNativeBridgeIsAvailable() {
        requireNativeBridge()
        val payload = fixture("sorafs_manifest", "orderbook", "order_request_v1.to")
        val json = SorafsReferenceValidators.validateOrderbookPayloadJson(
            SorafsOrderbookPayloadKind.ORDER_REQUEST,
            payload,
            label = "order_request_v1.to",
            generatedAtUnix = 123,
        )
        assertEquals(
            fixture(
                "sorafs_manifest",
                "orderbook",
                "order_request_validation_outcome_v1.json",
            ).toString(Charsets.UTF_8),
            json,
        )

        for (name in listOf("order_request_bad_signature", "order_request_trailing_bytes")) {
            val outcome = SorafsReferenceValidators.validateOrderbookPayloadJson(
                SorafsOrderbookPayloadKind.ORDER_REQUEST,
                fixture("sorafs_manifest", "orderbook", "negative", "${name}_v1.to"),
                label = "${name}_v1.to",
                generatedAtUnix = 123,
            )
            assertEquals(
                fixture(
                    "sorafs_manifest",
                    "orderbook",
                    "negative",
                    "${name}_validation_outcome_v1.json",
                ).toString(Charsets.UTF_8),
                outcome,
                name,
            )
        }
    }

    @Test
    fun validatesAppealFinanceCancelAssetLockProfiles() {
        assertTrue(
            SorafsReferenceValidators.isNativeAvailable(),
            "ABI-29 appeal-finance reference bridge is required",
        )
        val profiles =
            listOf(
                arrayOf(
                    "cancel_asset_lock_v1.to",
                    "Ok",
                    "SFS-OK-000",
                    "validation",
                ),
                arrayOf(
                    "negative/cancel_asset_lock_legacy_missing_expected_v1.to",
                    "Error",
                    "SFS-NORITO-001",
                    "norito",
                ),
                arrayOf(
                    "negative/cancel_asset_lock_zero_expected_v1.to",
                    "Error",
                    "SFS-VAL-001",
                    "validation",
                ),
            )
        for (profile in profiles) {
            val path = profile[0]
            val label = path.substringAfterLast('/')
            val outcome =
                SorafsReferenceValidators.validateAppealFinanceCancelAssetLockJson(
                    fixture("sorafs_manifest", "appeal_finance", *path.split('/').toTypedArray()),
                    label = label,
                    generatedAtUnix = 123,
                )
            val fields = Json.parseToJsonElement(outcome).jsonObject
            assertEquals(profile[1], fields.getValue("status").jsonPrimitive.content, path)
            assertEquals(profile[2], fields.getValue("code").jsonPrimitive.content, path)
            assertEquals(profile[3], fields.getValue("category").jsonPrimitive.content, path)
            assertEquals("1", fields.getValue("version").jsonPrimitive.content, path)
            assertEquals("123", fields.getValue("generated_at").jsonPrimitive.content, path)
            assertTrue(outcome.contains("\"sorafs.reference.appeal_finance\""), path)
        }

        val exactProfiles =
            listOf(
                "cancel_asset_lock_v1.to" to
                    "appeal_finance_cancel_asset_lock_positive_validation_outcome_v1.json",
                "negative/cancel_asset_lock_zero_expected_v1.to" to
                    (
                        "appeal_finance_cancel_asset_lock_zero_expected_negative_" +
                            "validation_outcome_v1.json"
                    ),
            )
        for ((path, expectedName) in exactProfiles) {
            val label = path.substringAfterLast('/')
            val outcome =
                SorafsReferenceValidators.validateAppealFinanceCancelAssetLockJson(
                    fixture("sorafs_manifest", "appeal_finance", *path.split('/').toTypedArray()),
                    label = label,
                    generatedAtUnix = 123,
                )
            assertEquals(
                fixture("sorafs_manifest", "reference_sdk", expectedName)
                    .toString(Charsets.UTF_8),
                outcome,
                path,
            )
        }
    }

    @Test
    fun validatesEveryPdpOutcomeFixtureWhenNativeBridgeIsAvailable() {
        requireNativeBridge()
        val commitment = fixture("sorafs_manifest", "pdp", "commitment_v1.to")
        val challenge = fixture("sorafs_manifest", "pdp", "challenge_v1.to")
        val proof = fixture("sorafs_manifest", "pdp", "proof_v1.to")
        val bundle = SorafsReferenceValidators.validatePdpBundleJson(
            commitment,
            challenge,
            proof,
            commitmentLabel = "commitment_v1.to",
            challengeLabel = "challenge_v1.to",
            proofLabel = "proof_v1.to",
            generatedAtUnix = 123,
        )
        assertEquals(
            fixture(
                "sorafs_manifest",
                "pdp",
                "bundle_validation_outcome_v1.json",
            ).toString(Charsets.UTF_8),
            bundle,
        )

        for ((name, kind) in listOf(
            "duplicate_hot_leaf_challenge" to SorafsPdpPayloadKind.CHALLENGE,
            "missing_signature_proof" to SorafsPdpPayloadKind.PROOF,
        )) {
            val outcome = SorafsReferenceValidators.validatePdpPayloadJson(
                kind,
                fixture("sorafs_manifest", "pdp", "negative", "${name}_v1.to"),
                label = "${name}_v1.to",
                generatedAtUnix = 123,
            )
            assertPdpOutcome(name, outcome)
        }

        for (name in listOf("late_proof", "wrong_manifest_proof", "wrong_provider_proof")) {
            val outcome = SorafsReferenceValidators.validatePdpChallengeProofJson(
                challenge,
                fixture("sorafs_manifest", "pdp", "negative", "${name}_v1.to"),
                challengeLabel = "challenge_v1.to",
                proofLabel = "${name}_v1.to",
                generatedAtUnix = 123,
            )
            assertPdpOutcome(name, outcome)
        }

        for (name in listOf(
            "missing_hot_leaf_path_proof",
            "missing_segment_path_proof",
            "wrong_path_proof",
        )) {
            val outcome = SorafsReferenceValidators.validatePdpBundleJson(
                commitment,
                challenge,
                fixture("sorafs_manifest", "pdp", "negative", "${name}_v1.to"),
                commitmentLabel = "commitment_v1.to",
                challengeLabel = "challenge_v1.to",
                proofLabel = "${name}_v1.to",
                generatedAtUnix = 123,
            )
            assertPdpOutcome(name, outcome)
        }
    }

    @Test
    fun validatesLinkedFixtureBundleWhenNativeBridgeIsAvailable() {
        requireNativeBridge()
        val outcome =
            SorafsReferenceValidators.validateFixtureBundleJson(
                listOf(
                    SorafsFixtureBundlePayloadInput(
                        SorafsFixtureBundlePayloadKind.REPLICATION_ORDER,
                        fixture("sorafs_manifest", "replication_order", "order_v1.to"),
                        "replication-order.to",
                    ),
                    SorafsFixtureBundlePayloadInput(
                        SorafsFixtureBundlePayloadKind.POR_PROOF,
                        fixture("sorafs_manifest", "por", "proof_v1.to"),
                        "por-proof.to",
                    ),
                ),
                nowUnix = 1_700_000_001,
                generatedAtUnix = 1_700_001_238,
            )
        val fields = Json.parseToJsonElement(outcome).jsonObject
        assertEquals("Ok", fields.getValue("status").jsonPrimitive.content)
        assertEquals("SFS-OK-000", fields.getValue("code").jsonPrimitive.content)
        assertEquals("1700001238", fields.getValue("generated_at").jsonPrimitive.content)
    }

    @Test
    fun validatesEveryReferenceSdkBundleOutcomeByteForByte() {
        requireNativeBridge()
        val outcomePaths = referenceBundleProfiles.map { it.outcomePath }
        assertEquals(9, outcomePaths.size)
        assertEquals(outcomePaths.sorted(), outcomePaths)

        for (profile in referenceBundleProfiles) {
            val payloads =
                profile.inputs.map { input ->
                    SorafsFixtureBundlePayloadInput(
                        input.kind,
                        fixture("sorafs_manifest", *input.path.split("/").toTypedArray()),
                        input.path,
                    )
                }
            val actual =
                SorafsReferenceValidators.validateFixtureBundleJson(
                    payloads,
                    nowUnix = profile.nowUnix,
                    generatedAtUnix = referenceFixtureGeneratedAtUnix,
                )
            assertArrayEquals(
                fixture("sorafs_manifest", "reference_sdk", profile.outcomePath),
                actual.toByteArray(Charsets.UTF_8),
                profile.outcomePath,
            )
        }
    }

    @Test
    fun validatesModerationGovernanceLogNodeOutcomeByteForByte() {
        requireNativeBridge()
        val actual =
            SorafsReferenceValidators.validateGovernanceLogNodeJson(
                noritoBytes =
                    fixture("sorafs_manifest", "moderation", "governance_node_v1.to"),
                expectedNodeCid =
                    decodeHex(
                        "4dd7d8901fd8fdd78ce9edd0456fa1dc" +
                            "6bb072709ddc762e43116013c15ff20c",
                    ),
                label = "moderation/governance_node_v1.to",
                generatedAtUnix = referenceFixtureGeneratedAtUnix,
            )
        assertArrayEquals(
            fixture(
                "sorafs_manifest",
                "moderation",
                "governance_node_validation_outcome_v1.json",
            ),
            actual.toByteArray(Charsets.UTF_8),
        )
    }

    @Test
    fun validatesGovernanceDagFixturesAndNegativeVectorsWhenNativeBridgeIsAvailable() {
        requireGovernanceDagNativeBridge()
        val first = fixture("sorafs_manifest", "governance", "dag_block_0_v1.to")
        val second = fixture("sorafs_manifest", "governance", "dag_block_1_v1.to")
        val head = fixture("sorafs_manifest", "governance", "dag_head_v1.to")

        val blockOutcome = SorafsReferenceValidators.validateGovernanceDagBlockJson(
            first,
            label = "dag_block_0_v1.to",
            generatedAtUnix = 123,
        )
        assertEquals(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_block_validation_outcome_v1.json",
            ).toString(Charsets.UTF_8),
            blockOutcome,
        )

        val cidMismatch = SorafsReferenceValidators.validateGovernanceDagBlockJson(
            first,
            expectedBlockCid = ByteArray(32) { 0x7f },
            generatedAtUnix = 123,
        )
        assertEquals(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_block_cid_mismatch_validation_outcome_v1.json",
            ).toString(Charsets.UTF_8),
            cidMismatch,
        )

        val headOutcome = SorafsReferenceValidators.validateGovernanceDagHeadChainJson(
            head = head,
            blocks = listOf(first, second),
            headLabel = "dag_head_v1.to",
            blockLabels = listOf("dag_block_0_v1.to", "dag_block_1_v1.to"),
            generatedAtUnix = 123,
        )
        val goldenOutcome = fixture(
            "sorafs_manifest",
            "governance",
            "dag_head_validation_outcome_v1.json",
        ).toString(Charsets.UTF_8)
        assertEquals(goldenOutcome, headOutcome)

        val reordered = SorafsReferenceValidators.validateGovernanceDagHeadChainJson(
            head,
            listOf(second, first),
            generatedAtUnix = 123,
        )
        assertEquals(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_head_reordered_validation_outcome_v1.json",
            ).toString(Charsets.UTF_8),
            reordered,
        )

        val blockSignatureOutcome =
            SorafsReferenceValidators.validateGovernanceDagBlockJson(
                fixture(
                    "sorafs_manifest",
                    "governance",
                    "dag_block_bad_signature_v1.to",
                ),
                label = "dag_block_bad_signature_v1.to",
                generatedAtUnix = 123,
            )
        assertEquals(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_block_bad_signature_validation_outcome_v1.json",
            ).toString(Charsets.UTF_8),
            blockSignatureOutcome,
        )

        val trailingBytesOutcome =
            SorafsReferenceValidators.validateGovernanceDagBlockJson(
                fixture(
                    "sorafs_manifest",
                    "governance",
                    "dag_block_trailing_bytes_v1.to",
                ),
                label = "dag_block_trailing_bytes_v1.to",
                generatedAtUnix = 123,
            )
        assertEquals(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_block_trailing_bytes_validation_outcome_v1.json",
            ).toString(Charsets.UTF_8),
            trailingBytesOutcome,
        )

        val headSignatureOutcome =
            SorafsReferenceValidators.validateGovernanceDagHeadChainJson(
                head = fixture(
                    "sorafs_manifest",
                    "governance",
                    "dag_head_bad_signature_v1.to",
                ),
                blocks = listOf(first, second),
                headLabel = "dag_head_bad_signature_v1.to",
                blockLabels = listOf("dag_block_0_v1.to", "dag_block_1_v1.to"),
                generatedAtUnix = 123,
            )
        assertEquals(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_head_bad_signature_validation_outcome_v1.json",
            ).toString(Charsets.UTF_8),
            headSignatureOutcome,
        )

        val predecessorOutcome =
            SorafsReferenceValidators.validateGovernanceDagHeadChainJson(
                head = fixture(
                    "sorafs_manifest",
                    "governance",
                    "dag_head_bad_predecessor_v1.to",
                ),
                blocks = listOf(
                    first,
                    fixture(
                        "sorafs_manifest",
                        "governance",
                        "dag_block_1_bad_predecessor_v1.to",
                    ),
                ),
                headLabel = "dag_head_bad_predecessor_v1.to",
                blockLabels = listOf(
                    "dag_block_0_v1.to",
                    "dag_block_1_bad_predecessor_v1.to",
                ),
                generatedAtUnix = 123,
            )
        assertEquals(
            fixture(
                "sorafs_manifest",
                "governance",
                "dag_head_bad_predecessor_validation_outcome_v1.json",
            ).toString(Charsets.UTF_8),
            predecessorOutcome,
        )
    }

    private fun requireGovernanceDagNativeBridge() {
        requireNativeBridge(
            "ABI-29 connect_norito_bridge with Governance DAG symbols is required.",
        )
    }

    private fun requireNativeBridge(
        requiredMessage: String = "ABI-29 connect_norito_bridge is required.",
    ) {
        if (SorafsReferenceValidators.isNativeAvailable()) {
            return
        }
        throw AssertionError(requiredMessage)
    }

    @Test
    fun signsOrderbookFixtureWhenNativeBridgeIsAvailable() {
        requireNativeBridge()
        val payload = fixture("sorafs_manifest", "orderbook", "order_request_v1.to")
        val signed = SorafsReferenceValidators.signOrderbookPayload(
            SorafsOrderbookPayloadKind.ORDER_REQUEST,
            payload,
            ByteArray(32) { 0xB8.toByte() },
        )
        assertTrue(signed.isNotEmpty())
        assertTrue(!signed.contentEquals(payload))
        val outcome =
            SorafsReferenceValidators.validateOrderbookPayloadJson(
                SorafsOrderbookPayloadKind.ORDER_REQUEST,
                signed,
                label = "order_request_resigned_v1.to",
                generatedAtUnix = 123,
            )
        val fields = Json.parseToJsonElement(outcome).jsonObject
        assertEquals("Ok", fields.getValue("status").jsonPrimitive.content)
        assertEquals("SFS-OK-000", fields.getValue("code").jsonPrimitive.content)
    }

    @Test
    fun derivesCanonicalOrderIdAndRejectsExplicitMismatchWhenNativeBridgeIsAvailable() {
        requireNativeBridge()
        val owner = "buyer@sora".toByteArray(Charsets.UTF_8)
        val orderId = SorafsReferenceValidators.deriveOrderbookOrderId(owner, 7)
        assertEquals(
            "9d91ad7700ca0c4762e031f9231aa38dd4502c6048c6ffa31d365e3c4e080b69",
            orderId.toHex(),
        )
        assertTrue(!orderId.contentEquals(SorafsReferenceValidators.deriveOrderbookOrderId(owner, 8)))
        assertTrue(
            !orderId.contentEquals(
                SorafsReferenceValidators.deriveOrderbookOrderId(
                    "provider@sora".toByteArray(Charsets.UTF_8),
                    7,
                ),
            ),
        )

        val maximumOwner = ByteArray(
            SorafsReferenceValidators.ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1,
        ) { 0x45 }
        val maximumOwnerOrderId =
            SorafsReferenceValidators.deriveOrderbookOrderId(maximumOwner, 9)
        val maximumOwnerOrder = SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
            side = SorafsOrderbookSide.BID,
            tier = SorafsOrderbookTier.HOT,
            pricePerGib = "1",
            quantityGib = 1,
            ownerAccount = maximumOwner,
            providerId = null,
            expiryUnix = 1_800_000_000,
            nonce = 9,
            makerFeeBps = 0,
            takerFeeBps = 0,
            privateKey = ByteArray(32) { 0xB7.toByte() },
        )
        assertTrue(
            SorafsReferenceValidators.validateOrderbookPayloadJson(
                SorafsOrderbookPayloadKind.ORDER_REQUEST,
                maximumOwnerOrder,
                generatedAtUnix = 123,
            ).contains("\"status\": \"Ok\""),
        )
        val maximumOwnerCancel = SorafsReferenceValidators.buildSignedOrderbookOrderCancel(
            orderId = maximumOwnerOrderId,
            ownerAccount = maximumOwner,
            reason = SorafsOrderbookCancelReason.OWNER_REQUESTED,
            nonce = 10,
            privateKey = ByteArray(32) { 0xB7.toByte() },
        )
        assertTrue(
            SorafsReferenceValidators.validateOrderbookPayloadJson(
                SorafsOrderbookPayloadKind.ORDER_CANCEL,
                maximumOwnerCancel,
                generatedAtUnix = 123,
            ).contains("\"status\": \"Ok\""),
        )

        val signed = SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
            side = SorafsOrderbookSide.BID,
            tier = SorafsOrderbookTier.HOT,
            pricePerGib = maxScaledXor,
            quantityGib = 64,
            ownerAccount = owner,
            providerId = null,
            expiryUnix = 1_800_000_000,
            nonce = 7,
            makerFeeBps = 10,
            takerFeeBps = 15,
            privateKey = ByteArray(32) { 0xB7.toByte() },
        )
        val outcome = SorafsReferenceValidators.validateOrderbookPayloadJson(
            SorafsOrderbookPayloadKind.ORDER_REQUEST,
            signed,
            generatedAtUnix = 123,
        )
        assertTrue(outcome.contains("\"status\": \"Ok\""), outcome)

        val ask = SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
            side = SorafsOrderbookSide.ASK,
            tier = SorafsOrderbookTier.HOT,
            pricePerGib = "1.25",
            quantityGib = 4,
            ownerAccount = owner,
            providerId = ByteArray(32) { 0x72 },
            expiryUnix = 1_800_000_000,
            nonce = 8,
            makerFeeBps = 10,
            takerFeeBps = 15,
            privateKey = ByteArray(32) { 0xB7.toByte() },
        )
        val askOutcome = SorafsReferenceValidators.validateOrderbookPayloadJson(
            SorafsOrderbookPayloadKind.ORDER_REQUEST,
            ask,
            generatedAtUnix = 123,
        )
        assertTrue(askOutcome.contains("\"status\": \"Ok\""), askOutcome)

        val bidProviderError = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
                side = SorafsOrderbookSide.BID,
                tier = SorafsOrderbookTier.HOT,
                pricePerGib = "1",
                quantityGib = 1,
                ownerAccount = owner,
                providerId = ByteArray(32) { 0x72 },
                expiryUnix = 1_800_000_000,
                nonce = 17,
                makerFeeBps = 0,
                takerFeeBps = 0,
                privateKey = ByteArray(32) { 0xB7.toByte() },
            )
        }
        assertTrue(bidProviderError.message.orEmpty().contains("absent or empty"))

        val askProviderError = assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
                side = SorafsOrderbookSide.ASK,
                tier = SorafsOrderbookTier.HOT,
                pricePerGib = "1",
                quantityGib = 1,
                ownerAccount = owner,
                providerId = null,
                expiryUnix = 1_800_000_000,
                nonce = 17,
                makerFeeBps = 0,
                takerFeeBps = 0,
                privateKey = ByteArray(32) { 0xB7.toByte() },
            )
        }
        assertTrue(askProviderError.message.orEmpty().contains("providerId"))

        assertThrows(IllegalArgumentException::class.java) {
            SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
                orderId = ByteArray(32) { 0x11.toByte() },
                side = SorafsOrderbookSide.BID,
                tier = SorafsOrderbookTier.HOT,
                pricePerGib = "0.000000001",
                quantityGib = 64,
                ownerAccount = owner,
                providerId = null,
                expiryUnix = 1_800_000_000,
                nonce = 7,
                makerFeeBps = 10,
                takerFeeBps = 15,
                privateKey = ByteArray(32) { 0xB7.toByte() },
            )
        }
    }

    private fun assertPdpOutcome(name: String, actual: String) {
        assertEquals(
            fixture(
                "sorafs_manifest",
                "pdp",
                "negative",
                "${name}_validation_outcome_v1.json",
            ).toString(Charsets.UTF_8),
            actual,
            name,
        )
    }

    private fun fixture(vararg parts: String): ByteArray {
        val cwd = Paths.get(System.getProperty("user.dir")).toAbsolutePath()
        val relative = parts.fold(Paths.get("fixtures")) { path, part -> path.resolve(part) }
        val candidates = listOf(
            cwd.resolve(relative),
            cwd.resolve("..").resolve(relative),
            cwd.resolve("..").resolve("..").resolve(relative),
        )
        val path = candidates.firstOrNull { Files.exists(it) }
            ?: throw IllegalStateException("missing fixture ${relative.joinToString("/")}")
        return Files.readAllBytes(path.normalizeAbsolute())
    }

    private fun decodeHex(value: String): ByteArray {
        require(value.length % 2 == 0)
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private fun ByteArray.toHex(): String {
        val alphabet = "0123456789abcdef"
        val output = StringBuilder(size * 2)
        for (byte in this) {
            val value = byte.toInt() and 0xff
            output.append(alphabet[value ushr 4])
            output.append(alphabet[value and 0x0f])
        }
        return output.toString()
    }

    private fun Path.normalizeAbsolute(): Path = toAbsolutePath().normalize()
}
