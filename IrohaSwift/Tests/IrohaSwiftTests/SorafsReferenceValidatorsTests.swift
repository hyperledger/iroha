import Foundation
import XCTest
@testable import IrohaSwift

final class SorafsReferenceValidatorsTests: XCTestCase {
    private struct FixtureBundleInputSpec {
        let kind: SorafsFixtureBundlePayloadKind
        let path: String
    }

    private struct FixtureBundleProfile {
        let outcomePath: String
        let nowUnix: UInt64
        let inputs: [FixtureBundleInputSpec]
    }

    private static let nativeValidationRequiredMessage =
        "ABI-30 connect_norito_bridge with Governance DAG symbols is required."
    private static let referenceFixtureGeneratedAtUnix: UInt64 = 1_700_001_234
    private static let referenceBundleProfiles: [FixtureBundleProfile] = [
        FixtureBundleProfile(
            outcomePath: "bundle_heterogeneous_positive_validation_outcome_v1.json",
            nowUnix: 1_700_000_001,
            inputs: [
                FixtureBundleInputSpec(
                    kind: .replicationOrder,
                    path: "replication_order/order_v1.to"
                ),
                FixtureBundleInputSpec(kind: .pdpCommitment, path: "pdp/commitment_v1.to"),
                FixtureBundleInputSpec(kind: .pdpChallenge, path: "pdp/challenge_v1.to"),
                FixtureBundleInputSpec(kind: .pdpProof, path: "pdp/proof_v1.to"),
                FixtureBundleInputSpec(kind: .porChallenge, path: "por/challenge_v1.to"),
                FixtureBundleInputSpec(kind: .porProof, path: "por/proof_v1.to"),
                FixtureBundleInputSpec(kind: .potrReceipt, path: "potr/receipt_v1.to"),
                FixtureBundleInputSpec(kind: .repairTaskRecord, path: "repair/task_v1.to"),
                FixtureBundleInputSpec(
                    kind: .orderbookOrderRequest,
                    path: "orderbook/order_request_v1.to"
                ),
                FixtureBundleInputSpec(
                    kind: .orderbookOrderCancel,
                    path: "orderbook/order_cancel_v1.to"
                ),
                FixtureBundleInputSpec(
                    kind: .orderbookTradeEvent,
                    path: "orderbook/trade_event_v1.to"
                ),
                FixtureBundleInputSpec(
                    kind: .orderbookSettlementChannel,
                    path: "orderbook/settlement_channel_v1.to"
                ),
                FixtureBundleInputSpec(
                    kind: .orderbookSettlementReceipt,
                    path: "orderbook/settlement_receipt_v1.to"
                )
            ]
        ),
        FixtureBundleProfile(
            outcomePath: "bundle_orderbook_bad_signature_negative_validation_outcome_v1.json",
            nowUnix: 1_700_000_001,
            inputs: [
                FixtureBundleInputSpec(
                    kind: .replicationOrder,
                    path: "replication_order/order_v1.to"
                ),
                FixtureBundleInputSpec(kind: .porChallenge, path: "por/challenge_v1.to"),
                FixtureBundleInputSpec(kind: .porProof, path: "por/proof_v1.to"),
                FixtureBundleInputSpec(
                    kind: .orderbookOrderRequest,
                    path: "orderbook/negative/order_request_bad_signature_v1.to"
                )
            ]
        ),
        FixtureBundleProfile(
            outcomePath: "bundle_orderbook_trailing_bytes_negative_validation_outcome_v1.json",
            nowUnix: 1_700_000_001,
            inputs: [
                FixtureBundleInputSpec(
                    kind: .replicationOrder,
                    path: "replication_order/order_v1.to"
                ),
                FixtureBundleInputSpec(kind: .porChallenge, path: "por/challenge_v1.to"),
                FixtureBundleInputSpec(kind: .porProof, path: "por/proof_v1.to"),
                FixtureBundleInputSpec(
                    kind: .orderbookOrderRequest,
                    path: "orderbook/negative/order_request_trailing_bytes_v1.to"
                )
            ]
        ),
        FixtureBundleProfile(
            outcomePath: "bundle_pdp_duplicate_hot_leaf_negative_validation_outcome_v1.json",
            nowUnix: 1_700_000_001,
            inputs: [
                FixtureBundleInputSpec(
                    kind: .replicationOrder,
                    path: "replication_order/order_v1.to"
                ),
                FixtureBundleInputSpec(kind: .pdpCommitment, path: "pdp/commitment_v1.to"),
                FixtureBundleInputSpec(
                    kind: .pdpChallenge,
                    path: "pdp/negative/duplicate_hot_leaf_challenge_v1.to"
                )
            ]
        ),
        FixtureBundleProfile(
            outcomePath: "bundle_pdp_missing_signature_negative_validation_outcome_v1.json",
            nowUnix: 1_700_000_001,
            inputs: [
                FixtureBundleInputSpec(
                    kind: .replicationOrder,
                    path: "replication_order/order_v1.to"
                ),
                FixtureBundleInputSpec(kind: .pdpCommitment, path: "pdp/commitment_v1.to"),
                FixtureBundleInputSpec(kind: .pdpChallenge, path: "pdp/challenge_v1.to"),
                FixtureBundleInputSpec(
                    kind: .pdpProof,
                    path: "pdp/negative/missing_signature_proof_v1.to"
                )
            ]
        ),
        FixtureBundleProfile(
            outcomePath: "bundle_pdp_wrong_provider_negative_validation_outcome_v1.json",
            nowUnix: 1_700_000_001,
            inputs: [
                FixtureBundleInputSpec(
                    kind: .replicationOrder,
                    path: "replication_order/order_v1.to"
                ),
                FixtureBundleInputSpec(kind: .pdpCommitment, path: "pdp/commitment_v1.to"),
                FixtureBundleInputSpec(kind: .pdpChallenge, path: "pdp/challenge_v1.to"),
                FixtureBundleInputSpec(
                    kind: .pdpProof,
                    path: "pdp/negative/wrong_provider_proof_v1.to"
                )
            ]
        ),
        FixtureBundleProfile(
            outcomePath: "bundle_repair_manifest_mismatch_negative_validation_outcome_v1.json",
            nowUnix: 1_700_000_001,
            // The outcome names only the offender; the order establishes the expected digest.
            inputs: [
                FixtureBundleInputSpec(
                    kind: .replicationOrder,
                    path: "replication_order/order_v1.to"
                ),
                FixtureBundleInputSpec(
                    kind: .repairTaskRecord,
                    path: "repair/negative/task_manifest_mismatch_v1.to"
                )
            ]
        ),
        FixtureBundleProfile(
            outcomePath: "bundle_repair_provider_unassigned_negative_validation_outcome_v1.json",
            nowUnix: 1_700_000_001,
            inputs: [
                FixtureBundleInputSpec(
                    kind: .replicationOrder,
                    path: "replication_order/order_v1.to"
                ),
                FixtureBundleInputSpec(
                    kind: .repairTaskRecord,
                    path: "repair/negative/task_provider_unassigned_v1.to"
                )
            ]
        ),
        FixtureBundleProfile(
            outcomePath: "bundle_routing_admission_positive_validation_outcome_v1.json",
            nowUnix: 300,
            inputs: [
                FixtureBundleInputSpec(
                    kind: .providerAdvert,
                    path: "provider_admission/advert_v1.to"
                ),
                FixtureBundleInputSpec(
                    kind: .providerAdmissionEnvelope,
                    path: "provider_admission/envelope_v1.to"
                )
            ]
        )
    ]

    private let maxScaledXor =
        "6703903964971298549787012499102923063739682910296196688861780721860882015" +
        "036773488400937149083451713845015929093243025426876941405973284973216824" +
        ".503042047"

    func testBridgeSelectors() {
        XCTAssertEqual(SorafsOrderbookPayloadKind.orderRequest.rawValue, 1)
        XCTAssertNil(SorafsOrderbookPayloadKind(rawValue: 6))
        XCTAssertTrue(SorafsOrderbookPayloadKind.orderRequest.isUserSignedPayload)
        XCTAssertFalse(SorafsOrderbookPayloadKind.tradeEvent.isUserSignedPayload)
        XCTAssertEqual(SorafsPdpPayloadKind.commitment.rawValue, 1)
        XCTAssertEqual(SorafsPdpPayloadKind.proof.rawValue, 3)
        XCTAssertEqual(SorafsPopPayloadKind.credential.rawValue, 1)
        XCTAssertEqual(SorafsPopPayloadKind.membershipProof.rawValue, 6)
        XCTAssertEqual(SorafsPopPayloadKind.issuedCredentialBundle.rawValue, 7)
        XCTAssertEqual(SorafsHedgingPayloadKind.priceFeed.rawValue, 1)
        XCTAssertEqual(SorafsHedgingPayloadKind.billingStatement.rawValue, 4)
        let fixtureKinds: [SorafsFixtureBundlePayloadKind] = [
            .providerAdvert,
            .providerAdmissionEnvelope,
            .replicationOrder,
            .porChallenge,
            .porProof,
            .potrReceipt,
            .repairEvidence,
            .repairReport,
            .repairTaskRecord,
            .repairSlashProposal,
            .repairTaskEvent,
            .orderbookOrderRequest,
            .orderbookOrderCancel,
            .orderbookTradeEvent,
            .orderbookSettlementChannel,
            .orderbookSettlementReceipt,
            .pdpCommitment,
            .pdpChallenge,
            .pdpProof,
        ]
        XCTAssertEqual(fixtureKinds.map(\.rawValue), (1...19).map { UInt32($0) })
        XCTAssertEqual(
            fixtureKinds.map(\.defaultLabel),
            [
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
            ]
        )
        XCTAssertNil(SorafsFixtureBundlePayloadKind(rawValue: 0))
        XCTAssertNil(SorafsFixtureBundlePayloadKind(rawValue: 20))
        XCTAssertEqual(SorafsOrderbookSide.bid.rawValue, 1)
        XCTAssertEqual(SorafsOrderbookTier.archive.rawValue, 3)
        XCTAssertEqual(SorafsOrderbookCancelReason.replaced.rawValue, 4)
        XCTAssertEqual(SorafsReferenceValidators.orderbookOwnerAccountMaxBytesV1, 256)
        XCTAssertEqual(SorafsReferenceValidators.governanceDagMaxBlocksV1, 64)
        XCTAssertEqual(SorafsReferenceValidators.governanceDagCidBytesV1, 32)
        XCTAssertEqual(SorafsReferenceValidators.referenceMaxInputBytesV1, 67_108_864)
        XCTAssertEqual(SorafsReferenceValidators.referenceMaxLabelBytesV1, 1_024)
        XCTAssertEqual(SorafsReferenceValidators.fixtureBundleMaxPayloadsV1, 64)
    }

    func testRejectsBlankLabelBeforeNativeDispatch() {
        XCTAssertThrowsError(
            try SorafsReferenceValidators.validateHedgingPayloadJSON(
                kind: .priceFeed,
                payload: Data(),
                label: " ",
                generatedAtUnix: 1
            )
        ) { error in
            XCTAssertEqual(
                error as? SorafsReferenceValidationError,
                .invalidLabel("label must not be blank")
            )
        }
    }

    func testDefaultTimestampOverloadsValidateLabelsBeforeNativeDispatch() {
        func assertInvalidLabel(_ operation: () throws -> String, line: UInt = #line) {
            XCTAssertThrowsError(try operation(), line: line) { error in
                XCTAssertEqual(
                    error as? SorafsReferenceValidationError,
                    .invalidLabel("label must not be blank"),
                    line: line
                )
            }
        }

        assertInvalidLabel {
            try SorafsReferenceValidators.validateOrderbookPayloadJSON(
                kind: .orderRequest,
                payload: Data(),
                label: " "
            )
        }
        assertInvalidLabel {
            try SorafsReferenceValidators.validatePdpPayloadJSON(
                kind: .proof,
                payload: Data(),
                label: " "
            )
        }
        assertInvalidLabel {
            try SorafsReferenceValidators.validatePdpCommitmentChallengeJSON(
                commitment: Data(),
                challenge: Data(),
                commitmentLabel: " "
            )
        }
        assertInvalidLabel {
            try SorafsReferenceValidators.validatePdpChallengeProofJSON(
                challenge: Data(),
                proof: Data(),
                challengeLabel: " "
            )
        }
        assertInvalidLabel {
            try SorafsReferenceValidators.validatePdpBundleJSON(
                commitment: Data(),
                challenge: Data(),
                proof: Data(),
                commitmentLabel: " "
            )
        }
        assertInvalidLabel {
            try SorafsReferenceValidators.validateGovernanceDagBlockJSON(
                payload: Data(),
                label: " "
            )
        }
        assertInvalidLabel {
            try SorafsReferenceValidators.validateGovernanceDagHeadChainJSON(
                head: Data(),
                blocks: [SorafsGovernanceDagBlockInput(payload: Data())],
                headLabel: " "
            )
        }
    }

    func testBoundsGovernanceDagInputsBeforeNativeDispatch() {
        XCTAssertThrowsError(
            try SorafsReferenceValidators.validateGovernanceDagHeadChainJSON(
                head: Data(),
                blocks: [],
                generatedAtUnix: 1
            )
        ) { error in
            XCTAssertEqual(
                error as? SorafsReferenceValidationError,
                .invalidGovernanceDagInput("blocks must contain 1...64 entries")
            )
        }

        XCTAssertThrowsError(
            try SorafsReferenceValidators.validateGovernanceDagHeadChainJSON(
                head: Data(),
                blocks: Array(
                    repeating: SorafsGovernanceDagBlockInput(payload: Data()),
                    count: 65
                ),
                generatedAtUnix: 1
            )
        ) { error in
            XCTAssertEqual(
                error as? SorafsReferenceValidationError,
                .invalidGovernanceDagInput("blocks must contain 1...64 entries")
            )
        }

        XCTAssertThrowsError(
            try SorafsReferenceValidators.validateGovernanceDagBlockJSON(
                payload: Data(),
                label: String(repeating: "x", count: 1_025),
                generatedAtUnix: 1
            )
        ) { error in
            XCTAssertEqual(
                error as? SorafsReferenceValidationError,
                .invalidLabel("label must be at most 1024 UTF-8 bytes")
            )
        }

        XCTAssertThrowsError(
            try SorafsReferenceValidators.validateGovernanceDagBlockJSON(
                payload: Data(),
                label: "bad\u{1}label",
                generatedAtUnix: 1
            )
        ) { error in
            XCTAssertEqual(
                error as? SorafsReferenceValidationError,
                .invalidLabel("label must not contain control characters")
            )
        }

        for invalidLength in [0, 31, 33] {
            XCTAssertThrowsError(
                try SorafsReferenceValidators.validateGovernanceDagBlockJSON(
                    payload: Data(),
                    expectedBlockCid: Data(repeating: 0, count: invalidLength),
                    generatedAtUnix: 1
                )
            ) { error in
                XCTAssertEqual(
                    error as? SorafsReferenceValidationError,
                    .invalidGovernanceDagInput(
                        "expectedBlockCid must contain exactly 32 bytes"
                    )
                )
            }
        }
    }

    func testBoundsFixtureBundleInputsBeforeNativeDispatch() {
        XCTAssertThrowsError(
            try SorafsReferenceValidators.validateFixtureBundleJSON(
                payloads: [],
                generatedAtUnix: 1
            )
        ) { error in
            XCTAssertEqual(
                error as? SorafsReferenceValidationError,
                .invalidFixtureBundleInput("payloads must contain 1...64 entries")
            )
        }

        let item = SorafsFixtureBundlePayloadInput(
            kind: .porProof,
            payload: Data([0xA5])
        )
        XCTAssertThrowsError(
            try SorafsReferenceValidators.validateFixtureBundleJSON(
                payloads: Array(repeating: item, count: 65),
                generatedAtUnix: 1
            )
        ) { error in
            XCTAssertEqual(
                error as? SorafsReferenceValidationError,
                .invalidFixtureBundleInput("payloads must contain 1...64 entries")
            )
        }
    }

    func testFixtureBundleInputSnapshotsPayloadValue() {
        var source = Data([1, 2, 3])
        let input = SorafsFixtureBundlePayloadInput(kind: .porProof, payload: source)
        source[0] = 9
        XCTAssertEqual(input.payload, Data([1, 2, 3]))
    }

    func testBoundsGovernanceLogNodeCidBeforeNativeDispatch() {
        for invalidLength in [0, 31, 33] {
            XCTAssertThrowsError(
                try SorafsReferenceValidators.validateGovernanceLogNodeJSON(
                    payload: Data(),
                    expectedNodeCid: Data(repeating: 0, count: invalidLength),
                    generatedAtUnix: 1
                )
            ) { error in
                XCTAssertEqual(
                    error as? SorafsReferenceValidationError,
                    .invalidGovernanceLogNodeInput(
                        "expectedNodeCid must contain exactly 32 bytes"
                    )
                )
            }
        }
    }

    func testRejectsNonSignableOrderbookPayloadBeforeNativeDispatch() {
        XCTAssertThrowsError(
            try SorafsReferenceValidators.signOrderbookPayload(
                kind: .tradeEvent,
                payload: Data(),
                privateKey: Data(repeating: 0xB7, count: 32)
            )
        ) { error in
            XCTAssertEqual(
                error as? SorafsReferenceValidationError,
                .unsupportedOrderbookPayloadKind(.tradeEvent)
            )
        }
    }

    func testRejectsBadSigningKeyBeforeNativeDispatch() {
        XCTAssertThrowsError(
            try SorafsReferenceValidators.signOrderbookPayload(
                kind: .orderRequest,
                payload: Data(),
                privateKey: Data(repeating: 0x00, count: 32)
            )
        ) { error in
            XCTAssertEqual(
                error as? SorafsReferenceValidationError,
                .invalidPrivateKey("privateKey must not be all zero")
            )
        }
    }

    func testRejectsInvalidOrderIdDerivationInputsBeforeNativeDispatch() {
        XCTAssertThrowsError(
            try SorafsReferenceValidators.deriveOrderbookOrderId(
                ownerAccount: Data(),
                nonce: 7
            )
        ) { error in
            XCTAssertEqual(
                error as? SorafsReferenceValidationError,
                .invalidOrderbookField("ownerAccount must not be empty")
            )
        }
        XCTAssertThrowsError(
            try SorafsReferenceValidators.deriveOrderbookOrderId(
                ownerAccount: Data([0x01]),
                nonce: 0
            )
        ) { error in
            XCTAssertEqual(
                error as? SorafsReferenceValidationError,
                .invalidOrderbookField("nonce must be greater than zero")
            )
        }
    }

    func testRejectsOversizedOrderbookOwnerAccountsBeforeNativeDispatch() {
        let oversized = Data(
            repeating: 0x45,
            count: SorafsReferenceValidators.orderbookOwnerAccountMaxBytesV1 + 1
        )
        let expected = SorafsReferenceValidationError.invalidOrderbookField(
            "ownerAccount must be at most 256 bytes"
        )

        XCTAssertThrowsError(
            try SorafsReferenceValidators.deriveOrderbookOrderId(
                ownerAccount: oversized,
                nonce: 7
            )
        ) { error in
            XCTAssertEqual(error as? SorafsReferenceValidationError, expected)
        }

        let request = SorafsSignedOrderbookOrderRequestFields(
            side: .bid,
            tier: .hot,
            pricePerGib: "1",
            quantityGib: 1,
            ownerAccount: oversized,
            expiryUnix: 1,
            nonce: 7,
            makerFeeBps: 0,
            takerFeeBps: 0
        )
        XCTAssertThrowsError(
            try SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
                request,
                privateKey: Data(repeating: 0xB7, count: 32)
            )
        ) { error in
            XCTAssertEqual(error as? SorafsReferenceValidationError, expected)
        }

        let cancel = SorafsSignedOrderbookOrderCancelFields(
            orderId: Data(repeating: 0x11, count: 32),
            ownerAccount: oversized,
            reason: .ownerRequested,
            nonce: 8
        )
        XCTAssertThrowsError(
            try SorafsReferenceValidators.buildSignedOrderbookOrderCancel(
                cancel,
                privateKey: Data(repeating: 0xB7, count: 32)
            )
        ) { error in
            XCTAssertEqual(error as? SorafsReferenceValidationError, expected)
        }
    }

    func testRejectsOrderbookOrderRequestFieldsBeforeNativeDispatch() {
        let fields = SorafsSignedOrderbookOrderRequestFields(
            orderId: Data(repeating: 0x11, count: 31),
            side: .bid,
            tier: .hot,
            pricePerGib: "42",
            quantityGib: 7,
            ownerAccount: Data([0x01]),
            expiryUnix: 123,
            nonce: 1,
            makerFeeBps: 0,
            takerFeeBps: 25
        )
        XCTAssertThrowsError(
            try SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
                fields,
                privateKey: Data(repeating: 0xB7, count: 32)
            )
        ) { error in
            XCTAssertEqual(
                error as? SorafsReferenceValidationError,
                .invalidOrderbookField("orderId must be 32 bytes")
            )
        }
    }

    func testRejectsOrderbookSettlementReceiptFieldsBeforeNativeDispatch() {
        let fields = SorafsSignedOrderbookSettlementReceiptFields(
            receiptId: Data(repeating: 0x21, count: 32),
            channelId: Data(repeating: 0x22, count: 32),
            tradeId: Data(repeating: 0x23, count: 32),
            rangeStart: 0,
            rangeEnd: 64,
            chunkHash: Data(repeating: 0x24, count: 32),
            bytesDelivered: 64,
            xorDebited: "not-a-decimal",
            providerCredit: "10",
            feeAmount: "1",
            issuedAtUnix: 123
        )
        XCTAssertThrowsError(
            try SorafsReferenceValidators.buildSignedOrderbookSettlementReceipt(
                fields,
                privateKey: Data(repeating: 0xB7, count: 32)
            )
        ) { error in
            XCTAssertEqual(
                error as? SorafsReferenceValidationError,
                .invalidOrderbookField("xorDebited must be a canonical non-negative XOR quantity")
            )
        }
    }

    func testRejectsNoncanonicalXorQuantitiesBeforeNativeDispatch() {
        XCTAssertEqual(maxScaledXor.utf8.count, 155)
        for value in ["1.0", "0.0000000001", String(repeating: "1", count: 156)] {
            let fields = SorafsSignedOrderbookSettlementReceiptFields(
                receiptId: Data(repeating: 0x21, count: 32),
                channelId: Data(repeating: 0x22, count: 32),
                tradeId: Data(repeating: 0x23, count: 32),
                rangeStart: 0,
                rangeEnd: 64,
                chunkHash: Data(repeating: 0x24, count: 32),
                bytesDelivered: 64,
                xorDebited: value,
                providerCredit: "0",
                feeAmount: "0",
                issuedAtUnix: 123
            )
            XCTAssertThrowsError(
                try SorafsReferenceValidators.buildSignedOrderbookSettlementReceipt(
                    fields,
                    privateKey: Data(repeating: 0xB7, count: 32)
                )
            ) { error in
                guard let validation = error as? SorafsReferenceValidationError,
                      case let .invalidOrderbookField(message) = validation else {
                    return XCTFail("unexpected error: \(error)")
                }
                XCTAssertTrue(message.contains("xorDebited"), message)
            }
        }
    }

    func testPopMembershipStructuralFixturesRequirePresentationBinding() throws {
        guard try requireNativeCapability(
            SorafsReferenceValidators.isNativeAvailable,
            "SoraFS reference bridge unavailable"
        ) else {
            return
        }
        // These shared fixtures validate wire metadata, not cryptographic recipient authorization.
        let profiles = [
            ("pop_membership_current_v1", "Ok", "SFS-OK-000"),
            ("pop_membership_missing_binding_v1", "Error", "SFS-NORITO-001"),
            ("pop_membership_zero_binding_v1", "Error", "SFS-VAL-001")
        ]
        for (name, status, code) in profiles {
            let outcome = try SorafsReferenceValidators.validatePopPayloadJSON(
                kind: .membershipProof,
                payload: try fixture("sorafs_manifest/reference_sdk/\(name).to"),
                label: "\(name).to",
                generatedAtUnix: 123
            )
            let data = try XCTUnwrap(outcome.data(using: .utf8))
            let fields = try XCTUnwrap(
                JSONSerialization.jsonObject(with: data) as? [String: Any]
            )
            XCTAssertEqual(fields["status"] as? String, status, name)
            XCTAssertEqual(fields["code"] as? String, code, name)
            XCTAssertEqual(
                outcome,
                String(
                    decoding: try fixture(
                        "sorafs_manifest/reference_sdk/\(name)_validation_outcome.json"
                    ),
                    as: UTF8.self
                ),
                name
            )
        }
    }

    func testValidatesOrderbookFixtureWhenNativeBridgeIsAvailable() throws {
        guard try requireNativeCapability(
            SorafsReferenceValidators.isNativeAvailable,
            "SoraFS reference bridge unavailable"
        ) else {
            return
        }
        let payload = try fixture("sorafs_manifest/orderbook/order_request_v1.to")
        let json = try SorafsReferenceValidators.validateOrderbookPayloadJSON(
            kind: .orderRequest,
            payload: payload,
            label: "order_request_v1.to",
            generatedAtUnix: 123
        )
        XCTAssertEqual(
            json,
            String(
                decoding: try fixture(
                    "sorafs_manifest/orderbook/order_request_validation_outcome_v1.json"
                ),
                as: UTF8.self
            )
        )

        for name in [
            "order_request_bad_signature",
            "order_request_trailing_bytes"
        ] {
            let outcome = try SorafsReferenceValidators.validateOrderbookPayloadJSON(
                kind: .orderRequest,
                payload: try fixture(
                    "sorafs_manifest/orderbook/negative/\(name)_v1.to"
                ),
                label: "\(name)_v1.to",
                generatedAtUnix: 123
            )
            XCTAssertEqual(
                outcome,
                String(
                    decoding: try fixture(
                        "sorafs_manifest/orderbook/negative/"
                            + "\(name)_validation_outcome_v1.json"
                    ),
                    as: UTF8.self
                ),
                name
            )
        }
    }

    func testAppealFinanceCancelAssetLockValidationProfiles() throws {
        guard SorafsReferenceValidators.isAppealFinanceNativeAvailable else {
            return XCTFail("ABI-30 appeal-finance reference bridge is required")
        }
        let profiles: [(path: String, status: String, code: String, category: String)] = [
            (
                "sorafs_manifest/appeal_finance/cancel_asset_lock_v1.to",
                "Ok",
                "SFS-OK-000",
                "validation"
            ),
            (
                "sorafs_manifest/appeal_finance/negative/"
                    + "cancel_asset_lock_legacy_missing_expected_v1.to",
                "Error",
                "SFS-NORITO-001",
                "norito"
            ),
            (
                "sorafs_manifest/appeal_finance/negative/"
                    + "cancel_asset_lock_zero_expected_v1.to",
                "Error",
                "SFS-VAL-001",
                "validation"
            ),
        ]
        for profile in profiles {
            let label = URL(fileURLWithPath: profile.path).lastPathComponent
            let json = try SorafsReferenceValidators.validateAppealFinanceCancelAssetLockJSON(
                payload: try fixture(profile.path),
                label: label,
                generatedAtUnix: 123
            )
            let data = try XCTUnwrap(json.data(using: .utf8))
            let outcome = try XCTUnwrap(
                JSONSerialization.jsonObject(with: data) as? [String: Any]
            )
            XCTAssertEqual(outcome["status"] as? String, profile.status, profile.path)
            XCTAssertEqual(outcome["code"] as? String, profile.code, profile.path)
            XCTAssertEqual(outcome["category"] as? String, profile.category, profile.path)
            XCTAssertEqual((outcome["version"] as? NSNumber)?.intValue, 1, profile.path)
            XCTAssertEqual(
                (outcome["generated_at"] as? NSNumber)?.uint64Value,
                123,
                profile.path
            )
            XCTAssertTrue(
                (outcome["telemetry_tags"] as? [String] ?? [])
                    .contains("sorafs.reference.appeal_finance"),
                profile.path
            )
        }

        for (payloadPath, expectedName) in [
            (
                "sorafs_manifest/appeal_finance/cancel_asset_lock_v1.to",
                "appeal_finance_cancel_asset_lock_positive_validation_outcome_v1.json"
            ),
            (
                "sorafs_manifest/appeal_finance/negative/"
                    + "cancel_asset_lock_zero_expected_v1.to",
                "appeal_finance_cancel_asset_lock_zero_expected_negative_"
                    + "validation_outcome_v1.json"
            ),
        ] {
            let label = URL(fileURLWithPath: payloadPath).lastPathComponent
            let outcome = try SorafsReferenceValidators.validateAppealFinanceCancelAssetLockJSON(
                payload: try fixture(payloadPath),
                label: label,
                generatedAtUnix: 123
            )
            XCTAssertEqual(
                outcome,
                String(
                    decoding: try fixture(
                        "sorafs_manifest/reference_sdk/\(expectedName)"
                    ),
                    as: UTF8.self
                ),
                payloadPath
            )
        }
    }

    func testValidatesLinkedFixtureBundleWhenNativeBridgeIsAvailable() throws {
        guard try requireNativeCapability(
            SorafsReferenceValidators.isFixtureBundleNativeAvailable,
            "SoraFS fixture-bundle reference bridge unavailable"
        ) else {
            return
        }
        let json = try SorafsReferenceValidators.validateFixtureBundleJSON(
            payloads: [
                SorafsFixtureBundlePayloadInput(
                    kind: .replicationOrder,
                    payload: try fixture("sorafs_manifest/replication_order/order_v1.to"),
                    label: "replication-order.to"
                ),
                SorafsFixtureBundlePayloadInput(
                    kind: .porProof,
                    payload: try fixture("sorafs_manifest/por/proof_v1.to"),
                    label: "por-proof.to"
                )
            ],
            nowUnix: 1_700_000_001,
            generatedAtUnix: 1_700_001_238
        )
        let jsonData = try XCTUnwrap(json.data(using: .utf8))
        let outcome = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: jsonData) as? [String: Any]
        )
        XCTAssertEqual(outcome["status"] as? String, "Ok")
        XCTAssertEqual(outcome["code"] as? String, "SFS-OK-000")
        XCTAssertEqual(
            (outcome["generated_at"] as? NSNumber)?.uint64Value,
            1_700_001_238
        )
        let inputs = try XCTUnwrap(outcome["inputs"] as? [[String: Any]])
        XCTAssertEqual(
            inputs.compactMap { $0["kind"] as? String },
            ["replication_order", "por_proof"]
        )
    }

    func testValidatesEveryReferenceSdkBundleOutcomeByteForByte() throws {
        guard try requireNativeCapability(
            SorafsReferenceValidators.isFixtureBundleNativeAvailable,
            "SoraFS fixture-bundle reference bridge unavailable"
        ) else {
            return
        }
        let outcomePaths = Self.referenceBundleProfiles.map(\.outcomePath)
        XCTAssertEqual(outcomePaths.count, 9)
        XCTAssertEqual(outcomePaths, outcomePaths.sorted())

        for profile in Self.referenceBundleProfiles {
            let payloads = try profile.inputs.map { input in
                SorafsFixtureBundlePayloadInput(
                    kind: input.kind,
                    payload: try fixture("sorafs_manifest/\(input.path)"),
                    label: input.path
                )
            }
            let actual = try SorafsReferenceValidators.validateFixtureBundleJSON(
                payloads: payloads,
                nowUnix: profile.nowUnix,
                generatedAtUnix: Self.referenceFixtureGeneratedAtUnix
            )
            XCTAssertEqual(
                Data(actual.utf8),
                try fixture("sorafs_manifest/reference_sdk/\(profile.outcomePath)"),
                profile.outcomePath
            )
        }
    }

    func testValidatesModerationGovernanceLogNodeOutcomeByteForByte() throws {
        guard try requireNativeCapability(
            SorafsReferenceValidators.isGovernanceLogNodeNativeAvailable,
            "SoraFS governance-log-node reference bridge unavailable"
        ) else {
            return
        }
        let expectedNodeCid = try XCTUnwrap(
            Data(
                hexString: "4dd7d8901fd8fdd78ce9edd0456fa1dc"
                    + "6bb072709ddc762e43116013c15ff20c"
            )
        )
        let actual = try SorafsReferenceValidators.validateGovernanceLogNodeJSON(
            payload: try fixture("sorafs_manifest/moderation/governance_node_v1.to"),
            label: "moderation/governance_node_v1.to",
            expectedNodeCid: expectedNodeCid,
            generatedAtUnix: Self.referenceFixtureGeneratedAtUnix
        )
        XCTAssertEqual(
            Data(actual.utf8),
            try fixture(
                "sorafs_manifest/moderation/governance_node_validation_outcome_v1.json"
            )
        )
    }

    func testValidatesAllPdpOutcomeFixturesWhenNativeBridgeIsAvailable() throws {
        guard try requireNativeCapability(
            SorafsReferenceValidators.isNativeAvailable,
            "SoraFS reference bridge unavailable"
        ) else {
            return
        }
        let commitment = try fixture("sorafs_manifest/pdp/commitment_v1.to")
        let challenge = try fixture("sorafs_manifest/pdp/challenge_v1.to")
        let proof = try fixture("sorafs_manifest/pdp/proof_v1.to")
        let bundle = try SorafsReferenceValidators.validatePdpBundleJSON(
            commitment: commitment,
            challenge: challenge,
            proof: proof,
            commitmentLabel: "commitment_v1.to",
            challengeLabel: "challenge_v1.to",
            proofLabel: "proof_v1.to",
            generatedAtUnix: 123
        )
        XCTAssertEqual(
            bundle,
            String(
                decoding: try fixture(
                    "sorafs_manifest/pdp/bundle_validation_outcome_v1.json"
                ),
                as: UTF8.self
            )
        )

        for (name, kind) in [
            ("duplicate_hot_leaf_challenge", SorafsPdpPayloadKind.challenge),
            ("missing_signature_proof", SorafsPdpPayloadKind.proof)
        ] {
            let outcome = try SorafsReferenceValidators.validatePdpPayloadJSON(
                kind: kind,
                payload: try fixture("sorafs_manifest/pdp/negative/\(name)_v1.to"),
                label: "\(name)_v1.to",
                generatedAtUnix: 123
            )
            XCTAssertEqual(
                outcome,
                String(
                    decoding: try fixture(
                        "sorafs_manifest/pdp/negative/"
                            + "\(name)_validation_outcome_v1.json"
                    ),
                    as: UTF8.self
                ),
                name
            )
        }

        for name in [
            "late_proof",
            "wrong_manifest_proof",
            "wrong_provider_proof"
        ] {
            let outcome = try SorafsReferenceValidators.validatePdpChallengeProofJSON(
                challenge: challenge,
                proof: try fixture("sorafs_manifest/pdp/negative/\(name)_v1.to"),
                challengeLabel: "challenge_v1.to",
                proofLabel: "\(name)_v1.to",
                generatedAtUnix: 123
            )
            XCTAssertEqual(
                outcome,
                String(
                    decoding: try fixture(
                        "sorafs_manifest/pdp/negative/"
                            + "\(name)_validation_outcome_v1.json"
                    ),
                    as: UTF8.self
                ),
                name
            )
        }

        for name in [
            "missing_hot_leaf_path_proof",
            "missing_segment_path_proof",
            "wrong_path_proof"
        ] {
            let outcome = try SorafsReferenceValidators.validatePdpBundleJSON(
                commitment: commitment,
                challenge: challenge,
                proof: try fixture("sorafs_manifest/pdp/negative/\(name)_v1.to"),
                commitmentLabel: "commitment_v1.to",
                challengeLabel: "challenge_v1.to",
                proofLabel: "\(name)_v1.to",
                generatedAtUnix: 123
            )
            XCTAssertEqual(
                outcome,
                String(
                    decoding: try fixture(
                        "sorafs_manifest/pdp/negative/"
                            + "\(name)_validation_outcome_v1.json"
                    ),
                    as: UTF8.self
                ),
                name
            )
        }
    }

    func testValidatesGovernanceDagFixturesAndNegativeVectorsWhenNativeBridgeIsAvailable() throws {
        guard try requireGovernanceDagNativeBridge() else {
            return
        }
        let first = try fixture("sorafs_manifest/governance/dag_block_0_v1.to")
        let second = try fixture("sorafs_manifest/governance/dag_block_1_v1.to")
        let head = try fixture("sorafs_manifest/governance/dag_head_v1.to")

        let blockOutcome = try SorafsReferenceValidators.validateGovernanceDagBlockJSON(
            payload: first,
            label: "dag_block_0_v1.to",
            generatedAtUnix: 123
        )
        XCTAssertEqual(
            blockOutcome,
            String(
                decoding: try fixture(
                    "sorafs_manifest/governance/"
                        + "dag_block_validation_outcome_v1.json"
                ),
                as: UTF8.self
            )
        )

        let cidMismatch = try SorafsReferenceValidators.validateGovernanceDagBlockJSON(
            payload: first,
            expectedBlockCid: Data(repeating: 0x7F, count: 32),
            generatedAtUnix: 123
        )
        XCTAssertEqual(
            cidMismatch,
            String(
                decoding: try fixture(
                    "sorafs_manifest/governance/"
                        + "dag_block_cid_mismatch_validation_outcome_v1.json"
                ),
                as: UTF8.self
            )
        )

        let headOutcome = try SorafsReferenceValidators.validateGovernanceDagHeadChainJSON(
            head: head,
            blocks: [
                SorafsGovernanceDagBlockInput(
                    payload: first,
                    label: "dag_block_0_v1.to"
                ),
                SorafsGovernanceDagBlockInput(
                    payload: second,
                    label: "dag_block_1_v1.to"
                )
            ],
            headLabel: "dag_head_v1.to",
            generatedAtUnix: 123
        )
        let goldenOutcome = String(
            decoding: try fixture(
                "sorafs_manifest/governance/dag_head_validation_outcome_v1.json"
            ),
            as: UTF8.self
        )
        XCTAssertEqual(headOutcome, goldenOutcome)

        let reordered = try SorafsReferenceValidators.validateGovernanceDagHeadChainJSON(
            head: head,
            blocks: [
                SorafsGovernanceDagBlockInput(payload: second),
                SorafsGovernanceDagBlockInput(payload: first)
            ],
            generatedAtUnix: 123
        )
        XCTAssertEqual(
            reordered,
            String(
                decoding: try fixture(
                    "sorafs_manifest/governance/"
                        + "dag_head_reordered_validation_outcome_v1.json"
                ),
                as: UTF8.self
            )
        )

        let blockSignatureOutcome =
            try SorafsReferenceValidators.validateGovernanceDagBlockJSON(
                payload: try fixture(
                    "sorafs_manifest/governance/dag_block_bad_signature_v1.to"
                ),
                label: "dag_block_bad_signature_v1.to",
                generatedAtUnix: 123
            )
        XCTAssertEqual(
            blockSignatureOutcome,
            String(
                decoding: try fixture(
                    "sorafs_manifest/governance/"
                        + "dag_block_bad_signature_validation_outcome_v1.json"
                ),
                as: UTF8.self
            )
        )

        let trailingBytesOutcome =
            try SorafsReferenceValidators.validateGovernanceDagBlockJSON(
                payload: try fixture(
                    "sorafs_manifest/governance/dag_block_trailing_bytes_v1.to"
                ),
                label: "dag_block_trailing_bytes_v1.to",
                generatedAtUnix: 123
            )
        XCTAssertEqual(
            trailingBytesOutcome,
            String(
                decoding: try fixture(
                    "sorafs_manifest/governance/"
                        + "dag_block_trailing_bytes_validation_outcome_v1.json"
                ),
                as: UTF8.self
            )
        )

        let headSignatureOutcome =
            try SorafsReferenceValidators.validateGovernanceDagHeadChainJSON(
                head: try fixture(
                    "sorafs_manifest/governance/dag_head_bad_signature_v1.to"
                ),
                blocks: [
                    SorafsGovernanceDagBlockInput(
                        payload: first,
                        label: "dag_block_0_v1.to"
                    ),
                    SorafsGovernanceDagBlockInput(
                        payload: second,
                        label: "dag_block_1_v1.to"
                    )
                ],
                headLabel: "dag_head_bad_signature_v1.to",
                generatedAtUnix: 123
            )
        XCTAssertEqual(
            headSignatureOutcome,
            String(
                decoding: try fixture(
                    "sorafs_manifest/governance/"
                        + "dag_head_bad_signature_validation_outcome_v1.json"
                ),
                as: UTF8.self
            )
        )

        let predecessorOutcome =
            try SorafsReferenceValidators.validateGovernanceDagHeadChainJSON(
                head: try fixture(
                    "sorafs_manifest/governance/dag_head_bad_predecessor_v1.to"
                ),
                blocks: [
                    SorafsGovernanceDagBlockInput(
                        payload: first,
                        label: "dag_block_0_v1.to"
                    ),
                    SorafsGovernanceDagBlockInput(
                        payload: try fixture(
                            "sorafs_manifest/governance/"
                                + "dag_block_1_bad_predecessor_v1.to"
                        ),
                        label: "dag_block_1_bad_predecessor_v1.to"
                    )
                ],
                headLabel: "dag_head_bad_predecessor_v1.to",
                generatedAtUnix: 123
            )
        XCTAssertEqual(
            predecessorOutcome,
            String(
                decoding: try fixture(
                    "sorafs_manifest/governance/"
                        + "dag_head_bad_predecessor_validation_outcome_v1.json"
                ),
                as: UTF8.self
            )
        )
    }

    private func requireGovernanceDagNativeBridge() throws -> Bool {
        try requireNativeCapability(
            SorafsReferenceValidators.isGovernanceDagNativeAvailable,
            "SoraFS governance DAG reference bridge unavailable"
        )
    }

    private func requireNativeCapability(
        _ available: Bool,
        _ unavailableMessage: String
    ) throws -> Bool {
        guard !available else { return true }
        XCTFail("\(Self.nativeValidationRequiredMessage) \(unavailableMessage)")
        return false
    }

    func testSignsOrderbookFixtureWhenNativeBridgeIsAvailable() throws {
        guard try requireNativeCapability(
            SorafsReferenceValidators.isOrderbookSigningAvailable,
            "SoraFS orderbook signing bridge unavailable"
        ) else {
            return
        }
        let payload = try fixture("sorafs_manifest/orderbook/order_request_v1.to")
        let signed = try SorafsReferenceValidators.signOrderbookPayload(
            kind: .orderRequest,
            payload: payload,
            privateKey: Data(repeating: 0xB8, count: 32)
        )
        XCTAssertFalse(signed.isEmpty)
        XCTAssertNotEqual(signed, payload)
        let json = try SorafsReferenceValidators.validateOrderbookPayloadJSON(
            kind: .orderRequest,
            payload: signed,
            label: "order_request_resigned_v1.to",
            generatedAtUnix: 123
        )
        let jsonData = try XCTUnwrap(json.data(using: .utf8))
        let outcome = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: jsonData) as? [String: Any]
        )
        XCTAssertEqual(outcome["status"] as? String, "Ok")
        XCTAssertEqual(outcome["code"] as? String, "SFS-OK-000")
    }

    func testDerivesCanonicalOrderIdAndRejectsExplicitMismatchWhenNativeBridgeIsAvailable() throws {
        guard try requireNativeCapability(
            SorafsReferenceValidators.isOrderbookFieldBuilderAvailable,
            "SoraFS orderbook field-builder bridge unavailable"
        ) else {
            return
        }
        let owner = Data("buyer@sora".utf8)
        let orderId = try SorafsReferenceValidators.deriveOrderbookOrderId(
            ownerAccount: owner,
            nonce: 7
        )
        XCTAssertEqual(
            orderId,
            Data(hexString: "9d91ad7700ca0c4762e031f9231aa38dd4502c6048c6ffa31d365e3c4e080b69")
        )
        XCTAssertNotEqual(
            orderId,
            try SorafsReferenceValidators.deriveOrderbookOrderId(ownerAccount: owner, nonce: 8)
        )
        XCTAssertNotEqual(
            orderId,
            try SorafsReferenceValidators.deriveOrderbookOrderId(
                ownerAccount: Data("provider@sora".utf8),
                nonce: 7
            )
        )

        let maximumOwner = Data(
            repeating: 0x45,
            count: SorafsReferenceValidators.orderbookOwnerAccountMaxBytesV1
        )
        let maximumOwnerOrderId = try SorafsReferenceValidators.deriveOrderbookOrderId(
            ownerAccount: maximumOwner,
            nonce: 9
        )
        let maximumOwnerOrder = try SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
            SorafsSignedOrderbookOrderRequestFields(
                side: .bid,
                tier: .hot,
                pricePerGib: "1",
                quantityGib: 1,
                ownerAccount: maximumOwner,
                expiryUnix: 1_800_000_000,
                nonce: 9,
                makerFeeBps: 0,
                takerFeeBps: 0
            ),
            privateKey: Data(repeating: 0xB7, count: 32)
        )
        let maximumOwnerOrderOutcome = try SorafsReferenceValidators.validateOrderbookPayloadJSON(
            kind: .orderRequest,
            payload: maximumOwnerOrder,
            generatedAtUnix: 123
        )
        XCTAssertTrue(maximumOwnerOrderOutcome.contains("\"status\": \"Ok\""))
        let maximumOwnerCancel = try SorafsReferenceValidators.buildSignedOrderbookOrderCancel(
            SorafsSignedOrderbookOrderCancelFields(
                orderId: maximumOwnerOrderId,
                ownerAccount: maximumOwner,
                reason: .ownerRequested,
                nonce: 10
            ),
            privateKey: Data(repeating: 0xB7, count: 32)
        )
        let maximumOwnerCancelOutcome = try SorafsReferenceValidators.validateOrderbookPayloadJSON(
            kind: .orderCancel,
            payload: maximumOwnerCancel,
            generatedAtUnix: 123
        )
        XCTAssertTrue(maximumOwnerCancelOutcome.contains("\"status\": \"Ok\""))

        let canonicalFields = SorafsSignedOrderbookOrderRequestFields(
            side: .bid,
            tier: .hot,
            pricePerGib: maxScaledXor,
            quantityGib: 64,
            ownerAccount: owner,
            expiryUnix: 1_800_000_000,
            nonce: 7,
            makerFeeBps: 10,
            takerFeeBps: 15
        )
        let signed = try SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
            canonicalFields,
            privateKey: Data(repeating: 0xB7, count: 32)
        )
        let outcome = try SorafsReferenceValidators.validateOrderbookPayloadJSON(
            kind: .orderRequest,
            payload: signed,
            generatedAtUnix: 123
        )
        XCTAssertTrue(outcome.contains("\"status\": \"Ok\""), outcome)

        let askFields = SorafsSignedOrderbookOrderRequestFields(
            side: .ask,
            tier: .hot,
            pricePerGib: "1.25",
            quantityGib: 4,
            ownerAccount: owner,
            providerId: Data(repeating: 0x72, count: 32),
            expiryUnix: 1_800_000_000,
            nonce: 8,
            makerFeeBps: 10,
            takerFeeBps: 15
        )
        let ask = try SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
            askFields,
            privateKey: Data(repeating: 0xB7, count: 32)
        )
        let askOutcome = try SorafsReferenceValidators.validateOrderbookPayloadJSON(
            kind: .orderRequest,
            payload: ask,
            generatedAtUnix: 123
        )
        XCTAssertTrue(askOutcome.contains("\"status\": \"Ok\""), askOutcome)

        XCTAssertThrowsError(
            try SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
                SorafsSignedOrderbookOrderRequestFields(
                    side: .bid,
                    tier: .hot,
                    pricePerGib: "1",
                    quantityGib: 1,
                    ownerAccount: owner,
                    providerId: Data(repeating: 0x72, count: 32),
                    expiryUnix: 1_800_000_000,
                    nonce: 17,
                    makerFeeBps: 0,
                    takerFeeBps: 0
                ),
                privateKey: Data(repeating: 0xB7, count: 32)
            )
        ) { error in
            XCTAssertEqual(
                error as? SorafsReferenceValidationError,
                .invalidOrderbookField(
                    "providerId must be absent or empty for bid orders"
                )
            )
        }

        XCTAssertThrowsError(
            try SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
                SorafsSignedOrderbookOrderRequestFields(
                    side: .ask,
                    tier: .hot,
                    pricePerGib: "1",
                    quantityGib: 1,
                    ownerAccount: owner,
                    expiryUnix: 1_800_000_000,
                    nonce: 17,
                    makerFeeBps: 0,
                    takerFeeBps: 0
                ),
                privateKey: Data(repeating: 0xB7, count: 32)
            )
        ) { error in
            XCTAssertEqual(
                error as? SorafsReferenceValidationError,
                .invalidOrderbookField(
                    "providerId must be exactly 32 bytes for ask orders"
                )
            )
        }

        let mismatchedFields = SorafsSignedOrderbookOrderRequestFields(
            orderId: Data(repeating: 0x11, count: 32),
            side: .bid,
            tier: .hot,
            pricePerGib: "0.000000001",
            quantityGib: 64,
            ownerAccount: owner,
            expiryUnix: 1_800_000_000,
            nonce: 7,
            makerFeeBps: 10,
            takerFeeBps: 15
        )
        XCTAssertThrowsError(
            try SorafsReferenceValidators.buildSignedOrderbookOrderRequest(
                mismatchedFields,
                privateKey: Data(repeating: 0xB7, count: 32)
            )
        ) { error in
            XCTAssertEqual(
                error as? SorafsReferenceValidationError,
                .invalidOrderbookField(
                    "orderId must equal the canonical owner-and-nonce derivation"
                )
            )
        }
    }

    private func fixture(_ relativePath: String) throws -> Data {
        let testFile = URL(fileURLWithPath: #filePath)
        let url = testFile
            .deletingLastPathComponent()
            .appendingPathComponent("../../../fixtures/\(relativePath)")
            .standardizedFileURL
        return try Data(contentsOf: url)
    }
}
