import Foundation
import XCTest
@testable import IrohaSwift

final class DetachedTransactionNativeBridgeTests: XCTestCase {
    private let hashA = String(repeating: "11", count: 32)
    private let hashB = String(repeating: "22", count: 32)
    private let hashC = String(repeating: "33", count: 32)
    private let networkId = TestNetworkIds.canonical

    func testContractInspectionDecodesTypedBindingsAndLosslessMetadataIntegers() throws {
        let json = Data(
            """
            {
              "schema":"iroha.detached_transaction_scaffold.v1",
              "payload_signing_hash_hex":"\(hashA)","payload_hash_hex":"\(hashC)","fee_payment":{"payer":"authority","value":{"charge_limits":[],"gas_limit":null}},
              "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
              "network_id":"\(networkId.literal)",
              "creation_time_ms":18446744073709551615,
              "time_to_live_ms":60000,
              "metadata":{"signed":-9223372036854775808,"unsigned":18446744073709551615,"nested":{"ok":true}},
              "entrypoint_hash_hex":"\(hashB)",
              "executable":{"kind":"contract_call","contract_address":"irohac1contract","expected_code_hash":"hash:contract","entrypoint":"pay","arguments_b64":"AQID"}
            }
            """.utf8
        )
        let inspection = try DetachedTransactionBridgeJSONCodec.decodeInspection(json)
        XCTAssertEqual(inspection.payloadSigningHash, Data(repeating: 0x11, count: 32))
        XCTAssertEqual(inspection.payloadHash, Data(repeating: 0x33, count: 32))
        XCTAssertEqual(inspection.feePayment, .authority(chargeLimits: [], gasLimit: nil))
        XCTAssertEqual(inspection.entrypointHash, Data(repeating: 0x22, count: 32))
        XCTAssertEqual(inspection.networkId, networkId)
        XCTAssertEqual(inspection.creationTimeMs, UInt64.max)
        XCTAssertEqual(inspection.metadata["signed"], .signedInteger(Int64.min))
        XCTAssertEqual(inspection.metadata["unsigned"], .unsignedInteger(UInt64.max))
        guard case let .contractCall(call) = inspection.executable else {
            return XCTFail("expected contract call")
        }
        XCTAssertEqual(call.contractAddress, "irohac1contract")
        XCTAssertEqual(call.expectedCodeHash, "hash:contract")
        XCTAssertEqual(call.entrypoint, "pay")
        XCTAssertEqual(call.arguments, Data([1, 2, 3]))
    }

    func testAssetTransferInspectionDecodesGlobalAndDataspaceScopes() throws {
        for (scopeJSON, expectedScope) in [
            ("{\"kind\":\"global\"}", DetachedAssetScopeInspection.global),
            ("{\"kind\":\"dataspace\",\"dataspace_id\":42}", .dataspace(42))
        ] {
            let json = Data(
                """
                {"schema":"iroha.detached_transaction_scaffold.v1","payload_signing_hash_hex":"\(hashA)","payload_hash_hex":"\(hashC)","fee_payment":{"payer":"authority","value":{"charge_limits":[],"gas_limit":null}},"authority":"source","network_id":"\(networkId.literal)","creation_time_ms":1,"time_to_live_ms":60000,"metadata":{},"entrypoint_hash_hex":"\(hashB)","executable":{"kind":"asset_transfer","asset_definition_id":"asset","asset_scope":\(scopeJSON),"source_asset_id":"asset#source","source_account_id":"source","destination_account_id":"destination","amount":"1.25"}}
                """.utf8
            )
            let inspection = try DetachedTransactionBridgeJSONCodec.decodeInspection(json)
            guard case let .assetTransfer(transfer) = inspection.executable else {
                return XCTFail("expected asset transfer")
            }
            XCTAssertEqual(transfer.assetScope, expectedScope)
            XCTAssertEqual(transfer.amount, "1.25")
        }
    }

    func testAtomicTransferBatchInspectionRetainsOrderAndRejectsExtraOrMissingLegs() throws {
        let principal = """
        {"kind":"asset_transfer","asset_definition_id":"asset","asset_scope":{"kind":"dataspace","dataspace_id":18446744073709551615},"source_asset_id":"principal","source_account_id":"source","destination_account_id":"recipient","amount":"10"}
        """
        let fee = principal.replacingOccurrences(of: "principal", with: "fee").replacingOccurrences(of: "recipient", with: "treasury").replacingOccurrences(of: "\"amount\":\"10\"", with: "\"amount\":\"1\"")
        func json(_ legs: String) -> Data { Data("""
        {"schema":"iroha.detached_transaction_scaffold.v1","payload_signing_hash_hex":"\(hashA)","payload_hash_hex":"\(hashC)","fee_payment":{"payer":"authority","value":{"charge_limits":[],"gas_limit":null}},"authority":"source","network_id":"\(networkId.literal)","creation_time_ms":1,"time_to_live_ms":60000,"metadata":{"fee_instruction_index":1},"entrypoint_hash_hex":"\(hashB)","executable":{"kind":"atomic_transfer_sequence","transfers":[\(legs)]}}
        """.utf8) }
        let result = try DetachedTransactionBridgeJSONCodec.decodeInspection(json(principal + "," + fee))
        guard case let .atomicTransferSequence(transfers) = result.executable else { return XCTFail("batch") }
        XCTAssertEqual(transfers.map(\.destinationAccountId), ["recipient", "treasury"])
        XCTAssertEqual(transfers[0].assetScope, .dataspace(UInt64.max))
        for legs in ["", principal, principal + "," + fee + "," + fee, principal + "," + fee.replacingOccurrences(of: "asset_transfer", with: "atomic_transfer_sequence"), principal + "," + fee.replacingOccurrences(of: "\"amount\":", with: "\"extra\":true,\"amount\":")] {
            XCTAssertThrowsError(try DetachedTransactionBridgeJSONCodec.decodeInspection(json(legs)))
        }
    }

    func testInspectionRejectsSchemaHashBase64AndScopeSubstitution() {
        let valid = """
        {"schema":"iroha.detached_transaction_scaffold.v1","payload_signing_hash_hex":"\(hashA)","payload_hash_hex":"\(hashC)","fee_payment":{"payer":"authority","value":{"charge_limits":[],"gas_limit":null}},"authority":"a","network_id":"\(networkId.literal)","creation_time_ms":1,"time_to_live_ms":60000,"metadata":{},"entrypoint_hash_hex":"\(hashB)","executable":{"kind":"contract_call","contract_address":"x","expected_code_hash":"hash:contract","entrypoint":"y","arguments_b64":null}}
        """
        let hostile = [
            valid.replacingOccurrences(of: "iroha.detached_transaction_scaffold.v1", with: "other"),
            valid.replacingOccurrences(of: hashA, with: String(repeating: "AA", count: 32)),
            valid.replacingOccurrences(of: hashB, with: "22"),
            valid.replacingOccurrences(of: "\"arguments_b64\":null", with: "\"arguments_b64\":\"AQI\""),
            valid.replacingOccurrences(of: "\"expected_code_hash\":\"hash:contract\"", with: "\"expected_code_hash\":\"\""),
            valid.replacingOccurrences(of: "\"kind\":\"contract_call\"", with: "\"kind\":\"ivm\""),
            valid.replacingOccurrences(of: "\"time_to_live_ms\":60000", with: "\"time_to_live_ms\":null"),
            valid.replacingOccurrences(of: networkId.literal, with: networkId.literal.lowercased()),
            valid.replacingOccurrences(of: networkId.literal, with: "network-label"),
            valid.replacingOccurrences(of: "\"schema\":", with: "\"future\":true,\"schema\":"),
            valid.replacingOccurrences(
                of: "\"schema\":\"iroha.detached_transaction_scaffold.v1\"",
                with: "\"schema\":\"other\",\"schema\":\"iroha.detached_transaction_scaffold.v1\""
            )
        ]
        for candidate in hostile {
            XCTAssertThrowsError(
                try DetachedTransactionBridgeJSONCodec.decodeInspection(Data(candidate.utf8))
            )
        }

        for retiredKey in ["chain", "chain_id", "chainId"] {
            let retired = valid.replacingOccurrences(of: "\"network_id\"", with: "\"\(retiredKey)\"")
            XCTAssertThrowsError(
                try DetachedTransactionBridgeJSONCodec.decodeInspection(Data(retired.utf8)),
                retiredKey
            )
        }

        let impossibleScope = valid
            .replacingOccurrences(
                of: "{\"kind\":\"contract_call\",\"contract_address\":\"x\",\"expected_code_hash\":\"hash:contract\",\"entrypoint\":\"y\",\"arguments_b64\":null}",
                with: "{\"kind\":\"asset_transfer\",\"asset_definition_id\":\"d\",\"asset_scope\":{\"kind\":\"global\",\"dataspace_id\":1},\"source_asset_id\":\"s\",\"source_account_id\":\"a\",\"destination_account_id\":\"b\",\"amount\":\"1\"}"
            )
        XCTAssertThrowsError(
            try DetachedTransactionBridgeJSONCodec.decodeInspection(Data(impossibleScope.utf8))
        )
    }

    func testFinalizationRequiresExactSchemaAndLowercaseHashes() throws {
        let valid = Data(
            """
            {"schema":"iroha.detached_transaction_finalization.v1","payload_signing_hash_hex":"\(hashA)","transaction_hash_hex":"\(hashB)","entrypoint_hash_hex":"\(hashC)"}
            """.utf8
        )
        let finalization = try DetachedTransactionBridgeJSONCodec.decodeFinalization(valid)
        XCTAssertEqual(finalization.payloadSigningHash, Data(repeating: 0x11, count: 32))
        XCTAssertEqual(finalization.transactionHash, Data(repeating: 0x22, count: 32))
        XCTAssertEqual(finalization.entrypointHash, Data(repeating: 0x33, count: 32))
        let uppercaseHash = "AB" + String(hashA.dropFirst(2))

        for candidate in [
            String(decoding: valid, as: UTF8.self).replacingOccurrences(
                of: "iroha.detached_transaction_finalization.v1",
                with: "v0"
            ),
            String(decoding: valid, as: UTF8.self).replacingOccurrences(
                of: hashA,
                with: uppercaseHash
            ),
            String(decoding: valid, as: UTF8.self).replacingOccurrences(
                of: hashC,
                with: "zz" + String(hashC.dropFirst(2))
            ),
            String(decoding: valid, as: UTF8.self).replacingOccurrences(
                of: "\"schema\":",
                with: "\"future\":true,\"schema\":"
            )
        ] {
            XCTAssertThrowsError(
                try DetachedTransactionBridgeJSONCodec.decodeFinalization(Data(candidate.utf8))
            )
        }
    }

    private func monetaryReview(_ executable: String) -> Data {
        Data("""
        {"schema":"iroha.detached_transaction_scaffold.v1","payload_signing_hash_hex":"\(hashA)",
        "payload_hash_hex":"\(hashC)","fee_payment":{"payer":"authority","value":{"charge_limits":[],"gas_limit":null}},
        "authority":"owner","network_id":"\(networkId.literal)","creation_time_ms":1,"time_to_live_ms":60000,
        "metadata":{},"entrypoint_hash_hex":"\(hashB)","executable":\(executable)}
        """.utf8)
    }

    func testNativeBatchReviewRetainsModeOrderedIdentitiesAndRejectsHiddenFields() throws {
        let legs = """
        [{"leg_id":"israel","source_account_id":"owner","destination_account_id":"israel-wallet","asset_definition_id":"ds","amount":"20"},
        {"leg_id":"roman","source_account_id":"owner","destination_account_id":"roman-wallet","asset_definition_id":"ds","amount":"60"}]
        """
        for mode in ["atomic", "independent"] {
            let json = """
            {"kind":"asset_transfer_batch","mode":"\(mode)","entries":\(legs)}
            """
            let result = try DetachedTransactionBridgeJSONCodec.decodeInspection(monetaryReview(json))
            guard case let .assetTransferBatch(batch) = result.executable else { return XCTFail("native batch") }
            XCTAssertEqual(batch.mode.rawValue, mode)
            XCTAssertEqual(batch.entries.map(\.legId), ["israel", "roman"])
            XCTAssertEqual(batch.entries.map(\.amount), ["20", "60"])
            for hostile in [
                json.replacingOccurrences(of: "\"mode\":\"\(mode)\"", with: "\"mode\":\"best_effort\""),
                json.replacingOccurrences(of: "\"leg_id\":\"roman\"", with: "\"leg_id\":\"israel\""),
                json.replacingOccurrences(of: "\"amount\":\"60\"", with: "\"amount\":\"60\",\"hidden_transfer\":true"),
                json.replacingOccurrences(of: "\"entries\":", with: "\"retired_transfers\":"),
            ] {
                XCTAssertThrowsError(try DetachedTransactionBridgeJSONCodec.decodeInspection(monetaryReview(hostile)))
            }
        }
    }

    func testConditionalReviewPreservesIndependentAttestorsAndDistinctDeliveryAndConfirmationTerms() throws {
        let json = """
        {"kind":"conditional_escrow_open","escrow_id":"laptop","asset_definition_id":"ds","beneficiary":"intel",
        "amount":"20","expires_at_ms":1700604800000,"evidence_hashes":["document-digest"],"conditions":[
        {"kind":"oracle","id":"product","attestor":"product-asp","sequence":1,"predicate":{"kind":"equals","value":{"kind":"text","value":"i7"}}},
        {"kind":"oracle","id":"delivery","attestor":"delivery-asp","sequence":2,"predicate":{"kind":"quantity_at_most","value":"3"}},
        {"kind":"within","id":"confirmation","duration_ms":604800000}]}
        """
        let result = try DetachedTransactionBridgeJSONCodec.decodeInspection(monetaryReview(json))
        guard case let .conditionalEscrowOpen(escrow) = result.executable else { return XCTFail("conditional escrow") }
        XCTAssertEqual(escrow.conditions, [
            .oracle(id: "product", attestor: "product-asp", sequence: 1, predicate: .equals(.text("i7"))),
            .oracle(id: "delivery", attestor: "delivery-asp", sequence: 2, predicate: .quantityAtMost("3")),
            .within(id: "confirmation", durationMs: 604_800_000),
        ])
        XCTAssertEqual(escrow.expiresAtMs, 1_700_604_800_000)
        XCTAssertEqual(escrow.evidenceHashes, ["document-digest"])
        for hostile in [
            json.replacingOccurrences(of: "\"quantity_at_most\"", with: "\"approve_any\""),
            json.replacingOccurrences(of: "\"sequence\":2", with: "\"sequence\":0"),
            json.replacingOccurrences(of: "\"duration_ms\":604800000", with: "\"duration_ms\":604800000,\"cancel_anytime\":true"),
            json.replacingOccurrences(of: "\"value\":\"i7\"", with: "\"value\":true"),
        ] {
            XCTAssertThrowsError(try DetachedTransactionBridgeJSONCodec.decodeInspection(monetaryReview(hostile)))
        }
    }

    func testBridgeStatusMapsNewFailClosedErrors() {
        XCTAssertEqual(NativeBridgeError.fromStatus(-501), .detachedTransactionScaffold)
        XCTAssertEqual(NativeBridgeError.fromStatus(-502), .detachedTransactionSignature)
        XCTAssertEqual(NativeBridgeError.fromStatus(-503), .canonicalJSON)
    }

    func testLinkedABI31CanonicalizerRunsEndToEndAndRejectsHostileJSON() throws {
        let bridge = NoritoNativeBridge.shared
        XCTAssertTrue(bridge.isDetachedTransactionVerificationAvailable)

        let first = try bridge.canonicalizeJSONBlake3(
            Data(#"{ "z": [3,2,1], "a": {"y":true,"x":null} }"#.utf8)
        )
        let second = try bridge.canonicalizeJSONBlake3(
            Data(#"{"a":{"x":null,"y":true},"z":[3,2,1]}"#.utf8)
        )
        XCTAssertEqual(first, second)
        XCTAssertEqual(
            first.canonicalJSON,
            Data(#"{"a":{"x":null,"y":true},"z":[3,2,1]}"#.utf8)
        )
        XCTAssertEqual(first.hash.count, 32)
        XCTAssertTrue(first.hash.contains(where: { $0 != 0 }))

        let empty = try bridge.canonicalizeJSONBlake3(Data())
        XCTAssertTrue(empty.canonicalJSON.isEmpty)
        XCTAssertEqual(
            empty.hash.map { String(format: "%02x", $0) }.joined(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        )

        for hostile in [
            #"{"a":1,"a":2}"#,
            #"{"nested":{"a":1,"a":2}}"#,
            #"{"a":NaN}"#,
            #"{"a":1} false"#,
        ] {
            XCTAssertThrowsError(
                try bridge.canonicalizeJSONBlake3(Data(hostile.utf8)),
                hostile
            ) { error in
                XCTAssertEqual(error as? NativeBridgeError, .canonicalJSON)
            }
        }
    }

    func testPublicModelsAreSendable() {
        func requireSendable<T: Sendable>(_: T.Type) {}
        requireSendable(DetachedTransactionScaffoldInspection.self)
        requireSendable(DetachedTransactionFinalizationResult.self)
        requireSendable(CanonicalJSONBlake3Result.self)
        requireSendable(NativeBridgeJSONValue.self)
    }
}
