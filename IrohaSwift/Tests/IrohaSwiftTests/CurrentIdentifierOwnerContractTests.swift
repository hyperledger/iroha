import Foundation
import XCTest
@testable import IrohaSwift

/// SOURCE controls only until the current genuine Rust DATA fixture has been generated.
final class CurrentIdentifierOwnerContractTests: XCTestCase {
    private let marked = String(repeating: "ab", count: 32)
    private let nonce = String(repeating: "12", count: 32)
    private func object<T: Encodable>(_ value: T) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any])
    }
    private func account(_ seed: UInt8 = 1) throws -> String {
        try Keypair(privateKeyBytes: Data(repeating: seed, count: 32)).accountId(networkPrefix: AccountId.defaultNetworkPrefix)
    }
    private func opening(program: String = "identifier_lookup_retail") -> ToriiRamLfeOutputOpening {
        // Structural DATA; these bytes establish no opening signature authority.
        ToriiRamLfeOutputOpening(payload: ToriiRamLfeOutputOpeningPayload(
            programId: program, inputCiphertextHash: marked, outputCiphertextHash: marked,
            parameterDigest: marked, evaluationKeyDigest: marked, openedOutputHash: marked,
            openedAtMs: 42, expiresAtMs: 142
        ), signature: String(repeating: "ab", count: 64))
    }
    private func programPolicy(key: String, active: Bool = true) throws -> ToriiRamLfeProgramPolicySummary {
        let body: [String: Any] = [
            "program_id": "identifier_lookup_retail", "owner": try account(), "active": active,
            "resolver_public_key": key, "backend": "hkdf-sha3-512-prf-v1", "verification_mode": "signed"
        ]
        return try JSONDecoder().decode(ToriiRamLfeProgramPolicySummary.self, from: JSONSerialization.data(withJSONObject: body))
    }
    func testOwnerInputCarriesOnlyCurrentPrivateFieldsAndRejectsInvalidNonce() throws {
        let request = try ToriiIdentifierLookupRequest.prepare(policyId: "email#retail", normalizedInput: "private@example.org", inputNonceHex: nonce)
        let body = try object(request)
        XCTAssertEqual(Set(body.keys), ["phase", "policy_id", "normalized_input", "input_nonce"])
        XCTAssertEqual(body["phase"] as? String, "prepare")
        XCTAssertEqual(body["normalized_input"] as? String, "private@example.org")
        for bad in [String(repeating: "00", count: 32), nonce.uppercased().replacingOccurrences(of: "12", with: "AB"), "0x" + nonce, nonce + " "] {
            XCTAssertThrowsError(try ToriiRamLfeExecuteRequest.ownerInput(normalizedInput: "private@example.org", inputNonceHex: bad))
        }
        XCTAssertThrowsError(try ToriiRamLfeExecuteRequest.ownerInput(normalizedInput: "", inputNonceHex: nonce))
        XCTAssertThrowsError(try ToriiRamLfeExecuteRequest.ownerInput(normalizedInput: String(repeating: "é", count: 257), inputNonceHex: nonce))
    }
    func testClaimTransportsOriginalTypedOpeningAndPublicOpeningRemainsFlat() throws {
        let original = opening()
        let request = try ToriiIdentifierLookupRequest.claim(policyId: "email#retail", normalizedInput: "private@example.org", inputNonceHex: nonce, outputOpening: original)
        let body = try object(request)
        let typed = try XCTUnwrap(body["output_opening"] as? [String: Any])
        let payload = try XCTUnwrap(typed["payload"] as? [String: Any])
        XCTAssertEqual((payload["program_id"] as? [String: Any])?["name"] as? String, "identifier_lookup_retail")
        XCTAssertEqual(payload["input_ciphertext_hash"] as? String, try ToriiIdentifierOwnerContract.modelHash(marked))
        XCTAssertEqual(typed["signature"] as? String, original.signature.uppercased())
        let flat = try object(original)
        XCTAssertEqual((flat["payload"] as? [String: Any])?["program_id"] as? String, "identifier_lookup_retail")
        XCTAssertEqual(flat["signature"] as? String, original.signature)
        XCTAssertThrowsError(try JSONDecoder().decode(ToriiIdentifierOriginalOpening.self, from: JSONEncoder().encode(original)))
        XCTAssertThrowsError(try JSONDecoder().decode(ToriiRamLfeOutputOpening.self, from: JSONSerialization.data(withJSONObject: typed)))
    }
    func testPhoneOriginalUsesTypedNetworkPolicyProgramAndTupleUaid() throws {
        let original = opening(program: "phone_retail")
        let phone = try ToriiPhoneRetailCanonicalityPayloadV1(
            networkId: TestNetworkIds.canonical, policyId: "phone#retail", programId: "phone_retail",
            inputCiphertextHash: marked, outputCiphertextHash: marked, openedOutputHash: marked,
            canonicalPhoneNullifier: marked, uaid: "uaid:" + marked, accountId: try account(2), issuedAtMs: 42, expiresAtMs: 142
        )
        let signed = try ToriiPhoneRetailCanonicalityAttestationV1(payload: phone, signature: String(repeating: "ab", count: 64))
        let request = try ToriiIdentifierLookupRequest.claim(policyId: "phone#retail", normalizedInput: "+6771234567", inputNonceHex: nonce, outputOpening: original, phoneRetailCanonicality: signed)
        let body = try object(request)
        let carrier = try XCTUnwrap(body["phone_retail_canonicality"] as? [String: Any])
        let payload = try XCTUnwrap(carrier["payload"] as? [String: Any])
        XCTAssertEqual(payload["network_id"] as? String, TestNetworkIds.canonical.literal)
        XCTAssertEqual((payload["policy_id"] as? [String: Any])?["kind"] as? String, "phone")
        XCTAssertEqual((payload["program_id"] as? [String: Any])?["name"] as? String, "phone_retail")
        XCTAssertEqual(payload["uaid"] as? [String], [try ToriiIdentifierOwnerContract.modelHash(marked)])
        XCTAssertEqual(payload["account_id"] as? String, try account(2))
        XCTAssertThrowsError(try ToriiIdentifierLookupRequest.claim(policyId: "phone#retail", normalizedInput: "+6771234567", inputNonceHex: nonce, outputOpening: original))
        XCTAssertThrowsError(try ToriiIdentifierLookupRequest.claim(policyId: "email#retail", normalizedInput: "private@example.org", inputNonceHex: nonce, outputOpening: original, phoneRetailCanonicality: signed))
    }
    func testPrepareAudienceIsMandatoryRawLowerHexWithoutAliases() throws {
        let body: [String: Any] = [
            "network_id": ToriiIdentifierOwnerContract.rawNetwork(TestNetworkIds.canonical),
            "policy_id": "email#retail", "account_id": try account(), "uaid": "uaid:" + marked,
            "output_opening": try object(ToriiIdentifierOriginalOpening(opening()))
        ]
        func decode(_ data: [String: Any]) throws -> ToriiIdentifierPrfPrepareResponse {
            try JSONDecoder().decode(ToriiIdentifierPrfPrepareResponse.self, from: JSONSerialization.data(withJSONObject: data))
        }
        XCTAssertEqual(try decode(body).networkId, TestNetworkIds.canonical)
        var missing = body; missing.removeValue(forKey: "network_id")
        XCTAssertThrowsError(try decode(missing))
        for alias in [TestNetworkIds.canonical.literal, ToriiIdentifierOwnerContract.rawNetwork(TestNetworkIds.canonical).uppercased()] {
            var changed = body; changed["network_id"] = alias
            XCTAssertThrowsError(try decode(changed))
        }
    }
    func testGenuineExecuteDataMatchesNativePayloadAndPinnedResolver() throws {
        let fixture = try currentOwnerExecuteFixture()
        let response = try JSONDecoder().decode(ToriiRamLfeExecuteResponse.self, from: ramLfeExecuteResponseJSON())
        let bytes = try ToriiIdentifierReceiptCanonicalEncoder.encodeExecutionPayload(response.execution)
        XCTAssertEqual(bytes, Data(hexString: try XCTUnwrap(fixture["canonical_execution_payload_hex"] as? String)))
        XCTAssertEqual(ToriiIdentifierReceiptVerifier.prehash(bytes), Data(hexString: try XCTUnwrap(fixture["execution_prehash_hex"] as? String)))
        let policy = try programPolicy(key: XCTUnwrap(fixture["resolver_public_key"] as? String))
        XCTAssertTrue(try response.verifyExecutionResolverAttestation(using: policy))
        XCTAssertThrowsError(try response.verifyExecutionResolverAttestation(using: programPolicy(key: policy.resolverPublicKey, active: false)))
    }
    func testExecuteRejectsAlteredOpaqueFrameHashAndOriginalReceipt() throws {
        let fixture = try currentOwnerExecuteFixture()
        let original = try XCTUnwrap(fixture["response"] as? [String: Any])
        func decode(_ value: [String: Any]) throws -> ToriiRamLfeExecuteResponse {
            try JSONDecoder().decode(ToriiRamLfeExecuteResponse.self, from: JSONSerialization.data(withJSONObject: value))
        }
        for field in ["opaque_output", "output_hash", "opaque_hash", "receipt_hash", "associated_data_hash"] {
            var changed = original
            changed[field] = field == "opaque_output" ? String(repeating: "AB", count: 32) : marked
            XCTAssertThrowsError(try decode(changed), field)
        }
        for value in ["", String(repeating: "AB", count: 4097), (original["program_id_canonical"] as! String).lowercased(), "AB"] {
            var changed = original; changed["program_id_canonical"] = value
            XCTAssertThrowsError(try decode(changed))
        }
        var changed = original
        var receipt = try XCTUnwrap(changed["receipt"] as? [String: Any])
        var payload = try XCTUnwrap(receipt["payload"] as? [String: Any])
        payload["output_ciphertext_hash"] = marked; receipt["payload"] = payload; changed["receipt"] = receipt
        XCTAssertThrowsError(try decode(changed))
    }
    func testExecuteCompleteSignatureRejectsChangedPrivateInputCommitment() throws {
        let fixture = try currentOwnerExecuteFixture()
        var changed = try XCTUnwrap(fixture["response"] as? [String: Any])
        var receipt = try XCTUnwrap(changed["receipt"] as? [String: Any])
        var payload = try XCTUnwrap(receipt["payload"] as? [String: Any])
        payload["input_ciphertext_hash"] = marked; receipt["payload"] = payload; changed["receipt"] = receipt
        let decoded = try JSONDecoder().decode(ToriiRamLfeExecuteResponse.self, from: JSONSerialization.data(withJSONObject: changed))
        XCTAssertFalse(try decoded.verifyExecutionResolverAttestation(using: programPolicy(key: XCTUnwrap(fixture["resolver_public_key"] as? String))))
    }
    func testCanonicalOwnerSignatureBindsSelectedRawNetworkMethodUriAndExactBody() throws {
        let body = try JSONEncoder().encode(ToriiRamLfeExecuteRequest.ownerInput(normalizedInput: "private@example.org", inputNonceHex: nonce))
        let url = URL(string: "https://example.test/v1/ram-lfe/programs/identifier_lookup_retail/execute")!
        func message(network: NetworkId = TestNetworkIds.canonical, method: String = "POST", target: URL? = nil, bytes: Data? = nil) throws -> Data {
            try ToriiCanonicalRequest.signatureMessage(networkId: network, method: method, url: target ?? url, body: bytes ?? body, timestampMs: 42, nonce: nonce)
        }
        let original = try message()
        let foreign = try ToriiIdentifierOwnerContract.network(marked)
        XCTAssertNotEqual(original, try message(network: foreign))
        XCTAssertNotEqual(original, try message(method: "GET"))
        XCTAssertNotEqual(original, try message(target: URL(string: "https://example.test/v1/identifiers/resolve")!))
        XCTAssertNotEqual(original, try message(bytes: body + Data(" ".utf8)))
        XCTAssertTrue(original.starts(with: Data("iroha.app.request.network.v1\0".utf8) + TestNetworkIds.canonical.bytes))
    }
}
