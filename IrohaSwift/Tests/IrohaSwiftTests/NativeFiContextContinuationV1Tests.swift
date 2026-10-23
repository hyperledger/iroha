import CryptoKit
import Foundation
import XCTest
@testable import IrohaSwift

final class NativeFiContextContinuationV1Tests: XCTestCase {
    private func trust() throws -> NativeFiContextTrustV1 {
        let target = NativeFiLinkApprovalTargetV1(assetDefinitionId: "asset#domain", accountId: "wallet", fiAccountId: "fi",
            referenceDigest: Data(repeating: 2, count: 32), fiRevision: 1, attestationRevision: 1,
            revision: 1, expectedPolicyRevision: 1, enabled: true, controller: nil, waterfall: false, reverseWaterfall: false)
        return .init(networkId: try NetworkId(bytes: Data(repeating: 1, count: 32)), chainId: "chain",
            checkpointSHA256: Data(repeating: 2, count: 32), checkpointHeight: 2,
            checkpointContextID: Data(repeating: 3, count: 32), assetOwner: "owner",
            assetIncarnation: Data(repeating: 5, count: 32), assetDefinitionId: "asset#domain",
            walletAccountId: "wallet", uid: Data(repeating: 6, count: 32), fiAccountId: "fi", fiParticipant: "participant",
            uidController: nil, runtimeManifestSHA256: Data(repeating: 7, count: 32), ownerKeyIdentity: "key",
            walletScopeCanonical: Data("{}".utf8), retainedRequestSHA256: Data(SHA256.hash(data: Data([9]))), target: target)
    }
    func testAdmissionMetadataRetainsExactOriginalAndChecksBothStatusHashes() throws {
        let selected = try trust(), wire = Data([1, 2, 3]), entrypoint = Data(repeating: 5, count: 32)
        let sha = Data(SHA256.hash(data: wire))
        func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
        let object = ["schema": "iroha.fi-assertion-original.admitted.v1", "requestSha256": hex(selected.retainedRequestSHA256),
            "assertionEntrypointHash": hex(entrypoint), "assertionWireSha256": hex(sha),
            "originalCheckpointHeight": "2", "originalCheckpointBlockHash": hex(entrypoint)]
        func decode(_ value: [String: String], actualWire: Data = wire) throws -> AdmittedFiAssertionOriginalV1 {
            try NativeFiContextContinuationV1.decodeAdmittedOriginal(JSONSerialization.data(withJSONObject: value),
                signedOriginal: actualWire, trust: selected, trustJSON: Data("local-trust".utf8),
                expectedEntrypointHash: entrypoint, expectedWireSHA256: sha)
        }
        let admitted = try decode(object)
        XCTAssertEqual(admitted.signedOriginal, wire); XCTAssertEqual(admitted.wireSHA256, sha)
        XCTAssertEqual(admitted.entrypointHash, entrypoint); XCTAssertEqual(admitted.originalCheckpointHeight, 2)
        XCTAssertThrowsError(try decode(object, actualWire: Data([1, 2, 4])))
        for (key, value) in [("schema", "untrusted"), ("requestSha256", String(repeating: "01", count: 32)),
                             ("assertionEntrypointHash", String(repeating: "07", count: 32)),
                             ("assertionWireSha256", String(repeating: "01", count: 32)),
                             ("originalCheckpointHeight", "02"), ("originalCheckpointBlockHash", String(repeating: "04", count: 32)),
                             ("extra", "field")] {
            var changed = object; changed[key] = value
            XCTAssertThrowsError(try decode(changed))
        }
    }
    func testMalformedOriginalRefusesBeforeNativeAdmission() throws {
        let selected = try trust()
        for wire in [Data(), Data(repeating: 1, count: 64 * 1024 + 1)] {
            XCTAssertThrowsError(try NativeFiContextContinuationV1.admitOriginal(signedOriginal: wire,
                retainedRequest: Data([9]), originalCheckpoint: Data([1]), trust: selected,
                statusEntrypointHash: Data(repeating: 5, count: 32), statusWireSHA256: Data(SHA256.hash(data: wire)))) {
                XCTAssertEqual($0 as? NativeFiContextAssertionErrorV1, .invalidInput)
            }
        }
        XCTAssertThrowsError(try NativeFiContextContinuationV1.admitOriginal(signedOriginal: Data([1]),
            retainedRequest: Data([8]), originalCheckpoint: Data([1]), trust: selected,
            statusEntrypointHash: Data(repeating: 5, count: 32), statusWireSHA256: Data(SHA256.hash(data: Data([1]))))) {
            XCTAssertEqual($0 as? NativeFiContextAssertionErrorV1, .invalidInput)
        }
    }
}
