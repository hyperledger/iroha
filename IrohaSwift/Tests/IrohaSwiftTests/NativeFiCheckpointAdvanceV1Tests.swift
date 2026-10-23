import CryptoKit
import Foundation
import XCTest
@testable import IrohaSwift

final class NativeFiCheckpointAdvanceV1Tests: XCTestCase {
    func testMalformedAndOverBoundPagesRefuseBeforeNativeDispatch() throws {
        let checkpoint = Data([1]), sha = Data(repeating: 2, count: 32), context = Data(repeating: 3, count: 32)
        for page in [[], [Data([1])], [Data(), Data([1])],
                     Array(repeating: Data([1]), count: 4097),
                     [Data(repeating: 1, count: 16 * 1024 * 1024), Data([1])]] {
            XCTAssertThrowsError(try NativeFiCheckpointAdvanceV1.validate(checkpoint: checkpoint,
                proofOriginals: page, chain: "chain", sha: sha, height: 2, context: context))
        }
        for height in [UInt64(0), UInt64.max] {
            XCTAssertThrowsError(try NativeFiCheckpointAdvanceV1.validate(checkpoint: checkpoint,
                proofOriginals: [Data([1]), Data([2])], chain: "chain", sha: sha, height: height, context: context))
        }
        try NativeFiCheckpointAdvanceV1.validate(checkpoint: checkpoint,
            proofOriginals: [Data([1]), Data([2])], chain: "chain", sha: sha, height: 2, context: context)
    }

    func testNativeMetadataChecksDigestDomainSuccessorAndFullUnsignedHeight() throws {
        let checkpoint = Data([4, 5, 6]), height = UInt64.max - 1
        let object: [String: String] = ["schema": "iroha.fi-checkpoint-advance.verified.v1",
            "networkId": "network", "chainId": "chain", "anchorHeight": String(height - 1),
            "height": String(height), "proofCount": "2",
            "checkpointSha256": SHA256.hash(data: checkpoint).map { String(format: "%02x", $0) }.joined(),
            "contextId": String(repeating: "03", count: 32), "blockHash": String(repeating: "05", count: 32)]
        func decode(_ value: [String: String], _ cp: Data = checkpoint) throws -> VerifiedFiCheckpointAdvanceV1 {
            try NativeFiCheckpointAdvanceV1.decodeNativeResult(JSONSerialization.data(withJSONObject: value),
                checkpoint: cp, network: "network", chain: "chain", anchorHeight: height - 1, proofCount: 2)
        }
        let verified = try decode(object)
        XCTAssertEqual(verified.height, height); XCTAssertEqual(verified.checkpoint, checkpoint)
        XCTAssertThrowsError(try decode(object, Data([4, 5, 7])))
        for (key, value) in [("networkId", "other"), ("chainId", "other"), ("anchorHeight", "2"),
                             ("height", String(height - 1)), ("height", "0" + String(height)),
                             ("height", String(UInt64.max)), ("proofCount", "3"),
                             ("contextId", String(repeating: "00", count: 32)),
                             ("blockHash", String(repeating: "04", count: 32)), ("extra", "field")] {
            var changed = object; changed[key] = value
            XCTAssertThrowsError(try decode(changed), key)
        }
    }
}
