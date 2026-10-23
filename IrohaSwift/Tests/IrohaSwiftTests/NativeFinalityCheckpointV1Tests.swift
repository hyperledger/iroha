import Foundation
import XCTest
@testable import IrohaSwift

final class NativeFinalityCheckpointV1Tests: XCTestCase {
    func testInvalidSelectionRefusesBeforeNativeDispatch() throws {
        let network = try NetworkId(bytes: Data(repeating: 1, count: 32))
        for (checkpoint, chain, sha, height, context) in [
            (Data(), "chain", Data(repeating: 1, count: 32), UInt64(2), Data(repeating: 3, count: 32)),
            (Data([1]), "", Data(repeating: 1, count: 32), UInt64(2), Data(repeating: 3, count: 32)),
            (Data([1]), "chain", Data(repeating: 1, count: 31), UInt64(2), Data(repeating: 3, count: 32)),
            (Data([1]), "chain", Data(repeating: 1, count: 32), UInt64(0), Data(repeating: 3, count: 32)),
            (Data([1]), "chain", Data(repeating: 1, count: 32), UInt64.max, Data(repeating: 3, count: 32)),
            (Data([1]), "chain", Data(repeating: 1, count: 32), UInt64(2), Data(repeating: 0, count: 32))
        ] {
            XCTAssertThrowsError(try NativeFinalityCheckpointV1.verifyFiCheckpointSelectionV1(
                checkpointBytes: checkpoint, networkId: network, expectedChain: chain,
                expectedSHA256: sha, expectedHeight: height, expectedContextID: context)) {
                XCTAssertEqual($0 as? NativeFinalityCheckpointErrorV1, .invalidInput)
            }
        }
    }

    func testNativeMetadataIsClosedAndRetainsExactUnsignedHeight() throws {
        let context = Data(repeating: 3, count: 32), block = Data(repeating: 5, count: 32)
        let ctx = String(repeating: "03", count: 32), hash = String(repeating: "05", count: 32)
        let height = UInt64.max - 1
        let raw = Data("{\"height\":\"\(height)\",\"context_id\":\"\(ctx)\",\"block_hash\":\"\(hash)\"}".utf8)
        let selected = try NativeFinalityCheckpointV1.decodeNativeResult(raw, expectedHeight: height, expectedContextID: context)
        XCTAssertEqual(selected.height, height); XCTAssertEqual(selected.blockHash, block)
        XCTAssertThrowsError(try NativeFinalityCheckpointV1.decodeNativeResult(raw, expectedHeight: 2, expectedContextID: context))
        XCTAssertThrowsError(try NativeFinalityCheckpointV1.decodeNativeResult(raw, expectedHeight: height, expectedContextID: block))
        var changed = String(decoding: raw, as: UTF8.self)
        changed = changed.replacingOccurrences(of: "\"height\":\"", with: "\"height\":\"0")
        XCTAssertThrowsError(try NativeFinalityCheckpointV1.decodeNativeResult(Data(changed.utf8), expectedHeight: height, expectedContextID: context))
        XCTAssertThrowsError(try NativeFinalityCheckpointV1.decodeNativeResult(raw + Data(" ".utf8), expectedHeight: height, expectedContextID: context))
    }
}
