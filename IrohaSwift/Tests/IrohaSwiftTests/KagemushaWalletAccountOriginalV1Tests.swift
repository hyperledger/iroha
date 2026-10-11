import Foundation
import XCTest
@testable import IrohaSwift

final class KagemushaWalletAccountOriginalV1Tests: XCTestCase {
    private func vectors() throws -> [[String: Any]] {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let file = root.appendingPathComponent("fixtures/account/multisig_wire_v1.json")
            if FileManager.default.fileExists(atPath: file.path) {
                let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
                XCTAssertEqual(object["schema"] as? String, "iroha.account.multisig-wire.v1")
                return try XCTUnwrap(object["positive"] as? [[String: Any]])
            }
            root.deleteLastPathComponent()
        }
        throw CocoaError(.fileNoSuchFile)
    }
    private func bytes(_ vector: [String: Any]) throws -> Data {
        let hex = try XCTUnwrap(vector["account_id_frame_hex"] as? String)
        return Data(try stride(from: 0, to: hex.count, by: 2).map { index in
            let start = hex.index(hex.startIndex, offsetBy: index)
            return try XCTUnwrap(UInt8(hex[start..<hex.index(start, offsetBy: 2)], radix: 16))
        })
    }
    func testPublishedRustOriginalsRoundTripUnderSelectedNetwork() throws {
        var admitted = 0
        for vector in try vectors() {
            let original = try bytes(vector), literal = try XCTUnwrap(vector["i105"] as? String)
            if original.count > 4_096 {
                XCTAssertThrowsError(try KagemushaWalletAccountOriginalV1.decode(original, chainDiscriminant: 753))
                XCTAssertThrowsError(try KagemushaWalletAccountOriginalV1.encode(literal))
            } else {
                XCTAssertEqual(try KagemushaWalletAccountOriginalV1.decode(original, chainDiscriminant: 753), literal)
                XCTAssertEqual(try KagemushaWalletAccountOriginalV1.encode(literal), original)
                admitted += 1
            }
        }
        XCTAssertGreaterThan(admitted, 0)
    }
    func testNoncanonicalFramesAreRejected() throws {
        let original = try bytes(XCTUnwrap(vectors().first))
        var wrongSchema = original; wrongSchema[6] ^= 1
        var compressed = original; compressed[22] = 1
        var corrupt = original; corrupt[corrupt.count - 1] ^= 1
        var flags = original; flags[39] = 0
        for value in [Data(), Data(repeating: 0, count: 4097), Data(original.dropLast()),
                      original + Data([0]), wrongSchema, compressed, corrupt, flags] {
            XCTAssertThrowsError(try KagemushaWalletAccountOriginalV1.decode(value, chainDiscriminant: 753))
        }
    }
}
