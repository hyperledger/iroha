import Foundation
import XCTest
@testable import IrohaSwift

/// `fixtures/kagemusha/peer_ask_v1.json`: the `IAK1` ask, `GET_ASK` and picture-pairing vectors
/// that the Kotlin SDK asserts byte for byte too, found by walking up from the calling test file.
func irohaPeerAskFixtureV1(filePath: String = #filePath) throws -> [String: Any] {
    var directory = URL(fileURLWithPath: filePath).deletingLastPathComponent()
    for _ in 0..<8 {
        let file = directory.appendingPathComponent("fixtures/kagemusha/peer_ask_v1.json")
        if FileManager.default.fileExists(atPath: file.path) {
            let object = try XCTUnwrap(
                JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any]
            )
            XCTAssertEqual(object["fixture_version"] as? Int, 1)
            return object
        }
        directory.deleteLastPathComponent()
    }
    throw CocoaError(.fileNoSuchFile)
}

/// The fixture's `key` array of objects.
func irohaPeerAskVectorsV1(_ key: String, in fixture: [String: Any]) throws -> [[String: Any]] {
    try XCTUnwrap(fixture[key] as? [[String: Any]], key)
}

/// Strict hexadecimal fixture bytes.
func irohaPeerAskBytesV1(_ value: Any?) throws -> Data {
    let hex = Array(try XCTUnwrap(value as? String).utf8)
    guard hex.count.isMultiple(of: 2) else { throw CocoaError(.fileReadCorruptFile) }
    return Data(try stride(from: 0, to: hex.count, by: 2).map { index in
        try XCTUnwrap(UInt8(String(decoding: hex[index..<(index + 2)], as: UTF8.self), radix: 16))
    })
}

/// A decimal fixture amount below 2^128 as the wallet's unsigned 128-bit value.
func irohaPeerAskAmountV1(decimal value: Any?) throws -> KagemushaWalletUInt128V1 {
    let digits = Array(try XCTUnwrap(value as? String).utf8)
    guard !digits.isEmpty else { throw CocoaError(.fileReadCorruptFile) }
    var low: UInt64 = 0
    var high: UInt64 = 0
    for digit in digits {
        guard (48...57).contains(digit) else { throw CocoaError(.fileReadCorruptFile) }
        let lowProduct = low.multipliedFullWidth(by: 10)
        let highProduct = high.multipliedReportingOverflow(by: 10)
        let carried = highProduct.partialValue.addingReportingOverflow(lowProduct.high)
        let sum = lowProduct.low.addingReportingOverflow(UInt64(digit - 48))
        let next = carried.partialValue.addingReportingOverflow(sum.overflow ? 1 : 0)
        guard !highProduct.overflow, !carried.overflow, !next.overflow else {
            throw CocoaError(.fileReadCorruptFile)
        }
        low = sum.partialValue
        high = next.partialValue
    }
    return KagemushaWalletUInt128V1(low: low, high: high)
}
