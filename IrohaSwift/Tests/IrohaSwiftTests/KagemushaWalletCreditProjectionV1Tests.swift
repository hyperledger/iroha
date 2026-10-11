import Foundation
import XCTest
@testable import IrohaSwift

/// Typed DATA geometry fixtures only; these do not establish Native financial execution.
final class KagemushaWalletCreditProjectionV1Tests: XCTestCase {
    private func original(evidence: UInt8 = 2, archive: UInt8 = 0, pending: UInt8 = 0,
        payload: Data = Data([7])) -> Data {
        var bytes = Data([1, 0, evidence, archive, pending, 0, 0, 0])
        bytes += Data(repeating: 3, count: 32); bytes += Data(repeating: 4, count: 32)
        bytes += Data(repeating: 255, count: 16)
        for shift in 0..<4 { bytes.append(UInt8(truncatingIfNeeded: payload.count >> (shift * 8))) }
        return bytes + payload
    }
    private func decode(_ bytes: Data) throws -> KagemushaWalletCreditProjectionV1 {
        try .init(.init(status: 47, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: bytes))
    }
    func testReceiverEvidencePreservesCreditAndOriginalWithoutArchivePermission() throws {
        for evidence in UInt8(1)...3 {
            let value = try decode(original(evidence: evidence))
            XCTAssertEqual(value.evidence.rawValue, evidence); XCTAssertEqual(value.archive, .receiver)
            XCTAssertFalse(value.corePending); XCTAssertEqual(value.amount, .init(low: .max, high: .max))
            XCTAssertEqual(value.creditId, Data(repeating: 3, count: 32))
            XCTAssertEqual(value.paymentDigest, Data(repeating: 4, count: 32))
            XCTAssertEqual(value.creditedOriginal, Data([7])); XCTAssertNoThrow(try value.requireReceiver())
            XCTAssertThrowsError(try value.requirePayer())
        }
    }
    func testPayerBurnEvidenceIsIndependentFromArchiveProgress() throws {
        for evidence in UInt8(1)...3 { for archive in UInt8(1)...3 { for pending in UInt8(0)...1 {
            let value = try decode(original(evidence: evidence, archive: archive, pending: pending, payload: Data()))
            XCTAssertEqual(value.evidence.rawValue, evidence); XCTAssertEqual(value.archive.rawValue, archive)
            XCTAssertEqual(value.corePending, pending == 1); XCTAssertNil(value.creditedOriginal)
            XCTAssertNoThrow(try value.requirePayer()); XCTAssertThrowsError(try value.requireReceiver())
        } } }
    }
    func testMalformedAndCrossOwnerGeometryIsRefused() throws {
        let valid = original()
        for (offset, value) in [(0, UInt8(2)), (1, 1), (2, 0), (2, 4), (3, 4), (4, 2), (5, 1), (6, 1), (7, 1)] {
            var bytes = valid; bytes[offset] = value; XCTAssertThrowsError(try decode(bytes))
        }
        for range in [8..<40, 40..<72, 72..<88] {
            var bytes = valid; bytes.replaceSubrange(range, with: repeatElement(UInt8(0), count: range.count))
            XCTAssertThrowsError(try decode(bytes))
        }
        for bytes in [Data(valid.dropLast()), valid + Data([1]), original(pending: 1),
            original(payload: Data()), original(archive: 1), original(payload: Data(repeating: 1, count: 10_001))] {
            XCTAssertThrowsError(try decode(bytes))
        }
        XCTAssertNoThrow(try decode(original(payload: Data(repeating: 1, count: 10_000))))
        let other = try KagemushaWalletCallV1(status: 48, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: valid)
        XCTAssertThrowsError(try KagemushaWalletCreditProjectionV1(other))
        let result = try KagemushaWalletCallV1(status: 47, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: valid)
        XCTAssertThrowsError(try result.completion())
    }
    func testCreditAndDeliverySelectorsKeepIdentityAndOriginalBounds() throws {
        let id = Data(repeating: 1, count: 32), anchor = Data([1]), newer = Data([2])
        XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 43, identity: id))
        XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 43))
        XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 43, identity: id, first: anchor))
        for candidate in [Data(), newer, Data(repeating: 1, count: 10_000)] {
            let input = try KagemushaWalletSetupInputV1(selector: 44, identity: id, first: anchor, second: candidate)
            XCTAssertEqual(input.identity, id); XCTAssertEqual(input.first, anchor); XCTAssertEqual(input.second, candidate)
        }
        XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 44, first: anchor))
        XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 44, identity: id))
        XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 44, identity: id, first: anchor, third: newer))
        XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 44, identity: id, first: anchor, second: Data(repeating: 1, count: 10_001)))
        for selector in [UInt32(43), 44] {
            let first = selector == 44 ? anchor : Data()
            XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, identity: id, amount: .init(low: 1, high: 0), first: first))
            XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, identity: id, token: 1, first: first))
        }
    }
}
