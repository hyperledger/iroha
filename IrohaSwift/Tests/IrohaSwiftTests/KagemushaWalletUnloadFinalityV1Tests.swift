import Foundation
import XCTest
@testable import IrohaSwift

final class KagemushaWalletUnloadFinalityV1Tests: XCTestCase {
    func testSettlementDistinguishesAbsentHistoryProgressAndExactConfirmation() throws {
        let absent = try KagemushaWalletUnloadFinalityV1(.init(status: 34, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data()))
        XCTAssertNil(absent.confirmation)
        XCTAssertNil(absent.verifiedHeight)
        XCTAssertNil(absent.blockHash)
        let hash = Data(repeating: 7, count: 32)
        let progress = try KagemushaWalletUnloadFinalityV1(.init(status: 33, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: hash))
        XCTAssertNil(progress.confirmation)
        XCTAssertEqual(progress.verifiedHeight, 1)
        let confirmed = try KagemushaWalletUnloadFinalityV1(.init(status: 42, sequenceLow: UInt64.max, sequenceHigh: 0, detail: 0, bytes: hash))
        XCTAssertEqual(confirmed.confirmation?.height, UInt64.max)
        XCTAssertEqual(confirmed.confirmation?.blockHash, hash)
        XCTAssertEqual(confirmed.blockHash, hash)
        XCTAssertThrowsError(try KagemushaWalletCallV1(status: 42, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: hash))
        XCTAssertThrowsError(try KagemushaWalletUnloadFinalityV1(.init(status: 44, sequenceLow: 2, sequenceHigh: 0, detail: 0, bytes: hash)))
        XCTAssertThrowsError(try KagemushaWalletUnloadFinalityV1(.init(status: 0, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data())))
    }
}
