import Foundation
import XCTest
@testable import IrohaSwift

final class KagemushaWalletUnloadChargeReviewV1Tests: XCTestCase {
    func testExactBoundedCompanionAndMalformedCarrierRefusal() throws {
        let frame = try KagemushaWalletUnloadChargeReviewV1.encode(certificates: Data(repeating: 7, count: 10_000), beneficiary: Data(repeating: 8, count: 4_096))
        XCTAssertEqual(frame.count, 14_112)
        XCTAssertEqual(frame.prefix(12), Data([75, 87, 85, 67, 86, 49, 0, 0, 16, 39, 0, 0]))
        try KagemushaWalletUnloadChargeReviewV1.validate(frame)
        for invalid in [Data(repeating: 7, count: 10_000), Data(frame.dropLast()), frame + Data([0])] {
            XCTAssertThrowsError(try KagemushaWalletUnloadChargeReviewV1.validate(invalid))
        }
        for offset in [0, 8, 10_012] {
            var invalid = frame; invalid[offset] ^= 0xff
            XCTAssertThrowsError(try KagemushaWalletUnloadChargeReviewV1.validate(invalid))
        }
        XCTAssertThrowsError(try KagemushaWalletUnloadChargeReviewV1.encode(certificates: Data(), beneficiary: Data([1])))
        XCTAssertThrowsError(try KagemushaWalletUnloadChargeReviewV1.encode(certificates: Data([1]), beneficiary: Data(repeating: 1, count: 4_097)))
    }
}
