import Foundation
import XCTest
@testable import IrohaSwift

/// Owned input DATA tests only. No Native wallet, proof or verified receipt is substituted.
final class KagemushaWalletLoadOriginalV1Tests: XCTestCase {
  private func selection() throws -> ToriiKagemushaWalletLoadSelectionV1 {
    try .init(schemeID: Data(repeating: 1, count: 32), walletID: Data(repeating: 2, count: 32), requestID: Data(repeating: 3, count: 32))
  }
  func testOwnedFramesSurviveCallerAndAccessorMutations() throws {
    var receipt = Data([7, 8]), finality = Data([9, 10])
    let input = try KagemushaWalletLoadOriginalInputV1(selection: selection(), payer: "bounded-I105-input", receipt: receipt, finality: finality)
    receipt[0] = 0; finality[0] = 0
    XCTAssertEqual(input.receipt, Data([7, 8])); XCTAssertEqual(input.finality, Data([9, 10]))
    var returned = input.receipt; returned[0] = 0
    XCTAssertEqual(input.receipt, Data([7, 8]))
  }
  func testRetainedReopeningAppliesBoundsBeforeAccessingNative() throws {
    let network = try NetworkId(literal: "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0")
    for (receipt, finality) in [(Data(), Data([1])), (Data([1]), Data(repeating: 0, count: 256 * 1024 + 1))] {
      XCTAssertThrowsError(try KagemushaWalletLoadOriginalV1.decodeRetained(selection: selection(),
        payerAccountID: "payer", networkID: network, receiptOriginal: receipt, finalityOriginal: finality)) {
        XCTAssertEqual($0 as? KagemushaWalletErrorV1, .invalidInput)
      }
    }
  }
  func testAbsentOrOversizedOriginalIsRejectedBeforeNative() throws {
    for bad in [Data(), Data(repeating: 0, count: 513)] {
      XCTAssertThrowsError(try KagemushaWalletLoadOriginalInputV1(selection: selection(), payer: "x", receipt: bad, finality: Data([1])))
    }
    for bad in [Data(), Data(repeating: 0, count: 256 * 1024 + 1)] {
      XCTAssertThrowsError(try KagemushaWalletLoadOriginalInputV1(selection: selection(), payer: "x", receipt: Data([1]), finality: bad))
    }
  }
  func testPayerCeilingCountsExactUtf8Bytes() throws {
    XCTAssertThrowsError(try KagemushaWalletLoadOriginalInputV1(selection: selection(), payer: "", receipt: Data([1]), finality: Data([1])))
    let atLimit = [String(repeating: "x", count: 1024), String(repeating: "é", count: 512),
      String(repeating: "ﾛ", count: 341) + "x", String(repeating: "\u{10000}", count: 256)]
    for payer in atLimit {
      let input = try KagemushaWalletLoadOriginalInputV1(selection: selection(), payer: payer, receipt: Data([1]), finality: Data([1]))
      XCTAssertEqual(input.payer.count, 1024)
      XCTAssertEqual(input.payer, Data(payer.utf8))
      XCTAssertThrowsError(try KagemushaWalletLoadOriginalInputV1(selection: selection(), payer: payer + "x", receipt: Data([1]), finality: Data([1])))
    }
  }
  func testPayerRetainsI105KanaAndDoesNotNormalizeOrGrantIdentity() throws {
    // Maintained CanonicalRequestSigner fixture. Other strings remain unvalidated DATA.
    let canonical = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
    for payer in [canonical, "é", "e\u{301}", " payer ", "x\n", "\0"] {
      let input = try KagemushaWalletLoadOriginalInputV1(selection: selection(), payer: payer, receipt: Data([1]), finality: Data([1]))
      XCTAssertEqual(input.payer, Data(payer.utf8))
      var returned = input.payer
      returned[0] ^= 1
      XCTAssertEqual(input.payer, Data(payer.utf8))
    }
  }
  func testIndependentRouteSelectorsAndMaximumFramesRemainExactData() throws {
    let input = try KagemushaWalletLoadOriginalInputV1(selection: selection(), payer: "x", receipt: Data(repeating: 7, count: 512), finality: Data(repeating: 8, count: 256 * 1024))
    XCTAssertEqual(input.schemeID, Data(repeating: 1, count: 32)); XCTAssertEqual(input.walletID, Data(repeating: 2, count: 32))
    XCTAssertEqual(input.requestID, Data(repeating: 3, count: 32)); XCTAssertEqual(input.receipt.count, 512); XCTAssertEqual(input.finality.count, 256 * 1024)
  }
}
