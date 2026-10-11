import Foundation
import XCTest
@testable import IrohaSwift

/// Unadmitted managed DATA fixtures only; no Native, keys, proof or custody invocation.
final class KagemushaWalletCurrentReviewIntegrationV1Tests: XCTestCase {
  private func projection(_ selector: UInt8 = 1) -> Data {
    var original = Data([75, 87, 79, 82, 86, 49, 0, 0, selector])
    original.append(Data(repeating: 255, count: 64))
    original.append(selector == 1 ? 1 : 0)
    original.append(Data(repeating: selector == 1 ? 7 : 0, count: 32))
    for index in 1...10 { original.append(Data(repeating: (index==3 && selector==1 || index==2 && selector==8) ? 0 : UInt8(index), count: 32)) }
    original.append(4); original.append(Data(repeating: 9, count: 64))
    original.append(contentsOf: selector == 1 ? [3,0,0,0,0xa1,0xb2,0xc3] : [0,0,0,0])
    return original
  }
  func testLosslessImmutableProjectionData() throws {
    var original = projection()
    let value = try KagemushaWalletReviewProjectionV1(original: original)
    original[0] = 0
    XCTAssertEqual(value.kind, .send)
    for amount in [value.amount, value.fee, value.grossDebit, value.netDestinationAmount] {
      XCTAssertEqual(amount, .init(low: UInt64.max, high: UInt64.max))
    }
    var receiver = try XCTUnwrap(value.receiverWalletId); receiver[0] = 0
    XCTAssertEqual(value.receiverWalletId, Data(repeating: 7, count: 32))
    XCTAssertEqual(value.destinationAccountDigest, Data(repeating: 1, count: 32))
    XCTAssertEqual(value.artifactManifestDigest, Data(repeating: 10, count: 32))
    XCTAssertEqual(value.paymentKey.first, 4)
    var account = try XCTUnwrap(value.destinationAccountOriginal); account[0] = 0
    XCTAssertEqual(value.destinationAccountOriginal, Data([0xa1,0xb2,0xc3]))
  }
  func testOriginBindingAndAliasCannotReplayToken() throws {
    let owner = KagemushaWalletReviewOriginV1(), another = KagemushaWalletReviewOriginV1()
    let data = try KagemushaWalletReviewProjectionV1(original: projection())
    let review = try KagemushaWalletReviewReplyV1(status:18,reason:-1,platformCode:0,sequenceLow:19,sequenceHigh:0,detail:0,bytes:data.bytes).review(origin:owner,expected:.send)
    XCTAssertThrowsError(try review.consume(origin: another))
    let alias = review
    XCTAssertEqual(try alias.consume(origin: owner), 19)
    XCTAssertThrowsError(try review.consume(origin: owner))
    XCTAssertThrowsError(try KagemushaWalletReviewReplyV1(status:18,reason:-1,platformCode:0,sequenceLow:0,sequenceHigh:0,detail:0,bytes:data.bytes).review(origin:owner,expected:.send))
    XCTAssertThrowsError(try KagemushaWalletReviewReplyV1(status:18,reason:-1,platformCode:0,sequenceLow:UInt64.max,sequenceHigh:0,detail:0,bytes:data.bytes).review(origin:owner,expected:.send))
  }
  func testMalformedProjectionAndCompletionSeparation() throws {
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 18, sequenceLow: 19, sequenceHigh: 0, detail: 0, bytes: projection()))
    for count in [0, 490, 491, 494, 4_592] {
      XCTAssertThrowsError(try KagemushaWalletReviewProjectionV1(original: Data(repeating: 0, count: count)))
    }
    let mutations: [(Int, UInt8)] = [(0, 0), (8, 2), (73, 2), (73, 0), (426, 3)]
    for (offset, byte) in mutations {
      var changed = projection(); changed[offset] = byte
      XCTAssertThrowsError(try KagemushaWalletReviewProjectionV1(original: changed))
    }
    let unload = try KagemushaWalletReviewProjectionV1(original: projection(8))
    XCTAssertEqual(unload.kind, .unload); XCTAssertNil(unload.receiverWalletId); XCTAssertNil(unload.destinationAccountOriginal)
    var changed = projection(8); changed[74] = 1
    XCTAssertThrowsError(try KagemushaWalletReviewProjectionV1(original: changed))
  }
  func testFixedInputBoundsAndForeignFieldRefusal() throws {
    _ = try KagemushaWalletReviewInputV1(selector: 1, first: Data(repeating: 1, count: 10_000), second: Data(repeating: 2, count: 4_096))
    _ = try KagemushaWalletReviewInputV1(selector: 8, amount: .init(low: UInt64.max, high: UInt64.max))
    _ = try KagemushaWalletReviewInputV1(selector: 8, amount: .init(low: 1, high: 0), first: Data(repeating: 1, count: 1_024), second: KagemushaWalletUnloadChargeReviewV1.encode(certificates: Data(repeating: 1, count: 10_000), beneficiary: Data(repeating: 2, count: 4_096)))
    let makers: [() throws -> KagemushaWalletReviewInputV1] = [
      { try .init(selector: 2, first: Data([1])) },
      { try .init(selector: 1) },
      { try .init(selector: 1, first: Data(repeating: 1, count: 10_001), second: Data([1])) },
      { try .init(selector: 1, amount: .init(low: 1, high: 0), first: Data([1]), second: Data([1])) },
      { try .init(selector: 1, first: Data([1])) },
      { try .init(selector: 1, second: Data([1])) },
      { try .init(selector: 1, first: Data([1]), second: Data(repeating: 2, count: 4_097)) },
      { try .init(selector: 8) },
      { try .init(selector: 8, amount: .init(low: 1, high: 0), first: Data([1])) },
      { try .init(selector: 8, amount: .init(low: 1, high: 0), second: Data([1])) },
      { try .init(selector: 8, amount: .init(low: 1, high: 0), first: Data(repeating: 1, count: 1_025), second: Data([1])) },
      { try .init(selector: 8, amount: .init(low: 1, high: 0), first: Data([1]), second: Data(repeating: 1, count: 10_001)) },
    ]
    for make in makers { XCTAssertThrowsError(try make()) }
  }
  func testReviewIntakeKeepsExactCOriginals() throws {
    var request = Data(repeating: 7, count: 10_000)
    var account = Data(repeating: 9, count: 4_096)
    let input = try KagemushaWalletReviewInputV1(selector: 1, first: request, second: account)
    request[0] = 0; account[0] = 0
    input.withRequest { value in
      XCTAssertEqual(value.pointee.selector, 1)
      XCTAssertEqual(value.pointee.amount.low, 0); XCTAssertEqual(value.pointee.amount.high, 0)
      XCTAssertEqual(value.pointee.first_length, 10_000); XCTAssertEqual(value.pointee.second_length, 4_096)
      XCTAssertEqual(Data(bytes: value.pointee.first!, count: 10_000), Data(repeating: 7, count: 10_000))
      XCTAssertEqual(Data(bytes: value.pointee.second!, count: 4_096), Data(repeating: 9, count: 4_096))
    }
  }
}
