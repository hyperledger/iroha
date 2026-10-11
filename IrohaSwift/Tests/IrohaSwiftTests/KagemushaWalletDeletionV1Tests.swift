import Foundation
import XCTest
@testable import IrohaSwift

final class KagemushaWalletDeletionV1Tests: XCTestCase {
  private func frame() -> Data {
    var value = Data(repeating: 0, count: 254)
    value.replaceSubrange(0..<8, with: Data("KWCDV1\0\0".utf8))
    value[8] = 1; value[9] = 2; value[10] = 8
    value[11] = 1; value[12] = 1; value[13] = 1
    for offset in [14, 46, 78, 110, 142, 174] { value[offset] = 1 }
    value[206] = 7; value[222] = 9; value[238] = 3
    return value
  }
  private func call(_ status: Int32, token: UInt64 = 0, bytes: Data = Data()) throws -> KagemushaWalletCallV1 {
    try .init(status: status, sequenceLow: token, sequenceHigh: 0, detail: 0, bytes: bytes)
  }
  func testActualNativeDeletionSelectorsRefuseUnknownOwner() throws {
    let driver = try KagemushaWalletNativeDriverV1()
    for selector in [UInt32(48), 49, 50, 51] {
      let input = try KagemushaWalletSetupInputV1(selector: selector, token: [49, 51].contains(selector) ? 1 : 0)
      XCTAssertThrowsError(try driver.result { output in
        input.withRequest { driver.setup(0, $0, output) }
      }) { error in XCTAssertEqual(error as? KagemushaWalletErrorV1, .closed) }
    }
  }
  func testProjectionIsExactClosedAndCopyOwned() throws {
    var bytes = frame()
    let projection = try KagemushaWalletDeletionProjectionV1(bytes)
    bytes[14] = 2
    XCTAssertEqual(projection.slot.first, 1)
    XCTAssertTrue(projection.pending); XCTAssertEqual(projection.lifecycle, .retiring)
    XCTAssertEqual(projection.operationKind, 8)
    XCTAssertTrue(projection.pendingOutgoing && projection.feeClaims && projection.loadRedeem)
    XCTAssertEqual(projection.sequence, .init(low: 7, high: 0))
    XCTAssertEqual(projection.grossBalance, .init(low: 9, high: 0))
    XCTAssertEqual(projection.coreBurnedTotal, .init(low: 3, high: 0))
    for offset in [8, 9, 10, 11, 12, 13] {
      var invalid = frame(); invalid[offset] = 255
      XCTAssertThrowsError(try KagemushaWalletDeletionProjectionV1(invalid))
    }
    for offset in [14, 46, 78, 110, 142, 174] {
      var invalid = frame(); invalid.replaceSubrange(offset..<offset+32, with: Data(repeating: 0, count: 32))
      XCTAssertThrowsError(try KagemushaWalletDeletionProjectionV1(invalid))
    }
    var wrongMagic = frame(); wrongMagic[7] = 1
    for invalid in [Data(), frame().dropLast(), frame() + Data([0]), wrongMagic] {
      XCTAssertThrowsError(try KagemushaWalletDeletionProjectionV1(Data(invalid)))
    }
    var maximum = frame()
    maximum.replaceSubrange(222..<254, with: Data(repeating: 255, count: 32))
    XCTAssertEqual(try KagemushaWalletDeletionProjectionV1(maximum).grossBalance, .init(low: .max, high: .max))
    maximum[222] = 254
    XCTAssertThrowsError(try KagemushaWalletDeletionProjectionV1(maximum))
  }
  func testRequestAndReplyClosedShapes() throws {
    for selector in [UInt32(48), 49, 50, 51] {
      let token: UInt64 = [49, 51].contains(selector) ? 7 : 0
      let input = try KagemushaWalletSetupInputV1(selector: selector, token: token)
      XCTAssertEqual(input.identity, Data(repeating: 0, count: 32))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, token: token, first: Data([1])))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, amount: .init(low: 1, high: 0), token: token))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, token: token == 0 ? 1 : 0))
    }
    _ = try call(53, token: UInt64(Int64.max), bytes: frame())
    _ = try call(54, bytes: Data(repeating: 1, count: 32))
    _ = try call(55); _ = try call(56)
    XCTAssertThrowsError(try call(53, bytes: frame()))
    XCTAssertThrowsError(try call(53, token: 1, bytes: frame() + Data([0])))
    XCTAssertThrowsError(try call(54, bytes: Data(repeating: 0, count: 32)))
    for status in [Int32(54), 55, 56] {
      XCTAssertThrowsError(try call(status, token: 1, bytes: status == 54 ? Data(repeating: 1, count: 32) : Data()))
    }
    XCTAssertThrowsError(try call(57))
  }
  func testOneUseOwnerBindingAndUncertainConfirmationFreeze() throws {
    enum Failure: Error { case lost }
    let gate = KagemushaWalletDeletionGateV1(), foreign = KagemushaWalletDeletionGateV1()
    XCTAssertThrowsError(try gate.resume { XCTFail("fresh resume dispatched"); return try call(56) })
    try gate.requireOrdinary()
    let review = try gate.review { try call(53, token: 7, bytes: frame()) }
    XCTAssertThrowsError(try foreign.confirm(review) { _ in XCTFail("foreign dispatch"); return try call(54, bytes: Data(repeating: 1, count: 32)) })
    let stale = try gate.review { try call(53, token: 8, bytes: frame()) }
    XCTAssertThrowsError(try gate.confirm(review) { token in
      XCTAssertEqual(token, 7)
      XCTAssertThrowsError(try gate.requireOrdinary())
      XCTAssertThrowsError(try gate.resume { XCTFail("concurrent resume"); return try call(56) })
      throw Failure.lost
    })
    XCTAssertThrowsError(try gate.requireOrdinary())
    XCTAssertThrowsError(try gate.discard(review) { _ in XCTFail("cannot undo"); return try call(55) })
    XCTAssertEqual(try gate.resume { try call(56) }, .notDeleted)
    try gate.requireOrdinary()
    XCTAssertThrowsError(try gate.confirm(stale) { _ in XCTFail("stale review"); return try call(56) })
    let fresh = try gate.review { try call(53, token: 9, bytes: frame()) }
    let marker = Data(repeating: 3, count: 32)
    XCTAssertEqual(try gate.confirm(fresh) { _ in try call(54, bytes: marker) }, marker)
    XCTAssertThrowsError(try gate.requireOrdinary())
    XCTAssertEqual(try gate.resume { try call(54, bytes: marker) }, .deleted(marker: marker))
    XCTAssertThrowsError(try gate.resume { try call(54, bytes: Data(repeating: 4, count: 32)) })
    XCTAssertThrowsError(try gate.resume { try call(56) })
    XCTAssertThrowsError(try gate.requireOrdinary())
  }
  func testDiscardAndMalformedResponseDoNotAuthorizeDeletionOrResume() throws {
    let gate = KagemushaWalletDeletionGateV1()
    let review = try gate.review { try call(53, token: 1, bytes: frame()) }
    try gate.discard(review) { _ in try call(55) }
    try gate.requireOrdinary()
    XCTAssertThrowsError(try gate.confirm(review) { _ in XCTFail("discarded"); return try call(56) })
    let fresh = try gate.review { try call(53, token: 2, bytes: frame()) }
    XCTAssertThrowsError(try gate.confirm(fresh) { _ in try call(55) })
    XCTAssertThrowsError(try gate.requireOrdinary())
    XCTAssertThrowsError(try gate.resume { try call(55) })
    XCTAssertThrowsError(try gate.requireOrdinary())
    _ = try gate.resume { try call(56) }
    try gate.requireOrdinary()
  }
}
