import Foundation
import XCTest
@testable import IrohaSwift

/// DATA-only transport tests. These fixtures carry no Native proof or review capability grant.
final class KagemushaWalletReviewV1Tests: XCTestCase {
  private func data(send: Bool = true) -> Data {
    var b = [UInt8](repeating: 0, count: 491)
    b.replaceSubrange(0..<8, with: [75,87,79,82,86,49,0,0]); b[8] = send ? 1 : 8
    for offset in [9,25,41,57] { for i in 0..<16 { b[offset+i] = UInt8(i+1) } }
    if send { b[73] = 1; b[74] = 2; b[138] = 3 }
    for offset in [106,202,234,266,298,330,362,394] { b[offset] = 4 }
    b[426] = 4; b[427] = 5
    b.append(contentsOf: send ? [3,0,0,0,0xa1,0xb2,0xc3] : [0,0,0,0])
    return Data(b)
  }
  private func reply(_ bytes: Data? = nil, status: Int32 = 18, token: UInt64 = 8, high: UInt64 = 0, detail: UInt32 = 0) -> KagemushaWalletReviewReplyV1 {
    .init(status: status, reason: -1, platformCode: 0, sequenceLow: token, sequenceHigh: high, detail: detail, bytes: bytes ?? data())
  }
  func testPreservesAllUnsignedScalarBitsAndWholeProjection() throws {
    var bytes = data(); bytes.replaceSubrange(9..<25, with: Data(repeating: 255, count: 16))
    let p = try KagemushaWalletReviewProjectionV1(bytes)
    XCTAssertEqual(p.amount.low, UInt64.max); XCTAssertEqual(p.amount.high, UInt64.max); XCTAssertEqual(bytes,p.bytes)
  }
  func testRetainsValueCopiesAndExactSourceFields() throws {
    var bytes = data(); let original = bytes, p = try KagemushaWalletReviewProjectionV1(bytes)
    bytes.resetBytes(in: 0..<bytes.count)
    var account = try XCTUnwrap(p.destinationAccountOriginal); account[0] = 0
    XCTAssertEqual(p.destinationAccountOriginal, Data([0xa1,0xb2,0xc3]))
    XCTAssertEqual(p.bytes,original); XCTAssertEqual(p.walletID[0],4); XCTAssertEqual(p.paymentPublicKey[0],4)
  }
  func testRequiresExactLengthMagicSelectorAndHardwareKeyForm() {
    var variants = [Data(data().dropLast()), data()+Data([0])]
    for (offset,value) in [(0,UInt8(0)),(8,2),(426,3)] { var b=data(); b[offset]=value; variants.append(b) }
    for b in variants { XCTAssertThrowsError(try KagemushaWalletReviewProjectionV1(b)) }
  }
  func testSendAndUnloadHaveDifferentReceiverAndRequestShapes() throws {
    var b=data(); b[73]=0; XCTAssertThrowsError(try KagemushaWalletReviewProjectionV1(b))
    b=data(); b[170]=1; XCTAssertThrowsError(try KagemushaWalletReviewProjectionV1(b))
    let p=try KagemushaWalletReviewProjectionV1(data(send:false)); XCTAssertNil(p.receiverWalletID); XCTAssertNil(p.destinationAccountOriginal); XCTAssertEqual(p.requestDigest,Data(repeating:0,count:32))
  }
  func testAccountOriginalLengthIsMandatoryExactAndBounded() throws {
    var variants = [Data(data().prefix(491)), Data(data().prefix(495)), data()+Data([0]),
      Data(data().prefix(491))+Data([0,0,0,0])]
    let lengths: [[UInt8]] = [[2,0,0,0],[4,0,0,0],[1,16,0,0],[255,255,255,255]]
    for length in lengths {
      var b = data(); b.replaceSubrange(491..<495, with: length); variants.append(b)
    }
    var unload = data(send:false); unload.replaceSubrange(491..<495, with:[1,0,0,0]); unload.append(7); variants.append(unload)
    for b in variants { XCTAssertThrowsError(try KagemushaWalletReviewProjectionV1(b)) }
    var maximum = Data(data().prefix(491)); maximum.append(contentsOf:[0,16,0,0]); maximum.append(Data(repeating:7,count:4_096))
    XCTAssertEqual(try KagemushaWalletReviewProjectionV1(maximum).destinationAccountOriginal?.count,4_096)
  }
  func testRejectsMissingCurrentSourceAndZeroAmount() {
    for offset in [106,202,234,266,298,330,362,394] { var b=data(); b.resetBytes(in:offset..<(offset+32)); XCTAssertThrowsError(try KagemushaWalletReviewProjectionV1(b)) }
    var b=data(); b.resetBytes(in:9..<25); XCTAssertThrowsError(try KagemushaWalletReviewProjectionV1(b))
  }
  func testDedicatedReviewRejectsOpenActivationAndMalformedToken() {
    for status: Int32 in [0,1,12,13,14,15,16,17,19] { XCTAssertThrowsError(try reply(status:status).review(origin:NSObject(),expected:.send)) }
    for r in [reply(token:0),reply(token:UInt64.max),reply(high:1),reply(detail:1)] { XCTAssertThrowsError(try r.review(origin:NSObject(),expected:.send)) }
    XCTAssertThrowsError(try reply().review(origin:NSObject(),expected:.unload))
    XCTAssertThrowsError(try KagemushaWalletCallV1(status:18,sequenceLow:8,sequenceHigh:0,detail:0,bytes:data()))
  }
  func testForeignOwnerCannotConsumeAndOriginalCanConsumeOnlyOnce() throws {
    let owner=NSObject(), r=try reply().review(origin:owner,expected:.send)
    XCTAssertThrowsError(try r.consume(origin:NSObject())); XCTAssertEqual(try r.consume(origin:owner),8)
    XCTAssertThrowsError(try r.consume(origin:owner))
  }
  func testProjectionCopyDoesNotCreateAnotherToken() throws {
    let owner=NSObject(), r=try reply().review(origin:owner,expected:.send), p=r.projection
    XCTAssertEqual(p.bytes,r.projection.bytes); _=try r.consume(origin:owner)
    XCTAssertThrowsError(try r.consume(origin:owner)); XCTAssertEqual(p.bytes,data())
  }
}
