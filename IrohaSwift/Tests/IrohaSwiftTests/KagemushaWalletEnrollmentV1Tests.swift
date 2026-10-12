import Foundation
import XCTest
@testable import IrohaSwift

final class KagemushaWalletEnrollmentV1Tests: XCTestCase {
  func testAbandonmentLedgerInstructionKeepsLocalAbsenceAndExactFrameDistinct() throws {
    let input = try KagemushaWalletEnrollmentInputV1(20)
    input.withRequest { XCTAssertEqual($0.pointee.selector, 20) }
    XCTAssertThrowsError(try KagemushaWalletEnrollmentInputV1(20, Data([1])))
    let local = try KagemushaWalletCallV1(status:58, sequenceLow:7, sequenceHigh:0, detail:0, bytes:Data())
    XCTAssertNil(try KagemushaWalletEnrollmentV1.abandonmentLedgerInstruction(local))
    let frame = Data([1, 2, 3])
    let instruction = try KagemushaWalletCallV1(status:59, sequenceLow:7, sequenceHigh:0, detail:0, bytes:frame)
    XCTAssertEqual(try KagemushaWalletEnrollmentV1.abandonmentLedgerInstruction(instruction), frame)
    XCTAssertThrowsError(try KagemushaWalletCallV1(status:59, sequenceLow:0, sequenceHigh:0, detail:0, bytes:frame))
    for bytes in [Data(), Data(count:65_537)] {
      XCTAssertThrowsError(try KagemushaWalletCallV1(status:59, sequenceLow:7, sequenceHigh:0, detail:0, bytes:bytes))
    }
    let marker = try KagemushaWalletCallV1(status:28, sequenceLow:7, sequenceHigh:0, detail:0, bytes:frame)
    XCTAssertThrowsError(try KagemushaWalletEnrollmentV1.abandonmentLedgerInstruction(marker))
  }
  func testEnrollmentOutputBoundsAndShapesKeepPaymentLimit() throws {
    for (status,count) in [(18,32),(19,161),(20,0),(21,0),(22,0),(23,32),(24,131072),(25,262144),(26,0),(27,16384),(28,1024),(58,0)] {
      let reply = try KagemushaWalletCallV1(status:Int32(status),sequenceLow:7,sequenceHigh:0,detail:0,bytes:Data(repeating:5,count:count))
      XCTAssertEqual(reply.bytes.count,count)
      XCTAssertThrowsError(try reply.completion())
      XCTAssertThrowsError(try KagemushaWalletCallV1(status:Int32(status),sequenceLow:0,sequenceHigh:0,detail:0,bytes:reply.bytes))
    }
    XCTAssertThrowsError(try KagemushaWalletCallV1(status:1,sequenceLow:0,sequenceHigh:0,detail:0,bytes:Data(count:10001)))
    XCTAssertThrowsError(try KagemushaWalletCallV1(status:25,sequenceLow:7,sequenceHigh:0,detail:0,bytes:Data(count:262145)))
    XCTAssertThrowsError(try KagemushaWalletCallV1(status:19,sequenceLow:7,sequenceHigh:0,detail:0,bytes:Data(count:160)))
  }
  func testEnrollmentInputsAreBoundedAndKeepOnlyOriginals() throws {
    for selector:UInt32 in [0,1,2,4,5,6,7,8,9,10,11,12] {
      XCTAssertThrowsError(try KagemushaWalletEnrollmentInputV1(selector,Data(count:262145)))
    }
    XCTAssertThrowsError(try KagemushaWalletEnrollmentInputV1(3))
    XCTAssertThrowsError(try KagemushaWalletEnrollmentInputV1(4,Data(count:32),Data(count:65536),Data(count:4097)))
    let input = try KagemushaWalletEnrollmentInputV1(4,Data(repeating:1,count:32),Data([2]),Data([3]))
    input.withRequest { request in
      XCTAssertEqual(request.pointee.selector,4)
      XCTAssertEqual(request.pointee.first_length,32)
      XCTAssertNil(request.pointee.certificates)
      XCTAssertEqual(request.pointee.certificate_count,0)
    }
    let target = try KagemushaWalletEnrollmentTargetV1(Data((0..<161).map(UInt8.init)))
    XCTAssertEqual(target.slot.count,32);XCTAssertEqual(target.paymentKey.count,65)
    XCTAssertEqual(target.challengeDigest.first,97);XCTAssertEqual(target.keyBindingDigest.first,129)
  }
  func testPersistedResultIntakeRetainsOnlyExactResultAndAccountFrames() throws {
    let result = Data(repeating: 9, count: KagemushaWalletEnrollmentV1.RESULT_MAX_BYTES)
    let account = Data(repeating: 7, count: 4096)
    let input = try KagemushaWalletEnrollmentInputV1(12, result, account)
    input.withRequest { request in
      XCTAssertEqual(request.pointee.selector, 12)
      XCTAssertEqual(request.pointee.first_length, result.count)
      XCTAssertEqual(request.pointee.second_length, account.count)
      XCTAssertEqual(request.pointee.third_length, 0)
      XCTAssertEqual(request.pointee.certificate_count, 0)
    }
    XCTAssertThrowsError(try KagemushaWalletEnrollmentInputV1(12, result, Data(count: 4097)))
    XCTAssertThrowsError(try KagemushaWalletEnrollmentInputV1(12, result, account, Data([1])))
  }
  func testSessionTransportAllowsEmptyProofWithoutWeakeningTokenOrRootBounds() throws {
    let token = Data(repeating: 1, count: 16_384), root = Data(repeating: 2, count: 16_384)
    let bpng = try KagemushaWalletEnrollmentSessionOriginalsV1(accessToken: token, dpopProof: Data(), attestationRootDER: root)
    XCTAssertEqual(bpng.originals, [token, Data(), root])
    let proof = Data(repeating: 3, count: 4096)
    XCTAssertEqual(try KagemushaWalletEnrollmentSessionOriginalsV1(accessToken: token, dpopProof: proof, attestationRootDER: root).originals[1], proof)
    for values in [[Data(),Data(),root],[token,Data(),Data()],[token + Data([1]),Data(),root],[token,proof + Data([1]),root],[token,Data(),root + Data([1])]] {
      XCTAssertThrowsError(try KagemushaWalletEnrollmentSessionOriginalsV1(accessToken: values[0], dpopProof: values[1], attestationRootDER: values[2]))
    }
  }
  func testRetainedResultSelectorHasNoCallerOriginalsAndPreservesAppleSelectors() throws {
    for selector: UInt32 in [13,16,17,18] {
      let input = try KagemushaWalletEnrollmentInputV1(selector)
      XCTAssertEqual(input.originals, [Data(),Data(),Data()])
      XCTAssertThrowsError(try KagemushaWalletEnrollmentInputV1(selector,Data([1])))
      XCTAssertThrowsError(try KagemushaWalletEnrollmentInputV1(selector,Data(),Data([1])))
      XCTAssertThrowsError(try KagemushaWalletEnrollmentInputV1(selector,Data(),Data(),Data([1])))
    }
    _ = try KagemushaWalletEnrollmentInputV1(14,Data([1]))
    _ = try KagemushaWalletEnrollmentInputV1(15,Data([1]),Data([2]))
    XCTAssertThrowsError(try KagemushaWalletEnrollmentInputV1(21))
  }
  func testRenewedSessionUsesOnlyBoundedOriginalFramesAndNonmonetaryAcknowledgement() throws {
    let session = try KagemushaWalletEnrollmentSessionOriginalsV1(accessToken: Data([1]), dpopProof: Data([2]), attestationRootDER: Data([3]))
    let frames = session.originals
    let input = try KagemushaWalletEnrollmentInputV1(19,frames[0],frames[1],frames[2])
    input.withRequest { request in
      XCTAssertEqual(request.pointee.selector,19)
      XCTAssertEqual(request.pointee.first_length,1)
      XCTAssertEqual(request.pointee.second_length,1)
      XCTAssertEqual(request.pointee.third_length,1)
      XCTAssertEqual(request.pointee.certificate_count,0)
    }
    for originals in [[Data(count:16_385),Data(),Data()], [Data(),Data(count:4097),Data()], [Data(),Data(),Data(count:16_385)]] {
      XCTAssertThrowsError(try KagemushaWalletEnrollmentInputV1(19,originals[0],originals[1],originals[2]))
    }
    let reply = try KagemushaWalletCallV1(status:39,sequenceLow:7,sequenceHigh:0,detail:0,bytes:Data())
    XCTAssertThrowsError(try reply.completion())
    XCTAssertThrowsError(try KagemushaWalletCallV1(status:39,sequenceLow:0,sequenceHigh:0,detail:0,bytes:Data()))
  }
  func testAbandonProjectsLocalAndMarkerFormsExactly() throws {
    func reply(_ status: Int32, _ bytes: Data) throws -> KagemushaWalletCallV1 {
      try KagemushaWalletCallV1(status:status,sequenceLow:7,sequenceHigh:0,detail:0,bytes:bytes)
    }
    XCTAssertEqual(try KagemushaWalletEnrollmentV1.abandonment(reply(58,Data())), .localAbandoned)
    var frame = Data((0..<1024).map { UInt8(truncatingIfNeeded: $0 &+ 1) })
    let marker = try KagemushaWalletEnrollmentV1.abandonment(reply(28,frame))
    frame[0] = 0
    guard case .abandonment(let retained) = marker else { return XCTFail("marker form expected") }
    XCTAssertEqual(retained.count,1024)
    XCTAssertEqual(retained.first,1)
    XCTAssertEqual(try KagemushaWalletEnrollmentV1.abandonment(reply(28,Data([9]))), .abandonment(Data([9])))
    // The local form never carries bytes, the marker form always carries 1...1024 bytes, and the
    // native envelope binds both to the same enrollment owner.
    XCTAssertThrowsError(try reply(58,Data([1])))
    XCTAssertThrowsError(try reply(28,Data()))
    XCTAssertThrowsError(try reply(28,Data(count:1025)))
    XCTAssertThrowsError(try KagemushaWalletCallV1(status:58,sequenceLow:0,sequenceHigh:0,detail:0,bytes:Data()))
    XCTAssertThrowsError(try KagemushaWalletCallV1(status:58,sequenceLow:7,sequenceHigh:1,detail:0,bytes:Data()))
    XCTAssertThrowsError(try KagemushaWalletCallV1(status:58,sequenceLow:7,sequenceHigh:0,detail:1,bytes:Data()))
    XCTAssertThrowsError(try KagemushaWalletCallV1(status:59,sequenceLow:7,sequenceHigh:0,detail:0,bytes:Data()))
    XCTAssertThrowsError(try reply(58,Data()).completion())
    // No other enrollment status is an abandonment result.
    for status: Int32 in [20,21,22,26] {
      XCTAssertThrowsError(try KagemushaWalletEnrollmentV1.abandonment(reply(status,Data())))
    }
    XCTAssertThrowsError(try KagemushaWalletEnrollmentV1.abandonment(reply(25,Data([1]))))
  }
  func testAppleHasOnlyTheSecureEnclaveProfile() {
    XCTAssertEqual(KagemushaWalletAppleKeyProfileV1(rawValue:1), .secureElement)
    for tag: UInt8 in [0,2,3,255] { XCTAssertNil(KagemushaWalletAppleKeyProfileV1(rawValue:tag)) }
  }
}
