import Foundation
import XCTest

@testable import IrohaSwift

/// Managed result contracts; authenticated native artifact execution remains separately gated.
final class KagemushaWalletNativeV1Tests: XCTestCase {
  func testExactBytesAndDistinctCompletionOutcomes() throws {
    let bytes = Data([0, 255, 0, 7])
    for status in Int32(0)...11 {
      let value = try KagemushaWalletCallV1(
        status: status, sequenceLow: 7, sequenceHigh: 2,
        detail: 0, bytes: status == 1 || status == 10 ? bytes : Data())
      XCTAssertEqual(value.status, status)
      XCTAssertEqual(value.sequenceHigh, 2)
      if status == 1 { XCTAssertEqual(value.bytes, bytes) }
    }
  }
  func testMalformedNativeOutputNeverBecomesCompletion() {
    for (status, bytes) in [
      (Int32(1), Data()), (10, Data()), (2, Data([1])), (12, Data()), (-1, Data()),
      (1, Data(repeating: 1, count: 10_001)),
    ] {
      XCTAssertThrowsError(
        try KagemushaWalletCallV1(
          status: status, sequenceLow: 0,
          sequenceHigh: 0, detail: 0, bytes: bytes)
      ) { error in
        XCTAssertEqual(error as? KagemushaWalletErrorV1, .invalidNativeOutput)
      }
    }
    for status in Int32(0)...11 where status != 1 && status != 10 {
      XCTAssertThrowsError(
        try KagemushaWalletCallV1(
          status: status, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data([1])))
    }
  }
  func testCompletionPreservesTheInclusiveEnvelopeBound() throws {
    let bytes = Data(repeating: 0xff, count: 10_000)
    let value = try KagemushaWalletCallV1(
      status: 1, sequenceLow: UInt64.max, sequenceHigh: UInt64.max, detail: 0, bytes: bytes)
    XCTAssertEqual(value.bytes, bytes)
    XCTAssertEqual(value.sequenceLow, UInt64.max)
    XCTAssertEqual(value.sequenceHigh, UInt64.max)
  }
  func testTypedLifecycleInputsHaveExactOriginalBoundsAndScalarProjection() throws {
    let identity = Data(repeating: 1, count: 32)
    for selector in [UInt32(0), 2, 3, 4, 5, 6, 7, 9, 10] {
      let limits: [Int] = selector == 0 ? [512, 256 * 1024, 0]
        : selector == 2 ? [10_000, 1_024, 10_000] : selector == 5 ? [65_536 * 34 + 512, 10_000, 0]
        : selector == 6 ? [512, 10_000, 0] : selector == 7 ? [8_192, 10_000, 0]
        : selector == 9 ? [0, 0, 0] : selector == 10 ? [10_000, 10_000, 0] : [1_024, 10_000, 0]
      let originals = limits.map { Data(repeating: 7, count: $0 == 0 ? 0 : 1) }
      let amount = KagemushaWalletUInt128V1(low: 0, high: 0)
      let input = try KagemushaWalletOperationInputV1(requestId: identity, selector: selector, amount: amount, first: originals[0], second: originals[1], third: originals[2])
      input.withRequest { value in
        XCTAssertEqual(value.pointee.selector, selector)
        XCTAssertEqual(value.pointee.amount.low, amount.low)
        XCTAssertEqual(value.pointee.amount.high, amount.high)
        XCTAssertEqual(Data(bytes: value.pointee.request_id!, count: 32), identity)
        XCTAssertEqual(value.pointee.first_length, originals[0].count)
        XCTAssertEqual(value.pointee.second_length, originals[1].count)
        XCTAssertEqual(value.pointee.third_length, originals[2].count)
      }
      for index in 0..<3 {
        var changed = originals
        changed[index] = Data(repeating: 0, count: limits[index] + 1)
        XCTAssertThrowsError(try KagemushaWalletOperationInputV1(requestId: identity, selector: selector, amount: amount, first: changed[0], second: changed[1], third: changed[2]))
      }
    }
    XCTAssertThrowsError(try KagemushaWalletOperationInputV1(requestId: Data(repeating: 0, count: 32), selector: 9))
    XCTAssertThrowsError(try KagemushaWalletOperationInputV1(requestId: identity, selector: 10))
    XCTAssertThrowsError(try KagemushaWalletOperationInputV1(requestId: identity, selector: 8))
    XCTAssertThrowsError(try KagemushaWalletOperationInputV1(requestId: identity, selector: 8, amount: .init(low: 1, high: 0), first: Data([1])))
    XCTAssertThrowsError(try KagemushaWalletOperationInputV1(requestId: identity, selector: 8, amount: .init(low: 1, high: 0)))
    XCTAssertThrowsError(try KagemushaWalletOperationInputV1(requestId: identity, selector: 1, first: Data([1])))
  }

  func testReceiveFromOfferRetainsBothBoundedOriginalsAndRejectsForeignFields() throws {
    var identity = Data(repeating: 1, count: 32)
    var payment = Data(repeating: 7, count: 10_000)
    var offer = Data(repeating: 9, count: 10_000)
    let input = try KagemushaWalletOperationInputV1(requestId: identity, selector: 10, first: payment, second: offer)
    identity[0] = 0; payment[0] = 0; offer[0] = 0
    input.withRequest { value in
      XCTAssertEqual(value.pointee.selector, 10)
      XCTAssertEqual(value.pointee.amount.low, 0)
      XCTAssertEqual(value.pointee.amount.high, 0)
      XCTAssertEqual(Data(bytes: value.pointee.request_id!, count: 32), Data(repeating: 1, count: 32))
      XCTAssertEqual(Data(bytes: value.pointee.first!, count: value.pointee.first_length), Data(repeating: 7, count: 10_000))
      XCTAssertEqual(Data(bytes: value.pointee.second!, count: value.pointee.second_length), Data(repeating: 9, count: 10_000))
      XCTAssertEqual(value.pointee.third_length, 0)
    }
    let id = Data(repeating: 1, count: 32), one = Data([1])
    for invalid in [Data(repeating: 1, count: 31), Data(repeating: 0, count: 32), Data(repeating: 1, count: 33)] {
      XCTAssertThrowsError(try KagemushaWalletOperationInputV1(requestId: invalid, selector: 10, first: one, second: one))
    }
    for (first, second, third) in [
      (Data(), one, Data()), (one, Data(), Data()),
      (Data(repeating: 1, count: 10_001), one, Data()),
      (one, Data(repeating: 1, count: 10_001), Data()), (one, one, one),
    ] {
      XCTAssertThrowsError(try KagemushaWalletOperationInputV1(requestId: id, selector: 10, first: first, second: second, third: third))
    }
    for amount in [KagemushaWalletUInt128V1(low: 1, high: 0), .init(low: 0, high: 1), .init(low: .max, high: .max)] {
      XCTAssertThrowsError(try KagemushaWalletOperationInputV1(requestId: id, selector: 10, amount: amount, first: one, second: one))
    }
  }

  func testSetupOriginalsCannotBecomeMonetaryCompletionOrTimeAuthority() throws {
    var bytes = Data([1, 2, 3])
    let original = try KagemushaWalletCallV1(status: 12, sequenceLow: 0,
      sequenceHigh: 0, detail: 0, bytes: bytes)
    bytes[0] = 9
    var returned = try original.original(); returned[1] = 9
    XCTAssertEqual(try original.original(), Data([1, 2, 3]))
    XCTAssertThrowsError(try original.completion())
    XCTAssertThrowsError(try original.exchange(origin: KagemushaWalletSetupOriginV1()))
    XCTAssertThrowsError(try original.timeRetained())
    for status in Int32(12)...14 {
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: status,
        sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data([1])).completion())
    }
  }
  func testTimeChallengeIsOneUseExactAndBoundToItsOrigin() throws {
    let owner = KagemushaWalletSetupOriginV1(), successor = KagemushaWalletSetupOriginV1()
    var nonce = Data(repeating: 7, count: 32)
    let exchange = try KagemushaWalletCallV1(status: 13, sequenceLow: 19,
      sequenceHigh: 0, detail: 0, bytes: nonce).exchange(origin: owner)
    nonce[0] = 0; var returned = exchange.nonce; returned[1] = 0
    XCTAssertEqual(exchange.nonce, Data(repeating: 7, count: 32))
    XCTAssertThrowsError(try exchange.tokenFor(origin: successor))
    XCTAssertThrowsError(try exchange.consume(origin: successor))
    XCTAssertEqual(try exchange.tokenFor(origin: owner), 19)
    try exchange.consume(origin: owner)
    XCTAssertThrowsError(try exchange.tokenFor(origin: owner))
    XCTAssertThrowsError(try exchange.consume(origin: owner))
    XCTAssertTrue(exchange.description.contains("[REDACTED]"))
    XCTAssertFalse(exchange.description.contains("19"))
  }
  func testMalformedSetupEnvelopesCannotPublishOriginalOrChallenge() throws {
    for (status, low, high, detail, bytes) in [
      (Int32(12), UInt64(0), UInt64(0), UInt32(0), Data()),
      (12, 1, 0, 0, Data([1])), (12, 0, 1, 0, Data([1])),
      (12, 0, 0, 1, Data([1])), (1, 0, 0, 0, Data([1])),
    ] {
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: status,
        sequenceLow: low, sequenceHigh: high, detail: detail, bytes: bytes).original())
    }
    for (low, high, detail, bytes) in [
      (UInt64(0), UInt64(0), UInt32(0), Data(repeating: 1, count: 32)),
      (UInt64.max, 0, 0, Data(repeating: 1, count: 32)),
      (1, 1, 0, Data(repeating: 1, count: 32)), (1, 0, 1, Data(repeating: 1, count: 32)),
      (1, 0, 0, Data(repeating: 0, count: 32)), (1, 0, 0, Data(repeating: 1, count: 31)),
    ] {
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: 13,
        sequenceLow: low, sequenceHigh: high, detail: detail, bytes: bytes)
        .exchange(origin: KagemushaWalletSetupOriginV1()))
    }
    for (low, high, detail, bytes) in [(UInt64(1), UInt64(0), UInt32(0), Data()),
      (0, 1, 0, Data()), (0, 0, 1, Data()), (0, 0, 0, Data([1]))] {
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: 14,
        sequenceLow: low, sequenceHigh: high, detail: detail, bytes: bytes).timeRetained())
    }
    XCTAssertNoThrow(try KagemushaWalletCallV1(status: 14,
      sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data()).timeRetained())
  }
  func testSetupReplyBoundsKeepAllOriginalBytesWithoutTruncation() throws {
    let bytes = Data(repeating: 0xff, count: 10_000)
    XCTAssertEqual(try KagemushaWalletCallV1(status: 12,
      sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: bytes).original(), bytes)
    for status in [Int32(-1), 15] {
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: status,
        sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data()))
    }
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 12,
      sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 7, count: 10_001)))
  }
  func testOfferPreservesFullUnsignedAmountAndExactCIdentity() throws {
    var identity = Data(repeating: 1, count: 32)
    let input = try KagemushaWalletSetupInputV1(selector: 1, identity: identity,
      amount: .init(low: UInt64.max, high: UInt64.max))
    identity[0] = 0
    input.withRequest { request in
      XCTAssertEqual(request.pointee.selector, 1)
      XCTAssertEqual(request.pointee.amount.low, UInt64.max)
      XCTAssertEqual(request.pointee.amount.high, UInt64.max)
      XCTAssertEqual(request.pointee.token, 0)
      XCTAssertEqual(Data(bytes: request.pointee.setup_id!, count: 32), Data(repeating: 1, count: 32))
      XCTAssertEqual(request.pointee.first_length, 0)
      XCTAssertEqual(request.pointee.second_length, 0)
      XCTAssertEqual(request.pointee.third_length, 0)
    }
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 1, identity: identity))
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: 1, identity: identity,
      amount: .init(low: 0, high: 1)))
  }
  func testFeeOriginalsRemainPairedAndBoundedBeforeNativeCopy() throws {
    let identity = Data(repeating: 1, count: 32)
    var offer = Data([7]), fee = Data(repeating: 8, count: 1_024), certificate = Data(repeating: 9, count: 512)
    let input = try KagemushaWalletSetupInputV1.request(identity: identity,
      offer: offer, feeSchedule: fee, feeCertificate: certificate)
    offer[0] = 0; fee[0] = 0; certificate[0] = 0
    input.withRequest { request in
      XCTAssertEqual(request.pointee.first_length, 1)
      XCTAssertEqual(request.pointee.second_length, 1_024)
      XCTAssertEqual(request.pointee.third_length, 512)
      XCTAssertEqual(Data(bytes: request.pointee.first!, count: 1), Data([7]))
      XCTAssertEqual(Data(bytes: request.pointee.second!, count: 1_024), Data(repeating: 8, count: 1_024))
      XCTAssertEqual(Data(bytes: request.pointee.third!, count: 512), Data(repeating: 9, count: 512))
    }
    XCTAssertNoThrow(try KagemushaWalletSetupInputV1.request(identity: identity,
      offer: offer, feeSchedule: nil, feeCertificate: nil))
    for (fee, certificate) in [(Data([1]) as Data?, nil as Data?), (nil, Data([1])),
      (Data(), Data()), (Data(), Data([1])), (Data([1]), Data()),
      (Data(repeating: 1, count: 1_025), Data([1])), (Data([1]), Data(repeating: 1, count: 513))] {
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1.request(identity: identity,
        offer: offer, feeSchedule: fee, feeCertificate: certificate))
    }
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1.request(identity: identity,
      offer: Data(), feeSchedule: nil, feeCertificate: nil))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1.request(identity: identity,
      offer: Data(repeating: 1, count: 10_001), feeSchedule: nil, feeCertificate: nil))
  }
  func testSetupCannotCarryUnusedIdentityTokenAmountOrSigningOriginal() throws {
    let id = Data(repeating: 1, count: 32)
    for selector in [UInt32(0), 4] {
      XCTAssertNoThrow(try KagemushaWalletSetupInputV1(selector: selector))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, identity: id))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, amount: .init(low: 1, high: 0)))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, token: 1))
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: selector, first: Data([7])))
    }
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 1, identity: Data(repeating: 0, count: 32), amount: .init(low: 1, high: 0)))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 2, first: Data([7])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 3, first: Data()))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 3, first: Data(repeating: 1, count: 10_001)))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 6))
  }
  func testMalformedTimeReplyCannotConsumeTheExistingOrigin() throws {
    let owner = KagemushaWalletSetupOriginV1()
    let exchange = try KagemushaWalletCallV1(status: 13, sequenceLow: 23,
      sequenceHigh: 0, detail: 0, bytes: Data(repeating: 2, count: 32)).exchange(origin: owner)
    for (anchor, certificate) in [(Data(), Data([1])), (Data([1]), Data()),
      (Data(repeating: 1, count: 513), Data([1])), (Data([1]), Data(repeating: 1, count: 513))] {
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 5,
        token: exchange.tokenFor(origin: owner), first: anchor, second: certificate))
      XCTAssertEqual(try exchange.tokenFor(origin: owner), 23)
    }
    let input = try KagemushaWalletSetupInputV1(selector: 5,
      token: exchange.tokenFor(origin: owner), first: Data(repeating: 1, count: 512),
      second: Data(repeating: 2, count: 512))
    input.withRequest { request in
      XCTAssertEqual(request.pointee.token, 23)
      XCTAssertEqual(request.pointee.first_length, 512)
      XCTAssertEqual(request.pointee.second_length, 512)
      XCTAssertEqual(request.pointee.third_length, 0)
    }
    try exchange.consume(origin: owner)
    XCTAssertThrowsError(try exchange.tokenFor(origin: owner))
  }
  func testBootstrapAndCreditedKeepPreparingPendingAndCompletionSeparate() throws {
    for status in [Int32(0), 2, 3, 4, 5, 6, 7, 8, 9, 11] {
      let original = try KagemushaWalletCallV1(status: status, sequenceLow: 17,
        sequenceHigh: 1, detail: 0, bytes: Data())
      XCTAssertEqual(try original.completion().status, status)
      XCTAssertThrowsError(try original.original())
      XCTAssertThrowsError(try original.exchange(origin: KagemushaWalletSetupOriginV1()))
    }
    let completed = try KagemushaWalletCallV1(status: 1, sequenceLow: 17,
      sequenceHigh: 1, detail: 0, bytes: Data([1, 0, 2]))
    XCTAssertEqual(try completed.completion().bytes, Data([1, 0, 2]))
    XCTAssertThrowsError(try completed.original())
  }

}
