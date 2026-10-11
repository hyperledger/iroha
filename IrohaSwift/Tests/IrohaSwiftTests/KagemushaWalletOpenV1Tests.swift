import Foundation
import XCTest
@testable import IrohaSwift

final class KagemushaWalletOpenV1Tests: XCTestCase {
  func testOriginalIntakeBoundsAndNativeLayout() throws {
    let one = Data([7])
    let value = try KagemushaWalletOpenOriginalsV1(credential: one, enrollmentCertificates: one, account: one, assetScope: one)
    value.withRequest {
      XCTAssertEqual($0.pointee.credential_length, 1)
      XCTAssertEqual($0.pointee.certificates_length, 1)
      XCTAssertEqual($0.pointee.account_length, 1)
      XCTAssertEqual($0.pointee.asset_length, 1)
      XCTAssertEqual($0.pointee.credential!.pointee, 7)
    }
    for role in 0..<4 {
      var values = [one, one, one, one]
      values[role] = Data(repeating: 0, count: [1_024, 10_000, 4_096, 1_024][role] + 1)
      XCTAssertThrowsError(try KagemushaWalletOpenOriginalsV1(credential: values[0], enrollmentCertificates: values[1], account: values[2], assetScope: values[3]))
      values[role] = Data()
      XCTAssertThrowsError(try KagemushaWalletOpenOriginalsV1(credential: values[0], enrollmentCertificates: values[1], account: values[2], assetScope: values[3]))
    }
    // Runtime raw-handle construction is internal and requires its actual driver/platform lease.
    // Invalid internal handles and callback retention are covered by NativeLease component tests.
  }
  func testAccountChallengeAndOpenedHandleAreDistinctBoundedOutcomes() throws {
    XCTAssertNoThrow(try KagemushaWalletCallV1(status: 15, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: 32)))
    XCTAssertNoThrow(try KagemushaWalletCallV1(status: 16, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: Data()))
    for count in [0, 31, 33] {
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: 15, sequenceLow: 1, sequenceHigh: 0, detail: 0, bytes: Data(repeating: 1, count: count)))
    }
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 16, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: Data()))
    XCTAssertThrowsError(try KagemushaWalletCallV1(status: 16, sequenceLow: 1, sequenceHigh: 1, detail: 0, bytes: Data()))
  }
  private enum Refusal: Error { case storage }
  private final class Selected {
    let identity: KagemushaWalletAdmissionIdentityV1
    init(_ identity: KagemushaWalletAdmissionIdentityV1) { self.identity = identity }
  }
  func testSameChallengeAndIdentitySurviveOrdinaryRefusal() throws {
    let lifetime = KagemushaWalletAdmissionLifetimeV1<Selected>()
    let challenge = Data(repeating: 7, count: 32)
    var creations = 0
    let first = try lifetime.select(challenge) { creations += 1; return Selected($0) }
    XCTAssertThrowsError(try lifetime.finish(first.identity) { throw Refusal.storage })
    let repeated = try lifetime.select(challenge) { creations += 1; return Selected($0) }
    XCTAssertTrue(first === repeated)
    XCTAssertEqual(creations, 1)
    XCTAssertThrowsError(try lifetime.select(Data(repeating: 8, count: 32)) { Selected($0) })
    XCTAssertTrue(first === (try lifetime.select(challenge) { Selected($0) }))
    XCTAssertEqual(try lifetime.finish(first.identity) { 17 }, 17)
    var staleActionRan = false
    XCTAssertThrowsError(try lifetime.finish(first.identity) { staleActionRan = true })
    XCTAssertFalse(staleActionRan)
  }
  func testOldWrapperCannotCancelLaterChallenge() throws {
    let lifetime = KagemushaWalletAdmissionLifetimeV1<Selected>()
    let first = try lifetime.select(Data(repeating: 1, count: 32)) { Selected($0) }
    try lifetime.abandon(first.identity) {}
    let next = try lifetime.select(Data(repeating: 2, count: 32)) { Selected($0) }
    var cancelledLater = false
    try lifetime.abandon(first.identity) { cancelledLater = true }
    XCTAssertFalse(cancelledLater)
    XCTAssertEqual(try lifetime.finish(next.identity) { 19 }, 19)
  }
  func testCancelRefusalRetainsSamePendingUntilSuccess() throws {
    let lifetime = KagemushaWalletAdmissionLifetimeV1<Selected>()
    let challenge = Data(repeating: 3, count: 32)
    let first = try lifetime.select(challenge) { Selected($0) }
    XCTAssertThrowsError(try lifetime.abandon(first.identity) { throw Refusal.storage })
    XCTAssertTrue(first === (try lifetime.select(challenge) { Selected($0) }))
    try lifetime.abandon(first.identity) {}
    let next = try lifetime.select(challenge) { Selected($0) }
    XCTAssertFalse(first.identity === next.identity)
    try lifetime.abandon(first.identity) { XCTFail("stale cancellation dispatched") }
    XCTAssertEqual(try lifetime.finish(next.identity) { 23 }, 23)
  }
  func testWeakPendingCacheAllowsDeinitCancellationBeforeRecovery() throws {
    let lifetime = KagemushaWalletAdmissionLifetimeV1<Selected>()
    let challenge = Data(repeating: 4, count: 32)
    var selected: Selected? = try lifetime.select(challenge) { Selected($0) }
    weak var weakSelected = selected
    let identity = try XCTUnwrap(selected).identity
    selected = nil
    XCTAssertNil(weakSelected)
    var abandoned = false
    try lifetime.abandon(identity) { abandoned = true }
    XCTAssertTrue(abandoned)
    XCTAssertThrowsError(try lifetime.finish(identity) { 29 })
  }
  func testWaitingOldDeinitCannotCancelRecoveredWrapperAfterWeakZeroing() throws {
    let lifetime = KagemushaWalletAdmissionLifetimeV1<Selected>()
    let challenge = Data(repeating: 6, count: 32)
    var selected: Selected? = try lifetime.select(challenge) { Selected($0) }
    weak var weakSelected = selected
    let oldIdentity = try XCTUnwrap(selected).identity
    selected = nil
    XCTAssertNil(weakSelected)
    // Deterministic managed schedule: begin owns Runtime lock; old deinit waits.
    // Weak cache is nil, so begin recovers the exact challenge with a fresh wrapper token.
    let recovered = try lifetime.select(challenge) { Selected($0) }
    XCTAssertFalse(recovered.identity === oldIdentity)
    var cancelledReplacement = false
    try lifetime.abandon(oldIdentity) { cancelledReplacement = true }
    XCTAssertFalse(cancelledReplacement)
    XCTAssertTrue(recovered === (try lifetime.select(challenge) { Selected($0) }))
    XCTAssertEqual(try lifetime.finish(recovered.identity) { 41 }, 41)
  }
  func testInterruptedCompletionRetainsSelectionOnRefusalAndClearsOnSuccess() throws {
    let lifetime = KagemushaWalletAdmissionLifetimeV1<Selected>()
    let challenge = Data(repeating: 5, count: 32)
    let selected = try lifetime.select(challenge) { Selected($0) }
    XCTAssertThrowsError(try lifetime.complete { throw Refusal.storage })
    XCTAssertTrue(selected === (try lifetime.select(challenge) { Selected($0) }))
    XCTAssertEqual(try lifetime.complete { 31 }, 31)
    try lifetime.abandon(selected.identity) { XCTFail("completed wrapper dispatched cancellation") }
    XCTAssertThrowsError(try lifetime.finish(selected.identity) { 37 })
  }
}
