// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import XCTest
import Darwin

final class KagemushaNearbyAttemptGateTests: XCTestCase {
  func testClockUsesContinuousNanosecondsRatherThanRawTicksOrSuspendingUptime() {
    var scale = mach_timebase_info_data_t()
    XCTAssertEqual(mach_timebase_info(&scale), KERN_SUCCESS)
    guard scale.denom > 0 else { return XCTFail("invalid clock timebase") }
    func nanoseconds(_ ticks: UInt64) -> UInt64 {
      let product = ticks.multipliedFullWidth(by: UInt64(scale.numer))
      return UInt64(scale.denom).dividingFullWidth(product).quotient
    }
    let before = nanoseconds(mach_continuous_time())
    let actual = KagemushaNearbyClock.nowNanoseconds()
    let after = nanoseconds(mach_continuous_time())
    XCTAssertGreaterThan(actual, 0)
    XCTAssertGreaterThanOrEqual(actual, before)
    XCTAssertLessThanOrEqual(actual, after)
  }
  func testContinuousElapsedRetainsInterruptionAndSeparateAdmissionDelay() throws {
    var gate = try sender()
    try gate.confirmed(at: 100)
    try gate.sentPayment(); try gate.admit(.credited)
    // A three-second interruption must not become a sub-two-second observation.
    // These are synthetic continuous-clock ticks, not a physical sleep experiment.
    let elapsed = try XCTUnwrap(gate.credited(status: 1, arrival: 3_000_000_100, admitted: 3_200_000_100))
    XCTAssertEqual(elapsed.0, 3_000_000_000)
    XCTAssertEqual(elapsed.1, 3_200_000_000)
    XCTAssertGreaterThan(elapsed.0, 2_000_000_000)
  }
  private func sender(recovery: Bool = false) throws -> KagemushaNearbyAttemptGate {
    var gate = KagemushaNearbyAttemptGate(role: .sender, recovery: recovery)
    try gate.admit(.hello); try gate.admit(.authentication); try gate.admit(.request)
    return gate
  }
  func testTimingRequiresConfirmationReleaseAndCompleteNativeAdmission() throws {
    var gate = try sender()
    XCTAssertThrowsError(try gate.admit(.credited))
    XCTAssertThrowsError(try gate.sentPayment())
    try gate.confirmed(at: 100); try gate.sentPayment(); try gate.admit(.credited)
    XCTAssertThrowsError(try gate.credited(status: 2, arrival: 150, admitted: 175))
    XCTAssertThrowsError(try gate.credited(status: 1, arrival: 99, admitted: 175))
    XCTAssertFalse(gate.terminal)
    let elapsed = try XCTUnwrap(gate.credited(status: 1, arrival: 150, admitted: 175))
    XCTAssertEqual(elapsed.0, 50); XCTAssertEqual(elapsed.1, 75)
    XCTAssertThrowsError(try gate.credited(status: 1, arrival: 150, admitted: 175))
  }
  func testRecoveryNeverConstructsMissingOriginalClockAnchor() throws {
    var gate = try sender(recovery: true)
    XCTAssertThrowsError(try gate.confirmed(at: 100))
    try gate.sentPayment(); try gate.admit(.credited)
    XCTAssertNil(try gate.credited(status: 1, arrival: 150, admitted: 175))
    XCTAssertTrue(gate.terminal)
  }
  func testReceiverRejectsReorderedAndExtraRecords() throws {
    var gate = KagemushaNearbyAttemptGate(role: .receiver, recovery: false)
    XCTAssertThrowsError(try gate.admit(.payment))
    try gate.admit(.hello); try gate.admit(.authentication); try gate.admit(.payment)
    XCTAssertThrowsError(try gate.admit(.credited))
    try gate.receiverDelivered(); XCTAssertTrue(gate.terminal)
    XCTAssertThrowsError(try gate.admit(.hello))
  }
  func testFailureIsTerminalAndOtherStatusesDoNotMeanComplete() throws {
    for status: Int32 in [0,2,3,4,5,6,7,8,9,10,11,12,59] {
      XCTAssertThrowsError(try KagemushaNearbyAttemptGate.requireComplete(status))
    }
    var gate = try sender(); gate.fail()
    XCTAssertThrowsError(try gate.confirmed(at: 100))
  }
  func testReceiveRejectsOtherStatusesBeforeReadingRetainedOrProjectedData() {
    let requestID = Data(repeating: 0x31, count: 32)
    let statuses: [Int32] = [Int32.min, -15, -1] + Array(0...59) + [Int32.max]
    for recovery in [false, true] {
      for status in statuses where status != 1 && !(recovery && status == 10) {
        var callbacks = 0
        XCTAssertThrowsError(try KagemushaNearbyAttemptGate.receivedCredit(
          status: status, recovery: recovery, requestID: requestID,
          retainedOutput: { _ in callbacks += 1 },
          projection: { _ in
            callbacks += 1
            return .init(isReceiver: true, isBurned: false, original: Data([0x71]))
          }), "status \(status), recovery \(recovery)")
        XCTAssertEqual(callbacks, 0, "status must be admitted before any evidence lookup")
      }
    }
    XCTAssertThrowsError(try KagemushaNearbyAttemptGate.requireComplete(10),
      "Send admission remains COMPLETE-only, including recovery")
  }
  func testCollectedReceiveRecoveryNeverLooksUpRetainedOutputAndReturnsExactFreshBytes() throws {
    let requestID = Data(repeating: 0x32, count: 32)
    let fresh = Data([0x00, 0x7f, 0x80, 0xff, 0x00])
    var requests: [Data] = []
    let actual = try KagemushaNearbyAttemptGate.receivedCredit(
      status: 10, recovery: true, requestID: requestID,
      retainedOutput: { _ in XCTFail("collected Receive no longer has retained output") },
      projection: { requested in
        requests.append(requested)
        return .init(isReceiver: true, isBurned: false, original: fresh)
      })
    XCTAssertEqual(requests, [requestID], "the native projection must use the exact Receive ID")
    XCTAssertEqual(actual, fresh)
  }
  func testCompleteReceiveStillCapturesOriginalReleaseBeforeReadingFreshCredit() throws {
    let requestID = Data(repeating: 0x33, count: 32)
    let retainedReceipt = Data([0x81, 0x82])
    let fresh = Data([0x91, 0x92, 0x93])
    for recovery in [false, true] {
      var callbacks: [String] = []
      var captured: Data?
      let actual = try KagemushaNearbyAttemptGate.receivedCredit(
        status: 1, recovery: recovery, requestID: requestID,
        retainedOutput: { requested in
          XCTAssertEqual(requested, requestID)
          callbacks.append("retained")
          captured = retainedReceipt
        },
        projection: { requested in
          XCTAssertEqual(requested, requestID)
          callbacks.append("projection")
          return .init(isReceiver: true, isBurned: false, original: fresh)
        })
      XCTAssertEqual(callbacks, ["retained", "projection"])
      XCTAssertEqual(captured, retainedReceipt, "normal Receive keeps its original release evidence")
      XCTAssertEqual(actual, fresh, "the radio acknowledgement must use current native credit evidence")
      XCTAssertNotEqual(actual, captured)
    }
  }
  func testReceiveRejectsMissingBurnedAndPayerProjectionEvidence() {
    let requestID = Data(repeating: 0x34, count: 32)
    let invalid: [KagemushaNearbyAttemptGate.ReceivedCredit] = [
      .init(isReceiver: true, isBurned: false, original: nil),
      .init(isReceiver: true, isBurned: false, original: Data()),
      .init(isReceiver: true, isBurned: true, original: Data([0x71])),
      .init(isReceiver: false, isBurned: false, original: Data([0x71])),
    ]
    let attempts: [(Int32, Bool)] = [(1, false), (1, true), (10, true)]
    for (status, recovery) in attempts {
      for value in invalid {
        var retainedCalls = 0, projectionCalls = 0
        XCTAssertThrowsError(try KagemushaNearbyAttemptGate.receivedCredit(
          status: status, recovery: recovery, requestID: requestID,
          retainedOutput: { _ in retainedCalls += 1 },
          projection: { requested in
            XCTAssertEqual(requested, requestID)
            projectionCalls += 1
            return value
          }))
        XCTAssertEqual(retainedCalls, status == 1 ? 1 : 0)
        XCTAssertEqual(projectionCalls, 1)
      }
    }
  }
  func testReceivePropagatesProjectionAndRetainedOutputFailuresWithoutFallback() {
    enum ProbeFailure: Error { case retained, projection }
    let requestID = Data(repeating: 0x35, count: 32)
    let attempts: [(Int32, Bool)] = [(1, false), (1, true), (10, true)]
    for (status, recovery) in attempts {
      var retainedCalls = 0, projectionCalls = 0
      XCTAssertThrowsError(try KagemushaNearbyAttemptGate.receivedCredit(
        status: status, recovery: recovery, requestID: requestID,
        retainedOutput: { _ in retainedCalls += 1 },
        projection: { _ in projectionCalls += 1; throw ProbeFailure.projection })) { error in
        guard case ProbeFailure.projection = error else { return XCTFail("changed projection failure") }
      }
      XCTAssertEqual(retainedCalls, status == 1 ? 1 : 0)
      XCTAssertEqual(projectionCalls, 1)
    }
    var projectionCalled = false
    XCTAssertThrowsError(try KagemushaNearbyAttemptGate.receivedCredit(
      status: 1, recovery: false, requestID: requestID,
      retainedOutput: { _ in throw ProbeFailure.retained },
      projection: { _ in
        projectionCalled = true
        return .init(isReceiver: true, isBurned: false, original: Data([0x71]))
      })) { error in
      guard case ProbeFailure.retained = error else { return XCTFail("changed retained-output failure") }
    }
    XCTAssertFalse(projectionCalled, "failed original-release capture cannot become a successful diagnostic")
  }
  func testAuthenticationOwnsOneContextAndCompletesOnlyOnce() {
    let first = UUID(), second = UUID()
    var gate = KagemushaNearbyAuthenticationGate()
    XCTAssertTrue(gate.begin(first))
    XCTAssertFalse(gate.begin(second))
    XCTAssertFalse(gate.finish(second))
    XCTAssertEqual(gate.activeID, first)
    XCTAssertTrue(gate.finish(first))
    XCTAssertNil(gate.activeID)
    XCTAssertFalse(gate.finish(first))
  }
  func testCancelledAuthenticationCannotClearItsReplacement() {
    let first = UUID(), second = UUID()
    var gate = KagemushaNearbyAuthenticationGate()
    XCTAssertTrue(gate.begin(first))
    gate.cancel()
    XCTAssertNil(gate.activeID)
    XCTAssertTrue(gate.begin(second))
    XCTAssertFalse(gate.finish(first))
    XCTAssertEqual(gate.activeID, second)
    XCTAssertTrue(gate.finish(second))
    gate.cancel()
    XCTAssertNil(gate.activeID)
  }
}
