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
  func testNearbyCommandInputsAreClosedAndRecoveryHasSameOriginalIDs() throws {
    let sender: Set<String> = ["request-id", "session-id", "request-hash", "peer-certificate"]
    for action in ["nearby-send", "nearby-recover-send"] {
      try KagemushaMonetaryProbeManifest.validate(action, names: sender)
      XCTAssertThrowsError(try KagemushaMonetaryProbeManifest.validate(action, names: sender.union(["payment"])))
    }
    for action in ["nearby-receive", "nearby-recover-receive"] {
      try KagemushaMonetaryProbeManifest.validate(action, names: sender.union(["setup-id"]))
      XCTAssertThrowsError(try KagemushaMonetaryProbeManifest.validate(action, names: sender))
    }
    XCTAssertThrowsError(try KagemushaMonetaryProbeManifest.validate("nearby-prepare", names: ["setup-id", "offer", "fee-schedule"]))
    XCTAssertEqual(try KagemushaMonetaryProbeManifest.maximum("session-id"), 16)
    XCTAssertEqual(try KagemushaMonetaryProbeManifest.maximum("peer-certificate"), 32)
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
