// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import XCTest

final class KagemushaQRAttemptGateTests: XCTestCase {
  private func admit(_ record: KagemushaQRAttemptGate.Record, _ gate: inout KagemushaQRAttemptGate) throws {
    let id = UUID(); try gate.beginScan(id); XCTAssertTrue(try gate.observed(id)); try gate.admit(record, scan: id)
  }
  func testFreshSenderRequiresAskRequestAuthenticationReleaseAndNativeAdmission() throws {
    var gate = KagemushaQRAttemptGate(role: .sender, recovery: false, previouslyDispatched: false, retainedAsk: false, retainedRequest: false)
    try admit(.ask, &gate); try admit(.request, &gate)
    XCTAssertThrowsError(try gate.releasedPayment(status: 1))
    try gate.authenticated(at: 10)
    XCTAssertThrowsError(try gate.releasedPayment(status: 2))
    try gate.releasedPayment(status: 1); try admit(.credited, &gate)
    XCTAssertThrowsError(try gate.credited(status: 2, arrival: 20, admitted: 21))
    let sample = try XCTUnwrap(gate.credited(status: 1, arrival: 20, admitted: 25))
    XCTAssertEqual(sample.0, 10); XCTAssertEqual(sample.1, 15); XCTAssertTrue(gate.terminal)
  }
  func testCreditedCannotPrecedePaymentRelease() throws {
    var gate = KagemushaQRAttemptGate(role: .sender, recovery: false, previouslyDispatched: false, retainedAsk: false, retainedRequest: false)
    try admit(.ask, &gate); try admit(.request, &gate)
    let id = UUID(); try gate.beginScan(id)
    XCTAssertThrowsError(try gate.admit(.credited, scan: id))
  }
  func testRecoveryUsesExactRequestAndNeverInventsFreshLatency() throws {
    var gate = KagemushaQRAttemptGate(role: .sender, recovery: true, previouslyDispatched: true, retainedAsk: true, retainedRequest: true)
    try admit(.request, &gate)
    XCTAssertThrowsError(try gate.authenticated(at: 10))
    try gate.releasedPayment(status: 1); try admit(.credited, &gate)
    XCTAssertNil(try gate.credited(status: 1, arrival: 20, admitted: 25))
  }
  func testPredispatchRecoveryStillNeedsFreshAuthentication() throws {
    var gate = KagemushaQRAttemptGate(role: .sender, recovery: true, previouslyDispatched: false, retainedAsk: true, retainedRequest: false)
    try admit(.request, &gate)
    XCTAssertThrowsError(try gate.releasedPayment(status: 1))
    try gate.authenticated(at: 10); try gate.releasedPayment(status: 1); try admit(.credited, &gate)
    XCTAssertNil(try gate.credited(status: 1, arrival: 20, admitted: 25))
  }
  func testReceiverDisplayCloseNeverMeansPeerDelivery() throws {
    var gate = KagemushaQRAttemptGate(role: .receiver, recovery: false, previouslyDispatched: false, retainedAsk: false, retainedRequest: false)
    XCTAssertThrowsError(try gate.closedReceiverDisplay())
    try admit(.offer, &gate); try admit(.payment, &gate)
    XCTAssertThrowsError(try gate.displayedCredited())
    try gate.received(); XCTAssertFalse(gate.terminal)
    try gate.displayedCredited(); XCTAssertFalse(gate.terminal)
    try gate.closedReceiverDisplay(); XCTAssertTrue(gate.terminal)
  }
  func testReceiverRecoveryRescansPayment() throws {
    var gate = KagemushaQRAttemptGate(role: .receiver, recovery: true, previouslyDispatched: true, retainedAsk: true, retainedRequest: true)
    try admit(.payment, &gate); try gate.received(); try gate.displayedCredited(); try gate.closedReceiverDisplay()
    XCTAssertTrue(gate.terminal)
  }
  func testStaleCancelledAndWrongOrderCallbacksCannotAdvance() throws {
    var gate = KagemushaQRAttemptGate(role: .sender, recovery: false, previouslyDispatched: false, retainedAsk: false, retainedRequest: false)
    let id = UUID(); try gate.beginScan(id)
    XCTAssertFalse(try gate.observed(UUID())); XCTAssertEqual(gate.observations, 0)
    XCTAssertThrowsError(try gate.beginScan(UUID()))
    XCTAssertThrowsError(try gate.admit(.request, scan: id))
    try gate.admit(.ask, scan: id); XCTAssertFalse(try gate.observed(id))
    gate.fail(); XCTAssertFalse(try gate.observed(id)); XCTAssertThrowsError(try gate.beginScan(UUID()))
  }
  func testObservationStorageIsBoundedEvenForIdenticalDuplicates() throws {
    var gate = KagemushaQRAttemptGate(role: .sender, recovery: false, previouslyDispatched: false, retainedAsk: false, retainedRequest: false)
    let id = UUID(); try gate.beginScan(id)
    for _ in 0..<KagemushaQRAttemptGate.maximumObservations { XCTAssertTrue(try gate.observed(id)) }
    XCTAssertThrowsError(try gate.observed(id))
    XCTAssertEqual(gate.observations, KagemushaQRAttemptGate.maximumObservations)
  }
  func testClockRegressionCannotQualify() throws {
    var gate = KagemushaQRAttemptGate(role: .sender, recovery: false, previouslyDispatched: false, retainedAsk: true, retainedRequest: true)
    try admit(.request, &gate); try gate.authenticated(at: 20); try gate.releasedPayment(status: 1); try admit(.credited, &gate)
    XCTAssertThrowsError(try gate.credited(status: 1, arrival: 19, admitted: 21))
    XCTAssertThrowsError(try gate.credited(status: 1, arrival: 21, admitted: 20))
    XCTAssertFalse(gate.terminal)
  }
}
