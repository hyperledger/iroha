// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import Foundation

/// Bounded optical callback order and local timing only. Native retains monetary authority.
struct KagemushaQRAttemptGate {
  enum Failure: Error { case order, observations, incomplete }
  enum Role { case sender, receiver }
  enum Record { case ask, offer, request, payment, credited }
  let role: Role
  let recovery: Bool
  let previouslyDispatched: Bool
  private let records: [Record]
  private var index = 0
  private var confirmation: UInt64?
  private var paymentReleased = false
  private var receiverDurable = false
  private var receiverDisplayed = false
  private(set) var terminal = false
  private(set) var observations = 0
  private var scanID: UUID?
  static let maximumObservations = 4096
  init(role: Role, recovery: Bool, previouslyDispatched: Bool, retainedAsk: Bool, retainedRequest: Bool) {
    self.role = role; self.recovery = recovery; self.previouslyDispatched = previouslyDispatched
    records = role == .sender ? ((retainedAsk ? [] : [.ask]) + [.request, .credited])
      : ((retainedRequest ? [] : [.offer]) + [.payment])
  }
  mutating func beginScan(_ id: UUID) throws {
    guard !terminal, scanID == nil, index < records.count else { throw Failure.order }
    scanID = id
  }
  /// Late callbacks are ignored; current callbacks consume a bounded observation slot.
  mutating func observed(_ id: UUID) throws -> Bool {
    guard !terminal, scanID == id else { return false }
    try observation(); return true
  }
  mutating func observation() throws {
    guard !terminal else { throw Failure.order }
    guard observations < Self.maximumObservations else { throw Failure.observations }
    observations += 1
  }
  mutating func admit(_ record: Record, scan id: UUID) throws {
    guard !terminal, scanID == id, index < records.count, records[index] == record,
      record != .credited || paymentReleased else { throw Failure.order }
    scanID = nil; index += 1
  }
  mutating func authenticated(at ticks: UInt64) throws {
    guard !terminal, role == .sender, !previouslyDispatched, confirmation == nil, ticks > 0,
      index > 0, records[index - 1] == .request else { throw Failure.order }
    confirmation = ticks
  }
  mutating func releasedPayment(status: Int32) throws {
    guard !terminal, role == .sender, !paymentReleased,
      index > 0, records[index - 1] == .request,
      previouslyDispatched || confirmation != nil else { throw Failure.order }
    guard status == 1 else { throw Failure.incomplete }
    paymentReleased = true
  }
  mutating func credited(status: Int32, arrival: UInt64, admitted: UInt64) throws -> (UInt64, UInt64)? {
    guard !terminal, role == .sender, index == records.count, paymentReleased,
      admitted >= arrival else { throw Failure.order }
    guard status == 1 else { throw Failure.incomplete }
    if let confirmation { guard arrival >= confirmation else { throw Failure.order } }
    guard recovery || confirmation != nil else { throw Failure.order }
    terminal = true
    guard !recovery, let confirmation else { return nil }
    return (arrival - confirmation, admitted - confirmation)
  }
  mutating func received() throws {
    guard !terminal, role == .receiver, index == records.count, !receiverDurable else { throw Failure.order }
    receiverDurable = true
  }
  mutating func displayedCredited() throws {
    guard !terminal, role == .receiver, receiverDurable, !receiverDisplayed else { throw Failure.order }
    receiverDisplayed = true
  }
  /// Closing the local screen supplies no evidence of payer receipt or admission.
  mutating func closedReceiverDisplay() throws {
    guard !terminal, role == .receiver, receiverDisplayed else { throw Failure.order }
    terminal = true
  }
  mutating func fail() { terminal = true; scanID = nil }
}
