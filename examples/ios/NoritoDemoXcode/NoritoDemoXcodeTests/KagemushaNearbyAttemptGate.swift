// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import Foundation
import Darwin

/// One local clock for all attempt timestamps, including time the phone spends asleep.
/// Different phones and reboots have unrelated origins; never subtract their timestamps.
enum KagemushaNearbyClock {
  static let identity = "darwin-monotonic-raw-including-sleep"
  static func nowNanoseconds() -> UInt64 {
    clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
  }
}

/// Local diagnostic ordering and same-clock sample admission; Native owns all money.
struct KagemushaNearbyAttemptGate {
  enum Failure: Error { case order, incomplete, unknownStart }
  enum Role { case sender, receiver }
  enum Record { case hello, authentication, request, payment, credited }
  let role: Role
  let recovery: Bool
  private(set) var inboundCount = 0
  private(set) var confirmationNanoseconds: UInt64?
  private(set) var terminal = false
  private var paymentReleased = false

  mutating func admit(_ record: Record) throws {
    guard !terminal else { throw Failure.order }
    let expected: [Record] = role == .sender
      ? [.hello, .authentication, .request, .credited]
      : [.hello, .authentication, .payment]
    guard inboundCount < expected.count, expected[inboundCount] == record else {
      throw Failure.order
    }
    if record == .credited && !paymentReleased { throw Failure.order }
    inboundCount += 1
  }
  mutating func confirmed(at nanoseconds: UInt64) throws {
    guard !terminal, role == .sender, !recovery, inboundCount == 3,
      confirmationNanoseconds == nil, nanoseconds > 0 else { throw Failure.order }
    confirmationNanoseconds = nanoseconds
  }
  mutating func sentPayment() throws {
    guard !terminal, role == .sender, inboundCount == 3, !paymentReleased,
      recovery || confirmationNanoseconds != nil else { throw Failure.order }
    paymentReleased = true
  }
  static func requireComplete(_ status: Int32) throws {
    guard status == 1 else { throw Failure.incomplete }
  }
  mutating func credited(status: Int32, arrival: UInt64, admitted: UInt64) throws -> (UInt64, UInt64)? {
    guard !terminal, role == .sender, inboundCount == 4 else { throw Failure.order }
    try Self.requireComplete(status)
    guard admitted >= arrival else { throw Failure.order }
    guard confirmationNanoseconds != nil || recovery else { throw Failure.unknownStart }
    // A reconnect/restart never invents the missing historical confirmation timestamp.
    guard let start = confirmationNanoseconds else { terminal = true; return nil }
    guard arrival >= start else { throw Failure.order }
    terminal = true
    return (arrival - start, admitted - start)
  }
  mutating func receiverDelivered() throws {
    guard !terminal, role == .receiver, inboundCount == 3 else { throw Failure.order }
    terminal = true
  }
  mutating func fail() { terminal = true }
}

/// Main-actor authentication ownership; stale callbacks cannot clear a newer attempt.
struct KagemushaNearbyAuthenticationGate {
  private(set) var activeID: UUID?

  mutating func begin(_ id: UUID) -> Bool {
    guard activeID == nil else { return false }
    activeID = id
    return true
  }
  mutating func finish(_ id: UUID) -> Bool {
    guard activeID == id else { return false }
    activeID = nil
    return true
  }
  mutating func cancel() { activeID = nil }
}
