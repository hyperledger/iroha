import Foundation

/// Display-only snapshot selected by Native for explicit destructive confirmation.
/// Gross retained value and core burns are not a fully folded spendable balance.
public struct KagemushaWalletDeletionProjectionV1: Sendable {
  /// Deletion permanently loses the payment key, offline-value recovery, pending
  /// delivery and unpaid late claims. These figures are not fully folded spendable value.
  public static let warning = "Permanently delete the payment key and lose offline-value recovery, pending delivery and unpaid late claims. Gross value and core burns are not a fully folded spendable balance."
  public let pending: Bool
  public let lifecycle: KagemushaWalletLifecycleV1
  /// Bootstrap1, Load2, Send3, Receive4, ArchiveSent5, Unload6, RefreshPolicy7, Retiring8.
  public let operationKind: UInt8
  public let pendingOutgoing: Bool
  public let feeClaims: Bool
  public let loadRedeem: Bool
  public let slot: Data
  public let markerFileDigest: Data
  public let schemeId: Data
  public let assetDigest: Data
  public let walletId: Data
  public let head: Data
  public let sequence: KagemushaWalletUInt128V1
  public let grossBalance: KagemushaWalletUInt128V1
  public let coreBurnedTotal: KagemushaWalletUInt128V1

  init(_ original: Data) throws {
    guard original.count == 254 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    let bytes = Array(original)
    guard bytes.count == 254, Array(bytes[0..<8]) == Array("KWCDV1\0\0".utf8),
      (1...2).contains(bytes[8]), let lifecycle = KagemushaWalletLifecycleV1(rawValue: UInt32(bytes[9])),
      (1...8).contains(bytes[10]), bytes[11...13].allSatisfy({ $0 <= 1 }),
      [14, 46, 78, 110, 142, 174].allSatisfy({ start in bytes[start..<start+32].contains(where: { $0 != 0 }) })
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    func scalar(_ start: Int) -> KagemushaWalletUInt128V1 {
      func limb(_ offset: Int) -> UInt64 {
        (0..<8).reduce(UInt64(0)) { $0 | (UInt64(bytes[offset+$1]) << ($1*8)) }
      }
      return .init(low: limb(start), high: limb(start+8))
    }
    let gross = scalar(222), burned = scalar(238)
    guard burned <= gross else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    self.pending = bytes[8] == 1; self.lifecycle = lifecycle; self.operationKind = bytes[10]
    self.pendingOutgoing = bytes[11] == 1; self.feeClaims = bytes[12] == 1; self.loadRedeem = bytes[13] == 1
    self.slot = Data(bytes[14..<46]); self.markerFileDigest = Data(bytes[46..<78])
    self.schemeId = Data(bytes[78..<110]); self.assetDigest = Data(bytes[110..<142])
    self.walletId = Data(bytes[142..<174]); self.head = Data(bytes[174..<206])
    self.sequence = scalar(206); self.grossBalance = gross; self.coreBurnedTotal = burned
  }
}

/// One-use review bound to its wallet instance. Its DATA cannot authorize another owner.
public final class KagemushaWalletDeletionReviewV1: @unchecked Sendable, CustomStringConvertible {
  public let projection: KagemushaWalletDeletionProjectionV1
  fileprivate let origin: KagemushaWalletDeletionGateV1
  fileprivate let epoch: UInt64
  fileprivate let token: UInt64
  // Accessed only while holding origin.lock.
  fileprivate var consumed = false
  fileprivate init(origin: KagemushaWalletDeletionGateV1, epoch: UInt64, token: UInt64,
                   projection: KagemushaWalletDeletionProjectionV1) {
    self.origin = origin; self.epoch = epoch; self.token = token; self.projection = projection
  }
  public var description: String { "KagemushaWalletDeletionReviewV1(review=[REDACTED])" }
}

/// Definitive native deletion recovery outcome; neither outcome implies ledger settlement.
public enum KagemushaWalletDeletionStatusV1: Sendable, Equatable {
  case deleted(marker: Data)
  /// Native definitely retained nonterminal custody; a fresh review is required to try again.
  case notDeleted
}

/// Managed dispatch guard only; the native owner remains authoritative. No lock spans an upcall.
final class KagemushaWalletDeletionGateV1: @unchecked Sendable {
  private let lock = NSLock()
  private var frozen = false
  private var inFlight = false
  private var terminalMarker: Data?
  private var epoch: UInt64 = 0
  func requireOrdinary() throws {
    lock.lock(); defer { lock.unlock() }
    guard !frozen else { throw KagemushaWalletErrorV1.closed }
  }
  func review(_ call: () throws -> KagemushaWalletCallV1) throws -> KagemushaWalletDeletionReviewV1 {
    lock.lock()
    guard !frozen else { lock.unlock(); throw KagemushaWalletErrorV1.closed }
    let issuedEpoch = epoch
    lock.unlock()
    let result = try call()
    guard result.status == 53 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    let projection = try KagemushaWalletDeletionProjectionV1(result.bytes)
    lock.lock(); defer { lock.unlock() }
    guard !frozen, epoch == issuedEpoch else { throw KagemushaWalletErrorV1.closed }
    return .init(origin: self, epoch: epoch, token: result.sequenceLow, projection: projection)
  }
  private func consume(_ review: KagemushaWalletDeletionReviewV1) throws -> UInt64 {
    guard !frozen, !inFlight, review.origin === self, review.epoch == epoch, !review.consumed else {
      throw KagemushaWalletErrorV1.invalidInput
    }
    review.consumed = true
    return review.token
  }
  func confirm(_ review: KagemushaWalletDeletionReviewV1,
               call: (UInt64) throws -> KagemushaWalletCallV1) throws -> Data {
    lock.lock()
    let token: UInt64
    do { token = try consume(review) } catch { lock.unlock(); throw error }
    frozen = true; inFlight = true; epoch &+= 1
    lock.unlock()
    defer { finishFlight() }
    let result = try call(token)
    guard result.status == 54 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    lock.lock(); terminalMarker = result.bytes; lock.unlock()
    return result.bytes
  }
  func resume(_ call: () throws -> KagemushaWalletCallV1) throws -> KagemushaWalletDeletionStatusV1 {
    lock.lock()
    guard frozen, !inFlight else { lock.unlock(); throw KagemushaWalletErrorV1.closed }
    frozen = true; inFlight = true; epoch &+= 1
    lock.unlock()
    defer { finishFlight() }
    let result = try call()
    lock.lock(); defer { lock.unlock() }
    if result.status == 54 {
      guard terminalMarker == nil || terminalMarker == result.bytes else { throw KagemushaWalletErrorV1.invalidNativeOutput }
      terminalMarker = result.bytes
      return .deleted(marker: result.bytes)
    }
    guard result.status == 56, terminalMarker == nil else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    frozen = false
    return .notDeleted
  }
  func discard(_ review: KagemushaWalletDeletionReviewV1,
               call: (UInt64) throws -> KagemushaWalletCallV1) throws {
    lock.lock()
    let token: UInt64
    do { token = try consume(review) } catch { lock.unlock(); throw error }
    lock.unlock()
    guard try call(token).status == 55 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
  }
  private func finishFlight() { lock.lock(); inFlight = false; lock.unlock() }
}
