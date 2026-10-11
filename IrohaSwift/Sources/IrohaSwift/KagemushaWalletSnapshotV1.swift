import Foundation
import NoritoBridge

/// Lossless unsigned Native scalar. No balance computation is performed in this wrapper.
public struct KagemushaWalletUInt128V1: Sendable, Equatable, Comparable {
  public let low: UInt64
  public let high: UInt64
  public init(low: UInt64, high: UInt64) { self.low = low; self.high = high }
  public static func < (a: Self, b: Self) -> Bool {
    a.high == b.high ? a.low < b.low : a.high < b.high
  }
  init(_ value: connect_norito_kagemusha_wallet_u128_v1) {
    self.init(low: value.low, high: value.high)
  }
}

/// Actual retained lifecycle; Retiring may Send/Unload remaining value under Native rules.
public enum KagemushaWalletLifecycleV1: UInt32, Sendable {
  case active = 1, retiring = 2
}

/// Exact verified source-indexed fold. Its credential may precede a current renewal.
public struct KagemushaWalletSnapshotFoldV1: Sendable, Equatable {
  public let sequence: KagemushaWalletUInt128V1
  public let head: Data
  public let credentialDigest: Data
  public let burnedTotal: KagemushaWalletUInt128V1
}

/// Native ownership and local proof progress (§PC/P1a/P1b/P4), with no operation permission.
/// Owned value excludes known burns. An unfinished Receive fold can discover the sole P4
/// burn exception. `foldedBalance` exists only for Ω of this exact current head; each Native
/// operation still enforces its lifecycle, controls, authentication and other prerequisites.
public struct KagemushaWalletSnapshotV1: Sendable, Equatable {
  public let schemeId: Data
  public let walletId: Data
  public let head: Data
  public let credentialDigest: Data
  public let sequence: KagemushaWalletUInt128V1
  public let lifecycle: KagemushaWalletLifecycleV1
  public let grossBalance: KagemushaWalletUInt128V1
  public let coreBurnedTotal: KagemushaWalletUInt128V1
  public let knownBurnedTotal: KagemushaWalletUInt128V1
  public let ownedBalance: KagemushaWalletUInt128V1
  public let foldedBalance: KagemushaWalletUInt128V1?
  public let foldBacklog: KagemushaWalletUInt128V1
  public let verifiedFold: KagemushaWalletSnapshotFoldV1?
  public var headIsFolded: Bool { foldedBalance != nil }

  init(_ value: connect_norito_kagemusha_wallet_snapshot_v1_t) throws {
    func bytes<T>(_ word: T) -> Data { withUnsafeBytes(of: word) { Data($0) } }
    func word(_ data: Data) -> Bool { data.count == 32 && data.contains { $0 != 0 } }
    let scheme = bytes(value.scheme), wallet = bytes(value.wallet)
    let head = bytes(value.head), credential = bytes(value.credential)
    let foldHead = bytes(value.folded_head), foldCredential = bytes(value.folded_credential)
    let seq = KagemushaWalletUInt128V1(value.sequence)
    let backlog = KagemushaWalletUInt128V1(value.fold_backlog)
    let foldedSeq = KagemushaWalletUInt128V1(value.folded_sequence)
    let knownBurns = KagemushaWalletUInt128V1(value.known_burned_total)
    let foldedBurns = KagemushaWalletUInt128V1(value.folded_burned_total)
    let owned = KagemushaWalletUInt128V1(value.owned_balance)
    let folded = KagemushaWalletUInt128V1(value.folded_balance)
    let zero = KagemushaWalletUInt128V1(low: 0, high: 0)
    let hasFold = value.flags & 1 != 0, headFolded = value.flags & 2 != 0
    guard value.status == 0, value.reason == -1, value.platform_code == 0,
      let lifecycle = KagemushaWalletLifecycleV1(rawValue: value.lifecycle), value.flags <= 3,
      !headFolded || hasFold, [scheme, wallet, head, credential].allSatisfy(word)
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    if hasFold {
      guard word(foldHead), word(foldCredential), foldedSeq <= seq, foldedBurns == knownBurns
      else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    } else {
      guard foldHead.allSatisfy({ $0 == 0 }), foldCredential.allSatisfy({ $0 == 0 }),
        foldedSeq == zero, foldedBurns == zero
      else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    }
    if headFolded {
      guard foldedSeq == seq, foldHead == head, foldCredential == credential,
        backlog == zero, folded == owned
      else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    } else {
      guard folded == zero, backlog > zero, !hasFold || foldedSeq < seq
      else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    }
    self.schemeId = scheme; self.walletId = wallet; self.head = head
    self.credentialDigest = credential; self.sequence = seq; self.lifecycle = lifecycle
    self.grossBalance = KagemushaWalletUInt128V1(value.balance)
    self.coreBurnedTotal = KagemushaWalletUInt128V1(value.core_burned_total)
    self.knownBurnedTotal = knownBurns; self.ownedBalance = owned
    self.foldedBalance = headFolded ? folded : nil; self.foldBacklog = backlog
    self.verifiedFold = hasFold ? KagemushaWalletSnapshotFoldV1(
      sequence: foldedSeq, head: foldHead, credentialDigest: foldCredential,
      burnedTotal: foldedBurns) : nil
  }
}
