import Foundation
import NoritoBridge
import XCTest
@testable import IrohaSwift

/// Typed ABI projections only; no Native monetary proof or device qualification is implied.
final class KagemushaWalletSnapshotV1Tests: XCTestCase {
  private func output(flags: UInt32 = 0, retiring: Bool = false) -> connect_norito_kagemusha_wallet_snapshot_v1_t {
    var out = connect_norito_kagemusha_wallet_snapshot_v1_t()
    out.status = 0; out.reason = -1; out.lifecycle = retiring ? 2 : 1; out.flags = flags
    func fill<T>(_ target: inout T, _ byte: UInt8) {
      withUnsafeMutableBytes(of: &target) { $0.initializeMemory(as: UInt8.self, repeating: byte) }
    }
    fill(&out.scheme, 1); fill(&out.wallet, 2); fill(&out.head, 3); fill(&out.credential, 4)
    out.balance.low = 20; out.owned_balance.low = 20; out.fold_backlog.low = 1
    if flags & 1 != 0 { fill(&out.folded_head, 3); fill(&out.folded_credential, 4) }
    if flags & 2 != 0 { out.folded_balance.low = 20; out.fold_backlog.low = 0 }
    return out
  }
  func testOwnedUnfoldedValueAndFoldedZeroRemainDistinct() throws {
    let unfolded = try KagemushaWalletSnapshotV1(output())
    XCTAssertEqual(unfolded.ownedBalance, .init(low: 20, high: 0))
    XCTAssertFalse(unfolded.headIsFolded); XCTAssertNil(unfolded.foldedBalance)
    XCTAssertEqual(unfolded.foldBacklog, .init(low: 1, high: 0))
    var native = output(flags: 3)
    native.balance.low = 0; native.owned_balance.low = 0; native.folded_balance.low = 0
    let folded = try KagemushaWalletSnapshotV1(native)
    XCTAssertTrue(folded.headIsFolded)
    XCTAssertEqual(folded.foldedBalance, .init(low: 0, high: 0))
  }
  func testRetiringDoesNotHideFoldedRemainingValueAndAll128BitsArePreserved() throws {
    var native = output(flags: 3, retiring: true)
    native.balance.low = UInt64.max; native.balance.high = UInt64.max
    native.owned_balance = native.balance; native.folded_balance = native.balance
    let value = try KagemushaWalletSnapshotV1(native)
    XCTAssertEqual(value.lifecycle, .retiring)
    XCTAssertEqual(value.foldedBalance, .init(low: UInt64.max, high: UInt64.max))
    XCTAssertLessThan(KagemushaWalletUInt128V1(low: UInt64.max, high: 0),
      KagemushaWalletUInt128V1(low: 0, high: 1))
  }
  func testAncestorFoldKeepsItsOwnCredentialAndCannotLookLikeCurrentHeadProof() throws {
    var native = output(flags: 1)
    native.sequence.low = 1
    withUnsafeMutableBytes(of: &native.folded_credential) { $0.initializeMemory(as: UInt8.self, repeating: 5) }
    let value = try KagemushaWalletSnapshotV1(native)
    XCTAssertFalse(value.headIsFolded); XCTAssertNil(value.foldedBalance)
    XCTAssertEqual(value.verifiedFold?.credentialDigest, Data(repeating: 5, count: 32))
    native.flags = 3; native.fold_backlog.low = 0; native.folded_balance.low = 20
    XCTAssertThrowsError(try KagemushaWalletSnapshotV1(native))
  }
  func testMalformedSourceSelectionTagsCannotProjectAnEmptyOrSpendableWallet() {
    for field in 0..<7 {
      var native = output(flags: 3)
      switch field {
      case 0: native.status = -5
      case 1: native.flags = 2
      case 2: native.lifecycle = 0
      case 3: native.head = connect_norito_kagemusha_wallet_snapshot_v1_t().head
      case 4: native.fold_backlog.low = 1
      case 5: native.folded_sequence.low = 1
      default: native.folded_balance.low = 19
      }
      XCTAssertThrowsError(try KagemushaWalletSnapshotV1(native))
    }
    var absent = output(); absent.folded_burned_total.low = 1
    XCTAssertThrowsError(try KagemushaWalletSnapshotV1(absent))
  }
}
