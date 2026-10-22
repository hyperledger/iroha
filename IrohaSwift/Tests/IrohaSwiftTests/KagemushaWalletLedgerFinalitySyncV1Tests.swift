import Foundation
import XCTest
@testable import IrohaSwift

/// Scheduling of one direct-finality confirmation pass. The callbacks stand in for the installed
/// Native wallet and Torii; they never construct an outcome Native did not return.
final class KagemushaWalletLedgerFinalitySyncV1Tests: XCTestCase {
  private let entrypoint = Data(repeating: 0x0f, count: 32)
  private let commit = KagemushaWalletLedgerCommitV1(height: 7, commitHash: Data(repeating: 9, count: 32))

  private final class Counts {
    var outcomes = 0, fetches = 0, ingests = 0, syncs = 0
    var fetched: [Data] = []
    var ingested: [Data] = []
  }

  private func confirm(
    _ counts: Counts,
    retained: KagemushaWalletLedgerOutcomeV1,
    read: KagemushaWalletLedgerReadV1,
    ingest: [KagemushaWalletLedgerIngestV1],
    synchronize: (covered: Bool, selected: Bool) = (true, true),
    requireCurrentOwner: () async throws -> Void = {}
  ) async throws -> KagemushaWalletLedgerConfirmationV1 {
    var replies = ingest
    return try await kagemushaWalletConfirmLedgerAttemptV1(
      requireCurrentOwner: requireCurrentOwner,
      outcome: { counts.outcomes += 1; return retained },
      fetch: { entrypoint in counts.fetches += 1; counts.fetched.append(entrypoint); return read },
      ingest: { bytes in
        counts.ingests += 1; counts.ingested.append(bytes)
        guard !replies.isEmpty else { throw KagemushaWalletErrorV1.invalidNativeOutput }
        return replies.removeFirst()
      },
      synchronize: { _, target in
        counts.syncs += 1
        XCTAssertEqual(target, 3_601)
        return synchronize
      })
  }

  func testRetainedOutcomeNeedsNoNetworkAndIsNotAnAdvance() async throws {
    for retained in [KagemushaWalletLedgerOutcomeV1.confirmed(commit), .rejected(commit)] {
      let counts = Counts()
      let result = try await confirm(counts, retained: retained, read: .original(Data([1])), ingest: [])
      XCTAssertEqual(result, .init(outcome: retained, advanced: false))
      XCTAssertEqual([counts.outcomes, counts.fetches, counts.ingests, counts.syncs], [1, 0, 0, 0])
    }
  }

  func testAwaitingMakesOneReadByNativeEntrypointAndOneIngest() async throws {
    let counts = Counts()
    let result = try await confirm(counts, retained: .awaiting(entrypoint: entrypoint),
      read: .original(Data([1, 2])), ingest: [.outcome(.confirmed(commit))])
    XCTAssertEqual(result, .init(outcome: .confirmed(commit), advanced: true))
    XCTAssertEqual([counts.outcomes, counts.fetches, counts.ingests, counts.syncs], [1, 1, 1, 0])
    XCTAssertEqual(counts.fetched, [entrypoint])
    XCTAssertEqual(counts.ingested, [Data([1, 2])])
    let rejected = Counts()
    let refused = try await confirm(rejected, retained: .awaiting(entrypoint: entrypoint),
      read: .original(Data([3])), ingest: [.outcome(.rejected(commit))])
    XCTAssertEqual(refused, .init(outcome: .rejected(commit), advanced: true))
  }

  func testTypedWaitsReturnAwaitingWithoutIngest() async throws {
    for read in [KagemushaWalletLedgerReadV1.notCommitted, .unavailable] {
      let counts = Counts()
      let result = try await confirm(counts, retained: .awaiting(entrypoint: entrypoint), read: read, ingest: [])
      XCTAssertEqual(result, .init(outcome: .awaiting(entrypoint: entrypoint), advanced: false))
      XCTAssertEqual([counts.fetches, counts.ingests, counts.syncs], [1, 0, 0])
    }
  }

  func testEpochRequiredSynchronizesThenReingestsTheSameOriginalOnce() async throws {
    let counts = Counts()
    let result = try await confirm(counts, retained: .awaiting(entrypoint: entrypoint),
      read: .original(Data([5])), ingest: [.epochRequired(targetHeight: 3_601), .outcome(.confirmed(commit))])
    XCTAssertEqual(result, .init(outcome: .confirmed(commit), advanced: true))
    XCTAssertEqual([counts.fetches, counts.ingests, counts.syncs], [1, 2, 1])
    XCTAssertEqual(counts.ingested, [Data([5]), Data([5])])
    // A second EpochRequired after covering synchronization is invalid Native output.
    let twice = Counts()
    do {
      _ = try await confirm(twice, retained: .awaiting(entrypoint: entrypoint), read: .original(Data([5])),
        ingest: [.epochRequired(targetHeight: 3_601), .epochRequired(targetHeight: 3_601)])
      XCTFail("a repeated epoch requirement was accepted")
    } catch { XCTAssertEqual(error as? KagemushaWalletErrorV1, .invalidNativeOutput) }
  }

  func testUncoveredEpochIsAwaitingAndReportsOnlySelectedBoundaries() async throws {
    for selected in [false, true] {
      let counts = Counts()
      let result = try await confirm(counts, retained: .awaiting(entrypoint: entrypoint),
        read: .original(Data([5])), ingest: [.epochRequired(targetHeight: 3_601)],
        synchronize: (false, selected))
      XCTAssertEqual(result, .init(outcome: .awaiting(entrypoint: entrypoint), advanced: selected))
      XCTAssertEqual([counts.ingests, counts.syncs], [1, 1])
    }
  }

  func testOwnerLossAndCancellationStopBeforeIngest() async throws {
    enum Changed: Error { case owner }
    var checks = 0
    let counts = Counts()
    do {
      _ = try await confirm(counts, retained: .awaiting(entrypoint: entrypoint), read: .original(Data([1])),
        ingest: [.outcome(.confirmed(commit))], requireCurrentOwner: {
          checks += 1
          if checks == 2 { throw Changed.owner }
        })
      XCTFail("owner loss after the read ingested")
    } catch Changed.owner {}
    XCTAssertEqual([counts.fetches, counts.ingests], [1, 0])
    // Cancellation is a pause: it propagates before any read and is never an outcome.
    let cancelled = Counts()
    do {
      _ = try await confirm(cancelled, retained: .awaiting(entrypoint: entrypoint), read: .original(Data([1])),
        ingest: [.outcome(.confirmed(commit))], requireCurrentOwner: { throw CancellationError() })
      XCTFail("cancelled pass completed")
    } catch is CancellationError {}
    XCTAssertEqual([cancelled.outcomes, cancelled.fetches, cancelled.ingests], [0, 0, 0])
  }

  func testNativeOutcomeErrorsPropagateAndNeverBecomeVerdicts() async throws {
    let counts = Counts()
    do {
      _ = try await kagemushaWalletConfirmLedgerAttemptV1(
        requireCurrentOwner: {},
        outcome: { throw KagemushaWalletErrorV1.native(status: -9, reason: -1, platformCode: 0) },
        fetch: { _ in counts.fetches += 1; return .notCommitted },
        ingest: { _ in counts.ingests += 1; return .outcome(.confirmed(self.commit)) },
        synchronize: { _, _ in (true, true) })
      XCTFail("a Native refusal became an outcome")
    } catch { XCTAssertEqual(error as? KagemushaWalletErrorV1, .native(status: -9, reason: -1, platformCode: 0)) }
    XCTAssertEqual([counts.fetches, counts.ingests], [0, 0])
  }
}
