import Foundation
import XCTest
@testable import IrohaSwift

final class KagemushaWalletEpochSyncV1Tests: XCTestCase {
  private func progress(_ epoch: UInt64, _ first: UInt64, _ last: UInt64) throws -> KagemushaWalletEpochProgressV1 {
    let bytes = [first, last].flatMap { value in (0..<8).map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) } }
    return try .init(.init(status: 57, sequenceLow: epoch, sequenceHigh: 0, detail: 0, bytes: Data(bytes)))
  }

  func testEpochInputAndOutputAreBoundedData() throws {
    _ = try KagemushaWalletSetupInputV1(selector: 52)
    _ = try KagemushaWalletSetupInputV1(selector: 53, amount: .init(low: .max, high: 0), first: Data(repeating: 1, count: 262_144))
    for bytes in [Data(), Data(repeating: 1, count: 262_145)] {
      XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 53, first: bytes))
    }
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 53, amount: .init(low: 0, high: 1), first: Data([1])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 52, first: Data([1])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 53, identity: Data(repeating: 1, count: 32), first: Data([1])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 53, first: Data([1]), second: Data([1])))
    XCTAssertThrowsError(try KagemushaWalletSetupInputV1(selector: 53, token: 1, first: Data([1])))
    XCTAssertEqual(try progress(.max, 1, .max).boundaryHeight, .max)
    XCTAssertThrowsError(try progress(0, 0, 3))
    XCTAssertThrowsError(try progress(0, 4, 3))
    for bytes in [Data(), Data(repeating: 0, count: 15), Data(repeating: 0, count: 17)] {
      XCTAssertThrowsError(try KagemushaWalletCallV1(status: 57, sequenceLow: 0, sequenceHigh: 0, detail: 0, bytes: bytes))
    }
  }

  func testSyncUsesNativeBoundariesAndOlderReceiptsNeedNoFetch() async throws {
    var selected = try progress(0, 1, 3)
    var heights: [UInt64] = []
    let result = try await kagemushaWalletSynchronizeEpochsV1(receiptHeight: 7, maximumBoundaries: 2,
      requireCurrentOwner: {}, progress: { selected }, fetch: { height in heights.append(height); return Data([7]) },
      ingest: { epoch, bytes in
        XCTAssertEqual(epoch, selected.epoch); XCTAssertEqual(bytes, Data([7]))
        selected = try self.progress(epoch + 1, selected.boundaryHeight + 1, selected.boundaryHeight + 3)
        return selected
      })
    XCTAssertEqual(heights, [3, 6]); XCTAssertEqual(result.epoch, 2)
    _ = try await kagemushaWalletSynchronizeEpochsV1(receiptHeight: 2, maximumBoundaries: 1,
      requireCurrentOwner: {}, progress: { selected }, fetch: { _ in XCTFail("old receipt fetched history"); return Data() },
      ingest: { _, _ in XCTFail("old receipt ingested history"); return selected })
  }

  func testLimitAndOwnerLossDoNotIngestAnotherBoundary() async throws {
    enum Refused: Error { case owner }
    var selected = try progress(0, 1, 3)
    var fetched = 0
    let partial = try await kagemushaWalletSynchronizeEpochsV1(receiptHeight: 9, maximumBoundaries: 1,
        requireCurrentOwner: {}, progress: { selected }, fetch: { _ in fetched += 1; return Data([1]) },
        ingest: { _, _ in selected = try self.progress(1, 4, 6); return selected })
    XCTAssertEqual(fetched, 1); XCTAssertEqual(partial.epoch, 1)
    var ownerValid = true
    do {
      _ = try await kagemushaWalletSynchronizeEpochsV1(receiptHeight: 9, maximumBoundaries: 1,
        requireCurrentOwner: { if !ownerValid { throw Refused.owner } }, progress: { selected },
        fetch: { _ in ownerValid = false; return Data([1]) },
        ingest: { _, _ in XCTFail("owner loss ingested"); return selected })
      XCTFail("owner loss accepted")
    } catch Refused.owner {} catch { XCTFail("unexpected refusal: \(error)") }
  }

  func testStalledNativeProgressFailsClosed() async throws {
    let selected = try progress(0, 1, 3)
    do {
      _ = try await kagemushaWalletSynchronizeEpochsV1(receiptHeight: 4, maximumBoundaries: 1,
        requireCurrentOwner: {}, progress: { selected }, fetch: { _ in Data([1]) }, ingest: { _, _ in selected })
      XCTFail("stalled native progress accepted")
    } catch { XCTAssertEqual(error as? KagemushaWalletErrorV1, .invalidNativeOutput) }
  }

  func testMoreThan64EpochsResumesFromDurableProgress() async throws {
    var selected = try progress(0, 1, 3)
    var fetched = 0
    func sync() async throws -> KagemushaWalletEpochProgressV1 {
      try await kagemushaWalletSynchronizeEpochsV1(receiptHeight: 198, maximumBoundaries: 64,
        requireCurrentOwner: {}, progress: { selected },
        fetch: { height in XCTAssertEqual(height, selected.boundaryHeight); fetched += 1; return Data([1]) },
        ingest: { epoch, _ in
          selected = try self.progress(epoch + 1, selected.boundaryHeight + 1, selected.boundaryHeight + 3)
          return selected
        })
    }
    let first = try await sync()
    XCTAssertEqual(first.epoch, 64); XCTAssertEqual(fetched, 64); XCTAssertEqual(first.boundaryHeight, 195)
    let second = try await sync()
    XCTAssertEqual(second.epoch, 65); XCTAssertEqual(fetched, 65); XCTAssertEqual(second.boundaryHeight, 198)
  }
}
