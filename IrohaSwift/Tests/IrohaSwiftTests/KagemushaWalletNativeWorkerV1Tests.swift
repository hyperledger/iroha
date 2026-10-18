import Foundation
#if canImport(Darwin)
import Darwin
#endif
import XCTest
@testable import IrohaSwift

/// Scheduling and ownership tests only; these closures do not represent payment proofs.
final class KagemushaWalletNativeWorkerV1Tests: XCTestCase {
  private final class State<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: T
    init(_ value: T) { storage = value }
    func update<R>(_ body: (inout T) -> R) -> R {
      lock.lock(); defer { lock.unlock() }
      return body(&storage)
    }
    var value: T { update { $0 } }
  }

  #if canImport(Darwin)
  func testSmallCallerGetsOwnedEightMiBStack() throws {
    let result = State<Result<(Int, Int, Bool), Error>?>(nil)
    let done = expectation(description: "small caller returned")
    let caller = Thread {
      let callerThread = pthread_self()
      let callerStack = pthread_get_stacksize_np(callerThread)
      let value = Result {
        try KagemushaWalletNativeWorkerV1.perform {
          (callerStack, pthread_get_stacksize_np(pthread_self()),
            pthread_equal(callerThread, pthread_self()) != 0)
        }
      }
      result.update { $0 = value }
      done.fulfill()
    }
    caller.stackSize = 544 * 1024
    caller.start()
    wait(for: [done], timeout: 5)
    let (callerStack, workerStack, reusedCaller) = try XCTUnwrap(result.value).get()
    XCTAssertLessThan(callerStack, KagemushaWalletNativeWorkerV1.stackBytes)
    XCTAssertGreaterThanOrEqual(workerStack, KagemushaWalletNativeWorkerV1.stackBytes)
    XCTAssertFalse(reusedCaller)
  }
  #endif

  func testNestedWorkerAndWorkClassesExecuteInlineWithoutPermitDeadlock() throws {
    let worker = KagemushaWalletNativeWorkerV1(maximumConcurrentCalls: 1)
    let done = expectation(description: "nested worker returned")
    let result = State<Result<Bool, Error>?>(nil)
    DispatchQueue.global().async {
      let value = Result {
        try worker.run {
          let outer = Thread.current
          return try worker.run {
            try KagemushaWalletNativeWorkerV1.perform(workClass: .folding) {
              Thread.current === outer
            }
          }
        }
      }
      result.update { $0 = value }
      done.fulfill()
    }
    wait(for: [done], timeout: 5)
    XCTAssertTrue(try XCTUnwrap(result.value).get())
  }

  func testBlockedFoldAndNonPreemptingWaitersKeepForegroundCapacityAvailable() throws {
    let foldingEntered = DispatchSemaphore(value: 0)
    let releaseFold = DispatchSemaphore(value: 0)
    let foldDone = expectation(description: "fold joined")
    foldDone.expectedFulfillmentCount = 3
    let foregroundDone = expectation(description: "foreground bypassed fold")
    let failures = State<[Error]>([])
    DispatchQueue.global().async {
      do {
        try KagemushaWalletNativeWorkerV1.perform(workClass: .folding) {
          foldingEntered.signal()
          releaseFold.wait()
        }
      } catch { failures.update { $0.append(error) } }
      foldDone.fulfill()
    }
    XCTAssertEqual(foldingEntered.wait(timeout: .now() + 5), .success)
    // Snapshot and collection use this same non-preempting lane. Queued callers must not
    // occupy the foreground permits that a payment needs to cancel a native fold.
    let waitersQueued = DispatchSemaphore(value: 0)
    for _ in 0..<2 {
      DispatchQueue.global().async {
        waitersQueued.signal()
        do {
          try KagemushaWalletNativeWorkerV1.perform(workClass: .folding) { releaseFold.wait() }
        } catch { failures.update { $0.append(error) } }
        foldDone.fulfill()
      }
    }
    XCTAssertEqual(waitersQueued.wait(timeout: .now() + 5), .success)
    XCTAssertEqual(waitersQueued.wait(timeout: .now() + 5), .success)
    DispatchQueue.global().async {
      do { try KagemushaWalletNativeWorkerV1.perform {} }
      catch { failures.update { $0.append(error) } }
      foregroundDone.fulfill()
    }
    wait(for: [foregroundDone], timeout: 5)
    releaseFold.signal(); releaseFold.signal(); releaseFold.signal()
    wait(for: [foldDone], timeout: 5)
    XCTAssertTrue(failures.value.isEmpty)
  }

  func testConcurrencyIsBoundedUntilPriorWorkersJoin() {
    let worker = KagemushaWalletNativeWorkerV1(maximumConcurrentCalls: 2)
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    let done = expectation(description: "all callers joined")
    done.expectedFulfillmentCount = 3
    let counts = State((active: 0, maximum: 0))
    let failures = State<[Error]>([])
    for _ in 0..<3 {
      DispatchQueue.global().async {
        do {
          try worker.run {
            counts.update { value in
              value.active += 1
              value.maximum = max(value.maximum, value.active)
            }
            entered.signal()
            release.wait()
            counts.update { $0.active -= 1 }
          }
        } catch { failures.update { $0.append(error) } }
        done.fulfill()
      }
    }
    XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)
    XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)
    XCTAssertEqual(entered.wait(timeout: .now() + 0.05), .timedOut)
    release.signal()
    XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)
    release.signal(); release.signal()
    wait(for: [done], timeout: 5)
    XCTAssertEqual(counts.value.maximum, 2)
    XCTAssertEqual(counts.value.active, 0)
    XCTAssertTrue(failures.value.isEmpty)
  }

  func testBorrowedBufferAndCleanupFinishBeforeReturn() throws {
    var bytes = [UInt8](repeating: 0, count: 32)
    var cleanupFinished = false
    let returned = try bytes.withUnsafeMutableBufferPointer { buffer in
      try KagemushaWalletNativeWorkerV1.perform {
        defer { cleanupFinished = true }
        for index in buffer.indices { buffer[index] = UInt8(index) }
        return Array(buffer)
      }
    }
    XCTAssertTrue(cleanupFinished)
    XCTAssertEqual(returned, Array(UInt8(0)..<32))
    XCTAssertEqual(bytes, returned)
  }

  func testThrownErrorIdentityAndCleanupArePreserved() throws {
    final class Failure: Error {}
    let failure = Failure()
    var cleanupFinished = false
    XCTAssertThrowsError(try KagemushaWalletNativeWorkerV1.perform {
      defer { cleanupFinished = true }
      throw failure
    }) { error in
      XCTAssertTrue(error as AnyObject === failure)
      XCTAssertTrue(cleanupFinished)
    }
    XCTAssertEqual(try KagemushaWalletNativeWorkerV1.perform { 17 }, 17)
  }

  func testInvalidStackFailsLocallyWithoutExecutingOperationOrLeakingPermit() {
    let worker = KagemushaWalletNativeWorkerV1(maximumConcurrentCalls: 1, stackBytes: 1)
    var executed = false
    for _ in 0..<2 {
      XCTAssertThrowsError(try worker.run { executed = true }) { error in
        XCTAssertEqual((error as? KagemushaWalletNativeWorkerErrorV1)?.code, EINVAL)
      }
    }
    XCTAssertFalse(executed)
  }
}
