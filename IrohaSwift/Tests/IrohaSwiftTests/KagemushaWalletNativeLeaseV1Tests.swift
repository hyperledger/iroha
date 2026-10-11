import Foundation
import XCTest
@testable import IrohaSwift

/// Cleanup transport fault fixtures only. No Native wallet admission, trusted artifact,
/// proof, account key, balance or monetary success is constructed by these tests.
/// Wrapper-deinit tests resolve the real Native symbols; their synthetic IDs exercise
/// only the test-owned close transport, never Native admission or financial authority.
final class KagemushaWalletNativeLeaseV1Tests: XCTestCase {
  private final class PlatformLifetime {}
  private final class CloseDriver: KagemushaWalletNativeCloseDriverV1, @unchecked Sendable {
    private let lock = NSLock()
    private var statuses: [Int32]
    private var recorded: [UInt64] = []
    init(_ statuses: [Int32]) { self.statuses = statuses }
    func closeNativeLease(_ owner: UInt64) -> Int32 {
      lock.lock(); defer { lock.unlock() }
      recorded.append(owner)
      return statuses.isEmpty ? 0 : statuses.removeFirst()
    }
    var ids: [UInt64] { lock.lock(); defer { lock.unlock() }; return recorded }
  }
  private actor CancellationGate {
    private var released = false
    private var continuation: CheckedContinuation<Void, Never>?
    func wait() async {
      if released { return }
      await withCheckedContinuation { continuation = $0 }
    }
    func release() {
      released = true; continuation?.resume(); continuation = nil
    }
  }
  private func blockedCleanup(file: StaticString = #filePath, line: UInt = #line) -> KagemushaWalletAdmissionCleanupErrorV1? {
    do {
      try KagemushaWalletInstalledRuntimeV1.requireNoUnreleasedAdmissions()
      XCTFail("Replacement admission must remain blocked", file: file, line: line); return nil
    } catch {
      let failure = error as? KagemushaWalletAdmissionCleanupErrorV1
      XCTAssertNotNil(failure, file: file, line: line); return failure
    }
  }
  override func setUpWithError() throws {
    try KagemushaWalletInstalledRuntimeV1.requireNoUnreleasedAdmissions()
  }
  func testProviderFailureRetriesSameIDAndRetainsPlatformUntilActualZero() throws {
    let driver = CloseDriver([-5, 0])
    var platform: PlatformLifetime? = .init()
    weak var retainedPlatform = platform
    let lease = KagemushaWalletNativeLeaseV1(owner: 71, driver: driver, platformOwner: platform!)
    platform = nil
    defer { try? lease.close(); try? KagemushaWalletInstalledRuntimeV1.requireNoUnreleasedAdmissions() }
    XCTAssertEqual(try lease.handle(), 71)
    XCTAssertThrowsError(try lease.close())
    XCTAssertEqual(driver.ids, [71]); XCTAssertFalse(lease.isReleased); XCTAssertNotNil(retainedPlatform)
    XCTAssertThrowsError(try lease.handle())
    let failure = try XCTUnwrap(blockedCleanup())
    XCTAssertFalse(failure.resourceReleased)
    try failure.retryCleanup()
    XCTAssertEqual(driver.ids, [71, 71]); XCTAssertTrue(lease.isReleased); XCTAssertNil(retainedPlatform)
    XCTAssertThrowsError(try lease.handle())
    XCTAssertNoThrow(try KagemushaWalletInstalledRuntimeV1.requireNoUnreleasedAdmissions())
    try lease.close(); XCTAssertEqual(driver.ids, [71, 71])
  }
  func testEveryNonzeroStatusIncludingNoOwnerIsNotAReleaseAcknowledgement() throws {
    for status in [Int32(-1), -2, -4, -5] {
      let driver = CloseDriver([status, 0])
      var platform: PlatformLifetime? = .init()
      weak var retainedPlatform = platform
      let lease = KagemushaWalletNativeLeaseV1(owner: 81, driver: driver, platformOwner: platform!)
      platform = nil
      defer { try? lease.close(); try? KagemushaWalletInstalledRuntimeV1.requireNoUnreleasedAdmissions() }
      XCTAssertThrowsError(try lease.close())
      XCTAssertFalse(lease.isReleased); XCTAssertNotNil(retainedPlatform)
      let failure = try XCTUnwrap(blockedCleanup())
      if status == -2 { XCTAssertEqual(failure.cleanup as? KagemushaWalletErrorV1, .closed) }
      try failure.retryCleanup()
      XCTAssertEqual(driver.ids, [81, 81]); XCTAssertTrue(lease.isReleased); XCTAssertNil(retainedPlatform)
      try KagemushaWalletInstalledRuntimeV1.requireNoUnreleasedAdmissions()
    }
  }
  func testFailedCloseDuringRuntimeDeinitQuarantinesLeaseWithoutRetainingDyingRuntime() throws {
    let driver = CloseDriver([-5, 0])
    var platform: PlatformLifetime? = .init()
    weak var retainedPlatform = platform
    var runtime: KagemushaWalletRuntimeV1? = try .init(nativeRuntimeHandle: 91,
      driver: KagemushaWalletNativeDriverV1(), platformOwner: platform!, cleanupDriver: driver)
    weak var retainedLease = runtime?.cleanupLease
    weak var dyingRuntime = runtime
    platform = nil; runtime = nil
    XCTAssertNil(dyingRuntime)
    XCTAssertEqual(driver.ids, [91]); XCTAssertNotNil(retainedLease); XCTAssertNotNil(retainedPlatform)
    let failure = try XCTUnwrap(blockedCleanup())
    defer { try? failure.retryCleanup(); try? KagemushaWalletInstalledRuntimeV1.requireNoUnreleasedAdmissions() }
    try failure.retryCleanup()
    XCTAssertEqual(driver.ids, [91, 91]); XCTAssertNil(retainedPlatform)
    try KagemushaWalletInstalledRuntimeV1.requireNoUnreleasedAdmissions()
    // The error still owns the released lease, but none of its platform custody.
    XCTAssertTrue(failure.resourceReleased); XCTAssertNotNil(retainedLease)
  }
  func testFailedCloseDuringWalletDeinitQuarantinesLeaseWithoutRetainingDyingWallet() throws {
    let driver = CloseDriver([-5, 0])
    var platform: PlatformLifetime? = .init()
    weak var retainedPlatform = platform
    var lease: KagemushaWalletNativeLeaseV1? = .init(owner: 92, driver: driver, platformOwner: platform!)
    weak var retainedLease = lease
    // Only destruction is exercised. Actual Native admission/financial calls are not mocked.
    var wallet: KagemushaWalletV1? = .init(lease: lease!, driver: try KagemushaWalletNativeDriverV1())
    weak var dyingWallet = wallet
    platform = nil; lease = nil; wallet = nil
    XCTAssertNil(dyingWallet)
    XCTAssertEqual(driver.ids, [92]); XCTAssertNotNil(retainedLease); XCTAssertNotNil(retainedPlatform)
    let failure = try XCTUnwrap(blockedCleanup())
    defer { try? failure.retryCleanup(); try? KagemushaWalletInstalledRuntimeV1.requireNoUnreleasedAdmissions() }
    try failure.retryCleanup()
    XCTAssertEqual(driver.ids, [92, 92]); XCTAssertNil(retainedPlatform)
    try KagemushaWalletInstalledRuntimeV1.requireNoUnreleasedAdmissions()
    XCTAssertTrue(failure.resourceReleased)
  }
  func testSuccessfulRuntimeDeinitJoinsOnceAndReleasesPlatform() throws {
    let driver = CloseDriver([0])
    var platform: PlatformLifetime? = .init()
    weak var retainedPlatform = platform
    var runtime: KagemushaWalletRuntimeV1? = try .init(nativeRuntimeHandle: 101,
      driver: KagemushaWalletNativeDriverV1(), platformOwner: platform!, cleanupDriver: driver)
    weak var dyingRuntime = runtime
    platform = nil; runtime = nil
    XCTAssertNil(dyingRuntime); XCTAssertNil(retainedPlatform); XCTAssertEqual(driver.ids, [101])
    try KagemushaWalletInstalledRuntimeV1.requireNoUnreleasedAdmissions()
  }
  func testRuntimeAdoptsExactExistingLeaseAndReleasesItsPlatform() throws {
    let driver = CloseDriver([0])
    var platform: PlatformLifetime? = .init()
    weak var retainedPlatform = platform
    let lease = KagemushaWalletNativeLeaseV1(owner: 102, driver: driver, platformOwner: platform!)
    let runtime = KagemushaWalletRuntimeV1(lease: lease, driver: try KagemushaWalletNativeDriverV1())
    platform = nil
    XCTAssertTrue(runtime.cleanupLease === lease)
    XCTAssertNotNil(retainedPlatform)
    try runtime.close()
    XCTAssertEqual(driver.ids, [102])
    XCTAssertTrue(lease.isReleased)
    XCTAssertNil(retainedPlatform)
    try runtime.close()
    XCTAssertEqual(driver.ids, [102])
  }
  func testCancellationCleanupProviderFailureKeepsPlatformUntilSameIDRetryZero() async throws {
    let driver = CloseDriver([-5, 0])
    var platform: PlatformLifetime? = .init()
    weak var retainedPlatform = platform
    let lease = KagemushaWalletNativeLeaseV1(owner: 111, driver: driver, platformOwner: platform!)
    platform = nil
    defer { try? lease.close(); try? KagemushaWalletInstalledRuntimeV1.requireNoUnreleasedAdmissions() }
    let started = expectation(description: "Cancellation handler registered")
    let gate = CancellationGate()
    let operation = Task {
      await withTaskCancellationHandler(operation: {
        started.fulfill(); await gate.wait()
      }, onCancel: { try? lease.close() })
    }
    await fulfillment(of: [started], timeout: 2)
    operation.cancel()
    await gate.release(); await operation.value
    XCTAssertEqual(driver.ids, [111]); XCTAssertFalse(lease.isReleased); XCTAssertNotNil(retainedPlatform)
    XCTAssertThrowsError(try lease.handle())
    let failure = try XCTUnwrap(blockedCleanup())
    try failure.retryCleanup()
    XCTAssertEqual(driver.ids, [111, 111]); XCTAssertTrue(lease.isReleased); XCTAssertNil(retainedPlatform)
    try KagemushaWalletInstalledRuntimeV1.requireNoUnreleasedAdmissions()
  }
}
