import Foundation
import XCTest
@testable import IrohaSwift

/// Exact owned DATA only; no Native owner, artifact trust or financial verdict is simulated.
final class KagemushaWalletInstalledRuntimeV1Tests: XCTestCase {
  func testRelocationCallsActualNativeAndRefusesMalformedOriginalData() throws {
    XCTAssertThrowsError(try KagemushaWalletRuntimeOriginalsV1.relocateRegistrationSource(Data([1]), to: "/private")) { error in
      XCTAssertEqual(error as? KagemushaWalletErrorV1, .native(status: -1, reason: -1, platformCode: 0))
    }
  }
  func testRelocationBoundsRejectBeforeNativeLoading() {
    for source in [Data(), Data(repeating: 0, count: 8193)] {
      XCTAssertThrowsError(try KagemushaWalletRuntimeOriginalsV1.relocateRegistrationSource(source, to: "/private"))
    }
    for root in ["", "relative", "/nul\0root", "/" + String(repeating: "x", count: 4096)] {
      XCTAssertThrowsError(try KagemushaWalletRuntimeOriginalsV1.relocateRegistrationSource(Data([1]), to: root))
    }
  }
  private func runtime(_ inputs: [Data] = Array(repeating: Data([7]), count: 6), root: String = "/selected/originals", registration: Data = Data()) throws -> KagemushaWalletRuntimeOriginalsV1 {
    try .init(appManifest: inputs[0], envelope: inputs[1], walletRuntime: inputs[2], verifierPack: inputs[3], producerInventory: inputs[4], signedGenesis: inputs[5], originalsRoot: root, registrationSource: registration)
  }
  func testRegistrationSourceIsBoundedOwnedDataWithNoAdmissionVerdict() throws {
    var source = Data(repeating: 7, count: 8192)
    let original = try runtime(registration: source)
    source[0] = 0
    XCTAssertEqual(original.originals[7], Data(repeating: 7, count: 8192))
    XCTAssertThrowsError(try runtime(registration: Data(repeating: 1, count: 8193)))
    XCTAssertEqual(try runtime().originals[7], Data())
  }
  func testOriginalsOwnTheirBytesAcrossSourceAndAccessorMutation() throws {
    var bytes = Data([7, 8])
    let r = try runtime(Array(repeating: bytes, count: 6))
    let e = try KagemushaWalletOpenOriginalsV1(credential: bytes, enrollmentCertificates: bytes, account: bytes, assetScope: bytes)
    bytes[0] = 0
    var returned = r.originals[0]; returned[1] = 0
    XCTAssertEqual(r.originals[0], Data([7, 8])); XCTAssertEqual(e.originals[0], Data([7, 8]))
  }
  func testFinancialOriginalsAreWhollyPresentOrAbsentBeforeNativeAuthentication() {
    for offered in 0..<8 {
      let inputs = [Data([1]), Data([2]), Data([3]),
        offered & 1 == 0 ? Data() : Data([4]),
        offered & 2 == 0 ? Data() : Data([5]), Data([6])]
      let root = offered & 4 == 0 ? "" : "/selected/originals"
      if offered == 0 || offered == 7 { XCTAssertNoThrow(try runtime(inputs, root: root)) }
      else { XCTAssertThrowsError(try runtime(inputs, root: root)) }
    }
  }
  func testEveryInstallationOriginalIsRequired() {
    for index in 0..<6 {
      var originals = Array(repeating: Data([7]), count: 6); originals[index] = Data()
      XCTAssertThrowsError(try runtime(originals))
    }
  }
  func testAllRuntimeFieldsAreBoundedBeforeNativeCopy() {
    for (index, cap) in [8_388_608, 2048, 131_072, 16_842_752, 16_777_216, 67_108_864].enumerated() {
      var inputs = Array(repeating: Data([7]), count: 6); inputs[index] = Data(repeating: 0, count: cap + 1)
      XCTAssertThrowsError(try runtime(inputs))
    }
  }
  func testRootIsAbsoluteNULFreeAndUTF8Bounded() throws {
    for value in ["", "relative", "/x\0y", "/" + String(repeating: "é", count: 2048)] { XCTAssertThrowsError(try runtime(root: value)) }
    XCTAssertEqual(try runtime(root: "/" + String(repeating: "x", count: 4095)).originals[6].count, 4096)
    XCTAssertEqual(try runtime(root: "/検証").originals[6], Data("/検証".utf8))
  }
  func testEveryEnrollmentOriginalIsRequiredAndIndependentlyFinite() {
    for (index, cap) in [1024, 10_000, 4096, 1024].enumerated() {
      for bad in [Data(), Data(repeating: 0, count: cap + 1)] {
        var inputs = Array(repeating: Data([7]), count: 4); inputs[index] = bad
        XCTAssertThrowsError(try KagemushaWalletOpenOriginalsV1(credential: inputs[0], enrollmentCertificates: inputs[1], account: inputs[2], assetScope: inputs[3]))
      }
    }
  }

  func testOrdinaryFailureRetainsExactOriginalFramesAndRejectsConcurrentOrChangedRetry() throws {
    let admission=KagemushaWalletInstalledAdmissionV1()
    var frames=(0..<4).map { Data([UInt8($0), 7]) }
    try admission.start(frames)
    XCTAssertThrowsError(try admission.start(frames))
    frames[0][0]=99
    admission.failed()
    XCTAssertThrowsError(try admission.start(frames))
    let exact=(0..<4).map { Data([UInt8($0), 7]) }
    try admission.start(exact)
    admission.failed()
    try admission.start(exact)
    try admission.completed()
    admission.failed()
    XCTAssertThrowsError(try admission.start(exact))
  }
  func testPersistedResultRetryCannotSwitchAccountOrIntakeRepresentation() throws {
    let admission = KagemushaWalletInstalledAdmissionV1()
    let frames = [Data([1, 2, 3]), Data([4, 5])]
    try admission.start(frames)
    admission.failed()
    XCTAssertFalse(admission.canTransferToEnrollment)
    XCTAssertThrowsError(try admission.start([frames[0], Data([4, 6])]))
    XCTAssertThrowsError(try admission.start(frames + [Data([7]), Data([8])]))
    try admission.start(frames)
    try admission.completed()
    XCTAssertThrowsError(try admission.start(frames))
  }
  func testSignatureOriginalIsBoundedFrozenAndRetainedAcrossOrdinaryFailure() throws {
    let admission=KagemushaWalletInstalledAdmissionV1()
    let frames=Array(repeating: Data([7]), count: 4)
    try admission.start(frames)
    for count in [0, 63, 65] { XCTAssertThrowsError(try admission.retainSignature(Data(repeating: 9, count: count))) }
    var offered=Data(repeating: 9, count: 64)
    var delivered=try admission.retainSignature(offered)
    offered[0]=1; delivered[1]=2
    admission.failed()
    XCTAssertEqual(admission.signatureOriginal, Data(repeating: 9, count: 64))
    try admission.start(frames)
    XCTAssertThrowsError(try admission.retainSignature(offered))
    XCTAssertEqual(try admission.retainSignature(Data(repeating: 9, count: 64)), Data(repeating: 9, count: 64))
    try admission.completed()
    XCTAssertNil(admission.signatureOriginal)
    XCTAssertThrowsError(try admission.retainSignature(Data(repeating: 9, count: 64)))
  }
  func testProducerCancellationErrorDoesNotCancelTheTask() async throws {
    let admission=KagemushaWalletInstalledAdmissionV1()
    let frames=Array(repeating: Data([7]), count: 4)
    try admission.start(frames)
    do { throw CancellationError() }
    catch { XCTAssertFalse(Task.isCancelled); XCTAssertTrue(error is CancellationError) }
    admission.failed()
    try admission.start(frames)
    try admission.completed()
  }
  func testExplicitTaskCancellationIsIndependentOfThrownErrorType() async {
    // Gate DATA only, never a fake Native owner or admission. Cancel before releasing the continuation.
    let gate=InstalledRetryTaskGate()
    let task=Task { await gate.wait(); return Task.isCancelled }
    await gate.untilWaiting()
    task.cancel()
    await gate.release()
    let cancelled=await task.value
    XCTAssertTrue(cancelled)
  }
}

/// Test scheduling only; no platform callbacks, Native owner, authentication or cleanup acknowledgement.
private actor InstalledRetryTaskGate {
  private var continuation: CheckedContinuation<Void, Never>?
  private var observers: [CheckedContinuation<Void, Never>]=[]
  func wait() async {
    await withCheckedContinuation { value in
      continuation=value
      for observer in observers { observer.resume() }
      observers.removeAll()
    }
  }
  func untilWaiting() async {
    if continuation != nil { return }
    await withCheckedContinuation { observers.append($0) }
  }
  func release() { continuation?.resume(); continuation=nil }
}
