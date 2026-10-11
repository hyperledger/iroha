import Foundation
import NoritoBridge

/// Whole bounded DATA. Only Native compiled trust authenticates the installation.
/// Registration source is bounded DATA, required by generic release and empty for fixed adapters.
/// Native authenticates successful Global registration before any platform owner is acquired.
/// Four signed base originals are mandatory; financial originals are wholly present or absent.
/// Native authenticates an absent financial selection before reporting artifacts unavailable.
public struct KagemushaWalletRuntimeOriginalsV1: Sendable, CustomStringConvertible {
  public var description: String { "KagemushaWalletRuntimeOriginalsV1(originals=[REDACTED])" }
  let originals: [Data]
  /// After copying the exact package originals into private device storage, rebind only its
  /// platform-specific locator path. This copies no files and reports no proof or admission.
  public static func relocateRegistrationSource(_ original: Data, to root: String) throws -> Data {
    let path = Data(root.utf8)
    guard !original.isEmpty, original.count <= 8192, !path.isEmpty, path.count <= 4096,
      root.hasPrefix("/"), !path.contains(0) else { throw KagemushaWalletErrorV1.invalidInput }
    typealias Relocate = @convention(c) (UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<connect_norito_kagemusha_wallet_result_v1>?) -> Int32
    let driver = try KagemushaWalletNativeDriverV1()
    guard let relocate = NoritoNativeBridge.shared.resolveNativeSymbol(
      "connect_norito_kagemusha_wallet_registration_source_relocate_v1", as: Relocate.self)
    else { throw KagemushaWalletErrorV1.bridgeUnavailable }
    let result = try driver.result { output in
      original.withUnsafeBytes { source in path.withUnsafeBytes { destination in
        relocate(source.bindMemory(to: UInt8.self).baseAddress, original.count,
          destination.bindMemory(to: UInt8.self).baseAddress, path.count, output)
      } }
    }
    guard result.status == 12, result.sequenceLow == 0, result.sequenceHigh == 0,
      result.detail == 0, !result.bytes.isEmpty, result.bytes.count <= 8192
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    return result.bytes
  }
  public init(appManifest: Data, envelope: Data, walletRuntime: Data, verifierPack: Data,
    producerInventory: Data, signedGenesis: Data, originalsRoot: String, registrationSource: Data) throws {
    let inputs = [appManifest, envelope, walletRuntime, verifierPack, producerInventory, signedGenesis]
    let caps = [8_388_608, 2048, 131_072, 16_842_752, 16_777_216, 67_108_864]
    for (index, value) in inputs.enumerated() {
      guard value.count <= caps[index] else { throw KagemushaWalletErrorV1.invalidInput }
    }
    guard [appManifest, envelope, walletRuntime, signedGenesis].allSatisfy({ !$0.isEmpty })
    else { throw KagemushaWalletErrorV1.invalidInput }
    let financialAbsent = [verifierPack.isEmpty, producerInventory.isEmpty, originalsRoot.isEmpty]
    guard financialAbsent.allSatisfy({ $0 }) || financialAbsent.allSatisfy({ !$0 })
    else { throw KagemushaWalletErrorV1.invalidInput }
    guard (originalsRoot.isEmpty || originalsRoot.hasPrefix("/")), !originalsRoot.utf8.contains(0),
      originalsRoot.utf8.count <= 4096 else { throw KagemushaWalletErrorV1.invalidInput }
    guard registrationSource.count <= 8192 else { throw KagemushaWalletErrorV1.invalidInput }
    originals = inputs.map { Data($0) } + [Data(originalsRoot.utf8), Data(registrationSource)]
  }
}

/// A failed release retains the exact resource and blocks replacement admission.
public final class KagemushaWalletAdmissionCleanupErrorV1: Error, @unchecked Sendable {
  public let primary: Error, cleanup: Error
  private let retainedResource: AnyObject
  init(primary: Error, cleanup: Error, resource: AnyObject) {
    self.primary=primary; self.cleanup=cleanup
    // The cleanup lease predates wrapper deinit and preserves exact Native/platform lifetime.
    if let lease=(resource as? KagemushaWalletCleanupResourceV1)?.cleanupLease { retainedResource=lease }
    else { retainedResource=resource }
  }
  var resourceReleased: Bool { (retainedResource as? any KagemushaWalletCleanupLeaseV1)?.isReleased == true }
  /// Retry release of the same quarantined Native owner, including after wrapper destruction.
  /// No-owner/invalid status remains a failure; only actual Native zero acknowledges release.
  public func retryCleanup() throws {
    guard let lease=retainedResource as? any KagemushaWalletCleanupLeaseV1 else { throw cleanup }
    try lease.close()
  }
}

/// Installation joins the single existing Native Runtime/PendingOpen owner. No second registry.
public final class KagemushaWalletInstalledRuntimeV1: KagemushaWalletCleanupResourceV1, @unchecked Sendable {
  private let condition=NSCondition()
  private let runtime: KagemushaWalletRuntimeV1
  private var fenced=false, closing=false, closed=false
  private let admission=KagemushaWalletInstalledAdmissionV1()
  // Runtime caches Pending weakly; this strong reference preserves its real challenge on ordinary failure.
  private var pendingOriginal: KagemushaWalletPendingOpenV1?
  private var closeFailure: Error?
  private static let failuresLock=NSLock()
  private static var failedCleanup: [KagemushaWalletAdmissionCleanupErrorV1]=[]
  private init(runtime: KagemushaWalletRuntimeV1) { self.runtime=runtime }
  var cleanupLease: (any KagemushaWalletCleanupLeaseV1)? { runtime.cleanupLease }
  /// Native authenticates the signed base and complete financial custody before registration.
  /// Retain the returned attempt and explicitly register/retry that same owner. Worker-only.
  public static func install(platform: KagemushaWalletApplePlatformV1, originals: KagemushaWalletRuntimeOriginalsV1) throws -> KagemushaWalletInstallationAttemptV1 {
    try requireNoUnreleasedAdmissions()
    return try KagemushaWalletInstallationAttemptV1.begin(platform:platform,originals:originals)
  }
  static func adoptRegistered(handle: UInt64, driver: KagemushaWalletNativeDriverV1, platform: KagemushaWalletApplePlatformV1) throws -> KagemushaWalletInstalledRuntimeV1 {
    .init(runtime:try KagemushaWalletRuntimeV1(nativeRuntimeHandle:handle,driver:driver,platformOwner:platform))
  }
  static func adoptEnrolled(_ runtime: KagemushaWalletRuntimeV1) -> KagemushaWalletInstalledRuntimeV1 {
    .init(runtime: runtime)
  }
  public static func requireNoUnreleasedAdmissions() throws {
    failuresLock.lock(); defer{failuresLock.unlock()}
    failedCleanup.removeAll { $0.resourceReleased }
    if let first=failedCleanup.first { throw first }
  }
  private func requireLive() throws {
    condition.lock(); defer{condition.unlock()}; guard !fenced else { throw closeFailure ?? KagemushaWalletErrorV1.closed }
  }
  private func fenceCancellation() {
    condition.lock(); fenced=true; condition.unlock()
  }
  private func startOpen(_ frames: [Data]) throws {
    condition.lock(); defer { condition.unlock() }
    guard !fenced else { throw closeFailure ?? KagemushaWalletErrorV1.closed }
    try admission.start(frames)
  }
  private func failedOpen() {
    condition.lock(); defer { condition.unlock() }; admission.failed()
  }
  private func completedOpen() throws {
    condition.lock(); defer { condition.unlock() }
    try admission.completed(); pendingOriginal=nil
  }
  private func pendingForOpen(_ begin: () throws -> KagemushaWalletPendingOpenV1) throws -> KagemushaWalletPendingOpenV1 {
    condition.lock()
    guard !fenced else {
      let failure=closeFailure ?? KagemushaWalletErrorV1.closed
      condition.unlock(); throw failure
    }
    if let retained=pendingOriginal { condition.unlock(); return retained }
    condition.unlock()
    // No InstalledRuntime condition is held across Native I/O or another owner's close lock.
    let selected=try begin()
    condition.lock(); defer { condition.unlock() }
    guard !fenced else { throw closeFailure ?? KagemushaWalletErrorV1.closed }
    pendingOriginal=selected
    return selected
  }
  private func retainedSignature() throws -> Data? {
    condition.lock(); defer { condition.unlock() }
    guard !fenced else { throw closeFailure ?? KagemushaWalletErrorV1.closed }
    return admission.signatureOriginal
  }
  private func freezeSignature(_ original: Data) throws -> Data {
    condition.lock(); defer { condition.unlock() }
    guard !fenced else { throw closeFailure ?? KagemushaWalletErrorV1.closed }
    return try admission.retainSignature(original)
  }
  /// Worker-only. Native authenticates the signed FI session and transfers this same installed lease.
  /// On refusal this owner remains retained for retry with the exact original session.
  public func startEnrollment(session: KagemushaWalletEnrollmentSessionOriginalsV1) throws -> KagemushaWalletEnrollmentV1 {
    condition.lock(); defer { condition.unlock() }
    guard !fenced, admission.canTransferToEnrollment else { throw closeFailure ?? KagemushaWalletErrorV1.closed }
    let enrollment = try runtime.startEnrollment(session)
    fenced = true; closed = true
    return enrollment
  }
  /// Retry ordinary refusal with the same original frames, Native Pending and exact signature.
  /// Explicit Task cancellation retires custody; successful admission transfers it once.
  public func open(originals: KagemushaWalletOpenOriginalsV1,
    signExistingAccount: @escaping @Sendable (Data) async throws -> Data,
    requireCurrent: @escaping @Sendable () throws -> Void) async throws -> KagemushaWalletV1 {
    try await openFrames(originals.originals, begin: { try self.runtime.begin(originals) },
      signExistingAccount: signExistingAccount, requireCurrent: requireCurrent)
  }
  /// Reopen an exact persisted E6 result. Native selects the installed asset and authenticates
  /// its credential/certificates with the original account and existing hardware/journal custody.
  /// The expired enrollment session is neither replayed nor required for this fresh account open.
  public func openEnrolledResult(resultOriginal: Data, accountOriginal: Data,
    signExistingAccount: @escaping @Sendable (Data) async throws -> Data,
    requireCurrent: @escaping @Sendable () throws -> Void) async throws -> KagemushaWalletV1 {
    guard (1...KagemushaWalletEnrollmentV1.RESULT_MAX_BYTES).contains(resultOriginal.count),
      (1...4096).contains(accountOriginal.count) else { throw KagemushaWalletErrorV1.invalidInput }
    let result = Data([UInt8](resultOriginal)), account = Data([UInt8](accountOriginal))
    return try await openFrames([result, account], begin: { try self.runtime.beginEnrolledResult(result, account: account) },
      signExistingAccount: signExistingAccount, requireCurrent: requireCurrent)
  }
  private func openFrames(_ frames: [Data], begin: @escaping @Sendable () throws -> KagemushaWalletPendingOpenV1,
    signExistingAccount: @escaping @Sendable (Data) async throws -> Data,
    requireCurrent: @escaping @Sendable () throws -> Void) async throws -> KagemushaWalletV1 {
    try await withTaskCancellationHandler(operation:{
      var wallet: KagemushaWalletV1?
      var started=false
      do {
        try Task.checkCancellation(); try Self.requireNoUnreleasedAdmissions(); try requireCurrent(); try startOpen(frames)
        started=true
        let pending=try await walletAdmissionWorkerV1 { try requireCurrent(); return try self.pendingForOpen(begin) }
        try Task.checkCancellation(); try requireCurrent(); try requireLive()
        guard pending.challenge.count==32 && pending.challenge.contains(where:{$0 != 0}) else { throw KagemushaWalletErrorV1.invalidNativeOutput }
        let signature: Data
        if let retained=try retainedSignature() { signature=retained }
        else {
          let delivered=try await signExistingAccount(pending.challenge)
          // Bound and copy producer DATA before asynchronous dispatch. It supplies no verdict.
          signature=try freezeSignature(delivered)
        }
        try Task.checkCancellation(); try requireCurrent(); try requireLive()
        wallet=try await walletAdmissionWorkerV1 { try requireCurrent(); try self.requireLive(); return try pending.finish(accountSignature:signature) }
        try completedOpen(); started=false
        try Task.checkCancellation(); try requireCurrent(); try requireLive()
        guard let admitted=wallet else { throw KagemushaWalletErrorV1.invalidNativeOutput }; return admitted
      } catch {
        if started { failedOpen(); started=false }
        let primary=error, admitted=wallet
        // A producer may throw CancellationError without cancelling this Task. Retain custody then.
        guard admitted != nil || Task.isCancelled else { throw primary }
        throw await walletAdmissionWorkerResultV1 {
          var reported: Error=primary
          if let admitted { reported=Self.cleanup(reported,resource:admitted){try admitted.close()} }
          return Self.cleanup(reported,resource:self){try self.close()}
        }
      }
    },onCancel:{
      // Fence new operations synchronously; release still requires the actual same-owner acknowledgement.
      self.fenceCancellation()
      DispatchQueue.global(qos:.utility).async { do{try self.close()}catch{/* actual close failure retained */} }
    })
  }
  /// Close unadmitted custody; successful finish transfers exactly the same ID to its wallet.
  public func close() throws {
    condition.lock(); var waited=false
    while closing { waited=true; condition.wait() }
    if closed { condition.unlock(); return }
    if waited, let failure=closeFailure { condition.unlock(); throw failure }
    // A new explicit close retries; every operation remains fenced after the first attempt.
    fenced=true; closing=true; condition.unlock()
    do {
      try runtime.close()
      condition.lock(); closed=true; closeFailure=nil; closing=false; condition.broadcast(); condition.unlock()
    } catch {
      let failure=Self.retain(error,cleanup:error,resource:runtime)
      condition.lock(); closeFailure=failure; closing=false; condition.broadcast(); condition.unlock(); throw failure
    }
  }
  public func closeAsync() async throws { try await walletAdmissionWorkerV1 { try self.close() } }
  static func retain(_ primary: Error,cleanup: Error,resource: AnyObject) -> KagemushaWalletAdmissionCleanupErrorV1 {
    let failure=KagemushaWalletAdmissionCleanupErrorV1(primary:primary,cleanup:cleanup,resource:resource)
    failuresLock.lock(); failedCleanup.append(failure); failuresLock.unlock(); return failure
  }
  private static func cleanup(_ primary: Error,resource: AnyObject,release: () throws -> Void) -> Error {
    do{try release();return primary}catch{return retain(primary,cleanup:error,resource:resource)}
  }
}
/// Managed DATA sequencing only. The InstalledRuntime condition serializes every production call.
/// This type cannot choose a Native owner, authenticate originals, or acknowledge close.
internal final class KagemushaWalletInstalledAdmissionV1 {
  private var originalFrames: [Data]?
  private var retainedSignature: Data?
  private var active=false, transferred=false
  var canTransferToEnrollment: Bool { !active && !transferred && originalFrames == nil }
  func start(_ frames: [Data]) throws {
    guard !active && !transferred else { throw KagemushaWalletErrorV1.closed }
    if let retained=originalFrames {
      guard retained==frames else { throw KagemushaWalletErrorV1.invalidInput }
    } else { originalFrames=frames.map { Data([UInt8]($0)) } }
    active=true
  }
  // Only managed sequencing resets. Exact original frames, signature and real Pending remain retained.
  func failed() { active=false }
  var signatureOriginal: Data? { retainedSignature.map { Data([UInt8]($0)) } }
  func retainSignature(_ original: Data) throws -> Data {
    guard active && !transferred, original.count==64 else { throw KagemushaWalletErrorV1.invalidInput }
    let frozen=Data([UInt8](original))
    if let retained=retainedSignature {
      guard retained==frozen else { throw KagemushaWalletErrorV1.invalidInput }
      return Data([UInt8](retained))
    }
    retainedSignature=frozen
    return Data([UInt8](frozen))
  }
  func completed() throws {
    guard active && !transferred else { throw KagemushaWalletErrorV1.closed }
    transferred=true; active=false; retainedSignature=nil
  }
}
func withPinnedWalletOriginalsV1<T>(_ originals:[Data],_ body:([UnsafePointer<UInt8>?])->T)->T {
  func pin(_ index:Int,_ pointers:[UnsafePointer<UInt8>?])->T {
    if index==originals.count{return body(pointers)}
    return originals[index].withUnsafeBytes{pin(index+1,pointers+[$0.bindMemory(to:UInt8.self).baseAddress])}
  };return pin(0,[])
}
private func walletAdmissionWorkerV1<T:Sendable>(_ operation:@escaping @Sendable () throws->T) async throws->T {
  try await withCheckedThrowingContinuation{continuation in DispatchQueue.global(qos:.userInitiated).async{
    do{continuation.resume(returning:try operation())}catch{continuation.resume(throwing:error)}
  }}
}
private func walletAdmissionWorkerResultV1(_ operation:@escaping @Sendable ()->Error) async->Error {
  await withCheckedContinuation{continuation in DispatchQueue.global(qos:.userInitiated).async{continuation.resume(returning:operation())}}
}
