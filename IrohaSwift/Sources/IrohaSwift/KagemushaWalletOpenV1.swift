import Foundation
import NoritoBridge

/// Exact original owner frames. Their contents are authenticated exclusively by Native.
public struct KagemushaWalletOpenOriginalsV1: Sendable {
  let originals: [Data]
  public init(credential: Data, enrollmentCertificates: Data, account: Data, assetScope: Data) throws {
    let values = [credential, enrollmentCertificates, account, assetScope]
    guard zip(values, [1_024, 10_000, 4_096, 1_024]).allSatisfy({ !$0.0.isEmpty && $0.0.count <= $0.1 })
    else { throw KagemushaWalletErrorV1.invalidInput }
    originals = values
  }
  func withRequest<T>(_ body: (UnsafePointer<connect_norito_kagemusha_wallet_open_request_v1>) throws -> T) rethrows -> T {
    try originals[0].withUnsafeBytes { a in try originals[1].withUnsafeBytes { b in
      try originals[2].withUnsafeBytes { c in try originals[3].withUnsafeBytes { d in
        var request = connect_norito_kagemusha_wallet_open_request_v1()
        request.credential = a.bindMemory(to: UInt8.self).baseAddress; request.credential_length = a.count
        request.certificates = b.bindMemory(to: UInt8.self).baseAddress; request.certificates_length = b.count
        request.account = c.bindMemory(to: UInt8.self).baseAddress; request.account_length = c.count
        request.asset = d.bindMemory(to: UInt8.self).baseAddress; request.asset_length = d.count
        return try body(&request)
      }}
    }}
  }
}

/// Sole release acknowledgement from the same Native owner, retained before wrapper destruction.
protocol KagemushaWalletCleanupLeaseV1: AnyObject {
  var isReleased: Bool { get }
  func close() throws
}

/// A cleanup view of the one actual Native owner, never a second admission registry.
protocol KagemushaWalletCleanupResourceV1: AnyObject {
  var cleanupLease: (any KagemushaWalletCleanupLeaseV1)? { get }
}

/// Only close is injectable for cleanup fault tests; this interface cannot admit or spend.
protocol KagemushaWalletNativeCloseDriverV1: AnyObject, Sendable {
  func closeNativeLease(_ owner: UInt64) -> Int32
}

extension KagemushaWalletNativeDriverV1: KagemushaWalletNativeCloseDriverV1 {
  func closeNativeLease(_ owner: UInt64) -> Int32 { close(owner) }
}

/// Strongly owns the actual Native ID, its driver and its callback platform until close joins.
/// Wrappers already own this lease before their deinit starts. A failed close quarantines
/// the lease itself; it never publishes a wrapper whose destruction has begun.
final class KagemushaWalletNativeLeaseV1: KagemushaWalletCleanupResourceV1, KagemushaWalletCleanupLeaseV1, @unchecked Sendable {
  private let condition = NSCondition()
  private var owner: UInt64
  private let driver: any KagemushaWalletNativeCloseDriverV1
  private var platformOwner: AnyObject?
  private var fenced = false, closing = false
  private var closeFailure: Error?
  init(owner: UInt64, driver: any KagemushaWalletNativeCloseDriverV1, platformOwner: AnyObject) {
    precondition(owner > 0 && owner <= UInt64(Int64.max))
    self.owner = owner; self.driver = driver; self.platformOwner = platformOwner
  }
  var cleanupLease: (any KagemushaWalletCleanupLeaseV1)? { self }
  /// True only after this exact Native ID returned close status zero.
  var isReleased: Bool {
    condition.lock(); defer { condition.unlock() }; return owner == 0
  }
  func ownsPlatform(_ platform: AnyObject) -> Bool {
    condition.lock(); defer { condition.unlock() }; return platformOwner === platform && !fenced && owner != 0
  }
  func handle() throws -> UInt64 {
    condition.lock(); defer { condition.unlock() }
    guard !fenced && owner != 0 else { throw closeFailure ?? KagemushaWalletErrorV1.closed }
    return owner
  }
  /// First close irrevocably blocks operations. Explicit retries use the unchanged ID.
  /// Concurrent callers join the current attempt; a waiter never starts an implicit retry.
  func close() throws {
    condition.lock()
    var waited = false
    while closing { waited = true; condition.wait() }
    if owner == 0 { condition.unlock(); return }
    if waited {
      let failure = closeFailure ?? KagemushaWalletErrorV1.closed
      condition.unlock(); throw failure
    }
    fenced = true; closing = true; let value = owner; condition.unlock()
    do {
      // Invalid/no-owner, unavailable and provider errors are not release acknowledgements.
      try KagemushaWalletNativeDriverV1.check(driver.closeNativeLease(value))
      condition.lock()
      owner = 0; platformOwner = nil; closeFailure = nil; closing = false
      condition.broadcast(); condition.unlock()
    } catch {
      // Do not hold the lease lock while entering the existing quarantine lock.
      let failure = KagemushaWalletInstalledRuntimeV1.retain(error, cleanup: error, resource: self)
      condition.lock(); closeFailure = error; closing = false
      condition.broadcast(); condition.unlock(); throw failure
    }
  }
}

/// Runtime already provisioned by the embedding app's trusted native startup loader.
/// This handle selects retained native custody; it supplies no trust pins or proof verdicts.
public final class KagemushaWalletRuntimeV1: KagemushaWalletCleanupResourceV1, @unchecked Sendable {
  private let lock = NSLock()
  private var lease: KagemushaWalletNativeLeaseV1?
  private let driver: KagemushaWalletNativeDriverV1
  private let pending=KagemushaWalletAdmissionLifetimeV1<KagemushaWalletPendingOpenV1>()
  // The optional close-only seam is internal and used solely by synthetic cleanup tests.
  // Production installation always binds cleanup to the same real Native driver.
  init(nativeRuntimeHandle: UInt64, driver: KagemushaWalletNativeDriverV1,
    platformOwner: AnyObject, cleanupDriver: (any KagemushaWalletNativeCloseDriverV1)? = nil) throws {
    guard nativeRuntimeHandle > 0 && nativeRuntimeHandle <= UInt64(Int64.max)
    else { throw KagemushaWalletErrorV1.invalidInput }
    lease = .init(owner: nativeRuntimeHandle, driver: cleanupDriver ?? driver, platformOwner: platformOwner)
    self.driver = driver
  }
  init(lease: KagemushaWalletNativeLeaseV1, driver: KagemushaWalletNativeDriverV1) {
    self.lease = lease; self.driver = driver
  }
  var cleanupLease: (any KagemushaWalletCleanupLeaseV1)? {
    lock.lock(); defer { lock.unlock() }; return lease
  }
  /// Transfer the existing Native lease only after it authenticates the live session originals.
  func startEnrollment(_ session: KagemushaWalletEnrollmentSessionOriginalsV1) throws -> KagemushaWalletEnrollmentV1 {
    lock.lock(); defer { lock.unlock() }
    guard let lease else { throw KagemushaWalletErrorV1.closed }
    let owner = try lease.handle(), originals = session.originals
    let input = try KagemushaWalletEnrollmentInputV1(11, originals[0], originals[1], originals[2])
    let reply = try driver.result { out in input.withRequest { driver.enrollment(owner, $0, out) } }
    guard reply.status == 37, reply.sequenceLow == owner, reply.sequenceHigh == 0,
      reply.detail == 0, (5...1028).contains(reply.bytes.count)
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    let enrollment = KagemushaWalletEnrollmentV1(lease: lease, driver: driver, assetScope: reply.bytes.dropFirst(4), assetScale: reply.bytes.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) })
    self.lease = nil
    return enrollment
  }
  /// Begin with original issuer/account frames. Native reconciles before sampling its challenge.
  public func begin(_ originals: KagemushaWalletOpenOriginalsV1) throws -> KagemushaWalletPendingOpenV1 {
    lock.lock(); defer { lock.unlock() }
    guard let lease else { throw KagemushaWalletErrorV1.closed }
    let owner = try lease.handle()
    let result = try driver.result { out in originals.withRequest { driver.openBegin(owner, $0, out) } }
    guard result.status == 15 && result.sequenceLow == owner && result.sequenceHigh == 0 && result.detail == 0 && result.bytes.count == 32 && result.bytes.contains(where: { $0 != 0 }) else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    return try pending.select(result.bytes){identity in
      KagemushaWalletPendingOpenV1(runtime:self,identity:identity,challenge:result.bytes)
    }
  }
  /// Begin admission with exact Native-retained E5/E6 originals after enrollment handoff.
  public func beginEnrolled() throws -> KagemushaWalletPendingOpenV1 {
    lock.lock(); defer { lock.unlock() }
    guard let lease else { throw KagemushaWalletErrorV1.closed }
    let owner = try lease.handle()
    let input = try KagemushaWalletEnrollmentInputV1(8)
    let result = try driver.result { out in input.withRequest { driver.enrollment(owner, $0, out) } }
    guard result.status == 15 && result.sequenceLow == owner && result.sequenceHigh == 0 && result.detail == 0 && result.bytes.count == 32 && result.bytes.contains(where: { $0 != 0 }) else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    return try pending.select(result.bytes) { identity in
      KagemushaWalletPendingOpenV1(runtime: self, identity: identity, challenge: result.bytes)
    }
  }
  /// Reopen persisted full E6 DATA through the same original-account/custody boundary.
  func beginEnrolledResult(_ original: Data, account: Data) throws -> KagemushaWalletPendingOpenV1 {
    lock.lock(); defer { lock.unlock() }
    guard let lease else { throw KagemushaWalletErrorV1.closed }
    let owner = try lease.handle()
    let input = try KagemushaWalletEnrollmentInputV1(12, original, account)
    let result = try driver.result { out in input.withRequest { driver.enrollment(owner, $0, out) } }
    guard result.status == 15 && result.sequenceLow == owner && result.sequenceHigh == 0 && result.detail == 0 && result.bytes.count == 32 && result.bytes.contains(where: { $0 != 0 }) else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    return try pending.select(result.bytes) { identity in
      KagemushaWalletPendingOpenV1(runtime: self, identity: identity, challenge: result.bytes)
    }
  }
  // Called exclusively under this Runtime's lock.
  private func finishNative(_ signature:Data) throws->KagemushaWalletV1 {
    guard let lease else { throw KagemushaWalletErrorV1.closed }
    let owner = try lease.handle()
    let result = try driver.result { out in signature.withUnsafeBytes { driver.openFinish(owner, $0.bindMemory(to: UInt8.self).baseAddress, $0.count, out) } }
    guard result.status == 16 && result.sequenceLow == owner && result.sequenceHigh == 0 && result.detail == 0 && result.bytes.isEmpty else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    // Transfer the same pre-existing lease. No owner ID or callback lifetime is reconstructed.
    let wallet = KagemushaWalletV1(lease: lease, driver: driver)
    self.lease = nil
    return wallet
  }
  fileprivate func finish(_ identity:KagemushaWalletAdmissionIdentityV1,signature:Data) throws->KagemushaWalletV1 {
    lock.lock();defer{lock.unlock()}
    return try pending.finish(identity){try finishNative(signature)}
  }
  // Called exclusively under this Runtime's lock.
  private func cancelNative() throws {
    guard let lease else{throw KagemushaWalletErrorV1.closed}
    try KagemushaWalletNativeDriverV1.check(driver.openCancel(try lease.handle()))
  }
  fileprivate func cancel(_ identity:KagemushaWalletAdmissionIdentityV1) throws {
    lock.lock();defer{lock.unlock()};try pending.abandon(identity){try cancelNative()}
  }
  /// Discard a pending challenge after interrupted begin delivery, retaining Native custody.
  public func cancelPendingOpen() throws {
    lock.lock();defer{lock.unlock()};try pending.complete{try cancelNative()}
  }
  /// Ordinary authorization refusal retains the same Native Pending challenge, recoverable
  /// by begin or retry; interrupted successful finish transfers the same actual owner.
  public func retryOpenCompletion(accountSignature:Data) throws->KagemushaWalletV1 {
    lock.lock();defer{lock.unlock()};return try pending.complete{try finishNative(accountSignature)}
  }
  /// Close only unadmitted custody; a successful finish transfers ownership to its wallet.
  public func close() throws {
    lock.lock(); defer { lock.unlock() }
    try lease?.close();pending.clear()
  }
  deinit { try? close() }
}

/// Exact retained 32-byte account challenge. The existing Ed25519 account signs these bytes.
public final class KagemushaWalletPendingOpenV1: @unchecked Sendable {
  private let runtime: KagemushaWalletRuntimeV1
  private let identity: KagemushaWalletAdmissionIdentityV1
  public let challenge: Data
  fileprivate init(runtime: KagemushaWalletRuntimeV1, identity: KagemushaWalletAdmissionIdentityV1, challenge: Data) {
    self.runtime = runtime; self.identity = identity; self.challenge = challenge
  }
  /// Ordinary refusal retains the same Native Pending challenge and managed owner for retry;
  /// successful finish consumes this managed selection and transfers the actual lease.
  public func finish(accountSignature: Data) throws -> KagemushaWalletV1 {
    try runtime.finish(identity, signature: accountSignature)
  }
  /// Abandon this challenge without admitting ownership or releasing native custody.
  public func cancel() throws { try runtime.cancel(identity) }
  deinit { try? cancel() }
}

// Managed lifetime only. The token cannot select a native handle, trust pin or verdict.
internal final class KagemushaWalletAdmissionIdentityV1 {}
internal final class KagemushaWalletAdmissionLifetimeV1<P: AnyObject> {
  // Pending owns its Runtime. A weak cache prevents the reverse edge from creating an ARC cycle.
  // The separately retained identity also makes deinit cancellation safe after weak zeroing.
  private weak var current: P?
  private var identity: KagemushaWalletAdmissionIdentityV1?
  private var challenge: Data?

  // All production calls are serialized by the actual Runtime lock.
  func select(_ original: Data, create: (KagemushaWalletAdmissionIdentityV1) -> P) throws -> P {
    guard original.count == 32 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    let selectedIdentity: KagemushaWalletAdmissionIdentityV1
    if identity != nil {
      guard challenge == original else { throw KagemushaWalletErrorV1.invalidNativeOutput }
      if let selected = current { return selected }
      // A prior Pending deinit may already be waiting on the Runtime lock. Give the
      // replacement wrapper a fresh managed identity so that old cancellation is stale.
      // The exact retained Native challenge remains unchanged.
      selectedIdentity = KagemushaWalletAdmissionIdentityV1()
    } else {
      selectedIdentity = KagemushaWalletAdmissionIdentityV1()
    }
    let selected = create(selectedIdentity)
    challenge = original
    identity = selectedIdentity
    current = selected
    return selected
  }

  func finish<T>(_ selected: KagemushaWalletAdmissionIdentityV1, action: () throws -> T) throws -> T {
    guard identity === selected else { throw KagemushaWalletErrorV1.closed }
    return try complete(action)
  }

  func abandon(_ selected: KagemushaWalletAdmissionIdentityV1, action: () throws -> Void) throws {
    // An old or completed wrapper must never cancel a subsequent challenge.
    if identity === selected { try complete(action) }
  }

  func complete<T>(_ action: () throws -> T) rethrows -> T {
    let result = try action()
    clear()
    return result
  }

  func clear() {
    current = nil
    identity = nil
    challenge = nil
  }
}
