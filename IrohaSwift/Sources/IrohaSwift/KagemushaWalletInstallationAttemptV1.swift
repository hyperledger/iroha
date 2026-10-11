import Foundation
import NoritoBridge

/// Sole managed custody of one genuine Native Runtime and authenticated original binding.
/// No raw pointer or authority constructor is public. Retain this attempt on registration refusal.
public final class KagemushaWalletInstallationAttemptV1: KagemushaWalletCleanupResourceV1, @unchecked Sendable {
  private let lease: KagemushaWalletInstallationLeaseV1
  private init(_ lease: KagemushaWalletInstallationLeaseV1) { self.lease=lease }
  var cleanupLease: (any KagemushaWalletCleanupLeaseV1)? { lease }
  /// Retry this same loaded owner in the existing registry. Success transfers once. Worker-only.
  public func register() throws -> KagemushaWalletInstalledRuntimeV1 {
    try KagemushaWalletInstalledRuntimeV1.requireNoUnreleasedAdmissions()
    return try lease.register()
  }
  /// Irreversibly fence registration and join the same Native custody. Worker-only.
  public func close() throws { try lease.close() }
  deinit { do { try lease.close() } catch { /* exact lease already retained in quarantine */ } }
  static func begin(platform:KagemushaWalletApplePlatformV1,originals:KagemushaWalletRuntimeOriginalsV1) throws -> KagemushaWalletInstallationAttemptV1 {
    // Resolve mandatory actual functions and allocate managed storage before Native loads custody.
    let walletDriver=try KagemushaWalletNativeDriverV1(), driver=try KagemushaWalletInstallationDriverV1()
    let lease=KagemushaWalletInstallationLeaseV1(driver:driver,walletDriver:walletDriver,platform:platform)
    let wrapper=KagemushaWalletInstallationAttemptV1(lease)
    try lease.begin(originals)
    return wrapper
  }
}

/// Owns the exact Native pointer slot, actual callbacks and drivers before wrapper deinit starts.
private final class KagemushaWalletInstallationLeaseV1: KagemushaWalletCleanupLeaseV1 {
  private let condition=NSCondition()
  private let driver:KagemushaWalletInstallationDriverV1
  private let walletDriver:KagemushaWalletNativeDriverV1
  private var platform:KagemushaWalletApplePlatformV1?
  private var pointer:OpaquePointer?
  private let sequence=KagemushaWalletInstallationSequenceV1()
  private var closeFailure:Error?
  private var closing=false
  init(driver:KagemushaWalletInstallationDriverV1,walletDriver:KagemushaWalletNativeDriverV1,platform:KagemushaWalletApplePlatformV1) {
    self.driver=driver; self.walletDriver=walletDriver; self.platform=platform
  }
  var isReleased:Bool {
    condition.lock(); defer { condition.unlock() }; return sequence.isReleased
  }
  func begin(_ originals:KagemushaWalletRuntimeOriginalsV1) throws {
    guard let platform else { throw KagemushaWalletErrorV1.closed }
    var callbacks=kagemushaWalletCallbacksV1(platform)
    let status=withExtendedLifetime(platform) {
      withPinnedWalletOriginalsV1(originals.originals) { ptr in
        var value=connect_norito_kagemusha_wallet_runtime_originals_v1()
        value.app_manifest=ptr[0]; value.app_manifest_length=originals.originals[0].count
        value.envelope=ptr[1]; value.envelope_length=originals.originals[1].count
        value.wallet_runtime=ptr[2]; value.wallet_runtime_length=originals.originals[2].count
        value.verifier_pack=ptr[3]; value.verifier_pack_length=originals.originals[3].count
        value.producer_inventory=ptr[4]; value.producer_inventory_length=originals.originals[4].count
        value.signed_genesis=ptr[5]; value.signed_genesis_length=originals.originals[5].count
        value.originals_root=ptr[6]; value.originals_root_length=originals.originals[6].count
        value.registration_source=ptr[7]; value.registration_source_length=originals.originals[7].count
        return driver.begin(&value,&callbacks,&pointer)
      }
    }
    // Genuine begin returns no pointer on error. A contradictory retained pointer is still retired.
    do {
      try KagemushaWalletNativeDriverV1.check(status)
      guard pointer != nil else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    } catch {
      let primary=error
      if pointer != nil {
        do { try close() } catch { throw KagemushaWalletInstalledRuntimeV1.retain(primary,cleanup:error,resource:self) }
      } else { sequence.noOwner() ; self.platform=nil }
      throw primary
    }
  }
  func register() throws -> KagemushaWalletInstalledRuntimeV1 {
    condition.lock(); defer { condition.unlock() }
    try sequence.requireRegistration()
    guard let original=pointer, let platform else { throw KagemushaWalletErrorV1.closed }
    var handle:UInt64=0
    let status=driver.register(&pointer,&handle)
    if status != 0 {
      guard pointer==original, handle==0 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
      try KagemushaWalletNativeDriverV1.check(status)
    }
    guard status==0, pointer==nil, handle>0, handle<=UInt64(Int64.max) else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    // Native has consumed this same opaque box and transferred its whole owner into the registry.
    try sequence.transferred()
    let installed=try KagemushaWalletInstalledRuntimeV1.adoptRegistered(handle:handle,driver:walletDriver,platform:platform)
    self.platform=nil
    return installed
  }
  func close() throws {
    condition.lock(); var waited=false
    while closing { waited=true; condition.wait() }
    if sequence.isReleased { condition.unlock(); return }
    if waited, let failure=closeFailure { condition.unlock(); throw failure }
    // A new explicit close retries only this same owner. Operations stay permanently fenced.
    guard sequence.startClose() else { condition.unlock(); return }
    guard let original=pointer else { condition.unlock(); throw KagemushaWalletErrorV1.invalidNativeOutput }
    closing=true; condition.unlock()
    var slot:OpaquePointer?=original
    do {
      let status=driver.close(&slot)
      if status != 0 {
        guard slot==original else { throw KagemushaWalletErrorV1.invalidNativeOutput }
      }
      try checkInstallationCloseStatusV1(status)
      guard slot==nil else { throw KagemushaWalletErrorV1.invalidNativeOutput }
      condition.lock()
      do {
        try sequence.acknowledgedClose(); pointer=nil; platform=nil
        closeFailure=nil; closing=false; condition.broadcast(); condition.unlock()
      } catch {
        closing=false; condition.broadcast(); condition.unlock(); throw error
      }
    } catch {
      let failure=KagemushaWalletInstalledRuntimeV1.retain(error,cleanup:error,resource:self)
      condition.lock()
      // Genuine refusal keeps the original pointer. No status other than zero releases custody.
      closeFailure=failure; closing=false; condition.broadcast(); condition.unlock(); throw failure
    }
  }
}

private final class KagemushaWalletInstallationDriverV1 {
  typealias Begin=@convention(c)(UnsafePointer<connect_norito_kagemusha_wallet_runtime_originals_v1>?,UnsafePointer<connect_norito_kagemusha_platform_v1>?,UnsafeMutablePointer<OpaquePointer?>?)->Int32
  typealias Register=@convention(c)(UnsafeMutablePointer<OpaquePointer?>?,UnsafeMutablePointer<UInt64>?)->Int32
  typealias Close=@convention(c)(UnsafeMutablePointer<OpaquePointer?>?)->Int32
  let begin:Begin, register:Register, close:Close
  init() throws {
    guard let begin=NoritoNativeBridge.shared.resolveNativeSymbol("connect_norito_kagemusha_wallet_installation_begin_v1",as:Begin.self),
      let register=NoritoNativeBridge.shared.resolveNativeSymbol("connect_norito_kagemusha_wallet_installation_register_v1",as:Register.self),
      let close=NoritoNativeBridge.shared.resolveNativeSymbol("connect_norito_kagemusha_wallet_installation_close_v1",as:Close.self)
    else { throw KagemushaWalletErrorV1.bridgeUnavailable }
    self.begin=begin; self.register=register; self.close=close
  }
}

func checkInstallationCloseStatusV1(_ status:Int32) throws {
  if status<0 { try KagemushaWalletNativeDriverV1.check(status) }
  guard status==0 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
}

/// Managed sequencing DATA only; cannot manufacture a Native pointer, registry ID or zero ack.
final class KagemushaWalletInstallationSequenceV1 {
  private var wasTransferred=false, retiring=false, acknowledged=false
  func requireRegistration() throws {
    guard !wasTransferred && !retiring && !acknowledged else { throw KagemushaWalletErrorV1.closed }
  }
  func transferred() throws { try requireRegistration(); wasTransferred=true }
  func startClose() -> Bool {
    if wasTransferred || acknowledged { return false }; retiring=true; return true
  }
  func acknowledgedClose() throws {
    guard retiring && !wasTransferred && !acknowledged else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    acknowledged=true
  }
  func noOwner() { acknowledged=true }
  var isReleased:Bool { wasTransferred || acknowledged }
}
