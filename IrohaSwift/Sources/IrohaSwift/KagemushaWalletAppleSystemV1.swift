import CryptoKit
import Darwin
import Foundation
import Security
import os
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

// Operating-system seams of the iPhone wallet platform adapter
// (`KagemushaWalletApplePlatformV1`), plus its custody root and boot identity. Every seam is a
// value the tests replace with a fake; the live values call the system. There is no clock
// here: the Rust default `KagemushaWalletPlatformV1::monotonic_ms` already reads
// `mach_continuous_time` on Apple targets.

/// A failed Security or CryptoTokenKit call: its error domain and code.
struct KagemushaWalletAppleSecurityErrorV1: Equatable, Sendable {
  /// Error domain (`NSOSStatusErrorDomain`, `CryptoTokenKit`, `com.apple.LocalAuthentication`).
  let domain: String
  /// Code within `domain`.
  let code: Int

  init(domain: String, code: Int) {
    self.domain = domain
    self.code = code
  }

  /// An `OSStatus` result.
  init(status: OSStatus) {
    self.init(domain: NSOSStatusErrorDomain, code: Int(status))
  }

  /// The error of a failed call; a failure without an error is `errSecInternalComponent`.
  init(_ error: CFError?) {
    guard let error else {
      self.init(status: errSecInternalComponent)
      return
    }
    self.init(domain: CFErrorGetDomain(error) as String, code: CFErrorGetCode(error))
  }

  /// The `OSStatus` of an `NSOSStatusErrorDomain` error; `nil` for every other domain, so a
  /// CryptoTokenKit or LocalAuthentication code is never read as an `OSStatus`.
  var osStatus: OSStatus? {
    domain == NSOSStatusErrorDomain ? OSStatus(exactly: code) : nil
  }

  /// `<domain> <code>`, for diagnostics.
  var detail: String { "\(domain) \(code)" }
}

/// One condition the adapter reports as unavailable, for the field log; never acted on.
struct KagemushaWalletAppleDiagnosticV1: Equatable, Sendable {
  /// What happened: fixed text, logged publicly.
  let event: String
  /// Keychain name of the slot concerned; logged as private.
  let slot: String?
  /// An item count, a protection class or an error domain and code; logged publicly.
  let detail: String?
}

/// Keychain operations the adapter performs. Production uses
/// ``KagemushaWalletAppleSystemKeychainV1``; tests inject a fake.
protocol KagemushaWalletAppleKeychainV1: Sendable {
  /// `SecItemCopyMatching`.
  func copyMatching(_ query: [String: Any]) -> (status: OSStatus, result: CFTypeRef?)
  /// `SecItemAdd` without a returned result.
  func add(_ attributes: [String: Any]) -> OSStatus
  /// `SecItemUpdate`.
  func update(_ query: [String: Any], _ attributes: [String: Any]) -> OSStatus
  /// `SecItemDelete`.
  func delete(_ query: [String: Any]) -> OSStatus
  /// `SecKeyCreateRandomKey`; on failure the error's domain and code.
  func createRandomKey(_ attributes: [String: Any])
    -> (key: SecKey?, error: KagemushaWalletAppleSecurityErrorV1?)
}

/// The system keychain.
struct KagemushaWalletAppleSystemKeychainV1: KagemushaWalletAppleKeychainV1 {
  func copyMatching(_ query: [String: Any]) -> (status: OSStatus, result: CFTypeRef?) {
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    return (status, result)
  }

  func add(_ attributes: [String: Any]) -> OSStatus {
    SecItemAdd(attributes as CFDictionary, nil)
  }

  func update(_ query: [String: Any], _ attributes: [String: Any]) -> OSStatus {
    SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
  }

  func delete(_ query: [String: Any]) -> OSStatus {
    SecItemDelete(query as CFDictionary)
  }

  func createRandomKey(_ attributes: [String: Any])
    -> (key: SecKey?, error: KagemushaWalletAppleSecurityErrorV1?)
  {
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      return (nil, KagemushaWalletAppleSecurityErrorV1(error?.takeRetainedValue()))
    }
    return (key, nil)
  }
}

/// Operating-system services of the adapter.
struct KagemushaWalletAppleSystemV1: Sendable {
  /// Keychain and Secure Enclave key creation.
  var keychain: any KagemushaWalletAppleKeychainV1
  /// Whether this device has a Secure Enclave.
  var secureEnclaveAvailable: @Sendable () -> Bool
  /// `true` with a device passcode, `false` when the system reports none, `nil` when unknown.
  var passcodeSet: @Sendable () -> Bool?
  /// Whether the OS enforces file data protection: an iPhone or iPad app on its own device;
  /// never macOS, Mac Catalyst or an iPhone app running on a Mac.
  var dataProtectionEnforced: @Sendable () -> Bool
  /// The app's `Library/Application Support` directory.
  var applicationSupportDirectory: @Sendable () -> Result<URL, KagemushaWalletAppleUnavailableV1>
  /// Open and read one byte of `path`; `0` on success, otherwise the `errno`.
  var probeReadable: @Sendable (String) -> Int32
  /// Data-protection class of the file at `path` (`nil` when the file system reports none).
  var fileProtection: @Sendable (String) -> Result<FileProtectionType?, KagemushaWalletAppleUnavailableV1>
  /// Set the data-protection class of the file at `path`.
  var setFileProtection: @Sendable (String, FileProtectionType) -> Result<Void, KagemushaWalletAppleUnavailableV1>
  /// Raw bytes of a string `sysctl`.
  var sysctl: @Sendable (String) -> Result<[UInt8], KagemushaWalletAppleUnavailableV1>
  /// Field log of conditions reported as unavailable (never acted on).
  var diagnostic: @Sendable (KagemushaWalletAppleDiagnosticV1) -> Void

  /// The live system.
  static let live = KagemushaWalletAppleSystemV1(
    keychain: KagemushaWalletAppleSystemKeychainV1(),
    secureEnclaveAvailable: { SecureEnclave.isAvailable },
    passcodeSet: { liveDevicePasscodeSet() },
    dataProtectionEnforced: { liveDataProtectionEnforced() },
    applicationSupportDirectory: { liveApplicationSupportDirectory() },
    probeReadable: { liveProbeReadable($0) },
    fileProtection: { liveFileProtection($0) },
    setFileProtection: { liveSetFileProtection($0, $1) },
    sysctl: { liveSysctlBytes($0) },
    diagnostic: { liveDiagnostic($0) })

  /// Unified-log destination of the live diagnostics.
  static let logger = Logger(subsystem: "org.hyperledger.iroha.kagemusha.wallet", category: "platform")

  /// POSIX code of a Foundation error (directly or as its underlying error), or `0`.
  static func posixCode(_ error: Error) -> Int32 {
    let nsError = error as NSError
    if nsError.domain == NSPOSIXErrorDomain {
      return Int32(clamping: nsError.code)
    }
    if let underlying = nsError.userInfo[NSUnderlyingErrorKey] as? NSError,
      underlying.domain == NSPOSIXErrorDomain
    {
      return Int32(clamping: underlying.code)
    }
    return 0
  }

  /// Write `entry` to the unified log; the slot name is private.
  static func liveDiagnostic(_ entry: KagemushaWalletAppleDiagnosticV1) {
    logger.error(
      "\(entry.event, privacy: .public) \(entry.detail ?? "", privacy: .public) slot=\(entry.slot ?? "-", privacy: .private)"
    )
  }

  private static func liveDevicePasscodeSet() -> Bool? {
    #if canImport(LocalAuthentication)
    let context = LAContext()
    var error: NSError?
    if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
      return true
    }
    if let error, (error as Error as? LAError)?.code == .passcodeNotSet {
      return false
    }
    return nil
    #else
    return nil
    #endif
  }

  private static func liveDataProtectionEnforced() -> Bool {
    #if os(iOS) && !targetEnvironment(macCatalyst)
    return !ProcessInfo.processInfo.isiOSAppOnMac
    #else
    return false
    #endif
  }

  private static func liveApplicationSupportDirectory()
    -> Result<URL, KagemushaWalletAppleUnavailableV1>
  {
    do {
      return .success(
        try FileManager.default.url(
          for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil,
          create: true))
    } catch {
      return .failure(.io(posixCode(error)))
    }
  }

  private static func liveProbeReadable(_ path: String) -> Int32 {
    var descriptor: Int32
    repeat {
      descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    } while descriptor < 0 && errno == EINTR
    guard descriptor >= 0 else { return errno }
    defer { close(descriptor) }
    var byte: UInt8 = 0
    while true {
      if read(descriptor, &byte, 1) >= 0 { return 0 }
      let code = errno
      if code != EINTR { return code }
    }
  }

  private static func liveFileProtection(_ path: String)
    -> Result<FileProtectionType?, KagemushaWalletAppleUnavailableV1>
  {
    do {
      let value = try FileManager.default.attributesOfItem(atPath: path)[.protectionKey]
      if let protection = value as? FileProtectionType { return .success(protection) }
      if let raw = value as? String { return .success(FileProtectionType(rawValue: raw)) }
      return .success(nil)
    } catch {
      return .failure(.io(posixCode(error)))
    }
  }

  private static func liveSetFileProtection(_ path: String, _ protection: FileProtectionType)
    -> Result<Void, KagemushaWalletAppleUnavailableV1>
  {
    do {
      try FileManager.default.setAttributes([.protectionKey: protection], ofItemAtPath: path)
      return .success(())
    } catch {
      return .failure(.io(posixCode(error)))
    }
  }

  private static func liveSysctlBytes(_ name: String)
    -> Result<[UInt8], KagemushaWalletAppleUnavailableV1>
  {
    var size = 0
    guard sysctlbyname(name, nil, &size, nil, 0) == 0 else { return .failure(.io(errno)) }
    guard size > 0, size <= 1_024 else { return .failure(.io(EINVAL)) }
    var buffer = [UInt8](repeating: 0, count: size)
    guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return .failure(.io(errno)) }
    return .success(Array(buffer.prefix(size)))
  }
}

// MARK: - Custody root

/// Kind of one path, from `lstat` (symbolic links are never followed).
enum KagemushaWalletAppleEntryKindV1: Equatable {
  case missing
  case directory
  case file
  case other
  case error(Int32)

  init(path: String) {
    var info = stat()
    guard lstat(path, &info) == 0 else {
      let code = errno
      self = code == ENOENT ? .missing : .error(code)
      return
    }
    switch info.st_mode & S_IFMT {
    case S_IFDIR: self = .directory
    case S_IFREG: self = .file
    default: self = .other
    }
  }
}

extension KagemushaWalletApplePlatformV1 {
  /// Directory name of the custody root (Rust `KAGEMUSHA_WALLET_ROOT_DIR_NAME_V1`). The iOS
  /// Application Support directory is per app, so the name needs no bundle prefix.
  static let custodyRootName = "kagemusha-wallet-v1"
  /// Protected-data canary name (Rust `KAGEMUSHA_WALLET_CANARY_NAME_V1`).
  static let canaryName = "canary"
  /// First-unlock probe, next to the custody root (the Rust root admits no other entry).
  static let firstUnlockProbeName = "kagemusha-wallet-v1.first-unlock"
  /// Default protection class of the custody root, so every file the Rust store creates in it
  /// is readable after the first unlock (design: completeUntilFirstUserAuthentication).
  static let custodyRootProtection = FileProtectionType.completeUntilFirstUserAuthentication
  /// Protection class of the canary: readable only while the device is unlocked.
  static let canaryProtection = FileProtectionType.complete
  /// Protection class of the first-unlock probe: readable once unlocked since boot.
  static let firstUnlockProbeProtection = FileProtectionType.completeUntilFirstUserAuthentication

  /// Attributes (re)applied to the custody root on every preparation.
  static var custodyRootAttributes: [FileAttributeKey: Any] {
    var attributes: [FileAttributeKey: Any] = [.posixPermissions: NSNumber(value: Int16(0o700))]
    #if os(iOS)
    attributes[.protectionKey] = custodyRootProtection
    #endif
    return attributes
  }

  /// Create-new write options of the canary.
  static var canaryWriteOptions: Data.WritingOptions {
    #if os(iOS)
    return [.withoutOverwriting, .completeFileProtection]
    #else
    return [.withoutOverwriting]
    #endif
  }

  /// Create-new write options of the first-unlock probe.
  static var firstUnlockProbeWriteOptions: Data.WritingOptions {
    #if os(iOS)
    return [.withoutOverwriting, .completeFileProtectionUntilFirstUserAuthentication]
    #else
    return [.withoutOverwriting]
    #endif
  }

  /// `Library/Application Support/kagemusha-wallet-v1`, without touching the filesystem.
  func custodyRootURL() -> Result<URL, KagemushaWalletAppleUnavailableV1> {
    system.applicationSupportDirectory().map {
      $0.appendingPathComponent(Self.custodyRootName, isDirectory: true)
    }
  }

  /// Prepare the custody root and return its path for the Rust store. The provider calls it
  /// when it opens; protected-data answers stay unavailable until it has succeeded in this
  /// process.
  ///
  /// The root lives in `Library/Application Support` (never `Documents` or an App Group
  /// container, which app extensions could reach). It is created with mode `0700`; its mode,
  /// its default protection class and `isExcludedFromBackup` are re-applied on every call
  /// (exclusion is Apple guidance only, so safety never depends on it: a surviving newer
  /// keychain anchor detects restored files). Keychain mutation acknowledgements have no
  /// documented power-loss fence; rollback closure requires separate platform qualification.
  /// The canary is created once, create-new, and is never rewritten;
  /// its Complete protection class is read back on every call, re-applied once when it
  /// differs, and the root is refused while it still differs. A root or canary that is a
  /// symbolic link or another kind of entry is refused; nothing is ever removed. Refused
  /// outright where the OS does not enforce file data protection.
  func custodyRootPath() -> Result<String, KagemushaWalletAppleUnavailableV1> {
    prepareCustodyRoot().map(\.path)
  }

  func prepareCustodyRoot() -> Result<URL, KagemushaWalletAppleUnavailableV1> {
    let prepared = prepareCustodyRootEntries()
    if case .success = prepared {
      custodyRootVerified = true
    } else {
      custodyRootVerified = false
    }
    return prepared
  }

  private func prepareCustodyRootEntries() -> Result<URL, KagemushaWalletAppleUnavailableV1> {
    guard system.dataProtectionEnforced() else {
      return .failure(.platform(KagemushaWalletAppleStatusV1.dataProtectionUnavailable))
    }
    let support: URL
    switch system.applicationSupportDirectory() {
    case .success(let url): support = url
    case .failure(let reason): return .failure(reason)
    }
    let root = support.appendingPathComponent(Self.custodyRootName, isDirectory: true)
    let manager = FileManager.default
    switch KagemushaWalletAppleEntryKindV1(path: root.path) {
    case .directory:
      break
    case .missing:
      do {
        try manager.createDirectory(
          at: root, withIntermediateDirectories: false, attributes: Self.custodyRootAttributes)
      } catch {
        // A concurrent creator may have won; only a directory is accepted below.
        guard KagemushaWalletAppleEntryKindV1(path: root.path) == .directory else {
          return .failure(.io(KagemushaWalletAppleSystemV1.posixCode(error)))
        }
      }
    case .file, .other:
      return .failure(.platform(KagemushaWalletAppleStatusV1.invalidCustodyRoot))
    case .error(let code):
      return .failure(.io(code))
    }
    guard KagemushaWalletAppleEntryKindV1(path: root.path) == .directory else {
      return .failure(.platform(KagemushaWalletAppleStatusV1.invalidCustodyRoot))
    }
    do {
      try manager.setAttributes(Self.custodyRootAttributes, ofItemAtPath: root.path)
      var excluded = root
      var values = URLResourceValues()
      values.isExcludedFromBackup = true
      try excluded.setResourceValues(values)
    } catch {
      return .failure(.io(KagemushaWalletAppleSystemV1.posixCode(error)))
    }
    let canary = root.appendingPathComponent(Self.canaryName, isDirectory: false)
    switch KagemushaWalletAppleEntryKindV1(path: canary.path) {
    case .file:
      break
    case .missing:
      do {
        try Data([0x01]).write(to: canary, options: Self.canaryWriteOptions)
        try manager.setAttributes(
          [.posixPermissions: NSNumber(value: Int16(0o600))], ofItemAtPath: canary.path)
      } catch {
        // A concurrent creator may have won; its class is verified below like any other.
        guard KagemushaWalletAppleEntryKindV1(path: canary.path) == .file else {
          return .failure(.io(KagemushaWalletAppleSystemV1.posixCode(error)))
        }
      }
    case .directory, .other:
      return .failure(.platform(KagemushaWalletAppleStatusV1.invalidCustodyRoot))
    case .error(let code):
      return .failure(.io(code))
    }
    if case .failure(let reason) = requireCanaryProtection(canary.path) {
      return .failure(reason)
    }
    prepareFirstUnlockProbe(support.appendingPathComponent(Self.firstUnlockProbeName))
    return .success(root)
  }

  /// Verify the canary's Complete class, re-applying it once when it differs (a crash between
  /// creation and protection, a restored or pre-existing file). Both protected-data brackets
  /// depend on the canary, so an unverified one is never accepted.
  private func requireCanaryProtection(_ path: String) -> Result<Void, KagemushaWalletAppleUnavailableV1> {
    let found: FileProtectionType?
    switch system.fileProtection(path) {
    case .success(let protection): found = protection
    case .failure(let reason): return .failure(reason)
    }
    if found == Self.canaryProtection { return .success(()) }
    diagnose(
      "custody canary is not in the Complete protection class",
      detail: found?.rawValue ?? "none")
    if case .failure(let reason) = system.setFileProtection(path, Self.canaryProtection) {
      return .failure(reason)
    }
    switch system.fileProtection(path) {
    case .success(let protection) where protection == Self.canaryProtection:
      return .success(())
    case .success:
      return .failure(.platform(KagemushaWalletAppleStatusV1.invalidCustodyRoot))
    case .failure(let reason):
      return .failure(reason)
    }
  }

  /// Create the first-unlock probe once (best effort). Without it, an `EPERM` canary reads as
  /// locked even before the first unlock; both answers are unavailable, so nothing else
  /// depends on it.
  private func prepareFirstUnlockProbe(_ url: URL) {
    switch KagemushaWalletAppleEntryKindV1(path: url.path) {
    case .file:
      return
    case .missing:
      do {
        try Data([0x01]).write(to: url, options: Self.firstUnlockProbeWriteOptions)
      } catch {
        guard KagemushaWalletAppleEntryKindV1(path: url.path) == .file else {
          diagnose(
            "first-unlock probe not created",
            detail: "errno \(KagemushaWalletAppleSystemV1.posixCode(error))")
          return
        }
      }
    case .directory, .other, .error:
      diagnose("first-unlock probe is not a regular file")
    }
  }

  /// Reason for a refused Complete-class canary: `beforeFirstUnlock` when the first-unlock
  /// probe (completeUntilFirstUserAuthentication) is refused with `EPERM` too, otherwise
  /// `locked`.
  func lockedReason() -> KagemushaWalletAppleUnavailableV1 {
    guard case .success(let support) = system.applicationSupportDirectory() else { return .locked }
    let code = system.probeReadable(support.appendingPathComponent(Self.firstUnlockProbeName).path)
    return code == EPERM ? .beforeFirstUnlock : .locked
  }
}

// MARK: - Boot identity

extension KagemushaWalletApplePlatformV1 {
  /// Sysctl naming the boot session (read-only in XNU).
  static let bootSessionSysctl = "kern.bootsessionuuid"

  /// Lowercase boot session UUID of the current boot (`kern.bootsessionuuid`).
  ///
  /// Rust hashes this text to the 32-byte boot identity with
  /// `kagemusha_wallet_boot_id_from_text_v1` (its `kagemusha_wallet_native_boot_id_v1` has no
  /// Apple source). Whether the sysctl is readable from the iOS app sandbox is unverified;
  /// when it is not, the answer is unavailable and the provider treats every file as written
  /// in the current boot.
  // TODO(G2-iOS): device-test `kern.bootsessionuuid` from the app sandbox.
  func bootSessionUUID() -> Result<String, KagemushaWalletAppleUnavailableV1> {
    system.sysctl(Self.bootSessionSysctl).flatMap(Self.bootSessionUUID(fromSysctl:))
  }

  /// Parse the NUL-terminated sysctl value: a trimmed 36-character hyphenated UUID, returned
  /// in lowercase; anything else is `io(0)` (as Rust `kagemusha_wallet_boot_id_from_text_v1`).
  static func bootSessionUUID(fromSysctl bytes: [UInt8])
    -> Result<String, KagemushaWalletAppleUnavailableV1>
  {
    let text = bytes.prefix { $0 != 0 }
    guard let decoded = String(bytes: text, encoding: .ascii) else { return .failure(.io(0)) }
    let uuid = Array(decoded.trimmingCharacters(in: .whitespacesAndNewlines).utf8)
    let wellFormed = uuid.count == 36
      && uuid.enumerated().allSatisfy { index, byte in
        [8, 13, 18, 23].contains(index)
          ? byte == UInt8(ascii: "-")
          : (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x46)
            || (byte >= 0x61 && byte <= 0x66)
      }
    guard wellFormed else { return .failure(.io(0)) }
    return .success(String(decoding: uuid, as: UTF8.self).lowercased())
  }
}
