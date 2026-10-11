import Foundation
import Security

// iPhone platform adapter of the KAGEMUSHA wallet Advance provider (G2 design rev 2, iOS;
// specs/kagemusha_single_design_proposal.md §§1.2, 2.2, 2.3, 4.2).
//
// The Rust provider (`crates/iroha_core_zk/src/kagemusha_wallet_advance_v1`) owns
// custody bytes, marker selection, reconciliation, the role-checked signer, low-S
// normalization and the monotonic clock. This adapter supplies only what its
// `KagemushaWalletPlatformV1` trait needs from the phone: the Secure Enclave payment key
// (probe, generate, sign, delete, enumerate), the keychain rollback anchor, protected-storage
// state, the custody root path and the boot identity.
//
// Every probe answers present, absent or unavailable. Absent is only the keychain's
// `errSecItemNotFound` observed while protected data was available before and after the
// query; every other error is unavailable and never read as absence.
//
// TODO(G2-bridge): connect_norito_bridge registers this adapter as the C vtable behind the
// Rust `KagemushaWalletPlatformV1` (kagemusha_wallet_advance_v1/platform.rs). The
// vtable-facing methods stay internal so app code reaches the payment key and the anchor only
// through the Rust provider: `keySign` with arbitrary bytes would bypass the role-checked
// receipt signer. The bridge obtains the custody root path (which verifies the canary) before
// any storage answer.
//
// TODO(G2-iOS): device tests: Secure Enclave key generation and signing under
// kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly (the error domain and code of a signature
// attempted while locked); kSecAttrTokenID and kSecAttrAccessGroup as match attributes of
// SecItemCopyMatching and SecItemDelete, and the access group of a generated key read back;
// enumeration returning application tags; the canary's class read back as Complete; EPERM on
// the canary while locked and on the first-unlock probe before the first unlock.

/// Reason a platform answer is not definitive; never absence.
///
/// Each case is the Rust `KagemushaWalletUnavailableV1` variant of the same name. The Rust
/// `Busy` (custody lock) and `PermanentlyInvalidated` (Android Keystore) never arise here.
public enum KagemushaWalletAppleUnavailableV1: Error, Equatable, Hashable, Sendable {
  /// Protected data or the keychain is locked (`errSecInteractionNotAllowed`, or the
  /// Complete-class canary refused with `EPERM`).
  case locked
  /// The device has not been unlocked since it booted: the first-unlock probe is refused with
  /// `EPERM` as well as the canary.
  case beforeFirstUnlock
  /// A POSIX error, or `0` when none is available.
  case io(Int32)
  /// An `OSStatus`, or a ``KagemushaWalletAppleStatusV1`` code.
  case platform(Int32)
  /// The payment key exists but cannot be used: its public key cannot be exported, or it does
  /// not support ECDSA P-256 / SHA-256 signing.
  case keyUnusable
}

/// Adapter-defined codes reported as ``KagemushaWalletAppleUnavailableV1/platform(_:)``. They lie
/// outside every `OSStatus` range.
public enum KagemushaWalletAppleStatusV1 {
  /// The device has no Secure Enclave; enrollment is refused.
  public static let secureEnclaveUnavailable: Int32 = 0x4B47_0001
  /// App Attest is unsupported; enrollment is refused (spec §2.2).
  public static let appAttestUnsupported: Int32 = 0x4B47_0002
  /// More than one payment key carries the slot's tag; none is selected.
  public static let ambiguousPaymentKey: Int32 = 0x4B47_0003
  /// A generated payment key could not be found again under its tag.
  public static let paymentKeyNotPersisted: Int32 = 0x4B47_0004
  /// The keychain returned a result of an unexpected shape.
  public static let malformedKeychainResult: Int32 = 0x4B47_0005
  /// No device passcode is set; the passcode-bound custody items cannot exist.
  public static let passcodeNotSet: Int32 = 0x4B47_0006
  /// The custody root or its canary is not the expected kind of entry, or the canary is not in
  /// the Complete protection class.
  public static let invalidCustodyRoot: Int32 = 0x4B47_0007
  /// An anchor value is empty or larger than the Rust bound.
  public static let invalidAnchorValue: Int32 = 0x4B47_0008
  /// A Security call failed with an error outside `NSOSStatusErrorDomain` (CryptoTokenKit,
  /// LocalAuthentication); the domain and code go to the diagnostic log.
  public static let nonOSStatusError: Int32 = 0x4B47_0009
  /// The OS does not enforce file data protection here (macOS, Mac Catalyst, an iPhone app on
  /// a Mac), so protected-data state cannot be observed.
  public static let dataProtectionUnavailable: Int32 = 0x4B47_000A
  /// The custody root has not been prepared and its canary verified in this process.
  public static let custodyRootNotPrepared: Int32 = 0x4B47_000B
}

/// Why the adapter's keychain access group could not be derived.
public enum KagemushaWalletAppleConfigurationErrorV1: Error, Equatable, Sendable {
  /// The App ID prefix is not 10 uppercase letters or digits.
  case invalidApplicationIdentifierPrefix
  /// The main bundle has no bundle identifier.
  case missingBundleIdentifier
}

/// Wallet slot identity: 32 nonzero bytes chosen by the Rust provider. Its keychain name
/// `kgm-w1-<64 lowercase hex>` is the payment key's application tag and the anchor's account.
public struct KagemushaWalletAppleSlotV1: Equatable, Hashable, Sendable {
  static let keychainNamePrefix = "kgm-w1-"

  /// Slot bytes.
  public let bytes: Data

  /// `nil` unless `bytes` is 32 bytes and not all zero (as Rust `KagemushaWalletSlotIdV1`).
  public init?(_ bytes: Data) {
    guard bytes.count == 32, bytes.contains(where: { $0 != 0 }) else { return nil }
    self.bytes = Data(bytes)
  }

  /// Strict parse of a payment key's application tag (``keychainName``).
  init?(applicationTag tag: Data) {
    let bytes = Array(tag)
    let prefix = Array(Self.keychainNamePrefix.utf8)
    guard bytes.count == prefix.count + 64, bytes.starts(with: prefix),
      let raw = kagemushaWalletAppleParseHex(bytes[prefix.count...])
    else { return nil }
    self.init(raw)
  }

  /// `kgm-w1-<slot hex>`.
  public var keychainName: String { Self.keychainNamePrefix + kagemushaWalletAppleHex(bytes) }

  /// Application tag of the payment key.
  var applicationTag: Data { Data(keychainName.utf8) }
}

/// Hardware key policy of one enrollment (Rust `KagemushaWalletKeyProfileV1`). On iPhone both
/// profiles generate a Secure Enclave key; the tag is recorded with the key.
public enum KagemushaWalletAppleKeyProfileV1: UInt8, Equatable, Hashable, Sendable {
  /// The dedicated secure element only.
  case secureElement = 1
  /// The secure element or, on Android, the TEE.
  case secureElementOrTee = 2
}

/// What a payment-key generation binds (Rust `KagemushaWalletKeyGenerationRequestV1`): the
/// issuer challenge digest that the App Attest `clientDataHash` carries at E5, and the profile.
/// Both are recorded in the key item's label, so E5 attests only the challenge the key was
/// generated for.
struct KagemushaWalletAppleKeyGenerationRequestV1: Equatable, Sendable {
  static let labelPrefix = "kgm-w1-binding:"

  let challengeDigest: Data
  let profile: KagemushaWalletAppleKeyProfileV1

  init?(challengeDigest: Data, profile: KagemushaWalletAppleKeyProfileV1) {
    guard challengeDigest.count == 32 else { return nil }
    self.challengeDigest = Data(challengeDigest)
    self.profile = profile
  }

  /// Strict parse of ``label``.
  init?(label: String) {
    let bytes = Array(label.utf8)
    let prefix = Array(Self.labelPrefix.utf8)
    guard bytes.count == prefix.count + 2 + 64, bytes.starts(with: prefix),
      bytes[prefix.count + 1] == UInt8(ascii: ":"),
      let profile = KagemushaWalletAppleKeyProfileV1(rawValue: bytes[prefix.count] &- 0x30),
      let digest = kagemushaWalletAppleParseHex(bytes[(prefix.count + 2)...])
    else { return nil }
    self.init(challengeDigest: digest, profile: profile)
  }

  /// `kgm-w1-binding:<profile tag>:<challenge digest hex>`.
  var label: String {
    Self.labelPrefix + String(profile.rawValue) + ":" + kagemushaWalletAppleHex(challengeDigest)
  }
}

/// Tri-state answer (Rust `KagemushaWalletProbeV1`).
enum KagemushaWalletAppleProbeV1<Value> {
  case present(Value)
  case absent
  case unavailable(KagemushaWalletAppleUnavailableV1)

  func map<Mapped>(_ transform: (Value) -> Mapped) -> KagemushaWalletAppleProbeV1<Mapped> {
    switch self {
    case .present(let value): return .present(transform(value))
    case .absent: return .absent
    case .unavailable(let reason): return .unavailable(reason)
    }
  }
}

extension KagemushaWalletAppleProbeV1: Equatable where Value: Equatable {}

/// Outcome of a payment-key generation (Rust `KagemushaWalletKeyGenerationV1`).
enum KagemushaWalletAppleKeyGenerationV1: Equatable {
  /// A new key exists under the slot's tag; its 65-byte X9.63 public key.
  case generated(publicKey: Data)
  /// A key already exists; it is never replaced.
  case alreadyPresent
  /// Unknown; the provider probes again before acting.
  case unavailable(KagemushaWalletAppleUnavailableV1)
}

/// Why a write did not publish (Rust `KagemushaWalletNotPublishedV1`).
enum KagemushaWalletAppleNotPublishedV1: Equatable {
  case destinationExists
  case destinationAbsent
  case noSpace
  case failed(KagemushaWalletAppleUnavailableV1)
}

/// Outcome of an anchor write (Rust `KagemushaWalletPublishOutcomeV1`).
enum KagemushaWalletApplePublishOutcomeV1: Equatable {
  case published
  case notPublished(KagemushaWalletAppleNotPublishedV1)
  case uncertain(KagemushaWalletAppleUnavailableV1)
}

/// Outcome of a key deletion (Rust `KagemushaWalletRemoveOutcomeV1`).
enum KagemushaWalletAppleRemoveOutcomeV1: Equatable {
  case removed
  case notRemoved(KagemushaWalletAppleUnavailableV1)
  case uncertain(KagemushaWalletAppleUnavailableV1)
}

/// iPhone platform adapter of the KAGEMUSHA wallet Advance provider.
///
/// - The payment key is a Secure Enclave P-256 key (`kSecAttrTokenIDSecureEnclave`) stored
///   permanently under the slot's tag with `.privateKeyUsage` only. It is never bound to user
///   presence or biometry (spec §2.3), never replaced, and signs only as DER through
///   `SecKeyCreateSignature(.ecdsaSignatureMessageX962SHA256)`; Rust normalizes to low S and
///   verifies before any byte is written.
/// - The rollback anchor is one generic-password item per slot, created add-only and read
///   inside protected-data brackets. Its value is the Rust-encoded
///   `{generation, marker_file_digest}`.
/// - Both custody items use ``custodyAccessibility`` (never backed up, synced or migrated) and
///   the app's own keychain access group, never a shared one.
/// - Protected-data state is the readability of a Complete-class canary in the custody root.
///
/// Only an iPhone or iPad app on its own device can construct it: elsewhere file data
/// protection is not enforced. App extensions cannot reach the custody root and must not use
/// this adapter.
public final class KagemushaWalletApplePlatformV1: @unchecked Sendable {
  /// Keychain service of the rollback anchor items.
  public static let anchorService = "org.hyperledger.iroha.kagemusha.wallet.v1.marker-anchor"
  /// Rust `KAGEMUSHA_WALLET_ANCHOR_MAX_BYTES_V1`.
  static let anchorMaxBytes = 256
  /// Rust `KagemushaWalletAnchorPolicyV1::Keychain` tag: this platform keeps an anchor.
  static let anchorPolicyTag: UInt8 = 1
  /// Accessibility of both custody keychain items, the payment key and the rollback anchor:
  /// never backed up, synced, escrowed or migrated (spec §4.2: no backup, restore or
  /// device-transfer path may carry keys or markers); usable only while unlocked, which every
  /// Advance needs anyway because it reads the anchor; rendered useless if the passcode is
  /// removed or reset (lost custody, warned before enrollment, spec §2.3).
  // TODO(owner Q6): the owner has not confirmed this class. Under the alternative A' both items
  // switch together to kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: it survives passcode
  // removal, but Apple copies such items into same-device backups and safety then relies on
  // undocumented Secure Enclave restore behavior.
  static let custodyAccessibility = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
  /// Access-control flags of the payment key: Secure Enclave private-key use only, with no
  /// user-presence, biometry or passcode-entry constraint (spec §2.3).
  static let paymentKeyAccessFlags: SecAccessControlCreateFlags = [.privateKeyUsage]

  /// Keychain access group of every item the adapter adds or queries: the app's own
  /// application identifier `<App ID prefix>.<bundle id>`, so no extension or other app of the
  /// team sharing a group reaches the payment key or the anchor through a default group.
  let accessGroup: String
  let system: KagemushaWalletAppleSystemV1
  let appAttest: any KagemushaWalletAppAttestServiceV1
  private let generationLock = NSLock()
  private let rootStateLock = NSLock()
  private var rootVerified = false

  #if os(iOS) && !targetEnvironment(macCatalyst)
  /// Adapter over the system keychain, Secure Enclave and file system.
  ///
  /// - Parameters:
  ///   - appAttest: App Attest service of enrollment step E5
  ///     (``attestEnrollment(slot:paymentPublicKey:challengeDigest:)``); key generation is
  ///     refused where it is unsupported.
  ///   - applicationIdentifierPrefix: the app's App ID prefix (normally its Team ID); with the
  ///     main bundle identifier it names the app's own keychain access group.
  /// - Throws: ``KagemushaWalletAppleConfigurationErrorV1``.
  public convenience init(
    appAttest: any KagemushaWalletAppAttestServiceV1, applicationIdentifierPrefix: String
  ) throws {
    let group = try KagemushaWalletApplePlatformV1.keychainAccessGroup(
      applicationIdentifierPrefix: applicationIdentifierPrefix,
      bundleIdentifier: Bundle.main.bundleIdentifier)
    self.init(appAttest: appAttest, accessGroup: group, system: .live)
  }

  #if canImport(DeviceCheck)
  /// Adapter using the system App Attest service.
  ///
  /// - Throws: ``KagemushaWalletAppleConfigurationErrorV1``.
  public convenience init(applicationIdentifierPrefix: String) throws {
    try self.init(
      appAttest: KagemushaWalletAppleAppAttestServiceV1(),
      applicationIdentifierPrefix: applicationIdentifierPrefix)
  }
  #endif
  #endif

  init(
    appAttest: any KagemushaWalletAppAttestServiceV1, accessGroup: String,
    system: KagemushaWalletAppleSystemV1
  ) {
    self.appAttest = appAttest
    self.accessGroup = accessGroup
    self.system = system
  }

  /// `<prefix>.<bundle id>` for a 10-character uppercase alphanumeric App ID prefix.
  static func keychainAccessGroup(applicationIdentifierPrefix prefix: String, bundleIdentifier: String?)
    throws -> String
  {
    let bytes = Array(prefix.utf8)
    guard bytes.count == 10,
      bytes.allSatisfy({ (0x30...0x39).contains($0) || (0x41...0x5A).contains($0) })
    else { throw KagemushaWalletAppleConfigurationErrorV1.invalidApplicationIdentifierPrefix }
    guard let bundleIdentifier, !bundleIdentifier.isEmpty else {
      throw KagemushaWalletAppleConfigurationErrorV1.missingBundleIdentifier
    }
    return prefix + "." + bundleIdentifier
  }

  /// Whether ``custodyRootPath()`` last succeeded in this process, which verified the canary.
  var custodyRootVerified: Bool {
    get {
      rootStateLock.lock()
      defer { rootStateLock.unlock() }
      return rootVerified
    }
    set {
      rootStateLock.lock()
      rootVerified = newValue
      rootStateLock.unlock()
    }
  }

  /// Report a condition to the diagnostic log.
  func diagnose(_ event: String, slot: KagemushaWalletAppleSlotV1? = nil, detail: String? = nil) {
    system.diagnostic(
      KagemushaWalletAppleDiagnosticV1(event: event, slot: slot?.keychainName, detail: detail))
  }

  // MARK: - Protected data

  /// Whether protected data is available now: the Complete-class canary opens and reads.
  /// `EPERM` is ``KagemushaWalletAppleUnavailableV1/locked`` or
  /// ``KagemushaWalletAppleUnavailableV1/beforeFirstUnlock``; any other error is `io`.
  /// Unavailable until ``custodyRootPath()`` has verified the canary in this process.
  func storageState() -> Result<Void, KagemushaWalletAppleUnavailableV1> {
    guard system.dataProtectionEnforced() else {
      return .failure(.platform(KagemushaWalletAppleStatusV1.dataProtectionUnavailable))
    }
    guard custodyRootVerified else {
      return .failure(.platform(KagemushaWalletAppleStatusV1.custodyRootNotPrepared))
    }
    switch custodyRootURL() {
    case .failure(let reason):
      return .failure(reason)
    case .success(let root):
      switch system.probeReadable(root.appendingPathComponent(Self.canaryName).path) {
      case 0: return .success(())
      case EPERM: return .failure(lockedReason())
      case let code: return .failure(.io(code))
      }
    }
  }

  /// Run `query` inside protected-data brackets: nothing is queried while storage is
  /// unavailable, and an absent answer counts only if storage was still available afterwards
  /// (a single check races with a lock event).
  func bracketed<Value>(_ query: () -> KagemushaWalletAppleProbeV1<Value>)
    -> KagemushaWalletAppleProbeV1<Value>
  {
    if case .failure(let reason) = storageState() { return .unavailable(reason) }
    let answer = query()
    guard case .absent = answer else { return answer }
    if case .failure(let reason) = storageState() { return .unavailable(reason) }
    return .absent
  }

  // MARK: - Payment key

  /// Keychain query matching every Secure Enclave payment key of the adapter's access group.
  func paymentKeyClassQuery() -> [String: Any] {
    [
      kSecClass as String: kSecClassKey,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecAttrAccessGroup as String: accessGroup,
      kSecUseDataProtectionKeychain as String: true,
    ]
  }

  /// Keychain query matching the slot's payment key.
  func paymentKeyQuery(_ slot: KagemushaWalletAppleSlotV1) -> [String: Any] {
    var query = paymentKeyClassQuery()
    query[kSecAttrApplicationTag as String] = slot.applicationTag
    return query
  }

  /// `SecKeyCreateRandomKey` attributes of the slot's Secure Enclave payment key.
  func paymentKeyGenerationAttributes(
    _ slot: KagemushaWalletAppleSlotV1, _ request: KagemushaWalletAppleKeyGenerationRequestV1,
    accessControl: SecAccessControl
  ) -> [String: Any] {
    [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecUseDataProtectionKeychain as String: true,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: slot.applicationTag,
        kSecAttrLabel as String: request.label,
        kSecAttrAccessGroup as String: accessGroup,
        kSecAttrAccessControl as String: accessControl,
      ] as [String: Any],
    ]
  }

  /// Access control of a new payment key.
  static func paymentKeyAccessControl() -> Result<SecAccessControl, KagemushaWalletAppleUnavailableV1> {
    var error: Unmanaged<CFError>?
    guard
      let access = SecAccessControlCreateWithFlags(
        nil, custodyAccessibility, paymentKeyAccessFlags, &error)
    else {
      return .failure(unavailable(KagemushaWalletAppleSecurityErrorV1(error?.takeRetainedValue())))
    }
    return .success(access)
  }

  /// One payment key found under a slot's tag.
  struct PaymentKeyItem {
    let key: SecKey
    let publicKey: Data
    let label: String?
  }

  /// Look up the slot's payment key (not bracketed). More than one key under the tag is
  /// ambiguous and never selected; a key whose public key cannot be exported is unusable and
  /// is never deleted or regenerated.
  func lookupPaymentKey(_ slot: KagemushaWalletAppleSlotV1)
    -> KagemushaWalletAppleProbeV1<PaymentKeyItem>
  {
    var query = paymentKeyQuery(slot)
    query[kSecReturnRef as String] = true
    query[kSecReturnAttributes as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitAll
    let (status, result) = system.keychain.copyMatching(query)
    switch status {
    case errSecSuccess: break
    case errSecItemNotFound: return .absent
    default: return .unavailable(Self.unavailable(status))
    }
    guard let items = result as? [[String: Any]], !items.isEmpty else {
      diagnose("malformed payment-key lookup", slot: slot)
      return .unavailable(.platform(KagemushaWalletAppleStatusV1.malformedKeychainResult))
    }
    guard items.count == 1 else {
      diagnose("ambiguous payment key", slot: slot, detail: "\(items.count) items")
      return .unavailable(.platform(KagemushaWalletAppleStatusV1.ambiguousPaymentKey))
    }
    guard let reference = items[0][kSecValueRef as String],
      CFGetTypeID(reference as AnyObject) == SecKeyGetTypeID()
    else {
      diagnose("malformed payment-key lookup", slot: slot)
      return .unavailable(.platform(KagemushaWalletAppleStatusV1.malformedKeychainResult))
    }
    let object = reference as AnyObject
    let key = object as! SecKey
    guard let publicKey = Self.x963PublicKey(of: key) else {
      diagnose("payment key public key cannot be exported", slot: slot)
      return .unavailable(.keyUnusable)
    }
    return .present(
      PaymentKeyItem(key: key, publicKey: publicKey, label: items[0][kSecAttrLabel as String] as? String))
  }

  /// 65-byte uncompressed X9.63 public key of `privateKey`.
  static func x963PublicKey(of privateKey: SecKey) -> Data? {
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else { return nil }
    var error: Unmanaged<CFError>?
    guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
      _ = error?.takeRetainedValue()
      return nil
    }
    guard data.count == 65, data.first == 0x04 else { return nil }
    return data
  }

  /// Probe the slot's payment key (Rust `key_probe`).
  func keyProbe(_ slot: KagemushaWalletAppleSlotV1) -> KagemushaWalletAppleProbeV1<Data> {
    bracketed { lookupPaymentKey(slot).map(\.publicKey) }
  }

  /// Generate the slot's payment key (Rust `key_generate`). The provider calls it only after a
  /// definitive absent probe; the adapter probes again under its lock and never replaces a
  /// key. Generation is refused without a Secure Enclave, App Attest support or a device
  /// passcode. Any unknown outcome is unavailable, so the provider probes again before acting.
  func keyGenerate(
    _ slot: KagemushaWalletAppleSlotV1, _ request: KagemushaWalletAppleKeyGenerationRequestV1
  ) -> KagemushaWalletAppleKeyGenerationV1 {
    generationLock.lock()
    defer { generationLock.unlock() }
    switch keyProbe(slot) {
    case .present: return .alreadyPresent
    case .unavailable(let reason): return .unavailable(reason)
    case .absent: break
    }
    guard system.secureEnclaveAvailable() else {
      return .unavailable(.platform(KagemushaWalletAppleStatusV1.secureEnclaveUnavailable))
    }
    guard appAttest.isSupported else {
      return .unavailable(.platform(KagemushaWalletAppleStatusV1.appAttestUnsupported))
    }
    if system.passcodeSet() == false {
      return .unavailable(.platform(KagemushaWalletAppleStatusV1.passcodeNotSet))
    }
    let accessControl: SecAccessControl
    switch Self.paymentKeyAccessControl() {
    case .success(let access): accessControl = access
    case .failure(let reason): return .unavailable(reason)
    }
    let (createdKey, error) = system.keychain.createRandomKey(
      paymentKeyGenerationAttributes(slot, request, accessControl: accessControl))
    guard let created = createdKey else {
      let failure = error ?? KagemushaWalletAppleSecurityErrorV1(nil)
      if failure.osStatus == errSecDuplicateItem { return .alreadyPresent }
      return .unavailable(securityFailure("payment key generation failed", slot: slot, failure))
    }
    guard let publicKey = Self.x963PublicKey(of: created) else {
      diagnose("generated payment key public key cannot be exported", slot: slot)
      return .unavailable(.keyUnusable)
    }
    switch keyProbe(slot) {
    case .present(let stored) where stored == publicKey:
      return .generated(publicKey: publicKey)
    case .present:
      diagnose("generated payment key differs from the stored key", slot: slot)
      return .unavailable(.platform(KagemushaWalletAppleStatusV1.ambiguousPaymentKey))
    case .absent:
      diagnose("generated payment key not found under its tag", slot: slot)
      return .unavailable(.platform(KagemushaWalletAppleStatusV1.paymentKeyNotPersisted))
    case .unavailable(let reason):
      return .unavailable(reason)
    }
  }

  /// Sign the exact 32-byte canonical message with the slot's payment key (Rust `key_sign`).
  /// The Secure Enclave signs `SHA-256(message)` and returns strict DER. Only the Rust
  /// role-checked signers construct messages; this method stays internal for that reason. It is
  /// not bracketed, so a locked keychain is told apart from one not yet unlocked since boot.
  func keySign(_ slot: KagemushaWalletAppleSlotV1, message: Data)
    -> Result<Data, KagemushaWalletAppleUnavailableV1>
  {
    guard message.count == 32 else { return .failure(.keyUnusable) }
    let signed: Result<Data, KagemushaWalletAppleUnavailableV1>
    switch lookupPaymentKey(slot) {
    case .present(let item): signed = sign(item.key, slot: slot, message: message)
    case .absent: signed = .failure(.platform(errSecItemNotFound))
    case .unavailable(let reason): signed = .failure(reason)
    }
    if case .failure(.locked) = signed { return .failure(lockedReason()) }
    return signed
  }

  /// DER ECDSA P-256 / SHA-256 over `message` with `key`.
  func sign(_ key: SecKey, slot: KagemushaWalletAppleSlotV1, message: Data)
    -> Result<Data, KagemushaWalletAppleUnavailableV1>
  {
    guard message.count == 32 else { return .failure(.keyUnusable) }
    let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
    guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
      diagnose("payment key does not support ECDSA P-256 SHA-256 signing", slot: slot)
      return .failure(.keyUnusable)
    }
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(key, algorithm, message as CFData, &error) as Data?
    else {
      return .failure(
        securityFailure(
          "payment key signing failed", slot: slot,
          KagemushaWalletAppleSecurityErrorV1(error?.takeRetainedValue())))
    }
    return .success(signature)
  }

  /// Delete the slot's payment key (Rust `key_delete`, custody deletion step D3 only).
  /// Removed only when a bracketed probe afterwards finds no key.
  func keyDelete(_ slot: KagemushaWalletAppleSlotV1) -> KagemushaWalletAppleRemoveOutcomeV1 {
    if case .failure(let reason) = storageState() { return .notRemoved(reason) }
    let status = system.keychain.delete(paymentKeyQuery(slot))
    guard status == errSecSuccess || status == errSecItemNotFound else {
      return Self.definitelyNotPerformed(status)
        ? .notRemoved(Self.unavailable(status)) : .uncertain(Self.unavailable(status))
    }
    switch keyProbe(slot) {
    case .absent: return .removed
    case .present: return .uncertain(.platform(errSecDuplicateItem))
    case .unavailable(let reason): return .uncertain(reason)
    }
  }

  /// Slots of every payment key in the adapter's access group, sorted by slot bytes (design
  /// R10: a payment-key item whose slot has no files is `LostCustody(KeyWithoutMarker)` after
  /// delete and reinstall). Empty only for `errSecItemNotFound` inside protected-data
  /// brackets. Tags are parsed strictly; a key with another tag is not a wallet key, and a
  /// malformed `kgm-w1-` tag is reported and never read as a slot.
  // TODO(G2-bridge): expose as a vtable entry once the Rust trait gains the key enumeration
  // that reconcile.rs `TODO(G2-iOS)` (R10, KeyWithoutMarker) asks for.
  func keyEnumerate() -> Result<[KagemushaWalletAppleSlotV1], KagemushaWalletAppleUnavailableV1> {
    let answer = bracketed { () -> KagemushaWalletAppleProbeV1<[KagemushaWalletAppleSlotV1]> in
      var query = paymentKeyClassQuery()
      query[kSecReturnAttributes as String] = true
      query[kSecMatchLimit as String] = kSecMatchLimitAll
      let (status, result) = system.keychain.copyMatching(query)
      switch status {
      case errSecSuccess: break
      case errSecItemNotFound: return .absent
      default: return .unavailable(Self.unavailable(status))
      }
      guard let items = result as? [[String: Any]] else {
        diagnose("malformed payment-key enumeration")
        return .unavailable(.platform(KagemushaWalletAppleStatusV1.malformedKeychainResult))
      }
      var slots = Set<KagemushaWalletAppleSlotV1>()
      let walletPrefix = Data(KagemushaWalletAppleSlotV1.keychainNamePrefix.utf8)
      for item in items {
        guard let tag = item[kSecAttrApplicationTag as String] as? Data else { continue }
        if let slot = KagemushaWalletAppleSlotV1(applicationTag: tag) {
          slots.insert(slot)
        } else if tag.starts(with: walletPrefix) {
          diagnose("malformed wallet payment-key tag", detail: "\(tag.count) bytes")
        }
      }
      return .present(slots.sorted { $0.bytes.lexicographicallyPrecedes($1.bytes) })
    }
    switch answer {
    case .present(let slots): return .success(slots)
    case .absent: return .success([])
    case .unavailable(let reason): return .failure(reason)
    }
  }

  // MARK: - Rollback anchor

  /// Keychain query matching the slot's anchor item. With the access group pinned, the
  /// keychain's uniqueness of (group, service, account, synchronizable) leaves at most one
  /// match.
  func anchorQuery(_ slot: KagemushaWalletAppleSlotV1) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.anchorService,
      kSecAttrAccount as String: slot.keychainName,
      kSecAttrAccessGroup as String: accessGroup,
      kSecAttrSynchronizable as String: false,
      kSecUseDataProtectionKeychain as String: true,
    ]
  }

  /// `SecItemAdd` attributes of the slot's anchor item holding `value`.
  func anchorAddAttributes(_ slot: KagemushaWalletAppleSlotV1, value: Data) -> [String: Any] {
    var attributes = anchorQuery(slot)
    attributes[kSecAttrAccessible as String] = Self.custodyAccessibility
    attributes[kSecValueData as String] = value
    return attributes
  }

  private static func validAnchorValue(_ value: Data) -> Bool {
    !value.isEmpty && value.count <= anchorMaxBytes
  }

  /// Add the slot's anchor item (Rust `anchor_create`; add-only). Refused while locked or
  /// without a device passcode.
  func anchorCreate(_ slot: KagemushaWalletAppleSlotV1, value: Data)
    -> KagemushaWalletApplePublishOutcomeV1
  {
    guard Self.validAnchorValue(value) else {
      return .notPublished(.failed(.platform(KagemushaWalletAppleStatusV1.invalidAnchorValue)))
    }
    if case .failure(let reason) = storageState() { return .notPublished(.failed(reason)) }
    if system.passcodeSet() == false {
      return .notPublished(.failed(.platform(KagemushaWalletAppleStatusV1.passcodeNotSet)))
    }
    return Self.addOutcome(system.keychain.add(anchorAddAttributes(slot, value: value)))
  }

  /// Read the slot's anchor item (Rust `anchor_read`) inside protected-data brackets.
  func anchorRead(_ slot: KagemushaWalletAppleSlotV1) -> KagemushaWalletAppleProbeV1<Data> {
    bracketed {
      var query = anchorQuery(slot)
      query[kSecReturnData as String] = true
      query[kSecMatchLimit as String] = kSecMatchLimitOne
      let (status, result) = system.keychain.copyMatching(query)
      switch status {
      case errSecSuccess:
        guard let data = result as? Data else {
          diagnose("malformed anchor read", slot: slot)
          return .unavailable(.platform(KagemushaWalletAppleStatusV1.malformedKeychainResult))
        }
        return .present(data)
      case errSecItemNotFound:
        return .absent
      default:
        return .unavailable(Self.unavailable(status))
      }
    }
  }

  /// Replace the value of the slot's anchor item (Rust `anchor_update`). The provider raises
  /// it only to a durable marker and re-reads it after an uncertain outcome.
  func anchorUpdate(_ slot: KagemushaWalletAppleSlotV1, value: Data)
    -> KagemushaWalletApplePublishOutcomeV1
  {
    guard Self.validAnchorValue(value) else {
      return .notPublished(.failed(.platform(KagemushaWalletAppleStatusV1.invalidAnchorValue)))
    }
    if case .failure(let reason) = storageState() { return .notPublished(.failed(reason)) }
    return Self.updateOutcome(
      system.keychain.update(anchorQuery(slot), [kSecValueData as String: value]))
  }

  // MARK: - Status mapping

  /// Reason of a non-success keychain status: `errSecInteractionNotAllowed` is locked, every
  /// other status (including `errSecItemNotFound` outside a probe) is `platform(status)`.
  static func unavailable(_ status: OSStatus) -> KagemushaWalletAppleUnavailableV1 {
    status == errSecInteractionNotAllowed ? .locked : .platform(status)
  }

  /// Reason of a failed Security call: an `OSStatus` as above; any other error domain is
  /// ``KagemushaWalletAppleStatusV1/nonOSStatusError``, never a colliding `OSStatus`.
  static func unavailable(_ error: KagemushaWalletAppleSecurityErrorV1)
    -> KagemushaWalletAppleUnavailableV1
  {
    guard let status = error.osStatus else {
      return .platform(KagemushaWalletAppleStatusV1.nonOSStatusError)
    }
    return unavailable(status)
  }

  /// Reason of a failed Security call, with a diagnostic carrying its domain and code unless
  /// the keychain was merely locked.
  func securityFailure(
    _ event: String, slot: KagemushaWalletAppleSlotV1, _ error: KagemushaWalletAppleSecurityErrorV1
  ) -> KagemushaWalletAppleUnavailableV1 {
    let reason = Self.unavailable(error)
    if reason != .locked { diagnose(event, slot: slot, detail: error.detail) }
    return reason
  }

  /// Statuses with which the keychain refused before changing anything. Every other failure
  /// of a write is uncertain and reconciled by re-reading.
  static func definitelyNotPerformed(_ status: OSStatus) -> Bool {
    [
      errSecInteractionNotAllowed, errSecParam, errSecMissingEntitlement, errSecNotAvailable,
      errSecUnimplemented, errSecNoSuchAttr, errSecDiskFull,
    ].contains(status)
  }

  static func addOutcome(_ status: OSStatus) -> KagemushaWalletApplePublishOutcomeV1 {
    switch status {
    case errSecSuccess: return .published
    case errSecDuplicateItem: return .notPublished(.destinationExists)
    default: return writeFailure(status)
    }
  }

  static func updateOutcome(_ status: OSStatus) -> KagemushaWalletApplePublishOutcomeV1 {
    switch status {
    case errSecSuccess: return .published
    case errSecItemNotFound: return .notPublished(.destinationAbsent)
    default: return writeFailure(status)
    }
  }

  private static func writeFailure(_ status: OSStatus) -> KagemushaWalletApplePublishOutcomeV1 {
    if status == errSecDiskFull { return .notPublished(.noSpace) }
    return definitelyNotPerformed(status)
      ? .notPublished(.failed(unavailable(status))) : .uncertain(unavailable(status))
  }
}

/// Lowercase hex of `bytes`.
func kagemushaWalletAppleHex<Bytes: Sequence>(_ bytes: Bytes) -> String where Bytes.Element == UInt8 {
  let digits = Array("0123456789abcdef".utf8)
  var text = [UInt8]()
  for byte in bytes {
    text.append(digits[Int(byte >> 4)])
    text.append(digits[Int(byte & 0x0f)])
  }
  return String(decoding: text, as: UTF8.self)
}

/// Strict lowercase hex; `nil` for an odd length or any other character.
func kagemushaWalletAppleParseHex<Text: Collection>(_ text: Text) -> Data? where Text.Element == UInt8 {
  guard text.count % 2 == 0 else { return nil }
  func value(_ digit: UInt8) -> UInt8? {
    switch digit {
    case 0x30...0x39: return digit - 0x30
    case 0x61...0x66: return digit - 0x61 + 10
    default: return nil
    }
  }
  var bytes = Data()
  var high: UInt8?
  for digit in text {
    guard let nibble = value(digit) else { return nil }
    if let first = high {
      bytes.append(first << 4 | nibble)
      high = nil
    } else {
      high = nibble
    }
  }
  return bytes
}
