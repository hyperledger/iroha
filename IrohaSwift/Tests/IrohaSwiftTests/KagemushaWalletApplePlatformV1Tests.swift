import CryptoKit
import Darwin
import Foundation
import Security
import XCTest

@testable import IrohaSwift

/// In-memory keychain: payment keys are software P-256 keys (a Secure Enclave is not needed to
/// exercise the adapter's logic), generic passwords are byte values.
private final class FakeWalletKeychain: KagemushaWalletAppleKeychainV1, @unchecked Sendable {
  /// What a successful generation leaves under the requested tag.
  enum Persistence {
    case generated
    case nothing
    case differentKey
  }

  private struct StoredKey {
    let tag: Data?
    let label: String?
    let key: SecKey
  }

  private let lock = NSLock()
  private var keys: [StoredKey] = []
  private var passwords: [String: Data] = [:]
  private var log: [String] = []
  private var queryLog: [[String: Any]] = []
  private var generations: [[String: Any]] = []

  var copyStatus: OSStatus?
  var copyResultOverride: CFTypeRef??
  var addStatus: OSStatus?
  var updateStatus: OSStatus?
  var deleteStatus: OSStatus?
  var createError: KagemushaWalletAppleSecurityErrorV1?
  var persistence = Persistence.generated

  var operations: [String] { locked { log } }
  var queries: [[String: Any]] { locked { queryLog } }
  var generationAttributes: [[String: Any]] { locked { generations } }

  static func softwareKey() -> SecKey {
    var error: Unmanaged<CFError>?
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
    ]
    return SecKeyCreateRandomKey(attributes as CFDictionary, &error)!
  }

  @discardableResult
  func storeKey(tag: Data?, label: String?, key: SecKey = FakeWalletKeychain.softwareKey()) -> SecKey {
    locked { keys.append(StoredKey(tag: tag, label: label, key: key)) }
    return key
  }

  func copyMatching(_ query: [String: Any]) -> (status: OSStatus, result: CFTypeRef?) {
    locked {
      log.append("copy")
      queryLog.append(query)
      if let copyStatus { return (copyStatus, copyResultOverride ?? nil) }
      if let override = copyResultOverride { return (errSecSuccess, override) }
      if Self.isKey(query) {
        let tag = query[kSecAttrApplicationTag as String] as? Data
        let matches = tag == nil ? keys : keys.filter { $0.tag == tag }
        guard !matches.isEmpty else { return (errSecItemNotFound, nil) }
        let items: [[String: Any]] = matches.map { stored in
          var item: [String: Any] = [kSecValueRef as String: stored.key]
          if let tag = stored.tag { item[kSecAttrApplicationTag as String] = tag }
          if let label = stored.label { item[kSecAttrLabel as String] = label }
          return item
        }
        return (errSecSuccess, items as NSArray)
      }
      guard let value = passwords[Self.passwordName(query)] else { return (errSecItemNotFound, nil) }
      return (errSecSuccess, value as NSData)
    }
  }

  func add(_ attributes: [String: Any]) -> OSStatus {
    locked {
      log.append("add")
      queryLog.append(attributes)
      if let addStatus { return addStatus }
      let name = Self.passwordName(attributes)
      guard passwords[name] == nil else { return errSecDuplicateItem }
      passwords[name] = attributes[kSecValueData as String] as? Data
      return errSecSuccess
    }
  }

  func update(_ query: [String: Any], _ attributes: [String: Any]) -> OSStatus {
    locked {
      log.append("update")
      queryLog.append(query)
      if let updateStatus { return updateStatus }
      let name = Self.passwordName(query)
      guard passwords[name] != nil else { return errSecItemNotFound }
      passwords[name] = attributes[kSecValueData as String] as? Data
      return errSecSuccess
    }
  }

  func delete(_ query: [String: Any]) -> OSStatus {
    locked {
      log.append("delete")
      queryLog.append(query)
      if let deleteStatus { return deleteStatus }
      let tag = query[kSecAttrApplicationTag as String] as? Data
      let before = keys.count
      keys.removeAll { $0.tag == tag }
      return keys.count == before ? errSecItemNotFound : errSecSuccess
    }
  }

  func createRandomKey(_ attributes: [String: Any])
    -> (key: SecKey?, error: KagemushaWalletAppleSecurityErrorV1?)
  {
    locked {
      log.append("create")
      generations.append(attributes)
      if let createError { return (nil, createError) }
      let key = Self.softwareKey()
      let privateAttributes = attributes[kSecPrivateKeyAttrs as String] as? [String: Any] ?? [:]
      if let tag = privateAttributes[kSecAttrApplicationTag as String] as? Data {
        let label = privateAttributes[kSecAttrLabel as String] as? String
        switch persistence {
        case .generated: keys.append(StoredKey(tag: tag, label: label, key: key))
        case .nothing: break
        case .differentKey: keys.append(StoredKey(tag: tag, label: label, key: Self.softwareKey()))
        }
      }
      return (key, nil)
    }
  }

  private static func isKey(_ query: [String: Any]) -> Bool {
    (query[kSecClass as String] as? String) == (kSecClassKey as String)
  }

  private static func passwordName(_ query: [String: Any]) -> String {
    "\(query[kSecAttrService as String] as? String ?? "")\u{0}\(query[kSecAttrAccount as String] as? String ?? "")"
  }

  private func locked<T>(_ body: () -> T) -> T {
    lock.lock()
    defer { lock.unlock() }
    return body()
  }
}

/// Scripted protected-data probes: queued `errno` answers for the canary (then `0`), and a
/// fixed answer for the first-unlock probe.
private final class FakeProtectedData: @unchecked Sendable {
  private let lock = NSLock()
  private var queue: [Int32] = []
  private var canaryCount = 0
  private var firstUnlockCount = 0
  private var firstUnlockCode: Int32 = 0

  var firstUnlock: Int32 {
    get { locked { firstUnlockCode } }
    set { locked { firstUnlockCode = newValue } }
  }

  func push(_ codes: Int32...) {
    locked { queue.append(contentsOf: codes) }
  }

  func probe(_ path: String) -> Int32 {
    locked {
      switch (path as NSString).lastPathComponent {
      case KagemushaWalletApplePlatformV1.canaryName:
        canaryCount += 1
        return queue.isEmpty ? 0 : queue.removeFirst()
      case KagemushaWalletApplePlatformV1.firstUnlockProbeName:
        firstUnlockCount += 1
        return firstUnlockCode
      default:
        return ENOENT
      }
    }
  }

  var canaryReads: Int { locked { canaryCount } }
  var firstUnlockReads: Int { locked { firstUnlockCount } }

  private func locked<T>(_ body: () -> T) -> T {
    lock.lock()
    defer { lock.unlock() }
    return body()
  }
}

/// File protection classes by path: `initial` until a class is set.
private final class FakeFileProtection: @unchecked Sendable {
  private let lock = NSLock()
  private var classes: [String: FileProtectionType] = [:]
  private var readCount = 0
  private var setCount = 0
  var initial: FileProtectionType? = .complete
  var readFailure: KagemushaWalletAppleUnavailableV1?
  var setFailure: KagemushaWalletAppleUnavailableV1?
  var setTakesEffect = true

  func read(_ path: String) -> Result<FileProtectionType?, KagemushaWalletAppleUnavailableV1> {
    locked {
      readCount += 1
      if let readFailure { return .failure(readFailure) }
      if let stored = classes[path] { return .success(stored) }
      return .success(initial)
    }
  }

  func set(_ path: String, _ protection: FileProtectionType)
    -> Result<Void, KagemushaWalletAppleUnavailableV1>
  {
    locked {
      setCount += 1
      if let setFailure { return .failure(setFailure) }
      if setTakesEffect { classes[path] = protection }
      return .success(())
    }
  }

  var reads: Int { locked { readCount } }
  var sets: Int { locked { setCount } }

  private func locked<T>(_ body: () -> T) -> T {
    lock.lock()
    defer { lock.unlock() }
    return body()
  }
}

/// Recording diagnostic sink.
private final class DiagnosticLog: @unchecked Sendable {
  private let lock = NSLock()
  private var entries: [KagemushaWalletAppleDiagnosticV1] = []

  func record(_ entry: KagemushaWalletAppleDiagnosticV1) {
    lock.lock()
    entries.append(entry)
    lock.unlock()
  }

  var all: [KagemushaWalletAppleDiagnosticV1] {
    lock.lock()
    defer { lock.unlock() }
    return entries
  }
}

/// The error a failing fake App Attest stage throws (`DCError.serverUnavailable`).
private let appAttestServerUnavailable = NSError(domain: "com.apple.devicecheck.error", code: 4)

private final class FakeWalletAppAttest: KagemushaWalletAppAttestServiceV1, @unchecked Sendable {
  private let lock = NSLock()
  private var log: [String] = []
  private var keyCount = 0
  var supported = true
  var failingStage: KagemushaWalletAppleAppAttestStageV1?
  var malformedKeyIDs = false

  var isSupported: Bool { supported }
  var calls: [String] {
    lock.lock()
    defer { lock.unlock() }
    return log
  }

  /// Identifier of the `index`-th generated key: base64 of 32 bytes.
  static func keyID(_ index: Int) -> String {
    Data(repeating: UInt8(index), count: 32).base64EncodedString()
  }

  func generateKey() async throws -> String {
    let index = nextKeyIndex()
    try check(.generateKey)
    return malformedKeyIDs ? Data(repeating: 1, count: 31).base64EncodedString() : Self.keyID(index)
  }

  func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data {
    record("attestKey:\(keyID):\(kagemushaWalletAppleHex(clientDataHash))")
    try check(.attestKey)
    return Data("attestation".utf8) + clientDataHash
  }

  func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
    record("generateAssertion:\(keyID):\(kagemushaWalletAppleHex(clientDataHash))")
    try check(.generateAssertion)
    return Data("assertion".utf8) + clientDataHash
  }

  private func nextKeyIndex() -> Int {
    lock.lock()
    defer { lock.unlock() }
    keyCount += 1
    log.append("generateKey")
    return keyCount
  }

  private func record(_ entry: String) {
    lock.lock()
    log.append(entry)
    lock.unlock()
  }

  private func check(_ stage: KagemushaWalletAppleAppAttestStageV1) throws {
    if failingStage == stage { throw appAttestServerUnavailable }
  }
}

private enum ApplePlatformFixtureFailure: Error {
  case missingFixture
  case malformed(String)
}

/// Locates `fixtures/kagemusha/wallet_v1_vectors.json` by walking up from this source file.
private func applePlatformFixtureURL() throws -> URL {
  var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
  for _ in 0..<8 {
    let candidate = directory.appendingPathComponent("fixtures/kagemusha/wallet_v1_vectors.json")
    if FileManager.default.fileExists(atPath: candidate.path) { return candidate }
    directory.deleteLastPathComponent()
  }
  throw ApplePlatformFixtureFailure.missingFixture
}

final class KagemushaWalletApplePlatformV1Tests: XCTestCase {
  private typealias Platform = KagemushaWalletApplePlatformV1
  private typealias SecurityError = KagemushaWalletAppleSecurityErrorV1
  private typealias Status = KagemushaWalletAppleStatusV1

  private static let accessGroup = "ABCDE12345.org.hyperledger.iroha.wallet-tests"
  private let slot = KagemushaWalletAppleSlotV1(Data((1...32).map { UInt8($0) }))!
  private let challenge = Data(repeating: 0xc4, count: 32)

  private func makePlatform(
    keychain: FakeWalletKeychain = FakeWalletKeychain(),
    probe: FakeProtectedData = FakeProtectedData(),
    protection: FakeFileProtection = FakeFileProtection(),
    diagnostics: DiagnosticLog = DiagnosticLog(),
    appAttest: FakeWalletAppAttest = FakeWalletAppAttest(), secureEnclave: Bool = true,
    passcode: Bool? = true, dataProtection: Bool = true, base: URL? = nil,
    prepared: Bool = true, liveProbe: Bool = false,
    sysctl: @escaping @Sendable (String) -> Result<[UInt8], KagemushaWalletAppleUnavailableV1> = {
      _ in .failure(.io(ENOENT))
    }
  ) throws -> KagemushaWalletApplePlatformV1 {
    let directory: URL
    if let base {
      directory = base
    } else {
      directory = try temporaryDirectory()
    }
    var probeReadable: @Sendable (String) -> Int32 = { probe.probe($0) }
    if liveProbe { probeReadable = KagemushaWalletAppleSystemV1.live.probeReadable }
    let system = KagemushaWalletAppleSystemV1(
      keychain: keychain, secureEnclaveAvailable: { secureEnclave }, passcodeSet: { passcode },
      dataProtectionEnforced: { dataProtection },
      applicationSupportDirectory: { .success(directory) }, probeReadable: probeReadable,
      fileProtection: { protection.read($0) }, setFileProtection: { protection.set($0, $1) },
      sysctl: sysctl, diagnostic: { diagnostics.record($0) })
    let platform = KagemushaWalletApplePlatformV1(
      appAttest: appAttest, accessGroup: Self.accessGroup, system: system)
    if prepared {
      _ = try platform.custodyRootPath().get()
    }
    return platform
  }

  private func request(
    _ profile: KagemushaWalletAppleKeyProfileV1 = .secureElement
  ) -> KagemushaWalletAppleKeyGenerationRequestV1 {
    KagemushaWalletAppleKeyGenerationRequestV1(challengeDigest: challenge, profile: profile)!
  }

  private func temporaryDirectory() throws -> URL {
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("kagemusha-wallet-apple-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
    return directory
  }

  private func failure<Success>(
    _ result: Result<Success, KagemushaWalletAppleUnavailableV1>
  ) -> KagemushaWalletAppleUnavailableV1? {
    if case .failure(let reason) = result { return reason }
    return nil
  }

  private func generatedKey(_ platform: KagemushaWalletApplePlatformV1) throws -> Data {
    guard case .generated(let publicKey) = platform.keyGenerate(slot, request()) else {
      XCTFail("payment key was not generated")
      throw ApplePlatformFixtureFailure.malformed("generation")
    }
    return publicKey
  }

  private static func cfError(_ domain: String, _ code: Int) -> CFError {
    CFErrorCreate(nil, domain as CFString, code, nil)
  }

  private static func isExcludedFromBackup(_ path: String) throws -> Bool? {
    try URL(fileURLWithPath: path, isDirectory: true)
      .resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup
  }

  // MARK: Configuration, slot and generation binding

  func testKeychainAccessGroupIsTheAppsOwnApplicationIdentifier() throws {
    XCTAssertEqual(
      try Platform.keychainAccessGroup(
        applicationIdentifierPrefix: "ABCDE12345", bundleIdentifier: "org.example.wallet"),
      "ABCDE12345.org.example.wallet")
    for prefix in ["ABCDE1234", "ABCDE123456", "abcde12345", "ABCDE.1234", "", "ABCDE1234É"] {
      XCTAssertThrowsError(
        try Platform.keychainAccessGroup(
          applicationIdentifierPrefix: prefix, bundleIdentifier: "org.example.wallet"), prefix
      ) { error in
        XCTAssertEqual(
          error as? KagemushaWalletAppleConfigurationErrorV1, .invalidApplicationIdentifierPrefix)
      }
    }
    for bundle in [nil, ""] as [String?] {
      XCTAssertThrowsError(
        try Platform.keychainAccessGroup(
          applicationIdentifierPrefix: "ABCDE12345", bundleIdentifier: bundle)
      ) { error in
        XCTAssertEqual(error as? KagemushaWalletAppleConfigurationErrorV1, .missingBundleIdentifier)
      }
    }
  }

  func testSlotRequiresThirtyTwoNonzeroBytesAndNamesTheKeychainItems() {
    XCTAssertEqual(
      slot.keychainName,
      "kgm-w1-0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
    XCTAssertEqual(slot.applicationTag, Data(slot.keychainName.utf8))
    XCTAssertNil(KagemushaWalletAppleSlotV1(Data(repeating: 1, count: 31)))
    XCTAssertNil(KagemushaWalletAppleSlotV1(Data(repeating: 1, count: 33)))
    XCTAssertNil(KagemushaWalletAppleSlotV1(Data(repeating: 0, count: 32)))

    XCTAssertEqual(KagemushaWalletAppleSlotV1(applicationTag: slot.applicationTag), slot)
    let hex = kagemushaWalletAppleHex(slot.bytes)
    for tag in [
      "kgm-w1-" + hex.uppercased(), "kgm-w1-" + hex.dropLast(2), "kgm-w1-" + hex + "00",
      "kgm-w2-" + hex, "kgm-w1:" + hex, "kgm-w1-" + String(repeating: "0", count: 64), "",
    ] {
      XCTAssertNil(KagemushaWalletAppleSlotV1(applicationTag: Data(tag.utf8)), tag)
    }
  }

  func testGenerationLabelBindsChallengeAndProfileAndParsesStrictly() {
    let bound = request(.secureElementOrTee)
    XCTAssertEqual(bound.label, "kgm-w1-binding:2:" + String(repeating: "c4", count: 32))
    XCTAssertEqual(KagemushaWalletAppleKeyGenerationRequestV1(label: bound.label), bound)
    XCTAssertEqual(
      KagemushaWalletAppleKeyGenerationRequestV1(label: request(.secureElement).label)?.profile,
      .secureElement)
    let digest = String(repeating: "c4", count: 32)
    for label in [
      "kgm-w1-binding:3:" + digest, "kgm-w1-binding:0:" + digest,
      "kgm-w1-binding:1:" + digest.uppercased(), "kgm-w1-binding:1-" + digest,
      "kgm-w1-binding:1:" + digest.dropLast(2), "kgm-w1-binding:1:" + digest + "00",
      "kgm-w1-bindinG:1:" + digest, "",
    ] {
      XCTAssertNil(KagemushaWalletAppleKeyGenerationRequestV1(label: label), label)
    }
    XCTAssertNil(
      KagemushaWalletAppleKeyGenerationRequestV1(
        challengeDigest: Data(repeating: 1, count: 31), profile: .secureElement))
  }

  // MARK: Status mapping

  func testKeychainStatusesMapToTriStateAndExplicitWriteOutcomes() {
    XCTAssertEqual(Platform.unavailable(errSecInteractionNotAllowed), .locked)
    XCTAssertEqual(Platform.unavailable(errSecItemNotFound), .platform(errSecItemNotFound))
    XCTAssertEqual(Platform.unavailable(errSecIO), .platform(errSecIO))

    XCTAssertEqual(Platform.addOutcome(errSecSuccess), .published)
    XCTAssertEqual(Platform.addOutcome(errSecDuplicateItem), .notPublished(.destinationExists))
    XCTAssertEqual(Platform.addOutcome(errSecInteractionNotAllowed), .notPublished(.failed(.locked)))
    XCTAssertEqual(Platform.addOutcome(errSecDiskFull), .notPublished(.noSpace))
    XCTAssertEqual(Platform.addOutcome(errSecParam), .notPublished(.failed(.platform(errSecParam))))
    XCTAssertEqual(
      Platform.addOutcome(errSecMissingEntitlement),
      .notPublished(.failed(.platform(errSecMissingEntitlement))))
    XCTAssertEqual(Platform.addOutcome(errSecIO), .uncertain(.platform(errSecIO)))
    XCTAssertEqual(
      Platform.addOutcome(errSecInternalComponent), .uncertain(.platform(errSecInternalComponent)))

    XCTAssertEqual(Platform.updateOutcome(errSecSuccess), .published)
    XCTAssertEqual(Platform.updateOutcome(errSecItemNotFound), .notPublished(.destinationAbsent))
    XCTAssertEqual(Platform.updateOutcome(errSecInteractionNotAllowed), .notPublished(.failed(.locked)))
    XCTAssertEqual(Platform.updateOutcome(errSecIO), .uncertain(.platform(errSecIO)))
  }

  func testSecurityErrorsKeepTheirDomainAndNeverReadAsAnOSStatus() throws {
    let osStatus = SecurityError(Self.cfError(NSOSStatusErrorDomain, Int(errSecIO)))
    XCTAssertEqual(osStatus, SecurityError(status: errSecIO))
    XCTAssertEqual(osStatus.osStatus, errSecIO)
    XCTAssertEqual(Platform.unavailable(osStatus), .platform(errSecIO))
    XCTAssertEqual(Platform.unavailable(SecurityError(status: errSecInteractionNotAllowed)), .locked)
    XCTAssertEqual(SecurityError(nil), SecurityError(status: errSecInternalComponent))

    // TKError.canceledByUser (-4) must not read as errSecUnimplemented (-4).
    let token = SecurityError(Self.cfError("CryptoTokenKit", -4))
    XCTAssertEqual(token.domain, "CryptoTokenKit")
    XCTAssertEqual(token.code, -4)
    XCTAssertNil(token.osStatus)
    XCTAssertEqual(Platform.unavailable(token), .platform(Status.nonOSStatusError))
    XCTAssertNotEqual(Platform.unavailable(token), .platform(errSecUnimplemented))
    let authentication = SecurityError(Self.cfError("com.apple.LocalAuthentication", -1004))
    XCTAssertEqual(Platform.unavailable(authentication), .platform(Status.nonOSStatusError))
    let outOfRange = SecurityError(domain: NSOSStatusErrorDomain, code: Int(Int32.max) + 1)
    XCTAssertNil(outOfRange.osStatus)
    XCTAssertEqual(Platform.unavailable(outOfRange), .platform(Status.nonOSStatusError))

    let diagnostics = DiagnosticLog()
    let platform = try makePlatform(diagnostics: diagnostics)
    XCTAssertEqual(
      platform.securityFailure(
        "payment key signing failed", slot: slot, SecurityError(status: errSecInteractionNotAllowed)),
      .locked)
    XCTAssertEqual(diagnostics.all, [], "a locked keychain is routine, not a diagnostic")
    XCTAssertEqual(
      platform.securityFailure("payment key signing failed", slot: slot, token),
      .platform(Status.nonOSStatusError))
    XCTAssertEqual(
      platform.securityFailure("payment key signing failed", slot: slot, osStatus),
      .platform(errSecIO))
    XCTAssertEqual(
      diagnostics.all,
      [
        KagemushaWalletAppleDiagnosticV1(
          event: "payment key signing failed", slot: slot.keychainName, detail: "CryptoTokenKit -4"),
        KagemushaWalletAppleDiagnosticV1(
          event: "payment key signing failed", slot: slot.keychainName,
          detail: "\(NSOSStatusErrorDomain) \(errSecIO)"),
      ])
    // The live sink writes to the unified log without failing.
    KagemushaWalletAppleSystemV1.live.diagnostic(diagnostics.all[0])
  }

  // MARK: Protected data

  func testStorageStateNeedsAPreparedRootAndEnforcedDataProtection() throws {
    let keychain = FakeWalletKeychain()
    let base = try temporaryDirectory()
    let unprepared = try makePlatform(keychain: keychain, base: base, prepared: false)
    let notPrepared = KagemushaWalletAppleUnavailableV1.platform(Status.custodyRootNotPrepared)
    XCTAssertEqual(failure(unprepared.storageState()), notPrepared)
    XCTAssertEqual(unprepared.keyProbe(slot), .unavailable(notPrepared))
    XCTAssertEqual(unprepared.anchorRead(slot), .unavailable(notPrepared))
    XCTAssertEqual(keychain.operations, [], "no keychain query before the canary is verified")

    let unprotected = try makePlatform(keychain: keychain, dataProtection: false, prepared: false)
    let refused = KagemushaWalletAppleUnavailableV1.platform(Status.dataProtectionUnavailable)
    XCTAssertEqual(failure(unprotected.custodyRootPath()), refused)
    XCTAssertEqual(failure(unprotected.storageState()), refused)
    XCTAssertEqual(unprotected.keyProbe(slot), .unavailable(refused))
    XCTAssertEqual(unprotected.keyGenerate(slot, request()), .unavailable(refused))
    XCTAssertEqual(unprotected.keyDelete(slot), .notRemoved(refused))
    XCTAssertEqual(
      unprotected.anchorCreate(slot, value: Data([1])), .notPublished(.failed(refused)))
    XCTAssertEqual(keychain.operations, [])
    let unprotectedBase = try XCTUnwrap(try? unprotected.system.applicationSupportDirectory().get())
    XCTAssertEqual(
      try FileManager.default.contentsOfDirectory(atPath: unprotectedBase.path), [],
      "nothing is created where data protection is not enforced")

    #if os(macOS) || targetEnvironment(macCatalyst)
    XCTAssertFalse(KagemushaWalletAppleSystemV1.live.dataProtectionEnforced())
    #endif
  }

  func testStorageStateTellsBeforeFirstUnlockFromLocked() throws {
    let keychain = FakeWalletKeychain()
    let probe = FakeProtectedData()
    let platform = try makePlatform(keychain: keychain, probe: probe)
    XCTAssertNil(failure(platform.storageState()))
    XCTAssertEqual(probe.firstUnlockReads, 0, "read only after the canary is refused")

    probe.firstUnlock = EPERM
    probe.push(EPERM)
    XCTAssertEqual(failure(platform.storageState()), .beforeFirstUnlock)
    probe.firstUnlock = 0
    probe.push(EPERM)
    XCTAssertEqual(failure(platform.storageState()), .locked)
    probe.firstUnlock = ENOENT
    probe.push(EPERM)
    XCTAssertEqual(failure(platform.storageState()), .locked, "a missing probe merges into locked")
    probe.push(ENOENT)
    XCTAssertEqual(failure(platform.storageState()), .io(ENOENT))

    probe.firstUnlock = EPERM
    probe.push(EPERM)
    XCTAssertEqual(platform.keyProbe(slot), .unavailable(.beforeFirstUnlock))
    XCTAssertEqual(keychain.operations, [])

    // Signing is not bracketed; a refused keychain is told apart the same way.
    keychain.copyStatus = errSecInteractionNotAllowed
    XCTAssertEqual(failure(platform.keySign(slot, message: Data(repeating: 1, count: 32))), .beforeFirstUnlock)
    probe.firstUnlock = 0
    XCTAssertEqual(failure(platform.keySign(slot, message: Data(repeating: 1, count: 32))), .locked)
  }

  func testProtectedDataBracketsSurroundEveryAbsence() throws {
    let keychain = FakeWalletKeychain()
    let probe = FakeProtectedData()
    let platform = try makePlatform(keychain: keychain, probe: probe)

    probe.push(EPERM)
    XCTAssertEqual(platform.keyProbe(slot), .unavailable(.locked))
    XCTAssertEqual(keychain.operations, [], "no keychain query while protected data is locked")

    probe.push(0, EPERM)
    XCTAssertEqual(platform.keyProbe(slot), .unavailable(.locked))
    probe.push(0, EPERM)
    XCTAssertEqual(platform.anchorRead(slot), .unavailable(.locked))
    probe.push(0, ENOENT)
    XCTAssertEqual(platform.anchorRead(slot), .unavailable(.io(ENOENT)))
    XCTAssertEqual(platform.keyProbe(slot), .absent)

    let key = keychain.storeKey(tag: slot.applicationTag, label: nil)
    probe.push(0, EPERM)
    XCTAssertEqual(
      platform.keyProbe(slot), .present(Platform.x963PublicKey(of: key)!),
      "a present answer stands even if the device locks afterwards")
  }

  // MARK: Payment key

  func testKeyProbeIsTriStateAndNeverInfersAbsenceFromAnError() throws {
    let keychain = FakeWalletKeychain()
    let diagnostics = DiagnosticLog()
    let platform = try makePlatform(keychain: keychain, diagnostics: diagnostics)
    XCTAssertEqual(platform.keyProbe(slot), .absent)

    keychain.copyStatus = errSecInteractionNotAllowed
    XCTAssertEqual(platform.keyProbe(slot), .unavailable(.locked))
    keychain.copyStatus = errSecIO
    XCTAssertEqual(platform.keyProbe(slot), .unavailable(.platform(errSecIO)))
    keychain.copyStatus = errSecMissingEntitlement
    XCTAssertEqual(platform.keyProbe(slot), .unavailable(.platform(errSecMissingEntitlement)))
    keychain.copyStatus = nil

    let malformed = KagemushaWalletAppleProbeV1<Data>.unavailable(
      .platform(Status.malformedKeychainResult))
    keychain.copyResultOverride = .some(nil)
    XCTAssertEqual(platform.keyProbe(slot), malformed)
    keychain.copyResultOverride = .some([[String: Any]]() as NSArray)
    XCTAssertEqual(platform.keyProbe(slot), malformed)
    keychain.copyResultOverride = .some([[kSecAttrLabel as String: "x"]] as NSArray)
    XCTAssertEqual(platform.keyProbe(slot), malformed)
    // Two items are ambiguous whatever their shape, even when the first has no key reference.
    let twoItems: [[String: Any]] = [
      [kSecAttrLabel as String: "no reference"],
      [kSecValueRef as String: FakeWalletKeychain.softwareKey()],
    ]
    keychain.copyResultOverride = .some(twoItems as NSArray)
    XCTAssertEqual(
      platform.keyProbe(slot), .unavailable(.platform(Status.ambiguousPaymentKey)))
    keychain.copyResultOverride = nil

    let key = keychain.storeKey(tag: slot.applicationTag, label: request().label)
    let expected = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(key)!, nil)! as Data
    XCTAssertEqual(expected.count, 65)
    XCTAssertEqual(expected.first, 0x04)
    XCTAssertEqual(platform.keyProbe(slot), .present(expected))

    keychain.storeKey(tag: slot.applicationTag, label: nil)
    XCTAssertEqual(
      platform.keyProbe(slot), .unavailable(.platform(Status.ambiguousPaymentKey)))
    XCTAssertEqual(
      diagnostics.all.last,
      KagemushaWalletAppleDiagnosticV1(
        event: "ambiguous payment key", slot: slot.keychainName, detail: "2 items"))
  }

  func testPaymentKeyQueriesArePinnedToTheSecureEnclaveAndTheAppsGroup() throws {
    let keychain = FakeWalletKeychain()
    let platform = try makePlatform(keychain: keychain)
    _ = platform.keyProbe(slot)
    _ = platform.keyDelete(slot)
    _ = platform.keyEnumerate()
    let keyQueries = keychain.queries.filter {
      ($0[kSecClass as String] as? String) == (kSecClassKey as String)
    }
    XCTAssertEqual(keyQueries.count, 4, "probe, delete, confirming probe, enumeration")
    for query in keyQueries {
      XCTAssertEqual(query[kSecAttrAccessGroup as String] as? String, Self.accessGroup)
      XCTAssertEqual(
        query[kSecAttrTokenID as String] as? String, kSecAttrTokenIDSecureEnclave as String)
      XCTAssertEqual(query[kSecAttrKeyClass as String] as? String, kSecAttrKeyClassPrivate as String)
      XCTAssertEqual(query[kSecUseDataProtectionKeychain as String] as? Bool, true)
    }
    XCTAssertEqual(keyQueries[0][kSecAttrApplicationTag as String] as? Data, slot.applicationTag)
    XCTAssertEqual(keyQueries[1][kSecAttrApplicationTag as String] as? Data, slot.applicationTag)
    XCTAssertNil(keyQueries[3][kSecAttrApplicationTag as String])
  }

  func testKeyGenerationUsesSecureEnclavePolicyAndBindsTheChallenge() throws {
    let keychain = FakeWalletKeychain()
    let platform = try makePlatform(keychain: keychain)
    let publicKey = try generatedKey(platform)
    XCTAssertEqual(publicKey.count, 65)
    XCTAssertEqual(platform.keyProbe(slot), .present(publicKey))

    let attributes = try XCTUnwrap(keychain.generationAttributes.first)
    XCTAssertEqual(attributes[kSecAttrTokenID as String] as? String, kSecAttrTokenIDSecureEnclave as String)
    XCTAssertEqual(attributes[kSecAttrKeyType as String] as? String, kSecAttrKeyTypeECSECPrimeRandom as String)
    XCTAssertEqual(attributes[kSecAttrKeySizeInBits as String] as? Int, 256)
    let privateAttributes = try XCTUnwrap(attributes[kSecPrivateKeyAttrs as String] as? [String: Any])
    XCTAssertEqual(privateAttributes[kSecAttrIsPermanent as String] as? Bool, true)
    XCTAssertEqual(privateAttributes[kSecAttrApplicationTag as String] as? Data, slot.applicationTag)
    XCTAssertEqual(privateAttributes[kSecAttrLabel as String] as? String, request().label)
    XCTAssertEqual(privateAttributes[kSecAttrAccessGroup as String] as? String, Self.accessGroup)
    let access = try XCTUnwrap(privateAttributes[kSecAttrAccessControl as String])
    XCTAssertEqual(CFGetTypeID(access as AnyObject), SecAccessControlGetTypeID())

    XCTAssertEqual(platform.keyGenerate(slot, request()), .alreadyPresent)
    XCTAssertEqual(keychain.generationAttributes.count, 1, "an existing key is never replaced")
  }

  func testKeyGenerationRefusesOrReportsUnknownOutcomes() throws {
    XCTAssertEqual(
      try makePlatform(secureEnclave: false).keyGenerate(slot, request()),
      .unavailable(.platform(Status.secureEnclaveUnavailable)))
    let unsupported = FakeWalletAppAttest()
    unsupported.supported = false
    XCTAssertEqual(
      try makePlatform(appAttest: unsupported).keyGenerate(slot, request()),
      .unavailable(.platform(Status.appAttestUnsupported)))
    let noPasscode = FakeWalletKeychain()
    XCTAssertEqual(
      try makePlatform(keychain: noPasscode, passcode: false).keyGenerate(slot, request()),
      .unavailable(.platform(Status.passcodeNotSet)))
    XCTAssertEqual(noPasscode.generationAttributes.count, 0)

    let probe = FakeProtectedData()
    probe.push(EPERM)
    let lockedKeychain = FakeWalletKeychain()
    XCTAssertEqual(
      try makePlatform(keychain: lockedKeychain, probe: probe).keyGenerate(slot, request()),
      .unavailable(.locked))
    XCTAssertEqual(lockedKeychain.generationAttributes.count, 0)

    let cases: [(SecurityError, KagemushaWalletAppleKeyGenerationV1, Bool)] = [
      (SecurityError(status: errSecDuplicateItem), .alreadyPresent, false),
      (SecurityError(status: errSecInteractionNotAllowed), .unavailable(.locked), false),
      (SecurityError(status: errSecIO), .unavailable(.platform(errSecIO)), true),
      (
        SecurityError(domain: "CryptoTokenKit", code: -2),
        .unavailable(.platform(Status.nonOSStatusError)), true
      ),
    ]
    for (error, expected, diagnosed) in cases {
      let keychain = FakeWalletKeychain()
      let diagnostics = DiagnosticLog()
      keychain.createError = error
      XCTAssertEqual(
        try makePlatform(keychain: keychain, diagnostics: diagnostics).keyGenerate(slot, request()),
        expected, error.detail)
      XCTAssertEqual(
        diagnostics.all.map(\.detail), diagnosed ? [error.detail] : [], error.detail)
    }

    let unpersisted = FakeWalletKeychain()
    unpersisted.persistence = .nothing
    XCTAssertEqual(
      try makePlatform(keychain: unpersisted).keyGenerate(slot, request()),
      .unavailable(.platform(Status.paymentKeyNotPersisted)))

    let replaced = FakeWalletKeychain()
    replaced.persistence = .differentKey
    let diagnostics = DiagnosticLog()
    XCTAssertEqual(
      try makePlatform(keychain: replaced, diagnostics: diagnostics).keyGenerate(slot, request()),
      .unavailable(.platform(Status.ambiguousPaymentKey)),
      "a different key under the tag after generation is never reported as generated")
    XCTAssertEqual(
      diagnostics.all.map(\.event), ["generated payment key differs from the stored key"])
  }

  func testCustodyItemsAreNeverBackedUpOrBoundToUserAuthentication() throws {
    XCTAssertEqual(
      Platform.custodyAccessibility as String,
      kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String)
    XCTAssertEqual(Platform.paymentKeyAccessFlags, [.privateKeyUsage])
    XCTAssertTrue(
      Platform.paymentKeyAccessFlags.isDisjoint(
        with: [.userPresence, .biometryAny, .biometryCurrentSet, .devicePasscode, .applicationPassword]))
    if case .failure(let reason) = Platform.paymentKeyAccessControl() {
      XCTFail("access control: \(reason)")
    }
  }

  func testKeySignReturnsDERThatVerifiesOverTheSHA256SigningMessage() throws {
    let keychain = FakeWalletKeychain()
    let platform = try makePlatform(keychain: keychain)
    let publicKey = try generatedKey(platform)
    let message = Data(repeating: 7, count: 32)
    let der: Data
    switch platform.keySign(slot, message: message) {
    case .success(let signature): der = signature
    case .failure(let reason): return XCTFail("sign: \(reason)")
    }
    XCTAssertEqual(der.first, 0x30, "strict DER sequence; low-S normalization is Rust's")
    let signature = try P256.Signing.ECDSASignature(derRepresentation: der)
    let verifier = try P256.Signing.PublicKey(x963Representation: publicKey)
    XCTAssertTrue(verifier.isValidSignature(signature, for: message))
    XCTAssertFalse(verifier.isValidSignature(signature, for: message + Data([0])))

    let other = KagemushaWalletAppleSlotV1(Data(repeating: 9, count: 32))!
    XCTAssertEqual(failure(platform.keySign(other, message: message)), .platform(errSecItemNotFound))
    keychain.copyStatus = errSecInteractionNotAllowed
    XCTAssertEqual(failure(platform.keySign(slot, message: message)), .locked)
  }

  func testKeySignRejectsWrongMessageLengthsBeforeKeychainAccess() throws {
    let keychain = FakeWalletKeychain()
    let platform = try makePlatform(keychain: keychain)
    let queries = keychain.queries.count
    for length in [0, 31, 33, 1024] {
      XCTAssertEqual(failure(platform.keySign(slot, message: Data(repeating: 7, count: length))), .keyUnusable)
    }
    XCTAssertEqual(keychain.queries.count, queries, "malformed messages never reach the keychain")
  }

  func testKeySignReportsAKeyThatCannotSignAsUnusable() throws {
    let keychain = FakeWalletKeychain()
    let diagnostics = DiagnosticLog()
    let platform = try makePlatform(keychain: keychain, diagnostics: diagnostics)
    let publicOnly = try XCTUnwrap(SecKeyCopyPublicKey(FakeWalletKeychain.softwareKey()))
    keychain.storeKey(tag: slot.applicationTag, label: nil, key: publicOnly)
    XCTAssertEqual(failure(platform.keySign(slot, message: Data(repeating: 1, count: 32))), .keyUnusable)
    XCTAssertEqual(diagnostics.all.count, 1)
    XCTAssertEqual(diagnostics.all.first?.slot, slot.keychainName)
  }

  func testKeyDeleteIsConfirmedByABracketedProbe() throws {
    let keychain = FakeWalletKeychain()
    let probe = FakeProtectedData()
    let platform = try makePlatform(keychain: keychain, probe: probe)
    _ = try generatedKey(platform)

    probe.push(EPERM)
    XCTAssertEqual(platform.keyDelete(slot), .notRemoved(.locked))
    XCTAssertFalse(keychain.operations.contains("delete"))

    keychain.deleteStatus = errSecInteractionNotAllowed
    XCTAssertEqual(platform.keyDelete(slot), .notRemoved(.locked))
    keychain.deleteStatus = errSecIO
    XCTAssertEqual(platform.keyDelete(slot), .uncertain(.platform(errSecIO)))
    keychain.deleteStatus = nil

    probe.push(0, 0, EPERM)
    XCTAssertEqual(platform.keyDelete(slot), .uncertain(.locked))
    XCTAssertEqual(platform.keyProbe(slot), .absent)
    XCTAssertEqual(platform.keyDelete(slot), .removed)
  }

  func testKeyEnumerationListsWalletSlotsOnlyInsideBrackets() throws {
    let keychain = FakeWalletKeychain()
    let probe = FakeProtectedData()
    let diagnostics = DiagnosticLog()
    let platform = try makePlatform(keychain: keychain, probe: probe, diagnostics: diagnostics)
    XCTAssertEqual(try platform.keyEnumerate().get(), [])

    probe.push(0, EPERM)
    XCTAssertEqual(failure(platform.keyEnumerate()), .locked, "an empty answer counts only if still unlocked")
    probe.push(EPERM)
    let before = keychain.operations.count
    XCTAssertEqual(failure(platform.keyEnumerate()), .locked)
    XCTAssertEqual(keychain.operations.count, before, "nothing is queried while locked")
    keychain.copyStatus = errSecIO
    XCTAssertEqual(failure(platform.keyEnumerate()), .platform(errSecIO))
    keychain.copyStatus = nil
    keychain.copyResultOverride = .some(Data() as NSData)
    XCTAssertEqual(failure(platform.keyEnumerate()), .platform(Status.malformedKeychainResult))
    keychain.copyResultOverride = nil

    let other = KagemushaWalletAppleSlotV1(Data(repeating: 0xab, count: 32))!
    keychain.storeKey(tag: other.applicationTag, label: nil)
    keychain.storeKey(tag: slot.applicationTag, label: request().label)
    keychain.storeKey(tag: slot.applicationTag, label: nil)
    keychain.storeKey(tag: Data("com.example.app.signing".utf8), label: nil)
    keychain.storeKey(tag: Data(("kgm-w1-" + String(repeating: "AB", count: 32)).utf8), label: nil)
    keychain.storeKey(tag: Data(("kgm-w1-" + String(repeating: "00", count: 32)).utf8), label: nil)
    keychain.storeKey(tag: nil, label: nil)
    XCTAssertEqual(try platform.keyEnumerate().get(), [slot, other], "sorted, each slot once")
    XCTAssertEqual(
      diagnostics.all.map(\.event),
      ["malformed payment-key enumeration", "malformed wallet payment-key tag",
       "malformed wallet payment-key tag"])

    let query = try XCTUnwrap(keychain.queries.last)
    XCTAssertEqual(query[kSecMatchLimit as String] as? String, kSecMatchLimitAll as String)
    XCTAssertEqual(query[kSecReturnAttributes as String] as? Bool, true)
    XCTAssertNil(query[kSecReturnRef as String])
  }

  // MARK: Rollback anchor

  func testAnchorItemIsPasscodeBoundDeviceOnlyAndKeepsTheRustBytes() throws {
    let platform = try makePlatform()
    let value = Data((0..<57).map { UInt8(truncatingIfNeeded: $0 &* 7) })
    let attributes = platform.anchorAddAttributes(slot, value: value)
    XCTAssertEqual(attributes[kSecClass as String] as? String, kSecClassGenericPassword as String)
    XCTAssertEqual(
      attributes[kSecAttrService as String] as? String,
      "org.hyperledger.iroha.kagemusha.wallet.v1.marker-anchor")
    XCTAssertEqual(attributes[kSecAttrAccount as String] as? String, slot.keychainName)
    XCTAssertEqual(attributes[kSecAttrAccessGroup as String] as? String, Self.accessGroup)
    XCTAssertEqual(
      attributes[kSecAttrAccessible as String] as? String,
      kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String)
    XCTAssertEqual(attributes[kSecAttrSynchronizable as String] as? Bool, false)
    XCTAssertEqual(attributes[kSecUseDataProtectionKeychain as String] as? Bool, true)
    XCTAssertEqual(attributes[kSecValueData as String] as? Data, value)

    let query = platform.anchorQuery(slot)
    XCTAssertEqual(query[kSecAttrAccessGroup as String] as? String, Self.accessGroup)
    XCTAssertNil(query[kSecValueData as String])
    XCTAssertNil(query[kSecAttrAccessible as String])
    XCTAssertEqual(Platform.anchorPolicyTag, 1)
  }

  func testAnchorIsAddOnlyAndUpdatedOnlyInPlace() throws {
    let keychain = FakeWalletKeychain()
    let platform = try makePlatform(keychain: keychain)
    let none = Data(repeating: 0x11, count: 54)
    let raised = Data(repeating: 0x22, count: 54)

    XCTAssertEqual(platform.anchorRead(slot), .absent)
    XCTAssertEqual(platform.anchorUpdate(slot, value: raised), .notPublished(.destinationAbsent))
    XCTAssertEqual(platform.anchorCreate(slot, value: none), .published)
    XCTAssertEqual(platform.anchorRead(slot), .present(none))
    XCTAssertEqual(platform.anchorCreate(slot, value: raised), .notPublished(.destinationExists))
    XCTAssertEqual(platform.anchorRead(slot), .present(none))
    XCTAssertEqual(platform.anchorUpdate(slot, value: raised), .published)
    XCTAssertEqual(platform.anchorRead(slot), .present(raised))

    let invalid = KagemushaWalletAppleNotPublishedV1.failed(.platform(Status.invalidAnchorValue))
    XCTAssertEqual(platform.anchorCreate(slot, value: Data()), .notPublished(invalid))
    XCTAssertEqual(
      platform.anchorUpdate(slot, value: Data(repeating: 1, count: 257)), .notPublished(invalid))
    XCTAssertEqual(platform.anchorUpdate(slot, value: Data(repeating: 1, count: 256)), .published)

    for query in keychain.queries {
      XCTAssertEqual(query[kSecAttrAccessGroup as String] as? String, Self.accessGroup)
    }

    keychain.copyStatus = errSecInteractionNotAllowed
    XCTAssertEqual(platform.anchorRead(slot), .unavailable(.locked))
    keychain.copyStatus = errSecIO
    XCTAssertEqual(platform.anchorRead(slot), .unavailable(.platform(errSecIO)))
    keychain.copyStatus = nil
    keychain.copyResultOverride = .some([[String: Any]]() as NSArray)
    XCTAssertEqual(
      platform.anchorRead(slot), .unavailable(.platform(Status.malformedKeychainResult)))
    keychain.copyResultOverride = nil
    keychain.updateStatus = errSecIO
    XCTAssertEqual(platform.anchorUpdate(slot, value: raised), .uncertain(.platform(errSecIO)))
  }

  func testAnchorCreationIsRefusedWhileLockedOrWithoutPasscode() throws {
    let keychain = FakeWalletKeychain()
    let probe = FakeProtectedData()
    probe.push(EPERM, EPERM)
    let platform = try makePlatform(keychain: keychain, probe: probe)
    let value = Data(repeating: 0x11, count: 54)
    XCTAssertEqual(platform.anchorCreate(slot, value: value), .notPublished(.failed(.locked)))
    XCTAssertEqual(platform.anchorUpdate(slot, value: value), .notPublished(.failed(.locked)))
    XCTAssertEqual(keychain.operations, [])

    let noPasscode = try makePlatform(keychain: keychain, passcode: false)
    XCTAssertEqual(
      noPasscode.anchorCreate(slot, value: value),
      .notPublished(.failed(.platform(Status.passcodeNotSet))))
    XCTAssertEqual(keychain.operations, [])

    keychain.addStatus = errSecIO
    XCTAssertEqual(
      try makePlatform(keychain: keychain, passcode: nil).anchorCreate(slot, value: value),
      .uncertain(.platform(errSecIO)))
  }

  // MARK: Custody root

  func testCustodyRootIsPrivateExcludedFromBackupAndCarriesTheCanary() throws {
    let base = try temporaryDirectory()
    let protection = FakeFileProtection()
    let platform = try makePlatform(
      protection: protection, base: base, prepared: false, liveProbe: true)
    XCTAssertEqual(failure(platform.storageState()), .platform(Status.custodyRootNotPrepared))

    let path = try platform.custodyRootPath().get()
    let root = base.appendingPathComponent("kagemusha-wallet-v1", isDirectory: true)
    XCTAssertEqual(path, root.path)
    let manager = FileManager.default
    let attributes = try manager.attributesOfItem(atPath: path)
    XCTAssertEqual(attributes[.type] as? FileAttributeType, .typeDirectory)
    XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
    XCTAssertEqual(try Self.isExcludedFromBackup(path), true)
    let canary = root.appendingPathComponent("canary").path
    XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: canary)), Data([0x01]))
    XCTAssertEqual(
      try Data(contentsOf: base.appendingPathComponent("kagemusha-wallet-v1.first-unlock")),
      Data([0x01]), "the first-unlock probe sits next to the root, never inside it")
    XCTAssertEqual(try manager.contentsOfDirectory(atPath: path), ["canary"])
    XCTAssertNil(failure(platform.storageState()))
    XCTAssertEqual(protection.reads, 1)
    let inode = try manager.attributesOfItem(atPath: canary)[.systemFileNumber] as? NSNumber

    try manager.setAttributes([.posixPermissions: NSNumber(value: Int16(0o755))], ofItemAtPath: path)
    var reset = URL(fileURLWithPath: path, isDirectory: true)
    var values = URLResourceValues()
    values.isExcludedFromBackup = false
    try reset.setResourceValues(values)
    XCTAssertEqual(try Self.isExcludedFromBackup(path), false)

    XCTAssertEqual(try platform.custodyRootPath().get(), path)
    XCTAssertEqual(
      (try manager.attributesOfItem(atPath: path)[.posixPermissions] as? NSNumber)?.intValue, 0o700,
      "mode is re-applied on every preparation")
    XCTAssertEqual(
      try Self.isExcludedFromBackup(path), true, "backup exclusion is re-applied on every preparation")
    XCTAssertEqual(protection.reads, 2, "the canary class is verified on every preparation")
    XCTAssertEqual(
      try manager.attributesOfItem(atPath: canary)[.systemFileNumber] as? NSNumber, inode,
      "the canary is never rewritten")
  }

  func testCanaryProtectionClassIsVerifiedAndNeverAcceptedUnverified() throws {
    let manager = FileManager.default
    let invalid = KagemushaWalletAppleUnavailableV1.platform(Status.invalidCustodyRoot)
    let notPrepared = KagemushaWalletAppleUnavailableV1.platform(Status.custodyRootNotPrepared)
    func canaryPath(_ base: URL) -> String {
      base.appendingPathComponent("kagemusha-wallet-v1/canary").path
    }

    // A canary in a weaker class is re-protected once and accepted when it reads back Complete.
    let repaired = FakeFileProtection()
    repaired.initial = .completeUntilFirstUserAuthentication
    let diagnostics = DiagnosticLog()
    let repairedPlatform = try makePlatform(
      protection: repaired, diagnostics: diagnostics, prepared: false)
    XCTAssertNotNil(try? repairedPlatform.custodyRootPath().get())
    XCTAssertEqual(repaired.sets, 1)
    XCTAssertEqual(repaired.reads, 2)
    XCTAssertNil(failure(repairedPlatform.storageState()))
    XCTAssertEqual(
      diagnostics.all,
      [
        KagemushaWalletAppleDiagnosticV1(
          event: "custody canary is not in the Complete protection class", slot: nil,
          detail: FileProtectionType.completeUntilFirstUserAuthentication.rawValue)
      ])

    // A class that stays wrong refuses the root; nothing is removed.
    let stuck = FakeFileProtection()
    stuck.initial = FileProtectionType.none
    stuck.setTakesEffect = false
    let stuckBase = try temporaryDirectory()
    let stuckPlatform = try makePlatform(protection: stuck, base: stuckBase, prepared: false)
    XCTAssertEqual(failure(stuckPlatform.custodyRootPath()), invalid)
    XCTAssertTrue(manager.fileExists(atPath: canaryPath(stuckBase)))
    XCTAssertEqual(failure(stuckPlatform.storageState()), notPrepared)

    // A file system that reports no class at all is refused the same way.
    let unreported = FakeFileProtection()
    unreported.initial = nil
    unreported.setTakesEffect = false
    XCTAssertEqual(
      failure(try makePlatform(protection: unreported, prepared: false).custodyRootPath()), invalid)

    // Failures to read or re-apply the class are reported as such.
    let refused = FakeFileProtection()
    refused.initial = nil
    refused.setFailure = .io(EPERM)
    XCTAssertEqual(
      failure(try makePlatform(protection: refused, prepared: false).custodyRootPath()), .io(EPERM))
    let unreadable = FakeFileProtection()
    unreadable.readFailure = .io(EIO)
    XCTAssertEqual(
      failure(try makePlatform(protection: unreadable, prepared: false).custodyRootPath()), .io(EIO))

    // A root verified earlier stops answering once a later preparation fails verification.
    let flipping = FakeFileProtection()
    let flippingPlatform = try makePlatform(protection: flipping)
    XCTAssertNil(failure(flippingPlatform.storageState()))
    flipping.initial = FileProtectionType.none
    flipping.setTakesEffect = false
    XCTAssertEqual(failure(flippingPlatform.custodyRootPath()), invalid)
    XCTAssertEqual(failure(flippingPlatform.storageState()), notPrepared)
  }

  func testCustodyRootRefusesLinksAndUnexpectedEntriesWithoutRemovingThem() throws {
    let manager = FileManager.default
    let invalid = KagemushaWalletAppleUnavailableV1.platform(Status.invalidCustodyRoot)

    let linked = try temporaryDirectory()
    let target = try temporaryDirectory()
    let link = linked.appendingPathComponent("kagemusha-wallet-v1")
    try manager.createSymbolicLink(at: link, withDestinationURL: target)
    XCTAssertEqual(
      failure(try makePlatform(base: linked, prepared: false).custodyRootPath()), invalid)
    XCTAssertEqual(try manager.destinationOfSymbolicLink(atPath: link.path), target.path)

    let file = try temporaryDirectory()
    let fileRoot = file.appendingPathComponent("kagemusha-wallet-v1")
    XCTAssertTrue(manager.createFile(atPath: fileRoot.path, contents: Data([7])))
    XCTAssertEqual(failure(try makePlatform(base: file, prepared: false).custodyRootPath()), invalid)
    XCTAssertEqual(try Data(contentsOf: fileRoot), Data([7]))

    let canaryDirectory = try temporaryDirectory()
    try manager.createDirectory(
      at: canaryDirectory.appendingPathComponent("kagemusha-wallet-v1/canary"),
      withIntermediateDirectories: true)
    XCTAssertEqual(
      failure(try makePlatform(base: canaryDirectory, prepared: false).custodyRootPath()), invalid)

    // An unusable first-unlock probe is only reported; the root is still prepared.
    let probeDirectory = try temporaryDirectory()
    try manager.createDirectory(
      at: probeDirectory.appendingPathComponent("kagemusha-wallet-v1.first-unlock"),
      withIntermediateDirectories: false)
    let diagnostics = DiagnosticLog()
    XCTAssertNotNil(
      try? makePlatform(diagnostics: diagnostics, base: probeDirectory, prepared: false)
        .custodyRootPath().get())
    XCTAssertEqual(diagnostics.all.map(\.event), ["first-unlock probe is not a regular file"])
  }

  func testProtectionClassesFollowTheDesign() {
    XCTAssertEqual(Platform.custodyRootProtection, .completeUntilFirstUserAuthentication)
    XCTAssertEqual(Platform.canaryProtection, .complete)
    XCTAssertEqual(Platform.firstUnlockProbeProtection, .completeUntilFirstUserAuthentication)
    XCTAssertEqual((Platform.custodyRootAttributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
    XCTAssertTrue(Platform.canaryWriteOptions.contains(.withoutOverwriting))
    XCTAssertTrue(Platform.firstUnlockProbeWriteOptions.contains(.withoutOverwriting))
    #if os(iOS)
    XCTAssertEqual(
      Platform.custodyRootAttributes[.protectionKey] as? FileProtectionType,
      .completeUntilFirstUserAuthentication)
    XCTAssertTrue(Platform.canaryWriteOptions.contains(.completeFileProtection))
    XCTAssertTrue(
      Platform.firstUnlockProbeWriteOptions.contains(.completeFileProtectionUntilFirstUserAuthentication))
    #endif
  }

  // MARK: Boot identity

  func testBootSessionUUIDParsing() throws {
    let uuid = "6F1C2B3A-1234-4ABC-8DEF-0123456789AB"
    XCTAssertEqual(
      try Platform.bootSessionUUID(fromSysctl: Array(uuid.utf8) + [0]).get(), uuid.lowercased())
    XCTAssertEqual(
      try Platform.bootSessionUUID(fromSysctl: Array(uuid.lowercased().utf8) + [0x0a, 0, 0]).get(),
      uuid.lowercased())
    for malformed in [
      String(uuid.dropLast()), uuid + "0", uuid.replacingOccurrences(of: "-4ABC", with: "4-ABC"),
      uuid.replacingOccurrences(of: "F", with: "G"), "", "\u{0}" + uuid,
    ] {
      XCTAssertEqual(
        failure(Platform.bootSessionUUID(fromSysctl: Array(malformed.utf8) + [0])), .io(0), malformed)
    }
    XCTAssertEqual(failure(Platform.bootSessionUUID(fromSysctl: [0xff, 0])), .io(0))

    let requested = DiagnosticLog()
    let platform = try makePlatform(sysctl: { name in
      requested.record(KagemushaWalletAppleDiagnosticV1(event: name, slot: nil, detail: nil))
      return name == "kern.bootsessionuuid" ? .success(Array(uuid.utf8) + [0]) : .failure(.io(EINVAL))
    })
    XCTAssertEqual(try platform.bootSessionUUID().get(), uuid.lowercased())
    XCTAssertEqual(requested.all.map(\.event), ["kern.bootsessionuuid"])
    XCTAssertEqual(failure(try makePlatform().bootSessionUUID()), .io(ENOENT))
  }

  func testLiveBootSessionUUIDIsWellFormedWhenReadable() {
    let platform = KagemushaWalletApplePlatformV1(
      appAttest: FakeWalletAppAttest(), accessGroup: Self.accessGroup, system: .live)
    switch platform.bootSessionUUID() {
    case .success(let text):
      XCTAssertEqual(text.count, 36)
      XCTAssertEqual(text, text.lowercased())
    case .failure(let reason):
      // The sysctl may be unreadable in a sandbox; the answer is then unavailable, never empty.
      XCTAssertNotEqual(reason, .io(0))
    }
  }

  // MARK: App Attest (E5)

  private func expectAttestationError(
    _ expected: KagemushaWalletAppleEnrollmentAttestationErrorV1,
    file: StaticString = #filePath, line: UInt = #line,
    _ body: () async throws -> KagemushaWalletAppleEnrollmentEvidenceV1
  ) async {
    do {
      _ = try await body()
      XCTFail("expected \(expected)", file: file, line: line)
    } catch let error as KagemushaWalletAppleEnrollmentAttestationErrorV1 {
      XCTAssertEqual(error, expected, file: file, line: line)
    } catch {
      XCTFail("unexpected \(error)", file: file, line: line)
    }
  }

  func testEnrollmentKeyBindingDigestMatchesTheRustVector() throws {
    let data = try Data(contentsOf: applePlatformFixtureURL())
    let fixture = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    let digests = try XCTUnwrap(fixture["digests"] as? [[String: Any]])
    let vector = try XCTUnwrap(
      digests.first { $0["object"] as? String == "receiver App Attest enrollment assertion client data" })
    XCTAssertEqual(vector["role"] as? String, "enrollment-key-binding")
    let body = try XCTUnwrap(kagemushaWalletAppleParseHex(Array((vector["body_hex"] as? String ?? "").utf8)))
    XCTAssertEqual(body.count, 97)
    let expected = try XCTUnwrap(
      kagemushaWalletAppleParseHex(Array((vector["digest_hex"] as? String ?? "").utf8)))
    XCTAssertEqual(
      Platform.enrollmentKeyBindingDigest(
        challengeDigest: body.prefix(32), paymentPublicKey: body.suffix(65)),
      expected)
  }

  func testEnrollmentAttestationUsesTheBoundChallengeAndAFreshAppAttestKey() async throws {
    let appAttest = FakeWalletAppAttest()
    let platform = try makePlatform(appAttest: appAttest)
    let publicKey = try generatedKey(platform)
    let keyBinding = Platform.enrollmentKeyBindingDigest(
      challengeDigest: challenge, paymentPublicKey: publicKey)
    XCTAssertEqual(
      keyBinding,
      KagemushaWalletWireV1.digest(role: .enrollmentKeyBinding, body: challenge + publicKey))

    let evidence = try await platform.attestEnrollment(
      slot: slot, paymentPublicKey: publicKey, challengeDigest: challenge)
    let firstKey = FakeWalletAppAttest.keyID(1)
    XCTAssertEqual(evidence.appAttestKeyID, firstKey)
    XCTAssertEqual(evidence.attestation, Data("attestation".utf8) + challenge)
    XCTAssertEqual(evidence.keyBindingDigest, keyBinding)
    XCTAssertEqual(evidence.keyBindingAssertion, Data("assertion".utf8) + keyBinding)
    XCTAssertEqual(KagemushaWalletAppleEnrollmentEvidenceV1.keyBindingAssertionCounter, 1)
    XCTAssertEqual(
      appAttest.calls,
      [
        "generateKey",
        "attestKey:\(firstKey):" + kagemushaWalletAppleHex(challenge),
        "generateAssertion:\(firstKey):" + kagemushaWalletAppleHex(keyBinding),
      ])

    let stages: [KagemushaWalletAppleAppAttestStageV1] = [.generateKey, .attestKey, .generateAssertion]
    for stage in stages {
      appAttest.failingStage = stage
      await expectAttestationError(
        .appAttestFailed(stage: stage, domain: "com.apple.devicecheck.error", code: 4)
      ) {
        try await platform.attestEnrollment(
          slot: slot, paymentPublicKey: publicKey, challengeDigest: challenge)
      }
    }
    appAttest.failingStage = nil
    let retried = try await platform.attestEnrollment(
      slot: slot, paymentPublicKey: publicKey, challengeDigest: challenge)
    XCTAssertEqual(retried.appAttestKeyID, FakeWalletAppAttest.keyID(5), "every attempt uses a fresh key")
  }

  func testEnrollmentAttestationRefusesUnboundOrMissingKeys() async throws {
    let appAttest = FakeWalletAppAttest()
    let keychain = FakeWalletKeychain()
    let platform = try makePlatform(keychain: keychain, appAttest: appAttest)
    await expectAttestationError(.paymentKeyAbsent) {
      try await platform.attestEnrollment(
        slot: slot, paymentPublicKey: Data(), challengeDigest: challenge)
    }
    keychain.copyStatus = errSecInteractionNotAllowed
    await expectAttestationError(.paymentKeyUnavailable(.locked)) {
      try await platform.attestEnrollment(
        slot: slot, paymentPublicKey: Data(), challengeDigest: challenge)
    }
    keychain.copyStatus = nil
    let publicKey = try generatedKey(platform)
    await expectAttestationError(.bindingMismatch) {
      try await platform.attestEnrollment(
        slot: slot, paymentPublicKey: publicKey, challengeDigest: Data(repeating: 0xc5, count: 32))
    }
    var otherKey = publicKey
    otherKey[64] ^= 1
    await expectAttestationError(.bindingMismatch) {
      try await platform.attestEnrollment(
        slot: slot, paymentPublicKey: otherKey, challengeDigest: challenge)
    }
    await expectAttestationError(.invalidDigest) {
      try await platform.attestEnrollment(
        slot: slot, paymentPublicKey: publicKey, challengeDigest: Data(repeating: 1, count: 31))
    }

    // A key whose recorded binding is missing or garbled is never attested.
    for label in [nil, "kgm-w1-binding:1:garbled"] as [String?] {
      let unlabeled = FakeWalletKeychain()
      let key = unlabeled.storeKey(tag: slot.applicationTag, label: label)
      let unlabeledPlatform = try makePlatform(keychain: unlabeled, appAttest: appAttest)
      await expectAttestationError(.bindingMismatch) {
        try await unlabeledPlatform.attestEnrollment(
          slot: slot, paymentPublicKey: Platform.x963PublicKey(of: key)!, challengeDigest: challenge)
      }
    }
    XCTAssertEqual(appAttest.calls, [], "no App Attest call without a bound payment key")

    appAttest.malformedKeyIDs = true
    await expectAttestationError(.malformedAppAttestKeyID) {
      try await platform.attestEnrollment(
        slot: slot, paymentPublicKey: publicKey, challengeDigest: challenge)
    }
    XCTAssertEqual(appAttest.calls, ["generateKey"], "a malformed key identifier is never attested")

    appAttest.supported = false
    await expectAttestationError(.appAttestUnsupported) {
      try await platform.attestEnrollment(
        slot: slot, paymentPublicKey: publicKey, challengeDigest: challenge)
    }
  }
}
