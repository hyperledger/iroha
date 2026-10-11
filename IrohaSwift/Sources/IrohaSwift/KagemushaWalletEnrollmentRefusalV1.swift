import Foundation

/// What the holder can do about an E1 refusal (design §2.4). The app owns the wording.
/// The raw value is Native's holder-class number (`connect_norito_kagemusha_wallet_enrollment_refusal_v1`).
public enum KagemushaWalletEnrollmentRefusalClassV1: Int32, CaseIterable, Sendable {
  /// This phone cannot hold offline value. Abandon the attempt and do not start again on this
  /// phone. Online payments are unaffected.
  case phone = 1
  /// Install the released app from an official channel, or update it, then start again.
  case app = 2
  /// Abandon and start again with a new challenge. A repeat is a defect report, not a device verdict.
  case attempt = 3
  /// The account's status, not the phone, blocks enrollment. Before issuance this is a terminal
  /// refusal (start again after the status changes); at E6 delivery it only withholds delivery.
  case account = 4
}

/// One closed E1 refusal reason (design §2.4; Rust `KagemushaWalletEnrollmentRefusalV1`).
/// The raw value is the stable `u16` wire code that the issuer reports and BPNG Core relays
/// unchanged; there is no free-text substitute. A refusal never states that a phone is
/// compromised: it names the first admission check that failed.
///
/// Native owns the table. ``init(relayedCode:)`` admits a relayed code only when Native's
/// table and this projection agree; zero, unknown and Android-only codes are protocol
/// errors, never admission and never a phone verdict.
public enum KagemushaWalletEnrollmentRefusalV1: UInt16, CaseIterable, Sendable {
  /// Android: the attestation or KeyMint security level is Software, the two levels differ,
  /// or attestation version 2 is not TEE.
  case keyNotInSecureHardware = 1
  /// Android: the attestation carries no application identity (Keymaster 2 / attestation
  /// version 1, or a later attestation without `attestationApplicationId`).
  case attestationWithoutAppIdentity = 2
  /// Android: the RootOfTrust records an unlocked bootloader.
  case bootloaderUnlocked = 3
  /// Android: boot state is not Verified, the verified-boot key is zero, or a KeyMint boot
  /// hash is not 32 nonzero bytes.
  case bootNotVerified = 4
  /// The chain does not validate to a pinned root (Android) or to Apple's App Attestation root.
  case untrustedAttestationRoot = 5
  /// Android: a chain certificate is listed by its root's revocation source or the operator denylist.
  case attestationRevoked = 6
  /// The package, a signer, the App ID or the App Attest environment differs from the app policy.
  case appIdentityMismatch = 7
  /// Android: the attested package version is below the app policy minimum.
  case appVersionBelowMinimum = 8
  /// The evidence is malformed or does not match this attempt (including the App Attest nonce,
  /// key identifier, counter or key-binding assertion).
  case evidenceInvalid = 9
  /// E5 verification began after the E1 challenge lifetime.
  case challengeExpired = 10
  /// The eligibility provider reports `NotApproved`.
  case accountNotApproved = 11
  /// The eligibility provider reports `Frozen`.
  case accountFrozen = 12

  /// Stable `u16` wire code, 1–12.
  public var code: UInt16 { rawValue }

  /// What the holder can do about this reason.
  public var holderClass: KagemushaWalletEnrollmentRefusalClassV1 {
    switch self {
    case .keyNotInSecureHardware, .attestationWithoutAppIdentity, .bootloaderUnlocked,
      .bootNotVerified, .untrustedAttestationRoot, .attestationRevoked:
      return .phone
    case .appIdentityMismatch, .appVersionBelowMinimum: return .app
    case .evidenceInvalid, .challengeExpired: return .attempt
    case .accountNotApproved, .accountFrozen: return .account
    }
  }

  /// Whether this reason can occur for Apple App Attest evidence. The other reasons are
  /// Android-only, so an iPhone relay that names one is a protocol error.
  public var appliesToApple: Bool {
    switch self {
    case .untrustedAttestationRoot, .appIdentityMismatch, .evidenceInvalid, .challengeExpired,
      .accountNotApproved, .accountFrozen:
      return true
    case .keyNotInSecureHardware, .attestationWithoutAppIdentity, .bootloaderUnlocked,
      .bootNotVerified, .attestationRevoked, .appVersionBelowMinimum:
      return false
    }
  }

  /// Whether the eligibility provider, not evidence verification, decides this reason (codes
  /// 11 and 12). After issuance these only withhold E6 delivery.
  public var isEligibility: Bool { holderClass == .account }

  /// Admit one code that BPNG Core relayed for this SDK's Apple App Attest evidence.
  ///
  /// Native's closed table decides first; this typed projection must agree with it.
  /// - Throws: ``KagemushaWalletErrorV1/invalidInput`` for zero, unknown and Android-only
  ///   codes; ``KagemushaWalletErrorV1/bridgeUnavailable`` without the ABI-29 Native table;
  ///   ``KagemushaWalletErrorV1/invalidNativeOutput`` if Native and this projection disagree.
  public init(relayedCode code: UInt16) throws {
    try self.init(relayedCode: code, nativeClass: kagemushaWalletEnrollmentRefusalNativeV1())
  }

  /// Agreement check against an injected Native table (`code`, `android`) -> class or -1.
  init(relayedCode code: UInt16, nativeClass: (UInt16, UInt8) -> Int32) throws {
    let reported = nativeClass(code, 0)
    let projected = Self(rawValue: code).flatMap { $0.appliesToApple ? $0 : nil }
    if reported == -1, projected == nil { throw KagemushaWalletErrorV1.invalidInput }
    guard let projected, reported == projected.holderClass.rawValue
    else { throw KagemushaWalletErrorV1.invalidNativeOutput }
    self = projected
  }
}

typealias KagemushaWalletEnrollmentRefusalSymbolV1 = @convention(c) (UInt16, UInt8) -> Int32

/// Resolve Native's closed E1 refusal table, a pure ABI-29 lookup without handle or state.
func kagemushaWalletEnrollmentRefusalNativeV1() throws -> (UInt16, UInt8) -> Int32 {
  guard
    let table = NoritoNativeBridge.shared.resolveNativeSymbol(
      "connect_norito_kagemusha_wallet_enrollment_refusal_v1",
      as: KagemushaWalletEnrollmentRefusalSymbolV1.self)
  else { throw KagemushaWalletErrorV1.bridgeUnavailable }
  return { code, android in table(code, android) }
}

/// Closed non-success outcome of one enrollment exchange (design §2.4), relayed by exactly one
/// response header (Rust `iroha_torii_shared` `EnrollmentServiceOutcomeV1`). Identical HTTP
/// statuses carry different outcomes, so a client must read the header. `Unavailable` is a
/// recovery state that carries no outcome header: retry the same retained originals.
public enum KagemushaWalletEnrollmentOutcomeV1: Equatable, Sendable {
  /// HTTP 403: the immutable Refused outcome of this attempt; every retry returns it unchanged.
  /// The E1 challenge is consumed: abandon this attempt with its marker form and, as the
  /// reason's ``KagemushaWalletEnrollmentRefusalV1/holderClass`` allows, start again with a new
  /// challenge, slot and key.
  case refused(KagemushaWalletEnrollmentRefusalV1)
  /// HTTP 403: a fresh eligibility observation withholds delivery of an Issued outcome (code 11
  /// or 12). This is not a refusal. The issuer keeps the exact E6; keep the slot, marker and
  /// retained E5 and retry delivery later. It never forces abandonment or a fresh attempt.
  case deliveryWithheld(KagemushaWalletEnrollmentRefusalV1)
  /// HTTP 409: an effect may have taken place without a retained terminal outcome. Recover the
  /// same exchange with its exact retained E5, or abandon it with the marker form; never restart
  /// it as a fresh attempt.
  case outcomeUnknown

  /// Response header relaying a terminal refusal's closed code (canonical decimal).
  public static let refusalCodeHeader = "x-iroha-kagemusha-refusal-code"
  /// Response header relaying the code (11 or 12) that withholds delivery of an Issued outcome.
  public static let deliveryWithheldHeader = "x-iroha-kagemusha-delivery-withheld-code"
  /// Response header marking an outcome that is unknown after a possible effect.
  public static let outcomeHeader = "x-iroha-kagemusha-outcome"
  /// The only value of ``outcomeHeader``.
  public static let outcomeUnknownValue = "unknown"

  /// Exact HTTP status that carries this outcome.
  public var httpStatus: Int {
    switch self {
    case .refused, .deliveryWithheld: return 403
    case .outcomeUnknown: return 409
    }
  }

  /// The one header that carries this outcome, with its exact value.
  public var header: (name: String, value: String) {
    switch self {
    case .refused(let reason): return (Self.refusalCodeHeader, String(reason.code))
    case .deliveryWithheld(let reason): return (Self.deliveryWithheldHeader, String(reason.code))
    case .outcomeUnknown: return (Self.outcomeHeader, Self.outcomeUnknownValue)
    }
  }

  /// Strictly read the outcome of one response for this SDK's Apple evidence. Header names
  /// compare case-insensitively. `nil` means the response carries no outcome header.
  /// - Throws: ``KagemushaWalletErrorV1/invalidInput`` for more than one outcome header
  ///   (including a repeated or comma-joined one), a noncanonical, zero, unknown or Android-only
  ///   code, a withholding code other than 11/12, another outcome value, or a status that does
  ///   not carry the outcome (a success carrying one included); the refusal-table errors of
  ///   ``KagemushaWalletEnrollmentRefusalV1/init(relayedCode:)``.
  public static func parse(status: Int, headers: [(name: String, value: String)]) throws -> Self? {
    try parse(status: status, headers: headers) { try KagemushaWalletEnrollmentRefusalV1(relayedCode: $0) }
  }

  /// ``parse(status:headers:)`` over a received HTTP response.
  public static func parse(_ response: HTTPURLResponse) throws -> Self? {
    var headers: [(name: String, value: String)] = []
    for (name, value) in response.allHeaderFields {
      guard let name = name as? String, let value = value as? String
      else { throw KagemushaWalletErrorV1.invalidInput }
      headers.append((name, value))
    }
    return try parse(status: response.statusCode, headers: headers)
  }

  static func parse(status: Int, headers: [(name: String, value: String)],
    reason: (UInt16) throws -> KagemushaWalletEnrollmentRefusalV1) throws -> Self? {
    func code(_ value: String) throws -> KagemushaWalletEnrollmentRefusalV1 {
      let digits = Array(value.utf8)
      guard (1...5).contains(digits.count), digits[0] != UInt8(ascii: "0"),
        digits.allSatisfy({ (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) }),
        let parsed = UInt16(value)
      else { throw KagemushaWalletErrorV1.invalidInput }
      return try reason(parsed)
    }
    // ASCII-only case folding, as HTTP field names are compared; no Unicode folding.
    func folded(_ name: String) -> String {
      String(decoding: name.utf8.map { (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains($0) ? $0 | 0x20 : $0 },
        as: UTF8.self)
    }
    var outcome: Self?
    for (name, value) in headers {
      let parsed: Self
      switch folded(name) {
      case refusalCodeHeader: parsed = .refused(try code(value))
      case deliveryWithheldHeader:
        let withheld = try code(value)
        guard withheld.isEligibility else { throw KagemushaWalletErrorV1.invalidInput }
        parsed = .deliveryWithheld(withheld)
      case outcomeHeader:
        guard value == outcomeUnknownValue else { throw KagemushaWalletErrorV1.invalidInput }
        parsed = .outcomeUnknown
      default: continue
      }
      guard outcome == nil else { throw KagemushaWalletErrorV1.invalidInput }
      outcome = parsed
    }
    if let outcome, outcome.httpStatus != status { throw KagemushaWalletErrorV1.invalidInput }
    return outcome
  }
}
