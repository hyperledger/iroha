import Foundation

// Enrollment step E5 of the iPhone wallet adapter: App Attest evidence for a Secure Enclave
// payment key (spec §2.2; G2 design rev 2, iOS "Enrollment evidence"). The App Attest calls go
// through the `KagemushaWalletAppAttestServiceV1` protocol below; only its thin iOS system
// adapter, `KagemushaWalletAppleAppAttestServiceV1`, calls DeviceCheck.

/// Raw App Attest operations; these operations do not authorize value movement.
public protocol KagemushaWalletAppAttestServiceV1: Sendable {
  var isSupported: Bool { get }
  func generateKey() async throws -> String
  func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data
  func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data
}

/// App Attest enrollment evidence of one payment key.
public struct KagemushaWalletAppleEnrollmentEvidenceV1: Equatable, Sendable {
  /// App Attest counter consumed by ``keyBindingAssertion``: the first assertion of a fresh App
  /// Attest key (its attestation carries counter 0). Any later assertion owner of
  /// ``appAttestKeyID`` (renewal) continues after this counter; it never treats the key as
  /// unused, which would restart the counter at 0.
  public static let keyBindingAssertionCounter: UInt32 = 1

  /// Identifier of the fresh App Attest key (base64 of 32 bytes); the enrollment owner keeps
  /// it for renewal assertions (an App Attest key is attested only once).
  public let appAttestKeyID: String
  /// `attestKey(clientDataHash: challenge_digest)`.
  public let attestation: Data
  /// `H("enrollment-key-binding", challenge_digest || payment_key)`, the Rust
  /// `kagemusha_wallet_enrollment_key_binding_v1`: the `clientDataHash` of
  /// ``keyBindingAssertion``.
  public let keyBindingDigest: Data
  /// `generateAssertion(clientDataHash: keyBindingDigest)` by the same App Attest key, at
  /// counter ``keyBindingAssertionCounter``.
  public let keyBindingAssertion: Data
}

/// App Attest call of enrollment step E5.
public enum KagemushaWalletAppleAppAttestStageV1: String, Equatable, Hashable, Sendable {
  case generateKey
  case attestKey
  case generateAssertion
}

/// Why App Attest enrollment evidence was not produced. Nothing is deleted or regenerated.
public enum KagemushaWalletAppleEnrollmentAttestationErrorV1: Error, Equatable, Sendable {
  /// The challenge digest is not 32 bytes.
  case invalidDigest
  /// App Attest is unsupported on this device; enrollment is refused.
  case appAttestUnsupported
  /// The keychain gave no definitive answer about the payment key; retry.
  case paymentKeyUnavailable(KagemushaWalletAppleUnavailableV1)
  /// The keychain definitively reports no payment key for the slot.
  case paymentKeyAbsent
  /// The slot's payment key is not `paymentPublicKey`, or was not generated for
  /// `challengeDigest` (its recorded binding is missing, malformed or different).
  case bindingMismatch
  /// App Attest returned a key identifier that is not base64 of 32 bytes; nothing was attested.
  case malformedAppAttestKeyID
  /// An App Attest call failed at `stage` with the underlying error's `domain` and `code`
  /// (`DCError.Code` in `DCErrorDomain`: for example `serverUnavailable` is worth retrying,
  /// `featureUnsupported` is not). An uncertain effect is never repeated implicitly.
  case appAttestFailed(stage: KagemushaWalletAppleAppAttestStageV1, domain: String, code: Int)
}

/// Internal custody callbacks. They confer no authority independently; production uses only
/// the actual Native Enrollment owner, while component tests supply explicitly unauthenticated DATA.
protocol KagemushaWalletAppleEvidenceJournalV1: Sendable {
  func originals() throws -> [Data]
  func begin(_ stage: UInt8) throws
  func retain(_ stage: UInt8, _ original: Data) throws
  func complete() throws
}

extension KagemushaWalletApplePlatformV1 {
  /// `H("enrollment-key-binding", challengeDigest || paymentPublicKey)` (Rust
  /// `kagemusha_wallet_enrollment_key_binding_v1`).
  static func enrollmentKeyBindingDigest(challengeDigest: Data, paymentPublicKey: Data) -> Data {
    KagemushaWalletWireV1.digest(role: .enrollmentKeyBinding, body: challengeDigest + paymentPublicKey)
  }

  /// Component sequencing only. Production supplies the same actual Native enrollment journal.
  /// Its dispatch claims and returned originals survive retries; no new key replaces an uncertain effect.
  func collectEnrollmentEvidence(
    slot: KagemushaWalletAppleSlotV1, paymentPublicKey: Data, challengeDigest: Data,
    journal: any KagemushaWalletAppleEvidenceJournalV1
  ) async throws -> KagemushaWalletAppleEnrollmentEvidenceV1 {
    guard challengeDigest.count == 32 else {
      throw KagemushaWalletAppleEnrollmentAttestationErrorV1.invalidDigest
    }
    guard appAttest.isSupported else {
      throw KagemushaWalletAppleEnrollmentAttestationErrorV1.appAttestUnsupported
    }
    switch bracketed({ lookupPaymentKey(slot) }) {
    case .present(let item):
      guard item.publicKey == paymentPublicKey,
        let binding = item.label.flatMap(KagemushaWalletAppleKeyGenerationRequestV1.init(label:)),
        binding.challengeDigest == challengeDigest
      else { throw KagemushaWalletAppleEnrollmentAttestationErrorV1.bindingMismatch }
    case .absent:
      throw KagemushaWalletAppleEnrollmentAttestationErrorV1.paymentKeyAbsent
    case .unavailable(let reason):
      throw KagemushaWalletAppleEnrollmentAttestationErrorV1.paymentKeyUnavailable(reason)
    }
    let keyBindingDigest = Self.enrollmentKeyBindingDigest(
      challengeDigest: challengeDigest, paymentPublicKey: paymentPublicKey)
    var originals = try journal.originals()
    if originals[0].isEmpty {
      let actual = try await appAttestCall(.generateKey, authorize: {
        try Task.checkCancellation(); try journal.begin(1)
      }) { try await appAttest.generateKey() }
      // Retain the actual return before cancellation, key-shape checks or another vendor effect.
      try journal.retain(1, Data(actual.utf8))
      originals = try journal.originals()
    }
    guard let keyID = String(data: originals[0], encoding: .utf8),
      let decoded = Data(base64Encoded: keyID), decoded.count == 32,
      decoded.contains(where: { $0 != 0 }), decoded.base64EncodedString() == keyID
    else { throw KagemushaWalletAppleEnrollmentAttestationErrorV1.malformedAppAttestKeyID }
    if originals[1].isEmpty {
      let actual = try await appAttestCall(.attestKey, authorize: {
        try Task.checkCancellation(); try journal.begin(2)
      }) {
        try await appAttest.attestKey(keyID, clientDataHash: challengeDigest)
      }
      try journal.retain(2, actual)
      originals = try journal.originals()
    }
    if originals[2].isEmpty {
      let actual = try await appAttestCall(.generateAssertion, authorize: {
        try Task.checkCancellation(); try journal.begin(3)
      }) {
        try await appAttest.generateAssertion(keyID, clientDataHash: keyBindingDigest)
      }
      try journal.retain(3, actual)
      originals = try journal.originals()
    }
    try Task.checkCancellation()
    try journal.complete()
    let attestation = originals[1], assertion = originals[2]
    return KagemushaWalletAppleEnrollmentEvidenceV1(
      appAttestKeyID: keyID, attestation: attestation, keyBindingDigest: keyBindingDigest,
      keyBindingAssertion: assertion)
  }

  /// Run one App Attest call, keeping the underlying error's domain and code on failure.
  private func appAttestCall<Value>(
    _ stage: KagemushaWalletAppleAppAttestStageV1, authorize: () throws -> Void,
    _ call: () async throws -> Value
  ) async throws -> Value {
    // Execute the Native check after entering this asynchronous function, immediately
    // before calling the vendor; no awaited preparation follows the one-use authorization.
    try authorize()
    do {
      return try await call()
    } catch {
      let underlying = error as NSError
      throw KagemushaWalletAppleEnrollmentAttestationErrorV1.appAttestFailed(
        stage: stage, domain: underlying.domain, code: underlying.code)
    }
  }
}

#if os(iOS) && canImport(DeviceCheck)
import DeviceCheck

/// Thin iOS system adapter; enrollment and assertion verification remain independent.
@available(iOS 15.0, *)
public final class KagemushaWalletAppleAppAttestServiceV1: KagemushaWalletAppAttestServiceV1,
  @unchecked Sendable
{
  private let service = DCAppAttestService.shared

  public init() {}
  public var isSupported: Bool { service.isSupported }
  public func generateKey() async throws -> String { try await service.generateKey() }
  public func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data {
    try await service.attestKey(keyID, clientDataHash: clientDataHash)
  }
  public func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
    try await service.generateAssertion(keyID, clientDataHash: clientDataHash)
  }
}
#endif
