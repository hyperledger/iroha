import CryptoKit
import Foundation

// KAGEMUSHA wallet V1 wire consumer (specs/kagemusha_single_design_proposal.md §8).
//
// The canonical objects, transcripts and vectors are owned by the Rust module
// `iroha_data_model::kagemusha::kagemusha_wallet_v1`; this file consumes
// `fixtures/kagemusha/wallet_v1_vectors.json` and mirrors only the parts an SDK needs before it
// hands bytes to the typed decoder: SHA-256 domain digests, the signing domains, the raw low-S
// P-256 signature rule over 32-byte signing messages, the canonical σ-field encoding check, the
// envelope frame header and per-kind bounds, and the strict `kgm1:` text form.
//
// Poseidon values (`credit_id`, `proof_digest`, the Payment, lineage, credit-opening,
// credit-status and credited digests, every signing message, state commitments, chains, map,
// blacklist, quota-window and credit-digest roots and openings) are computed only by the native
// Rust core over the bridge. Swift carries them as opaque 32-byte σ-field values and checks only
// that they are canonical (``KagemushaWalletWireV1/isCanonicalFieldValue(_:)``).
//
// TODO(G4): typed Swift decoding and `validate()` of the wallet message bodies (or the shared
// Rust core over the native bridge); structural envelope
// validation here carries no monetary or delivery authority on its own.

/// Failure of a KAGEMUSHA wallet V1 wire helper.
///
/// Field labels mirror the Rust `KagemushaWalletValidationErrorV1` labels (for example
/// `text.prefix`, `envelope.version`, `envelope.scheme_id`).
public enum KagemushaWalletWireErrorV1: Error, Equatable, Sendable {
  /// A complete text or canonical frame exceeds its bound.
  case encodedSizeExceeded(actual: Int, maximum: Int)
  /// A version field differs from ``KagemushaWalletWireV1/version``.
  case unsupportedVersion(field: String, version: UInt16)
  /// The envelope names a scheme other than the expected one.
  case schemeMismatch(field: String)
  /// A text, frame header or structural field is malformed.
  case invalidField(String)
}

/// Exact role label of one domain-separated KAGEMUSHA wallet V1 digest `H(role, body)`.
///
/// The 18 cases and their order mirror the Rust `KagemushaWalletDigestRoleV1::ALL`. `H` remains
/// only for values no relation recomputes: fixed identities, ledger, platform-attestation and
/// artifact boundaries, output descriptors and local custody records. Only the artifact manifest hashes
/// `m || signature`. Signed-object, certificate-set, package, statement, operation and nullifier
/// digests are opaque Poseidon field values computed by the native core (wire record §1).
public enum KagemushaWalletDigestRoleV1: String, CaseIterable, Sendable {
  /// Scheme identity.
  case scheme = "scheme"
  /// Frozen relation identity.
  case relation = "relation"
  /// Advance contract and receipt format identity.
  case providerContract = "provider-contract"
  /// Asset incarnation and scale.
  case assetScope = "asset-scope"
  /// Canonical domainless `AccountId` frame.
  case account = "account"
  /// Issuer enrollment challenge.
  case enrollmentChallenge = "enrollment-challenge"
  /// NEW first-release typed app identity; unsigned selection, no approval implied.
  case appPolicy = "app-policy"
  /// NEW first-release typed enrollment inputs; unsigned selection, no approval implied.
  case enrollmentPolicy = "enrollment-policy"
  /// Enrollment incarnation identity.
  case enrollmentID = "enrollment-id"
  /// App Attest enrollment assertion client data.
  case enrollmentKeyBinding = "enrollment-key-binding"
  /// Wallet incarnation identity.
  case walletID = "wallet-id"
  /// Artifact manifest digest.
  case artifactManifest = "artifact-manifest"
  /// Original platform evidence bytes.
  case evidence = "evidence"
  /// App Attest renewal assertion client data.
  case renewalAssertion = "renewal-assertion"
  /// σ verifying-key allowlist; its digest is the manifest's `verifying_key_set_digest`.
  case verifyingKeySet = "verifying-key-set"
  /// Receipt-free output descriptor.
  case output = "output"
  /// Local provider marker frame.
  case marker = "marker"
  /// Local recovery capsule frame.
  case capsule = "capsule"
  /// Local completion record frame.
  case completion = "completion"
  /// Durable fold record of one self-verified Ω.
  case fold = "fold"
}

/// Signing domain of one signed KAGEMUSHA wallet V1 body (wire record §1, owner answer A1).
///
/// The 17 cases and their order mirror the Rust `KagemushaWalletSigningDomainV1::ALL`; the raw
/// value is the 8-byte ASCII Poseidon domain word. Every P-256 signature of the protocol signs, as
/// its message, the 32-byte canonical encoding `m` of `P_bytes(d, transcript)` with standard
/// ECDSA-P256-SHA256 (the ECDSA hash is `SHA-256(m)`): the Secure Enclave through
/// `kSecKeyAlgorithmECDSASignatureMessageX962SHA256`, Android KeyMint through a `DIGEST_SHA256`
/// key and `SHA256withECDSA`, and issuer, policy, ledger and artifact signers with the same
/// algorithm. No-digest modes are never used. The native core computes `m`; Swift treats it as an
/// opaque canonical σ-field value.
public enum KagemushaWalletSigningDomainV1: String, CaseIterable, Sendable {
  /// Signer certificate body, signed by the scheme root.
  case certificate = "kgwcert1"
  /// Credential body, signed by an Enrollment-role key.
  case credential = "kgwcred1"
  /// Renewal challenge, signed by the payment key (possession).
  case renewalChallenge = "kgwrnch1"
  /// Renewal key binding of a newly attested Android key, signed by the payment key.
  case renewalKeyBinding = "kgwrnkb1"
  /// Artifact manifest body, signed by an Artifact-role key.
  case artifactManifest = "kgwartf1"
  /// Provider receipt body, signed by the payment key.
  case receipt = "kgwrcpt1"
  /// Scheme policy body, signed by a RegulatoryPolicy-role key.
  case schemePolicy = "kgwspol1"
  /// Fee schedule body, signed by a RegulatoryPolicy-role key.
  case feeSchedule = "kgwfsch1"
  /// Blacklist body, signed by a RegulatoryPolicy-role key.
  case blacklist = "kgwblst1"
  /// Quota share body, signed by a RegulatoryPolicy-role key.
  case quotaShare = "kgwqshr1"
  /// Time anchor body, signed by a TimeAnchor-role key.
  case timeAnchor = "kgwtanc1"
  /// Charge quote body, signed by a RegulatoryPolicy-role key.
  case chargeQuote = "kgwchgq1"
  /// Offer body, signed by the payer payment key.
  case offer = "kgwoffr1"
  /// Session control body, signed by the session payment key.
  case sessionControl = "kgwsctl1"
  /// Request body, signed by the receiver payment key.
  case request = "kgwrqst1"
  /// Ledger control body, signed by the payment key.
  case ledgerControl = "kgwlctl1"

  /// Exact byte length of the signed transcript.
  public var transcriptBytes: Int {
    switch self {
    case .certificate: 108
    case .credential: 476
    case .renewalChallenge: 130
    case .renewalKeyBinding: 163
    case .artifactManifest: 290
    case .receipt: 338
    case .schemePolicy: 142
    case .feeSchedule: 191
    case .blacklist: 118
    case .quotaShare: 190
    case .timeAnchor: 138
    case .chargeQuote: 219
    case .offer: 194
    case .sessionControl: 197
    case .request: 458
    case .ledgerControl: 211
    }
  }
}

/// Peer message kind carried by the canonical envelope; the raw value is the Norito wire tag.
public enum KagemushaWalletMessageKindV1: UInt32, CaseIterable, Sendable {
  /// Payer session hint.
  case offer = 1
  /// Receiver setup quote.
  case request = 2
  /// Complete committed Payment.
  case payment = 3
  /// Delivery evidence.
  case credited = 4
  /// Nonmonetary session control.
  case sessionControl = 5
  /// Nonmonetary policy data.
  case policyData = 6
  /// Ω of the payer's folded head, sent only after an authenticated Offer.
  case lineage = 7

  /// Maximum complete canonical envelope frame of this kind, header and padding included.
  public var maximumFrameBytes: Int {
    switch self {
    case .offer, .sessionControl:
      KagemushaWalletWireV1.sessionMaximumBytes
    case .request, .payment, .credited, .policyData, .lineage:
      KagemushaWalletWireV1.messageMaximumBytes
    }
  }

  /// Maximum complete `kgm1:` text of this kind.
  public var maximumTextBytes: Int {
    switch self {
    case .offer, .sessionControl:
      KagemushaWalletWireV1.sessionTextMaximumBytes
    case .request, .payment, .credited, .policyData, .lineage:
      KagemushaWalletWireV1.messageTextMaximumBytes
    }
  }

  /// Field path, from the variant fields, to the message's top-level `version: u16`.
  ///
  /// Offer and Request carry it in their signed body; the other kinds carry it first.
  var versionFieldPath: [Int] {
    switch self {
    case .offer, .request: [0, 0, 0]
    case .payment, .credited, .sessionControl, .policyData, .lineage: [0, 0]
    }
  }

  /// Field path, from the variant fields, to the scheme checked at decode (wire record §3.4):
  /// the body scheme of Offer and Request, the carried signed Request body's scheme of Payment
  /// (`{version, request: {body, signature}, …}`), Ω's public scheme of Lineage
  /// (`{version, lineage: {public: {version, scheme_id, …}, proof}}`), and the message's own
  /// scheme field otherwise (Credited `{version, scheme_id, evidence}`, SessionControl and
  /// PolicyData).
  var schemeFieldPath: [Int] {
    switch self {
    case .offer, .request: [0, 0, 1]
    case .payment, .lineage: [0, 1, 0, 1]
    case .credited, .sessionControl, .policyData: [0, 1]
    }
  }
}

/// One canonical envelope frame whose header, versions and per-kind bound were checked.
///
/// ``KagemushaWalletWireV1/validateEnvelope(_:expectedSchemeID:)`` also checked ``schemeID``
/// against the expected scheme; ``KagemushaWalletWireV1/inspectEnvelope(_:)`` did not.
/// Structural only: the caller must still run the typed decoder, `validate()` and signature
/// verification before acting on the message.
public struct KagemushaWalletEnvelopeFrameV1: Equatable, Sendable {
  /// Message kind selected by the envelope's wire tag.
  public let kind: KagemushaWalletMessageKindV1
  /// Scheme identity the frame names at its decode-time scheme field (32 bytes).
  public let schemeID: Data
  /// Complete canonical frame bytes.
  public let canonicalBytes: Data
}

/// KAGEMUSHA wallet V1 wire constants, digests, signature rule, envelope header and `kgm1:` text.
public enum KagemushaWalletWireV1 {
  /// Version carried by every wallet V1 object and transcript.
  public static let version: UInt16 = 1
  /// Prefix of every wallet V1 digest preimage.
  public static let digestPrefix = Data("iroha:kagemusha:wallet:v1:".utf8)
  /// Text transport discriminator.
  public static let textPrefix = "kgm1:"
  /// Maximum complete canonical envelope frame for Offer and SessionControl.
  public static let sessionMaximumBytes = 2_048
  /// Maximum complete canonical envelope frame for Request, Payment, Credited, PolicyData and
  /// Lineage.
  public static let messageMaximumBytes = 10_000
  /// `F_payment`: the bytes of a Payment envelope frame other than its Ω and σ_send proofs.
  public static let paymentFixedBytes = 1_723
  /// Joint budget of the Ω transport proof and the largest σ_send (R9): `10,000 − F_payment`.
  ///
  /// Proof transport is bounded by this budget, ``creditedReceiveProofBudgetBytes`` and
  /// ``lineageProofCapBytes``; exact lengths come from the frozen verifying-key allowlist
  /// (owner answer Q6). Until the artifacts
  /// freeze (TODO(G3)) only the carrying frame bounds them, which is all the structural envelope
  /// check enforces.
  public static let paymentProofBudgetBytes = messageMaximumBytes - paymentFixedBytes
  /// Bytes of a Credited::Receive envelope other than its σ proof.
  public static let creditedReceiveFixedBytes = 679
  /// Available σ bytes in a complete Credited::Receive envelope.
  public static let creditedReceiveProofBudgetBytes = messageMaximumBytes - creditedReceiveFixedBytes
  /// `F_status`: the bytes of a Credited::Status envelope frame other than its Ω(h) transport
  /// proof, with the fixed 32-sibling credit opening.
  public static let creditedStatusFixedBytes = 2_188
  /// Cap of the Ω transport proof so that Credited::Status fits: `10,000 − F_status`.
  public static let lineageProofCapBytes = messageMaximumBytes - creditedStatusFixedBytes
  /// Maximum σ entries of the verifying-key allowlist: one per operation, Send also once per
  /// supported enabled-controls mask, and Receive also once with the blacklist bit.
  public static let verifyingKeyEntriesMaximum = 16
  /// Maximum standalone canonical frame of the verifying-key allowlist.
  public static let verifyingKeyAllowlistMaximumBytes = 2_048
  /// Depth of every Poseidon indexed map tree and of the credit-digest tree (owner answer A2):
  /// every opening carries exactly this many siblings.
  public static let indexedTreeDepth = 32
  /// Depth of the quota-window and aligned quota-usage arrays.
  public static let quotaTreeDepth = 6
  /// Exact number of slots in each quota-usage array.
  public static let quotaUsageSlots = 1 << quotaTreeDepth
  /// Exact credit-opening transcript of a CreditStatus: `credit_id ‖ payment_digest ‖ u8 burned ‖
  /// next_key ‖ LE32 slot ‖ 32 siblings`.
  public static let creditOpeningBytes = 3 * 32 + 1 + 4 + indexedTreeDepth * 32
  /// Bytes of one signing message `m`: one canonical σ-field value (wire record §1).
  public static let signingMessageBytes = 32
  /// Maximum complete `kgm1:` text of a session-bounded envelope (2_736).
  public static let sessionTextMaximumBytes = constantTextMaximumBytes(sessionMaximumBytes)
  /// Maximum complete `kgm1:` text of a message-bounded envelope (13_339).
  public static let messageTextMaximumBytes = constantTextMaximumBytes(messageMaximumBytes)
  /// Norito frame name of the single peer-message envelope; its schema hash is derived from it.
  public static let envelopeFrameName =
    "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletEnvelopeV1"
  /// Archived payload alignment of the envelope (it contains `u128`), which fixes its padding.
  public static let envelopePayloadAlignment = 16
  /// Bytes of one digest, nonce or scheme identity.
  public static let digestBytes = 32
  /// Bytes of one uncompressed SEC1 P-256 public key.
  public static let publicKeyBytes = 65
  /// Bytes of one fixed-width `r || s` signature.
  public static let signatureBytes = 64
  /// P-256 group order `n`, big-endian.
  public static let groupOrder: [UInt8] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
  ]
  /// `floor(n / 2)`, big-endian; a canonical signature has `1 <= s <= halfOrder`.
  public static let halfOrder: [UInt8] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
  ]
  /// Bytes of one σ-field value: its canonical little-endian encoding.
  public static let fieldValueBytes = 32
  /// σ-field modulus `p` of Pasta `Fp` (the Vesta scalar field), little-endian:
  /// `p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`.
  ///
  /// Mirrors the Rust `KAGEMUSHA_WALLET_FIELD_MODULUS_V1`.
  public static let fieldModulus: [UInt8] = [
    0x01, 0x00, 0x00, 0x00, 0xed, 0x30, 0x2d, 0x99, 0x1b, 0xf9, 0x4c, 0x09, 0xfc, 0x98, 0x46, 0x22,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
  ]

  private static let base64URLAlphabet = Array(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)

  // MARK: Bounds

  /// Exact unpadded base64url length of `count` raw bytes, or `nil` on overflow or a negative
  /// count.
  public static func unpaddedBase64URLLength(_ count: Int) -> Int? {
    guard count >= 0 else { return nil }
    let (groups, overflow) = (count / 3).multipliedReportingOverflow(by: 4)
    guard !overflow else { return nil }
    let tail: Int
    switch count % 3 {
    case 0: tail = 0
    case 1: tail = 2
    default: tail = 3
    }
    let (total, tailOverflow) = groups.addingReportingOverflow(tail)
    return tailOverflow ? nil : total
  }

  /// Maximum `kgm1:` text length of a frame of at most `frameBytes` bytes, or `nil` on overflow
  /// or a negative count.
  public static func textMaximumBytes(forFrameBytes frameBytes: Int) -> Int? {
    guard let body = unpaddedBase64URLLength(frameBytes) else { return nil }
    let (total, overflow) = textPrefix.utf8.count.addingReportingOverflow(body)
    return overflow ? nil : total
  }

  /// Text bound of a protocol frame constant; the constants are small, so this cannot fail.
  private static func constantTextMaximumBytes(_ frameBytes: Int) -> Int {
    guard let total = textMaximumBytes(forFrameBytes: frameBytes) else {
      preconditionFailure("KAGEMUSHA wallet V1 text bound overflow")
    }
    return total
  }

  // MARK: Digests

  /// Exact SHA-256 preimage of `H(role, body)`.
  ///
  /// The layout is `prefix || role || 0x00 || LE64(len(body)) || body`. It is never a signed
  /// message: signatures sign the Poseidon message `m` of their ``KagemushaWalletSigningDomainV1``.
  public static func preimage(role: KagemushaWalletDigestRoleV1, body: Data) -> Data {
    let label = Data(role.rawValue.utf8)
    var preimage = Data()
    preimage.reserveCapacity(digestPrefix.count + label.count + 9 + body.count)
    preimage.append(digestPrefix)
    preimage.append(label)
    preimage.append(0)
    preimage.append(contentsOf: littleEndianLength(body.count))
    preimage.append(body)
    return preimage
  }

  /// Domain-separated digest `H(role, body)` (§8).
  public static func digest(role: KagemushaWalletDigestRoleV1, body: Data) -> Data {
    var hasher = SHA256()
    hasher.update(data: digestPrefix)
    hasher.update(data: Data(role.rawValue.utf8))
    hasher.update(data: Data([0]))
    hasher.update(data: Data(littleEndianLength(body.count)))
    hasher.update(data: body)
    return Data(hasher.finalize())
  }

  /// Artifact manifest digest: `H(artifact-manifest, m || signature)`, where `m` is its
  /// 32-byte Poseidon signing message (a canonical σ-field value).
  ///
  /// - Throws: ``KagemushaWalletWireErrorV1/invalidField(_:)`` for a message that is not one
  ///   canonical 32-byte σ-field value or a signature that is not canonical low-S.
  public static func artifactManifestDigest(
    message: Data,
    signature: Data
  ) throws -> Data {
    guard message.count == signingMessageBytes, isCanonicalFieldValue(message) else {
      throw KagemushaWalletWireErrorV1.invalidField("signing_message")
    }
    guard isCanonicalLowSSignature(signature) else {
      throw KagemushaWalletWireErrorV1.invalidField("signature")
    }
    var body = Data(message)
    body.append(signature)
    return digest(role: .artifactManifest, body: body)
  }

  // MARK: σ-field values

  /// Whether `value` is a canonical σ-field encoding: 32 little-endian bytes below
  /// ``fieldModulus``.
  ///
  /// This is a byte comparison from the most significant byte down, like the Rust
  /// `kagemusha_wallet_is_canonical_field_v1`. It is the only check Swift applies to a Poseidon
  /// value, which the native core computes; it never recomputes one.
  public static func isCanonicalFieldValue(_ value: Data) -> Bool {
    let bytes = [UInt8](value)
    guard bytes.count == fieldValueBytes else { return false }
    for index in stride(from: fieldValueBytes - 1, through: 0, by: -1)
    where bytes[index] != fieldModulus[index] {
      return bytes[index] < fieldModulus[index]
    }
    return false
  }

  // MARK: Signatures

  /// Whether `signature` is `r || s` with `1 <= r < n` and `1 <= s <= floor(n / 2)`.
  ///
  /// CryptoKit accepts a high-S signature, so every received signature must pass this check
  /// before ``verifySignature(publicKey:message:signature:)`` hands it to CryptoKit.
  public static func isCanonicalLowSSignature(_ signature: Data) -> Bool {
    guard signature.count == signatureBytes else { return false }
    let bytes = [UInt8](signature)
    let r = Array(bytes[0..<32])
    let s = Array(bytes[32..<64])
    return !isZero(r) && compareBigEndian(r, groupOrder) < 0
      && !isZero(s) && compareBigEndian(s, halfOrder) <= 0
  }

  /// Whether `publicKey` is a 65-byte uncompressed SEC1 point on P-256.
  public static func isValidPublicKey(_ publicKey: Data) -> Bool {
    publicKey.count == publicKeyBytes && publicKey.first == 0x04
      && (try? P256.Signing.PublicKey(x963Representation: publicKey)) != nil
  }

  /// Verify a received low-S ECDSA-P256-SHA256 signature over the 32-byte signing `message`
  /// (wire record §1).
  ///
  /// The message must be one canonical σ-field value: the Poseidon `P_bytes(d, transcript)` the
  /// native core computed for the body's ``KagemushaWalletSigningDomainV1``. The raw low-S check
  /// runs next; CryptoKit then checks the ECDSA equation with `e = SHA-256(message)`. Received
  /// bytes are never normalized. Returns `false` for another message length, a non-canonical
  /// message, key or signature, and a signature that does not verify.
  public static func verifySignature(publicKey: Data, message: Data, signature: Data) -> Bool {
    guard
      message.count == signingMessageBytes,
      isCanonicalFieldValue(message),
      isCanonicalLowSSignature(signature),
      isValidPublicKey(publicKey),
      let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
      let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
    else {
      return false
    }
    return key.isValidSignature(parsed, for: message)
  }

  // MARK: Text

  /// `kgm1:` text of one canonical frame: the prefix and unpadded base64url.
  public static func encodeText(_ frame: Data) -> String {
    let bytes = [UInt8](frame)
    var out = Array(textPrefix.utf8)
    out.reserveCapacity(out.count + (unpaddedBase64URLLength(bytes.count) ?? 0))
    var index = 0
    while bytes.count - index >= 3 {
      let value =
        UInt32(bytes[index]) << 16 | UInt32(bytes[index + 1]) << 8 | UInt32(bytes[index + 2])
      appendSextets(value, count: 4, to: &out)
      index += 3
    }
    switch bytes.count - index {
    case 1:
      appendSextets(UInt32(bytes[index]) << 16, count: 2, to: &out)
    case 2:
      appendSextets(UInt32(bytes[index]) << 16 | UInt32(bytes[index + 1]) << 8, count: 3, to: &out)
    default:
      break
    }
    return String(decoding: out, as: UTF8.self)
  }

  /// Strictly decode `kgm1:` text into canonical frame bytes (§8, design §4.7).
  ///
  /// Same rules and order as the Rust `kagemusha_wallet_text_decode_v1`: at most the largest
  /// text bound, the exact prefix, a non-empty body of only the base64url alphabet without
  /// padding or whitespace, a length that is not `1 mod 4`, and re-encode equality.
  ///
  /// - Throws: ``KagemushaWalletWireErrorV1`` for any other form.
  public static func decodeText(_ text: String) throws -> Data {
    let textBytes = Array(text.utf8)
    guard textBytes.count <= messageTextMaximumBytes else {
      throw KagemushaWalletWireErrorV1.encodedSizeExceeded(
        actual: textBytes.count, maximum: messageTextMaximumBytes)
    }
    let prefix = Array(textPrefix.utf8)
    guard textBytes.count >= prefix.count, Array(textBytes[0..<prefix.count]) == prefix else {
      throw KagemushaWalletWireErrorV1.invalidField("text.prefix")
    }
    let body = Array(textBytes[prefix.count...])
    guard !body.isEmpty else {
      throw KagemushaWalletWireErrorV1.invalidField("text.body")
    }
    let sextets = body.map(base64URLSextet)
    guard sextets.allSatisfy({ $0 != nil }) else {
      throw KagemushaWalletWireErrorV1.invalidField("text.alphabet")
    }
    guard body.count % 4 != 1 else {
      throw KagemushaWalletWireErrorV1.invalidField("text.length")
    }
    var frame = [UInt8]()
    frame.reserveCapacity(body.count * 3 / 4)
    var accumulator: UInt32 = 0
    var bits = 0
    for case let sextet? in sextets {
      accumulator = (accumulator << 6) | UInt32(sextet)
      bits += 6
      if bits >= 8 {
        bits -= 8
        frame.append(UInt8(truncatingIfNeeded: accumulator >> UInt32(bits)))
        accumulator &= (UInt32(1) << UInt32(bits)) - 1
      }
    }
    let decoded = Data(frame)
    guard encodeText(decoded) == text else {
      throw KagemushaWalletWireErrorV1.invalidField("text.base64url")
    }
    return decoded
  }

  // MARK: Envelope

  /// Validate one canonical envelope frame for `expectedSchemeID` (design §0 order).
  ///
  /// Rejects, in order: a frame above the largest bound (before any parsing); an expected
  /// scheme that is not 32 bytes; then everything ``inspectEnvelope(_:)`` rejects; and finally
  /// another scheme.
  ///
  /// - Throws: ``KagemushaWalletWireErrorV1``.
  public static func validateEnvelope(
    _ frame: Data,
    expectedSchemeID: Data
  ) throws -> KagemushaWalletEnvelopeFrameV1 {
    guard frame.count <= messageMaximumBytes else {
      throw KagemushaWalletWireErrorV1.encodedSizeExceeded(
        actual: frame.count, maximum: messageMaximumBytes)
    }
    guard expectedSchemeID.count == digestBytes else {
      throw KagemushaWalletWireErrorV1.invalidField("expected_scheme_id")
    }
    let envelope = try inspectEnvelope(frame)
    guard envelope.schemeID == expectedSchemeID else {
      throw KagemushaWalletWireErrorV1.schemeMismatch(field: "envelope.scheme_id")
    }
    return envelope
  }

  /// Validate one canonical envelope frame without the expected-scheme check.
  ///
  /// This is the structural check a carrier applies before handing a complete bounded message
  /// to the wallet, and the check a receiver applies to an Offer of an unknown scheme before
  /// answering UnsupportedScheme (wire record §3.4). It rejects, in order: a frame above the
  /// largest bound (before any parsing); a Norito header that is malformed, has nonzero padding
  /// or a CRC64 mismatch (`frame.header`); another schema hash than the envelope frame name's
  /// (`frame.schema`); flags other than `COMPACT_LEN` (`frame.flags`); padding other than the
  /// envelope's 16-byte payload alignment (`frame.padding`); a malformed field layout; another
  /// envelope or message version; an unknown message tag; a frame above its kind's bound; and a
  /// scheme field that is not 32 bytes. The returned ``KagemushaWalletEnvelopeFrameV1/schemeID``
  /// is the scheme the frame names, not one the caller trusts.
  ///
  /// - Throws: ``KagemushaWalletWireErrorV1``.
  public static func inspectEnvelope(_ frame: Data) throws -> KagemushaWalletEnvelopeFrameV1 {
    guard frame.count <= messageMaximumBytes else {
      throw KagemushaWalletWireErrorV1.encodedSizeExceeded(
        actual: frame.count, maximum: messageMaximumBytes)
    }
    let canonical = Data(frame)
    guard let decoded = noritoDecodeFrame(canonical) else {
      throw KagemushaWalletWireErrorV1.invalidField("frame.header")
    }
    guard decoded.header.schema == noritoSchemaHash(forTypeName: envelopeFrameName) else {
      throw KagemushaWalletWireErrorV1.invalidField("frame.schema")
    }
    guard decoded.header.compression == .none, decoded.header.flags == NoritoHeader.compactLen
    else {
      throw KagemushaWalletWireErrorV1.invalidField("frame.flags")
    }
    guard
      let padding = noritoHeaderPaddingLength(payloadAlignment: envelopePayloadAlignment),
      decoded.paddingLength == padding,
      decoded.header.length == UInt64(decoded.payload.count)
    else {
      throw KagemushaWalletWireErrorV1.invalidField("frame.padding")
    }

    let payload = [UInt8](decoded.payload)
    let envelopeFields = try structFields(payload, in: 0..<payload.count)
    guard envelopeFields.count == 2 else {
      throw KagemushaWalletWireErrorV1.invalidField("envelope.fields")
    }
    let envelopeVersion = try versionValue(payload, in: envelopeFields[0], field: "envelope.version")
    guard envelopeVersion == version else {
      throw KagemushaWalletWireErrorV1.unsupportedVersion(
        field: "envelope.version", version: envelopeVersion)
    }

    let message = envelopeFields[1]
    guard message.count >= 4 else {
      throw KagemushaWalletWireErrorV1.invalidField("message.tag")
    }
    let tag =
      UInt32(payload[message.lowerBound])
      | UInt32(payload[message.lowerBound + 1]) << 8
      | UInt32(payload[message.lowerBound + 2]) << 16
      | UInt32(payload[message.lowerBound + 3]) << 24
    guard let kind = KagemushaWalletMessageKindV1(rawValue: tag) else {
      throw KagemushaWalletWireErrorV1.invalidField("message.tag")
    }
    let variant = (message.lowerBound + 4)..<message.upperBound
    guard try structFields(payload, in: variant).count == 1 else {
      throw KagemushaWalletWireErrorV1.invalidField("message.fields")
    }
    let messageVersion = try versionValue(
      payload,
      in: fieldPath(payload, in: variant, path: kind.versionFieldPath),
      field: "message.version")
    guard messageVersion == version else {
      throw KagemushaWalletWireErrorV1.unsupportedVersion(
        field: "message.version", version: messageVersion)
    }

    guard canonical.count <= kind.maximumFrameBytes else {
      throw KagemushaWalletWireErrorV1.encodedSizeExceeded(
        actual: canonical.count, maximum: kind.maximumFrameBytes)
    }

    let schemeRange = try fieldPath(payload, in: variant, path: kind.schemeFieldPath)
    guard schemeRange.count == digestBytes else {
      throw KagemushaWalletWireErrorV1.invalidField("envelope.scheme_id")
    }
    return KagemushaWalletEnvelopeFrameV1(
      kind: kind, schemeID: Data(payload[schemeRange]), canonicalBytes: canonical)
  }

  /// Require exact structural correspondence for one Request/Payment/Credited exchange.
  /// Request has five fields and a 19-field body; Payment has five fields, including the
  /// two-field signed Request. Its body and signature must equal the quoted originals.
  /// Credited, when supplied, has three fields and must name that Request's scheme.
  /// These comparisons grant no signature, proof, recipient or monetary authority; Native
  /// still authenticates the complete messages and the evidence's payment/credit binding.
  public static func requireExchangeBinding(
    request: Data, payment: Data, credited: Data? = nil
  ) throws {
    let requestFields = try exchangeMessageFields(request, kind: .request, count: 5)
    _ = try exchangeRecordFields(requestFields[0], count: 19, label: "request.body")
    let paymentFields = try exchangeMessageFields(payment, kind: .payment, count: 5)
    let signedRequest = try exchangeRecordFields(
      paymentFields[1], count: 2, label: "payment.request")
    guard signedRequest[0] == requestFields[0], signedRequest[1] == requestFields[4] else {
      throw KagemushaWalletWireErrorV1.invalidField("payment.request.binding")
    }
    if let credited { try requireCreditedScheme(request: request, credited: credited) }
  }

  // A restored receiver record retains the Payment hash rather than the whole Payment.
  // The retained Request still owns its exact scheme comparison before ACK replay.
  static func requireCreditedScheme(request: Data, credited: Data) throws {
    let requestFields = try exchangeMessageFields(request, kind: .request, count: 5)
    let body = try exchangeRecordFields(requestFields[0], count: 19, label: "request.body")
    let creditedFields = try exchangeMessageFields(credited, kind: .credited, count: 3)
    guard creditedFields[1] == body[1] else {
      throw KagemushaWalletWireErrorV1.schemeMismatch(field: "credited.scheme_id")
    }
  }

  private static func exchangeMessageFields(
    _ frame: Data, kind: KagemushaWalletMessageKindV1, count: Int
  ) throws -> [Data] {
    guard try inspectEnvelope(frame).kind == kind,
          let decoded = noritoDecodeFrame(frame) else {
      throw KagemushaWalletWireErrorV1.invalidField("exchange.kind")
    }
    let payload = [UInt8](decoded.payload)
    let fields = try structFields(payload, in: 0..<payload.count)
    let tagged = fields[1]
    let message = try fieldPath(
      payload, in: (tagged.lowerBound + 4)..<tagged.upperBound, path: [0])
    return try exchangeRecordFields(Data(payload[message]), count: count, label: "exchange.fields")
  }

  private static func exchangeRecordFields(_ data: Data, count: Int, label: String) throws -> [Data] {
    let bytes = [UInt8](data)
    let fields = try structFields(bytes, in: 0..<bytes.count)
    guard fields.count == count else { throw KagemushaWalletWireErrorV1.invalidField(label) }
    return fields.map { Data(bytes[$0]) }
  }

  /// Strictly decode `kgm1:` text and validate the envelope frame it carries.
  ///
  /// - Throws: what ``decodeText(_:)`` and ``validateEnvelope(_:expectedSchemeID:)`` throw.
  public static func decodeEnvelopeText(
    _ text: String,
    expectedSchemeID: Data
  ) throws -> KagemushaWalletEnvelopeFrameV1 {
    try validateEnvelope(decodeText(text), expectedSchemeID: expectedSchemeID)
  }

  /// Validate a canonical envelope frame and encode its `kgm1:` text.
  ///
  /// - Throws: what ``validateEnvelope(_:expectedSchemeID:)`` throws.
  public static func encodeEnvelopeText(_ frame: Data, expectedSchemeID: Data) throws -> String {
    encodeText(try validateEnvelope(frame, expectedSchemeID: expectedSchemeID).canonicalBytes)
  }

  // MARK: Private helpers

  private static func littleEndianLength(_ count: Int) -> [UInt8] {
    // A Swift collection count is never negative, so the conversion is exact.
    withUnsafeBytes(of: UInt64(count).littleEndian, Array.init)
  }

  private static func isZero(_ bytes: [UInt8]) -> Bool {
    bytes.allSatisfy { $0 == 0 }
  }

  private static func compareBigEndian(_ lhs: [UInt8], _ rhs: [UInt8]) -> Int {
    for (left, right) in zip(lhs, rhs) where left != right {
      return left < right ? -1 : 1
    }
    return 0
  }

  private static func appendSextets(_ value: UInt32, count: Int, to out: inout [UInt8]) {
    for position in 0..<count {
      let shift = UInt32(18 - 6 * position)
      out.append(base64URLAlphabet[Int((value >> shift) & 0x3f)])
    }
  }

  private static func base64URLSextet(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 0x41...0x5a: return byte - 0x41
    case 0x61...0x7a: return byte - 0x61 + 26
    case 0x30...0x39: return byte - 0x30 + 52
    case 0x2d: return 62
    case 0x5f: return 63
    default: return nil
    }
  }

  /// Read one canonical Norito compact length (unsigned LEB128, shortest form) that must fit
  /// in the bytes remaining before `end`.
  private static func readCompactLength(
    _ bytes: [UInt8],
    at offset: inout Int,
    end: Int
  ) throws -> Int {
    var value: UInt64 = 0
    var shift: UInt64 = 0
    var groups = 0
    while true {
      guard offset < end else {
        throw KagemushaWalletWireErrorV1.invalidField("frame.length")
      }
      let byte = bytes[offset]
      offset += 1
      groups += 1
      let group = UInt64(byte & 0x7f)
      guard shift < 64, shift < 63 || group <= 1 else {
        throw KagemushaWalletWireErrorV1.invalidField("frame.varint")
      }
      value |= group << shift
      if byte & 0x80 == 0 {
        guard groups == 1 || byte != 0 else {
          throw KagemushaWalletWireErrorV1.invalidField("frame.varint")
        }
        break
      }
      shift += 7
    }
    guard value <= UInt64(end - offset) else {
      throw KagemushaWalletWireErrorV1.invalidField("frame.length")
    }
    return Int(value)
  }

  /// Every `[len][payload]` field of the struct encoded in exactly `range`.
  private static func structFields(_ bytes: [UInt8], in range: Range<Int>) throws -> [Range<Int>] {
    var fields: [Range<Int>] = []
    var offset = range.lowerBound
    while offset < range.upperBound {
      let length = try readCompactLength(bytes, at: &offset, end: range.upperBound)
      fields.append(offset..<(offset + length))
      offset += length
    }
    return fields
  }

  /// Field `index` of the struct encoded in `range`; earlier fields are skipped by length.
  private static func structField(
    _ bytes: [UInt8],
    in range: Range<Int>,
    index: Int
  ) throws -> Range<Int> {
    var offset = range.lowerBound
    for position in 0...index {
      let length = try readCompactLength(bytes, at: &offset, end: range.upperBound)
      if position == index {
        return offset..<(offset + length)
      }
      offset += length
    }
    throw KagemushaWalletWireErrorV1.invalidField("frame.length")
  }

  private static func fieldPath(
    _ bytes: [UInt8],
    in range: Range<Int>,
    path: [Int]
  ) throws -> Range<Int> {
    try path.reduce(range) { current, index in
      try structField(bytes, in: current, index: index)
    }
  }

  private static func versionValue(
    _ bytes: [UInt8],
    in range: Range<Int>,
    field: String
  ) throws -> UInt16 {
    guard range.count == 2 else {
      throw KagemushaWalletWireErrorV1.invalidField(field)
    }
    return UInt16(bytes[range.lowerBound]) | UInt16(bytes[range.lowerBound + 1]) << 8
  }
}
