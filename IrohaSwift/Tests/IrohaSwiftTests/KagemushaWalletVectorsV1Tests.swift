import CryptoKit
import Foundation
import XCTest
@testable import IrohaSwift

/// Consumes `fixtures/kagemusha/wallet_v1_vectors.json`, written by the Rust
/// `kagemusha_wallet_v1` vector test, and checks the Swift wallet wire helpers against it.
///
/// Poseidon values are computed only by the native Rust core; these tests never recompute one.
/// They check every SHA-256 role, frame, envelope and signature vector, the σ-field element lists
/// and the `P_bytes` packing, and that each Poseidon value is a canonical σ-field encoding placed
/// consistently in the frames and SHA transcripts that carry it.
final class KagemushaWalletVectorsV1Tests: XCTestCase {
  private typealias Wire = KagemushaWalletWireV1

  /// Signed objects whose digest is `H(role, e || signature)` over the matching `-body` role.
  private static let signedObjectRoles: [KagemushaWalletDigestRoleV1] = [
    .certificate, .credential, .schemePolicy, .feeSchedule, .blacklist, .quotaShare,
    .timeAnchor, .request, .receipt, .voucher, .artifactManifest, .chargeQuote,
  ]

  /// The 22 Poseidon domains of wire record §3.2, in table order.
  private static let poseidonDomains = [
    "kgwcore1", "kgwrest1", "kgwstmt1", "kgwcrdt1", "kgwschn1", "kgwrchn1", "kgwccrd1",
    "kgwpout1", "kgwload1", "kgwrdm_1", "kgwfee_1", "kgwquse1", "kgwcdig1", "kgwsmte1",
    "kgwsmtn1", "kgwblkl1", "kgwblkn1", "kgwqwin1", "kgwqwnd1", "kgwprf_1", "kgwstep1",
    "kgwpay_1",
  ]

  /// Empty depth-256 sparse-tree root pinned by wire record §3.2.
  private static let emptySparseRootHex =
    "1450223519c41ddd33c971fb997ddca6344588e5f5b7411d310cb55136b4711b"

  // MARK: Constants and bounds

  func testConstantsMatchFixtureBounds() throws {
    let fixture = try loadFixture()
    let bounds = try object(fixture, "bounds")
    XCTAssertEqual(try int(fixture, "fixture_version"), 1)
    XCTAssertEqual(try int(bounds, "version"), Int(Wire.version))
    XCTAssertEqual(try int(bounds, "session_max_bytes"), Wire.sessionMaximumBytes)
    XCTAssertEqual(try int(bounds, "message_max_bytes"), Wire.messageMaximumBytes)
    XCTAssertEqual(try int(bounds, "session_text_max_bytes"), Wire.sessionTextMaximumBytes)
    XCTAssertEqual(try int(bounds, "message_text_max_bytes"), Wire.messageTextMaximumBytes)
    XCTAssertEqual(try string(bounds, "text_prefix"), Wire.textPrefix)
    XCTAssertEqual(Wire.sessionMaximumBytes, 2_048)
    XCTAssertEqual(Wire.messageMaximumBytes, 10_000)
    XCTAssertEqual(Wire.sessionTextMaximumBytes, 2_736)
    XCTAssertEqual(Wire.messageTextMaximumBytes, 13_339)
    XCTAssertEqual(
      try int(bounds, "lineage_max_bytes"), KagemushaWalletMessageKindV1.lineage.maximumFrameBytes)
    // σ and Ω carry no separate byte caps: their exact lengths come from the frozen
    // verifying-key allowlist, jointly bounded by the Payment budget (owner answer Q6, R9).
    XCTAssertNil(bounds["proof_max_bytes"])
    XCTAssertNil(bounds["credit_status_proof_max_bytes"])
    XCTAssertFalse(try string(bounds, "proof_caps").isEmpty)
    XCTAssertEqual(try int(bounds, "payment_fixed_bytes"), Wire.paymentFixedBytes)
    XCTAssertEqual(try int(bounds, "payment_proof_budget_bytes"), Wire.paymentProofBudgetBytes)
    XCTAssertEqual(Wire.paymentFixedBytes, 1_615)
    XCTAssertEqual(Wire.paymentProofBudgetBytes, 8_385)
    XCTAssertEqual(try int(bounds, "verifying_key_entries_max"), Wire.verifyingKeyEntriesMaximum)
    XCTAssertEqual(
      try int(bounds, "credit_opening_siblings_max"), Wire.creditOpeningSiblingsMaximum)
    XCTAssertEqual(try int(bounds, "certificate_set_max"), 3)
    let frameCaps = try Dictionary(
      uniqueKeysWithValues: objects(fixture, "frames").map {
        (try string($0, "type"), try int($0, "max_bytes"))
      })
    XCTAssertEqual(
      try int(bounds, "credential_max_bytes"), frameCaps["KagemushaWalletCredentialV1"])
    XCTAssertEqual(
      try int(bounds, "fold_record_max_bytes"), frameCaps["KagemushaWalletFoldRecordV1"])
    XCTAssertEqual(
      try int(bounds, "verifying_key_allowlist_max_bytes"),
      frameCaps["KagemushaWalletVerifyingKeyAllowlistV1"])
    XCTAssertEqual(
      frameCaps["KagemushaWalletVerifyingKeyAllowlistV1"], Wire.verifyingKeyAllowlistMaximumBytes)

    XCTAssertEqual(try string(fixture, "domain_prefix"), String(decoding: Wire.digestPrefix, as: UTF8.self))
    XCTAssertEqual(try string(fixture, "domain_prefix_hex"), hex(Wire.digestPrefix))

    let header = try object(fixture, "norito_header")
    XCTAssertEqual(try int(header, "header_bytes"), NoritoHeader.encodedLength)
    XCTAssertEqual(try hexData(string(header, "magic_hex")), NoritoHeader.magic)
    XCTAssertEqual(try int(header, "major"), Int(NoritoHeader.versionMajor))
    XCTAssertEqual(try int(header, "minor"), Int(NoritoHeader.versionMinor))
    XCTAssertEqual(try int(header, "compression"), Int(NoritoCompression.none.rawValue))
    XCTAssertEqual(noritoHeaderPaddingLength(payloadAlignment: Wire.envelopePayloadAlignment), 8)

    let boundaries = try object(fixture, "signature_boundaries")
    XCTAssertEqual(try bytes(boundaries, "order_hex"), Wire.groupOrder)
    XCTAssertEqual(try bytes(boundaries, "half_order_hex"), Wire.halfOrder)
  }

  func testBase64URLLengthAndTextBoundsAreExact() {
    XCTAssertEqual(Wire.unpaddedBase64URLLength(0), 0)
    XCTAssertEqual(Wire.unpaddedBase64URLLength(1), 2)
    XCTAssertEqual(Wire.unpaddedBase64URLLength(2), 3)
    XCTAssertEqual(Wire.unpaddedBase64URLLength(3), 4)
    XCTAssertEqual(Wire.unpaddedBase64URLLength(2_048), 2_731)
    XCTAssertEqual(Wire.unpaddedBase64URLLength(10_000), 13_334)
    XCTAssertNil(Wire.unpaddedBase64URLLength(-1))
    XCTAssertNil(Wire.unpaddedBase64URLLength(Int.max))
    XCTAssertEqual(Wire.textMaximumBytes(forFrameBytes: 2_048), 2_736)
    XCTAssertEqual(Wire.textMaximumBytes(forFrameBytes: 10_000), 13_339)
    XCTAssertEqual(Wire.textMaximumBytes(forFrameBytes: 0), 5)
    XCTAssertNil(Wire.textMaximumBytes(forFrameBytes: -1))
    XCTAssertNil(Wire.textMaximumBytes(forFrameBytes: Int.max))
    for length in 0..<64 {
      XCTAssertEqual(
        Wire.unpaddedBase64URLLength(length),
        Wire.encodeText(Data(repeating: 0xa5, count: length)).utf8.count - Wire.textPrefix.utf8.count)
    }
  }

  func testMessageKindsMatchRustTagsAndBounds() throws {
    let fixture = try loadFixture()
    let tags = try objects(object(fixture, "enum_tags"), "KagemushaWalletMessageV1")
    XCTAssertEqual(tags.count, KagemushaWalletMessageKindV1.allCases.count)
    for row in tags {
      let kind = try XCTUnwrap(KagemushaWalletMessageKindV1(rawValue: UInt32(int(row, "tag"))))
      XCTAssertEqual(kindName(kind), try string(row, "variant"))
    }
    for kind in KagemushaWalletMessageKindV1.allCases {
      switch kind {
      case .offer, .sessionControl:
        XCTAssertEqual(kind.maximumFrameBytes, 2_048)
        XCTAssertEqual(kind.maximumTextBytes, 2_736)
      case .request, .payment, .credited, .policyData, .lineage:
        XCTAssertEqual(kind.maximumFrameBytes, 10_000)
        XCTAssertEqual(kind.maximumTextBytes, 13_339)
      }
    }
    XCTAssertEqual(KagemushaWalletMessageKindV1.allCases.map(\.rawValue), [1, 2, 3, 4, 5, 6, 7])
  }

  func testFrameSchemaHashesFollowFrameNames() throws {
    let frames = try objects(loadFixture(), "frames")
    XCTAssertEqual(frames.count, 26)
    var sawEnvelope = false
    for frame in frames {
      let name = try string(frame, "frame_name")
      XCTAssertEqual(
        noritoSchemaHash(forTypeName: name), try bytes(frame, "frame_hash_hex"), name)
      XCTAssertEqual(
        name, "iroha_data_model::kagemusha::kagemusha_wallet_v1::" + (try string(frame, "type")))
      if name == Wire.envelopeFrameName {
        sawEnvelope = true
        XCTAssertEqual(try int(frame, "max_bytes"), Wire.messageMaximumBytes)
      }
    }
    XCTAssertTrue(sawEnvelope)
  }

  // MARK: Digests

  func testDigestVectorsRecomputeEveryRole() throws {
    let vectors = try objects(loadFixture(), "digests")
    // Rust's current ALL table has 55 SHA-256 roles; step-relation values use Poseidon.
    XCTAssertEqual(KagemushaWalletDigestRoleV1.allCases.count, 55)
    XCTAssertEqual(vectors.count, KagemushaWalletDigestRoleV1.allCases.count)
    XCTAssertEqual(
      Set(try vectors.map { try string($0, "role") }),
      Set(KagemushaWalletDigestRoleV1.allCases.map(\.rawValue)))
    XCTAssertEqual(
      try vectors.map { try string($0, "role") },
      KagemushaWalletDigestRoleV1.allCases.map(\.rawValue))
    // Pre-split and superseded SHA-256 roles are gone; current step values use Poseidon.
    for retired in [
      "dependencies", "credit-status-statement", "credit", "proof", "step-proof", "payment",
      "blacklist-leaf", "blacklist-node", "quota-window", "quota-node",
    ] {
      XCTAssertNil(KagemushaWalletDigestRoleV1(rawValue: retired), retired)
    }
    for vector in vectors {
      let roleName = try string(vector, "role")
      let role = try XCTUnwrap(KagemushaWalletDigestRoleV1(rawValue: roleName), roleName)
      let body = try hexData(string(vector, "body_hex"))
      let preimage = try hexData(string(vector, "preimage_hex"))
      let expected = try hexData(string(vector, "digest_hex"))
      _ = try XCTUnwrap(vector["stand_in_proof"] as? Bool, roleName)
      XCTAssertEqual(Wire.preimage(role: role, body: body), preimage, roleName)
      XCTAssertEqual(Wire.digest(role: role, body: body), expected, roleName)
      XCTAssertEqual(Data(SHA256.hash(data: preimage)), expected, roleName)

      var flipped = body
      if flipped.isEmpty {
        flipped.append(0)
      } else {
        flipped[flipped.startIndex] ^= 0x01
      }
      XCTAssertNotEqual(Wire.digest(role: role, body: flipped), expected, roleName)
      let otherRole: KagemushaWalletDigestRoleV1 = role == .scheme ? .relation : .scheme
      XCTAssertNotEqual(Wire.digest(role: otherRole, body: body), expected, roleName)
    }
  }

  func testSignedObjectDigestsBindBodyDigestAndSignature() throws {
    let fixture = try loadFixture()
    let digests = try digestVectors(fixture)
    // A role may sign more than one vector object (the Send and the Receive receipt).
    let signatures = try Dictionary(
      grouping: objects(fixture, "signatures"), by: { try string($0, "role") })
    XCTAssertEqual(signatures["receipt-body"]?.count, 2)
    for role in Self.signedObjectRoles {
      let bodyRoleName = role.rawValue + "-body"
      let bodyRole = try XCTUnwrap(KagemushaWalletDigestRoleV1(rawValue: bodyRoleName))
      let objectVector = try XCTUnwrap(digests[role.rawValue], role.rawValue)
      let bodyVector = try XCTUnwrap(digests[bodyRoleName], bodyRoleName)

      let transcript = try hexData(string(objectVector, "body_hex"))
      XCTAssertEqual(transcript.count, 96, role.rawValue)
      let bodyDigest = Data(transcript.prefix(32))
      let signature = Data(transcript.suffix(64))
      let signatureVector = try XCTUnwrap(
        signatures[bodyRoleName]?.first {
          (try? hexData(string($0, "signature_hex"))) == signature
        },
        bodyRoleName)
      let body = try hexData(string(bodyVector, "body_hex"))
      XCTAssertEqual(bodyDigest, Wire.digest(role: bodyRole, body: body), role.rawValue)
      XCTAssertEqual(bodyDigest, try hexData(string(signatureVector, "e_hex")), role.rawValue)
      XCTAssertEqual(signature, try hexData(string(signatureVector, "signature_hex")))
      XCTAssertTrue(
        Wire.verifySignature(
          publicKey: try hexData(string(signatureVector, "public_key_hex")),
          role: bodyRole, body: body, signature: signature),
        role.rawValue)
      XCTAssertEqual(
        try Wire.signedObjectDigest(role: role, bodyDigest: bodyDigest, signature: signature),
        try hexData(string(objectVector, "digest_hex")),
        role.rawValue)

      let twin = try hexData(string(object(signatureVector, "high_s_twin"), "signature_hex"))
      assertWireError(
        try Wire.signedObjectDigest(role: role, bodyDigest: bodyDigest, signature: twin),
        .invalidField("signature"))
      assertWireError(
        try Wire.signedObjectDigest(
          role: role, bodyDigest: bodyDigest.prefix(31), signature: signature),
        .invalidField("body_digest"))
    }
  }

  // MARK: Signatures

  func testFixedKeysDeriveFromScalars() throws {
    let keys = try objects(loadFixture(), "keys")
    XCTAssertFalse(keys.isEmpty)
    for key in keys {
      let name = try string(key, "name")
      let scalar = try hexData(string(key, "scalar_hex"))
      let publicKey = try hexData(string(key, "public_key_hex"))
      let derived = try P256.Signing.PrivateKey(rawRepresentation: scalar).publicKey
      XCTAssertEqual(derived.x963Representation, publicKey, name)
      XCTAssertTrue(Wire.isValidPublicKey(publicKey), name)

      let sec1 = [UInt8](publicKey)
      let compressed = Data([0x02 | (sec1[64] & 1)] + sec1[1..<33])
      XCTAssertFalse(Wire.isValidPublicKey(compressed), name)
      XCTAssertFalse(Wire.isValidPublicKey(publicKey.prefix(64)), name)
      var wrongPrefix = publicKey
      wrongPrefix[wrongPrefix.startIndex] = 0x05
      XCTAssertFalse(Wire.isValidPublicKey(wrongPrefix), name)
      var offCurve = publicKey
      offCurve[offCurve.index(before: offCurve.endIndex)] ^= 0x01
      XCTAssertFalse(Wire.isValidPublicKey(offCurve), name)
    }
  }

  func testSignatureVectorsRejectHighSTwinBeforeCryptoKit() throws {
    let fixture = try loadFixture()
    XCTAssertEqual(
      try string(fixture, "signature_rule"),
      "ECDSA-P256-SHA256 over preimage_hex; RFC 6979 from the fixed scalars, frozen to low S; "
        + "a consumer accepts iff codec_ok and verify_ok")
    let keys = try objects(fixture, "keys").map { try hexData(string($0, "public_key_hex")) }
    let vectors = try objects(fixture, "signatures")
    XCTAssertEqual(vectors.count, 18)
    for vector in vectors {
      let label = try string(vector, "object")
      let role = try XCTUnwrap(KagemushaWalletDigestRoleV1(rawValue: string(vector, "role")))
      let publicKey = try hexData(string(vector, "public_key_hex"))
      let preimage = try hexData(string(vector, "preimage_hex"))
      let signature = try hexData(string(vector, "signature_hex"))
      let codecOK = try bool(vector, "codec_ok")
      let verifyOK = try bool(vector, "verify_ok")
      XCTAssertTrue(codecOK && verifyOK, label)

      // The preimage is exactly prefix || role || 0x00 || LE64(len) || body.
      let body = try bodyOfPreimage(preimage, role: role)
      XCTAssertEqual(Wire.preimage(role: role, body: body), preimage, label)
      let e = try hexData(string(vector, "e_hex"))
      XCTAssertEqual(Data(SHA256.hash(data: preimage)), e, label)
      XCTAssertEqual(Wire.digest(role: role, body: body), e, label)

      XCTAssertTrue(Wire.isValidPublicKey(publicKey), label)
      XCTAssertEqual(Wire.isCanonicalLowSSignature(signature), codecOK, label)
      XCTAssertEqual(cryptoKitEquation(publicKey, preimage, signature), verifyOK, label)
      XCTAssertTrue(
        Wire.verifySignature(publicKey: publicKey, preimage: preimage, signature: signature), label)
      XCTAssertTrue(
        Wire.verifySignature(publicKey: publicKey, role: role, body: body, signature: signature),
        label)

      // CryptoKit accepts the high-S twin; the raw low-S check rejects it first.
      let twinVector = try object(vector, "high_s_twin")
      let twin = try hexData(string(twinVector, "signature_hex"))
      XCTAssertFalse(try bool(twinVector, "codec_ok"), label)
      XCTAssertTrue(try bool(twinVector, "verify_ok"), label)
      XCTAssertFalse(Wire.isCanonicalLowSSignature(twin), label)
      XCTAssertTrue(cryptoKitEquation(publicKey, preimage, twin), label)
      XCTAssertFalse(
        Wire.verifySignature(publicKey: publicKey, preimage: preimage, signature: twin), label)
      XCTAssertFalse(
        Wire.verifySignature(publicKey: publicKey, role: role, body: body, signature: twin), label)
      XCTAssertEqual(
        try P256.Signing.ECDSASignature(
          derRepresentation: hexData(string(twinVector, "der_hex"))
        ).rawRepresentation,
        twin, label)
      XCTAssertEqual(try hexData(string(twinVector, "frozen_signature_hex")), signature, label)
      XCTAssertEqual(twin.prefix(32), signature.prefix(32), label)
      XCTAssertEqual(
        addBigEndian(Array(signature.suffix(32)), Array(twin.suffix(32))), Wire.groupOrder, label)

      // The signature binds the exact preimage and key.
      var tampered = preimage
      tampered[tampered.index(before: tampered.endIndex)] ^= 0x01
      XCTAssertFalse(
        Wire.verifySignature(publicKey: publicKey, preimage: tampered, signature: signature),
        label)
      for other in keys where other != publicKey {
        XCTAssertFalse(
          Wire.verifySignature(publicKey: other, preimage: preimage, signature: signature), label)
      }
      XCTAssertFalse(
        Wire.verifySignature(
          publicKey: publicKey, preimage: preimage, signature: signature.prefix(63)),
        label)
    }
  }

  func testSignatureBoundaryCasesSeparateCodecFromEquation() throws {
    let boundary = try object(loadFixture(), "signature_boundaries")
    let role = try XCTUnwrap(KagemushaWalletDigestRoleV1(rawValue: string(boundary, "role")))
    let body = try hexData(string(boundary, "body_hex"))
    let preimage = try hexData(string(boundary, "preimage_hex"))
    let publicKey = try hexData(string(boundary, "public_key_hex"))
    XCTAssertEqual(Wire.preimage(role: role, body: body), preimage)
    XCTAssertEqual(Data(SHA256.hash(data: preimage)), try hexData(string(boundary, "e_hex")))
    XCTAssertEqual(
      try P256.Signing.PrivateKey(rawRepresentation: hexData(string(boundary, "d_hex")))
        .publicKey.x963Representation,
      publicKey)
    let half = try bytes(boundary, "half_order_hex")
    let halfPlusOne = try bytes(boundary, "half_order_plus_one_hex")
    XCTAssertEqual(addBigEndian(half, halfPlusOne), Wire.groupOrder)

    let expected: [String: (Bool, Bool)] = [
      "s_half_order": (true, true),
      "s_half_order_plus_one_high_s_twin": (false, true),
      "r_zero": (false, false),
      "s_zero": (false, false),
      "r_order": (false, false),
      "s_order": (false, false),
    ]
    let cases = try objects(boundary, "cases")
    XCTAssertEqual(Set(try cases.map { try string($0, "name") }), Set(expected.keys))
    for row in cases {
      let name = try string(row, "name")
      let signature = try hexData(string(row, "signature_hex"))
      let codecOK = try bool(row, "codec_ok")
      let verifyOK = try bool(row, "verify_ok")
      let pinned = try XCTUnwrap(expected[name])
      XCTAssertEqual(codecOK, pinned.0, name)
      XCTAssertEqual(verifyOK, pinned.1, name)
      XCTAssertEqual(Wire.isCanonicalLowSSignature(signature), codecOK, name)
      XCTAssertEqual(cryptoKitEquation(publicKey, preimage, signature), verifyOK, name)
      XCTAssertEqual(
        Wire.verifySignature(publicKey: publicKey, preimage: preimage, signature: signature),
        codecOK && verifyOK, name)
      XCTAssertEqual(
        Wire.verifySignature(publicKey: publicKey, role: role, body: body, signature: signature),
        codecOK && verifyOK, name)
      if name == "s_half_order" {
        XCTAssertEqual(Array(signature.prefix(32)), try bytes(boundary, "r_hex"))
        XCTAssertEqual(Array(signature.suffix(32)), half)
      }
    }
  }

  // MARK: Envelopes

  func testEnvelopeVectorsValidateHeaderBoundAndScheme() throws {
    let vectors = try objects(loadFixture(), "envelopes")
    var kinds = Set<KagemushaWalletMessageKindV1>()
    for vector in vectors {
      let label = try string(vector, "variant")
      let frame = try hexData(string(vector, "canonical_hex"))
      let scheme = try hexData(string(vector, "scheme_id_hex"))
      let kind = try XCTUnwrap(
        KagemushaWalletMessageKindV1(rawValue: UInt32(int(vector, "tag"))), label)
      kinds.insert(kind)
      _ = try XCTUnwrap(vector["stand_in_proof"] as? Bool, label)
      XCTAssertEqual(kindName(kind), try string(vector, "kind"), label)
      XCTAssertEqual(kind.maximumFrameBytes, try int(vector, "bound"), label)
      XCTAssertEqual(kind.maximumTextBytes, try int(vector, "text_bound"), label)
      XCTAssertEqual(frame.count, try int(vector, "frame_len"), label)
      XCTAssertLessThanOrEqual(frame.count, kind.maximumFrameBytes, label)

      // Header: schema hash from the frame name, flags, padding, CRC64 and length.
      let frameName = try string(vector, "frame_name")
      XCTAssertEqual(frameName, Wire.envelopeFrameName, label)
      let schemaHash = try bytes(vector, "schema_hash_hex")
      XCTAssertEqual(noritoSchemaHash(forTypeName: frameName), schemaHash, label)
      let decoded = try XCTUnwrap(noritoDecodeFrame(frame), label)
      XCTAssertEqual(decoded.header.schema, schemaHash, label)
      XCTAssertEqual(Int(decoded.header.flags), try int(vector, "flags"), label)
      XCTAssertEqual(decoded.paddingLength, try int(vector, "padding_len"), label)
      XCTAssertEqual(decoded.payload.count, try int(vector, "payload_len"), label)
      XCTAssertEqual(decoded.header.length, UInt64(decoded.payload.count), label)
      let crc = try string(vector, "crc64_hex")
      XCTAssertEqual(String(format: "%016llx", crc64ECMA(decoded.payload)), crc, label)
      XCTAssertEqual(String(format: "%016llx", decoded.header.checksum), crc, label)

      let validated = try Wire.validateEnvelope(frame, expectedSchemeID: scheme)
      XCTAssertEqual(validated.kind, kind, label)
      XCTAssertEqual(validated.schemeID, scheme, label)
      XCTAssertEqual(validated.canonicalBytes, frame, label)

      var otherScheme = scheme
      otherScheme[otherScheme.startIndex] ^= 0x01
      assertWireError(
        try Wire.validateEnvelope(frame, expectedSchemeID: otherScheme),
        .schemeMismatch(field: "envelope.scheme_id"))
      // The scheme-agnostic inspection a carrier applies returns the same frame and scheme.
      XCTAssertEqual(try Wire.inspectEnvelope(frame), validated, label)
      assertWireError(
        try Wire.validateEnvelope(frame, expectedSchemeID: scheme.prefix(31)),
        .invalidField("expected_scheme_id"))

      // Strict `kgm1:` round trip.
      let text = try string(vector, "text")
      XCTAssertLessThanOrEqual(text.utf8.count, kind.maximumTextBytes, label)
      XCTAssertEqual(Wire.encodeText(frame), text, label)
      XCTAssertEqual(try Wire.decodeText(text), frame, label)
      XCTAssertEqual(try Wire.decodeEnvelopeText(text, expectedSchemeID: scheme), validated, label)
      XCTAssertEqual(try Wire.encodeEnvelopeText(frame, expectedSchemeID: scheme), text, label)
      assertWireError(
        try Wire.decodeEnvelopeText(text, expectedSchemeID: otherScheme),
        .schemeMismatch(field: "envelope.scheme_id"))
    }
    XCTAssertEqual(kinds, Set(KagemushaWalletMessageKindV1.allCases))
  }

  func testEnvelopeEveryByteFlipIsRejected() throws {
    for vector in try objects(loadFixture(), "envelopes") {
      let label = try string(vector, "variant")
      let frame = try hexData(string(vector, "canonical_hex"))
      let scheme = try hexData(string(vector, "scheme_id_hex"))
      var accepted: [Int] = []
      for index in 0..<frame.count {
        var flipped = frame
        flipped[index] ^= 0x01
        if (try? Wire.validateEnvelope(flipped, expectedSchemeID: scheme)) != nil {
          accepted.append(index)
        }
      }
      XCTAssertEqual(accepted, [], label)
      XCTAssertThrowsError(try Wire.validateEnvelope(frame.dropLast(), expectedSchemeID: scheme))
      var extended = frame
      extended.append(0)
      XCTAssertThrowsError(try Wire.validateEnvelope(extended, expectedSchemeID: scheme))
    }
  }

  func testEnvelopeBoundsAcceptLimitAndRejectLimitPlusOne() throws {
    let scheme = [UInt8](repeating: 0x5c, count: 32)
    for kind in KagemushaWalletMessageKindV1.allCases {
      let label = kindName(kind)
      let bound = kind.maximumFrameBytes
      let atLimit = try sizedEnvelope(kind: kind, scheme: scheme, frameBytes: bound)
      let validated = try Wire.validateEnvelope(atLimit, expectedSchemeID: Data(scheme))
      XCTAssertEqual(validated.kind, kind, label)
      let atLimitText = Wire.encodeText(atLimit)
      XCTAssertEqual(atLimitText.utf8.count, kind.maximumTextBytes, label)
      XCTAssertEqual(
        try Wire.decodeEnvelopeText(atLimitText, expectedSchemeID: Data(scheme)), validated, label)

      let overLimit = try sizedEnvelope(kind: kind, scheme: scheme, frameBytes: bound + 1)
      assertWireError(
        try Wire.validateEnvelope(overLimit, expectedSchemeID: Data(scheme)),
        .encodedSizeExceeded(actual: bound + 1, maximum: bound))
      assertWireError(
        try Wire.inspectEnvelope(overLimit),
        .encodedSizeExceeded(actual: bound + 1, maximum: bound))
      let overLimitText = Wire.encodeText(overLimit)
      XCTAssertEqual(overLimitText.utf8.count, kind.maximumTextBytes + 1, label)
      XCTAssertThrowsError(
        try Wire.decodeEnvelopeText(overLimitText, expectedSchemeID: Data(scheme)), label)
      assertWireError(
        try Wire.encodeEnvelopeText(overLimit, expectedSchemeID: Data(scheme)),
        .encodedSizeExceeded(actual: bound + 1, maximum: bound))

      // Decode order: versions before the per-kind bound, the bound before the scheme.
      var wrongVersion = SyntheticEnvelope(kind: kind, scheme: scheme)
      wrongVersion.messageVersion = 2
      let wrongVersionFrame = try sized(wrongVersion, frameBytes: bound + 1)
      if bound < Wire.messageMaximumBytes {
        assertWireError(
          try Wire.validateEnvelope(wrongVersionFrame, expectedSchemeID: Data(scheme)),
          .unsupportedVersion(field: "message.version", version: 2))
      }
      var otherScheme = scheme
      otherScheme[0] ^= 0x01
      assertWireError(
        try Wire.validateEnvelope(overLimit, expectedSchemeID: Data(otherScheme)),
        .encodedSizeExceeded(actual: bound + 1, maximum: bound))
    }
    // The byte cap applies before any header parsing.
    assertWireError(
      try Wire.validateEnvelope(Data(repeating: 0, count: 10_001), expectedSchemeID: Data(scheme)),
      .encodedSizeExceeded(actual: 10_001, maximum: 10_000))
  }

  func testEnvelopeStructuralRejections() throws {
    let scheme = [UInt8](repeating: 0x3a, count: 32)
    let expected = Data(scheme)
    for kind in KagemushaWalletMessageKindV1.allCases {
      let label = kindName(kind)
      let base = SyntheticEnvelope(kind: kind, scheme: scheme, fillerBytes: 17)
      XCTAssertEqual(
        try Wire.validateEnvelope(base.frame(), expectedSchemeID: expected).kind, kind, label)

      var envelopeVersion = base
      envelopeVersion.envelopeVersion = 2
      assertWireError(
        try Wire.validateEnvelope(envelopeVersion.frame(), expectedSchemeID: expected),
        .unsupportedVersion(field: "envelope.version", version: 2))

      var messageVersion = base
      messageVersion.messageVersion = 0
      assertWireError(
        try Wire.validateEnvelope(messageVersion.frame(), expectedSchemeID: expected),
        .unsupportedVersion(field: "message.version", version: 0))

      var shortScheme = base
      shortScheme.scheme = Array(scheme.prefix(31))
      assertWireError(
        try Wire.validateEnvelope(shortScheme.frame(), expectedSchemeID: expected),
        .invalidField("envelope.scheme_id"))

      var trailing = base
      trailing.trailingEnvelopeField = true
      assertWireError(
        try Wire.validateEnvelope(trailing.frame(), expectedSchemeID: expected),
        .invalidField("envelope.fields"))

      var schema = base
      schema.typeName = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletMessageV1"
      assertWireError(
        try Wire.validateEnvelope(schema.frame(), expectedSchemeID: expected),
        .invalidField("frame.schema"))

      var fixedWidth = base
      fixedWidth.flags = 0
      assertWireError(
        try Wire.validateEnvelope(fixedWidth.frame(), expectedSchemeID: expected),
        .invalidField("frame.flags"))

      for alignment in [1, 8, 32] {
        var padding = base
        padding.payloadAlignment = alignment
        assertWireError(
          try Wire.validateEnvelope(padding.frame(), expectedSchemeID: expected),
          .invalidField("frame.padding"))
      }

      var corrupted = try base.frame()
      corrupted[corrupted.index(before: corrupted.endIndex)] ^= 0x01
      assertWireError(
        try Wire.validateEnvelope(corrupted, expectedSchemeID: expected),
        .invalidField("frame.header"))
    }

    for tag: UInt32 in [0, 8, 0x0100_0001] {
      var unknown = SyntheticEnvelope(kind: .offer, scheme: scheme)
      unknown.tag = tag
      assertWireError(
        try Wire.validateEnvelope(unknown.frame(), expectedSchemeID: expected),
        .invalidField("message.tag"))
    }

    let version = compactField([1, 0])
    let offer = compactField(compactField(compactField([1, 0]) + compactField(scheme)))
    let cases: [(String, [UInt8])] = [
      ("message.tag", version + compactField([1, 0, 0])),
      ("message.fields", version + compactField(le32(1) + offer + compactField([0]))),
      ("envelope.version", compactField([1, 0, 0]) + compactField(le32(1) + offer)),
      ("envelope.fields", version),
      ("frame.length", [0x05, 1, 0]),
      ("frame.length", version + [0x80]),
      ("frame.varint", [0x82, 0x00, 1, 0] + compactField(le32(1) + offer)),
      ("frame.varint", [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]),
      ("frame.length", version + compactField(le32(1) + compactField([0x05, 1]))),
    ]
    for (field, payload) in cases {
      let frame = noritoEncode(
        typeName: Wire.envelopeFrameName, payload: Data(payload),
        flags: NoritoHeader.compactLen, payloadAlignment: Wire.envelopePayloadAlignment)
      assertWireError(
        try Wire.validateEnvelope(frame, expectedSchemeID: expected), .invalidField(field))
    }
  }

  func testEnvelopeVectorsCarryTheSplitLineageLayouts() throws {
    let fixture = try loadFixture()
    let vectors = try Dictionary(
      uniqueKeysWithValues: objects(fixture, "envelopes").map { (try string($0, "variant"), $0) })
    let offer = try vectorMessage(XCTUnwrap(vectors["Offer"]))
    let request = try vectorMessage(XCTUnwrap(vectors["Request"]))
    XCTAssertEqual(offer.fields.count, 4)
    XCTAssertEqual(request.fields.count, 5)

    // Compact Payment {version, request: {body, signature}, payer_payment_key,
    // payer_credential_digest, send}: the signed Request is exactly the Request message's body
    // and signature, and the Send package's lineage slot is Present (Ω(pred)).
    let payment = try vectorMessage(XCTUnwrap(vectors["Payment"]))
    XCTAssertEqual(payment.fields.count, 5)
    let signedRequest = try XCTUnwrap(compactFields(payment.payload, payment.fields[1]))
    XCTAssertEqual(signedRequest.count, 2)
    XCTAssertEqual(payment.bytes(signedRequest[0]), request.bytes(request.fields[0]))
    XCTAssertEqual(payment.bytes(signedRequest[1]), request.bytes(request.fields[4]))
    XCTAssertTrue(Wire.isValidPublicKey(payment.bytes(payment.fields[2])))
    XCTAssertEqual(payment.fields[3].count, Wire.digestBytes)
    let send = try XCTUnwrap(compactFields(payment.payload, payment.fields[4]))
    XCTAssertEqual(send.count, 5)
    XCTAssertEqual(payment.tag(send[2]), 1)
    let paymentObject = try XCTUnwrap(
      objects(fixture, "objects").first { $0["type"] as? String == "KagemushaWalletPaymentV1" })
    let paymentFrame = try XCTUnwrap(
      noritoDecodeFrame(hexData(string(paymentObject, "canonical_hex"))))
    XCTAssertEqual(payment.bytes(payment.message), paymentFrame.payload)

    // The Send effect carries credit_id as one canonical σ-field value: the Poseidon value of
    // the Request body (owner answer Q1).
    let creditID = try hexData(
      string(object(object(object(fixture, "poseidon"), "credit_id"), "poseidon"), "digest_hex"))
    let statement = try XCTUnwrap(compactFields(payment.payload, send[1]))
    XCTAssertEqual(statement.count, 14)
    XCTAssertEqual(payment.tag(statement[13]), 3)
    let effect = try XCTUnwrap(
      compactFields(payment.payload, (statement[13].lowerBound + 4)..<statement[13].upperBound))
    XCTAssertEqual(effect.count, 8)
    XCTAssertTrue(Wire.isCanonicalFieldValue(payment.bytes(effect[0])))
    XCTAssertEqual(payment.bytes(effect[0]), creditID)

    // Credited {version, scheme_id, evidence}: Receive 1 {package} with an empty lineage slot,
    // or Status 2 {CreditStatus}; the scheme the envelope is checked against is its own field.
    for (variant, tag) in [("Credited::Receive", UInt32(1)), ("Credited::Status", 2)] {
      let vector = try XCTUnwrap(vectors[variant], variant)
      let credited = try vectorMessage(vector)
      XCTAssertEqual(credited.fields.count, 3, variant)
      XCTAssertEqual(
        credited.bytes(credited.fields[1]), try hexData(string(vector, "scheme_id_hex")), variant)
      XCTAssertEqual(credited.tag(credited.fields[2]), tag, variant)
    }
    let receive = try vectorMessage(XCTUnwrap(vectors["Credited::Receive"]))
    let evidence = receive.fields[2]
    let evidenceFields = try XCTUnwrap(
      compactFields(receive.payload, (evidence.lowerBound + 4)..<evidence.upperBound))
    XCTAssertEqual(evidenceFields.count, 1)
    let receivePackage = try XCTUnwrap(compactFields(receive.payload, evidenceFields[0]))
    XCTAssertEqual(receivePackage.count, 5)
    XCTAssertEqual(receive.tag(receivePackage[2]), 0)

    // Lineage {version, lineage: {public, proof}}: Ω's 13 public outputs name the Offer's
    // payer wallet and a valid payment key.
    let lineage = try vectorMessage(XCTUnwrap(vectors["Lineage"]))
    XCTAssertEqual(lineage.fields.count, 2)
    let omega = try XCTUnwrap(compactFields(lineage.payload, lineage.fields[1]))
    XCTAssertEqual(omega.count, 2)
    let omegaPublic = try XCTUnwrap(compactFields(lineage.payload, omega[0]))
    XCTAssertEqual(omegaPublic.count, 13)
    let offerBody = try XCTUnwrap(compactFields(offer.payload, offer.fields[0]))
    XCTAssertEqual(lineage.bytes(omegaPublic[4]), offer.bytes(offerBody[3]))
    XCTAssertTrue(Wire.isValidPublicKey(lineage.bytes(omegaPublic[6])))

    // SessionControl {version, scheme_id, asset_digest, sender, peer, session_nonce, kind,
    // reason, credit_id, auth}: credit_id is a canonical σ-field value, zero except for
    // ReceiveDeferred.
    for variant in ["SessionControl::Close", "SessionControl::UnsupportedScheme"] {
      let control = try vectorMessage(XCTUnwrap(vectors[variant], variant))
      XCTAssertEqual(control.fields.count, 10, variant)
      XCTAssertEqual(control.bytes(control.fields[8]), Data(count: 32), variant)
    }
  }

  // MARK: Object frames

  func testObjectFramesDecodeAndReencodeByteIdentically() throws {
    let fixture = try loadFixture()
    let caps = try Dictionary(
      uniqueKeysWithValues: objects(fixture, "frames").map {
        (try string($0, "type"), try int($0, "max_bytes"))
      })
    let vectors = try objects(fixture, "objects")
    var types = Set<String>()
    for vector in vectors {
      let type = try string(vector, "type")
      let label = type + " " + (try string(vector, "variant"))
      types.insert(type)
      _ = try XCTUnwrap(vector["stand_in_proof"] as? Bool, label)
      let name = try string(vector, "frame_name")
      XCTAssertEqual(name, "iroha_data_model::kagemusha::kagemusha_wallet_v1::" + type, label)
      let frame = try hexData(string(vector, "canonical_hex"))
      XCTAssertEqual(frame.count, try int(vector, "frame_len"), label)
      if let cap = caps[type] {
        XCTAssertLessThanOrEqual(frame.count, cap, label)
      }
      let decoded = try XCTUnwrap(noritoDecodeFrame(frame), label)
      XCTAssertEqual(decoded.header.schema, noritoSchemaHash(forTypeName: name), label)
      XCTAssertEqual(decoded.header.compression, .none, label)
      XCTAssertEqual(decoded.header.flags, NoritoHeader.compactLen, label)
      XCTAssertEqual(decoded.header.length, UInt64(decoded.payload.count), label)
      let payload = [UInt8](decoded.payload)
      let fields = try XCTUnwrap(compactFields(payload, 0..<payload.count), label)
      XCTAssertFalse(fields.isEmpty, label)
      // The padding is that of the archived payload alignment (16 when the payload contains a
      // u128, none otherwise), so the frame re-encodes byte for byte.
      let alignment = try XCTUnwrap(
        [1, 16].first { noritoHeaderPaddingLength(payloadAlignment: $0) == decoded.paddingLength },
        label)
      XCTAssertEqual(
        noritoEncode(
          typeName: name, payload: decoded.payload, flags: decoded.header.flags,
          payloadAlignment: alignment),
        frame, label)
      var flipped = frame
      flipped[flipped.index(before: flipped.endIndex)] ^= 0x01
      XCTAssertNil(noritoDecodeFrame(flipped), label)
    }
    XCTAssertTrue(
      types.isSuperset(of: [
        "KagemushaWalletPaymentV1", "KagemushaWalletPackageV1", "KagemushaWalletMarkerV1",
        "KagemushaWalletRecoveryCapsuleV1", "KagemushaWalletCompletionRecordV1",
        "KagemushaWalletFoldRecordV1", "KagemushaWalletVerifyingKeyAllowlistV1",
      ]))
  }

  // MARK: Field encodings

  func testCanonicalFieldValueIsAByteComparisonBelowTheModulus() {
    // p, big-endian, as wire record §3.2 states it.
    XCTAssertEqual(
      hex(Data(Wire.fieldModulus.reversed())),
      "40000000000000000000000000000000224698fc094cf91b992d30ed00000001")
    XCTAssertEqual(Wire.fieldValueBytes, 32)
    XCTAssertFalse(Wire.isCanonicalFieldValue(Data(Wire.fieldModulus)))
    var belowModulus = Wire.fieldModulus
    belowModulus[0] -= 1
    XCTAssertTrue(Wire.isCanonicalFieldValue(Data(belowModulus)))
    var aboveModulus = Wire.fieldModulus
    aboveModulus[0] += 1
    XCTAssertFalse(Wire.isCanonicalFieldValue(Data(aboveModulus)))
    // The high half equals p's while the low half exceeds it.
    var lowHalfAbove = Wire.fieldModulus
    lowHalfAbove[15] += 1
    XCTAssertFalse(Wire.isCanonicalFieldValue(Data(lowHalfAbove)))
    // 2^254 < p, and every value below 2^254 is canonical.
    XCTAssertTrue(Wire.isCanonicalFieldValue(Data(repeating: 0, count: 31) + Data([0x40])))
    XCTAssertTrue(Wire.isCanonicalFieldValue(Data(repeating: 0xff, count: 31) + Data([0x3f])))
    XCTAssertTrue(Wire.isCanonicalFieldValue(Data(count: 32)))
    // A 31-byte chunk and a u128 integer are canonical once zero-filled to 32 bytes.
    XCTAssertTrue(Wire.isCanonicalFieldValue(Data(repeating: 0xff, count: 31) + Data([0])))
    XCTAssertTrue(
      Wire.isCanonicalFieldValue(Data(repeating: 0xff, count: 16) + Data(count: 16)))
    XCTAssertFalse(Wire.isCanonicalFieldValue(Data(repeating: 0xff, count: 32)))
    XCTAssertFalse(Wire.isCanonicalFieldValue(Data(count: 31)))
    XCTAssertFalse(Wire.isCanonicalFieldValue(Data(count: 33)))
    XCTAssertFalse(Wire.isCanonicalFieldValue(Data()))
  }

  func testEffectLayoutsMatchTheOperationTable() {
    // Effect widths before zero fill and σ element counts of wire record §3.2, by tag 1…8.
    let layouts = (1...8).map { statementEffectLayouts[UInt8($0)] ?? [] }
    XCTAssertEqual(
      layouts.map { $0.reduce(0) { $0 + $1.width } }, [64, 80, 160, 80, 64, 112, 41, 0])
    XCTAssertEqual(
      layouts.map { $0.reduce(0) { $0 + $1.elementCount } }, [4, 5, 10, 4, 3, 7, 4, 0])
    XCTAssertEqual(statementEffectLayouts.count, 8)
  }

  func testFieldEncodingsFollowTheElementRule() throws {
    let fixture = try loadFixture()
    let encodings = try object(fixture, "field_encodings")
    let digests = try digestVectors(fixture)
    XCTAssertEqual(try bytes(encodings, "modulus_le_hex"), Wire.fieldModulus)
    XCTAssertTrue(
      try string(encodings, "field")
        .hasSuffix("0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001"))
    for rule in ["element_rule", "poseidon_rule", "packing_rule"] {
      XCTAssertFalse(try string(encodings, rule).isEmpty, rule)
    }

    let domains = try objects(encodings, "domains")
    // The current Rust Poseidon domain uses, in declaration order (poseidon.rs).
    let expectedUses = [
      "core", "rest", "statement", "credit_id", "send_chain", "recv_chain",
      "consumed_credit_leaf", "pending_outgoing_leaf", "load_recovery_leaf",
      "redeem_recovery_leaf", "fee_claim_leaf", "quota_usage_leaf", "credit_digest_leaf",
      "sparse_empty_leaf", "sparse_node", "blacklist_leaf", "blacklist_node",
      "quota_window_leaf", "quota_node", "proof_digest", "step_proof_digest", "payment_digest",
    ]
    XCTAssertEqual(domains.count, expectedUses.count)
    XCTAssertEqual(try domains.map { try string($0, "use") }, expectedUses)
    XCTAssertEqual(try domains.map { try string($0, "ascii") }, Self.poseidonDomains)
    XCTAssertEqual(Set(try domains.map { try string($0, "use") }).count, domains.count)
    for domain in domains {
      let ascii = try string(domain, "ascii")
      XCTAssertEqual(ascii.utf8.count, 8, ascii)
      XCTAssertEqual(try hexData(string(domain, "u64_le_hex")), Data(ascii.utf8), ascii)
    }

    let sendStatement = try object(encodings, "send_statement")
    let receiveStatement = try object(encodings, "receive_statement")
    let state = try object(encodings, "receive_successor_state")
    let send = try fieldElements(sendStatement, "items")
    let receive = try fieldElements(receiveStatement, "items")
    let core = try fieldElements(state, "core_items")
    let rest = try fieldElements(state, "rest_items")
    let sendChain = try fieldElements(encodings, "send_chain_append_from_empty")
    let recvChain = try fieldElements(encodings, "recv_chain_append")
    let consumed = try fieldElements(encodings, "consumed_credit_leaf")
    let pending = try fieldElements(encodings, "pending_outgoing_leaf")
    let feeClaim = try fieldElements(encodings, "fee_claim_leaf")
    let creditDigest = try fieldElements(encodings, "credit_digest_leaf")
    let lists: [(String, [Data], Int)] = [
      ("send_statement", send, 28), ("receive_statement", receive, 28), ("core", core, 32),
      ("rest", rest, 13), ("send_chain", sendChain, 9), ("recv_chain", recvChain, 5),
      ("consumed_credit_leaf", consumed, 3), ("pending_outgoing_leaf", pending, 8),
      ("fee_claim_leaf", feeClaim, 4), ("credit_digest_leaf", creditDigest, 3),
    ]
    for (name, items, count) in lists {
      XCTAssertEqual(items.count, count, name)
      for item in items {
        XCTAssertTrue(Wire.isCanonicalFieldValue(item), name)
      }
    }
    guard lists.allSatisfy({ $0.1.count == $0.2 }) else { return }
    for (name, value) in [
      ("send statement digest", try hexData(string(sendStatement, "digest_hex"))),
      ("receive statement digest", try hexData(string(receiveStatement, "digest_hex"))),
      ("send chain", try hexData(string(encodings, "send_chain_append_from_empty_hex"))),
      ("recv chain", try hexData(string(encodings, "recv_chain_append_hex"))),
      ("rest digest", try hexData(string(state, "rest_digest_hex"))),
      ("commitment", try hexData(string(state, "commitment_hex"))),
    ] {
      XCTAssertTrue(Wire.isCanonicalFieldValue(value), name)
    }

    // Statement items: the element rule applied to the exact 440-byte statement transcript;
    // the Send statement is the `statement` digest vector.
    let sendTranscript = try hexData(string(sendStatement, "statement_hex"))
    XCTAssertEqual(try statementFieldElements(sendTranscript), send)
    XCTAssertEqual(
      try statementFieldElements(hexData(string(receiveStatement, "statement_hex"))), receive)
    XCTAssertEqual(sendTranscript, try digestBody(digests, "statement"))

    // Core and rest items: the element rule applied to the state frame `{version, core, rest}`,
    // whose field order is the element order.
    let stateEncoded = try hexData(string(state, "state_hex"))
    let stateFrame = try VectorFrame(stateEncoded)
    XCTAssertEqual(
      stateFrame.schema,
      noritoSchemaHash(
        forTypeName: "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletStateV1"))
    XCTAssertEqual(
      try XCTUnwrap(noritoDecodeFrame(stateEncoded)).header.flags, NoritoHeader.compactLen)
    let stateFields = try stateFrame.fields(stateFrame.root)
    XCTAssertEqual(stateFields.count, 3)
    guard stateFields.count == 3 else { return }
    XCTAssertEqual(stateFrame.data(stateFields[0]), Data([1, 0]))
    XCTAssertEqual(try frameFieldElements(stateFrame, stateFields[1], stateCoreLayout), core)
    XCTAssertEqual(try frameFieldElements(stateFrame, stateFields[2], stateRestLayout), rest)
    // The five map roots and the state nonce are nonzero canonical values.
    for index in [17, 18, 19, 20, 21, 31] {
      XCTAssertNotEqual(core[index], Data(count: 32), "core[\(index)]")
    }
    // The Receive statement's successor is the successor state's commitment.
    XCTAssertEqual(receive[16], try hexData(string(state, "commitment_hex")))

    // One credit throughout: credit_id and the Payment digest are one element each.
    let poseidon = try object(fixture, "poseidon")
    let credit = try hexData(
      string(object(object(poseidon, "credit_id"), "poseidon"), "digest_hex"))
    let paymentDigest = try hexData(string(object(poseidon, "payment_digest"), "digest_hex"))
    let sendDescriptor = Array(send[18..<26])
    XCTAssertEqual(send[18], credit)
    XCTAssertEqual(receive[18], credit)
    XCTAssertEqual(Array(send[24..<26]), fieldDigestLimbs(try digestValue(digests, "request")))
    XCTAssertEqual(Array(receive[19..<21]), fieldDigestLimbs(try digestValue(digests, "wallet-id")))
    XCTAssertEqual(receive[21], send[22])
    XCTAssertEqual(pending, sendDescriptor)
    XCTAssertEqual(sendChain, [Data(count: 32)] + sendDescriptor)
    XCTAssertEqual(Array(recvChain.dropFirst()), Array(receive[18..<22]))
    XCTAssertEqual(consumed, [credit, receive[21], receive[10]])
    XCTAssertEqual(Array(feeClaim.prefix(2)), [credit, send[23]])
    XCTAssertEqual(
      Array(feeClaim.suffix(2)), fieldDigestLimbs(try digestValue(digests, "fee-schedule")))
    XCTAssertEqual(creditDigest, [credit, paymentDigest, Data(count: 32)])

    // The receiver's successor core agrees with its Receive statement and the Send's receiver.
    XCTAssertEqual(core[0], receive[9])
    XCTAssertEqual(Array(core[1..<3]), Array(receive[3..<5]))
    XCTAssertEqual(Array(core[3..<5]), Array(receive[5..<7]))
    XCTAssertEqual(Array(core[5..<7]), Array(send[19..<21]))
    XCTAssertEqual(Array(core[7..<9]), Array(receive[7..<9]))
    XCTAssertEqual(core[11], receive[10])
    XCTAssertEqual(core[13], receive[11])
    XCTAssertEqual(core[22], receive[12])
    XCTAssertEqual(core[10], receive[13])
  }

  func testControlledStateBindsEveryPositionToItsField() throws {
    // Every element of this state is distinct and its fields are named, so the core and rest
    // layouts (owner answers Q3, Q4 and Q5: one load/redeem root, scheme and asset in the core,
    // the blacklist issue time and maximum age beside each other) are pinned by position.
    let encodings = try object(loadFixture(), "field_encodings")
    let controlled = try object(encodings, "controlled_state")
    let core = try fieldElements(controlled, "core_items")
    let rest = try fieldElements(controlled, "rest_items")
    XCTAssertEqual(core.count, 32)
    XCTAssertEqual(rest.count, 13)
    XCTAssertEqual(Set(core).count, core.count, "distinct core elements")
    XCTAssertEqual(Set(rest).count, rest.count, "distinct rest elements")
    for item in core + rest {
      XCTAssertTrue(Wire.isCanonicalFieldValue(item))
    }
    for key in ["rest_digest_hex", "commitment_hex"] {
      XCTAssertTrue(Wire.isCanonicalFieldValue(try hexData(string(controlled, key))), key)
    }
    let frame = try VectorFrame(hexData(string(controlled, "state_hex")))
    let stateFields = try frame.fields(frame.root)
    XCTAssertEqual(stateFields.count, 3)
    guard stateFields.count == 3 else { return }
    XCTAssertEqual(try frameFieldElements(frame, stateFields[1], stateCoreLayout), core)
    XCTAssertEqual(try frameFieldElements(frame, stateFields[2], stateRestLayout), rest)

    let coreOrder: [(String, FrameSlotV1)] = [
      ("lifecycle", .tag), ("scheme_id", .digest), ("asset_digest", .digest),
      ("wallet_id", .digest), ("credential_digest", .digest), ("balance", .integer),
      ("burned_total", .integer), ("sequence", .integer), ("next_send", .integer),
      ("next_load", .integer), ("next_redeem", .integer), ("send_chain", .field),
      ("recv_chain", .field), ("consumed_credit_root", .field), ("pending_outgoing_root", .field),
      ("load_redeem_recovery_root", .field), ("fee_claim_root", .field),
      ("quota_usage_root", .field), ("enabled_controls", .integer),
      ("quota_windows_root", .field), ("blacklist_version", .integer), ("blacklist_root", .field),
      ("blacklist_issued_at_ms", .integer), ("blacklist_max_age_ms", .integer),
      ("lease_expires_at_ms", .integer), ("policy_epoch", .integer),
      ("accepted_time_floor_ms", .integer), ("state_nonce", .field),
    ]
    let restOrder: [(String, FrameSlotV1)] = [
      ("permitted_controls", .integer), ("time_anchor_max_response_ms", .integer),
      ("scheme_policy", .digest), ("fee_schedule", .digest), ("blacklist", .digest),
      ("quota_share", .digest), ("quota_share_id", .integer), ("time_anchor", .digest),
    ]
    XCTAssertEqual(coreOrder.map { $0.1 }, stateCoreLayout)
    XCTAssertEqual(restOrder.map { $0.1 }, stateRestLayout)
    func named(_ fields: [String: Any], _ order: [(String, FrameSlotV1)]) throws -> [Data] {
      XCTAssertEqual(Set(fields.keys), Set(order.map { $0.0 }))
      var items: [Data] = []
      for (name, slot) in order {
        let text = try string(fields, name)
        switch slot {
        case .tag, .integer:
          guard let value = UInt64(text) else { throw WalletFixtureFailure.malformed(name) }
          items.append(fieldInteger(withUnsafeBytes(of: value.littleEndian, Array.init)))
        case .digest:
          items += fieldDigestLimbs(try hexData(text))
        case .field:
          items.append(try hexData(text))
        }
      }
      return items
    }
    XCTAssertEqual(try named(object(controlled, "core_fields"), coreOrder), core)
    XCTAssertEqual(try named(object(controlled, "rest_fields"), restOrder), rest)
  }

  // MARK: Poseidon values

  func testPoseidonKnownAnswersAndPackingFollowTheRules() throws {
    let poseidon = try object(loadFixture(), "poseidon")
    // One known answer per domain over [1, 2, 3]. Swift never recomputes `P`: it checks the
    // domain set and element lists, and that every value is a distinct canonical encoding.
    let kats = try objects(poseidon, "kats")
    XCTAssertEqual(try kats.map { try string($0, "domain") }, Self.poseidonDomains)
    let oneTwoThree = [1, 2, 3].map { fieldInteger([UInt8($0)]) }
    var values = Set<Data>()
    for kat in kats {
      let domain = try string(kat, "domain")
      XCTAssertEqual(try fieldElements(kat, "items"), oneTwoThree, domain)
      let value = try hexData(string(kat, "digest_hex"))
      XCTAssertTrue(Wire.isCanonicalFieldValue(value), domain)
      values.insert(value)
    }
    XCTAssertEqual(values.count, kats.count)

    // The `P_bytes` packing at the empty input and the 31-byte chunk boundaries.
    let packing = try objects(poseidon, "packing")
    XCTAssertEqual(try packing.map { try int($0, "len") }, [0, 1, 30, 31, 32, 62, 63])
    var packed = Set<Data>()
    for row in packing {
      let length = try int(row, "len")
      let input = try hexData(string(row, "bytes_hex"))
      XCTAssertEqual(input, Data((0..<length).map { UInt8($0 + 1) }), "len \(length)")
      let hashed = try object(row, "poseidon")
      XCTAssertEqual(try string(hashed, "domain"), "kgwstep1", "len \(length)")
      let items = try fieldElements(hashed, "items")
      XCTAssertEqual(items, packedFieldElements(input), "len \(length)")
      XCTAssertEqual(items.count, 1 + (length + 30) / 31, "len \(length)")
      for item in items {
        XCTAssertTrue(Wire.isCanonicalFieldValue(item), "len \(length)")
      }
      let value = try hexData(string(hashed, "digest_hex"))
      XCTAssertTrue(Wire.isCanonicalFieldValue(value), "len \(length)")
      packed.insert(value)
    }
    XCTAssertEqual(packed.count, packing.count)
  }

  func testCreditIDIsOneValueOverTheRequestBodyElements() throws {
    let fixture = try loadFixture()
    let digests = try digestVectors(fixture)
    let creditID = try object(object(fixture, "poseidon"), "credit_id")
    let body = try hexData(string(creditID, "request_body_hex"))
    XCTAssertEqual(body, try digestBody(digests, "request-body"))
    XCTAssertEqual(body.count, 354)
    let hashed = try object(creditID, "poseidon")
    XCTAssertEqual(try string(hashed, "domain"), "kgwcrdt1")
    let items = try fieldElements(hashed, "items")
    XCTAssertEqual(items.count, 24)
    XCTAssertEqual(items, try transcriptFieldElements([UInt8](body), requestBodyLayout))
    let credit = try hexData(string(hashed, "digest_hex"))
    XCTAssertTrue(Wire.isCanonicalFieldValue(credit))
    XCTAssertNotEqual(credit, Data(count: 32))
    // The Request envelope's body record is these fixed-width fields in transcript order.
    let request = try VectorFrame(envelopeFrame(fixture, "Request"))
    let message = try request.envelopeMessage()
    XCTAssertEqual(message.tag, 2)
    let bodyFields = try request.fields(XCTUnwrap(message.fields.first))
    XCTAssertEqual(bodyFields.count, 15)
    XCTAssertEqual(bodyFields.reduce(Data()) { $0 + request.data($1) }, body)
  }

  func testProofAndPaymentDigestsBindTheCarriedBytes() throws {
    let fixture = try loadFixture()
    let poseidon = try object(fixture, "poseidon")
    let digests = try digestVectors(fixture)

    // The Payment's Send package carries Ω(pred) and σ_send.
    let paymentFrame = try VectorFrame(envelopeFrame(fixture, "Payment"))
    let payment = try paymentFrame.envelopeMessage()
    XCTAssertEqual(payment.tag, 3)
    XCTAssertEqual(payment.fields.count, 5)
    let send = try paymentFrame.fields(payment.fields[4])
    XCTAssertEqual(send.count, 5)
    let slot = try paymentFrame.variant(send[2])
    XCTAssertEqual(slot.tag, 1)
    let omega = try paymentFrame.fields(XCTUnwrap(slot.fields.first))
    XCTAssertEqual(omega.count, 2)
    let omegaBytes =
      try lineagePublicTranscript(paymentFrame, omega[0]) + paymentFrame.byteVector(omega[1])
    // `lineage` is the SHA digest of exactly these Ω bytes.
    XCTAssertEqual(omegaBytes, try digestBody(digests, "lineage"))
    let sigmaSend = try paymentFrame.byteVector(paymentFrame.field(send[3], 0))

    // proof_digest: P_bytes(kgwprf_1, LE32 len(Ω) ‖ Ω ‖ LE32 len(σ) ‖ σ) for Send.
    let proofDigests = try objects(poseidon, "proof_digests")
    XCTAssertEqual(proofDigests.count, 2)
    guard proofDigests.count == 2 else { return }
    XCTAssertEqual(
      try hexData(string(proofDigests[0], "body_hex")), lengthPrefixed([omegaBytes, sigmaSend]))
    let sendProof = try packedDigest(proofDigests[0], domain: "kgwprf_1")

    // The Send receipt body, package digest and statement place it by position (§3.2).
    let sendReceipt = [UInt8](try signedBody(fixture, object: "Send receipt"))
    XCTAssertEqual(Data(sendReceipt), try digestBody(digests, "receipt-body"))
    XCTAssertEqual(sendReceipt.count, 338)
    guard sendReceipt.count == 338 else { return }
    XCTAssertEqual(Data(sendReceipt[242..<274]), sendProof)
    XCTAssertEqual(Data(sendReceipt[306..<338]), Data(count: 32))
    let package = [UInt8](try digestBody(digests, "package"))
    XCTAssertEqual(package.count, 96)
    XCTAssertEqual(Data(package[0..<32]), try digestValue(digests, "statement"))
    XCTAssertEqual(Data(package[32..<64]), sendProof)
    XCTAssertEqual(Data(package[64..<96]), try digestValue(digests, "receipt"))

    // proof_digest: P_bytes(kgwstep1, LE32 len(σ) ‖ σ) for the Receive package of Credited.
    let receiveFrame = try VectorFrame(envelopeFrame(fixture, "Credited::Receive"))
    let credited = try receiveFrame.envelopeMessage()
    XCTAssertEqual(credited.tag, 4)
    let evidence = try receiveFrame.variant(credited.fields[2])
    XCTAssertEqual(evidence.tag, 1)
    let receivePackage = try receiveFrame.fields(XCTUnwrap(evidence.fields.first))
    XCTAssertEqual(receivePackage.count, 5)
    let sigmaReceive = try receiveFrame.byteVector(receiveFrame.field(receivePackage[3], 0))
    XCTAssertEqual(try hexData(string(proofDigests[1], "body_hex")), lengthPrefixed([sigmaReceive]))
    let receiveProof = try packedDigest(proofDigests[1], domain: "kgwstep1")
    XCTAssertNotEqual(receiveProof, sendProof)

    // Payment digest: P_bytes(kgwpay_1, payment transcript), binding Ω(pred), σ_send and τ_send
    // through the Send package digest (owner answer Q9).
    let paymentDigest = try object(poseidon, "payment_digest")
    let transcript = [UInt8](try hexData(string(paymentDigest, "body_hex")))
    XCTAssertEqual(transcript.count, 163)
    guard transcript.count == 163 else { return }
    XCTAssertEqual(Array(transcript[0..<2]), [1, 0])
    XCTAssertEqual(Data(transcript[2..<34]), try digestValue(digests, "request"))
    XCTAssertEqual(Data(transcript[34..<99]), paymentFrame.data(payment.fields[2]))
    XCTAssertEqual(Data(transcript[99..<131]), paymentFrame.data(payment.fields[3]))
    XCTAssertEqual(Data(transcript[99..<131]), try digestValue(digests, "credential"))
    XCTAssertEqual(Data(transcript[131..<163]), try digestValue(digests, "package"))
    let paymentValue = try packedDigest(paymentDigest, domain: "kgwpay_1")
    XCTAssertEqual(try int(paymentDigest, "elements"), 7)

    // The Receive receipt binds σ_recv's proof_digest and the Payment digest; the Receive
    // package's receipt, its output descriptor and the Credited transcript carry the same value.
    let receiveReceipt = [UInt8](
      try signedBody(fixture, object: "Receive receipt binding the Payment digest"))
    XCTAssertEqual(receiveReceipt.count, 338)
    guard receiveReceipt.count == 338 else { return }
    XCTAssertEqual(Data(receiveReceipt[242..<274]), receiveProof)
    XCTAssertEqual(Data(receiveReceipt[306..<338]), paymentValue)
    XCTAssertEqual(
      receiveFrame.data(try receiveFrame.field(receivePackage[4], 3)), paymentValue)
    let output = [UInt8](try digestBody(digests, "output"))
    XCTAssertEqual(output.count, 97)
    guard output.count == 97 else { return }
    XCTAssertEqual(output[0], 4)
    let receiveStatement = try hexData(
      string(object(object(fixture, "field_encodings"), "receive_statement"), "statement_hex"))
    XCTAssertEqual(Data(output[1..<33]), Wire.digest(role: .statement, body: receiveStatement))
    XCTAssertEqual(Data(output[33..<65]), receiveProof)
    XCTAssertEqual(Data(output[65..<97]), paymentValue)
    let creditedBody = [UInt8](try digestBody(digests, "credited"))
    XCTAssertEqual(creditedBody.count, 99)
    guard creditedBody.count == 99 else { return }
    XCTAssertEqual(Array(creditedBody[0..<3]), [1, 0, 1])
    XCTAssertEqual(
      Data(creditedBody[3..<35]),
      try hexData(string(object(object(poseidon, "credit_id"), "poseidon"), "digest_hex")))
    XCTAssertEqual(Data(creditedBody[35..<67]), paymentValue)
  }

  func testMapLeavesAndSparseOpeningsFollowTheKeyRules() throws {
    let fixture = try loadFixture()
    let poseidon = try object(fixture, "poseidon")
    let encodings = try object(fixture, "field_encodings")
    let digests = try digestVectors(fixture)
    let credit = try hexData(
      string(object(object(poseidon, "credit_id"), "poseidon"), "digest_hex"))

    // Every map leaf: its domain, element list and key; `credit_id` keys the credit maps.
    let leaves = try object(poseidon, "leaves")
    let expectations: [(name: String, domain: String, list: String?)] = [
      ("consumed_credit", "kgwccrd1", "consumed_credit_leaf"),
      ("pending_outgoing", "kgwpout1", "pending_outgoing_leaf"),
      ("fee_claim", "kgwfee_1", "fee_claim_leaf"),
      ("load_recovery", "kgwload1", nil),
      ("redeem_recovery", "kgwrdm_1", nil),
      ("quota_usage", "kgwquse1", nil),
    ]
    XCTAssertEqual(Set(leaves.keys), Set(expectations.map { $0.name }))
    for expectation in expectations {
      let leaf = try object(leaves, expectation.name)
      XCTAssertEqual(try string(leaf, "domain"), expectation.domain, expectation.name)
      let items = try fieldElements(leaf, "items")
      for value in items + [try hexData(string(leaf, "key_hex"))] {
        XCTAssertTrue(Wire.isCanonicalFieldValue(value), expectation.name)
      }
      let value = try hexData(string(leaf, "digest_hex"))
      XCTAssertTrue(Wire.isCanonicalFieldValue(value), expectation.name)
      if let list = expectation.list {
        XCTAssertEqual(items, try fieldElements(encodings, list), expectation.name)
        XCTAssertEqual(try hexData(string(leaf, "key_hex")), credit, expectation.name)
      }
    }

    // One load/redeem recovery map keyed by (kind, ordinal) = kind · 2^128 + ordinal (owner
    // answer Q3): Load 1 {ordinal, voucher (2), amount}, Redeem 2 {ordinal, nullifier (2),
    // amount, online_charge}, whose nullifier recomputes from the vector's scheme and wallet.
    let load = try object(leaves, "load_recovery")
    let loadItems = try fieldElements(load, "items")
    XCTAssertEqual(loadItems.count, 4)
    let loadKey = try hexData(string(load, "key_hex"))
    XCTAssertEqual(loadKey, pairKey(high: 1, low: loadItems[0]))
    XCTAssertEqual(Array(loadItems[1..<3]), fieldDigestLimbs(try digestValue(digests, "voucher")))
    let redeem = try object(leaves, "redeem_recovery")
    let redeemItems = try fieldElements(redeem, "items")
    XCTAssertEqual(redeemItems.count, 5)
    let redeemKey = try hexData(string(redeem, "key_hex"))
    XCTAssertEqual(redeemKey, pairKey(high: 2, low: redeemItems[0]))
    let nullifierBody = try digestBody(digests, "unload-nullifier")
    XCTAssertEqual(nullifierBody.count, 80)
    let nullifier = Wire.digest(
      role: .unloadNullifier, body: nullifierBody.prefix(64) + redeemItems[0].prefix(16))
    XCTAssertEqual(Array(redeemItems[1..<3]), fieldDigestLimbs(nullifier))
    // Quota usage keyed by window kind · 2^128 + window start.
    let usage = try object(leaves, "quota_usage")
    let usageItems = try fieldElements(usage, "items")
    XCTAssertEqual(usageItems.count, 4)
    XCTAssertEqual(
      try hexData(string(usage, "key_hex")),
      pairKey(high: usageItems[0].first ?? 0, low: usageItems[1]))

    // The depth-256 sparse tree: the pinned empty root and known default subtrees.
    let sparse = try object(poseidon, "sparse_tree")
    let emptyLeaf = try hexData(string(sparse, "empty_leaf_hex"))
    let heightOne = try hexData(string(sparse, "default_height_1_hex"))
    let emptyRoot = try hexData(string(sparse, "empty_root_hex"))
    XCTAssertEqual(hex(emptyRoot), Self.emptySparseRootHex)
    XCTAssertEqual(Set([emptyLeaf, heightOne, emptyRoot]).count, 3)
    for value in [emptyLeaf, heightOne, emptyRoot] {
      XCTAssertTrue(Wire.isCanonicalFieldValue(value))
    }
    let defaults = [emptyLeaf, heightOne]

    // A one-leaf consumed-credit map: the member opens with no siblings; the key that differs
    // in bit 0 is absent, opens to the empty leaf, and its only sibling is the member's leaf.
    let membership = try object(sparse, "consumed_credit_membership")
    let absence = try object(sparse, "consumed_credit_absence")
    let member = try checkedOpening(membership, defaults: defaults, label: "membership")
    let absent = try checkedOpening(absence, defaults: defaults, label: "absence")
    XCTAssertEqual(try hexData(string(membership, "key_hex")), credit)
    XCTAssertEqual(
      try hexData(string(membership, "leaf_hex")),
      try hexData(string(object(leaves, "consumed_credit"), "digest_hex")))
    XCTAssertEqual(member.siblings, [])
    XCTAssertEqual(member.bitmap, Data(count: 32))
    var flipped = [UInt8](credit)
    flipped[0] ^= 0x01
    XCTAssertEqual(try hexData(string(absence, "key_hex")), Data(flipped))
    XCTAssertEqual(try hexData(string(absence, "leaf_hex")), emptyLeaf)
    XCTAssertEqual(try string(absence, "root_hex"), try string(membership, "root_hex"))
    XCTAssertEqual(absent.bitmap, Data([1]) + Data(count: 31))
    XCTAssertEqual(absent.siblings, [try hexData(string(membership, "leaf_hex"))])

    // The load and redeem leaves share one recovery root. Their keys first differ at bit 129
    // (kinds 1 and 2), so the load opening's only sibling sits at that height.
    let loadOpening = try object(sparse, "load_membership")
    let opened = try checkedOpening(loadOpening, defaults: defaults, label: "load")
    XCTAssertEqual(try hexData(string(loadOpening, "key_hex")), loadKey)
    XCTAssertEqual(
      try hexData(string(loadOpening, "leaf_hex")), try hexData(string(load, "digest_hex")))
    XCTAssertEqual(
      try string(loadOpening, "root_hex"), try string(sparse, "load_redeem_recovery_root_hex"))
    let height = try XCTUnwrap(highestDifferingBit(loadKey, redeemKey))
    XCTAssertEqual(height, 129)
    var bitmap = [UInt8](repeating: 0, count: 32)
    bitmap[height / 8] |= 1 << UInt8(height % 8)
    XCTAssertEqual(opened.bitmap, Data(bitmap))
    XCTAssertEqual(opened.siblings.count, 1)
  }

  func testCreditStatusOpeningMatchesItsCreditDigestLeaf() throws {
    let fixture = try loadFixture()
    let poseidon = try object(fixture, "poseidon")
    let digests = try digestVectors(fixture)
    let credit = try hexData(
      string(object(object(poseidon, "credit_id"), "poseidon"), "digest_hex"))
    let paymentValue = try hexData(string(object(poseidon, "payment_digest"), "digest_hex"))
    let sparse = try object(poseidon, "sparse_tree")
    let defaults = try ["empty_leaf_hex", "default_height_1_hex"].map {
      try hexData(string(sparse, $0))
    }

    // The credit-digest leaf P(kgwcdig1, [credit_id, payment_digest, burned]) keyed by credit_id
    // (owner answer Q7).
    let vector = try object(poseidon, "credit_digest_opening")
    let leaf = try object(vector, "leaf")
    XCTAssertEqual(try string(leaf, "domain"), "kgwcdig1")
    XCTAssertEqual(try fieldElements(leaf, "items"), [credit, paymentValue, Data(count: 32)])
    XCTAssertEqual(try hexData(string(leaf, "key_hex")), credit)
    let opening = try object(vector, "opening")
    let checked = try checkedOpening(opening, defaults: defaults, label: "credit digest")
    XCTAssertEqual(try hexData(string(opening, "key_hex")), credit)
    XCTAssertEqual(try string(opening, "leaf_hex"), try string(leaf, "digest_hex"))

    // Credited::Status carries the same compressed opening, and Ω(h) exposes its root.
    let frame = try VectorFrame(envelopeFrame(fixture, "Credited::Status"))
    let credited = try frame.envelopeMessage()
    XCTAssertEqual(credited.tag, 4)
    let evidence = try frame.variant(credited.fields[2])
    XCTAssertEqual(evidence.tag, 2)
    let status = try frame.fields(XCTUnwrap(evidence.fields.first))
    XCTAssertEqual(status.count, 6)
    guard status.count == 6 else { return }
    let carried = try frame.fields(status[5])
    XCTAssertEqual(carried.count, 5)
    guard carried.count == 5 else { return }
    XCTAssertEqual(frame.data(carried[0]), credit)
    XCTAssertEqual(frame.data(carried[1]), paymentValue)
    XCTAssertEqual(frame.data(carried[2]), Data([0]))
    XCTAssertEqual(frame.data(carried[3]), checked.bitmap)
    let siblingBytes = try frame.byteVector(carried[4])
    XCTAssertEqual(siblingBytes, checked.siblings.reduce(Data(), +))
    let omega = try frame.fields(status[4])
    XCTAssertEqual(omega.count, 2)
    let omegaPublic = try lineagePublicTranscript(frame, omega[0])
    XCTAssertEqual(Data(omegaPublic.suffix(32)), try hexData(string(opening, "root_hex")))
    let statusProof = frame.data(status[2])
    XCTAssertTrue(Wire.isCanonicalFieldValue(statusProof))
    XCTAssertNotEqual(statusProof, Data(count: 32))

    // The `credit-opening` and `credit-status` SHA transcripts carry these values by position.
    var openingTranscript = credit + paymentValue + Data([0]) + checked.bitmap
    openingTranscript.append(contentsOf: le32(UInt32(checked.siblings.count)))
    openingTranscript.append(siblingBytes)
    XCTAssertEqual(openingTranscript, try digestBody(digests, "credit-opening"))
    XCTAssertEqual(openingTranscript.count, 101 + 32 * checked.siblings.count)
    let statusBody = [UInt8](try digestBody(digests, "credit-status"))
    XCTAssertEqual(statusBody.count, 162)
    guard statusBody.count == 162 else { return }
    XCTAssertEqual(Data(statusBody[34..<66]), statusProof)
    let omegaBytes = try omegaPublic + frame.byteVector(omega[1])
    XCTAssertEqual(Data(statusBody[98..<130]), Wire.digest(role: .lineage, body: omegaBytes))
    XCTAssertEqual(Data(statusBody[130..<162]), try digestValue(digests, "credit-opening"))
  }

  func testBlacklistAndQuotaTreesBindTheirSignedFrames() throws {
    let fixture = try loadFixture()
    let poseidon = try object(fixture, "poseidon")
    let digests = try digestVectors(fixture)

    // Blacklist {body, signature, entries: [{account_digest}]}: strictly ascending entries
    // strictly between the 00…00 and FF…FF sentinels.
    let blacklistFrame = try VectorFrame(objectFrame(fixture, "KagemushaWalletBlacklistV1"))
    let blacklistFields = try blacklistFrame.fields(blacklistFrame.root)
    XCTAssertEqual(blacklistFields.count, 3)
    guard blacklistFields.count == 3 else { return }
    let entries = try blacklistFrame.sequence(blacklistFields[2]).map {
      try blacklistFrame.data(blacklistFrame.field($0, 0))
    }
    XCTAssertFalse(entries.isEmpty)
    let low = Data(count: 32)
    let high = Data(repeating: 0xff, count: 32)
    let sentinels = [low] + entries + [high]
    for (lower, upper) in zip(sentinels, sentinels.dropFirst()) {
      XCTAssertTrue(lower.lexicographicallyPrecedes(upper))
    }
    let blacklist = try object(poseidon, "blacklist")
    let root = try hexData(string(blacklist, "entries_root_hex"))
    XCTAssertTrue(Wire.isCanonicalFieldValue(root))
    XCTAssertNotEqual(root, Data(count: 32))
    let body = [UInt8](try digestBody(digests, "blacklist-body"))
    XCTAssertEqual(body.count, 118)
    guard body.count == 118, let firstEntry = entries.first else { return }
    XCTAssertEqual(readLE32(body, at: 50), UInt32(entries.count))
    XCTAssertEqual(Data(body[54..<86]), root)

    // Leaf P(kgwblkl1, limbs(s_i) ‖ limbs(s_(i+1))) and node P(kgwblkn1, [left, right]).
    let leaf0 = try object(blacklist, "leaf_0")
    XCTAssertEqual(try string(leaf0, "domain"), "kgwblkl1")
    XCTAssertEqual(
      try fieldElements(leaf0, "items"), fieldDigestLimbs(low) + fieldDigestLimbs(firstEntry))
    let node = try object(blacklist, "node_0_1")
    XCTAssertEqual(try string(node, "domain"), "kgwblkn1")
    let nodeItems = try fieldElements(node, "items")
    XCTAssertEqual(nodeItems.count, 2)
    XCTAssertEqual(nodeItems.first, try hexData(string(leaf0, "digest_hex")))
    for value in nodeItems + [try hexData(string(node, "digest_hex"))] {
      XCTAssertTrue(Wire.isCanonicalFieldValue(value))
    }

    // A gap opening of an unlisted account: its leaf's bounds enclose it, with 16 siblings.
    let gap = try object(blacklist, "gap_opening")
    let account = try hexData(string(gap, "account_digest_hex"))
    XCTAssertEqual(account, Wire.digest(role: .account, body: Data("unlisted".utf8)))
    let index = try int(gap, "leaf_index")
    XCTAssertTrue(sentinels.indices.dropLast().contains(index))
    guard sentinels.indices.dropLast().contains(index) else { return }
    let lower = try hexData(string(gap, "lower_hex"))
    let upper = try hexData(string(gap, "upper_hex"))
    XCTAssertEqual(lower, sentinels[index])
    XCTAssertEqual(upper, sentinels[index + 1])
    XCTAssertTrue(lower.lexicographicallyPrecedes(account))
    XCTAssertTrue(account.lexicographicallyPrecedes(upper))
    let gapSiblings = try fieldElements(gap, "siblings")
    XCTAssertEqual(gapSiblings.count, 16)
    XCTAssertTrue(gapSiblings.allSatisfy(Wire.isCanonicalFieldValue))
    XCTAssertEqual(try hexData(string(gap, "root_hex")), root)

    // Quota share {body, windows, signature}: window {kind, start_ms, end_ms, limit}; leaf
    // P(kgwqwin1, [tag kind, start, end, limit]) and node P(kgwqwnd1, [left, right]).
    let quotaFrame = try VectorFrame(objectFrame(fixture, "KagemushaWalletQuotaShareV1"))
    let quotaFields = try quotaFrame.fields(quotaFrame.root)
    XCTAssertEqual(quotaFields.count, 3)
    guard quotaFields.count == 3 else { return }
    let windows = try quotaFrame.sequence(quotaFields[1])
    XCTAssertTrue((1...64).contains(windows.count))
    guard let firstWindow = windows.first else { return }
    let window = try quotaFrame.fields(firstWindow)
    XCTAssertEqual(window.count, 4)
    guard window.count == 4 else { return }
    let kind = try quotaFrame.variant(window[0])
    XCTAssertEqual(kind.fields.count, 0)
    let expectedWindow =
      [fieldInteger(le32(kind.tag))]
      + window[1...].map { fieldInteger([UInt8](quotaFrame.data($0))) }
    let quota = try object(poseidon, "quota_windows")
    let window0 = try object(quota, "window_0")
    XCTAssertEqual(try string(window0, "domain"), "kgwqwin1")
    XCTAssertEqual(try fieldElements(window0, "items"), expectedWindow)
    let quotaNode = try object(quota, "node_0_1")
    XCTAssertEqual(try string(quotaNode, "domain"), "kgwqwnd1")
    let quotaNodeItems = try fieldElements(quotaNode, "items")
    XCTAssertEqual(quotaNodeItems.count, 2)
    XCTAssertEqual(quotaNodeItems.first, try hexData(string(window0, "digest_hex")))
    let emptyWindow = try hexData(string(quota, "empty_window_hex"))
    XCTAssertTrue(Wire.isCanonicalFieldValue(emptyWindow))
    XCTAssertNotEqual(emptyWindow, try hexData(string(window0, "digest_hex")))
    let windowsRoot = try hexData(string(quota, "windows_root_hex"))
    XCTAssertTrue(Wire.isCanonicalFieldValue(windowsRoot))
    let shareBody = [UInt8](try digestBody(digests, "quota-share-body"))
    XCTAssertEqual(shareBody.count, 190)
    guard shareBody.count == 190 else { return }
    XCTAssertEqual(Data(shareBody[122..<154]), windowsRoot)
    XCTAssertEqual(readLE32(shareBody, at: 154), UInt32(windows.count))
  }

  func testVerifyingKeyAllowlistSelectsExactProofLengths() throws {
    let fixture = try loadFixture()
    let digests = try digestVectors(fixture)
    let vector = try object(object(fixture, "poseidon"), "verifying_key_set")
    let transcript = try hexData(string(vector, "transcript_hex"))
    let digest = try hexData(string(vector, "digest_hex"))
    // The allowlist digest is the SHA role `verifying-key-set` over its transcript (owner
    // answer Q11); the manifest's verifying_key_set_digest names it.
    XCTAssertEqual(transcript, try digestBody(digests, "verifying-key-set"))
    XCTAssertEqual(digest, try digestValue(digests, "verifying-key-set"))
    XCTAssertEqual(Wire.digest(role: .verifyingKeySet, body: transcript), digest)

    let allowlist = try parseAllowlist(transcript)
    XCTAssertEqual(allowlist.version, 1)
    XCTAssertTrue((8...Wire.verifyingKeyEntriesMaximum).contains(allowlist.steps.count))
    // Strictly ascending by (tag, mask); every operation once with mask 0; only Send repeats,
    // once per supported mask of defined control bits; nonzero keys; lengths within a frame.
    let selectors = allowlist.steps.map { UInt64($0.kind) << 32 | UInt64($0.mask) }
    XCTAssertEqual(selectors, selectors.sorted())
    XCTAssertEqual(Set(selectors).count, selectors.count)
    for kind in UInt8(1)...8 {
      XCTAssertTrue(allowlist.steps.contains { $0.kind == kind && $0.mask == 0 }, "kind \(kind)")
    }
    for step in allowlist.steps {
      XCTAssertTrue((1...8).contains(step.kind))
      XCTAssertEqual(step.mask & ~UInt32(0b111), 0)
      if step.mask != 0 {
        XCTAssertEqual(step.kind, 3)
      }
      XCTAssertNotEqual(step.key, Data(count: 32))
      XCTAssertTrue((1...Wire.messageMaximumBytes).contains(Int(step.proofBytes)))
    }
    XCTAssertNotEqual(allowlist.lineageKey, Data(count: 32))
    XCTAssertGreaterThanOrEqual(allowlist.lineageProofBytes, 1)
    let largestSend = allowlist.steps.filter { $0.kind == 3 }.map(\.proofBytes).max() ?? 0
    XCTAssertLessThanOrEqual(
      Int(allowlist.lineageProofBytes) + Int(largestSend), Wire.paymentProofBudgetBytes)

    // The standalone frame {version, steps, lineage_verifying_key_digest, lineage_proof_bytes}
    // carries exactly this transcript.
    let frame = try VectorFrame(objectFrame(fixture, "KagemushaWalletVerifyingKeyAllowlistV1"))
    XCTAssertEqual(try allowlistTranscript(frame), transcript)

    // Selection: σ_send by Send and Ω(pred).enabled_controls, Ω by the transport length, and
    // σ_recv by Receive; each vector proof has exactly the listed length.
    let paymentFrame = try VectorFrame(envelopeFrame(fixture, "Payment"))
    let send = try paymentFrame.fields(paymentFrame.envelopeMessage().fields[4])
    let slot = try paymentFrame.variant(send[2])
    let omega = try paymentFrame.fields(XCTUnwrap(slot.fields.first))
    let mask = readLE32(
      [UInt8](paymentFrame.data(try paymentFrame.field(omega[0], 9))), at: 0)
    let sendEntry = try XCTUnwrap(allowlist.steps.first { $0.kind == 3 && $0.mask == mask })
    XCTAssertEqual(
      Int(sendEntry.proofBytes),
      try paymentFrame.byteVector(paymentFrame.field(send[3], 0)).count)
    XCTAssertEqual(
      Int(allowlist.lineageProofBytes), try paymentFrame.byteVector(omega[1]).count)
    let receiveFrame = try VectorFrame(envelopeFrame(fixture, "Credited::Receive"))
    let evidence = try receiveFrame.variant(receiveFrame.envelopeMessage().fields[2])
    let receivePackage = try receiveFrame.fields(XCTUnwrap(evidence.fields.first))
    let receiveEntry = try XCTUnwrap(allowlist.steps.first { $0.kind == 4 && $0.mask == 0 })
    XCTAssertEqual(
      Int(receiveEntry.proofBytes),
      try receiveFrame.byteVector(receiveFrame.field(receivePackage[3], 0)).count)
  }

  // MARK: Text

  func testTextCodecIsStrict() throws {
    XCTAssertEqual(Wire.encodeText(Data()), "kgm1:")
    XCTAssertEqual(Wire.encodeText(Data([0xfb, 0xff])), "kgm1:-_8")
    XCTAssertEqual(try Wire.decodeText("kgm1:-_8"), Data([0xfb, 0xff]))
    XCTAssertEqual(try Wire.decodeText("kgm1:AA"), Data([0]))
    XCTAssertEqual(try Wire.decodeText("kgm1:AAA"), Data([0, 0]))
    XCTAssertEqual(try Wire.decodeText("kgm1:AAAA"), Data([0, 0, 0]))
    // An empty frame encodes to the bare prefix, which decoding rejects (`text.body`) like Rust.
    for length in 1..<70 {
      let frame = Data((0..<length).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ 11) })
      XCTAssertEqual(try Wire.decodeText(Wire.encodeText(frame)), frame)
      XCTAssertEqual(
        String(Wire.encodeText(frame).dropFirst(5)),
        frame.base64EncodedString()
          .replacingOccurrences(of: "+", with: "-")
          .replacingOccurrences(of: "/", with: "_")
          .replacingOccurrences(of: "=", with: ""))
    }

    let rejected: [(String, KagemushaWalletWireErrorV1)] = [
      ("", .invalidField("text.prefix")),
      ("kgm1", .invalidField("text.prefix")),
      ("KGM1:AAAA", .invalidField("text.prefix")),
      (" kgm1:AAAA", .invalidField("text.prefix")),
      ("kgm2:AAAA", .invalidField("text.prefix")),
      ("kgm1:", .invalidField("text.body")),
      ("kgm1:AA==", .invalidField("text.alphabet")),
      ("kgm1:AAA=", .invalidField("text.alphabet")),
      ("kgm1:AA+A", .invalidField("text.alphabet")),
      ("kgm1:AA/A", .invalidField("text.alphabet")),
      ("kgm1:AA A", .invalidField("text.alphabet")),
      ("kgm1:AAAA\n", .invalidField("text.alphabet")),
      ("kgm1:AA\u{00e9}", .invalidField("text.alphabet")),
      ("kgm1:A", .invalidField("text.length")),
      ("kgm1:AAAAA", .invalidField("text.length")),
      ("kgm1:AB", .invalidField("text.base64url")),
      ("kgm1:AAB", .invalidField("text.base64url")),
      ("kgm1:AAAAAB", .invalidField("text.base64url")),
    ]
    for (text, error) in rejected {
      assertWireError(try Wire.decodeText(text), error)
    }

    // A real vector text with one character outside the alphabet.
    let vector = try XCTUnwrap(objects(loadFixture(), "envelopes").first)
    var characters = Array(try string(vector, "text"))
    characters[characters.count / 2] = "+"
    assertWireError(try Wire.decodeText(String(characters)), .invalidField("text.alphabet"))
  }

  func testTextBoundIsCheckedBeforeAnyOtherRule() throws {
    let maximum = "kgm1:" + String(repeating: "A", count: Wire.messageTextMaximumBytes - 5)
    XCTAssertEqual(maximum.utf8.count, 13_339)
    XCTAssertEqual(try Wire.decodeText(maximum), Data(repeating: 0, count: 10_000))
    assertWireError(
      try Wire.decodeText(maximum + "A"),
      .encodedSizeExceeded(actual: 13_340, maximum: 13_339))
    assertWireError(
      try Wire.decodeText("XXXX:" + String(repeating: "=", count: 13_335)),
      .encodedSizeExceeded(actual: 13_340, maximum: 13_339))
    let scheme = [UInt8](repeating: 0x11, count: 32)
    let overCap = try sizedEnvelope(kind: .payment, scheme: scheme, frameBytes: 10_001)
    assertWireError(
      try Wire.decodeEnvelopeText(Wire.encodeText(overCap), expectedSchemeID: Data(scheme)),
      .encodedSizeExceeded(actual: 13_340, maximum: 13_339))
    let overSession = try sizedEnvelope(kind: .offer, scheme: scheme, frameBytes: 2_049)
    let overSessionText = Wire.encodeText(overSession)
    XCTAssertEqual(overSessionText.utf8.count, 2_737)
    assertWireError(
      try Wire.decodeEnvelopeText(overSessionText, expectedSchemeID: Data(scheme)),
      .encodedSizeExceeded(actual: 2_049, maximum: 2_048))
  }
}

// MARK: - Synthetic envelopes

/// Structurally valid envelope frame with the field paths the validator reads; its contents are
/// not a valid typed message.
private struct SyntheticEnvelope {
  var kind: KagemushaWalletMessageKindV1
  var scheme: [UInt8]
  var fillerBytes = 0
  var envelopeVersion: UInt16 = 1
  var messageVersion: UInt16 = 1
  var tag: UInt32?
  var trailingEnvelopeField = false
  var typeName = KagemushaWalletWireV1.envelopeFrameName
  var flags = NoritoHeader.compactLen
  var payloadAlignment = KagemushaWalletWireV1.envelopePayloadAlignment

  func payload() -> [UInt8] {
    let version = compactField(le16(messageVersion))
    let leaf =
      version + compactField(scheme)
      + compactField([UInt8](repeating: 0xa5, count: fillerBytes))
    let variant: [UInt8]
    switch kind {
    case .offer, .request:
      variant = compactField(compactField(leaf))
    case .payment, .lineage:
      variant = compactField(version + compactField(compactField(leaf)))
    case .credited, .sessionControl, .policyData:
      variant = compactField(leaf)
    }
    var payload =
      compactField(le16(envelopeVersion)) + compactField(le32(tag ?? kind.rawValue) + variant)
    if trailingEnvelopeField {
      payload += compactField([0])
    }
    return payload
  }

  func frame() throws -> Data {
    noritoEncode(
      typeName: typeName, payload: Data(payload()), flags: flags,
      payloadAlignment: payloadAlignment)
  }
}

private enum SyntheticFailure: Error {
  case unreachableSize(Int)
}

private func sized(_ template: SyntheticEnvelope, frameBytes: Int) throws -> Data {
  var envelope = template
  envelope.fillerBytes = 0
  for _ in 0..<16 {
    let frame = try envelope.frame()
    if frame.count == frameBytes { return frame }
    envelope.fillerBytes += frameBytes - frame.count
    guard envelope.fillerBytes >= 0 else { break }
  }
  throw SyntheticFailure.unreachableSize(frameBytes)
}

private func sizedEnvelope(
  kind: KagemushaWalletMessageKindV1,
  scheme: [UInt8],
  frameBytes: Int
) throws -> Data {
  try sized(SyntheticEnvelope(kind: kind, scheme: scheme), frameBytes: frameBytes)
}

/// `[compact length][content]` with a canonical unsigned LEB128 length.
private func compactField(_ content: [UInt8]) -> [UInt8] {
  var length = UInt64(content.count)
  var prefix: [UInt8] = []
  repeat {
    var byte = UInt8(length & 0x7f)
    length >>= 7
    if length != 0 { byte |= 0x80 }
    prefix.append(byte)
  } while length != 0
  return prefix + content
}

private func le16(_ value: UInt16) -> [UInt8] {
  withUnsafeBytes(of: value.littleEndian, Array.init)
}

private func le32(_ value: UInt32) -> [UInt8] {
  withUnsafeBytes(of: value.littleEndian, Array.init)
}

// MARK: - Vector layouts

/// Every `[compact length][content]` field of the struct encoded in exactly `range`, or `nil`
/// when a length is truncated or overruns the range.
private func compactFields(_ bytes: [UInt8], _ range: Range<Int>) -> [Range<Int>]? {
  var fields: [Range<Int>] = []
  var offset = range.lowerBound
  while offset < range.upperBound {
    var length = 0
    var shift = 0
    while true {
      guard offset < range.upperBound, shift < 63 else { return nil }
      let byte = bytes[offset]
      offset += 1
      length |= Int(byte & 0x7f) << shift
      shift += 7
      if byte & 0x80 == 0 { break }
    }
    guard length <= range.upperBound - offset else { return nil }
    fields.append(offset..<(offset + length))
    offset += length
  }
  return fields
}

/// The message struct of one envelope vector, with the payload its field ranges index.
private struct VectorMessage {
  let payload: [UInt8]
  /// Range of the message struct: the envelope variant's single field.
  let message: Range<Int>
  /// Field ranges of the message struct.
  let fields: [Range<Int>]

  func bytes(_ range: Range<Int>) -> Data { Data(payload[range]) }

  /// Little-endian `u32` enum tag at the start of `range`, or `nil` when it is shorter.
  func tag(_ range: Range<Int>) -> UInt32? {
    guard range.count >= 4 else { return nil }
    return (0..<4).reduce(UInt32(0)) {
      $0 | UInt32(payload[range.lowerBound + $1]) << (8 * UInt32($1))
    }
  }
}

private func vectorMessage(_ vector: [String: Any]) throws -> VectorMessage {
  let frame = try hexData(string(vector, "canonical_hex"))
  guard let decoded = noritoDecodeFrame(frame) else {
    throw WalletFixtureFailure.malformed("envelope frame")
  }
  let payload = [UInt8](decoded.payload)
  guard
    let envelope = compactFields(payload, 0..<payload.count), envelope.count == 2,
    envelope[1].count >= 4,
    let variant = compactFields(payload, (envelope[1].lowerBound + 4)..<envelope[1].upperBound),
    variant.count == 1,
    let fields = compactFields(payload, variant[0])
  else {
    throw WalletFixtureFailure.malformed("envelope fields")
  }
  return VectorMessage(payload: payload, message: variant[0], fields: fields)
}

/// Payload of one canonical vector frame with field navigation (wire record §2 layout).
private struct VectorFrame {
  /// Schema hash of the frame header.
  let schema: [UInt8]
  /// Frame payload that every range indexes.
  let payload: [UInt8]

  init(_ frame: Data) throws {
    guard let decoded = noritoDecodeFrame(frame) else {
      throw WalletFixtureFailure.malformed("vector frame")
    }
    schema = decoded.header.schema
    payload = [UInt8](decoded.payload)
  }

  /// Range of the payload's top-level record.
  var root: Range<Int> { 0..<payload.count }

  func data(_ range: Range<Int>) -> Data { Data(payload[range]) }

  /// Field ranges of the record encoded in exactly `range`.
  func fields(_ range: Range<Int>) throws -> [Range<Int>] {
    guard let fields = compactFields(payload, range) else {
      throw WalletFixtureFailure.malformed("record fields")
    }
    return fields
  }

  /// Field `path[0]` of the record at `range`, then field `path[1]` of that field, and so on.
  func field(_ range: Range<Int>, _ path: Int...) throws -> Range<Int> {
    var current = range
    for index in path {
      let record = try self.fields(current)
      guard index < record.count else { throw WalletFixtureFailure.malformed("field index") }
      current = record[index]
    }
    return current
  }

  /// The enum at `range`: its LE32 tag and the field ranges of its variant.
  func variant(_ range: Range<Int>) throws -> (tag: UInt32, fields: [Range<Int>]) {
    guard range.count >= 4 else { throw WalletFixtureFailure.malformed("enum tag") }
    let tag = readLE32(payload, at: range.lowerBound)
    let variantFields = try fields((range.lowerBound + 4)..<range.upperBound)
    return (tag, variantFields)
  }

  /// The `Vec<u8>` at `range`: an LE64 count, then exactly that many bytes.
  func byteVector(_ range: Range<Int>) throws -> Data {
    guard range.count >= 8, readLE64(payload, at: range.lowerBound) == UInt64(range.count - 8)
    else {
      throw WalletFixtureFailure.malformed("byte vector")
    }
    return Data(payload[(range.lowerBound + 8)..<range.upperBound])
  }

  /// The element ranges of the sequence at `range`: an LE64 count, then that many
  /// `[len][element]`.
  func sequence(_ range: Range<Int>) throws -> [Range<Int>] {
    guard range.count >= 8 else { throw WalletFixtureFailure.malformed("sequence") }
    let elements = try fields((range.lowerBound + 8)..<range.upperBound)
    guard UInt64(elements.count) == readLE64(payload, at: range.lowerBound) else {
      throw WalletFixtureFailure.malformed("sequence count")
    }
    return elements
  }

  /// Message tag and record fields of an envelope frame `{version, message}`.
  func envelopeMessage() throws -> (tag: UInt32, fields: [Range<Int>]) {
    let envelope = try fields(root)
    guard envelope.count == 2 else { throw WalletFixtureFailure.malformed("envelope") }
    let message = try variant(envelope[1])
    guard message.fields.count == 1 else { throw WalletFixtureFailure.malformed("message") }
    let messageFields = try fields(message.fields[0])
    return (message.tag, messageFields)
  }
}

/// The 320-byte Ω public transcript of its 13-field public frame (wire record §3.2): fixed-width
/// fields as carried, the head commitment `{value}` unwrapped and the lifecycle as its one-byte
/// tag.
private func lineagePublicTranscript(_ frame: VectorFrame, _ record: Range<Int>) throws -> Data {
  let fields = try frame.fields(record)
  guard fields.count == 13 else { throw WalletFixtureFailure.malformed("lineage public fields") }
  var transcript = Data()
  for (index, field) in fields.enumerated() {
    switch index {
    case 3:
      let head = try frame.fields(field)
      guard head.count == 1 else { throw WalletFixtureFailure.malformed("lineage head") }
      transcript.append(frame.data(head[0]))
    case 7:
      let lifecycle = try frame.variant(field)
      guard lifecycle.fields.isEmpty, lifecycle.tag <= 0xff else {
        throw WalletFixtureFailure.malformed("lineage lifecycle")
      }
      transcript.append(UInt8(lifecycle.tag))
    default:
      transcript.append(frame.data(field))
    }
  }
  guard transcript.count == 320 else { throw WalletFixtureFailure.malformed("lineage public") }
  return transcript
}

// MARK: - σ-field elements

/// One integer element: the little-endian integer bytes zero-filled to 32.
private func fieldInteger(_ littleEndian: [UInt8]) -> Data {
  Data(littleEndian + [UInt8](repeating: 0, count: 32 - littleEndian.count))
}

/// The two elements of a 32-byte digest or identifier: its 128-bit limbs, low half first.
private func fieldDigestLimbs(_ digest: Data) -> [Data] {
  let bytes = [UInt8](digest)
  return [fieldInteger(Array(bytes.prefix(16))), fieldInteger(Array(bytes.dropFirst(16)))]
}

private func fieldElements(_ value: [String: Any], _ key: String) throws -> [Data] {
  guard let items = value[key] as? [String] else { throw WalletFixtureFailure.malformed(key) }
  return try items.map(hexData)
}

/// One slot of a fixed-width transcript under the element rule (wire record §3.2).
private enum TranscriptSlotV1 {
  /// A little-endian integer, tag or mask of this many bytes: one element.
  case integer(Int)
  /// A 32-byte SHA-256 digest or identifier: two `u128` limbs, low half first.
  case digest
  /// A 32-byte Poseidon σ-field value (`credit_id`, a commitment or root): one element.
  case field

  var width: Int {
    switch self {
    case .integer(let width): return width
    case .digest, .field: return 32
    }
  }

  var elementCount: Int {
    switch self {
    case .digest: return 2
    case .integer, .field: return 1
    }
  }
}

/// σ-field elements of a transcript that is exactly `layout`, slot by slot.
private func transcriptFieldElements(
  _ transcript: [UInt8],
  _ layout: [TranscriptSlotV1]
) throws -> [Data] {
  var offset = 0
  var items: [Data] = []
  for slot in layout {
    guard offset + slot.width <= transcript.count else {
      throw WalletFixtureFailure.malformed("transcript length")
    }
    let bytes = Array(transcript[offset..<(offset + slot.width)])
    offset += slot.width
    switch slot {
    case .integer: items.append(fieldInteger(bytes))
    case .digest: items += fieldDigestLimbs(Data(bytes))
    case .field: items.append(Data(bytes))
    }
  }
  guard offset == transcript.count else { throw WalletFixtureFailure.malformed("transcript fill") }
  return items
}

/// Effect fields by operation tag (wire record §3.2): `credit_id` is one σ-field value, every
/// other 32-byte field a digest.
private let statementEffectLayouts: [UInt8: [TranscriptSlotV1]] = [
  1: [.digest, .digest],
  2: [.digest, .integer(16), .integer(16), .integer(16)],
  3: [
    .field, .digest, .integer(16), .integer(16), .integer(16), .digest, .integer(8),
    .integer(8),
  ],
  4: [.field, .digest, .integer(16)],
  5: [.field, .digest],
  6: [.digest, .integer(16), .integer(16), .integer(16), .digest],
  7: [.integer(1), .digest, .integer(8)],
  8: [],
]

/// The 354-byte `request-body` transcript, whose 24 elements `credit_id` hashes (owner answer Q1).
private let requestBodyLayout: [TranscriptSlotV1] = [
  .integer(2), .digest, .digest, .digest, .digest, .integer(16), .digest, .integer(16), .digest,
  .integer(16), .integer(8), .digest, .integer(8), .digest, .digest,
]

/// The 28 σ-field elements of one 440-byte `statement` transcript, in the Rust `field_items`
/// order: version; relation, scheme, asset and credential limbs; successor lifecycle, sequence
/// and `next_load`; enabled controls; lineage `burned_total`; lineage pending-outgoing root,
/// predecessor and successor as one element each; the effect tag; and the effect's elements
/// zero-filled to 10.
private func statementFieldElements(_ transcript: Data) throws -> [Data] {
  let bytes = [UInt8](transcript)
  guard bytes.count == 440 else { throw WalletFixtureFailure.malformed("statement length") }
  // Transcript order is version, scheme, relation, credential, asset; the element order puts
  // the relation first and the asset before the credential.
  let scheme = Data(bytes[2..<34])
  let relation = Data(bytes[34..<66])
  let credential = Data(bytes[66..<98])
  let asset = Data(bytes[98..<130])
  var items = [fieldInteger(Array(bytes[0..<2]))]
  for digest in [relation, scheme, asset, credential] {
    items += fieldDigestLimbs(digest)
  }
  items += try transcriptFieldElements(
    Array(bytes[130..<279]),
    [.integer(1), .integer(16), .integer(16), .integer(4), .integer(16), .field, .field, .field])
  let tag = bytes[279]
  items.append(fieldInteger([tag]))
  guard let layout = statementEffectLayouts[tag] else {
    throw WalletFixtureFailure.malformed("effect tag")
  }
  let width = layout.reduce(0) { $0 + $1.width }
  let union = Array(bytes[280..<440])
  guard union[width...].allSatisfy({ $0 == 0 }) else {
    throw WalletFixtureFailure.malformed("effect fill")
  }
  let effect = try transcriptFieldElements(Array(union[..<width]), layout)
  guard effect.count <= 10 else { throw WalletFixtureFailure.malformed("effect elements") }
  return items + effect + Array(repeating: Data(count: 32), count: 10 - effect.count)
}

/// One field of a Norito record under the element rule.
private enum FrameSlotV1 {
  /// A unit-variant enum: its LE32 tag is one element.
  case tag
  /// A fixed-width little-endian integer: one element.
  case integer
  /// A SHA-256 digest or identifier: two limbs.
  case digest
  /// A Poseidon σ-field value: one element.
  case field
}

/// The 28 fields of the state core `{lifecycle, scheme_id, …, state_nonce}` (32 elements).
private let stateCoreLayout: [FrameSlotV1] = [
  .tag, .digest, .digest, .digest, .digest,
  .integer, .integer, .integer, .integer, .integer, .integer,
  .field, .field,
  .field, .field, .field, .field, .field,
  .integer, .field,
  .integer, .field, .integer, .integer,
  .integer, .integer, .integer, .field,
]

/// The 8 fields of the state rest `{permitted_controls, …, time_anchor}` (13 elements).
private let stateRestLayout: [FrameSlotV1] = [
  .integer, .integer, .digest, .digest, .digest, .digest, .integer, .digest,
]

/// σ-field elements of the record at `record`, field by field.
private func frameFieldElements(
  _ frame: VectorFrame,
  _ record: Range<Int>,
  _ layout: [FrameSlotV1]
) throws -> [Data] {
  let fields = try frame.fields(record)
  guard fields.count == layout.count else { throw WalletFixtureFailure.malformed("record layout") }
  var items: [Data] = []
  for (field, slot) in zip(fields, layout) {
    let bytes = [UInt8](frame.data(field))
    switch slot {
    case .tag:
      let variant = try frame.variant(field)
      guard variant.fields.isEmpty else { throw WalletFixtureFailure.malformed("unit enum") }
      items.append(fieldInteger(le32(variant.tag)))
    case .integer:
      guard [1, 2, 4, 8, 16].contains(bytes.count) else {
        throw WalletFixtureFailure.malformed("integer width")
      }
      items.append(fieldInteger(bytes))
    case .digest:
      guard bytes.count == 32 else { throw WalletFixtureFailure.malformed("digest width") }
      items += fieldDigestLimbs(Data(bytes))
    case .field:
      guard bytes.count == 32 else { throw WalletFixtureFailure.malformed("field width") }
      items.append(Data(bytes))
    }
  }
  return items
}

/// The `P_bytes` element list of `bytes` (wire record §1): the byte length as one element, then
/// the 31-byte little-endian chunks, the last zero-filled. Swift mirrors the packing, never `P`.
private func packedFieldElements(_ bytes: Data) -> [Data] {
  let input = [UInt8](bytes)
  var items = [fieldInteger(withUnsafeBytes(of: UInt64(input.count).littleEndian, Array.init))]
  var offset = 0
  while offset < input.count {
    let end = min(offset + 31, input.count)
    items.append(fieldInteger(Array(input[offset..<end])))
    offset = end
  }
  return items
}

/// `LE32 len(part) ‖ part` for every part, the `proof_digest` body (wire record §3.2).
private func lengthPrefixed(_ parts: [Data]) -> Data {
  var out = Data()
  for part in parts {
    out.append(contentsOf: le32(UInt32(part.count)))
    out.append(part)
  }
  return out
}

/// Map key `high · 2^128 + low` of an integer pair whose low part is the element `low`.
private func pairKey(high: UInt8, low: Data) -> Data {
  Data([UInt8](low.prefix(16)) + [high] + [UInt8](repeating: 0, count: 15))
}

/// Height of the most significant bit in which two 32-byte little-endian keys differ.
private func highestDifferingBit(_ lhs: Data, _ rhs: Data) -> Int? {
  let left = [UInt8](lhs)
  let right = [UInt8](rhs)
  guard left.count == 32, right.count == 32 else { return nil }
  for height in stride(from: 255, through: 0, by: -1)
  where (left[height / 8] ^ right[height / 8]) >> UInt8(height % 8) & 1 == 1 {
    return height
  }
  return nil
}

/// Checks one `P_bytes` vector row (domain, element count and encoding) and returns its value.
private func packedDigest(
  _ row: [String: Any],
  domain: String,
  file: StaticString = #filePath,
  line: UInt = #line
) throws -> Data {
  let label = try string(row, "object")
  XCTAssertEqual(try string(row, "domain"), domain, label, file: file, line: line)
  let body = try hexData(string(row, "body_hex"))
  XCTAssertEqual(
    try int(row, "elements"), packedFieldElements(body).count, label, file: file, line: line)
  let value = try hexData(string(row, "digest_hex"))
  XCTAssertTrue(
    KagemushaWalletWireV1.isCanonicalFieldValue(value), label, file: file, line: line)
  XCTAssertNotEqual(value, Data(count: 32), label, file: file, line: line)
  return value
}

/// Checks one compressed sparse-tree opening vector and returns its bitmap and siblings: the
/// bitmap's population count is the sibling count, every value is canonical, and a present
/// sibling is never the default subtree of its height (for the `defaults` known by height).
private func checkedOpening(
  _ opening: [String: Any],
  defaults: [Data],
  label: String,
  file: StaticString = #filePath,
  line: UInt = #line
) throws -> (bitmap: Data, siblings: [Data]) {
  let bitmap = try hexData(string(opening, "path_bitmap_hex"))
  let siblings = try fieldElements(opening, "siblings")
  let bits = [UInt8](bitmap)
  XCTAssertEqual(bits.count, 32, label, file: file, line: line)
  XCTAssertEqual(
    bits.reduce(0) { $0 + $1.nonzeroBitCount }, siblings.count, label, file: file, line: line)
  XCTAssertLessThanOrEqual(
    siblings.count, KagemushaWalletWireV1.creditOpeningSiblingsMaximum, label, file: file,
    line: line)
  for key in ["key_hex", "leaf_hex", "root_hex"] {
    XCTAssertTrue(
      KagemushaWalletWireV1.isCanonicalFieldValue(try hexData(string(opening, key))), label,
      file: file, line: line)
  }
  guard bits.count == 32 else { return (bitmap, siblings) }
  var next = siblings.makeIterator()
  for height in 0..<256 where bits[height / 8] >> UInt8(height % 8) & 1 == 1 {
    guard let sibling = next.next() else { break }
    XCTAssertTrue(
      KagemushaWalletWireV1.isCanonicalFieldValue(sibling), label, file: file, line: line)
    if height < defaults.count {
      XCTAssertNotEqual(sibling, defaults[height], label, file: file, line: line)
    }
  }
  return (bitmap, siblings)
}

/// One σ entry of the verifying-key allowlist.
private struct AllowlistStepV1 {
  let kind: UInt8
  let mask: UInt32
  let key: Data
  let proofBytes: UInt32
}

/// The parsed `verifying-key-set` transcript `LE16 version ‖ LE32 n ‖ n × (tag kind ‖ LE32 mask
/// ‖ key ‖ LE32 proof_bytes) ‖ lineage key ‖ LE32 lineage_proof_bytes` (wire record §3.1).
private func parseAllowlist(
  _ transcript: Data
) throws -> (version: UInt16, steps: [AllowlistStepV1], lineageKey: Data, lineageProofBytes: UInt32)
{
  let bytes = [UInt8](transcript)
  guard bytes.count >= 42 else { throw WalletFixtureFailure.malformed("allowlist length") }
  let count = Int(readLE32(bytes, at: 2))
  guard bytes.count == 42 + 41 * count else { throw WalletFixtureFailure.malformed("allowlist") }
  var steps: [AllowlistStepV1] = []
  var offset = 6
  for _ in 0..<count {
    steps.append(
      AllowlistStepV1(
        kind: bytes[offset], mask: readLE32(bytes, at: offset + 1),
        key: Data(bytes[(offset + 5)..<(offset + 37)]),
        proofBytes: readLE32(bytes, at: offset + 37)))
    offset += 41
  }
  let version = UInt16(bytes[0]) | UInt16(bytes[1]) << 8
  return (
    version, steps, Data(bytes[offset..<(offset + 32)]), readLE32(bytes, at: offset + 32)
  )
}

/// The `verifying-key-set` transcript rebuilt from the allowlist frame
/// `{version, steps: [{kind, enabled_controls, verifying_key_digest, proof_bytes}],
/// lineage_verifying_key_digest, lineage_proof_bytes}`.
private func allowlistTranscript(_ frame: VectorFrame) throws -> Data {
  let fields = try frame.fields(frame.root)
  guard fields.count == 4 else { throw WalletFixtureFailure.malformed("allowlist fields") }
  let steps = try frame.sequence(fields[1])
  var transcript = frame.data(fields[0])
  transcript.append(contentsOf: le32(UInt32(steps.count)))
  for step in steps {
    let stepFields = try frame.fields(step)
    guard stepFields.count == 4 else { throw WalletFixtureFailure.malformed("allowlist step") }
    let kind = try frame.variant(stepFields[0])
    guard kind.fields.isEmpty, kind.tag <= 0xff else {
      throw WalletFixtureFailure.malformed("allowlist kind")
    }
    transcript.append(UInt8(kind.tag))
    for field in stepFields.dropFirst() {
      transcript.append(frame.data(field))
    }
  }
  transcript.append(frame.data(fields[2]))
  transcript.append(frame.data(fields[3]))
  return transcript
}

private func readLE32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
  (0..<4).reduce(UInt32(0)) { $0 | UInt32(bytes[offset + $1]) << UInt32(8 * $1) }
}

private func readLE64(_ bytes: [UInt8], at offset: Int) -> UInt64 {
  (0..<8).reduce(UInt64(0)) { $0 | UInt64(bytes[offset + $1]) << UInt64(8 * $1) }
}

// MARK: - Fixture and assertion helpers

private enum WalletFixtureFailure: Error {
  case missingFixture
  case malformed(String)
}

private func kindName(_ kind: KagemushaWalletMessageKindV1) -> String {
  switch kind {
  case .offer: "Offer"
  case .request: "Request"
  case .payment: "Payment"
  case .credited: "Credited"
  case .sessionControl: "SessionControl"
  case .policyData: "PolicyData"
  case .lineage: "Lineage"
  }
}

/// Locates `fixtures/kagemusha/wallet_v1_vectors.json` by walking up from this source file.
private func walletFixtureURL() throws -> URL {
  var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
  for _ in 0..<8 {
    let candidate = directory.appendingPathComponent("fixtures/kagemusha/wallet_v1_vectors.json")
    if FileManager.default.fileExists(atPath: candidate.path) { return candidate }
    directory.deleteLastPathComponent()
  }
  throw WalletFixtureFailure.missingFixture
}

private func loadFixture() throws -> [String: Any] {
  let data = try Data(contentsOf: walletFixtureURL())
  guard let fixture = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
    throw WalletFixtureFailure.malformed("root")
  }
  return fixture
}

private func object(_ value: [String: Any], _ key: String) throws -> [String: Any] {
  guard let object = value[key] as? [String: Any] else {
    throw WalletFixtureFailure.malformed(key)
  }
  return object
}

private func objects(_ value: [String: Any], _ key: String) throws -> [[String: Any]] {
  guard let array = value[key] as? [[String: Any]] else {
    throw WalletFixtureFailure.malformed(key)
  }
  return array
}

private func string(_ value: [String: Any], _ key: String) throws -> String {
  guard let text = value[key] as? String else { throw WalletFixtureFailure.malformed(key) }
  return text
}

private func int(_ value: [String: Any], _ key: String) throws -> Int {
  guard let number = value[key] as? NSNumber else { throw WalletFixtureFailure.malformed(key) }
  return number.intValue
}

private func bool(_ value: [String: Any], _ key: String) throws -> Bool {
  guard let flag = value[key] as? Bool else { throw WalletFixtureFailure.malformed(key) }
  return flag
}

private func bytes(_ value: [String: Any], _ key: String) throws -> [UInt8] {
  [UInt8](try hexData(string(value, key)))
}

private func hexData(_ text: String) throws -> Data {
  let digits = Array(text.utf8)
  guard digits.count % 2 == 0 else { throw WalletFixtureFailure.malformed("odd hex") }
  func nibble(_ digit: UInt8) throws -> UInt8 {
    switch digit {
    case 0x30...0x39: return digit - 0x30
    case 0x61...0x66: return digit - 0x61 + 10
    default: throw WalletFixtureFailure.malformed("hex digit")
    }
  }
  var out = Data(capacity: digits.count / 2)
  var index = 0
  while index < digits.count {
    out.append(try nibble(digits[index]) << 4 | nibble(digits[index + 1]))
    index += 2
  }
  return out
}

private func hex(_ data: Data) -> String {
  data.map { String(format: "%02x", $0) }.joined()
}

/// Body of a wallet preimage `prefix || role || 0x00 || LE64(len) || body`, checking the frame.
private func bodyOfPreimage(_ preimage: Data, role: KagemushaWalletDigestRoleV1) throws -> Data {
  let bytes = [UInt8](preimage)
  let head = [UInt8](KagemushaWalletWireV1.digestPrefix) + Array(role.rawValue.utf8) + [0]
  guard bytes.count >= head.count + 8, Array(bytes[0..<head.count]) == head else {
    throw WalletFixtureFailure.malformed("preimage head")
  }
  var length: UInt64 = 0
  for (shift, byte) in bytes[head.count..<(head.count + 8)].enumerated() {
    length |= UInt64(byte) << UInt64(8 * shift)
  }
  let body = Array(bytes[(head.count + 8)...])
  guard length == UInt64(body.count) else { throw WalletFixtureFailure.malformed("preimage len") }
  return Data(body)
}

/// The ECDSA equation as CryptoKit checks it, scalars taken as they are (high S accepted).
private func cryptoKitEquation(_ publicKey: Data, _ preimage: Data, _ signature: Data) -> Bool {
  guard
    let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
    let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
  else {
    return false
  }
  return key.isValidSignature(parsed, for: preimage)
}

/// Big-endian sum of two equal-width integers, or `nil` on a carry out.
private func addBigEndian(_ lhs: [UInt8], _ rhs: [UInt8]) -> [UInt8]? {
  guard lhs.count == rhs.count else { return nil }
  var out = [UInt8](repeating: 0, count: lhs.count)
  var carry = 0
  for index in stride(from: lhs.count - 1, through: 0, by: -1) {
    let sum = Int(lhs[index]) + Int(rhs[index]) + carry
    out[index] = UInt8(sum & 0xff)
    carry = sum >> 8
  }
  return carry == 0 ? out : nil
}

private func assertWireError<T>(
  _ expression: @autoclosure () throws -> T,
  _ expected: KagemushaWalletWireErrorV1,
  file: StaticString = #filePath,
  line: UInt = #line
) {
  XCTAssertThrowsError(try expression(), file: file, line: line) { error in
    XCTAssertEqual(error as? KagemushaWalletWireErrorV1, expected, file: file, line: line)
  }
}

/// Digest vectors by role.
private func digestVectors(_ fixture: [String: Any]) throws -> [String: [String: Any]] {
  try Dictionary(
    uniqueKeysWithValues: objects(fixture, "digests").map { (try string($0, "role"), $0) })
}

/// Digest of the vector of `role`.
private func digestValue(_ digests: [String: [String: Any]], _ role: String) throws -> Data {
  guard let vector = digests[role] else { throw WalletFixtureFailure.malformed(role) }
  return try hexData(string(vector, "digest_hex"))
}

/// Body (transcript) of the vector of `role`.
private func digestBody(_ digests: [String: [String: Any]], _ role: String) throws -> Data {
  guard let vector = digests[role] else { throw WalletFixtureFailure.malformed(role) }
  return try hexData(string(vector, "body_hex"))
}

/// Canonical frame of the envelope vector `variant`.
private func envelopeFrame(_ fixture: [String: Any], _ variant: String) throws -> Data {
  guard
    let vector = try objects(fixture, "envelopes").first(where: {
      $0["variant"] as? String == variant
    })
  else {
    throw WalletFixtureFailure.malformed(variant)
  }
  return try hexData(string(vector, "canonical_hex"))
}

/// Canonical frame of the first object vector of `type`.
private func objectFrame(_ fixture: [String: Any], _ type: String) throws -> Data {
  guard let vector = try objects(fixture, "objects").first(where: { $0["type"] as? String == type })
  else {
    throw WalletFixtureFailure.malformed(type)
  }
  return try hexData(string(vector, "canonical_hex"))
}

/// Signed transcript of the signature vector of `label`, taken from its preimage.
private func signedBody(_ fixture: [String: Any], object label: String) throws -> Data {
  guard
    let vector = try objects(fixture, "signatures").first(where: {
      $0["object"] as? String == label
    })
  else {
    throw WalletFixtureFailure.malformed(label)
  }
  let roleName = try string(vector, "role")
  guard let role = KagemushaWalletDigestRoleV1(rawValue: roleName) else {
    throw WalletFixtureFailure.malformed(roleName)
  }
  return try bodyOfPreimage(hexData(string(vector, "preimage_hex")), role: role)
}
