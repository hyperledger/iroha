import CryptoKit
import Foundation
import XCTest
@testable import IrohaSwift

/// Consumes `fixtures/kagemusha/wallet_v1_vectors.json`, written by the Rust
/// `kagemusha_wallet_v1` vector test, and checks the Swift wallet wire helpers against it.
///
/// Poseidon values are computed only by the native Rust core; these tests never recompute one.
/// They check every SHA-256 role (the 20 roles, including NEW unsigned E1 policies, with every retired role rejected), frame,
/// envelope and signature vector (each over its 32-byte Poseidon signing message), the σ-field
/// element lists, the `P_bytes` packing of every large-input digest and signing message, the
/// depth-32 indexed-tree openings, the limb-ordered blacklist and the verifying-key allowlist,
/// and that each Poseidon value is a canonical σ-field encoding placed consistently in the frames
/// and transcripts that carry it.
final class KagemushaWalletVectorsV1Tests: XCTestCase {
  private typealias Wire = KagemushaWalletWireV1

  /// The 59 domains: 33 protocol hashes, 16 signing messages, 10 signed objects.
  private static let poseidonDomains = [
    "kgwcore1",
    "kgwrest1",
    "kgwstmt1",
    "kgwcrdt1",
    "kgwschn1",
    "kgwrchn1",
    "kgwccrd1",
    "kgwpout1",
    "kgwload1",
    "kgwolod1",
    "kgwrdm_1",
    "kgwfee_1",
    "kgwbhst1",
    "kgwcset1",
    "kgwpkg_1",
    "kgwnull1",
    "kgwcdig1",
    "kgwimlf1",
    "kgwimnd1",
    "kgwblkl1",
    "kgwblkn1",
    "kgwqwin1",
    "kgwqwnd1",
    "kgwquse1",
    "kgwqusn1",
    "kgwprf_1",
    "kgwstep1",
    "kgwpay_1",
    "kgwlin_1",
    "kgwcopn1",
    "kgwcsts1",
    "kgwcrdd1",
    "kgwopid1",
    "kgwcert1",
    "kgwcred1",
    "kgwrnch1",
    "kgwrnkb1",
    "kgwartf1",
    "kgwrcpt1",
    "kgwspol1",
    "kgwfsch1",
    "kgwblst1",
    "kgwqshr1",
    "kgwtanc1",
    "kgwchgq1",
    "kgwoffr1",
    "kgwsctl1",
    "kgwrqst1",
    "kgwlctl1",
    "kgwocrt1",
    "kgwocrd1",
    "kgworcp1",
    "kgwopol1",
    "kgwofee1",
    "kgwoblk1",
    "kgwoqsh1",
    "kgwotim1",
    "kgwochg1",
    "kgworeq1",
  ]

  /// Operation tags of Send and Receive, and the tags whose packages carry Ω(pred).
  private static let sendTag: UInt32 = 3
  private static let receiveTag: UInt32 = 4
  private static let lineageConsumingTags: Set<UInt32> = [3, 6, 8]
  /// Bit 0 of `enabled_controls`: BLACKLIST.
  private static let blacklistControl: UInt32 = 1
  /// Request-body field positions of the wallets and account digests (owner answer A5).
  private static let requestPayerWallet = 3
  private static let requestPayerAccount = 4
  private static let requestReceiverWallet = 5
  private static let requestReceiverAccount = 6

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
    // Exact σ and Ω lengths come from the frozen verifying-key allowlist and must fit
    // their complete carrying envelopes.
    XCTAssertNil(bounds["proof_max_bytes"])
    XCTAssertNil(bounds["credit_status_proof_max_bytes"])
    XCTAssertFalse(try string(bounds, "proof_caps").isEmpty)
    XCTAssertEqual(
      Set(bounds.keys),
      [
        "certificate_set_max", "credential_max_bytes", "credit_opening_bytes",
        "credited_receive_fixed_bytes", "credited_receive_proof_budget_bytes",
        "credited_status_fixed_bytes", "fold_record_max_bytes", "indexed_tree_depth",
        "lineage_max_bytes", "lineage_proof_cap_bytes", "message_max_bytes",
        "quota_tree_depth", "quota_usage_slots",
        "message_text_max_bytes", "payment_fixed_bytes", "payment_proof_budget_bytes",
        "proof_caps", "session_max_bytes", "session_text_max_bytes", "text_prefix",
        "verifying_key_allowlist_max_bytes", "verifying_key_entries_max", "version",
      ])
    XCTAssertEqual(try int(bounds, "payment_fixed_bytes"), Wire.paymentFixedBytes)
    XCTAssertEqual(try int(bounds, "payment_proof_budget_bytes"), Wire.paymentProofBudgetBytes)
    XCTAssertEqual(Wire.paymentFixedBytes, 1_723)
    XCTAssertEqual(Wire.paymentProofBudgetBytes, 8_277)
    XCTAssertEqual(try int(bounds, "credited_receive_fixed_bytes"), Wire.creditedReceiveFixedBytes)
    XCTAssertEqual(
      try int(bounds, "credited_receive_proof_budget_bytes"), Wire.creditedReceiveProofBudgetBytes)
    XCTAssertEqual(Wire.creditedReceiveFixedBytes, 679)
    XCTAssertEqual(Wire.creditedReceiveProofBudgetBytes, 9_321)
    XCTAssertEqual(
      Wire.creditedReceiveFixedBytes + Wire.creditedReceiveProofBudgetBytes, Wire.messageMaximumBytes)
    XCTAssertTrue(try string(bounds, "proof_caps").contains("credited_receive_proof_budget_bytes"))
    // Credited::Status carries Ω(h) and the fixed 32-sibling opening: F_status + Ω cap = 10,000.
    XCTAssertEqual(try int(bounds, "credited_status_fixed_bytes"), Wire.creditedStatusFixedBytes)
    XCTAssertEqual(try int(bounds, "lineage_proof_cap_bytes"), Wire.lineageProofCapBytes)
    XCTAssertEqual(Wire.lineageProofCapBytes, 7_812)
    XCTAssertEqual(Wire.creditedStatusFixedBytes + Wire.lineageProofCapBytes, 10_000)
    XCTAssertTrue(try string(bounds, "proof_caps").contains("lineage_proof_cap_bytes"))
    XCTAssertEqual(try int(bounds, "verifying_key_entries_max"), Wire.verifyingKeyEntriesMaximum)
    XCTAssertEqual(Wire.verifyingKeyEntriesMaximum, 16)
    // Indexed maps have depth 32; quota usage follows the depth-six window array.
    XCTAssertEqual(try int(bounds, "indexed_tree_depth"), Wire.indexedTreeDepth)
    XCTAssertEqual(Wire.indexedTreeDepth, 32)
    XCTAssertEqual(try int(bounds, "quota_tree_depth"), Wire.quotaTreeDepth)
    XCTAssertEqual(try int(bounds, "quota_usage_slots"), Wire.quotaUsageSlots)
    XCTAssertEqual(try int(bounds, "credit_opening_bytes"), Wire.creditOpeningBytes)
    XCTAssertEqual(Wire.creditOpeningBytes, 1_125)
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
    XCTAssertEqual(frames.count, 28)
    var sawEnvelope = false
    for frame in frames {
      let name = try string(frame, "frame_name")
      XCTAssertEqual(
        noritoSchemaHash(forTypeName: name), try bytes(frame, "frame_hash_hex"), name)
      let type = try string(frame, "type")
      let namespace = type == "KagemushaWalletLoadReceiptV1"
        ? "iroha_data_model::isi::kagemusha_wallet::"
        : "iroha_data_model::kagemusha::kagemusha_wallet_v1::"
      XCTAssertEqual(name, namespace + type)
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
    XCTAssertEqual(KagemushaWalletDigestRoleV1.allCases.count, 20)
    // One vector per role, in the order of the Rust `KagemushaWalletDigestRoleV1::ALL`.
    XCTAssertEqual(
      try vectors.map { try string($0, "role") },
      KagemushaWalletDigestRoleV1.allCases.map(\.rawValue))
    // Roles of earlier revisions are gone, not aliased: the pre-split roles; the SHA roles whose
    // values are now Poseidon σ-field values (owner answers Q1, Q2 and Q9); every signed-body
    // role, now a Poseidon signing message (A1); and the lineage, credit-opening, credit-status
    // and credited digests, now `P_bytes` values (A3).
    let labels = Set(try vectors.map { try string($0, "role") })
    for retired in [
      "dependencies", "credit-status-statement", "credit", "proof", "step-proof", "payment",
      "blacklist-leaf", "blacklist-node", "quota-window", "quota-node", "certificate-body",
      "credential-body", "scheme-policy-body", "fee-schedule-body", "blacklist-body",
      "quota-share-body", "time-anchor-body", "offer-body", "session-control-body",
      "request-body", "receipt-body", "voucher-body", "ledger-control-body",
      "artifact-manifest-body", "charge-quote-body", "renewal-challenge", "renewal-key-binding",
      "lineage", "credit-opening", "credit-status", "credited",
      "certificate", "credential", "receipt", "scheme-policy", "fee-schedule", "blacklist",
      "quota-share", "time-anchor", "charge-quote", "request", "voucher",
      "certificate-set", "package", "statement", "operation-id", "unload-nullifier",
    ] {
      XCTAssertNil(KagemushaWalletDigestRoleV1(rawValue: retired), retired)
      XCTAssertFalse(labels.contains(retired), retired)
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

  func testArtifactManifestIsTheOnlySHA256SignedObjectDigest() throws {
    let fixture = try loadFixture()
    let vector = try signatureVector(fixture, object: "artifact manifest")
    let expected = try XCTUnwrap(digestVectors(fixture)["artifact-manifest"])
    let message = try hexData(string(vector, "message_hex"))
    let signature = try hexData(string(vector, "signature_hex"))
    XCTAssertEqual(message + signature, try hexData(string(expected, "body_hex")))
    XCTAssertEqual(try Wire.artifactManifestDigest(message: message, signature: signature),
                   try hexData(string(expected, "digest_hex")))
    for bad in [message.prefix(31), message + Data([0]), Data(Wire.fieldModulus)] {
      assertWireError(try Wire.artifactManifestDigest(message: Data(bad), signature: signature),
                      .invalidField("signing_message"))
    }
    let twin = try hexData(string(object(vector, "high_s_twin"), "signature_hex"))
    assertWireError(try Wire.artifactManifestDigest(message: message, signature: twin),
                    .invalidField("signature"))
  }

  // MARK: Signatures

  func testOrdinaryLoadReceiptUsesUnsignedFixedTranscript() throws {
    let fixture = try loadFixture()
    let receipt = try object(fixture, "ordinary_load_receipt")
    let transcript = try hexData(string(receipt, "transcript_hex"))
    XCTAssertEqual(transcript.count, 282)
    XCTAssertEqual(try string(receipt, "domain_ascii"), "kgwolod1")
    XCTAssertNil(KagemushaWalletSigningDomainV1(rawValue: "kgwolod1"))
    XCTAssertEqual(try fieldElements(receipt, "packed_items"), packedFieldElements(transcript))
    let values = try object(object(fixture, "poseidon"), "map_values")
    let load = try fieldElements(object(values, "load"), "items")
    XCTAssertEqual(load[1], try hexData(string(receipt, "digest_hex")))
    assertPoseidonValue(load[1], "ordinary receipt digest")
  }

  func testSigningDomainsMirrorTheRustTableAndEveryVectorSignsItsMessage() throws {
    let fixture = try loadFixture()
    // 16 signing domains in Rust declaration order, each with its exact transcript length.
    let domains = KagemushaWalletSigningDomainV1.allCases
    XCTAssertEqual(domains.count, 16)
    XCTAssertEqual(domains.map(\.rawValue), Array(Self.poseidonDomains[33..<49]))
    for domain in domains {
      XCTAssertEqual(domain.rawValue.utf8.count, 8, domain.rawValue)
    }
    XCTAssertNil(KagemushaWalletSigningDomainV1(rawValue: "kgwprf_1"))
    XCTAssertTrue(
      try string(fixture, "signature_rule")
        .hasPrefix("ECDSA-P256-SHA256 over the 32-byte message_hex"))

    let signatures = try objects(fixture, "signatures")
    let messages = try objects(object(fixture, "poseidon"), "signing_messages")
    XCTAssertEqual(signatures.count, 17)
    XCTAssertEqual(
      try signatures.map { try string($0, "object") }, try messages.map { try string($0, "object") }
    )
    XCTAssertEqual(Set(try signatures.map(signingDomain)), Set(domains))
    for (vector, row) in zip(signatures, messages) {
      let label = try string(vector, "object")
      let domain = try signingDomain(vector)
      let transcript = try hexData(string(vector, "transcript_hex"))
      XCTAssertEqual(transcript.count, domain.transcriptBytes, label)
      // m = P_bytes(d, transcript): the packed element count re-derives; m itself is opaque.
      XCTAssertEqual(try int(vector, "elements"), packedFieldElements(transcript).count, label)
      XCTAssertEqual(try string(row, "domain"), domain.rawValue, label)
      XCTAssertEqual(try hexData(string(row, "body_hex")), transcript, label)
      XCTAssertEqual(try int(row, "elements"), try int(vector, "elements"), label)
      let message = try hexData(string(vector, "message_hex"))
      XCTAssertEqual(try hexData(string(row, "digest_hex")), message, label)
      XCTAssertEqual(message.count, Wire.signingMessageBytes, label)
      assertPoseidonValue(message, label)
    }
    XCTAssertEqual(
      Set(try signatures.map { try string($0, "message_hex") }).count, signatures.count,
      "distinct messages")
  }

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
      "ECDSA-P256-SHA256 over the 32-byte message_hex = P_bytes(domain, transcript_hex); "
        + "RFC 6979 from the fixed scalars, frozen to low S; "
        + "a consumer accepts iff codec_ok and verify_ok")
    let keys = try objects(fixture, "keys").map { try hexData(string($0, "public_key_hex")) }
    let vectors = try objects(fixture, "signatures")
    XCTAssertEqual(vectors.count, 17)
    for vector in vectors {
      let label = try string(vector, "object")
      let publicKey = try hexData(string(vector, "public_key_hex"))
      let message = try hexData(string(vector, "message_hex"))
      let transcript = try hexData(string(vector, "transcript_hex"))
      let signature = try hexData(string(vector, "signature_hex"))
      let codecOK = try bool(vector, "codec_ok")
      let verifyOK = try bool(vector, "verify_ok")
      XCTAssertTrue(codecOK && verifyOK, label)

      XCTAssertTrue(Wire.isValidPublicKey(publicKey), label)
      XCTAssertEqual(Wire.isCanonicalLowSSignature(signature), codecOK, label)
      XCTAssertEqual(cryptoKitEquation(publicKey, message, signature), verifyOK, label)
      XCTAssertTrue(
        Wire.verifySignature(publicKey: publicKey, message: message, signature: signature), label)
      // The ECDSA hash is SHA-256(m): the signature binds the 32-byte message, never the
      // transcript or a SHA-256 preimage of it.
      XCTAssertTrue(
        cryptoKitDigestEquation(publicKey, SHA256.hash(data: message), signature), label)
      XCTAssertFalse(cryptoKitEquation(publicKey, transcript, signature), label)
      XCTAssertFalse(
        Wire.verifySignature(publicKey: publicKey, message: transcript, signature: signature),
        label)

      // CryptoKit accepts the high-S twin; the raw low-S check rejects it first.
      let twinVector = try object(vector, "high_s_twin")
      let twin = try hexData(string(twinVector, "signature_hex"))
      XCTAssertFalse(try bool(twinVector, "codec_ok"), label)
      XCTAssertTrue(try bool(twinVector, "verify_ok"), label)
      XCTAssertFalse(Wire.isCanonicalLowSSignature(twin), label)
      XCTAssertTrue(cryptoKitEquation(publicKey, message, twin), label)
      XCTAssertFalse(
        Wire.verifySignature(publicKey: publicKey, message: message, signature: twin), label)
      XCTAssertEqual(
        try P256.Signing.ECDSASignature(
          derRepresentation: hexData(string(twinVector, "der_hex"))
        ).rawRepresentation,
        twin, label)
      XCTAssertEqual(try hexData(string(twinVector, "frozen_signature_hex")), signature, label)
      XCTAssertEqual(twin.prefix(32), signature.prefix(32), label)
      XCTAssertEqual(
        addBigEndian(Array(signature.suffix(32)), Array(twin.suffix(32))), Wire.groupOrder, label)

      // The signature binds the exact message and key; the message is one canonical value.
      var tampered = message
      tampered[tampered.startIndex] ^= 0x01
      XCTAssertFalse(
        Wire.verifySignature(publicKey: publicKey, message: tampered, signature: signature),
        label)
      for other in keys where other != publicKey {
        XCTAssertFalse(
          Wire.verifySignature(publicKey: other, message: message, signature: signature), label)
      }
      XCTAssertFalse(
        Wire.verifySignature(
          publicKey: publicKey, message: message, signature: signature.prefix(63)),
        label)
      XCTAssertFalse(
        Wire.verifySignature(
          publicKey: publicKey, message: message.prefix(31), signature: signature),
        label)
      XCTAssertFalse(
        Wire.verifySignature(
          publicKey: publicKey, message: message + Data([0]), signature: signature),
        label)
      XCTAssertFalse(
        Wire.verifySignature(
          publicKey: publicKey, message: Data(Wire.fieldModulus), signature: signature),
        label)
    }
  }

  func testSignatureBoundaryCasesSeparateCodecFromEquation() throws {
    let boundary = try object(loadFixture(), "signature_boundaries")
    // The boundary signs the receipt-domain message of a fixed 338-byte transcript.
    let domain = try XCTUnwrap(KagemushaWalletSigningDomainV1(rawValue: string(boundary, "domain")))
    XCTAssertEqual(domain, .receipt)
    XCTAssertEqual(try hexData(string(boundary, "transcript_hex")).count, domain.transcriptBytes)
    let message = try hexData(string(boundary, "message_hex"))
    assertPoseidonValue(message, "boundary message")
    XCTAssertEqual(Data(SHA256.hash(data: message)), try hexData(string(boundary, "e_hex")))
    let publicKey = try hexData(string(boundary, "public_key_hex"))
    XCTAssertEqual(
      try P256.Signing.PrivateKey(rawRepresentation: hexData(string(boundary, "d_hex")))
        .publicKey.x963Representation,
      publicKey)
    // r = x(kG) mod n: x(kG) is r or r + n.
    let kG = try [UInt8](
      P256.Signing.PrivateKey(rawRepresentation: hexData(string(boundary, "k_hex")))
        .publicKey.x963Representation)
    let x = Array(kG[1..<33])
    let r = try bytes(boundary, "r_hex")
    XCTAssertTrue(x == r || addBigEndian(r, Wire.groupOrder) == x)
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
      XCTAssertEqual(cryptoKitEquation(publicKey, message, signature), verifyOK, name)
      XCTAssertEqual(
        Wire.verifySignature(publicKey: publicKey, message: message, signature: signature),
        codecOK && verifyOK, name)
      if name == "s_half_order" {
        XCTAssertEqual(Array(signature.prefix(32)), r)
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
      let namespace = type == "KagemushaWalletLoadReceiptV1"
        ? "iroha_data_model::isi::kagemusha_wallet::"
        : "iroha_data_model::kagemusha::kagemusha_wallet_v1::"
      XCTAssertEqual(name, namespace + type, label)
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

  func testQuotaRefreshRetainsCanonicalFullPredecessorUsageWitness() throws {
    let fixture = try loadFixture()
    let type = "KagemushaWalletQuotaRefreshWitnessV1"
    let identity = try XCTUnwrap(objects(fixture, "frames").first { $0["type"] as? String == type })
    XCTAssertEqual(try int(identity, "max_bytes"), 8_192)
    let witness = try XCTUnwrap(objects(fixture, "objects").first { $0["type"] as? String == type })
    XCTAssertFalse(try bool(witness, "stand_in_proof"))
    let original = try hexData(string(witness, "canonical_hex"))
    XCTAssertLessThanOrEqual(original.count, try int(identity, "max_bytes"))
    let decoded = try XCTUnwrap(noritoDecodeFrame(original))
    XCTAssertEqual(
      decoded.header.schema, try noritoSchemaHash(forTypeName: string(identity, "frame_name")))
    XCTAssertEqual(decoded.paddingLength, 8)
    let frame = try VectorFrame(original)
    let fields = try frame.fields(frame.root)
    XCTAssertEqual(fields.count, 2)
    XCTAssertEqual(frame.data(fields[0]), Data([1, 0]))
    // Fixed arrays have exactly 64 length-prefixed Option values, without a Vec count.
    let slots = try frame.fields(fields[1])
    XCTAssertEqual(slots.count, 64)
    var previousEnd: UInt64 = 0
    for (index, slot) in slots.enumerated() {
      XCTAssertEqual(frame.payload[slot.lowerBound], 1, "occupied slot \(index)")
      let value = try frame.fields((slot.lowerBound + 1)..<slot.upperBound)
      XCTAssertEqual(value.count, 1)
      let leaf = try frame.fields(value[0])
      XCTAssertEqual(leaf.map(\.count), [4, 8, 8, 16])
      let start = readLE64(frame.payload, at: leaf[1].lowerBound)
      let end = readLE64(frame.payload, at: leaf[2].lowerBound)
      XCTAssertTrue(start >= previousEnd && end > start, "ordered window \(index)")
      XCTAssertEqual(
        try unsignedElement(frame.data(leaf[3]) + Data(count: 16)), UInt64(100 + index))
      previousEnd = end
    }
    let tags = try objects(object(fixture, "enum_tags"), "KagemushaWalletRetainedInputRoleV1")
    let role = try XCTUnwrap(tags.first { $0["variant"] as? String == "QuotaRefreshWitness" })
    XCTAssertEqual(try int(role, "tag"), 10)
    let capsuleVector = try XCTUnwrap(
      objects(fixture, "objects").first {
        $0["type"] as? String == "KagemushaWalletRecoveryCapsuleV1"
          && $0["variant"] as? String == "QuotaShare, 64 retained predecessor slots"
      })
    XCTAssertTrue(
      try bool(capsuleVector, "stand_in_proof"), "structural sample is not proof acceptance")
    let capsule = try VectorFrame(hexData(string(capsuleVector, "canonical_hex")))
    let capsuleFields = try capsule.fields(capsule.root)
    XCTAssertEqual(capsuleFields.count, 14, "capsule field layout is unchanged")
    let retained = try capsule.sequence(capsuleFields[12]).map { try capsule.fields($0) }
    XCTAssertEqual(retained.count, 3)
    let input = try XCTUnwrap(
      retained.first { readLE32(capsule.payload, at: $0[0].lowerBound) == 10 })
    XCTAssertEqual(input.count, 2)
    XCTAssertEqual(try capsule.byteVector(input[1]), original)
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
      layouts.map { $0.reduce(0) { $0 + $1.elementCount } }, [4, 4, 9, 4, 2, 5, 3, 0])
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
      "core",
      "rest",
      "statement",
      "credit_id",
      "send_chain",
      "recv_chain",
      "consumed_credit_value",
      "pending_outgoing_value",
      "load_value",
      "load_receipt",
      "redeem_value",
      "fee_claim_value",
      "blacklist_history_value",
      "certificate_set",
      "package",
      "nullifier",
      "credit_digest_value",
      "indexed_leaf",
      "indexed_node",
      "blacklist_leaf",
      "blacklist_node",
      "quota_window_leaf",
      "quota_node",
      "quota_usage_leaf",
      "quota_usage_node",
      "proof_digest",
      "step_proof_digest",
      "payment_digest",
      "lineage_digest",
      "credit_opening_digest",
      "credit_status_digest",
      "credited_digest",
      "operation_id",
      "signing_certificate",
      "signing_credential",
      "signing_renewal_challenge",
      "signing_renewal_key_binding",
      "signing_artifact_manifest",
      "signing_receipt",
      "signing_scheme_policy",
      "signing_fee_schedule",
      "signing_blacklist",
      "signing_quota_share",
      "signing_time_anchor",
      "signing_charge_quote",
      "signing_offer",
      "signing_session_control",
      "signing_request",
      "signing_ledger_control",
      "object_certificate",
      "object_credential",
      "object_receipt",
      "object_scheme_policy",
      "object_fee_schedule",
      "object_blacklist",
      "object_quota_share",
      "object_time_anchor",
      "object_charge_quote",
      "object_request",
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
    // The map value element lists (owner answer A2: each map leaf hashes its key, this value
    // and the next key).
    let consumed = try fieldElements(encodings, "consumed_credit_value")
    let pending = try fieldElements(encodings, "pending_outgoing_value")
    let feeClaim = try fieldElements(encodings, "fee_claim_value")
    let creditDigest = try fieldElements(encodings, "credit_digest_value")
    XCTAssertTrue(try string(encodings, "indexed_leaf_rule").hasPrefix("leaf = P(kgwimlf1"))
    for retired in [
      "consumed_credit_leaf", "pending_outgoing_leaf", "fee_claim_leaf", "credit_digest_leaf",
    ] {
      XCTAssertNil(encodings[retired], retired)
    }
    let lists: [(String, [Data], Int)] = [
      ("send_statement", send, 26), ("receive_statement", receive, 26), ("core", core, 33),
      ("rest", rest, 8), ("send_chain", sendChain, 8), ("recv_chain", recvChain, 5),
      ("consumed_credit_value", consumed, 3), ("pending_outgoing_value", pending, 7),
      ("fee_claim_value", feeClaim, 3), ("credit_digest_value", creditDigest, 3),
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

    // Statement field elements are re-derived from the canonical package records.
    let paymentFrame = try VectorFrame(envelopeFrame(fixture, "Payment"))
    let sendPackage = try paymentFrame.envelopeMessage().fields[4]
    XCTAssertEqual(try statementFieldElements(paymentFrame, paymentFrame.field(sendPackage, 1)), send)
    let receiveFrame = try VectorFrame(objectFrame(fixture, "KagemushaWalletPackageV1", variant: "Receive"))
    XCTAssertEqual(try statementFieldElements(receiveFrame, receiveFrame.field(receiveFrame.root, 1)), receive)

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
    for index in [16, 17, 18, 19, 20, 32] {
      XCTAssertNotEqual(core[index], Data(count: 32), "core[\(index)]")
    }
    // The Receive statement's successor is the successor state's commitment.
    XCTAssertEqual(receive[15], try hexData(string(state, "commitment_hex")))

    // One credit throughout: credit_id and the Payment digest are one element each.
    let poseidon = try object(fixture, "poseidon")
    let credit = try hexData(
      string(object(object(poseidon, "credit_id"), "poseidon"), "digest_hex"))
    let paymentDigest = try hexData(string(largeInput(fixture, "kgwpay_1"), "digest_hex"))
    let sendDescriptor = Array(send[17..<24])
    XCTAssertEqual(send[17], credit)
    XCTAssertEqual(receive[17], credit)
    let paymentBody = try hexData(string(largeInput(fixture, "kgwpay_1"), "body_hex"))
    XCTAssertEqual(send[23], Data(paymentBody[2..<34]))
    XCTAssertEqual(Array(receive[18..<20]), fieldDigestLimbs(try digestValue(digests, "wallet-id")))
    XCTAssertEqual(receive[20], send[21])
    XCTAssertEqual(pending, sendDescriptor)
    XCTAssertEqual(sendChain, [Data(count: 32)] + sendDescriptor)
    XCTAssertEqual(Array(recvChain.dropFirst()), Array(receive[17..<21]))
    assertStandInField(recvChain[0], seed: 0x2c, "recv_chain before the append")
    XCTAssertEqual(consumed, [credit, receive[20], receive[9]])
    XCTAssertEqual(Array(feeClaim.prefix(2)), [credit, send[22]])
    let requestFrame = try VectorFrame(envelopeFrame(fixture, "Request"))
    let requestBody = try requestFrame.envelopeMessage().fields[0]
    XCTAssertEqual(feeClaim[2], try requestFrame.data(requestFrame.field(requestBody, 10)))
    XCTAssertEqual(creditDigest, [credit, paymentDigest, Data(count: 32)])
    XCTAssertEqual(core[0], receive[8])
    XCTAssertEqual(Array(core[1..<3]), Array(receive[3..<5]))
    XCTAssertEqual(Array(core[3..<5]), Array(receive[5..<7]))
    XCTAssertEqual(Array(core[5..<7]), Array(send[18..<20]))
    XCTAssertEqual(core[7], receive[7])
    XCTAssertEqual(core[10], receive[9])
    XCTAssertEqual(core[12], receive[10])
    XCTAssertEqual(core[21], receive[11])
    XCTAssertEqual(core[9], receive[12])

    // Stand-in field values follow their labelled rule; empty map roots are computed.
    let standIns = try object(fixture, "stand_ins")
    XCTAssertNil(standIns["empty_roots_hex"])
    for key in ["credit_digest_root_hex", "lineage_pending_outgoing_root_hex"] {
      let value = try hexData(string(standIns, key))
      assertStandInField(value, seed: value[value.startIndex], key)
    }
  }

  func testControlledStateBindsEveryPositionToItsField() throws {
    // Every element of this state is distinct and its fields are named, so the core and rest
    // layouts (owner answers Q3, Q4 and Q5: one load/redeem root, scheme and asset in the core,
    // the blacklist issue time and maximum age beside each other) are pinned by position.
    let encodings = try object(loadFixture(), "field_encodings")
    let controlled = try object(encodings, "controlled_state")
    let core = try fieldElements(controlled, "core_items")
    let rest = try fieldElements(controlled, "rest_items")
    XCTAssertEqual(core.count, 33)
    XCTAssertEqual(rest.count, 8)
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
      ("wallet_id", .digest), ("credential_digest", .field), ("balance", .integer),
      ("burned_total", .integer), ("sequence", .integer), ("next_send", .integer),
      ("next_load", .integer), ("next_redeem", .integer), ("send_chain", .field),
      ("recv_chain", .field), ("consumed_credit_root", .field), ("pending_outgoing_root", .field),
      ("load_redeem_recovery_root", .field), ("fee_claim_root", .field),
      ("quota_usage_root", .field), ("enabled_controls", .integer),
      ("quota_windows_root", .field), ("quota_share_expires_at_ms", .integer), ("blacklist_version", .integer), ("blacklist_root", .field),
      ("blacklist_issued_at_ms", .integer), ("blacklist_max_age_ms", .integer),
      ("time_anchor_max_response_ms", .integer), ("lease_expires_at_ms", .integer), ("policy_epoch", .integer),
      ("accepted_time_floor_ms", .integer), ("state_nonce", .field),
    ]
    let restOrder: [(String, FrameSlotV1)] = [
      ("permitted_controls", .integer), ("scheme_policy", .field), ("fee_schedule", .field),
      ("blacklist", .field), ("quota_share", .field), ("quota_share_id", .integer),
      ("time_anchor", .field), ("blacklist_history_root", .field),
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

  func testIndexedKeyOrderUsesLittleEndianIntegers() {
    let zero = Data(count: 32)
    let byteMaximum = Data([0xff]) + Data(count: 31)
    let nextByte = Data([0, 1]) + Data(count: 30)
    let lowLimbMaximum = Data(repeating: 0xff, count: 16) + Data(count: 16)
    let nextLimb = Data(count: 16) + Data([1]) + Data(count: 15)
    XCTAssertLessThan(compareLittleEndian(zero, byteMaximum), 0)
    XCTAssertLessThan(compareLittleEndian(byteMaximum, nextByte), 0)
    XCTAssertGreaterThan(compareLittleEndian(nextByte, byteMaximum), 0)
    XCTAssertLessThan(compareLittleEndian(lowLimbMaximum, nextLimb), 0)
    XCTAssertGreaterThan(compareLittleEndian(nextLimb, lowLimbMaximum), 0)
    XCTAssertEqual(compareLittleEndian(nextLimb, nextLimb), 0)
  }

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
    let creditID = try object(object(fixture, "poseidon"), "credit_id")
    let body = try hexData(string(creditID, "request_body_hex"))
    // credit_id = P(kgwcrdt1, the 26 Request-body elements in transcript order) (owner answers
    // Q1 and A5: both account digests are inside the preimage).
    XCTAssertEqual(body, try signedBody(fixture, object: "Request"))
    XCTAssertEqual(body.count, KagemushaWalletSigningDomainV1.request.transcriptBytes)
    XCTAssertEqual(body.count, 458)
    let hashed = try object(creditID, "poseidon")
    XCTAssertEqual(try string(hashed, "domain"), "kgwcrdt1")
    let items = try fieldElements(hashed, "items")
    XCTAssertEqual(items.count, 26)
    XCTAssertEqual(items, try transcriptFieldElements([UInt8](body), requestBodyLayout))
    assertPoseidonValue(try hexData(string(hashed, "digest_hex")), "credit_id")
    // The Request envelope's body record is these fixed-width fields in transcript order.
    let request = try VectorFrame(envelopeFrame(fixture, "Request"))
    let message = try request.envelopeMessage()
    XCTAssertEqual(message.tag, 2)
    let bodyFields = try request.fields(XCTUnwrap(message.fields.first))
    XCTAssertEqual(bodyFields.count, 19)
    XCTAssertEqual(bodyFields.reduce(Data()) { $0 + request.data($1) }, body)
  }

  func testRequestAccountDigestsNameBothCredentialsInsideTheCreditIDPreimage() throws {
    // Request body (19 fields, owner answer A5): payer_account_digest and
    // receiver_account_digest, so the payer's and the receiver's blacklist checks are provable
    // against the same credit_id.
    let fixture = try loadFixture()
    let request = try VectorFrame(envelopeFrame(fixture, "Request"))
    let requestMessage = try request.envelopeMessage()
    XCTAssertEqual(requestMessage.fields.count, 5)
    let body = try request.fields(requestMessage.fields[0]).map { request.data($0) }
    XCTAssertEqual(body.count, 19)
    guard body.count == 19 else { return }

    // The payer's digest is the Offer credential's, the receiver's the Request credential's.
    let offer = try VectorFrame(envelopeFrame(fixture, "Offer"))
    let offerMessage = try offer.envelopeMessage()
    XCTAssertEqual(offerMessage.fields.count, 4)
    let offerBody = try offer.fields(offerMessage.fields[0])
    let payerCredential = try offer.fields(offer.field(offerMessage.fields[1], 0))
    let receiverCredential = try request.fields(request.field(requestMessage.fields[1], 0))
    XCTAssertEqual(offer.data(offerBody[3]), body[Self.requestPayerWallet])
    XCTAssertEqual(offer.data(payerCredential[3]), body[Self.requestPayerWallet])
    XCTAssertEqual(offer.data(payerCredential[4]), body[Self.requestPayerAccount])
    XCTAssertEqual(
      try digestValue(digestVectors(fixture), "account"), body[Self.requestPayerAccount])
    XCTAssertEqual(request.data(receiverCredential[3]), body[Self.requestReceiverWallet])
    XCTAssertEqual(request.data(receiverCredential[4]), body[Self.requestReceiverAccount])
    XCTAssertNotEqual(body[Self.requestPayerAccount], body[Self.requestReceiverAccount])
    for account in [body[Self.requestPayerAccount], body[Self.requestReceiverAccount]] {
      XCTAssertEqual(account.count, 32)
      XCTAssertNotEqual(account, Data(count: 32), "nonzero account digest")
    }

    // Both digests are limb pairs of the 26 credit_id elements.
    let items = try fieldElements(
      object(object(object(fixture, "poseidon"), "credit_id"), "poseidon"), "items")
    XCTAssertEqual(items.count, 26)
    XCTAssertEqual(Array(items[7..<9]), fieldDigestLimbs(body[Self.requestPayerAccount]))
    XCTAssertEqual(Array(items[11..<13]), fieldDigestLimbs(body[Self.requestReceiverAccount]))
  }

  func testLargeInputDigestsPackTheirExactBodiesUnderTheirDomains() throws {
    // The P_bytes digests over large inputs (owner answer A3): both proof_digest domains, the
    // Payment digest, the lineage digest over Ω, the credit-opening and credit-status digests
    // and the Credited digest of both evidence forms. Swift re-derives each packed element
    // count; the values themselves are opaque canonical σ-field values.
    let inputs = try objects(object(loadFixture(), "poseidon"), "large_input_digests")
    XCTAssertEqual(
      try inputs.map { try string($0, "domain") },
      [
        "kgwprf_1", "kgwstep1", "kgwpay_1", "kgwlin_1", "kgwcopn1", "kgwcsts1", "kgwcrdd1",
        "kgwcrdd1",
      ])
    for row in inputs {
      let domain = try string(row, "domain")
      XCTAssertTrue(Self.poseidonDomains.contains(domain), domain)
      _ = try packedDigest(row, domain: domain)
    }
    XCTAssertEqual(
      Set(try inputs.map { try string($0, "digest_hex") }).count, inputs.count, "distinct values")
  }

  func testProofAndPaymentDigestsBindTheCarriedBytes() throws {
    let fixture = try loadFixture()
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
    let omegaPublic = try lineagePublicTranscript(paymentFrame, omega[0])
    let omegaBytes = try omegaPublic + paymentFrame.byteVector(omega[1])
    // The lineage digest is P_bytes(kgwlin_1, Ω bytes) over exactly these bytes (owner answer A3).
    let lineage = try largeInput(fixture, "kgwlin_1")
    XCTAssertEqual(try hexData(string(lineage, "body_hex")), omegaBytes)
    _ = try packedDigest(lineage, domain: "kgwlin_1")
    let sigmaSend = try paymentFrame.byteVector(paymentFrame.field(send[3], 0))
    assertSigmaStandIn(sigmaSend, "σ_send")

    // proof_digest: P_bytes(kgwprf_1, LE32 len(Ω) ‖ Ω ‖ LE32 len(σ) ‖ σ) for Send.
    let sendProofRow = try largeInput(fixture, "kgwprf_1")
    XCTAssertEqual(
      try hexData(string(sendProofRow, "body_hex")), lengthPrefixed([omegaBytes, sigmaSend]))
    let sendProof = try packedDigest(sendProofRow, domain: "kgwprf_1")

    // Ω's 320-byte public transcript: version, scheme, relation, head, wallet, credential, payment
    // key, lifecycle, policy epoch, enabled controls, burned total and the two lineage roots.
    let exposed = [UInt8](omegaPublic)
    XCTAssertEqual(exposed.count, 320)
    guard exposed.count == 320 else { return }
    XCTAssertEqual(Array(exposed[0..<2]), [1, 0])
    XCTAssertEqual(Data(exposed[2..<34]), try digestValue(digests, "scheme"))
    XCTAssertEqual(Data(exposed[34..<66]), try digestValue(digests, "relation"))
    let head = Data(exposed[66..<98])
    assertPoseidonValue(head, "Ω head")
    XCTAssertEqual(Data(exposed[98..<130]), try digestValue(digests, "wallet-id"))
    XCTAssertEqual(Data(exposed[130..<162]), try fieldElements(object(object(fixture, "field_encodings"), "send_statement"), "items")[7])
    XCTAssertEqual(Data(exposed[162..<227]), try fixedKey(fixture, "payer_payment"))
    XCTAssertTrue((1...2).contains(exposed[227]), "lifecycle Active or Retiring")
    let burned = Array(exposed[240..<256])
    let pendingRoot = Data(exposed[256..<288])
    let standIns = try object(fixture, "stand_ins")
    XCTAssertEqual(pendingRoot, try hexData(string(standIns, "lineage_pending_outgoing_root_hex")))
    XCTAssertEqual(
      Data(exposed[288..<320]), try hexData(string(standIns, "credit_digest_root_hex")))
    // The transport proof follows the labelled stand-in rule.
    let transport = [UInt8](omegaBytes.dropFirst(320))
    XCTAssertFalse(transport.isEmpty)
    XCTAssertTrue(transport.indices.allSatisfy { Int(transport[$0]) == ($0 + 7) % 251 })
    // The Send statement consumes this Ω(pred): its lineage fields are Ω's burned total and
    // pending-outgoing root and its predecessor is Ω's head (consumer checks, §3.2).
    let sendItems = try fieldElements(
      object(object(fixture, "field_encodings"), "send_statement"), "items")
    XCTAssertEqual(Array(sendItems[12..<15]), [fieldInteger(burned), pendingRoot, head])

    // The Send receipt body, package digest and statement place it by position (§3.2).
    let sendReceipt = [UInt8](try signedBody(fixture, object: "Send receipt"))
    XCTAssertEqual(sendReceipt.count, 338)
    guard sendReceipt.count == 338 else { return }
    XCTAssertEqual(Data(sendReceipt[242..<274]), sendProof)
    XCTAssertEqual(Data(sendReceipt[306..<338]), Data(count: 32))
    let packageVector = try object(object(fixture, "poseidon"), "package")
    let package = try fieldElements(packageVector, "items")
    XCTAssertEqual(try string(packageVector, "domain"), "kgwpkg_1")
    XCTAssertEqual(package.count, 3)
    XCTAssertEqual(package[0], try hexData(string(object(object(fixture, "field_encodings"), "send_statement"), "digest_hex")))
    XCTAssertEqual(package[1], sendProof)
    assertPoseidonValue(package[2], "Send receipt object digest")

    // proof_digest: P_bytes(kgwstep1, LE32 len(σ) ‖ σ) for the Receive package of Credited.
    let receiveFrame = try VectorFrame(envelopeFrame(fixture, "Credited::Receive"))
    let credited = try receiveFrame.envelopeMessage()
    XCTAssertEqual(credited.tag, 4)
    let evidence = try receiveFrame.variant(credited.fields[2])
    XCTAssertEqual(evidence.tag, 1)
    let receivePackage = try receiveFrame.fields(XCTUnwrap(evidence.fields.first))
    XCTAssertEqual(receivePackage.count, 5)
    let sigmaReceive = try receiveFrame.byteVector(receiveFrame.field(receivePackage[3], 0))
    let receiveProofRow = try largeInput(fixture, "kgwstep1")
    XCTAssertEqual(
      try hexData(string(receiveProofRow, "body_hex")), lengthPrefixed([sigmaReceive]))
    let receiveProof = try packedDigest(receiveProofRow, domain: "kgwstep1")
    XCTAssertNotEqual(receiveProof, sendProof)

    // Payment digest: P_bytes(kgwpay_1, payment transcript), binding Ω(pred), σ_send and τ_send
    // through the Send package digest (owner answer Q9).
    let paymentRow = try largeInput(fixture, "kgwpay_1")
    let transcript = [UInt8](try hexData(string(paymentRow, "body_hex")))
    XCTAssertEqual(transcript.count, 163)
    guard transcript.count == 163 else { return }
    XCTAssertEqual(Array(transcript[0..<2]), [1, 0])
    XCTAssertEqual(Data(transcript[2..<34]), try fieldElements(object(fixture, "field_encodings"), "pending_outgoing_value")[6])
    XCTAssertEqual(Data(transcript[34..<99]), paymentFrame.data(payment.fields[2]))
    XCTAssertEqual(Data(transcript[99..<131]), paymentFrame.data(payment.fields[3]))
    XCTAssertEqual(Data(transcript[99..<131]), try fieldElements(object(object(fixture, "field_encodings"), "send_statement"), "items")[7])
    XCTAssertEqual(Data(transcript[131..<163]), try hexData(string(packageVector, "digest_hex")))
    let paymentValue = try packedDigest(paymentRow, domain: "kgwpay_1")
    XCTAssertEqual(try int(paymentRow, "elements"), 7)

    // The Receive receipt binds σ_recv's proof_digest and the Payment digest; the Receive
    // package's receipt and its output descriptor carry the same value.
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
    let receiveStatementDigest = try hexData(string(
      object(object(fixture, "field_encodings"), "receive_statement"), "digest_hex"))
    XCTAssertEqual(Data(output[1..<33]), receiveStatementDigest)
    XCTAssertEqual(Data(output[33..<65]), receiveProof)
    XCTAssertEqual(Data(output[65..<97]), paymentValue)

    // The Credited digest P_bytes(kgwcrdd1, LE16 version ‖ tag evidence ‖ credit_id ‖
    // payment_digest ‖ evidence digest) of both forms (owner answer A3).
    let creditedRows = try largeInputs(fixture, "kgwcrdd1")
    XCTAssertEqual(creditedRows.count, 2)
    guard creditedRows.count == 2 else { return }
    let credit = try hexData(
      string(object(object(object(fixture, "poseidon"), "credit_id"), "poseidon"), "digest_hex"))
    var evidenceDigests: [Data] = []
    for (index, row) in creditedRows.enumerated() {
      let label = try string(row, "object")
      let body = [UInt8](try hexData(string(row, "body_hex")))
      XCTAssertEqual(body.count, 99, label)
      guard body.count == 99 else { return }
      XCTAssertEqual(Array(body[0..<3]), [1, 0, UInt8(index + 1)], label)
      XCTAssertEqual(Data(body[3..<35]), credit, label)
      XCTAssertEqual(Data(body[35..<67]), paymentValue, label)
      evidenceDigests.append(Data(body[67..<99]))
    }
    // Receive form carries the native Poseidon package digest.
    assertPoseidonValue(evidenceDigests[0], "Receive package digest")
    // Status form: the evidence digest is the credit-status digest.
    XCTAssertEqual(
      evidenceDigests[1], try hexData(string(largeInput(fixture, "kgwcsts1"), "digest_hex")))
  }

  func testMapValuesFollowTheirDomainsAndKeyRules() throws {
    let fixture = try loadFixture()
    let poseidon = try object(fixture, "poseidon")
    let encodings = try object(fixture, "field_encodings")
    let digests = try digestVectors(fixture)
    let credit = try hexData(
      string(object(object(poseidon, "credit_id"), "poseidon"), "digest_hex"))

    // Every map value: its domain, element list and key; `credit_id` keys the credit maps.
    let values = try object(poseidon, "map_values")
    let expectations: [(name: String, domain: String)] = [
      ("consumed_credit", "kgwccrd1"), ("pending_outgoing", "kgwpout1"), ("load", "kgwload1"),
      ("redeem", "kgwrdm_1"), ("fee_claim", "kgwfee_1"),
    ]
    XCTAssertEqual(Set(values.keys), Set(expectations.map { $0.name }))
    for expectation in expectations {
      let value = try object(values, expectation.name)
      XCTAssertEqual(try string(value, "domain"), expectation.domain, expectation.name)
      let key = try hexData(string(value, "key_hex"))
      assertPoseidonValue(key, "\(expectation.name) key")
      for item in try fieldElements(value, "items") {
        XCTAssertTrue(Wire.isCanonicalFieldValue(item), expectation.name)
      }
      assertPoseidonValue(try hexData(string(value, "digest_hex")), expectation.name)
    }
    for name in ["consumed_credit", "pending_outgoing", "fee_claim"] {
      let value = try object(values, name)
      XCTAssertEqual(try hexData(string(value, "key_hex")), credit, name)
      XCTAssertEqual(
        try fieldElements(value, "items"), try fieldElements(encodings, name + "_value"), name)
    }

    // One load/redeem recovery map keyed by (kind, ordinal) = kind · 2^128 + ordinal (owner
    // answer Q3): ordinary receipt and nullifier digests each occupy one field element.
    let load = try object(values, "load")
    let loadItems = try fieldElements(load, "items")
    XCTAssertEqual(loadItems.count, 3)
    XCTAssertEqual(try hexData(string(load, "key_hex")), pairKey(high: 1, low: loadItems[0]))
    assertPoseidonValue(loadItems[1], "ordinary receipt digest")
    let redeem = try object(values, "redeem")
    let redeemItems = try fieldElements(redeem, "items")
    XCTAssertEqual(redeemItems.count, 4)
    XCTAssertEqual(try hexData(string(redeem, "key_hex")), pairKey(high: 2, low: redeemItems[0]))
    let nullifier = try object(poseidon, "unload_nullifier")
    XCTAssertEqual(try string(nullifier, "domain"), "kgwnull1")
    let nullifierItems = try fieldElements(nullifier, "items")
    XCTAssertEqual(nullifierItems.count, 5)
    XCTAssertEqual(Array(nullifierItems.prefix(2)), fieldDigestLimbs(try digestValue(digests, "scheme")))
    let requestFrame = try VectorFrame(envelopeFrame(fixture, "Request"))
    let requestBody = try requestFrame.envelopeMessage().fields[0]
    XCTAssertEqual(Array(nullifierItems[2..<4]), try fieldDigestLimbs(requestFrame.data(requestFrame.field(requestBody, Self.requestPayerWallet))))
    XCTAssertEqual(try unsignedElement(nullifierItems[4]), 2)
    assertPoseidonValue(try hexData(string(nullifier, "digest_hex")), "unload nullifier")
    assertPoseidonValue(redeemItems[1], "recovery nullifier")
    XCTAssertLessThanOrEqual(try unsignedElement(redeemItems[3]), try unsignedElement(redeemItems[2]))
  }

  func testIndexedTreeInsertionsOpeningsAndRemovalLinkSortedLeaves() throws {
    // Indexed maps are depth-32 Poseidon trees (owner answer A2): sorted linked
    // leaves (key, value, next_key), an empty slot is zero, and the empty tree is the zero
    // sentinel leaf in slot 0.
    let fixture = try loadFixture()
    let poseidon = try object(fixture, "poseidon")
    let tree = try object(poseidon, "indexed_tree")
    XCTAssertEqual(try hexData(string(tree, "empty_slot_hex")), Data(count: 32))
    let sentinel = try object(tree, "sentinel_leaf")
    XCTAssertEqual(try string(sentinel, "domain"), "kgwimlf1")
    XCTAssertEqual(
      try fieldElements(sentinel, "items"), Array(repeating: Data(count: 32), count: 3))
    assertPoseidonValue(try hexData(string(sentinel, "digest_hex")), "sentinel leaf")
    let heightOne = try object(tree, "empty_subtree_height_1")
    XCTAssertEqual(try string(heightOne, "domain"), "kgwimnd1")
    XCTAssertEqual(
      try fieldElements(heightOne, "items"), Array(repeating: Data(count: 32), count: 2))
    let heightOneValue = try hexData(string(heightOne, "digest_hex"))
    assertPoseidonValue(heightOneValue, "empty subtree of height 1")
    assertPoseidonValue(try hexData(string(tree, "empty_root_hex")), "empty root")
    let empties = EmptySubtreesV1(heightOne: heightOneValue)
    let values = try object(poseidon, "map_values")

    // Successive insertions write the next free slots 1, 2, 3: the low leaf that brackets the
    // new key is relinked to it, then the new leaf takes the low leaf's old next key.
    let insertions = try objects(tree, "load_redeem_insertions")
    XCTAssertEqual(insertions.count, 3)
    var root = try hexData(string(tree, "empty_root_hex"))
    for (index, insertion) in insertions.enumerated() {
      let slot = index + 1
      let label = "insertion at slot \(slot)"
      XCTAssertEqual(try int(insertion, "slot"), slot, label)
      XCTAssertEqual(try hexData(string(insertion, "old_root_hex")), root, label)
      let key = try hexData(string(insertion, "key_hex"))
      let lowVector = try object(insertion, "low")
      XCTAssertEqual(try hexData(string(lowVector, "root_hex")), root, label)
      let low = try checkedLeafOpening(
        lowVector, occupiedThrough: slot - 1, empties: empties, label: "\(label) low leaf")
      assertBrackets(low, key, label)
      let linked = try object(insertion, "linked_low")
      XCTAssertEqual(try hexData(string(linked, "key_hex")), low.key, label)
      XCTAssertEqual(try hexData(string(linked, "value_hex")), low.value, label)
      XCTAssertEqual(try hexData(string(linked, "next_key_hex")), key, label)
      assertPoseidonValue(try hexData(string(linked, "leaf_hex")), label)
      assertPoseidonValue(try hexData(string(insertion, "intermediate_root_hex")), label)
      let emptySiblings = try checkedEmptySlotOpening(
        object(insertion, "empty_slot_opening"), slot: slot, occupiedThrough: slot - 1,
        empties: empties, label: label)
      // The relinked low leaf sits beside the written slot when their slots are siblings.
      if low.slot == slot ^ 1, let first = emptySiblings.first {
        XCTAssertEqual(try hexData(string(linked, "leaf_hex")), first, label)
      }
      let leaf = try object(insertion, "leaf")
      XCTAssertEqual(try hexData(string(leaf, "key_hex")), key, label)
      XCTAssertEqual(
        try hexData(string(leaf, "value_hex")), try hexData(string(insertion, "value_hex")), label)
      XCTAssertEqual(try hexData(string(leaf, "next_key_hex")), low.nextKey, label)
      assertPoseidonValue(try hexData(string(leaf, "leaf_hex")), label)
      root = try hexData(string(insertion, "root_hex"))
      assertPoseidonValue(root, label)
    }
    guard insertions.count == 3 else { return }
    // The recovery map receives the Redeem and Load values of the map_values section.
    let redeem = try object(values, "redeem")
    let load = try object(values, "load")
    XCTAssertEqual(try string(insertions[0], "key_hex"), try string(redeem, "key_hex"))
    XCTAssertEqual(try string(insertions[0], "value_hex"), try string(redeem, "digest_hex"))
    XCTAssertEqual(try string(insertions[1], "key_hex"), try string(load, "key_hex"))
    XCTAssertEqual(try string(insertions[1], "value_hex"), try string(load, "digest_hex"))
    XCTAssertEqual(
      try hexData(string(insertions[2], "key_hex")), pairKey(high: 1, low: fieldInteger([1])))

    // Membership opens the leaf at its slot; non-membership opens the low leaf whose key and
    // next key bracket the absent key: through the sentinel, an interior leaf and the largest.
    let membership = try object(tree, "membership")
    XCTAssertEqual(try hexData(string(membership, "root_hex")), root)
    let member = try checkedLeafOpening(
      membership, occupiedThrough: 3, empties: empties, label: "membership")
    XCTAssertEqual(member.key, try hexData(string(load, "key_hex")))
    XCTAssertEqual(member.value, try hexData(string(load, "digest_hex")))
    let presentKeys = Set(try insertions.map { try string($0, "key_hex") })
    var lows: [LeafOpeningV1] = []
    for name in [
      "non_membership_through_sentinel", "non_membership_through_interior_low_leaf",
      "non_membership_above_the_largest_key",
    ] {
      let vector = try object(tree, name)
      let absent = try hexData(string(vector, "absent_key_hex"))
      XCTAssertFalse(presentKeys.contains(hex(absent)), name)
      let lowVector = try object(vector, "low")
      XCTAssertEqual(try hexData(string(lowVector, "root_hex")), root, name)
      let low = try checkedLeafOpening(
        lowVector, occupiedThrough: 3, empties: empties, label: name)
      assertBrackets(low, absent, name)
      lows.append(low)
    }
    XCTAssertEqual(lows[0].key, Data(count: 32), "the sentinel is the low leaf below every key")
    XCTAssertEqual(lows[0].slot, 0)
    XCTAssertNotEqual(lows[1].key, Data(count: 32), "interior low leaf")
    XCTAssertNotEqual(lows[1].nextKey, Data(count: 32), "interior low leaf")
    XCTAssertEqual(lows[2].nextKey, Data(count: 32), "the largest key has a zero next key")

    // A removal unlinks the leaf from its predecessor, then clears its slot; slots are not
    // reused, so the next free slot stays above it.
    let removal = try object(tree, "pending_outgoing_removal")
    let removedKey = try hexData(string(removal, "removed_key_hex"))
    XCTAssertEqual(
      removedKey,
      try hexData(string(object(object(poseidon, "credit_id"), "poseidon"), "digest_hex")))
    let nextFree = try int(removal, "next_free_slot")
    let predecessorVector = try object(removal, "predecessor")
    XCTAssertEqual(
      try string(predecessorVector, "root_hex"), try string(removal, "old_root_hex"))
    let predecessor = try checkedLeafOpening(
      predecessorVector, occupiedThrough: nextFree - 1, empties: empties,
      label: "removal predecessor")
    XCTAssertEqual(predecessor.nextKey, removedKey)
    let removedVector = try object(removal, "removed")
    XCTAssertEqual(
      try string(removedVector, "root_hex"), try string(removal, "intermediate_root_hex"))
    let removed = try checkedLeafOpening(
      removedVector, occupiedThrough: nextFree - 1, empties: empties, label: "removed leaf")
    XCTAssertEqual(removed.key, removedKey)
    XCTAssertEqual(
      removed.value, try hexData(string(object(values, "pending_outgoing"), "digest_hex")))
    XCTAssertLessThan(removed.slot, nextFree)
    XCTAssertLessThan(predecessor.slot, nextFree)
    let relinked = try object(removal, "relinked_predecessor")
    XCTAssertEqual(try hexData(string(relinked, "key_hex")), predecessor.key)
    XCTAssertEqual(try hexData(string(relinked, "value_hex")), predecessor.value)
    XCTAssertEqual(try hexData(string(relinked, "next_key_hex")), removed.nextKey)
    assertPoseidonValue(try hexData(string(removal, "root_hex")), "root after removal")

    // Every learned empty subtree is one value per height across all openings.
    XCTAssertEqual(empties.count, Wire.indexedTreeDepth, "an empty subtree at every height")
  }

  func testQuotaUsageChargesItsAlignedDepthSixArraySlot() throws {
    let array = try object(object(loadFixture(), "poseidon"), "quota_usage_array")
    XCTAssertEqual(try int(array, "depth"), Wire.quotaTreeDepth)
    XCTAssertEqual(try int(array, "slots"), Wire.quotaUsageSlots)
    let leaves = try fieldElements(array, "leaf_values")
    XCTAssertEqual(leaves.count, 64)
    let usage = try object(array, "usage")
    let charged = try object(array, "charged_usage")
    for value in [usage, charged] { XCTAssertEqual(try string(value, "domain"), "kgwquse1") }
    let before = try fieldElements(usage, "items")
    let after = try fieldElements(charged, "items")
    XCTAssertEqual(before.count, 4)
    XCTAssertEqual(after.count, 4)
    XCTAssertEqual(Array(before.prefix(3)), Array(after.prefix(3)))
    let gross = try XCTUnwrap(UInt64(string(array, "gross")))
    XCTAssertEqual(try unsignedElement(before[3]) + gross, try unsignedElement(after[3]))
    let window = try fieldElements(object(array, "window"), "items")
    XCTAssertEqual(Array(before.prefix(3)), Array(window.prefix(3)))
    XCTAssertLessThanOrEqual(try unsignedElement(after[3]), try unsignedElement(window[3]))
    XCTAssertEqual(leaves[0], try hexData(string(usage, "digest_hex")))
    let padding = try object(array, "padding_leaf")
    XCTAssertEqual(try fieldElements(padding, "items"), Array(repeating: Data(count: 32), count: 4))
    let paddingValue = try hexData(string(padding, "digest_hex"))
    for leaf in leaves.dropFirst(2) { XCTAssertEqual(leaf, paddingValue) }
    let node = try object(array, "padding_node_height_1")
    XCTAssertEqual(try string(node, "domain"), "kgwqusn1")
    XCTAssertEqual(try fieldElements(node, "items"), [paddingValue, paddingValue])
    for (name, slot) in [("usage_opening", 0), ("window_opening", 0), ("padding_opening", 63)] {
      let opening = try object(array, name)
      XCTAssertEqual(try int(opening, "slot"), slot)
      let siblings = try fieldElements(opening, "siblings")
      XCTAssertEqual(siblings.count, 6)
      for value in siblings { assertPoseidonValue(value, name) }
    }
    for name in ["old_root_hex", "root_hex", "empty_root_hex", "windows_root_hex"] {
      assertPoseidonValue(try hexData(string(array, name)), name)
    }
    XCTAssertNotEqual(try string(array, "old_root_hex"), try string(array, "root_hex"))
    XCTAssertNotEqual(try string(usage, "digest_hex"), try string(charged, "digest_hex"))
  }

  func testCreditStatusOpeningIsAFixed32SiblingLeafOpening() throws {
    let fixture = try loadFixture()
    let poseidon = try object(fixture, "poseidon")
    let digests = try digestVectors(fixture)
    let credit = try hexData(
      string(object(object(poseidon, "credit_id"), "poseidon"), "digest_hex"))
    let paymentValue = try hexData(string(largeInput(fixture, "kgwpay_1"), "digest_hex"))

    // The credit-digest value P(kgwcdig1, [credit_id, payment_digest, burned]) keyed by
    // credit_id in the depth-32 indexed credit-digest tree (owner answers Q7 and A2).
    let vector = try object(poseidon, "credit_digest_opening")
    let value = try object(vector, "value")
    XCTAssertEqual(try string(value, "domain"), "kgwcdig1")
    XCTAssertEqual(try hexData(string(value, "key_hex")), credit)
    let valueItems = try fieldElements(value, "items")
    XCTAssertEqual(
      valueItems, try fieldElements(object(fixture, "field_encodings"), "credit_digest_value"))
    XCTAssertEqual(valueItems, [credit, paymentValue, Data(count: 32)])
    guard valueItems.count == 3 else { return }
    let valueDigest = try hexData(string(value, "digest_hex"))
    assertPoseidonValue(valueDigest, "credit-digest value")
    let membership = try object(vector, "membership")
    let leaf = try checkedLeafOpening(
      membership, occupiedThrough: nil, empties: nil, label: "credit-digest membership")
    XCTAssertEqual(leaf.key, credit)
    XCTAssertEqual(leaf.value, valueDigest)
    XCTAssertGreaterThanOrEqual(leaf.slot, 1, "slot 0 holds only the sentinel")

    // Its credit-opening transcript (1,125): credit_id ‖ payment_digest ‖ u8 burned ‖ next_key
    // ‖ LE32 slot ‖ 32 siblings; the credit-opening digest packs it.
    let burned = UInt8(try unsignedElement(valueItems[2]))
    var opening = credit + paymentValue + Data([burned]) + leaf.nextKey
    opening.append(contentsOf: le32(UInt32(leaf.slot)))
    opening.append(leaf.siblings.reduce(Data(), +))
    XCTAssertEqual(opening.count, Wire.creditOpeningBytes)
    XCTAssertEqual(try hexData(string(vector, "credit_opening_hex")), opening)
    let openingRow = try largeInput(fixture, "kgwcopn1")
    XCTAssertEqual(try hexData(string(openingRow, "body_hex")), opening)
    let openingDigest = try packedDigest(openingRow, domain: "kgwcopn1")

    // Credited::Status carries this opening against Ω(h)'s credit_digest_root, and Ω(h) names
    // the Request's receiver by wallet_id and payment key (owner answer Q8).
    let frame = try VectorFrame(envelopeFrame(fixture, "Credited::Status"))
    let credited = try frame.envelopeMessage()
    XCTAssertEqual(credited.tag, 4)
    XCTAssertEqual(credited.fields.count, 3)
    let evidence = try frame.variant(credited.fields[2])
    XCTAssertEqual(evidence.tag, 2)
    let status = try frame.fields(XCTUnwrap(evidence.fields.first))
    XCTAssertEqual(status.count, 6)
    guard status.count == 6 else { return }
    let carried = try frame.fields(status[5])
    XCTAssertEqual(carried.count, 6)
    guard carried.count == 6 else { return }
    XCTAssertEqual(frame.data(carried[0]), credit)
    XCTAssertEqual(frame.data(carried[1]), paymentValue)
    XCTAssertEqual(frame.data(carried[2]), Data([burned]))
    XCTAssertEqual(frame.data(carried[3]), leaf.nextKey)
    XCTAssertEqual(frame.data(carried[4]), Data(le32(UInt32(leaf.slot))))
    let siblingBytes = try frame.byteVector(carried[5])
    XCTAssertEqual(siblingBytes.count, Wire.indexedTreeDepth * 32)
    XCTAssertEqual(siblingBytes, leaf.siblings.reduce(Data(), +))
    let omega = try frame.fields(status[4])
    XCTAssertEqual(omega.count, 2)
    let omegaPublic = [UInt8](try lineagePublicTranscript(frame, omega[0]))
    XCTAssertEqual(
      Data(omegaPublic.suffix(32)), try hexData(string(membership, "root_hex")),
      "Ω(h) credit_digest_root")
    let requestFrame = try VectorFrame(envelopeFrame(fixture, "Request"))
    let requestBody = try requestFrame.fields(
      XCTUnwrap(requestFrame.envelopeMessage().fields.first))
    XCTAssertEqual(
      Data(omegaPublic[98..<130]), requestFrame.data(requestBody[Self.requestReceiverWallet]),
      "Ω(h) wallet is the Request receiver")
    XCTAssertEqual(
      Data(omegaPublic[162..<227]), try fixedKey(fixture, "receiver_payment"),
      "Ω(h) payment key is the receiver's")
    let statusProof = frame.data(status[2])
    assertPoseidonValue(statusProof, "CreditStatus proof_digest")

    // The credit-status transcript (162): LE16 version ‖ statement_digest ‖ proof_digest ‖
    // receipt_digest ‖ lineage_digest ‖ opening_digest; its lineage digest is the P_bytes value
    // of Ω(h)'s bytes and its opening digest the credit-opening digest.
    let statusBody = [UInt8](try hexData(string(largeInput(fixture, "kgwcsts1"), "body_hex")))
    XCTAssertEqual(statusBody.count, 162)
    guard statusBody.count == 162 else { return }
    XCTAssertEqual(Array(statusBody[0..<2]), [1, 0])
    XCTAssertEqual(Data(statusBody[34..<66]), statusProof)
    assertPoseidonValue(Data(statusBody[98..<130]), "Ω(h) lineage digest")
    XCTAssertEqual(Data(statusBody[130..<162]), openingDigest)
    // No SHA role carries the lineage, opening, status or Credited digests (owner answer A3).
    for retired in ["lineage", "credit-opening", "credit-status", "credited"] {
      XCTAssertNil(digests[retired], retired)
    }
  }

  func testBlacklistAndQuotaTreesBindTheirSignedFrames() throws {
    let fixture = try loadFixture()
    let poseidon = try object(fixture, "poseidon")

    // Blacklist {body, signature, entries: [{account_digest}]}: entries strictly ascending in
    // limb order (owner answer A4), here unlike their unsigned byte order, strictly between the
    // 00…00 and FF…FF sentinels.
    let blacklistFrame = try VectorFrame(
      objectFrame(fixture, "KagemushaWalletBlacklistV1", variant: "3 entries"))
    let blacklistFields = try blacklistFrame.fields(blacklistFrame.root)
    XCTAssertEqual(blacklistFields.count, 3)
    guard blacklistFields.count == 3 else { return }
    let entries = try blacklistFrame.sequence(blacklistFields[2]).map {
      try blacklistFrame.data(blacklistFrame.field($0, 0))
    }
    XCTAssertEqual(entries.count, 3)
    let blacklist = try object(poseidon, "blacklist")
    XCTAssertTrue(try string(blacklist, "order").hasPrefix("limb order"))
    XCTAssertEqual(try fieldElements(blacklist, "entries"), entries)
    let low = Data(count: 32)
    let high = Data(repeating: 0xff, count: 32)
    let sentinels = [low] + entries + [high]
    for (lower, upper) in zip(sentinels, sentinels.dropFirst()) {
      XCTAssertLessThan(compareLittleEndian(lower, upper), 0)
    }
    let byteOrder = try fieldElements(blacklist, "entries_in_unsigned_byte_order")
    XCTAssertEqual(byteOrder, entries.sorted { $0.lexicographicallyPrecedes($1) })
    XCTAssertNotEqual(byteOrder, entries, "the orders differ")
    let root = try hexData(string(blacklist, "entries_root_hex"))
    assertPoseidonValue(root, "blacklist root")
    XCTAssertEqual(try blacklistFrame.data(blacklistFrame.field(blacklistFields[0], 5)), root)
    let body = [UInt8](try signedBody(fixture, object: "blacklist"))
    XCTAssertEqual(body.count, 118)
    guard body.count == 118, let firstEntry = entries.first else { return }
    XCTAssertEqual(readLE32(body, at: 50), UInt32(entries.count))
    XCTAssertEqual(Data(body[54..<86]), root)

    // Leaf P(kgwblkl1, limbs(s_i) ‖ limbs(s_(i+1))) and node P(kgwblkn1, [left, right]).
    let leaf0 = try object(blacklist, "leaf_0")
    XCTAssertEqual(try string(leaf0, "domain"), "kgwblkl1")
    XCTAssertEqual(
      try fieldElements(leaf0, "items"), fieldDigestLimbs(low) + fieldDigestLimbs(firstEntry))
    let leaf0Value = try hexData(string(leaf0, "digest_hex"))
    assertPoseidonValue(leaf0Value, "gap leaf 0")
    let node = try object(blacklist, "node_0_1")
    XCTAssertEqual(try string(node, "domain"), "kgwblkn1")
    let nodeItems = try fieldElements(node, "items")
    XCTAssertEqual(nodeItems.count, 2)
    XCTAssertEqual(nodeItems.first, leaf0Value)
    assertPoseidonValue(try hexData(string(node, "digest_hex")), "blacklist node")

    // A non-membership witness: one gap leaf with lower < x < upper in limb order and its 16
    // siblings. The unsigned byte order would not bracket this account.
    let gap = try object(blacklist, "gap_opening")
    let account = try hexData(string(gap, "account_digest_hex"))
    XCTAssertEqual(account, Wire.digest(role: .account, body: Data("unlisted".utf8)))
    let index = try int(gap, "leaf_index")
    XCTAssertEqual(index, 1)
    guard sentinels.indices.dropLast().contains(index) else { return }
    let lower = try hexData(string(gap, "lower_hex"))
    let upper = try hexData(string(gap, "upper_hex"))
    XCTAssertEqual(lower, sentinels[index])
    XCTAssertEqual(upper, sentinels[index + 1])
    XCTAssertLessThan(compareLittleEndian(lower, account), 0, "lower < account")
    XCTAssertLessThan(compareLittleEndian(account, upper), 0, "account < upper")
    XCTAssertFalse(
      lower.lexicographicallyPrecedes(account) && account.lexicographicallyPrecedes(upper),
      "the byte order does not bracket it")
    let gapSiblings = try fieldElements(gap, "siblings")
    XCTAssertEqual(gapSiblings.count, 16)
    for sibling in gapSiblings {
      assertPoseidonValue(sibling, "gap sibling")
    }
    XCTAssertEqual(gapSiblings.first, leaf0Value, "gap leaf 1 sits beside leaf 0")
    XCTAssertEqual(try hexData(string(gap, "root_hex")), root)

    // Quota share {body, windows, signature}: window {kind, start_ms, end_ms, limit}; leaf
    // P(kgwqwin1, [tag kind, start, end, limit]) and node P(kgwqwnd1, [left, right]).
    let quotaFrame = try VectorFrame(
      objectFrame(fixture, "KagemushaWalletQuotaShareV1", variant: "2 windows"))
    let quotaFields = try quotaFrame.fields(quotaFrame.root)
    XCTAssertEqual(quotaFields.count, 3)
    guard quotaFields.count == 3 else { return }
    let windows = try quotaFrame.sequence(quotaFields[1])
    XCTAssertEqual(windows.count, 2)
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
    let window0Value = try hexData(string(window0, "digest_hex"))
    assertPoseidonValue(window0Value, "window 0")
    let quotaNode = try object(quota, "node_0_1")
    XCTAssertEqual(try string(quotaNode, "domain"), "kgwqwnd1")
    let quotaNodeItems = try fieldElements(quotaNode, "items")
    XCTAssertEqual(quotaNodeItems.count, 2)
    XCTAssertEqual(quotaNodeItems.first, window0Value)
    assertPoseidonValue(try hexData(string(quotaNode, "digest_hex")), "window node")
    let emptyWindow = try hexData(string(quota, "empty_window_hex"))
    assertPoseidonValue(emptyWindow, "empty window slot")
    XCTAssertNotEqual(emptyWindow, window0Value)
    let windowsRoot = try hexData(string(quota, "windows_root_hex"))
    assertPoseidonValue(windowsRoot, "quota windows root")
    XCTAssertEqual(try quotaFrame.data(quotaFrame.field(quotaFields[0], 7)), windowsRoot)
    let shareBody = [UInt8](try signedBody(fixture, object: "quota share"))
    XCTAssertEqual(shareBody.count, 190)
    guard shareBody.count == 190 else { return }
    XCTAssertEqual(Data(shareBody[122..<154]), windowsRoot)
    XCTAssertEqual(readLE32(shareBody, at: 154), UInt32(windows.count))
    // The quota-usage value counts against the first window.
    let usage = try fieldElements(object(object(poseidon, "quota_usage_array"), "usage"), "items")
    XCTAssertEqual(Array(usage.prefix(3)), Array(expectedWindow.prefix(3)))
    XCTAssertLessThanOrEqual(
      try unsignedElement(usage[3]), try unsignedElement(expectedWindow[3]), "usage within limit")
  }

  func testVerifyingKeyAllowlistBindsTheManifestAndEveryVectoredProofLength() throws {
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
    // Strictly ascending by (tag, mask); every operation once with mask 0; Send repeats once
    // per supported mask of defined control bits, and Receive once with the blacklist bit
    // exactly when some Send mask has it; nonzero stand-in keys; lengths within a frame.
    let selectors = allowlist.steps.map { UInt64($0.kind) << 32 | UInt64($0.mask) }
    XCTAssertEqual(selectors, selectors.sorted())
    XCTAssertEqual(Set(selectors).count, selectors.count)
    for kind in UInt8(1)...8 {
      XCTAssertTrue(allowlist.steps.contains { $0.kind == kind && $0.mask == 0 }, "kind \(kind)")
    }
    var lengths: [UInt64: Int] = [:]
    for step in allowlist.steps {
      XCTAssertTrue((1...8).contains(step.kind))
      XCTAssertEqual(step.mask & ~UInt32(0b111), 0)
      XCTAssertTrue(
        step.mask == 0 || UInt32(step.kind) == Self.sendTag
          || (UInt32(step.kind) == Self.receiveTag && step.mask == Self.blacklistControl),
        "selector \(step.kind)/\(step.mask)")
      let keyByte = 0x80 | step.kind << 3 | UInt8(step.mask)
      XCTAssertEqual(step.key, Data(repeating: keyByte, count: 32), "stand-in key")
      XCTAssertTrue((1...Wire.messageMaximumBytes).contains(Int(step.proofBytes)))
      if UInt32(step.kind) == Self.receiveTag {
        XCTAssertLessThanOrEqual(Int(step.proofBytes), Wire.creditedReceiveProofBudgetBytes)
      }
      lengths[UInt64(step.kind) << 32 | UInt64(step.mask)] = Int(step.proofBytes)
    }
    XCTAssertEqual(
      allowlist.steps.contains {
        UInt32($0.kind) == Self.sendTag && $0.mask & Self.blacklistControl != 0
      },
      allowlist.steps.contains {
        UInt32($0.kind) == Self.receiveTag && $0.mask == Self.blacklistControl
      })
    XCTAssertEqual(allowlist.lineageKey, Data(repeating: 0xc4, count: 32), "stand-in Ω key")
    let lineageProofBytes = Int(allowlist.lineageProofBytes)
    let largestSend =
      allowlist.steps.filter { UInt32($0.kind) == Self.sendTag }.map { Int($0.proofBytes) }.max()
      ?? 0
    XCTAssertLessThanOrEqual(lineageProofBytes + largestSend, Wire.paymentProofBudgetBytes)
    XCTAssertTrue((1...Wire.lineageProofCapBytes).contains(lineageProofBytes), "Ω cap")

    // The standalone frame {version, steps, lineage_verifying_key_digest, lineage_proof_bytes}
    // carries exactly this transcript.
    let frame = try VectorFrame(objectFrame(fixture, "KagemushaWalletVerifyingKeyAllowlistV1"))
    XCTAssertLessThanOrEqual(
      try objectFrame(fixture, "KagemushaWalletVerifyingKeyAllowlistV1").count,
      Wire.verifyingKeyAllowlistMaximumBytes)
    XCTAssertEqual(try allowlistTranscript(frame), transcript)

    // The vectors are self-consistent (defect d1): the relation identity and the signed
    // artifact manifest bind this computed digest, so the allowlist decodes against the
    // manifest; no separate stand-in digest exists.
    XCTAssertEqual(try hexData(string(vector, "manifest_verifying_key_set_digest_hex")), digest)
    XCTAssertNil(try object(fixture, "stand_ins")["verifying_key_set_digest_hex"])
    let relation = [UInt8](try digestBody(digests, "relation"))
    XCTAssertEqual(relation.count, 162)
    guard relation.count == 162 else { return }
    XCTAssertEqual(Data(relation[98..<130]), digest, "the relation binds the allowlist")
    let manifest = [UInt8](try signedBody(fixture, object: "artifact manifest"))
    XCTAssertEqual(manifest.count, KagemushaWalletSigningDomainV1.artifactManifest.transcriptBytes)
    guard manifest.count == 290 else { return }
    XCTAssertEqual(Data(manifest[34..<66]), try digestValue(digests, "relation"))
    XCTAssertEqual(Array(manifest[66..<162]), Array(relation[2..<98]), "manifest bindings")
    XCTAssertEqual(Data(manifest[162..<194]), digest, "the manifest binds the allowlist")
    XCTAssertEqual(Array(manifest[194..<226]), Array(relation[130..<162]), "artifact inventory")
    let manifestFrame = try VectorFrame(objectFrame(fixture, "KagemushaWalletArtifactManifestV1"))
    XCTAssertEqual(
      try manifestFrame.data(manifestFrame.field(manifestFrame.root, 0, 6)), digest,
      "the manifest frame binds the allowlist")

    // Every vectored package has exactly its selector's σ length and every Ω(pred) the
    // allowlist's transport length (defect d2): σ_send by Ω's mask, σ_recv by the statement's
    // blacklist bit, every other operation by its tag.
    let payment = try VectorFrame(envelopeFrame(fixture, "Payment"))
    let receive = try VectorFrame(envelopeFrame(fixture, "Credited::Receive"))
    let receiveEvidence = try receive.variant(receive.envelopeMessage().fields[2])
    let paymentObject = try VectorFrame(objectFrame(fixture, "KagemushaWalletPaymentV1"))
    let packageObject = try VectorFrame(objectFrame(fixture, "KagemushaWalletPackageV1"))
    let unloadClaim = try VectorFrame(objectFrame(fixture, "KagemushaWalletUnloadClaimV1"))
    let closeLoads = try VectorFrame(objectFrame(fixture, "KagemushaWalletCloseLoadsV1"))
    let feeClaim = try VectorFrame(objectFrame(fixture, "KagemushaWalletFeeClaimV1"))
    let activation = try VectorFrame(objectFrame(fixture, "KagemushaWalletActivationV1"))
    let packages: [(String, VectorFrame, Range<Int>)] = try [
      ("Payment envelope Send", payment, payment.envelopeMessage().fields[4]),
      ("Credited::Receive", receive, XCTUnwrap(receiveEvidence.fields.first)),
      ("Payment object Send", paymentObject, paymentObject.field(paymentObject.root, 4)),
      ("Receive package object", packageObject, packageObject.root),
      ("Unload claim", unloadClaim, unloadClaim.field(unloadClaim.root, 2)),
      ("Close loads Retiring", closeLoads, closeLoads.field(closeLoads.root, 3)),
      ("Fee claim Send", feeClaim, feeClaim.field(feeClaim.root, 1, 4)),
      ("Activation Bootstrap", activation, activation.field(activation.root, 3)),
    ]
    var tags = Set<UInt32>()
    var omegas: [(String, Data)] = []
    for (label, carrier, record) in packages {
      let proofs = try packageProofs(carrier, record)
      tags.insert(proofs.tag)
      XCTAssertEqual(
        lengths[UInt64(proofs.tag) << 32 | UInt64(proofs.mask)], proofs.sigma.count, "\(label) σ")
      assertSigmaStandIn(proofs.sigma, label)
      XCTAssertEqual(
        Self.lineageConsumingTags.contains(proofs.tag), proofs.omega != nil,
        "\(label) Ω(pred) slot")
      if let omega = proofs.omega {
        omegas.append((label, omega))
      }
    }
    XCTAssertEqual(tags, [Self.sendTag, Self.receiveTag, 6, 8, 1])
    // Ω carried alone: the Lineage message and the fold record.
    let lineage = try VectorFrame(envelopeFrame(fixture, "Lineage"))
    try omegas.append(
      ("Lineage envelope", omegaBytes(lineage, lineage.envelopeMessage().fields[1])))
    let fold = try VectorFrame(objectFrame(fixture, "KagemushaWalletFoldRecordV1"))
    try omegas.append(("fold record", omegaBytes(fold, fold.field(fold.root, 7))))
    for (label, omega) in omegas {
      XCTAssertEqual(omega.count - 320, lineageProofBytes, "\(label) Ω length")
      let transport = [UInt8](omega.dropFirst(320))
      XCTAssertTrue(
        transport.indices.allSatisfy { Int(transport[$0]) == ($0 + 7) % 251 }, "\(label) Ω rule")
    }
    // The CreditStatus Ω(h) has the same length under its own stand-in byte rule.
    let status = try VectorFrame(envelopeFrame(fixture, "Credited::Status"))
    let statusEvidence = try status.variant(status.envelopeMessage().fields[2])
    let statusOmega = try omegaBytes(
      status, status.field(XCTUnwrap(statusEvidence.fields.first), 4))
    XCTAssertEqual(statusOmega.count - 320, lineageProofBytes, "CreditStatus Ω(h) length")
    let statusTransport = [UInt8](statusOmega.dropFirst(320))
    XCTAssertTrue(
      statusTransport.indices.allSatisfy { Int(statusTransport[$0]) == ($0 + 11) % 251 },
      "Ω(h) rule")

    // The large-input proof digests pack these same lengths.
    let sendParts = try le32Parts(hexData(string(largeInput(fixture, "kgwprf_1"), "body_hex")))
    XCTAssertEqual(sendParts.count, 2)
    guard sendParts.count == 2 else { return }
    XCTAssertEqual(sendParts[0].count - 320, lineageProofBytes)
    let sendMask = readLE32([UInt8](sendParts[0]), at: 236)
    XCTAssertEqual(lengths[UInt64(Self.sendTag) << 32 | UInt64(sendMask)], sendParts[1].count)
    let receiveItems = try fieldElements(
      object(object(fixture, "field_encodings"), "receive_statement"), "items")
    let receiveMask = UInt32(try unsignedElement(receiveItems[11])) & Self.blacklistControl
    let receiveParts = try le32Parts(
      hexData(string(largeInput(fixture, "kgwstep1"), "body_hex")))
    XCTAssertEqual(receiveParts.count, 1)
    XCTAssertEqual(
      lengths[UInt64(Self.receiveTag) << 32 | UInt64(receiveMask)], receiveParts.first?.count)
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

/// Effect fields by operation tag; circuit hashes are one field element.
private let statementEffectLayouts: [UInt8: [TranscriptSlotV1]] = [
  1: [.digest, .digest],
  2: [.field, .integer(16), .integer(16), .integer(16)],
  3: [.field, .digest, .integer(16), .integer(16), .integer(16), .field, .integer(8), .integer(8)],
  4: [.field, .digest, .integer(16)],
  5: [.field, .field],
  6: [.field, .integer(16), .integer(16), .integer(16), .field],
  7: [.integer(1), .field, .integer(8)],
  8: [],
]

/// The 458-byte Request transcript hashes to 26 field elements, including its recorded blacklist.
private let requestBodyLayout: [TranscriptSlotV1] = [
  .integer(2), .digest, .digest, .digest, .digest, .digest, .digest, .integer(16), .field,
  .integer(16), .field, .integer(16), .integer(8), .field, .integer(8), .integer(8), .field, .field, .digest,
]

/// Re-derive the 26 field elements from the canonical statement record.
private func statementFieldElements(_ frame: VectorFrame, _ record: Range<Int>) throws -> [Data] {
  let fields = try frame.fields(record)
  guard fields.count == 14 else { throw WalletFixtureFailure.malformed("statement fields") }
  var items = [fieldInteger([UInt8](frame.data(fields[0])))]
  for index in [2, 1, 4] { items += fieldDigestLimbs(frame.data(fields[index])) }
  items.append(frame.data(fields[3]))
  for index in 5..<10 { items.append(fieldInteger([UInt8](frame.data(fields[index])))) }
  items.append(frame.data(fields[10]))
  for index in 11..<13 {
    items.append(try frame.data(frame.field(fields[index], 0)))
  }
  let effect = try frame.variant(fields[13])
  items.append(fieldInteger(le32(effect.tag)))
  guard let layout = statementEffectLayouts[UInt8(effect.tag)], layout.count == effect.fields.count else {
    throw WalletFixtureFailure.malformed("effect fields")
  }
  var effectItems: [Data] = []
  for (slot, field) in zip(layout, effect.fields) {
    let bytes = frame.data(field)
    switch slot {
    case .digest: effectItems += fieldDigestLimbs(bytes)
    case .field: effectItems.append(bytes)
    case .integer: effectItems.append(fieldInteger([UInt8](bytes)))
    }
  }
  guard effectItems.count <= 9 else { throw WalletFixtureFailure.malformed("effect elements") }
  return items + effectItems + Array(repeating: Data(count: 32), count: 9 - effectItems.count)
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

/// The current canonical state core and rest field layouts.
private let stateCoreLayout: [FrameSlotV1] = [
  .tag, .digest, .digest, .digest, .field, .integer, .integer, .integer, .integer, .integer, .integer, .field, .field, .field, .field, .field, .field, .field, .integer, .field, .integer, .integer, .field, .integer, .integer, .integer, .integer, .integer, .integer, .field
]
private let stateRestLayout: [FrameSlotV1] = [
  .integer, .field, .field, .field, .field, .integer, .field, .field
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

/// Order of two 32-byte little-endian integers: a σ-field value, or an account digest in limb
/// order `hi · 2^128 + lo` (owner answer A4). Negative, zero or positive.
private func compareLittleEndian(_ lhs: Data, _ rhs: Data) -> Int {
  let left = [UInt8](lhs)
  let right = [UInt8](rhs)
  precondition(left.count == 32 && right.count == 32)
  for index in stride(from: 31, through: 0, by: -1) where left[index] != right[index] {
    return left[index] < right[index] ? -1 : 1
  }
  return 0
}

/// The small integer one σ-field element encodes: its bytes 8 through 31 are zero.
private func unsignedElement(_ element: Data) throws -> UInt64 {
  let bytes = [UInt8](element)
  guard bytes.count == 32, bytes[8...].allSatisfy({ $0 == 0 }) else {
    throw WalletFixtureFailure.malformed("small element")
  }
  return readLE64(bytes, at: 0)
}

/// `value` is a Poseidon value of the native core: a canonical, nonzero σ-field value. Swift
/// never recomputes it.
private func assertPoseidonValue(
  _ value: Data,
  _ label: String,
  file: StaticString = #filePath,
  line: UInt = #line
) {
  XCTAssertEqual(value.count, 32, label, file: file, line: line)
  XCTAssertTrue(
    KagemushaWalletWireV1.isCanonicalFieldValue(value), label, file: file, line: line)
  XCTAssertNotEqual(value, Data(count: 32), label, file: file, line: line)
}

/// A labelled stand-in field value of seed `seed`: 31 bytes `seed`, then `seed & 0x3f`.
private func assertStandInField(
  _ value: Data,
  seed: UInt8,
  _ label: String,
  file: StaticString = #filePath,
  line: UInt = #line
) {
  XCTAssertEqual(
    value, Data(repeating: seed, count: 31) + Data([seed & 0x3f]), label, file: file, line: line)
  assertPoseidonValue(value, label, file: file, line: line)
}

/// A stand-in σ: non-empty, byte `i` is `i mod 251`.
private func assertSigmaStandIn(
  _ sigma: Data,
  _ label: String,
  file: StaticString = #filePath,
  line: UInt = #line
) {
  let bytes = [UInt8](sigma)
  XCTAssertFalse(bytes.isEmpty, label, file: file, line: line)
  XCTAssertTrue(
    bytes.indices.allSatisfy { Int(bytes[$0]) == $0 % 251 }, label, file: file, line: line)
}

/// The `LE32 len ‖ bytes` parts that make up `bytes` exactly.
private func le32Parts(_ bytes: Data) throws -> [Data] {
  let input = [UInt8](bytes)
  var parts: [Data] = []
  var offset = 0
  while offset < input.count {
    guard offset + 4 <= input.count else { throw WalletFixtureFailure.malformed("LE32 part") }
    let length = Int(readLE32(input, at: offset))
    offset += 4
    guard length <= input.count - offset else { throw WalletFixtureFailure.malformed("part") }
    parts.append(Data(input[offset..<(offset + length)]))
    offset += length
  }
  return parts
}

/// Exact leaf-opening transcript: key, value and next key, LE32 slot and 32 siblings (1,124).
private let leafOpeningBytes = 3 * 32 + 4 + 32 * 32

/// Exact empty-slot opening transcript: LE32 slot and 32 siblings (1,028).
private let emptySlotOpeningBytes = 4 + 32 * 32

/// One opened indexed-tree leaf `(key, value, next_key)` at `slot` with its siblings, height 0
/// first.
private struct LeafOpeningV1 {
  let key: Data
  let value: Data
  let nextKey: Data
  let slot: Int
  let siblings: [Data]
}

/// Empty-subtree values learned per height across openings: height 0 is the empty slot (zero),
/// height 1 the vectored empty subtree, and every other height must agree across openings.
private final class EmptySubtreesV1 {
  private var known: [Int: Data]

  init(heightOne: Data) {
    known = [0: Data(count: 32), 1: heightOne]
  }

  /// Heights whose empty subtree is known.
  var count: Int { known.count }

  /// Siblings of `slot` whose subtree lies entirely above `occupiedThrough` (the highest slot
  /// ever written) are the empty subtree of their height.
  func check(
    slot: Int,
    siblings: [Data],
    occupiedThrough: Int,
    label: String,
    file: StaticString,
    line: UInt
  ) {
    for (height, sibling) in siblings.enumerated() {
      let first = ((slot >> height) ^ 1) << height
      guard first > occupiedThrough else { continue }
      if let expected = known[height] {
        XCTAssertEqual(
          sibling, expected, "\(label) empty subtree at height \(height)", file: file, line: line)
      } else {
        known[height] = sibling
      }
    }
  }
}

/// The 32 canonical siblings of an opening `{slot, siblings}`, height 0 first.
private func openingSiblings(
  _ opening: [String: Any],
  label: String,
  file: StaticString,
  line: UInt
) throws -> [Data] {
  let siblings = try fieldElements(opening, "siblings")
  XCTAssertEqual(
    siblings.count, KagemushaWalletWireV1.indexedTreeDepth, "\(label) sibling count", file: file,
    line: line)
  for sibling in siblings {
    XCTAssertTrue(
      KagemushaWalletWireV1.isCanonicalFieldValue(sibling), label, file: file, line: line)
  }
  return siblings
}

/// Structural checks of one indexed-tree leaf opening `{leaf, opening, root_hex,
/// transcript_hex}` (owner answer A2): canonical key, value and next key with `next_key = 0` or
/// above the key; a Poseidon leaf and root; exactly 32 siblings; and its transcript `key ‖ value
/// ‖ next_key ‖ LE32 slot ‖ siblings`. With `empties`, siblings over subtrees entirely above
/// `occupiedThrough` are the empty subtree of their height.
private func checkedLeafOpening(
  _ vector: [String: Any],
  occupiedThrough: Int?,
  empties: EmptySubtreesV1?,
  label: String,
  file: StaticString = #filePath,
  line: UInt = #line
) throws -> LeafOpeningV1 {
  let leaf = try object(vector, "leaf")
  let opening = try object(vector, "opening")
  let key = try hexData(string(leaf, "key_hex"))
  let value = try hexData(string(leaf, "value_hex"))
  let nextKey = try hexData(string(leaf, "next_key_hex"))
  for item in [key, value, nextKey] {
    XCTAssertTrue(KagemushaWalletWireV1.isCanonicalFieldValue(item), label, file: file, line: line)
  }
  guard key.count == 32, nextKey.count == 32 else {
    throw WalletFixtureFailure.malformed("\(label) leaf width")
  }
  XCTAssertTrue(
    nextKey == Data(count: 32) || compareLittleEndian(key, nextKey) < 0,
    "\(label) next key above key", file: file, line: line)
  assertPoseidonValue(
    try hexData(string(leaf, "leaf_hex")), "\(label) leaf", file: file, line: line)
  assertPoseidonValue(
    try hexData(string(vector, "root_hex")), "\(label) root", file: file, line: line)
  let slot = try int(opening, "slot")
  let siblings = try openingSiblings(opening, label: label, file: file, line: line)
  var expected = key + value + nextKey
  expected.append(contentsOf: le32(UInt32(slot)))
  expected.append(siblings.reduce(Data(), +))
  let transcript = try hexData(string(vector, "transcript_hex"))
  XCTAssertEqual(transcript, expected, label, file: file, line: line)
  XCTAssertEqual(transcript.count, leafOpeningBytes, label, file: file, line: line)
  if let empties = empties, let occupiedThrough = occupiedThrough {
    empties.check(
      slot: slot, siblings: siblings, occupiedThrough: occupiedThrough, label: label, file: file,
      line: line)
  }
  return LeafOpeningV1(key: key, value: value, nextKey: nextKey, slot: slot, siblings: siblings)
}

/// Structural checks of one empty-slot opening `{opening, transcript_hex}` of `slot`: its
/// transcript `LE32 slot ‖ siblings`. Returns the siblings.
private func checkedEmptySlotOpening(
  _ vector: [String: Any],
  slot: Int,
  occupiedThrough: Int,
  empties: EmptySubtreesV1,
  label: String,
  file: StaticString = #filePath,
  line: UInt = #line
) throws -> [Data] {
  let opening = try object(vector, "opening")
  XCTAssertEqual(try int(opening, "slot"), slot, label, file: file, line: line)
  let siblings = try openingSiblings(opening, label: label, file: file, line: line)
  var expected = Data(le32(UInt32(slot)))
  expected.append(siblings.reduce(Data(), +))
  let transcript = try hexData(string(vector, "transcript_hex"))
  XCTAssertEqual(transcript, expected, label, file: file, line: line)
  XCTAssertEqual(transcript.count, emptySlotOpeningBytes, label, file: file, line: line)
  empties.check(
    slot: slot, siblings: siblings, occupiedThrough: occupiedThrough,
    label: "\(label) empty slot", file: file, line: line)
  return siblings
}

/// The low leaf `low` brackets the absent `key`: `low.key < key` and (`next = 0` or
/// `key < next`).
private func assertBrackets(
  _ low: LeafOpeningV1,
  _ key: Data,
  _ label: String,
  file: StaticString = #filePath,
  line: UInt = #line
) {
  guard key.count == 32 else { return XCTFail("\(label) key width", file: file, line: line) }
  XCTAssertNotEqual(key, Data(count: 32), "\(label) nonzero key", file: file, line: line)
  XCTAssertLessThan(
    compareLittleEndian(low.key, key), 0, "\(label) low key below", file: file, line: line)
  XCTAssertTrue(
    low.nextKey == Data(count: 32) || compareLittleEndian(key, low.nextKey) < 0,
    "\(label) next key above", file: file, line: line)
}

/// Ω bytes of a `KagemushaWalletLineageV1 {public, proof}` record: the 320-byte public
/// transcript followed by the transport proof bytes.
private func omegaBytes(_ frame: VectorFrame, _ record: Range<Int>) throws -> Data {
  let fields = try frame.fields(record)
  guard fields.count == 2 else { throw WalletFixtureFailure.malformed("lineage fields") }
  return try lineagePublicTranscript(frame, fields[0]) + frame.byteVector(fields[1])
}

/// σ selector, σ bytes and Ω(pred) bytes of one Package record `{version, statement, lineage
/// slot, step_proof, receipt}`: the statement's effect tag, its σ selector mask (Send:
/// `enabled_controls`; Receive: the blacklist bit; otherwise 0), σ and Ω(pred) when the slot is
/// Present.
private func packageProofs(
  _ frame: VectorFrame,
  _ record: Range<Int>
) throws -> (tag: UInt32, mask: UInt32, sigma: Data, omega: Data?) {
  let fields = try frame.fields(record)
  guard fields.count == 5 else { throw WalletFixtureFailure.malformed("package fields") }
  let statement = try frame.fields(fields[1])
  guard statement.count == 14, statement[13].count >= 4, statement[8].count == 4 else {
    throw WalletFixtureFailure.malformed("statement fields")
  }
  let tag = readLE32(frame.payload, at: statement[13].lowerBound)
  let controls = readLE32(frame.payload, at: statement[8].lowerBound)
  let slot = try frame.variant(fields[2])
  let omega: Data?
  switch slot.tag {
  case 0 where slot.fields.isEmpty:
    omega = nil
  case 1 where slot.fields.count == 1:
    omega = try omegaBytes(frame, slot.fields[0])
  default:
    throw WalletFixtureFailure.malformed("lineage slot")
  }
  let sigma = try frame.byteVector(frame.field(fields[3], 0))
  let mask: UInt32
  switch tag {
  case 3: mask = controls
  case 4: mask = controls & 1
  default: mask = 0
  }
  return (tag, mask, sigma, omega)
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

/// The ECDSA equation as CryptoKit checks it over `message` (hash `SHA-256(message)`), scalars
/// taken as they are (high S accepted).
private func cryptoKitEquation(_ publicKey: Data, _ message: Data, _ signature: Data) -> Bool {
  guard
    let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
    let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
  else {
    return false
  }
  return key.isValidSignature(parsed, for: message)
}

/// The ECDSA equation as CryptoKit checks it over a precomputed SHA-256 `digest`.
private func cryptoKitDigestEquation(
  _ publicKey: Data,
  _ digest: SHA256.Digest,
  _ signature: Data
) -> Bool {
  guard
    let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
    let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
  else {
    return false
  }
  return key.isValidSignature(parsed, for: digest)
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

/// Canonical frame of the first object vector of `type` (and `variant`, when given).
private func objectFrame(
  _ fixture: [String: Any],
  _ type: String,
  variant: String? = nil
) throws -> Data {
  guard
    let vector = try objects(fixture, "objects").first(where: {
      $0["type"] as? String == type && (variant == nil || $0["variant"] as? String == variant)
    })
  else {
    throw WalletFixtureFailure.malformed(type)
  }
  return try hexData(string(vector, "canonical_hex"))
}

/// Signing domain of one signature vector.
private func signingDomain(_ vector: [String: Any]) throws -> KagemushaWalletSigningDomainV1 {
  let label = try string(vector, "domain")
  guard let domain = KagemushaWalletSigningDomainV1(rawValue: label) else {
    throw WalletFixtureFailure.malformed(label)
  }
  return domain
}

/// The signature vector of `label`.
private func signatureVector(_ fixture: [String: Any], object label: String) throws -> [String: Any]
{
  guard
    let vector = try objects(fixture, "signatures").first(where: {
      $0["object"] as? String == label
    })
  else {
    throw WalletFixtureFailure.malformed(label)
  }
  return vector
}

/// Signed transcript of the signature vector of `label`, of its domain's exact length.
private func signedBody(_ fixture: [String: Any], object label: String) throws -> Data {
  let vector = try signatureVector(fixture, object: label)
  let transcript = try hexData(string(vector, "transcript_hex"))
  guard try signingDomain(vector).transcriptBytes == transcript.count else {
    throw WalletFixtureFailure.malformed("\(label) transcript length")
  }
  return transcript
}

/// The large-input `P_bytes` digest vectors under `domain`, in vector order.
private func largeInputs(_ fixture: [String: Any], _ domain: String) throws -> [[String: Any]] {
  try objects(object(fixture, "poseidon"), "large_input_digests").filter {
    try string($0, "domain") == domain
  }
}

/// The single large-input `P_bytes` digest vector under `domain`.
private func largeInput(_ fixture: [String: Any], _ domain: String) throws -> [String: Any] {
  let rows = try largeInputs(fixture, domain)
  guard rows.count == 1 else { throw WalletFixtureFailure.malformed(domain) }
  return rows[0]
}

/// SEC1 public key of the fixed key `name`.
private func fixedKey(_ fixture: [String: Any], _ name: String) throws -> Data {
  guard
    let vector = try objects(fixture, "keys").first(where: { $0["name"] as? String == name })
  else {
    throw WalletFixtureFailure.malformed(name)
  }
  return try hexData(string(vector, "public_key_hex"))
}
