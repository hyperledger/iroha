import Foundation
import XCTest
@testable import IrohaSwift

final class AccountControllerFinalV1Tests: XCTestCase {
  func testCanonicalAccountParsersRejectSurroundingUnicodeWhitespace() throws {
    let literal = "sorauﾛ1P2PMｲbjRｦ2jrLFﾁｽｸFjjBヱYﾜｴ3ﾋNRjﾌｸﾆｺNXcfﾒXSKXAW"
    let parsers: [(String) throws -> Void] = [
      { _ = try AccountAddress.parseEncoded($0) },
      { _ = try AccountAddress.fromI105($0) },
      { _ = try AccountAddress.parseCanonicalI105($0) },
      { _ = try AccountAddress.inspectI105NetworkPrefix($0) },
    ]
    for whitespace in [" ", "\t", "\r\n", "\u{00a0}", "\u{2003}", "\u{202f}", "\u{3000}"] {
      for invalid in [whitespace + literal, literal + whitespace] {
        for parse in parsers {
          XCTAssertThrowsError(try parse(invalid)) { error in
            XCTAssertEqual(error as? AccountAddressError, .unsupportedAddressFormat)
          }
        }
      }
    }
  }

  func testPublicAccountConstructionRequiresNativeAdmission() throws {
    let key = try keys(1)[0]
    if NoritoNativeBridge.shared.isAccountAddressCodecAvailable {
      XCTAssertNoThrow(try AccountAddress.fromAccount(publicKey: key))
    } else {
      XCTAssertThrowsError(try AccountAddress.fromAccount(publicKey: key)) { error in
        XCTAssertEqual(error as? AccountAddressError, .nativeBridgeUnavailable)
      }
      XCTAssertThrowsError(try MultisigPolicyBuilder().setThreshold(1)
        .addMember(algorithm: .ed25519, weight: 1, publicKey: key).build()) { error in
        XCTAssertEqual(error as? AccountAddressError, .nativeBridgeUnavailable)
      }
    }
  }

  func testNativeAdmissionRejectsMalformedCurvePoints() throws {
    XCTAssertTrue(NoritoNativeBridge.shared.isAccountAddressCodecAvailable,
                  "The final SDK requires the real ABI-30 address validator.")
    var cases: [(UInt8, Data)] = [
      (1, Data([1]) + Data(repeating: 0, count: 31)),
      (1, Data(repeating: 255, count: 32)),
      (4, Data([2]) + Data(repeating: 255, count: 32)),
      (3, Data(repeating: 255, count: 48)),
      (5, Data(repeating: 255, count: 96)),
      (15, Data([0, 0, 4]) + Data(repeating: 255, count: 64)),
    ]
    for curve: UInt8 in [10, 11, 12, 13, 14] {
      cases.append((curve, Data(repeating: 255, count: curve >= 13 ? 128 : 64)))
    }
    for (curve, key) in cases {
      let canonical = Data([2, 0, curve, UInt8(key.count)]) + key
      XCTAssertThrowsError(try AccountAddress.fromCanonicalBytes(canonical)) { error in
        XCTAssertEqual(error as? AccountAddressError, .invalidPublicKey)
      }
    }
  }

  func testAllRustOwnedFullControllerFixturesMatchCanonicalWire() throws {
    let url = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent()
      .appendingPathComponent("fixtures/account/multisig_wire_v1.json")
    let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    XCTAssertEqual(root["schema"] as? String, "iroha.account.multisig-wire.v1")
    XCTAssertEqual(root["chain_discriminant"] as? Int, 753)
    let positives = try XCTUnwrap(root["positive"] as? [[String: Any]])
    XCTAssertEqual(positives.count, 16)
    for item in positives {
      let name = try XCTUnwrap(item["name"] as? String)
      XCTAssertEqual(item["layout_flags"] as? Int, 2, name)
      let literal = try XCTUnwrap(item["i105"] as? String)
      let address = try AccountAddress.parseEncoded(literal, expectedPrefix: 753)
      XCTAssertEqual(try AccountAddress.fromI105(literal, expectedPrefix: 753).canonicalBytes(),
        try address.canonicalBytes(), name)
      let canonical = try XCTUnwrap(Data(hexString: XCTUnwrap(item["canonical_address_hex"] as? String)))
      XCTAssertEqual(try address.canonicalBytes(), canonical, name)
      let expected = try XCTUnwrap(Data(hexString: XCTUnwrap(item["account_id_payload_hex"] as? String)))
      XCTAssertEqual(try CanonicalNorito.encodeCompactAccountId(literal), expected, name)
      XCTAssertTrue(AccountAddress.isCanonicalCompactNoritoAccountControllerPayload(expected), name)
      let frame = try XCTUnwrap(noritoDecodeFrame(Data(hexString: XCTUnwrap(item["account_id_frame_hex"] as? String))!))
      XCTAssertEqual(frame.header.flags, 2, name); XCTAssertEqual(frame.payload, expected, name)
      if let policy = item["policy"] as? [String: Any] {
        let parsed = try XCTUnwrap(address.multisigPolicyInfo())
        XCTAssertEqual(Int(parsed.version), policy["version"] as? Int, name)
        XCTAssertEqual(Int(parsed.threshold), policy["threshold"] as? Int, name)
        let members = try XCTUnwrap(policy["members"] as? [[String: Any]])
        XCTAssertEqual(parsed.members.count, members.count, name)
        for index in members.indices {
          XCTAssertEqual(parsed.members[index].algorithm, members[index]["algorithm"] as? String, name)
          XCTAssertEqual(Int(parsed.members[index].weight), members[index]["weight"] as? Int, name)
          XCTAssertEqual(Data(hexString: String(parsed.members[index].publicKeyHex.dropFirst(2))),
            Data(hexString: try XCTUnwrap(members[index]["public_key_hex"] as? String)), name)
        }
      } else { XCTAssertNil(try address.multisigPolicyInfo(), name) }
    }
    let negatives = try XCTUnwrap(root["negative"] as? [[String: Any]])
    XCTAssertEqual(negatives.count, 7)
    for item in negatives {
      let name = try XCTUnwrap(item["name"] as? String)
      XCTAssertEqual(item["layout_flags"] as? Int, 2, name)
      let payload = try XCTUnwrap(Data(hexString: XCTUnwrap(item["account_id_payload_hex"] as? String)))
      XCTAssertFalse(AccountAddress.isCanonicalCompactNoritoAccountControllerPayload(payload), name)
    }
  }

  func testAccountEncodingAlwaysRequiresCanonicalController() throws {
    let address = try AccountAddress.fromAccount(publicKey: keys(1)[0])
    let literal = try address.toI105(networkPrefix: AccountId.defaultNetworkPrefix)
    XCTAssertEqual(try CanonicalNorito.encodeAccountId(literal), try address.noritoAccountControllerPayload())
    for invalid in ["alice", "alice@wonderland.sora", "0x1234", literal + " ", " " + literal] {
      XCTAssertThrowsError(try CanonicalNorito.encodeAccountId(invalid), invalid)
      XCTAssertThrowsError(try CanonicalNorito.encodeCompactAccountId(invalid), invalid)
    }
  }

  func testAddressRejectsRetiredCountAndNoncanonicalMultisigPolicies() throws {
    let publicKeys = try keys(2)
    let canonical = try addressBytes(threshold: 2, members: [(publicKeys[0], 1), (publicKeys[1], 2)])
    XCTAssertNoThrow(try AccountAddress.fromCanonicalBytes(canonical))
    let invalidMembers: [[(Data, UInt16)]] = [
      [(publicKeys[1], 1), (publicKeys[0], 1)],
      [(publicKeys[0], 1), (publicKeys[0], 2)],
      [(publicKeys[0], 0)],
    ]
    for members in invalidMembers {
      XCTAssertThrowsError(try AccountAddress.fromCanonicalBytes(addressBytes(threshold: 1, members: members)))
    }
    XCTAssertThrowsError(try AccountAddress.fromCanonicalBytes(addressBytes(threshold: 2, members: [(publicKeys[0], 1)])))
    var invalid = canonical; invalid[2] = 2
    XCTAssertThrowsError(try AccountAddress.fromCanonicalBytes(invalid))
    invalid = try addressBytes(threshold: 1, members: [(publicKeys[0], 1)])
    invalid.remove(at: 5)
    XCTAssertThrowsError(try AccountAddress.fromCanonicalBytes(invalid))
    // A forged large count must fail before reserving the advertised vector.
    XCTAssertThrowsError(try AccountAddress.fromCanonicalBytes(Data([0x0a, 1, 1, 0, 1, 255, 255])))
  }

  func testFullU16CountRetainsAll256Members() throws {
    let publicKeys = try keys(256)
    let members = publicKeys.map { ($0, UInt16(1)) }
    let canonical = try addressBytes(threshold: 256, members: members)
    let address = try AccountAddress.fromCanonicalBytes(canonical)
    XCTAssertEqual(Array(canonical[5..<7]), [1, 0])
    let compact = try address.compactNoritoAccountControllerPayload()
    XCTAssertTrue(AccountAddress.isCanonicalCompactNoritoAccountControllerPayload(compact))
    var outer = CanonicalNoritoReader(data: compact)
    XCTAssertEqual(try outer.readUInt32LE(), 1)
    var policy = CanonicalNoritoReader(data: try outer.readCompactField())
    _ = try policy.readCompactField(); _ = try policy.readCompactField()
    var encodedMembers = CanonicalNoritoReader(data: try policy.readCompactField())
    XCTAssertEqual(try encodedMembers.readUInt64LE(), 256)
    let builder = MultisigPolicyBuilder().setThreshold(256)
    for key in publicKeys.reversed() { builder.addMember(algorithm: .ed25519, weight: 1, publicKey: key) }
    let built = try builder.build()
    XCTAssertEqual(built.members.map(\.publicKey), publicKeys)
    XCTAssertEqual(built.threshold, 256)
  }

  func testBuilderRejectsInvalidPolicyAndCanonicalizesOnlyInputOrder() throws {
    let publicKeys = try keys(2)
    let build: (UInt8, UInt16, [(Data, UInt16)]) throws -> MultisigPolicy = { version, threshold, members in
      let builder = MultisigPolicyBuilder().setVersion(version).setThreshold(threshold)
      for (key, weight) in members { builder.addMember(algorithm: .ed25519, weight: weight, publicKey: key) }
      return try builder.build()
    }
    let invalidPolicies: [(UInt8, UInt16, [(Data, UInt16)])] = [
      (2, 1, [(publicKeys[0], 1)]), (1, 0, [(publicKeys[0], 1)]),
      (1, 2, [(publicKeys[0], 1)]), (1, 1, [(publicKeys[0], 0)]),
      (1, 1, [(publicKeys[0], 1), (publicKeys[0], 2)]),
    ]
    for (version, threshold, members) in invalidPolicies { XCTAssertThrowsError(try build(version, threshold, members)) }
    let first = try build(1, 2, [(publicKeys[0], 1), (publicKeys[1], 2)])
    let second = try build(1, 2, [(publicKeys[1], 2), (publicKeys[0], 1)])
    XCTAssertEqual(first.ctap2Cbor, second.ctap2Cbor)
    XCTAssertEqual(first.digestBlake2b256, second.digestBlake2b256)
    XCTAssertNotEqual(first.ctap2Cbor, try build(1, 1, [(publicKeys[0], 1), (publicKeys[1], 2)]).ctap2Cbor)
    XCTAssertNotEqual(first.ctap2Cbor, try build(1, 2, [(publicKeys[0], 2), (publicKeys[1], 1)]).ctap2Cbor)
  }

  func testCompactControllerReencodingUsesU16CountAcrossByteBoundary() throws {
    XCTAssertTrue(NoritoNativeBridge.shared.isAccountAddressCodecAvailable,
                  "The count regression requires the real ABI-30 address validator.")
    let publicKeys = try keys(256)
    for count in [1, 2, 255, 256] {
      let members = publicKeys.prefix(count).map { ($0, UInt16(1)) }
      let canonical = try addressBytes(threshold: UInt16(count), members: members)
      XCTAssertEqual(Array(canonical[5..<7]), [UInt8(count >> 8), UInt8(count & 255)])
      let address = try AccountAddress.fromCanonicalBytes(canonical)
      let compact = try address.compactNoritoAccountControllerPayload()
      // This path constructs a fresh address with no raw-byte cache, then invokes
      // ControllerPayload.encode and the native canonical validator.
      XCTAssertTrue(AccountAddress.isCanonicalCompactNoritoAccountControllerPayload(compact),
                    "member count \(count)")
      XCTAssertEqual(try address.canonicalBytes(), canonical)
    }
  }

  func testCompactControllerRejectsEmptyOversizedAndTruncatedMemberCounts() {
    XCTAssertTrue(NoritoNativeBridge.shared.isAccountAddressCodecAvailable,
                  "The final SDK requires the real ABI-30 address validator.")
    for count: UInt64 in [0, 65_535, 65_536, UInt64.max] {
      var members = CompactNoritoWriter()
      members.writeUInt64LE(count)
      var policy = CompactNoritoWriter()
      policy.writeField(Data([1]))
      policy.writeField(Data([1, 0]))
      policy.writeField(members.data)
      var controller = CompactNoritoWriter()
      controller.writeUInt32LE(1)
      controller.writeField(policy.data)
      XCTAssertFalse(AccountAddress.isCanonicalCompactNoritoAccountControllerPayload(controller.data),
                     "advertised member count \(count) without members")
    }
  }

  private func keys(_ count: Int) throws -> [Data] {
    try (1...count).map { index in
      var seed = Data(repeating: 0, count: 32)
      seed[0] = UInt8(index & 255); seed[1] = UInt8(index >> 8)
      return try Keypair(privateKeyBytes: seed).publicKey
    }.sorted { $0.lexicographicallyPrecedes($1) }
  }

  private func addressBytes(threshold: UInt16, members: [(Data, UInt16)]) throws -> Data {
    var bytes = Data([0x0a, 1, 1])
    func append(_ value: UInt16) { bytes.append(UInt8(value >> 8)); bytes.append(UInt8(value & 255)) }
    append(threshold); append(UInt16(members.count))
    for (key, weight) in members {
      bytes.append(1); append(weight); append(UInt16(key.count)); bytes.append(key)
    }
    return bytes
  }
}
