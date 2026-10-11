import XCTest
import CryptoKit
@testable import NoritoDemo

final class PosManifestTests: XCTestCase {
  private func manifestData() throws -> Data {
    let thisFile = URL(fileURLWithPath: #filePath)
    let repositoryRoot = thisFile
      .deletingLastPathComponent() // Tests
      .deletingLastPathComponent() // NoritoDemo
      .deletingLastPathComponent() // ios
      .deletingLastPathComponent() // examples
      .deletingLastPathComponent() // repository
    let manifestUrl = repositoryRoot
      .appendingPathComponent("fixtures/sdk/pos/manifest_v1.json")
    return try Data(contentsOf: manifestUrl)
  }

  func testManifestParsesAndVerifies() throws {
    let manifest = try PosManifestLoader.parse(data: try manifestData())
    XCTAssertEqual(manifest.manifestId, "pos-retail-v1")
    XCTAssertEqual(manifest.sequence, 7)
    XCTAssertEqual(manifest.backendRoots.count, 2)
  }

  func testSharedFixtureActivatesEveryRequiredTrustRoot() throws {
    // The required roles and the shared signed fixture must change together.
    let manifest = try PosManifestLoader.parse(data: try manifestData())
    let inWindow = Date(timeIntervalSince1970: TimeInterval(manifest.validFromMs) / 1000.0)
    let status = PosManifestStatus.from(manifest: manifest, now: inWindow)
    XCTAssertTrue(status.dualStatusHealthy, status.dualStatusLabel)
    XCTAssertTrue(status.backendRoots.allSatisfy(\.active))
  }

  func testTamperedSignatureFails() throws {
    let envelope = try fixtureEnvelope()
    var signature = envelope["operator_signature"]!
    signature.replaceSubrange(signature.startIndex...signature.startIndex,
                              with: signature.first == "0" ? "1" : "0")
    let tampered = envelopeData(payload: envelope["payload_base64"]!, signature: signature)
    XCTAssertThrowsError(try PosManifestLoader.parse(data: tampered)) { error in
      let description = (error as NSError).localizedDescription.lowercased()
      XCTAssertTrue(description.contains("signature"))
    }
  }

  func testDisplayedFieldSubstitutionRequiresANewSignature() throws {
    let envelope = try fixtureEnvelope()
    let payload = String(data: Data(base64Encoded: envelope["payload_base64"]!)!, encoding: .utf8)!
    let changed = payload.replacingOccurrences(of: "pos-retail-v1", with: "substituted-manifest")
    XCTAssertNotEqual(payload, changed)
    let bytes = envelopeData(payload: Data(changed.utf8).base64EncodedString(),
                             signature: envelope["operator_signature"]!)
    XCTAssertThrowsError(try PosManifestLoader.parse(data: bytes))
  }

  func testUnknownAndDuplicateSignedPayloadFieldsAreRejected() throws {
    let envelope = try fixtureEnvelope()
    let payload = String(data: Data(base64Encoded: envelope["payload_base64"]!)!, encoding: .utf8)!
    // Public RFC8032 testvector1. Each rejected payload has a genuine valid
    // signature, so failure exercises canonical field admission, not bad crypto.
    let seed = Data(hexString: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")!
    let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    let variants = [
      payload.replacingOccurrences(of: "\"sequence\":7", with: "\"sequence\":7,\"sequence\":7"),
      payload.replacingOccurrences(of: "\"label\":\"torii-admission\"",
                                   with: "\"label\":\"torii-admission\",\"label\":\"torii-admission\""),
      payload.replacingOccurrences(of: "\"sequence\":7", with: "\"foreign_field\":true,\"sequence\":7")
    ]
    for changed in variants {
      XCTAssertNotEqual(changed, payload)
      let bytes = Data(changed.utf8)
      let signature = try key.signature(for: bytes)
      XCTAssertTrue(key.publicKey.isValidSignature(signature, for: bytes))
      XCTAssertThrowsError(try PosManifestLoader.parse(data: envelopeData(
        payload: bytes.base64EncodedString(),
        signature: signature.map { String(format: "%02x", $0) }.joined()
      )))
    }
  }

  func testUnsignedOuterFieldsAndDuplicateEnvelopeKeysAreRejected() throws {
    let original = String(data: try manifestData(), encoding: .utf8)!
    for changed in [
      original.replacingOccurrences(of: "{", with: "{\"manifest_id\":\"substituted\",", range: original.startIndex..<original.index(after: original.startIndex)),
      original.replacingOccurrences(of: "{", with: "{\"payload_base64\":\"\",", range: original.startIndex..<original.index(after: original.startIndex))
    ] {
      XCTAssertNotEqual(original, changed)
      XCTAssertThrowsError(try PosManifestLoader.parse(data: Data(changed.utf8)))
    }
  }

  private func fixtureEnvelope() throws -> [String: String] {
    try JSONDecoder().decode([String: String].self, from: manifestData())
  }

  private func envelopeData(payload: String, signature: String) -> Data {
    Data("{\"operator_signature\":\"\(signature)\",\"payload_base64\":\"\(payload)\"}\n".utf8)
  }
}
