import CryptoKit
import Foundation
import XCTest
@testable import IrohaSwift

/// Actual C DATA decoding only. The Rust vector deliberately contains no valid BLS certificate.
/// Success here grants no finality, wallet admission, signature or monetary completion.
final class KagemushaWalletLoadOriginalNativeV1Tests: XCTestCase {
  private struct Fixture {
    let selection: ToriiKagemushaWalletLoadSelectionV1
    let receipt: Data
    let finality: Data
    let network: NetworkId

    static func read() throws -> Self {
      var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      var url: URL?
      for _ in 0..<8 {
        let candidate = directory.appendingPathComponent("fixtures/kagemusha/wallet_v1_vectors.json")
        if FileManager.default.fileExists(atPath: candidate.path) { url = candidate; break }
        directory.deleteLastPathComponent()
      }
      let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: XCTUnwrap(url))) as? [String: Any])
      let objects = try XCTUnwrap(root["objects"] as? [[String: Any]])
      func original(_ type: String, standIn: Bool) throws -> Data {
        let matches = objects.filter { $0["type"] as? String == type }
        XCTAssertEqual(matches.count, 1)
        let row = try XCTUnwrap(matches.first)
        XCTAssertEqual(try XCTUnwrap(row["stand_in_proof"] as? Bool), standIn)
        return try hex(XCTUnwrap(row["canonical_hex"] as? String))
      }
      let ordinary = try XCTUnwrap(root["ordinary_load_receipt"] as? [String: Any])
      let transcript = try hex(XCTUnwrap(ordinary["transcript_hex"] as? String))
      // Rust's explicit fixed receipt transcript, not a guessed Norito payload layout.
      XCTAssertEqual(transcript.count, 282)
      guard transcript.count == 282 else { throw KagemushaWalletErrorV1.invalidInput }
      XCTAssertEqual(transcript.prefix(2), Data([1, 0]))
      XCTAssertEqual(transcript.subdata(in: 242..<250), Data([42, 0, 0, 0, 0, 0, 0, 0]))
      return try Self(selection: .init(schemeID: transcript.subdata(in: 2..<34),
        walletID: transcript.subdata(in: 66..<98), requestID: transcript.subdata(in: 98..<130)),
        receipt: original("KagemushaWalletLoadReceiptV1", standIn: false),
        finality: original("KagemushaWalletLoadFinalityV1", standIn: true),
        network: NetworkId(bytes: Data(repeating: 0x41, count: 32)))
    }

    func issuance(selection selected: ToriiKagemushaWalletLoadSelectionV1? = nil,
      payerSeed: UInt8 = 0x5b, receipt original: Data? = nil) throws -> ToriiKagemushaWalletLoadIssuanceOriginalV1 {
      let selected = selected ?? selection
      // Same 32-byte Ed25519 seed as Rust vectors_tests::BENEFICIARY_SEED. This is test DATA.
      let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: payerSeed, count: 32))
      let payer = try AccountAddress.fromAccount(publicKey: key.publicKey.rawRepresentation)
        .toI105(networkPrefix: AccountId.defaultNetworkPrefix)
      XCTAssertTrue(payer.unicodeScalars.contains { $0.value > 0x7f }, "exercise canonical I105 kana")
      let url = try XCTUnwrap(URL(string: "https://example.test" + selected.path))
      let response = try XCTUnwrap(HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil,
        headerFields: ["Content-Type": "application/x-norito"]))
      // Canned transport DATA; no HTTP server or wallet is authenticated by this fixture.
      return try .init(selection: selected, payerAccountID: payer, networkID: network,
        expectedURL: url, response: response, bytes: original ?? receipt)
    }
  }

  func testPublicDecodeRetainsCanonicalKanaPayerAndExactNonproofDataThroughC() throws {
    let fixture = try Fixture.read(), issuance = try fixture.issuance()
    var finality = fixture.finality
    let value = try KagemushaWalletLoadOriginalV1.decode(issuance: issuance, finalityOriginal: finality)
    XCTAssertEqual(value.blockHeight, 42)
    XCTAssertEqual(value.networkID, fixture.network)
    XCTAssertEqual(value.payerAccountID, issuance.payerAccountID)
    XCTAssertEqual(value.selection.schemeID, fixture.selection.schemeID)
    XCTAssertEqual(value.selection.walletID, fixture.selection.walletID)
    XCTAssertEqual(value.selection.requestID, fixture.selection.requestID)
    XCTAssertEqual(value.requestID, fixture.selection.requestID)
    XCTAssertEqual(value.receiptOriginal, fixture.receipt)
    XCTAssertEqual(value.finalityOriginal, fixture.finality)
    finality[0] ^= 1
    var returnedReceipt = value.receiptOriginal, returnedFinality = value.finalityOriginal
    returnedReceipt[0] ^= 1; returnedFinality[0] ^= 1
    XCTAssertEqual(value.receiptOriginal, fixture.receipt)
    XCTAssertEqual(value.finalityOriginal, fixture.finality)
  }

  func testPublicDecodeRejectsEachForeignReadIdentityThroughC() throws {
    let fixture = try Fixture.read()
    let ids = [fixture.selection.schemeID, fixture.selection.walletID, fixture.selection.requestID]
    for index in ids.indices {
      var changed = ids
      changed[index][0] ^= 1
      let selection = try ToriiKagemushaWalletLoadSelectionV1(schemeID: changed[0], walletID: changed[1], requestID: changed[2])
      let issuance = try fixture.issuance(selection: selection)
      assertNativeInvalid { try KagemushaWalletLoadOriginalV1.decode(issuance: issuance, finalityOriginal: fixture.finality) }
    }
    let foreignPayer = try fixture.issuance(payerSeed: 0x5c)
    assertNativeInvalid { try KagemushaWalletLoadOriginalV1.decode(issuance: foreignPayer, finalityOriginal: fixture.finality) }
  }

  func testPublicDecodeRejectsTrailingReceiptAndFinalityThroughC() throws {
    let fixture = try Fixture.read()
    let trailingReceipt = try fixture.issuance(receipt: fixture.receipt + Data([0]))
    assertNativeInvalid { try KagemushaWalletLoadOriginalV1.decode(issuance: trailingReceipt, finalityOriginal: fixture.finality) }
    let issuance = try fixture.issuance()
    assertNativeInvalid { try KagemushaWalletLoadOriginalV1.decode(issuance: issuance, finalityOriginal: fixture.finality + Data([0])) }
  }

  private func assertNativeInvalid(_ action: () throws -> KagemushaWalletLoadOriginalV1,
    file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertThrowsError(try action(), file: file, line: line) { error in
      XCTAssertEqual(error as? KagemushaWalletErrorV1, .native(status: -1, reason: -1, platformCode: 0), file: file, line: line)
    }
  }
}

private func hex(_ text: String) throws -> Data {
  guard text.count.isMultiple(of: 2) else { throw KagemushaWalletErrorV1.invalidInput }
  var result = Data(); result.reserveCapacity(text.count / 2)
  var index = text.startIndex
  while index < text.endIndex {
    let next = text.index(index, offsetBy: 2)
    guard let byte = UInt8(text[index..<next], radix: 16) else { throw KagemushaWalletErrorV1.invalidInput }
    result.append(byte); index = next
  }
  return result
}
