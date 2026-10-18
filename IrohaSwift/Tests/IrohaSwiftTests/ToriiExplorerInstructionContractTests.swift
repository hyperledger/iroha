import CryptoKit
import Foundation
import XCTest
@testable import IrohaSwift

// Fixtures use the same current Rust wire schema as explorer_history.rs. These
// helpers author complete frames; no retired JSON instruction representation is
// accepted by the production decoder.
func explorerAccountFixture(seed: UInt8) throws -> String {
    let keypair = try Keypair(privateKeyBytes: Data(repeating: seed, count: 32))
    return try AccountAddress.fromAccount(publicKey: keypair.publicKey)
        .toI105(networkPrefix: AccountId.defaultNetworkPrefix)
}

func explorerInstructionBoxFixture(frame: Data, wireId: String) throws -> String {
    let box: [String: String] = [
        "wire_id": wireId,
        "framed_sha256": SHA256.hash(data: frame).map { String(format: "%02x", $0) }.joined(),
        "instruction": frame.base64EncodedString(),
    ]
    return String(decoding: try JSONSerialization.data(withJSONObject: box, options: [.sortedKeys]), as: UTF8.self)
}

func explorerInstructionFixtureFrame(wireId: String, schema: String, payload: Data) -> Data {
    let inner = noritoEncode(typeName: schema, payload: payload, flags: NoritoHeader.compactLen)
    var pair = CompactNoritoWriter()
    pair.writeField(CompactNorito.encodeString(wireId))
    pair.writeField(CanonicalNorito.encodeBytesVec(inner))
    return noritoEncode(typeName: "(alloc::string::String, alloc::vec::Vec<u8>)",
                        payload: pair.data, flags: NoritoHeader.compactLen)
}

func explorerTransferBoxFixture(sourceAssetId: String, destination: String, amount: String,
                                kind: String = "Transfer") throws -> String {
    try explorerTransferBoxFixture(sourceAssetId: sourceAssetId, destination: destination,
        quantityPayload: CanonicalNorito.encodeCompactQuantity(amount), kind: kind)
}

func explorerTransferBoxFixture(sourceAssetId: String, destination: String, quantityPayload: Data,
                                kind: String = "Transfer") throws -> String {
    let parts = sourceAssetId.split(separator: "#", omittingEmptySubsequences: false)
    guard parts.count >= 2 else { throw ToriiClientError.invalidPayload("fixture requires a full AssetId") }
    var source = CompactNoritoWriter()
    source.writeField(try CanonicalNorito.encodeCompactAccountId(String(parts[1])))
    source.writeField(try CanonicalNorito.encodeCompactAssetDefinitionId(String(parts[0])))
    var scope = CompactNoritoWriter()
    if parts.count == 3 {
        scope.writeUInt32LE(1)
        scope.writeField(CompactNorito.encodeUInt64(UInt64(parts[2].dropFirst("dataspace:".count))!))
    } else {
        scope.writeUInt32LE(0)
    }
    source.writeField(scope.data)
    var body = CompactNoritoWriter()
    if kind == "Transfer" { body.writeField(source.data) }
    body.writeField(quantityPayload)
    body.writeField(kind == "Transfer"
        ? try CanonicalNorito.encodeCompactAccountId(destination) : source.data)
    var payload = CompactNoritoWriter()
    payload.writeUInt32LE(kind == "Transfer" ? 2 : 0)
    payload.writeField(body.data)
    let wireId = "iroha." + kind.lowercased()
    let schema = kind == "Transfer" ? "iroha_data_model::isi::transfer::TransferBox"
        : "iroha_data_model::isi::mint_burn::\(kind)Box"
    return try explorerInstructionBoxFixture(
        frame: explorerInstructionFixtureFrame(wireId: wireId, schema: schema, payload: payload.data),
        wireId: wireId)
}

func explorerBatchBoxFixture(_ entries: [(String, String, String, String)]) throws -> String {
    try explorerBatchBoxFixture(quantities: entries.map {
        ($0.0, $0.1, $0.2, try CanonicalNorito.encodeCompactQuantity($0.3))
    })
}

func explorerBatchBoxFixture(quantities entries: [(String, String, String, Data)]) throws -> String {
    var vector = CompactNoritoWriter()
    vector.writeUInt64LE(UInt64(entries.count))
    for (index, entry) in entries.enumerated() {
        var body = CompactNoritoWriter()
        body.writeField(CompactNorito.encodeString("leg-\(index)"))
        body.writeField(try CanonicalNorito.encodeCompactAccountId(entry.0))
        body.writeField(try CanonicalNorito.encodeCompactAccountId(entry.1))
        body.writeField(try CanonicalNorito.encodeCompactAssetDefinitionId(entry.2))
        body.writeField(entry.3)
        vector.writeField(body.data)
    }
    var payload = CompactNoritoWriter()
    payload.writeField(CompactNorito.encodeUInt32(0))
    payload.writeField(vector.data)
    return try explorerInstructionBoxFixture(frame: explorerInstructionFixtureFrame(
        wireId: "iroha.transfer_batch", schema: "iroha_data_model::isi::transfer::TransferAssetBatch",
        payload: payload.data), wireId: "iroha.transfer_batch")
}

final class ToriiExplorerInstructionContractTests: XCTestCase {
    // Rust producer: crates/iroha_data_model/src/isi/generated_box_identity_tests.rs,
    // checked-in instruction_box_generated_identity_frames.json / TransferBox.Asset.
    private let rustAssetFrame = "TlJUMAAAhip9dwddTSP/bBJh2wJ4EQAbAQAAAAAAAGjXJ8w0uSkIAg8OaXJvaGEudHJhbnNmZXKJAgEBAAAAAAAATlJUMAAApBdMeNY0H4+Y/Cra6O1nuQDZAAAAAAAAAIt6iOS5q/eOAgIAAADTAXZPAAAAAEohAAAAAAAAAAEAAZMB2wGfAS4B4AH3AeMBngGUAS8BtQGUAUEBGQELAfIBCwGcAUMBzwHMAYoBBQEaARUBJAGZAc8BOQErAXoBNyABlAH4AeUBWgF2AX0BTAG8AYQB/QHAAdkBRgG9AXgBegQAAAAACwUBAAAABwQAAAAATwAAAABKIQAAAAAAAAABAAGTAdsBnwEuAeAB9wHjAZ4BlAEvAbUBlAFBARkBCwHyAQsBnAFDAc8BzAGKAQUBGgEVASQBmQHPATkBKwF6ATc="

    func testRustAssetFrameDecodesCurrentBoxWithoutJSON() throws {
        let box = try decodeBox()
        XCTAssertEqual(box.wireId, "iroha.transfer")
        XCTAssertEqual(box.instruction, rustAssetFrame)
        XCTAssertEqual(box.framedSha256.count, 64)
    }

    func testRustAssetFrameProjectsExactTransferOnAuthorityNetwork() throws {
        let authority = try AccountAddress.fromAccount(publicKey: Data(hexString:
            "93db9f2ee0f7e39e942fb59441190bf20b9c43cfcc8a051a152499cf392b7a37")!).toI105(networkPrefix: 369)
        let item = try decodeItem(box: boxObject(), authority: authority)
        guard case let .asset(asset)? = item.transferDetails() else { return XCTFail("Missing Rust transfer") }
        XCTAssertEqual(asset.amount, "7")
        XCTAssertEqual(asset.senderAccountId, authority)
        XCTAssertEqual(asset.destinationAccountId, authority)
        XCTAssertEqual(asset.assetDefinitionId,
            AssetDefinitionAddress.encode(uuidBytes: Data(hexString: "94f8e55a767d4cbc84fdc0d946bd787a")!))
    }

    func testRetiredAndUnknownBoxFieldsAreRejected() throws {
        for field in ["json", "encoded", "scale", "unrecognized"] {
            var box = try boxObject()
            box[field] = "retired"
            XCTAssertThrowsError(try decodeBox(box))
        }
        for field in ["wire_id", "framed_sha256", "instruction"] {
            var box = try boxObject(); box.removeValue(forKey: field)
            XCTAssertThrowsError(try decodeBox(box))
        }
    }

    func testDigestAndBase64AreExact() throws {
        for digest in [String(repeating: "0", count: 64), "0x" + String(repeating: "a", count: 64),
                       try boxObject()["framed_sha256"]!.uppercased()] {
            var box = try boxObject(); box["framed_sha256"] = digest
            XCTAssertThrowsError(try decodeBox(box))
        }
        for value in [rustAssetFrame + "\n", String(rustAssetFrame.dropLast()), "*"] {
            var box = try boxObject(); box["instruction"] = value
            XCTAssertThrowsError(try decodeBox(box))
        }
    }

    func testWireIDMustMatchEmbeddedFrame() throws {
        for wire in ["iroha.mint", " iroha.transfer", "", "iroha.transfer\n"] {
            var box = try boxObject(); box["wire_id"] = wire
            XCTAssertThrowsError(try decodeBox(box))
        }
    }

    func testWrongOuterSchemaChecksumPaddingAndTrailingBytesAreRejectedEvenWithCorrectDigest() throws {
        let original = Data(base64Encoded: rustAssetFrame)!
        var checksum = original; checksum[40] ^= 1
        var flags = original; flags[39] = 0
        var schema = original; schema[6] ^= 1
        var padding = original; padding.insert(0, at: 40)
        for frame in [checksum, flags, schema, padding, original + Data([0]), Data(original.dropLast())] {
            let box = try fixtureObject(frame: frame)
            XCTAssertThrowsError(try decodeBox(box))
        }
    }

    func testKnownTransferRejectsWrongInnerSchemaAndMalformedPayloadBeforeMapping() throws {
        for (schema, payload) in [("iroha_data_model::isi::mint_burn::MintBox", Data([2, 0, 0, 0, 0])),
                                  ("iroha_data_model::isi::transfer::TransferBox", Data([2, 0, 0, 0]))] {
            let frame = explorerInstructionFixtureFrame(wireId: "iroha.transfer", schema: schema, payload: payload)
            XCTAssertThrowsError(try decodeItem(box: fixtureObject(frame: frame), authority: "unused"))
        }
    }

    func testKnownKindMustMatchWireID() throws {
        XCTAssertThrowsError(try decodeItem(box: boxObject(), authority: "unused", kind: "Mint"))
    }

    func testCompactQuantityRoundTripPreservesPrecisionAndRejectsNoncanonicalValues() throws {
        for value in ["0", "7", "123456789012345678901234567890.1234567890123456789012345678"] {
            XCTAssertEqual(try CanonicalNorito.decodeCompactQuantity(CanonicalNorito.encodeCompactQuantity(value)).canonicalString, value)
        }
        var negative = CompactNoritoWriter(); negative.writeField(Data([1, 0, 0, 0, 255])); negative.writeField(CompactNorito.encodeUInt32(0))
        var padded = CompactNoritoWriter(); padded.writeField(Data([2, 0, 0, 0, 7, 0])); padded.writeField(CompactNorito.encodeUInt32(0))
        var scaledZero = CompactNoritoWriter(); scaledZero.writeField(Data([0, 0, 0, 0])); scaledZero.writeField(CompactNorito.encodeUInt32(1))
        for payload in [negative.data, padded.data, scaledZero.data, try CanonicalNorito.encodeCompactQuantity("7") + Data([0])] {
            XCTAssertThrowsError(try CanonicalNorito.decodeCompactQuantity(payload))
        }
    }

    private func boxObject() throws -> [String: String] {
        try fixtureObject(frame: Data(base64Encoded: rustAssetFrame)!)
    }
    private func fixtureObject(frame: Data) throws -> [String: String] {
        try JSONDecoder().decode([String: String].self, from: Data(explorerInstructionBoxFixture(frame: frame, wireId: "iroha.transfer").utf8))
    }
    private func decodeBox(_ box: [String: String]? = nil) throws -> ToriiExplorerInstructionBox {
        try JSONDecoder().decode(ToriiExplorerInstructionBox.self,
            from: JSONSerialization.data(withJSONObject: box ?? boxObject()))
    }
    private func decodeItem(box: [String: String], authority: String, kind: String = "Transfer") throws -> ToriiExplorerInstructionItem {
        try JSONDecoder().decode(ToriiExplorerInstructionItem.self, from: JSONSerialization.data(withJSONObject: [
            "authority": authority, "created_at": "2026-10-14T00:00:00Z", "kind": kind, "box": box,
            "transaction_hash": "hash", "transaction_status": "Committed", "block": 1, "index": 0,
        ] as [String: Any]))
    }
}
