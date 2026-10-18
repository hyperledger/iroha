import Foundation
import XCTest
@testable import IrohaSwift

/// Adversarial coverage for nominal quantity values embedded in explorer instruction readbacks.
final class ToriiQuantityReadbackTests: XCTestCase {
    private let source =
        "62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
    private let destination =
        "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"

    func testAssetTransferReadbackAcceptsOnlyCanonicalQuantityStrings() throws {
        XCTAssertEqual(try quantityFromJSON(#""1.25""#).canonicalString, "1.25")
        let valid = try item(
            kind: "Transfer",
            box: explorerTransferBoxFixture(sourceAssetId: source, destination: destination,
                                            amount: "1.25")
        )
        guard case let .asset(asset)? = valid.transferDetails() else {
            return XCTFail("canonical transfer quantity was rejected")
        }
        XCTAssertEqual(asset.amount, "1.25")

        for invalid in invalidQuantityJSONValues() {
            XCTAssertThrowsError(try quantityFromJSON(invalid),
                                 "accepted invalid transfer quantity \(invalid)")
        }
        for (label, quantity) in try invalidQuantityPayloads() {
            let box = try explorerTransferBoxFixture(sourceAssetId: source, destination: destination,
                                                     quantityPayload: quantity)
            XCTAssertThrowsError(try item(kind: "Transfer", box: box),
                                 "accepted invalid transfer quantity wire: \(label)")
        }
    }

    func testMintAndBurnReadbacksAcceptOnlyCanonicalQuantityStrings() throws {
        for kind in ["Mint", "Burn"] {
            XCTAssertEqual(try quantityFromJSON(#""2.5""#).canonicalString, "2.5")
            let valid = try item(
                kind: kind,
                box: explorerTransferBoxFixture(sourceAssetId: source, destination: destination,
                                                amount: "2.5", kind: kind)
            )
            guard case let .asset(asset)? = valid.transferDetails() else {
                return XCTFail("canonical \(kind) quantity was rejected")
            }
            XCTAssertEqual(asset.amount, "2.5")

            for invalid in invalidQuantityJSONValues() {
                XCTAssertThrowsError(try quantityFromJSON(invalid),
                                     "accepted invalid \(kind) quantity \(invalid)")
            }
            for (label, quantity) in try invalidQuantityPayloads() {
                let box = try explorerTransferBoxFixture(sourceAssetId: source, destination: destination,
                                                         quantityPayload: quantity, kind: kind)
                XCTAssertThrowsError(try item(kind: kind, box: box),
                                     "accepted invalid \(kind) quantity wire: \(label)")
            }
        }
    }

    func testAssetBatchReadbackRejectsOneInvalidQuantityEntry() throws {
        XCTAssertEqual(try quantityFromJSON(#""3""#).canonicalString, "3")
        let valid = try item(
            kind: "Transfer",
            box: explorerBatchBoxFixture([(sender, destination, definition, "3")])
        )
        guard case let .assetBatch(entries)? = valid.transferDetails() else {
            return XCTFail("canonical batch quantity was rejected")
        }
        XCTAssertEqual(entries.map(\.amount), ["3"])

        for invalid in invalidQuantityJSONValues() {
            XCTAssertThrowsError(try quantityFromJSON(invalid),
                                 "accepted invalid batch quantity \(invalid)")
        }
        let canonicalQuantity = try CanonicalNorito.encodeCompactQuantity("3")
        for (label, quantity) in try invalidQuantityPayloads() {
            // A valid first entry must not hide a malformed later transfer.
            let box = try explorerBatchBoxFixture(quantities: [
                (sender, destination, definition, canonicalQuantity),
                (sender, destination, definition, quantity),
            ])
            XCTAssertThrowsError(try item(kind: "Transfer", box: box),
                                 "accepted invalid batch quantity wire: \(label)")
        }
    }

    private func item(kind: String, box: String) throws -> ToriiExplorerInstructionItem {
        let json = """
        {
            "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            "created_at":"2025-01-01T00:00:00Z",
            "kind":"\(kind)",
            "box":\(box),
            "transaction_hash":"hash",
            "transaction_status":"Committed",
            "block":1,
            "index":0
        }
        """
        return try JSONDecoder().decode(
            ToriiExplorerInstructionItem.self,
            from: Data(json.utf8)
        )
    }

    private var sender: String { String(source.split(separator: "#", maxSplits: 1)[1]) }
    private var definition: String { String(source.split(separator: "#", maxSplits: 1)[0]) }

    private func quantityFromJSON(_ json: String) throws -> KotodamaQuantity {
        // Keep every lexical JSON case: the current explorer carries only Norito,
        // so JSON spelling is checked at the nominal quantity codec boundary.
        let text = try JSONDecoder().decode(String.self, from: Data(json.utf8))
        return try KotodamaNumericV1Codec.decodeQuantityJSON(text)
    }

    private func invalidQuantityPayloads() throws -> [(String, Data)] {
        func payload(mantissa: [UInt8], scale: UInt32) -> Data {
            var integer = CompactNoritoWriter()
            integer.writeUInt32LE(UInt32(mantissa.count))
            integer.writeBytes(Data(mantissa))
            var quantity = CompactNoritoWriter()
            quantity.writeField(integer.data)
            quantity.writeField(CompactNorito.encodeUInt32(scale))
            return quantity.data
        }
        let canonical = try CanonicalNorito.encodeCompactQuantity("3")
        return [
            ("negative", payload(mantissa: [0xff], scale: 0)),
            ("redundant sign extension", payload(mantissa: [3, 0], scale: 0)),
            ("noncanonical empty zero", payload(mantissa: [], scale: 0)),
            ("scaled zero", payload(mantissa: [0], scale: 1)),
            ("unreduced decimal", payload(mantissa: [10], scale: 1)),
            ("scale 29", payload(mantissa: [1], scale: 29)),
            ("mantissa overflow", payload(mantissa: Array(repeating: 1, count: 65), scale: 0)),
            ("trailing data", canonical + Data([0])),
            ("truncated scale", Data(canonical.dropLast())),
        ]
    }

    private func invalidQuantityJSONValues() -> [String] {
        let scaleTwentyNine = "0." + String(repeating: "0", count: 28) + "1"
        let overflow = String(repeating: "9", count: 155)
        return [
            "1",
            "true",
            #""+1""#,
            #""01""#,
            #""1.""#,
            #""1.0""#,
            #""0.0""#,
            #""1e0""#,
            #"" 1""#,
            #""1 ""#,
            #""-0""#,
            #""-1""#,
            #""NaN""#,
            "\"\(scaleTwentyNine)\"",
            "\"\(overflow)\"",
        ]
    }
}
