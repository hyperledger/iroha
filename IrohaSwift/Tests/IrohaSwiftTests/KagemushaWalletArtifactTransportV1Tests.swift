import Foundation
import XCTest
@testable import IrohaSwift

final class KagemushaWalletArtifactTransportV1Tests: XCTestCase {
    private let raw = String(repeating: "11", count: 32)
    private let stored = String(repeating: "aa", count: 32)
    private func row(_ rawDigest: String? = nil) -> String {
        "{\"bytes\":8000,\"sha256\":\"\(rawDigest ?? raw)\",\"storedBytes\":27,\"storedSha256\":\"\(stored)\"}"
    }
    private func frame(_ rows: String? = nil) -> String {
        "{\"schema\":\"\(KagemushaWalletArtifactTransportV1.schema)\",\"encoding\":\"zstd\",\"walletOriginals\":[\(rows ?? row())]}\n"
    }
    private func decode(_ text: String) throws -> [KagemushaWalletArtifactExtentV1] {
        try KagemushaWalletArtifactTransportV1.decode(Data(text.utf8))
    }
    func testPreservesDistinctDecodedAndStoredIdentities() throws {
        XCTAssertEqual(try decode(frame()), [.init(rawBytes: 8000, rawSha256: raw, storedBytes: 27, storedSha256: stored)])
        XCTAssertEqual(try decode(frame(row() + "," + row(String(repeating: "22", count: 32)))).count, 2)
    }
    func testRejectsRawCarriersDuplicatesAndNoncanonicalRepresentations() throws {
        let original = frame()
        let replacements = [("\"encoding\":\"zstd\",", ""), ("zstd", "gzip"),
            ("\"encoding\":", "\"encoding\":\"zstd\",\"encoding\":"), ("8000", "8e3"),
            ("8000", "8000.0"), ("8000", "true"), ("\"storedBytes\":27", "\"storedBytes\":\"27\""),
            ("]}", "],\"finalityOriginals\":[]}"), ("{\"bytes\":", "{\"unknown\":0,\"bytes\":")]
        for (from, to) in replacements {
            XCTAssertThrowsError(try decode(original.replacingOccurrences(of: from, with: to)))
        }
        XCTAssertThrowsError(try decode(String(original.dropLast())))
        XCTAssertThrowsError(try decode(" " + original))
    }
    func testRejectsInvalidExtentsHashesAndOrder() throws {
        let original = frame()
        for (from, to) in [("8000", "0"), ("8000", "1073741825"),
            ("\"storedBytes\":27", "\"storedBytes\":0"), ("\"storedBytes\":27", "\"storedBytes\":1077936129"),
            (stored, stored.uppercased()), (stored, String(repeating: "0", count: 64)), (raw, "../" + String(repeating: "a", count: 61))] {
            XCTAssertThrowsError(try decode(original.replacingOccurrences(of: from, with: to)))
        }
        for rows in ["", row() + "," + row(), row(String(repeating: "22", count: 32)) + "," + row(),
                     Array(repeating: row(), count: 12289).joined(separator: ",")] {
            XCTAssertThrowsError(try decode(frame(rows)))
        }
    }
    func testExactBoundsAndInvalidUTF8() throws {
        let rows = try decode(frame().replacingOccurrences(of: "8000", with: "1073741824")
            .replacingOccurrences(of: "\"storedBytes\":27", with: "\"storedBytes\":1077936128"))
        XCTAssertEqual(rows[0].rawBytes, KagemushaWalletArtifactTransportV1.maxRawBytes)
        XCTAssertEqual(rows[0].storedBytes, KagemushaWalletArtifactTransportV1.maxStoredBytes)
        XCTAssertThrowsError(try KagemushaWalletArtifactTransportV1.decode(Data([0xc3])))
    }
    func testRejectsExcessiveDepthAndNodesBeforeMaterializingJSON() {
        for input in [String(repeating: "[", count: 50000) + "0" + String(repeating: "]", count: 50000),
            "[" + Array(repeating: "0", count: 100000).joined(separator: ",") + "]",
            "[" + Array(repeating: "{}", count: 12291).joined(separator: ",") + "]"] {
            XCTAssertThrowsError(try decode(input))
        }
    }
    func testAcceptsMaximumCanonicalRowCount() throws {
        let rows = (1...12288).map { value -> String in
            let hex = String(value, radix: 16)
            return row(String(repeating: "0", count: 64 - hex.count) + hex)
        }.joined(separator: ",")
        XCTAssertEqual(try decode(frame(rows)).count, 12288)
    }

}
