import Foundation
import XCTest
@testable import IrohaSwift

/// Nearby picture pairing: the shared token and target vectors, the strict token alphabet and the
/// random grid.
final class IrohaPeerNearbyPictureCodeV1Tests: XCTestCase {
    func testSharedVectorsPinTheTargetPicture() throws {
        let pictures = try irohaPeerNearbyPictureFixtureV1()
        XCTAssertEqual(pictures["picture_count"] as? Int, IrohaPeerNearbyPictureCodeV1.pictureCount)
        XCTAssertEqual(pictures["grid_size"] as? Int, IrohaPeerNearbyPictureCodeV1.gridSize)
        XCTAssertEqual(IrohaPeerNearbyPictureCodeV1.pictureCount, 16)
        XCTAssertEqual(IrohaPeerNearbyPictureCodeV1.gridSize, 6)
        let vectors = try XCTUnwrap(pictures["vectors"] as? [[String: Any]])
        XCTAssertEqual(vectors.count, 12)
        for vector in vectors {
            let token = try XCTUnwrap(vector["token"] as? String)
            XCTAssertTrue(IrohaPeerNearbyPairingTokenV1.isValid(token), token)
            XCTAssertEqual(try IrohaPeerNearbyPictureCodeV1.targetIndex(token: token),
                           vector["index"] as? Int, token)
        }
    }

    /// iOS receives the token from Google Nearby as is; Android derives the same token from the raw
    /// verification string, so both phones of one connection draw the same picture. Each vector follows
    /// the rule iOS Nearby applies (encryption_runner.cc `ToHumanReadableString`).
    func testTokenVectorsFollowNearbysTokenRule() throws {
        let pictures = try irohaPeerNearbyPictureFixtureV1()
        let vectors = try XCTUnwrap(pictures["token_vectors"] as? [[String: Any]])
        XCTAssertEqual(vectors.count, 6)
        for vector in vectors {
            let token = try XCTUnwrap(vector["token"] as? String)
            let raw = try XCTUnwrap(Data(hexString: try XCTUnwrap(vector["raw_hex"] as? String)), token)
            XCTAssertEqual(raw.count, 32, token)
            let webSafe = raw.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            XCTAssertEqual(String(webSafe.prefix(IrohaPeerNearbyPairingTokenV1.length)).uppercased(), token)
            XCTAssertTrue(IrohaPeerNearbyPairingTokenV1.isValid(token), token)
        }
    }

    func testOnlyFiveCharacterTokensMakeAPicture() throws {
        let pictures = try irohaPeerNearbyPictureFixtureV1()
        let invalid = try XCTUnwrap(pictures["invalid_tokens"] as? [String])
        XCTAssertTrue(invalid.contains("1234"), "Android's retired authentication digits")
        let extra = ["ABCD\u{0}", "AB\u{0}CD", "ABCDE\u{0}", " ABCD", "ABCD ", "ABC\u{200B}D", "ABCDE\n", "K7Q2f"]
        for token in invalid + extra {
            XCTAssertFalse(IrohaPeerNearbyPairingTokenV1.isValid(token), token)
            XCTAssertThrowsError(try IrohaPeerNearbyPictureCodeV1.targetIndex(token: token), token) {
                XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidPictureCode, token)
            }
        }
        // Every character of the token alphabet gives an index inside the picture set.
        for character in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" {
            let token = String(repeating: character, count: IrohaPeerNearbyPairingTokenV1.length)
            XCTAssertTrue((0..<16).contains(try IrohaPeerNearbyPictureCodeV1.targetIndex(token: token)), token)
        }
    }

    func testGridHasSixDistinctPicturesIncludingTheTarget() throws {
        for target in 0..<IrohaPeerNearbyPictureCodeV1.pictureCount {
            for seed in UInt64(1)...40 {
                var generator = IrohaPeerPictureTestGeneratorV1(seed: seed &* 0x9E37_79B9 &+ UInt64(target))
                let grid = try IrohaPeerNearbyPictureCodeV1.grid(target: target, using: &generator)
                XCTAssertEqual(grid.count, IrohaPeerNearbyPictureCodeV1.gridSize)
                XCTAssertEqual(Set(grid).count, grid.count)
                XCTAssertTrue(grid.allSatisfy { (0..<IrohaPeerNearbyPictureCodeV1.pictureCount).contains($0) })
                XCTAssertTrue(grid.contains(target))
            }
            let system = try IrohaPeerNearbyPictureCodeV1.grid(target: target)
            XCTAssertEqual(system.count, 6)
            XCTAssertEqual(Set(system).count, 6)
            XCTAssertTrue(system.contains(target))
        }
        for target in [-1, 16, Int.min, Int.max] {
            XCTAssertThrowsError(try IrohaPeerNearbyPictureCodeV1.grid(target: target)) {
                XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidPictureCode)
            }
        }
    }

    func testGridOrderComesOnlyFromTheRandomSource() throws {
        var first = IrohaPeerPictureTestGeneratorV1(seed: 1)
        var again = IrohaPeerPictureTestGeneratorV1(seed: 1)
        var second = IrohaPeerPictureTestGeneratorV1(seed: 2)
        let one = try IrohaPeerNearbyPictureCodeV1.grid(target: 5, using: &first)
        XCTAssertEqual(try IrohaPeerNearbyPictureCodeV1.grid(target: 5, using: &again), one)
        XCTAssertNotEqual(try IrohaPeerNearbyPictureCodeV1.grid(target: 5, using: &second), one)
    }

    func testTargetPositionAndDecoysAreUniform() throws {
        // Deterministic draws: a missing final shuffle would pin the target to one slot.
        var generator = IrohaPeerPictureTestGeneratorV1(seed: 0x51C7)
        var positions = Array(repeating: 0, count: IrohaPeerNearbyPictureCodeV1.gridSize)
        var decoys = Array(repeating: 0, count: IrohaPeerNearbyPictureCodeV1.pictureCount)
        let rounds = 6_000
        for _ in 0..<rounds {
            let grid = try IrohaPeerNearbyPictureCodeV1.grid(target: 3, using: &generator)
            positions[try XCTUnwrap(grid.firstIndex(of: 3))] += 1
            grid.filter { $0 != 3 }.forEach { decoys[$0] += 1 }
        }
        for count in positions {
            XCTAssertTrue((850...1_150).contains(count), "target position count \(count)")
        }
        XCTAssertEqual(decoys[3], 0)
        // Each of the 15 other pictures appears in 5 of 15 slots: about 2,000 times.
        for (picture, count) in decoys.enumerated() where picture != 3 {
            XCTAssertTrue((1_800...2_200).contains(count), "picture \(picture) count \(count)")
        }
    }
}

/// The picture-pairing vectors of `fixtures/kagemusha/nearby_picture_v1.json` that the Kotlin SDK
/// asserts byte for byte too, found by walking up from the calling test file. The vectors are the
/// file's `nearby_picture` object, or the file itself when it holds them at its root.
private func irohaPeerNearbyPictureFixtureV1(filePath: String = #filePath) throws -> [String: Any] {
    var directory = URL(fileURLWithPath: filePath).deletingLastPathComponent()
    for _ in 0..<8 {
        let file = directory.appendingPathComponent("fixtures/kagemusha/nearby_picture_v1.json")
        if FileManager.default.fileExists(atPath: file.path) {
            let object = try XCTUnwrap(
                JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any]
            )
            if let version = object["fixture_version"] { XCTAssertEqual(version as? Int, 2) }
            return object["nearby_picture"] as? [String: Any] ?? object
        }
        directory.deleteLastPathComponent()
    }
    throw CocoaError(.fileNoSuchFile)
}

/// SplitMix64: a deterministic test source, never used for real grids.
private struct IrohaPeerPictureTestGeneratorV1: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) { state = seed }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var value = state
        value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
        value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
        return value ^ (value >> 31)
    }
}
