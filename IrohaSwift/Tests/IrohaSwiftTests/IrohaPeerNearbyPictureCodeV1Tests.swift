import Foundation
import XCTest
@testable import IrohaSwift

/// Nearby picture pairing: the shared target vectors, strict ASCII digits and the random grid.
final class IrohaPeerNearbyPictureCodeV1Tests: XCTestCase {
    func testSharedVectorsPinTheTargetPicture() throws {
        let pictures = try irohaPeerNearbyPictureFixtureV1()
        XCTAssertEqual(pictures["picture_count"] as? Int, IrohaPeerNearbyPictureCodeV1.pictureCount)
        XCTAssertEqual(pictures["grid_size"] as? Int, IrohaPeerNearbyPictureCodeV1.gridSize)
        XCTAssertEqual(IrohaPeerNearbyPictureCodeV1.pictureCount, 16)
        XCTAssertEqual(IrohaPeerNearbyPictureCodeV1.gridSize, 6)
        let vectors = try XCTUnwrap(pictures["vectors"] as? [[String: Any]])
        XCTAssertEqual(vectors.count, 10)
        for vector in vectors {
            let digits = try XCTUnwrap(vector["digits"] as? String)
            XCTAssertEqual(try IrohaPeerNearbyPictureCodeV1.targetIndex(digits: digits),
                           vector["index"] as? Int, digits)
        }
    }

    func testOnlyFourToTwelveASCIIDigitsMakeAPicture() throws {
        let pictures = try irohaPeerNearbyPictureFixtureV1()
        let invalid = try XCTUnwrap(pictures["invalid_digits"] as? [String])
        XCTAssertTrue(invalid.contains("\u{0661}\u{0662}\u{0663}\u{0664}"), "Arabic-Indic digits vector")
        let extra = ["１２３４", "１234", "+1234", "-1234", "1234 ", " 1234", "12\u{0}34", "123456789012\u{0}",
                     "1234\u{200B}", "١٢٣٤٥", "0x12", "1e10", "12.4"]
        for digits in invalid + extra {
            XCTAssertFalse(IrohaPeerNearbyVerificationCodeV1.isValid(digits), digits)
            XCTAssertThrowsError(try IrohaPeerNearbyPictureCodeV1.targetIndex(digits: digits), digits) {
                XCTAssertEqual($0 as? IrohaPeerNearbyErrorV1, .invalidPictureCode, digits)
            }
        }
        // Every valid length gives an index inside the picture set.
        for length in 4...12 {
            let digits = String(repeating: "9", count: length)
            XCTAssertTrue((0..<16).contains(try IrohaPeerNearbyPictureCodeV1.targetIndex(digits: digits)))
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
            if let version = object["fixture_version"] { XCTAssertEqual(version as? Int, 1) }
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
