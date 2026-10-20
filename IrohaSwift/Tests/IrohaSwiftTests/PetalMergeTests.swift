import Foundation
import XCTest
@testable import IrohaSwift

/// Capture averaging and session isolation, including the Rust reference's
/// noisy, banded and torn-camera captures in the shared golden fixture.
final class PetalMergeTests: XCTestCase {
    private typealias Support = PetalTestSupport

    private func setup(_ number: UInt16 = 11) throws -> (PetalStreamEncoder, PetalLuma, PetalDecodedFrame) {
        let encoder = try PetalStreamEncoder(payload: Support.payload(700, seed: 3), kind: 2)
        let image = try Support.render(encoder, frame: number, size: 512, supersample: 2)
        return (encoder, image, try PetalDecoder.decode(image))
    }

    private func frame(
        _ pose: PetalDecodedFrame,
        p: PetalLaneResult? = nil,
        k: PetalLaneResult? = nil,
        d: PetalLaneResult? = nil,
        inferredCorner: Int? = nil
    ) -> PetalDecodedFrame {
        PetalDecodedFrame(
            homography: pose.homography, rotation: pose.rotation, mirrored: pose.mirrored,
            p: p, k: k, d: d, inferredCorner: inferredCorner
        )
    }

    private func lane(_ data: [UInt8]) -> PetalLaneResult {
        PetalLaneResult(data: data, corrected: 0, erasures: 0)
    }

    func testSharedCRCMatchesTheExistingPeerQRGoldenVector() {
        // The peer QR suite pins this same CRC-32C check value. Keep the
        // shared helper in this focused source-only Petal test closure too.
        XCTAssertEqual(IrohaPeerCRC32CV1.checksum(Data("123456789".utf8)), 0xE306_9283)
        XCTAssertEqual(IrohaPeerCRC32CV1.checksum([UInt8]()), 0)
    }

    func testOneEvidenceMatchesTheSingleCaptureAndTransformsStayInCodeCoordinates() throws {
        let (encoder, clean, _) = try setup()
        var shadow = clean.pixels
        for y in 0..<clean.height {
            for x in clean.width * 7 / 20..<clean.width * 3 / 5 {
                let i = y * clean.width + x
                shadow[i] = UInt8((Double(shadow[i]) * 0.3).rounded())
            }
        }
        var hidden = clean.pixels
        let center = PetalLayout.finderCenters[3]
        let scale = Double(clean.width) / 1024
        for y in 0..<clean.height {
            for x in 0..<clean.width {
                let dx = Double(x) + 0.5 - center.x * scale
                let dy = Double(y) + 0.5 - center.y * scale
                if dx * dx + dy * dy <= pow(75 * scale, 2) { hidden[y * clean.width + x] = 0 }
            }
        }
        let images = [
            clean,
            try PetalLuma(width: clean.width, height: clean.height, pixels: shadow),
            try PetalLuma(width: clean.width, height: clean.height, pixels: hidden),
            try Support.mirror(clean),
            try Support.transform(clean) { x, y in (y, clean.width - 1 - x) },
        ]
        var captures: [PetalTileEvidence] = []
        for image in images {
            let decoded = try PetalDecoder.decode(image)
            let evidence = try XCTUnwrap(PetalDecoder.tileEvidence(image, frame: decoded))
            let merged = PetalDecoder.mergeTiles([evidence])
            XCTAssertEqual(merged.p, decoded.p)
            XCTAssertEqual(merged.k, decoded.k)
            captures.append(evidence)
        }
        let merged = PetalDecoder.mergeTiles(captures)
        XCTAssertEqual(merged.p?.data, encoder.laneData(frame: 11).p)
        XCTAssertEqual(merged.k?.data, encoder.laneData(frame: 11).k)
    }

    func testIndependentCellNoiseIsAveragedDown() throws {
        let (encoder, image, pose) = try setup(5)
        let clean = try XCTUnwrap(PetalDecoder.tileEvidence(image, frame: pose))
        var rng = PetalXorshift32(seed: 9)
        let captures = (0..<4).map { _ in
            PetalTileEvidence(
                patches: clean.patches.map { $0 + (Double(rng.nextByte()) - 127.5) * 3.0 },
                reference: clean.reference
            )
        }
        for capture in captures {
            XCTAssertNil(PetalDecoder.mergeTiles([capture]).k, "each capture must lose K for this test to prove recovery")
        }
        let merged = PetalDecoder.mergeTiles(captures)
        XCTAssertEqual(merged.p?.data, encoder.laneData(frame: 5).p)
        XCTAssertEqual(merged.k?.data, encoder.laneData(frame: 5).k)
    }

    func testEvidenceRequiresUsableImageAndCornerAndEmptyMergeReadsNothing() throws {
        let (_, image, pose) = try setup()
        XCTAssertNil(PetalDecoder.tileEvidence(try PetalLuma(width: 20, height: 20), frame: pose))
        XCTAssertNil(PetalDecoder.tileEvidence(image, frame: frame(pose, inferredCorner: 7)))
        XCTAssertNil(PetalDecoder.tileEvidence(image, frame: pose, options: PetalDecodeOptions(maximumPixels: 100)))
        XCTAssertNil(PetalDecoder.mergeTiles([]).p)
        XCTAssertNil(PetalDecoder.mergeTiles([]).k)
    }

    func testUnkeyedTornAndShortHeadersAreNotHeld() throws {
        let (encoder, image, pose) = try setup()
        var session = PetalScanSession()
        for rejected in [
            frame(pose),
            frame(pose, p: lane([1, 2])),
            frame(pose, p: lane(encoder.laneData(frame: 11).p), d: lane(encoder.laneData(frame: 10).d)),
        ] {
            XCTAssertNil(PetalScanSession.shownFrame(rejected))
            XCTAssertEqual(session.merge(image, frame: rejected), "")
        }
        XCTAssertTrue(session.held.isEmpty)
        XCTAssertEqual(session.stats.merges, 0)
    }

    func testRecoveredLanesMustNameTheShownFrameAndOnlyMissingLanesAreOffered() throws {
        let (encoder, image, pose) = try setup()
        let wrongRings = frame(pose, d: lane(encoder.laneData(frame: 10).d))
        var session = PetalScanSession()
        for _ in 0..<3 { XCTAssertEqual(session.merge(image, frame: wrongRings), "") }
        XCTAssertEqual(session.stats.merges, 2)
        XCTAssertEqual(session.stats.mergedP, 0)
        XCTAssertEqual(session.stats.mergedK, 0)
        XCTAssertEqual(session.progress.atomsReceived, 0)
        let rejected = PetalDecoder.mergeTiles(try XCTUnwrap(session.held.first).evidence)
        XCTAssertEqual(rejected.p?.data, encoder.laneData(frame: 11).p)
        XCTAssertEqual(rejected.k?.data, encoder.laneData(frame: 11).k)

        session.reset()
        let pRead = frame(pose, p: pose.p, d: pose.d)
        XCTAssertEqual(session.merge(image, frame: pRead), "")
        XCTAssertEqual(session.merge(image, frame: pRead), "K")
        XCTAssertEqual(session.stats.mergedP, 0)
        XCTAssertEqual(session.stats.mergedK, 1)
        XCTAssertTrue(try XCTUnwrap(session.held.first).evidence.isEmpty)
        let merges = session.stats.merges
        XCTAssertEqual(session.merge(image, frame: pRead), "")
        XCTAssertEqual(session.stats.merges, merges, "a completed shown frame releases evidence and stops merging")
    }

    func testCaptureAndShownFrameFIFOsAreBoundedAndResetAndSessionsStayIsolated() throws {
        let (encoder, image, pose) = try setup()
        let rings = frame(pose, d: lane(encoder.laneData(frame: 10).d))
        var first = PetalScanSession()
        var second = PetalScanSession()
        XCTAssertEqual(first.merge(image, frame: rings), "")
        XCTAssertEqual(second.merge(image, frame: rings), "")
        XCTAssertEqual(second.stats.merges, 0, "sessions never share captures")
        for _ in 0..<PetalScanSession.mergeCaptures + 1 { _ = first.merge(image, frame: rings) }
        XCTAssertEqual(first.held.count, 1)
        XCTAssertEqual(first.held[0].evidence.count, PetalScanSession.mergeCaptures)
        XCTAssertEqual(first.stats.merges, UInt32(PetalScanSession.mergeCaptures + 1))
        for number in 12..<12 + PetalScanSession.mergeWindow {
            _ = first.merge(image, frame: frame(pose, d: lane(encoder.laneData(frame: UInt16(number)).d)))
        }
        XCTAssertEqual(first.held.count, PetalScanSession.mergeWindow)
        XCTAssertEqual(first.held.map(\.shown.frame), (12..<18).map(UInt16.init))
        // A different stream tag gets its own shown-frame slot even with the same counter.
        var other = encoder.laneData(frame: 17).d
        other[0] ^= 1
        _ = first.merge(image, frame: frame(pose, d: lane(other)))
        XCTAssertEqual(first.held.suffix(2).map(\.shown.frame), [17, 17])
        XCTAssertNotEqual(first.held[first.held.count - 2].shown.tag, first.held.last?.shown.tag)
        first.reset()
        XCTAssertTrue(first.held.isEmpty)
        XCTAssertEqual(first.merge(image, frame: rings), "")
        XCTAssertEqual(first.held[0].evidence.count, 1)
        XCTAssertEqual(second.held[0].evidence.count, 1)
    }

    func testSessionTimeoutsReleaseHeldEvidence() throws {
        let (encoder, image, pose) = try setup(0)
        let rings = frame(pose, d: lane(encoder.laneData(frame: 1).d))
        for limits in [
            PetalScanLimits(idleTimeoutMilliseconds: 10),
            PetalScanLimits(absoluteTimeoutMilliseconds: 10),
        ] {
            var session = PetalScanSession(limits: limits)
            XCTAssertNotNil(session.push(image, nowMilliseconds: 0).progress.meta)
            XCTAssertEqual(session.merge(image, frame: rings), "")
            XCTAssertFalse(session.held.flatMap(\.evidence).isEmpty)
            let expired = session.push(try PetalLuma(width: 320, height: 240), nowMilliseconds: 11)
            XCTAssertNil(expired.progress.meta)
            XCTAssertTrue(expired.merged.isEmpty)
            XCTAssertTrue(session.held.isEmpty)
        }
    }

    func testActualMetadataSwitchClearsSameTagFrameEvidenceAndDoneFlags() throws {
        // Same cross-port collision: full stream identity differs although
        // the eight-bit tag and frame counter are identical.
        let old = try PetalStreamEncoder(payload: [0, 0, 0, 49] + [UInt8](repeating: 0, count: 96), kind: 2)
        let next = try PetalStreamEncoder(payload: [0, 0, 0, 128] + [UInt8](repeating: 0, count: 96), kind: 2)
        XCTAssertEqual(old.meta.tag, 61)
        XCTAssertEqual(next.meta.tag, old.meta.tag)
        XCTAssertNotEqual(next.meta, old.meta)
        let oldImage = try Support.render(old, frame: 0, size: 512, supersample: 2)
        let nextImage = try Support.render(next, frame: 0, size: 512, supersample: 2)
        let oldFull = try PetalDecoder.decode(oldImage)
        let oldD = frame(oldFull, d: oldFull.d)
        let nextFull = try PetalDecoder.decode(nextImage)
        let nextD = frame(nextFull, d: nextFull.d)
        for oldTileLanesDone in [false, true] {
            var session = PetalScanSession()
            XCTAssertEqual(session.merge(oldImage, frame: oldD), "")
            _ = session.absorb(oldTileLanesDone ? oldFull : oldD)
            XCTAssertEqual(session.progress.meta, old.meta)
            XCTAssertEqual(session.held.count, 1, "initial nil-to-meta admission preserves keyed evidence")
            if oldTileLanesDone { _ = session.merge(oldImage, frame: oldFull) }
            XCTAssertEqual(session.held[0].pDone, oldTileLanesDone)
            XCTAssertEqual(session.held[0].kDone, oldTileLanesDone)
            XCTAssertEqual(session.held[0].evidence.isEmpty, oldTileLanesDone)

            _ = session.absorb(nextD)
            XCTAssertEqual(session.progress.meta, old.meta, "one competing beacon does not switch streams")
            XCTAssertEqual(session.held.count, 1)
            _ = session.absorb(nextD)
            XCTAssertEqual(session.progress.meta, next.meta)
            XCTAssertTrue(session.held.isEmpty, "an accepted metadata switch drops both evidence and done flags")
            XCTAssertEqual(session.merge(nextImage, frame: nextD), "")
            XCTAssertEqual(session.held[0].evidence.count, 1)
            let fresh = PetalDecoder.mergeTiles(session.held[0].evidence)
            XCTAssertEqual(fresh.p?.data, next.laneData(frame: 0).p)
            XCTAssertEqual(fresh.k?.data, next.laneData(frame: 0).k)
            XCTAssertEqual(session.merge(nextImage, frame: nextD), "PK")
            XCTAssertEqual(session.stats.mergedP, 1)
            XCTAssertEqual(session.stats.mergedK, 1)
        }
    }

    private func fixtures() throws -> [String: Any] {
        try Support.loadJSON("petal_captures_v1.json")
    }

    private func mergeSet(_ set: [String: Any]) throws -> (
        p: PetalLaneResult?, k: PetalLaneResult?, merged: String, stats: PetalScanStats
    ) {
        let name = try Support.string(set, "name")
        var evidence: [PetalTileEvidence] = []
        var session = PetalScanSession()
        var merged = ""
        for (index, capture) in try Support.objects(set, "captures").enumerated() {
            var entry = capture
            entry["width"] = set["width"]
            entry["height"] = set["height"]
            let image = try Support.luma(of: entry)
            let decoded = try PetalDecoder.decode(image)
            XCTAssertEqual(decoded.laneLetters, try Support.string(capture, "reference_decoded"), "\(name) capture \(index)")
            for (lane, key) in [(decoded.p, "p_data"), (decoded.k, "k_data"), (decoded.d, "d_data")] {
                if let lane { XCTAssertEqual(lane.data, try Support.bytes(set, key), "\(name) capture \(index) \(key)") }
            }
            evidence.append(try XCTUnwrap(PetalDecoder.tileEvidence(image, frame: decoded)))
            merged += session.push(image, nowMilliseconds: UInt64(index) * 33).merged
        }
        let results = PetalDecoder.mergeTiles(evidence)
        return (results.p, results.k, merged, session.stats)
    }

    func testRustGoldenNoisyAndBandedCapturesRecoverExactlyTheReferenceLanes() throws {
        for set in try Support.objects(fixtures(), "merges") {
            let result = try mergeSet(set)
            var letters = ""
            if let p = result.p {
                XCTAssertEqual(p.data, try Support.bytes(set, "p_data"))
                letters += "P"
            }
            if let k = result.k {
                XCTAssertEqual(k.data, try Support.bytes(set, "k_data"))
                letters += "K"
            }
            XCTAssertEqual(letters, try Support.string(set, "reference_merged"))
            XCTAssertEqual(result.merged, try Support.string(set, "must_merge"))
            XCTAssertGreaterThan(result.stats.merges, 0)
        }
    }

    func testRustGoldenTornCapturesNeverOfferTheOtherFramesLanes() throws {
        for set in try Support.objects(fixtures(), "mixed_merges") {
            let result = try mergeSet(set)
            XCTAssertEqual(result.p?.data, try Support.bytes(set, "p_data"))
            XCTAssertNil(result.k)
            XCTAssertTrue(result.merged.isEmpty)
            XCTAssertGreaterThan(result.stats.merges, 0)
            XCTAssertEqual(result.stats.mergedP, 0)
            XCTAssertEqual(result.stats.mergedK, 0)
        }
    }
}
