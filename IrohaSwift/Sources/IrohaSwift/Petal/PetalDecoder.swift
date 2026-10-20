import Foundation

/// Decoder tuning.
public struct PetalDecodeOptions: Equatable, Sendable {
    /// Also try horizontally mirrored images (front-camera previews).
    public var tryMirrored: Bool
    /// Blur widths (in template cells) tried for glyph matching.
    public var templateSigmas: [Double]
    /// Largest image (in pixels) the decoder accepts; larger frames should be
    /// downscaled by the caller. Bounds memory and work on hostile input.
    public var maximumPixels: Int

    public init(
        tryMirrored: Bool = true,
        templateSigmas: [Double] = [0.0, 0.5, 0.8, 1.1, 1.5],
        maximumPixels: Int = 12_000_000
    ) {
        self.tryMirrored = tryMirrored
        self.templateSigmas = templateSigmas
        self.maximumPixels = maximumPixels
    }
}

/// A lane that passed its Reed–Solomon check.
public struct PetalLaneResult: Equatable, Sendable {
    /// Lane data bytes (header and atoms, or the beacon).
    public let data: [UInt8]
    /// Byte positions the Reed–Solomon decoder rewrote (erased bytes plus
    /// unflagged errors).
    public let corrected: Int
    /// Bytes that were passed to the Reed–Solomon decoder as erasures.
    public let erasures: Int
}

/// The tile patches sampled under one decoded pose, in camera levels, and
/// that capture's finder levels. A capture holds about 128 KB. Use
/// ``PetalDecoder/tileEvidence(_:frame:options:)`` to sample it and
/// ``PetalDecoder/mergeTiles(_:options:)`` to average captures of one shown frame.
public struct PetalTileEvidence: Equatable, Sendable {
    let patches: [Double]
    let reference: PetalDecoder.Reference
}

/// Everything read from one camera frame.
public struct PetalDecodedFrame: Equatable, Sendable {
    /// Canvas-to-pixel homography that was used.
    public let homography: PetalHomography
    /// Orientation: how many quarter turns the code is rotated, i.e. which
    /// image corner (clockwise from the top-left) holds the code's top-left
    /// finder.
    public let rotation: Int
    /// Whether the image was mirrored.
    public let mirrored: Bool
    /// Lane `P` result.
    public let p: PetalLaneResult?
    /// Lane `K` result.
    public let k: PetalLaneResult?
    /// Lane `D` result.
    public let d: PetalLaneResult?
    /// The corner finder that was hidden (by a finger, a glare or the edge of
    /// the frame) and inferred from the other three, as its canonical index:
    /// 0 top-left, 1 top-right, 2 bottom-right, 3 bottom-left of the upright
    /// code.
    public let inferredCorner: Int?

    /// Number of lanes that decoded.
    public var lanesOK: Int {
        (p == nil ? 0 : 1) + (k == nil ? 0 : 1) + (d == nil ? 0 : 1)
    }

    /// Letters (`"PKD"` order) of the lanes that decoded.
    public var laneLetters: String {
        var letters = ""
        if p != nil { letters.append(PetalLane.p.letter) }
        if k != nil { letters.append(PetalLane.k.letter) }
        if d != nil { letters.append(PetalLane.d.letter) }
        return letters
    }

    /// What lane `D` carried, when it decoded.
    public var dLane: PetalDLane? {
        d.flatMap { PetalStream.parseDLane($0.data) }
    }

    /// The beacon, when lane `D` decoded on a beacon frame.
    public var beacon: PetalBeacon? {
        if case .beacon(let beacon) = dLane { return beacon }
        return nil
    }

    /// Atom packets from every lane that decoded.
    public var atomPackets: [PetalAtomPacket] {
        var packets: [PetalAtomPacket] = []
        if let p, let packet = PetalStream.parseAtomLane(.p, data: p.data) { packets.append(packet) }
        if let k, let packet = PetalStream.parseAtomLane(.k, data: k.data) { packets.append(packet) }
        if case .atoms(let packet) = dLane { packets.append(packet) }
        return packets
    }

    /// Offers everything this frame carries to `assembler`.
    public func feed(_ assembler: inout PetalStreamAssembler) {
        if let lane = dLane { assembler.push(dLane: lane) }
        if let p, let packet = PetalStream.parseAtomLane(.p, data: p.data) {
            assembler.push(atoms: packet)
        }
        if let k, let packet = PetalStream.parseAtomLane(.k, data: k.data) {
            assembler.push(atoms: packet)
        }
    }
}

/// Why a frame could not be decoded at all.
public enum PetalDecodeError: Error, Equatable, LocalizedError, Sendable {
    /// The image is smaller than 48 pixels on a side or larger than
    /// ``PetalDecodeOptions/maximumPixels``.
    case unsupportedImage
    /// The four corner finders were not found.
    case noFinders
    /// Finders were found but no orientation produced a readable lane.
    case noOrientation

    public var errorDescription: String? {
        switch self {
        case .unsupportedImage: return "Petal image has an unsupported size."
        case .noFinders: return "Petal finders not found."
        case .noOrientation: return "No Petal orientation produced a readable lane."
        }
    }
}

/// From a camera luma plane to lane data (port of
/// `crates/iroha_petal/src/decode.rs`).
///
/// The decoder locates the four finders (or three, inferring the fourth),
/// derives a homography for each orientation hypothesis (four rotations,
/// optionally mirrored), ranks the orientations by their ring gates and the
/// `天` silhouette, picks the one whose lane `D` codeword (or a tile lane)
/// checks out, then reads the tiles and dots. Every tile is classified
/// jointly: the 8×8 sample patch is compared against the 32 hypotheses
/// (polarity × glyph) and the best match wins. Cells the decoder is unsure about become
/// Reed–Solomon erasures. A lane is only reported when its codeword checks
/// out; the payload CRC-32C of the stream catches the rare miscorrection.
///
/// The tile *level read* judges every patch against the light and dark levels
/// measured at the finders. When it leaves lane `P` or `K` unreadable, the
/// *normalised read* is tried: it rescales each patch (and each template) by
/// its own contrast, so over-exposure, veiling light, glare, shadows and
/// gradients cancel out.
public enum PetalDecoder {
    /// Relative level of the glyph ink on a light tile (ink / light fill).
    static let inkOnLight = 0.04
    /// Relative level of a pink glyph on a dark tile (pink / light fill).
    static let pinkOnDark = 0.83
    static let patch = PetalGlyphs.templateSize
    static let cells = patch * patch
    static let hypothesisCount = 2 * PetalGlyphs.count
    /// Cells cut from each end of a sorted patch to find its robust darkest
    /// and brightest level.
    static let patchCut = cells / 10
    /// Tiles whose contrast is below this fraction of the median tile
    /// contrast become erasures in the normalised read.
    static let weakTile = 0.25

    /// Decodes one camera frame.
    ///
    /// Tries the finder candidates of ``PetalLocator/candidates(_:)`` in order
    /// and returns the first that reads. For each, the orientation hypotheses
    /// (four quarter turns, optionally mirrored) are ranked by the ring gates
    /// plus the `天`; lane `D` is tried under the best three whose gate score is
    /// at least 0.2, then the tile lanes under the best four.
    ///
    /// - Throws: ``PetalDecodeError/unsupportedImage`` for unusable sizes,
    ///   ``PetalDecodeError/noFinders`` when no code is visible and
    ///   ``PetalDecodeError/noOrientation`` when no orientation yields a
    ///   readable lane.
    public static func decode(
        _ image: PetalLuma,
        options: PetalDecodeOptions = PetalDecodeOptions()
    ) throws -> PetalDecodedFrame {
        try decodeResult(image, options: options).get()
    }

    /// ``decode(_:options:)`` with a typed failure.
    static func decodeResult(
        _ image: PetalLuma,
        options: PetalDecodeOptions
    ) -> Result<PetalDecodedFrame, PetalDecodeError> {
        guard isSupported(image, options: options) else { return .failure(.unsupportedImage) }
        return image.withView { view in
            var candidates = PetalCandidateSearch()
            var located = false
            while let set = candidates.next(view) {
                located = true
                if let frame = decodeCandidate(view, options, set) { return .success(frame) }
            }
            return .failure(located ? .noOrientation : .noFinders)
        }
    }

    /// Follows a code from the previous frame that decoded, without searching
    /// the whole image for finders (the most expensive part of
    /// ``decode(_:options:)``).
    ///
    /// Each corner finder seen in the previous frame is re-found near where the
    /// previous pose puts it (see ``PetalLocator/follow(_:expected:)``); the
    /// mean movement of those predicts the rest. A corner inferred in the
    /// previous frame counts as seen again only when its blossom is re-found
    /// within a quarter diameter of that prediction (so a thumb beside it does
    /// not count). When exactly one corner is missing it is placed at the
    /// prediction and refined against the rings like an inferred corner. The
    /// orientation is kept from the previous frame. Returns `nil` for a broken
    /// previous pose (non-finite, or finders larger than the image), when two
    /// corners are lost or when no lane decodes; the caller then runs
    /// ``decode(_:options:)``.
    public static func track(
        _ image: PetalLuma,
        previous: PetalDecodedFrame,
        options: PetalDecodeOptions = PetalDecodeOptions()
    ) -> PetalDecodedFrame? {
        // a frame built by the caller may name a corner that does not exist
        guard isSupported(image, options: options),
              previous.inferredCorner.map({ (0...3).contains($0) }) ?? true else { return nil }
        return image.withView { view in track(view, previous: previous, options: options) }
    }

    static func track(
        _ image: PetalLumaView,
        previous: PetalDecodedFrame,
        options: PetalDecodeOptions
    ) -> PetalDecodedFrame? {
        let h0 = previous.homography
        func span(_ a: (Double, Double), _ b: (Double, Double)) -> Double {
            let dx = a.0 - b.0
            let dy = a.1 - b.1
            return (dx * dx + dy * dy).squareRoot()
        }
        let expected = PetalLayout.finderCenters.map { center -> PetalFinder in
            let cx = center.x
            let cy = center.y
            let (x, y) = h0.apply(cx, cy)
            let size = Double.maximum(
                span(h0.apply(cx - 60.0, cy), h0.apply(cx + 60.0, cy)),
                span(h0.apply(cx, cy - 60.0), h0.apply(cx, cy + 60.0))
            )
            return PetalFinder(x: x, y: y, size: size)
        }
        let short = Double(min(image.width, image.height))
        for finder in expected
        where !(finder.x.isFinite && finder.y.isFinite && finder.size.isFinite) || finder.size > short {
            return nil
        }
        let previouslyInferred = previous.inferredCorner
        var found: [PetalFinder?] = (0..<4).map { index in
            previouslyInferred == index ? nil : PetalLocator.follow(image, expected: expected[index])
        }
        // the mean movement of the corners that were followed predicts the others
        var moved: [(x: Double, y: Double)] = []
        for index in 0..<4 {
            if let f = found[index] { moved.append((f.x - expected[index].x, f.y - expected[index].y)) }
        }
        if moved.count < 3 { return nil }
        var sumX = -0.0
        for m in moved { sumX += m.x }
        var sumY = -0.0
        for m in moved { sumY += m.y }
        let shift = (x: sumX / Double(moved.count), y: sumY / Double(moved.count))
        func predicted(_ index: Int) -> PetalFinder {
            PetalFinder(x: expected[index].x + shift.x, y: expected[index].y + shift.y, size: expected[index].size)
        }
        // a corner that was hidden is seen again only when its blossom is found right where
        // the others say it is (a bright thumb beside it must not count)
        if let m = previouslyInferred, (0..<4).contains(m) {
            let at = predicted(m)
            found[m] = PetalLocator.follow(image, expected: at).flatMap { f in
                let dx = f.x - at.x
                let dy = f.y - at.y
                return (dx * dx + dy * dy).squareRoot() <= 0.25 * at.size ? f : nil
            }
        }
        let lost = (0..<4).filter { found[$0] == nil }
        let inferred: Int?
        switch lost.count {
        case 0:
            inferred = nil
        case 1:
            found[lost[0]] = predicted(lost[0])
            inferred = lost[0]
        default:
            return nil
        }
        var corners = found.map { $0 ?? expected[0] }
        if let m = inferred { corners = refineInferredCorner(image, corners, inferred: m) }
        let points = corners.map { PetalPoint(x: $0.x, y: $0.y) }
        guard let h = PetalHomography.fit(from: PetalLayout.finderCenters, to: points),
              let reference = referenceLevels(image, h, inferred: inferred) else { return nil }
        let d = readLaneD(image, h, reference)
        let patches = samplePatches(image, h)
        let lanes = readTileLanes(patches, reference, options.templateSigmas)
        if lanes.p == nil && lanes.k == nil && d == nil { return nil }
        return PetalDecodedFrame(
            homography: h,
            rotation: previous.rotation,
            mirrored: previous.mirrored,
            p: lanes.p,
            k: lanes.k,
            d: d,
            inferredCorner: inferred
        )
    }

    /// Reads all lanes with a known canvas-to-pixel homography (no finder
    /// search).
    ///
    /// Returns `nil` when the image is unusable or the finder reference
    /// levels are too weak. Used by trackers that already know the pose, by
    /// refinement passes and by qualification tooling with a ground-truth
    /// pose.
    public static func decode(
        _ image: PetalLuma,
        homography: PetalHomography,
        options: PetalDecodeOptions = PetalDecodeOptions()
    ) -> PetalDecodedFrame? {
        guard isSupported(image, options: options) else { return nil }
        return image.withView { view in
            guard let reference = referenceLevels(view, homography, inferred: nil) else { return nil }
            return finish(
                view,
                options,
                rotation: 0,
                mirrored: false,
                homography: homography,
                reference: reference,
                d: nil,
                inferredCorner: nil
            )
        }
    }

    /// Builds the cells a decoder believes it saw, for diagnostics.
    ///
    /// Tiles are taken from the level read (the one that judges against the
    /// finder levels), even for a frame whose lanes were rescued by the
    /// normalised read. Returns `nil` for an image ``decode(_:options:)``
    /// refuses.
    public static func observedCells(
        _ image: PetalLuma,
        frame: PetalDecodedFrame,
        options: PetalDecodeOptions = PetalDecodeOptions()
    ) -> PetalFrameCells? {
        guard isSupported(image, options: options) else { return nil }
        return image.withView { view in
            guard let reference = referenceLevels(view, frame.homography, inferred: frame.inferredCorner) else {
                return nil
            }
            let patches = samplePatches(view, frame.homography)
            let reads = readTiles(patches, reference, options.templateSigmas)
            let words = tileWords(reads)
            let (d, _) = readDots(view, frame.homography, reference)
            return PetalFrameCells(validatedP: words.p, k: words.k, d: d)
        }
    }

    /// Mean squared tile-match error of the level read, a quick image-quality
    /// indicator.
    ///
    /// It can be large for a frame whose lanes were rescued by the normalised
    /// read, which is the point: the finder levels did not describe that
    /// picture. Returns `nil` for an image ``decode(_:options:)`` refuses.
    public static func tileMatchError(
        _ image: PetalLuma,
        frame: PetalDecodedFrame,
        options: PetalDecodeOptions = PetalDecodeOptions()
    ) -> Double? {
        guard isSupported(image, options: options) else { return nil }
        return image.withView { view in
            guard let reference = referenceLevels(view, frame.homography, inferred: frame.inferredCorner) else {
                return nil
            }
            let patches = samplePatches(view, frame.homography)
            let reads = readTiles(patches, reference, options.templateSigmas)
            var total = -0.0
            for read in reads { total += read.error }
            return total / Double(reads.count)
        }
    }

    private static func isSupported(_ image: PetalLuma, options: PetalDecodeOptions) -> Bool {
        let (pixels, overflow) = image.width.multipliedReportingOverflow(by: image.height)
        return image.width >= 48 && image.height >= 48
            && !overflow && pixels <= options.maximumPixels
            && image.pixels.count == pixels
    }

    // MARK: - Orientation

    /// One hypothesis: gate score, `天` score, orientation, pose and levels.
    struct Scored {
        let gate: Double
        let mask: Double
        let rotation: Int
        let mirrored: Bool
        let homography: PetalHomography
        let reference: Reference
    }

    /// Reads one finder candidate: ranks its orientation hypotheses by gate
    /// score plus `天` score, tries lane `D` under the best three whose gate
    /// score is at least 0.2, then the tile lanes under the best four.
    static func decodeCandidate(
        _ image: PetalLumaView,
        _ options: PetalDecodeOptions,
        _ set: PetalFinderSet
    ) -> PetalDecodedFrame? {
        let corners = set.inferred.map { refineInferredCorner(image, set.corners, inferred: $0) } ?? set.corners
        var scored: [Scored] = []
        for hypothesis in hypotheses(corners, tryMirrored: options.tryMirrored) {
            let inferred = set.inferred.map {
                canonicalCorner($0, rotation: hypothesis.rotation, mirrored: hypothesis.mirrored)
            }
            let h = hypothesis.homography
            guard let reference = referenceLevels(image, h, inferred: inferred) else { continue }
            scored.append(Scored(
                gate: gateScore(image, h, reference),
                mask: maskScore(image, h, reference),
                rotation: hypothesis.rotation,
                mirrored: hypothesis.mirrored,
                homography: h,
                reference: reference
            ))
        }
        // Stable descending sort under total order (Rust `sort_by`).
        let keys = scored.map { PetalNumeric.totalOrderKey($0.gate + $0.mask) }
        let ranked = scored.indices.sorted { left, right in
            keys[left] != keys[right] ? keys[left] > keys[right] : left < right
        }.map { scored[$0] }
        func inferredCorner(_ candidate: Scored) -> Int? {
            set.inferred.map { canonicalCorner($0, rotation: candidate.rotation, mirrored: candidate.mirrored) }
        }
        // 1. the ring beacon is the cheapest and strongest orientation check
        for candidate in ranked.prefix(3) {
            if candidate.gate < 0.2 { continue }
            if let d = readLaneD(image, candidate.homography, candidate.reference) {
                return finish(
                    image,
                    options,
                    rotation: candidate.rotation,
                    mirrored: candidate.mirrored,
                    homography: candidate.homography,
                    reference: candidate.reference,
                    d: d,
                    inferredCorner: inferredCorner(candidate)
                )
            }
        }
        // 2. fall back to the tile lanes under the most promising orientations
        for candidate in ranked.prefix(4) {
            let patches = samplePatches(image, candidate.homography)
            let lanes = readTileLanes(patches, candidate.reference, options.templateSigmas)
            if lanes.p != nil || lanes.k != nil {
                return PetalDecodedFrame(
                    homography: candidate.homography,
                    rotation: candidate.rotation,
                    mirrored: candidate.mirrored,
                    p: lanes.p,
                    k: lanes.k,
                    d: readLaneD(image, candidate.homography, candidate.reference),
                    inferredCorner: inferredCorner(candidate)
                )
            }
        }
        return nil
    }

    /// Canonical index of the corner at index `index` of a finder quad under
    /// one orientation hypothesis.
    static func canonicalCorner(_ index: Int, rotation: Int, mirrored: Bool) -> Int {
        mirrored ? (rotation + 4 - index) % 4 : (index + 4 - rotation) % 4
    }

    struct Hypothesis {
        let rotation: Int
        let mirrored: Bool
        let homography: PetalHomography
    }

    static func hypotheses(_ finders: [PetalFinder], tryMirrored: Bool) -> [Hypothesis] {
        let canonical = PetalLayout.finderCenters
        var out: [Hypothesis] = []
        for mirrored in [false, true] {
            if mirrored && !tryMirrored { continue }
            for rotation in 0..<4 {
                let destination = (0..<4).map { i -> PetalPoint in
                    let q = mirrored ? finders[(rotation + 4 - i) % 4] : finders[(i + rotation) % 4]
                    return PetalPoint(x: q.x, y: q.y)
                }
                if let homography = PetalHomography.fit(from: canonical, to: destination) {
                    out.append(Hypothesis(rotation: rotation, mirrored: mirrored, homography: homography))
                }
            }
        }
        return out
    }

    // MARK: - Reference levels and dots

    /// Lit and dark levels at the four finders, interpolated over the canvas.
    struct Reference: Equatable, Sendable {
        let lit: [Double]
        let dark: [Double]

        /// Bilinear interpolation over the canvas of the four corner estimates.
        @inline(__always)
        func at(_ x: Double, _ y: Double) -> (lit: Double, dark: Double) {
            let u = PetalNumeric.clamp(x / 1024.0, 0.0, 1.0)
            let v = PetalNumeric.clamp(y / 1024.0, 0.0, 1.0)
            func mix(_ c: [Double]) -> Double {
                let top = c[0] * (1.0 - u) + c[1] * u
                let bottom = c[3] * (1.0 - u) + c[2] * u
                return top * (1.0 - v) + bottom * v
            }
            return (mix(lit), mix(dark))
        }
    }

    @inline(__always)
    static func dotSamples(
        _ image: PetalLumaView,
        _ h: PetalHomography,
        _ x: Double,
        _ y: Double,
        _ spread: Double
    ) -> Double {
        var sum = 0.0
        var (px, py) = h.apply(x + 0.0, y + 0.0)
        sum += image.sample(px, py)
        (px, py) = h.apply(x + spread, y + 0.0)
        sum += image.sample(px, py)
        (px, py) = h.apply(x + -spread, y + 0.0)
        sum += image.sample(px, py)
        (px, py) = h.apply(x + 0.0, y + spread)
        sum += image.sample(px, py)
        (px, py) = h.apply(x + 0.0, y + -spread)
        sum += image.sample(px, py)
        return sum / 5.0
    }

    /// Light and dark levels at the four corners: the solid blossom core, and
    /// the black canvas 100 units inward of it. An `inferred` corner
    /// (canonical index) was not seen, so its levels are extrapolated from the
    /// other three by the parallelogram rule and kept within their range.
    static func referenceLevels(_ image: PetalLumaView, _ h: PetalHomography, inferred: Int?) -> Reference? {
        var lit = [Double](repeating: 0, count: 4)
        var dark = [Double](repeating: 0, count: 4)
        let tau = 2 * Double.pi
        for (i, center) in PetalLayout.finderCenters.enumerated() where i != inferred {
            let cx = center.x
            let cy = center.y
            // the blossom is solid out to radius 24 around its centre
            var (px, py) = h.apply(cx, cy)
            var sum = image.sample(px, py)
            for k in 0..<8 {
                let angle = tau * Double(k) / 8.0
                (px, py) = h.apply(cx + 20.0 * cos(angle), cy + 20.0 * sin(angle))
                sum += image.sample(px, py)
            }
            lit[i] = sum / 9.0
            let sx = cx < 512.0 ? 1.0 : -1.0
            let sy = cy < 512.0 ? 1.0 : -1.0
            let a = dotSamples(image, h, cx + sx * 100.0, cy, 5.0)
            let b = dotSamples(image, h, cx, cy + sy * 100.0, 5.0)
            dark[i] = 0.5 * (a + b)
            // a NaN contrast (from a broken pose) refuses as well
            if !(lit[i] - dark[i]).isFinite || lit[i] - dark[i] < 12.0 { return nil }
        }
        if let m = inferred {
            let n1 = (m + 1) % 4
            let opposite = (m + 2) % 4
            let n2 = (m + 3) % 4
            func extrapolate(_ v: [Double]) -> Double {
                let low = Double.minimum(Double.minimum(v[n1], v[opposite]), v[n2])
                let high = Double.maximum(Double.maximum(v[n1], v[opposite]), v[n2])
                return PetalNumeric.clamp(v[n1] + v[n2] - v[opposite], low, high)
            }
            lit[m] = extrapolate(lit)
            dark[m] = extrapolate(dark)
            // uneven light can push the estimates past each other; an inferred
            // corner needs the same contrast as a seen one
            if lit[m] - dark[m] < 12.0 { return nil }
        }
        return Reference(lit: lit, dark: dark)
    }

    /// Centres of the lattice cells outside the `天` mask (no tile is ever
    /// drawn there), row-major.
    static let emptyCells: [PetalPoint] = {
        var cells: [PetalPoint] = []
        for (row, line) in PetalLayout.mask.enumerated() {
            for (column, mark) in line.enumerated() where mark != "#" {
                cells.append(PetalPoint(
                    x: PetalLayout.tileOrigin + PetalLayout.tilePitch * (Double(column) + 0.5),
                    y: PetalLayout.tileOrigin + PetalLayout.tilePitch * (Double(row) + 0.5)
                ))
            }
        }
        return cells
    }()

    /// How well the `天` lines up: the mean normalised level over the tiles
    /// (each sampled at five points across the tile, so a glyph stroke at the
    /// centre does not decide it) minus the mean over the empty lattice cells.
    /// The mask is symmetric left to right but not top to bottom, so this
    /// tells the four quarter turns apart even when the ring gates are
    /// damaged.
    static func maskScore(_ image: PetalLumaView, _ h: PetalHomography, _ reference: Reference) -> Double {
        @inline(__always)
        func level(_ x: Double, _ y: Double) -> Double {
            let (lit, dark) = reference.at(x, y)
            return (dotSamples(image, h, x, y, 8.0) - dark) / (lit - dark)
        }
        var tiles = -0.0
        for tile in 0..<PetalLayout.tileCount {
            let center = PetalLayout.tileCenter(tile)
            tiles += level(center.x, center.y)
        }
        var empty = -0.0
        for cell in emptyCells { empty += level(cell.x, cell.y) }
        return tiles / Double(PetalLayout.tileCount) - empty / Double(emptyCells.count)
    }

    /// The brightness summed over all ring slots under the pose that maps the
    /// canonical corners onto `corners` (in quad order). The slots form the
    /// same set of points under every quarter turn and mirror of the canvas
    /// (80, 92 and 104 are multiples of four), so the value does not depend on
    /// the orientation.
    static func ringBrightness(_ image: PetalLumaView, _ corners: [PetalPoint]) -> Double? {
        guard let h = PetalHomography.fit(from: PetalLayout.finderCenters, to: corners) else { return nil }
        var sum = -0.0
        for center in PetalLayout.flatSlotCenters {
            sum += dotSamples(image, h, center.x, center.y, 3.5)
        }
        return sum
    }

    /// Moves an inferred corner to where the three dotted rings line up best:
    /// a 13 × 13 search in steps of 2 % of the mean leg around the
    /// parallelogram estimate, then a 9 × 9 search in steps of 0.5 % around the
    /// best point. The rings fix the geometry only; the orientation is decided
    /// afterwards by the gates and the `天`.
    static func refineInferredCorner(
        _ image: PetalLumaView,
        _ corners: [PetalFinder],
        inferred: Int
    ) -> [PetalFinder] {
        var points = corners.map { PetalPoint(x: $0.x, y: $0.y) }
        let start = points[inferred]
        func distance(_ other: Int) -> Double {
            let dx = points[other].x - start.x
            let dy = points[other].y - start.y
            return (dx * dx + dy * dy).squareRoot()
        }
        let leg = 0.5 * (distance((inferred + 1) % 4) + distance((inferred + 3) % 4))
        var best = (brightness: -Double.greatestFiniteMagnitude, point: start)
        func search(_ centre: PetalPoint, step: Double, reach: Int) {
            for dy in -reach...reach {
                for dx in -reach...reach {
                    let candidate = PetalPoint(x: centre.x + Double(dx) * step, y: centre.y + Double(dy) * step)
                    points[inferred] = candidate
                    if let brightness = ringBrightness(image, points), brightness > best.brightness {
                        best = (brightness, candidate)
                    }
                }
            }
        }
        search(start, step: 0.02 * leg, reach: 6)
        search(best.point, step: 0.005 * leg, reach: 4)
        var refined = corners
        refined[inferred] = PetalFinder(x: best.point.x, y: best.point.y, size: corners[inferred].size)
        return refined
    }

    @inline(__always)
    static func normalisedDot(
        _ image: PetalLumaView,
        _ h: PetalHomography,
        _ reference: Reference,
        _ flat: Int
    ) -> Double {
        let center = PetalLayout.flatSlotCenters[flat]
        let (lit, dark) = reference.at(center.x, center.y)
        return (dotSamples(image, h, center.x, center.y, 3.5) - dark) / (lit - dark)
    }

    static func gateScore(_ image: PetalLumaView, _ h: PetalHomography, _ reference: Reference) -> Double {
        func mean(_ slots: [Int]) -> Double {
            var sum = -0.0
            for slot in slots { sum += normalisedDot(image, h, reference, slot) }
            return sum / Double(slots.count)
        }
        return mean(PetalLayout.gateSlots) - mean(PetalLayout.guardSlots)
    }

    /// Reads lane `D`: the transmitted bytes and per-byte confidence.
    static func readDots(
        _ image: PetalLumaView,
        _ h: PetalHomography,
        _ reference: Reference
    ) -> ([UInt8], [Double]) {
        // per-ring thresholds from the gates (lit) and guards (dark)
        var thresholds = [Double](repeating: 0.5, count: PetalLayout.ringCount)
        for ring in 0..<PetalLayout.ringCount {
            var litSum = -0.0
            var litCount = 0
            for slot in PetalLayout.gateSlots where PetalLayout.splitSlot(slot).ring == ring {
                litSum += normalisedDot(image, h, reference, slot)
                litCount += 1
            }
            var darkSum = -0.0
            var darkCount = 0
            for slot in PetalLayout.guardSlots where PetalLayout.splitSlot(slot).ring == ring {
                darkSum += normalisedDot(image, h, reference, slot)
                darkCount += 1
            }
            if litCount > 0 && darkCount > 0 {
                let l = litSum / Double(litCount)
                let d = darkSum / Double(darkCount)
                if l - d > 0.2 { thresholds[ring] = 0.5 * (l + d) }
            }
        }
        var bytes = [UInt8](repeating: 0, count: PetalLane.d.wordLength)
        var confidence = [Double](repeating: .greatestFiniteMagnitude, count: PetalLane.d.wordLength)
        for (bit, slot) in PetalLayout.dataSlots.enumerated() {
            let value = normalisedDot(image, h, reference, slot)
            let threshold = thresholds[PetalLayout.splitSlot(slot).ring]
            if value > threshold { bytes[bit / 8] |= 1 << (7 - bit % 8) }
            confidence[bit / 8] = Double.minimum(confidence[bit / 8], abs(value - threshold))
        }
        return (bytes, confidence)
    }

    /// Lane `D` under one pose.
    static func readLaneD(
        _ image: PetalLumaView,
        _ h: PetalHomography,
        _ reference: Reference
    ) -> PetalLaneResult? {
        let (word, confidence) = readDots(image, h, reference)
        return decodeWithErasures(.d, word, confidence)
    }

    /// Tries Reed–Solomon with growing numbers of erasures, least confident
    /// first.
    ///
    /// The schedule erases 0, ⅛, ¼, ⅓ and ½ of the parity bytes, and for lane
    /// `K` also ⅔. Lanes `D` and `P` stop at ½: their words have only 11 and
    /// 13 parity bytes, and a further erasure step leaves so few spare ones
    /// that it accepts wrong codewords (lane `D` at 7 erasures: about 0.4 % of
    /// random words, and 5 wrong lanes in 2 900 simulated harsh frames; lane
    /// `P` at 8: 2 wrong lanes in 600 banded 480p frames). Capping them costs
    /// 0.65 % of the lane `D` reads and 0.15 % of the lane `P` reads in those
    /// frames.
    static func decodeWithErasures(_ lane: PetalLane, _ word: [UInt8], _ confidence: [Double]) -> PetalLaneResult? {
        let nsym = lane.parityLength
        let keys = confidence.map(PetalNumeric.totalOrderKey)
        // Stable ascending sort under total order (Rust `sort_by`).
        let order = word.indices.sorted { a, b in
            keys[a] != keys[b] ? keys[a] < keys[b] : a < b
        }
        var steps = [0, nsym / 8, nsym / 4, nsym / 3, nsym / 2]
        if lane == .k { steps.append(nsym * 2 / 3) }
        // Rust `Vec::dedup`: drop consecutive repeats.
        var schedule: [Int] = []
        for erasures in steps where schedule.last != erasures {
            schedule.append(erasures)
        }
        for erasures in schedule {
            let positions = Array(order.prefix(erasures))
            var trial = word
            // zero the erased bytes so stale values cannot leak through
            for position in positions { trial[position] = 0 }
            if let result = try? lane.decodeCounted(trial, erasures: positions) {
                return PetalLaneResult(data: result.data, corrected: result.corrected, erasures: positions.count)
            }
        }
        return nil
    }

    // MARK: - Tiles

    /// `patterns[(polarity * 16 + glyph) * 64 + cell]`: the expected
    /// normalised patch for each of the 32 hypotheses.
    static func buildPatterns(_ sigma: Double) -> [Double] {
        var raw = [Double](repeating: 0, count: 5)
        for i in -2...2 {
            if sigma < 0.05 {
                raw[i + 2] = i == 0 ? 1.0 : 0.0
            } else {
                let di = Double(i)
                raw[i + 2] = exp(-(di * di) / (2.0 * sigma * sigma))
            }
        }
        var sum = -0.0
        for value in raw { sum += value }
        let kernel = raw.map { $0 / sum }
        var patterns = [Double](repeating: 0, count: hypothesisCount * cells)
        var hypothesis = 0
        for polarity in 0..<2 {
            for template in PetalGlyphs.templates {
                let coverage = template.map { Double($0) / 255.0 }
                for v in 0..<patch {
                    for u in 0..<patch {
                        var acc = 0.0
                        for (ky, wy) in kernel.enumerated() {
                            for (kx, wx) in kernel.enumerated() {
                                let sx = u + kx - 2
                                let sy = v + ky - 2
                                if sx >= 0 && sx < patch && sy >= 0 && sy < patch {
                                    acc += wx * wy * coverage[sy * patch + sx]
                                }
                            }
                        }
                        let index = hypothesis * cells + v * patch + u
                        patterns[index] = polarity == 1
                            ? 1.0 - (1.0 - inkOnLight) * acc
                            : pinkOnDark * acc
                    }
                }
                hypothesis += 1
            }
        }
        return patterns
    }

    struct TileRead {
        let light: Bool
        let glyph: UInt8
        let polarityMargin: Double
        let glyphMargin: Double
        let error: Double
    }

    /// The raw 8×8 luma patch of every tile, as captured: row-major, 64 cells
    /// per tile, each the mean of four bilinear samples at ±¼ cell, in luma
    /// levels (no reference levels applied).
    static func samplePatches(_ image: PetalLumaView, _ h: PetalHomography) -> [Double] {
        var patches = [Double](repeating: 0, count: PetalLayout.tileCount * cells)
        let half = PetalLayout.glyphBox / 2.0
        let cell = PetalLayout.glyphBox / Double(patch)
        let offsets: [(Double, Double)] = [(-0.25, -0.25), (0.25, -0.25), (-0.25, 0.25), (0.25, 0.25)]
        patches.withUnsafeMutableBufferPointer { patches in
            for tile in 0..<PetalLayout.tileCount {
                let center = PetalLayout.tileCenter(tile)
                let cx = center.x
                let cy = center.y
                let base = tile * cells
                for v in 0..<patch {
                    for u in 0..<patch {
                        let gx = cx - half + (Double(u) + 0.5) * cell
                        let gy = cy - half + (Double(v) + 0.5) * cell
                        var sum = 0.0
                        for (ox, oy) in offsets {
                            let (px, py) = h.apply(gx + ox * cell, gy + oy * cell)
                            sum += image.sample(px, py)
                        }
                        patches[base + v * patch + u] = sum / 4.0
                    }
                }
            }
        }
        return patches
    }

    /// The robust darkest and brightest level of a patch: the values
    /// `patchCut` cells in from either end of the sorted cells.
    ///
    /// `values` holds one patch (64 cells). The sort follows the IEEE total
    /// order (Rust `sort_by(f64::total_cmp)`), so a damaged cell cannot make
    /// the result depend on the sorting algorithm.
    static func patchLevels(_ values: UnsafeBufferPointer<Double>) -> (low: Double, high: Double) {
        withUnsafeTemporaryAllocation(of: Double.self, capacity: cells) { sorted in
            // insertion sort: 64 cells, no allocation
            for index in 0..<cells {
                let value = values[index]
                let key = PetalNumeric.totalOrderKey(value)
                var slot = index
                while slot > 0 && PetalNumeric.totalOrderKey(sorted[slot - 1]) > key {
                    sorted[slot] = sorted[slot - 1]
                    slot -= 1
                }
                sorted[slot] = value
            }
            return (sorted[patchCut], sorted[cells - 1 - patchCut])
        }
    }

    /// Maps a patch's own darkest level to 0 and brightest to 1, in place,
    /// with `floor` as the smallest span that counts as contrast. Results are
    /// clamped to [-0.25, 1.25].
    static func rescale(_ values: UnsafeMutableBufferPointer<Double>, floor: Double) {
        let (low, high) = patchLevels(UnsafeBufferPointer(values))
        let range = Double.maximum(high - low, floor)
        for index in 0..<cells {
            values[index] = PetalNumeric.clamp((values[index] - low) / range, -0.25, 1.25)
        }
    }

    /// Picks for every patch the polarity and glyph whose template matches
    /// best.
    ///
    /// `patches` holds 64 cells per tile. The template blur is chosen per
    /// frame, by the lowest total error. With `rescaleTemplates` the templates
    /// are rescaled like the patches; tiles flagged in `erased` get zero
    /// margins, so they are the first the Reed–Solomon decoder treats as
    /// erasures.
    static func classify(
        _ patches: [Double],
        _ sigmas: [Double],
        rescaleTemplates: Bool,
        erased: [Bool]
    ) -> [TileRead] {
        var bestTotal = Double.greatestFiniteMagnitude
        var bestReads: [TileRead] = []
        var errors = [Double](repeating: 0, count: hypothesisCount)
        for sigma in sigmas {
            var patterns = buildPatterns(sigma)
            if rescaleTemplates {
                patterns.withUnsafeMutableBufferPointer { patterns in
                    for hypothesis in 0..<hypothesisCount {
                        let base = hypothesis * cells
                        rescale(UnsafeMutableBufferPointer(rebasing: patterns[base..<base + cells]), floor: 0.001)
                    }
                }
            }
            var total = 0.0
            var reads: [TileRead] = []
            reads.reserveCapacity(PetalLayout.tileCount)
            patches.withUnsafeBufferPointer { patches in
                patterns.withUnsafeBufferPointer { patterns in
                    errors.withUnsafeMutableBufferPointer { errors in
                        for tile in 0..<PetalLayout.tileCount {
                            let patchBase = tile * cells
                            for hypothesis in 0..<hypothesisCount {
                                let patternBase = hypothesis * cells
                                var error = -0.0
                                for index in 0..<cells {
                                    let difference = patches[patchBase + index] - patterns[patternBase + index]
                                    error += difference * difference
                                }
                                errors[hypothesis] = error
                            }
                            let best = PetalNumeric.firstMinimumIndex(UnsafeBufferPointer(errors))
                            let polarity = best / PetalGlyphs.count
                            let glyph = best % PetalGlyphs.count
                            var otherPolarity = Double.greatestFiniteMagnitude
                            var otherGlyph = Double.greatestFiniteMagnitude
                            for g in 0..<PetalGlyphs.count {
                                otherPolarity = Double.minimum(
                                    otherPolarity,
                                    errors[(1 - polarity) * PetalGlyphs.count + g]
                                )
                                if g != glyph {
                                    otherGlyph = Double.minimum(otherGlyph, errors[polarity * PetalGlyphs.count + g])
                                }
                            }
                            total += errors[best]
                            let flagged = erased[tile]
                            reads.append(TileRead(
                                light: polarity == 1,
                                glyph: UInt8(glyph),
                                polarityMargin: flagged ? 0.0 : otherPolarity - errors[best],
                                glyphMargin: flagged ? 0.0 : otherGlyph - errors[best],
                                error: errors[best]
                            ))
                        }
                    }
                }
            }
            if total < bestTotal {
                bestTotal = total
                bestReads = reads
            }
        }
        return bestReads
    }

    /// The level read: every patch is judged against the light and dark
    /// levels measured at the finders, interpolated to the tile.
    static func levelledPatches(_ patches: [Double], _ reference: Reference) -> [Double] {
        var levelled = patches
        levelled.withUnsafeMutableBufferPointer { levelled in
            for tile in 0..<PetalLayout.tileCount {
                let center = PetalLayout.tileCenter(tile)
                let (lit, dark) = reference.at(center.x, center.y)
                let base = tile * cells
                for index in base..<base + cells {
                    levelled[index] = (levelled[index] - dark) / (lit - dark)
                }
            }
        }
        return levelled
    }

    static func readTiles(_ patches: [Double], _ reference: Reference, _ sigmas: [Double]) -> [TileRead] {
        return classify(
            levelledPatches(patches, reference),
            sigmas,
            rescaleTemplates: false,
            erased: [Bool](repeating: false, count: PetalLayout.tileCount)
        )
    }

    /// The normalised read: every patch and every template is rescaled by its
    /// own contrast before they are compared, so the judgement does not
    /// depend on absolute levels. Tiles whose contrast is below `weakTile`
    /// times the median tile contrast are flagged as erasures.
    static func readTilesNormalised(_ patches: [Double], _ sigmas: [Double]) -> [TileRead] {
        var spans = [Double](repeating: 0, count: PetalLayout.tileCount)
        var scaled = patches
        patches.withUnsafeBufferPointer { patches in
            scaled.withUnsafeMutableBufferPointer { scaled in
                for tile in 0..<PetalLayout.tileCount {
                    let base = tile * cells
                    let (low, high) = patchLevels(UnsafeBufferPointer(rebasing: patches[base..<base + cells]))
                    spans[tile] = high - low
                    rescale(UnsafeMutableBufferPointer(rebasing: scaled[base..<base + cells]), floor: 1.0)
                }
            }
        }
        // element `tileCount / 2` of the ascending spans, under the IEEE total order
        let median = spans.sorted {
            PetalNumeric.totalOrderKey($0) < PetalNumeric.totalOrderKey($1)
        }[PetalLayout.tileCount / 2]
        var erased = [Bool](repeating: false, count: PetalLayout.tileCount)
        for (tile, span) in spans.enumerated() { erased[tile] = span < weakTile * median }
        return classify(scaled, sigmas, rescaleTemplates: true, erased: erased)
    }

    /// Lanes `P` and `K` from one set of patches: the level read first, then,
    /// for any lane still unreadable, the normalised read.
    static func readTileLanes(
        _ patches: [Double],
        _ reference: Reference,
        _ sigmas: [Double]
    ) -> (p: PetalLaneResult?, k: PetalLaneResult?) {
        let words = tileWords(readTiles(patches, reference, sigmas))
        var p = decodeWithErasures(.p, words.p, words.pConfidence)
        var k = decodeWithErasures(.k, words.k, words.kConfidence)
        if p == nil || k == nil {
            let words = tileWords(readTilesNormalised(patches, sigmas))
            if p == nil { p = decodeWithErasures(.p, words.p, words.pConfidence) }
            if k == nil { k = decodeWithErasures(.k, words.k, words.kConfidence) }
        }
        return (p, k)
    }

    /// Samples the tile field of `image` under the pose that decoded `frame`.
    /// Returns `nil` for an unusable image, an invalid inferred corner, or
    /// finder levels too weak to read. Evidence is in canonical code coordinates,
    /// so captures may have different positions, rotations and reflections.
    public static func tileEvidence(
        _ image: PetalLuma,
        frame: PetalDecodedFrame,
        options: PetalDecodeOptions = PetalDecodeOptions()
    ) -> PetalTileEvidence? {
        guard isSupported(image, options: options),
              frame.inferredCorner.map({ (0...3).contains($0) }) ?? true else { return nil }
        return image.withView { view in
            guard let reference = referenceLevels(view, frame.homography, inferred: frame.inferredCorner) else {
                return nil
            }
            return PetalTileEvidence(patches: samplePatches(view, frame.homography), reference: reference)
        }
    }

    /// Reads tile lanes from the average of captures of one shown frame.
    /// The level read averages patches after applying each capture's finder
    /// levels. Any lane still unreadable is tried with the normalised read of
    /// the mean raw patches. One capture reads exactly its original tile lanes.
    /// The caller must group evidence using independently decoded lane headers
    /// and check each recovered lane's header before offering its atoms.
    public static func mergeTiles(
        _ evidence: [PetalTileEvidence],
        options: PetalDecodeOptions = PetalDecodeOptions()
    ) -> (p: PetalLaneResult?, k: PetalLaneResult?) {
        guard !evidence.isEmpty else { return (nil, nil) }
        // Sum cell by cell in capture order, matching the Rust reference.
        func mean(_ patches: (PetalTileEvidence) -> [Double]) -> [Double] {
            var result = [Double](repeating: 0, count: PetalLayout.tileCount * cells)
            for capture in evidence {
                let values = patches(capture)
                for index in result.indices { result[index] += values[index] }
            }
            for index in result.indices { result[index] /= Double(evidence.count) }
            return result
        }
        let levelled = mean { levelledPatches($0.patches, $0.reference) }
        let reads = classify(
            levelled, options.templateSigmas, rescaleTemplates: false,
            erased: [Bool](repeating: false, count: PetalLayout.tileCount)
        )
        var words = tileWords(reads)
        var p = decodeWithErasures(.p, words.p, words.pConfidence)
        var k = decodeWithErasures(.k, words.k, words.kConfidence)
        if p == nil || k == nil {
            words = tileWords(readTilesNormalised(mean { $0.patches }, options.templateSigmas))
            if p == nil { p = decodeWithErasures(.p, words.p, words.pConfidence) }
            if k == nil { k = decodeWithErasures(.k, words.k, words.kConfidence) }
        }
        return (p, k)
    }

    struct TileWords {
        var p: [UInt8]
        var pConfidence: [Double]
        var k: [UInt8]
        var kConfidence: [Double]
    }

    static func tileWords(_ reads: [TileRead]) -> TileWords {
        var words = TileWords(
            p: [UInt8](repeating: 0, count: PetalLane.p.wordLength),
            pConfidence: [Double](repeating: .greatestFiniteMagnitude, count: PetalLane.p.wordLength),
            k: [UInt8](repeating: 0, count: PetalLane.k.wordLength),
            kConfidence: [Double](repeating: .greatestFiniteMagnitude, count: PetalLane.k.wordLength)
        )
        for (tile, read) in reads.enumerated() {
            if read.light { words.p[tile / 8] |= 1 << (7 - tile % 8) }
            words.pConfidence[tile / 8] = Double.minimum(words.pConfidence[tile / 8], read.polarityMargin)
            words.k[tile / 2] |= tile % 2 == 0 ? read.glyph << 4 : read.glyph
            words.kConfidence[tile / 2] = Double.minimum(
                words.kConfidence[tile / 2],
                Double.minimum(read.glyphMargin, read.polarityMargin)
            )
        }
        return words
    }

    static func finish(
        _ image: PetalLumaView,
        _ options: PetalDecodeOptions,
        rotation: Int,
        mirrored: Bool,
        homography h: PetalHomography,
        reference: Reference,
        d: PetalLaneResult?,
        inferredCorner: Int?
    ) -> PetalDecodedFrame {
        let d = d ?? readLaneD(image, h, reference)
        let patches = samplePatches(image, h)
        let lanes = readTileLanes(patches, reference, options.templateSigmas)
        return PetalDecodedFrame(
            homography: h,
            rotation: rotation,
            mirrored: mirrored,
            p: lanes.p,
            k: lanes.k,
            d: d,
            inferredCorner: inferredCorner
        )
    }
}
