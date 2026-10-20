import Foundation

/// Limits of a Petal scan session.
public struct PetalScanLimits: Equatable, Sendable {
    /// Forget a half-received stream after this long without progress.
    public var idleTimeoutMilliseconds: UInt64
    /// Forget a stream that has not finished this long after it started.
    public var absoluteTimeoutMilliseconds: UInt64
    /// Assembler memory and size limits.
    public var assembler: PetalAssemblerLimits
    /// Image decoder options.
    public var decode: PetalDecodeOptions

    public init(
        idleTimeoutMilliseconds: UInt64 = 30_000,
        absoluteTimeoutMilliseconds: UInt64 = 180_000,
        assembler: PetalAssemblerLimits = PetalAssemblerLimits(),
        decode: PetalDecodeOptions = PetalDecodeOptions()
    ) {
        self.idleTimeoutMilliseconds = idleTimeoutMilliseconds
        self.absoluteTimeoutMilliseconds = absoluteTimeoutMilliseconds
        self.assembler = assembler
        self.decode = decode
    }
}

/// Counters for diagnostics and UI hints.
public struct PetalScanStats: Equatable, Sendable {
    /// Camera frames offered.
    public internal(set) var frames: UInt32 = 0
    /// Frames in which the four finders were located, readable or not.
    public internal(set) var located: UInt32 = 0
    /// Frames in which at least one lane decoded.
    public internal(set) var readable: UInt32 = 0
    /// Lane `P` successes.
    public internal(set) var laneP: UInt32 = 0
    /// Lane `K` successes.
    public internal(set) var laneK: UInt32 = 0
    /// Lane `D` successes.
    public internal(set) var laneD: UInt32 = 0
    /// Frames read by tracking the previous pose instead of a full search.
    public internal(set) var tracked: UInt32 = 0
    /// Frames read with one corner finder hidden and inferred.
    public internal(set) var inferred: UInt32 = 0
    /// Merges of two or more captures of one shown frame.
    public internal(set) var merges: UInt32 = 0
    /// Lane `P` reads recovered by merging captures.
    public internal(set) var mergedP: UInt32 = 0
    /// Lane `K` reads recovered by merging captures.
    public internal(set) var mergedK: UInt32 = 0

    public init() {}
}

/// The result of offering one camera frame to a ``PetalScanSession``.
public struct PetalScanOutcome: Equatable, Sendable {
    /// Why the frame produced nothing, when it did not.
    public let error: PetalDecodeError?
    /// Lanes that decoded in this capture alone, as letters from `"PKD"`.
    public let lanes: String
    /// Lanes recovered by merging captures of this shown frame, as letters
    /// from `"PK"`.
    public let merged: String
    /// Receive progress after this frame.
    public let progress: PetalProgress
    /// The finished payload, delivered exactly once.
    public let completed: PetalCompletedPayload?
}

/// The receive-side object an app holds while its camera is open: decodes
/// camera frames and reassembles the stream they carry (port of
/// `crates/iroha_petal/src/session.rs`).
///
/// After a frame decodes, the next frames are first read by tracking the code
/// from its last pose (``PetalDecoder/track(_:previous:options:)``), which
/// skips the finder search; a full ``PetalDecoder/decode(_:options:)`` runs
/// when tracking fails or the last pose is older than
/// ``trackWindowMilliseconds``. A half-received stream is forgotten after
/// ``PetalScanLimits/idleTimeoutMilliseconds`` without progress or
/// ``PetalScanLimits/absoluteTimeoutMilliseconds`` after it started.
/// Repeated captures are held under the frame identity of their decoded lane
/// headers, up to ``mergeCaptures`` captures of ``mergeWindow`` shown frames.
/// Averaging recovers missing tile lanes; a recovered lane is offered only
/// when its header names the same shown frame. Unkeyed and torn captures are
/// never combined.
public struct PetalScanSession: Sendable {
    /// How long a decoded pose stays usable for tracking the next frames.
    public static let trackWindowMilliseconds: UInt64 = 500
    /// Shown frames whose captures are held for merging.
    public static let mergeWindow = 6
    /// Captures held per shown frame; a further capture replaces the oldest.
    public static let mergeCaptures = 4

    /// The session limits.
    public let limits: PetalScanLimits
    private var assembler: PetalStreamAssembler
    /// Diagnostic counters.
    public private(set) var stats = PetalScanStats()
    private var startedMilliseconds: UInt64?
    private var progressMilliseconds: UInt64 = 0
    private var lastRank = 0
    /// The last frame that decoded and when it was captured.
    private var lastPose: (frame: PetalDecodedFrame, at: UInt64)?
    struct Held: Sendable {
        let shown: PetalLaneHeader
        var evidence: [PetalTileEvidence] = []
        var pDone = false
        var kDone = false
    }
    private(set) var held: [Held] = []

    /// Creates a session.
    public init(limits: PetalScanLimits = PetalScanLimits()) {
        self.limits = limits
        assembler = PetalStreamAssembler(limits: limits.assembler)
    }

    /// Current progress.
    public var progress: PetalProgress { assembler.progress }

    /// Drops all partial state.
    public mutating func reset() {
        assembler.reset()
        startedMilliseconds = nil
        lastRank = 0
        lastPose = nil
        held.removeAll()
    }

    /// Offers one camera luma plane captured at monotonic time `nowMilliseconds`.
    public mutating func push(_ image: PetalLuma, nowMilliseconds now: UInt64) -> PetalScanOutcome {
        if let start = startedMilliseconds,
           Self.elapsed(now, since: progressMilliseconds) > limits.idleTimeoutMilliseconds
            || Self.elapsed(now, since: start) > limits.absoluteTimeoutMilliseconds {
            reset()
        }
        stats.frames &+= 1
        var tracked: PetalDecodedFrame?
        if let pose = lastPose, Self.elapsed(now, since: pose.at) <= Self.trackWindowMilliseconds {
            tracked = PetalDecoder.track(image, previous: pose.frame, options: limits.decode)
        }
        if tracked != nil { stats.tracked &+= 1 }
        let result = tracked.map { Result.success($0) } ?? PetalDecoder.decodeResult(image, options: limits.decode)
        let error: PetalDecodeError?
        let lanes: String
        let merged: String
        switch result {
        case .success(let frame):
            error = nil
            if frame.inferredCorner != nil { stats.inferred &+= 1 }
            lastPose = (frame, now)
            lanes = absorb(frame)
            merged = merge(image, frame: frame)
        case .failure(let failure):
            error = failure
            lanes = ""
            merged = ""
        }
        // A code was seen unless no finders were found or the image was unusable.
        if error != .noFinders && error != .unsupportedImage { stats.located &+= 1 }
        let progress = assembler.progress
        if progress.rank > lastRank || (progress.meta != nil && startedMilliseconds == nil) {
            progressMilliseconds = now
            if startedMilliseconds == nil { startedMilliseconds = now }
        }
        lastRank = progress.rank
        return PetalScanOutcome(
            error: error,
            lanes: lanes,
            merged: merged,
            progress: progress,
            completed: assembler.takeCompleted()
        )
    }

    private static func elapsed(_ now: UInt64, since start: UInt64) -> UInt64 {
        now >= start ? now - start : 0
    }

    mutating func absorb(_ frame: PetalDecodedFrame) -> String {
        if frame.p != nil { stats.laneP &+= 1 }
        if frame.k != nil { stats.laneK &+= 1 }
        if frame.d != nil { stats.laneD &+= 1 }
        let lanes = frame.laneLetters
        if !lanes.isEmpty { stats.readable &+= 1 }
        let previousMeta = assembler.progress.meta
        frame.feed(&assembler)
        // The tag is only eight bits: two streams can share a tag and frame
        // counter. Once the assembler accepts a different full stream identity,
        // none of the previous stream's evidence or completed-lane flags apply.
        if let previousMeta, assembler.progress.meta != previousMeta { held.removeAll() }
        return lanes
    }

    /// Returns the header all independently decoded lanes name, or `nil`
    /// when none decoded or a torn capture names different shown frames.
    static func shownFrame(_ frame: PetalDecodedFrame) -> PetalLaneHeader? {
        var shown: PetalLaneHeader?
        for lane in [frame.d, frame.p, frame.k].compactMap({ $0 }) {
            guard lane.data.count >= PetalLane.headerLength else { return nil }
            let header = PetalLaneHeader(
                tag: lane.data[0], frame: UInt16(lane.data[1]) << 8 | UInt16(lane.data[2])
            )
            if let shown, shown != header { return nil }
            shown = header
        }
        return shown
    }

    /// Holds only keyed evidence and fills tile lanes not read earlier for
    /// this shown frame. Recovered atoms must name exactly that frame.
    mutating func merge(_ image: PetalLuma, frame: PetalDecodedFrame) -> String {
        guard let shown = Self.shownFrame(frame) else { return "" }
        let index: Int
        if let existing = held.firstIndex(where: { $0.shown == shown }) {
            index = existing
        } else {
            if held.count == Self.mergeWindow { held.removeFirst() }
            held.append(Held(shown: shown))
            index = held.count - 1
        }
        held[index].pDone = held[index].pDone || frame.p != nil
        held[index].kDone = held[index].kDone || frame.k != nil
        if held[index].pDone && held[index].kDone {
            held[index].evidence.removeAll()
            return ""
        }
        guard let evidence = PetalDecoder.tileEvidence(image, frame: frame, options: limits.decode) else { return "" }
        if held[index].evidence.count == Self.mergeCaptures { held[index].evidence.removeFirst() }
        held[index].evidence.append(evidence)
        if held[index].evidence.count < 2 { return "" }
        stats.merges &+= 1
        let results = PetalDecoder.mergeTiles(held[index].evidence, options: limits.decode)
        var merged = ""
        for (lane, result) in [(PetalLane.p, results.p), (.k, results.k)] {
            guard let result, let packet = PetalStream.parseAtomLane(lane, data: result.data),
                  packet.header == shown else { continue }
            if lane == .p {
                if held[index].pDone { continue }
                held[index].pDone = true
                stats.mergedP &+= 1
            } else {
                if held[index].kDone { continue }
                held[index].kDone = true
                stats.mergedK &+= 1
            }
            assembler.push(atoms: packet)
            merged.append(lane.letter)
        }
        if held[index].pDone && held[index].kDone { held[index].evidence.removeAll() }
        return merged
    }
}
