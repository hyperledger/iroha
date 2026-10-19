import Foundation

public enum IrohaPeerQRFrameKindV1: UInt8, Sendable {
    case complete = 0
    case header = 1
    case data = 2
    case parity = 3
}

public enum IrohaPeerQRErrorV1: Error, Equatable, LocalizedError, Sendable {
    case malformedText
    case nonCanonicalBase45
    case invalidMagic
    case unsupportedWireVersion(UInt8)
    case invalidFrameKind(UInt8)
    case invalidProfile(UInt16)
    case invalidPayloadKind(UInt8)
    case invalidFlags(UInt8)
    case invalidFrameShape
    case checksumMismatch
    case frameTextTooLarge(actual: Int, maximum: Int)
    case messageTooLarge
    case tooManyActiveStreams(maximum: Int)
    case invalidUptime
    case streamQuarantined
    case conflictingDuplicate
    case invalidHeader
    case invalidMessage
    case unexpectedProfile(expected: IrohaPeerWireProfileV1, actual: IrohaPeerWireProfileV1)
    case unexpectedKind(expected: IrohaPeerWireKindV1, actual: IrohaPeerWireKindV1)
    case unexpectedSchemaVersion(expected: UInt16, actual: UInt16)

    public var errorDescription: String? {
        switch self {
        case .malformedText: return "Malformed IQR1 text."
        case .nonCanonicalBase45: return "IQR1 text is not canonical RFC 9285 Base45."
        case .invalidMagic: return "IRQR frame magic mismatch."
        case .unsupportedWireVersion(let value): return "Unsupported IRQR wire version \(value)."
        case .invalidFrameKind(let value): return "Invalid IRQR frame kind \(value)."
        case .invalidProfile(let value): return "Invalid IRQR profile \(value)."
        case .invalidPayloadKind(let value): return "Invalid IRQR payload kind \(value)."
        case .invalidFlags(let value): return "Invalid IRQR flags \(value)."
        case .invalidFrameShape: return "IRQR frame fields are inconsistent."
        case .checksumMismatch: return "IRQR CRC32C mismatch."
        case .frameTextTooLarge(let actual, let maximum):
            return "IQR1 text is \(actual) bytes; the limit is \(maximum)."
        case .messageTooLarge: return "The IPM1 message exceeds the bounded QR stream."
        case .tooManyActiveStreams(let maximum):
            return "The QR decoder already has \(maximum) active streams."
        case .invalidUptime:
            return "QR scanner uptime must be finite, nonnegative, and monotonic until reset."
        case .streamQuarantined: return "The QR stream is quarantined."
        case .conflictingDuplicate: return "The QR stream supplied a conflicting duplicate."
        case .invalidHeader: return "The QR stream IPM1 header is invalid."
        case .invalidMessage: return "The reconstructed IPM1 message is invalid."
        case .unexpectedProfile(let expected, let actual):
            return "Expected QR profile \(expected), received \(actual)."
        case .unexpectedKind(let expected, let actual):
            return "Expected QR payload kind \(expected), received \(actual)."
        case .unexpectedSchemaVersion(let expected, let actual):
            return "Expected QR schema version \(expected), received \(actual)."
        }
    }
}

/// One CRC32C-protected `IRQR` binary frame.
public struct IrohaPeerQRFrameV1: Equatable, Sendable {
    public static let magic = Data("IRQR".utf8)
    public static let wireVersion: UInt8 = 1
    public static let payloadOffset = 32
    public static let checksumBytes = 4

    public let frameKind: IrohaPeerQRFrameKindV1
    public let profile: IrohaPeerWireProfileV1
    public let payloadKind: IrohaPeerWireKindV1
    public let streamID: Data
    public let index: Int
    /// Data-shard count for header, data, and parity frames; one for complete.
    public let total: Int
    public let payload: Data

    public init(
        frameKind: IrohaPeerQRFrameKindV1,
        profile: IrohaPeerWireProfileV1,
        payloadKind: IrohaPeerWireKindV1,
        streamID: Data,
        index: Int,
        total: Int,
        payload: Data,
        limits: IrohaPeerWireLimitsV1 = .peerV1
    ) throws {
        guard profile != .reject else { throw IrohaPeerQRErrorV1.invalidProfile(profile.rawValue) }
        guard streamID.count == 16, total > 0, total <= Int(UInt16.max),
              index >= 0, index <= Int(UInt16.max), payload.count <= Int(UInt16.max) else {
            throw IrohaPeerQRErrorV1.invalidFrameShape
        }
        let maximumDataShards = try limits.maximumEncodedBytes(for: profile)
            .qrCeilingDivisor(IrohaPeerWireMessageV1.qrDataShardBytes)
        guard total <= maximumDataShards else { throw IrohaPeerQRErrorV1.messageTooLarge }
        switch frameKind {
        case .complete:
            guard index == 0, total == 1,
                  payload.count > IrohaPeerWireMessageV1.headerBytes,
                  payload.count <= IrohaPeerWireMessageV1.headerBytes
                    + (try limits.maximumEncodedBytes(for: profile)) else {
                throw IrohaPeerQRErrorV1.invalidFrameShape
            }
        case .header:
            guard index == 0, payload.count == IrohaPeerWireMessageV1.headerBytes else {
                throw IrohaPeerQRErrorV1.invalidFrameShape
            }
        case .data:
            guard index < total,
                  payload.count == IrohaPeerWireMessageV1.qrDataShardBytes else {
                throw IrohaPeerQRErrorV1.invalidFrameShape
            }
        case .parity:
            guard index < total.qrCeilingDivisor(2),
                  payload.count == IrohaPeerWireMessageV1.qrDataShardBytes else {
                throw IrohaPeerQRErrorV1.invalidFrameShape
            }
        }
        self.frameKind = frameKind
        self.profile = profile
        self.payloadKind = payloadKind
        self.streamID = streamID
        self.index = index
        self.total = total
        self.payload = payload
    }

    public var encoded: Data {
        var data = Self.magic
        data.append(Self.wireVersion)
        data.append(frameKind.rawValue)
        data.iqrAppendUInt16BE(profile.rawValue)
        data.append(payloadKind.rawValue)
        data.append(0)
        data.append(streamID)
        data.iqrAppendUInt16BE(UInt16(index))
        data.iqrAppendUInt16BE(UInt16(total))
        data.iqrAppendUInt16BE(UInt16(payload.count))
        data.append(payload)
        data.iqrAppendUInt32BE(IrohaPeerCRC32CV1.checksum(data))
        return data
    }

    public static func decode(
        _ data: Data,
        limits: IrohaPeerWireLimitsV1 = .peerV1
    ) throws -> Self {
        guard data.count >= payloadOffset + checksumBytes else {
            throw IrohaPeerQRErrorV1.invalidFrameShape
        }
        guard data.prefix(4) == magic else { throw IrohaPeerQRErrorV1.invalidMagic }
        guard data[4] == wireVersion else {
            throw IrohaPeerQRErrorV1.unsupportedWireVersion(data[4])
        }
        guard let frameKind = IrohaPeerQRFrameKindV1(rawValue: data[5]) else {
            throw IrohaPeerQRErrorV1.invalidFrameKind(data[5])
        }
        let rawProfile = data.iqrUInt16BE(at: 6)
        guard let profile = IrohaPeerWireProfileV1(rawValue: rawProfile), profile != .reject else {
            throw IrohaPeerQRErrorV1.invalidProfile(rawProfile)
        }
        guard let payloadKind = IrohaPeerWireKindV1(rawValue: data[8]) else {
            throw IrohaPeerQRErrorV1.invalidPayloadKind(data[8])
        }
        guard data[9] == 0 else { throw IrohaPeerQRErrorV1.invalidFlags(data[9]) }
        let payloadLength = Int(data.iqrUInt16BE(at: 30))
        let payloadEnd = payloadOffset + payloadLength
        guard payloadEnd + checksumBytes == data.count else {
            throw IrohaPeerQRErrorV1.invalidFrameShape
        }
        guard data.iqrUInt32BE(at: payloadEnd)
            == IrohaPeerCRC32CV1.checksum(data.prefix(payloadEnd)) else {
            throw IrohaPeerQRErrorV1.checksumMismatch
        }
        return try Self(
            frameKind: frameKind,
            profile: profile,
            payloadKind: payloadKind,
            streamID: data.subdata(in: 10..<26),
            index: Int(data.iqrUInt16BE(at: 26)),
            total: Int(data.iqrUInt16BE(at: 28)),
            payload: data.subdata(in: payloadOffset..<payloadEnd),
            limits: limits
        )
    }
}

/// Strict RFC 9285 Base45 `IQR1:<body>:` framing and deterministic IRQR sharding.
public enum IrohaPeerQRCodecV1 {
    public static let textPrefix = "IQR1:"
    public static let textSuffix = ":"
    public static let maximumStaticTextBytes = 700
    public static let headerRepeatInterval = 12

    public static func encodeFrame(_ frame: IrohaPeerQRFrameV1) -> String {
        textPrefix + IrohaBase45V1.encode(frame.encoded) + textSuffix
    }

    public static func decodeFrame(
        _ text: String,
        limits: IrohaPeerWireLimitsV1 = .peerV1
    ) throws -> IrohaPeerQRFrameV1 {
        guard text.utf8.count <= maximumStaticTextBytes else {
            throw IrohaPeerQRErrorV1.frameTextTooLarge(
                actual: text.utf8.count,
                maximum: maximumStaticTextBytes
            )
        }
        guard text.hasPrefix(textPrefix), text.hasSuffix(textSuffix),
              text.utf8.count > textPrefix.utf8.count + textSuffix.utf8.count else {
            throw IrohaPeerQRErrorV1.malformedText
        }
        let bodyStart = text.index(text.startIndex, offsetBy: textPrefix.count)
        let bodyEnd = text.index(text.endIndex, offsetBy: -textSuffix.count)
        let body = String(text[bodyStart..<bodyEnd])
        guard let bytes = IrohaBase45V1.decode(body),
              encodeRawText(bytes) == text else {
            throw IrohaPeerQRErrorV1.nonCanonicalBase45
        }
        return try IrohaPeerQRFrameV1.decode(bytes, limits: limits)
    }

    /// Returns the character-bounded static candidate. A renderer must still
    /// confirm that it fits QR version 17-M or lower before presenting it.
    public static func staticCompleteTextCandidate(
        for message: IrohaPeerWireMessageV1,
        limits: IrohaPeerWireLimitsV1 = .peerV1
    ) throws -> String? {
        let messageByteCount = IrohaPeerWireMessageV1.headerBytes + message.encodedBody.count
        let maximumEncodedBytes = try limits.maximumEncodedBytes(for: message.profile)
        guard messageByteCount > IrohaPeerWireMessageV1.headerBytes,
              messageByteCount <= IrohaPeerWireMessageV1.headerBytes + maximumEncodedBytes else {
            throw IrohaPeerQRErrorV1.invalidFrameShape
        }
        let frameByteCount = IrohaPeerQRFrameV1.payloadOffset
            + messageByteCount
            + IrohaPeerQRFrameV1.checksumBytes
        guard framedTextByteCount(forEncodedFrameByteCount: frameByteCount)
                <= maximumStaticTextBytes else {
            return nil
        }
        let frame = try IrohaPeerQRFrameV1(
            frameKind: .complete,
            profile: message.profile,
            payloadKind: message.kind,
            streamID: message.streamID,
            index: 0,
            total: 1,
            payload: message.encoded,
            limits: limits
        )
        return encodeFrame(frame)
    }

    /// Animated sequence: `header,D0,D1,P0,...`, with another identical
    /// header after each twelve emitted non-header shards.
    public static func animatedFrameTexts(
        for message: IrohaPeerWireMessageV1,
        limits: IrohaPeerWireLimitsV1 = .peerV1
    ) throws -> [String] {
        let shardBytes = IrohaPeerWireMessageV1.qrDataShardBytes
        let dataCount = message.encodedBody.count.qrCeilingDivisor(shardBytes)
        guard dataCount > 0, dataCount <= Int(UInt16.max) else {
            throw IrohaPeerQRErrorV1.messageTooLarge
        }
        func shard(at index: Int) -> Data {
            let start = index * shardBytes
            let end = min(start + shardBytes, message.encodedBody.count)
            var shard = message.encodedBody.subdata(in: start..<end)
            if shard.count < shardBytes {
                shard.append(Data(repeating: 0, count: shardBytes - shard.count))
            }
            return shard
        }
        let header = try IrohaPeerQRFrameV1(
            frameKind: .header,
            profile: message.profile,
            payloadKind: message.kind,
            streamID: message.streamID,
            index: 0,
            total: dataCount,
            payload: message.header.bytes,
            limits: limits
        )
        let parityCount = dataCount.qrCeilingDivisor(2)
        let nonHeaderFrameCount = dataCount + parityCount
        let headerEmissionCount = 1 + nonHeaderFrameCount / headerRepeatInterval
        let headerText = encodeFrame(header)
        var texts: [String] = []
        texts.reserveCapacity(nonHeaderFrameCount + headerEmissionCount)
        texts.append(headerText)
        var nonHeaderCount = 0
        func appendNonHeader(_ frame: IrohaPeerQRFrameV1) {
            texts.append(encodeFrame(frame))
            nonHeaderCount += 1
            if nonHeaderCount % headerRepeatInterval == 0 { texts.append(headerText) }
        }
        for pairIndex in 0..<parityCount {
            let firstIndex = pairIndex * 2
            let firstShard = shard(at: firstIndex)
            appendNonHeader(try IrohaPeerQRFrameV1(
                frameKind: .data,
                profile: message.profile,
                payloadKind: message.kind,
                streamID: message.streamID,
                index: firstIndex,
                total: dataCount,
                payload: firstShard,
                limits: limits
            ))
            let secondShard: Data?
            if firstIndex + 1 < dataCount {
                let value = shard(at: firstIndex + 1)
                secondShard = value
                appendNonHeader(try IrohaPeerQRFrameV1(
                    frameKind: .data,
                    profile: message.profile,
                    payloadKind: message.kind,
                    streamID: message.streamID,
                    index: firstIndex + 1,
                    total: dataCount,
                    payload: value,
                    limits: limits
                ))
            } else {
                secondShard = nil
            }
            var parity = firstShard
            if let secondShard {
                for byteIndex in 0..<shardBytes {
                    parity[byteIndex] ^= secondShard[byteIndex]
                }
            }
            appendNonHeader(try IrohaPeerQRFrameV1(
                frameKind: .parity,
                profile: message.profile,
                payloadKind: message.kind,
                streamID: message.streamID,
                index: pairIndex,
                total: dataCount,
                payload: parity,
                limits: limits
            ))
        }
        return texts
    }

    private static func framedTextByteCount(forEncodedFrameByteCount byteCount: Int) -> Int {
        textPrefix.utf8.count
            + (byteCount / 2) * 3
            + (byteCount % 2) * 2
            + textSuffix.utf8.count
    }

    private static func encodeRawText(_ bytes: Data) -> String {
        textPrefix + IrohaBase45V1.encode(bytes) + textSuffix
    }
}

public struct IrohaPeerQRScanLimitsV1: Equatable, Sendable {
    public let maximumActiveStreams: Int
    public let maximumPreheaderFramesPerStream: Int
    public let maximumPreheaderPayloadBytesPerStream: Int
    public let idleTimeout: TimeInterval
    public let absoluteTimeout: TimeInterval

    public init(
        maximumActiveStreams: Int = 3,
        maximumPreheaderFramesPerStream: Int = 12,
        maximumPreheaderPayloadBytesPerStream: Int = 3_072,
        idleTimeout: TimeInterval = 30,
        absoluteTimeout: TimeInterval = 180
    ) {
        precondition(
            Self.areValid(
                maximumActiveStreams: maximumActiveStreams,
                maximumPreheaderFramesPerStream: maximumPreheaderFramesPerStream,
                maximumPreheaderPayloadBytesPerStream: maximumPreheaderPayloadBytesPerStream,
                idleTimeout: idleTimeout,
                absoluteTimeout: absoluteTimeout
            )
        )
        self.maximumActiveStreams = maximumActiveStreams
        self.maximumPreheaderFramesPerStream = maximumPreheaderFramesPerStream
        self.maximumPreheaderPayloadBytesPerStream = maximumPreheaderPayloadBytesPerStream
        self.idleTimeout = idleTimeout
        self.absoluteTimeout = absoluteTimeout
    }

    public static let standard = IrohaPeerQRScanLimitsV1()

    static func areValid(
        maximumActiveStreams: Int,
        maximumPreheaderFramesPerStream: Int,
        maximumPreheaderPayloadBytesPerStream: Int,
        idleTimeout: TimeInterval,
        absoluteTimeout: TimeInterval
    ) -> Bool {
        (1...3).contains(maximumActiveStreams) &&
            (1...12).contains(maximumPreheaderFramesPerStream) &&
            (1...3_072).contains(maximumPreheaderPayloadBytesPerStream) &&
            idleTimeout.isFinite && idleTimeout > 0 && idleTimeout <= 30 &&
            absoluteTimeout.isFinite && absoluteTimeout >= idleTimeout && absoluteTimeout <= 180
    }
}

public struct IrohaPeerQRScanProgressV1: Equatable, Sendable {
    public let streamID: Data
    public let receivedDataShards: Int
    public let totalDataShards: Int
    public let recoveredDataShards: Int

    public var fractionComplete: Double {
        guard totalDataShards > 0 else { return 0 }
        return min(1, Double(receivedDataShards) / Double(totalDataShards))
    }
}

public enum IrohaPeerQRScanEventV1: Equatable, Sendable {
    case accepted(IrohaPeerQRScanProgressV1)
    case duplicate(IrohaPeerQRScanProgressV1)
    case completed(IrohaPeerWireMessageV1)
}

/// Bounded, multi-stream animated QR decoder. State expires by both idle and
/// absolute age so scanner noise cannot keep stale app sessions alive forever.
public final class IrohaPeerQRScanSessionV1: @unchecked Sendable {
    private struct FrameKey: Hashable {
        let kind: IrohaPeerQRFrameKindV1
        let index: Int
    }

    private struct Candidate {
        let streamID: Data
        let profile: IrohaPeerWireProfileV1
        let payloadKind: IrohaPeerWireKindV1
        let firstSeen: TimeInterval
        var lastProgress: TimeInterval
        var header: IrohaPeerWireHeaderV1?
        var declaredTotal: Int?
        var encodedFrames: [FrameKey: Data] = [:]
        var data: [Int: Data] = [:]
        var parity: [Int: Data] = [:]
        var recovered = Set<Int>()
        var preheaderFrameCount = 0
        var preheaderPayloadBytes = 0
    }

    private let lock = NSRecursiveLock()
    private let expectedProfile: IrohaPeerWireProfileV1?
    private let expectedKind: IrohaPeerWireKindV1?
    private let expectedSchemaVersion: UInt16?
    private let wireLimits: IrohaPeerWireLimitsV1
    private let scanLimits: IrohaPeerQRScanLimitsV1
    private let clock: @Sendable () -> TimeInterval
    private var candidates: [Data: Candidate] = [:]
    private var quarantinedUntil: [Data: TimeInterval] = [:]
    private var lastObservedUptime: TimeInterval?

    public init(
        expectedProfile: IrohaPeerWireProfileV1? = nil,
        expectedKind: IrohaPeerWireKindV1? = nil,
        expectedSchemaVersion: UInt16? = nil,
        wireLimits: IrohaPeerWireLimitsV1 = .peerV1,
        scanLimits: IrohaPeerQRScanLimitsV1 = .standard,
        clock: @escaping @Sendable () -> TimeInterval = {
            ProcessInfo.processInfo.systemUptime
        }
    ) {
        precondition(expectedSchemaVersion != 0)
        self.expectedProfile = expectedProfile
        self.expectedKind = expectedKind
        self.expectedSchemaVersion = expectedSchemaVersion
        self.wireLimits = wireLimits
        self.scanLimits = scanLimits
        self.clock = clock
    }

    public var activeStreamCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return candidates.count
    }

    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        candidates.removeAll(keepingCapacity: false)
        quarantinedUntil.removeAll(keepingCapacity: false)
        lastObservedUptime = nil
    }

    @discardableResult
    public func expire() throws -> [Data] {
        lock.lock()
        defer { lock.unlock() }
        return try expire(atUptime: clock())
    }

    public func expire(atUptime now: TimeInterval) throws -> [Data] {
        try validateUptime(now)
        lock.lock()
        defer { lock.unlock() }
        try observeUptimeLocked(now)
        return expireLocked(at: now)
    }

    /// Quarantines a structurally valid stream whose application payload was
    /// rejected after IPM1 completion. Quarantine is bounded and expires on
    /// the same absolute lifetime as scanner-detected conflicts.
    public func quarantine(streamID: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        try quarantine(streamID: streamID, atUptime: clock())
    }

    public func quarantine(streamID: Data, atUptime now: TimeInterval) throws {
        guard streamID.count == 16 else { throw IrohaPeerQRErrorV1.invalidFrameShape }
        try validateUptime(now)
        lock.lock()
        defer { lock.unlock() }
        try observeUptimeLocked(now)
        _ = expireLocked(at: now)
        quarantineLocked(streamID, at: now)
    }

    public func ingest(_ text: String) throws -> IrohaPeerQRScanEventV1 {
        lock.lock()
        defer { lock.unlock() }
        return try ingest(text, atUptime: clock())
    }

    public func ingest(
        _ text: String,
        atUptime now: TimeInterval
    ) throws -> IrohaPeerQRScanEventV1 {
        try validateUptime(now)
        let frame = try IrohaPeerQRCodecV1.decodeFrame(text, limits: wireLimits)
        lock.lock()
        defer { lock.unlock() }
        try observeUptimeLocked(now)
        _ = expireLocked(at: now)
        if let until = quarantinedUntil[frame.streamID], until > now {
            throw IrohaPeerQRErrorV1.streamQuarantined
        }
        if let expectedProfile, frame.profile != expectedProfile {
            quarantineLocked(frame.streamID, at: now)
            throw IrohaPeerQRErrorV1.unexpectedProfile(
                expected: expectedProfile,
                actual: frame.profile
            )
        }
        if let expectedKind, frame.payloadKind != expectedKind {
            quarantineLocked(frame.streamID, at: now)
            throw IrohaPeerQRErrorV1.unexpectedKind(
                expected: expectedKind,
                actual: frame.payloadKind
            )
        }
        if frame.frameKind == .complete {
            do {
                let header = try IrohaPeerWireMessageV1.inspectHeader(
                    Data(frame.payload.prefix(IrohaPeerWireMessageV1.headerBytes)),
                    expectedProfile: frame.profile,
                    expectedKind: frame.payloadKind,
                    limits: wireLimits
                )
                try validateExpectedSchemaVersion(header.schemaVersion)
                let message = try IrohaPeerWireMessageV1.decode(
                    frame.payload,
                    expectedProfile: frame.profile,
                    expectedKind: frame.payloadKind,
                    limits: wireLimits
                )
                guard message.streamID == frame.streamID else {
                    throw IrohaPeerQRErrorV1.invalidMessage
                }
                candidates.removeValue(forKey: frame.streamID)
                return .completed(message)
            } catch {
                quarantineLocked(frame.streamID, at: now)
                throw (error as? IrohaPeerQRErrorV1) ?? .invalidMessage
            }
        }

        var candidate: Candidate
        if let existing = candidates[frame.streamID] {
            candidate = existing
            guard candidate.profile == frame.profile,
                  candidate.payloadKind == frame.payloadKind else {
                quarantineLocked(frame.streamID, at: now)
                throw IrohaPeerQRErrorV1.conflictingDuplicate
            }
        } else {
            guard candidates.count < scanLimits.maximumActiveStreams else {
                throw IrohaPeerQRErrorV1.tooManyActiveStreams(
                    maximum: scanLimits.maximumActiveStreams
                )
            }
            candidate = Candidate(
                streamID: frame.streamID,
                profile: frame.profile,
                payloadKind: frame.payloadKind,
                firstSeen: now,
                lastProgress: now
            )
        }

        let key = FrameKey(kind: frame.frameKind, index: frame.index)
        if let previous = candidate.encodedFrames[key] {
            guard previous == frame.encoded else {
                quarantineLocked(frame.streamID, at: now)
                throw IrohaPeerQRErrorV1.conflictingDuplicate
            }
            candidates[frame.streamID] = candidate
            return .duplicate(progress(for: candidate))
        }

        do {
            try validateFrameTotal(frame, candidate: candidate)
            // Retain the stream's immutable total even when the payload cannot be buffered.
            if candidate.declaredTotal == nil { candidate.declaredTotal = frame.total }
            if candidate.header == nil, frame.frameKind != .header {
                guard candidate.preheaderFrameCount < scanLimits.maximumPreheaderFramesPerStream,
                      candidate.preheaderPayloadBytes
                        <= scanLimits.maximumPreheaderPayloadBytesPerStream - frame.payload.count else {
                    // The bound limits buffering, not the stream: a scan that missed the header
                    // must not be refused. This frame is dropped unbuffered and returns next loop.
                    candidates[frame.streamID] = candidate
                    return .duplicate(progress(for: candidate))
                }
                candidate.preheaderFrameCount += 1
                candidate.preheaderPayloadBytes += frame.payload.count
            }
            candidate.encodedFrames[key] = frame.encoded
            switch frame.frameKind {
            case .header:
                let header: IrohaPeerWireHeaderV1
                do {
                    header = try IrohaPeerWireMessageV1.inspectHeader(
                        frame.payload,
                        expectedProfile: frame.profile,
                        expectedKind: frame.payloadKind,
                        limits: wireLimits
                    )
                } catch {
                    throw IrohaPeerQRErrorV1.invalidHeader
                }
                guard header.streamID == frame.streamID,
                      header.dataShardCount == frame.total else {
                    throw IrohaPeerQRErrorV1.invalidHeader
                }
                try validateExpectedSchemaVersion(header.schemaVersion)
                candidate.header = header
            case .data:
                if let recovered = candidate.data[frame.index] {
                    guard recovered == frame.payload else {
                        throw IrohaPeerQRErrorV1.conflictingDuplicate
                    }
                    candidate.recovered.remove(frame.index)
                }
                candidate.data[frame.index] = frame.payload
            case .parity:
                candidate.parity[frame.index] = frame.payload
            case .complete:
                preconditionFailure("complete frames return before candidate allocation")
            }
            candidate.lastProgress = now
            if let header = candidate.header {
                try validateBuffered(candidate, header: header)
                recoverData(in: &candidate, total: header.dataShardCount)
                if candidate.data.count == header.dataShardCount {
                    let message = try finish(candidate, header: header)
                    candidates.removeValue(forKey: frame.streamID)
                    quarantinedUntil.removeValue(forKey: frame.streamID)
                    return .completed(message)
                }
            }
            candidates[frame.streamID] = candidate
            return .accepted(progress(for: candidate))
        } catch let error as IrohaPeerQRErrorV1 {
            quarantineLocked(frame.streamID, at: now)
            throw error
        } catch {
            quarantineLocked(frame.streamID, at: now)
            throw IrohaPeerQRErrorV1.invalidMessage
        }
    }

    private func validateFrameTotal(
        _ frame: IrohaPeerQRFrameV1,
        candidate: Candidate
    ) throws {
        let maximumShards = try wireLimits.maximumEncodedBytes(for: frame.profile)
            .qrCeilingDivisor(IrohaPeerWireMessageV1.qrDataShardBytes)
        guard frame.total <= maximumShards else { throw IrohaPeerQRErrorV1.messageTooLarge }
        if let header = candidate.header {
            guard frame.total == header.dataShardCount else {
                throw IrohaPeerQRErrorV1.conflictingDuplicate
            }
        } else if let declaredTotal = candidate.declaredTotal, declaredTotal != frame.total {
            throw IrohaPeerQRErrorV1.conflictingDuplicate
        }
    }

    private func validateExpectedSchemaVersion(_ actual: UInt16) throws {
        guard let expectedSchemaVersion, expectedSchemaVersion != actual else { return }
        throw IrohaPeerQRErrorV1.unexpectedSchemaVersion(
            expected: expectedSchemaVersion,
            actual: actual
        )
    }

    private func validateBuffered(
        _ candidate: Candidate,
        header: IrohaPeerWireHeaderV1
    ) throws {
        for encoded in candidate.encodedFrames.values {
            let frame = try IrohaPeerQRFrameV1.decode(encoded, limits: wireLimits)
            guard frame.total == header.dataShardCount else {
                throw IrohaPeerQRErrorV1.conflictingDuplicate
            }
        }
    }

    private func recoverData(in candidate: inout Candidate, total: Int) {
        for pairIndex in 0..<total.qrCeilingDivisor(2) {
            guard let parity = candidate.parity[pairIndex] else { continue }
            let first = pairIndex * 2
            let indices = first + 1 < total ? [first, first + 1] : [first]
            let missing = indices.filter { candidate.data[$0] == nil }
            guard missing.count == 1 else { continue }
            var recovered = parity
            for index in indices where index != missing[0] {
                guard let present = candidate.data[index] else { continue }
                for byteIndex in 0..<IrohaPeerWireMessageV1.qrDataShardBytes {
                    recovered[byteIndex] ^= present[byteIndex]
                }
            }
            candidate.data[missing[0]] = recovered
            candidate.recovered.insert(missing[0])
        }
    }

    private func finish(
        _ candidate: Candidate,
        header: IrohaPeerWireHeaderV1
    ) throws -> IrohaPeerWireMessageV1 {
        var paddedBody = Data()
        paddedBody.reserveCapacity(header.dataShardCount * IrohaPeerWireMessageV1.qrDataShardBytes)
        for index in 0..<header.dataShardCount {
            guard let shard = candidate.data[index] else { throw IrohaPeerQRErrorV1.invalidMessage }
            paddedBody.append(shard)
        }
        guard paddedBody.count >= header.encodedLength else {
            throw IrohaPeerQRErrorV1.invalidMessage
        }
        if header.encodedLength < paddedBody.count,
           paddedBody[header.encodedLength..<paddedBody.count].contains(where: { $0 != 0 }) {
            throw IrohaPeerQRErrorV1.invalidMessage
        }
        let messageBytes = header.bytes + paddedBody.prefix(header.encodedLength)
        let message: IrohaPeerWireMessageV1
        do {
            message = try IrohaPeerWireMessageV1.decode(
                messageBytes,
                expectedProfile: candidate.profile,
                expectedKind: candidate.payloadKind,
                limits: wireLimits
            )
        } catch {
            throw IrohaPeerQRErrorV1.invalidMessage
        }
        guard message.streamID == candidate.streamID else {
            throw IrohaPeerQRErrorV1.invalidMessage
        }
        return message
    }

    private func progress(for candidate: Candidate) -> IrohaPeerQRScanProgressV1 {
        IrohaPeerQRScanProgressV1(
            streamID: candidate.streamID,
            receivedDataShards: candidate.data.count,
            totalDataShards: candidate.header?.dataShardCount ?? 0,
            recoveredDataShards: candidate.recovered.count
        )
    }

    private func expireLocked(at now: TimeInterval) -> [Data] {
        let expired = candidates.compactMap { streamID, candidate -> Data? in
            let idleAge = now - candidate.lastProgress
            let absoluteAge = now - candidate.firstSeen
            return idleAge >= scanLimits.idleTimeout || absoluteAge >= scanLimits.absoluteTimeout
                ? streamID : nil
        }
        for streamID in expired { candidates.removeValue(forKey: streamID) }
        quarantinedUntil = quarantinedUntil.filter {
            $0.value == .infinity || $0.value > now
        }
        return expired
    }

    private func quarantineLocked(_ streamID: Data, at now: TimeInterval) {
        candidates.removeValue(forKey: streamID)
        let proposed = now + scanLimits.absoluteTimeout
        quarantinedUntil[streamID] = proposed.isFinite && proposed > now
            ? proposed
            : .infinity
        if quarantinedUntil.count > 12,
           let earliest = quarantinedUntil.min(by: { $0.value < $1.value })?.key {
            quarantinedUntil.removeValue(forKey: earliest)
        }
    }

    private func validateUptime(_ now: TimeInterval) throws {
        guard now.isFinite, now >= 0 else { throw IrohaPeerQRErrorV1.invalidUptime }
    }

    private func observeUptimeLocked(_ now: TimeInterval) throws {
        if let lastObservedUptime, now < lastObservedUptime {
            throw IrohaPeerQRErrorV1.invalidUptime
        }
        lastObservedUptime = now
    }
}

enum IrohaBase45V1 {
    private static let alphabet = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".utf8)
    private static let reverse: [Int16] = {
        var table = [Int16](repeating: -1, count: 128)
        for (index, byte) in alphabet.enumerated() { table[Int(byte)] = Int16(index) }
        return table
    }()

    static func encode(_ data: Data) -> String {
        var output = [UInt8]()
        output.reserveCapacity((data.count / 2) * 3 + (data.count % 2) * 2)
        var index = 0
        while index + 1 < data.count {
            var value = Int(data[index]) * 256 + Int(data[index + 1])
            output.append(alphabet[value % 45])
            value /= 45
            output.append(alphabet[value % 45])
            output.append(alphabet[value / 45])
            index += 2
        }
        if index < data.count {
            let value = Int(data[index])
            output.append(alphabet[value % 45])
            output.append(alphabet[value / 45])
        }
        return String(decoding: output, as: UTF8.self)
    }

    static func decode(_ value: String) -> Data? {
        let input = Array(value.utf8)
        guard !input.isEmpty, input.count % 3 != 1 else { return nil }
        var output = Data()
        output.reserveCapacity((input.count / 3) * 2 + (input.count % 3 == 2 ? 1 : 0))
        var index = 0
        while index + 2 < input.count {
            guard let a = digit(input[index]), let b = digit(input[index + 1]),
                  let c = digit(input[index + 2]) else { return nil }
            let decoded = a + b * 45 + c * 2_025
            guard decoded <= 0xFFFF else { return nil }
            output.append(UInt8(decoded / 256))
            output.append(UInt8(decoded % 256))
            index += 3
        }
        if index < input.count {
            guard index + 1 < input.count,
                  let a = digit(input[index]), let b = digit(input[index + 1]) else {
                return nil
            }
            let decoded = a + b * 45
            guard decoded <= 0xFF else { return nil }
            output.append(UInt8(decoded))
        }
        return output
    }

    private static func digit(_ byte: UInt8) -> Int? {
        guard byte < 128 else { return nil }
        let value = reverse[Int(byte)]
        return value >= 0 ? Int(value) : nil
    }
}

enum IrohaPeerCRC32CV1 {
    private static let table: [UInt32] = (0..<256).map { value in
        var crc = UInt32(value)
        for _ in 0..<8 {
            crc = (crc & 1) == 0 ? crc >> 1 : (crc >> 1) ^ 0x82F6_3B78
        }
        return crc
    }

    static func checksum<C: Collection>(_ bytes: C) -> UInt32 where C.Element == UInt8 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in bytes {
            let tableIndex = Int((crc ^ UInt32(byte)) & 0xFF)
            crc = (crc >> 8) ^ table[tableIndex]
        }
        return crc ^ 0xFFFF_FFFF
    }
}

private extension Int {
    func qrCeilingDivisor(_ divisor: Int) -> Int {
        (self + divisor - 1) / divisor
    }
}

private extension Data {
    mutating func iqrAppendUInt16BE(_ value: UInt16) {
        append(UInt8(truncatingIfNeeded: value >> 8))
        append(UInt8(truncatingIfNeeded: value))
    }

    mutating func iqrAppendUInt32BE(_ value: UInt32) {
        append(UInt8(truncatingIfNeeded: value >> 24))
        append(UInt8(truncatingIfNeeded: value >> 16))
        append(UInt8(truncatingIfNeeded: value >> 8))
        append(UInt8(truncatingIfNeeded: value))
    }

    func iqrUInt16BE(at offset: Int) -> UInt16 {
        UInt16(self[offset]) << 8 | UInt16(self[offset + 1])
    }

    func iqrUInt32BE(at offset: Int) -> UInt32 {
        UInt32(self[offset]) << 24
            | UInt32(self[offset + 1]) << 16
            | UInt32(self[offset + 2]) << 8
            | UInt32(self[offset + 3])
    }
}
