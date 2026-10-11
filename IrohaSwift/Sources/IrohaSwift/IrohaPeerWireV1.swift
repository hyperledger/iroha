import Compression
import Foundation
import zlib

/// Wire-stable application profiles carried by an `IPM1` peer message.
public enum IrohaPeerWireProfileV1: UInt16, CaseIterable, Sendable {
    /// Reserved on the wire so a zero-filled or omitted profile is never accepted.
    case reject = 0
    /// KAGEMUSHA wallet V1 peer messages: Request carries its unchanged envelope and mandatory account companion;
    /// other payloads are one complete `KagemushaWalletEnvelopeV1` frame (`specs/kagemusha_wallet_wire_v1.md` §§2, 3.4).
    case kagemushaWalletV1 = 1
}

/// Wire-stable message kinds carried by an `IPM1` peer message.
///
/// Each raw value equals the KAGEMUSHA wallet V1 envelope message tag
/// (`KagemushaWalletMessageKindV1`) of the frame the message carries.
public enum IrohaPeerWireKindV1: UInt8, CaseIterable, Sendable {
    /// Payer session hint.
    case offer = 1
    /// Receiver setup quote.
    case request = 2
    /// Complete committed Payment.
    case payment = 3
    /// Receiver delivery evidence.
    case credited = 4
    /// Nonmonetary session control.
    case sessionControl = 5
    /// Nonmonetary policy data.
    case policyData = 6
    /// Ω of the payer's folded head, sent only after an authenticated Offer.
    case lineage = 7
}

/// Canonical cross-SDK spellings shared with the upstream Iroha SDK.
public typealias IrohaPeerPayloadProfile = IrohaPeerWireProfileV1
public typealias IrohaPeerPayloadKind = IrohaPeerWireKindV1

public extension IrohaPeerWireProfileV1 {
    /// The sole first-release canonical payload schema admitted by this profile.
    var requiredSchemaVersion: UInt16 {
        switch self {
        case .reject: return 0
        case .kagemushaWalletV1: return KagemushaWalletWireV1.version
        }
    }
}

public extension IrohaPeerWireKindV1 {
    /// KAGEMUSHA wallet V1 envelope message kind carried under this IPM1 kind.
    var walletMessageKind: KagemushaWalletMessageKindV1 {
        switch self {
        case .offer: return .offer
        case .request: return .request
        case .payment: return .payment
        case .credited: return .credited
        case .sessionControl: return .sessionControl
        case .policyData: return .policyData
        case .lineage: return .lineage
        }
    }

    /// Exact complete-frame cap of a wallet envelope of this kind, header and padding included.
    var maximumWalletFrameBytes: Int {
        self == .request ? IrohaPeerWalletRequestV1.maximumBytes : walletMessageKind.maximumFrameBytes
    }
}

public enum IrohaPeerWireEncodingV1: UInt8, Sendable {
    case none = 0
    case zlib = 1
}

/// Compression is opt-in. The shared peer policy emits zlib only when it
/// saves meaningful bytes and at least one fixed-size transport shard.
public enum IrohaPeerWireCompressionPolicyV1: Sendable {
    case disabled
    /// Cross-rail V1 encoding: use zlib only when it saves at least 32 bytes
    /// and at least one 256-byte shard.
    case peerOptimized
}

/// Allocation limits applied before an untrusted body is decompressed.
public struct IrohaPeerWireLimitsV1: Equatable, Sendable {
    /// Largest complete KAGEMUSHA wallet V1 envelope frame carried by IPM1.
    public static let maximumWalletProfileBytes = IrohaPeerWalletRequestV1.maximumBytes

    public let maximumCanonicalBytes: Int
    public let maximumWalletEncodedBytes: Int

    public init(
        maximumCanonicalBytes: Int = Self.maximumWalletProfileBytes,
        maximumWalletEncodedBytes: Int = Self.maximumWalletProfileBytes
    ) {
        precondition(
            Self.areValid(
                maximumCanonicalBytes: maximumCanonicalBytes,
                maximumWalletEncodedBytes: maximumWalletEncodedBytes
            )
        )
        self.maximumCanonicalBytes = maximumCanonicalBytes
        self.maximumWalletEncodedBytes = maximumWalletEncodedBytes
    }

    public static let peerV1 = IrohaPeerWireLimitsV1()

    static func areValid(
        maximumCanonicalBytes: Int,
        maximumWalletEncodedBytes: Int
    ) -> Bool {
        (1...maximumWalletProfileBytes).contains(maximumCanonicalBytes) &&
            (1...maximumWalletProfileBytes).contains(maximumWalletEncodedBytes)
    }

    public func maximumEncodedBytes(for profile: IrohaPeerWireProfileV1) throws -> Int {
        switch profile {
        case .reject:
            throw IrohaPeerWireMessageErrorV1.invalidProfile(profile.rawValue)
        case .kagemushaWalletV1:
            return maximumWalletEncodedBytes
        }
    }
}

public enum IrohaPeerWireMessageErrorV1: Error, Equatable, LocalizedError, Sendable {
    case invalidMagic
    case unsupportedWireVersion(UInt8)
    case unsupportedEncoding(UInt8)
    case invalidProfile(UInt16)
    case invalidKind(UInt8)
    case invalidFlags(UInt8)
    case invalidSchemaVersion
    case schemaVersionMismatch(
        profile: IrohaPeerWireProfileV1,
        expected: UInt16,
        actual: UInt16
    )
    case emptyCanonicalPayload
    case emptyEncodedBody
    case canonicalLengthOutOfRange(actual: Int, maximum: Int)
    case encodedLengthOutOfRange(actual: Int, maximum: Int)
    case lengthMismatch
    case compressionPolicyNotSatisfied
    case decompressionFailed
    case canonicalHashMismatch
    case wireHashMismatch
    case unexpectedProfile(expected: IrohaPeerWireProfileV1, actual: IrohaPeerWireProfileV1)
    case unexpectedKind(expected: IrohaPeerWireKindV1, actual: IrohaPeerWireKindV1)
    case invalidCanonicalPayload(
        profile: IrohaPeerWireProfileV1,
        kind: IrohaPeerWireKindV1
    )

    public var errorDescription: String? {
        switch self {
        case .invalidMagic: return "IPM1 peer message magic mismatch."
        case .unsupportedWireVersion(let value): return "Unsupported IPM1 wire version \(value)."
        case .unsupportedEncoding(let value): return "Unsupported IPM1 content encoding \(value)."
        case .invalidProfile(let value): return "Invalid IPM1 payload profile \(value)."
        case .invalidKind(let value): return "Invalid IPM1 payload kind \(value)."
        case .invalidFlags(let value): return "Invalid IPM1 flags \(value)."
        case .invalidSchemaVersion: return "IPM1 schema version zero is reserved."
        case .schemaVersionMismatch(let profile, let expected, let actual):
            return "IPM1 profile \(profile) requires schema \(expected), received \(actual)."
        case .emptyCanonicalPayload: return "IPM1 canonical payload must not be empty."
        case .emptyEncodedBody: return "IPM1 encoded body must not be empty."
        case .canonicalLengthOutOfRange(let actual, let maximum):
            return "IPM1 canonical length \(actual) exceeds the \(maximum)-byte limit."
        case .encodedLengthOutOfRange(let actual, let maximum):
            return "IPM1 encoded length \(actual) exceeds the \(maximum)-byte profile limit."
        case .lengthMismatch: return "IPM1 declared and actual lengths differ."
        case .compressionPolicyNotSatisfied: return "IPM1 zlib encoding does not satisfy the peer compression policy."
        case .decompressionFailed: return "IPM1 zlib body is invalid."
        case .canonicalHashMismatch: return "IPM1 canonical payload hash mismatch."
        case .wireHashMismatch: return "IPM1 wire hash mismatch."
        case .unexpectedProfile(let expected, let actual):
            return "Expected IPM1 profile \(expected), received \(actual)."
        case .unexpectedKind(let expected, let actual):
            return "Expected IPM1 kind \(expected), received \(actual)."
        case .invalidCanonicalPayload(let profile, let kind):
            return "IPM1 profile \(profile) has invalid canonical bytes for kind \(kind)."
        }
    }
}

/// Parsed, allocation-safe metadata from the fixed 84-byte `IPM1` header.
public struct IrohaPeerWireHeaderV1: Equatable, Sendable {
    public let encoding: IrohaPeerWireEncodingV1
    public let profile: IrohaPeerWireProfileV1
    public let kind: IrohaPeerWireKindV1
    public let schemaVersion: UInt16
    public let canonicalLength: Int
    public let encodedLength: Int
    public let canonicalHash: Data
    public let wireHash: Data
    public let bytes: Data

    public var streamID: Data { Data(wireHash.prefix(16)) }
    public var dataShardCount: Int {
        (encodedLength + IrohaPeerWireMessageV1.qrDataShardBytes - 1)
            / IrohaPeerWireMessageV1.qrDataShardBytes
    }
}

/// Transport-neutral `IPM1` envelope. It wraps already-canonical application
/// bytes and deliberately has no knowledge of domain payload construction.
public struct IrohaPeerWireMessageV1: Equatable, Sendable {
    public static let magic = Data("IPM1".utf8)
    public static let wireVersion: UInt8 = 1
    public static let headerBytes = 84
    public static let qrDataShardBytes = 256

    private static let canonicalHashDomain = Data("IROHA-PEER-PAYLOAD-V1\0".utf8)
    private static let wireHashDomain = Data("IROHA-PEER-MESSAGE-V1\0".utf8)

    public let header: IrohaPeerWireHeaderV1
    public let canonicalPayload: Data
    public let encodedBody: Data

    public var encoding: IrohaPeerWireEncodingV1 { header.encoding }
    public var profile: IrohaPeerWireProfileV1 { header.profile }
    public var kind: IrohaPeerWireKindV1 { header.kind }
    public var schemaVersion: UInt16 { header.schemaVersion }
    public var canonicalHash: Data { header.canonicalHash }
    public var wireHash: Data { header.wireHash }
    public var streamID: Data { header.streamID }
    public var encoded: Data { header.bytes + encodedBody }

    public init(
        profile: IrohaPeerWireProfileV1,
        kind: IrohaPeerWireKindV1,
        schemaVersion: UInt16,
        canonicalPayload: Data,
        compressionPolicy: IrohaPeerWireCompressionPolicyV1 = .disabled,
        limits: IrohaPeerWireLimitsV1 = .peerV1
    ) throws {
        guard profile != .reject else {
            throw IrohaPeerWireMessageErrorV1.invalidProfile(profile.rawValue)
        }
        guard schemaVersion != 0 else {
            throw IrohaPeerWireMessageErrorV1.invalidSchemaVersion
        }
        guard schemaVersion == profile.requiredSchemaVersion else {
            throw IrohaPeerWireMessageErrorV1.schemaVersionMismatch(
                profile: profile,
                expected: profile.requiredSchemaVersion,
                actual: schemaVersion
            )
        }
        guard !canonicalPayload.isEmpty else {
            throw IrohaPeerWireMessageErrorV1.emptyCanonicalPayload
        }
        guard canonicalPayload.count <= min(limits.maximumCanonicalBytes, kind.maximumWalletFrameBytes) else {
            throw IrohaPeerWireMessageErrorV1.canonicalLengthOutOfRange(
                actual: canonicalPayload.count,
                maximum: min(limits.maximumCanonicalBytes, kind.maximumWalletFrameBytes)
            )
        }
        try Self.validateCanonicalPayload(
            profile: profile,
            kind: kind,
            canonicalPayload: canonicalPayload
        )
        let maximumEncoded = try limits.maximumEncodedBytes(for: profile)
        let selected = try Self.selectEncoding(
            canonicalPayload,
            policy: compressionPolicy,
            maximumEncodedBytes: maximumEncoded
        )
        let canonicalHash = Self.canonicalHash(
            profile: profile,
            kind: kind,
            schemaVersion: schemaVersion,
            canonicalPayload: canonicalPayload
        )
        let prefix = Self.makeHeaderPrefix(
            encoding: selected.encoding,
            profile: profile,
            kind: kind,
            schemaVersion: schemaVersion,
            canonicalLength: canonicalPayload.count,
            encodedLength: selected.body.count,
            canonicalHash: canonicalHash
        )
        let wireHash = Blake2b.hash256(Self.wireHashDomain + prefix + selected.body)
        let headerBytes = prefix + wireHash
        self.header = try Self.inspectHeader(headerBytes, limits: limits)
        self.canonicalPayload = canonicalPayload
        self.encodedBody = selected.body
    }

    private init(header: IrohaPeerWireHeaderV1, canonicalPayload: Data, encodedBody: Data) {
        self.header = header
        self.canonicalPayload = canonicalPayload
        self.encodedBody = encodedBody
    }

    public static func inspectHeader(
        _ data: Data,
        expectedProfile: IrohaPeerWireProfileV1? = nil,
        expectedKind: IrohaPeerWireKindV1? = nil,
        limits: IrohaPeerWireLimitsV1 = .peerV1
    ) throws -> IrohaPeerWireHeaderV1 {
        guard data.count == headerBytes else { throw IrohaPeerWireMessageErrorV1.lengthMismatch }
        guard data.prefix(4) == magic else { throw IrohaPeerWireMessageErrorV1.invalidMagic }
        guard data[4] == wireVersion else {
            throw IrohaPeerWireMessageErrorV1.unsupportedWireVersion(data[4])
        }
        guard let encoding = IrohaPeerWireEncodingV1(rawValue: data[5]) else {
            throw IrohaPeerWireMessageErrorV1.unsupportedEncoding(data[5])
        }
        let rawProfile = data.ipmUInt16BE(at: 6)
        guard let profile = IrohaPeerWireProfileV1(rawValue: rawProfile), profile != .reject else {
            throw IrohaPeerWireMessageErrorV1.invalidProfile(rawProfile)
        }
        guard let kind = IrohaPeerWireKindV1(rawValue: data[8]) else {
            throw IrohaPeerWireMessageErrorV1.invalidKind(data[8])
        }
        guard data[9] == 0 else { throw IrohaPeerWireMessageErrorV1.invalidFlags(data[9]) }
        let schemaVersion = data.ipmUInt16BE(at: 10)
        guard schemaVersion != 0 else { throw IrohaPeerWireMessageErrorV1.invalidSchemaVersion }
        guard schemaVersion == profile.requiredSchemaVersion else {
            throw IrohaPeerWireMessageErrorV1.schemaVersionMismatch(
                profile: profile,
                expected: profile.requiredSchemaVersion,
                actual: schemaVersion
            )
        }
        let canonicalLength = Int(data.ipmUInt32BE(at: 12))
        let encodedLength = Int(data.ipmUInt32BE(at: 16))
        guard canonicalLength > 0 else {
            throw IrohaPeerWireMessageErrorV1.emptyCanonicalPayload
        }
        guard encodedLength > 0 else {
            throw IrohaPeerWireMessageErrorV1.emptyEncodedBody
        }
        guard canonicalLength <= min(limits.maximumCanonicalBytes, kind.maximumWalletFrameBytes) else {
            throw IrohaPeerWireMessageErrorV1.canonicalLengthOutOfRange(
                actual: canonicalLength,
                maximum: min(limits.maximumCanonicalBytes, kind.maximumWalletFrameBytes)
            )
        }
        let maximumEncoded = min(try limits.maximumEncodedBytes(for: profile), kind.maximumWalletFrameBytes)
        guard encodedLength <= maximumEncoded else {
            throw IrohaPeerWireMessageErrorV1.encodedLengthOutOfRange(
                actual: encodedLength,
                maximum: maximumEncoded
            )
        }
        guard encoding != .none || canonicalLength == encodedLength else {
            throw IrohaPeerWireMessageErrorV1.lengthMismatch
        }
        if encoding == .zlib {
            guard canonicalLength > 0,
                  encodedLength > 0,
                  canonicalLength >= encodedLength,
                  canonicalLength - encodedLength >= 32,
                  shardCount(encodedLength) < shardCount(canonicalLength) else {
                throw IrohaPeerWireMessageErrorV1.compressionPolicyNotSatisfied
            }
        }
        if let expectedProfile, expectedProfile != profile {
            throw IrohaPeerWireMessageErrorV1.unexpectedProfile(expected: expectedProfile, actual: profile)
        }
        if let expectedKind, expectedKind != kind {
            throw IrohaPeerWireMessageErrorV1.unexpectedKind(expected: expectedKind, actual: kind)
        }
        return IrohaPeerWireHeaderV1(
            encoding: encoding,
            profile: profile,
            kind: kind,
            schemaVersion: schemaVersion,
            canonicalLength: canonicalLength,
            encodedLength: encodedLength,
            canonicalHash: data.subdata(in: 20..<52),
            wireHash: data.subdata(in: 52..<84),
            bytes: data
        )
    }

    public static func decode(
        _ data: Data,
        expectedProfile: IrohaPeerWireProfileV1? = nil,
        expectedKind: IrohaPeerWireKindV1? = nil,
        limits: IrohaPeerWireLimitsV1 = .peerV1
    ) throws -> Self {
        guard data.count >= headerBytes else { throw IrohaPeerWireMessageErrorV1.lengthMismatch }
        let headerData = data.subdata(in: 0..<headerBytes)
        let header = try inspectHeader(
            headerData,
            expectedProfile: expectedProfile,
            expectedKind: expectedKind,
            limits: limits
        )
        guard data.count == headerBytes + header.encodedLength else {
            throw IrohaPeerWireMessageErrorV1.lengthMismatch
        }
        let encodedBody = data.subdata(in: headerBytes..<data.count)
        let expectedWireHash = Blake2b.hash256(
            wireHashDomain + headerData.subdata(in: 0..<52) + encodedBody
        )
        guard expectedWireHash == header.wireHash else {
            throw IrohaPeerWireMessageErrorV1.wireHashMismatch
        }
        let canonicalPayload: Data
        switch header.encoding {
        case .none:
            canonicalPayload = encodedBody
        case .zlib:
            canonicalPayload = try decodeZlib(
                encodedBody,
                expectedLength: header.canonicalLength,
                maximumLength: limits.maximumCanonicalBytes
            )
        }
        guard canonicalPayload.count == header.canonicalLength else {
            throw IrohaPeerWireMessageErrorV1.lengthMismatch
        }
        try validateCanonicalPayload(
            profile: header.profile,
            kind: header.kind,
            canonicalPayload: canonicalPayload
        )
        let expectedCanonicalHash = canonicalHash(
            profile: header.profile,
            kind: header.kind,
            schemaVersion: header.schemaVersion,
            canonicalPayload: canonicalPayload
        )
        guard expectedCanonicalHash == header.canonicalHash else {
            throw IrohaPeerWireMessageErrorV1.canonicalHashMismatch
        }
        return Self(header: header, canonicalPayload: canonicalPayload, encodedBody: encodedBody)
    }

    /// A wallet-profile Request requires its account companion and unchanged Native envelope.
    /// Other kinds contain one complete canonical `KagemushaWalletEnvelopeV1` frame within its kind's bound whose message tag is this IPM1 kind. The check is
    /// structural (`KagemushaWalletWireV1.inspectEnvelope`): the wallet still decodes, validates
    /// and verifies the message, and decides its scheme, before acting on it.
    private static func validateCanonicalPayload(
        profile: IrohaPeerWireProfileV1,
        kind: IrohaPeerWireKindV1,
        canonicalPayload: Data
    ) throws {
        guard profile == .kagemushaWalletV1 else { return }
        let original: Data
        if kind == .request {
            guard let request = try? IrohaPeerWalletRequestV1.decode(canonicalPayload) else {
                throw IrohaPeerWireMessageErrorV1.invalidCanonicalPayload(profile: profile, kind: kind)
            }
            original = request.requestEnvelope
        } else { original = canonicalPayload }
        guard canonicalPayload.count <= kind.maximumWalletFrameBytes,
              let envelope = try? KagemushaWalletWireV1.inspectEnvelope(original),
              envelope.kind == kind.walletMessageKind else {
            throw IrohaPeerWireMessageErrorV1.invalidCanonicalPayload(
                profile: profile,
                kind: kind
            )
        }
    }

    private static func selectEncoding(
        _ canonicalPayload: Data,
        policy: IrohaPeerWireCompressionPolicyV1,
        maximumEncodedBytes: Int
    ) throws -> (encoding: IrohaPeerWireEncodingV1, body: Data) {
        if policy == .peerOptimized,
           let compressed = encodeZlibIfSmaller(canonicalPayload),
           canonicalPayload.count - compressed.count >= 32,
           shardCount(compressed.count) < shardCount(canonicalPayload.count),
           compressed.count <= maximumEncodedBytes {
            return (.zlib, compressed)
        }
        guard canonicalPayload.count <= maximumEncodedBytes else {
            throw IrohaPeerWireMessageErrorV1.encodedLengthOutOfRange(
                actual: canonicalPayload.count,
                maximum: maximumEncodedBytes
            )
        }
        return (.none, canonicalPayload)
    }

    private static func shardCount(_ byteCount: Int) -> Int {
        (byteCount + qrDataShardBytes - 1) / qrDataShardBytes
    }

    private static func canonicalHash(
        profile: IrohaPeerWireProfileV1,
        kind: IrohaPeerWireKindV1,
        schemaVersion: UInt16,
        canonicalPayload: Data
    ) -> Data {
        var input = canonicalHashDomain
        input.ipmAppendUInt16BE(profile.rawValue)
        input.append(kind.rawValue)
        input.ipmAppendUInt16BE(schemaVersion)
        input.append(canonicalPayload)
        return Blake2b.hash256(input)
    }

    private static func makeHeaderPrefix(
        encoding: IrohaPeerWireEncodingV1,
        profile: IrohaPeerWireProfileV1,
        kind: IrohaPeerWireKindV1,
        schemaVersion: UInt16,
        canonicalLength: Int,
        encodedLength: Int,
        canonicalHash: Data
    ) -> Data {
        precondition(canonicalLength <= Int(UInt32.max))
        precondition(encodedLength <= Int(UInt32.max))
        precondition(canonicalHash.count == 32)
        var data = magic
        data.append(wireVersion)
        data.append(encoding.rawValue)
        data.ipmAppendUInt16BE(profile.rawValue)
        data.append(kind.rawValue)
        data.append(0)
        data.ipmAppendUInt16BE(schemaVersion)
        data.ipmAppendUInt32BE(UInt32(canonicalLength))
        data.ipmAppendUInt32BE(UInt32(encodedLength))
        data.append(canonicalHash)
        precondition(data.count == 52)
        return data
    }

    private static func encodeZlibIfSmaller(_ input: Data) -> Data? {
        guard !input.isEmpty else { return nil }
        // A QR-eligible candidate must be smaller than its input, so the input
        // size itself is a sufficient bounded destination capacity.
        var output = [UInt8](repeating: 0, count: input.count)
        let outputCapacity = output.count
        let encodedCount = input.withUnsafeBytes { inputBytes in
            output.withUnsafeMutableBytes { outputBytes in
                compression_encode_buffer(
                    outputBytes.bindMemory(to: UInt8.self).baseAddress!,
                    outputCapacity,
                    inputBytes.bindMemory(to: UInt8.self).baseAddress!,
                    input.count,
                    nil,
                    COMPRESSION_ZLIB
                )
            }
        }
        guard encodedCount > 0, encodedCount < input.count else { return nil }
        // Compression.framework emits an RFC 1951 stream for
        // COMPRESSION_ZLIB. Encoding id 1 is instead the interoperable RFC
        // 1950 form: canonical 32 KiB/no-dictionary header, DEFLATE body, and
        // the canonical-payload Adler-32 in network order.
        var wrapped = Data([0x78, 0x9C])
        wrapped.append(contentsOf: output.prefix(encodedCount))
        wrapped.ipmAppendUInt32BE(adler32(input))
        guard wrapped.count < input.count else { return nil }
        return wrapped
    }

    private static func decodeZlib(
        _ encoded: Data,
        expectedLength: Int,
        maximumLength: Int
    ) throws -> Data {
        guard expectedLength <= maximumLength else {
            throw IrohaPeerWireMessageErrorV1.canonicalLengthOutOfRange(
                actual: expectedLength,
                maximum: maximumLength
            )
        }
        guard !encoded.isEmpty, expectedLength > 0 else {
            throw IrohaPeerWireMessageErrorV1.decompressionFailed
        }
        guard encoded.count >= 6, encoded[0] == 0x78, encoded[1] == 0x9C else {
            throw IrohaPeerWireMessageErrorV1.decompressionFailed
        }
        let declaredAdler32 = encoded.ipmUInt32BE(at: encoded.count - 4)
        var stream = z_stream()
        guard inflateInit_(&stream, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            throw IrohaPeerWireMessageErrorV1.decompressionFailed
        }
        defer { inflateEnd(&stream) }

        // One extra byte detects expansion beyond the declared canonical size.
        var output = [UInt8](repeating: 0, count: expectedLength + 1)
        let outputCapacity = output.count
        var status = Int32(Z_STREAM_ERROR)
        encoded.withUnsafeBytes { rawInput in
            output.withUnsafeMutableBytes { rawOutput in
                stream.next_in = UnsafeMutablePointer(
                    mutating: rawInput.bindMemory(to: Bytef.self).baseAddress!
                )
                stream.avail_in = uInt(encoded.count)
                stream.next_out = rawOutput.bindMemory(to: Bytef.self).baseAddress!
                stream.avail_out = uInt(outputCapacity)
                status = inflate(&stream, Z_FINISH)
            }
        }
        guard status == Z_STREAM_END,
              stream.avail_in == 0,
              stream.total_out == uLong(expectedLength) else {
            throw IrohaPeerWireMessageErrorV1.decompressionFailed
        }
        let canonical = Data(output.prefix(expectedLength))
        guard adler32(canonical) == declaredAdler32 else {
            throw IrohaPeerWireMessageErrorV1.decompressionFailed
        }
        return canonical
    }

    private static func adler32(_ data: Data) -> UInt32 {
        let modulus: UInt32 = 65_521
        var first: UInt32 = 1
        var second: UInt32 = 0
        for byte in data {
            first = (first + UInt32(byte)) % modulus
            second = (second + first) % modulus
        }
        return second << 16 | first
    }
}

private extension Data {
    mutating func ipmAppendUInt16BE(_ value: UInt16) {
        append(UInt8(truncatingIfNeeded: value >> 8))
        append(UInt8(truncatingIfNeeded: value))
    }

    mutating func ipmAppendUInt32BE(_ value: UInt32) {
        append(UInt8(truncatingIfNeeded: value >> 24))
        append(UInt8(truncatingIfNeeded: value >> 16))
        append(UInt8(truncatingIfNeeded: value >> 8))
        append(UInt8(truncatingIfNeeded: value))
    }

    func ipmUInt16BE(at offset: Int) -> UInt16 {
        UInt16(self[offset]) << 8 | UInt16(self[offset + 1])
    }

    func ipmUInt32BE(at offset: Int) -> UInt32 {
        UInt32(self[offset]) << 24
            | UInt32(self[offset + 1]) << 16
            | UInt32(self[offset + 2]) << 8
            | UInt32(self[offset + 3])
    }
}
