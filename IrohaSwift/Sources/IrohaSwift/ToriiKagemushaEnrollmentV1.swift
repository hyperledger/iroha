import Foundation

/// One explicitly authorized enrollment service action, covered by the HTTP account signature.
public enum ToriiKagemushaEnrollmentActionV1: UInt32, CaseIterable, Sendable {
    case preKey = 0
    case evidence = 1
    case issue = 2
    case deliver = 3
}

/// Immutable transport DATA retaining the native dispatch and, only for Evidence, signed E5.
/// Reuse this same value after uncertain delivery with fresh HTTP authentication. Neither
/// constructing nor decoding the envelope verifies its native originals or creates a new attempt.
public struct ToriiKagemushaEnrollmentRequestV1: Equatable, Sendable, CustomStringConvertible {
    public static let maximumDispatchBytes = 16_384
    public static let maximumEvidenceBytes = 524_288
    public static let maximumBytes = 544 * 1024
    public let action: ToriiKagemushaEnrollmentActionV1
    public let dispatchOriginal: Data
    public let evidenceOriginal: Data
    public let canonicalOriginal: Data
    public var description: String { "ToriiKagemushaEnrollmentRequestV1(action=\(action), originals=[REDACTED])" }

    public init(action: ToriiKagemushaEnrollmentActionV1, dispatchOriginal: Data,
                evidenceOriginal: Data = Data()) throws {
        guard (1...Self.maximumDispatchBytes).contains(dispatchOriginal.count),
              evidenceOriginal.count <= Self.maximumEvidenceBytes,
              (action == .evidence) == !evidenceOriginal.isEmpty else {
            throw ToriiClientError.invalidPayload("invalid enrollment action/original bounds")
        }
        self.action = action
        self.dispatchOriginal = Data([UInt8](dispatchOriginal))
        self.evidenceOriginal = Data([UInt8](evidenceOriginal))
        var payload = CompactNoritoWriter()
        payload.writeField(CompactNorito.encodeUInt16(1))
        payload.writeField(CompactNorito.encodeUInt32(action.rawValue))
        payload.writeField(CompactNorito.encodeBytesVec(self.dispatchOriginal))
        payload.writeField(CompactNorito.encodeBytesVec(self.evidenceOriginal))
        canonicalOriginal = EnrollmentServiceCodec.frame(payload.data, schema: .request)
        guard canonicalOriginal.count <= Self.maximumBytes else {
            throw ToriiClientError.invalidPayload("enrollment request exceeds complete frame bound")
        }
    }

    /// Admit only the single current canonical request layout; recovery preserves every byte.
    public init(canonicalOriginal: Data) throws {
        var reader = try EnrollmentServiceCodec.reader(canonicalOriginal, schema: .request,
                                                       maximum: Self.maximumBytes)
        guard try reader.readCompactField() == CompactNorito.encodeUInt16(1) else {
            throw ToriiClientError.invalidPayload("invalid enrollment request version")
        }
        var actionReader = CanonicalNoritoReader(data: try reader.readCompactField())
        guard let action = try ToriiKagemushaEnrollmentActionV1(rawValue: actionReader.readUInt32LE()),
              actionReader.remaining() == 0 else {
            throw ToriiClientError.invalidPayload("unknown enrollment action")
        }
        let dispatch = try EnrollmentServiceCodec.bytes(&reader, maximum: Self.maximumDispatchBytes)
        let evidence = try EnrollmentServiceCodec.bytes(&reader, maximum: Self.maximumEvidenceBytes)
        guard reader.remaining() == 0 else {
            throw ToriiClientError.invalidPayload("trailing enrollment request fields")
        }
        try self.init(action: action, dispatchOriginal: dispatch, evidenceOriginal: evidence)
        guard self.canonicalOriginal == canonicalOriginal else {
            throw ToriiClientError.invalidPayload("noncanonical enrollment request")
        }
    }
}

/// Bounded canonical service output. Permit and Credential remain unverified originals:
/// pass them to the same native enrollment owner for authority, deadline and custody checks.
public struct ToriiKagemushaEnrollmentResponseV1: Equatable, Sendable, CustomStringConvertible {
    public static let maximumPermitBytes = 2_048
    public static let maximumCredentialBytes = 262_144
    public static let maximumBytes = 264 * 1024

    /// Pending retains the consumed attempt; it never authorizes new platform evidence.
    public enum Outcome: Equatable, Sendable {
        case permit(Data)
        case evidenceReady
        case pending
        case credentialReady
        case credential(Data)
    }

    public let outcome: Outcome
    public let canonicalOriginal: Data
    public var description: String { "ToriiKagemushaEnrollmentResponseV1(originals=[REDACTED])" }

    public init(canonicalOriginal: Data) throws {
        var reader = try EnrollmentServiceCodec.reader(canonicalOriginal, schema: .response,
                                                       maximum: Self.maximumBytes)
        let tag = try reader.readUInt32LE()
        var payload = CompactNoritoWriter()
        payload.writeUInt32LE(tag)
        switch tag {
        case 0, 4:
            let bytes = try EnrollmentServiceCodec.bytes(&reader,
                maximum: tag == 0 ? Self.maximumPermitBytes : Self.maximumCredentialBytes)
            guard !bytes.isEmpty else {
                throw ToriiClientError.invalidPayload("empty enrollment response original")
            }
            outcome = tag == 0 ? .permit(bytes) : .credential(bytes)
            payload.writeField(CompactNorito.encodeBytesVec(bytes))
        case 1: outcome = .evidenceReady
        case 2: outcome = .pending
        case 3: outcome = .credentialReady
        default: throw ToriiClientError.invalidPayload("unknown enrollment response")
        }
        // Rust emits COMPACT_LEN only when the selected variant has a field.
        let flags: UInt8 = (tag == 0 || tag == 4) ? NoritoHeader.compactLen : 0
        guard reader.remaining() == 0,
              EnrollmentServiceCodec.frame(payload.data, schema: .response, flags: flags) == canonicalOriginal else {
            throw ToriiClientError.invalidPayload("noncanonical enrollment response")
        }
        self.canonicalOriginal = Data([UInt8](canonicalOriginal))
    }

    func requireAction(_ action: ToriiKagemushaEnrollmentActionV1) throws {
        switch (action, outcome) {
        case (.preKey, .permit), (.evidence, .evidenceReady), (.evidence, .pending),
             (.issue, .credentialReady), (.deliver, .credential): return
        default: throw ToriiClientError.invalidPayload("enrollment response does not match requested action")
        }
    }
}

/// The Rust shared service schema uses compact fields, raw Vec<u8> and u32 enum tags.
/// Both envelope types have eight-byte payload alignment (zero padding after the 40-byte header).
private enum EnrollmentServiceCodec {
    enum Schema: String {
        case request = "iroha.torii.kagemusha.enrollment.request.v1"
        case response = "iroha.torii.kagemusha.enrollment.response.v1"
    }

    static func frame(_ payload: Data, schema: Schema, flags: UInt8 = NoritoHeader.compactLen) -> Data {
        noritoEncode(typeName: schema.rawValue, payload: payload,
                     flags: flags, payloadAlignment: 8)
    }

    static func reader(_ original: Data, schema: Schema, maximum: Int) throws -> CanonicalNoritoReader {
        guard !original.isEmpty, original.count <= maximum else {
            throw ToriiClientError.invalidPayload("enrollment envelope exceeds frame bound")
        }
        let bytes = Data([UInt8](original))
        guard let decoded = noritoDecodeFrame(bytes), decoded.paddingLength == 0,
              (decoded.header.flags == NoritoHeader.compactLen ||
               (schema == .response && decoded.header.flags == 0)),
              decoded.header.schema == noritoSchemaHash(forTypeName: schema.rawValue),
              frame(decoded.payload, schema: schema, flags: decoded.header.flags) == bytes else {
            throw ToriiClientError.invalidPayload("invalid canonical enrollment frame")
        }
        return CanonicalNoritoReader(data: decoded.payload)
    }

    static func bytes(_ reader: inout CanonicalNoritoReader, maximum: Int) throws -> Data {
        let fieldLength = try reader.readVarint()
        guard fieldLength >= 8, fieldLength <= UInt64(maximum + 8) else {
            throw ToriiClientError.invalidPayload("enrollment original field exceeds bound")
        }
        let count = try reader.readUInt64LE()
        guard count == fieldLength - 8 else {
            throw ToriiClientError.invalidPayload("enrollment original count differs from field length")
        }
        return try reader.readBytes(Int(count))
    }
}
