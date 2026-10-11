import Foundation

/// Exact Request transport originals. IPM1 hashes cover both; only Native authenticates them.
/// The companion is canonical AccountId DATA from the receiving wallet. Structural decoding
/// supplies no signature, recipient, financial or digest-binding verdict.
public struct IrohaPeerWalletRequestV1: Sendable, Equatable {
    public static let headerBytes = 16
    public static let maximumAccountBytes = 4_096
    public static let maximumBytes = headerBytes + KagemushaWalletWireV1.messageMaximumBytes + maximumAccountBytes
    private static let magic = Data("KWRQAC1\0".utf8)
    public let requestEnvelope: Data
    public let destinationAccountOriginal: Data

    public init(requestEnvelope: Data, destinationAccountOriginal: Data) throws {
        guard (1...KagemushaWalletWireV1.messageMaximumBytes).contains(requestEnvelope.count),
              (1...Self.maximumAccountBytes).contains(destinationAccountOriginal.count),
              try KagemushaWalletWireV1.inspectEnvelope(requestEnvelope).kind == .request else {
            throw Self.invalid()
        }
        self.requestEnvelope = Data(requestEnvelope)
        self.destinationAccountOriginal = Data(destinationAccountOriginal)
    }
    public func encode() -> Data {
        var bytes = Self.magic
        for value in [requestEnvelope.count, destinationAccountOriginal.count] {
            for shift in stride(from: 24, through: 0, by: -8) {
                bytes.append(UInt8(truncatingIfNeeded: value >> shift))
            }
        }
        bytes.append(requestEnvelope)
        bytes.append(destinationAccountOriginal)
        return bytes
    }
    public static func decode(_ original: Data) throws -> Self {
        guard (headerBytes + 2...maximumBytes).contains(original.count) else { throw invalid() }
        let bytes = [UInt8](original)
        guard Data(bytes.prefix(8)) == magic else { throw invalid() }
        func length(_ offset: Int, _ maximum: Int) throws -> Int {
            var value: UInt64 = 0
            for index in offset..<offset + 4 { value = (value << 8) | UInt64(bytes[index]) }
            guard value > 0 && value <= UInt64(maximum) else { throw invalid() }
            return Int(value)
        }
        let envelopeLength = try length(8, KagemushaWalletWireV1.messageMaximumBytes)
        let accountLength = try length(12, maximumAccountBytes)
        guard bytes.count == headerBytes + envelopeLength + accountLength else { throw invalid() }
        return try .init(requestEnvelope: Data(bytes[headerBytes..<headerBytes + envelopeLength]),
                         destinationAccountOriginal: Data(bytes[(headerBytes + envelopeLength)...]))
    }
    private static func invalid() -> IrohaPeerWireMessageErrorV1 {
        .invalidCanonicalPayload(profile: .kagemushaWalletV1, kind: .request)
    }
}

/// The current IPM1 wallet carrier. Request always includes its account companion.
public enum IrohaPeerKagemushaWalletAdapterV1 {
    public static func wrap(_ envelope: Data, destinationAccountOriginal: Data? = nil,
                            compressionPolicy: IrohaPeerWireCompressionPolicyV1 = .disabled) throws -> IrohaPeerWireMessageV1 {
        let frame = try KagemushaWalletWireV1.inspectEnvelope(envelope)
        guard let kind = IrohaPeerWireKindV1(rawValue: UInt8(frame.kind.rawValue)) else {
            throw IrohaPeerWireMessageErrorV1.invalidKind(UInt8(frame.kind.rawValue))
        }
        let payload: Data
        if kind == .request {
            guard let destinationAccountOriginal else {
                throw IrohaPeerWireMessageErrorV1.invalidCanonicalPayload(profile: .kagemushaWalletV1, kind: .request)
            }
            payload = try IrohaPeerWalletRequestV1(requestEnvelope: envelope,
                destinationAccountOriginal: destinationAccountOriginal).encode()
        } else {
            guard destinationAccountOriginal == nil else {
                throw IrohaPeerWireMessageErrorV1.invalidCanonicalPayload(profile: .kagemushaWalletV1, kind: kind)
            }
            payload = envelope
        }
        return try IrohaPeerWireMessageV1(profile: .kagemushaWalletV1, kind: kind,
            schemaVersion: KagemushaWalletWireV1.version, canonicalPayload: payload,
            compressionPolicy: compressionPolicy)
    }

    public static func decode(_ message: IrohaPeerWireMessageV1) throws -> Data {
        guard message.profile == .kagemushaWalletV1 else {
            throw IrohaPeerWireMessageErrorV1.invalidProfile(message.profile.rawValue)
        }
        return message.kind == .request
            ? try IrohaPeerWalletRequestV1.decode(message.canonicalPayload).requestEnvelope : message.canonicalPayload
    }

    public static func destinationAccountOriginal(_ message: IrohaPeerWireMessageV1) throws -> Data {
        guard message.profile == .kagemushaWalletV1 && message.kind == .request else {
            throw IrohaPeerWireMessageErrorV1.invalidCanonicalPayload(profile: message.profile, kind: message.kind)
        }
        return try IrohaPeerWalletRequestV1.decode(message.canonicalPayload).destinationAccountOriginal
    }
}
