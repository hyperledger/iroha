import Foundation
import CryptoKit

public enum ConfidentialEncryptedPayloadError: Error, Sendable, Equatable {
    case unsupportedVersion(UInt8)
    case invalidEphemeralKeyLength(Int)
    case invalidEphemeralPublicKey
    case invalidNonceLength(Int)
    case emptyCiphertext
    case ciphertextTooLarge
    case truncatedPayload
    case varintOverflow
    case trailingBytes(Int)
}

extension ConfidentialEncryptedPayloadError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case let .unsupportedVersion(version):
            return "Unsupported encrypted payload version: \(version)."
        case let .invalidEphemeralKeyLength(length):
            return "Ephemeral public key must be 32 bytes; got \(length)."
        case .invalidEphemeralPublicKey:
            return "Ephemeral public key must be a valid non-low-order X25519 public key."
        case let .invalidNonceLength(length):
            return "Nonce must be 24 bytes; got \(length)."
        case .emptyCiphertext:
            return "Ciphertext must not be empty."
        case .ciphertextTooLarge:
            return "Ciphertext length exceeds supported range."
        case .truncatedPayload:
            return "Encrypted payload bytes ended unexpectedly."
        case .varintOverflow:
            return "Length varint overflow while decoding encrypted payload."
        case let .trailingBytes(count):
            return "Encrypted payload contains \(count) trailing bytes."
        }
    }
}

public struct ConfidentialEncryptedPayload: Equatable, Sendable {
    public static let v1: UInt8 = 1
    private static let typeName = "iroha_data_model::confidential::ConfidentialEncryptedPayload"
    private static let lowOrderProbePrivateKey = Data(repeating: 0x01, count: 32)

    public let version: UInt8
    public let ephemeralPublicKey: Data
    public let nonce: Data
    public let ciphertext: Data

    public init(version: UInt8 = ConfidentialEncryptedPayload.v1,
                ephemeralPublicKey: Data,
                nonce: Data,
                ciphertext: Data) throws {
        guard ephemeralPublicKey.count == 32 else {
            throw ConfidentialEncryptedPayloadError.invalidEphemeralKeyLength(ephemeralPublicKey.count)
        }
        guard nonce.count == 24 else {
            throw ConfidentialEncryptedPayloadError.invalidNonceLength(nonce.count)
        }
        guard version == ConfidentialEncryptedPayload.v1 else {
            throw ConfidentialEncryptedPayloadError.unsupportedVersion(version)
        }
        guard !ciphertext.isEmpty else {
            throw ConfidentialEncryptedPayloadError.emptyCiphertext
        }
        guard !Self.isLowOrderX25519PublicKey(ephemeralPublicKey) else {
            throw ConfidentialEncryptedPayloadError.invalidEphemeralPublicKey
        }
        self.version = version
        self.ephemeralPublicKey = ephemeralPublicKey
        self.nonce = nonce
        self.ciphertext = ciphertext
    }

    public func serializedPayload() throws -> Data {
        guard ciphertext.count <= Int(UInt32.max) else {
            throw ConfidentialEncryptedPayloadError.ciphertextTooLarge
        }
        var payload = Data()
        payload.reserveCapacity(1 + ephemeralPublicKey.count + nonce.count + 5 + ciphertext.count)
        payload.append(version)
        payload.append(ephemeralPublicKey)
        payload.append(nonce)
        Self.appendVarint(UInt64(ciphertext.count), into: &payload)
        payload.append(ciphertext)
        return payload
    }

    public func noritoEnvelope(flags: UInt8 = NoritoHeader.compactLen) throws -> Data {
        let payload = try serializedPayload()
        return noritoEncode(typeName: Self.typeName, payload: payload, flags: flags)
    }

    public func asHexDictionary() -> [String: String] {
        [
            "version": String(format: "%02x", version),
            "ephemeral_pubkey": ephemeralPublicKey.map { String(format: "%02x", $0) }.joined(),
            "nonce": nonce.map { String(format: "%02x", $0) }.joined(),
            "ciphertext": ciphertext.map { String(format: "%02x", $0) }.joined(),
        ]
    }

    public static func deserialize(from payload: Data) throws -> ConfidentialEncryptedPayload {
        var reader = NoritoReader(bytes: payload)
        let version = try reader.readU8()
        let ephemeral = try reader.readFixed(count: 32)
        let nonce = try reader.readFixed(count: 24)
        let length = try reader.readVarint()
        guard length <= UInt64(Int.max) else {
            throw ConfidentialEncryptedPayloadError.ciphertextTooLarge
        }
        let ciphertext = try reader.readFixed(count: Int(length))
        let remaining = reader.remainingCount
        guard remaining == 0 else {
            throw ConfidentialEncryptedPayloadError.trailingBytes(remaining)
        }
        return try ConfidentialEncryptedPayload(version: version,
                                                ephemeralPublicKey: ephemeral,
                                                nonce: nonce,
                                                ciphertext: ciphertext)
    }

    private static func appendVarint(_ value: UInt64, into buffer: inout Data) {
        var remaining = value
        while remaining >= 0x80 {
            buffer.append(UInt8(remaining & 0x7F) | 0x80)
            remaining >>= 7
        }
        buffer.append(UInt8(remaining))
    }

    private static func isLowOrderX25519PublicKey(_ publicKey: Data) -> Bool {
        do {
            let probe = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: lowOrderProbePrivateKey)
            let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
            let sharedSecret = try probe.sharedSecretFromKeyAgreement(with: peer)
            return sharedSecret.withUnsafeBytes { bytes in
                bytes.allSatisfy { $0 == 0 }
            }
        } catch {
            return true
        }
    }
}

private struct NoritoReader {
    private let bytes: Data
    private(set) var index: Int = 0

    init(bytes: Data) { self.bytes = bytes }

    var remainingCount: Int { bytes.count - index }

    mutating func readU8() throws -> UInt8 {
        guard index < bytes.count else {
            throw ConfidentialEncryptedPayloadError.truncatedPayload
        }
        let value = bytes[index]
        index += 1
        return value
    }

    mutating func readFixed(count: Int) throws -> Data {
        guard count >= 0 else { return Data() }
        guard index + count <= bytes.count else {
            throw ConfidentialEncryptedPayloadError.truncatedPayload
        }
        let slice = bytes[index..<(index + count)]
        index += count
        return Data(slice)
    }

    mutating func readVarint() throws -> UInt64 {
        var value: UInt64 = 0
        var shift: UInt8 = 0
        while true {
            let byte = try readU8()
            value |= UInt64(byte & 0x7F) << shift
            if (byte & 0x80) == 0 { break }
            shift += 7
            if shift >= 64 {
                throw ConfidentialEncryptedPayloadError.varintOverflow
            }
        }
        return value
    }
}
