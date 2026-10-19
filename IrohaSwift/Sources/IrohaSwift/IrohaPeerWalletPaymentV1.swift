import Foundation

/// Exact Payment transport originals (`KWPYPC1`). IPM1 hashes cover both; only Native authenticates them.
/// The companion is the payer's canonical `KagemushaWalletPayerCompanionV1` DATA (its credential
/// and issuer certificate set) that the receiver hands unchanged to Receive. Structural decoding
/// supplies no signature, credential, financial or digest-binding verdict.
///
/// `"KWPYPC1" ‖ 0x00 ‖ BE32 envelope_length ‖ BE32 companion_length ‖ payment_envelope ‖ companion`:
/// a 1...10,000-byte Payment envelope and a 1...2,048-byte companion, at most 12,064 bytes in all.
public struct IrohaPeerWalletPaymentV1: Sendable, Equatable {
    public static let headerBytes = 16
    public static let maximumCompanionBytes = KagemushaWalletWireV1.payerCompanionMaximumBytes
    public static let maximumBytes = headerBytes + KagemushaWalletWireV1.messageMaximumBytes + maximumCompanionBytes
    private static let magic = Data("KWPYPC1\0".utf8)
    public let paymentEnvelope: Data
    public let payerCompanion: Data

    public init(paymentEnvelope: Data, payerCompanion: Data) throws {
        guard (1...KagemushaWalletWireV1.messageMaximumBytes).contains(paymentEnvelope.count),
              (1...Self.maximumCompanionBytes).contains(payerCompanion.count),
              try KagemushaWalletWireV1.inspectEnvelope(paymentEnvelope).kind == .payment else {
            throw Self.invalid()
        }
        self.paymentEnvelope = Data(paymentEnvelope)
        self.payerCompanion = Data(payerCompanion)
    }
    public func encode() -> Data {
        var bytes = Self.magic
        for value in [paymentEnvelope.count, payerCompanion.count] {
            for shift in stride(from: 24, through: 0, by: -8) {
                bytes.append(UInt8(truncatingIfNeeded: value >> shift))
            }
        }
        bytes.append(paymentEnvelope)
        bytes.append(payerCompanion)
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
        let companionLength = try length(12, maximumCompanionBytes)
        guard bytes.count == headerBytes + envelopeLength + companionLength else { throw invalid() }
        return try .init(paymentEnvelope: Data(bytes[headerBytes..<headerBytes + envelopeLength]),
                         payerCompanion: Data(bytes[(headerBytes + envelopeLength)...]))
    }
    private static func invalid() -> IrohaPeerWireMessageErrorV1 {
        .invalidCanonicalPayload(profile: .kagemushaWalletV1, kind: .payment)
    }
}
