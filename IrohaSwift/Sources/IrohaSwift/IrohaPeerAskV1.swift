import Foundation

/// Failure of an `IAK1` ask record or of its QR text.
public enum IrohaPeerAskErrorV1: Error, Equatable, Sendable {
    /// The record is not exactly ``IrohaPeerAskV1/recordBytes`` bytes.
    case invalidLength
    /// The record does not start with `IAK1`.
    case invalidMagic
    /// The record version is not 1.
    case unsupportedVersion
    /// The flags byte is not zero.
    case invalidFlags
    /// The payload profile is not a known profile.
    case invalidProfile
    /// The amount is zero.
    case invalidAmount
    /// The receiver account digest is not 32 bytes or is all zero.
    case invalidAccountDigest
    /// The text is not exactly `IAK1:`, canonical Base45 of one record and `:`.
    case invalidText
}

/// The receiver's ask (`specs/kagemusha_wallet_wire_v1.md` §6, Ask): the amount the receiver
/// sets and its account digest `H(account, original)`. Native requires the Request amount to
/// equal the Offer amount, so the ask reaches the payer before the payer builds its Offer: over
/// NFC `GET_ASK` (`IrohaPeerNfcOfferExchangeV1.runFromAsk(offerFactory:)`), as the first Nearby
/// record after authentication (``IrohaPeerNearbySessionV1/sealAsk(_:)``) or as one QR text
/// (``toText()``).
///
/// The fixed 56-byte `IAK1` record is `"IAK1" ‖ 1 ‖ flags 0 ‖ BE16 profile ‖ LE128 amount ‖
/// receiver account digest`; its QR text is `IAK1:` ‖ canonical Base45 (RFC 9285) ‖ `:`, always
/// 90 characters. Every value matches the Kotlin `IrohaPeerAskV1` byte for byte
/// (`fixtures/kagemusha/peer_ask_v1.json`).
///
/// Display DATA only. An ask is unsigned, belongs to no wallet object digest and authorizes
/// nothing: the payer's hardware-confirmed review of the receiver-signed Request stays the only
/// approval, and the receiver declines an Offer whose amount differs from its ask
/// (``KagemushaWalletWireV1/offerAmountData(_:)``).
public struct IrohaPeerAskV1: Equatable, Sendable {
    /// Bytes of one `IAK1` record.
    public static let recordBytes = 56
    /// Prefix of the QR text.
    public static let textPrefix = "IAK1:"

    private static let magic = Data("IAK1".utf8)
    private static let version: UInt8 = 1
    private static let textSuffix = ":"
    /// The prefix, three Base45 characters per two record bytes and the suffix.
    private static let textBytes = textPrefix.utf8.count + recordBytes / 2 * 3 + textSuffix.utf8.count

    /// Asked amount in the asset's smallest unit; never zero.
    public let amount: KagemushaWalletUInt128V1
    /// Receiver account digest `H(account, original)`: 32 bytes, not all zero.
    public let receiverAccountDigest: Data
    /// The receiver's account check code (``KagemushaWalletAccountCheckCodeV1``) for
    /// ``receiverAccountDigest``.
    public let checkCode: String

    /// The ask for `amount` to the account whose digest is `receiverAccountDigest`.
    ///
    /// - Throws: ``IrohaPeerAskErrorV1/invalidAmount`` for a zero amount and
    ///   ``IrohaPeerAskErrorV1/invalidAccountDigest`` for a digest that is not 32 bytes or is all
    ///   zero.
    public init(amount: KagemushaWalletUInt128V1, receiverAccountDigest: Data) throws {
        guard amount.low != 0 || amount.high != 0 else {
            throw IrohaPeerAskErrorV1.invalidAmount
        }
        let digest = Data(receiverAccountDigest)
        guard digest.count == KagemushaWalletWireV1.digestBytes,
              digest.contains(where: { $0 != 0 }) else {
            throw IrohaPeerAskErrorV1.invalidAccountDigest
        }
        self.amount = amount
        self.receiverAccountDigest = digest
        self.checkCode = try KagemushaWalletAccountCheckCodeV1.code(accountDigest: digest)
    }

    /// The ask for `amount` to the I105 account `accountID`, through its canonical account
    /// original (``KagemushaWalletAccountOriginalV1``), so ``checkCode`` equals
    /// ``KagemushaWalletAccountCheckCodeV1/code(accountID:)``.
    ///
    /// - Throws: ``IrohaPeerAskErrorV1/invalidAmount`` for a zero amount, or what
    ///   ``KagemushaWalletAccountOriginalV1/encode(_:)`` throws for the account.
    public init(amount: KagemushaWalletUInt128V1, accountID: String) throws {
        try self.init(
            amount: amount,
            receiverAccountDigest: KagemushaWalletWireV1.digest(
                role: .account,
                body: KagemushaWalletAccountOriginalV1.encode(accountID)
            )
        )
    }

    /// The 56-byte `IAK1` record.
    public func encode() -> Data {
        var record = Self.magic
        record.append(Self.version)
        record.append(0)
        let profile = IrohaPeerPayloadProfile.kagemushaWalletV1.rawValue
        record.append(UInt8(truncatingIfNeeded: profile >> 8))
        record.append(UInt8(truncatingIfNeeded: profile))
        withUnsafeBytes(of: amount.low.littleEndian) { record.append(contentsOf: $0) }
        withUnsafeBytes(of: amount.high.littleEndian) { record.append(contentsOf: $0) }
        record.append(receiverAccountDigest)
        precondition(record.count == Self.recordBytes)
        return record
    }

    /// The QR text: `IAK1:` ‖ canonical Base45 of ``encode()`` ‖ `:`.
    public func toText() -> String {
        Self.textPrefix + IrohaBase45V1.encode(encode()) + Self.textSuffix
    }

    /// Strictly decode one `IAK1` record. Any other length, magic, version, flags or profile, a
    /// zero amount and a zero digest are refused, in that order.
    ///
    /// - Throws: ``IrohaPeerAskErrorV1``.
    public static func decode(_ record: Data) throws -> IrohaPeerAskV1 {
        let bytes = [UInt8](record)
        guard bytes.count == recordBytes else { throw IrohaPeerAskErrorV1.invalidLength }
        guard Data(bytes[0..<4]) == magic else { throw IrohaPeerAskErrorV1.invalidMagic }
        guard bytes[4] == version else { throw IrohaPeerAskErrorV1.unsupportedVersion }
        guard bytes[5] == 0 else { throw IrohaPeerAskErrorV1.invalidFlags }
        // Exhaustive on purpose: a new profile must decide here how its asks encode.
        switch IrohaPeerPayloadProfile(rawValue: UInt16(bytes[6]) << 8 | UInt16(bytes[7])) {
        case .kagemushaWalletV1:
            break
        case .reject, nil:
            throw IrohaPeerAskErrorV1.invalidProfile
        }
        func u64(_ offset: Int) -> UInt64 {
            (0..<8).reduce(UInt64(0)) { $0 | (UInt64(bytes[offset + $1]) << (8 * $1)) }
        }
        return try IrohaPeerAskV1(
            amount: KagemushaWalletUInt128V1(low: u64(8), high: u64(16)),
            receiverAccountDigest: Data(bytes[24..<recordBytes])
        )
    }

    /// Strictly decode the QR text: exactly `IAK1:`, 84 Base45 characters and `:`, compared as
    /// UTF-8 bytes, whose body re-encodes to itself (no lowercase, whitespace, foreign characters
    /// or truncation); then ``decode(_:)``.
    ///
    /// - Throws: ``IrohaPeerAskErrorV1/invalidText`` for the text, or what ``decode(_:)`` throws
    ///   for the record it carries.
    public static func fromText(_ text: String) throws -> IrohaPeerAskV1 {
        let bytes = Array(text.utf8)
        let prefix = Array(textPrefix.utf8)
        let suffix = Array(textSuffix.utf8)
        guard bytes.count == textBytes,
              bytes.starts(with: prefix),
              Array(bytes.suffix(suffix.count)) == suffix else {
            throw IrohaPeerAskErrorV1.invalidText
        }
        let body = Array(bytes[prefix.count..<(bytes.count - suffix.count)])
        guard let record = IrohaBase45V1.decode(String(decoding: body, as: UTF8.self)),
              Array(IrohaBase45V1.encode(record).utf8) == body else {
            throw IrohaPeerAskErrorV1.invalidText
        }
        return try decode(record)
    }
}

extension IrohaPeerAskV1: CustomStringConvertible {
    /// Names the record only: the amount and the receiver's digest stay out of logs.
    public var description: String { "IrohaPeerAskV1(kagemushaWalletV1)" }
}
