import Foundation

/// Stable strict-decoder categories for Kotodama V1 exact numerics.
public enum KotodamaNumericV1ErrorCode: String, Sendable {
    case mantissaOverflow = "mantissa_overflow"
    case noncanonicalMantissa = "noncanonical_mantissa"
    case invalidScale = "invalid_scale"
    case noncanonicalDecimal = "noncanonical_decimal"
    case negativeQuantity = "negative_quantity"
    case invalidText = "invalid_text"
    case frameTooShort = "frame_too_short"
    case frameTooLarge = "frame_too_large"
    case invalidHeader = "invalid_header"
    case schemaMismatch = "schema_mismatch"
    case compressionNotAllowed = "compression_not_allowed"
    case layoutFlagsNotAllowed = "layout_flags_not_allowed"
    case lengthMismatch = "length_mismatch"
    case checksumMismatch = "checksum_mismatch"
    case truncatedEnvelope = "truncated_envelope"
    case unknownType = "unknown_type"
    case typeNotAllowed = "type_not_allowed"
    case wrongType = "wrong_type"
    case invalidEnvelopeVersion = "invalid_envelope_version"
    case oversizedLength = "oversized_length"
    case payloadHashMismatch = "payload_hash_mismatch"
}

/// Strict Kotodama V1 numeric validation failure.
public struct KotodamaNumericV1Error: Swift.Error, Equatable, Sendable {
    public let code: KotodamaNumericV1ErrorCode
    public let message: String

    public init(code: KotodamaNumericV1ErrorCode, message: String) {
        self.code = code
        self.message = message
    }
}

private func numericFailure(_ code: KotodamaNumericV1ErrorCode, _ message: String) -> KotodamaNumericV1Error {
    KotodamaNumericV1Error(code: code, message: message)
}

/// Lossless signed 512-bit Kotodama integer represented by canonical decimal text.
public struct KotodamaInt: Equatable, Hashable, Sendable, CustomStringConvertible {
    public let canonicalString: String

    public init(_ value: String) throws {
        guard numericFullMatch(value, pattern: #"-?(?:0|[1-9][0-9]*)"#), value != "-0" else {
            throw numericFailure(.invalidText, "int must use canonical base-10 syntax")
        }
        guard value.utf8.count <= NumericV1Internal.maximumIntTextBytes else {
            throw numericFailure(.mantissaOverflow, "integer text exceeds the signed 512-bit input bound")
        }
        _ = try NumericV1Internal.encodeTwos(value)
        canonicalString = value
    }

    fileprivate init(validated value: String) {
        canonicalString = value
    }

    public var description: String { canonicalString }
}

/// Lossless exact Kotodama decimal represented by a canonical mantissa and scale.
public struct KotodamaDecimal: Equatable, Hashable, Sendable, CustomStringConvertible {
    public let mantissa: KotodamaInt
    public let scale: UInt8

    public init(_ value: String) throws {
        let parsed = try NumericV1Internal.parseScaled(value, quantity: false)
        mantissa = parsed.mantissa
        scale = parsed.scale
    }

    public init(mantissa: KotodamaInt, scale: UInt8) throws {
        let normalized = try NumericV1Internal.normalizeScaled(
            mantissa.canonicalString,
            scale: Int(scale),
            quantity: false
        )
        self.mantissa = normalized.mantissa
        self.scale = normalized.scale
    }

    fileprivate init(canonicalMantissa: KotodamaInt, scale: UInt8) {
        mantissa = canonicalMantissa
        self.scale = scale
    }

    public var canonicalString: String {
        NumericV1Internal.scaledText(mantissa.canonicalString, scale: Int(scale))
    }

    public var description: String { canonicalString }
}

/// Lossless nominal non-negative Kotodama asset quantity.
public struct KotodamaQuantity: Equatable, Hashable, Sendable, CustomStringConvertible {
    public let mantissa: KotodamaInt
    public let scale: UInt8

    public init(_ value: String) throws {
        let parsed = try NumericV1Internal.parseScaled(value, quantity: true)
        mantissa = parsed.mantissa
        scale = parsed.scale
    }

    public init(mantissa: KotodamaInt, scale: UInt8) throws {
        let normalized = try NumericV1Internal.normalizeScaled(
            mantissa.canonicalString,
            scale: Int(scale),
            quantity: true
        )
        self.mantissa = normalized.mantissa
        self.scale = normalized.scale
    }

    fileprivate init(canonicalMantissa: KotodamaInt, scale: UInt8) {
        mantissa = canonicalMantissa
        self.scale = scale
    }

    public var canonicalString: String {
        NumericV1Internal.scaledText(mantissa.canonicalString, scale: Int(scale))
    }

    public var description: String { canonicalString }
}

/// Canonical schema-bound frames and pointer envelopes for Kotodama V1 numerics.
public enum KotodamaNumericV1Codec {
    public static func encodeIntJSON(_ value: KotodamaInt) -> String {
        value.canonicalString
    }

    public static func encodeDecimalJSON(_ value: KotodamaDecimal) -> String {
        value.canonicalString
    }

    public static func encodeQuantityJSON(_ value: KotodamaQuantity) -> String {
        value.canonicalString
    }

    public static func decodeIntJSON(_ value: String) throws -> KotodamaInt {
        try KotodamaInt(value)
    }

    public static func decodeDecimalJSON(_ value: String) throws -> KotodamaDecimal {
        let decoded = try KotodamaDecimal(value)
        guard decoded.canonicalString == value else {
            throw numericFailure(.invalidText, "decimal JSON must use canonical spelling")
        }
        return decoded
    }

    public static func decodeQuantityJSON(_ value: String) throws -> KotodamaQuantity {
        let decoded = try KotodamaQuantity(value)
        guard decoded.canonicalString == value else {
            throw numericFailure(.invalidText, "quantity JSON must use canonical spelling")
        }
        return decoded
    }

    public static func encodeIntFrame(_ value: KotodamaInt) throws -> Data {
        try NumericV1Internal.encodeFrame(.int, mantissa: value, scale: 0)
    }

    public static func encodeDecimalFrame(_ value: KotodamaDecimal) throws -> Data {
        try NumericV1Internal.encodeFrame(.decimal, mantissa: value.mantissa, scale: value.scale)
    }

    public static func encodeQuantityFrame(_ value: KotodamaQuantity) throws -> Data {
        try NumericV1Internal.encodeFrame(.quantity, mantissa: value.mantissa, scale: value.scale)
    }

    public static func decodeIntFrame(_ frame: Data) throws -> KotodamaInt {
        try NumericV1Internal.decodeFrame(.int, frame: frame).mantissa
    }

    public static func decodeDecimalFrame(_ frame: Data) throws -> KotodamaDecimal {
        let value = try NumericV1Internal.decodeFrame(.decimal, frame: frame)
        return KotodamaDecimal(canonicalMantissa: value.mantissa, scale: value.scale)
    }

    public static func decodeQuantityFrame(_ frame: Data) throws -> KotodamaQuantity {
        let value = try NumericV1Internal.decodeFrame(.quantity, frame: frame)
        return KotodamaQuantity(canonicalMantissa: value.mantissa, scale: value.scale)
    }

    public static func encodeIntEnvelope(_ value: KotodamaInt) throws -> Data {
        try NumericV1Internal.encodeEnvelope(.int, frame: encodeIntFrame(value))
    }

    public static func encodeDecimalEnvelope(_ value: KotodamaDecimal) throws -> Data {
        try NumericV1Internal.encodeEnvelope(.decimal, frame: encodeDecimalFrame(value))
    }

    public static func encodeQuantityEnvelope(_ value: KotodamaQuantity) throws -> Data {
        try NumericV1Internal.encodeEnvelope(.quantity, frame: encodeQuantityFrame(value))
    }

    public static func decodeIntEnvelope(_ envelope: Data) throws -> KotodamaInt {
        try decodeIntFrame(NumericV1Internal.decodeEnvelope(.int, envelope: envelope))
    }

    public static func decodeDecimalEnvelope(_ envelope: Data) throws -> KotodamaDecimal {
        try decodeDecimalFrame(NumericV1Internal.decodeEnvelope(.decimal, envelope: envelope))
    }

    public static func decodeQuantityEnvelope(_ envelope: Data) throws -> KotodamaQuantity {
        try decodeQuantityFrame(NumericV1Internal.decodeEnvelope(.quantity, envelope: envelope))
    }
}

// BEGIN GENERATED: kotodama-v1-numeric-policy
private enum NumericV1Kind {
    case int
    case decimal
    case quantity

    var schemaName: String {
        switch self {
        case .int: return "iroha.numeric.IntValueV1"
        case .decimal: return "iroha.numeric.DecimalValueV1"
        case .quantity: return "iroha.numeric.QuantityValueV1"
        }
    }

    var schemaHash: [UInt8] {
        switch self {
        case .int: return NumericV1Internal.hex("07c039457363b9e1d36bbd31d93dec4a")
        case .decimal: return NumericV1Internal.hex("ba2ffed52e4d8ee16f17efefe1828524")
        case .quantity: return NumericV1Internal.hex("e4769984c81ce0e8b678f2eb06274ee3")
        }
    }

    var pointerType: UInt16 {
        switch self {
        case .int: return 0x0011
        case .decimal: return 0x0012
        case .quantity: return 0x0010
        }
    }

    var isScaled: Bool {
        switch self {
        case .int: return false
        case .decimal: return true
        case .quantity: return true
        }
    }
}

private let numericV1MinKnownPointerType: UInt16 = 0x0001
private let numericV1MaxAssignedPointerType: UInt16 = 0x0013
private let numericV1UnassignedPointerType: UInt16 = 0x000C
// END GENERATED: kotodama-v1-numeric-policy

private enum NumericV1Internal {
    static let maximumMantissaBytes = 64
    static let maximumIntTextBytes = 155
    static let maximumSignificantDigits = 154
    static let frameHeaderBytes = 40
    static let envelopeHeaderBytes = 7
    static let hashBytes = 32

    static func parseScaled(
        _ value: String,
        quantity: Bool
    ) throws -> (mantissa: KotodamaInt, scale: UInt8) {
        guard let match = numericCaptures(value, pattern: #"^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?$"#),
              value != "-0" else {
            throw numericFailure(.invalidText, "value must use exact decimal syntax")
        }
        let sign = match[1] ?? ""
        let integer = match[2] ?? "0"
        let fraction = match[3] ?? ""
        let rawDigits = Array((integer + fraction).utf8)
        var first = 0
        while first < rawDigits.count && rawDigits[first] == 0x30 { first += 1 }
        if first == rawDigits.count {
            return try normalizeScaled("0", scale: 0, quantity: quantity)
        }
        var end = rawDigits.count
        var scale = fraction.utf8.count
        while scale > 0 && rawDigits[end - 1] == 0x30 {
            end -= 1
            scale -= 1
        }
        guard scale <= 28 else {
            throw numericFailure(.invalidScale, "canonical scale exceeds 28")
        }
        guard end - first <= maximumSignificantDigits else {
            throw numericFailure(.mantissaOverflow, "decimal mantissa exceeds the signed 512-bit input bound")
        }
        let magnitude = String(decoding: rawDigits[first..<end], as: UTF8.self)
        return try normalizeScaled(sign + magnitude, scale: scale, quantity: quantity)
    }

    static func normalizeScaled(
        _ rawMantissa: String,
        scale rawScale: Int,
        quantity: Bool
    ) throws -> (mantissa: KotodamaInt, scale: UInt8) {
        guard rawScale >= 0 else {
            throw numericFailure(.invalidScale, "scale cannot be negative")
        }
        let negative = rawMantissa.hasPrefix("-")
        var magnitude = negative ? String(rawMantissa.dropFirst()) : rawMantissa
        magnitude = stripLeadingDecimalZeros(magnitude)
        var scale = rawScale
        if magnitude == "0" {
            scale = 0
        } else {
            while scale > 0 && magnitude.last == "0" {
                magnitude.removeLast()
                scale -= 1
            }
        }
        guard scale <= 28 else {
            throw numericFailure(.invalidScale, "canonical scale exceeds 28")
        }
        let canonical = negative && magnitude != "0" ? "-" + magnitude : magnitude
        let mantissa = try KotodamaInt(canonical)
        if quantity && mantissa.canonicalString.hasPrefix("-") {
            throw numericFailure(.negativeQuantity, "quantity cannot be negative")
        }
        return (mantissa, UInt8(scale))
    }

    static func scaledText(_ rawMantissa: String, scale: Int) -> String {
        if scale == 0 { return rawMantissa }
        let negative = rawMantissa.hasPrefix("-")
        var digits = negative ? String(rawMantissa.dropFirst()) : rawMantissa
        if digits.count <= scale {
            digits = String(repeating: "0", count: scale + 1 - digits.count) + digits
        }
        let split = digits.index(digits.endIndex, offsetBy: -scale)
        return (negative ? "-" : "") + digits[..<split] + "." + digits[split...]
    }

    static func encodeFrame(
        _ kind: NumericV1Kind,
        mantissa: KotodamaInt,
        scale: UInt8
    ) throws -> Data {
        let twos = try encodeTwos(mantissa.canonicalString)
        var body = Data()
        appendUInt32LE(UInt32(twos.count), to: &body)
        body.append(contentsOf: twos)
        if kind.isScaled { body.append(scale) }
        return noritoEncode(typeName: kind.schemaName, payload: body, flags: 0)
    }

    static func decodeFrame(
        _ kind: NumericV1Kind,
        frame: Data
    ) throws -> (mantissa: KotodamaInt, scale: UInt8) {
        // `Data.SubSequence` is also `Data` and retains its source indices.
        // Rebase every externally supplied collection before absolute header access.
        let frame = Data(frame)
        let maximum = frameHeaderBytes + 4 + maximumMantissaBytes + (kind.isScaled ? 1 : 0)
        guard frame.count >= frameHeaderBytes else {
            throw numericFailure(.frameTooShort, "frame is truncated")
        }
        guard frame.count <= maximum else {
            throw numericFailure(.frameTooLarge, "frame is oversized")
        }
        guard Array(frame.prefix(6)) == [0x4e, 0x52, 0x54, 0x30, 0, 0] else {
            throw numericFailure(.invalidHeader, "frame has the wrong magic or version")
        }
        guard Array(frame[6..<22]) == kind.schemaHash else {
            throw numericFailure(.schemaMismatch, "frame schema does not match")
        }
        guard frame[22] == 0 else {
            throw numericFailure(.compressionNotAllowed, "compression is forbidden")
        }
        guard frame[39] == 0 else {
            throw numericFailure(.layoutFlagsNotAllowed, "layout flags must be zero")
        }
        guard let declaredLength = readUInt64LE(frame, at: 23),
              declaredLength == UInt64(frame.count - frameHeaderBytes) else {
            throw numericFailure(.lengthMismatch, "frame length is inconsistent")
        }
        let body = Data(frame.dropFirst(frameHeaderBytes))
        guard let checksum = readUInt64LE(frame, at: 31), checksum == crc64ECMA(body) else {
            throw numericFailure(.checksumMismatch, "frame checksum failed")
        }
        guard let mantissaLength = readUInt32LE(body, at: 0) else {
            throw numericFailure(.lengthMismatch, "body has no mantissa length")
        }
        guard mantissaLength <= maximumMantissaBytes else {
            throw numericFailure(.mantissaOverflow, "mantissa length exceeds 64 bytes")
        }
        let expected = 4 + mantissaLength + (kind.isScaled ? 1 : 0)
        guard expected == body.count else {
            throw numericFailure(.lengthMismatch, "numeric body length is inconsistent")
        }
        let twos = Array(body[4..<(4 + mantissaLength)])
        let canonical = try decodeTwos(twos)
        let mantissa = KotodamaInt(validated: canonical)
        guard kind.isScaled else { return (mantissa, 0) }
        let scale = body[body.count - 1]
        guard scale <= 28 else { throw numericFailure(.invalidScale, "scale exceeds 28") }
        let magnitude = canonical.hasPrefix("-") ? canonical.dropFirst() : canonical[...]
        if (canonical == "0" && scale != 0) || (scale > 0 && magnitude.last == "0") {
            throw numericFailure(.noncanonicalDecimal, "scaled value is not canonical")
        }
        if kind == .quantity && canonical.hasPrefix("-") {
            throw numericFailure(.negativeQuantity, "quantity cannot be negative")
        }
        return (mantissa, scale)
    }

    static func encodeEnvelope(_ kind: NumericV1Kind, frame: Data) throws -> Data {
        guard frame.count <= Int(UInt32.max) else {
            throw numericFailure(.oversizedLength, "frame length does not fit u32")
        }
        var envelope = Data()
        appendUInt16BE(kind.pointerType, to: &envelope)
        envelope.append(1)
        appendUInt32BE(UInt32(frame.count), to: &envelope)
        envelope.append(frame)
        envelope.append(payloadHash(frame))
        return envelope
    }

    static func decodeEnvelope(_ kind: NumericV1Kind, envelope: Data) throws -> Data {
        // See `decodeFrame`: callers may pass a non-zero-index Data slice.
        let envelope = Data(envelope)
        guard envelope.count >= envelopeHeaderBytes else {
            throw numericFailure(.truncatedEnvelope, "envelope is truncated")
        }
        guard let pointerType = readUInt16BE(envelope, at: 0) else {
            throw numericFailure(.truncatedEnvelope, "envelope is truncated")
        }
        let knownAllowedType = (numericV1MinKnownPointerType...numericV1MaxAssignedPointerType)
            .contains(pointerType) && pointerType != numericV1UnassignedPointerType
        guard knownAllowedType else {
            throw numericFailure(.unknownType, "unknown pointer type")
        }
        guard pointerType == kind.pointerType else {
            throw numericFailure(.wrongType, "pointer type does not match")
        }
        guard envelope[2] == 1 else {
            throw numericFailure(.invalidEnvelopeVersion, "envelope version must be 1")
        }
        guard let frameLength = readUInt32BE(envelope, at: 3) else {
            throw numericFailure(.truncatedEnvelope, "envelope is truncated")
        }
        let maximum = frameHeaderBytes + 4 + maximumMantissaBytes + (kind.isScaled ? 1 : 0)
        guard frameLength <= maximum else {
            throw numericFailure(.oversizedLength, "declared frame is oversized")
        }
        guard envelopeHeaderBytes + frameLength + hashBytes == envelope.count else {
            throw numericFailure(.truncatedEnvelope, "envelope length is inconsistent")
        }
        let frame = Data(envelope[envelopeHeaderBytes..<(envelopeHeaderBytes + frameLength)])
        let suppliedHash = Data(envelope[(envelopeHeaderBytes + frameLength)...])
        guard constantTimeEqual(payloadHash(frame), suppliedHash) else {
            throw numericFailure(.payloadHashMismatch, "payload hash failed")
        }
        return frame
    }

    static func encodeTwos(_ canonical: String) throws -> [UInt8] {
        let negative = canonical.hasPrefix("-")
        let magnitudeText = negative ? String(canonical.dropFirst()) : canonical
        if magnitudeText == "0" { return [] }
        let magnitude = decimalMagnitudeToLittleEndian(magnitudeText)
        if !negative {
            var result = magnitude
            if result.last.map({ ($0 & 0x80) != 0 }) == true { result.append(0) }
            guard result.count <= maximumMantissaBytes else {
                throw numericFailure(.mantissaOverflow, "mantissa is outside signed 512-bit range")
            }
            return result
        }

        var width = max(1, magnitude.count)
        if magnitude.count == width, let top = magnitude.last {
            let lowerNonZero = magnitude.dropLast().contains(where: { $0 != 0 })
            if top > 0x80 || (top == 0x80 && lowerNonZero) { width += 1 }
        }
        guard width <= maximumMantissaBytes else {
            throw numericFailure(.mantissaOverflow, "mantissa is outside signed 512-bit range")
        }
        var result = magnitude + Array(repeating: 0, count: width - magnitude.count)
        for index in result.indices { result[index] = ~result[index] }
        var carry: UInt16 = 1
        for index in result.indices {
            let sum = UInt16(result[index]) + carry
            result[index] = UInt8(sum & 0xff)
            carry = sum >> 8
        }
        return result
    }

    static func decodeTwos(_ bytes: [UInt8]) throws -> String {
        guard bytes.count <= maximumMantissaBytes else {
            throw numericFailure(.mantissaOverflow, "mantissa is too wide")
        }
        guard let last = bytes.last else { return "0" }
        if bytes.count == 1 && last == 0 {
            throw numericFailure(.noncanonicalMantissa, "zero must use an empty mantissa")
        }
        if bytes.count > 1 {
            let previous = bytes[bytes.count - 2]
            if (last == 0 && (previous & 0x80) == 0)
                || (last == 0xff && (previous & 0x80) != 0) {
                throw numericFailure(.noncanonicalMantissa, "mantissa has redundant sign extension")
            }
        }
        if (last & 0x80) == 0 { return littleEndianMagnitudeToDecimal(bytes) }
        var magnitude = bytes.map { ~$0 }
        var carry: UInt16 = 1
        for index in magnitude.indices {
            let sum = UInt16(magnitude[index]) + carry
            magnitude[index] = UInt8(sum & 0xff)
            carry = sum >> 8
        }
        while magnitude.last == 0 { magnitude.removeLast() }
        return "-" + littleEndianMagnitudeToDecimal(magnitude)
    }

    static func decimalMagnitudeToLittleEndian(_ value: String) -> [UInt8] {
        var digits = value.compactMap { $0.wholeNumberValue }.map(UInt16.init)
        var result: [UInt8] = []
        while !digits.isEmpty && digits.contains(where: { $0 != 0 }) {
            var quotient: [UInt16] = []
            var remainder: UInt16 = 0
            for digit in digits {
                let current = remainder * 10 + digit
                let q = current / 256
                remainder = current % 256
                if !quotient.isEmpty || q != 0 { quotient.append(q) }
            }
            result.append(UInt8(remainder))
            digits = quotient
        }
        return result
    }

    static func littleEndianMagnitudeToDecimal(_ bytes: [UInt8]) -> String {
        var digits: [UInt8] = [0]
        for byte in bytes.reversed() {
            var carry = Int(byte)
            for index in digits.indices.reversed() {
                let current = Int(digits[index]) * 256 + carry
                digits[index] = UInt8(current % 10)
                carry = current / 10
            }
            while carry > 0 {
                digits.insert(UInt8(carry % 10), at: 0)
                carry /= 10
            }
        }
        return digits.map(String.init).joined()
    }

    static func hex(_ value: String) -> [UInt8] {
        stride(from: 0, to: value.count, by: 2).map { offset in
            let start = value.index(value.startIndex, offsetBy: offset)
            let end = value.index(start, offsetBy: 2)
            return UInt8(value[start..<end], radix: 16)!
        }
    }

    static func appendUInt16BE(_ value: UInt16, to data: inout Data) {
        data.append(UInt8(value >> 8))
        data.append(UInt8(value & 0xff))
    }

    static func appendUInt32LE(_ value: UInt32, to data: inout Data) {
        for shift in stride(from: 0, through: 24, by: 8) { data.append(UInt8((value >> shift) & 0xff)) }
    }

    static func appendUInt32BE(_ value: UInt32, to data: inout Data) {
        for shift in stride(from: 24, through: 0, by: -8) { data.append(UInt8((value >> shift) & 0xff)) }
    }

    static func readUInt16BE(_ data: Data, at offset: Int) -> UInt16? {
        guard offset >= 0, offset + 2 <= data.count else { return nil }
        return UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
    }

    static func readUInt32LE(_ data: Data, at offset: Int) -> Int? {
        guard offset >= 0, offset + 4 <= data.count else { return nil }
        var result: UInt32 = 0
        for index in 0..<4 { result |= UInt32(data[offset + index]) << UInt32(index * 8) }
        return Int(result)
    }

    static func readUInt32BE(_ data: Data, at offset: Int) -> Int? {
        guard offset >= 0, offset + 4 <= data.count else { return nil }
        var result: UInt32 = 0
        for index in 0..<4 { result = result << 8 | UInt32(data[offset + index]) }
        return Int(result)
    }

    static func readUInt64LE(_ data: Data, at offset: Int) -> UInt64? {
        guard offset >= 0, offset + 8 <= data.count else { return nil }
        var result: UInt64 = 0
        for index in 0..<8 { result |= UInt64(data[offset + index]) << UInt64(index * 8) }
        return result
    }

    static func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for (leftByte, rightByte) in zip(left, right) {
            difference |= leftByte ^ rightByte
        }
        return difference == 0
    }

    static func payloadHash(_ frame: Data) -> Data {
        var digest = Blake2b.hash256(frame)
        digest[digest.count - 1] |= 1
        return digest
    }
}

private func numericFullMatch(_ value: String, pattern: String) -> Bool {
    value.range(of: "^(?:\(pattern))$", options: .regularExpression) != nil
}

private func numericCaptures(_ value: String, pattern: String) -> [String?]? {
    guard let expression = try? NSRegularExpression(pattern: pattern),
          let match = expression.firstMatch(
              in: value,
              range: NSRange(value.startIndex..<value.endIndex, in: value)
          ),
          match.range == NSRange(value.startIndex..<value.endIndex, in: value) else {
        return nil
    }
    return (0..<match.numberOfRanges).map { index in
        let range = match.range(at: index)
        guard range.location != NSNotFound, let swiftRange = Range(range, in: value) else { return nil }
        return String(value[swiftRange])
    }
}

private func stripLeadingDecimalZeros(_ value: String) -> String {
    let stripped = value.drop(while: { $0 == "0" })
    return stripped.isEmpty ? "0" : String(stripped)
}


extension CanonicalNorito {
    /// Decode one exact bare compact-Norito Quantity, including canonical
    /// mantissa width, non-negative value, scale and byte-for-byte round trip.
    public static func decodeCompactQuantity(_ payload: Data) throws -> KotodamaQuantity {
        var reader = CanonicalNoritoReader(data: payload)
        var mantissa = CanonicalNoritoReader(data: try reader.readCompactField())
        var scale = CanonicalNoritoReader(data: try reader.readCompactField())
        let count = try mantissa.readUInt32LE()
        guard count <= 64, Int(count) == mantissa.remaining() else {
            throw numericFailure(.mantissaOverflow, "quantity mantissa length is invalid")
        }
        let bytes = try mantissa.readBytes(Int(count))
        // Bare Numeric uses the BigInt codec's one-byte zero; the separate
        // Kotodama V1 numeric frame represents zero with an empty mantissa.
        let digits = bytes == Data([0]) ? "0" : try NumericV1Internal.decodeTwos(Array(bytes))
        let scaleValue = try scale.readUInt32LE()
        guard reader.remaining() == 0, scale.remaining() == 0, scaleValue <= 28 else {
            throw numericFailure(.invalidScale, "quantity scale or payload length is invalid")
        }
        let value = try KotodamaQuantity(mantissa: KotodamaInt(digits), scale: UInt8(scaleValue))
        guard try encodeCompactQuantity(value.canonicalString) == payload else {
            throw numericFailure(.noncanonicalDecimal, "quantity is not canonical")
        }
        return value
    }
}
