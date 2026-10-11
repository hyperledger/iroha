import Foundation
@testable import IrohaSwift

/// Scheme named by every structural wallet envelope built here.
let irohaPeerWalletStructuralSchemeV1 = Data(repeating: 0x5c, count: 32)

/// Canonical KAGEMUSHA wallet V1 envelope frame of `kind` that carries `payload` as an opaque
/// field.
///
/// The frame has the header, versions, message tag and scheme field that
/// `KagemushaWalletWireV1.inspectEnvelope` checks, but it is not a valid typed message. It
/// proves only the IPM framing layer; typed wallet validation is tested by
/// `KagemushaWalletVectorsV1Tests`.
func irohaPeerWalletStructuralEnvelopeV1(
    kind: IrohaPeerWireKindV1,
    payload: Data
) -> Data {
    let version = irohaPeerWalletField([1, 0])
    let leaf = version + irohaPeerWalletField([UInt8](irohaPeerWalletStructuralSchemeV1))
        + irohaPeerWalletField([UInt8](payload))
    // The variant mirrors the version and scheme field paths of the real message layouts.
    let variant: [UInt8]
    switch kind {
    case .offer, .request:
        variant = irohaPeerWalletField(irohaPeerWalletField(leaf))
    case .payment, .lineage:
        variant = irohaPeerWalletField(version + irohaPeerWalletField(irohaPeerWalletField(leaf)))
    case .credited, .sessionControl, .policyData:
        variant = irohaPeerWalletField(leaf)
    }
    let tag = withUnsafeBytes(of: UInt32(kind.rawValue).littleEndian, Array.init)
    let envelope = version + irohaPeerWalletField(tag + variant)
    return noritoEncode(
        typeName: KagemushaWalletWireV1.envelopeFrameName,
        payload: Data(envelope),
        flags: NoritoHeader.compactLen,
        payloadAlignment: KagemushaWalletWireV1.envelopePayloadAlignment
    )
}

/// Structural wallet envelope of `kind` whose complete frame is exactly `frameBytes` long; its
/// opaque field is `filler(count)` for the count that reaches that size.
func irohaPeerWalletStructuralEnvelopeV1(
    kind: IrohaPeerWireKindV1,
    frameBytes: Int,
    filler: (Int) -> Data = { Data(repeating: 0xA5, count: $0) }
) -> Data {
    var count = 0
    for _ in 0..<16 {
        let frame = irohaPeerWalletStructuralEnvelopeV1(kind: kind, payload: filler(count))
        if frame.count == frameBytes { return frame }
        count += frameBytes - frame.count
        precondition(count >= 0, "\(kind) envelope cannot be \(frameBytes) bytes")
    }
    preconditionFailure("\(kind) envelope cannot be exactly \(frameBytes) bytes")
}

/// `[compact length][content]` with a canonical unsigned LEB128 length.
private func irohaPeerWalletField(_ content: [UInt8]) -> [UInt8] {
    var length = UInt64(content.count)
    var prefix: [UInt8] = []
    repeat {
        var byte = UInt8(length & 0x7f)
        length >>= 7
        if length != 0 { byte |= 0x80 }
        prefix.append(byte)
    } while length != 0
    return prefix + content
}

/// Published canonical AccountId DATA from fixtures/account/multisig_wire_v1.json positive[0].
/// It carries no account possession, signature or Native admission authority.
func irohaPeerWalletRequestAccountOriginalV1() throws -> Data {
    let hex = "4e525430000060e81473aed0a1276f1c5776d0f69c38004f000000000000002f6837f47715857502000000004a21000000000000000100015f017c01bf019a0165019c01f101230100019e015b010c012c01c00128015d01fa015e01d7016b01ed01ae010701cd0128011a01f70127010601be01950136"
    var bytes = Data()
    var cursor = hex.startIndex
    while cursor < hex.endIndex {
        let next = hex.index(cursor, offsetBy: 2)
        bytes.append(UInt8(hex[cursor..<next], radix: 16)!)
        cursor = next
    }
    return bytes
}

/// Current carrier payload, preserving the small structural envelope for generic wire sizing.
func irohaPeerWalletStructuralPayloadV1(kind: IrohaPeerWireKindV1, payload: Data) throws -> Data {
    let envelope = irohaPeerWalletStructuralEnvelopeV1(kind: kind, payload: payload)
    return kind == .request
        ? try IrohaPeerWalletRequestV1(requestEnvelope: envelope,
            destinationAccountOriginal: irohaPeerWalletRequestAccountOriginalV1()).encode() : envelope
}

/// Exact record-count exchange DATA. Nested credentials/proofs remain opaque and unadmitted.
/// Filler is outside the signed Request so transport tests can vary each message's size.
func irohaPeerWalletExchangeEnvelopeV1(
    kind: IrohaPeerWireKindV1, payload: Data,
    schemeID: Data = irohaPeerWalletStructuralSchemeV1,
    requestBodyByte: UInt8 = 0x29, requestSignatureByte: UInt8 = 0x36
) -> Data {
    func record(_ fields: [Data]) -> [UInt8] {
        fields.flatMap { irohaPeerWalletField([UInt8]($0)) }
    }
    let version = Data([1, 0])
    let body = Data(record([version, schemeID, Data([requestBodyByte])] + Array(repeating: Data(), count: 16)))
    let signature = Data(repeating: requestSignatureByte, count: 64)
    let fields: [Data]
    switch kind {
    case .request:
        fields = [body, payload, Data(), Data(), signature]
    case .payment:
        fields = [version, Data(record([body, signature])), Data(repeating: 0x42, count: 65),
                  Data(repeating: 0x24, count: 32), payload]
    case .credited:
        fields = [version, schemeID, payload]
    default:
        return irohaPeerWalletStructuralEnvelopeV1(kind: kind, payload: payload)
    }
    let tag = withUnsafeBytes(of: UInt32(kind.rawValue).littleEndian, Array.init)
    return noritoEncode(typeName: KagemushaWalletWireV1.envelopeFrameName,
        payload: Data(irohaPeerWalletField([1, 0]) + irohaPeerWalletField(tag + irohaPeerWalletField(record(fields)))),
        flags: NoritoHeader.compactLen, payloadAlignment: KagemushaWalletWireV1.envelopePayloadAlignment)
}

/// Exact-size exchange DATA for testing the envelope bound without changing its quoted Request.
func irohaPeerWalletExchangeEnvelopeV1(
    kind: IrohaPeerWireKindV1, frameBytes: Int
) -> Data {
    var count = 0
    for _ in 0..<16 {
        let frame = irohaPeerWalletExchangeEnvelopeV1(
            kind: kind, payload: Data(repeating: 0xa5, count: count))
        if frame.count == frameBytes { return frame }
        count += frameBytes - frame.count
        precondition(count >= 0, "exchange envelope cannot fit requested size")
    }
    preconditionFailure("exchange envelope cannot reach requested size")
}

func irohaPeerWalletExchangeMessageV1(
    kind: IrohaPeerWireKindV1, payload: Data,
    schemeID: Data = irohaPeerWalletStructuralSchemeV1,
    requestBodyByte: UInt8 = 0x29, requestSignatureByte: UInt8 = 0x36
) throws -> IrohaPeerWireMessageV1 {
    let envelope = irohaPeerWalletExchangeEnvelopeV1(kind: kind, payload: payload,
        schemeID: schemeID, requestBodyByte: requestBodyByte, requestSignatureByte: requestSignatureByte)
    return try IrohaPeerKagemushaWalletAdapterV1.wrap(envelope,
        destinationAccountOriginal: kind == .request ? irohaPeerWalletRequestAccountOriginalV1() : nil)
}
