import Foundation
import XCTest
@testable import IrohaSwift

/// Carrier DATA only. These structural originals confer no Native payment verdict.
final class IrohaPeerWalletPaymentV1Tests: XCTestCase {
    private func payment(_ count: Int = 512) -> Data {
        irohaPeerWalletStructuralEnvelopeV1(kind: .payment, frameBytes: count)
    }

    func testExactOriginalsBigEndianLengthsAndValueOwnership() throws {
        var envelope = payment(), companion = irohaPeerWalletPayerCompanionV1()
        let expectedEnvelope = envelope, expectedCompanion = companion
        let value = try IrohaPeerWalletPaymentV1(paymentEnvelope: envelope, payerCompanion: companion)
        envelope[envelope.count - 1] ^= 1; companion[0] ^= 1
        let bytes = value.encode()
        XCTAssertEqual(Data(bytes.prefix(8)), Data("KWPYPC1\0".utf8))
        func length(_ offset: Int) -> Int { bytes[offset..<offset + 4].reduce(0) { ($0 << 8) | Int($1) } }
        XCTAssertEqual(length(8), expectedEnvelope.count)
        XCTAssertEqual(length(12), expectedCompanion.count)
        let decoded = try IrohaPeerWalletPaymentV1.decode(bytes)
        XCTAssertEqual(decoded.paymentEnvelope, expectedEnvelope)
        XCTAssertEqual(decoded.payerCompanion, expectedCompanion)
        XCTAssertEqual(decoded.encode(), bytes)
    }

    func testCarrierAndEnvelopeBoundsAreIndependent() throws {
        XCTAssertEqual(IrohaPeerWalletPaymentV1.headerBytes, 16)
        XCTAssertEqual(IrohaPeerWalletPaymentV1.maximumCompanionBytes, 2_048)
        XCTAssertEqual(IrohaPeerWalletPaymentV1.maximumBytes, 12_064)
        XCTAssertEqual(IrohaPeerWireKindV1.payment.maximumWalletFrameBytes, 12_064)
        for count in [1, 2_048] {
            let value = try IrohaPeerWalletPaymentV1(paymentEnvelope: payment(10_000),
                payerCompanion: Data(repeating: 0x71, count: count))
            XCTAssertEqual(try IrohaPeerWalletPaymentV1.decode(value.encode()), value)
        }
        let maximum = try IrohaPeerKagemushaWalletAdapterV1.wrap(payment(10_000),
            payerCompanion: Data(repeating: 0x71, count: 2_048), compressionPolicy: .disabled)
        XCTAssertEqual(maximum.canonicalPayload.count, 12_064)
        XCTAssertEqual(maximum.encoded.count, 12_148)
        XCTAssertEqual(try IrohaPeerWireMessageV1.decode(maximum.encoded), maximum)
        for count in [0, 2_049] {
            XCTAssertThrowsError(try IrohaPeerWalletPaymentV1(paymentEnvelope: payment(),
                payerCompanion: Data(repeating: 1, count: count)))
        }
        for envelope in [Data(), payment(10_001),
                         irohaPeerWalletStructuralEnvelopeV1(kind: .request, payload: Data([1]))] {
            XCTAssertThrowsError(try IrohaPeerWalletPaymentV1(paymentEnvelope: envelope,
                payerCompanion: Data([1])))
        }
    }

    func testMalformedMagicLengthsAndRawEnvelopesAreRejected() throws {
        let envelope = payment()
        let original = try IrohaPeerWalletPaymentV1(paymentEnvelope: envelope,
            payerCompanion: irohaPeerWalletPayerCompanionV1()).encode()
        var bad = [envelope, Data(), Data(original.prefix(15)), Data(original.dropLast()), original + Data([0])]
        var wrongMagic = original; wrongMagic[0] ^= 1; bad.append(wrongMagic)
        for (offset, value) in [(8, UInt32(0)), (8, UInt32(10_001)), (8, UInt32.max),
                                (12, UInt32(0)), (12, UInt32(2_049)), (12, UInt32.max)] {
            var bytes = original
            for index in 0..<4 { bytes[offset + index] = UInt8(truncatingIfNeeded: value >> (24 - index * 8)) }
            bad.append(bytes)
        }
        let request = irohaPeerWalletStructuralEnvelopeV1(kind: .request, payload: Data([1]))
        bad.append(try IrohaPeerWalletRequestV1(requestEnvelope: request,
            destinationAccountOriginal: irohaPeerWalletRequestAccountOriginalV1()).encode())
        for bytes in bad { XCTAssertThrowsError(try IrohaPeerWalletPaymentV1.decode(bytes)) }
    }

    func testIpM1HashesBindPaymentAndCompanionAndAdaptersRequireCorrectKind() throws {
        let envelope = payment(), companion = irohaPeerWalletPayerCompanionV1()
        let message = try IrohaPeerKagemushaWalletAdapterV1.wrap(envelope, payerCompanion: companion)
        var changedCompanion = companion; changedCompanion[0] ^= 1
        let changed = try IrohaPeerKagemushaWalletAdapterV1.wrap(envelope, payerCompanion: changedCompanion)
        XCTAssertNotEqual(message.canonicalHash, changed.canonicalHash)
        XCTAssertNotEqual(message.wireHash, changed.wireHash)
        let changedEnvelope = irohaPeerWalletStructuralEnvelopeV1(kind: .payment, payload: Data([0x72]))
        let changedPayment = try IrohaPeerKagemushaWalletAdapterV1.wrap(changedEnvelope, payerCompanion: companion)
        XCTAssertNotEqual(message.canonicalHash, changedPayment.canonicalHash)
        XCTAssertNotEqual(message.wireHash, changedPayment.wireHash)
        var tampered = message.encoded; tampered[tampered.count - 1] ^= 1
        XCTAssertThrowsError(try IrohaPeerWireMessageV1.decode(tampered))
        let decoded = try IrohaPeerWireMessageV1.decode(message.encoded)
        XCTAssertEqual(try IrohaPeerKagemushaWalletAdapterV1.decode(decoded), envelope)
        XCTAssertEqual(try IrohaPeerKagemushaWalletAdapterV1.payerCompanion(decoded), companion)
        XCTAssertThrowsError(try IrohaPeerKagemushaWalletAdapterV1.wrap(envelope))
        XCTAssertThrowsError(try IrohaPeerKagemushaWalletAdapterV1.wrap(envelope,
            destinationAccountOriginal: Data([1]), payerCompanion: companion))
        XCTAssertThrowsError(try IrohaPeerWireMessageV1(profile: .kagemushaWalletV1,
            kind: .payment, schemaVersion: 1, canonicalPayload: envelope))
        let creditedEnvelope = irohaPeerWalletStructuralEnvelopeV1(kind: .credited, payload: Data([1]))
        XCTAssertThrowsError(try IrohaPeerKagemushaWalletAdapterV1.wrap(creditedEnvelope, payerCompanion: companion))
        let credited = try IrohaPeerKagemushaWalletAdapterV1.wrap(creditedEnvelope)
        XCTAssertThrowsError(try IrohaPeerKagemushaWalletAdapterV1.payerCompanion(credited))
        XCTAssertNil(IrohaPeerWireKindV1(rawValue: 1))
        XCTAssertNil(IrohaPeerWireKindV1(rawValue: 7))
    }

    func testAnimatedQrPreservesBothOriginals() throws {
        let envelope = payment(10_000), companion = irohaPeerWalletPayerCompanionV1(count: 2_048)
        let message = try IrohaPeerKagemushaWalletAdapterV1.wrap(envelope, payerCompanion: companion)
        let session = IrohaPeerQRScanSessionV1(expectedProfile: .kagemushaWalletV1,
            expectedKind: .payment, expectedSchemaVersion: 1)
        var completed: IrohaPeerWireMessageV1?
        for text in try IrohaPeerQRCodecV1.animatedFrameTexts(for: message) {
            if case let .completed(decoded) = try session.ingest(text) { completed = decoded; break }
        }
        let decoded = try XCTUnwrap(completed)
        XCTAssertEqual(try IrohaPeerKagemushaWalletAdapterV1.decode(decoded), envelope)
        XCTAssertEqual(try IrohaPeerKagemushaWalletAdapterV1.payerCompanion(decoded), companion)
    }
}
