import Foundation
import XCTest
@testable import IrohaSwift

/// Transport DATA only: no fixture is an admitted Native recipient or financial permission.
final class IrohaPeerWalletRequestV1Tests: XCTestCase {
    private func request() throws -> Data {
        try XCTUnwrap(irohaPeerWalletVectorEnvelopesV1().first { $0.kind == .request }).frame
    }

    func testExactOriginalsAndBigEndianFraming() throws {
        let envelope = try request(), account = try irohaPeerWalletRequestAccountOriginalV1()
        let value = try IrohaPeerWalletRequestV1(requestEnvelope: envelope, destinationAccountOriginal: account)
        let bytes = value.encode()
        XCTAssertEqual(Data(bytes.prefix(8)), Data("KWRQAC1\0".utf8))
        func length(_ offset: Int) -> Int { bytes[offset..<offset + 4].reduce(0) { ($0 << 8) | Int($1) } }
        XCTAssertEqual(length(8), envelope.count); XCTAssertEqual(length(12), account.count)
        let decoded = try IrohaPeerWalletRequestV1.decode(bytes)
        XCTAssertEqual(decoded.requestEnvelope, envelope)
        XCTAssertEqual(decoded.destinationAccountOriginal, account)
        XCTAssertEqual(decoded.encode(), bytes)
    }

    func testMissingCompanionAndMalformedLengthsAreRejected() throws {
        let envelope = try request()
        let original = try IrohaPeerWalletRequestV1(requestEnvelope: envelope,
            destinationAccountOriginal: irohaPeerWalletRequestAccountOriginalV1()).encode()
        var bad = [envelope, Data(original.prefix(15)), Data(original.dropLast()), original + Data([0])]
        for (offset, value) in [(8, UInt32(10_001)), (12, UInt32(4_097)), (12, UInt32(0)), (8, UInt32.max)] {
            var bytes = original
            for index in 0..<4 { bytes[offset + index] = UInt8(truncatingIfNeeded: value >> (24 - index * 8)) }
            bad.append(bytes)
        }
        for bytes in bad { XCTAssertThrowsError(try IrohaPeerWalletRequestV1.decode(bytes)) }
        XCTAssertThrowsError(try IrohaPeerKagemushaWalletAdapterV1.wrap(envelope))
        for count in [0, 4_097] {
            XCTAssertThrowsError(try IrohaPeerWalletRequestV1(requestEnvelope: envelope,
                destinationAccountOriginal: Data(repeating: 0, count: count)))
        }
    }

    func testBothOriginalsAreBoundByIpM1Hashes() throws {
        let envelope = try request(), account = try irohaPeerWalletRequestAccountOriginalV1()
        let message = try IrohaPeerKagemushaWalletAdapterV1.wrap(envelope, destinationAccountOriginal: account)
        var changedAccount = account; changedAccount[changedAccount.count - 1] ^= 1
        let changed = try IrohaPeerKagemushaWalletAdapterV1.wrap(envelope, destinationAccountOriginal: changedAccount)
        XCTAssertNotEqual(message.canonicalHash, changed.canonicalHash)
        XCTAssertNotEqual(message.wireHash, changed.wireHash)
        var tampered = message.encoded; tampered[tampered.count - 1] ^= 1
        XCTAssertThrowsError(try IrohaPeerWireMessageV1.decode(tampered))
        let decoded = try IrohaPeerWireMessageV1.decode(message.encoded)
        XCTAssertEqual(try IrohaPeerKagemushaWalletAdapterV1.decode(decoded), envelope)
        XCTAssertEqual(try IrohaPeerKagemushaWalletAdapterV1.destinationAccountOriginal(decoded), account)
    }

    func testOnlyRequestGetsExpandedTransportBound() throws {
        XCTAssertEqual(IrohaPeerWireKindV1.request.maximumWalletFrameBytes, 14_112)
        XCTAssertEqual(IrohaPeerWireKindV1.payment.maximumWalletFrameBytes, 10_000)
        let envelope = irohaPeerWalletStructuralEnvelopeV1(kind: .request, frameBytes: 10_000)
        let message = try IrohaPeerKagemushaWalletAdapterV1.wrap(envelope,
            destinationAccountOriginal: Data(repeating: 1, count: 4_096))
        XCTAssertEqual(message.canonicalPayload.count, 14_112)
        XCTAssertEqual(try IrohaPeerWireMessageV1.decode(message.encoded), message)
        XCTAssertThrowsError(try IrohaPeerWireMessageV1(profile: .kagemushaWalletV1,
            kind: .payment, schemaVersion: 1, canonicalPayload: message.canonicalPayload))
    }
}
