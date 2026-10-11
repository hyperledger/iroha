import XCTest
@testable import IrohaSwift

/// Structural correspondence only: these opaque DATA records carry no Native authority.
final class KagemushaWalletExchangeBindingV1Tests: XCTestCase {
    func testExactRequestPaymentAndCreditedRecordsCorrespond() throws {
        try KagemushaWalletWireV1.requireExchangeBinding(
            request: envelope(.request, requestFields()),
            payment: envelope(.payment, paymentFields()),
            credited: envelope(.credited, creditedFields()))
    }

    func testDifferentQuotedBodyOrSignatureIsRejected() throws {
        let request = envelope(.request, requestFields())
        for index in [0, 1] {
            var signedRequest = [record(bodyFields()), signature]
            signedRequest[index][signedRequest[index].count - 1] ^= 1
            var payment = paymentFields()
            payment[1] = record(signedRequest)
            XCTAssertThrowsError(try KagemushaWalletWireV1.requireExchangeBinding(
                request: request, payment: envelope(.payment, payment))) {
                XCTAssertEqual($0 as? KagemushaWalletWireErrorV1,
                    .invalidField("payment.request.binding"))
            }
        }
    }

    func testCreditedMustNameRetainedRequestScheme() throws {
        var credited = creditedFields()
        credited[1][0] ^= 1
        XCTAssertThrowsError(try KagemushaWalletWireV1.requireExchangeBinding(
            request: envelope(.request, requestFields()),
            payment: envelope(.payment, paymentFields()),
            credited: envelope(.credited, credited))) {
            XCTAssertEqual($0 as? KagemushaWalletWireErrorV1,
                .schemeMismatch(field: "credited.scheme_id"))
        }
    }

    func testEveryTopLevelRecordRequiresExactFieldCount() throws {
        for kind: IrohaPeerWireKindV1 in [.request, .payment, .credited] {
            let fields = kind == .request ? requestFields()
                : kind == .payment ? paymentFields() : creditedFields()
            for malformed in [Array(fields.dropLast()), fields + [Data()]] {
                let request = envelope(.request, kind == .request ? malformed : requestFields())
                let payment = envelope(.payment, kind == .payment ? malformed : paymentFields())
                let credited = envelope(.credited, kind == .credited ? malformed : creditedFields())
                XCTAssertThrowsError(try KagemushaWalletWireV1.requireExchangeBinding(
                    request: request, payment: payment, credited: credited), "\(kind)")
            }
        }
    }

    func testRequestBodyAndPaymentSignedRequestRequireExactFieldCount() throws {
        for malformed in [Array(bodyFields().dropLast()), bodyFields() + [Data()]] {
            var request = requestFields()
            request[0] = record(malformed)
            var payment = paymentFields()
            payment[1] = record([request[0], signature])
            XCTAssertThrowsError(try KagemushaWalletWireV1.requireExchangeBinding(
                request: envelope(.request, request), payment: envelope(.payment, payment)))
        }
        let signedRequest = [record(bodyFields()), signature]
        for malformed in [Array(signedRequest.dropLast()), signedRequest + [Data()]] {
            var payment = paymentFields()
            payment[1] = record(malformed)
            XCTAssertThrowsError(try KagemushaWalletWireV1.requireExchangeBinding(
                request: envelope(.request, requestFields()), payment: envelope(.payment, payment)))
        }
    }

    func testWrongKindsAndOldThreeFieldStructuralRecordsAreRejected() throws {
        let request = envelope(.request, requestFields())
        let payment = envelope(.payment, paymentFields())
        XCTAssertThrowsError(try KagemushaWalletWireV1.requireExchangeBinding(
            request: payment, payment: request))
        XCTAssertThrowsError(try KagemushaWalletWireV1.requireExchangeBinding(
            request: request, payment: payment, credited: request))
        XCTAssertThrowsError(try KagemushaWalletWireV1.requireExchangeBinding(
            request: irohaPeerWalletStructuralEnvelopeV1(kind: .request, payload: Data()),
            payment: payment))
    }

    func testMalformedCompactLengthAndUnconsumedRecordBytesAreRejected() throws {
        // Fifth field is after the scheme/version paths inspected by the generic envelope parser.
        let validPrefix = record(Array(requestFields().prefix(4)))
        for suffix in [Data([0x80]), Data([0x80, 0x00]), Data([0x7f, 0x01])] {
            XCTAssertThrowsError(try KagemushaWalletWireV1.requireExchangeBinding(
                request: envelope(.request, rawRecord: validPrefix + suffix),
                payment: envelope(.payment, paymentFields())))
        }
    }

    func testFrameBoundsAndTrailingBytesRemainEnforced() throws {
        let request = envelope(.request, requestFields())
        let payment = envelope(.payment, paymentFields())
        XCTAssertThrowsError(try KagemushaWalletWireV1.requireExchangeBinding(
            request: request + Data([0]), payment: payment))
        var oversized = paymentFields()
        oversized[4] = Data(repeating: 0xa5, count: 10_000)
        XCTAssertThrowsError(try KagemushaWalletWireV1.requireExchangeBinding(
            request: request, payment: envelope(.payment, oversized)))
    }

    private let version = Data([1, 0])
    private let signature = Data(repeating: 0x36, count: 64)

    private func bodyFields() -> [Data] {
        [version, irohaPeerWalletStructuralSchemeV1, Data([0x29])]
            + Array(repeating: Data(), count: 16)
    }

    private func requestFields() -> [Data] {
        [record(bodyFields()), Data([1]), Data(), Data(), signature]
    }

    private func paymentFields() -> [Data] {
        [version, record([record(bodyFields()), signature]), Data([2]), Data([3]), Data([4])]
    }

    private func creditedFields() -> [Data] {
        [version, irohaPeerWalletStructuralSchemeV1, Data([5])]
    }

    private func record(_ fields: [Data]) -> Data {
        fields.reduce(into: Data()) { result, field in
            var length = field.count
            repeat {
                let byte = UInt8(length & 0x7f)
                length >>= 7
                result.append(byte | (length == 0 ? 0 : 0x80))
            } while length != 0
            result.append(field)
        }
    }

    private func envelope(_ kind: IrohaPeerWireKindV1, _ fields: [Data]) -> Data {
        envelope(kind, rawRecord: record(fields))
    }

    private func envelope(_ kind: IrohaPeerWireKindV1, rawRecord: Data) -> Data {
        let tag = withUnsafeBytes(of: UInt32(kind.rawValue).littleEndian) { Data($0) }
        return noritoEncode(typeName: KagemushaWalletWireV1.envelopeFrameName,
            payload: record([version, tag + record([rawRecord])]),
            flags: NoritoHeader.compactLen,
            payloadAlignment: KagemushaWalletWireV1.envelopePayloadAlignment)
    }
}
