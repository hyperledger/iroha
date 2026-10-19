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
        // Unique field 0 is the payer account: completing an open Request may fill it.
        // Fields 1...8 are immutable receiver terms; field 9 is the receiver signature.
        for index in 1...9 {
            var signedRequest = uniqueRequestFields()
            if signedRequest[index].isEmpty { signedRequest[index] = Data([1]) }
            else { signedRequest[index][signedRequest[index].count - 1] ^= 1 }
            var payment = paymentFields()
            payment[1] = record(signedRequest)
            XCTAssertThrowsError(try KagemushaWalletWireV1.requireExchangeBinding(
                request: request, payment: envelope(.payment, payment)), "unique Request field \(index)") {
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
            let payment = paymentFields()
            XCTAssertThrowsError(try KagemushaWalletWireV1.requireExchangeBinding(
                request: envelope(.request, request), payment: envelope(.payment, payment)))
        }
        let signedRequest = uniqueRequestFields()
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
        oversized[2] = Data(repeating: 0xa5, count: 10_000)
        XCTAssertThrowsError(try KagemushaWalletWireV1.requireExchangeBinding(
            request: request, payment: envelope(.payment, oversized)))
    }

    func testPaymentProofRolesAreBoundedBeforeExchangeBinding() throws {
        let wire = KagemushaWalletWireV1.self
        let request = envelope(.request, requestFields())
        for (sigma, omega) in [(0, 0), (3_520, 0), (0, 5_086), (3_520, 5_086)] {
            let payment = envelope(.payment, paymentWithProofVectors(
                sigma: proofVector(count: sigma), omega: proofVector(count: omega)))
            XCTAssertLessThanOrEqual(payment.count, wire.messageMaximumBytes)
            XCTAssertEqual(try wire.inspectEnvelope(payment).kind, .payment)
            try wire.requireExchangeBinding(request: request, payment: payment)
        }
        let sigmaCap = wire.paymentSigmaProofCapBytes
        let omegaCap = wire.paymentOmegaProofCapBytes
        for (sigma, omega, field) in [
            (sigmaCap + 1, 0, "payment.sigma_proof"), (0, omegaCap + 1, "payment.omega_proof"),
            (sigmaCap + 1, omegaCap - 1, "payment.sigma_proof"), (sigmaCap - 1, omegaCap + 1, "payment.omega_proof")
        ] {
            let payment = envelope(.payment, paymentWithProofVectors(
                sigma: proofVector(count: sigma), omega: proofVector(count: omega)))
            XCTAssertLessThanOrEqual(payment.count, wire.messageMaximumBytes)
            XCTAssertLessThanOrEqual(sigma + omega, wire.paymentProofBudgetBytes)
            for operation in [
                { _ = try wire.inspectEnvelope(payment) },
                { try wire.requireExchangeBinding(request: request, payment: payment) }
            ] {
                XCTAssertThrowsError(try operation()) {
                    XCTAssertEqual($0 as? KagemushaWalletWireErrorV1, .invalidField(field))
                }
            }
        }
    }

    func testPaymentProofVectorLengthsMustMatchExactOriginalBytes() throws {
        let malformed = [Data(), Data(repeating: 0, count: 7),
            proofVector(count: 1, declared: 0), proofVector(count: 1, declared: 2),
            proofVector(count: 1, declared: UInt64.max)]
        for bad in malformed {
            for sigma in [true, false] {
                let payment = envelope(.payment, paymentWithProofVectors(
                    sigma: sigma ? bad : proofVector(count: 0),
                    omega: sigma ? proofVector(count: 0) : bad))
                XCTAssertThrowsError(try KagemushaWalletWireV1.inspectEnvelope(payment)) {
                    XCTAssertEqual($0 as? KagemushaWalletWireErrorV1,
                        .invalidField(sigma ? "payment.sigma_proof" : "payment.omega_proof"))
                }
            }
        }
    }

    func testPaymentDisplayAmountPreservesExactUnsignedRequestData() throws {
        // These synthetic DATA records authenticate nothing. The caller still needs the
        // exact Payment supplied by genuine Native completion before displaying a receipt.
        for amount: KagemushaWalletUInt128V1 in [
            .init(low: 1, high: 0), .init(low: 0, high: 1),
            .init(low: 0x0123_4567_89ab_cdef, high: 0xfedc_ba98_7654_3210),
            .init(low: 0, high: UInt64(1) << 63), .init(low: .max, high: .max)
        ] {
            let bytes = withUnsafeBytes(of: amount.low.littleEndian) { Data($0) }
                + withUnsafeBytes(of: amount.high.littleEndian) { Data($0) }
            XCTAssertEqual(try KagemushaWalletWireV1.paymentAmountData(paymentWithAmount(bytes)), amount)
        }
    }

    func testPaymentDisplayAmountRejectsZeroNoncanonicalScalarsAndWrongKinds() throws {
        for bytes in [Data(repeating: 0, count: 16), Data(repeating: 1, count: 15),
                      Data(repeating: 1, count: 17)] {
            XCTAssertThrowsError(try KagemushaWalletWireV1.paymentAmountData(paymentWithAmount(bytes))) {
                XCTAssertEqual($0 as? KagemushaWalletWireErrorV1, .invalidField("payment.amount"))
            }
        }
        for kind: IrohaPeerWireKindV1 in [.request, .credited] {
            let fields = kind == .request ? requestFields() : creditedFields()
            XCTAssertThrowsError(try KagemushaWalletWireV1.paymentAmountData(envelope(kind, fields)))
        }
    }

    func testPaymentDisplayAmountKeepsEnvelopeAndRecordBounds() throws {
        let payment = paymentWithAmount(Data([1]) + Data(repeating: 0, count: 15))
        for invalid in [Data(payment.dropLast()), payment + Data([0]),
                        Data(repeating: 0, count: KagemushaWalletWireV1.messageMaximumBytes + 1)] {
            XCTAssertThrowsError(try KagemushaWalletWireV1.paymentAmountData(invalid))
        }
        let fields = paymentFields()
        for invalid in [Array(fields.dropLast()), fields + [Data()]] {
            XCTAssertThrowsError(try KagemushaWalletWireV1.paymentAmountData(envelope(.payment, invalid)))
        }
    }

    func testRequestDisplayAmountPreservesExactUnsignedQuotedData() throws {
        // A receiver shows its own Request's quote before the payer approves. These synthetic
        // DATA records authenticate nothing; only Native output may supply the Request.
        for amount: KagemushaWalletUInt128V1 in [
            .init(low: 1, high: 0), .init(low: 0, high: 1),
            .init(low: 0x0123_4567_89ab_cdef, high: 0xfedc_ba98_7654_3210),
            .init(low: 0, high: UInt64(1) << 63), .init(low: .max, high: .max)
        ] {
            let bytes = withUnsafeBytes(of: amount.low.littleEndian) { Data($0) }
                + withUnsafeBytes(of: amount.high.littleEndian) { Data($0) }
            XCTAssertEqual(try KagemushaWalletWireV1.requestAmountData(requestWithAmount(bytes)), amount)
            // The Payment that carries this Request reads the same amount.
            XCTAssertEqual(try KagemushaWalletWireV1.paymentAmountData(paymentWithAmount(bytes)), amount)
        }
    }

    func testRequestDisplayAmountRejectsZeroNoncanonicalScalarsAndWrongKinds() throws {
        for bytes in [Data(repeating: 0, count: 16), Data(repeating: 1, count: 15),
                      Data(repeating: 1, count: 17)] {
            XCTAssertThrowsError(try KagemushaWalletWireV1.requestAmountData(requestWithAmount(bytes))) {
                XCTAssertEqual($0 as? KagemushaWalletWireErrorV1, .invalidField("request.amount"))
            }
        }
        for kind: IrohaPeerWireKindV1 in [.payment, .credited] {
            let fields = kind == .payment ? paymentFields() : creditedFields()
            XCTAssertThrowsError(try KagemushaWalletWireV1.requestAmountData(envelope(kind, fields)))
        }
        let request = requestWithAmount(Data([1]) + Data(repeating: 0, count: 15))
        for invalid in [Data(request.dropLast()), request + Data([0])] {
            XCTAssertThrowsError(try KagemushaWalletWireV1.requestAmountData(invalid))
        }
    }

    func testOpenRequestAcceptsPayerCompletionButCompletedRequestCannotBeRetargeted() throws {
        let open = bodyFields(), completed = completedBodyFields()
        let payment = envelope(.payment, irohaPeerWalletPaymentFieldsV1(body: completed, signature: signature, proof: Data([4])))
        for body in [open, completed] {
            try KagemushaWalletWireV1.requireExchangeBinding(
                request: envelope(.request, [record(body), Data([1]), Data(), Data(), signature]), payment: payment)
        }
        for field in [3, 4, 7] {
            var changed = completed
            changed[field][0] ^= 1
            XCTAssertThrowsError(try KagemushaWalletWireV1.requireExchangeBinding(
                request: envelope(.request, [record(changed), Data([1]), Data(), Data(), signature]), payment: payment))
        }
    }

    func testOpenRequestRequiresCanonicalPayerFieldWidths() throws {
        let payment = envelope(.payment, irohaPeerWalletPaymentFieldsV1(body: completedBodyFields(), signature: signature, proof: Data([4])))
        for field in [3, 4, 7] {
            for width in [0, 1, field == 7 ? 15 : 31, field == 7 ? 17 : 33] {
                var malformed = bodyFields()
                malformed[field] = Data(repeating: 0, count: width)
                XCTAssertThrowsError(try KagemushaWalletWireV1.requireExchangeBinding(
                    request: envelope(.request, [record(malformed), Data([1]), Data(), Data(), signature]), payment: payment))
            }
        }
    }

    private func completedBodyFields() -> [Data] {
        var body = bodyFields()
        body[3] = Data(repeating: 0x31, count: 32)
        body[4] = Data(repeating: 0x42, count: 32)
        body[7] = Data([1]) + Data(repeating: 0, count: 15)
        return body
    }

    private func requestWithAmount(_ amount: Data) -> Data {
        var body = bodyFields()
        body[9] = amount
        return envelope(.request, [record(body), Data([1]), Data(), Data(), signature])
    }

    private func paymentWithAmount(_ amount: Data) -> Data {
        var body = bodyFields()
        body[9] = amount
        return envelope(.payment,
            irohaPeerWalletPaymentFieldsV1(body: body, signature: signature, proof: Data([4])))
    }

    private func proofVector(count: Int, declared: UInt64? = nil) -> Data {
        withUnsafeBytes(of: (declared ?? UInt64(count)).littleEndian) { Data($0) }
            + Data(repeating: 0x5a, count: count)
    }

    // Explicit malformed-vector seam in test DATA only; enclosing records/header remain canonical.
    private func paymentWithProofVectors(sigma: Data, omega: Data) -> [Data] {
        let body = bodyFields()
        var publicFields = Array(repeating: Data(), count: 13)
        publicFields[4] = body[3]
        let lineage = record([record(publicFields), omega])
        let effect = [Data(), body[5], body[7], body[9], body[11], Data(), Data(), Data()]
        var statement = Array(repeating: Data(), count: 14)
        statement[0] = body[0]
        statement[1] = body[1]
        statement[4] = body[2]
        statement[13] = Data([3, 0, 0, 0]) + record(effect)
        let send = record([body[0], record(statement), Data([1, 0, 0, 0]) + record([lineage]),
            record([sigma]), Data()])
        return [body[0], record(uniqueRequestFields()), send]
    }

    private let version = Data([1, 0])
    private let signature = Data(repeating: 0x36, count: 64)

    private func bodyFields() -> [Data] {
        var body = [version, irohaPeerWalletStructuralSchemeV1, Data([0x29])]
            + Array(repeating: Data(), count: 14)
        body[3] = Data(repeating: 0, count: 32)
        body[4] = Data(repeating: 0, count: 32)
        body[7] = Data(repeating: 0, count: 16)
        return body
    }

    private func requestFields() -> [Data] {
        [record(bodyFields()), Data([1]), Data(), Data(), signature]
    }

    private func paymentFields() -> [Data] {
        irohaPeerWalletPaymentFieldsV1(body: bodyFields(), signature: signature, proof: Data([4]))
    }

    private func uniqueRequestFields() -> [Data] {
        let body = bodyFields()
        return [4, 6, 8, 10, 12, 13, 14, 15, 16].map { body[$0] } + [signature]
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
