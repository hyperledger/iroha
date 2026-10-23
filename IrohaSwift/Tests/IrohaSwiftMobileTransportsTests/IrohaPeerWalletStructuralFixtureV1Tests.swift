import Foundation
import XCTest
@testable import IrohaSwift

/// The mobile fixture follows current bounded proof roles and mandatory companion framing.
final class IrohaPeerWalletStructuralFixtureV1Tests: XCTestCase {
    func testMaximumPaymentPreservesRequestBindingAndCompanion() throws {
        // These are structural DATA, not typed proofs or payment authority.
        let request = irohaPeerWalletExchangeEnvelopeV1(
            kind: .request, frameBytes: KagemushaWalletWireV1.messageMaximumBytes)
        let payment = irohaPeerWalletExchangeEnvelopeV1(
            kind: .payment, frameBytes: KagemushaWalletWireV1.messageMaximumBytes)
        XCTAssertEqual(request.count, 10_000)
        XCTAssertEqual(payment.count, 10_000)
        try KagemushaWalletWireV1.requireExchangeBinding(request: request, payment: payment)
        let companion = Data(repeating: 0xcd, count: IrohaPeerWalletPaymentV1.maximumCompanionBytes)
        let wrapped = try IrohaPeerKagemushaWalletAdapterV1.wrap(
            payment, payerCompanion: companion)
        XCTAssertEqual(wrapped.encoded.count, IrohaPeerNfcV1.maximumPaymentMessageBytes)
        XCTAssertEqual(wrapped.encoded.count, 84 + 12_064)
        XCTAssertThrowsError(try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1, kind: .payment, schemaVersion: 1,
            canonicalPayload: payment)) {
            XCTAssertEqual($0 as? IrohaPeerWireMessageErrorV1,
                .invalidCanonicalPayload(profile: .kagemushaWalletV1, kind: .payment))
        }
    }

    func testMaximumSizeFixtureDoesNotRelaxEitherProofRoleCap() throws {
        let cases: [(Data, Data, String)] = [
            (Data(repeating: 0xa5, count: KagemushaWalletWireV1.paymentSigmaProofCapBytes + 1),
             Data(), "payment.sigma_proof"),
            (Data(), Data(repeating: 0xa5, count: KagemushaWalletWireV1.paymentOmegaProofCapBytes + 1),
             "payment.omega_proof"),
        ]
        for (sigma, omega, field) in cases {
            let payment = irohaPeerWalletExchangeEnvelopeV1(
                kind: .payment, payload: sigma, lineageProof: omega)
            XCTAssertThrowsError(try IrohaPeerKagemushaWalletAdapterV1.wrap(
                payment, payerCompanion: irohaPeerWalletPayerCompanionV1())) {
                XCTAssertEqual($0 as? KagemushaWalletWireErrorV1, .invalidField(field))
            }
        }
    }
}
