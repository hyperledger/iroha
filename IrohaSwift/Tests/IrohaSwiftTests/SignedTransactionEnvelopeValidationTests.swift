import Foundation
import XCTest
@testable import IrohaSwift

final class SignedTransactionEnvelopeValidationTests: XCTestCase {
    private let sdk = IrohaSDK(baseURL: URL(string: "https://envelope-validation.example")!)

    private func fixture() throws -> (SignedTransactionEnvelope, String, Data) {
        let key = try Keypair(privateKeyBytes: Data(repeating: 0x35, count: 32))
        let authority = try AccountId.make(publicKey: key.publicKey)
        let payload = try CanonicalUnsignedTransactionTestSupport.genericPayload(authority: authority)
        let envelope = try InstructionTransactionV1.envelope(
            payload: payload, signature: key.sign(InstructionTransactionV1.signingMessage(payload: payload)),
            ed25519PublicKey: key.publicKey
        )
        return (envelope, authority, payload)
    }

    func testExactEnvelopeWithOptionalRetainedPayloadAndCodableReopen() throws {
        let (original, authority, payload) = try fixture()
        for retainedPayload: Data? in [nil, payload] {
            let envelope = SignedTransactionEnvelope(norito: original.norito,
                signedTransaction: original.signedTransaction, payload: retainedPayload,
                transactionHash: original.transactionHash)
            let reopened = try JSONDecoder().decode(SignedTransactionEnvelope.self,
                from: JSONEncoder().encode(envelope))
            XCTAssertNoThrow(try sdk.requireCanonicalSignedEnvelope(envelope: reopened,
                expectedNetworkId: TestNetworkIds.canonical, expectedAuthority: authority))
        }
    }

    func testRejectsWrongNetworkAuthorityAndEveryRetainedFieldMismatch() throws {
        let (original, authority, payload) = try fixture()
        XCTAssertThrowsError(try sdk.requireCanonicalSignedEnvelope(envelope: original,
            expectedNetworkId: NetworkId(bytes: Data(repeating: 0x94, count: 32)),
            expectedAuthority: authority))
        let other = try AccountId.make(publicKey: Keypair(privateKeyBytes: Data(repeating: 0x36, count: 32)).publicKey)
        XCTAssertThrowsError(try sdk.requireCanonicalSignedEnvelope(envelope: original,
            expectedNetworkId: TestNetworkIds.canonical, expectedAuthority: other))
        let candidates = [
            SignedTransactionEnvelope(norito: original.norito,
                signedTransaction: original.norito, payload: nil, transactionHash: original.transactionHash),
            SignedTransactionEnvelope(norito: original.norito,
                signedTransaction: original.signedTransaction + Data([0]), payload: nil,
                transactionHash: original.transactionHash),
            SignedTransactionEnvelope(norito: original.norito,
                signedTransaction: original.signedTransaction, payload: payload + Data([0]),
                transactionHash: original.transactionHash),
            SignedTransactionEnvelope(norito: original.norito,
                signedTransaction: original.signedTransaction, payload: nil,
                transactionHash: IrohaHash.hash(payload))
        ]
        for candidate in candidates {
            XCTAssertThrowsError(try sdk.requireCanonicalSignedEnvelope(envelope: candidate,
                expectedNetworkId: TestNetworkIds.canonical, expectedAuthority: authority))
        }
    }

    func testRejectsInvalidSignatureAndNoncanonicalWireEvenWithConsistentEnvelopeFields() throws {
        let (original, authority, payload) = try fixture()
        let otherKey = try Keypair(privateKeyBytes: Data(repeating: 0x36, count: 32))
        let forged = try InstructionTransactionV1.envelope(payload: payload,
            signature: otherKey.sign(InstructionTransactionV1.signingMessage(payload: payload)))
        for wire in [forged.norito, original.norito + Data([0]), Data([2]) + original.signedTransaction] {
            let candidate = SignedTransactionEnvelope(norito: wire,
                signedTransaction: Data(wire.dropFirst()), payload: payload,
                transactionHash: original.transactionHash)
            XCTAssertThrowsError(try sdk.requireCanonicalSignedEnvelope(envelope: candidate,
                expectedNetworkId: TestNetworkIds.canonical, expectedAuthority: authority))
        }
    }
}
