import Foundation
import XCTest
@testable import IrohaSwift

final class TransferPayloadTests: XCTestCase {
    func testUnsignedTransferPayloadMatchesNativeSignedWireWithoutMemo() throws {
        XCTAssertTrue(NoritoNativeBridge.shared.supportsTransactions(using: .ed25519))
        let keypair = try Keypair(privateKeyBytes: Data(repeating: 0x2a, count: 32))
        let account = try AccountId.make(publicKey: keypair.publicKey)
        let destination = try AccountId.make(publicKey: Keypair(privateKeyBytes: Data(repeating: 0x2b, count: 32)).publicKey)
        let network = try NetworkId(bytes: Data(repeating: 0x31, count: 32))
        let sdk = IrohaSDK(baseURL: URL(string: "https://native-transfer.example")!)
        let time: UInt64 = 1_760_000_000_000
        sdk.creationTimeProvider = { time }
        let fee = FeePaymentIntent.authority(chargeLimits: [], gasLimit: nil)
        for ttl: UInt64? in [nil, 60_000] {
            for nonce: UInt32? in [nil, 7] {
                let transfer = TransferRequest(networkId: network, authority: account,
                    assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM", quantity: "12.3", destination: destination,
                    feePayment: fee, ttlMs: ttl, nonce: nonce)
                let unsigned = try IrohaSDK.buildTransferPayload(transfer: transfer, creationTimeMs: time)
                let envelope = try sdk.buildSignedTransfer(transfer: transfer, keypair: keypair)
                let native = try XCTUnwrap(NoritoNativeBridge.shared.encodeTransfer(networkId: network,
                    authority: account, creationTimeMs: time, ttlMs: ttl, nonce: nonce,
                    assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM", quantity: "12.3", destination: destination,
                    feePaymentJSON: fee.canonicalJSONData(), privateKey: keypair.privateKeyBytes))
                // CryptoKit may hedge Ed25519 signatures. Both signatures must verify
                // over the exact same canonical payload, including the Native default TTL.
                for wire in [envelope.norito, native.signedBytes] {
                    XCTAssertEqual(try ToriiCanonicalTransactionDraft.transactionPayload(
                        fromVersionedSignedTransaction: wire, context: "transfer parity"), unsigned)
                }
                XCTAssertEqual(envelope.transactionHash, native.hash)
                let detached = try InstructionTransactionV1.envelope(payload: unsigned,
                    signature: keypair.sign(InstructionTransactionV1.signingMessage(payload: unsigned)),
                    ed25519PublicKey: keypair.publicKey)
                XCTAssertEqual(try ToriiCanonicalTransactionDraft.transactionPayload(
                    fromVersionedSignedTransaction: detached.norito, context: "detached transfer"), unsigned)
                XCTAssertEqual(detached.transactionHash, native.hash)
            }
        }
    }

    func testTransferMemoIsPreservedByQuotationSerializationAndNativeSignatureDecoding() throws {
        XCTAssertTrue(NoritoNativeBridge.shared.supportsTransactions(using: .ed25519))
        let keypair = try Keypair(privateKeyBytes: Data(repeating: 0x2a, count: 32))
        let account = try AccountId.make(publicKey: keypair.publicKey)
        let network = try NetworkId(bytes: Data(repeating: 0x31, count: 32))
        let sdk = IrohaSDK(baseURL: URL(string: "https://native-transfer.example")!)
        let time: UInt64 = 1_760_000_000_000
        sdk.creationTimeProvider = { time }
        for memo: String? in [nil, "", "invoice 42", " カイカイ — 42\nsecond line "] {
            let transfer = TransferRequest(networkId: network, authority: account,
                assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM", quantity: "0.01", destination: account,
                description: memo, feePayment: .authority(chargeLimits: [], gasLimit: nil),
                ttlMs: 60_000, nonce: 9)
            let unsigned = try IrohaSDK.buildTransferPayload(transfer: transfer, creationTimeMs: time)
            let draft = try InstructionTransactionV1.envelope(payload: unsigned,
                signature: keypair.sign(InstructionTransactionV1.signingMessage(payload: unsigned)))
            let quotePayload = try XCTUnwrap(InstructionTransactionV1.unsignedPayloadJSON(draft, chainDiscriminant: AccountId.defaultNetworkPrefix))
            let signed = try sdk.buildSignedTransfer(transfer: transfer, keypair: keypair)
            XCTAssertEqual(InstructionTransactionV1.unsignedPayloadJSON(signed, chainDiscriminant: AccountId.defaultNetworkPrefix), quotePayload)
            let metadata = memo.flatMap { $0.isEmpty ? nil : ["memo": ToriiJSONValue.string($0)] } ?? [:]
            XCTAssertEqual(quotePayload["metadata"], .object(metadata))
            XCTAssertEqual(quotePayload["nonce"], .number(9))
            XCTAssertEqual(quotePayload["time_to_live_ms"], .number(60_000))
            XCTAssertNil(quotePayload["admission_intent"])
            let independentlySigned = try InstructionTransactionV1.envelope(payload: unsigned,
                signature: keypair.sign(InstructionTransactionV1.signingMessage(payload: unsigned)),
                ed25519PublicKey: keypair.publicKey)
            for wire in [signed.norito, independentlySigned.norito] {
                XCTAssertEqual(try ToriiCanonicalTransactionDraft.transactionPayload(
                    fromVersionedSignedTransaction: wire, context: "memo transfer"), unsigned)
            }
            XCTAssertEqual(signed.transactionHash, independentlySigned.transactionHash)
        }
    }
}

extension TransferPayloadTests {

    func testUnsignedPayloadJSONScopesAuthorityAndSponsorToTheSelectedChain() throws {
        let key = try Keypair(privateKeyBytes: Data(repeating: 0x41, count: 32))
        let otherKey = try Keypair(privateKeyBytes: Data(repeating: 0x42, count: 32))
        let address = try AccountAddress.fromI105(AccountId.make(publicKey: key.publicKey))
        let otherAddress = try AccountAddress.fromI105(AccountId.make(publicKey: otherKey.publicKey))
        let authority = try address.toI105(networkPrefix: 369)
        let destination = try otherAddress.toI105(networkPrefix: 369)
        let fee = FeePaymentIntent.sponsor(programId: try FeeSponsorProgramId(sponsor: destination, name: "wallet"),
            programRevision: 1, chargeLimits: [], gasLimit: nil)
        let sdk = IrohaSDK(baseURL: URL(string: "https://native-transfer.example")!)
        let envelope = try sdk.buildSignedTransfer(transfer: TransferRequest(
            networkId: NetworkId(bytes: Data(repeating: 0x31, count: 32)), authority: authority,
            assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM", quantity: "12.3", destination: destination,
            description: "preserve カイカイ", feePayment: fee, ttlMs: 60_000), keypair: key)
        let exactPayload = try ToriiCanonicalTransactionDraft.transactionPayload(
            fromVersionedSignedTransaction: envelope.norito, context: "chain scoped quote")
        var instructions: ToriiJSONValue?
        for prefix: UInt16 in [369, 753, 369] {
            let payload = try XCTUnwrap(InstructionTransactionV1.unsignedPayloadJSON(envelope,
                chainDiscriminant: prefix))
            XCTAssertEqual(payload["authority"], .string(try address.toI105(networkPrefix: prefix)))
            let expectedFee = FeePaymentIntent.sponsor(programId: try FeeSponsorProgramId(
                sponsor: otherAddress.toI105(networkPrefix: prefix), name: "wallet"),
                programRevision: 1, chargeLimits: [], gasLimit: nil)
            XCTAssertEqual(payload["fee_payment"], try JSONDecoder().decode(ToriiJSONValue.self,
                from: expectedFee.canonicalJSONData()))
            XCTAssertEqual(payload["metadata"], .object(["memo": .string("preserve カイカイ")]))
            if let instructions { XCTAssertEqual(payload["instructions"], instructions) }
            instructions = payload["instructions"]
            XCTAssertEqual(try ToriiCanonicalTransactionDraft.transactionPayload(
                fromVersionedSignedTransaction: envelope.norito, context: "unchanged signed transfer"), exactPayload)
        }
    }

    func testUnsignedPayloadJSONRestoresNativeScopeAfterFailureAndThrownOuterOperation() throws {
        let key = try Keypair(privateKeyBytes: Data(repeating: 0x41, count: 32))
        let account = try AccountId.make(publicKey: key.publicKey)
        let address = try AccountAddress.fromI105(account)
        let sdk = IrohaSDK(baseURL: URL(string: "https://native-transfer.example")!)
        let envelope = try sdk.buildSignedTransfer(transfer: TransferRequest(
            networkId: NetworkId(bytes: Data(repeating: 0x31, count: 32)), authority: account,
            assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM", quantity: "1", destination: account,
            feePayment: .authority(chargeLimits: [], gasLimit: nil)), keypair: key)
        let bridge = NoritoNativeBridge.shared
        func ambientAuthority() throws -> ToriiJSONValue? {
            let json = try XCTUnwrap(bridge.decodeSignedTransaction(envelope.norito))
            let root = try JSONDecoder().decode(ToriiJSONValue.self, from: Data(json.utf8))
            guard case let .object(value) = root, case let .object(payload)? = value["payload"] else {
                XCTFail("Missing native payload"); return nil
            }
            return payload["authority"]
        }
        let original = try ambientAuthority()
        enum ExpectedScopeFailure: Error { case interrupted }
        XCTAssertThrowsError(try bridge.withChainDiscriminant(369) { () throws -> Void in
            let nested = try XCTUnwrap(InstructionTransactionV1.unsignedPayloadJSON(envelope, chainDiscriminant: 0))
            XCTAssertEqual(nested["authority"], .string(try address.toI105(networkPrefix: 0)))
            XCTAssertEqual(try ambientAuthority(), .string(try address.toI105(networkPrefix: 369)))
            throw ExpectedScopeFailure.interrupted
        }) { XCTAssertTrue($0 is ExpectedScopeFailure) }
        XCTAssertEqual(try ambientAuthority(), original)
        let malformed = SignedTransactionEnvelope(norito: Data([0]), signedTransaction: Data(),
            payload: nil, transactionHash: Data(repeating: 0, count: 32))
        XCTAssertNil(InstructionTransactionV1.unsignedPayloadJSON(malformed, chainDiscriminant: 369))
        XCTAssertEqual(try ambientAuthority(), original)
    }
}
