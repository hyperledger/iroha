import CryptoKit
import Foundation

/// Ordinary `Executable::Instructions` transactions whose signature is produced by the caller.
///
/// Apps that keep the account key behind their own user-presence gate build the exact payload,
/// sign `signingMessage(payload)` with that key, then assemble the versioned signed wire. The
/// same payload bytes are retained for exact-byte retries; nothing here re-signs or refreshes TTL.
public enum InstructionTransactionV1 {
    /// Canonical unsigned payload for one or more dynamic instruction frames.
    public static func payload(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64 = 100_000,
        frames: [TransactionInstructionFrame],
        feePayment: FeePaymentIntent
    ) throws -> Data {
        guard creationTimeMs > 0, ttlMs > 0 else { throw ExecutableBatchInputError.zeroTimeToLive }
        return try SingleInstructionSwiftNoritoEncoder.instructionsPayload(
            networkId: networkId, authority: authority, creationTimeMs: creationTimeMs,
            ttlMs: ttlMs, frames: frames, feePayment: feePayment)
    }

    /// The 32-byte Iroha prehash the account key signs.
    public static func signingMessage(payload: Data) -> Data { IrohaHash.hash(payload) }

    /// Assemble the versioned signed wire. An Ed25519 public key, when supplied, must verify
    /// the detached signature over this exact payload.
    public static func envelope(payload: Data, signature: Data, ed25519PublicKey: Data? = nil) throws
        -> SignedTransactionEnvelope {
        guard !payload.isEmpty, signature.count == 64 else { throw ExecutableBatchInputError.invalidInstructionFrame }
        if let ed25519PublicKey {
            guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: ed25519PublicKey),
                  key.isValidSignature(signature, for: signingMessage(payload: payload)) else {
                throw SigningKeyError.publicKeyUnavailable
            }
        }
        return SingleInstructionSwiftNoritoEncoder.signedEnvelope(transactionPayload: payload, signature: signature)
    }

    /// The Native ABI-bound decoder's JSON form of the envelope's unsigned payload, in the
    /// exact shape `ToriiClient.quoteFees(unsignedPayload:)` accepts. Nil when unavailable.
    public static func unsignedPayloadJSON(_ envelope: SignedTransactionEnvelope) -> [String: ToriiJSONValue]? {
        guard let json = NoritoNativeBridge.shared.decodeSignedTransaction(envelope.norito),
              let data = json.data(using: .utf8),
              case let .object(root)? = try? JSONDecoder().decode(ToriiJSONValue.self, from: data),
              case let .object(payload)? = root["payload"] else { return nil }
        return payload
    }

    /// Quote the network fee for the payload built by `build`, then rebuild it with the quoted
    /// intent. The rebuilt payload must decode to exactly the payload Torii quoted.
    public static func quotedPayload(
        draftFeePayment: FeePaymentIntent,
        client: ToriiClient,
        canonicalAuth: ToriiCanonicalRequestAuth,
        build: (FeePaymentIntent) throws -> Data
    ) async throws -> (payload: Data, feePayment: FeePaymentIntent) {
        let draft = try build(draftFeePayment)
        guard let unsigned = unsignedPayloadJSON(try envelope(payload: draft, signature: Data(count: 64))) else {
            throw SwiftTransactionEncoderError.nativeBridgeUnavailable
        }
        let quoted = try await client.quoteAndApplyFees(unsignedPayload: unsigned, canonicalAuth: canonicalAuth)
        let payload = try build(quoted.quote.intent)
        guard unsignedPayloadJSON(try envelope(payload: payload, signature: Data(count: 64))) == quoted.payload else {
            throw ToriiClientError.invalidPayload("The rebuilt transaction differs from the quoted payload.")
        }
        return (payload, quoted.quote.intent)
    }
}

extension KagemushaWalletLedgerTransportV1 {
    /// Sole registered dynamic wire identity of the KAGEMUSHA ordinary ledger instruction.
    public static let instructionWireName = "iroha.kagemusha.wallet.ledger.v1"

    /// Exact Native-produced ledger frame (Activate, Load, Unload or CloseLoads) as an instruction.
    public static func instructionFrame(_ nativeFrame: Data) throws -> TransactionInstructionFrame {
        guard (1...65_536).contains(nativeFrame.count) else { throw ExecutableBatchInputError.invalidInstructionFrame }
        return try TransactionInstructionFrame(wireName: instructionWireName, framedPayload: nativeFrame)
    }
}
