import Foundation

extension IrohaSDK {
    /// Authenticate a retained envelope before submitting or reconciling its exact bytes.
    ///
    /// The canonical decoder verifies the inner signature against the payload's authority.
    /// This additionally binds every retained envelope field to that payload, the selected
    /// network and the expected account. No signature, timestamp or transaction is rebuilt.
    public func requireCanonicalSignedEnvelope(
        envelope: SignedTransactionEnvelope,
        expectedNetworkId: NetworkId,
        expectedAuthority: String
    ) throws {
        let context = "retained signed transaction"
        let inspected = try ToriiCanonicalTransactionDraft.inspectVersionedSignedTransaction(
            envelope.norito, context: context
        )
        guard envelope.signedTransaction == Data(inspected.wire.dropFirst()),
              envelope.payload == nil || envelope.payload == inspected.transactionPayload else {
            throw ToriiClientError.invalidPayload(
                "\(context) fields differ from the authenticated canonical wire."
            )
        }
        guard inspected.payload.networkId == expectedNetworkId else {
            throw ToriiClientError.invalidPayload("\(context) belongs to a different network.")
        }
        try ToriiCanonicalTransactionDraft.requireAuthority(
            inspected.payload, equals: expectedAuthority, context: context
        )
        var entrypoint = CompactNoritoWriter()
        entrypoint.writeUInt32LE(0)
        entrypoint.writeField(inspected.transactionPayload)
        guard envelope.transactionHash == IrohaHash.hash(entrypoint.data) else {
            throw ToriiClientError.invalidPayload(
                "\(context) hash differs from its canonical external entrypoint."
            )
        }
    }
}
