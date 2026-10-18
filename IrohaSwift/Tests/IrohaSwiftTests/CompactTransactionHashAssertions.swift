import XCTest
@testable import IrohaSwift

func canonicalSignedTransactionPayload(_ signedTransaction: Data) throws -> Data {
    var reader = CanonicalNoritoReader(data: signedTransaction)
    _ = try reader.readCompactField()
    let payload = try reader.readCompactField()
    _ = try reader.readCompactField()
    guard reader.remaining() == 0 else {
        throw CanonicalNoritoDecodingError.invalidField(
            "signed transaction must contain exactly three fields"
        )
    }
    return payload
}

/// Compare hedged Ed25519 output without hiding invalid signatures or changing payload framing.
/// Both original signatures must verify before only the signature field is substituted.
func canonicalSignedTransactionUsingReferenceSignature(
    _ envelope: SignedTransactionEnvelope,
    referenceWire: Data
) throws -> Data {
    guard envelope.signedTransaction == Data(envelope.norito.dropFirst()) else {
        throw CanonicalNoritoDecodingError.invalidField(
            "signed transaction differs from its versioned wire"
        )
    }
    let actual = try ToriiCanonicalTransactionDraft.inspectVersionedSignedTransaction(
        envelope.norito, context: "actual signing parity"
    )
    let reference = try ToriiCanonicalTransactionDraft.inspectVersionedSignedTransaction(
        referenceWire, context: "reference signing parity"
    )
    guard actual.transactionPayload == reference.transactionPayload else {
        throw CanonicalNoritoDecodingError.invalidField(
            "signing parity requires exactly equal canonical payloads"
        )
    }
    var actualReader = CanonicalNoritoReader(data: envelope.signedTransaction)
    _ = try actualReader.readCompactField()
    var referenceReader = CanonicalNoritoReader(data: Data(referenceWire.dropFirst()))
    _ = try referenceReader.readCompactField()
    // Retain all original payload/attachment bytes, including their length prefixes.
    return Data(referenceWire.prefix(1 + referenceReader.offset))
        + Data(envelope.norito.dropFirst(1 + actualReader.offset))
}

func XCTAssertCanonicalExternalEntrypointHash(
    _ envelope: SignedTransactionEnvelope,
    file: StaticString = #filePath,
    line: UInt = #line
) {
    let transactionPayload: Data
    do {
        transactionPayload = try canonicalSignedTransactionPayload(envelope.signedTransaction)
    } catch {
        XCTFail(
            "invalid canonical signed transaction: \(error)",
            file: file,
            line: line
        )
        return
    }

    var compact = CompactNoritoWriter()
    compact.writeUInt32LE(0)
    compact.writeField(transactionPayload)
    XCTAssertEqual(
        envelope.transactionHash,
        IrohaHash.hash(compact.data),
        "transaction hash must use compact TransactionEntrypoint::External intent framing",
        file: file,
        line: line
    )

    var fixedWidth = CanonicalNoritoWriter()
    fixedWidth.writeUInt32LE(0)
    fixedWidth.writeField(transactionPayload)
    XCTAssertNotEqual(
        envelope.transactionHash,
        IrohaHash.hash(fixedWidth.data),
        "fixed-u64 entrypoint framing must not alias the canonical transaction hash",
        file: file,
        line: line
    )
}
