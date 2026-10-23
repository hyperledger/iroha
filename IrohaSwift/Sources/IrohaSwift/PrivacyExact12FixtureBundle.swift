import Foundation

/// Fail-closed errors emitted by the native-independent Exact12 fixture codec.
public enum PrivacyExact12FixtureCodecErrorV1: Error, LocalizedError, Equatable, Sendable {
    case emptyArchive
    case archiveTooLarge(maximum: Int, actual: Int)
    case invalidBase64(String)
    case malformedArchive(String)
    case schemaMismatch(String)
    case nonCanonicalArchive(String)
    case unsupportedVersion(UInt32)
    case invalidRowCount(Int)
    case unknownProtocolDiscriminant(UInt32)
    case protocolOrderMismatch(index: Int)
    case invalidSubmitProofWireId
    case emptyNestedBlob(row: Int, field: String)
    case nestedBlobTooLarge(row: Int, field: String, maximum: Int, actual: Int)
    case invalidHashLength(row: Int, field: String, actual: Int)
    case aggregateNestedBytesTooLarge(maximum: Int, actual: Int)
    case invalidCrossFieldBinding(row: Int, field: String)
    case fixtureIdentityMismatch

    public var errorDescription: String? {
        switch self {
        case .emptyArchive:
            return "Exact12 fixture input must not be empty."
        case let .archiveTooLarge(maximum, actual):
            return "Exact12 fixture archive must not exceed \(maximum) bytes (found \(actual))."
        case let .invalidBase64(reason):
            return "Exact12 fixture Base64 is invalid: \(reason)"
        case let .malformedArchive(reason):
            return "Exact12 fixture archive is malformed: \(reason)"
        case let .schemaMismatch(field):
            return "Exact12 fixture carries the wrong Norito schema for \(field)."
        case let .nonCanonicalArchive(field):
            return "Exact12 fixture is not canonical Norito at \(field)."
        case let .unsupportedVersion(version):
            return "Exact12 fixture version \(version) is unsupported; version 1 is required."
        case let .invalidRowCount(actual):
            return "Exact12 fixture must contain exactly 12 rows (found \(actual))."
        case let .unknownProtocolDiscriminant(tag):
            return "Exact12 fixture contains unknown protocol discriminant \(tag)."
        case let .protocolOrderMismatch(index):
            return "Exact12 fixture row \(index) is outside the closed canonical protocol order."
        case .invalidSubmitProofWireId:
            return "Exact12 fixture must use the sole first-release submit-proof wire identifier."
        case let .emptyNestedBlob(row, field):
            return "Exact12 fixture row \(row) has an empty \(field) blob."
        case let .nestedBlobTooLarge(row, field, maximum, actual):
            return "Exact12 fixture row \(row) \(field) exceeds \(maximum) bytes (found \(actual))."
        case let .invalidHashLength(row, field, actual):
            return "Exact12 fixture row \(row) \(field) must be exactly 32 bytes (found \(actual))."
        case let .aggregateNestedBytesTooLarge(maximum, actual):
            return "Exact12 fixture nested material exceeds \(maximum) bytes (found \(actual))."
        case let .invalidCrossFieldBinding(row, field):
            return "Exact12 fixture row \(row) has an invalid \(field) binding."
        case .fixtureIdentityMismatch:
            return "Exact12 fixture differs from the independently supplied canonical Rust archive."
        }
    }
}

/// One byte-complete canonical first-release privacy fixture row.
public struct PrivacyExact12TypedFixtureRowV1: Equatable, Sendable {
    public let protocolId: PrivacyProtocolIdV1
    public let statementNorito: Data
    public let envelopeNorito: Data
    public let submitProofWireId: String
    public let submitProofInstructionNorito: Data
    public let transactionIntentProjectionNorito: Data
    public let transactionIntentDigest: Data
    public let unsignedTransactionPayloadNorito: Data
    public let signedTransactionVersionedNorito: Data
    public let signedTransactionHash: Data

    public init(
        protocolId: PrivacyProtocolIdV1,
        statementNorito: Data,
        envelopeNorito: Data,
        submitProofWireId: String,
        submitProofInstructionNorito: Data,
        transactionIntentProjectionNorito: Data,
        transactionIntentDigest: Data,
        unsignedTransactionPayloadNorito: Data,
        signedTransactionVersionedNorito: Data,
        signedTransactionHash: Data
    ) throws {
        self.protocolId = protocolId
        self.statementNorito = Data(statementNorito)
        self.envelopeNorito = Data(envelopeNorito)
        self.submitProofWireId = submitProofWireId
        self.submitProofInstructionNorito = Data(submitProofInstructionNorito)
        self.transactionIntentProjectionNorito = Data(transactionIntentProjectionNorito)
        self.transactionIntentDigest = Data(transactionIntentDigest)
        self.unsignedTransactionPayloadNorito = Data(unsignedTransactionPayloadNorito)
        self.signedTransactionVersionedNorito = Data(signedTransactionVersionedNorito)
        self.signedTransactionHash = Data(signedTransactionHash)
        let rowIndex = PrivacyExact12FixtureCodecV1.protocols.firstIndex(of: protocolId)
            ?? 0
        try PrivacyExact12FixtureCodecV1.validateRowResources(self, rowIndex: rowIndex)
    }
}

/// The closed set of twelve signed, byte-complete first-release privacy rows.
public struct PrivacyExact12FixtureBundleV1: Equatable, Sendable {
    public let version: UInt32
    public let rows: [PrivacyExact12TypedFixtureRowV1]

    public init(version: UInt32, rows: [PrivacyExact12TypedFixtureRowV1]) throws {
        guard version == PrivacyExact12FixtureCodecV1.version else {
            throw PrivacyExact12FixtureCodecErrorV1.unsupportedVersion(version)
        }
        guard rows.count == PrivacyExact12FixtureCodecV1.rowCount else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidRowCount(rows.count)
        }
        var aggregate = 0
        for (index, row) in rows.enumerated() {
            guard row.protocolId == PrivacyExact12FixtureCodecV1.protocols[index] else {
                throw PrivacyExact12FixtureCodecErrorV1.protocolOrderMismatch(index: index)
            }
            try PrivacyExact12FixtureCodecV1.validateRowResources(row, rowIndex: index)
            aggregate = try PrivacyExact12FixtureCodecV1.checkedAdd(
                aggregate,
                PrivacyExact12FixtureCodecV1.nestedByteCount(row),
                label: "aggregate nested material"
            )
            guard aggregate <= PrivacyExact12FixtureCodecV1.maximumAggregateNestedBytes else {
                throw PrivacyExact12FixtureCodecErrorV1.aggregateNestedBytesTooLarge(
                    maximum: PrivacyExact12FixtureCodecV1.maximumAggregateNestedBytes,
                    actual: aggregate
                )
            }
        }
        self.version = version
        self.rows = rows
    }
}

/// Strict pure-Swift codec for the canonical Rust-derived Exact12 outer bundle.
///
/// This codec does not load `NoritoBridge`. It validates canonical Norito
/// framing and the bindings that Swift can reproduce soundly: closed protocol
/// order, statement/envelope/proof discriminants, proof-system and engine
/// selection, envelope reuse by the submit instruction, normalized and signed
/// transaction structure, signed-payload equality, and the pipeline hash.
public enum PrivacyExact12FixtureCodecV1 {
    public static let schemaName = "iroha.privacy.exact12-typed-fixture-bundle.v1"
    public static let submitProofWireId = "iroha.privacy.submit_proof.v1"
    public static let version: UInt32 = 1
    public static let rowCount = 12
    public static let hashByteCount = 32
    public static let maximumArchiveBytes = 2 * 1024 * 1024
    public static let maximumAggregateNestedBytes = 2 * 1024 * 1024
    public static let maximumStatementBytes = 256 * 1024
    public static let maximumEnvelopeBytes = 512 * 1024
    public static let maximumInstructionBytes = 512 * 1024
    public static let maximumIntentProjectionBytes = 512 * 1024
    public static let maximumUnsignedTransactionBytes = 768 * 1024
    public static let maximumSignedTransactionBytes = 1024 * 1024

    static let protocols = PrivacyProtocolIdV1.allCases
    private static let maximumWireIdBytes = 128
    private static let outerPayloadAlignment = 8
    private static let typedPrivacyPayloadAlignment = 16
    private static let transactionPayloadAlignment = 8
    private static let statementSchemaName = "iroha.privacy.statement.v1"
    private static let envelopeSchemaName = "iroha.privacy.proof-envelope.v1"
    private static let proofWireMagic = Data([0x49, 0x52, 0x48, 0x5a, 0x4b, 0x31, 0xa5, 0x5a])
    private static let catalogCommitment = Data([
        0x5b, 0xcf, 0x36, 0x6f, 0xb1, 0x8d, 0x2e, 0x43,
        0x61, 0x48, 0x6c, 0x01, 0x5d, 0xa5, 0xb4, 0x1a,
        0x3f, 0xb0, 0x0e, 0xdf, 0x05, 0x61, 0x10, 0x42,
        0xcc, 0xc4, 0x52, 0x12, 0x0d, 0x17, 0x6e, 0xb0,
    ])
    private static let instructionSchemaName =
        "iroha_data_model::isi::privacy::SubmitPrivacyProofV1"
    private static let transactionPayloadSchemaName =
        "iroha_data_model::transaction::signed::model::TransactionPayload"

    /// Decode one canonical Norito archive without consulting the native bridge.
    public static func decodeCanonicalArchive(_ archive: Data) throws
        -> PrivacyExact12FixtureBundleV1
    {
        guard !archive.isEmpty else {
            throw PrivacyExact12FixtureCodecErrorV1.emptyArchive
        }
        guard archive.count <= maximumArchiveBytes else {
            throw PrivacyExact12FixtureCodecErrorV1.archiveTooLarge(
                maximum: maximumArchiveBytes,
                actual: archive.count
            )
        }
        let frame = try decodeFrame(
            archive,
            schemaName: schemaName,
            payloadAlignment: outerPayloadAlignment,
            maximumBytes: maximumArchiveBytes,
            label: "outer bundle"
        )
        var reader = Exact12Reader(frame.payload)
        let versionBytes = try reader.readField(maximum: 4, label: "bundle version")
        guard versionBytes.count == 4 else {
            throw PrivacyExact12FixtureCodecErrorV1.malformedArchive(
                "bundle version must occupy four bytes"
            )
        }
        let decodedVersion = try readUInt32LE(versionBytes, at: 0, label: "bundle version")
        let rowsPayload = try reader.readField(
            maximum: maximumArchiveBytes,
            label: "bundle rows"
        )
        try reader.requireFinished(label: "outer bundle")

        var rowsReader = Exact12Reader(rowsPayload)
        let count = try rowsReader.readUInt64LE(label: "row count")
        guard count == UInt64(rowCount) else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidRowCount(
                count <= UInt64(Int.max) ? Int(count) : Int.max
            )
        }
        var rows: [PrivacyExact12TypedFixtureRowV1] = []
        rows.reserveCapacity(rowCount)
        for index in 0..<rowCount {
            let rowPayload = try rowsReader.readField(
                maximum: maximumArchiveBytes,
                label: "row \(index)"
            )
            rows.append(try decodeRow(rowPayload, rowIndex: index))
        }
        try rowsReader.requireFinished(label: "bundle rows")

        let bundle = try PrivacyExact12FixtureBundleV1(
            version: decodedVersion,
            rows: rows
        )
        for (index, row) in rows.enumerated() {
            try validateCrossFieldBindings(row, rowIndex: index)
        }
        guard try encodeCanonicalArchive(bundle) == archive else {
            throw PrivacyExact12FixtureCodecErrorV1.nonCanonicalArchive("outer bundle")
        }
        return bundle
    }

    /// Encode one validated bundle in Rust's exact compact-length layout.
    public static func encodeCanonicalArchive(_ bundle: PrivacyExact12FixtureBundleV1) throws
        -> Data
    {
        let validated = try PrivacyExact12FixtureBundleV1(
            version: bundle.version,
            rows: bundle.rows
        )
        var rowsPayload = Data()
        appendUInt64LE(UInt64(rowCount), to: &rowsPayload)
        for (index, row) in validated.rows.enumerated() {
            try validateCrossFieldBindings(row, rowIndex: index)
            appendCompactField(try encodeRow(row, rowIndex: index), to: &rowsPayload)
        }
        var payload = Data()
        var versionBytes = Data()
        appendUInt32LE(validated.version, to: &versionBytes)
        appendCompactField(versionBytes, to: &payload)
        appendCompactField(rowsPayload, to: &payload)
        let archive = noritoEncode(
            typeName: schemaName,
            payload: payload,
            flags: NoritoHeader.compactLen,
            payloadAlignment: outerPayloadAlignment
        )
        guard archive.count <= maximumArchiveBytes else {
            throw PrivacyExact12FixtureCodecErrorV1.archiveTooLarge(
                maximum: maximumArchiveBytes,
                actual: archive.count
            )
        }
        return archive
    }

    /// Decode canonical padded STANDARD Base64. Whitespace and alternate
    /// padding spellings are rejected before any archive allocation.
    public static func decodeCanonicalBase64(_ encoded: String) throws
        -> PrivacyExact12FixtureBundleV1
    {
        guard !encoded.isEmpty else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidBase64("input is empty")
        }
        guard encoded.utf8.count <= maximumCanonicalBase64Bytes else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidBase64("input exceeds the archive ceiling")
        }
        guard encoded.unicodeScalars.allSatisfy({ scalar in
            switch scalar.value {
            case 43, 47, 48...57, 61, 65...90, 97...122:
                return true
            default:
                return false
            }
        }) else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidBase64(
                "only the STANDARD alphabet and terminal padding are accepted"
            )
        }
        guard let decoded = Data(base64Encoded: encoded, options: []),
              decoded.base64EncodedString() == encoded else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidBase64(
                "encoding is not the canonical padded spelling"
            )
        }
        return try decodeCanonicalArchive(decoded)
    }

    /// Decode the checked-in fixture-file representation: one unwrapped
    /// canonical Base64 line followed by exactly one LF.
    public static func decodeCanonicalBase64File(_ contents: String) throws
        -> PrivacyExact12FixtureBundleV1
    {
        guard contents.hasSuffix("\n"), !contents.hasSuffix("\n\n") else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidBase64(
                "fixture files must end with exactly one LF"
            )
        }
        let encoded = String(contents.dropLast())
        guard !encoded.contains("\n"), !encoded.contains("\r") else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidBase64(
                "fixture Base64 must be a single unwrapped line"
            )
        }
        return try decodeCanonicalBase64(encoded)
    }

    /// Encode one bundle as a canonical padded STANDARD Base64 string.
    public static func encodeCanonicalBase64(_ bundle: PrivacyExact12FixtureBundleV1) throws
        -> String
    {
        try encodeCanonicalArchive(bundle).base64EncodedString()
    }

    /// Require a candidate to equal an independently supplied Rust-derived
    /// canonical archive after validating both archives independently.
    ///
    /// This closes bindings that pure Swift intentionally does not
    /// reimplement, notably BLAKE3 statement and transaction-intent digests.
    public static func requireCanonicalArchive(
        _ candidate: Data,
        expectedCanonicalArchive: Data
    ) throws -> PrivacyExact12FixtureBundleV1 {
        _ = try decodeCanonicalArchive(expectedCanonicalArchive)
        let decoded = try decodeCanonicalArchive(candidate)
        guard candidate == expectedCanonicalArchive else {
            throw PrivacyExact12FixtureCodecErrorV1.fixtureIdentityMismatch
        }
        return decoded
    }

    /// Exact padded Base64 size for a bounded decoded byte count.
    public static func canonicalBase64EncodedLength(decodedByteCount: Int) throws -> Int {
        guard decodedByteCount >= 0 else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidBase64(
                "decoded byte count must be non-negative"
            )
        }
        let adjusted = try checkedAdd(decodedByteCount, 2, label: "Base64 length")
        let groups = adjusted / 3
        return try checkedMultiply(groups, 4, label: "Base64 length")
    }

    private static var maximumCanonicalBase64Bytes: Int {
        // Constants are compile-time bounded, so this cannot overflow.
        ((maximumArchiveBytes + 2) / 3) * 4
    }

    static func validateRowResources(
        _ row: PrivacyExact12TypedFixtureRowV1,
        rowIndex: Int
    ) throws {
        guard row.submitProofWireId == submitProofWireId else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidSubmitProofWireId
        }
        try requireBlob(
            row.statementNorito,
            maximum: maximumStatementBytes,
            row: rowIndex,
            field: "statement"
        )
        try requireBlob(
            row.envelopeNorito,
            maximum: maximumEnvelopeBytes,
            row: rowIndex,
            field: "envelope"
        )
        try requireBlob(
            row.submitProofInstructionNorito,
            maximum: maximumInstructionBytes,
            row: rowIndex,
            field: "submit-proof instruction"
        )
        try requireBlob(
            row.transactionIntentProjectionNorito,
            maximum: maximumIntentProjectionBytes,
            row: rowIndex,
            field: "transaction-intent projection"
        )
        try requireBlob(
            row.unsignedTransactionPayloadNorito,
            maximum: maximumUnsignedTransactionBytes,
            row: rowIndex,
            field: "unsigned transaction"
        )
        try requireBlob(
            row.signedTransactionVersionedNorito,
            maximum: maximumSignedTransactionBytes,
            row: rowIndex,
            field: "signed transaction"
        )
        try requireHash(row.transactionIntentDigest, row: rowIndex, field: "intent digest")
        try requireHash(row.signedTransactionHash, row: rowIndex, field: "transaction hash")
    }

    static func nestedByteCount(_ row: PrivacyExact12TypedFixtureRowV1) -> Int {
        row.statementNorito.count
            + row.envelopeNorito.count
            + row.submitProofWireId.utf8.count
            + row.submitProofInstructionNorito.count
            + row.transactionIntentProjectionNorito.count
            + row.transactionIntentDigest.count
            + row.unsignedTransactionPayloadNorito.count
            + row.signedTransactionVersionedNorito.count
            + row.signedTransactionHash.count
    }

    static func checkedAdd(_ left: Int, _ right: Int, label: String) throws -> Int {
        let (result, overflow) = left.addingReportingOverflow(right)
        guard !overflow else {
            throw PrivacyExact12FixtureCodecErrorV1.malformedArchive("\(label) overflow")
        }
        return result
    }

    private static func checkedMultiply(_ left: Int, _ right: Int, label: String) throws -> Int {
        let (result, overflow) = left.multipliedReportingOverflow(by: right)
        guard !overflow else {
            throw PrivacyExact12FixtureCodecErrorV1.malformedArchive("\(label) overflow")
        }
        return result
    }

    private static func decodeRow(_ payload: Data, rowIndex: Int) throws
        -> PrivacyExact12TypedFixtureRowV1
    {
        var reader = Exact12Reader(payload)
        let protocolBytes = try reader.readField(maximum: 4, label: "protocol id")
        guard protocolBytes.count == 4 else {
            throw PrivacyExact12FixtureCodecErrorV1.malformedArchive(
                "protocol discriminant must occupy four bytes"
            )
        }
        let protocolTag = try readUInt32LE(protocolBytes, at: 0, label: "protocol id")
        guard let protocolId = try? PrivacyProtocolIdV1(
            noritoDiscriminant: protocolTag
        ) else {
            throw PrivacyExact12FixtureCodecErrorV1.unknownProtocolDiscriminant(protocolTag)
        }
        guard protocolId == protocols[rowIndex] else {
            throw PrivacyExact12FixtureCodecErrorV1.protocolOrderMismatch(index: rowIndex)
        }

        let statement = try reader.readRawByteVector(
            maximum: maximumStatementBytes,
            label: "statement"
        )
        let envelope = try reader.readRawByteVector(
            maximum: maximumEnvelopeBytes,
            label: "envelope"
        )
        let wireId = try reader.readString(
            maximumUTF8Bytes: maximumWireIdBytes,
            label: "submit-proof wire id"
        )
        guard wireId == submitProofWireId else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidSubmitProofWireId
        }
        let instruction = try reader.readRawByteVector(
            maximum: maximumInstructionBytes,
            label: "submit-proof instruction"
        )
        let projection = try reader.readRawByteVector(
            maximum: maximumIntentProjectionBytes,
            label: "transaction-intent projection"
        )
        let intentDigest = try reader.readField(maximum: hashByteCount, label: "intent digest")
        guard intentDigest.count == hashByteCount else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidHashLength(
                row: rowIndex,
                field: "intent digest",
                actual: intentDigest.count
            )
        }
        let unsigned = try reader.readRawByteVector(
            maximum: maximumUnsignedTransactionBytes,
            label: "unsigned transaction"
        )
        let signed = try reader.readRawByteVector(
            maximum: maximumSignedTransactionBytes,
            label: "signed transaction"
        )
        let transactionHash = try reader.readField(
            maximum: hashByteCount,
            label: "transaction hash"
        )
        guard transactionHash.count == hashByteCount else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidHashLength(
                row: rowIndex,
                field: "transaction hash",
                actual: transactionHash.count
            )
        }
        try reader.requireFinished(label: "row \(rowIndex)")
        return try PrivacyExact12TypedFixtureRowV1(
            protocolId: protocolId,
            statementNorito: statement,
            envelopeNorito: envelope,
            submitProofWireId: wireId,
            submitProofInstructionNorito: instruction,
            transactionIntentProjectionNorito: projection,
            transactionIntentDigest: intentDigest,
            unsignedTransactionPayloadNorito: unsigned,
            signedTransactionVersionedNorito: signed,
            signedTransactionHash: transactionHash
        )
    }

    private static func encodeRow(
        _ row: PrivacyExact12TypedFixtureRowV1,
        rowIndex: Int
    ) throws -> Data {
        try validateRowResources(row, rowIndex: rowIndex)
        guard row.protocolId == protocols[rowIndex] else {
            throw PrivacyExact12FixtureCodecErrorV1.protocolOrderMismatch(index: rowIndex)
        }
        var payload = Data()
        var protocolBytes = Data()
        appendUInt32LE(row.protocolId.noritoDiscriminant, to: &protocolBytes)
        appendCompactField(protocolBytes, to: &payload)
        appendCompactField(rawByteVector(row.statementNorito), to: &payload)
        appendCompactField(rawByteVector(row.envelopeNorito), to: &payload)
        appendCompactField(compactString(row.submitProofWireId), to: &payload)
        appendCompactField(rawByteVector(row.submitProofInstructionNorito), to: &payload)
        appendCompactField(rawByteVector(row.transactionIntentProjectionNorito), to: &payload)
        appendCompactField(row.transactionIntentDigest, to: &payload)
        appendCompactField(rawByteVector(row.unsignedTransactionPayloadNorito), to: &payload)
        appendCompactField(rawByteVector(row.signedTransactionVersionedNorito), to: &payload)
        appendCompactField(row.signedTransactionHash, to: &payload)
        return payload
    }

    private static func validateCrossFieldBindings(
        _ row: PrivacyExact12TypedFixtureRowV1,
        rowIndex: Int
    ) throws {
        let protocolTag = row.protocolId.noritoDiscriminant
        let statement = try decodeFrame(
            row.statementNorito,
            schemaName: statementSchemaName,
            payloadAlignment: typedPrivacyPayloadAlignment,
            maximumBytes: maximumStatementBytes,
            label: "row \(rowIndex) statement"
        )
        try validateTaggedEnum(
            statement.payload,
            expectedTag: protocolTag,
            rowIndex: rowIndex,
            field: "statement protocol"
        )

        let envelope = try decodeFrame(
            row.envelopeNorito,
            schemaName: envelopeSchemaName,
            payloadAlignment: typedPrivacyPayloadAlignment,
            maximumBytes: maximumEnvelopeBytes,
            label: "row \(rowIndex) envelope"
        )
        try validateEnvelopePayload(
            envelope.payload,
            expectedProtocolTag: protocolTag,
            expectedStatementPayload: statement.payload,
            normalizedProjection: false,
            rowIndex: rowIndex
        )

        let instruction = try decodeFrame(
            row.submitProofInstructionNorito,
            schemaName: instructionSchemaName,
            payloadAlignment: typedPrivacyPayloadAlignment,
            maximumBytes: maximumInstructionBytes,
            label: "row \(rowIndex) submit-proof instruction"
        )
        var instructionReader = Exact12Reader(instruction.payload)
        let submittedEnvelope = try instructionReader.readField(
            maximum: maximumEnvelopeBytes,
            label: "submitted envelope"
        )
        try instructionReader.requireFinished(label: "submit-proof instruction")
        guard submittedEnvelope == envelope.payload else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex,
                field: "instruction-to-envelope"
            )
        }

        let unsignedFields = try decodeTransactionPayload(
            row.unsignedTransactionPayloadNorito,
            expectedProtocolTag: protocolTag,
            rowIndex: rowIndex,
            label: "unsigned transaction",
            expectedInstructionArchive: row.submitProofInstructionNorito,
            normalizedProjection: false
        )
        let projection = try decodeFrame(
            row.transactionIntentProjectionNorito,
            schemaName: transactionPayloadSchemaName,
            payloadAlignment: transactionPayloadAlignment,
            maximumBytes: maximumIntentProjectionBytes,
            label: "row \(rowIndex) transaction-intent projection"
        )
        let projectionFields = try decodeTransactionPayload(
            projection.payload,
            expectedProtocolTag: protocolTag,
            rowIndex: rowIndex,
            label: "transaction-intent projection",
            expectedInstructionArchive: nil,
            normalizedProjection: true
        )
        guard unsignedFields.count == projectionFields.count else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex,
                field: "projection field count"
            )
        }
        for index in unsignedFields.indices where index != 3 {
            guard unsignedFields[index] == projectionFields[index] else {
                throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                    row: rowIndex,
                    field: "projection field \(index)"
                )
            }
        }
        guard row.unsignedTransactionPayloadNorito != projection.payload else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex,
                field: "projection normalization"
            )
        }

        try validateSignedTransaction(
            row.signedTransactionVersionedNorito,
            unsignedPayload: row.unsignedTransactionPayloadNorito,
            rowIndex: rowIndex
        )
        var entrypoint = Data()
        appendUInt32LE(0, to: &entrypoint)
        appendCompactField(row.unsignedTransactionPayloadNorito, to: &entrypoint)
        var transactionHash = Blake2b.hash256(entrypoint)
        transactionHash[transactionHash.index(before: transactionHash.endIndex)] |= 1
        guard transactionHash == row.signedTransactionHash else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex,
                field: "pipeline transaction hash"
            )
        }
    }

    private static func validateEnvelopePayload(
        _ payload: Data,
        expectedProtocolTag: UInt32,
        expectedStatementPayload: Data?,
        normalizedProjection: Bool,
        rowIndex: Int
    ) throws {
        var reader = Exact12Reader(payload)
        var fields: [Data] = []
        fields.reserveCapacity(13)
        for index in 0..<13 {
            fields.append(
                try reader.readField(maximum: maximumEnvelopeBytes, label: "envelope field \(index)")
            )
        }
        try reader.requireFinished(label: "proof envelope")
        guard fields[0] == proofWireMagic else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex, field: "final V1 wire marker"
            )
        }
        guard fields[1] == catalogCommitment else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex, field: "Exact12 catalog commitment"
            )
        }
        guard fields[2].count == 4,
              try readUInt32LE(fields[2], at: 0, label: "envelope protocol")
                == expectedProtocolTag else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex,
                field: "envelope protocol"
            )
        }
        guard let protocolId = try? PrivacyProtocolIdV1(
            noritoDiscriminant: expectedProtocolTag
        ) else {
            throw PrivacyExact12FixtureCodecErrorV1.unknownProtocolDiscriminant(
                expectedProtocolTag
            )
        }
        let expectedTags = [
            (3, "proof system", protocolId.expectedProofSystem.rawValue),
            (4, "engine", protocolId.expectedEngine.rawValue),
        ]
        for (index, label, expectedTag) in expectedTags {
            guard fields[index].count == 4,
                  try readUInt32LE(fields[index], at: 0, label: label) == expectedTag else {
                throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                    row: rowIndex,
                    field: "envelope \(label)"
                )
            }
        }
        for index in 5...9 {
            let digestField = fields[index]
            guard digestField.count == 33,
                  digestField.first == 32,
                  digestField.dropFirst().contains(where: { $0 != 0 }) else {
                throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                    row: rowIndex,
                    field: "envelope digest field \(index)"
                )
            }
        }
        let statementDigest = fields[10]
        guard statementDigest.count == 33, statementDigest.first == 32 else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex,
                field: "envelope statement digest encoding"
            )
        }
        let statementDigestIsZero = statementDigest.dropFirst().allSatisfy { $0 == 0 }
        guard normalizedProjection ? statementDigestIsZero : !statementDigestIsZero else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex,
                field: "envelope statement digest normalization"
            )
        }
        if let expectedStatementPayload, fields[11] != expectedStatementPayload {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex,
                field: "envelope-to-statement"
            )
        }
        try validateTaggedEnum(
            fields[11],
            expectedTag: expectedProtocolTag,
            rowIndex: rowIndex,
            field: "envelope statement protocol"
        )
        try validateTaggedEnum(
            fields[12],
            expectedTag: expectedProtocolTag,
            rowIndex: rowIndex,
            field: "envelope proof protocol"
        )
    }

    private static func validateTaggedEnum(
        _ payload: Data,
        expectedTag: UInt32,
        rowIndex: Int,
        field: String
    ) throws {
        guard payload.count >= 5 else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex,
                field: field
            )
        }
        let tag = try readUInt32LE(payload, at: 0, label: field)
        var reader = Exact12Reader(Data(payload.dropFirst(4)))
        let variant = try reader.readField(maximum: maximumArchiveBytes, label: field)
        guard tag == expectedTag, !variant.isEmpty else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex,
                field: field
            )
        }
        try reader.requireFinished(label: field)
    }

    private static func decodeTransactionPayload(
        _ payload: Data,
        expectedProtocolTag: UInt32,
        rowIndex: Int,
        label: String,
        expectedInstructionArchive: Data?,
        normalizedProjection: Bool
    ) throws -> [Data] {
        var reader = Exact12Reader(payload)
        var fields: [Data] = []
        fields.reserveCapacity(9)
        for index in 0..<9 {
            fields.append(
                try reader.readField(
                    maximum: maximumUnsignedTransactionBytes,
                    label: "\(label) field \(index)"
                )
            )
        }
        try reader.requireFinished(label: label)
        let instructionArchive = try decodeSingleSubmitInstruction(
            fields[3],
            rowIndex: rowIndex,
            label: label
        )
        if let expectedInstructionArchive, instructionArchive != expectedInstructionArchive {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex,
                field: "unsigned transaction instruction"
            )
        }
        let instruction = try decodeFrame(
            instructionArchive,
            schemaName: instructionSchemaName,
            payloadAlignment: typedPrivacyPayloadAlignment,
            maximumBytes: maximumInstructionBytes,
            label: "row \(rowIndex) \(label) submit instruction"
        )
        var instructionReader = Exact12Reader(instruction.payload)
        let envelopePayload = try instructionReader.readField(
            maximum: maximumEnvelopeBytes,
            label: "\(label) envelope"
        )
        try instructionReader.requireFinished(label: "\(label) submit instruction")
        try validateEnvelopePayload(
            envelopePayload,
            expectedProtocolTag: expectedProtocolTag,
            expectedStatementPayload: nil,
            normalizedProjection: normalizedProjection,
            rowIndex: rowIndex
        )
        return fields
    }

    private static func decodeSingleSubmitInstruction(
        _ executable: Data,
        rowIndex: Int,
        label: String
    ) throws -> Data {
        guard executable.count >= 5,
              try readUInt32LE(executable, at: 0, label: "\(label) executable") == 0 else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex,
                field: "\(label) executable variant"
            )
        }
        var executableReader = Exact12Reader(Data(executable.dropFirst(4)))
        let sequence = try executableReader.readField(
            maximum: maximumUnsignedTransactionBytes,
            label: "\(label) instruction sequence"
        )
        try executableReader.requireFinished(label: "\(label) executable")
        var sequenceReader = Exact12Reader(sequence)
        guard try sequenceReader.readUInt64LE(label: "\(label) instruction count") == 1 else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex,
                field: "\(label) instruction count"
            )
        }
        let instructionBox = try sequenceReader.readField(
            maximum: maximumInstructionBytes,
            label: "\(label) instruction box"
        )
        try sequenceReader.requireFinished(label: "\(label) instruction sequence")
        var boxReader = Exact12Reader(instructionBox)
        let wireId = try boxReader.readString(
            maximumUTF8Bytes: maximumWireIdBytes,
            label: "\(label) wire id"
        )
        guard wireId == submitProofWireId else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidSubmitProofWireId
        }
        let archive = try boxReader.readRawByteVector(
            maximum: maximumInstructionBytes,
            label: "\(label) instruction archive"
        )
        try boxReader.requireFinished(label: "\(label) instruction box")
        return archive
    }

    private static func validateSignedTransaction(
        _ signed: Data,
        unsignedPayload: Data,
        rowIndex: Int
    ) throws {
        guard signed.first == 1 else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex,
                field: "signed transaction version"
            )
        }
        var reader = Exact12Reader(Data(signed.dropFirst()))
        let signature = try reader.readField(
            maximum: maximumSignedTransactionBytes,
            label: "transaction signature"
        )
        let embeddedPayload = try reader.readField(
            maximum: maximumUnsignedTransactionBytes,
            label: "signed payload"
        )
        let multisig = try reader.readField(maximum: 1, label: "multisig option")
        try reader.requireFinished(label: "signed transaction")
        guard !signature.isEmpty,
              embeddedPayload == unsignedPayload,
              multisig == Data([0]) else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: rowIndex,
                field: "signed-to-unsigned transaction"
            )
        }
    }

    private static func requireBlob(
        _ bytes: Data,
        maximum: Int,
        row: Int,
        field: String
    ) throws {
        guard !bytes.isEmpty else {
            throw PrivacyExact12FixtureCodecErrorV1.emptyNestedBlob(row: row, field: field)
        }
        guard bytes.count <= maximum else {
            throw PrivacyExact12FixtureCodecErrorV1.nestedBlobTooLarge(
                row: row,
                field: field,
                maximum: maximum,
                actual: bytes.count
            )
        }
    }

    private static func requireHash(_ bytes: Data, row: Int, field: String) throws {
        guard bytes.count == hashByteCount else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidHashLength(
                row: row,
                field: field,
                actual: bytes.count
            )
        }
        guard bytes.contains(where: { $0 != 0 }) else {
            throw PrivacyExact12FixtureCodecErrorV1.invalidCrossFieldBinding(
                row: row,
                field: "zero \(field)"
            )
        }
    }

    private static func decodeFrame(
        _ archive: Data,
        schemaName: String,
        payloadAlignment: Int,
        maximumBytes: Int,
        label: String
    ) throws -> (payload: Data, paddingLength: Int) {
        guard !archive.isEmpty, archive.count <= maximumBytes else {
            throw PrivacyExact12FixtureCodecErrorV1.malformedArchive(
                "\(label) violates its byte ceiling"
            )
        }
        guard archive.count >= NoritoHeader.encodedLength,
              archive.prefix(4) == NoritoHeader.magic,
              archive[4] == NoritoHeader.versionMajor,
              archive[5] == NoritoHeader.versionMinor else {
            throw PrivacyExact12FixtureCodecErrorV1.malformedArchive(
                "\(label) has an invalid Norito header"
            )
        }
        guard Array(archive[6..<22]) == noritoSchemaHash(forTypeName: schemaName) else {
            throw PrivacyExact12FixtureCodecErrorV1.schemaMismatch(label)
        }
        guard archive[22] == NoritoCompression.none.rawValue,
              archive[39] == NoritoHeader.compactLen else {
            throw PrivacyExact12FixtureCodecErrorV1.nonCanonicalArchive(label)
        }
        let payloadLength = try readUInt64LE(archive, at: 23, label: "\(label) payload length")
        guard payloadLength <= UInt64(maximumBytes), payloadLength <= UInt64(Int.max) else {
            throw PrivacyExact12FixtureCodecErrorV1.malformedArchive(
                "\(label) declares an oversized payload"
            )
        }
        guard let expectedPadding = noritoHeaderPaddingLength(payloadAlignment: payloadAlignment),
              archive.count == NoritoHeader.encodedLength + expectedPadding + Int(payloadLength) else {
            throw PrivacyExact12FixtureCodecErrorV1.nonCanonicalArchive(label)
        }
        if expectedPadding > 0 {
            let padding = archive[
                NoritoHeader.encodedLength..<(NoritoHeader.encodedLength + expectedPadding)
            ]
            guard padding.allSatisfy({ $0 == 0 }) else {
                throw PrivacyExact12FixtureCodecErrorV1.nonCanonicalArchive(label)
            }
        }
        let payloadStart = NoritoHeader.encodedLength + expectedPadding
        let payload = Data(archive[payloadStart..<archive.count])
        let expectedChecksum = try readUInt64LE(archive, at: 31, label: "\(label) checksum")
        guard crc64ECMA(payload) == expectedChecksum else {
            throw PrivacyExact12FixtureCodecErrorV1.malformedArchive(
                "\(label) checksum mismatch"
            )
        }
        guard noritoEncode(
            typeName: schemaName,
            payload: payload,
            flags: NoritoHeader.compactLen,
            payloadAlignment: payloadAlignment
        ) == archive else {
            throw PrivacyExact12FixtureCodecErrorV1.nonCanonicalArchive(label)
        }
        return (payload, expectedPadding)
    }

    private static func readUInt32LE(_ data: Data, at offset: Int, label: String) throws -> UInt32 {
        guard offset >= 0, data.count - offset >= 4 else {
            throw PrivacyExact12FixtureCodecErrorV1.malformedArchive("truncated \(label)")
        }
        var value: UInt32 = 0
        let range = data.index(data.startIndex, offsetBy: offset)..<data.index(
            data.startIndex,
            offsetBy: offset + 4
        )
        data[range].withUnsafeBytes { buffer in
            if let base = buffer.baseAddress { memcpy(&value, base, 4) }
        }
        return UInt32(littleEndian: value)
    }

    private static func readUInt64LE(_ data: Data, at offset: Int, label: String) throws -> UInt64 {
        guard offset >= 0, data.count - offset >= 8 else {
            throw PrivacyExact12FixtureCodecErrorV1.malformedArchive("truncated \(label)")
        }
        var value: UInt64 = 0
        let range = data.index(data.startIndex, offsetBy: offset)..<data.index(
            data.startIndex,
            offsetBy: offset + 8
        )
        data[range].withUnsafeBytes { buffer in
            if let base = buffer.baseAddress { memcpy(&value, base, 8) }
        }
        return UInt64(littleEndian: value)
    }

    private static func appendUInt32LE(_ value: UInt32, to output: inout Data) {
        var littleEndian = value.littleEndian
        output.append(Data(bytes: &littleEndian, count: 4))
    }

    private static func appendUInt64LE(_ value: UInt64, to output: inout Data) {
        var littleEndian = value.littleEndian
        output.append(Data(bytes: &littleEndian, count: 8))
    }

    private static func appendCompactLength(_ value: UInt64, to output: inout Data) {
        var remaining = value
        while remaining >= 0x80 {
            output.append(UInt8(remaining & 0x7f) | 0x80)
            remaining >>= 7
        }
        output.append(UInt8(remaining))
    }

    private static func appendCompactField(_ field: Data, to output: inout Data) {
        appendCompactLength(UInt64(field.count), to: &output)
        output.append(field)
    }

    private static func rawByteVector(_ bytes: Data) -> Data {
        var encoded = Data()
        appendUInt64LE(UInt64(bytes.count), to: &encoded)
        encoded.append(bytes)
        return encoded
    }

    private static func compactString(_ value: String) -> Data {
        let bytes = Data(value.utf8)
        var encoded = Data()
        appendCompactLength(UInt64(bytes.count), to: &encoded)
        encoded.append(bytes)
        return encoded
    }

    private struct Exact12Reader {
        private let data: Data
        private(set) var offset = 0

        init(_ data: Data) {
            self.data = data
        }

        mutating func readUInt64LE(label: String) throws -> UInt64 {
            let bytes = try readBytes(8, label: label)
            return try PrivacyExact12FixtureCodecV1.readUInt64LE(bytes, at: 0, label: label)
        }

        mutating func readField(maximum: Int, label: String) throws -> Data {
            let length = try readCompactLength(label: label)
            guard length <= UInt64(maximum), length <= UInt64(Int.max) else {
                throw PrivacyExact12FixtureCodecErrorV1.malformedArchive(
                    "\(label) length exceeds its byte ceiling"
                )
            }
            return try readBytes(Int(length), label: label)
        }

        mutating func readRawByteVector(maximum: Int, label: String) throws -> Data {
            let field = try readField(
                maximum: try PrivacyExact12FixtureCodecV1.checkedAdd(
                    maximum,
                    8,
                    label: "\(label) vector"
                ),
                label: label
            )
            var fieldReader = Exact12Reader(field)
            let count = try fieldReader.readUInt64LE(label: "\(label) byte count")
            guard count > 0, count <= UInt64(maximum), count <= UInt64(Int.max) else {
                throw PrivacyExact12FixtureCodecErrorV1.malformedArchive(
                    "\(label) byte count is empty or oversized"
                )
            }
            let bytes = try fieldReader.readBytes(Int(count), label: label)
            try fieldReader.requireFinished(label: label)
            return bytes
        }

        mutating func readString(maximumUTF8Bytes: Int, label: String) throws -> String {
            let field = try readField(
                maximum: try PrivacyExact12FixtureCodecV1.checkedAdd(
                    maximumUTF8Bytes,
                    2,
                    label: "\(label) string"
                ),
                label: label
            )
            var fieldReader = Exact12Reader(field)
            let count = try fieldReader.readCompactLength(label: "\(label) UTF-8 count")
            guard count <= UInt64(maximumUTF8Bytes), count <= UInt64(Int.max) else {
                throw PrivacyExact12FixtureCodecErrorV1.malformedArchive(
                    "\(label) UTF-8 count is oversized"
                )
            }
            let bytes = try fieldReader.readBytes(Int(count), label: label)
            try fieldReader.requireFinished(label: label)
            guard let value = String(data: bytes, encoding: .utf8) else {
                throw PrivacyExact12FixtureCodecErrorV1.malformedArchive(
                    "\(label) is not valid UTF-8"
                )
            }
            return value
        }

        mutating func requireFinished(label: String) throws {
            guard offset == data.count else {
                throw PrivacyExact12FixtureCodecErrorV1.malformedArchive(
                    "\(label) contains trailing bytes"
                )
            }
        }

        private mutating func readCompactLength(label: String) throws -> UInt64 {
            var value: UInt64 = 0
            for byteIndex in 0..<10 {
                let byte = try readByte(label: label)
                let payload = UInt64(byte & 0x7f)
                if byteIndex == 9, payload > 1 {
                    throw PrivacyExact12FixtureCodecErrorV1.malformedArchive(
                        "\(label) length varint overflows UInt64"
                    )
                }
                value |= payload << UInt64(byteIndex * 7)
                if byte & 0x80 == 0 {
                    guard byteIndex == 0 || payload != 0 else {
                        throw PrivacyExact12FixtureCodecErrorV1.nonCanonicalArchive(label)
                    }
                    return value
                }
            }
            throw PrivacyExact12FixtureCodecErrorV1.malformedArchive(
                "\(label) length varint exceeds ten bytes"
            )
        }

        private mutating func readByte(label: String) throws -> UInt8 {
            guard offset < data.count else {
                throw PrivacyExact12FixtureCodecErrorV1.malformedArchive("truncated \(label)")
            }
            let byte = data[data.index(data.startIndex, offsetBy: offset)]
            offset += 1
            return byte
        }

        private mutating func readBytes(_ count: Int, label: String) throws -> Data {
            guard count >= 0, offset <= data.count, count <= data.count - offset else {
                throw PrivacyExact12FixtureCodecErrorV1.malformedArchive("truncated \(label)")
            }
            let start = data.index(data.startIndex, offsetBy: offset)
            let end = data.index(start, offsetBy: count)
            offset += count
            return Data(data[start..<end])
        }
    }
}
