import Foundation

public enum TransactionInputError: Error, LocalizedError, Equatable {
    case emptyAccountId(field: String)
    case malformedAccountId(field: String, value: String)
    case emptyRwaId(field: String)
    case malformedRwaId(field: String, value: String)
    case emptyAssetDefinitionId
    case malformedAssetDefinitionId(String)
    case emptyDomainId(field: String)
    case malformedDomainId(field: String, value: String)
    case emptyLabel(field: String)
    case malformedLabel(field: String, value: String)
    case emptyAssetId
    case malformedAssetId(String)
    case invalidGovernanceAbiVersion(UInt16)
    case invalidGovernanceHashLength(field: String, actual: Int)
    case invalidGovernanceManifestProvenance(field: String)
    case invalidGovernanceSelector(field: String, value: String)
    case governanceOwnerMustEqualAuthority
    case invalidZkBallotPublicInputs(String)
    /// The native transfer encoder cannot attach a memo yet; a non-empty
    /// `TransferRequest.description` would otherwise be silently dropped.
    case transferDescriptionUnsupported

    public var errorDescription: String? {
        switch self {
        case let .emptyAccountId(field):
            return "Account id for \(field) must not be empty."
        case let .malformedAccountId(field, value):
            return "Account id for \(field) must be a canonical bare I105 literal with no whitespace (received '\(value)')."
        case let .emptyRwaId(field):
            return "RWA id for \(field) must not be empty."
        case let .malformedRwaId(field, value):
            return "RWA id for \(field) must use '<64-hex-hash>$<domain>' public form with no whitespace (received '\(value)')."
        case .emptyAssetDefinitionId:
            return "Asset definition id must not be empty."
        case let .malformedAssetDefinitionId(value):
            return "Asset definition id must use canonical unprefixed Base58 form with optional canonical #dataspace:<id> suffix (received '\(value)')."
        case let .emptyDomainId(field):
            return "Domain id for \(field) must not be empty."
        case let .malformedDomainId(field, value):
            return "Domain id for \(field) must use canonical fully-qualified 'name.dataspace' form with no whitespace or reserved separators (received '\(value)')."
        case let .emptyLabel(field):
            return "Label for \(field) must not be empty."
        case let .malformedLabel(field, value):
            return "Label for \(field) must use lowercase a-z, 0-9, '_' or '-' and be 32 characters or fewer (received '\(value)')."
        case .emptyAssetId:
            return "Asset id must not be empty."
        case let .malformedAssetId(value):
            return "Asset id must use canonical unprefixed Base58 form with no whitespace (received '\(value)')."
        case let .invalidGovernanceAbiVersion(value):
            return "Governance ABI version must be exactly 1 in the first release (received \(value))."
        case let .invalidGovernanceHashLength(field, actual):
            return "Governance \(field) must contain exactly 32 bytes (received \(actual))."
        case let .invalidGovernanceManifestProvenance(field):
            return "Governance manifest provenance \(field) must be an exact non-empty string."
        case let .invalidGovernanceSelector(field, value):
            return "Governance selector for \(field) must be 1...128 RFC 3986 unreserved ASCII bytes and must not start with a dot (received '\(value)')."
        case .governanceOwnerMustEqualAuthority:
            return "A public conviction update must be owned by its transaction authority."
        case let .invalidZkBallotPublicInputs(reason):
            return "Governance ZK public inputs are invalid: \(reason)"
        case .transferDescriptionUnsupported:
            return "TransferRequest.description is not encoded into transfers yet; pass nil. A non-empty memo is rejected rather than silently dropped from the signed transaction."
        }
    }
}

/// Canonicalizes one explicit `DomainId` label without attaching domain state
/// to an account address.
func canonicalizeDomainIdLabel(_ raw: String) -> String? {
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty,
          trimmed == raw,
          trimmed.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
          !trimmed.contains("@"),
          !trimmed.contains("#"),
          !trimmed.contains("$") else {
        return nil
    }
    let lowered = trimmed.lowercased()
    for scalar in lowered.unicodeScalars {
        guard scalar.isASCII else {
            return nil
        }
        let value = scalar.value
        let isAlphaNum = (value >= 48 && value <= 57) || (value >= 97 && value <= 122)
        if !isAlphaNum && value != 45 && value != 95 && value != 46 {
            return nil
        }
    }
    return lowered
}

struct TransactionInputValidator {
    struct NamedAccountId {
        let field: String
        let value: String
    }

    struct ValidatedIds {
        let networkId: NetworkId
        let authorityId: String
        let assetDefinitionId: String?
        let accountIds: [String: String]
    }

    static func validate(networkId: NetworkId,
                         authorityId: String,
                         assetDefinitionId: String? = nil,
                         accountIds: [NamedAccountId] = []) throws -> ValidatedIds {
        let sanitizedAuthority = try sanitizeAccountId(authorityId, field: "authority")
        var sanitizedAccounts: [String: String] = [:]
        for account in accountIds {
            sanitizedAccounts[account.field] = try sanitizeAccountId(account.value, field: account.field)
        }
        let sanitizedAssetDefinitionId = try assetDefinitionId.map { try sanitizeAssetDefinitionId($0) }
        return ValidatedIds(networkId: networkId,
                            authorityId: sanitizedAuthority,
                            assetDefinitionId: sanitizedAssetDefinitionId,
                            accountIds: sanitizedAccounts)
    }

    static func sanitizeGovernanceSelector(_ value: String, field: String) throws -> String {
        guard GovernanceSelectorV1.isValid(value) else {
            throw TransactionInputError.invalidGovernanceSelector(field: field, value: value)
        }
        return value
    }

    static func sanitizeAccountId(_ accountId: String, field: String) throws -> String {
        let checked = try requireExactNonEmpty(
            accountId,
            empty: .emptyAccountId(field: field),
            invalid: { .malformedAccountId(field: field, value: $0) }
        )
        if checked.rangeOfCharacter(from: .whitespacesAndNewlines) != nil {
            throw TransactionInputError.malformedAccountId(field: field, value: checked)
        }
        if checked.contains("@") || checked.contains("#") || checked.contains("$") {
            throw TransactionInputError.malformedAccountId(field: field, value: checked)
        }
        do {
            let prefix = try AccountAddress.inspectI105NetworkPrefix(checked).chainDiscriminant
            let address = try AccountAddress.parseCanonicalI105(
                checked,
                expectedPrefix: prefix
            )
            let canonical = try address.toI105(networkPrefix: prefix)
            guard canonical.utf8.elementsEqual(checked.utf8) else {
                throw TransactionInputError.malformedAccountId(field: field, value: checked)
            }
            return canonical
        } catch AccountAddressError.nativeBridgeUnavailable {
            throw SwiftTransactionEncoderError.nativeBridgeUnavailable
        } catch {
            throw TransactionInputError.malformedAccountId(field: field, value: checked)
        }
    }

    static func sanitizeRwaId(_ rwaId: String, field: String) throws -> String {
        let checked = try requireExactNonEmpty(
            rwaId,
            empty: .emptyRwaId(field: field),
            invalid: { .malformedRwaId(field: field, value: $0) }
        )
        if checked.rangeOfCharacter(from: .whitespacesAndNewlines) != nil {
            throw TransactionInputError.malformedRwaId(field: field, value: checked)
        }
        let parts = checked.split(separator: "$", omittingEmptySubsequences: false)
        guard parts.count == 2 else {
            throw TransactionInputError.malformedRwaId(field: field, value: checked)
        }
        let hashPart = String(parts[0])
        let domainPart = String(parts[1])
        let hexScalars = CharacterSet(charactersIn: "0123456789abcdefABCDEF")
        guard hashPart.count == 64, hashPart.unicodeScalars.allSatisfy({ hexScalars.contains($0) }) else {
            throw TransactionInputError.malformedRwaId(field: field, value: checked)
        }
        let sanitizedDomain = try sanitizeDomainId(domainPart, field: field)
        return "\(hashPart.lowercased())$\(sanitizedDomain)"
    }

    private static func sanitizeAssetDefinitionId(_ assetDefinitionId: String) throws -> String {
        let checked = try requireExactNonEmpty(
            assetDefinitionId,
            empty: .emptyAssetDefinitionId,
            invalid: { .malformedAssetDefinitionId($0) }
        )
        if checked.rangeOfCharacter(from: .whitespacesAndNewlines) != nil {
            throw TransactionInputError.malformedAssetDefinitionId(checked)
        }
        let definitionLiteral: String
        let scopeSuffix: String
        if let (definition, scope) = parseAssetBalanceScopeSuffix(checked) {
            definitionLiteral = definition
            scopeSuffix = scope
        } else {
            definitionLiteral = checked
            scopeSuffix = ""
        }
        guard AssetDefinitionAddress.looksCanonical(definitionLiteral) else {
            throw TransactionInputError.malformedAssetDefinitionId(checked)
        }
        if AssetDefinitionAddress.decode(definitionLiteral) == nil {
            throw TransactionInputError.malformedAssetDefinitionId(checked)
        }
        return definitionLiteral + scopeSuffix
    }

    private static func parseAssetBalanceScopeSuffix(_ value: String) -> (String, String)? {
        guard value.contains("#") else {
            return nil
        }
        let marker = "#dataspace:"
        guard let markerRange = value.range(of: marker) else {
            return ("", "")
        }
        let definition = String(value[..<markerRange.lowerBound])
        let rawDataspaceId = String(value[markerRange.upperBound...])
        guard !definition.isEmpty,
              !rawDataspaceId.contains("#"),
              isCanonicalUnsignedDecimal(rawDataspaceId),
              let dataspaceId = UInt64(rawDataspaceId) else {
            return ("", "")
        }
        return (definition, "\(marker)\(dataspaceId)")
    }

    private static func isCanonicalUnsignedDecimal(_ value: String) -> Bool {
        guard !value.isEmpty,
              value == "0" || !value.hasPrefix("0") else {
            return false
        }
        return value.unicodeScalars.allSatisfy { scalar in
            scalar.value >= 48 && scalar.value <= 57
        }
    }

    static func sanitizeDomainId(_ domainId: String, field: String) throws -> String {
        let checked = try requireExactNonEmpty(
            domainId,
            empty: .emptyDomainId(field: field),
            invalid: { .malformedDomainId(field: field, value: $0) }
        )
        if checked.rangeOfCharacter(from: .whitespacesAndNewlines) != nil
            || checked.contains("@")
            || checked.contains("#")
            || checked.contains("$")
        {
            throw TransactionInputError.malformedDomainId(field: field, value: checked)
        }
        let parts = checked.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2,
              !parts[0].isEmpty,
              !parts[1].isEmpty
        else {
            throw TransactionInputError.malformedDomainId(field: field, value: checked)
        }
        guard let name = canonicalizeDomainIdLabel(String(parts[0])),
              let dataspace = canonicalizeDomainIdLabel(String(parts[1])) else {
            throw TransactionInputError.malformedDomainId(field: field, value: checked)
        }
        return "\(name).\(dataspace)"
    }

    static func sanitizeLabel(_ label: String, field: String) throws -> String {
        let checked = try requireExactNonEmpty(
            label,
            empty: .emptyLabel(field: field),
            invalid: { .malformedLabel(field: field, value: $0) }
        )
        if checked.count > 32 || checked != checked.lowercased() {
            throw TransactionInputError.malformedLabel(field: field, value: checked)
        }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789_-")
        if checked.unicodeScalars.contains(where: { !allowed.contains($0) }) {
            throw TransactionInputError.malformedLabel(field: field, value: checked)
        }
        return checked
    }

    private static func sanitizeAssetId(_ assetId: String) throws -> String {
        let checked = try requireExactNonEmpty(
            assetId,
            empty: .emptyAssetId,
            invalid: { .malformedAssetId($0) }
        )
        do {
            return try sanitizeAssetDefinitionId(checked)
        } catch {
            throw TransactionInputError.malformedAssetId(checked)
        }
    }

    private static func requireExactNonEmpty(_ value: String,
                                             empty: TransactionInputError,
                                             invalid: (String) -> TransactionInputError) throws -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw empty
        }
        guard trimmed == value else {
            throw invalid(value)
        }
        return value
    }

    static func sanitizeMetadataTarget(_ target: MetadataTarget) throws -> MetadataTarget {
        switch target {
        case let .domain(domainId):
            let sanitized = try sanitizeDomainId(domainId, field: "target")
            return .domain(sanitized)
        case let .account(accountId):
            let sanitized = try sanitizeAccountId(accountId, field: "target")
            return .account(sanitized)
        case let .rwa(rwaId):
            let sanitized = try sanitizeRwaId(rwaId, field: "target")
            return .rwa(sanitized)
        case let .assetDefinition(assetDefinitionId):
            let sanitized = try sanitizeAssetDefinitionId(assetDefinitionId)
            return .assetDefinition(sanitized)
        case let .asset(assetId):
            let sanitized = try sanitizeAssetId(assetId)
            return .asset(sanitized)
        }
    }
}

enum SwiftTransactionEncoderError: Error, LocalizedError, Sendable {
    case nativeBridgeUnavailable
    case nativeBridgeError(NativeBridgeError)
    case unsupportedSigningAlgorithm(SigningAlgorithm)
    case invalidClaimIdentifierReceipt(String)
    case invalidInput(String)
    case invalidNativeSignedTransaction(String)

    public var errorDescription: String? {
        switch self {
        case .nativeBridgeUnavailable:
            return NoritoNativeBridge.bridgeUnavailableMessage(
                "Norito native bridge is unavailable on this platform."
            )
        case let .nativeBridgeError(error):
            return "Norito native bridge call failed: \(error)"
        case let .unsupportedSigningAlgorithm(algorithm):
            return "Signing algorithm \(algorithm) is not supported by this encoder."
        case let .invalidClaimIdentifierReceipt(reason):
            return "ClaimIdentifier receipt is invalid: \(reason)"
        case let .invalidInput(reason):
            return "Transaction input is invalid: \(reason)"
        case let .invalidNativeSignedTransaction(reason):
            return "Native signed transaction is invalid: \(reason)"
        }
    }
}

private let signedTransactionWireVersion: UInt8 = 1

private func encodeVersionedSignedTransaction(_ signedTransaction: Data) -> Data {
    var bytes = Data([signedTransactionWireVersion])
    bytes.append(signedTransaction)
    return bytes
}

func encodeNativeClaimIdentifierReceiptJSON(_ receipt: ToriiIdentifierResolutionReceipt) throws -> Data {
    do {
        _ = try ToriiIdentifierReceiptCanonicalEncoder.canonicalPayloadBytes(for: receipt)
        try receipt.requireCurrentOwnerScope()
        return try JSONEncoder().encode(receipt)
    } catch let ToriiClientError.invalidPayload(message) {
        throw SwiftTransactionEncoderError.invalidClaimIdentifierReceipt(message)
    }
}

enum SingleInstructionSwiftNoritoEncoder {
    static func executableBatchPayload(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        nonce: UInt32?,
        entries: [TransactionBatchEntry],
        feePayment: FeePaymentIntent,
        metadata: [String: ToriiJSONValue]
    ) throws -> Data {
        guard !entries.isEmpty else {
            throw ExecutableBatchInputError.emptyBatch
        }
        let resolvedTtlMs = ttlMs ?? 100_000
        guard resolvedTtlMs != 0 else {
            throw ExecutableBatchInputError.zeroTimeToLive
        }
        guard nonce != 0 else {
            throw ExecutableBatchInputError.zeroNonce
        }
        if entries.contains(where: {
            if case .contractCall = $0 { return true }
            return false
        }), feePayment.gasLimit == nil {
            throw ExecutableBatchInputError.missingGasLimit
        }
        let ids = try TransactionInputValidator.validate(
            networkId: networkId,
            authorityId: authority
        )
        let executable = try encodeBatchExecutable(entries, expectedNetworkId: networkId)
        var networkDomain = CompactNoritoWriter()
        networkDomain.writeUInt32LE(0)
        networkDomain.writeField(ids.networkId.bytes)

        var transactionPayload = CompactNoritoWriter()
        transactionPayload.writeField(networkDomain.data)
        transactionPayload.writeField(try CanonicalNorito.encodeCompactAccountId(ids.authorityId))
        transactionPayload.writeField(CompactNorito.encodeUInt64(creationTimeMs))
        transactionPayload.writeField(executable)
        transactionPayload.writeField(
            try CompactNorito.encodeOption(resolvedTtlMs, encode: CompactNorito.encodeUInt64)
        )
        transactionPayload.writeField(
            try CompactNorito.encodeOption(nonce, encode: CompactNorito.encodeUInt32)
        )
        transactionPayload.writeField(try feePayment.compactNorito())

        transactionPayload.writeField(try CanonicalNorito.encodeCompactMetadata(metadata))
        transactionPayload.writeField(encodeNoneOption())

        return transactionPayload.data
    }

    /// Ordinary `Executable::Instructions` payload over exact dynamic instruction frames.
    static func instructionsPayload(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        frames: [TransactionInstructionFrame],
        feePayment: FeePaymentIntent
    ) throws -> Data {
        guard !frames.isEmpty else { throw ExecutableBatchInputError.emptyBatch }
        return try encodeNetworkTransactionPayload(
            networkId: networkId, authority: authority, creationTimeMs: creationTimeMs,
            ttlMs: ttlMs, feePayment: feePayment,
            instructionPayloads: try frames.map { try $0.compactInstructionBoxPayload(expectedNetworkId: networkId) }
        )
    }

    /// Versioned signed wire and entrypoint hash for an exact payload and its detached signature.
    static func signedEnvelope(transactionPayload: Data, signature: Data) -> SignedTransactionEnvelope {
        let signed = encodeCompactSignedTransaction(signature: signature, transactionPayload: transactionPayload)
        return SignedTransactionEnvelope(
            norito: encodeVersionedSignedTransaction(signed), signedTransaction: signed, payload: nil,
            transactionHash: IrohaHash.hash(encodeTransactionEntrypoint(transactionPayload))
        )
    }

    static func encodeExecutableBatch(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        nonce: UInt32?,
        entries: [TransactionBatchEntry],
        feePayment: FeePaymentIntent,
        metadata: [String: ToriiJSONValue],
        signingKey: SigningKey
    ) throws -> SignedTransactionEnvelope {
        let payload = try executableBatchPayload(
            networkId: networkId, authority: authority, creationTimeMs: creationTimeMs,
            ttlMs: ttlMs, nonce: nonce, entries: entries, feePayment: feePayment,
            metadata: metadata
        )
        let signature = try signingKey.sign(IrohaHash.hash(payload))
        let signed = encodeCompactSignedTransaction(
            signature: signature,
            transactionPayload: payload
        )
        return SignedTransactionEnvelope(
            norito: encodeVersionedSignedTransaction(signed),
            signedTransaction: signed,
            payload: nil,
            transactionHash: IrohaHash.hash(encodeTransactionEntrypoint(payload))
        )
    }

    static func encodeCommitContractDeployment(
        networkId: NetworkId, authority: String, creationTimeMs: UInt64, ttlMs: UInt64?,
        expectedDeployNonce: UInt64, contractAddress: String, codeHash: Data,
        contractAlias: String, leaseExpiryMs: UInt64?, expectedPreviousContractAddress: String?,
        feePayment: FeePaymentIntent,
        signingKey: SigningKey
    ) throws -> SignedTransactionEnvelope {
        var payload = CanonicalNoritoWriter()
        payload.writeField(CanonicalNorito.encodeUInt64(expectedDeployNonce))
        payload.writeField(CanonicalNorito.encodeString(contractAddress))
        payload.writeField(CanonicalNorito.encodeConstVec(codeHash))
        payload.writeField(CanonicalNorito.encodeString(contractAlias))
        payload.writeField(try CanonicalNorito.encodeOption(leaseExpiryMs, encode: CanonicalNorito.encodeUInt64))
        payload.writeField(try CanonicalNorito.encodeOption(expectedPreviousContractAddress, encode: CanonicalNorito.encodeString))
        let typeName = "iroha_data_model::isi::smart_contract_code::CommitContractDeployment"
        let wireId = "iroha.instruction.v1::smart_contract_code::CommitContractDeployment"
        let framed = noritoEncode(typeName: typeName, payload: payload.data, flags: 0)
        var wire = CompactNoritoWriter()
        wire.writeField(CompactNorito.encodeString(wireId))
        wire.writeField(CompactNorito.encodeBytesVec(framed))
        let transactionPayload = try encodeNetworkTransactionPayload(
            networkId: networkId, authority: authority, creationTimeMs: creationTimeMs,
            ttlMs: ttlMs, feePayment: feePayment, instructionPayload: wire.data
        )
        let signature = try signingKey.sign(IrohaHash.hash(transactionPayload))
        let signed = encodeCompactSignedTransaction(
            signature: signature,
            transactionPayload: transactionPayload
        )
        return SignedTransactionEnvelope(
            norito: encodeVersionedSignedTransaction(signed), signedTransaction: signed,
            payload: nil,
            transactionHash: IrohaHash.hash(encodeTransactionEntrypoint(transactionPayload))
        )
    }

    static func encodeAliasSetupPlan(
        request: AliasSetupPlanRequestV1,
        networkId: NetworkId,
        plan: AliasTransactionPlanV1,
        bodyEncoder: (AliasTransactionPlanBodyV1) throws -> Data,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        feePayment: FeePaymentIntent,
        signingKey: SigningKey,
        decodeAndReencode: (String, Data) throws -> DecodedEnsureAliasFrame
    ) throws -> SignedTransactionEnvelope {
        guard plan.body.networkId == networkId else {
            throw AliasSetupModelError.planValidation(["alias.plan.network_mismatch"])
        }
        let canonicalBodyNorito = try bodyEncoder(plan.body)
        guard !canonicalBodyNorito.isEmpty else {
            throw AliasSetupModelError.planValidation(["alias.plan.body_encoding_empty"])
        }
        try AliasPlanVerifier.requireExecutableForRequest(
            request,
            plan: plan,
            canonicalBodyNorito: canonicalBodyNorito,
            decodeAndReencode: decodeAndReencode
        )
        guard creationTimeMs <= plan.body.validUntilMs else {
            throw AliasSetupModelError.planValidation(["alias.plan.expired"])
        }
        let instructionPayloads = plan.body.instructions.map { instruction -> Data in
            var wire = CompactNoritoWriter()
            wire.writeField(CompactNorito.encodeString(instruction.wireId))
            wire.writeField(CompactNorito.encodeBytesVec(instruction.framedPayload))
            return wire.data
        }
        let transactionPayload = try encodeNetworkTransactionPayload(
            networkId: networkId,
            authority: plan.body.authority,
            creationTimeMs: creationTimeMs,
            ttlMs: ttlMs,
            feePayment: feePayment,
            instructionPayloads: instructionPayloads
        )
        let signature = try signingKey.sign(IrohaHash.hash(transactionPayload))
        let signedTransaction = encodeCompactSignedTransaction(
            signature: signature,
            transactionPayload: transactionPayload
        )
        return SignedTransactionEnvelope(
            norito: encodeVersionedSignedTransaction(signedTransaction),
            signedTransaction: signedTransaction,
            payload: nil,
            transactionHash: IrohaHash.hash(encodeTransactionEntrypoint(transactionPayload))
        )
    }

    static func encodeAliasLifecyclePlan(
        request: AliasLifecyclePlanRequestV1,
        networkId: NetworkId,
        plan: AliasLifecycleTransactionPlanV1,
        bodyEncoder: (AliasLifecycleTransactionPlanBodyV1) throws -> Data,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        feePayment: FeePaymentIntent,
        signingKey: SigningKey,
        decodeAndReencode: (String, Data) throws -> DecodedAliasLifecycleFrame
    ) throws -> SignedTransactionEnvelope? {
        guard plan.body.networkId == networkId else {
            throw AliasSetupModelError.planValidation(["alias.lifecycle.plan.network_mismatch"])
        }
        let canonicalBodyNorito = try bodyEncoder(plan.body)
        guard !canonicalBodyNorito.isEmpty else {
            throw AliasSetupModelError.planValidation(["alias.lifecycle.plan.body_encoding_empty"])
        }
        try AliasPlanVerifier.requireExecutableForRequest(
            request,
            plan: plan,
            canonicalBodyNorito: canonicalBodyNorito,
            decodeAndReencode: decodeAndReencode
        )
        guard creationTimeMs <= plan.body.validUntilMs else {
            throw AliasSetupModelError.planValidation(["alias.lifecycle.plan.expired"])
        }
        guard let instruction = plan.body.instruction else { return nil }
        var wire = CompactNoritoWriter()
        wire.writeField(CompactNorito.encodeString(instruction.wireId))
        wire.writeField(CompactNorito.encodeBytesVec(instruction.framedPayload))
        let transactionPayload = try encodeNetworkTransactionPayload(
            networkId: networkId,
            authority: plan.body.authority,
            creationTimeMs: creationTimeMs,
            ttlMs: ttlMs,
            feePayment: feePayment,
            instructionPayload: wire.data
        )
        let signature = try signingKey.sign(IrohaHash.hash(transactionPayload))
        let signedTransaction = encodeCompactSignedTransaction(
            signature: signature,
            transactionPayload: transactionPayload
        )
        return SignedTransactionEnvelope(
            norito: encodeVersionedSignedTransaction(signedTransaction),
            signedTransaction: signedTransaction,
            payload: nil,
            transactionHash: IrohaHash.hash(encodeTransactionEntrypoint(transactionPayload))
        )
    }

    private static func encodeNetworkTransactionPayload(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        feePayment: FeePaymentIntent,
        instructionPayload: Data

    ) throws -> Data {
        try encodeNetworkTransactionPayload(
            networkId: networkId,
            authority: authority,
            creationTimeMs: creationTimeMs,
            ttlMs: ttlMs,
            feePayment: feePayment,
            instructionPayloads: [instructionPayload],

        )
    }

    private static func encodeNetworkTransactionPayload(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        feePayment: FeePaymentIntent,
        instructionPayloads: [Data]

    ) throws -> Data {
        let resolvedTtlMs = ttlMs ?? 100_000
        guard resolvedTtlMs != 0 else {
            throw ExecutableBatchInputError.zeroTimeToLive
        }
        let ids = try TransactionInputValidator.validate(
            networkId: networkId,
            authorityId: authority
        )
        let executablePayload = encodeCompactNativeExecutable(
            instructionPayloads: instructionPayloads
        )
        var networkDomain = CompactNoritoWriter()
        networkDomain.writeUInt32LE(0)
        networkDomain.writeField(ids.networkId.bytes)

        var transactionPayload = CompactNoritoWriter()
        transactionPayload.writeField(networkDomain.data)
        transactionPayload.writeField(
            try CanonicalNorito.encodeCompactAccountId(ids.authorityId)
        )
        transactionPayload.writeField(CompactNorito.encodeUInt64(creationTimeMs))
        transactionPayload.writeField(executablePayload)
        transactionPayload.writeField(
            try CompactNorito.encodeOption(
                resolvedTtlMs,
                encode: CompactNorito.encodeUInt64
            )
        )
        transactionPayload.writeField(encodeNoneOption())
        transactionPayload.writeField(try feePayment.compactNorito())

        transactionPayload.writeField(encodeEmptyMetadata())
        transactionPayload.writeField(encodeNoneOption())
        return transactionPayload.data
    }

    private static func encodeCompactNativeExecutable(instructionPayloads: [Data]) -> Data {
        var instructions = CompactNoritoWriter()
        instructions.writeUInt64LE(UInt64(instructionPayloads.count))
        for instructionPayload in instructionPayloads {
            instructions.writeField(instructionPayload)
        }

        var executable = CompactNoritoWriter()
        executable.writeUInt32LE(0)
        executable.writeField(instructions.data)
        return executable.data
    }

    private static func encodeBatchExecutable(
        _ entries: [TransactionBatchEntry],
        expectedNetworkId: NetworkId
    ) throws -> Data {
        var sequence = CompactNoritoWriter()
        sequence.writeUInt64LE(UInt64(entries.count))
        for entry in entries {
            var item = CompactNoritoWriter()
            switch entry {
            case let .instruction(frame):
                item.writeUInt32LE(0)
                item.writeField(try frame.compactInstructionBoxPayload(expectedNetworkId: expectedNetworkId))
            case let .contractCall(invocation):
                item.writeUInt32LE(1)
                var call = CompactNoritoWriter()
                call.writeField(CompactNorito.encodeString(invocation.contractAddress))
                call.writeField(invocation.expectedCodeHash)
                call.writeField(CompactNorito.encodeString(invocation.entrypoint))
                call.writeField(
                    try CompactNorito.encodeOption(
                        invocation.arguments,
                        encode: CompactNorito.encodeBytesVec
                    )
                )
                item.writeField(call.data)
            }
            sequence.writeField(item.data)
        }

        var executable = CompactNoritoWriter()
        executable.writeUInt32LE(4)
        executable.writeField(sequence.data)
        return executable.data
    }

    private static func encodeCompactSignedTransaction(
        signature: Data,
        transactionPayload: Data
    ) -> Data {
        // `SignedTransaction.signature` contains the `TransactionSignature`
        // tuple-newtype. Its sole field wraps the transparent
        // `SignatureOf<TransactionPayload>`/`Signature` byte-vector payload.
        var transactionSignature = CompactNoritoWriter()
        transactionSignature.writeField(CompactNorito.encodeConstVec(signature))

        var signedTransaction = CompactNoritoWriter()
        signedTransaction.writeField(transactionSignature.data)
        signedTransaction.writeField(transactionPayload)
        signedTransaction.writeField(encodeNoneOption())
        return signedTransaction.data
    }

    private static func encodeTransactionEntrypoint(_ transactionPayload: Data) -> Data {
        var entrypoint = CompactNoritoWriter()
        entrypoint.writeUInt32LE(0)
        entrypoint.writeField(transactionPayload)
        return entrypoint.data
    }

    private static func encodeEmptyMetadata() -> Data {
        var metadata = CompactNoritoWriter()
        metadata.writeUInt64LE(0)
        return metadata.data
    }

    private static func encodeNoneOption() -> Data {
        Data([0])
    }
}

struct SwiftTransactionEncoder {
    static func bridgeOrThrow(_ body: () throws -> NativeSignedTransaction?) throws -> NativeSignedTransaction {
        guard NoritoNativeBridge.shared.isAvailable else {
            throw SwiftTransactionEncoderError.nativeBridgeUnavailable
        }
        do {
            if let native = try body() {
                return native
            }
            throw SwiftTransactionEncoderError.nativeBridgeUnavailable
        } catch let error as NativeBridgeError {
            throw SwiftTransactionEncoderError.nativeBridgeError(error)
        }
    }

    static func wrap(native: NativeSignedTransaction) throws -> SignedTransactionEnvelope {
        guard native.signedBytes.first == signedTransactionWireVersion else {
            throw SwiftTransactionEncoderError.invalidNativeSignedTransaction(
                "missing version byte \(signedTransactionWireVersion)"
            )
        }
        let signedTransaction = Data(native.signedBytes.dropFirst())
        guard !signedTransaction.isEmpty else {
            throw SwiftTransactionEncoderError.invalidNativeSignedTransaction("empty signed transaction payload")
        }
        return SignedTransactionEnvelope(norito: native.signedBytes,
                                         signedTransaction: signedTransaction,
                                         payload: nil,
                                         transactionHash: native.hash)
    }

    static func encodeTransfer(transfer: TransferRequest,
                               keypair: Keypair,
                               creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let signingKey = try SigningKey.ed25519(privateKey: keypair.privateKeyBytes)
        return try encodeTransfer(transfer: transfer, signingKey: signingKey, creationTimeMs: creationTimeMs)
    }

    static func encodeTransfer(transfer: TransferRequest,
                               signingKey: SigningKey,
                               creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        // TODO: encode the memo once the native transfer encoder accepts one;
        // until then reject it rather than signing a transaction without it.
        if let description = transfer.description, !description.isEmpty {
            throw TransactionInputError.transferDescriptionUnsupported
        }
        let ids = try TransactionInputValidator.validate(networkId: transfer.networkId,
                                                         authorityId: transfer.authority,
                                                         assetDefinitionId: transfer.assetDefinitionId,
                                                         accountIds: [.init(field: "destination", value: transfer.destination)])
        guard let assetDefinitionId = ids.assetDefinitionId else {
            throw TransactionInputError.emptyAssetDefinitionId
        }
        let destination = ids.accountIds["destination"] ?? transfer.destination
        let quantity = try KotodamaNumericV1Codec.decodeQuantityJSON(transfer.quantity).canonicalString
        let feePaymentJSON = try transfer.feePayment.canonicalJSONData()
        let privateKey = try privateKeyBytes(from: signingKey)
        let native = try bridgeOrThrow {
            try NoritoNativeBridge.shared.encodeTransfer(networkId: ids.networkId,
                                                         authority: ids.authorityId,
                                                         creationTimeMs: creationTimeMs,
                                                         ttlMs: transfer.ttlMs,
                                                         nonce: transfer.nonce,
                                                         assetDefinitionId: assetDefinitionId,
                                                         quantity: quantity,
                                                         destination: destination,
                                                         feePaymentJSON: feePaymentJSON,
                                                         privateKey: privateKey,
                                                         algorithm: signingKey.algorithm)
        }
        return try wrap(native: native)
    }

    static func encodeMint(request: MintRequest,
                            keypair: Keypair,
                            creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let signingKey = try SigningKey.ed25519(privateKey: keypair.privateKeyBytes)
        return try encodeMint(request: request, signingKey: signingKey, creationTimeMs: creationTimeMs)
    }

    static func encodeMint(request: MintRequest,
                            signingKey: SigningKey,
                            creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let ids = try TransactionInputValidator.validate(networkId: request.networkId,
                                                         authorityId: request.authority,
                                                         assetDefinitionId: request.assetDefinitionId,
                                                         accountIds: [.init(field: "destination", value: request.destination)])
        guard let assetDefinitionId = ids.assetDefinitionId else {
            throw TransactionInputError.emptyAssetDefinitionId
        }
        let destination = ids.accountIds["destination"] ?? request.destination
        let quantity = try KotodamaNumericV1Codec.decodeQuantityJSON(request.quantity).canonicalString
        let privateKey = try privateKeyBytes(from: signingKey)
        let native = try bridgeOrThrow {
            try NoritoNativeBridge.shared.encodeMint(networkId: ids.networkId,
                                                     authority: ids.authorityId,
                                                     creationTimeMs: creationTimeMs,
                                                     ttlMs: request.ttlMs,
                                                     nonce: request.nonce,
                                                     assetDefinitionId: assetDefinitionId,
                                                     quantity: quantity,
                                                     destination: destination,
                                                     feePaymentJSON: try request.feePayment.canonicalJSONData(),
                                                     privateKey: privateKey,
                                                     algorithm: signingKey.algorithm)
        }
        return try wrap(native: native)
    }

    static func encodeBurn(request: BurnRequest,
                            keypair: Keypair,
                            creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let signingKey = try SigningKey.ed25519(privateKey: keypair.privateKeyBytes)
        return try encodeBurn(request: request, signingKey: signingKey, creationTimeMs: creationTimeMs)
    }

    static func encodeBurn(request: BurnRequest,
                            signingKey: SigningKey,
                            creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let ids = try TransactionInputValidator.validate(networkId: request.networkId,
                                                         authorityId: request.authority,
                                                         assetDefinitionId: request.assetDefinitionId,
                                                         accountIds: [.init(field: "destination", value: request.destination)])
        guard let assetDefinitionId = ids.assetDefinitionId else {
            throw TransactionInputError.emptyAssetDefinitionId
        }
        let destination = ids.accountIds["destination"] ?? request.destination
        let quantity = try KotodamaNumericV1Codec.decodeQuantityJSON(request.quantity).canonicalString
        let privateKey = try privateKeyBytes(from: signingKey)
        let native = try bridgeOrThrow {
            try NoritoNativeBridge.shared.encodeBurn(networkId: ids.networkId,
                                                     authority: ids.authorityId,
                                                     creationTimeMs: creationTimeMs,
                                                     ttlMs: request.ttlMs,
                                                     nonce: request.nonce,
                                                     assetDefinitionId: assetDefinitionId,
                                                     quantity: quantity,
                                                     destination: destination,
                                                     feePaymentJSON: try request.feePayment.canonicalJSONData(),
                                                     privateKey: privateKey,
                                                     algorithm: signingKey.algorithm)
        }
        return try wrap(native: native)
    }

    static func encodeRegisterZkAsset(request: RegisterZkAssetRequest,
                                      keypair: Keypair,
                                      creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let signingKey = try SigningKey.ed25519(privateKey: keypair.privateKeyBytes)
        return try encodeRegisterZkAsset(request: request,
                                         signingKey: signingKey,
                                         creationTimeMs: creationTimeMs)
    }

    static func encodeRegisterZkAsset(request: RegisterZkAssetRequest,
                                      signingKey: SigningKey,
                                      creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let ids = try TransactionInputValidator.validate(networkId: request.networkId,
                                                         authorityId: request.authority,
                                                         assetDefinitionId: request.assetDefinitionId)
        guard let assetDefinitionId = ids.assetDefinitionId else {
            throw TransactionInputError.emptyAssetDefinitionId
        }
        let privateKey = try privateKeyBytes(from: signingKey)
        let unshieldVk = request.unshieldVerifyingKey?.encodedValue
        let native = try bridgeOrThrow {
            try NoritoNativeBridge.shared.encodeRegisterZkAsset(
                networkId: ids.networkId,
                authority: ids.authorityId,
                creationTimeMs: creationTimeMs,
                ttlMs: request.ttlMs,
                assetDefinitionId: assetDefinitionId,
                unshieldVerifyingKey: unshieldVk,
                feePaymentJSON: try request.feePayment.canonicalJSONData(),
                privateKey: privateKey,
                algorithm: signingKey.algorithm
            )
        }
        return try wrap(native: native)
    }

    static func encodeMultisigRegister(request: MultisigRegisterRequest,
                                       keypair: Keypair,
                                       creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let signingKey = try SigningKey.ed25519(privateKey: keypair.privateKeyBytes)
        return try encodeMultisigRegister(request: request,
                                          signingKey: signingKey,
                                          creationTimeMs: creationTimeMs)
    }

    static func encodeMultisigRegister(request: MultisigRegisterRequest,
                                       signingKey: SigningKey,
                                       creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let ids = try TransactionInputValidator.validate(networkId: request.networkId,
                                                         authorityId: request.authority,
                                                         accountIds: [
                                                            TransactionInputValidator.NamedAccountId(field: "account", value: request.accountId)
                                                         ])
        let privateKey = try privateKeyBytes(from: signingKey)
        let specJSON = try request.spec.encodeJSON()
        let native = try bridgeOrThrow {
            try NoritoNativeBridge.shared.encodeMultisigRegister(networkId: ids.networkId,
                                                                 authority: ids.authorityId,
                                                                 creationTimeMs: creationTimeMs,
                                                                 ttlMs: request.ttlMs,
                                                                 accountId: ids.accountIds["account"] ?? request.accountId,
                                                                 specJSON: specJSON,
                                                                 feePaymentJSON: try request.feePayment.canonicalJSONData(),
                                                                 privateKey: privateKey,
                                                                 algorithm: signingKey.algorithm)
        }
        return try wrap(native: native)
    }

    static func encodeClaimIdentifier(request: ClaimIdentifierRequest,
                                      keypair: Keypair,
                                      creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let signingKey = try SigningKey.ed25519(privateKey: keypair.privateKeyBytes)
        return try encodeClaimIdentifier(request: request,
                                         signingKey: signingKey,
                                         creationTimeMs: creationTimeMs)
    }

    static func encodeClaimIdentifier(request: ClaimIdentifierRequest,
                                      signingKey: SigningKey,
                                      creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        guard request.networkId == request.receipt.payload.networkId else {
            throw SwiftTransactionEncoderError.invalidClaimIdentifierReceipt("Receipt network must equal the independently selected transaction network.")
        }
        let receiptAccountId = request.receipt.payload.accountId
        let ids = try TransactionInputValidator.validate(networkId: request.networkId,
                                                         authorityId: request.authority,
                                                         accountIds: [
                                                            TransactionInputValidator.NamedAccountId(field: "account", value: request.accountId),
                                                            TransactionInputValidator.NamedAccountId(field: "receipt_account", value: receiptAccountId)
                                                         ])
        let canonicalAccountId = ids.accountIds["account"] ?? request.accountId
        guard canonicalAccountId == ids.accountIds["receipt_account"] else {
            throw SwiftTransactionEncoderError.invalidClaimIdentifierReceipt(
                "accountId must match receipt.payload.account_id."
            )
        }

        let privateKey = try privateKeyBytes(from: signingKey)
        let receiptJSON = try encodeNativeClaimIdentifierReceiptJSON(request.receipt)
        let native = try bridgeOrThrow {
            try NoritoNativeBridge.shared.encodeClaimIdentifier(
                networkId: ids.networkId,
                authority: ids.authorityId,
                creationTimeMs: creationTimeMs,
                ttlMs: request.ttlMs,
                accountId: canonicalAccountId,
                receiptJSON: receiptJSON,
                feePaymentJSON: try request.feePayment.canonicalJSONData(),
                privateKey: privateKey,
                algorithm: signingKey.algorithm
            )
        }
        return try wrap(native: native)
    }

    static func encodeCommitContractDeployment(
        request: CommitContractDeploymentRequest,
        signingKey: SigningKey,
        creationTimeMs: UInt64
    ) throws -> SignedTransactionEnvelope {
        let ids = try TransactionInputValidator.validate(
            networkId: request.networkId, authorityId: request.authority
        )
        guard request.contractAddress == request.contractAddress.trimmingCharacters(in: .whitespacesAndNewlines),
              !request.contractAddress.isEmpty,
              request.contractAlias == request.contractAlias.trimmingCharacters(in: .whitespacesAndNewlines),
              !request.contractAlias.isEmpty else {
            throw SwiftTransactionEncoderError.invalidInput("contract address and alias must be exact non-empty strings")
        }
        guard request.codeHashHex.count == 64,
              let codeHash = Data(hexString: request.codeHashHex) else {
            throw SwiftTransactionEncoderError.invalidInput("codeHashHex must contain exactly 64 hexadecimal characters")
        }
        return try SingleInstructionSwiftNoritoEncoder.encodeCommitContractDeployment(
            networkId: ids.networkId, authority: ids.authorityId, creationTimeMs: creationTimeMs,
            ttlMs: request.ttlMs, expectedDeployNonce: request.expectedDeployNonce,
            contractAddress: request.contractAddress, codeHash: codeHash,
            contractAlias: request.contractAlias, leaseExpiryMs: request.leaseExpiryMs,
            expectedPreviousContractAddress: request.expectedPreviousContractAddress,
            feePayment: request.feePayment,
            signingKey: signingKey
        )
    }

    static func encodeSetMetadata(request: SetMetadataRequest,
                                  keypair: Keypair,
                                  creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let signingKey = try SigningKey.ed25519(privateKey: keypair.privateKeyBytes)
        return try encodeSetMetadata(request: request, signingKey: signingKey, creationTimeMs: creationTimeMs)
    }

    static func encodeSetMetadata(request: SetMetadataRequest,
                                  signingKey: SigningKey,
                                  creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let ids = try TransactionInputValidator.validate(networkId: request.networkId,
                                                         authorityId: request.authority)
        let target = try TransactionInputValidator.sanitizeMetadataTarget(request.target)
        let privateKey = try privateKeyBytes(from: signingKey)
        let native = try bridgeOrThrow {
            try NoritoNativeBridge.shared.encodeSetKeyValue(
                networkId: ids.networkId,
                authority: ids.authorityId,
                creationTimeMs: creationTimeMs,
                ttlMs: request.ttlMs,
                targetKind: target.targetKind,
                objectId: target.objectId,
                key: request.key,
                valueJson: request.value.data,
                feePaymentJSON: try request.feePayment.canonicalJSONData(),
                privateKey: privateKey,
                algorithm: signingKey.algorithm
            )
        }
        return try wrap(native: native)
    }

    static func encodeRemoveMetadata(request: RemoveMetadataRequest,
                                     keypair: Keypair,
                                     creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let signingKey = try SigningKey.ed25519(privateKey: keypair.privateKeyBytes)
        return try encodeRemoveMetadata(request: request, signingKey: signingKey, creationTimeMs: creationTimeMs)
    }

    static func encodeRemoveMetadata(request: RemoveMetadataRequest,
                                     signingKey: SigningKey,
                                     creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let ids = try TransactionInputValidator.validate(networkId: request.networkId,
                                                         authorityId: request.authority)
        let target = try TransactionInputValidator.sanitizeMetadataTarget(request.target)
        let privateKey = try privateKeyBytes(from: signingKey)
        let native = try bridgeOrThrow {
            try NoritoNativeBridge.shared.encodeRemoveKeyValue(
                networkId: ids.networkId,
                authority: ids.authorityId,
                creationTimeMs: creationTimeMs,
                ttlMs: request.ttlMs,
                targetKind: target.targetKind,
                objectId: target.objectId,
                key: request.key,
                feePaymentJSON: try request.feePayment.canonicalJSONData(),
                privateKey: privateKey,
                algorithm: signingKey.algorithm
            )
        }
        return try wrap(native: native)
    }

    static func encodeProposeDeploy(request: ProposeDeployContractRequest,
                                    keypair: Keypair,
                                    creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let signingKey = try SigningKey.ed25519(privateKey: keypair.privateKeyBytes)
        return try encodeProposeDeploy(request: request, signingKey: signingKey, creationTimeMs: creationTimeMs)
    }

    static func encodeProposeDeploy(request: ProposeDeployContractRequest,
                                    signingKey: SigningKey,
                                    creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let ids = try TransactionInputValidator.validate(networkId: request.networkId,
                                                         authorityId: request.authority)
        let privateKey = try privateKeyBytes(from: signingKey)
        let native = try bridgeOrThrow {
            try NoritoNativeBridge.shared.encodeGovernanceProposeDeploy(
                networkId: ids.networkId,
                authority: ids.authorityId,
                creationTimeMs: creationTimeMs,
                ttlMs: request.ttlMs,
                contractAddress: request.contractAddress,
                codeHash: request.codeHash,
                abiHash: request.abiHash,
                abiVersion: request.abiVersion,
                manifestProvenance: request.manifestProvenance,
                feePaymentJSON: try request.feePayment.canonicalJSONData(),
                privateKey: privateKey,
                algorithm: signingKey.algorithm
            )
        }
        return try wrap(native: native)
    }

    static func encodeCastPlainBallot(request: CastPlainBallotRequest,
                                      keypair: Keypair,
                                      creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let signingKey = try SigningKey.ed25519(privateKey: keypair.privateKeyBytes)
        return try encodeCastPlainBallot(request: request, signingKey: signingKey, creationTimeMs: creationTimeMs)
    }

    static func encodeCastPlainBallot(request: CastPlainBallotRequest,
                                      signingKey: SigningKey,
                                      creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let ids = try TransactionInputValidator.validate(
            networkId: request.networkId,
            authorityId: request.authority,
            accountIds: [.init(field: "owner", value: request.owner)]
        )
        let owner = ids.accountIds["owner"] ?? request.owner
        let referendumId = try TransactionInputValidator.sanitizeGovernanceSelector(
            request.referendumId,
            field: "referendum_id"
        )
        let amount = try KotodamaNumericV1Codec
            .decodeQuantityJSON(request.amount)
            .canonicalString
        let privateKey = try privateKeyBytes(from: signingKey)
        let native = try bridgeOrThrow {
            try NoritoNativeBridge.shared.encodeGovernanceCastPlainBallot(
                networkId: ids.networkId,
                authority: ids.authorityId,
                creationTimeMs: creationTimeMs,
                ttlMs: request.ttlMs,
                referendumId: referendumId,
                owner: owner,
                amount: amount,
                durationBlocks: request.durationBlocks,
                direction: request.direction.rawValue,
                feePaymentJSON: try request.feePayment.canonicalJSONData(),
                privateKey: privateKey,
                algorithm: signingKey.algorithm
            )
        }
        return try wrap(native: native)
    }

    static func encodeUpdatePlainConviction(request: UpdatePlainConvictionRequest,
                                            keypair: Keypair,
                                            creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let signingKey = try SigningKey.ed25519(privateKey: keypair.privateKeyBytes)
        return try encodeUpdatePlainConviction(request: request, signingKey: signingKey, creationTimeMs: creationTimeMs)
    }

    static func encodeUpdatePlainConviction(request: UpdatePlainConvictionRequest,
                                            signingKey: SigningKey,
                                            creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let ids = try TransactionInputValidator.validate(
            networkId: request.networkId,
            authorityId: request.authority,
            accountIds: [.init(field: "owner", value: request.owner)]
        )
        let owner = ids.accountIds["owner"] ?? request.owner
        guard owner == ids.authorityId else {
            throw TransactionInputError.governanceOwnerMustEqualAuthority
        }
        let referendumId = try TransactionInputValidator.sanitizeGovernanceSelector(
            request.referendumId,
            field: "referendum_id"
        )
        let amount = try KotodamaNumericV1Codec
            .decodeQuantityJSON(request.amount)
            .canonicalString
        let privateKey = try privateKeyBytes(from: signingKey)
        let native = try bridgeOrThrow {
            try NoritoNativeBridge.shared.encodeGovernanceUpdatePlainConviction(
                networkId: ids.networkId,
                authority: ids.authorityId,
                creationTimeMs: creationTimeMs,
                ttlMs: request.ttlMs,
                referendumId: referendumId,
                owner: owner,
                amount: amount,
                durationBlocks: request.durationBlocks,
                feePaymentJSON: try request.feePayment.canonicalJSONData(),
                privateKey: privateKey,
                algorithm: signingKey.algorithm
            )
        }
        return try wrap(native: native)
    }

    static func encodeCastZkBallot(request: CastZkBallotRequest,
                                   keypair: Keypair,
                                   creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let signingKey = try SigningKey.ed25519(privateKey: keypair.privateKeyBytes)
        return try encodeCastZkBallot(request: request, signingKey: signingKey, creationTimeMs: creationTimeMs)
    }

    static func encodeCastZkBallot(request: CastZkBallotRequest,
                                   signingKey: SigningKey,
                                   creationTimeMs: UInt64) throws -> SignedTransactionEnvelope {
        let ids = try TransactionInputValidator.validate(networkId: request.networkId,
                                                         authorityId: request.authority)
        let electionId = try TransactionInputValidator.sanitizeGovernanceSelector(
            request.electionId,
            field: "election_id"
        )
        let privateKey = try privateKeyBytes(from: signingKey)
        let publicInputs = try normalizeZkBallotPublicInputs(request.publicInputs)
        let native = try bridgeOrThrow {
            try NoritoNativeBridge.shared.encodeGovernanceCastZkBallot(
                networkId: ids.networkId,
                authority: ids.authorityId,
                creationTimeMs: creationTimeMs,
                ttlMs: request.ttlMs,
                electionId: electionId,
                proofB64: request.proofB64,
                publicInputs: publicInputs,
                feePaymentJSON: try request.feePayment.canonicalJSONData(),
                privateKey: privateKey,
                algorithm: signingKey.algorithm
            )
        }
        return try wrap(native: native)
    }

    static func normalizeZkBallotPublicInputs(
        _ inputs: GovernanceZkBallotPublicInputs
    ) throws -> Data {
        let encoder = JSONEncoder()
        if #available(iOS 11.0, macOS 10.13, *) {
            encoder.outputFormatting.insert(.sortedKeys)
        }
        let encoded: Data
        do {
            encoded = try encoder.encode(inputs)
        } catch let ToriiClientError.invalidPayload(reason) {
            throw TransactionInputError.invalidZkBallotPublicInputs(reason)
        } catch {
            throw TransactionInputError.invalidZkBallotPublicInputs(
                "public inputs could not be encoded canonically"
            )
        }
        try rejectGovernancePrivateKeyAliases(inJSONData: encoded)
        return encoded
    }

    private static let governancePrivateKeyAliases: Set<String> = [
        "private_key", "privateKey", "private_key_hex", "privateKeyHex",
        "private_key_bytes", "privateKeyBytes", "private_key_seed", "privateKeySeed",
        "private_key_multihash", "privateKeyMultihash", "private_key_algorithm",
        "privateKeyAlgorithm",
    ]

    static func rejectGovernancePrivateKeyAliases(inJSONData data: Data) throws {
        let value: Any
        do {
            value = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw TransactionInputError.invalidZkBallotPublicInputs(
                "public inputs must be valid JSON"
            )
        }
        try rejectGovernancePrivateKeyAliases(in: value, path: "public_inputs")
    }

    private static func rejectGovernancePrivateKeyAliases(in value: Any,
                                                           path: String) throws {
        if let object = value as? [String: Any] {
            for key in object.keys.sorted() {
                if governancePrivateKeyAliases.contains(key) {
                    throw TransactionInputError.invalidZkBallotPublicInputs(
                        "\(path) does not accept private-key field \(key)"
                    )
                }
                if let nested = object[key] {
                    try rejectGovernancePrivateKeyAliases(
                        in: nested,
                        path: "\(path).\(key)"
                    )
                }
            }
        } else if let array = value as? [Any] {
            for (index, nested) in array.enumerated() {
                try rejectGovernancePrivateKeyAliases(
                    in: nested,
                    path: "\(path)[\(index)]"
                )
            }
        }
    }

    static func privateKeyBytes(from signingKey: SigningKey) throws -> Data {
        if signingKey.algorithm != .ed25519 {
            guard NoritoNativeBridge.shared.supportsTransactions(using: signingKey.algorithm) else {
                throw SwiftTransactionEncoderError.unsupportedSigningAlgorithm(signingKey.algorithm)
            }
        }
        if let privateKey = signingKey.exportPrivateKeyBytes() {
            return privateKey
        }
        throw SwiftTransactionEncoderError.unsupportedSigningAlgorithm(signingKey.algorithm)
    }
}
