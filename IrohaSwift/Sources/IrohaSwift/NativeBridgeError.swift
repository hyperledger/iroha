enum NativeBridgeError: Error, Equatable {
    case nullPointer
    case utf8
    case networkId
    case authority
    case assetDefinition
    case destination
    case quantity
    case invalidTtl
    case invalidNonce
    case privateKey
    case alloc
    case hashOutBuffer
    case invalidNoteCommitment
    case confidentialPayload
    case proofAttachment
    case invalidNullifiers
    case invalidRootHint
    case unsupportedAlgorithm
    case metadataTarget
    case metadataKey
    case metadataValue
    case governance
    case hex
    case accountList
    case feePayment
    case multisigSpec
    case identifierReceipt
    case accountOnboardingBody
    case aliasInstruction
    case verifyingKeyId
    case secpParse
    case secpSign
    case secpVerify
    case invalidPrivacyRequest
    case invalidPrivacyOutput
    case bridgeUnavailable
    case detachedTransactionScaffold
    case detachedTransactionSignature
    case canonicalJSON
    case invalidDetachedTransactionOutput
    case parliamentTimedOvnWallet
    case unknown(Int32)

    static func fromStatus(_ status: Int32) -> NativeBridgeError? {
        if status == 0 { return nil }
        switch status {
        case -1: return .nullPointer
        case -2: return .utf8
        case -3: return .networkId
        case -4: return .authority
        case -5: return .assetDefinition
        case -6: return .destination
        case -7: return .quantity
        case -8: return .invalidTtl
        case -31: return .invalidNonce
        case -9: return .privateKey
        case -10: return .alloc
        case -11: return .hashOutBuffer
        case -14: return .invalidNoteCommitment
        case -15: return .confidentialPayload
        case -18: return .proofAttachment
        case -19: return .invalidNullifiers
        case -20: return .invalidRootHint
        case -21: return .unsupportedAlgorithm
        case -22: return .secpParse
        case -23: return .secpSign
        case -24: return .secpVerify
        case -25: return .metadataTarget
        case -26: return .metadataKey
        case -27: return .metadataValue
        case -28: return .governance
        case -29: return .hex
        case -30: return .accountList
        case -34: return .feePayment
        case -402: return .multisigSpec
        case -406: return .identifierReceipt
        case -408: return .accountOnboardingBody
        case -409: return .aliasInstruction
        case -403: return .verifyingKeyId
        case -501: return .detachedTransactionScaffold
        case -502: return .detachedTransactionSignature
        case -503: return .canonicalJSON
        case -505: return .parliamentTimedOvnWallet
        default: return .unknown(status)
        }
    }
}
