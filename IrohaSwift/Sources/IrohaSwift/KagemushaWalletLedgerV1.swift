import Foundation

/// Closed original Native transports accepted by the current ledger instruction.
public enum KagemushaWalletLedgerTransportV1: UInt64, Sendable {
    case activate = 1, unload = 2, closeLoads = 3
}

extension KagemushaWalletV1 {
    /// Freeze an exact next Load instruction under durable Native request custody.
    /// Retry the same request ID and amount after uncertain delivery.
    public func prepareLedgerLoad(requestId: Data, amount: KagemushaWalletUInt128V1) throws -> Data {
        let result = try setup(.init(selector: 27, identity: requestId, amount: amount))
        guard result.status == 40 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
        return result.bytes
    }

    /// Canonical instruction framing only; ledger execution still validates every authority.
    public func ledgerInstruction(kind: KagemushaWalletLedgerTransportV1, original: Data) throws -> Data {
        let result = try setup(.init(selector: 29, token: kind.rawValue, first: original))
        guard result.status == 40 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
        return result.bytes
    }
    /// Read the exact retained confirmation or history for this transaction and claim.
    /// Absent inclusion is explicit; malformed or mismatched custody remains an error.
    public func unloadFinalityProgress(transactionHash: Data, original: Data) throws -> KagemushaWalletUnloadFinalityV1 {
        try .init(setup(.init(selector: 33, identity: transactionHash, first: original)))
    }
    /// Verify one next original block for this Unload's own durable history cursor.
    public func ingestUnloadFinality(transactionHash: Data, original: Data, finality: Data) throws -> KagemushaWalletLedgerProgressV1 {
        try .init(setup(.init(selector: 34, identity: transactionHash, first: original, second: finality)))
    }

    /// Retain this exact same-Activation outer attempt before its first dispatch.
    /// Intake alone establishes neither ledger inclusion nor permission to Load.
    public func retainActivationAttempt(signedWire: Data) throws -> KagemushaWalletActivationFinalityV1 {
        try .init(setup(.init(selector: 46, first: signedWire)))
    }

    /// Recover wallet activation through successful inclusion of any retained attempt.
    /// Confirmation does not assert that every outer transaction executed successfully.
    public func confirmLedgerActivation(signedWire: Data) throws -> KagemushaWalletActivationConfirmationV1 {
        try .init(setup(.init(selector: 35, first: signedWire)))
    }

    /// Verify one next original block for this registered attempt's independent Native history.
    public func ingestActivationFinality(signedWire: Data, original: Data) throws -> KagemushaWalletActivationFinalityV1 {
        try .init(setup(.init(selector: 36, first: signedWire, second: original)))
    }

    /// Read this registered attempt's progress or the wallet's common activation confirmation.
    public func activationFinalityProgress(signedWire: Data) throws -> KagemushaWalletActivationFinalityV1 {
        try .init(setup(.init(selector: 37, first: signedWire)))
    }

    /// Confirm exact successful input/output inclusion of this original Unload in its own Native-selected block.
    public func confirmLedgerUnload(transactionHash: Data, original: Data) throws -> KagemushaWalletUnloadConfirmationV1 {
        let result = try setup(.init(selector: 30, identity: transactionHash, first: original))
        guard result.status == 42 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
        return .init(height: result.sequenceLow, blockHash: result.bytes)
    }

}


/// Native-verified successful execution of the exact submitted Unload claim.
public struct KagemushaWalletUnloadConfirmationV1: Sendable {
    public let height: UInt64
    public let blockHash: Data
}

/// Native-owned Unload history. Only a confirmation establishes successful settlement.
public struct KagemushaWalletUnloadFinalityV1: Sendable {
    public let confirmation: KagemushaWalletUnloadConfirmationV1?
    public let verifiedHeight: UInt64?
    public let blockHash: Data?
    init(_ result: KagemushaWalletCallV1) throws {
        switch result.status {
        case 42:
            confirmation = .init(height: result.sequenceLow, blockHash: result.bytes)
            verifiedHeight = result.sequenceLow
            blockHash = result.bytes
        case 33:
            confirmation = nil
            verifiedHeight = result.sequenceLow
            blockHash = result.bytes
        case 34:
            confirmation = nil
            verifiedHeight = nil
            blockHash = nil
        default:
            throw KagemushaWalletErrorV1.invalidNativeOutput
        }
    }
}

/// Native-verified wallet activation through one exact retained signed Activate attempt.
public struct KagemushaWalletActivationConfirmationV1: Sendable {
    public let height: UInt64
    public let blockHash: Data
    init(_ result: KagemushaWalletCallV1) throws {
        guard result.status == 44 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
        height = result.sequenceLow
        blockHash = result.bytes
    }
}

/// Native-owned Activate history. Only a confirmation establishes activation.
public struct KagemushaWalletActivationFinalityV1: Sendable {
    public let confirmation: KagemushaWalletActivationConfirmationV1?
    /// Exact authenticated rejected execution of this attempt; it never establishes activation.
    public let rejected: Bool
    public let verifiedHeight: UInt64?
    public let blockHash: Data?
    init(_ result: KagemushaWalletCallV1) throws {
        switch result.status {
        case 44:
            confirmation = try .init(result)
            rejected = false
            verifiedHeight = result.sequenceLow
            blockHash = result.bytes
        case 45, 49:
            confirmation = nil
            rejected = result.status == 49
            verifiedHeight = result.sequenceLow
            blockHash = result.bytes
        case 46:
            confirmation = nil
            rejected = false
            verifiedHeight = nil
            blockHash = nil
        default:
            throw KagemushaWalletErrorV1.invalidNativeOutput
        }
    }
}
