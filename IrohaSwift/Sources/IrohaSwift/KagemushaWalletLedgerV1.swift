import Foundation

/// Closed original Native transports accepted by the current ledger instruction.
public enum KagemushaWalletLedgerTransportV1: UInt64, Sendable {
    case activate = 1, unload = 2, closeLoads = 3
}

/// BLS-certified native consensus identity of an attempt's inclusion block. It is not the Iroha
/// block-header hash, which a compact certificate does not authenticate.
public struct KagemushaWalletLedgerCommitV1: Equatable, Sendable {
    public let height: UInt64
    public let commitHash: Data
}

/// Native-retained outcome of one exact signed Activate or Unload attempt.
public enum KagemushaWalletLedgerOutcomeV1: Equatable, Sendable {
    /// No authenticated outcome is retained. `entrypoint` is the hash Native derived from the
    /// retained signed wire; it only selects the attempt's finality route.
    case awaiting(entrypoint: Data)
    /// Certified rejected execution of this attempt only. It never changes offline value or
    /// the retained claim; a new attempt over the same original may still succeed.
    case rejected(KagemushaWalletLedgerCommitV1)
    /// Certified successful execution. For Activate this is the wallet's activation; it does
    /// not assert that every other attempt executed successfully.
    case confirmed(KagemushaWalletLedgerCommitV1)

    init(_ result: KagemushaWalletCallV1) throws {
        switch result.status {
        case 46:
            guard result.bytes.count == 32 else { throw KagemushaWalletErrorV1.invalidNativeOutput }
            self = .awaiting(entrypoint: result.bytes)
        case 61, 62:
            let commit = KagemushaWalletLedgerCommitV1(
                height: result.sequenceLow, commitHash: result.bytes)
            self = result.status == 62 ? .confirmed(commit) : .rejected(commit)
        default:
            throw KagemushaWalletErrorV1.invalidNativeOutput
        }
    }
}

/// Result of offering one ledger finality original to Native.
public enum KagemushaWalletLedgerIngestV1: Equatable, Sendable {
    /// The attempt's authenticated outcome after this original.
    case outcome(KagemushaWalletLedgerOutcomeV1)
    /// The original names an epoch the wallet has not selected. This is DATA: nothing was
    /// verified or written. Synchronize boundaries until they cover `targetHeight`, then offer
    /// the same original again.
    case epochRequired(targetHeight: UInt64)

    init(_ result: KagemushaWalletCallV1) throws {
        if result.status == 60 {
            self = .epochRequired(targetHeight: result.sequenceLow)
            return
        }
        let outcome = try KagemushaWalletLedgerOutcomeV1(result)
        // An offered original either decides the attempt or names a missing epoch.
        if case .awaiting = outcome { throw KagemushaWalletErrorV1.invalidNativeOutput }
        self = .outcome(outcome)
    }
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

    /// Retain this exact same-Activation outer attempt before its first dispatch.
    /// Intake alone establishes neither ledger inclusion nor permission to Load.
    public func retainActivationAttempt(signedWire: Data) throws -> KagemushaWalletLedgerOutcomeV1 {
        try .init(setup(.init(selector: 46, first: signedWire)))
    }

    /// Read this retained attempt's outcome: the wallet's activation, this attempt's
    /// authenticated rejection, or Awaiting with Native's route selector. Reads never verify.
    public func activationAttemptOutcome(signedWire: Data) throws -> KagemushaWalletLedgerOutcomeV1 {
        try .init(setup(.init(selector: 37, first: signedWire)))
    }

    /// Verify one direct ledger finality original for this retained Activate attempt.
    public func ingestActivationFinality(signedWire: Data, finality: Data) throws -> KagemushaWalletLedgerIngestV1 {
        try .init(setup(.init(selector: 36, first: signedWire, second: finality)))
    }

    /// Read the outcome of this exact signed Unload envelope over this exact claim.
    /// Only `confirmed` establishes the payout; `rejected` closes this envelope only.
    public func unloadAttemptOutcome(claim: Data, signedWire: Data) throws -> KagemushaWalletLedgerOutcomeV1 {
        try .init(setup(.init(selector: 33, first: claim, second: signedWire)))
    }

    /// Verify one direct ledger finality original for this exact signed Unload envelope.
    public func ingestUnloadFinality(claim: Data, signedWire: Data, finality: Data) throws -> KagemushaWalletLedgerIngestV1 {
        try .init(setup(.init(selector: 34, first: claim, second: signedWire, third: finality)))
    }
}
