import Foundation

/// One retained attempt to confirm. Native derives its route selector from these exact bytes.
public enum KagemushaWalletLedgerAttemptV1: Sendable {
    case activation(signedWire: Data)
    case unload(claim: Data, signedWire: Data)
}

/// Native outcome after one confirmation pass.
public struct KagemushaWalletLedgerConfirmationV1: Equatable, Sendable {
    public let outcome: KagemushaWalletLedgerOutcomeV1
    /// True only when this pass retained a new authenticated outcome or selected at least one
    /// epoch boundary. Polls and unchanged outcomes report false.
    public let advanced: Bool
}

private struct KagemushaWalletLedgerWaitV1: Error {}

extension KagemushaWalletV1 {
    /// Confirm one retained Activate or Unload attempt with at most one finality read.
    ///
    /// A retained outcome returns without network. Otherwise one account-signed GET reads the
    /// attempt's direct original by the entrypoint Native derived, and a typed wait returns
    /// `awaiting`. An unselected epoch synchronizes at most `maximumBoundaries` boundaries
    /// through the attempt's epoch route, then offers the same in-memory original once more.
    /// The SDK persists no bytes, signs nothing, and never infers non-inclusion or rejection
    /// from a status, expiry or absence.
    public func confirmLedgerAttempt(
        _ attempt: KagemushaWalletLedgerAttemptV1,
        schemeID: Data, walletID: Data,
        transport: ToriiClient,
        canonicalAuth: ToriiCanonicalRequestAuth,
        maximumBoundaries: Int = 64,
        requireCurrentOwner: @escaping @Sendable () async throws -> Void
    ) async throws -> KagemushaWalletLedgerConfirmationV1 {
        try await kagemushaWalletConfirmLedgerAttemptV1(
            requireCurrentOwner: requireCurrentOwner,
            outcome: { try self.ledgerAttemptOutcome(attempt) },
            fetch: { entrypoint in
                try await transport.getKagemushaWalletLedgerAttemptFinalityV1(
                    selection: .init(schemeID: schemeID, walletID: walletID, entrypointHash: entrypoint),
                    canonicalAuth: canonicalAuth, requireCurrentOwner: requireCurrentOwner)
            },
            ingest: { finality in try self.ingestLedgerAttempt(attempt, finality: finality) },
            synchronize: { entrypoint, targetHeight in
                let selection = try ToriiKagemushaWalletLedgerSelectionV1(
                    schemeID: schemeID, walletID: walletID, entrypointHash: entrypoint)
                let before = try self.epochProgress()
                do {
                    let after = try await kagemushaWalletSynchronizeEpochsV1(
                        targetHeight: targetHeight, maximumBoundaries: maximumBoundaries,
                        requireCurrentOwner: requireCurrentOwner,
                        progress: { try self.epochProgress() },
                        fetch: { height in
                            let read = try await transport.getKagemushaWalletLedgerAttemptEpochV1(
                                selection: selection, boundaryHeight: height,
                                canonicalAuth: canonicalAuth, requireCurrentOwner: requireCurrentOwner)
                            guard case .original(let bytes) = read else { throw KagemushaWalletLedgerWaitV1() }
                            return bytes
                        },
                        ingest: { epoch, bytes in try self.ingestEpochBoundary(expectedEpoch: epoch, original: bytes) })
                    return (targetHeight <= after.boundaryHeight, after.epoch != before.epoch)
                } catch is KagemushaWalletLedgerWaitV1 {
                    return (false, try self.epochProgress().epoch != before.epoch)
                }
            })
    }

    func ledgerAttemptOutcome(_ attempt: KagemushaWalletLedgerAttemptV1) throws -> KagemushaWalletLedgerOutcomeV1 {
        switch attempt {
        case .activation(let signedWire):
            return try activationAttemptOutcome(signedWire: signedWire)
        case .unload(let claim, let signedWire):
            return try unloadAttemptOutcome(claim: claim, signedWire: signedWire)
        }
    }

    func ingestLedgerAttempt(_ attempt: KagemushaWalletLedgerAttemptV1, finality: Data) throws -> KagemushaWalletLedgerIngestV1 {
        switch attempt {
        case .activation(let signedWire):
            return try ingestActivationFinality(signedWire: signedWire, finality: finality)
        case .unload(let claim, let signedWire):
            return try ingestUnloadFinality(claim: claim, signedWire: signedWire, finality: finality)
        }
    }
}

// The callbacks separate transport scheduling tests from cryptographic authority: production
// always supplies the installed wallet's Native outcome, ingestion and epoch entry points above.
func kagemushaWalletConfirmLedgerAttemptV1(
    requireCurrentOwner: () async throws -> Void,
    outcome: () throws -> KagemushaWalletLedgerOutcomeV1,
    fetch: (Data) async throws -> KagemushaWalletLedgerReadV1,
    ingest: (Data) throws -> KagemushaWalletLedgerIngestV1,
    synchronize: (Data, UInt64) async throws -> (covered: Bool, selected: Bool)
) async throws -> KagemushaWalletLedgerConfirmationV1 {
    try Task.checkCancellation()
    try await requireCurrentOwner()
    let retained = try outcome()
    guard case .awaiting(let entrypoint) = retained else {
        return .init(outcome: retained, advanced: false)
    }
    let read = try await fetch(entrypoint)
    try Task.checkCancellation()
    try await requireCurrentOwner()
    guard case .original(let finality) = read else {
        return .init(outcome: retained, advanced: false)
    }
    switch try ingest(finality) {
    case .outcome(let decided):
        return .init(outcome: decided, advanced: true)
    case .epochRequired(let targetHeight):
        let synchronized = try await synchronize(entrypoint, targetHeight)
        guard synchronized.covered else {
            return .init(outcome: retained, advanced: synchronized.selected)
        }
        try Task.checkCancellation()
        try await requireCurrentOwner()
        guard case .outcome(let decided) = try ingest(finality) else {
            throw KagemushaWalletErrorV1.invalidNativeOutput
        }
        return .init(outcome: decided, advanced: true)
    }
}
