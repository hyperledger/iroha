import Foundation

/// Route selector of one retained Activate or Unload attempt. The entrypoint hash comes only
/// from Native's Awaiting outcome, which Native derived from the retained signed wire; an
/// app-supplied or Core-reported transaction hash is never used. It identifies DATA only.
public struct ToriiKagemushaWalletLedgerSelectionV1: Equatable, Sendable {
    /// Complete direct finality original: one certificate, one output row, paths and framing.
    public static let finalityMaximumBytes = 1_327_104
    /// One epoch boundary certificate.
    public static let epochMaximumBytes = 262_144
    public let schemeID: Data
    public let walletID: Data
    public let entrypointHash: Data

    init(schemeID: Data, walletID: Data, entrypointHash: Data) throws {
        for value in [schemeID, walletID, entrypointHash] {
            guard value.count == 32, value.contains(where: { $0 != 0 }) else {
                throw ToriiClientError.invalidPayload("KAGEMUSHA ledger selectors must be nonzero 32-byte identities")
            }
        }
        self.schemeID = Data(schemeID)
        self.walletID = Data(walletID)
        self.entrypointHash = Data(entrypointHash)
    }

    var path: String {
        func hex(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }
        return "/v1/kagemusha/\(hex(schemeID))/wallets/\(hex(walletID))/ledger/\(hex(entrypointHash))"
    }
}

/// One account-signed ledger attempt read. Only Torii's two typed codes are waits; every
/// other status, including an untyped 404 or a route absent after a rollback, throws.
public enum KagemushaWalletLedgerReadV1: Equatable, Sendable {
    /// Exact original DATA bytes; only the installed Native wallet authenticates them.
    case original(Data)
    /// 404 `kagemusha_ledger_entry_not_committed`: not committed yet, or not this account's attempt.
    case notCommitted
    /// 503 `kagemusha_ledger_finality_unavailable`: retryable unavailability.
    case unavailable
}
