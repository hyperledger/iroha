import Foundation

extension FeePaymentIntent {
    /// Exact payer/revision/gas selection, before a quote supplies per-component limits.
    public var payerSelection: FeePaymentIntent {
        switch self {
        case let .authority(_, gasLimit):
            return .authority(chargeLimits: [], gasLimit: gasLimit)
        case let .sponsor(program, revision, _, gasLimit):
            return .sponsor(programId: program, programRevision: revision, chargeLimits: [], gasLimit: gasLimit)
        }
    }

    /// Canonical standalone archive, matching Rust `norito::to_bytes(FeePaymentIntent)`.
    public func canonicalNoritoArchive() throws -> Data {
        noritoEncode(typeName: "iroha_data_model::transaction::signed::model::FeePaymentIntent",
            payload: try compactNorito(), flags: NoritoHeader.compactLen, payloadAlignment: 8)
    }
}
