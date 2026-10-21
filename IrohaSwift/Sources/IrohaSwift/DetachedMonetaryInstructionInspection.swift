import Foundation

/// Native batch semantics. Independent batches can commit with refused legs.
public enum DetachedTransferBatchMode: String, Decodable, Sendable {
    case atomic
    case independent
}

/// One exact, ordered native batch leg, including its receipt correlation identity.
public struct DetachedTransferBatchLegInspection: Decodable, Sendable, Equatable {
    public let legId: String
    public let sourceAccountId: String
    public let destinationAccountId: String
    public let assetDefinitionId: String
    public let amount: String

    private enum CodingKeys: String, CodingKey {
        case legId = "leg_id"
        case sourceAccountId = "source_account_id"
        case destinationAccountId = "destination_account_id"
        case assetDefinitionId = "asset_definition_id"
        case amount
    }

    public init(from decoder: Decoder) throws {
        try requireMonetaryFields(decoder, [
            "leg_id", "source_account_id", "destination_account_id", "asset_definition_id", "amount"
        ])
        let values = try decoder.container(keyedBy: CodingKeys.self)
        legId = try values.decode(String.self, forKey: .legId)
        sourceAccountId = try values.decode(String.self, forKey: .sourceAccountId)
        destinationAccountId = try values.decode(String.self, forKey: .destinationAccountId)
        assetDefinitionId = try values.decode(String.self, forKey: .assetDefinitionId)
        amount = try values.decode(String.self, forKey: .amount)
        guard !legId.isEmpty, !sourceAccountId.isEmpty, !destinationAccountId.isEmpty,
              !assetDefinitionId.isEmpty, !amount.isEmpty else {
            throw invalidMonetaryInspection(decoder)
        }
    }
}

/// A single native TransferAssetBatch instruction, distinct from an executable sequence.
public struct DetachedAssetTransferBatchInspection: Decodable, Sendable, Equatable {
    public let mode: DetachedTransferBatchMode
    public let entries: [DetachedTransferBatchLegInspection]

    private enum CodingKeys: String, CodingKey { case kind, mode, entries }

    public init(from decoder: Decoder) throws {
        try requireMonetaryFields(decoder, ["kind", "mode", "entries"])
        let values = try decoder.container(keyedBy: CodingKeys.self)
        guard try values.decode(String.self, forKey: .kind) == "asset_transfer_batch" else {
            throw invalidMonetaryInspection(decoder)
        }
        mode = try values.decode(DetachedTransferBatchMode.self, forKey: .mode)
        entries = try values.decode([DetachedTransferBatchLegInspection].self, forKey: .entries)
        guard !entries.isEmpty, Set(entries.map(\.legId)).count == entries.count else {
            throw invalidMonetaryInspection(decoder)
        }
    }
}

/// A typed external fact; text and quantities are never treated as booleans.
public enum DetachedEscrowValueInspection: Decodable, Sendable, Equatable {
    case bool(Bool)
    case text(String)
    case quantity(String)

    private enum CodingKeys: String, CodingKey { case kind, value }

    public init(from decoder: Decoder) throws {
        try requireMonetaryFields(decoder, ["kind", "value"])
        let values = try decoder.container(keyedBy: CodingKeys.self)
        switch try values.decode(String.self, forKey: .kind) {
        case "bool": self = .bool(try values.decode(Bool.self, forKey: .value))
        case "text": self = .text(try values.decode(String.self, forKey: .value))
        case "quantity": self = .quantity(try values.decode(String.self, forKey: .value))
        default: throw invalidMonetaryInspection(decoder)
        }
    }
}

/// Exact predicate the native ledger will evaluate.
public enum DetachedEscrowPredicateInspection: Decodable, Sendable, Equatable {
    case equals(DetachedEscrowValueInspection)
    case quantityAtMost(String)

    private enum CodingKeys: String, CodingKey { case kind, value }

    public init(from decoder: Decoder) throws {
        try requireMonetaryFields(decoder, ["kind", "value"])
        let values = try decoder.container(keyedBy: CodingKeys.self)
        switch try values.decode(String.self, forKey: .kind) {
        case "equals":
            self = .equals(try values.decode(DetachedEscrowValueInspection.self, forKey: .value))
        case "quantity_at_most":
            self = .quantityAtMost(try values.decode(String.self, forKey: .value))
        default: throw invalidMonetaryInspection(decoder)
        }
    }
}

/// An immutable attestor predicate or a ledger-time window.
public enum DetachedEscrowConditionInspection: Decodable, Sendable, Equatable {
    case oracle(id: String, attestor: String, sequence: UInt32, predicate: DetachedEscrowPredicateInspection)
    case within(id: String, durationMs: UInt64)

    private enum CodingKeys: String, CodingKey {
        case kind, id, attestor, sequence, predicate
        case durationMs = "duration_ms"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let id = try values.decode(String.self, forKey: .id)
        guard !id.isEmpty else { throw invalidMonetaryInspection(decoder) }
        switch try values.decode(String.self, forKey: .kind) {
        case "oracle":
            try requireMonetaryFields(decoder, ["kind", "id", "attestor", "sequence", "predicate"])
            let attestor = try values.decode(String.self, forKey: .attestor)
            let sequence = try values.decode(UInt32.self, forKey: .sequence)
            guard !attestor.isEmpty, sequence > 0 else {
                throw invalidMonetaryInspection(decoder)
            }
            self = .oracle(
                id: id, attestor: attestor, sequence: sequence,
                predicate: try values.decode(DetachedEscrowPredicateInspection.self, forKey: .predicate)
            )
        case "within":
            try requireMonetaryFields(decoder, ["kind", "id", "duration_ms"])
            let duration = try values.decode(UInt64.self, forKey: .durationMs)
            guard duration > 0 else { throw invalidMonetaryInspection(decoder) }
            self = .within(id: id, durationMs: duration)
        default:
            throw invalidMonetaryInspection(decoder)
        }
    }
}

/// Owner-funded conditional escrow with all conditions, evidence and expiry retained.
public struct DetachedConditionalEscrowInspection: Decodable, Sendable, Equatable {
    public let escrowId: String
    public let assetDefinitionId: String
    public let beneficiary: String
    public let amount: String
    public let conditions: [DetachedEscrowConditionInspection]
    public let expiresAtMs: UInt64
    public let evidenceHashes: [String]

    private enum CodingKeys: String, CodingKey {
        case kind
        case escrowId = "escrow_id"
        case assetDefinitionId = "asset_definition_id"
        case beneficiary, amount, conditions
        case expiresAtMs = "expires_at_ms"
        case evidenceHashes = "evidence_hashes"
    }

    public init(from decoder: Decoder) throws {
        try requireMonetaryFields(decoder, [
            "kind", "escrow_id", "asset_definition_id", "beneficiary", "amount",
            "conditions", "expires_at_ms", "evidence_hashes"
        ])
        let values = try decoder.container(keyedBy: CodingKeys.self)
        guard try values.decode(String.self, forKey: .kind) == "conditional_escrow_open" else {
            throw invalidMonetaryInspection(decoder)
        }
        escrowId = try values.decode(String.self, forKey: .escrowId)
        assetDefinitionId = try values.decode(String.self, forKey: .assetDefinitionId)
        beneficiary = try values.decode(String.self, forKey: .beneficiary)
        amount = try values.decode(String.self, forKey: .amount)
        conditions = try values.decode([DetachedEscrowConditionInspection].self, forKey: .conditions)
        expiresAtMs = try values.decode(UInt64.self, forKey: .expiresAtMs)
        evidenceHashes = try values.decode([String].self, forKey: .evidenceHashes)
        guard !escrowId.isEmpty, !assetDefinitionId.isEmpty, !beneficiary.isEmpty,
              !amount.isEmpty, !conditions.isEmpty, expiresAtMs > 0 else {
            throw invalidMonetaryInspection(decoder)
        }
    }
}

private struct MonetaryInspectionKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

private func requireMonetaryFields(_ decoder: Decoder, _ fields: Set<String>) throws {
    let values = try decoder.container(keyedBy: MonetaryInspectionKey.self)
    guard Set(values.allKeys.map(\.stringValue)) == fields else {
        throw invalidMonetaryInspection(decoder)
    }
}

private func invalidMonetaryInspection(_ decoder: Decoder) -> DecodingError {
    .dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Unsupported or malformed native monetary inspection"))
}
