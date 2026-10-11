import Foundation

// Torii event-stream payloads (`GET /v1/events/sse`; `specs/torii/collection_queries.md`,
// "Event streams"). Every SSE `data` line is one JSON object with `category`
// (`Pipeline`, `Data` or `Other`) and `event`. Statuses are variant names, and a
// `summary` member, where present, is diagnostic text without a stable format.

// MARK: - Messages

/// One server-sent event: the decoded payload plus its SSE envelope fields.
public struct ToriiEventMessage<Event: Sendable>: Sendable {
    /// The decoded payload.
    public let event: Event
    /// The SSE `event:` field, when present.
    public let eventName: String?
    /// The SSE `id:` field, when present.
    public let eventId: String?
    /// The SSE `retry:` hint in milliseconds, when present.
    public let retryHintMilliseconds: Int?
    /// The raw SSE lines of this event.
    public let rawEvent: String

    public init(event: Event,
                eventName: String? = nil,
                eventId: String? = nil,
                retryHintMilliseconds: Int? = nil,
                rawEvent: String = "") {
        self.event = event
        self.eventName = eventName
        self.eventId = eventId
        self.retryHintMilliseconds = retryHintMilliseconds
        self.rawEvent = rawEvent
    }

    /// The same envelope carrying `event` instead.
    func replacingEvent<Other: Sendable>(_ event: Other) -> ToriiEventMessage<Other> {
        ToriiEventMessage<Other>(event: event,
                                 eventName: eventName,
                                 eventId: eventId,
                                 retryHintMilliseconds: retryHintMilliseconds,
                                 rawEvent: rawEvent)
    }
}

extension ToriiEventMessage: Equatable where Event: Equatable {}

// MARK: - Events

/// An event published on `GET /v1/events/sse`.
///
/// Events this SDK does not model, including any new `category` or `event`
/// value, decode as `.data` or `.other` instead of failing the stream.
public enum ToriiEvent: Sendable, Equatable {
    /// `Pipeline`/`Transaction`: a transaction moved through the pipeline.
    case transaction(ToriiPipelineTransactionEvent)
    /// `Pipeline`/`Block`: a block moved through the pipeline.
    case block(ToriiPipelineBlockEvent)
    /// `Pipeline`/`Warning`.
    case warning(ToriiPipelineWarningEvent)
    /// `Pipeline`/`Witness`: execution witness of a block.
    case witness(ToriiPipelineWitnessEvent)
    /// `Data`/`ProofVerified`, `ProofRejected` or `ProofPruned`.
    case proof(ToriiProofEvent)
    /// Any other data event; `event` is the data-event kind, such as `Asset`,
    /// `VerifyingKey` or `Trigger`.
    case data(ToriiEventNotice)
    /// Non-data events (`Time`, `ExecuteTrigger`, `TriggerCompleted`, `Other`)
    /// and any category or pipeline event this SDK does not model.
    case other(ToriiEventNotice)

    /// The `category` member: `Pipeline`, `Data` or `Other`.
    public var category: String {
        switch self {
        case .transaction, .block, .warning, .witness:
            return "Pipeline"
        case .proof:
            return "Data"
        case let .data(notice), let .other(notice):
            return notice.category
        }
    }

    /// The `event` member, for example `Transaction`, `ProofVerified` or `Asset`.
    public var name: String {
        switch self {
        case .transaction: return "Transaction"
        case .block: return "Block"
        case .warning: return "Warning"
        case .witness: return "Witness"
        case .proof(.verified): return "ProofVerified"
        case .proof(.rejected): return "ProofRejected"
        case .proof(.pruned): return "ProofPruned"
        case let .data(notice), let .other(notice): return notice.event
        }
    }
}

extension ToriiEvent: Decodable {
    private enum CodingKeys: String, CodingKey {
        case category
        case event
        case summary
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let category = try container.decode(String.self, forKey: .category)
        let event = try container.decode(String.self, forKey: .event)
        switch (category, event) {
        case ("Pipeline", "Transaction"):
            self = .transaction(try ToriiPipelineTransactionEvent(from: decoder))
        case ("Pipeline", "Block"):
            self = .block(try ToriiPipelineBlockEvent(from: decoder))
        case ("Pipeline", "Warning"):
            self = .warning(try ToriiPipelineWarningEvent(from: decoder))
        case ("Pipeline", "Witness"):
            self = .witness(try ToriiPipelineWitnessEvent(from: decoder))
        case ("Data", "ProofVerified"):
            self = .proof(.verified(try ToriiProofEventBody(from: decoder)))
        case ("Data", "ProofRejected"):
            self = .proof(.rejected(try ToriiProofEventBody(from: decoder)))
        case ("Data", "ProofPruned"):
            self = .proof(.pruned(try ToriiProofPrunedEvent(from: decoder)))
        default:
            // `summary` has no stable format; an unexpected shape is dropped, not fatal.
            let summary = (try? container.decodeIfPresent(String.self, forKey: .summary)) ?? nil
            let notice = ToriiEventNotice(category: category, event: event, summary: summary)
            self = category == "Data" ? .data(notice) : .other(notice)
        }
    }
}

/// An event Torii describes only by kind.
public struct ToriiEventNotice: Sendable, Equatable {
    /// `Data`, `Other`, or a category this SDK does not know.
    public let category: String
    /// The event kind, such as `Asset`, `VerifyingKey`, `Trigger` or `Time`.
    public let event: String
    /// Diagnostic text without a stable format; never parse it.
    public let summary: String?

    public init(category: String, event: String, summary: String?) {
        self.category = category
        self.event = event
        self.summary = summary
    }
}

// MARK: - Pipeline events

/// Why Torii rejected a transaction (`rejection_code`).
public enum ToriiTransactionRejectionCode: Hashable, Sendable, CustomStringConvertible {
    case accountDoesNotExist
    case limitCheck
    case validation
    case instructionExecution
    case ivmExecution
    case triggerExecution
    /// A code this SDK does not know.
    case other(String)

    public init(rawValue: String) {
        switch rawValue {
        case "account_does_not_exist": self = .accountDoesNotExist
        case "limit_check": self = .limitCheck
        case "validation": self = .validation
        case "instruction_execution": self = .instructionExecution
        case "ivm_execution": self = .ivmExecution
        case "trigger_execution": self = .triggerExecution
        default: self = .other(rawValue)
        }
    }

    /// The wire spelling, e.g. `limit_check`.
    public var rawValue: String {
        switch self {
        case .accountDoesNotExist: return "account_does_not_exist"
        case .limitCheck: return "limit_check"
        case .validation: return "validation"
        case .instructionExecution: return "instruction_execution"
        case .ivmExecution: return "ivm_execution"
        case .triggerExecution: return "trigger_execution"
        case let .other(code): return code
        }
    }

    public var description: String {
        rawValue
    }
}

/// `Pipeline`/`Transaction`: a transaction moved through the pipeline.
public struct ToriiPipelineTransactionEvent: Sendable, Equatable {
    /// Transaction hash: 64 lowercase hexadecimal digits.
    public let hash: String
    /// `Queued`, `Expired`, `Approved` or `Rejected`.
    public let status: PipelineTransactionState
    public let laneId: UInt32?
    public let dataspaceId: UInt64?
    /// Height of the block holding the transaction, once it has one.
    public let blockHeight: UInt64?
    /// Why a rejected transaction was rejected.
    public let rejectionCode: ToriiTransactionRejectionCode?
    /// Fixed public text describing the rejection.
    public let rejectionReason: String?

    public init(hash: String,
                status: PipelineTransactionState,
                laneId: UInt32? = nil,
                dataspaceId: UInt64? = nil,
                blockHeight: UInt64? = nil,
                rejectionCode: ToriiTransactionRejectionCode? = nil,
                rejectionReason: String? = nil) {
        self.hash = hash
        self.status = status
        self.laneId = laneId
        self.dataspaceId = dataspaceId
        self.blockHeight = blockHeight
        self.rejectionCode = rejectionCode
        self.rejectionReason = rejectionReason
    }
}

extension ToriiPipelineTransactionEvent: Decodable {
    private enum CodingKeys: String, CodingKey {
        case hash
        case status
        case laneId = "lane_id"
        case dataspaceId = "dataspace_id"
        case blockHeight = "block_height"
        case rejectionCode = "rejection_code"
        case rejectionReason = "rejection_reason"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let hash = try container.decode(String.self, forKey: .hash)
        guard (try? ToriiRequestValidation.exactTransactionHashHex(hash, field: "hash")) == hash else {
            throw DecodingError.dataCorruptedError(
                forKey: .hash,
                in: container,
                debugDescription: "pipeline transaction event.hash must be one canonical typed transaction hash"
            )
        }
        self.init(
            hash: hash,
            status: PipelineTransactionState(kind: try container.decode(String.self, forKey: .status)),
            laneId: try container.decodeIfPresent(UInt32.self, forKey: .laneId),
            dataspaceId: try container.decodeIfPresent(UInt64.self, forKey: .dataspaceId),
            blockHeight: try container.decodeIfPresent(UInt64.self, forKey: .blockHeight),
            rejectionCode: try container.decodeIfPresent(String.self, forKey: .rejectionCode)
                .map(ToriiTransactionRejectionCode.init(rawValue:)),
            rejectionReason: try container.decodeIfPresent(String.self, forKey: .rejectionReason)
        )
    }
}

/// `Pipeline`/`Block`: a block moved through the pipeline.
public struct ToriiPipelineBlockEvent: Sendable, Equatable {
    /// Block status, from its variant name.
    public enum Status: Hashable, Sendable {
        case created
        case approved
        case rejected
        case committed
        case applied
        /// A status this SDK does not know.
        case other(String)

        public init(name: String) {
            switch name {
            case "Created": self = .created
            case "Approved": self = .approved
            case "Rejected": self = .rejected
            case "Committed": self = .committed
            case "Applied": self = .applied
            default: self = .other(name)
            }
        }

        /// The variant name, e.g. `Committed`.
        public var name: String {
            switch self {
            case .created: return "Created"
            case .approved: return "Approved"
            case .rejected: return "Rejected"
            case .committed: return "Committed"
            case .applied: return "Applied"
            case let .other(name): return name
            }
        }
    }

    public let status: Status
    /// Block rejection variant name (for example `EmptyBlock`) when rejected.
    public let rejectionCode: String?

    public init(status: Status, rejectionCode: String? = nil) {
        self.status = status
        self.rejectionCode = rejectionCode
    }
}

extension ToriiPipelineBlockEvent: Decodable {
    private enum CodingKeys: String, CodingKey {
        case status
        case rejectionCode = "rejection_code"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(status: Status(name: try container.decode(String.self, forKey: .status)),
                  rejectionCode: try container.decodeIfPresent(String.self, forKey: .rejectionCode))
    }
}

/// `Pipeline`/`Warning`.
public struct ToriiPipelineWarningEvent: Decodable, Sendable, Equatable {
    public let kind: String
    public let details: String
    /// Height of the block the warning is about.
    public let height: UInt64

    public init(kind: String, details: String, height: UInt64) {
        self.kind = kind
        self.details = details
        self.height = height
    }
}

/// `Pipeline`/`Witness`: execution witness summary of a block.
public struct ToriiPipelineWitnessEvent: Decodable, Sendable, Equatable {
    public let blockHash: String
    public let height: UInt64
    public let view: UInt64
    public let epoch: UInt64
    public let readCount: UInt64
    public let writeCount: UInt64

    private enum CodingKeys: String, CodingKey {
        case blockHash = "block_hash"
        case height
        case view
        case epoch
        case readCount = "read_count"
        case writeCount = "write_count"
    }

    public init(blockHash: String, height: UInt64, view: UInt64, epoch: UInt64, readCount: UInt64, writeCount: UInt64) {
        self.blockHash = blockHash
        self.height = height
        self.view = view
        self.epoch = epoch
        self.readCount = readCount
        self.writeCount = writeCount
    }
}

// MARK: - Proof events

/// A proof verification event.
public enum ToriiProofEvent: Sendable, Equatable {
    /// `ProofVerified`
    case verified(ToriiProofEventBody)
    /// `ProofRejected`
    case rejected(ToriiProofEventBody)
    /// `ProofPruned`: retention removed proof records of one backend.
    case pruned(ToriiProofPrunedEvent)
}

/// A proof record identity: verifier backend and proof hash.
public struct ToriiProofId: Sendable, Hashable {
    /// Verifier-registry backend label, e.g. `pipa-r/pasta`.
    public let backend: String
    /// Proof hash: 64 lowercase hexadecimal digits.
    public let proofHashHex: String

    public init(backend: String, proofHashHex: String) {
        self.backend = backend
        self.proofHashHex = proofHashHex.lowercased()
    }
}

extension ToriiProofId: Decodable {
    private enum CodingKeys: String, CodingKey {
        case backend
        case proofHash = "proof_hash"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(backend: try ToriiProofEventDecoding.backend(in: container, forKey: .backend),
                  proofHashHex: try ToriiProofEventDecoding.hash(in: container, forKey: .proofHash))
    }
}

/// Payload of `ProofVerified` and `ProofRejected`.
public struct ToriiProofEventBody: Sendable, Equatable {
    public let id: ToriiProofId
    public let callHashHex: String?
    public let envelopeHashHex: String?
    /// The verifying key the proof referenced, as `backend::name`.
    public let verifyingKeyRef: String?
    public let verifyingKeyCommitmentHex: String?

    public init(id: ToriiProofId,
                callHashHex: String? = nil,
                envelopeHashHex: String? = nil,
                verifyingKeyRef: String? = nil,
                verifyingKeyCommitmentHex: String? = nil) {
        self.id = id
        self.callHashHex = callHashHex
        self.envelopeHashHex = envelopeHashHex
        self.verifyingKeyRef = verifyingKeyRef
        self.verifyingKeyCommitmentHex = verifyingKeyCommitmentHex
    }

    /// `verifyingKeyRef` split into backend and name, when it is well formed.
    public var verifyingKeyId: ToriiVerifyingKeyId? {
        guard let reference = verifyingKeyRef,
              let separator = reference.range(of: "::") else {
            return nil
        }
        return try? ToriiVerifyingKeyId(backend: String(reference[..<separator.lowerBound]),
                                        name: String(reference[separator.upperBound...]))
    }
}

extension ToriiProofEventBody: Decodable {
    private enum CodingKeys: String, CodingKey {
        case callHash = "call_hash"
        case envelopeHash = "envelope_hash"
        case verifyingKeyRef = "vk_ref"
        case verifyingKeyCommitment = "vk_commitment"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            id: try ToriiProofId(from: decoder),
            callHashHex: try ToriiProofEventDecoding.hashIfPresent(in: container, forKey: .callHash),
            envelopeHashHex: try ToriiProofEventDecoding.hashIfPresent(in: container, forKey: .envelopeHash),
            verifyingKeyRef: try container.decodeIfPresent(String.self, forKey: .verifyingKeyRef),
            verifyingKeyCommitmentHex: try ToriiProofEventDecoding.hashIfPresent(in: container,
                                                                                forKey: .verifyingKeyCommitment)
        )
    }
}

/// Payload of `ProofPruned`.
public struct ToriiProofPrunedEvent: Sendable, Equatable {
    /// What started the pruning pass.
    public enum Origin: Hashable, Sendable {
        /// Retention enforcement while inserting a new proof record.
        case insert
        /// An explicit prune instruction.
        case manual
        /// An origin this SDK does not know.
        case other(String)

        public init(name: String) {
            switch name {
            case "Insert": self = .insert
            case "Manual": self = .manual
            default: self = .other(name)
            }
        }

        /// The variant name, e.g. `Insert`.
        public var name: String {
            switch self {
            case .insert: return "Insert"
            case .manual: return "Manual"
            case let .other(name): return name
            }
        }
    }

    public let backend: String
    public let removedCount: UInt64
    /// Proof records of the backend left after pruning.
    public let remaining: UInt64
    public let cap: UInt64
    public let graceBlocks: UInt64
    public let pruneBatch: UInt64
    public let prunedAtHeight: UInt64
    /// Account that issued the pruning instruction or the insert that pruned.
    public let prunedBy: String
    public let origin: Origin
    public let removed: [ToriiProofId]

    public init(backend: String,
                removedCount: UInt64,
                remaining: UInt64,
                cap: UInt64,
                graceBlocks: UInt64,
                pruneBatch: UInt64,
                prunedAtHeight: UInt64,
                prunedBy: String,
                origin: Origin,
                removed: [ToriiProofId]) {
        self.backend = backend
        self.removedCount = removedCount
        self.remaining = remaining
        self.cap = cap
        self.graceBlocks = graceBlocks
        self.pruneBatch = pruneBatch
        self.prunedAtHeight = prunedAtHeight
        self.prunedBy = prunedBy
        self.origin = origin
        self.removed = removed
    }
}

extension ToriiProofPrunedEvent: Decodable {
    private enum CodingKeys: String, CodingKey {
        case backend
        case removedCount = "removed_count"
        case remaining
        case cap
        case graceBlocks = "grace_blocks"
        case pruneBatch = "prune_batch"
        case prunedAtHeight = "pruned_at_height"
        case prunedBy = "pruned_by"
        case origin
        case removed
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            backend: try ToriiProofEventDecoding.backend(in: container, forKey: .backend),
            removedCount: try container.decode(UInt64.self, forKey: .removedCount),
            remaining: try container.decode(UInt64.self, forKey: .remaining),
            cap: try container.decode(UInt64.self, forKey: .cap),
            graceBlocks: try container.decode(UInt64.self, forKey: .graceBlocks),
            pruneBatch: try container.decode(UInt64.self, forKey: .pruneBatch),
            prunedAtHeight: try container.decode(UInt64.self, forKey: .prunedAtHeight),
            prunedBy: try container.decode(String.self, forKey: .prunedBy),
            origin: Origin(name: try container.decode(String.self, forKey: .origin)),
            removed: try container.decode([ToriiProofId].self, forKey: .removed)
        )
    }
}

/// Field checks shared by the proof-event decoders.
private enum ToriiProofEventDecoding {
    /// An exact supported verifier-registry label.
    static func backend<Key: CodingKey>(in container: KeyedDecodingContainer<Key>, forKey key: Key) throws -> String {
        let value = try container.decode(String.self, forKey: key)
        guard !value.isEmpty,
              value.trimmingCharacters(in: .whitespacesAndNewlines) == value,
              VerifierBackendRegistryLabels.isSupported(value) else {
            throw DecodingError.dataCorruptedError(
                forKey: key,
                in: container,
                debugDescription: "\(key.stringValue) is not an exact supported verifier-registry label: \(value)"
            )
        }
        return value
    }

    /// A 32-byte hash as 64 hexadecimal digits, lowercased.
    static func hash<Key: CodingKey>(in container: KeyedDecodingContainer<Key>, forKey key: Key) throws -> String {
        let value = try container.decode(String.self, forKey: key)
        guard value.utf8.count == 64, value.utf8.allSatisfy({ byte in
            (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
                || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(byte)
                || (UInt8(ascii: "A")...UInt8(ascii: "F")).contains(byte)
        }) else {
            throw DecodingError.dataCorruptedError(
                forKey: key,
                in: container,
                debugDescription: "\(key.stringValue) must be a 32-byte hash in hexadecimal"
            )
        }
        return value.lowercased()
    }

    static func hashIfPresent<Key: CodingKey>(in container: KeyedDecodingContainer<Key>,
                                              forKey key: Key) throws -> String? {
        guard container.contains(key), try !container.decodeNil(forKey: key) else {
            return nil
        }
        return try hash(in: container, forKey: key)
    }
}
