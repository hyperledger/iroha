import Foundation

/// Sole native status protocol revision.
public let sumeragiStatusProtocolVersion: UInt16 = 1

private func requireNativeStatusFields(_ decoder: Decoder, _ fields: [String]) throws {
    let container = try decoder.container(keyedBy: NativeStatusCodingKey.self)
    guard Set(container.allKeys.map(\.stringValue)) == Set(fields) else {
        throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath,
            debugDescription: "native status requires every field and rejects unknown fields"))
    }
}
private struct NativeStatusCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

// Every numeric field in native status is unsigned. Reject the sign token before
// Foundation can normalize JSON -0 to the same UInt64 as canonical zero.
private func rejectNativeStatusSignedNumbers(_ data: Data) throws {
    var inString = false
    var escaped = false
    for byte in data {
        if inString {
            if escaped { escaped = false }
            else if byte == 0x5c { escaped = true }
            else if byte == 0x22 { inString = false }
        } else if byte == 0x22 {
            inString = true
        } else if byte == 0x2d {
            throw DecodingError.dataCorrupted(.init(codingPath: [],
                debugDescription: "native status requires unsigned numeric tokens"))
        }
    }
}

private func nativeStatusPublicKey(_ literal: String?, codingPath: [CodingKey]) throws -> String? {
    guard let literal else { return nil }
    let parsed = try governancePublicKeyOrderV1(literal, codingPath: codingPath)
    guard let algorithm = SigningAlgorithm(noritoDiscriminant: parsed.algorithm) else {
        throw DecodingError.dataCorrupted(.init(codingPath: codingPath, debugDescription: "unsupported public key"))
    }
    _ = try AccountAddress.fromAccount(publicKey: Data(parsed.payload), algorithm: algorithm.wireName)
    return literal
}

/// Unsigned native core memory counters.
public struct ToriiSumeragiFootprint: Decodable, Sendable, Equatable {
    public let votes: UInt64
    public let timeouts: UInt64
    public let blocks: UInt64
    public let execEntries: UInt64
    public let wants: UInt64
    public let pendingApply: UInt64
    public let syncEntries: UInt64
    public let syncBytes: UInt64
    public let peers: UInt64
    public let recentHeaders: UInt64
    public let configs: UInt64
    public let certCache: UInt64
    public let evidenceKeys: UInt64
    public let probe: UInt64
    private enum CodingKeys: String, CodingKey {
        case votes
        case timeouts
        case blocks
        case execEntries = "exec_entries"
        case wants
        case pendingApply = "pending_apply"
        case syncEntries = "sync_entries"
        case syncBytes = "sync_bytes"
        case peers
        case recentHeaders = "recent_headers"
        case configs
        case certCache = "cert_cache"
        case evidenceKeys = "evidence_keys"
        case probe
    }
    public init(from decoder: Decoder) throws {
        try requireNativeStatusFields(decoder, ["votes", "timeouts", "blocks", "exec_entries", "wants", "pending_apply", "sync_entries", "sync_bytes", "peers", "recent_headers", "configs", "cert_cache", "evidence_keys", "probe"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        votes = try c.decode(UInt64.self, forKey: .votes)
        timeouts = try c.decode(UInt64.self, forKey: .timeouts)
        blocks = try c.decode(UInt64.self, forKey: .blocks)
        execEntries = try c.decode(UInt64.self, forKey: .execEntries)
        wants = try c.decode(UInt64.self, forKey: .wants)
        pendingApply = try c.decode(UInt64.self, forKey: .pendingApply)
        syncEntries = try c.decode(UInt64.self, forKey: .syncEntries)
        syncBytes = try c.decode(UInt64.self, forKey: .syncBytes)
        peers = try c.decode(UInt64.self, forKey: .peers)
        recentHeaders = try c.decode(UInt64.self, forKey: .recentHeaders)
        configs = try c.decode(UInt64.self, forKey: .configs)
        certCache = try c.decode(UInt64.self, forKey: .certCache)
        evidenceKeys = try c.decode(UInt64.self, forKey: .evidenceKeys)
        probe = try c.decode(UInt64.self, forKey: .probe)
    }
}

/// Applied-cut readiness from the sole native pulse owner.
public struct ToriiSumeragiBeaconHorizon: Decodable, Sendable, Equatable {
    public let epochLengthBlocks: UInt64
    public let nextRequiredPulseHeight: UInt64?
    public let activeSessionId: String?
    public let sessionCoversNextPulse: Bool
    public let localProviderReady: Bool
    private enum CodingKeys: String, CodingKey {
        case epochLengthBlocks = "epoch_length_blocks"
        case nextRequiredPulseHeight = "next_required_pulse_height"
        case activeSessionId = "active_session_id"
        case sessionCoversNextPulse = "session_covers_next_pulse"
        case localProviderReady = "local_provider_ready"
    }
    public init(from decoder: Decoder) throws {
        try requireNativeStatusFields(decoder, ["epoch_length_blocks", "next_required_pulse_height", "active_session_id", "session_covers_next_pulse", "local_provider_ready"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        epochLengthBlocks = try c.decode(UInt64.self, forKey: .epochLengthBlocks)
        nextRequiredPulseHeight = try c.decodeIfPresent(UInt64.self, forKey: .nextRequiredPulseHeight)
        activeSessionId = try c.decodeIfPresent(String.self, forKey: .activeSessionId)
        sessionCoversNextPulse = try c.decode(Bool.self, forKey: .sessionCoversNextPulse)
        localProviderReady = try c.decode(Bool.self, forKey: .localProviderReady)
        guard activeSessionId.map({ $0.count == 64 && $0.utf8.allSatisfy { (48...57).contains($0) || (65...70).contains($0) } }) ?? true,
              !sessionCoversNextPulse || (nextRequiredPulseHeight != nil && activeSessionId != nil),
              !localProviderReady || activeSessionId != nil else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "invalid native beacon readiness"))
        }
    }
}

/// Closed halt cases reported by the native core.
public enum ToriiSumeragiHaltReason: Decodable, Sendable, Equatable {
    case safetyRecordCorrupt, safetyRecordInconsistent, driverAnomaly
    case safetyViolation(UInt64), applyDiverged(UInt64), publicationRecoveryRequired(UInt64)
    private enum CodingKeys: String, CodingKey { case reason, details }
    public init(from decoder: Decoder) throws {
        try requireNativeStatusFields(decoder, ["reason", "details"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let reason = try c.decode(String.self, forKey: .reason)
        switch reason {
        case "safety_violation": self = .safetyViolation(try c.decode(UInt64.self, forKey: .details))
        case "apply_diverged": self = .applyDiverged(try c.decode(UInt64.self, forKey: .details))
        case "publication_recovery_required": self = .publicationRecoveryRequired(try c.decode(UInt64.self, forKey: .details))
        default:
            guard try c.decodeNil(forKey: .details) else {
                throw DecodingError.dataCorruptedError(forKey: .details, in: c, debugDescription: "unit halt requires null details")
            }
            switch reason {
            case "safety_record_corrupt": self = .safetyRecordCorrupt
            case "safety_record_inconsistent": self = .safetyRecordInconsistent
            case "driver_anomaly": self = .driverAnomaly
            default: throw DecodingError.dataCorruptedError(forKey: .reason, in: c, debugDescription: "unknown native halt reason")
            }
        }
    }
}

/// Sole native status observation; it confers no finality authority.
public struct ToriiSumeragiStatusSnapshot: Decodable, Sendable, Equatable {
    /// Bounded, duplicate-key and non-integral-token rejecting JSON decoder.
    public static func parseJSON(_ data: Data) throws -> Self {
        guard !data.isEmpty, data.count <= 1_048_576 else { throw CocoaError(.fileReadTooLarge) }
        try rejectNativeStatusSignedNumbers(data)
        try StrictJSONDuplicateKeyRejector.rejectDuplicateObjectKeys(in: data, requireAllNumbersInteger: true)
        return try JSONDecoder().decode(Self.self, from: data)
    }

    public let protocolVersion: UInt16
    public let configFingerprint: String
    public let beaconHorizon: ToriiSumeragiBeaconHorizon?
    public let instance: String
    public let height: UInt64
    public let view: UInt64
    public let stage: UInt8
    public let leader: String?
    public let proxyTail: String?
    public let highQcView: UInt64?
    public let level: UInt32
    public let startLevel: UInt32
    public let tRetxMs: UInt64
    public let committedHeight: UInt64
    public let appliedHeight: UInt64
    public let awaiting: Bool
    public let signer: String?
    public let unanchored: Bool
    public let abstaining: Bool
    public let halted: ToriiSumeragiHaltReason?
    public let footprint: ToriiSumeragiFootprint
    public var isHalted: Bool { halted != nil }
    public var isSigning: Bool { signer != nil && !abstaining && !unanchored }
    public var applyLag: UInt64 { committedHeight >= appliedHeight ? committedHeight - appliedHeight : 0 }
    private enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case configFingerprint = "config_fingerprint"
        case beaconHorizon = "beacon_horizon"
        case instance
        case height
        case view
        case stage
        case leader
        case proxyTail = "proxy_tail"
        case highQcView = "high_qc_view"
        case level
        case startLevel = "start_level"
        case tRetxMs = "t_retx_ms"
        case committedHeight = "committed_height"
        case appliedHeight = "applied_height"
        case awaiting
        case signer
        case unanchored
        case abstaining
        case halted
        case footprint
    }
    public init(from decoder: Decoder) throws {
        try requireNativeStatusFields(decoder, ["protocol_version", "config_fingerprint", "beacon_horizon", "instance", "height", "view", "stage", "leader", "proxy_tail", "high_qc_view", "level", "start_level", "t_retx_ms", "committed_height", "applied_height", "awaiting", "signer", "unanchored", "abstaining", "halted", "footprint"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        protocolVersion = try c.decode(UInt16.self, forKey: .protocolVersion)
        configFingerprint = try c.decode(String.self, forKey: .configFingerprint)
        beaconHorizon = try c.decodeIfPresent(ToriiSumeragiBeaconHorizon.self, forKey: .beaconHorizon)
        instance = try c.decode(String.self, forKey: .instance)
        height = try c.decode(UInt64.self, forKey: .height)
        view = try c.decode(UInt64.self, forKey: .view)
        stage = try c.decode(UInt8.self, forKey: .stage)
        leader = try nativeStatusPublicKey(try c.decodeIfPresent(String.self, forKey: .leader), codingPath: decoder.codingPath)
        proxyTail = try nativeStatusPublicKey(try c.decodeIfPresent(String.self, forKey: .proxyTail), codingPath: decoder.codingPath)
        highQcView = try c.decodeIfPresent(UInt64.self, forKey: .highQcView)
        level = try c.decode(UInt32.self, forKey: .level)
        startLevel = try c.decode(UInt32.self, forKey: .startLevel)
        tRetxMs = try c.decode(UInt64.self, forKey: .tRetxMs)
        committedHeight = try c.decode(UInt64.self, forKey: .committedHeight)
        appliedHeight = try c.decode(UInt64.self, forKey: .appliedHeight)
        awaiting = try c.decode(Bool.self, forKey: .awaiting)
        signer = try nativeStatusPublicKey(try c.decodeIfPresent(String.self, forKey: .signer), codingPath: decoder.codingPath)
        unanchored = try c.decode(Bool.self, forKey: .unanchored)
        abstaining = try c.decode(Bool.self, forKey: .abstaining)
        halted = try c.decodeIfPresent(ToriiSumeragiHaltReason.self, forKey: .halted)
        footprint = try c.decode(ToriiSumeragiFootprint.self, forKey: .footprint)
        guard protocolVersion == sumeragiStatusProtocolVersion,
              ToriiCanonicalWire.isCanonicalHash(configFingerprint), stage <= 2,
              instance.count == 64,
              instance.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "invalid native status protocol, fingerprint, stage or instance"))
        }
    }
}

private func nativeLaneFailure(_ decoder: Decoder, _ description: String) -> DecodingError {
    DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: description))
}

// `[u8; 32]` lane values use the canonical Norito JSON spelling: exactly 64 uppercase hex digits.
private func nativeLaneByte32(_ value: String, _ decoder: Decoder, _ field: String) throws -> String {
    guard value.utf8.count == 64,
          value.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) }) else {
        throw nativeLaneFailure(decoder, "\(field) must be exactly 32 uppercase hex bytes")
    }
    return value
}

/// Chain parameters pinned into one lane incarnation (Rust `SumeragiParameters`).
public struct ToriiSumeragiParameters: Decodable, Sendable, Equatable {
    /// Algorithm names the Rust data model admits in `key_allowed_algorithms`.
    public static let admittedKeyAlgorithms: Set<String> = [
        "ed25519", "secp256k1", "ml-dsa", "bls_normal", "bls_small",
        "gost3410-2012-256-paramset-a", "gost3410-2012-256-paramset-b", "gost3410-2012-256-paramset-c",
        "gost3410-2012-512-paramset-a", "gost3410-2012-512-paramset-b", "sm2",
    ]
    public let blockCadenceMs: UInt64
    public let maxClockDriftMs: UInt64
    /// Positive committed first-Prepare freshness allowance for due work.
    public let dueWorkMaxLagMs: UInt64
    public let keyActivationLeadBlocks: UInt64
    public let keyOverlapGraceBlocks: UInt64
    public let keyExpiryGraceBlocks: UInt64
    public let keyAllowedAlgorithms: [String]
    public let payloadRetryIntervalMs: UInt64
    public let execBudgetMs: UInt64
    public let applyBudgetMs: UInt64
    public let maxBlockBytes: UInt32
    public let epochLengthBlocks: UInt64
    public let demotionWindow: UInt64
    private enum CodingKeys: String, CodingKey {
        case blockCadenceMs = "block_cadence_ms"
        case maxClockDriftMs = "max_clock_drift_ms"
        case dueWorkMaxLagMs = "due_work_max_lag_ms"
        case keyActivationLeadBlocks = "key_activation_lead_blocks"
        case keyOverlapGraceBlocks = "key_overlap_grace_blocks"
        case keyExpiryGraceBlocks = "key_expiry_grace_blocks"
        case keyAllowedAlgorithms = "key_allowed_algorithms"
        case payloadRetryIntervalMs = "payload_retry_interval_ms"
        case execBudgetMs = "exec_budget_ms"
        case applyBudgetMs = "apply_budget_ms"
        case maxBlockBytes = "max_block_bytes"
        case epochLengthBlocks = "epoch_length_blocks"
        case demotionWindow = "demotion_window"
    }
    public init(from decoder: Decoder) throws {
        try requireNativeStatusFields(decoder, ["block_cadence_ms", "max_clock_drift_ms", "due_work_max_lag_ms", "key_activation_lead_blocks", "key_overlap_grace_blocks", "key_expiry_grace_blocks", "key_allowed_algorithms", "payload_retry_interval_ms", "exec_budget_ms", "apply_budget_ms", "max_block_bytes", "epoch_length_blocks", "demotion_window"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        blockCadenceMs = try c.decode(UInt64.self, forKey: .blockCadenceMs)
        maxClockDriftMs = try c.decode(UInt64.self, forKey: .maxClockDriftMs)
        dueWorkMaxLagMs = try c.decode(UInt64.self, forKey: .dueWorkMaxLagMs)
        keyActivationLeadBlocks = try c.decode(UInt64.self, forKey: .keyActivationLeadBlocks)
        keyOverlapGraceBlocks = try c.decode(UInt64.self, forKey: .keyOverlapGraceBlocks)
        keyExpiryGraceBlocks = try c.decode(UInt64.self, forKey: .keyExpiryGraceBlocks)
        keyAllowedAlgorithms = try c.decode([String].self, forKey: .keyAllowedAlgorithms)
        payloadRetryIntervalMs = try c.decode(UInt64.self, forKey: .payloadRetryIntervalMs)
        execBudgetMs = try c.decode(UInt64.self, forKey: .execBudgetMs)
        applyBudgetMs = try c.decode(UInt64.self, forKey: .applyBudgetMs)
        maxBlockBytes = try c.decode(UInt32.self, forKey: .maxBlockBytes)
        epochLengthBlocks = try c.decode(UInt64.self, forKey: .epochLengthBlocks)
        demotionWindow = try c.decode(UInt64.self, forKey: .demotionWindow)
        guard [blockCadenceMs, dueWorkMaxLagMs, payloadRetryIntervalMs, execBudgetMs, applyBudgetMs, epochLengthBlocks, demotionWindow].allSatisfy({ $0 > 0 }),
              maxBlockBytes > 0 else {
            throw nativeLaneFailure(decoder, "lane chain parameters require nonzero cadence, due-work lag, budgets, block bytes, epoch and demotion window")
        }
        guard keyAllowedAlgorithms.allSatisfy({ Self.admittedKeyAlgorithms.contains($0) }) else {
            throw nativeLaneFailure(decoder, "key_allowed_algorithms contains an unknown algorithm")
        }
    }
}

/// One pinned lane committee member: its BLS-normal peer key and admitted proof of possession.
public struct ToriiSumeragiLaneMember: Decodable, Sendable, Equatable {
    public let peer: String
    /// The 96-byte BLS-normal proof of possession.
    public let proofOfPossession: Data
    private enum CodingKeys: String, CodingKey {
        case peer
        case pop
    }
    public init(from decoder: Decoder) throws {
        try requireNativeStatusFields(decoder, ["peer", "pop"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let peer = try c.decode(String.self, forKey: .peer)
        guard peer.hasPrefix("ea0130") else {
            throw nativeLaneFailure(decoder, "lane committee peer must be a canonical BLS-normal key")
        }
        self.peer = try nativeStatusPublicKey(peer, codingPath: decoder.codingPath) ?? peer
        let pop = try c.decode(String.self, forKey: .pop)
        guard let bytes = Data(base64Encoded: pop), bytes.base64EncodedString() == pop, bytes.count == 96 else {
            throw nativeLaneFailure(decoder, "lane committee pop must be a canonical base64 96-byte proof")
        }
        proofOfPossession = bytes
    }
}

/// The highest lane block the global chain merged (`height` 0: nothing merged yet).
public struct ToriiSumeragiLaneFrontier: Decodable, Sendable, Equatable {
    public let height: UInt64
    public let blockHash: String
    public let result: String
    private enum CodingKeys: String, CodingKey {
        case height
        case blockHash = "block_hash"
        case result
    }
    public init(from decoder: Decoder) throws {
        try requireNativeStatusFields(decoder, ["height", "block_hash", "result"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        height = try c.decode(UInt64.self, forKey: .height)
        blockHash = try nativeLaneByte32(c.decode(String.self, forKey: .blockHash), decoder, "block_hash")
        result = try nativeLaneByte32(c.decode(String.self, forKey: .result), decoder, "result")
    }
}

/// Mandatory signed RS16 geometry pinned into one lane incarnation.
public struct ToriiSumeragiDataAvailabilityLayout: Decodable, Sendable, Equatable {
    public let encoding: String
    public let chunkSizeBytes: UInt32
    public let dataShards: UInt16
    public let parityShards: UInt16
    public let maxPayloadSizeBytes: UInt64
    public let maxChunkCount: UInt32
    private enum CodingKeys: String, CodingKey {
        case encoding
        case chunkSizeBytes = "chunk_size_bytes"
        case dataShards = "data_shards"
        case parityShards = "parity_shards"
        case maxPayloadSizeBytes = "max_payload_size_bytes"
        case maxChunkCount = "max_chunk_count"
    }
    private enum EncodingKeys: String, CodingKey { case encoding, details }
    public init(from decoder: Decoder) throws {
        try requireNativeStatusFields(decoder, ["encoding", "chunk_size_bytes", "data_shards", "parity_shards", "max_payload_size_bytes", "max_chunk_count"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let encodingDecoder = try c.superDecoder(forKey: .encoding)
        try requireNativeStatusFields(encodingDecoder, ["encoding", "details"])
        let e = try encodingDecoder.container(keyedBy: EncodingKeys.self)
        encoding = try e.decode(String.self, forKey: .encoding)
        guard encoding == "reed_solomon16", try e.decodeNil(forKey: .details) else {
            throw nativeLaneFailure(decoder, "lane payload encoding must be Reed-Solomon16")
        }
        chunkSizeBytes = try c.decode(UInt32.self, forKey: .chunkSizeBytes)
        dataShards = try c.decode(UInt16.self, forKey: .dataShards)
        parityShards = try c.decode(UInt16.self, forKey: .parityShards)
        maxPayloadSizeBytes = try c.decode(UInt64.self, forKey: .maxPayloadSizeBytes)
        maxChunkCount = try c.decode(UInt32.self, forKey: .maxChunkCount)
        guard (2...262_144).contains(chunkSizeBytes), chunkSizeBytes % 2 == 0,
              (1...16).contains(dataShards), (1...16).contains(parityShards),
              (1...16_777_216).contains(maxPayloadSizeBytes), (1...1024).contains(maxChunkCount) else {
            throw nativeLaneFailure(decoder, "lane data-availability layout exceeds protocol bounds")
        }
        let stripeBytes = UInt64(dataShards) * UInt64(chunkSizeBytes)
        let full = maxPayloadSizeBytes / stripeBytes
        let remainder = maxPayloadSizeBytes % stripeBytes
        let stripes = full + (remainder > 0 ? 1 : 0)
        let terminalRow = 2 * ((remainder + 2 * UInt64(dataShards) - 1) / (2 * UInt64(dataShards)))
        let width = UInt64(dataShards) + UInt64(parityShards)
        guard stripes * width <= UInt64(maxChunkCount),
              (full * UInt64(chunkSizeBytes) + terminalRow) * width <= 33_554_432 else {
            throw nativeLaneFailure(decoder, "lane data-availability geometry exceeds protocol bounds")
        }
    }
}

/// The committed lifecycle record of one lane incarnation (`specs/sumeragi_lanes.md` §2.1).
public struct ToriiSumeragiLaneRecord: Decodable, Sendable, Equatable {
    public let lane: UInt32
    public let dataspace: UInt64
    public let incarnation: String
    public let params: ToriiSumeragiParameters
    public let daLayout: ToriiSumeragiDataAvailabilityLayout
    public let committee: [ToriiSumeragiLaneMember]
    public let createdAt: UInt64
    public let activeFrom: UInt64
    public let closing: UInt64?
    public let anchorFreshness: UInt64
    public let merged: ToriiSumeragiLaneFrontier
    public let mergedAt: UInt64
    public let rescued: UInt64
    public var isClosing: Bool { closing != nil }
    private enum CodingKeys: String, CodingKey {
        case lane
        case dataspace
        case incarnation
        case params
        case daLayout = "da_layout"
        case committee
        case createdAt = "created_at"
        case activeFrom = "active_from"
        case closing
        case anchorFreshness = "anchor_freshness"
        case merged
        case mergedAt = "merged_at"
        case rescued
    }
    public init(from decoder: Decoder) throws {
        try requireNativeStatusFields(decoder, ["lane", "dataspace", "incarnation", "params", "da_layout", "committee", "created_at", "active_from", "closing", "anchor_freshness", "merged", "merged_at", "rescued"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        lane = try c.decode(UInt32.self, forKey: .lane)
        dataspace = try c.decode(UInt64.self, forKey: .dataspace)
        incarnation = try nativeLaneByte32(c.decode(String.self, forKey: .incarnation), decoder, "incarnation")
        params = try c.decode(ToriiSumeragiParameters.self, forKey: .params)
        daLayout = try c.decode(ToriiSumeragiDataAvailabilityLayout.self, forKey: .daLayout)
        guard UInt64(params.maxBlockBytes) <= daLayout.maxPayloadSizeBytes else {
            throw nativeLaneFailure(decoder, "lane block limit exceeds its data-availability payload limit")
        }
        committee = try c.decode([ToriiSumeragiLaneMember].self, forKey: .committee)
        createdAt = try c.decode(UInt64.self, forKey: .createdAt)
        activeFrom = try c.decode(UInt64.self, forKey: .activeFrom)
        closing = try c.decodeIfPresent(UInt64.self, forKey: .closing)
        anchorFreshness = try c.decode(UInt64.self, forKey: .anchorFreshness)
        merged = try c.decode(ToriiSumeragiLaneFrontier.self, forKey: .merged)
        mergedAt = try c.decode(UInt64.self, forKey: .mergedAt)
        rescued = try c.decode(UInt64.self, forKey: .rescued)
    }
}

/// One lane as the node serves it (`GET /v1/sumeragi/lanes`): the committed record and the status
/// of the node's instance (`nil` while it runs none). This observation confers no finality.
public struct ToriiSumeragiLaneStatus: Decodable, Sendable, Equatable {
    /// Maximum JSON body accepted from the lane list route.
    public static let maximumJSONBytes = 16 * 1_048_576

    /// Bounded, duplicate-key and non-integral-token rejecting JSON list decoder.
    public static func parseJSONList(_ data: Data) throws -> [Self] {
        guard !data.isEmpty, data.count <= maximumJSONBytes else { throw CocoaError(.fileReadTooLarge) }
        try rejectNativeStatusSignedNumbers(data)
        try StrictJSONDuplicateKeyRejector.rejectDuplicateObjectKeys(in: data, requireAllNumbersInteger: true)
        return try JSONDecoder().decode([Self].self, from: data)
    }

    public let record: ToriiSumeragiLaneRecord
    public let instance: ToriiSumeragiStatusSnapshot?
    private enum CodingKeys: String, CodingKey {
        case record
        case instance
    }
    public init(from decoder: Decoder) throws {
        try requireNativeStatusFields(decoder, ["record", "instance"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        record = try c.decode(ToriiSumeragiLaneRecord.self, forKey: .record)
        instance = try c.decodeIfPresent(ToriiSumeragiStatusSnapshot.self, forKey: .instance)
    }
}
