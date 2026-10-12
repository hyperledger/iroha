import Foundation
import XCTest
@testable import IrohaSwift

private enum ParityHarnessError: Error {
    case encodingFailed
}

final class SorafsOrchestratorParityTests: XCTestCase {
    func testLocalFetchParityIsDeterministic() async throws {
        guard NoritoNativeBridge.shared.isAvailable else {
            XCTFail("ABI-29 NoritoBridge is required on this platform")
            return
        }

        let orchestratorFixture = try OrchestratorFixture.load()
        let planEnvelope = orchestratorFixture.plan
        XCTAssertEqual(planEnvelope.schema, "sorafs.chunk_fetch_plan.v1")
        XCTAssertEqual(planEnvelope.payloadDigestBlake3Hex.count, 64)
        let planSpecs = planEnvelope.chunkFetchSpecs
        let planJSON = try encodeJSONString(planEnvelope)
        let payloadBytes = try Data(contentsOf: orchestratorFixture.payloadURL())
        let maxChunkLength = planSpecs.map(\.length).max() ?? 0
        XCTAssertGreaterThan(maxChunkLength, 0)

        let tempDirectory = try createTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let providers = try orchestratorFixture.providerSpecs(at: tempDirectory, payload: payloadBytes)
        let providersJSON = try encodeJSONString(providers)

        let localProxy = LocalProxyOptionsPayload(
            proxyMode: "bridge",
            noritoBridge: LocalProxyNoritoBridgePayload(
                spoolDir: "/tmp/norito-spool",
                fileExtension: "norito"
            ),
            kaigiBridge: LocalProxyKaigiBridgePayload(
                spoolDir: "/tmp/kaigi-spool",
                fileExtension: "norito",
                roomPolicy: "authenticated"
            )
        )
        let options = orchestratorFixture.optionsPayload(
            telemetry: orchestratorFixture.telemetry,
            localProxy: localProxy
        )
        let optionsJSON = try encodeJSONString(options)
        XCTAssertTrue(optionsJSON.contains("\"local_proxy\""))
        XCTAssertTrue(optionsJSON.contains("\"kaigi_bridge\""))
        guard let optionsJSONData = optionsJSON.data(using: .utf8) else {
            XCTFail("Failed to encode options JSON data")
            return
        }
        let decoder = JSONDecoder()
        let optionsOverride = try decoder.decode(PolicyOverrideFixture.self, from: optionsJSONData)
        let expectedOverride = try PolicyOverrideFixture.load()
        XCTAssertEqual(optionsOverride.policyOverride, expectedOverride.policyOverride)

        let fetcher = SorafsOrchestratorClient()

        let firstStart = Date()
        let firstOutput = try await fetcher.fetchRaw(
            planJSON: planJSON,
            providersJSON: providersJSON,
            optionsJSON: optionsJSON
        )
        let firstDurationMs = Date().timeIntervalSince(firstStart) * 1_000.0

        let secondStart = Date()
        let secondOutput = try await fetcher.fetchRaw(
            planJSON: planJSON,
            providersJSON: providersJSON,
            optionsJSON: optionsJSON
        )
        let secondDurationMs = Date().timeIntervalSince(secondStart) * 1_000.0

        XCTAssertEqual(firstOutput.payload.count, orchestratorFixture.payloadLength())
        XCTAssertEqual(secondOutput.payload.count, orchestratorFixture.payloadLength())
        XCTAssertEqual(firstOutput.payload, secondOutput.payload)

        let firstReport = firstOutput.report
        let secondReport = secondOutput.report

        XCTAssertEqual(firstReport.chunkCount, planSpecs.count)
        XCTAssertEqual(secondReport.chunkCount, planSpecs.count)

        let normalizedFirst = firstReport.normalized()
        let normalizedSecond = secondReport.normalized()
        XCTAssertEqual(normalizedFirst, normalizedSecond)

        XCTAssertLessThanOrEqual(firstDurationMs, 2_000.0, "first parity run exceeded 2 s")
        XCTAssertLessThanOrEqual(secondDurationMs, 2_000.0, "second parity run exceeded 2 s")

        let peakReservedBytes = orchestratorFixture.options.maxParallel * maxChunkLength
        let formattedDuration = String(format: "%.2f", firstDurationMs)
        print(
            "Swift orchestrator parity: duration_ms=\(formattedDuration) " +
            "total_bytes=\(firstOutput.payload.count) " +
            "max_parallel=\(orchestratorFixture.options.maxParallel) " +
            "peak_reserved_bytes=\(peakReservedBytes)"
        )
    }

    func testGatewayOptionsEncodingIncludesRolloutPhase() throws {
        let options = SorafsGatewayFetchOptions(
            telemetryRegion: "ap-northeast-1",
            rolloutPhase: "ramp",
            transportPolicy: "soranet-first",
            anonymityPolicy: "anon-guard-pq",
            maxPeers: 3,
            retryBudget: 2,
            policyOverride: .init(anonymityPolicy: "anon-strict-pq")
        )
        let json = try options.jsonString()
        XCTAssertTrue(json.contains("\"rollout_phase\":\"ramp\""))
        XCTAssertTrue(json.contains("\"telemetry_region\":\"ap-northeast-1\""))
        XCTAssertTrue(json.contains("\"policy_override\""))
    }

    func testGatewayOptionsTrimTelemetryRegion() throws {
        let options = SorafsGatewayFetchOptions(telemetryRegion: "  iad-prod  ")
        let json = try options.jsonString()
        XCTAssertTrue(json.contains("\"telemetry_region\":\"iad-prod\""))

        let emptyOptions = SorafsGatewayFetchOptions(telemetryRegion: "   ")
        let emptyJSON = try emptyOptions.jsonString()
        XCTAssertFalse(emptyJSON.contains("telemetry_region"))
    }

    func testGatewayOptionsEncodingIncludesWriteMode() throws {
        let options = SorafsGatewayFetchOptions(writeMode: "  upload-pq-only  ")
        let json = try options.jsonString()
        XCTAssertTrue(json.contains("\"write_mode\":\"upload-pq-only\""))

        let emptyOptions = SorafsGatewayFetchOptions(writeMode: "   ")
        let emptyJSON = try emptyOptions.jsonString()
        XCTAssertFalse(emptyJSON.contains("write_mode"))
    }

    private func encodeJSONString<T: Encodable>(_ value: T) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(value)
        guard let json = String(data: data, encoding: .utf8) else {
            throw ParityHarnessError.encodingFailed
        }
        return json
    }

    private func createTemporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("sorafs-swift-parity-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

}

// MARK: - Fixtures and payloads

private enum SorafsFixturePaths {
    static var repoRoot: URL {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 {
            url.deleteLastPathComponent()
        }
        return url
    }

    static var policyOverrideURL: URL {
        repoRoot.appendingPathComponent("fixtures/sorafs_gateway/policy_override/override.json")
    }

    static var orchestratorRoot: URL {
        repoRoot.appendingPathComponent(
            "fixtures/sorafs_orchestrator/multi_peer_parity_v1",
            isDirectory: true
        )
    }

    static var orchestratorPlanURL: URL {
        orchestratorRoot.appendingPathComponent("plan.json")
    }

    static var orchestratorProvidersURL: URL {
        orchestratorRoot.appendingPathComponent("providers.json")
    }

    static var orchestratorTelemetryURL: URL {
        orchestratorRoot.appendingPathComponent("telemetry.json")
    }

    static var orchestratorOptionsURL: URL {
        orchestratorRoot.appendingPathComponent("options.json")
    }

    static var orchestratorMetadataURL: URL {
        orchestratorRoot.appendingPathComponent("metadata.json")
    }
}

// MARK: - JSON payloads

private struct PlanChunkSpec: Codable {
    let chunkIndex: Int
    let offset: Int
    let length: Int
    let digestBlake3: String

    enum CodingKeys: String, CodingKey {
        case chunkIndex = "chunk_index"
        case offset
        case length
        case digestBlake3 = "digest_blake3"
    }
}

private struct ChunkFetchPlanFixture: Codable {
    let schema: String
    let payloadDigestBlake3Hex: String
    let chunkFetchSpecs: [PlanChunkSpec]

    enum CodingKeys: String, CodingKey {
        case schema
        case payloadDigestBlake3Hex = "payload_digest_blake3_hex"
        case chunkFetchSpecs = "chunk_fetch_specs"
    }
}

private struct OrchestratorFixture {
    struct OptionsFixture: Decodable {
        let verifyDigests: Bool
        let verifyLengths: Bool
        let retryBudget: Int
        let providerFailureThreshold: Int
        let maxParallel: Int
        let maxPeers: Int
        let useScoreboard: Bool
        let returnScoreboard: Bool
        let scoreboard: ScoreboardFixture
        let rolloutPhase: String?
        let policyOverride: PolicyOverridePayload?

        enum CodingKeys: String, CodingKey {
            case verifyDigests = "verify_digests"
            case verifyLengths = "verify_lengths"
            case retryBudget = "retry_budget"
            case providerFailureThreshold = "provider_failure_threshold"
            case maxParallel = "max_parallel"
            case maxPeers = "max_peers"
            case useScoreboard = "use_scoreboard"
            case returnScoreboard = "return_scoreboard"
            case scoreboard
            case rolloutPhase = "rollout_phase"
            case policyOverride = "policy_override"
        }
    }

    struct ScoreboardFixture: Decodable {
        let nowUnixSecs: UInt64

        enum CodingKeys: String, CodingKey {
            case nowUnixSecs = "now_unix_secs"
        }
    }

    struct Metadata: Decodable {
        let payloadPath: String
        let payloadBytes: Int

        enum CodingKeys: String, CodingKey {
            case payloadPath = "payload_path"
            case payloadBytes = "payload_bytes"
        }

        func payloadURL() -> URL {
            URL(fileURLWithPath: payloadPath, relativeTo: SorafsFixturePaths.repoRoot)
        }
    }

    let plan: ChunkFetchPlanFixture
    let providers: [ProviderMetadata]
    let telemetry: [TelemetryEntry]
    let options: OptionsFixture
    let metadata: Metadata

    static func load() throws -> OrchestratorFixture {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .useDefaultKeys

        let planData = try Data(contentsOf: SorafsFixturePaths.orchestratorPlanURL)
        let plan = try decoder.decode(ChunkFetchPlanFixture.self, from: planData)

        let providersData = try Data(contentsOf: SorafsFixturePaths.orchestratorProvidersURL)
        let providers = try decoder.decode([ProviderMetadata].self, from: providersData)

        let telemetryData = try Data(contentsOf: SorafsFixturePaths.orchestratorTelemetryURL)
        let telemetry = try decoder.decode([TelemetryEntry].self, from: telemetryData)

        let optionsData = try Data(contentsOf: SorafsFixturePaths.orchestratorOptionsURL)
        let options = try decoder.decode(OptionsFixture.self, from: optionsData)

        let metadataData = try Data(contentsOf: SorafsFixturePaths.orchestratorMetadataURL)
        let metadata = try decoder.decode(Metadata.self, from: metadataData)

        return OrchestratorFixture(
            plan: plan,
            providers: providers,
            telemetry: telemetry,
            options: options,
            metadata: metadata
        )
    }

    func payloadURL() -> URL {
        metadata.payloadURL()
    }

    func payloadLength() -> Int {
        metadata.payloadBytes
    }

    func providerSpecs(at directory: URL, payload: Data) throws -> [ProviderSpec] {
        try providers.map { provider in
            let fileURL = directory.appendingPathComponent("\(provider.providerID).bin")
            try payload.write(to: fileURL, options: .atomic)
            return ProviderSpec(
                name: provider.providerID,
                path: fileURL.path,
                maxConcurrent: 2,
                weight: 1,
                metadata: provider
            )
        }
    }

    func optionsPayload(
        telemetry: [TelemetryEntry],
        localProxy: LocalProxyOptionsPayload?
    ) -> LocalFetchOptionsPayload {
        LocalFetchOptionsPayload(
            verifyDigests: options.verifyDigests,
            verifyLengths: options.verifyLengths,
            retryBudget: options.retryBudget,
            providerFailureThreshold: options.providerFailureThreshold,
            maxParallel: options.maxParallel,
            maxPeers: options.maxPeers,
            telemetry: telemetry,
            useScoreboard: options.useScoreboard,
            scoreboardNowUnixSecs: options.scoreboard.nowUnixSecs,
            returnScoreboard: options.returnScoreboard,
            localProxy: localProxy,
            rolloutPhase: options.rolloutPhase,
            policyOverride: options.policyOverride
        )
    }
}

private struct ProviderSpec: Encodable {
    let name: String
    let path: String
    let maxConcurrent: Int
    let weight: Int
    let metadata: ProviderMetadata

    enum CodingKeys: String, CodingKey {
        case name
        case path
        case maxConcurrent = "max_concurrent"
        case weight
        case metadata
    }
}

private struct ProviderMetadata: Codable {
    let providerID: String
    let profileAliases: [String]
    let availability: String
    let allowUnknownCapabilities: Bool
    let capabilityNames: [String]
    let rangeCapability: RangeCapability
    let streamBudget: StreamBudget
    let refreshDeadline: UInt64
    let expiresAt: UInt64
    let ttlSecs: UInt64
    let notes: String
    let transportHints: [TransportHint]

    enum CodingKeys: String, CodingKey {
        case providerID = "provider_id"
        case profileAliases = "profile_aliases"
        case availability
        case allowUnknownCapabilities = "allow_unknown_capabilities"
        case capabilityNames = "capability_names"
        case rangeCapability = "range_capability"
        case streamBudget = "stream_budget"
        case refreshDeadline = "refresh_deadline"
        case expiresAt = "expires_at"
        case ttlSecs = "ttl_secs"
        case notes
        case transportHints = "transport_hints"
    }
}

private struct RangeCapability: Codable {
    let maxChunkSpan: Int
    let minGranularity: Int
    let supportsSparseOffsets: Bool
    let requiresAlignment: Bool
    let supportsMerkleProof: Bool

    enum CodingKeys: String, CodingKey {
        case maxChunkSpan = "max_chunk_span"
        case minGranularity = "min_granularity"
        case supportsSparseOffsets = "supports_sparse_offsets"
        case requiresAlignment = "requires_alignment"
        case supportsMerkleProof = "supports_merkle_proof"
    }
}

private struct StreamBudget: Codable {
    let maxInFlight: Int
    let maxBytesPerSec: Int
    let burstBytes: Int

    enum CodingKeys: String, CodingKey {
        case maxInFlight = "max_in_flight"
        case maxBytesPerSec = "max_bytes_per_sec"
        case burstBytes = "burst_bytes"
    }
}

private struct TransportHint: Codable {
    let `protocol`: String
    let protocolID: Int
    let priority: Int

    enum CodingKeys: String, CodingKey {
        case `protocol` = "protocol"
        case protocolID = "protocol_id"
        case priority
    }
}

private struct TelemetryEntry: Codable {
    let providerID: String
    let qosScore: Double
    let latencyP95Ms: Double
    let failureRateEwma: Double
    let tokenHealth: Double
    let stakingWeight: Double
    let penalty: Bool
    let lastUpdatedUnix: UInt64

    enum CodingKeys: String, CodingKey {
        case providerID = "provider_id"
        case qosScore = "qos_score"
        case latencyP95Ms = "latency_p95_ms"
        case failureRateEwma = "failure_rate_ewma"
        case tokenHealth = "token_health"
        case stakingWeight = "staking_weight"
        case penalty
        case lastUpdatedUnix = "last_updated_unix"
    }
}

private struct LocalFetchOptionsPayload: Encodable {
    let verifyDigests: Bool
    let verifyLengths: Bool
    let retryBudget: Int
    let providerFailureThreshold: Int
    let maxParallel: Int
    let maxPeers: Int
    let telemetry: [TelemetryEntry]
    let useScoreboard: Bool
    let scoreboardNowUnixSecs: UInt64
    let returnScoreboard: Bool
    let localProxy: LocalProxyOptionsPayload?
    let rolloutPhase: String?
    let policyOverride: PolicyOverridePayload?

    enum CodingKeys: String, CodingKey {
        case verifyDigests = "verify_digests"
        case verifyLengths = "verify_lengths"
        case retryBudget = "retry_budget"
        case providerFailureThreshold = "provider_failure_threshold"
        case maxParallel = "max_parallel"
        case maxPeers = "max_peers"
        case telemetry
        case useScoreboard = "use_scoreboard"
        case scoreboardNowUnixSecs = "scoreboard_now_unix_secs"
        case returnScoreboard = "return_scoreboard"
        case localProxy = "local_proxy"
        case rolloutPhase = "rollout_phase"
        case policyOverride = "policy_override"
    }
}

private struct PolicyOverridePayload: Codable, Equatable {
    let transportPolicy: String
    let anonymityPolicy: String

    enum CodingKeys: String, CodingKey {
        case transportPolicy = "transport_policy"
        case anonymityPolicy = "anonymity_policy"
    }
}

private struct PolicyOverrideFixture: Decodable, Equatable {
    let policyOverride: PolicyOverridePayload

    enum CodingKeys: String, CodingKey {
        case policyOverride = "policy_override"
    }

    static func load() throws -> PolicyOverrideFixture {
        let data = try Data(contentsOf: SorafsFixturePaths.policyOverrideURL)
        let decoder = JSONDecoder()
        return try decoder.decode(PolicyOverrideFixture.self, from: data)
    }
}

private struct LocalProxyOptionsPayload: Encodable {
    let proxyMode: String?
    let noritoBridge: LocalProxyNoritoBridgePayload?
    let kaigiBridge: LocalProxyKaigiBridgePayload?

    enum CodingKeys: String, CodingKey {
        case proxyMode = "proxy_mode"
        case noritoBridge = "norito_bridge"
        case kaigiBridge = "kaigi_bridge"
    }
}

private struct LocalProxyNoritoBridgePayload: Encodable {
    let spoolDir: String
    let fileExtension: String?

    enum CodingKeys: String, CodingKey {
        case spoolDir = "spool_dir"
        case fileExtension = "extension"
    }
}

private struct LocalProxyKaigiBridgePayload: Encodable {
    let spoolDir: String
    let fileExtension: String?
    let roomPolicy: String?

    enum CodingKeys: String, CodingKey {
        case spoolDir = "spool_dir"
        case fileExtension = "extension"
        case roomPolicy = "room_policy"
    }
}

// MARK: - Report decoding

private struct NormalizedReport: Equatable {
    let chunkCount: Int
    let providerReports: [SorafsGatewayFetchReport.ProviderReport]
    let chunkReceipts: [NormalizedChunkReceipt]
    let scoreboard: [SorafsGatewayFetchReport.ScoreboardEntry]
}

private struct NormalizedChunkReceipt: Equatable {
    let chunkIndex: Int
    let provider: String
    let attempts: Int
    let bytes: Int
}

private extension SorafsGatewayFetchReport {
    func normalized() -> NormalizedReport {
        let sortedReports = providerReports.sorted { $0.provider < $1.provider }
        let sortedReceipts = chunkReceipts.sorted {
            if $0.chunkIndex == $1.chunkIndex {
                return $0.provider < $1.provider
            }
            return $0.chunkIndex < $1.chunkIndex
        }.map {
            NormalizedChunkReceipt(
                chunkIndex: $0.chunkIndex,
                provider: $0.provider,
                attempts: $0.attempts,
                bytes: $0.bytes
            )
        }
        let sortedScoreboard = (scoreboard ?? []).sorted {
            if $0.providerID == $1.providerID {
                return $0.alias < $1.alias
            }
            return $0.providerID < $1.providerID
        }
        return NormalizedReport(
            chunkCount: chunkCount,
            providerReports: sortedReports,
            chunkReceipts: sortedReceipts,
            scoreboard: sortedScoreboard
        )
    }
}
