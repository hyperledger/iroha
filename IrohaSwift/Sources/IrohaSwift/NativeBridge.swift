import Foundation
import CryptoKit
#if IROHASWIFT_LOCAL_UNIT_ARTIFACT
#if !os(macOS)
#error("A local-unit NoritoBridge artifact is restricted to macOS Swift tests.")
#endif
#if !IROHASWIFT_LOCAL_UNIT_DEBUG
#error("A local-unit NoritoBridge artifact cannot enter a Release build.")
#endif
#endif
#if canImport(Darwin)
import Darwin
#if IROHASWIFT_BRIDGE_PRESENT
import NoritoBridge
#endif
#if SWIFT_PACKAGE
import NoritoBridgeRetention
#endif

enum BridgePolicyHint {
    private static let relativeBridgePath = "../dist/NoritoBridge.xcframework"

    static var message: String {
        "NoritoBridge.xcframework is required under \(relativeBridgePath) for native helpers."
    }

    static func unavailableMessage(_ prefix: String) -> String {
        "\(prefix) \(message)"
    }
}

struct SorafsLocalFetchOutput {
    let payload: Data
    let reportJSON: String
}

struct NativeSorafsOrderbookOrderRequestFields {
    let orderId: Data
    let side: UInt32
    let tier: UInt32
    let pricePerGib: String
    let quantityGib: UInt64
    let remainingGib: UInt64
    let ownerAccount: Data
    let providerId: Data
    let expiryUnix: UInt64
    let nonce: UInt64
    let makerFeeBps: UInt32
    let takerFeeBps: UInt32
}

struct NativeSorafsOrderbookOrderCancelFields {
    let orderId: Data
    let ownerAccount: Data
    let reason: UInt32
    let nonce: UInt64
}

struct NativeSorafsOrderbookSettlementReceiptFields {
    let receiptId: Data
    let channelId: Data
    let tradeId: Data
    let rangeStart: UInt64
    let rangeEnd: UInt64
    let chunkHash: Data
    let bytesDelivered: UInt64
    let xorDebited: String
    let providerCredit: String
    let feeAmount: String
    let issuedAtUnix: UInt64
}

private struct NativeSorafsReferenceInput {
    let bytesPointer: UnsafePointer<UInt8>?
    let bytesLength: CUnsignedLong
    let labelPointer: UnsafePointer<UInt8>?
    let labelLength: CUnsignedLong
}

private struct NativeSorafsReferenceBundleInput {
    let kind: UInt32
    let bytesPointer: UnsafePointer<UInt8>?
    let bytesLength: CUnsignedLong
    let labelPointer: UnsafePointer<UInt8>?
    let labelLength: CUnsignedLong
}

enum NoritoBridgeLoader {
    enum ValidationStatus: Equatable {
        case valid(path: String, identifier: String)
        case pathDenied(path: String)
        case missing(path: String)
        case hashMismatch(path: String, expected: String, actual: String?)
        case versionMismatch(path: String, expected: String, actual: String?)
        case abiMismatch(path: String, expected: UInt32, actual: UInt32?)
    }

    static let expectedVersion = "0.1.0"
    static var expectedBridgeAbiVersion: UInt32 {
        expectedBridgeAbiVersion(for: currentIdentifier())
    }
    private static let expectedHashes: [String: String] = [
        "macos-arm64_x86_64": "4018b7967ed842dd096ee26d71b20a2e601e80f4c5b609ce72b1e15f3d9e4f54",
        "ios-arm64": "fe36df91b0a1d2d2e26650f84da8d744634933a872443fe02343f2791a3dcff9",
        "ios-arm64_x86_64-simulator": "c4b4a7deeb226643a54b11954aa7d6b0df1a5614ffb14fb9330d3eaefe3ff3a8"
    ]
    static let parliamentTimedOvnWalletRequiredSymbols = [
        "connect_norito_parliament_timed_ovn_verify_casting_proof_page_v1",
        "connect_norito_parliament_timed_ovn_verify_casting_proof_v1",
        "connect_norito_parliament_timed_ovn_registration_from_proof_v1",
        "connect_norito_parliament_timed_ovn_ballot_from_proof_v1"
    ]
    static let accelerationRequiredSymbols = [
        "connect_norito_acceleration_config_set_v1",
        "connect_norito_acceleration_config_get_v1",
        "connect_norito_acceleration_state_get_v1"
    ]
    // ML-DSA is owned by the mandatory soranet_pq/pqc native dependency.
    static let mldsaRequiredSymbols = [
        "soranet_mldsa_parameters",
        "soranet_mldsa_generate_keypair",
        "soranet_mldsa_sign",
        "soranet_mldsa_verify"
    ]
    private static let requiredSymbols = [
        "connect_norito_bridge_abi_version",
        "connect_norito_free",
        "connect_norito_encode_transfer_signed_transaction",
        "connect_norito_encode_governance_update_plain_conviction_signed_transaction_alg",
        "connect_norito_encode_transfer_instruction_box",
        "connect_norito_detached_transaction_scaffold_inspect_v1",
        "connect_norito_detached_transaction_scaffold_finalize_ed25519_v1",
        "connect_norito_canonical_json_blake3_v1",
        "connect_norito_encode_account_onboarding_plan_body_v1",
        "connect_norito_alias_instruction_round_trip_v1",
        "connect_norito_account_read_permission_multisig_payload_hash",
        "connect_norito_account_read_permission_multisig_finalize",
        "connect_norito_committed_transaction_query_payload_hash_v1",
        "connect_norito_committed_transaction_query_finalize_v1",
        "connect_norito_verify_committed_transaction_inclusion_v1",
        "connect_norito_committed_transaction_candidate_block_hash_v1",
        "iroha_privacy_compiled_profile_catalog_v1",
        "iroha_privacy_validate_compiled_profile_catalog_v1",
        "iroha_privacy_validate_exact12_capability_manifest_v1",
        "iroha_privacy_exact12_fixture_bundle_v1",
        "iroha_privacy_validate_exact12_fixture_bundle_v1",
        "iroha_privacy_free_buffer",
        "connect_norito_sorafs_reference_validate_appeal_finance_cancel_asset_lock_json",
        "connect_norito_sorafs_reference_validate_bundle_json",
        "connect_norito_sorafs_reference_validate_governance_json",
        "connect_norito_sorafs_reference_validate_governance_dag_block_json",
        "connect_norito_sorafs_reference_validate_governance_dag_head_chain_json",
        "connect_norito_retail_fee_intent_hash_v1",
        "connect_norito_retail_fee_assessment_marker_v1",
        "connect_norito_retail_fee_assessment_decode_v1",
        "connect_norito_private_settlement_committee_proof_response_verify_v1",
        "connect_norito_private_settlement_auditor_capsule_response_verify_with_request_v1",
        "connect_norito_private_settlement_audit_approval_response_verify_v1"
    ] + parliamentTimedOvnWalletRequiredSymbols + accelerationRequiredSymbols + mldsaRequiredSymbols

    private typealias BridgeAbiVersionFn = @convention(c) () -> UInt32

    private struct ArtifactManifest {
        let version: String
        let bridgeAbiVersion: UInt32?
        let hashes: [String: String]
    }

    static func expectedBridgeAbiVersion(for identifier: String) -> UInt32 {
        return 25
    }

    static func isSupportedBridgeAbiVersion(_ actual: UInt32?, for identifier: String = currentIdentifier()) -> Bool {
        guard let actual else {
            return false
        }
        return actual == expectedBridgeAbiVersion(for: identifier)
    }

    private static func packagedBinaryRelativePaths(for identifier: String = currentIdentifier()) -> [String] {
        return ["libNoritoBridge.a", "NoritoBridge.framework/NoritoBridge"]
    }

    static func openHandle() -> (UnsafeMutableRawPointer?, ValidationStatus) {
        #if SWIFT_PACKAGE
        // The direct C call roots every dynamically resolved native export;
        // the loader still authenticates the exact symbols and ABI below.
        _ = iroha_norito_bridge_retain_exports()
        #endif
        // Xcode 26 debug-dylib: app code lives in <name>.debug.dylib, not the main executable.
        // dlopen(nil) returns a handle to the 57 KB launcher image. It may re-export a few symbols
        // (e.g. connect_norito_free) so the dlsym probe succeeds, but calling heavier functions
        // through that image crashes. Always prefer the debug dylib.
        if let execURL = Bundle.main.executableURL {
            let debugDylibURL = execURL.deletingLastPathComponent()
                .appendingPathComponent(execURL.lastPathComponent + ".debug.dylib")
            let exists = FileManager.default.fileExists(atPath: debugDylibURL.path)
            NSLog("[NoritoBridgeLoader] debug dylib path=%@ exists=%d", debugDylibURL.path, exists ? 1 : 0)
            if exists {
                let debugHandle = debugDylibURL.path.withCString { ptr in
                    dlopen(ptr, RTLD_NOW | RTLD_GLOBAL)
                }
                let abiVersion = bridgeAbiVersion(in: debugHandle)
                let hasCurrentAbi = hasRequiredSymbols(in: debugHandle)
                let hasTransfer = debugHandle.flatMap {
                    dlsym($0, "connect_norito_encode_transfer_signed_transaction")
                } != nil
                NSLog(
                    "[NoritoBridgeLoader] debug dylib handle=%@, hasCurrentAbi=%d, abi=%@, hasTransfer=%d",
                    debugHandle == nil ? "nil" : "ok",
                    hasCurrentAbi ? 1 : 0,
                    abiVersion.map(String.init) ?? "nil",
                    hasTransfer ? 1 : 0
                )
                if let debugHandle, hasCurrentAbi, hasTransfer {
                    return (debugHandle, .valid(path: "debug.dylib", identifier: currentIdentifier()))
                }
                if let debugHandle {
                    dlclose(debugHandle)
                }
            }
        } else {
            NSLog("[NoritoBridgeLoader] Bundle.main.executableURL is nil")
        }

        if let executableURL = Bundle.main.executableURL,
           let executableHandle = openImageIfSymbolsPresent(at: executableURL) {
            NSLog("[NoritoBridgeLoader] loaded bridge symbols from main executable %@", executableURL.path)
            return (executableHandle, .valid(path: executableURL.path, identifier: currentIdentifier()))
        }

        if let defaultHandle = rtldDefaultHandle(),
           hasRequiredSymbols(in: defaultHandle) {
            NSLog("[NoritoBridgeLoader] loaded bridge symbols from RTLD_DEFAULT")
            return (defaultHandle, .valid(path: "RTLD_DEFAULT", identifier: currentIdentifier()))
        }

        var lastFailure: ValidationStatus = .missing(path: defaultBridgeBinaryPath())
        for path in candidateLibraryPaths() {
            let status = validateBridge(at: path, allowUntrustedLocation: false)
            switch status {
            case .valid:
                let handle = path.withCString { pointer in
                    dlopen(pointer, RTLD_NOW | RTLD_GLOBAL)
                }
                if let handle,
                   hasRequiredSymbols(in: handle) {
                    return (handle, status)
                }
                let actualAbi = bridgeAbiVersion(in: handle)
                if let handle {
                    dlclose(handle)
                }
                lastFailure = .abiMismatch(
                    path: path,
                    expected: expectedBridgeAbiVersion,
                    actual: actualAbi
                )
            default:
                lastFailure = status
            }
        }

        if let defaultHandle = dlopen(nil, RTLD_NOW | RTLD_GLOBAL),
           hasRequiredSymbols(in: defaultHandle) {
            NSLog("[NoritoBridgeLoader] loaded bridge symbols from dlopen(nil)")
            return (defaultHandle, .valid(path: "RTLD_DEFAULT", identifier: currentIdentifier()))
        }

        return (nil, lastFailure)
    }

    private static func rtldDefaultHandle() -> UnsafeMutableRawPointer? {
        UnsafeMutableRawPointer(bitPattern: UInt(bitPattern: -2))
    }

    static func hasRequiredExports(resolving resolve: (String) -> Bool) -> Bool {
        requiredSymbols.allSatisfy(resolve)
    }

    private static func hasRequiredSymbols(in handle: UnsafeMutableRawPointer?) -> Bool {
        guard let handle, hasRequiredExports(resolving: { dlsym(handle, $0) != nil }) else { return false }
        return isSupportedBridgeAbiVersion(bridgeAbiVersion(in: handle))
    }

    private static func bridgeAbiVersion(in handle: UnsafeMutableRawPointer?) -> UInt32? {
        guard let handle,
              let symbol = dlsym(handle, "connect_norito_bridge_abi_version") else {
            return nil
        }
        let function = unsafeBitCast(symbol, to: BridgeAbiVersionFn.self)
        return function()
    }

    private static func openImageIfSymbolsPresent(at url: URL) -> UnsafeMutableRawPointer? {
        let handle = url.path.withCString { pointer in
            dlopen(pointer, RTLD_NOW | RTLD_GLOBAL)
        }
        guard hasRequiredSymbols(in: handle) else {
            if let handle {
                dlclose(handle)
            }
            return nil
        }
        return handle
    }

    static func validateForTests(at path: String, allowUntrustedLocation: Bool = true) -> ValidationStatus {
        validateBridge(at: path, allowUntrustedLocation: allowUntrustedLocation)
    }

    static func validateForTests(
        at path: String,
        allowUntrustedLocation: Bool,
        pinnedHashesForTests: [String: String]
    ) -> ValidationStatus {
        validateBridge(
            at: path,
            allowUntrustedLocation: allowUntrustedLocation,
            pinnedHashes: pinnedHashesForTests
        )
    }

    private static func validateBridge(
        at path: String,
        allowUntrustedLocation: Bool,
        pinnedHashes: [String: String] = expectedHashes
    ) -> ValidationStatus {
        let url = URL(fileURLWithPath: path)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return .missing(path: path)
        }
        guard allowUntrustedLocation || isTrustedLocation(url) else {
            return .pathDenied(path: path)
        }
        guard let identifier = identifier(for: url) else {
            return .pathDenied(path: path)
        }

        let manifest = artifactManifest(near: url)
        if let version = manifest?.version, version != expectedVersion {
            return .versionMismatch(path: path, expected: expectedVersion, actual: version)
        }
        if let manifest,
           manifest.bridgeAbiVersion != expectedBridgeAbiVersion(for: identifier) {
            return .abiMismatch(
                path: path,
                expected: expectedBridgeAbiVersion(for: identifier),
                actual: manifest.bridgeAbiVersion
            )
        }
        guard let expectedHash = manifest?.hashes[identifier] ?? pinnedHashes[identifier] else {
            return .pathDenied(path: path)
        }

        let actualHash = sha256(url: url)
        if actualHash != expectedHash {
            return .hashMismatch(path: path, expected: expectedHash, actual: actualHash)
        }

        return .valid(path: path, identifier: identifier)
    }

    private static func artifactManifest(near binaryURL: URL) -> ArtifactManifest? {
        let candidates = candidateArtifactManifestURLs(near: binaryURL)
        for candidate in candidates {
            if let manifest = parseArtifactManifest(at: candidate) {
                return manifest
            }
        }
        return nil
    }

    private static let artifactManifestMaxAscents = 64

    static func candidateArtifactManifestURLsForTests(near binaryURL: URL, maxAscents: Int) -> [URL] {
        candidateArtifactManifestURLs(near: binaryURL, maxAscents: maxAscents)
    }

    private static func candidateArtifactManifestURLs(
        near binaryURL: URL,
        maxAscents: Int = artifactManifestMaxAscents
    ) -> [URL] {
        var seen = Set<String>()
        var candidates: [URL] = []
        var cursor = binaryURL.deletingLastPathComponent()

        // Bound the ascent because Foundation URL normalization may not converge
        // at the filesystem root on every platform.
        for _ in 0..<max(0, maxAscents) {
            if cursor.pathExtension == "xcframework" {
                let urls = [
                    cursor.appendingPathComponent("NoritoBridge.artifacts.json"),
                    cursor.deletingLastPathComponent().appendingPathComponent("NoritoBridge.artifacts.json")
                ]
                for url in urls where !seen.contains(url.path) {
                    seen.insert(url.path)
                    candidates.append(url)
                }
            }
            let parent = cursor.deletingLastPathComponent()
            if parent.path == cursor.path {
                break
            }
            cursor = parent
        }

        if candidates.isEmpty {
            let defaultCandidates = [
                binaryURL.deletingLastPathComponent().appendingPathComponent("NoritoBridge.artifacts.json"),
                binaryURL.deletingLastPathComponent().deletingLastPathComponent()
                    .appendingPathComponent("NoritoBridge.artifacts.json")
            ]
            for url in defaultCandidates where !seen.contains(url.path) {
                seen.insert(url.path)
                candidates.append(url)
            }
        }

        return candidates
    }

    private static func parseArtifactManifest(at url: URL) -> ArtifactManifest? {
        guard let data = try? Data(contentsOf: url),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let version = json["version"] as? String else {
            return nil
        }
        let hashes = json["hashes"] as? [String: String] ?? [:]
        return ArtifactManifest(
            version: version,
            bridgeAbiVersion: json["native_bridge_abi_version"] as? UInt32,
            hashes: hashes
        )
    }

    private static func sha256(url: URL) -> String? {
        guard let data = try? Data(contentsOf: url) else {
            return nil
        }
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private static func identifier(for url: URL) -> String? {
        for key in expectedHashes.keys {
            if url.path.contains("/\(key)/") {
                return key
            }
        }
        return currentIdentifier()
    }

    static func currentIdentifier() -> String {
        #if os(macOS)
        return "macos-arm64_x86_64"
        #else
        #if targetEnvironment(simulator)
        return "ios-arm64_x86_64-simulator"
        #else
        return "ios-arm64"
        #endif
        #endif
    }

    private static func isTrustedLocation(_ url: URL) -> Bool {
        let allowedRoots = trustedSearchRoots()
        return allowedRoots.contains { url.path.hasPrefix($0.path) }
    }

    private static func candidateLibraryPaths() -> [String] {
        var seen = Set<String>()
        var paths: [String] = []

        func addIfExisting(_ url: URL) {
            let path = url.path
            guard FileManager.default.fileExists(atPath: path), !seen.contains(path) else {
                return
            }
            seen.insert(path)
            paths.append(path)
        }

        for framework in Bundle.allFrameworks
            where framework.bundleURL.lastPathComponent == "NoritoBridge.framework" {
            if let executableURL = framework.executableURL {
                addIfExisting(executableURL)
            }
        }

        for root in trustedSearchRoots() {
            for relativePath in packagedBinaryRelativePaths() {
                addIfExisting(root.appendingPathComponent(relativePath))
            }
        }

        return paths
    }

    private static func trustedSearchRoots() -> [URL] {
        var roots: [URL] = []
        let bundleRoots = Bundle.allBundles + Bundle.allFrameworks
        for bundle in bundleRoots {
            roots.append(bundle.bundleURL)
            roots.append(bundle.bundleURL.deletingLastPathComponent())
        }

        if let mainBundleURL = Bundle.main.bundleURL as URL? {
            roots.append(mainBundleURL.deletingLastPathComponent())
            roots.append(mainBundleURL.appendingPathComponent("Frameworks"))
            if let privateFrameworks = Bundle.main.privateFrameworksPath {
                roots.append(URL(fileURLWithPath: privateFrameworks))
            }
        }

        if let executableURL = Bundle.main.executableURL {
            roots.append(executableURL.deletingLastPathComponent()
                .appendingPathComponent("Frameworks"))
            roots.append(executableURL.deletingLastPathComponent().deletingLastPathComponent()
                .appendingPathComponent("Frameworks"))
        }

        // XCTest and simulator launches often expose the real build-products directory through
        // dyld environment variables even when the app bundle only embeds a thin framework shell.
        let processInfo = ProcessInfo.processInfo
        for key in ["BUILT_PRODUCTS_DIR", "DYLD_FRAMEWORK_PATH", "DYLD_LIBRARY_PATH"] {
            guard let rawValue = processInfo.environment[key]?
                .trimmingCharacters(in: .whitespacesAndNewlines),
                  !rawValue.isEmpty else {
                continue
            }
            for component in rawValue.split(separator: ":") {
                let path = String(component).trimmingCharacters(in: .whitespacesAndNewlines)
                guard !path.isEmpty else { continue }
                roots.append(URL(fileURLWithPath: path))
            }
        }

        let sourceFile = URL(fileURLWithPath: #filePath)
        var root = sourceFile
        for _ in 0..<4 {
            root.deleteLastPathComponent()
        }
        roots.append(root.appendingPathComponent("dist/NoritoBridge.xcframework/\(currentIdentifier())"))

        var deduped: [URL] = []
        var seen = Set<String>()
        for url in roots {
            let path = url.standardized.path
            if !seen.contains(path) {
                seen.insert(path)
                deduped.append(URL(fileURLWithPath: path))
            }
        }
        return deduped
    }

    private static func defaultBridgeBinaryPath() -> String {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 {
            root.deleteLastPathComponent()
        }
        let sliceRoot = root
            .appendingPathComponent("dist/NoritoBridge.xcframework")
            .appendingPathComponent(currentIdentifier())
        for relativePath in packagedBinaryRelativePaths() {
            let candidate = sliceRoot.appendingPathComponent(relativePath)
            if FileManager.default.fileExists(atPath: candidate.path) {
                return candidate.path
            }
        }
        return sliceRoot.appendingPathComponent(packagedBinaryRelativePaths().first ?? "libNoritoBridge.a").path
    }
}

private extension ConnectFrame {
    var ciphertextPayload: Data? {
        if case .ciphertext(let ciphertext) = kind {
            return ciphertext.payload
        }
        return nil
    }
}


#endif

struct NativeSignedTransaction {
    let signedBytes: Data
    let hash: Data
}

struct NativeAccountAddressParseResult {
    let canonicalBytes: Data
    let networkPrefix: UInt16?
}

struct NativeAccountAddressRenderResult {
    let canonicalHex: String
    let i105: String
}

struct NativeAliasInstructionRoundTripResult {
    let framedPayload: Data
    let typedJSON: Data
}

/// Opaque caller-owned source of one 32-byte Parliament timed-OVN root seed.
///
/// Implementations should retain the seed in Keychain or a Secure Enclave-backed
/// wrapping scheme and expose it only for the duration of `body`. The SDK never
/// serializes, persists, or logs the bytes supplied through this handle.
public protocol ParliamentTimedOvnSeedHandle: Sendable {
    /// Borrow the seed for one native wallet operation without transferring ownership.
    func withUnsafeSeedBytes(
        _ body: (UnsafeRawBufferPointer) throws -> Data
    ) throws -> Data
}

/// Closed V1 choice set accepted by the native Parliament timed-OVN wallet.
public enum ParliamentTimedOvnBallotChoiceV1: UInt8, Sendable {
    /// Approve the proposal.
    case aye = 0
    /// Reject the proposal.
    case nay = 1
    /// Record an explicit abstention.
    case abstain = 2
}

/// Immutable external trust anchor for one Parliament timed-OVN casting proof.
public struct ParliamentTimedOvnCastingTrustAnchorV1: Equatable, Sendable {
    private let networkIDBytes: [UInt8]
    /// Positive request-height hint; native verification authenticates the complete checkpoint.
    public let trustedCheckpointHeight: UInt64
    private let checkpointBytes: [UInt8]
    private let ballotAttemptIDBytes: [UInt8]

    /// Create a complete network/checkpoint/ballot anchor; no field has a default.
    public init(
        networkID: Data,
        trustedCheckpointHeight: UInt64,
        trustedCheckpointNorito: Data,
        expectedBallotAttemptID: Data
    ) throws {
        guard networkID.count == 32,
              trustedCheckpointHeight > 0,
              !trustedCheckpointNorito.isEmpty && trustedCheckpointNorito.count <= 68 * 1024 * 1024,
              expectedBallotAttemptID.count == 32,
              expectedBallotAttemptID.contains(where: { $0 != 0 }) else {
            throw ParliamentTimedOvnNativeWalletError.invalidTrustAnchor
        }
        self.networkIDBytes = Array(networkID)
        self.trustedCheckpointHeight = trustedCheckpointHeight
        self.checkpointBytes = Array(trustedCheckpointNorito)
        self.ballotAttemptIDBytes = Array(expectedBallotAttemptID)
    }

    /// Defensive copy of the raw genesis-derived network id.
    public var networkID: Data { Data(networkIDBytes) }

    /// Defensive copy of the independently selected complete canonical checkpoint.
    public var trustedCheckpointNorito: Data { Data(checkpointBytes) }

    /// Defensive copy of the expected `BallotAttemptId`.
    public var expectedBallotAttemptID: Data { Data(ballotAttemptIDBytes) }

    /// Return a new immutable trust anchor promoted by one native-authenticated page.
    public func promoted(
        by verification: ParliamentTimedOvnCastingProofPageVerificationV1
    ) throws -> ParliamentTimedOvnCastingTrustAnchorV1 {
        try ParliamentTimedOvnCastingTrustAnchorV1(
            networkID: networkID,
            trustedCheckpointHeight: verification.evaluatedBlockHeight,
            trustedCheckpointNorito: verification.promotedCheckpointNorito,
            expectedBallotAttemptID: expectedBallotAttemptID
        )
    }

    fileprivate func snapshot() -> (
        networkID: [UInt8],
        checkpointNorito: [UInt8],
        ballotAttemptID: [UInt8]
    ) {
        (networkIDBytes, checkpointBytes, ballotAttemptIDBytes)
    }
}

/// Native-authenticated promotion carried by one bounded casting-proof page.
public struct ParliamentTimedOvnCastingProofPageVerificationV1: Equatable, Sendable {
    /// Exact positive u64 height authenticated by the finality verifier.
    public let evaluatedBlockHeight: UInt64
    /// Exact authenticated `HeightContextId`.
    public let evaluatedContextID: Data
    /// Whether another independently fetched and verified page is required.
    public let moreAvailable: Bool
    /// Exact complete checkpoint returned by native authentication.
    public let promotedCheckpointNorito: Data

    public init(
        evaluatedBlockHeight: UInt64,
        evaluatedContextID: Data,
        moreAvailable: Bool,
        promotedCheckpointNorito: Data
    ) throws {
        guard evaluatedBlockHeight > 0,
              evaluatedContextID.count == 32,
              !promotedCheckpointNorito.isEmpty,
              promotedCheckpointNorito.count <= 68 * 1024 * 1024,
              evaluatedContextID.contains(where: { $0 != 0 }) else {
            throw ParliamentTimedOvnNativeWalletError.invalidPageVerification
        }
        self.evaluatedBlockHeight = evaluatedBlockHeight
        self.evaluatedContextID = Data(evaluatedContextID)
        self.moreAvailable = moreAvailable
        self.promotedCheckpointNorito = Data(promotedCheckpointNorito)
    }
}

/// A public wallet record and its exact native-authenticated checkpoint promotion.
public struct ParliamentTimedOvnPublicRecordV1: Equatable, Sendable {
    /// Canonical registration or masked-ballot record for submission.
    public let record: Data
    /// Complete canonical checkpoint, to persist with the operation's public state.
    public let promotedCheckpointNorito: Data
}

/// Fail-closed errors from secret-local Parliament timed-OVN wallet operations.
public enum ParliamentTimedOvnNativeWalletError: Error, Equatable, Sendable {
    /// The exact ABI-25 bridge and all proof-gated V1 wallet symbols are unavailable.
    case bridgeUnavailable
    /// The canonical proof response is empty or exceeds 8 MiB.
    case invalidCastingProof
    /// Native code returned a page promotion with a noncanonical width, height, context, or flag.
    case invalidPageVerification
    /// A trust-anchor field has the wrong width or zero checkpoint/ballot identity.
    case invalidTrustAnchor
    /// The authority is empty, contains NUL, or exceeds the bridge bound.
    case invalidAuthority
    /// The opaque handle did not supply exactly 32 nonzero bytes.
    case invalidSeed
    /// Native replay, derivation, proof generation, or binding validation failed.
    case nativeRejected
    /// Native code returned a public record with a noncanonical width.
    case invalidPublicRecord
}

public final class NoritoNativeBridge: @unchecked Sendable {
    public static let shared = NoritoNativeBridge()
    private var bridgeStatus: NoritoBridgeLoader.ValidationStatus
    #if canImport(Darwin)
    private typealias LoadedBridgeAbiVersionFn = @convention(c) () -> UInt32
    #endif

    private func throwOnStatus(_ status: Int32) throws {
        if let error = NativeBridgeError.fromStatus(status) {
            throw error
        }
    }

    #if canImport(Darwin)
    private static func loadedBridgeAbiVersion(in handle: UnsafeMutableRawPointer?) -> UInt32? {
        guard let handle,
              let symbol = dlsym(handle, "connect_norito_bridge_abi_version") else {
            return nil
        }
        let function = unsafeBitCast(symbol, to: LoadedBridgeAbiVersionFn.self)
        return function()
    }

    static func bridgeHandleForStaticFallback(
        currentHandle: UnsafeMutableRawPointer?,
        processHandle: UnsafeMutableRawPointer?
    ) -> UnsafeMutableRawPointer? {
        processHandle ?? currentHandle
    }

    func resolveNativeSymbol<T>(_ symbol: String, as type: T.Type) -> T? {
        #if canImport(Darwin)
        guard let bridgeHandle, let address = dlsym(bridgeHandle, symbol) else { return nil }
        return unsafeBitCast(address, to: type)
        #else
        _ = symbol
        _ = type
        return nil
        #endif
    }

    #endif

    static let privacyCompiledProfileCatalogArchiveMaxBytes = 256 * 1024
    static let privacyExact12FixtureBundleMaxBytes = 2 * 1024 * 1024
    private static let detachedTransactionNativeMaximumBytes = 16 * 1024 * 1024
    private static let parliamentTimedOvnCastingProofMaximumBytes = 8 * 1024 * 1024
    /// Exact ABI-25 diagnostic summary width; complete checkpoint bytes are separate.
    public static let parliamentTimedOvnCastingProofPageSummaryBytes = 41
    private static let parliamentTimedOvnSeedBytes = 32
    private static let parliamentTimedOvnAuthorityMaximumBytes = 8 * 1024
    private static let parliamentTimedOvnRegistrationRecordBytes = 3_624
    private static let parliamentTimedOvnBallotRecordBytes = 2_858

    #if canImport(Darwin)
    private typealias EncodeTransferFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UInt32,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32
    private typealias EncodeTransferWithAlgFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UInt32,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UInt8,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32
    private typealias EncodeTransferInstructionBoxFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32
    private typealias EncodeMintFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UInt32,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32
    private typealias EncodeMintWithAlgFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UInt32,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UInt8,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32

    private typealias EncodeRegisterZkAssetFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt8,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32
    private typealias EncodeRegisterZkAssetWithAlgFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt8,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UInt8,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32
    private typealias EncodeMultisigRegisterFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32

    private typealias EncodeMultisigRegisterWithAlgFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UInt8,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32

    private typealias EncodeClaimIdentifierFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32

    private typealias EncodeClaimIdentifierWithAlgFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UInt8,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32

    private typealias EncodeBurnFn = EncodeMintFn
    private typealias EncodeBurnWithAlgFn = EncodeMintWithAlgFn
    private typealias EncodeSetKeyValueFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32
    private typealias EncodeSetKeyValueWithAlgFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UInt8,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32
    private typealias EncodeRemoveKeyValueFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32
    private typealias EncodeRemoveKeyValueWithAlgFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UInt8,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32
    private typealias EncodeGovernanceProposeDeployFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UInt16,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt8,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32
    private typealias EncodeGovernanceProposeDeployWithAlgFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UInt16,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt8,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UInt8,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32
    private typealias EncodeGovernanceCastPlainBallotFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt8,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32
    private typealias EncodeGovernanceCastPlainBallotWithAlgFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt8,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UInt8,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32
    private typealias EncodeGovernanceUpdatePlainConvictionFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UInt8,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32
    private typealias EncodeGovernanceCastZkBallotFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32
    private typealias EncodeGovernanceCastZkBallotWithAlgFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UInt64,
        UInt64,
        UInt8,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UInt8,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt8>?,
        UInt
    ) -> Int32
    private typealias DecodeSignedFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32
    private typealias DecodeReceiptFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32
    private typealias DecodeAssetIdFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    typealias FreeFn = @convention(c) (UnsafeMutablePointer<UInt8>?) -> Void
    private typealias ChainDiscriminantScopeEnterFn = @convention(c) (UInt16) -> UInt64
    private typealias ChainDiscriminantScopeExitFn = @convention(c) (UInt64) -> Int32
    private typealias SetAccelerationConfigFn = @convention(c) (UnsafeRawPointer?, UInt) -> Int32
    private typealias GetAccelerationConfigFn = @convention(c) (UnsafeMutableRawPointer?, UInt) -> Int32
    private typealias GetAccelerationStateFn = @convention(c) (UnsafeMutableRawPointer?, UInt) -> Int32

    private typealias EncodeCiphertextFrameFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt8, UInt64,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias EncodeControlOpenFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt8, UInt64,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias EncodeControlApproveFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt8, UInt64,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<CChar>?,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias EncodeControlApproveWithAlgFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt8, UInt64,
        UnsafePointer<UInt8>?,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias EncodeControlRejectFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt8, UInt64,
        UInt16,
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<CChar>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias EncodeControlCloseFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt8, UInt64,
        UInt8,
        UInt16,
        UnsafePointer<CChar>?, UInt,
        UInt8,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias EncodeControlPingFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt8, UInt64,
        UInt64,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias EncodeControlPongFn = EncodeControlPingFn

    private typealias EncodeConfidentialPayloadFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias AccountAddressParseFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UInt16, UInt8,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UInt16>?,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias AccountAddressRenderFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UInt16,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias Sm2DefaultDistidFn = @convention(c) (
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias Sm2KeypairFromSeedFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UInt8>?, UInt
    ) -> Int32

    private typealias Sm2SignFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UInt8>?, UInt
    ) -> Int32

    private typealias Sm2VerifyFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt
    ) -> Int32

    private typealias Sm2PublicKeyStringFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias Sm2ComputeZaFn = @convention(c) (
        UnsafePointer<CChar>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UInt8>?, UInt
    ) -> Int32

    private typealias Secp256k1PublicKeyFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UInt8>?, CUnsignedLong
    ) -> Int32

    private typealias Secp256k1SignFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UInt8>?, CUnsignedLong
    ) -> Int32

    private typealias Secp256k1VerifyFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong
    ) -> Int32

    private typealias MldsaParametersFn = @convention(c) (
        UInt32,
        UnsafeMutablePointer<UInt32>?,
        UnsafeMutablePointer<UInt32>?,
        UnsafeMutablePointer<UInt32>?
    ) -> Int32

    private typealias MldsaGenerateKeypairFn = @convention(c) (
        UInt32,
        UnsafeMutablePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UInt8>?, UInt
    ) -> Int32

    private typealias MldsaSignFn = @convention(c) (
        UInt32,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UInt8>?, UInt
    ) -> Int32

    private typealias MldsaVerifyFn = @convention(c) (
        UInt32,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt
    ) -> Int32

    private typealias ConnectGenerateKeypairFn = @convention(c) (
        UnsafeMutablePointer<UInt8>?,
        UnsafeMutablePointer<UInt8>?
    ) -> Int32

    private typealias ConnectPublicFromPrivateFn = @convention(c) (
        UnsafePointer<UInt8>?,
        UnsafeMutablePointer<UInt8>?
    ) -> Int32

    private typealias ConnectDeriveKeysFn = @convention(c) (
        UnsafePointer<UInt8>?,
        UnsafePointer<UInt8>?,
        UnsafePointer<UInt8>?,
        UnsafeMutablePointer<UInt8>?,
        UnsafeMutablePointer<UInt8>?
    ) -> Int32

    private typealias ConnectEncryptEnvelopeFn = @convention(c) (
        UnsafePointer<UInt8>?,
        UnsafePointer<UInt8>?,
        UInt8,
        UnsafePointer<UInt8>?,
        UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias ConnectDecryptCiphertextFn = @convention(c) (
        UnsafePointer<UInt8>?,
        UnsafePointer<UInt8>?,
        UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias EncodeEnvelopeSignRequestTxFn = @convention(c) (
        UInt64,
        UnsafePointer<UInt8>?,
        UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias EncodeEnvelopeSignRequestRawFn = @convention(c) (
        UInt64,
        UnsafePointer<UInt8>?,
        UInt,
        UnsafePointer<UInt8>?,
        UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias EncodeEnvelopeSignResultOkFn = @convention(c) (
        UInt64,
        UnsafePointer<UInt8>?,
        UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias EncodeEnvelopeSignResultOkWithAlgFn = @convention(c) (
        UInt64,
        UnsafePointer<CChar>?,
        UInt,
        UnsafePointer<UInt8>?,
        UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias EncodeEnvelopeSignResultErrFn = @convention(c) (
        UInt64,
        UnsafePointer<UInt8>?,
        UInt,
        UnsafePointer<UInt8>?,
        UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias EncodeEnvelopeControlCloseFn = @convention(c) (
        UInt64,
        UInt8,
        UInt16,
        UnsafePointer<UInt8>?,
        UInt,
        UInt8,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias EncodeEnvelopeControlRejectFn = @convention(c) (
        UInt64,
        UInt16,
        UnsafePointer<UInt8>?,
        UInt,
        UnsafePointer<UInt8>?,
        UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias DecodeEnvelopeKindFn = @convention(c) (
        UnsafePointer<UInt8>?,
        UInt,
        UnsafeMutablePointer<UInt64>?,
        UnsafeMutablePointer<UInt16>?
    ) -> Int32

    private typealias DecodeEnvelopeJSONFn = @convention(c) (
        UnsafePointer<UInt8>?,
        UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias DecodeControlKindFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UInt8>?,
        UnsafeMutablePointer<UInt8>?,
        UnsafeMutablePointer<UInt64>?,
        UnsafeMutablePointer<UInt16>?
    ) -> Int32

    private typealias DecodeCiphertextFrameFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UInt8>?,
        UnsafeMutablePointer<UInt8>?,
        UnsafeMutablePointer<UInt64>?,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias DecodeControlOpenPubFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UInt8>?
    ) -> Int32

    private typealias DecodeControlOpenNetworkIdFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias DecodeControlOpenAppMetadataFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias DecodeControlOpenPermissionsFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias DecodeControlApprovePubFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UInt8>?
    ) -> Int32

    private typealias DecodeControlApproveAccountFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias DecodeControlApprovePermissionsFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias DecodeControlApproveProofFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias DecodeControlApproveSigFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UInt8>?
    ) -> Int32

    private typealias DecodeControlApproveSigAlgFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias DecodeControlCloseFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UInt8>?,
        UnsafeMutablePointer<UInt16>?,
        UnsafeMutablePointer<UInt8>?,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias DecodeControlRejectFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UInt16>?,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
        UnsafeMutablePointer<UInt>?
    ) -> Int32

    private typealias DecodeControlPingFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UInt64>?
    ) -> Int32

    private typealias DecodeControlPongFn = DecodeControlPingFn

    private typealias SorafsLocalFetchFn = @convention(c) (
        UnsafePointer<CChar>?, CUnsignedLong,
        UnsafePointer<CChar>?, CUnsignedLong,
        UnsafePointer<CChar>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias SorafsReferencePayloadFn = @convention(c) (
        UInt32,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UInt64,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias SorafsReferenceSinglePayloadFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UInt64,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias SorafsReferenceFixtureBundleFn = @convention(c) (
        UnsafeRawPointer?, CUnsignedLong,
        UInt64, UInt64,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias SorafsReferenceGovernanceLogNodeFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UInt64,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias SorafsReferenceGovernanceDagBlockFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UInt64,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias SorafsReferenceGovernanceDagHeadChainFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeRawPointer?, CUnsignedLong,
        UInt64,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias SorafsReferenceOrderbookSignFn = @convention(c) (
        UInt32,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias SorafsReferenceOrderbookOrderIdDeriveFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UInt64,
        UnsafeMutablePointer<UInt8>?, CUnsignedLong
    ) -> Int32
    private typealias SorafsReferenceOrderbookOrderRequestBuilderFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UInt32, UInt32,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UInt64, UInt64,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UInt64, UInt64,
        UInt32, UInt32,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias SorafsReferenceOrderbookCancelBuilderFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UInt32, UInt64,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias SorafsReferenceOrderbookSettlementReceiptBuilderFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UInt64, UInt64,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UInt64,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UInt64,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias SorafsReferencePdpPairFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UInt64,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias SorafsReferencePdpBundleFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UInt64,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias Blake3HashFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias DetachedTransactionInspectFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias DetachedTransactionFinalizeEd25519Fn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias EncodeAccountOnboardingPlanBodyFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias AliasInstructionRoundTripFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias CanonicalJSONBlake3Fn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?,
        UnsafeMutablePointer<UInt8>?, CUnsignedLong
    ) -> Int32
    private typealias PrivacyCompiledProfileCatalogFn = @convention(c) (
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias PrivacyValidateCompiledProfileCatalogFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong
    ) -> Int32
    private typealias PrivacyExact12FixtureBundleFn = @convention(c) (
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias PrivacyValidateExact12FixtureBundleFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong
    ) -> Int32
    private typealias PublicKeyFromPrivateFn = @convention(c) (
        UInt8,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias KeypairFromSeedFn = @convention(c) (
        UInt8,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias SignDetachedFn = @convention(c) (
        UInt8,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias VerifyDetachedFn = @convention(c) (
        UInt8,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UInt8>?
    ) -> Int32
    private typealias ParliamentTimedOvnVerifyCastingProofFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias ParliamentTimedOvnVerifyCastingProofPageFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias ParliamentTimedOvnRegistrationFromProofFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<CChar>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32
    private typealias ParliamentTimedOvnBallotFromProofFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<CChar>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong,
        UInt8,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?
    ) -> Int32

    private var bridgeHandle: UnsafeMutableRawPointer? = nil
    private var loadedBridgeAbiVersion: UInt32? = nil
    private var encodeTransferFn: EncodeTransferFn? = nil
    private var encodeTransferWithAlgFn: EncodeTransferWithAlgFn? = nil
    private var encodeTransferInstructionBoxFn: EncodeTransferInstructionBoxFn? = nil
    private var encodeTransferInstructionFrameFn: EncodeTransferInstructionBoxFn? = nil
    private var encodeMintFn: EncodeMintFn? = nil
    private var encodeMintWithAlgFn: EncodeMintWithAlgFn? = nil
    private var encodeRegisterZkAssetFn: EncodeRegisterZkAssetFn? = nil
    private var encodeRegisterZkAssetWithAlgFn: EncodeRegisterZkAssetWithAlgFn? = nil
    private var encodeMultisigRegisterFn: EncodeMultisigRegisterFn? = nil
    private var encodeMultisigRegisterWithAlgFn: EncodeMultisigRegisterWithAlgFn? = nil
    private var encodeClaimIdentifierFn: EncodeClaimIdentifierFn? = nil
    private var encodeClaimIdentifierWithAlgFn: EncodeClaimIdentifierWithAlgFn? = nil
    private var encodeBurnFn: EncodeBurnFn? = nil
    private var encodeBurnWithAlgFn: EncodeBurnWithAlgFn? = nil
    private var encodeSetKeyValueFn: EncodeSetKeyValueFn? = nil
    private var encodeSetKeyValueWithAlgFn: EncodeSetKeyValueWithAlgFn? = nil
    private var encodeRemoveKeyValueFn: EncodeRemoveKeyValueFn? = nil
    private var encodeRemoveKeyValueWithAlgFn: EncodeRemoveKeyValueWithAlgFn? = nil
    private var encodeGovernanceProposeDeployFn: EncodeGovernanceProposeDeployFn? = nil
    private var encodeGovernanceProposeDeployWithAlgFn: EncodeGovernanceProposeDeployWithAlgFn? = nil
    private var encodeGovernanceCastPlainBallotFn: EncodeGovernanceCastPlainBallotFn? = nil
    private var encodeGovernanceCastPlainBallotWithAlgFn: EncodeGovernanceCastPlainBallotWithAlgFn? = nil
    private var encodeGovernanceUpdatePlainConvictionFn: EncodeGovernanceUpdatePlainConvictionFn? = nil
    private var encodeGovernanceCastZkBallotFn: EncodeGovernanceCastZkBallotFn? = nil
    private var encodeGovernanceCastZkBallotWithAlgFn: EncodeGovernanceCastZkBallotWithAlgFn? = nil
    private var decodeSignedFn: DecodeSignedFn? = nil
    private var decodeReceiptFn: DecodeReceiptFn? = nil
    private var decodeAssetIdFn: DecodeAssetIdFn? = nil
    var freeFn: FreeFn? = nil
    private var chainDiscriminantScopeFns: (
        enter: ChainDiscriminantScopeEnterFn,
        exit: ChainDiscriminantScopeExitFn
    )? = nil
    private var setAccelerationConfigFn: SetAccelerationConfigFn? = nil
    private var getAccelerationConfigFn: GetAccelerationConfigFn? = nil
    private var getAccelerationStateFn: GetAccelerationStateFn? = nil
    private var encodeCiphertextFrameFn: EncodeCiphertextFrameFn? = nil
    private var encodeControlOpenFn: EncodeControlOpenFn? = nil
    private var encodeControlApproveFn: EncodeControlApproveFn? = nil
    private var encodeControlApproveWithAlgFn: EncodeControlApproveWithAlgFn? = nil
    private var encodeControlRejectFn: EncodeControlRejectFn? = nil
    private var encodeControlCloseFn: EncodeControlCloseFn? = nil
    private var encodeControlPingFn: EncodeControlPingFn? = nil
    private var encodeControlPongFn: EncodeControlPongFn? = nil
    private var encodeConfidentialPayloadFn: EncodeConfidentialPayloadFn? = nil
    private var accountAddressParseFn: AccountAddressParseFn? = nil
    private var accountAddressRenderFn: AccountAddressRenderFn? = nil
    private var publicKeyFromPrivateFn: PublicKeyFromPrivateFn? = nil
    private var keypairFromSeedFn: KeypairFromSeedFn? = nil
    private var signDetachedFn: SignDetachedFn? = nil
    private var verifyDetachedFn: VerifyDetachedFn? = nil
    private var parliamentTimedOvnVerifyCastingProofPageFn: ParliamentTimedOvnVerifyCastingProofPageFn? = nil
    private var parliamentTimedOvnVerifyCastingProofFn: ParliamentTimedOvnVerifyCastingProofFn? = nil
    private var parliamentTimedOvnRegistrationFromProofFn: ParliamentTimedOvnRegistrationFromProofFn? = nil
    private var parliamentTimedOvnBallotFromProofFn: ParliamentTimedOvnBallotFromProofFn? = nil
    private var sm2DefaultDistidFn: Sm2DefaultDistidFn? = nil
    private var sm2KeypairFromSeedFn: Sm2KeypairFromSeedFn? = nil
    private var sm2SignFn: Sm2SignFn? = nil
    private var sm2VerifyFn: Sm2VerifyFn? = nil
    private var sm2PublicKeyPrefixedFn: Sm2PublicKeyStringFn? = nil
    private var sm2PublicKeyMultihashFn: Sm2PublicKeyStringFn? = nil
    private var sm2ComputeZaFn: Sm2ComputeZaFn? = nil
    private var secp256k1PublicKeyFn: Secp256k1PublicKeyFn? = nil
    private var secp256k1SignFn: Secp256k1SignFn? = nil
    private var secp256k1VerifyFn: Secp256k1VerifyFn? = nil
    private var mldsaParametersFn: MldsaParametersFn? = nil
    private var mldsaGenerateKeypairFn: MldsaGenerateKeypairFn? = nil
    private var mldsaSignFn: MldsaSignFn? = nil
    private var mldsaVerifyFn: MldsaVerifyFn? = nil
    private var connectGenerateKeypairFn: ConnectGenerateKeypairFn? = nil
    private var connectPublicFromPrivateFn: ConnectPublicFromPrivateFn? = nil
    private var connectDeriveKeysFn: ConnectDeriveKeysFn? = nil
    private var connectEncryptEnvelopeFn: ConnectEncryptEnvelopeFn? = nil
    private var connectDecryptCiphertextFn: ConnectDecryptCiphertextFn? = nil
    private var encodeEnvelopeSignRequestTxFn: EncodeEnvelopeSignRequestTxFn? = nil
    private var encodeEnvelopeSignRequestRawFn: EncodeEnvelopeSignRequestRawFn? = nil
    private var encodeEnvelopeSignResultOkFn: EncodeEnvelopeSignResultOkFn? = nil
    private var encodeEnvelopeSignResultOkWithAlgFn: EncodeEnvelopeSignResultOkWithAlgFn? = nil
    private var encodeEnvelopeSignResultErrFn: EncodeEnvelopeSignResultErrFn? = nil
    private var encodeEnvelopeControlCloseFn: EncodeEnvelopeControlCloseFn? = nil
    private var encodeEnvelopeControlRejectFn: EncodeEnvelopeControlRejectFn? = nil
    private var decodeEnvelopeKindFn: DecodeEnvelopeKindFn? = nil
    private var decodeEnvelopeJSONFn: DecodeEnvelopeJSONFn? = nil
    private var decodeControlKindFn: DecodeControlKindFn? = nil
    private var decodeCiphertextFrameFn: DecodeCiphertextFrameFn? = nil
    private var decodeControlOpenPubFn: DecodeControlOpenPubFn? = nil
    private var decodeControlOpenNetworkIdFn: DecodeControlOpenNetworkIdFn? = nil
    private var decodeControlOpenAppMetadataFn: DecodeControlOpenAppMetadataFn? = nil
    private var decodeControlOpenPermissionsFn: DecodeControlOpenPermissionsFn? = nil
    private var decodeControlApprovePubFn: DecodeControlApprovePubFn? = nil
    private var decodeControlApproveAccountFn: DecodeControlApproveAccountFn? = nil
    private var decodeControlApprovePermissionsFn: DecodeControlApprovePermissionsFn? = nil
    private var decodeControlApproveProofFn: DecodeControlApproveProofFn? = nil
    private var decodeControlApproveSigFn: DecodeControlApproveSigFn? = nil
    private var decodeControlApproveSigAlgFn: DecodeControlApproveSigAlgFn? = nil
    private var decodeControlCloseFn: DecodeControlCloseFn? = nil
    private var decodeControlRejectFn: DecodeControlRejectFn? = nil
    private var decodeControlPingFn: DecodeControlPingFn? = nil
    private var decodeControlPongFn: DecodeControlPongFn? = nil
    private var sorafsLocalFetchFn: SorafsLocalFetchFn? = nil
    private var sorafsReferenceValidateOrderbookFn: SorafsReferencePayloadFn? = nil
    private var sorafsReferenceSignOrderbookFn: SorafsReferenceOrderbookSignFn? = nil
    private var sorafsReferenceDeriveOrderbookOrderIdFn: SorafsReferenceOrderbookOrderIdDeriveFn? = nil
    private var sorafsReferenceBuildOrderbookOrderRequestFn: SorafsReferenceOrderbookOrderRequestBuilderFn? = nil
    private var sorafsReferenceBuildOrderbookOrderCancelFn: SorafsReferenceOrderbookCancelBuilderFn? = nil
    private var sorafsReferenceBuildOrderbookSettlementReceiptFn: SorafsReferenceOrderbookSettlementReceiptBuilderFn? = nil
    private var sorafsReferenceValidatePopPayloadFn: SorafsReferencePayloadFn? = nil
    private var sorafsReferenceValidateHedgingPayloadFn: SorafsReferencePayloadFn? = nil
    private var sorafsReferenceValidateAppealFinanceCancelAssetLockFn: SorafsReferenceSinglePayloadFn? = nil
    private var sorafsReferenceValidateFixtureBundleFn: SorafsReferenceFixtureBundleFn? = nil
    private var sorafsReferenceValidateGovernanceLogNodeFn: SorafsReferenceGovernanceLogNodeFn? = nil
    private var sorafsReferenceValidateGovernanceDagBlockFn: SorafsReferenceGovernanceDagBlockFn? = nil
    private var sorafsReferenceValidateGovernanceDagHeadChainFn: SorafsReferenceGovernanceDagHeadChainFn? = nil
    private var sorafsReferenceValidatePdpPayloadFn: SorafsReferencePayloadFn? = nil
    private var sorafsReferenceValidatePdpCommitmentChallengeFn: SorafsReferencePdpPairFn? = nil
    private var sorafsReferenceValidatePdpChallengeProofFn: SorafsReferencePdpPairFn? = nil
    private var sorafsReferenceValidatePdpBundleFn: SorafsReferencePdpBundleFn? = nil
    var daProofSummaryFn: DaProofSummaryFn? = nil
    private var blake3HashFn: Blake3HashFn? = nil
    private var detachedTransactionInspectFn: DetachedTransactionInspectFn? = nil
    private var detachedTransactionFinalizeEd25519Fn: DetachedTransactionFinalizeEd25519Fn? = nil
    private var encodeAccountOnboardingPlanBodyFn: EncodeAccountOnboardingPlanBodyFn? = nil
    private var aliasInstructionRoundTripFn: AliasInstructionRoundTripFn? = nil
    private var canonicalJSONBlake3Fn: CanonicalJSONBlake3Fn? = nil
    private var privacyCompiledProfileCatalogFn: PrivacyCompiledProfileCatalogFn? = nil
    private var privacyValidateCompiledProfileCatalogFn: PrivacyValidateCompiledProfileCatalogFn? = nil
    private var privacyValidateExact12CapabilityManifestFn: PrivacyValidateCompiledProfileCatalogFn? = nil
    private var privacyExact12FixtureBundleFn: PrivacyExact12FixtureBundleFn? = nil
    private var privacyValidateExact12FixtureBundleFn: PrivacyValidateExact12FixtureBundleFn? = nil
    // Privacy outputs point past a private allocation header. Only the dedicated
    // privacy free function can recover and zeroize that allocation safely.
    private var privacyFreeFn: FreeFn? = nil
    private var privacyNativeProbeOk = false
#else
    private let bridgeHandle: Any? = nil
    private let loadedBridgeAbiVersion: UInt32? = nil
    private let encodeTransferFn: Any? = nil
    private let encodeTransferWithAlgFn: Any? = nil
    private let encodeMintFn: Any? = nil
    private let encodeMintWithAlgFn: Any? = nil
    private let encodeRegisterZkAssetFn: Any? = nil
    private let encodeRegisterZkAssetWithAlgFn: Any? = nil
    private let encodeMultisigRegisterFn: Any? = nil
    private let encodeMultisigRegisterWithAlgFn: Any? = nil
    private let encodeClaimIdentifierFn: Any? = nil
    private let encodeClaimIdentifierWithAlgFn: Any? = nil
    private let encodeBurnFn: Any? = nil
    private let encodeBurnWithAlgFn: Any? = nil
    private let encodeSetKeyValueFn: Any? = nil
    private let encodeSetKeyValueWithAlgFn: Any? = nil
    private let encodeRemoveKeyValueFn: Any? = nil
    private let encodeRemoveKeyValueWithAlgFn: Any? = nil
    private let encodeGovernanceProposeDeployFn: Any? = nil
    private let encodeGovernanceProposeDeployWithAlgFn: Any? = nil
    private let encodeGovernanceCastPlainBallotFn: Any? = nil
    private let encodeGovernanceCastPlainBallotWithAlgFn: Any? = nil
    private let encodeGovernanceUpdatePlainConvictionFn: Any? = nil
    private let encodeGovernanceCastZkBallotFn: Any? = nil
    private let encodeGovernanceCastZkBallotWithAlgFn: Any? = nil
    private let decodeSignedFn: Any? = nil
    private let decodeAssetIdFn: Any? = nil
    private let freeFn: Any? = nil
    private let chainDiscriminantScopeFns: Any? = nil
    private let setAccelerationConfigFn: Any? = nil
    private let encodeCiphertextFrameFn: Any? = nil
    private let encodeControlOpenFn: Any? = nil
    private let encodeControlApproveFn: Any? = nil
    private let encodeControlApproveWithAlgFn: Any? = nil
    private let encodeControlRejectFn: Any? = nil
    private let encodeControlCloseFn: Any? = nil
    private let encodeControlPingFn: Any? = nil
    private let encodeControlPongFn: Any? = nil
    private let encodeConfidentialPayloadFn: Any? = nil
    private let accountAddressParseFn: Any? = nil
    private let accountAddressRenderFn: Any? = nil
    private let publicKeyFromPrivateFn: Any? = nil
    private let keypairFromSeedFn: Any? = nil
    private let signDetachedFn: Any? = nil
    private let verifyDetachedFn: Any? = nil
    private let parliamentTimedOvnVerifyCastingProofPageFn: Any? = nil
    private let parliamentTimedOvnVerifyCastingProofFn: Any? = nil
    private let parliamentTimedOvnRegistrationFromProofFn: Any? = nil
    private let parliamentTimedOvnBallotFromProofFn: Any? = nil
    private let sm2DefaultDistidFn: Any? = nil
    private let sm2KeypairFromSeedFn: Any? = nil
    private let sm2SignFn: Any? = nil
    private let sm2VerifyFn: Any? = nil
    private let sm2PublicKeyPrefixedFn: Any? = nil
    private let sm2PublicKeyMultihashFn: Any? = nil
    private let sm2ComputeZaFn: Any? = nil
    private let secp256k1PublicKeyFn: Any? = nil
    private let secp256k1SignFn: Any? = nil
    private let secp256k1VerifyFn: Any? = nil
    private let mldsaParametersFn: Any? = nil
    private let mldsaGenerateKeypairFn: Any? = nil
    private let mldsaSignFn: Any? = nil
    private let mldsaVerifyFn: Any? = nil
    private let connectGenerateKeypairFn: Any? = nil
    private let connectPublicFromPrivateFn: Any? = nil
    private let connectDeriveKeysFn: Any? = nil
    private let connectEncryptEnvelopeFn: Any? = nil
    private let connectDecryptCiphertextFn: Any? = nil
    private let encodeEnvelopeSignRequestTxFn: Any? = nil
    private let encodeEnvelopeSignRequestRawFn: Any? = nil
    private let encodeEnvelopeSignResultOkFn: Any? = nil
    private let encodeEnvelopeSignResultOkWithAlgFn: Any? = nil
    private let encodeEnvelopeSignResultErrFn: Any? = nil
    private let encodeEnvelopeControlCloseFn: Any? = nil
    private let encodeEnvelopeControlRejectFn: Any? = nil
    private let decodeEnvelopeKindFn: Any? = nil
    private let decodeEnvelopeJSONFn: Any? = nil
    private let decodeControlKindFn: Any? = nil
    private let decodeCiphertextFrameFn: Any? = nil
    private let decodeControlOpenPubFn: Any? = nil
    private let decodeControlOpenNetworkIdFn: Any? = nil
    private let decodeControlOpenAppMetadataFn: Any? = nil
    private let decodeControlOpenPermissionsFn: Any? = nil
    private let decodeControlApprovePubFn: Any? = nil
    private let decodeControlApproveAccountFn: Any? = nil
    private let decodeControlApprovePermissionsFn: Any? = nil
    private let decodeControlApproveProofFn: Any? = nil
    private let decodeControlApproveSigFn: Any? = nil
    private let decodeControlApproveSigAlgFn: Any? = nil
    private let decodeControlCloseFn: Any? = nil
    private let decodeControlRejectFn: Any? = nil
    private let decodeControlPingFn: Any? = nil
    private let decodeControlPongFn: Any? = nil
    private let sorafsLocalFetchFn: Any? = nil
    private let sorafsReferenceValidateOrderbookFn: Any? = nil
    private let sorafsReferenceSignOrderbookFn: Any? = nil
    private let sorafsReferenceDeriveOrderbookOrderIdFn: Any? = nil
    private let sorafsReferenceBuildOrderbookOrderRequestFn: Any? = nil
    private let sorafsReferenceBuildOrderbookOrderCancelFn: Any? = nil
    private let sorafsReferenceBuildOrderbookSettlementReceiptFn: Any? = nil
    private let sorafsReferenceValidatePopPayloadFn: Any? = nil
    private let sorafsReferenceValidateHedgingPayloadFn: Any? = nil
    private let sorafsReferenceValidateAppealFinanceCancelAssetLockFn: Any? = nil
    private let sorafsReferenceValidateFixtureBundleFn: Any? = nil
    private let sorafsReferenceValidateGovernanceLogNodeFn: Any? = nil
    private let sorafsReferenceValidatePdpPayloadFn: Any? = nil
    private let sorafsReferenceValidatePdpCommitmentChallengeFn: Any? = nil
    private let sorafsReferenceValidatePdpChallengeProofFn: Any? = nil
    private let sorafsReferenceValidatePdpBundleFn: Any? = nil
    private let daProofSummaryFn: Any? = nil
    private let blake3HashFn: Any? = nil
    private let detachedTransactionInspectFn: Any? = nil
    private let detachedTransactionFinalizeEd25519Fn: Any? = nil
    private let encodeAccountOnboardingPlanBodyFn: Any? = nil
    private let aliasInstructionRoundTripFn: Any? = nil
    private let canonicalJSONBlake3Fn: Any? = nil
    private let privacyCompiledProfileCatalogFn: Any? = nil
    private let privacyValidateCompiledProfileCatalogFn: Any? = nil
    private let privacyValidateExact12CapabilityManifestFn: Any? = nil
    private let privacyExact12FixtureBundleFn: Any? = nil
    private let privacyValidateExact12FixtureBundleFn: Any? = nil
    private let privacyFreeFn: Any? = nil
    private let privacyNativeProbeOk = false
#endif

#if canImport(Darwin)
#endif

    #if canImport(Darwin)
    private func loadPrivacySymbols(from handle: UnsafeMutableRawPointer?) {
        guard let handle else {
            self.privacyCompiledProfileCatalogFn = nil
            self.privacyValidateCompiledProfileCatalogFn = nil
            self.privacyValidateExact12CapabilityManifestFn = nil
            self.privacyExact12FixtureBundleFn = nil
            self.privacyValidateExact12FixtureBundleFn = nil
            self.privacyFreeFn = nil
            return
        }
        if let catalogSymbol = dlsym(handle, "iroha_privacy_compiled_profile_catalog_v1") {
            self.privacyCompiledProfileCatalogFn = unsafeBitCast(
                catalogSymbol,
                to: PrivacyCompiledProfileCatalogFn.self
            )
        } else {
            self.privacyCompiledProfileCatalogFn = nil
        }
        if let validateSymbol = dlsym(
            handle,
            "iroha_privacy_validate_compiled_profile_catalog_v1"
        ) {
            self.privacyValidateCompiledProfileCatalogFn = unsafeBitCast(
                validateSymbol,
                to: PrivacyValidateCompiledProfileCatalogFn.self
            )
        } else {
            self.privacyValidateCompiledProfileCatalogFn = nil
        }
        if let validateCapabilitySymbol = dlsym(
            handle,
            "iroha_privacy_validate_exact12_capability_manifest_v1"
        ) {
            self.privacyValidateExact12CapabilityManifestFn = unsafeBitCast(
                validateCapabilitySymbol,
                to: PrivacyValidateCompiledProfileCatalogFn.self
            )
        } else {
            self.privacyValidateExact12CapabilityManifestFn = nil
        }
        if let fixtureSymbol = dlsym(handle, "iroha_privacy_exact12_fixture_bundle_v1") {
            self.privacyExact12FixtureBundleFn = unsafeBitCast(
                fixtureSymbol,
                to: PrivacyExact12FixtureBundleFn.self
            )
        } else {
            self.privacyExact12FixtureBundleFn = nil
        }
        if let validateFixtureSymbol = dlsym(
            handle,
            "iroha_privacy_validate_exact12_fixture_bundle_v1"
        ) {
            self.privacyValidateExact12FixtureBundleFn = unsafeBitCast(
                validateFixtureSymbol,
                to: PrivacyValidateExact12FixtureBundleFn.self
            )
        } else {
            self.privacyValidateExact12FixtureBundleFn = nil
        }
        if let freeSymbol = dlsym(handle, "iroha_privacy_free_buffer") {
            self.privacyFreeFn = unsafeBitCast(freeSymbol, to: FreeFn.self)
        } else {
            self.privacyFreeFn = nil
        }
    }

    private func installStaticallyLinkedBridgeIfAvailable() {
        #if IROHASWIFT_BRIDGE_PRESENT
        let abiVersion = connect_norito_bridge_abi_version()
        guard NoritoBridgeLoader.isSupportedBridgeAbiVersion(abiVersion) else {
            self.loadedBridgeAbiVersion = nil
            NSLog(
                "[NoritoNativeBridge] statically linked transfer bridge ABI mismatch expected=%u actual=%u",
                NoritoBridgeLoader.expectedBridgeAbiVersion,
                abiVersion
            )
            return
        }
        self.loadedBridgeAbiVersion = abiVersion

        let staticHandle = dlopen(nil, RTLD_NOW | RTLD_GLOBAL)
        guard let mldsaParameters = staticHandle.flatMap({ dlsym($0, "soranet_mldsa_parameters") }),
              let mldsaGenerateKeypair = staticHandle.flatMap({ dlsym($0, "soranet_mldsa_generate_keypair") }),
              let mldsaSign = staticHandle.flatMap({ dlsym($0, "soranet_mldsa_sign") }),
              let mldsaVerify = staticHandle.flatMap({ dlsym($0, "soranet_mldsa_verify") }) else {
            self.loadedBridgeAbiVersion = nil
            NSLog("[NoritoNativeBridge] missing canonical ML-DSA exports")
            return
        }
        guard let accelerationSet = staticHandle.flatMap({ dlsym($0, "connect_norito_acceleration_config_set_v1") }),
              let accelerationGet = staticHandle.flatMap({ dlsym($0, "connect_norito_acceleration_config_get_v1") }),
              let accelerationState = staticHandle.flatMap({ dlsym($0, "connect_norito_acceleration_state_get_v1") }) else {
            self.loadedBridgeAbiVersion = nil
            NSLog("[NoritoNativeBridge] missing canonical acceleration exports")
            return
        }
        self.setAccelerationConfigFn = unsafeBitCast(accelerationSet, to: SetAccelerationConfigFn.self)
        self.getAccelerationConfigFn = unsafeBitCast(accelerationGet, to: GetAccelerationConfigFn.self)
        self.getAccelerationStateFn = unsafeBitCast(accelerationState, to: GetAccelerationStateFn.self)
        self.bridgeHandle = Self.bridgeHandleForStaticFallback(
            currentHandle: self.bridgeHandle,
            processHandle: staticHandle
        )
        guard let castZkSymbol = staticHandle.flatMap({
            dlsym($0, "connect_norito_encode_governance_cast_zk_ballot_signed_transaction")
        }), let castZkAlgSymbol = staticHandle.flatMap({
            dlsym($0, "connect_norito_encode_governance_cast_zk_ballot_signed_transaction_alg")
        }), let timedOvnPageVerifySymbol = staticHandle.flatMap({
            dlsym($0, "connect_norito_parliament_timed_ovn_verify_casting_proof_page_v1")
        }), let timedOvnVerifySymbol = staticHandle.flatMap({
            dlsym($0, "connect_norito_parliament_timed_ovn_verify_casting_proof_v1")
        }), let timedOvnRegistrationSymbol = staticHandle.flatMap({
            dlsym($0, "connect_norito_parliament_timed_ovn_registration_from_proof_v1")
        }), let timedOvnBallotSymbol = staticHandle.flatMap({
            dlsym($0, "connect_norito_parliament_timed_ovn_ballot_from_proof_v1")
        }) else {
            self.loadedBridgeAbiVersion = nil
            NSLog(
                "[NoritoNativeBridge] statically linked bridge is missing mandatory ABI-25 exports"
            )
            return
        }
        // Swift 6.2 can fail to produce a diagnostic while coercing these large
        // imported C signatures directly to @convention(c) optionals. Resolve
        // the statically linked symbols through the process handle instead;
        // this is the same typed binding path used for a dynamically loaded
        // bridge and keeps the ABI contract identical.
        self.encodeTransferFn = staticHandle
            .flatMap { dlsym($0, "connect_norito_encode_transfer_signed_transaction") }
            .map { unsafeBitCast($0, to: EncodeTransferFn.self) }
        self.encodeTransferWithAlgFn = staticHandle
            .flatMap { dlsym($0, "connect_norito_encode_transfer_signed_transaction_alg") }
            .map { unsafeBitCast($0, to: EncodeTransferWithAlgFn.self) }
        self.encodeMintFn = staticHandle
            .flatMap { dlsym($0, "connect_norito_encode_mint_signed_transaction") }
            .map { unsafeBitCast($0, to: EncodeMintFn.self) }
        self.encodeMintWithAlgFn = staticHandle
            .flatMap { dlsym($0, "connect_norito_encode_mint_signed_transaction_alg") }
            .map { unsafeBitCast($0, to: EncodeMintWithAlgFn.self) }
        self.encodeGovernanceCastZkBallotFn = unsafeBitCast(
            castZkSymbol,
            to: EncodeGovernanceCastZkBallotFn.self
        )
        self.encodeGovernanceCastZkBallotWithAlgFn = unsafeBitCast(
            castZkAlgSymbol,
            to: EncodeGovernanceCastZkBallotWithAlgFn.self
        )
        self.parliamentTimedOvnVerifyCastingProofFn = unsafeBitCast(
            timedOvnVerifySymbol,
            to: ParliamentTimedOvnVerifyCastingProofFn.self
        )
        self.parliamentTimedOvnVerifyCastingProofPageFn = unsafeBitCast(
            timedOvnPageVerifySymbol,
            to: ParliamentTimedOvnVerifyCastingProofPageFn.self
        )
        self.parliamentTimedOvnRegistrationFromProofFn = unsafeBitCast(
            timedOvnRegistrationSymbol,
            to: ParliamentTimedOvnRegistrationFromProofFn.self
        )
        self.parliamentTimedOvnBallotFromProofFn = unsafeBitCast(
            timedOvnBallotSymbol,
            to: ParliamentTimedOvnBallotFromProofFn.self
        )
        if let instructionBoxSymbol = staticHandle.flatMap({
            dlsym($0, "connect_norito_encode_transfer_instruction_box")
        }) {
            self.encodeTransferInstructionBoxFn = unsafeBitCast(
                instructionBoxSymbol,
                to: EncodeTransferInstructionBoxFn.self
            )
        } else {
            self.encodeTransferInstructionBoxFn = nil
        }
        self.encodeTransferInstructionFrameFn = staticHandle
            .flatMap { dlsym($0, "connect_norito_encode_transfer_instruction_frame_v1") }
            .map { unsafeBitCast($0, to: EncodeTransferInstructionBoxFn.self) }
        loadPrivacySymbols(from: staticHandle)
        self.detachedTransactionInspectFn = staticHandle
            .flatMap { dlsym($0, "connect_norito_detached_transaction_scaffold_inspect_v1") }
            .map { unsafeBitCast($0, to: DetachedTransactionInspectFn.self) }
        self.detachedTransactionFinalizeEd25519Fn = staticHandle
            .flatMap {
                dlsym($0, "connect_norito_detached_transaction_scaffold_finalize_ed25519_v1")
            }
            .map { unsafeBitCast($0, to: DetachedTransactionFinalizeEd25519Fn.self) }
        self.encodeAccountOnboardingPlanBodyFn = staticHandle
            .flatMap {
                dlsym($0, "connect_norito_encode_account_onboarding_plan_body_v1")
            }
            .map { unsafeBitCast($0, to: EncodeAccountOnboardingPlanBodyFn.self) }
        self.aliasInstructionRoundTripFn = staticHandle
            .flatMap {
                dlsym($0, "connect_norito_alias_instruction_round_trip_v1")
            }
            .map { unsafeBitCast($0, to: AliasInstructionRoundTripFn.self) }
        self.canonicalJSONBlake3Fn = staticHandle
            .flatMap { dlsym($0, "connect_norito_canonical_json_blake3_v1") }
            .map { unsafeBitCast($0, to: CanonicalJSONBlake3Fn.self) }
        guard let accountParse = staticHandle.flatMap({ dlsym($0, "connect_norito_account_address_parse") }),
              let accountRender = staticHandle.flatMap({ dlsym($0, "connect_norito_account_address_render") }) else {
            self.loadedBridgeAbiVersion = nil
            NSLog("[NoritoNativeBridge] missing canonical account address exports")
            return
        }
        self.accountAddressParseFn = unsafeBitCast(accountParse, to: AccountAddressParseFn.self)
        self.accountAddressRenderFn = unsafeBitCast(accountRender, to: AccountAddressRenderFn.self)
        self.publicKeyFromPrivateFn = staticHandle
            .flatMap { dlsym($0, "connect_norito_public_key_from_private") }
            .map { unsafeBitCast($0, to: PublicKeyFromPrivateFn.self) }
        self.keypairFromSeedFn = staticHandle
            .flatMap { dlsym($0, "connect_norito_keypair_from_seed") }
            .map { unsafeBitCast($0, to: KeypairFromSeedFn.self) }
        self.signDetachedFn = staticHandle
            .flatMap { dlsym($0, "connect_norito_sign_detached") }
            .map { unsafeBitCast($0, to: SignDetachedFn.self) }
        self.verifyDetachedFn = staticHandle
            .flatMap { dlsym($0, "connect_norito_verify_detached") }
            .map { unsafeBitCast($0, to: VerifyDetachedFn.self) }
        self.mldsaParametersFn = unsafeBitCast(mldsaParameters, to: MldsaParametersFn.self)
        self.mldsaGenerateKeypairFn = unsafeBitCast(mldsaGenerateKeypair, to: MldsaGenerateKeypairFn.self)
        self.mldsaSignFn = unsafeBitCast(mldsaSign, to: MldsaSignFn.self)
        self.mldsaVerifyFn = unsafeBitCast(mldsaVerify, to: MldsaVerifyFn.self)
        self.freeFn = connect_norito_free
        if let enterSymbol = staticHandle.flatMap({
            dlsym($0, "connect_norito_chain_discriminant_scope_enter")
        }), let exitSymbol = staticHandle.flatMap({
            dlsym($0, "connect_norito_chain_discriminant_scope_exit")
        }) {
            self.chainDiscriminantScopeFns = (
                enter: unsafeBitCast(enterSymbol, to: ChainDiscriminantScopeEnterFn.self),
                exit: unsafeBitCast(exitSymbol, to: ChainDiscriminantScopeExitFn.self)
            )
        } else {
            self.chainDiscriminantScopeFns = nil
        }
        self.bridgeStatus = .valid(path: "static", identifier: NoritoBridgeLoader.currentIdentifier())
        NSLog("[NoritoNativeBridge] using statically linked Norito bridge")
        #endif
    }

    private func withSignedOutputs<R>(
        signedPtr: inout UnsafeMutablePointer<UInt8>?,
        signedLen: inout UInt,
        _ body: (UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                 UnsafeMutablePointer<UInt>?) -> R
    ) -> R {
        return withUnsafeMutablePointer(to: &signedPtr) { signedPtrPtr in
            withUnsafeMutablePointer(to: &signedLen) { signedLenPtr in
                body(signedPtrPtr, signedLenPtr)
            }
        }
    }

    private func withOptionalCString<R>(
        _ value: String?,
        _ body: (UnsafePointer<CChar>?, UInt, UInt8) -> R
    ) -> R {
        guard let value else {
            return body(nil, 0, 0)
        }
        return value.withCString { pointer in
            body(pointer, UInt(value.utf8.count), 1)
        }
    }
#endif

    static func validateChainDiscriminantContext(
        _ discriminant: UInt16?,
        scopeAvailable: Bool
    ) throws {
        guard discriminant == nil || scopeAvailable else {
            throw NativeBridgeError.bridgeUnavailable
        }
    }

    func withChainDiscriminant<R>(
        _ discriminant: UInt16?,
        _ body: () throws -> R
    ) throws -> R {
        #if canImport(Darwin)
        try Self.validateChainDiscriminantContext(
            discriminant,
            scopeAvailable: chainDiscriminantScopeFns != nil
        )
        guard let discriminant else {
            return try body()
        }
        guard let chainDiscriminantScopeFns else {
            throw NativeBridgeError.bridgeUnavailable
        }
        let token = chainDiscriminantScopeFns.enter(discriminant)
        guard token != 0 else {
            throw NativeBridgeError.bridgeUnavailable
        }
        var exitStatus: Int32?
        let result: Result<R, Error> = {
            defer {
                exitStatus = chainDiscriminantScopeFns.exit(token)
            }
            return Result {
                try body()
            }
        }()
        guard exitStatus == 0 else {
            throw NativeBridgeError.bridgeUnavailable
        }
        return try result.get()
        #else
        return try body()
        #endif
    }

    func validatedAuthorityChainDiscriminant(authority: String) throws -> UInt16 {
        guard !authority.isEmpty,
              authority.trimmingCharacters(in: .whitespacesAndNewlines) == authority,
              authority.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              !authority.contains("@"),
              !authority.contains("#"),
              !authority.contains("$") else {
            throw NativeBridgeError.authority
        }
        do {
            let prefix = try AccountAddress.inspectI105NetworkPrefix(authority, expectedPrefix: nil).chainDiscriminant
            let address = try AccountAddress.parseCanonicalI105(authority, expectedPrefix: prefix)
            guard try address.toI105(networkPrefix: prefix) == authority else {
                throw NativeBridgeError.authority
            }
            return prefix
        } catch let error as NativeBridgeError {
            throw error
        } catch {
            throw NativeBridgeError.authority
        }
    }

    private func withAuthorityChainDiscriminant<R>(
        authority: String,
        _ body: () throws -> R
    ) throws -> R {
        try withChainDiscriminant(validatedAuthorityChainDiscriminant(authority: authority), body)
    }

    private init() {
        #if canImport(Darwin)
        let loadResult = NoritoBridgeLoader.openHandle()
        let handle = loadResult.0
        self.bridgeStatus = loadResult.1
        self.bridgeHandle = handle
        self.loadedBridgeAbiVersion = Self.loadedBridgeAbiVersion(in: handle)
        if let handle,
           let encodeSymbol = dlsym(handle, "connect_norito_encode_transfer_signed_transaction"),
           let freeSymbol = dlsym(handle, "connect_norito_free"),
           let detachedInspectSymbol = dlsym(
               handle,
               "connect_norito_detached_transaction_scaffold_inspect_v1"
           ),
           let detachedFinalizeSymbol = dlsym(
               handle,
               "connect_norito_detached_transaction_scaffold_finalize_ed25519_v1"
           ),
           let canonicalJSONSymbol = dlsym(handle, "connect_norito_canonical_json_blake3_v1") {
            self.encodeTransferFn = unsafeBitCast(encodeSymbol, to: EncodeTransferFn.self)
            self.freeFn = unsafeBitCast(freeSymbol, to: FreeFn.self)
            self.detachedTransactionInspectFn = unsafeBitCast(
                detachedInspectSymbol,
                to: DetachedTransactionInspectFn.self
            )
            self.detachedTransactionFinalizeEd25519Fn = unsafeBitCast(
                detachedFinalizeSymbol,
                to: DetachedTransactionFinalizeEd25519Fn.self
            )
            self.canonicalJSONBlake3Fn = unsafeBitCast(
                canonicalJSONSymbol,
                to: CanonicalJSONBlake3Fn.self
            )
            self.encodeAccountOnboardingPlanBodyFn = dlsym(
                handle,
                "connect_norito_encode_account_onboarding_plan_body_v1"
            ).map { unsafeBitCast($0, to: EncodeAccountOnboardingPlanBodyFn.self) }
            self.aliasInstructionRoundTripFn = dlsym(
                handle,
                "connect_norito_alias_instruction_round_trip_v1"
            ).map { unsafeBitCast($0, to: AliasInstructionRoundTripFn.self) }
            self.parliamentTimedOvnVerifyCastingProofFn = dlsym(
                handle,
                "connect_norito_parliament_timed_ovn_verify_casting_proof_v1"
            ).map { unsafeBitCast($0, to: ParliamentTimedOvnVerifyCastingProofFn.self) }
            self.parliamentTimedOvnVerifyCastingProofPageFn = dlsym(
                handle,
                "connect_norito_parliament_timed_ovn_verify_casting_proof_page_v1"
            ).map { unsafeBitCast($0, to: ParliamentTimedOvnVerifyCastingProofPageFn.self) }
            self.parliamentTimedOvnRegistrationFromProofFn = dlsym(
                handle,
                "connect_norito_parliament_timed_ovn_registration_from_proof_v1"
            ).map { unsafeBitCast($0, to: ParliamentTimedOvnRegistrationFromProofFn.self) }
            self.parliamentTimedOvnBallotFromProofFn = dlsym(
                handle,
                "connect_norito_parliament_timed_ovn_ballot_from_proof_v1"
            ).map { unsafeBitCast($0, to: ParliamentTimedOvnBallotFromProofFn.self) }
            loadPrivacySymbols(from: handle)
            if let enterSymbol = dlsym(
                handle,
                "connect_norito_chain_discriminant_scope_enter"
            ), let exitSymbol = dlsym(
                handle,
                "connect_norito_chain_discriminant_scope_exit"
            ) {
                self.chainDiscriminantScopeFns = (
                    enter: unsafeBitCast(enterSymbol, to: ChainDiscriminantScopeEnterFn.self),
                    exit: unsafeBitCast(exitSymbol, to: ChainDiscriminantScopeExitFn.self)
                )
            } else {
                self.chainDiscriminantScopeFns = nil
            }
            if let encodeAlgSymbol = dlsym(handle, "connect_norito_encode_transfer_signed_transaction_alg") {
                self.encodeTransferWithAlgFn = unsafeBitCast(encodeAlgSymbol, to: EncodeTransferWithAlgFn.self)
            } else {
                self.encodeTransferWithAlgFn = nil
            }
            if let encodeInstructionBoxSymbol = dlsym(handle, "connect_norito_encode_transfer_instruction_box") {
                self.encodeTransferInstructionBoxFn = unsafeBitCast(
                    encodeInstructionBoxSymbol,
                    to: EncodeTransferInstructionBoxFn.self
                )
            } else {
                self.encodeTransferInstructionBoxFn = nil
            }
            self.encodeTransferInstructionFrameFn = dlsym(handle, "connect_norito_encode_transfer_instruction_frame_v1")
                .map { unsafeBitCast($0, to: EncodeTransferInstructionBoxFn.self) }
            if let mintSymbol = dlsym(handle, "connect_norito_encode_mint_signed_transaction") {
                self.encodeMintFn = unsafeBitCast(mintSymbol, to: EncodeMintFn.self)
            } else {
                self.encodeMintFn = nil
            }
            if let mintAlgSymbol = dlsym(handle, "connect_norito_encode_mint_signed_transaction_alg") {
                self.encodeMintWithAlgFn = unsafeBitCast(mintAlgSymbol, to: EncodeMintWithAlgFn.self)
            } else {
                self.encodeMintWithAlgFn = nil
            }
            if let registerZkSymbol = dlsym(handle, "connect_norito_encode_register_zk_asset_signed_transaction") {
                self.encodeRegisterZkAssetFn = unsafeBitCast(registerZkSymbol, to: EncodeRegisterZkAssetFn.self)
            } else {
                self.encodeRegisterZkAssetFn = nil
            }
            if let registerZkAlgSymbol = dlsym(handle, "connect_norito_encode_register_zk_asset_signed_transaction_alg") {
                self.encodeRegisterZkAssetWithAlgFn = unsafeBitCast(registerZkAlgSymbol, to: EncodeRegisterZkAssetWithAlgFn.self)
            } else {
                self.encodeRegisterZkAssetWithAlgFn = nil
            }
            if let multisigRegisterSymbol = dlsym(handle, "connect_norito_encode_multisig_register_signed_transaction") {
                self.encodeMultisigRegisterFn = unsafeBitCast(multisigRegisterSymbol, to: EncodeMultisigRegisterFn.self)
            } else {
                self.encodeMultisigRegisterFn = nil
            }
            if let multisigRegisterAlgSymbol = dlsym(handle, "connect_norito_encode_multisig_register_signed_transaction_alg") {
                self.encodeMultisigRegisterWithAlgFn = unsafeBitCast(multisigRegisterAlgSymbol, to: EncodeMultisigRegisterWithAlgFn.self)
            } else {
                self.encodeMultisigRegisterWithAlgFn = nil
            }
            if let claimIdentifierSymbol = dlsym(handle, "connect_norito_encode_claim_identifier_signed_transaction") {
                self.encodeClaimIdentifierFn = unsafeBitCast(claimIdentifierSymbol, to: EncodeClaimIdentifierFn.self)
            } else {
                self.encodeClaimIdentifierFn = nil
            }
            if let claimIdentifierAlgSymbol = dlsym(handle, "connect_norito_encode_claim_identifier_signed_transaction_alg") {
                self.encodeClaimIdentifierWithAlgFn = unsafeBitCast(claimIdentifierAlgSymbol, to: EncodeClaimIdentifierWithAlgFn.self)
            } else {
                self.encodeClaimIdentifierWithAlgFn = nil
            }
            if let burnSymbol = dlsym(handle, "connect_norito_encode_burn_signed_transaction") {
                self.encodeBurnFn = unsafeBitCast(burnSymbol, to: EncodeBurnFn.self)
            } else {
                self.encodeBurnFn = nil
            }
            if let burnAlgSymbol = dlsym(handle, "connect_norito_encode_burn_signed_transaction_alg") {
                self.encodeBurnWithAlgFn = unsafeBitCast(burnAlgSymbol, to: EncodeBurnWithAlgFn.self)
            } else {
                self.encodeBurnWithAlgFn = nil
            }
            if let setMetadataSymbol = dlsym(handle, "connect_norito_encode_set_key_value_signed_transaction") {
                self.encodeSetKeyValueFn = unsafeBitCast(setMetadataSymbol, to: EncodeSetKeyValueFn.self)
            } else {
                self.encodeSetKeyValueFn = nil
            }
            if let setMetadataAlgSymbol = dlsym(handle, "connect_norito_encode_set_key_value_signed_transaction_alg") {
                self.encodeSetKeyValueWithAlgFn = unsafeBitCast(setMetadataAlgSymbol, to: EncodeSetKeyValueWithAlgFn.self)
            } else {
                self.encodeSetKeyValueWithAlgFn = nil
            }
            if let removeMetadataSymbol = dlsym(handle, "connect_norito_encode_remove_key_value_signed_transaction") {
                self.encodeRemoveKeyValueFn = unsafeBitCast(removeMetadataSymbol, to: EncodeRemoveKeyValueFn.self)
            } else {
                self.encodeRemoveKeyValueFn = nil
            }
            if let removeMetadataAlgSymbol = dlsym(handle, "connect_norito_encode_remove_key_value_signed_transaction_alg") {
                self.encodeRemoveKeyValueWithAlgFn = unsafeBitCast(removeMetadataAlgSymbol, to: EncodeRemoveKeyValueWithAlgFn.self)
            } else {
                self.encodeRemoveKeyValueWithAlgFn = nil
            }
            if let proposeDeploySymbol = dlsym(handle, "connect_norito_encode_governance_propose_deploy_v1_signed_transaction") {
                self.encodeGovernanceProposeDeployFn = unsafeBitCast(proposeDeploySymbol, to: EncodeGovernanceProposeDeployFn.self)
            } else {
                self.encodeGovernanceProposeDeployFn = nil
            }
            if let proposeDeployAlgSymbol = dlsym(handle, "connect_norito_encode_governance_propose_deploy_v1_signed_transaction_alg") {
                self.encodeGovernanceProposeDeployWithAlgFn = unsafeBitCast(proposeDeployAlgSymbol, to: EncodeGovernanceProposeDeployWithAlgFn.self)
            } else {
                self.encodeGovernanceProposeDeployWithAlgFn = nil
            }
            if let castPlainSymbol = dlsym(handle, "connect_norito_encode_governance_cast_plain_ballot_signed_transaction") {
                self.encodeGovernanceCastPlainBallotFn = unsafeBitCast(castPlainSymbol, to: EncodeGovernanceCastPlainBallotFn.self)
            } else {
                self.encodeGovernanceCastPlainBallotFn = nil
            }
            if let castPlainAlgSymbol = dlsym(handle, "connect_norito_encode_governance_cast_plain_ballot_signed_transaction_alg") {
                self.encodeGovernanceCastPlainBallotWithAlgFn = unsafeBitCast(castPlainAlgSymbol, to: EncodeGovernanceCastPlainBallotWithAlgFn.self)
            } else {
                self.encodeGovernanceCastPlainBallotWithAlgFn = nil
            }
            if let updatePlainSymbol = dlsym(handle, "connect_norito_encode_governance_update_plain_conviction_signed_transaction_alg") {
                self.encodeGovernanceUpdatePlainConvictionFn = unsafeBitCast(updatePlainSymbol, to: EncodeGovernanceUpdatePlainConvictionFn.self)
            } else {
                self.encodeGovernanceUpdatePlainConvictionFn = nil
            }
            if let castZkSymbol = dlsym(handle, "connect_norito_encode_governance_cast_zk_ballot_signed_transaction") {
                self.encodeGovernanceCastZkBallotFn = unsafeBitCast(castZkSymbol, to: EncodeGovernanceCastZkBallotFn.self)
            } else {
                self.encodeGovernanceCastZkBallotFn = nil
            }
            if let castZkAlgSymbol = dlsym(handle, "connect_norito_encode_governance_cast_zk_ballot_signed_transaction_alg") {
                self.encodeGovernanceCastZkBallotWithAlgFn = unsafeBitCast(castZkAlgSymbol, to: EncodeGovernanceCastZkBallotWithAlgFn.self)
            } else {
                self.encodeGovernanceCastZkBallotWithAlgFn = nil
            }
            if let decodeSymbol = dlsym(handle, "connect_norito_decode_signed_transaction_json") {
                self.decodeSignedFn = unsafeBitCast(decodeSymbol, to: DecodeSignedFn.self)
            } else {
                self.decodeSignedFn = nil
            }
            if let decodeReceiptSymbol = dlsym(handle, "connect_norito_decode_transaction_receipt_json") {
                self.decodeReceiptFn = unsafeBitCast(decodeReceiptSymbol, to: DecodeReceiptFn.self)
            } else {
                self.decodeReceiptFn = nil
            }
            if let decodeAssetIdSymbol = dlsym(handle, "connect_norito_decode_asset_id_json") {
                self.decodeAssetIdFn = unsafeBitCast(decodeAssetIdSymbol, to: DecodeAssetIdFn.self)
            } else {
                self.decodeAssetIdFn = nil
            }
            if let publicKeyFromPrivateSymbol = dlsym(handle, "connect_norito_public_key_from_private") {
                self.publicKeyFromPrivateFn = unsafeBitCast(publicKeyFromPrivateSymbol, to: PublicKeyFromPrivateFn.self)
            } else {
                self.publicKeyFromPrivateFn = nil
            }
            if let keypairFromSeedSymbol = dlsym(handle, "connect_norito_keypair_from_seed") {
                self.keypairFromSeedFn = unsafeBitCast(keypairFromSeedSymbol, to: KeypairFromSeedFn.self)
            } else {
                self.keypairFromSeedFn = nil
            }
            if let signDetachedSymbol = dlsym(handle, "connect_norito_sign_detached") {
                self.signDetachedFn = unsafeBitCast(signDetachedSymbol, to: SignDetachedFn.self)
            } else {
                self.signDetachedFn = nil
            }
            if let verifyDetachedSymbol = dlsym(handle, "connect_norito_verify_detached") {
                self.verifyDetachedFn = unsafeBitCast(verifyDetachedSymbol, to: VerifyDetachedFn.self)
            } else {
                self.verifyDetachedFn = nil
            }
            if let accelSymbol = dlsym(handle, "connect_norito_acceleration_config_set_v1") {
                self.setAccelerationConfigFn = unsafeBitCast(accelSymbol, to: SetAccelerationConfigFn.self)
            } else {
                self.setAccelerationConfigFn = nil
            }
            if let accelGetSymbol = dlsym(handle, "connect_norito_acceleration_config_get_v1") {
                self.getAccelerationConfigFn = unsafeBitCast(accelGetSymbol, to: GetAccelerationConfigFn.self)
            } else {
                self.getAccelerationConfigFn = nil
            }
            if let accelStateSymbol = dlsym(handle, "connect_norito_acceleration_state_get_v1") {
                self.getAccelerationStateFn = unsafeBitCast(accelStateSymbol, to: GetAccelerationStateFn.self)
            } else {
                self.getAccelerationStateFn = nil
            }
            if let encodeCiphertextSymbol = dlsym(handle, "connect_norito_encode_ciphertext_frame") {
                self.encodeCiphertextFrameFn = unsafeBitCast(encodeCiphertextSymbol, to: EncodeCiphertextFrameFn.self)
            } else {
                self.encodeCiphertextFrameFn = nil
            }
            if let encodeControlOpenSymbol = dlsym(handle, "connect_norito_encode_control_open_ext") {
                self.encodeControlOpenFn = unsafeBitCast(encodeControlOpenSymbol, to: EncodeControlOpenFn.self)
            } else {
                self.encodeControlOpenFn = nil
            }
            if let encodeControlApproveSymbol = dlsym(handle, "connect_norito_encode_control_approve_ext") {
                self.encodeControlApproveFn = unsafeBitCast(encodeControlApproveSymbol, to: EncodeControlApproveFn.self)
            } else {
                self.encodeControlApproveFn = nil
            }
            if let encodeControlApproveAlgSymbol = dlsym(handle, "connect_norito_encode_control_approve_ext_with_alg") {
                self.encodeControlApproveWithAlgFn = unsafeBitCast(encodeControlApproveAlgSymbol, to: EncodeControlApproveWithAlgFn.self)
            } else {
                self.encodeControlApproveWithAlgFn = nil
            }
            if let encodeControlRejectSymbol = dlsym(handle, "connect_norito_encode_control_reject") {
                self.encodeControlRejectFn = unsafeBitCast(encodeControlRejectSymbol, to: EncodeControlRejectFn.self)
            } else {
                self.encodeControlRejectFn = nil
            }
            if let encodeControlCloseSymbol = dlsym(handle, "connect_norito_encode_control_close") {
                self.encodeControlCloseFn = unsafeBitCast(encodeControlCloseSymbol, to: EncodeControlCloseFn.self)
            } else {
                self.encodeControlCloseFn = nil
            }
            if let encodeControlPingSymbol = dlsym(handle, "connect_norito_encode_control_ping") {
                self.encodeControlPingFn = unsafeBitCast(encodeControlPingSymbol, to: EncodeControlPingFn.self)
            } else {
                self.encodeControlPingFn = nil
            }
            if let encodeControlPongSymbol = dlsym(handle, "connect_norito_encode_control_pong") {
                self.encodeControlPongFn = unsafeBitCast(encodeControlPongSymbol, to: EncodeControlPongFn.self)
            } else {
                self.encodeControlPongFn = nil
            }
            if let encodeConfidentialSymbol = dlsym(handle, "connect_norito_encode_confidential_encrypted_payload") {
                self.encodeConfidentialPayloadFn = unsafeBitCast(encodeConfidentialSymbol, to: EncodeConfidentialPayloadFn.self)
            } else {
                self.encodeConfidentialPayloadFn = nil
            }
            if let accountAddressParseSymbol = dlsym(handle, "connect_norito_account_address_parse") {
                self.accountAddressParseFn = unsafeBitCast(accountAddressParseSymbol, to: AccountAddressParseFn.self)
            } else {
                self.accountAddressParseFn = nil
            }
            if let accountAddressRenderSymbol = dlsym(handle, "connect_norito_account_address_render") {
                self.accountAddressRenderFn = unsafeBitCast(accountAddressRenderSymbol, to: AccountAddressRenderFn.self)
            } else {
                self.accountAddressRenderFn = nil
            }
            if let connectGenerateKeypairSymbol = dlsym(handle, "connect_norito_connect_generate_keypair") {
                self.connectGenerateKeypairFn = unsafeBitCast(connectGenerateKeypairSymbol, to: ConnectGenerateKeypairFn.self)
            } else {
                self.connectGenerateKeypairFn = nil
            }
            if let connectPublicFromPrivateSymbol = dlsym(handle, "connect_norito_connect_public_from_private") {
                self.connectPublicFromPrivateFn = unsafeBitCast(connectPublicFromPrivateSymbol, to: ConnectPublicFromPrivateFn.self)
            } else {
                self.connectPublicFromPrivateFn = nil
            }
            if let connectDeriveKeysSymbol = dlsym(handle, "connect_norito_connect_derive_keys") {
                self.connectDeriveKeysFn = unsafeBitCast(connectDeriveKeysSymbol, to: ConnectDeriveKeysFn.self)
            } else {
                self.connectDeriveKeysFn = nil
            }
            if let connectEncryptEnvelopeSymbol = dlsym(handle, "connect_norito_connect_encrypt_envelope") {
                self.connectEncryptEnvelopeFn = unsafeBitCast(connectEncryptEnvelopeSymbol, to: ConnectEncryptEnvelopeFn.self)
            } else {
                self.connectEncryptEnvelopeFn = nil
            }
            if let connectDecryptCiphertextSymbol = dlsym(handle, "connect_norito_connect_decrypt_ciphertext") {
                self.connectDecryptCiphertextFn = unsafeBitCast(connectDecryptCiphertextSymbol, to: ConnectDecryptCiphertextFn.self)
            } else {
                self.connectDecryptCiphertextFn = nil
            }
            if let encodeEnvelopeSignRequestTxSymbol = dlsym(handle, "connect_norito_encode_envelope_sign_request_tx") {
                self.encodeEnvelopeSignRequestTxFn = unsafeBitCast(encodeEnvelopeSignRequestTxSymbol, to: EncodeEnvelopeSignRequestTxFn.self)
            } else {
                self.encodeEnvelopeSignRequestTxFn = nil
            }
            if let encodeEnvelopeSignRequestRawSymbol = dlsym(handle, "connect_norito_encode_envelope_sign_request_raw") {
                self.encodeEnvelopeSignRequestRawFn = unsafeBitCast(encodeEnvelopeSignRequestRawSymbol, to: EncodeEnvelopeSignRequestRawFn.self)
            } else {
                self.encodeEnvelopeSignRequestRawFn = nil
            }
            if let encodeEnvelopeSignResultOkSymbol = dlsym(handle, "connect_norito_encode_envelope_sign_result_ok") {
                self.encodeEnvelopeSignResultOkFn = unsafeBitCast(encodeEnvelopeSignResultOkSymbol, to: EncodeEnvelopeSignResultOkFn.self)
            } else {
                self.encodeEnvelopeSignResultOkFn = nil
            }
            if let encodeEnvelopeSignResultOkWithAlgSymbol = dlsym(handle, "connect_norito_encode_envelope_sign_result_ok_with_alg") {
                self.encodeEnvelopeSignResultOkWithAlgFn = unsafeBitCast(encodeEnvelopeSignResultOkWithAlgSymbol, to: EncodeEnvelopeSignResultOkWithAlgFn.self)
            } else {
                self.encodeEnvelopeSignResultOkWithAlgFn = nil
            }
            if let encodeEnvelopeSignResultErrSymbol = dlsym(handle, "connect_norito_encode_envelope_sign_result_err") {
                self.encodeEnvelopeSignResultErrFn = unsafeBitCast(encodeEnvelopeSignResultErrSymbol, to: EncodeEnvelopeSignResultErrFn.self)
            } else {
                self.encodeEnvelopeSignResultErrFn = nil
            }
            if let encodeEnvelopeControlCloseSymbol = dlsym(handle, "connect_norito_encode_envelope_control_close") {
                self.encodeEnvelopeControlCloseFn = unsafeBitCast(encodeEnvelopeControlCloseSymbol, to: EncodeEnvelopeControlCloseFn.self)
            } else {
                self.encodeEnvelopeControlCloseFn = nil
            }
            if let encodeEnvelopeControlRejectSymbol = dlsym(handle, "connect_norito_encode_envelope_control_reject") {
                self.encodeEnvelopeControlRejectFn = unsafeBitCast(encodeEnvelopeControlRejectSymbol, to: EncodeEnvelopeControlRejectFn.self)
            } else {
                self.encodeEnvelopeControlRejectFn = nil
            }
            if let decodeEnvelopeKindSymbol = dlsym(handle, "connect_norito_decode_envelope_kind") {
                self.decodeEnvelopeKindFn = unsafeBitCast(decodeEnvelopeKindSymbol, to: DecodeEnvelopeKindFn.self)
            } else {
                self.decodeEnvelopeKindFn = nil
            }
            if let decodeEnvelopeJsonSymbol = dlsym(handle, "connect_norito_decode_envelope_json") {
                self.decodeEnvelopeJSONFn = unsafeBitCast(decodeEnvelopeJsonSymbol, to: DecodeEnvelopeJSONFn.self)
            } else {
                self.decodeEnvelopeJSONFn = nil
            }
            if let decodeControlKindSymbol = dlsym(handle, "connect_norito_decode_control_kind") {
                self.decodeControlKindFn = unsafeBitCast(decodeControlKindSymbol, to: DecodeControlKindFn.self)
            } else {
                self.decodeControlKindFn = nil
            }
            if let decodeCiphertextSymbol = dlsym(handle, "connect_norito_decode_ciphertext_frame") {
                self.decodeCiphertextFrameFn = unsafeBitCast(decodeCiphertextSymbol, to: DecodeCiphertextFrameFn.self)
            } else {
                self.decodeCiphertextFrameFn = nil
            }
            if let decodeControlOpenPubSymbol = dlsym(handle, "connect_norito_decode_control_open_pub") {
                self.decodeControlOpenPubFn = unsafeBitCast(decodeControlOpenPubSymbol, to: DecodeControlOpenPubFn.self)
            } else {
                self.decodeControlOpenPubFn = nil
            }
            if let decodeControlOpenNetworkSymbol = dlsym(handle, "connect_norito_decode_control_open_network_id") {
                self.decodeControlOpenNetworkIdFn = unsafeBitCast(decodeControlOpenNetworkSymbol, to: DecodeControlOpenNetworkIdFn.self)
            } else {
                self.decodeControlOpenNetworkIdFn = nil
            }
            if let decodeControlOpenMetadataSymbol = dlsym(handle, "connect_norito_decode_control_open_app_metadata_json") {
                self.decodeControlOpenAppMetadataFn = unsafeBitCast(decodeControlOpenMetadataSymbol, to: DecodeControlOpenAppMetadataFn.self)
            } else {
                self.decodeControlOpenAppMetadataFn = nil
            }
            if let decodeControlOpenPermsSymbol = dlsym(handle, "connect_norito_decode_control_open_permissions_json") {
                self.decodeControlOpenPermissionsFn = unsafeBitCast(decodeControlOpenPermsSymbol, to: DecodeControlOpenPermissionsFn.self)
            } else {
                self.decodeControlOpenPermissionsFn = nil
            }
            if let decodeControlApprovePubSymbol = dlsym(handle, "connect_norito_decode_control_approve_pub") {
                self.decodeControlApprovePubFn = unsafeBitCast(decodeControlApprovePubSymbol, to: DecodeControlApprovePubFn.self)
            } else {
                self.decodeControlApprovePubFn = nil
            }
            if let decodeControlApproveAccountSymbol = dlsym(handle, "connect_norito_decode_control_approve_account") {
                self.decodeControlApproveAccountFn = unsafeBitCast(decodeControlApproveAccountSymbol, to: DecodeControlApproveAccountFn.self)
            } else {
                self.decodeControlApproveAccountFn = nil
            }
            if let decodeControlApprovePermsSymbol = dlsym(handle, "connect_norito_decode_control_approve_permissions_json") {
                self.decodeControlApprovePermissionsFn = unsafeBitCast(decodeControlApprovePermsSymbol, to: DecodeControlApprovePermissionsFn.self)
            } else {
                self.decodeControlApprovePermissionsFn = nil
            }
            if let decodeControlApproveProofSymbol = dlsym(handle, "connect_norito_decode_control_approve_proof_json") {
                self.decodeControlApproveProofFn = unsafeBitCast(decodeControlApproveProofSymbol, to: DecodeControlApproveProofFn.self)
            } else {
                self.decodeControlApproveProofFn = nil
            }
            if let decodeControlApproveSigSymbol = dlsym(handle, "connect_norito_decode_control_approve_sig") {
                self.decodeControlApproveSigFn = unsafeBitCast(decodeControlApproveSigSymbol, to: DecodeControlApproveSigFn.self)
            } else {
                self.decodeControlApproveSigFn = nil
            }
            if let decodeControlApproveSigAlgSymbol = dlsym(handle, "connect_norito_decode_control_approve_sig_alg") {
                self.decodeControlApproveSigAlgFn = unsafeBitCast(decodeControlApproveSigAlgSymbol, to: DecodeControlApproveSigAlgFn.self)
            } else {
                self.decodeControlApproveSigAlgFn = nil
            }
            if let decodeControlCloseSymbol = dlsym(handle, "connect_norito_decode_control_close") {
                self.decodeControlCloseFn = unsafeBitCast(decodeControlCloseSymbol, to: DecodeControlCloseFn.self)
            } else {
                self.decodeControlCloseFn = nil
            }
            if let decodeControlRejectSymbol = dlsym(handle, "connect_norito_decode_control_reject") {
                self.decodeControlRejectFn = unsafeBitCast(decodeControlRejectSymbol, to: DecodeControlRejectFn.self)
            } else {
                self.decodeControlRejectFn = nil
            }
            if let decodeControlPingSymbol = dlsym(handle, "connect_norito_decode_control_ping") {
                self.decodeControlPingFn = unsafeBitCast(decodeControlPingSymbol, to: DecodeControlPingFn.self)
            } else {
                self.decodeControlPingFn = nil
            }
            if let decodeControlPongSymbol = dlsym(handle, "connect_norito_decode_control_pong") {
                self.decodeControlPongFn = unsafeBitCast(decodeControlPongSymbol, to: DecodeControlPongFn.self)
            } else {
                self.decodeControlPongFn = nil
            }
            if let sorafsLocalFetchSymbol = dlsym(handle, "connect_norito_sorafs_local_fetch") {
                self.sorafsLocalFetchFn = unsafeBitCast(sorafsLocalFetchSymbol, to: SorafsLocalFetchFn.self)
            } else {
                self.sorafsLocalFetchFn = nil
            }
            if let symbol = dlsym(handle, "connect_norito_sorafs_reference_validate_orderbook_json") {
                self.sorafsReferenceValidateOrderbookFn = unsafeBitCast(symbol, to: SorafsReferencePayloadFn.self)
            } else {
                self.sorafsReferenceValidateOrderbookFn = nil
            }
            if let symbol = dlsym(handle, "connect_norito_sorafs_reference_validate_pop_json") {
                self.sorafsReferenceValidatePopPayloadFn = unsafeBitCast(symbol, to: SorafsReferencePayloadFn.self)
            } else {
                self.sorafsReferenceValidatePopPayloadFn = nil
            }
            if let symbol = dlsym(handle, "connect_norito_sorafs_reference_validate_hedging_json") {
                self.sorafsReferenceValidateHedgingPayloadFn = unsafeBitCast(symbol, to: SorafsReferencePayloadFn.self)
            } else {
                self.sorafsReferenceValidateHedgingPayloadFn = nil
            }
            if let symbol = dlsym(
                handle,
                "connect_norito_sorafs_reference_validate_appeal_finance_cancel_asset_lock_json"
            ) {
                self.sorafsReferenceValidateAppealFinanceCancelAssetLockFn = unsafeBitCast(
                    symbol,
                    to: SorafsReferenceSinglePayloadFn.self
                )
            } else {
                self.sorafsReferenceValidateAppealFinanceCancelAssetLockFn = nil
            }
            if let symbol = dlsym(handle, "connect_norito_sorafs_reference_validate_bundle_json") {
                self.sorafsReferenceValidateFixtureBundleFn = unsafeBitCast(
                    symbol,
                    to: SorafsReferenceFixtureBundleFn.self
                )
            } else {
                self.sorafsReferenceValidateFixtureBundleFn = nil
            }
            if let symbol = dlsym(
                handle,
                "connect_norito_sorafs_reference_validate_governance_json"
            ) {
                self.sorafsReferenceValidateGovernanceLogNodeFn = unsafeBitCast(
                    symbol,
                    to: SorafsReferenceGovernanceLogNodeFn.self
                )
            } else {
                self.sorafsReferenceValidateGovernanceLogNodeFn = nil
            }
            if let symbol = dlsym(
                handle,
                "connect_norito_sorafs_reference_validate_governance_dag_block_json"
            ) {
                self.sorafsReferenceValidateGovernanceDagBlockFn = unsafeBitCast(
                    symbol,
                    to: SorafsReferenceGovernanceDagBlockFn.self
                )
            } else {
                self.sorafsReferenceValidateGovernanceDagBlockFn = nil
            }
            if let symbol = dlsym(
                handle,
                "connect_norito_sorafs_reference_validate_governance_dag_head_chain_json"
            ) {
                self.sorafsReferenceValidateGovernanceDagHeadChainFn = unsafeBitCast(
                    symbol,
                    to: SorafsReferenceGovernanceDagHeadChainFn.self
                )
            } else {
                self.sorafsReferenceValidateGovernanceDagHeadChainFn = nil
            }
            if let symbol = dlsym(handle, "connect_norito_sorafs_reference_sign_orderbook_payload") {
                self.sorafsReferenceSignOrderbookFn = unsafeBitCast(symbol, to: SorafsReferenceOrderbookSignFn.self)
            } else {
                self.sorafsReferenceSignOrderbookFn = nil
            }
            if let symbol = dlsym(handle, "connect_norito_sorafs_reference_derive_orderbook_order_id") {
                self.sorafsReferenceDeriveOrderbookOrderIdFn = unsafeBitCast(
                    symbol,
                    to: SorafsReferenceOrderbookOrderIdDeriveFn.self
                )
            } else {
                self.sorafsReferenceDeriveOrderbookOrderIdFn = nil
            }
            if let symbol = dlsym(handle, "connect_norito_sorafs_reference_build_signed_orderbook_order_request") {
                self.sorafsReferenceBuildOrderbookOrderRequestFn = unsafeBitCast(
                    symbol,
                    to: SorafsReferenceOrderbookOrderRequestBuilderFn.self
                )
            } else {
                self.sorafsReferenceBuildOrderbookOrderRequestFn = nil
            }
            if let symbol = dlsym(handle, "connect_norito_sorafs_reference_build_signed_orderbook_order_cancel") {
                self.sorafsReferenceBuildOrderbookOrderCancelFn = unsafeBitCast(
                    symbol,
                    to: SorafsReferenceOrderbookCancelBuilderFn.self
                )
            } else {
                self.sorafsReferenceBuildOrderbookOrderCancelFn = nil
            }
            if let symbol = dlsym(handle, "connect_norito_sorafs_reference_build_signed_orderbook_settlement_receipt") {
                self.sorafsReferenceBuildOrderbookSettlementReceiptFn = unsafeBitCast(
                    symbol,
                    to: SorafsReferenceOrderbookSettlementReceiptBuilderFn.self
                )
            } else {
                self.sorafsReferenceBuildOrderbookSettlementReceiptFn = nil
            }
            if let symbol = dlsym(handle, "connect_norito_sorafs_reference_validate_pdp_payload_json") {
                self.sorafsReferenceValidatePdpPayloadFn = unsafeBitCast(symbol, to: SorafsReferencePayloadFn.self)
            } else {
                self.sorafsReferenceValidatePdpPayloadFn = nil
            }
            if let symbol = dlsym(handle, "connect_norito_sorafs_reference_validate_pdp_commitment_challenge_json") {
                self.sorafsReferenceValidatePdpCommitmentChallengeFn = unsafeBitCast(symbol, to: SorafsReferencePdpPairFn.self)
            } else {
                self.sorafsReferenceValidatePdpCommitmentChallengeFn = nil
            }
            if let symbol = dlsym(handle, "connect_norito_sorafs_reference_validate_pdp_challenge_proof_json") {
                self.sorafsReferenceValidatePdpChallengeProofFn = unsafeBitCast(symbol, to: SorafsReferencePdpPairFn.self)
            } else {
                self.sorafsReferenceValidatePdpChallengeProofFn = nil
            }
            if let symbol = dlsym(handle, "connect_norito_sorafs_reference_validate_pdp_bundle_json") {
                self.sorafsReferenceValidatePdpBundleFn = unsafeBitCast(symbol, to: SorafsReferencePdpBundleFn.self)
            } else {
                self.sorafsReferenceValidatePdpBundleFn = nil
            }
            if let daProofSummarySymbol = dlsym(handle, "connect_norito_da_proof_summary") {
                self.daProofSummaryFn = unsafeBitCast(daProofSummarySymbol, to: DaProofSummaryFn.self)
            } else {
                self.daProofSummaryFn = nil
            }
            if let blake3Symbol = dlsym(handle, "connect_norito_blake3_hash") {
                self.blake3HashFn = unsafeBitCast(blake3Symbol, to: Blake3HashFn.self)
            } else {
                self.blake3HashFn = nil
            }
            if let sm2DefaultSymbol = dlsym(handle, "connect_norito_sm2_default_distid") {
                self.sm2DefaultDistidFn = unsafeBitCast(sm2DefaultSymbol, to: Sm2DefaultDistidFn.self)
            } else {
                self.sm2DefaultDistidFn = nil
            }
            if let sm2KeypairSymbol = dlsym(handle, "connect_norito_sm2_keypair_from_seed") {
                self.sm2KeypairFromSeedFn = unsafeBitCast(sm2KeypairSymbol, to: Sm2KeypairFromSeedFn.self)
            } else {
                self.sm2KeypairFromSeedFn = nil
            }
            if let sm2SignSymbol = dlsym(handle, "connect_norito_sm2_sign") {
                self.sm2SignFn = unsafeBitCast(sm2SignSymbol, to: Sm2SignFn.self)
            } else {
                self.sm2SignFn = nil
            }
            if let sm2VerifySymbol = dlsym(handle, "connect_norito_sm2_verify") {
                self.sm2VerifyFn = unsafeBitCast(sm2VerifySymbol, to: Sm2VerifyFn.self)
            } else {
                self.sm2VerifyFn = nil
            }
            if let sm2PrefixedSymbol = dlsym(handle, "connect_norito_sm2_public_key_prefixed") {
                self.sm2PublicKeyPrefixedFn = unsafeBitCast(sm2PrefixedSymbol, to: Sm2PublicKeyStringFn.self)
            } else {
                self.sm2PublicKeyPrefixedFn = nil
            }
            if let sm2MultihashSymbol = dlsym(handle, "connect_norito_sm2_public_key_multihash") {
                self.sm2PublicKeyMultihashFn = unsafeBitCast(sm2MultihashSymbol, to: Sm2PublicKeyStringFn.self)
            } else {
                self.sm2PublicKeyMultihashFn = nil
            }
            if let sm2ComputeZaSymbol = dlsym(handle, "connect_norito_sm2_compute_za") {
                self.sm2ComputeZaFn = unsafeBitCast(sm2ComputeZaSymbol, to: Sm2ComputeZaFn.self)
            } else {
                self.sm2ComputeZaFn = nil
            }
            if let secpPublicSymbol = dlsym(handle, "connect_norito_secp256k1_public_key") {
                self.secp256k1PublicKeyFn = unsafeBitCast(secpPublicSymbol, to: Secp256k1PublicKeyFn.self)
            } else {
                self.secp256k1PublicKeyFn = nil
            }
            if let secpSignSymbol = dlsym(handle, "connect_norito_secp256k1_sign") {
                self.secp256k1SignFn = unsafeBitCast(secpSignSymbol, to: Secp256k1SignFn.self)
            } else {
                self.secp256k1SignFn = nil
            }
            if let secpVerifySymbol = dlsym(handle, "connect_norito_secp256k1_verify") {
                self.secp256k1VerifyFn = unsafeBitCast(secpVerifySymbol, to: Secp256k1VerifyFn.self)
            } else {
                self.secp256k1VerifyFn = nil
            }
            if let mldsaParamsSymbol = dlsym(handle, "soranet_mldsa_parameters") {
                self.mldsaParametersFn = unsafeBitCast(mldsaParamsSymbol, to: MldsaParametersFn.self)
            } else {
                self.mldsaParametersFn = nil
            }
            if let mldsaGenerateSymbol = dlsym(handle, "soranet_mldsa_generate_keypair") {
                self.mldsaGenerateKeypairFn = unsafeBitCast(mldsaGenerateSymbol, to: MldsaGenerateKeypairFn.self)
            } else {
                self.mldsaGenerateKeypairFn = nil
            }
            if let mldsaSignSymbol = dlsym(handle, "soranet_mldsa_sign") {
                self.mldsaSignFn = unsafeBitCast(mldsaSignSymbol, to: MldsaSignFn.self)
            } else {
                self.mldsaSignFn = nil
            }
            if let mldsaVerifySymbol = dlsym(handle, "soranet_mldsa_verify") {
                self.mldsaVerifyFn = unsafeBitCast(mldsaVerifySymbol, to: MldsaVerifyFn.self)
            } else {
                self.mldsaVerifyFn = nil
            }
        } else {
            self.encodeTransferFn = nil
            self.encodeTransferWithAlgFn = nil
            self.encodeTransferInstructionBoxFn = nil
            self.encodeTransferInstructionFrameFn = nil
            self.encodeMintFn = nil
            self.encodeMintWithAlgFn = nil
            self.encodeRegisterZkAssetFn = nil
            self.encodeRegisterZkAssetWithAlgFn = nil
            self.encodeMultisigRegisterFn = nil
            self.encodeMultisigRegisterWithAlgFn = nil
            self.encodeClaimIdentifierFn = nil
            self.encodeClaimIdentifierWithAlgFn = nil
            self.encodeBurnFn = nil
            self.encodeBurnWithAlgFn = nil
            self.encodeSetKeyValueFn = nil
            self.encodeSetKeyValueWithAlgFn = nil
            self.encodeRemoveKeyValueFn = nil
            self.encodeRemoveKeyValueWithAlgFn = nil
            self.encodeGovernanceProposeDeployFn = nil
            self.encodeGovernanceProposeDeployWithAlgFn = nil
            self.encodeGovernanceCastPlainBallotFn = nil
            self.encodeGovernanceCastPlainBallotWithAlgFn = nil
            self.encodeGovernanceUpdatePlainConvictionFn = nil
            self.encodeGovernanceCastZkBallotFn = nil
            self.encodeGovernanceCastZkBallotWithAlgFn = nil
            self.decodeSignedFn = nil
            self.decodeReceiptFn = nil
            self.decodeAssetIdFn = nil
            self.freeFn = nil
            self.chainDiscriminantScopeFns = nil
            self.setAccelerationConfigFn = nil
            self.getAccelerationConfigFn = nil
            self.getAccelerationStateFn = nil
            self.encodeCiphertextFrameFn = nil
            self.encodeControlOpenFn = nil
            self.encodeControlApproveFn = nil
            self.encodeControlApproveWithAlgFn = nil
            self.encodeControlRejectFn = nil
            self.encodeControlCloseFn = nil
            self.encodeControlPingFn = nil
            self.encodeControlPongFn = nil
            self.sorafsLocalFetchFn = nil
            self.sorafsReferenceValidateOrderbookFn = nil
            self.sorafsReferenceSignOrderbookFn = nil
            self.sorafsReferenceDeriveOrderbookOrderIdFn = nil
            self.sorafsReferenceBuildOrderbookOrderRequestFn = nil
            self.sorafsReferenceBuildOrderbookOrderCancelFn = nil
            self.sorafsReferenceBuildOrderbookSettlementReceiptFn = nil
            self.sorafsReferenceValidatePopPayloadFn = nil
            self.sorafsReferenceValidateHedgingPayloadFn = nil
            self.sorafsReferenceValidateAppealFinanceCancelAssetLockFn = nil
            self.sorafsReferenceValidateFixtureBundleFn = nil
            self.sorafsReferenceValidateGovernanceLogNodeFn = nil
            self.sorafsReferenceValidatePdpPayloadFn = nil
            self.sorafsReferenceValidatePdpCommitmentChallengeFn = nil
            self.sorafsReferenceValidatePdpChallengeProofFn = nil
            self.sorafsReferenceValidatePdpBundleFn = nil
            self.daProofSummaryFn = nil
            self.blake3HashFn = nil
            self.detachedTransactionInspectFn = nil
            self.detachedTransactionFinalizeEd25519Fn = nil
            self.encodeAccountOnboardingPlanBodyFn = nil
            self.aliasInstructionRoundTripFn = nil
            self.canonicalJSONBlake3Fn = nil
            self.parliamentTimedOvnVerifyCastingProofPageFn = nil
            self.parliamentTimedOvnVerifyCastingProofFn = nil
            self.parliamentTimedOvnRegistrationFromProofFn = nil
            self.parliamentTimedOvnBallotFromProofFn = nil
            self.privacyCompiledProfileCatalogFn = nil
            self.privacyValidateCompiledProfileCatalogFn = nil
            self.privacyValidateExact12CapabilityManifestFn = nil
            self.privacyExact12FixtureBundleFn = nil
            self.privacyValidateExact12FixtureBundleFn = nil
            self.privacyFreeFn = nil
            self.encodeConfidentialPayloadFn = nil
            self.accountAddressParseFn = nil
            self.accountAddressRenderFn = nil
            self.sm2DefaultDistidFn = nil
            self.sm2KeypairFromSeedFn = nil
            self.sm2SignFn = nil
            self.sm2VerifyFn = nil
            self.sm2PublicKeyPrefixedFn = nil
            self.sm2PublicKeyMultihashFn = nil
            self.sm2ComputeZaFn = nil
            self.secp256k1PublicKeyFn = nil
            self.secp256k1SignFn = nil
            self.secp256k1VerifyFn = nil
            self.mldsaParametersFn = nil
            self.mldsaGenerateKeypairFn = nil
            self.mldsaSignFn = nil
            self.mldsaVerifyFn = nil
            self.connectGenerateKeypairFn = nil
            self.connectPublicFromPrivateFn = nil
            self.connectDeriveKeysFn = nil
            self.connectEncryptEnvelopeFn = nil
            self.connectDecryptCiphertextFn = nil
            self.encodeEnvelopeSignRequestTxFn = nil
            self.encodeEnvelopeSignRequestRawFn = nil
            self.encodeEnvelopeSignResultOkFn = nil
            self.encodeEnvelopeSignResultOkWithAlgFn = nil
            self.encodeEnvelopeSignResultErrFn = nil
            self.encodeEnvelopeControlCloseFn = nil
            self.encodeEnvelopeControlRejectFn = nil
            self.decodeEnvelopeKindFn = nil
            self.decodeEnvelopeJSONFn = nil
            self.decodeControlKindFn = nil
            self.decodeCiphertextFrameFn = nil
            self.decodeControlOpenPubFn = nil
            self.decodeControlOpenNetworkIdFn = nil
            self.decodeControlOpenAppMetadataFn = nil
            self.decodeControlOpenPermissionsFn = nil
            self.decodeControlApprovePubFn = nil
            self.decodeControlApproveAccountFn = nil
            self.decodeControlApprovePermissionsFn = nil
            self.decodeControlApproveProofFn = nil
            self.decodeControlApproveSigFn = nil
            self.decodeControlApproveSigAlgFn = nil
            self.decodeControlCloseFn = nil
            self.decodeControlRejectFn = nil
            self.decodeControlPingFn = nil
            self.decodeControlPongFn = nil
        }

        if self.encodeTransferFn == nil || self.freeFn == nil {
            installStaticallyLinkedBridgeIfAvailable()
        }
        probePrivacyNativeAvailability()

        // The process-owned native configuration supplies enabled defaults.
        // Loading this facade must preserve an existing file-configured policy.
        NSLog("[NoritoNativeBridge] init done — status=%@, handle=%@, free=%@",
              "\(self.bridgeStatus)",
              self.bridgeHandle == nil ? "nil" : "ok",
              self.freeFn == nil ? "nil" : "ok")
        #else
        self.bridgeStatus = .missing(path: "unsupported platform")
        #endif
    }

    #if canImport(Darwin)
    private static func isValidPrivacyNativeProbeResult(
        status: Int32,
        outPtr: UnsafeMutablePointer<UInt8>?,
        outLen: CUnsignedLong,
        validate: PrivacyValidateCompiledProfileCatalogFn?,
        maximumBytes: Int
    ) -> Bool {
        guard status == 0,
              let outPtr,
              outLen > 0,
              outLen <= CUnsignedLong(maximumBytes),
              let validate else {
            return false
        }
        return validate(UnsafePointer(outPtr), outLen) == 0
    }

    private func probePrivacyNativeAvailability() {
        privacyNativeProbeOk =
            probePrivacyArchiveFunction(
                privacyCompiledProfileCatalogFn,
                validate: privacyValidateCompiledProfileCatalogFn,
                maximumBytes: Self.privacyCompiledProfileCatalogArchiveMaxBytes
            )
            && probePrivacyArchiveFunction(
                privacyExact12FixtureBundleFn,
                validate: privacyValidateExact12FixtureBundleFn,
                maximumBytes: Self.privacyExact12FixtureBundleMaxBytes
            )
    }

    private func probePrivacyArchiveFunction(
        _ function: PrivacyCompiledProfileCatalogFn?,
        validate: PrivacyValidateCompiledProfileCatalogFn?,
        maximumBytes: Int
    ) -> Bool {
        guard let function,
              let validate,
              let privacyFreeFn else {
            return false
        }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = function(&outPtr, &outLen)
        return consumePrivacyNativeProbeResult(
            status: status,
            outPtr: outPtr,
            outLen: outLen,
            validate: validate,
            maximumBytes: maximumBytes,
            free: privacyFreeFn
        )
    }

    private func consumePrivacyNativeProbeResult(
        status: Int32,
        outPtr: UnsafeMutablePointer<UInt8>?,
        outLen: CUnsignedLong,
        validate: PrivacyValidateCompiledProfileCatalogFn?,
        maximumBytes: Int,
        free: FreeFn
    ) -> Bool {
        let expected = Self.isValidPrivacyNativeProbeResult(
            status: status,
            outPtr: outPtr,
            outLen: outLen,
            validate: validate,
            maximumBytes: maximumBytes
        )
        if let outPtr {
            Self.clearPrivacyNativeBuffer(
                outPtr,
                length: outLen,
                maximumBytes: maximumBytes
            )
            free(outPtr)
        }
        return expected
    }
    #endif

    public var isAvailable: Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }
        return encodeTransferFn != nil
            && detachedTransactionInspectFn != nil
            && detachedTransactionFinalizeEd25519Fn != nil
            && canonicalJSONBlake3Fn != nil
            && freeFn != nil
        #else
        return false
        #endif
    }

    /// Whether the exact ABI-25 bridge exposes the complete proof-gated Parliament wallet.
    public var isParliamentTimedOvnWalletAvailable: Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }
        return loadedBridgeAbiVersion == NoritoBridgeLoader.expectedBridgeAbiVersion
            && parliamentTimedOvnVerifyCastingProofPageFn != nil
            && parliamentTimedOvnVerifyCastingProofFn != nil
            && parliamentTimedOvnRegistrationFromProofFn != nil
            && parliamentTimedOvnBallotFromProofFn != nil
            && freeFn != nil
        #else
        return false
        #endif
    }

    /// Authenticate one bounded casting-proof page without borrowing any seed material.
    public func parliamentTimedOvnVerifyCastingProofPageV1(
        castingProofResponseNorito: Data,
        trustAnchor: ParliamentTimedOvnCastingTrustAnchorV1
    ) throws -> ParliamentTimedOvnCastingProofPageVerificationV1 {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime,
              loadedBridgeAbiVersion == NoritoBridgeLoader.expectedBridgeAbiVersion,
              let verifyPageFn = parliamentTimedOvnVerifyCastingProofPageFn,
              let freeFn else {
            throw ParliamentTimedOvnNativeWalletError.bridgeUnavailable
        }
        guard !castingProofResponseNorito.isEmpty,
              castingProofResponseNorito.count <= Self.parliamentTimedOvnCastingProofMaximumBytes else {
            throw ParliamentTimedOvnNativeWalletError.invalidCastingProof
        }

        let proofBytes = Array(castingProofResponseNorito)
        let anchor = trustAnchor.snapshot()
        var encoded = [UInt8](
            repeating: 0,
            count: Self.parliamentTimedOvnCastingProofPageSummaryBytes
        )
        var checkpointPointer: UnsafeMutablePointer<UInt8>? = nil
        var checkpointLength: CUnsignedLong = 0
        defer { if let checkpointPointer { freeFn(checkpointPointer) } }
        let status = proofBytes.withUnsafeBytes { proof in
            anchor.networkID.withUnsafeBytes { networkID in
                anchor.checkpointNorito.withUnsafeBytes { checkpointNorito in
                    anchor.ballotAttemptID.withUnsafeBytes { ballotAttemptID in
                        encoded.withUnsafeMutableBytes { output in
                            verifyPageFn(
                                proof.bindMemory(to: UInt8.self).baseAddress,
                                CUnsignedLong(proofBytes.count),
                                networkID.bindMemory(to: UInt8.self).baseAddress,
                                CUnsignedLong(anchor.networkID.count),
                                checkpointNorito.bindMemory(to: UInt8.self).baseAddress,
                                CUnsignedLong(anchor.checkpointNorito.count),
                                ballotAttemptID.bindMemory(to: UInt8.self).baseAddress,
                                CUnsignedLong(anchor.ballotAttemptID.count),
                                output.bindMemory(to: UInt8.self).baseAddress,
                                CUnsignedLong(
                                    Self.parliamentTimedOvnCastingProofPageSummaryBytes
                                ),
                                &checkpointPointer,
                                &checkpointLength
                            )
                        }
                    }
                }
            }
        }
        guard status == 0 else {
            throw ParliamentTimedOvnNativeWalletError.nativeRejected
        }
        guard let checkpointPointer, checkpointLength > 0,
              checkpointLength <= 68 * 1024 * 1024 else {
            throw ParliamentTimedOvnNativeWalletError.invalidPageVerification
        }
        return try Self.decodeParliamentTimedOvnCastingProofPageVerificationV1(
            Data(encoded),
            checkpointNorito: Data(bytes: checkpointPointer, count: Int(checkpointLength))
        )
        #else
        _ = castingProofResponseNorito
        _ = trustAnchor
        throw ParliamentTimedOvnNativeWalletError.bridgeUnavailable
        #endif
    }

    static func decodeParliamentTimedOvnCastingProofPageVerificationV1(
        _ encoded: Data,
        checkpointNorito: Data
    ) throws -> ParliamentTimedOvnCastingProofPageVerificationV1 {
        guard encoded.count == parliamentTimedOvnCastingProofPageSummaryBytes,
              encoded[40] == 0 || encoded[40] == 1 else {
            throw ParliamentTimedOvnNativeWalletError.invalidPageVerification
        }
        var evaluatedHeight: UInt64 = 0
        for byte in encoded[0..<8] {
            evaluatedHeight = (evaluatedHeight << 8) | UInt64(byte)
        }
        return try ParliamentTimedOvnCastingProofPageVerificationV1(
            evaluatedBlockHeight: evaluatedHeight,
            evaluatedContextID: Data(encoded[8..<40]),
            moreAvailable: encoded[40] == 1,
            promotedCheckpointNorito: checkpointNorito
        )
    }

    /// Derive one canonical public timed-OVN registration from an authenticated proof response.
    ///
    /// The seed is borrowed only through `seedHandle`; this method never returns,
    /// serializes, persists, or logs it. Proof/finality/archive validation
    /// completes before the handle is asked to borrow the seed.
    public func parliamentTimedOvnRegistrationFromProofV1(
        castingProofResponseNorito: Data,
        trustAnchor: ParliamentTimedOvnCastingTrustAnchorV1,
        authority: String,
        seedHandle: any ParliamentTimedOvnSeedHandle
    ) throws -> ParliamentTimedOvnPublicRecordV1 {
        try parliamentTimedOvnPublicRecordV1(
            castingProofResponseNorito: castingProofResponseNorito,
            trustAnchor: trustAnchor,
            authority: authority,
            seedHandle: seedHandle,
            choice: nil
        )
    }

    /// Derive one canonical survivor-bound public timed-OVN ballot from the same seed.
    ///
    /// Native code requires a `SurvivorsFrozen` archive, reproduces the exact
    /// committed registration, and returns only the 2,858-byte masked ballot.
    public func parliamentTimedOvnBallotFromProofV1(
        castingProofResponseNorito: Data,
        trustAnchor: ParliamentTimedOvnCastingTrustAnchorV1,
        authority: String,
        seedHandle: any ParliamentTimedOvnSeedHandle,
        choice: ParliamentTimedOvnBallotChoiceV1
    ) throws -> ParliamentTimedOvnPublicRecordV1 {
        try parliamentTimedOvnPublicRecordV1(
            castingProofResponseNorito: castingProofResponseNorito,
            trustAnchor: trustAnchor,
            authority: authority,
            seedHandle: seedHandle,
            choice: choice
        )
    }

    private func parliamentTimedOvnPublicRecordV1(
        castingProofResponseNorito: Data,
        trustAnchor: ParliamentTimedOvnCastingTrustAnchorV1,
        authority: String,
        seedHandle: any ParliamentTimedOvnSeedHandle,
        choice: ParliamentTimedOvnBallotChoiceV1?
    ) throws -> ParliamentTimedOvnPublicRecordV1 {
        #if canImport(Darwin)
        guard isParliamentTimedOvnWalletAvailable,
              let verifyFn = parliamentTimedOvnVerifyCastingProofFn,
              let registrationFn = parliamentTimedOvnRegistrationFromProofFn,
              let ballotFn = parliamentTimedOvnBallotFromProofFn,
              let freeFn else {
            throw ParliamentTimedOvnNativeWalletError.bridgeUnavailable
        }
        guard !castingProofResponseNorito.isEmpty,
              castingProofResponseNorito.count <= Self.parliamentTimedOvnCastingProofMaximumBytes else {
            throw ParliamentTimedOvnNativeWalletError.invalidCastingProof
        }
        let authorityBytes = authority.utf8.count
        guard authorityBytes > 0,
              authorityBytes <= Self.parliamentTimedOvnAuthorityMaximumBytes,
              !authority.utf8.contains(0) else {
            throw ParliamentTimedOvnNativeWalletError.invalidAuthority
        }

        // Force independent snapshots so caller mutation cannot retarget either
        // the preflight or the seed-bearing native call.
        let proofBytes = Array(castingProofResponseNorito)
        let anchor = trustAnchor.snapshot()
        var verifiedCheckpointPointer: UnsafeMutablePointer<UInt8>? = nil
        var verifiedCheckpointLength: CUnsignedLong = 0
        defer { if let verifiedCheckpointPointer { freeFn(verifiedCheckpointPointer) } }
        let verifyStatus = proofBytes.withUnsafeBytes { proof in
            anchor.networkID.withUnsafeBytes { networkID in
                anchor.checkpointNorito.withUnsafeBytes { checkpointNorito in
                    anchor.ballotAttemptID.withUnsafeBytes { ballotAttemptID in
                        verifyFn(
                            proof.bindMemory(to: UInt8.self).baseAddress,
                            CUnsignedLong(proofBytes.count),
                            networkID.bindMemory(to: UInt8.self).baseAddress,
                            CUnsignedLong(anchor.networkID.count),
                            checkpointNorito.bindMemory(to: UInt8.self).baseAddress,
                            CUnsignedLong(anchor.checkpointNorito.count),
                            ballotAttemptID.bindMemory(to: UInt8.self).baseAddress,
                            CUnsignedLong(anchor.ballotAttemptID.count),
                            &verifiedCheckpointPointer,
                            &verifiedCheckpointLength
                        )
                    }
                }
            }
        }
        guard verifyStatus == 0 else {
            throw ParliamentTimedOvnNativeWalletError.nativeRejected
        }

        guard let verifiedCheckpointPointer, verifiedCheckpointLength > 0,
              verifiedCheckpointLength <= 68 * 1024 * 1024 else {
            throw ParliamentTimedOvnNativeWalletError.invalidPageVerification
        }
        let verifiedCheckpoint = Data(bytes: verifiedCheckpointPointer, count: Int(verifiedCheckpointLength))
        let record = try seedHandle.withUnsafeSeedBytes { seed in
            guard seed.count == Self.parliamentTimedOvnSeedBytes,
                  seed.contains(where: { $0 != 0 }) else {
                throw ParliamentTimedOvnNativeWalletError.invalidSeed
            }
            var outputPointer: UnsafeMutablePointer<UInt8>? = nil
            var outputLength: CUnsignedLong = 0
            var checkpointPointer: UnsafeMutablePointer<UInt8>? = nil
            var checkpointLength: CUnsignedLong = 0
            defer { if let checkpointPointer { freeFn(checkpointPointer) } }
            let status = proofBytes.withUnsafeBytes { proof in
                anchor.networkID.withUnsafeBytes { networkID in
                    anchor.checkpointNorito.withUnsafeBytes { checkpointNorito in
                        anchor.ballotAttemptID.withUnsafeBytes { ballotAttemptID in
                            authority.withCString { authorityPointer in
                                let proofPointer = proof.bindMemory(to: UInt8.self).baseAddress
                                let networkPointer = networkID.bindMemory(to: UInt8.self).baseAddress
                                let contextPointer = checkpointNorito
                                    .bindMemory(to: UInt8.self).baseAddress
                                let ballotPointer = ballotAttemptID
                                    .bindMemory(to: UInt8.self).baseAddress
                                let seedPointer = seed.bindMemory(to: UInt8.self).baseAddress
                                if let choice {
                                    return ballotFn(
                                        proofPointer,
                                        CUnsignedLong(proofBytes.count),
                                        networkPointer,
                                        CUnsignedLong(anchor.networkID.count),
                                                contextPointer,
                                        CUnsignedLong(anchor.checkpointNorito.count),
                                        ballotPointer,
                                        CUnsignedLong(anchor.ballotAttemptID.count),
                                        authorityPointer,
                                        CUnsignedLong(authorityBytes),
                                        seedPointer,
                                        CUnsignedLong(seed.count),
                                        choice.rawValue,
                                        &outputPointer,
                                        &outputLength,
                                        &checkpointPointer,
                                        &checkpointLength
                                    )
                                }
                                return registrationFn(
                                    proofPointer,
                                    CUnsignedLong(proofBytes.count),
                                    networkPointer,
                                    CUnsignedLong(anchor.networkID.count),
                                        contextPointer,
                                    CUnsignedLong(anchor.checkpointNorito.count),
                                    ballotPointer,
                                    CUnsignedLong(anchor.ballotAttemptID.count),
                                    authorityPointer,
                                    CUnsignedLong(authorityBytes),
                                    seedPointer,
                                    CUnsignedLong(seed.count),
                                    &outputPointer,
                                    &outputLength,
                                    &checkpointPointer,
                                    &checkpointLength
                                )
                            }
                        }
                    }
                }
            }
            guard status == 0 else {
                if let outputPointer {
                    freeFn(outputPointer)
                }
                throw ParliamentTimedOvnNativeWalletError.nativeRejected
            }
            guard let outputPointer else {
                throw ParliamentTimedOvnNativeWalletError.invalidPublicRecord
            }
            defer { freeFn(outputPointer) }
            let expectedLength = choice == nil
                ? Self.parliamentTimedOvnRegistrationRecordBytes
                : Self.parliamentTimedOvnBallotRecordBytes
            guard outputLength == CUnsignedLong(expectedLength) else {
                throw ParliamentTimedOvnNativeWalletError.invalidPublicRecord
            }
            guard let checkpointPointer, checkpointLength == verifiedCheckpointLength,
                  Data(bytes: checkpointPointer, count: Int(checkpointLength)) == verifiedCheckpoint else {
                throw ParliamentTimedOvnNativeWalletError.invalidPageVerification
            }
            return Data(bytes: outputPointer, count: expectedLength)
        }
        return ParliamentTimedOvnPublicRecordV1(record: record, promotedCheckpointNorito: verifiedCheckpoint)
        #else
        _ = castingProofResponseNorito
        _ = trustAnchor
        _ = authority
        _ = seedHandle
        _ = choice
        throw ParliamentTimedOvnNativeWalletError.bridgeUnavailable
        #endif
    }

    public var isDetachedTransactionVerificationAvailable: Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }
        return loadedBridgeAbiVersion == NoritoBridgeLoader.expectedBridgeAbiVersion
            && detachedTransactionInspectFn != nil
            && detachedTransactionFinalizeEd25519Fn != nil
            && canonicalJSONBlake3Fn != nil
            && freeFn != nil
        #else
        return false
        #endif
    }

    public var isSorafsReferenceValidationAvailable: Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }
        return sorafsReferenceValidateOrderbookFn != nil
            && sorafsReferenceValidatePopPayloadFn != nil
            && sorafsReferenceValidateHedgingPayloadFn != nil
            && sorafsReferenceValidateAppealFinanceCancelAssetLockFn != nil
            && sorafsReferenceValidateFixtureBundleFn != nil
            && sorafsReferenceValidateGovernanceLogNodeFn != nil
            && sorafsReferenceValidatePdpPayloadFn != nil
            && sorafsReferenceValidatePdpCommitmentChallengeFn != nil
            && sorafsReferenceValidatePdpChallengeProofFn != nil
            && sorafsReferenceValidatePdpBundleFn != nil
            && freeFn != nil
        #else
        return false
        #endif
    }

    public var isSorafsReferencePopValidationAvailable: Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }
        return sorafsReferenceValidatePopPayloadFn != nil && freeFn != nil
        #else
        return false
        #endif
    }

    public var isSorafsReferenceHedgingValidationAvailable: Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }
        return sorafsReferenceValidateHedgingPayloadFn != nil && freeFn != nil
        #else
        return false
        #endif
    }

    public var isSorafsReferenceAppealFinanceValidationAvailable: Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }
        return sorafsReferenceValidateAppealFinanceCancelAssetLockFn != nil && freeFn != nil
        #else
        return false
        #endif
    }

    public var isSorafsReferenceFixtureBundleValidationAvailable: Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }
        return sorafsReferenceValidateFixtureBundleFn != nil && freeFn != nil
        #else
        return false
        #endif
    }

    public var isSorafsReferenceGovernanceLogNodeValidationAvailable: Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }
        return sorafsReferenceValidateGovernanceLogNodeFn != nil && freeFn != nil
        #else
        return false
        #endif
    }

    public var isSorafsReferenceGovernanceDagValidationAvailable: Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }
        return sorafsReferenceValidateGovernanceDagBlockFn != nil
            && sorafsReferenceValidateGovernanceDagHeadChainFn != nil
            && freeFn != nil
        #else
        return false
        #endif
    }

    public var isSorafsReferenceOrderbookSigningAvailable: Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }
        return sorafsReferenceSignOrderbookFn != nil && freeFn != nil
        #else
        return false
        #endif
    }

    public var isSorafsReferenceOrderbookFieldBuilderAvailable: Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }
        return sorafsReferenceBuildOrderbookOrderRequestFn != nil
            && sorafsReferenceBuildOrderbookOrderCancelFn != nil
            && sorafsReferenceBuildOrderbookSettlementReceiptFn != nil
            && sorafsReferenceDeriveOrderbookOrderIdFn != nil
            && freeFn != nil
        #else
        return false
        #endif
    }

    public var isPrivacyNativeAvailable: Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }
        return loadedBridgeAbiVersion == PrivacyNativeBridge.requiredBridgeABIVersion
            && privacyCompiledProfileCatalogFn != nil
            && privacyValidateCompiledProfileCatalogFn != nil
            && privacyValidateExact12CapabilityManifestFn != nil
            && privacyExact12FixtureBundleFn != nil
            && privacyValidateExact12FixtureBundleFn != nil
            && privacyFreeFn != nil
            && privacyNativeProbeOk
        #else
        return false
        #endif
    }

    public var bridgeStatusDescription: String {
        #if canImport(Darwin)
        return "\(bridgeStatus)"
        #else
        return "non-Darwin"
        #endif
    }

    public var bridgeLoadIssue: String? {
        #if canImport(Darwin)
        switch bridgeStatus {
        case .valid:
            return nil
        case .pathDenied(let path):
            return BridgePolicyHint.unavailableMessage("NoritoBridge load denied for path \(path).")
        case .missing(let path):
            return BridgePolicyHint.unavailableMessage("NoritoBridge missing at \(path).")
        case .hashMismatch(let path, let expected, let actual):
            return BridgePolicyHint.unavailableMessage(
                "NoritoBridge hash mismatch for \(path) (expected \(expected), actual \(actual ?? "nil"))."
            )
        case .versionMismatch(let path, let expected, let actual):
            return BridgePolicyHint.unavailableMessage(
                "NoritoBridge version mismatch for \(path) (expected \(expected), actual \(actual ?? "nil"))."
            )
        case .abiMismatch(let path, let expected, let actual):
            return BridgePolicyHint.unavailableMessage(
                "NoritoBridge ABI mismatch for \(path) (expected \(expected), actual \(actual.map(String.init) ?? "nil"))."
            )
        }
        #else
        return BridgePolicyHint.unavailableMessage("NoritoBridge unsupported on this platform.")
        #endif
    }

    var isConnectCryptoAvailable: Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }
        return canUseConnectCrypto
        #else
        return false
        #endif
    }

    var isSm2Available: Bool {
        #if canImport(Darwin)
        return sm2DefaultDistidFn != nil
            && sm2KeypairFromSeedFn != nil
            && sm2SignFn != nil
            && sm2VerifyFn != nil
            && sm2PublicKeyPrefixedFn != nil
            && sm2PublicKeyMultihashFn != nil
            && sm2ComputeZaFn != nil
            && freeFn != nil
        #else
        return false
        #endif
    }

    public func supportsTransactions(using algorithm: SigningAlgorithm) -> Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }

        let hasAlgorithmEncoders =
            self.encodeTransferWithAlgFn != nil
                && self.encodeMintWithAlgFn != nil
                && self.encodeBurnWithAlgFn != nil
                && self.encodeRegisterZkAssetWithAlgFn != nil

        switch algorithm {
        case .ed25519:
            return encodeTransferFn != nil
                && encodeMintFn != nil
                && encodeBurnFn != nil
                && encodeRegisterZkAssetFn != nil
        case .sm2:
            return isSm2Available && hasAlgorithmEncoders && canParseSm2TransactionAuthority()
        case .secp256k1:
            return secp256k1Supported && hasAlgorithmEncoders
        case .mlDsa:
            return mldsaSupported && hasAlgorithmEncoders
        case .blsNormal, .blsSmall,
             .gost2012_256A, .gost2012_256B, .gost2012_256C,
             .gost2012_512A, .gost2012_512B:
            return publicKeyFromPrivateFn != nil
                && signDetachedFn != nil
                && verifyDetachedFn != nil
                && hasAlgorithmEncoders
        }
        #else
        return false
        #endif
    }

    private func canParseSm2TransactionAuthority() -> Bool {
        #if canImport(Darwin) && IROHASWIFT_ENABLE_SM
        guard isAccountAddressCodecAvailable else { return false }
        let distid = Sm2Keypair.defaultDistid()
        let seed = Data(repeating: 0xA5, count: Sm2Keypair.privateKeyLength)
        guard let pair = sm2KeypairFromSeed(distid: distid, seed: seed),
              let authority = try? AccountId.makeI105(
                publicKey: pair.publicKey,
                algorithm: "sm2",
                distid: distid
              ) else {
            return false
        }
        return (try? parseAccountAddress(
            literal: authority,
            expectedPrefix: AccountId.defaultNetworkPrefix
        )) != nil
        #else
        return false
        #endif
    }

    var isAccountAddressCodecAvailable: Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }
        return accountAddressParseFn != nil
            && accountAddressRenderFn != nil
            && freeFn != nil
        #else
        return false
        #endif
    }

    var isConnectCodecAvailable: Bool {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime else { return false }
        if connectCodecAvailabilityOverride == false {
            return false
        }
        return canUseConnectCodec
        #else
        return false
        #endif
    }

    func overrideConnectCodecAvailabilityForTests(_ override: Bool?) {
        #if canImport(Darwin)
        connectCodecAvailabilityOverride = override
        #endif
    }

    func overrideBridgeAvailabilityForTests(_ override: Bool?) {
        #if canImport(Darwin)
        bridgeAvailabilityOverride = override
        #endif
    }

    #if canImport(Darwin)
    private var bridgeEnabledForRuntime: Bool {
        if let override = bridgeAvailabilityOverride {
            return override
        }
        return true
    }

    private var bridgeAvailabilityOverride: Bool?
    private var connectCodecAvailabilityOverride: Bool?
    #endif

    private var canUseConnectCodec: Bool {
        #if canImport(Darwin)
        let hasEncode =
            encodeCiphertextFrameFn != nil
            && encodeControlOpenFn != nil
            && (encodeControlApproveFn != nil || encodeControlApproveWithAlgFn != nil)
            && encodeControlRejectFn != nil
            && encodeControlCloseFn != nil
            && encodeControlPingFn != nil
            && encodeControlPongFn != nil
        let hasDecode =
            decodeControlKindFn != nil
            && decodeCiphertextFrameFn != nil
            && decodeControlOpenPubFn != nil
            && decodeControlOpenNetworkIdFn != nil
            && decodeControlOpenAppMetadataFn != nil
            && decodeControlOpenPermissionsFn != nil
            && decodeControlApprovePubFn != nil
            && decodeControlApproveAccountFn != nil
            && decodeControlApprovePermissionsFn != nil
            && decodeControlApproveProofFn != nil
            && decodeControlApproveSigFn != nil
            && decodeControlApproveSigAlgFn != nil
            && decodeControlCloseFn != nil
            && decodeControlRejectFn != nil
            && decodeControlPingFn != nil
            && decodeControlPongFn != nil
        return hasEncode && hasDecode && freeFn != nil
        #else
        return false
        #endif
    }

    #if canImport(Darwin)
    private func withOptionalBytes<R>(_ data: Data?, _ body: (UnsafePointer<UInt8>?, UInt) -> R) -> R {
        if let data {
            return data.withUnsafeBytes { buffer in
                let base = buffer.bindMemory(to: UInt8.self).baseAddress
                return body(base, UInt(data.count))
            }
        } else {
            return body(nil, 0)
        }
    }

    private func withOptionalCStringData<R>(_ data: Data?, _ body: (UnsafePointer<CChar>?, UInt) -> R) -> R {
        if let data {
            return data.withUnsafeBytes { buffer in
                let base = buffer.bindMemory(to: CChar.self).baseAddress
                return body(base, UInt(data.count))
            }
        } else {
            return body(nil, 0)
        }
    }

    private func withOptionalCString<R>(_ string: String?, _ body: (UnsafePointer<CChar>?, UInt) -> R) -> R {
        if let string {
            return string.withCString { cString in
                body(cString, UInt(string.utf8.count))
            }
        } else {
            return body(nil, 0)
        }
    }

    private func withDataPointer<R>(_ data: Data, _ body: (UnsafePointer<UInt8>?, CUnsignedLong) -> R) -> R {
        data.withUnsafeBytes { buffer in
            body(buffer.bindMemory(to: UInt8.self).baseAddress, CUnsignedLong(buffer.count))
        }
    }

    private func takeData(pointer: UnsafeMutablePointer<UInt8>?, length: UInt) -> Data? {
        guard let pointer else { return nil }
        let data = Data(bytes: pointer, count: Int(length))
        if let freeFn {
            freeFn(pointer)
        } else {
            Darwin.free(pointer)
        }
        return data
    }

    private func takeString(pointer: UnsafeMutablePointer<UInt8>?, length: UInt) -> String? {
        guard let data = takeData(pointer: pointer, length: length) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func takeCString(pointer: UnsafeMutablePointer<CChar>?, length: UInt) -> String? {
        guard let pointer else { return nil }
        let data = Data(bytes: pointer, count: Int(length))
        Darwin.free(pointer)
        return String(data: data, encoding: .utf8)
    }

    private func consumeAccountAddressError(pointer: UnsafeMutablePointer<UInt8>?, length: UInt) -> AccountAddressError? {
        guard let data = takeData(pointer: pointer, length: length) else { return nil }
        guard let payload = AccountAddressError.bridgePayload(from: data) else { return nil }
        return AccountAddressError.fromBridgePayload(payload)
    }
    #endif

    func parseAccountAddress(
        literal: String,
        expectedPrefix: UInt16?
    ) throws -> NativeAccountAddressParseResult? {
        #if canImport(Darwin)
        guard isAccountAddressCodecAvailable,
              let accountAddressParseFn else {
            return nil
        }

        var canonicalPtr: UnsafeMutablePointer<UInt8>? = nil
        var canonicalLen: UInt = 0
        var networkPrefix: UInt16 = 0
        var errorPtr: UnsafeMutablePointer<UInt8>? = nil
        var errorLen: UInt = 0
        let prefixFlag: UInt8 = expectedPrefix == nil ? 0 : 1
        let prefixValue = expectedPrefix ?? 0

        let status = literal.withCString { cString in
            accountAddressParseFn(
                cString,
                UInt(literal.utf8.count),
                prefixValue,
                prefixFlag,
                &canonicalPtr,
                &canonicalLen,
                &networkPrefix,
                &errorPtr,
                &errorLen
            )
        }

        if status == 0 {
            guard let canonicalPtr,
                  let canonical = takeData(pointer: canonicalPtr, length: canonicalLen)
            else {
                return nil
            }
            return NativeAccountAddressParseResult(
                canonicalBytes: canonical,
                networkPrefix: networkPrefix
            )
        }

        if let error = consumeAccountAddressError(pointer: errorPtr, length: errorLen) {
            throw error
        }
        if let canonicalPtr {
            freeFn?(canonicalPtr)
        }
        return nil
        #else
        return nil
        #endif
    }

    func renderAccountAddress(
        canonicalBytes: Data,
        networkPrefix: UInt16
    ) throws -> NativeAccountAddressRenderResult? {
        #if canImport(Darwin)
        guard isAccountAddressCodecAvailable,
              let accountAddressRenderFn else {
            return nil
        }

        var hexPtr: UnsafeMutablePointer<UInt8>? = nil
        var hexLen: UInt = 0
        var i105Ptr: UnsafeMutablePointer<UInt8>? = nil
        var i105Len: UInt = 0
        var errorPtr: UnsafeMutablePointer<UInt8>? = nil
        var errorLen: UInt = 0

        let status = canonicalBytes.withUnsafeBytes { buffer in
            accountAddressRenderFn(
                buffer.bindMemory(to: UInt8.self).baseAddress,
                UInt(canonicalBytes.count),
                networkPrefix,
                &hexPtr,
                &hexLen,
                &i105Ptr,
                &i105Len,
                &errorPtr,
                &errorLen
            )
        }

        if status == 0 {
            guard
                let canonicalHex = takeString(pointer: hexPtr, length: hexLen),
                let i105 = takeString(pointer: i105Ptr, length: i105Len)
            else {
                return nil
            }
            return NativeAccountAddressRenderResult(
                canonicalHex: canonicalHex,
                i105: i105
            )
        }

        if let error = consumeAccountAddressError(pointer: errorPtr, length: errorLen) {
            if let hexPtr { freeFn?(hexPtr) }
            if let i105Ptr { freeFn?(i105Ptr) }
            throw error
        }

        if let hexPtr { freeFn?(hexPtr) }
        if let i105Ptr { freeFn?(i105Ptr) }
        return nil
        #else
        return nil
        #endif
    }

    func blake3Hash(data: Data) -> Data? {
        #if canImport(Darwin)
        guard let blake3HashFn else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = data.withUnsafeBytes { buffer -> Int32 in
            let baseAddress = buffer.bindMemory(to: UInt8.self).baseAddress
            return blake3HashFn(baseAddress, CUnsignedLong(buffer.count), &outPtr, &outLen)
        }
        guard status == 0 else {
            if let outPtr {
                freeFn?(outPtr)
            }
            return nil
        }
        return takeData(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    /// Inspect one exact canonical versioned detached transaction scaffold.
    public func inspectDetachedTransactionScaffold(
        _ scaffold: Data
    ) throws -> DetachedTransactionScaffoldInspection {
        #if canImport(Darwin)
        guard isDetachedTransactionVerificationAvailable,
              let detachedTransactionInspectFn,
              let freeFn else {
            throw NativeBridgeError.bridgeUnavailable
        }
        guard !scaffold.isEmpty,
              scaffold.count <= Self.detachedTransactionNativeMaximumBytes else {
            throw NativeBridgeError.detachedTransactionScaffold
        }
        var jsonPointer: UnsafeMutablePointer<UInt8>? = nil
        var jsonLength: CUnsignedLong = 0
        let status = scaffold.withUnsafeBytes { buffer -> Int32 in
            detachedTransactionInspectFn(
                buffer.bindMemory(to: UInt8.self).baseAddress,
                CUnsignedLong(buffer.count),
                &jsonPointer,
                &jsonLength
            )
        }
        defer {
            if let jsonPointer {
                freeFn(jsonPointer)
            }
        }
        try throwOnStatus(status)
        guard let jsonPointer,
              jsonLength > 0,
              jsonLength <= CUnsignedLong(Self.detachedTransactionNativeMaximumBytes) else {
            throw NativeBridgeError.invalidDetachedTransactionOutput
        }
        let json = Data(bytes: jsonPointer, count: Int(jsonLength))
        do {
            return try DetachedTransactionBridgeJSONCodec.decodeInspection(json)
        } catch let error as NativeBridgeError {
            throw error
        } catch {
            throw NativeBridgeError.invalidDetachedTransactionOutput
        }
        #else
        throw NativeBridgeError.bridgeUnavailable
        #endif
    }

    /// Finalize a detached scaffold with an exact raw Ed25519 key and signature.
    public func finalizeDetachedTransactionScaffold(
        _ scaffold: Data,
        publicKey: Data,
        signature: Data
    ) throws -> DetachedTransactionFinalizationResult {
        #if canImport(Darwin)
        guard isDetachedTransactionVerificationAvailable,
              let detachedTransactionFinalizeEd25519Fn,
              let freeFn else {
            throw NativeBridgeError.bridgeUnavailable
        }
        guard !scaffold.isEmpty,
              scaffold.count <= Self.detachedTransactionNativeMaximumBytes else {
            throw NativeBridgeError.detachedTransactionScaffold
        }
        guard publicKey.count == 32, signature.count == 64 else {
            throw NativeBridgeError.detachedTransactionSignature
        }

        var signedPointer: UnsafeMutablePointer<UInt8>? = nil
        var signedLength: CUnsignedLong = 0
        var jsonPointer: UnsafeMutablePointer<UInt8>? = nil
        var jsonLength: CUnsignedLong = 0
        let status = scaffold.withUnsafeBytes { scaffoldBuffer -> Int32 in
            publicKey.withUnsafeBytes { publicKeyBuffer -> Int32 in
                signature.withUnsafeBytes { signatureBuffer -> Int32 in
                    detachedTransactionFinalizeEd25519Fn(
                        scaffoldBuffer.bindMemory(to: UInt8.self).baseAddress,
                        CUnsignedLong(scaffoldBuffer.count),
                        publicKeyBuffer.bindMemory(to: UInt8.self).baseAddress,
                        CUnsignedLong(publicKeyBuffer.count),
                        signatureBuffer.bindMemory(to: UInt8.self).baseAddress,
                        CUnsignedLong(signatureBuffer.count),
                        &signedPointer,
                        &signedLength,
                        &jsonPointer,
                        &jsonLength
                    )
                }
            }
        }
        defer {
            if let signedPointer {
                freeFn(signedPointer)
            }
            if let jsonPointer {
                freeFn(jsonPointer)
            }
        }
        try throwOnStatus(status)
        guard let signedPointer,
              signedLength > 0,
              signedLength <= CUnsignedLong(Self.detachedTransactionNativeMaximumBytes),
              let jsonPointer,
              jsonLength > 0,
              jsonLength <= CUnsignedLong(Self.detachedTransactionNativeMaximumBytes) else {
            throw NativeBridgeError.invalidDetachedTransactionOutput
        }
        let signedTransaction = Data(bytes: signedPointer, count: Int(signedLength))
        let json = Data(bytes: jsonPointer, count: Int(jsonLength))
        let finalization: DetachedTransactionFinalization
        do {
            finalization = try DetachedTransactionBridgeJSONCodec.decodeFinalization(json)
        } catch let error as NativeBridgeError {
            throw error
        } catch {
            throw NativeBridgeError.invalidDetachedTransactionOutput
        }
        let signedInspection = try inspectDetachedTransactionScaffold(signedTransaction)
        guard signedInspection.payloadSigningHash == finalization.payloadSigningHash,
              signedInspection.entrypointHash == finalization.entrypointHash,
              finalization.transactionHash == finalization.entrypointHash else {
            throw NativeBridgeError.invalidDetachedTransactionOutput
        }
        return DetachedTransactionFinalizationResult(
            signedTransaction: signedTransaction,
            finalization: finalization
        )
        #else
        throw NativeBridgeError.bridgeUnavailable
        #endif
    }

    /// Encode the exact sponsored-onboarding plan body as bare canonical Norito.
    func encodeAccountOnboardingPlanBody(
        _ body: ToriiAccountOnboardingPlanBody
    ) throws -> Data {
        #if canImport(Darwin)
        guard let encodeAccountOnboardingPlanBodyFn, let freeFn else {
            throw NativeBridgeError.bridgeUnavailable
        }
        let encoder = JSONEncoder()
        let json = try encoder.encode(body)
        guard !json.isEmpty, json.count <= Self.detachedTransactionNativeMaximumBytes else {
            throw NativeBridgeError.accountOnboardingBody
        }
        var outputPointer: UnsafeMutablePointer<UInt8>? = nil
        var outputLength: CUnsignedLong = 0
        let status = json.withUnsafeBytes { buffer -> Int32 in
            encodeAccountOnboardingPlanBodyFn(
                buffer.bindMemory(to: UInt8.self).baseAddress,
                CUnsignedLong(buffer.count),
                &outputPointer,
                &outputLength
            )
        }
        defer {
            if let outputPointer { freeFn(outputPointer) }
        }
        try throwOnStatus(status)
        guard outputLength > 0,
              outputLength <= CUnsignedLong(Self.detachedTransactionNativeMaximumBytes),
              outputPointer != nil else {
            throw NativeBridgeError.accountOnboardingBody
        }
        return Data(bytes: outputPointer!, count: Int(outputLength))
        #else
        throw NativeBridgeError.bridgeUnavailable
        #endif
    }

    /// Registry-decode and canonically re-encode one exact alias instruction frame.
    func roundTripAliasInstruction(
        wireId: String,
        framedPayload: Data
    ) throws -> NativeAliasInstructionRoundTripResult {
        #if canImport(Darwin)
        guard let aliasInstructionRoundTripFn, let freeFn else {
            throw NativeBridgeError.bridgeUnavailable
        }
        let wireIdBytes = Data(wireId.utf8)
        guard !wireIdBytes.isEmpty,
              wireIdBytes.count <= 256,
              !framedPayload.isEmpty,
              framedPayload.count <= Self.detachedTransactionNativeMaximumBytes else {
            throw NativeBridgeError.aliasInstruction
        }
        var outputFramePointer: UnsafeMutablePointer<UInt8>? = nil
        var outputFrameLength: CUnsignedLong = 0
        var outputJSONPointer: UnsafeMutablePointer<UInt8>? = nil
        var outputJSONLength: CUnsignedLong = 0
        let status = wireIdBytes.withUnsafeBytes { wireIdBuffer -> Int32 in
            framedPayload.withUnsafeBytes { framedPayloadBuffer -> Int32 in
                aliasInstructionRoundTripFn(
                    wireIdBuffer.bindMemory(to: UInt8.self).baseAddress,
                    CUnsignedLong(wireIdBuffer.count),
                    framedPayloadBuffer.bindMemory(to: UInt8.self).baseAddress,
                    CUnsignedLong(framedPayloadBuffer.count),
                    &outputFramePointer,
                    &outputFrameLength,
                    &outputJSONPointer,
                    &outputJSONLength
                )
            }
        }
        defer {
            if let outputFramePointer { freeFn(outputFramePointer) }
            if let outputJSONPointer { freeFn(outputJSONPointer) }
        }
        try throwOnStatus(status)
        guard outputFrameLength > 0,
              outputFrameLength <= CUnsignedLong(Self.detachedTransactionNativeMaximumBytes),
              let outputFramePointer,
              outputJSONLength > 0,
              outputJSONLength <= CUnsignedLong(Self.detachedTransactionNativeMaximumBytes),
              let outputJSONPointer else {
            throw NativeBridgeError.aliasInstruction
        }
        return NativeAliasInstructionRoundTripResult(
            framedPayload: Data(bytes: outputFramePointer, count: Int(outputFrameLength)),
            typedJSON: Data(bytes: outputJSONPointer, count: Int(outputJSONLength))
        )
        #else
        throw NativeBridgeError.bridgeUnavailable
        #endif
    }

    /// Strictly canonicalize JSON and compute BLAKE3 over those exact bytes.
    public func canonicalizeJSONBlake3(_ json: Data) throws -> CanonicalJSONBlake3Result {
        #if canImport(Darwin)
        guard isDetachedTransactionVerificationAvailable,
              let canonicalJSONBlake3Fn,
              let freeFn else {
            throw NativeBridgeError.bridgeUnavailable
        }
        guard json.count <= Self.detachedTransactionNativeMaximumBytes else {
            throw NativeBridgeError.canonicalJSON
        }
        var canonicalPointer: UnsafeMutablePointer<UInt8>? = nil
        var canonicalLength: CUnsignedLong = 0
        var hash = [UInt8](repeating: 0, count: 32)
        let status = json.withUnsafeBytes { buffer -> Int32 in
            canonicalJSONBlake3Fn(
                buffer.bindMemory(to: UInt8.self).baseAddress,
                CUnsignedLong(buffer.count),
                &canonicalPointer,
                &canonicalLength,
                &hash,
                CUnsignedLong(hash.count)
            )
        }
        defer {
            if let canonicalPointer {
                freeFn(canonicalPointer)
            }
        }
        try throwOnStatus(status)
        guard canonicalLength <= CUnsignedLong(Self.detachedTransactionNativeMaximumBytes),
              (canonicalLength == 0) == json.isEmpty,
              canonicalLength == 0 || canonicalPointer != nil else {
            throw NativeBridgeError.invalidDetachedTransactionOutput
        }
        let canonicalJSON = canonicalPointer.map {
            Data(bytes: $0, count: Int(canonicalLength))
        } ?? Data()
        return CanonicalJSONBlake3Result(canonicalJSON: canonicalJSON, hash: Data(hash))
        #else
        throw NativeBridgeError.bridgeUnavailable
        #endif
    }

    func encodeTransfer(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        nonce: UInt32? = nil,
        assetDefinitionId: String,
        quantity: String,
        destination: String,
        feePaymentJSON: Data,
        privateKey: Data,
        algorithm: SigningAlgorithm = .ed25519
    ) throws -> NativeSignedTransaction? {
        let canonicalQuantity = try KotodamaNumericV1Codec
            .decodeQuantityJSON(quantity).canonicalString
        guard !feePaymentJSON.isEmpty else {
            throw NativeBridgeError.feePayment
        }
        #if canImport(Darwin)
        guard let freeFn else { return nil }
        let ttlValue = ttlMs ?? 0
        let ttlFlag: UInt8 = ttlMs == nil ? 0 : 1
        let nonceValue = nonce ?? 0
        let nonceFlag: UInt8 = nonce == nil ? 0 : 1
        let useAlg = algorithm != .ed25519
        guard useAlg ? encodeTransferWithAlgFn != nil : encodeTransferFn != nil else {
            return nil
        }

        var signedPtr: UnsafeMutablePointer<UInt8>? = nil
        var signedLen: UInt = 0
        var hashBytes = [UInt8](repeating: 0, count: 32)
        let hashLength = UInt(hashBytes.count)
        let algorithmRaw = algorithm.noritoDiscriminant

        let status = try withAuthorityChainDiscriminant(authority: authority) {
            networkId.literal.withCString { networkIdPtr in
            authority.withCString { authorityPtr in
                assetDefinitionId.withCString { assetPtr in
                    canonicalQuantity.withCString { quantityPtr in
                        destination.withCString { destinationPtr in
                            let encodeTransferCall: (UnsafePointer<UInt8>?, UInt) -> Int32 = { [self] feePaymentPtr, feePaymentLen in
                                privateKey.withUnsafeBytes { keyBuffer -> Int32 in
                                    hashBytes.withUnsafeMutableBufferPointer { hashBuffer -> Int32 in
                                        guard let feePaymentPtr,
                                              feePaymentLen > 0,
                                              let hashPtr = hashBuffer.baseAddress else {
                                            return -34
                                        }
                                        return self.withSignedOutputs(signedPtr: &signedPtr, signedLen: &signedLen) { signedPtrPtr, signedLenPtr in
                                            if useAlg, let encodeTransferWithAlgFn = self.encodeTransferWithAlgFn {
                                                return encodeTransferWithAlgFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                                    authorityPtr, UInt(authority.utf8.count),
                                                    creationTimeMs,
                                                    ttlValue,
                                                    ttlFlag,
                                                    nonceValue,
                                                    nonceFlag,
                                                    assetPtr, UInt(assetDefinitionId.utf8.count),
                                                    quantityPtr, UInt(canonicalQuantity.utf8.count),
                                                    destinationPtr, UInt(destination.utf8.count),
                                                    feePaymentPtr, feePaymentLen,
                                                    keyBuffer.bindMemory(to: UInt8.self).baseAddress, UInt(privateKey.count),
                                                    algorithmRaw,
                                                    signedPtrPtr,
                                                    signedLenPtr,
                                                    hashPtr,
                                                    hashLength
                                                )
                                            } else if let encodeTransferFn = self.encodeTransferFn {
                                                return encodeTransferFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                                    authorityPtr, UInt(authority.utf8.count),
                                                    creationTimeMs,
                                                    ttlValue,
                                                    ttlFlag,
                                                    nonceValue,
                                                    nonceFlag,
                                                    assetPtr, UInt(assetDefinitionId.utf8.count),
                                                    quantityPtr, UInt(canonicalQuantity.utf8.count),
                                                    destinationPtr, UInt(destination.utf8.count),
                                                    feePaymentPtr, feePaymentLen,
                                                    keyBuffer.bindMemory(to: UInt8.self).baseAddress, UInt(privateKey.count),
                                                    signedPtrPtr,
                                                    signedLenPtr,
                                                    hashPtr,
                                                    hashLength
                                                )
                                            } else {
                                                return -1
                                            }
                                        }
                                    }
                                }
                            }
                            return feePaymentJSON.withUnsafeBytes { feePaymentBuffer in
                                encodeTransferCall(
                                    feePaymentBuffer.bindMemory(to: UInt8.self).baseAddress,
                                    UInt(feePaymentJSON.count)
                                )
                            }
                        }
                    }
                }
            }
        }
        }

        if status != 0 {
            if let signedPtr { freeFn(signedPtr) }
            try throwOnStatus(status)
            return nil
        }
        guard let signedPtr else { return nil }

        let signedData = Data(bytes: signedPtr, count: Int(signedLen))
        freeFn(signedPtr)
        let hashData = Data(hashBytes)
        return NativeSignedTransaction(signedBytes: signedData, hash: hashData)
        #else
        return nil
        #endif
    }

    public func encodeTransferInstructionBox(
        authority: String,
        assetDefinitionId: String,
        quantity: String,
        destination: String
    ) throws -> Data? {
        let canonicalQuantity = try KotodamaNumericV1Codec
            .decodeQuantityJSON(quantity).canonicalString
        #if canImport(Darwin)
        guard let freeFn, let encodeTransferInstructionBoxFn else { return nil }

        var instructionPtr: UnsafeMutablePointer<UInt8>? = nil
        var instructionLen: UInt = 0
        let status = try withAuthorityChainDiscriminant(authority: authority) {
            authority.withCString { authorityPtr in
                assetDefinitionId.withCString { assetPtr in
                    canonicalQuantity.withCString { quantityPtr in
                        destination.withCString { destinationPtr in
                            self.withSignedOutputs(
                                signedPtr: &instructionPtr,
                                signedLen: &instructionLen
                            ) { instructionPtrPtr, instructionLenPtr in
                                encodeTransferInstructionBoxFn(
                                    authorityPtr,
                                    UInt(authority.utf8.count),
                                    assetPtr,
                                    UInt(assetDefinitionId.utf8.count),
                                    quantityPtr,
                                    UInt(canonicalQuantity.utf8.count),
                                    destinationPtr,
                                    UInt(destination.utf8.count),
                                    instructionPtrPtr,
                                    instructionLenPtr
                                )
                            }
                        }
                    }
                }
            }
        }

        if status != 0 {
            if let instructionPtr { freeFn(instructionPtr) }
            try throwOnStatus(status)
            return nil
        }
        guard let instructionPtr else { return nil }

        let data = Data(bytes: instructionPtr, count: Int(instructionLen))
        freeFn(instructionPtr)
        return data
        #else
        return nil
        #endif
    }

    public func encodeTransferInstructionFrame(
        authority: String,
        assetDefinitionId: String,
        quantity: String,
        destination: String
    ) throws -> TransactionInstructionFrame {
        let canonicalQuantity = try KotodamaNumericV1Codec
            .decodeQuantityJSON(quantity).canonicalString
        #if canImport(Darwin)
        guard let freeFn, let encodeTransferInstructionFrameFn else { throw NativeBridgeError.bridgeUnavailable }

        var instructionPtr: UnsafeMutablePointer<UInt8>? = nil
        var instructionLen: UInt = 0
        let status = try withAuthorityChainDiscriminant(authority: authority) {
            authority.withCString { authorityPtr in
                assetDefinitionId.withCString { assetPtr in
                    canonicalQuantity.withCString { quantityPtr in
                        destination.withCString { destinationPtr in
                            self.withSignedOutputs(
                                signedPtr: &instructionPtr,
                                signedLen: &instructionLen
                            ) { instructionPtrPtr, instructionLenPtr in
                                encodeTransferInstructionFrameFn(
                                    authorityPtr,
                                    UInt(authority.utf8.count),
                                    assetPtr,
                                    UInt(assetDefinitionId.utf8.count),
                                    quantityPtr,
                                    UInt(canonicalQuantity.utf8.count),
                                    destinationPtr,
                                    UInt(destination.utf8.count),
                                    instructionPtrPtr,
                                    instructionLenPtr
                                )
                            }
                        }
                    }
                }
            }
        }

        if status != 0 {
            if let instructionPtr { freeFn(instructionPtr) }
            try throwOnStatus(status)
            throw NativeBridgeError.invalidDetachedTransactionOutput
        }
        guard let instructionPtr else { throw NativeBridgeError.bridgeUnavailable }

        defer { freeFn(instructionPtr) }
        guard instructionLen > 0, instructionLen <= 1024 * 1024 else {
            throw NativeBridgeError.invalidDetachedTransactionOutput
        }
        let data = Data(bytes: instructionPtr, count: Int(instructionLen))
        try StrictJSONDuplicateKeyRejector.rejectDuplicateObjectKeys(in: data)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(json.keys) == ["schema", "wire_name", "framed_payload_b64"],
              json["schema"] as? String == "iroha.transfer_instruction_frame.v1",
              let wireName = json["wire_name"] as? String,
              let encoded = json["framed_payload_b64"] as? String,
              let frame = Data(base64Encoded: encoded), frame.base64EncodedString() == encoded else {
            throw NativeBridgeError.invalidDetachedTransactionOutput
        }
        return try TransactionInstructionFrame(wireName: wireName, framedPayload: frame)
        #else
        throw NativeBridgeError.bridgeUnavailable
        #endif
    }

    func encodeRegisterZkAsset(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        assetDefinitionId: String,
        unshieldVerifyingKey: String?,
        feePaymentJSON: Data,
        privateKey: Data,
        algorithm: SigningAlgorithm = .ed25519
    ) throws -> NativeSignedTransaction? {
        guard !feePaymentJSON.isEmpty else { throw NativeBridgeError.feePayment }
        #if canImport(Darwin)
        guard let freeFn else { return nil }
        let feePaymentBytes = feePaymentJSON as NSData
        let feePaymentPtr = feePaymentBytes.bytes.assumingMemoryBound(to: UInt8.self)
        let ttlValue = ttlMs ?? 0
        let ttlFlag: UInt8 = ttlMs == nil ? 0 : 1
        let useAlg = algorithm != .ed25519 && encodeRegisterZkAssetWithAlgFn != nil
        guard useAlg || encodeRegisterZkAssetFn != nil else { return nil }

        var signedPtr: UnsafeMutablePointer<UInt8>? = nil
        var signedLen: UInt = 0
        var hashBytes = [UInt8](repeating: 0, count: 32)
        let hashLength = UInt(hashBytes.count)
        let algorithmRaw = algorithm.noritoDiscriminant

        let status = try withAuthorityChainDiscriminant(authority: authority) {
            networkId.literal.withCString { networkIdPtr in
            authority.withCString { authorityPtr in
                assetDefinitionId.withCString { assetPtr in
                    privateKey.withUnsafeBytes { keyBuffer -> Int32 in
                        guard let keyBase = keyBuffer.bindMemory(to: UInt8.self).baseAddress else {
                            return -1
                        }
                        return hashBytes.withUnsafeMutableBufferPointer { hashBuffer -> Int32 in
                            guard let hashPtr = hashBuffer.baseAddress else {
                                return -1
                            }
                            return withSignedOutputs(signedPtr: &signedPtr, signedLen: &signedLen) { signedPtrPtr, signedLenPtr in
                                withOptionalCString(unshieldVerifyingKey) { unshieldPtr, unshieldLen, unshieldFlag in
                                    if useAlg, let encodeRegisterZkAssetWithAlgFn {
                                        return encodeRegisterZkAssetWithAlgFn(
                                            networkIdPtr, UInt(networkId.literal.utf8.count),
                                            authorityPtr, UInt(authority.utf8.count),
                                            creationTimeMs,
                                            ttlValue,
                                            ttlFlag,
                                            assetPtr, UInt(assetDefinitionId.utf8.count),
                                            unshieldPtr, unshieldLen,
                                            unshieldFlag,
                                            feePaymentPtr, UInt(feePaymentJSON.count),
                                            keyBase, UInt(privateKey.count),
                                            algorithmRaw,
                                            signedPtrPtr,
                                            signedLenPtr,
                                            hashPtr,
                                            hashLength
                                        )
                                    } else if let encodeRegisterZkAssetFn {
                                        return encodeRegisterZkAssetFn(
                                            networkIdPtr, UInt(networkId.literal.utf8.count),
                                            authorityPtr, UInt(authority.utf8.count),
                                            creationTimeMs,
                                            ttlValue,
                                            ttlFlag,
                                            assetPtr, UInt(assetDefinitionId.utf8.count),
                                            unshieldPtr, unshieldLen,
                                            unshieldFlag,
                                            feePaymentPtr, UInt(feePaymentJSON.count),
                                            keyBase, UInt(privateKey.count),
                                            signedPtrPtr,
                                            signedLenPtr,
                                            hashPtr,
                                            hashLength
                                        )
                                    } else {
                                        return -1
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        }

        if status != 0 {
            if let signedPtr {
                freeFn(signedPtr)
            }
            try throwOnStatus(status)
            return nil
        }
        guard let signedPtr else { return nil }

        let signedData = Data(bytes: signedPtr, count: Int(signedLen))
        freeFn(signedPtr)
        let hashData = Data(hashBytes)
        return NativeSignedTransaction(signedBytes: signedData, hash: hashData)
        #else
        return nil
        #endif
    }

    func encodeMint(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        nonce: UInt32? = nil,
        assetDefinitionId: String,
        quantity: String,
        destination: String,
        feePaymentJSON: Data,
        privateKey: Data,
        algorithm: SigningAlgorithm = .ed25519
    ) throws -> NativeSignedTransaction? {
        guard !feePaymentJSON.isEmpty else { throw NativeBridgeError.feePayment }
        let canonicalQuantity = try KotodamaNumericV1Codec
            .decodeQuantityJSON(quantity).canonicalString
        #if canImport(Darwin)
        guard let freeFn else { return nil }
        let feePaymentBytes = feePaymentJSON as NSData
        let feePaymentPtr = feePaymentBytes.bytes.assumingMemoryBound(to: UInt8.self)
        let ttlValue = ttlMs ?? 0
        let ttlFlag: UInt8 = ttlMs == nil ? 0 : 1
        let nonceValue = nonce ?? 0
        let nonceFlag: UInt8 = nonce == nil ? 0 : 1
        let useAlg = algorithm != .ed25519 && encodeMintWithAlgFn != nil
        guard useAlg || encodeMintFn != nil else { return nil }

        var signedPtr: UnsafeMutablePointer<UInt8>? = nil
        var signedLen: UInt = 0
        var hashBytes = [UInt8](repeating: 0, count: 32)
        let hashLength = UInt(hashBytes.count)
        let algorithmRaw = algorithm.noritoDiscriminant

        let status = try withAuthorityChainDiscriminant(authority: authority) {
            networkId.literal.withCString { networkIdPtr in
            authority.withCString { authorityPtr in
                assetDefinitionId.withCString { assetPtr in
                    canonicalQuantity.withCString { quantityPtr in
                        destination.withCString { destinationPtr in
                            privateKey.withUnsafeBytes { keyBuffer -> Int32 in
                                hashBytes.withUnsafeMutableBufferPointer { hashBuffer -> Int32 in
                                    guard let hashPtr = hashBuffer.baseAddress else {
                                        return -1
                                    }
                                    return withSignedOutputs(signedPtr: &signedPtr, signedLen: &signedLen) { signedPtrPtr, signedLenPtr in
                                        if useAlg, let encodeMintWithAlgFn {
                                            return encodeMintWithAlgFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                                authorityPtr, UInt(authority.utf8.count),
                                                creationTimeMs,
                                                ttlValue,
                                                ttlFlag,
                                                nonceValue,
                                                nonceFlag,
                                                assetPtr, UInt(assetDefinitionId.utf8.count),
                                                quantityPtr, UInt(canonicalQuantity.utf8.count),
                                                destinationPtr, UInt(destination.utf8.count),
                                                feePaymentPtr, UInt(feePaymentJSON.count),
                                                keyBuffer.bindMemory(to: UInt8.self).baseAddress, UInt(privateKey.count),
                                                algorithmRaw,
                                                signedPtrPtr,
                                                signedLenPtr,
                                                hashPtr,
                                                hashLength
                                            )
                                        } else if let encodeMintFn {
                                            return encodeMintFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                                authorityPtr, UInt(authority.utf8.count),
                                                creationTimeMs,
                                                ttlValue,
                                                ttlFlag,
                                                nonceValue,
                                                nonceFlag,
                                                assetPtr, UInt(assetDefinitionId.utf8.count),
                                                quantityPtr, UInt(canonicalQuantity.utf8.count),
                                                destinationPtr, UInt(destination.utf8.count),
                                                feePaymentPtr, UInt(feePaymentJSON.count),
                                                keyBuffer.bindMemory(to: UInt8.self).baseAddress, UInt(privateKey.count),
                                                signedPtrPtr,
                                                signedLenPtr,
                                                hashPtr,
                                                hashLength
                                            )
                                        } else {
                                            return -1
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        }

        if status != 0 {
            if let signedPtr { freeFn(signedPtr) }
            try throwOnStatus(status)
            return nil
        }
        guard let signedPtr else { return nil }

        let signedData = Data(bytes: signedPtr, count: Int(signedLen))
        freeFn(signedPtr)
        let hashData = Data(hashBytes)
        return NativeSignedTransaction(signedBytes: signedData, hash: hashData)
        #else
        return nil
        #endif
    }

    func encodeMultisigRegister(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        accountId: String,
        specJSON: Data,
        feePaymentJSON: Data,
        privateKey: Data,
        algorithm: SigningAlgorithm
    ) throws -> NativeSignedTransaction? {
        guard !feePaymentJSON.isEmpty else { throw NativeBridgeError.feePayment }
        #if canImport(Darwin)
        guard let freeFn else { return nil }
        let feePaymentBytes = feePaymentJSON as NSData
        let feePaymentPtr = feePaymentBytes.bytes.assumingMemoryBound(to: UInt8.self)
        let useAlg = algorithm != .ed25519 && encodeMultisigRegisterWithAlgFn != nil
        guard useAlg || encodeMultisigRegisterFn != nil else { return nil }

        var signedPtr: UnsafeMutablePointer<UInt8>? = nil
        var signedLen: UInt = 0
        var hashBytes = [UInt8](repeating: 0, count: 32)
        let hashLength = UInt(hashBytes.count)
        let algorithmRaw = algorithm.noritoDiscriminant
        let ttlValue = ttlMs ?? 0
        let ttlFlag: UInt8 = ttlMs == nil ? 0 : 1

        let status = try withAuthorityChainDiscriminant(authority: authority) {
            networkId.literal.withCString { networkIdPtr -> Int32 in
                return authority.withCString { authorityPtr -> Int32 in
                return accountId.withCString { accountPtr -> Int32 in
                    return specJSON.withUnsafeBytes { specBuffer -> Int32 in
                        guard let specPtr = specBuffer.bindMemory(to: CChar.self).baseAddress else {
                            return -1
                        }
                        return privateKey.withUnsafeBytes { keyBuffer -> Int32 in
                            guard let keyPtr = keyBuffer.bindMemory(to: UInt8.self).baseAddress else {
                                return -1
                            }
                            return hashBytes.withUnsafeMutableBufferPointer { hashBuffer -> Int32 in
                                guard let hashPtr = hashBuffer.baseAddress else {
                                    return -1
                                }
                                return withSignedOutputs(signedPtr: &signedPtr, signedLen: &signedLen) { signedPtrPtr, signedLenPtr in
                                    let specLen = UInt(specJSON.count)
                                    let keyLen = UInt(privateKey.count)
                                    let accountLen = UInt(accountId.utf8.count)
                                    if useAlg, let encodeMultisigRegisterWithAlgFn {
                                        return encodeMultisigRegisterWithAlgFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                            authorityPtr, UInt(authority.utf8.count),
                                            creationTimeMs,
                                            ttlValue,
                                            ttlFlag,
                                            specPtr, specLen,
                                            accountPtr, accountLen,
                                            feePaymentPtr, UInt(feePaymentJSON.count),
                                            keyPtr, keyLen,
                                            algorithmRaw,
                                            signedPtrPtr,
                                            signedLenPtr,
                                            hashPtr,
                                            hashLength
                                        )
                                    } else if let encodeMultisigRegisterFn {
                                        return encodeMultisigRegisterFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                            authorityPtr, UInt(authority.utf8.count),
                                            creationTimeMs,
                                            ttlValue,
                                            ttlFlag,
                                            specPtr, specLen,
                                            accountPtr, accountLen,
                                            feePaymentPtr, UInt(feePaymentJSON.count),
                                            keyPtr, keyLen,
                                            signedPtrPtr,
                                            signedLenPtr,
                                            hashPtr,
                                            hashLength
                                        )
                                    } else {
                                        return -1
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        }

        if status != 0 {
            if let signedPtr { freeFn(signedPtr) }
            try throwOnStatus(status)
            return nil
        }
        guard let signedPtr else { return nil }

        let signedData = Data(bytes: signedPtr, count: Int(signedLen))
        freeFn(signedPtr)
        let hashData = Data(hashBytes)
        return NativeSignedTransaction(signedBytes: signedData, hash: hashData)
        #else
        return nil
        #endif
    }

    func encodeClaimIdentifier(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        accountId: String,
        receiptJSON: Data,
        feePaymentJSON: Data,
        privateKey: Data,
        algorithm: SigningAlgorithm
    ) throws -> NativeSignedTransaction? {
        guard !feePaymentJSON.isEmpty else { throw NativeBridgeError.feePayment }
        #if canImport(Darwin)
        guard let freeFn else { return nil }
        let feePaymentBytes = feePaymentJSON as NSData
        let feePaymentPtr = feePaymentBytes.bytes.assumingMemoryBound(to: UInt8.self)
        let useAlg = algorithm != .ed25519 && encodeClaimIdentifierWithAlgFn != nil
        guard useAlg || encodeClaimIdentifierFn != nil else { return nil }

        var signedPtr: UnsafeMutablePointer<UInt8>? = nil
        var signedLen: UInt = 0
        var hashBytes = [UInt8](repeating: 0, count: 32)
        let hashLength = UInt(hashBytes.count)
        let algorithmRaw = algorithm.noritoDiscriminant
        let ttlValue = ttlMs ?? 0
        let ttlFlag: UInt8 = ttlMs == nil ? 0 : 1

        let status = try withAuthorityChainDiscriminant(authority: authority) {
            networkId.literal.withCString { networkIdPtr -> Int32 in
                authority.withCString { authorityPtr -> Int32 in
                    accountId.withCString { accountPtr -> Int32 in
                        receiptJSON.withUnsafeBytes { receiptBuffer -> Int32 in
                            guard let receiptPtr = receiptBuffer.bindMemory(to: CChar.self).baseAddress else {
                                return -1
                            }
                            return privateKey.withUnsafeBytes { keyBuffer -> Int32 in
                                guard let keyPtr = keyBuffer.bindMemory(to: UInt8.self).baseAddress else {
                                    return -1
                                }
                                return hashBytes.withUnsafeMutableBufferPointer { hashBuffer -> Int32 in
                                    guard let hashPtr = hashBuffer.baseAddress else {
                                        return -1
                                    }
                                    return withSignedOutputs(signedPtr: &signedPtr, signedLen: &signedLen) { signedPtrPtr, signedLenPtr in
                                        if useAlg, let encodeClaimIdentifierWithAlgFn {
                                            return encodeClaimIdentifierWithAlgFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                                authorityPtr, UInt(authority.utf8.count),
                                                creationTimeMs,
                                                ttlValue,
                                                ttlFlag,
                                                accountPtr, UInt(accountId.utf8.count),
                                                receiptPtr, UInt(receiptJSON.count),
                                                feePaymentPtr, UInt(feePaymentJSON.count),
                                                keyPtr, UInt(privateKey.count),
                                                algorithmRaw,
                                                signedPtrPtr,
                                                signedLenPtr,
                                                hashPtr,
                                                hashLength
                                            )
                                        } else if let encodeClaimIdentifierFn {
                                            return encodeClaimIdentifierFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                                authorityPtr, UInt(authority.utf8.count),
                                                creationTimeMs,
                                                ttlValue,
                                                ttlFlag,
                                                accountPtr, UInt(accountId.utf8.count),
                                                receiptPtr, UInt(receiptJSON.count),
                                                feePaymentPtr, UInt(feePaymentJSON.count),
                                                keyPtr, UInt(privateKey.count),
                                                signedPtrPtr,
                                                signedLenPtr,
                                                hashPtr,
                                                hashLength
                                            )
                                        } else {
                                            return -1
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if status != 0 {
            if let signedPtr { freeFn(signedPtr) }
            try throwOnStatus(status)
            return nil
        }
        guard let signedPtr else { return nil }

        let signedData = Data(bytes: signedPtr, count: Int(signedLen))
        freeFn(signedPtr)
        let hashData = Data(hashBytes)
        return NativeSignedTransaction(signedBytes: signedData, hash: hashData)
        #else
        return nil
        #endif
    }

    func encodeBurn(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        nonce: UInt32? = nil,
        assetDefinitionId: String,
        quantity: String,
        destination: String,
        feePaymentJSON: Data,
        privateKey: Data,
        algorithm: SigningAlgorithm = .ed25519
    ) throws -> NativeSignedTransaction? {
        guard !feePaymentJSON.isEmpty else { throw NativeBridgeError.feePayment }
        let canonicalQuantity = try KotodamaNumericV1Codec
            .decodeQuantityJSON(quantity).canonicalString
        #if canImport(Darwin)
        guard let freeFn else { return nil }
        let feePaymentBytes = feePaymentJSON as NSData
        let feePaymentPtr = feePaymentBytes.bytes.assumingMemoryBound(to: UInt8.self)
        let ttlValue = ttlMs ?? 0
        let ttlFlag: UInt8 = ttlMs == nil ? 0 : 1
        let nonceValue = nonce ?? 0
        let nonceFlag: UInt8 = nonce == nil ? 0 : 1
        let useAlg = algorithm != .ed25519 && encodeBurnWithAlgFn != nil
        guard useAlg || encodeBurnFn != nil else { return nil }

        var signedPtr: UnsafeMutablePointer<UInt8>? = nil
        var signedLen: UInt = 0
        var hashBytes = [UInt8](repeating: 0, count: 32)
        let hashLength = UInt(hashBytes.count)
        let algorithmRaw = algorithm.noritoDiscriminant

        let status = try withAuthorityChainDiscriminant(authority: authority) {
            networkId.literal.withCString { networkIdPtr in
            authority.withCString { authorityPtr in
                assetDefinitionId.withCString { assetPtr in
                    canonicalQuantity.withCString { quantityPtr in
                        destination.withCString { destinationPtr in
                            privateKey.withUnsafeBytes { keyBuffer -> Int32 in
                                hashBytes.withUnsafeMutableBufferPointer { hashBuffer -> Int32 in
                                    guard let hashPtr = hashBuffer.baseAddress else {
                                        return -1
                                    }
                                    return withSignedOutputs(signedPtr: &signedPtr, signedLen: &signedLen) { signedPtrPtr, signedLenPtr in
                                        if useAlg, let encodeBurnWithAlgFn {
                                            return encodeBurnWithAlgFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                                authorityPtr, UInt(authority.utf8.count),
                                                creationTimeMs,
                                                ttlValue,
                                                ttlFlag,
                                                nonceValue,
                                                nonceFlag,
                                                assetPtr, UInt(assetDefinitionId.utf8.count),
                                                quantityPtr, UInt(canonicalQuantity.utf8.count),
                                                destinationPtr, UInt(destination.utf8.count),
                                                feePaymentPtr, UInt(feePaymentJSON.count),
                                                keyBuffer.bindMemory(to: UInt8.self).baseAddress, UInt(privateKey.count),
                                                algorithmRaw,
                                                signedPtrPtr,
                                                signedLenPtr,
                                                hashPtr,
                                                hashLength
                                            )
                                        } else if let encodeBurnFn {
                                            return encodeBurnFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                                authorityPtr, UInt(authority.utf8.count),
                                                creationTimeMs,
                                                ttlValue,
                                                ttlFlag,
                                                nonceValue,
                                                nonceFlag,
                                                assetPtr, UInt(assetDefinitionId.utf8.count),
                                                quantityPtr, UInt(canonicalQuantity.utf8.count),
                                                destinationPtr, UInt(destination.utf8.count),
                                                feePaymentPtr, UInt(feePaymentJSON.count),
                                                keyBuffer.bindMemory(to: UInt8.self).baseAddress, UInt(privateKey.count),
                                                signedPtrPtr,
                                                signedLenPtr,
                                                hashPtr,
                                                hashLength
                                            )
                                        } else {
                                            return -1
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        }

        if status != 0 {
            if let signedPtr { freeFn(signedPtr) }
            try throwOnStatus(status)
            return nil
        }
        guard let signedPtr else { return nil }

        let signedData = Data(bytes: signedPtr, count: Int(signedLen))
        freeFn(signedPtr)
        let hashData = Data(hashBytes)
        return NativeSignedTransaction(signedBytes: signedData, hash: hashData)
        #else
        return nil
        #endif
    }

    func encodeSetKeyValue(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        targetKind: UInt8,
        objectId: String,
        key: String,
        valueJson: Data,
        feePaymentJSON: Data,
        privateKey: Data,
        algorithm: SigningAlgorithm = .ed25519
    ) throws -> NativeSignedTransaction? {
        guard !feePaymentJSON.isEmpty else { throw NativeBridgeError.feePayment }
        #if canImport(Darwin)
        guard let freeFn else { return nil }
        let feePaymentBytes = feePaymentJSON as NSData
        let feePaymentPtr = feePaymentBytes.bytes.assumingMemoryBound(to: UInt8.self)
        let ttlValue = ttlMs ?? 0
        let ttlFlag: UInt8 = ttlMs == nil ? 0 : 1
        let useAlg = algorithm != .ed25519 && encodeSetKeyValueWithAlgFn != nil
        guard useAlg || encodeSetKeyValueFn != nil else { return nil }

        var signedPtr: UnsafeMutablePointer<UInt8>? = nil
        var signedLen: UInt = 0
        var hashBytes = [UInt8](repeating: 0, count: 32)
        let hashLength = UInt(hashBytes.count)
        let algorithmRaw = algorithm.noritoDiscriminant

        let status = try withAuthorityChainDiscriminant(authority: authority) {
            networkId.literal.withCString { networkIdPtr in
            authority.withCString { authorityPtr in
                objectId.withCString { objectPtr in
                    key.withCString { keyCStrPtr in
                        valueJson.withUnsafeBytes { valueBuffer -> Int32 in
                            guard let valuePtr = valueBuffer.bindMemory(to: UInt8.self).baseAddress else {
                                return -1
                            }
                            return privateKey.withUnsafeBytes { keyBuffer -> Int32 in
                                guard let privateKeyPtr = keyBuffer.bindMemory(to: UInt8.self).baseAddress else {
                                    return -1
                                }
                                return hashBytes.withUnsafeMutableBufferPointer { hashBuffer -> Int32 in
                                    guard let hashPtr = hashBuffer.baseAddress else {
                                        return -1
                                    }
                                    return withSignedOutputs(signedPtr: &signedPtr, signedLen: &signedLen) { signedPtrPtr, signedLenPtr in
                                        if useAlg, let encodeSetKeyValueWithAlgFn {
                                            return encodeSetKeyValueWithAlgFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                                authorityPtr, UInt(authority.utf8.count),
                                                creationTimeMs,
                                                ttlValue,
                                                ttlFlag,
                                                targetKind,
                                                objectPtr, UInt(objectId.utf8.count),
                                                keyCStrPtr, UInt(key.utf8.count),
                                                valuePtr, UInt(valueJson.count),
                                                feePaymentPtr, UInt(feePaymentJSON.count),
                                                privateKeyPtr, UInt(privateKey.count),
                                                algorithmRaw,
                                                signedPtrPtr,
                                                signedLenPtr,
                                                hashPtr,
                                                hashLength
                                            )
                                        } else if let encodeSetKeyValueFn {
                                            return encodeSetKeyValueFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                                authorityPtr, UInt(authority.utf8.count),
                                                creationTimeMs,
                                                ttlValue,
                                                ttlFlag,
                                                targetKind,
                                                objectPtr, UInt(objectId.utf8.count),
                                                keyCStrPtr, UInt(key.utf8.count),
                                                valuePtr, UInt(valueJson.count),
                                                feePaymentPtr, UInt(feePaymentJSON.count),
                                                privateKeyPtr, UInt(privateKey.count),
                                                signedPtrPtr,
                                                signedLenPtr,
                                                hashPtr,
                                                hashLength
                                            )
                                        } else {
                                            return -1
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        }

        if status != 0 {
            if let signedPtr { freeFn(signedPtr) }
            try throwOnStatus(status)
            return nil
        }
        guard let signedPtr else { return nil }

        let signedData = Data(bytes: signedPtr, count: Int(signedLen))
        freeFn(signedPtr)
        let hashData = Data(hashBytes)
        return NativeSignedTransaction(signedBytes: signedData, hash: hashData)
        #else
        return nil
        #endif
    }

    func encodeRemoveKeyValue(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        targetKind: UInt8,
        objectId: String,
        key: String,
        feePaymentJSON: Data,
        privateKey: Data,
        algorithm: SigningAlgorithm = .ed25519
    ) throws -> NativeSignedTransaction? {
        guard !feePaymentJSON.isEmpty else { throw NativeBridgeError.feePayment }
        #if canImport(Darwin)
        guard let freeFn else { return nil }
        let feePaymentBytes = feePaymentJSON as NSData
        let feePaymentPtr = feePaymentBytes.bytes.assumingMemoryBound(to: UInt8.self)
        let ttlValue = ttlMs ?? 0
        let ttlFlag: UInt8 = ttlMs == nil ? 0 : 1
        let useAlg = algorithm != .ed25519 && encodeRemoveKeyValueWithAlgFn != nil
        guard useAlg || encodeRemoveKeyValueFn != nil else { return nil }

        var signedPtr: UnsafeMutablePointer<UInt8>? = nil
        var signedLen: UInt = 0
        var hashBytes = [UInt8](repeating: 0, count: 32)
        let hashLength = UInt(hashBytes.count)
        let algorithmRaw = algorithm.noritoDiscriminant

        let status = try withAuthorityChainDiscriminant(authority: authority) {
            networkId.literal.withCString { networkIdPtr in
            authority.withCString { authorityPtr in
                objectId.withCString { objectPtr in
                    key.withCString { keyPtr in
                        privateKey.withUnsafeBytes { keyBuffer -> Int32 in
                            guard let keyPtrBytes = keyBuffer.bindMemory(to: UInt8.self).baseAddress else {
                                return -1
                            }
                            return hashBytes.withUnsafeMutableBufferPointer { hashBuffer -> Int32 in
                                guard let hashPtr = hashBuffer.baseAddress else {
                                    return -1
                                }
                                return withSignedOutputs(signedPtr: &signedPtr, signedLen: &signedLen) { signedPtrPtr, signedLenPtr in
                                    if useAlg, let encodeRemoveKeyValueWithAlgFn {
                                        return encodeRemoveKeyValueWithAlgFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                            authorityPtr, UInt(authority.utf8.count),
                                            creationTimeMs,
                                            ttlValue,
                                            ttlFlag,
                                            targetKind,
                                            objectPtr, UInt(objectId.utf8.count),
                                            keyPtr, UInt(key.utf8.count),
                                            feePaymentPtr, UInt(feePaymentJSON.count),
                                            keyPtrBytes, UInt(privateKey.count),
                                            algorithmRaw,
                                            signedPtrPtr,
                                            signedLenPtr,
                                            hashPtr,
                                            hashLength
                                        )
                                    } else if let encodeRemoveKeyValueFn {
                                        return encodeRemoveKeyValueFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                            authorityPtr, UInt(authority.utf8.count),
                                            creationTimeMs,
                                            ttlValue,
                                            ttlFlag,
                                            targetKind,
                                            objectPtr, UInt(objectId.utf8.count),
                                            keyPtr, UInt(key.utf8.count),
                                            feePaymentPtr, UInt(feePaymentJSON.count),
                                            keyPtrBytes, UInt(privateKey.count),
                                            signedPtrPtr,
                                            signedLenPtr,
                                            hashPtr,
                                            hashLength
                                        )
                                    } else {
                                        return -1
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        }

        if status != 0 {
            if let signedPtr { freeFn(signedPtr) }
            try throwOnStatus(status)
            return nil
        }
        guard let signedPtr else { return nil }

        let signedData = Data(bytes: signedPtr, count: Int(signedLen))
        freeFn(signedPtr)
        let hashData = Data(hashBytes)
        return NativeSignedTransaction(signedBytes: signedData, hash: hashData)
        #else
        return nil
        #endif
    }

    func encodeGovernanceProposeDeploy(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        contractAddress: String,
        codeHash: Data,
        abiHash: Data,
        abiVersion: UInt16,
        manifestProvenance: ToriiContractManifestProvenance?,
        feePaymentJSON: Data,
        privateKey: Data,
        algorithm: SigningAlgorithm = .ed25519
    ) throws -> NativeSignedTransaction? {
        guard !feePaymentJSON.isEmpty else { throw NativeBridgeError.feePayment }
        guard codeHash.count == 32, abiHash.count == 32, abiVersion == 1 else {
            throw NativeBridgeError.governance
        }
        if let manifestProvenance {
            guard isExactContractManifestString(manifestProvenance.signer),
                  isExactContractManifestString(manifestProvenance.signature) else {
                throw NativeBridgeError.governance
            }
        }
        #if canImport(Darwin)
        guard let freeFn else { return nil }
        let feePaymentBytes = feePaymentJSON as NSData
        let feePaymentPtr = feePaymentBytes.bytes.assumingMemoryBound(to: UInt8.self)
        let ttlValue = ttlMs ?? 0
        let ttlFlag: UInt8 = ttlMs == nil ? 0 : 1
        let useAlg = algorithm != .ed25519 && encodeGovernanceProposeDeployWithAlgFn != nil
        guard useAlg || encodeGovernanceProposeDeployFn != nil else { return nil }

        var signedPtr: UnsafeMutablePointer<UInt8>? = nil
        var signedLen: UInt = 0
        var hashBytes = [UInt8](repeating: 0, count: 32)
        let hashLength = UInt(hashBytes.count)
        let algorithmRaw = algorithm.noritoDiscriminant
        let provenanceSigner = manifestProvenance?.signer ?? ""
        let provenanceSignature = manifestProvenance?.signature ?? ""
        let provenanceFlag: UInt8 = manifestProvenance == nil ? 0 : 1

        let status = try withAuthorityChainDiscriminant(authority: authority) {
            networkId.literal.withCString { networkIdPtr in
                authority.withCString { authorityPtr in
                    contractAddress.withCString { contractAddressPtr in
                        provenanceSigner.withCString { provenanceSignerPtr in
                            provenanceSignature.withCString { provenanceSignaturePtr in
                                codeHash.withUnsafeBytes { codeHashBuffer -> Int32 in
                                    guard let codeHashPtr = codeHashBuffer.bindMemory(to: UInt8.self).baseAddress else {
                                        return -1
                                    }
                                    return abiHash.withUnsafeBytes { abiHashBuffer -> Int32 in
                                        guard let abiHashPtr = abiHashBuffer.bindMemory(to: UInt8.self).baseAddress else {
                                            return -1
                                        }
                                        return privateKey.withUnsafeBytes { keyBuffer -> Int32 in
                                            guard let keyPtr = keyBuffer.bindMemory(to: UInt8.self).baseAddress else {
                                                return -1
                                            }
                                            return hashBytes.withUnsafeMutableBufferPointer { hashBuffer -> Int32 in
                                                guard let hashPtr = hashBuffer.baseAddress else {
                                                    return -1
                                                }
                                                return withSignedOutputs(signedPtr: &signedPtr, signedLen: &signedLen) { signedPtrPtr, signedLenPtr in
                                                    if useAlg, let encodeGovernanceProposeDeployWithAlgFn {
                                                        return encodeGovernanceProposeDeployWithAlgFn(
                                                            networkIdPtr, UInt(networkId.literal.utf8.count),
                                                            authorityPtr, UInt(authority.utf8.count),
                                                            creationTimeMs,
                                                            ttlValue,
                                                            ttlFlag,
                                                            contractAddressPtr, UInt(contractAddress.utf8.count),
                                                            codeHashPtr, UInt(codeHash.count),
                                                            abiHashPtr, UInt(abiHash.count),
                                                            abiVersion,
                                                            provenanceSignerPtr, UInt(provenanceSigner.utf8.count),
                                                            provenanceSignaturePtr, UInt(provenanceSignature.utf8.count),
                                                            provenanceFlag,
                                                            feePaymentPtr, UInt(feePaymentJSON.count),
                                                            keyPtr, UInt(privateKey.count),
                                                            algorithmRaw,
                                                            signedPtrPtr,
                                                            signedLenPtr,
                                                            hashPtr,
                                                            hashLength
                                                        )
                                                    } else if let encodeGovernanceProposeDeployFn {
                                                        return encodeGovernanceProposeDeployFn(
                                                            networkIdPtr, UInt(networkId.literal.utf8.count),
                                                            authorityPtr, UInt(authority.utf8.count),
                                                            creationTimeMs,
                                                            ttlValue,
                                                            ttlFlag,
                                                            contractAddressPtr, UInt(contractAddress.utf8.count),
                                                            codeHashPtr, UInt(codeHash.count),
                                                            abiHashPtr, UInt(abiHash.count),
                                                            abiVersion,
                                                            provenanceSignerPtr, UInt(provenanceSigner.utf8.count),
                                                            provenanceSignaturePtr, UInt(provenanceSignature.utf8.count),
                                                            provenanceFlag,
                                                            feePaymentPtr, UInt(feePaymentJSON.count),
                                                            keyPtr, UInt(privateKey.count),
                                                            signedPtrPtr,
                                                            signedLenPtr,
                                                            hashPtr,
                                                            hashLength
                                                        )
                                                    }
                                                    return -1
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if status != 0 {
            if let signedPtr { freeFn(signedPtr) }
            try throwOnStatus(status)
            return nil
        }
        guard let signedPtr else { return nil }

        let signedData = Data(bytes: signedPtr, count: Int(signedLen))
        freeFn(signedPtr)
        let hashData = Data(hashBytes)
        return NativeSignedTransaction(signedBytes: signedData, hash: hashData)
        #else
        return nil
        #endif
    }

    func encodeGovernanceCastPlainBallot(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        referendumId: String,
        owner: String,
        amount: String,
        durationBlocks: UInt64,
        direction: UInt8,
        feePaymentJSON: Data,
        privateKey: Data,
        algorithm: SigningAlgorithm = .ed25519
    ) throws -> NativeSignedTransaction? {
        guard !feePaymentJSON.isEmpty else { throw NativeBridgeError.feePayment }
        #if canImport(Darwin)
        guard let freeFn else { return nil }
        let feePaymentBytes = feePaymentJSON as NSData
        let feePaymentPtr = feePaymentBytes.bytes.assumingMemoryBound(to: UInt8.self)
        let ttlValue = ttlMs ?? 0
        let ttlFlag: UInt8 = ttlMs == nil ? 0 : 1
        let useAlg = algorithm != .ed25519 && encodeGovernanceCastPlainBallotWithAlgFn != nil
        guard useAlg || encodeGovernanceCastPlainBallotFn != nil else { return nil }

        var signedPtr: UnsafeMutablePointer<UInt8>? = nil
        var signedLen: UInt = 0
        var hashBytes = [UInt8](repeating: 0, count: 32)
        let hashLength = UInt(hashBytes.count)
        let algorithmRaw = algorithm.noritoDiscriminant

        let status = try withAuthorityChainDiscriminant(authority: authority) {
            networkId.literal.withCString { networkIdPtr in
            authority.withCString { authorityPtr in
                referendumId.withCString { referendumPtr in
                    owner.withCString { ownerPtr in
                        amount.withCString { amountPtr in
                            privateKey.withUnsafeBytes { keyBuffer -> Int32 in
                                guard let keyPtr = keyBuffer.bindMemory(to: UInt8.self).baseAddress else {
                                    return -1
                                }
                                return hashBytes.withUnsafeMutableBufferPointer { hashBuffer -> Int32 in
                                    guard let hashPtr = hashBuffer.baseAddress else {
                                        return -1
                                    }
                                    return withSignedOutputs(signedPtr: &signedPtr, signedLen: &signedLen) { signedPtrPtr, signedLenPtr in
                                        if useAlg, let encodeGovernanceCastPlainBallotWithAlgFn {
                                            return encodeGovernanceCastPlainBallotWithAlgFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                                authorityPtr, UInt(authority.utf8.count),
                                                creationTimeMs,
                                                ttlValue,
                                                ttlFlag,
                                                referendumPtr, UInt(referendumId.utf8.count),
                                                ownerPtr, UInt(owner.utf8.count),
                                                amountPtr, UInt(amount.utf8.count),
                                                durationBlocks,
                                                direction,
                                                feePaymentPtr, UInt(feePaymentJSON.count),
                                                keyPtr, UInt(privateKey.count),
                                                algorithmRaw,
                                                signedPtrPtr,
                                                signedLenPtr,
                                                hashPtr,
                                                hashLength
                                            )
                                        } else if let encodeGovernanceCastPlainBallotFn {
                                            return encodeGovernanceCastPlainBallotFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                                authorityPtr, UInt(authority.utf8.count),
                                                creationTimeMs,
                                                ttlValue,
                                                ttlFlag,
                                                referendumPtr, UInt(referendumId.utf8.count),
                                                ownerPtr, UInt(owner.utf8.count),
                                                amountPtr, UInt(amount.utf8.count),
                                                durationBlocks,
                                                direction,
                                                feePaymentPtr, UInt(feePaymentJSON.count),
                                                keyPtr, UInt(privateKey.count),
                                                signedPtrPtr,
                                                signedLenPtr,
                                                hashPtr,
                                                hashLength
                                            )
                                        } else {
                                            return -1
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        }

        if status != 0 {
            if let signedPtr { freeFn(signedPtr) }
            try throwOnStatus(status)
            return nil
        }
        guard let signedPtr else { return nil }

        let signedData = Data(bytes: signedPtr, count: Int(signedLen))
        freeFn(signedPtr)
        let hashData = Data(hashBytes)
        return NativeSignedTransaction(signedBytes: signedData, hash: hashData)
        #else
        return nil
        #endif
    }

    func encodeGovernanceUpdatePlainConviction(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        referendumId: String,
        owner: String,
        amount: String,
        durationBlocks: UInt64,
        feePaymentJSON: Data,
        privateKey: Data,
        algorithm: SigningAlgorithm
    ) throws -> NativeSignedTransaction? {
        guard !feePaymentJSON.isEmpty else { throw NativeBridgeError.feePayment }
        #if canImport(Darwin)
        guard let freeFn, let encodeGovernanceUpdatePlainConvictionFn else { return nil }
        let feePaymentBytes = feePaymentJSON as NSData
        let feePaymentPtr = feePaymentBytes.bytes.assumingMemoryBound(to: UInt8.self)
        let ttlValue = ttlMs ?? 0
        let ttlFlag: UInt8 = ttlMs == nil ? 0 : 1
        var signedPtr: UnsafeMutablePointer<UInt8>? = nil
        var signedLen: UInt = 0
        var hashBytes = [UInt8](repeating: 0, count: 32)
        let hashLength = UInt(hashBytes.count)

        let status = try withAuthorityChainDiscriminant(authority: authority) {
            networkId.literal.withCString { networkIdPtr in
                authority.withCString { authorityPtr in
                    referendumId.withCString { referendumPtr in
                        owner.withCString { ownerPtr in
                            amount.withCString { amountPtr in
                                privateKey.withUnsafeBytes { keyBuffer -> Int32 in
                                    guard let keyPtr = keyBuffer.bindMemory(to: UInt8.self).baseAddress else {
                                        return -1
                                    }
                                    return hashBytes.withUnsafeMutableBufferPointer { hashBuffer -> Int32 in
                                        guard let hashPtr = hashBuffer.baseAddress else {
                                            return -1
                                        }
                                        return withSignedOutputs(signedPtr: &signedPtr, signedLen: &signedLen) { signedPtrPtr, signedLenPtr in
                                            encodeGovernanceUpdatePlainConvictionFn(
                                                networkIdPtr, UInt(networkId.literal.utf8.count),
                                                authorityPtr, UInt(authority.utf8.count),
                                                creationTimeMs,
                                                ttlValue,
                                                ttlFlag,
                                                referendumPtr, UInt(referendumId.utf8.count),
                                                ownerPtr, UInt(owner.utf8.count),
                                                amountPtr, UInt(amount.utf8.count),
                                                durationBlocks,
                                                feePaymentPtr, UInt(feePaymentJSON.count),
                                                keyPtr, UInt(privateKey.count),
                                                algorithm.noritoDiscriminant,
                                                signedPtrPtr,
                                                signedLenPtr,
                                                hashPtr,
                                                hashLength
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if status != 0 {
            if let signedPtr { freeFn(signedPtr) }
            try throwOnStatus(status)
            return nil
        }
        guard let signedPtr else { return nil }
        let signedData = Data(bytes: signedPtr, count: Int(signedLen))
        freeFn(signedPtr)
        return NativeSignedTransaction(signedBytes: signedData, hash: Data(hashBytes))
        #else
        return nil
        #endif
    }

    func encodeGovernanceCastZkBallot(
        networkId: NetworkId,
        authority: String,
        creationTimeMs: UInt64,
        ttlMs: UInt64?,
        electionId: String,
        proofB64: String,
        publicInputs: Data,
        feePaymentJSON: Data,
        privateKey: Data,
        algorithm: SigningAlgorithm = .ed25519
    ) throws -> NativeSignedTransaction? {
        guard !feePaymentJSON.isEmpty else { throw NativeBridgeError.feePayment }
        #if canImport(Darwin)
        guard let freeFn else { return nil }
        let feePaymentBytes = feePaymentJSON as NSData
        let feePaymentPtr = feePaymentBytes.bytes.assumingMemoryBound(to: UInt8.self)
        let ttlValue = ttlMs ?? 0
        let ttlFlag: UInt8 = ttlMs == nil ? 0 : 1
        let useAlg = algorithm != .ed25519 && encodeGovernanceCastZkBallotWithAlgFn != nil
        guard useAlg || encodeGovernanceCastZkBallotFn != nil else { return nil }

        var signedPtr: UnsafeMutablePointer<UInt8>? = nil
        var signedLen: UInt = 0
        var hashBytes = [UInt8](repeating: 0, count: 32)
        let hashLength = UInt(hashBytes.count)
        let algorithmRaw = algorithm.noritoDiscriminant

        let status = try withAuthorityChainDiscriminant(authority: authority) {
            networkId.literal.withCString { networkIdPtr in
            authority.withCString { authorityPtr in
                electionId.withCString { electionPtr in
                    proofB64.withCString { proofPtr in
                        publicInputs.withUnsafeBytes { inputsBuffer -> Int32 in
                            guard let inputsPtr = inputsBuffer.bindMemory(to: UInt8.self).baseAddress else {
                                return -1
                            }
                            return privateKey.withUnsafeBytes { keyBuffer -> Int32 in
                                guard let keyPtr = keyBuffer.bindMemory(to: UInt8.self).baseAddress else {
                                    return -1
                                }
                                return hashBytes.withUnsafeMutableBufferPointer { hashBuffer -> Int32 in
                                    guard let hashPtr = hashBuffer.baseAddress else {
                                        return -1
                                    }
                                    return withSignedOutputs(signedPtr: &signedPtr, signedLen: &signedLen) { signedPtrPtr, signedLenPtr in
                                        if useAlg, let encodeGovernanceCastZkBallotWithAlgFn {
                                            return encodeGovernanceCastZkBallotWithAlgFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                                authorityPtr, UInt(authority.utf8.count),
                                                creationTimeMs,
                                                ttlValue,
                                                ttlFlag,
                                                electionPtr, UInt(electionId.utf8.count),
                                                proofPtr, UInt(proofB64.utf8.count),
                                                inputsPtr, UInt(publicInputs.count),
                                                feePaymentPtr, UInt(feePaymentJSON.count),
                                                keyPtr, UInt(privateKey.count),
                                                algorithmRaw,
                                                signedPtrPtr,
                                                signedLenPtr,
                                                hashPtr,
                                                hashLength
                                            )
                                        } else if let encodeGovernanceCastZkBallotFn {
                                            return encodeGovernanceCastZkBallotFn(
                                                    networkIdPtr, UInt(networkId.literal.utf8.count),
                                                authorityPtr, UInt(authority.utf8.count),
                                                creationTimeMs,
                                                ttlValue,
                                                ttlFlag,
                                                electionPtr, UInt(electionId.utf8.count),
                                                proofPtr, UInt(proofB64.utf8.count),
                                                inputsPtr, UInt(publicInputs.count),
                                                feePaymentPtr, UInt(feePaymentJSON.count),
                                                keyPtr, UInt(privateKey.count),
                                                signedPtrPtr,
                                                signedLenPtr,
                                                hashPtr,
                                                hashLength
                                            )
                                        } else {
                                            return -1
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        }

        if status != 0 {
            if let signedPtr { freeFn(signedPtr) }
            try throwOnStatus(status)
            return nil
        }
        guard let signedPtr else { return nil }

        let signedData = Data(bytes: signedPtr, count: Int(signedLen))
        freeFn(signedPtr)
        let hashData = Data(hashBytes)
        return NativeSignedTransaction(signedBytes: signedData, hash: hashData)
        #else
        return nil
        #endif
    }

    @discardableResult
    func applyAccelerationSettings(_ settings: AccelerationSettings) -> Bool {
        #if canImport(Darwin)
        guard isAvailable, let setAccelerationConfigFn else { return false }
        var config = settings.nativeConfig
        let status = withUnsafePointer(to: &config) { pointer in
            setAccelerationConfigFn(UnsafeRawPointer(pointer), UInt(MemoryLayout<ConnectNoritoAccelerationConfig>.size))
        }
        return status == 0
        #else
        return false
        #endif
    }

    func currentAccelerationSettings() -> AccelerationSettings? {
        #if canImport(Darwin)
        guard isAvailable else {
            return nil
        }
        guard let getAccelerationConfigFn else {
            return nil
        }

        var native = ConnectNoritoAccelerationConfig.empty

        let status = withUnsafeMutablePointer(to: &native) { pointer in
            getAccelerationConfigFn(UnsafeMutableRawPointer(pointer), UInt(MemoryLayout<ConnectNoritoAccelerationConfig>.size))
        }
        guard status == 0 else { return nil }
        return AccelerationSettings(nativeConfig: native)
        #else
        return nil
        #endif
    }

    func currentAccelerationState() -> AccelerationState? {
        #if canImport(Darwin)
        guard isAvailable else {
            return nil
        }
        guard let getAccelerationStateFn else {
            return nil
        }

        var native = ConnectNoritoAccelerationState(
            config: .empty,
            simd: ConnectNoritoAccelerationBackendStatus(supported: 0, configured: 0, available: 0, parity_ok: 0, last_error_ptr: nil, last_error_len: 0),
            metal: ConnectNoritoAccelerationBackendStatus(supported: 0, configured: 0, available: 0, parity_ok: 0, last_error_ptr: nil, last_error_len: 0),
            cuda: ConnectNoritoAccelerationBackendStatus(supported: 0, configured: 0, available: 0, parity_ok: 0, last_error_ptr: nil, last_error_len: 0)
        )

        let status = withUnsafeMutablePointer(to: &native) { pointer in
            getAccelerationStateFn(UnsafeMutableRawPointer(pointer), UInt(MemoryLayout<ConnectNoritoAccelerationState>.size))
        }
        guard status == 0 else { return nil }
        let decoded = AccelerationState(nativeState: native)
        if let freeFn {
            freeFn(native.simd.last_error_ptr)
            freeFn(native.metal.last_error_ptr)
            freeFn(native.cuda.last_error_ptr)
        }
        return decoded
        #else
        return nil
        #endif
    }

    func decodeSignedTransaction(_ data: Data) -> String? {
        #if canImport(Darwin)
        guard let decodeSignedFn, let freeFn else { return nil }

        var jsonPtr: UnsafeMutablePointer<UInt8>? = nil
        var jsonLen: UInt = 0

        let status = data.withUnsafeBytes { buffer -> Int32 in
            decodeSignedFn(buffer.bindMemory(to: UInt8.self).baseAddress, UInt(data.count), &jsonPtr, &jsonLen)
        }

        guard status == 0, let jsonPtr else {
            if let jsonPtr { freeFn(jsonPtr) }
            return nil
        }

        let jsonData = Data(bytes: jsonPtr, count: Int(jsonLen))
        freeFn(jsonPtr)
        return String(data: jsonData, encoding: .utf8)
        #else
        return nil
        #endif
    }

    func decodeTransactionReceipt(_ data: Data) -> String? {
        #if canImport(Darwin)
        guard let decodeReceiptFn, let freeFn else { return nil }

        var jsonPtr: UnsafeMutablePointer<UInt8>? = nil
        var jsonLen: UInt = 0

        let status = data.withUnsafeBytes { buffer -> Int32 in
            decodeReceiptFn(buffer.bindMemory(to: UInt8.self).baseAddress, UInt(data.count), &jsonPtr, &jsonLen)
        }

        guard status == 0, let jsonPtr else {
            if let jsonPtr { freeFn(jsonPtr) }
            return nil
        }

        let jsonData = Data(bytes: jsonPtr, count: Int(jsonLen))
        freeFn(jsonPtr)
        return String(data: jsonData, encoding: .utf8)
        #else
        return nil
        #endif
    }

    func decodeAssetId(_ literal: String) -> String? {
        #if canImport(Darwin)
        guard let decodeAssetIdFn, let freeFn else { return nil }
        let trimmed = literal.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        var jsonPtr: UnsafeMutablePointer<UInt8>? = nil
        var jsonLen: UInt = 0

        let status = trimmed.withCString { cString -> Int32 in
            decodeAssetIdFn(cString, UInt(trimmed.utf8.count), &jsonPtr, &jsonLen)
        }

        guard status == 0, let jsonPtr else {
            if let jsonPtr { freeFn(jsonPtr) }
            return nil
        }

        let jsonData = Data(bytes: jsonPtr, count: Int(jsonLen))
        freeFn(jsonPtr)
        return String(data: jsonData, encoding: .utf8)
        #else
        return nil
        #endif
    }

    func privacyCompiledProfileCatalogV1() throws -> Data? {
        #if canImport(Darwin)
        guard let privacyCompiledProfileCatalogFn,
              let privacyValidateCompiledProfileCatalogFn,
              let privacyFreeFn else {
            return nil
        }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = privacyCompiledProfileCatalogFn(&outPtr, &outLen)
        if let error = NativeBridgeError.fromStatus(status) {
            if let outPtr {
                privacyFreeFn(outPtr)
            }
            throw error
        }
        guard let outPtr else {
            throw NativeBridgeError.nullPointer
        }
        return try Self.readPrivacyNativeOutput(
            pointer: outPtr,
            length: outLen,
            validate: privacyValidateCompiledProfileCatalogFn,
            maximumBytes: Self.privacyCompiledProfileCatalogArchiveMaxBytes
        ) { pointer in
            privacyFreeFn(pointer)
        }
        #else
        return nil
        #endif
    }

    func privacyExact12FixtureBundleV1() throws -> Data? {
        #if canImport(Darwin)
        guard let privacyExact12FixtureBundleFn,
              let privacyValidateExact12FixtureBundleFn,
              let privacyFreeFn else {
            return nil
        }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = privacyExact12FixtureBundleFn(&outPtr, &outLen)
        if let error = NativeBridgeError.fromStatus(status) {
            if let outPtr {
                privacyFreeFn(outPtr)
            }
            throw error
        }
        guard let outPtr else {
            throw NativeBridgeError.nullPointer
        }
        return try Self.readPrivacyNativeOutput(
            pointer: outPtr,
            length: outLen,
            validate: privacyValidateExact12FixtureBundleFn,
            maximumBytes: Self.privacyExact12FixtureBundleMaxBytes
        ) { pointer in
            privacyFreeFn(pointer)
        }
        #else
        return nil
        #endif
    }

    private static func readPrivacyNativeOutput(
        pointer: UnsafeMutablePointer<UInt8>?,
        length: CUnsignedLong,
        validate: PrivacyValidateCompiledProfileCatalogFn,
        maximumBytes: Int,
        free: (UnsafeMutablePointer<UInt8>?) -> Void
    ) throws -> Data {
        guard let pointer else {
            throw NativeBridgeError.nullPointer
        }
        defer {
            Self.clearPrivacyNativeBuffer(
                pointer,
                length: length,
                maximumBytes: maximumBytes
            )
            free(pointer)
        }
        guard length > 0, length <= CUnsignedLong(maximumBytes) else {
            throw NativeBridgeError.invalidPrivacyOutput
        }
        guard validate(UnsafePointer(pointer), length) == 0 else {
            throw NativeBridgeError.invalidPrivacyOutput
        }
        return Data(bytes: pointer, count: Int(length))
    }

    func privacyCompiledProfileCatalogValidationStatusV1(_ archive: Data) -> Int32? {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime,
              let privacyValidateCompiledProfileCatalogFn,
              archive.count <= Self.privacyCompiledProfileCatalogArchiveMaxBytes else {
            return nil
        }
        return archive.withUnsafeBytes { bytes in
            privacyValidateCompiledProfileCatalogFn(
                bytes.bindMemory(to: UInt8.self).baseAddress,
                CUnsignedLong(archive.count)
            )
        }
        #else
        return nil
        #endif
    }

    func privacyExact12CapabilityManifestValidationStatusV1(_ archive: Data) -> Int32? {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime,
              let privacyValidateExact12CapabilityManifestFn,
              archive.count <= PrivacyNativeBridge.exact12CapabilityManifestArchiveMaximumBytes else {
            return nil
        }
        return archive.withUnsafeBytes { bytes in
            privacyValidateExact12CapabilityManifestFn(
                bytes.bindMemory(to: UInt8.self).baseAddress,
                CUnsignedLong(archive.count)
            )
        }
        #else
        return nil
        #endif
    }

    func privacyExact12FixtureValidationStatusV1(_ archive: Data) -> Int32? {
        #if canImport(Darwin)
        guard bridgeEnabledForRuntime,
              let privacyValidateExact12FixtureBundleFn,
              archive.count <= Self.privacyExact12FixtureBundleMaxBytes else {
            return nil
        }
        return archive.withUnsafeBytes { bytes in
            privacyValidateExact12FixtureBundleFn(
                bytes.bindMemory(to: UInt8.self).baseAddress,
                CUnsignedLong(archive.count)
            )
        }
        #else
        return nil
        #endif
    }

    private static func clearPrivacyNativeBuffer(
        _ pointer: UnsafeMutablePointer<UInt8>,
        length: CUnsignedLong,
        maximumBytes: Int
    ) {
        guard
            length > 0,
            length <= CUnsignedLong(maximumBytes),
            let count = Int(exactly: length)
        else {
            return
        }
        pointer.update(repeating: 0, count: count)
    }

    var canUseConnectCrypto: Bool {
        #if canImport(Darwin)
        return connectGenerateKeypairFn != nil
            && connectDeriveKeysFn != nil
            && connectEncryptEnvelopeFn != nil
            && connectDecryptCiphertextFn != nil
        #else
        return false
        #endif
    }

    func publicKeyFromPrivate(algorithm: SigningAlgorithm, privateKey: Data) -> Data? {
        #if canImport(Darwin)
        guard let publicKeyFromPrivateFn, let freeFn else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = privateKey.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return publicKeyFromPrivateFn(
                algorithm.noritoDiscriminant,
                base,
                CUnsignedLong(privateKey.count),
                &outPtr,
                &outLen
            )
        }
        guard status == 0, let ptr = outPtr else {
            if let outPtr { freeFn(outPtr) }
            return nil
        }
        let publicKey = Data(bytes: ptr, count: Int(outLen))
        freeFn(ptr)
        return publicKey
        #else
        return nil
        #endif
    }

    func keypairFromSeed(algorithm: SigningAlgorithm, seed: Data) -> (privateKey: Data, publicKey: Data)? {
        #if canImport(Darwin)
        guard let keypairFromSeedFn, let freeFn else { return nil }
        var outPrivatePtr: UnsafeMutablePointer<UInt8>? = nil
        var outPrivateLen: CUnsignedLong = 0
        var outPublicPtr: UnsafeMutablePointer<UInt8>? = nil
        var outPublicLen: CUnsignedLong = 0
        let status = seed.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return keypairFromSeedFn(
                algorithm.noritoDiscriminant,
                base,
                CUnsignedLong(seed.count),
                &outPrivatePtr,
                &outPrivateLen,
                &outPublicPtr,
                &outPublicLen
            )
        }
        guard status == 0, let privatePtr = outPrivatePtr, let publicPtr = outPublicPtr else {
            if let outPrivatePtr { freeFn(outPrivatePtr) }
            if let outPublicPtr { freeFn(outPublicPtr) }
            return nil
        }
        let privateKey = Data(bytes: privatePtr, count: Int(outPrivateLen))
        let publicKey = Data(bytes: publicPtr, count: Int(outPublicLen))
        freeFn(privatePtr)
        freeFn(publicPtr)
        return (privateKey, publicKey)
        #else
        return nil
        #endif
    }

    func signDetached(algorithm: SigningAlgorithm, privateKey: Data, message: Data) -> Data? {
        #if canImport(Darwin)
        guard let signDetachedFn, let freeFn else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = privateKey.withUnsafeBytes { keyBuffer -> Int32 in
            guard let keyBase = keyBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return message.withUnsafeBytes { msgBuffer -> Int32 in
                guard let msgBase = msgBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return signDetachedFn(
                    algorithm.noritoDiscriminant,
                    keyBase,
                    CUnsignedLong(privateKey.count),
                    msgBase,
                    CUnsignedLong(message.count),
                    &outPtr,
                    &outLen
                )
            }
        }
        guard status == 0, let ptr = outPtr else {
            if let outPtr { freeFn(outPtr) }
            return nil
        }
        let signature = Data(bytes: ptr, count: Int(outLen))
        freeFn(ptr)
        return signature
        #else
        return nil
        #endif
    }

    func verifyDetached(
        algorithm: SigningAlgorithm,
        publicKey: Data,
        message: Data,
        signature: Data
    ) -> Bool? {
        #if canImport(Darwin)
        guard let verifyDetachedFn else { return nil }
        var valid: UInt8 = 0
        let status = publicKey.withUnsafeBytes { pubBuffer -> Int32 in
            guard let pubBase = pubBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return message.withUnsafeBytes { msgBuffer -> Int32 in
                guard let msgBase = msgBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return signature.withUnsafeBytes { sigBuffer -> Int32 in
                    guard let sigBase = sigBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                    return verifyDetachedFn(
                        algorithm.noritoDiscriminant,
                        pubBase,
                        CUnsignedLong(publicKey.count),
                        msgBase,
                        CUnsignedLong(message.count),
                        sigBase,
                        CUnsignedLong(signature.count),
                        &valid
                    )
                }
            }
        }
        guard status == 0 else { return nil }
        return valid != 0
        #else
        return nil
        #endif
    }

    func sm2DefaultDistid() -> String? {
        #if canImport(Darwin)
        guard let sm2DefaultDistidFn,
              let freeFn else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: UInt = 0
        let status = sm2DefaultDistidFn(&outPtr, &outLen)
        guard status == 0, let ptr = outPtr else { return nil }
        let data = Data(bytes: ptr, count: Int(outLen))
        freeFn(ptr)
        return String(data: data, encoding: .utf8)
        #else
        return nil
        #endif
    }

    func sm2KeypairFromSeed(distid: String?, seed: Data) -> (privateKey: Data, publicKey: Data)? {
        #if canImport(Darwin)
        guard let sm2KeypairFromSeedFn else { return nil }
        var privateKey = [UInt8](repeating: 0, count: 32)
        var publicKey = [UInt8](repeating: 0, count: 65)
        let distData = distid?.data(using: .utf8)
        let seedCount = seed.count
        let privateCapacity = privateKey.count
        let publicCapacity = publicKey.count
        let status = withOptionalCStringData(distData) { distPtr, distLen in
            seed.withUnsafeBytes { seedBuffer -> Int32 in
                guard let seedBase = seedBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return privateKey.withUnsafeMutableBytes { privBuffer -> Int32 in
                    guard let privBase = privBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                    return publicKey.withUnsafeMutableBytes { pubBuffer -> Int32 in
                        guard let pubBase = pubBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                        return sm2KeypairFromSeedFn(
                            distPtr,
                            distLen,
                            seedBase,
                            UInt(seedCount),
                            privBase,
                            UInt(privateCapacity),
                            pubBase,
                            UInt(publicCapacity)
                        )
                    }
                }
            }
        }
        guard status == 0 else { return nil }
        return (Data(privateKey), Data(publicKey))
        #else
        return nil
        #endif
    }

    func sm2Sign(distid: String?, privateKey: Data, message: Data) -> Data? {
        #if canImport(Darwin)
        guard let sm2SignFn,
              privateKey.count == 32 else { return nil }
        var signature = [UInt8](repeating: 0, count: 64)
        let distData = distid?.data(using: .utf8)
        let privateCapacity = privateKey.count
        let messageCount = message.count
        let signatureCapacity = signature.count
        let status = withOptionalCStringData(distData) { distPtr, distLen in
            privateKey.withUnsafeBytes { privBuffer -> Int32 in
                guard let privBase = privBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return message.withUnsafeBytes { msgBuffer -> Int32 in
                    guard let msgBase = msgBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                    return signature.withUnsafeMutableBytes { sigBuffer -> Int32 in
                        guard let sigBase = sigBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                        return sm2SignFn(
                            distPtr,
                            distLen,
                            privBase,
                            UInt(privateCapacity),
                            msgBase,
                            UInt(messageCount),
                            sigBase,
                            UInt(signatureCapacity)
                        )
                    }
                }
            }
        }
        guard status == 0 else { return nil }
        return Data(signature)
        #else
        return nil
        #endif
    }

    func sm2Verify(distid: String?, publicKey: Data, message: Data, signature: Data) -> Bool? {
        #if canImport(Darwin)
        guard let sm2VerifyFn,
              publicKey.count == 65,
              signature.count == 64 else { return nil }
        let distData = distid?.data(using: .utf8)
        let publicCapacity = publicKey.count
        let messageCount = message.count
        let signatureCount = signature.count
        let status = withOptionalCStringData(distData) { distPtr, distLen in
            publicKey.withUnsafeBytes { pubBuffer -> Int32 in
                guard let pubBase = pubBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return message.withUnsafeBytes { msgBuffer -> Int32 in
                    guard let msgBase = msgBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                    return signature.withUnsafeBytes { sigBuffer -> Int32 in
                        guard let sigBase = sigBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                        return sm2VerifyFn(
                            distPtr,
                            distLen,
                            pubBase,
                            UInt(publicCapacity),
                            msgBase,
                            UInt(messageCount),
                            sigBase,
                            UInt(signatureCount)
                        )
                    }
                }
            }
        }
        if status < 0 {
            return nil
        }
        return status == 1
        #else
        return nil
        #endif
    }

    func sm2PublicKeyPrefixed(distid: String?, publicKey: Data) -> String? {
        #if canImport(Darwin)
        guard let sm2PublicKeyPrefixedFn,
              let freeFn,
              publicKey.count == 65 else { return nil }
        let distData = distid?.data(using: .utf8)
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: UInt = 0
        let status = withOptionalCStringData(distData) { distPtr, distLen in
            publicKey.withUnsafeBytes { pubBuffer -> Int32 in
                guard let pubBase = pubBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return sm2PublicKeyPrefixedFn(
                    distPtr,
                    distLen,
                    pubBase,
                    UInt(publicKey.count),
                    &outPtr,
                    &outLen
                )
            }
        }
        guard status == 0, let ptr = outPtr else { return nil }
        let data = Data(bytes: ptr, count: Int(outLen))
        freeFn(ptr)
        return String(data: data, encoding: .utf8)
        #else
        return nil
        #endif
    }

    func sm2PublicKeyMultihash(distid: String?, publicKey: Data) -> String? {
        #if canImport(Darwin)
        guard let sm2PublicKeyMultihashFn,
              let freeFn,
              publicKey.count == 65 else { return nil }
        let distData = distid?.data(using: .utf8)
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: UInt = 0
        let status = withOptionalCStringData(distData) { distPtr, distLen in
            publicKey.withUnsafeBytes { pubBuffer -> Int32 in
                guard let pubBase = pubBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return sm2PublicKeyMultihashFn(
                    distPtr,
                    distLen,
                    pubBase,
                    UInt(publicKey.count),
                    &outPtr,
                    &outLen
                )
            }
        }
        guard status == 0, let ptr = outPtr else { return nil }
        let data = Data(bytes: ptr, count: Int(outLen))
        freeFn(ptr)
        return String(data: data, encoding: .utf8)
        #else
        return nil
        #endif
    }

    func sm2ComputeZa(distid: String?, publicKey: Data) -> Data? {
        #if canImport(Darwin)
        guard let sm2ComputeZaFn,
              publicKey.count == 65 else { return nil }
        var za = [UInt8](repeating: 0, count: 32)
        let distData = distid?.data(using: .utf8)
        let publicCapacity = publicKey.count
        let zaCapacity = za.count
        let status = withOptionalCStringData(distData) { distPtr, distLen in
            publicKey.withUnsafeBytes { pubBuffer -> Int32 in
                guard let pubBase = pubBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return za.withUnsafeMutableBytes { zaBuffer -> Int32 in
                    guard let zaBase = zaBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                    return sm2ComputeZaFn(
                        distPtr,
                        distLen,
                        pubBase,
                        UInt(publicCapacity),
                        zaBase,
                        UInt(zaCapacity)
                    )
                }
            }
        }
        guard status == 0 else { return nil }
        return Data(za)
        #else
        return nil
        #endif
    }

    func secp256k1PublicKey(privateKey: Data) -> Data? {
        #if canImport(Darwin)
        guard let secp256k1PublicKeyFn,
              privateKey.count == 32 else { return nil }
        var publicKey = [UInt8](repeating: 0, count: 33)
        let privateCapacity = privateKey.count
        let publicCount = publicKey.count
        let status = privateKey.withUnsafeBytes { privBuffer -> Int32 in
            guard let privBase = privBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return publicKey.withUnsafeMutableBytes { pubBuffer -> Int32 in
                guard let pubBase = pubBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return secp256k1PublicKeyFn(
                    privBase,
                    UInt(privateCapacity),
                    pubBase,
                    UInt(publicCount)
                )
            }
        }
        guard status == 0 else { return nil }
        return Data(publicKey)
        #else
        return nil
        #endif
    }

    func secp256k1Sign(privateKey: Data, message: Data) -> Data? {
        #if canImport(Darwin)
        guard let secp256k1SignFn,
              privateKey.count == 32 else { return nil }
        var signature = [UInt8](repeating: 0, count: 64)
        let privateCapacity = privateKey.count
        let messageCount = message.count
        let signatureCount = signature.count
        let status = privateKey.withUnsafeBytes { privBuffer -> Int32 in
            guard let privBase = privBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return message.withUnsafeBytes { msgBuffer -> Int32 in
                guard let msgBase = msgBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return signature.withUnsafeMutableBytes { sigBuffer -> Int32 in
                    guard let sigBase = sigBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                    return secp256k1SignFn(
                        privBase,
                        UInt(privateCapacity),
                        msgBase,
                        UInt(messageCount),
                        sigBase,
                        UInt(signatureCount)
                    )
                }
            }
        }
        guard status == 0 else { return nil }
        return Data(signature)
        #else
        return nil
        #endif
    }

    func secp256k1Verify(publicKey: Data, message: Data, signature: Data) -> Bool? {
        #if canImport(Darwin)
        guard let secp256k1VerifyFn,
              publicKey.count == 33,
              signature.count == 64 else { return nil }
        let publicCapacity = publicKey.count
        let messageCount = message.count
        let signatureCount = signature.count
        let status = publicKey.withUnsafeBytes { pubBuffer -> Int32 in
            guard let pubBase = pubBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return message.withUnsafeBytes { msgBuffer -> Int32 in
                guard let msgBase = msgBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return signature.withUnsafeBytes { sigBuffer -> Int32 in
                    guard let sigBase = sigBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                    return secp256k1VerifyFn(
                        pubBase,
                        UInt(publicCapacity),
                        msgBase,
                        UInt(messageCount),
                        sigBase,
                        UInt(signatureCount),
                        nil,
                        0
                    )
                }
            }
        }
        if status < 0 {
            return nil
        }
        return status == 1
        #else
        return nil
        #endif
    }

    var secp256k1Supported: Bool {
        #if canImport(Darwin)
        let generic = publicKeyFromPrivateFn != nil
            && signDetachedFn != nil
            && verifyDetachedFn != nil
        let dedicated = secp256k1PublicKeyFn != nil
            && secp256k1SignFn != nil
            && secp256k1VerifyFn != nil
        return generic || dedicated
        #else
        return false
        #endif
    }

    var mldsaSupported: Bool {
        #if canImport(Darwin)
        return mldsaParametersFn != nil
            && mldsaGenerateKeypairFn != nil
            && mldsaSignFn != nil
            && mldsaVerifyFn != nil
        #else
        return false
        #endif
    }

    func mldsaParameters(suiteId: UInt8) -> (publicKeyLength: Int, secretKeyLength: Int, signatureLength: Int)? {
        #if canImport(Darwin)
        guard let mldsaParametersFn else { return nil }
        var publicLen: UInt32 = 0
        var secretLen: UInt32 = 0
        var signatureLen: UInt32 = 0
        let status = mldsaParametersFn(UInt32(suiteId), &publicLen, &secretLen, &signatureLen)
        guard status == 0 else { return nil }
        return (Int(publicLen), Int(secretLen), Int(signatureLen))
        #else
        return nil
        #endif
    }

    func mldsaGenerateKeypair(suiteId: UInt8, publicKeyLength: Int, secretKeyLength: Int) -> (publicKey: Data, secretKey: Data)? {
        #if canImport(Darwin)
        guard let mldsaGenerateKeypairFn else { return nil }
        var publicKey = Data(repeating: 0, count: publicKeyLength)
        var secretKey = Data(repeating: 0, count: secretKeyLength)
        let status = publicKey.withUnsafeMutableBytes { pubBuffer -> Int32 in
            guard let pubBase = pubBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return secretKey.withUnsafeMutableBytes { secBuffer -> Int32 in
                guard let secBase = secBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return mldsaGenerateKeypairFn(
                    UInt32(suiteId),
                    pubBase,
                    UInt(publicKeyLength),
                    secBase,
                    UInt(secretKeyLength)
                )
            }
        }
        guard status == 0 else { return nil }
        return (publicKey, secretKey)
        #else
        return nil
        #endif
    }

    func mldsaSign(suiteId: UInt8, secretKey: Data, message: Data, signatureLength: Int) -> Data? {
        #if canImport(Darwin)
        guard let mldsaSignFn else { return nil }
        var signature = Data(repeating: 0, count: signatureLength)
        let status = secretKey.withUnsafeBytes { skBuffer -> Int32 in
            guard let skBase = skBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return message.withUnsafeBytes { msgBuffer -> Int32 in
                guard let msgBase = msgBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return signature.withUnsafeMutableBytes { sigBuffer -> Int32 in
                    guard let sigBase = sigBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                    return mldsaSignFn(
                        UInt32(suiteId),
                        skBase,
                        UInt(secretKey.count),
                        msgBase,
                        UInt(message.count),
                        sigBase,
                        UInt(signatureLength)
                    )
                }
            }
        }
        guard status == 0 else { return nil }
        return signature
        #else
        return nil
        #endif
    }

    func mldsaVerify(suiteId: UInt8, publicKey: Data, message: Data, signature: Data) -> Bool? {
        #if canImport(Darwin)
        if let detachedResult = verifyDetached(
            algorithm: .mlDsa,
            publicKey: publicKey,
            message: message,
            signature: signature
        ) {
            return detachedResult
        }
        guard let mldsaVerifyFn else { return nil }
        let status = publicKey.withUnsafeBytes { pkBuffer -> Int32 in
            guard let pkBase = pkBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return message.withUnsafeBytes { msgBuffer -> Int32 in
                guard let msgBase = msgBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return signature.withUnsafeBytes { sigBuffer -> Int32 in
                    guard let sigBase = sigBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                    return mldsaVerifyFn(
                        UInt32(suiteId),
                        pkBase,
                        UInt(publicKey.count),
                        msgBase,
                        UInt(message.count),
                        sigBase,
                        UInt(signature.count)
                    )
                }
            }
        }
        if status < 0 {
            return nil
        }
        return status == 0
        #else
        return nil
        #endif
    }

    func connectGenerateKeypair() -> (publicKey: Data, privateKey: Data)? {
        #if canImport(Darwin)
        guard let connectGenerateKeypairFn else { return nil }
        var publicKey = [UInt8](repeating: 0, count: 32)
        var privateKey = [UInt8](repeating: 0, count: 32)
        let status = publicKey.withUnsafeMutableBytes { pkBuffer -> Int32 in
            guard let pkBase = pkBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return privateKey.withUnsafeMutableBytes { skBuffer -> Int32 in
                guard let skBase = skBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return connectGenerateKeypairFn(pkBase, skBase)
            }
        }
        guard status == 0 else { return nil }
        return (Data(publicKey), Data(privateKey))
        #else
        return nil
        #endif
    }

    func connectPublicFromPrivate(_ privateKey: Data) -> Data? {
        #if canImport(Darwin)
        guard let connectPublicFromPrivateFn,
              privateKey.count == 32 else { return nil }
        var publicKey = [UInt8](repeating: 0, count: 32)
        let status = publicKey.withUnsafeMutableBytes { pkBuffer -> Int32 in
            guard let pkBase = pkBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return privateKey.withUnsafeBytes { skBuffer -> Int32 in
                guard let skBase = skBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return connectPublicFromPrivateFn(skBase, pkBase)
            }
        }
        guard status == 0 else { return nil }
        return Data(publicKey)
        #else
        return nil
        #endif
    }

    func connectDeriveKeys(privateKey: Data, peerPublicKey: Data, sessionID: Data) -> (appKey: Data, walletKey: Data)? {
        #if canImport(Darwin)
        guard let connectDeriveKeysFn,
              privateKey.count == 32,
              peerPublicKey.count == 32,
              sessionID.count == 32 else { return nil }
        var appKey = [UInt8](repeating: 0, count: 32)
        var walletKey = [UInt8](repeating: 0, count: 32)
        let status = privateKey.withUnsafeBytes { skBuffer -> Int32 in
            guard let skBase = skBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return peerPublicKey.withUnsafeBytes { pkBuffer -> Int32 in
                guard let pkBase = pkBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return sessionID.withUnsafeBytes { sidBuffer -> Int32 in
                    guard let sidBase = sidBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                    return appKey.withUnsafeMutableBytes { appBuffer -> Int32 in
                        guard let appBase = appBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                        return walletKey.withUnsafeMutableBytes { walBuffer -> Int32 in
                            guard let walBase = walBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                            return connectDeriveKeysFn(skBase, pkBase, sidBase, appBase, walBase)
                        }
                    }
                }
            }
        }
        guard status == 0 else { return nil }
        return (Data(appKey), Data(walletKey))
        #else
        return nil
        #endif
    }

    func connectEncryptEnvelope(key: Data, sessionID: Data, direction: ConnectDirection, envelope: Data) -> Data? {
        #if canImport(Darwin)
        guard let connectEncryptEnvelopeFn,
              let freeFn,
              key.count == 32,
              sessionID.count == 32 else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: UInt = 0
        let dirRaw: UInt8 = direction == .appToWallet ? 0 : 1
        let status = key.withUnsafeBytes { keyBuffer -> Int32 in
            guard let keyBase = keyBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return sessionID.withUnsafeBytes { sidBuffer -> Int32 in
                guard let sidBase = sidBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return envelope.withUnsafeBytes { envBuffer -> Int32 in
                    let envBase = envBuffer.bindMemory(to: UInt8.self).baseAddress
                    return connectEncryptEnvelopeFn(
                        keyBase,
                        sidBase,
                        dirRaw,
                        envBase,
                        UInt(envelope.count),
                        &outPtr,
                        &outLen
                    )
                }
            }
        }
        guard status == 0, let outPtr else {
            if status == 0, let outPtr { freeFn(outPtr) }
            return nil
        }
        return takeData(pointer: outPtr, length: outLen)
        #else
        return nil
        #endif
    }

    func connectDecryptCiphertext(key: Data, frame: Data) -> Data? {
        #if canImport(Darwin)
        guard let connectDecryptCiphertextFn,
              let freeFn,
              key.count == 32 else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: UInt = 0
        let status = key.withUnsafeBytes { keyBuffer -> Int32 in
            guard let keyBase = keyBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return frame.withUnsafeBytes { frameBuffer -> Int32 in
                guard let frameBase = frameBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return connectDecryptCiphertextFn(
                    keyBase,
                    frameBase,
                    UInt(frame.count),
                    &outPtr,
                    &outLen
                )
            }
        }
        guard status == 0, let outPtr else {
            if status == 0, let outPtr { freeFn(outPtr) }
            return nil
        }
        return takeData(pointer: outPtr, length: outLen)
        #else
        return nil
        #endif
    }

    func encodeEnvelopeSignRequestTx(sequence: UInt64, txBytes: Data) -> Data? {
        #if canImport(Darwin)
        guard let encodeEnvelopeSignRequestTxFn,
              let freeFn else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: UInt = 0
        let status = txBytes.withUnsafeBytes { txBuffer -> Int32 in
            let txBase = txBuffer.bindMemory(to: UInt8.self).baseAddress
            return encodeEnvelopeSignRequestTxFn(
                sequence,
                txBase,
                UInt(txBytes.count),
                &outPtr,
                &outLen
            )
        }
        guard status == 0, let outPtr else {
            if status == 0, let outPtr { freeFn(outPtr) }
            return nil
        }
        return takeData(pointer: outPtr, length: outLen)
        #else
        return nil
        #endif
    }

    func encodeEnvelopeSignRequestRaw(sequence: UInt64, domainTag: String, bytes: Data) -> Data? {
        #if canImport(Darwin)
        guard let encodeEnvelopeSignRequestRawFn,
              let freeFn else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: UInt = 0
        let tagData = Data(domainTag.utf8)
        let status = tagData.withUnsafeBytes { tagBuffer -> Int32 in
            let tagBase = tagBuffer.bindMemory(to: UInt8.self).baseAddress
            return bytes.withUnsafeBytes { bytesBuffer -> Int32 in
                let bytesBase = bytesBuffer.bindMemory(to: UInt8.self).baseAddress
                return encodeEnvelopeSignRequestRawFn(
                    sequence,
                    tagBase,
                    UInt(tagData.count),
                    bytesBase,
                    UInt(bytes.count),
                    &outPtr,
                    &outLen
                )
            }
        }
        guard status == 0, let outPtr else {
            if status == 0, let outPtr { freeFn(outPtr) }
            return nil
        }
        return takeData(pointer: outPtr, length: outLen)
        #else
        return nil
        #endif
    }

    func encodeEnvelopeSignResultOk(sequence: UInt64, algorithm: String?, signature: Data) -> Data? {
        #if canImport(Darwin)
        guard signature.count > 0 else { return nil }
        guard let freeFn else { return nil }
        let normalizedAlgorithm: String?
        if let algorithm {
            guard let normalized = ConnectWalletSignatureAlgorithm.normalize(algorithm) else { return nil }
            normalizedAlgorithm = normalized
        } else {
            normalizedAlgorithm = nil
        }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: UInt = 0
        let status: Int32
        if let normalizedAlgorithm,
           let encodeEnvelopeSignResultOkWithAlgFn {
            status = normalizedAlgorithm.withCString { algPtr in
                signature.withUnsafeBytes { sigBuffer -> Int32 in
                    guard let sigBase = sigBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                    return encodeEnvelopeSignResultOkWithAlgFn(
                        sequence,
                        algPtr,
                        UInt(normalizedAlgorithm.utf8.count),
                        sigBase,
                        UInt(signature.count),
                        &outPtr,
                        &outLen
                    )
                }
            }
        } else if let encodeEnvelopeSignResultOkFn {
            status = signature.withUnsafeBytes { sigBuffer -> Int32 in
                guard let sigBase = sigBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return encodeEnvelopeSignResultOkFn(
                    sequence,
                    sigBase,
                    UInt(signature.count),
                    &outPtr,
                    &outLen
                )
            }
        } else {
            return nil
        }
        guard status == 0, let outPtr else {
            if status == 0, let outPtr { freeFn(outPtr) }
            return nil
        }
        return takeData(pointer: outPtr, length: outLen)
        #else
        return nil
        #endif
    }

    func encodeEnvelopeSignResultErr(sequence: UInt64, code: String, message: String) -> Data? {
        #if canImport(Darwin)
        guard let encodeEnvelopeSignResultErrFn,
              let freeFn else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: UInt = 0
        let codeData = Data(code.utf8)
        let messageData = Data(message.utf8)
        let status = codeData.withUnsafeBytes { codeBuffer -> Int32 in
            let codeBase = codeBuffer.bindMemory(to: UInt8.self).baseAddress
            return messageData.withUnsafeBytes { msgBuffer -> Int32 in
                let msgBase = msgBuffer.bindMemory(to: UInt8.self).baseAddress
                return encodeEnvelopeSignResultErrFn(
                    sequence,
                    codeBase,
                    UInt(codeData.count),
                    msgBase,
                    UInt(messageData.count),
                    &outPtr,
                    &outLen
                )
            }
        }
        guard status == 0, let outPtr else {
            if status == 0, let outPtr { freeFn(outPtr) }
            return nil
        }
        return takeData(pointer: outPtr, length: outLen)
        #else
        return nil
        #endif
    }

    func encodeEnvelopeControlClose(sequence: UInt64,
                                    who: ConnectRole,
                                    code: UInt16,
                                    reason: String?,
                                    retryable: Bool) -> Data? {
        #if canImport(Darwin)
        guard let encodeEnvelopeControlCloseFn,
              let freeFn else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: UInt = 0
        let whoRaw: UInt8 = who == .app ? 0 : 1
        let retryRaw: UInt8 = retryable ? 1 : 0
        let status: Int32
        if let reason {
            let reasonData = Data(reason.utf8)
            status = reasonData.withUnsafeBytes { reasonBuffer -> Int32 in
                let reasonBase = reasonBuffer.bindMemory(to: UInt8.self).baseAddress
                return encodeEnvelopeControlCloseFn(
                    sequence,
                    whoRaw,
                    code,
                    reasonBase,
                    UInt(reasonData.count),
                    retryRaw,
                    &outPtr,
                    &outLen
                )
            }
        } else {
            status = encodeEnvelopeControlCloseFn(
                sequence,
                whoRaw,
                code,
                nil,
                0,
                retryRaw,
                &outPtr,
                &outLen
            )
        }
        guard status == 0, let outPtr else {
            if status == 0, let outPtr { freeFn(outPtr) }
            return nil
        }
        return takeData(pointer: outPtr, length: outLen)
        #else
        return nil
        #endif
    }

    func encodeEnvelopeControlReject(sequence: UInt64,
                                     code: UInt16,
                                     codeID: String,
                                     reason: String) -> Data? {
        #if canImport(Darwin)
        guard let encodeEnvelopeControlRejectFn,
              let freeFn else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: UInt = 0
        let codeData = Data(codeID.utf8)
        let reasonData = Data(reason.utf8)
        let status = codeData.withUnsafeBytes { codeBuffer -> Int32 in
            let codeBase = codeBuffer.bindMemory(to: UInt8.self).baseAddress
            return reasonData.withUnsafeBytes { reasonBuffer -> Int32 in
                let reasonBase = reasonBuffer.bindMemory(to: UInt8.self).baseAddress
                return encodeEnvelopeControlRejectFn(
                    sequence,
                    code,
                    codeBase,
                    UInt(codeData.count),
                    reasonBase,
                    UInt(reasonData.count),
                    &outPtr,
                    &outLen
                )
            }
        }
        guard status == 0, let outPtr else {
            if status == 0, let outPtr { freeFn(outPtr) }
            return nil
        }
        return takeData(pointer: outPtr, length: outLen)
        #else
        return nil
        #endif
    }

    func encodeConfidentialPayload(ephemeralPublicKey: Data,
                                   nonce: Data,
                                   ciphertext: Data) -> Data? {
        #if canImport(Darwin)
        guard let encodeConfidentialPayloadFn, let freeFn else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: UInt = 0
        let status = ephemeralPublicKey.withUnsafeBytes { ep in
            nonce.withUnsafeBytes { np in
                ciphertext.withUnsafeBytes { cp in
                    encodeConfidentialPayloadFn(
                        ep.bindMemory(to: UInt8.self).baseAddress, UInt(ep.count),
                        np.bindMemory(to: UInt8.self).baseAddress, UInt(nonce.count),
                        cp.bindMemory(to: UInt8.self).baseAddress, UInt(ciphertext.count),
                        &outPtr,
                        &outLen
                    )
                }
            }
        }
        guard status == 0, let outPtr else {
            if status == 0, let outPtr { freeFn(outPtr) }
            return nil
        }
        return takeData(pointer: outPtr, length: outLen)
        #else
        return nil
        #endif
    }

    func decodeEnvelopeKind(_ data: Data) -> (sequence: UInt64, kind: UInt16)? {
        #if canImport(Darwin)
        guard let decodeEnvelopeKindFn else { return nil }
        var sequence: UInt64 = 0
        var kind: UInt16 = 0
        let status = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return decodeEnvelopeKindFn(base, UInt(data.count), &sequence, &kind)
        }
        guard status == 0 else { return nil }
        return (sequence, kind)
        #else
        return nil
        #endif
    }

    func decodeEnvelopeJSON(_ data: Data) -> Data? {
        #if canImport(Darwin)
        guard let decodeEnvelopeJSONFn,
              let freeFn else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: UInt = 0
        let status = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return decodeEnvelopeJSONFn(base, UInt(data.count), &outPtr, &outLen)
        }
        guard status == 0, let outPtr else {
            if status == 0, let outPtr { freeFn(outPtr) }
            return nil
        }
        return takeData(pointer: outPtr, length: outLen)
        #else
        return nil
        #endif
    }

    func sorafsLocalFetch(planJSON: String,
                          providersJSON: String,
                          optionsJSON: String?) -> SorafsLocalFetchOutput? {
        #if canImport(Darwin)
        guard let sorafsLocalFetchFn else { return nil }

        guard let planData = planJSON.data(using: .utf8),
              let providersData = providersJSON.data(using: .utf8) else {
            return nil
        }
        let optionsData = optionsJSON?.data(using: .utf8) ?? Data()

        var outPayloadPtr: UnsafeMutablePointer<UInt8>? = nil
        var outPayloadLen: CUnsignedLong = 0
        var outReportPtr: UnsafeMutablePointer<UInt8>? = nil
        var outReportLen: CUnsignedLong = 0

        var status: Int32 = 0
        planData.withUnsafeBytes { planBuffer in
            providersData.withUnsafeBytes { providerBuffer in
                optionsData.withUnsafeBytes { optionsBuffer in
                    status = sorafsLocalFetchFn(
                        planBuffer.bindMemory(to: CChar.self).baseAddress,
                        CUnsignedLong(planBuffer.count),
                        providerBuffer.bindMemory(to: CChar.self).baseAddress,
                        CUnsignedLong(providerBuffer.count),
                        optionsBuffer.bindMemory(to: CChar.self).baseAddress,
                        CUnsignedLong(optionsBuffer.count),
                        &outPayloadPtr,
                        &outPayloadLen,
                        &outReportPtr,
                        &outReportLen
                    )
                }
            }
        }

        if status != 0 {
            if let ptr = outPayloadPtr {
                if let freeFn {
                    freeFn(ptr)
                } else {
                    Darwin.free(ptr)
                }
            }
            if let ptr = outReportPtr {
                if let freeFn {
                    freeFn(ptr)
                } else {
                    Darwin.free(ptr)
                }
            }
            return nil
        }

        guard let payload = takeData(pointer: outPayloadPtr, length: UInt(outPayloadLen)),
              let report = takeString(pointer: outReportPtr, length: UInt(outReportLen)) else {
            return nil
        }

        return SorafsLocalFetchOutput(payload: payload, reportJSON: report)
        #else
        return nil
        #endif
    }

    func sorafsReferenceValidateOrderbook(kind: UInt32,
                                          payload: Data,
                                          label: String,
                                          generatedAtUnix: UInt64) -> String? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceValidateOrderbookFn,
              let labelData = label.data(using: .utf8) else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = withDataPointer(payload) { payloadPtr, payloadLen in
            withDataPointer(labelData) { labelPtr, labelLen in
                function(kind, payloadPtr, payloadLen, labelPtr, labelLen, generatedAtUnix, &outPtr, &outLen)
            }
        }
        guard status == 0 else {
            if let outPtr {
                if let freeFn { freeFn(outPtr) } else { Darwin.free(outPtr) }
            }
            return nil
        }
        return takeString(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    func sorafsReferenceValidatePopPayload(kind: UInt32,
                                           payload: Data,
                                           label: String,
                                           generatedAtUnix: UInt64) -> String? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceValidatePopPayloadFn,
              let labelData = label.data(using: .utf8) else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = withDataPointer(payload) { payloadPtr, payloadLen in
            withDataPointer(labelData) { labelPtr, labelLen in
                function(kind, payloadPtr, payloadLen, labelPtr, labelLen, generatedAtUnix, &outPtr, &outLen)
            }
        }
        guard status == 0 else {
            if let outPtr {
                if let freeFn { freeFn(outPtr) } else { Darwin.free(outPtr) }
            }
            return nil
        }
        return takeString(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    func sorafsReferenceValidateHedgingPayload(kind: UInt32,
                                               payload: Data,
                                               label: String,
                                               generatedAtUnix: UInt64) -> String? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceValidateHedgingPayloadFn,
              let labelData = label.data(using: .utf8) else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = withDataPointer(payload) { payloadPtr, payloadLen in
            withDataPointer(labelData) { labelPtr, labelLen in
                function(kind, payloadPtr, payloadLen, labelPtr, labelLen, generatedAtUnix, &outPtr, &outLen)
            }
        }
        guard status == 0 else {
            if let outPtr {
                if let freeFn { freeFn(outPtr) } else { Darwin.free(outPtr) }
            }
            return nil
        }
        return takeString(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    func sorafsReferenceValidateAppealFinanceCancelAssetLock(
        payload: Data,
        label: String,
        generatedAtUnix: UInt64
    ) -> String? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceValidateAppealFinanceCancelAssetLockFn,
              let labelData = label.data(using: .utf8) else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = withDataPointer(payload) { payloadPtr, payloadLen in
            withDataPointer(labelData) { labelPtr, labelLen in
                function(
                    payloadPtr,
                    payloadLen,
                    labelPtr,
                    labelLen,
                    generatedAtUnix,
                    &outPtr,
                    &outLen
                )
            }
        }
        guard status == 0 else {
            if let outPtr {
                if let freeFn { freeFn(outPtr) } else { Darwin.free(outPtr) }
            }
            return nil
        }
        return takeString(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    func sorafsReferenceValidateFixtureBundle(
        payloads: [(kind: UInt32, payload: Data, label: String)],
        nowUnix: UInt64,
        generatedAtUnix: UInt64
    ) -> String? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceValidateFixtureBundleFn else { return nil }
        let payloadBytes = payloads.map(\.payload)
        let labels = payloads.map { Data($0.label.utf8) }
        let kinds = payloads.map(\.kind)
        var descriptors: [NativeSorafsReferenceBundleInput] = []
        descriptors.reserveCapacity(payloads.count)
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = withSorafsReferenceBundleInputs(
            kinds: kinds,
            payloads: payloadBytes,
            labels: labels,
            index: 0,
            descriptors: &descriptors
        ) { descriptorsPtr, descriptorsLen in
            function(
                descriptorsPtr,
                descriptorsLen,
                nowUnix,
                generatedAtUnix,
                &outPtr,
                &outLen
            )
        }
        guard status == 0 else {
            if let outPtr {
                if let freeFn { freeFn(outPtr) } else { Darwin.free(outPtr) }
            }
            return nil
        }
        return takeString(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    func sorafsReferenceValidateGovernanceLogNode(
        payload: Data,
        label: String,
        expectedNodeCid: Data,
        generatedAtUnix: UInt64
    ) -> String? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceValidateGovernanceLogNodeFn,
              let labelData = label.data(using: .utf8) else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = withDataPointer(payload) { payloadPtr, payloadLen in
            withDataPointer(labelData) { labelPtr, labelLen in
                withDataPointer(expectedNodeCid) { expectedCidPtr, expectedCidLen in
                    function(
                        payloadPtr,
                        payloadLen,
                        labelPtr,
                        labelLen,
                        expectedCidPtr,
                        expectedCidLen,
                        generatedAtUnix,
                        &outPtr,
                        &outLen
                    )
                }
            }
        }
        guard status == 0 else {
            if let outPtr {
                if let freeFn { freeFn(outPtr) } else { Darwin.free(outPtr) }
            }
            return nil
        }
        return takeString(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    func sorafsReferenceValidateGovernanceDagBlock(
        payload: Data,
        label: String,
        expectedBlockCid: Data?,
        generatedAtUnix: UInt64
    ) -> String? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceValidateGovernanceDagBlockFn,
              let labelData = label.data(using: .utf8) else { return nil }
        let expectedCid = expectedBlockCid ?? Data()
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = withDataPointer(payload) { payloadPtr, payloadLen in
            withDataPointer(labelData) { labelPtr, labelLen in
                withDataPointer(expectedCid) { expectedCidPtr, expectedCidLen in
                    function(
                        payloadPtr,
                        payloadLen,
                        labelPtr,
                        labelLen,
                        expectedCidPtr,
                        expectedCidLen,
                        generatedAtUnix,
                        &outPtr,
                        &outLen
                    )
                }
            }
        }
        guard status == 0 else {
            if let outPtr {
                if let freeFn { freeFn(outPtr) } else { Darwin.free(outPtr) }
            }
            return nil
        }
        return takeString(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    func sorafsReferenceValidateGovernanceDagHeadChain(
        head: Data,
        headLabel: String,
        blocks: [(payload: Data, label: String)],
        generatedAtUnix: UInt64
    ) -> String? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceValidateGovernanceDagHeadChainFn,
              let headLabelData = headLabel.data(using: .utf8) else { return nil }
        let blockPayloads = blocks.map(\.payload)
        let blockLabels = blocks.map { Data($0.label.utf8) }
        var descriptors: [NativeSorafsReferenceInput] = []
        descriptors.reserveCapacity(blocks.count)
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = withDataPointer(head) { headPtr, headLen in
            withDataPointer(headLabelData) { headLabelPtr, headLabelLen in
                withSorafsReferenceInputs(
                    payloads: blockPayloads,
                    labels: blockLabels,
                    index: 0,
                    descriptors: &descriptors
                ) { descriptorsPtr, descriptorsLen in
                    function(
                        headPtr,
                        headLen,
                        headLabelPtr,
                        headLabelLen,
                        descriptorsPtr,
                        descriptorsLen,
                        generatedAtUnix,
                        &outPtr,
                        &outLen
                    )
                }
            }
        }
        guard status == 0 else {
            if let outPtr {
                if let freeFn { freeFn(outPtr) } else { Darwin.free(outPtr) }
            }
            return nil
        }
        return takeString(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    #if canImport(Darwin)
    private func withSorafsReferenceInputs<Result>(
        payloads: [Data],
        labels: [Data],
        index: Int,
        descriptors: inout [NativeSorafsReferenceInput],
        body: (UnsafeRawPointer?, CUnsignedLong) -> Result
    ) -> Result {
        precondition(payloads.count == labels.count)
        guard index < payloads.count else {
            guard !descriptors.isEmpty else {
                return body(nil, 0)
            }
            let wordSize = MemoryLayout<UInt>.size
            let descriptorSize = wordSize * 4
            let rawDescriptors = UnsafeMutableRawPointer.allocate(
                byteCount: descriptorSize * descriptors.count,
                alignment: MemoryLayout<UInt>.alignment
            )
            defer { rawDescriptors.deallocate() }
            for (descriptorIndex, descriptor) in descriptors.enumerated() {
                let base = rawDescriptors.advanced(by: descriptorIndex * descriptorSize)
                base.storeBytes(
                    of: descriptor.bytesPointer.map { UInt(bitPattern: $0) } ?? 0,
                    as: UInt.self
                )
                base.advanced(by: wordSize).storeBytes(
                    of: UInt(descriptor.bytesLength),
                    as: UInt.self
                )
                base.advanced(by: wordSize * 2).storeBytes(
                    of: descriptor.labelPointer.map { UInt(bitPattern: $0) } ?? 0,
                    as: UInt.self
                )
                base.advanced(by: wordSize * 3).storeBytes(
                    of: UInt(descriptor.labelLength),
                    as: UInt.self
                )
            }
            return body(UnsafeRawPointer(rawDescriptors), CUnsignedLong(descriptors.count))
        }
        return withDataPointer(payloads[index]) { payloadPtr, payloadLen in
            withDataPointer(labels[index]) { labelPtr, labelLen in
                descriptors.append(
                    NativeSorafsReferenceInput(
                        bytesPointer: payloadPtr,
                        bytesLength: payloadLen,
                        labelPointer: labelPtr,
                        labelLength: labelLen
                    )
                )
                defer { descriptors.removeLast() }
                return withSorafsReferenceInputs(
                    payloads: payloads,
                    labels: labels,
                    index: index + 1,
                    descriptors: &descriptors,
                    body: body
                )
            }
        }
    }

    private func withSorafsReferenceBundleInputs<Result>(
        kinds: [UInt32],
        payloads: [Data],
        labels: [Data],
        index: Int,
        descriptors: inout [NativeSorafsReferenceBundleInput],
        body: (UnsafeRawPointer?, CUnsignedLong) -> Result
    ) -> Result {
        precondition(kinds.count == payloads.count && payloads.count == labels.count)
        guard index < payloads.count else {
            guard !descriptors.isEmpty else {
                return body(nil, 0)
            }
            let wordSize = MemoryLayout<UInt>.size
            let pointerOffset = (MemoryLayout<UInt32>.size + wordSize - 1) & ~(wordSize - 1)
            let descriptorSize = pointerOffset + wordSize * 4
            let rawDescriptors = UnsafeMutableRawPointer.allocate(
                byteCount: descriptorSize * descriptors.count,
                alignment: MemoryLayout<UInt>.alignment
            )
            defer { rawDescriptors.deallocate() }
            for (descriptorIndex, descriptor) in descriptors.enumerated() {
                let base = rawDescriptors.advanced(by: descriptorIndex * descriptorSize)
                base.storeBytes(of: descriptor.kind, as: UInt32.self)
                base.advanced(by: pointerOffset).storeBytes(
                    of: descriptor.bytesPointer.map { UInt(bitPattern: $0) } ?? 0,
                    as: UInt.self
                )
                base.advanced(by: pointerOffset + wordSize).storeBytes(
                    of: UInt(descriptor.bytesLength),
                    as: UInt.self
                )
                base.advanced(by: pointerOffset + wordSize * 2).storeBytes(
                    of: descriptor.labelPointer.map { UInt(bitPattern: $0) } ?? 0,
                    as: UInt.self
                )
                base.advanced(by: pointerOffset + wordSize * 3).storeBytes(
                    of: UInt(descriptor.labelLength),
                    as: UInt.self
                )
            }
            return body(UnsafeRawPointer(rawDescriptors), CUnsignedLong(descriptors.count))
        }
        return withDataPointer(payloads[index]) { payloadPtr, payloadLen in
            withDataPointer(labels[index]) { labelPtr, labelLen in
                descriptors.append(
                    NativeSorafsReferenceBundleInput(
                        kind: kinds[index],
                        bytesPointer: payloadPtr,
                        bytesLength: payloadLen,
                        labelPointer: labelPtr,
                        labelLength: labelLen
                    )
                )
                defer { descriptors.removeLast() }
                return withSorafsReferenceBundleInputs(
                    kinds: kinds,
                    payloads: payloads,
                    labels: labels,
                    index: index + 1,
                    descriptors: &descriptors,
                    body: body
                )
            }
        }
    }
    #endif

    func sorafsReferenceSignOrderbook(kind: UInt32,
                                      payload: Data,
                                      privateKey: Data) -> Data? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceSignOrderbookFn else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = withDataPointer(payload) { payloadPtr, payloadLen in
            withDataPointer(privateKey) { keyPtr, keyLen in
                function(kind, payloadPtr, payloadLen, keyPtr, keyLen, &outPtr, &outLen)
            }
        }
        guard status == 0 else {
            if let outPtr {
                if let freeFn { freeFn(outPtr) } else { Darwin.free(outPtr) }
            }
            return nil
        }
        return takeData(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    func sorafsReferenceDeriveOrderbookOrderId(ownerAccount: Data, nonce: UInt64) -> Data? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceDeriveOrderbookOrderIdFn else { return nil }
        var output = Data(count: 32)
        let status = output.withUnsafeMutableBytes { outputBytes in
            let outputPtr = outputBytes.baseAddress?.assumingMemoryBound(to: UInt8.self)
            return withDataPointer(ownerAccount) { ownerPtr, ownerLen in
                function(ownerPtr, ownerLen, nonce, outputPtr, CUnsignedLong(outputBytes.count))
            }
        }
        guard status == 0 else { return nil }
        return output
        #else
        return nil
        #endif
    }

    func sorafsReferenceBuildSignedOrderbookOrderRequest(
        fields: NativeSorafsOrderbookOrderRequestFields,
        privateKey: Data
    ) -> Data? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceBuildOrderbookOrderRequestFn else { return nil }
        guard let priceData = fields.pricePerGib.data(using: .utf8) else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = withDataPointer(fields.orderId) { orderIdPtr, orderIdLen in
            withDataPointer(priceData) { pricePtr, priceLen in
                withDataPointer(fields.ownerAccount) { ownerPtr, ownerLen in
                    withDataPointer(fields.providerId) { providerPtr, providerLen in
                        withDataPointer(privateKey) { keyPtr, keyLen in
                            function(
                                orderIdPtr,
                                orderIdLen,
                                fields.side,
                                fields.tier,
                                pricePtr,
                                priceLen,
                                fields.quantityGib,
                                fields.remainingGib,
                                ownerPtr,
                                ownerLen,
                                providerPtr,
                                providerLen,
                                fields.expiryUnix,
                                fields.nonce,
                                fields.makerFeeBps,
                                fields.takerFeeBps,
                                keyPtr,
                                keyLen,
                                &outPtr,
                                &outLen
                            )
                        }
                    }
                }
            }
        }
        guard status == 0 else {
            if let outPtr {
                if let freeFn { freeFn(outPtr) } else { Darwin.free(outPtr) }
            }
            return nil
        }
        return takeData(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    func sorafsReferenceBuildSignedOrderbookOrderCancel(
        fields: NativeSorafsOrderbookOrderCancelFields,
        privateKey: Data
    ) -> Data? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceBuildOrderbookOrderCancelFn else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = withDataPointer(fields.orderId) { orderIdPtr, orderIdLen in
            withDataPointer(fields.ownerAccount) { ownerPtr, ownerLen in
                withDataPointer(privateKey) { keyPtr, keyLen in
                    function(
                        orderIdPtr,
                        orderIdLen,
                        ownerPtr,
                        ownerLen,
                        fields.reason,
                        fields.nonce,
                        keyPtr,
                        keyLen,
                        &outPtr,
                        &outLen
                    )
                }
            }
        }
        guard status == 0 else {
            if let outPtr {
                if let freeFn { freeFn(outPtr) } else { Darwin.free(outPtr) }
            }
            return nil
        }
        return takeData(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    func sorafsReferenceBuildSignedOrderbookSettlementReceipt(
        fields: NativeSorafsOrderbookSettlementReceiptFields,
        privateKey: Data
    ) -> Data? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceBuildOrderbookSettlementReceiptFn else { return nil }
        guard let debitData = fields.xorDebited.data(using: .utf8),
              let creditData = fields.providerCredit.data(using: .utf8),
              let feeData = fields.feeAmount.data(using: .utf8) else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = withDataPointer(fields.receiptId) { receiptPtr, receiptLen in
            withDataPointer(fields.channelId) { channelPtr, channelLen in
                withDataPointer(fields.tradeId) { tradePtr, tradeLen in
                    withDataPointer(fields.chunkHash) { chunkPtr, chunkLen in
                        withDataPointer(debitData) { debitPtr, debitLen in
                            withDataPointer(creditData) { creditPtr, creditLen in
                                withDataPointer(feeData) { feePtr, feeLen in
                                    withDataPointer(privateKey) { keyPtr, keyLen in
                                        function(
                                            receiptPtr,
                                            receiptLen,
                                            channelPtr,
                                            channelLen,
                                            tradePtr,
                                            tradeLen,
                                            fields.rangeStart,
                                            fields.rangeEnd,
                                            chunkPtr,
                                            chunkLen,
                                            fields.bytesDelivered,
                                            debitPtr,
                                            debitLen,
                                            creditPtr,
                                            creditLen,
                                            feePtr,
                                            feeLen,
                                            fields.issuedAtUnix,
                                            keyPtr,
                                            keyLen,
                                            &outPtr,
                                            &outLen
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        guard status == 0 else {
            if let outPtr {
                if let freeFn { freeFn(outPtr) } else { Darwin.free(outPtr) }
            }
            return nil
        }
        return takeData(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    func sorafsReferenceValidatePdpPayload(kind: UInt32,
                                           payload: Data,
                                           label: String,
                                           generatedAtUnix: UInt64) -> String? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceValidatePdpPayloadFn,
              let labelData = label.data(using: .utf8) else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = withDataPointer(payload) { payloadPtr, payloadLen in
            withDataPointer(labelData) { labelPtr, labelLen in
                function(kind, payloadPtr, payloadLen, labelPtr, labelLen, generatedAtUnix, &outPtr, &outLen)
            }
        }
        guard status == 0 else {
            if let outPtr {
                if let freeFn { freeFn(outPtr) } else { Darwin.free(outPtr) }
            }
            return nil
        }
        return takeString(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    func sorafsReferenceValidatePdpCommitmentChallenge(commitment: Data,
                                                       commitmentLabel: String,
                                                       challenge: Data,
                                                       challengeLabel: String,
                                                       generatedAtUnix: UInt64) -> String? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceValidatePdpCommitmentChallengeFn,
              let commitmentLabelData = commitmentLabel.data(using: .utf8),
              let challengeLabelData = challengeLabel.data(using: .utf8) else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = withDataPointer(commitment) { commitmentPtr, commitmentLen in
            withDataPointer(commitmentLabelData) { commitmentLabelPtr, commitmentLabelLen in
                withDataPointer(challenge) { challengePtr, challengeLen in
                    withDataPointer(challengeLabelData) { challengeLabelPtr, challengeLabelLen in
                        function(
                            commitmentPtr, commitmentLen,
                            commitmentLabelPtr, commitmentLabelLen,
                            challengePtr, challengeLen,
                            challengeLabelPtr, challengeLabelLen,
                            generatedAtUnix,
                            &outPtr, &outLen
                        )
                    }
                }
            }
        }
        guard status == 0 else {
            if let outPtr {
                if let freeFn { freeFn(outPtr) } else { Darwin.free(outPtr) }
            }
            return nil
        }
        return takeString(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    func sorafsReferenceValidatePdpChallengeProof(challenge: Data,
                                                  challengeLabel: String,
                                                  proof: Data,
                                                  proofLabel: String,
                                                  generatedAtUnix: UInt64) -> String? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceValidatePdpChallengeProofFn,
              let challengeLabelData = challengeLabel.data(using: .utf8),
              let proofLabelData = proofLabel.data(using: .utf8) else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = withDataPointer(challenge) { challengePtr, challengeLen in
            withDataPointer(challengeLabelData) { challengeLabelPtr, challengeLabelLen in
                withDataPointer(proof) { proofPtr, proofLen in
                    withDataPointer(proofLabelData) { proofLabelPtr, proofLabelLen in
                        function(
                            challengePtr, challengeLen,
                            challengeLabelPtr, challengeLabelLen,
                            proofPtr, proofLen,
                            proofLabelPtr, proofLabelLen,
                            generatedAtUnix,
                            &outPtr, &outLen
                        )
                    }
                }
            }
        }
        guard status == 0 else {
            if let outPtr {
                if let freeFn { freeFn(outPtr) } else { Darwin.free(outPtr) }
            }
            return nil
        }
        return takeString(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    func sorafsReferenceValidatePdpBundle(commitment: Data,
                                          commitmentLabel: String,
                                          challenge: Data,
                                          challengeLabel: String,
                                          proof: Data,
                                          proofLabel: String,
                                          generatedAtUnix: UInt64) -> String? {
        #if canImport(Darwin)
        guard let function = sorafsReferenceValidatePdpBundleFn,
              let commitmentLabelData = commitmentLabel.data(using: .utf8),
              let challengeLabelData = challengeLabel.data(using: .utf8),
              let proofLabelData = proofLabel.data(using: .utf8) else { return nil }
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: CUnsignedLong = 0
        let status = withDataPointer(commitment) { commitmentPtr, commitmentLen in
            withDataPointer(commitmentLabelData) { commitmentLabelPtr, commitmentLabelLen in
                withDataPointer(challenge) { challengePtr, challengeLen in
                    withDataPointer(challengeLabelData) { challengeLabelPtr, challengeLabelLen in
                        withDataPointer(proof) { proofPtr, proofLen in
                            withDataPointer(proofLabelData) { proofLabelPtr, proofLabelLen in
                                function(
                                    commitmentPtr, commitmentLen,
                                    commitmentLabelPtr, commitmentLabelLen,
                                    challengePtr, challengeLen,
                                    challengeLabelPtr, challengeLabelLen,
                                    proofPtr, proofLen,
                                    proofLabelPtr, proofLabelLen,
                                    generatedAtUnix,
                                    &outPtr, &outLen
                                )
                            }
                        }
                    }
                }
            }
        }
        guard status == 0 else {
            if let outPtr {
                if let freeFn { freeFn(outPtr) } else { Darwin.free(outPtr) }
            }
            return nil
        }
        return takeString(pointer: outPtr, length: UInt(outLen))
        #else
        return nil
        #endif
    }

    func encodeConnectFrame(_ frame: ConnectFrame, launchNonce: Data?) -> Data? {
        #if canImport(Darwin)
        guard isConnectCodecAvailable else { return nil }
        switch frame.kind {
        case .control(let control):
            switch control {
            case .open(let open):
                guard let launchNonce else { return nil }
                return encodeControlOpenFrame(frame: frame, open: open, launchNonce: launchNonce)
            case .approve(let approve):
                return encodeControlApproveFrame(frame: frame, approve: approve)
            case .reject(let reject):
                return encodeControlRejectFrame(frame: frame, reject: reject)
            case .close(let close):
                return encodeControlCloseFrame(frame: frame, close: close)
            case .ping(let ping):
                return encodeControlPingFrame(frame: frame, ping: ping)
            case .pong(let pong):
                return encodeControlPongFrame(frame: frame, pong: pong)
            case .serverEvent:
                return nil
            }
        case .ciphertext(let ciphertext):
            return encodeCiphertextFrame(frame: frame, ciphertext: ciphertext)
        }
        #else
        return nil
        #endif
    }

    func decodeConnectFrame(_ data: Data) -> ConnectFrame? {
        #if canImport(Darwin)
        guard isConnectCodecAvailable else { return nil }
        var sessionBytes = [UInt8](repeating: 0, count: 32)
        var dirRaw: UInt8 = 0
        var sequence: UInt64 = 0
        var kind: UInt16 = 0
        guard let decodeControlKindFn else { return nil }
        let status = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return decodeControlKindFn(base, UInt(data.count), &sessionBytes, &dirRaw, &sequence, &kind)
        }
        guard status == 0 else { return nil }
        let sessionID = Data(sessionBytes)
        let direction: ConnectDirection = dirRaw == 0 ? .appToWallet : .walletToApp
        switch kind {
        case 1:
            return decodeControlOpenFrame(data: data, sessionID: sessionID, direction: direction, sequence: sequence)
        case 2:
            return decodeControlApproveFrame(data: data, sessionID: sessionID, direction: direction, sequence: sequence)
        case 100:
            return decodeCiphertextFrame(data: data, sessionID: sessionID, direction: direction, sequence: sequence)
        case 3:
            return decodeControlRejectFrame(data: data, sessionID: sessionID, direction: direction, sequence: sequence)
        case 4:
            return decodeControlCloseFrame(data: data, sessionID: sessionID, direction: direction, sequence: sequence)
        case 5:
            return decodeControlPingFrame(data: data, sessionID: sessionID, direction: direction, sequence: sequence)
        case 6:
            return decodeControlPongFrame(data: data, sessionID: sessionID, direction: direction, sequence: sequence)
        default:
            return nil
        }
        #else
        return nil
        #endif
    }

    #if canImport(Darwin)
    private func encodeControlOpenFrame(frame: ConnectFrame, open: ConnectOpen, launchNonce: Data) -> Data? {
        guard let encodeControlOpenFn,
              let freeFn,
              frame.sessionID.count == 32,
              open.appPublicKey.count == 32,
              launchNonce.count == 16
        else { return nil }
        let permissionsData = ConnectCodec.encodePermissionsJSON(open.permissions)
        let appMetadataData = ConnectCodec.encodeAppMetadataJSON(open.appMetadata)
        var result: Data?
        let status = frame.sessionID.withUnsafeBytes { sidBuffer -> Int32 in
            guard let sidBase = sidBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return open.appPublicKey.withUnsafeBytes { pkBuffer -> Int32 in
                guard let pkBase = pkBuffer.bindMemory(to: UInt8.self).baseAddress else { return -2 }
                return launchNonce.withUnsafeBytes { nonceBuffer -> Int32 in
                    guard let nonceBase = nonceBuffer.bindMemory(to: UInt8.self).baseAddress else { return -3 }
                    return withOptionalBytes(appMetadataData) { metaPtr, metaLen in
                        withOptionalBytes(permissionsData) { permsPtr, permsLen in
                            open.constraints.networkID.bytes.withUnsafeBytes { networkBuffer in
                                guard let networkPtr = networkBuffer.bindMemory(to: UInt8.self).baseAddress else { return -4 }
                                var outPtr: UnsafeMutablePointer<UInt8>? = nil
                                var outLen: UInt = 0
                                let dirRaw: UInt8 = frame.direction == .appToWallet ? 0 : 1
                                let status = encodeControlOpenFn(
                                    sidBase, dirRaw, frame.sequence,
                                    pkBase, UInt(open.appPublicKey.count),
                                    nonceBase, UInt(launchNonce.count),
                                    metaPtr, metaLen,
                                    networkPtr, UInt(open.constraints.networkID.bytes.count),
                                    permsPtr, permsLen,
                                    &outPtr,
                                    &outLen
                                )
                                if status == 0, let outPtr {
                                    result = Data(bytes: outPtr, count: Int(outLen))
                                    freeFn(outPtr)
                                }
                                return status
                            }
                        }
                    }
                }
            }
        }
        if status != 0 {
            result = nil
        }
        return result
    }

    private func encodeControlApproveFrame(frame: ConnectFrame, approve: ConnectApprove) -> Data? {
        guard let freeFn,
              frame.sessionID.count == 32,
              approve.walletPublicKey.count == 32 else { return nil }
        let permissionsData = ConnectCodec.encodePermissionsJSON(approve.permissions)
        let proofData = ConnectCodec.encodeProofJSON(approve.proof)
        let signature = approve.walletSignature.signature
        let normalizedAlgorithm = ConnectWalletSignatureAlgorithm.normalize(approve.walletSignature.algorithm)
        guard !signature.isEmpty else { return nil }

        var result: Data?
        let dirRaw: UInt8 = frame.direction == .appToWallet ? 0 : 1
        let signatureStatus = frame.sessionID.withUnsafeBytes { sidBuffer -> Int32 in
            guard let sidBase = sidBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return approve.walletPublicKey.withUnsafeBytes { pkBuffer -> Int32 in
                guard let pkBase = pkBuffer.bindMemory(to: UInt8.self).baseAddress else { return -2 }
                return signature.withUnsafeBytes { sigBuffer -> Int32 in
                    guard let sigBase = sigBuffer.bindMemory(to: UInt8.self).baseAddress else { return -3 }
                    if let encodeControlApproveWithAlgFn,
                       let normalizedAlgorithm,
                       let algorithmData = normalizedAlgorithm.data(using: .utf8) {
                        let status = withOptionalBytes(permissionsData) { permsRaw, permsLen in
                            withOptionalBytes(proofData) { proofRaw, proofLen in
                                algorithmData.withUnsafeBytes { algBuffer -> Int32 in
                                    guard let algRaw = algBuffer.bindMemory(to: UInt8.self).baseAddress else { return -5 }
                                    var outPtr: UnsafeMutablePointer<UInt8>? = nil
                                    var outLen: UInt = 0
                                    let permsPtr = permsRaw.map { UnsafeRawPointer($0).assumingMemoryBound(to: CChar.self) }
                                    let proofPtr = proofRaw.map { UnsafeRawPointer($0).assumingMemoryBound(to: CChar.self) }
                                    let algPtr = UnsafeRawPointer(algRaw).assumingMemoryBound(to: CChar.self)
                                    let status = approve.accountID.withCString { accountPtr in
                                        encodeControlApproveWithAlgFn(
                                            sidBase,
                                            dirRaw,
                                            frame.sequence,
                                            pkBase,
                                            accountPtr,
                                            UInt(approve.accountID.utf8.count),
                                            permsPtr,
                                            permsLen,
                                            proofPtr,
                                            proofLen,
                                            algPtr,
                                            UInt(algorithmData.count),
                                            sigBase,
                                            UInt(signature.count),
                                            &outPtr,
                                            &outLen
                                        )
                                    }
                                    if status == 0, let outPtr {
                                        result = Data(bytes: outPtr, count: Int(outLen))
                                        freeFn(outPtr)
                                    }
                                    return status
                                }
                            }
                        }
                        return status
                    } else {
                        guard let encodeControlApproveFn,
                              normalizedAlgorithm == "ed25519",
                              signature.count == 64 else { return -4 }
                        let status = withOptionalBytes(permissionsData) { permsPtr, permsLen in
                            withOptionalBytes(proofData) { proofPtr, proofLen in
                                var outPtr: UnsafeMutablePointer<UInt8>? = nil
                                var outLen: UInt = 0
                                let status = approve.accountID.withCString { accountPtr in
                                    encodeControlApproveFn(
                                        sidBase,
                                        dirRaw,
                                        frame.sequence,
                                        pkBase,
                                        UInt(approve.walletPublicKey.count),
                                        accountPtr,
                                        permsPtr,
                                        permsLen,
                                        proofPtr,
                                        proofLen,
                                        sigBase,
                                        UInt(signature.count),
                                        &outPtr,
                                        &outLen
                                    )
                                }
                                if status == 0, let outPtr {
                                    result = Data(bytes: outPtr, count: Int(outLen))
                                    freeFn(outPtr)
                                }
                                return status
                            }
                        }
                        return status
                    }
                }
            }
        }
        if signatureStatus != 0 {
            result = nil
        }
        return result
    }

    private func encodeControlRejectFrame(frame: ConnectFrame, reject: ConnectReject) -> Data? {
        guard let encodeControlRejectFn,
              let freeFn,
              frame.sessionID.count == 32 else { return nil }

        var result: Data?
        let dirRaw: UInt8 = frame.direction == .appToWallet ? 0 : 1
        let status = frame.sessionID.withUnsafeBytes { sidBuffer -> Int32 in
            guard let sidBase = sidBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return reject.codeID.withCString { codeIdPtr in
                withOptionalCString(reject.reason.isEmpty ? nil : reject.reason) { reasonPtr, reasonLen in
                    var outPtr: UnsafeMutablePointer<UInt8>? = nil
                    var outLen: UInt = 0
                    let status = encodeControlRejectFn(
                        sidBase,
                        dirRaw,
                        frame.sequence,
                        reject.code,
                        codeIdPtr,
                        UInt(reject.codeID.utf8.count),
                        reasonPtr,
                        reasonLen,
                        &outPtr,
                        &outLen
                    )
                    if status == 0, let outPtr {
                        result = Data(bytes: outPtr, count: Int(outLen))
                        freeFn(outPtr)
                    }
                    return status
                }
            }
        }
        if status != 0 {
            result = nil
        }
        return result
    }

    private func encodeControlCloseFrame(frame: ConnectFrame, close: ConnectClose) -> Data? {
        guard let encodeControlCloseFn,
              let freeFn,
              frame.sessionID.count == 32 else { return nil }

        var result: Data?
        let dirRaw: UInt8 = frame.direction == .appToWallet ? 0 : 1
        let whoRaw: UInt8 = close.role == .app ? 0 : 1
        let status = frame.sessionID.withUnsafeBytes { sidBuffer -> Int32 in
            guard let sidBase = sidBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return withOptionalCString(close.reason) { reasonPtr, reasonLen in
                var outPtr: UnsafeMutablePointer<UInt8>? = nil
                var outLen: UInt = 0
                let status = encodeControlCloseFn(
                    sidBase,
                    dirRaw,
                    frame.sequence,
                    whoRaw,
                    close.code,
                    reasonPtr,
                    reasonLen,
                    close.retryable ? 1 : 0,
                    &outPtr,
                    &outLen
                )
                if status == 0, let outPtr {
                    result = Data(bytes: outPtr, count: Int(outLen))
                    freeFn(outPtr)
                }
                return status
            }
        }
        if status != 0 {
            result = nil
        }
        return result
    }

    private func encodeControlPingFrame(frame: ConnectFrame, nonce: UInt64, fn pointer: EncodeControlPingFn?) -> Data? {
        guard let pointer,
              let freeFn,
              frame.sessionID.count == 32 else { return nil }
        var result: Data?
        let dirRaw: UInt8 = frame.direction == .appToWallet ? 0 : 1
        let status = frame.sessionID.withUnsafeBytes { sidBuffer -> Int32 in
            guard let sidBase = sidBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            var outPtr: UnsafeMutablePointer<UInt8>? = nil
            var outLen: UInt = 0
            let status = pointer(
                sidBase,
                dirRaw,
                frame.sequence,
                nonce,
                &outPtr,
                &outLen
            )
            if status == 0, let outPtr {
                result = Data(bytes: outPtr, count: Int(outLen))
                freeFn(outPtr)
            }
            return status
        }
        if status != 0 {
            result = nil
        }
        return result
    }

    private func encodeControlPingFrame(frame: ConnectFrame, ping: ConnectPing) -> Data? {
        encodeControlPingFrame(frame: frame, nonce: ping.nonce, fn: encodeControlPingFn)
    }

    private func encodeControlPongFrame(frame: ConnectFrame, pong: ConnectPong) -> Data? {
        encodeControlPingFrame(frame: frame, nonce: pong.nonce, fn: encodeControlPongFn)
    }

    private func encodeCiphertextFrame(frame: ConnectFrame, ciphertext: ConnectCiphertext) -> Data? {
        guard let encodeCiphertextFrameFn,
              let freeFn,
              frame.sessionID.count == 32 else { return nil }
        var result: Data?
        let dirRaw: UInt8 = frame.direction == .appToWallet ? 0 : 1
        let status = frame.sessionID.withUnsafeBytes { sidBuffer -> Int32 in
            guard let sidBase = sidBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return ciphertext.payload.withUnsafeBytes { payloadBuffer -> Int32 in
                let payloadBase = payloadBuffer.bindMemory(to: UInt8.self).baseAddress
                var outPtr: UnsafeMutablePointer<UInt8>? = nil
                var outLen: UInt = 0
                let status = encodeCiphertextFrameFn(
                    sidBase,
                    dirRaw,
                    frame.sequence,
                    payloadBase,
                    UInt(ciphertext.payload.count),
                    &outPtr,
                    &outLen
                )
                if status == 0, let outPtr {
                    result = Data(bytes: outPtr, count: Int(outLen))
                    freeFn(outPtr)
                }
                return status
            }
        }
        if status != 0 {
            result = nil
        }
        return result
    }

    private func decodeControlOpenFrame(data: Data, sessionID: Data, direction: ConnectDirection, sequence: UInt64) -> ConnectFrame? {
        guard let decodeControlOpenPubFn,
              let decodeControlOpenNetworkIdFn,
              let decodeControlOpenPermissionsFn else { return nil }
        var publicKeyBytes = [UInt8](repeating: 0, count: 32)
        let pubStatus = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return decodeControlOpenPubFn(base, UInt(data.count), &publicKeyBytes)
        }
        guard pubStatus == 0 else { return nil }

        var networkPtr: UnsafeMutablePointer<UInt8>? = nil
        var networkLen: UInt = 0
        let networkStatus = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return decodeControlOpenNetworkIdFn(base, UInt(data.count), &networkPtr, &networkLen)
        }
        guard networkStatus == 0,
              let networkData = takeData(pointer: networkPtr, length: networkLen),
              let networkID = try? NetworkId(bytes: networkData) else { return nil }

        var permissionsPtr: UnsafeMutablePointer<UInt8>? = nil
        var permissionsLen: UInt = 0
        let permsStatus = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return decodeControlOpenPermissionsFn(base, UInt(data.count), &permissionsPtr, &permissionsLen)
        }
        guard permsStatus == 0 else { return nil }
        let permissionsData = takeData(pointer: permissionsPtr, length: permissionsLen)
        let permissions: ConnectPermissions?
        if let permissionsData {
            do {
                permissions = try ConnectCodec.decodePermissionsJSON(permissionsData)
            } catch {
                return nil
            }
        } else {
            permissions = nil
        }

        var appMetadata: ConnectAppMetadata?
        if let decodeControlOpenAppMetadataFn {
            var metadataPtr: UnsafeMutablePointer<UInt8>? = nil
            var metadataLen: UInt = 0
            let metadataStatus = data.withUnsafeBytes { buffer -> Int32 in
                guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return decodeControlOpenAppMetadataFn(base, UInt(data.count), &metadataPtr, &metadataLen)
            }
            if metadataStatus == 0 {
                let metadataData = takeData(pointer: metadataPtr, length: metadataLen)
                if let metadataData {
                    do {
                        appMetadata = try ConnectCodec.decodeAppMetadataJSON(metadataData)
                    } catch {
                        return nil
                    }
                } else {
                    appMetadata = nil
                }
            }
        }

        let open = ConnectOpen(
            appPublicKey: Data(publicKeyBytes),
            appMetadata: appMetadata,
            constraints: ConnectConstraints(networkID: networkID),
            permissions: permissions
        )
        return ConnectFrame(sessionID: sessionID, direction: direction, sequence: sequence, kind: .control(.open(open)))
    }

    private func decodeControlApproveFrame(data: Data, sessionID: Data, direction: ConnectDirection, sequence: UInt64) -> ConnectFrame? {
        guard let decodeControlApprovePubFn,
              let decodeControlApproveAccountFn,
              let decodeControlApprovePermissionsFn,
              let decodeControlApproveProofFn,
              let decodeControlApproveSigFn,
              let decodeControlApproveSigAlgFn else { return nil }

        var walletPkBytes = [UInt8](repeating: 0, count: 32)
        let pubStatus = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return decodeControlApprovePubFn(base, UInt(data.count), &walletPkBytes)
        }
        guard pubStatus == 0 else { return nil }

        var accountPtr: UnsafeMutablePointer<UInt8>? = nil
        var accountLen: UInt = 0
        let accountStatus = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return decodeControlApproveAccountFn(base, UInt(data.count), &accountPtr, &accountLen)
        }
        guard accountStatus == 0, let accountID = takeString(pointer: accountPtr, length: accountLen) else { return nil }

        var permissionsPtr: UnsafeMutablePointer<UInt8>? = nil
        var permissionsLen: UInt = 0
        let permsStatus = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return decodeControlApprovePermissionsFn(base, UInt(data.count), &permissionsPtr, &permissionsLen)
        }
        guard permsStatus == 0 else { return nil }
        let permissionsData = takeData(pointer: permissionsPtr, length: permissionsLen)
        let permissions: ConnectPermissions?
        if let permissionsData {
            do {
                permissions = try ConnectCodec.decodePermissionsJSON(permissionsData)
            } catch {
                return nil
            }
        } else {
            permissions = nil
        }

        var proofPtr: UnsafeMutablePointer<UInt8>? = nil
        var proofLen: UInt = 0
        let proofStatus = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return decodeControlApproveProofFn(base, UInt(data.count), &proofPtr, &proofLen)
        }
        guard proofStatus == 0 else { return nil }
        let proofData = takeData(pointer: proofPtr, length: proofLen)
        let proof: ConnectSignInProof?
        if let proofData {
            do {
                proof = try ConnectCodec.decodeProofJSON(proofData)
            } catch {
                return nil
            }
        } else {
            proof = nil
        }

        var signatureBytes = [UInt8](repeating: 0, count: 64)
        let sigStatus = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return decodeControlApproveSigFn(base, UInt(data.count), &signatureBytes)
        }
        guard sigStatus == 0 else { return nil }

        var algPtr: UnsafeMutablePointer<CChar>? = nil
        var algLen: UInt = 0
        let algStatus = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return decodeControlApproveSigAlgFn(base, UInt(data.count), &algPtr, &algLen)
        }
        guard algStatus == 0, let algorithm = takeCString(pointer: algPtr, length: algLen) else { return nil }

        let signature = ConnectWalletSignature(algorithm: algorithm, signature: Data(signatureBytes))
        let approve = ConnectApprove(walletPublicKey: Data(walletPkBytes),
                                     accountID: accountID,
                                     permissions: permissions,
                                     proof: proof,
                                     walletSignature: signature,
                                     walletMetadata: nil)
        return ConnectFrame(sessionID: sessionID, direction: direction, sequence: sequence, kind: .control(.approve(approve)))
    }

    private func decodeCiphertextFrame(data: Data, sessionID: Data, direction: ConnectDirection, sequence: UInt64) -> ConnectFrame? {
        guard let decodeCiphertextFrameFn else { return nil }
        var outSession = [UInt8](repeating: 0, count: 32)
        var outDir: UInt8 = 0
        var outSeq: UInt64 = 0
        var payloadPtr: UnsafeMutablePointer<UInt8>? = nil
        var payloadLen: UInt = 0
        let status = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return decodeCiphertextFrameFn(base, UInt(data.count), &outSession, &outDir, &outSeq, &payloadPtr, &payloadLen)
        }
        guard status == 0 else { return nil }
        let payload = takeData(pointer: payloadPtr, length: payloadLen) ?? Data()
        let frame = ConnectFrame(sessionID: sessionID,
                                 direction: direction,
                                 sequence: sequence,
                                 kind: .ciphertext(ConnectCiphertext(payload: payload)))
        return frame
    }

    private func decodeControlRejectFrame(data: Data, sessionID: Data, direction: ConnectDirection, sequence: UInt64) -> ConnectFrame? {
        guard let decodeControlRejectFn else { return nil }
        var code: UInt16 = 0
        var codeIdPtr: UnsafeMutablePointer<UInt8>? = nil
        var codeIdLen: UInt = 0
        var reasonPtr: UnsafeMutablePointer<UInt8>? = nil
        var reasonLen: UInt = 0
        let status = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return decodeControlRejectFn(base, UInt(data.count), &code, &codeIdPtr, &codeIdLen, &reasonPtr, &reasonLen)
        }
        guard status == 0,
              let codeID = takeString(pointer: codeIdPtr, length: codeIdLen) else { return nil }
        let reason = takeString(pointer: reasonPtr, length: reasonLen) ?? ""
        let reject = ConnectReject(code: code, codeID: codeID, reason: reason)
        return ConnectFrame(sessionID: sessionID,
                             direction: direction,
                             sequence: sequence,
                             kind: .control(.reject(reject)))
    }

    private func decodeControlCloseFrame(data: Data, sessionID: Data, direction: ConnectDirection, sequence: UInt64) -> ConnectFrame? {
        guard let decodeControlCloseFn else { return nil }
        var roleRaw: UInt8 = 0
        var code: UInt16 = 0
        var retryRaw: UInt8 = 0
        var reasonPtr: UnsafeMutablePointer<UInt8>? = nil
        var reasonLen: UInt = 0
        let status = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return decodeControlCloseFn(base, UInt(data.count), &roleRaw, &code, &retryRaw, &reasonPtr, &reasonLen)
        }
        guard status == 0 else { return nil }
        let reasonString = takeString(pointer: reasonPtr, length: reasonLen)
        let role: ConnectRole = roleRaw == 0 ? .app : .wallet
        let close = ConnectClose(role: role,
                                 code: code,
                                 reason: (reasonString?.isEmpty ?? true) ? nil : reasonString,
                                 retryable: retryRaw != 0)
        return ConnectFrame(sessionID: sessionID,
                             direction: direction,
                             sequence: sequence,
                             kind: .control(.close(close)))
    }

    private func decodeControlPingFrame(data: Data, sessionID: Data, direction: ConnectDirection, sequence: UInt64, fn pointer: DecodeControlPingFn?, builder: (UInt64) -> ConnectControl) -> ConnectFrame? {
        guard let pointer else { return nil }
        var nonce: UInt64 = 0
        let status = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return pointer(base, UInt(data.count), &nonce)
        }
        guard status == 0 else { return nil }
        return ConnectFrame(sessionID: sessionID,
                             direction: direction,
                             sequence: sequence,
                             kind: .control(builder(nonce)))
    }

    private func decodeControlPingFrame(data: Data, sessionID: Data, direction: ConnectDirection, sequence: UInt64) -> ConnectFrame? {
        decodeControlPingFrame(data: data, sessionID: sessionID, direction: direction, sequence: sequence, fn: decodeControlPingFn) {
            .ping(ConnectPing(nonce: $0))
        }
    }

    private func decodeControlPongFrame(data: Data, sessionID: Data, direction: ConnectDirection, sequence: UInt64) -> ConnectFrame? {
        decodeControlPingFrame(data: data, sessionID: sessionID, direction: direction, sequence: sequence, fn: decodeControlPongFn) {
            .pong(ConnectPong(nonce: $0))
        }
    }
    #endif
}

extension NoritoNativeBridge {
    static var bridgeRequirementHint: String {
        BridgePolicyHint.message
    }

    static func bridgeUnavailableMessage(_ prefix: String) -> String {
        BridgePolicyHint.unavailableMessage(prefix)
    }
}
