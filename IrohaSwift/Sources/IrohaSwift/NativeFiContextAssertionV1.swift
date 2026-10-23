import Foundation

public enum NativeFiContextAssertionErrorV1: Error, Equatable, Sendable {
    case invalidInput
    case bridgeUnavailable
    case nativeRejected(Int32)
    case invalidNativeResult
}

/// Complete independently retained comparison target. Construction is not proof.
public struct NativeFiLinkApprovalTargetV1: Sendable {
    public let assetDefinitionId: String
    public let accountId: String
    public let fiAccountId: String
    public let referenceDigest: Data
    public let fiRevision: UInt64
    public let attestationRevision: UInt64
    public let revision: UInt64
    public let expectedPolicyRevision: UInt64
    public let enabled: Bool
    public let controller: String?
    public let waterfall: Bool
    public let reverseWaterfall: Bool

    public init(assetDefinitionId: String, accountId: String, fiAccountId: String,
                referenceDigest: Data, fiRevision: UInt64, attestationRevision: UInt64,
                revision: UInt64, expectedPolicyRevision: UInt64, enabled: Bool,
                controller: String?, waterfall: Bool, reverseWaterfall: Bool) {
        self.assetDefinitionId = assetDefinitionId; self.accountId = accountId; self.fiAccountId = fiAccountId
        self.referenceDigest = referenceDigest; self.fiRevision = fiRevision; self.attestationRevision = attestationRevision
        self.revision = revision; self.expectedPolicyRevision = expectedPolicyRevision; self.enabled = enabled
        self.controller = controller; self.waterfall = waterfall; self.reverseWaterfall = reverseWaterfall
    }
    fileprivate var object: [String: Any] {
        ["assetDefinitionId": assetDefinitionId, "accountId": accountId, "fiAccountId": fiAccountId,
         "referenceDigest": referenceDigest.fiContextHex, "fiRevision": fiRevision,
         "attestationRevision": attestationRevision, "revision": revision,
         "expectedPolicyRevision": expectedPolicyRevision, "enabled": enabled,
         "controller": controller.map { $0 as Any } ?? NSNull(),
         "waterfall": waterfall, "reverseWaterfall": reverseWaterfall]
    }
}

/// Local trust/owner selection. Keep the request digest and complete target from
/// the retained original; do not derive them from a server's capsule/reference.
public struct NativeFiContextTrustV1: Sendable {
    public let networkId: NetworkId
    public let chainId: String
    public let checkpointSHA256: Data
    public let checkpointHeight: UInt64
    public let checkpointContextID: Data
    public let assetOwner: String
    public let assetIncarnation: Data
    public let assetDefinitionId: String
    public let walletAccountId: String
    public let uid: Data
    public let fiAccountId: String
    public let fiParticipant: String
    public let uidController: String?
    public let runtimeManifestSHA256: Data
    public let ownerKeyIdentity: String
    public let walletScopeCanonical: Data
    public let retainedRequestSHA256: Data
    public let target: NativeFiLinkApprovalTargetV1

    public init(networkId: NetworkId, chainId: String, checkpointSHA256: Data, checkpointHeight: UInt64,
                checkpointContextID: Data, assetOwner: String, assetIncarnation: Data,
                assetDefinitionId: String, walletAccountId: String, uid: Data, fiAccountId: String,
                fiParticipant: String, uidController: String?, runtimeManifestSHA256: Data,
                ownerKeyIdentity: String, walletScopeCanonical: Data, retainedRequestSHA256: Data,
                target: NativeFiLinkApprovalTargetV1) {
        self.networkId = networkId; self.chainId = chainId; self.checkpointSHA256 = checkpointSHA256
        self.checkpointHeight = checkpointHeight; self.checkpointContextID = checkpointContextID
        self.assetOwner = assetOwner; self.assetIncarnation = assetIncarnation
        self.assetDefinitionId = assetDefinitionId; self.walletAccountId = walletAccountId; self.uid = uid
        self.fiAccountId = fiAccountId; self.fiParticipant = fiParticipant; self.uidController = uidController
        self.runtimeManifestSHA256 = runtimeManifestSHA256; self.ownerKeyIdentity = ownerKeyIdentity
        self.walletScopeCanonical = walletScopeCanonical; self.retainedRequestSHA256 = retainedRequestSHA256
        self.target = target
    }

    func canonicalJSON() throws -> Data {
        guard [checkpointSHA256, checkpointContextID, assetIncarnation, uid, runtimeManifestSHA256,
               retainedRequestSHA256, target.referenceDigest].allSatisfy({ $0.count == 32 && $0.contains(where: { $0 != 0 }) }),
              checkpointHeight > 0, checkpointHeight < UInt64.max,
              assetIncarnation[31] & 1 == 1,
              !walletScopeCanonical.isEmpty, walletScopeCanonical.count <= 16384,
              let scope = String(data: walletScopeCanonical, encoding: .utf8),
              target.assetDefinitionId == assetDefinitionId, target.accountId == walletAccountId,
              target.fiAccountId == fiAccountId, fiAccountId != walletAccountId,
              target.controller == nil || target.controller == uidController,
              [target.fiRevision, target.attestationRevision, target.revision, target.expectedPolicyRevision].allSatisfy({ $0 > 0 }),
              !(target.waterfall || target.reverseWaterfall) || (target.enabled && target.controller != nil) else {
            throw NativeFiContextAssertionErrorV1.invalidInput
        }
        for (text, maximum) in [(chainId, 1024), (assetOwner, 1024), (walletAccountId, 1024),
                               (fiAccountId, 1024), (assetDefinitionId, 128), (fiParticipant, 256),
                               (ownerKeyIdentity, 256)] {
            guard !text.isEmpty, text.utf8.count <= maximum,
                  text == text.trimmingCharacters(in: .whitespacesAndNewlines),
                  !text.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
                throw NativeFiContextAssertionErrorV1.invalidInput
            }
        }
        let object: [String: Any] = [
            "schema": "iroha.fi-context-verification-trust.v1", "networkId": networkId.literal,
            "chainId": chainId, "checkpointSha256": checkpointSHA256.fiContextHex,
            "checkpointHeight": String(checkpointHeight), "checkpointContextId": checkpointContextID.fiContextHex,
            "assetOwner": assetOwner, "assetIncarnation": assetIncarnation.fiContextHex,
            "assetDefinitionId": assetDefinitionId, "walletAccountId": walletAccountId,
            "uid": uid.fiContextHex, "fiAccountId": fiAccountId, "fiParticipant": fiParticipant,
            "uidController": uidController.map { $0 as Any } ?? NSNull(),
            "runtimeManifestSha256": runtimeManifestSHA256.fiContextHex, "ownerKeyIdentity": ownerKeyIdentity,
            "walletScopeCanonical": scope, "requestSha256": retainedRequestSHA256.fiContextHex,
            "target": target.object,
        ]
        let bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        guard bytes.count <= 32 * 1024 else { throw NativeFiContextAssertionErrorV1.invalidInput }
        // Only local trust selectors are canonicalized here. The retained original
        // request is never reconstructed or translated before native verification.
        return try NoritoNativeBridge.shared.canonicalizeJSONBlake3(bytes).canonicalJSON
    }
}

/// Native-authenticated execution-cut observation. No public JSON initializer.
/// Applications still enforce owner/runtime identity, nondecreasing height, local
/// monotonic freshness and business eligibility before a signing context exists.
public struct VerifiedFiContextAssertionV1: Sendable {
    public let requestSHA256: Data
    public let blockHash: Data
    public let blockHeight: UInt64
    public let blockCreationTimeMs: UInt64
    public let snapshotJSON: Data
    fileprivate init(requestSHA256: Data, blockHash: Data, blockHeight: UInt64,
                     blockCreationTimeMs: UInt64, snapshotJSON: Data) {
        self.requestSHA256 = requestSHA256; self.blockHash = blockHash; self.blockHeight = blockHeight
        self.blockCreationTimeMs = blockCreationTimeMs; self.snapshotJSON = snapshotJSON
    }
}

public enum NativeFiContextAssertionV1 {
    #if canImport(Darwin)
    private typealias VerifyFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt, UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt, UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<UInt>?
    ) -> Int32
    private typealias FreeFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    #endif

    public static func verify(capsule: Data, retainedRequest: Data, checkpoint: Data,
                              trust: NativeFiContextTrustV1) throws -> VerifiedFiContextAssertionV1 {
        guard !capsule.isEmpty, capsule.count <= 512 * 1024,
              !retainedRequest.isEmpty, retainedRequest.count <= 64 * 1024,
              !checkpoint.isEmpty, checkpoint.count <= 68 * 1024 * 1024 else {
            throw NativeFiContextAssertionErrorV1.invalidInput
        }
        #if canImport(Darwin)
        let bridge = NoritoNativeBridge.shared
        guard bridge.isAvailable,
              let verify: VerifyFn = bridge.resolveNativeSymbol("connect_norito_verify_fi_context_assertion_v1", as: VerifyFn.self),
              let free: FreeFn = bridge.resolveNativeSymbol("connect_norito_free", as: FreeFn.self) else {
            throw NativeFiContextAssertionErrorV1.bridgeUnavailable
        }
        let pins = try trust.canonicalJSON()
        var output: UnsafeMutablePointer<UInt8>?
        var length: UInt = 0
        let status = capsule.withUnsafeBytes { capsule in
            retainedRequest.withUnsafeBytes { request in
                checkpoint.withUnsafeBytes { checkpoint in
                    pins.withUnsafeBytes { pins in
                        verify(capsule.bindMemory(to: UInt8.self).baseAddress, UInt(capsule.count),
                               request.bindMemory(to: UInt8.self).baseAddress, UInt(request.count),
                               checkpoint.bindMemory(to: UInt8.self).baseAddress, UInt(checkpoint.count),
                               pins.bindMemory(to: UInt8.self).baseAddress, UInt(pins.count), &output, &length)
                    }
                }
            }
        }
        defer { if let output { free(UnsafeMutableRawPointer(output)) } }
        guard status == 0 else { throw NativeFiContextAssertionErrorV1.nativeRejected(status) }
        guard let output, length > 0, length <= 512 * 1024 else {
            throw NativeFiContextAssertionErrorV1.invalidNativeResult
        }
        return try decodeNativeResult(Data(bytes: output, count: Int(length)), trust: trust)
        #else
        throw NativeFiContextAssertionErrorV1.bridgeUnavailable
        #endif
    }

    static func decodeNativeResult(_ bytes: Data, trust: NativeFiContextTrustV1) throws -> VerifiedFiContextAssertionV1 {
        guard try NoritoNativeBridge.shared.canonicalizeJSONBlake3(bytes).canonicalJSON == bytes,
              let object = try JSONSerialization.jsonObject(with: bytes) as? [String: String],
              Set(object.keys) == ["schema", "requestSha256", "blockHash", "blockHeight", "blockCreationTimeMs", "snapshotJsonBase64"],
              object["schema"] == "iroha.fi-context-assertion.verified.v1",
              object["requestSha256"] == trust.retainedRequestSHA256.fiContextHex,
              let blockText = object["blockHash"], let block = raw32(blockText), block[31] & 1 == 1,
              let heightText = object["blockHeight"], let height = UInt64(heightText),
              String(height) == heightText, height > trust.checkpointHeight,
              let timeText = object["blockCreationTimeMs"], let time = UInt64(timeText),
              String(time) == timeText, time > 0,
              let snapshotText = object["snapshotJsonBase64"], let snapshot = Data(base64Encoded: snapshotText),
              !snapshot.isEmpty, snapshot.count <= 512 * 1024, snapshot.base64EncodedString() == snapshotText else {
            throw NativeFiContextAssertionErrorV1.invalidNativeResult
        }
        return .init(requestSHA256: trust.retainedRequestSHA256, blockHash: block,
                     blockHeight: height, blockCreationTimeMs: time, snapshotJSON: snapshot)
    }
    private static func raw32(_ text: String) -> Data? {
        let bytes = Array(text.utf8)
        guard bytes.count == 64 else { return nil }
        func digit(_ value: UInt8) -> UInt8? {
            switch value { case 48...57: return value - 48; case 97...102: return value - 87; default: return nil }
        }
        var result = Data(capacity: 32)
        for offset in stride(from: 0, to: 64, by: 2) {
            guard let first = digit(bytes[offset]), let last = digit(bytes[offset + 1]) else { return nil }
            result.append(first * 16 + last)
        }
        return result.contains(where: { $0 != 0 }) ? result : nil
    }
}

private extension Data { var fiContextHex: String { map { String(format: "%02x", $0) }.joined() } }
