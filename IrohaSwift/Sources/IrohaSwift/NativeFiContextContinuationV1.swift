import CryptoKit
import Foundation

/// Signed shape and original selection were natively admitted. This is NOT proof
/// that the assertion executed, nor a snapshot, freshness or signing capability.
public struct AdmittedFiAssertionOriginalV1: Sendable {
    public let signedOriginal: Data
    public let entrypointHash: Data
    public let wireSHA256: Data
    public let requestSHA256: Data
    public let originalCheckpointHeight: UInt64
    public let originalCheckpointBlockHash: Data
    fileprivate let originalTrustJSON: Data
    fileprivate init(signedOriginal: Data, entrypointHash: Data, wireSHA256: Data, requestSHA256: Data,
                     originalCheckpointHeight: UInt64, originalCheckpointBlockHash: Data, originalTrustJSON: Data) {
        self.signedOriginal = signedOriginal; self.entrypointHash = entrypointHash
        self.wireSHA256 = wireSHA256; self.requestSHA256 = requestSHA256
        self.originalCheckpointHeight = originalCheckpointHeight
        self.originalCheckpointBlockHash = originalCheckpointBlockHash; self.originalTrustJSON = originalTrustJSON
    }
}

/// Selectors from the protected local operation branch. Constructing this value is
/// not authentication. The caller must retain native-derived lineage and check its
/// local branch generation before/after verification and every asynchronous step.
public struct NativeFiContinuationCursorTrustV1: Sendable {
    public let checkpointSHA256: Data
    public let height: UInt64
    public let contextID: Data
    public let blockHash: Data
    public init(checkpointSHA256: Data, height: UInt64, contextID: Data, blockHash: Data) {
        self.checkpointSHA256 = checkpointSHA256; self.height = height
        self.contextID = contextID; self.blockHash = blockHash
    }
    fileprivate func envelope(original: Data) throws -> Data {
        guard [checkpointSHA256, contextID, blockHash].allSatisfy({ $0.count == 32 && $0.contains(where: { $0 != 0 }) }),
              height > 0, height < UInt64.max, blockHash[31] & 1 == 1,
              let originalObject = try JSONSerialization.jsonObject(with: original) as? [String: Any] else {
            throw NativeFiContextAssertionErrorV1.invalidInput
        }
        let value: [String: Any] = ["schema": "iroha.fi-context-continuation-trust.v1", "original": originalObject,
            "cursor": ["checkpointSha256": checkpointSHA256.continuationHex, "checkpointHeight": String(height),
                       "checkpointContextId": contextID.continuationHex, "checkpointBlockHash": blockHash.continuationHex]]
        let json = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
        guard json.count <= 36 * 1024 else { throw NativeFiContextAssertionErrorV1.invalidInput }
        return try NoritoNativeBridge.shared.canonicalizeJSONBlake3(json).canonicalJSON
    }
}

public enum NativeFiContextContinuationV1 {
    #if canImport(Darwin)
    private typealias AdmitFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt, UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt, UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<UInt>?
    ) -> Int32
    private typealias VerifyFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt, UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt, UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt, UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<UInt>?
    ) -> Int32
    private typealias FreeFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    #endif

    /// Server status hashes are comparisons only; native derives both identities
    /// from the exact signed wire and binds its singleton assertion to local pins.
    public static func admitOriginal(signedOriginal: Data, retainedRequest: Data,
                                     originalCheckpoint: Data, trust: NativeFiContextTrustV1,
                                     statusEntrypointHash: Data, statusWireSHA256: Data) throws -> AdmittedFiAssertionOriginalV1 {
        guard !signedOriginal.isEmpty, signedOriginal.count <= 64 * 1024,
              !retainedRequest.isEmpty, retainedRequest.count <= 64 * 1024,
              !originalCheckpoint.isEmpty, originalCheckpoint.count <= 68 * 1024 * 1024,
              statusEntrypointHash.count == 32, statusEntrypointHash[31] & 1 == 1,
              statusWireSHA256 == Data(SHA256.hash(data: signedOriginal)),
              trust.retainedRequestSHA256 == Data(SHA256.hash(data: retainedRequest)) else {
            throw NativeFiContextAssertionErrorV1.invalidInput
        }
        #if canImport(Darwin)
        let bridge = NoritoNativeBridge.shared
        guard bridge.isAvailable,
              let admit: AdmitFn = bridge.resolveNativeSymbol("connect_norito_admit_fi_assertion_original_v1", as: AdmitFn.self),
              let free: FreeFn = bridge.resolveNativeSymbol("connect_norito_free", as: FreeFn.self) else {
            throw NativeFiContextAssertionErrorV1.bridgeUnavailable
        }
        let pins = try trust.canonicalJSON()
        var output: UnsafeMutablePointer<UInt8>?, length: UInt = 0
        let status = signedOriginal.withUnsafeBytes { signed in
            retainedRequest.withUnsafeBytes { request in
                originalCheckpoint.withUnsafeBytes { checkpoint in
                    pins.withUnsafeBytes { pins in
                        admit(signed.bindMemory(to: UInt8.self).baseAddress, UInt(signed.count),
                            request.bindMemory(to: UInt8.self).baseAddress, UInt(request.count),
                            checkpoint.bindMemory(to: UInt8.self).baseAddress, UInt(checkpoint.count),
                            pins.bindMemory(to: UInt8.self).baseAddress, UInt(pins.count), &output, &length)
                    }
                }
            }
        }
        defer { if let output { free(UnsafeMutableRawPointer(output)) } }
        guard status == 0 else { throw NativeFiContextAssertionErrorV1.nativeRejected(status) }
        guard let output, length > 0, length <= 2048 else { throw NativeFiContextAssertionErrorV1.invalidNativeResult }
        let bytes = Data(bytes: output, count: Int(length))
        guard try bridge.canonicalizeJSONBlake3(bytes).canonicalJSON == bytes else { throw NativeFiContextAssertionErrorV1.invalidNativeResult }
        return try decodeAdmittedOriginal(bytes, signedOriginal: signedOriginal, trust: trust, trustJSON: pins,
            expectedEntrypointHash: statusEntrypointHash, expectedWireSHA256: statusWireSHA256)
        #else
        throw NativeFiContextAssertionErrorV1.bridgeUnavailable
        #endif
    }

    public static func verify(capsule: Data, retainedRequest: Data, admittedOriginal: AdmittedFiAssertionOriginalV1,
                              originalCheckpoint: Data, cursorCheckpoint: Data, trust: NativeFiContextTrustV1,
                              cursorTrust: NativeFiContinuationCursorTrustV1) throws -> VerifiedFiContextAssertionV1 {
        guard !capsule.isEmpty, capsule.count <= 512 * 1024,
              !retainedRequest.isEmpty, retainedRequest.count <= 64 * 1024,
              !originalCheckpoint.isEmpty, originalCheckpoint.count <= 68 * 1024 * 1024,
              !cursorCheckpoint.isEmpty, cursorCheckpoint.count <= 68 * 1024 * 1024,
              admittedOriginal.requestSHA256 == trust.retainedRequestSHA256,
              trust.retainedRequestSHA256 == Data(SHA256.hash(data: retainedRequest)),
              admittedOriginal.originalCheckpointHeight == trust.checkpointHeight,
              cursorTrust.height >= trust.checkpointHeight else { throw NativeFiContextAssertionErrorV1.invalidInput }
        #if canImport(Darwin)
        let bridge = NoritoNativeBridge.shared
        guard bridge.isAvailable,
              let verify: VerifyFn = bridge.resolveNativeSymbol("connect_norito_verify_fi_context_continuation_v1", as: VerifyFn.self),
              let free: FreeFn = bridge.resolveNativeSymbol("connect_norito_free", as: FreeFn.self) else {
            throw NativeFiContextAssertionErrorV1.bridgeUnavailable
        }
        let originalPins = try trust.canonicalJSON()
        guard originalPins == admittedOriginal.originalTrustJSON else { throw NativeFiContextAssertionErrorV1.invalidInput }
        let pins = try cursorTrust.envelope(original: originalPins)
        var output: UnsafeMutablePointer<UInt8>?, length: UInt = 0
        let status = capsule.withUnsafeBytes { capsule in
            retainedRequest.withUnsafeBytes { request in
                admittedOriginal.signedOriginal.withUnsafeBytes { signed in
                    originalCheckpoint.withUnsafeBytes { original in
                        cursorCheckpoint.withUnsafeBytes { cursor in
                            pins.withUnsafeBytes { pins in
                                verify(capsule.bindMemory(to: UInt8.self).baseAddress, UInt(capsule.count),
                                    request.bindMemory(to: UInt8.self).baseAddress, UInt(request.count),
                                    signed.bindMemory(to: UInt8.self).baseAddress, UInt(signed.count),
                                    original.bindMemory(to: UInt8.self).baseAddress, UInt(original.count),
                                    cursor.bindMemory(to: UInt8.self).baseAddress, UInt(cursor.count),
                                    pins.bindMemory(to: UInt8.self).baseAddress, UInt(pins.count), &output, &length)
                            }
                        }
                    }
                }
            }
        }
        defer { if let output { free(UnsafeMutableRawPointer(output)) } }
        guard status == 0 else { throw NativeFiContextAssertionErrorV1.nativeRejected(status) }
        guard let output, length > 0, length <= 512 * 1024 else { throw NativeFiContextAssertionErrorV1.invalidNativeResult }
        let verified = try NativeFiContextAssertionV1.decodeNativeResult(Data(bytes: output, count: Int(length)), trust: trust)
        guard verified.blockHeight >= cursorTrust.height else { throw NativeFiContextAssertionErrorV1.invalidNativeResult }
        return verified
        #else
        throw NativeFiContextAssertionErrorV1.bridgeUnavailable
        #endif
    }

    static func decodeAdmittedOriginal(_ bytes: Data, signedOriginal: Data, trust: NativeFiContextTrustV1,
        trustJSON: Data, expectedEntrypointHash: Data, expectedWireSHA256: Data) throws -> AdmittedFiAssertionOriginalV1 {
        guard !bytes.isEmpty, bytes.count <= 2048,
              let value = try JSONSerialization.jsonObject(with: bytes) as? [String: String],
              Set(value.keys) == ["schema", "requestSha256", "assertionEntrypointHash", "assertionWireSha256", "originalCheckpointHeight", "originalCheckpointBlockHash"],
              value["schema"] == "iroha.fi-assertion-original.admitted.v1",
              value["requestSha256"] == trust.retainedRequestSHA256.continuationHex,
              value["assertionEntrypointHash"] == expectedEntrypointHash.continuationHex,
              expectedEntrypointHash.count == 32, expectedEntrypointHash[31] & 1 == 1,
              value["assertionWireSha256"] == expectedWireSHA256.continuationHex,
              expectedWireSHA256 == Data(SHA256.hash(data: signedOriginal)),
              value["originalCheckpointHeight"] == String(trust.checkpointHeight),
              let blockText = value["originalCheckpointBlockHash"], let block = raw32(blockText), block[31] & 1 == 1 else {
            throw NativeFiContextAssertionErrorV1.invalidNativeResult
        }
        return .init(signedOriginal: signedOriginal, entrypointHash: expectedEntrypointHash,
            wireSHA256: expectedWireSHA256, requestSHA256: trust.retainedRequestSHA256,
            originalCheckpointHeight: trust.checkpointHeight, originalCheckpointBlockHash: block, originalTrustJSON: trustJSON)
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

private extension Data { var continuationHex: String { map { String(format: "%02x", $0) }.joined() } }
