import Foundation

/// A policy projection and its successor checkpoint returned together by native verification.
/// Persist both before using the checkpoint to request the next page.
public struct ValidationFeeVerifiedNativePageV1: Sendable {
    public let projectionJSON: Data
    public let promotedCheckpoint: Data
    fileprivate init(projectionJSON: Data, promotedCheckpoint: Data) {
        self.projectionJSON = projectionJSON
        self.promotedCheckpoint = promotedCheckpoint
    }
}

public enum ValidationFeeFinalityErrorV1: Error, Equatable, Sendable {
    case invalidInput
    case bridgeUnavailable
    case nativeRejected(Int32)
    case invalidNativeOutput
}

/// Bounded access to the current native fee-policy proof API. Swift does not parse proofs.
public enum ValidationFeeFinalityV1 {
    public static let maximumProofBytes = 4 * 1024 * 1024
    public static let maximumCheckpointBytes = 68 * 1024 * 1024
    private static let maximumProjectionBytes = 16 * 1024 * 1024

    private typealias RequestFn = @convention(c) (UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?) -> Int32
    private typealias VerifyFn = @convention(c) (
        UnsafePointer<UInt8>?, CUnsignedLong, UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafePointer<UInt8>?, CUnsignedLong, UnsafePointer<UInt8>?, CUnsignedLong,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<CUnsignedLong>?) -> Int32
    private typealias FreeFn = @convention(c) (UnsafeMutablePointer<UInt8>?) -> Void

    /// Encode the canonical request from the complete retained checkpoint.
    public static func request(checkpoint: Data) throws -> Data {
        guard !checkpoint.isEmpty, checkpoint.count <= maximumCheckpointBytes else {
            throw ValidationFeeFinalityErrorV1.invalidInput
        }
        #if canImport(Darwin)
        let bridge = NoritoNativeBridge.shared
        guard bridge.isAvailable,
              let invoke = bridge.resolveNativeSymbol("connect_norito_validation_fee_current_policy_proof_request_v1", as: RequestFn.self),
              let free = bridge.resolveNativeSymbol("connect_norito_free", as: FreeFn.self) else {
            throw ValidationFeeFinalityErrorV1.bridgeUnavailable
        }
        var output: UnsafeMutablePointer<UInt8>?
        var length: CUnsignedLong = 0
        defer { if let output { free(output) } }
        let status = checkpoint.withUnsafeBytes { bytes in
            invoke(bytes.bindMemory(to: UInt8.self).baseAddress, CUnsignedLong(bytes.count), &output, &length)
        }
        guard status == 0 else { throw ValidationFeeFinalityErrorV1.nativeRejected(status) }
        guard let output, length > 0, length <= 1024 else {
            throw ValidationFeeFinalityErrorV1.invalidNativeOutput
        }
        return Data(bytes: output, count: Int(length))
        #else
        throw ValidationFeeFinalityErrorV1.bridgeUnavailable
        #endif
    }

    /// Verify the original proof against immutable network/genesis pins and the full checkpoint.
    public static func verify(proof: Data, networkID: Data, policyChainGenesisHash: Data,
                              checkpoint: Data) throws -> ValidationFeeVerifiedNativePageV1 {
        guard !proof.isEmpty, proof.count <= maximumProofBytes,
              networkID.count == 32, policyChainGenesisHash.count == 32,
              !checkpoint.isEmpty, checkpoint.count <= maximumCheckpointBytes else {
            throw ValidationFeeFinalityErrorV1.invalidInput
        }
        #if canImport(Darwin)
        let bridge = NoritoNativeBridge.shared
        guard bridge.isAvailable,
              let invoke = bridge.resolveNativeSymbol("connect_norito_validation_fee_current_policy_proof_verify_v1", as: VerifyFn.self),
              let free = bridge.resolveNativeSymbol("connect_norito_free", as: FreeFn.self) else {
            throw ValidationFeeFinalityErrorV1.bridgeUnavailable
        }
        var projection: UnsafeMutablePointer<UInt8>?, promoted: UnsafeMutablePointer<UInt8>?
        var projectionLength: CUnsignedLong = 0, promotedLength: CUnsignedLong = 0
        defer {
            if let projection { free(projection) }
            if let promoted, promoted != projection { free(promoted) }
        }
        let status = proof.withUnsafeBytes { proofBytes in networkID.withUnsafeBytes { networkBytes in
            policyChainGenesisHash.withUnsafeBytes { genesisBytes in checkpoint.withUnsafeBytes { checkpointBytes in
                invoke(proofBytes.bindMemory(to: UInt8.self).baseAddress, CUnsignedLong(proofBytes.count),
                    networkBytes.bindMemory(to: UInt8.self).baseAddress, CUnsignedLong(networkBytes.count),
                    genesisBytes.bindMemory(to: UInt8.self).baseAddress, CUnsignedLong(genesisBytes.count),
                    checkpointBytes.bindMemory(to: UInt8.self).baseAddress, CUnsignedLong(checkpointBytes.count),
                    &projection, &projectionLength, &promoted, &promotedLength)
            }}
        }}
        guard status == 0 else { throw ValidationFeeFinalityErrorV1.nativeRejected(status) }
        guard let projection, let promoted, projection != promoted,
              projectionLength > 0, projectionLength <= maximumProjectionBytes,
              promotedLength > 0, promotedLength <= maximumCheckpointBytes else {
            throw ValidationFeeFinalityErrorV1.invalidNativeOutput
        }
        return .init(projectionJSON: Data(bytes: projection, count: Int(projectionLength)),
                     promotedCheckpoint: Data(bytes: promoted, count: Int(promotedLength)))
        #else
        throw ValidationFeeFinalityErrorV1.bridgeUnavailable
        #endif
    }
}
