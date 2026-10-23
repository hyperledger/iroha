import CryptoKit
import Foundation

public enum NativeFiCheckpointAdvanceErrorV1: Error, Equatable, Sendable {
    case invalidInput
    case bridgeUnavailable
    case nativeRejected(Int32)
    case invalidNativeResult
}

/// Historical native Global checkpoint advancement. It grants no current-state,
/// freshness or route permission. Persist its original proof page and provenance;
/// a caller must never replace a pending operation's original assertion floor.
public struct VerifiedFiCheckpointAdvanceV1: Sendable {
    public let checkpoint: Data
    public let checkpointSHA256: Data
    public let height: UInt64
    public let contextID: Data
    public let blockHash: Data
    public let anchorHeight: UInt64
    public let proofCount: Int
    fileprivate init(checkpoint: Data, checkpointSHA256: Data, height: UInt64, contextID: Data,
                     blockHash: Data, anchorHeight: UInt64, proofCount: Int) {
        self.checkpoint = checkpoint; self.checkpointSHA256 = checkpointSHA256
        self.height = height; self.contextID = contextID; self.blockHash = blockHash
        self.anchorHeight = anchorHeight; self.proofCount = proofCount
    }
}

public enum NativeFiCheckpointAdvanceV1 {
    public static let maximumProofCount = 4096
    public static let maximumProofBytes = 16 * 1024 * 1024
    public static let maximumCheckpointBytes = 68 * 1024 * 1024
    #if canImport(Darwin)
    private typealias AdvanceFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UnsafePointer<UInt8>?>?, UnsafePointer<UInt>?, UInt,
        UnsafePointer<UInt8>?, UInt, UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt, UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<UInt>?,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<UInt>?
    ) -> Int32
    private typealias FreeFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    #endif

    public static func advance(checkpoint: Data, proofOriginals: [Data], networkId: NetworkId,
                               expectedChain: String, expectedSHA256: Data,
                               expectedHeight: UInt64, expectedContextID: Data) throws -> VerifiedFiCheckpointAdvanceV1 {
        try validate(checkpoint: checkpoint, proofOriginals: proofOriginals, chain: expectedChain,
                     sha: expectedSHA256, height: expectedHeight, context: expectedContextID)
        #if canImport(Darwin)
        let bridge = NoritoNativeBridge.shared
        guard bridge.isAvailable,
              let advance: AdvanceFn = bridge.resolveNativeSymbol("connect_norito_advance_fi_checkpoint_v1", as: AdvanceFn.self),
              let free: FreeFn = bridge.resolveNativeSymbol("connect_norito_free", as: FreeFn.self) else {
            throw NativeFiCheckpointAdvanceErrorV1.bridgeUnavailable
        }
        let network = Data(networkId.literal.utf8), chain = Data(expectedChain.utf8)
        let height = Data(String(expectedHeight).utf8)
        // NSData owns stable read-only storage for every pointer until the single
        // synchronous C call returns; no escaped Data.withUnsafeBytes pointers.
        let owners = proofOriginals.map { NSData(data: $0) }
        let pointers: [UnsafePointer<UInt8>?] = owners.map { $0.bytes.assumingMemoryBound(to: UInt8.self) }
        let lengths = owners.map { UInt($0.length) }
        var output: UnsafeMutablePointer<UInt8>?, metadata: UnsafeMutablePointer<UInt8>?
        var outputLength: UInt = 0, metadataLength: UInt = 0
        let status = withExtendedLifetime(owners) {
            pointers.withUnsafeBufferPointer { pointers in
                lengths.withUnsafeBufferPointer { lengths in
                    checkpoint.withUnsafeBytes { cp in
                        network.withUnsafeBytes { network in
                            chain.withUnsafeBytes { chain in
                                expectedSHA256.withUnsafeBytes { sha in
                                    height.withUnsafeBytes { height in
                                        expectedContextID.withUnsafeBytes { context in
                                            advance(cp.bindMemory(to: UInt8.self).baseAddress, UInt(cp.count),
                                                pointers.baseAddress, lengths.baseAddress, UInt(pointers.count),
                                                network.bindMemory(to: UInt8.self).baseAddress, UInt(network.count),
                                                chain.bindMemory(to: UInt8.self).baseAddress, UInt(chain.count),
                                                sha.bindMemory(to: UInt8.self).baseAddress, UInt(sha.count),
                                                height.bindMemory(to: UInt8.self).baseAddress, UInt(height.count),
                                                context.bindMemory(to: UInt8.self).baseAddress, UInt(context.count),
                                                &output, &outputLength, &metadata, &metadataLength)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        defer {
            if let output { free(UnsafeMutableRawPointer(output)) }
            if let metadata { free(UnsafeMutableRawPointer(metadata)) }
        }
        guard status == 0 else { throw NativeFiCheckpointAdvanceErrorV1.nativeRejected(status) }
        guard let output, outputLength > 0, outputLength <= maximumCheckpointBytes,
              let metadata, metadataLength > 0, metadataLength <= 4096 else {
            throw NativeFiCheckpointAdvanceErrorV1.invalidNativeResult
        }
        let bytes = Data(bytes: metadata, count: Int(metadataLength))
        guard try bridge.canonicalizeJSONBlake3(bytes).canonicalJSON == bytes else {
            throw NativeFiCheckpointAdvanceErrorV1.invalidNativeResult
        }
        return try decodeNativeResult(bytes, checkpoint: Data(bytes: output, count: Int(outputLength)),
            network: networkId.literal, chain: expectedChain, anchorHeight: expectedHeight,
            proofCount: proofOriginals.count)
        #else
        throw NativeFiCheckpointAdvanceErrorV1.bridgeUnavailable
        #endif
    }

    static func validate(checkpoint: Data, proofOriginals: [Data], chain: String,
                         sha: Data, height: UInt64, context: Data) throws {
        guard !checkpoint.isEmpty, checkpoint.count <= maximumCheckpointBytes,
              (2...maximumProofCount).contains(proofOriginals.count),
              !chain.isEmpty, chain.utf8.count <= 1024,
              chain == chain.trimmingCharacters(in: .whitespacesAndNewlines),
              !chain.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
              sha.count == 32, sha.contains(where: { $0 != 0 }),
              context.count == 32, context.contains(where: { $0 != 0 }),
              height > 0, height < UInt64.max else { throw NativeFiCheckpointAdvanceErrorV1.invalidInput }
        var remaining = maximumProofBytes
        for proof in proofOriginals {
            guard !proof.isEmpty, proof.count <= remaining else { throw NativeFiCheckpointAdvanceErrorV1.invalidInput }
            remaining -= proof.count
        }
    }

    static func decodeNativeResult(_ bytes: Data, checkpoint: Data, network: String, chain: String,
                                   anchorHeight: UInt64, proofCount: Int) throws -> VerifiedFiCheckpointAdvanceV1 {
        guard !bytes.isEmpty, bytes.count <= 4096,
              !checkpoint.isEmpty, checkpoint.count <= maximumCheckpointBytes,
              (2...maximumProofCount).contains(proofCount), anchorHeight > 0,
              let object = try JSONSerialization.jsonObject(with: bytes) as? [String: String],
              Set(object.keys) == ["schema", "networkId", "chainId", "anchorHeight", "height", "proofCount", "checkpointSha256", "contextId", "blockHash"],
              object["schema"] == "iroha.fi-checkpoint-advance.verified.v1",
              object["networkId"] == network, object["chainId"] == chain,
              object["anchorHeight"] == String(anchorHeight), object["proofCount"] == String(proofCount),
              let heightText = object["height"], let height = UInt64(heightText), String(height) == heightText,
              height > anchorHeight, height < UInt64.max, height - anchorHeight == UInt64(proofCount - 1),
              let shaText = object["checkpointSha256"], let sha = raw32(shaText),
              sha == Data(SHA256.hash(data: checkpoint)),
              let contextText = object["contextId"], let context = raw32(contextText),
              let blockText = object["blockHash"], let block = raw32(blockText), block[31] & 1 == 1 else {
            throw NativeFiCheckpointAdvanceErrorV1.invalidNativeResult
        }
        return .init(checkpoint: checkpoint, checkpointSHA256: sha, height: height, contextID: context,
                     blockHash: block, anchorHeight: anchorHeight, proofCount: proofCount)
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
