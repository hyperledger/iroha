import Foundation

public enum NativeFinalityCheckpointErrorV1: Error, Equatable, Sendable {
    case invalidInput
    case bridgeUnavailable
    case nativeRejected(Int32)
    case invalidNativeResult
}

/// An authenticated historical Global tip. It supplies neither current FI state,
/// freshness nor physical route permission. Its selectors must be independently
/// admitted from the local signed runtime, never copied from a proof response.
public struct VerifiedFiCheckpointSelectionV1: Sendable {
    public let height: UInt64
    public let contextID: Data
    public let blockHash: Data
    fileprivate init(height: UInt64, contextID: Data, blockHash: Data) {
        self.height = height; self.contextID = contextID; self.blockHash = blockHash
    }
}

public enum NativeFinalityCheckpointV1 {
    public static let maximumCheckpointBytes = 68 * 1024 * 1024

    #if canImport(Darwin)
    private typealias VerifyFn = @convention(c) (
        UnsafePointer<UInt8>?, UInt, UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt, UnsafePointer<UInt8>?, UInt,
        UnsafePointer<UInt8>?, UInt, UnsafePointer<UInt8>?, UInt,
        UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<UInt>?
    ) -> Int32
    private typealias FreeFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    #endif

    public static func verifyFiCheckpointSelectionV1(
        checkpointBytes: Data, networkId: NetworkId, expectedChain: String,
        expectedSHA256: Data, expectedHeight: UInt64, expectedContextID: Data
    ) throws -> VerifiedFiCheckpointSelectionV1 {
        guard !checkpointBytes.isEmpty, checkpointBytes.count <= maximumCheckpointBytes,
              !expectedChain.isEmpty, expectedChain.utf8.count <= 1024,
              expectedChain == expectedChain.trimmingCharacters(in: .whitespacesAndNewlines),
              !expectedChain.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
              expectedSHA256.count == 32, expectedSHA256.contains(where: { $0 != 0 }),
              expectedContextID.count == 32, expectedContextID.contains(where: { $0 != 0 }),
              expectedHeight > 0, expectedHeight < UInt64.max else {
            throw NativeFinalityCheckpointErrorV1.invalidInput
        }
        #if canImport(Darwin)
        let bridge = NoritoNativeBridge.shared
        guard bridge.isAvailable,
              let verify: VerifyFn = bridge.resolveNativeSymbol("connect_norito_verify_fi_checkpoint_selection_v1", as: VerifyFn.self),
              let free: FreeFn = bridge.resolveNativeSymbol("connect_norito_free", as: FreeFn.self) else {
            throw NativeFinalityCheckpointErrorV1.bridgeUnavailable
        }
        let network = Data(networkId.literal.utf8), chain = Data(expectedChain.utf8)
        let height = Data(String(expectedHeight).utf8)
        var output: UnsafeMutablePointer<UInt8>?
        var outputLength: UInt = 0
        let status = checkpointBytes.withUnsafeBytes { cp in
            network.withUnsafeBytes { network in
                chain.withUnsafeBytes { chain in
                    expectedSHA256.withUnsafeBytes { sha in
                        height.withUnsafeBytes { height in
                            expectedContextID.withUnsafeBytes { context in
                                verify(cp.bindMemory(to: UInt8.self).baseAddress, UInt(cp.count),
                                    network.bindMemory(to: UInt8.self).baseAddress, UInt(network.count),
                                    chain.bindMemory(to: UInt8.self).baseAddress, UInt(chain.count),
                                    sha.bindMemory(to: UInt8.self).baseAddress, UInt(sha.count),
                                    height.bindMemory(to: UInt8.self).baseAddress, UInt(height.count),
                                    context.bindMemory(to: UInt8.self).baseAddress, UInt(context.count),
                                    &output, &outputLength)
                            }
                        }
                    }
                }
            }
        }
        defer { if let output { free(UnsafeMutableRawPointer(output)) } }
        guard status == 0 else { throw NativeFinalityCheckpointErrorV1.nativeRejected(status) }
        guard let output, outputLength > 0, outputLength <= 1024 else {
            throw NativeFinalityCheckpointErrorV1.invalidNativeResult
        }
        return try decodeNativeResult(Data(bytes: output, count: Int(outputLength)),
            expectedHeight: expectedHeight, expectedContextID: expectedContextID)
        #else
        throw NativeFinalityCheckpointErrorV1.bridgeUnavailable
        #endif
    }

    static func decodeNativeResult(_ bytes: Data, expectedHeight: UInt64,
                                  expectedContextID: Data) throws -> VerifiedFiCheckpointSelectionV1 {
        guard !bytes.isEmpty, bytes.count <= 1024,
              let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: String],
              Set(object.keys) == ["height", "context_id", "block_hash"],
              let heightText = object["height"], let height = UInt64(heightText),
              height > 0, height < UInt64.max, String(height) == heightText, height == expectedHeight,
              let contextText = object["context_id"], let context = hex(contextText),
              context == expectedContextID,
              let blockText = object["block_hash"], let block = hex(blockText), block[31] & 1 == 1,
              bytes == Data("{\"height\":\"\(heightText)\",\"context_id\":\"\(contextText)\",\"block_hash\":\"\(blockText)\"}".utf8) else {
            throw NativeFinalityCheckpointErrorV1.invalidNativeResult
        }
        return .init(height: height, contextID: context, blockHash: block)
    }

    private static func hex(_ value: String) -> Data? {
        let utf8 = Array(value.utf8)
        guard utf8.count == 64 else { return nil }
        func digit(_ byte: UInt8) -> UInt8? {
            switch byte { case 48...57: return byte - 48; case 97...102: return byte - 87; default: return nil }
        }
        var result = Data(capacity: 32)
        for index in stride(from: 0, to: 64, by: 2) {
            guard let first = digit(utf8[index]), let second = digit(utf8[index + 1]) else { return nil }
            result.append(first * 16 + second)
        }
        return result.contains(where: { $0 != 0 }) ? result : nil
    }
}
