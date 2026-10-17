import Foundation
import Darwin
import CryptoKit
import XCTest
@testable import IrohaSwift

// Pinned public originals exercise the actual native codec. No wallet is opened or value moved.
// The finality test deliberately has no selected transaction row, so its final status
// is a refusal. A returned -508 is NOT asserted to be an authenticated positive result.
final class KagemushaWalletNativePublicFinalityStackV1Tests: XCTestCase {
    private var directory: URL { Bundle.module.resourceURL! }
    private let network = "hash:CA7BEBB1579D7F490C23BCBABD27E116BF2F921A7DB69862F0AD28E22257B465#450F"
    private let chain = "fc56984b-2be7-431d-840e-21514d1883f0"

    private final class Call: @unchecked Sendable {
        let body: () throws -> Void
        var result: Result<Void, Error>?
        init(_ body: @escaping () throws -> Void) { self.body = body }
    }
    private func onSmallCaller(_ body: @escaping () throws -> Void) throws {
        var attributes = pthread_attr_t()
        guard pthread_attr_init(&attributes) == 0 else { throw Failure.pthread }
        defer { pthread_attr_destroy(&attributes) }
        // Darwin simulator may report a small runtime reservation above the request.
        // Start at 512 KiB and require the actual caller to remain no larger than the
        // 544 KiB stack on which the physical-device finality decoder exhausted its stack.
        guard pthread_attr_setstacksize(&attributes, 512 * 1024) == 0 else { throw Failure.pthread }
        let call = Call(body)
        let retained = Unmanaged.passRetained(call)
        var thread: pthread_t?
        let status = pthread_create(&thread, &attributes, { pointer in
            let call = Unmanaged<Call>.fromOpaque(pointer).takeRetainedValue()
            call.result = Result {
                let actual = pthread_get_stacksize_np(pthread_self())
                XCTAssertGreaterThanOrEqual(actual, 512 * 1024)
                XCTAssertLessThanOrEqual(actual, 544 * 1024)
                print("public-stack-regression: actualCallerStackBytes=\(actual)")
                try call.body()
            }
            return nil
        }, retained.toOpaque())
        guard status == 0, let thread else { retained.release(); throw Failure.pthread }
        guard pthread_join(thread, nil) == 0 else { throw Failure.pthread }
        try XCTUnwrap(call.result).get()
    }
    private enum Failure: Error { case pthread, missingSymbol, native(Int32), output }
    private func bytes(_ name: String, sha256: String? = nil) throws -> Data {
        let data = try Data(contentsOf: directory.appendingPathComponent(name))
        if let sha256 {
            let actual = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            XCTAssertEqual(actual, sha256)
            guard actual == sha256 else { throw Failure.output }
        }
        return data
    }
    private func checkpoint() throws -> Data {
        try bytes("kagemusha-public-checkpoint49.norito", sha256: "38d2535a113c1c9aa2697d5eb4e7854fd295eb68a80347fcf9f9e50baa5e5ddb")
    }
    private typealias RequestFn = @convention(c) (UnsafePointer<UInt8>?, UInt, UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<UInt>?) -> Int32
    private typealias FreeFn = @convention(c) (UnsafeMutableRawPointer?) -> Void

    private func canonicalCheckpointRequest(_ checkpoint: Data) throws -> Data {
        let bridge = NoritoNativeBridge.shared
        guard bridge.isAvailable,
              let request: RequestFn = bridge.resolveNativeSymbol("connect_norito_validation_fee_current_policy_proof_request_v1", as: RequestFn.self),
              let free: FreeFn = bridge.resolveNativeSymbol("connect_norito_free", as: FreeFn.self) else { throw Failure.missingSymbol }
        var pointer: UnsafeMutablePointer<UInt8>?
        var length: UInt = 0
        let status = checkpoint.withUnsafeBytes { raw in
            request(raw.bindMemory(to: UInt8.self).baseAddress, UInt(checkpoint.count), &pointer, &length)
        }
        defer { if let pointer { free(UnsafeMutableRawPointer(pointer)) } }
        guard status == 0 else { throw Failure.native(status) }
        guard let pointer, length > 0, length < 4096 else { throw Failure.output }
        return Data(bytes: pointer, count: Int(length))
    }

    func testActualCanonicalCheckpointCodecFromAtMost544KiBCaller() throws {
        let original = try checkpoint()
        try onSmallCaller {
            try KagemushaWalletNativeWorkerV1.perform(workClass: .foreground) {
                XCTAssertGreaterThanOrEqual(pthread_get_stacksize_np(pthread_self()), 8 * 1024 * 1024)
                let first = try self.canonicalCheckpointRequest(original)
                let second = try self.canonicalCheckpointRequest(original)
                XCTAssertEqual(first, second)
                var truncated = original
                truncated.removeLast()
                XCTAssertThrowsError(try self.canonicalCheckpointRequest(truncated))
                print("public-stack-regression: canonical-checkpoint-codec succeeded; worker=\(pthread_get_stacksize_np(pthread_self())); requestBytes=\(first.count)")
            }
        }
    }

    func testActualPublicProofChainRefusesMissingRowAndMutationsFromAtMost544KiBCaller() throws {
        let original = try checkpoint()
        let page = try bytes("kagemusha-public-proof49-50-page.json", sha256: "c884a7af7743edf38a81ff9f6c6d60cff15625d11fd8300da2a9f8f32165eef9")
        var changed = try XCTUnwrap(JSONSerialization.jsonObject(with: page) as? [[String: Any]])
        var wire = try XCTUnwrap(changed[1]["block_wire"] as? [UInt8])
        guard !wire.isEmpty else { throw Failure.output }
        wire.removeLast()
        changed[1]["block_wire"] = wire
        let malformed = try JSONSerialization.data(withJSONObject: changed, options: [.sortedKeys])
        var hash = Data(repeating: 0, count: 32)
        hash[31] = 1
        try onSmallCaller {
            try KagemushaWalletNativeWorkerV1.perform(workClass: .foreground) {
                XCTAssertGreaterThanOrEqual(pthread_get_stacksize_np(pthread_self()), 8 * 1024 * 1024)
                for candidate in [page, malformed] {
                    XCTAssertThrowsError(try CommittedTransactionInclusionV1.verify(
                        response: Data([0]), nativeFinalityProofChainJSON: candidate,
                        networkId: NetworkId(literal: self.network), expectedChain: self.chain,
                        trustedCheckpoint: original, transactionHash: hash
                    )) { error in
                        XCTAssertEqual(error as? CommittedTransactionInclusionErrorV1, .nativeRejected(-508))
                    }
                }
                print("public-stack-regression: genuine public proof chain and malformed chain returned typed native refusal; no authenticated transaction success claimed")
            }
        }
    }
}
