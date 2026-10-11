import Foundation
import XCTest
@testable import IrohaSwift

final class ConfidentialProverTests: XCTestCase {
    private let root = Data(repeating: 3, count: 32)

    private func note() throws -> ConfidentialInput {
        try ConfidentialInput(amount: 7, rho: Data(repeating: 4, count: 32),
                              diversifier: Data(repeating: 5, count: 32), leafIndex: 0)
    }
    private func wallet(_ driver: WalletDriver) throws -> ConfidentialProver {
        try ConfidentialProver(networkId: NetworkId(bytes: Data(repeating: 1, count: 32)),
                               assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                               spendKey: Data(repeating: 2, count: 32), driver: driver)
    }
    private var tree: ConfidentialTree { .commitments(root: root, leaves: [root]) }

    func testAmountFullWidthParsingAndPrivateDescriptions() throws {
        XCTAssertEqual(try ConfidentialAmount(decimal: "0"), 0)
        XCTAssertEqual(try ConfidentialAmount(decimal: "7"), 7)
        let carry = try ConfidentialAmount(decimal: "18446744073709551616")
        XCTAssertEqual(carry.high, 1); XCTAssertEqual(carry.low, 0)
        let maximum = try ConfidentialAmount(decimal: "340282366920938463463374607431768211455")
        XCTAssertEqual(maximum.high, .max); XCTAssertEqual(maximum.low, .max)
        XCTAssertEqual(maximum.decimal, "340282366920938463463374607431768211455")
        XCTAssertEqual(carry.decimal, "18446744073709551616")
        XCTAssertEqual(ConfidentialAmount(0).decimal, "0")
        for invalid in ["", "00", "01", "+1", "-1", " 1", "1 ", "１", "1.0",
                        "340282366920938463463374607431768211456"] {
            XCTAssertThrowsError(try ConfidentialAmount(decimal: invalid))
        }
        XCTAssertEqual(String(reflecting: try note()), "ConfidentialInput([REDACTED])")
        XCTAssertEqual(String(reflecting: tree), "ConfidentialTree([REDACTED])")
        let driver = WalletDriver()
        let prover = try wallet(driver)
        XCTAssertEqual(String(reflecting: prover), "ConfidentialProver(privateContext: [REDACTED])")
        try prover.close(); try prover.close()
        XCTAssertEqual(driver.closeCount, 1)
        for asset in ["rose#wonderland", " 62Fk4FPcMuLvW5QjDGNF2a4jAmjM", "invalid"] {
            XCTAssertThrowsError(try ConfidentialProver(
                networkId: TestNetworkIds.canonical, assetDefinitionId: asset,
                spendKey: Data(repeating: 2, count: 32), driver: driver
            ))
        }
    }

    func testAcceptedBackgroundProofSurvivesCloseAndCancellation() async throws {
        let driver = WalletDriver()
        let started = expectation(description: "background proof entered")
        driver.entered = { started.fulfill() }
        driver.gate = DispatchSemaphore(value: 0)
        let prover = try wallet(driver)
        let input = try note()
        let job = Task { try await prover.proveUnshield(tree: tree, inputs: [input], publicAmount: 7) }
        await fulfillment(of: [started], timeout: 5)
        try prover.close()
        job.cancel()
        driver.gate?.signal()
        let proof = try await job.value
        XCTAssertEqual(proof.relation, .fullRedemption)
        XCTAssertEqual(proof.nullifiers.count, 1)
        XCTAssertEqual(proof.outputCommitments.count, 0)
        XCTAssertFalse(driver.provedOnMainThread)
        XCTAssertEqual(driver.proveCount, 1)
        XCTAssertEqual(driver.jobCloseCount, 1, "cleanup also covers failure before native consumption")
        XCTAssertEqual(driver.activeJobs, 0)
        do {
            _ = try await prover.proveUnshield(tree: tree, inputs: [input], publicAmount: 7)
            XCTFail("closed wallet accepted a new job")
        } catch { XCTAssertEqual(error as? ConfidentialProverError, .closed) }
    }

    func testPartialInputFailureClosesNativeJobBeforeReturning() async throws {
        let driver = WalletDriver(); driver.rejectInput = true
        let prover = try wallet(driver)
        do {
            _ = try await prover.proveUnshield(tree: tree, inputs: [try note()], publicAmount: 7)
            XCTFail("malformed note was accepted")
        } catch { XCTAssertEqual(error as? ConfidentialProverError, .native(code: -20)) }
        XCTAssertEqual(driver.jobCloseCount, 1)
        XCTAssertEqual(driver.proveCount, 0)
    }

    func testDriverFailureBeforeNativeConsumptionClosesJob() async throws {
        let driver = WalletDriver(); driver.rejectBeforeConsumption = true
        let prover = try wallet(driver)
        do {
            _ = try await prover.proveUnshield(tree: tree, inputs: [try note()], publicAmount: 7)
            XCTFail("driver failure was ignored")
        } catch { XCTAssertEqual(error as? ConfidentialProverError, .bridgeUnavailable) }
        XCTAssertEqual(driver.proveCount, 0)
        XCTAssertEqual(driver.jobCloseCount, 1)
        XCTAssertEqual(driver.activeJobs, 0)
    }

    func testTransferAndChangeSelectExactRelationsAndCounts() async throws {
        let driver = WalletDriver(); let prover = try wallet(driver)
        let output = try ConfidentialOutput(amount: 7, rho: Data(repeating: 6, count: 32),
                                            ownerTag: Data(repeating: 7, count: 32))
        let transfer = try await prover.proveTransfer(tree: tree, inputs: [try note()], outputs: [output])
        XCTAssertEqual(transfer.relation, .transfer)
        XCTAssertEqual(transfer.outputCommitments.count, 1)
        let change = try ConfidentialChange(amount: 3, rho: Data(repeating: 8, count: 32))
        let redemption = try await prover.proveUnshield(tree: tree, inputs: [try note()],
                                                         publicAmount: 4, change: change)
        XCTAssertEqual(redemption.relation, .redemptionWithChange)
        XCTAssertEqual(redemption.outputCommitments.count, 1)
        XCTAssertEqual(driver.proveCount, 2)
    }

    func testMismatchedPathAndMalformedNativeResultFailClosed() async throws {
        let driver = WalletDriver(); let prover = try wallet(driver)
        let path = try ZkAssetMerklePath(leafIndex: 1, siblings: Array(repeating: root, count: 16),
                                       directions: Data([1] + Array(repeating: 0, count: 15)),
                                       rootAtHeight: root, heightOrIndex: 1)
        do {
            _ = try await prover.proveUnshield(tree: .paths(root: root, paths: [path]),
                                               inputs: [try note()], publicAmount: 7)
            XCTFail("path for a different note was accepted")
        } catch { XCTAssertEqual(driver.jobCreateCount, 0) }
        driver.invalidResult = true
        do {
            _ = try await prover.proveUnshield(tree: tree, inputs: [try note()], publicAmount: 7)
            XCTFail("wrong native proof relation was accepted")
        } catch { XCTAssertEqual(error as? ConfidentialProverError, .invalidNativeOutput) }
        XCTAssertEqual(driver.proveCount, 1)
        XCTAssertEqual(driver.jobCloseCount, 1)
        XCTAssertEqual(driver.activeJobs, 0)
    }
}

/// Exercises wrapper scheduling/lifetimes only; native proofs have separate integration controls.
private final class WalletDriver: ConfidentialProverDriver, @unchecked Sendable {
    private let lock = NSLock()
    private var next: UInt64 = 1
    private var jobs: [UInt64: (transfer: Bool, root: Data, inputs: Int, outputs: Int)] = [:]
    private var counters = [0, 0, 0, 0]
    private var mainThread = false
    var gate: DispatchSemaphore?
    var entered: (() -> Void)?
    var rejectInput = false
    var rejectBeforeConsumption = false
    var invalidResult = false
    var closeCount: Int { snapshot(0) }
    var jobCloseCount: Int { snapshot(1) }
    var proveCount: Int { snapshot(2) }
    var jobCreateCount: Int { snapshot(3) }
    var provedOnMainThread: Bool { lock.lock(); defer { lock.unlock() }; return mainThread }
    var activeJobs: Int { lock.lock(); defer { lock.unlock() }; return jobs.count }
    private func snapshot(_ index: Int) -> Int { lock.lock(); defer { lock.unlock() }; return counters[index] }
    func create(network: NetworkId, asset: String, key: Data) throws -> UInt64 { 1 }
    func close(_ handle: UInt64) throws { lock.lock(); defer { lock.unlock() }; counters[0] += 1 }
    func closeJob(_ job: UInt64) {
        lock.lock(); defer { lock.unlock() }; jobs.removeValue(forKey: job); counters[1] += 1
    }
    func createJob(_ handle: UInt64, transfer: Bool, root: Data, publicAmount: ConfidentialAmount) throws -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        next += 1; jobs[next] = (transfer, root, 0, 0); counters[3] += 1; return next
    }
    func input(_ job: UInt64, note: ConfidentialInput) throws {
        if rejectInput { throw ConfidentialProverError.native(code: -20) }
        lock.lock(); defer { lock.unlock() }; jobs[job]!.inputs += 1
    }
    func output(_ job: UInt64, amount: ConfidentialAmount, rho: Data, owner: Data) throws {
        lock.lock(); defer { lock.unlock() }; jobs[job]!.outputs += 1
    }
    func evidence(_ job: UInt64, tree: ConfidentialTree) throws {}
    func prove(_ job: UInt64) throws -> Data {
        if rejectBeforeConsumption { throw ConfidentialProverError.bridgeUnavailable }
        lock.lock()
        let request = jobs.removeValue(forKey: job)!
        counters[2] += 1; mainThread = Thread.isMainThread
        lock.unlock()
        entered?()
        if let gate { XCTAssertEqual(gate.wait(timeout: .now() + 10), .success) }
        let relation = request.transfer ? "confidential_transfer" :
            (request.outputs == 0 ? "confidential_full_unshield" : "confidential_change_unshield")
        let hex = request.root.map { String(format: "%02x", $0) }.joined()
        return try JSONSerialization.data(withJSONObject: [
            "relation": invalidResult ? "wrong_relation" : relation,
            "backend": "pipa-r/pasta", "proof_hex": "abcd", "root_hex": hex,
            "nullifiers_hex": Array(repeating: hex, count: request.inputs),
            "output_commitments_hex": Array(repeating: hex, count: request.outputs),
        ])
    }
}
