import Foundation
import XCTest
@testable import IrohaSwift

/// Exact Rust-produced `GET /v1/pipeline/preflight` body; never a hand-written golden.
///
/// `fixtures/torii/pipeline_preflight.json` is generated from Torii's `PipelinePreflightResponse`
/// by `cargo test -p iroha_torii --lib pipeline_preflight_fixture`.
enum PipelinePreflightFixture {
    static func data() throws -> Data {
        var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        while directory.path != "/" {
            let path = directory.appendingPathComponent("fixtures/torii/pipeline_preflight.json")
            if FileManager.default.fileExists(atPath: path.path) {
                return try Data(contentsOf: path)
            }
            directory.deleteLastPathComponent()
        }
        throw CocoaError(.fileNoSuchFile)
    }

    static func object() throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: data()) as? [String: Any] else {
            throw CocoaError(.fileReadCorruptFile)
        }
        return object
    }
}

final class PipelinePreflightFixtureTests: XCTestCase {
    private func decode(_ object: [String: Any]) throws -> ToriiPipelinePreflight {
        try JSONDecoder().decode(
            ToriiPipelinePreflight.self,
            from: JSONSerialization.data(withJSONObject: object)
        )
    }

    private func mutated(
        _ section: String?,
        _ mutate: (inout [String: Any]) -> Void
    ) throws -> [String: Any] {
        var object = try PipelinePreflightFixture.object()
        guard let section else {
            mutate(&object)
            return object
        }
        var nested = try XCTUnwrap(object[section] as? [String: Any])
        mutate(&nested)
        object[section] = nested
        return object
    }

    private func status(
        queueSize: Int,
        nonEmptyElapsedMs: Int,
        blockElapsedMs: Int = 0
    ) throws -> ToriiStatusPayload {
        try ToriiStatusPayload(raw: [
            "queue_size": .number(Double(queueSize)),
            "time_since_last_non_empty_block_ms": .number(Double(nonEmptyElapsedMs)),
            "time_since_last_block_ms": .number(Double(blockElapsedMs)),
        ])
    }

    func testFixtureDecodesEveryServedField() throws {
        let object = try PipelinePreflightFixture.object()
        let served = try XCTUnwrap(object["sumeragi"] as? [String: Any])
        XCTAssertEqual(Array(served.keys), ["block_cadence_ms"])

        let preflight = try JSONDecoder().decode(
            ToriiPipelinePreflight.self,
            from: PipelinePreflightFixture.data()
        )
        XCTAssertEqual(preflight.schemaVersion, 1)
        XCTAssertEqual(preflight.chainHeight, 42)
        XCTAssertEqual(preflight.sumeragi.blockCadenceMs, 1_000)
        XCTAssertEqual(preflight.admission.maxSignatures, 16)
        XCTAssertEqual(preflight.admission.maxInstructions, 4_096)
        XCTAssertEqual(preflight.admission.maxTxBytes, 1_048_576)
        XCTAssertEqual(preflight.admission.maxDecompressedBytes, 4_194_304)
        XCTAssertEqual(preflight.admission.maxMetadataDepth, 8)
        XCTAssertEqual(preflight.block.maxTransactions, 512)
        XCTAssertEqual(preflight.pipeline.signatureBatchMaxEd25519, 64)
        XCTAssertEqual(preflight.pipeline.signatureBatchMaxSecp256k1, 32)
        XCTAssertEqual(preflight.pipeline.signatureBatchMaxPqc, 12)
        XCTAssertEqual(preflight.pipeline.signatureBatchMaxBls, 24)
        XCTAssertEqual(preflight.pipeline.overlayMaxInstructions, 2_048)
        XCTAssertEqual(preflight.pipeline.ivmMaxCyclesUpperBound, 2_000_000)
        XCTAssertEqual(preflight.pipeline.ivmAdmissionCycleLimit, 1_000_000)
        XCTAssertEqual(preflight.pipeline.ivmMaxDecodedInstructions, 131_072)
        XCTAssertEqual(preflight.queue.size, 3)
        XCTAssertEqual(preflight.queue.queued, 2)
        XCTAssertEqual(preflight.queue.inflight, 1)

        let fees = try XCTUnwrap(object["fees"] as? [String: Any])
        XCTAssertEqual(preflight.fees.feeAssetId, fees["fee_asset_id"] as? String)
        XCTAssertEqual(preflight.fees.feeSinkAccountId, fees["fee_sink_account_id"] as? String)
        XCTAssertEqual(preflight.fees.baseFee, "0.1")
        XCTAssertEqual(preflight.fees.perByteFee, "0.0002")
        XCTAssertEqual(preflight.fees.perInstructionFee, "0.001")
        XCTAssertEqual(preflight.fees.perGasUnitFee, "0.00005")
        XCTAssertEqual(
            preflight.fees.sponsorVaultCustodyAccountId,
            fees["sponsor_vault_custody_account_id"] as? String
        )
        XCTAssertNotEqual(preflight.fees.feeSinkAccountId, preflight.fees.sponsorVaultCustodyAccountId)
        XCTAssertEqual(
            preflight.fees.successfulClaimFeeExemptAuthorities,
            fees["successful_claim_fee_exempt_authorities"] as? [String]
        )
        XCTAssertEqual(preflight.fees.successfulClaimFeeExemptAuthorities.count, 1)
    }

    func testStallThresholdIsTwentyServedBlockCadences() throws {
        let preflight = try decode(PipelinePreflightFixture.object())
        let threshold = 20 * 1_000

        XCTAssertEqual(ToriiPipelinePreflight.stallBlockCadences, 20)
        XCTAssertEqual(preflight.stallThresholdMs, threshold)
        XCTAssertFalse(preflight.isStatusStalled(try status(queueSize: 1, nonEmptyElapsedMs: threshold)))
        XCTAssertTrue(preflight.isStatusStalled(try status(queueSize: 1, nonEmptyElapsedMs: threshold + 1)))
        XCTAssertFalse(preflight.isStatusStalled(try status(queueSize: 0, nonEmptyElapsedMs: threshold + 1)))
        // Before the first non-empty block the elapsed time since any block is used.
        XCTAssertTrue(
            preflight.isStatusStalled(
                try status(queueSize: 1, nonEmptyElapsedMs: 0, blockElapsedMs: threshold + 1)
            )
        )
        XCTAssertFalse(
            preflight.isStatusStalled(
                try status(queueSize: 1, nonEmptyElapsedMs: 0, blockElapsedMs: threshold)
            )
        )

        let slow = try decode(mutated("sumeragi") { $0["block_cadence_ms"] = 5_000 })
        XCTAssertEqual(slow.stallThresholdMs, 100_000)
        let huge = try decode(mutated("sumeragi") { $0["block_cadence_ms"] = Int.max })
        XCTAssertEqual(huge.stallThresholdMs, Int.max)
    }

    func testRejectsTheRetiredSumeragiTimingFields() throws {
        for field in ["block_time_ms", "commit_time_ms", "stall_threshold_ms"] {
            let object = try mutated("sumeragi") { $0[field] = 6_000 }
            XCTAssertThrowsError(try decode(object), field) { error in
                XCTAssertTrue(
                    String(describing: error).contains("pipeline preflight sumeragi contains an unknown or retired field"),
                    String(describing: error)
                )
            }
        }
    }

    func testRequiresAPositiveIntegerBlockCadence() throws {
        let cases: [(String, (inout [String: Any]) -> Void)] = [
            ("missing", { $0.removeValue(forKey: "block_cadence_ms") }),
            ("zero", { $0["block_cadence_ms"] = 0 }),
            ("negative", { $0["block_cadence_ms"] = -1 }),
            ("string", { $0["block_cadence_ms"] = "1000" }),
            ("fraction", { $0["block_cadence_ms"] = 1.5 }),
        ]
        for (name, mutate) in cases {
            XCTAssertThrowsError(try decode(mutated("sumeragi", mutate)), name)
        }
    }

    func testRejectsFieldsToriiDoesNotServe() throws {
        for section in [nil, "admission", "block", "pipeline", "queue", "fees"] as [String?] {
            let object = try mutated(section) { $0["unserved_field"] = 1 }
            XCTAssertThrowsError(try decode(object), section ?? "root") { error in
                XCTAssertTrue(
                    String(describing: error).contains("contains an unknown or retired field"),
                    String(describing: error)
                )
            }
        }
    }

    func testRequiresTheServedFeeValues() throws {
        let cases: [(String, (inout [String: Any]) -> Void)] = [
            ("missing fee asset", { $0.removeValue(forKey: "fee_asset_id") }),
            ("empty fee asset", { $0["fee_asset_id"] = "" }),
            ("numeric base fee", { $0["base_fee"] = 0 }),
            ("unknown settlement", { $0["settlement_mode"] = "burn" }),
            ("alias fee sink", { $0["fee_sink_account_id"] = "fees@system" }),
            ("alias exempt authority", { $0["successful_claim_fee_exempt_authorities"] = ["authority@system"] }),
        ]
        for (name, mutate) in cases {
            XCTAssertThrowsError(try decode(mutated("fees", mutate)), name)
        }
        XCTAssertThrowsError(try decode(mutated("fees") { $0["settlement_mode"] = "lane_relay_burn" }))
    }
}
