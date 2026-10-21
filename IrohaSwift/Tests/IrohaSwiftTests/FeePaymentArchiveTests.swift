import Foundation
import XCTest
@testable import IrohaSwift

final class FeePaymentArchiveTests: XCTestCase {
    func testSelectionRetainsPayerRevisionAndGasButDropsOnlyQuotedLimits() throws {
        let program = try FeeSponsorProgramId(
            sponsor: "testuﾛ1PｵEmｷjMZZﾑﾙeｱﾁﾎﾅﾂﾊmECepdbﾎｳ2uWﾃｸﾊﾘvｵi2ｦP1Y18A", name: "wallet")
        let limit = try FeeChargeLimit(kind: .pipelineGas,
            assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM", maxAmount: "2")
        let intent = FeePaymentIntent.sponsor(programId: program, programRevision: 7,
            chargeLimits: [limit], gasLimit: 100)
        XCTAssertEqual(intent.payerSelection,
            .sponsor(programId: program, programRevision: 7, chargeLimits: [], gasLimit: 100))
        XCTAssertNotEqual(try intent.canonicalNoritoArchive(), try intent.payerSelection.canonicalNoritoArchive())
        XCTAssertNotEqual(try intent.payerSelection.canonicalNoritoArchive(),
            try FeePaymentIntent.authority(chargeLimits: [], gasLimit: 100).canonicalNoritoArchive())
    }

    func testStandaloneArchivePreservesCompactCanonicalPayloadAndSchema() throws {
        let intent = FeePaymentIntent.authority(chargeLimits: [], gasLimit: nil)
        let bytes = try intent.canonicalNoritoArchive()
        let decoded = try XCTUnwrap(noritoDecodeFrame(bytes))
        XCTAssertEqual(decoded.header.schema,
            noritoSchemaHash(forTypeName: "iroha_data_model::transaction::signed::model::FeePaymentIntent"))
        XCTAssertEqual(decoded.header.flags, NoritoHeader.compactLen)
        XCTAssertEqual(decoded.payload, Data([0, 0, 0, 0, 11, 8, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]))
        // Cross-SDK archive originals emitted by Kotlin's maintained canonical adapter.
        XCTAssertEqual(bytes.map { String(format: "%02x", $0) }.joined(),
            "4e5254300000b2af78f4ab51dfb6898be9939425dfe4001000000000000000ad72af85285db4ee02000000000b0800000000000000000100")
        let bounded = try FeePaymentIntent.authority(chargeLimits: [], gasLimit: 100).canonicalNoritoArchive()
        XCTAssertEqual(bounded.map { String(format: "%02x", $0) }.joined(),
            "4e5254300000b2af78f4ab51dfb6898be9939425dfe40019000000000000003b000b74a60a379d0200000000140800000000000000000a01086400000000000000")
        XCTAssertThrowsError(try FeePaymentIntent.authority(chargeLimits: [], gasLimit: 0).canonicalNoritoArchive())
    }
}
