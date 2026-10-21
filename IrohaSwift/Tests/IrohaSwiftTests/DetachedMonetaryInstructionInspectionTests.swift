import Foundation
import XCTest
@testable import IrohaSwift

final class DetachedMonetaryInstructionInspectionTests: XCTestCase {
    private let legs = """
    [{"leg_id":"israel","source_account_id":"owner","destination_account_id":"israel-wallet","asset_definition_id":"ds","amount":"20"},
    {"leg_id":"roman","source_account_id":"owner","destination_account_id":"roman-wallet","asset_definition_id":"ds","amount":"60"}]
    """

    private func batch(_ mode: String) -> String {
        """
        {"kind":"asset_transfer_batch","mode":"\(mode)","entries":\(legs)}
        """
    }

    private let escrow = """
    {"kind":"conditional_escrow_open","escrow_id":"laptop","asset_definition_id":"ds","beneficiary":"intel","amount":"20",
    "expires_at_ms":1700604800000,"evidence_hashes":["document-digest"],"conditions":[
    {"kind":"oracle","id":"product","attestor":"product-asp","sequence":1,"predicate":{"kind":"equals","value":{"kind":"text","value":"i7"}}},
    {"kind":"oracle","id":"delivery","attestor":"delivery-asp","sequence":2,"predicate":{"kind":"quantity_at_most","value":"3"}},
    {"kind":"within","id":"confirmation","duration_ms":604800000}]}
    """

    func testBatchRetainsNativeModeAndExactOrderedLegs() throws {
        for mode in ["atomic", "independent"] {
            let value = try JSONDecoder().decode(DetachedAssetTransferBatchInspection.self, from: Data(batch(mode).utf8))
            XCTAssertEqual(value.mode.rawValue, mode)
            XCTAssertEqual(value.entries.map(\.legId), ["israel", "roman"])
            XCTAssertEqual(value.entries.map(\.destinationAccountId), ["israel-wallet", "roman-wallet"])
            XCTAssertEqual(value.entries.map(\.amount), ["20", "60"])
        }
    }

    func testBatchRejectsUnknownModesKindsDuplicateIdsAndHiddenLegFields() {
        let valid = batch("independent")
        for input in [
            batch("best_effort"),
            valid.replacingOccurrences(of: "\"asset_transfer_batch\"", with: "\"contract_call\""),
            valid.replacingOccurrences(of: "\"leg_id\":\"roman\"", with: "\"leg_id\":\"israel\""),
            valid.replacingOccurrences(of: "\"amount\":\"60\"", with: "\"amount\":\"60\",\"extra\":true"),
            valid.replacingOccurrences(of: "\"entries\":", with: "\"transfers\":"),
            valid.replacingOccurrences(of: legs, with: "[]"),
        ] {
            XCTAssertThrowsError(try JSONDecoder().decode(DetachedAssetTransferBatchInspection.self, from: Data(input.utf8)))
        }
    }

    func testEscrowSeparatesAttestorsPredicatesSequenceAndTimeWindow() throws {
        let value = try JSONDecoder().decode(DetachedConditionalEscrowInspection.self, from: Data(escrow.utf8))
        XCTAssertEqual(value.amount, "20")
        XCTAssertEqual(value.beneficiary, "intel")
        XCTAssertEqual(value.conditions, [
            .oracle(id: "product", attestor: "product-asp", sequence: 1, predicate: .equals(.text("i7"))),
            .oracle(id: "delivery", attestor: "delivery-asp", sequence: 2, predicate: .quantityAtMost("3")),
            .within(id: "confirmation", durationMs: 604_800_000),
        ])
        XCTAssertEqual(value.expiresAtMs, 1_700_604_800_000)
        XCTAssertEqual(value.evidenceHashes, ["document-digest"])
    }

    func testEscrowRejectsUnknownTermsTypedFactSubstitutionAndInvalidWindows() {
        for input in [
            escrow.replacingOccurrences(of: "\"conditional_escrow_open\"", with: "\"other\""),
            escrow.replacingOccurrences(of: "\"quantity_at_most\"", with: "\"approve_any\""),
            escrow.replacingOccurrences(of: "\"value\":\"i7\"", with: "\"value\":true"),
            escrow.replacingOccurrences(of: "\"sequence\":2", with: "\"sequence\":0"),
            escrow.replacingOccurrences(of: "\"sequence\":2", with: "\"sequence\":4294967296"),
            escrow.replacingOccurrences(of: "\"duration_ms\":604800000", with: "\"duration_ms\":0"),
            escrow.replacingOccurrences(of: "\"duration_ms\":604800000", with: "\"duration_ms\":604800000,\"cancel_anytime\":true"),
            escrow.replacingOccurrences(of: "\"expires_at_ms\":1700604800000", with: "\"expires_at_ms\":null"),
        ] {
            XCTAssertThrowsError(try JSONDecoder().decode(DetachedConditionalEscrowInspection.self, from: Data(input.utf8)))
        }
    }
}
