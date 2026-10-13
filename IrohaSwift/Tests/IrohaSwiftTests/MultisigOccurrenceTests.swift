import Foundation
import XCTest
@testable import IrohaSwift

final class MultisigOccurrenceTests: XCTestCase {
    private let account = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
    private let otherAccount = "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"

    func testNativeIdentityRetainsRetriesAndSeparatesNewPayments() throws {
        let nonce = String(repeating: "07", count: 32)
        let first = try MultisigOccurrence.derive(networkId: TestNetworkIds.canonical, accountId: account, proposalNonce: nonce)
        XCTAssertEqual(first, try MultisigOccurrence.derive(networkId: TestNetworkIds.canonical, accountId: account, proposalNonce: nonce))
        XCTAssertNotEqual(first, try MultisigOccurrence.derive(networkId: TestNetworkIds.canonical, accountId: account, proposalNonce: String(repeating: "08", count: 32)))
        XCTAssertNotEqual(first, try MultisigOccurrence.derive(networkId: TestNetworkIds.other, accountId: account, proposalNonce: nonce))
        XCTAssertNotEqual(first, try MultisigOccurrence.derive(networkId: TestNetworkIds.canonical, accountId: otherAccount, proposalNonce: nonce))
    }

    func testNonceHasOneExactNonzeroRepresentation() throws {
        for nonce in ["", String(repeating: "00", count: 32), String(repeating: "AB", count: 32), " " + String(repeating: "07", count: 32), String(repeating: "07", count: 31)] {
            XCTAssertThrowsError(try MultisigOccurrence.derive(networkId: TestNetworkIds.canonical, accountId: account, proposalNonce: nonce)) { error in
                XCTAssertEqual(error as? MultisigOccurrenceError, .invalidInput)
            }
            let request = ToriiMultisigProposeRequest(
                selector: ToriiMultisigAccountSelector(multisigAccountId: account),
                signerAccountId: otherAccount, proposalNonce: nonce,
                instructions: [try ToriiMultisigProposeInstruction(base64: "AQID")],
                feePayment: .authority(chargeLimits: [], gasLimit: nil)
            )
            XCTAssertThrowsError(try JSONEncoder().encode(request))
        }
    }

    func testApprovalRequiresExactIndependentOccurrenceAndContent() throws {
        let id = String(repeating: "07", count: 32)
        let hash = String(repeating: "08", count: 32)
        var request = ToriiMultisigContractCallApproveRequest(
            selector: ToriiMultisigAccountSelector(multisigAccountId: account),
            signerAccountId: otherAccount, proposalId: id, instructionsHash: hash,
            feePayment: .authority(chargeLimits: [], gasLimit: nil)
        )
        let wire = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(request)) as? [String: Any])
        XCTAssertEqual(wire["proposal_id"] as? String, id)
        XCTAssertEqual(wire["instructions_hash"] as? String, hash)
        request.proposalId = String(repeating: "00", count: 32)
        XCTAssertThrowsError(try JSONEncoder().encode(request))
        request.proposalId = id
        for invalid in ["", "0x" + id, String(repeating: "AB", count: 32)] {
            request.proposalId = invalid
            XCTAssertThrowsError(try JSONEncoder().encode(request))
            request.proposalId = id
            request.instructionsHash = invalid
            XCTAssertThrowsError(try JSONEncoder().encode(request))
            request.instructionsHash = hash
        }
    }

    func testSubmittedProposalStillRequiresIndependentContentCommitment() throws {
        let nonce = String(repeating: "07", count: 32)
        let proposalId = try MultisigOccurrence.derive(
            networkId: TestNetworkIds.canonical, accountId: account, proposalNonce: nonce
        )
        let instructionsHash = String(repeating: "ab", count: 32)
        let fee = FeePaymentIntent.authority(chargeLimits: [], gasLimit: nil)
        let intent = try ToriiMultisigUnsignedTransactionIntent(
            networkId: TestNetworkIds.canonical,
            resolvedMultisigAccountId: account,
            proposalId: proposalId,
            instructionsHash: instructionsHash,
            executable: CanonicalUnsignedTransactionTestSupport.instructionExecutable([Data([1])]),
            metadata: [:]
        )
        func response(_ hash: String) throws -> ToriiMultisigContractCallResponse {
            let object: [String: Any] = [
                "ok": true, "submitted": true,
                "resolved_multisig_account_id": account,
                "proposal_id": proposalId, "instructions_hash": hash,
                "tx_hash_hex": String(repeating: "cd", count: 32),
                "creation_time_ms": 123,
                "fee_payment": ["payer": "authority", "value": ["charge_limits": [], "gas_limit": NSNull()]],
            ]
            return try JSONDecoder().decode(
                ToriiMultisigContractCallResponse.self,
                from: JSONSerialization.data(withJSONObject: object)
            )
        }
        func validate(_ response: ToriiMultisigContractCallResponse,
                      intent: ToriiMultisigUnsignedTransactionIntent?) throws {
            _ = try response.validatingRequestBindings(
                signerAccountId: otherAccount,
                selector: ToriiMultisigAccountSelector(multisigAccountId: account),
                requestedProposalNonce: nonce,
                requestedFeePayment: fee,
                requestedCreationTimeMs: 123,
                unsignedTransactionIntent: intent,
                clientNetworkId: TestNetworkIds.canonical
            )
        }
        XCTAssertNoThrow(try validate(response(instructionsHash), intent: intent))
        XCTAssertThrowsError(try validate(response(instructionsHash), intent: nil))
        XCTAssertThrowsError(try validate(response(String(repeating: "ef", count: 32)), intent: intent))
    }
}
