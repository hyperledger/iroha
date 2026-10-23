import Foundation
import XCTest
@testable import IrohaSwift

final class CommittedTransactionInclusionV1Tests: XCTestCase {
    func testInvalidCheckpointInputsFailBeforeNativeDispatch() throws {
        let hash = Data(repeating: 1, count: 32)
        let network = try NetworkId(bytes: hash)
        let invalidInputs: [(String, Data, Data)] = [
            ("chain", Data(), hash),
            ("", Data([1]), hash),
            (String(repeating: "x", count: 1025), Data([1]), hash),
            ("chain", Data([1]), Data(repeating: 1, count: 31))
        ]
        for (chain, checkpoint, transaction) in invalidInputs {
            XCTAssertThrowsError(try CommittedTransactionInclusionV1.verify(
                response: Data([1]), nativeFinalityProofChainJSON: Data([1]),
                networkId: network, expectedChain: chain,
                trustedCheckpoint: checkpoint, transactionHash: transaction
            )) { error in
                XCTAssertEqual(error as? CommittedTransactionInclusionErrorV1, .invalidInput)
            }
        }
    }

    func testVerifiedCheckpointRetainsValueSemantics() {
        var checkpoint = Data([5, 7])
        let verified = VerifiedCommittedTransactionV1(
            canonicalRow: Data([1]), outputHash: Data(repeating: 1, count: 32),
            blockHash: Data(repeating: 3, count: 32), blockHeight: 2,
            resultOk: false, promotedCheckpoint: checkpoint
        )
        checkpoint[0] = 0
        XCTAssertEqual(verified.promotedCheckpoint, Data([5, 7]))
        var exported = verified.promotedCheckpoint
        exported[0] = 0
        XCTAssertEqual(verified.promotedCheckpoint, Data([5, 7]))
        XCTAssertFalse(verified.resultOk)
    }
    func testExactSuccessfulRejectsMissingOrOversizedOriginalBeforeNativeDispatch() throws {
        let network = try NetworkId(bytes: Data(repeating: 1, count: 32))
        for original in [Data(), Data(repeating: 1, count: 4 * 1024 * 1024 + 1)] {
            XCTAssertThrowsError(try CommittedTransactionInclusionV1.verifyExactSuccessful(
                response: Data([1]), nativeFinalityProofChainJSON: Data([1]),
                networkId: network, expectedChain: "chain", trustedCheckpoint: Data([1]),
                originalSignedTransaction: original
            )) { error in
                XCTAssertEqual(error as? CommittedTransactionInclusionErrorV1, .invalidInput)
            }
        }
    }

    func testExactSuccessfulStillRequiresIndependentCheckpoint() throws {
        let network = try NetworkId(bytes: Data(repeating: 1, count: 32))
        XCTAssertThrowsError(try CommittedTransactionInclusionV1.verifyExactSuccessful(
            response: Data([1]), nativeFinalityProofChainJSON: Data([1]),
            networkId: network, expectedChain: "chain", trustedCheckpoint: Data(),
            originalSignedTransaction: Data([1])
        )) { error in
            XCTAssertEqual(error as? CommittedTransactionInclusionErrorV1, .invalidInput)
        }
    }

}
