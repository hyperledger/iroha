import Foundation
import XCTest
@testable import IrohaSwift

final class ValidationFeeFinalityV1Tests: XCTestCase {
    func testRejectsInvalidBoundsBeforeNativeAdmission() throws {
        let hash = Data(repeating: 1, count: 32)
        for checkpoint in [Data(), Data(count: ValidationFeeFinalityV1.maximumCheckpointBytes + 1)] {
            XCTAssertThrowsError(try ValidationFeeFinalityV1.request(checkpoint: checkpoint)) {
                XCTAssertEqual($0 as? ValidationFeeFinalityErrorV1, .invalidInput)
            }
        }
        for proof in [Data(), Data(count: ValidationFeeFinalityV1.maximumProofBytes + 1)] {
            XCTAssertThrowsError(try ValidationFeeFinalityV1.verify(proof: proof, networkID: hash,
                policyChainGenesisHash: hash, checkpoint: Data([1]))) {
                XCTAssertEqual($0 as? ValidationFeeFinalityErrorV1, .invalidInput)
            }
        }
        XCTAssertThrowsError(try ValidationFeeFinalityV1.verify(proof: Data([1]), networkID: Data(),
            policyChainGenesisHash: hash, checkpoint: Data([1]))) {
            XCTAssertEqual($0 as? ValidationFeeFinalityErrorV1, .invalidInput)
        }
    }

    func testGenuineNativeDecoderRefusesMalformedCheckpointAndProof() throws {
        XCTAssertTrue(NoritoNativeBridge.shared.isAvailable)
        XCTAssertThrowsError(try ValidationFeeFinalityV1.request(checkpoint: Data([1]))) {
            guard case .nativeRejected = $0 as? ValidationFeeFinalityErrorV1 else {
                return XCTFail("Malformed checkpoint must reach and be refused by native verification: \($0)")
            }
        }
        XCTAssertThrowsError(try ValidationFeeFinalityV1.verify(proof: Data([1]),
            networkID: Data(repeating: 1, count: 32), policyChainGenesisHash: Data(repeating: 1, count: 32),
            checkpoint: Data([1]))) {
            guard case .nativeRejected = $0 as? ValidationFeeFinalityErrorV1 else {
                return XCTFail("Malformed proof must reach and be refused by native verification: \($0)")
            }
        }
    }
}
