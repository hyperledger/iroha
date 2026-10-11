import Foundation
import XCTest
@testable import IrohaSwift

/// Sequencing/status DATA only; never a fabricated Native installation or custody owner.
final class KagemushaWalletInstallationAttemptV1Tests: XCTestCase {
  func testOrdinaryRegistrationRefusalRetainsRegistrationState() throws {
    let state=KagemushaWalletInstallationSequenceV1()
    for _ in 0..<3 { try state.requireRegistration(); XCTAssertFalse(state.isReleased) }
    try state.transferred()
    XCTAssertTrue(state.isReleased)
    XCTAssertThrowsError(try state.requireRegistration())
    XCTAssertThrowsError(try state.transferred())
    XCTAssertFalse(state.startClose())
  }
  func testCloseRefusalFencesRegistrationUntilExactAcknowledgement() throws {
    let state=KagemushaWalletInstallationSequenceV1()
    XCTAssertTrue(state.startClose()); XCTAssertFalse(state.isReleased)
    XCTAssertThrowsError(try state.requireRegistration()); XCTAssertThrowsError(try state.transferred())
    for status: Int32 in [-1,-2,-5,-6,1,15,16] {
      XCTAssertThrowsError(try checkInstallationCloseStatusV1(status))
      XCTAssertFalse(state.isReleased); XCTAssertTrue(state.startClose())
    }
    try checkInstallationCloseStatusV1(0); try state.acknowledgedClose()
    XCTAssertTrue(state.isReleased); XCTAssertFalse(state.startClose())
    XCTAssertThrowsError(try state.requireRegistration()); XCTAssertThrowsError(try state.acknowledgedClose())
  }
  func testCloseCannotAcknowledgeWithoutBeginningRetirement() {
    let state=KagemushaWalletInstallationSequenceV1()
    XCTAssertThrowsError(try state.acknowledgedClose()); XCTAssertFalse(state.isReleased)
    XCTAssertNoThrow(try state.requireRegistration())
  }
  func testFailedBeginWithoutNativeOwnerNeedsNoRetirement() {
    let state=KagemushaWalletInstallationSequenceV1()
    state.noOwner()
    XCTAssertTrue(state.isReleased); XCTAssertFalse(state.startClose())
    XCTAssertThrowsError(try state.requireRegistration())
  }
}
