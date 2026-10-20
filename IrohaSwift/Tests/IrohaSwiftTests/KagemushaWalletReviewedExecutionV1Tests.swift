import Foundation
import XCTest
@testable import IrohaSwift

/// One-use review cleanup transport tests. No wallet admission, proof, custody,
/// payment key or monetary success is manufactured by these fixtures.
final class KagemushaWalletReviewedExecutionV1Tests: XCTestCase {
  private enum Failure: Error, Equatable {
    case execution(Int32), malformedReply, close
  }

  func testConsumedNativeReviewDoesNotCloseWalletOrReplaceExecutionFailure() {
    for primary in [
      Failure.execution(-1), .execution(-5), .execution(-6),
      .execution(-9), .malformedReply,
    ] {
      var tokenPresent = true
      var trace: [String] = []
      XCTAssertThrowsError(try KagemushaWalletReviewedExecutionV1.run(execute: { () throws -> Void in
        trace.append("execute")
        XCTAssertTrue(tokenPresent)
        tokenPresent = false // Native consumes before its source recheck and execution.
        throw primary
      }, discard: {
        trace.append("discard")
        // The shipping Rust Tokens.take returns INVALID for this consumed token.
        if tokenPresent { tokenPresent = false; return 0 }
        return -1
      }, close: {
        trace.append("close")
      })) { error in
        XCTAssertEqual(error as? Failure, primary)
      }
      XCTAssertEqual(trace, ["execute", "discard"])
      XCTAssertFalse(tokenPresent)
    }
  }

  func testRefusalBeforeConsumptionStillDiscardsTheUnusedReview() {
    var tokenPresent = true
    var closed = false
    let primary = Failure.execution(-5)
    XCTAssertThrowsError(try KagemushaWalletReviewedExecutionV1.run(execute: { () throws -> Void in
      throw primary
    }, discard: {
      XCTAssertTrue(tokenPresent)
      tokenPresent = false
      return 0
    }, close: { closed = true })) {
      XCTAssertEqual($0 as? Failure, primary)
    }
    XCTAssertFalse(tokenPresent)
    XCTAssertFalse(closed)
  }

  func testUnresolvedCleanupRetiresOwnerAndPreservesOriginalFailure() {
    let primary = Failure.execution(-1)
    for status: Int32 in [-3, -4, -5, -6, -7, -9, -13, -100, 1] {
      var closes = 0
      XCTAssertThrowsError(try KagemushaWalletReviewedExecutionV1.run(execute: { () throws -> Void in
        throw primary
      }, discard: { status }, close: { closes += 1 })) {
        XCTAssertEqual($0 as? Failure, primary)
      }
      XCTAssertEqual(closes, 1, "Only definitive review cleanup avoids owner retirement")
    }
  }

  func testFailedOwnerRetirementIsNotHiddenByTheExecutionError() {
    XCTAssertThrowsError(try KagemushaWalletReviewedExecutionV1.run(execute: { () throws -> Void in
      throw Failure.malformedReply
    }, discard: { -5 }, close: { throw Failure.close })) {
      XCTAssertEqual($0 as? Failure, .close)
    }
  }

  func testCompletedDispatchDoesNotDiscardOrClose() throws {
    var cleanupCalls = 0
    try KagemushaWalletReviewedExecutionV1.run(execute: {}, discard: {
      cleanupCalls += 1
      return -1
    }, close: { cleanupCalls += 1 })
    XCTAssertEqual(cleanupCalls, 0)
  }
}
