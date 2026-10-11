import Foundation
import XCTest
@testable import IrohaSwift

final class KagemushaWalletEnrollmentRefusalV1Tests: XCTestCase {
  private typealias Refusal = KagemushaWalletEnrollmentRefusalV1
  private typealias Outcome = KagemushaWalletEnrollmentOutcomeV1

  /// Design §2.4 table: code, Apple applicability, holder class.
  private let table: [(UInt16, Refusal, Bool, KagemushaWalletEnrollmentRefusalClassV1)] = [
    (1, .keyNotInSecureHardware, false, .phone),
    (2, .attestationWithoutAppIdentity, false, .phone),
    (3, .bootloaderUnlocked, false, .phone),
    (4, .bootNotVerified, false, .phone),
    (5, .untrustedAttestationRoot, true, .phone),
    (6, .attestationRevoked, false, .phone),
    (7, .appIdentityMismatch, true, .app),
    (8, .appVersionBelowMinimum, false, .app),
    (9, .evidenceInvalid, true, .attempt),
    (10, .challengeExpired, true, .attempt),
    (11, .accountNotApproved, true, .account),
    (12, .accountFrozen, true, .account),
  ]

  func testRefusalCodesAreTheClosedStableDesignTable() {
    XCTAssertEqual(Refusal.allCases.map(\.code), Array(1...12))
    XCTAssertEqual(KagemushaWalletEnrollmentRefusalClassV1.allCases.map(\.rawValue), [1, 2, 3, 4])
    for (code, reason, apple, holderClass) in table {
      XCTAssertEqual(Refusal(rawValue: code), reason)
      XCTAssertEqual(reason.code, code)
      XCTAssertEqual(reason.appliesToApple, apple, "\(reason)")
      XCTAssertEqual(reason.holderClass, holderClass, "\(reason)")
      XCTAssertEqual(reason.isEligibility, holderClass == .account, "\(reason)")
    }
    for code: UInt16 in [0, 13, 255, .max] { XCTAssertNil(Refusal(rawValue: code)) }
  }

  func testLinkedNativeTableAgreesWithTheTypedProjection() throws {
    let native = try kagemushaWalletEnrollmentRefusalNativeV1()
    for (code, reason, apple, holderClass) in table {
      XCTAssertEqual(native(code, 1), holderClass.rawValue, "android \(code)")
      XCTAssertEqual(native(code, 0), apple ? holderClass.rawValue : -1, "apple \(code)")
      if apple {
        XCTAssertEqual(try Refusal(relayedCode: code), reason)
      } else {
        XCTAssertThrowsError(try Refusal(relayedCode: code)) {
          XCTAssertEqual($0 as? KagemushaWalletErrorV1, .invalidInput)
        }
      }
    }
    for code: UInt16 in [0, 13, 14, 255, 4096, .max] {
      XCTAssertEqual(native(code, 0), -1)
      XCTAssertEqual(native(code, 1), -1)
      XCTAssertThrowsError(try Refusal(relayedCode: code)) {
        XCTAssertEqual($0 as? KagemushaWalletErrorV1, .invalidInput)
      }
    }
    // The platform flag is exactly 0 (Apple) or 1 (Android).
    XCTAssertEqual(native(5, 2), -1)
  }

  func testRelayedCodeFailsClosedWhenNativeAndProjectionDisagree() {
    func admit(_ code: UInt16, _ native: @escaping (UInt16, UInt8) -> Int32) -> Result<Refusal, KagemushaWalletErrorV1> {
      Result { try Refusal(relayedCode: code, nativeClass: native) }.mapError { $0 as! KagemushaWalletErrorV1 }
    }
    var platforms: [UInt8] = []
    XCTAssertEqual(try admit(12) { platforms.append($1); return 4 }.get(), .accountFrozen)
    XCTAssertEqual(platforms, [0])
    XCTAssertEqual(admit(12) { _, _ in 3 }, .failure(.invalidNativeOutput))
    XCTAssertEqual(admit(12) { _, _ in -1 }, .failure(.invalidNativeOutput))
    XCTAssertEqual(admit(12) { _, _ in 0 }, .failure(.invalidNativeOutput))
    XCTAssertEqual(admit(3) { _, _ in 1 }, .failure(.invalidNativeOutput))
    XCTAssertEqual(admit(13) { _, _ in 1 }, .failure(.invalidNativeOutput))
    XCTAssertEqual(admit(3) { _, _ in -1 }, .failure(.invalidInput))
    XCTAssertEqual(admit(0) { _, _ in -1 }, .failure(.invalidInput))
    XCTAssertEqual(admit(0) { _, _ in -100 }, .failure(.invalidNativeOutput))
  }

  private func parse(_ status: Int, _ headers: [(name: String, value: String)]) throws -> Outcome? {
    try Outcome.parse(status: status, headers: headers) { code in
      guard let reason = Refusal(rawValue: code), reason.appliesToApple else {
        throw KagemushaWalletErrorV1.invalidInput
      }
      return reason
    }
  }

  func testOutcomeHeadersAreExactClosedAndStatusBound() throws {
    let outcomes = table.filter { $0.2 }.map { Outcome.refused($0.1) }
      + [.deliveryWithheld(.accountNotApproved), .deliveryWithheld(.accountFrozen), .outcomeUnknown]
    for outcome in outcomes {
      let (name, value) = outcome.header
      for spelling in [name, name.uppercased()] {
        XCTAssertEqual(try parse(outcome.httpStatus, [("content-type", "text/plain"), (spelling, value)]), outcome)
      }
      // Another status, including a success, never carries it; a repeated header is refused.
      for status in [200, 503, outcome.httpStatus == 403 ? 409 : 403] {
        XCTAssertThrowsError(try parse(status, [(name, value)]))
      }
      XCTAssertThrowsError(try parse(outcome.httpStatus, [(name, value), (name, value)]))
    }
    XCTAssertEqual(Outcome.refused(.accountFrozen).header.name, "x-iroha-kagemusha-refusal-code")
    XCTAssertEqual(Outcome.deliveryWithheld(.accountFrozen).header.name, "x-iroha-kagemusha-delivery-withheld-code")
    XCTAssertEqual(Outcome.outcomeUnknown.header.name, "x-iroha-kagemusha-outcome")
    XCTAssertEqual(Outcome.outcomeUnknown.header.value, "unknown")
    // Identical 403 statuses carry distinguishable outcomes: a withheld delivery keeps the
    // Issued outcome, a refusal is terminal.
    XCTAssertEqual(try parse(403, [(Outcome.refusalCodeHeader, "12")]), .refused(.accountFrozen))
    XCTAssertEqual(try parse(403, [(Outcome.deliveryWithheldHeader, "12")]), .deliveryWithheld(.accountFrozen))
    XCTAssertNotEqual(Outcome.refused(.accountFrozen), Outcome.deliveryWithheld(.accountFrozen))
    XCTAssertNil(try parse(503, [("retry-after", "1")]))
    XCTAssertNil(try parse(200, []))
    for (name, value) in [
      (Outcome.refusalCodeHeader, "0"), (Outcome.refusalCodeHeader, "13"),
      (Outcome.refusalCodeHeader, "012"), (Outcome.refusalCodeHeader, "+1"),
      (Outcome.refusalCodeHeader, ""), (Outcome.refusalCodeHeader, "65536"),
      (Outcome.refusalCodeHeader, " 5"), (Outcome.refusalCodeHeader, "5, 5"),
      (Outcome.refusalCodeHeader, "\u{FF15}"),
      // Android-only codes are protocol errors for Apple evidence.
      (Outcome.refusalCodeHeader, "3"), (Outcome.refusalCodeHeader, "8"),
      (Outcome.deliveryWithheldHeader, "1"), (Outcome.deliveryWithheldHeader, "5"),
      (Outcome.deliveryWithheldHeader, "10"),
      (Outcome.outcomeHeader, "Unknown"), (Outcome.outcomeHeader, ""),
    ] {
      XCTAssertThrowsError(try parse(403, [(name, value)]), "\(name): \(value)")
    }
    XCTAssertThrowsError(try parse(403, [(Outcome.refusalCodeHeader, "11"), (Outcome.deliveryWithheldHeader, "11")]))
    // Field names fold ASCII case only.
    XCTAssertNil(try parse(403, [("x-iroha-\u{212A}agemusha-refusal-code", "5")]))
  }

  func testOutcomeParsesAReceivedResponseThroughTheNativeTable() throws {
    let url = URL(string: "https://core.invalid/v1/kagemusha/wallet/enrollment/complete")!
    func response(_ status: Int, _ headers: [String: String]) -> HTTPURLResponse {
      HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
    }
    XCTAssertEqual(try Outcome.parse(response(403, ["X-Iroha-Kagemusha-Refusal-Code": "7"])), .refused(.appIdentityMismatch))
    XCTAssertEqual(try Outcome.parse(response(403, ["x-iroha-kagemusha-delivery-withheld-code": "11"])),
      .deliveryWithheld(.accountNotApproved))
    XCTAssertEqual(try Outcome.parse(response(409, ["x-iroha-kagemusha-outcome": "unknown"])), .outcomeUnknown)
    XCTAssertNil(try Outcome.parse(response(503, ["Retry-After": "1"])))
    XCTAssertThrowsError(try Outcome.parse(response(403, ["x-iroha-kagemusha-refusal-code": "1"])))
    XCTAssertThrowsError(try Outcome.parse(response(200, ["x-iroha-kagemusha-refusal-code": "5"])))
  }
}
