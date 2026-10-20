// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import Foundation
import XCTest

@testable import IrohaSwift

/// Test-only intent/decision guards; no reconstructed Native authority or fake proof output.
final class KagemushaMonetaryProbeManifestTests: XCTestCase {
  func testQRCommandsAdmitOnlyLocalSelectionAndNoImportedOpticalEvidence() throws {
    let identity: Set<String> = ["setup-id", "request-id"]
    for action in ["qr-send", "qr-recover-send", "qr-recover-receive"] {
      try KagemushaMonetaryProbeManifest.validate(action, names: identity)
      for imported in ["qr-text", "image", "payment", "credited", "envelope", "caller-success"] {
        XCTAssertThrowsError(try KagemushaMonetaryProbeManifest.validate(action, names: identity.union([imported])))
      }
      XCTAssertThrowsError(try KagemushaMonetaryProbeManifest.validate(action, names: ["request-id"]))
    }
    try KagemushaMonetaryProbeManifest.validate("qr-receive", names: identity.union(["amount"]))
    try KagemushaMonetaryProbeManifest.validate("qr-receive", names: identity.union(["amount", "fee-schedule", "fee-certificate"]))
    XCTAssertThrowsError(try KagemushaMonetaryProbeManifest.validate("qr-receive", names: identity))
    XCTAssertThrowsError(try KagemushaMonetaryProbeManifest.validate("qr-receive", names: identity.union(["amount", "fee-schedule"])))
    XCTAssertThrowsError(try KagemushaMonetaryProbeManifest.validate("qr-import", names: ["qr-text"]))
  }
  func testNearbyCommandInputsAreClosedAndRecoveryHasSameOriginalIDs() throws {
    let sender: Set<String> = ["request-id", "session-id", "request-hash", "peer-certificate"]
    for action in ["nearby-send", "nearby-recover-send"] {
      try KagemushaMonetaryProbeManifest.validate(action, names: sender)
      XCTAssertThrowsError(try KagemushaMonetaryProbeManifest.validate(action, names: sender.union(["payment"])))
    }
    for action in ["nearby-receive", "nearby-recover-receive"] {
      try KagemushaMonetaryProbeManifest.validate(action, names: sender.union(["setup-id"]))
      XCTAssertThrowsError(try KagemushaMonetaryProbeManifest.validate(action, names: sender))
    }
    XCTAssertThrowsError(try KagemushaMonetaryProbeManifest.validate("nearby-prepare", names: ["setup-id", "offer", "fee-schedule"]))
    XCTAssertEqual(try KagemushaMonetaryProbeManifest.maximum("session-id"), 16)
    XCTAssertEqual(try KagemushaMonetaryProbeManifest.maximum("peer-certificate"), 32)
  }
  func testOnlyWholeOptionalFeeAndUnloadBundlesAreAccepted() throws {
    try KagemushaMonetaryProbeManifest.validate("request", names: ["setup-id", "offer"])
    try KagemushaMonetaryProbeManifest.validate(
      "request", names: ["setup-id", "offer", "fee-schedule", "fee-certificate"])
    XCTAssertThrowsError(
      try KagemushaMonetaryProbeManifest.validate(
        "request", names: ["setup-id", "offer", "fee-schedule"]))
    XCTAssertThrowsError(
      try KagemushaMonetaryProbeManifest.validate(
        "review-unload", names: ["request-id", "amount", "quote", "beneficiary"]))
    XCTAssertThrowsError(
      try KagemushaMonetaryProbeManifest.validate(
        "load", names: ["request-id", "receipt", "finality", "success"]))
    XCTAssertThrowsError(try KagemushaMonetaryProbeManifest.validate("fake-proof", names: []))
  }
  func testUnsignedAmountUsesExactTwoLimbsWithoutFloatingPointOrZero() throws {
    let value = try KagemushaMonetaryProbeManifest.amount(Data(repeating: 255, count: 16))
    XCTAssertEqual(value.low, UInt64.max)
    XCTAssertEqual(value.high, UInt64.max)
    var bytes = Data(repeating: 0, count: 16)
    bytes[8] = 1
    XCTAssertEqual(try KagemushaMonetaryProbeManifest.amount(bytes), .init(low: 0, high: 1))
    XCTAssertThrowsError(try KagemushaMonetaryProbeManifest.amount(Data(repeating: 0, count: 16)))
    XCTAssertThrowsError(try KagemushaMonetaryProbeManifest.amount(Data(repeating: 1, count: 15)))
    XCTAssertThrowsError(try KagemushaMonetaryProbeManifest.word(Data(repeating: 0, count: 32)))
    XCTAssertThrowsError(try KagemushaMonetaryProbeManifest.word(Data(repeating: 1, count: 31)))
  }
  func testConfirmedAndCancelledDecisionsBindExactLiveReview() throws {
    let invocation = UUID().uuidString
    let projection = Data([7, 8, 9])
    var row: [String: Any] = [
      "decision": "confirm", "invocation": invocation, "reviewSequence": 12,
      "reviewSHA256": EnrollmentProbeFiles.digest(projection),
    ]
    func decision(_ row: [String: Any]) throws -> KagemushaMonetaryProbeManifest.Decision {
      try .init(
        EnrollmentProbeFiles.encode(row), invocation: invocation, sequence: 12,
        projection: projection)
    }
    XCTAssertTrue(try decision(row).confirmed)
    row["decision"] = "cancel"
    XCTAssertFalse(try decision(row).confirmed)
    row["reviewSequence"] = 11
    XCTAssertThrowsError(try decision(row))
    row["reviewSequence"] = 12
    row["invocation"] = UUID().uuidString
    XCTAssertThrowsError(try decision(row))
    row["invocation"] = invocation
    row["reviewSHA256"] = EnrollmentProbeFiles.digest(Data([1]))
    XCTAssertThrowsError(try decision(row))
    row["reviewSHA256"] = EnrollmentProbeFiles.digest(projection)
    row["allowStale"] = true
    XCTAssertThrowsError(try decision(row))
  }
  func testIntentBindingCannotChangeAmountsOrOriginalsOnRetry() {
    let first = KagemushaMonetaryProbeManifest.binding(
      "load", inputs: ["amount": Data([1]), "id": Data([2])])
    let reordered = KagemushaMonetaryProbeManifest.binding(
      "load", inputs: ["id": Data([2]), "amount": Data([1])])
    XCTAssertEqual(first, reordered)
    XCTAssertNotEqual(
      first,
      KagemushaMonetaryProbeManifest.binding(
        "load", inputs: ["amount": Data([3]), "id": Data([2])]))
    XCTAssertNotEqual(
      first,
      KagemushaMonetaryProbeManifest.binding(
        "send", inputs: ["amount": Data([1]), "id": Data([2])]))
  }
  func testAttestationDiagnosticsKeepSafeStageDomainAndCodeWithoutDescriptions() {
    let fields = EnrollmentProbeFailureMetadata.fields(
      KagemushaWalletAppleEnrollmentAttestationErrorV1.appAttestFailed(
        stage: .attestKey, domain: "DCErrorDomain", code: 4))
    XCTAssertEqual(fields["attestationStage"] as? String, "attestKey")
    XCTAssertEqual(fields["attestationDomain"] as? String, "DCErrorDomain")
    XCTAssertEqual(fields["attestationCode"] as? Int, 4)
    let locked = EnrollmentProbeFailureMetadata.fields(
      KagemushaWalletAppleEnrollmentAttestationErrorV1.paymentKeyUnavailable(.locked))
    XCTAssertEqual(locked["keyFailure"] as? String, "locked")
    let unexpected = EnrollmentProbeFailureMetadata.fields(
      KagemushaWalletAppleEnrollmentAttestationErrorV1.appAttestFailed(
        stage: .generateKey, domain: "contains secret\ntext", code: 5))
    XCTAssertEqual(unexpected["attestationDomain"] as? String, "unrecognized-domain")
  }
}

/// Exact controller JSON and refusal rules; these tests do not execute Native retention.
final class KagemushaActivationRetentionProbeTests: XCTestCase {
  private let runID = "AED28BDB-83D3-45E9-A976-D6B4E03224C9"
  private let wire = Data([0, 1, 2, 255])

  func testReceiptBindsExactWireAndInvocationUsingOnlyStringFields() throws {
    let original = try XCTUnwrap(KagemushaActivationRetentionProbe.receipt(
      signedWire: wire, hasConfirmation: false, rejected: false, verifiedHeight: nil,
      blockHash: nil, returned: UInt64.max, invocation: runID, sequence: 3))
    let row = try XCTUnwrap(JSONSerialization.jsonObject(with: original) as? [String: String])
    XCTAssertEqual(row, [
      "schema": "iroha.kagemusha.wallet-activation-retained.v1", "action": "retain-activation",
      "signedWireSHA256": EnrollmentProbeFiles.digest(wire), "signedWireBytes": "4",
      "nativeResult": "not_started", "nativeReturnedTicks": String(UInt64.max),
      "invocation": runID, "sequence": "3",
    ])
    let changed = try XCTUnwrap(KagemushaActivationRetentionProbe.receipt(
      signedWire: Data([0, 1, 2, 254]), hasConfirmation: false, rejected: false,
      verifiedHeight: nil, blockHash: nil, returned: UInt64.max, invocation: runID, sequence: 3))
    XCTAssertNotEqual(original, changed)
  }

  func testProgressConfirmationAndRejectionCannotAuthorizeInitialSubmission() throws {
    for (confirmed, rejected, height, hash) in [
      (true, false, nil as UInt64?, nil as Data?),
      (false, true, nil, nil), (false, false, 1, nil),
      (false, false, nil, Data()), (false, false, 4, Data(repeating: 1, count: 32)),
    ] {
      XCTAssertNil(try KagemushaActivationRetentionProbe.receipt(
        signedWire: wire, hasConfirmation: confirmed, rejected: rejected, verifiedHeight: height,
        blockHash: hash, returned: 1, invocation: runID, sequence: 1))
    }
  }

  func testMalformedControllerIdentityAndWireCannotProduceReceipt() throws {
    for (bytes, ticks, run, sequence) in [
      (Data(), UInt64(1), runID, 1),
      (Data(repeating: 1, count: 65_537), 1, runID, 1),
      (wire, 0, runID, 1), (wire, 1, "invalid", 1),
      (wire, 1, runID.lowercased(), 1), (wire, 1, runID, 10_000),
      (wire, 1, runID, -1),
    ] {
      XCTAssertThrowsError(try KagemushaActivationRetentionProbe.receipt(
        signedWire: bytes, hasConfirmation: false, rejected: false, verifiedHeight: nil,
        blockHash: nil, returned: ticks, invocation: run, sequence: sequence))
    }
  }
}
