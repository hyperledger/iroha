// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import XCTest

final class KagemushaQRProbeManifestTests: XCTestCase {
  func testOnlyExactLocalSelectionInputsAreAccepted() {
    let identity: Set<String> = ["setup-id", "request-id"]
    for action in ["qr-send", "qr-recover-send", "qr-recover-receive"] {
      XCTAssertTrue(KagemushaQRProbeManifest.accepts(action, names: identity))
      for imported in ["qr-text", "image", "payment", "credited", "envelope", "caller-success"] {
        XCTAssertFalse(KagemushaQRProbeManifest.accepts(action, names: identity.union([imported])))
      }
      for name in identity { XCTAssertFalse(KagemushaQRProbeManifest.accepts(action, names: identity.subtracting([name]))) }
    }
  }
  func testReceiverRequiresAmountAndWholeFeeBundle() {
    let required: Set<String> = ["setup-id", "request-id", "amount"]
    XCTAssertTrue(KagemushaQRProbeManifest.accepts("qr-receive", names: required))
    XCTAssertTrue(KagemushaQRProbeManifest.accepts("qr-receive", names: required.union(["fee-schedule", "fee-certificate"])))
    for name in required { XCTAssertFalse(KagemushaQRProbeManifest.accepts("qr-receive", names: required.subtracting([name]))) }
    for name in ["fee-schedule", "fee-certificate", "qr-text", "payment"] {
      XCTAssertFalse(KagemushaQRProbeManifest.accepts("qr-receive", names: required.union([name])))
    }
  }
  func testUnknownCaseVariantAndImportActionsAreRefused() {
    for action in ["qr-import", "QR-send", "qr-recover", "qr-send ", ""] {
      XCTAssertFalse(KagemushaQRProbeManifest.accepts(action, names: ["setup-id", "request-id"]))
    }
    XCTAssertEqual(Set(KagemushaQRProbeManifest.schemas.keys), ["qr-send", "qr-receive", "qr-recover-send", "qr-recover-receive"])
  }
}
