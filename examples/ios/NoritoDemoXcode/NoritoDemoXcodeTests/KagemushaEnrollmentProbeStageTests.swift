// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import XCTest

/// Actor stage bookkeeping only; these synthetic outcomes confer no Native or device evidence.
final class KagemushaEnrollmentProbeStageTests: XCTestCase {
  func testExistingObservedStagesRemainDistinct() {
    let expected = [
      "native-installation-registered": "installed",
      "installed-owner-retained": "installed",
      "live-dispatch-exported": "dispatch",
      "retained-e5-exported": "e5",
      "native-durable-e5-exported": "e5",
      "retained-e6-exported": "e6",
      "native-durable-e6-exported-not-activated": "e6",
      "native-wallet-opened": "opened",
      "native-activation-confirmed": "activated",
      "native-complete-load": "loaded",
      "native-complete-send": "sent",
      "native-exact-send-delivery-admitted-over-nearby": "sent",
      "native-exact-send-delivery-admitted-over-qr": "sent",
      "native-durable-receive-credited-display-closed-over-qr": "received",
      "native-complete-receive": "received",
      "native-durable-receive-acknowledged-over-nearby": "received",
      "native-unload-confirmed": "unloaded",
    ]
    for (outcome, stage) in expected {
      XCTAssertEqual(KagemushaEnrollmentProbeStage.observed(outcome), stage, outcome)
    }
  }

  func testCollectedReceiveNeedsFreshUnburnedCreditObservation() {
    for evidence in [1, 2] {
      var achieved = Set<String>()
      if let stage = KagemushaEnrollmentProbeStage.observed("native-call-status-10") {
        achieved.insert(stage)
      }
      XCTAssertTrue(achieved.isEmpty, "collected output status alone does not establish credit")
      if let stage = KagemushaEnrollmentProbeStage.observed("native-credit-evidence-\(evidence)") {
        achieved.insert(stage)
      }
      XCTAssertEqual(achieved, ["received"], "fold backlog does not erase durable credit")
    }
  }

  func testRawStatusesBurnedPendingAndExportsNeverEstablishReceived() {
    let outcomes = [
      "qr-displayed", "receiver-display-closed", "camera-qr-observed",
      "native-credit-evidence-0", "native-credit-evidence-3", "native-credit-evidence-4",
      "native-credit-evidence-PENDING", "native-credit-evidence-ARCHIVED",
      "native-credit-evidence-UNFOLDED", "native-credit-evidence-CREDITED",
      "native-credit-evidence-01", "native-credit-evidence-2 ",
      "native-activation-exported-not-submitted", "native-activation-rejected",
      "native-load-plan-retained", "native-review-awaiting-explicit-decision",
      "native-peer-envelope-decoded-not-admitted", "native-unload-claim-exported-not-settled",
      "native-unload-prefix-retained-not-confirmed", "native-current-head-not-folded",
    ] + (0...60).map { "native-call-status-\($0)" }
    for outcome in outcomes {
      XCTAssertNil(KagemushaEnrollmentProbeStage.observed(outcome), outcome)
    }
    let recoveredBurned = ["native-call-status-10", "native-credit-evidence-3"]
    XCTAssertTrue(recoveredBurned.compactMap(KagemushaEnrollmentProbeStage.observed).isEmpty)
  }
}
