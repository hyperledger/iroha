// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

/// Stages from exact Native observations emitted by the device actor.
/// Recovered unburned credit observes an earlier durable Receive; it does not establish
/// a new Receive, radio delivery or the original operation's completion time.
enum KagemushaEnrollmentProbeStage {
  static func observed(_ outcome: String) -> String? {
    switch outcome {
    case "native-installation-registered", "installed-owner-retained": return "installed"
    case "live-dispatch-exported": return "dispatch"
    case "retained-e5-exported", "native-durable-e5-exported": return "e5"
    case "retained-e6-exported", "native-durable-e6-exported-not-activated": return "e6"
    case "native-wallet-opened": return "opened"
    case "native-activation-confirmed": return "activated"
    case "native-complete-load": return "loaded"
    case "native-complete-send", "native-exact-send-delivery-admitted-over-nearby": return "sent"
    case "native-complete-receive", "native-durable-receive-acknowledged-over-nearby",
      "native-credit-evidence-1", "native-credit-evidence-2": return "received"
    case "native-unload-confirmed": return "unloaded"
    default: return nil
    }
  }
}
