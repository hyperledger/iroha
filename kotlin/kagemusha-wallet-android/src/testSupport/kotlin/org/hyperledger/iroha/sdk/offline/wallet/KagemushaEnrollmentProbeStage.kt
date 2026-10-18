// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

/**
 * Stages from exact Native observations emitted by the device actor.
 * Recovered unburned credit observes an earlier durable Receive; it does not establish
 * a new Receive, radio delivery or the original operation's completion time.
 */
internal fun enrollmentProbeStage(outcome: String): String? = when (outcome) {
    "native-installation-registered", "installed-owner-retained" -> "installed"
    "live-dispatch-exported" -> "dispatch"
    "retained-e5-exported", "native-durable-e5-exported" -> "e5"
    "retained-e6-exported", "native-durable-e6-exported-not-activated" -> "e6"
    "native-wallet-opened" -> "opened"
    "native-local-abandoned", "native-signed-abandonment-exported", "native-expired-local-abandoned" -> "abandoned"
    "native-activation-confirmed" -> "activated"
    "native-complete-load" -> "loaded"
    "native-complete-send", "native-exact-send-delivery-admitted-over-nearby" -> "sent"
    "native-complete-receive", "native-durable-receive-acknowledged-over-nearby",
    "native-credit-evidence-UNFOLDED", "native-credit-evidence-CREDITED" -> "received"
    "native-current-head-folded" -> "folded"
    "native-unload-confirmed" -> "unloaded"
    else -> null
}
