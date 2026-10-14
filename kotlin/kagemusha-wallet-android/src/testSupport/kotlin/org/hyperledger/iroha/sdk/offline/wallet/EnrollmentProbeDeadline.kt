// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

/** Test-worker intake boundary; it never cancels an already dispatched Native operation. */
internal class EnrollmentProbeDeadline(
    private val started: Long, private val duration: Long, private val now: () -> Long,
    private val requireLive: () -> Unit = {},
) {
    init { probeRequire(started >= 0 && duration > 0) }

    /** Preserve lifecycle, worker cancellation and timeout as separate closed failure codes. */
    fun check() {
        requireLive()
        probeRequire(!Thread.currentThread().isInterrupted, "cancelled")
        val elapsed = now() - started
        probeRequire(elapsed >= 0 && elapsed < duration, "timeout")
    }

    /** A ready marker does not bypass the bound, even when selection itself blocks. */
    fun <T> select(read: () -> T): T {
        check()
        val selected = read()
        check()
        return selected
    }
}
