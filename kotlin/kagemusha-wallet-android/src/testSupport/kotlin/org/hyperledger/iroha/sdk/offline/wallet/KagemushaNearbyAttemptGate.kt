// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

/** Test-actor timing gate. A transport completion is never a durable monetary acknowledgment. */
internal class KagemushaNearbyAttemptGate(private val recovery: Boolean) {
    private var authorization: Long? = null
    private var dispatched = recovery
    private var released = false
    private var arrival: Long? = null
    private var admitted: Long? = null
    fun authorized(ticks: Long) {
        check(!recovery && !dispatched && authorization == null && ticks >= 0)
        authorization = ticks
    }
    /** Called only after exclusive durable dispatch-marker publication. */
    fun dispatchMarked() {
        check(!recovery && authorization != null && !dispatched)
        dispatched = true
    }
    /** Called after COMPLETE plus typed native Send output for the exact request identity. */
    fun sendReleased() { check(dispatched && !released); released = true }
    fun creditedArrived(ticks: Long) {
        check(released && arrival == null && ticks >= 0)
        authorization?.let { check(ticks >= it) }
        arrival = ticks
    }
    /** Native exact-Send delivery admission is required even for an authenticated radio message. */
    fun creditedAdmitted(ticks: Long) {
        check(admitted == null && arrival != null && ticks >= arrival!!)
        admitted = ticks
    }
    /** Recovery never invents an original process clock anchor. */
    fun elapsedNanos(): Long? = if (authorization != null && admitted != null) admitted!! - authorization!! else null
    fun arrivalElapsedNanos(): Long? = if (authorization != null && admitted != null) arrival!! - authorization!! else null
}
