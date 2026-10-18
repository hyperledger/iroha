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
    /** A collected Receive has no retained output; read its fresh Native credit evidence. */
    fun receivedCredit(
        status: Int,
        requestId: ByteArray,
        retainedOutput: (ByteArray) -> Unit,
        projection: (ByteArray) -> ReceivedCredit,
    ): ByteArray {
        check(status == 1 || recovery && status == 10) { "nearby-native-incomplete" }
        val selected = requestId.copyOf()
        if (status == 1) retainedOutput(selected.copyOf())
        val current = projection(selected.copyOf())
        val original = current.original()
        check(current.isReceiver && !current.isBurned && original != null && original.isNotEmpty()) {
            "nearby-native-credit-incomplete"
        }
        return original
    }
    /** Adapter DATA from the Native owner; this gate grants no monetary authority. */
    class ReceivedCredit(val isReceiver: Boolean, val isBurned: Boolean, original: ByteArray?) {
        private val retained = original?.copyOf()
        fun original(): ByteArray? = retained?.copyOf()
    }
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
