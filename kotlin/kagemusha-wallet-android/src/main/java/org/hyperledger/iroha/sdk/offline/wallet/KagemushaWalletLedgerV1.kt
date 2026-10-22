// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.math.BigInteger
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import org.hyperledger.iroha.sdk.client.KagemushaWalletLedgerReadV1

/** Closed original Native transports accepted by the current ledger instruction. */
enum class KagemushaWalletLedgerTransportV1(internal val tag: Long) {
    ACTIVATE(1), UNLOAD(2), CLOSE_LOADS(3),
}

/** BLS-certified native consensus identity of an attempt's inclusion block. It is not the Iroha
 * block-header hash. The height is an unsigned u64 carried as its exact Long bits. */
class KagemushaWalletLedgerCommitV1 internal constructor(val heightBits: Long, commitHash: ByteArray) {
    private val hash = commitHash.copyOf()
    fun commitHash(): ByteArray = hash.copyOf()
    override fun equals(other: Any?): Boolean =
        other is KagemushaWalletLedgerCommitV1 && other.heightBits == heightBits && other.hash.contentEquals(hash)
    override fun hashCode(): Int = 31 * heightBits.hashCode() + hash.contentHashCode()
    override fun toString(): String = "KagemushaWalletLedgerCommitV1(heightBits=$heightBits)"
}

/** Native-retained outcome of one exact signed Activate or Unload attempt. */
sealed class KagemushaWalletLedgerOutcomeV1 {
    /** No authenticated outcome is retained. [entrypoint] is the hash Native derived from the
     * retained signed wire; it only selects the attempt's finality route. */
    class Awaiting internal constructor(entrypoint: ByteArray) : KagemushaWalletLedgerOutcomeV1() {
        private val hash = entrypoint.copyOf()
        fun entrypoint(): ByteArray = hash.copyOf()
        override fun equals(other: Any?): Boolean = other is Awaiting && other.hash.contentEquals(hash)
        override fun hashCode(): Int = hash.contentHashCode()
        override fun toString(): String = "Awaiting"
    }

    /** Certified rejected execution of this attempt only. Offline value and the retained claim
     * are unchanged; a new attempt over the same original may still succeed. */
    class Rejected internal constructor(val commit: KagemushaWalletLedgerCommitV1) : KagemushaWalletLedgerOutcomeV1() {
        override fun equals(other: Any?): Boolean = other is Rejected && other.commit == commit
        override fun hashCode(): Int = commit.hashCode()
        override fun toString(): String = "Rejected($commit)"
    }

    /** Certified successful execution. For Activate this is the wallet's activation; it does not
     * assert that every other attempt executed successfully. */
    class Confirmed internal constructor(val commit: KagemushaWalletLedgerCommitV1) : KagemushaWalletLedgerOutcomeV1() {
        override fun equals(other: Any?): Boolean = other is Confirmed && other.commit == commit
        override fun hashCode(): Int = 31 + commit.hashCode()
        override fun toString(): String = "Confirmed($commit)"
    }

    internal companion object {
        fun of(result: KagemushaWalletCallV1): KagemushaWalletLedgerOutcomeV1 = when (result.status) {
            KagemushaWalletCallV1.LEDGER_AWAITING -> Awaiting(result.bytes())
            KagemushaWalletCallV1.LEDGER_CONFIRMED ->
                Confirmed(KagemushaWalletLedgerCommitV1(result.sequenceLow, result.bytes()))
            KagemushaWalletCallV1.LEDGER_REJECTED ->
                Rejected(KagemushaWalletLedgerCommitV1(result.sequenceLow, result.bytes()))
            else -> throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        }
    }
}

/** Result of offering one ledger finality original to Native. */
sealed class KagemushaWalletLedgerIngestV1 {
    /** The attempt's authenticated outcome after this original. */
    class Outcome internal constructor(val outcome: KagemushaWalletLedgerOutcomeV1) : KagemushaWalletLedgerIngestV1() {
        override fun equals(other: Any?): Boolean = other is Outcome && other.outcome == outcome
        override fun hashCode(): Int = outcome.hashCode()
        override fun toString(): String = "Outcome($outcome)"
    }

    /** DATA: nothing was verified or written. Synchronize boundaries until they cover the
     * unsigned [targetHeightBits], then offer the same original again. */
    class EpochRequired internal constructor(val targetHeightBits: Long) : KagemushaWalletLedgerIngestV1() {
        override fun equals(other: Any?): Boolean = other is EpochRequired && other.targetHeightBits == targetHeightBits
        override fun hashCode(): Int = targetHeightBits.hashCode()
        override fun toString(): String = "EpochRequired(targetHeightBits=$targetHeightBits)"
    }

    internal companion object {
        fun of(result: KagemushaWalletCallV1): KagemushaWalletLedgerIngestV1 {
            if (result.status == KagemushaWalletCallV1.LEDGER_EPOCH_REQUIRED) return EpochRequired(result.sequenceLow)
            val outcome = KagemushaWalletLedgerOutcomeV1.of(result)
            // An offered original either decides the attempt or names a missing epoch.
            if (outcome is KagemushaWalletLedgerOutcomeV1.Awaiting) {
                throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
            }
            return Outcome(outcome)
        }
    }
}

/** One retained attempt to confirm. Native derives its route selector from these exact bytes. */
sealed class KagemushaWalletLedgerAttemptV1 {
    class Activation(signedWire: ByteArray) : KagemushaWalletLedgerAttemptV1() {
        private val wire = signedWire.copyOf()
        internal fun signedWire(): ByteArray = wire.copyOf()
    }

    class Unload(claim: ByteArray, signedWire: ByteArray) : KagemushaWalletLedgerAttemptV1() {
        private val claimBytes = claim.copyOf()
        private val wire = signedWire.copyOf()
        internal fun claim(): ByteArray = claimBytes.copyOf()
        internal fun signedWire(): ByteArray = wire.copyOf()
    }
}

/** Native outcome after one confirmation pass. [advanced] is true only when this pass retained a
 * new authenticated outcome or selected at least one epoch boundary; polls report false. */
class KagemushaWalletLedgerConfirmationV1 internal constructor(
    val outcome: KagemushaWalletLedgerOutcomeV1,
    val advanced: Boolean,
) {
    override fun equals(other: Any?): Boolean =
        other is KagemushaWalletLedgerConfirmationV1 && other.outcome == outcome && other.advanced == advanced
    override fun hashCode(): Int = 31 * outcome.hashCode() + advanced.hashCode()
    override fun toString(): String = "KagemushaWalletLedgerConfirmationV1($outcome, advanced=$advanced)"
}

/** Epoch synchronization for one attempt: whether it now covers the target, and whether at least
 * one boundary was selected. A typed wait on a boundary read ends it without an error. */
internal class KagemushaWalletLedgerEpochSyncV1(val covered: Boolean, val selected: Boolean)

private class KagemushaWalletLedgerWaitV1 : RuntimeException()

private fun failureCause(failure: Throwable): Throwable =
    if (failure is CompletionException && failure.cause != null) failure.cause!! else failure

/** Bounded transport scheduling only; the installed Native wallet owns every outcome. */
internal fun confirmKagemushaLedgerAttemptV1(
    requireCurrentOwner: Runnable,
    outcome: () -> KagemushaWalletLedgerOutcomeV1,
    fetch: (ByteArray) -> CompletableFuture<KagemushaWalletLedgerReadV1>,
    ingest: (ByteArray) -> KagemushaWalletLedgerIngestV1,
    synchronize: (ByteArray, BigInteger) -> CompletableFuture<KagemushaWalletLedgerEpochSyncV1>,
): CompletableFuture<KagemushaWalletLedgerConfirmationV1> {
    val result = CompletableFuture<KagemushaWalletLedgerConfirmationV1>()
    try {
        requireCurrentOwner.run()
        val retained = outcome()
        if (retained !is KagemushaWalletLedgerOutcomeV1.Awaiting) {
            result.complete(KagemushaWalletLedgerConfirmationV1(retained, false))
            return result
        }
        val entrypoint = retained.entrypoint()
        val read = fetch(entrypoint)
        result.whenComplete { _, _ -> if (result.isCancelled) read.cancel(false) }
        read.whenComplete { value, failure ->
            if (result.isDone) return@whenComplete
            try {
                if (read.isCancelled) { result.cancel(false); return@whenComplete }
                if (failure != null) throw failure
                requireCurrentOwner.run()
                if (value !is KagemushaWalletLedgerReadV1.Original) {
                    result.complete(KagemushaWalletLedgerConfirmationV1(retained, false)); return@whenComplete
                }
                val finality = value.bytes()
                when (val first = ingest(finality)) {
                    is KagemushaWalletLedgerIngestV1.Outcome ->
                        result.complete(KagemushaWalletLedgerConfirmationV1(first.outcome, true))
                    is KagemushaWalletLedgerIngestV1.EpochRequired -> {
                        val target = BigInteger(java.lang.Long.toUnsignedString(first.targetHeightBits))
                        val sync = synchronize(entrypoint, target)
                        result.whenComplete { _, _ -> if (result.isCancelled) sync.cancel(false) }
                        sync.whenComplete { synced, syncFailure ->
                            if (result.isDone) return@whenComplete
                            try {
                                if (sync.isCancelled) { result.cancel(false); return@whenComplete }
                                if (syncFailure != null) throw syncFailure
                                if (!synced.covered) {
                                    result.complete(KagemushaWalletLedgerConfirmationV1(retained, synced.selected))
                                    return@whenComplete
                                }
                                requireCurrentOwner.run()
                                val again = ingest(finality)
                                if (again !is KagemushaWalletLedgerIngestV1.Outcome) {
                                    throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
                                }
                                result.complete(KagemushaWalletLedgerConfirmationV1(again.outcome, true))
                            } catch (error: Throwable) { result.completeExceptionally(error) }
                        }
                    }
                }
            } catch (error: Throwable) { result.completeExceptionally(error) }
        }
    } catch (error: Throwable) { result.completeExceptionally(error) }
    return result
}

/** Synchronize the attempt's epochs through its own epoch route, reusing the Load scheduler. */
internal fun synchronizeKagemushaLedgerEpochsV1(
    targetHeight: BigInteger, maximumBoundaries: Int, requireCurrentOwner: Runnable,
    progress: () -> KagemushaWalletEpochProgressV1,
    fetch: (BigInteger) -> CompletableFuture<KagemushaWalletLedgerReadV1>,
    ingest: (BigInteger, ByteArray) -> KagemushaWalletEpochProgressV1,
): CompletableFuture<KagemushaWalletLedgerEpochSyncV1> {
    val result = CompletableFuture<KagemushaWalletLedgerEpochSyncV1>()
    try {
        val before = progress()
        val sync = synchronizeKagemushaEpochsV1(targetHeight, maximumBoundaries, requireCurrentOwner, progress,
            { height -> fetch(height).thenApply { read ->
                (read as? KagemushaWalletLedgerReadV1.Original)?.bytes() ?: throw KagemushaWalletLedgerWaitV1()
            } },
            ingest)
        result.whenComplete { _, _ -> if (result.isCancelled) sync.cancel(false) }
        sync.whenComplete { after, failure ->
            if (result.isDone) return@whenComplete
            try {
                if (sync.isCancelled) { result.cancel(false); return@whenComplete }
                if (failure != null) {
                    if (failureCause(failure) !is KagemushaWalletLedgerWaitV1) throw failure
                    result.complete(KagemushaWalletLedgerEpochSyncV1(false, progress().epoch != before.epoch))
                    return@whenComplete
                }
                result.complete(KagemushaWalletLedgerEpochSyncV1(targetHeight <= after.boundaryHeight, after.epoch != before.epoch))
            } catch (error: Throwable) { result.completeExceptionally(error) }
        }
    } catch (error: Throwable) { result.completeExceptionally(error) }
    return result
}
