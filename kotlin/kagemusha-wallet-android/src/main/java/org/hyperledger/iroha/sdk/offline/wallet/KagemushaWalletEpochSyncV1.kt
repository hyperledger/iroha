// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.math.BigInteger
import java.util.concurrent.CompletableFuture
import java.util.concurrent.atomic.AtomicReference

/** Bounded transport scheduling only. Native callbacks own all authority and publication. */
internal fun synchronizeKagemushaEpochsV1(
    receiptHeight: BigInteger, maximumBoundaries: Int, requireCurrentOwner: Runnable,
    progress: () -> KagemushaWalletEpochProgressV1,
    fetch: (BigInteger) -> CompletableFuture<ByteArray>,
    ingest: (BigInteger, ByteArray) -> KagemushaWalletEpochProgressV1,
): CompletableFuture<KagemushaWalletEpochProgressV1> {
    require(receiptHeight.signum() > 0 && receiptHeight.bitLength() <= 64 && maximumBoundaries in 1..64)
    val result = CompletableFuture<KagemushaWalletEpochProgressV1>()
    val pending = AtomicReference<CompletableFuture<ByteArray>?>(null)
    result.whenComplete { _, _ -> if (result.isCancelled) pending.get()?.cancel(false) }
    fun advance(selected: KagemushaWalletEpochProgressV1, remaining: Int) {
        if (result.isDone) return
        try {
            requireCurrentOwner.run()
            if (receiptHeight <= selected.boundaryHeight || remaining == 0) { result.complete(selected); return }
            val request = fetch(selected.boundaryHeight)
            pending.set(request)
            if (result.isCancelled) { request.cancel(false); return }
            request.whenComplete { bytes, failure ->
                if (!result.isDone) {
                    try {
                        if (request.isCancelled) { result.cancel(false); return@whenComplete }
                        if (failure != null) throw failure
                        requireCurrentOwner.run()
                        val next = ingest(selected.epoch, bytes)
                        if (next.epoch <= selected.epoch || next.boundaryHeight <= selected.boundaryHeight) {
                            throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
                        }
                        advance(next, remaining - 1)
                    } catch (error: Throwable) { result.completeExceptionally(error) }
                }
            }
        } catch (error: Throwable) { result.completeExceptionally(error) }
    }
    try { requireCurrentOwner.run(); advance(progress(), maximumBoundaries) }
    catch (error: Throwable) { result.completeExceptionally(error) }
    return result
}
