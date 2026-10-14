// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

/** Synchronous SDK execution boundary; the authenticated JNI exports and replies are unchanged. */
internal object KagemushaWalletNativeCallsV1 {
    private val worker get() = KagemushaWalletNativeWorkerV1.shared

    fun revision() = KagemushaWalletNativeV1.revision()
    fun openBegin(runtime: Long, credential: ByteArray, certificates: ByteArray, account: ByteArray, asset: ByteArray) =
        worker.run { KagemushaWalletNativeV1.openBegin(runtime, credential, certificates, account, asset) }
    fun openFinish(runtime: Long, signature: ByteArray) =
        worker.run { KagemushaWalletNativeV1.openFinish(runtime, signature) }
    fun openCancel(runtime: Long) = KagemushaWalletNativeV1.openCancel(runtime)
    // Never queue control behind a fold or payment which it must cancel/join.
    fun close(handle: Long) = KagemushaWalletNativeV1.close(handle)
    fun activity(handle: Long, foreground: Int, charging: Int) =
        KagemushaWalletNativeV1.activity(handle, foreground, charging)
    fun call(handle: Long, operation: Int, first: ByteArray, second: ByteArray) =
        worker.run(fold = operation == 3) { KagemushaWalletNativeV1.call(handle, operation, first, second) }
    fun enrollment(runtime: Long, selector: Int, first: ByteArray, second: ByteArray, third: ByteArray, certificates: Array<ByteArray>) =
        worker.run { KagemushaWalletNativeV1.enrollment(runtime, selector, first, second, third, certificates) }
    fun enrollmentRefusal(code: Int, android: Boolean) = KagemushaWalletNativeV1.enrollmentRefusal(code, android)
    fun setup(handle: Long, setupId: ByteArray, selector: Int, amountLow: Long, amountHigh: Long, token: Long, first: ByteArray, second: ByteArray, third: ByteArray) =
        worker.setup(selector) { KagemushaWalletNativeV1.setup(handle, setupId, selector, amountLow, amountHigh, token, first, second, third) }
    fun execute(handle: Long, requestId: ByteArray, selector: Int, amountLow: Long, amountHigh: Long, first: ByteArray, second: ByteArray, third: ByteArray) =
        worker.run { KagemushaWalletNativeV1.execute(handle, requestId, selector, amountLow, amountHigh, first, second, third) }
    fun snapshot(handle: Long) = worker.snapshot { KagemushaWalletNativeV1.snapshot(handle) }
    fun review(handle: Long, selector: Int, amountLow: Long, amountHigh: Long, first: ByteArray, second: ByteArray) =
        worker.run { KagemushaWalletNativeV1.review(handle, selector, amountLow, amountHigh, first, second) }
    fun executeReviewed(handle: Long, token: Long, requestId: ByteArray) =
        worker.run { KagemushaWalletNativeV1.executeReviewed(handle, token, requestId) }
    fun discardReview(handle: Long, token: Long) = KagemushaWalletNativeV1.discardReview(handle, token)

}
