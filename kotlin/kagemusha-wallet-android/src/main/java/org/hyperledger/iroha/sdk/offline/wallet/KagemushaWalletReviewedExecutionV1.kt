// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

/** Cleanup of the exact owner/token handed to executeReviewed. This never classifies the
 * monetary outcome or makes the consumed managed review reusable. */
internal object KagemushaWalletReviewedExecutionV1 {
    fun <T> run(execute: () -> T, discard: () -> Int, close: () -> Unit): T {
        try {
            return execute()
        } catch (primary: Throwable) {
            try {
                // Native consumes its token before source recheck/execution. Tokens.take returns
                // INVALID (-1) when this exact token is already absent; only this cleanup reply
                // is accepted. An execution INVALID remains the original failure.
                when (val status = discard()) {
                    0, -1, -2 -> Unit
                    else -> throw KagemushaWalletExceptionV1(status)
                }
            } catch (cleanup: Throwable) {
                if (primary !== cleanup) primary.addSuppressed(cleanup)
                try {
                    close()
                } catch (retirement: Throwable) {
                    if (primary !== retirement) primary.addSuppressed(retirement)
                }
            }
            throw primary
        }
    }
}
