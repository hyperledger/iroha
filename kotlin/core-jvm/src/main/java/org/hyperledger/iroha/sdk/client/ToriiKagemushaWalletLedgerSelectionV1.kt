// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.client

/**
 * Route selector of one retained Activate or Unload attempt.
 *
 * The entrypoint hash must be the one Native derived from the retained signed wire and returned
 * as its Awaiting outcome; an app-supplied or Core-reported transaction hash is never a selector.
 * It identifies DATA only and grants no outcome.
 */
class ToriiKagemushaWalletLedgerSelectionV1(
    schemeId: ByteArray,
    walletId: ByteArray,
    entrypointHash: ByteArray,
) {
    private val scheme = checkedIdentity(schemeId)
    private val wallet = checkedIdentity(walletId)
    private val entrypoint = checkedIdentity(entrypointHash)

    /** Owned copy of the selected scheme identity. */
    val schemeId: ByteArray get() = scheme.copyOf()
    /** Owned copy of the selected wallet incarnation. */
    val walletId: ByteArray get() = wallet.copyOf()
    /** Owned copy of the Native-derived entrypoint hash. */
    val entrypointHash: ByteArray get() = entrypoint.copyOf()

    internal val path: String
        get() = "/v1/kagemusha/${hex(scheme)}/wallets/${hex(wallet)}/ledger/${hex(entrypoint)}"

    private fun checkedIdentity(value: ByteArray): ByteArray {
        require(value.size == 32 && value.any { it != 0.toByte() }) {
            "KAGEMUSHA ledger selectors must be nonzero 32-byte identities"
        }
        return value.copyOf()
    }

    private fun hex(value: ByteArray): String = buildString(value.size * 2) {
        for (byte in value) {
            val unsigned = byte.toInt() and 0xff
            append("0123456789abcdef"[unsigned ushr 4])
            append("0123456789abcdef"[unsigned and 15])
        }
    }

    companion object {
        /** Complete direct finality original: one certificate, one output row, paths and framing. */
        const val FINALITY_MAXIMUM_BYTES = 1_327_104
        /** One epoch boundary certificate. */
        const val EPOCH_MAXIMUM_BYTES = 262_144
    }
}

/**
 * One account-signed ledger attempt read. Only Torii's two typed codes are waits; every other
 * status, including an untyped 404 or a route absent after a rollback, fails the read.
 */
sealed class KagemushaWalletLedgerReadV1 {
    /** Exact original DATA bytes; only the installed Native wallet authenticates them. */
    class Original(bytes: ByteArray) : KagemushaWalletLedgerReadV1() {
        private val retained = bytes.copyOf()
        fun bytes(): ByteArray = retained.copyOf()
        override fun equals(other: Any?): Boolean = other is Original && other.retained.contentEquals(retained)
        override fun hashCode(): Int = retained.contentHashCode()
        override fun toString(): String = "Original(bytes=${retained.size})"
    }

    /** 404 `kagemusha_ledger_entry_not_committed`: not committed yet, or not this account's attempt. */
    object NotCommitted : KagemushaWalletLedgerReadV1()

    /** 503 `kagemusha_ledger_finality_unavailable`: retryable unavailability. */
    object Unavailable : KagemushaWalletLedgerReadV1()
}
