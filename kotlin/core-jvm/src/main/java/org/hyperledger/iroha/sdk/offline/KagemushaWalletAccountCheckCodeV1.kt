// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline

/**
 * The account check code two people compare aloud before an offline payment: eight decimal digits
 * in two groups of four, such as `0006 6051`. The payer's wallet shows it for the reviewed
 * receiver account digest and the receiver's wallet shows it for its own account, so every wallet
 * renders the same text for one account (`specs/kagemusha_wallet_wire_v1.md` §6,
 * `fixtures/kagemusha/wallet_account_check_code_v1.json`).
 *
 * Display DATA only. A code authenticates nothing; Native still binds the payment to the full
 * reviewed account.
 */
object KagemushaWalletAccountCheckCodeV1 {
    private const val MODULUS = 100_000_000L

    /**
     * The code for a 32-byte account digest `H(account, original)`: its first four bytes as a
     * big-endian unsigned integer, modulo 10^8, as eight zero-padded digits split by one space.
     */
    @JvmStatic
    fun forAccountDigest(accountDigest: ByteArray): String {
        require(accountDigest.size == KagemushaWalletWireV1.DIGEST_BYTES) {
            "A KAGEMUSHA account digest has ${KagemushaWalletWireV1.DIGEST_BYTES} bytes"
        }
        val value = (0 until 4).fold(0L) { total, index -> (total shl 8) or (accountDigest[index].toLong() and 0xff) }
        val digits = (value % MODULUS).toString().padStart(8, '0')
        return digits.substring(0, 4) + " " + digits.substring(4)
    }

    /** The code for a canonical account original ([KagemushaWalletAccountOriginalV1]). */
    @JvmStatic
    fun forAccountOriginal(accountOriginal: ByteArray): String =
        forAccountDigest(KagemushaWalletWireV1.digest(KagemushaWalletDigestRoleV1.ACCOUNT, accountOriginal))

    /** The code for an I105 account ID, through its canonical account original. */
    @JvmStatic
    fun forAccountId(accountId: String): String =
        forAccountOriginal(KagemushaWalletAccountOriginalV1.encode(accountId))
}
