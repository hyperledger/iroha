// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.math.BigInteger

/**
 * The receiver's ask (`specs/kagemusha_wallet_wire_v1.md` §6, Ask): the amount the receiver sets and
 * its account digest `H(account, original)`. Native requires the Request amount to equal the Offer
 * amount, so the ask reaches the payer before the payer builds its Offer: over NFC GET_ASK
 * ([IrohaPeerNfcOfferExchangeV1.runFromAsk]), as the first Nearby record after authentication
 * ([IrohaPeerNearbySessionV1.sealAsk]) or as one QR text ([toText]).
 *
 * The fixed 56-byte `IAK1` record is `"IAK1" ‖ 1 ‖ flags 0 ‖ BE16 profile ‖ LE128 amount ‖ receiver
 * account digest`; its QR text is `IAK1:` ‖ canonical Base45 (RFC 9285) ‖ `:`, always 90 characters.
 * Every value matches the Swift `IrohaPeerAskV1` byte for byte (`fixtures/kagemusha/peer_ask_v1.json`).
 *
 * Display DATA only. An ask is unsigned, belongs to no wallet object digest and authorizes nothing: the
 * payer's hardware-confirmed review of the receiver-signed Request stays the only approval, and the
 * receiver declines an Offer whose amount differs from its ask ([KagemushaWalletWireV1.offerAmountData]).
 */
class IrohaPeerAskV1 private constructor(
    private val profile: IrohaPeerPayloadProfile,
    /** Asked amount in the asset's smallest unit, 0 < amount < 2^128. */
    @JvmField val amount: BigInteger,
    receiverAccountDigest: ByteArray,
) {
    private val digest: ByteArray = receiverAccountDigest.copyOf()

    init {
        require(amount.signum() > 0 && amount.bitLength() <= 8 * AMOUNT_BYTES) {
            "An ask amount is positive and below 2^128"
        }
        require(digest.size == KagemushaWalletWireV1.DIGEST_BYTES && digest.any { it.toInt() != 0 }) {
            "An ask names one nonzero ${KagemushaWalletWireV1.DIGEST_BYTES}-byte receiver account digest"
        }
    }

    /** Receiver account digest `H(account, original)`; a defensive copy. */
    val receiverAccountDigest: ByteArray get() = digest.copyOf()

    /** The receiver's account check code ([KagemushaWalletAccountCheckCodeV1.forAccountDigest]). */
    @JvmField val checkCode: String = KagemushaWalletAccountCheckCodeV1.forAccountDigest(digest)

    /** The 56-byte `IAK1` record. */
    fun encode(): ByteArray = ByteArray(RECORD_BYTES).also { record ->
        MAGIC.copyInto(record)
        record[4] = VERSION.toByte()
        record[6] = (profile.code ushr 8).toByte()
        record[7] = profile.code.toByte()
        for (index in 0 until AMOUNT_BYTES) record[AMOUNT_OFFSET + index] = amount.shiftRight(8 * index).toInt().toByte()
        digest.copyInto(record, AMOUNT_OFFSET + AMOUNT_BYTES)
    }

    /** The QR text `IAK1:` ‖ canonical Base45 of [encode] ‖ `:`. */
    fun toText(): String = TEXT_PREFIX + PeerBase45.encode(encode()) + TEXT_SUFFIX

    override fun equals(other: Any?): Boolean = other is IrohaPeerAskV1 && profile == other.profile &&
        amount == other.amount && digest.contentEquals(other.digest)

    override fun hashCode(): Int = (31 * profile.hashCode() + amount.hashCode()) * 31 + digest.contentHashCode()

    override fun toString(): String = "IrohaPeerAskV1(${profile.name})"

    companion object {
        const val RECORD_BYTES = 56
        const val TEXT_PREFIX = "IAK1:"
        private const val TEXT_SUFFIX = ":"
        private const val VERSION = 1
        private const val AMOUNT_OFFSET = 8
        private const val AMOUNT_BYTES = 16
        private val MAGIC = "IAK1".toByteArray(Charsets.US_ASCII)
        private val TEXT_LENGTH = TEXT_PREFIX.length + RECORD_BYTES / 2 * 3 + TEXT_SUFFIX.length

        /** The ask for [amount] (0 < amount < 2^128) to the account whose digest is [receiverAccountDigest]. */
        @JvmStatic
        fun of(amount: BigInteger, receiverAccountDigest: ByteArray): IrohaPeerAskV1 =
            IrohaPeerAskV1(IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1, amount, receiverAccountDigest)

        /**
         * The ask for [amount] to the I105 account [accountId], through its canonical account original
         * ([KagemushaWalletAccountOriginalV1]), so [checkCode] equals
         * [KagemushaWalletAccountCheckCodeV1.forAccountId].
         */
        @JvmStatic
        fun forAccountId(amount: BigInteger, accountId: String): IrohaPeerAskV1 = of(
            amount,
            KagemushaWalletWireV1.digest(KagemushaWalletDigestRoleV1.ACCOUNT, KagemushaWalletAccountOriginalV1.encode(accountId)),
        )

        /** Strictly decode one `IAK1` record: any other length, magic, version, flags or profile is refused. */
        @JvmStatic
        fun decode(record: ByteArray): IrohaPeerAskV1 {
            require(record.size == RECORD_BYTES) { "An IAK1 ask has exactly $RECORD_BYTES bytes" }
            require(MAGIC.indices.all { record[it] == MAGIC[it] }) { "Not an IAK1 ask" }
            require((record[4].toInt() and 0xff) == VERSION) { "Unsupported IAK1 version" }
            require(record[5].toInt() == 0) { "IAK1 flags must be zero" }
            val profile = IrohaPeerPayloadProfile.fromCode(((record[6].toInt() and 0xff) shl 8) or (record[7].toInt() and 0xff))
                ?: throw IllegalArgumentException("Unknown IAK1 payload profile")
            return IrohaPeerAskV1(
                profile,
                BigInteger(1, record.copyOfRange(AMOUNT_OFFSET, AMOUNT_OFFSET + AMOUNT_BYTES).reversedArray()),
                record.copyOfRange(AMOUNT_OFFSET + AMOUNT_BYTES, RECORD_BYTES),
            )
        }

        /**
         * Strictly decode the QR text: exactly `IAK1:`, 84 canonical Base45 characters and `:`, whose body
         * re-encodes to itself (no lowercase, whitespace, foreign characters or truncation), then [decode].
         */
        @JvmStatic
        fun fromText(text: String): IrohaPeerAskV1 {
            require(text.length == TEXT_LENGTH && text.startsWith(TEXT_PREFIX) && text.endsWith(TEXT_SUFFIX)) {
                "Malformed IAK1 text"
            }
            val body = text.substring(TEXT_PREFIX.length, text.length - TEXT_SUFFIX.length)
            val record = PeerBase45.decode(body) ?: throw IllegalArgumentException("IAK1 body is not canonical Base45")
            require(PeerBase45.encode(record) == body) { "IAK1 body is not canonical Base45" }
            return decode(record)
        }
    }
}
