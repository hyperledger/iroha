// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline

/** Exact Payment transport originals (`KWPYPC1`). IPM1 hashes cover both; only Native authenticates them.
 * The companion is the payer's canonical `KagemushaWalletPayerCompanionV1` DATA (its credential and
 * issuer certificate set) that the receiver hands unchanged to Receive. This structural codec cannot
 * verify the credential, the Payment proofs or their binding.
 *
 * `"KWPYPC1" ‖ 0x00 ‖ BE32 envelope_length ‖ BE32 companion_length ‖ payment_envelope ‖ companion`:
 * a 1..10,034-byte Payment envelope and a 1..2,048-byte companion, at most 12,098 bytes in all.
 */
class IrohaPeerWalletPaymentV1(paymentEnvelope: ByteArray, payerCompanion: ByteArray) {
    private val envelope = paymentEnvelope.copyOf()
    private val payer = payerCompanion.copyOf()
    init {
        require(envelope.size in 1..KagemushaWalletWireV1.MESSAGE_MAX_BYTES)
        require(payer.size in 1..MAXIMUM_COMPANION_BYTES)
        require(KagemushaWalletWireV1.inspectEnvelope(envelope).kind == KagemushaWalletMessageKindV1.PAYMENT)
    }
    fun paymentEnvelope(): ByteArray = envelope.copyOf()
    fun payerCompanion(): ByteArray = payer.copyOf()
    fun encode(): ByteArray = ByteArray(HEADER_BYTES + envelope.size + payer.size).also { out ->
        MAGIC.copyInto(out)
        writeLength(out, 8, envelope.size)
        writeLength(out, 12, payer.size)
        envelope.copyInto(out, HEADER_BYTES)
        payer.copyInto(out, HEADER_BYTES + envelope.size)
    }
    override fun toString(): String = "IrohaPeerWalletPaymentV1(originals=[REDACTED])"

    companion object {
        const val HEADER_BYTES = 16
        const val MAXIMUM_COMPANION_BYTES = KagemushaWalletWireV1.PAYER_COMPANION_MAX_BYTES
        const val MAXIMUM_BYTES = HEADER_BYTES + KagemushaWalletWireV1.MESSAGE_MAX_BYTES + MAXIMUM_COMPANION_BYTES
        private val MAGIC = "KWPYPC1\u0000".toByteArray(Charsets.US_ASCII)

        @JvmStatic fun decode(original: ByteArray): IrohaPeerWalletPaymentV1 {
            require(original.size in (HEADER_BYTES + 2)..MAXIMUM_BYTES)
            val bytes = original.copyOf()
            require(bytes.copyOfRange(0, 8).contentEquals(MAGIC)) { "Payment payer companion is mandatory" }
            val envelopeLength = readLength(bytes, 8, KagemushaWalletWireV1.MESSAGE_MAX_BYTES)
            val companionLength = readLength(bytes, 12, MAXIMUM_COMPANION_BYTES)
            require(bytes.size == HEADER_BYTES + envelopeLength + companionLength) { "Payment carrier length differs" }
            return IrohaPeerWalletPaymentV1(bytes.copyOfRange(HEADER_BYTES, HEADER_BYTES + envelopeLength),
                bytes.copyOfRange(HEADER_BYTES + envelopeLength, bytes.size))
        }
        private fun readLength(bytes: ByteArray, offset: Int, maximum: Int): Int {
            var value = 0L
            for (i in 0..3) value = (value shl 8) or (bytes[offset + i].toLong() and 255)
            require(value in 1..maximum.toLong()) { "Payment carrier field exceeds its bound" }
            return value.toInt()
        }
        private fun writeLength(bytes: ByteArray, offset: Int, value: Int) {
            for (i in 0..3) bytes[offset + i] = (value ushr (24 - i * 8)).toByte()
        }
    }
}
