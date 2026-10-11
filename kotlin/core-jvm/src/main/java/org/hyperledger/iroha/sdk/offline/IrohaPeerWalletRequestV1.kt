// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline

/** Exact Request transport originals. IPM1 hashes cover both; only Native authenticates them.
 * The account original is canonical AccountId DATA supplied by the receiving wallet. This
 * structural codec cannot verify its identity, the Request signature, or their digest binding.
 */
class IrohaPeerWalletRequestV1(requestEnvelope: ByteArray, destinationAccountOriginal: ByteArray) {
    private val envelope = requestEnvelope.copyOf()
    private val account = destinationAccountOriginal.copyOf()
    init {
        require(envelope.size in 1..KagemushaWalletWireV1.MESSAGE_MAX_BYTES)
        require(account.size in 1..MAXIMUM_ACCOUNT_BYTES)
        require(KagemushaWalletWireV1.inspectEnvelope(envelope).kind == KagemushaWalletMessageKindV1.REQUEST)
    }
    fun requestEnvelope(): ByteArray = envelope.copyOf()
    fun destinationAccountOriginal(): ByteArray = account.copyOf()
    fun encode(): ByteArray = ByteArray(HEADER_BYTES + envelope.size + account.size).also { out ->
        MAGIC.copyInto(out)
        writeLength(out, 8, envelope.size)
        writeLength(out, 12, account.size)
        envelope.copyInto(out, HEADER_BYTES)
        account.copyInto(out, HEADER_BYTES + envelope.size)
    }
    override fun toString(): String = "IrohaPeerWalletRequestV1(originals=[REDACTED])"

    companion object {
        const val HEADER_BYTES = 16
        const val MAXIMUM_ACCOUNT_BYTES = 4_096
        const val MAXIMUM_BYTES = HEADER_BYTES + KagemushaWalletWireV1.MESSAGE_MAX_BYTES + MAXIMUM_ACCOUNT_BYTES
        private val MAGIC = "KWRQAC1\u0000".toByteArray(Charsets.US_ASCII)

        @JvmStatic fun decode(original: ByteArray): IrohaPeerWalletRequestV1 {
            require(original.size in (HEADER_BYTES + 2)..MAXIMUM_BYTES)
            val bytes = original.copyOf()
            require(bytes.copyOfRange(0, 8).contentEquals(MAGIC)) { "Request account companion is mandatory" }
            val envelopeLength = readLength(bytes, 8, KagemushaWalletWireV1.MESSAGE_MAX_BYTES)
            val accountLength = readLength(bytes, 12, MAXIMUM_ACCOUNT_BYTES)
            require(bytes.size == HEADER_BYTES + envelopeLength + accountLength) { "Request carrier length differs" }
            return IrohaPeerWalletRequestV1(bytes.copyOfRange(HEADER_BYTES, HEADER_BYTES + envelopeLength),
                bytes.copyOfRange(HEADER_BYTES + envelopeLength, bytes.size))
        }
        private fun readLength(bytes: ByteArray, offset: Int, maximum: Int): Int {
            var value = 0L
            for (i in 0..3) value = (value shl 8) or (bytes[offset + i].toLong() and 255)
            require(value in 1..maximum.toLong()) { "Request carrier field exceeds its bound" }
            return value.toInt()
        }
        private fun writeLength(bytes: ByteArray, offset: Int, value: Int) {
            for (i in 0..3) bytes[offset + i] = (value ushr (24 - i * 8)).toByte()
        }
    }
}
