package org.hyperledger.iroha.sdk.tx

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import org.hyperledger.iroha.sdk.client.JsonParser

/** Native-verified exact signed wire and its identities; this is not an execution receipt. */
class DetachedTransactionFinalization private constructor(
    signedTransaction: ByteArray,
    val payloadSigningHashHex: String,
    val transactionHashHex: String,
    val entrypointHashHex: String,
) {
    private val signedWire = signedTransaction.copyOf()
    val signedTransactionBytes: ByteArray get() = signedWire.copyOf()

    override fun toString(): String = "DetachedTransactionFinalization(redacted)"

    companion object {
        internal fun fromNative(signedTransaction: ByteArray, metadata: ByteArray): DetachedTransactionFinalization {
            require(signedTransaction.isNotEmpty() && signedTransaction.size <= DetachedTransactionInspection.MAX_BYTES) {
                "Invalid native signed transaction size"
            }
            require(metadata.isNotEmpty() && metadata.size <= 4096) { "Invalid native finalization metadata size" }
            val text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(metadata)).toString()
            val root = JsonParser.parse(text) as? Map<*, *> ?: error("Native finalization metadata must be an object")
            require(root.keys == setOf("schema", "payload_signing_hash_hex", "transaction_hash_hex", "entrypoint_hash_hex")) {
                "Invalid native finalization metadata fields"
            }
            require(root["schema"] == "iroha.detached_transaction_finalization.v1") { "Unknown native finalization schema" }
            fun hash(name: String): String {
                val value = root[name] as? String ?: error("Native finalization hash must be text")
                require(Regex("[0-9a-f]{64}").matches(value) && (value.last().digitToInt(16) and 1) == 1) {
                    "Invalid native finalization hash"
                }
                return value
            }
            val payload = hash("payload_signing_hash_hex")
            val transaction = hash("transaction_hash_hex")
            val entrypoint = hash("entrypoint_hash_hex")
            require(transaction == entrypoint) { "Native transaction and entrypoint identities differ" }
            return DetachedTransactionFinalization(signedTransaction, payload, transaction, entrypoint)
        }
    }
}
