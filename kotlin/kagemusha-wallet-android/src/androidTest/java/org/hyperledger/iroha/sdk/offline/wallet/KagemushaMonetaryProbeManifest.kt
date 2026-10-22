// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.math.BigInteger

/** Closed controller DATA, not protocol encoders or monetary authority. */
internal object KagemushaMonetaryProbeManifest {
    val schemas: Map<String, Set<Set<String>>> = mapOf(
        "bootstrap" to setOf(emptySet()), "activation" to setOf(emptySet()),
        "retain-activation" to setOf(setOf("signed-wire")),
        "activation-status" to setOf(setOf("signed-wire")),
        "activation-finality" to setOf(setOf("signed-wire", "finality")),
        "confirm-activation" to setOf(setOf("signed-wire")),
        "prepare-load" to setOf(setOf("request-id", "amount")),
        "prepared-load" to setOf(setOf("request-id")),
        "load" to setOf(setOf("request-id", "receipt", "finality")),
        "ledger-finality" to setOf(setOf("finality")), "ledger-status" to setOf(emptySet()),
        "epoch-boundary" to setOf(setOf("epoch", "boundary")), "epoch-status" to setOf(emptySet()),
        "request" to setOf(setOf("setup-id", "amount"), setOf("setup-id", "amount", "fee-schedule", "fee-certificate")),
        "payment-companion" to setOf(setOf("payment")),
        "review-send" to setOf(setOf("request-id", "request", "destination")),
        "review-unload" to setOf(setOf("request-id", "amount"), setOf("request-id", "amount", "quote", "certificates", "beneficiary")),
        "decide-review" to setOf(setOf("decision")),
        "receive" to setOf(setOf("request-id", "payment", "companion")), "credit" to setOf(setOf("request-id")),
        "accept-credited" to setOf(setOf("request-id", "credited")),
        "credited-status" to setOf(setOf("request-id", "credited")),
        "fold-once" to setOf(emptySet()), "fold-status" to setOf(emptySet()), "snapshot" to setOf(emptySet()),
        "request-status" to setOf(setOf("request-id")), "retry" to setOf(setOf("operation-id")),
        "resume" to setOf(emptySet()), "released-request" to setOf(setOf("request-id")),
        "released-operation" to setOf(setOf("operation-id")),
        "unload-claim" to setOf(setOf("request-id"), setOf("request-id", "beneficiary")),
        "unload-status" to setOf(setOf("transaction-hash", "claim")),
        "unload-finality" to setOf(setOf("transaction-hash", "claim", "finality")),
        "confirm-unload" to setOf(setOf("transaction-hash", "claim")),
        "decode-request" to setOf(setOf("envelope")),
        "decode-payment" to setOf(setOf("envelope")), "decode-credited" to setOf(setOf("envelope")),
        "refresh-time" to setOf(setOf("request-id", "anchor", "certificates")),
        "begin-time" to setOf(emptySet()), "finish-time" to setOf(setOf("anchor", "certificate")),
        "cancel-time" to setOf(emptySet()),
    )
    fun validate(action: String, names: Set<String>) = probeRequire(schemas[action]?.contains(names) == true)
    fun maximum(name: String): Int = when (name) {
        "request-id", "setup-id", "operation-id", "transaction-hash" -> 32
        "amount" -> 16
        "epoch" -> 8
        "finality" -> 36 * 1024 * 1024
        "boundary" -> 256 * 1024
        "signed-wire", "claim" -> 65_536
        "receipt", "fee-certificate", "anchor", "certificate" -> 512
        "fee-schedule", "quote" -> 1024
        "destination", "beneficiary", "decision" -> 4096
        "companion" -> 2_048
        "request", "payment", "credited", "certificates", "envelope" -> 10_034
        else -> throw EnrollmentProbeFailure("input")
    }
    fun word(bytes: ByteArray): ByteArray {
        probeRequire(bytes.size == 32 && bytes.any { it != 0.toByte() }); return bytes
    }
    fun limb(bytes: ByteArray): BigInteger {
        probeRequire(bytes.size == 8); return BigInteger(1, bytes.reversedArray())
    }
    fun amount(bytes: ByteArray): KagemushaWalletUInt128V1 {
        probeRequire(bytes.size == 16 && bytes.any { it != 0.toByte() })
        return KagemushaWalletUInt128V1(limb(bytes.copyOfRange(0, 8)).toLong(), limb(bytes.copyOfRange(8, 16)).toLong())
    }
    fun unsigned(value: Long): String = java.lang.Long.toUnsignedString(value)
    fun decimal(value: KagemushaWalletUInt128V1): String =
        BigInteger(unsigned(value.high)).shiftLeft(64).add(BigInteger(unsigned(value.low))).toString()
    /** Intent identity uses actual bytes and sorted names, never mutable paths or JSON order. */
    fun binding(kind: String, inputs: Map<String, ByteArray>): ByteArray =
        (listOf(kind) + inputs.toSortedMap().map { (name, bytes) -> "$name:${EnrollmentProbeFiles.digest(bytes)}" })
            .joinToString("\n").toByteArray(Charsets.UTF_8)

    class Decision(bytes: ByteArray, invocation: String, sequence: Int, projection: ByteArray) {
        val confirmed: Boolean
        init {
            val row = probeObject(bytes)
            probeRequire(row.keys == setOf("decision", "invocation", "reviewSequence", "reviewSHA256"))
            val choice = row.text("decision")
            probeRequire(choice in setOf("confirm", "cancel") && row.text("invocation") == invocation &&
                row.text("reviewSequence") == sequence.toString() &&
                row.text("reviewSHA256") == EnrollmentProbeFiles.digest(projection))
            confirmed = choice == "confirm"
        }
    }
}
