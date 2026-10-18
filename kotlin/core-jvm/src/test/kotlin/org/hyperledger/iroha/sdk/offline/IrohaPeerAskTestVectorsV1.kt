// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.io.File
import java.math.BigInteger
import kotlin.test.assertEquals
import org.hyperledger.iroha.sdk.client.JsonParser

/**
 * `fixtures/kagemusha/peer_ask_v1.json`: the receiver's ask (`IAK1`), the NFC GET_ASK APDU, the Nearby
 * picture indices and the vector Offer's amount, shared byte for byte with the Swift tests.
 */
internal object IrohaPeerAskTestVectorsV1 {
    val fixture: Map<*, *> by lazy {
        val file = generateSequence(File(".").canonicalFile) { it.parentFile }
            .map { File(it, "fixtures/kagemusha/peer_ask_v1.json") }.first(File::isFile)
        (JsonParser.parse(file.readText()) as Map<*, *>).also {
            assertEquals(1, (it["fixture_version"] as Number).toInt())
        }
    }

    fun section(key: String): Map<*, *> = fixture[key] as Map<*, *>

    fun list(key: String, owner: Map<*, *> = fixture): List<Map<*, *>> = (owner[key] as List<*>).map { it as Map<*, *> }

    fun hex(value: Any?): ByteArray = (value as String).chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    /** The ask of one `asks` vector, built from its amount and receiver account digest. */
    fun ask(vector: Map<*, *>): IrohaPeerAskV1 =
        IrohaPeerAskV1.of(BigInteger(vector["amount_decimal"] as String), hex(vector["account_digest_hex"]))

    /** The amount of the vector Offer (`fixtures/kagemusha/wallet_v1_vectors.json` `envelopes[0]`). */
    val offerAmount: BigInteger get() = BigInteger(section("offer_amount")["amount_decimal"] as String)
}
