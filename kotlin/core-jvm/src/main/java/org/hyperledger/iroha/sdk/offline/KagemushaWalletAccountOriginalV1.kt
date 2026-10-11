// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline

import org.hyperledger.iroha.sdk.core.model.instructions.TransferWirePayloadEncoder
import org.hyperledger.iroha.sdk.norito.CRC64
import org.hyperledger.iroha.sdk.norito.NoritoCodec
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.SchemaHash

/** Bounded canonical AccountId DATA for Native wallet intake and reviewed account display.
 * Encoding or rendering does not authenticate a recipient. Native binds the original to the
 * signed Request and its credential before returning a monetary review.
 */
object KagemushaWalletAccountOriginalV1 {
    private const val MAXIMUM_BYTES = 4_096
    private const val SCHEMA = "iroha_data_model::account::model::AccountId"

    /** Encode the exact uncompressed Norito frame consumed by the Native wallet. */
    @JvmStatic
    fun encode(accountId: String): ByteArray {
        val payload = TransferWirePayloadEncoder.encodeAccountIdPayload(accountId)
        require(payload.size <= MAXIMUM_BYTES - NoritoHeader.HEADER_LENGTH)
        return NoritoHeader(SchemaHash.hash16(SCHEMA), payload.size, CRC64.compute(payload),
            NoritoCodec.DEFAULT_FLAGS, NoritoHeader.COMPRESSION_NONE).encode() + payload
    }

    /** Render only under the application's independently selected network discriminant. */
    @JvmStatic
    fun decode(original: ByteArray, chainDiscriminant: Int): String {
        require(original.size in NoritoHeader.HEADER_LENGTH..MAXIMUM_BYTES)
        val retained = original.copyOf()
        val frame = NoritoHeader.decode(retained, SchemaHash.hash16(SCHEMA))
        require(frame.header.compression == NoritoHeader.COMPRESSION_NONE &&
            frame.header.flags == NoritoCodec.DEFAULT_FLAGS) { "Account original must use canonical framing" }
        frame.header.validateChecksum(frame.payload)
        val account = TransferWirePayloadEncoder.decodeAccountIdPayload(frame.payload, chainDiscriminant)
        require(encode(account).contentEquals(retained)) { "Account original must be canonical" }
        return account
    }
}
