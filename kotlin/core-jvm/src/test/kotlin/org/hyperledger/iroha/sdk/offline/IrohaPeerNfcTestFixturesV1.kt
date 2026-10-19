// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.io.IOException
import kotlin.test.assertEquals
import org.hyperledger.iroha.sdk.norito.CRC64
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.Varint

/**
 * Exchange-bound wallet messages from `fixtures/kagemusha/wallet_v1_vectors.json` (the Request with
 * its account companion, the Payment carrying that Request beside a synthetic payer companion and
 * the Credited naming its scheme), wrapped in IPM1. Public fixture DATA only: structural carriage
 * grants no authority.
 */
internal object IrohaPeerNfcTestFixturesV1 {
    val PROFILE = IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1
    val POLICY = IrohaPeerNfcProfilePolicyV1(PROFILE)
    val BPNG_AID: IrohaPeerNfcApplicationIdentifierV1 = IrohaPeerNfcApplicationIdentifierV1.fromHex("F05047444B4E464301")

    val request: IrohaPeerWireMessageV1 by lazy { message(IrohaPeerPayloadKind.REQUEST) }
    val payment: IrohaPeerWireMessageV1 by lazy { message(IrohaPeerPayloadKind.PAYMENT) }
    val credited: IrohaPeerWireMessageV1 by lazy { message(IrohaPeerPayloadKind.CREDITED) }

    /**
     * The vector Request with payer wallet, payer account and send ordinal zero: the open form a
     * receiver hosts, which the vector Payment completes (idempotent for an open fixture Request).
     */
    val openRequest: IrohaPeerWireMessageV1 by lazy { requestWithPayerFields(0) }

    /**
     * The vector Request with every byte of payer wallet, payer account and send ordinal set to
     * [value], keeping the signature bytes the carrier never verifies.
     */
    fun requestWithPayerFields(value: Byte): IrohaPeerWireMessageV1 {
        val frame = IrohaPeerRequestFixtureV1.envelope(IrohaPeerPayloadKind.REQUEST)
        val payloadOffset = NoritoHeader.HEADER_LENGTH + KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES
        var cursor = Varint.decode(frame, payloadOffset).nextOffset + 2
        cursor = Varint.decode(frame, cursor).nextOffset + 4
        cursor = Varint.decode(frame, cursor).nextOffset
        cursor = Varint.decode(frame, cursor).nextOffset
        for (index in 0..7) {
            val field = Varint.decode(frame, cursor)
            val end = field.nextOffset + field.value.toInt()
            if (index == 3 || index == 4 || index == 7) frame.fill(value, field.nextOffset, end)
            cursor = end
        }
        val crc = CRC64.compute(frame.copyOfRange(payloadOffset, frame.size))
        for (index in 0 until 8) frame[31 + index] = (crc ushr (8 * index)).toByte()
        assertEquals(KagemushaWalletMessageKindV1.REQUEST, KagemushaWalletWireV1.inspectEnvelope(frame).kind)
        return IrohaPeerWireMessageV1(
            IrohaPeerCanonicalPayload(
                PROFILE,
                IrohaPeerPayloadKind.REQUEST,
                1,
                IrohaPeerRequestFixtureV1.payload(IrohaPeerPayloadKind.REQUEST, frame),
            ),
        )
    }

    fun message(kind: IrohaPeerPayloadKind): IrohaPeerWireMessageV1 = IrohaPeerWireMessageV1(
        IrohaPeerCanonicalPayload(
            PROFILE,
            kind,
            PROFILE.requiredSchemaVersion,
            IrohaPeerRequestFixtureV1.payload(kind, IrohaPeerRequestFixtureV1.envelope(kind)),
        ),
    )

    /** A card hosting the vector Request under [session], as the receiver arms it after the amount. */
    fun card(
        session: ByteArray = ByteArray(16) { 0x5a },
        limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
    ): IrohaPeerNfcCardEndpointV1 = IrohaPeerNfcCardEndpointV1.direct(
        BPNG_AID,
        IrohaPeerNfcReceiverSessionV1(session, request.encode(), limits = limits),
    )

    /**
     * Re-wrap an IPM1 wallet message after flipping the last byte of top-level message field
     * [field]; the envelope CRC64 is refreshed so the frame stays structurally valid.
     */
    fun rewrap(encoded: ByteArray, kind: IrohaPeerPayloadKind, field: Int): ByteArray {
        val frame = IrohaPeerKagemushaWalletAdapterV1.decode(IrohaPeerWireMessageV1.decode(encoded))
        val payloadOffset = NoritoHeader.HEADER_LENGTH + KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES
        var cursor = Varint.decode(frame, payloadOffset).nextOffset + 2
        cursor = Varint.decode(frame, cursor).nextOffset + 4
        cursor = Varint.decode(frame, cursor).nextOffset
        var end = cursor
        for (index in 0..field) {
            val length = Varint.decode(frame, cursor)
            end = length.nextOffset + length.value.toInt()
            if (index < field) cursor = end
        }
        frame[end - 1] = (frame[end - 1].toInt() xor 1).toByte()
        val crc = CRC64.compute(frame.copyOfRange(payloadOffset, frame.size))
        for (index in 0 until 8) frame[31 + index] = (crc ushr (8 * index)).toByte()
        assertEquals(kind.walletMessageKind, KagemushaWalletWireV1.inspectEnvelope(frame).kind)
        return IrohaPeerWireMessageV1(
            IrohaPeerCanonicalPayload(PROFILE, kind, 1, IrohaPeerRequestFixtureV1.payload(kind, frame)),
        ).encode()
    }
}

/** A response the transport lost after the card may have applied the command. */
internal class IrohaPeerNfcLostResponseV1(operation: IrohaPeerNfcOperationV1) :
    IOException("lost ${operation.name} response"), IrohaPeerNfcAmbiguousResponseErrorV1

/**
 * In-memory carrier between the reader exchanges and an [IrohaPeerNfcCardEndpointV1]: every command
 * crosses the canonical APDU codec and every response its encoding. The wallet behind the card
 * durably admits Payments and answers COMMIT with [walletAcknowledgement].
 */
internal class IrohaPeerNfcLoopbackV1(
    var endpoint: IrohaPeerNfcCardEndpointV1,
    private val walletAcknowledgement: ByteArray = IrohaPeerNfcTestFixturesV1.credited.encode(),
) : IrohaPeerNfcReaderTransceiverV1 {
    /** Commands in transmission order, plus `persist:` markers written by the reader's storage. */
    val log = mutableListOf<String>()
    val writeSizes = mutableListOf<Int>()
    val readSizes = mutableListOf<Int>()
    val admissionRecords = mutableListOf<ByteArray>()
    val acknowledgementRecords = mutableListOf<ByteArray>()
    val persistedCheckpoints = mutableListOf<ByteArray>()
    var loseResponseFor: IrohaPeerNfcOperationV1? = null
    var durableCommits = 0

    val updateCheckpoint = IrohaPeerNfcReaderExchangeV1.UpdateDurableCheckpoint { checkpoint ->
        log += "persist:checkpoint"
        persistedCheckpoints += checkpoint.copyOf()
    }

    fun count(operation: IrohaPeerNfcOperationV1): Int = log.count { it == operation.name }

    override fun transceive(command: IrohaPeerNfcCommandV1): IrohaPeerNfcAPDUResponseV1 {
        log += command.operation.name
        when (command) {
            is IrohaPeerNfcCommandV1.Write -> writeSizes += command.byteCount
            is IrohaPeerNfcCommandV1.ReadRequest -> readSizes += command.length
            is IrohaPeerNfcCommandV1.ReadAcknowledgement -> readSizes += command.length
            else -> Unit
        }
        val raw = endpoint.process(
            IrohaPeerNfcAPDUCodecV1.encode(command),
            IrohaPeerNfcReceiverSessionV1.DurableAdmissionHandler { context ->
                IrohaPeerNfcDurablePaymentAdmissionV1(context).also { admissionRecords += it.encode() }
            },
            IrohaPeerNfcReceiverSessionV1.DurableCommitHandler { context ->
                durableCommits += 1
                IrohaPeerNfcDurableAcknowledgementV1(context, walletAcknowledgement).also {
                    acknowledgementRecords += it.encode()
                }
            },
        ).encode()
        val response = IrohaPeerNfcAPDUResponseV1.decode(raw)
        if (loseResponseFor == command.operation) {
            loseResponseFor = null
            throw IrohaPeerNfcLostResponseV1(command.operation)
        }
        return response
    }
}
