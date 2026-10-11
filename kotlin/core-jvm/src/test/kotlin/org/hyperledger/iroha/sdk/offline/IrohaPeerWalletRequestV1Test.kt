package org.hyperledger.iroha.sdk.offline

import java.io.File
import org.hyperledger.iroha.sdk.client.JsonParser
import kotlin.test.*

/** Public fixture DATA only. Transport integrity is not Native recipient admission. */
internal object IrohaPeerRequestFixtureV1 {
    private fun root(): File = generateSequence(File(".").canonicalFile) { it.parentFile }
        .first { File(it, "fixtures/kagemusha/wallet_v1_vectors.json").isFile }
    private fun json(path: String) = JsonParser.parse(File(root(), path).readText()) as Map<*, *>
    private fun hex(value: Any?) = (value as String).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    fun account(): ByteArray = (json("fixtures/account/multisig_wire_v1.json")["positive"] as List<*>)
        .map { it as Map<*, *> }.map { hex(it["account_id_frame_hex"]) }.first { it.size <= 4096 }
    fun envelope(kind: IrohaPeerPayloadKind): ByteArray = (json("fixtures/kagemusha/wallet_v1_vectors.json")["envelopes"] as List<*>)
        .map { it as Map<*, *> }.first { (it["tag"] as Number).toInt() == kind.code }.let { hex(it["canonical_hex"]) }
    fun payload(kind: IrohaPeerPayloadKind, original: ByteArray): ByteArray =
        if (kind == IrohaPeerPayloadKind.REQUEST) IrohaPeerWalletRequestV1(original, account()).encode() else original
}

class IrohaPeerWalletRequestV1Test {
    @Test fun exactOriginalsAndBigEndianLengthsSurviveDefensiveCopies() {
        val envelope = IrohaPeerRequestFixtureV1.envelope(IrohaPeerPayloadKind.REQUEST)
        val account = IrohaPeerRequestFixtureV1.account()
        val retainedEnvelope = envelope.copyOf(); val retainedAccount = account.copyOf()
        val carrier = IrohaPeerWalletRequestV1(envelope, account)
        envelope.fill(0); account.fill(0)
        val encoded = carrier.encode()
        assertContentEquals("KWRQAC1\u0000".toByteArray(), encoded.copyOfRange(0,8))
        assertEquals(retainedEnvelope.size, java.nio.ByteBuffer.wrap(encoded,8,4).int)
        assertEquals(retainedAccount.size, java.nio.ByteBuffer.wrap(encoded,12,4).int)
        val decoded = IrohaPeerWalletRequestV1.decode(encoded)
        assertContentEquals(retainedEnvelope, decoded.requestEnvelope())
        assertContentEquals(retainedAccount, decoded.destinationAccountOriginal())
        decoded.requestEnvelope().fill(0); decoded.destinationAccountOriginal().fill(0); encoded.fill(0)
        assertContentEquals(carrier.encode(), decoded.encode())
    }
    @Test fun missingCompanionTruncationTrailingBytesAndOversizedLengthsAreRefused() {
        val envelope = IrohaPeerRequestFixtureV1.envelope(IrohaPeerPayloadKind.REQUEST)
        val valid = IrohaPeerWalletRequestV1(envelope, IrohaPeerRequestFixtureV1.account()).encode()
        val bad = listOf(envelope, valid.copyOf(15), valid.copyOf(valid.size-1), valid+byteArrayOf(0),
            valid.copyOf().also{it[0]=0}, valid.copyOf().also{java.nio.ByteBuffer.wrap(it,8,4).putInt(10001)},
            valid.copyOf().also{java.nio.ByteBuffer.wrap(it,12,4).putInt(4097)},
            valid.copyOf().also{java.nio.ByteBuffer.wrap(it,12,4).putInt(0)},
            valid.copyOf().also{java.nio.ByteBuffer.wrap(it,8,4).putInt(-1)})
        for (bytes in bad) assertFailsWith<IllegalArgumentException>{IrohaPeerWalletRequestV1.decode(bytes)}
        assertFailsWith<IllegalArgumentException>{IrohaPeerKagemushaWalletAdapterV1.wrap(envelope)}
        for (size in listOf(0,4097)) assertFailsWith<IllegalArgumentException>{IrohaPeerWalletRequestV1(envelope, ByteArray(size))}
        assertFailsWith<IllegalArgumentException>{IrohaPeerWalletRequestV1(IrohaPeerRequestFixtureV1.envelope(IrohaPeerPayloadKind.PAYMENT), byteArrayOf(1))}
    }
    @Test fun bothOriginalsAreCoveredByIpM1HashesAndQr() {
        val request = IrohaPeerRequestFixtureV1.envelope(IrohaPeerPayloadKind.REQUEST)
        val account = IrohaPeerRequestFixtureV1.account()
        val message = IrohaPeerKagemushaWalletAdapterV1.wrap(request, destinationAccountOriginal=account)
        val changed = IrohaPeerKagemushaWalletAdapterV1.wrap(request,
            destinationAccountOriginal=account.copyOf().also{it[it.lastIndex]=(it.last().toInt() xor 1).toByte()})
        assertFalse(message.canonicalHash.contentEquals(changed.canonicalHash))
        assertFalse(message.wireHash.contentEquals(changed.wireHash))
        val tampered=message.encode().also{it[it.lastIndex]=(it.last().toInt() xor 1).toByte()}
        assertFailsWith<IllegalArgumentException>{IrohaPeerWireMessageV1.decode(tampered)}
        val scan=IrohaPeerQRScanSessionV1(IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1,IrohaPeerPayloadKind.REQUEST,1)
        val restored=IrohaPeerQRCodecV1.encode(message).asSequence().map{scan.ingestAt(it,0)}.first{it.isComplete}.message!!
        assertContentEquals(request,IrohaPeerKagemushaWalletAdapterV1.decode(restored))
        assertContentEquals(account,IrohaPeerKagemushaWalletAdapterV1.destinationAccountOriginal(restored))
    }
    @Test fun expandedAllocationBelongsOnlyToRequest() {
        assertEquals(14112,IrohaPeerPayloadKind.REQUEST.maximumWalletFrameBytes)
        assertEquals(10000,IrohaPeerPayloadKind.PAYMENT.maximumWalletFrameBytes)
        val payment=IrohaPeerKagemushaWalletAdapterV1.wrap(IrohaPeerRequestFixtureV1.envelope(IrohaPeerPayloadKind.PAYMENT)).encode()
        java.nio.ByteBuffer.wrap(payment,12,4).putInt(10001)
        assertFailsWith<IllegalArgumentException>{IrohaPeerWireMessageV1.decode(payment)}
        val request=IrohaPeerRequestFixtureV1.envelope(IrohaPeerPayloadKind.REQUEST)
        assertEquals(4096,IrohaPeerWalletRequestV1(request,ByteArray(4096)).destinationAccountOriginal().size)
    }
}
