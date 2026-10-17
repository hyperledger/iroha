package org.hyperledger.iroha.sdk.offline

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class IrohaPeerNfcAidSelectionV1Test {
    private val bpng = IrohaPeerNfcApplicationIdentifierV1.fromHex("F05047444B4E464301")
    private val protocol = IrohaPeerNfcApplicationIdentifierV1.PROTOCOL

    @Test
    fun `reader selects the exact registered AID before protocol APDUs`() {
        val selection = IrohaPeerNfcAidSelectionV1(bpng)
        val command = selection.command()
        assertContentEquals(
            byteArrayOf(0x00, 0xa4.toByte(), 0x04, 0x00, 0x09) + bpng.bytes() + byteArrayOf(0x00),
            command,
        )
        assertTrue(IrohaPeerNfcAidSelectionV1.isSelect(command))
        assertTrue(selection.accepts(command))
        assertFalse(
            IrohaPeerNfcAidSelectionV1.isSelect(IrohaPeerNfcAPDUCodecV1.encode(IrohaPeerNfcCommandV1.GetInfo)),
        )
        val protocolSelection = IrohaPeerNfcAidSelectionV1(protocol)
        assertContentEquals(
            byteArrayOf(0x00, 0xa4.toByte(), 0x04, 0x00, 0x0b) + protocol.bytes() + byteArrayOf(0x00),
            protocolSelection.command(),
        )
    }

    @Test
    fun `a card configured with its own AID refuses the protocol AID`() {
        val selection = IrohaPeerNfcAidSelectionV1(bpng)
        assertFalse(selection.accepts(IrohaPeerNfcAidSelectionV1(protocol).command()))
        assertFalse(IrohaPeerNfcAidSelectionV1(protocol).accepts(selection.command()))
    }

    @Test
    fun `wrong or malformed AID never selects the receiver`() {
        val selection = IrohaPeerNfcAidSelectionV1(bpng)
        val command = selection.command()
        assertFalse(selection.accepts(command.copyOf(command.size - 1)))
        assertFalse(selection.accepts(command.copyOf(command.size - 2)))
        assertFalse(selection.accepts(command + byteArrayOf(0x00)))
        assertFalse(selection.accepts(command.copyOf().apply { this[5] = 0x01 }))
        assertFalse(selection.accepts(command.copyOf().apply { this[2] = 0x00 }))
        assertFalse(selection.accepts(command.copyOf().apply { this[4] = 0x08 }))
        assertFalse(selection.accepts(command.copyOf().apply { this[command.size - 1] = 0x10 }))
    }

    @Test
    fun `selection success requires an exact status response`() {
        assertTrue(IrohaPeerNfcAidSelectionV1.succeeded(byteArrayOf(0x90.toByte(), 0x00)))
        assertFalse(IrohaPeerNfcAidSelectionV1.succeeded(byteArrayOf(0x6a, 0x82.toByte())))
        assertFalse(IrohaPeerNfcAidSelectionV1.succeeded(byteArrayOf(0x01, 0x90.toByte(), 0x00)))
    }

    @Test
    fun `reselect and deactivation invalidate an old asynchronous reply`() {
        val state = IrohaPeerNfcApduSelectionStateV1(bpng)
        val select = IrohaPeerNfcAidSelectionV1(bpng).command()
        assertNull(state.currentEpoch())
        assertTrue(state.select(select))
        val first = requireNotNull(state.currentEpoch())
        assertTrue(state.isCurrent(first))
        assertTrue(state.select(select))
        val second = requireNotNull(state.currentEpoch())
        assertFalse(state.isCurrent(first))
        assertTrue(state.isCurrent(second))
        state.deactivate()
        assertFalse(state.isCurrent(second))
        assertNull(state.currentEpoch())
        assertTrue(state.select(select))
        val third = requireNotNull(state.currentEpoch())
        assertFalse(state.select(IrohaPeerNfcAidSelectionV1(protocol).command()))
        assertFalse(state.isCurrent(third))
    }

    @Test
    fun `the HCE boundary answers its own AID and gates replies by selection`() {
        val posted = mutableListOf<Runnable>()
        val sent = mutableListOf<ByteArray>()
        val handler = RecordingHandler()
        val dispatcher = IrohaPeerNfcHostApduDispatcherV1(bpng, { handler }, { posted += it }, { sent += it })

        assertEquals("6700", hex(dispatcher.process(null)))
        // Non-SELECT commands before selection are refused.
        val getInfo = IrohaPeerNfcAPDUCodecV1.encode(IrohaPeerNfcCommandV1.GetInfo)
        assertEquals("6985", hex(dispatcher.process(getInfo)))
        assertEquals("6A82", hex(dispatcher.process(IrohaPeerNfcAidSelectionV1(protocol).command())))
        assertEquals("6985", hex(dispatcher.process(getInfo)))
        assertEquals("9000", hex(dispatcher.process(IrohaPeerNfcAidSelectionV1(bpng).command())))
        assertTrue(handler.deactivations.isEmpty())

        // Decoding is strict and maps to the specified status words.
        assertEquals("6E00", hex(dispatcher.process(bytes("9010000062"))))
        assertEquals("6D00", hex(dispatcher.process(bytes("807F000000"))))
        assertEquals("6A80", hex(dispatcher.process(bytes("80100000000062"))))
        assertTrue(handler.commands.isEmpty())

        // A synchronous reply is returned directly.
        handler.reply = IrohaPeerNfcAPDUResponseV1(byteArrayOf(1, 2), IrohaPeerNfcStatusWordV1.SUCCESS)
        assertEquals("01029000", hex(dispatcher.process(getInfo)))
        assertEquals(listOf<IrohaPeerNfcCommandV1>(IrohaPeerNfcCommandV1.GetInfo), handler.commands)

        // An asynchronous reply is posted and sent while its SELECT is current.
        handler.reply = null
        assertNull(dispatcher.process(getInfo))
        handler.pending.removeAt(0).respond(IrohaPeerNfcAPDUResponseV1.of(IrohaPeerNfcStatusWordV1.SUCCESS))
        posted.removeAt(0).run()
        assertEquals("9000", hex(sent.single()))

        // A reply completed after RF deactivation or a newer SELECT is never sent.
        assertNull(dispatcher.process(getInfo))
        dispatcher.deactivated(0)
        assertEquals(listOf(0), handler.deactivations)
        handler.pending.removeAt(0).respond(IrohaPeerNfcAPDUResponseV1.of(IrohaPeerNfcStatusWordV1.SUCCESS))
        posted.removeAt(0).run()
        assertEquals(1, sent.size)
        assertEquals("6985", hex(dispatcher.process(getInfo)))
        assertEquals("9000", hex(dispatcher.process(IrohaPeerNfcAidSelectionV1(bpng).command())))
        assertNull(dispatcher.process(getInfo))
        assertEquals("9000", hex(dispatcher.process(IrohaPeerNfcAidSelectionV1(bpng).command())))
        assertEquals(listOf(0, 1), handler.deactivations)
        handler.pending.removeAt(0).respond(IrohaPeerNfcAPDUResponseV1.of(IrohaPeerNfcStatusWordV1.SUCCESS))
        posted.removeAt(0).run()
        assertEquals(1, sent.size)

        // Handler failures still answer exactly once.
        handler.failure = IrohaPeerNfcExceptionV1(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        assertEquals("6982", hex(dispatcher.process(getInfo)))
    }

    @Test
    fun `reply before return is direct and never posted twice`() {
        val posted = mutableListOf<ByteArray>()
        val gate = IrohaPeerNfcApduReplyGateV1 { posted.add(it) }
        val answer = byteArrayOf(0x90.toByte(), 0x00)
        gate.deliver(answer)
        gate.deliver(byteArrayOf(0x65, 0x81.toByte()))
        assertContentEquals(answer, gate.finish())
        assertTrue(posted.isEmpty())
    }

    @Test
    fun `reply after return is posted exactly once`() {
        val posted = mutableListOf<ByteArray>()
        val gate = IrohaPeerNfcApduReplyGateV1 { posted.add(it) }
        assertNull(gate.finish())
        val answer = byteArrayOf(0x90.toByte(), 0x00)
        gate.deliver(answer)
        gate.deliver(byteArrayOf(0x65, 0x81.toByte()))
        assertEquals(1, posted.size)
        assertContentEquals(answer, posted.single())
    }

    @Test
    fun `cross thread reply and method return have exactly one delivery`() {
        val answer = byteArrayOf(0x90.toByte(), 0x00)
        repeat(128) {
            val posted = CopyOnWriteArrayList<ByteArray>()
            val direct = AtomicReference<ByteArray?>()
            val gate = IrohaPeerNfcApduReplyGateV1 { posted.add(it) }
            val start = CountDownLatch(1)
            val responder = thread {
                start.await()
                gate.deliver(answer)
            }
            val returning = thread {
                start.await()
                direct.set(gate.finish())
            }
            start.countDown()
            responder.join()
            returning.join()
            assertEquals(1, posted.size + if (direct.get() == null) 0 else 1)
            assertContentEquals(answer, direct.get() ?: posted.single())
        }
    }

    @Test
    fun `IsoDep limits fit the canonical short and extended APDUs`() {
        val short = IrohaPeerIsoDepLimitsV1.derive(261, false)
        assertEquals(256, short.maximumReadChunkBytes)
        assertEquals(203, short.maximumWriteChunkBytes)
        val write = IrohaPeerNfcCommandV1.Write(ByteArray(16) { 1 }, ByteArray(32) { 2 }, 0, ByteArray(203))
        val encoded = IrohaPeerNfcAPDUCodecV1.encode(write)
        assertEquals(4 + 1 + 255, encoded.size)
        val extended = IrohaPeerIsoDepLimitsV1.derive(65_279, true)
        assertEquals(4096, extended.maximumReadChunkBytes)
        assertEquals(4096, extended.maximumWriteChunkBytes)
        val small = IrohaPeerIsoDepLimitsV1.derive(1024, true)
        assertEquals(1022, small.maximumReadChunkBytes)
        assertEquals(1024 - 7 - 52, small.maximumWriteChunkBytes)
        val largestWrite = IrohaPeerNfcCommandV1.Write(
            ByteArray(16) { 1 },
            ByteArray(32) { 2 },
            0,
            ByteArray(small.maximumWriteChunkBytes),
        )
        assertEquals(1024, IrohaPeerNfcAPDUCodecV1.encode(largestWrite).size)
        assertEquals(
            IllegalArgumentException::class,
            runCatching { IrohaPeerIsoDepLimitsV1.derive(136, true) }.exceptionOrNull()?.let { it::class },
        )
    }

    private class RecordingHandler : IrohaPeerNfcAsyncCommandHandlerV1 {
        val commands = mutableListOf<IrohaPeerNfcCommandV1>()
        val pending = mutableListOf<IrohaPeerNfcApduResponseHandlerV1>()
        val deactivations = mutableListOf<Int>()
        var reply: IrohaPeerNfcAPDUResponseV1? = null
        var failure: RuntimeException? = null

        override fun handle(command: IrohaPeerNfcCommandV1, respond: IrohaPeerNfcApduResponseHandlerV1) {
            failure?.let { throw it }
            commands += command
            val immediate = reply
            if (immediate != null) respond.respond(immediate) else pending += respond
        }

        override fun onDeactivated(reason: Int) {
            deactivations += reason
        }
    }

    private fun hex(bytes: ByteArray?): String =
        requireNotNull(bytes).joinToString("") { "%02X".format(it.toInt() and 0xff) }

    private fun bytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
}
