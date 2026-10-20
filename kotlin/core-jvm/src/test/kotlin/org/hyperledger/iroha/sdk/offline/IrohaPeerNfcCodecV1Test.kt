// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Golden vectors shared byte for byte with the Swift `IrohaPeerNfcV1` tests
 * (`specs/kagemusha_wallet_wire_v1.md` §6, NFC), and strict APDU decoding.
 */
class IrohaPeerNfcCodecV1Test {
    @Test
    fun `every command encodes and decodes to its golden vector`() {
        for ((name, command) in goldenCommands()) {
            val expected = VECTORS.getValue(name)
            assertEquals(expected, hex(IrohaPeerNfcAPDUCodecV1.encode(command)), name)
            val aid = if (name == "selectProtocol") IrohaPeerNfcApplicationIdentifierV1.PROTOCOL else BPNG_AID
            val decoded = IrohaPeerNfcAPDUCodecV1.decode(bytes(expected), aid)
            assertEquals(command, decoded, name)
            assertEquals(command.operation, decoded.operation, name)
            assertEquals(expected, hex(IrohaPeerNfcAPDUCodecV1.encode(decoded)), name)
        }
        assertEquals(17, VECTORS.size)
    }

    @Test
    fun `records decode and re-encode their golden vectors`() {
        val readyIntake = IrohaPeerNfcIntakeRecordV1.decode(bytes(VECTORS.getValue("ioi1RequestReady")))
        assertEquals(IrohaPeerNfcIntakeStateV1.REQUEST_READY, readyIntake.state)
        assertContentEquals(S, readyIntake.sessionId)
        assertEquals(4096, readyIntake.maximumWriteChunkBytes)
        assertEquals(VECTORS.getValue("ioi1RequestReady"), hex(readyIntake.encode()))

        val info = IrohaPeerNfcInfoV1.decode(bytes(VECTORS.getValue("inf1RequestReady")))
        assertEquals(IrohaPeerNfcPhaseV1.REQUEST_READY, info.phase)
        assertEquals(IrohaPeerNfcFlagsV1.IDEMPOTENT_WRITES, info.flags)
        assertEquals(9500, info.requestLength)
        assertContentEquals(S, info.identity.sessionId)
        assertContentEquals(HR, info.identity.requestCanonicalHash)
        assertContentEquals(WR, info.identity.requestWireHash)
        assertEquals(
            VECTORS.getValue("inf1RequestReady"),
            hex(
                IrohaPeerNfcInfoV1(
                    IrohaPeerNfcPhaseV1.REQUEST_READY,
                    IrohaPeerNfcFlagsV1.IDEMPOTENT_WRITES,
                    IrohaPeerNfcRequestIdentityV1(PROFILE, S, HR, WR),
                    9500,
                    4096,
                    4096,
                ).encode(),
            ),
        )

        val receivingStatus = IrohaPeerNfcStatusV1.decode(bytes(VECTORS.getValue("nst1PaymentReceiving")))
        assertEquals(IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING, receivingStatus.phase)
        assertEquals(PROFILE, receivingStatus.paymentProfile)
        assertEquals(9084, receivingStatus.paymentLength)
        assertEquals(4096, receivingStatus.receivedPaymentBytes)
        assertContentEquals(WP, receivingStatus.paymentWireHash)
        assertEquals(null, receivingStatus.acknowledgementProfile)
        assertEquals(VECTORS.getValue("nst1PaymentReceiving"), hex(receivingStatus.encode()))

        val ready = IrohaPeerNfcStatusV1.decode(bytes(VECTORS.getValue("nst1AcknowledgementReady")))
        assertEquals(IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY, ready.phase)
        assertEquals(IrohaPeerNfcFlagsV1.KNOWN, ready.flags)
        assertEquals(1200, ready.acknowledgementLength)
        assertContentEquals(WA, ready.acknowledgementWireHash)
        assertEquals(
            VECTORS.getValue("nst1AcknowledgementReady"),
            hex(
                IrohaPeerNfcStatusV1(
                    IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY,
                    IrohaPeerNfcFlagsV1.KNOWN,
                    IrohaPeerNfcRequestIdentityV1(PROFILE, S, HR, WR),
                    PROFILE,
                    9084,
                    9084,
                    WP,
                    PROFILE,
                    1200,
                    WA,
                    4096,
                    4096,
                ).encode(),
            ),
        )
    }

    @Test
    fun `intake records have only the ready state and reject retired fields`() {
        val ready = bytes(VECTORS.getValue("ioi1RequestReady"))
        assertContentEquals(ready, IrohaPeerNfcIntakeRecordV1(PROFILE, S, 4096).encode())
        for (offset in (24..63) + listOf(66, 67)) {
            val changed = ready.copyOf().also { it[offset] = 1 }
            assertEquals(IrohaPeerNfcErrorV1.INVALID_LENGTH,
                assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcIntakeRecordV1.decode(changed) }.error)
        }
        for (state in listOf(0, 1, 2, 3, 5, 255)) {
            assertFailsWith<IrohaPeerNfcExceptionV1> {
                IrohaPeerNfcIntakeRecordV1.decode(ready.copyOf().also { it[5] = state.toByte() })
            }
        }
        for (chunk in listOf(0, 4097)) {
            assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcIntakeRecordV1(PROFILE, S, chunk) }
        }
        assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcIntakeRecordV1(PROFILE, ByteArray(16), 4096) }
        for (offset in listOf(0, 4, 7)) {
            assertFailsWith<IrohaPeerNfcExceptionV1> {
                IrohaPeerNfcIntakeRecordV1.decode(ready.copyOf().also { it[offset] = 0x7f })
            }
        }
        assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcIntakeRecordV1.decode(ready + byteArrayOf(0)) }
    }

    @Test
    fun `status and info records keep durable flags and phases consistent`() {
        val ready = bytes(VECTORS.getValue("nst1AcknowledgementReady"))
        assertEquals(
            IrohaPeerNfcErrorV1.INVALID_LENGTH,
            assertFailsWith<IrohaPeerNfcExceptionV1> {
                IrohaPeerNfcStatusV1.decode(ready.copyOf().also { it[8] = 0x01 })
            }.error,
        )
        assertEquals(
            IrohaPeerNfcErrorV1.INVALID_FLAGS,
            assertFailsWith<IrohaPeerNfcExceptionV1> {
                IrohaPeerNfcStatusV1.decode(ready.copyOf().also { it[8] = 0x07 })
            }.error,
        )
        val info = bytes(VECTORS.getValue("inf1RequestReady"))
        assertEquals(
            IrohaPeerNfcErrorV1.INVALID_FLAGS,
            assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcInfoV1.decode(info.copyOf().also { it[8] = 0x03 }) }.error,
        )
        assertEquals(
            IrohaPeerNfcErrorV1.INVALID_APDU,
            assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcInfoV1.decode(info.copyOf().also { it[9] = 0x01 }) }.error,
        )
        assertEquals(
            IrohaPeerNfcErrorV1.INVALID_SESSION,
            assertFailsWith<IrohaPeerNfcExceptionV1> {
                IrohaPeerNfcInfoV1.decode(info.copyOf().also { ByteArray(16).copyInto(it, 10) })
            }.error,
        )
    }

    @Test
    fun `non canonical and malformed APDUs are rejected`() {
        val cases = mapOf(
            // GET_INFO as Case 2E with a short-representable Le.
            "80100000000062" to IrohaPeerNfcErrorV1.INVALID_APDU,
            // GET_INTAKE with the wrong Le, without Le and with trailing data.
            "8030000045" to IrohaPeerNfcErrorV1.INVALID_APDU,
            "80300000" to IrohaPeerNfcErrorV1.INVALID_APDU,
            "803000004400" to IrohaPeerNfcErrorV1.INVALID_APDU,
            // SUBMIT_OFFER data as Case 3E although Lc ≤ 255.
            "80330000000030" + hex(S) + hex(WO) to IrohaPeerNfcErrorV1.INVALID_APDU,
            // READ_REQUEST as Case 4E although Lc ≤ 255 and Le ≤ 256.
            "80110000000034" + hex(S) + hex(HR) + "00000000" + "00F0" to IrohaPeerNfcErrorV1.INVALID_APDU,
            // READ_REQUEST beyond the 4,096-byte chunk.
            "80110000000034" + hex(S) + hex(HR) + "00000000" + "1001" to IrohaPeerNfcErrorV1.INVALID_LENGTH,
            // Truncated and over-long frames.
            "801000" to IrohaPeerNfcErrorV1.INVALID_APDU,
            "8033000030" + hex(S) to IrohaPeerNfcErrorV1.INVALID_APDU,
            "8033000030" + hex(S) + hex(WO) + "0000" to IrohaPeerNfcErrorV1.INVALID_APDU,
            // Wrong class, instruction and parameters.
            "9010000062" to IrohaPeerNfcErrorV1.INVALID_COMMAND_CLASS,
            "807F000000" to IrohaPeerNfcErrorV1.UNSUPPORTED_INSTRUCTION,
            "8010010062" to IrohaPeerNfcErrorV1.INVALID_APDU,
            // Zero session and zero hash.
            "8022000050" + "00".repeat(16) + hex(HR) + hex(WP) to IrohaPeerNfcErrorV1.INVALID_SESSION,
            "8022000050" + hex(S) + hex(HR) + "00".repeat(32) to IrohaPeerNfcErrorV1.INVALID_HASH,
            // The retired BEGIN_OFFER instruction, and a header of the retired Offer kind (1) in BEGIN_PAYMENT.
            "8031000064" + hex(S) + hex(PAYMENT_HEADER) to IrohaPeerNfcErrorV1.UNSUPPORTED_INSTRUCTION,
            "8020000084" + hex(S) + hex(HR) + hex(OFFER_HEADER) to IrohaPeerNfcErrorV1.INVALID_IPM1,
            // An empty WRITE and a WRITE beyond the chunk bound.
            "8021000034" + hex(S) + hex(WP) + "00000000" to IrohaPeerNfcErrorV1.INVALID_APDU,
            "80210000001035" + hex(S) + hex(WP) + "00000000" + "AB".repeat(4097) to IrohaPeerNfcErrorV1.INVALID_APDU,
        )
        for ((apdu, expected) in cases) {
            val error = assertFailsWith<IrohaPeerNfcExceptionV1>(apdu.take(24)) {
                IrohaPeerNfcAPDUCodecV1.decode(bytes(apdu), BPNG_AID)
            }
            assertEquals(expected, error.error, apdu.take(24))
        }
        val endpoint = IrohaPeerNfcTestFixturesV1.card()
        assertEquals(
            IrohaPeerNfcStatusWordV1.CLASS_NOT_SUPPORTED,
            endpoint.process(bytes("9010000062")).statusWord,
        )
        assertEquals(
            IrohaPeerNfcStatusWordV1.INSTRUCTION_NOT_SUPPORTED,
            endpoint.process(bytes("807F000000")).statusWord,
        )
        assertEquals(IrohaPeerNfcStatusWordV1.WRONG_DATA, endpoint.process(bytes("80100000000062")).statusWord)
        assertEquals(
            IrohaPeerNfcStatusWordV1.WRONG_LENGTH,
            endpoint.process(bytes("80110000000034" + hex(S) + hex(HR) + "00000000" + "1001")).statusWord,
        )
    }

    @Test
    fun `a card answers only its own application identifier`() {
        val bpng = IrohaPeerNfcTestFixturesV1.card()
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, bpng.process(bytes(VECTORS.getValue("selectBpng"))).statusWord)
        assertEquals(IrohaPeerNfcStatusWordV1.NOT_FOUND, bpng.process(bytes(VECTORS.getValue("selectProtocol"))).statusWord)
        val protocol = IrohaPeerNfcCardEndpointV1.direct(
            IrohaPeerNfcApplicationIdentifierV1.PROTOCOL,
            IrohaPeerNfcReceiverSessionV1(S, IrohaPeerNfcTestFixturesV1.request.encode(), profilePolicy = POLICY),
        )
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, protocol.process(bytes(VECTORS.getValue("selectProtocol"))).statusWord)
        assertEquals(IrohaPeerNfcStatusWordV1.NOT_FOUND, protocol.process(bytes(VECTORS.getValue("selectBpng"))).statusWord)
        for (select in listOf(
            "00A4040009F05047444B4E464301", // no Le
            "00A4040009F05047444B4E46430110", // Le 16
            "00A4000009F05047444B4E46430100", // P1 00
            "00A404000CF05047444B4E464301000000", // longer AID
            "00A4040004F050474400", // four-byte AID
        )) {
            assertEquals(IrohaPeerNfcStatusWordV1.NOT_FOUND, bpng.process(bytes(select)).statusWord, select)
        }
    }

    @Test
    fun `application identifiers are 5 to 16 bytes`() {
        assertEquals("F0504B45504B524E464301", IrohaPeerNfcApplicationIdentifierV1.PROTOCOL.hex())
        assertEquals(11, IrohaPeerNfcApplicationIdentifierV1.PROTOCOL.byteCount)
        assertEquals(BPNG_AID, IrohaPeerNfcApplicationIdentifierV1.fromHex("f05047444b4e464301"))
        assertEquals("F05047444B4E464301", BPNG_AID.hex())
        assertEquals(BPNG_AID, IrohaPeerNfcApplicationIdentifierV1(BPNG_AID.bytes()))
        assertTrue(BPNG_AID != IrohaPeerNfcApplicationIdentifierV1.PROTOCOL)
        IrohaPeerNfcApplicationIdentifierV1(ByteArray(5) { 1 })
        IrohaPeerNfcApplicationIdentifierV1(ByteArray(16) { 1 })
        for (invalid in listOf("", "F0", "F0504B45", "F0504B45504B524E46430", "F0504B45504B524E464301AABBCCDDEEFF00",
            "G0504B45504B")) {
            assertEquals(
                IrohaPeerNfcErrorV1.INVALID_APPLICATION_IDENTIFIER,
                assertFailsWith<IrohaPeerNfcExceptionV1>(invalid) { IrohaPeerNfcApplicationIdentifierV1.fromHex(invalid) }.error,
            )
        }
        assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcApplicationIdentifierV1(ByteArray(4)) }
        assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcApplicationIdentifierV1(ByteArray(17)) }
        val source = BPNG_AID.bytes()
        source.fill(0)
        assertEquals("F05047444B4E464301", BPNG_AID.hex())
    }

    @Test
    fun `command construction validates every field`() {
        val invalid = listOf<Pair<IrohaPeerNfcErrorV1, () -> Unit>>(
            IrohaPeerNfcErrorV1.INVALID_SESSION to { IrohaPeerNfcCommandV1.Commit(ByteArray(15) { 1 }, HR, WP) },
            IrohaPeerNfcErrorV1.INVALID_HASH to { IrohaPeerNfcCommandV1.GetStatus(S, ByteArray(32)) },
            IrohaPeerNfcErrorV1.INVALID_LENGTH to { IrohaPeerNfcCommandV1.Write(S, WP, 0, ByteArray(0)) },
            IrohaPeerNfcErrorV1.INVALID_LENGTH to { IrohaPeerNfcCommandV1.Write(S, WP, 0, ByteArray(4097)) },
            IrohaPeerNfcErrorV1.INVALID_OFFSET to { IrohaPeerNfcCommandV1.Write(S, WP, 0x1_0000_0000L, byteArrayOf(1)) },
            IrohaPeerNfcErrorV1.INVALID_OFFSET to { IrohaPeerNfcCommandV1.Write(S, WP, -1, byteArrayOf(1)) },
        )
        for ((expected, construct) in invalid) {
            assertEquals(expected, assertFailsWith<IrohaPeerNfcExceptionV1> { construct() }.error)
        }
        assertEquals(
            IrohaPeerNfcErrorV1.INVALID_LENGTH,
            assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcCommandV1.ReadRequest(S, HR, 0, 4097) }.error,
        )
        assertEquals(
            IrohaPeerNfcErrorV1.INVALID_IPM1,
            assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcCommandV1.BeginPayment(S, HR, OFFER_HEADER) }.error,
        )
        // The largest BE32 offset round-trips; a card rejects it as an invalid offset.
        val extreme = IrohaPeerNfcCommandV1.Write(S, WP, 0xffff_ffffL, byteArrayOf(1))
        assertEquals(extreme, IrohaPeerNfcAPDUCodecV1.decode(IrohaPeerNfcAPDUCodecV1.encode(extreme), BPNG_AID))
        // Commands keep defensive copies.
        val chunk = byteArrayOf(1, 2, 3)
        val write = IrohaPeerNfcCommandV1.Write(S, WP, 0, chunk)
        chunk.fill(0)
        write.bytes.fill(0)
        assertContentEquals(byteArrayOf(1, 2, 3), write.bytes)
    }

    @Test
    fun `status words follow the specification`() {
        assertEquals(0x9000, IrohaPeerNfcStatusWordV1.SUCCESS.code)
        val expected = mapOf(
            IrohaPeerNfcErrorV1.INVALID_APPLICATION_IDENTIFIER to 0x6a82,
            IrohaPeerNfcErrorV1.STATE_MISMATCH to 0x6985,
            IrohaPeerNfcErrorV1.CONFLICTING_REPLAY to 0x6985,
            IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH to 0x6982,
            IrohaPeerNfcErrorV1.INVALID_HASH to 0x6982,
            IrohaPeerNfcErrorV1.INVALID_PROFILE to 0x6982,
            IrohaPeerNfcErrorV1.INVALID_IPM1 to 0x6982,
            IrohaPeerNfcErrorV1.INVALID_LENGTH to 0x6700,
            IrohaPeerNfcErrorV1.MESSAGE_TOO_LARGE to 0x6700,
            IrohaPeerNfcErrorV1.INVALID_APDU to 0x6a80,
            IrohaPeerNfcErrorV1.INVALID_OFFSET to 0x6a80,
            IrohaPeerNfcErrorV1.UNSUPPORTED_INSTRUCTION to 0x6d00,
            IrohaPeerNfcErrorV1.INVALID_COMMAND_CLASS to 0x6e00,
        )
        for ((error, code) in expected) assertEquals(code, IrohaPeerNfcStatusWordV1.forError(error).code, error.name)
        assertEquals(0x6581, IrohaPeerNfcStatusWordV1.STORAGE_FAILURE.code)
        val response = IrohaPeerNfcAPDUResponseV1(byteArrayOf(1, 2), IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED)
        assertEquals("01026985", hex(response.encode()))
        assertEquals(response, IrohaPeerNfcAPDUResponseV1.decode(response.encode()))
        assertEquals(
            IrohaPeerNfcErrorV1.INVALID_APDU,
            assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcAPDUResponseV1.decode(bytes("6F00")) }.error,
        )
        assertEquals(
            IrohaPeerNfcErrorV1.INVALID_LENGTH,
            assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcAPDUResponseV1.decode(ByteArray(4099)) }.error,
        )
    }

    @Test
    fun `retired Offer and Ask instructions are unsupported`() {
        val endpoint = IrohaPeerNfcTestFixturesV1.card()
        for (instruction in listOf(0x31, 0x32, 0x33, 0x34)) {
            val apdu = byteArrayOf(0x80.toByte(), instruction.toByte(), 0, 0, 0)
            assertEquals(IrohaPeerNfcErrorV1.UNSUPPORTED_INSTRUCTION,
                assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcAPDUCodecV1.decode(apdu, BPNG_AID) }.error)
            assertEquals(IrohaPeerNfcStatusWordV1.INSTRUCTION_NOT_SUPPORTED, endpoint.process(apdu).statusWord)
        }
    }

    internal companion object {
        val PROFILE = IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1
        val POLICY = IrohaPeerNfcProfilePolicyV1(PROFILE)
        val BPNG_AID = IrohaPeerNfcApplicationIdentifierV1.fromHex("F05047444B4E464301")
        val S = ByteArray(16) { 0x11 }
        val HR = ByteArray(32) { 0x22 }
        val WR = ByteArray(32) { 0x33 }
        val WP = ByteArray(32) { 0x44 }
        val WA = ByteArray(32) { 0x55 }
        val WO = ByteArray(32) { 0x66 }
        private val CO = ByteArray(32) { 0x77 }
        private val CP = ByteArray(32) { 0x88.toByte() }
        val OFFER_HEADER = ipm1Header(1, 600, CO, WO)
        val PAYMENT_HEADER = ipm1Header(3, 9000, CP, WP)
        private val CHUNK200 = ByteArray(200) { it.toByte() }
        private val CHUNK300 = ByteArray(300) { ((it * 7) and 0xff).toByte() }

        private fun ipm1Header(kind: Int, length: Int, canonicalHash: ByteArray, wireHash: ByteArray): ByteArray =
            NfcRecordWriter(84).apply {
                bytes("IPM1".toByteArray(Charsets.US_ASCII))
                u8(1)
                u8(0)
                u16(1)
                u8(kind)
                u8(0)
                u16(1)
                u32(length.toLong())
                u32(length.toLong())
                bytes(canonicalHash)
                bytes(wireHash)
            }.finish(84)

        fun goldenCommands(): List<Pair<String, IrohaPeerNfcCommandV1>> = listOf(
            "selectBpng" to IrohaPeerNfcCommandV1.SelectApplication(BPNG_AID),
            "selectProtocol" to IrohaPeerNfcCommandV1.SelectApplication(IrohaPeerNfcApplicationIdentifierV1.PROTOCOL),
            "getIntake" to IrohaPeerNfcCommandV1.GetIntake,
            "getInfo" to IrohaPeerNfcCommandV1.GetInfo,
            "readRequest240At0" to IrohaPeerNfcCommandV1.ReadRequest(S, HR, 0, 240),
            "readRequest4096At4096" to IrohaPeerNfcCommandV1.ReadRequest(S, HR, 4096, 4096),
            "beginPayment" to IrohaPeerNfcCommandV1.BeginPayment(S, HR, PAYMENT_HEADER),
            "write200At0" to IrohaPeerNfcCommandV1.Write(S, WP, 0, CHUNK200),
            "write300At8700" to IrohaPeerNfcCommandV1.Write(S, WP, 8700, CHUNK300),
            "commit" to IrohaPeerNfcCommandV1.Commit(S, HR, WP),
            "readAcknowledgement256At512" to IrohaPeerNfcCommandV1.ReadAcknowledgement(S, WP, 512, 256),
            "confirmAcknowledgement" to IrohaPeerNfcCommandV1.ConfirmAcknowledgement(S, WP, WA),
            "getStatus" to IrohaPeerNfcCommandV1.GetStatus(S, HR),
        )

        /** `nfc_vectors.json`, generated from the §6 layouts and shared with the Swift tests. */
        val VECTORS: Map<String, String> = mapOf(
            "selectBpng" to "00A4040009F05047444B4E46430100",
            "selectProtocol" to "00A404000BF0504B45504B524E46430100",
            "getIntake" to "8030000044",
            "getInfo" to "8010000062",
            "readRequest240At0" to
                "801100003411111111111111111111111111111111222222222222222222222222222222222222222222222222222222" +
                "222222222200000000F0",
            "readRequest4096At4096" to
                "801100000000341111111111111111111111111111111122222222222222222222222222222222222222222222222222" +
                "22222222222222000010001000",
            "beginPayment" to
                "802000008411111111111111111111111111111111222222222222222222222222222222222222222222222222222222" +
                "222222222249504D31010000010300000100002328000023288888888888888888888888888888888888888888888888" +
                "8888888888888888884444444444444444444444444444444444444444444444444444444444444444",
            "write200At0" to
                "80210000FC11111111111111111111111111111111444444444444444444444444444444444444444444444444444444" +
                "444444444400000000000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223242526" +
                "2728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F50515253545556" +
                "5758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F80818283848586" +
                "8788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6" +
                "B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
            "write300At8700" to
                "802100000001601111111111111111111111111111111144444444444444444444444444444444444444444444444444" +
                "44444444444444000021FC00070E151C232A31383F464D545B626970777E858C939AA1A8AFB6BDC4CBD2D9E0E7EEF5FC" +
                "030A11181F262D343B424950575E656C737A81888F969DA4ABB2B9C0C7CED5DCE3EAF1F8FF060D141B222930373E454C" +
                "535A61686F767D848B9299A0A7AEB5BCC3CAD1D8DFE6EDF4FB020910171E252C333A41484F565D646B727980878E959C" +
                "A3AAB1B8BFC6CDD4DBE2E9F0F7FE050C131A21282F363D444B525960676E757C838A91989FA6ADB4BBC2C9D0D7DEE5EC" +
                "F3FA01080F161D242B323940474E555C636A71787F868D949BA2A9B0B7BEC5CCD3DAE1E8EFF6FD040B121920272E353C" +
                "434A51585F666D747B828990979EA5ACB3BAC1C8CFD6DDE4EBF2F900070E151C232A31383F464D545B626970777E858C" +
                "939AA1A8AFB6BDC4CBD2D9E0E7EEF5FC030A11181F262D",
            "commit" to
                "802200005011111111111111111111111111111111222222222222222222222222222222222222222222222222222222" +
                "22222222224444444444444444444444444444444444444444444444444444444444444444",
            "readAcknowledgement256At512" to
                "802300003411111111111111111111111111111111444444444444444444444444444444444444444444444444444444" +
                "44444444440000020000",
            "confirmAcknowledgement" to
                "802400005011111111111111111111111111111111444444444444444444444444444444444444444444444444444444" +
                "44444444445555555555555555555555555555555555555555555555555555555555555555",
            "getStatus" to
                "802500003011111111111111111111111111111111222222222222222222222222222222222222222222222222222222" +
                "2222222222AE",
            "ioi1RequestReady" to
                "494F49310104000111111111111111111111111111111111000000000000000000000000000000000000000000000000" +
                "0000000000000000000000000000000010000000",
            "inf1RequestReady" to
                "494E4631010100010100111111111111111111111111111111110000251C222222222222222222222222222222222222" +
                "222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333331000" +
                "1000",
            "nst1PaymentReceiving" to
                "4E5354310102000101001111111111111111111111111111111122222222222222222222222222222222222222222222" +
                "22222222222222222222333333333333333333333333333333333333333333333333333333333333333300010000237C" +
                "000010004444444444444444444444444444444444444444444444444444444444444444000000000000000000000000" +
                "000000000000000000000000000000000000000000000000000010001000",
            "nst1AcknowledgementReady" to
                "4E5354310103000103001111111111111111111111111111111122222222222222222222222222222222222222222222" +
                "22222222222222222222333333333333333333333333333333333333333333333333333333333333333300010000237C" +
                "0000237C44444444444444444444444444444444444444444444444444444444444444440001000004B0555555555555" +
                "555555555555555555555555555555555555555555555555555510001000",
        )

        fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02X".format(it.toInt() and 0xff) }

        fun bytes(hex: String): ByteArray {
            require(hex.length % 2 == 0) { "odd hex length" }
            return ByteArray(hex.length / 2) { ((Character.digit(hex[2 * it], 16) shl 4) or Character.digit(hex[2 * it + 1], 16)).toByte() }
        }
    }
}
