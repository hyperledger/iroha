// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.client

import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import org.hyperledger.iroha.sdk.client.ToriiKagemushaWalletEnrollmentRequestV1 as Request
import org.hyperledger.iroha.sdk.client.ToriiKagemushaWalletEnrollmentResponseV1 as Response
import org.hyperledger.iroha.sdk.norito.CRC64
import org.hyperledger.iroha.sdk.norito.NoritoEncoder
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.SchemaHash

/** Envelope construction tests; opaque sample originals do not establish native enrollment. */
class ToriiKagemushaWalletEnrollmentCodecV1Test {
    private val dispatch = byteArrayOf(1, 2, 3)
    private val evidence = byteArrayOf(4, 5, 6)
    private fun requests() = listOf(Request.preKey(dispatch), Request.evidence(dispatch, evidence),
        Request.issue(dispatch), Request.deliver(dispatch))
    private fun responses() = listOf(Response.Permit(byteArrayOf(7, 8)), Response.EvidenceReady,
        Response.Pending, Response.CredentialReady, Response.Credential(byteArrayOf(9, 10)))

    @Test
    fun rustCanonicalFixturesMatchEveryActionResponseAndInclusiveBoundary() {
        val fixture = generateSequence(File(".").canonicalFile) { it.parentFile }.map {
            File(it, "fixtures/kagemusha/enrollment_service_v1_vectors.json") }.first(File::isFile)
        val root = JsonParser.parse(fixture.readText()) as Map<*, *>
        assertEquals(1, (root["version"] as Number).toInt())
        assertEquals(Request.ROUTE, root["route"])
        assertEquals(Request.MAXIMUM_BYTES, (root["request_frame_max_bytes"] as Number).toInt())
        assertEquals(Response.MAXIMUM_BYTES, (root["response_frame_max_bytes"] as Number).toInt())
        fun rows(name: String) = (root[name] as List<*>).map { it as Map<*, *> }
        fun check(row: Map<*, *>, wire: ByteArray, includeWire: Boolean) {
            assertEquals((row["wire_length"] as Number).toInt(), wire.size, row["name"].toString())
            assertEquals((row["flags"] as Number).toInt(), wire[39].toInt())
            assertContentEquals(hex(row["header_hex"]), wire.copyOfRange(0, 40))
            assertContentEquals(hex(row["sha256"]), MessageDigest.getInstance("SHA-256").digest(wire))
            if (includeWire) assertContentEquals(hex(row["wire_hex"]), wire)
        }
        assertEquals(4, rows("requests").size)
        rows("requests").zip(requests()).forEach { (row, request) ->
            check(row, request.canonicalWire(), true)
            assertContentEquals(request.canonicalWire(), Request.decodeCanonical(hex(row["wire_hex"])).canonicalWire())
        }
        assertEquals(5, rows("responses").size)
        rows("responses").zip(responses()).forEachIndexed { index, (row, response) ->
            check(row, response.canonicalWire(), true)
            val request = requests()[when (index) { 0 -> 0; 1, 2 -> 1; 3 -> 2; else -> 3 }]
            assertContentEquals(response.canonicalWire(), request.decodeResponse(hex(row["wire_hex"])).canonicalWire())
        }
        val fullDispatch = ByteArray(Request.MAXIMUM_DISPATCH_BYTES) { 1 }
        val fullEvidence = ByteArray(Request.MAXIMUM_EVIDENCE_BYTES) { 2 }
        val bounds = listOf(Request.preKey(fullDispatch).canonicalWire(), Request.evidence(fullDispatch, fullEvidence).canonicalWire(),
            Request.issue(fullDispatch).canonicalWire(), Request.deliver(fullDispatch).canonicalWire(),
            Response.Permit(ByteArray(Response.MAXIMUM_PERMIT_BYTES) { 1 }).canonicalWire(),
            Response.Credential(ByteArray(Response.MAXIMUM_CREDENTIAL_BYTES) { 2 }).canonicalWire())
        assertEquals(6, rows("inclusive_bounds").size)
        rows("inclusive_bounds").zip(bounds).forEach { (row, wire) -> check(row, wire, false) }
    }

    @Test
    fun allRequestActionsRoundtripAndRecoveryPreservesExactOriginals() {
        requests().forEachIndexed { index, request ->
            val wire = request.canonicalWire()
            val recovered = Request.decodeCanonical(wire)
            wire.fill(0)
            assertEquals(index, recovered.action.tag)
            assertContentEquals(request.canonicalWire(), recovered.canonicalWire())
            assertContentEquals(dispatch, recovered.dispatchOriginal)
            assertContentEquals(if (index == 1) evidence else ByteArray(0), recovered.evidenceOriginal)
            recovered.dispatchOriginal.fill(0)
            recovered.evidenceOriginal.fill(0)
            assertContentEquals(request.canonicalWire(), recovered.canonicalWire())
        }
        val request = Request.evidence(dispatch, evidence)
        dispatch.fill(0); evidence.fill(0)
        assertContentEquals(byteArrayOf(1, 2, 3), request.dispatchOriginal)
        assertContentEquals(byteArrayOf(4, 5, 6), request.evidenceOriginal)
    }

    @Test
    fun responseMatrixRejectsEveryWrongActionAndReturnsTypedPending() {
        requests().forEachIndexed { action, request ->
            responses().forEachIndexed { variant, response ->
                val accepted = (action == 0 && variant == 0) || (action == 1 && variant in 1..2) ||
                    (action == 2 && variant == 3) || (action == 3 && variant == 4)
                if (accepted) {
                    val decoded = request.decodeResponse(response.canonicalWire())
                    assertContentEquals(response.canonicalWire(), decoded.canonicalWire())
                    if (variant == 2) assertSame(Response.Pending, decoded)
                } else assertFailsWith<IllegalArgumentException> { request.decodeResponse(response.canonicalWire()) }
            }
        }
    }

    @Test
    fun permitAndCredentialSnapshotAndReturnOwnedExactOriginals() {
        val original = byteArrayOf(7, 8)
        val permit = Response.Permit(original)
        val credential = Response.Credential(original)
        original.fill(0); permit.unverifiedOriginal.fill(0); credential.unverifiedOriginal.fill(0)
        assertContentEquals(byteArrayOf(7, 8), permit.unverifiedOriginal)
        assertContentEquals(byteArrayOf(7, 8), credential.unverifiedOriginal)
    }

    @Test
    fun inclusiveOriginalBoundsRoundtripAndExcessOrEmptyOriginalsFail() {
        val request = Request.evidence(ByteArray(Request.MAXIMUM_DISPATCH_BYTES), ByteArray(Request.MAXIMUM_EVIDENCE_BYTES))
        assertContentEquals(request.canonicalWire(), Request.decodeCanonical(request.canonicalWire()).canonicalWire())
        val permit = Response.Permit(ByteArray(Response.MAXIMUM_PERMIT_BYTES))
        assertContentEquals(permit.canonicalWire(), Request.preKey(dispatch).decodeResponse(permit.canonicalWire()).canonicalWire())
        val credential = Response.Credential(ByteArray(Response.MAXIMUM_CREDENTIAL_BYTES))
        assertContentEquals(credential.canonicalWire(), Request.deliver(dispatch).decodeResponse(credential.canonicalWire()).canonicalWire())
        for (bad in listOf(ByteArray(0), ByteArray(Request.MAXIMUM_DISPATCH_BYTES + 1))) {
            assertFailsWith<IllegalArgumentException> { Request.preKey(bad) }
            assertFailsWith<IllegalArgumentException> { Request.evidence(bad, evidence) }
            assertFailsWith<IllegalArgumentException> { Request.issue(bad) }
            assertFailsWith<IllegalArgumentException> { Request.deliver(bad) }
        }
        for (bad in listOf(ByteArray(0), ByteArray(Request.MAXIMUM_EVIDENCE_BYTES + 1))) {
            assertFailsWith<IllegalArgumentException> { Request.evidence(dispatch, bad) }
        }
        for (bad in listOf(ByteArray(0), ByteArray(Response.MAXIMUM_PERMIT_BYTES + 1))) {
            assertFailsWith<IllegalArgumentException> { Response.Permit(bad) }
        }
        for (bad in listOf(ByteArray(0), ByteArray(Response.MAXIMUM_CREDENTIAL_BYTES + 1))) {
            assertFailsWith<IllegalArgumentException> { Response.Credential(bad) }
        }
    }

    @Test
    fun malformedRequestShapeAndUnboundedLengthsFailBeforeAllocation() {
        fun request(version: Int = 1, action: Long = 0, dispatch: ByteArray = bytes(this.dispatch),
            evidence: ByteArray = bytes(ByteArray(0))): ByteArray = frame("request", fields(listOf(
                uint(version.toLong(), 16), uint(action, 32), dispatch, evidence)))
        val malformed = listOf(request(version = 0), request(version = 2), request(action = 4), request(action = 0xffffffffL),
            request(dispatch = bytes(ByteArray(0))), request(action = 1), request(evidence = bytes(evidence)),
            request(action = 2, evidence = bytes(evidence)), request(action = 3, evidence = bytes(evidence)),
            request(dispatch = uint(Long.MAX_VALUE, 64)), request(dispatch = uint(-1, 64)),
            request(dispatch = bytes(dispatch) + byteArrayOf(0)),
            frame("request", byteArrayOf(0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0x0f)))
        malformed.forEach { assertFailsWith<IllegalArgumentException> { Request.decodeCanonical(it) } }
    }

    @Test
    fun malformedResponseVariantsAndLengthsFail() {
        val malformed = listOf(frame("response", uint(5, 32)), frame("response", uint(0xffffffffL, 32)),
            frame("response", uint(0, 32)), frame("response", uint(0, 32) + fields(listOf(bytes(ByteArray(0))))),
            frame("response", uint(4, 32) + fields(listOf(bytes(ByteArray(0))))),
            frame("response", uint(0, 32) + fields(listOf(uint(Long.MAX_VALUE, 64)))),
            frame("response", uint(0, 32) + fields(listOf(bytes(ByteArray(Response.MAXIMUM_PERMIT_BYTES + 1))))),
            frame("response", uint(4, 32) + fields(listOf(bytes(ByteArray(Response.MAXIMUM_CREDENTIAL_BYTES + 1))))),
            frame("response", uint(1, 32) + byteArrayOf(0)), frame("response", uint(2, 32) + byteArrayOf(0)),
            frame("response", uint(3, 32) + byteArrayOf(0)))
        requests().forEach { request -> malformed.forEach { assertFailsWith<IllegalArgumentException> { request.decodeResponse(it) } } }
    }

    @Test
    fun canonicalDecoderRejectsBadHeaderChecksumSchemaCompressionPaddingAndTrailingData() {
        fun variants(wire: ByteArray, bound: Int): List<ByteArray> = listOf(
            ByteArray(0), ByteArray(bound + 1), wire.copyOf(wire.size - 1), wire + byteArrayOf(1),
            wire.copyOf().apply { this[0] = 0 }, wire.copyOf().apply { this[4] = 1 },
            wire.copyOf().apply { this[5] = 1 }, wire.copyOf().apply { this[6] = (this[6].toInt() xor 1).toByte() },
            wire.copyOf().apply { this[22] = 1 }, wire.copyOf().apply { this[31] = (this[31].toInt() xor 1).toByte() },
            wire.copyOf().apply { this[39] = (this[39].toInt() xor 2).toByte() }, wire.copyOf().apply { this[39] = 3 },
            wire.copyOfRange(0, 40) + ByteArray(8) + wire.copyOfRange(40, wire.size))
        variants(Request.preKey(dispatch).canonicalWire(), Request.MAXIMUM_BYTES).forEach {
            assertFailsWith<IllegalArgumentException> { Request.decodeCanonical(it) }
        }
        variants(Response.Pending.canonicalWire(), Response.MAXIMUM_BYTES).forEach {
            assertFailsWith<IllegalArgumentException> { Request.evidence(dispatch, evidence).decodeResponse(it) }
        }
        val payload = Request.preKey(dispatch).canonicalWire().drop(40).toByteArray()
        val nonminimal = frame("request", byteArrayOf(0x82.toByte(), 0) + payload.drop(1))
        assertFailsWith<IllegalArgumentException> { Request.decodeCanonical(nonminimal) }
    }

    // These helpers create malformed envelopes for negative tests, never cross-language goldens.
    private fun uint(value: Long, bits: Int) = NoritoEncoder(NoritoHeader.COMPACT_LEN).apply { writeUInt(value, bits) }.toByteArray()
    private fun bytes(value: ByteArray) = uint(value.size.toLong(), 64) + value
    private fun fields(values: List<ByteArray>) = NoritoEncoder(NoritoHeader.COMPACT_LEN).apply {
        values.forEach { writeLength(it.size.toLong(), true); writeBytes(it) }
    }.toByteArray()
    private fun frame(kind: String, payload: ByteArray): ByteArray = NoritoHeader(
        SchemaHash.hash16("iroha.torii.kagemusha.enrollment.$kind.v1"), payload.size, CRC64.compute(payload),
        NoritoHeader.COMPACT_LEN, NoritoHeader.COMPRESSION_NONE).encode() + payload
    private fun hex(value: Any?): ByteArray = (value as String).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
