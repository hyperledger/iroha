package org.hyperledger.iroha.sdk.consensus

import java.io.File
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.client.JsonEncoder

/** Exact Rust-generated `GET /v1/sumeragi/lanes` corpus; a missing capture is a test failure. */
object NativeLaneFixtures {
    @JvmStatic fun rows(): Map<String, String> {
        val relative = "fixtures/sumeragi/native_lanes_v1.tsv"
        val file = generateSequence(File(System.getProperty("user.dir"))) { it.parentFile }
            .map { File(it, relative) }.firstOrNull { it.isFile }
            ?: error("missing shared native lane fixture: $relative")
        val rows = file.readLines(Charsets.UTF_8).filter { it.isNotBlank() && !it.startsWith("#") }.map {
            val fields = it.split('\t')
            check(fields.size == 3) { "invalid native lane fixture row" }
            check(fields[2].isNotEmpty() && fields[2].length % 2 == 0 && fields[2].all { it in "0123456789abcdef" })
            fields[0] to fields[1]
        }
        check(rows.map { it.first }.toSet().size == rows.size) { "duplicate native lane fixture case" }
        val byName = rows.toMap()
        check(byName.keys == setOf("empty", "running_lane", "mixed_lanes")) {
            "native lane fixture must contain exactly every canonical case"
        }
        return byName
    }
    @JvmStatic fun json(name: String): String = requireNotNull(rows()[name])
}

class SumeragiLaneModelsTest {
    private val u64Max = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)
    private val u32Max = BigInteger.ONE.shiftLeft(32).subtract(BigInteger.ONE)

    @Test fun `layout construction enforces the same invariants as JSON decoding`() {
        fun layout(
            encoding: String = "reed_solomon16", chunk: Long = 262144, data: Long = 4,
            parity: Long = 2, payload: Long = 4194305, chunks: Long = 30,
        ) = SumeragiDataAvailabilityLayout(
            encoding, BigInteger.valueOf(chunk), BigInteger.valueOf(data), BigInteger.valueOf(parity),
            BigInteger.valueOf(payload), BigInteger.valueOf(chunks),
        )
        assertEquals(BigInteger.valueOf(4194305), layout().maxPayloadSizeBytes)
        for (invalid in listOf<() -> SumeragiDataAvailabilityLayout>(
            { layout(encoding = "legacy") }, { layout(chunk = 0) }, { layout(chunk = 3) },
            { layout(chunk = 262146) }, { layout(data = -1) }, { layout(data = 17) },
            { layout(parity = 0) }, { layout(parity = 17) }, { layout(payload = 0) },
            { layout(payload = 16777217) }, { layout(chunks = 29) }, { layout(chunks = 1025) },
        )) assertFails { invalid() }
    }

    private fun lanes(name: String = "mixed_lanes"): MutableList<Any?> =
        SumeragiJsonPrimitives.array(
            SumeragiJsonPrimitives.parseValue(NativeLaneFixtures.json(name), "fixture"),
            "fixture",
            Int.MAX_VALUE,
        ).toMutableList()

    @Suppress("UNCHECKED_CAST")
    private fun changed(change: (MutableMap<String, Any?>) -> Unit): String {
        val lanes = lanes()
        val lane = (lanes[0] as Map<String, Any?>).toMutableMap()
        change(lane)
        lanes[0] = lane
        return JsonEncoder.encode(lanes)
    }

    @Suppress("UNCHECKED_CAST")
    private fun changedRecord(change: (MutableMap<String, Any?>) -> Unit): String = changed { lane ->
        lane["record"] = (lane["record"] as Map<String, Any?>).toMutableMap().also(change)
    }

    @Test fun `Rust lane corpus preserves every lane state and unsigned range`() {
        assertEquals(emptyList(), SumeragiLaneStatus.parseJsonList(NativeLaneFixtures.json("empty")))

        val running = SumeragiLaneStatus.parseJsonList(NativeLaneFixtures.json("running_lane")).single()
        assertEquals(BigInteger.ONE, running.record.lane)
        assertEquals(BigInteger.ZERO, running.record.dataspace)
        assertEquals("11".repeat(32), running.record.incarnation)
        assertEquals(4, running.record.committee.size)
        assertTrue(running.record.committee.all { it.peer.startsWith("ea0130") && it.proofOfPossession().size == 96 })
        assertNull(running.record.closing)
        assertEquals(BigInteger.valueOf(40), running.record.createdAt)
        assertEquals(BigInteger.valueOf(42), running.record.activeFrom)
        assertEquals(BigInteger.valueOf(7), running.record.merged.height)
        assertEquals("22".repeat(32), running.record.merged.blockHash)
        assertEquals("33".repeat(32), running.record.merged.result)
        assertEquals(listOf("bls_normal"), running.record.params.keyAllowedAlgorithms)
        assertEquals(BigInteger.valueOf(60_000), running.record.params.dueWorkMaxLagMs)
        assertEquals("reed_solomon16", running.record.daLayout.encoding)
        assertEquals(BigInteger.valueOf(262144), running.record.daLayout.chunkSizeBytes)
        assertEquals(BigInteger.valueOf(4), running.record.daLayout.dataShards)
        assertEquals(BigInteger.valueOf(2), running.record.daLayout.parityShards)
        assertEquals(BigInteger.valueOf(16777216), running.record.daLayout.maxPayloadSizeBytes)
        assertEquals(BigInteger.valueOf(1024), running.record.daLayout.maxChunkCount)
        val instance = assertNotNull(running.instance)
        assertEquals(1, instance.protocolVersion)
        assertEquals(running.record.committee[0].peer, instance.leader)
        assertEquals(running.record.committee[1].peer, instance.signer)
        assertEquals("5a".repeat(32), instance.instance)
        assertEquals(u64Max, instance.footprint.probe)

        val mixed = SumeragiLaneStatus.parseJsonList(NativeLaneFixtures.json("mixed_lanes"))
        assertEquals(3, mixed.size)
        assertEquals(running, mixed[0])
        assertEquals(running.hashCode(), mixed[0].hashCode())
        val pending = mixed[1]
        assertNull(pending.instance)
        assertEquals(BigInteger.valueOf(16), pending.record.lane)
        assertEquals(u64Max, pending.record.dataspace)
        assertEquals(u64Max, pending.record.rescued)
        assertEquals(BigInteger.ZERO, pending.record.merged.height)
        assertEquals("00".repeat(32), pending.record.merged.blockHash)
        val closing = mixed[2]
        assertEquals(u32Max, closing.record.lane)
        assertEquals(u64Max, closing.record.closing)
        assertTrue(closing.record.isClosing())
        assertEquals(u64Max, closing.record.anchorFreshness)
        assertEquals(u64Max, closing.record.merged.height)
        assertEquals(SumeragiHaltKind.PUBLICATION_RECOVERY_REQUIRED, closing.instance?.halted?.kind)
        assertEquals(u64Max, closing.instance?.halted?.height)
        assertEquals(mixed, SumeragiLaneStatus.parseJsonList(NativeLaneFixtures.json("mixed_lanes").toByteArray()))
    }

    @Suppress("UNCHECKED_CAST")
    @Test fun `every lane field at every level is required and unknown fields fail closed`() {
        // The unmodified re-encoding stays valid, so each failure below comes from its own mutation.
        assertEquals(3, SumeragiLaneStatus.parseJsonList(changed { }).size)
        val lane = lanes()[0] as Map<String, Any?>
        for (field in lane.keys) assertFails(field) { SumeragiLaneStatus.parseJsonList(changed { it.remove(field) }) }
        assertFails { SumeragiLaneStatus.parseJsonList(changed { it["retired"] = null }) }
        val record = lane["record"] as Map<String, Any?>
        for (field in record.keys) {
            assertFails("record.$field") { SumeragiLaneStatus.parseJsonList(changedRecord { it.remove(field) }) }
        }
        for (retired in listOf("lane_finality_manifest", "merge_carrier", "queue_plan", "relay_envelope")) {
            assertFails(retired) { SumeragiLaneStatus.parseJsonList(changedRecord { it[retired] = null }) }
        }
        for (owner in listOf("params", "da_layout", "merged")) {
            val nested = record[owner] as Map<String, Any?>
            for (field in nested.keys) assertFails("$owner.$field") {
                SumeragiLaneStatus.parseJsonList(changedRecord { it[owner] = nested - field })
            }
            assertFails { SumeragiLaneStatus.parseJsonList(changedRecord { it[owner] = nested + ("legacy" to 0L) }) }
        }
        val layout = record["da_layout"] as Map<String, Any?>
        val encoding = layout["encoding"] as Map<String, Any?>
        for (field in encoding.keys) assertFails("da_layout.encoding.$field") {
            SumeragiLaneStatus.parseJsonList(changedRecord { it["da_layout"] = layout + ("encoding" to (encoding - field)) })
        }
        assertFails {
            SumeragiLaneStatus.parseJsonList(changedRecord {
                it["da_layout"] = layout + ("encoding" to (encoding + ("legacy" to null)))
            })
        }
        val member = (record["committee"] as List<Map<String, Any?>>)[0]
        for (field in member.keys) assertFails("committee.$field") {
            SumeragiLaneStatus.parseJsonList(changedRecord { it["committee"] = listOf(member - field) })
        }
        assertFails { SumeragiLaneStatus.parseJsonList(changed { it["instance"] = mapOf("protocol_version" to 1L) }) }
    }

    @Suppress("UNCHECKED_CAST")
    @Test fun `lane data availability keeps compact final stripes and rejects malformed RS16 geometry`() {
        val record = (lanes()[0] as Map<String, Any?>)["record"] as Map<String, Any?>
        val layout = record["da_layout"] as Map<String, Any?>
        val params = record["params"] as Map<String, Any?>
        fun changedLayout(values: Map<String, Any?>): String = changedRecord {
            // Keep the block bound valid so these cases exercise the changed DA geometry.
            it["params"] = params + ("max_block_bytes" to 4194304L)
            it["da_layout"] = layout + values
        }
        val compact = mapOf("max_payload_size_bytes" to 4194305L, "max_chunk_count" to 30L)
        assertEquals(BigInteger.valueOf(4194305), SumeragiLaneStatus.parseJsonList(changedLayout(compact))[0].record.daLayout.maxPayloadSizeBytes)
        for ((field, bad) in listOf(
            "chunk_size_bytes" to 0L, "chunk_size_bytes" to 1L, "chunk_size_bytes" to 3L, "chunk_size_bytes" to 262146L,
            "data_shards" to 0L, "data_shards" to 17L, "data_shards" to 65536L, "parity_shards" to 0L, "parity_shards" to 17L,
            "max_payload_size_bytes" to 0L, "max_payload_size_bytes" to 16777217L, "max_chunk_count" to 0L,
            "max_chunk_count" to 1025L, "max_chunk_count" to 95L,
        )) assertFails("$field=$bad") { SumeragiLaneStatus.parseJsonList(changedLayout(mapOf(field to bad))) }
        for (bad in listOf(
            mapOf("data_shards" to 1L, "parity_shards" to 2L),
            mapOf("encoding" to mapOf("encoding" to "plain", "details" to null)),
            mapOf("encoding" to mapOf("encoding" to "reed_solomon16", "details" to emptyMap<String, Any?>())),
            compact + ("max_chunk_count" to 29L),
        )) assertFails { SumeragiLaneStatus.parseJsonList(changedLayout(bad)) }
        assertFails { SumeragiLaneStatus.parseJsonList(changedRecord { it["params"] = params + ("max_block_bytes" to 16777217L) }) }
    }

    @Suppress("UNCHECKED_CAST")
    @Test fun `malformed lane scalars keys proofs and bodies never alias canonical values`() {
        val record = lanes()[0].let { (it as Map<String, Any?>)["record"] as Map<String, Any?> }
        for (bad in listOf<Any?>(-1L, "1", 1.5, null, true, BigInteger.ONE.shiftLeft(32))) {
            assertFails("lane $bad") { SumeragiLaneStatus.parseJsonList(changedRecord { it["lane"] = bad }) }
        }
        for (bad in listOf<Any?>(-1L, BigInteger.ONE.shiftLeft(64), "40", null)) {
            assertFails("created_at $bad") { SumeragiLaneStatus.parseJsonList(changedRecord { it["created_at"] = bad }) }
        }
        for (bad in listOf<Any?>("11".repeat(31), "aa".repeat(32), "11".repeat(33), 17L)) {
            assertFails("incarnation $bad") { SumeragiLaneStatus.parseJsonList(changedRecord { it["incarnation"] = bad }) }
        }
        val params = record["params"] as Map<String, Any?>
        for (field in listOf("block_cadence_ms", "due_work_max_lag_ms", "payload_retry_interval_ms", "exec_budget_ms", "apply_budget_ms",
            "max_block_bytes", "epoch_length_blocks", "demotion_window")) {
            assertFails("zero $field") { SumeragiLaneStatus.parseJsonList(changedRecord { it["params"] = params + (field to 0L) }) }
        }
        assertEquals(u64Max, SumeragiLaneStatus.parseJsonList(changedRecord {
            it["params"] = params + ("due_work_max_lag_ms" to u64Max)
        })[0].record.params.dueWorkMaxLagMs)
        for (bad in listOf<Any?>(-1L, u64Max + BigInteger.ONE, "60000", true, null)) {
            assertFails("due-work lag $bad") {
                SumeragiLaneStatus.parseJsonList(changedRecord { it["params"] = params + ("due_work_max_lag_ms" to bad) })
            }
        }
        assertFails { SumeragiLaneStatus.parseJsonList(changedRecord { it["params"] = params + ("max_block_bytes" to BigInteger.ONE.shiftLeft(32)) }) }
        for (algorithms in listOf<Any?>(listOf("bls"), listOf("BLS_NORMAL"), "bls_normal", listOf(1L))) {
            assertFails("algorithms $algorithms") {
                SumeragiLaneStatus.parseJsonList(changedRecord { it["params"] = params + ("key_allowed_algorithms" to algorithms) })
            }
        }
        val member = (record["committee"] as List<Map<String, Any?>>)[0]
        val peer = member["peer"] as String
        val pop = member["pop"] as String
        for (badPeer in listOf(peer.lowercase(), "bls_normal:$peer", "ed0120" + "AB".repeat(32), " $peer")) {
            assertFails(badPeer) {
                SumeragiLaneStatus.parseJsonList(changedRecord { it["committee"] = listOf(member + ("peer" to badPeer)) })
            }
        }
        for (badPop in listOf(pop.dropLast(4), pop + "AAAA", "-" + pop.drop(1), "$pop=", "")) {
            assertFails(badPop) {
                SumeragiLaneStatus.parseJsonList(changedRecord { it["committee"] = listOf(member + ("pop" to badPop)) })
            }
        }
        val payload = NativeLaneFixtures.json("running_lane")
        assertFails { SumeragiLaneStatus.parseJsonList(payload.replace("\"rescued\":0", "\"rescued\":-0")) }
        assertFails { SumeragiLaneStatus.parseJsonList(payload.replace("\"rescued\":0", "\"rescued\":0,\"rescued\":0")) }
        assertFails { SumeragiLaneStatus.parseJsonList("{}") }
        assertFails { SumeragiLaneStatus.parseJsonList("") }
        assertFails { SumeragiLaneStatus.parseJsonList(byteArrayOf(0x5b, 0xc3.toByte(), 0x28, 0x5d)) }
        assertFails { SumeragiLaneStatus.parseJsonList(ByteArray((SUMERAGI_LANES_JSON_MAX_BYTES + 1).toInt()) { ' '.code.toByte() }) }
    }
}
