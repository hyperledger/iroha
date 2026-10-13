// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.consensus

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Collections
import org.hyperledger.iroha.sdk.address.decodePublicKeyLiteral
import org.hyperledger.iroha.sdk.address.encodePublicKeyMultihash

/** Maximum JSON response size accepted from `GET /v1/sumeragi/lanes`. */
const val SUMERAGI_LANES_JSON_MAX_BYTES: Long = 16L * 1024L * 1024L

/** Algorithm names the Rust data model admits in `SumeragiParameters.key_allowed_algorithms`. */
private val SUMERAGI_KEY_ALGORITHMS: Set<String> = setOf(
    "ed25519", "secp256k1", "ml-dsa", "bls_normal", "bls_small",
    "gost3410-2012-256-paramset-a", "gost3410-2012-256-paramset-b", "gost3410-2012-256-paramset-c",
    "gost3410-2012-512-paramset-a", "gost3410-2012-512-paramset-b", "sm2",
)

/** Chain parameters pinned into one lane incarnation (Rust `SumeragiParameters`). */
class SumeragiParameters internal constructor(
    @JvmField val blockCadenceMs: BigInteger,
    @JvmField val maxClockDriftMs: BigInteger,
    /** Positive committed first-Prepare freshness allowance for due work. */
    @JvmField val dueWorkMaxLagMs: BigInteger,
    @JvmField val keyActivationLeadBlocks: BigInteger,
    @JvmField val keyOverlapGraceBlocks: BigInteger,
    @JvmField val keyExpiryGraceBlocks: BigInteger,
    keyAllowedAlgorithms: List<String>,
    @JvmField val payloadRetryIntervalMs: BigInteger,
    @JvmField val execBudgetMs: BigInteger,
    @JvmField val applyBudgetMs: BigInteger,
    @JvmField val maxBlockBytes: BigInteger,
    @JvmField val epochLengthBlocks: BigInteger,
    @JvmField val demotionWindow: BigInteger,
) : SumeragiStatusValue() {
    /** Allowed consensus key algorithms, in the served order. */
    @JvmField val keyAllowedAlgorithms: List<String> =
        Collections.unmodifiableList(ArrayList(keyAllowedAlgorithms))

    override fun equalityFields(): List<Any?> = listOf(
        blockCadenceMs, maxClockDriftMs, dueWorkMaxLagMs, keyActivationLeadBlocks, keyOverlapGraceBlocks,
        keyExpiryGraceBlocks, keyAllowedAlgorithms, payloadRetryIntervalMs, execBudgetMs,
        applyBudgetMs, maxBlockBytes, epochLengthBlocks, demotionWindow,
    )
}

/** One pinned lane committee member: its BLS-normal peer key and admitted proof of possession. */
class SumeragiLaneMember internal constructor(
    @JvmField val peer: String,
    proofOfPossession: ByteArray,
) : SumeragiStatusValue() {
    private val pop: ByteArray = proofOfPossession.copyOf()

    /** A copy of the 96-byte proof of possession. */
    fun proofOfPossession(): ByteArray = pop.copyOf()

    override fun equalityFields(): List<Any?> = listOf(peer, pop.toList())
}

/** The highest lane block the global chain merged (`height` 0: nothing merged yet). */
class SumeragiLaneFrontier internal constructor(
    @JvmField val height: BigInteger,
    @JvmField val blockHash: String,
    @JvmField val result: String,
) : SumeragiStatusValue() {
    override fun equalityFields(): List<Any?> = listOf(height, blockHash, result)
}

/** Mandatory signed RS16 geometry pinned into one lane incarnation. */
class SumeragiDataAvailabilityLayout internal constructor(
    @JvmField val encoding: String,
    @JvmField val chunkSizeBytes: BigInteger,
    @JvmField val dataShards: BigInteger,
    @JvmField val parityShards: BigInteger,
    @JvmField val maxPayloadSizeBytes: BigInteger,
    @JvmField val maxChunkCount: BigInteger,
) : SumeragiStatusValue() {
    init {
        require(encoding == "reed_solomon16") { "lane payload encoding must be Reed-Solomon16" }
        fun within(value: BigInteger, minimum: Long, maximum: Long): Boolean =
            value >= BigInteger.valueOf(minimum) && value <= BigInteger.valueOf(maximum)
        require(within(chunkSizeBytes, 2, 256 * 1024) && !chunkSizeBytes.testBit(0) &&
            within(dataShards, 1, 16) && within(parityShards, 1, 16) &&
            within(maxPayloadSizeBytes, 1, 16 * 1024 * 1024) && within(maxChunkCount, 1, 1024)) {
            "lane data-availability layout exceeds protocol bounds"
        }
        // Protocol caps above make every product fit in a signed Long.
        val data = dataShards.toLong()
        val chunk = chunkSizeBytes.toLong()
        val payload = maxPayloadSizeBytes.toLong()
        val stripeBytes = data * chunk
        val full = payload / stripeBytes
        val remainder = payload % stripeBytes
        val stripes = full + if (remainder > 0) 1 else 0
        val terminalRow = 2 * ((remainder + 2 * data - 1) / (2 * data))
        val width = data + parityShards.toLong()
        require(stripes * width <= maxChunkCount.toLong() &&
            (full * chunk + terminalRow) * width <= 32 * 1024 * 1024) {
            "lane data-availability geometry exceeds protocol bounds"
        }
    }

    override fun equalityFields(): List<Any?> = listOf(
        encoding, chunkSizeBytes, dataShards, parityShards, maxPayloadSizeBytes, maxChunkCount,
    )
}

/** The committed lifecycle record of one lane incarnation (`specs/sumeragi_lanes.md` §2.1). */
class SumeragiLaneRecord internal constructor(
    @JvmField val lane: BigInteger,
    @JvmField val dataspace: BigInteger,
    @JvmField val incarnation: String,
    @JvmField val params: SumeragiParameters,
    @JvmField val daLayout: SumeragiDataAvailabilityLayout,
    committee: List<SumeragiLaneMember>,
    @JvmField val createdAt: BigInteger,
    @JvmField val activeFrom: BigInteger,
    @JvmField val closing: BigInteger?,
    @JvmField val anchorFreshness: BigInteger,
    @JvmField val merged: SumeragiLaneFrontier,
    @JvmField val mergedAt: BigInteger,
    @JvmField val rescued: BigInteger,
) : SumeragiStatusValue() {
    /** The pinned committee in canonical order. */
    @JvmField val committee: List<SumeragiLaneMember> =
        Collections.unmodifiableList(ArrayList(committee))

    /** Whether the lane has a closing height. */
    fun isClosing(): Boolean = closing != null

    override fun equalityFields(): List<Any?> = listOf(
        lane, dataspace, incarnation, params, daLayout, committee, createdAt, activeFrom, closing,
        anchorFreshness, merged, mergedAt, rescued,
    )
}

/**
 * One lane as the node serves it: the committed record and the status of the node's instance
 * (`null` while the node runs no instance of it). This observation is not a finality proof.
 */
class SumeragiLaneStatus internal constructor(
    @JvmField val record: SumeragiLaneRecord,
    @JvmField val instance: SumeragiStatus?,
) : SumeragiStatusValue() {
    override fun equalityFields(): List<Any?> = listOf(record, instance)

    companion object {
        /** Strict bounded UTF-8 JSON list with required nullable fields and no unknown fields. */
        @JvmStatic
        fun parseJsonList(payload: ByteArray): List<SumeragiLaneStatus> {
            require(payload.isNotEmpty() && payload.size.toLong() <= SUMERAGI_LANES_JSON_MAX_BYTES) {
                "Sumeragi lanes response is empty or exceeds its byte limit"
            }
            return NativeLaneParser.parse(SumeragiJsonPrimitives.decodeUtf8(payload, "Sumeragi lanes"))
        }

        /** Strict JSON decoding; exact unsigned values never pass through floating point. */
        @JvmStatic
        fun parseJsonList(payload: String): List<SumeragiLaneStatus> =
            parseJsonList(payload.toByteArray(StandardCharsets.UTF_8))
    }
}

private object NativeLaneParser {
    private val statusFields = setOf("record", "instance")
    private val recordFields = setOf(
        "lane", "dataspace", "incarnation", "params", "da_layout", "committee", "created_at", "active_from",
        "closing", "anchor_freshness", "merged", "merged_at", "rescued",
    )
    private val paramFields = setOf(
        "block_cadence_ms", "max_clock_drift_ms", "due_work_max_lag_ms", "key_activation_lead_blocks",
        "key_overlap_grace_blocks", "key_expiry_grace_blocks", "key_allowed_algorithms",
        "payload_retry_interval_ms", "exec_budget_ms", "apply_budget_ms", "max_block_bytes",
        "epoch_length_blocks", "demotion_window",
    )
    private val memberFields = setOf("peer", "pop")
    private val layoutFields = setOf(
        "encoding", "chunk_size_bytes", "data_shards", "parity_shards", "max_payload_size_bytes", "max_chunk_count",
    )
    private val frontierFields = setOf("height", "block_hash", "result")
    private const val BLS_NORMAL_PREFIX = "ea0130"
    private const val BLS_NORMAL_POP_BYTES = 96
    // Bounds only the parse effort of a hostile body; the committee size is pinned per lane.
    private const val MAX_COMMITTEE = 1 shl 16

    fun parse(payload: String): List<SumeragiLaneStatus> {
        val lanes = SumeragiJsonPrimitives.array(
            SumeragiJsonPrimitives.parseValue(payload, "Sumeragi lanes"),
            "Sumeragi lanes",
            Int.MAX_VALUE,
        )
        return Collections.unmodifiableList(lanes.mapIndexed { index, lane -> status(lane, "lanes[$index]") })
    }

    private fun status(value: Any?, context: String): SumeragiLaneStatus {
        val r = SumeragiJsonPrimitives.exactObject(value, statusFields, context)
        val instance = r["instance"]?.let { NativeStatusParser.parseValue(it) }
        return SumeragiLaneStatus(record(r["record"], "$context.record"), instance)
    }

    private fun record(value: Any?, context: String): SumeragiLaneRecord {
        val r = SumeragiJsonPrimitives.exactObject(value, recordFields, context)
        fun u64(name: String) = SumeragiJsonPrimitives.u64(r[name], "$context.$name")
        val committee = SumeragiJsonPrimitives.array(r["committee"], "$context.committee", MAX_COMMITTEE)
            .mapIndexed { index, member -> member(member, "$context.committee[$index]") }
        val params = params(r["params"], "$context.params")
        val layout = layout(r["da_layout"], "$context.da_layout")
        require(params.maxBlockBytes <= layout.maxPayloadSizeBytes) {
            "$context block limit exceeds its data-availability payload limit"
        }
        return SumeragiLaneRecord(
            SumeragiJsonPrimitives.u32(r["lane"], "$context.lane"),
            u64("dataspace"),
            byte32(r["incarnation"], "$context.incarnation"),
            params,
            layout,
            committee,
            u64("created_at"),
            u64("active_from"),
            r["closing"]?.let { SumeragiJsonPrimitives.u64(it, "$context.closing") },
            u64("anchor_freshness"),
            frontier(r["merged"], "$context.merged"),
            u64("merged_at"),
            u64("rescued"),
        )
    }

    private fun params(value: Any?, context: String): SumeragiParameters {
        val r = SumeragiJsonPrimitives.exactObject(value, paramFields, context)
        fun u64(name: String) = SumeragiJsonPrimitives.u64(r[name], "$context.$name")
        fun nonzero(name: String) = SumeragiJsonPrimitives.positiveU64(r[name], "$context.$name")
        val algorithms = SumeragiJsonPrimitives.array(
            r["key_allowed_algorithms"],
            "$context.key_allowed_algorithms",
            Int.MAX_VALUE,
        ).map { algorithm ->
            require(algorithm is String && algorithm in SUMERAGI_KEY_ALGORITHMS) {
                "$context.key_allowed_algorithms contains an unknown algorithm"
            }
            algorithm
        }
        return SumeragiParameters(
            nonzero("block_cadence_ms"),
            u64("max_clock_drift_ms"),
            nonzero("due_work_max_lag_ms"),
            u64("key_activation_lead_blocks"),
            u64("key_overlap_grace_blocks"),
            u64("key_expiry_grace_blocks"),
            algorithms,
            nonzero("payload_retry_interval_ms"),
            nonzero("exec_budget_ms"),
            nonzero("apply_budget_ms"),
            SumeragiJsonPrimitives.positiveU32(r["max_block_bytes"], "$context.max_block_bytes"),
            nonzero("epoch_length_blocks"),
            nonzero("demotion_window"),
        )
    }

    private fun member(value: Any?, context: String): SumeragiLaneMember {
        val r = SumeragiJsonPrimitives.exactObject(value, memberFields, context)
        val peer = r["peer"]
        require(peer is String && peer.startsWith(BLS_NORMAL_PREFIX)) {
            "$context.peer must be a canonical BLS-normal public key"
        }
        val key = requireNotNull(decodePublicKeyLiteral(peer)) { "$context.peer is not an admitted public key" }
        require(encodePublicKeyMultihash(key.curveId, key.keyBytes) == peer) { "$context.peer must be canonical" }
        val pop = r["pop"]
        require(pop is String) { "$context.pop must be standard base64" }
        val bytes = try {
            Base64.getDecoder().decode(pop)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("$context.pop must be standard base64", error)
        }
        require(Base64.getEncoder().encodeToString(bytes) == pop) { "$context.pop must be canonical base64" }
        require(bytes.size == BLS_NORMAL_POP_BYTES) { "$context.pop must be a 96-byte BLS-normal proof" }
        return SumeragiLaneMember(peer, bytes)
    }

    private fun layout(value: Any?, context: String): SumeragiDataAvailabilityLayout {
        val r = SumeragiJsonPrimitives.exactObject(value, layoutFields, context)
        val encoding = SumeragiJsonPrimitives.exactObject(r["encoding"], setOf("encoding", "details"), "$context.encoding")
        require(encoding["encoding"] == "reed_solomon16" && encoding["details"] == null) {
            "$context encoding must be Reed-Solomon16"
        }
        val chunk = SumeragiJsonPrimitives.u32(r["chunk_size_bytes"], "$context.chunk_size_bytes")
        val data = SumeragiJsonPrimitives.u32(r["data_shards"], "$context.data_shards")
        val parity = SumeragiJsonPrimitives.u32(r["parity_shards"], "$context.parity_shards")
        val payload = SumeragiJsonPrimitives.u64(r["max_payload_size_bytes"], "$context.max_payload_size_bytes")
        val chunks = SumeragiJsonPrimitives.u32(r["max_chunk_count"], "$context.max_chunk_count")
        return SumeragiDataAvailabilityLayout("reed_solomon16", chunk, data, parity, payload, chunks)
    }

    private fun frontier(value: Any?, context: String): SumeragiLaneFrontier {
        val r = SumeragiJsonPrimitives.exactObject(value, frontierFields, context)
        return SumeragiLaneFrontier(
            SumeragiJsonPrimitives.u64(r["height"], "$context.height"),
            byte32(r["block_hash"], "$context.block_hash"),
            byte32(r["result"], "$context.result"),
        )
    }

    private fun byte32(value: Any?, context: String): String = SumeragiJsonPrimitives.byte32(value, context)
}
