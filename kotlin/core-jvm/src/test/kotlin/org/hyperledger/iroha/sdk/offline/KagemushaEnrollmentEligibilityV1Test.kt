// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline

import java.io.File
import java.math.BigInteger
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.hyperledger.iroha.sdk.crypto.IrohaHash
import org.hyperledger.iroha.sdk.client.JsonParser
import org.hyperledger.iroha.sdk.norito.CRC64
import org.hyperledger.iroha.sdk.norito.NoritoDecoder
import org.hyperledger.iroha.sdk.norito.NoritoEncoder
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.junit.jupiter.api.Test
import kotlin.test.*
import org.hyperledger.iroha.sdk.offline.KagemushaEnrollmentEligibilityV1 as E

class KagemushaEnrollmentEligibilityV1Test {
    private fun rows(name: String = "enrollment_eligibility_template_v1_vectors.json"): List<Map<*, *>> {
        val file = generateSequence(File(".").canonicalFile) { it.parentFile }.map {
            File(it, "fixtures/kagemusha/$name") }.first(File::isFile)
        val root = JsonParser.parse(file.readText()) as Map<*, *>
        assertEquals(1, (root["version"] as Number).toInt())
        return (root["cases"] as List<*>).map { it as Map<*, *> }.also { assertEquals(24, it.size) }
    }
    private fun hex(value: Any?): ByteArray = (value as String).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun n(value: Long) = BigInteger.valueOf(value)
    private fun clock(vararg times: Long): E.Clock { var i = 0; return E.Clock { check(i < times.size); n(times[i++]) } }
    private fun lookup(approved: Boolean = true, frozen: Boolean = false, revision: Long = 1, observed: Long = 1100) =
        E.CurrentLookup { _, _, _ -> E.Current(approved, frozen, n(revision), n(observed)) }
    private fun failure(code: E.FailureCode, run: () -> Unit) { assertEquals(code, assertFailsWith<E.Failure>(block = run).code) }

    @Test fun allConcreteAndTemplateRustFramesDigestsSignaturesAndExactResponses() {
        for (row in rows() + rows("enrollment_eligibility_v1_vectors.json")) {
            val p = hex(row["policy_hex"]); val q = hex(row["request_hex"]); val r = hex(row["response_hex"])
            val policy = E.decodePolicy(p); val request = E.decodeRequest(policy, q)
            val response = E.decodeResponse(policy, request, n(1100), r)
            assertContentEquals(p, policy.originalBytes()); assertContentEquals(q, request.originalBytes()); assertContentEquals(r, response.originalBytes())
            assertContentEquals(hex(row["policy_digest_hex"]), policy.digest()); assertContentEquals(hex(row["request_digest_hex"]), request.digest())
            assertContentEquals(hex(row["signing_message_hex"]), response.signingMessage()); assertContentEquals(hex(row["signature_hex"]), response.signature())
            assertEquals((row["authority"] as String).replace('-', '_').uppercase(), policy.authority.name)
            assertEquals((row["decision"] as String).replace('-', '_').uppercase(), response.decision.name)
            assertEquals((row["purpose"] as String).replace('-', '_').uppercase(), request.purpose.name)
            if (row.containsKey("template_hex")) {
                val t = hex(row["template_hex"]); val o = hex(row["observation_hex"])
                val template = E.decodeTemplate(t); val observation = E.decodeObservation(template, o)
                assertContentEquals(t, template.originalBytes()); assertContentEquals(o, observation.originalBytes())
                assertContentEquals(p, observation.policy.originalBytes()); assertContentEquals(q, observation.request.originalBytes())
                assertContentEquals(hex(row["asset_hex"]), observation.asset.originalBytes())
                assertContentEquals(hex(row["asset_digest_hex"]), observation.asset.digest())
                assertEquals((row["scale"] as Number).toInt(), observation.asset.scale)
                var reads = 0; var signs = 0; var times = 0
                val output = E.answer(template, o, E.Clock { times++; n(1100) }, E.CurrentLookup { asset, selected, actual ->
                    reads++; assertContentEquals(p, selected.originalBytes()); assertContentEquals(q, actual.originalBytes())
                    assertContentEquals(hex(row["asset_hex"]), asset.originalBytes())
                    E.Current(response.decision == E.Decision.APPROVED_UNFROZEN, response.decision == E.Decision.FROZEN, response.sourceRevision, n(1100))
                }, E.Signer { message -> signs++; assertContentEquals(hex(row["signing_message_hex"]), message); hex(row["signature_hex"]) })
                assertContentEquals(r, output); assertEquals(1, reads); assertEquals(1, signs); assertEquals(3, times)
            }
        }
    }
    @Test fun ordinaryEd25519CustodySignsExactMessageWithoutTransactionPrehash() {
        val row = rows().first()
        val privateKey = Ed25519PrivateKeyParameters(ByteArray(32) { 42 }, 0)
        val template = E.decodeTemplate(mutate(hex(row["template_hex"])) { this[5] = privateKey.generatePublicKey().encoded })
        val selected = E.decodeObservation(E.decodeTemplate(hex(row["template_hex"])), hex(row["observation_hex"]))
        val policy = template.forAsset(selected.asset)
        val observation = mutate(hex(row["observation_hex"])) { this[2] = mutatePayload(this[2]) { this[1] = policy.digest() } }
        val request = E.decodeObservation(template, observation).request
        fun sign(message: ByteArray): ByteArray = Ed25519Signer().run {
            init(true, privateKey); update(message, 0, message.size); generateSignature()
        }
        val original = E.answer(template, observation, clock(1100, 1100, 1100), lookup(), E.Signer(::sign))
        val response = E.decodeResponse(policy, request, n(1100), original)
        assertEquals(E.Decision.APPROVED_UNFROZEN, response.decision)
        assertContentEquals(request.digest(), response.requestDigest())
        failure(E.FailureCode.SIGNATURE) {
            E.answer(template, observation, clock(1100, 1100, 1100), lookup(), E.Signer { sign(IrohaHash.prehash(it)) })
        }
    }
    @Test fun frozenPrecedesApprovalAndEveryRequestReadsAgain() {
        val row = rows().first { it["decision"] == "frozen" }; val template = E.decodeTemplate(hex(row["template_hex"]))
        var reads = 0
        repeat(2) { assertContentEquals(hex(row["response_hex"]), E.answer(template, hex(row["observation_hex"]), clock(1100, 1100, 1100),
            E.CurrentLookup { _, _, _ -> reads++; E.Current(true, true, n(1), n(1100)) }, E.Signer { hex(row["signature_hex"]) })) }
        assertEquals(2, reads)
    }
    @Test fun failuresExpiryRollbackAndObservationsNeverEmitResponse() {
        val row = rows().first { it["decision"] == "approved-unfrozen" }; val template = E.decodeTemplate(hex(row["template_hex"])); val request = hex(row["observation_hex"])
        val signer = E.Signer { hex(row["signature_hex"]) }
        for (times in listOf(longArrayOf(999), longArrayOf(2000), longArrayOf(1100, 1099), longArrayOf(1100, 2000), longArrayOf(1100, 1100, 1099), longArrayOf(1100, 1100, 2000)))
            failure(E.FailureCode.CLOCK) { E.answer(template, request, clock(*times), lookup(), signer) }
        failure(E.FailureCode.CLOCK) { E.answer(template, request, E.Clock { error("clock unavailable") }, lookup(), signer) }
        for (value in listOf(lookup(revision = 0), lookup(observed = 1099), lookup(observed = 1101)))
            failure(E.FailureCode.INVALID_OBSERVATION) { E.answer(template, request, clock(1100, 1100, 1100), value, signer) }
        failure(E.FailureCode.UNAVAILABLE) { E.answer(template, request, clock(1100), E.CurrentLookup { _, _, _ -> error("unknown subject") }, signer) }
        failure(E.FailureCode.SIGNING) { E.answer(template, request, clock(1100, 1100), lookup(), E.Signer { error("signer unavailable") }) }
        val foreign = rows().first { it["decision"] == "frozen" }
        failure(E.FailureCode.SIGNATURE) { E.answer(template, request, clock(1100, 1100, 1100), lookup(), E.Signer { hex(foreign["signature_hex"]) }) }
    }
    @Test fun canonicalBoundsSchemasFlagsTruncationAndTrailingBytesReject() {
        val row = rows().first(); val policy = E.decodePolicy(hex(row["policy_hex"])); val request = E.decodeRequest(policy, hex(row["request_hex"]))
        for ((key, decode) in listOf<Pair<String, (ByteArray) -> Unit>>("policy_hex" to { E.decodePolicy(it) },
            "request_hex" to { E.decodeRequest(policy, it) }, "response_hex" to { E.decodeResponse(policy, request, n(1100), it) })) {
            val original = hex(row[key])
            for (bad in listOf(ByteArray(0), ByteArray(2049), original.copyOf(original.size - 1), original + byteArrayOf(0),
                original.copyOf().also { it[6] = (it[6].toInt() xor 1).toByte() }, original.copyOf().also { it[22] = 1 },
                original.copyOf().also { it[39] = 0 }, original.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }))
                assertFailsWith<E.Failure> { decode(bad) }
        }
    }
    @Test fun providerIdentityUnknownArmsRemovedLayoutAndWeakKeysReject() {
        val row = rows().first(); val original = hex(row["policy_hex"]); val policy = E.decodePolicy(original)
        for (index in listOf(1, 2, 3, 4, 6, 7)) assertFailsWith<E.Failure> { E.decodePolicy(mutate(original) { this[index] = ByteArray(this[index].size) }) }
        for (tag in listOf(0, 3, 255)) assertFailsWith<E.Failure> { E.decodePolicy(mutate(original) { this[5][0] = tag.toByte() }) }
        // The retired ninth classification field has no decoder or compatibility fallback.
        assertFailsWith<E.Failure> { E.decodePolicy(mutate(original) { add(5, byteArrayOf(1, 0, 0, 0)) }) }
        for (authority in listOf("bank", "scheme-operator")) {
            val selected = hex(rows().first { it["authority"] == authority }["policy_hex"])
            assertFailsWith<E.Failure> { E.decodePolicy(mutate(selected) { this[5].fill(0, this[5].size - 32) }) }
        }
        for (index in 1..6) assertFailsWith<E.Failure> { E.decodeRequest(policy, mutate(hex(row["request_hex"])) { this[index] = ByteArray(this[index].size) }) }
        val foreign = E.decodePolicy(hex(rows().first { it["authority"] == "scheme-operator" }["policy_hex"]))
        assertFailsWith<E.Failure> { E.decodeRequest(foreign, hex(row["request_hex"])) }
        val sameScopeOtherAuthority = E.decodePolicy(mutate(original) { this[5][0] = 2 })
        assertContentEquals(policy.scopeDigest(), sameScopeOtherAuthority.scopeDigest())
        assertFailsWith<E.Failure> { E.decodeRequest(sameScopeOtherAuthority, hex(row["request_hex"])) }
    }
    @Test fun strictSignaturePointScalarAndFreshRequestBindingReject() {
        val row = rows().first(); val policy = E.decodePolicy(hex(row["policy_hex"])); val request = E.decodeRequest(policy, hex(row["request_hex"]))
        val original = hex(row["response_hex"])
        for (signature in listOf(ByteArray(64), hex(row["signature_hex"]).also { it.fill(0, 0, 32); it[0] = 1 },
            hex(row["signature_hex"]).also { it.fill(0xff.toByte(), 32, 64) }, hex(row["signature_hex"]).also { it[40] = (it[40].toInt() xor 1).toByte() }))
            assertFailsWith<E.Failure> { E.decodeResponse(policy, request, n(1100), mutate(original) { this[1] = signature }) }
        for (now in listOf(1099L, 2000L, 2001L)) assertFailsWith<E.Failure> { E.decodeResponse(policy, request, n(now), original) }
        val other = E.decodeRequest(policy, mutate(hex(row["request_hex"])) { this[5][0] = 42 })
        assertFailsWith<E.Failure> { E.decodeResponse(policy, other, n(1100), original) }
    }
    @Test fun unsignedMaximumsAndDefensiveCopiesPreserveOriginals() {
        val row = rows().first(); val input = hex(row["policy_hex"]); val policy = E.decodePolicy(input); val before = policy.originalBytes()
        input.fill(0); policy.publicKey().fill(0); policy.networkId().fill(0); policy.scopeDigest().fill(0); policy.originalBytes().fill(0)
        assertContentEquals(before, policy.originalBytes())
        val huge = E.decodePolicy(mutate(before) { this[4] = ByteArray(8) { 0xff.toByte() }; this[7] = ByteArray(8) { 0xff.toByte() } })
        assertEquals(BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE), huge.maximumResponseMs)
        val original = hex(row["request_hex"]); val request = E.decodeRequest(policy, original)
        original.fill(0); request.nonce().fill(0); request.actorDigest().fill(0); request.operationDigest().fill(0)
        assertContentEquals(hex(row["request_hex"]), request.originalBytes())
    }
    @Test fun observationAssetAndTemplateSubstitutionRejectBeforeLookup() {
        val row = rows().first(); val template = E.decodeTemplate(hex(row["template_hex"])); val original = hex(row["observation_hex"])
        val selected = E.decodeObservation(template, original)
        for (index in listOf(1, 2, 3)) {
            val wrong = mutate(original) { this[1] = mutatePayload(this[1]) { this[index][0] = (this[index][0].toInt() xor 1).toByte() } }
            failure(E.FailureCode.INVALID_REQUEST) { E.answer(template, wrong, E.Clock { error("no clock") }, E.CurrentLookup { _, _, _ -> error("no lookup") }, E.Signer { error("no signer") }) }
        }
        val otherAuthority = E.decodeTemplate(mutate(template.originalBytes()) { this[4][0] = 2 })
        assertContentEquals(template.scopeDigest(), otherAuthority.scopeDigest())
        failure(E.FailureCode.INVALID_REQUEST) { E.decodeObservation(otherAuthority, original) }
        for (wrong in listOf(ByteArray(0), ByteArray(2049), original + byteArrayOf(0), original.copyOf(original.size - 1)))
            failure(E.FailureCode.INVALID_REQUEST) { E.decodeObservation(template, wrong) }
        val copy = selected.asset.originalBytes(); copy.fill(0); selected.asset.assetDefinitionBytes().fill(0); selected.asset.incarnationBytes().fill(0)
        assertContentEquals(hex(row["asset_hex"]), selected.asset.originalBytes())
        val t = template.originalBytes(); t.fill(0); template.publicKey().fill(0); template.scopeDigest().fill(0)
        assertContentEquals(hex(row["template_hex"]), template.originalBytes())
    }
    private fun mutatePayload(payload: ByteArray, change: MutableList<ByteArray>.() -> Unit): ByteArray {
        val reader = NoritoDecoder(payload, NoritoHeader.COMPACT_LEN)
        val fields = mutableListOf<ByteArray>()
        while (reader.remaining() > 0) fields += reader.readBytes(reader.readLength(true).toInt())
        fields.change()
        return NoritoEncoder(NoritoHeader.COMPACT_LEN).apply { fields.forEach { writeLength(it.size.toLong(), true); writeBytes(it) } }.toByteArray()
    }
    private fun mutate(original: ByteArray, change: MutableList<ByteArray>.() -> Unit): ByteArray {
        val decoded = NoritoHeader.decode(original, null); val reader = NoritoDecoder(decoded.payload, NoritoHeader.COMPACT_LEN)
        val fields = mutableListOf<ByteArray>()
        while (reader.remaining() > 0) fields += reader.readBytes(reader.readLength(true).toInt())
        fields.change()
        val payload = NoritoEncoder(NoritoHeader.COMPACT_LEN).apply { fields.forEach { writeLength(it.size.toLong(), true); writeBytes(it) } }.toByteArray()
        return NoritoHeader(decoded.header.schemaHash, payload.size, CRC64.compute(payload), NoritoHeader.COMPACT_LEN, 0).encode() + payload
    }
}
