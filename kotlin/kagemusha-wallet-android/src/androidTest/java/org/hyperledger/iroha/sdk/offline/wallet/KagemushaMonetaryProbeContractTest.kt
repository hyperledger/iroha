// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.math.BigInteger
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import org.junit.Assert.*
import org.junit.Test

/** Host-compatible controller/lifetime contracts only: no Native, prompt, key or physical evidence. */
class KagemushaMonetaryProbeContractTest {
    private fun refused(body: () -> Unit) {
        try { body(); fail("expected closed refusal") } catch (_: EnrollmentProbeFailure) { }
    }
    private fun command(action: String, names: Set<String>): EnrollmentProbeCommand {
        val inputs = names.associateWith { name -> probeObject(probeJson("path" to "inbox/selected/$name",
            "size" to "1", "sha256" to "a".repeat(64))) }
        return EnrollmentProbeCommand(org.hyperledger.iroha.sdk.json.Json.obj(mapOf(
            "action" to org.hyperledger.iroha.sdk.json.Json.of(action),
            "inputs" to org.hyperledger.iroha.sdk.json.Json.obj(inputs))))
    }
    @Test fun monetarySchemasAreClosedAndOptionalBundlesAreAllOrNothing() {
        for ((action, schemas) in KagemushaMonetaryProbeManifest.schemas) {
            for (names in schemas) {
                assertEquals(action, command(action, names).action)
                assertEquals(names, command(action, names).pins.keys)
                names.forEach { assertTrue(KagemushaMonetaryProbeManifest.maximum(it) > 0) }
                refused { command(action, names + "caller-verdict") }
                names.forEach { missing ->
                    if (names - missing !in schemas) refused { command(action, names - missing) }
                }
            }
        }
        refused { command("execute-reviewed", setOf("request-id", "unsigned-permission")) }
        refused { command("destructively-delete", emptySet()) }
        refused { command("request", setOf("setup-id", "amount", "fee-schedule")) }
        refused { command("request", setOf("setup-id", "offer")) }
        refused { command("review-unload", setOf("request-id", "amount", "quote", "certificates")) }
        assertEquals(36 * 1024 * 1024, KagemushaMonetaryProbeManifest.maximum("finality"))
    }
    @Test fun amountsAndIdentifiersPreserveUnsignedBitsAndRefuseTruncation() {
        val all = ByteArray(16) { 0xff.toByte() }
        val max = KagemushaMonetaryProbeManifest.amount(all)
        assertEquals(-1L, max.low); assertEquals(-1L, max.high)
        assertEquals(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE).toString(), KagemushaMonetaryProbeManifest.decimal(max))
        val hi = ByteArray(16); hi[15] = 0x80.toByte(); hi[0] = 1
        assertEquals(BigInteger.ONE.shiftLeft(127).add(BigInteger.ONE).toString(),
            KagemushaMonetaryProbeManifest.decimal(KagemushaMonetaryProbeManifest.amount(hi)))
        assertEquals(BigInteger("18446744073709551615"), KagemushaMonetaryProbeManifest.limb(ByteArray(8) { -1 }))
        refused { KagemushaMonetaryProbeManifest.amount(ByteArray(16)) }
        refused { KagemushaMonetaryProbeManifest.amount(ByteArray(15) { 1 }) }
        refused { KagemushaMonetaryProbeManifest.amount(ByteArray(17) { 1 }) }
        refused { KagemushaMonetaryProbeManifest.limb(ByteArray(9)) }
        refused { KagemushaMonetaryProbeManifest.word(ByteArray(32)) }
        refused { KagemushaMonetaryProbeManifest.word(ByteArray(31) { 1 }) }
        assertArrayEquals(ByteArray(32) { 1 }, KagemushaMonetaryProbeManifest.word(ByteArray(32) { 1 }))
    }
    @Test fun exactIntentBindingIgnoresInputOrderButBindsFamilyNamesAndBytes() {
        val first = linkedMapOf("amount" to byteArrayOf(1), "request-id" to byteArrayOf(2))
        val original = KagemushaMonetaryProbeManifest.binding("load", first)
        assertArrayEquals(original, KagemushaMonetaryProbeManifest.binding("load", first.toList().reversed().toMap()))
        assertFalse(original.contentEquals(KagemushaMonetaryProbeManifest.binding("receive", first)))
        assertFalse(original.contentEquals(KagemushaMonetaryProbeManifest.binding("load", first + ("amount" to byteArrayOf(3)))))
        assertFalse(original.contentEquals(KagemushaMonetaryProbeManifest.binding("load", mapOf("renamed" to byteArrayOf(1), "request-id" to byteArrayOf(2)))))
    }
    @Test fun decisionBindsInvocationSequenceAndExactNativeProjection() {
        val projection = byteArrayOf(1, 2, 3)
        fun row(choice: String = "confirm", invocation: String = "actor-invocation", sequence: String = "7",
            digest: String = EnrollmentProbeFiles.digest(projection)) = probeJson(
                "decision" to choice, "invocation" to invocation, "reviewSequence" to sequence, "reviewSHA256" to digest)
        fun parse(bytes: ByteArray) = KagemushaMonetaryProbeManifest.Decision(bytes, "actor-invocation", 7, projection)
        assertTrue(parse(row()).confirmed); assertFalse(parse(row(choice = "cancel")).confirmed)
        refused { parse(row(choice = "approved")) }; refused { parse(row(invocation = "old-invocation")) }
        refused { parse(row(sequence = "07")) }; refused { parse(row(sequence = "8")) }
        refused { parse(row(digest = "a".repeat(64))) }
        refused { parse(row().toString(Charsets.UTF_8).replace("\"confirm\"", "\"confirm\",\"extra\":\"x\"").toByteArray()) }
        refused { parse(row().toString(Charsets.UTF_8).replace("\"7\"", "7").toByteArray()) }
    }
    @Test fun componentStagesNeverInferMoneyOrSettlementFromExportsAndUnknownStatus() {
        val real = mapOf("native-activation-confirmed" to "activated", "native-complete-load" to "loaded",
            "native-complete-send" to "sent", "native-complete-receive" to "received",
            "native-current-head-folded" to "folded", "native-unload-confirmed" to "unloaded")
        for ((status, stage) in real) assertEquals(stage, enrollmentProbeStage(status))
        for (status in listOf("native-activation-exported-not-submitted", "native-activation-rejected",
            "native-load-plan-retained", "native-review-awaiting-explicit-decision",
            "native-peer-envelope-decoded-not-admitted", "native-unload-claim-exported-not-settled",
            "native-activation-unconfirmed", "native-activation-epoch-required", "native-unload-unconfirmed",
            "native-unload-rejected", "native-unload-epoch-required", "native-current-head-not-folded") + (0..60).map { "native-call-status-$it" }) {
            assertNull(status, enrollmentProbeStage(status))
        }
        assertEquals("abandoned", enrollmentProbeStage("native-expired-local-abandoned"))
        assertEquals("e6", enrollmentProbeStage("native-durable-e6-exported-not-activated"))
    }
    @Test fun promptTicketRequiresFreshClaimAndRejectsStaleDuplicateAndLateCallbacks() {
        val first = KagemushaProbeConfirmationTicket<String>("first")
        assertFalse(first.succeed("unclaimed")); assertFalse(first.claim("wrong"))
        assertTrue(first.claim("first")); assertFalse(first.claim("first"))
        assertTrue(first.succeed("actual-callback")); assertFalse(first.succeed("duplicate"))
        assertFalse(first.fail(EnrollmentProbeFailure("late")))
        assertEquals("actual-callback", first.await(1, TimeUnit.SECONDS))
        val second = KagemushaProbeConfirmationTicket<String>("second")
        assertFalse(second.claim("first"))
        try { second.await(1, TimeUnit.MILLISECONDS); fail("fresh prompt must remain pending") }
        catch (_: TimeoutException) { }
        assertTrue(second.fail(EnrollmentProbeFailure("cancelled")))
        assertFalse(second.claim("second")); assertFalse(second.succeed("late-success"))
        try { second.await(1, TimeUnit.SECONDS); fail("cancelled ticket") }
        catch (failure: ExecutionException) { assertEquals("cancelled", (failure.cause as EnrollmentProbeFailure).code) }
    }
    private class Injected : RuntimeException()
    private class MemoryPublication : EnrollmentProbePublicationIo {
        val files = mutableMapOf<String, ByteArray>()
        var failAt: Int? = null
        var after = false
        var step = 0
        var race = false
        private fun <T> event(body: () -> T): T {
            val point = step++
            if (failAt == point && !after) throw Injected()
            val value = body()
            if (failAt == point && after) throw Injected()
            return value
        }
        override fun exists(path: String) = event { files.containsKey(path) }
        override fun requireExact(path: String, bytes: ByteArray, links: Long) = event {
            val value = files[path] ?: throw EnrollmentProbeFailure("absent")
            probeRequire(value.contentEquals(bytes), "collision")
            probeRequire(files.values.count { it === value }.toLong() == links, "custody")
        }
        override fun createStage(path: String, bytes: ByteArray) = event {
            probeRequire(!files.containsKey(path), "collision"); files[path] = bytes.copyOf()
        }
        override fun syncFile(path: String, links: Long) = event { probeRequire(files.containsKey(path), "absent") }
        override fun removeStage(path: String, links: Long) = event { files.remove(path); Unit }
        override fun renameStage(stage: String, target: String) = event {
            if (race) files[target] = files[stage]!!.copyOf()
            if (files.containsKey(target)) false else { files[target] = files.remove(stage)!!; true }
        }
        override fun syncParent(path: String) = event { Unit }
    }
    @Test fun exclusiveAttemptMarkerNeverPermitsDispatchAfterUncertainPublication() {
        val bytes = byteArrayOf(3, 2, 1)
        fun publish(io: MemoryPublication) = publishEnrollmentProbeOriginal(io, "attempt", "stage", bytes, exclusive = true)
        val completed = MemoryPublication(); publish(completed)
        val boundaries = completed.step
        assertTrue(boundaries >= 10)
        for (point in 0 until boundaries) for (after in listOf(false, true)) {
            val io = MemoryPublication(); io.failAt = point; io.after = after
            try { publish(io); fail("injection $point $after") } catch (_: Injected) { }
            val named = io.files.containsKey("attempt")
            io.failAt = null
            if (named) {
                refused { publish(io) } // lost acknowledgement cannot grant dispatch to a retry
                assertArrayEquals(bytes, io.files["attempt"])
            } else {
                publish(io) // no marker and therefore no Native dispatch yet
                assertArrayEquals(bytes, io.files["attempt"])
            }
            refused { publish(io) }
        }
    }
    @Test fun exclusiveMarkerRejectsSameByteRaceWhileOrdinaryRecordsRemainRetryable() {
        val bytes = byteArrayOf(4)
        val race = MemoryPublication(); race.race = true
        refused { publishEnrollmentProbeOriginal(race, "attempt", "stage", bytes, exclusive = true) }
        assertArrayEquals(bytes, race.files["attempt"])
        val ordinary = MemoryPublication()
        publishEnrollmentProbeOriginal(ordinary, "record", "stage", bytes)
        publishEnrollmentProbeOriginal(ordinary, "record", "stage", bytes)
        refused { publishEnrollmentProbeOriginal(ordinary, "record", "stage", byteArrayOf(5)) }
    }
    @Test fun activationRetentionReceiptOnlyAdmitsTheInitialNativeRetentionResult() {
        val invocation = "11111111-1111-4111-8111-111111111111"
        val wire = byteArrayOf(8, 9, 10)
        fun value(status: Int): KagemushaWalletLedgerOutcomeV1 {
            val awaiting = status == KagemushaWalletCallV1.LEDGER_AWAITING
            return KagemushaWalletLedgerOutcomeV1.of(KagemushaWalletCallV1(status, 0, 0,
                if (awaiting) 0L else 2L, 0, 0, if (awaiting) ByteArray(32) { 0x0f } else ByteArray(32) { 1 }))
        }
        val initial = value(KagemushaWalletCallV1.LEDGER_AWAITING)
        val original = activationRetentionReceipt(wire, initial, 44, invocation, 12)!!
        val row = probeObject(original)
        assertEquals(setOf("schema", "action", "signedWireSHA256", "signedWireBytes", "nativeResult",
            "entrypointHex", "nativeReturnedTicks", "invocation", "sequence"), row.keys)
        assertEquals("iroha.kagemusha.wallet-activation-retained.v1", row.text("schema"))
        assertEquals("retain-activation", row.text("action"))
        assertEquals(EnrollmentProbeFiles.digest(wire), row.text("signedWireSHA256"))
        assertEquals("3", row.text("signedWireBytes")); assertEquals("awaiting", row.text("nativeResult"))
        assertEquals("0f".repeat(32), row.text("entrypointHex"))
        assertEquals("44", row.text("nativeReturnedTicks")); assertEquals(invocation, row.text("invocation"))
        assertEquals("12", row.text("sequence"))
        assertFalse(original.contentEquals(activationRetentionReceipt(byteArrayOf(8, 9, 11), initial, 44, invocation, 12)))
        for (status in listOf(KagemushaWalletCallV1.LEDGER_REJECTED, KagemushaWalletCallV1.LEDGER_CONFIRMED)) {
            assertNull(activationRetentionReceipt(wire, value(status), 44, invocation, 12))
        }
        refused { activationRetentionReceipt(ByteArray(0), initial, 44, invocation, 12) }
        refused { activationRetentionReceipt(wire, initial, -1, invocation, 12) }
        refused { activationRetentionReceipt(wire, initial, 0, invocation, 12) }
        refused { activationRetentionReceipt(wire, initial, 44, invocation, 10000) }
    }

}
