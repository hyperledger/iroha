// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.io.IOException
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

/** Deterministic test-mailbox crash model, separate from Android or Native custody evidence. */
class EnrollmentProbePublicationTest {
    private val target = "private/identity.json"
    private val stage = "private/.kagemusha-publication-stage"
    private val original = byteArrayOf(10, 20, 30, 40)

    private class Inode(var bytes: ByteArray) {
        var synced: ByteArray? = null
    }
    private class Files : EnrollmentProbePublicationIo {
        val names = linkedMapOf<String, Inode>()
        private var syncedNames = linkedMapOf<String, Inode>()
        val events = mutableListOf<String>()
        var failAt: Int? = null
        var partialWrite = false
        var contender: Pair<String, ByteArray>? = null
        private fun event(name: String) {
            events.add(name)
            if (events.size == failAt) throw IOException("injected publication interruption")
        }
        private fun <T> operation(name: String, action: () -> T): T {
            event("before:$name")
            val result = action()
            event("after:$name")
            return result
        }
        private fun file(path: String, links: Long): Inode {
            val file = names.getValue(path)
            check(names.values.count { it === file }.toLong() == links)
            return file
        }
        override fun exists(path: String) = operation("exists:$path") { path in names }
        override fun requireExact(path: String, bytes: ByteArray, links: Long) = operation("verify:$path") {
            probeRequire(file(path, links).bytes.contentEquals(bytes), "collision")
        }
        override fun createStage(path: String, bytes: ByteArray) = operation("write:$path") {
            check(path !in names)
            names[path] = Inode(bytes.copyOf(if (partialWrite) 1 else bytes.size))
            if (partialWrite) throw IOException("injected partial write")
        }
        override fun syncFile(path: String, links: Long) = operation("fsync:$path") {
            file(path, links).let { it.synced = it.bytes.copyOf() }
        }
        override fun removeStage(path: String, links: Long) = operation("unlink:$path") {
            file(path, links)
            names.remove(path)
            Unit
        }
        override fun renameStage(stage: String, target: String) = operation("rename:$target") {
            contender?.let { (name, bytes) -> names[name] = Inode(bytes.copyOf()) }
            if (target in names) false else {
                names[target] = file(stage, 1)
                names.remove(stage)
                true
            }
        }
        override fun syncParent(path: String) = operation("directory:$path") {
            syncedNames = LinkedHashMap(names)
        }
        fun crash(namesSurviveWithoutSync: Boolean) {
            val retained = if (namesSurviveWithoutSync) names else syncedNames
            names.clearAndPut(retained.toMap())
            names.values.distinct().forEach { inode ->
                // Unsynced staging may survive partially; a target may only name a synced inode.
                inode.bytes = inode.synced?.copyOf() ?: inode.bytes.copyOf(minOf(1, inode.bytes.size))
            }
            failAt = null
            partialWrite = false
            events.clear()
        }
        private fun <K, V> MutableMap<K, V>.clearAndPut(values: Map<K, V>) {
            clear(); putAll(values)
        }
        fun assertDurable(path: String, bytes: ByteArray) {
            assertEquals(setOf(path), names.keys)
            val file = names.getValue(path)
            assertContentEquals(bytes, file.bytes)
            assertContentEquals(bytes, file.synced)
            assertEquals(setOf(path), syncedNames.keys)
            assertTrue(syncedNames.getValue(path) === file)
        }
    }

    private fun publish(files: Files, bytes: ByteArray = original) =
        publishEnrollmentProbeOriginal(files, target, stage, bytes)

    @Test fun `publication makes bytes durable before exposing the final name`() {
        val files = Files()
        publish(files)
        files.assertDurable(target, original)
        assertTrue(files.events.indexOf("after:fsync:$stage") < files.events.indexOf("before:rename:$target"))
        assertTrue(files.events.indexOf("after:rename:$target") < files.events.indexOf("before:directory:$target"))
        assertFalse(stage in files.names)
    }

    @Test fun `every interrupted filesystem boundary resumes with the same original`() {
        val successful = Files().also { publish(it) }
        for (boundary in 1..successful.events.size) {
            for (unsyncedNamesSurvive in listOf(false, true)) {
                val files = Files().apply { failAt = boundary }
                assertFailsWith<IOException>("boundary $boundary") { publish(files) }
                files.names[target]?.let { assertContentEquals(original, it.bytes) }
                files.crash(unsyncedNamesSurvive)
                files.names[target]?.let { assertContentEquals(original, it.bytes) }
                publish(files)
                files.assertDurable(target, original)
            }
        }
    }

    @Test fun `partial unpublished staging is discarded without poisoning the final identity`() {
        val files = Files().apply { partialWrite = true }
        assertFailsWith<IOException> { publish(files) }
        assertFalse(target in files.names)
        assertContentEquals(byteArrayOf(10), files.names.getValue(stage).bytes)
        files.partialWrite = false
        publish(files)
        files.assertDurable(target, original)
    }

    @Test fun `an identical existing original always retries both synchronization barriers`() {
        val files = Files().also { publish(it) }
        files.events.clear()
        publish(files)
        val events = files.events.toList()
        assertTrue("before:fsync:$target" in events)
        assertTrue("before:directory:$target" in events)
        for (failure in listOf("before:fsync:$target", "before:directory:$target")) {
            files.events.clear()
            files.failAt = events.indexOf(failure) + 1
            assertFailsWith<IOException> { publish(files) }
            files.failAt = null
            files.events.clear()
            publish(files)
            files.assertDurable(target, original)
        }
    }

    @Test fun `different originals never replace a published inode or delete its uncertain staging`() {
        val files = Files().also { publish(it) }
        val inode = files.names.getValue(target)
        files.names[stage] = Inode(byteArrayOf(88)) // A losing stage remains after a no-replace collision.
        assertFailsWith<EnrollmentProbeFailure> { publish(files, byteArrayOf(99)) }
        assertTrue(files.names.getValue(target) === inode && files.names.getValue(stage).bytes.contentEquals(byteArrayOf(88)))
        assertContentEquals(original, inode.bytes)
        publish(files)
        files.assertDurable(target, original)
    }

    @Test fun `no-replace races compare the winner and never overwrite it`() {
        for (winner in listOf(original, byteArrayOf(99))) {
            val files = Files().apply { contender = target to winner }
            if (winner.contentEquals(original)) {
                publish(files)
                files.assertDurable(target, original)
            } else {
                assertFailsWith<EnrollmentProbeFailure> { publish(files) }
                assertContentEquals(winner, files.names.getValue(target).bytes)
                assertContentEquals(original, files.names.getValue(stage).bytes)
            }
        }
    }

    @Test fun `unexpected aliases cannot be treated as disposable staging`() {
        val files = Files()
        val inode = Inode(byteArrayOf(1))
        files.names[stage] = inode
        files.names["unrelated-original"] = inode
        assertFailsWith<IllegalStateException> { publish(files) }
        assertTrue(files.names[stage] === inode && files.names["unrelated-original"] === inode)
        assertFalse(target in files.names)
    }
    @Test fun `exclusive attempts fence every interruption after naming`() {
        fun attempt(files: Files) = publishEnrollmentProbeOriginal(files, target, stage, original, exclusive = true)
        val completed = Files().also { attempt(it) }
        for (boundary in 1..completed.events.size) {
            val files = Files().apply { failAt = boundary }
            assertFailsWith<IOException> { attempt(files) }
            val named = target in files.names
            files.failAt = null
            if (named) {
                assertEquals("recovery-required", assertFailsWith<EnrollmentProbeFailure> { attempt(files) }.code)
                assertContentEquals(original, files.names.getValue(target).bytes)
            } else {
                attempt(files) // Nothing was named, so the caller could not have dispatched.
                files.assertDurable(target, original)
            }
            assertEquals("recovery-required", assertFailsWith<EnrollmentProbeFailure> { attempt(files) }.code)
        }
    }

    @Test fun `exclusive same-byte racing winner is recovery only`() {
        val files = Files().apply { contender = target to original }
        assertEquals("recovery-required", assertFailsWith<EnrollmentProbeFailure> {
            publishEnrollmentProbeOriginal(files, target, stage, original, exclusive = true)
        }.code)
        assertContentEquals(original, files.names.getValue(target).bytes)
        assertContentEquals(original, files.names.getValue(stage).bytes)
    }

    @Test fun `a target with an unexpected second link is never repaired`() {
        val files = Files().also { publish(it) }
        val inode = files.names.getValue(target)
        files.names["unrelated-original"] = inode
        assertFailsWith<IllegalStateException> { publish(files) }
        assertTrue(files.names.getValue(target) === inode && files.names.getValue("unrelated-original") === inode)
        assertContentEquals(original, inode.bytes)
    }

}
