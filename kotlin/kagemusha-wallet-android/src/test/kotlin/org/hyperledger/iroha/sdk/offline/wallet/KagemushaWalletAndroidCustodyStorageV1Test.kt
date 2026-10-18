// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.io.File
import java.io.FileDescriptor
import java.io.IOException
import kotlin.test.*
import org.junit.jupiter.api.Test

class KagemushaWalletAndroidCustodyStorageV1Test {
    private val parent = File("/owned/no_backup")
    private val child = File(parent, "kagemusha-wallet-v1")
    private val witness = File(parent, "kagemusha-wallet-root-v1.witness")
    private inner class Fs : KagemushaWalletAndroidStorageV1.CustodyOperations {
        override val uid = 10384
        override val gid = uid
        val directory = KagemushaWalletAndroidStorageV1.Stat(0x41c0, uid, gid, 7, 11)
        val nodes = mutableMapOf(parent to directory)
        val handles = mutableMapOf<FileDescriptor, Pair<File, KagemushaWalletAndroidStorageV1.Stat>>()
        var bytes = byteArrayOf()
        val retainedContents = byteArrayOf(9, 2, 7)
        val events = mutableListOf<String>()
        var onEvent: (String) -> Unit = {}
        var mkdirWinner: KagemushaWalletAndroidStorageV1.Stat? = null
        var ignoreSeal = false
        fun event(value: String) { events += value; onEvent(value) }
        fun name(path: File) = when(path) { parent -> "parent"; child -> "child"; witness -> "witness"; else -> error("unexpected path") }
        override fun lstat(directory: File): KagemushaWalletAndroidStorageV1.Stat {
            event("stat:${name(directory)}"); return nodes[directory] ?: throw IOException("absent")
        }
        override fun lstatOrAbsent(path: File): KagemushaWalletAndroidStorageV1.Stat? {
            event("probe:${name(path)}"); return nodes[path]
        }
        override fun openDirectory(directory: File): FileDescriptor {
            event("open:${name(directory)}")
            return FileDescriptor().also { handles[it] = directory to checkNotNull(nodes[directory]) }
        }
        override fun openWitness(path: File, create: Boolean): FileDescriptor {
            assertEquals(witness, path); event("open:witness:$create")
            if (create) {
                check(path !in nodes)
                nodes[path] = directory.copy(mode = 0x8180, inode = 30)
                bytes = byteArrayOf()
            }
            return FileDescriptor().also { handles[it] = path to checkNotNull(nodes[path]) }
        }
        override fun fstat(descriptor: FileDescriptor): KagemushaWalletAndroidStorageV1.Stat {
            val (path, stat) = checkNotNull(handles[descriptor]); event("fstat:${name(path)}"); return stat
        }
        override fun fchmod(descriptor: FileDescriptor, mode: Int) {
            val (path, stat) = checkNotNull(handles[descriptor]); assertEquals(witness, path); assertEquals(0x100, mode)
            event("seal:witness")
            if (!ignoreSeal) {
                val sealed = stat.copy(mode = 0x8100)
                handles[descriptor] = path to sealed
                if (nodes[path]?.inode == stat.inode) nodes[path] = sealed
            }
        }
        override fun mkdirPrivate(directory: File) {
            assertEquals(child, directory); event("mkdir:child")
            check(directory !in nodes)
            nodes[directory] = mkdirWinner ?: this.directory.copy(inode = 20)
        }
        override fun readWitness(descriptor: FileDescriptor): ByteArray {
            assertEquals(witness, handles[descriptor]?.first); event("read:witness"); return bytes.copyOf()
        }
        override fun writeWitness(descriptor: FileDescriptor, bytes: ByteArray) {
            assertEquals(witness, handles[descriptor]?.first); event("write:witness"); this.bytes = bytes.copyOf()
        }
        override fun fsync(descriptor: FileDescriptor) { event("sync:${name(checkNotNull(handles[descriptor]).first)}") }
        override fun close(descriptor: FileDescriptor) { event("close:${name(checkNotNull(handles[descriptor]).first)}"); handles.remove(descriptor) }
    }
    private fun prepare(fs: Fs) = KagemushaWalletAndroidStorageV1.prepareCustodyRoot(parent, fs)

    @Test fun `fresh root reserves durable witness before mkdir and reopens exact inode without changing contents`() {
        val fs = Fs()
        assertEquals(child, prepare(fs))
        val mkdir = fs.events.indexOf("mkdir:child")
        assertTrue(fs.events.indexOf("sync:witness") < mkdir)
        assertTrue(fs.events.indexOf("sync:parent") < mkdir)
        val write = fs.events.indexOf("write:witness")
        assertTrue(fs.events.indexOf("sync:child") < write)
        assertTrue(fs.events.subList(write + 1, fs.events.indexOf("seal:witness")).contains("sync:witness"))
        assertEquals(32, fs.bytes.size); assertEquals(0x8100, fs.nodes[witness]?.mode)
        val root = fs.nodes[child]; val binding = fs.bytes.copyOf()
        fs.events.clear()
        assertEquals(child, prepare(fs))
        assertEquals(root, fs.nodes[child]); assertContentEquals(binding, fs.bytes)
        assertContentEquals(byteArrayOf(9, 2, 7), fs.retainedContents)
        assertFalse(fs.events.any { it.startsWith("mkdir") || it.startsWith("write") || it.startsWith("seal") })
        assertTrue(fs.handles.isEmpty())
    }
    @Test fun `existing strict root is preserved and bound before its first native opening`() {
        val fs = Fs().apply { nodes[child] = directory.copy(inode = 22) }
        val before = fs.nodes[child]
        assertEquals(child, prepare(fs)); assertEquals(before, fs.nodes[child])
        assertFalse("mkdir:child" in fs.events); assertTrue("seal:witness" in fs.events)
    }
    @Test fun `missing or replaced witnessed root is never recreated or rebound`() {
        for (replacement in listOf<KagemushaWalletAndroidStorageV1.Stat?>(null,
            Fs().directory.copy(inode = 99), Fs().directory.copy(device = 8, inode = 20))) {
            val fs = Fs(); prepare(fs); fs.events.clear()
            if (replacement == null) fs.nodes.remove(child) else fs.nodes[child] = replacement
            val before = fs.bytes.copyOf()
            assertFails { prepare(fs) }; assertContentEquals(before, fs.bytes)
            assertFalse(fs.events.any { it.startsWith("mkdir") || it.startsWith("write") || it.startsWith("seal") })
            assertTrue(fs.handles.isEmpty())
        }
    }
    @Test fun `unsafe existing child or witness is refused without repair`() {
        val original = Fs().directory
        for (bad in listOf(original.copy(mode = 0x41f9), original.copy(uid = 10385),
            original.copy(gid = 10385), original.copy(mode = 0xa1c0), original.copy(mode = 0x81c0))) {
            val fs = Fs().apply { nodes[child] = bad }
            assertFails { prepare(fs) }; assertEquals(bad, fs.nodes[child]); assertNull(fs.nodes[witness])
            assertTrue(fs.handles.isEmpty())
        }
        for (bad in listOf(original.copy(mode = 0x8180), original.copy(mode = 0x8100, links = 2),
            original.copy(mode = 0x8100, uid = 10385), original.copy(mode = 0xa100))) {
            val fs = Fs(); prepare(fs); fs.nodes[witness] = bad; fs.events.clear()
            assertFails { prepare(fs) }; assertEquals(bad, fs.nodes[witness])
            assertFalse("write:witness" in fs.events); assertTrue(fs.handles.isEmpty())
        }
        val partial = Fs(); prepare(partial); partial.bytes = byteArrayOf(1)
        assertFails { prepare(partial) }; assertContentEquals(byteArrayOf(1), partial.bytes)
    }
    @Test fun `interrupted creation write and binding sync preserve pending witness and refuse retry creation`() {
        for (point in listOf("mkdir:child", "write:witness", "binding-sync")) {
            val fs = Fs(); var written = false
            fs.onEvent = { value ->
                if (value == "write:witness") written = true
                if (value == point || (point == "binding-sync" && written && value == "sync:witness")) throw IOException(point)
            }
            assertFailsWith<IOException> { prepare(fs) }; assertEquals(0x8180, fs.nodes[witness]?.mode)
            assertTrue(fs.handles.isEmpty()); fs.onEvent = {}; fs.events.clear()
            assertFails { prepare(fs) }
            assertFalse("mkdir:child" in fs.events); assertFalse("write:witness" in fs.events)
        }
    }
    @Test fun `raced parent and opened child replacements fail without deleting anything`() {
        val parentRace = Fs().apply {
            onEvent = { if (it == "probe:child") nodes[parent] = directory.copy(inode = 88) }
        }
        assertFails { prepare(parentRace) }; assertNull(parentRace.nodes[child]); assertNull(parentRace.nodes[witness])
        val childRace = Fs().apply {
            onEvent = { if (it == "fstat:child") nodes[child] = directory.copy(inode = 88) }
        }
        assertFails { prepare(childRace) }; assertEquals(88L, childRace.nodes[child]?.inode)
        assertEquals(0x8180, childRace.nodes[witness]?.mode); assertTrue(childRace.handles.isEmpty())
    }
    @Test fun `mkdir EEXIST winner is accepted only with strict private custody`() {
        val good = Fs().apply { mkdirWinner = directory.copy(inode = 24) }
        assertEquals(child, prepare(good)); assertEquals(24L, good.nodes[child]?.inode)
        val unsafe = Fs().apply { mkdirWinner = directory.copy(mode = 0x41f9, inode = 24) }
        assertFails { prepare(unsafe) }; assertEquals(0x41f9, unsafe.nodes[child]?.mode)
        assertEquals(0x8180, unsafe.nodes[witness]?.mode)
    }
    @Test fun `failed seal or final sync never returns custody or repairs an existing witness`() {
        val noop = Fs().apply { ignoreSeal = true }
        assertFails { prepare(noop) }; assertEquals(0x8180, noop.nodes[witness]?.mode); assertTrue(noop.handles.isEmpty())
        val sync = Fs(); prepare(sync); sync.events.clear()
        sync.onEvent = { if (it == "sync:child") throw IOException("sync") }
        assertFailsWith<IOException> { prepare(sync) }
        assertFalse(sync.events.any { it.startsWith("write") || it.startsWith("mkdir") || it.startsWith("seal") })
        assertTrue(sync.handles.isEmpty())
    }
}
