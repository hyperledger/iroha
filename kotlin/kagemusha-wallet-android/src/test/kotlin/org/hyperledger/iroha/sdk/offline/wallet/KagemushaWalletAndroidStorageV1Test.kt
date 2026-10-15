// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.io.File
import java.io.FileDescriptor
import java.io.IOException
import kotlin.test.*
import org.junit.jupiter.api.Test

class KagemushaWalletAndroidStorageV1Test {
    private val directory = File("/owned/no_backup")
    private class Files : KagemushaWalletAndroidStorageV1.Operations {
        override val uid = 10384
        override val gid = 10384
        val descriptor = FileDescriptor()
        var named = KagemushaWalletAndroidStorageV1.Stat(0x41f9, uid, gid, 7, 11)
        var opened = named
        var namedReads = 0
        var fdReads = 0
        var onNamedRead: (Int) -> Unit = {}
        var onFdRead: (Int) -> Unit = {}
        var chmodFailure: Throwable? = null
        var syncFailure: Throwable? = null
        var closeFailure: Throwable? = null
        var ignoreChmod = false
        val events = mutableListOf<String>()
        override fun lstat(directory: File): KagemushaWalletAndroidStorageV1.Stat {
            events += "lstat"; onNamedRead(++namedReads); return named
        }
        override fun openDirectory(directory: File): FileDescriptor { events += "open"; return descriptor }
        override fun fstat(descriptor: FileDescriptor): KagemushaWalletAndroidStorageV1.Stat {
            assertSame(this.descriptor, descriptor)
            events += "fstat"; onFdRead(++fdReads); return opened
        }
        override fun fchmod(descriptor: FileDescriptor, mode: Int) {
            assertSame(this.descriptor, descriptor); assertEquals(0x1c0, mode)
            events += "fchmod"
            chmodFailure?.let { throw it }
            if (!ignoreChmod) {
                opened = opened.copy(mode = 0x4000 or mode)
                if (named.device == opened.device && named.inode == opened.inode) named = opened
            }
        }
        override fun fsync(descriptor: FileDescriptor) { assertSame(this.descriptor, descriptor); events += "fsync"; syncFailure?.let { throw it } }
        override fun close(descriptor: FileDescriptor) { assertSame(this.descriptor, descriptor); events += "close"; closeFailure?.let { throw it } }
    }
    private fun prepare(files: Files) = KagemushaWalletAndroidStorageV1.prepare(directory, files)

    @Test fun `stock Android own uid and gid 0771 is tightened through its descriptor`() {
        val files = Files()
        val before = files.named
        assertEquals(directory, prepare(files))
        assertEquals(before.copy(mode = 0x41c0), files.named)
        assertEquals(listOf("lstat", "open", "fstat", "lstat", "fchmod", "fsync", "fstat", "lstat", "close"), files.events)
    }

    @Test fun `existing 0700 is unchanged and repeated opening never chmods again`() {
        val files = Files().apply { named = named.copy(mode = 0x41c0); opened = named }
        repeat(2) { assertEquals(directory, prepare(files)) }
        assertFalse("fchmod" in files.events)
        assertFalse("fsync" in files.events)
        assertEquals(2, files.events.count { it == "close" })
    }

    @Test fun `foreign uid gid world write special modes and missing owner rights refuse before open`() {
        val original = Files().named
        val unsafe = listOf(original.copy(uid = 10385), original.copy(gid = 10385),
            original.copy(mode = 0x41ff), original.copy(mode = 0x49f9),
            original.copy(mode = original.mode and 0x80.inv()), original.copy(mode = original.mode and 0x40.inv()),
            original.copy(mode = original.mode and 0x100.inv()), original.copy(mode = 0xa1ff), original.copy(mode = 0x81c0))
        for (stat in unsafe) {
            val files = Files().apply { named = stat }
            assertFailsWith<IllegalStateException> { prepare(files) }
            assertEquals(listOf("lstat"), files.events)
        }
    }

    @Test fun `raced regular fifo and symlink descriptors are rejected before chmod and closed`() {
        for (mode in listOf(0x81c0, 0x11c0, 0xa1c0)) {
            val files = Files().apply { opened = opened.copy(mode = mode) }
            assertFailsWith<IllegalStateException> { prepare(files) }
            assertFalse("fchmod" in files.events)
            assertEquals("close", files.events.last())
        }
    }

    @Test fun `opened descriptor must retain preopen inode device uid and gid`() {
        val original = Files().opened
        for (changed in listOf(original.copy(inode = 12), original.copy(device = 8),
            original.copy(uid = 10385), original.copy(gid = 10385))) {
            val files = Files().apply { opened = changed }
            assertFailsWith<IllegalStateException> { prepare(files) }
            assertFalse("fchmod" in files.events)
            assertEquals("close", files.events.last())
        }
    }

    @Test fun `named replacement before mutation is rejected without chmod`() {
        val files = Files().apply { onNamedRead = { if (it == 2) named = named.copy(inode = 12) } }
        assertFailsWith<IllegalStateException> { prepare(files) }
        assertFalse("fchmod" in files.events)
        assertEquals("close", files.events.last())
    }

    @Test fun `named replacement after mutation is not returned as admitted`() {
        val files = Files().apply { onNamedRead = { if (it == 3) named = named.copy(inode = 12) } }
        assertFailsWith<IllegalStateException> { prepare(files) }
        assertEquals(1, files.events.count { it == "fchmod" })
        assertEquals("close", files.events.last())
    }

    @Test fun `chmod refusal noop and sync failure never return a usable parent`() {
        val denied = IOException("denied")
        val chmod = Files().apply { chmodFailure = denied }
        assertSame(denied, assertFails { prepare(chmod) })
        val noop = Files().apply { ignoreChmod = true }
        assertFailsWith<IllegalStateException> { prepare(noop) }
        val sync = Files().apply { syncFailure = denied }
        assertSame(denied, assertFails { prepare(sync) })
        for (files in listOf(chmod, noop, sync)) {
            assertEquals(1, files.events.count { it == "fchmod" })
            assertEquals("close", files.events.last())
        }
    }

    @Test fun `concurrent successful tightening of same inode is allowed`() {
        val files = Files().apply { onFdRead = { if (it == 1) { opened = opened.copy(mode = 0x41c0); named = opened } } }
        assertEquals(directory, prepare(files))
        assertFalse("fchmod" in files.events)
    }

    @Test fun `close failure is not hidden and never replaces the primary failure`() {
        val closeFailure = IOException("close")
        val private = Files().apply { named = named.copy(mode = 0x41c0); opened = named; this.closeFailure = closeFailure }
        assertSame(closeFailure, assertFails { prepare(private) })
        val original = IOException("chmod")
        val refused = Files().apply { chmodFailure = original; this.closeFailure = closeFailure }
        assertSame(original, assertFails { prepare(refused) })
        assertSame(closeFailure, original.suppressed.single())
    }

    private class Opener : KagemushaWalletAndroidStorageV1.DescriptorOpener {
        val descriptor = FileDescriptor()
        val events = mutableListOf<String>()
        var enabled = false
        var settingFailure: Throwable? = null
        var ignoreSetting = false
        override fun open(directory: File, atomicCloseOnExec: Boolean): FileDescriptor {
            events += "open:$atomicCloseOnExec"; enabled = atomicCloseOnExec; return descriptor
        }
        override fun enableCloseOnExec(descriptor: FileDescriptor) { events += "set"; settingFailure?.let { throw it }; if (!ignoreSetting) enabled = true }
        override fun closeOnExecEnabled(descriptor: FileDescriptor): Boolean { events += "get"; return enabled }
        override fun close(descriptor: FileDescriptor) { events += "close" }
    }

    @Test fun `API26 uses immediate public fcntl path and verifies before returning`() {
        val opener = Opener()
        assertSame(opener.descriptor, KagemushaWalletAndroidStorageV1.openDirectory(directory, 26, opener))
        assertEquals(listOf("open:false", "set", "get"), opener.events)
    }

    @Test fun `API27 and newer select atomic close on exec and verify it`() {
        for (api in listOf(27, 37)) {
            val opener = Opener()
            assertSame(opener.descriptor, KagemushaWalletAndroidStorageV1.openDirectory(directory, api, opener))
            assertEquals(listOf("open:true", "get"), opener.events)
        }
    }

    @Test fun `API26 setting failure or failed verification closes the descriptor`() {
        val denied = IOException("fcntl")
        val refused = Opener().apply { settingFailure = denied }
        assertSame(denied, assertFails { KagemushaWalletAndroidStorageV1.openDirectory(directory, 26, refused) })
        val noop = Opener().apply { ignoreSetting = true }
        assertFailsWith<IllegalStateException> { KagemushaWalletAndroidStorageV1.openDirectory(directory, 26, noop) }
        for (opener in listOf(refused, noop)) assertEquals("close", opener.events.last())
    }
}
