// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import android.system.Os
import android.system.OsConstants
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.security.MessageDigest
import java.util.UUID
import org.hyperledger.iroha.sdk.offline.KagemushaWalletArtifactTransportV1
import org.junit.Assert.*
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters

/** Run only in the explicitly disposable instrumentation package. No account, session,
 * enrollment, debit, network call or payment key generation is requested by these tests. */
@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class KagemushaWalletAndroidStorageDeviceV1Test {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private fun disposable() {
        val expectedUid = checkNotNull(InstrumentationRegistry.getArguments().getString("expectedUid")).toInt()
        check(expectedUid > 0 && Os.getuid() == expectedUid && context.applicationInfo.uid == expectedUid) {
            "Disposable probe UID changed"
        }
        check(context.packageName == "org.hyperledger.iroha.kagemusha.enrollmentprobe.usb20261015.unattended") {
            "This storage regression requires the retained disposable probe package"
        }
    }
    private fun same(first: android.system.StructStat, second: android.system.StructStat) {
        assertEquals(first.st_dev, second.st_dev); assertEquals(first.st_ino, second.st_ino)
        assertEquals(first.st_uid, second.st_uid); assertEquals(first.st_gid, second.st_gid)
    }

    @Test fun aFramework0771BecomesPrivateWithoutReplacingExistingData() {
        disposable()
        val supplied = context.noBackupFilesDir.absoluteFile
        val root = File(checkNotNull(supplied.parentFile).canonicalFile, supplied.name)
        val before = Os.lstat(root.path)
        assertEquals(505, before.st_mode and 4095) // Exact observed stock 0771, not a synthesized fixture.
        val ancestor = Os.lstat(checkNotNull(root.parentFile).path)
        val marker = File(root, "storage-normalization-${UUID.randomUUID()}")
        val bytes = byteArrayOf(2, 7, 9, 31)
        FileOutputStream(marker).use { it.write(bytes); it.fd.sync() }
        val original = Os.lstat(marker.path)
        try {
            assertEquals(root, KagemushaWalletAndroidStorageV1.privateNoBackupFilesDir(context))
            val after = Os.lstat(root.path)
            same(before, after)
            assertEquals(448, after.st_mode and 4095)
            assertArrayEquals(bytes, marker.readBytes()); same(original, Os.lstat(marker.path))
            assertEquals(original.st_nlink, (Files.getAttribute(marker.toPath(), "unix:nlink", NOFOLLOW_LINKS) as Number).toLong())
            same(ancestor, Os.lstat(checkNotNull(root.parentFile).path))
            assertEquals(ancestor.st_mode, Os.lstat(checkNotNull(root.parentFile).path).st_mode)
            assertEquals(root, KagemushaWalletAndroidStorageV1.privateNoBackupFilesDir(context))
            same(after, Os.lstat(root.path))
        } finally { check(marker.delete()) }
    }

    @Test fun bAcceptedBundledOriginalsReachRealNativeInstallationAndRegistration() {
        disposable()
        val parent = KagemushaWalletAndroidStorageV1.privateNoBackupFilesDir(context)
        val custody = KagemushaWalletAndroidStorageV1.preparedCustodyRoot(context)
        assertEquals(File(parent, "kagemusha-wallet-v1"), custody)
        val custodyStat = Os.lstat(custody.path)
        assertEquals(448, custodyStat.st_mode and 4095)
        assertEquals(Os.getuid(), custodyStat.st_uid); assertEquals(Os.getgid(), custodyStat.st_gid)
        val witness = File(parent, "kagemusha-wallet-root-v1.witness")
        val witnessStat = Os.lstat(witness.path)
        assertEquals(256, witnessStat.st_mode and 4095)
        assertEquals(Os.getuid(), witnessStat.st_uid); assertEquals(1L, witnessStat.st_nlink)
        val binding = java.nio.ByteBuffer.wrap(witness.readBytes())
        assertEquals(32, binding.remaining())
        val magic = ByteArray(8); binding.get(magic)
        assertArrayEquals(byteArrayOf(75, 71, 77, 82, 79, 79, 84, 49), magic)
        assertEquals(custodyStat.st_dev, binding.long); assertEquals(custodyStat.st_ino, binding.long)
        assertEquals(custodyStat.st_uid, binding.int); assertEquals(custodyStat.st_gid, binding.int)
        assertEquals(custody, KagemushaWalletAndroidStorageV1.preparedCustodyRoot(context))
        same(custodyStat, Os.lstat(custody.path)); same(witnessStat, Os.lstat(witness.path))
        val root = File(parent, "storage-native-originals-${UUID.randomUUID()}")
        Os.mkdir(root.path, 448)
        val originalsDirectory = File(root, "wallet-originals")
        Os.mkdir(originalsDirectory.path, 448)
        val assets = instrumentation.context.assets
        fun asset(path: String, maximum: Int): ByteArray = assets.open(path).use { source ->
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(65536)
            while (true) {
                val read = source.read(buffer)
                if (read < 0) break
                check(read > 0 && output.size() <= maximum - read)
                output.write(buffer, 0, read)
            }
            output.toByteArray().also { check(it.isNotEmpty()) }
        }
        fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        fun persist(name: String, bytes: ByteArray) {
            val file = File(root, name)
            check(!file.exists())
            FileOutputStream(file).use { it.write(bytes); it.fd.sync() }
            Os.chmod(file.path, 256)
        }
        fun sync(file: File) {
            val descriptor = Os.open(file.path, OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW, 0)
            try { Os.fsync(descriptor) } finally { Os.close(descriptor) }
        }
        val prefix = "config/wallet-runtime/artifacts/"
        val manifest = asset("config/app-runtime-manifest.json", 8 * 1024 * 1024)
        val runtime = asset("config/wallet-runtime/wallet-core-runtime.json", 128 * 1024)
        assertEquals("96ffc4b776f552fa73cc101508adad3f9b170bab63e15e2fdb96fdc464f72091", digest(manifest))
        assertEquals("9feb10c1a67168bf05343c5da73db58e14a15d33d8baf557bdeaba2a40e4a56b", digest(runtime))
        val pack = asset(prefix + "verifier-pack.norito", 10 * 1024 * 1024)
        val inventory = asset(prefix + "producer-inventory.norito", 10 * 1024 * 1024)
        val transport = asset(prefix + "transport.json", KagemushaWalletArtifactTransportV1.MAX_BYTES)
        val financial = asset(prefix + "financial-originals.json", 2048)
        persist("verifier-pack.norito", pack); persist("producer-inventory.norito", inventory)
        persist("transport.json", transport); persist("financial-originals.json", financial)
        val extents = KagemushaWalletArtifactTransportV1.decode(transport)
        assertEquals(1029, extents.size)
        check(extents.sumOf { it.storedBytes } <= 10L * 1024 * 1024)
        for (extent in extents) {
            val original = asset(prefix + "wallet-originals/" + extent.rawSha256, 10 * 1024 * 1024)
            assertEquals(extent.storedBytes, original.size.toLong())
            assertEquals(extent.storedSha256, digest(original))
            persist("wallet-originals/" + extent.rawSha256, original)
        }
        sync(originalsDirectory); sync(root); sync(parent)
        val originals = KagemushaWalletInstallationOriginalsV1(manifest,
            asset("config/app-runtime-manifest.sig.json", 2048), runtime, pack, inventory,
            asset("config/wallet-runtime/signed-genesis.norito", 64 * 1024 * 1024),
            root.path.toByteArray(Charsets.UTF_8), byteArrayOf())
        val platform = KagemushaWalletAndroidPlatformV1.create(context)
        KagemushaWalletInstalledRuntimeV1.install(platform, originals).use { attempt ->
            val installed = attempt.register()
            installed.use { assertFalse(it.cleanupReleased()) }
            assertTrue(installed.cleanupReleased())
        }
        // Keep the exact immutable public originals and Native probe custody for diagnosis/reuse.
        assertEquals(448, Os.lstat(parent.path).st_mode and 4095)
    }
}
