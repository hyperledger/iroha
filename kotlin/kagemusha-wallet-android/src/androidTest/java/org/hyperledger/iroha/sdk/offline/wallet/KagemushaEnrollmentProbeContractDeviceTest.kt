// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import android.system.Os
import android.system.OsConstants
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith

/** Test-mailbox contracts only. These tests never create a platform owner, key or wallet JNI handle. */
@RunWith(AndroidJUnit4::class)
class KagemushaEnrollmentProbeContractDeviceTest {
    private fun refused(body: () -> Unit) {
        var refused = false
        try { body() } catch (_: Exception) { refused = true }
        org.junit.Assert.assertTrue("expected closed refusal", refused)
    }
    @Test fun closedCommandsRejectMissingExtraAndUnknownInputs() {
        val install = EnrollmentProbeCommand(probeObject("""{"action":"install","inputs":{}}""".toByteArray()))
        assertEquals("install", install.action)
        assertEquals("abandon", EnrollmentProbeCommand(probeObject(
            """{"action":"abandon","inputs":{}}""".toByteArray())).action)
        refused { EnrollmentProbeCommand(probeObject(
            """{"action":"abandon","inputs":{"reason":{}}}""".toByteArray())) }
        refused { EnrollmentProbeCommand(probeObject("""{"action":"abandon-expired","inputs":{}}""".toByteArray())) }
        val expiryCommand = """{"action":"abandon-expired","inputs":{"proof":{"path":"inbox/proof.norito","size":"1","sha256":"${"a".repeat(64)}"}}}"""
        assertEquals(setOf("proof"), EnrollmentProbeCommand(probeObject(expiryCommand.toByteArray())).pins.keys)
        refused { EnrollmentProbeCommand(probeObject(expiryCommand.replace("proof", "expiry-verdict").toByteArray())) }
        refused { EnrollmentProbeCommand(probeObject("""{"action":"open","inputs":{}}""".toByteArray())) }
        refused { EnrollmentProbeCommand(probeObject("""{"action":"delete","inputs":{}}""".toByteArray())) }
        refused { EnrollmentProbeCommand(probeObject("""{"action":"stop","inputs":{},"extra":"x"}""".toByteArray())) }
        refused { probeObject("""{"action":"stop","action":"install","inputs":{}}""".toByteArray()) }
    }
    @Test fun descriptorsRejectEscapesAndNoncanonicalIdentities() {
        for (path in listOf("../secret", "/absolute", "catalog//file", "catalog/./file", "catalog/é")) {
            refused { EnrollmentProbeFiles.parts(path) }
        }
        refused { EnrollmentProbeConfiguration.uuid("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA") }
        refused { EnrollmentProbePin(probeObject(probeJson("path" to "catalog/a", "size" to "01", "sha256" to "a".repeat(64)))) }
        assertFalse(EnrollmentProbeFiles.isDigest("A".repeat(64)))
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            EnrollmentProbeFiles.digest(ByteArray(0)))
    }
    @Test fun canonicalSystemDirectoryDoesNotAdmitMailboxAliases() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val parent = context.noBackupFilesDir.canonicalFile
        val root = File(parent, "enrollment-canonical-root-${UUID.randomUUID()}")
        Os.mkdir(root.path, 448)
        assertEquals(root, EnrollmentProbeFiles(root).root)
        refused { EnrollmentProbeFiles(File(root, "../${root.name}")) }
        val alias = File(parent, "enrollment-root-alias-${UUID.randomUUID()}")
        Os.symlink(root.path, alias.path)
        refused { EnrollmentProbeFiles(alias) }
        // A stock Android context may expose an alias; only its trusted parent is resolved.
        println("KAGEMUSHA filesystem parent already canonical: ${context.noBackupFilesDir == parent}")
    }

    @Test fun publicationIsPrivateBoundedAndNeverRepairsExistingBytes() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(context.noBackupFilesDir.canonicalFile, "enrollment-mailbox-contract-${UUID.randomUUID()}")
        Os.mkdir(root.path, 448)
        // Retain this isolated test fixture; no cleanup walks any wallet/native custody.
        val files = EnrollmentProbeFiles(root)
        files.mkdir("private/one", exclusive = true)
        val bytes = byteArrayOf(1, 2, 3)
        files.publish("private/one/value", bytes)
        files.publish("private/one/value", bytes)
        refused { files.publish("private/one/value", byteArrayOf(4)) }
        refused { files.mkdir("private/one", exclusive = true) }
        assertArrayEquals(bytes, files.read("private/one/value", 3))
        val pin = EnrollmentProbePin(probeObject(probeJson("path" to "private/one/value",
            "size" to "3", "sha256" to EnrollmentProbeFiles.digest(bytes))))
        assertArrayEquals(bytes, files.pinned(pin, 3)); files.verify(pin)
        assertEquals(setOf("private/one/value"), files.inventory("private"))
        assertFalse(files.exists("private/one/absent"))
        val wrong = EnrollmentProbePin(probeObject(probeJson("path" to "private/one/value",
            "size" to "3", "sha256" to "a".repeat(64))))
        refused { files.verify(wrong) }
        refused { files.read("private/one/value", 2) }
        Os.symlink(files.file("private/one/value").path, files.file("private/one/link").path)
        refused { files.read("private/one/link", 3) }
        // Owner-only bits alone are insufficient: reject special permission bits too.
        Os.chmod(files.file("private/one/value").path, 896) // 01600
        refused { files.read("private/one/value", 3) }
        Os.chmod(files.file("private/one/value").path, 384) // 0600
        Os.chmod(files.file("private/one").path, 960) // 01700
        refused { files.read("private/one/value", 3) }
        Os.chmod(files.file("private/one").path, 448) // 0700
        Os.chmod(files.file("private/one/value").path, 420)
        refused { files.read("private/one/value", 3) }
        files.lock().use { refused { files.lock().close() } }
    }

    @Test fun interruptedStagingAndPublishedRenameResumeTheExactOriginal() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(context.noBackupFilesDir.canonicalFile, "enrollment-publication-contract-${UUID.randomUUID()}")
        Os.mkdir(root.path, 448)
        val files = EnrollmentProbeFiles(root)
        files.mkdir("private")
        val target = "private/identity.json"
        val stage = "private/.kagemusha-publication-${EnrollmentProbeFiles.digest(target.toByteArray(Charsets.UTF_8))}.stage"
        val fd = Os.open(files.file(stage).path, OsConstants.O_CREAT or OsConstants.O_EXCL or
            OsConstants.O_WRONLY or OsConstants.O_NOFOLLOW, 384)
        try { Os.write(fd, byteArrayOf(1), 0, 1); Os.fsync(fd) } finally { Os.close(fd) }
        val original = byteArrayOf(1, 2, 3)
        files.publish(target, original)
        assertFalse(files.exists(stage))
        assertArrayEquals(original, files.read(target, 3))
        // Atomic rename consumes the stage; a lost acknowledgement retries the exact target.
        assertEquals(1L, Os.lstat(files.file(target).path).st_nlink)
        refused { files.publish(target, byteArrayOf(9)) }
        EnrollmentProbeFiles(root).publish(target, original)
        assertFalse(files.exists(stage))
        assertEquals(1L, Os.lstat(files.file(target).path).st_nlink)
        assertArrayEquals(original, files.read(target, 3))
        refused { files.publish(".publication.lock", byteArrayOf()) }
        refused { files.publish(stage, byteArrayOf()) }
    }

    @Test fun mergedConfirmationActivityIsPrivateAndDeclaresBiometricPermission() {
        val context = InstrumentationRegistry.getInstrumentation().context
        val name = android.content.ComponentName(context, KagemushaProbeConfirmationActivity::class.java)
        val activity = context.packageManager.getActivityInfo(name, 0)
        assertFalse(activity.exported)
        assertEquals(context.applicationInfo.uid, activity.applicationInfo.uid)
        assertEquals(context.packageName, activity.packageName)
        assertEquals(android.content.pm.PackageManager.PERMISSION_GRANTED,
            context.packageManager.checkPermission("android.permission.USE_BIOMETRIC", context.packageName))
    }

    @Test fun exclusiveAttemptMarkerCannotAuthorizeTwice() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(context.noBackupFilesDir.canonicalFile, "enrollment-attempt-contract-${UUID.randomUUID()}")
        Os.mkdir(root.path, 448)
        val files = EnrollmentProbeFiles(root)
        files.mkdir("private")
        val target = "private/attempt"
        val original = byteArrayOf(7, 8, 9)
        files.publish(target, original, exclusive = true)
        refused { files.publish(target, original, exclusive = true) }
        assertArrayEquals(original, files.read(target, original.size))
        // A fresh helper cannot authorize again after the exclusive marker was named.
        val stage = "private/.kagemusha-publication-${EnrollmentProbeFiles.digest(target.toByteArray(Charsets.UTF_8))}.stage"
        refused { EnrollmentProbeFiles(root).publish(target, original, exclusive = true) }
        assertFalse(files.exists(stage))
        assertEquals(1L, Os.lstat(files.file(target).path).st_nlink)
        // Ordinary audit originals keep their exact-byte repair-free retry contract.
        files.publish(target, original)
        assertFalse(files.exists(stage))
        assertEquals(1L, Os.lstat(files.file(target).path).st_nlink)
    }

    @Test fun concurrentHelperInstancesNeverOverwriteTheWinningOriginal() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(context.noBackupFilesDir.canonicalFile, "enrollment-concurrency-contract-${UUID.randomUUID()}")
        Os.mkdir(root.path, 448)
        val files = EnrollmentProbeFiles(root)
        files.mkdir("private")
        val executor = Executors.newFixedThreadPool(2)
        try {
            for (sameBytes in listOf(true, false)) {
                val gate = CountDownLatch(1)
                val target = "private/concurrent-$sameBytes"
                val results = (0..1).map { index ->
                    executor.submit<Boolean> {
                        gate.await()
                        try {
                            EnrollmentProbeFiles(root).publish(target, byteArrayOf(if (sameBytes) 1 else index.toByte()))
                            true
                        } catch (failure: EnrollmentProbeFailure) {
                            assertEquals("collision", failure.code)
                            false
                        }
                    }
                }
                gate.countDown()
                assertEquals(if (sameBytes) 2 else 1, results.count { it.get(10, TimeUnit.SECONDS) })
                assertEquals(1, files.read(target, 1).size)
                assertEquals(1L, Os.lstat(files.file(target).path).st_nlink)
            }
        } finally { executor.shutdownNow() }
    }
    @Test fun kernelNoReplaceRenameKeepsExactlyOneConcurrentWinner() {
        val parent = InstrumentationRegistry.getInstrumentation().targetContext.noBackupFilesDir.canonicalFile
        val root = File(parent, "enrollment-kernel-rename-${UUID.randomUUID()}")
        Os.mkdir(root.path, 448)
        val executor = Executors.newFixedThreadPool(2)
        try {
            repeat(16) { round ->
                val gate = CountDownLatch(1)
                val stages = (0..1).map { index ->
                    val stage = ".kagemusha-publication-$round-$index.stage"
                    val fd = Os.open(File(root, stage).path, OsConstants.O_WRONLY or OsConstants.O_CREAT or
                        OsConstants.O_EXCL or OsConstants.O_NOFOLLOW, 384)
                    try { Os.write(fd, byteArrayOf(index.toByte()), 0, 1); Os.fsync(fd) } finally { Os.close(fd) }
                    stage
                }
                // Bypass the JVM and advisory publication locks: the syscall itself must fence.
                val attempts = stages.map { stage -> executor.submit<Int> {
                    gate.await()
                    EnrollmentProbeRename.publish(root.path, stage, "winner-$round")
                } }
                gate.countDown()
                val results = attempts.map { it.get(10, TimeUnit.SECONDS) }
                assertEquals(listOf(0, OsConstants.EEXIST), results.sorted())
                val winner = results.indexOf(0)
                val loser = 1 - winner
                assertFalse(File(root, stages[winner]).exists())
                assertArrayEquals(byteArrayOf(loser.toByte()), File(root, stages[loser]).readBytes())
                assertArrayEquals(byteArrayOf(winner.toByte()), File(root, "winner-$round").readBytes())
                assertEquals(1L, Os.lstat(File(root, "winner-$round").path).st_nlink)
                assertEquals(384, Os.lstat(File(root, "winner-$round").path).st_mode and 4095)
            }
        } finally { executor.shutdownNow() }
    }

    @Test fun kernelRenameRejectsSymlinksModesAndEscapingLeaves() {
        val parent = InstrumentationRegistry.getInstrumentation().targetContext.noBackupFilesDir.canonicalFile
        val root = File(parent, "enrollment-kernel-refusal-${UUID.randomUUID()}")
        Os.mkdir(root.path, 448)
        val stage = ".kagemusha-publication-selected.stage"
        val fd = Os.open(File(root, stage).path, OsConstants.O_WRONLY or OsConstants.O_CREAT or
            OsConstants.O_EXCL or OsConstants.O_NOFOLLOW, 384)
        try { Os.write(fd, byteArrayOf(8), 0, 1); Os.fsync(fd) } finally { Os.close(fd) }
        for (bad in listOf("../outside", "a/b", ".", "..", "", "é", stage)) {
            assertEquals(OsConstants.EINVAL, EnrollmentProbeRename.publish(root.path, stage, bad))
        }
        Os.symlink(File(root, stage).path, File(root, "target-link").path)
        assertEquals(OsConstants.EEXIST, EnrollmentProbeRename.publish(root.path, stage, "target-link"))
        org.junit.Assert.assertTrue(OsConstants.S_ISLNK(Os.lstat(File(root, "target-link").path).st_mode))
        Os.symlink(File(root, stage).path, File(root, ".kagemusha-publication-link.stage").path)
        assertEquals(OsConstants.ELOOP, EnrollmentProbeRename.publish(root.path,
            ".kagemusha-publication-link.stage", "target"))
        Os.chmod(File(root, stage).path, 420)
        assertEquals(OsConstants.EPERM, EnrollmentProbeRename.publish(root.path, stage, "target"))
        Os.chmod(File(root, stage).path, 384)
        Os.chmod(root.path, 493)
        assertEquals(OsConstants.EPERM, EnrollmentProbeRename.publish(root.path, stage, "target"))
        Os.chmod(root.path, 448)
        val alias = File(parent, "enrollment-kernel-alias-${UUID.randomUUID()}")
        Os.symlink(root.path, alias.path)
        org.junit.Assert.assertTrue(EnrollmentProbeRename.publish(alias.path, stage, "target") != 0)
        assertFalse(File(root, "target").exists())
        assertArrayEquals(byteArrayOf(8), File(root, stage).readBytes())
    }

    @Test fun incompleteIntakeIsInvisibleUntilExclusiveDirectoryCommit() {
        val parent = InstrumentationRegistry.getInstrumentation().targetContext.noBackupFilesDir.canonicalFile
        val root = File(parent, "enrollment-intake-${UUID.randomUUID()}")
        Os.mkdir(root.path, 448)
        val files = EnrollmentProbeFiles(root); files.mkdir("inbox")
        files.publish("inbox/partial.json", byteArrayOf(1))
        files.publish("inbox/partial.sha256", byteArrayOf(2))
        org.junit.Assert.assertNull(files.committedCommand("inbox/partial", 1024))
        val command = "{\"action\":\"stop\",\"inputs\":{}}".toByteArray()
        files.publish("inbox/complete.json", command)
        files.publish("inbox/complete.sha256", EnrollmentProbeFiles.digest(command).toByteArray(Charsets.US_ASCII))
        org.junit.Assert.assertNull(files.committedCommand("inbox/complete", 1024))
        files.mkdir("inbox/complete.ready", exclusive = true)
        assertArrayEquals(command, files.committedCommand("inbox/complete", 1024))
        refused { files.mkdir("inbox/complete.ready", exclusive = true) }
        assertArrayEquals(command, files.committedCommand("inbox/complete", 1024))
        // The former regular-file marker is not another accepted protocol.
        files.publish("inbox/old.ready", ByteArray(64) { 'a'.code.toByte() })
        refused { files.committedCommand("inbox/old", 1024) }
    }

    @Test fun committedIntakeRejectsMalformedAndReplacedMarkers() {
        val parent = InstrumentationRegistry.getInstrumentation().targetContext.noBackupFilesDir.canonicalFile
        val root = File(parent, "enrollment-intake-refusal-${UUID.randomUUID()}")
        Os.mkdir(root.path, 448)
        val files = EnrollmentProbeFiles(root); files.mkdir("inbox")
        val command = byteArrayOf(7, 8, 9)
        fun stage(base: String, digest: ByteArray = EnrollmentProbeFiles.digest(command).toByteArray(Charsets.US_ASCII)) {
            files.publish("$base.json", command); files.publish("$base.sha256", digest)
            files.mkdir("$base.ready", exclusive = true)
        }
        stage("inbox/nonempty")
        files.publish("inbox/nonempty.ready/extra", byteArrayOf(1))
        refused { files.committedCommand("inbox/nonempty", 1024) }
        stage("inbox/mode")
        Os.chmod(files.file("inbox/mode.ready").path, 493)
        refused { files.committedCommand("inbox/mode", 1024) }
        Os.symlink(files.file("inbox/mode.ready").path, files.file("inbox/alias.ready").path)
        refused { files.committedCommand("inbox/alias", 1024) }
        stage("inbox/mismatch", ByteArray(64) { 'a'.code.toByte() })
        refused { files.committedCommand("inbox/mismatch", 1024) }
        stage("inbox/short", ByteArray(63) { 'a'.code.toByte() })
        refused { files.committedCommand("inbox/short", 1024) }
        stage("inbox/replaced")
        assertArrayEquals(command, files.committedCommand("inbox/replaced", 1024))
        refused { files.committedCommand("inbox/replaced", 1024) {
            Os.rename(files.file("inbox/replaced.ready").path, files.file("inbox/retained-old-marker").path)
            Os.mkdir(files.file("inbox/replaced.ready").path, 448)
        } }
    }

    @Test fun callbackIntakeKeepsExactNativeChallengeAndSignaturePin() {
        val challenge = ByteArray(32) { 7 }
        val expected = EnrollmentProbeFiles.digest(challenge)
        val record = """{"challengeSHA256":"$expected","signature":{"path":"inbox/callback/signature.bin","size":"64","sha256":"${"a".repeat(64)}"}}""".toByteArray()
        assertEquals(64L, probeOpenSignature(record, challenge).size)
        refused { probeOpenSignature(record, ByteArray(32) { 8 }) }
        refused { probeOpenSignature(record, ByteArray(32)) }
        refused { probeOpenSignature(record.toString(Charsets.UTF_8).replace("\"64\"", "\"63\"").toByteArray(), challenge) }
        refused { probeOpenSignature(record.toString(Charsets.UTF_8).replace("{\"challenge", "{\"extra\":\"x\",\"challenge").toByteArray(), challenge) }
    }

}
