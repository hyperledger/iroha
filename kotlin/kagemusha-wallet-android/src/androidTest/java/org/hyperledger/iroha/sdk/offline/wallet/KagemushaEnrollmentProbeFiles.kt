// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import android.os.Process
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructStat
import java.io.Closeable
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import org.hyperledger.iroha.sdk.json.Json
import org.hyperledger.iroha.sdk.json.JsonObject
import org.hyperledger.iroha.sdk.json.JsonString

internal fun probeObject(bytes: ByteArray): JsonObject = Json.parse(bytes) as? JsonObject
    ?: throw EnrollmentProbeFailure("input")
internal fun JsonObject.text(name: String): String = (this[name] as? JsonString)?.value
    ?: throw EnrollmentProbeFailure("input")
internal fun probeJson(vararg entries: Pair<String, String>): ByteArray =
    Json.obj(entries.associate { it.first to Json.of(it.second) }).toJsonBytes()

/** The exact Native open challenge remains the binding; the controller supplies only its signature. */
internal fun probeOpenSignature(bytes: ByteArray, challenge: ByteArray): EnrollmentProbePin {
    probeRequire(challenge.size == 32 && challenge.any { it != 0.toByte() })
    val row = probeObject(bytes)
    probeRequire(row.keys == setOf("challengeSHA256", "signature") &&
        row.text("challengeSHA256") == EnrollmentProbeFiles.digest(challenge))
    return EnrollmentProbePin(row["signature"] as? JsonObject ?: throw EnrollmentProbeFailure("input"))
        .also { probeRequire(it.size == 64L) }
}

/** Immutable private staging descriptor; never a protocol decoder or authenticated authority. */
internal class EnrollmentProbePin(row: JsonObject) {
    val path = row.text("path")
    val size = row.text("size").toLongOrNull() ?: throw EnrollmentProbeFailure("input")
    val sha256 = row.text("sha256")
    init {
        probeRequire(row.keys == setOf("path", "size", "sha256"))
        EnrollmentProbeFiles.parts(path)
        probeRequire(size in 0..4_294_967_296L && EnrollmentProbeFiles.isDigest(sha256))
        probeRequire(row.text("size") == size.toString())
    }
}

/**
 * Owner-only test mailbox. Ancestors must remain immutable under the trusted staging owner;
 * path validation plus O_NOFOLLOW is not a sandbox against concurrent same-UID ancestor swaps.
 * Interrupted helper staging is recoverable; published originals are never replaced. Neither
 * this helper nor the driver repairs Native custody.
 */
internal class EnrollmentProbeFiles(val root: File) {
    companion object {
        private val publicationGate = Any()
        private const val PUBLICATION_LOCK = ".publication.lock"
        private const val STAGE_PREFIX = ".kagemusha-publication-"
        fun parts(path: String): List<String> {
            val parts = path.split('/')
            probeRequire(parts.isNotEmpty() && parts.all {
                it.isNotEmpty() && it != "." && it != ".." &&
                    it.length <= 128 && it.all { c -> c in 'a'..'z' || c in 'A'..'Z' ||
                        c in '0'..'9' || c == '-' || c == '_' || c == '.' }
            })
            return parts
        }
        fun isDigest(text: String) = text.length == 64 && text.all { it in '0'..'9' || it in 'a'..'f' }
        fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
        fun digest(bytes: ByteArray) = hex(MessageDigest.getInstance("SHA-256").digest(bytes))
        fun directory(file: File) {
            val row = Os.lstat(file.path)
            probeRequire(OsConstants.S_ISDIR(row.st_mode) && row.st_uid == Process.myUid() &&
                row.st_mode and 4095 == 448, "custody")
        }
    }
    init { probeRequire(root.isAbsolute && root.canonicalFile == root, "custody"); directory(root) }
    fun file(path: String): File {
        val parts = parts(path)
        var current = root
        directory(current)
        for (part in parts.dropLast(1)) { current = File(current, part); directory(current) }
        return File(current, parts.last())
    }
    fun exists(path: String): Boolean = try { Os.lstat(file(path).path); true } catch (e: ErrnoException) {
        if (e.errno == OsConstants.ENOENT) false else throw e
    }
    fun mkdir(path: String, exclusive: Boolean = false) {
        val parts = parts(path)
        var current = root
        for ((index, part) in parts.withIndex()) {
            directory(current)
            current = File(current, part)
            try { Os.mkdir(current.path, 448); sync(current.parentFile!!) } catch (e: ErrnoException) {
                if (e.errno != OsConstants.EEXIST || (exclusive && index == parts.lastIndex)) throw e
            }
            directory(current)
        }
    }
    private fun regular(row: StructStat, links: Long = 1) {
        probeRequire(OsConstants.S_ISREG(row.st_mode) && row.st_uid == Process.myUid() &&
            row.st_nlink == links && row.st_mode and 4095 == 384, "custody")
    }
    private fun same(a: StructStat, b: StructStat) = a.st_dev == b.st_dev && a.st_ino == b.st_ino &&
        a.st_size == b.st_size && a.st_mtime == b.st_mtime && a.st_ctime == b.st_ctime
    private fun consume(path: String, maximum: Long, links: Long = 1, body: (FileInputStream, Long) -> Unit) {
        val selected = file(path)
        val before = Os.lstat(selected.path); regular(before, links)
        probeRequire(before.st_size in 0..maximum, "input")
        val fd = Os.open(selected.path, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0)
        FileInputStream(fd).use { input ->
            val opened = Os.fstat(fd); regular(opened, links); probeRequire(same(before, opened), "custody")
            body(input, opened.st_size)
            probeRequire(input.read() == -1, "custody")
            val after = Os.fstat(fd); regular(after, links)
            val named = Os.lstat(selected.path); regular(named, links)
            probeRequire(same(opened, after) && same(after, named), "custody")
        }
    }
    fun read(path: String, maximum: Int): ByteArray {
        var bytes = ByteArray(0)
        consume(path, maximum.toLong()) { input, size ->
            bytes = ByteArray(size.toInt()); var offset = 0
            while (offset < bytes.size) {
                val n = input.read(bytes, offset, bytes.size - offset)
                probeRequire(n > 0, "custody"); offset += n
            }
        }
        return bytes
    }
    /**
     * Host intake has one atomic empty-directory commit marker and a separate exact digest.
     * Until the directory exists, partial command/input DATA is invisible to dispatch. The
     * selected marker inode is retained through validation and synchronization; it is never
     * created or repaired here. The callback is a deterministic test-only custody fault seam.
     */
    fun committedCommand(base: String, maximum: Int, afterSelection: () -> Unit = {}): ByteArray? {
        val marker = file("$base.ready")
        val before = try { Os.lstat(marker.path) } catch (failure: ErrnoException) {
            if (failure.errno == OsConstants.ENOENT) return null else throw failure
        }
        directory(marker)
        val fd = Os.open(marker.path, OsConstants.O_RDONLY or
            OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC, 0)
        try {
            val selected = Os.fstat(fd)
            probeRequire(OsConstants.S_ISDIR(selected.st_mode) && selected.st_uid == Process.myUid() &&
                selected.st_mode and 4095 == 448 && same(before, selected), "custody")
            probeRequire(marker.list()?.isEmpty() == true, "custody")
            afterSelection()
            val bytes = read("$base.json", maximum)
            probeRequire(read("$base.sha256", 64).contentEquals(
                digest(bytes).toByteArray(Charsets.US_ASCII)), "collision")
            publicationIo.syncFile("$base.json", 1)
            publicationIo.syncFile("$base.sha256", 1)
            Os.fsync(fd)
            sync(marker.parentFile!!)
            directory(marker)
            val retained = Os.fstat(fd)
            probeRequire(same(selected, retained) && same(retained, Os.lstat(marker.path)) &&
                marker.list()?.isEmpty() == true, "custody")
            return bytes
        } finally { Os.close(fd) }
    }
    fun pinned(pin: EnrollmentProbePin, maximum: Int): ByteArray {
        probeRequire(pin.size <= maximum)
        return read(pin.path, maximum).also {
            probeRequire(it.size.toLong() == pin.size && digest(it) == pin.sha256, "collision")
        }
    }
    fun verify(pin: EnrollmentProbePin) {
        val digest = MessageDigest.getInstance("SHA-256")
        consume(pin.path, pin.size) { input, size ->
            probeRequire(size == pin.size, "collision")
            val chunk = ByteArray(65_536); var left = size
            while (left > 0) {
                val n = input.read(chunk, 0, minOf(left, chunk.size.toLong()).toInt())
                probeRequire(n > 0, "custody"); digest.update(chunk, 0, n); left -= n
            }
        }
        probeRequire(hex(digest.digest()) == pin.sha256, "collision")
    }
    fun inventory(path: String): Set<String> {
        val result = mutableSetOf<String>()
        fun walk(path: String) {
            val directory = file(path); Companion.directory(directory)
            for (child in directory.listFiles() ?: throw EnrollmentProbeFailure("custody")) {
                val name = path + "/" + child.name; parts(name)
                val row = Os.lstat(child.path)
                if (OsConstants.S_ISDIR(row.st_mode)) walk(name) else { regular(row); result.add(name) }
            }
        }
        walk(path); return result
    }
    fun publish(path: String, bytes: ByteArray, exclusive: Boolean = false) {
        val components = parts(path)
        probeRequire(path != PUBLICATION_LOCK && components.none { it.startsWith(STAGE_PREFIX) }, "input")
        val parent = components.dropLast(1).joinToString("/").let { if (it.isEmpty()) "" else "$it/" }
        val stage = parent + STAGE_PREFIX + digest(path.toByteArray(Charsets.UTF_8)) + ".stage"
        // The JVM gate serializes helper instances/threads; the stable private file lock fences
        // other processes. A busy owner is a retryable refusal, never permission to remove staging.
        synchronized(publicationGate) {
            publicationLock().use {
                publishEnrollmentProbeOriginal(publicationIo, path, stage, bytes.copyOf(), exclusive)
            }
        }
    }
    private fun publicationLock(): Closeable {
        val selected = file(PUBLICATION_LOCK)
        val fd = Os.open(selected.path, OsConstants.O_RDWR or OsConstants.O_CREAT or
            OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 384)
        val stream = FileOutputStream(fd)
        try {
            val opened = Os.fstat(fd); regular(opened)
            probeRequire(opened.st_size == 0L && same(opened, Os.lstat(selected.path)), "custody")
            val lock = stream.channel.tryLock() ?: throw EnrollmentProbeFailure("publication-busy")
            try {
                val named = Os.lstat(selected.path); regular(named)
                probeRequire(same(opened, named), "custody")
            } catch (failure: Throwable) { lock.release(); throw failure }
            return Closeable { try { lock.release() } finally { stream.close() } }
        } catch (failure: Throwable) { stream.close(); throw failure }
    }
    private val publicationIo = object : EnrollmentProbePublicationIo {
        override fun exists(path: String) = this@EnrollmentProbeFiles.exists(path)
        override fun requireExact(path: String, bytes: ByteArray, links: Long) {
            consume(path, bytes.size.toLong(), links) { input, size ->
                probeRequire(size == bytes.size.toLong(), "collision")
                val chunk = ByteArray(65_536); var offset = 0
                while (offset < bytes.size) {
                    val n = input.read(chunk, 0, minOf(chunk.size, bytes.size - offset))
                    probeRequire(n > 0, "custody")
                    for (index in 0 until n) probeRequire(chunk[index] == bytes[offset + index], "collision")
                    offset += n
                }
            }
        }
        override fun createStage(path: String, bytes: ByteArray) {
            val fd = Os.open(file(path).path, OsConstants.O_WRONLY or OsConstants.O_CREAT or
                OsConstants.O_EXCL or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC, 384)
            try {
                regular(Os.fstat(fd)); var offset = 0
                while (offset < bytes.size) {
                    val n = Os.write(fd, bytes, offset, bytes.size - offset)
                    probeRequire(n > 0, "custody"); offset += n
                }
            } finally { Os.close(fd) }
        }
        override fun syncFile(path: String, links: Long) {
            val selected = file(path)
            val fd = Os.open(selected.path, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0)
            try {
                val before = Os.fstat(fd); regular(before, links)
                val named = Os.lstat(selected.path); regular(named, links)
                probeRequire(same(before, named), "custody")
                Os.fsync(fd)
                val after = Os.fstat(fd); regular(after, links)
                val retained = Os.lstat(selected.path); regular(retained, links)
                probeRequire(same(before, after) && same(after, retained), "custody")
            } finally { Os.close(fd) }
        }
        override fun removeStage(path: String, links: Long) {
            probeRequire(parts(path).last().startsWith(STAGE_PREFIX), "custody")
            val selected = file(path); regular(Os.lstat(selected.path), links)
            Os.remove(selected.path)
        }
        override fun renameStage(stage: String, target: String): Boolean {
            val staged = file(stage)
            val selected = file(target)
            probeRequire(staged.parentFile == selected.parentFile, "custody")
            regular(Os.lstat(staged.path))
            val result = EnrollmentProbeRename.publish(staged.parentFile!!.path, staged.name, selected.name)
            return when (result) {
                0 -> true
                OsConstants.EEXIST -> false
                else -> throw ErrnoException("test-mailbox-rename-noreplace", result)
            }
        }
        override fun syncParent(path: String) = sync(file(path).parentFile!!)
    }
    private fun sync(directory: File) {
        val fd = Os.open(directory.path, OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC, 0)
        try {
            val row = Os.fstat(fd)
            probeRequire(OsConstants.S_ISDIR(row.st_mode) && row.st_uid == Process.myUid() &&
                row.st_mode and 4095 == 448, "custody")
            Os.fsync(fd)
        } finally { Os.close(fd) }
    }
    fun lock(): Closeable {
        publish("driver.lock", ByteArray(0))
        val selected = file("driver.lock")
        val fd = Os.open(selected.path, OsConstants.O_RDWR or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0)
        val file = FileOutputStream(fd)
        try { regular(Os.fstat(fd)) } catch (e: Throwable) { file.close(); throw e }
        val lock = try { file.channel.tryLock() } catch (e: Throwable) { file.close(); throw e }
        if (lock == null) { file.close(); throw EnrollmentProbeFailure("custody") }
        return Closeable { try { lock.release() } finally { file.close() } }
    }
}
