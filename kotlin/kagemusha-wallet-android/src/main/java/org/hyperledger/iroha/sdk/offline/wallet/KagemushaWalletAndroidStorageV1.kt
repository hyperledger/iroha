// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline.wallet

import android.content.Context
import android.os.Build
import android.system.Os
import android.system.ErrnoException
import android.system.OsConstants
import java.io.File
import java.io.FileDescriptor
import java.nio.ByteBuffer

/** Prepares the application's existing credential-encrypted no-backup directory for wallet custody.
 * Android creates this parent with mode 0771. The wallet requires app-owned ancestry to be private:
 * this adapter removes group/other access from that exact framework directory through an open,
 * authenticated descriptor. Parent normalization changes no child, key or record. The internal
 * first initializer separately creates the fixed custody leaf and its durable identity witness. */
object KagemushaWalletAndroidStorageV1 {
    /** Returns the same Context-owned directory with mode 0700, or throws without admitting it.
     * Call at storage opening, not application construction. Errors must remain storage failures;
     * callers must not substitute another directory, replace data or generate keys in response. */
    @JvmStatic
    fun privateNoBackupFilesDir(context: Context): File {
        val application = context.applicationContext ?: context
        check(!application.isDeviceProtectedStorage) { "Wallet storage requires a credential-encrypted context" }
        val supplied = application.noBackupFilesDir.absoluteFile
        // Resolve only the trusted Android system parent alias; never canonicalize the final leaf.
        val selected = File(checkNotNull(supplied.parentFile).canonicalFile, supplied.name)
        return prepare(selected, AndroidOperations)
    }

    /** The fixed native leaf and its immutable sibling witness are one first-init boundary.
     * The witness is durably published before mkdir. Missing/partial/mismatched witnessed
     * custody is refused, never recreated. Losing both objects is outside this local fence. */
    internal fun preparedCustodyRoot(context: Context): File =
        prepareCustodyRoot(privateNoBackupFilesDir(context), AndroidOperations)

    internal interface CustodyOperations : Operations {
        /** Only actual ENOENT is absence; other errors propagate. */
        fun lstatOrAbsent(path: File): Stat?
        fun mkdirPrivate(directory: File)
        /** Create uses exclusive0600; existing witnesses are opened read-only, without links. */
        fun openWitness(path: File, create: Boolean): FileDescriptor
        fun readWitness(descriptor: FileDescriptor): ByteArray
        fun writeWitness(descriptor: FileDescriptor, bytes: ByteArray)
    }

    internal fun prepareCustodyRoot(parent: File, operations: CustodyOperations): File {
        check(parent.isAbsolute && parent.toPath().normalize().toFile() == parent)
        val parentNamed = operations.lstat(parent)
        requirePrivateDirectory(parentNamed, operations)
        val child = File(parent, KAGEMUSHA_WALLET_ANDROID_CUSTODY_DIR_NAME_V1)
        val witness = File(parent, "kagemusha-wallet-root-v1.witness")
        return withDescriptor(operations.openDirectory(parent), operations) { parentDescriptor ->
            revalidatePrivateDirectory(parent, parentDescriptor, parentNamed, operations)
            val existingChild = operations.lstatOrAbsent(child)
            if (existingChild != null) requirePrivateDirectory(existingChild, operations)
            val existingWitness = operations.lstatOrAbsent(witness)
            if (existingWitness != null) {
                requireWitness(existingWitness, operations)
                check(existingChild != null) { "Previously initialized wallet custody is missing" }
            }
            revalidatePrivateDirectory(parent, parentDescriptor, parentNamed, operations)
            withDescriptor(operations.openWitness(witness, existingWitness == null), operations) { witnessDescriptor ->
                val witnessIdentity = operations.fstat(witnessDescriptor)
                requireWitness(witnessIdentity, operations, existingWitness == null)
                if (existingWitness != null) requireSame(existingWitness, witnessIdentity)
                revalidateWitness(witness, witnessDescriptor, witnessIdentity, operations, existingWitness == null)
                if (existingWitness == null) {
                    // A crash from this point leaves a visible incomplete witness and refuses
                    // subsequent admission. Never delete it or infer permission to recreate.
                    check(operations.readWitness(witnessDescriptor).isEmpty())
                    operations.fsync(witnessDescriptor)
                    operations.fsync(parentDescriptor)
                }
                revalidatePrivateDirectory(parent, parentDescriptor, parentNamed, operations)
                if (existingChild == null) operations.mkdirPrivate(child)
                revalidatePrivateDirectory(parent, parentDescriptor, parentNamed, operations)
                val childNamed = operations.lstat(child)
                requirePrivateDirectory(childNamed, operations)
                if (existingChild != null) requireSame(existingChild, childNamed)
                withDescriptor(operations.openDirectory(child), operations) { childDescriptor ->
                    revalidatePrivateDirectory(child, childDescriptor, childNamed, operations)
                    val binding = witnessBinding(childNamed)
                    if (existingWitness == null) {
                        operations.fsync(childDescriptor)
                        operations.fsync(parentDescriptor)
                        revalidatePrivateDirectory(parent, parentDescriptor, parentNamed, operations)
                        revalidatePrivateDirectory(child, childDescriptor, childNamed, operations)
                        revalidateWitness(witness, witnessDescriptor, witnessIdentity, operations, true)
                        operations.writeWitness(witnessDescriptor, binding)
                        operations.fsync(witnessDescriptor)
                        operations.fchmod(witnessDescriptor, 0x100) // Seal only this new witness.
                    } else {
                        check(operations.readWitness(witnessDescriptor).contentEquals(binding)) {
                            "Wallet custody witness is incomplete or names another root"
                        }
                    }
                    // Close durability on reopening too, including a previously uncertain sync.
                    operations.fsync(witnessDescriptor)
                    operations.fsync(childDescriptor)
                    operations.fsync(parentDescriptor)
                    revalidatePrivateDirectory(parent, parentDescriptor, parentNamed, operations)
                    revalidatePrivateDirectory(child, childDescriptor, childNamed, operations)
                    revalidateWitness(witness, witnessDescriptor, witnessIdentity, operations)
                    check(operations.readWitness(witnessDescriptor).contentEquals(binding))
                    child
                }
            }
        }
    }

    private fun witnessBinding(root: Stat): ByteArray = ByteBuffer.allocate(32)
        .put(byteArrayOf(75, 71, 77, 82, 79, 79, 84, 49)) // KGMROOT1, local filesystem identity only.
        .putLong(root.device).putLong(root.inode).putInt(root.uid).putInt(root.gid).array()

    private fun requirePrivateDirectory(stat: Stat, operations: Operations) {
        requireOwnedDirectory(stat, operations)
        check(stat.mode and PERMISSION_BITS == PRIVATE_MODE) { "Wallet custody directory is not private" }
    }

    private fun requireWitness(stat: Stat, operations: Operations, pending: Boolean = false) {
        val mode = if (pending) 0x180 else 0x100
        check(stat.mode and TYPE_MASK == 0x8000 && stat.mode and PERMISSION_BITS == mode &&
            stat.uid == operations.uid && stat.gid == operations.gid && stat.links == 1L) {
            "Wallet custody witness is not a private single-link file"
        }
    }

    private fun revalidatePrivateDirectory(directory: File, descriptor: FileDescriptor,
        expected: Stat, operations: Operations) {
        val held = operations.fstat(descriptor)
        requirePrivateDirectory(held, operations)
        requireSame(expected, held)
        val named = operations.lstat(directory)
        requirePrivateDirectory(named, operations)
        requireSame(held, named)
    }

    private fun revalidateWitness(path: File, descriptor: FileDescriptor, expected: Stat,
        operations: Operations, pending: Boolean = false) {
        val held = operations.fstat(descriptor)
        requireWitness(held, operations, pending)
        requireSame(expected, held)
        val named = operations.lstat(path)
        requireWitness(named, operations, pending)
        requireSame(held, named)
    }

    private inline fun <T> withDescriptor(descriptor: FileDescriptor, operations: Operations,
        body: (FileDescriptor) -> T): T {
        var failure: Throwable? = null
        try { return body(descriptor) }
        catch (caught: Throwable) { failure = caught; throw caught }
        finally {
            try { operations.close(descriptor) }
            catch (close: Throwable) {
                if (failure == null) throw close
                if (close !== failure) failure.addSuppressed(close)
            }
        }
    }

    internal data class Stat(val mode: Int, val uid: Int, val gid: Int, val device: Long, val inode: Long, val links: Long = 1)
    internal interface Operations {
        val uid: Int
        val gid: Int
        fun lstat(directory: File): Stat
        fun openDirectory(directory: File): FileDescriptor
        fun fstat(descriptor: FileDescriptor): Stat
        fun fchmod(descriptor: FileDescriptor, mode: Int)
        fun fsync(descriptor: FileDescriptor)
        fun close(descriptor: FileDescriptor)
    }

    /** The syscall seam is internal; public callers can select only their own Context directory. */
    internal fun prepare(directory: File, operations: Operations): File {
        check(directory.isAbsolute && directory.toPath().normalize().toFile() == directory)
        val named = operations.lstat(directory)
        requireOwnedDirectory(named, operations)
        val descriptor = operations.openDirectory(directory)
        var failure: Throwable? = null
        try {
            val opened = operations.fstat(descriptor)
            requireOwnedDirectory(opened, operations)
            requireSame(named, opened)
            val before = operations.lstat(directory)
            requireOwnedDirectory(before, operations)
            requireSame(opened, before)
            // Owner access was already present: tightening removes permissions only, on the
            // authenticated descriptor. Never repair an arbitrary path or replace its contents.
            if (opened.mode and PERMISSION_BITS != PRIVATE_MODE) {
                operations.fchmod(descriptor, PRIVATE_MODE)
                operations.fsync(descriptor)
            }
            val sealed = operations.fstat(descriptor)
            requireOwnedDirectory(sealed, operations)
            requireSame(opened, sealed)
            check(sealed.mode and PERMISSION_BITS == PRIVATE_MODE) { "Wallet no-backup parent remains non-private" }
            val after = operations.lstat(directory)
            requireOwnedDirectory(after, operations)
            requireSame(sealed, after)
            check(after.mode == sealed.mode) { "Wallet no-backup parent mode changed" }
            return directory
        } catch (caught: Throwable) {
            failure = caught
            throw caught
        } finally {
            try { operations.close(descriptor) }
            catch (close: Throwable) {
                if (failure == null) throw close
                if (close !== failure) failure.addSuppressed(close)
            }
        }
    }

    private fun requireOwnedDirectory(stat: Stat, operations: Operations) {
        check(stat.mode and TYPE_MASK == DIRECTORY && stat.uid == operations.uid && stat.gid == operations.gid) {
            "Wallet no-backup parent is not the application's directory"
        }
        check(stat.mode and PRIVATE_MODE == PRIVATE_MODE) { "Wallet no-backup parent lacks owner access" }
        check(stat.mode and (SPECIAL_BITS or OTHERS_WRITE) == 0) { "Wallet no-backup parent has unsafe permissions" }
    }

    private fun requireSame(first: Stat, second: Stat) {
        check(first.device == second.device && first.inode == second.inode &&
            first.uid == second.uid && first.gid == second.gid) { "Wallet no-backup parent identity changed" }
    }

    private object AndroidOperations : CustodyOperations {
        override val uid: Int get() = Os.getuid()
        override val gid: Int get() = Os.getgid()
        override fun lstat(directory: File): Stat = Os.lstat(directory.path).let {
            Stat(it.st_mode, it.st_uid, it.st_gid, it.st_dev, it.st_ino, it.st_nlink)
        }
        override fun lstatOrAbsent(path: File): Stat? = try { lstat(path) }
            catch (error: ErrnoException) { if (error.errno == OsConstants.ENOENT) null else throw error }
        override fun mkdirPrivate(directory: File) {
            try { Os.mkdir(directory.path, PRIVATE_MODE) }
            catch (error: ErrnoException) { if (error.errno != OsConstants.EEXIST) throw error }
        }
        override fun openWitness(path: File, create: Boolean): FileDescriptor {
            var flags = OsConstants.O_NOFOLLOW or OsConstants.O_NONBLOCK or
                if (create) OsConstants.O_RDWR or OsConstants.O_CREAT or OsConstants.O_EXCL else OsConstants.O_RDONLY
            if (Build.VERSION.SDK_INT >= 27) flags = flags or OsConstants.O_CLOEXEC
            val descriptor = Os.open(path.path, flags, 0x180)
            try {
                if (Build.VERSION.SDK_INT == 26) AndroidDescriptorOpener.enableCloseOnExec(descriptor)
                check(AndroidDescriptorOpener.closeOnExecEnabled(descriptor))
                return descriptor
            } catch (failure: Throwable) {
                try { Os.close(descriptor) }
                catch (close: Throwable) { if (close !== failure) failure.addSuppressed(close) }
                throw failure
            }
        }
        override fun readWitness(descriptor: FileDescriptor): ByteArray {
            Os.lseek(descriptor, 0, OsConstants.SEEK_SET)
            val bytes = ByteArray(33)
            var count = 0
            while (count < bytes.size) {
                val read = Os.read(descriptor, bytes, count, bytes.size - count)
                if (read == 0) break
                check(read > 0)
                count += read
            }
            return bytes.copyOf(count)
        }
        override fun writeWitness(descriptor: FileDescriptor, bytes: ByteArray) {
            check(bytes.size == 32)
            Os.lseek(descriptor, 0, OsConstants.SEEK_SET)
            var offset = 0
            while (offset < bytes.size) {
                val written = Os.write(descriptor, bytes, offset, bytes.size - offset)
                check(written > 0)
                offset += written
            }
        }
        override fun openDirectory(directory: File): FileDescriptor = openDirectory(directory, Build.VERSION.SDK_INT, AndroidDescriptorOpener)
        override fun fstat(descriptor: FileDescriptor): Stat = Os.fstat(descriptor).let {
            Stat(it.st_mode, it.st_uid, it.st_gid, it.st_dev, it.st_ino, it.st_nlink)
        }
        override fun fchmod(descriptor: FileDescriptor, mode: Int) = Os.fchmod(descriptor, mode)
        override fun fsync(descriptor: FileDescriptor) = Os.fsync(descriptor)
        override fun close(descriptor: FileDescriptor) = Os.close(descriptor)
    }

    internal interface DescriptorOpener {
        fun open(directory: File, atomicCloseOnExec: Boolean): FileDescriptor
        fun enableCloseOnExec(descriptor: FileDescriptor)
        fun closeOnExecEnabled(descriptor: FileDescriptor): Boolean
        fun close(descriptor: FileDescriptor)
    }

    internal fun openDirectory(directory: File, apiLevel: Int, opener: DescriptorOpener): FileDescriptor {
        check(apiLevel >= 26)
        val descriptor = opener.open(directory, apiLevel >= 27)
        try {
            // O_CLOEXEC is public from API27. API26 uses the public fcntl API immediately;
            // unlike the newer open flag, this does not promise atomic fork/exec exclusion.
            if (apiLevel == 26) opener.enableCloseOnExec(descriptor)
            check(opener.closeOnExecEnabled(descriptor)) { "Wallet storage descriptor is inheritable" }
            return descriptor
        } catch (failure: Throwable) {
            try { opener.close(descriptor) }
            catch (close: Throwable) { if (close !== failure) failure.addSuppressed(close) }
            throw failure
        }
    }

    private object AndroidDescriptorOpener : DescriptorOpener {
        override fun open(directory: File, atomicCloseOnExec: Boolean): FileDescriptor {
            // O_DIRECTORY is not a public Android constant. NONBLOCK prevents a raced FIFO
            // from hanging; mandatory lstat/fstat directory identity checks precede mutation.
            var flags = OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_NONBLOCK
            if (atomicCloseOnExec) flags = flags or OsConstants.O_CLOEXEC
            return Os.open(directory.path, flags, 0)
        }
        override fun enableCloseOnExec(descriptor: FileDescriptor) {
            Os.fcntlInt(descriptor, OsConstants.F_SETFD, OsConstants.FD_CLOEXEC)
        }
        override fun closeOnExecEnabled(descriptor: FileDescriptor): Boolean =
            Os.fcntlInt(descriptor, OsConstants.F_GETFD, 0) and OsConstants.FD_CLOEXEC != 0
        override fun close(descriptor: FileDescriptor) = Os.close(descriptor)
    }

    private const val TYPE_MASK = 0xf000
    private const val DIRECTORY = 0x4000
    private const val PERMISSION_BITS = 0xfff
    private const val SPECIAL_BITS = 0xe00
    private const val OTHERS_WRITE = 0x2
    private const val PRIVATE_MODE = 0x1c0
}
