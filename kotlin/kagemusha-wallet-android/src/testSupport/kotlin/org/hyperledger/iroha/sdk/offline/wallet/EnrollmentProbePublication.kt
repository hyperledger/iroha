// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

/** Closed test diagnostics; never contains supplied paths or credentials. */
internal class EnrollmentProbeFailure(val code: String) : IllegalStateException(code)
internal fun probeRequire(value: Boolean, code: String = "input") {
    if (!value) throw EnrollmentProbeFailure(code)
}

/** Filesystem operations below run under the mailbox's exclusive publication lock. */
internal interface EnrollmentProbePublicationIo {
    fun exists(path: String): Boolean
    fun requireExact(path: String, bytes: ByteArray, links: Long)
    fun createStage(path: String, bytes: ByteArray)
    fun syncFile(path: String, links: Long)
    fun removeStage(path: String, links: Long)
    /** Atomic no-replace operation: false means that the target already exists. */
    fun renameStage(stage: String, target: String): Boolean
    fun syncParent(path: String)
}

/**
 * Crash-recoverable test evidence publication, never Native custody repair. The reserved stage
 * is a sibling of the target. Its incomplete bytes may be discarded only before publication;
 * an existing target is never replaced. Atomic no-replace rename consumes the stage without
 * ever creating a second hard link. Readback alone never
 * completes an uncertain synchronization: every successful retry fsyncs the file and parent.
 * Exclusive attempt markers reject every existing target, including identical bytes after
 * uncertain publication, so the caller can only enter Native recovery, never dispatch again.
 */
internal fun publishEnrollmentProbeOriginal(
    io: EnrollmentProbePublicationIo, target: String, stage: String, bytes: ByteArray,
    exclusive: Boolean = false,
) {
    fun finish() {
        io.requireExact(target, bytes, 1)
        io.syncFile(target, 1)
        if (io.exists(stage)) io.removeStage(stage, 1)
        // Persists the atomic rename, any losing stage removal, or a prior uncertain publication.
        io.syncParent(target)
        io.requireExact(target, bytes, 1)
    }
    if (io.exists(target)) {
        probeRequire(!exclusive, "recovery-required")
        finish()
        return
    }
    if (io.exists(stage)) {
        io.removeStage(stage, 1)
        io.syncParent(stage)
    }
    io.createStage(stage, bytes)
    io.syncFile(stage, 1)
    // A competing publication is compared, never overwritten, even if it ignored our lock.
    val renamed = io.renameStage(stage, target)
    probeRequire(renamed || !exclusive, "recovery-required")
    finish()
}
