// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.io.Closeable
import java.util.concurrent.CancellationException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import java.util.concurrent.Executors

/**
 * Exact public installation originals, retained as bounded DATA until Native authenticates them.
 * The independent application trust key is compiled into Native and cannot be supplied here.
 *
 * [originalsRoot] is the exact UTF-8 absolute path to the retained private financial directory:
 * verifier-pack.norito, producer-inventory.norito, transport.json, financial-originals.json and
 * wallet-originals/. Native opens the original files without following links and verifies the
 * complete authenticated catalog. This constructor neither reads nor creates that directory.
 *
 * [registrationSource] is canonical asset registration transport DATA. Generic app release
 * requires it; fixed deployment adapters require empty bytes. Native authenticates its whole
 * prefix and successful Global Register before creating any platform owner.
 *
 * The four signed base originals are mandatory. The financial trio is all present or all absent.
 * Complete absence still enters Native base authentication, then ArtifactsUnavailable (-4)
 * with no installed owner. Partial financial offers are invalid.
 */
class KagemushaWalletInstallationOriginalsV1(
    appManifest: ByteArray,
    signatureEnvelope: ByteArray,
    walletRuntime: ByteArray,
    verifierPack: ByteArray,
    producerInventory: ByteArray,
    signedGenesis: ByteArray,
    originalsRoot: ByteArray,
    registrationSource: ByteArray,
) {
    private val originals: List<ByteArray>
    companion object {
        /** Rebind locator DATA after copying exact originals into private device storage.
         * This copies no file and grants no proof, registration or wallet admission. */
        @JvmStatic fun relocateRegistrationSource(original: ByteArray, root: String): ByteArray {
            val path = root.toByteArray(Charsets.UTF_8)
            require(original.isNotEmpty() && original.size <= 8192 && path.isNotEmpty() && path.size <= 4096 &&
                root.startsWith("/") && !path.contains(0.toByte())) { "bounded source and private absolute root required" }
            if (!org.hyperledger.iroha.sdk.privacy.PrivacyNativeBridge.isNativeAvailable())
                throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.BRIDGE_UNAVAILABLE)
            val result = try { KagemushaWalletInstalledRuntimeNativeV1.relocateRegistrationSource(original.copyOf(), path) }
                catch (_: LinkageError) { throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.BRIDGE_UNAVAILABLE) }
                ?: throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
            if (result.status < 0) throw KagemushaWalletExceptionV1(result.status, result.reason, result.platformCode)
            val bytes = result.original()
            if (bytes.size > 8192) throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
            return bytes
        }
    }

    init {
        val values = listOf(appManifest, signatureEnvelope, walletRuntime, verifierPack,
            producerInventory, signedGenesis, originalsRoot, registrationSource)
        val bounds = intArrayOf(8 * 1024 * 1024, 2048, 128 * 1024,
            16 * 1024 * 1024 + 65536, 16 * 1024 * 1024, 64 * 1024 * 1024, 4096, 8192)
        require(values.indices.all { values[it].size <= bounds[it] }) {
            "installation original exceeds its native input bound"
        }
        require(listOf(appManifest, signatureEnvelope, walletRuntime, signedGenesis).all { it.isNotEmpty() }) {
            "four signed base originals are required"
        }
        val financial = listOf(verifierPack, producerInventory, originalsRoot)
        require(financial.all { it.isEmpty() } || financial.all { it.isNotEmpty() }) {
            "financial originals must be all present or all absent"
        }
        originals = values.map { it.copyOf() }
    }

    internal fun frames(): List<ByteArray> = originals.map { it.copyOf() }
    override fun toString(): String = "KagemushaWalletInstallationOriginalsV1(originals=[REDACTED])"
}


/** A cleanup view of one actual owner. Only Native close zero permits release. */
interface KagemushaWalletCleanupResourceV1 {
    fun retryCleanup()
    fun cleanupReleased():Boolean
}

/** One actual Native startup owner. Opening uses the existing RuntimeV1/PendingOpenV1 registry. */
class KagemushaWalletInstalledRuntimeV1 private constructor(
    private val runtime: KagemushaWalletRuntimeV1,
    // JNI Native platform owns a GlobalRef too; retain the actual adapter through retirement.
    private val platform: KagemushaWalletAndroidPlatformV1,
) : Closeable, KagemushaWalletCleanupResourceV1 {
    private val gate = Any()
    private var closing: CompletableFuture<Void>? = null
    private fun requireLive() = synchronized(gate) { check(closing == null) { "installed runtime retired" } }
    private val admission = KagemushaWalletInstalledAdmissionV1 { requireLive() }
    private var pendingOriginal: KagemushaWalletPendingOpenV1? = null
    private var accountSignatureOriginal: ByteArray? = null
    private fun startOpen(frames: List<ByteArray>) = synchronized(gate) {
        admission.start(frames)
    }
    private fun failedOpen() = synchronized(gate) { admission.failed() }
    private fun completedOpen() = synchronized(gate) {
        admission.completed()
        pendingOriginal = null
        accountSignatureOriginal?.fill(0)
        accountSignatureOriginal = null
    }
    /** Worker-only. Authenticate the FI session and transfer the SAME installed Native owner. */
    fun startEnrollment(session: KagemushaWalletEnrollmentSessionOriginalsV1): KagemushaWalletEnrollmentV1 = synchronized(gate) {
        requireLive()
        check(admission.canTransferToEnrollment()) { "account admission already started" }
        val enrollment = runtime.startEnrollment(session)
        closing = CompletableFuture.completedFuture(null)
        enrollment
    }
    /** Retry ordinary refusal using the same originals, Native challenge and account signature.
     * Explicit future cancellation retires custody; successful admission transfers it once.
     */
    fun openAsync(originals: KagemushaWalletOpenOriginalsV1,
        signExistingAccount: (ByteArray) -> CompletableFuture<ByteArray>,
        requireCurrent: () -> Unit): CompletableFuture<KagemushaWalletV1> =
        openFrames(originals.frames(), { runtime.begin(originals) }, signExistingAccount, requireCurrent)

    /** Reopen exact persisted E6 DATA using Native-selected asset and ordinary account/journal
     * admission. It does not replay or require the expired enrollment session/permit. */
    fun openEnrolledResult(resultOriginal: ByteArray, accountOriginal: ByteArray,
        signExistingAccount: (ByteArray) -> CompletableFuture<ByteArray>,
        requireCurrent: () -> Unit): CompletableFuture<KagemushaWalletV1> {
        require(resultOriginal.size in 1..KagemushaWalletEnrollmentV1.RESULT_MAX_BYTES && accountOriginal.size in 1..4096)
        val original = resultOriginal.copyOf(); val account = accountOriginal.copyOf()
        return openFrames(listOf(original, account), { runtime.beginEnrolledResult(original, account) }, signExistingAccount, requireCurrent)
    }
    private fun openFrames(frames: List<ByteArray>, begin: () -> KagemushaWalletPendingOpenV1,
        signExistingAccount: (ByteArray) -> CompletableFuture<ByteArray>,
        requireCurrent: () -> Unit): CompletableFuture<KagemushaWalletV1> {
        val result = CompletableFuture<KagemushaWalletV1>()
        result.whenComplete { _, _ ->
            if (result.isCancelled) io.execute { try { close() } catch (_: Throwable) {} }
        }
        io.execute {
            var started = false
            try {
                if (result.isCancelled) return@execute
                requireNoUnreleasedAdmissions(); requireCurrent(); startOpen(frames)
                started = true
                val pending = pendingOriginal ?: begin().also { pendingOriginal = it }
                requireCurrent(); requireLive()
                if (result.isCancelled) throw java.util.concurrent.CancellationException()
                val challenge = pending.challenge()
                check(challenge.size == 32 && challenge.any { it != 0.toByte() }) { "invalid native account challenge" }
                val signatureFuture = accountSignatureOriginal?.let {
                    CompletableFuture.completedFuture(it.copyOf())
                } ?: signExistingAccount(challenge.copyOf())
                signatureFuture.whenComplete { signature, error ->
                    // Freeze bounded producer DATA before queueing; callbacks do no Native I/O.
                    val deliveredSignature = signature?.takeIf { it.size == 64 }?.copyOf()
                    io.execute {
                        var wallet: KagemushaWalletV1? = null
                        try {
                            if (error != null) throw unwrap(error)
                            if (result.isCancelled) throw java.util.concurrent.CancellationException()
                            requireCurrent(); requireLive()
                            val exactSignature = requireNotNull(deliveredSignature)
                            require(exactSignature.size == 64)
                            val originalSignature = accountSignatureOriginal ?: exactSignature.also {
                                accountSignatureOriginal = it.copyOf()
                            }
                            check(originalSignature.contentEquals(exactSignature)) { "account signature original changed" }
                            wallet = pending.finish(originalSignature.copyOf())
                            completedOpen(); started = false
                            requireCurrent(); requireLive()
                            if (!result.complete(wallet)) { wallet.close(); wallet = null }
                        } catch (failure: Throwable) {
                            var reported = failure
                            if (started) { failedOpen(); started = false }
                            wallet?.let { admitted ->
                                reported = cleanup(reported, admitted) { admitted.close() }
                                reported = cleanup(reported, this) { close() }
                            }
                            if (result.isCancelled) {
                                reported = cleanup(reported, this) { close() }
                            }
                            completeInstalledOpenFailureV1(result, reported)
                        }
                    }
                }
            } catch (failure: Throwable) {
                if (started) { failedOpen(); started = false }
                val reported = if (result.isCancelled)
                    cleanup(failure, this) { close() } else failure
                completeInstalledOpenFailureV1(result, reported)
            }
        }
        return result
    }
    /** Close only unadmitted runtime custody. Successful Open transfers the same Native ID to its wallet. */
    override fun close() {
        var perform = false
        val completion = synchronized(gate) { closing ?: CompletableFuture<Void>().also { closing=it; perform=true } }
        if (perform) {
            try { runtime.close(); completion.complete(null) }
            catch (failure: Throwable) { retainFailure(this,failure); completion.completeExceptionally(failure) }
        }
        try { completion.join() } catch (failure: CompletionException) { throw unwrap(failure) }
    }
    /** Explicit close retry cannot reopen admission or substitute a new Native ID. */
    override fun retryCleanup() {
        val attempt=synchronized(gate) {
            val previous=closing
            check(previous!=null && previous.isDone){"cleanup retry requires a completed retirement attempt"}
            CompletableFuture<Void>().also{closing=it}
        }
        try{runtime.retryCleanup();attempt.complete(null)}
        catch(failure:Throwable){retainFailure(this,failure);attempt.completeExceptionally(failure);throw failure}
    }
    override fun cleanupReleased():Boolean = runtime.cleanupReleased()
    fun closeAsync(): CompletableFuture<Void> = CompletableFuture<Void>().also { future ->
        io.execute { try { close(); future.complete(null) } catch (failure: Throwable) { future.completeExceptionally(failure) } }
    }
    override fun toString() = "KagemushaWalletInstalledRuntimeV1(owner=[REDACTED])"
    companion object {
        private val io = Executors.newSingleThreadExecutor { task -> Thread(task,"iroha-wallet-admission-io").apply { isDaemon=true } }
        private val failedCleanup=KagemushaWalletCleanupQuarantineV1()
        internal fun retainFailure(resource:Any,failure:Throwable)=failedCleanup.retain(resource,failure)
        @JvmStatic fun requireNoUnreleasedAdmissions()=failedCleanup.requireReleased()
        /** Retry retained resources only; no admission, replacement owner or key freshness. */
        @JvmStatic fun retryRetainedCleanup()=failedCleanup.retry()
        internal fun cleanup(primary: Throwable,resource: Any,release: () -> Unit): Throwable {
            try { release() } catch (failure: Throwable) { if(primary !== failure)primary.addSuppressed(failure); retainFailure(resource,failure) }; return primary
        }
        private fun unwrap(error: Throwable): Throwable = if(error is CompletionException && error.cause != null) error.cause!! else error
        /** Authenticate the signed base, then return retained financial custody before registry registration.
         * The caller retains this attempt and explicitly invokes register(); ordinary refusal retries it.
         */
        @JvmStatic fun install(platform: KagemushaWalletAndroidPlatformV1, originals: KagemushaWalletInstallationOriginalsV1): KagemushaWalletInstallationAttemptV1 {
            requireNoUnreleasedAdmissions()
            return KagemushaWalletInstallationAttemptV1.begin(platform,originals)
        }
        internal fun adoptRegistered(handle:Long,platform:KagemushaWalletAndroidPlatformV1):KagemushaWalletInstalledRuntimeV1 =
            KagemushaWalletInstalledRuntimeV1(KagemushaWalletRuntimeV1(handle,platform),platform)

    }
}

/** Ordinary producer/guard cancellation is an error, not an explicit cancellation of Open.
 * CompletableFuture otherwise reports a directly completed CancellationException as cancelled,
 * triggering the real same-owner retirement observer. Preserve the exact original cause.
 */
internal fun <T> completeInstalledOpenFailureV1(result: CompletableFuture<T>, failure: Throwable): Boolean =
    result.completeExceptionally(if (failure is CancellationException) CompletionException(failure) else failure)

/** Managed sequencing only; callbacks retain all Native authority. Caller serializes its gate. */
internal class KagemushaWalletInstalledAdmissionV1(private val requireLive: () -> Unit) {
    private var originalFrames: List<ByteArray>? = null
    fun canTransferToEnrollment(): Boolean = originalFrames == null
    private var active = false
    private var transferred = false
    fun start(frames: List<ByteArray>) {
        requireLive()
        check(!active && !transferred) { "admission is active or already transferred" }
        val retained = originalFrames
        if (retained == null) originalFrames = frames.map { it.copyOf() }
        else check(retained.size == frames.size && retained.indices.all {
            retained[it].contentEquals(frames[it])
        }) { "admission originals changed" }
        active = true
    }
    fun failed() { check(active && !transferred); active = false }
    fun completed() { check(active && !transferred); transferred = true; active = false }

}
/** JNI returns one positive registry owner or a negative i32 Native failure, never a verdict. */
internal fun installationRuntimeHandle(result: Long): Long {
    if (result in Int.MIN_VALUE.toLong()..-1L) throw KagemushaWalletExceptionV1(result.toInt())
    if (result <= 0) throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
    return result
}

internal object KagemushaWalletInstalledRuntimeNativeV1 {
    @JvmStatic external fun relocateRegistrationSource(source: ByteArray, root: ByteArray): KagemushaWalletCallV1?
    @JvmStatic external fun beginInstallation(platform: KagemushaWalletAndroidPlatformV1,appManifest: ByteArray,envelope: ByteArray,
        walletRuntime: ByteArray,verifierPack: ByteArray,producerInventory: ByteArray,signedGenesis: ByteArray,originalsRoot: ByteArray,registrationSource: ByteArray): Long
    @JvmStatic external fun registerInstallation(attempt: Long): Long
    @JvmStatic external fun closeInstallation(attempt: Long): Int
}

/** Cleanup quarantine only; no owner lookup, raw ID, admission or monetary capability. */
internal class KagemushaWalletCleanupQuarantineV1 {
    private val entries=ArrayList<Pair<Any,Throwable>>()
    fun retain(resource:Any,failure:Throwable)=synchronized(entries){entries.add(resource to failure);Unit}
    private fun pruneReleased() {
        val snapshot=synchronized(entries){entries.toList()}
        // Native close can publish its failure while holding the resource's close lock.
        // Never hold this quarantine lock while querying or retrying that resource.
        val released=snapshot.map{it.first}.distinct().filter{(it as? KagemushaWalletCleanupResourceV1)?.cleanupReleased()==true}
        synchronized(entries){entries.removeAll{entry->released.any{it===entry.first}}}
    }
    fun requireReleased() {
        pruneReleased()
        synchronized(entries){entries.firstOrNull()?.let{throw it.second}}
    }
    fun retry() {
        val resources=synchronized(entries){entries.mapNotNull{it.first as? KagemushaWalletCleanupResourceV1}.distinct()}
        var failure:Throwable?=null
        resources.forEach{resource->try{resource.retryCleanup()}catch(error:Throwable){if(failure==null)failure=error else if(error !== failure)failure!!.addSuppressed(error)}}
        pruneReleased()
        failure?.let{throw it}
    }
}
