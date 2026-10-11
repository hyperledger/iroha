package org.hyperledger.iroha.sdk.offline.wallet

import java.io.Closeable
import org.hyperledger.iroha.sdk.privacy.PrivacyNativeBridge

/** Exact original frames, authenticated exclusively by Native. Defensive copies are retained. */
class KagemushaWalletOpenOriginalsV1(credential: ByteArray, enrollmentCertificates: ByteArray, account: ByteArray, assetScope: ByteArray) {
    private val originals: List<ByteArray>
    init {
        val values = listOf(credential, enrollmentCertificates, account, assetScope)
        require(values.zip(listOf(1_024, 10_000, 4_096, 1_024)).all { (bytes, bound) -> bytes.isNotEmpty() && bytes.size <= bound }) { "bounded original owner frames" }
        originals = values.map { it.copyOf() }
    }
    internal fun frames(): List<ByteArray> = originals.map { it.copyOf() }
}

/** A handle returned by the embedding app's trusted native startup loader, never trust pins. */
class KagemushaWalletRuntimeV1 internal constructor(nativeRuntimeHandle: Long, private val platformOwner: Any) : Closeable, KagemushaWalletCleanupResourceV1 {
    private var owner = nativeRuntimeHandle
    private var closeFailure:Throwable?=null
    private var retired=false
    private val pending = KagemushaWalletAdmissionLifetimeV1<KagemushaWalletPendingOpenV1>()
    init {require(owner>0){"native runtime handle"}}
    private fun handle():Long {
        if(retired)throw closeFailure?:KagemushaWalletExceptionV1(-2)
        return owner.takeIf{it>0}?:throw KagemushaWalletExceptionV1(-2)
    }
    private fun reply(value: KagemushaWalletCallV1?): KagemushaWalletCallV1 {
        val result = value ?: throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        if (result.status < 0) throw KagemushaWalletExceptionV1(result.status, result.reason, result.platformCode)
        return result
    }
    /** Transfer the existing owner only after Native authenticates exact live session originals. */
    @Synchronized internal fun startEnrollment(session: KagemushaWalletEnrollmentSessionOriginalsV1): KagemushaWalletEnrollmentV1 {
        val id = handle()
        val frames = session.frames()
        val result = reply(KagemushaWalletNativeV1.enrollment(id, 11, frames[0], frames[1], frames[2], emptyArray()))
        if (result.status != 37 || result.sequenceLow != id || result.sequenceHigh != 0L || result.detail != 0 || result.bytes().size !in 5..1028) {
            throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        }
        val enrollment = KagemushaWalletEnrollmentV1(id, NativeEnrollmentDriver, result.bytes().copyOfRange(4,result.bytes().size), platformOwner, java.nio.ByteBuffer.wrap(result.bytes(),0,4).int)
        owner = 0
        return enrollment
    }
    /** Reconcile these originals, retaining the same challenge and pending owner on retry. */
    @Synchronized fun begin(originals: KagemushaWalletOpenOriginalsV1): KagemushaWalletPendingOpenV1 {
        val id = handle()
        val frames = originals.frames()
        val result = reply(KagemushaWalletNativeV1.openBegin(id, frames[0], frames[1], frames[2], frames[3]))
        if (result.status != KagemushaWalletCallV1.ACCOUNT_CHALLENGE || result.sequenceLow != id || result.sequenceHigh != 0L || result.detail != 0 || result.bytes().size != 32 || result.bytes().all { it==0.toByte() }) throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        val challenge = result.bytes()
        return pending.select(challenge) { KagemushaWalletPendingOpenV1(this, challenge) }
    }
    /** Begin admission using exact native-retained E5/E6 originals after enrollment handoff. */
    @Synchronized fun beginEnrolled(): KagemushaWalletPendingOpenV1 {
        val id = handle()
        val result = reply(KagemushaWalletNativeV1.enrollment(id, 8, byteArrayOf(), byteArrayOf(), byteArrayOf(), emptyArray()))
        if (result.status != KagemushaWalletCallV1.ACCOUNT_CHALLENGE || result.sequenceLow != id || result.sequenceHigh != 0L || result.detail != 0 || result.bytes().size != 32 || result.bytes().all { it == 0.toByte() }) {
            throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        }
        val challenge = result.bytes()
        return pending.select(challenge) { KagemushaWalletPendingOpenV1(this, challenge) }
    }
    /** Reopen persisted full E6 DATA through ordinary Native account/journal admission. */
    @Synchronized internal fun beginEnrolledResult(original: ByteArray, account: ByteArray): KagemushaWalletPendingOpenV1 {
        require(original.size in 1..KagemushaWalletEnrollmentV1.RESULT_MAX_BYTES && account.size in 1..4096)
        val id = handle()
        val result = reply(KagemushaWalletNativeV1.enrollment(id, 12, original.copyOf(), account.copyOf(), byteArrayOf(), emptyArray()))
        if (result.status != KagemushaWalletCallV1.ACCOUNT_CHALLENGE || result.sequenceLow != id || result.sequenceHigh != 0L || result.detail != 0 || result.bytes().size != 32 || result.bytes().all { it == 0.toByte() }) throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        return pending.select(result.bytes()) { KagemushaWalletPendingOpenV1(this, result.bytes()) }
    }
    private fun finishNative(signature: ByteArray): KagemushaWalletV1 {
        val id = handle()
        val result = reply(KagemushaWalletNativeV1.openFinish(id, signature.copyOf()))
        if (result.status != KagemushaWalletCallV1.OPENED || result.sequenceLow != id || result.sequenceHigh != 0L || result.detail != 0 || result.bytes().isNotEmpty()) throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        val wallet = KagemushaWalletV1(id)
        owner = 0
        return wallet
    }
    @Synchronized internal fun finish(selected: KagemushaWalletPendingOpenV1, signature: ByteArray): KagemushaWalletV1 =
        pending.finish(selected) { finishNative(signature) }
    @Synchronized internal fun cancel(selected: KagemushaWalletPendingOpenV1) {
        pending.abandon(selected) { cancelNative() }
    }
    private fun cancelNative() {
        val status = KagemushaWalletNativeV1.openCancel(handle())
        if (status != 0) throw KagemushaWalletExceptionV1(status)
    }
    /** Discard a pending challenge after interrupted begin delivery, retaining native custody. */
    @Synchronized fun cancelPendingOpen() {
        pending.complete { cancelNative() }
    }
    /** Retry the retained challenge or recover interrupted finish delivery/registration. */
    @Synchronized fun retryOpenCompletion(accountSignature: ByteArray): KagemushaWalletV1 =
        pending.complete { finishNative(accountSignature) }
    /** Successful finish transfers ownership to the wallet; closing this runtime then does nothing. */
    @Synchronized override fun close() { closeFailure?.let{throw it}; closeAttempt() }
    /** Explicit cleanup retry on the same Native ID; operations remain permanently retired. */
    @Synchronized override fun retryCleanup() { closeAttempt() }
    @Synchronized override fun cleanupReleased():Boolean = owner==0L
    private fun closeAttempt() {
        retired=true
        val id=owner
        if(id!=0L) {
            try {
                val status=KagemushaWalletNativeV1.close(id)
                if(status!=0)throw KagemushaWalletExceptionV1(status)
                owner=0;pending.clear();closeFailure=null
            }catch(failure:Throwable){
                closeFailure=failure
                KagemushaWalletInstalledRuntimeV1.retainFailure(this,failure)
                throw failure
            }
        }
    }
}

/** Exact retained 32-byte account challenge; no decoder or authority constructor exists. */
class KagemushaWalletPendingOpenV1 internal constructor(private val runtime: KagemushaWalletRuntimeV1, challenge: ByteArray) : Closeable {
    private val original = challenge.copyOf()
    /** The existing Ed25519 account signs these exact native bytes. */
    fun challenge(): ByteArray = original.copyOf()
    /** Ordinary refusal retains this pending owner for retry; success transfers ownership. */
    @Synchronized fun finish(accountSignature: ByteArray): KagemushaWalletV1 =
        runtime.finish(this, accountSignature)
    /** Abandon this challenge without admitting ownership or releasing native custody. */
    @Synchronized override fun close() {
        runtime.cancel(this)
    }
}

/** Managed lifetime only, serialized by the runtime lock. Callbacks retain all Native authority. */
internal class KagemushaWalletAdmissionLifetimeV1<P : Any> {
    private var current: P? = null
    private var challenge: ByteArray? = null

    fun select(original: ByteArray, create: () -> P): P {
        current?.let {
            if (!checkNotNull(challenge).contentEquals(original)) {
                throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
            }
            return it
        }
        val selected = create()
        challenge = original.copyOf()
        current = selected
        return selected
    }

    fun <T> finish(selected: P, action: () -> T): T {
        if (current !== selected) throw KagemushaWalletExceptionV1(-2)
        return complete(action)
    }

    fun abandon(selected: P, action: () -> Unit) {
        // Closing a completed or explicitly cancelled wrapper is idempotent. In particular,
        // it must never cancel a subsequent challenge owned by this same runtime.
        if (current === selected) complete(action)
    }

    fun <T> complete(action: () -> T): T {
        val result = action()
        clear()
        return result
    }

    fun clear() {
        current = null
        challenge = null
    }
}
