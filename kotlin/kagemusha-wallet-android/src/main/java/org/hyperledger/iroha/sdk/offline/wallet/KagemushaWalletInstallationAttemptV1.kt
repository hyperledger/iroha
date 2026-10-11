// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.io.Closeable
import org.hyperledger.iroha.sdk.privacy.PrivacyNativeBridge

/** Sole managed custody of the genuine Native-loaded Runtime and authenticated originals.
 * No raw pointer or authority constructor is public. Ordinary registry refusal preserves this
 * exact attempt; close irreversibly fences registration and requires genuine Native zero.
 */
class KagemushaWalletInstallationAttemptV1 private constructor(
    platform: KagemushaWalletAndroidPlatformV1,
) : Closeable, KagemushaWalletCleanupResourceV1 {
    private val gate=Any()
    private val sequence=KagemushaWalletInstallationSequenceV1()
    private var pointer=0L
    private var platform:KagemushaWalletAndroidPlatformV1?=platform
    private var closeFailure:Throwable?=null

    /** Retry registration of the same loaded originals/provider; no reload or new reservation.
     * Success transfers once into the existing Runtime registry. Worker-only.
     */
    fun register():KagemushaWalletInstalledRuntimeV1=synchronized(gate) {
        sequence.requireRegistration()
        KagemushaWalletInstalledRuntimeV1.requireNoUnreleasedAdmissions()
        val actual=pointer.takeIf{it!=0L}?:throw KagemushaWalletExceptionV1(-2)
        val retainedPlatform=checkNotNull(platform)
        val result=try{KagemushaWalletInstalledRuntimeNativeV1.registerInstallation(actual)}
        catch(_:LinkageError){throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.BRIDGE_UNAVAILABLE)}
        // Negative i32 refusal retains exact opaque pointer. Only positive ID consumed Native's box.
        val handle=installationRuntimeHandle(result)
        pointer=0L; sequence.transferred()
        val installed=KagemushaWalletInstalledRuntimeV1.adoptRegistered(handle,retainedPlatform)
        platform=null
        installed
    }

    /** Explicitly retire this same unregistered owner. An ordinary refusal keeps it quarantined. */
    override fun close()=synchronized(gate) {
        if(sequence.isReleased)return@synchronized
        closeFailure?.let{throw it}
        closeAttempt()
    }
    /** Retry only the retained owner after refusal; registration remains permanently fenced. */
    override fun retryCleanup()=synchronized(gate) { closeAttempt() }
    override fun cleanupReleased():Boolean=synchronized(gate) { sequence.isReleased }
    private fun closeAttempt() {
        if(!sequence.startClose())return
        val actual=pointer.takeIf{it!=0L}?:throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        try {
            val status=try{KagemushaWalletInstalledRuntimeNativeV1.closeInstallation(actual)}
            catch(_:LinkageError){throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.BRIDGE_UNAVAILABLE)}
            checkInstallationCloseStatusV1(status)
            // Native consumed this exact box only after custody join returned zero.
            pointer=0L; sequence.acknowledgedClose(); platform=null; closeFailure=null
        }catch(failure:Throwable){
            closeFailure=failure
            KagemushaWalletInstalledRuntimeV1.retainFailure(this,failure)
            throw failure
        }
    }
    override fun toString()="KagemushaWalletInstallationAttemptV1(owner=[REDACTED])"
    internal companion object {
        fun begin(platform:KagemushaWalletAndroidPlatformV1,originals:KagemushaWalletInstallationOriginalsV1):KagemushaWalletInstallationAttemptV1 {
            if(!PrivacyNativeBridge.isNativeAvailable())throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.BRIDGE_UNAVAILABLE)
            // Prepare managed storage and actual adapter before Native loading acquires custody.
            val attempt=KagemushaWalletInstallationAttemptV1(platform)
            val frames=originals.frames()
            val result=try {
                if(KagemushaWalletNativeV1.revision()!=1)throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.BRIDGE_UNAVAILABLE)
                // Resolve both consuming JNI methods before loading any owner. Documented NULL
                // input must return INVALID and creates no registry/custody/provider operation.
                if(KagemushaWalletInstalledRuntimeNativeV1.registerInstallation(0L)!=-1L ||
                    KagemushaWalletInstalledRuntimeNativeV1.closeInstallation(0L)!=-1)
                    throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.BRIDGE_UNAVAILABLE)
                KagemushaWalletInstalledRuntimeNativeV1.beginInstallation(platform,
                    frames[0],frames[1],frames[2],frames[3],frames[4],frames[5],frames[6],frames[7])
            }catch(_:LinkageError){throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.BRIDGE_UNAVAILABLE)}
            attempt.pointer=installationAttemptPointerV1(result)
            return attempt
        }
    }
}

/** Private JNI pointer DATA is distinct from positive registry ID; signed64 addresses are legal.
 * Native i32 failures occupy exactly the negative i32 range. No fallback to installRuntime.
 */
internal fun installationAttemptPointerV1(result:Long):Long {
    if(result in Int.MIN_VALUE.toLong()..-1L)throw KagemushaWalletExceptionV1(result.toInt())
    if(result==0L)throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
    return result
}
internal fun checkInstallationCloseStatusV1(status:Int) {
    if(status<0)throw KagemushaWalletExceptionV1(status)
    if(status!=0)throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
}

/** Managed sequencing DATA only. Cannot create, register or close a Native owner. */
internal class KagemushaWalletInstallationSequenceV1 {
    private var transferred=false
    private var retiring=false
    private var acknowledged=false
    fun requireRegistration(){check(!transferred && !retiring && !acknowledged){"installation attempt consumed or retiring"}}
    fun transferred(){requireRegistration();transferred=true}
    fun startClose():Boolean {
        if(transferred || acknowledged)return false
        retiring=true
        return true
    }
    fun acknowledgedClose(){check(retiring && !transferred && !acknowledged);acknowledged=true}
    val isReleased:Boolean get()=transferred || acknowledged
}
