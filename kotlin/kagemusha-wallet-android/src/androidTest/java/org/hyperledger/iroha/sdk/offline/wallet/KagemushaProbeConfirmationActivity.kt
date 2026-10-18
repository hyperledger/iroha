// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import android.annotation.TargetApi
import android.app.Activity
import android.content.Intent
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.WindowManager
import android.widget.TextView
import androidx.test.platform.app.InstrumentationRegistry
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** Closed numeric authentication diagnostics; no OS messages or private exception causes. */
internal class KagemushaProbeAuthenticationFailure(val code: Int) : IllegalStateException()

/** One callback claim per prompt lifetime. Host tests of this gate grant no device evidence. */
internal class KagemushaProbeConfirmationTicket<T>(val id: String = UUID.randomUUID().toString()) {
    private var claimed = false
    private var terminal = false
    private val result = CompletableFuture<T>()
    @Synchronized fun claim(candidate: String): Boolean {
        if (candidate != id || claimed || terminal) return false
        claimed = true; return true
    }
    @Synchronized fun succeed(value: T): Boolean {
        if (!claimed || terminal) return false
        terminal = true; return result.complete(value)
    }
    @Synchronized fun fail(failure: Throwable): Boolean {
        if (terminal) return false
        terminal = true; return result.completeExceptionally(failure)
    }
    fun await(timeout: Long, unit: TimeUnit): T = result.get(timeout, unit)
}

/** Fresh real platform prompt per exact Native review; no cached verdict or key reconstruction. */
internal object KagemushaProbeConfirmation {
    class Result(val promptStartedTicks: Long, val ticks: Long, val authenticationType: Int)
    class Request(val projection: KagemushaWalletReviewProjectionV1) {
        val ticket = KagemushaProbeConfirmationTicket<Result>()
        var activity: KagemushaProbeConfirmationActivity? = null // accessed only on the main thread
    }
    private var current: Request? = null
    @Synchronized private fun register(request: Request) {
        probeRequire(current == null, "confirmation-busy"); current = request
    }
    @Synchronized fun claim(id: String): Request? = current?.takeIf { it.ticket.claim(id) }
    @Synchronized private fun clear(request: Request) { if (current === request) current = null }
    fun authenticate(projection: KagemushaWalletReviewProjectionV1): Result {
        probeRequire(Build.VERSION.SDK_INT >= 30, "confirmation-api")
        probeRequire(Looper.myLooper() != Looper.getMainLooper(), "confirmation-thread")
        val request = Request(projection)
        register(request)
        val main = Handler(Looper.getMainLooper())
        try {
            val context = InstrumentationRegistry.getInstrumentation().context
            context.startActivity(Intent(context, KagemushaProbeConfirmationActivity::class.java)
                .putExtra("ticket", request.ticket.id).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            return try { request.ticket.await(120, TimeUnit.SECONDS) }
                catch (failure: ExecutionException) { throw failure.cause ?: failure }
                catch (_: TimeoutException) { throw EnrollmentProbeFailure("confirmation-timeout") }
                catch (failure: InterruptedException) { Thread.currentThread().interrupt(); throw failure }
        } finally {
            // Retire the ticket before scheduling UI cleanup; a late callback cannot authorize.
            request.ticket.fail(EnrollmentProbeFailure("confirmation-closed"))
            clear(request)
            main.post { request.activity?.closePrompt() }
        }
    }
}

/** Non-exported disposable test Activity. Android owns the authentication UI and success callback. */
@TargetApi(30)
class KagemushaProbeConfirmationActivity : Activity() {
    private var request: KagemushaProbeConfirmation.Request? = null
    private var signal: CancellationSignal? = null
    private var started = false
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        if (Build.VERSION.SDK_INT < 30 || state != null) { finish(); return }
        val id = intent.getStringExtra("ticket") ?: run { finish(); return }
        val selected = KagemushaProbeConfirmation.claim(id) ?: run { finish(); return }
        request = selected; selected.activity = this
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val p = selected.projection
        val digest = EnrollmentProbeFiles.digest(p.bytes())
        val text = TextView(this)
        text.textSize = 18f
        text.setPadding(32, 48, 32, 32)
        text.text = "Disposable KAGEMUSHA ${p.kind.name}\n\n" +
            "Gross debit (atomic units): ${KagemushaMonetaryProbeManifest.decimal(p.grossDebit)}\n" +
            "Amount: ${KagemushaMonetaryProbeManifest.decimal(p.amount)}\n" +
            "Fee: ${KagemushaMonetaryProbeManifest.decimal(p.fee)}\n" +
            "Net destination: ${KagemushaMonetaryProbeManifest.decimal(p.netDestinationAmount)}\n\n" +
            "Destination digest: ${EnrollmentProbeFiles.hex(p.destinationAccountDigest())}\n\n" +
            "Exact review SHA-256: $digest\n\nAuthenticate this review to continue."
        setContentView(text)
    }
    override fun onResume() {
        super.onResume()
        val selected = request ?: return
        if (started) return
        started = true
        try {
            val p = selected.projection
            val digest = EnrollmentProbeFiles.digest(p.bytes())
            val prompt = BiometricPrompt.Builder(this)
                .setTitle("Confirm KAGEMUSHA ${p.kind.name}")
                .setSubtitle("Review ${digest.take(12)}")
                .setDescription("Gross debit ${KagemushaMonetaryProbeManifest.decimal(p.grossDebit)} atomic units. Authenticate only the exact review you confirmed.")
                .setConfirmationRequired(true)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build()
            val cancellation = CancellationSignal(); signal = cancellation
            val before = SystemClock.elapsedRealtimeNanos()
            prompt.authenticate(cancellation, mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val type = result.authenticationType
                    if (type != BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC &&
                        type != BiometricPrompt.AUTHENTICATION_RESULT_TYPE_DEVICE_CREDENTIAL) {
                        selected.ticket.fail(EnrollmentProbeFailure("confirmation-type"))
                    } else {
                        selected.ticket.succeed(KagemushaProbeConfirmation.Result(before, SystemClock.elapsedRealtimeNanos(), type))
                    }
                    finish()
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    selected.ticket.fail(KagemushaProbeAuthenticationFailure(errorCode)); finish()
                }
                // A failed scan is neither approval nor a terminal error; Android may prompt again.
            })
        } catch (failure: Throwable) {
            selected.ticket.fail(failure); finish()
        }
    }
    internal fun closePrompt() { signal?.cancel(); signal = null; finish() }
    override fun onDestroy() {
        request?.let { selected ->
            selected.ticket.fail(EnrollmentProbeFailure("confirmation-activity-destroyed"))
            selected.activity = null
        }
        signal?.cancel(); signal = null; request = null
        super.onDestroy()
    }
}
