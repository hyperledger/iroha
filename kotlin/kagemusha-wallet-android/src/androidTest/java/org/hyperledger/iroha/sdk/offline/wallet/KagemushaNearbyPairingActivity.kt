// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.test.platform.app.InstrumentationRegistry
import java.util.concurrent.TimeUnit

/** Explicit on-device code comparison for the exact selected endpoint and pinned certificate. */
internal object KagemushaNearbyPairing {
    class Request(val peer: String, val digits: String, val certificate: String, val session: String) {
        val ticket = KagemushaProbeConfirmationTicket<Boolean>()
        var activity: KagemushaNearbyPairingActivity? = null
    }
    private var current: Request? = null
    @Synchronized private fun register(value: Request) { check(current == null); current = value }
    @Synchronized fun claim(id: String): Request? = current?.takeIf { it.ticket.claim(id) }
    @Synchronized private fun retire(value: Request) { if (current === value) current = null }
    fun confirm(peer: String, digits: String, certificate: String, session: String): Boolean {
        check(Looper.myLooper() != Looper.getMainLooper())
        val value = Request(peer, digits, certificate, session); register(value)
        try {
            val context = InstrumentationRegistry.getInstrumentation().context
            context.startActivity(Intent(context, KagemushaNearbyPairingActivity::class.java)
                .putExtra("ticket", value.ticket.id).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            return value.ticket.await(90, TimeUnit.SECONDS)
        } finally {
            value.ticket.fail(IllegalStateException("pairing closed")); retire(value)
            Handler(Looper.getMainLooper()).post { value.activity?.finish() }
        }
    }
}

/** No default acceptance, external intent authorization, cached code or automated UI click. */
class KagemushaNearbyPairingActivity : Activity() {
    private var request: KagemushaNearbyPairing.Request? = null
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        if (state != null) { finish(); return }
        val selected = intent.getStringExtra("ticket")?.let(KagemushaNearbyPairing::claim)
            ?: run { finish(); return }
        request = selected; selected.activity = this
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val layout = LinearLayout(this); layout.orientation = LinearLayout.VERTICAL; layout.setPadding(32, 48, 32, 32)
        val text = TextView(this); text.textSize = 18f
        text.text = "Compare Nearby code on both devices: ${selected.digits}\n\n" +
            "Peer: ${selected.peer}\nSession: ${selected.session}\nPinned transport certificate SHA-256: ${selected.certificate}\n\n" +
            "This diagnostic identity is not hardware attestation. Continue only if the selected device displays the same code."
        layout.addView(text)
        fun button(label: String, accepted: Boolean) {
            val button = Button(this); button.text = label
            button.setOnClickListener { selected.ticket.succeed(accepted); finish() }; layout.addView(button)
        }
        button("Codes match on my selected device", true); button("Reject", false); setContentView(layout)
    }
    override fun onDestroy() {
        request?.let { it.ticket.fail(IllegalStateException("pairing activity destroyed")); it.activity = null }
        request = null; super.onDestroy()
    }
}
