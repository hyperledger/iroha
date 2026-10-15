// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.test.platform.app.InstrumentationRegistry
import java.util.concurrent.TimeUnit

/** Real OS grants only, scoped to this disposable APK; no shell grant or settings mutation. */
internal object KagemushaNearbyPermissions {
    class Request {
        val ticket = KagemushaProbeConfirmationTicket<Boolean>()
        var activity: KagemushaNearbyPermissionsActivity? = null
    }
    private var current: Request? = null
    @Synchronized private fun register(value: Request) { check(current == null); current = value }
    @Synchronized fun claim(id: String): Request? = current?.takeIf { it.ticket.claim(id) }
    @Synchronized private fun retire(value: Request) { if (current === value) current = null }
    fun request(): Boolean {
        check(Looper.myLooper() != Looper.getMainLooper())
        val selected = Request(); register(selected)
        try {
            val context = InstrumentationRegistry.getInstrumentation().context
            context.startActivity(Intent(context, KagemushaNearbyPermissionsActivity::class.java)
                .putExtra("ticket", selected.ticket.id).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            return selected.ticket.await(90, TimeUnit.SECONDS)
        } finally {
            selected.ticket.fail(IllegalStateException("permissions closed")); retire(selected)
            Handler(Looper.getMainLooper()).post { selected.activity?.finish() }
        }
    }
    fun names(api: Int): List<String> = buildList {
        if (api <= 32) {
            add("android.permission.ACCESS_COARSE_LOCATION")
            if (api >= 29) add("android.permission.ACCESS_FINE_LOCATION")
        }
        if (api >= 31) {
            add("android.permission.BLUETOOTH_ADVERTISE"); add("android.permission.BLUETOOTH_CONNECT")
            add("android.permission.BLUETOOTH_SCAN")
        }
        if (api >= 33) add("android.permission.NEARBY_WIFI_DEVICES")
        if (api >= 37) add("android.permission.ACCESS_LOCAL_NETWORK")
    }
}

/** Declared permissions follow actual Android API availability; Android owns every grant. */
class KagemushaNearbyPermissionsActivity : Activity() {
    private var request: KagemushaNearbyPermissions.Request? = null
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        if (state != null) { finish(); return }
        val selected = intent.getStringExtra("ticket")?.let(KagemushaNearbyPermissions::claim)
            ?: run { finish(); return }
        request = selected; selected.activity = this
        val layout = LinearLayout(this); layout.orientation = LinearLayout.VERTICAL; layout.setPadding(32, 48, 32, 32)
        val text = TextView(this); text.text = "Allow Nearby permissions for this disposable diagnostic APK. Pairing still requires comparing the code on both selected phones."
        layout.addView(text)
        val accept = Button(this); accept.text = "Review Android permissions"
        accept.setOnClickListener {
            val missing = KagemushaNearbyPermissions.names(Build.VERSION.SDK_INT).filter {
                checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED
            }
            if (missing.isEmpty()) { selected.ticket.succeed(true); finish() }
            else requestPermissions(missing.toTypedArray(), 901)
        }
        val reject = Button(this); reject.text = "Cancel"; reject.setOnClickListener { selected.ticket.succeed(false); finish() }
        layout.addView(accept); layout.addView(reject); setContentView(layout)
    }
    override fun onRequestPermissionsResult(code: Int, permissions: Array<out String>, results: IntArray) {
        super.onRequestPermissionsResult(code, permissions, results)
        if (code != 901) return
        request?.ticket?.succeed(KagemushaNearbyPermissions.names(Build.VERSION.SDK_INT).all {
            checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
        }); finish()
    }
    override fun onDestroy() {
        request?.let { it.ticket.fail(IllegalStateException("permissions activity destroyed")); it.activity = null }
        request = null; super.onDestroy()
    }
}
