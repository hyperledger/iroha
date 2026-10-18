// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import org.hyperledger.iroha.sdk.offline.*

/** Exact actor inputs. Public context staging is not claimed as a physical carrier transfer. */
internal object KagemushaNearbyProbeManifest {
    private val common = setOf("request-id", "session-id", "request-hash", "peer-certificate")
    val schemas = mapOf(
        "nearby-identity" to setOf(emptySet<String>()), "nearby-permissions" to setOf(emptySet<String>()),
        "nearby-prepare" to setOf(setOf("setup-id", "offer"), setOf("setup-id", "offer", "fee-schedule", "fee-certificate")),
        "nearby-send" to setOf(common), "nearby-recover-send" to setOf(common),
        "nearby-receive" to setOf(common + "setup-id"), "nearby-recover-receive" to setOf(common + "setup-id"),
    )
    fun validate(action: String, names: Set<String>) = probeRequire(schemas[action]?.contains(names) == true)
    fun maximum(name: String): Int = when (name) {
        "session-id" -> 16
        "request-hash", "peer-certificate" -> 32
        else -> KagemushaMonetaryProbeManifest.maximum(name)
    }
}

/** Actual Nearby/IPN1/IPM1 rail plus the existing native wallet owner. No proof or custody bypass. */
internal class KagemushaNearbyDeviceStages(
    private val config: EnrollmentProbeConfiguration,
    private val walletOwner: () -> KagemushaWalletV1,
    private val output: (String, ByteArray, Int) -> Unit,
    private val requireLive: () -> Unit,
) : AutoCloseable {
    private val identity = KagemushaNearbyProbeIdentity()
    private val profile = IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1
    private fun digest(value: ByteArray) = EnrollmentProbeFiles.digest(value)
    private fun word(value: ByteArray, size: Int): ByteArray {
        probeRequire(value.size == size && value.any { it != 0.toByte() }); return value
    }
    private fun message(kind: IrohaPeerPayloadKind, bytes: ByteArray) =
        IrohaPeerWireMessageV1(IrohaPeerCanonicalPayload(profile, kind, 1, bytes))
    private fun marker(id: ByteArray) = "private/intents/executed-${digest(id)}"
    private fun bind(id: ByteArray, family: String, inputs: Map<String, ByteArray>, recovery: Boolean) {
        val path = "private/intents/operation-${digest(id)}"
        if (recovery) probeRequire(config.files.exists(path), "recovery-required")
        config.files.publish(path, KagemushaMonetaryProbeManifest.binding("operation",
            inputs + ("family" to family.toByteArray(Charsets.UTF_8))))
    }
    private sealed class Incoming {
        class State(val value: IrohaPeerNearbyConnectionsStateV1, val peer: String?, val error: IrohaPeerNearbyConnectionsErrorV1?) : Incoming()
        class Verify(val peer: String, val digits: String, val decision: IrohaPeerNearbyVerificationDecisionV1) : Incoming()
        class Record(val peer: String, val bytes: ByteArray, val ticks: Long) : Incoming()
        class Context(val peer: String, val value: IrohaPeerNearbyDiscoveryContextV1) : Incoming()
    }
    fun execute(command: EnrollmentProbeCommand, sequence: Int): String {
        requireLive(); KagemushaNearbyProbeManifest.validate(command.action, command.pins.keys)
        var index = 0
        var traceContext = emptyArray<Pair<String, String>>()
        fun trace(event: String, ticks: Long = SystemClock.elapsedRealtimeNanos(), vararg fields: Pair<String, String>) {
            output("nearby-${(index++).toString().padStart(4, '0')}-$event.json", probeJson(
                "schema" to "iroha.kagemusha.physical-nearby-trace.v1", "event" to event, "monotonicNs" to ticks.toString(), "invocation" to config.invocation,
                "commandSequence" to sequence.toString(), "actor" to config.actor,
                "clock" to "android-elapsed-realtime-including-sleep",
                "transportIdentity" to "raw-ed25519-application-pinned",
                "hardwareAttestationClaimed" to "false", "shippingQualificationClaimed" to "false", *traceContext, *fields), sequence)
        }
        val values = command.pins.mapValues { (name, pin) ->
            probeRequire(pin.path.startsWith("inbox/${config.invocation}/"))
            config.files.pinned(pin, KagemushaNearbyProbeManifest.maximum(name)).also {
                probeRequire(it.isNotEmpty())
                config.files.publish("private/${config.invocation}/${sequence.toString().padStart(4, '0')}-$name", it)
            }
        }
        fun input(name: String) = values[name] ?: throw EnrollmentProbeFailure("input")
        config.files.mkdir("private/nearby"); config.files.mkdir("private/intents")
        if (command.action == "nearby-identity") {
            val certificate = identity.certificate(); output("nearby-certificate.bin", certificate, sequence)
            trace("identity", fields = arrayOf("certificateSHA256" to digest(certificate)))
            return "engineering-transport-identity-exported"
        }
        if (command.action == "nearby-permissions") {
            val granted = KagemushaNearbyPermissions.request()
            trace("permissions", fields = arrayOf("granted" to granted.toString()))
            probeRequire(granted, "nearby-permissions-refused")
            return "nearby-os-permissions-granted"
        }
        val wallet = walletOwner()
        if (command.action == "nearby-prepare") {
            val setup = word(input("setup-id"), 32); val path = "private/nearby/setup-${digest(setup)}"
            config.files.publish("$path-binding", KagemushaMonetaryProbeManifest.binding("nearby-prepare", values))
            val request = wallet.request(setup, input("offer"), values["fee-schedule"], values["fee-certificate"])
            val payload = IrohaPeerWalletRequestV1(wallet.envelope(KagemushaWalletTransportKindV1.REQUEST, request),
                wallet.metadata().accountOriginal()).encode()
            val wire = message(IrohaPeerPayloadKind.REQUEST, payload)
            config.files.publish("$path-request", wire.encode()); config.files.publish("$path-offer", input("offer"))
            output("nearby-request-hash.bin", wire.canonicalHash, sequence)
            output("nearby-request-ipm1.bin", wire.encode(), sequence)
            trace("request-prepared", fields = arrayOf("requestSHA256" to digest(request),
                "requestCanonicalHash" to EnrollmentProbeFiles.hex(wire.canonicalHash), "carrierDeliveryClaimed" to "false"))
            return "native-request-ready-for-nearby"
        }
        val sender = command.action.endsWith("send")
        val recovery = command.action.contains("recover")
        val requestId = word(input("request-id"), 32)
        val sessionId = word(input("session-id"), 16)
        val requestHash = word(input("request-hash"), 32)
        val peerCertificate = word(input("peer-certificate"), 32)
        probeRequire(!peerCertificate.contentEquals(identity.certificate()), "nearby-peer")
        val role = if (sender) IrohaPeerNearbyRoleV1.SENDER else IrohaPeerNearbyRoleV1.RECEIVER
        val peerRole = if (sender) IrohaPeerNearbyRoleV1.RECEIVER else IrohaPeerNearbyRoleV1.SENDER
        val context = IrohaPeerNearbyDiscoveryContextV1(profile, role, sessionId, requestHash)
        val peerContext = IrohaPeerNearbyDiscoveryContextV1(profile, peerRole, sessionId, requestHash)
        traceContext = arrayOf("requestID" to EnrollmentProbeFiles.hex(requestId),
            "sessionID" to EnrollmentProbeFiles.hex(sessionId), "requestCanonicalHash" to EnrollmentProbeFiles.hex(requestHash),
            "role" to role.name, "recovery" to recovery.toString())
        val gate = KagemushaNearbyAttemptGate(recovery)
        val inputsDigest = KagemushaMonetaryProbeManifest.binding(command.action, values)
        // A restarted or failed radio attempt must select a fresh session, retaining this failed cell.
        config.files.publish("private/nearby/session-${digest(sessionId)}", inputsDigest, exclusive = true)
        trace("attempt-start", fields = arrayOf("requestID" to EnrollmentProbeFiles.hex(requestId),
            "sessionID" to EnrollmentProbeFiles.hex(sessionId), "requestCanonicalHash" to EnrollmentProbeFiles.hex(requestHash),
            "peerCertificateSHA256" to digest(peerCertificate), "localCertificateSHA256" to digest(identity.certificate()),
            "recovery" to recovery.toString(), "role" to role.name))
        val queue = ArrayBlockingQueue<Incoming>(16)
        val overflow = AtomicBoolean(false)
        fun enqueue(event: Incoming) {
            if (!queue.offer(event)) { overflow.set(true); if (event is Incoming.Verify) event.decision.decide(false) }
        }
        val transport = IrohaPeerNearbyConnectionsTransportV1(InstrumentationRegistry.getInstrumentation().context)
        val session = IrohaPeerNearbySessionV1(profile, role, sessionId, requestHash, identity.certificate())
        var peer: String? = null
        var connected = false
        transport.listener = object : IrohaPeerNearbyConnectionsListenerV1 {
            override fun onStateChanged(state: IrohaPeerNearbyConnectionsStateV1, peerId: String?, error: IrohaPeerNearbyConnectionsErrorV1?) =
                enqueue(Incoming.State(state, peerId, error))
            override fun verifyPeer(peerId: String, authenticationDigits: String, decision: IrohaPeerNearbyVerificationDecisionV1) =
                enqueue(Incoming.Verify(peerId, authenticationDigits, decision))
            override fun onRecord(peerId: String, record: ByteArray) = enqueue(Incoming.Record(peerId, record.copyOf(), SystemClock.elapsedRealtimeNanos()))
            override fun onPeerContext(peerId: String, context: IrohaPeerNearbyDiscoveryContextV1) = enqueue(Incoming.Context(peerId, context))
        }
        fun event(): Incoming {
            val deadline = SystemClock.elapsedRealtimeNanos() + TimeUnit.SECONDS.toNanos(90)
            while (true) {
                requireLive(); probeRequire(!overflow.get(), "nearby-overflow")
                val next = queue.poll(200, TimeUnit.MILLISECONDS)
                if (next != null) return next
                probeRequire(SystemClock.elapsedRealtimeNanos() < deadline, "nearby-timeout")
            }
        }
        fun handle(next: Incoming) {
            when (next) {
                is Incoming.Verify -> {
                    probeRequire(peer == null, "nearby-peer")
                    val accepted = try { KagemushaNearbyPairing.confirm(next.peer, next.digits, digest(peerCertificate),
                        EnrollmentProbeFiles.hex(sessionId)) } catch (failure: Throwable) { next.decision.decide(false); throw failure }
                    requireLive(); next.decision.decide(accepted)
                    trace("pairing-decision", fields = arrayOf("accepted" to accepted.toString(), "peerID" to next.peer))
                    probeRequire(accepted, "nearby-pairing-rejected"); peer = next.peer
                }
                is Incoming.State -> {
                    trace("radio-state", fields = arrayOf("state" to next.value.name, "error" to (next.error?.name ?: "none")))
                    probeRequire(next.error == null && next.value != IrohaPeerNearbyConnectionsStateV1.FAILED &&
                        next.value != IrohaPeerNearbyConnectionsStateV1.STOPPED, "nearby-radio")
                    if (next.value == IrohaPeerNearbyConnectionsStateV1.CONNECTED) {
                        probeRequire(peer != null && next.peer == peer && !connected, "nearby-peer"); connected = true
                    }
                }
                is Incoming.Context -> probeRequire(next.value == peerContext && (peer == null || next.peer == peer), "nearby-context")
                is Incoming.Record -> throw EnrollmentProbeFailure("nearby-order")
            }
        }
        fun receive(): Incoming.Record {
            while (true) {
                val next = event()
                if (next is Incoming.Record) {
                    probeRequire(connected && next.peer == peer, "nearby-peer")
                    output("nearby-${index.toString().padStart(4, '0')}-radio-received.bin", next.bytes, sequence)
                    trace("radio-record", next.ticks, "recordSHA256" to digest(next.bytes)); return next
                }
                handle(next)
            }
        }
        fun send(bytes: ByteArray) {
            requireLive()
            output("nearby-${index.toString().padStart(4, '0')}-radio-send.bin", bytes, sequence)
            trace("radio-send", fields = arrayOf("recordSHA256" to digest(bytes)))
            val done = CompletableFuture<Unit>()
            transport.send(bytes) { error -> if (error == null) done.complete(Unit)
                else done.completeExceptionally(EnrollmentProbeFailure("nearby-send-${error.name}")) }
            val deadline = SystemClock.elapsedRealtimeNanos() + TimeUnit.SECONDS.toNanos(90)
            while (true) {
                requireLive(); probeRequire(!overflow.get(), "nearby-overflow")
                try { done.get(200, TimeUnit.MILLISECONDS); break } catch (_: TimeoutException) {
                    probeRequire(SystemClock.elapsedRealtimeNanos() < deadline, "nearby-timeout")
                }
            }
            trace("radio-delivered", fields = arrayOf("recordSHA256" to digest(bytes)))
        }
        fun complete(call: KagemushaWalletCallV1) {
            trace("native-return", fields = arrayOf("status" to call.status.toString(), "outputSHA256" to digest(call.bytes())))
            probeRequire(call.status == KagemushaWalletCallV1.COMPLETE, "nearby-native-incomplete")
        }
        fun released(kind: KagemushaWalletReleasedOutputV1.Kind): KagemushaWalletReleasedOutputV1 {
            val released = wallet.releasedOutputForRequest(requestId)
            probeRequire(released.kind == kind && released.peerKind == if (kind == KagemushaWalletReleasedOutputV1.Kind.SEND)
                KagemushaWalletTransportKindV1.PAYMENT else KagemushaWalletTransportKindV1.CREDITED, "native-projection")
            output("nearby-released-original.norito", released.original(), sequence)
            trace("native-released", fields = arrayOf("kind" to kind.name,
                "operationID" to EnrollmentProbeFiles.hex(released.operationId()), "outputSHA256" to digest(released.original())))
            return released
        }
        try {
            if (sender) transport.startDiscovering(context) else transport.startAdvertising(context)
            while (!connected) handle(event())
            send(session.localHello.encode())
            session.acceptPeerHello(IrohaPeerNearbyHelloV1.decode(receive().bytes))
            send(session.makeAuthentication(identity.sign(session.authenticationPreimage())).encode())
            session.acceptPeerAuthentication(IrohaPeerNearbyAuthenticationV1.decode(receive().bytes),
                IrohaPeerNearbySignatureVerifierV1 { selectedRole, certificate, bytes, signature ->
                    selectedRole == peerRole && KagemushaNearbyProbeIdentity.verify(peerCertificate, certificate, bytes, signature)
                })
            trace("ipn1-authenticated")
            if (sender) {
                val requestWire = session.open(IrohaPeerNearbyEncryptedRecordV1.decode(receive().bytes))
                probeRequire(requestWire.canonicalPayload.kind == IrohaPeerPayloadKind.REQUEST &&
                    requestWire.canonicalHash.contentEquals(requestHash), "nearby-request")
                output("nearby-request-opened-ipm1.bin", requestWire.encode(), sequence)
                val companion = IrohaPeerWalletRequestV1.decode(requestWire.canonicalPayload.bytes)
                val request = wallet.original(KagemushaWalletTransportKindV1.REQUEST, companion.requestEnvelope())
                val destination = companion.destinationAccountOriginal()
                bind(requestId, "review-send", mapOf("request-id" to requestId, "request" to request, "destination" to destination), recovery)
                if (recovery) {
                    probeRequire(config.files.exists(marker(requestId)), "recovery-required")
                    complete(wallet.requestStatus(requestId))
                } else {
                    probeRequire(!config.files.exists(marker(requestId)), "recovery-required")
                    val review = wallet.reviewSend(request, destination)
                    output("nearby-native-review.bin", review.projection.bytes(), sequence)
                    var dispatched = false
                    try {
                        val confirmation = KagemushaProbeConfirmation.authenticate(review.projection)
                        gate.authorized(confirmation.ticks); requireLive()
                        trace("user-authenticated", confirmation.ticks, "reviewSHA256" to digest(review.projection.bytes()))
                        config.files.publish(marker(requestId), probeJson("kind" to "SEND",
                            "reviewSHA256" to digest(review.projection.bytes())), exclusive = true)
                        gate.dispatchMarked(); dispatched = true
                        complete(wallet.executeReviewed(review, requestId))
                    } finally { if (!dispatched) wallet.discardReview(review) }
                }
                val nativeOutput = released(KagemushaWalletReleasedOutputV1.Kind.SEND); gate.sendReleased()
                val payment = nativeOutput.peerOriginal() ?: throw EnrollmentProbeFailure("native-projection")
                send(session.seal(message(IrohaPeerPayloadKind.PAYMENT,
                    wallet.envelope(KagemushaWalletTransportKindV1.PAYMENT, payment))).encode())
                val received = receive()
                val creditedWire = session.open(IrohaPeerNearbyEncryptedRecordV1.decode(received.bytes))
                probeRequire(creditedWire.canonicalPayload.kind == IrohaPeerPayloadKind.CREDITED, "nearby-credited")
                output("nearby-credited-opened-ipm1.bin", creditedWire.encode(), sequence)
                val credited = wallet.original(KagemushaWalletTransportKindV1.CREDITED, creditedWire.canonicalPayload.bytes)
                gate.creditedArrived(received.ticks)
                trace("credited-arrival", received.ticks, "creditedSHA256" to digest(credited))
                output("nearby-credited-original.norito", credited, sequence)
                complete(wallet.acceptCreditedForSend(requestId, credited))
                val admitted = SystemClock.elapsedRealtimeNanos(); gate.creditedAdmitted(admitted)
                trace("payer-complete", admitted, "creditedSHA256" to digest(credited),
                    "elapsedNs" to (gate.elapsedNanos()?.toString() ?: "unknown"),
                    "rawArrivalElapsedNs" to (gate.arrivalElapsedNanos()?.toString() ?: "unknown"),
                    "rawArrivalScope" to "receiver-durable-completion-upper-bound",
                    "elapsedScope" to "payer-confirmation-to-credited-admission",
                    "physicalCarrierObserved" to "true", "timingAnchor" to if (recovery) "unknown-original-process" else "payer-authentication-success")
                return "native-exact-send-delivery-admitted-over-nearby"
            } else {
                val setup = word(input("setup-id"), 32); val path = "private/nearby/setup-${digest(setup)}"
                val requestWire = IrohaPeerWireMessageV1.decode(config.files.read("$path-request", 32_768))
                probeRequire(requestWire.canonicalPayload.kind == IrohaPeerPayloadKind.REQUEST &&
                    requestWire.canonicalHash.contentEquals(requestHash), "nearby-request")
                val companion = IrohaPeerWalletRequestV1.decode(requestWire.canonicalPayload.bytes)
                probeRequire(companion.destinationAccountOriginal().contentEquals(wallet.metadata().accountOriginal()), "nearby-owner")
                val offer = config.files.read("$path-offer", 10_000)
                send(session.seal(requestWire).encode())
                val paymentWire = session.open(IrohaPeerNearbyEncryptedRecordV1.decode(receive().bytes))
                probeRequire(paymentWire.canonicalPayload.kind == IrohaPeerPayloadKind.PAYMENT, "nearby-payment")
                output("nearby-payment-opened-ipm1.bin", paymentWire.encode(), sequence)
                val payment = wallet.original(KagemushaWalletTransportKindV1.PAYMENT, paymentWire.canonicalPayload.bytes)
                bind(requestId, "receive", mapOf("request-id" to requestId, "payment" to payment, "offer" to offer), recovery)
                if (recovery) {
                    probeRequire(config.files.exists(marker(requestId)), "recovery-required")
                    complete(wallet.requestStatus(requestId))
                } else {
                    config.files.publish(marker(requestId), probeJson("kind" to "RECEIVE", "paymentSHA256" to digest(payment)), exclusive = true)
                    complete(wallet.receiveFromOffer(requestId, payment, offer))
                }
                val nativeOutput = released(KagemushaWalletReleasedOutputV1.Kind.RECEIVE)
                val credited = nativeOutput.peerOriginal() ?: throw EnrollmentProbeFailure("native-projection")
                trace("receiver-durable-before-ack", fields = arrayOf("creditedSHA256" to digest(credited)))
                send(session.seal(message(IrohaPeerPayloadKind.CREDITED,
                    wallet.envelope(KagemushaWalletTransportKindV1.CREDITED, credited))).encode())
                trace("receiver-ack-delivered", fields = arrayOf("creditedSHA256" to digest(credited), "physicalCarrierObserved" to "true"))
                return "native-durable-receive-acknowledged-over-nearby"
            }
        } catch (failure: Throwable) {
            trace("attempt-incomplete", fields = arrayOf("failureClass" to failure.javaClass.simpleName,
                "latencyUsable" to "false", "automaticResampling" to "false"))
            throw failure
        } finally { transport.listener = null; transport.close(); session.close() }
    }
    override fun close() { identity.close() }
}
