// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import android.os.SystemClock

/** Worker-only real SDK monetary lifecycle. This driver neither signs ledger transactions nor owns keys. */
internal class KagemushaWalletDeviceStages(
    private val config: EnrollmentProbeConfiguration,
    private val walletOwner: () -> KagemushaWalletV1,
    private val output: (String, ByteArray, Int) -> Unit,
    private val requireLive: () -> Unit,
) {
    private class PendingReview(val review: KagemushaWalletReviewV1, val requestId: ByteArray, val sequence: Int)
    private var pendingReview: PendingReview? = null
    private var timeExchange: KagemushaWalletTimeExchangeV1? = null
    /** Call only after the owning wallet acknowledged close. Native owns the actual lifetime. */
    fun released() { pendingReview = null; timeExchange = null }
    private fun event(name: String, sequence: Int, vararg fields: Pair<String, String>) =
        output("$name.json", probeJson(*fields), sequence)
    private fun hex(bytes: ByteArray) = EnrollmentProbeFiles.hex(bytes)
    private fun unsigned(value: Long) = KagemushaMonetaryProbeManifest.unsigned(value)
    private fun scalar(name: String, value: KagemushaWalletUInt128V1) = listOf(
        "${name}Low" to unsigned(value.low), "${name}High" to unsigned(value.high))
    private fun inputs(command: EnrollmentProbeCommand, sequence: Int): Map<String, ByteArray> {
        KagemushaMonetaryProbeManifest.validate(command.action, command.pins.keys)
        return command.pins.toSortedMap().mapValues { (name, pin) ->
            probeRequire(pin.path.startsWith("inbox/${config.invocation}/"))
            config.files.pinned(pin, KagemushaMonetaryProbeManifest.maximum(name)).also { bytes ->
                probeRequire(bytes.isNotEmpty())
                config.files.publish("private/${config.invocation}/${sequence.toString().padStart(4, '0')}-$name", bytes)
            }
        }
    }
    /** Immutable audit guard only; Native remains the sole recovery authority. */
    private fun bind(kind: String, id: ByteArray, inputs: Map<String, ByteArray>) {
        config.files.mkdir("private/intents")
        config.files.publish("private/intents/$kind-${EnrollmentProbeFiles.digest(id)}",
            KagemushaMonetaryProbeManifest.binding(kind, inputs))
    }
    private fun executedPath(id: ByteArray) = "private/intents/executed-${EnrollmentProbeFiles.digest(id)}"
    private fun call(value: KagemushaWalletCallV1, returned: Long, sequence: Int): String {
        val bytes = value.bytes()
        output("native-call.bin", bytes, sequence)
        event("native-call", sequence, "status" to value.status.toString(),
            "sequenceLow" to unsigned(value.sequenceLow), "sequenceHigh" to unsigned(value.sequenceHigh),
            "detail" to value.detail.toString(), "nativeReturnedTicks" to returned.toString(),
            "originalSHA256" to EnrollmentProbeFiles.digest(bytes))
        // Pending, Preparing, Unknown, Archived and delivery-data loss are preserved verbatim.
        return "native-call-status-${value.status}"
    }
    private fun released(value: KagemushaWalletReleasedOutputV1, observed: Long, sequence: Int): String {
        output("released-original.norito", value.original(), sequence)
        output("operation-id.bin", value.operationId(), sequence)
        value.peerKind?.let { kind ->
            val original = value.peerOriginal() ?: throw EnrollmentProbeFailure("native-projection")
            output("peer-original.norito", original, sequence)
            output("peer-envelope.norito", walletOwner().envelope(kind, original), sequence)
        }
        event("released", sequence, *(listOf("kind" to value.kind.name,
            "operationID" to hex(value.operationId()), "durableCompletionObservedTicks" to observed.toString(),
            "originalSHA256" to EnrollmentProbeFiles.digest(value.original()),
            "carrierDeliveryClaimed" to "false") + scalar("sequence", value.sequence)).toTypedArray())
        return when (value.kind) {
            KagemushaWalletReleasedOutputV1.Kind.LOAD -> "native-complete-load"
            KagemushaWalletReleasedOutputV1.Kind.SEND -> "native-complete-send"
            KagemushaWalletReleasedOutputV1.Kind.RECEIVE -> "native-complete-receive"
            else -> "native-released-kind-${value.kind.name}"
        }
    }
    private fun completion(value: KagemushaWalletCallV1, returned: Long, requestId: ByteArray, sequence: Int): String {
        val status = call(value, returned, sequence)
        if (value.status != KagemushaWalletCallV1.COMPLETE) return status
        val original = walletOwner().releasedOutputForRequest(requestId)
        // Observations after recovery do not reconstruct the unknown historical commit time.
        event("durable-call-return", sequence, "nativeReturnedTicks" to returned.toString(),
            "requestID" to hex(requestId), "operationID" to hex(original.operationId()))
        return released(original, SystemClock.elapsedRealtimeNanos(), sequence)
    }
    // `kind` is "activation" or "unload"; Awaiting carries only Native's route selector.
    private fun ledgerOutcomeState(value: KagemushaWalletLedgerOutcomeV1, kind: String, name: String,
        returned: Long, sequence: Int): String {
        val row = mutableListOf("nativeReturnedTicks" to returned.toString())
        val state = when (value) {
            is KagemushaWalletLedgerOutcomeV1.Awaiting -> { row.add("entrypoint" to hex(value.entrypoint())); "unconfirmed" }
            is KagemushaWalletLedgerOutcomeV1.Rejected -> { row.addAll(commit(value.commit)); "rejected" }
            is KagemushaWalletLedgerOutcomeV1.Confirmed -> { row.addAll(commit(value.commit)); "confirmed" }
        }
        row.add("confirmed" to (state == "confirmed").toString()); row.add("rejected" to (state == "rejected").toString())
        event(name, sequence, *row.toTypedArray())
        return "native-$kind-$state"
    }
    private fun commit(value: KagemushaWalletLedgerCommitV1) =
        listOf("height" to unsigned(value.heightBits), "commitHash" to hex(value.commitHash()))
    private fun ledgerIngestState(value: KagemushaWalletLedgerIngestV1, kind: String, name: String,
        returned: Long, sequence: Int): String = when (value) {
        is KagemushaWalletLedgerIngestV1.Outcome -> ledgerOutcomeState(value.outcome, kind, name, returned, sequence)
        is KagemushaWalletLedgerIngestV1.EpochRequired -> {
            event("$kind-epoch-required", sequence, "nativeReturnedTicks" to returned.toString(),
                "targetHeight" to unsigned(value.targetHeightBits))
            "native-$kind-epoch-required"
        }
    }
    private fun ledgerState(value: KagemushaWalletLedgerProgressV1?, returned: Long, sequence: Int) {
        val row = mutableListOf("nativeReturnedTicks" to returned.toString(), "present" to (value != null).toString())
        value?.let { row.add("height" to unsigned(it.heightBits)); row.add("blockHash" to hex(it.blockHash())) }
        event("ledger-progress", sequence, *row.toTypedArray())
    }
    private fun snapshot(sequence: Int): String {
        val value = walletOwner().snapshot()
        val observed = SystemClock.elapsedRealtimeNanos()
        val row = mutableListOf("observedTicks" to observed.toString(), "head" to hex(value.head()),
            "credentialDigest" to hex(value.credentialDigest()), "headIsFolded" to value.headIsFolded.toString(),
            "lifecycle" to value.lifecycle.name, "operationPermissionClaimed" to "false")
        row.addAll(scalar("sequence", value.sequence)); row.addAll(scalar("ownedBalance", value.ownedBalance))
        row.addAll(scalar("knownBurnedTotal", value.knownBurnedTotal)); row.addAll(scalar("backlog", value.foldBacklog))
        value.foldedBalance?.let { row.addAll(scalar("foldedBalance", it)); row.add("currentHeadFoldReadyObservedTicks" to observed.toString()) }
        event("snapshot", sequence, *row.toTypedArray())
        return if (value.headIsFolded) "native-current-head-folded" else "native-current-head-not-folded"
    }
    fun execute(command: EnrollmentProbeCommand, sequence: Int): String {
        requireLive()
        val values = inputs(command, sequence)
        fun input(name: String) = values[name] ?: throw EnrollmentProbeFailure("input")
        fun id(name: String = "request-id") = KagemushaMonetaryProbeManifest.word(input(name))
        fun family(name: String) = values + ("family" to name.toByteArray(Charsets.UTF_8))
        val wallet = walletOwner()
        return when (command.action) {
            "bootstrap" -> {
                val value = wallet.bootstrap(); call(value, SystemClock.elapsedRealtimeNanos(), sequence)
            }
            "activation" -> {
                val original = wallet.activation(); val returned = SystemClock.elapsedRealtimeNanos()
                output("activation.norito", original, sequence)
                output("ledger-instruction.norito", wallet.ledgerInstruction(KagemushaWalletLedgerTransportV1.ACTIVATE, original), sequence)
                event("activation-export", sequence, "nativeReturnedTicks" to returned.toString(), "confirmed" to "false")
                "native-activation-exported-not-submitted"
            }
            "retain-activation", "activation-status", "activation-finality" -> {
                val wire = input("signed-wire")
                if (command.action == "activation-finality") {
                    val value = wallet.ingestActivationFinality(wire, input("finality"))
                    ledgerIngestState(value, "activation", "activation-state", SystemClock.elapsedRealtimeNanos(), sequence)
                } else {
                    val value = if (command.action == "retain-activation") wallet.retainActivationAttempt(wire)
                        else wallet.activationAttemptOutcome(wire)
                    val returned = SystemClock.elapsedRealtimeNanos()
                    if (command.action == "retain-activation") {
                        // Only the actual Native return may produce this original, before any controller POST.
                        activationRetentionReceipt(wire, value, returned, config.invocation, sequence)?.let {
                            output("activation-retained.json", it, sequence)
                        }
                    }
                    ledgerOutcomeState(value, "activation", "activation-state", returned, sequence)
                }
            }
            "prepare-load" -> {
                val identity = id(); val amount = KagemushaMonetaryProbeManifest.amount(input("amount"))
                bind("load-plan", identity, values)
                val original = wallet.prepareLedgerLoad(identity, amount); val returned = SystemClock.elapsedRealtimeNanos()
                output("ledger-load-instruction.norito", original, sequence)
                event("prepared-load", sequence, "nativeReturnedTicks" to returned.toString(),
                    "requestID" to hex(identity), "settlementClaimed" to "false")
                "native-load-plan-retained"
            }
            "prepared-load" -> {
                val plan = wallet.preparedLedgerLoad(id()); val returned = SystemClock.elapsedRealtimeNanos()
                if (plan == null) "native-load-plan-absent" else {
                    output("ledger-load-instruction.norito", plan.instructionOriginal(), sequence)
                    event("prepared-load", sequence, *(listOf("nativeReturnedTicks" to returned.toString(),
                        "requestID" to hex(plan.requestId())) + scalar("ordinal", plan.ordinal) +
                        scalar("amount", plan.amount) + scalar("onlineCharge", plan.onlineCharge)).toTypedArray())
                    "native-load-plan-retained"
                }
            }
            "load" -> {
                val identity = id(); bind("operation", identity, family("load"))
                val value = wallet.load(identity, input("receipt"), input("finality"))
                completion(value, SystemClock.elapsedRealtimeNanos(), identity, sequence)
            }
            "ledger-finality", "ledger-status" -> {
                val value = if (command.action == "ledger-finality") wallet.ingestLedgerFinality(input("finality")) else wallet.ledgerProgress()
                ledgerState(value, SystemClock.elapsedRealtimeNanos(), sequence); "native-ledger-prefix-observed"
            }
            "epoch-boundary", "epoch-status" -> {
                val value = if (command.action == "epoch-boundary") wallet.ingestEpochBoundary(
                    KagemushaMonetaryProbeManifest.limb(input("epoch")), input("boundary")) else wallet.epochProgress()
                event("epoch", sequence, "nativeReturnedTicks" to SystemClock.elapsedRealtimeNanos().toString(),
                    "epoch" to value.epoch.toString(), "firstHeight" to value.firstHeight.toString(),
                    "boundaryHeight" to value.boundaryHeight.toString())
                "native-epoch-prefix-observed"
            }
            "request" -> {
                val identity = id("setup-id"); bind("setup", identity, family(command.action))
                val original = wallet.request(identity, KagemushaMonetaryProbeManifest.amount(input("amount")),
                    values["fee-schedule"], values["fee-certificate"])
                val returned = SystemClock.elapsedRealtimeNanos()
                val kind = KagemushaWalletTransportKindV1.REQUEST
                output("peer-original.norito", original, sequence)
                output("peer-envelope.norito", wallet.envelope(kind, original), sequence)
                event("setup-export", sequence, "nativeReturnedTicks" to returned.toString(),
                    "kind" to kind.name, "setupID" to hex(identity), "carrierDeliveryClaimed" to "false")
                "native-${command.action}-exported-carrier-unobserved"
            }
            "review-send", "review-unload" -> {
                probeRequire(pendingReview == null, "lifecycle")
                val identity = id(); bind("operation", identity, family(command.action))
                probeRequire(!config.files.exists(executedPath(identity)), "recovery-required")
                val review = if (command.action == "review-send") wallet.reviewSend(input("request"), input("destination"))
                    else wallet.reviewUnload(KagemushaMonetaryProbeManifest.amount(input("amount")),
                        values["quote"], values["certificates"], values["beneficiary"])
                val returned = SystemClock.elapsedRealtimeNanos()
                pendingReview = PendingReview(review, identity, sequence)
                val p = review.projection
                output("native-review.bin", p.bytes(), sequence)
                event("native-review", sequence, *(listOf("nativeReturnedTicks" to returned.toString(),
                    "reviewSHA256" to EnrollmentProbeFiles.digest(p.bytes()), "kind" to p.kind.name,
                    "requestID" to hex(identity), "head" to hex(p.currentHead()),
                    "sourceStateCommitment" to hex(p.sourceStateCommitment()),
                    "destinationAccountDigest" to hex(p.destinationAccountDigest()),
                    "onwardSendReviewReadyObserved" to (p.kind == KagemushaWalletReviewProjectionV1.Kind.SEND).toString()) +
                    scalar("amount", p.amount) + scalar("fee", p.fee) + scalar("grossDebit", p.grossDebit) +
                    scalar("netDestinationAmount", p.netDestinationAmount)).toTypedArray())
                "native-review-awaiting-explicit-decision"
            }
            "decide-review" -> decideReview(input("decision"), sequence)
            "payment-companion" -> {
                val companion = wallet.paymentCompanion(input("payment")); val returned = SystemClock.elapsedRealtimeNanos()
                output("payer-companion.norito", companion, sequence)
                event("payment-companion", sequence, "nativeReturnedTicks" to returned.toString(),
                    "carrierDeliveryClaimed" to "false", "monetaryAdmissionClaimed" to "false")
                "native-payment-companion-exported-carrier-unobserved"
            }
            "receive" -> {
                val identity = id(); bind("operation", identity, family("receive"))
                val value = wallet.receiveWithCompanion(identity, input("payment"), input("companion"))
                completion(value, SystemClock.elapsedRealtimeNanos(), identity, sequence)
            }
            "credit" -> {
                val value = wallet.receivedCredit(id()); val returned = SystemClock.elapsedRealtimeNanos()
                event("credit", sequence, *(listOf("nativeReturnedTicks" to returned.toString(),
                    "evidence" to value.evidence.name, "archive" to value.archive.name, "corePending" to value.corePending.toString(),
                    "creditID" to hex(value.creditId()), "paymentDigest" to hex(value.paymentDigest())) + scalar("amount", value.amount)).toTypedArray())
                value.creditedOriginal()?.let { original ->
                    output("peer-original.norito", original, sequence)
                    output("peer-envelope.norito", wallet.envelope(KagemushaWalletTransportKindV1.CREDITED, original), sequence)
                }
                "native-credit-evidence-${value.evidence.name}"
            }
            "accept-credited", "credited-status" -> {
                val value = if (command.action == "accept-credited") wallet.acceptCreditedForSend(id(), input("credited"))
                    else wallet.creditedStatusForSend(id(), input("credited"))
                call(value, SystemClock.elapsedRealtimeNanos(), sequence)
            }
            "fold-once" -> {
                val value = wallet.foldOnce(); call(value, SystemClock.elapsedRealtimeNanos(), sequence); snapshot(sequence)
            }
            "snapshot" -> snapshot(sequence)
            "fold-status" -> {
                val value = wallet.foldStatus(); val returned = SystemClock.elapsedRealtimeNanos()
                val fields = mutableListOf("nativeReturnedTicks" to returned.toString(),
                    "phase" to value.phase.name, "eligible" to value.eligible.toString())
                value.observedBacklog?.let { fields.addAll(scalar("observedBacklog", it)) }
                event("fold-status", sequence, *fields.toTypedArray()); "native-fold-worker-observed"
            }
            "request-status" -> {
                val identity = id(); val value = wallet.requestStatus(identity)
                completion(value, SystemClock.elapsedRealtimeNanos(), identity, sequence)
            }
            "retry" -> {
                val operation = id("operation-id"); val value = wallet.retry(operation)
                val status = call(value, SystemClock.elapsedRealtimeNanos(), sequence)
                if (value.status == KagemushaWalletCallV1.COMPLETE) {
                    val original = wallet.releasedOutputForOperation(operation)
                    released(original, SystemClock.elapsedRealtimeNanos(), sequence)
                } else status
            }
            "resume" -> {
                val value = wallet.resume(); call(value, SystemClock.elapsedRealtimeNanos(), sequence)
            }
            "released-request" -> {
                val value = wallet.releasedOutputForRequest(id()); released(value, SystemClock.elapsedRealtimeNanos(), sequence)
            }
            "released-operation" -> {
                val value = wallet.releasedOutputForOperation(id("operation-id")); released(value, SystemClock.elapsedRealtimeNanos(), sequence)
            }
            "unload-claim" -> {
                val original = wallet.unloadClaimTransport(id(), values["beneficiary"]); val returned = SystemClock.elapsedRealtimeNanos()
                output("unload-claim.norito", original, sequence)
                output("ledger-instruction.norito", wallet.ledgerInstruction(KagemushaWalletLedgerTransportV1.UNLOAD, original), sequence)
                event("unload-claim", sequence, "nativeReturnedTicks" to returned.toString(), "settled" to "false")
                "native-unload-claim-exported-not-settled"
            }
            "unload-status" -> {
                val value = wallet.unloadAttemptOutcome(input("claim"), input("signed-wire"))
                ledgerOutcomeState(value, "unload", "unload-status", SystemClock.elapsedRealtimeNanos(), sequence)
            }
            "unload-finality" -> {
                val value = wallet.ingestUnloadFinality(input("claim"), input("signed-wire"), input("finality"))
                ledgerIngestState(value, "unload", "unload-status", SystemClock.elapsedRealtimeNanos(), sequence)
            }
            "decode-request", "decode-payment", "decode-credited" -> {
                val kind = when (command.action) {
                    "decode-request" -> KagemushaWalletTransportKindV1.REQUEST
                    "decode-payment" -> KagemushaWalletTransportKindV1.PAYMENT
                    else -> KagemushaWalletTransportKindV1.CREDITED
                }
                val original = wallet.original(kind, input("envelope")); val returned = SystemClock.elapsedRealtimeNanos()
                output("peer-original.norito", original, sequence)
                event("peer-decoded", sequence, "nativeReturnedTicks" to returned.toString(), "kind" to kind.name,
                    "carrierDeliveryClaimed" to "false", "monetaryAdmissionClaimed" to "false")
                "native-peer-envelope-decoded-not-admitted"
            }
            "refresh-time" -> {
                val identity = id(); bind("operation", identity, family("refresh-time"))
                val value = wallet.refresh(identity, KagemushaWalletRefreshKindV1.TIME_ANCHOR, input("anchor"), input("certificates"))
                completion(value, SystemClock.elapsedRealtimeNanos(), identity, sequence)
            }
            "begin-time" -> {
                probeRequire(timeExchange == null, "lifecycle")
                val exchange = wallet.beginTimeExchange(); val returned = SystemClock.elapsedRealtimeNanos()
                timeExchange = exchange; output("time-nonce.bin", exchange.nonce(), sequence)
                event("time-exchange", sequence, "nativeReturnedTicks" to returned.toString())
                "native-time-exchange-awaiting-issuer"
            }
            "finish-time" -> {
                val exchange = timeExchange ?: throw EnrollmentProbeFailure("lifecycle")
                // All bounded input reads precede consumption; never reconstruct the Native token.
                val anchor = input("anchor"); val certificate = input("certificate"); timeExchange = null
                wallet.finishTimeExchange(exchange, anchor, certificate)
                event("time-retained", sequence, "nativeReturnedTicks" to SystemClock.elapsedRealtimeNanos().toString())
                "native-time-response-retained-refresh-required"
            }
            "cancel-time" -> {
                val exchange = timeExchange ?: throw EnrollmentProbeFailure("lifecycle")
                timeExchange = null; wallet.cancelTimeExchange(exchange); "native-time-exchange-cancelled"
            }
            else -> throw EnrollmentProbeFailure("input")
        }
    }
    private fun decideReview(bytes: ByteArray, sequence: Int): String {
        val pending = pendingReview ?: throw EnrollmentProbeFailure("lifecycle")
        val wallet = walletOwner(); val projection = pending.review.projection
        val decision = KagemushaMonetaryProbeManifest.Decision(bytes, config.invocation, pending.sequence, projection.bytes())
        if (!decision.confirmed) {
            pendingReview = null; wallet.discardReview(pending.review)
            event("review-cancelled", sequence, "nativeReturnedTicks" to SystemClock.elapsedRealtimeNanos().toString(),
                "reviewSequence" to pending.sequence.toString())
            return "native-review-cancelled"
        }
        // A prior marker whose fsync acknowledgement was lost fences this retained review too.
        probeRequire(!config.files.exists(executedPath(pending.requestId)), "recovery-required")
        val digest = EnrollmentProbeFiles.digest(projection.bytes())
        event("confirmation-start", sequence, "ticks" to SystemClock.elapsedRealtimeNanos().toString(),
            "reviewSequence" to pending.sequence.toString(), "reviewSHA256" to digest)
        val authenticated = KagemushaProbeConfirmation.authenticate(projection)
        requireLive()
        event("confirmation", sequence, "deviceOwnerAuthenticatedTicks" to authenticated.ticks.toString(),
            "authenticationType" to authenticated.authenticationType.toString(),
            "promptStartedTicks" to authenticated.promptStartedTicks.toString(),
            "reviewSequence" to pending.sequence.toString(), "reviewSHA256" to digest,
            "requestID" to hex(pending.requestId),
            "confirmationSurface" to "external-exact-review-plus-android-device-owner-authentication")
        // Persist before dispatch; even an uncertain marker write permits only Native recovery.
        config.files.publish(executedPath(pending.requestId), digest.toByteArray(Charsets.US_ASCII), exclusive = true)
        pendingReview = null
        event("execute-reviewed-start", sequence, "ticks" to SystemClock.elapsedRealtimeNanos().toString(),
            "requestID" to hex(pending.requestId), "reviewSHA256" to digest)
        val value = wallet.executeReviewed(pending.review, pending.requestId)
        return completion(value, SystemClock.elapsedRealtimeNanos(), pending.requestId, sequence)
    }
}
