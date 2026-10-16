package org.hyperledger.iroha.sdk.offline

import java.io.File
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import org.hyperledger.iroha.sdk.client.JsonParser
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The host card emulation bridge: tap-1 Request preparation off the HCE thread, durable
 * BEGIN_PAYMENT and COMMIT replies gated by the RF activation epoch, and the durable deadline.
 */
class IrohaPeerNfcCardBridgeV1Test {
    private val aid = IrohaPeerNfcApplicationIdentifierV1.fromHex("F05047444B4E464301")
    private val policy = IrohaPeerNfcProfilePolicyV1(IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1)
    private val session = ByteArray(16) { 0x42 }
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()
    private val queued = CopyOnWriteArrayList<Runnable>()
    private val callbackExecutor = Executor { queued += it }
    private val events = CopyOnWriteArrayList<IrohaPeerNfcCardEventV1>()

    @AfterEach
    fun stop() {
        scheduler.shutdownNow()
    }

    private fun runCallbacks() {
        while (queued.isNotEmpty()) queued.removeAt(0).run()
    }

    private class Callbacks : IrohaPeerNfcCardCallbacksV1 {
        val offers = CopyOnWriteArrayList<IrohaPeerWireMessageV1>()
        val preparations = CopyOnWriteArrayList<IrohaPeerNfcRequestPreparationV1>()
        val admissions = CopyOnWriteArrayList<Pair<IrohaPeerNfcPaymentAdmissionContextV1,
            IrohaPeerNfcCardCompletionV1<IrohaPeerNfcDurablePaymentAdmissionV1>>>()
        val commits = CopyOnWriteArrayList<Pair<IrohaPeerNfcCommitContextV1,
            IrohaPeerNfcCardCompletionV1<IrohaPeerNfcDurableAcknowledgementV1>>>()

        override fun prepareRequest(offer: IrohaPeerWireMessageV1, preparation: IrohaPeerNfcRequestPreparationV1) {
            offers += offer
            preparations += preparation
        }

        override fun admitPayment(
            context: IrohaPeerNfcPaymentAdmissionContextV1,
            completion: IrohaPeerNfcCardCompletionV1<IrohaPeerNfcDurablePaymentAdmissionV1>,
        ) {
            admissions += context to completion
        }

        override fun durableCommit(
            context: IrohaPeerNfcCommitContextV1,
            completion: IrohaPeerNfcCardCompletionV1<IrohaPeerNfcDurableAcknowledgementV1>,
        ) {
            commits += context to completion
        }
    }

    private class Replies {
        val responses = CopyOnWriteArrayList<IrohaPeerNfcAPDUResponseV1>()
        val handler = IrohaPeerNfcApduResponseHandlerV1 { responses += it }
    }

    private fun bridge(
        endpoint: IrohaPeerNfcCardEndpointV1,
        callbacks: Callbacks,
        deadline: Long = IrohaPeerNfcCardApduBridgeV1.DEFAULT_DURABLE_DEADLINE_MILLIS,
    ) = IrohaPeerNfcCardApduBridgeV1(endpoint, callbacks, { events += it }, deadline, callbackExecutor, scheduler)

    private fun IrohaPeerNfcCardApduBridgeV1.send(command: IrohaPeerNfcCommandV1): Replies =
        Replies().also { handle(command, it.handler) }

    @Test
    fun `submit answers at once and the request is prepared asynchronously`() {
        val endpoint = IrohaPeerNfcCardEndpointV1.intake(aid, IrohaPeerNfcOfferIntakeV1(policy, sessionId = session))
        val callbacks = Callbacks()
        val bridge = bridge(endpoint, callbacks)
        val offer = Fixtures.message(IrohaPeerPayloadKind.OFFER)
        val offerBytes = offer.encode()
        assertEquals(
            IrohaPeerNfcStatusWordV1.SUCCESS,
            bridge.send(IrohaPeerNfcCommandV1.BeginOffer(session, offerBytes.copyOfRange(0, 84))).responses.single().statusWord,
        )
        bridge.send(IrohaPeerNfcCommandV1.WriteOffer(session, offer.wireHash, 0, offerBytes))
        val submit = bridge.send(IrohaPeerNfcCommandV1.SubmitOffer(session, offer.wireHash))
        // 9000 precedes the wallet callback, which runs off the HCE thread.
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, submit.responses.single().statusWord)
        assertTrue(callbacks.offers.isEmpty())
        assertEquals(1, queued.size)
        runCallbacks()
        assertEquals(listOf(offer), callbacks.offers.toList())
        assertEquals(IrohaPeerNfcIntakeStateV1.PREPARING_REQUEST, endpoint.intakeRecord().state)

        // An RF loss does not lose the preparation; the late Request still installs.
        bridge.onDeactivated(0)
        callbacks.preparations.single().prepared(Fixtures.message(IrohaPeerPayloadKind.REQUEST).encode())
        callbacks.preparations.single().declined(9)
        assertEquals(IrohaPeerNfcIntakeStateV1.REQUEST_READY, endpoint.intakeRecord().state)
        assertTrue(events.any { it is IrohaPeerNfcCardEventV1.RequestPrepared })
        assertTrue(events.any { it is IrohaPeerNfcCardEventV1.Deactivated && it.reason == 0 })
        // The replayed SUBMIT is idempotent and never prepares again.
        bridge.send(IrohaPeerNfcCommandV1.SubmitOffer(session, offer.wireHash))
        runCallbacks()
        assertEquals(1, callbacks.offers.size)
    }

    @Test
    fun `an invalid prepared request is reported and the card keeps preparing`() {
        val endpoint = IrohaPeerNfcCardEndpointV1.intake(aid, IrohaPeerNfcOfferIntakeV1(policy, sessionId = session))
        val callbacks = Callbacks()
        val bridge = bridge(endpoint, callbacks)
        val offer = Fixtures.message(IrohaPeerPayloadKind.OFFER)
        val offerBytes = offer.encode()
        bridge.send(IrohaPeerNfcCommandV1.BeginOffer(session, offerBytes.copyOfRange(0, 84)))
        bridge.send(IrohaPeerNfcCommandV1.WriteOffer(session, offer.wireHash, 0, offerBytes))
        bridge.send(IrohaPeerNfcCommandV1.SubmitOffer(session, offer.wireHash))
        runCallbacks()
        callbacks.preparations.single().prepared(offerBytes)
        assertTrue(
            events.any {
                it is IrohaPeerNfcCardEventV1.Failed &&
                    it.failure == IrohaPeerNfcCardFailureV1.REQUEST_PREPARATION_FAILED
            },
        )
        assertEquals(IrohaPeerNfcIntakeStateV1.PREPARING_REQUEST, endpoint.intakeRecord().state)
    }

    @Test
    fun `durable replies wait for the persisted record and drop late completions`() {
        val receiver = IrohaPeerNfcReceiverSessionV1(session, Fixtures.message(IrohaPeerPayloadKind.REQUEST).encode())
        val endpoint = IrohaPeerNfcCardEndpointV1.direct(aid, receiver)
        val callbacks = Callbacks()
        val bridge = bridge(endpoint, callbacks)
        val payment = Fixtures.message(IrohaPeerPayloadKind.PAYMENT)
        val paymentBytes = payment.encode()
        val begin = IrohaPeerNfcCommandV1.BeginPayment(
            session,
            receiver.identity.requestCanonicalHash,
            paymentBytes.copyOfRange(0, 84),
        )

        // BEGIN_PAYMENT answers only after the admission record is complete.
        val first = bridge.send(begin)
        assertTrue(first.responses.isEmpty())
        runCallbacks()
        val (context, completion) = callbacks.admissions.single()
        completion.complete(IrohaPeerNfcDurablePaymentAdmissionV1(context))
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, first.responses.single().statusWord)
        assertEquals(IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING, receiver.phase)
        assertTrue(events.any { it is IrohaPeerNfcCardEventV1.PaymentAdmitted })
        // Only the first completion counts.
        completion.fail(IllegalStateException("late"))
        assertEquals(1, first.responses.size)
        // The exact replay is idempotent without another admission.
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, bridge.send(begin).responses.single().statusWord)
        runCallbacks()
        assertEquals(1, callbacks.admissions.size)

        assertEquals(
            IrohaPeerNfcStatusWordV1.SUCCESS,
            bridge.send(IrohaPeerNfcCommandV1.Write(session, payment.wireHash, 0, paymentBytes)).responses.single().statusWord,
        )
        val commit = IrohaPeerNfcCommandV1.Commit(session, receiver.identity.requestCanonicalHash, payment.wireHash)

        // A completion after RF deactivation is dropped: no reply and no installation.
        val lost = bridge.send(commit)
        runCallbacks()
        bridge.onDeactivated(1)
        val (commitContext, lateCompletion) = callbacks.commits.single()
        val record = IrohaPeerNfcDurableAcknowledgementV1(commitContext, Fixtures.message(IrohaPeerPayloadKind.CREDITED).encode())
        lateCompletion.complete(record)
        assertTrue(lost.responses.isEmpty())
        assertEquals(IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING, receiver.phase)
        assertNull(receiver.durableAcknowledgement)

        // The reader's exact replay re-stages the same context.
        val replay = bridge.send(commit)
        runCallbacks()
        assertEquals(2, callbacks.commits.size)
        callbacks.commits[1].second.complete(record)
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, replay.responses.single().statusWord)
        assertEquals(IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY, receiver.phase)
        assertTrue(events.any { it is IrohaPeerNfcCardEventV1.AcknowledgementReady })
        // The committed replay answers at once.
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, bridge.send(commit).responses.single().statusWord)
        assertEquals(2, callbacks.commits.size)

        val confirm = IrohaPeerNfcCommandV1.ConfirmAcknowledgement(
            session,
            payment.wireHash,
            Fixtures.message(IrohaPeerPayloadKind.CREDITED).wireHash,
        )
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, bridge.send(confirm).responses.single().statusWord)
        assertEquals(IrohaPeerNfcPhaseV1.COMPLETE, receiver.phase)
        assertTrue(events.any { it is IrohaPeerNfcCardEventV1.AcknowledgementConfirmed })
    }

    @Test
    fun `persistence failures and the durable deadline answer 6581`() {
        val receiver = IrohaPeerNfcReceiverSessionV1(session, Fixtures.message(IrohaPeerPayloadKind.REQUEST).encode())
        val callbacks = Callbacks()
        val bridge = bridge(IrohaPeerNfcCardEndpointV1.direct(aid, receiver), callbacks, deadline = 50)
        val payment = Fixtures.message(IrohaPeerPayloadKind.PAYMENT)
        val begin = IrohaPeerNfcCommandV1.BeginPayment(
            session,
            receiver.identity.requestCanonicalHash,
            payment.encode().copyOfRange(0, 84),
        )

        val failed = bridge.send(begin)
        runCallbacks()
        callbacks.admissions.single().second.fail(IllegalStateException("disk full"))
        assertEquals(IrohaPeerNfcStatusWordV1.STORAGE_FAILURE, failed.responses.single().statusWord)
        assertTrue(
            events.any {
                it is IrohaPeerNfcCardEventV1.Failed &&
                    it.failure == IrohaPeerNfcCardFailureV1.PAYMENT_ADMISSION_PERSISTENCE_FAILED
            },
        )
        assertEquals(IrohaPeerNfcPhaseV1.REQUEST_READY, receiver.phase)

        val timedOut = Replies()
        val answered = CountDownLatch(1)
        bridge.handle(begin) { response ->
            timedOut.responses += response
            answered.countDown()
        }
        runCallbacks()
        assertTrue(answered.await(5, TimeUnit.SECONDS))
        assertEquals(IrohaPeerNfcStatusWordV1.STORAGE_FAILURE, timedOut.responses.single().statusWord)
        assertTrue(
            events.any {
                it is IrohaPeerNfcCardEventV1.Failed &&
                    it.failure == IrohaPeerNfcCardFailureV1.PAYMENT_ADMISSION_TIMED_OUT
            },
        )
        // A completion after the deadline is dropped.
        val (context, completion) = callbacks.admissions[1]
        completion.complete(IrohaPeerNfcDurablePaymentAdmissionV1(context))
        assertEquals(1, timedOut.responses.size)
        assertEquals(IrohaPeerNfcPhaseV1.REQUEST_READY, receiver.phase)

        // A callback that throws is a persistence failure too.
        val throwing = object : IrohaPeerNfcCardCallbacksV1 by callbacks {
            override fun admitPayment(
                context: IrohaPeerNfcPaymentAdmissionContextV1,
                completion: IrohaPeerNfcCardCompletionV1<IrohaPeerNfcDurablePaymentAdmissionV1>,
            ) = throw IllegalStateException("keystore unavailable")
        }
        val thrown = Replies()
        IrohaPeerNfcCardApduBridgeV1(
            IrohaPeerNfcCardEndpointV1.direct(aid, receiver),
            throwing,
            { events += it },
            50,
            callbackExecutor,
            scheduler,
        ).handle(begin, thrown.handler)
        runCallbacks()
        assertEquals(IrohaPeerNfcStatusWordV1.STORAGE_FAILURE, thrown.responses.single().statusWord)
    }

    @Test
    fun `protocol failures answer their status words`() {
        val receiver = IrohaPeerNfcReceiverSessionV1(session, Fixtures.message(IrohaPeerPayloadKind.REQUEST).encode())
        val bridge = bridge(IrohaPeerNfcCardEndpointV1.direct(aid, receiver), Callbacks())
        val payment = Fixtures.message(IrohaPeerPayloadKind.PAYMENT)
        val wrongSession = IrohaPeerNfcCommandV1.Commit(
            ByteArray(16) { 0x43 },
            receiver.identity.requestCanonicalHash,
            payment.wireHash,
        )
        assertEquals(IrohaPeerNfcStatusWordV1.SECURITY_STATUS_NOT_SATISFIED, bridge.send(wrongSession).responses.single().statusWord)
        val early = IrohaPeerNfcCommandV1.Commit(session, receiver.identity.requestCanonicalHash, payment.wireHash)
        assertEquals(IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED, bridge.send(early).responses.single().statusWord)
        assertEquals(
            IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED,
            bridge.send(IrohaPeerNfcCommandV1.SubmitOffer(session, payment.wireHash)).responses.single().statusWord,
        )
        val intake = IrohaPeerNfcIntakeRecordV1.decode(bridge.send(IrohaPeerNfcCommandV1.GetIntake).responses.single().data())
        assertEquals(IrohaPeerNfcIntakeStateV1.REQUEST_READY, intake.state)
        assertTrue(queued.isEmpty())
    }

    @Test
    fun `the durable deadline is bounded`() {
        val receiver = IrohaPeerNfcReceiverSessionV1(session, Fixtures.message(IrohaPeerPayloadKind.REQUEST).encode())
        val endpoint = IrohaPeerNfcCardEndpointV1.direct(aid, receiver)
        assertFailsWith<IllegalArgumentException> { bridge(endpoint, Callbacks(), deadline = 0) }
        assertFailsWith<IllegalArgumentException> { bridge(endpoint, Callbacks(), deadline = 15_001) }
        assertEquals(15_000L, bridge(endpoint, Callbacks(), deadline = 15_000).durableDeadlineMillis)
        assertEquals(5_000L, IrohaPeerNfcCardApduBridgeV1(endpoint, Callbacks()).durableDeadlineMillis)
    }

    /** Exchange-bound wallet envelopes of `fixtures/kagemusha/wallet_v1_vectors.json`, in IPM1. */
    private object Fixtures {
        private fun root(): File = generateSequence(File(".").canonicalFile) { it.parentFile }
            .first { File(it, "fixtures/kagemusha/wallet_v1_vectors.json").isFile }

        private fun json(path: String) = JsonParser.parse(File(root(), path).readText()) as Map<*, *>

        private fun hex(value: Any?) = (value as String).chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        private val account: ByteArray by lazy {
            (json("fixtures/account/multisig_wire_v1.json")["positive"] as List<*>)
                .map { it as Map<*, *> }
                .map { hex(it["account_id_frame_hex"]) }
                .first { it.size <= 4096 }
        }

        private val envelopes: List<Map<*, *>> by lazy {
            (json("fixtures/kagemusha/wallet_v1_vectors.json")["envelopes"] as List<*>).map { it as Map<*, *> }
        }

        fun message(kind: IrohaPeerPayloadKind): IrohaPeerWireMessageV1 = IrohaPeerKagemushaWalletAdapterV1.wrap(
            hex(envelopes.first { (it["tag"] as Number).toInt() == kind.code }["canonical_hex"]),
            destinationAccountOriginal = if (kind == IrohaPeerPayloadKind.REQUEST) account else null,
        )
    }
}
