package org.hyperledger.iroha.sdk.client.stream

import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.client.collections.AccountHistoryRow
import org.hyperledger.iroha.sdk.client.transport.TransportExecutor
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.query.Filter

class AccountHistoryStreamTest {
    private val account = "testuﾛ1PiiHﾛWﾔﾋADｼoQﾏ22AｷﾒﾅﾗRﾋﾂｿrDSHVVmRTﾅﾋtｸS5GJ593"

    private fun row(height: Long, movement: Long, direction: String = "incoming"): String =
        """{"id":"h$height-m$movement","block_height":$height,"block_index":0,""" +
            """"movement_index":$movement,"direction":"$direction","account_id":"$account",""" +
            """"amount":"20","tx_hash":"${"ab".repeat(32)}","type":"TRANSFER","status":"SUCCESS"}"""

    private fun sse(body: String): CompletableFuture<TransportResponse> =
        CompletableFuture.completedFuture(
            TransportResponse.builder()
                .setStatusCode(200)
                .setBody(body.toByteArray(StandardCharsets.UTF_8))
                .build(),
        )

    private class Recorder : AccountHistoryStreamListener {
        val events = CopyOnWriteArrayList<String>()
        val rows = CopyOnWriteArrayList<AccountHistoryRow>()
        val errors = CopyOnWriteArrayList<Throwable>()
        val streamErrors = CopyOnWriteArrayList<ToriiStreamException>()
        val done = CountDownLatch(1)

        override fun onOpen() { events += "open" }
        override fun onMovement(row: AccountHistoryRow) { events += "movement"; rows += row }
        override fun onStreamError(error: ToriiStreamException) { events += "stream_error"; streamErrors += error }
        override fun onClosed() { events += "closed"; done.countDown() }
        override fun onError(error: Throwable) { events += "error"; errors += error; done.countDown() }
    }

    private fun client(onRequest: (TransportRequest) -> CompletableFuture<TransportResponse>) =
        ToriiEventStreamClient.builder()
            .setBaseUri(URI.create("https://torii.example"))
            .setTransportExecutor(object : TransportExecutor {
                override fun execute(request: TransportRequest) = onRequest(request)
            })
            .build()

    @Test
    fun movementFramesDecodeInOrderAndOtherFramesAreSkipped() {
        var recorded: TransportRequest? = null
        val body = buildString {
            append(": heartbeat\n\n")
            append("event: movement\ndata: ${row(7, 0)}\n\n")
            append("event: future_kind\ndata: {}\n\n")
            append("event: movement\ndata: ${row(7, 1, "outgoing")}\n\n")
        }
        val recorder = Recorder()
        client { request -> recorded = request; sse(body) }
            .streamAccountHistory(account, Filter.field("direction").eq("incoming"), recorder)
        assertTrue(recorder.done.await(2, TimeUnit.SECONDS))
        assertEquals(listOf("open", "movement", "movement", "closed"), recorder.events)
        assertEquals(listOf(0L, 1L), recorder.rows.map { it.movementIndex })
        assertEquals(listOf("incoming", "outgoing"), recorder.rows.map { it.direction })
        val request = assertNotNull(recorded)
        assertTrue(request.uri.rawPath.startsWith("/v1/accounts/testu%EF%BE%9B"), request.uri.toString())
        assertTrue(request.uri.rawPath.endsWith("/history/sse"))
        assertEquals(account, java.net.URLDecoder.decode(request.uri.rawPath.removePrefix("/v1/accounts/").removeSuffix("/history/sse"), "UTF-8"))
        assertEquals("filter=" + java.net.URLEncoder.encode("direction = \"incoming\"", "UTF-8"), request.uri.rawQuery)
        assertEquals(listOf("text/event-stream"), request.headers["Accept"])
    }

    @Test
    fun aTerminalStreamErrorReachesTheListener() {
        val body = "event: stream_error\ndata: " +
            """{"code":"stream_lagged","message":"lost","dropped_messages":3,"replay_available":false}""" +
            "\n\n"
        val recorder = Recorder()
        client { sse(body) }.streamAccountHistory(account, null, recorder)
        assertTrue(recorder.done.await(2, TimeUnit.SECONDS))
        assertEquals("stream_lagged", recorder.streamErrors.single().code)
        assertFalse(recorder.events.contains("movement"))
    }

    @Test
    fun aMovementThatIsNotAHistoryRowFailsTheStream() {
        val recorder = Recorder()
        client { sse("event: movement\ndata: [1,2]\n\n") }.streamAccountHistory(account, null, recorder)
        assertTrue(recorder.done.await(2, TimeUnit.SECONDS))
        assertIs<IllegalArgumentException>(rootCause(recorder.errors.single()))
    }

    @Test
    fun theHistoryStreamRejectsLastEventIdLikeTheOtherLiveStreams() {
        val options = ToriiEventStreamOptions.builder().putHeader("Last-Event-ID", "7").build()
        assertFailsWith<IllegalArgumentException> {
            client { sse("") }.streamAccountHistory(account, null, Recorder(), options)
        }
        assertTrue(isAccountHistoryStreamRawPath("/v1/accounts/abc/history/sse"))
        assertFalse(isAccountHistoryStreamRawPath("/v1/accounts//history/sse"))
        assertFalse(isAccountHistoryStreamRawPath("/v1/accounts/a/b/history/sse"))
        assertFailsWith<IllegalArgumentException> { accountHistoryStreamPath(" ") }
    }

    @Test
    fun theSubscriptionReopensAfterEachEndAndAnnouncesEveryConnection() {
        val opens = CountDownLatch(3)
        val requests = CopyOnWriteArrayList<TransportRequest>()
        val listener = object : AccountHistoryStreamListener {
            override fun onOpen() = opens.countDown()
            override fun onMovement(row: AccountHistoryRow) {}
        }
        val subscription = client { request ->
            requests += request
            sse("event: movement\ndata: ${row(requests.size.toLong(), 0)}\n\n")
        }
            .accountHistorySubscription(account, null, listener)
            .setInitialBackoff(java.time.Duration.ofMillis(1))
            .setMaxBackoff(java.time.Duration.ofMillis(5))
            .build()
            .start()
        try {
            assertTrue(opens.await(5, TimeUnit.SECONDS), "three connections")
            assertTrue(requests.all { it.uri.rawPath.endsWith("/history/sse") })
        } finally {
            subscription.close()
        }
    }

    @Test
    fun closingTheSubscriptionStopsReconnectingAndDelivery() {
        val requests = java.util.concurrent.atomic.AtomicInteger()
        val firstOpen = CountDownLatch(1)
        val listener = object : AccountHistoryStreamListener {
            override fun onOpen() = firstOpen.countDown()
            override fun onMovement(row: AccountHistoryRow) {}
        }
        val subscription = client {
            requests.incrementAndGet()
            sse(": heartbeat\n\n")
        }
            .accountHistorySubscription(account, null, listener)
            .setInitialBackoff(java.time.Duration.ofMillis(50))
            .setMaxBackoff(java.time.Duration.ofMillis(50))
            .build()
            .start()
        assertTrue(firstOpen.await(5, TimeUnit.SECONDS))
        subscription.close()
        val afterClose = requests.get()
        Thread.sleep(300)
        assertEquals(afterClose, requests.get(), "no reconnect after close")
        assertFalse(subscription.isRunning)
    }

    private class EndedStream : ToriiEventStream {
        override fun isOpen() = false
        override fun completion(): CompletableFuture<Void> = CompletableFuture.completedFuture(null)
        override fun close() {}
    }

    @Test
    fun aFailureReportedWhileOpeningStillSchedulesAReconnect() {
        val attempts = java.util.concurrent.atomic.AtomicInteger()
        val reopened = CountDownLatch(1)
        val subscription = ToriiEventStreamSubscription.builder(
            ToriiEventStreamSubscription.StreamOpener { listener ->
                if (attempts.incrementAndGet() == 1) {
                    // A transport that fails synchronously reports before open() returns.
                    listener.onError(java.io.IOException("refused"))
                } else {
                    reopened.countDown()
                }
                EndedStream()
            },
            object : ToriiEventStreamListener {
                override fun onEvent(event: ServerSentEvent) {}
            },
        )
            .setInitialBackoff(java.time.Duration.ofMillis(5))
            .setMaxBackoff(java.time.Duration.ofMillis(5))
            .build()
            .start()
        try {
            assertTrue(reopened.await(5, TimeUnit.SECONDS), "the subscription must not die after an in-open failure")
        } finally {
            subscription.close()
        }
    }

    @Test
    fun aPersistentlyFailingEndpointBacksOffInsteadOfRetryingAtTheInitialDelay() {
        val stamps = CopyOnWriteArrayList<Long>()
        val enough = CountDownLatch(5)
        val subscription = ToriiEventStreamSubscription.builder(
            ToriiEventStreamSubscription.StreamOpener { listener ->
                stamps += System.nanoTime()
                enough.countDown()
                // Established at the transport level, then refused (e.g. HTTP 404) without onOpen.
                Thread { listener.onError(java.io.IOException("404")) }.start()
                EndedStream()
            },
            object : ToriiEventStreamListener {
                override fun onEvent(event: ServerSentEvent) {}
            },
        )
            .setInitialBackoff(java.time.Duration.ofMillis(20))
            .setMaxBackoff(java.time.Duration.ofMillis(160))
            .build()
            .start()
        try {
            assertTrue(enough.await(10, TimeUnit.SECONDS))
        } finally {
            subscription.close()
        }
        val gapsMs = stamps.zipWithNext { a, b -> (b - a) / 1_000_000 }
        assertTrue(gapsMs.size >= 4, "$gapsMs")
        assertTrue(gapsMs[3] >= 2 * 20, "the delay must grow past the initial backoff: $gapsMs")
    }

    private fun rootCause(error: Throwable): Throwable {
        var current = error
        while (current.cause != null && current.cause !== current) current = current.cause!!
        return current
    }
}
