package org.hyperledger.iroha.sdk.client

import java.io.IOException
import java.net.URI
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.ArrayDeque
import java.util.concurrent.CancellationException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.client.queue.PendingTransactionQueue
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportRequestNotDispatchedException
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.core.model.Executable
import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent
import org.hyperledger.iroha.sdk.core.model.JsonValue
import org.hyperledger.iroha.sdk.core.model.TransactionPayload
import org.hyperledger.iroha.sdk.testing.TestEd25519Keys
import org.hyperledger.iroha.sdk.testing.TestNetworkIds
import org.hyperledger.iroha.sdk.tx.SignedTransaction
import org.hyperledger.iroha.sdk.tx.SignedTransactionHasher
import org.hyperledger.iroha.sdk.tx.norito.NoritoJavaCodecAdapter

class TransactionSubmissionCompatibilityTest {
    @Test
    fun `all four transaction ingress forms guard immediately before post`() {
        val cases = listOf<Pair<String, (HttpClientTransport) -> Unit>>(
            "/v1/pipeline/transactions" to { client ->
                client.submitTransaction(sampleTransaction(1)).join()
            },
            "/v1/pipeline/transactions" to { client ->
                client.submitTransactionJson("""{"version":1}""".toByteArray()).join()
            },
            "/v1/pipeline/transaction-entrypoints" to { client ->
                client.submitTransactionEntrypoint(byteArrayOf(1, 2, 3)).join()
            },
            "/v1/pipeline/transaction-entrypoints" to { client ->
                client.submitTransactionEntrypointJson("""{"version":1}""".toByteArray()).join()
            },
        )

        for ((postPath, submit) in cases) {
            val executor = CompatibilityExecutor(listOf(capabilities()))
            submit(transport(executor))

            assertEquals(
                listOf(
                    "GET /v1/node/capabilities",
                    "POST $postPath",
                ),
                executor.requests,
            )
        }
    }

    @Test
    fun `data model drift fails before transaction post`() {
        val executor = CompatibilityExecutor(listOf(capabilities(dataModelVersion = 5)))

        val error = assertFailsWith<CompletionException> {
            transport(executor)
                .submitTransactionJson("""{"version":1}""".toByteArray())
                .join()
        }

        val mismatch = assertIs<ToriiDataModelMismatchException>(error.cause)
        assertEquals(4, mismatch.expected)
        assertEquals(5, mismatch.actual)
        assertEquals(listOf("GET /v1/node/capabilities"), executor.requests)
    }

    @Test
    fun `signed transaction schema drift fails before entrypoint post`() {
        val executor = CompatibilityExecutor(
            listOf(capabilities(schemaHash = "0".repeat(32))),
        )

        val error = assertFailsWith<CompletionException> {
            transport(executor)
                .submitTransactionEntrypoint(byteArrayOf(1))
                .join()
        }

        val mismatch = assertIs<ToriiTransactionSchemaMismatchException>(error.cause)
        assertEquals(
            ToriiTransactionCompatibility.EXPECTED_SIGNED_TRANSACTION_SCHEMA_HASH_HEX,
            mismatch.expected,
        )
        assertEquals("0".repeat(32), mismatch.actual)
        assertEquals(listOf("GET /v1/node/capabilities"), executor.requests)
    }

    @Test
    fun `guard fetches fresh capabilities for each submission`() {
        val executor = CompatibilityExecutor(
            listOf(
                capabilities(),
                capabilities(dataModelVersion = 3),
            ),
        )
        val client = transport(executor)

        client.submitTransactionJson("""{"version":1}""".toByteArray()).join()
        val error = assertFailsWith<CompletionException> {
            client.submitTransactionJson("""{"version":1}""".toByteArray()).join()
        }

        assertIs<ToriiDataModelMismatchException>(error.cause)
        assertEquals(
            listOf(
                "GET /v1/node/capabilities",
                "POST /v1/pipeline/transactions",
                "GET /v1/node/capabilities",
            ),
            executor.requests,
        )
    }

    @Test
    fun `redirect and transient statuses never redispatch signed bytes`() {
        for (status in listOf(307, 308, 503)) {
            val transaction = sampleTransaction(status)
            val executor = CompatibilityExecutor(
                capabilities = listOf(capabilities()),
                postStatuses = listOf(status, 202),
            )
            val client = transport(
                executor,
                retryPolicy = RetryPolicy.builder()
                    .setMaxAttempts(2)
                    .setBaseDelay(Duration.ZERO)
                    .build(),
            )

            val error = assertFailsWith<CompletionException> {
                client.submitTransaction(transaction).join()
            }

            val ambiguous = assertIs<AmbiguousTransactionSubmissionException>(error.cause)
            assertEquals(SignedTransactionHasher.hashHex(transaction), ambiguous.hashHex)
            assertEquals(status, ambiguous.statusCode)
            assertEquals(
                listOf(
                    "GET /v1/node/capabilities",
                    "POST /v1/pipeline/transactions",
                ),
                executor.requests,
            )
        }
    }

    @Test
    fun `network failure is ambiguous and never redispatches signed bytes`() {
        val transaction = sampleTransaction(7)
        val executor = NetworkFailureExecutor()
        val client = transport(
            executor,
            retryPolicy = RetryPolicy.builder()
                .setMaxAttempts(3)
                .setBaseDelay(Duration.ZERO)
                .build(),
        )

        val error = assertFailsWith<CompletionException> {
            client.submitTransaction(transaction).join()
        }

        val ambiguous = assertIs<AmbiguousTransactionSubmissionException>(error.cause)
        assertEquals(SignedTransactionHasher.hashHex(transaction), ambiguous.hashHex)
        assertEquals(null, ambiguous.statusCode)
        assertEquals(
            listOf(
                "GET /v1/node/capabilities",
                "POST /v1/pipeline/transactions",
            ),
            executor.requests,
        )
    }

    @Test
    fun `configured pending queue is never drained or replayed implicitly`() {
        val queue = MemoryPendingQueue()
        queue.enqueue(sampleTransaction(10))
        val executor = CompatibilityExecutor(listOf(capabilities()))
        val client = transport(executor, queue)

        client.submitTransaction(sampleTransaction(11)).join()

        assertEquals(1, queue.size())
        assertEquals(
            listOf(
                "GET /v1/node/capabilities",
                "POST /v1/pipeline/transactions",
            ),
            executor.requests,
        )
    }

    @Test
    fun `compatibility failure neither drains queue nor dispatches signed bytes`() {
        val queue = MemoryPendingQueue()
        queue.enqueue(sampleTransaction(20))
        val executor = CompatibilityExecutor(
            listOf(capabilities(dataModelVersion = 9)),
        )

        val error = assertFailsWith<CompletionException> {
            transport(executor, queue)
                .submitTransaction(sampleTransaction(21))
                .join()
        }

        assertIs<ToriiDataModelMismatchException>(error.cause)
        assertEquals(1, queue.size())
        assertEquals(
            listOf("GET /v1/node/capabilities"),
            executor.requests,
        )
    }

    @Test
    fun `all transaction ingress forms preserve synchronous pre-dispatch refusal causes`() {
        assertPreDispatchRefusal(synchronous = true)
    }

    @Test
    fun `all transaction ingress forms preserve asynchronous pre-dispatch refusal causes`() {
        assertPreDispatchRefusal(synchronous = false)
    }

    @Test
    fun `untyped synchronous failures remain ambiguous after one signed dispatch`() {
        assertAmbiguousUntypedFailure(synchronous = true)
    }

    @Test
    fun `untyped asynchronous failures remain ambiguous after one signed dispatch`() {
        assertAmbiguousUntypedFailure(synchronous = false)
    }

    @Test
    fun `cancelled transport future remains ambiguous after one signed dispatch`() {
        val transaction = sampleTransaction(33)
        val executor = SubmissionFailureExecutor(
            CancellationException("cancelled after dispatch"),
            synchronous = false,
            dispatchPost = true,
        )
        val future = transport(executor, retryPolicy = retryThreeTimes()).submitTransaction(transaction)
        assertFalse(future.isDone)
        assertTrue(executor.postResult.cancel(false))

        val error = assertFailsWith<CompletionException> { future.join() }
        val ambiguous = assertIs<AmbiguousTransactionSubmissionException>(error.cause)
        assertEquals(SignedTransactionHasher.hashHex(transaction), ambiguous.hashHex)
        assertEquals(null, ambiguous.statusCode)
        assertIs<CancellationException>(ambiguous.cause)
        assertOnePostAttempt(executor, "/v1/pipeline/transactions", dispatched = true)
    }

    @Test
    fun `other transaction ingress forms retain ordinary transport failure contracts`() {
        for (synchronous in listOf(true, false)) {
            for ((index, ingress) in transactionIngressForms(sampleTransaction(34)).withIndex()) {
                if (index == 0) continue
                val (postPath, submit) = ingress
                for (failure in listOf(IOException("connection reset"), CancellationException("transport cancelled"))) {
                    val executor = SubmissionFailureExecutor(failure, synchronous, dispatchPost = true)
                    val future = submit(transport(executor, retryPolicy = retryThreeTimes()))
                    if (!synchronous) {
                        assertFalse(future.isDone)
                        assertTrue(executor.postResult.completeExceptionally(CompletionException(failure)))
                    }

                    val error = assertFailsWith<CompletionException> { future.join() }
                    if (index == 2) {
                        assertSame(failure, error.cause)
                    } else {
                        val context = assertIs<RuntimeException>(error.cause)
                        assertEquals(
                            if (index == 1) "transaction JSON submit request failed"
                            else "transaction entrypoint JSON submit request failed",
                            context.message,
                        )
                        assertSame(failure, context.cause)
                    }
                    assertOnePostAttempt(executor, postPath, dispatched = true)
                }
            }
        }
    }

    private fun assertPreDispatchRefusal(synchronous: Boolean) {
        for ((postPath, submit) in transactionIngressForms(sampleTransaction(30))) {
            for (failure in listOf(
                CancellationException("owner replaced before dispatch"),
                IOException("request signing unavailable"),
                IllegalStateException("request admission refused"),
            )) {
                val marker = TransportRequestNotDispatchedException(failure)
                assertSame(failure, marker.originalFailure)
                assertSame(failure, marker.cause)
                val executor = SubmissionFailureExecutor(marker, synchronous, dispatchPost = false)
                val queue = MemoryPendingQueue()
                val queued = sampleTransaction(31)
                queue.enqueue(queued)
                val future = submit(transport(executor, queue, retryThreeTimes()))
                if (!synchronous) {
                    assertFalse(future.isDone)
                    assertTrue(executor.postResult.completeExceptionally(CompletionException(marker)))
                }

                val error = assertFailsWith<CompletionException> { future.join() }
                assertSame(failure, error.cause)
                assertOnePostAttempt(executor, postPath, dispatched = false)
                assertEquals(1, queue.size())
                assertSame(queued, queue.drain().single())
            }
        }
    }

    private fun assertAmbiguousUntypedFailure(synchronous: Boolean) {
        val transaction = sampleTransaction(32)
        for (failure in listOf(
            IOException("connection reset after dispatch"),
            CancellationException("cancelled after dispatch"),
            IOException(
                "a nested refusal is not proof this request was undispatched",
                TransportRequestNotDispatchedException(CancellationException("nested refusal")),
            ),
            RuntimeException("transport failed", CancellationException("nested cancellation")),
        )) {
            val executor = SubmissionFailureExecutor(failure, synchronous, dispatchPost = true)
            val future = transport(executor, retryPolicy = retryThreeTimes()).submitTransaction(transaction)
            if (!synchronous) {
                assertFalse(future.isDone)
                assertTrue(executor.postResult.completeExceptionally(CompletionException(failure)))
            }

            val error = assertFailsWith<CompletionException> { future.join() }
            val ambiguous = assertIs<AmbiguousTransactionSubmissionException>(error.cause)
            assertEquals(SignedTransactionHasher.hashHex(transaction), ambiguous.hashHex)
            assertEquals(null, ambiguous.statusCode)
            assertEquals(null, ambiguous.rejectCode)
            assertEquals(null, ambiguous.responseBody)
            assertSame(failure, ambiguous.cause)
            assertOnePostAttempt(executor, "/v1/pipeline/transactions", dispatched = true)
        }
    }

    private fun transactionIngressForms(
        transaction: SignedTransaction,
    ): List<Pair<String, (HttpClientTransport) -> CompletableFuture<ClientResponse>>> = listOf(
        "/v1/pipeline/transactions" to { client -> client.submitTransaction(transaction) },
        "/v1/pipeline/transactions" to { client ->
            client.submitTransactionJson("""{"version":1}""".toByteArray(StandardCharsets.UTF_8))
        },
        "/v1/pipeline/transaction-entrypoints" to { client ->
            client.submitTransactionEntrypoint(byteArrayOf(1, 2, 3))
        },
        "/v1/pipeline/transaction-entrypoints" to { client ->
            client.submitTransactionEntrypointJson("""{"version":1}""".toByteArray(StandardCharsets.UTF_8))
        },
    )

    private fun retryThreeTimes(): RetryPolicy = RetryPolicy.builder()
        .setMaxAttempts(3)
        .setBaseDelay(Duration.ZERO)
        .build()

    private fun assertOnePostAttempt(
        executor: SubmissionFailureExecutor,
        postPath: String,
        dispatched: Boolean,
    ) {
        assertEquals(
            listOf("GET /v1/node/capabilities", "POST $postPath"),
            executor.attemptedRequests,
        )
        assertEquals(
            if (dispatched) listOf("GET /v1/node/capabilities", "POST $postPath")
            else listOf("GET /v1/node/capabilities"),
            executor.dispatchedRequests,
        )
    }

    private fun transport(
        executor: HttpTransportExecutor,
        queue: PendingTransactionQueue? = null,
        retryPolicy: RetryPolicy = RetryPolicy.none(),
    ): HttpClientTransport =
        HttpClientTransport(
            executor,
            ClientConfig.builder()
                .setBaseUri(URI.create("https://torii.example"))
                .setPendingQueue(queue)
                .setRetryPolicy(retryPolicy)
                .build(),
        )

    private fun sampleTransaction(seed: Int): SignedTransaction {
        val codec = NoritoJavaCodecAdapter(AccountAddress.DEFAULT_I105_DISCRIMINANT)
        val authority = AccountAddress
            .fromAccount(TestEd25519Keys.publicKey(0x37), "ed25519")
            .toI105(AccountAddress.DEFAULT_I105_DISCRIMINANT)
        val payload = TransactionPayload(
            networkId = TestNetworkIds.fromSeed(seed.toLong()),
            authority = authority,
            creationTimeMs = 1_700_000_000_000L + seed,
            executable = Executable.instructions(emptyList()),
            timeToLiveMs = 5_000L,
            nonce = seed.toLong() + 1L,
            feePayment = FeePaymentIntent.authority(emptyList(), 1L),

            metadata = mapOf("note" to JsonValue.string("compat-$seed")),
        )
        return SignedTransaction(
            codec.encodeTransaction(payload),
            ByteArray(64) { (seed + 1).toByte() },
            TestEd25519Keys.publicKey(seed + 2),
            codec.schemaName(),
        )
    }

    private class CompatibilityExecutor(
        capabilities: List<String>,
        postStatuses: List<Int> = listOf(202),
    ) : HttpTransportExecutor {
        val requests = mutableListOf<String>()
        private val capabilityResponses = ArrayDeque(capabilities)
        private val postResponses = ArrayDeque(postStatuses)
        private var lastCapability = capabilities.last()
        private var lastPostStatus = postStatuses.last()

        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            requests.add("${request.method} ${request.uri.path}")
            if (request.method == "GET" && request.uri.path.endsWith("/v1/node/capabilities")) {
                if (capabilityResponses.isNotEmpty()) {
                    lastCapability = capabilityResponses.removeFirst()
                }
                return CompletableFuture.completedFuture(
                    TransportResponse.builder()
                        .setStatusCode(200)
                        .setBody(lastCapability.toByteArray(StandardCharsets.UTF_8))
                        .build(),
                )
            }
            if (postResponses.isNotEmpty()) {
                lastPostStatus = postResponses.removeFirst()
            }
            return CompletableFuture.completedFuture(
                TransportResponse.builder()
                    .setStatusCode(lastPostStatus)
                    .setBody(byteArrayOf())
                    .build(),
            )
        }
    }

    private class MemoryPendingQueue : PendingTransactionQueue {
        private val pending = mutableListOf<SignedTransaction>()

        override fun enqueue(transaction: SignedTransaction) {
            pending.add(transaction)
        }

        override fun drain(): List<SignedTransaction> {
            val drained = pending.toList()
            pending.clear()
            return drained
        }

        override fun size(): Int = pending.size

        override fun telemetryQueueName(): String = "memory"
    }

    private class SubmissionFailureExecutor(
        private val failure: Exception,
        private val synchronous: Boolean,
        private val dispatchPost: Boolean,
    ) : HttpTransportExecutor {
        val attemptedRequests = mutableListOf<String>()
        val dispatchedRequests = mutableListOf<String>()
        val postResult = CompletableFuture<TransportResponse>()

        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            val description = "${request.method} ${request.uri.path}"
            attemptedRequests.add(description)
            if (request.method == "GET") {
                dispatchedRequests.add(description)
                return CompletableFuture.completedFuture(
                    TransportResponse.builder()
                        .setStatusCode(200)
                        .setBody(capabilities().toByteArray(StandardCharsets.UTF_8))
                        .build(),
                )
            }
            if (dispatchPost) dispatchedRequests.add(description)
            if (synchronous) throw failure
            return postResult
        }
    }

    private class NetworkFailureExecutor : HttpTransportExecutor {
        val requests = mutableListOf<String>()

        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            requests.add("${request.method} ${request.uri.path}")
            if (request.method == "GET") {
                return CompletableFuture.completedFuture(
                    TransportResponse.builder()
                        .setStatusCode(200)
                        .setBody(capabilities().toByteArray(StandardCharsets.UTF_8))
                        .build(),
                )
            }
            return CompletableFuture<TransportResponse>().also {
                it.completeExceptionally(IllegalStateException("connection reset"))
            }
        }
    }

    private companion object {
        fun capabilities(
            dataModelVersion: Int = ToriiTransactionCompatibility.EXPECTED_DATA_MODEL_VERSION,
            schemaHash: String =
                ToriiTransactionCompatibility.EXPECTED_SIGNED_TRANSACTION_SCHEMA_HASH_HEX,
        ): String =
            """{"data_model_version":$dataModelVersion,"signed_transaction_schema_hash_hex":"$schemaHash"}"""
    }
}
