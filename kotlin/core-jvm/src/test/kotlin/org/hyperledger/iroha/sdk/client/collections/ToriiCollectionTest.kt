package org.hyperledger.iroha.sdk.client.collections

import java.math.BigDecimal
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.util.concurrent.CancellationException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.hyperledger.iroha.sdk.client.CanonicalRequestSigner
import org.hyperledger.iroha.sdk.client.ClientConfig
import org.hyperledger.iroha.sdk.client.HttpClientTransport
import org.hyperledger.iroha.sdk.client.HttpTransportExecutor
import org.hyperledger.iroha.sdk.client.LocalSigningContext
import org.hyperledger.iroha.sdk.client.RequestSigner
import org.hyperledger.iroha.sdk.client.ToriiApiException
import org.hyperledger.iroha.sdk.client.ToriiCanonicalRequestAuth
import org.hyperledger.iroha.sdk.client.ToriiProtocolException
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.json.Json
import org.hyperledger.iroha.sdk.json.JsonObject
import org.hyperledger.iroha.sdk.json.JsonString
import org.hyperledger.iroha.sdk.query.AggregateMetric
import org.hyperledger.iroha.sdk.query.AggregateSpec
import org.hyperledger.iroha.sdk.query.ListQuery
import org.hyperledger.iroha.sdk.query.ListQueryException
import org.hyperledger.iroha.sdk.query.field
import org.hyperledger.iroha.sdk.query.listQuery
import org.hyperledger.iroha.sdk.testing.TestNetworkIds
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ToriiCollectionTest {
    @Test
    fun explorerFeedsUseTheSharedEnvelopeAndHistoryControls() {
        val executor = ScriptedExecutor()
        val client = client(executor)
        val feeds = listOf(
            "accounts" to client.explorerAccounts,
            "domains" to client.explorerDomains,
            "asset-definitions" to client.explorerAssetDefinitions,
            "assets" to client.explorerAssets,
            "nfts" to client.explorerNfts,
            "rwas" to client.explorerRwas,
            "blocks" to client.explorerBlocks,
            "transactions" to client.explorerTransactions,
            "transactions/latest" to client.explorerLatestTransactions,
            "instructions" to client.explorerInstructions,
            "instructions/latest" to client.explorerLatestInstructions
        )
        for ((path, feed) in feeds) {
            executor.reply(200, """{"items":[{"id":"row"}],"next_cursor":null}""")
            assertEquals(Json.of("row"), feed.page(listQuery { limit(1) }).join().items.single()["id"])
            assertEquals("/api/v1/explorer/$path/query", executor.requests.last().uri.path)
            val before = executor.requests.size
            assertFailsWith<IllegalArgumentException> { feed.page(listQuery { includeTotal() }).join() }
            assertEquals(before, executor.requests.size)
        }
    }

    @Test
    fun migratedCollectionsUseSharedPostPagesAndPreserveRows() {
        val executor = ScriptedExecutor()
        val client = client(executor)
        executor.reply(200, """{"items":[{"name":"CanSetParameters","payload":null}],"next_cursor":"permission-next","total":2}""")
        executor.reply(200, """{"items":[{"name":"CanSetParameters","payload":{"scope":7}}],"next_cursor":null}""")
        val permissions = client.accountPermissions("alice@wonderland").fetchAll(listQuery { limit(1); includeTotal() }).join()
        assertEquals(2, permissions.size)
        assertEquals(Json.NULL, permissions[0].payload)
        assertEquals(Json.parse("""{"scope":7}"""), permissions[1].payload)
        assertEquals("/api/v1/accounts/alice@wonderland/permissions/query", executor.requests[0].uri.path)
        assertEquals(Json.of("permission-next"), (Json.parse(executor.requests[1].body) as JsonObject)["cursor"])
        executor.reply(200, """{"items":[{"id":"plan","provider":"alice","pricing":{"Fixed":1}}],"next_cursor":null}""")
        assertEquals("plan", client.subscriptionPlans.page().join().items.single().id)
        executor.reply(200, """{"items":[{"id":"subscription","status":"active","plan_id":"plan","invoice":null}],"next_cursor":null}""")
        assertEquals("active", client.subscriptions.page().join().items.single().status)
        executor.reply(200, """{"items":[{"block_height":9,"block_index":2,"entrypoint_hash":"tx"}],"next_cursor":null}""")
        assertEquals(2L, client.contractActivity.page().join().items.single().blockIndex)
        executor.reply(200, """{"items":[{"schema_version":1,"block_height":9,"block_hash_hex":"block","event_id":"block:2:0","execution_hash_hex":"execution","output_index":2,"emission_index":0,"provenance":"emitted","result_ok":true,"authority":"alice","contract_address":"contract","event_kind":"Changed","payload":{},"emission":{"contract":"contract","code_hash":"code","entrypoint":0,"event":0,"caller":"alice","definition":{"name":"Changed","payload_type":{"nodes":[{"kind":"Struct","value":{"name":"Demo::Changed","fields":[]}}]}},"payload":{"schema_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"atoms":[]}}}],"next_cursor":null}""")
        assertEquals("block:2:0", client.contractEvents.page().join().items.single().eventId)
        executor.reply(200, """{"items":[{"id":"movement","block_height":9,"block_index":2,"movement_index":3,"amount":"1.25"}],"next_cursor":null}""")
        assertEquals(3L, client.accountHistory("alice@wonderland").page().join().items.single().movementIndex)
        assertTrue(executor.requests.all { it.method == "POST" })
        assertEquals(listOf("/api/v1/subscriptions/plans/query", "/api/v1/subscriptions/query", "/api/v1/contracts/activity/query", "/api/v1/contracts/events/query", "/api/v1/accounts/alice@wonderland/history/query"), executor.requests.drop(2).map { it.uri.path })
    }

    @Test
    fun uaidManifestsCheckScopeAndRejectRetiredPages() {
        val uaid = "uaid:" + "ab".repeat(32)
        val executor = ScriptedExecutor()
        val client = client(executor)
        val row = """{"dataspace_id":7,"dataspace_alias":null,"manifest_hash":"${"ab".repeat(32)}","status":"Pending","lifecycle":{"activated_epoch":null,"expired_epoch":null,"revocation":null},"accounts":[],"manifest":{"version":1,"uaid":"$uaid","dataspace":7,"issued_ms":0,"activation_epoch":1,"entries":[]}}"""
        executor.reply(200, """{"items":[$row],"next_cursor":null}""")
        assertEquals(7L, client.uaidManifests(uaid).page().join().items.single().dataspaceId)
        assertEquals("/api/v1/space-directory/uaids/$uaid/manifests/query", executor.requests.last().uri.path)
        executor.reply(200, """{"items":[${row.replace(uaid, "uaid:" + "cd".repeat(32))}],"next_cursor":null}""")
        assertFailsWith<CompletionException> { client.uaidManifests(uaid).page().join() }
        for (body in listOf("""{"items":[],"has_more":false}""", """{"items":[]}""", """{"items":[],"next_cursor":""}""")) {
            executor.reply(200, body)
            assertFailsWith<CompletionException> { client.subscriptions.page().join() }
        }
    }

    @Test
    fun directAssetDefinitionHomesPreserveExactUnsignedIdentityAndPartialRows() {
        for (home in listOf("1", "9007199254740993", "8648377547929788715", "18446744073709551615")) {
            val row = AssetDefinitionRow(Json.parse("""{"id":"asset","owning_domain":null,"owning_dataspace":"$home"}""") as JsonObject)
            assertEquals(home, row.owningDataspace)
            assertNull(row.owningDomain)
        }
        for (body in listOf(
            """{"id":"asset"}""",
            """{"id":"asset","owning_domain":null,"owning_dataspace":null}""",
            """{"id":"asset","owning_domain":"treasury.bpng","owning_dataspace":null}""",
        )) {
            assertNull(AssetDefinitionRow(Json.parse(body) as JsonObject).owningDataspace)
        }
        val selected = AssetDefinitionRow(Json.parse("""{"id":"asset","owning_dataspace":"7"}""") as JsonObject)
        assertEquals("7", selected.owningDataspace)
        assertNull(selected.owningDomain, "selected rows retain optional field semantics")
    }

    @Test
    fun directAssetDefinitionHomesRejectNoncanonicalAndConflictingValues() {
        for (home in listOf("0", "00", "01", "18446744073709551616", "184467440737095516150", "", "+1", "-1", "1.0", "1e0", " 1", "1 ", "１")) {
            assertFailsWith<IllegalArgumentException>(home) {
                AssetDefinitionRow(Json.parse("""{"id":"asset","owning_dataspace":"$home"}""") as JsonObject)
            }
        }
        for (home in listOf("0", "7", "9007199254740992", "true", "{}", "[]")) {
            assertFailsWith<IllegalArgumentException>(home) {
                AssetDefinitionRow(Json.parse("""{"id":"asset","owning_dataspace":$home}""") as JsonObject)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            AssetDefinitionRow(Json.parse("""{"id":"asset","owning_domain":"treasury.bpng","owning_dataspace":"7"}""") as JsonObject)
        }
    }

    @Test
    fun pagePostsTheCanonicalBodyAndDecodesTypedRows() {
        val executor = ScriptedExecutor()
        executor.reply(
            200,
            """{"items":[
                {"id":"7ZepsJTHCVLKsrFFNZGSRGZgvBhv","name":"xor","alias":"xor#universal","owned_by":"alice@wonderland",
                 "owning_domain":"universal","mintable":"Infinitely","description":null,"logo":"sorafs://logo",
                 "spec":{"scale":9},"balance_scope_policy":"Global","future_field":[1,2],
                 "alias_binding":{"alias":"xor#universal","status":"active","lease_expiry_ms":1700000000000,"bound_at_ms":1690000000000},
                 "metadata":{"display-name":"XOR"}},
                {"id":"6TEAJqbb8oEPmLncoNiMRbLEK6tw","name":"ds","alias":null,"owned_by":"bob@wonderland",
                 "owning_domain":"boi","mintable":"Once"}
               ],"next_cursor":"q1_next","total":2}""",
        )
        val client = client(executor)
        val query = listQuery {
            filter((field("owned_by") eq "alice@wonderland") and (field("alias_binding.bound_at_ms") gt 1))
            sort("-alias_binding.bound_at_ms,id")
            limit(2)
            includeTotal()
        }

        val page = client.assetDefinitions.page(query).join()

        val request = executor.requests.single()
        assertEquals("POST", request.method)
        assertEquals(URI("https://torii.example/api/v1/assets/definitions/query"), request.uri)
        assertEquals(listOf("application/json"), request.headers["Content-Type"])
        assertEquals(listOf("application/json"), request.headers["Accept"])
        assertEquals(
            """{"filter":{"op":"and","args":[{"op":"eq","args":["owned_by","alice@wonderland"]},""" +
                """{"op":"gt","args":["alias_binding.bound_at_ms",1]}]},"sort":["-alias_binding.bound_at_ms","id"],""" +
                """"limit":2,"include_total":true}""",
            String(request.body, StandardCharsets.UTF_8),
        )
        assertFalse(request.headers.keys.any { it.equals(CanonicalRequestSigner.HEADER_ACCOUNT, ignoreCase = true) })
        assertEquals("q1_next", page.nextCursor)
        assertEquals(2L, page.total)
        val xor = page.items[0]
        assertEquals("7ZepsJTHCVLKsrFFNZGSRGZgvBhv", xor.id)
        assertEquals("xor#universal", xor.alias)
        assertEquals("Infinitely", xor.mintable)
        assertNull(xor.description)
        assertEquals("universal", xor.owningDomain)
        assertNull(xor.owningDataspace)
        assertEquals(Json.parse("""{"scale":9}"""), xor.spec)
        assertEquals("active", xor.aliasBinding!!.status)
        assertEquals(1_700_000_000_000L, xor.aliasBinding!!.leaseExpiryMs)
        assertNull(xor.aliasBinding!!.graceUntilMs)
        assertEquals(JsonString("XOR"), xor.metadata["display-name"])
        assertEquals(Json.parse("[1,2]"), xor.json["future_field"], "unknown members stay available")
        assertNull(page.items[1].alias)
        assertNull(page.items[1].aliasBinding)
        assertEquals(JsonObject.EMPTY, page.items[1].metadata)
    }

    @Test
    fun fetchAllFollowsCursorsIterativelyAndKeepsTheQuery() {
        val executor = ScriptedExecutor()
        val pages = 5_000
        repeat(pages) { index ->
            val next = if (index == pages - 1) "null" else "\"c${index + 1}\""
            executor.reply(200, """{"items":[{"id":"d$index","owned_by":"o@w"}],"next_cursor":$next}""")
        }
        val client = client(executor)
        val query = listQuery {
            filter(field("owned_by") eq "o@w")
            limit(1)
        }

        val all = client.domains.fetchAll(query).join()

        assertEquals(pages, all.size)
        assertEquals("d4999", all.last().id)
        assertEquals(pages, executor.requests.size)
        val third = Json.parse(executor.requests[2].body) as JsonObject
        assertEquals(JsonString("c2"), third["cursor"])
        assertEquals(query.withCursor("c2").toJson(), third)
    }

    @Test
    fun iterateIsLazySingleUseAndClosable() {
        val executor = ScriptedExecutor()
        executor.reply(200, """{"items":[{"id":"a","owned_by":"o@w"},{"id":"b","owned_by":"o@w"}],"next_cursor":"c1"}""")
        executor.reply(200, """{"items":[{"id":"c","owned_by":"o@w"},{"id":"d","owned_by":"o@w"}],"next_cursor":"c2"}""")
        val client = client(executor)

        val results = client.domains.iterate()
        val firstThree = results.asSequence().take(3).map { it.id }.toList()

        assertEquals(listOf("a", "b", "c"), firstThree)
        assertEquals(2, executor.requests.size, "the third page is never requested")
        assertFailsWith<IllegalStateException> { results.iterator() }
        results.close()

        val pages = client.domains.pages(ListQuery.builder().limit(2).build())
        executor.reply(200, """{"items":[{"id":"x","owned_by":"o@w"}],"next_cursor":null,"total":1}""")
        val only = pages.single()
        assertEquals(listOf("x"), only.items.map { it.id })
        assertFalse(only.hasMore())
    }

    @Test
    fun closeCancelsTheRequestInFlight() {
        val pending = CompletableFuture<TransportResponse>()
        val executor = object : HttpTransportExecutor {
            override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> = pending
        }
        val client = HttpClientTransport(executor, config())
        val results = client.domains.iterate()
        val started = CountDownLatch(1)
        val outcome = CompletableFuture<Boolean>()
        val reader = Thread {
            started.countDown()
            try {
                outcome.complete(results.iterator().hasNext())
            } catch (error: Throwable) {
                outcome.completeExceptionally(error)
            }
        }
        reader.start()
        started.await()
        Thread.sleep(100)
        results.close()

        assertEquals(false, outcome.get(5, TimeUnit.SECONDS), "closing ends the iteration")
        assertTrue(pending.isCancelled, "the in-flight request is cancelled")
        reader.join(5_000)
    }

    @Test
    fun cancellingFetchAllCancelsTheRequestInFlight() {
        val pending = CompletableFuture<TransportResponse>()
        val executor = object : HttpTransportExecutor {
            override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> = pending
        }
        val all = HttpClientTransport(executor, config()).nfts.fetchAll()
        assertTrue(all.cancel(true))
        assertTrue(pending.isCancelled)
    }

    @Test
    fun errorEnvelopesBecomeTypedExceptions() {
        val executor = ScriptedExecutor()
        executor.reply(
            400,
            """{"code":"invalid_filter","message":"invalid `filter`: use the keyword `and` instead of `&` or `&&` (column 17)",""" +
                """"details":{"field":"filter","hint":"write `and`","expected":"and","actual":"&&"}}""",
            mapOf("x-iroha-reject-code" to listOf("query_rejected")),
        )
        executor.reply(503, "upstream unavailable")
        val client = client(executor)

        val failure = assertFailsWith<CompletionException> {
            client.accounts.page(ListQuery.builder().filter("owned_by == \"x\" && quantity > 1").build()).join()
        }
        val error = assertIs<ToriiApiException>(failure.cause)
        assertEquals(400, error.status)
        assertEquals("invalid_filter", error.code)
        assertEquals("invalid `filter`: use the keyword `and` instead of `&` or `&&` (column 17)", error.message)
        assertEquals("filter", error.field)
        assertEquals("write `and`", error.hint)
        assertEquals("&&", error.actual)
        assertEquals(listOf("and"), error.expected)
        assertEquals("query_rejected", error.rejectCode)
        val body = Json.parse(executor.requests.single().body) as JsonObject
        assertEquals(JsonString("owned_by == \"x\" && quantity > 1"), body["filter"], "text filters pass through")

        val unavailable = assertFailsWith<ToriiApiException> { client.accounts.iterate().iterator().hasNext() }
        assertEquals(503, unavailable.status)
        assertNull(unavailable.code)
        assertEquals("upstream unavailable", unavailable.message)
    }

    @Test
    fun malformedResponsesAreProtocolErrors() {
        val cases = listOf(
            "not json",
            """{"next_cursor":null}""",
            """{"items":[1],"next_cursor":null}""",
            """{"items":[{"owned_by":"o@w"}],"next_cursor":null}""",
            """{"items":[{"id":7}],"next_cursor":null}""",
            """{"items":[],"next_cursor":7}""",
            """{"items":[],"next_cursor":null,"total":-1}""",
        )
        for (body in cases) {
            val executor = ScriptedExecutor()
            executor.reply(200, body)
            val failure = assertFailsWith<CompletionException>(body) { client(executor).nfts.page().join() }
            val error = assertIs<ToriiProtocolException>(failure.cause, body)
            assertEquals(ToriiProtocolException.CODE, error.code)
        }
        val stuck = ScriptedExecutor()
        stuck.reply(200, """{"items":[],"next_cursor":"same"}""")
        stuck.reply(200, """{"items":[],"next_cursor":"same"}""")
        val failure = assertFailsWith<CompletionException> { client(stuck).nfts.fetchAll().join() }
        assertIs<ToriiProtocolException>(failure.cause)
    }

    @Test
    fun typedRowsNeedCompleteItemsAndJsonRowsTakeProjections() {
        val executor = ScriptedExecutor()
        executor.reply(200, """{"items":[{"id":"a"}],"next_cursor":null}""")
        executor.reply(200, """{"items":[{"asset":"xor","holders":12,"supply":"10.5"}],"next_cursor":null}""")
        val client = client(executor)
        val projection = ListQuery.builder().select("id").build()
        assertFailsWith<IllegalArgumentException> { client.domains.page(projection) }

        val rows = client.domains.json().page(projection).join().items
        assertEquals(listOf(Json.parse("""{"id":"a"}""")), rows)

        val aggregate = listQuery {
            filter(field("quantity") gt 0)
            aggregate(
                AggregateSpec.builder()
                    .groupBy("asset")
                    .metric(AggregateMetric.count("holders"))
                    .metric(AggregateMetric.sum("supply", "quantity"))
                    .having(field("holders") gte 10)
                    .build(),
            )
            sort("-supply")
            limit(20)
        }
        val grouped = client.assetHolders("7ZepsJTHCVLKsrFFNZGSRGZgvBhv").json().page(aggregate).join()
        assertEquals("12", (grouped.items.single()["holders"] as org.hyperledger.iroha.sdk.json.JsonNumber).text)
        assertEquals(
            """{"filter":{"op":"gt","args":["quantity",0]},"sort":["-supply"],"aggregate":{"group_by":["asset"],""" +
                """"metrics":[{"alias":"holders","fn":"count"},{"alias":"supply","fn":"sum","field":"quantity"}],""" +
                """"having":{"op":"gte","args":["holders",10]}},"limit":20}""",
            String(executor.requests[1].body, StandardCharsets.UTF_8),
        )
        assertEquals("/api/v1/assets/7ZepsJTHCVLKsrFFNZGSRGZgvBhv/holders/query", executor.requests[1].uri.rawPath)
    }

    @Test
    fun everyCollectionUsesItsContractPath() {
        val executor = ScriptedExecutor()
        repeat(10) { executor.reply(200, """{"items":[],"next_cursor":null}""") }
        val client = client(executor)
        val account = "sorauﾛ1PaQ@x"
        client.domains.page().join()
        client.accounts.page().join()
        client.assetDefinitions.page().join()
        client.nfts.page().join()
        client.rwas.page().join()
        client.repoAgreements.page().join()
        client.accountAssets(account).page().join()
        client.assetHolders("6TEAJqbb8oEPmLncoNiMRbLEK6tw").page().join()
        client.accountTransactions(account).page().join()
        client.transactions.page().join()
        assertEquals(
            listOf(
                "/api/v1/domains/query",
                "/api/v1/accounts/query",
                "/api/v1/assets/definitions/query",
                "/api/v1/nfts/query",
                "/api/v1/rwas/query",
                "/api/v1/repo/agreements/query",
                "/api/v1/accounts/sorau%EF%BE%9B1PaQ%40x/assets/query",
                "/api/v1/assets/6TEAJqbb8oEPmLncoNiMRbLEK6tw/holders/query",
                "/api/v1/accounts/sorau%EF%BE%9B1PaQ%40x/transactions/query",
                "/api/v1/transactions/query",
            ),
            executor.requests.map { it.uri.rawPath },
        )
        executor.requests.forEach { assertEquals("{}", String(it.body, StandardCharsets.UTF_8)) }
        assertFailsWith<IllegalArgumentException> { client.accountAssets(" padded") }
    }

    @Test
    fun rowsDecodeExactQuantitiesAndRequiredFields() {
        val executor = ScriptedExecutor()
        executor.reply(
            200,
            """{"items":[{"asset":"xor","asset_name":"XOR","asset_alias":null,"scope":"global","account_id":"a@w",""" +
                """"quantity":"123456789012345678901234567890.000000001"}],"next_cursor":null}""",
        )
        executor.reply(
            200,
            """{"items":[{"entrypoint_hash":"ab","block_height":12,"block_index":3,"block_hash":"cd","authority":null,""" +
                """"timestamp_ms":1700000000123,"entrypoint_kind":"external","result_ok":false,""" +
                """"asset_ids":["xor##a@w","ds##a@w"],"asset_definition_ids":["xor"],"metadata":{"memo":"x"}}],"next_cursor":null}""",
        )
        executor.reply(
            200,
            """{"items":[{"id":"repo-1","initiator":"a@w","counterparty":"b@w","status":"active",""" +
                """"cash_leg":{"asset_definition_id":"xor","quantity":"100"},"rate_bps":250,""" +
                """"governance":{"haircut_bps":500}}],"next_cursor":null}""",
        )
        val client = client(executor)
        val balance = client.accountAssets("a@w").page().join().items.single()
        assertEquals(BigDecimal("123456789012345678901234567890.000000001"), balance.quantity)
        assertEquals("global", balance.scope)
        val transaction = client.accountTransactions("a@w").page().join().items.single()
        assertEquals("ab", transaction.entrypointHash)
        assertEquals(12L, transaction.blockHeight)
        assertEquals(3L, transaction.blockIndex)
        assertEquals("cd", transaction.blockHash)
        assertNull(transaction.authority)
        assertEquals(1_700_000_000_123L, transaction.timestampMs)
        assertEquals(false, transaction.resultOk)
        assertEquals(listOf("xor##a@w", "ds##a@w"), transaction.assetIds)
        assertEquals(listOf("xor"), transaction.assetDefinitionIds)
        assertEquals(JsonString("x"), transaction.metadata["memo"])
        val repo = client.repoAgreements.page().join().items.single()
        assertEquals(BigDecimal("100"), repo.cashLeg!!.quantity)
        assertEquals(250L, repo.rateBps)
        assertEquals(500L, repo.governance!!.haircutBps)
        assertNull(repo.collateralLeg)
    }

    @Test
    fun historyCollectionsFollowShortAndEmptyPages() {
        val executor = ScriptedExecutor()
        executor.reply(200, """{"items":[],"next_cursor":"h1"}""")
        executor.reply(200, """{"items":[{"entrypoint_hash":"t1","block_height":1500,"block_index":0}],"next_cursor":"h2"}""")
        executor.reply(200, """{"items":[],"next_cursor":null}""")
        executor.reply(200, """{"items":[],"next_cursor":"h1"}""")
        executor.reply(200, """{"items":[{"entrypoint_hash":"t1","block_height":1500,"block_index":0}],"next_cursor":"h2"}""")
        executor.reply(200, """{"items":[],"next_cursor":null}""")
        val client = client(executor)
        val query = listQuery {
            filter((field("block_height") gte 1200) and (field("asset_definition_ids") eq "xor"))
            limit(100)
        }

        val all = client.transactions.fetchAll(query).join()
        assertEquals(listOf("t1"), all.map { it.entrypointHash })
        assertEquals(3, executor.requests.size, "empty and short pages with a cursor do not end the read")
        val iterated = client.transactions.iterate(query).use { rows -> rows.map { it.blockHeight } }
        assertEquals(listOf(1500L), iterated)
        assertEquals(6, executor.requests.size)
        assertEquals(JsonString("h2"), (Json.parse(executor.requests[2].body) as JsonObject)["cursor"])

        val missing = ScriptedExecutor()
        missing.reply(200, """{"items":[{"entrypoint_hash":"t1","block_height":1500}],"next_cursor":null}""")
        val failure = assertFailsWith<CompletionException> { client(missing).transactions.page().join() }
        assertIs<ToriiProtocolException>(failure.cause, "block_index is an identity field")
    }

    @Test
    fun historyCollectionsRejectSortTotalAndAggregate() {
        val executor = ScriptedExecutor()
        val client = client(executor)
        val aggregate = AggregateSpec.builder().metric(AggregateMetric.count("n")).build()
        val cases = listOf(
            ListQuery.builder().sort("-block_height").build() to "invalid_sort",
            ListQuery.builder().includeTotal().build() to "invalid_include_total",
            ListQuery.builder().aggregate(aggregate).build() to "invalid_aggregate",
        )
        for ((query, code) in cases) {
            for (collection in listOf(client.transactions.json(), client.accountTransactions("a@w").json())) {
                val error = assertFailsWith<ListQueryException>(code) { collection.page(query) }
                assertEquals(code, error.code)
            }
            assertEquals(code, assertFailsWith<ListQueryException> { client.transactions.fetchAll(query) }.code)
        }
        assertTrue(executor.requests.isEmpty(), "nothing is sent")
        client.domains.json().page(ListQuery.builder().sort("-id").includeTotal().build())
    }

    @Test
    fun clientWideCanonicalAuthSignsEveryPageWithFreshNonces() {
        val keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val executor = ScriptedExecutor()
        executor.reply(200, """{"items":[{"id":"a","owned_by":"o@w"}],"next_cursor":"c1"}""")
        executor.reply(200, """{"items":[{"id":"b","owned_by":"o@w"}],"next_cursor":null}""")
        val client = HttpClientTransport(
            executor,
            config().toBuilder()
                .setCanonicalAuth(ToriiCanonicalRequestAuth("alice@wonderland", RequestSigner.ed25519(keys.private)))
                .build(),
        )

        assertEquals(listOf("a", "b"), client.domains.fetchAll().join().map { it.id })

        val nonces = executor.requests.map { it.headers.getValue(CanonicalRequestSigner.HEADER_NONCE).single() }
        assertEquals(2, nonces.toSet().size)
        executor.requests.forEach {
            assertEquals(listOf("alice@wonderland"), it.headers[CanonicalRequestSigner.HEADER_ACCOUNT])
            assertTrue(it.headers.containsKey(CanonicalRequestSigner.HEADER_SIGNATURE))
        }
        assertFailsWith<IllegalArgumentException> {
            config().toBuilder().setCanonicalAuth(
                ToriiCanonicalRequestAuth("alice@wonderland", RequestSigner.ed25519(keys.private), 1L, "fixed"),
            )
        }
        assertFailsWith<IllegalStateException> {
            ClientConfig.builder()
                .setCanonicalAuth(ToriiCanonicalRequestAuth("alice@wonderland", RequestSigner.ed25519(keys.private)))
                .build()
        }
    }

    @Test
    fun signedPlaintextRequestsNeedTheLoopbackOptIn() {
        val keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val auth = ToriiCanonicalRequestAuth("alice@wonderland", RequestSigner.ed25519(keys.private))
        fun clientFor(base: String, optIn: Boolean, executor: ScriptedExecutor) = HttpClientTransport(
            executor,
            ClientConfig.builder()
                .setBaseUri(URI(base))
                .setLocalSigningContext(LocalSigningContext(TestNetworkIds.canonical()))
                .setCanonicalAuth(auth)
                .setAllowPlaintextLoopback(optIn)
                .build(),
        )
        val refused = ScriptedExecutor()
        val strict = assertFailsWith<CompletionException> { clientFor("http://127.0.0.1:8080", false, refused).domains.page().join() }
        assertIs<IllegalArgumentException>(strict.cause)
        assertTrue(refused.requests.isEmpty())

        for (loopback in listOf("http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080")) {
            val allowed = ScriptedExecutor()
            allowed.reply(200, """{"items":[],"next_cursor":null}""")
            clientFor(loopback, true, allowed).domains.page().join()
            assertEquals(1, allowed.requests.size, loopback)
        }

        val remote = ScriptedExecutor()
        val remoteFailure = assertFailsWith<CompletionException> {
            clientFor("http://torii.example", true, remote).domains.page().join()
        }
        assertIs<IllegalArgumentException>(remoteFailure.cause)
        assertTrue(remote.requests.isEmpty())
    }

    @Test
    fun signedViewsRequirePerRequestFreshness() {
        val keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val executor = ScriptedExecutor()
        executor.reply(200, """{"items":[],"next_cursor":null}""")
        val client = client(executor)
        client.domains.signedBy(ToriiCanonicalRequestAuth("bob@wonderland", RequestSigner.ed25519(keys.private))).page().join()
        assertEquals(listOf("bob@wonderland"), executor.requests.single().headers[CanonicalRequestSigner.HEADER_ACCOUNT])
        assertFailsWith<IllegalArgumentException> {
            client.domains.signedBy(ToriiCanonicalRequestAuth("bob@wonderland", RequestSigner.ed25519(keys.private), 1L, "n"))
        }
        assertNotEquals(client.domains.toString(), client.accounts.toString())
    }

    private fun config(): ClientConfig = ClientConfig.builder()
        .setBaseUri(URI("https://torii.example/api"))
        .setLocalSigningContext(LocalSigningContext(TestNetworkIds.canonical()))
        .build()

    private fun client(executor: HttpTransportExecutor): HttpClientTransport = HttpClientTransport(executor, config())

    /** Answers requests synchronously from a queue of scripted responses. */
    private class ScriptedExecutor : HttpTransportExecutor {
        val requests = ArrayList<TransportRequest>()
        private val responses = ArrayDeque<TransportResponse>()

        fun reply(status: Int, body: String, headers: Map<String, List<String>> = emptyMap()) {
            responses.addLast(
                TransportResponse.builder()
                    .setStatusCode(status)
                    .setBody(body.toByteArray(StandardCharsets.UTF_8))
                    .setHeaders(headers + ("Content-Type" to listOf("application/json")))
                    .build(),
            )
        }

        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            requests.add(request)
            val response = responses.removeFirstOrNull()
                ?: return CompletableFuture<TransportResponse>().also {
                    it.completeExceptionally(CancellationException("no scripted response"))
                }
            return CompletableFuture.completedFuture(response)
        }
    }
}
