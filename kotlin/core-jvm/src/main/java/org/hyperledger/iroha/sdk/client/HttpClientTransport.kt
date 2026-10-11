package org.hyperledger.iroha.sdk.client

import java.math.BigInteger
import org.hyperledger.iroha.sdk.client.transport.OkHttpTransportExecutor
import org.hyperledger.iroha.sdk.client.transport.HttpTransportScope
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import java.util.LinkedHashMap
import java.util.Optional
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.function.Function
import org.hyperledger.iroha.sdk.address.requireCanonicalI105Address
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.address.algorithmForCurveId
import org.hyperledger.iroha.sdk.crypto.Blake3
import org.hyperledger.iroha.sdk.crypto.Ed25519PublicKeyAdmission
import org.hyperledger.iroha.sdk.crypto.IrohaHash
import org.hyperledger.iroha.sdk.crypto.NativeSignerBridge
import org.hyperledger.iroha.sdk.crypto.SigningAlgorithm
import org.hyperledger.iroha.sdk.consensus.SUMERAGI_LANES_JSON_MAX_BYTES
import org.hyperledger.iroha.sdk.consensus.SUMERAGI_STATUS_JSON_MAX_BYTES
import org.hyperledger.iroha.sdk.consensus.SumeragiLaneStatus
import org.hyperledger.iroha.sdk.consensus.SumeragiStatus
import org.hyperledger.iroha.sdk.nexus.*
import org.hyperledger.iroha.sdk.privacy.PrivacyExact12CapabilityAdmissionV1
import org.hyperledger.iroha.sdk.privacy.PrivacyExact12CapabilityManifestV1
import org.hyperledger.iroha.sdk.privacy.PrivacyExact12CapabilityTupleAdmissionV1
import org.hyperledger.iroha.sdk.privacy.PrivacyNativeBridge
import org.hyperledger.iroha.sdk.privacy.PrivacyProtocolIdV1
import org.hyperledger.iroha.sdk.sorafs.GatewayFetchRequest
import org.hyperledger.iroha.sdk.sorafs.GatewayFetchSummary
import org.hyperledger.iroha.sdk.sorafs.SorafsGatewayClient
import org.hyperledger.iroha.sdk.telemetry.*
import org.hyperledger.iroha.sdk.client.stream.ToriiEventStreamClient
import org.hyperledger.iroha.sdk.tx.SignedTransaction
import org.hyperledger.iroha.sdk.tx.SignedTransactionHasher
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.core.model.zk.VerifyingKeyBackendTag
import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent
import org.hyperledger.iroha.sdk.core.model.FeeSponsorProgramId
import org.hyperledger.iroha.sdk.core.model.Executable
import org.hyperledger.iroha.sdk.core.model.JsonValue
import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.hyperledger.iroha.sdk.core.model.instructions.GovernanceInstructionUtils
import org.hyperledger.iroha.sdk.tx.norito.NoritoJavaCodecAdapter
import org.hyperledger.iroha.sdk.alias.AliasSetupPlanRequestV1
import org.hyperledger.iroha.sdk.alias.AliasAutoRenewPlanRequestV1
import org.hyperledger.iroha.sdk.alias.AliasLeaseRenewPlanRequestV1
import org.hyperledger.iroha.sdk.alias.AliasLifecycleTransactionPlanJsonParser
import org.hyperledger.iroha.sdk.alias.AliasLifecycleTransactionPlanV1
import org.hyperledger.iroha.sdk.alias.AccountOnboardingJsonParser
import org.hyperledger.iroha.sdk.alias.AccountOnboardingPlanReceiptV1
import org.hyperledger.iroha.sdk.alias.AccountOnboardingPlanRequestV1
import org.hyperledger.iroha.sdk.alias.AccountOnboardingPrepareRequestV1
import org.hyperledger.iroha.sdk.alias.AccountOnboardingPrepareResponseV1
import org.hyperledger.iroha.sdk.alias.AccountOnboardingPreparedTransactionV1
import org.hyperledger.iroha.sdk.alias.AccountOnboardingProofRequiredPrepareResponseV1
import org.hyperledger.iroha.sdk.alias.AccountOnboardingCurrentStateRequestV1
import org.hyperledger.iroha.sdk.alias.AccountOnboardingCurrentStateV1
import org.hyperledger.iroha.sdk.alias.AccountFaucetClaimV1
import org.hyperledger.iroha.sdk.alias.AccountFaucetPolicyV1
import org.hyperledger.iroha.sdk.alias.AccountFaucetPrepareRequestV1
import org.hyperledger.iroha.sdk.alias.AccountFaucetPreparedTransactionV1
import org.hyperledger.iroha.sdk.alias.AccountFaucetPreparedVerifier
import org.hyperledger.iroha.sdk.alias.AccountOnboardingPreparedVerifier
import org.hyperledger.iroha.sdk.alias.AccountOnboardingReceiptVerifier
import org.hyperledger.iroha.sdk.alias.AliasSetupReportV1
import org.hyperledger.iroha.sdk.alias.PreparedTransactionSubmitResponseV1
import org.hyperledger.iroha.sdk.alias.PreparedOperationBindingV1
import org.hyperledger.iroha.sdk.alias.requireOnboardingCredential
import org.hyperledger.iroha.sdk.alias.AliasTransactionPlanJsonParser
import org.hyperledger.iroha.sdk.alias.AliasTransactionPlanV1
import org.hyperledger.iroha.sdk.alias.AccountAliasName
import org.hyperledger.iroha.sdk.client.collections.AccountAssetRow
import org.hyperledger.iroha.sdk.client.collections.AccountHistoryRow
import org.hyperledger.iroha.sdk.client.collections.AccountRow
import org.hyperledger.iroha.sdk.client.collections.AccountPermissionRow
import org.hyperledger.iroha.sdk.client.collections.SubscriptionPlanRow
import org.hyperledger.iroha.sdk.client.collections.SubscriptionRow
import org.hyperledger.iroha.sdk.client.collections.ContractActivityRow
import org.hyperledger.iroha.sdk.client.collections.ContractEventRow
import org.hyperledger.iroha.sdk.client.collections.AssetDefinitionRow
import org.hyperledger.iroha.sdk.client.collections.AssetHolderRow
import org.hyperledger.iroha.sdk.client.collections.CollectionQueryTransport
import org.hyperledger.iroha.sdk.client.collections.DomainRow
import org.hyperledger.iroha.sdk.client.collections.NftRow
import org.hyperledger.iroha.sdk.client.collections.RepoAgreementRow
import org.hyperledger.iroha.sdk.client.collections.RwaLotRow
import org.hyperledger.iroha.sdk.client.collections.ToriiCollection
import org.hyperledger.iroha.sdk.client.collections.TransactionRow

/**
 * HTTP client for one Iroha Torii endpoint.
 *
 * Transactions are submitted through `/v1/pipeline/transactions`. The Torii collections
 * ([domains], [accounts], [assetDefinitions], [nfts], [rwas], [repoAgreements], [accountAssets],
 * [assetHolders], [transactions] and [accountTransactions]) are read with
 * [org.hyperledger.iroha.sdk.query.ListQuery] through `POST <collection>/query`; see
 * [ToriiCollection]. Network execution is delegated to [HttpTransportExecutor] so tests can run
 * without making outbound calls.
 */
class HttpClientTransport private constructor(
    private val executor: HttpTransportScope,
    private val config: ClientConfig
) : IrohaClient, AutoCloseable {
    /** Borrows an executor; closing this client cancels only calls admitted by this client. */
    constructor(executor: HttpTransportExecutor, config: ClientConfig) :
        this(HttpTransportScope.create(executor), config)


    private val sorafsGatewayClient: SorafsGatewayClient by lazy {
        SorafsGatewayClient(
            baseUri = config.sorafsGatewayUri(),
            executor = executor,
            timeout = config.requestTimeout(),
            defaultHeaders = config.defaultHeaders(),
            observers = config.observers(),
        )
    }
    private val deviceProfileEmitted = AtomicBoolean(false)
    private val lifecycleLock = Any()
    private var closed = false
    private val pendingPolls = LinkedHashSet<CompletableFuture<Map<String, Any>>>()
    private val lazyScheduler = lazy {
        Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "iroha-http-pipeline-poll").apply { isDaemon = true }
        }
    }
    private val scheduler: ScheduledExecutorService by lazyScheduler

    override fun submitTransaction(transaction: SignedTransaction): CompletableFuture<ClientResponse> {
        val hashHex = SignedTransactionHasher.hashHex(transaction)
        return submitOnce(transaction, hashHex)
    }

    override fun submitTransactionJson(encodedVersionedTransactionJson: ByteArray): CompletableFuture<ClientResponse> {
        val request = ToriiRequestBuilder.buildSubmitJsonRequest(
            config.baseUri(),
            encodedVersionedTransactionJson,
            config.requestTimeout(),
            config.defaultHeaders(),
            config.wireFormatPreference().acceptHeader(),
            config.allowPlaintextLoopback(),
        )
        return ensureTransactionSubmissionCompatibility()
            .thenCompose { executeAccepted(request, "transaction JSON submit", 202) }
    }

    override fun submitTransactionEntrypoint(encodedVersionedEntrypoint: ByteArray): CompletableFuture<ClientResponse> {
        val request = ToriiRequestBuilder.buildSubmitEntrypointRequest(
            config.baseUri(),
            encodedVersionedEntrypoint,
            config.requestTimeout(),
            config.defaultHeaders(),
            config.wireFormatPreference().acceptHeader(),
            config.allowPlaintextLoopback(),
        )
        return ensureTransactionSubmissionCompatibility().thenCompose {
            notifyRequest(request)
            executor.execute(request).handle { response, throwable ->
                if (throwable != null) {
                    val cause = unwrapCompletion(throwable)
                    notifyFailure(request, cause)
                    val failed = CompletableFuture<ClientResponse>()
                    failed.completeExceptionally(cause)
                    return@handle failed
                }
                val statusCode = response.statusCode
                if (statusCode != 202) {
                    val error = ToriiApiException.fromResponse(
                        statusCode,
                        response.headers,
                        response.body,
                        "transaction entrypoint submit",
                    )
                    notifyFailure(request, error)
                    return@handle CompletableFuture<ClientResponse>().also {
                        it.completeExceptionally(error)
                    }
                }
                val clientResponse = ClientResponse(
                    statusCode,
                    response.body,
                    response.message,
                    extractEntrypointHash(response),
                    extractRejectCode(response),
                )
                notifyResponse(request, clientResponse)
                CompletableFuture.completedFuture(clientResponse)
            }.thenCompose { it }
        }
    }

    /**
     * Execute one wallet-signed, nonce-bearing native selective query. The caller
     * must create [signedQuery] with [CommittedTransactionInclusionBridge] and
     * verify its returned row against independently pinned finality before use.
     * This POST is one-shot: transport retries and redirects are forbidden.
     */
    fun postSignedCommittedTransactionQuery(signedQuery: ByteArray): CompletableFuture<ByteArray> {
        require(signedQuery.isNotEmpty() && signedQuery.size <= 16 * 1024) {
            "signed committed-transaction query exceeds its native bound"
        }
        require(config.baseUri().scheme.equals("https", ignoreCase = true)) {
            "signed committed-transaction query requires HTTPS"
        }
        val ownedHeaders = listOf("Accept", "Content-Type", "Accept-Encoding", "Content-Encoding", "Cache-Control")
        require(config.defaultHeaders().keys.none { candidate ->
            ownedHeaders.any { it.equals(candidate, ignoreCase = true) }
        }) { "selective query transport headers must not be overridden" }
        requireCanonicalHeadersUnset()
        val target = resolvePath("/v1/query")
        val request = TransportRequest.builder()
            .setUri(target)
            .setMethod("POST")
            .setBody(signedQuery.copyOf())
            .addHeader("Content-Type", APPLICATION_NORITO)
            .addHeader("Accept", APPLICATION_NORITO)
            .addHeader("Accept-Encoding", "identity")
            .addHeader("Cache-Control", "no-store")
            .setMaximumResponseBytes(32L * 1024 * 1024)
            .setTimeout(config.requestTimeout())
            .apply {
                for ((name, value) in config.defaultHeaders()) addHeader(name, value)
            }
            .build()
        TransportSecurity.requireHttpRequestAllowed(
            "signed committed-transaction query", config.baseUri(), target,
            config.defaultHeaders(), signedQuery,
        )
        return fetchExactNoritoBytes(
            request, "signed committed-transaction query",
            requireIdentityEncoding = true,
            forbidRejectCodeHeader = true,
            allowExplicitIdentityEncoding = true,
            requireExactResponseProvenance = true,
        )
    }

    /**
     * Fetch one untrusted bridge bundle for a checkpoint-inclusive, consecutive
     * finality scan. The caller must bound the whole chain to 4096 bundles and
     * 16 MiB, locate the candidate hash, then invoke the native verifier.
     */
    fun getBridgeFinalityBundleJson(height: Long): CompletableFuture<ByteArray> {
        require(height > 0) { "bridge finality height must be positive" }
        require(config.baseUri().scheme.equals("https", ignoreCase = true)) {
            "bridge finality bundle fetch requires HTTPS"
        }
        val ownedHeaders = listOf("Accept", "Accept-Encoding", "Cache-Control")
        require(config.defaultHeaders().keys.none { candidate ->
            ownedHeaders.any { it.equals(candidate, ignoreCase = true) }
        }) { "bridge finality transport headers must not be overridden" }
        requireCanonicalHeadersUnset()
        val request = TransportRequest.builder()
            .setUri(resolvePath("/v1/bridge/finality/bundle/$height"))
            .setMethod("GET")
            .addHeader("Accept", "application/json")
            .addHeader("Accept-Encoding", "identity")
            .addHeader("Cache-Control", "no-store")
            .setMaximumResponseBytes(4L * 1024 * 1024)
            .setTimeout(config.requestTimeout())
            .apply { for ((name, value) in config.defaultHeaders()) addHeader(name, value) }
            .build()
        return executeResponse(request, "bridge finality bundle") { response ->
            requireExactSignedResponseProvenance(request, response, "bridge finality bundle")
            requireExactJsonResponse(response, "bridge finality bundle")
            requireAbsentOrIdentityEncoding(response.headers, "bridge finality bundle")
            val body = response.body
            require(body.isNotEmpty() && body.size.toLong() <= requireNotNull(request.maximumResponseBytes)) {
                "bridge finality bundle exceeds its response bound"
            }
            requireExactOptionalContentLength(response.headers, body.size, "bridge finality bundle")
            notifyResponse(request, ClientResponse(response.statusCode, body, response.message, null, extractRejectCode(response)))
            body.copyOf()
        }
    }

    override fun submitTransactionEntrypointJson(encodedVersionedEntrypointJson: ByteArray): CompletableFuture<ClientResponse> {
        val request = ToriiRequestBuilder.buildSubmitEntrypointJsonRequest(
            config.baseUri(),
            encodedVersionedEntrypointJson,
            config.requestTimeout(),
            config.defaultHeaders(),
            config.wireFormatPreference().acceptHeader(),
            config.allowPlaintextLoopback(),
        )
        return ensureTransactionSubmissionCompatibility()
            .thenCompose { executeAccepted(request, "transaction entrypoint JSON submit", 202) }
    }

    override fun waitForTransactionStatus(hashHex: String, options: PipelineStatusOptions?): CompletableFuture<Map<String, Any>> {
        ToriiRequestBuilder.requireTransactionHash(hashHex)
        val resolved = PipelineStatusOptions.resolve(options)
        val timeoutMillis = resolved.timeoutMillis
        val deadline = if (timeoutMillis == null) {
            Long.MAX_VALUE
        } else {
            val now = System.currentTimeMillis()
            if (timeoutMillis > Long.MAX_VALUE - now) Long.MAX_VALUE else now + timeoutMillis
        }
        val future = CompletableFuture<Map<String, Any>>()
        synchronized(lifecycleLock) {
            if (closed) {
                future.completeExceptionally(IllegalStateException("HTTP client is closed"))
                return future
            }
            pendingPolls.add(future)
        }
        future.whenComplete { _, _ -> synchronized(lifecycleLock) { pendingPolls.remove(future) } }
        pollPipelineStatus(hashHex, resolved, deadline, 0, null, future)
        return future
    }

    fun config(): ClientConfig = config

    private val collectionTransport = CollectionQueryTransport(::queryCollection)

    /** Domains (`/v1/domains`), default order `id`. */
    @get:JvmName("domains")
    val domains: ToriiCollection<DomainRow> = collection("/v1/domains", ::DomainRow)

    /** Accounts (`/v1/accounts`), default order `id`. */
    @get:JvmName("accounts")
    val accounts: ToriiCollection<AccountRow> = collection("/v1/accounts", ::AccountRow)

    /** Asset definitions (`/v1/assets/definitions`), default order `id`. */
    @get:JvmName("assetDefinitions")
    val assetDefinitions: ToriiCollection<AssetDefinitionRow> =
        collection("/v1/assets/definitions", ::AssetDefinitionRow)

    /** NFTs (`/v1/nfts`), default order `id`. */
    @get:JvmName("nfts")
    val nfts: ToriiCollection<NftRow> = collection("/v1/nfts", ::NftRow)

    /** Real-world-asset lots (`/v1/rwas`), default order `id`. */
    @get:JvmName("rwas")
    val rwas: ToriiCollection<RwaLotRow> = collection("/v1/rwas", ::RwaLotRow)

    /** Repo agreements (`/v1/repo/agreements`), default order `id`. */
    @get:JvmName("repoAgreements")
    val repoAgreements: ToriiCollection<RepoAgreementRow> = collection("/v1/repo/agreements", ::RepoAgreementRow)

    /** Effective direct and role-granted permissions for the account. */
    fun accountPermissions(accountId: String): ToriiCollection<AccountPermissionRow> =
        collection("/v1/accounts/${collectionPathSegment(accountId, "accountId")}/permissions", ::AccountPermissionRow)

    /** Subscription plans, ordered by id. */
    @get:JvmName("subscriptionPlans")
    val subscriptionPlans: ToriiCollection<SubscriptionPlanRow> = collection("/v1/subscriptions/plans", ::SubscriptionPlanRow)

    /** Flattened subscriptions, ordered by id. */
    @get:JvmName("subscriptions")
    val subscriptions: ToriiCollection<SubscriptionRow> = collection("/v1/subscriptions", ::SubscriptionRow)

    /** Space-directory manifests for one canonical UAID. */
    fun uaidManifests(uaid: String): ToriiCollection<UaidManifestRecord> {
        val canonical = UaidLiteral.canonicalize(uaid, "uaid manifests")
        return collection("/v1/space-directory/uaids/${encodePathSegment(canonical)}/manifests", {
            UaidJsonParser.parseManifestRecord(it.toJsonBytes(), canonical)
        })
    }

    /** Contract transaction history, newest first; sort, aggregate and include_total are unsupported. */
    @get:JvmName("contractActivity")
    val contractActivity: ToriiCollection<ContractActivityRow> = collection("/v1/contracts/activity", ::ContractActivityRow, history = true)

    /** Contract event history, newest first; sort, aggregate and include_total are unsupported. */
    @get:JvmName("contractEvents")
    val contractEvents: ToriiCollection<ContractEventRow> = collection("/v1/contracts/events", ::ContractEventRow, history = true)

    /**
     * Balances of [accountId] (`/v1/accounts/{account_id}/assets`), default order `asset`, `scope`.
     * [accountId] is a canonical I105 literal or an on-chain alias.
     */
    fun accountAssets(accountId: String): ToriiCollection<AccountAssetRow> =
        collection("/v1/accounts/${collectionPathSegment(accountId, "accountId")}/assets", ::AccountAssetRow)

    /** Holders of [assetDefinitionId] (`/v1/assets/{definition_id}/holders`), default order `account_id`, `scope`. */
    fun assetHolders(assetDefinitionId: String): ToriiCollection<AssetHolderRow> =
        collection(
            "/v1/assets/${collectionPathSegment(assetDefinitionId, "assetDefinitionId")}/holders",
            ::AssetHolderRow,
        )

    /**
     * Every committed transaction (`POST /v1/transactions/query`), a history collection read
     * newest first by (`block_height`, `block_index`). `sort`, `include_total` and `aggregate`
     * are rejected; a page may hold fewer than `limit` rows and still have a `next_cursor`.
     */
    @get:JvmName("transactions")
    val transactions: ToriiCollection<TransactionRow> = collection("/v1/transactions", ::TransactionRow, history = true)

    /**
     * Committed transactions [accountId] signed or that reference it
     * (`/v1/accounts/{account_id}/transactions`), a history collection like [transactions].
     */
    fun accountTransactions(accountId: String): ToriiCollection<TransactionRow> =
        collection(
            "/v1/accounts/${collectionPathSegment(accountId, "accountId")}/transactions",
            ::TransactionRow,
            history = true,
        )

    /** Account movements, newest first, with cursor-bounded history controls. */
    fun accountHistory(accountId: String): ToriiCollection<AccountHistoryRow> =
        collection("/v1/accounts/${collectionPathSegment(accountId, "accountId")}/history", ::AccountHistoryRow, history = true)

    /** Explorer accounts rows, with bounded cursor pagination. */
    @get:JvmName("explorerAccounts")
    val explorerAccounts: ToriiCollection<org.hyperledger.iroha.sdk.json.JsonObject> =
        collection("/v1/explorer/accounts", { it }, history = true).json()

    /** Explorer domains rows, with bounded cursor pagination. */
    @get:JvmName("explorerDomains")
    val explorerDomains: ToriiCollection<org.hyperledger.iroha.sdk.json.JsonObject> =
        collection("/v1/explorer/domains", { it }, history = true).json()

    /** Explorer asset-definitions rows, with bounded cursor pagination. */
    @get:JvmName("explorerAssetDefinitions")
    val explorerAssetDefinitions: ToriiCollection<org.hyperledger.iroha.sdk.json.JsonObject> =
        collection("/v1/explorer/asset-definitions", { it }, history = true).json()

    /** Explorer assets rows, with bounded cursor pagination. */
    @get:JvmName("explorerAssets")
    val explorerAssets: ToriiCollection<org.hyperledger.iroha.sdk.json.JsonObject> =
        collection("/v1/explorer/assets", { it }, history = true).json()

    /** Explorer nfts rows, with bounded cursor pagination. */
    @get:JvmName("explorerNfts")
    val explorerNfts: ToriiCollection<org.hyperledger.iroha.sdk.json.JsonObject> =
        collection("/v1/explorer/nfts", { it }, history = true).json()

    /** Explorer rwas rows, with bounded cursor pagination. */
    @get:JvmName("explorerRwas")
    val explorerRwas: ToriiCollection<org.hyperledger.iroha.sdk.json.JsonObject> =
        collection("/v1/explorer/rwas", { it }, history = true).json()

    /** Explorer blocks rows, with bounded cursor pagination. */
    @get:JvmName("explorerBlocks")
    val explorerBlocks: ToriiCollection<org.hyperledger.iroha.sdk.json.JsonObject> =
        collection("/v1/explorer/blocks", { it }, history = true).json()

    /** Explorer transactions rows, with bounded cursor pagination. */
    @get:JvmName("explorerTransactions")
    val explorerTransactions: ToriiCollection<org.hyperledger.iroha.sdk.json.JsonObject> =
        collection("/v1/explorer/transactions", { it }, history = true).json()

    /** Explorer transactions/latest rows, with bounded cursor pagination. */
    @get:JvmName("explorerLatestTransactions")
    val explorerLatestTransactions: ToriiCollection<org.hyperledger.iroha.sdk.json.JsonObject> =
        collection("/v1/explorer/transactions/latest", { it }, history = true).json()

    /** Explorer instructions rows, with bounded cursor pagination. */
    @get:JvmName("explorerInstructions")
    val explorerInstructions: ToriiCollection<org.hyperledger.iroha.sdk.json.JsonObject> =
        collection("/v1/explorer/instructions", { it }, history = true).json()

    /** Explorer instructions/latest rows, with bounded cursor pagination. */
    @get:JvmName("explorerLatestInstructions")
    val explorerLatestInstructions: ToriiCollection<org.hyperledger.iroha.sdk.json.JsonObject> =
        collection("/v1/explorer/instructions/latest", { it }, history = true).json()

    private fun <T> collection(
        path: String,
        decode: (org.hyperledger.iroha.sdk.json.JsonObject) -> T,
        history: Boolean = false,
    ): ToriiCollection<T> = ToriiCollection(collectionTransport, path, true, null, history, decode)

    private fun collectionPathSegment(value: String, name: String): String {
        require(value.isNotEmpty() && value.trim() == value) { "$name must be non-empty without surrounding whitespace" }
        return encodePathSegment(value)
    }

    /** One `POST <path>/query`, signed when [auth] or the client-wide canonical auth is configured. */
    private fun queryCollection(
        path: String,
        body: ByteArray,
        auth: ToriiCanonicalRequestAuth?,
    ): CompletableFuture<TransportResponse> {
        val target = resolvePath("$path/query")
        val signer = auth ?: config.canonicalAuth()
        val canonicalHeaders = if (signer == null) {
            emptyMap()
        } else {
            requireCanonicalHeadersUnset()
            buildCanonicalHeaders("POST", target, body, signer)
        }
        val headers = LinkedHashMap<String, String>()
        headers["Accept"] = "application/json"
        headers["Content-Type"] = "application/json"
        for ((name, value) in config.defaultHeaders()) {
            if (headers.keys.none { it.equals(name, ignoreCase = true) }) headers[name] = value
        }
        headers.putAll(canonicalHeaders)
        TransportSecurity.requireHttpRequestAllowed(
            "HttpClientTransport collection query",
            config.baseUri(),
            target,
            headers,
            body,
            config.allowPlaintextLoopback(),
        )
        val builder = TransportRequest.builder()
            .setUri(target)
            .setMethod("POST")
            .setBody(body)
            .setTimeout(config.requestTimeout())
            .setMaximumResponseBytes(COLLECTION_RESPONSE_MAX_BYTES)
        for ((name, value) in headers) builder.addHeader(name, value)
        val request = builder.build()
        notifyRequest(request)
        val response = executor.execute(request)
        response.whenComplete { result, failure ->
            if (failure != null) {
                notifyFailure(request, unwrapCompletion(failure))
            } else if (result.statusCode == 200) {
                notifyResponse(request, ClientResponse(result.statusCode, ByteArray(0), result.message))
            } else {
                notifyFailure(request, ToriiApiException.fromResponse(result.statusCode, result.headers, result.body))
            }
        }
        return response
    }
    override fun close() {
        val polls = synchronized(lifecycleLock) {
            if (closed) return
            closed = true
            if (lazyScheduler.isInitialized()) scheduler.shutdownNow()
            pendingPolls.toList().also { pendingPolls.clear() }
        }
        polls.forEach { it.cancel(false) }
        executor.close()
    }
    fun newNoritoRpcClient(): NoritoRpcClient = config.toNoritoRpcClient(executor)
    /**
     * Creates an event-stream client. Requests are signed with the client-wide
     * [ClientConfig.canonicalAuth] when one is configured and are anonymous otherwise.
     */
    fun newEventStreamClient(): ToriiEventStreamClient =
        config.canonicalAuth()?.let(::newEventStreamClient) ?: newEventStreamClientBuilder().build()

    /** Creates an event-stream client that signs each exact final request URI. */
    fun newEventStreamClient(canonicalAuth: ToriiCanonicalRequestAuth): ToriiEventStreamClient =
        newEventStreamClientBuilder()
            .canonicalRequestAuth(config.requireLocalSigningContext(), canonicalAuth)
            .build()

    private fun newEventStreamClientBuilder(): ToriiEventStreamClient.Builder =
        ToriiEventStreamClient.builder()
            .setBaseUri(config.baseUri())
            .setTransportExecutor(executor)
            .defaultHeaders(config.defaultHeaders())
            .observers(config.observers())
            .allowPlaintextLoopback(config.allowPlaintextLoopback())

    fun newSorafsGatewayClient(): SorafsGatewayClient = newSorafsGatewayClient(config.sorafsGatewayUri())
    fun newSorafsGatewayClient(baseUri: URI): SorafsGatewayClient = SorafsGatewayClient(executor = executor, baseUri = baseUri, timeout = config.requestTimeout(), defaultHeaders = config.defaultHeaders(), observers = config.observers())
    fun newDaToriiClient(): DaToriiClient = DaToriiClient.builder()
        .executor(executor)
        .baseUri(config.baseUri())
        .timeout(config.requestTimeout())
        .defaultHeaders(config.defaultHeaders())
        .observers(config.observers())
        .build()

    /** Fetch one election's exact public u128 tally from a committed state snapshot. */
    fun getElectionTally(
        electionId: String,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<ElectionTallyV1> {
        val selector = GovernanceInstructionUtils.requireGovernanceSelectorV1(
            electionId,
            "election_id",
        )
        require(config.baseUri().scheme.equals("https", ignoreCase = true)) {
            "election tally requests require an HTTPS Torii endpoint"
        }
        require(config.defaultHeaders().keys.none { name ->
            name.equals("Accept", ignoreCase = true) ||
                name.equals("Content-Type", ignoreCase = true)
        }) { "election tally JSON headers must not be overridden" }
        val body = encodeJsonBody(linkedMapOf("election_id" to selector))
        val request = buildVpnRequest(
            "POST",
            "/v1/zk/vote/tally",
            body,
            canonicalAuth,
            ElectionTallyV1.MAX_RESPONSE_BYTES.toLong(),
        )
        return fetchExactJson(request, ElectionTallyV1::parse, "election tally")
    }
    /**
     * Create the exact-route private-settlement client without inheriting request observers.
     *
     * Restricted proof and encrypted-capsule bodies must not enter generic SDK telemetry.
     */
    fun newAtomicPrivateSettlementToriiClientV1(): AtomicPrivateSettlementToriiClientV1 =
        AtomicPrivateSettlementToriiClientV1.builder()
            .executor(executor)
            .baseUri(config.baseUri())
            .localSigningContext(config.requireLocalSigningContext())
            .timeout(config.requestTimeout())
            .defaultHeaders(config.defaultHeaders())
            .build()
    fun sorafsGatewayClient(): SorafsGatewayClient = sorafsGatewayClient
    fun sorafsGatewayFetch(request: GatewayFetchRequest): CompletableFuture<ClientResponse> = sorafsGatewayClient.fetch(request)
    fun sorafsGatewayFetchSummary(request: GatewayFetchRequest): CompletableFuture<GatewayFetchSummary> = sorafsGatewayClient.fetchSummary(request)

    fun getUaidPortfolio(uaid: String): CompletableFuture<UaidPortfolioResponse> = getUaidPortfolio(uaid, null)
    fun getUaidPortfolio(uaid: String, query: UaidPortfolioQuery?): CompletableFuture<UaidPortfolioResponse> {
        val canonical = UaidLiteral.canonicalize(uaid, "uaid portfolio")
        val params = query?.toQueryParameters() ?: emptyMap()
        val request = buildJsonGetRequest("/v1/accounts/${encodePathSegment(canonical)}/portfolio", params)
        return fetchJson(request, UaidJsonParser::parsePortfolio, "UAID portfolio")
    }

    fun getUaidBindings(uaid: String): CompletableFuture<UaidBindingsResponse> = getUaidBindings(uaid, null)
    fun getUaidBindings(uaid: String, query: UaidBindingsQuery?): CompletableFuture<UaidBindingsResponse> {
        val canonical = UaidLiteral.canonicalize(uaid, "uaid bindings")
        val params = query?.toQueryParameters() ?: emptyMap()
        return fetchJson(buildJsonGetRequest("/v1/space-directory/uaids/${encodePathSegment(canonical)}", params), UaidJsonParser::parseBindings, "UAID bindings")
    }

    fun listIdentifierPolicies(): CompletableFuture<IdentifierPolicyListResponse> = fetchJson(buildJsonGetRequest("/v1/identifier-policies", emptyMap()), IdentifierJsonParser::parsePolicyList, "identifier policy list")
    fun listRamLfeProgramPolicies(): CompletableFuture<RamLfeProgramPolicyListResponse> = fetchJson(buildJsonGetRequest("/v1/ram-lfe/program-policies", emptyMap()), RamLfeJsonParser::parsePolicyList, "ram-lfe program policy list")

    /** Fetch the exact result-bearing `SignedBlockWire` committed at `height`. */
    fun getLedgerExecutedBlockWire(height: BigInteger): CompletableFuture<ByteArray> {
        require(height.signum() > 0 && height.bitLength() <= 64) {
            "height must be a positive u64"
        }
        val request = buildExactNoritoGetRequest(
            "/v1/ledger/block/$height",
            EXECUTED_BLOCK_WIRE_MAX_BYTES,
        )
        return fetchExactNoritoBytes(request, "executed block wire")
    }

    /** Convenience overload for positive signed heights. */
    fun getLedgerExecutedBlockWire(height: Long): CompletableFuture<ByteArray> =
        getLedgerExecutedBlockWire(BigInteger.valueOf(height))

    /**
     * Read one bounded, unverified unsigned Load receipt with the existing account signer.
     *
     * [requireCurrentOwner] must throw whenever the captured application actor/account or wallet
     * incarnation has changed. It is checked before signing, before dispatch and before delivery;
     * it must be safe to invoke on the completion thread. The consumer must check it again before
     * passing the original to Native. Request cancellation cancels this client's underlying call.
     *
     * This performs one signed empty-body GET without compatibility probes, retries, redirects,
     * JSON fallback or monetary decoding. The expected payer and network remain immutable; server
     * authentication owns canonical controller/signer admission. Before wallet admission, the
     * consumer must bind the canonical receipt to the expected request/payer/scheme/wallet and
     * independently authenticate the successful receipt event and its native BLS Commit certificate
     * before signing Advance. This transport supplies no wallet admission or balance
     * change. A nonempty malformed binary response remains unverified transport data.
     */
    fun getKagemushaWalletLoadIssuanceOriginalV1(
        selection: ToriiKagemushaWalletLoadSelectionV1,
        canonicalAuth: ToriiCanonicalRequestAuth,
        requireCurrentOwner: Runnable,
    ): CompletableFuture<ToriiKagemushaWalletLoadIssuanceOriginalV1> {
        requireCurrentOwner.run()
        val expectedNetwork = config.requireLocalSigningContext().networkId()
        val expectedPayer = canonicalAuth.accountId
        val request = buildKagemushaWalletLoadIssuanceRequestV1(selection, canonicalAuth)
        val result = CompletableFuture<ToriiKagemushaWalletLoadIssuanceOriginalV1>()
        val upstream = try {
            requireCurrentOwner.run()
            notifyRequest(request)
            // An observer may have changed application ownership while seeing the request.
            requireCurrentOwner.run()
            executor.execute(request)
        } catch (error: Throwable) {
            try { notifyFailure(request, error) } catch (observerError: Throwable) {
                if (observerError !== error) error.addSuppressed(observerError)
            }
            result.completeExceptionally(error)
            return result
        }
        result.whenComplete { _, _ -> if (result.isCancelled) upstream.cancel(false) }
        upstream.whenComplete { response, failure ->
            if (result.isDone) return@whenComplete
            if (upstream.isCancelled) {
                result.cancel(false)
                return@whenComplete
            }
            try {
                if (failure != null) throw unwrapCompletion(failure)
                requireCurrentOwner.run()
                requireExactSignedResponseProvenance(request, response, "KAGEMUSHA load issuance")
                val body = response.body
                require(body.isNotEmpty() && body.size <= ToriiKagemushaWalletLoadIssuanceOriginalV1.MAXIMUM_BYTES) {
                    "KAGEMUSHA issuance original is empty or exceeds its bound"
                }
                requireExactOptionalContentLength(response.headers, body.size, "KAGEMUSHA load issuance")
                if (response.statusCode != 200) {
                    throw ToriiApiException.fromResponse(
                        response.statusCode, response.headers, body, "KAGEMUSHA load issuance",
                    )
                }
                requireExactHeader(response.headers, "Content-Type", APPLICATION_NORITO, "KAGEMUSHA load issuance")
                requireAbsentOrIdentityEncoding(response.headers, "KAGEMUSHA load issuance")
                val original = ToriiKagemushaWalletLoadIssuanceOriginalV1(
                    selection, expectedPayer, expectedNetwork, body,
                )
                notifyResponse(request, ClientResponse(response.statusCode, body, response.message))
                requireCurrentOwner.run()
                result.complete(original)
            } catch (error: Throwable) {
                try { notifyFailure(request, error) } catch (observerError: Throwable) {
                    if (observerError !== error) error.addSuppressed(observerError)
                }
                result.completeExceptionally(error)
            }
        }
        return result
    }

    /**
     * Submit one explicit enrollment action with fresh account authentication and no automatic retry.
     *
     * Retain [enrollment] before dispatch. A timeout or Pending preserves the same native attempt:
     * recovery explicitly resubmits its exact originals with fresh [canonicalAuth]. The callback
     * must throw when the captured actor/account or enrollment attempt changes, and must be safe
     * on the completion thread. The caller checks ownership again before Native admits a returned
     * permit or credential. Neither HTTP success nor a Ready result confers enrollment authority.
     */
    fun enrollKagemushaWalletV1(
        enrollment: ToriiKagemushaWalletEnrollmentRequestV1,
        canonicalAuth: ToriiCanonicalRequestAuth,
        requireCurrentOwner: Runnable,
    ): CompletableFuture<ToriiKagemushaWalletEnrollmentResponseV1> {
        val startedAt = System.nanoTime()
        val timeoutNanos = try { config.requestTimeout().toNanos() } catch (_: ArithmeticException) { Long.MAX_VALUE }
        fun requireWithinDeadline() {
            if (System.nanoTime() - startedAt >= timeoutNanos) {
                throw java.util.concurrent.TimeoutException("KAGEMUSHA enrollment request deadline elapsed")
            }
        }
        requireCurrentOwner.run()
        val request = buildKagemushaWalletEnrollmentRequestV1(enrollment, canonicalAuth)
        val result = CompletableFuture<ToriiKagemushaWalletEnrollmentResponseV1>()
        val upstream = try {
            requireCurrentOwner.run()
            notifyRequest(request)
            requireCurrentOwner.run()
            requireWithinDeadline()
            executor.execute(request)
        } catch (error: Throwable) {
            try { notifyFailure(request, error) } catch (observerError: Throwable) {
                if (observerError !== error) error.addSuppressed(observerError)
            }
            result.completeExceptionally(error)
            return result
        }
        result.whenComplete { _, _ -> if (result.isCancelled) upstream.cancel(false) }
        upstream.whenComplete { response, failure ->
            if (result.isDone) return@whenComplete
            if (upstream.isCancelled) { result.cancel(false); return@whenComplete }
            try {
                if (failure != null) throw unwrapCompletion(failure)
                requireCurrentOwner.run()
                requireWithinDeadline()
                requireExactSignedResponseProvenance(request, response, "KAGEMUSHA enrollment")
                val body = response.body
                require(body.isNotEmpty() && body.size <= ToriiKagemushaWalletEnrollmentResponseV1.MAXIMUM_BYTES) {
                    "KAGEMUSHA enrollment response is empty or exceeds its bound"
                }
                requireExactOptionalContentLength(response.headers, body.size, "KAGEMUSHA enrollment")
                if (response.statusCode != 200) throw ToriiApiException.fromResponse(
                    response.statusCode, response.headers, body, "KAGEMUSHA enrollment")
                requireExactHeader(response.headers, "Content-Type", APPLICATION_NORITO, "KAGEMUSHA enrollment")
                requireAbsentOrIdentityEncoding(response.headers, "KAGEMUSHA enrollment")
                val decoded = enrollment.decodeResponse(body)
                notifyResponse(request, ClientResponse(response.statusCode, body, response.message))
                requireCurrentOwner.run()
                requireWithinDeadline()
                result.complete(decoded)
            } catch (error: Throwable) {
                try { notifyFailure(request, error) } catch (observerError: Throwable) {
                    if (observerError !== error) error.addSuppressed(observerError)
                }
                result.completeExceptionally(error)
            }
        }
        return result
    }

    /** Build the exact canonical body and fresh account signature for one issuer operation. */
    internal fun buildKagemushaWalletEnrollmentRequestV1(
        enrollment: ToriiKagemushaWalletEnrollmentRequestV1,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): TransportRequest {
        config.requireLocalSigningContext()
        require(config.baseUri().scheme.equals("https", ignoreCase = true)) {
            "KAGEMUSHA enrollment requires an HTTPS Torii endpoint"
        }
        require(config.baseUri().rawUserInfo == null && config.baseUri().rawQuery == null &&
            config.baseUri().rawFragment == null) {
            "KAGEMUSHA enrollment base URI must not contain user information, query or fragment"
        }
        require(!config.requestTimeout().isZero) { "KAGEMUSHA enrollment requires a positive request timeout" }
        require(!CanonicalRequestSigner.isCanonicalAsciiAccountAlias(canonicalAuth.accountId)) {
            "KAGEMUSHA enrollment requires the expected canonical account, not an alias"
        }
        val forbiddenHeaders = CANONICAL_AUTH_HEADERS + setOf(
            "X-Iroha-Witness", "X-Iroha-Operator-Public-Key", "X-Iroha-Operator-Signature",
            "X-Iroha-Operator-Timestamp-Ms", "X-Iroha-Operator-Nonce", "Content-Type",
            "Content-Encoding", "Accept", "Accept-Encoding", "Cache-Control",
        )
        require(config.defaultHeaders().keys.none { name -> forbiddenHeaders.any { it.equals(name, ignoreCase = true) } }) {
            "KAGEMUSHA enrollment authentication, encoding and cache headers are owned by the transport"
        }
        val controller = requireNotNull(AccountAddress.parseEncoded(canonicalAuth.accountId, null).singleKeyPayload()) {
            "KAGEMUSHA enrollment requires the direct single account signer"
        }
        val request = buildExactNoritoPostRequest(ToriiKagemushaWalletEnrollmentRequestV1.ROUTE,
            enrollment.canonicalWire(), ToriiKagemushaWalletEnrollmentResponseV1.MAXIMUM_BYTES.toLong(),
            canonicalAuth, requestNoStore = true)
        val message = CanonicalRequestSigner.canonicalRequestSignatureMessage(
            config.requireLocalSigningContext().networkId(), request.method, request.uri, request.body,
            request.headers.getValue(CanonicalRequestSigner.HEADER_TIMESTAMP_MS).single().toLong(),
            request.headers.getValue(CanonicalRequestSigner.HEADER_NONCE).single())
        require(NativeSignerBridge.verifyDetached(
            SigningAlgorithm.fromAlgorithmName(algorithmForCurveId(controller.curveId)), controller.publicKey,
            message, Base64.getDecoder().decode(request.headers.getValue(CanonicalRequestSigner.HEADER_SIGNATURE).single()))) {
            "KAGEMUSHA enrollment signature does not match the direct account controller"
        }
        return request
    }

    /** One native BLS certificate and exact Load event inclusion. The response remains DATA
     * until Native verifies the signed genesis, epoch transitions and receipt binding. */
    fun getKagemushaWalletLoadFinalityOriginalV1(
        selection: ToriiKagemushaWalletLoadSelectionV1,
        canonicalAuth: ToriiCanonicalRequestAuth,
        requireCurrentOwner: Runnable,
    ): CompletableFuture<ByteArray> {
        requireCurrentOwner.run()
        config.requireLocalSigningContext()
        val request = buildKagemushaWalletLedgerOriginalRequestV1(selection.path + "/finality", 256 * 1024, canonicalAuth)
        return readKagemushaWalletLedgerOriginalV1(request, requireCurrentOwner)
    }

    /** One boundary selected by Native's authenticated epoch progress. Only Native's
     * incumbent BLS verification may accept its successor; this response is DATA. */
    fun getKagemushaWalletLoadEpochOriginalV1(
        selection: ToriiKagemushaWalletLoadSelectionV1,
        boundaryHeight: BigInteger,
        canonicalAuth: ToriiCanonicalRequestAuth,
        requireCurrentOwner: Runnable,
    ): CompletableFuture<ByteArray> {
        requireCurrentOwner.run()
        require(boundaryHeight >= BigInteger.valueOf(2) && boundaryHeight.bitLength() <= 64) {
            "u64 epoch boundary must follow genesis"
        }
        config.requireLocalSigningContext()
        val request = buildKagemushaWalletLedgerOriginalRequestV1(
            selection.path + "/epochs/$boundaryHeight", 256 * 1024, canonicalAuth)
        return readKagemushaWalletLedgerOriginalV1(request, requireCurrentOwner)
    }

    /** One original ordinary finality proof. Height is a locator, never a verified checkpoint. */
    fun getKagemushaWalletLedgerFinalityOriginalV1(
        height: BigInteger,
        requireCurrentOwner: Runnable,
    ): CompletableFuture<ByteArray> {
        requireCurrentOwner.run()
        require(height.signum() > 0 && height.bitLength() <= 64) { "positive u64 finality height required" }
        config.requireLocalSigningContext()
        val request = buildKagemushaWalletLedgerOriginalRequestV1("/v1/bridge/finality/$height", 36 * 1024 * 1024, null)
        return readKagemushaWalletLedgerOriginalV1(request, requireCurrentOwner)
    }

    private fun readKagemushaWalletLedgerOriginalV1(request: TransportRequest,
        requireCurrentOwner: Runnable): CompletableFuture<ByteArray> {
        val result = CompletableFuture<ByteArray>()
        val upstream = try {
            requireCurrentOwner.run()
            notifyRequest(request)
            requireCurrentOwner.run()
            executor.execute(request)
        } catch (error: Throwable) {
            result.completeExceptionally(error)
            return result
        }
        result.whenComplete { _, _ -> if (result.isCancelled) upstream.cancel(false) }
        upstream.whenComplete { response, failure ->
            if (result.isDone) return@whenComplete
            if (upstream.isCancelled) { result.cancel(false); return@whenComplete }
            try {
                if (failure != null) throw unwrapCompletion(failure)
                requireCurrentOwner.run()
                requireExactSignedResponseProvenance(request, response, "KAGEMUSHA ledger original")
                val body = response.body
                require(body.isNotEmpty() && body.size.toLong() <= requireNotNull(request.maximumResponseBytes))
                requireExactOptionalContentLength(response.headers, body.size, "KAGEMUSHA ledger original")
                if (response.statusCode != 200) throw ToriiApiException.fromResponse(
                    response.statusCode, response.headers, body, "KAGEMUSHA ledger original")
                requireExactHeader(response.headers, "Content-Type", APPLICATION_NORITO, "KAGEMUSHA ledger original")
                requireAbsentOrIdentityEncoding(response.headers, "KAGEMUSHA ledger original")
                notifyResponse(request, ClientResponse(response.statusCode, body, response.message))
                requireCurrentOwner.run()
                result.complete(body.copyOf())
            } catch (error: Throwable) {
                try { notifyFailure(request, error) } catch (observerError: Throwable) {
                    if (observerError !== error) error.addSuppressed(observerError)
                }
                result.completeExceptionally(error)
            }
        }
        return result
    }

    /** Build one exact account-signed Load read; retained headers cannot replace its signer. */
    internal fun buildKagemushaWalletLoadIssuanceRequestV1(
        selection: ToriiKagemushaWalletLoadSelectionV1,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): TransportRequest = buildKagemushaWalletLedgerOriginalRequestV1(
        selection.path, ToriiKagemushaWalletLoadIssuanceOriginalV1.MAXIMUM_BYTES, canonicalAuth)

    private fun buildKagemushaWalletLedgerOriginalRequestV1(path: String, maximumBytes: Int,
        canonicalAuth: ToriiCanonicalRequestAuth?): TransportRequest {
        require(config.baseUri().scheme.equals("https", ignoreCase = true)) {
            "KAGEMUSHA issuance requires an HTTPS Torii endpoint"
        }
        require(config.baseUri().rawUserInfo == null && config.baseUri().rawQuery == null &&
            config.baseUri().rawFragment == null) {
            "KAGEMUSHA issuance base URI must not contain user information, query or fragment"
        }
        require(!config.requestTimeout().isZero) { "KAGEMUSHA issuance requires a positive request timeout" }
        require(canonicalAuth == null || !CanonicalRequestSigner.isCanonicalAsciiAccountAlias(canonicalAuth.accountId)) {
            "KAGEMUSHA issuance requires the expected canonical payer account, not an alias"
        }
        val forbiddenHeaders = CANONICAL_AUTH_HEADERS + setOf(
            "X-Iroha-Witness", "X-Iroha-Operator-Public-Key", "X-Iroha-Operator-Signature",
            "X-Iroha-Operator-Timestamp-Ms", "X-Iroha-Operator-Nonce", "Content-Type",
            "Content-Encoding", "Accept", "Accept-Encoding", "Cache-Control",
        )
        require(config.defaultHeaders().keys.none { name ->
            forbiddenHeaders.any { it.equals(name, ignoreCase = true) }
        }) { "KAGEMUSHA issuance request authentication, encoding and cache headers are owned by the transport" }
        return buildExactNoritoGetRequest(
            path, maximumBytes.toLong(), canonicalAuth, requestNoStore = true,
        )
    }

    /** Fetch the exact committed Exact12 manifest with one-shot canonical account authentication. */
    fun getPrivacyCapabilities(
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<PrivacyExact12CapabilityManifestV1> {
        require(config.baseUri().scheme == "https") {
            "Exact12 privacy capabilities require an HTTPS Torii endpoint"
        }
        val expectedNetworkId = config.requireLocalSigningContext().networkId()
        return fetchExactNoritoBytes(
            buildExactNoritoGetRequest(
                "/v1/privacy/capabilities",
                PrivacyExact12CapabilityManifestV1.MAX_ARCHIVE_BYTES.toLong(),
                canonicalAuth,
                requestNoStore = true,
            ),
            "privacy capabilities",
            requireIdentityEncoding = true,
            requireExactResponseProvenance = true,
        ).thenApply { archive ->
            PrivacyExact12CapabilityManifestV1.fromAuthenticatedTorii(archive, expectedNetworkId)
        }
    }

    /**
     * Obtain the token required immediately before constructing a retained privacy action.
     *
     * The token is issued only when committed readiness/activation and the complete native local
     * profile tuple agree. A legacy snapshot or local catalog cannot enter this path. Capability
     * discovery is authenticated against the exact locally configured network.
     */
    fun requirePrivacyExact12CapabilityAdmission(
        protocolId: PrivacyProtocolIdV1,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<PrivacyExact12CapabilityTupleAdmissionV1> =
        getPrivacyCapabilities(canonicalAuth).thenApply { manifest ->
            PrivacyExact12CapabilityAdmissionV1.requireExact12CapabilityTupleV1(
                manifest,
                protocolId,
            )
        }

    fun getIdentifierClaimByReceiptHash(receiptHash: String): CompletableFuture<Optional<IdentifierClaimRecord>> {
        val normalizedReceiptHash = normalizeHex32(receiptHash, "receiptHash")
        return fetchJsonAllowingNotFound(buildJsonGetRequest("/v1/identifiers/receipts/${encodePathSegment(normalizedReceiptHash)}", emptyMap()), IdentifierJsonParser::parseClaimRecord, "identifier claim lookup")
    }

    fun resolveIdentifier(
        requestBody: IdentifierResolveRequest,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<IdentifierResolutionReceipt?> {
        require(requestBody.phase == "claim") { "resolve requires the exact original claim request" }
        requireIdentifierPhoneRequestScope(requestBody)
        val body = encodeJsonBody(requestBody.toJsonMap())
        return fetchJsonAllowingNotFound(buildVpnRequest("POST", "/v1/identifiers/resolve", body, canonicalAuth, 65_536L), IdentifierJsonParser::parseResolutionReceipt, "identifier resolve")
            .thenApply { response -> response.orElse(null)?.also { requireIdentifierReceiptScope(it, requestBody, null) } }
    }

    override fun resolveAccountAlias(alias: String): CompletableFuture<Optional<AccountAliasResolution>> {
        val normalizedAlias = AccountAliasName.parse(alias).canonicalText()
        val body = encodeJsonBody(linkedMapOf("alias" to normalizedAlias))
        return fetchJsonAllowingNotFound(
            buildJsonPostRequest("/v1/aliases/resolve", body),
            Function { response -> parsePinnedAliasResolution(response, normalizedAlias) },
            "account alias resolve",
        )
    }

    /** Resolves a restricted account alias with canonical account/signature/timestamp/nonce headers. */
    override fun resolveAccountAlias(
        alias: String,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<Optional<AccountAliasResolution>> {
        val normalizedAlias = AccountAliasName.parse(alias).canonicalText()
        val body = encodeJsonBody(linkedMapOf("alias" to normalizedAlias))
        val request = buildVpnRequest("POST", "/v1/aliases/resolve", body, canonicalAuth)
        return fetchJsonAllowingNotFound(
            request,
            Function { response -> parsePinnedAliasResolution(response, normalizedAlias) },
            "account alias resolve",
        )
    }

    override fun planAliasSetup(
        request: AliasSetupPlanRequestV1,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<AliasTransactionPlanV1> {
        val body = JsonEncoder.encode(request.toJsonMap()).toByteArray(StandardCharsets.UTF_8)
        val httpRequest = buildVpnRequest("POST", "/v1/aliases/setup/plan", body, canonicalAuth)
        return fetchJson(
            httpRequest,
            Function { response ->
                AliasTransactionPlanJsonParser.parse(response).also { plan ->
                    require(plan.body.authority == canonicalAuth.accountId) {
                        "alias setup plan authority does not match the canonical request signer"
                    }
                }
            },
            "alias setup plan",
            200,
        )
    }

    override fun planAliasLeaseRenewal(
        request: AliasLeaseRenewPlanRequestV1,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<AliasLifecycleTransactionPlanV1> =
        planAliasLifecycle(
            "/v1/aliases/lease/renew/plan",
            request.toJsonMap(),
            canonicalAuth,
            "alias lease renewal plan",
        )

    override fun planAliasAutoRenew(
        request: AliasAutoRenewPlanRequestV1,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<AliasLifecycleTransactionPlanV1> =
        planAliasLifecycle(
            "/v1/aliases/auto-renew/plan",
            request.toJsonMap(),
            canonicalAuth,
            "alias auto-renew plan",
        )

    private fun planAliasLifecycle(
        path: String,
        requestBody: Map<String, Any?>,
        canonicalAuth: ToriiCanonicalRequestAuth,
        context: String,
    ): CompletableFuture<AliasLifecycleTransactionPlanV1> {
        val body = JsonEncoder.encode(requestBody).toByteArray(StandardCharsets.UTF_8)
        return fetchJson(
            buildVpnRequest("POST", path, body, canonicalAuth),
            Function { response ->
                AliasLifecycleTransactionPlanJsonParser.parse(response).also { plan ->
                    require(plan.body.authority == canonicalAuth.accountId) {
                        "$context authority does not match the canonical request signer"
                    }
                }
            },
            context,
            200,
        )
    }

    override fun planSponsoredAccountOnboarding(
        request: AccountOnboardingPlanRequestV1,
        onboardingToken: String,
        expectedAuthority: String,
        expectedNetworkId: NetworkId,
    ): CompletableFuture<AccountOnboardingPlanReceiptV1> {
        val body = JsonEncoder.encode(request.toJsonMap()).toByteArray(StandardCharsets.UTF_8)
        return fetchJson(
            buildOnboardingRequest("POST", "/v1/accounts/onboard/plan", body, onboardingToken),
            Function { response ->
                AccountOnboardingReceiptVerifier.requireValidForRequest(
                    request,
                    AccountOnboardingJsonParser.parseReceipt(response),
                    expectedNetworkId,
                    expectedAuthority,
                )
            },
            "sponsored account onboarding plan",
            200,
        )
    }

    override fun prepareSponsoredAccountOnboarding(
        request: AccountOnboardingPlanRequestV1,
        receipt: AccountOnboardingPlanReceiptV1,
        binding: PreparedOperationBindingV1,
        feePayment: FeePaymentIntent,
        onboardingToken: String,
        expectedAuthority: String,
        expectedNetworkId: NetworkId,
    ): CompletableFuture<AccountOnboardingPrepareResponseV1> {
        AccountOnboardingReceiptVerifier.requireValidForRequest(
            request,
            receipt,
            expectedNetworkId,
            expectedAuthority,
        )
        require(binding.kind == PreparedOperationBindingV1.ONBOARDING) {
            "onboarding prepare requires an onboarding binding"
        }
        require(binding.executionExpiresAtUnixMs > System.currentTimeMillis()) {
            "onboarding prepare binding is expired"
        }
        val body = JsonEncoder.encode(
            AccountOnboardingPrepareRequestV1(binding, receipt, feePayment).toJsonMap(),
        )
            .toByteArray(StandardCharsets.UTF_8)
        return fetchJson(
            buildOnboardingRequest("POST", "/v1/accounts/onboard/prepare", body, onboardingToken),
            Function { response ->
                when (val result = AccountOnboardingJsonParser.parsePrepareResponse(response)) {
                    is AccountOnboardingPreparedTransactionV1 -> {
                        AccountOnboardingPreparedVerifier.requireValidPrepared(
                            result,
                            request,
                            receipt,
                            binding,
                            feePayment,
                            expectedNetworkId,
                            expectedAuthority,
                        )
                        result
                    }
                    is AccountOnboardingProofRequiredPrepareResponseV1 ->
                        AccountOnboardingPreparedVerifier.requireValidProofRequired(
                            result,
                            request,
                            receipt,
                            binding,
                            expectedNetworkId,
                            expectedAuthority,
                        )
                }
            },
            "sponsored account onboarding prepare",
            200,
        )
    }

    override fun verifyAccountOnboardingCurrentState(
        proofRequired: AccountOnboardingProofRequiredPrepareResponseV1,
        request: AccountOnboardingPlanRequestV1,
        receipt: AccountOnboardingPlanReceiptV1,
        binding: PreparedOperationBindingV1,
        expectedAuthority: String,
        expectedNetworkId: NetworkId,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<AccountOnboardingCurrentStateV1> {
        AccountOnboardingPreparedVerifier.requireValidProofRequired(
            proofRequired,
            request,
            receipt,
            binding,
            expectedNetworkId,
            expectedAuthority,
        )
        val atomicRequest = AccountOnboardingCurrentStateRequestV1(
            proofRequired.accountId,
            proofRequired.alias,
        )
        val body = JsonEncoder.encode(atomicRequest.toJsonMap())
            .toByteArray(StandardCharsets.UTF_8)
        require(config.requireLocalSigningContext().networkId() == expectedNetworkId) {
            "atomic onboarding current-state signing requires the expected network context"
        }
        return fetchExactJson(
            buildVpnRequest(
                "POST",
                "/v1/accounts/onboarding/current-state",
                body,
                canonicalAuth,
                ACCOUNT_ONBOARDING_CURRENT_STATE_RESPONSE_MAX_BYTES,
            ),
            Function { payload ->
                AccountOnboardingJsonParser.parseCurrentStateResponse(payload)
                    .classify(atomicRequest, expectedNetworkId)
            },
            "atomic account onboarding current-state",
        )
    }

    override fun submitPreparedAccountOnboarding(
        request: AccountOnboardingPlanRequestV1,
        prepared: AccountOnboardingPreparedTransactionV1,
        expectedFeePayment: FeePaymentIntent,
        onboardingToken: String,
        expectedAuthority: String,
        expectedNetworkId: NetworkId,
    ): CompletableFuture<PreparedTransactionSubmitResponseV1> {
        AccountOnboardingPreparedVerifier.requireValidPrepared(
            prepared,
            request,
            prepared.receipt,
            prepared.binding,
            expectedFeePayment,
            expectedNetworkId,
            expectedAuthority,
        )
        require(prepared.binding.executionExpiresAtUnixMs > System.currentTimeMillis()) {
            "prepared onboarding binding is expired"
        }
        val body = JsonEncoder.encode(prepared.toJsonMap()).toByteArray(StandardCharsets.UTF_8)
        return fetchJson(
            buildOnboardingRequest("POST", "/v1/accounts/onboard", body, onboardingToken),
            AccountOnboardingJsonParser::parseSubmitResponse,
            "prepared account onboarding submit",
            responseValidator = { response, statusCode ->
                AccountOnboardingPreparedVerifier.requireValidSubmitResponse(
                    response,
                    prepared,
                    expectedFeePayment,
                    statusCode,
                )
            },
        )
    }

    override fun prepareAccountFaucetTransaction(
        claim: AccountFaucetClaimV1,
        binding: PreparedOperationBindingV1,
        feePayment: FeePaymentIntent,
        policy: AccountFaucetPolicyV1,
        expectedNetworkId: NetworkId,
    ): CompletableFuture<AccountFaucetPreparedTransactionV1> {
        require(binding.kind == PreparedOperationBindingV1.FAUCET) {
            "faucet prepare requires a faucet binding"
        }
        require(binding.executionExpiresAtUnixMs > System.currentTimeMillis()) {
            "faucet prepare binding is expired"
        }
        val body = JsonEncoder.encode(
            AccountFaucetPrepareRequestV1(binding, claim, feePayment).toJsonMap(),
        ).toByteArray(StandardCharsets.UTF_8)
        return fetchJson(
            buildJsonPostRequest("/v1/accounts/faucet/prepare", body),
            Function { response ->
                AccountOnboardingJsonParser.parseFaucetPrepareResponse(response).also { prepared ->
                    AccountFaucetPreparedVerifier.requireValidPrepared(
                        prepared,
                        claim,
                        binding,
                        feePayment,
                        policy,
                        expectedNetworkId,
                    )
                }
            },
            "account faucet prepare",
            200,
        )
    }

    override fun submitPreparedAccountFaucetTransaction(
        prepared: AccountFaucetPreparedTransactionV1,
        expectedFeePayment: FeePaymentIntent,
        policy: AccountFaucetPolicyV1,
        expectedNetworkId: NetworkId,
    ): CompletableFuture<PreparedTransactionSubmitResponseV1> {
        AccountFaucetPreparedVerifier.requireValidPrepared(
            prepared,
            prepared.claim,
            prepared.binding,
            expectedFeePayment,
            policy,
            expectedNetworkId,
        )
        require(prepared.binding.executionExpiresAtUnixMs > System.currentTimeMillis()) {
            "prepared faucet binding is expired"
        }
        val body = JsonEncoder.encode(prepared.toJsonMap()).toByteArray(StandardCharsets.UTF_8)
        return fetchJson(
            buildJsonPostRequest("/v1/accounts/faucet", body),
            AccountOnboardingJsonParser::parseSubmitResponse,
            "prepared account faucet submit",
            responseValidator = { response, statusCode ->
                AccountFaucetPreparedVerifier.requireValidSubmitResponse(
                    response,
                    prepared,
                    expectedFeePayment,
                    policy,
                    expectedNetworkId,
                    statusCode,
                )
            },
        )
    }

    override fun getAccountOnboardingReadiness(
        onboardingToken: String,
    ): CompletableFuture<AliasSetupReportV1> = fetchJson(
        buildOnboardingRequest("GET", "/v1/accounts/onboarding/readiness", null, onboardingToken),
        AccountOnboardingJsonParser::parseReadiness,
        "account onboarding readiness",
        200,
    )

    override fun getSumeragiStatus(): CompletableFuture<SumeragiStatus> =
        fetchExactJson(
            buildExactOperatorJsonGetRequest(
                "/v1/sumeragi/status",
                SUMERAGI_STATUS_JSON_MAX_BYTES,
            ),
            Function { payload -> SumeragiStatus.parseJson(payload) },
            "Sumeragi status",
        )

    override fun getSumeragiLanes(): CompletableFuture<List<SumeragiLaneStatus>> =
        fetchExactJson(
            buildExactOperatorJsonGetRequest(
                "/v1/sumeragi/lanes",
                SUMERAGI_LANES_JSON_MAX_BYTES,
            ),
            Function { payload -> SumeragiLaneStatus.parseJsonList(payload) },
            "Sumeragi lanes",
        )

    override fun resolveAccountAliasIndex(
        index: BigInteger,
    ): CompletableFuture<Optional<AccountAliasIndexResolution>> {
        requireAliasU64(index, "index")
        val body = encodeJsonBody(linkedMapOf("index" to index))
        return fetchJsonAllowingNotFound(
            buildJsonPostRequest("/v1/aliases/resolve-index", body),
            Function { response -> parsePinnedAliasIndexResolution(response, index) },
            "account alias index resolve",
        )
    }

    override fun resolveAccountAliasIndex(
        index: BigInteger,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<Optional<AccountAliasIndexResolution>> {
        requireAliasU64(index, "index")
        val body = encodeJsonBody(linkedMapOf("index" to index))
        return fetchJsonAllowingNotFound(
            buildVpnRequest("POST", "/v1/aliases/resolve-index", body, canonicalAuth),
            Function { response -> parsePinnedAliasIndexResolution(response, index) },
            "account alias index resolve",
        )
    }

    override fun listAccountAliases(
        request: AccountAliasesByAccountRequest,
    ): CompletableFuture<Optional<AccountAliasesByAccount>> {
        val body = JsonEncoder.encode(request.toJsonMap()).toByteArray(StandardCharsets.UTF_8)
        return fetchJsonAllowingNotFound(
            buildJsonPostRequest("/v1/aliases/by-account", body),
            Function { response -> parsePinnedAliasesByAccount(response, request) },
            "account aliases lookup",
        )
    }

    override fun listAccountAliases(
        request: AccountAliasesByAccountRequest,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<Optional<AccountAliasesByAccount>> {
        val body = JsonEncoder.encode(request.toJsonMap()).toByteArray(StandardCharsets.UTF_8)
        return fetchJsonAllowingNotFound(
            buildVpnRequest("POST", "/v1/aliases/by-account", body, canonicalAuth),
            Function { response -> parsePinnedAliasesByAccount(response, request) },
            "account aliases lookup",
        )
    }

    private fun parsePinnedAliasResolution(
        response: ByteArray,
        requestedAlias: String,
    ): AccountAliasResolution = AccountAliasJsonParser.parseResolution(response).also { resolution ->
        require(AccountAliasName.parse(resolution.alias).canonicalText() == requestedAlias) {
            "account alias response does not match the requested alias"
        }
    }

    private fun parsePinnedAliasIndexResolution(
        response: ByteArray,
        requestedIndex: BigInteger,
    ): AccountAliasIndexResolution = AccountAliasReadJsonParser.parseIndexResolution(response).also { resolution ->
        require(resolution.index == requestedIndex) {
            "account alias index response does not match the requested index"
        }
    }

    private fun parsePinnedAliasesByAccount(
        response: ByteArray,
        request: AccountAliasesByAccountRequest,
    ): AccountAliasesByAccount = AccountAliasReadJsonParser.parseByAccount(response).also { aliases ->
        require(aliases.accountId == request.accountId) {
            "account aliases response does not match the requested account"
        }
        require(
            aliases.items.all { item ->
                (request.dataspace == null || item.dataspace == request.dataspace) &&
                    (request.domain == null || item.domain == request.domain)
            },
        ) { "account aliases response contains entries outside the requested scope" }
    }

    fun prepareIdentifierClaim(
        accountId: String,
        requestBody: IdentifierResolveRequest,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<IdentifierPrfPrepareResponse?> {
        require(requestBody.phase == "prepare") { "prepare requires a prepare request with no opening or phone proof" }
        val beneficiary = org.hyperledger.iroha.sdk.address.requireCanonicalI105Address(accountId, "accountId")
        val body = encodeJsonBody(requestBody.toJsonMap())
        return fetchJsonAllowingNotFound(buildVpnRequest("POST", "/v1/accounts/${encodePathSegment(beneficiary)}/identifiers/claim-receipt", body, canonicalAuth, 65_536L), IdentifierJsonParser::parsePrepareResponse, "identifier prepare")
            .thenApply { response -> response.orElse(null)?.also {
                require(it.networkId == config.requireLocalSigningContext().networkId() && it.policyId == requestBody.policyId && it.accountId == beneficiary) { "prepare response differs from the selected network, policy or beneficiary" }
                val phone = it.phoneRetailCanonicalityPayload
                if (requestBody.policyId == "phone#retail") {
                    requireNotNull(phone) { "phone prepare requires its unsigned independent-attestor projection" }
                    require(phone.networkId == it.networkId && phone.policyId == it.policyId && phone.accountId == beneficiary && phone.uaid == it.uaid) { "phone projection scope differs from prepare" }
                    PhoneRetailCanonicalityAttestationV1.requireOpeningFields(phone, it.outputOpening)
                } else require(phone == null) { "nonphone prepare contains phone projection" }
            } }
    }

    fun issueIdentifierClaimReceipt(
        accountId: String,
        requestBody: IdentifierResolveRequest,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<IdentifierResolutionReceipt?> {
        require(requestBody.phase == "claim") { "claim receipt requires its original claim request" }
        val beneficiary = org.hyperledger.iroha.sdk.address.requireCanonicalI105Address(accountId, "accountId")
        requireIdentifierPhoneRequestScope(requestBody)
        requestBody.phoneRetailCanonicality?.let { require(it.payload.accountId == beneficiary) { "phone statement beneficiary differs from selected account" } }
        val body = encodeJsonBody(requestBody.toJsonMap())
        return fetchJsonAllowingNotFound(buildVpnRequest("POST", "/v1/accounts/${encodePathSegment(beneficiary)}/identifiers/claim-receipt", body, canonicalAuth, 65_536L), IdentifierJsonParser::parseResolutionReceipt, "identifier claim receipt")
            .thenApply { response -> response.orElse(null)?.also { requireIdentifierReceiptScope(it, requestBody, beneficiary) } }
    }

    private fun requireIdentifierPhoneRequestScope(request: IdentifierResolveRequest) {
        request.phoneRetailCanonicality?.let { require(it.payload.networkId == config.requireLocalSigningContext().networkId()) { "phone statement differs from selected network" } }
    }

    /** Structural scope/refusal only; server admission authenticates the retained signatures. */
    private fun requireIdentifierReceiptScope(receipt: IdentifierResolutionReceipt, request: IdentifierResolveRequest, beneficiary: String?) {
        require(receipt.payload.networkId == config.requireLocalSigningContext().networkId() && receipt.policyId == request.policyId) { "receipt differs from selected network or policy" }
        if (beneficiary != null) require(receipt.accountId == beneficiary) { "receipt beneficiary differs from selected account" }
        require(receipt.payload.opening.toJsonMap() == requireNotNull(request.outputOpening).toJsonMap()) { "receipt replaced its exact original opening" }
        require(receipt.phoneRetailCanonicality?.toJsonMap() == request.phoneRetailCanonicality?.toJsonMap()) { "receipt replaced its original phone statement/signature" }
    }

    fun executeRamLfeProgram(
        programId: String,
        requestBody: RamLfeExecuteRequest,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<RamLfeExecuteResponse?> {
        val program = IdentifierOwnerInputV1.exactText(programId, "programId")
        val body = encodeJsonBody(requestBody.toJsonMap())
        return fetchJsonAllowingNotFound(buildVpnRequest("POST", "/v1/ram-lfe/programs/${encodePathSegment(program)}/execute", body, canonicalAuth, 65_536L), RamLfeJsonParser::parseExecuteResponse, "ram-lfe execute")
            .thenApply { response -> response.orElse(null)?.also { require(it.programId == program) { "execution program differs from selected program" } } }
    }

    fun verifyRamLfeReceipt(
        requestBody: RamLfeReceiptVerifyRequest,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<RamLfeReceiptVerifyResponse> {
        val body = encodeJsonBody(buildRamLfeReceiptVerifyPayload(requestBody.receipt, requestBody.outputHex))
        return fetchJson(buildVpnRequest("POST", "/v1/ram-lfe/receipts/verify", body, canonicalAuth), RamLfeJsonParser::parseReceiptVerifyResponse, "ram-lfe receipt verify")
    }

    fun verifyRamLfeReceipt(
        receipt: Map<String, Any>,
        outputHex: String?,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<RamLfeReceiptVerifyResponse> =
        verifyRamLfeReceipt(RamLfeReceiptVerifyRequest(receipt, outputHex), canonicalAuth)

    fun getVpnProfile(): CompletableFuture<VpnProfile> {
        requireSecureVpnBaseUri()
        return fetchJson(buildJsonGetRequest("/v1/vpn/profile", emptyMap()), VpnJsonParser::parseProfile, "vpn profile", 200)
    }

    fun registerPushDevice(requestBody: PushDeviceRequest, canonicalAuth: ToriiCanonicalRequestAuth): CompletableFuture<ClientResponse> {
        val body = encodeJsonBody(buildPushDevicePayload(requestBody.accountId, requestBody.platform, requestBody.token, requestBody.topics))
        return executeAccepted(buildVpnRequest("POST", "/v1/notify/devices", body, canonicalAuth), "push device register", 202)
    }

    fun unregisterPushDevice(requestBody: PushDeviceRequest, canonicalAuth: ToriiCanonicalRequestAuth): CompletableFuture<ClientResponse> {
        val body = encodeJsonBody(buildPushDevicePayload(requestBody.accountId, requestBody.platform, requestBody.token, requestBody.topics))
        return executeAccepted(buildVpnRequest("DELETE", "/v1/notify/devices", body, canonicalAuth), "push device unregister", 202)
    }

    fun createVpnQuote(requestBody: VpnQuoteCreateRequest, canonicalAuth: ToriiCanonicalRequestAuth): CompletableFuture<VpnQuote> {
        val body = encodeJsonBody(buildVpnQuoteCreatePayload(requestBody.exitClass, requestBody.meteringPublicKeyHex))
        return fetchJson(buildVpnRequest("POST", "/v1/vpn/quotes", body, canonicalAuth), VpnJsonParser::parseQuote, "vpn quote create", 201)
    }

    fun createVpnSession(requestBody: VpnSessionCreateRequest, canonicalAuth: ToriiCanonicalRequestAuth): CompletableFuture<VpnSession> {
        val body = encodeJsonBody(buildVpnSessionCreatePayload(requestBody.exitClass, requestBody.quoteId, requestBody.paymentTxHash, requestBody.meteringPublicKeyHex))
        return fetchJson(buildVpnRequest("POST", "/v1/vpn/sessions", body, canonicalAuth), VpnJsonParser::parseSession, "vpn session create", 201)
    }

    fun getVpnSession(sessionId: String, canonicalAuth: ToriiCanonicalRequestAuth): CompletableFuture<Optional<VpnSession>> {
        val normalizedSessionId = normalizeHex16(sessionId, "sessionId")
        return fetchJsonAllowingNotFound(
            buildVpnRequest("GET", "/v1/vpn/sessions/${encodePathSegment(normalizedSessionId)}", null, canonicalAuth),
            VpnJsonParser::parseSession,
            "vpn session lookup",
            200,
        )
    }

    fun submitVpnReceipt(requestBody: VpnReceiptSubmitRequest, canonicalAuth: ToriiCanonicalRequestAuth): CompletableFuture<VpnReceipt> {
        val body = encodeJsonBody(buildVpnReceiptSubmitPayload(requestBody.relayReceiptHex, requestBody.clientVoucherHex, requestBody.leaseIdHex))
        return fetchJson(buildVpnRequest("POST", "/v1/vpn/receipts", body, canonicalAuth), VpnJsonParser::parseReceipt, "vpn receipt submit", 201)
    }

    fun listVpnReceipts(canonicalAuth: ToriiCanonicalRequestAuth): CompletableFuture<VpnReceiptListResponse> =
        fetchJson(buildVpnRequest("GET", "/v1/vpn/receipts", null, canonicalAuth), VpnJsonParser::parseReceiptList, "vpn receipt list", 200)

    /**
     * Prepare an unsigned verifying-key registration transaction for local signing.
     *
     * Requires [ClientConfig.localSigningContext] and rejects any draft not bound to that exact
     * network, the requested authority, and the exact requested registry record.
     */
    fun registerVerifyingKey(
        requestBody: VerifyingKeyRegisterRequest,
    ): CompletableFuture<VerifyingKeyTransactionDraft> {
        val signingContext = config.requireLocalSigningContext()
        val payload = buildVerifyingKeyRegisterPayload(requestBody)
        val body = encodeJsonBody(payload)
        return fetchJson(
            buildJsonPostRequest("/v1/zk/vk/register", body),
            { bytes ->
                VerifyingKeyTransactionDraftParser.parseRegister(
                    bytes,
                    signingContext.networkId(),
                    payload,
                )
            },
            "verifying key register draft",
            200,
        )
    }

    /**
     * Prepare an unsigned verifying-key update transaction for local signing.
     *
     * Requires [ClientConfig.localSigningContext] and rejects any draft not bound to that exact
     * network, the requested authority, and the exact requested registry record.
     */
    fun updateVerifyingKey(
        requestBody: VerifyingKeyUpdateRequest,
    ): CompletableFuture<VerifyingKeyTransactionDraft> {
        val signingContext = config.requireLocalSigningContext()
        val payload = buildVerifyingKeyUpdatePayload(requestBody)
        val body = encodeJsonBody(payload)
        return fetchJson(
            buildJsonPostRequest("/v1/zk/vk/update", body),
            { bytes ->
                VerifyingKeyTransactionDraftParser.parseUpdate(
                    bytes,
                    signingContext.networkId(),
                    payload,
                )
            },
            "verifying key update draft",
            200,
        )
    }

    /** Quote the exact unsigned transaction payload before replacing only its fee maxima. */
    fun quoteFees(
        unsignedPayload: Map<String, Any?>,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<FeeQuoteResponse> {
        requireNetworkTransactionDomain(unsignedPayload)
        val authority = requireCanonicalI105Address(
            unsignedPayload["authority"] as? String
                ?: throw IllegalArgumentException("unsignedPayload.authority must be a string"),
            "unsignedPayload.authority",
        )
        require(
            CanonicalRequestSigner.isCanonicalAsciiAccountAlias(canonicalAuth.accountId) ||
                sameFeeQuoteAccountIdentity(authority, canonicalAuth.accountId),
        ) {
            "canonicalAuth.accountId must identify unsignedPayload.authority or be a canonical account alias"
        }
        val requestedIntent = FeePaymentJson.parse(
            unsignedPayload["fee_payment"],
            "unsignedPayload.fee_payment",
        )
        val body = encodeJsonBody(linkedMapOf("payload" to unsignedPayload))
        return fetchJson(
            buildVpnRequest(
                "POST",
                "/v1/fees/quote",
                body,
                canonicalAuth,
                FEE_QUOTE_RESPONSE_MAX_BYTES,
            ),
            { response ->
                require(response.size.toLong() <= FEE_QUOTE_RESPONSE_MAX_BYTES) {
                    "fee quote response exceeds the $FEE_QUOTE_RESPONSE_MAX_BYTES byte limit"
                }
                FeePaymentJson.parseQuote(response)
            },
            "fee quote",
            200,
            exactJsonMediaType = true,
        ).thenApply { quote ->
            quote.validateForDraft(requestedIntent, authority)
            quote
        }
    }

    private fun requireNetworkTransactionDomain(
        unsignedPayload: Map<String, Any?>,
    ): NetworkId {
        for (field in listOf("chain", "chainId", "chain_id")) {
            require(field !in unsignedPayload) {
                "unsignedPayload contains retired transaction identity field `$field`"
            }
        }
        val domain = unsignedPayload["domain"] as? Map<*, *>
            ?: throw IllegalArgumentException(
                "unsignedPayload.domain must be TransactionDomain::Network",
            )
        require(
            domain.keys == setOf("kind", "value") &&
                domain["kind"] == "network" &&
                domain["value"] is String,
        ) {
            "unsignedPayload.domain must contain exactly kind=network and a NetworkId value"
        }
        return NetworkId.parse(domain["value"] as String)
    }

    /** Fetch one exact on-chain fee sponsor program under canonical request authentication. */
    fun getFeeSponsorProgram(
        programId: FeeSponsorProgramId,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<FeeSponsorProgramResponse> {
        val body = encodeJsonBody(linkedMapOf("program_id" to programId.literal()))
        return fetchJson(
            buildVpnRequest(
                "POST",
                "/v1/fee-sponsor-programs/by-id",
                body,
                canonicalAuth,
                FEE_SPONSOR_PROGRAM_RESPONSE_MAX_BYTES,
            ),
            FeePaymentJson::parseProgram,
            "fee sponsor program lookup",
            200,
            exactJsonMediaType = true,
        ).thenApply { program ->
            require(program.id == programId) {
                "fee sponsor program response id does not match the requested program"
            }
            program
        }
    }

    /**
     * Prepares and verifies an unsigned contract call against an off-wire caller-trusted intent.
     *
     * The intent must contain the exact resolved invocation and complete final transaction
     * metadata. Torii may enrich fee charge maxima, but cannot select any other signed field.
     * The complete canonical payload is verified before signing material is returned.
     */
    fun prepareContractCall(
        authority: String,
        feePayment: FeePaymentIntent,
        contractAddress: String? = null,
        contractAlias: String? = null,
        entrypoint: String,
        payload: Any? = null,
        draftIntent: ContractCallDraftIntent,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<ContractCallResponse> {
        val signingContext = config.requireLocalSigningContext()
        val requestPayload = buildContractCallDraftPayload(
            authority = authority,
            feePayment = feePayment,
            contractAddress = contractAddress,
            contractAlias = contractAlias,
            entrypoint = entrypoint,
            payload = payload,
        )
        requireCanonicalI105Address(requestPayload.getValue("authority") as String, "authority")
        require(sameFeeQuoteAccountIdentity(authority, canonicalAuth.accountId)) {
            "canonicalAuth.accountId must identify the contract call authority"
        }
        validateContractCallDraftIntent(draftIntent, requestPayload, payload != null)
        val body = encodeJsonBody(requestPayload)
        return fetchJson(
            buildVpnRequest("POST", "/v1/contracts/call", body, canonicalAuth),
            ContractJsonParser::parseCallResponse,
            "contract call draft",
        ).thenApply { response ->
            validateContractCallDraft(
                response,
                requestPayload,
                draftIntent,
                signingContext.networkId(),
            )
        }
    }

    override fun proposeMultisig(request: MultisigProposeRequest): CompletableFuture<MultisigResponse> {
        val signingContext = config.requireLocalSigningContext()
        // The request owns immutable JSON and defensive instruction snapshots.
        val requestSnapshot = request
        val requestPayload = buildMultisigProposePayload(requestSnapshot)
        requireCanonicalI105Address(
            requestPayload.getValue("signer_account_id") as String,
            "signerAccountId",
        )
        (requestPayload["multisig_account_id"] as? String)?.let {
            requireCanonicalI105Address(it, "multisigAccountId")
        }
        val proposalInstructions =
            NoritoJavaCodecAdapter.canonicalMultisigProposalInstructionBoxes(requestSnapshot)
        val expectedMetadata = canonicalMultisigMetadata(requestPayload)
        val body = encodeJsonBody(requestPayload)
        return fetchJson(
            buildJsonPostRequest("/v1/multisig/propose", body),
            ContractJsonParser::parseMultisigResponse,
            "multisig propose",
        ).thenApply { response ->
            validateMultisigResponse(
                response,
                requestSnapshot,
                requestPayload,
                proposalInstructions,
                expectedMetadata,
                signingContext.networkId(),
            )
        }
    }

    fun getGovernanceContract(contractAddress: String, canonicalAuth: ToriiCanonicalRequestAuth): CompletableFuture<GovernanceContractResponse> {
        val normalizedAddress = normalizeNonBlank(contractAddress, "contractAddress")
        return fetchJson(
            buildVpnRequest("GET", "/v1/gov/contracts/${encodePathSegment(normalizedAddress)}", null, canonicalAuth),
            ContractJsonParser::parseGovernanceContractResponse,
            "governance contract"
        )
    }

    /** Draft one typed Parliament attempt for local transaction signing. */
    fun draftParliamentAttemptV1(
        proposal: ParliamentApiV1.Proposal,
        attemptSequence: Long,
        expectedProposalContentId: String,
        expectedGovernanceAttemptId: String,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<ParliamentAttemptDraftResponseV1> {
        val body = ParliamentApiV1.attemptDraftRequestJson(proposal, attemptSequence)
        return fetchJson(
            buildVpnRequest(
                "POST",
                ParliamentApiV1.ATTEMPT_DRAFT_PATH,
                body,
                canonicalAuth,
                1024L * 1024L,
            ),
            Function { response ->
                ParliamentApiV1.parseAttemptDraftResponse(
                    response,
                    expectedProposalContentId,
                    expectedGovernanceAttemptId,
                )
            },
            "Parliament attempt draft",
            200,
        )
    }

    /** Read and strictly validate one authenticated typed Parliament attempt. */
    fun getParliamentAttemptV1(
        governanceAttemptId: String,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<ParliamentAttemptReadResponseV1> = fetchJson(
        buildVpnRequest(
            "GET",
            ParliamentApiV1.attemptReadPath(governanceAttemptId),
            null,
            canonicalAuth,
            2L * ParliamentApiV1.MAX_STATE_BYTES + 2L * 1024L * 1024L,
        ),
        Function { response ->
            ParliamentApiV1.parseAttemptReadResponse(response, governanceAttemptId)
        },
        "Parliament attempt read",
        200,
    )

    /** Draft one closed public Parliament transition for local transaction signing. */
    fun draftParliamentTransitionV1(
        governanceAttemptId: String,
        transitionJson: ByteArray,
        expectedTransitionKind: String,
        expectedTransitionDigest: ByteArray,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<ParliamentTransitionDraftResponseV1> {
        val body = ParliamentApiV1.transitionDraftRequestJson(governanceAttemptId, transitionJson)
        return fetchJson(
            buildVpnRequest(
                "POST",
                ParliamentApiV1.TRANSITION_DRAFT_PATH,
                body,
                canonicalAuth,
                1024L * 1024L,
            ),
            Function { response ->
                ParliamentApiV1.parseTransitionDraftResponse(
                    response,
                    governanceAttemptId,
                    expectedTransitionKind,
                    expectedTransitionDigest,
                )
            },
            "Parliament transition draft",
            200,
        )
    }

    /** Fetch one authenticated pre-seal timed-OVN casting context. */
    fun getParliamentTimedOvnCastingContextV1(
        ballotAttemptId: String,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<ParliamentTimedOvnCastingContextResponseV1> = fetchJson(
        buildVpnRequest(
            "GET",
            ParliamentApiV1.timedOvnCastingContextReadPath(ballotAttemptId),
            null,
            canonicalAuth,
            ParliamentApiV1.MAX_STATE_BYTES.toLong(),
        ),
        Function { response ->
            ParliamentApiV1.parseTimedOvnCastingContextResponse(response, ballotAttemptId)
        },
        "Parliament timed-OVN casting context",
        200,
    )

    /** Request one exact, consensus-authenticated timed-OVN casting-proof page. */
    fun requestParliamentTimedOvnCastingProofV1(
        ballotAttemptId: String,
        trustedCheckpointHeight: BigInteger,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<ParliamentTimedOvnCastingProofResponseV1> {
        val body = ParliamentApiV1.timedOvnCastingProofRequestNorito(trustedCheckpointHeight)
        val request = buildExactNoritoPostRequest(
            ParliamentApiV1.timedOvnCastingProofPath(ballotAttemptId),
            body,
            ParliamentApiV1.MAX_TIMED_OVN_CASTING_PROOF_RESPONSE_BYTES.toLong(),
            canonicalAuth,
        )
        return fetchExactNoritoBytes(
            request,
            "Parliament timed-OVN casting proof",
            requireIdentityEncoding = true,
        )
            .thenApply(ParliamentApiV1::parseTimedOvnCastingProofResponse)
    }

    /** Convenience overload for positive signed checkpoint heights. */
    fun requestParliamentTimedOvnCastingProofV1(
        ballotAttemptId: String,
        trustedCheckpointHeight: Long,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<ParliamentTimedOvnCastingProofResponseV1> =
        requestParliamentTimedOvnCastingProofV1(
            ballotAttemptId,
            BigInteger.valueOf(trustedCheckpointHeight),
            canonicalAuth,
        )

    /** Fetch one bounded checkpoint-promotion page for native wallet verification. */
    fun getParliamentTimedOvnCastingProofPageV1(
        ballotAttemptId: String,
        trustedCheckpointHeight: BigInteger,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<ParliamentTimedOvnCastingProofResponseV1> =
        requestParliamentTimedOvnCastingProofV1(
            ballotAttemptId,
            trustedCheckpointHeight,
            canonicalAuth,
        )

    /** Convenience overload for positive signed checkpoint heights. */
    fun getParliamentTimedOvnCastingProofPageV1(
        ballotAttemptId: String,
        trustedCheckpointHeight: Long,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<ParliamentTimedOvnCastingProofResponseV1> =
        getParliamentTimedOvnCastingProofPageV1(
            ballotAttemptId,
            BigInteger.valueOf(trustedCheckpointHeight),
            canonicalAuth,
        )

    /**
     * Fetch, natively authenticate, and durably promote bounded proof pages until terminal.
     *
     * The supplied authentication must leave timestamp and nonce unpinned so every exact POST is
     * signed with a fresh anti-replay tuple. A promotion is never used for the next request until
     * [checkpointPersister] completes successfully.
     */
    fun requestParliamentTimedOvnCastingProofUntilTerminalV1(
        ballotAttemptId: String,
        initialTrustedCheckpointHeight: BigInteger,
        initialTrustedCheckpointNorito: ByteArray,
        canonicalAuth: ToriiCanonicalRequestAuth,
        pageVerifier: ParliamentTimedOvnCastingProofPageVerifierV1,
        checkpointPersister: ParliamentTimedOvnCastingCheckpointPersisterV1,
    ): CompletableFuture<ParliamentTimedOvnCastingProofTerminalV1> {
        require(canonicalAuth.timestampMs == null && canonicalAuth.nonce == null) {
            "casting-proof paging requires unpinned canonical authentication"
        }
        return ParliamentTimedOvnCastingProofPagerV1.synchronize(
            initialTrustedCheckpointHeight,
            initialTrustedCheckpointNorito,
            { height -> requestParliamentTimedOvnCastingProofV1(ballotAttemptId, height, canonicalAuth) },
            pageVerifier,
            checkpointPersister,
        )
    }

    /** Convenience overload for a positive signed initial checkpoint. */
    fun requestParliamentTimedOvnCastingProofUntilTerminalV1(
        ballotAttemptId: String,
        initialTrustedCheckpointHeight: Long,
        initialTrustedCheckpointNorito: ByteArray,
        canonicalAuth: ToriiCanonicalRequestAuth,
        pageVerifier: ParliamentTimedOvnCastingProofPageVerifierV1,
        checkpointPersister: ParliamentTimedOvnCastingCheckpointPersisterV1,
    ): CompletableFuture<ParliamentTimedOvnCastingProofTerminalV1> =
        requestParliamentTimedOvnCastingProofUntilTerminalV1(
            ballotAttemptId,
            BigInteger.valueOf(initialTrustedCheckpointHeight),
            initialTrustedCheckpointNorito,
            canonicalAuth,
            pageVerifier,
            checkpointPersister,
        )

    /** Fetch the complete public transcript for one currently authorized TLE release. */
    fun getParliamentTleReleaseContextV1(
        ballotAttemptId: String,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<ParliamentTleReleaseContextResponseV1> = fetchJson(
        buildVpnRequest(
            "GET",
            ParliamentApiV1.tleReleaseContextReadPath(ballotAttemptId),
            null,
            canonicalAuth,
            1024L * 1024L,
        ),
        Function { response ->
            ParliamentApiV1.parseTleReleaseContextResponse(response, ballotAttemptId)
        },
        "Parliament TLE release context",
        200,
    )

    /** Request one node-local proof-carrying partial bound to an admitted release context. */
    fun requestParliamentTlePartialReleaseV1(
        ballotAttemptId: String,
        context: ParliamentTleReleaseContextResponseV1,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<ParliamentTlePartialReleaseShareV1> {
        require(context.ballotAttemptId == ballotAttemptId) {
            "release context ballot id differs from the partial-release request"
        }
        return fetchJson(
            buildVpnRequest(
                "POST",
                ParliamentApiV1.tlePartialReleasePath(ballotAttemptId),
                null,
                canonicalAuth,
                16L * 1024L,
            ),
            Function { response ->
                ParliamentApiV1.parseTlePartialReleaseResponse(
                    response,
                    context.keySession.keySessionId,
                    context.identityDigest,
                    context.keySession.committeeSize,
                )
            },
            "Parliament TLE partial release",
            200,
        )
    }

    override fun getContractManifest(
        artifactId: ContractArtifactId,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<ContractManifestRecord> {
        val networkId = config.requireLocalSigningContext().networkId()
        return fetchJson(
            buildVpnRequest(
                "GET",
                "/v1/contracts/artifacts/${artifactId.dataspaceId}/${artifactId.codeHashHex}",
                null,
                canonicalAuth,
                24L * 1024L * 1024L,
            ),
            Function { payload ->
                ContractJsonParser.parseManifestRecord(payload).also { record ->
                    check(record.networkId == networkId && record.artifactId == artifactId) {
                        "contract manifest response does not match the selected network and exact artifact"
                    }
                }
            },
            "contract manifest",
        )
    }

    fun subscriptionToriiClient(): SubscriptionToriiClient = config.toSubscriptionToriiClient(executor)

    private fun submitOnce(
        transaction: SignedTransaction,
        hashHex: String,
    ): CompletableFuture<ClientResponse> {
        val request = ToriiRequestBuilder.buildSubmitRequest(
            config.baseUri(),
            transaction,
            config.requestTimeout(),
            config.defaultHeaders(),
            config.wireFormatPreference().acceptHeader(),
            config.allowPlaintextLoopback(),
        )

        return ensureTransactionSubmissionCompatibility().thenCompose {
            notifyRequest(request)
            executor.execute(request).handle { response, throwable ->
                if (throwable != null) {
                    val cause = unwrapCompletion(throwable)
                    val error = AmbiguousTransactionSubmissionException(
                        hashHex,
                        null,
                        null,
                        null,
                        cause,
                    )
                    notifyFailure(request, error)
                    return@handle CompletableFuture<ClientResponse>().also {
                        it.completeExceptionally(error)
                    }
                }
                val statusCode = response.statusCode
                val rejectCode = extractRejectCode(response)
                val responseBody = HttpErrorMessageExtractor.extractMessage(response.body)
                if (submissionOutcomeIsAmbiguous(statusCode)) {
                    val error = AmbiguousTransactionSubmissionException(
                        hashHex,
                        statusCode,
                        rejectCode,
                        responseBody,
                        null,
                    )
                    notifyFailure(request, error)
                    return@handle CompletableFuture<ClientResponse>().also {
                        it.completeExceptionally(error)
                    }
                }
                if (statusCode != 202) {
                    val error = TransactionSubmissionHttpException.from(
                        hashHex,
                        statusCode,
                        rejectCode,
                        response.body,
                    )
                    notifyFailure(request, error)
                    return@handle CompletableFuture<ClientResponse>().also {
                        it.completeExceptionally(error)
                    }
                }
                val clientResponse = ClientResponse(
                    statusCode,
                    response.body,
                    response.message,
                    extractEntrypointHash(response) ?: hashHex,
                    rejectCode,
                )
                notifyResponse(request, clientResponse)
                CompletableFuture.completedFuture(clientResponse)
            }.thenCompose { it }
        }
    }

    private fun submissionOutcomeIsAmbiguous(statusCode: Int): Boolean =
        statusCode in 300..399 ||
            statusCode == 408 ||
            statusCode == 409 ||
            statusCode == 425 ||
            statusCode == 429 ||
            statusCode >= 500

    private fun emitDeviceProfileTelemetry() {
        if (!config.telemetryOptions().enabled || !deviceProfileEmitted.compareAndSet(false, true)) return
        val sink = config.telemetrySink().orElse(null) ?: return
        val provider = config.deviceProfileProvider()
        val profile = provider.snapshot().orElse(null) ?: return
        sink.emitSignal("android.telemetry.device_profile", mapOf("profile_bucket" to profile.bucket))
    }

    private fun emitNetworkContextTelemetry() {
        if (!config.telemetryOptions().enabled) return
        val sink = config.telemetrySink().orElse(null) ?: return
        val context = config.networkContextProvider().snapshot().orElse(null) ?: return
        sink.emitSignal("android.telemetry.network_context", context.toTelemetryFields())
    }

    private fun emitPipelineStatusTelemetry(request: TransportRequest, transactionHash: String?, statusKind: String?, isSuccess: Boolean, isFailure: Boolean, attempts: Int) {
        if (!config.telemetryOptions().enabled) return; val sink = config.telemetrySink().orElse(null) ?: return
        val fields = LinkedHashMap<String, Any>()
        maybePutAuthorityHash(fields, request, sink, PIPELINE_STATUS_SIGNAL)
        if (transactionHash != null) fields["tx_hash"] = transactionHash
        fields["status_kind"] = statusKind ?: ""; fields["outcome"] = if (isSuccess) "success" else if (isFailure) "failure" else "pending"; fields["attempts"] = attempts
        sink.emitSignal(PIPELINE_STATUS_SIGNAL, fields)
    }

    private fun maybePutAuthorityHash(fields: MutableMap<String, Any>, request: TransportRequest, sink: TelemetrySink, signalId: String) {
        val redaction = config.telemetryOptions().redaction; if (!redaction.enabled) return
        val authority = resolveAuthority(request).trim(); if (authority.isEmpty()) { emitRedactionFailure(sink, signalId, "blank_authority"); return }
        val hashed = redaction.hashAuthority(authority); if (hashed.isPresent) fields["authority_hash"] = hashed.get() else emitRedactionFailure(sink, signalId, "hash_failed")
    }

    /** Attempt counter and last observed status carried between polls. */
    private class PollProgress(val attempts: Int, val lastPayload: Map<String, Any>?)

    /**
     * Poll until a terminal status. Synchronously completed requests (and zero intervals) loop here
     * instead of recursing, so long waits cannot overflow the stack; positive intervals hop to the
     * scheduler thread.
     */
    private fun pollPipelineStatus(hashHex: String, options: PipelineStatusOptions, deadline: Long, attemptsSoFar: Int, lastPayload: Map<String, Any>?, future: CompletableFuture<Map<String, Any>>) {
        var progress = PollProgress(attemptsSoFar, lastPayload)
        while (!future.isDone) {
            val configuredMaxAttempts = options.maxAttempts
            if (configuredMaxAttempts != null && progress.attempts >= configuredMaxAttempts) {
                future.completeExceptionally(TransactionTimeoutException("Transaction $hashHex did not reach a terminal status after ${progress.attempts} attempts", hashHex, progress.attempts, progress.lastPayload))
                return
            }
            val request = try {
                ToriiRequestBuilder.buildStatusRequest(
                    config.baseUri(),
                    hashHex,
                    config.requestTimeout(),
                    config.defaultHeaders(),
                    config.allowPlaintextLoopback(),
                )
            } catch (error: RuntimeException) {
                future.completeExceptionally(error)
                return
            }
            notifyRequest(request)
            val responseFuture = executor.execute(request)
            val current = progress
            if (!responseFuture.isDone) {
                responseFuture.whenComplete { response, throwable ->
                    val next = observePipelineStatus(hashHex, options, deadline, current, request, response, throwable, future)
                    if (next != null) scheduleNextPoll(hashHex, options, deadline, next, future)
                }
                return
            }
            val outcome: Pair<TransportResponse?, Throwable?> = try {
                responseFuture.join() to null
            } catch (error: Throwable) {
                null to error
            }
            val next = observePipelineStatus(hashHex, options, deadline, current, request, outcome.first, outcome.second, future) ?: return
            if (options.intervalMillis > 0L) {
                scheduleNextPoll(hashHex, options, deadline, next, future)
                return
            }
            progress = next
        }
    }

    /** Settle [future] on a terminal or failed observation; otherwise return the next progress. */
    private fun observePipelineStatus(
        hashHex: String,
        options: PipelineStatusOptions,
        deadline: Long,
        progress: PollProgress,
        request: TransportRequest,
        response: TransportResponse?,
        throwable: Throwable?,
        future: CompletableFuture<Map<String, Any>>,
    ): PollProgress? {
        try {
            if (future.isDone) return null
            if (throwable != null) { val cause = unwrapCompletion(throwable); notifyFailure(request, cause); future.completeExceptionally(cause); return null }
            response!!
            val configuredMaxAttempts = options.maxAttempts
            val clientResponse = ClientResponse(response.statusCode, response.body, response.message, null, extractRejectCode(response))
            notifyResponse(request, clientResponse)
            val statusCode = clientResponse.statusCode
            if (statusCode != 200 && statusCode != 404) { future.completeExceptionally(buildPipelineStatusHttpException(hashHex, response)); return null }
            val payload =
                if (statusCode == 404) null
                else parsePipelineStatusPayload(clientResponse.body)
            val nextAttempts = progress.attempts + 1
            val statusLiteral =
                if (payload == null) null
                else PipelineStatusExtractor.requireAuthoritativeStatus(payload, hashHex)
            val isStateResolved = payload?.get("resolved_from") == "state"
            val isSuccess = statusLiteral == "Applied" && isStateResolved
            val isFailure =
                (statusLiteral == "Rejected" || statusLiteral == "Expired") &&
                    isStateResolved
            emitPipelineStatusTelemetry(request, hashHex, statusLiteral, isSuccess, isFailure, nextAttempts)
            if (options.observer != null) { try { options.observer.onStatus(statusLiteral ?: "", payload ?: emptyMap(), nextAttempts) } catch (observerError: RuntimeException) { future.completeExceptionally(observerError); return null } }
            if (isSuccess) { future.complete(payload); return null }
            if (isFailure) { future.completeExceptionally(TransactionStatusException(hashHex, statusLiteral, payload)); return null }
            if (configuredMaxAttempts != null && nextAttempts >= configuredMaxAttempts) { future.completeExceptionally(TransactionTimeoutException("Transaction $hashHex did not reach a terminal status after $nextAttempts attempts", hashHex, nextAttempts, payload)); return null }
            if (deadline != Long.MAX_VALUE && System.currentTimeMillis() >= deadline) { future.completeExceptionally(TransactionTimeoutException("Transaction $hashHex did not reach a terminal status within the configured timeout", hashHex, nextAttempts, payload)); return null }
            return PollProgress(nextAttempts, payload)
        } catch (e: Exception) {
            if (!future.isDone) future.completeExceptionally(e)
            return null
        }
    }

    private fun scheduleNextPoll(hashHex: String, options: PipelineStatusOptions, deadline: Long, progress: PollProgress, future: CompletableFuture<Map<String, Any>>) {
        if (future.isDone) return
        val interval = options.intervalMillis
        if (interval <= 0L) {
            pollPipelineStatus(hashHex, options, deadline, progress.attempts, progress.lastPayload, future)
            return
        }
        synchronized(lifecycleLock) {
            if (closed || future.isDone) return
            scheduler.schedule(
                { pollPipelineStatus(hashHex, options, deadline, progress.attempts, progress.lastPayload, future) },
                interval,
                TimeUnit.MILLISECONDS,
            )
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun parsePipelineStatusPayload(body: ByteArray?): Map<String, Any> {
        check(body != null && body.isNotEmpty()) {
            "Pipeline status response must not be empty"
        }
        val hasNoritoHeader =
            body.size >= 4 &&
                body[0] == 'N'.code.toByte() &&
                body[1] == 'R'.code.toByte() &&
                body[2] == 'T'.code.toByte() &&
                body[3] == '0'.code.toByte()
        check(!hasNoritoHeader) {
            "Pipeline status response violated the requested application/json contract"
        }
        val json = String(body, StandardCharsets.UTF_8).trim()
        check(json.isNotEmpty()) { "Pipeline status response must not be empty" }
        val parsed = JsonParser.parse(json); check(parsed is Map<*, *>) { "Pipeline status response must be a JSON object" }
        return PipelineStatusExtractor.normalizePublicStatus(parsed as Map<String, Any>)
    }

    private fun notifyRequest(request: TransportRequest) { emitDeviceProfileTelemetry(); emitNetworkContextTelemetry(); for (o in config.observers()) o.onRequest(request) }
    private fun notifyResponse(request: TransportRequest, response: ClientResponse) { for (o in config.observers()) o.onResponse(request, response) }
    private fun notifyFailure(request: TransportRequest, error: Throwable) { for (o in config.observers()) o.onFailure(request, error) }

    private fun buildJsonGetRequest(
        path: String,
        queryParams: Map<String, String>,
        maximumResponseBytes: Long? = null,
    ): TransportRequest {
        val target = appendQuery(resolvePath(path), queryParams)
        val builder = TransportRequest.builder().setUri(target).setMethod("GET").addHeader("Accept", "application/json").setTimeout(config.requestTimeout())
        if (maximumResponseBytes != null) builder.setMaximumResponseBytes(maximumResponseBytes)
        for ((k, v) in config.defaultHeaders()) builder.addHeader(k, v)
        return builder.build()
    }

    private fun buildExactJsonGetRequest(
        path: String,
        maximumResponseBytes: Long,
    ): TransportRequest {
        require(config.defaultHeaders().keys.none { it.equals("Accept", ignoreCase = true) }) {
            "Accept must not be overridden for exact JSON requests"
        }
        val builder = TransportRequest.builder()
            .setUri(resolvePath(path))
            .setMethod("GET")
            .addHeader("Accept", "application/json")
            .setMaximumResponseBytes(maximumResponseBytes)
            .setTimeout(config.requestTimeout())
        for ((key, value) in config.defaultHeaders()) builder.addHeader(key, value)
        return builder.build()
    }

    private fun buildExactOperatorJsonGetRequest(
        path: String,
        maximumResponseBytes: Long,
    ): TransportRequest {
        require(config.defaultHeaders().keys.none { it.equals("Accept", ignoreCase = true) }) {
            "Accept must not be overridden for exact JSON requests"
        }
        OperatorRequestSigner.requireGeneratedAuth(config.defaultHeaders())
        val target = resolvePath(path)
        val operatorHeaders = OperatorRequestSigner.buildHeaders(
            config.requireOperatorSigningContext(),
            "GET",
            target,
            ByteArray(0),
        )
        val builder = TransportRequest.builder()
            .setUri(target)
            .setMethod("GET")
            .addHeader("Accept", "application/json")
            .setMaximumResponseBytes(maximumResponseBytes)
            .setTimeout(config.requestTimeout())
        for ((key, value) in config.defaultHeaders()) builder.addHeader(key, value)
        for ((key, value) in operatorHeaders) builder.addHeader(key, value)
        TransportSecurity.requireHttpRequestAllowed(
            "HttpClientTransport operator GET",
            config.baseUri(),
            target,
            operatorHeaders,
            null,
            config.allowPlaintextLoopback(),
        )
        return builder.build()
    }

    private fun buildJsonPostRequest(
        path: String,
        body: ByteArray,
        maximumResponseBytes: Long? = null,
    ): TransportRequest {
        val builder = TransportRequest.builder().setUri(resolvePath(path)).setMethod("POST").setBody(body).addHeader("Content-Type", "application/json").addHeader("Accept", "application/json").setTimeout(config.requestTimeout())
        if (maximumResponseBytes != null) builder.setMaximumResponseBytes(maximumResponseBytes)
        for ((k, v) in config.defaultHeaders()) builder.addHeader(k, v)
        return builder.build()
    }

    private fun buildExactNoritoGetRequest(
        path: String,
        maximumResponseBytes: Long,
        canonicalAuth: ToriiCanonicalRequestAuth? = null,
        requestNoStore: Boolean = false,
    ): TransportRequest {
        require(config.defaultHeaders().keys.none { it.equals("Accept", ignoreCase = true) }) {
            "Accept must not be overridden for exact Norito requests"
        }
        if (requestNoStore) {
            require(config.defaultHeaders().keys.none {
                it.equals("Cache-Control", ignoreCase = true) ||
                    it.equals("Accept-Encoding", ignoreCase = true)
            }) { "Exact Norito cache and encoding headers are owned by the transport" }
        }
        if (canonicalAuth != null) requireCanonicalHeadersUnset()
        val target = resolvePath(path)
        val builder = TransportRequest.builder()
            .setUri(target)
            .setMethod("GET")
            .addHeader("Accept", APPLICATION_NORITO)
            .setMaximumResponseBytes(maximumResponseBytes)
            .setTimeout(config.requestTimeout())
        if (requestNoStore) {
            builder.addHeader("Cache-Control", "no-store")
            builder.addHeader("Accept-Encoding", "identity")
        }
        for ((key, value) in config.defaultHeaders()) builder.addHeader(key, value)
        if (canonicalAuth != null) {
            val canonicalHeaders = buildCanonicalHeaders("GET", target, null, canonicalAuth)
            for ((key, value) in canonicalHeaders) builder.addHeader(key, value)
            TransportSecurity.requireHttpRequestAllowed(
                "HttpClientTransport",
                config.baseUri(),
                target,
                canonicalHeaders,
                null,
                config.allowPlaintextLoopback(),
            )
        }
        return builder.build()
    }

    private fun buildExactNoritoPostRequest(
        path: String,
        body: ByteArray,
        maximumResponseBytes: Long,
        canonicalAuth: ToriiCanonicalRequestAuth,
        requestNoStore: Boolean = false,
    ): TransportRequest {
        val managedHeaders = if (requestNoStore) {
            listOf("Accept", "Content-Type", "Accept-Encoding", "Content-Encoding", "Cache-Control")
        } else {
            listOf("Accept", "Content-Type", "Accept-Encoding", "Content-Encoding")
        }
        require(config.defaultHeaders().keys.none { candidate ->
            managedHeaders.any { it.equals(candidate, ignoreCase = true) }
        }) { "exact Norito POST headers must not be overridden" }
        requireCanonicalHeadersUnset()
        val target = resolvePath(path)
        val builder = TransportRequest.builder()
            .setUri(target)
            .setMethod("POST")
            .setBody(body)
            .addHeader("Content-Type", APPLICATION_NORITO)
            .addHeader("Accept", APPLICATION_NORITO)
            .addHeader("Accept-Encoding", "identity")
            .setMaximumResponseBytes(maximumResponseBytes)
            .setTimeout(config.requestTimeout())
        if (requestNoStore) builder.addHeader("Cache-Control", "no-store")
        for ((key, value) in config.defaultHeaders()) builder.addHeader(key, value)
        val canonicalHeaders = buildCanonicalHeaders("POST", target, body, canonicalAuth)
        for ((key, value) in canonicalHeaders) builder.addHeader(key, value)
        TransportSecurity.requireHttpRequestAllowed(
            "HttpClientTransport",
            config.baseUri(),
            target,
            canonicalHeaders,
            body,
            config.allowPlaintextLoopback(),
        )
        return builder.build()
    }

    private fun requireCanonicalHeadersUnset() {
        require(config.defaultHeaders().keys.none { candidate ->
            CANONICAL_AUTH_HEADERS.any { it.equals(candidate, ignoreCase = true) }
        }) { "canonical request headers must be supplied only through canonicalAuth" }
    }

    private fun buildVpnRequest(
        method: String,
        path: String,
        body: ByteArray?,
        canonicalAuth: ToriiCanonicalRequestAuth,
        maximumResponseBytes: Long? = null,
    ): TransportRequest {
        if (path.startsWith("/v1/vpn/")) requireSecureVpnBaseUri()
        requireCanonicalHeadersUnset()
        val target = resolvePath(path)
        val builder = TransportRequest.builder().setUri(target).setMethod(method).addHeader("Accept", "application/json").setTimeout(config.requestTimeout())
        if (maximumResponseBytes != null) builder.setMaximumResponseBytes(maximumResponseBytes)
        if (body != null) {
            builder.setBody(body).addHeader("Content-Type", "application/json")
        }
        if (maximumResponseBytes != null) builder.setMaximumResponseBytes(maximumResponseBytes)
        for ((k, v) in config.defaultHeaders()) builder.addHeader(k, v)
        val canonicalHeaders = buildCanonicalHeaders(method, target, body, canonicalAuth)
        for ((k, v) in canonicalHeaders) builder.addHeader(k, v)
        TransportSecurity.requireHttpRequestAllowed(
            "HttpClientTransport",
            config.baseUri(),
            target,
            canonicalHeaders,
            body,
            config.allowPlaintextLoopback(),
        )
        return builder.build()
    }

    private fun requireSecureVpnBaseUri() {
        require(config.baseUri().scheme.equals("https", ignoreCase = true)) {
            "Sora VPN requests require an HTTPS Torii base URI"
        }
    }

    private fun buildOnboardingRequest(
        method: String,
        path: String,
        body: ByteArray?,
        onboardingToken: String,
    ): TransportRequest {
        val token = requireOnboardingCredential(onboardingToken)
        require(config.defaultHeaders().keys.none { it.equals(ONBOARDING_TOKEN_HEADER, ignoreCase = true) }) {
            "$ONBOARDING_TOKEN_HEADER must be supplied only through the sponsored onboarding API"
        }
        val builder = TransportRequest.builder()
            .setUri(resolvePath(path))
            .setMethod(method)
            .addHeader("Accept", "application/json")
            .setTimeout(config.requestTimeout())
        if (body != null) {
            builder.setBody(body).addHeader("Content-Type", "application/json")
        }
        for ((key, value) in config.defaultHeaders()) builder.addHeader(key, value)
        builder.addHeader(ONBOARDING_TOKEN_HEADER, token)
        return builder.build()
    }

    private fun buildCanonicalHeaders(method: String, target: URI, body: ByteArray?, canonicalAuth: ToriiCanonicalRequestAuth): Map<String, String> =
        canonicalAuth.headers(config.requireLocalSigningContext().networkId(), method, target, body)

    private fun resolvePath(path: String?): URI {
        if (path.isNullOrBlank()) return config.baseUri()
        if (path.startsWith("http://") || path.startsWith("https://")) return URI.create(path)
        val normalized = if (path.startsWith("/")) path.substring(1) else path
        val base = config.baseUri().toString()
        return URI.create(if (base.endsWith("/")) base + normalized else "$base/$normalized")
    }

    private fun ensureTransactionSubmissionCompatibility(): CompletableFuture<Unit> {
        val request = buildJsonGetRequest(
            "/v1/node/capabilities",
            emptyMap(),
            NODE_CAPABILITIES_RESPONSE_MAX_BYTES,
        )
        return fetchJson(
            request,
            Function { payload ->
                ToriiTransactionCompatibility.requireCompatible(payload)
                Unit
            },
            "transaction submission compatibility",
            200,
        ).handle { _, throwable ->
            if (throwable != null) {
                val cause = unwrapCompletion(throwable)
                if (cause is ToriiTransactionCompatibilityException) {
                    throw CompletionException(cause)
                }
                throw CompletionException(ToriiTransactionCompatibilityProbeException(cause))
            }
            Unit
        }
    }

    private fun unwrapCompletion(throwable: Throwable): Throwable {
        var current = throwable
        while (current is CompletionException && current.cause != null) {
            current = current.cause!!
        }
        return current
    }

    private fun <T> executeResponse(
        request: TransportRequest,
        errorContext: String,
        consume: (TransportResponse) -> T,
    ): CompletableFuture<T> = CompletableFuture.completedFuture(Unit).thenCompose {
        notifyRequest(request)
        executor.execute(request)
    }.handle { response, failure ->
        try {
            if (failure != null) {
                throw RuntimeException("$errorContext request failed", unwrapCompletion(failure))
            }
            consume(response)
        } catch (error: Throwable) {
            try {
                notifyFailure(request, error)
            } catch (observerError: Throwable) {
                if (observerError !== error) error.addSuppressed(observerError)
            }
            throw CompletionException(error)
        }
    }

    private fun <T> fetchJson(
        request: TransportRequest,
        parser: Function<ByteArray, T>,
        errorContext: String,
        acceptedStatus: Int? = null,
        responseValidator: ((T, Int) -> T)? = null,
        exactJsonMediaType: Boolean = false,
    ): CompletableFuture<T> {
        return executeResponse(request, errorContext) { response ->
            val maximumResponseBytes = request.maximumResponseBytes
            if (maximumResponseBytes != null && response.body.size.toLong() > maximumResponseBytes) {
                val error = IllegalArgumentException(
                    "$errorContext response exceeds the $maximumResponseBytes byte limit",
                )
                throw error
            }
            val clientResponse = ClientResponse(response.statusCode, response.body, response.message, null, extractRejectCode(response))
            val statusAccepted = acceptedStatus?.let { response.statusCode == it }
                ?: (response.statusCode in 200..299)
            if (!statusAccepted) throw ToriiApiException.fromResponse(response.statusCode, response.headers, response.body, errorContext)
            if (exactJsonMediaType) {
                requireExactJsonResponse(response, errorContext)
            }
            val parsed = parser.apply(response.body)
            val validated = responseValidator?.invoke(parsed, response.statusCode) ?: parsed
            notifyResponse(request, clientResponse)
            validated
        }
    }

    private fun <T> fetchExactJson(
        request: TransportRequest,
        parser: Function<ByteArray, T>,
        errorContext: String,
    ): CompletableFuture<T> {
        return executeResponse(request, errorContext) { response ->
            val body = response.body
            val clientResponse = ClientResponse(
                response.statusCode,
                body,
                response.message,
                null,
                extractRejectCode(response),
            )
            requireExactJsonResponse(response, errorContext)
            val maximumResponseBytes = requireNotNull(request.maximumResponseBytes) {
                "$errorContext request must declare a response-body limit"
            }
            require(body.isNotEmpty()) { "$errorContext response must not be empty" }
            require(body.size.toLong() <= maximumResponseBytes) {
                "$errorContext response exceeds $maximumResponseBytes bytes"
            }
            requireExactOptionalContentLength(response.headers, body.size, errorContext)
            val parsed = parser.apply(body)
            notifyResponse(request, clientResponse)
            parsed
        }
    }

    private fun fetchExactNoritoBytes(
        request: TransportRequest,
        errorContext: String,
        requireIdentityEncoding: Boolean = false,
        forbidRejectCodeHeader: Boolean = false,
        allowExplicitIdentityEncoding: Boolean = false,
        requirePrivateNoStoreResponse: Boolean = false,
        requireExactResponseProvenance: Boolean = false,
    ): CompletableFuture<ByteArray> {
        return executeResponse(request, errorContext) { response ->
            val body = response.body
            val clientResponse = ClientResponse(
                response.statusCode,
                body,
                response.message,
                null,
                extractRejectCode(response),
            )
            if (requireExactResponseProvenance) {
                requireExactSignedResponseProvenance(request, response, errorContext)
            }
            val maximumResponseBytes = requireNotNull(request.maximumResponseBytes) {
                "$errorContext request must declare a response-body limit"
            }
            require(body.isNotEmpty()) { "$errorContext response must not be empty" }
            require(body.size.toLong() <= maximumResponseBytes) {
                "$errorContext response exceeds $maximumResponseBytes bytes"
            }
            requireExactOptionalContentLength(response.headers, body.size, errorContext)
            if (requirePrivateNoStoreResponse) {
                requireExactHeader(
                    response.headers,
                    "Content-Type",
                    APPLICATION_NORITO,
                    errorContext,
                )
                if (requireIdentityEncoding) {
                    if (allowExplicitIdentityEncoding) {
                        requireAbsentOrIdentityEncoding(response.headers, errorContext)
                    } else {
                        requireHeaderAbsent(response.headers, "Content-Encoding", errorContext)
                    }
                }
                requirePrivateNoStore(response.headers, errorContext)
            }
            if (response.statusCode != 200) {
                throw ToriiApiException.fromResponse(response.statusCode, response.headers, response.body, errorContext)
            }
            if (!requirePrivateNoStoreResponse) {
                requireExactHeader(
                    response.headers,
                    "Content-Type",
                    APPLICATION_NORITO,
                    errorContext,
                )
                if (requireIdentityEncoding) {
                    if (allowExplicitIdentityEncoding) {
                        requireAbsentOrIdentityEncoding(response.headers, errorContext)
                    } else {
                        requireHeaderAbsent(response.headers, "Content-Encoding", errorContext)
                    }
                }
            }
            if (forbidRejectCodeHeader) {
                require(response.headers.keys.none {
                    it.equals("x-iroha-reject-code", ignoreCase = true)
                }) {
                    "$errorContext successful response carried x-iroha-reject-code"
                }
            }
            notifyResponse(request, clientResponse)
            body.copyOf()
        }
    }

    private fun requireExactSignedResponseProvenance(
        request: TransportRequest,
        response: TransportResponse,
        errorContext: String,
    ) {
        require(
            !response.redirected &&
                response.finalUri?.toASCIIString() == request.uri.toASCIIString(),
        ) {
            "$errorContext response must come from the exact signed URL without redirects"
        }
    }

    private fun requireExactHeader(
        headers: Map<String, List<String>>,
        name: String,
        expected: String,
        errorContext: String,
    ) {
        val values = headers.entries
            .asSequence()
            .filter { (header, _) -> header.equals(name, ignoreCase = true) }
            .flatMap { (_, headerValues) -> headerValues.asSequence() }
            .toList()
        require(values.size == 1 && values[0] == expected) {
            "$errorContext response $name must be exactly $expected"
        }
    }

    private fun requireHeaderAbsent(
        headers: Map<String, List<String>>,
        name: String,
        errorContext: String,
    ) {
        require(headers.keys.none { it.equals(name, ignoreCase = true) }) {
            "$errorContext response must not contain $name"
        }
    }

    private fun requireAbsentOrIdentityEncoding(
        headers: Map<String, List<String>>,
        errorContext: String,
    ) {
        val values = headers.entries
            .asSequence()
            .filter { (name, _) -> name.equals("Content-Encoding", ignoreCase = true) }
            .flatMap { (_, headerValues) -> headerValues.asSequence() }
            .toList()
        require(
            values.isEmpty() ||
                values.size == 1 && values.single().trim().equals("identity", ignoreCase = true),
        ) {
            "$errorContext response Content-Encoding must be absent or identity"
        }
    }

    private fun requirePrivateNoStore(
        headers: Map<String, List<String>>,
        errorContext: String,
    ) {
        val headerValues = headers.entries
            .asSequence()
            .filter { (name, _) -> name.equals("Cache-Control", ignoreCase = true) }
            .flatMap { (_, headerValues) -> headerValues.asSequence() }
            .toList()
        val directives = parseCacheControlDirectives(headerValues)
        val validPolicy = directives?.let { parsed ->
            parsed.any { it.name == "private" && !it.hasValue } &&
                parsed.any { it.name == "no-store" && !it.hasValue } &&
                parsed.none { it.name == "public" }
        } ?: false
        require(validPolicy) {
            "$errorContext response must remain private and no-store"
        }
    }

    private data class CacheControlDirective(
        val name: String,
        val hasValue: Boolean,
    )

    private fun parseCacheControlDirectives(
        headerValues: List<String>,
    ): List<CacheControlDirective>? {
        val parsed = mutableListOf<CacheControlDirective>()
        for (headerValue in headerValues) {
            val rawDirectives = splitCacheControlDirectives(headerValue) ?: return null
            for (rawDirective in rawDirectives) {
                parsed += parseCacheControlDirective(rawDirective) ?: return null
            }
        }
        return parsed
    }

    private fun splitCacheControlDirectives(headerValue: String): List<String>? {
        val directives = mutableListOf<String>()
        var start = 0
        var inQuotes = false
        var escaped = false
        for (index in headerValue.indices) {
            val character = headerValue[index]
            if (inQuotes) {
                when {
                    escaped -> {
                        if (!isHttpQuotedPairCharacter(character)) return null
                        escaped = false
                    }

                    character == '\\' -> escaped = true
                    character == '"' -> inQuotes = false
                }
            } else {
                when (character) {
                    '"' -> inQuotes = true
                    ',' -> {
                        directives += headerValue.substring(start, index)
                        start = index + 1
                    }
                }
            }
        }
        if (inQuotes || escaped) return null
        directives += headerValue.substring(start)
        return directives
    }

    private fun parseCacheControlDirective(rawDirective: String): CacheControlDirective? {
        var index = skipHttpOws(rawDirective, 0)
        val nameStart = index
        while (index < rawDirective.length && isHttpTokenCharacter(rawDirective[index])) {
            index += 1
        }
        if (index == nameStart) return null
        val name = rawDirective.substring(nameStart, index).lowercase()
        index = skipHttpOws(rawDirective, index)
        if (index == rawDirective.length) return CacheControlDirective(name, false)
        if (rawDirective[index] != '=') return null
        index = skipHttpOws(rawDirective, index + 1)
        if (index == rawDirective.length) return null

        index = if (rawDirective[index] == '"') {
            parseCacheControlQuotedValue(rawDirective, index) ?: return null
        } else {
            val valueStart = index
            while (
                index < rawDirective.length &&
                isHttpTokenCharacter(rawDirective[index])
            ) {
                index += 1
            }
            if (index == valueStart) return null
            index
        }
        index = skipHttpOws(rawDirective, index)
        return if (index == rawDirective.length) CacheControlDirective(name, true) else null
    }

    private fun parseCacheControlQuotedValue(value: String, quoteIndex: Int): Int? {
        var index = quoteIndex + 1
        while (index < value.length) {
            val character = value[index]
            when {
                character == '"' -> return index + 1
                character == '\\' -> {
                    index += 1
                    if (
                        index == value.length ||
                        !isHttpQuotedPairCharacter(value[index])
                    ) {
                        return null
                    }
                }

                !isHttpQuotedTextCharacter(character) -> return null
            }
            index += 1
        }
        return null
    }

    private fun requireExactOptionalContentLength(
        headers: Map<String, List<String>>,
        actualBytes: Int,
        errorContext: String,
    ) {
        val matchingHeaders = headers.entries
            .filter { (name, _) -> name.equals("Content-Length", ignoreCase = true) }
        if (matchingHeaders.isEmpty()) return
        val values = matchingHeaders
            .asSequence()
            .flatMap { (_, headerValues) -> headerValues.asSequence() }
            .toList()
        require(values.size == 1) { "$errorContext response has ambiguous Content-Length" }
        val value = values.single()
        require(
            value == "0" ||
                (value.isNotEmpty() && value[0] in '1'..'9' &&
                    value.drop(1).all { it in '0'..'9' }),
        ) {
            "$errorContext response Content-Length must be one canonical decimal integer"
        }
        require(value.toLongOrNull() == actualBytes.toLong()) {
            "$errorContext response Content-Length does not match the body"
        }
    }

    private fun executeAccepted(request: TransportRequest, errorContext: String, acceptedStatus: Int): CompletableFuture<ClientResponse> {
        return executeResponse(request, errorContext) { response ->
            val clientResponse = ClientResponse(response.statusCode, response.body, response.message, null, extractRejectCode(response))
            if (response.statusCode != acceptedStatus) {
                throw ToriiApiException.fromResponse(response.statusCode, response.headers, response.body, errorContext)
            }
            notifyResponse(request, clientResponse)
            clientResponse
        }
    }

    private fun requireExactJsonResponse(
        response: TransportResponse,
        errorContext: String,
    ) {
        if (response.statusCode != 200) {
            throw ToriiApiException.fromResponse(response.statusCode, response.headers, response.body, errorContext)
        }
        val contentTypes = response.headers.entries
            .asSequence()
            .filter { (name, _) -> name.equals("Content-Type", ignoreCase = true) }
            .flatMap { (_, values) -> values.asSequence() }
            .toList()
        if (contentTypes.size != 1 || !isUnambiguousApplicationJson(contentTypes[0])) {
            throw RuntimeException(
                "$errorContext response Content-Type must be exactly application/json",
            )
        }
    }

    private fun isUnambiguousApplicationJson(value: String): Boolean {
        if (',' in value) {
            return false
        }
        var index = skipHttpOws(value, 0)
        val mediaType = "application/json"
        if (index + mediaType.length > value.length) {
            return false
        }
        mediaType.indices.forEach { offset ->
            val actual = value[index + offset]
            val expected = mediaType[offset]
            if (actual != expected && !(expected in 'a'..'z' && actual == (expected.code - 32).toChar())) {
                return false
            }
        }
        index = skipHttpOws(value, index + mediaType.length)
        while (index < value.length) {
            if (value[index] != ';') {
                return false
            }
            index = skipHttpOws(value, index + 1)
            val nameStart = index
            while (index < value.length && isHttpTokenCharacter(value[index])) {
                index += 1
            }
            if (index == nameStart || index >= value.length || value[index] != '=') {
                return false
            }
            index += 1
            if (index >= value.length) {
                return false
            }
            if (value[index] == '"') {
                index += 1
                var closed = false
                while (index < value.length) {
                    val current = value[index]
                    if (current == '"') {
                        index += 1
                        closed = true
                        break
                    }
                    if (current == '\\') {
                        index += 1
                        if (index >= value.length || !isHttpQuotedPairCharacter(value[index])) {
                            return false
                        }
                    } else if (!isHttpQuotedTextCharacter(current)) {
                        return false
                    }
                    index += 1
                }
                if (!closed) {
                    return false
                }
            } else {
                val parameterValueStart = index
                while (index < value.length && isHttpTokenCharacter(value[index])) {
                    index += 1
                }
                if (index == parameterValueStart) {
                    return false
                }
            }
            index = skipHttpOws(value, index)
        }
        return true
    }

    private fun skipHttpOws(value: String, start: Int): Int {
        var index = start
        while (index < value.length && (value[index] == ' ' || value[index] == '\t')) {
            index += 1
        }
        return index
    }

    private fun isHttpTokenCharacter(value: Char): Boolean =
        value in '0'..'9' || value in 'A'..'Z' || value in 'a'..'z' ||
            value in "!#$%&'*+-.^_`|~"

    private fun isHttpQuotedTextCharacter(value: Char): Boolean {
        val code = value.code
        return code == 0x09 || code in 0x20..0x21 || code in 0x23..0x5B ||
            code in 0x5D..0x7E || code in 0x80..0xFF
    }

    private fun isHttpQuotedPairCharacter(value: Char): Boolean {
        val code = value.code
        return code == 0x09 || code in 0x20..0x7E || code in 0x80..0xFF
    }

    private fun <T : Any> fetchJsonAllowingNotFound(
        request: TransportRequest,
        parser: Function<ByteArray, T>,
        errorContext: String,
        acceptedStatus: Int? = null,
    ): CompletableFuture<Optional<T>> {
        return executeResponse(request, errorContext) { response ->
            val clientResponse = ClientResponse(response.statusCode, response.body, response.message, null, extractRejectCode(response))
            if (response.statusCode == 404) { notifyResponse(request, clientResponse); return@executeResponse Optional.empty<T>() }
            val statusAccepted = acceptedStatus?.let { response.statusCode == it }
                ?: (response.statusCode in 200..299)
            if (!statusAccepted) throw ToriiApiException.fromResponse(response.statusCode, response.headers, response.body, errorContext)
            val parsed = parser.apply(response.body)
            notifyResponse(request, clientResponse)
            Optional.of<T>(parsed)
        }
    }

    private fun <T : Any> fetchOptionalJson(request: TransportRequest, parser: Function<ByteArray, T>, errorContext: String): CompletableFuture<Optional<T>> {
        return executeResponse(request, errorContext) { response ->
            val clientResponse = ClientResponse(response.statusCode, response.body, response.message, null, extractRejectCode(response))
            if (response.statusCode < 200 || response.statusCode >= 300) throw ToriiApiException.fromResponse(response.statusCode, response.headers, response.body, errorContext)
            if (response.body.isEmpty()) { notifyResponse(request, clientResponse); return@executeResponse Optional.empty<T>() }
            val parsed = parser.apply(response.body)
            notifyResponse(request, clientResponse)
            Optional.of(parsed)
        }
    }

    companion object {
        private const val ONBOARDING_TOKEN_HEADER = "X-Iroha-Onboarding-Token"
        private const val PIPELINE_STATUS_SIGNAL = "android.torii.pipeline.status"
        private const val REDACTION_FAILURE_SIGNAL = "android.telemetry.redaction.failure"
        private const val U32_MAX = 4_294_967_295L
        private const val FEE_QUOTE_RESPONSE_MAX_BYTES = 64L * 1024L
        private const val FEE_SPONSOR_PROGRAM_RESPONSE_MAX_BYTES = 64L * 1024L
        private const val NODE_CAPABILITIES_RESPONSE_MAX_BYTES = 64L * 1024L
        private const val EXECUTED_BLOCK_WIRE_MAX_BYTES = 32L * 1024L * 1024L
        private const val ACCOUNT_ONBOARDING_CURRENT_STATE_RESPONSE_MAX_BYTES = 4L * 1024L
        private const val DEFAULT_TRANSACTION_TTL_MS = 100_000L
        private const val APPLICATION_NORITO = "application/x-norito"
        private const val COLLECTION_RESPONSE_MAX_BYTES = 32L * 1024 * 1024
        private val CANONICAL_AUTH_HEADERS = setOf(
            CanonicalRequestSigner.HEADER_ACCOUNT,
            CanonicalRequestSigner.HEADER_SIGNATURE,
            CanonicalRequestSigner.HEADER_TIMESTAMP_MS,
            CanonicalRequestSigner.HEADER_NONCE,
        )

        /**
         * Creates an owned transport. A supplied scheduling executor stays application-owned;
         * closing this transport cancels its calls and releases its own connection resources.
         */
        @JvmStatic
        @JvmOverloads
        fun createDefault(config: ClientConfig, asyncExecutor: Executor? = null): HttpClientTransport =
            HttpClientTransport(
                HttpTransportScope.own(OkHttpTransportExecutor.create(asyncExecutor = asyncExecutor)), config,
            )

        /**
         * Transfers one freshly constructed executor to this client's lifetime. The application
         * must not share the transferred executor with another client. Closing this client cancels
         * its calls and closes the executor; resources borrowed by that executor stay borrowed.
         */
        @JvmStatic
        fun createOwned(executor: HttpTransportExecutor, config: ClientConfig): HttpClientTransport =
            HttpClientTransport(HttpTransportScope.own(executor), config)
        /** Adds explicit local staging; transaction submission never drains or fills this queue. */
        @JvmStatic fun withDirectoryPendingQueue(config: ClientConfig, queueDir: Path): ClientConfig = config.toBuilder().enableDirectoryPendingQueue(queueDir).build()
        /** Adds explicit local staging; transaction submission never drains or fills this queue. */
        @JvmStatic fun withFilePendingQueue(config: ClientConfig, queueFile: Path): ClientConfig = config.toBuilder().enableFilePendingQueue(queueFile).build()

        private fun resolveRoute(request: TransportRequest?): String = request?.uri?.rawPath ?: ""
        private fun extractRejectCode(response: TransportResponse?): String? =
            if (response == null) null else HttpErrorMessageExtractor.extractRejectCode(
                response.headers,
                "x-iroha-reject-code",
                response.body,
            )
        private fun extractEntrypointHash(response: TransportResponse?): String? {
            if (response == null) return null
            val values = response.headers["x-iroha-entrypoint-hash"] ?: return null
            check(values.size == 1) {
                "Torii transaction hash header must contain exactly one value"
            }
            val value = values.single()
            check(value.matches(Regex("[0-9a-f]{63}[13579bdf]"))) {
                "Torii transaction hash header must be an exact lowercase marked 32-byte hash"
            }
            return value
        }
        private fun resolveAuthority(request: TransportRequest?): String {
            if (request == null) return ""; val authority = request.uri.authority; if (authority != null) return authority
            val host = request.headers["Host"]; return if (host.isNullOrEmpty()) "" else host[0]
        }
        private fun emitRedactionFailure(sink: TelemetrySink, signalId: String, reason: String) { sink.emitSignal(REDACTION_FAILURE_SIGNAL, mapOf("signal_id" to signalId, "reason" to reason)) }
        private fun buildPipelineStatusHttpException(hashHex: String, response: TransportResponse): TransactionStatusHttpException =
            TransactionStatusHttpException.from(hashHex, response.statusCode, extractRejectCode(response), response.body)
        private fun appendQuery(target: URI, params: Map<String, String>): URI {
            if (params.isEmpty()) return target
            val targetText = target.toString()
            val fragmentIndex = targetText.indexOf('#').let { if (it >= 0) it else targetText.length }
            val builder = StringBuilder(targetText.length + 1)
                .append(targetText, 0, fragmentIndex)
            builder.append(if (builder.indexOf("?") >= 0) "&" else "?")
            builder.append(encodeQuery(params))
            builder.append(targetText, fragmentIndex, targetText.length)
            return URI.create(builder.toString())
        }
        private fun encodeQuery(params: Map<String, String>): String = params.entries.joinToString("&") { (k, v) -> "${urlEncode(k)}=${urlEncode(v)}" }
        private fun encodePathSegment(segment: String): String = urlEncode(segment).replace("+", "%20")
        private fun urlEncode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8.name())
        private fun encodeJsonBody(payload: Map<String, Any>): ByteArray = JsonEncoder.encode(payload).toByteArray(StandardCharsets.UTF_8)

        @JvmStatic internal fun buildRamLfeReceiptVerifyPayload(receipt: Map<String, Any>, outputHex: String?): Map<String, Any> {
            val payload = LinkedHashMap<String, Any>(); payload["receipt"] = LinkedHashMap(receipt)
            if (outputHex != null) payload["output_hex"] = normalizeEvenLengthHex(outputHex, "outputHex")
            return payload
        }

        @JvmStatic internal fun buildVpnQuoteCreatePayload(exitClass: String?, meteringPublicKeyHex: String): Map<String, Any> {
            val payload = LinkedHashMap<String, Any>()
            payload["exit_class"] = normalizeOptionalNonBlank(exitClass, "exitClass") ?: ""
            payload["metering_public_key_hex"] =
                normalizeEd25519PublicKeyHex(meteringPublicKeyHex, "meteringPublicKeyHex")
            return payload
        }

        @JvmStatic internal fun buildPushDevicePayload(accountId: String, platform: String, token: String, topics: List<String>?): Map<String, Any> {
            val payload = LinkedHashMap<String, Any>()
            payload["account_id"] = normalizeNonBlank(accountId, "accountId")
            payload["platform"] = normalizeNonBlank(platform, "platform")
            payload["token"] = normalizeNonBlank(token, "token")
            if (topics != null) payload["topics"] = topics.map { normalizeNonBlank(it, "topics") }
            return payload
        }

        @JvmStatic internal fun buildVpnSessionCreatePayload(
            exitClass: String?,
            quoteId: String,
            paymentTxHash: String,
            meteringPublicKeyHex: String,
        ): Map<String, Any> {
            val payload = LinkedHashMap<String, Any>()
            payload["exit_class"] = normalizeOptionalNonBlank(exitClass, "exitClass") ?: ""
            payload["quote_id"] = normalizeHex32(quoteId, "quoteId")
            payload["payment_tx_hash"] = normalizeHex32(paymentTxHash, "paymentTxHash")
            payload["metering_public_key_hex"] =
                normalizeEd25519PublicKeyHex(meteringPublicKeyHex, "meteringPublicKeyHex")
            return payload
        }

        @JvmStatic internal fun buildVpnReceiptSubmitPayload(relayReceiptHex: String, clientVoucherHex: String, leaseIdHex: String?): Map<String, Any> {
            val payload = LinkedHashMap<String, Any>()
            payload["relay_receipt_hex"] = normalizeEvenLengthHex(relayReceiptHex, "relayReceiptHex")
            payload["client_voucher_hex"] = normalizeEvenLengthHex(clientVoucherHex, "clientVoucherHex")
            if (leaseIdHex != null) payload["lease_id_hex"] = normalizeHex32(leaseIdHex, "leaseIdHex")
            return payload
        }

        /** Builds the secret-free request used to prepare a contract-call draft. */
        @JvmStatic internal fun buildContractCallDraftPayload(
            authority: String,
            feePayment: FeePaymentIntent,
            contractAddress: String?,
            contractAlias: String?,
            entrypoint: String,
            payload: Any?,
        ): Map<String, Any> {
            require(feePayment.gasLimit != null) { "contract feePayment must include gasLimit" }
            val normalized = LinkedHashMap<String, Any>()
            normalized["authority"] = normalizeNonBlank(authority, "authority")
            normalized.putAll(buildContractTargetSelector(contractAddress, contractAlias))
            normalized["entrypoint"] = normalizeNonBlank(entrypoint, "entrypoint")
            if (payload != null) normalized["payload"] = payload
            normalized["fee_payment"] = feePayment.toJsonMap()
            return normalized
        }

        private fun validateContractCallDraftIntent(
            intent: ContractCallDraftIntent,
            request: Map<String, Any>,
            hasRequestPayload: Boolean,
        ) {
            require(intent.invocation.entrypoint == request["entrypoint"]) {
                "contract call draft intent entrypoint does not match the request"
            }
            request["contract_address"]?.let { expected ->
                require(intent.invocation.contractAddress == expected) {
                    "contract call draft intent address does not match the request"
                }
            }
            require((intent.invocation.arguments != null) == hasRequestPayload) {
                "contract call draft intent argument presence does not match the request payload"
            }
        }

        /** Validates that Torii returned a secret-free draft bound to the trusted call intent. */
        @JvmStatic internal fun validateContractCallDraft(
            response: ContractCallResponse,
            request: Map<String, Any>,
            draftIntent: ContractCallDraftIntent,
            expectedNetworkId: NetworkId,
        ): ContractCallResponse {
            check(response.ok) { "contract call draft.ok must be true" }
            check(!response.submitted) { "contract call draft must not be submitted" }
            check(response.txHashHex == null && response.pipelineStatus == null) {
                "contract call draft must not contain submission state"
            }
            check(response.entrypoint == request["entrypoint"]) {
                "contract call draft entrypoint is not bound to the request"
            }
            val receipt = response.operationReceipt
            check(
                receipt.operationKind == "contract_call" &&
                    receipt.status == "pending_signature" &&
                    receipt.transport == "torii",
            ) {
                "contract call draft receipt must be pending_signature"
            }
            check(receipt.entrypoint == response.entrypoint && receipt.txHashHex == null) {
                "contract call draft receipt is inconsistent"
            }
            check(response.transactionPayloadB64 != null) {
                "contract call draft must contain one exact canonical transaction payload"
            }
            check(response.signingMessageB64 != null) {
                "contract call draft must contain a signing message"
            }
            check(response.entrypointHashHex == null && receipt.entrypointHashHex == null) {
                "contract call draft must not claim a final entrypoint hash"
            }
            val invocation = draftIntent.invocation
            check(
                response.contractAddress == invocation.contractAddress &&
                    receipt.contractAddress == invocation.contractAddress,
            ) {
                "contract call draft resolved address does not match the trusted intent"
            }
            val expectedCodeHashHex = hexLower(invocation.expectedCodeHash)
            check(
                response.codeHashHex == expectedCodeHashHex &&
                    receipt.codeHashHex == expectedCodeHashHex,
            ) {
                "contract call draft code hash does not match the trusted intent"
            }
            request["contract_alias"]?.let { expected ->
                check(receipt.contractAlias == expected) {
                    "contract call draft alias is not bound to the request"
                }
            } ?: check(receipt.contractAlias == null) {
                "contract call draft receipt unexpectedly contains an alias"
            }
            check(receipt.dataspace == response.dataspace && receipt.abiHashHex == response.abiHashHex) {
                "contract call draft receipt target metadata is inconsistent"
            }
            check(response.transactionTtlMs == null) {
                "contract call draft response unexpectedly selected a transaction TTL"
            }
            val responseFeePayment = checkNotNull(receipt.feePayment) {
                "contract call draft receipt omitted fee_payment"
            }
            val requestedFeePayment = request["fee_payment"]
            check(requestedFeePayment is Map<*, *>) {
                "contract call draft request omitted fee_payment"
            }
            val payloadBase64 = checkNotNull(response.transactionPayloadB64) {
                "contract call draft omitted transaction_payload_b64"
            }
            val transactionBytes = Base64.getDecoder().decode(payloadBase64)
            check(Base64.getEncoder().encodeToString(transactionBytes) == payloadBase64) {
                "contract call draft transaction payload must use exact standard-base64"
            }
            val signingBase64 = checkNotNull(response.signingMessageB64) {
                "contract call draft omitted signing_message_b64"
            }
            val signingBytes = Base64.getDecoder().decode(signingBase64)
            check(Base64.getEncoder().encodeToString(signingBytes) == signingBase64) {
                "contract call draft signing message must use exact standard-base64"
            }
            check(
                signingBytes.size == 32 &&
                    signingBytes.contentEquals(IrohaHash.prehash(transactionBytes)),
            ) {
                "contract call draft signing message must be the exact transaction payload hash"
            }
            val decoded = NoritoJavaCodecAdapter.decodeCanonicalTransactionPayload(
                transactionBytes,

            )
            check(decoded.networkId == expectedNetworkId) {
                "contract call transaction payload changed the configured network"
            }
            check(
                sameFeeQuoteAccountIdentity(
                    decoded.authority,
                    request.getValue("authority") as String,
                ),
            ) {
                "contract call transaction payload changed the requested authority"
            }
            check(responseFeePayment.hasSamePayerAndGasBound(decoded.feePayment)) {
                "contract call response fee_payment changed the payer, sponsor revision, or gas bound"
            }
            check(responseFeePayment == decoded.feePayment) {
                "contract call response fee_payment does not match the transaction payload"
            }
            check(receipt.gasLimit == responseFeePayment.gasLimit) {
                "contract call draft receipt gas limit is inconsistent"
            }
            check(receipt.payloadDigestHex == contractCallPayloadDigestHex(request)) {
                "contract call draft receipt payload digest does not match the exact request payload"
            }
            check(receipt.gasUsed == null) {
                "contract call draft receipt must not claim gas use before signing"
            }
            check(decoded.creationTimeMs == response.creationTimeMs) {
                "contract call response creation_time_ms does not match the transaction payload"
            }
            check(decoded.executable == Executable.contractCall(invocation)) {
                "contract call transaction payload changed the caller-trusted invocation"
            }
            check(decoded.metadata == draftIntent.metadata) {
                "contract call transaction payload changed the caller-trusted metadata"
            }
            check(
                decoded.timeToLiveMs == DEFAULT_TRANSACTION_TTL_MS &&
                    decoded.nonce == null &&

                    decoded.attachments == null,
            ) {
                "contract call transaction payload changed default lifetime, nonce, admission, or attachments"
            }
            val requestedFee = FeePaymentJson.parse(
                requestedFeePayment,
                "contract call draft request.fee_payment",
            )
            check(requestedFee.hasSamePayerAndGasBound(responseFeePayment)) {
                "contract call response fee_payment changed the requested payer, sponsor revision, or gas bound"
            }
            return response
        }

        private fun contractCallPayloadDigestHex(request: Map<String, Any>): String {
            val payload = request["payload"] ?: return hexLower(Blake3.hash(ByteArray(0)))
            val canonical = JsonValue.parse(JsonEncoder.encode(payload)).canonicalJson
            return hexLower(Blake3.hash(canonical.toByteArray(StandardCharsets.UTF_8)))
        }

        @JvmStatic internal fun buildMultisigProposePayload(request: MultisigProposeRequest): Map<String, Any> {
            val hasAccountId = request.multisigAccountId != null
            val hasAlias = request.multisigAccountAlias != null
            require(hasAccountId != hasAlias) { "Exactly one of multisigAccountId or multisigAccountAlias must be provided" }
            require(request.instructions.isNotEmpty()) { "instructions must not be empty" }

            val payload = LinkedHashMap<String, Any>()
            val accountId = request.multisigAccountId
            val accountAlias = request.multisigAccountAlias
            if (accountId != null) {
                payload["multisig_account_id"] = normalizeNonBlank(accountId, "multisigAccountId")
            } else {
                payload["multisig_account_alias"] = normalizeNonBlank(accountAlias!!, "multisigAccountAlias")
            }
            payload["signer_account_id"] = normalizeNonBlank(request.signerAccountId, "signerAccountId")
            if (request.publicKeyHex != null) {
                payload["public_key_hex"] =
                    normalizeEd25519PublicKeyHex(request.publicKeyHex, "publicKeyHex")
            }
            if (request.signatureB64 != null) payload["signature_b64"] = normalizeRequiredExactBase64Payload(request.signatureB64, "signatureB64")
            if (request.creationTimeMs != null) {
                require(request.creationTimeMs >= 0) { "creationTimeMs must be non-negative" }
                payload["creation_time_ms"] = request.creationTimeMs
            }
            payload["fee_payment"] = request.feePayment.toJsonMap()
            if (request.memo != null) payload["memo"] = normalizeNonBlank(request.memo, "memo")
            request.validationFeeAssessment?.let { assessment ->
                // Native decoding rejects unknown fields and validates the exact signed marker.
                org.hyperledger.iroha.sdk.validationfee.RetailFeeAssessmentBridge.assessmentMarkerV1(
                    assessment.canonicalJson.toByteArray(StandardCharsets.UTF_8),
                )
                payload["validation_fee_assessment"] = requireNotNull(JsonParser.parse(assessment.canonicalJson))
            }
            payload["instructions"] = request.instructions.mapIndexed { index, instruction ->
                require(instruction.isNotEmpty()) { "instructions[$index] must not be empty" }
                Base64.getEncoder().encodeToString(instruction)
            }
            return payload
        }

        /** Reject a multisig response that changes a signature-bound request field. */
        @JvmStatic internal fun validateMultisigResponse(
            response: MultisigResponse,
            request: MultisigProposeRequest,
            requestPayload: Map<String, Any>,
            proposalInstructions: List<ByteArray>,
            expectedMetadata: Map<String, JsonValue>,
            expectedNetworkId: NetworkId,
        ): MultisigResponse {
            check(response.ok) { "multisig response.ok must be true" }
            check(request.feePayment == response.feePayment) {
                "multisig response fee_payment changed the exact requested fee intent"
            }
            request.creationTimeMs?.let { expected ->
                check(response.creationTimeMs == expected) {
                    "multisig response creation_time_ms is not bound to the request"
                }
            }
            val expectedProposalHash = hexLower(
                NoritoJavaCodecAdapter.hashCanonicalInstructionBoxes(proposalInstructions),
            )
            check(
                response.proposalId == expectedProposalHash &&
                    response.instructionsHash == expectedProposalHash,
            ) {
                "multisig response proposal hash does not match the exact requested instructions"
            }
            val requestedMultisigAccount = requestPayload["multisig_account_id"] as? String
                ?: throw IllegalStateException(
                    "multisig aliases require a caller-trusted resolved account",
                )
            check(response.resolvedMultisigAccountId == requestedMultisigAccount) {
                "multisig response resolved account does not match the requested account"
            }
            if (response.submitted) return response
            val transactionBytes = Base64.getDecoder().decode(
                checkNotNull(response.transactionPayloadB64) {
                    "unsigned multisig response omitted transaction_payload_b64"
                },
            )
            val decoded = NoritoJavaCodecAdapter.decodeCanonicalTransactionPayload(
                transactionBytes,

            )
            check(decoded.networkId == expectedNetworkId) {
                "multisig response transaction changed the configured network"
            }
            check(
                sameFeeQuoteAccountIdentity(
                    decoded.authority,
                    requestPayload.getValue("signer_account_id") as String,
                ),
            ) {
                "multisig response transaction authority does not match the requested signer"
            }
            check(decoded.feePayment == response.feePayment) {
                "multisig response fee_payment does not match the transaction payload"
            }
            check(decoded.creationTimeMs == response.creationTimeMs) {
                "multisig response creation_time_ms does not match the transaction payload"
            }
            check(decoded.metadata == expectedMetadata) {
                "multisig response transaction metadata does not match the exact request"
            }
            check(
                decoded.timeToLiveMs == DEFAULT_TRANSACTION_TTL_MS &&
                    decoded.nonce == null &&

                    decoded.attachments == null,
            ) {
                "multisig response transaction changed default lifetime, nonce, admission, or attachments"
            }
            val executableHash = NoritoJavaCodecAdapter.verifyCanonicalMultisigProposeExecutable(
                decoded,
                requestedMultisigAccount,
                proposalInstructions,
            )
            check(hexLower(executableHash) == expectedProposalHash) {
                "multisig response executable changed the requested proposal hash"
            }
            return response
        }

        @JvmStatic internal fun canonicalMultisigMetadata(
            requestPayload: Map<String, Any>,
        ): Map<String, JsonValue> {
            val metadata = LinkedHashMap<String, JsonValue>()
            (requestPayload["memo"] as? String)?.let {
                metadata["memo"] = JsonValue.string(it)
            }
            // The signed nested marker is the sole assessment carrier, including
            // proposals whose first signer immediately reaches quorum.
            return metadata
        }

        @JvmStatic internal fun buildVerifyingKeyRegisterPayload(request: VerifyingKeyRegisterRequest): Map<String, Any> {
            val backend = VerifyingKeyBackendTag.requireVerifierBackendRegistryLabelV1(request.backend, "backend")
            val vkPayload = normalizeVerifierBytes(request.verifyingKeyBytes, request.verifyingKeyLength)
            val commitmentHex = normalizeOptionalHex32(request.commitmentHex, "commitmentHex")
            validateVerifyingKeyMaterial(vkPayload, commitmentHex)
            validateInlineVerifyingKeyCommitment(backend, vkPayload?.bytes, commitmentHex)
            validateVerifyingKeyHeightRange(request.activationHeight, request.withdrawHeight)

            val payload = LinkedHashMap<String, Any>()
            payload["authority"] = normalizeVerifyingKeyAuthority(request.authority)
            payload["backend"] = backend
            payload["name"] = normalizeVerifyingKeyName(request.name)
            payload["version"] = normalizePositiveU32(request.version, "version")
            payload["circuit_id"] = normalizeNonBlank(request.circuitId, "circuitId")
            payload["public_inputs_schema_hash_hex"] = normalizeHex32(request.publicInputsSchemaHashHex, "publicInputsSchemaHashHex")
            payload["gas_schedule_id"] = normalizeNonBlank(request.gasScheduleId, "gasScheduleId")
            putOptionalVerifierFields(
                payload,
                request.curve,
                request.maxProofBytes,
                request.metadataUriCid,
                request.verifyingKeyBytesCid,
                request.activationHeight,
                request.withdrawHeight,
                commitmentHex,
                vkPayload,
                request.status,
            )
            return payload
        }

        @JvmStatic internal fun buildVerifyingKeyUpdatePayload(request: VerifyingKeyUpdateRequest): Map<String, Any> {
            val backend = VerifyingKeyBackendTag.requireVerifierBackendRegistryLabelV1(request.backend, "backend")
            val vkPayload = normalizeVerifierBytes(request.verifyingKeyBytes, request.verifyingKeyLength)
            val commitmentHex = normalizeOptionalHex32(request.commitmentHex, "commitmentHex")
            validateVerifyingKeyMaterial(vkPayload, commitmentHex)
            validateInlineVerifyingKeyCommitment(backend, vkPayload?.bytes, commitmentHex)
            validateVerifyingKeyHeightRange(request.activationHeight, request.withdrawHeight)

            val payload = LinkedHashMap<String, Any>()
            payload["authority"] = normalizeVerifyingKeyAuthority(request.authority)
            payload["backend"] = backend
            payload["name"] = normalizeVerifyingKeyName(request.name)
            payload["version"] = normalizePositiveU32(request.version, "version")
            payload["circuit_id"] = normalizeNonBlank(request.circuitId, "circuitId")
            payload["public_inputs_schema_hash_hex"] = normalizeHex32(request.publicInputsSchemaHashHex, "publicInputsSchemaHashHex")
            request.gasScheduleId?.let { payload["gas_schedule_id"] = normalizeNonBlank(it, "gasScheduleId") }
            putOptionalVerifierFields(
                payload,
                request.curve,
                request.maxProofBytes,
                request.metadataUriCid,
                request.verifyingKeyBytesCid,
                request.activationHeight,
                request.withdrawHeight,
                commitmentHex,
                vkPayload,
                request.status,
            )
            return payload
        }

        @JvmStatic internal fun buildContractTargetSelector(contractAddress: String?, contractAlias: String?): Map<String, String> {
            val hasContractAddress = contractAddress != null
            val hasContractAlias = contractAlias != null
            require(hasContractAddress != hasContractAlias) { "Exactly one of contractAddress or contractAlias must be provided" }
            return if (contractAddress != null) {
                mapOf("contract_address" to normalizeNonBlank(contractAddress, "contractAddress"))
            } else {
                mapOf("contract_alias" to normalizeNonBlank(requireNotNull(contractAlias), "contractAlias"))
            }
        }

        @JvmStatic internal fun normalizeRequiredBase64Payload(value: String, field: String): String {
            val normalized = normalizeNonBlank(value, field)
            val decoded = try {
                Base64.getDecoder().decode(normalized)
            } catch (ex: IllegalArgumentException) {
                throw IllegalArgumentException("$field must be valid base64", ex)
            }
            require(decoded.isNotEmpty()) { "$field must not decode to empty bytes" }
            return normalized
        }

        @JvmStatic internal fun normalizeRequiredExactBase64Payload(value: String, field: String): String {
            require(value.isNotEmpty() && value == value.trim()) { "$field must be exact standard-base64" }
            val decoded = try {
                Base64.getDecoder().decode(value)
            } catch (ex: IllegalArgumentException) {
                throw IllegalArgumentException("$field must be valid base64", ex)
            }
            require(decoded.isNotEmpty()) { "$field must not decode to empty bytes" }
            require(Base64.getEncoder().encodeToString(decoded) == value) {
                "$field must be exact standard-base64"
            }
            return value
        }

        @JvmStatic internal fun normalizeOptionalNonBlank(value: String?, field: String): String? = if (value == null) null else normalizeNonBlank(value, field)
        @JvmStatic internal fun normalizeNonBlank(value: String, field: String): String { val trimmed = value.trim(); require(trimmed.isNotEmpty()) { "$field must not be blank" }; return trimmed }
        @JvmStatic internal fun normalizeVerifyingKeyName(value: String): String {
            val normalized = normalizeNonBlank(value, "name")
            require(!normalized.contains(':')) { "name must not contain ':' characters" }
            return normalized
        }
        @JvmStatic internal fun normalizeVerifyingKeyAuthority(value: String): String {
            val normalized = normalizeNonBlank(value, "authority")
            org.hyperledger.iroha.sdk.address.requireCanonicalI105Address(
                normalized,
                "authority",
            )
            return normalized
        }
        @JvmStatic internal fun normalizeEvenLengthHex(value: String, field: String): String {
            var trimmed = normalizeNonBlank(value, field)
            if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) trimmed = trimmed.substring(2)
            require(trimmed.length % 2 == 0 && trimmed.isNotEmpty()) { "$field must be an even-length hex string" }
            for (c in trimmed) require(c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F') { "$field must be an even-length hex string" }
            return trimmed.lowercase()
        }
        @JvmStatic internal fun normalizeExactEvenLengthHex(value: String, field: String): String {
            require(value.trim() == value) { "$field must be a canonical hex string" }
            return normalizeEvenLengthHex(value, field)
        }
        @JvmStatic internal fun normalizeHexBytes(value: String, field: String, expectedByteLength: Int): String {
            val normalized = normalizeEvenLengthHex(value, field)
            require(normalized.length == expectedByteLength * 2) { "$field must be a $expectedByteLength-byte hex string" }
            return normalized
        }
        @JvmStatic internal fun normalizeHex16(value: String, field: String): String { val normalized = normalizeEvenLengthHex(value, field); require(normalized.length == 32) { "$field must contain 32 hex characters" }; return normalized }
        @JvmStatic internal fun normalizeHex32(value: String, field: String): String { val normalized = normalizeEvenLengthHex(value, field); require(normalized.length == 64) { "$field must contain 64 hex characters" }; return normalized }
        @JvmStatic internal fun normalizeEd25519PublicKeyHex(value: String, field: String): String {
            val normalized = normalizeHex32(value, field)
            val publicKey = ByteArray(Ed25519PublicKeyAdmission.PUBLIC_KEY_LENGTH) { index ->
                val offset = index * 2
                ((Character.digit(normalized[offset], 16) shl 4) or
                    Character.digit(normalized[offset + 1], 16)).toByte()
            }
            require(Ed25519PublicKeyAdmission.isValid(publicKey)) {
                "$field must encode a canonical prime-order Ed25519 public key"
            }
            return normalized
        }
        @JvmStatic internal fun normalizeOptionalHex32(value: String?, field: String): String? = if (value == null || value.trim().isEmpty()) null else normalizeHex32(value, field)

        @JvmStatic internal fun normalizePositiveU32(value: Long, field: String): Long {
            require(value > 0L && value <= U32_MAX) { "$field must be a positive u32" }
            return value
        }

        @JvmStatic internal fun normalizeOptionalU32(value: Long?, field: String): Long? {
            if (value == null) return null
            require(value >= 0L && value <= U32_MAX) { "$field must be a u32" }
            return value
        }

        @JvmStatic internal fun normalizeOptionalNonNegative(value: Long?, field: String): Long? {
            if (value == null) return null
            require(value >= 0L) { "$field must be non-negative" }
            return value
        }

        @JvmStatic internal fun normalizeVerifyingKeyStatus(value: String?): String? {
            val normalized = normalizeOptionalNonBlank(value, "status")?.lowercase() ?: return null
            return when (normalized) {
                "proposed" -> "Proposed"
                "active" -> "Active"
                "withdrawn" -> "Withdrawn"
                else -> throw IllegalArgumentException("status must be Proposed, Active, or Withdrawn")
            }
        }

        private data class VerifyingKeyPayload(val bytes: ByteArray?, val length: Long?)

        private fun normalizeVerifierBytes(bytes: ByteArray?, explicitLength: Long?): VerifyingKeyPayload? {
            if (bytes == null) {
                val length = explicitLength?.let { normalizePositiveU32(it, "vkLen") }
                return if (length == null) null else VerifyingKeyPayload(null, length)
            }
            require(bytes.isNotEmpty()) { "vkBytes must not be empty" }
            val actualLength = bytes.size.toLong()
            require(actualLength <= U32_MAX) { "vkBytes length must fit in a u32" }
            if (explicitLength != null) {
                val expected = normalizePositiveU32(explicitLength, "vkLen")
                require(expected == actualLength) { "vkLen must match vkBytes length" }
            }
            return VerifyingKeyPayload(bytes.copyOf(), actualLength)
        }

        @JvmStatic internal fun validateVerifyingKeyHeightRange(activationHeight: Long?, withdrawHeight: Long?) {
            val activation = normalizeOptionalNonNegative(activationHeight, "activationHeight")
            val withdraw = normalizeOptionalNonNegative(withdrawHeight, "withdrawHeight")
            require(activation == null || withdraw == null || withdraw >= activation) {
                "withdrawHeight must be greater than or equal to activationHeight"
            }
        }

        private fun validateVerifyingKeyMaterial(
            vkPayload: VerifyingKeyPayload?,
            commitmentHex: String?,
        ) {
            if (vkPayload?.bytes == null) {
                require(commitmentHex != null) { "commitmentHex is required when vkBytes is omitted" }
                require(vkPayload?.length != null) { "vkLen is required when vkBytes is omitted" }
            }
        }

        @JvmStatic internal fun validateInlineVerifyingKeyCommitment(backend: String, bytes: ByteArray?, commitmentHex: String?) {
            if (bytes == null || commitmentHex == null) return
            val expected = verifyingKeyCommitmentHex(backend, bytes)
            require(expected == commitmentHex) {
                "commitmentHex must match domain-separated SHA-256 of backend and vkBytes"
            }
        }

        @JvmStatic internal fun verifyingKeyCommitmentHex(
            backend: String,
            bytes: ByteArray,
        ): String {
            val digest = MessageDigest.getInstance("SHA-256")
            val backendBytes = backend.toByteArray(StandardCharsets.UTF_8)
            digest.update("iroha:zk:v1:vk".toByteArray(StandardCharsets.UTF_8))
            digest.update(u64Be(backendBytes.size.toLong()))
            digest.update(backendBytes)
            digest.update(u64Be(bytes.size.toLong()))
            digest.update(bytes)
            return hexLower(digest.digest())
        }

        private fun u64Be(value: Long): ByteArray {
            var remaining = value
            val out = ByteArray(8)
            for (index in 7 downTo 0) {
                out[index] = (remaining and 0xffL).toByte()
                remaining = remaining ushr 8
            }
            return out
        }

        private fun putOptionalVerifierFields(
            payload: MutableMap<String, Any>,
            curve: String?,
            maxProofBytes: Long?,
            metadataUriCid: String?,
            verifyingKeyBytesCid: String?,
            activationHeight: Long?,
            withdrawHeight: Long?,
            commitmentHex: String?,
            vkPayload: VerifyingKeyPayload?,
            status: String?,
        ) {
            curve?.let { payload["curve"] = normalizeNonBlank(it, "curve") }
            normalizeOptionalU32(maxProofBytes, "maxProofBytes")?.let { payload["max_proof_bytes"] = it }
            metadataUriCid?.let { payload["metadata_uri_cid"] = normalizeNonBlank(it, "metadataUriCid") }
            verifyingKeyBytesCid?.let { payload["vk_bytes_cid"] = normalizeNonBlank(it, "verifyingKeyBytesCid") }
            normalizeOptionalNonNegative(activationHeight, "activationHeight")?.let { payload["activation_height"] = it }
            normalizeOptionalNonNegative(withdrawHeight, "withdrawHeight")?.let { payload["withdraw_height"] = it }
            commitmentHex?.let { payload["commitment_hex"] = it }
            vkPayload?.bytes?.let { payload["vk_bytes"] = Base64.getEncoder().encodeToString(it) }
            vkPayload?.length?.let { payload["vk_len"] = it }
            normalizeVerifyingKeyStatus(status)?.let { payload["status"] = it }
        }

        private fun hexLower(bytes: ByteArray): String {
            val out = StringBuilder(bytes.size * 2)
            for (byte in bytes) {
                val value = byte.toInt() and 0xff
                if (value < 16) out.append('0')
                out.append(value.toString(16))
            }
            return out.toString()
        }
    }
}
