package org.hyperledger.iroha.sdk.client

import java.io.IOException
import java.net.URI
import java.nio.file.Path
import java.time.Duration
import java.util.Collections
import java.util.LinkedHashMap
import java.util.Optional
import org.hyperledger.iroha.sdk.crypto.KeyProvider
import org.hyperledger.iroha.sdk.client.queue.DirectoryPendingTransactionQueue
import org.hyperledger.iroha.sdk.client.queue.FilePendingTransactionQueue
import org.hyperledger.iroha.sdk.client.queue.PendingTransactionQueue
import org.hyperledger.iroha.sdk.telemetry.*

/** Configuration options for [IrohaClient] implementations. */
class ClientConfig private constructor(builder: Builder) {
    private val localSigningContext: LocalSigningContext? = builder.localSigningContext
    private val operatorSigningContext: OperatorSigningContext? = builder.operatorSigningContext
    private val canonicalAuth: ToriiCanonicalRequestAuth? = builder.canonicalAuth
    private val baseUri: URI = builder.baseUri
    private val sorafsGatewayUri: URI = builder.sorafsGatewayUri ?: builder.baseUri
    private val requestTimeout: Duration = builder.requestTimeout
    private val defaultHeaders: Map<String, String> = Collections.unmodifiableMap(LinkedHashMap(builder.defaultHeaders))
    private val wireFormatPreference: WireFormatPreference = builder.wireFormatPreference
    private val observers: List<ClientObserver>
    private val retryPolicy: RetryPolicy = builder.retryPolicy
    private val pendingQueue: PendingTransactionQueue? = builder.pendingQueue
    private val exportOptions: ExportOptions?
    private val noritoRpcFlowController: NoritoRpcFlowController = builder.noritoRpcFlowController ?: NoritoRpcFlowController.unlimited()
    private val telemetryOptions: TelemetryOptions = builder.telemetryOptions
    private val telemetrySink: TelemetrySink?
    private val telemetryExporterName: String
    private val networkContextProvider: NetworkContextProvider = builder.networkContextProvider
    private val deviceProfileProvider: DeviceProfileProvider = builder.deviceProfileProvider
    private val crashTelemetryEnabled: Boolean = builder.crashTelemetryEnabled
    private val crashMetadataProvider: MetadataProvider = builder.crashMetadataProvider
    private val crashTelemetryHandler: CrashTelemetryHandler?
    private val allowLocalDevelopmentHttp: Boolean = builder.allowLocalDevelopmentHttp

    init {
        if (canonicalAuth != null) {
            checkNotNull(localSigningContext) {
                "canonicalAuth requires a localSigningContext carrying the exact NetworkId"
            }
        }
        val resolvedExporterName = builder.resolveTelemetryExporterName()
        val instrumentedSink = if (builder.telemetrySink == null) null else TelemetryExportStatusSink.wrap(builder.telemetrySink, resolvedExporterName)
        val observerList = ArrayList(builder.observers)
        if (builder.telemetryOptions.enabled && instrumentedSink != null) observerList.add(TelemetryObserver(builder.telemetryOptions, instrumentedSink))
        observers = observerList.toList()
        val keystoreTelemetry = KeystoreTelemetryEmitter.from(builder.telemetryOptions, instrumentedSink, builder.deviceProfileProvider)
        exportOptions = builder.exportOptions?.withTelemetry(keystoreTelemetry)
        telemetrySink = instrumentedSink
        telemetryExporterName = resolvedExporterName
        crashTelemetryHandler = maybeInstallCrashTelemetryHandler(builder, instrumentedSink)
    }

    /** Local context used to validate server-prepared drafts before signing, when configured. */
    fun localSigningContext(): Optional<LocalSigningContext> =
        Optional.ofNullable(localSigningContext)

    internal fun requireLocalSigningContext(): LocalSigningContext =
        checkNotNull(localSigningContext) {
            "localSigningContext must be configured before signing a request or requesting a signing draft"
        }

    /** Immutable exact-network signer used only by operator-only Torii APIs. */
    fun operatorSigningContext(): Optional<OperatorSigningContext> =
        Optional.ofNullable(operatorSigningContext)

    internal fun requireOperatorSigningContext(): OperatorSigningContext =
        checkNotNull(operatorSigningContext) {
            "operatorSigningContext must be configured before an operator request"
        }

    /**
     * Default account identity for requests where a signature is optional, such as collection
     * queries (a signature only widens visibility into restricted dataspaces). `null` sends them
     * anonymously.
     */
    fun canonicalAuth(): ToriiCanonicalRequestAuth? = canonicalAuth

    fun baseUri(): URI = baseUri
    /** Base URI used for SoraFS gateway requests. Defaults to [baseUri] when unset. */
    fun sorafsGatewayUri(): URI = sorafsGatewayUri
    fun requestTimeout(): Duration = requestTimeout
    /** Headers that will be applied to every Torii request. */
    fun defaultHeaders(): Map<String, String> = defaultHeaders
    /** Wire-format preference used for dual-format Torii routes. */
    fun wireFormatPreference(): WireFormatPreference = wireFormatPreference
    /** Whether Torii HTTP requests may use the local transport exception described by [Builder.setAllowLocalDevelopmentHttp]. */
    fun allowLocalDevelopmentHttp(): Boolean = allowLocalDevelopmentHttp
    /** Registered observers that receive request lifecycle callbacks. */
    fun observers(): List<ClientObserver> = observers
    /** Policy available to caller-managed replay-safe reads; signed submissions ignore it. */
    fun retryPolicy(): RetryPolicy = retryPolicy
    /** Explicit local staging queue; [HttpClientTransport] never drains or fills it automatically. */
    fun pendingQueue(): PendingTransactionQueue? = pendingQueue
    fun exportOptions(): ExportOptions? = exportOptions
    fun noritoRpcFlowController(): NoritoRpcFlowController = noritoRpcFlowController
    fun telemetryOptions(): TelemetryOptions = telemetryOptions
    fun telemetrySink(): Optional<TelemetrySink> = Optional.ofNullable(telemetrySink)
    fun telemetryExporterName(): String = telemetryExporterName
    fun networkContextProvider(): NetworkContextProvider = networkContextProvider
    fun deviceProfileProvider(): DeviceProfileProvider = deviceProfileProvider
    fun crashTelemetryHandler(): Optional<CrashTelemetryHandler> = Optional.ofNullable(crashTelemetryHandler)

    fun crashTelemetryReporter(): Optional<CrashTelemetryReporter> {
        if (!telemetryOptions.enabled || telemetrySink == null) return Optional.empty()
        return Optional.of(CrashTelemetryReporter(telemetryOptions, telemetrySink))
    }

    fun toBuilder(): Builder {
        val nonTelemetryObservers = observers.filter { it !is TelemetryObserver }
        val builder = Builder()
            .setBaseUri(baseUri).setSorafsGatewayUri(sorafsGatewayUri).setRequestTimeout(requestTimeout)
            .setDefaultHeaders(defaultHeaders).setWireFormatPreference(wireFormatPreference)
            .setObservers(nonTelemetryObservers).setRetryPolicy(retryPolicy)
            .setPendingQueue(pendingQueue).setExportOptions(exportOptions).setNoritoRpcFlowController(noritoRpcFlowController)
            .setTelemetryOptions(telemetryOptions).setTelemetrySink(TelemetryExportStatusSink.unwrap(telemetrySink))
            .setTelemetryExporterName(telemetryExporterName).setNetworkContextProvider(networkContextProvider)
            .setDeviceProfileProvider(deviceProfileProvider).setCrashTelemetryMetadataProvider(crashMetadataProvider)
            .setCrashTelemetryEnabled(crashTelemetryEnabled)
            .setAllowLocalDevelopmentHttp(allowLocalDevelopmentHttp)
        localSigningContext?.let(builder::setLocalSigningContext)
        operatorSigningContext?.let(builder::setOperatorSigningContext)
        canonicalAuth?.let(builder::setCanonicalAuth)
        return builder
    }

    fun toNoritoRpcClient(executor: HttpTransportExecutor?): NoritoRpcClient {
        val b = toNoritoRpcClientBuilder()
        if (executor != null) b.setTransportExecutor(executor)
        return b.build()
    }

    fun toNoritoRpcClient(): NoritoRpcClient = toNoritoRpcClient(null)

    private fun toNoritoRpcClientBuilder(): NoritoRpcClient.Builder =
        NoritoRpcClient.builder().setBaseUri(baseUri).setTimeout(requestTimeout).defaultHeaders(defaultHeaders)
            .observers(observers).setTelemetryOptions(telemetryOptions).setTelemetrySink(telemetrySink)
            .setNetworkContextProvider(networkContextProvider).setDeviceProfileProvider(deviceProfileProvider)
            .setFlowController(noritoRpcFlowController).setWireFormatPreference(wireFormatPreference)
            .setAllowLocalDevelopmentHttp(allowLocalDevelopmentHttp)

    fun toConfidentialAssetToriiClient(executor: HttpTransportExecutor): ConfidentialAssetToriiClient =
        ConfidentialAssetToriiClient.builder().executor(executor).baseUri(baseUri)
            .localSigningContext(requireLocalSigningContext()).timeout(requestTimeout)
            .defaultHeaders(defaultHeaders).observers(observers)
            .setAllowLocalDevelopmentHttp(allowLocalDevelopmentHttp).build()

    fun toSubscriptionToriiClient(executor: HttpTransportExecutor): SubscriptionToriiClient =
        SubscriptionToriiClient.builder().executor(executor).baseUri(baseUri).timeout(requestTimeout)
            .defaultHeaders(defaultHeaders).observers(observers)
            .setAllowLocalDevelopmentHttp(allowLocalDevelopmentHttp).build()

    fun toSubscriptionToriiClient(): SubscriptionToriiClient = SubscriptionToriiClient.builder()
        .baseUri(baseUri).timeout(requestTimeout).defaultHeaders(defaultHeaders).observers(observers)
        .setAllowLocalDevelopmentHttp(allowLocalDevelopmentHttp).build()

    private fun maybeInstallCrashTelemetryHandler(builder: Builder, sink: TelemetrySink?): CrashTelemetryHandler? {
        if (!builder.crashTelemetryEnabled) return null
        if (!builder.telemetryOptions.enabled || sink == null) return null
        return CrashTelemetryHandler.install(builder.telemetryOptions, sink, builder.crashMetadataProvider)
    }

    class Builder {
        internal var localSigningContext: LocalSigningContext? = null
        internal var operatorSigningContext: OperatorSigningContext? = null
        internal var canonicalAuth: ToriiCanonicalRequestAuth? = null
        internal var baseUri: URI = URI.create("http://localhost:8080")
        internal var sorafsGatewayUri: URI? = null
        internal var requestTimeout: Duration = Duration.ofSeconds(10)
        internal val defaultHeaders = LinkedHashMap<String, String>()
        internal var wireFormatPreference: WireFormatPreference = WireFormatPreference.NORITO_PREFERRED
        internal val observers = ArrayList<ClientObserver>()
        internal var retryPolicy: RetryPolicy = RetryPolicy.none()
        internal var pendingQueue: PendingTransactionQueue? = null
        internal var exportOptions: ExportOptions? = null
        internal var noritoRpcFlowController: NoritoRpcFlowController? = NoritoRpcFlowController.unlimited()
        internal var telemetryOptions: TelemetryOptions = TelemetryOptions.disabled()
        internal var telemetrySink: TelemetrySink? = null
        internal var telemetryExporterName: String? = null
        internal var networkContextProvider: NetworkContextProvider = NetworkContextProvider.disabled()
        internal var deviceProfileProvider: DeviceProfileProvider = DeviceProfileProvider.disabled()
        internal var crashTelemetryEnabled: Boolean = false
        internal var crashMetadataProvider: MetadataProvider = CrashTelemetryHandler.defaultMetadataProvider()
        internal var allowLocalDevelopmentHttp: Boolean = false

        /** Enables local draft signing with one immutable, caller-owned network context. */
        fun setLocalSigningContext(context: LocalSigningContext): Builder {
            this.localSigningContext = context
            return this
        }
        /** Enables fresh exact-network signing for operator-only Torii APIs. */
        fun setOperatorSigningContext(context: OperatorSigningContext): Builder {
            this.operatorSigningContext = context
            return this
        }
        /**
         * Sign requests whose signature is optional (collection queries) with [auth]. Requires a
         * [LocalSigningContext]; [auth] must use per-request freshness (no explicit nonce).
         */
        fun setCanonicalAuth(auth: ToriiCanonicalRequestAuth?): Builder {
            require(auth == null || !auth.hasExplicitFreshness) {
                "a client-wide canonicalAuth signs many requests; omit timestampMs/nonce"
            }
            this.canonicalAuth = auth
            return this
        }

        fun setBaseUri(baseUri: URI): Builder { this.baseUri = baseUri; return this }
        fun setSorafsGatewayUri(sorafsGatewayUri: URI): Builder { this.sorafsGatewayUri = sorafsGatewayUri; return this }
        fun setRequestTimeout(requestTimeout: Duration?): Builder { if (requestTimeout != null && !requestTimeout.isNegative) this.requestTimeout = requestTimeout; return this }
        fun putDefaultHeader(name: String, value: String): Builder { defaultHeaders[name] = value; return this }
        fun clearDefaultHeaders(): Builder { defaultHeaders.clear(); return this }
        fun setDefaultHeaders(headers: Map<String, String>?): Builder { clearDefaultHeaders(); headers?.forEach { (k, v) -> putDefaultHeader(k, v) }; return this }
        fun setWireFormatPreference(preference: WireFormatPreference): Builder { this.wireFormatPreference = preference; return this }
        /**
         * Allows Torii HTTP requests carrying signatures or credentials over plain HTTP to
         * `localhost` (including `*.localhost`), loopback literals (`127.0.0.0/8`, `::1`), and private IPv4 literals
         * (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, including emulator host `10.0.2.2`).
         * The request must retain the configured HTTP scheme, host, and effective port.
         * Enable only in development builds. This option is off by default and inherited by HTTP clients from this config
         * or [HttpClientTransport], including event streams. WebSockets and SoraFS gateways keep
         * their separate secure-transport requirements.
         */
        fun setAllowLocalDevelopmentHttp(allow: Boolean): Builder { this.allowLocalDevelopmentHttp = allow; return this }
        fun addObserver(observer: ClientObserver): Builder { observers.add(observer); return this }
        fun clearObservers(): Builder { observers.clear(); return this }
        fun setObservers(observers: List<ClientObserver>?): Builder { clearObservers(); observers?.forEach { addObserver(it) }; return this }
        /** Configures caller-managed replay-safe read retries; one-shot requests ignore it. */
        fun setRetryPolicy(retryPolicy: RetryPolicy): Builder { this.retryPolicy = retryPolicy; return this }
        /** Configures explicit local staging only; submission never drains or fills this queue. */
        fun setPendingQueue(pendingQueue: PendingTransactionQueue?): Builder { this.pendingQueue = pendingQueue; return this }

        /** Enables an explicit directory-backed staging queue; submission never replays it. */
        fun enableDirectoryPendingQueue(rootDir: Path): Builder {
            try { pendingQueue = DirectoryPendingTransactionQueue(rootDir) }
            catch (ex: IOException) { throw IllegalStateException("Failed to initialise directory pending queue", ex) }
            return this
        }

        /** Enables an explicit file-backed staging queue; submission never replays it. */
        fun enableFilePendingQueue(queueFile: Path): Builder {
            try { pendingQueue = FilePendingTransactionQueue(queueFile) }
            catch (ex: IOException) { throw IllegalStateException("Failed to initialise file pending queue", ex) }
            return this
        }

        fun setExportOptions(exportOptions: ExportOptions?): Builder { this.exportOptions = exportOptions; return this }
        fun setNoritoRpcFlowController(flowController: NoritoRpcFlowController): Builder { this.noritoRpcFlowController = flowController; return this }
        fun setNoritoRpcMaxConcurrentRequests(maxConcurrentRequests: Int): Builder { this.noritoRpcFlowController = NoritoRpcFlowController.semaphore(maxConcurrentRequests); return this }
        fun setTelemetryOptions(telemetryOptions: TelemetryOptions): Builder { this.telemetryOptions = telemetryOptions; return this }
        fun setTelemetrySink(telemetrySink: TelemetrySink?): Builder { this.telemetrySink = telemetrySink; return this }
        fun setTelemetryExporterName(exporterName: String?): Builder { this.telemetryExporterName = exporterName?.trim(); return this }
        fun setNetworkContextProvider(provider: NetworkContextProvider): Builder { this.networkContextProvider = provider; return this }
        fun setDeviceProfileProvider(provider: DeviceProfileProvider): Builder { this.deviceProfileProvider = provider; return this }
        fun enableCrashTelemetryHandler(): Builder { crashTelemetryEnabled = true; return this }
        internal fun setCrashTelemetryEnabled(enabled: Boolean): Builder { crashTelemetryEnabled = enabled; return this }
        fun setCrashTelemetryMetadataProvider(metadataProvider: MetadataProvider): Builder { this.crashMetadataProvider = metadataProvider; return this }
        fun build(): ClientConfig = ClientConfig(this)

        internal fun resolveTelemetryExporterName(): String {
            val candidate = telemetryExporterName?.trim() ?: ""
            if (candidate.isNotEmpty()) return candidate
            if (telemetrySink != null) {
                val simpleName = telemetrySink!!.javaClass.simpleName
                if (!simpleName.isNullOrEmpty()) return simpleName
            }
            return "android_sdk"
        }
    }

    /** Options controlling deterministic key exports for queued transactions. */
    class ExportOptions private constructor(
        private val keyManager: KeyProvider,
        private val passphraseProvider: PassphraseProvider?
    ) {
        fun keyManager(): KeyProvider = keyManager

        internal fun withTelemetry(telemetry: KeystoreTelemetryEmitter?): ExportOptions {
            if (telemetry == null) return this
            return this
        }

        fun passphraseForAlias(alias: String): CharArray {
            if (passphraseProvider == null) return CharArray(0)
            return passphraseProvider.passphraseForAlias(alias) ?: CharArray(0)
        }

        fun interface PassphraseProvider {
            fun passphraseForAlias(alias: String): CharArray?
        }

        class Builder {
            private var keyManager: KeyProvider? = null
            private var passphraseProvider: PassphraseProvider? = null
            fun setKeyManager(keyManager: KeyProvider): Builder { this.keyManager = keyManager; return this }
            fun setPassphrase(passphrase: CharArray?): Builder {
                if (passphrase == null) { passphraseProvider = null } else { val base = passphrase.clone(); passphraseProvider = PassphraseProvider { base.clone() } }
                return this
            }
            fun setPassphraseProvider(provider: PassphraseProvider?): Builder { passphraseProvider = provider; return this }
            fun build(): ExportOptions = ExportOptions(keyManager!!, passphraseProvider)
        }

        companion object {
            @JvmStatic fun builder(): Builder = Builder()
        }
    }

    companion object {
        @JvmStatic fun builder(): Builder = Builder()
    }
}
