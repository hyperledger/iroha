package org.hyperledger.iroha.android.client;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiFunction;
import java.util.function.Function;
import org.hyperledger.iroha.android.alias.AccountAliasName;
import org.hyperledger.iroha.android.alias.AliasSetupPlanRequestV1;
import org.hyperledger.iroha.android.alias.AliasAutoRenewPlanRequestV1;
import org.hyperledger.iroha.android.alias.AliasLeaseRenewPlanRequestV1;
import org.hyperledger.iroha.android.alias.AliasLifecyclePlanRequestV1;
import org.hyperledger.iroha.android.alias.AliasLifecycleTransactionPlanJsonParser;
import org.hyperledger.iroha.android.alias.AliasLifecycleTransactionPlanV1;
import org.hyperledger.iroha.android.alias.AliasSetupModels;
import org.hyperledger.iroha.android.alias.AccountOnboardingJsonParser;
import org.hyperledger.iroha.android.alias.AccountOnboardingPlanReceiptV1;
import org.hyperledger.iroha.android.alias.AccountOnboardingPlanRequestV1;
import org.hyperledger.iroha.android.alias.AccountOnboardingPrepareRequestV1;
import org.hyperledger.iroha.android.alias.AccountOnboardingPrepareResponseV1;
import org.hyperledger.iroha.android.alias.AccountOnboardingPreparedTransactionV1;
import org.hyperledger.iroha.android.alias.AccountOnboardingProofRequiredPrepareResponseV1;
import org.hyperledger.iroha.android.alias.AccountOnboardingCurrentStateRequestV1;
import org.hyperledger.iroha.android.alias.AccountOnboardingCurrentStateV1;
import org.hyperledger.iroha.android.alias.AccountFaucetClaimV1;
import org.hyperledger.iroha.android.alias.AccountFaucetPolicyV1;
import org.hyperledger.iroha.android.alias.AccountFaucetPrepareRequestV1;
import org.hyperledger.iroha.android.alias.AccountFaucetPreparedTransactionV1;
import org.hyperledger.iroha.android.alias.AccountFaucetPreparedVerifier;
import org.hyperledger.iroha.android.alias.AccountOnboardingPreparedVerifier;
import org.hyperledger.iroha.android.alias.AccountOnboardingReceiptVerifier;
import org.hyperledger.iroha.android.alias.PreparedTransactionSubmitResponseV1;
import org.hyperledger.iroha.android.alias.PreparedOperationBindingV1;
import org.hyperledger.iroha.android.alias.AliasTransactionPlanJsonParser;
import org.hyperledger.iroha.android.alias.AliasTransactionPlanV1;
import org.hyperledger.iroha.android.address.AccountAddress;
import org.hyperledger.iroha.android.address.AccountIdLiteral;
import org.hyperledger.iroha.android.crypto.Blake3;
import org.hyperledger.iroha.sdk.crypto.Ed25519PublicKeyAdmission;
import org.hyperledger.iroha.android.crypto.IrohaHash;
import org.hyperledger.iroha.android.nexus.UaidBindingsQuery;
import org.hyperledger.iroha.android.nexus.UaidBindingsResponse;
import org.hyperledger.iroha.android.nexus.UaidJsonParser;
import org.hyperledger.iroha.android.nexus.UaidLiteral;
import org.hyperledger.iroha.android.nexus.UaidManifestQuery;
import org.hyperledger.iroha.android.nexus.UaidManifestsResponse;
import org.hyperledger.iroha.android.nexus.UaidPortfolioQuery;
import org.hyperledger.iroha.android.nexus.UaidPortfolioResponse;
import org.hyperledger.iroha.android.model.zk.VerifyingKeyBackendTag;
import org.hyperledger.iroha.android.model.FeePaymentIntent;
import org.hyperledger.iroha.android.model.FeeSponsorProgramId;
import org.hyperledger.iroha.android.model.Executable;
import org.hyperledger.iroha.android.model.JsonValue;
import org.hyperledger.iroha.android.model.NetworkId;
import org.hyperledger.iroha.android.model.TransactionPayload;
import org.hyperledger.iroha.android.norito.NoritoJavaCodecAdapter;
import org.hyperledger.iroha.android.sorafs.GatewayFetchRequest;
import org.hyperledger.iroha.android.sorafs.GatewayFetchSummary;
import org.hyperledger.iroha.android.sorafs.SorafsGatewayClient;
import org.hyperledger.iroha.sdk.privacy.PrivacyNativeBridge;
import org.hyperledger.iroha.sdk.privacy.PrivacyProtocolIdV1;
import org.hyperledger.iroha.android.telemetry.DeviceProfile;
import org.hyperledger.iroha.android.telemetry.DeviceProfileProvider;
import org.hyperledger.iroha.android.telemetry.NetworkContext;
import org.hyperledger.iroha.android.telemetry.NetworkContextProvider;
import org.hyperledger.iroha.android.telemetry.TelemetryOptions;
import org.hyperledger.iroha.android.telemetry.TelemetrySink;
import org.hyperledger.iroha.sdk.privacy.PrivacyExact12CapabilityAdmissionV1;
import org.hyperledger.iroha.sdk.privacy.PrivacyExact12CapabilityManifestV1;
import org.hyperledger.iroha.sdk.privacy.PrivacyExact12CapabilityTupleAdmissionV1;
import org.hyperledger.iroha.android.client.stream.ToriiEventStreamClient;
import org.hyperledger.iroha.android.tx.SignedTransaction;
import org.hyperledger.iroha.android.tx.SignedTransactionHasher;
import org.hyperledger.iroha.android.client.HttpTransportExecutor;
import org.hyperledger.iroha.android.client.transport.TransportRequest;
import org.hyperledger.iroha.android.client.transport.TransportResponse;
import org.hyperledger.iroha.sdk.client.ParliamentTimedOvnCastingCheckpointPersisterV1;
import org.hyperledger.iroha.sdk.client.ParliamentTimedOvnCastingProofPageVerificationV1;
import org.hyperledger.iroha.sdk.client.ParliamentTimedOvnCastingProofPageVerifierV1;
import org.hyperledger.iroha.sdk.client.ParliamentTimedOvnCastingProofResponseV1;
import org.hyperledger.iroha.sdk.client.ParliamentTimedOvnCastingProofTerminalV1;

/**
 * HTTP-based client implementation that will forward transactions to an Iroha Torii endpoint.
 *
 * <p>Serialization and endpoint construction follow the `/v1/pipeline/transactions` Torii route.
 * Network execution is delegated to {@link HttpTransportExecutor} so tests can run without making
 * outbound calls.
 */
public final class HttpClientTransport implements IrohaClient {
  private static final String ONBOARDING_TOKEN_HEADER = "X-Iroha-Onboarding-Token";

  private static final String PIPELINE_STATUS_SIGNAL = "android.torii.pipeline.status";
  private static final String REDACTION_FAILURE_SIGNAL = "android.telemetry.redaction.failure";
  private static final long U32_MAX = 4_294_967_295L;
  private static final String ENTRYPOINT_HASH_HEADER = "x-iroha-entrypoint-hash";

  private final HttpTransportExecutor executor;
  private final ClientConfig config;
  private volatile SorafsGatewayClient sorafsGatewayClient;
  private final AtomicBoolean deviceProfileEmitted = new AtomicBoolean(false);

  public HttpClientTransport(final HttpTransportExecutor executor, final ClientConfig config) {
    this.executor = Objects.requireNonNull(executor, "executor");
    this.config = Objects.requireNonNull(config, "config");
  }

  @Override
  public CompletableFuture<ClientResponse> submitTransaction(final SignedTransaction transaction) {
    Objects.requireNonNull(transaction, "transaction");
    final String hashHex = SignedTransactionHasher.hashHex(transaction);
    return submitOnce(transaction, hashHex);
  }

  @Override
  public CompletableFuture<ClientResponse> submitTransactionJson(
      final byte[] encodedVersionedTransactionJson) {
    final TransportRequest request =
        ToriiRequestBuilder.buildSubmitJsonRequest(
            config.baseUri(),
            encodedVersionedTransactionJson,
            config.requestTimeout(),
            config.defaultHeaders(),
            config.wireFormatPreference().acceptHeader());
    return ensureTransactionSubmissionCompatibility()
        .thenCompose(
            ignored -> executeAccepted(request, "transaction JSON submit", 202));
  }

  @Override
  public CompletableFuture<ClientResponse> submitTransactionEntrypoint(
      final byte[] encodedVersionedEntrypoint) {
    final TransportRequest request =
        ToriiRequestBuilder.buildSubmitEntrypointRequest(
            config.baseUri(),
            encodedVersionedEntrypoint,
            config.requestTimeout(),
            config.defaultHeaders(),
            config.wireFormatPreference().acceptHeader());
    return ensureTransactionSubmissionCompatibility()
        .thenCompose(
            ignored -> {
              notifyRequest(request);
              return executor
                  .execute(request)
                  .handle(
                      (response, throwable) -> {
                        if (throwable != null) {
                          final Throwable cause = unwrapCompletion(throwable);
                          notifyFailure(request, cause);
                          final CompletableFuture<ClientResponse> failed =
                              new CompletableFuture<>();
                          failed.completeExceptionally(cause);
                          return failed;
                        }
                        final ClientResponse clientResponse =
                            new ClientResponse(
                                response.statusCode(),
                                response.body(),
                                response.message(),
                                extractEntrypointHash(response).orElse(null),
                                extractRejectCode(response));
                        if (clientResponse.statusCode() < 200
                            || clientResponse.statusCode() >= 300) {
                          notifyFailure(
                              request,
                              new RuntimeException(
                                  "Torii request failed with status "
                                      + clientResponse.statusCode()));
                        } else {
                          notifyResponse(request, clientResponse);
                        }
                        return CompletableFuture.completedFuture(clientResponse);
                      })
                  .thenCompose(future -> future);
            });
  }

  @Override
  public CompletableFuture<ClientResponse> submitTransactionEntrypointJson(
      final byte[] encodedVersionedEntrypointJson) {
    final TransportRequest request =
        ToriiRequestBuilder.buildSubmitEntrypointJsonRequest(
            config.baseUri(),
            encodedVersionedEntrypointJson,
            config.requestTimeout(),
            config.defaultHeaders(),
            config.wireFormatPreference().acceptHeader());
    return ensureTransactionSubmissionCompatibility()
        .thenCompose(
            ignored ->
                executeAccepted(
                    request, "transaction entrypoint JSON submit", 202));
  }

  private CompletableFuture<ClientResponse> executeAccepted(
      final TransportRequest request, final String errorContext, final int acceptedStatus) {
    notifyRequest(request);
    final CompletableFuture<ClientResponse> future = new CompletableFuture<>();
    executor
        .execute(request)
        .whenComplete(
            (response, throwable) -> {
              if (throwable != null) {
                final Throwable cause =
                    throwable instanceof CompletionException ? throwable.getCause() : throwable;
                notifyFailure(request, cause);
                future.completeExceptionally(
                    new RuntimeException(errorContext + " request failed", cause));
                return;
              }
              final ClientResponse clientResponse =
                  new ClientResponse(
                      response.statusCode(),
                      response.body(),
                      response.message(),
                      null,
                      extractRejectCode(response));
              if (response.statusCode() != acceptedStatus) {
                final RuntimeException error =
                    new RuntimeException(
                        errorContext + " request failed with status " + response.statusCode());
                notifyFailure(request, error);
                future.completeExceptionally(error);
                return;
              }
              notifyResponse(request, clientResponse);
              future.complete(clientResponse);
            });
    return future;
  }

  @Override
  public CompletableFuture<Map<String, Object>> waitForTransactionStatus(
      final String hashHex, final PipelineStatusOptions options) {
    Objects.requireNonNull(hashHex, "hashHex");
    final PipelineStatusOptions resolved = PipelineStatusOptions.resolve(options);
    final long deadline = saturatedDeadline(resolved.timeoutMillis());
    final CompletableFuture<Map<String, Object>> future = new CompletableFuture<>();
    pollPipelineStatus(hashHex, resolved, deadline, 0, null, future);
    return future;
  }

  public ClientConfig config() {
    return config;
  }

  /**
   * Cancels in-flight HTTP requests and releases any underlying resources held by the executor.
   *
   * <p>This is a no-op for executors that do not expose lifecycle hooks.</p>
   */
  public void invalidateAndCancel() {
    executor.invalidateAndCancel();
  }

  /** Creates a Norito RPC client that reuses this transport's configuration (and HTTP client when possible). */
  public NoritoRpcClient newNoritoRpcClient() {
    return config.toNoritoRpcClient(executor);
  }

  /** Creates a streaming client without a canonical account identity. */
  public ToriiEventStreamClient newEventStreamClient() {
    return newEventStreamClientBuilder().build();
  }

  /** Creates a streaming client that signs each exact final request URI. */
  public ToriiEventStreamClient newEventStreamClient(
      final ToriiCanonicalRequestAuth canonicalAuth) {
    return newEventStreamClientBuilder()
        .canonicalRequestAuth(
            config.requireLocalSigningContext(),
            Objects.requireNonNull(canonicalAuth, "canonicalAuth"))
        .build();
  }

  private ToriiEventStreamClient.Builder newEventStreamClientBuilder() {
    return ToriiEventStreamClient.builder()
        .setBaseUri(config.baseUri())
        .setTransportExecutor(executor)
        .defaultHeaders(config.defaultHeaders())
        .observers(config.observers());
  }

  /** Creates a typed DA proof client that reuses this transport's configuration. */
  public DaToriiClient newDaToriiClient() {
    return DaToriiClient.builder()
        .setExecutor(executor)
        .setBaseUri(config.baseUri())
        .setTimeout(config.requestTimeout())
        .setDefaultHeaders(config.defaultHeaders())
        .setObservers(config.observers())
        .build();
  }

  /**
   * Creates the exact-route private-settlement client without inheriting request observers.
   *
   * <p>Restricted proof and encrypted-capsule bodies must not enter generic SDK telemetry.
   */
  public AtomicPrivateSettlementToriiClientV1 newAtomicPrivateSettlementToriiClientV1() {
    return AtomicPrivateSettlementToriiClientV1.builder()
        .executor(executor)
        .baseUri(config.baseUri())
        .localSigningContext(config.requireLocalSigningContext())
        .timeout(config.requestTimeout())
        .defaultHeaders(config.defaultHeaders())
        .build();
  }

  /** Creates a SoraFS gateway client that reuses this transport's HTTP executor and configuration. */
  public SorafsGatewayClient newSorafsGatewayClient() {
    return newSorafsGatewayClient(config.sorafsGatewayUri());
  }

  /**
   * Creates a SoraFS gateway client targeting {@code baseUri} while reusing this transport's
   * executor, timeout, headers, and observers.
   */
  public SorafsGatewayClient newSorafsGatewayClient(final URI baseUri) {
    final SorafsGatewayClient.Builder builder =
        SorafsGatewayClient.builder()
            .setExecutor(executor)
            .setBaseUri(Objects.requireNonNull(baseUri, "baseUri"))
            .setTimeout(config.requestTimeout())
            .setDefaultHeaders(config.defaultHeaders())
            .setObservers(config.observers());
    return builder.build();
  }

  /** Returns the SoraFS gateway client wired to this transport's configuration. */
  public SorafsGatewayClient sorafsGatewayClient() {
    SorafsGatewayClient client = sorafsGatewayClient;
    if (client == null) {
      synchronized (this) {
        client = sorafsGatewayClient;
        if (client == null) {
          client = newSorafsGatewayClient(config.sorafsGatewayUri());
          sorafsGatewayClient = client;
        }
      }
    }
    return client;
  }

  /** Post a gateway fetch request and return the raw response. */
  public CompletableFuture<ClientResponse> sorafsGatewayFetch(final GatewayFetchRequest request) {
    return sorafsGatewayClient().fetch(request);
  }

  /** Post a gateway fetch request and parse the response summary. */
  public CompletableFuture<GatewayFetchSummary> sorafsGatewayFetchSummary(
      final GatewayFetchRequest request) {
    return sorafsGatewayClient().fetchSummary(request);
  }

  /** Fetches `/v1/accounts/{uaid}/portfolio`. */
  public CompletableFuture<UaidPortfolioResponse> getUaidPortfolio(final String uaid) {
    return getUaidPortfolio(uaid, null);
  }

  /** Fetches `/v1/accounts/{uaid}/portfolio` with optional query parameters. */
  public CompletableFuture<UaidPortfolioResponse> getUaidPortfolio(
      final String uaid, final UaidPortfolioQuery query) {
    final String canonical = UaidLiteral.canonicalize(uaid, "uaid portfolio");
    final Map<String, String> params =
        query == null ? Collections.emptyMap() : query.toQueryParameters();
    final TransportRequest request =
        buildJsonGetRequest(
            "/v1/accounts/" + encodePathSegment(canonical) + "/portfolio", params);
    return fetchJson(request, UaidJsonParser::parsePortfolio, "UAID portfolio");
  }

  /** Fetches `/v1/space-directory/uaids/{uaid}` bindings. */
  public CompletableFuture<UaidBindingsResponse> getUaidBindings(final String uaid) {
    return getUaidBindings(uaid, null);
  }

  /** Fetches `/v1/space-directory/uaids/{uaid}` bindings with query parameters. */
  public CompletableFuture<UaidBindingsResponse> getUaidBindings(
      final String uaid, final UaidBindingsQuery query) {
    final String canonical = UaidLiteral.canonicalize(uaid, "uaid bindings");
    final Map<String, String> params =
        query == null ? Collections.emptyMap() : query.toQueryParameters();
    final TransportRequest request =
        buildJsonGetRequest(
            "/v1/space-directory/uaids/" + encodePathSegment(canonical), params);
    return fetchJson(request, UaidJsonParser::parseBindings, "UAID bindings");
  }

  /** Fetches `/v1/space-directory/uaids/{uaid}/manifests`. */
  public CompletableFuture<UaidManifestsResponse> getUaidManifests(
      final String uaid, final UaidManifestQuery query) {
    final String canonical = UaidLiteral.canonicalize(uaid, "uaid manifests");
    final Map<String, String> params =
        query == null ? Collections.emptyMap() : query.toQueryParameters();
    final TransportRequest request =
        buildJsonGetRequest(
            "/v1/space-directory/uaids/" + encodePathSegment(canonical) + "/manifests", params);
    return fetchJson(request, UaidJsonParser::parseManifests, "UAID manifests");
  }

  /** Fetches globally registered identifier policies from `/v1/identifier-policies`. */
  public CompletableFuture<IdentifierPolicyListResponse> listIdentifierPolicies() {
    final TransportRequest request =
        buildJsonGetRequest("/v1/identifier-policies", Collections.emptyMap());
    return fetchJson(request, IdentifierJsonParser::parsePolicyList, "identifier policy list");
  }

  /** Fetches globally registered RAM-LFE program policies from `/v1/ram-lfe/program-policies`. */
  public CompletableFuture<RamLfeProgramPolicyListResponse> listRamLfeProgramPolicies() {
    final TransportRequest request =
        buildJsonGetRequest("/v1/ram-lfe/program-policies", Collections.emptyMap());
    return fetchJson(request, RamLfeJsonParser::parsePolicyList, "ram-lfe program policy list");
  }

  /** Fetch the exact result-bearing {@code SignedBlockWire} committed at {@code height}. */
  public CompletableFuture<byte[]> getLedgerExecutedBlockWire(final BigInteger height) {
    if (height == null || height.signum() <= 0 || height.bitLength() > 64) {
      throw new IllegalArgumentException("height must be a positive u64");
    }
    final TransportRequest request =
        buildExactNoritoGetRequest(
            "/v1/ledger/block/" + height.toString(), EXECUTED_BLOCK_WIRE_MAX_BYTES);
    return fetchExactNoritoBytes(request, "executed block wire");
  }

  /** Convenience overload for positive signed heights. */
  public CompletableFuture<byte[]> getLedgerExecutedBlockWire(final long height) {
    return getLedgerExecutedBlockWire(BigInteger.valueOf(height));
  }

  /** Fetch the exact committed Exact12 manifest with one-shot canonical account authentication. */
  public CompletableFuture<PrivacyExact12CapabilityManifestV1> getPrivacyCapabilities(
      final ToriiCanonicalRequestAuth canonicalAuth) {
    return fetchExactNoritoBytes(
            buildExactNoritoGetRequest(
                "/v1/privacy/capabilities",
                (long) PrivacyExact12CapabilityManifestV1.MAX_ARCHIVE_BYTES,
                Objects.requireNonNull(canonicalAuth, "canonicalAuth")),
            "privacy capabilities")
        .thenApply(PrivacyNativeBridge::decodeExact12CapabilityManifestV1);
  }

  /**
   * Require committed/native tuple agreement before retained privacy construction, authenticated
   * against the exact locally configured network.
   */
  public CompletableFuture<PrivacyExact12CapabilityTupleAdmissionV1>
      requirePrivacyExact12CapabilityAdmission(
          final PrivacyProtocolIdV1 protocolId,
          final ToriiCanonicalRequestAuth canonicalAuth) {
    return getPrivacyCapabilities(canonicalAuth)
        .thenApply(
            manifest ->
                PrivacyExact12CapabilityAdmissionV1.requireExact12CapabilityTupleV1(
                    manifest,
                    protocolId));
  }

  /** Fetches a persisted identifier claim by its deterministic receipt hash. */
  public CompletableFuture<Optional<IdentifierClaimRecord>> getIdentifierClaimByReceiptHash(
      final String receiptHash) {
    final String normalizedReceiptHash = normalizeHex32(receiptHash, "receiptHash");
    final TransportRequest request =
        buildJsonGetRequest(
            "/v1/identifiers/receipts/" + encodePathSegment(normalizedReceiptHash),
            Collections.emptyMap());
    return fetchJsonAllowingNotFound(
        request, IdentifierJsonParser::parseClaimRecord, "identifier claim lookup");
  }

  /** Resolves an identifier using a typed request wrapper. */
  public CompletableFuture<Optional<IdentifierResolutionReceipt>> resolveIdentifier(
      final IdentifierResolveRequest requestBody,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    Objects.requireNonNull(requestBody, "requestBody");
    final byte[] body =
        encodeJsonBody(
            buildIdentifierResolvePayload(
                requestBody.policyId(),
                requestBody.encryptedInputHex(),
                requestBody.outputOpening()));
    final TransportRequest request =
        buildVpnRequest("POST", "/v1/identifiers/resolve", body, canonicalAuth);
    return fetchJsonAllowingNotFound(
        request, IdentifierJsonParser::parseResolutionReceipt, "identifier resolve");
  }

  /** Resolves a hidden identifier by posting encrypted input and a verified output opening. */
  public CompletableFuture<Optional<IdentifierResolutionReceipt>> resolveIdentifier(
      final String policyId,
      final String encryptedInputHex,
      final RamLfeOutputOpening outputOpening,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    return resolveIdentifier(
        IdentifierResolveRequest.encrypted(policyId, encryptedInputHex, outputOpening),
        canonicalAuth);
  }

  /** Issues a claim receipt using a typed request wrapper. */
  public CompletableFuture<Optional<IdentifierResolutionReceipt>> issueIdentifierClaimReceipt(
      final String accountId,
      final IdentifierResolveRequest requestBody,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    Objects.requireNonNull(requestBody, "requestBody");
    final String normalizedAccountId =
        org.hyperledger.iroha.android.address.AccountIdLiteral.requireCanonicalI105Address(
            accountId, "accountId");
    if (!normalizedAccountId.equals(canonicalAuth.accountId())) {
      throw new IllegalArgumentException(
          "canonicalAuth.accountId must equal the claim-receipt path accountId");
    }
    final byte[] body =
        encodeJsonBody(
            buildIdentifierResolvePayload(
                requestBody.policyId(),
                requestBody.encryptedInputHex(),
                requestBody.outputOpening()));
    final TransportRequest request =
        buildVpnRequest(
            "POST",
            "/v1/accounts/"
                + encodePathSegment(normalizedAccountId)
                + "/identifiers/claim-receipt",
            body,
            canonicalAuth);
    return fetchJsonAllowingNotFound(
        request, IdentifierJsonParser::parseResolutionReceipt, "identifier claim receipt");
  }

  /** Issues a claim receipt by posting encrypted input and a verified output opening. */
  public CompletableFuture<Optional<IdentifierResolutionReceipt>> issueIdentifierClaimReceipt(
      final String accountId,
      final String policyId,
      final String encryptedInputHex,
      final RamLfeOutputOpening outputOpening,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    return issueIdentifierClaimReceipt(
        accountId,
        IdentifierResolveRequest.encrypted(policyId, encryptedInputHex, outputOpening),
        canonicalAuth);
  }

  /** Executes a RAM-LFE program using a typed request wrapper. */
  public CompletableFuture<Optional<RamLfeExecuteResponse>> executeRamLfeProgram(
      final String programId,
      final RamLfeExecuteRequest requestBody,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    Objects.requireNonNull(requestBody, "requestBody");
    final String normalizedProgramId = normalizeNonBlank(programId, "programId");
    final byte[] body =
        encodeJsonBody(buildRamLfeExecutePayload(requestBody.encryptedInputHex()));
    final TransportRequest request =
        buildVpnRequest(
            "POST",
            "/v1/ram-lfe/programs/" + encodePathSegment(normalizedProgramId) + "/execute",
            body,
            canonicalAuth);
    return fetchJsonAllowingNotFound(
        request, RamLfeJsonParser::parseExecuteResponse, "ram-lfe execute");
  }

  /**
   * Executes a RAM-LFE program by posting BFV ciphertext hex to
   * `/v1/ram-lfe/programs/{program_id}/execute`.
   */
  public CompletableFuture<Optional<RamLfeExecuteResponse>> executeRamLfeProgram(
      final String programId,
      final String encryptedInputHex,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    return executeRamLfeProgram(
        programId, buildRamLfeExecuteRequest(encryptedInputHex), canonicalAuth);
  }

  /** Verifies a RAM-LFE execution receipt against the node's registered program policy. */
  public CompletableFuture<RamLfeReceiptVerifyResponse> verifyRamLfeReceipt(
      final RamLfeReceiptVerifyRequest requestBody,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    Objects.requireNonNull(requestBody, "requestBody");
    final byte[] body =
        encodeJsonBody(
            buildRamLfeReceiptVerifyPayload(requestBody.receipt(), requestBody.outputHex()));
    final TransportRequest request =
        buildVpnRequest("POST", "/v1/ram-lfe/receipts/verify", body, canonicalAuth);
    return fetchJson(
        request, RamLfeJsonParser::parseReceiptVerifyResponse, "ram-lfe receipt verify");
  }

  /** Verifies a RAM-LFE execution receipt against the node's registered program policy. */
  public CompletableFuture<RamLfeReceiptVerifyResponse> verifyRamLfeReceipt(
      final Map<String, Object> receipt,
      final String outputHex,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    return verifyRamLfeReceipt(
        new RamLfeReceiptVerifyRequest(receipt, outputHex), canonicalAuth);
  }

  /** Fetches the public Sora VPN profile. */
  public CompletableFuture<VpnProfile> getVpnProfile() {
    requireSecureVpnBaseUri();
    final TransportRequest request =
        buildJsonGetRequest("/v1/vpn/profile", Collections.emptyMap());
    return fetchJson(request, VpnJsonParser::parseProfile, "vpn profile", 200);
  }

  /** Creates a signed quote for a native XOR VPN lease escrow. */
  public CompletableFuture<VpnQuote> createVpnQuote(
      final VpnQuoteCreateRequest requestBody,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    Objects.requireNonNull(requestBody, "requestBody");
    final byte[] body =
        encodeJsonBody(
            buildVpnQuoteCreatePayload(
                requestBody.exitClass(), requestBody.meteringPublicKeyHex()));
    final TransportRequest request =
        buildVpnRequest("POST", "/v1/vpn/quotes", body, canonicalAuth);
    return fetchJson(request, VpnJsonParser::parseQuote, "vpn quote create", 201);
  }

  /** Opens a VPN session after the exact quote-bound native lease transaction commits. */
  public CompletableFuture<VpnSession> createVpnSession(
      final VpnSessionCreateRequest requestBody,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    Objects.requireNonNull(requestBody, "requestBody");
    final byte[] body =
        encodeJsonBody(
            buildVpnSessionCreatePayload(
                requestBody.exitClass(),
                requestBody.quoteId(),
                requestBody.paymentTxHash(),
                requestBody.meteringPublicKeyHex()));
    final TransportRequest request =
        buildVpnRequest("POST", "/v1/vpn/sessions", body, canonicalAuth);
    return fetchJson(request, VpnJsonParser::parseSession, "vpn session create", 201);
  }

  /** Fetches an active VPN session owned by the signed account. */
  public CompletableFuture<Optional<VpnSession>> getVpnSession(
      final String sessionId,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    final String normalizedSessionId = normalizeHex16(sessionId, "sessionId");
    final TransportRequest request =
        buildVpnRequest(
            "GET",
            "/v1/vpn/sessions/" + encodePathSegment(normalizedSessionId),
            null,
            canonicalAuth);
    return fetchJsonAllowingNotFound(
        request, VpnJsonParser::parseSession, "vpn session lookup", 200);
  }

  /** Submits an operator receipt and returns the native lease settlement instruction. */
  public CompletableFuture<VpnReceipt> submitVpnReceipt(
      final VpnReceiptSubmitRequest requestBody,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    Objects.requireNonNull(requestBody, "requestBody");
    final byte[] body =
        encodeJsonBody(
            buildVpnReceiptSubmitPayload(
                requestBody.relayReceiptHex(),
                requestBody.clientVoucherHex(),
                requestBody.leaseIdHex()));
    final TransportRequest request =
        buildVpnRequest("POST", "/v1/vpn/receipts", body, canonicalAuth);
    return fetchJson(request, VpnJsonParser::parseReceipt, "vpn receipt submit", 201);
  }

  /** Lists VPN receipts for the signed account. */
  public CompletableFuture<VpnReceiptListResponse> listVpnReceipts(
      final ToriiCanonicalRequestAuth canonicalAuth) {
    final TransportRequest request = buildVpnRequest("GET", "/v1/vpn/receipts", null, canonicalAuth);
    return fetchJson(request, VpnJsonParser::parseReceiptList, "vpn receipt list", 200);
  }

  /**
   * Prepares an unsigned verifier registration transaction for local signing.
   *
   * <p>Requires {@link ClientConfig#localSigningContext()} and rejects any draft not bound to that
   * exact network, the requested authority, and the exact requested registry record.
   */
  public CompletableFuture<VerifyingKeyTransactionDraft> registerVerifyingKey(
      final VerifyingKeyRegisterRequest requestBody) {
    final LocalSigningContext signingContext = config.requireLocalSigningContext();
    final Map<String, Object> payload = buildVerifyingKeyRegisterPayload(requestBody);
    final byte[] body = encodeJsonBody(payload);
    final TransportRequest request = buildJsonPostRequest("/v1/zk/vk/register", body);
    return fetchJson(
        request,
        bytes -> VerifyingKeyTransactionDraft.parseRegister(
            bytes, signingContext.networkId(), payload),
        "verifying key register draft",
        200);
  }

  /**
   * Prepares an unsigned verifier update transaction for local signing.
   *
   * <p>Requires {@link ClientConfig#localSigningContext()} and rejects any draft not bound to that
   * exact network, the requested authority, and the exact requested registry record.
   */
  public CompletableFuture<VerifyingKeyTransactionDraft> updateVerifyingKey(
      final VerifyingKeyUpdateRequest requestBody) {
    final LocalSigningContext signingContext = config.requireLocalSigningContext();
    final Map<String, Object> payload = buildVerifyingKeyUpdatePayload(requestBody);
    final byte[] body = encodeJsonBody(payload);
    final TransportRequest request = buildJsonPostRequest("/v1/zk/vk/update", body);
    return fetchJson(
        request,
        bytes -> VerifyingKeyTransactionDraft.parseUpdate(
            bytes, signingContext.networkId(), payload),
        "verifying key update draft",
        200);
  }

  /** Quotes the exact unsigned transaction payload before signing. */
  public CompletableFuture<FeeQuoteResponse> quoteFees(
      final Map<String, Object> unsignedPayload,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    Objects.requireNonNull(unsignedPayload, "unsignedPayload");
    Objects.requireNonNull(canonicalAuth, "canonicalAuth");
    requireNetworkTransactionDomain(unsignedPayload);
    final Object authority = unsignedPayload.get("authority");
    if (!(authority instanceof String)) {
      throw new IllegalArgumentException("unsignedPayload.authority must be a string");
    }
    final String canonicalAuthority =
        AccountIdLiteral.requireCanonicalI105Address(
            (String) authority, "unsignedPayload.authority");
    if (!CanonicalRequestSigner.isCanonicalAsciiAccountAlias(canonicalAuth.accountId())
        && !FeeQuoteResponse.sameFeeQuoteAccountIdentity(
            canonicalAuthority, canonicalAuth.accountId())) {
      throw new IllegalArgumentException(
          "canonicalAuth.accountId must identify unsignedPayload.authority or be a canonical account alias");
    }
    final FeePaymentIntent requestedIntent =
        FeePaymentJson.parse(unsignedPayload.get("fee_payment"), "unsignedPayload.fee_payment");
    final Map<String, Object> requestBody = new LinkedHashMap<>();
    requestBody.put("payload", unsignedPayload);
    final byte[] body = encodeJsonBody(requestBody);
    return fetchJson(
            buildExactCanonicalJsonPostRequest(
                "/v1/fees/quote", body, canonicalAuth, FEE_QUOTE_RESPONSE_MAX_BYTES),
            response -> {
              if ((long) response.length > FEE_QUOTE_RESPONSE_MAX_BYTES) {
                throw new IllegalArgumentException(
                    "fee quote response exceeds the "
                        + FEE_QUOTE_RESPONSE_MAX_BYTES
                        + " byte limit");
              }
              return FeePaymentJson.parseQuote(response);
            },
            "fee quote",
            200,
            null,
            true)
        .thenApply(
            quote -> {
              quote.validateForDraft(requestedIntent, canonicalAuthority);
              return quote;
            });
  }




  private static NetworkId requireNetworkTransactionDomain(
      final Map<String, Object> unsignedPayload) {
    for (final String field : Arrays.asList("chain", "chainId", "chain_id")) {
      if (unsignedPayload.containsKey(field)) {
        throw new IllegalArgumentException(
            "unsignedPayload contains retired transaction identity field `" + field + "`");
      }
    }
    final Object rawDomain = unsignedPayload.get("domain");
    if (!(rawDomain instanceof Map<?, ?>)) {
      throw new IllegalArgumentException(
          "unsignedPayload.domain must be TransactionDomain::Network");
    }
    final Map<?, ?> domain = (Map<?, ?>) rawDomain;
    if (!domain.keySet().equals(Set.of("kind", "value"))
        || !"network".equals(domain.get("kind"))
        || !(domain.get("value") instanceof String)) {
      throw new IllegalArgumentException(
          "unsignedPayload.domain must contain exactly kind=network and a NetworkId value");
    }
    return NetworkId.parse((String) domain.get("value"));
  }

  /** Fetches one exact on-chain fee sponsor program under canonical request authentication. */
  public CompletableFuture<FeeSponsorProgramResponse> getFeeSponsorProgram(
      final FeeSponsorProgramId programId,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    Objects.requireNonNull(programId, "programId");
    Objects.requireNonNull(canonicalAuth, "canonicalAuth");
    final Map<String, Object> requestBody = new LinkedHashMap<>();
    requestBody.put("program_id", programId.literal());
    final byte[] body = encodeJsonBody(requestBody);
    return fetchJson(
            buildExactCanonicalJsonPostRequest(
                "/v1/fee-sponsor-programs/by-id",
                body,
                canonicalAuth,
                FEE_SPONSOR_PROGRAM_RESPONSE_MAX_BYTES),
            FeePaymentJson::parseProgram,
            "fee sponsor program lookup",
            200,
            null,
            true)
        .thenApply(
            program -> {
              if (!programId.equals(program.id())) {
                throw new IllegalArgumentException(
                    "fee sponsor program response id does not match the requested program");
              }
              return program;
            });
  }

  /**
   * Prepares an unsigned contract-call transaction and binds it to caller-trusted local intent.
   *
   * <p>The intent is deliberately local-only. It is used after the response is decoded to prove
   * that Torii did not substitute the resolved invocation or final transaction metadata. Torii
   * may enrich fee charge maxima, but cannot select any other signed field.
   */
  public CompletableFuture<ContractCallResponse> prepareContractCall(
      final String authority,
      final FeePaymentIntent feePayment,
      final String contractAddress,
      final String contractAlias,
      final String entrypoint,
      final Object payload,
      final ContractCallDraftIntent draftIntent,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    final Map<String, Object> requestPayload =
        buildContractCallDraftPayload(
            authority,
            feePayment,
            contractAddress,
            contractAlias,
            entrypoint,
            payload);
    Objects.requireNonNull(canonicalAuth, "canonicalAuth");
    if (!FeeQuoteResponse.sameFeeQuoteAccountIdentity(authority, canonicalAuth.accountId())) {
      throw new IllegalArgumentException(
          "canonicalAuth.accountId must identify the contract call authority");
    }
    validateContractCallDraftIntent(requestPayload, draftIntent);
    final NetworkId expectedNetworkId = config.requireLocalSigningContext().networkId();
    final byte[] body = encodeJsonBody(requestPayload);
    final TransportRequest request = buildVpnRequest("POST", "/v1/contracts/call", body, canonicalAuth);
    return fetchJson(request, ContractJsonParser::parseCallResponse, "contract call draft")
        .thenApply(
            response ->
                validateContractCallDraft(
                    response, requestPayload, expectedNetworkId, draftIntent));
  }


  /** Fetches one governance binding via `GET /v1/gov/contracts/{contract_address}`. */
  public CompletableFuture<GovernanceContractResponse> getGovernanceContract(
      final String contractAddress, final ToriiCanonicalRequestAuth canonicalAuth) {
    final String normalizedAddress = normalizeNonBlank(contractAddress, "contractAddress");
    final TransportRequest request =
        buildVpnRequest(
            "GET",
            "/v1/gov/contracts/" + encodePathSegment(normalizedAddress),
            null,
            canonicalAuth);
    return fetchJson(
        request,
        ContractJsonParser::parseGovernanceContractResponse,
        "governance contract");
  }

  /** Drafts one typed Parliament attempt for local transaction signing. */
  public CompletableFuture<ParliamentApiV1.AttemptDraftResponse> draftParliamentAttemptV1(
      final org.hyperledger.iroha.sdk.client.ParliamentApiV1.Proposal proposal,
      final long attemptSequence,
      final String expectedProposalContentId,
      final String expectedGovernanceAttemptId,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    final byte[] body =
        org.hyperledger.iroha.sdk.client.ParliamentApiV1.attemptDraftRequestJson(proposal, attemptSequence);
    return fetchJson(
        buildVpnRequest(
            "POST",
            ParliamentApiV1.ATTEMPT_DRAFT_PATH,
            body,
            canonicalAuth,
            1024L * 1024L),
        response ->
            ParliamentApiV1.parseAttemptDraftResponse(
                response, expectedProposalContentId, expectedGovernanceAttemptId),
        "Parliament attempt draft",
        200);
  }

  /** Reads and strictly validates one authenticated typed Parliament attempt. */
  public CompletableFuture<ParliamentApiV1.AttemptReadResponse> getParliamentAttemptV1(
      final String governanceAttemptId,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    return fetchJson(
        buildVpnRequest(
            "GET",
            ParliamentApiV1.attemptReadPath(governanceAttemptId),
            null,
            canonicalAuth,
            2L * ParliamentApiV1.MAX_STATE_BYTES + 2L * 1024L * 1024L),
        response -> ParliamentApiV1.parseAttemptReadResponse(response, governanceAttemptId),
        "Parliament attempt read",
        200);
  }

  /** Drafts one closed public Parliament transition for local transaction signing. */
  public CompletableFuture<ParliamentApiV1.TransitionDraftResponse>
      draftParliamentTransitionV1(
          final String governanceAttemptId,
          final byte[] transitionJson,
          final String expectedTransitionKind,
          final byte[] expectedTransitionDigest,
          final ToriiCanonicalRequestAuth canonicalAuth) {
    final byte[] body =
        ParliamentApiV1.transitionDraftRequestJson(governanceAttemptId, transitionJson);
    return fetchJson(
        buildVpnRequest(
            "POST",
            ParliamentApiV1.TRANSITION_DRAFT_PATH,
            body,
            canonicalAuth,
            1024L * 1024L),
        response ->
            ParliamentApiV1.parseTransitionDraftResponse(
                response,
                governanceAttemptId,
                expectedTransitionKind,
                expectedTransitionDigest),
        "Parliament transition draft",
        200);
  }

  /** Fetches one authenticated pre-seal timed-OVN casting context. */
  public CompletableFuture<ParliamentApiV1.TimedOvnCastingContextResponse>
      getParliamentTimedOvnCastingContextV1(
          final String ballotAttemptId,
          final ToriiCanonicalRequestAuth canonicalAuth) {
    return fetchJson(
        buildVpnRequest(
            "GET",
            ParliamentApiV1.timedOvnCastingContextReadPath(ballotAttemptId),
            null,
            canonicalAuth,
            ParliamentApiV1.MAX_STATE_BYTES),
        response ->
            ParliamentApiV1.parseTimedOvnCastingContextResponse(
                response, ballotAttemptId),
        "Parliament timed-OVN casting context",
        200);
  }

  /** Requests one exact, consensus-authenticated timed-OVN casting-proof page. */
  public CompletableFuture<ParliamentTimedOvnCastingProofResponseV1>
      requestParliamentTimedOvnCastingProofV1(
          final String ballotAttemptId,
          final BigInteger trustedCheckpointHeight,
          final ToriiCanonicalRequestAuth canonicalAuth) {
    final byte[] body =
        ParliamentApiV1.timedOvnCastingProofRequestNorito(trustedCheckpointHeight);
    final TransportRequest request =
        buildExactNoritoPostRequest(
            ParliamentApiV1.timedOvnCastingProofPath(ballotAttemptId),
            body,
            ParliamentApiV1.MAX_TIMED_OVN_CASTING_PROOF_RESPONSE_BYTES,
            canonicalAuth);
    return fetchExactNoritoBytes(
            request, "Parliament timed-OVN casting proof", true)
        .thenApply(org.hyperledger.iroha.sdk.client.ParliamentApiV1::parseTimedOvnCastingProofResponse);
  }

  /** Convenience overload for positive signed checkpoint heights. */
  public CompletableFuture<ParliamentTimedOvnCastingProofResponseV1>
      requestParliamentTimedOvnCastingProofV1(
          final String ballotAttemptId,
          final long trustedCheckpointHeight,
          final ToriiCanonicalRequestAuth canonicalAuth) {
    return requestParliamentTimedOvnCastingProofV1(
        ballotAttemptId, BigInteger.valueOf(trustedCheckpointHeight), canonicalAuth);
  }

  /** Fetches one bounded checkpoint-promotion page for native wallet verification. */
  public CompletableFuture<ParliamentTimedOvnCastingProofResponseV1>
      getParliamentTimedOvnCastingProofPageV1(
          final String ballotAttemptId,
          final BigInteger trustedCheckpointHeight,
          final ToriiCanonicalRequestAuth canonicalAuth) {
    return requestParliamentTimedOvnCastingProofV1(
        ballotAttemptId, trustedCheckpointHeight, canonicalAuth);
  }

  /** Convenience overload for positive signed checkpoint heights. */
  public CompletableFuture<ParliamentTimedOvnCastingProofResponseV1>
      getParliamentTimedOvnCastingProofPageV1(
          final String ballotAttemptId,
          final long trustedCheckpointHeight,
          final ToriiCanonicalRequestAuth canonicalAuth) {
    return getParliamentTimedOvnCastingProofPageV1(
        ballotAttemptId, BigInteger.valueOf(trustedCheckpointHeight), canonicalAuth);
  }

  /**
   * Fetches, natively authenticates, and durably promotes bounded proof pages until terminal.
   *
   * <p>The authentication must leave timestamp and nonce unpinned so each exact POST receives a
   * fresh anti-replay tuple. A promoted checkpoint is never used until persistence completes.
   */
  public CompletableFuture<ParliamentTimedOvnCastingProofTerminalV1>
      requestParliamentTimedOvnCastingProofUntilTerminalV1(
          final String ballotAttemptId,
          final BigInteger initialTrustedCheckpointHeight,
          final byte[] initialTrustedCheckpointNorito,
          final ToriiCanonicalRequestAuth canonicalAuth,
          final ParliamentTimedOvnCastingProofPageVerifierV1 pageVerifier,
          final ParliamentTimedOvnCastingCheckpointPersisterV1 checkpointPersister) {
    Objects.requireNonNull(canonicalAuth, "canonicalAuth");
    if (canonicalAuth.timestampMs() != null || canonicalAuth.nonce() != null) {
      throw new IllegalArgumentException(
          "casting-proof paging requires unpinned canonical authentication");
    }
    return org.hyperledger.iroha.sdk.client.ParliamentTimedOvnCastingProofPagerV1.synchronize(
        initialTrustedCheckpointHeight,
        initialTrustedCheckpointNorito,
        height -> requestParliamentTimedOvnCastingProofV1(ballotAttemptId, height, canonicalAuth),
        Objects.requireNonNull(pageVerifier, "pageVerifier"),
        Objects.requireNonNull(checkpointPersister, "checkpointPersister"));
  }

  /** Convenience overload for a positive signed initial checkpoint. */
  public CompletableFuture<ParliamentTimedOvnCastingProofTerminalV1>
      requestParliamentTimedOvnCastingProofUntilTerminalV1(
          final String ballotAttemptId,
          final long initialTrustedCheckpointHeight,
          final byte[] initialTrustedCheckpointNorito,
          final ToriiCanonicalRequestAuth canonicalAuth,
          final ParliamentTimedOvnCastingProofPageVerifierV1 pageVerifier,
          final ParliamentTimedOvnCastingCheckpointPersisterV1 checkpointPersister) {
    return requestParliamentTimedOvnCastingProofUntilTerminalV1(
        ballotAttemptId,
        BigInteger.valueOf(initialTrustedCheckpointHeight),
        initialTrustedCheckpointNorito,
        canonicalAuth,
        pageVerifier,
        checkpointPersister);
  }

  /** Fetches the complete public transcript for one currently authorized TLE release. */
  public CompletableFuture<ParliamentApiV1.TleReleaseContextResponse>
      getParliamentTleReleaseContextV1(
          final String ballotAttemptId,
          final ToriiCanonicalRequestAuth canonicalAuth) {
    return fetchJson(
        buildVpnRequest(
            "GET",
            ParliamentApiV1.tleReleaseContextReadPath(ballotAttemptId),
            null,
            canonicalAuth,
            1024L * 1024L),
        response -> ParliamentApiV1.parseTleReleaseContextResponse(response, ballotAttemptId),
        "Parliament TLE release context",
        200);
  }

  /** Requests one node-local proof-carrying partial bound to an admitted release context. */
  public CompletableFuture<ParliamentApiV1.TlePartialReleaseShare>
      requestParliamentTlePartialReleaseV1(
          final String ballotAttemptId,
          final ParliamentApiV1.TleReleaseContextResponse context,
          final ToriiCanonicalRequestAuth canonicalAuth) {
    Objects.requireNonNull(context, "context");
    if (!context.ballotAttemptId.equals(ballotAttemptId)) {
      throw new IllegalArgumentException(
          "release context ballot id differs from the partial-release request");
    }
    return fetchJson(
        buildVpnRequest(
            "POST",
            ParliamentApiV1.tlePartialReleasePath(ballotAttemptId),
            null,
            canonicalAuth,
            16L * 1024L),
        response ->
            ParliamentApiV1.parseTlePartialReleaseResponse(
                response,
                context.keySession.keySessionId,
                context.identityDigest,
                context.keySession.committeeSize),
        "Parliament TLE partial release",
        200);
  }

  /** Fetches the complete manifest via `GET /v1/contracts/code/{code_hash}`. */
  @Override
  public CompletableFuture<org.hyperledger.iroha.sdk.client.ContractManifestRecord>
      getContractManifest(final String codeHash) {
    if (codeHash == null || codeHash.length() != 64) {
      throw new IllegalArgumentException("codeHash must contain exactly 64 hex characters");
    }
    final String normalizedCodeHash = normalizeExactEvenLengthHex(codeHash, "codeHash");
    final TransportRequest request =
        buildJsonGetRequest(
            "/v1/contracts/code/" + encodePathSegment(normalizedCodeHash),
            Collections.emptyMap());
    return fetchJson(
        request,
        org.hyperledger.iroha.sdk.client.ContractJsonParser::parseManifestRecord,
        "contract manifest");
  }

  /** Resolves an account alias via `POST /v1/aliases/resolve`. */
  @Override
  public CompletableFuture<Optional<AccountAliasResolution>> resolveAccountAlias(
      final String alias) {
    final String normalizedAlias = AccountAliasName.parse(alias).canonicalText();
    final byte[] body = encodeJsonBody(objectMapOf("alias", normalizedAlias));
    final TransportRequest request = buildJsonPostRequest("/v1/aliases/resolve", body);
    return fetchJsonAllowingNotFound(
        request,
        response -> parsePinnedAliasResolution(response, normalizedAlias),
        "account alias resolve");
  }

  /** Plans one atomic alias setup transaction without invoking a mutation route. */
  @Override
  public CompletableFuture<AliasTransactionPlanV1> planAliasSetup(
      final AliasSetupPlanRequestV1 requestBody,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    Objects.requireNonNull(requestBody, "requestBody");
    Objects.requireNonNull(canonicalAuth, "canonicalAuth");
    final byte[] body = encodeJsonBody(requestBody.toJsonMap());
    final TransportRequest request =
        buildVpnRequest("POST", "/v1/aliases/setup/plan", body, canonicalAuth);
    return fetchJson(
        request,
        response -> {
          final AliasTransactionPlanV1 plan = AliasTransactionPlanJsonParser.parse(response);
          if (!plan.body().authority().equals(canonicalAuth.accountId())) {
            throw new IllegalArgumentException(
                "alias setup plan authority does not match the canonical request signer");
          }
          return plan;
        },
        "alias setup plan",
        200);
  }

  @Override
  public CompletableFuture<AliasLifecycleTransactionPlanV1> planAliasLeaseRenewal(
      final AliasLeaseRenewPlanRequestV1 requestBody,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    return planAliasLifecycle(
        "/v1/aliases/lease/renew/plan",
        requestBody,
        canonicalAuth,
        "alias lease renewal plan");
  }

  @Override
  public CompletableFuture<AliasLifecycleTransactionPlanV1> planAliasAutoRenew(
      final AliasAutoRenewPlanRequestV1 requestBody,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    return planAliasLifecycle(
        "/v1/aliases/auto-renew/plan",
        requestBody,
        canonicalAuth,
        "alias auto-renew plan");
  }

  private CompletableFuture<AliasLifecycleTransactionPlanV1> planAliasLifecycle(
      final String path,
      final AliasLifecyclePlanRequestV1 requestBody,
      final ToriiCanonicalRequestAuth canonicalAuth,
      final String context) {
    final byte[] body =
        JsonEncoder.encode(requestBody.toJsonMap()).getBytes(StandardCharsets.UTF_8);
    final TransportRequest request = buildVpnRequest("POST", path, body, canonicalAuth);
    return fetchJson(
        request,
        response -> {
          final AliasLifecycleTransactionPlanV1 plan =
              AliasLifecycleTransactionPlanJsonParser.parse(response);
          if (!plan.body().authority().equals(canonicalAuth.accountId())) {
            throw new IllegalArgumentException(
                context + " authority does not match the canonical request signer");
          }
          return plan;
        },
        context,
        200);
  }

  @Override
  public CompletableFuture<AccountOnboardingPlanReceiptV1> planSponsoredAccountOnboarding(
      final AccountOnboardingPlanRequestV1 requestBody,
      final String onboardingToken,
      final String expectedAuthority,
      final NetworkId expectedNetworkId) {
    final byte[] body =
        JsonEncoder.encode(requestBody.toJsonMap()).getBytes(StandardCharsets.UTF_8);
    return fetchJson(
        buildOnboardingRequest("POST", "/v1/accounts/onboard/plan", body, onboardingToken),
        response ->
            AccountOnboardingReceiptVerifier.requireValidForRequest(
                requestBody,
                AccountOnboardingJsonParser.parseReceipt(response),
                expectedNetworkId,
                expectedAuthority),
        "sponsored account onboarding plan",
        200);
  }

  @Override
  public CompletableFuture<AccountOnboardingPrepareResponseV1> prepareSponsoredAccountOnboarding(
      final AccountOnboardingPlanRequestV1 requestBody,
      final AccountOnboardingPlanReceiptV1 receipt,
      final PreparedOperationBindingV1 binding,
      final FeePaymentIntent feePayment,
      final String onboardingToken,
      final String expectedAuthority,
      final NetworkId expectedNetworkId) {
    AccountOnboardingReceiptVerifier.requireValidForRequest(
        requestBody, receipt, expectedNetworkId, expectedAuthority);
    if (!PreparedOperationBindingV1.ONBOARDING.equals(binding.kind())) {
      throw new IllegalArgumentException("onboarding prepare requires an onboarding binding");
    }
    if (binding.executionExpiresAtUnixMs() <= System.currentTimeMillis()) {
      throw new IllegalArgumentException("onboarding prepare binding is expired");
    }
    final byte[] body =
        JsonEncoder.encode(
                new AccountOnboardingPrepareRequestV1(binding, receipt, feePayment).toJsonMap())
            .getBytes(StandardCharsets.UTF_8);
    return fetchJson(
        buildOnboardingRequest("POST", "/v1/accounts/onboard/prepare", body, onboardingToken),
        response -> {
          final AccountOnboardingPrepareResponseV1 result =
              AccountOnboardingJsonParser.parsePrepareResponse(response);
          if (result instanceof AccountOnboardingPreparedTransactionV1) {
            AccountOnboardingPreparedVerifier.requireValidPrepared(
                (AccountOnboardingPreparedTransactionV1) result,
                requestBody,
                receipt,
                binding,
                feePayment,
                expectedNetworkId,
                expectedAuthority);
          } else if (result instanceof AccountOnboardingProofRequiredPrepareResponseV1) {
            AccountOnboardingPreparedVerifier.requireValidProofRequired(
                (AccountOnboardingProofRequiredPrepareResponseV1) result,
                requestBody,
                receipt,
                binding,
                expectedNetworkId,
                expectedAuthority);
          } else {
            throw new IllegalArgumentException("unsupported onboarding prepare response");
          }
          return result;
        },
        "sponsored account onboarding prepare",
        200);
  }

  @Override
  public CompletableFuture<AccountOnboardingCurrentStateV1>
      verifyAccountOnboardingCurrentState(
          final AccountOnboardingProofRequiredPrepareResponseV1 proofRequired,
          final AccountOnboardingPlanRequestV1 requestBody,
          final AccountOnboardingPlanReceiptV1 receipt,
          final PreparedOperationBindingV1 binding,
          final String expectedAuthority,
          final NetworkId expectedNetworkId,
          final ToriiCanonicalRequestAuth canonicalAuth) {
    AccountOnboardingPreparedVerifier.requireValidProofRequired(
        proofRequired,
        requestBody,
        receipt,
        binding,
        expectedNetworkId,
        expectedAuthority);
    final AccountOnboardingCurrentStateRequestV1 atomicRequest =
        new AccountOnboardingCurrentStateRequestV1(
            proofRequired.accountId(), proofRequired.alias());
    final byte[] body =
        JsonEncoder.encode(atomicRequest.toJsonMap()).getBytes(StandardCharsets.UTF_8);
    if (!config.requireLocalSigningContext().networkId().equals(expectedNetworkId)) {
      throw new IllegalArgumentException(
          "atomic onboarding current-state signing requires the expected network context");
    }
    return fetchExactJson(
        buildExactCanonicalJsonPostRequest(
            "/v1/accounts/onboarding/current-state",
            body,
            canonicalAuth,
            ACCOUNT_ONBOARDING_CURRENT_STATE_RESPONSE_MAX_BYTES),
        response ->
            AccountOnboardingJsonParser.parseCurrentStateResponse(response)
                .classify(atomicRequest, expectedNetworkId),
        "atomic account onboarding current-state");
  }

  @Override
  public CompletableFuture<PreparedTransactionSubmitResponseV1> submitPreparedAccountOnboarding(
      final AccountOnboardingPlanRequestV1 requestBody,
      final AccountOnboardingPreparedTransactionV1 prepared,
      final FeePaymentIntent expectedFeePayment,
      final String onboardingToken,
      final String expectedAuthority,
      final NetworkId expectedNetworkId) {
    AccountOnboardingPreparedVerifier.requireValidPrepared(
        prepared,
        requestBody,
        prepared.receipt(),
        prepared.binding(),
        expectedFeePayment,
        expectedNetworkId,
        expectedAuthority);
    if (prepared.binding().executionExpiresAtUnixMs() <= System.currentTimeMillis()) {
      throw new IllegalArgumentException("prepared onboarding binding is expired");
    }
    final byte[] body =
        JsonEncoder.encode(prepared.toJsonMap()).getBytes(StandardCharsets.UTF_8);
    return fetchJson(
        buildOnboardingRequest("POST", "/v1/accounts/onboard", body, onboardingToken),
        AccountOnboardingJsonParser::parseSubmitResponse,
        "prepared account onboarding submit",
        null,
        (response, statusCode) ->
            AccountOnboardingPreparedVerifier.requireValidSubmitResponse(
                response, prepared, expectedFeePayment, statusCode.intValue()));
  }

  @Override
  public CompletableFuture<AccountFaucetPreparedTransactionV1>
      prepareAccountFaucetTransaction(
          final AccountFaucetClaimV1 claim,
          final PreparedOperationBindingV1 binding,
          final FeePaymentIntent feePayment,
          final AccountFaucetPolicyV1 policy,
          final NetworkId expectedNetworkId) {
    Objects.requireNonNull(claim, "claim");
    Objects.requireNonNull(feePayment, "feePayment");
    Objects.requireNonNull(policy, "policy");
    Objects.requireNonNull(expectedNetworkId, "expectedNetworkId");
    if (!PreparedOperationBindingV1.FAUCET.equals(
        Objects.requireNonNull(binding, "binding").kind())) {
      throw new IllegalArgumentException("faucet prepare requires a faucet binding");
    }
    if (binding.executionExpiresAtUnixMs() <= System.currentTimeMillis()) {
      throw new IllegalArgumentException("faucet prepare binding is expired");
    }
    final byte[] body =
        JsonEncoder.encode(new AccountFaucetPrepareRequestV1(binding, claim, feePayment).toJsonMap())
            .getBytes(StandardCharsets.UTF_8);
    return fetchJson(
        buildJsonPostRequest("/v1/accounts/faucet/prepare", body),
        response -> {
          final AccountFaucetPreparedTransactionV1 prepared =
              AccountOnboardingJsonParser.parseFaucetPrepareResponse(response);
          AccountFaucetPreparedVerifier.requireValidPrepared(
              prepared, claim, binding, feePayment, policy, expectedNetworkId);
          return prepared;
        },
        "account faucet prepare",
        Integer.valueOf(200));
  }

  @Override
  public CompletableFuture<PreparedTransactionSubmitResponseV1>
      submitPreparedAccountFaucetTransaction(
          final AccountFaucetPreparedTransactionV1 prepared,
          final FeePaymentIntent expectedFeePayment,
          final AccountFaucetPolicyV1 policy,
          final NetworkId expectedNetworkId) {
    AccountFaucetPreparedVerifier.requireValidPrepared(
        prepared,
        prepared.claim(),
        prepared.binding(),
        expectedFeePayment,
        policy,
        expectedNetworkId);
    if (prepared.binding().executionExpiresAtUnixMs() <= System.currentTimeMillis()) {
      throw new IllegalArgumentException("prepared faucet binding is expired");
    }
    final byte[] body =
        JsonEncoder.encode(prepared.toJsonMap()).getBytes(StandardCharsets.UTF_8);
    return fetchJson(
        buildJsonPostRequest("/v1/accounts/faucet", body),
        AccountOnboardingJsonParser::parseSubmitResponse,
        "prepared account faucet submit",
        null,
        (response, statusCode) ->
            AccountFaucetPreparedVerifier.requireValidSubmitResponse(
                response,
                prepared,
                expectedFeePayment,
                policy,
                expectedNetworkId,
                statusCode.intValue()));
  }

  @Override
  public CompletableFuture<AliasSetupModels.AliasSetupReportV1> getAccountOnboardingReadiness(
      final String onboardingToken) {
    return fetchJson(
        buildOnboardingRequest(
            "GET", "/v1/accounts/onboarding/readiness", null, onboardingToken),
        AccountOnboardingJsonParser::parseReadiness,
        "account onboarding readiness",
        200);
  }

  @Override
  public CompletableFuture<Optional<AccountAliasIndexResolution>> resolveAccountAliasIndex(
      final BigInteger index) {
    AccountAliasUInt64.require(index, "index");
    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("index", index);
    final byte[] body = JsonEncoder.encode(payload).getBytes(StandardCharsets.UTF_8);
    return fetchJsonAllowingNotFound(
        buildJsonPostRequest("/v1/aliases/resolve-index", body),
        response -> parsePinnedAliasIndexResolution(response, index),
        "account alias index resolve");
  }

  @Override
  public CompletableFuture<Optional<AccountAliasIndexResolution>> resolveAccountAliasIndex(
      final BigInteger index, final ToriiCanonicalRequestAuth canonicalAuth) {
    AccountAliasUInt64.require(index, "index");
    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("index", index);
    final byte[] body = JsonEncoder.encode(payload).getBytes(StandardCharsets.UTF_8);
    return fetchJsonAllowingNotFound(
        buildVpnRequest("POST", "/v1/aliases/resolve-index", body, canonicalAuth),
        response -> parsePinnedAliasIndexResolution(response, index),
        "account alias index resolve");
  }

  @Override
  public CompletableFuture<Optional<AccountAliasesByAccount>> listAccountAliases(
      final AccountAliasesByAccountRequest requestBody) {
    final byte[] body =
        JsonEncoder.encode(requestBody.toJsonMap()).getBytes(StandardCharsets.UTF_8);
    return fetchJsonAllowingNotFound(
        buildJsonPostRequest("/v1/aliases/by-account", body),
        response -> parsePinnedAliasesByAccount(response, requestBody),
        "account aliases lookup");
  }

  @Override
  public CompletableFuture<Optional<AccountAliasesByAccount>> listAccountAliases(
      final AccountAliasesByAccountRequest requestBody,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    final byte[] body =
        JsonEncoder.encode(requestBody.toJsonMap()).getBytes(StandardCharsets.UTF_8);
    return fetchJsonAllowingNotFound(
        buildVpnRequest("POST", "/v1/aliases/by-account", body, canonicalAuth),
        response -> parsePinnedAliasesByAccount(response, requestBody),
        "account aliases lookup");
  }

  /** Resolves a restricted account alias with canonical Iroha request headers. */
  @Override
  public CompletableFuture<Optional<AccountAliasResolution>> resolveAccountAlias(
      final String alias, final ToriiCanonicalRequestAuth canonicalAuth) {
    final String normalizedAlias = AccountAliasName.parse(alias).canonicalText();
    final byte[] body = encodeJsonBody(objectMapOf("alias", normalizedAlias));
    final TransportRequest request =
        buildVpnRequest("POST", "/v1/aliases/resolve", body, canonicalAuth);
    return fetchJsonAllowingNotFound(
        request,
        response -> parsePinnedAliasResolution(response, normalizedAlias),
        "account alias resolve");
  }

  private static AccountAliasResolution parsePinnedAliasResolution(
      final byte[] response, final String requestedAlias) {
    final AccountAliasResolution resolution = AccountAliasJsonParser.parseResolution(response);
    if (!AccountAliasName.parse(resolution.alias()).canonicalText().equals(requestedAlias)) {
      throw new IllegalArgumentException(
          "account alias response does not match the requested alias");
    }
    return resolution;
  }

  private static AccountAliasIndexResolution parsePinnedAliasIndexResolution(
      final byte[] response, final BigInteger requestedIndex) {
    final AccountAliasIndexResolution resolution =
        AccountAliasReadJsonParser.parseIndexResolution(response);
    if (!resolution.index().equals(requestedIndex)) {
      throw new IllegalArgumentException(
          "account alias index response does not match the requested index");
    }
    return resolution;
  }

  private static AccountAliasesByAccount parsePinnedAliasesByAccount(
      final byte[] response, final AccountAliasesByAccountRequest request) {
    final AccountAliasesByAccount aliases = AccountAliasReadJsonParser.parseByAccount(response);
    if (!aliases.accountId().equals(request.accountId())) {
      throw new IllegalArgumentException(
          "account aliases response does not match the requested account");
    }
    for (final AccountAliasListItem item : aliases.items()) {
      if ((request.dataspace() != null && !request.dataspace().equals(item.dataspace()))
          || (request.domain() != null && !request.domain().equals(item.domain()))) {
        throw new IllegalArgumentException(
            "account aliases response contains entries outside the requested scope");
      }
    }
    return aliases;
  }

  /** Creates a transport backed by the platform HTTP executor (OkHttp on Android). */
  public static HttpClientTransport createDefault(final ClientConfig config) {
    return new HttpClientTransport(PlatformHttpTransportExecutor.createDefault(), config);
  }

  public static HttpClientTransport withExecutor(
      final HttpTransportExecutor executor, final ClientConfig config) {
    return new HttpClientTransport(executor, config);
  }

  /**
   * Creates a transport using the platform-default executor (OkHttp on Android, JDK client on JVM).
   */
  public static HttpClientTransport withDefaultExecutor(final ClientConfig config) {
    return new HttpClientTransport(PlatformHttpTransportExecutor.createDefault(), config);
  }

  /**
   * Returns a copy of {@code config} with a directory-backed pending queue rooted at {@code
   * queueDir}. Each queued transaction is persisted as its own envelope file to satisfy OEM or
   * managed-device storage policies. Transaction submission never drains or fills this queue.
   */
  public static ClientConfig withDirectoryPendingQueue(
      final ClientConfig config, final Path queueDir) {
    Objects.requireNonNull(config, "config");
    return config.toBuilder().enableDirectoryPendingQueue(queueDir).build();
  }

  /** Returns a copy with explicit local staging; transaction submission never drains or fills it. */
  public static ClientConfig withFilePendingQueue(
      final ClientConfig config, final Path queueFile) {
    Objects.requireNonNull(config, "config");
    return config.toBuilder().enableFilePendingQueue(queueFile).build();
  }

  /**
   * Creates a {@link SubscriptionToriiClient} that reuses this transport's HTTP executor, base
   * URI, headers, and observers.
   */
  public SubscriptionToriiClient subscriptionToriiClient() {
    return config.toSubscriptionToriiClient(executor);
  }

  private CompletableFuture<ClientResponse> submitOnce(
      final SignedTransaction transaction, final String hashHex) {
    final TransportRequest request =
        ToriiRequestBuilder.buildSubmitRequest(
            config.baseUri(),
            transaction,
            config.requestTimeout(),
            config.defaultHeaders(),
            config.wireFormatPreference().acceptHeader());

    return ensureTransactionSubmissionCompatibility()
        .thenCompose(
            ignored -> {
              notifyRequest(request);
              return executor
                  .execute(request)
                  .handle(
                      (response, throwable) -> {
                        if (throwable != null) {
                          final Throwable cause = unwrapCompletion(throwable);
                          final AmbiguousTransactionSubmissionException error =
                              new AmbiguousTransactionSubmissionException(hashHex, null, cause);
                          notifyFailure(request, error);
                          final CompletableFuture<ClientResponse> failed =
                              new CompletableFuture<>();
                          failed.completeExceptionally(error);
                          return failed;
                        }
                        final ClientResponse clientResponse =
                            new ClientResponse(
                                response.statusCode(),
                                response.body(),
                                response.message(),
                                extractEntrypointHash(response).orElse(hashHex),
                                extractRejectCode(response));
                        if (submissionOutcomeIsAmbiguous(clientResponse.statusCode())) {
                          final AmbiguousTransactionSubmissionException error =
                              new AmbiguousTransactionSubmissionException(
                                  hashHex, Integer.valueOf(clientResponse.statusCode()), null);
                          notifyFailure(request, error);
                          final CompletableFuture<ClientResponse> failed =
                              new CompletableFuture<>();
                          failed.completeExceptionally(error);
                          return failed;
                        }
                        notifyResponse(request, clientResponse);
                        return CompletableFuture.completedFuture(clientResponse);
                      })
                  .thenCompose(future -> future);
            });
  }

  private static boolean submissionOutcomeIsAmbiguous(final int statusCode) {
    return (statusCode >= 300 && statusCode <= 399)
        || statusCode == 408
        || statusCode == 425
        || statusCode == 429
        || statusCode >= 500;
  }

  private void emitDeviceProfileTelemetry() {
    if (!config.telemetryOptions().enabled()) {
      return;
    }
    if (!deviceProfileEmitted.compareAndSet(false, true)) {
      return;
    }
    final Optional<TelemetrySink> sink = config.telemetrySink();
    if (!sink.isPresent()) {
      return;
    }
    final DeviceProfileProvider provider = config.deviceProfileProvider();
    if (provider == null) {
      return;
    }
    final Optional<DeviceProfile> profile = provider.snapshot();
    if (!profile.isPresent()) {
      return;
    }
    sink
        .get()
        .emitSignal(
            "android.telemetry.device_profile",
            objectMapOf("profile_bucket", profile.get().bucket()));
  }

  private void emitNetworkContextTelemetry() {
    if (!config.telemetryOptions().enabled()) {
      return;
    }
    final Optional<TelemetrySink> sink = config.telemetrySink();
    if (!sink.isPresent()) {
      return;
    }
    final Optional<NetworkContext> context = config.networkContextProvider().snapshot();
    if (!context.isPresent()) {
      return;
    }
    sink
        .get()
        .emitSignal("android.telemetry.network_context", context.get().toTelemetryFields());
  }

  private void emitPipelineStatusTelemetry(
      final TransportRequest request,
      final String transactionHash,
      final String statusKind,
      final boolean isSuccess,
      final boolean isFailure,
      final int attempts) {
    if (!config.telemetryOptions().enabled()) {
      return;
    }
    final Optional<TelemetrySink> sink = config.telemetrySink();
    if (!sink.isPresent()) {
      return;
    }
    final Map<String, Object> fields = new LinkedHashMap<>();
    maybePutAuthorityHash(fields, request, sink.get(), PIPELINE_STATUS_SIGNAL);
    if (transactionHash != null) {
      fields.put("tx_hash", transactionHash);
    }
    fields.put("status_kind", statusKind == null ? "" : statusKind);
    fields.put("outcome", isSuccess ? "success" : (isFailure ? "failure" : "pending"));
    fields.put("attempts", attempts);
    sink.get().emitSignal(PIPELINE_STATUS_SIGNAL, fields);
  }

  private void maybePutAuthorityHash(
      final Map<String, Object> fields,
      final TransportRequest request,
      final TelemetrySink sink,
      final String signalId) {
    final TelemetryOptions.Redaction redaction = config.telemetryOptions().redaction();
    if (!redaction.enabled()) {
      return;
    }
    final String authority = resolveAuthority(request).trim();
    if (authority.isEmpty()) {
      emitRedactionFailure(sink, signalId, "blank_authority");
      return;
    }
    final Optional<String> hashed = redaction.hashAuthority(authority);
    if (hashed.isPresent()) {
      fields.put("authority_hash", hashed.get());
    } else {
      emitRedactionFailure(sink, signalId, "hash_failed");
    }
  }

  private static String resolveRoute(final TransportRequest request) {
    final URI uri = request == null ? null : request.uri();
    if (uri == null) {
      return "";
    }
    final String path = uri.getRawPath();
    return path == null ? "" : path;
  }

  private static String extractRejectCode(final TransportResponse response) {
    if (response == null) {
      return null;
    }
    return HttpErrorMessageExtractor.extractRejectCode(
        response.headers(), "x-iroha-reject-code", response.body());
  }

  private static Optional<String> extractEntrypointHash(final TransportResponse response) {
    if (response == null) {
      return Optional.empty();
    }
    final List<String> values = response.headers().get(ENTRYPOINT_HASH_HEADER);
    if (values == null) {
      return Optional.empty();
    }
    if (values.size() != 1) {
      throw new IllegalStateException(
          "Torii transaction hash header must contain exactly one value");
    }
    final String value = values.get(0);
    if (value == null || !value.matches("[0-9a-f]{63}[13579bdf]")) {
      throw new IllegalStateException(
          "Torii transaction hash header must be an exact lowercase marked 32-byte hash");
    }
    return Optional.of(value);
  }

  private static String resolveAuthority(final TransportRequest request) {
    if (request == null) {
      return "";
    }
    final URI uri = request.uri();
    if (uri != null && uri.getAuthority() != null) {
      return uri.getAuthority();
    }
    final List<String> host = request.headers().get("Host");
    return host == null || host.isEmpty() ? "" : host.get(0);
  }

  private static void emitRedactionFailure(
      final TelemetrySink sink, final String signalId, final String reason) {
    sink.emitSignal(
        REDACTION_FAILURE_SIGNAL,
        objectMapOf(
            "signal_id", signalId,
            "reason", reason));
  }

  private void pollPipelineStatus(
      final String hashHex,
      final PipelineStatusOptions options,
      final long deadline,
      final int attemptsSoFar,
      final Map<String, Object> lastPayload,
      final CompletableFuture<Map<String, Object>> future) {
    if (future.isDone()) {
      return;
    }
    if (options.maxAttempts() != null && attemptsSoFar >= options.maxAttempts()) {
      future.completeExceptionally(
          new TransactionTimeoutException(
              "Transaction " + hashHex + " did not reach a terminal status "
                  + "after " + attemptsSoFar + " attempts",
              hashHex,
              attemptsSoFar,
              lastPayload));
      return;
    }

    final TransportRequest request =
        ToriiRequestBuilder.buildStatusRequest(
            config.baseUri(), hashHex, config.requestTimeout(), config.defaultHeaders());
    notifyRequest(request);
    executor
        .execute(request)
        .whenComplete(
            (response, throwable) -> {
              try {
                if (future.isDone()) {
                  return;
                }
                if (throwable != null) {
                  final Throwable cause =
                      throwable instanceof CompletionException && throwable.getCause() != null
                          ? throwable.getCause()
                          : throwable;
                  notifyFailure(request, cause);
                  future.completeExceptionally(cause);
                  return;
                }

                final ClientResponse clientResponse =
                    new ClientResponse(
                        response.statusCode(),
                        response.body(),
                        response.message(),
                        null,
                        extractRejectCode(response));
                notifyResponse(request, clientResponse);

                final int statusCode = clientResponse.statusCode();
                if (statusCode != 200 && statusCode != 404) {
                  future.completeExceptionally(
                      buildPipelineStatusHttpException(hashHex, clientResponse));
                  return;
                }

                final Map<String, Object> payload =
                    statusCode == 404
                        ? null
                        : parsePipelineStatusPayload(clientResponse.body());
                final int nextAttempts = attemptsSoFar + 1;
                final String statusLiteral =
                    payload == null
                        ? null
                        : PipelineStatusExtractor.requireAuthoritativeStatus(payload, hashHex);
                final boolean isStateResolved =
                    payload != null && "state".equals(payload.get("resolved_from"));
                final boolean isSuccess =
                    "Applied".equals(statusLiteral) && isStateResolved;
                final boolean isFailure =
                    ("Rejected".equals(statusLiteral) || "Expired".equals(statusLiteral))
                        && isStateResolved;
                emitPipelineStatusTelemetry(
                    request, hashHex, statusLiteral, isSuccess, isFailure, nextAttempts);

                if (options.observer() != null) {
                  try {
                    options.observer().onStatus(statusLiteral, payload, nextAttempts);
                  } catch (final RuntimeException observerError) {
                    future.completeExceptionally(observerError);
                    return;
                  }
                }

                if (isSuccess) {
                  future.complete(payload != null ? payload : Collections.emptyMap());
                  return;
                }
                if (isFailure) {
                  future.completeExceptionally(
                      new TransactionStatusException(hashHex, statusLiteral, payload));
                  return;
                }

                if (options.maxAttempts() != null && nextAttempts >= options.maxAttempts()) {
                  future.completeExceptionally(
                      new TransactionTimeoutException(
                          "Transaction " + hashHex + " did not reach a terminal status "
                              + "after " + nextAttempts + " attempts",
                          hashHex,
                          nextAttempts,
                          payload));
                  return;
                }

                if (deadline != Long.MAX_VALUE && System.currentTimeMillis() >= deadline) {
                  future.completeExceptionally(
                      new TransactionTimeoutException(
                          "Transaction " + hashHex + " did not reach a terminal status "
                              + "within the configured timeout",
                          hashHex,
                          nextAttempts,
                          payload));
                  return;
                }

                scheduleNextPoll(
                    hashHex, options, deadline, nextAttempts, payload, future);
              } catch (final Exception e) {
                if (!future.isDone()) {
                  future.completeExceptionally(e);
                }
              }
            });
  }

  private void scheduleNextPoll(
      final String hashHex,
      final PipelineStatusOptions options,
      final long deadline,
      final int attemptsSoFar,
      final Map<String, Object> lastPayload,
      final CompletableFuture<Map<String, Object>> future) {
    if (future.isDone()) {
      return;
    }
    final long interval = options.intervalMillis();
    final Runnable task =
        () -> pollPipelineStatus(hashHex, options, deadline, attemptsSoFar, lastPayload, future);
    if (interval <= 0L) {
      task.run();
      return;
    }
    CompletableFuture
        .runAsync(
            () -> {},
            CompletableFuture.delayedExecutor(
                Math.min(interval, Long.MAX_VALUE), TimeUnit.MILLISECONDS))
        .whenComplete(
            (ignored, delayError) -> {
              if (delayError != null) {
                future.completeExceptionally(
                    delayError instanceof CompletionException ? delayError.getCause() : delayError);
              } else {
                task.run();
              }
            });
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> parsePipelineStatusPayload(final byte[] body) {
    if (body == null || body.length == 0) {
      throw new IllegalStateException("Pipeline status response must not be empty");
    }
    if (body.length >= 4
        && body[0] == 'N'
        && body[1] == 'R'
        && body[2] == 'T'
        && body[3] == '0') {
      throw new IllegalStateException(
          "Pipeline status response violated the requested application/json contract");
    }
    final String json = new String(body, StandardCharsets.UTF_8).trim();
    if (json.isEmpty()) {
      throw new IllegalStateException("Pipeline status response must not be empty");
    }
    final Object parsed = JsonParser.parse(json);
    if (parsed instanceof Map) {
      return PipelineStatusExtractor.normalizePublicStatus((Map<String, Object>) parsed);
    }
    throw new IllegalStateException("Pipeline status response must be a JSON object");
  }

  private static TransactionStatusHttpException buildPipelineStatusHttpException(
      final String hashHex, final ClientResponse response) {
    final String bodyPreview = HttpErrorMessageExtractor.extractMessage(response.body());
    return new TransactionStatusHttpException(
        hashHex,
        response.statusCode(),
        response.rejectCode().orElse(null),
        bodyPreview);
  }

  private void notifyRequest(final TransportRequest request) {
    emitDeviceProfileTelemetry();
    emitNetworkContextTelemetry();
    for (final ClientObserver observer : config.observers()) {
      observer.onRequest(request);
    }
  }

  private void notifyResponse(final TransportRequest request, final ClientResponse response) {
    for (final ClientObserver observer : config.observers()) {
      observer.onResponse(request, response);
    }
  }

  private void notifyFailure(final TransportRequest request, final Throwable error) {
    for (final ClientObserver observer : config.observers()) {
      observer.onFailure(request, error);
    }
  }

  private TransportRequest buildJsonGetRequest(
      final String path, final Map<String, String> queryParams) {
    return buildJsonGetRequest(path, queryParams, null);
  }

  private TransportRequest buildJsonGetRequest(
      final String path,
      final Map<String, String> queryParams,
      final Long maximumResponseBytes) {
    final URI target = appendQuery(resolvePath(path), queryParams);
    final TransportRequest.Builder builder =
        TransportRequest.builder()
            .setUri(target)
            .setMethod("GET")
            .addHeader("Accept", "application/json")
            .setTimeout(config.requestTimeout());
    if (maximumResponseBytes != null) {
      builder.setMaximumResponseBytes(maximumResponseBytes);
    }
    for (final Map.Entry<String, String> entry : config.defaultHeaders().entrySet()) {
      builder.addHeader(entry.getKey(), entry.getValue());
    }
    return builder.build();
  }

  private TransportRequest buildJsonPostRequest(final String path, final byte[] body) {
    return buildJsonPostRequest(path, body, null);
  }

  private TransportRequest buildExactJsonGetRequest(
      final String path, final long maximumResponseBytes) {
    for (final String name : config.defaultHeaders().keySet()) {
      if (name.equalsIgnoreCase("Accept")) {
        throw new IllegalArgumentException(
            "Accept must not be overridden for exact JSON requests");
      }
    }
    final TransportRequest.Builder builder =
        TransportRequest.builder()
            .setUri(resolvePath(path))
            .setMethod("GET")
            .addHeader("Accept", APPLICATION_JSON)
            .setMaximumResponseBytes(Long.valueOf(maximumResponseBytes))
            .setTimeout(config.requestTimeout());
    for (final Map.Entry<String, String> entry : config.defaultHeaders().entrySet()) {
      builder.addHeader(entry.getKey(), entry.getValue());
    }
    return builder.build();
  }

  private TransportRequest buildExactNoritoGetRequest(
      final String path, final long maximumResponseBytes) {
    return buildExactNoritoGetRequest(path, maximumResponseBytes, null);
  }

  private TransportRequest buildExactNoritoGetRequest(
      final String path,
      final long maximumResponseBytes,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    for (final String name : config.defaultHeaders().keySet()) {
      if (name.equalsIgnoreCase("Accept")) {
        throw new IllegalArgumentException(
            "Accept must not be overridden for exact Norito requests");
      }
    }
    if (canonicalAuth != null) {
      requireCanonicalHeadersUnset();
    }
    final URI target = resolvePath(path);
    final TransportRequest.Builder builder =
        TransportRequest.builder()
            .setUri(target)
            .setMethod("GET")
            .addHeader("Accept", APPLICATION_NORITO)
            .setMaximumResponseBytes(Long.valueOf(maximumResponseBytes))
            .setTimeout(config.requestTimeout());
    for (final Map.Entry<String, String> entry : config.defaultHeaders().entrySet()) {
      builder.addHeader(entry.getKey(), entry.getValue());
    }
    if (canonicalAuth != null) {
      final Map<String, String> canonicalHeaders =
          buildCanonicalHeaders("GET", target, null, canonicalAuth);
      for (final Map.Entry<String, String> entry : canonicalHeaders.entrySet()) {
        builder.addHeader(entry.getKey(), entry.getValue());
      }
      TransportSecurity.requireHttpRequestAllowed(
          "HttpClientTransport", config.baseUri(), target, canonicalHeaders, null);
    }
    return builder.build();
  }

  private TransportRequest buildExactNoritoPostRequest(
      final String path,
      final byte[] body,
      final long maximumResponseBytes,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    return buildExactNoritoPostRequest(
        path, body, maximumResponseBytes, canonicalAuth, false);
  }

  private TransportRequest buildExactNoritoPostRequest(
      final String path,
      final byte[] body,
      final long maximumResponseBytes,
      final ToriiCanonicalRequestAuth canonicalAuth,
      final boolean requestNoStore) {
    final List<String> managedHeaders =
        requestNoStore
            ? Arrays.asList(
                "Accept", "Content-Type", "Accept-Encoding", "Content-Encoding", "Cache-Control")
            : Arrays.asList("Accept", "Content-Type", "Accept-Encoding", "Content-Encoding");
    for (final String candidate : config.defaultHeaders().keySet()) {
      for (final String managed : managedHeaders) {
        if (candidate.equalsIgnoreCase(managed)) {
          throw new IllegalArgumentException(
              "exact Norito POST headers must not be overridden");
        }
      }
    }
    requireCanonicalHeadersUnset();
    final URI target = resolvePath(path);
    final TransportRequest.Builder builder =
        TransportRequest.builder()
            .setUri(target)
            .setMethod("POST")
            .setBody(Objects.requireNonNull(body, "body"))
            .addHeader("Content-Type", APPLICATION_NORITO)
            .addHeader("Accept", APPLICATION_NORITO)
            .addHeader("Accept-Encoding", "identity")
            .setMaximumResponseBytes(Long.valueOf(maximumResponseBytes))
            .setTimeout(config.requestTimeout());
    if (requestNoStore) {
      builder.addHeader("Cache-Control", "no-store");
    }
    for (final Map.Entry<String, String> entry : config.defaultHeaders().entrySet()) {
      builder.addHeader(entry.getKey(), entry.getValue());
    }
    final Map<String, String> canonicalHeaders =
        buildCanonicalHeaders("POST", target, body, canonicalAuth);
    for (final Map.Entry<String, String> entry : canonicalHeaders.entrySet()) {
      builder.addHeader(entry.getKey(), entry.getValue());
    }
    TransportSecurity.requireHttpRequestAllowed(
        "HttpClientTransport", config.baseUri(), target, canonicalHeaders, body);
    return builder.build();
  }

  private void requireCanonicalHeadersUnset() {
    for (final String candidate : config.defaultHeaders().keySet()) {
      if (candidate.equalsIgnoreCase(CanonicalRequestSigner.HEADER_ACCOUNT)
          || candidate.equalsIgnoreCase(CanonicalRequestSigner.HEADER_SIGNATURE)
          || candidate.equalsIgnoreCase(CanonicalRequestSigner.HEADER_TIMESTAMP_MS)
          || candidate.equalsIgnoreCase(CanonicalRequestSigner.HEADER_NONCE)) {
        throw new IllegalArgumentException(
            "canonical request headers must be supplied only through canonicalAuth");
      }
    }
  }

  private TransportRequest buildJsonPostRequest(
      final String path, final byte[] body, final Long maximumResponseBytes) {
    final TransportRequest.Builder builder =
        TransportRequest.builder()
            .setUri(resolvePath(path))
            .setMethod("POST")
            .setBody(Objects.requireNonNull(body, "body"))
            .addHeader("Content-Type", "application/json")
            .addHeader("Accept", "application/json")
            .setTimeout(config.requestTimeout());
    if (maximumResponseBytes != null) {
      builder.setMaximumResponseBytes(maximumResponseBytes);
    }
    for (final Map.Entry<String, String> entry : config.defaultHeaders().entrySet()) {
      builder.addHeader(entry.getKey(), entry.getValue());
    }
    return builder.build();
  }

  private TransportRequest buildVpnRequest(
      final String method,
      final String path,
      final byte[] body,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    return buildCanonicalJsonRequest(method, path, body, canonicalAuth, null);
  }

  private TransportRequest buildVpnRequest(
      final String method,
      final String path,
      final byte[] body,
      final ToriiCanonicalRequestAuth canonicalAuth,
      final long maximumResponseBytes) {
    return buildCanonicalJsonRequest(
        method, path, body, canonicalAuth, Long.valueOf(maximumResponseBytes));
  }

  private TransportRequest buildExactCanonicalJsonPostRequest(
      final String path,
      final byte[] body,
      final ToriiCanonicalRequestAuth canonicalAuth,
      final long maximumResponseBytes) {
    return buildCanonicalJsonRequest(
        "POST", path, body, canonicalAuth, Long.valueOf(maximumResponseBytes));
  }

  private TransportRequest buildCanonicalJsonRequest(
      final String method,
      final String path,
      final byte[] body,
      final ToriiCanonicalRequestAuth canonicalAuth,
      final Long maximumResponseBytes) {
    if (path.startsWith("/v1/vpn/")) {
      requireSecureVpnBaseUri();
    }
    Objects.requireNonNull(canonicalAuth, "canonicalAuth");
    requireCanonicalHeadersUnset();
    final URI target = resolvePath(path);
    final TransportRequest.Builder builder =
        TransportRequest.builder()
            .setUri(target)
            .setMethod(method)
            .addHeader("Accept", "application/json")
            .setTimeout(config.requestTimeout());
    if (maximumResponseBytes != null) {
      builder.setMaximumResponseBytes(maximumResponseBytes);
    }
    if (body != null) {
      builder.setBody(body).addHeader("Content-Type", "application/json");
    }
    if (maximumResponseBytes != null) {
      builder.setMaximumResponseBytes(maximumResponseBytes);
    }
    for (final Map.Entry<String, String> entry : config.defaultHeaders().entrySet()) {
      builder.addHeader(entry.getKey(), entry.getValue());
    }
    final Map<String, String> canonicalHeaders =
        buildCanonicalHeaders(method, target, body, canonicalAuth);
    for (final Map.Entry<String, String> entry : canonicalHeaders.entrySet()) {
      builder.addHeader(entry.getKey(), entry.getValue());
    }
    TransportSecurity.requireHttpRequestAllowed(
        "HttpClientTransport", config.baseUri(), target, canonicalHeaders, body);
    return builder.build();
  }

  private void requireSecureVpnBaseUri() {
    if (!"https".equalsIgnoreCase(config.baseUri().getScheme())) {
      throw new IllegalArgumentException("Sora VPN requests require an HTTPS Torii base URI");
    }
  }

  private TransportRequest buildOnboardingRequest(
      final String method,
      final String path,
      final byte[] body,
      final String onboardingToken) {
    final String token = requireOnboardingCredential(onboardingToken);
    for (final String key : config.defaultHeaders().keySet()) {
      if (ONBOARDING_TOKEN_HEADER.equalsIgnoreCase(key)) {
        throw new IllegalArgumentException(
            ONBOARDING_TOKEN_HEADER
                + " must be supplied only through the sponsored onboarding API");
      }
    }
    final TransportRequest.Builder builder =
        TransportRequest.builder()
            .setUri(resolvePath(path))
            .setMethod(method)
            .addHeader("Accept", "application/json")
            .setTimeout(config.requestTimeout());
    if (body != null) {
      builder.setBody(body).addHeader("Content-Type", "application/json");
    }
    for (final Map.Entry<String, String> entry : config.defaultHeaders().entrySet()) {
      builder.addHeader(entry.getKey(), entry.getValue());
    }
    builder.addHeader(ONBOARDING_TOKEN_HEADER, token);
    return builder.build();
  }

  private static String requireOnboardingCredential(final String value) {
    if (value == null || value.length() < 32 || value.length() > 256) {
      throw new IllegalArgumentException(
          "onboarding token must contain 32..256 printable non-whitespace ASCII bytes");
    }
    for (int index = 0; index < value.length(); index++) {
      final char character = value.charAt(index);
      if (character < '!' || character > '~') {
        throw new IllegalArgumentException(
            "onboarding token must contain 32..256 printable non-whitespace ASCII bytes");
      }
    }
    return value;
  }

  private Map<String, String> buildCanonicalHeaders(
      final String method,
      final URI target,
      final byte[] body,
      final ToriiCanonicalRequestAuth canonicalAuth) {
    final NetworkId networkId = config.requireLocalSigningContext().networkId();
    final Long timestampMs = canonicalAuth.timestampMs();
    final String nonce = canonicalAuth.nonce();
    if ((timestampMs == null) != (nonce == null)) {
      throw new IllegalArgumentException("timestampMs and nonce must be provided together");
    }
    if (timestampMs == null) {
      return CanonicalRequestSigner.buildHeaders(
          networkId, method, target, body, canonicalAuth);
    }
    return CanonicalRequestSigner.buildHeaders(
        networkId, method, target, body, canonicalAuth, timestampMs, nonce);
  }

  private URI resolvePath(final String path) {
    if (path == null || path.trim().isEmpty()) {
      return config.baseUri();
    }
    if (path.startsWith("http://") || path.startsWith("https://")) {
      return URI.create(path);
    }
    final String normalized = path.startsWith("/") ? path.substring(1) : path;
    final String base = config.baseUri().toString();
    final String joined = base.endsWith("/") ? base + normalized : base + "/" + normalized;
    return URI.create(joined);
  }

  private static URI appendQuery(final URI target, final Map<String, String> params) {
    if (params.isEmpty()) {
      return target;
    }
    final String targetText = target.toString();
    final int rawFragmentIndex = targetText.indexOf('#');
    final int fragmentIndex = rawFragmentIndex >= 0 ? rawFragmentIndex : targetText.length();
    final StringBuilder builder = new StringBuilder(targetText.length() + 1);
    builder.append(targetText, 0, fragmentIndex);
    builder.append(builder.indexOf("?") >= 0 ? "&" : "?");
    builder.append(encodeQuery(params));
    builder.append(targetText, fragmentIndex, targetText.length());
    return URI.create(builder.toString());
  }

  private static String encodeQuery(final Map<String, String> params) {
    final StringBuilder builder = new StringBuilder();
    boolean first = true;
    for (final Map.Entry<String, String> entry : params.entrySet()) {
      if (!first) {
        builder.append('&');
      } else {
        first = false;
      }
      builder
          .append(urlEncode(entry.getKey()))
          .append('=')
          .append(urlEncode(entry.getValue()));
    }
    return builder.toString();
  }

  private static String encodePathSegment(final String segment) {
    final String encoded = urlEncode(segment);
    return encoded.replace("+", "%20");
  }

  private static String urlEncode(final String value) {
    try {
      return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
    } catch (final UnsupportedEncodingException ex) {
      throw new IllegalStateException("UTF-8 not supported", ex);
    }
  }

  private static long saturatedDeadline(final Long timeoutMillis) {
    if (timeoutMillis == null) {
      return Long.MAX_VALUE;
    }
    final long now = System.currentTimeMillis();
    try {
      return Math.addExact(now, timeoutMillis);
    } catch (final ArithmeticException ignored) {
      return Long.MAX_VALUE;
    }
  }

  private static Throwable unwrapCompletion(final Throwable throwable) {
    Throwable current = throwable;
    while (current instanceof CompletionException && current.getCause() != null) {
      current = current.getCause();
    }
    return current;
  }

  private CompletableFuture<Void> ensureTransactionSubmissionCompatibility() {
    final TransportRequest request =
        buildJsonGetRequest(
            "/v1/node/capabilities",
            Collections.emptyMap(),
            NODE_CAPABILITIES_RESPONSE_MAX_BYTES);
    return fetchJson(
            request,
            payload -> {
              ToriiTransactionCompatibility.requireCompatible(payload);
              return Boolean.TRUE;
            },
            "transaction submission compatibility",
            200)
        .handle(
            (ignored, throwable) -> {
              if (throwable != null) {
                final Throwable cause = unwrapCompletion(throwable);
                if (cause instanceof ToriiTransactionCompatibilityException) {
                  throw new CompletionException(cause);
                }
                throw new CompletionException(
                    new ToriiTransactionCompatibilityProbeException(cause));
              }
              return null;
            });
  }

  private <T> CompletableFuture<T> fetchJson(
      final TransportRequest request,
      final Function<byte[], T> parser,
      final String errorContext) {
    return fetchJson(request, parser, errorContext, null, null);
  }

  private <T> CompletableFuture<T> fetchJson(
      final TransportRequest request,
      final Function<byte[], T> parser,
      final String errorContext,
      final Integer acceptedStatus) {
    return fetchJson(request, parser, errorContext, acceptedStatus, null);
  }

  private <T> CompletableFuture<T> fetchJson(
      final TransportRequest request,
      final Function<byte[], T> parser,
      final String errorContext,
      final Integer acceptedStatus,
      final BiFunction<T, Integer, T> responseValidator) {
    return fetchJson(request, parser, errorContext, acceptedStatus, responseValidator, false);
  }

  private <T> CompletableFuture<T> fetchJson(
      final TransportRequest request,
      final Function<byte[], T> parser,
      final String errorContext,
      final Integer acceptedStatus,
      final BiFunction<T, Integer, T> responseValidator,
      final boolean exactJsonMediaType) {
    notifyRequest(request);
    final CompletableFuture<T> future = new CompletableFuture<>();
    executor
        .execute(request)
        .whenComplete(
            (response, throwable) -> {
              if (throwable != null) {
                final Throwable cause =
                    throwable instanceof CompletionException ? throwable.getCause() : throwable;
                final RuntimeException error =
                    new RuntimeException(errorContext + " request failed", cause);
                notifyFailure(request, cause);
                future.completeExceptionally(error);
                return;
              }
              final Long maximumResponseBytes = request.maximumResponseBytes();
              if (maximumResponseBytes != null
                  && (long) response.body().length > maximumResponseBytes.longValue()) {
                final IllegalArgumentException error =
                    new IllegalArgumentException(
                        errorContext
                            + " response exceeds the "
                            + maximumResponseBytes
                            + " byte limit");
                notifyFailure(request, error);
                future.completeExceptionally(error);
                return;
              }
              final ClientResponse clientResponse =
                  new ClientResponse(
                      response.statusCode(),
                      response.body(),
                      response.message(),
                      null,
                      extractRejectCode(response));
              final boolean statusAccepted =
                  acceptedStatus == null
                      ? response.statusCode() >= 200 && response.statusCode() < 300
                      : response.statusCode() == acceptedStatus;
              if (!statusAccepted) {
                final RuntimeException error =
                    new RuntimeException(
                        errorContext + " request failed with status " + response.statusCode());
                notifyFailure(request, error);
                future.completeExceptionally(error);
                return;
              }
              try {
                if (exactJsonMediaType) {
                  requireUnambiguousApplicationJsonHeader(response.headers(), errorContext);
                }
                final T parsed = parser.apply(response.body());
                final T validated =
                    responseValidator == null
                        ? parsed
                        : responseValidator.apply(parsed, response.statusCode());
                notifyResponse(request, clientResponse);
                future.complete(validated);
              } catch (final RuntimeException ex) {
                notifyFailure(request, ex);
                future.completeExceptionally(ex);
              }
            });
    return future;
  }

  private <T> CompletableFuture<T> fetchExactJson(
      final TransportRequest request,
      final Function<byte[], T> parser,
      final String errorContext) {
    final Long maximumResponseBytes =
        Objects.requireNonNull(
            request.maximumResponseBytes(),
            errorContext + " request must declare a response-body limit");
    notifyRequest(request);
    final CompletableFuture<T> future = new CompletableFuture<>();
    executor
        .execute(request)
        .whenComplete(
            (response, throwable) -> {
              if (throwable != null) {
                final Throwable cause =
                    throwable instanceof CompletionException ? throwable.getCause() : throwable;
                notifyFailure(request, cause);
                future.completeExceptionally(
                    new RuntimeException(errorContext + " request failed", cause));
                return;
              }
              final byte[] body = response.body();
              final ClientResponse clientResponse =
                  new ClientResponse(
                      response.statusCode(),
                      body,
                      response.message(),
                      null,
                      extractRejectCode(response));
              try {
                requireExactJsonResponse(
                    response, body, maximumResponseBytes.longValue(), errorContext);
                final T parsed = parser.apply(body);
                notifyResponse(request, clientResponse);
                future.complete(parsed);
              } catch (final RuntimeException error) {
                notifyFailure(request, error);
                future.completeExceptionally(error);
              }
            });
    return future;
  }

  private CompletableFuture<byte[]> fetchExactNoritoBytes(
      final TransportRequest request, final String errorContext) {
    return fetchExactNoritoBytes(request, errorContext, false, false, false, false, false);
  }

  private CompletableFuture<byte[]> fetchExactNoritoBytes(
      final TransportRequest request,
      final String errorContext,
      final boolean requireIdentityEncoding) {
    return fetchExactNoritoBytes(
        request, errorContext, requireIdentityEncoding, false, false, false, false);
  }

  private CompletableFuture<byte[]> fetchExactNoritoBytes(
      final TransportRequest request,
      final String errorContext,
      final boolean requireIdentityEncoding,
      final boolean forbidRejectCodeHeader) {
    return fetchExactNoritoBytes(
        request, errorContext, requireIdentityEncoding, forbidRejectCodeHeader, false, false, false);
  }

  private CompletableFuture<byte[]> fetchExactNoritoBytes(
      final TransportRequest request,
      final String errorContext,
      final boolean requireIdentityEncoding,
      final boolean forbidRejectCodeHeader,
      final boolean allowExplicitIdentityEncoding,
      final boolean requirePrivateNoStore,
      final boolean requireExactResponseProvenance) {
    notifyRequest(request);
    final CompletableFuture<byte[]> future = new CompletableFuture<>();
    executor
        .execute(request)
        .whenComplete(
            (response, throwable) -> {
              if (throwable != null) {
                final Throwable cause =
                    throwable instanceof CompletionException ? throwable.getCause() : throwable;
                notifyFailure(request, cause);
                future.completeExceptionally(
                    new RuntimeException(errorContext + " request failed", cause));
                return;
              }
              final byte[] body = response.body();
              final ClientResponse clientResponse =
                  new ClientResponse(
                      response.statusCode(),
                      body,
                      response.message(),
                      null,
                      extractRejectCode(response));
              try {
                if (requireExactResponseProvenance) {
                  requireExactSignedResponseProvenance(request, response, errorContext);
                }
                final Long maximumResponseBytes = request.maximumResponseBytes();
                if (maximumResponseBytes == null) {
                  throw new IllegalStateException(
                      errorContext + " request must declare a response-body limit");
                }
                if (body.length == 0) {
                  throw new IllegalStateException(errorContext + " response must not be empty");
                }
                if ((long) body.length > maximumResponseBytes.longValue()) {
                  throw new IllegalStateException(
                      errorContext
                          + " response exceeds "
                          + maximumResponseBytes
                          + " bytes");
                }
                requireExactOptionalContentLength(response.headers(), body.length, errorContext);
                if (requirePrivateNoStore) {
                  requireExactHeader(
                      response.headers(),
                      "Content-Type",
                      APPLICATION_NORITO,
                      errorContext);
                  if (requireIdentityEncoding) {
                    if (allowExplicitIdentityEncoding) {
                      requireAbsentOrIdentityEncoding(response.headers(), errorContext);
                    } else {
                      requireHeaderAbsent(response.headers(), "Content-Encoding", errorContext);
                    }
                  }
                  requirePrivateNoStore(response.headers(), errorContext);
                }
                if (response.statusCode() != 200) {
                  throw new IllegalStateException(
                      errorContext + " request failed with status " + response.statusCode());
                }
                if (!requirePrivateNoStore) {
                  requireExactHeader(
                      response.headers(),
                      "Content-Type",
                      APPLICATION_NORITO,
                      errorContext);
                  if (requireIdentityEncoding) {
                    if (allowExplicitIdentityEncoding) {
                      requireAbsentOrIdentityEncoding(response.headers(), errorContext);
                    } else {
                      requireHeaderAbsent(response.headers(), "Content-Encoding", errorContext);
                    }
                  }
                }
                if (forbidRejectCodeHeader) {
                  for (final String name : response.headers().keySet()) {
                    if (name.equalsIgnoreCase("x-iroha-reject-code")) {
                      throw new IllegalStateException(
                          errorContext
                              + " successful response carried x-iroha-reject-code");
                    }
                  }
                }
                notifyResponse(request, clientResponse);
                future.complete(body.clone());
              } catch (final RuntimeException error) {
                notifyFailure(request, error);
                future.completeExceptionally(error);
              }
            });
    return future;
  }


  private static void requireExactSignedResponseProvenance(
      final TransportRequest request,
      final TransportResponse response,
      final String errorContext) {
    final URI finalUri = response.finalUri();
    if (response.redirected()
        || finalUri == null
        || !request.uri().toASCIIString().equals(finalUri.toASCIIString())) {
      throw new IllegalStateException(
          errorContext + " response must come from the exact signed URL without redirects");
    }
  }

  private static void requireExactHeader(
      final Map<String, List<String>> headers,
      final String name,
      final String expected,
      final String errorContext) {
    final List<String> values = headerValues(headers, name);
    if (values.size() != 1 || !expected.equals(values.get(0))) {
      throw new IllegalStateException(
          errorContext + " response " + name + " must be exactly " + expected);
    }
  }

  private static void requireHeaderAbsent(
      final Map<String, List<String>> headers,
      final String name,
      final String errorContext) {
    for (final String candidate : headers.keySet()) {
      if (candidate != null && candidate.equalsIgnoreCase(name)) {
        throw new IllegalStateException(
            errorContext + " response must not contain " + name);
      }
    }
  }

  private static void requireAbsentOrIdentityEncoding(
      final Map<String, List<String>> headers, final String errorContext) {
    final List<String> values = headerValues(headers, "Content-Encoding");
    if (!values.isEmpty()
        && (values.size() != 1 || !"identity".equalsIgnoreCase(values.get(0).trim()))) {
      throw new IllegalStateException(
          errorContext + " response Content-Encoding must be absent or identity");
    }
  }

  private static void requirePrivateNoStore(
      final Map<String, List<String>> headers, final String errorContext) {
    final List<CacheControlDirective> directives =
        parseCacheControlDirectives(headerValues(headers, "Cache-Control"));
    boolean privateDirectivePresent = false;
    boolean noStoreDirectivePresent = false;
    boolean publicDirectivePresent = false;
    if (directives != null) {
      for (final CacheControlDirective directive : directives) {
        if ("private".equals(directive.name) && !directive.hasValue) {
          privateDirectivePresent = true;
        } else if ("no-store".equals(directive.name) && !directive.hasValue) {
          noStoreDirectivePresent = true;
        }
        if ("public".equals(directive.name)) {
          publicDirectivePresent = true;
        }
      }
    }
    if (!privateDirectivePresent || !noStoreDirectivePresent || publicDirectivePresent) {
      throw new IllegalStateException(
          errorContext + " response must remain private and no-store");
    }
  }

  private static List<CacheControlDirective> parseCacheControlDirectives(
      final List<String> headerValues) {
    final List<CacheControlDirective> parsed = new ArrayList<>();
    for (final String headerValue : headerValues) {
      final List<String> rawDirectives = splitCacheControlDirectives(headerValue);
      if (rawDirectives == null) {
        return null;
      }
      for (final String rawDirective : rawDirectives) {
        final CacheControlDirective directive = parseCacheControlDirective(rawDirective);
        if (directive == null) {
          return null;
        }
        parsed.add(directive);
      }
    }
    return parsed;
  }

  private static List<String> splitCacheControlDirectives(final String headerValue) {
    final List<String> directives = new ArrayList<>();
    int start = 0;
    boolean inQuotes = false;
    boolean escaped = false;
    for (int index = 0; index < headerValue.length(); index++) {
      final char character = headerValue.charAt(index);
      if (inQuotes) {
        if (escaped) {
          if (!isHttpQuotedPairCharacter(character)) {
            return null;
          }
          escaped = false;
        } else if (character == '\\') {
          escaped = true;
        } else if (character == '"') {
          inQuotes = false;
        }
      } else if (character == '"') {
        inQuotes = true;
      } else if (character == ',') {
        directives.add(headerValue.substring(start, index));
        start = index + 1;
      }
    }
    if (inQuotes || escaped) {
      return null;
    }
    directives.add(headerValue.substring(start));
    return directives;
  }

  private static CacheControlDirective parseCacheControlDirective(final String rawDirective) {
    int index = skipHttpOws(rawDirective, 0);
    final int nameStart = index;
    while (index < rawDirective.length()
        && isHttpTokenCharacter(rawDirective.charAt(index))) {
      index++;
    }
    if (index == nameStart) {
      return null;
    }
    final String name = rawDirective.substring(nameStart, index).toLowerCase(Locale.ROOT);
    index = skipHttpOws(rawDirective, index);
    if (index == rawDirective.length()) {
      return new CacheControlDirective(name, false);
    }
    if (rawDirective.charAt(index) != '=') {
      return null;
    }
    index = skipHttpOws(rawDirective, index + 1);
    if (index == rawDirective.length()) {
      return null;
    }

    if (rawDirective.charAt(index) == '"') {
      index = parseCacheControlQuotedValue(rawDirective, index);
      if (index < 0) {
        return null;
      }
    } else {
      final int valueStart = index;
      while (index < rawDirective.length()
          && isHttpTokenCharacter(rawDirective.charAt(index))) {
        index++;
      }
      if (index == valueStart) {
        return null;
      }
    }
    index = skipHttpOws(rawDirective, index);
    return index == rawDirective.length() ? new CacheControlDirective(name, true) : null;
  }

  private static int parseCacheControlQuotedValue(final String value, final int quoteIndex) {
    int index = quoteIndex + 1;
    while (index < value.length()) {
      final char character = value.charAt(index);
      if (character == '"') {
        return index + 1;
      }
      if (character == '\\') {
        index++;
        if (index == value.length()
            || !isHttpQuotedPairCharacter(value.charAt(index))) {
          return -1;
        }
      } else if (!isHttpQuotedTextCharacter(character)) {
        return -1;
      }
      index++;
    }
    return -1;
  }

  private static final class CacheControlDirective {
    private final String name;
    private final boolean hasValue;

    private CacheControlDirective(final String name, final boolean hasValue) {
      this.name = name;
      this.hasValue = hasValue;
    }
  }

  private static void requireExactOptionalContentLength(
      final Map<String, List<String>> headers,
      final int actualBytes,
      final String errorContext) {
    final List<String> values = new ArrayList<>();
    boolean matchingHeaderPresent = false;
    for (final Map.Entry<String, List<String>> entry : headers.entrySet()) {
      if (entry.getKey() != null && entry.getKey().equalsIgnoreCase("Content-Length")) {
        matchingHeaderPresent = true;
        if (entry.getValue() != null) {
          values.addAll(entry.getValue());
        }
      }
    }
    if (!matchingHeaderPresent) {
      return;
    }
    if (values.size() != 1) {
      throw new IllegalStateException(errorContext + " response has ambiguous Content-Length");
    }
    final String value = values.get(0);
    if (!isCanonicalUnsignedDecimal(value)) {
      throw new IllegalStateException(
          errorContext + " response Content-Length must be one canonical decimal integer");
    }
    if (!Integer.toString(actualBytes).equals(value)) {
      throw new IllegalStateException(
          errorContext + " response Content-Length does not match the body");
    }
  }

  private static List<String> headerValues(
      final Map<String, List<String>> headers, final String name) {
    final List<String> values = new ArrayList<>();
    for (final Map.Entry<String, List<String>> entry : headers.entrySet()) {
      if (entry.getKey() != null
          && entry.getKey().equalsIgnoreCase(name)
          && entry.getValue() != null) {
        values.addAll(entry.getValue());
      }
    }
    return values;
  }

  private static boolean isCanonicalUnsignedDecimal(final String value) {
    if (value == null || value.isEmpty()) {
      return false;
    }
    if (value.equals("0")) {
      return true;
    }
    if (value.charAt(0) < '1' || value.charAt(0) > '9') {
      return false;
    }
    for (int index = 1; index < value.length(); index++) {
      final char character = value.charAt(index);
      if (character < '0' || character > '9') {
        return false;
      }
    }
    return true;
  }

  private static void requireExactJsonResponse(
      final TransportResponse response,
      final byte[] body,
      final long maximumResponseBytes,
      final String errorContext) {
    if (response.statusCode() != 200) {
      throw new IllegalStateException(
          errorContext + " request failed with status " + response.statusCode());
    }
    requireUnambiguousApplicationJsonHeader(response.headers(), errorContext);
    if (body.length == 0) {
      throw new IllegalStateException(errorContext + " response must not be empty");
    }
    if ((long) body.length > maximumResponseBytes) {
      throw new IllegalStateException(
          errorContext + " response exceeds " + maximumResponseBytes + " bytes");
    }
    requireExactOptionalContentLength(response.headers(), body.length, errorContext);
  }

  private static void requireUnambiguousApplicationJsonHeader(
      final Map<String, List<String>> headers, final String errorContext) {
    final List<String> contentTypes = headerValues(headers, "Content-Type");
    if (contentTypes.size() != 1 || !isUnambiguousApplicationJson(contentTypes.get(0))) {
      throw new IllegalStateException(
          errorContext + " response Content-Type must be exactly application/json");
    }
  }

  private static boolean isUnambiguousApplicationJson(final String value) {
    if (value == null || value.indexOf(',') >= 0) {
      return false;
    }
    int index = skipHttpOws(value, 0);
    if (index + APPLICATION_JSON.length() > value.length()) {
      return false;
    }
    for (int offset = 0; offset < APPLICATION_JSON.length(); offset++) {
      final char actual = value.charAt(index + offset);
      final char expected = APPLICATION_JSON.charAt(offset);
      if (actual != expected
          && !(expected >= 'a' && expected <= 'z' && actual == (char) (expected - 32))) {
        return false;
      }
    }
    index = skipHttpOws(value, index + APPLICATION_JSON.length());
    while (index < value.length()) {
      if (value.charAt(index) != ';') {
        return false;
      }
      index = skipHttpOws(value, index + 1);
      final int nameStart = index;
      while (index < value.length() && isHttpTokenCharacter(value.charAt(index))) {
        index++;
      }
      if (index == nameStart || index >= value.length() || value.charAt(index) != '=') {
        return false;
      }
      index++;
      if (index >= value.length()) {
        return false;
      }
      if (value.charAt(index) == '"') {
        index++;
        boolean closed = false;
        while (index < value.length()) {
          final char current = value.charAt(index);
          if (current == '"') {
            index++;
            closed = true;
            break;
          }
          if (current == '\\') {
            index++;
            if (index >= value.length()
                || !isHttpQuotedPairCharacter(value.charAt(index))) {
              return false;
            }
          } else if (!isHttpQuotedTextCharacter(current)) {
            return false;
          }
          index++;
        }
        if (!closed) {
          return false;
        }
      } else {
        final int parameterValueStart = index;
        while (index < value.length() && isHttpTokenCharacter(value.charAt(index))) {
          index++;
        }
        if (index == parameterValueStart) {
          return false;
        }
      }
      index = skipHttpOws(value, index);
    }
    return true;
  }

  private static int skipHttpOws(final String value, final int start) {
    int index = start;
    while (index < value.length()
        && (value.charAt(index) == ' ' || value.charAt(index) == '\t')) {
      index++;
    }
    return index;
  }

  private static boolean isHttpTokenCharacter(final char value) {
    return (value >= '0' && value <= '9')
        || (value >= 'A' && value <= 'Z')
        || (value >= 'a' && value <= 'z')
        || "!#$%&'*+-.^_`|~".indexOf(value) >= 0;
  }

  private static boolean isHttpQuotedTextCharacter(final char value) {
    return value == 0x09
        || (value >= 0x20 && value <= 0x21)
        || (value >= 0x23 && value <= 0x5B)
        || (value >= 0x5D && value <= 0x7E)
        || (value >= 0x80 && value <= 0xFF);
  }

  private static boolean isHttpQuotedPairCharacter(final char value) {
    return value == 0x09
        || (value >= 0x20 && value <= 0x7E)
        || (value >= 0x80 && value <= 0xFF);
  }

  private <T> CompletableFuture<Optional<T>> fetchJsonAllowingNotFound(
      final TransportRequest request,
      final Function<byte[], T> parser,
      final String errorContext) {
    return fetchJsonAllowingNotFound(request, parser, errorContext, null);
  }

  private <T> CompletableFuture<Optional<T>> fetchJsonAllowingNotFound(
      final TransportRequest request,
      final Function<byte[], T> parser,
      final String errorContext,
      final Integer acceptedStatus) {
    notifyRequest(request);
    final CompletableFuture<Optional<T>> future = new CompletableFuture<>();
    executor
        .execute(request)
        .whenComplete(
            (response, throwable) -> {
              if (throwable != null) {
                final Throwable cause =
                    throwable instanceof CompletionException ? throwable.getCause() : throwable;
                final RuntimeException error =
                    new RuntimeException(errorContext + " request failed", cause);
                notifyFailure(request, cause);
                future.completeExceptionally(error);
                return;
              }
              final ClientResponse clientResponse =
                  new ClientResponse(
                      response.statusCode(),
                      response.body(),
                      response.message(),
                      null,
                      extractRejectCode(response));
              if (response.statusCode() == 404) {
                notifyResponse(request, clientResponse);
                future.complete(Optional.empty());
                return;
              }
              final boolean statusAccepted =
                  acceptedStatus == null
                      ? response.statusCode() >= 200 && response.statusCode() < 300
                      : response.statusCode() == acceptedStatus;
              if (!statusAccepted) {
                final RuntimeException error =
                    new RuntimeException(
                        errorContext + " request failed with status " + response.statusCode());
                notifyFailure(request, error);
                future.completeExceptionally(error);
                return;
              }
              try {
                final T parsed = parser.apply(response.body());
                notifyResponse(request, clientResponse);
                future.complete(Optional.of(parsed));
              } catch (final RuntimeException ex) {
                notifyFailure(request, ex);
                future.completeExceptionally(ex);
              }
            });
    return future;
  }

  private <T> CompletableFuture<Optional<T>> fetchOptionalJson(
      final TransportRequest request,
      final Function<byte[], T> parser,
      final String errorContext) {
    notifyRequest(request);
    final CompletableFuture<Optional<T>> future = new CompletableFuture<>();
    executor
        .execute(request)
        .whenComplete(
            (response, throwable) -> {
              if (throwable != null) {
                final Throwable cause =
                    throwable instanceof CompletionException ? throwable.getCause() : throwable;
                final RuntimeException error =
                    new RuntimeException(errorContext + " request failed", cause);
                notifyFailure(request, cause);
                future.completeExceptionally(error);
                return;
              }
              final ClientResponse clientResponse =
                  new ClientResponse(
                      response.statusCode(),
                      response.body(),
                      response.message(),
                      null,
                      extractRejectCode(response));
              if (response.statusCode() < 200 || response.statusCode() >= 300) {
                final RuntimeException error =
                    new RuntimeException(
                        errorContext + " request failed with status " + response.statusCode());
                notifyFailure(request, error);
                future.completeExceptionally(error);
                return;
              }
              if (response.body().length == 0) {
                notifyResponse(request, clientResponse);
                future.complete(Optional.empty());
                return;
              }
              try {
                final T parsed = parser.apply(response.body());
                notifyResponse(request, clientResponse);
                future.complete(Optional.of(parsed));
              } catch (final RuntimeException ex) {
                notifyFailure(request, ex);
                future.completeExceptionally(ex);
              }
            });
    return future;
  }

  private static byte[] encodeJsonBody(final Map<String, Object> payload) {
    return JsonEncoder.encode(Objects.requireNonNull(payload, "payload"))
        .getBytes(StandardCharsets.UTF_8);
  }

  private static Map<String, Object> objectMapOf(final String key, final Object value) {
    final Map<String, Object> map = new LinkedHashMap<>();
    map.put(key, value);
    return Collections.unmodifiableMap(map);
  }

  private static Map<String, Object> objectMapOf(
      final String key1,
      final Object value1,
      final String key2,
      final Object value2) {
    final Map<String, Object> map = new LinkedHashMap<>();
    map.put(key1, value1);
    map.put(key2, value2);
    return Collections.unmodifiableMap(map);
  }

  private static Map<String, Object> objectMapOf(
      final String key1,
      final Object value1,
      final String key2,
      final Object value2,
      final String key3,
      final Object value3) {
    final Map<String, Object> map = new LinkedHashMap<>();
    map.put(key1, value1);
    map.put(key2, value2);
    map.put(key3, value3);
    return Collections.unmodifiableMap(map);
  }

  static IdentifierResolveRequest buildIdentifierResolveRequest(
      final String policyId,
      final String encryptedInputHex,
      final RamLfeOutputOpening outputOpening) {
    final String normalizedPolicyId = normalizeNonBlank(policyId, "policyId");
    final String normalizedEncryptedInput =
        normalizeEvenLengthHex(encryptedInputHex, "encryptedInputHex");
    return IdentifierResolveRequest.encrypted(
        normalizedPolicyId, normalizedEncryptedInput, outputOpening);
  }

  static RamLfeExecuteRequest buildRamLfeExecuteRequest(final String encryptedInputHex) {
    final String normalizedEncryptedInput =
        normalizeEvenLengthHex(encryptedInputHex, "encryptedInputHex");
    return RamLfeExecuteRequest.encrypted(normalizedEncryptedInput);
  }

  static Map<String, Object> buildIdentifierResolvePayload(
      final String policyId,
      final String encryptedInputHex,
      final RamLfeOutputOpening outputOpening) {
    final String normalizedPolicyId = normalizeNonBlank(policyId, "policyId");
    final String normalizedEncryptedInput =
        normalizeEvenLengthHex(encryptedInputHex, "encryptedInputHex");
    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("policy_id", normalizedPolicyId);
    payload.put("encrypted_input", normalizedEncryptedInput);
    payload.put("output_opening", Objects.requireNonNull(outputOpening, "outputOpening").toJsonMap());
    return payload;
  }

  static Map<String, Object> buildRamLfeExecutePayload(final String encryptedInputHex) {
    final String normalizedEncryptedInput =
        normalizeEvenLengthHex(encryptedInputHex, "encryptedInputHex");
    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("encrypted_input", normalizedEncryptedInput);
    return payload;
  }

  static Map<String, Object> buildRamLfeReceiptVerifyPayload(
      final Map<String, Object> receipt, final String outputHex) {
    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("receipt", new LinkedHashMap<>(Objects.requireNonNull(receipt, "receipt")));
    if (outputHex != null) {
      payload.put("output_hex", normalizeEvenLengthHex(outputHex, "outputHex"));
    }
    return payload;
  }

  static Map<String, Object> buildVpnQuoteCreatePayload(
      final String exitClass,
      final String meteringPublicKeyHex) {
    final Map<String, Object> payload = new LinkedHashMap<>();
    final String normalizedExitClass = normalizeOptionalNonBlank(exitClass, "exitClass");
    payload.put("exit_class", normalizedExitClass == null ? "" : normalizedExitClass);
    payload.put(
        "metering_public_key_hex",
        normalizeEd25519PublicKeyHex(meteringPublicKeyHex, "meteringPublicKeyHex"));
    return payload;
  }

  static Map<String, Object> buildVpnSessionCreatePayload(
      final String exitClass,
      final String quoteId,
      final String paymentTxHash,
      final String meteringPublicKeyHex) {
    final Map<String, Object> payload = new LinkedHashMap<>();
    final String normalizedExitClass = normalizeOptionalNonBlank(exitClass, "exitClass");
    payload.put("exit_class", normalizedExitClass == null ? "" : normalizedExitClass);
    payload.put("quote_id", normalizeHex32(quoteId, "quoteId"));
    payload.put("payment_tx_hash", normalizeHex32(paymentTxHash, "paymentTxHash"));
    payload.put(
        "metering_public_key_hex",
        normalizeEd25519PublicKeyHex(meteringPublicKeyHex, "meteringPublicKeyHex"));
    return payload;
  }

  static Map<String, Object> buildVpnReceiptSubmitPayload(
      final String relayReceiptHex,
      final String clientVoucherHex,
      final String leaseIdHex) {
    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("relay_receipt_hex", normalizeEvenLengthHex(relayReceiptHex, "relayReceiptHex"));
    payload.put("client_voucher_hex", normalizeEvenLengthHex(clientVoucherHex, "clientVoucherHex"));
    if (leaseIdHex != null) {
      payload.put("lease_id_hex", normalizeHex32(leaseIdHex, "leaseIdHex"));
    }
    return payload;
  }

  /** Builds the secret-free request used to prepare a contract-call draft. */
  static Map<String, Object> buildContractCallDraftPayload(
      final String authority,
      final FeePaymentIntent feePayment,
      final String contractAddress,
      final String contractAlias,
      final String entrypoint,
      final Object payloadValue) {
    if (feePayment == null || feePayment.gasLimit() == null) {
      throw new IllegalArgumentException("contract feePayment must include gasLimit");
    }
    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("authority", normalizeNonBlank(authority, "authority"));
    payload.putAll(buildContractTargetSelector(contractAddress, contractAlias));
    payload.put("entrypoint", normalizeNonBlank(entrypoint, "entrypoint"));
    if (payloadValue != null) {
      payload.put("payload", payloadValue);
    }
    payload.put("fee_payment", feePayment.toJsonMap());
    return payload;
  }

  private static void validateContractCallDraftIntent(
      final Map<String, Object> request, final ContractCallDraftIntent draftIntent) {
    Objects.requireNonNull(draftIntent, "draftIntent");
    final String authority = (String) request.get("authority");
    AccountIdLiteral.requireCanonicalI105Address(authority, "authority");
    if (!draftIntent.invocation().entrypoint().equals(request.get("entrypoint"))) {
      throw new IllegalArgumentException(
          "contract call draft intent entrypoint does not match the request");
    }
    final Object requestedAddress = request.get("contract_address");
    if (requestedAddress != null
        && !draftIntent.invocation().contractAddress().equals(requestedAddress)) {
      throw new IllegalArgumentException(
          "contract call draft intent address does not match the request");
    }
    if (request.containsKey("payload") != (draftIntent.invocation().arguments() != null)) {
      throw new IllegalArgumentException(
          "contract call draft intent argument presence does not match the request payload");
    }
  }

  /** Validates that Torii returned a secret-free draft bound to caller-trusted local intent. */
  static ContractCallResponse validateContractCallDraft(
      final ContractCallResponse response,
      final Map<String, Object> request,
      final NetworkId expectedNetworkId,
      final ContractCallDraftIntent draftIntent) {
    Objects.requireNonNull(response, "response");
    Objects.requireNonNull(expectedNetworkId, "expectedNetworkId");
    validateContractCallDraftIntent(request, draftIntent);
    if (!response.ok()) {
      throw new IllegalStateException("contract call draft.ok must be true");
    }
    if (response.submitted()) {
      throw new IllegalStateException("contract call draft must not be submitted");
    }
    if (response.txHashHex() != null || response.pipelineStatus() != null) {
      throw new IllegalStateException("contract call draft must not contain submission state");
    }
    if (!Objects.equals(response.entrypoint(), request.get("entrypoint"))) {
      throw new IllegalStateException(
          "contract call draft entrypoint is not bound to the request");
    }
    final ContractOperationReceipt receipt = response.operationReceipt();
    if (receipt == null) {
      throw new IllegalStateException("contract call draft must contain an operation receipt");
    }
    if (!"contract_call".equals(receipt.operationKind())
        || !"pending_signature".equals(receipt.status())
        || !"torii".equals(receipt.transport())) {
      throw new IllegalStateException(
          "contract call draft receipt must be a pending_signature Torii contract call");
    }
    if (!Objects.equals(receipt.entrypoint(), response.entrypoint())
        || receipt.txHashHex() != null) {
      throw new IllegalStateException("contract call draft receipt is inconsistent");
    }
    if (response.entrypointHashHex() != null || receipt.entrypointHashHex() != null) {
      throw new IllegalStateException(
          "contract call draft must not claim a final entrypoint hash");
    }
    final String expectedAddress = draftIntent.invocation().contractAddress();
    if (!expectedAddress.equals(response.contractAddress())
        || !expectedAddress.equals(receipt.contractAddress())) {
      throw new IllegalStateException(
          "contract call draft resolved address is not bound to the trusted intent");
    }
    final Object expectedAlias = request.get("contract_alias");
    if (expectedAlias != null) {
      if (!expectedAlias.equals(receipt.contractAlias())) {
        throw new IllegalStateException("contract call draft alias is not bound to the request");
      }
    } else if (receipt.contractAlias() != null) {
      throw new IllegalStateException("contract call draft receipt unexpectedly contains an alias");
    }
    final String expectedCodeHash = hexLower(draftIntent.invocation().expectedCodeHash());
    if (!expectedCodeHash.equals(response.codeHashHex())
        || !expectedCodeHash.equals(receipt.codeHashHex())) {
      throw new IllegalStateException(
          "contract call draft code hash is not bound to the trusted intent");
    }
    if (!draftIntent.invocation().entrypoint().equals(receipt.entrypoint())) {
      throw new IllegalStateException(
          "contract call draft receipt entrypoint is not bound to the trusted intent");
    }
    if (!Objects.equals(receipt.dataspace(), response.dataspace())
        || !Objects.equals(receipt.abiHashHex(), response.abiHashHex())) {
      throw new IllegalStateException(
          "contract call draft receipt target metadata is inconsistent with the response");
    }
    if (response.transactionTtlMs() != null) {
      throw new IllegalStateException(
          "contract call draft response unexpectedly selected a transaction TTL");
    }
    final FeePaymentIntent requestedFee =
        FeePaymentJson.parse(request.get("fee_payment"), "contract call request.fee_payment");
    final FeePaymentIntent responseFee = receipt.feePayment();
    if (responseFee == null || !requestedFee.hasSamePayerAndGasBound(responseFee)) {
      throw new IllegalStateException(
          "contract call draft fee_payment changed the requested payer, sponsor revision, or gas bound");
    }
    if (!Objects.equals(receipt.gasLimit(), responseFee.gasLimit())) {
      throw new IllegalStateException(
          "contract call draft receipt gas limit is inconsistent with fee_payment");
    }
    if (!contractCallPayloadDigestHex(request).equals(receipt.payloadDigestHex())) {
      throw new IllegalStateException(
          "contract call draft receipt payload digest does not match the exact request payload");
    }
    if (receipt.gasUsed() != null) {
      throw new IllegalStateException(
          "contract call draft receipt must not report gas usage before signing");
    }
    final TransactionPayload decoded =
        decodeUnsignedDraftPayload(
            response.transactionPayloadB64(),
            response.signingMessageB64(),
            "contract call draft");
    final TransactionPayload expected =
        TransactionPayload.builder()
            .setNetworkId(expectedNetworkId)
            .setAuthority((String) request.get("authority"))
            .setCreationTimeMs(response.creationTimeMs())
            .setExecutable(Executable.contractCall(draftIntent.invocation()))
            .setFeePayment(responseFee)
            .setMetadata(draftIntent.metadata())
            .buildDecodedForCodec();
    if (!sameTransactionPayload(decoded, expected)) {
      throw new IllegalStateException(
          "contract call transaction payload does not match the exact caller-trusted executable and metadata");
    }
    return response;
  }

  private static String contractCallPayloadDigestHex(final Map<String, Object> request) {
    final Object payload = request.get("payload");
    final byte[] canonicalBytes;
    if (payload == null) {
      canonicalBytes = new byte[0];
    } else {
      final String canonical = JsonValue.parse(JsonEncoder.encode(payload)).canonicalJson();
      canonicalBytes = canonical.getBytes(StandardCharsets.UTF_8);
    }
    return hexLower(Blake3.hashUnbounded(canonicalBytes));
  }




  private static TransactionPayload decodeUnsignedDraftPayload(
      final String transactionPayloadB64,
      final String signingMessageB64,
      final String context) {
    final byte[] transactionPayload;
    final byte[] signingMessage;
    try {
      transactionPayload =
          Base64.getDecoder()
              .decode(
                  normalizeRequiredExactBase64Payload(
                      transactionPayloadB64, context + ".transaction_payload_b64"));
      signingMessage =
          Base64.getDecoder()
              .decode(
                  normalizeRequiredExactBase64Payload(
                      signingMessageB64, context + ".signing_message_b64"));
    } catch (final RuntimeException ex) {
      throw new IllegalStateException(
          context + " must contain exact canonical base64 draft fields", ex);
    }
    if (signingMessage.length != 32
        || !Arrays.equals(signingMessage, IrohaHash.prehash(transactionPayload))) {
      throw new IllegalStateException(
          context + ".signing_message_b64 must be the exact TransactionPayload hash");
    }
    try {
      return NoritoJavaCodecAdapter.decodeCanonicalTransactionPayload(transactionPayload);
    } catch (final Exception ex) {
      throw new IllegalStateException(
          context + ".transaction_payload_b64 must contain one canonical TransactionPayload",
          ex);
    }
  }

  private static boolean sameTransactionPayload(
      final TransactionPayload left, final TransactionPayload right) {
    return left.networkId().equals(right.networkId())
        && sameCanonicalAccountId(left.authority(), right.authority())
        && left.creationTimeMs() == right.creationTimeMs()
        && left.executable().equals(right.executable())
        && left.timeToLiveMs().equals(right.timeToLiveMs())
        && left.nonce().equals(right.nonce())
        && left.feePayment().equals(right.feePayment())
        && left.metadata().equals(right.metadata())
        && left.attachments().equals(right.attachments());
  }

  private static boolean sameCanonicalAccountId(final String left, final String right) {
    try {
      return AccountAddress.parseEncodedIgnoringCurveSupport(left, null)
          .canonicalHex()
          .equals(
              AccountAddress.parseEncodedIgnoringCurveSupport(right, null).canonicalHex());
    } catch (final AccountAddress.AccountAddressException exception) {
      return false;
    }
  }


  static Map<String, Object> buildVerifyingKeyRegisterPayload(
      final VerifyingKeyRegisterRequest request) {
    Objects.requireNonNull(request, "request");
    final String backend =
        VerifyingKeyBackendTag.requireVerifierBackendRegistryLabelV1(request.backend(), "backend");
    final VerifyingKeyPayload vkPayload =
        normalizeVerifierBytes(request.verifyingKeyBytes(), request.verifyingKeyLength());
    final String commitmentHex = normalizeOptionalHex32(request.commitmentHex(), "commitmentHex");
    validateVerifyingKeyMaterial(vkPayload, commitmentHex);
    validateInlineVerifyingKeyCommitment(
        backend, vkPayload == null ? null : vkPayload.bytes(), commitmentHex);
    validateVerifyingKeyHeightRange(request.activationHeight(), request.withdrawHeight());

    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("authority", normalizeVerifyingKeyAuthority(request.authority()));
    payload.put("backend", backend);
    payload.put("name", normalizeVerifyingKeyName(request.name()));
    payload.put("version", normalizePositiveU32(request.version(), "version"));
    payload.put("circuit_id", normalizeNonBlank(request.circuitId(), "circuitId"));
    payload.put(
        "public_inputs_schema_hash_hex",
        normalizeHex32(request.publicInputsSchemaHashHex(), "publicInputsSchemaHashHex"));
    payload.put("gas_schedule_id", normalizeNonBlank(request.gasScheduleId(), "gasScheduleId"));
    putOptionalVerifierFields(
        payload,
        request.curve(),
        request.maxProofBytes(),
        request.metadataUriCid(),
        request.verifyingKeyBytesCid(),
        request.activationHeight(),
        request.withdrawHeight(),
        commitmentHex,
        vkPayload,
        request.status());
    return payload;
  }

  static Map<String, Object> buildVerifyingKeyUpdatePayload(
      final VerifyingKeyUpdateRequest request) {
    Objects.requireNonNull(request, "request");
    final String backend =
        VerifyingKeyBackendTag.requireVerifierBackendRegistryLabelV1(request.backend(), "backend");
    final VerifyingKeyPayload vkPayload =
        normalizeVerifierBytes(request.verifyingKeyBytes(), request.verifyingKeyLength());
    final String commitmentHex = normalizeOptionalHex32(request.commitmentHex(), "commitmentHex");
    validateVerifyingKeyMaterial(vkPayload, commitmentHex);
    validateInlineVerifyingKeyCommitment(
        backend, vkPayload == null ? null : vkPayload.bytes(), commitmentHex);
    validateVerifyingKeyHeightRange(request.activationHeight(), request.withdrawHeight());

    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("authority", normalizeVerifyingKeyAuthority(request.authority()));
    payload.put("backend", backend);
    payload.put("name", normalizeVerifyingKeyName(request.name()));
    payload.put("version", normalizePositiveU32(request.version(), "version"));
    payload.put("circuit_id", normalizeNonBlank(request.circuitId(), "circuitId"));
    payload.put(
        "public_inputs_schema_hash_hex",
        normalizeHex32(request.publicInputsSchemaHashHex(), "publicInputsSchemaHashHex"));
    if (request.gasScheduleId() != null) {
      payload.put("gas_schedule_id", normalizeNonBlank(request.gasScheduleId(), "gasScheduleId"));
    }
    putOptionalVerifierFields(
        payload,
        request.curve(),
        request.maxProofBytes(),
        request.metadataUriCid(),
        request.verifyingKeyBytesCid(),
        request.activationHeight(),
        request.withdrawHeight(),
        commitmentHex,
        vkPayload,
        request.status());
    return payload;
  }

  static Map<String, String> buildContractTargetSelector(
      final String contractAddress, final String contractAlias) {
    final boolean hasContractAddress = contractAddress != null;
    final boolean hasContractAlias = contractAlias != null;
    if (hasContractAddress == hasContractAlias) {
      throw new IllegalArgumentException(
          "Exactly one of contractAddress or contractAlias must be provided");
    }
    final Map<String, String> selector = new LinkedHashMap<>();
    if (hasContractAddress) {
      selector.put(
          "contract_address",
          normalizeNonBlank(contractAddress, "contractAddress"));
      return selector;
    }
    selector.put(
        "contract_alias",
        normalizeNonBlank(contractAlias, "contractAlias"));
    return selector;
  }

  static String normalizeRequiredBase64Payload(final String value, final String field) {
    final String normalized = normalizeNonBlank(value, field);
    final byte[] decoded;
    try {
      decoded = Base64.getDecoder().decode(normalized);
    } catch (final IllegalArgumentException ex) {
      throw new IllegalArgumentException(field + " must be valid base64", ex);
    }
    if (decoded.length == 0) {
      throw new IllegalArgumentException(field + " must not decode to empty bytes");
    }
    return normalized;
  }

  static String normalizeRequiredExactBase64Payload(final String value, final String field) {
    if (value.isEmpty() || !value.equals(value.trim())) {
      throw new IllegalArgumentException(field + " must be exact standard-base64");
    }
    final byte[] decoded;
    try {
      decoded = Base64.getDecoder().decode(value);
    } catch (final IllegalArgumentException ex) {
      throw new IllegalArgumentException(field + " must be valid base64", ex);
    }
    if (decoded.length == 0) {
      throw new IllegalArgumentException(field + " must not decode to empty bytes");
    }
    if (!Base64.getEncoder().encodeToString(decoded).equals(value)) {
      throw new IllegalArgumentException(field + " must be exact standard-base64");
    }
    return value;
  }

  static String normalizeOptionalNonBlank(final String value, final String field) {
    return value == null ? null : normalizeNonBlank(value, field);
  }

  static String normalizeNonBlank(final String value, final String field) {
    final String trimmed = Objects.requireNonNull(value, field + " must not be null").trim();
    if (trimmed.isEmpty()) {
      throw new IllegalArgumentException(field + " must not be blank");
    }
    return trimmed;
  }

  static String normalizeVerifyingKeyName(final String value) {
    final String normalized = normalizeNonBlank(value, "name");
    if (normalized.indexOf(':') >= 0) {
      throw new IllegalArgumentException("name must not contain ':' characters");
    }
    return normalized;
  }

  static String normalizeVerifyingKeyAuthority(final String value) {
    final String normalized = normalizeNonBlank(value, "authority");
    final Integer discriminant = AccountAddress.detectI105Discriminant(normalized);
    if (discriminant == null) {
      throw new IllegalArgumentException(
          "authority must be a canonical I105 account literal");
    }
    try {
      final AccountAddress address = AccountAddress.fromI105(normalized, discriminant);
      if (!normalized.equals(address.toI105(discriminant))) {
        throw new IllegalArgumentException(
            "authority must be a canonical I105 account literal");
      }
    } catch (final AccountAddress.AccountAddressException ex) {
      throw new IllegalArgumentException(
          "authority must be a canonical I105 account literal", ex);
    }
    return normalized;
  }

  static String normalizeEvenLengthHex(final String value, final String field) {
    String trimmed = normalizeNonBlank(value, field);
    if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
      trimmed = trimmed.substring(2);
    }
    if ((trimmed.length() & 1) != 0 || trimmed.isEmpty()) {
      throw new IllegalArgumentException(field + " must be an even-length hex string");
    }
    for (int i = 0; i < trimmed.length(); i++) {
      final char c = trimmed.charAt(i);
      final boolean isHex =
          (c >= '0' && c <= '9')
              || (c >= 'a' && c <= 'f')
              || (c >= 'A' && c <= 'F');
      if (!isHex) {
        throw new IllegalArgumentException(field + " must be an even-length hex string");
      }
    }
    return trimmed.toLowerCase();
  }

  static String normalizeExactEvenLengthHex(final String value, final String field) {
    if (!Objects.requireNonNull(value, field + " must not be null").trim().equals(value)) {
      throw new IllegalArgumentException(field + " must be a canonical hex string");
    }
    return normalizeEvenLengthHex(value, field);
  }

  static String normalizeHexBytes(
      final String value, final String field, final int expectedByteLength) {
    final String normalized = normalizeEvenLengthHex(value, field);
    if (normalized.length() != expectedByteLength * 2) {
      throw new IllegalArgumentException(
          field + " must be a " + expectedByteLength + "-byte hex string");
    }
    return normalized;
  }

  static String normalizeHex32(final String value, final String field) {
    final String normalized = normalizeEvenLengthHex(value, field);
    if (normalized.length() != 64) {
      throw new IllegalArgumentException(field + " must contain 64 hex characters");
    }
    return normalized;
  }

  static String normalizeHex16(final String value, final String field) {
    final String normalized = normalizeEvenLengthHex(value, field);
    if (normalized.length() != 32) {
      throw new IllegalArgumentException(field + " must contain 32 hex characters");
    }
    return normalized;
  }

  static String normalizeEd25519PublicKeyHex(final String value, final String field) {
    final String normalized = normalizeHex32(value, field);
    final byte[] publicKey = new byte[Ed25519PublicKeyAdmission.PUBLIC_KEY_LENGTH];
    for (int index = 0; index < publicKey.length; index++) {
      final int offset = index * 2;
      publicKey[index] =
          (byte)
              ((Character.digit(normalized.charAt(offset), 16) << 4)
                  | Character.digit(normalized.charAt(offset + 1), 16));
    }
    if (!Ed25519PublicKeyAdmission.isValid(publicKey)) {
      throw new IllegalArgumentException(
          field + " must encode a canonical prime-order Ed25519 public key");
    }
    return normalized;
  }

  static String normalizeOptionalHex32(final String value, final String field) {
    if (value == null || value.trim().isEmpty()) {
      return null;
    }
    return normalizeHex32(value, field);
  }

  static long normalizePositiveU32(final long value, final String field) {
    if (value <= 0L || value > U32_MAX) {
      throw new IllegalArgumentException(field + " must be a positive u32");
    }
    return value;
  }

  static Long normalizeOptionalU32(final Long value, final String field) {
    if (value == null) {
      return null;
    }
    if (value.longValue() < 0L || value.longValue() > U32_MAX) {
      throw new IllegalArgumentException(field + " must be a u32");
    }
    return value;
  }

  static Long normalizeOptionalNonNegative(final Long value, final String field) {
    if (value == null) {
      return null;
    }
    if (value.longValue() < 0L) {
      throw new IllegalArgumentException(field + " must be non-negative");
    }
    return value;
  }

  static String normalizeVerifyingKeyStatus(final String value) {
    final String normalized = normalizeOptionalNonBlank(value, "status");
    if (normalized == null) {
      return null;
    }
    if ("proposed".equalsIgnoreCase(normalized)) {
      return "Proposed";
    }
    if ("active".equalsIgnoreCase(normalized)) {
      return "Active";
    }
    if ("withdrawn".equalsIgnoreCase(normalized)) {
      return "Withdrawn";
    }
    throw new IllegalArgumentException("status must be Proposed, Active, or Withdrawn");
  }

  private static VerifyingKeyPayload normalizeVerifierBytes(
      final byte[] bytes, final Long explicitLength) {
    if (bytes == null) {
      final Long length =
          explicitLength == null ? null : normalizePositiveU32(explicitLength, "vkLen");
      return length == null ? null : new VerifyingKeyPayload(null, length);
    }
    if (bytes.length == 0) {
      throw new IllegalArgumentException("vkBytes must not be empty");
    }
    final long actualLength = bytes.length;
    if (actualLength > U32_MAX) {
      throw new IllegalArgumentException("vkBytes length must fit in a u32");
    }
    if (explicitLength != null) {
      final long expected = normalizePositiveU32(explicitLength, "vkLen");
      if (expected != actualLength) {
        throw new IllegalArgumentException("vkLen must match vkBytes length");
      }
    }
    return new VerifyingKeyPayload(bytes, actualLength);
  }

  static void validateVerifyingKeyHeightRange(
      final Long activationHeight, final Long withdrawHeight) {
    final Long activation = normalizeOptionalNonNegative(activationHeight, "activationHeight");
    final Long withdraw = normalizeOptionalNonNegative(withdrawHeight, "withdrawHeight");
    if (activation != null && withdraw != null && withdraw.longValue() < activation.longValue()) {
      throw new IllegalArgumentException(
          "withdrawHeight must be greater than or equal to activationHeight");
    }
  }

  static void validateVerifyingKeyMaterial(
      final VerifyingKeyPayload vkPayload, final String commitmentHex) {
    if (vkPayload == null || vkPayload.bytes() == null) {
      if (commitmentHex == null) {
        throw new IllegalArgumentException("commitmentHex is required when vkBytes is omitted");
      }
      if (vkPayload == null || vkPayload.length() == null) {
        throw new IllegalArgumentException("vkLen is required when vkBytes is omitted");
      }
    }
  }

  static void validateInlineVerifyingKeyCommitment(
      final String backend, final byte[] bytes, final String commitmentHex) {
    if (bytes == null || commitmentHex == null) {
      return;
    }
    final String expected = verifyingKeyCommitmentHex(backend, bytes);
    if (!expected.equals(commitmentHex)) {
      throw new IllegalArgumentException(
          "commitmentHex must match domain-separated SHA-256 of backend and vkBytes");
    }
  }

  static String verifyingKeyCommitmentHex(final String backend, final byte[] bytes) {
    try {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      final byte[] backendBytes = backend.getBytes(StandardCharsets.UTF_8);
      digest.update("iroha:zk:v1:vk".getBytes(StandardCharsets.UTF_8));
      updateU64Be(digest, backendBytes.length);
      digest.update(backendBytes);
      updateU64Be(digest, bytes.length);
      digest.update(bytes);
      return hexLower(digest.digest());
    } catch (final NoSuchAlgorithmException ex) {
      throw new IllegalStateException("SHA-256 is unavailable", ex);
    }
  }

  private static void updateU64Be(final MessageDigest digest, final long value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
      digest.update((byte) (value >>> shift));
    }
  }

  private static void putOptionalVerifierFields(
      final Map<String, Object> payload,
      final String curve,
      final Long maxProofBytes,
      final String metadataUriCid,
      final String verifyingKeyBytesCid,
      final Long activationHeight,
      final Long withdrawHeight,
      final String commitmentHex,
      final VerifyingKeyPayload vkPayload,
      final String status) {
    if (curve != null) {
      payload.put("curve", normalizeNonBlank(curve, "curve"));
    }
    final Long normalizedMaxProofBytes = normalizeOptionalU32(maxProofBytes, "maxProofBytes");
    if (normalizedMaxProofBytes != null) {
      payload.put("max_proof_bytes", normalizedMaxProofBytes);
    }
    if (metadataUriCid != null) {
      payload.put("metadata_uri_cid", normalizeNonBlank(metadataUriCid, "metadataUriCid"));
    }
    if (verifyingKeyBytesCid != null) {
      payload.put(
          "vk_bytes_cid", normalizeNonBlank(verifyingKeyBytesCid, "verifyingKeyBytesCid"));
    }
    final Long normalizedActivationHeight =
        normalizeOptionalNonNegative(activationHeight, "activationHeight");
    if (normalizedActivationHeight != null) {
      payload.put("activation_height", normalizedActivationHeight);
    }
    final Long normalizedWithdrawHeight =
        normalizeOptionalNonNegative(withdrawHeight, "withdrawHeight");
    if (normalizedWithdrawHeight != null) {
      payload.put("withdraw_height", normalizedWithdrawHeight);
    }
    if (commitmentHex != null) {
      payload.put("commitment_hex", commitmentHex);
    }
    if (vkPayload != null) {
      final byte[] bytes = vkPayload.bytes();
      if (bytes != null) {
        payload.put("vk_bytes", Base64.getEncoder().encodeToString(bytes));
      }
      if (vkPayload.length() != null) {
        payload.put("vk_len", vkPayload.length());
      }
    }
    final String normalizedStatus = normalizeVerifyingKeyStatus(status);
    if (normalizedStatus != null) {
      payload.put("status", normalizedStatus);
    }
  }

  private static String hexLower(final byte[] bytes) {
    final StringBuilder out = new StringBuilder(bytes.length * 2);
    for (final byte b : bytes) {
      final int value = b & 0xff;
      if (value < 16) {
        out.append('0');
      }
      out.append(Integer.toString(value, 16));
    }
    return out.toString();
  }

  private static final class VerifyingKeyPayload {
    private final byte[] bytes;
    private final Long length;

    VerifyingKeyPayload(final byte[] bytes, final Long length) {
      this.bytes = bytes == null ? null : bytes.clone();
      this.length = length;
    }

    byte[] bytes() {
      return bytes == null ? null : bytes.clone();
    }

    Long length() {
      return length;
    }
  }

  private static final long FEE_QUOTE_RESPONSE_MAX_BYTES = 64L * 1024L;
  private static final long FEE_SPONSOR_PROGRAM_RESPONSE_MAX_BYTES = 64L * 1024L;
  private static final long NODE_CAPABILITIES_RESPONSE_MAX_BYTES = 64L * 1024L;
  private static final long EXECUTED_BLOCK_WIRE_MAX_BYTES = 32L * 1024L * 1024L;
  private static final long ACCOUNT_ONBOARDING_CURRENT_STATE_RESPONSE_MAX_BYTES = 4L * 1024L;
  private static final String APPLICATION_JSON = "application/json";
  private static final String APPLICATION_NORITO = "application/x-norito";
}
