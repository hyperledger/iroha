package org.hyperledger.iroha.android.client;

import static org.hyperledger.iroha.android.client.CanonicalRequestSigningTestSupport.VERIFYING_KEY_NETWORK_ID;
import static org.hyperledger.iroha.android.client.CanonicalRequestSigningTestSupport.signedClientConfig;

import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import org.hyperledger.iroha.android.client.transport.TransportRequest;
import org.hyperledger.iroha.android.client.transport.TransportResponse;
import org.hyperledger.iroha.android.client.transport.RequestReplayPolicy;
import org.hyperledger.iroha.android.model.NetworkId;

/** Exact, bounded read-route contract tests split from the general transport harness. */
public final class HttpClientTransportExactReadTests {
  private static final NetworkId OTHER_NETWORK_ID =
      NetworkId.parse(
          "hash:0E5751C026E543B2E8AB2EB06099DAA1D1E5DF47778F7787FAAB45CDF12FE3A9#6A22");
  private static final KeyPair PRIVACY_KEY_PAIR = generatePrivacyKeyPair();

  private HttpClientTransportExactReadTests() {}

  public static void main(final String[] args) {
    retryPolicyRecognizesRetryableStatus();
    contractManifestUsesKotlinOwnedParserAndModel();
    ledgerExecutedBlockWireIsExactBoundedAndFailClosed();
    privacyCapabilitiesAreTypedAndExact();
  }

  private static void contractManifestUsesKotlinOwnedParserAndModel() {
    final String codeHash = "b".repeat(64);
    final String canonicalHash =
        "hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2";
    final String response =
        "{\"network_id\":\"" + VERIFYING_KEY_NETWORK_ID
            + "\",\"artifact_id\":{\"dataspace_id\":9,\"code_hash\":\"" + canonicalHash
            + "\"},\"manifest\":{\"seiyaku_name\":\"Vault\",\"code_hash\":\"" + canonicalHash
            + "\",\"abi_hash\":null},\"code_hash\":\"" + codeHash + "\",\"abi_hash\":null}";
    final byte[] body = response.getBytes(StandardCharsets.UTF_8);
    final OneResponseExecutor success =
        new OneResponseExecutor(new TransportResponse(200, body, "ok", Map.of(), null, false));
    final HttpClientTransport client =
        HttpClientTransport.withExecutor(
            success,
            ClientConfig.builder().setBaseUri(URI.create("https://torii.example/api")).build());

    final org.hyperledger.iroha.sdk.client.ContractManifestRecord record =
        client.getContractManifest(codeHash).join();
    assert "Vault".equals(record.manifest.seiyakuName);
    assert VERIFYING_KEY_NETWORK_ID.toString().equals(record.networkId.toString());
    assert BigInteger.valueOf(9).equals(record.artifactId.dataspaceId);
    assert codeHash.equals(record.artifactId.codeHashHex);
    assert codeHash.equals(record.manifest.codeHashHex);
    assert ("https://torii.example/api/v1/contracts/code/" + codeHash)
        .equals(success.lastRequest.uri().toString());
    assert success.requestCount == 1;
    try {
      client.getContractManifest("abc");
      throw new AssertionError("invalid code hash must fail before dispatch");
    } catch (final IllegalArgumentException expected) {
      assert success.requestCount == 1;
    }

    final byte[] malformed = response.replace("\"Vault\"", "\"Vault!\"")
        .getBytes(StandardCharsets.UTF_8);
    final HttpClientTransport rejectingClient =
        HttpClientTransport.withExecutor(
            new OneResponseExecutor(
                new TransportResponse(200, malformed, "ok", Map.of(), null, false)),
            ClientConfig.builder().setBaseUri(URI.create("https://torii.example")).build());
    try {
      rejectingClient.getContractManifest(codeHash).join();
      throw new AssertionError("invalid Kotlin-owned manifest must fail closed");
    } catch (final CompletionException expected) {
      assert expected.getCause() instanceof IllegalStateException;
      assert expected.getCause().getMessage().contains("canonical Kotodama identifier")
          : "the original malformed name must be the rejection cause";
    }
  }

  static String noncanonicalStandardBase64PadBitAlias(final String encoded) {
    if (!encoded.endsWith("==")) {
      throw new AssertionError("64-byte signatures encode with == padding");
    }
    final String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    final char[] chars = encoded.toCharArray();
    final int index = chars.length - 3;
    final int value = alphabet.indexOf(chars[index]);
    if (value < 0) {
      throw new AssertionError("standard base64 alphabet");
    }
    chars[index] = alphabet.charAt(value ^ 0x01);
    return new String(chars);
  }

  static String canonicalSignatureBase64Fixture() {
    final byte[] signature = new byte[64];
    for (int i = 0; i < signature.length; i++) {
      signature[i] = 0x01;
    }
    return Base64.getEncoder().encodeToString(signature);
  }

  private static void retryPolicyRecognizesRetryableStatus() {
    final RetryPolicy defaultPolicy = RetryPolicy.builder().setMaxAttempts(1).build();
    assert defaultPolicy.isRetryableStatus(503) : "Server errors should be retryable by default";
    assert defaultPolicy.isRetryableStatus(429) : "Too many requests should be retryable by default";
    assert !defaultPolicy.isRetryableStatus(400) : "Client errors should not be retryable";

    final RetryPolicy custom =
        RetryPolicy.builder()
            .setMaxAttempts(1)
            .setRetryOnServerError(false)
            .setRetryOnTooManyRequests(false)
            .addRetryStatusCode(418)
            .build();
    assert !custom.isRetryableStatus(503) : "Server errors must be disabled by policy";
    assert !custom.isRetryableStatus(429) : "429 must be disabled by policy";
    assert custom.isRetryableStatus(418) : "Custom retry codes must be honored";
  }

  private static void ledgerExecutedBlockWireIsExactBoundedAndFailClosed() {
    final byte[] canonical = new byte[] {0x4e, 0x52, 0x54, 0x30};
    final OneResponseExecutor success =
        new OneResponseExecutor(
            new TransportResponse(
                200,
                canonical,
                "ok",
                Map.of(
                    "Content-Type", List.of("application/x-norito"),
                    "Content-Length", List.of(Integer.toString(canonical.length))),
                null,
                false));
    final HttpClientTransport client =
        HttpClientTransport.withExecutor(
            success,
            ClientConfig.builder()
                .setBaseUri(URI.create("https://torii.example"))
                .build());
    final byte[] received =
        client
            .getLedgerExecutedBlockWire(new BigInteger("18446744073709551615"))
            .join();
    assert Arrays.equals(canonical, received);
    assert success.requestCount == 1;
    assert "GET".equals(success.lastRequest.method());
    assert "/v1/ledger/block/18446744073709551615".equals(success.lastRequest.uri().getRawPath());
    assert List.of("application/x-norito").equals(success.lastRequest.headers().get("Accept"));
    assert Long.valueOf(32L * 1024L * 1024L).equals(success.lastRequest.maximumResponseBytes());

    for (final BigInteger height :
        List.of(BigInteger.ZERO, BigInteger.valueOf(-1L), BigInteger.ONE.shiftLeft(64))) {
      boolean rejected = false;
      try {
        client.getLedgerExecutedBlockWire(height);
      } catch (final IllegalArgumentException expected) {
        rejected = true;
      }
      assert rejected : "invalid ledger height must fail before dispatch";
    }
    assert success.requestCount == 1 : "invalid heights must not dispatch";

    final List<TransportResponse> hostile =
        List.of(
            new TransportResponse(
                201, canonical, "", Map.of("Content-Type", List.of("application/x-norito")),
                null,
                false),
            new TransportResponse(
                200,
                canonical,
                "",
                Map.of("Content-Type", List.of("application/x-norito; charset=binary")),
                null,
                false),
            new TransportResponse(
                200,
                canonical,
                "",
                Map.of("Content-Type", List.of("application/x-norito", "application/x-norito")),
                null,
                false),
            new TransportResponse(
                200,
                canonical,
                "",
                Map.of(
                    "Content-Type", List.of("application/x-norito"),
                    "Content-Length", List.of("04")),
                null,
                false),
            new TransportResponse(
                200,
                canonical,
                "",
                Map.of(
                    "Content-Type", List.of("application/x-norito"),
                    "Content-Length", List.of("5")),
                null,
                false),
            new TransportResponse(
                200,
                new byte[0],
                "",
                Map.of("Content-Type", List.of("application/x-norito")),
                null,
                false));
    for (final TransportResponse response : hostile) {
      boolean rejected = false;
      try {
        HttpClientTransport.withExecutor(
                new OneResponseExecutor(response),
                ClientConfig.builder()
                    .setBaseUri(URI.create("https://torii.example"))
                    .build())
            .getLedgerExecutedBlockWire(1L)
            .join();
      } catch (final CompletionException expected) {
        rejected = true;
      }
      assert rejected : "hostile executed-block response must fail closed";
    }

    final byte[] oversized = new byte[32 * 1024 * 1024 + 1];
    boolean oversizedRejected = false;
    try {
      HttpClientTransport.withExecutor(
              new OneResponseExecutor(
                  new TransportResponse(
                      200,
                      oversized,
                      "",
                      Map.of("Content-Type", List.of("application/x-norito")),
                      null,
                      false)),
              ClientConfig.builder()
                  .setBaseUri(URI.create("https://torii.example"))
                  .build())
          .getLedgerExecutedBlockWire(1L)
          .join();
    } catch (final CompletionException expected) {
      oversizedRejected = true;
    }
    assert oversizedRejected : "oversized executed-block wire must fail closed";
  }

  private static void privacyCapabilitiesAreTypedAndExact() {
    final byte[] body = privacyCapabilitySnapshotJson().getBytes(StandardCharsets.UTF_8);
    final OneResponseExecutor executor =
        new OneResponseExecutor(
            new TransportResponse(
                200,
                body,
                "ok",
                Map.of(
                    "Content-Type", List.of("application/x-norito"),
                    "Content-Length", List.of(Integer.toString(body.length))),
                null,
                false));
    final HttpClientTransport client =
        HttpClientTransport.withExecutor(
            executor,
            signedClientConfig("https://torii.example"));
    boolean legacySnapshotRejected = false;
    try {
      client.getPrivacyCapabilities(privacyAuth("privacy-exact-1")).join();
    } catch (final CompletionException expected) {
      legacySnapshotRejected = true;
    }
    assert legacySnapshotRejected : "retired JSON capabilities must not authorize Exact12";
    assert "GET".equals(executor.lastRequest.method());
    assert "/v1/privacy/capabilities".equals(executor.lastRequest.uri().getRawPath());
    final List<String> requestAccepts = new ArrayList<>();
    for (final Map.Entry<String, List<String>> entry :
        executor.lastRequest.headers().entrySet()) {
      if (entry.getKey().equalsIgnoreCase("Accept")) {
        requestAccepts.addAll(entry.getValue());
      }
    }
    assert List.of("application/x-norito").equals(requestAccepts)
        : "privacy capability request must contain exactly one canonical Accept value";
    assert Long.valueOf(256L * 1024L).equals(executor.lastRequest.maximumResponseBytes());
    assert executor.lastRequest.replayPolicy() == RequestReplayPolicy.ONE_SHOT
        : "authenticated capability read must be one-shot";
    assert executor.requestCount == 1 : "authenticated capability read must dispatch once";
    assert executor.lastRequest.body().length == 0 : "capability GET must bind an empty body";
    assert canonicalSignatureVerifies(
        executor.lastRequest, VERIFYING_KEY_NETWORK_ID, "privacy-exact-1");
    assert !canonicalSignatureVerifies(
        executor.lastRequest, OTHER_NETWORK_ID, "privacy-exact-1");
    assert !canonicalSignatureVerifies(
        executor.lastRequest,
        VERIFYING_KEY_NETWORK_ID,
        "privacy-exact-1",
        "POST",
        executor.lastRequest.uri(),
        executor.lastRequest.body());
    assert !canonicalSignatureVerifies(
        executor.lastRequest,
        VERIFYING_KEY_NETWORK_ID,
        "privacy-exact-1",
        "GET",
        URI.create("https://torii.example/v1/privacy/other"),
        executor.lastRequest.body());
    assert !canonicalSignatureVerifies(
        executor.lastRequest,
        VERIFYING_KEY_NETWORK_ID,
        "privacy-exact-1",
        "GET",
        executor.lastRequest.uri(),
        new byte[] {0});

    assertPrivacyCapabilitiesResponseRejected(
        new TransportResponse(
            200,
            body,
            "ok",
            Map.of("Content-Type", List.of("application/x-norito")),
            null,
            false));

    for (final String defaultAcceptName : List.of("Accept", "aCcEpT")) {
      final OneResponseExecutor blockedExecutor =
          new OneResponseExecutor(
              new TransportResponse(
                  200,
                  body,
                  "ok",
                  Map.of("Content-Type", List.of("application/x-norito")),
                  null,
                  false));
      boolean overrideRejected = false;
      try {
        HttpClientTransport.withExecutor(
                blockedExecutor,
                signedClientConfig("https://torii.example")
                    .toBuilder()
                    .putDefaultHeader(defaultAcceptName, "application/x-norito")
                    .build())
            .getPrivacyCapabilities(privacyAuth("privacy-accept"));
      } catch (final IllegalArgumentException expected) {
        overrideRejected = true;
      }
      assert overrideRejected : "default Accept must be rejected case-insensitively";
      assert blockedExecutor.requestCount == 0 : "invalid default Accept must not dispatch";
    }

    final String retired =
        privacyCapabilitySnapshotJson()
            .replace("zk-ace-pq-authorization-v1", "sis-with-hints");
    boolean retiredRejected = false;
    try {
      HttpClientTransport.withExecutor(
              new OneResponseExecutor(
                  new TransportResponse(
                      200,
                      retired.getBytes(StandardCharsets.UTF_8),
                      "",
                      Map.of("Content-Type", List.of("application/x-norito")),
                      null,
                      false)),
              signedClientConfig("https://torii.example"))
          .getPrivacyCapabilities(privacyAuth("privacy-retired"))
          .join();
    } catch (final CompletionException expected) {
      retiredRejected = true;
    }
    assert retiredRejected : "retired privacy labels must fail closed";

    final String bodyLength = Integer.toString(body.length);
    final Map<String, List<String>> caseFoldedDuplicateContentType = new LinkedHashMap<>();
    caseFoldedDuplicateContentType.put("Content-Type", List.of("application/json"));
    caseFoldedDuplicateContentType.put("content-type", List.of("application/json"));
    final Map<String, List<String>> caseFoldedDuplicateContentLength = new LinkedHashMap<>();
    caseFoldedDuplicateContentLength.put("Content-Type", List.of("application/json"));
    caseFoldedDuplicateContentLength.put("Content-Length", List.of(bodyLength));
    caseFoldedDuplicateContentLength.put("content-length", List.of(bodyLength));
    final List<TransportResponse> hostileResponses =
        List.of(
            new TransportResponse(
                201, body, "", Map.of("Content-Type", List.of("application/json")),
                null,
                false),
            new TransportResponse(200, body, "", Map.of(), null, false),
            new TransportResponse(
                200,
                body,
                "",
                Map.of("Content-Type", List.of("application/json; charset=utf-8")),
                null,
                false),
            new TransportResponse(
                200,
                body,
                "",
                Map.of("Content-Type", List.of("Application/Json")),
                null,
                false),
            new TransportResponse(
                200,
                body,
                "",
                Map.of(
                    "Content-Type", List.of("application/json", "application/json")),
                null,
                false),
            new TransportResponse(200, body, "", caseFoldedDuplicateContentType, null, false),
            new TransportResponse(
                200,
                body,
                "",
                Map.of(
                    "Content-Type", List.of("application/json"),
                    "Content-Length", List.of(bodyLength, bodyLength)),
                null,
                false),
            new TransportResponse(200, body, "", caseFoldedDuplicateContentLength, null, false),
            new TransportResponse(
                200,
                body,
                "",
                Map.of(
                    "Content-Type", List.of("application/json"),
                    "Content-Length", List.of("0")),
                null,
                false),
            new TransportResponse(
                200,
                body,
                "",
                Map.of(
                    "Content-Type", List.of("application/json"),
                    "Content-Length", List.of("0" + bodyLength)),
                null,
                false),
            new TransportResponse(
                200,
                body,
                "",
                Map.of(
                    "Content-Type", List.of("application/json"),
                    "Content-Length", List.of("+" + bodyLength)),
                null,
                false),
            new TransportResponse(
                200,
                body,
                "",
                Map.of(
                    "Content-Type", List.of("application/json"),
                    "Content-Length", List.of(bodyLength + " ")),
                null,
                false),
            new TransportResponse(
                200,
                body,
                "",
                Map.of(
                    "Content-Type", List.of("application/json"),
                    "Content-Length", List.of("9".repeat(4096))),
                null,
                false),
            new TransportResponse(
                200,
                new byte[0],
                "",
                Map.of(
                    "Content-Type", List.of("application/json"),
                    "Content-Length", List.of("0")),
                null,
                false));
    for (final TransportResponse hostileResponse : hostileResponses) {
      assertPrivacyCapabilitiesResponseRejected(hostileResponse);
    }

    assertPrivacyCapabilitiesResponseRejected(
        new TransportResponse(
            200,
            new byte[256 * 1024 + 1],
            "",
            Map.of("Content-Type", List.of("application/json")),
            null,
            false));

    final OneResponseExecutor missingContextExecutor =
        new OneResponseExecutor(
            new TransportResponse(
                200, body, "", Map.of("Content-Type", List.of("application/x-norito")),
                null,
                false));
    boolean missingContextRejected = false;
    try {
      HttpClientTransport.withExecutor(
              missingContextExecutor,
              ClientConfig.builder()
                  .setBaseUri(URI.create("https://torii.example"))
                  .build())
          .getPrivacyCapabilities(privacyAuth("privacy-missing-context"));
    } catch (final IllegalStateException expected) {
      missingContextRejected = true;
    }
    assert missingContextRejected : "privacy authentication requires exact network context";
    assert missingContextExecutor.requestCount == 0 : "missing context must not dispatch";

    final OneResponseExecutor forgedHeaderExecutor =
        new OneResponseExecutor(
            new TransportResponse(
                200, body, "", Map.of("Content-Type", List.of("application/x-norito")),
                null,
                false));
    boolean forgedHeaderRejected = false;
    try {
      HttpClientTransport.withExecutor(
              forgedHeaderExecutor,
              signedClientConfig("https://torii.example")
                  .toBuilder()
                  .putDefaultHeader("x-IROHA-signature", "forged")
                  .build())
          .getPrivacyCapabilities(privacyAuth("privacy-forged-header"));
    } catch (final IllegalArgumentException expected) {
      forgedHeaderRejected = true;
    }
    assert forgedHeaderRejected : "caller-supplied canonical headers must be rejected";
    assert forgedHeaderExecutor.requestCount == 0 : "forged header must not dispatch";

    final OneResponseExecutor admissionExecutor =
        new OneResponseExecutor(
            new TransportResponse(
                200, body, "", Map.of("Content-Type", List.of("application/x-norito")),
                null,
                false));
    boolean admissionRejected = false;
    try {
      HttpClientTransport.withExecutor(
              admissionExecutor, signedClientConfig("https://torii.example"))
          .requirePrivacyExact12CapabilityAdmission(
              org.hyperledger.iroha.sdk.privacy.PrivacyProtocolIdV1
                  .ANONYMOUS_PGC_K_OUT_OF_N_V1,
              privacyAuth("privacy-admission"))
          .join();
    } catch (final CompletionException expected) {
      admissionRejected = true;
    }
    assert admissionRejected : "legacy capability body must not authorize admission";
    assert admissionExecutor.requestCount == 1 : "admission must dispatch exactly once";
    assert admissionExecutor.lastRequest.replayPolicy() == RequestReplayPolicy.ONE_SHOT
        : "admission capability request must be one-shot";
  }

  private static void assertPrivacyCapabilitiesResponseRejected(
      final TransportResponse response) {
    boolean rejected = false;
    try {
      HttpClientTransport.withExecutor(
              new OneResponseExecutor(response),
              signedClientConfig("https://torii.example"))
          .getPrivacyCapabilities(privacyAuth("privacy-hostile"))
          .join();
    } catch (final CompletionException expected) {
      rejected = true;
    }
    assert rejected : "hostile privacy capability response must fail closed";
  }

  private static String privacyCapabilitySnapshotJson() {
    final StringBuilder rows = new StringBuilder();
    for (final org.hyperledger.iroha.sdk.privacy.PrivacyProtocolIdV1 protocol :
        org.hyperledger.iroha.sdk.privacy.PrivacyProtocolIdV1.values()) {
      if (rows.length() != 0) {
        rows.append(',');
      }
      rows.append("{\"protocol_id\":{\"protocol\":\"")
          .append(protocol.getCanonicalLabel())
          .append(
              "\",\"value\":null},\"compiled_profile\":{\"status\":\"unavailable\","
                  + "\"value\":{\"reason\":\"engine-unavailable\",\"detail\":null}},"
                  + "\"activation\":null}");
    }
    return "{\"version\":1,\"committed_height\":42,\"consensus_policy\":{"
        + "\"current_limits\":{"
        + "\"max_actions_per_transaction\":1,\"max_actions_per_block\":2,"
        + "\"max_proof_bytes_per_action\":9437184,\"max_action_bytes\":9699840,"
        + "\"max_privacy_bytes_per_transaction\":9699840,"
        + "\"max_privacy_bytes_per_block\":16711680,"
        + "\"max_statement_and_encrypted_output_bytes_per_transaction\":262144,"
        + "\"max_nullifiers_per_action\":8,\"max_commitments_per_action\":8,"
        + "\"retained_root_count\":2048},\"pending_tightening\":null},"
        + "\"protocols\":["
        + rows
        + "]}";
  }

  private static ToriiCanonicalRequestAuth privacyAuth(final String nonce) {
    return new ToriiCanonicalRequestAuth(
        "alice@universal",
        HttpClientTransportExactReadTests::signPrivacyRequest,
        Long.valueOf(1_700_000_000_000L),
        nonce);
  }

  private static KeyPair generatePrivacyKeyPair() {
    try {
      return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    } catch (final Exception ex) {
      throw new IllegalStateException("failed to create privacy request signing key", ex);
    }
  }

  private static byte[] signPrivacyRequest(final byte[] message) {
    try {
      final Signature signer = Signature.getInstance("Ed25519");
      signer.initSign(PRIVACY_KEY_PAIR.getPrivate());
      signer.update(message);
      return signer.sign();
    } catch (final Exception ex) {
      throw new IllegalStateException("failed to sign privacy request", ex);
    }
  }

  private static boolean canonicalSignatureVerifies(
      final TransportRequest request,
      final NetworkId networkId,
      final String nonce) {
    return canonicalSignatureVerifies(
        request,
        networkId,
        nonce,
        request.method(),
        request.uri(),
        request.body());
  }

  private static boolean canonicalSignatureVerifies(
      final TransportRequest request,
      final NetworkId networkId,
      final String nonce,
      final String method,
      final URI uri,
      final byte[] body) {
    try {
      final byte[] signature =
          Base64.getDecoder()
              .decode(request.headers().get(CanonicalRequestSigner.HEADER_SIGNATURE).get(0));
      final Signature verifier = Signature.getInstance("Ed25519");
      verifier.initVerify(PRIVACY_KEY_PAIR.getPublic());
      verifier.update(
          CanonicalRequestSigner.canonicalRequestSignatureMessage(
              networkId,
              method,
              uri,
              body,
              1_700_000_000_000L,
              nonce));
      return verifier.verify(signature);
    } catch (final Exception ex) {
      throw new AssertionError("failed to verify privacy request signature", ex);
    }
  }

  private static final class OneResponseExecutor implements HttpTransportExecutor {
    private final TransportResponse response;
    private TransportRequest lastRequest;
    private int requestCount;

    private OneResponseExecutor(final TransportResponse response) {
      this.response = Objects.requireNonNull(response, "response");
    }

    @Override
    public CompletableFuture<TransportResponse> execute(final TransportRequest request) {
      lastRequest = Objects.requireNonNull(request, "request");
      requestCount++;
      return CompletableFuture.completedFuture(response);
    }
  }
}
