package org.hyperledger.iroha.sdk.offline;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.hyperledger.iroha.sdk.client.JsonParser;
import org.junit.jupiter.api.Test;

/** Java consumers authenticate and exchange verified Kotlin IPM1 values without a second channel. */
final class IrohaPeerNearbyJavaConsumerTest {
  private static final IrohaPeerPayloadProfile PROFILE = IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1;
  private static final Ed25519PrivateKeyParameters SENDER_SIGNER =
      new Ed25519PrivateKeyParameters(bytes(32, 7), 0);
  private static final Ed25519PrivateKeyParameters RECEIVER_SIGNER =
      new Ed25519PrivateKeyParameters(bytes(32, 8), 0);

  @Test
  void javaExchangesSharedRequestPaymentCreditedThroughAuthenticatedTypedSessions()
      throws IOException {
    final Fixtures fixtures = Fixtures.load();
    try (SessionPair pair = new SessionPair(fixtures)) {
      pair.authenticate(IrohaPeerNearbyJavaConsumerTest::verify);
      assertTrue(pair.sender.isAuthenticated());
      assertTrue(pair.receiver.isAuthenticated());
      assertTrue(pair.senderKey.isDestroyed());
      assertTrue(pair.receiverKey.isDestroyed());

      final IrohaPeerWireMessageV1 request = exchange(pair.receiver, pair.sender, fixtures.request, 0);
      final byte[] requestPayload = request.getCanonicalPayload().getBytes();
      assertArrayEquals(fixtures.request.getCanonicalPayload().getBytes(), requestPayload);
      final IrohaPeerWalletRequestV1 walletRequest = IrohaPeerWalletRequestV1.decode(requestPayload);
      assertArrayEquals(IrohaPeerRequestFixtureV1.INSTANCE.account(),
          walletRequest.destinationAccountOriginal());
      final byte[] requestEnvelope = walletRequest.requestEnvelope();
      assertEquals(KagemushaWalletMessageKindV1.REQUEST,
          KagemushaWalletWireV1.inspectEnvelope(requestEnvelope).kind);

      final IrohaPeerWireMessageV1 payment = exchange(pair.sender, pair.receiver, fixtures.payment, 0);
      final byte[] paymentEnvelope = payment.getCanonicalPayload().getBytes();
      assertArrayEquals(fixtures.payment.getCanonicalPayload().getBytes(), paymentEnvelope);
      KagemushaWalletWireV1.requireExchangeBinding(requestEnvelope, paymentEnvelope);

      final IrohaPeerWireMessageV1 credited =
          exchange(pair.receiver, pair.sender, fixtures.credited, 1);
      final byte[] creditedEnvelope = credited.getCanonicalPayload().getBytes();
      assertArrayEquals(fixtures.credited.getCanonicalPayload().getBytes(), creditedEnvelope);
      KagemushaWalletWireV1.requireExchangeBinding(
          requestEnvelope, paymentEnvelope, creditedEnvelope);
      assertThrows(IllegalArgumentException.class,
          () -> KagemushaWalletWireV1.requireExchangeBinding(
              requestEnvelope, creditedEnvelope, paymentEnvelope));
      // These are transport authentication and structural envelope checks, not monetary proof
      // validation.
    }
  }

  @Test
  void mutableJavaInputsAndReturnedBuffersCannotChangeTheVerifiedExchange() throws IOException {
    final Fixtures fixtures = Fixtures.load();
    final byte[] canonical = fixtures.payment.getCanonicalPayload().getBytes();
    final IrohaPeerWireMessageV1 message = new IrohaPeerWireMessageV1(
        new IrohaPeerCanonicalPayload(PROFILE, IrohaPeerPayloadKind.PAYMENT, 1, canonical));
    final byte[] expected = message.encode();
    final int expectedHash = message.hashCode();
    Arrays.fill(canonical, (byte) 0);
    Arrays.fill(message.getCanonicalPayload().getBytes(), (byte) 0);
    Arrays.fill(message.getCanonicalHash(), (byte) 0);
    Arrays.fill(message.getWireHash(), (byte) 0);
    Arrays.fill(message.getEncodedBody(), (byte) 0);
    Arrays.fill(message.getStreamId(), (byte) 0);
    Arrays.fill(message.encode(), (byte) 0);
    assertArrayEquals(expected, message.encode());
    assertEquals(expectedHash, message.hashCode());
    assertEquals(fixtures.payment, message);

    try (SessionPair pair = new SessionPair(fixtures)) {
      // Session and hello construction snapshot the Java arrays, including certificate and nonce.
      Arrays.fill(pair.sessionInput, (byte) 0);
      Arrays.fill(pair.requestHashInput, (byte) 0);
      Arrays.fill(pair.senderCertificateInput, (byte) 0);
      Arrays.fill(pair.senderNonceInput, (byte) 0);
      Arrays.fill(pair.sender.getSessionId(), (byte) 0);
      Arrays.fill(pair.sender.getRequestCanonicalHash(), (byte) 0);
      Arrays.fill(pair.sender.getLocalHello().getDeviceCertificate(), (byte) 0);
      Arrays.fill(pair.sender.getLocalHello().getNonce(), (byte) 0);
      assertArrayEquals(bytes(16, 9), pair.sender.getSessionId());
      assertArrayEquals(fixtures.request.getCanonicalHash(), pair.sender.getRequestCanonicalHash());
      pair.authenticate(IrohaPeerNearbyJavaConsumerTest::verify);

      final IrohaPeerNearbyEncryptedRecordV1 sealed = pair.sender.seal(message);
      final byte[] cipherInput = sealed.getCiphertextAndTag();
      final byte[] sessionInput = sealed.getSessionId();
      final IrohaPeerNearbyEncryptedRecordV1 copied = new IrohaPeerNearbyEncryptedRecordV1(
          sealed.getProfile(), sealed.getSenderRole(), sessionInput, sealed.getSequence(), cipherInput);
      Arrays.fill(cipherInput, (byte) 0);
      Arrays.fill(sessionInput, (byte) 0);
      Arrays.fill(copied.getCiphertextAndTag(), (byte) 0);
      Arrays.fill(copied.getSessionId(), (byte) 0);
      assertArrayEquals(sealed.encode(), copied.encode());

      final byte[] encoded = copied.encode();
      final IrohaPeerNearbyEncryptedRecordV1 decoded = IrohaPeerNearbyEncryptedRecordV1.decode(encoded);
      Arrays.fill(encoded, (byte) 0);
      final IrohaPeerWireMessageV1 received = pair.receiver.open(decoded);
      Arrays.fill(received.getCanonicalPayload().getBytes(), (byte) 0);
      Arrays.fill(received.getEncodedBody(), (byte) 0);
      assertEquals(message, received);
      assertArrayEquals(expected, received.encode());
      assertArrayEquals(expected, message.encode());
    }
  }

  @Test
  void javaVerifierReceivesOwnedSnapshotsWithoutMutatingTheAuthenticatedTranscript()
      throws IOException {
    final Fixtures fixtures = Fixtures.load();
    final AtomicInteger verifications = new AtomicInteger();
    try (SessionPair pair = new SessionPair(fixtures)) {
      final byte[] senderHello = pair.sender.getLocalHello().encode();
      final byte[] receiverHello = pair.receiver.getLocalHello().encode();
      pair.authenticate((role, certificate, signedBytes, signature) -> {
        final boolean authenticated = verify(role, certificate, signedBytes, signature);
        assertTrue(authenticated);
        final byte[] changedSignature = signature.clone();
        changedSignature[0] ^= 1;
        assertFalse(verify(role, certificate, signedBytes, changedSignature));
        verifications.incrementAndGet();
        Arrays.fill(certificate, (byte) 0);
        Arrays.fill(signedBytes, (byte) 0);
        Arrays.fill(signature, (byte) 0);
        return authenticated;
      });
      assertEquals(2, verifications.get());
      assertArrayEquals(senderHello, pair.sender.getLocalHello().encode());
      assertArrayEquals(receiverHello, pair.receiver.getLocalHello().encode());
      exchange(pair.sender, pair.receiver, fixtures.payment, 0);
      exchange(pair.receiver, pair.sender, fixtures.credited, 0);
    }
  }

  @Test
  void javaCloseAndDestroyAreIdempotentAndEndOwnedKeyAndSessionLifetimes() throws IOException {
    final Fixtures fixtures = Fixtures.load();
    try (SessionPair pending = new SessionPair(fixtures)) {
      assertFalse(pending.senderKey.isDestroyed());
      pending.sender.close();
      pending.sender.destroy();
      pending.sender.close();
      assertTrue(pending.sender.isDestroyed());
      assertTrue(pending.senderKey.isDestroyed());
      assertFalse(pending.sender.isAuthenticated());
      assertThrows(IllegalStateException.class, pending.senderKey::getPublicKey);
      assertThrows(IllegalStateException.class, pending.sender::getLocalHello);
      assertThrows(IllegalStateException.class, pending.sender::authenticationPreimage);
      assertThrows(IllegalStateException.class, () -> pending.sender.seal(fixtures.payment));
    }
    try (SessionPair authenticated = new SessionPair(fixtures)) {
      authenticated.authenticate(IrohaPeerNearbyJavaConsumerTest::verify);
      final IrohaPeerNearbyEncryptedRecordV1 record = authenticated.sender.seal(fixtures.payment);
      authenticated.receiver.destroy();
      authenticated.receiver.close();
      authenticated.receiver.destroy();
      assertTrue(authenticated.receiver.isDestroyed());
      assertFalse(authenticated.receiver.isAuthenticated());
      assertThrows(IllegalStateException.class, () -> authenticated.receiver.open(record));
      assertThrows(IllegalStateException.class,
          () -> authenticated.receiver.seal(fixtures.credited));
    }
  }

  private static IrohaPeerWireMessageV1 exchange(
      IrohaPeerNearbySessionV1 sender, IrohaPeerNearbySessionV1 receiver,
      IrohaPeerWireMessageV1 message, long sequence) {
    final byte[] original = message.encode();
    final IrohaPeerNearbyEncryptedRecordV1 record = sender.seal(message);
    assertEquals(sequence, record.getSequence());
    final IrohaPeerWireMessageV1 opened = receiver.open(
        IrohaPeerNearbyEncryptedRecordV1.decode(record.encode()));
    assertEquals(message, opened);
    assertEquals(message.getCanonicalPayload().getKind(), opened.getCanonicalPayload().getKind());
    assertArrayEquals(original, opened.encode());
    assertArrayEquals(original, message.encode());
    return opened;
  }

  private static boolean verify(IrohaPeerNearbyRoleV1 role, byte[] certificate,
      byte[] signedBytes, byte[] signature) {
    final Ed25519PrivateKeyParameters trusted =
        role == IrohaPeerNearbyRoleV1.SENDER ? SENDER_SIGNER : RECEIVER_SIGNER;
    if (!Arrays.equals(trusted.generatePublicKey().getEncoded(), certificate)) {
      return false;
    }
    final Ed25519Signer verifier = new Ed25519Signer();
    verifier.init(false, new Ed25519PublicKeyParameters(certificate, 0));
    verifier.update(signedBytes, 0, signedBytes.length);
    return verifier.verifySignature(signature);
  }

  private static IrohaPeerNearbyAuthenticationV1 authenticate(
      IrohaPeerNearbySessionV1 session, Ed25519PrivateKeyParameters signerKey) {
    final byte[] preimage = session.authenticationPreimage();
    final Ed25519Signer signer = new Ed25519Signer();
    signer.init(true, signerKey);
    signer.update(preimage, 0, preimage.length);
    final byte[] signature = signer.generateSignature();
    final IrohaPeerNearbyAuthenticationV1 result = session.makeAuthentication(signature);
    Arrays.fill(preimage, (byte) 0);
    Arrays.fill(signature, (byte) 0);
    return IrohaPeerNearbyAuthenticationV1.decode(result.encode());
  }

  private static byte[] bytes(int size, int value) {
    final byte[] result = new byte[size];
    Arrays.fill(result, (byte) value);
    return result;
  }

  private static final class SessionPair implements Closeable {
    private final byte[] sessionInput = bytes(16, 9);
    private final byte[] requestHashInput;
    private final byte[] senderCertificateInput = SENDER_SIGNER.generatePublicKey().getEncoded();
    private final byte[] senderNonceInput = bytes(32, 10);
    private final IrohaPeerNearbyP256V1 senderKey =
        IrohaPeerNearbyP256V1.fromPrivateBytes(bytes(32, 1));
    private final IrohaPeerNearbyP256V1 receiverKey =
        IrohaPeerNearbyP256V1.fromPrivateBytes(bytes(32, 2));
    private final IrohaPeerNearbySessionV1 sender;
    private final IrohaPeerNearbySessionV1 receiver;

    private SessionPair(Fixtures fixtures) {
      requestHashInput = fixtures.request.getCanonicalHash();
      sender = new IrohaPeerNearbySessionV1(PROFILE, IrohaPeerNearbyRoleV1.SENDER,
          sessionInput, requestHashInput, senderCertificateInput, senderNonceInput, senderKey);
      receiver = new IrohaPeerNearbySessionV1(PROFILE, IrohaPeerNearbyRoleV1.RECEIVER,
          sessionInput, requestHashInput, RECEIVER_SIGNER.generatePublicKey().getEncoded(),
          bytes(32, 11), receiverKey);
    }

    private void authenticate(IrohaPeerNearbySignatureVerifierV1 verifier) {
      sender.acceptPeerHello(IrohaPeerNearbyHelloV1.decode(receiver.getLocalHello().encode()));
      receiver.acceptPeerHello(IrohaPeerNearbyHelloV1.decode(sender.getLocalHello().encode()));
      final IrohaPeerNearbyAuthenticationV1 senderAuth =
          IrohaPeerNearbyJavaConsumerTest.authenticate(sender, SENDER_SIGNER);
      final IrohaPeerNearbyAuthenticationV1 receiverAuth =
          IrohaPeerNearbyJavaConsumerTest.authenticate(receiver, RECEIVER_SIGNER);
      sender.acceptPeerAuthentication(receiverAuth, verifier);
      receiver.acceptPeerAuthentication(senderAuth, verifier);
    }

    @Override
    public void close() {
      sender.close();
      receiver.close();
    }
  }

  private static final class Fixtures {
    private final IrohaPeerWireMessageV1 request;
    private final IrohaPeerWireMessageV1 payment;
    private final IrohaPeerWireMessageV1 credited;

    private Fixtures(Map<?, ?> root) {
      assertEquals(1, ((Number) root.get("fixture_version")).intValue());
      final List<?> envelopes = (List<?>) root.get("envelopes");
      request = message(envelopes, "Request", IrohaPeerPayloadKind.REQUEST);
      payment = message(envelopes, "Payment", IrohaPeerPayloadKind.PAYMENT);
      credited = message(envelopes, "Credited::Receive", IrohaPeerPayloadKind.CREDITED);
    }

    private static Fixtures load() throws IOException {
      Path root = Paths.get("").toAbsolutePath().normalize();
      while (root != null) {
        final Path fixture = root.resolve("fixtures/kagemusha/wallet_v1_vectors.json");
        if (Files.isRegularFile(fixture)) {
          return new Fixtures((Map<?, ?>) JsonParser.parse(
              new String(Files.readAllBytes(fixture), StandardCharsets.UTF_8)));
        }
        root = root.getParent();
      }
      throw new IOException("Shared fixtures/kagemusha/wallet_v1_vectors.json was not found");
    }

    private static IrohaPeerWireMessageV1 message(
        List<?> envelopes, String variant, IrohaPeerPayloadKind kind) {
      for (final Object entry : envelopes) {
        final Map<?, ?> record = (Map<?, ?>) entry;
        if (!variant.equals(record.get("variant"))) {
          continue;
        }
        assertEquals(kind.getCode(), ((Number) record.get("tag")).intValue());
        final String hex = (String) record.get("canonical_hex");
        assertEquals(0, hex.length() % 2);
        final byte[] canonical = new byte[hex.length() / 2];
        for (int index = 0; index < canonical.length; index++) {
          final int high = Character.digit(hex.charAt(index * 2), 16);
          final int low = Character.digit(hex.charAt(index * 2 + 1), 16);
          assertTrue(high >= 0 && low >= 0);
          canonical[index] = (byte) ((high << 4) | low);
        }
        assertEquals(canonical.length, ((Number) record.get("frame_len")).intValue());
        final byte[] payload;
        if (kind == IrohaPeerPayloadKind.REQUEST) {
          final byte[] account = IrohaPeerRequestFixtureV1.INSTANCE.account();
          payload = new IrohaPeerWalletRequestV1(canonical, account).encode();
          final IrohaPeerWalletRequestV1 recovered = IrohaPeerWalletRequestV1.decode(payload);
          assertArrayEquals(canonical, recovered.requestEnvelope());
          assertArrayEquals(account, recovered.destinationAccountOriginal());
          assertThrows(IllegalArgumentException.class,
              () -> new IrohaPeerCanonicalPayload(PROFILE, kind, 1, canonical));
        } else {
          payload = canonical;
        }
        return new IrohaPeerWireMessageV1(new IrohaPeerCanonicalPayload(PROFILE, kind, 1, payload));
      }
      throw new AssertionError("wallet envelope vector " + variant + " was not found");
    }
  }
}
