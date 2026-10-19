package org.hyperledger.iroha.android.norito;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.hyperledger.iroha.android.address.AccountAddress;
import org.hyperledger.iroha.android.crypto.NativeSignerBridge;
import org.hyperledger.iroha.android.crypto.SigningAlgorithm;
import org.hyperledger.iroha.android.model.Executable;
import org.hyperledger.iroha.android.model.FeePaymentIntent;
import org.hyperledger.iroha.android.model.InstructionBox;
import org.hyperledger.iroha.android.model.JsonValue;
import org.hyperledger.iroha.android.model.NetworkId;
import org.hyperledger.iroha.android.model.TransactionPayload;
import org.hyperledger.iroha.android.model.instructions.RegisterZkAssetInstruction;
import org.hyperledger.iroha.android.model.instructions.TransferWirePayloadEncoder;
import org.hyperledger.iroha.android.client.TairaTestnetProfile;
import org.hyperledger.iroha.android.testing.TestAssetDefinitionIds;
import org.hyperledger.iroha.android.testing.TestEd25519Keys;
import org.hyperledger.iroha.android.testing.TestNetworkIds;
import org.hyperledger.iroha.android.tx.SignedTransaction;
import org.hyperledger.iroha.norito.NoritoCodec;
import org.hyperledger.iroha.norito.NoritoDecoder;
import org.hyperledger.iroha.norito.NoritoEncoder;
import org.junit.Test;

/** Adversarial coverage for the caller-owned I105 chain context. */
public final class ExplicitChainContextTests {
  private static final Class<?> KOTLIN_NATIVE_SIGNER =
      org.hyperledger.iroha.sdk.crypto.NativeSignerBridge.class;


  private static final int TAIRA = TairaTestnetProfile.I105_DISCRIMINANT;
  private static final int OTHER = AccountAddress.DEFAULT_I105_DISCRIMINANT;

  @Test
  public void retiredGenericConfidentialSurfacesAreAbsent() {
    final String packageName = "org.hyperledger.iroha.android.model.instructions.";
    final String[][] variants = {{"Shi", "eld"}, {"Zk", "Transfer"}, {"Un", "shield"}};
    for (final String[] parts : variants) {
      final String variant = parts[0] + parts[1];
      try {
        Class.forName(packageName + variant + "Instruction");
        fail("retired generic instruction class is still present: " + variant);
      } catch (ClassNotFoundException expected) {
        // Expected: ABI V1 exposes only typed first-release movement flows.
      }
      for (final Method method : NativeSignerBridge.class.getDeclaredMethods()) {
        assertFalse(method.getName().equals("encode" + variant + "SignedTransaction"));
        assertFalse(method.getName().equals("nativeEncode" + variant + "SignedTransaction"));
      }
    }
  }

  @Test
  public void adaptersRequireBoundedExplicitContextAndRejectMismatchedPrefixes() throws Exception {
    assertFalse(
        "the codec must not expose a context-free constructor",
        Arrays.stream(NoritoJavaCodecAdapter.class.getConstructors())
            .anyMatch(constructor -> constructor.getParameterCount() == 0));
    expectIllegalArgument(() -> new NoritoJavaCodecAdapter(-1));
    expectIllegalArgument(() -> new NoritoJavaCodecAdapter(0x1_0000));

    final String tairaAuthority = account(0x41, TAIRA);
    final String otherAuthority = account(0x41, OTHER);
    final TransactionPayload tairaPayload = payload(tairaAuthority);
    final TransactionPayload otherPayload = payload(otherAuthority);
    final NoritoJavaCodecAdapter tairaAdapter = new NoritoJavaCodecAdapter(TAIRA);
    final NoritoJavaCodecAdapter otherAdapter = new NoritoJavaCodecAdapter(OTHER);

    final byte[] tairaBytes = tairaAdapter.encodeTransaction(tairaPayload);
    final byte[] otherBytes = otherAdapter.encodeTransaction(otherPayload);
    assertArrayEquals(
        "the chain context changes only the authenticated I105 projection", tairaBytes, otherBytes);
    assertEquals(tairaAuthority, tairaAdapter.decodeTransaction(tairaBytes).authority());
    assertEquals(otherAuthority, otherAdapter.decodeTransaction(tairaBytes).authority());
    assertNotEquals(tairaAuthority, otherAdapter.decodeTransaction(tairaBytes).authority());
    expectNoritoFailure(() -> otherAdapter.encodeTransaction(tairaPayload));
    expectNoritoFailure(() -> tairaAdapter.encodeTransaction(otherPayload));
  }

  @Test
  public void concurrentAdaptersDoNotLeakChainContext() throws Exception {
    final NoritoJavaCodecAdapter tairaAdapter = new NoritoJavaCodecAdapter(TAIRA);
    final NoritoJavaCodecAdapter otherAdapter = new NoritoJavaCodecAdapter(OTHER);
    final TransactionPayload tairaPayload = payload(account(0x42, TAIRA));
    final TransactionPayload otherPayload = payload(account(0x43, OTHER));
    final CountDownLatch start = new CountDownLatch(1);
    final ExecutorService executor = Executors.newFixedThreadPool(2);
    try {
      final Future<?> tairaFuture =
          executor.submit(
              () -> {
                await(start);
                for (int iteration = 0; iteration < 250; iteration++) {
                  assertEquals(
                      tairaPayload.authority(),
                      tairaAdapter
                          .decodeTransaction(tairaAdapter.encodeTransaction(tairaPayload))
                          .authority());
                }
                return null;
              });
      final Future<?> otherFuture =
          executor.submit(
              () -> {
                await(start);
                for (int iteration = 0; iteration < 250; iteration++) {
                  assertEquals(
                      otherPayload.authority(),
                      otherAdapter
                          .decodeTransaction(otherAdapter.encodeTransaction(otherPayload))
                          .authority());
                }
                return null;
              });
      start.countDown();
      tairaFuture.get(30, TimeUnit.SECONDS);
      otherFuture.get(30, TimeUnit.SECONDS);
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  public void transferDecoderProjectsOnlyTheCallerSelectedChain() throws Exception {
    final String owner = account(0x44, TAIRA);
    final String destination = account(0x45, TAIRA);
    final String assetId = TestAssetDefinitionIds.PRIMARY + "#" + owner;
    final InstructionBox instruction =
        TransferWirePayloadEncoder.encodeAssetTransfer(assetId, "10", destination);
    final byte[] wire =
        ((InstructionBox.WirePayload) instruction.payload()).payloadBytes();

    final TransferWirePayloadEncoder.DecodedAssetTransfer taira =
        TransferWirePayloadEncoder.decodeAssetTransferPayload(wire, TAIRA);
    final TransferWirePayloadEncoder.DecodedAssetTransfer adversarial =
        TransferWirePayloadEncoder.decodeAssetTransferPayload(wire, OTHER);

    assertEquals(assetId, taira.assetId());
    assertEquals(destination, taira.destinationAccountId());
    assertEquals(
        TAIRA, AccountAddress.detectI105Discriminant(taira.destinationAccountId()).intValue());
    assertEquals(
        OTHER,
        AccountAddress.detectI105Discriminant(adversarial.destinationAccountId()).intValue());
    assertNotEquals(taira.destinationAccountId(), adversarial.destinationAccountId());
    assertNotEquals(taira.assetId(), adversarial.assetId());
  }

  @Test
  public void signedEnvelopesPreserveCanonicalPayloadAndRejectAllNoncanonicalInnerForms()
      throws Exception {
    final NoritoJavaCodecAdapter adapter = new NoritoJavaCodecAdapter(TAIRA);
    final TransactionPayload payload =
        TransactionPayload.builder()
            .setNetworkId(
                org.hyperledger.iroha.android.testing.TestNetworkIds.fromSeed(1L))
            .setAuthority(account(0x46, TAIRA))
            .setCreationTimeMs(1_735_369_000_000L)
            .setExecutable(Executable.ivm(new byte[] {0x01}))
            .setFeePayment(FeePaymentIntent.authority(Collections.emptyList(), 1L))
            .putMetadata("b", JsonValue.string("two"))
            .putMetadata("a", JsonValue.string("one"))
            .build();
    final byte[] canonicalPayload = adapter.encodeTransaction(payload);
    final byte[] noncanonicalPayload = swapMetadataEntries(canonicalPayload);
    final byte[] trailingPayload =
        Arrays.copyOf(canonicalPayload, canonicalPayload.length + 1);
    final byte[] malformedPayload = new byte[] {0x01, 0x02, 0x03};

    assertFalse(Arrays.equals(canonicalPayload, noncanonicalPayload));
    assertEquals(
        payload.authority(), adapter.decodeTransaction(noncanonicalPayload).authority());

    final SignedTransaction canonicalSigned = signed(canonicalPayload, adapter.schemaName());
    final byte[] canonicalEnvelope = SignedTransactionEncoder.encode(canonicalSigned);
    assertArrayEquals(
        canonicalPayload,
        SignedTransactionEncoder.decode(canonicalEnvelope).encodedPayload());

    for (final byte[] rejected :
        new byte[][] {malformedPayload, trailingPayload, noncanonicalPayload}) {
      expectNoritoFailure(
          () -> SignedTransactionEncoder.encode(signed(rejected, adapter.schemaName())));
      expectNoritoFailure(
          () ->
              SignedTransactionEncoder.decode(
                  replaceSizedField(canonicalEnvelope, 1, rejected)));
    }
  }

  @Test
  public void nativeSignerBoundaryUsesNominalNetworkIdAndRawFixed32Jni() {
    assertAllMethodOverloadsHaveParameter(
        NativeSignerBridge.class,
        "encodeRegisterZkAssetSignedTransaction",
        1,
        NetworkId.class);
    // The bridge exports JNI only for the Kotlin owner; the Java class delegates to it.
    assertMethodHasParameter(
        KOTLIN_NATIVE_SIGNER,
        "nativeEncodeRegisterZkAssetSignedTransaction",
        1,
        byte[].class);
    assertMethodHasParameterCount(
        KOTLIN_NATIVE_SIGNER, "nativeEncodeRegisterZkAssetSignedTransaction", 12);
    assertNativeMethod(KOTLIN_NATIVE_SIGNER, "nativeEncodeRegisterZkAssetSignedTransaction");
    assertEquals(NetworkId.BYTE_LENGTH, TestNetworkIds.canonical().bytes().length);
  }

  @Test
  public void nativeAccountEntryPointsExposeAnExplicitChainArgument() {
    assertAllMethodOverloadsHaveIntParameter(
        NativeSignerBridge.class, "encodeRegisterZkAssetSignedTransaction", 2);
    assertMethodHasIntParameter(
        KOTLIN_NATIVE_SIGNER, "nativeEncodeRegisterZkAssetSignedTransaction", 2);

  }

  @Test
  public void nativeSignerRejectsOutOfRangeChainBeforeNativeDispatch() {
    final FeePaymentIntent feePayment = FeePaymentIntent.authority(Collections.emptyList());
    expectChainFailure(
        () ->
            NativeSignerBridge.encodeRegisterZkAssetSignedTransaction(
                SigningAlgorithm.ED25519,
                TestNetworkIds.canonical(),
                -1,
                "authority",
                0L,
                (RegisterZkAssetInstruction) null,
                new byte[] {1},
                feePayment));

    if (!NativeSignerBridge.isNativeAvailable()) {
      throw new AssertionError("connect_norito_bridge ABI 31 is required");
    }
    final NativeSignerBridge.KeypairBytes keypair =
        NativeSignerBridge.keypairFromSeed(SigningAlgorithm.ED25519, fill(0x21, 32));
    final String tairaAuthority;
    try {
      tairaAuthority =
          AccountAddress.fromAccount(keypair.publicKey(), "ed25519").toI105(TAIRA);
    } catch (final AccountAddress.AccountAddressException exception) {
      throw new AssertionError("failed to create Taira native signer authority", exception);
    }
    final RegisterZkAssetInstruction register =
        RegisterZkAssetInstruction.builder()
            .setAsset(TestAssetDefinitionIds.PRIMARY)
            .build();
    expectIllegalArgument(
        () ->
            NativeSignerBridge.encodeRegisterZkAssetSignedTransaction(
                SigningAlgorithm.ED25519,
                TestNetworkIds.canonical(),
                OTHER,
                tairaAuthority,
                1_736_000_000_000L,
                register,
                keypair.privateKey(),
                feePayment));
  }

  private static TransactionPayload payload(final String authority) {
    return TransactionPayload.builder()
        .setNetworkId(org.hyperledger.iroha.android.testing.TestNetworkIds.fromSeed(1L))
        .setAuthority(authority)
        .setCreationTimeMs(1_735_369_000_000L)
        .setExecutable(Executable.ivm(new byte[] {0x01}))
        .setFeePayment(FeePaymentIntent.authority(Collections.emptyList(), 1L))
        .build();
  }

  private static SignedTransaction signed(final byte[] payload, final String schemaName) {
    return new SignedTransaction(payload, fill(0x55, 64), new byte[0], schemaName);
  }

  private static byte[] swapMetadataEntries(final byte[] canonicalPayload) {
    final byte[][] fields = decodeSizedFields(canonicalPayload, 9);
    final NoritoDecoder metadata =
        new NoritoDecoder(fields[7], NoritoCodec.DEFAULT_FLAGS);
    assertEquals(2L, metadata.readLength(false));
    final byte[] first = readSizedField(metadata);
    final byte[] second = readSizedField(metadata);
    assertEquals(0, metadata.remaining());

    final NoritoEncoder swapped = new NoritoEncoder(NoritoCodec.DEFAULT_FLAGS);
    swapped.writeLength(2, false);
    writeSizedField(swapped, second);
    writeSizedField(swapped, first);
    fields[7] = swapped.toByteArray();
    return encodeSizedFields(fields);
  }

  private static byte[] replaceSizedField(
      final byte[] encoded, final int fieldIndex, final byte[] replacement) {
    final byte[][] fields = decodeSizedFields(encoded, 3);
    fields[fieldIndex] = replacement.clone();
    return encodeSizedFields(fields);
  }

  private static byte[][] decodeSizedFields(final byte[] encoded, final int count) {
    final NoritoDecoder decoder = new NoritoDecoder(encoded, NoritoCodec.DEFAULT_FLAGS);
    final byte[][] fields = new byte[count][];
    for (int index = 0; index < count; index++) {
      fields[index] = readSizedField(decoder);
    }
    assertEquals("unexpected trailing bytes", 0, decoder.remaining());
    return fields;
  }

  private static byte[] readSizedField(final NoritoDecoder decoder) {
    final long length = decoder.readLength(true);
    return decoder.readBytes(Math.toIntExact(length));
  }

  private static byte[] encodeSizedFields(final byte[][] fields) {
    final NoritoEncoder encoder = new NoritoEncoder(NoritoCodec.DEFAULT_FLAGS);
    for (final byte[] field : fields) {
      writeSizedField(encoder, field);
    }
    return encoder.toByteArray();
  }

  private static void writeSizedField(final NoritoEncoder encoder, final byte[] field) {
    encoder.writeLength(field.length, true);
    encoder.writeBytes(field);
  }

  private static String account(final int fill, final int chainDiscriminant) throws Exception {
    return AccountAddress.fromAccount(TestEd25519Keys.publicKey(fill), "ed25519")
        .toI105(chainDiscriminant);
  }

  private static byte[] fill(final int value, final int length) {
    final byte[] bytes = new byte[length];
    Arrays.fill(bytes, (byte) value);
    return bytes;
  }

  private static void assertAllMethodOverloadsHaveIntParameter(
      final Class<?> type, final String name, final int parameterIndex) {
    assertAllMethodOverloadsHaveParameter(type, name, parameterIndex, int.class);
  }

  private static void assertAllMethodOverloadsHaveParameter(
      final Class<?> type,
      final String name,
      final int parameterIndex,
      final Class<?> parameterType) {
    int matches = 0;
    for (final Method method : type.getDeclaredMethods()) {
      if (!method.getName().equals(name) || !Modifier.isStatic(method.getModifiers())) {
        continue;
      }
      matches++;
      assertTrue(method.getParameterCount() > parameterIndex);
      assertEquals(parameterType, method.getParameterTypes()[parameterIndex]);
    }
    assertTrue("missing method " + type.getName() + "." + name, matches > 0);
  }

  private static void assertMethodHasIntParameter(
      final Class<?> type, final String name, final int parameterIndex) {
    assertMethodHasParameter(type, name, parameterIndex, int.class);
  }

  private static void assertMethodHasParameter(
      final Class<?> type,
      final String name,
      final int parameterIndex,
      final Class<?> parameterType) {
    final Method method =
        Arrays.stream(type.getDeclaredMethods())
            .filter(candidate -> candidate.getName().equals(name))
            .findFirst()
            .orElseThrow(() -> new AssertionError("missing method " + type.getName() + "." + name));
    assertTrue(method.getParameterCount() > parameterIndex);
    assertEquals(parameterType, method.getParameterTypes()[parameterIndex]);
  }

  private static void assertNativeMethod(final Class<?> type, final String name) {
    assertTrue(
        type.getName() + "." + name + " must be the JNI declaration",
        Arrays.stream(type.getDeclaredMethods())
            .anyMatch(
                candidate ->
                    candidate.getName().equals(name)
                        && Modifier.isNative(candidate.getModifiers())
                        && Modifier.isStatic(candidate.getModifiers())));
  }

  private static void assertMethodHasParameterCount(
      final Class<?> type, final String name, final int parameterCount) {
    final Method method =
        Arrays.stream(type.getDeclaredMethods())
            .filter(candidate -> candidate.getName().equals(name))
            .findFirst()
            .orElseThrow(() -> new AssertionError("missing method " + type.getName() + "." + name));
    assertEquals(parameterCount, method.getParameterCount());
  }

  private static void await(final CountDownLatch latch) {
    try {
      latch.await();
    } catch (final InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new AssertionError("interrupted while waiting for concurrent chain test", interrupted);
    }
  }

  private static void expectChainFailure(final ThrowingRunnable operation) {
    try {
      operation.run();
      fail("expected an out-of-range chainDiscriminant failure");
    } catch (final IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("chainDiscriminant"));
    } catch (final Exception unexpected) {
      throw new AssertionError("unexpected failure type", unexpected);
    }
  }

  private static void expectIllegalArgument(final ThrowingRunnable operation) {
    try {
      operation.run();
      fail("expected IllegalArgumentException");
    } catch (final IllegalArgumentException expected) {
      // Expected.
    } catch (final Exception unexpected) {
      throw new AssertionError("unexpected failure type", unexpected);
    }
  }

  private static void expectNoritoFailure(final ThrowingRunnable operation) {
    try {
      operation.run();
      fail("expected NoritoException");
    } catch (final NoritoException expected) {
      // Expected.
    } catch (final Exception unexpected) {
      throw new AssertionError("unexpected failure type", unexpected);
    }
  }

  @FunctionalInterface
  private interface ThrowingRunnable {
    void run() throws Exception;
  }
}
