package org.hyperledger.iroha.sdk.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import kotlin.Pair;
import org.hyperledger.iroha.sdk.address.AccountAddress;
import org.hyperledger.iroha.sdk.core.model.FeeChargeKind;
import org.hyperledger.iroha.sdk.core.model.FeeChargeLimit;
import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent;
import org.hyperledger.iroha.sdk.core.model.NetworkId;
import org.hyperledger.iroha.sdk.core.model.TransactionPayload;
import org.hyperledger.iroha.sdk.core.model.instructions.RegisterZkAssetInstruction;
import org.hyperledger.iroha.sdk.testing.TestNetworkIds;
import org.hyperledger.iroha.sdk.tx.SignedTransaction;
import org.hyperledger.iroha.sdk.tx.norito.NoritoJavaCodecAdapter;
import org.hyperledger.iroha.sdk.tx.norito.SignedTransactionEncoder;
import org.junit.jupiter.api.Test;

/** Java signing consumers retain the network, fee and signature admission assertions. */
public final class NativeSignerBridgeJavaConsumerTest {
  private static final String GAS_ASSET = "7EAD8EFYUx1aVKZPUU1fyKvr8dF1";
  private static final int TAIRA = org.hyperledger.iroha.sdk.client.TairaTestnetProfile.I105_DISCRIMINANT;

  @Test
  void exposesNominalNetworkAndContractConstants() {
    assertEquals(29, NativeSignerBridge.REQUIRED_BRIDGE_ABI_VERSION);
    assertEquals(7, NativeSignerBridge.REQUIRED_NATIVE_SIGNER_CONTRACT_REVISION);
    final NetworkId network = TestNetworkIds.INSTANCE.canonical();
    assertEquals(NetworkId.BYTE_LENGTH, network.bytes().length);
    assertEquals(32, NetworkId.BYTE_LENGTH);
    // The JNI bytecode guard checks parameter types and absent retired entrypoints.
  }

  @Test
  void rejectsOutOfRangeChainBeforeNativeDispatch() {
    for (final int chain : new int[] {-1, 0x10000}) {
      final IllegalArgumentException error = assertThrows(
          IllegalArgumentException.class,
          () -> NativeSignerBridge.encodeRegisterZkAssetSignedTransaction(
              SigningAlgorithm.ED25519, TestNetworkIds.INSTANCE.canonical(), chain,
              "authority", 0L, null, null, new byte[] {1}, noFeePayment()));
      assertTrue(error.getMessage().contains("chainDiscriminant"));
    }
  }

  @Test
  void rejectsBadTtlBeforeNativeDispatch() {
    final RegisterZkAssetInstruction register =
        RegisterZkAssetInstruction.builder().setAsset("rose#wonderland").build();
    assertThrows(IllegalArgumentException.class,
        () -> NativeSignerBridge.encodeRegisterZkAssetSignedTransaction(
            SigningAlgorithm.ED25519, TestNetworkIds.INSTANCE.canonical(),
            AccountAddress.DEFAULT_I105_DISCRIMINANT, "alice", 0L, 0L,
            register, new byte[] {1}, noFeePayment()));
  }

  @Test
  void rejectsFeeBoundsBeforeNativeDispatch() {
    assertThrows(IllegalArgumentException.class,
        () -> FeePaymentIntent.authority(Collections.emptyList(), 0L));
    assertThrows(IllegalArgumentException.class,
        () -> new FeeChargeLimit(FeeChargeKind.PIPELINE_GAS, "xor#universal", "1"));
    assertThrows(IllegalArgumentException.class,
        () -> new FeeChargeLimit(FeeChargeKind.PIPELINE_GAS, GAS_ASSET, "0"));
    assertThrows(IllegalArgumentException.class,
        () -> FeePaymentIntent.authority(Arrays.asList(
            new FeeChargeLimit(FeeChargeKind.PIPELINE_GAS, GAS_ASSET, "1"),
            new FeeChargeLimit(FeeChargeKind.NEXUS, GAS_ASSET, "1"))));
  }

  @Test
  void signedTransactionOwnsInputsAndOutputs() {
    final byte[] versioned = {1, 2, 3};
    final byte[] hash = fill(0x30, 32);
    final NativeSignedTransaction signed = new NativeSignedTransaction(versioned, hash);
    versioned[0] = 9;
    hash[0] = 9;
    assertArrayEquals(new byte[] {1, 2, 3}, signed.getVersionedSignedTransaction());
    assertEquals(0x30, signed.getTransactionHash()[0]);
    signed.getVersionedSignedTransaction()[0] = 9;
    signed.getTransactionHash()[0] = 9;
    assertArrayEquals(new byte[] {1, 2, 3}, signed.getVersionedSignedTransaction());
    assertEquals(0x30, signed.getTransactionHash()[0]);
    assertThrows(IllegalArgumentException.class,
        () -> new NativeSignedTransaction(new byte[0], fill(1, 32)));
    assertThrows(IllegalArgumentException.class,
        () -> new NativeSignedTransaction(new byte[] {1}, fill(1, 31)));
  }

  @Test
  void nativeMlDsaRejectsMalformedSignatures() {
    requireNative();
    final Pair<byte[], byte[]> pair =
        NativeSignerBridge.keypairFromSeed(SigningAlgorithm.ML_DSA, fill(0x44, 32));
    final byte[] message = IrohaHash.prehash(
        "java-android-ml-dsa-signature-admission".getBytes(StandardCharsets.UTF_8));
    final byte[] signature =
        NativeSignerBridge.signDetached(SigningAlgorithm.ML_DSA, pair.getFirst(), message);
    assertTrue(NativeSignerBridge.verifyDetached(
        SigningAlgorithm.ML_DSA, pair.getSecond(), message, signature));
    final byte[] overlong = Arrays.copyOf(signature, signature.length + 1);
    overlong[signature.length] = 0x42;
    for (final byte[] malformed : new byte[][] {
        Arrays.copyOf(signature, signature.length - 1), overlong, new byte[signature.length]}) {
      assertFalse(NativeSignerBridge.verifyDetached(
          SigningAlgorithm.ML_DSA, pair.getSecond(), message, malformed));
    }
  }

  @Test
  void nativeEd25519KeyDerivationAndSignatureAgree() {
    requireNative();
    final Pair<byte[], byte[]> pair =
        NativeSignerBridge.keypairFromSeed(SigningAlgorithm.ED25519, fill(0x21, 32));
    assertArrayEquals(pair.getSecond(),
        NativeSignerBridge.publicKeyFromPrivate(SigningAlgorithm.ED25519, pair.getFirst()));
    final byte[] message = IrohaHash.prehash("java-kotlin-signer".getBytes(StandardCharsets.UTF_8));
    final byte[] signature =
        NativeSignerBridge.signDetached(SigningAlgorithm.ED25519, pair.getFirst(), message);
    assertTrue(NativeSignerBridge.verifyDetached(
        SigningAlgorithm.ED25519, pair.getSecond(), message, signature));
    message[0] ^= 1;
    assertFalse(NativeSignerBridge.verifyDetached(
        SigningAlgorithm.ED25519, pair.getSecond(), message, signature));
  }

  @Test
  void nativeSignerRejectsMismatchedAuthorityChain() throws Exception {
    requireNative();
    final Pair<byte[], byte[]> pair =
        NativeSignerBridge.keypairFromSeed(SigningAlgorithm.ED25519, fill(0x21, 32));
    final String authority = AccountAddress.fromAccount(pair.getSecond(), "ed25519").toI105(TAIRA);
    final RegisterZkAssetInstruction register =
        RegisterZkAssetInstruction.builder().setAsset(GAS_ASSET).build();
    assertThrows(IllegalArgumentException.class,
        () -> NativeSignerBridge.encodeRegisterZkAssetSignedTransaction(
            SigningAlgorithm.ED25519, TestNetworkIds.INSTANCE.canonical(),
            AccountAddress.DEFAULT_I105_DISCRIMINANT, authority, 1_736_000_000_000L,
            null, register, pair.getFirst(), noFeePayment()));
  }

  @Test
  void nativeTransactionBindsFeePayment() throws Exception {
    requireNative();
    final byte[] seed = new byte[32];
    for (int i = 0; i < seed.length; i++) seed[i] = (byte) (i + 1);
    final Pair<byte[], byte[]> pair =
        NativeSignerBridge.keypairFromSeed(SigningAlgorithm.ED25519, seed);
    final String authority = AccountAddress.fromAccount(pair.getSecond(), "ed25519")
        .toI105(AccountAddress.DEFAULT_I105_DISCRIMINANT);
    final FeePaymentIntent expected = FeePaymentIntent.authority(Collections.singletonList(
        new FeeChargeLimit(FeeChargeKind.PIPELINE_GAS, GAS_ASSET, "1000")), 1000L);
    final RegisterZkAssetInstruction register =
        RegisterZkAssetInstruction.builder().setAsset(GAS_ASSET).build();
    final NativeSignedTransaction nativeTx = NativeSignerBridge.encodeRegisterZkAssetSignedTransaction(
        SigningAlgorithm.ED25519, TestNetworkIds.INSTANCE.canonical(),
        AccountAddress.DEFAULT_I105_DISCRIMINANT, authority, 1_736_000_000_000L,
        null, register, pair.getFirst(), expected);
    final SignedTransaction signed =
        SignedTransactionEncoder.decodeVersioned(nativeTx.getVersionedSignedTransaction());
    final TransactionPayload payload =
        new NoritoJavaCodecAdapter(AccountAddress.DEFAULT_I105_DISCRIMINANT)
            .decodeTransaction(signed.encodedPayload());
    assertEquals(expected, payload.getFeePayment());
    assertFalse(payload.getMetadata().containsKey("gas_asset_id"));
    assertFalse(payload.getMetadata().containsKey("gas_limit"));
  }

  private static void requireNative() {
    assertTrue(NativeSignerBridge.isNativeAvailable(),
        "same-source connect_norito_bridge ABI 29 / signer contract 7 is required");
  }

  private static FeePaymentIntent noFeePayment() {
    return FeePaymentIntent.authority(Collections.emptyList());
  }

  private static byte[] fill(final int value, final int size) {
    final byte[] result = new byte[size];
    Arrays.fill(result, (byte) value);
    return result;
  }
}
