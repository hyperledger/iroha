package org.hyperledger.iroha.android;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.hyperledger.iroha.android.KeyManagementException;
import org.hyperledger.iroha.android.crypto.KeyProviderMetadata;
import org.hyperledger.iroha.android.crypto.IrohaHash;
import org.hyperledger.iroha.android.crypto.MlDsaPrivateKey;
import org.hyperledger.iroha.android.crypto.MlDsaPublicKey;
import org.hyperledger.iroha.android.crypto.NativeSignerBridge;
import org.hyperledger.iroha.android.crypto.SigningAlgorithm;
import org.hyperledger.iroha.android.crypto.Signer;
import org.hyperledger.iroha.android.crypto.SoftwareKeyProvider;
import org.hyperledger.iroha.android.crypto.keystore.KeyAttestation;
import org.hyperledger.iroha.android.crypto.keystore.KeyGenParameters;
import org.hyperledger.iroha.android.crypto.keystore.KeystoreBackend;
import org.hyperledger.iroha.android.crypto.keystore.KeyGenerationResult;
import org.hyperledger.iroha.android.crypto.keystore.KeystoreKeyProvider;
import org.hyperledger.iroha.android.crypto.keystore.attestation.AndroidAttestationRevocationPolicyV1;
import org.hyperledger.iroha.android.crypto.keystore.attestation.AndroidAttestationRevocationTestFixtures;
import org.hyperledger.iroha.android.crypto.keystore.attestation.AttestationResult;
import org.hyperledger.iroha.android.crypto.keystore.attestation.AttestationVerificationException;
import org.hyperledger.iroha.android.crypto.keystore.attestation.AttestationVerifier;

public final class IrohaKeyManagerTests {

  private IrohaKeyManagerTests() {}

  private static final byte[] ROOT_CERT = decodeBase64(
      "MIIDIjCCAgqgAwIBAgIUHifREEUziVTjk5SY9EdEKBhj+LAwDQYJKoZIhvcNAQELBQAwFzEVMBMGA1UE"
          + "AwwMVGVzdCBSb290IENBMB4XDTI1MTAyNTE1Mjc0M1oXDTM1MTAyMzE1Mjc0M1owFzEVMBMGA1UEAwwM"
          + "VGVzdCBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4cr8VyFyforGk8BkefC2"
          + "jy36UydWa50h/9tCGhx+JeYpsmNE050wPQTZJ+09vTjZN9N2dO/Bh8TGd4nIW5D+swmXrsnzyt9fpMMR"
          + "PrDpmXTAvaDdD+afCgTRkEasSb7wGNh7wtgUvP5aQnTRFHEPN8VVn31ndv093Ex84PvKgQt3SYQuW+ho"
          + "zw1TZyAhjc4ydGTX3szxx1SJNtnxCBWAspaCKVXo4vCgSHUO6/JXW8BfaCckAniGqrNySk35POmmlw70"
          + "oj0zuoqoeWygwZVnGXMAvkN6gVmW/OY18cvAhZHlLfJG0P/o+i7DTpllebDM6W7ILF+YTxEXrfi2ixdw"
          + "QwIDAQABo2YwZDAdBgNVHQ4EFgQUAiNcsp2ChOMGPTVGbslvK4wPnVQwHwYDVR0jBBgwFoAUAiNcsp2C"
          + "hOMGPTVGbslvK4wPnVQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcN"
          + "AQELBQADggEBAH1/kr4JUjckOxPIR0XdZE73Wwr4DXqCb/InpBs+2TJJPnXONpuwNtLPtFUyV9FuJ9qM"
          + "H+M2aGu3+enncDnaw8ChAPKn9+QmjgTrZk9sPQV9zi6coIrMqD67gMwJW7HE0YDem7pNpiN1l/VvDrwe"
          + "V/2QJu7Og+rDvVc48TIhVeTEaQLURsgwi2R8U/usieuDysfPq7OJm/1eu8pE+etK5GiR9t/24qfx8V8d"
          + "DVliRz7PjoxZoDZrgpJl94nq5665BpXQ5lbsrr22EFgqxkMs1nPNIUFVxgEZUPnOzPVGPEOefnSjuKxT"
          + "AR7INRwTwVOtoGf0swuwJo3VZHgfAcaLfLM=");

  private static final byte[] STRONGBOX_CERT = decodeBase64(
      "MIIDUTCCAjmgAwIBAgIULKS+BqcxAYB6ooMNchJ4LI59fxowDQYJKoZIhvcNAQELBQAwFzEVMBMGA1UE"
          + "AwwMVGVzdCBSb290IENBMB4XDTI1MTAyNTE1MjgwMFoXDTI2MTAyNTE1MjgwMFowHzEdMBsGA1UEAwwU"
          + "VGVzdCBBdHRlc3RhdGlvbiBLZXkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbQVFuKFDD"
          + "6t52BMS3ZVot+5OPrSIcXlY1xRgXJoh+yhmXjfc5UIBgjWyNuLWyaT8N6+iVUNqLsh7Nbow8ySi1vgWI"
          + "56OVhc4yLf6z2kbwTqJScHwQbphed/wLA3I0tkzu1E0zt3AqNsPlEEMiZYHe3PBbvLBrx+Ug+UsPe0uZ"
          + "UxU5l6fDd9MeWihEvnOCWX1Fi9D4IfOeNq1UiZlkzih97JhqEWx32FVyxOdM2gx/VySv6R4KGu3nVRzA"
          + "cl4Lgw2Zex81/x9TKu5Mnf+Sz+sYtPLfS+D7R5xHI/GZPZ/SHZ8g79dm0o6D/5S1B29kolGMAnnbLN3H"
          + "ym7WJm9tVf3zAgMBAAGjgYwwgYkwHQYDVR0OBBYEFAL9ObHQIHwRJ2kTOTzbnwzAM9o0MB8GA1UdIwQY"
          + "MBaAFAIjXLKdgoTjBj01Rm7JbyuMD51UMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgeAMC8GCisGAQQB1nkC"
          + "AREEITAfAgEDCgECAgEECgECBAVBRUVCRQQEAQIDBDAAMAAwADANBgkqhkiG9w0BAQsFAAOCAQEAE+vf"
          + "oKnq0xblVQmxeT8IjRRqzFnIpa7Fd92xoGSydhNwV1Ox29rPOkOthq3om/r03rETj07LbArH8iyfCs5m"
          + "cSrfWC+kELgKuWEVYs7Zi20UanZsV7lnYXaqTKt8uPLh4TDRbZ6ymRi5ionLJ8vu8cfEyAVCKmn983Kr"
          + "bMgwIYzmWPMPnp+oCJ/TXOLQjTgbmcP3QmXPs7BBjdasixlvmBForI08Y5qClDZMOqBf/l5xQi4IeLr9"
          + "Q3mFG3KuAmuoZKvKN6TAvY5Hleqy9pg4gKSB7/0wK5lfX/JfkLi6erS5l8VuED6OcOZc3VbO8OrwRdlP"
          + "FxdGTgtauVtYo24deQ==");

  private static final byte[] STRONGBOX_CHALLENGE = hex("4145454245");
  private static final long EVALUATION_TIME_EPOCH_MILLIS = 1761408000000L;
  private static final byte[] ED25519_SPKI_PREFIX =
      new byte[] {
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
      };
  private static final int ED25519_SPKI_SIZE = 44;

  public static void main(final String[] args) throws Exception {
    shouldGenerateDistinctEphemeralKeys();
    shouldReuseAliasAcrossInvocations();
    shouldBuildSoftwareManagerExplicitly();
    shouldErrorWhenHardwareIsRequiredButUnavailable();
    shouldPreferStrongBoxWhenAvailable();
    shouldRequireStrongBoxWhenRequested();
    shouldFailWhenStrongBoxUnavailable();
    shouldRejectProviderReturnsNonEd25519Key();
    shouldVerifyAttestationViaManager();
    shouldRejectAliasCollisionAcrossProviders();
    shouldGenerateAttestationViaManager();
    shouldSignPayloadViaAlias();
    shouldGenerateMlDsaKeysWhenConfigured();
    shouldRejectMalformedMlDsaSignatures();
    shouldRejectMlDsaHardwarePreferences();
    System.out.println("[IrohaAndroid] Key manager smoke tests passed.");
  }

  private static void shouldGenerateDistinctEphemeralKeys() throws Exception {
    final IrohaKeyManager manager = IrohaKeyManager.withSoftwareProvider();
    final KeyPair first = manager.generateEphemeral();
    final KeyPair second = manager.generateEphemeral();
    assert first.getPrivate() != null;
    assert second.getPrivate() != null;
    assert !Arrays.equals(first.getPrivate().getEncoded(), second.getPrivate().getEncoded())
        : "Ephemeral key material must differ per invocation";
  }

  private static void shouldReuseAliasAcrossInvocations() throws Exception {
    final IrohaKeyManager manager = IrohaKeyManager.withSoftwareProvider();
    final KeyPair generated =
        manager.generateOrLoad("android-alias", IrohaKeyManager.KeySecurityPreference.SOFTWARE_ONLY);
    final KeyPair loaded =
        manager.generateOrLoad("android-alias", IrohaKeyManager.KeySecurityPreference.HARDWARE_PREFERRED);

    assert Arrays.equals(generated.getPrivate().getEncoded(), loaded.getPrivate().getEncoded())
        : "Alias regeneration must return the same key material";
    assert !manager.hasHardwareBackedProvider()
        : "Software provider manager must report no hardware providers";
  }

  private static void shouldBuildSoftwareManagerExplicitly() throws Exception {
    final IrohaKeyManager manager = IrohaKeyManager.withSoftwareProvider();
    final KeyPair generated =
        manager.generateOrLoad("default-alias", IrohaKeyManager.KeySecurityPreference.HARDWARE_PREFERRED);
    assert generated.getPrivate() != null : "Software manager must generate keys";
    assert !manager.hasHardwareBackedProvider()
        : "Software provider manager should report no hardware providers";
    boolean threw = false;
    try {
      manager.generateOrLoad("default-hw", IrohaKeyManager.KeySecurityPreference.HARDWARE_REQUIRED);
    } catch (final KeyManagementException expected) {
      threw = true;
    }
    assert threw : "Hardware-required requests should fail when no keystore backend is present";
  }

  private static void shouldErrorWhenHardwareIsRequiredButUnavailable() throws Exception {
    final IrohaKeyManager manager = IrohaKeyManager.withSoftwareProvider();
    boolean threw = false;
    try {
      manager.generateOrLoad("hardware-only", IrohaKeyManager.KeySecurityPreference.HARDWARE_REQUIRED);
    } catch (final KeyManagementException expected) {
      threw = true;
    }
    assert threw : "Expect failure when hardware is required but not present";
  }

  private static void shouldPreferStrongBoxWhenAvailable() throws Exception {
    final RecordingProviderStub strongBox =
        RecordingProviderStub.strongBox("strongbox-provider");
    final RecordingProviderStub trustedEnvironment =
        RecordingProviderStub.trustedEnvironment("tee-provider");
    final SoftwareKeyProvider softwareProvider = new SoftwareKeyProvider();

    final IrohaKeyManager manager =
        IrohaKeyManager.fromProviders(
            List.of(strongBox, trustedEnvironment, softwareProvider));

    assert manager.hasStrongBoxProvider()
        : "Manager should report StrongBox availability when a StrongBox provider is registered";

    final KeyPair generated =
        manager.generateOrLoad(
            "sb-preferred", IrohaKeyManager.KeySecurityPreference.STRONGBOX_PREFERRED);

    assert generated.getPrivate() != null : "StrongBox preferred should yield a key";
    assert strongBox.generated("sb-preferred")
        : "StrongBox provider must generate the alias when available";
    assert !trustedEnvironment.generated("sb-preferred")
        : "TEE provider must not generate when StrongBox handled the alias";
  }

  private static void shouldRequireStrongBoxWhenRequested() throws Exception {
    final RecordingProviderStub strongBox =
        RecordingProviderStub.strongBox("strongbox-required-provider");
    final SoftwareKeyProvider softwareProvider = new SoftwareKeyProvider();

    final IrohaKeyManager manager =
        IrohaKeyManager.fromProviders(List.of(strongBox, softwareProvider));

    assert manager.hasStrongBoxProvider()
        : "Manager should report StrongBox availability when required provider is present";

    final KeyPair generated =
        manager.generateOrLoad(
            "sb-required", IrohaKeyManager.KeySecurityPreference.STRONGBOX_REQUIRED);

    assert generated.getPrivate() != null : "StrongBox required should yield a key";
    assert strongBox.generated("sb-required")
        : "StrongBox provider must back aliases when required";
  }

  private static void shouldFailWhenStrongBoxUnavailable() throws Exception {
    final RecordingProviderStub trustedEnvironment =
        RecordingProviderStub.trustedEnvironment("tee-only-provider");
    final SoftwareKeyProvider softwareProvider = new SoftwareKeyProvider();

    final IrohaKeyManager manager =
        IrohaKeyManager.fromProviders(List.of(trustedEnvironment, softwareProvider));

    assert !manager.hasStrongBoxProvider()
        : "Manager must report StrongBox absence when only TEE providers are registered";

    boolean threw = false;
    try {
      manager.generateOrLoad(
          "sb-missing", IrohaKeyManager.KeySecurityPreference.STRONGBOX_REQUIRED);
    } catch (final KeyManagementException expected) {
      threw = true;
    }
    assert threw : "StrongBox-required requests must fail when no StrongBox provider is present";
    assert !trustedEnvironment.generated("sb-missing")
        : "TEE provider must not service StrongBox-required aliases";
  }

  private static void shouldRejectProviderReturnsNonEd25519Key() throws Exception {
    final InvalidAlgorithmProviderStub invalidProvider =
        new InvalidAlgorithmProviderStub(KeyProviderMetadata.trustedEnvironment("invalid-provider"));
    final SoftwareKeyProvider softwareProvider = new SoftwareKeyProvider();
    final IrohaKeyManager manager =
        IrohaKeyManager.fromProviders(List.of(invalidProvider, softwareProvider));

    boolean threw = false;
    try {
        manager.generateOrLoad(
            "invalid-alias", IrohaKeyManager.KeySecurityPreference.HARDWARE_PREFERRED);
    } catch (final KeyManagementException expected) {
      threw = true;
    }

    assert threw : "Manager must reject invalid provider key material";
    assert invalidProvider.wasQueried()
        : "Invalid provider should have been queried before rejection";
  }

  private static void shouldVerifyAttestationViaManager() throws Exception {
    final AttestingBackend backend =
        new AttestingBackend(
            KeyProviderMetadata.builder("attesting-strongbox")
                .setStrongBoxBacked(true)
                .setSupportsAttestationCertificates(true)
                .build(),
            STRONGBOX_CERT,
            ROOT_CERT);
    final KeystoreKeyProvider keystoreProvider =
        new KeystoreKeyProvider(backend, KeyGenParameters.builder().setRequireStrongBox(true).build());

    backend.setAttestation(
        "attested-alias",
        KeyAttestation.builder()
            .setAlias("attested-alias")
            .addCertificate(STRONGBOX_CERT)
            .addCertificate(ROOT_CERT)
            .build());
    backend.setAttestedKey("attested-alias");

    final IrohaKeyManager manager =
        IrohaKeyManager.fromProviders(
            List.of(keystoreProvider, new SoftwareKeyProvider()));

    final AttestationVerifier verifier =
        verifierBuilder().addTrustedRoot(ROOT_CERT).requireStrongBox(true).build();

    final Optional<AttestationResult> result =
        manager.verifyAttestation("attested-alias", verifier, STRONGBOX_CHALLENGE);

    assert result.isPresent() : "Attestation verification should return a result";
    assert result.get().isStrongBoxAttestation() : "Expected StrongBox attestation result";
    assert Arrays.equals(STRONGBOX_CHALLENGE, result.get().attestationChallenge())
        : "Attestation challenge must match the expected value";
  }

  private static void shouldGenerateAttestationViaManager() throws Exception {
    final AttestingBackend backend =
        new AttestingBackend(
            KeyProviderMetadata.builder("attesting-strongbox")
                .setStrongBoxBacked(true)
                .setSupportsAttestationCertificates(true)
                .build(),
            STRONGBOX_CERT,
            ROOT_CERT);
    final KeystoreKeyProvider keystoreProvider =
        new KeystoreKeyProvider(backend, KeyGenParameters.builder().setRequireStrongBox(true).build());

    final IrohaKeyManager manager =
        IrohaKeyManager.fromProviders(
            List.of(keystoreProvider, new SoftwareKeyProvider()));

    backend.setAttestedKey("attest-on-demand");

    final Optional<KeyAttestation> generated =
        manager.generateAttestation("attest-on-demand", STRONGBOX_CHALLENGE);
    assert generated.isPresent() : "Expected generated attestation bundle";

    final AttestationVerifier verifier =
        verifierBuilder().addTrustedRoot(ROOT_CERT).requireStrongBox(true).build();
    final Optional<AttestationResult> verified =
        manager.verifyAttestation("attest-on-demand", verifier, STRONGBOX_CHALLENGE);
    assert verified.isPresent() : "Generated attestation should verify";
  }

  private static void shouldRejectAliasCollisionAcrossProviders() throws Exception {
    final KeyProviderMetadata metadata =
        KeyProviderMetadata.builder("attesting-strongbox")
            .setStrongBoxBacked(true)
            .setSupportsAttestationCertificates(true)
            .build();
    final AttestingBackend attesting =
        new AttestingBackend(metadata, STRONGBOX_CERT, ROOT_CERT);
    final AttestingBackend conflicting =
        new AttestingBackend(metadata, STRONGBOX_CERT, ROOT_CERT);
    attesting.setAttestation(
        "colliding-alias",
        KeyAttestation.builder()
            .setAlias("colliding-alias")
            .addCertificate(STRONGBOX_CERT)
            .addCertificate(ROOT_CERT)
            .build());
    attesting.setAttestedKey("colliding-alias");
    conflicting.setKeyFromCertificate("colliding-alias", ROOT_CERT);

    final IrohaKeyManager manager =
        IrohaKeyManager.fromProviders(
            List.of(
                new KeystoreKeyProvider(attesting, KeyGenParameters.builder().build()),
                new KeystoreKeyProvider(conflicting, KeyGenParameters.builder().build())));
    final AttestationVerifier verifier =
        verifierBuilder().addTrustedRoot(ROOT_CERT).requireStrongBox(true).build();

    boolean threw = false;
    try {
      manager.verifyAttestation("colliding-alias", verifier, STRONGBOX_CHALLENGE);
    } catch (final AttestationVerificationException expected) {
      threw = true;
      assert expected.getMessage().contains("different public keys")
          : "Expected a provider-collision failure";
    }
    assert threw : "Conflicting keys for one alias across providers must fail closed";
  }

  private static void shouldSignPayloadViaAlias() throws Exception {
    final IrohaKeyManager manager = IrohaKeyManager.withSoftwareProvider();
    final Signer signer =
        manager.signerForAlias("signing-alias", IrohaKeyManager.KeySecurityPreference.SOFTWARE_ONLY);

    final byte[] message = "hello-iroha-android".getBytes();
    final byte[] signature = signer.sign(message);

    final Signature verifier = Signature.getInstance("Ed25519");
    final KeyPair keyPair =
        manager.generateOrLoad("signing-alias", IrohaKeyManager.KeySecurityPreference.SOFTWARE_ONLY);
    verifier.initVerify(keyPair.getPublic());
    verifier.update(IrohaHash.prehash(message));
    assert verifier.verify(signature) : "Generated signature must verify with stored public key";
  }

  private static void shouldGenerateMlDsaKeysWhenConfigured() throws Exception {
    if (!NativeSignerBridge.isNativeAvailable()) {
      throw new AssertionError("connect_norito_bridge ABI 29 is required for ML-DSA keys");
    }
    final IrohaKeyManager manager = IrohaKeyManager.withSoftwareProvider(SigningAlgorithm.ML_DSA);
    final KeyPair keyPair =
        manager.generateOrLoad("ml-dsa-alias", IrohaKeyManager.KeySecurityPreference.SOFTWARE_ONLY);
    assert manager.signingAlgorithm() == SigningAlgorithm.ML_DSA
        : "Manager should expose ML-DSA when configured";
    assert keyPair.getPrivate() instanceof MlDsaPrivateKey
        : "ML-DSA manager must return ML-DSA private keys";
    assert keyPair.getPublic() instanceof MlDsaPublicKey
        : "ML-DSA manager must return ML-DSA public keys";

    final Signer signer =
        manager.signerForAlias("ml-dsa-alias", IrohaKeyManager.KeySecurityPreference.SOFTWARE_ONLY);
    final byte[] message = "hello-ml-dsa".getBytes();
    final byte[] signature = signer.sign(message);
    final boolean verified =
        NativeSignerBridge.verifyDetached(
            SigningAlgorithm.ML_DSA,
            signer.publicKey(),
            IrohaHash.prehash(message),
            signature);
    assert verified : "Generated ML-DSA signature must verify via the native bridge";
  }

  private static void shouldRejectMalformedMlDsaSignatures() throws Exception {
    if (!NativeSignerBridge.isNativeAvailable()) {
      throw new AssertionError(
          "connect_norito_bridge ABI 29 is required for ML-DSA signature admission");
    }
    final byte[] seed = new byte[32];
    Arrays.fill(seed, (byte) 0x44);
    final NativeSignerBridge.KeypairBytes pair =
        NativeSignerBridge.keypairFromSeed(SigningAlgorithm.ML_DSA, seed);
    final byte[] message =
        IrohaHash.prehash(
            "java-android-ml-dsa-signature-admission".getBytes(StandardCharsets.UTF_8));
    final byte[] signature =
        NativeSignerBridge.signDetached(SigningAlgorithm.ML_DSA, pair.privateKey(), message);

    assert NativeSignerBridge.verifyDetached(
            SigningAlgorithm.ML_DSA, pair.publicKey(), message, signature)
        : "Valid ML-DSA signature must verify via the native bridge";

    final byte[] shortSignature = Arrays.copyOf(signature, signature.length - 1);
    final byte[] overlongSignature = Arrays.copyOf(signature, signature.length + 1);
    overlongSignature[overlongSignature.length - 1] = 0x42;
    final byte[] allZeroSignature = new byte[signature.length];

    assert !NativeSignerBridge.verifyDetached(
            SigningAlgorithm.ML_DSA, pair.publicKey(), message, shortSignature)
        : "Short ML-DSA signature must not verify";
    assert !NativeSignerBridge.verifyDetached(
            SigningAlgorithm.ML_DSA, pair.publicKey(), message, overlongSignature)
        : "Overlong ML-DSA signature must not verify";
    assert !NativeSignerBridge.verifyDetached(
            SigningAlgorithm.ML_DSA, pair.publicKey(), message, allZeroSignature)
        : "All-zero ML-DSA signature must not verify";
  }

  private static void shouldRejectMlDsaHardwarePreferences() throws Exception {
    if (!NativeSignerBridge.isNativeAvailable()) {
      throw new AssertionError(
          "connect_norito_bridge ABI 29 is required for ML-DSA hardware preference checks");
    }
    final IrohaKeyManager manager = IrohaKeyManager.withSoftwareProvider(SigningAlgorithm.ML_DSA);
    boolean threw = false;
    try {
      manager.generateOrLoad(
          "ml-dsa-hardware", IrohaKeyManager.KeySecurityPreference.HARDWARE_PREFERRED);
    } catch (final KeyManagementException expected) {
      threw = true;
    }
    assert threw : "ML-DSA managers must fail fast for hardware preferences";
  }

  private static byte[] decodeBase64(final String value) {
    return Base64.getDecoder().decode(value);
  }

  private static AttestationVerifier.Builder verifierBuilder() {
    final AndroidAttestationRevocationPolicyV1 policy =
        AndroidAttestationRevocationTestFixtures.policy(
            EVALUATION_TIME_EPOCH_MILLIS,
            86_400L,
            java.util.Collections.emptyList(),
            java.util.Collections.emptyList());
    return AttestationVerifier.builder(policy, EVALUATION_TIME_EPOCH_MILLIS);
  }

  private static byte[] hex(final String value) {
    final int length = value.length();
    final byte[] output = new byte[length / 2];
    for (int i = 0; i < length; i += 2) {
      output[i / 2] = (byte) Integer.parseInt(value.substring(i, i + 2), 16);
    }
    return output;
  }

  private static boolean isEd25519Spki(final byte[] encoded) {
    if (encoded == null || encoded.length != ED25519_SPKI_SIZE) {
      return false;
    }
    for (int i = 0; i < ED25519_SPKI_PREFIX.length; i++) {
      if (encoded[i] != ED25519_SPKI_PREFIX[i]) {
        return false;
      }
    }
    return true;
  }

  private static final class RecordingProviderStub implements IrohaKeyManager.KeyProvider {
    private final SoftwareKeyProvider delegate = new SoftwareKeyProvider();
    private final KeyProviderMetadata metadata;
    private final ConcurrentMap<String, Boolean> generatedAliases = new ConcurrentHashMap<>();

    private RecordingProviderStub(final KeyProviderMetadata metadata) {
      this.metadata = metadata;
    }

    static RecordingProviderStub strongBox(final String name) {
      return new RecordingProviderStub(
          KeyProviderMetadata.builder(name)
              .setStrongBoxBacked(true)
              .setSupportsAttestationCertificates(true)
              .build());
    }

    static RecordingProviderStub trustedEnvironment(final String name) {
      return new RecordingProviderStub(KeyProviderMetadata.trustedEnvironment(name));
    }

    boolean generated(final String alias) {
      return generatedAliases.containsKey(alias);
    }

    @Override
    public Optional<KeyPair> load(final String alias) throws KeyManagementException {
      return delegate.load(alias);
    }

    @Override
    public KeyPair generate(final String alias) throws KeyManagementException {
      final KeyPair keyPair = delegate.generate(alias);
      generatedAliases.put(alias, Boolean.TRUE);
      return keyPair;
    }

    @Override
    public KeyPair generateEphemeral() throws KeyManagementException {
      return delegate.generateEphemeral();
    }

    @Override
    public boolean isHardwareBacked() {
      return metadata.hardwareBacked();
    }

    @Override
    public KeyProviderMetadata metadata() {
      return metadata;
    }

    @Override
    public org.hyperledger.iroha.android.crypto.KeyGenerationOutcome outcomeFor(
        final String alias, final KeyPair keyPair) {
      final org.hyperledger.iroha.android.crypto.KeyGenerationOutcome.Route route;
      if (metadata.strongBoxBacked()) {
        route = org.hyperledger.iroha.android.crypto.KeyGenerationOutcome.Route.STRONGBOX;
      } else if (metadata.hardwareBacked()) {
        route = org.hyperledger.iroha.android.crypto.KeyGenerationOutcome.Route.HARDWARE;
      } else {
        route = org.hyperledger.iroha.android.crypto.KeyGenerationOutcome.Route.SOFTWARE;
      }
      return new org.hyperledger.iroha.android.crypto.KeyGenerationOutcome(keyPair, route);
    }

    @Override
    public String name() {
      return metadata.name();
    }
  }

  private static final class InvalidAlgorithmProviderStub implements IrohaKeyManager.KeyProvider {
    private final KeyPair invalidKeyPair;
    private final KeyProviderMetadata metadata;
    private final ConcurrentMap<String, Boolean> queriedAliases = new ConcurrentHashMap<>();

    private InvalidAlgorithmProviderStub(final KeyProviderMetadata metadata) {
      this.metadata = metadata;
      try {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        this.invalidKeyPair = generator.generateKeyPair();
      } catch (final Exception ex) {
        throw new IllegalStateException("Failed to create invalid keypair", ex);
      }
    }

    boolean wasQueried() {
      return !queriedAliases.isEmpty();
    }

    @Override
    public Optional<KeyPair> load(final String alias) {
      queriedAliases.put(alias, Boolean.TRUE);
      return Optional.of(invalidKeyPair);
    }

    @Override
    public KeyPair generate(final String alias) {
      queriedAliases.put(alias, Boolean.TRUE);
      return invalidKeyPair;
    }

    @Override
    public KeyPair generateEphemeral() {
      return invalidKeyPair;
    }

    @Override
    public boolean isHardwareBacked() {
      return metadata.hardwareBacked();
    }

    @Override
    public KeyProviderMetadata metadata() {
      return metadata;
    }

    @Override
    public String name() {
      return metadata.name();
    }
  }

  private static final class AttestingBackend implements KeystoreBackend {
    private final ConcurrentMap<String, KeyPair> keys = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, KeyAttestation> attestations = new ConcurrentHashMap<>();
    private final SoftwareKeyProvider delegate = new SoftwareKeyProvider();
    private final KeyProviderMetadata metadata;
    private final byte[] leafCertificate;
    private final byte[] rootCertificate;

    private AttestingBackend(
        final KeyProviderMetadata metadata, final byte[] leafCertificate, final byte[] rootCertificate) {
      this.metadata = metadata;
      this.leafCertificate = leafCertificate.clone();
      this.rootCertificate = rootCertificate.clone();
    }

    @Override
    public Optional<KeyPair> load(final String alias) {
      return Optional.ofNullable(keys.get(alias));
    }

    @Override
    public KeyGenerationResult generate(final String alias, final KeyGenParameters parameters)
        throws KeyManagementException {
      final KeyPair keyPair = delegate.generate(alias);
      keys.put(alias, keyPair);
      final boolean strongBox = metadata.strongBoxBacked();
      return new KeyGenerationResult(keyPair, strongBox);
    }

    @Override
    public KeyPair generateEphemeral(final KeyGenParameters parameters)
        throws KeyManagementException {
      return delegate.generateEphemeral();
    }

    @Override
    public KeyProviderMetadata metadata() {
      return metadata;
    }

    @Override
    public String name() {
      return metadata.name();
    }

    @Override
    public Optional<KeyAttestation> attestation(final String alias) {
      return Optional.ofNullable(attestations.get(alias));
    }

    @Override
    public Optional<KeyAttestation> generateAttestation(final String alias, final byte[] challenge) {
      if (!keys.containsKey(alias)) {
        return Optional.empty();
      }
      final KeyAttestation attestation =
          KeyAttestation.builder()
              .setAlias(alias)
              .addCertificate(leafCertificate)
              .addCertificate(rootCertificate)
              .build();
      attestations.put(alias, attestation);
      return Optional.of(attestation);
    }

    void setAttestation(final String alias, final KeyAttestation attestation) {
      attestations.put(alias, attestation);
    }

    void setAttestedKey(final String alias) throws Exception {
      setKeyFromCertificate(alias, leafCertificate);
    }

    void setKeyFromCertificate(final String alias, final byte[] certificateDer) throws Exception {
      final java.security.cert.X509Certificate certificate =
          (java.security.cert.X509Certificate)
              java.security.cert.CertificateFactory.getInstance("X.509")
                  .generateCertificate(new ByteArrayInputStream(certificateDer));
      keys.put(alias, new KeyPair(certificate.getPublicKey(), null));
    }
  }
}
