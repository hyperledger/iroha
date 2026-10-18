package org.hyperledger.iroha.sdk.privacy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/** Original Java bridge assertions against the sole Kotlin privacy owner. */
public final class PrivacyNativeBridgeJavaConsumerTest {
  // Internal require-archive rejection uses the identical truncations in the selected
  // Kotlin friend tests. Native descriptors and retired methods are checked from
  // compiled class bytes by scripts/check_privacy_jvm_class_contract.py.
  private static final List<List<String>> MATRIX = loadExact12Matrix();
  private static final List<List<String>> PROTOCOL_ROWS = rows("protocol");
  private static final List<List<String>> TYPED_ENVELOPE_ROWS = rows("typed-envelope");
  private static final List<String> RETIRED =
      rows("retired").stream().map(row -> row.get(1)).collect(Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList));
  private static final List<String> EXPECTED =
      PROTOCOL_ROWS.stream().map(row -> row.get(2)).collect(Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList));
  private static final List<PrivacyProofSystemIdV1> EXPECTED_PROOF_SYSTEMS =
      Arrays.asList(
          PrivacyProofSystemIdV1.STARK_FRI_SHA3_384_GOLDILOCKS_V1,
          PrivacyProofSystemIdV1.ANONYMOUS_PGC_P256,
          PrivacyProofSystemIdV1.IROHA_VERANGE_P256,
          PrivacyProofSystemIdV1.ZK_AMS_MASKED_RELAXED_SPARTAN_T256_RISTRETTO255_SHA3_512,
          PrivacyProofSystemIdV1.VEGA_NEUTRON_NOVA_SPARTAN_HYRAX_T256,
          PrivacyProofSystemIdV1.STARK_FRI_SHA3_384_GOLDILOCKS_V1,
          PrivacyProofSystemIdV1.JINDO_POLYNOMIAL_COMMITMENT,
          PrivacyProofSystemIdV1.LANTERN_LNP22_MODULE_LINEAR_NORM,
          PrivacyProofSystemIdV1.HALO2_IPA_PASTA,
          PrivacyProofSystemIdV1.FCMP_PLUS_PLUS_CURVE_TREE_BULLETPROOFS,
          PrivacyProofSystemIdV1.STARK_FRI_SHA3_384_GOLDILOCKS_V1,
          PrivacyProofSystemIdV1.STARK_FRI_SHA3_384_GOLDILOCKS_V1);
  private static final List<PrivacyEngineIdV1> EXPECTED_ENGINES =
      Arrays.asList(
          PrivacyEngineIdV1.NATIVE_GOLDILOCKS_SHA3_384_STARK_FRI_V1,
          PrivacyEngineIdV1.NATIVE_ANONYMOUS_PGC_P256,
          PrivacyEngineIdV1.NATIVE_VERANGE_P256,
          PrivacyEngineIdV1.NATIVE_ZK_AMS_MASKED_RELAXED_SPARTAN_T256_RISTRETTO255,
          PrivacyEngineIdV1.NATIVE_VEGA,
          PrivacyEngineIdV1.NATIVE_GOLDILOCKS_SHA3_384_STARK_FRI_V1,
          PrivacyEngineIdV1.NATIVE_JINDO,
          PrivacyEngineIdV1.NATIVE_LANTERN_LNP22,
          PrivacyEngineIdV1.NATIVE_HALO2_ORCHARD,
          PrivacyEngineIdV1.NATIVE_FCMP_PLUS_PLUS,
          PrivacyEngineIdV1.NATIVE_GOLDILOCKS_SHA3_384_STARK_FRI_V1,
          PrivacyEngineIdV1.NATIVE_GOLDILOCKS_SHA3_384_STARK_FRI_V1);

  @Test
  public void exactClosedRegistryIsStable() {
    assert PrivacyNativeBridge.REQUIRED_BRIDGE_ABI_VERSION == 30;
    assert PrivacyNativeBridge.protocolsV1().size() == 12;
    assert PrivacyProtocolIdV1.ZK_ACE_PQ_AUTHORIZATION_V1.ordinal() == 0;
    assert PrivacyProtocolIdV1.VEGA_EXISTING_CREDENTIAL_ZK_V1.ordinal() == 4;
    assert PrivacyProtocolIdV1.IROHA_ZK_X509_STARK_P256_V1.ordinal() == 5;
    assert PrivacyProtocolIdV1.IROHA_JINDO_POLYNOMIAL_COMMITMENT_V1.ordinal() == 6;
    assert PrivacyProtocolIdV1.PQ_MASP_STARK_V1.ordinal() == 11;
    assert PrivacyProofSystemIdV1.STARK_FRI_SHA3_384_GOLDILOCKS_V1.ordinal() == 0;
    assert PrivacyProofSystemIdV1.STARK_FRI_SHA3_384_GOLDILOCKS_V1
        .getCanonicalLabel()
        .equals("stark-fri-sha3-384-goldilocks-v1");
    assert PrivacyEngineIdV1.NATIVE_GOLDILOCKS_SHA3_384_STARK_FRI_V1.ordinal() == 0;
    assert PrivacyEngineIdV1.NATIVE_GOLDILOCKS_SHA3_384_STARK_FRI_V1
        .getCanonicalLabel()
        .equals("native-goldilocks-sha3-384-stark-fri-v1");
    for (int index = 0; index < EXPECTED.size(); index++) {
      final String label = EXPECTED.get(index);
      final PrivacyProtocolIdV1 protocol = PrivacyNativeBridge.protocolsV1().get(index);
      assert protocol.getCanonicalLabel().equals(label);
      assert PrivacyProtocolIdV1.fromCanonicalLabel(label) == protocol;
      assert protocol.getExpectedProofSystem() == EXPECTED_PROOF_SYSTEMS.get(index);
      assert protocol.getExpectedEngine() == EXPECTED_ENGINES.get(index);
    }
    assertThrows(() -> PrivacyNativeBridge.protocolsV1().clear());
  }

  @Test
  public void sharedExact12MatrixBindsRoutesAndTypedEnvelopeDigests() {
    assert MATRIX.stream()
        .allMatch(
            row ->
                Arrays.asList(
                        "matrix-version",
                        "registry-sha256",
                        "protocol",
                        "typed-envelope",
                        "retired")
                    .contains(row.get(0)));
    assert rows("matrix-version").equals(Arrays.asList(Arrays.asList("matrix-version", "1")));
    assert PROTOCOL_ROWS.size() == 12;
    for (int index = 0; index < PROTOCOL_ROWS.size(); index++) {
      assert PROTOCOL_ROWS.get(index).size() == 5;
      assert PROTOCOL_ROWS.get(index).get(1).equals(Integer.toString(index));
    }
    assert EXPECTED.stream().distinct().count() == 12;
    final StringBuilder registryPreimage = new StringBuilder();
    EXPECTED.forEach(value -> registryPreimage.append(value).append('\n'));
    assert rows("registry-sha256")
        .equals(Arrays.asList(Arrays.asList("registry-sha256", sha256Hex(registryPreimage.toString()))));
    assert TYPED_ENVELOPE_ROWS.stream()
        .map(row -> row.subList(1, 4))
        .collect(Collectors.toList())
        .equals(
            PROTOCOL_ROWS.stream()
                .map(row -> row.subList(2, 5))
                .collect(Collectors.toList()));
    assert TYPED_ENVELOPE_ROWS.size() == 12;
    for (final List<String> row : TYPED_ENVELOPE_ROWS) {
      assert row.size() == 6;
      for (final String digest : row.subList(4, 6)) {
        assert digest.matches("[0-9a-f]{64}");
        assert !digest.equals(String.join("", Collections.nCopies(64, "0")));
      }
    }
    assert RETIRED.stream().distinct().count() == RETIRED.size();
    assert RETIRED.stream().noneMatch(EXPECTED::contains);
  }

  @Test
  public void aliasesAndNonCanonicalSpellingsAreRejected() {
    final List<String> rejectedLabels = new ArrayList<>(RETIRED);
    rejectedLabels.addAll(
        Arrays.asList(
            "iroha-zk-ams-v1 ",
            "Iroha-Zk-Ams-V1",
            "",
            "unknown-privacy-protocol-v1"));
    for (final String rejected : rejectedLabels) {
      assertThrows(() -> PrivacyProtocolIdV1.fromCanonicalLabel(rejected));
    }
    assertThrows(() -> PrivacyProtocolIdV1.fromCanonicalLabel(null));
  }

  private static List<List<String>> rows(final String kind) {
    return MATRIX.stream()
        .filter(row -> row.get(0).equals(kind))
        .collect(Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList));
  }

  private static List<List<String>> loadExact12Matrix() {
    Path cursor = Paths.get("").toAbsolutePath().normalize();
    Path fixture = null;
    while (cursor != null) {
      final Path candidate = cursor.resolve("fixtures/privacy/exact12_v1.tsv");
      if (Files.isRegularFile(candidate)) {
        fixture = candidate;
        break;
      }
      cursor = cursor.getParent();
    }
    if (fixture == null) {
      throw new IllegalStateException("cannot locate fixtures/privacy/exact12_v1.tsv");
    }
    try {
      final String text = new String(Files.readAllBytes(fixture), StandardCharsets.UTF_8);
      if (!text.endsWith("\n") || text.contains("\r")) {
        throw new IllegalStateException("exact12 fixture is not canonical LF text");
      }
      if (Arrays.stream(text.substring(0, text.length() - 1).split("\n", -1))
          .anyMatch(String::isEmpty)) {
        throw new IllegalStateException("exact12 fixture contains an empty row");
      }
      final List<List<String>> result = new ArrayList<>();
      for (final String line : text.split("\n")) {
        if (!line.isEmpty() && !line.startsWith("#")) {
          result.add(Collections.unmodifiableList(Arrays.asList(line.split("\t", -1))));
        }
      }
      return Collections.unmodifiableList(result);
    } catch (final IOException error) {
      throw new IllegalStateException("cannot read exact12 fixture", error);
    }
  }

  private static String sha256Hex(final String value) {
    try {
      final byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
      final StringBuilder output = new StringBuilder(64);
      for (final byte octet : digest) {
        output.append(String.format("%02x", octet & 0xff));
      }
      return output.toString();
    } catch (final NoSuchAlgorithmException error) {
      throw new IllegalStateException("SHA-256 is unavailable", error);
    }
  }

  @Test
  public void sharedTypedValidatorStatusContractIsStable() {
    assert PrivacyNativeBridge.COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES == 256 * 1024;
    assert PrivacyNativeBridge.EXACT12_FIXTURE_BUNDLE_MAX_BYTES == 2 * 1024 * 1024;
    final PrivacyNativeBridge.CompiledProfileCatalogValidationStatusV1[] statuses =
        PrivacyNativeBridge.CompiledProfileCatalogValidationStatusV1.values();
    assert statuses.length == 9;
    for (int index = 0; index < statuses.length; index++) {
      assert statuses[index].getCode() == index;
    }
    final PrivacyNativeBridge.Exact12FixtureValidationStatusV1[] fixtureStatuses =
        PrivacyNativeBridge.Exact12FixtureValidationStatusV1.values();
    assert fixtureStatuses.length == 9;
    for (int index = 0; index < fixtureStatuses.length; index++) {
      assert fixtureStatuses[index].getCode() == index;
    }
  }

  @Test
  public void compiledProfileCatalogPreflightRejectsNullEmptyAndOversizeWithoutNativeCalls() {
    assert PrivacyNativeBridge.validateCompiledProfileCatalogV1(null)
        == PrivacyNativeBridge.CompiledProfileCatalogValidationStatusV1.NULL_POINTER;
    assert PrivacyNativeBridge.validateCompiledProfileCatalogV1(new byte[0])
        == PrivacyNativeBridge.CompiledProfileCatalogValidationStatusV1.EMPTY;
    assert PrivacyNativeBridge.validateCompiledProfileCatalogV1(
            new byte[PrivacyNativeBridge.COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES + 1])
        == PrivacyNativeBridge.CompiledProfileCatalogValidationStatusV1.ARCHIVE_TOO_LARGE;
  }

  @Test
  public void compiledProfileCatalogRoundTripsAndRejectsAdversarialBytesThroughNativeAbi24() {
    final boolean available = PrivacyNativeBridge.isNativeAvailable();
    if (!available) {
      throw new AssertionError(
          "ABI-30 connect_norito_bridge with compiled-profile catalog JNI exports is required");
    }

    final byte[] canonical = PrivacyNativeBridge.compiledProfileCatalogV1();
    assert canonical.length > 0;
    assert canonical.length <= PrivacyNativeBridge.COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES;
    assert PrivacyNativeBridge.validateCompiledProfileCatalogV1(canonical)
        == PrivacyNativeBridge.CompiledProfileCatalogValidationStatusV1.VALID;
    assert Arrays.equals(canonical, PrivacyNativeBridge.compiledProfileCatalogV1());
    final org.hyperledger.iroha.sdk.privacy.PrivacyCompiledProfileCatalogV1 typed =
        PrivacyNativeBridge.compiledProfileCatalogTypedV1();
    assert typed.protocols.size() == 12;
    assert Arrays.equals(
        canonical,
        org.hyperledger.iroha.sdk.privacy.PrivacyCompiledProfileCatalogCodecV1.encodeCanonical(
            typed));

    final byte[][] truncated = {
      Arrays.copyOfRange(canonical, 0, canonical.length - 1),
      Arrays.copyOfRange(canonical, 1, canonical.length),
      Arrays.copyOfRange(canonical, 0, canonical.length / 2)
    };
    for (final byte[] candidate : truncated) {
      assert PrivacyNativeBridge.validateCompiledProfileCatalogV1(candidate)
          != PrivacyNativeBridge.CompiledProfileCatalogValidationStatusV1.VALID;
    }

    final byte[] trailing = Arrays.copyOf(canonical, canonical.length + 1);
    assert PrivacyNativeBridge.validateCompiledProfileCatalogV1(trailing)
        != PrivacyNativeBridge.CompiledProfileCatalogValidationStatusV1.VALID;
    final int[] mutationIndices = {0, canonical.length / 2, canonical.length - 1};
    for (final int index : mutationIndices) {
      final byte[] mutated = Arrays.copyOf(canonical, canonical.length);
      mutated[index] ^= (byte) 0x80;
      assert PrivacyNativeBridge.validateCompiledProfileCatalogV1(mutated)
          != PrivacyNativeBridge.CompiledProfileCatalogValidationStatusV1.VALID;
    }
  }

  @Test
  public void exact12FixturePreflightRejectsNullEmptyAndOversizeWithoutNativeCalls() {
    assert PrivacyNativeBridge.validateExact12FixtureBundleV1(null)
        == PrivacyNativeBridge.Exact12FixtureValidationStatusV1.NULL_POINTER;
    assert PrivacyNativeBridge.validateExact12FixtureBundleV1(new byte[0])
        == PrivacyNativeBridge.Exact12FixtureValidationStatusV1.EMPTY;
    assert PrivacyNativeBridge.validateExact12FixtureBundleV1(
            new byte[PrivacyNativeBridge.EXACT12_FIXTURE_BUNDLE_MAX_BYTES + 1])
        == PrivacyNativeBridge.Exact12FixtureValidationStatusV1.ARCHIVE_TOO_LARGE;
  }

  @Test
  public void exact12FixtureBundleRoundTripsAndRejectsAdversarialBytesThroughNativeAbi24() {
    final boolean available = PrivacyNativeBridge.isNativeAvailable();
    if (!available) {
      throw new AssertionError(
          "ABI-30 connect_norito_bridge with exact-12 fixture JNI exports is required");
    }

    final byte[] fetched = PrivacyNativeBridge.exact12FixtureBundleV1();
    final byte[] canonical = Arrays.copyOf(fetched, fetched.length);
    assert canonical.length > 0;
    assert canonical.length <= PrivacyNativeBridge.EXACT12_FIXTURE_BUNDLE_MAX_BYTES;
    assert PrivacyNativeBridge.validateExact12FixtureBundleV1(canonical)
        == PrivacyNativeBridge.Exact12FixtureValidationStatusV1.VALID;
    assert Arrays.equals(canonical, PrivacyNativeBridge.exact12FixtureBundleV1());

    fetched[0] ^= (byte) 0xff;
    assert Arrays.equals(canonical, PrivacyNativeBridge.exact12FixtureBundleV1());

    final byte[][] truncated = {
      Arrays.copyOfRange(canonical, 0, canonical.length - 1),
      Arrays.copyOfRange(canonical, 1, canonical.length),
      Arrays.copyOfRange(canonical, 0, canonical.length / 2)
    };
    for (final byte[] candidate : truncated) {
      assert PrivacyNativeBridge.validateExact12FixtureBundleV1(candidate)
          != PrivacyNativeBridge.Exact12FixtureValidationStatusV1.VALID;
    }

    final byte[] trailing = Arrays.copyOf(canonical, canonical.length + 1);
    assert PrivacyNativeBridge.validateExact12FixtureBundleV1(trailing)
        != PrivacyNativeBridge.Exact12FixtureValidationStatusV1.VALID;

    final int[] mutationIndices = {0, canonical.length / 2, canonical.length - 1};
    for (final int index : mutationIndices) {
      final byte[] mutated = Arrays.copyOf(canonical, canonical.length);
      mutated[index] ^= (byte) 0x80;
      assert PrivacyNativeBridge.validateExact12FixtureBundleV1(mutated)
          != PrivacyNativeBridge.Exact12FixtureValidationStatusV1.VALID;
    }

    assert PrivacyNativeBridge.validateExact12FixtureBundleV1(
            PrivacyNativeBridge.compiledProfileCatalogV1())
        != PrivacyNativeBridge.Exact12FixtureValidationStatusV1.VALID;
  }

  private static void assertThrows(final Runnable runnable) {
    try {
      runnable.run();
      throw new AssertionError("expected failure");
    } catch (final RuntimeException expected) {
      // Expected.
    }
  }
}
