package org.hyperledger.iroha.sdk.core.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import org.hyperledger.iroha.sdk.core.model.zk.VerifyingKeyBackendTag;
import org.junit.jupiter.api.Test;

/** Java consumers use the Kotlin-owned final V1 verifier registry. */
final class VerifyingKeyRegistryJavaConsumerTest {
  @Test
  void canonicalRegistryIsExactAndImmutable() {
    final Set<String> expected = new LinkedHashSet<>(Arrays.asList(
        "pipa-r/pasta",
        "pipa-r/pasta/kaigi-authorization-v1",
        "pipa-r/pasta/kaigi-usage-v1",
        "pipa-r/pasta/confidential-transfer-v1",
        "pipa-r/pasta/confidential-unshield-full-v1",
        "pipa-r/pasta/confidential-unshield-change-v1",
        "stark/fri/poseidon-x7-goldilocks-6x64-v1"));
    assertEquals(7, expected.size());
    assertEquals(expected, VerifyingKeyBackendTag.VERIFIER_BACKEND_REGISTRY_LABELS_V1);
    for (final String label : expected) {
      assertEquals(label, VerifyingKeyBackendTag.requireVerifierBackendRegistryLabelV1(label));
      assertEquals(label.startsWith("pipa-r/") ? VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA
              : VerifyingKeyBackendTag.STARK,
          VerifyingKeyBackendTag.verifierBackendRegistryTagV1(label));
    }
    assertThrows(UnsupportedOperationException.class,
        () -> VerifyingKeyBackendTag.VERIFIER_BACKEND_REGISTRY_LABELS_V1.clear());
  }

  @Test
  void retiredRosterAndUnsupportedFoldCannotBecomeVerifierProfiles() {
    for (final String label : Arrays.asList(
        "halo2/ipa",
        "halo2/pasta/ivm-execution-v1",
        "halo2/pasta/kaigi-authorization-v1",
        "halo2/pasta/kaigi-usage-v1",
        "pipa-r/ipa/pasta/kaigi-authorization-v1",
        "halo2/pasta/kaigi-roster-v1",
        "halo2/pasta/kagemusha-v1-mint-fold-merkle16-axiom-poseidon-v1")) {
      assertNull(VerifyingKeyBackendTag.verifierBackendRegistryTagV1(label));
      assertFalse(VerifyingKeyBackendTag.isVerifierBackendRegistryLabelV1(label));
      assertFalse(VerifyingKeyBackendTag.isProductionVerifyBackendLabel(label));
      assertThrows(IllegalArgumentException.class,
          () -> VerifyingKeyBackendTag.requireVerifierBackendRegistryLabelV1(label));
    }
  }
}
