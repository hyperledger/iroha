package org.hyperledger.iroha.sdk.core.model.zk

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class VerifyingKeyBackendTagTest {

    private val registry = linkedSetOf(
        "pipa-r/pasta",
        "pipa-r/pasta/kaigi-authorization-v1",
        "pipa-r/pasta/kaigi-usage-v1",
        "pipa-r/pasta/confidential-transfer-v1",
        "pipa-r/pasta/confidential-unshield-full-v1",
        "pipa-r/pasta/confidential-unshield-change-v1",
        "stark/fri/poseidon-x7-goldilocks-6x64-v1",
    )

    @Test
    fun `backend enum contains only canonical low-level engines`() {
        assertEquals(
            listOf(
                VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA,
                VerifyingKeyBackendTag.STARK,
            ),
            VerifyingKeyBackendTag.entries,
        )
        assertEquals(VerifyingKeyBackendTag.STARK, VerifyingKeyBackendTag.parse("stark"))
        assertEquals(VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA, VerifyingKeyBackendTag.parse("native-pipa-r-pasta"))
    }

    @Test
    fun `backend parser rejects aliases retired engines and malformed labels`() {
        for (label in listOf(
            "",
            "halo2-ipa-pasta",
            " halo2-ipa-pasta",
            "halo2-ipa-pasta ",
            "HALO2-IPA-PASTA",
            "Stark",
            "stark ",
            "halo2/ipa",
            "stark/fri",
            "halo2-bn254",
            "groth16",
            "groth16-bls12-377",
            "aztec-plonkish-private-kernel",
            "zkat",
            "silent-threshold-anoncred",
            "unsupported",
            "stark\u0000",
            "st\u0430rk",
        )) {
            assertFailsWith<IllegalArgumentException>(label) {
                VerifyingKeyBackendTag.parse(label)
            }
        }
    }

    @Test
    fun `registry is the exact immutable native allowlist`() {
        assertEquals(7, VerifyingKeyBackendTag.VERIFIER_BACKEND_REGISTRY_LABELS_V1.size)
        assertEquals(registry, VerifyingKeyBackendTag.VERIFIER_BACKEND_REGISTRY_LABELS_V1)
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (VerifyingKeyBackendTag.VERIFIER_BACKEND_REGISTRY_LABELS_V1 as MutableSet<String>)
                .add("stark/fri/latest")
        }
    }

    @Test
    fun `every registry label resolves to one exact engine`() {
        for (label in registry) {
            val expected = if (label.startsWith("pipa-r/")) {
                VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA
            } else {
                VerifyingKeyBackendTag.STARK
            }
            assertEquals(
                expected,
                VerifyingKeyBackendTag.verifierBackendRegistryTagV1(label),
                label,
            )
            assertTrue(VerifyingKeyBackendTag.isVerifierBackendRegistryLabelV1(label), label)
            assertTrue(VerifyingKeyBackendTag.isProductionVerifyBackendLabel(label), label)
            assertEquals(
                VerifyingKeyBackendCatalogTag.PRODUCTION,
                VerifyingKeyBackendTag.fromCatalogLabel(label),
            )
            assertEquals(
                label,
                VerifyingKeyBackendTag.requireVerifierBackendRegistryLabelV1(label),
            )
        }
    }

    @Test
    fun `registry rejects aliases retired families and confusables`() {
        val rejected = listOf(
            "",
            "halo2/ipa",
            "halo2/pasta/ivm-execution-v1",
            "halo2/pasta/kaigi-authorization-v1",
            "halo2/pasta/confidential-transfer-2x2-merkle16-axiom-poseidon-v3",
            "halo2/pasta/confidential-unshield-full-merkle16-axiom-poseidon-v3",
            "halo2/pasta/confidential-unshield-change-merkle16-axiom-poseidon-v4",
            "halo2/pasta/kaigi-usage-v1",
            "pipa-r/ipa/pasta/kaigi-authorization-v1",
            "pipa-r/pasta/kaigi-usage-v1/",
            "halo2/pasta/kaigi-roster-v1",
            "halo2/pasta/kagemusha-v1-mint-fold-merkle16-axiom-poseidon-v1",
            "halo2-ipa-pasta",
            "stark",
            " halo2/ipa",
            "halo2/ipa ",
            "\thalo2/ipa",
            "halo2/ipa\n",
            "HALO2/IPA",
            "halo2//ipa",
            "halo2/ipa/",
            "halo2/ipa:",
            "halo2/ipa:ivm-replay-binding-v1",
            "halo2/ipa::ivm-replay-binding-v1",
            "halo2/ipa/ivm-replay-binding-v1",
            "halo2/pasta/ipa/ivm-replay-binding-v1",
            "halo2/pasta/ivm_execution_v1",
            "halo2/pasta/ivm-replay-binding-v1/",
            "halo2/pasta/ivm-replay-binding-v1\u0000",
            "halo2/pasta/ipa-pasta-cycle-v1",
            "halo2/ipa-pasta-cycle-v1",
            "halo2/pasta/ivm-overlay-bind",
            "halo2/pasta/tiny-add",
            "stark/fri/",
            "stark/fri",
            "STARK/FRI",
            "stark/FRI",
            "stark/fri/poseidon2-goldilocks",
            "stark/fri/sha256_goldilocks.v1",
            "stark/fri/latest",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1/extra",
            "stark/fri/sha256 goldilocks",
            "stark/fri/sha256+goldilocks",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1\u200B",
            "halo2\uFF0Fipa",
            "halo2/\u200Bipa",
            "h\u0430lo2/ipa",
            "../halo2/ipa",
            "groth16",
            "groth16/bn254",
            "groth16/bls12-377",
            "halo2/bn254",
            "halo2/kzg",
            "kzg/powersoftau",
            "aztec-plonkish-private-kernel",
            "zkat",
            "silent-threshold-anoncred",
            "penumbra-masp",
            "orchard",
            "fcmp++",
            "jindo-lattice-pcs-zk",
            "sis-hints-anoncred-pq-v0",
            "sis-with-hints",
            "vega-existing-credential-zk-v1",
            "anonymous-pgc-k-out-of-n-v1",
            "stark/fri/dev-fixture",
            "stark/fri/externally-audited",
            "halo2/ipa:production-ready",
            "halo2/ipa:kzg",
        )

        for (label in rejected) {
            assertNull(VerifyingKeyBackendTag.verifierBackendRegistryTagV1(label), label)
            assertFalse(VerifyingKeyBackendTag.isVerifierBackendRegistryLabelV1(label), label)
            assertFailsWith<IllegalArgumentException>(label) {
                VerifyingKeyBackendTag.requireVerifierBackendRegistryLabelV1(label)
            }
        }
        assertNull(VerifyingKeyBackendTag.verifierBackendRegistryTagV1(null))
        assertFalse(VerifyingKeyBackendTag.isVerifierBackendRegistryLabelV1(null))
    }

    @Test
    fun `one-byte and structural mutations of every label stay rejected`() {
        for (label in registry) {
            val mutations = linkedSetOf(
                " $label",
                "$label ",
                label.uppercase(),
                "$label/",
                "$label\u0000",
                "$label\u200B",
                label.replaceFirst("/", "//"),
                label.dropLast(1) + if (label.last() == 'x') "y" else "x",
            )
            mutations.remove(label)
            for (mutation in mutations) {
                assertFalse(
                    VerifyingKeyBackendTag.isVerifierBackendRegistryLabelV1(mutation),
                    "$mutation mutated from $label",
                )
            }
        }
    }

    @Test
    fun `protocol and retired catalog aliases are unsupported`() {
        for (label in listOf(
            "halo2-ipa-orchard",
            "groth16-bls12-377",
            "fcmp-plus-plus-curve-tree",
            "lattice-pcs-sis",
            "miden-stark",
            "aztec-plonkish-private-kernel",
            "pq-masp-stark-fri",
            "anonymous-pgc",
            "verange",
            "zkat",
            "recursive-anonymous-admission",
            "vega-existing-credential-zk",
            "silent-threshold-anoncred",
            "zk-x509",
            "sis-with-hints",
        )) {
            assertEquals(
                VerifyingKeyBackendCatalogTag.UNSUPPORTED,
                VerifyingKeyBackendTag.fromCatalogLabel(label),
            )
            assertFalse(VerifyingKeyBackendTag.isProductionVerifyBackendLabel(label))
        }
    }

    @Test
    fun `catalog classifier accepts only exact production labels`() {
        for (label in listOf(
            "native-pipa-r-pasta",
            "stark",
            "pipa-r/pasta",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1",
        )) {
            assertEquals(
                VerifyingKeyBackendCatalogTag.PRODUCTION,
                VerifyingKeyBackendTag.fromCatalogLabel(label),
            )
        }
        for (label in listOf("HALO2/IPA", " halo2/ipa", "halo2/ipa ", "Stark")) {
            assertEquals(
                VerifyingKeyBackendCatalogTag.UNSUPPORTED,
                VerifyingKeyBackendTag.fromCatalogLabel(label),
            )
        }
    }

    @Test
    fun `adversarial alias splices stay unsupported and noncanonical`() {
        for (label in listOf(
            "halo2/ipa/orchard/dev-fixture",
            "stark/fri/miden/claimed-production",
            "anonymous-pgc-k-out-of-n-v1-production",
            "sis-hints-anoncred-pq-v0-devfixture",
            "groth16/bls12-377/../../prod",
            "post-quantum-masp/audit-claimed",
        )) {
            assertEquals(
                VerifyingKeyBackendCatalogTag.UNSUPPORTED,
                VerifyingKeyBackendTag.fromCatalogLabel(label),
            )
            assertFailsWith<IllegalArgumentException>(label) {
                VerifyingKeyBackendTag.parse(label)
            }
        }
    }

    @Test
    fun `production verifier classifier rejects unsafe labels and surrounding whitespace`() {
        for (label in listOf(
            "",
            "halo2/pasta/ivm-execution-v1",
            "halo2/pasta/kaigi-authorization-v1",
            "halo2/pasta/confidential-transfer-2x2-merkle16-axiom-poseidon-v3",
            "halo2/pasta/confidential-unshield-full-merkle16-axiom-poseidon-v3",
            "halo2/pasta/confidential-unshield-change-merkle16-axiom-poseidon-v4",
            "halo2/pasta/kaigi-usage-v1",
            "pipa-r/ipa/pasta/kaigi-authorization-v1",
            "pipa-r/pasta/kaigi-usage-v1/",
            "halo2/pasta/kaigi-roster-v1",
            "halo2/pasta/kagemusha-v1-mint-fold-merkle16-axiom-poseidon-v1",
            " halo2/ipa",
            "halo2/ipa ",
            "halo2/ipa\u0000",
            "halo2\uFF0Fipa",
            "halo2/\u200Bipa",
            "h\u0430lo2/ipa",
            "HALO2/IPA",
            "stark/FRI",
            "halo2/ipa::ivm-replay-binding-v1",
            "stark/fri/sha256..goldilocks",
            "halo2/ipa:production-ready",
            "halo2/ipa:mainnet-ready",
            "halo2/ipa:release-ready",
            "halo2/ipa:certified-mainnet",
            "halo2/ipa:third-party-audited",
            "stark/fri/audit-signoff",
            "stark/fri/boi-audited",
            "stark/fri/external-security-review",
            "stark/fri/S.e.c.u.r.i.t.yReviewPassed",
            "stark/fri/s-e-c-u-r-i-t-y-a-u-d-i-t-e-d",
            "stark/fri/a-u-d-i-t-c-l-a-i-m",
            "stark/fri/latest",
            "stark/fri/attestation",
            "stark/fri/contest",
            "stark/fri/random-profile",
            "stark/fri/sha512-goldilocks",
            "stark/fri/audit-proof-v1",
            "stark/fri/dev-fixture",
            "stark/fri/d-e-v-f-i-x-t-u-r-e",
            "stark/fri/dev",
            "stark/fri/d-e-v",
            "stark/fri/test",
            "stark/fri/t-e-s-t",
            "stark/fri/todo",
            "stark/fri/t-o-d-o",
            "stark/fri/draft-only",
            "stark/fri/d-r-a-f-t",
            "stark/fri/pending-audit",
            "stark/fri/replace-before-mainnet",
            "stark/fri/not-production-ready",
            "stark/fri/placeholder",
            "halo2/ipa:dev-fixture",
            "halo2/ipa:dev",
            "halo2/ipa:d-e-v",
            "halo2/ipa:todo-proof",
            "halo2/ipa:t-o-d-o-proof",
            "halo2/ipa:draft-proof",
            "halo2/ipa:d-r-a-f-t-proof",
            "halo2/ipa:pending-audit",
            "halo2/ipa:replace-before-production",
            "halo2/ipa:not-for-production",
            "halo2/ipa:dummy",
            "halo2/ipa:f-a-k-e",
            "halo2/ipa:stub",
            "halo2/ipa:s-a-m-p-l-e",
            "halo2/pasta/asset-hidden-transfer-public-test",
            "halo2/ipa/asset-hidden-transfer-public-test",
            "halo2/ipa:asset-hidden-transfer-public-test",
            "halo2/pasta/tiny-add",
            "halo2/ipa/tiny-add",
            "halo2/ipa:tiny-add",
            "halo2/pasta/tiny-commit-open",
            "halo2/pasta/vote-bool-commit",
            "halo2/ipa/vote-bool-commit",
            "halo2/ipa:vote-bool-commit",
            "halo2/pasta/vote-bool-commit-merkle2",
            "halo2/ipa/vote-bool-commit-merkle8",
            "halo2/ipa:vote-bool-commit-merkle16",
            "halo2/pasta/anon-transfer-2x2",
            "halo2/ipa/anon-transfer-2x2",
            "halo2/ipa:anon-transfer-2x2",
            "halo2/pasta/anon-transfer-2x2-merkle2",
            "halo2/ipa/anon-transfer-2x2-merkle8",
            "halo2/ipa:anon-transfer-2x2-merkle16",
        )) {
            assertFalse(VerifyingKeyBackendTag.isProductionVerifyBackendLabel(label), label)
            assertFailsWith<IllegalArgumentException>(label) {
                VerifyingKeyBackendTag.requireProductionVerifyBackendLabel(label)
            }
        }
    }
}
