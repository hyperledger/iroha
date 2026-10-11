import XCTest
@testable import IrohaSwift

final class VerifyingKeyBackendTagTests: XCTestCase {
    func testNoritoDiscriminantsMatchRustExactly() {
        let expected: [(VerifyingKeyBackendTag, UInt32)] = [
            (.stark, 1),
            (.nativePipaRPasta, 0)
        ]

        XCTAssertEqual(VerifyingKeyBackendTag.allCases.count, expected.count)
        XCTAssertNil(VerifyingKeyBackendTag(rawValue: 2))
        for (backend, discriminant) in expected {
            XCTAssertEqual(backend.noritoDiscriminant, discriminant)
            XCTAssertEqual(VerifyingKeyBackendTag(rawValue: discriminant), backend)
        }
        XCTAssertNil(VerifyingKeyBackendTag(rawValue: 3))
        XCTAssertNil(VerifyingKeyBackendTag(rawValue: UInt32.max))
    }

    func testExactNativeRegistryEngineMapping() {
        for label in ["pipa-r/pasta", "pipa-r/pasta/kaigi-authorization-v1", "pipa-r/pasta/kaigi-usage-v1", "pipa-r/pasta/confidential-transfer-v1", "pipa-r/pasta/confidential-unshield-full-v1", "pipa-r/pasta/confidential-unshield-change-v1"] {
            XCTAssertEqual(VerifyingKeyBackendTag.registryTag(label), .nativePipaRPasta)
        }
        XCTAssertNil(VerifyingKeyBackendTag.registryTag("halo2/pasta/kaigi-usage-v1"))
        XCTAssertNil(VerifyingKeyBackendTag.registryTag("pipa-r/ipa/pasta/kaigi-usage-v1"))
    }

    func testCanonicalLabelsRoundTripExactly() {
        let expected: [(VerifyingKeyBackendTag, String)] = [
            (.stark, "stark"),
            (.nativePipaRPasta, "native-pipa-r-pasta")
        ]

        for (backend, label) in expected {
            XCTAssertEqual(backend.canonicalLabel, label)
            XCTAssertEqual(VerifyingKeyBackendTag(canonicalLabel: label), backend)
        }
    }

    func testCanonicalParserRejectsAliasesRetiredBackendsAndConfusables() {
        let rejected = [
            "",
            " ",
            "\t",
            "\n",
            "halo2-ipa-pasta",
            " halo2-ipa-pasta",
            "halo2-ipa-pasta ",
            "HALO2-IPA-PASTA",
            "Halo2-Ipa-Pasta",
            "halo2/ipa",
            "halo2/pasta",
            "halo2-bn254",
            "groth16",
            "groth16-bls12-377",
            "stark ",
            "STARK",
            "stark/fri",
            "halo2-ipa-orchard",
            "anonymous-pgc",
            "verange",
            "zkat",
            "silent-threshold-anoncred",
            "aztec-plonkish-private-kernel",
            "penumbra-masp",
            "stark\u{0}",
            "st\u{0430}rk",
            "halo2\u{FF0F}ipa",
            "stark\u{200B}"
        ]

        for label in rejected {
            XCTAssertNil(
                VerifyingKeyBackendTag(canonicalLabel: label),
                "\(label.debugDescription) must be rejected"
            )
        }
    }

    func testVerifierRegistryAcceptsOnlyPinnedRustProfiles() throws {
        let supported = [
            "pipa-r/pasta",
            "pipa-r/pasta/kaigi-authorization-v1",
            "pipa-r/pasta/kaigi-usage-v1",
            "pipa-r/pasta/confidential-transfer-v1",
            "pipa-r/pasta/confidential-unshield-full-v1",
            "pipa-r/pasta/confidential-unshield-change-v1",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1"
        ]

        for label in supported {
            XCTAssertTrue(VerifierBackendRegistryLabels.isSupported(label), label)
            XCTAssertTrue(VerifyingKeyBackendTag.isProductionVerifyBackendLabel(label), label)
            XCTAssertEqual(VerifierBackendCatalogTag(catalogLabel: label), .production)
            XCTAssertEqual(
                try VerifierBackendRegistryLabels.requireSupported(label),
                label
            )
        }
    }

    func testVerifierRegistryRejectsAliasesRetiredProfilesAndConfusables() {
        let rejected: [String?] = [
            nil,
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
            "",
            " ",
            " halo2/ipa",
            "halo2/ipa ",
            "HALO2/IPA",
            "halo2-ipa-pasta",
            "halo2/ipa-pasta-cycle-v1",
            "halo2/pasta/ivm-execution-v1",
            "halo2/pasta/ipa/ivm-replay-binding-v1",
            "halo2/ipa:ivm-replay-binding-v1",
            "halo2/ipa::ivm-replay-binding-v1",
            "stark",
            "stark/fri",
            "STARK/FRI",
            "stark/fri/",
            "stark/fri/poseidon2-goldilocks",
            "stark/fri/sha256_goldilocks.v1",
            "stark/fri/latest",
            "stark/fri/sha512-goldilocks",
            "halo2/bn254",
            "groth16",
            "groth16/bls12-377",
            "halo2-ipa-orchard",
            "anonymous-pgc",
            "verange",
            "zkat",
            "silent-threshold-anoncred",
            "aztec-plonkish-private-kernel",
            "penumbra-masp",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1\u{0}",
            "st\u{0430}rk/fri",
            "stark\u{FF0F}fri",
            "stark/fri/\u{200B}sha256-goldilocks"
        ]

        for label in rejected {
            XCTAssertFalse(VerifierBackendRegistryLabels.isSupported(label))
            guard let label else {
                continue
            }
            XCTAssertThrowsError(
                try VerifierBackendRegistryLabels.requireSupported(
                    label,
                    context: "registryBackend"
                )
            ) { error in
                XCTAssertEqual(
                    error as? VerifierBackendRegistryLabelValidationError,
                    .unsupported(context: "registryBackend", label: label)
                )
            }
        }
    }

    func testProtocolAndRetiredCatalogAliasesAreUnsupported() {
        for label in [
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
            "sis-hints-anoncred-pq-v0",
            "sis-with-hints"
        ] {
            XCTAssertEqual(VerifierBackendCatalogTag(catalogLabel: label), .unsupported)
            XCTAssertFalse(VerifyingKeyBackendTag.isProductionVerifyBackendLabel(label))
            XCTAssertNil(VerifyingKeyBackendTag(canonicalLabel: label))
        }
    }

    func testCatalogClassifierAcceptsOnlyExactProductionLabels() {
        for label in [
            "native-pipa-r-pasta",
            "stark",
            "pipa-r/pasta",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1",
        ] {
            XCTAssertEqual(VerifierBackendCatalogTag(catalogLabel: label), .production)
        }
        for label in ["HALO2/IPA", " halo2/ipa", "halo2/ipa ", "Stark"] {
            XCTAssertEqual(VerifierBackendCatalogTag(catalogLabel: label), .unsupported)
        }
    }

    func testAdversarialAliasSplicesStayUnsupported() {
        for label in [
            "halo2/ipa/orchard/dev-fixture",
            "stark/fri/miden/claimed-production",
            "anonymous-pgc-k-out-of-n-v1-production",
            "sis-hints-anoncred-pq-v0-devfixture",
            "groth16/bls12-377/../../prod",
            "post-quantum-masp/audit-claimed"
        ] {
            XCTAssertEqual(VerifierBackendCatalogTag(catalogLabel: label), .unsupported)
            XCTAssertNil(VerifyingKeyBackendTag(canonicalLabel: label))
        }
    }

    func testProductionVerifierBackendClassifierRejectsUnsafeLabels() {
        let rejected = [
            "",
            "halo2/pasta/kaigi-authorization-v1",
            "halo2/pasta/confidential-transfer-2x2-merkle16-axiom-poseidon-v3",
            "halo2/pasta/confidential-unshield-full-merkle16-axiom-poseidon-v3",
            "halo2/pasta/confidential-unshield-change-merkle16-axiom-poseidon-v4",
            "halo2/pasta/kaigi-usage-v1",
            "pipa-r/ipa/pasta/kaigi-authorization-v1",
            "pipa-r/pasta/kaigi-usage-v1/",
            "halo2/pasta/kaigi-roster-v1",
            "halo2/pasta/kagemusha-v1-mint-fold-merkle16-axiom-poseidon-v1",
            "unknown/privacy/backend",
            "halo2/unknown-native-v1",
            " halo2/ipa",
            "halo2/ipa ",
            "halo2/ipa\0",
            "HALO2/IPA",
            "stark/FRI",
            "halo2/ipa::ivm-replay-binding-v1",
            "stark/fri/sha256..goldilocks",
            "halo2\u{FF0F}ipa",
            "halo2/\u{200B}ipa",
            "h\u{0430}lo2/ipa",
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
            "halo2/ipa:anon-transfer-2x2-merkle16"
        ]

        for backend in rejected {
            XCTAssertFalse(
                VerifyingKeyBackendTag.isProductionVerifyBackendLabel(backend),
                "\(backend.debugDescription) must stay fail-closed"
            )
            XCTAssertThrowsError(
                try VerifyingKeyBackendTag.requireProductionVerifyBackendLabel(backend)
            ) { error in
                let description = (error as? LocalizedError)?.errorDescription ?? "\(error)"
                let trimmed = backend.trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmed.isEmpty {
                    XCTAssertTrue(description.contains("must not be blank"), description)
                } else if trimmed != backend {
                    XCTAssertTrue(description.contains("surrounding whitespace"), description)
                } else {
                    XCTAssertTrue(
                        description.contains("unsupported production verifier backend"),
                        description
                    )
                }
            }
        }
    }
}
