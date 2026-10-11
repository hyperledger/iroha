using System;
using System.Collections.Generic;
using Hyperledger.Iroha.Zk;

namespace Hyperledger.Iroha.Sdk.Tests;

public sealed class VerifyingKeyBackendTagTests
{
    [Fact]
    public void NoritoDiscriminantsMatchRustOrderExactly()
    {
        var expected = new[]
        {
            (VerifyingKeyBackendTag.Stark, 1U),
            (VerifyingKeyBackendTag.NativePipaRPasta, 0U),
        };

        Assert.Equal(expected.Length, Enum.GetValues<VerifyingKeyBackendTag>().Length);
        foreach (var (tag, discriminant) in expected)
        {
            Assert.Equal(discriminant, tag.NoritoDiscriminant());
            Assert.Equal(tag, (VerifyingKeyBackendTag)discriminant);
        }
    }

    [Theory]
    [InlineData(VerifyingKeyBackendTag.Stark, "stark")]
    [InlineData(VerifyingKeyBackendTag.NativePipaRPasta, "native-pipa-r-pasta")]
    public void CanonicalLabelsRoundTripExactly(
        VerifyingKeyBackendTag expected,
        string label)
    {
        Assert.Equal(label, expected.CanonicalLabel());
        Assert.True(VerifyingKeyBackendTags.TryFromCanonicalLabel(label, out var parsed));
        Assert.Equal(expected, parsed);
        Assert.Equal(expected, VerifyingKeyBackendTags.FromCanonicalLabel(label));
        Assert.Equal(label, VerifyingKeyBackendTags.RequireCanonicalLabel(label));
    }

    [Fact]
    public void ExactNativeRegistryEngineMapping()
    {
        foreach (var label in new[] { "pipa-r/pasta", "pipa-r/pasta/kaigi-authorization-v1", "pipa-r/pasta/kaigi-usage-v1" })
            Assert.Equal(VerifyingKeyBackendTag.NativePipaRPasta, VerifyingKeyBackendTags.RegistryTag(label));
        Assert.Null(VerifyingKeyBackendTags.RegistryTag("halo2/pasta/kaigi-usage-v1"));
        Assert.Null(VerifyingKeyBackendTags.RegistryTag("pipa-r/ipa/pasta/kaigi-usage-v1"));
    }

    [Fact]
    public void UnknownEnumValuesCannotAcquireAStringOrWireDiscriminant()
    {
        var unknown = (VerifyingKeyBackendTag)3U;

        Assert.Throws<ArgumentOutOfRangeException>(() => unknown.CanonicalLabel());
        Assert.Throws<ArgumentOutOfRangeException>(() => unknown.NoritoDiscriminant());
    }

    [Theory]
    [MemberData(nameof(NonCanonicalLabels))]
    public void NonCanonicalAndRetiredLabelsAreRejected(string? label)
    {
        Assert.False(VerifyingKeyBackendTags.TryFromCanonicalLabel(label, out _));

        var parseError = Assert.Throws<ArgumentException>(
            () => VerifyingKeyBackendTags.FromCanonicalLabel(label, "proofBackend"));
        Assert.Equal("proofBackend", parseError.ParamName);

        var requireError = Assert.Throws<ArgumentException>(
            () => VerifyingKeyBackendTags.RequireCanonicalLabel(label, "proofBackend"));
        Assert.Equal("proofBackend", requireError.ParamName);
    }

    public static IEnumerable<object?[]> NonCanonicalLabels()
    {
        string?[] labels =
        [
            null,
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
            "halo2/bn254",
            "groth16",
            "groth16/bls12-377",
            "stark ",
            "STARK",
            "stark/fri",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1",
            "stark/fri/poseidon2-goldilocks",
            "halo2-ipa-orchard",
            "anonymous-pgc",
            "verange",
            "zkat",
            "silent-threshold-anoncred",
            "aztec-plonkish-private-kernel",
            "penumbra-masp",
            "unknown",
            "stark\0",
            "st\u0430rk",
            "halo2\uFF0Fipa",
            "stark\u200B",
        ];

        foreach (var label in labels)
        {
            yield return [label];
        }
    }

    [Theory]
    [InlineData("pipa-r/pasta")]
    [InlineData("pipa-r/pasta/kaigi-authorization-v1")]
    [InlineData("pipa-r/pasta/kaigi-usage-v1")]
    [InlineData("pipa-r/pasta/confidential-transfer-v1")]
    [InlineData("pipa-r/pasta/confidential-unshield-full-v1")]
    [InlineData("pipa-r/pasta/confidential-unshield-change-v1")]
    [InlineData("stark/fri/poseidon-x7-goldilocks-6x64-v1")]
    public void VerifierRegistryAcceptsOnlyPinnedProfiles(string label)
    {
        Assert.True(VerifierBackendRegistryLabels.IsSupportedLabel(label));
        Assert.Equal(label, VerifierBackendRegistryLabels.RequireSupportedLabel(label));
        if (label.StartsWith("pipa-r/", StringComparison.Ordinal))
            Assert.Equal(VerifyingKeyBackendTag.NativePipaRPasta, VerifyingKeyBackendTags.RegistryTag(label));
        Assert.True(VerifyingKeyBackendTags.IsProductionVerifyBackendLabel(label));
        Assert.Equal(VerifyingKeyBackendCatalogTag.Production,
            VerifyingKeyBackendTags.FromCatalogLabel(label));
    }

    [Theory]
    [MemberData(nameof(UnsupportedRegistryLabels))]
    public void VerifierRegistryRejectsAliasesAndRetiredProfiles(string? label)
    {
        Assert.False(VerifierBackendRegistryLabels.IsSupportedLabel(label));
        if (label is "halo2/pasta/ivm-execution-v1"
            or "halo2/pasta/kaigi-roster-v1"
            or "halo2/pasta/kagemusha-v1-mint-fold-merkle16-axiom-poseidon-v1")
        {
            Assert.False(VerifyingKeyBackendTags.IsProductionVerifyBackendLabel(label));
            Assert.Equal(VerifyingKeyBackendCatalogTag.Unsupported,
                VerifyingKeyBackendTags.FromCatalogLabel(label));
        }
        var error = Assert.Throws<ArgumentException>(
            () => VerifierBackendRegistryLabels.RequireSupportedLabel(
                label,
                "registryBackend"));
        Assert.Equal("registryBackend", error.ParamName);
    }

    public static IEnumerable<object?[]> UnsupportedRegistryLabels()
    {
        string?[] labels =
        [
            null,
            "halo2/ipa",
            "halo2/pasta/ivm-execution-v1",
            "halo2/pasta/kaigi-authorization-v1",
            "halo2/pasta/confidential-transfer-2x2-merkle16-axiom-poseidon-v3",
            "halo2/pasta/confidential-unshield-full-merkle16-axiom-poseidon-v3",
            "halo2/pasta/confidential-unshield-change-merkle16-axiom-poseidon-v4",
            "halo2/pasta/kaigi-usage-v1",
            "pipa-r/ipa/pasta/kaigi-authorization-v1",
            "halo2/pasta/kaigi-roster-v1",
            "halo2/pasta/kagemusha-v1-mint-fold-merkle16-axiom-poseidon-v1",
            "",
            " ",
            " halo2/ipa",
            "halo2/ipa ",
            "HALO2/IPA",
            "halo2-ipa-pasta",
            "halo2/pasta",
            "halo2/ipa-pasta-cycle-v1",
            "halo2/pasta/ipa/ivm-replay-binding-v1",
            "halo2/ipa:ivm-replay-binding-v1",
            "halo2/pasta/ivm-execution-v1",
            "halo2/ipa::ivm-replay-binding-v1",
            "halo2/pasta/ivm-overlay-bind",
            "halo2/pasta/kagemusha-v1-invalid-eq",
            "halo2/pasta/kagemusha-v1-invalid-ep",
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
            "stark/fri/poseidon-x7-goldilocks-6x64-v1\0",
            "st\u0430rk/fri",
            "stark\uFF0Ffri",
            "stark/fri/\u200Bsha256-goldilocks",
        ];

        foreach (var label in labels)
        {
            yield return [label];
        }
    }

    [Fact]
    public void ProtocolAndRetiredCatalogAliasesAreUnsupported()
    {
        string[] labels =
        [
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
            "sis-with-hints",
        ];

        foreach (var label in labels)
        {
            Assert.Equal(
                VerifyingKeyBackendCatalogTag.Unsupported,
                VerifyingKeyBackendTags.FromCatalogLabel(label));
            Assert.False(VerifyingKeyBackendTags.IsProductionVerifyBackendLabel(label));
        }
    }

    [Fact]
    public void CatalogClassifierAcceptsOnlyExactProductionLabels()
    {
        foreach (var label in new[]
        {
            "native-pipa-r-pasta",
            "stark",
            "pipa-r/pasta",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1",
        })
        {
            Assert.Equal(
                VerifyingKeyBackendCatalogTag.Production,
                VerifyingKeyBackendTags.FromCatalogLabel(label));
        }
        foreach (var label in new[] { "HALO2/IPA", " halo2/ipa", "halo2/ipa ", "Stark" })
        {
            Assert.Equal(
                VerifyingKeyBackendCatalogTag.Unsupported,
                VerifyingKeyBackendTags.FromCatalogLabel(label));
        }
    }

    [Fact]
    public void AdversarialAliasSplicesStayUnsupported()
    {
        string[] labels =
        [
            "halo2/ipa/orchard/dev-fixture",
            "stark/fri/miden/claimed-production",
            "anonymous-pgc-k-out-of-n-v1-production",
            "sis-hints-anoncred-pq-v0-devfixture",
            "groth16/bls12-377/../../prod",
            "post-quantum-masp/audit-claimed",
        ];

        foreach (var label in labels)
        {
            Assert.Equal(
                VerifyingKeyBackendCatalogTag.Unsupported,
                VerifyingKeyBackendTags.FromCatalogLabel(label));
        }
    }

    [Fact]
    public void ProductionVerifierBackendClassifierRejectsUnsafeLabels()
    {
        var paddedError = Assert.Throws<ArgumentException>(
            () => VerifyingKeyBackendTags.RequireProductionVerifyBackendLabel(
                " halo2/ipa",
                "backend"));
        Assert.Contains("surrounding whitespace", paddedError.Message);

        string[] labels =
        [
            "",
            "unknown/privacy/backend",
            "halo2/unknown-native-v1",
            " halo2/ipa",
            "halo2/ipa ",
            "halo2/ipa\0",
            "HALO2/IPA",
            "stark/FRI",
            "halo2/pasta/ivm-execution-v1",
            "halo2/ipa::ivm-replay-binding-v1",
            "stark/fri/sha256..goldilocks",
            "halo2\uFF0Fipa",
            "halo2/\u200Bipa",
            "h\u0430lo2/ipa",
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
            "halo2/ipa:anon-transfer-2x2-merkle16",
        ];

        foreach (var label in labels)
        {
            Assert.False(
                VerifyingKeyBackendTags.IsProductionVerifyBackendLabel(label),
                label);
            Assert.Throws<ArgumentException>(
                () => VerifyingKeyBackendTags.RequireProductionVerifyBackendLabel(label));
        }
    }
}
