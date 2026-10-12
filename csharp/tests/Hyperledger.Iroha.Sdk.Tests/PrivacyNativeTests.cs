using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Hyperledger.Iroha.Privacy;

namespace Hyperledger.Iroha.Sdk.Tests;

public sealed class PrivacyNativeTests
{
    private static readonly IReadOnlyList<string[]> Matrix = LoadExact12Matrix();
    private static readonly IReadOnlyList<string[]> ProtocolRows = Rows("protocol");
    private static readonly IReadOnlyList<string[]> TypedEnvelopeRows = Rows("typed-envelope");
    private static readonly string[] Expected = ProtocolRows.Select(row => row[2]).ToArray();

    [Fact]
    public void ExactClosedRegistryIsStable()
    {
        Assert.Equal(27U, PrivacyNative.RequiredBridgeAbiVersion);
        Assert.Equal(typeof(uint), Enum.GetUnderlyingType(typeof(PrivacyProtocolIdV1)));
        Assert.Equal(12, PrivacyProtocolsV1.All.Count);
        Assert.Equal(Expected, PrivacyProtocolsV1.All.Select(value => value.CanonicalLabel()));
        for (var index = 0; index < Expected.Length; index++)
        {
            var protocol = PrivacyProtocolsV1.All[index];
            var typedVariant = ProtocolRows[index][3];
            Assert.Equal((uint)index, Convert.ToUInt32(protocol, CultureInfo.InvariantCulture));
            Assert.Equal(
                protocol,
                PrivacyProtocolsV1.ParseCanonicalLabel(Expected[index]));
            Assert.Equal(typedVariant, protocol.CanonicalTypedVariantLabel());
            Assert.Equal(
                protocol,
                PrivacyProtocolsV1.ParseCanonicalTypedVariantLabel(typedVariant));
        }
    }

    [Fact]
    public void SharedExact12MatrixBindsRoutesAndTypedEnvelopeDigests()
    {
        Assert.True(
            new HashSet<string>(
                new[] { "matrix-version", "registry-sha256", "protocol", "typed-envelope" },
                StringComparer.Ordinal).SetEquals(Matrix.Select(row => row[0])));
        Assert.Equal(new[] { new[] { "matrix-version", "1" } }, Rows("matrix-version"));
        Assert.Equal(
            Enumerable.Range(0, 12).Select(index => index.ToString(CultureInfo.InvariantCulture)),
            ProtocolRows.Select(row => row[1]));
        Assert.Equal(12, Expected.Distinct(StringComparer.Ordinal).Count());
        var registryPreimage = string.Concat(Expected.Select(value => $"{value}\n"));
        var registryDigest = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(registryPreimage))).ToLowerInvariant();
        Assert.Equal(
            new[] { new[] { "registry-sha256", registryDigest } },
            Rows("registry-sha256"));
        Assert.Equal(
            ProtocolRows.Select(row => row[2..5]),
            TypedEnvelopeRows.Select(row => row[1..4]));
        Assert.Equal(
            ProtocolRows.Select(row => row[3]),
            PrivacyProtocolsV1.All.Select(value => value.CanonicalTypedVariantLabel()));
        Assert.Equal(
            ProtocolRows.Select(row => row[4]),
            PrivacyProtocolsV1.All.Select(value => value.CanonicalTypedVariantLabel()));
        Assert.Equal(12, TypedEnvelopeRows.Count);
        foreach (var row in TypedEnvelopeRows)
        {
            Assert.Equal(6, row.Length);
            foreach (var digest in row[4..])
            {
                Assert.Matches("^[0-9a-f]{64}$", digest);
                Assert.NotEqual(new string('0', 64), digest);
            }
        }
        Assert.Empty(Rows("retired"));
    }

    [Theory]
    [InlineData("jindo-lattice-pcs-zk-v0")]
    [InlineData("sis-hints-anoncred-pq-v0")]
    [InlineData("sis-with-hints")]
    [InlineData("silent-threshold-anoncred-v0")]
    [InlineData("zk-ams-recursive-admission-v0")]
    [InlineData("iroha-zk-ams-v1 ")]
    [InlineData("Iroha-Zk-Ams-V1")]
    [InlineData("")]
    [InlineData("unknown-privacy-protocol-v1")]
    public void AliasesAndNonCanonicalSpellingsAreRejected(string rejected)
    {
        Assert.Throws<ArgumentException>(
            () => PrivacyProtocolsV1.ParseCanonicalLabel(rejected));
    }

    [Theory]
    [InlineData("JindoLatticePcsZkV0")]
    [InlineData("SisHintsAnoncredPqV0")]
    [InlineData("SisWithHints")]
    [InlineData("ZkAmsRecursiveAdmissionV0")]
    [InlineData("VegaExistingCredentialZk")]
    [InlineData("IrohaZkAmsV1 ")]
    [InlineData("irohaZkAmsV1")]
    [InlineData("")]
    [InlineData("UnknownPrivacyProtocolV1")]
    public void LegacyAndNonCanonicalTypedVariantsAreRejected(string rejected)
    {
        Assert.Throws<ArgumentException>(
            () => PrivacyProtocolsV1.ParseCanonicalTypedVariantLabel(rejected));
    }

    [Fact]
    public void NullLabelsAndUnknownUnsignedTagsAreRejected()
    {
        Assert.Throws<ArgumentNullException>(
            () => PrivacyProtocolsV1.ParseCanonicalLabel(null!));
        Assert.Throws<ArgumentNullException>(
            () => PrivacyProtocolsV1.ParseCanonicalTypedVariantLabel(null!));

        foreach (var tag in new[] { 12U, uint.MaxValue })
        {
            var protocol = (PrivacyProtocolIdV1)tag;
            Assert.False(Enum.IsDefined(protocol));
            Assert.Throws<ArgumentOutOfRangeException>(() => protocol.CanonicalLabel());
            Assert.Throws<ArgumentOutOfRangeException>(
                () => protocol.CanonicalTypedVariantLabel());
        }
    }

    [Fact]
    public void RetiredProtocolsAreNotPartOfTheFirstReleaseMatrix()
    {
        foreach (var retired in new[]
        {
            "jindo-lattice-pcs-zk-v0",
            "sis-hints-anoncred-pq-v0",
            "sis-with-hints",
            "silent-threshold-anoncred-v0",
            "zk-ams-recursive-admission-v0",
        })
        {
            Assert.Throws<ArgumentException>(
                () => PrivacyProtocolsV1.ParseCanonicalLabel(retired));
        }
    }

    [Fact]
    public void SharedTypedValidatorStatusContractIsStable()
    {
        Assert.Equal(
            256 * 1024,
            PrivacyNative.PrivacyCompiledProfileCatalogArchiveMaxBytes);
        Assert.Equal(
            2 * 1024 * 1024,
            PrivacyNative.PrivacyExact12FixtureBundleMaxBytes);
        Assert.Equal(
            Enumerable.Range(0, 9),
            Enum.GetValues<PrivacyCompiledProfileCatalogValidationStatusV1>()
                .Select(value => (int)value));
        Assert.Equal(
            Enumerable.Range(0, 9),
            Enum.GetValues<PrivacyExact12FixtureValidationStatusV1>()
                .Select(value => (int)value));
        Assert.Empty(
            typeof(PrivacyCompiledProfileCatalogArchive).GetConstructors(
                BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(
            typeof(PrivacyExact12FixtureBundleArchive).GetConstructors(
                BindingFlags.Public | BindingFlags.Instance));
        var validator = typeof(PrivacyNative).GetMethod(
            "NativeValidateCompiledProfileCatalog",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(validator);
        Assert.NotNull(validator!.GetCustomAttribute<System.Runtime.InteropServices.DllImportAttribute>());
        Assert.Equal(
            "iroha_privacy_validate_compiled_profile_catalog_v1",
            validator.GetCustomAttribute<System.Runtime.InteropServices.DllImportAttribute>()!
                .EntryPoint);
        var capabilityValidator = typeof(PrivacyNative).GetMethod(
            "NativeValidateExact12CapabilityManifest",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(capabilityValidator);
        Assert.Equal(
            "iroha_privacy_validate_exact12_capability_manifest_v1",
            capabilityValidator!.GetCustomAttribute<System.Runtime.InteropServices.DllImportAttribute>()!
                .EntryPoint);
        var fixtureQuery = typeof(PrivacyNative).GetMethod(
            "NativeExact12FixtureBundle",
            BindingFlags.NonPublic | BindingFlags.Static);
        var fixtureValidator = typeof(PrivacyNative).GetMethod(
            "NativeValidateExact12FixtureBundle",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.Equal(
            "iroha_privacy_exact12_fixture_bundle_v1",
            fixtureQuery!
                .GetCustomAttribute<System.Runtime.InteropServices.DllImportAttribute>()!
                .EntryPoint);
        Assert.Equal(
            "iroha_privacy_validate_exact12_fixture_bundle_v1",
            fixtureValidator!
                .GetCustomAttribute<System.Runtime.InteropServices.DllImportAttribute>()!
                .EntryPoint);
    }

    [Fact]
    public void CompiledProfileCatalogPreflightRejectsNullEmptyAndOversizeWithoutNativeCalls()
    {
        Assert.Throws<ArgumentNullException>(
            () => PrivacyNative.ValidateCompiledProfileCatalogV1(null!));
        Assert.Equal(
            PrivacyCompiledProfileCatalogValidationStatusV1.Empty,
            PrivacyNative.ValidateCompiledProfileCatalogV1(Array.Empty<byte>()));
        Assert.Equal(
            PrivacyCompiledProfileCatalogValidationStatusV1.ArchiveTooLarge,
            PrivacyNative.ValidateCompiledProfileCatalogV1(
                new byte[PrivacyNative.PrivacyCompiledProfileCatalogArchiveMaxBytes + 1]));
    }

    [Fact]
    public void CompiledProfileCatalogRoundTripsAndRejectsAdversarialBytesThroughNativeAbi24()
    {
        Assert.True(
            PrivacyNative.IsAvailable(),
            "ABI-29 connect_norito_bridge with compiled-profile catalog symbols is required.");

        var catalog = PrivacyNative.CompiledProfileCatalogV1();
        var canonical = catalog.NoritoBytes;
        Assert.InRange(
            canonical.Length,
            1,
            PrivacyNative.PrivacyCompiledProfileCatalogArchiveMaxBytes);
        Assert.Equal(
            PrivacyCompiledProfileCatalogValidationStatusV1.Valid,
            PrivacyNative.ValidateCompiledProfileCatalogV1(canonical));
        Assert.Equal(
            canonical,
            PrivacyNative.CompiledProfileCatalogV1().NoritoBytes);

        foreach (var truncated in new[]
        {
            canonical[..^1],
            canonical[1..],
            canonical[..(canonical.Length / 2)],
        })
        {
            Assert.NotEqual(
                PrivacyCompiledProfileCatalogValidationStatusV1.Valid,
                PrivacyNative.ValidateCompiledProfileCatalogV1(truncated));
        }
        var trailing = canonical.Concat(new byte[] { 0 }).ToArray();
        Assert.NotEqual(
            PrivacyCompiledProfileCatalogValidationStatusV1.Valid,
            PrivacyNative.ValidateCompiledProfileCatalogV1(trailing));
        foreach (var index in new[] { 0, canonical.Length / 2, canonical.Length - 1 }
                     .Distinct())
        {
            var mutated = (byte[])canonical.Clone();
            mutated[index] ^= 0x80;
            Assert.NotEqual(
                PrivacyCompiledProfileCatalogValidationStatusV1.Valid,
                PrivacyNative.ValidateCompiledProfileCatalogV1(mutated));
        }
    }

    [Fact]
    public void Exact12FixturePreflightRejectsNullEmptyAndOversizeWithoutNativeCalls()
    {
        Assert.Throws<ArgumentNullException>(
            () => PrivacyNative.ValidateExact12FixtureBundleV1(null!));
        Assert.Equal(
            PrivacyExact12FixtureValidationStatusV1.Empty,
            PrivacyNative.ValidateExact12FixtureBundleV1(Array.Empty<byte>()));
        Assert.Equal(
            PrivacyExact12FixtureValidationStatusV1.ArchiveTooLarge,
            PrivacyNative.ValidateExact12FixtureBundleV1(
                new byte[PrivacyNative.PrivacyExact12FixtureBundleMaxBytes + 1]));
    }

    [Fact]
    public void Exact12FixtureBundleRoundTripsAndRejectsAdversarialBytesThroughNativeAbi24()
    {
        Assert.True(
            PrivacyNative.IsAvailable(),
            "ABI-29 connect_norito_bridge with exact-12 fixture symbols is required.");

        var bundle = PrivacyNative.Exact12FixtureBundleV1();
        var canonical = bundle.NoritoBytes;
        Assert.InRange(
            canonical.Length,
            1,
            PrivacyNative.PrivacyExact12FixtureBundleMaxBytes);
        Assert.Equal(
            PrivacyExact12FixtureValidationStatusV1.Valid,
            PrivacyNative.ValidateExact12FixtureBundleV1(canonical));
        Assert.Equal(
            canonical,
            PrivacyNative.Exact12FixtureBundleV1().NoritoBytes);

        var returnedCopy = bundle.NoritoBytes;
        returnedCopy[0] ^= 0xff;
        Assert.Equal(canonical, bundle.NoritoBytes);

        foreach (var truncated in new[]
        {
            canonical[..^1],
            canonical[1..],
            canonical[..(canonical.Length / 2)],
        })
        {
            Assert.NotEqual(
                PrivacyExact12FixtureValidationStatusV1.Valid,
                PrivacyNative.ValidateExact12FixtureBundleV1(truncated));
        }

        var trailing = canonical.Concat(new byte[] { 0 }).ToArray();
        Assert.NotEqual(
            PrivacyExact12FixtureValidationStatusV1.Valid,
            PrivacyNative.ValidateExact12FixtureBundleV1(trailing));

        foreach (var index in new[] { 0, canonical.Length / 2, canonical.Length - 1 }
                     .Distinct())
        {
            var mutated = (byte[])canonical.Clone();
            mutated[index] ^= 0x80;
            Assert.NotEqual(
                PrivacyExact12FixtureValidationStatusV1.Valid,
                PrivacyNative.ValidateExact12FixtureBundleV1(mutated));
        }

        var crossSchemaArchive = PrivacyNative.CompiledProfileCatalogV1().NoritoBytes;
        Assert.NotEqual(
            PrivacyExact12FixtureValidationStatusV1.Valid,
            PrivacyNative.ValidateExact12FixtureBundleV1(crossSchemaArchive));
    }

    [Fact]
    public async Task NativeArchivesRoundTripOnOrdinaryThreadPoolWorkers()
    {
        await Task.Run(() =>
        {
            Assert.True(Thread.CurrentThread.IsThreadPoolThread);
            Assert.True(PrivacyNative.IsAvailable());
            var catalog = PrivacyNative.CompiledProfileCatalogV1().NoritoBytes;
            var fixture = PrivacyNative.Exact12FixtureBundleV1().NoritoBytes;
            Assert.Equal(
                PrivacyCompiledProfileCatalogValidationStatusV1.Valid,
                PrivacyNative.ValidateCompiledProfileCatalogV1(catalog));
            Assert.Equal(
                PrivacyExact12FixtureValidationStatusV1.Valid,
                PrivacyNative.ValidateExact12FixtureBundleV1(fixture));
            Assert.NotEqual(
                PrivacyExact12FixtureValidationStatusV1.Valid,
                PrivacyNative.ValidateExact12FixtureBundleV1([.. fixture, 0]));
            Assert.NotEqual(
                PrivacyExact12CapabilityManifestValidationStatusV1.Valid,
                PrivacyNative.ValidateExact12CapabilityManifestV1(fixture));
        }, TestContext.Current.CancellationToken);
    }

    [Fact]
    public void RetiredGenericProofAndCapabilitySurfacesAreAbsent()
    {
        var privacyType = typeof(PrivacyNative);
        var names = privacyType
            .GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Select(method => method.Name)
            .ToArray();
        Assert.DoesNotContain(names, name => name.Contains("ProofRequest", StringComparison.Ordinal));
        Assert.DoesNotContain(names, name => name.Contains("BuildProof", StringComparison.Ordinal));
        Assert.DoesNotContain(names, name => name.Contains("VerifyProof", StringComparison.Ordinal));
        Assert.DoesNotContain("CapabilitiesV1", names);
        Assert.DoesNotContain("ValidateCapabilitiesV1", names);
        Assert.DoesNotContain("GetPrivacyCapabilities", names);

        var publicFieldNames = privacyType
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Select(field => field.Name)
            .ToArray();
        foreach (var retiredField in new[]
                 {
                     "FfiVersionV1",
                     "ProductionGateVersion",
                     "StatusError",
                     "ErrorUnsupportedAlgorithm",
                     "ErrorProductionDisabled",
                     "PrivacyNativeArchiveMaxBytes",
                 })
        {
            Assert.DoesNotContain(retiredField, publicFieldNames);
        }

        var assembly = privacyType.Assembly;
        foreach (var retiredType in new[]
                 {
                     "PrivacyCapabilitiesArchive",
                     "PrivacyProofResultArchive",
                     "PrivacyProofRequestArchive",
                     "PrivacyCapabilities",
                     "PrivacyProductionGate",
                     "PrivacyCapabilityValidationStatusV1",
                 })
        {
            Assert.Null(assembly.GetType($"Hyperledger.Iroha.Privacy.{retiredType}"));
        }
    }

    private static IReadOnlyList<string[]> Rows(string kind)
    {
        return Matrix.Where(row => row[0] == kind).ToArray();
    }

    private static IReadOnlyList<string[]> LoadExact12Matrix()
    {
        var directory = new DirectoryInfo(Directory.GetCurrentDirectory());
        FileInfo? fixture = null;
        while (directory is not null)
        {
            var candidate = new FileInfo(
                Path.Combine(directory.FullName, "fixtures", "privacy", "exact12_v1.tsv"));
            if (candidate.Exists)
            {
                fixture = candidate;
                break;
            }
            directory = directory.Parent;
        }
        if (fixture is null)
        {
            throw new InvalidOperationException("cannot locate fixtures/privacy/exact12_v1.tsv");
        }
        var text = File.ReadAllText(fixture.FullName, Encoding.UTF8);
        if (!text.EndsWith('\n') || text.Contains('\r'))
        {
            throw new InvalidOperationException("exact12 fixture is not canonical LF text");
        }
        if (text[..^1].Split('\n', StringSplitOptions.None).Any(string.IsNullOrEmpty))
        {
            throw new InvalidOperationException("exact12 fixture contains an empty row");
        }
        return text
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Where(line => !line.StartsWith('#'))
            .Select(line => line.Split('\t'))
            .ToArray();
    }
}
