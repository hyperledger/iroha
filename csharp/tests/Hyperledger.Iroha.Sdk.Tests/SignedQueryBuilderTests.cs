using System.Buffers.Binary;
using System.Text;
using Hyperledger.Iroha.Crypto;
using Hyperledger.Iroha.Norito;
using Hyperledger.Iroha.Queries;

namespace Hyperledger.Iroha.Sdk.Tests;

public sealed class SignedQueryBuilderTests
{
    private const string FixtureSeedHex = "616e64726f69642d666978747572652d7369676e696e672d6b65792d30313032";
    private const string FixtureAccountId = "sorauﾛ1NｲﾘｳdPBeｼRoｸQ2ﾔgｼQqeｶﾍｽﾁhRW2ｺｿZ9ﾕｦUﾅRX5NJYH53";
    private const string FixtureNetworkIdLiteral = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0";
    private const string AlternateNetworkIdLiteral = "hash:82531CE8EAE8BFF6BEECA4698BFD13A3BC8BEC5F0EE0D23D428C97FC17AB0F3B#3E94";
    private const string FixtureAssetDefinitionId = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
    private const string FixtureContractCodeHash = "00112233445566778899aabbccddeeff00112233445566778899aabbccddee01";
    private const string FixtureProofHash = "0x111122223333444455556666777788889999AAAABBBBCCCCDDDDEEEEFFFF0000";
    private const string FixtureTwitterDigest = "0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDE0";
    private const string FixtureStorageTicket = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string FixtureManifestDigest = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    private const string FixtureProviderId = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    private static readonly NetworkId FixtureNetworkId = NetworkId.Parse(FixtureNetworkIdLiteral);
    private static readonly NetworkId AlternateNetworkId = NetworkId.Parse(AlternateNetworkIdLiteral);

    [Fact]
    public void BuildSignedEncodesFindParametersQuery()
    {
        var envelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindParameters()
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));

        Assert.Equal(1, envelope.VersionedNoritoBytes[0]);

        var (singularDiscriminant, singularPayload) = ReadSingularQuery(envelope);
        Assert.Equal(1u, singularDiscriminant);
        Assert.Empty(ReadField(singularPayload, out _));

        AssertSignatureVerifies(envelope);
    }

    [Fact]
    public void BuildSignedEncodesFindAbiVersionQuery()
    {
        var envelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindAbiVersion()
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));

        var (singularDiscriminant, singularPayload) = ReadSingularQuery(envelope);
        Assert.Equal(8u, singularDiscriminant);
        Assert.Empty(ReadField(singularPayload, out _));

        AssertSignatureVerifies(envelope);
    }

    [Fact]
    public void BuildSignedEncodesFindExecutorDataModelQuery()
    {
        var envelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindExecutorDataModel()
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));

        var (singularDiscriminant, singularPayload) = ReadSingularQuery(envelope);
        Assert.Equal(0u, singularDiscriminant);
        Assert.Empty(ReadField(singularPayload, out _));

        AssertSignatureVerifies(envelope);
    }

    [Fact]
    public void SignedQueryEnvelopeDefensivelyCopiesBytes()
    {
        var envelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindParameters()
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));

        var expectedVersionedNoritoBytes = envelope.VersionedNoritoBytes;
        var expectedSignedQueryBytes = envelope.SignedQueryBytes;
        var expectedPayloadBytes = envelope.PayloadBytes;
        var expectedSignatureBytes = envelope.SignatureBytes;

        MutateFirstByte(envelope.VersionedNoritoBytes);
        MutateFirstByte(envelope.SignedQueryBytes);
        MutateFirstByte(envelope.PayloadBytes);
        MutateFirstByte(envelope.SignatureBytes);

        Assert.Equal(expectedVersionedNoritoBytes, envelope.VersionedNoritoBytes);
        Assert.Equal(expectedSignedQueryBytes, envelope.SignedQueryBytes);
        Assert.Equal(expectedPayloadBytes, envelope.PayloadBytes);
        Assert.Equal(expectedSignatureBytes, envelope.SignatureBytes);
        AssertSignatureVerifies(envelope);

        var constructorPayloadBytes = new byte[] { 0x07, 0x08, 0x09 };
        var constructorSignatureBytes = Enumerable
            .Range(0, Ed25519Signer.SignatureLength)
            .Select(index => (byte)(0x0a + index))
            .ToArray();
        var constructorSignedQueryBytes = BuildSignedQueryBytes(constructorSignatureBytes, constructorPayloadBytes);
        var constructorVersionedNoritoBytes = VersionSignedQueryBytes(constructorSignedQueryBytes);
        var expectedConstructorSignedQueryBytes = constructorSignedQueryBytes.ToArray();
        var expectedConstructorVersionedNoritoBytes = constructorVersionedNoritoBytes.ToArray();
        var expectedConstructorPayloadBytes = constructorPayloadBytes.ToArray();
        var expectedConstructorSignatureBytes = constructorSignatureBytes.ToArray();
        var direct = new SignedQueryEnvelope(
            constructorVersionedNoritoBytes,
            constructorSignedQueryBytes,
            constructorPayloadBytes,
            constructorSignatureBytes);

        MutateFirstByte(constructorVersionedNoritoBytes);
        MutateFirstByte(constructorSignedQueryBytes);
        MutateFirstByte(constructorPayloadBytes);
        MutateFirstByte(constructorSignatureBytes);
        MutateFirstByte(direct.VersionedNoritoBytes);
        MutateFirstByte(direct.SignedQueryBytes);
        MutateFirstByte(direct.PayloadBytes);
        MutateFirstByte(direct.SignatureBytes);

        Assert.Equal(expectedConstructorVersionedNoritoBytes, direct.VersionedNoritoBytes);
        Assert.Equal(expectedConstructorSignedQueryBytes, direct.SignedQueryBytes);
        Assert.Equal(expectedConstructorPayloadBytes, direct.PayloadBytes);
        Assert.Equal(expectedConstructorSignatureBytes, direct.SignatureBytes);

        static void MutateFirstByte(byte[] value)
        {
            Assert.NotEmpty(value);
            value[0] ^= 0xff;
        }
    }

    [Fact]
    public void SignedQueryEnvelopeRejectsMalformedConstructorBytes()
    {
        var payloadBytes = new byte[] { 0x07 };
        var signatureBytes = Enumerable.Repeat((byte)0x08, Ed25519Signer.SignatureLength).ToArray();
        var signedQueryBytes = BuildSignedQueryBytes(signatureBytes, payloadBytes);
        var versionedNoritoBytes = VersionSignedQueryBytes(signedQueryBytes);
        var malformedSignedQueryBytes = new byte[] { 0x04, 0x05, 0x06 };

        AssertArgumentException(
            "versionedNoritoBytes",
            () => new SignedQueryEnvelope([], signedQueryBytes, payloadBytes, signatureBytes));
        AssertArgumentException(
            "signedQueryBytes",
            () => new SignedQueryEnvelope([0x01], [], payloadBytes, signatureBytes));
        AssertArgumentException(
            "payloadBytes",
            () => new SignedQueryEnvelope(versionedNoritoBytes, signedQueryBytes, [], signatureBytes));
        AssertArgumentException(
            "signatureBytes",
            () => new SignedQueryEnvelope(versionedNoritoBytes, signedQueryBytes, payloadBytes, signatureBytes[..^1]));
        AssertArgumentException(
            "versionedNoritoBytes",
            () => new SignedQueryEnvelope([0x02, 0x04, 0x05, 0x06], signedQueryBytes, payloadBytes, signatureBytes));
        AssertArgumentException(
            "versionedNoritoBytes",
            () => new SignedQueryEnvelope([0x01, 0x04, 0xff, 0x06], signedQueryBytes, payloadBytes, signatureBytes));
        AssertArgumentException(
            "signedQueryBytes",
            () => new SignedQueryEnvelope(
                VersionSignedQueryBytes(malformedSignedQueryBytes),
                malformedSignedQueryBytes,
                payloadBytes,
                signatureBytes));
        AssertArgumentException(
            "payloadBytes",
            () => new SignedQueryEnvelope(versionedNoritoBytes, signedQueryBytes, [0x08], signatureBytes));
        AssertArgumentException(
            "signatureBytes",
            () =>
            {
                var mismatchedSignatureBytes = signatureBytes.ToArray();
                mismatchedSignatureBytes[0] ^= 0xff;
                _ = new SignedQueryEnvelope(
                    versionedNoritoBytes,
                    signedQueryBytes,
                    payloadBytes,
                    mismatchedSignatureBytes);
            });
        AssertArgumentException(
            "signedQueryBytes",
            () =>
            {
                var withTrailingField = signedQueryBytes.Concat(new byte[8]).ToArray();
                _ = new SignedQueryEnvelope(
                    VersionSignedQueryBytes(withTrailingField),
                    withTrailingField,
                    payloadBytes,
                    signatureBytes);
            });
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(" sorauﾛ1NｲﾘｳdPBeｼRoｸQ2ﾔgｼQqeｶﾍｽﾁhRW2ｺｿZ9ﾕｦUﾅRX5NJYH53")]
    [InlineData("sorauﾛ1NｲﾘｳdPBeｼRoｸQ2ﾔgｼQqeｶﾍｽﾁhRW2ｺｿZ9ﾕｦUﾅRX5NJYH53 ")]
    [InlineData("sorauﾛ1N\u0000ｲﾘｳdPBeｼRoｸQ2ﾔgｼQqeｶﾍｽﾁhRW2ｺｿZ9ﾕｦUﾅRX5NJYH53")]
    [InlineData("merchant@sora")]
    [InlineData("0x0a00012022d3c25e96fa1178ae08b3d30081a31a0d09e8f7321b1e015140cd37b332109ca")]
    [InlineData("n753uﾛ1NｲﾘｳdPBeｼRoｸQ2ﾔgｼQqeｶﾍｽﾁhRW2ｺｿZ9ﾕｦUﾅRX5NJYH53")]
    public void ConstructorRejectsNonExactAuthority(string authorityAccountId)
    {
        Assert.Throws<ArgumentException>(() => new SignedQueryBuilder(authorityAccountId, FixtureNetworkId));
    }

    [Fact]
    public void ConstructorRejectsInternalWhitespaceAuthority()
    {
        AssertArgumentException(
            "authorityAccountId",
            () => new SignedQueryBuilder(FixtureAccountId.Insert(8, " "), FixtureNetworkId));
    }

    [Fact]
    public void ConstructorRequiresNominalNetworkId()
    {
        Assert.Throws<ArgumentNullException>(
            () => new SignedQueryBuilder(FixtureAccountId, null!));
        Assert.Throws<FormatException>(() => NetworkId.Parse("chain/dev"));
        Assert.Throws<FormatException>(() => NetworkId.Parse("genesis"));
        Assert.Throws<FormatException>(() => NetworkId.Parse(""));
    }

    [Fact]
    public void SignedQueryBuildersExposeNoRawStringNetworkIdentityOverload()
    {
        foreach (var builderType in new[]
                 {
                     typeof(SignedQueryBuilder),
                     typeof(SignedIterableQueryBuilder),
                 })
        {
            var constructor = Assert.Single(builderType.GetConstructors());
            var parameters = constructor.GetParameters();
            Assert.Equal(2, parameters.Length);
            Assert.Equal(typeof(NetworkId), parameters[1].ParameterType);
            Assert.Equal(typeof(NetworkId), builderType.GetProperty("NetworkId")!.PropertyType);
        }
    }

    [Fact]
    public void BuildSignedRejectsInvalidReplayContext()
    {
        var seed = Convert.FromHexString(FixtureSeedHex);
        var builder = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindParameters();

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            builder.BuildSigned(seed, 1_000, 0, Enumerable.Repeat((byte)0x5A, 32).ToArray()));
        AssertArgumentException(
            "nonce",
            () => builder.BuildSigned(seed, 1_000, 10_000, new byte[32]));
        AssertArgumentException(
            "nonce",
            () => builder.BuildSigned(seed, 1_000, 10_000, new byte[31]));
    }

    [Fact]
    public void NetworkIdentityIsBoundIntoPayloadAndSignature()
    {
        var seed = Convert.FromHexString(FixtureSeedHex);
        var nonce = Enumerable.Repeat((byte)0x5A, 32).ToArray();
        var first = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindParameters()
            .BuildSigned(seed, 1_000, 10_000, nonce);
        var second = new SignedQueryBuilder(FixtureAccountId, AlternateNetworkId)
            .FindParameters()
            .BuildSigned(seed, 1_000, 10_000, nonce);

        Assert.False(first.PayloadBytes.SequenceEqual(second.PayloadBytes));
        Assert.False(first.SignatureBytes.SequenceEqual(second.SignatureBytes));
        AssertSignatureVerifies(first);
        AssertSignatureVerifies(second);
    }

    [Fact]
    public void QueryOperandSettersRejectNonExactRequiredValues()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindAliasesByAccountId(" " + FixtureAccountId);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindAliasesByAccountId("merchant@sora");
        });
        Assert.Throws<ArgumentException>(() =>
        {
            new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindAssetById(" " + FixtureAssetDefinitionId, FixtureAccountId);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindAssetById(
                FixtureAssetDefinitionId,
                "n753uﾛ1NｲﾘｳdPBeｼRoｸQ2ﾔgｼQqeｶﾍｽﾁhRW2ｺｿZ9ﾕｦUﾅRX5NJYH53");
        });
        Assert.Throws<ArgumentException>(() =>
        {
            new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindAssetById(
                FixtureAssetDefinitionId,
                "0x0a00012022d3c25e96fa1178ae08b3d30081a31a0d09e8f7321b1e015140cd37b332109ca");
        });
        Assert.Throws<ArgumentException>(() =>
        {
            new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindDomainEndorsements("banka ");
        });
        Assert.Throws<ArgumentException>(() =>
        {
            new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindDomainCommittee("committee-7\u0000");
        });
        Assert.Throws<ArgumentException>(() =>
        {
            new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindDaPinIntentByAlias(" manifest-root");
        });
        Assert.Throws<ArgumentException>(() =>
        {
            new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindDaPinIntentByTicket(FixtureStorageTicket + " ");
        });
    }

    [Fact]
    public void QueryOperandSettersRejectInternalWhitespaceBeforeBuild()
    {
        AssertArgumentException(
            "accountId",
            () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindAliasesByAccountId(FixtureAccountId.Insert(8, " ")));
        AssertArgumentException(
            "assetDefinitionId",
            () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindAssetById("asset def", FixtureAccountId));
        AssertArgumentException(
            "accountId",
            () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindAssetById(
                FixtureAssetDefinitionId,
                FixtureAccountId.Insert(8, "\t")));
        AssertArgumentException(
            "codeHash",
            () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindContractManifestByArtifactId(
                new ContractArtifactId(ulong.MaxValue, FixtureContractCodeHash.Insert(10, " "))));
        AssertArgumentException(
            "pepperId",
            () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindTwitterBindingByHash("pepper v1", FixtureTwitterDigest));
        AssertArgumentException(
            "digestHex",
            () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindTwitterBindingByHash(
                "pepper-v1",
                FixtureTwitterDigest.Insert(10, " ")));
        AssertArgumentException(
            "domainId",
            () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindDomainEndorsements("ban ka"));
        AssertArgumentException(
            "domainId",
            () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindDomainEndorsementPolicy("ban ka"));
        AssertArgumentException(
            "committeeId",
            () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindDomainCommittee("committee 7"));
        AssertArgumentException(
            "storageTicket",
            () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindDaPinIntentByTicket(FixtureStorageTicket.Insert(12, " ")));
        AssertArgumentException(
            "manifestDigest",
            () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindDaPinIntentByManifest(
                FixtureManifestDigest.Insert(12, "\u00A0")));
        AssertArgumentException(
            "alias",
            () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindDaPinIntentByAlias("manifest root"));
        AssertArgumentException(
            "providerId",
            () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindSorafsProviderOwner(FixtureProviderId.Insert(12, " ")));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(" paynet")]
    [InlineData("paynet ")]
    [InlineData("pay net")]
    [InlineData("pay\u00A0net")]
    [InlineData("pay\u0000net")]
    public void FindAliasesByAccountIdRejectsNonExactOptionalFilters(string filter)
    {
        AssertArgumentException("dataspace", () =>
        {
            new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindAliasesByAccountId(
                FixtureAccountId,
                dataspace: filter);
        });
        AssertArgumentException("domain", () =>
        {
            new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindAliasesByAccountId(
                FixtureAccountId,
                domain: filter);
        });
    }

    [Fact]
    public void BuildSignedEncodesFindAliasesByAccountIdWithFilters()
    {
        var envelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindAliasesByAccountId(FixtureAccountId, dataspace: "paynet", domain: "banka")
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));

        var (singularDiscriminant, singularPayload) = ReadSingularQuery(envelope);
        Assert.Equal(3u, singularDiscriminant);

        var structPayload = ReadField(singularPayload, out _);
        _ = ReadField(structPayload, out var offsetAfterAccountId);
        var dataspaceOption = ReadField(structPayload[offsetAfterAccountId..], out var offsetAfterDataspace);
        var domainOption = ReadField(structPayload[(offsetAfterAccountId + offsetAfterDataspace)..], out _);

        Assert.Equal("paynet", ReadOptionalString(dataspaceOption));
        Assert.Equal("banka", ReadOptionalString(domainOption));

        AssertSignatureVerifies(envelope);
    }

    [Fact]
    public void BuildSignedEncodesAssetLookupQueries()
    {
        var assetEnvelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindAssetById(FixtureAssetDefinitionId, FixtureAccountId, dataspaceId: 9)
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));

        var (assetDiscriminant, assetPayload) = ReadSingularQuery(assetEnvelope);
        Assert.Equal(9u, assetDiscriminant);

        var assetStruct = ReadField(assetPayload, out _);
        var assetId = ReadField(assetStruct, out _);
        _ = ReadField(assetId, out var offsetAfterAccountId);
        _ = ReadField(assetId[offsetAfterAccountId..], out var offsetAfterDefinitionId);
        var scopeBytes = ReadField(assetId[(offsetAfterAccountId + offsetAfterDefinitionId)..], out _);
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(scopeBytes[..4]));
        var dataspacePayload = ReadField(scopeBytes[4..], out _);
        Assert.Equal(9ul, BinaryPrimitives.ReadUInt64LittleEndian(ReadField(dataspacePayload, out _)));

        var definitionEnvelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindAssetDefinitionById(FixtureAssetDefinitionId)
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));

        var (definitionDiscriminant, definitionPayload) = ReadSingularQuery(definitionEnvelope);
        Assert.Equal(10u, definitionDiscriminant);
        var definitionStruct = ReadField(definitionPayload, out _);
        var definitionIdBytes = ReadField(definitionStruct, out _);
        AssertCanonicalAssetDefinitionId(definitionIdBytes);

        AssertSignatureVerifies(assetEnvelope);
        AssertSignatureVerifies(definitionEnvelope);
    }

    [Fact]
    public void BuildSignedEncodesContractManifestAndDataspaceOwnerQueries()
    {
        var manifestEnvelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindContractManifestByArtifactId(new ContractArtifactId(ulong.MaxValue, FixtureContractCodeHash))
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));

        var (manifestDiscriminant, manifestPayload) = ReadSingularQuery(manifestEnvelope);
        Assert.Equal(7u, manifestDiscriminant);
        var manifestStruct = ReadField(manifestPayload, out _);
        var artifactStruct = ReadField(manifestStruct, out _);
        var artifactScope = ReadField(artifactStruct, out var scopeEnd);
        Assert.Equal(ulong.MaxValue, BinaryPrimitives.ReadUInt64LittleEndian(ReadField(artifactScope, out _)));
        var manifestHashBytes = ReadField(artifactStruct[scopeEnd..], out _);
        var expectedHashBytes = Convert.FromHexString(FixtureContractCodeHash);
        Assert.Equal(expectedHashBytes, manifestHashBytes);

        var dataspaceEnvelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindDataspaceNameOwnerById(42)
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));

        var (dataspaceDiscriminant, dataspacePayload) = ReadSingularQuery(dataspaceEnvelope);
        Assert.Equal(83u, dataspaceDiscriminant);
        var dataspaceStruct = ReadField(dataspacePayload, out _);
        var dataspaceIdBytes = ReadField(dataspaceStruct, out _);
        Assert.Equal(42ul, BinaryPrimitives.ReadUInt64LittleEndian(ReadField(dataspaceIdBytes, out _)));

        AssertSignatureVerifies(manifestEnvelope);
        AssertSignatureVerifies(dataspaceEnvelope);
    }

    [Theory]
    [InlineData("banka")]
    [InlineData(".universal")]
    [InlineData("banka.")]
    [InlineData("a.b.c")]
    [InlineData("BANKA.universal")]
    [InlineData("banka.UNIVERSAL")]
    [InlineData("bad!.universal")]
    [InlineData("-banka.universal")]
    [InlineData("banka-.universal")]
    [InlineData("ab--cd.universal")]
    [InlineData("xn--.universal")]
    [InlineData("xn--a.universal")]
    [InlineData("xn--abc.universal")]
    [InlineData("bücher.universal")]
    public void DomainQueriesRequireBothNativeIdentityComponents(string domainId)
    {
        AssertArgumentException("domainId", () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindDomainEndorsements(domainId));
        AssertArgumentException("domainId", () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindDomainEndorsementPolicy(domainId));
    }

    [Fact]
    public void DomainQueriesRejectLabelsBeyondNativeDnsLengthBound()
    {
        foreach (var domainId in new[] { new string('a', 64) + ".universal", "banka." + new string('b', 64) })
        {
            AssertArgumentException("domainId", () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindDomainEndorsements(domainId));
            AssertArgumentException("domainId", () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindDomainEndorsementPolicy(domainId));
        }
    }

    [Theory]
    [InlineData("xn--bcher-kva.universal")]
    [InlineData("banka.xn--bcher-kva")]
    [InlineData("bank_a.universal")]
    [InlineData("_banka.universal")]
    [InlineData("banka_.universal")]
    public void DomainQueriesPreserveNativeCanonicalLabels(string domainId)
    {
        AssertNativeDomainQueryLabels(domainId);
    }

    [Fact]
    public void DomainQueriesAdmitTwoMaximumLengthNativeLabels()
    {
        AssertNativeDomainQueryLabels(new string('a', 63) + "." + new string('b', 63));
    }

    private static void AssertNativeDomainQueryLabels(string domainId)
    {
        var seed = Convert.FromHexString(FixtureSeedHex);
        try
        {
            foreach (var builder in new[] {
                new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindDomainEndorsements(domainId),
                new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindDomainEndorsementPolicy(domainId),
            })
            {
                var envelope = builder.BuildSigned(seed);
                var (_, payload) = ReadSingularQuery(envelope);
                var domain = ReadField(ReadField(payload, out _), out _);
                var name = ReadNoritoString(ReadField(domain, out var offset));
                var dataspace = ReadNoritoString(ReadField(domain[offset..], out _));
                Assert.Equal(domainId, name + "." + dataspace);
                AssertSignatureVerifies(envelope);
            }
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(seed);
        }
    }

    [Fact]
    public void BuildSignedEncodesDomainEndorsementQueries()
    {
        var endorsementsEnvelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindDomainEndorsements("banka.universal")
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));
        var (endorsementsDiscriminant, endorsementsPayload) = ReadSingularQuery(endorsementsEnvelope);
        Assert.Equal(19u, endorsementsDiscriminant);
        var endorsementsStruct = ReadField(endorsementsPayload, out _);
        var endorsementsDomainId = ReadField(endorsementsStruct, out _);
        var endorsementsDomain = ReadNoritoString(ReadField(endorsementsDomainId, out var endorsementsOffset));
        Assert.Equal("banka", endorsementsDomain);
        Assert.Equal("universal", ReadNoritoString(ReadField(endorsementsDomainId[endorsementsOffset..], out _)));

        var policyEnvelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindDomainEndorsementPolicy("banka.universal")
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));
        var (policyDiscriminant, policyPayload) = ReadSingularQuery(policyEnvelope);
        Assert.Equal(20u, policyDiscriminant);
        var policyStruct = ReadField(policyPayload, out _);
        var policyDomainId = ReadField(policyStruct, out _);
        var policyDomain = ReadNoritoString(ReadField(policyDomainId, out var policyOffset));
        Assert.Equal("banka", policyDomain);
        Assert.Equal("universal", ReadNoritoString(ReadField(policyDomainId[policyOffset..], out _)));

        var committeeEnvelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindDomainCommittee("committee-7")
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));
        var (committeeDiscriminant, committeePayload) = ReadSingularQuery(committeeEnvelope);
        Assert.Equal(21u, committeeDiscriminant);
        var committeeStruct = ReadField(committeePayload, out _);
        var committeeId = ReadNoritoString(ReadField(committeeStruct, out _));
        Assert.Equal("committee-7", committeeId);

        AssertSignatureVerifies(endorsementsEnvelope);
        AssertSignatureVerifies(policyEnvelope);
        AssertSignatureVerifies(committeeEnvelope);
    }

    [Fact]
    public void BuildSignedEncodesProofAndTwitterBindingQueries()
    {
        var proofEnvelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindProofRecordById("pipa-r/pasta", FixtureProofHash)
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));
        var (proofDiscriminant, proofPayload) = ReadSingularQuery(proofEnvelope);
        Assert.Equal(6u, proofDiscriminant);
        var proofStruct = ReadField(ReadField(proofPayload, out _), out _);
        var proofBackend = ReadNoritoString(ReadField(proofStruct, out var proofOffsetAfterBackend));
        var proofHash = ReadField(proofStruct[proofOffsetAfterBackend..], out _);
        Assert.Equal("pipa-r/pasta", proofBackend);
        Assert.Equal(Convert.FromHexString(FixtureProofHash[2..]), proofHash);

        var twitterEnvelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindTwitterBindingByHash("pepper-v1", FixtureTwitterDigest)
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));
        var (twitterDiscriminant, twitterPayload) = ReadSingularQuery(twitterEnvelope);
        Assert.Equal(13u, twitterDiscriminant);
        var twitterStruct = ReadField(ReadField(twitterPayload, out _), out _);
        var pepperId = ReadNoritoString(ReadField(twitterStruct, out var twitterOffsetAfterPepperId));
        var digestBytes = ReadField(twitterStruct[twitterOffsetAfterPepperId..], out _);
        var expectedDigestBytes = Convert.FromHexString(FixtureTwitterDigest[2..]);
        expectedDigestBytes[^1] |= 0x01;
        Assert.Equal("pepper-v1", pepperId);
        Assert.Equal(expectedDigestBytes, digestBytes);

        AssertSignatureVerifies(proofEnvelope);
        AssertSignatureVerifies(twitterEnvelope);
    }

    [Fact]
    public void FindProofRecordByIdRejectsUnsupportedBackendsAndMalformedHashesBeforeBuild()
    {
        var validHash = new string('a', 64);
        foreach (var backend in new[]
        {
            "halo2/ipa",
            " pipa-r/pasta",
            "pipa-r/pasta ",
            "\tpipa-r/pasta",
            "pipa-r/pasta\n",
            " halo2/ipa",
            "halo2/ipa ",
            "\thalo2/ipa",
            "halo2/ipa\n",
            "halo2/ipa/orchard",
            "groth16/bls12-377",
            "halo2/kzg",
            "mock/dev",
        })
        {
            var error = Assert.Throws<ArgumentException>(
                () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindProofRecordById(backend, validHash));
            Assert.Equal("backend", error.ParamName);
        }

        foreach (var proofHash in new[]
        {
            "",
            "abc",
            new string('z', 64),
            new string('a', 63),
            " " + new string('a', 64),
            new string('a', 64) + " ",
            new string('a', 32) + " " + new string('a', 32),
            new string('a', 32) + "\u0000" + new string('a', 31),
            "0x0x" + new string('a', 64),
        })
        {
            var error = Assert.Throws<ArgumentException>(
                () => new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId).FindProofRecordById("pipa-r/pasta", proofHash));
            Assert.Equal("proofHash", error.ParamName);
        }
    }

    [Fact]
    public void BuildSignedEncodesDaPinAndSorafsQueries()
    {
        var ticketEnvelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindDaPinIntentByTicket(FixtureStorageTicket)
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));
        var (ticketDiscriminant, ticketPayload) = ReadSingularQuery(ticketEnvelope);
        Assert.Equal(22u, ticketDiscriminant);
        var ticketStruct = ReadField(ticketPayload, out _);
        Assert.Equal(Convert.FromHexString(FixtureStorageTicket[2..]), ReadField(ReadField(ticketStruct, out _), out _));

        var manifestEnvelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindDaPinIntentByManifest(FixtureManifestDigest)
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));
        var (manifestDiscriminant, manifestPayload) = ReadSingularQuery(manifestEnvelope);
        Assert.Equal(23u, manifestDiscriminant);
        var manifestStruct = ReadField(manifestPayload, out _);
        Assert.Equal(Convert.FromHexString(FixtureManifestDigest[2..]), ReadField(ReadField(manifestStruct, out _), out _));

        var aliasEnvelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindDaPinIntentByAlias("manifest-root")
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));
        var (aliasDiscriminant, aliasPayload) = ReadSingularQuery(aliasEnvelope);
        Assert.Equal(24u, aliasDiscriminant);
        var aliasStruct = ReadField(aliasPayload, out _);
        Assert.Equal("manifest-root", ReadNoritoString(ReadField(aliasStruct, out _)));

        var laneEnvelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindDaPinIntentByLaneEpochSequence(7, 11, 13)
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));
        var (laneDiscriminant, lanePayload) = ReadSingularQuery(laneEnvelope);
        Assert.Equal(25u, laneDiscriminant);
        var laneStruct = ReadField(lanePayload, out _);
        var laneId = ReadField(laneStruct, out var laneOffsetAfterLaneId);
        var epoch = ReadField(laneStruct[laneOffsetAfterLaneId..], out var laneOffsetAfterEpoch);
        var sequence = ReadField(laneStruct[(laneOffsetAfterLaneId + laneOffsetAfterEpoch)..], out _);
        Assert.Equal(7u, BinaryPrimitives.ReadUInt32LittleEndian(ReadField(laneId, out _)));
        Assert.Equal(11ul, BinaryPrimitives.ReadUInt64LittleEndian(epoch));
        Assert.Equal(13ul, BinaryPrimitives.ReadUInt64LittleEndian(sequence));

        var providerEnvelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindSorafsProviderOwner(FixtureProviderId)
            .BuildSigned(Convert.FromHexString(FixtureSeedHex));
        var (providerDiscriminant, providerPayload) = ReadSingularQuery(providerEnvelope);
        Assert.Equal(30u, providerDiscriminant);
        var providerStruct = ReadField(providerPayload, out _);
        Assert.Equal(Convert.FromHexString(FixtureProviderId[2..]), ReadField(ReadField(providerStruct, out _), out _));

        AssertSignatureVerifies(ticketEnvelope);
        AssertSignatureVerifies(manifestEnvelope);
        AssertSignatureVerifies(aliasEnvelope);
        AssertSignatureVerifies(laneEnvelope);
        AssertSignatureVerifies(providerEnvelope);
    }

    [Fact]
    public void SignedQueryUsesCanonicalCompactFieldsAndRejectsFixedFieldAlias()
    {
        var envelope = new SignedQueryBuilder(FixtureAccountId, FixtureNetworkId)
            .FindParameters()
            .BuildSigned(
                Convert.FromHexString(FixtureSeedHex),
                creationTimeMilliseconds: 1_736_000_000_000,
                timeToLiveMilliseconds: 100_000,
                nonce: Enumerable.Repeat((byte)0x01, 32).ToArray());

        Assert.Equal(new byte[] { 0x88, 0x01 }, envelope.SignedQueryBytes[..2]);
        var signatureField = ReadField(
            envelope.SignedQueryBytes,
            out var signatureConsumed);
        Assert.Equal(138, signatureConsumed);
        Assert.Equal(136, signatureField.Length);
        Assert.Equal(
            (ulong)Ed25519Signer.SignatureLength,
            BinaryPrimitives.ReadUInt64LittleEndian(signatureField));
        var offset = sizeof(ulong);
        for (var index = 0; index < Ed25519Signer.SignatureLength; index++)
        {
            Assert.Equal(1, signatureField[offset]);
            offset += 2;
        }
        Assert.Equal(signatureField.Length, offset);

        var fixedFields = new OfflineNoritoWriter();
        fixedFields.WriteField(signatureField);
        fixedFields.WriteField(envelope.PayloadBytes);
        var obsolete = fixedFields.ToArray();
        AssertArgumentException(
            "signedQueryBytes",
            () => new SignedQueryEnvelope(
                VersionSignedQueryBytes(obsolete),
                obsolete,
                envelope.PayloadBytes,
                envelope.SignatureBytes));
    }

    private static byte[] VersionSignedQueryBytes(byte[] signedQueryBytes)
    {
        var versionedNoritoBytes = new byte[signedQueryBytes.Length + 1];
        versionedNoritoBytes[0] = 1;
        signedQueryBytes.CopyTo(versionedNoritoBytes.AsSpan(1));
        return versionedNoritoBytes;
    }

    private static byte[] BuildSignedQueryBytes(byte[] signatureBytes, byte[] payloadBytes)
    {
        var signedQuery = new CanonicalNoritoWriter();
        signedQuery.WriteField(EncodeConstVec(signatureBytes));
        signedQuery.WriteField(payloadBytes);
        return signedQuery.ToArray();
    }

    private static byte[] EncodeConstVec(byte[] value)
    {
        var writer = new CanonicalNoritoWriter();
        writer.WriteSequenceLength((ulong)value.Length);
        foreach (var item in value)
        {
            writer.WriteField([item]);
        }

        return writer.ToArray();
    }

    private static void AssertSignatureVerifies(SignedQueryEnvelope envelope)
    {
        Assert.Equal(envelope.VersionedNoritoBytes[1..], envelope.SignedQueryBytes);

        var signatureField = ReadField(envelope.SignedQueryBytes, out var offsetAfterSignature);
        var payloadField = ReadField(envelope.SignedQueryBytes[offsetAfterSignature..], out _);

        Assert.Equal(envelope.PayloadBytes, payloadField);
        Assert.Equal(envelope.SignatureBytes, DecodeConstVec(signatureField));

        var payloadHash = IrohaHash.Hash(envelope.PayloadBytes);
        var publicKey = Ed25519Signer.GetPublicKey(Convert.FromHexString(FixtureSeedHex));
        Assert.True(Ed25519Signer.Verify(payloadHash, envelope.SignatureBytes, publicKey));
    }

    private static void AssertArgumentException(string paramName, Action action)
    {
        var exception = Assert.Throws<ArgumentException>(action);
        Assert.Equal(paramName, exception.ParamName);
    }

    private static (uint SingularDiscriminant, byte[] SingularPayload) ReadSingularQuery(SignedQueryEnvelope envelope)
    {
        var requestField = ReadContextBoundRequest(envelope);
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(requestField[..4]));

        var singularField = ReadField(requestField[4..], out _);
        var discriminant = BinaryPrimitives.ReadUInt32LittleEndian(singularField[..4]);
        return (discriminant, singularField[4..].ToArray());
    }

    private static byte[] ReadContextBoundRequest(SignedQueryEnvelope envelope)
    {
        var payload = envelope.PayloadBytes.AsSpan();
        var offset = 0;
        var networkId = ReadField(payload[offset..], out var consumed);
        offset += consumed;
        var authority = ReadField(payload[offset..], out consumed);
        offset += consumed;
        var creationTime = ReadField(payload[offset..], out consumed);
        offset += consumed;
        var timeToLive = ReadField(payload[offset..], out consumed);
        offset += consumed;
        var nonce = ReadField(payload[offset..], out consumed);
        offset += consumed;
        var request = ReadField(payload[offset..], out consumed);
        offset += consumed;

        Assert.Equal(payload.Length, offset);
        Assert.Equal(Convert.FromHexString(FixtureNetworkIdLiteral.Substring(5, 64)), networkId);
        Assert.NotEmpty(authority);
        Assert.True(BinaryPrimitives.ReadUInt64LittleEndian(creationTime) > 0);
        Assert.Equal(100_000ul, BinaryPrimitives.ReadUInt64LittleEndian(timeToLive));
        Assert.Equal(32, nonce.Length);
        Assert.Contains(nonce, static value => value != 0);
        return request;
    }

    private static byte[] ReadField(ReadOnlySpan<byte> bytes, out int consumed)
    {
        var reader = new CanonicalNoritoReader(bytes, "signed-query test field", nameof(bytes));
        var field = reader.ReadField("field").ToArray();
        consumed = bytes.Length - reader.Remaining;
        return field;
    }

    private static void AssertCanonicalAssetDefinitionId(ReadOnlySpan<byte> bytes)
    {
        Assert.Equal(16 * 2, bytes.Length);
        var uuid = new byte[16];
        var offset = 0;
        for (var index = 0; index < uuid.Length; index++)
        {
            var component = ReadField(bytes[offset..], out var consumed);
            Assert.Single(component);
            Assert.Equal(2, consumed);
            uuid[index] = component[0];
            offset += consumed;
        }

        Assert.Equal(bytes.Length, offset);
        Assert.Equal(4, uuid[6] >> 4);
        Assert.Equal(2, uuid[8] >> 6);
    }

    private static byte[] DecodeConstVec(ReadOnlySpan<byte> bytes)
    {
        var reader = new CanonicalNoritoReader(bytes, "signed-query test signature", nameof(bytes));
        var count = checked((int)reader.ReadSequenceLength("count"));
        var output = new byte[count];
        for (var index = 0; index < count; index++)
        {
            var item = reader.ReadField($"signature[{index}]");
            Assert.Single(item.ToArray());
            output[index] = item[0];
        }

        reader.RequireEnd();
        return output;
    }

    private static string? ReadOptionalString(ReadOnlySpan<byte> bytes)
    {
        return bytes[0] switch
        {
            0 => null,
            1 => ReadNoritoString(ReadField(bytes[1..], out _)),
            _ => throw new InvalidOperationException("Unexpected option tag."),
        };
    }

    private static string ReadNoritoString(ReadOnlySpan<byte> bytes)
    {
        var reader = new CanonicalNoritoReader(bytes, "signed-query test string", nameof(bytes));
        var length = checked((int)reader.ReadCompactLength("length"));
        var value = Encoding.UTF8.GetString(reader.ReadExact(length, "value"));
        reader.RequireEnd();
        return value;
    }
}
