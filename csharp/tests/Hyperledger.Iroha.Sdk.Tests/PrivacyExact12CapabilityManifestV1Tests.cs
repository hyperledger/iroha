using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Hyperledger.Iroha.Norito;
using Hyperledger.Iroha.Privacy;
using Hyperledger.Iroha.Torii;

namespace Hyperledger.Iroha.Sdk.Tests;

public sealed class PrivacyExact12CapabilityManifestV1Tests
{
    private static readonly PrivacyExecutionModeV1[] ExecutionModes =
    [
        PrivacyExecutionModeV1.AuthorizationAction,
        PrivacyExecutionModeV1.PaymentAction,
        PrivacyExecutionModeV1.Component,
        PrivacyExecutionModeV1.AdmissionAction,
        PrivacyExecutionModeV1.PresentationAction,
        PrivacyExecutionModeV1.PresentationAction,
        PrivacyExecutionModeV1.Component,
        PrivacyExecutionModeV1.PresentationAction,
        PrivacyExecutionModeV1.NoteAction,
        PrivacyExecutionModeV1.PaymentAction,
        PrivacyExecutionModeV1.NoteAction,
        PrivacyExecutionModeV1.NoteAction,
    ];

    private static readonly byte[] FeatureMasks =
        [0, 6, 1, 2, 2, 2, 0, 2, 7, 2, 7, 31];

    private static readonly uint[] ProofSystems =
        [0, 2, 3, 1, 4, 0, 5, 8, 6, 7, 0, 0];

    private static readonly uint[] Engines =
        [0, 2, 3, 1, 4, 0, 5, 8, 6, 7, 0, 0];

    private static readonly uint[] SecurityModels =
        [0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0];

    [Fact]
    public void ManagedProjectionPreservesFieldsWithoutGrantingNativeQualification()
    {
        var fixture = BuildFixture();
        var decoded = PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
            fixture.Manifest,
            fixture.Catalog);

        Assert.Equal(1U, decoded.Version);
        Assert.Equal(3UL, decoded.CommittedHeight);
        var qualification = Assert.IsType<PrivacyExact12QualificationRecordV1>(
            decoded.Qualification);
        Assert.Equal(12, qualification.ReleaseManifest.Protocols.Count);
        Assert.Equal(
            qualification.ReleaseManifest.ManifestDigest,
            qualification.DeploymentQualification.ReleaseManifestDigest);
        Assert.Equal(12, decoded.Protocols.Count);
        Assert.True(decoded.Protocols[0].IsNetworkAvailable);
        Assert.All(decoded.Protocols, row => Assert.True(row.LocalCompiledTupleMatches));
        Assert.Equal(
            PrivacyCapabilityReadinessV1.Unavailable,
            decoded.Protocols[(int)PrivacyProtocolIdV1.IrohaJindoPolynomialCommitmentV1].Readiness);
        Assert.Equal(
            PrivacyCapabilityUnavailableReasonV1.NotRegistered,
            decoded.Protocols[(int)PrivacyProtocolIdV1.IrohaJindoPolynomialCommitmentV1]
                .UnavailableReason);
        Assert.Equal(
            PrivacyCapabilityUnavailableReasonV1.CompiledProfile,
            decoded.Protocols[1].UnavailableReason);
        Assert.Equal(
            PrivacyCompiledProfileUnavailableReasonV1.EngineUnavailable,
            decoded.Protocols[1].CompiledProfileUnavailableReason);
        Assert.Equal(ConsensusPolicy(), decoded.ConsensusPolicy);
        Assert.Equal(
            Option(ActivationForProfileZero(), present: true),
            decoded.Protocols[0].ActivationCanonicalBytes);
        var activationCopy = decoded.Protocols[0].ActivationCanonicalBytes;
        activationCopy[0] ^= 0xff;
        Assert.False(activationCopy.SequenceEqual(decoded.Protocols[0].ActivationCanonicalBytes));
        Assert.Equal(fixture.Manifest, decoded.CanonicalArchive);
    }

    [Fact]
    public void DeploymentProjectionRetainsExactNetworkAndRejectsOtherNetworkAdmission()
    {
        var fixture = BuildFixture();
        var decoded = PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
            fixture.Manifest, fixture.Catalog);
        var expected = NetworkId.FromBytes(Enumerable.Repeat((byte)0xd1, 32).ToArray());
        var qualification = Assert.IsType<PrivacyExact12QualificationRecordV1>(decoded.Qualification);
        Assert.Equal(expected, qualification.DeploymentQualification.NetworkId);
        PrivacyExact12CapabilityManifestCodecV1.RequireDeploymentNetwork(
            qualification, expected, requireQualification: true);
        var other = NetworkId.FromBytes(Enumerable.Repeat((byte)0xd3, 32).ToArray());
        Assert.Throws<PrivacyExact12CapabilityManifestException>(() =>
            PrivacyExact12CapabilityManifestCodecV1.RequireDeploymentNetwork(
                qualification, other, requireQualification: true));
        var copy = qualification.DeploymentQualification.NetworkId.ToBytes();
        copy[0] ^= 1;
        Assert.Equal(expected, qualification.DeploymentQualification.NetworkId);
    }

    [Fact]
    public void MissingDeploymentCanBeInspectedButCannotAuthorizeConstruction()
    {
        var expected = NetworkId.FromBytes(Enumerable.Repeat((byte)0xd1, 32).ToArray());
        PrivacyExact12CapabilityManifestCodecV1.RequireDeploymentNetwork(null, expected);
        Assert.Throws<PrivacyExact12CapabilityManifestException>(() =>
            PrivacyExact12CapabilityManifestCodecV1.RequireDeploymentNetwork(
                null, expected, requireQualification: true));
    }

    [Fact]
    public void RecomputedManifestDigestCannotHideMalformedOrMismatchedNetworkBytes()
    {
        var valid = Enumerable.Repeat((byte)0xd1, 32).ToArray();
        var invalid = new[]
        {
            Array.Empty<byte>(), valid[..31], valid.Concat(new byte[] { 0 }).ToArray(),
            Struct(valid), Enumerable.Repeat((byte)0xd0, 32).ToArray(),
        };
        foreach (var network in invalid)
        {
            var fixture = BuildFixture(deploymentNetwork: network);
            Assert.Throws<PrivacyExact12CapabilityManifestException>(() =>
                PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(fixture.Manifest, fixture.Catalog));
        }
        foreach (var genesis in invalid.Append(Enumerable.Repeat((byte)0xd3, 32).ToArray()))
        {
            var fixture = BuildFixture(deploymentGenesis: genesis);
            Assert.Throws<PrivacyExact12CapabilityManifestException>(() =>
                PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(fixture.Manifest, fixture.Catalog));
        }
    }

    [Fact]
    public void PublicValidatorRejectsEmptyReleaseAndDeploymentEvidence()
    {
        // The managed projection fixture omits all audits, release signatures,
        // validator canaries and signatures. Only Rust can qualify these bytes.
        var fixture = BuildFixture();
        Assert.Equal(
            PrivacyNative.IsAvailable()
                ? PrivacyExact12CapabilityManifestValidationStatusV1.InvalidManifest
                : PrivacyExact12CapabilityManifestValidationStatusV1.NativeUnavailable,
            PrivacyNative.ValidateExact12CapabilityManifestV1(fixture.Manifest));
    }

    [Fact]
    public void LocalCatalogTupleSubstitutionFailsClosed()
    {
        var fixture = BuildFixture();
        var mismatchedProfiles = fixture.CompiledProfiles.Select(static value => (byte[])value.Clone()).ToArray();
        mismatchedProfiles[0][^1] ^= 1;
        var mismatchedCatalog = BuildCatalog(mismatchedProfiles);

        Assert.Throws<PrivacyExact12CapabilityManifestCodecV1.LocalTupleMismatchException>(() =>
            PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
                fixture.Manifest,
                mismatchedCatalog));
    }

    [Fact]
    public void LegacySnapshotSchemaCannotAuthorize()
    {
        var fixture = BuildFixture();
        var legacy = NoritoCodec.Encode(
            "iroha.privacy.capability-snapshot.v1",
            NoritoCodec.Decode(
                PrivacyExact12CapabilityManifestCodecV1.ManifestSchemaName,
                fixture.Manifest).Payload,
            NoritoCodec.CanonicalLayoutFlags);

        Assert.Throws<PrivacyExact12CapabilityManifestException>(() =>
            PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
                legacy,
                fixture.Catalog));
    }

    [Fact]
    public void RecomputedDigestCannotHideActivationProjectionDrift()
    {
        var fixture = BuildFixture(
            rowZeroReadiness: UnavailableReadiness(3));

        Assert.Throws<PrivacyExact12CapabilityManifestException>(() =>
            PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
                fixture.Manifest,
                fixture.Catalog));
    }

    [Fact]
    public void ActiveProtocolWithoutRegisteredQualificationStaysUnavailable()
    {
        var fixture = BuildFixture(includeQualification: false);

        var decoded = PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
            fixture.Manifest,
            fixture.Catalog);

        Assert.Equal(PrivacyCapabilityReadinessV1.Unavailable, decoded.Protocols[0].Readiness);
        Assert.Equal(
            PrivacyCapabilityUnavailableReasonV1.MissingProductionQualification,
            decoded.Protocols[0].UnavailableReason);
        Assert.False(decoded.Protocols[0].IsNetworkAvailable);
    }

    [Fact]
    public void MismatchedRegisteredQualificationDerivesOnlyInvalidReadiness()
    {
        var fixture = BuildFixture(
            rowZeroReadiness: UnavailableReadiness(6),
            committedHeight: 4,
            qualificationActivationHeight: 3,
            qualificationConvergenceHeight: 4);
        var decoded = PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
            fixture.Manifest,
            fixture.Catalog);
        Assert.Equal(
            PrivacyCapabilityUnavailableReasonV1.InvalidProductionQualification,
            decoded.Protocols[0].UnavailableReason);

        var forged = BuildFixture(
            committedHeight: 4,
            qualificationActivationHeight: 3,
            qualificationConvergenceHeight: 4);
        Assert.Throws<PrivacyExact12CapabilityManifestException>(() =>
            PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
                forged.Manifest,
                forged.Catalog));
    }

    [Fact]
    public void GovernanceLifecycleProjectsEveryClosedUnavailableReason()
    {
        var cases = new[]
        {
            (
                Lifecycle: EnumValue(0, Struct(U64(1))),
                Reason: PrivacyCapabilityUnavailableReasonV1.Proposed,
                ReasonTag: 2U),
            (
                Lifecycle: EnumValue(2, Struct(U64(1), U64(2), U64(3))),
                Reason: PrivacyCapabilityUnavailableReasonV1.Suspended,
                ReasonTag: 3U),
            (
                Lifecycle: EnumValue(
                    3,
                    Struct(U64(1), Option(U64(2), present: true), U64(3))),
                Reason: PrivacyCapabilityUnavailableReasonV1.Retired,
                ReasonTag: 4U),
        };

        foreach (var item in cases)
        {
            var fixture = BuildFixture(
                rowZeroReadiness: UnavailableReadiness(item.ReasonTag),
                rowZeroLifecycle: item.Lifecycle,
                committedHeight: 3);
            var decoded = PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
                fixture.Manifest,
                fixture.Catalog);

            Assert.Equal(PrivacyCapabilityReadinessV1.Unavailable, decoded.Protocols[0].Readiness);
            Assert.Equal(item.Reason, decoded.Protocols[0].UnavailableReason);
            Assert.False(decoded.Protocols[0].IsNetworkAvailable);
        }
    }

    [Fact]
    public void PendingTighteningAcceptsNextBlockAndRejectsInvalidSnapshotHeights()
    {
        (ulong Scheduled, ulong Effective, ulong Committed, bool Accepted)[] cases =
        [
            (3, 4, 3, true), (3, 5, 3, true),
            (ulong.MaxValue - 1, ulong.MaxValue, ulong.MaxValue - 1, true),
            (0, 4, 3, false), (3, 3, 3, false), (3, 2, 3, false),
            (4, 5, 3, false), (3, 4, 4, false),
            (ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, false),
        ];
        foreach (var consensus in new[] { true, false })
        {
            foreach (var item in cases)
            {
                var next = consensus
                    ? Struct(U32(1), U32(2), U32(9 * 1024 * 1024), U32(9_699_840),
                        U32(9_699_840), U32(16_711_680), U32(256 * 1024),
                        U32(8), U32(8), U32(1_024))
                    : EnumValue(6, Struct(U32(3)));
                var pending = Struct(U64(item.Scheduled), U64(item.Effective), next);
                var fixture = BuildFixture(
                    committedHeight: item.Committed, includeQualification: false,
                    pendingConsensus: consensus ? pending : null,
                    pendingJindo: consensus ? null : pending);
                if (item.Accepted)
                {
                    var decoded = PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
                        fixture.Manifest, fixture.Catalog);
                    Assert.Equal(fixture.Manifest, decoded.CanonicalArchive);
                    Assert.False(decoded.Protocols[0].IsNetworkAvailable);
                }
                else
                {
                    Assert.Throws<PrivacyExact12CapabilityManifestException>(() =>
                        PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
                            fixture.Manifest, fixture.Catalog));
                }
            }
        }
    }

    [Fact]
    public void ProposedRemainsPendingUntilExplicitActivationAtEveryCommittedHeight()
    {
        foreach (var committedHeight in new[] { 1UL, 3UL, ulong.MaxValue })
        {
            var lifecycle = EnumValue(0, Struct(U64(1)));
            var fixture = BuildFixture(
                rowZeroReadiness: UnavailableReadiness(2),
                rowZeroLifecycle: lifecycle,
                committedHeight: committedHeight,
                includeQualification: false);
            var decoded = PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
                fixture.Manifest, fixture.Catalog);
            Assert.Equal(PrivacyCapabilityUnavailableReasonV1.Proposed,
                decoded.Protocols[0].UnavailableReason);
            Assert.False(decoded.Protocols[0].IsNetworkAvailable);
            Assert.Equal(Option(ActivationForProfileZero(lifecycleOverride: lifecycle), present: true),
                decoded.Protocols[0].ActivationCanonicalBytes);

            var forged = BuildFixture(
                rowZeroLifecycle: lifecycle,
                committedHeight: committedHeight,
                includeQualification: false);
            Assert.Throws<PrivacyExact12CapabilityManifestException>(() =>
                PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
                    forged.Manifest, forged.Catalog));
        }
    }

    [Fact]
    public void SameHeightActivationRetainsQualificationAndStrictLaterHistory()
    {
        var cases = new[]
        {
            (Lifecycle: EnumValue(1, Struct(U64(1), U64(1), U64(1))),
                Reason: PrivacyCapabilityUnavailableReasonV1.MissingProductionQualification, Tag: 5U),
            (Lifecycle: EnumValue(1, Struct(U64(1), U64(1), U64(3))),
                Reason: PrivacyCapabilityUnavailableReasonV1.MissingProductionQualification, Tag: 5U),
            (Lifecycle: EnumValue(2, Struct(U64(1), U64(1), U64(2))),
                Reason: PrivacyCapabilityUnavailableReasonV1.Suspended, Tag: 3U),
            (Lifecycle: EnumValue(3, Struct(U64(1), Option(U64(1), present: true), U64(2))),
                Reason: PrivacyCapabilityUnavailableReasonV1.Retired, Tag: 4U),
            (Lifecycle: EnumValue(3, Struct(U64(1), Option(Array.Empty<byte>(), present: false), U64(2))),
                Reason: PrivacyCapabilityUnavailableReasonV1.Retired, Tag: 4U),
        };
        foreach (var item in cases)
        {
            var fixture = BuildFixture(
                rowZeroReadiness: UnavailableReadiness(item.Tag),
                rowZeroLifecycle: item.Lifecycle,
                includeQualification: false);
            var decoded = PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
                fixture.Manifest, fixture.Catalog);
            Assert.Equal(item.Reason, decoded.Protocols[0].UnavailableReason);
            Assert.False(decoded.Protocols[0].IsNetworkAvailable);
            Assert.Equal(Option(ActivationForProfileZero(lifecycleOverride: item.Lifecycle), present: true),
                decoded.Protocols[0].ActivationCanonicalBytes);
        }

        var qualified = BuildFixture(
            rowZeroLifecycle: EnumValue(1, Struct(U64(1), U64(1), U64(1))),
            qualificationActivationHeight: 1);
        var projected = PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
            qualified.Manifest, qualified.Catalog);
        Assert.True(projected.Protocols[0].IsNetworkAvailable);
        // This managed projection preserves evidence; native admission still validates it.
    }

    [Fact]
    public void ExplicitActivationRejectsRemovedScheduleAndInvalidHistory()
    {
        var cases = new[]
        {
            (Lifecycle: EnumValue(0, Struct(U64(1), U64(4))), Tag: 2U),
            (Lifecycle: EnumValue(0, Struct(U64(1), U64(301))), Tag: 2U),
            (Lifecycle: EnumValue(0, Struct()), Tag: 2U),
            (Lifecycle: EnumValue(0, Struct(U64(0))), Tag: 2U),
            (Lifecycle: EnumValue(0, Struct(U64(4))), Tag: 2U),
            (Lifecycle: EnumValue(1, Struct(U64(2), U64(1), U64(2))), Tag: 5U),
            (Lifecycle: EnumValue(1, Struct(U64(1), U64(2), U64(1))), Tag: 5U),
            (Lifecycle: EnumValue(1, Struct(U64(1), U64(4), U64(4))), Tag: 5U),
            (Lifecycle: EnumValue(1, Struct(U64(1), U64(1), U64(4))), Tag: 5U),
            (Lifecycle: EnumValue(2, Struct(U64(1), U64(1), U64(1))), Tag: 3U),
            (Lifecycle: EnumValue(3, Struct(U64(1), Option(U64(1), present: true), U64(1))), Tag: 4U),
            (Lifecycle: EnumValue(3, Struct(U64(1), Option(Array.Empty<byte>(), present: false), U64(1))), Tag: 4U),
        };
        foreach (var item in cases)
        {
            var fixture = BuildFixture(
                rowZeroReadiness: UnavailableReadiness(item.Tag),
                rowZeroLifecycle: item.Lifecycle,
                includeQualification: false);
            Assert.Throws<PrivacyExact12CapabilityManifestException>(() =>
                PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
                    fixture.Manifest, fixture.Catalog));
        }
    }

    [Fact]
    public void LegacyNineFieldRowAndExperimentalAssuranceArchivesAreRejected()
    {
        var legacyRows = BuildFixture(useLegacyNineFieldRows: true);
        var legacyAssurance = BuildFixture(useLegacyAssurance: true);

        Assert.Throws<PrivacyExact12CapabilityManifestException>(() =>
            PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
                legacyRows.Manifest,
                legacyRows.Catalog));
        Assert.Throws<PrivacyExact12CapabilityManifestException>(() =>
            PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
                legacyAssurance.Manifest,
                legacyAssurance.Catalog));
    }

    [Fact]
    public void ReleaseQualificationMustBindItsCanonicalSecurityClaim()
    {
        var fixture = BuildFixture(corruptSecurityClaimDigest: true);

        Assert.Throws<PrivacyExact12CapabilityManifestException>(() =>
            PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
                fixture.Manifest,
                fixture.Catalog));
    }

    [Fact]
    public void ReadinessSurfaceContainsOnlyTheFinalHardCutStates()
    {
        Assert.Equal(
            new[] { "ProductionQualified", "Unavailable" },
            Enum.GetNames<PrivacyCapabilityReadinessV1>());
    }

    [Fact]
    public void RecomputedDigestCannotHideConsensusPolicyDrift()
    {
        var fixture = BuildFixture(maxActionsPerTransaction: 2);

        Assert.Throws<PrivacyExact12CapabilityManifestException>(() =>
            PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
                fixture.Manifest,
                fixture.Catalog));
    }

    [Fact]
    public void RecomputedDigestCannotHideActivationBindingDrift()
    {
        var fixture = BuildFixture(activationDigestByte: 0x32);

        Assert.Throws<PrivacyExact12CapabilityManifestException>(() =>
            PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
                fixture.Manifest,
                fixture.Catalog));
    }

    [Fact]
    public void PublicManifestAndAdmissionConstructorsAreClosed()
    {
        var manifestConstructor = Assert.Single(
            typeof(PrivacyExact12CapabilityManifestV1).GetConstructors(
                BindingFlags.NonPublic | BindingFlags.Instance));
        Assert.True(manifestConstructor.IsPrivate);
        var admissionConstructor = Assert.Single(
            typeof(PrivacyExact12CapabilityTupleAdmissionV1).GetConstructors(
                BindingFlags.NonPublic | BindingFlags.Instance));
        Assert.True(admissionConstructor.IsPrivate);
        Assert.DoesNotContain(
            typeof(PrivacyExact12CapabilityManifestCodecV1).GetMethods(
                BindingFlags.NonPublic | BindingFlags.Static),
            method => method.ReturnType == typeof(PrivacyExact12CapabilityManifestV1));

        var authenticatedFetch = Assert.Single(
            typeof(PrivacyExact12CapabilityManifestV1).GetMethods(
                BindingFlags.NonPublic | BindingFlags.Static),
            method => method.Name == "FetchAuthenticatedToriiAsync");
        Assert.Equal(
            new[] { typeof(ToriiClient), typeof(CancellationToken) },
            authenticatedFetch.GetParameters().Select(parameter => parameter.ParameterType));
        Assert.DoesNotContain(
            typeof(PrivacyExact12CapabilityAdmissionV1).GetMethods(
                BindingFlags.Public | BindingFlags.Static),
            method => method.GetParameters().Any(parameter =>
                parameter.ParameterType.Name.Contains(
                    "PrivacyCapabilitySnapshot",
                    StringComparison.Ordinal)));
    }

    private static Fixture BuildFixture(
        byte[]? rowZeroReadiness = null,
        byte[]? rowZeroLifecycle = null,
        ulong committedHeight = 3,
        uint maxActionsPerTransaction = 1,
        byte activationDigestByte = 0x31,
        bool includeQualification = true,
        bool useLegacyNineFieldRows = false,
        bool useLegacyAssurance = false,
        bool corruptSecurityClaimDigest = false,
        ulong qualificationActivationHeight = 2,
        ulong qualificationConvergenceHeight = 3,
        byte[]? deploymentNetwork = null,
        byte[]? deploymentGenesis = null,
        byte[]? pendingConsensus = null,
        byte[]? pendingJindo = null)
    {
        var profiles = new byte[12][];
        profiles[0] = AvailableProfile(
            protocol: 0,
            proofSystem: 0,
            engine: 0,
            digestByte: 0x31,
            limits: EnumValue(0));
        for (var index = 1; index < profiles.Length; index++)
        {
            if (index == 6)
            {
                profiles[index] = AvailableProfile(
                    protocol: 6,
                    proofSystem: 5,
                    engine: 5,
                    digestByte: 0x61,
                    limits: EnumValue(6, Struct(U32(4))));
            }
            else
            {
                profiles[index] = EnumValue(1, EnumValue(0));
            }
        }

        var rows = new byte[12][];
        for (var index = 0; index < rows.Length; index++)
        {
            var readiness = useLegacyNineFieldRows
                ? index switch
                {
                    0 => EnumValue(0),
                    6 => EnumValue(1),
                    _ => EnumValue(2, EnumValue(0)),
                }
                : index switch
                {
                    0 => rowZeroReadiness ?? (includeQualification
                        ? EnumValue(0)
                        : UnavailableReadiness(5)),
                    6 => UnavailableReadiness(pendingJindo is null ? 1U : 5U),
                    _ => UnavailableReadiness(0, EnumValue(0)),
                };
            var activation = index == 0
                ? Option(
                    ActivationForProfileZero(
                        activationDigestByte,
                        useLegacyAssurance || useLegacyNineFieldRows,
                        rowZeroLifecycle),
                    present: true)
                : index == 6 && pendingJindo is not null
                    ? Option(ActivationForJindo(pendingJindo), present: true)
                    : Option(Array.Empty<byte>(), present: false);
            var fields = new List<byte[]>
            {
                EnumValue(checked((uint)index)),
                EnumValue(checked((uint)index)),
                EnumValue((uint)ExecutionModes[index]),
                Struct(new[] { FeatureMasks[index] }),
                profiles[index],
                readiness,
            };
            if (useLegacyNineFieldRows)
            {
                fields.Add(EnumValue(index == 0 ? 2U : 0U));
                fields.Add(activation);
                fields.Add(index == 6
                    ? Option(EnumValue(0), present: true)
                    : Option(Array.Empty<byte>(), present: false));
            }
            else
            {
                fields.Add(activation);
            }
            rows[index] = Struct(fields.ToArray());
        }

        var catalog = BuildCatalog(profiles);
        var qualification = includeQualification
            ? Exact12Qualification(
                corruptSecurityClaimDigest,
                qualificationActivationHeight,
                qualificationConvergenceHeight,
                deploymentNetwork,
                deploymentGenesis)
            : Array.Empty<byte>();
        var manifestWithZeroDigest = BuildManifestArchive(
            rows,
            qualification,
            includeQualification,
            new byte[32],
            maxActionsPerTransaction,
            committedHeight,
            pendingConsensus);
        var digest = ComputeManifestDigest(manifestWithZeroDigest);
        return new Fixture(
            BuildManifestArchive(
                rows,
                qualification,
                includeQualification,
                digest,
                maxActionsPerTransaction,
                committedHeight,
                pendingConsensus),
            catalog,
            profiles);
    }

    private static byte[] AvailableProfile(
        uint protocol,
        uint proofSystem,
        uint engine,
        byte digestByte,
        byte[] limits)
    {
        var digest = Struct(Enumerable.Repeat(digestByte, 32).Select(static value => (byte)value).ToArray());
        return EnumValue(
            0,
            Struct(
                EnumValue(protocol),
                EnumValue(proofSystem),
                EnumValue(engine),
                digest,
                digest,
                digest,
                digest,
                digest,
                limits));
    }

    private static byte[] ActivationForJindo(byte[] pending)
    {
        var digest = Struct(Enumerable.Repeat((byte)0x61, 32).ToArray());
        return Struct(
            EnumValue(6), EnumValue(5), EnumValue(5),
            digest, digest, digest, digest, digest,
            EnumValue(1, Struct(U64(1), U64(2), U64(2))),
            EnumValue(6, Struct(U32(4))), Option(pending, present: true));
    }

    private static byte[] ActivationForProfileZero(
        byte digestByte = 0x31,
        bool useLegacyAssurance = false,
        byte[]? lifecycleOverride = null)
    {
        var digest = Struct(Enumerable.Repeat(digestByte, 32).ToArray());
        var lifecycle = lifecycleOverride ?? EnumValue(1, Struct(U64(1), U64(2), U64(2)));
        var fields = new List<byte[]>
        {
            EnumValue(0),
            EnumValue(0),
            EnumValue(0),
            digest,
            digest,
            digest,
            digest,
            digest,
            lifecycle,
            EnumValue(0),
            Option(Array.Empty<byte>(), present: false),
        };
        if (useLegacyAssurance)
        {
            fields.Add(EnumValue(0));
        }
        return Struct(fields.ToArray());
    }

    private static (byte[] Claim, byte[] Digest) SecurityClaim(
        int protocolIndex,
        byte digestByte,
        bool corruptDigest)
    {
        var activationDigest = Struct(Enumerable.Repeat(digestByte, 32).ToArray());
        var securityClaim = Struct(
            Exact12CatalogCommitment(),
            EnumValue(checked((uint)protocolIndex)),
            EnumValue(SecurityModels[protocolIndex]),
            U16(128),
            U16(128),
            activationDigest,
            activationDigest,
            Struct(Enumerable.Repeat((byte)0xe1, 32).ToArray()),
            Struct(Enumerable.Repeat((byte)0xe2, 32).ToArray()));
        var claimDigest = ComputeSecurityClaimDigest(securityClaim);
        if (corruptDigest)
        {
            claimDigest[0] ^= 0x80;
        }
        return (securityClaim, claimDigest);
    }

    private static byte[] Exact12Qualification(
        bool corruptSecurityClaimDigest,
        ulong firstActivationHeight,
        ulong convergenceHeight,
        byte[]? deploymentNetwork,
        byte[]? deploymentGenesis)
    {
        var releaseDigest = Enumerable.Repeat((byte)0xe3, 32).ToArray();
        var bindings = Enumerable.Range(0, 12)
            .Select(index => ReleaseBinding(
                index,
                ProfileDigestByte(index),
                corruptSecurityClaimDigest && index == 0))
            .ToArray();
        var source = Struct(
            Digest(0xa1),
            new byte[] { 1 },
            CompactString("csharp-test-toolchain"),
            Digest(0xa2),
            Digest(0xa3));
        var release = Struct(
            U16(1),
            CompactString("iroha-privacy-exact12-v1"),
            Exact12CatalogCommitment(),
            source,
            U16(1),
            Digest(0xa4),
            Digest(0xa5),
            Sequence(Array.Empty<byte[]>()),
            Sequence(bindings),
            Sequence(Array.Empty<byte[]>()),
            Sequence(Array.Empty<byte[]>()),
            Sequence(Array.Empty<byte[]>()),
            Sequence(Array.Empty<byte[]>()),
            Digest(0xa6),
            Sequence(Array.Empty<byte[]>()),
            Digest(0xe2),
            Sequence(Array.Empty<byte[]>()),
            Struct(releaseDigest));
        var activations = Enumerable.Range(0, 12)
            .Select(index => Struct(
                EnumValue(checked((uint)index)),
                U64(index == 0 ? firstActivationHeight : 2)))
            .ToArray();
        var deployment = Struct(
            U16(1),
            CompactString("csharp-test-chain"),
            deploymentNetwork ?? Enumerable.Repeat((byte)0xd1, 32).ToArray(),
            deploymentGenesis ?? Enumerable.Repeat((byte)0xd1, 32).ToArray(),
            Struct(releaseDigest),
            Digest(0xd1),
            Sequence(activations),
            Digest(0xd2),
            CompactString("v1"),
            U64(convergenceHeight),
            Digest(0xd3),
            Sequence(Array.Empty<byte[]>()),
            Sequence(Array.Empty<byte[]>()),
            Digest(0xe4));
        return Struct(release, deployment);
    }

    private static byte[] ReleaseBinding(
        int protocolIndex,
        byte digestByte,
        bool corruptSecurityClaimDigest)
    {
        var binding = Digest(digestByte);
        var claim = SecurityClaim(
            protocolIndex,
            digestByte,
            corruptSecurityClaimDigest);
        return Struct(
            EnumValue(checked((uint)protocolIndex)),
            EnumValue(ProofSystems[protocolIndex]),
            EnumValue(Engines[protocolIndex]),
            binding,
            binding,
            binding,
            binding,
            binding,
            claim.Claim,
            Struct(claim.Digest));
    }

    private static byte ProfileDigestByte(int index) => index switch
    {
        0 => 0x31,
        6 => 0x61,
        _ => checked((byte)(0x40 + index)),
    };

    private static byte[] Digest(byte value) =>
        Struct(Enumerable.Repeat(value, 32).ToArray());

    private static byte[] Exact12CatalogCommitment() =>
        Convert.FromHexString(
            "E037F13904A0307C00DB15D85CFB406BD79772D20144A949" +
            "DEF0F3FDA78E342E747F65787CBFBFFAC94F11C369E2BBFF");

    private static byte[] ComputeSecurityClaimDigest(byte[] claim)
    {
        var domain = Encoding.UTF8.GetBytes("iroha:privacy:security-claim:v1");
        var canonicalClaim = NoritoCodec.Encode(
            "iroha_data_model::privacy::protocol::PrivacySecurityClaimV1",
            claim,
            NoritoCodec.CanonicalLayoutFlags);
        Span<byte> length = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(length, checked((ulong)canonicalClaim.Length));
        var input = new byte[domain.Length + length.Length + canonicalClaim.Length];
        domain.CopyTo(input, 0);
        length.CopyTo(input.AsSpan(domain.Length));
        canonicalClaim.CopyTo(input, domain.Length + length.Length);
        return SHA256.HashData(input);
    }

    private static byte[] BuildCatalog(IReadOnlyList<byte[]> profiles)
    {
        var rows = profiles.Select((profile, index) =>
            Struct(EnumValue(checked((uint)index)), profile)).ToArray();
        return NoritoCodec.Encode(
            PrivacyExact12CapabilityManifestCodecV1.CatalogSchemaName,
            Struct(U32(1), Sequence(rows)),
            NoritoCodec.CanonicalLayoutFlags);
    }

    private static byte[] ConsensusPolicy(
        uint maxActionsPerTransaction = 1, byte[]? pending = null)
    {
        var consensusLimits = Struct(
            U32(maxActionsPerTransaction),
            U32(2),
            U32(9 * 1024 * 1024),
            U32(9_699_840),
            U32(9_699_840),
            U32(16_711_680),
            U32(256 * 1024),
            U32(8),
            U32(8),
            U32(2_048));
        return Struct(
            consensusLimits,
            Option(pending ?? Array.Empty<byte>(), present: pending is not null));
    }

    private static byte[] BuildManifestArchive(
        IReadOnlyList<byte[]> rows,
        byte[] qualification,
        bool includeQualification,
        byte[] digest,
        uint maxActionsPerTransaction,
        ulong committedHeight,
        byte[]? pendingConsensus = null)
    {
        return NoritoCodec.Encode(
            PrivacyExact12CapabilityManifestCodecV1.ManifestSchemaName,
            Struct(
                U32(1),
                U64(committedHeight),
                ConsensusPolicy(maxActionsPerTransaction, pendingConsensus),
                Option(qualification, includeQualification),
                Sequence(rows),
                Struct(digest)),
            NoritoCodec.CanonicalLayoutFlags);
    }

    private static byte[] ComputeManifestDigest(byte[] normalizedArchive)
    {
        var domain = Encoding.UTF8.GetBytes(
            "iroha:privacy:exact12-capability-manifest:v1");
        Span<byte> length = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(length, checked((ulong)normalizedArchive.Length));
        var input = new byte[domain.Length + length.Length + normalizedArchive.Length];
        domain.CopyTo(input, 0);
        length.CopyTo(input.AsSpan(domain.Length));
        normalizedArchive.CopyTo(input, domain.Length + length.Length);
        return SHA256.HashData(input);
    }

    private static byte[] Struct(params byte[][] fields)
    {
        var writer = new CanonicalNoritoWriter();
        foreach (var field in fields)
        {
            writer.WriteField(field);
        }
        return writer.ToArray();
    }

    private static byte[] Sequence(IReadOnlyList<byte[]> values)
    {
        var writer = new CanonicalNoritoWriter();
        writer.WriteSequenceLength(checked((ulong)values.Count));
        foreach (var value in values)
        {
            writer.WriteField(value);
        }
        return writer.ToArray();
    }

    private static byte[] EnumValue(uint tag, params byte[][] fields)
    {
        var writer = new CanonicalNoritoWriter();
        writer.WriteUInt32LittleEndian(tag);
        foreach (var field in fields)
        {
            writer.WriteField(field);
        }
        return writer.ToArray();
    }

    private static byte[] UnavailableReadiness(uint reasonTag, byte[]? detail = null) =>
        EnumValue(
            1,
            detail is null
                ? EnumValue(reasonTag)
                : EnumValue(reasonTag, detail));

    private static byte[] Option(byte[] value, bool present)
    {
        var writer = new CanonicalNoritoWriter();
        writer.WriteByte(present ? (byte)1 : (byte)0);
        if (present)
        {
            writer.WriteField(value);
        }
        return writer.ToArray();
    }

    private static byte[] U32(uint value)
    {
        var writer = new CanonicalNoritoWriter();
        writer.WriteUInt32LittleEndian(value);
        return writer.ToArray();
    }

    private static byte[] U16(ushort value)
    {
        var writer = new CanonicalNoritoWriter();
        writer.WriteUInt16LittleEndian(value);
        return writer.ToArray();
    }

    private static byte[] U64(ulong value)
    {
        var writer = new CanonicalNoritoWriter();
        writer.WriteUInt64LittleEndian(value);
        return writer.ToArray();
    }

    private static byte[] CompactString(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        var writer = new CanonicalNoritoWriter();
        writer.WriteCompactLength(checked((ulong)bytes.Length));
        writer.WriteBytes(bytes);
        return writer.ToArray();
    }

    private sealed record Fixture(byte[] Manifest, byte[] Catalog, byte[][] CompiledProfiles);
}
