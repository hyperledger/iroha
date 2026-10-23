using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Hyperledger.Iroha.Norito;
using Hyperledger.Iroha.Torii;

namespace Hyperledger.Iroha.Privacy;

/// <summary>Closed public operation schema carried by an Exact12 capability row.</summary>
public enum PrivacyOperationSchemaV1 : uint
{
    ZkAceAuthorizationActionV1 = 0,
    AnonymousPgcPaymentActionV1 = 1,
    VeRangeRangeProofV1 = 2,
    ZkAmsAdmissionAndProvisioningV1 = 3,
    VegaCredentialPresentationV1 = 4,
    ZkX509IdentityPresentationV1 = 5,
    JindoPolynomialEvaluationV1 = 6,
    BootleLanternCredentialPresentationV1 = 7,
    OrchardNoteActionV1 = 8,
    FcmpMembershipPaymentV1 = 9,
    IvmPrivateNoteActionV1 = 10,
    PqMaspNoteActionV1 = 11,
}

/// <summary>Closed execution classification carried by an Exact12 capability row.</summary>
public enum PrivacyExecutionModeV1 : uint
{
    AuthorizationAction = 0,
    PaymentAction = 1,
    Component = 2,
    AdmissionAction = 3,
    PresentationAction = 4,
    NoteAction = 5,
}

/// <summary>Evidence-derived readiness projected from compiled and committed governance state.</summary>
public enum PrivacyCapabilityReadinessV1
{
    ProductionQualified,
    Unavailable,
}

/// <summary>Evidence-derived reason why an Exact12 protocol is unavailable.</summary>
public enum PrivacyCapabilityUnavailableReasonV1
{
    CompiledProfile,
    NotRegistered,
    Proposed,
    Suspended,
    Retired,
    MissingProductionQualification,
    InvalidProductionQualification,
}

/// <summary>Exact portable release tuple for one retained protocol.</summary>
public sealed class PrivacyReleaseProtocolBindingV1
{
    private readonly byte[] parameterId;
    private readonly byte[] parameterDigest;
    private readonly byte[] verifierDigest;
    private readonly byte[] statementSchemaDigest;
    private readonly byte[] engineManifestDigest;
    private readonly byte[] securityClaimDigest;

    internal PrivacyReleaseProtocolBindingV1(
        PrivacyProtocolIdV1 protocolId,
        uint proofSystemId,
        uint engineId,
        byte[] parameterId,
        byte[] parameterDigest,
        byte[] verifierDigest,
        byte[] statementSchemaDigest,
        byte[] engineManifestDigest,
        byte[] securityClaimDigest)
    {
        ProtocolId = protocolId;
        ProofSystemId = proofSystemId;
        EngineId = engineId;
        this.parameterId = (byte[])parameterId.Clone();
        this.parameterDigest = (byte[])parameterDigest.Clone();
        this.verifierDigest = (byte[])verifierDigest.Clone();
        this.statementSchemaDigest = (byte[])statementSchemaDigest.Clone();
        this.engineManifestDigest = (byte[])engineManifestDigest.Clone();
        this.securityClaimDigest = (byte[])securityClaimDigest.Clone();
    }

    public PrivacyProtocolIdV1 ProtocolId { get; }
    public uint ProofSystemId { get; }
    public uint EngineId { get; }
    public byte[] ParameterId => (byte[])parameterId.Clone();
    public byte[] ParameterDigest => (byte[])parameterDigest.Clone();
    public byte[] VerifierDigest => (byte[])verifierDigest.Clone();
    public byte[] StatementSchemaDigest => (byte[])statementSchemaDigest.Clone();
    public byte[] EngineManifestDigest => (byte[])engineManifestDigest.Clone();
    public byte[] SecurityClaimDigest => (byte[])securityClaimDigest.Clone();
}

/// <summary>Full portable release evidence retained from native-validated bytes.</summary>
public sealed class PrivacyExact12ReleaseManifestV1
{
    private readonly byte[] catalogCommitment;
    private readonly byte[] manifestDigest;
    private readonly byte[] canonicalBytes;

    internal PrivacyExact12ReleaseManifestV1(
        ushort version,
        byte[] catalogCommitment,
        ushort abiVersion,
        IReadOnlyList<PrivacyReleaseProtocolBindingV1> protocols,
        byte[] manifestDigest,
        byte[] canonicalBytes)
    {
        Version = version;
        this.catalogCommitment = (byte[])catalogCommitment.Clone();
        AbiVersion = abiVersion;
        Protocols = new ReadOnlyCollection<PrivacyReleaseProtocolBindingV1>(protocols.ToArray());
        this.manifestDigest = (byte[])manifestDigest.Clone();
        this.canonicalBytes = (byte[])canonicalBytes.Clone();
    }

    public ushort Version { get; }
    public byte[] CatalogCommitment => (byte[])catalogCommitment.Clone();
    public ushort AbiVersion { get; }
    public IReadOnlyList<PrivacyReleaseProtocolBindingV1> Protocols { get; }
    public byte[] ManifestDigest => (byte[])manifestDigest.Clone();
    public byte[] CanonicalBytes => (byte[])canonicalBytes.Clone();
}

/// <summary>One protocol activation height bound by deployment evidence.</summary>
public sealed record PrivacyDeploymentActivationV1(
    PrivacyProtocolIdV1 ProtocolId,
    ulong ActivationHeight);

/// <summary>Full network deployment evidence retained from native-validated bytes.</summary>
public sealed class PrivacyExact12DeploymentQualificationV1
{
    private readonly byte[] releaseManifestDigest;
    private readonly byte[] qualificationDigest;
    private readonly byte[] canonicalBytes;

    internal PrivacyExact12DeploymentQualificationV1(
        ushort version,
        NetworkId networkId,
        byte[] releaseManifestDigest,
        IReadOnlyList<PrivacyDeploymentActivationV1> activations,
        ulong convergenceHeight,
        byte[] qualificationDigest,
        byte[] canonicalBytes)
    {
        Version = version;
        NetworkId = networkId;
        this.releaseManifestDigest = (byte[])releaseManifestDigest.Clone();
        Activations = new ReadOnlyCollection<PrivacyDeploymentActivationV1>(activations.ToArray());
        ConvergenceHeight = convergenceHeight;
        this.qualificationDigest = (byte[])qualificationDigest.Clone();
        this.canonicalBytes = (byte[])canonicalBytes.Clone();
    }

    public ushort Version { get; }
    /// <summary>Exact genesis-derived network authenticated by the deployment evidence.</summary>
    public NetworkId NetworkId { get; }
    public byte[] ReleaseManifestDigest => (byte[])releaseManifestDigest.Clone();
    public IReadOnlyList<PrivacyDeploymentActivationV1> Activations { get; }
    public ulong ConvergenceHeight { get; }
    public byte[] QualificationDigest => (byte[])qualificationDigest.Clone();
    public byte[] CanonicalBytes => (byte[])canonicalBytes.Clone();
}

/// <summary>Singleton release and target-network evidence from committed state.</summary>
public sealed record PrivacyExact12QualificationRecordV1(
    PrivacyExact12ReleaseManifestV1 ReleaseManifest,
    PrivacyExact12DeploymentQualificationV1 DeploymentQualification);

/// <summary>Typed reason why this binary has no complete executable profile.</summary>
public enum PrivacyCompiledProfileUnavailableReasonV1
{
    EngineUnavailable,
    ProfileInitializationFailed,
    StatementSchemaInvalid,
}

/// <summary>Typed failure while canonicalizing a compiled public-statement schema.</summary>
public enum PrivacyCompiledStatementSchemaErrorV1
{
    ConflictingStableTypeId,
    MissingTypeReference,
}

/// <summary>Bounded manifest-validation result. It is not native release authority.</summary>
public enum PrivacyExact12CapabilityManifestValidationStatusV1
{
    Valid = 0,
    Empty = 1,
    ArchiveTooLarge = 2,
    NativeUnavailable = 3,
    InvalidManifest = 4,
    LocalCompiledTupleMismatch = 5,
}

/// <summary>Strict canonical or semantic manifest validation failure.</summary>
public class PrivacyExact12CapabilityManifestException : IOException
{
    internal PrivacyExact12CapabilityManifestException(string message)
        : base(message)
    {
    }
}

/// <summary>One validated row from the committed Exact12 capability manifest.</summary>
public sealed class PrivacyExact12CapabilityRowV1
{
    private readonly byte[] compiledProfile;
    private readonly byte[] activation;

    internal PrivacyExact12CapabilityRowV1(
        PrivacyProtocolIdV1 protocolId,
        PrivacyOperationSchemaV1 operationSchema,
        PrivacyExecutionModeV1 executionMode,
        byte privacyFeatureMask,
        PrivacyCapabilityReadinessV1 readiness,
        PrivacyCapabilityUnavailableReasonV1? unavailableReason,
        PrivacyCompiledProfileUnavailableReasonV1? compiledProfileUnavailableReason,
        PrivacyCompiledStatementSchemaErrorV1? compiledStatementSchemaError,
        byte[] compiledProfile,
        byte[] activation,
        bool localCompiledTupleMatches)
    {
        ProtocolId = protocolId;
        OperationSchema = operationSchema;
        ExecutionMode = executionMode;
        PrivacyFeatureMask = privacyFeatureMask;
        Readiness = readiness;
        UnavailableReason = unavailableReason;
        CompiledProfileUnavailableReason = compiledProfileUnavailableReason;
        CompiledStatementSchemaError = compiledStatementSchemaError;
        this.compiledProfile = (byte[])compiledProfile.Clone();
        this.activation = (byte[])activation.Clone();
        LocalCompiledTupleMatches = localCompiledTupleMatches;
    }

    public PrivacyProtocolIdV1 ProtocolId { get; }

    public PrivacyOperationSchemaV1 OperationSchema { get; }

    public PrivacyExecutionModeV1 ExecutionMode { get; }

    public byte PrivacyFeatureMask { get; }

    public PrivacyCapabilityReadinessV1 Readiness { get; }

    /// <summary>Exact typed reason when <see cref="Readiness"/> is unavailable.</summary>
    public PrivacyCapabilityUnavailableReasonV1? UnavailableReason { get; }

    /// <summary>Nested compiled-profile reason when <see cref="UnavailableReason"/> is compiled profile.</summary>
    public PrivacyCompiledProfileUnavailableReasonV1? CompiledProfileUnavailableReason { get; }

    /// <summary>Nested schema error when the compiled profile's statement schema is invalid.</summary>
    public PrivacyCompiledStatementSchemaErrorV1? CompiledStatementSchemaError { get; }

    /// <summary>
    /// True only after byte-exact comparison with the native-validated local compiled catalog.
    /// </summary>
    public bool LocalCompiledTupleMatches { get; }

    /// <summary>Defensive copy of the canonical committed compiled-profile result field.</summary>
    public byte[] CompiledProfileCanonicalBytes => (byte[])compiledProfile.Clone();

    /// <summary>
    /// Defensive copy of the complete canonical committed activation option, including immutable
    /// profile bindings, lifecycle, and current and pending limits.
    /// </summary>
    public byte[] ActivationCanonicalBytes => (byte[])activation.Clone();

    /// <summary>Network availability is exactly committed production qualification.</summary>
    public bool IsNetworkAvailable =>
        Readiness == PrivacyCapabilityReadinessV1.ProductionQualified;
}

/// <summary>
/// Native-tuple-matched canonical manifest obtained from authenticated Torii transport.
/// </summary>
/// <remarks>
/// <see cref="ManifestDigest"/> is content identity, not producer authentication. Public instances
/// can only be issued by the HTTPS, canonical-request-authenticated Torii fetch path.
/// </remarks>
public sealed class PrivacyExact12CapabilityManifestV1
{
    public const uint VersionV1 = 1;
    public const int MaxArchiveBytes = 256 * 1024;

    private const string CapabilitiesPath = "/v1/privacy/capabilities";
    private const string NoritoMediaType = "application/x-norito";

    private readonly byte[] canonicalArchive;
    private readonly byte[] consensusPolicy;
    private readonly byte[] manifestDigest;

    private PrivacyExact12CapabilityManifestV1(
        uint version,
        ulong committedHeight,
        byte[] consensusPolicy,
        PrivacyExact12QualificationRecordV1? qualification,
        IReadOnlyList<PrivacyExact12CapabilityRowV1> protocols,
        byte[] manifestDigest,
        byte[] canonicalArchive,
        NetworkId networkId)
    {
        NetworkId = networkId;
        Version = version;
        CommittedHeight = committedHeight;
        this.consensusPolicy = (byte[])consensusPolicy.Clone();
        Qualification = qualification;
        Protocols = new ReadOnlyCollection<PrivacyExact12CapabilityRowV1>(protocols.ToArray());
        this.manifestDigest = (byte[])manifestDigest.Clone();
        this.canonicalArchive = (byte[])canonicalArchive.Clone();
    }

    public uint Version { get; }

    /// <summary>Immutable expected network from the authenticated Torii client.</summary>
    public NetworkId NetworkId { get; }

    public ulong CommittedHeight { get; }

    public PrivacyExact12QualificationRecordV1? Qualification { get; }

    public IReadOnlyList<PrivacyExact12CapabilityRowV1> Protocols { get; }

    public byte[] ManifestDigest => (byte[])manifestDigest.Clone();

    public byte[] ConsensusPolicyCanonicalBytes => (byte[])consensusPolicy.Clone();

    public byte[] CanonicalBytes => (byte[])canonicalArchive.Clone();

    public PrivacyExact12CapabilityRowV1 RowFor(PrivacyProtocolIdV1 protocol)
    {
        var tag = (uint)protocol;
        if (tag >= Protocols.Count)
        {
            throw new ArgumentOutOfRangeException(nameof(protocol));
        }
        var index = (int)tag;
        if (Protocols[index].ProtocolId != protocol)
        {
            throw new InvalidOperationException("Exact12 protocol registry order drifted.");
        }
        return Protocols[index];
    }

    /// <summary>
    /// Authority-bearing construction is intentionally confined to this method: it takes a
    /// configured Torii client, never caller-supplied manifest or catalog bytes.
    /// </summary>
    internal static async Task<PrivacyExact12CapabilityManifestV1> FetchAuthenticatedToriiAsync(
        ToriiClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (!string.Equals(client.BaseUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Exact12 privacy capabilities require an HTTPS Torii endpoint.");
        }
        if (client.Options.CanonicalRequestCredentials is null)
        {
            throw new InvalidOperationException(
                "Exact12 privacy capabilities require canonical request credentials.");
        }

        var expectedNetworkId = client.Options.NetworkId ?? throw new InvalidOperationException(
            "Exact12 privacy capabilities require the configured exact network identity.");

        // Resolve and native-validate the immutable local tuple before any authority-bearing read.
        var localCatalog = PrivacyNative.CompiledProfileCatalogV1().NoritoBytes;
        var expectedUri = new Uri(client.BaseUri, CapabilitiesPath.TrimStart('/'));
        using var response = await client.SendAsync(
            HttpMethod.Get,
            CapabilitiesPath,
            content: null,
            accept: NoritoMediaType,
            cancellationToken: cancellationToken);
        if (response.RequestMessage?.RequestUri is not Uri responseUri
            || !string.Equals(responseUri.AbsoluteUri, expectedUri.AbsoluteUri, StringComparison.Ordinal))
        {
            throw new HttpRequestException(
                "Exact12 privacy capability requests must not follow redirects.");
        }
        RequireExactNoritoContentType(response.Content.Headers.ContentType);
        var archive = await ReadBoundedManifestAsync(response.Content, cancellationToken);
        PrivacyNative.RequireValidCapabilityArchive(archive);
        var decoded = PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
            archive,
            localCatalog);
        PrivacyExact12CapabilityManifestCodecV1.RequireDeploymentNetwork(
            decoded.Qualification, expectedNetworkId);
        return new PrivacyExact12CapabilityManifestV1(
            decoded.Version,
            decoded.CommittedHeight,
            decoded.ConsensusPolicy,
            decoded.Qualification,
            decoded.Protocols,
            decoded.ManifestDigest,
            decoded.CanonicalArchive,
            expectedNetworkId);
    }

    private static void RequireExactNoritoContentType(MediaTypeHeaderValue? contentType)
    {
        if (contentType is null
            || !string.Equals(contentType.MediaType, NoritoMediaType, StringComparison.Ordinal)
            || contentType.Parameters.Count != 0)
        {
            throw new InvalidDataException(
                "Exact12 privacy capabilities require exact application/x-norito content.");
        }
    }

    private static async Task<byte[]> ReadBoundedManifestAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        var declaredLength = content.Headers.ContentLength;
        if (!declaredLength.HasValue
            || declaredLength.Value <= 0
            || declaredLength.Value > MaxArchiveBytes)
        {
            throw new InvalidDataException(
                "Exact12 privacy capability Content-Length is absent or outside its bound.");
        }

        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream(checked((int)declaredLength.Value));
        var buffer = new byte[8192];
        while (true)
        {
            var count = await stream.ReadAsync(buffer, cancellationToken);
            if (count == 0)
            {
                break;
            }
            if (output.Length > MaxArchiveBytes - count)
            {
                throw new InvalidDataException(
                    "Exact12 privacy capability response exceeds its byte bound.");
            }
            output.Write(buffer, 0, count);
        }
        if (output.Length != declaredLength.Value)
        {
            throw new InvalidDataException(
                "Exact12 privacy capability response length differs from Content-Length.");
        }
        return output.ToArray();
    }
}

/// <summary>Opaque admission token issued only after committed/native tuple agreement.</summary>
public sealed class PrivacyExact12CapabilityTupleAdmissionV1
{
    private static readonly object AdmissionSeal = new();
    private readonly byte[] manifestDigest;
    private readonly byte[] manifestArchive;
    private readonly object seal;

    private PrivacyExact12CapabilityTupleAdmissionV1(
        PrivacyProtocolIdV1 protocolId,
        ulong committedHeight,
        byte[] manifestDigest,
        PrivacyOperationSchemaV1 operationSchema,
        NetworkId networkId,
        byte[] manifestArchive)
    {
        NetworkId = networkId;
        this.manifestArchive = (byte[])manifestArchive.Clone();
        ProtocolId = protocolId;
        CommittedHeight = committedHeight;
        this.manifestDigest = (byte[])manifestDigest.Clone();
        OperationSchema = operationSchema;
        seal = AdmissionSeal;
    }

    public PrivacyProtocolIdV1 ProtocolId { get; }

    public ulong CommittedHeight { get; }

    public byte[] ManifestDigest => (byte[])manifestDigest.Clone();

    public PrivacyOperationSchemaV1 OperationSchema { get; }

    /// <summary>Exact network this token may authorize at construction time.</summary>
    public NetworkId NetworkId { get; }

    internal static PrivacyExact12CapabilityTupleAdmissionV1 IssueValidated(
        PrivacyExact12CapabilityManifestV1 manifest,
        PrivacyProtocolIdV1 protocol)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        _ = manifest.RowFor(protocol);
        PrivacyNative.RequireValidCapabilityArchive(manifest.CanonicalBytes);
        var decoded = PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
            manifest.CanonicalBytes, PrivacyNative.CompiledProfileCatalogV1().NoritoBytes);
        PrivacyExact12CapabilityManifestCodecV1.RequireDeploymentNetwork(
            decoded.Qualification, manifest.NetworkId, requireQualification: true);
        var row = decoded.Protocols[checked((int)protocol)];
        if (!row.IsNetworkAvailable)
        {
            throw new InvalidOperationException(
                $"Exact12 protocol {protocol.CanonicalLabel()} is not active and ready.");
        }
        if (!row.LocalCompiledTupleMatches)
        {
            throw new InvalidOperationException(
                "Exact12 committed profile differs from CompiledProfileCatalogV1.");
        }
        return new PrivacyExact12CapabilityTupleAdmissionV1(
            row.ProtocolId,
            manifest.CommittedHeight,
            manifest.ManifestDigest,
            row.OperationSchema,
            manifest.NetworkId,
            manifest.CanonicalBytes);
    }

    internal void RequireAuthentic(PrivacyProtocolIdV1 protocol, NetworkId expectedNetworkId)
    {
        if (!ReferenceEquals(seal, AdmissionSeal) || ProtocolId != protocol
            || !NetworkId.Equals(expectedNetworkId))
        {
            throw new InvalidOperationException(
                "Exact12 capability admission is absent, invalid, or protocol/network-substituted.");
        }
        PrivacyNative.RequireValidCapabilityArchive(manifestArchive);
        var decoded = PrivacyExact12CapabilityManifestCodecV1.DecodeValidated(
            manifestArchive, PrivacyNative.CompiledProfileCatalogV1().NoritoBytes);
        PrivacyExact12CapabilityManifestCodecV1.RequireDeploymentNetwork(
            decoded.Qualification, expectedNetworkId, requireQualification: true);
        var row = decoded.Protocols[checked((int)protocol)];
        if (decoded.CommittedHeight != CommittedHeight
            || !decoded.ManifestDigest.AsSpan().SequenceEqual(manifestDigest)
            || !row.IsNetworkAvailable || !row.LocalCompiledTupleMatches)
        {
            throw new InvalidOperationException("Exact12 capability admission no longer validates.");
        }
    }
}

/// <summary>Fail-closed bridge from authenticated committed state to privacy construction.</summary>
public static class PrivacyExact12CapabilityAdmissionV1
{
    /// <summary>Require active committed readiness and the exact local native tuple.</summary>
    public static PrivacyExact12CapabilityTupleAdmissionV1 RequireExact12CapabilityTupleV1(
        PrivacyExact12CapabilityManifestV1 manifest,
        PrivacyProtocolIdV1 protocol)
    {
        return PrivacyExact12CapabilityTupleAdmissionV1.IssueValidated(manifest, protocol);
    }

    /// <summary>Verify a sealed token immediately before retained privacy construction.</summary>
    public static void RequireForConstruction(
        PrivacyExact12CapabilityTupleAdmissionV1 admission,
        PrivacyProtocolIdV1 protocol,
        NetworkId expectedNetworkId)
    {
        ArgumentNullException.ThrowIfNull(admission);
        ArgumentNullException.ThrowIfNull(expectedNetworkId);
        admission.RequireAuthentic(protocol, expectedNetworkId);
    }
}

internal static class PrivacyExact12CapabilityManifestCodecV1
{
    internal const string ManifestSchemaName =
        "iroha.privacy.exact12-capability-manifest.v1";
    internal const string CatalogSchemaName =
        "iroha.privacy.compiled-profile-catalog.v1";
    private const string SecurityClaimSchemaName =
        "iroha_data_model::privacy::protocol::PrivacySecurityClaimV1";

    private const byte CanonicalFlags = NoritoCodec.CanonicalLayoutFlags;
    private const int RowCount = 12;

    private static readonly byte[] DigestDomain =
        Encoding.UTF8.GetBytes("iroha:privacy:exact12-capability-manifest:v1");

    private static readonly byte[] SecurityClaimDigestDomain =
        Encoding.UTF8.GetBytes("iroha:privacy:security-claim:v1");

    private static readonly byte[] Exact12CatalogCommitment = Convert.FromHexString(
        "5BCF366FB18D2E4361486C015DA5B41A3FB00EDF05611042CCC452120D176EB0");

    private static readonly PrivacyExecutionModeV1[] ExpectedExecutionModes =
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

    private static readonly byte[] ExpectedFeatureMasks =
    [
        0,
        6,
        1,
        2,
        2,
        2,
        0,
        2,
        7,
        2,
        7,
        31,
    ];

    private static readonly uint[] ExpectedProofSystems =
    [
        0,
        2,
        3,
        1,
        4,
        0,
        5,
        8,
        6,
        7,
        0,
        0,
    ];

    private static readonly uint[] ExpectedEngines =
    [
        0,
        2,
        3,
        1,
        4,
        0,
        5,
        8,
        6,
        7,
        0,
        0,
    ];

    private static readonly uint[] ExpectedSecurityModels =
    [
        0,
        1,
        1,
        1,
        1,
        1,
        0,
        0,
        1,
        1,
        0,
        0,
    ];

    internal static void Validate(byte[] archive, byte[] nativeValidatedCatalog) =>
        _ = Decode(archive, nativeValidatedCatalog);

    internal static DecodedManifest DecodeValidated(
        byte[] archive,
        byte[] nativeValidatedCatalog) => Decode(archive, nativeValidatedCatalog);

    private static DecodedManifest Decode(byte[] archive, byte[] nativeValidatedCatalog)
    {
        ArgumentNullException.ThrowIfNull(archive);
        ArgumentNullException.ThrowIfNull(nativeValidatedCatalog);
        if (archive.Length == 0 || archive.Length > PrivacyExact12CapabilityManifestV1.MaxArchiveBytes)
        {
            throw Invalid("Exact12 capability manifest length is outside its bound.");
        }

        var localProfiles = DecodeCatalog(nativeValidatedCatalog);
        var payload = DecodeExactArchive(ManifestSchemaName, archive);
        var reader = new FrameReader(payload);
        var version = ReadUInt32Field(ref reader, "manifest.version");
        if (version != PrivacyExact12CapabilityManifestV1.VersionV1)
        {
            throw Invalid("Exact12 capability manifest version must be 1.");
        }
        var committedHeight = ReadUInt64Field(ref reader, "manifest.committed_height");
        var consensusPolicy = reader.ReadField(
            "manifest.consensus_policy",
            out _).ToArray();
        ValidateConsensusPolicy(consensusPolicy, committedHeight);

        var qualification = ParseQualificationOption(
            reader.ReadField("manifest.qualification", out _));

        var protocolSequence = reader.ReadField("manifest.protocols", out _);
        var protocolReader = new FrameReader(protocolSequence);
        if (protocolReader.ReadUInt64Raw("manifest.protocols.length") != RowCount)
        {
            throw Invalid("Exact12 capability manifest must contain exactly twelve rows.");
        }

        var rows = new PrivacyExact12CapabilityRowV1[RowCount];
        for (var index = 0; index < RowCount; index++)
        {
            var row = protocolReader.ReadField($"manifest.protocols[{index}]", out _);
            rows[index] = DecodeRow(
                row,
                index,
                committedHeight,
                qualification,
                localProfiles[index]);
        }
        protocolReader.RequireEnd("manifest.protocols");

        var digestWrapper = reader.ReadField("manifest.manifest_digest", out var digestWrapperOffset);
        var digestReader = new FrameReader(digestWrapper);
        var digest = digestReader.ReadField("manifest.manifest_digest.value", out var digestOffset);
        if (digest.Length != 32)
        {
            throw Invalid("Exact12 manifest digest must contain exactly 32 bytes.");
        }
        digestReader.RequireEnd("manifest.manifest_digest");
        reader.RequireEnd("manifest");

        var normalizedPayload = (byte[])payload.Clone();
        normalizedPayload.AsSpan(digestWrapperOffset + digestOffset, 32).Clear();
        var normalizedArchive = NoritoCodec.Encode(
            ManifestSchemaName,
            normalizedPayload,
            CanonicalFlags);
        Span<byte> encodedLength = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(
            encodedLength,
            checked((ulong)normalizedArchive.Length));
        var digestInput = new byte[
            DigestDomain.Length + encodedLength.Length + normalizedArchive.Length];
        DigestDomain.CopyTo(digestInput, 0);
        encodedLength.CopyTo(digestInput.AsSpan(DigestDomain.Length));
        normalizedArchive.CopyTo(digestInput, DigestDomain.Length + encodedLength.Length);
        var computed = SHA256.HashData(digestInput);
        if (!CryptographicOperations.FixedTimeEquals(computed, digest))
        {
            throw Invalid("Exact12 manifest self-digest does not match canonical bytes.");
        }

        return new DecodedManifest(
            version,
            committedHeight,
            consensusPolicy,
            qualification,
            rows,
            digest.ToArray(),
            (byte[])archive.Clone());
    }

    private static byte[][] DecodeCatalog(byte[] archive)
    {
        if (archive.Length == 0 || archive.Length > PrivacyNative.PrivacyCompiledProfileCatalogArchiveMaxBytes)
        {
            throw Invalid("Native compiled-profile catalog length is outside its bound.");
        }
        var payload = DecodeExactArchive(CatalogSchemaName, archive);
        var reader = new FrameReader(payload);
        if (ReadUInt32Field(ref reader, "catalog.version") != 1)
        {
            throw Invalid("Native compiled-profile catalog version must be 1.");
        }
        var sequence = reader.ReadField("catalog.protocols", out _);
        reader.RequireEnd("catalog");
        var sequenceReader = new FrameReader(sequence);
        if (sequenceReader.ReadUInt64Raw("catalog.protocols.length") != RowCount)
        {
            throw Invalid("Native compiled-profile catalog must contain exactly twelve rows.");
        }
        var profiles = new byte[RowCount][];
        for (var index = 0; index < RowCount; index++)
        {
            var row = sequenceReader.ReadField($"catalog.protocols[{index}]", out _);
            var rowReader = new FrameReader(row);
            RequireUnitEnum(
                rowReader.ReadField($"catalog.protocols[{index}].protocol_id", out _),
                checked((uint)index),
                $"catalog.protocols[{index}].protocol_id");
            profiles[index] = rowReader.ReadField(
                $"catalog.protocols[{index}].compiled_profile",
                out _).ToArray();
            rowReader.RequireEnd($"catalog.protocols[{index}]");
        }
        sequenceReader.RequireEnd("catalog.protocols");
        return profiles;
    }

    private static PrivacyExact12CapabilityRowV1 DecodeRow(
        ReadOnlySpan<byte> encoded,
        int index,
        ulong committedHeight,
        PrivacyExact12QualificationRecordV1? qualification,
        byte[] localCompiledProfile)
    {
        var reader = new FrameReader(encoded);
        var protocol = (PrivacyProtocolIdV1)checked((uint)index);
        RequireUnitEnum(
            reader.ReadField($"row[{index}].protocol_id", out _),
            checked((uint)index),
            $"row[{index}].protocol_id");

        var operationSchema = (PrivacyOperationSchemaV1)ReadUnitEnum(
            reader.ReadField($"row[{index}].operation_schema", out _),
            $"row[{index}].operation_schema");
        if ((uint)operationSchema != (uint)index)
        {
            throw Invalid($"Exact12 row {index} operation schema is not canonical.");
        }

        var executionMode = (PrivacyExecutionModeV1)ReadUnitEnum(
            reader.ReadField($"row[{index}].execution_mode", out _),
            $"row[{index}].execution_mode");
        if (executionMode != ExpectedExecutionModes[index])
        {
            throw Invalid($"Exact12 row {index} execution mode is not canonical.");
        }

        var featureMask = ReadByteNewtype(
            reader.ReadField($"row[{index}].privacy_feature_mask", out _),
            $"row[{index}].privacy_feature_mask");
        if (featureMask != ExpectedFeatureMasks[index])
        {
            throw Invalid($"Exact12 row {index} privacy feature mask is not canonical.");
        }

        var compiledProfile = reader.ReadField(
            $"row[{index}].compiled_profile",
            out _).ToArray();
        if (!compiledProfile.AsSpan().SequenceEqual(localCompiledProfile))
        {
            throw new LocalTupleMismatchException(
                $"Exact12 row {index} differs from the native compiled-profile catalog.");
        }
        var compiled = ParseCompiledResult(compiledProfile, protocol, index);

        var readiness = ParseReadiness(
            reader.ReadField($"row[{index}].readiness", out _),
            index);

        var activation = reader.ReadField($"row[{index}].activation", out _).ToArray();
        var activationProjection = ParseActivation(
            activation,
            compiled,
            protocol,
            committedHeight,
            index);
        reader.RequireEnd($"row[{index}]");
        ValidateProjectedReadiness(
            readiness,
            compiled,
            activationProjection,
            qualification,
            committedHeight,
            index);

        return new PrivacyExact12CapabilityRowV1(
            protocol,
            operationSchema,
            executionMode,
            featureMask,
            readiness.Readiness,
            readiness.UnavailableReason,
            readiness.CompiledProfileUnavailableReason,
            readiness.CompiledStatementSchemaError,
            compiledProfile,
            activation,
            localCompiledTupleMatches: true);
    }

    private static CompiledResult ParseCompiledResult(
        ReadOnlySpan<byte> encoded,
        PrivacyProtocolIdV1 protocol,
        int index)
    {
        var reader = new FrameReader(encoded);
        var tag = reader.ReadUInt32Raw($"row[{index}].compiled_profile.status");
        if (tag == 1)
        {
            var reason = reader.ReadField($"row[{index}].compiled_profile.reason", out _).ToArray();
            var unavailable = ParseCompiledProfileUnavailableReason(reason, index);
            reader.RequireEnd($"row[{index}].compiled_profile");
            return new CompiledResult(
                false,
                reason,
                unavailable.Reason,
                unavailable.StatementSchemaError,
                null);
        }
        if (tag != 0)
        {
            throw Invalid($"Exact12 row {index} compiled-profile status is unknown.");
        }

        var profile = reader.ReadField($"row[{index}].compiled_profile.value", out _);
        reader.RequireEnd($"row[{index}].compiled_profile");
        var profileReader = new FrameReader(profile);
        var fields = new byte[9][];
        for (var field = 0; field < fields.Length; field++)
        {
            fields[field] = profileReader.ReadField(
                $"row[{index}].compiled_profile.value.field[{field}]",
                out _).ToArray();
        }
        profileReader.RequireEnd($"row[{index}].compiled_profile.value");
        RequireUnitEnum(fields[0], (uint)protocol, $"row[{index}].compiled_profile.protocol_id");
        RequireUnitEnum(
            fields[1],
            ExpectedProofSystems[index],
            $"row[{index}].compiled_profile.proof_system_id");
        RequireUnitEnum(
            fields[2],
            ExpectedEngines[index],
            $"row[{index}].compiled_profile.engine_id");
        for (var field = 3; field <= 7; field++)
        {
            RequireNonzeroDigestNewtype(
                fields[field],
                $"row[{index}].compiled_profile.digest[{field - 3}]");
        }
        _ = ParseProtocolLimits(fields[8], protocol, $"row[{index}].compiled_profile.protocol_limits");
        return new CompiledResult(true, null, null, null, fields);
    }

    private static ReadinessProjection ParseReadiness(
        ReadOnlySpan<byte> encoded,
        int index)
    {
        var reader = new FrameReader(encoded);
        var tag = reader.ReadUInt32Raw($"row[{index}].readiness.tag");
        if (tag == 0)
        {
            reader.RequireEnd($"row[{index}].readiness");
            return new ReadinessProjection(
                PrivacyCapabilityReadinessV1.ProductionQualified,
                null,
                null,
                null,
                null);
        }
        if (tag != 1)
        {
            throw Invalid($"Exact12 row {index} readiness discriminant is unknown.");
        }

        var reasonBytes = reader.ReadField($"row[{index}].readiness.reason", out _).ToArray();
        reader.RequireEnd($"row[{index}].readiness");
        var reasonReader = new FrameReader(reasonBytes);
        var reasonTag = reasonReader.ReadUInt32Raw($"row[{index}].readiness.reason.tag");
        if (reasonTag == 0)
        {
            var compiledReasonBytes = reasonReader.ReadField(
                $"row[{index}].readiness.reason.compiled_profile",
                out _).ToArray();
            reasonReader.RequireEnd($"row[{index}].readiness.reason");
            var compiledReason = ParseCompiledProfileUnavailableReason(compiledReasonBytes, index);
            return new ReadinessProjection(
                PrivacyCapabilityReadinessV1.Unavailable,
                PrivacyCapabilityUnavailableReasonV1.CompiledProfile,
                compiledReason.Reason,
                compiledReason.StatementSchemaError,
                compiledReasonBytes);
        }

        reasonReader.RequireEnd($"row[{index}].readiness.reason");
        var reason = reasonTag switch
        {
            1 => PrivacyCapabilityUnavailableReasonV1.NotRegistered,
            2 => PrivacyCapabilityUnavailableReasonV1.Proposed,
            3 => PrivacyCapabilityUnavailableReasonV1.Suspended,
            4 => PrivacyCapabilityUnavailableReasonV1.Retired,
            5 => PrivacyCapabilityUnavailableReasonV1.MissingProductionQualification,
            6 => PrivacyCapabilityUnavailableReasonV1.InvalidProductionQualification,
            _ => throw Invalid($"Exact12 row {index} readiness reason is unknown."),
        };
        return new ReadinessProjection(
            PrivacyCapabilityReadinessV1.Unavailable,
            reason,
            null,
            null,
            null);
    }

    private static CompiledUnavailableReason ParseCompiledProfileUnavailableReason(
        ReadOnlySpan<byte> encoded,
        int index)
    {
        var reader = new FrameReader(encoded);
        var tag = reader.ReadUInt32Raw($"row[{index}].compiled_profile.reason.tag");
        if (tag <= 1)
        {
            reader.RequireEnd($"row[{index}].compiled_profile.reason");
            return new CompiledUnavailableReason(
                tag == 0
                    ? PrivacyCompiledProfileUnavailableReasonV1.EngineUnavailable
                    : PrivacyCompiledProfileUnavailableReasonV1.ProfileInitializationFailed,
                null);
        }
        if (tag != 2)
        {
            throw Invalid($"Exact12 row {index} compiled-profile unavailable reason is unknown.");
        }

        var schemaError = reader.ReadField(
            $"row[{index}].compiled_profile.reason.schema_error",
            out _);
        reader.RequireEnd($"row[{index}].compiled_profile.reason");
        var schemaTag = ReadUnitEnum(
            schemaError,
            $"row[{index}].compiled_profile.reason.schema_error");
        var parsedSchemaError = schemaTag switch
        {
            0 => PrivacyCompiledStatementSchemaErrorV1.ConflictingStableTypeId,
            1 => PrivacyCompiledStatementSchemaErrorV1.MissingTypeReference,
            _ => throw Invalid($"Exact12 row {index} statement-schema error is unknown."),
        };
        return new CompiledUnavailableReason(
            PrivacyCompiledProfileUnavailableReasonV1.StatementSchemaInvalid,
            parsedSchemaError);
    }

    private static void ValidateProjectedReadiness(
        ReadinessProjection readiness,
        CompiledResult compiled,
        ActivationProjection? activation,
        PrivacyExact12QualificationRecordV1? qualification,
        ulong committedHeight,
        int index)
    {
        PrivacyCapabilityReadinessV1 expectedReadiness;
        PrivacyCapabilityUnavailableReasonV1? expectedReason;
        if (!compiled.IsAvailable)
        {
            expectedReadiness = PrivacyCapabilityReadinessV1.Unavailable;
            expectedReason = PrivacyCapabilityUnavailableReasonV1.CompiledProfile;
            if (activation is not null
                || readiness.CompiledProfileReasonCanonical is null
                || compiled.UnavailableReason is null
                || !readiness.CompiledProfileReasonCanonical.AsSpan().SequenceEqual(
                    compiled.UnavailableReason))
            {
                throw Invalid($"Exact12 row {index} readiness differs from its compiled failure.");
            }
        }
        else if (activation is null)
        {
            expectedReadiness = PrivacyCapabilityReadinessV1.Unavailable;
            expectedReason = PrivacyCapabilityUnavailableReasonV1.NotRegistered;
        }
        else
        {
            expectedReason = activation.Lifecycle switch
            {
                ProtocolLifecycle.Proposed => PrivacyCapabilityUnavailableReasonV1.Proposed,
                ProtocolLifecycle.Suspended => PrivacyCapabilityUnavailableReasonV1.Suspended,
                ProtocolLifecycle.Retired => PrivacyCapabilityUnavailableReasonV1.Retired,
                ProtocolLifecycle.Active when qualification is null =>
                    PrivacyCapabilityUnavailableReasonV1.MissingProductionQualification,
                ProtocolLifecycle.Active when !QualificationMatches(
                    qualification,
                    compiled,
                    activation,
                    committedHeight,
                    index) => PrivacyCapabilityUnavailableReasonV1.InvalidProductionQualification,
                ProtocolLifecycle.Active => null,
                _ => throw Invalid($"Exact12 row {index} lifecycle projection is unknown."),
            };
            expectedReadiness = expectedReason is null
                ? PrivacyCapabilityReadinessV1.ProductionQualified
                : PrivacyCapabilityReadinessV1.Unavailable;
        }

        if (readiness.Readiness != expectedReadiness
            || readiness.UnavailableReason != expectedReason)
        {
            throw Invalid(
                $"Exact12 row {index} readiness was not derived from compiled, lifecycle, and qualification evidence.");
        }
    }

    private static ActivationProjection? ParseActivation(
        ReadOnlySpan<byte> encoded,
        CompiledResult compiled,
        PrivacyProtocolIdV1 protocol,
        ulong committedHeight,
        int index)
    {
        var option = new FrameReader(encoded);
        var optionTag = option.ReadByteRaw($"row[{index}].activation.option");
        if (optionTag == 0)
        {
            option.RequireEnd($"row[{index}].activation");
            return null;
        }
        if (optionTag != 1)
        {
            throw Invalid($"Exact12 row {index} activation option tag is unknown.");
        }
        if (!compiled.IsAvailable || compiled.AvailableFields is null)
        {
            throw Invalid($"Exact12 row {index} cannot activate an unavailable profile.");
        }

        var activation = option.ReadField($"row[{index}].activation.value", out _);
        option.RequireEnd($"row[{index}].activation");
        var reader = new FrameReader(activation);
        var fields = new byte[11][];
        for (var field = 0; field < fields.Length; field++)
        {
            fields[field] = reader.ReadField(
                $"row[{index}].activation.value.field[{field}]",
                out _).ToArray();
        }
        reader.RequireEnd($"row[{index}].activation.value");
        for (var field = 0; field <= 7; field++)
        {
            if (!fields[field].AsSpan().SequenceEqual(compiled.AvailableFields[field]))
            {
                throw Invalid($"Exact12 row {index} activation binding field {field} drifted.");
            }
        }

        var ceiling = ParseProtocolLimits(
            compiled.AvailableFields[8],
            protocol,
            $"row[{index}].compiled_profile.protocol_limits");
        var current = ParseProtocolLimits(
            fields[9],
            protocol,
            $"row[{index}].activation.protocol_limits");
        RequireLimitCeiling(current, ceiling, $"row[{index}].activation.protocol_limits");
        ValidatePendingProtocolLimits(fields[10], current, protocol, committedHeight, index);
        var lifecycle = ParseLifecycle(fields[8], committedHeight, index);
        return new ActivationProjection(lifecycle.Lifecycle, lifecycle.ActivatedAtHeight);
    }

    private static LifecycleProjection ParseLifecycle(
        ReadOnlySpan<byte> encoded,
        ulong committedHeight,
        int index)
    {
        var reader = new FrameReader(encoded);
        var tag = reader.ReadUInt32Raw($"row[{index}].activation.lifecycle.state");
        if (tag > 3)
        {
            throw Invalid($"Exact12 row {index} lifecycle state is unknown.");
        }
        var record = reader.ReadField($"row[{index}].activation.lifecycle.record", out _);
        reader.RequireEnd($"row[{index}].activation.lifecycle");
        var fields = new FrameReader(record);
        var proposed = ReadUInt64Field(ref fields, $"row[{index}].lifecycle.proposed_at_height");
        if (proposed == 0 || proposed > committedHeight)
        {
            throw Invalid($"Exact12 row {index} lifecycle proposal height is invalid.");
        }

        if (tag == 0)
        {
            fields.RequireEnd($"row[{index}].lifecycle");
            return new LifecycleProjection(ProtocolLifecycle.Proposed, null);
        }

        ulong? activated;
        if (tag == 3)
        {
            activated = ReadOptionalUInt64Field(
                ref fields,
                $"row[{index}].lifecycle.activated_at_height");
        }
        else
        {
            activated = ReadUInt64Field(
                ref fields,
                $"row[{index}].lifecycle.activated_at_height");
        }
        var stateSince = ReadUInt64Field(ref fields, $"row[{index}].lifecycle.state_since_height");
        fields.RequireEnd($"row[{index}].lifecycle");
        if (stateSince == 0 || stateSince > committedHeight)
        {
            throw Invalid($"Exact12 row {index} lifecycle state height is invalid.");
        }
        if (activated.HasValue)
        {
            if (activated.Value < proposed || activated.Value > committedHeight)
            {
                throw Invalid($"Exact12 row {index} activation height is invalid.");
            }
            var validStateOrder = tag == 1
                ? stateSince >= activated.Value
                : stateSince > activated.Value;
            if (!validStateOrder)
            {
                throw Invalid($"Exact12 row {index} lifecycle state ordering is invalid.");
            }
        }
        else if (tag != 3 || stateSince <= proposed)
        {
            throw Invalid($"Exact12 row {index} retired lifecycle ordering is invalid.");
        }

        var lifecycle = tag switch
        {
            1 => ProtocolLifecycle.Active,
            2 => ProtocolLifecycle.Suspended,
            _ => ProtocolLifecycle.Retired,
        };
        return new LifecycleProjection(lifecycle, activated);
    }

    private static PrivacyExact12QualificationRecordV1? ParseQualificationOption(
        ReadOnlySpan<byte> encoded)
    {
        var option = new FrameReader(encoded);
        var tag = option.ReadByteRaw("manifest.qualification.option");
        if (tag == 0)
        {
            option.RequireEnd("manifest.qualification");
            return null;
        }
        if (tag != 1)
        {
            throw Invalid("Exact12 qualification option tag is unknown.");
        }
        var value = option.ReadField("manifest.qualification.value", out _).ToArray();
        option.RequireEnd("manifest.qualification");
        return ParseQualification(value);
    }

    private static PrivacyExact12QualificationRecordV1 ParseQualification(byte[] encoded)
    {
        var record = new FrameReader(encoded);
        var releaseBytes = record.ReadField("qualification.release_manifest", out _).ToArray();
        var deploymentBytes = record.ReadField(
            "qualification.deployment_qualification",
            out _).ToArray();
        record.RequireEnd("qualification");
        var release = ParseReleaseManifest(releaseBytes);
        var deployment = ParseDeploymentQualification(deploymentBytes);
        if (!CryptographicOperations.FixedTimeEquals(
            release.ManifestDigest,
            deployment.ReleaseManifestDigest))
        {
            throw Invalid("Deployment qualification names a different release manifest.");
        }
        return new PrivacyExact12QualificationRecordV1(release, deployment);
    }

    private static PrivacyExact12ReleaseManifestV1 ParseReleaseManifest(byte[] encoded)
    {
        var reader = new FrameReader(encoded);
        var version = ReadUInt16Field(ref reader, "qualification.release.version");
        if (version != 1)
        {
            throw Invalid("Exact12 release version must be 1.");
        }
        var catalogIdBytes = reader.ReadField("qualification.release.catalog_id", out _);
        var catalogIdReader = new FrameReader(catalogIdBytes);
        var catalogId = catalogIdReader.ReadCompactString("qualification.release.catalog_id");
        catalogIdReader.RequireEnd("qualification.release.catalog_id");
        if (!string.Equals(catalogId, "iroha-privacy-exact12-v1", StringComparison.Ordinal))
        {
            throw Invalid("Exact12 release catalog id is unknown.");
        }
        var catalogCommitment = reader.ReadField(
            "qualification.release.catalog_commitment",
            out _).ToArray();
        if (!catalogCommitment.AsSpan().SequenceEqual(Exact12CatalogCommitment))
        {
            throw Invalid("Exact12 release catalog commitment is unknown.");
        }
        _ = reader.ReadField("qualification.release.source", out _);
        var abiVersion = ReadUInt16Field(ref reader, "qualification.release.abi_version");
        if (abiVersion != 1)
        {
            throw Invalid("Exact12 release ABI version must be 1.");
        }
        _ = ReadNonzeroDigestNewtype(
            reader.ReadField("qualification.release.abi_hash", out _),
            "qualification.release.abi_hash");
        _ = ReadNonzeroDigestNewtype(
            reader.ReadField("qualification.release.syscall_list_digest", out _),
            "qualification.release.syscall_list_digest");
        _ = reader.ReadField("qualification.release.executables", out _);
        var protocolsBytes = reader.ReadField(
            "qualification.release.protocols",
            out _).ToArray();
        _ = reader.ReadField("qualification.release.stage_receipts", out _);
        _ = reader.ReadField("qualification.release.proof_artifacts", out _);
        _ = reader.ReadField("qualification.release.sdk_packages", out _);
        _ = reader.ReadField("qualification.release.hardware_results", out _);
        _ = ReadNonzeroDigestNewtype(
            reader.ReadField("qualification.release.release_artifact_set_digest", out _),
            "qualification.release.release_artifact_set_digest");
        _ = reader.ReadField("qualification.release.audits", out _);
        var auditBundleDigest = ReadNonzeroDigestNewtype(
            reader.ReadField("qualification.release.audit_bundle_digest", out _),
            "qualification.release.audit_bundle_digest");
        _ = reader.ReadField("qualification.release.release_signatures", out _);
        var manifestDigest = ReadNonzeroDigestNewtype(
            reader.ReadField("qualification.release.manifest_digest", out _),
            "qualification.release.manifest_digest");
        reader.RequireEnd("qualification.release");

        var protocolsReader = new FrameReader(protocolsBytes);
        if (protocolsReader.ReadUInt64Raw("qualification.release.protocols.length") != RowCount)
        {
            throw Invalid("Exact12 release must bind exactly twelve protocols.");
        }
        var protocols = new PrivacyReleaseProtocolBindingV1[RowCount];
        for (var index = 0; index < RowCount; index++)
        {
            protocols[index] = ParseReleaseBinding(
                protocolsReader.ReadField(
                    $"qualification.release.protocols[{index}]",
                    out _),
                index,
                auditBundleDigest);
        }
        protocolsReader.RequireEnd("qualification.release.protocols");
        return new PrivacyExact12ReleaseManifestV1(
            version,
            catalogCommitment,
            abiVersion,
            protocols,
            manifestDigest,
            encoded);
    }

    private static PrivacyReleaseProtocolBindingV1 ParseReleaseBinding(
        ReadOnlySpan<byte> encoded,
        int index,
        byte[] auditBundleDigest)
    {
        var reader = new FrameReader(encoded);
        var protocol = (PrivacyProtocolIdV1)checked((uint)index);
        RequireUnitEnum(
            reader.ReadField($"qualification.release.protocols[{index}].protocol_id", out _),
            checked((uint)index),
            $"qualification.release.protocols[{index}].protocol_id");
        var proofSystemId = ReadUnitEnum(
            reader.ReadField($"qualification.release.protocols[{index}].proof_system_id", out _),
            $"qualification.release.protocols[{index}].proof_system_id");
        var engineId = ReadUnitEnum(
            reader.ReadField($"qualification.release.protocols[{index}].engine_id", out _),
            $"qualification.release.protocols[{index}].engine_id");
        if (proofSystemId != ExpectedProofSystems[index] || engineId != ExpectedEngines[index])
        {
            throw Invalid($"Exact12 release protocol {index} differs from the final tuple.");
        }
        var parameterId = ReadNonzeroDigestNewtype(
            reader.ReadField($"qualification.release.protocols[{index}].parameter_id", out _),
            $"qualification.release.protocols[{index}].parameter_id");
        var parameterDigest = ReadNonzeroDigestNewtype(
            reader.ReadField($"qualification.release.protocols[{index}].parameter_digest", out _),
            $"qualification.release.protocols[{index}].parameter_digest");
        var verifierDigest = ReadNonzeroDigestNewtype(
            reader.ReadField($"qualification.release.protocols[{index}].verifier_digest", out _),
            $"qualification.release.protocols[{index}].verifier_digest");
        var statementSchemaDigest = ReadNonzeroDigestNewtype(
            reader.ReadField(
                $"qualification.release.protocols[{index}].statement_schema_digest",
                out _),
            $"qualification.release.protocols[{index}].statement_schema_digest");
        var engineManifestDigest = ReadNonzeroDigestNewtype(
            reader.ReadField(
                $"qualification.release.protocols[{index}].engine_manifest_digest",
                out _),
            $"qualification.release.protocols[{index}].engine_manifest_digest");
        var claim = reader.ReadField(
            $"qualification.release.protocols[{index}].security_claim",
            out _).ToArray();
        var claimAuditDigest = ValidateSecurityClaim(
            claim,
            protocol,
            parameterDigest,
            verifierDigest,
            index);
        if (!CryptographicOperations.FixedTimeEquals(claimAuditDigest, auditBundleDigest))
        {
            throw Invalid($"Exact12 release protocol {index} names another audit bundle.");
        }
        var securityClaimDigest = ReadNonzeroDigestNewtype(
            reader.ReadField(
                $"qualification.release.protocols[{index}].security_claim_digest",
                out _),
            $"qualification.release.protocols[{index}].security_claim_digest");
        reader.RequireEnd($"qualification.release.protocols[{index}]");
        var canonicalClaim = NoritoCodec.Encode(SecurityClaimSchemaName, claim, CanonicalFlags);
        var digestInput = new byte[
            SecurityClaimDigestDomain.Length + sizeof(ulong) + canonicalClaim.Length];
        SecurityClaimDigestDomain.CopyTo(digestInput, 0);
        BinaryPrimitives.WriteUInt64LittleEndian(
            digestInput.AsSpan(SecurityClaimDigestDomain.Length, sizeof(ulong)),
            checked((ulong)canonicalClaim.Length));
        canonicalClaim.CopyTo(
            digestInput,
            SecurityClaimDigestDomain.Length + sizeof(ulong));
        if (!CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(digestInput),
            securityClaimDigest))
        {
            throw Invalid($"Exact12 release protocol {index} security-claim digest is invalid.");
        }
        return new PrivacyReleaseProtocolBindingV1(
            protocol,
            proofSystemId,
            engineId,
            parameterId,
            parameterDigest,
            verifierDigest,
            statementSchemaDigest,
            engineManifestDigest,
            securityClaimDigest);
    }

    private static PrivacyExact12DeploymentQualificationV1 ParseDeploymentQualification(
        byte[] encoded)
    {
        var reader = new FrameReader(encoded);
        var version = ReadUInt16Field(ref reader, "qualification.deployment.version");
        if (version != 1)
        {
            throw Invalid("Exact12 deployment version must be 1.");
        }
        _ = reader.ReadField("qualification.deployment.chain_id", out _);
        NetworkId networkId;
        try
        {
            networkId = NetworkId.FromBytes(
                reader.ReadField("qualification.deployment.network_id", out _));
        }
        catch (ArgumentException)
        {
            throw Invalid("Deployment network id must be exactly 32 marked hash bytes.");
        }
        var genesisHash = reader.ReadField("qualification.deployment.genesis_hash", out _);
        if (!genesisHash.SequenceEqual(networkId.AsSpan()))
        {
            throw Invalid("Deployment genesis hash differs from its exact network identity.");
        }
        var releaseManifestDigest = ReadNonzeroDigestNewtype(
            reader.ReadField("qualification.deployment.release_manifest_digest", out _),
            "qualification.deployment.release_manifest_digest");
        _ = ReadNonzeroDigestNewtype(
            reader.ReadField("qualification.deployment.activation_transaction_digest", out _),
            "qualification.deployment.activation_transaction_digest");
        var activationsBytes = reader.ReadField(
            "qualification.deployment.activations",
            out _).ToArray();
        _ = ReadNonzeroDigestNewtype(
            reader.ReadField("qualification.deployment.validator_roster_digest", out _),
            "qualification.deployment.validator_roster_digest");
        _ = reader.ReadField("qualification.deployment.endpoint_version", out _);
        var convergenceHeight = ReadUInt64Field(
            ref reader,
            "qualification.deployment.convergence_height");
        if (convergenceHeight == 0)
        {
            throw Invalid("Exact12 deployment convergence height must be nonzero.");
        }
        _ = ReadNonzeroDigestNewtype(
            reader.ReadField("qualification.deployment.converged_state_digest", out _),
            "qualification.deployment.converged_state_digest");
        _ = reader.ReadField("qualification.deployment.validator_canaries", out _);
        _ = reader.ReadField("qualification.deployment.validator_signatures", out _);
        var qualificationDigest = ReadNonzeroDigestNewtype(
            reader.ReadField("qualification.deployment.qualification_digest", out _),
            "qualification.deployment.qualification_digest");
        reader.RequireEnd("qualification.deployment");

        var activationsReader = new FrameReader(activationsBytes);
        if (activationsReader.ReadUInt64Raw("qualification.deployment.activations.length") != RowCount)
        {
            throw Invalid("Exact12 deployment must bind exactly twelve activations.");
        }
        var activations = new PrivacyDeploymentActivationV1[RowCount];
        for (var index = 0; index < RowCount; index++)
        {
            var activation = new FrameReader(activationsReader.ReadField(
                $"qualification.deployment.activations[{index}]",
                out _));
            RequireUnitEnum(
                activation.ReadField(
                    $"qualification.deployment.activations[{index}].protocol_id",
                    out _),
                checked((uint)index),
                $"qualification.deployment.activations[{index}].protocol_id");
            var height = ReadUInt64Field(
                ref activation,
                $"qualification.deployment.activations[{index}].activation_height");
            activation.RequireEnd($"qualification.deployment.activations[{index}]");
            if (height == 0 || height >= convergenceHeight)
            {
                throw Invalid($"Exact12 deployment activation {index} must precede convergence.");
            }
            activations[index] = new PrivacyDeploymentActivationV1(
                (PrivacyProtocolIdV1)checked((uint)index),
                height);
        }
        activationsReader.RequireEnd("qualification.deployment.activations");
        return new PrivacyExact12DeploymentQualificationV1(
            version,
            networkId,
            releaseManifestDigest,
            activations,
            convergenceHeight,
            qualificationDigest,
            encoded);
    }

    internal static void RequireDeploymentNetwork(
        PrivacyExact12QualificationRecordV1? qualification,
        NetworkId expectedNetworkId,
        bool requireQualification = false)
    {
        ArgumentNullException.ThrowIfNull(expectedNetworkId);
        if (qualification is null)
        {
            if (requireQualification)
            {
                throw Invalid("Exact12 admission requires network deployment qualification.");
            }
            return;
        }
        if (!qualification.DeploymentQualification.NetworkId.Equals(expectedNetworkId))
        {
            throw Invalid("Exact12 deployment differs from the configured network identity.");
        }
    }

    private static bool QualificationMatches(
        PrivacyExact12QualificationRecordV1? qualification,
        CompiledResult compiled,
        ActivationProjection activation,
        ulong committedHeight,
        int index)
    {
        if (qualification is null
            || qualification.DeploymentQualification.ConvergenceHeight > committedHeight
            || compiled.AvailableFields is null
            || activation.ActivatedAtHeight is null)
        {
            return false;
        }
        var release = qualification.ReleaseManifest.Protocols[index];
        var deployment = qualification.DeploymentQualification.Activations[index];
        var fields = compiled.AvailableFields;
        return release.ProtocolId == (PrivacyProtocolIdV1)checked((uint)index)
            && deployment.ProtocolId == release.ProtocolId
            && release.ProofSystemId == ReadUnitEnum(fields[1], "qualified proof system")
            && release.EngineId == ReadUnitEnum(fields[2], "qualified engine")
            && release.ParameterId.AsSpan().SequenceEqual(
                ReadNonzeroDigestNewtype(fields[3], "qualified parameter id"))
            && release.ParameterDigest.AsSpan().SequenceEqual(
                ReadNonzeroDigestNewtype(fields[4], "qualified parameter digest"))
            && release.VerifierDigest.AsSpan().SequenceEqual(
                ReadNonzeroDigestNewtype(fields[5], "qualified verifier digest"))
            && release.StatementSchemaDigest.AsSpan().SequenceEqual(
                ReadNonzeroDigestNewtype(fields[6], "qualified statement-schema digest"))
            && release.EngineManifestDigest.AsSpan().SequenceEqual(
                ReadNonzeroDigestNewtype(fields[7], "qualified engine-manifest digest"))
            && deployment.ActivationHeight == activation.ActivatedAtHeight.Value;
    }

    private static byte[] ValidateSecurityClaim(
        ReadOnlySpan<byte> encoded,
        PrivacyProtocolIdV1 protocol,
        byte[] parameterDigest,
        byte[] verifierDigest,
        int index)
    {
        var reader = new FrameReader(encoded);
        var catalogCommitment = reader.ReadField(
            $"row[{index}].security_claim.catalog_commitment",
            out _);
        if (!catalogCommitment.SequenceEqual(Exact12CatalogCommitment))
        {
            throw Invalid($"Exact12 row {index} security claim has an unknown catalog commitment.");
        }
        RequireUnitEnum(
            reader.ReadField($"row[{index}].security_claim.protocol_id", out _),
            (uint)protocol,
            $"row[{index}].security_claim.protocol_id");
        RequireUnitEnum(
            reader.ReadField($"row[{index}].security_claim.security_model", out _),
            ExpectedSecurityModels[index],
            $"row[{index}].security_claim.security_model");
        var targetSecurityBits = ReadUInt16Field(
            ref reader,
            $"row[{index}].security_claim.target_security_bits");
        var achievedSecurityBits = ReadUInt16Field(
            ref reader,
            $"row[{index}].security_claim.achieved_security_bits");
        if (targetSecurityBits != 128 || achievedSecurityBits < targetSecurityBits)
        {
            throw Invalid($"Exact12 row {index} security claim does not establish 128 bits.");
        }
        var claimedParameterDigest = ReadNonzeroDigestNewtype(
            reader.ReadField($"row[{index}].security_claim.parameter_digest", out _),
            $"row[{index}].security_claim.parameter_digest");
        if (!claimedParameterDigest.AsSpan().SequenceEqual(parameterDigest))
        {
            throw Invalid($"Exact12 row {index} security-claim parameter digest drifted.");
        }
        var claimedVerifierDigest = ReadNonzeroDigestNewtype(
            reader.ReadField($"row[{index}].security_claim.verifier_digest", out _),
            $"row[{index}].security_claim.verifier_digest");
        if (!claimedVerifierDigest.AsSpan().SequenceEqual(verifierDigest))
        {
            throw Invalid($"Exact12 row {index} security-claim verifier digest drifted.");
        }
        _ = ReadNonzeroDigestNewtype(
            reader.ReadField($"row[{index}].security_claim.reduction_digest", out _),
            $"row[{index}].security_claim.reduction_digest");
        var auditBundleDigest = ReadNonzeroDigestNewtype(
            reader.ReadField($"row[{index}].security_claim.audit_bundle_digest", out _),
            $"row[{index}].security_claim.audit_bundle_digest");
        reader.RequireEnd($"row[{index}].security_claim");
        return auditBundleDigest;
    }

    private static void ValidateConsensusPolicy(ReadOnlySpan<byte> encoded, ulong committedHeight)
    {
        var reader = new FrameReader(encoded);
        var current = ParseConsensusLimits(
            reader.ReadField("manifest.consensus_policy.current_limits", out _),
            "manifest.consensus_policy.current_limits");
        var pending = reader.ReadField("manifest.consensus_policy.pending_tightening", out _);
        reader.RequireEnd("manifest.consensus_policy");
        var option = new FrameReader(pending);
        var tag = option.ReadByteRaw("manifest.consensus_policy.pending_tightening.option");
        if (tag == 0)
        {
            option.RequireEnd("manifest.consensus_policy.pending_tightening");
            return;
        }
        if (tag != 1)
        {
            throw Invalid("Privacy consensus pending-tightening option tag is unknown.");
        }
        var value = option.ReadField("manifest.consensus_policy.pending_tightening.value", out _);
        option.RequireEnd("manifest.consensus_policy.pending_tightening");
        var tightening = new FrameReader(value);
        var scheduled = ReadUInt64Field(ref tightening, "privacy policy scheduled_at_height");
        var effective = ReadUInt64Field(ref tightening, "privacy policy effective_at_height");
        var next = ParseConsensusLimits(
            tightening.ReadField("privacy policy next_limits", out _),
            "privacy policy next_limits");
        tightening.RequireEnd("privacy policy tightening");
        RequireSchedule(scheduled, effective, committedHeight, "privacy policy tightening");
        RequireLimitCeiling(next, current, "privacy policy tightening");
        if (next.Values.SequenceEqual(current.Values))
        {
            throw Invalid("Privacy policy tightening must not be a no-op.");
        }
    }

    private static LimitSet ParseConsensusLimits(ReadOnlySpan<byte> encoded, string context)
    {
        var reader = new FrameReader(encoded);
        var values = new uint[10];
        for (var index = 0; index < values.Length; index++)
        {
            values[index] = ReadUInt32Field(ref reader, $"{context}.field[{index}]");
        }
        reader.RequireEnd(context);
        uint[] maxima =
        [
            1,
            2,
            9 * 1024 * 1024,
            9 * 1024 * 1024 + 256 * 1024 + 512,
            9 * 1024 * 1024 + 256 * 1024 + 512,
            16 * 1024 * 1024 - 64 * 1024,
            256 * 1024,
            8,
            8,
            2_048,
        ];
        for (var index = 0; index < values.Length; index++)
        {
            if (values[index] == 0 || values[index] > maxima[index])
            {
                throw Invalid($"{context}.field[{index}] is outside the first-release ceiling.");
            }
        }
        if (values[0] > values[1]
            || values[2] > values[3]
            || values[3] > values[4]
            || values[4] > values[5]
            || values[6] > values[3])
        {
            throw Invalid($"{context} has inconsistent containing-scope limits.");
        }
        return new LimitSet(uint.MaxValue, values);
    }

    private static LimitSet ParseProtocolLimits(
        ReadOnlySpan<byte> encoded,
        PrivacyProtocolIdV1 expectedProtocol,
        string context)
    {
        var reader = new FrameReader(encoded);
        var tag = reader.ReadUInt32Raw($"{context}.protocol");
        if (tag != (uint)expectedProtocol)
        {
            throw Invalid($"{context} targets another protocol.");
        }
        var fieldCount = tag switch
        {
            1 or 3 or 9 or 10 or 11 => 2,
            2 or 6 or 8 => 1,
            0 or 4 or 5 or 7 => 0,
            _ => throw Invalid($"{context} has an unknown protocol tag."),
        };
        if (fieldCount == 0)
        {
            reader.RequireEnd(context);
            return new LimitSet(tag, Array.Empty<uint>());
        }
        var limits = reader.ReadField($"{context}.limits", out _);
        reader.RequireEnd(context);
        var limitReader = new FrameReader(limits);
        var values = new uint[fieldCount];
        for (var index = 0; index < fieldCount; index++)
        {
            values[index] = ReadUInt32Field(ref limitReader, $"{context}.limits[{index}]");
        }
        limitReader.RequireEnd($"{context}.limits");
        uint[] maxima = tag switch
        {
            1 => [64, 8],
            2 => [16],
            3 => [8, 64],
            6 => [4],
            8 => [2],
            9 => [2, 4],
            10 => [2, 2],
            11 => [2, 2],
            _ => throw Invalid($"{context} has an unsupported limit shape."),
        };
        for (var index = 0; index < values.Length; index++)
        {
            if (values[index] == 0 || values[index] > maxima[index])
            {
                throw Invalid($"{context}.limits[{index}] exceeds the first-release ceiling.");
            }
        }
        if (tag == 1 && values[0] is not (16 or 32 or 64))
        {
            throw Invalid($"{context} uses a non-canonical Anonymous PGC set size.");
        }
        if (tag == 3 && values[1] is not (16 or 32 or 64))
        {
            throw Invalid($"{context} uses a non-canonical ZK-AMS ring size.");
        }
        return new LimitSet(tag, values);
    }

    private static void ValidatePendingProtocolLimits(
        ReadOnlySpan<byte> encoded,
        LimitSet current,
        PrivacyProtocolIdV1 protocol,
        ulong committedHeight,
        int index)
    {
        var option = new FrameReader(encoded);
        var tag = option.ReadByteRaw($"row[{index}].activation.pending_limits.option");
        if (tag == 0)
        {
            option.RequireEnd($"row[{index}].activation.pending_limits");
            return;
        }
        if (tag != 1)
        {
            throw Invalid($"Exact12 row {index} pending-limit option tag is unknown.");
        }
        var value = option.ReadField($"row[{index}].activation.pending_limits.value", out _);
        option.RequireEnd($"row[{index}].activation.pending_limits");
        var reader = new FrameReader(value);
        var scheduled = ReadUInt64Field(ref reader, $"row[{index}].pending_limits.scheduled_at_height");
        var effective = ReadUInt64Field(ref reader, $"row[{index}].pending_limits.effective_at_height");
        var next = ParseProtocolLimits(
            reader.ReadField($"row[{index}].pending_limits.next_limits", out _),
            protocol,
            $"row[{index}].pending_limits.next_limits");
        reader.RequireEnd($"row[{index}].pending_limits");
        RequireSchedule(scheduled, effective, committedHeight, $"row[{index}].pending_limits");
        RequireLimitCeiling(next, current, $"row[{index}].pending_limits");
        if (next.Values.SequenceEqual(current.Values))
        {
            throw Invalid($"Exact12 row {index} pending protocol limits are a no-op.");
        }
    }

    private static void RequireSchedule(
        ulong scheduled,
        ulong effective,
        ulong committedHeight,
        string context)
    {
        if (scheduled == 0
            || scheduled > committedHeight
            || effective <= committedHeight
            || effective <= scheduled)
        {
            throw Invalid($"{context} has invalid future or committed-height binding.");
        }
    }

    private static void RequireLimitCeiling(LimitSet value, LimitSet ceiling, string context)
    {
        if (value.ProtocolTag != ceiling.ProtocolTag || value.Values.Length != ceiling.Values.Length)
        {
            throw Invalid($"{context} has a mismatched protocol-limit shape.");
        }
        for (var index = 0; index < value.Values.Length; index++)
        {
            if (value.Values[index] > ceiling.Values[index])
            {
                throw Invalid($"{context}.field[{index}] exceeds its compiled ceiling.");
            }
        }
    }

    private static void RequireNonzeroDigestNewtype(ReadOnlySpan<byte> encoded, string context)
    {
        _ = ReadNonzeroDigestNewtype(encoded, context);
    }

    private static byte[] ReadNonzeroDigestNewtype(ReadOnlySpan<byte> encoded, string context)
    {
        var reader = new FrameReader(encoded);
        var digest = reader.ReadField($"{context}.value", out _);
        reader.RequireEnd(context);
        if (digest.Length != 32 || digest.IndexOfAnyExcept((byte)0) < 0)
        {
            throw Invalid($"{context} must be one nonzero 32-byte value.");
        }
        return digest.ToArray();
    }

    private static byte ReadByteNewtype(ReadOnlySpan<byte> encoded, string context)
    {
        var reader = new FrameReader(encoded);
        var value = reader.ReadField($"{context}.value", out _);
        reader.RequireEnd(context);
        if (value.Length != 1)
        {
            throw Invalid($"{context} must contain exactly one byte.");
        }
        return value[0];
    }

    private static uint ReadUnitEnum(ReadOnlySpan<byte> encoded, string context)
    {
        var reader = new FrameReader(encoded);
        var tag = reader.ReadUInt32Raw($"{context}.tag");
        reader.RequireEnd(context);
        return tag;
    }

    private static void RequireUnitEnum(ReadOnlySpan<byte> encoded, uint expected, string context)
    {
        if (ReadUnitEnum(encoded, context) != expected)
        {
            throw Invalid($"{context} has an unexpected discriminant.");
        }
    }

    private static uint ReadUInt32Field(ref FrameReader reader, string context)
    {
        var field = reader.ReadField(context, out _);
        if (field.Length != sizeof(uint))
        {
            throw Invalid($"{context} must contain exactly four bytes.");
        }
        return BinaryPrimitives.ReadUInt32LittleEndian(field);
    }

    private static ushort ReadUInt16Field(ref FrameReader reader, string context)
    {
        var field = reader.ReadField(context, out _);
        if (field.Length != sizeof(ushort))
        {
            throw Invalid($"{context} must contain exactly two bytes.");
        }
        return BinaryPrimitives.ReadUInt16LittleEndian(field);
    }

    private static ulong ReadUInt64Field(ref FrameReader reader, string context)
    {
        var field = reader.ReadField(context, out _);
        if (field.Length != sizeof(ulong))
        {
            throw Invalid($"{context} must contain exactly eight bytes.");
        }
        return BinaryPrimitives.ReadUInt64LittleEndian(field);
    }

    private static ulong? ReadOptionalUInt64Field(ref FrameReader reader, string context)
    {
        var encoded = reader.ReadField(context, out _);
        var option = new FrameReader(encoded);
        var tag = option.ReadByteRaw($"{context}.option");
        if (tag == 0)
        {
            option.RequireEnd(context);
            return null;
        }
        if (tag != 1)
        {
            throw Invalid($"{context} has an unknown option tag.");
        }
        var value = option.ReadField($"{context}.value", out _);
        option.RequireEnd(context);
        if (value.Length != sizeof(ulong))
        {
            throw Invalid($"{context} must contain one UInt64.");
        }
        return BinaryPrimitives.ReadUInt64LittleEndian(value);
    }

    private static byte[] DecodeExactArchive(string schemaName, byte[] archive)
    {
        byte[] payload;
        byte flags;
        try
        {
            (payload, flags) = NoritoCodec.Decode(schemaName, archive);
        }
        catch (ArgumentException error)
        {
            throw Invalid($"{schemaName} is not a valid Norito archive: {error.Message}");
        }
        if (flags != CanonicalFlags
            || archive.Length != NoritoHeader.EncodedLength + payload.Length
            || !NoritoCodec.Encode(schemaName, payload, CanonicalFlags).AsSpan().SequenceEqual(archive))
        {
            throw Invalid($"{schemaName} is not one canonical unpadded archive.");
        }
        return payload;
    }

    private static PrivacyExact12CapabilityManifestException Invalid(string message) => new(message);

    internal sealed record DecodedManifest(
        uint Version,
        ulong CommittedHeight,
        byte[] ConsensusPolicy,
        PrivacyExact12QualificationRecordV1? Qualification,
        IReadOnlyList<PrivacyExact12CapabilityRowV1> Protocols,
        byte[] ManifestDigest,
        byte[] CanonicalArchive);

    private sealed record CompiledResult(
        bool IsAvailable,
        byte[]? UnavailableReason,
        PrivacyCompiledProfileUnavailableReasonV1? UnavailableReasonKind,
        PrivacyCompiledStatementSchemaErrorV1? StatementSchemaError,
        byte[][]? AvailableFields);

    private sealed record CompiledUnavailableReason(
        PrivacyCompiledProfileUnavailableReasonV1 Reason,
        PrivacyCompiledStatementSchemaErrorV1? StatementSchemaError);

    private sealed record ReadinessProjection(
        PrivacyCapabilityReadinessV1 Readiness,
        PrivacyCapabilityUnavailableReasonV1? UnavailableReason,
        PrivacyCompiledProfileUnavailableReasonV1? CompiledProfileUnavailableReason,
        PrivacyCompiledStatementSchemaErrorV1? CompiledStatementSchemaError,
        byte[]? CompiledProfileReasonCanonical);

    private sealed record ActivationProjection(
        ProtocolLifecycle Lifecycle,
        ulong? ActivatedAtHeight);

    private sealed record LifecycleProjection(
        ProtocolLifecycle Lifecycle,
        ulong? ActivatedAtHeight);

    private enum ProtocolLifecycle
    {
        Proposed,
        Active,
        Suspended,
        Retired,
    }

    private sealed record LimitSet(uint ProtocolTag, uint[] Values);

    internal sealed class LocalTupleMismatchException : PrivacyExact12CapabilityManifestException
    {
        internal LocalTupleMismatchException(string message)
            : base(message)
        {
        }
    }

    private ref struct FrameReader
    {
        private readonly ReadOnlySpan<byte> input;
        private int offset;

        internal FrameReader(ReadOnlySpan<byte> input)
        {
            this.input = input;
            offset = 0;
        }

        internal ReadOnlySpan<byte> ReadField(string context, out int payloadOffset)
        {
            var length = ReadCompactLength($"{context}.length");
            if (length > int.MaxValue)
            {
                throw Invalid($"{context} exceeds the managed runtime bound.");
            }
            payloadOffset = offset;
            return ReadExact(checked((int)length), context);
        }

        internal byte ReadByteRaw(string context) => ReadExact(1, context)[0];

        internal uint ReadUInt32Raw(string context) =>
            BinaryPrimitives.ReadUInt32LittleEndian(ReadExact(sizeof(uint), context));

        internal ulong ReadUInt64Raw(string context) =>
            BinaryPrimitives.ReadUInt64LittleEndian(ReadExact(sizeof(ulong), context));

        internal string ReadCompactString(string context)
        {
            var length = ReadCompactLength($"{context}.length");
            if (length > int.MaxValue)
            {
                throw Invalid($"{context} exceeds the managed runtime bound.");
            }
            var value = ReadExact(checked((int)length), context);
            try
            {
                return new UTF8Encoding(false, true).GetString(value);
            }
            catch (DecoderFallbackException error)
            {
                throw Invalid($"{context} is not UTF-8: {error.Message}");
            }
        }

        internal void RequireEnd(string context)
        {
            if (offset != input.Length)
            {
                throw Invalid($"{context} contains trailing, duplicate, or unknown bytes.");
            }
        }

        private ulong ReadCompactLength(string context)
        {
            ulong value = 0;
            var shift = 0;
            for (var index = 0; index < 10; index++)
            {
                var current = ReadByteRaw(context);
                var chunk = (ulong)(current & 0x7f);
                if (shift == 63 && chunk > 1)
                {
                    throw Invalid($"{context} overflows UInt64.");
                }
                value |= chunk << shift;
                if ((current & 0x80) == 0)
                {
                    if (index > 0 && chunk == 0)
                    {
                        throw Invalid($"{context} is overlong.");
                    }
                    return value;
                }
                shift += 7;
            }
            throw Invalid($"{context} overflows UInt64.");
        }

        private ReadOnlySpan<byte> ReadExact(int count, string context)
        {
            if (count < 0 || offset > input.Length - count)
            {
                throw Invalid($"{context} is truncated.");
            }
            var result = input.Slice(offset, count);
            offset += count;
            return result;
        }
    }
}
