using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Hyperledger.Iroha.Address;
using Hyperledger.Iroha.Numeric;
using Hyperledger.Iroha.Transactions;

namespace Hyperledger.Iroha.Torii;

internal static class ToriiListSnapshots
{
    internal static T[]? Copy<T>(IReadOnlyList<T>? values) =>
        values is null ? null : CopyNonNullItemsCore(values, nameof(values));

    internal static T[] CopyRequired<T>(IReadOnlyList<T>? values) =>
        values is null ? Array.Empty<T>() : CopyNonNullItemsCore(values, nameof(values));

    internal static T[]? CopyNonNullItems<T>(IReadOnlyList<T>? values, string parameterName)
    {
        if (values is null)
        {
            return null;
        }

        return CopyNonNullItemsCore(values, parameterName);
    }

    private static T[] CopyNonNullItemsCore<T>(IReadOnlyList<T> values, string parameterName)
    {
        var copy = new T[values.Count];
        for (var index = 0; index < values.Count; index++)
        {
            var item = values[index];
            if (item is null)
            {
                throw new ArgumentException("List elements must not be null.", $"{parameterName}[{index}]");
            }

            copy[index] = item;
        }

        return copy;
    }
}

internal static class ToriiJsonSnapshots
{
    internal static JsonNode? Copy(JsonNode? value) => value?.DeepClone();

    internal static JsonObject? CopyObject(JsonObject? value) =>
        value is null ? null : (JsonObject)value.DeepClone();
}

public sealed record class ToriiAccountAliasLookupRequest
{
    [JsonRequired, JsonPropertyName("account_id")]
    public string AccountId { get; init; } = string.Empty;

    [JsonPropertyName("dataspace")]
    public string? Dataspace { get; init; }

    [JsonPropertyName("domain")]
    public string? Domain { get; init; }
}

public sealed record class ToriiAliasResolutionRequest
{
    [JsonPropertyName("alias")]
    public string Alias { get; init; } = string.Empty;
}

public sealed record class ToriiAliasResolveIndexRequest
{
    [JsonPropertyName("index")]
    public ulong Index { get; init; }
}

/// <summary>Secret-free request accepted by the sponsored onboarding planner.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiAccountOnboardingPlanRequest
{
    private string[] permissions = Array.Empty<string>();

    [JsonRequired, JsonPropertyName("version")]
    public byte Version { get; init; } = 1;

    [JsonRequired, JsonPropertyName("alias")]
    public string Alias { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("account_id")]
    public string AccountId { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("permissions")]
    public IReadOnlyList<string> Permissions
    {
        get => permissions.ToArray();
        init => permissions = ToriiListSnapshots.CopyNonNullItems(value, nameof(Permissions))
            ?? throw new ArgumentNullException(nameof(Permissions));
    }
}

/// <summary>Canonical server-signed sponsored onboarding plan body.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiAccountOnboardingPlanBody
{
    [JsonRequired, JsonPropertyName("version")]
    public byte Version { get; init; }

    [JsonRequired, JsonPropertyName("request")]
    public ToriiAccountOnboardingPlanRequest Request { get; init; } = new();

    [JsonRequired, JsonPropertyName("authority")]
    public string Authority { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("network_id")]
    public NetworkId NetworkId { get; init; } = null!;

    [JsonRequired, JsonPropertyName("anchor")]
    public JsonElement Anchor { get; init; }

    [JsonRequired, JsonPropertyName("resource")]
    public JsonElement Resource { get; init; }

    [JsonRequired, JsonPropertyName("acquisition")]
    public JsonElement Acquisition { get; init; }

    [JsonRequired, JsonPropertyName("quote_guard")]
    public JsonElement QuoteGuard { get; init; }

    [JsonRequired, JsonPropertyName("instructions")]
    public JsonElement Instructions { get; init; }

    [JsonRequired, JsonPropertyName("owner_auto_renew_instruction")]
    public JsonElement OwnerAutoRenewInstruction { get; init; }

    [JsonRequired, JsonPropertyName("valid_until_ms")]
    public ulong ValidUntilMilliseconds { get; init; }
}

/// <summary>Encodes an onboarding plan body into its exact canonical Norito bytes.</summary>
public delegate byte[] ToriiAccountOnboardingPlanBodyEncoder(ToriiAccountOnboardingPlanBody body);

/// <summary>Stateless signer-authenticated sponsored onboarding receipt.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiAccountOnboardingPlanReceipt
{
    [JsonRequired, JsonPropertyName("body")]
    public ToriiAccountOnboardingPlanBody Body { get; init; } = new();

    [JsonRequired, JsonPropertyName("plan_hash")]
    public string PlanHash { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("signature")]
    public string Signature { get; init; } = string.Empty;
}

/// <summary>Exact public operation identity committed by a prepared transaction.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiPreparedOperationBindingV1
{
    public const string SchemaV1 = "iroha.prepared-operation.binding.v1";

    [JsonRequired, JsonPropertyName("schema")]
    public string Schema { get; init; } = SchemaV1;

    [JsonRequired, JsonPropertyName("semantic_hash_hex")]
    public string SemanticHashHex { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("kind")]
    public string Kind { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("request_id")]
    public string RequestId { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("execution_expires_at_unix_ms")]
    public ulong ExecutionExpiresAtUnixMilliseconds { get; init; }
}

/// <summary>Exact non-mutating onboarding prepare request.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiAccountOnboardingPrepareRequestV1
{
    public const string SchemaV1 = "iroha.accounts.onboard.prepare.v1";

    public ToriiAccountOnboardingPrepareRequestV1(
        ToriiPreparedOperationBindingV1 binding,
        ToriiAccountOnboardingPlanReceipt receipt,
        FeePaymentIntent feePayment)
        : this(SchemaV1, binding, receipt, feePayment)
    {
    }

    [JsonConstructor]
    public ToriiAccountOnboardingPrepareRequestV1(
        string schema,
        ToriiPreparedOperationBindingV1 binding,
        ToriiAccountOnboardingPlanReceipt receipt,
        FeePaymentIntent feePayment)
    {
        if (!string.Equals(schema, SchemaV1, StringComparison.Ordinal))
        {
            throw new JsonException("Unsupported account onboarding prepare schema.");
        }
        Binding = binding
            ?? throw new JsonException("Account onboarding prepare binding is required.");
        Receipt = receipt
            ?? throw new JsonException("Account onboarding prepare receipt is required.");
        FeePayment = feePayment
            ?? throw new JsonException("Account onboarding prepare fee_payment is required.");
        Schema = schema;
    }

    [JsonRequired, JsonPropertyName("schema")]
    public string Schema { get; init; }

    [JsonRequired, JsonPropertyName("binding")]
    public ToriiPreparedOperationBindingV1 Binding { get; init; }

    [JsonRequired, JsonPropertyName("receipt")]
    public ToriiAccountOnboardingPlanReceipt Receipt { get; init; }

    [JsonRequired, JsonPropertyName("fee_payment")]
    public FeePaymentIntent FeePayment { get; init; }
}

/// <summary>Live onboarding disposition used to prepare the exact instruction vector.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiAccountOnboardingDisposition
{
    [JsonRequired, JsonPropertyName("kind")]
    public string Kind { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("value")]
    public JsonElement Value { get; init; }
}

/// <summary>Authenticated exact onboarding transaction prepared by Torii.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiAccountOnboardingPreparedTransactionV1
{
    public const string SchemaV1 = "iroha.prepared-transaction.v1";
    public const string OperationV1 = "onboarding";

    [JsonRequired, JsonPropertyName("schema")]
    public string Schema { get; init; } = SchemaV1;

    [JsonRequired, JsonPropertyName("binding")]
    public ToriiPreparedOperationBindingV1 Binding { get; init; } = new();

    [JsonRequired, JsonPropertyName("operation")]
    public string Operation { get; init; } = OperationV1;

    [JsonRequired, JsonPropertyName("receipt")]
    public ToriiAccountOnboardingPlanReceipt Receipt { get; init; } = new();

    [JsonRequired, JsonPropertyName("semantic_hash_hex")]
    public string SemanticHashHex { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("account_id")]
    public string AccountId { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("alias")]
    public string Alias { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("disposition")]
    public ToriiAccountOnboardingDisposition Disposition { get; init; } = new();

    [JsonRequired, JsonPropertyName("transaction_hash_hex")]
    public string TransactionHashHex { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("signed_transaction_wire_hex")]
    public string SignedTransactionWireHex { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("signed_transaction_wire_sha256")]
    public string SignedTransactionWireSha256 { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("fee_payment")]
    public FeePaymentIntent FeePayment { get; init; } = null!;

    [JsonRequired, JsonPropertyName("server_signature")]
    public string ServerSignature { get; init; } = string.Empty;
}

/// <summary>
/// Authenticated nonterminal onboarding result requiring one fresh atomic state observation.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiAccountOnboardingProofRequiredPrepareResponseV1
{
    public const string SchemaV1 = "iroha.accounts.onboard.prepare-proof-required.v1";
    public const string OperationV1 = "onboarding";
    public const string OutcomeV1 = "ProofRequired";
    public const string ProofKindV1 = "account_alias_current_state";

    [JsonRequired, JsonPropertyName("schema")]
    public string Schema { get; init; } = SchemaV1;

    [JsonRequired, JsonPropertyName("binding")]
    public ToriiPreparedOperationBindingV1 Binding { get; init; } = new();

    [JsonRequired, JsonPropertyName("operation")]
    public string Operation { get; init; } = OperationV1;

    [JsonRequired, JsonPropertyName("outcome")]
    public string Outcome { get; init; } = OutcomeV1;

    [JsonRequired, JsonPropertyName("proof_kind")]
    public string ProofKind { get; init; } = ProofKindV1;

    [JsonRequired, JsonPropertyName("semantic_hash_hex")]
    public string SemanticHashHex { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("account_id")]
    public string AccountId { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("alias")]
    public string Alias { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("disposition")]
    public ToriiAccountOnboardingDisposition Disposition { get; init; } = new();

    [JsonRequired, JsonPropertyName("server_signature")]
    public string ServerSignature { get; init; } = string.Empty;
}

/// <summary>Closed onboarding preparation result.</summary>
public sealed record class ToriiAccountOnboardingPrepareResultV1
{
    private ToriiAccountOnboardingPrepareResultV1(
        ToriiAccountOnboardingPreparedTransactionV1? prepared,
        ToriiAccountOnboardingProofRequiredPrepareResponseV1? proofRequired)
    {
        Prepared = prepared;
        ProofRequired = proofRequired;
    }

    public ToriiAccountOnboardingPreparedTransactionV1? Prepared { get; }

    public ToriiAccountOnboardingProofRequiredPrepareResponseV1? ProofRequired { get; }

    public static ToriiAccountOnboardingPrepareResultV1 FromPrepared(
        ToriiAccountOnboardingPreparedTransactionV1 value) =>
        new(value ?? throw new ArgumentNullException(nameof(value)), null);

    public static ToriiAccountOnboardingPrepareResultV1 FromProofRequired(
        ToriiAccountOnboardingProofRequiredPrepareResponseV1 value) =>
        new(null, value ?? throw new ArgumentNullException(nameof(value)));
}

/// <summary>Closed first-release request for one atomic onboarding-state observation.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiAccountOnboardingCurrentStateRequestV1
{
    public const byte VersionV1 = 1;

    [JsonRequired, JsonPropertyName("version")]
    public byte Version { get; init; } = VersionV1;

    [JsonRequired, JsonPropertyName("account_id")]
    public string AccountId { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("alias")]
    public string Alias { get; init; } = string.Empty;
}

/// <summary>One internally consistent first-release onboarding-state observation.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiAccountOnboardingCurrentStateResponseV1
{
    public const byte VersionV1 = 1;

    [JsonRequired, JsonPropertyName("version")]
    public byte Version { get; init; } = VersionV1;

    [JsonRequired, JsonPropertyName("network_id")]
    public NetworkId NetworkId { get; init; } = null!;

    [JsonRequired, JsonPropertyName("account_id")]
    public string AccountId { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("alias")]
    public string Alias { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("account_exists")]
    public bool AccountExists { get; init; }

    [JsonRequired, JsonPropertyName("alias_target_account_id")]
    public string? AliasTargetAccountId { get; init; }

    [JsonRequired, JsonPropertyName("observed_block_height")]
    public ulong ObservedBlockHeight { get; init; }

    [JsonRequired, JsonPropertyName("observed_block_hash")]
    public string ObservedBlockHash { get; init; } = string.Empty;
}

/// <summary>Classification of the exact alias in one atomic onboarding-state observation.</summary>
public enum ToriiAccountOnboardingCurrentStateKindV1
{
    /// <summary>The alias targets the expected existing account.</summary>
    Applied,
    /// <summary>The expected account exists, but the alias has no active target.</summary>
    AliasAbsent,
    /// <summary>The expected account exists, but the alias targets another account.</summary>
    AliasConflict,
}

/// <summary>
/// Ephemeral evidence from one atomic account-and-alias state observation.
/// </summary>
public sealed class ToriiAccountOnboardingCurrentStateProofV1
{
    internal ToriiAccountOnboardingCurrentStateProofV1(
        ToriiAccountOnboardingProofRequiredPrepareResponseV1 proofRequired,
        ToriiAccountOnboardingCurrentStateResponseV1 observation,
        ToriiAccountOnboardingCurrentStateKindV1 kind)
    {
        ProofRequired = proofRequired;
        Observation = observation;
        Kind = kind;
    }

    public ToriiAccountOnboardingProofRequiredPrepareResponseV1 ProofRequired { get; }

    public ToriiAccountOnboardingCurrentStateResponseV1 Observation { get; }

    public ToriiAccountOnboardingCurrentStateKindV1 Kind { get; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiAccountFaucetClaimV1
{
    private string accountId = string.Empty;
    private ulong powAnchorHeight;
    private string powNonceHex = string.Empty;

    [JsonConstructor]
    public ToriiAccountFaucetClaimV1(
        string accountId,
        ulong powAnchorHeight,
        string powNonceHex)
    {
        AccountId = accountId;
        PowAnchorHeight = powAnchorHeight;
        PowNonceHex = powNonceHex;
    }

    [JsonRequired, JsonPropertyName("account_id")]
    public string AccountId
    {
        get => accountId;
        init => accountId = ToriiAccountFaucetMetadata.RequireCanonicalAccountId(
            value,
            nameof(AccountId));
    }

    [JsonRequired, JsonPropertyName("pow_anchor_height")]
    public ulong PowAnchorHeight
    {
        get => powAnchorHeight;
        init => powAnchorHeight = ToriiAccountFaucetMetadata.RequirePositive(
            value,
            nameof(PowAnchorHeight));
    }

    [JsonRequired, JsonPropertyName("pow_nonce_hex")]
    public string PowNonceHex
    {
        get => powNonceHex;
        init => powNonceHex = ToriiAccountFaucetMetadata.RequireFaucetNonceHex(
            value,
            nameof(PowNonceHex));
    }
}

/// <summary>
/// Independently trusted first-release faucet authority and exact issuance policy.
/// </summary>
public sealed record class ToriiAccountFaucetPolicyV1
{
    public ToriiAccountFaucetPolicyV1(
        string faucetAuthority,
        string assetDefinitionId,
        NumericV1.QuantityValue amount)
    {
        FaucetAuthority = ToriiAccountFaucetMetadata.RequireCanonicalAccountId(
            faucetAuthority,
            nameof(faucetAuthority));
        var authority = AccountAddress.Parse(FaucetAuthority);
        if (authority.AddressClass != AddressClass.SingleKey
            || authority.CurveIdentifier != CurveId.Ed25519)
        {
            throw new ArgumentException(
                "Faucet authority must be one canonical Ed25519 account.",
                nameof(faucetAuthority));
        }

        AssetDefinitionId = ToriiAccountFaucetMetadata.RequireExactTokenText(
            assetDefinitionId,
            nameof(assetDefinitionId));
        try
        {
            _ = new TransactionEncodingContext(FaucetAuthority)
                .EncodeAssetDefinitionId(AssetDefinitionId);
        }
        catch (ArgumentException error)
        {
            throw new ArgumentException(
                "Faucet asset definition must be canonical.",
                nameof(assetDefinitionId),
                error);
        }

        ArgumentNullException.ThrowIfNull(amount);
        if (amount.Mantissa.Sign <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(amount),
                "Faucet amount must be positive.");
        }
        Amount = amount;
    }

    public string FaucetAuthority { get; }

    public string AssetDefinitionId { get; }

    public NumericV1.QuantityValue Amount { get; }
}

/// <summary>Exact non-mutating faucet prepare request.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiAccountFaucetPrepareRequestV1
{
    public const string SchemaV1 = "iroha.accounts.faucet.prepare.v1";

    public ToriiAccountFaucetPrepareRequestV1(
        ToriiPreparedOperationBindingV1 binding,
        ToriiAccountFaucetClaimV1 claim,
        FeePaymentIntent feePayment)
        : this(SchemaV1, binding, claim, feePayment)
    {
    }

    [JsonConstructor]
    public ToriiAccountFaucetPrepareRequestV1(
        string schema,
        ToriiPreparedOperationBindingV1 binding,
        ToriiAccountFaucetClaimV1 claim,
        FeePaymentIntent feePayment)
    {
        if (!string.Equals(schema, SchemaV1, StringComparison.Ordinal))
        {
            throw new JsonException("Unsupported account faucet prepare schema.");
        }
        Binding = binding
            ?? throw new JsonException("Account faucet prepare binding is required.");
        Claim = claim
            ?? throw new JsonException("Account faucet prepare claim is required.");
        FeePayment = feePayment
            ?? throw new JsonException("Account faucet prepare fee_payment is required.");
        Schema = schema;
    }

    [JsonRequired, JsonPropertyName("schema")]
    public string Schema { get; init; }

    [JsonRequired, JsonPropertyName("binding")]
    public ToriiPreparedOperationBindingV1 Binding { get; init; }

    [JsonRequired, JsonPropertyName("claim")]
    public ToriiAccountFaucetClaimV1 Claim { get; init; }

    [JsonRequired, JsonPropertyName("fee_payment")]
    public FeePaymentIntent FeePayment { get; init; }
}

/// <summary>Authenticated exact faucet transaction prepared by Torii.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiAccountFaucetPreparedTransactionV1
{
    public const string SchemaV1 = "iroha.prepared-transaction.v1";
    public const string OperationV1 = "faucet";

    [JsonRequired, JsonPropertyName("schema")]
    public string Schema { get; init; } = SchemaV1;

    [JsonRequired, JsonPropertyName("binding")]
    public ToriiPreparedOperationBindingV1 Binding { get; init; } = new();

    [JsonRequired, JsonPropertyName("operation")]
    public string Operation { get; init; } = OperationV1;

    [JsonRequired, JsonPropertyName("claim")]
    public ToriiAccountFaucetClaimV1 Claim { get; init; } = null!;

    [JsonRequired, JsonPropertyName("semantic_hash_hex")]
    public string SemanticHashHex { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("account_id")]
    public string AccountId { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("asset_definition_id")]
    public string AssetDefinitionId { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("asset_id")]
    public string AssetId { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("amount")]
    public string Amount { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("transaction_hash_hex")]
    public string TransactionHashHex { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("signed_transaction_wire_hex")]
    public string SignedTransactionWireHex { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("signed_transaction_wire_sha256")]
    public string SignedTransactionWireSha256 { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("fee_payment")]
    public FeePaymentIntent FeePayment { get; init; } = null!;

    [JsonRequired, JsonPropertyName("server_signature")]
    public string ServerSignature { get; init; } = string.Empty;
}

/// <summary>Exact outcome for one submitted prepared transaction hash.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiPreparedTransactionSubmitResponseV1
{
    public const string SchemaV1 = "iroha.prepared-transaction-submit.v1";

    [JsonRequired, JsonPropertyName("schema")]
    public string Schema { get; init; } = SchemaV1;

    [JsonRequired, JsonPropertyName("binding")]
    public ToriiPreparedOperationBindingV1 Binding { get; init; } = new();

    [JsonRequired, JsonPropertyName("operation")]
    public string Operation { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("transaction_hash_hex")]
    public string TransactionHashHex { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("outcome")]
    public string Outcome { get; init; } = string.Empty;
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiVerifyingKeyRegisterRequest
{
    private byte[]? verifyingKeyBytes;

    [JsonPropertyName("authority")]
    public string? Authority { get; init; }

    [JsonPropertyName("backend")]
    public string? Backend { get; init; }

    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("version")]
    public uint? Version { get; init; }

    [JsonPropertyName("circuit_id")]
    public string? CircuitId { get; init; }

    [JsonPropertyName("public_inputs_schema_hash_hex")]
    public string? PublicInputsSchemaHashHex { get; init; }

    [JsonPropertyName("curve")]
    public string? Curve { get; init; }

    [JsonPropertyName("gas_schedule_id")]
    public string? GasScheduleId { get; init; }

    [JsonPropertyName("vk_len")]
    public uint? VerifyingKeyLength { get; init; }

    [JsonPropertyName("max_proof_bytes")]
    public uint? MaxProofBytes { get; init; }

    [JsonPropertyName("metadata_uri_cid")]
    public string? MetadataUriCid { get; init; }

    [JsonPropertyName("vk_bytes_cid")]
    public string? VerifyingKeyBytesCid { get; init; }

    [JsonPropertyName("activation_height")]
    public ulong? ActivationHeight { get; init; }

    [JsonPropertyName("withdraw_height")]
    public ulong? WithdrawHeight { get; init; }

    [JsonPropertyName("commitment_hex")]
    public string? CommitmentHex { get; init; }

    [JsonPropertyName("vk_bytes")]
    public byte[]? VerifyingKeyBytes
    {
        get => verifyingKeyBytes?.ToArray();
        init => verifyingKeyBytes = value?.ToArray();
    }

    [JsonPropertyName("status")]
    public string? Status { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiVerifyingKeyUpdateRequest
{
    private byte[]? verifyingKeyBytes;

    [JsonPropertyName("authority")]
    public string? Authority { get; init; }

    [JsonPropertyName("backend")]
    public string? Backend { get; init; }

    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("version")]
    public uint? Version { get; init; }

    [JsonPropertyName("circuit_id")]
    public string? CircuitId { get; init; }

    [JsonPropertyName("public_inputs_schema_hash_hex")]
    public string? PublicInputsSchemaHashHex { get; init; }

    [JsonPropertyName("curve")]
    public string? Curve { get; init; }

    [JsonPropertyName("gas_schedule_id")]
    public string? GasScheduleId { get; init; }

    [JsonPropertyName("commitment_hex")]
    public string? CommitmentHex { get; init; }

    [JsonPropertyName("vk_len")]
    public uint? VerifyingKeyLength { get; init; }

    [JsonPropertyName("max_proof_bytes")]
    public uint? MaxProofBytes { get; init; }

    [JsonPropertyName("metadata_uri_cid")]
    public string? MetadataUriCid { get; init; }

    [JsonPropertyName("vk_bytes_cid")]
    public string? VerifyingKeyBytesCid { get; init; }

    [JsonPropertyName("activation_height")]
    public ulong? ActivationHeight { get; init; }

    [JsonPropertyName("withdraw_height")]
    public ulong? WithdrawHeight { get; init; }

    [JsonPropertyName("vk_bytes")]
    public byte[]? VerifyingKeyBytes
    {
        get => verifyingKeyBytes?.ToArray();
        init => verifyingKeyBytes = value?.ToArray();
    }

    [JsonPropertyName("status")]
    public string? Status { get; init; }
}

/// <summary>
/// Exact unsigned transaction draft returned by verifying-key register/update routes.
/// </summary>
public sealed class ToriiVerifyingKeyTransactionDraft
{
    private readonly byte[] transactionPayload;
    private readonly byte[] signingMessage;

    internal ToriiVerifyingKeyTransactionDraft(
        string transactionPayloadBase64,
        string signingMessageBase64,
        byte[] transactionPayload,
        byte[] signingMessage)
    {
        Submitted = false;
        TransactionPayloadBase64 = transactionPayloadBase64;
        SigningMessageBase64 = signingMessageBase64;
        this.transactionPayload = transactionPayload.ToArray();
        this.signingMessage = signingMessage.ToArray();
    }

    /// <summary>
    /// Always <see langword="false"/> because the server never signs or submits the transaction.
    /// </summary>
    [JsonPropertyName("submitted")]
    public bool Submitted { get; }

    /// <summary>Canonical padded base64 containing the Norito <c>TransactionPayload</c>.</summary>
    [JsonPropertyName("transaction_payload_b64")]
    public string TransactionPayloadBase64 { get; }

    /// <summary>Canonical padded base64 containing the 32-byte Iroha payload prehash.</summary>
    [JsonPropertyName("signing_message_b64")]
    public string SigningMessageBase64 { get; }

    /// <summary>
    /// Canonical Norito payload bytes for SDK signers that apply the Iroha prehash themselves.
    /// </summary>
    [JsonIgnore]
    public byte[] TransactionPayload => transactionPayload.ToArray();

    /// <summary>
    /// Already-prehashed bytes for external signature primitives.
    /// </summary>
    [JsonIgnore]
    public byte[] SigningMessage => signingMessage.ToArray();
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiVpnQuoteCreateRequest
{
    [JsonPropertyName("exit_class")]
    public string ExitClass { get; init; } = string.Empty;

    [JsonPropertyName("metering_public_key_hex")]
    public string MeteringPublicKeyHex { get; init; } = string.Empty;
}

[JsonConverter(typeof(ToriiVpnQuoteJsonConverter))]
public sealed record class ToriiVpnQuote
{
    private string quoteId = string.Empty;
    private string leaseIdHex = string.Empty;
    private string sessionIdHex = string.Empty;
    private string paymentReference = string.Empty;
    private string accountId = string.Empty;
    private string exitClass = string.Empty;
    private string relayEndpoint = string.Empty;
    private ulong leaseSeconds;
    private ulong quoteExpiresAtMilliseconds;
    private string feeAssetId = string.Empty;
    private string escrowAccountId = string.Empty;
    private string operatorAccountId = string.Empty;
    private string leaseFee = string.Empty;
    private string[]? routePushes = Array.Empty<string>();
    private string[]? excludedRoutes = Array.Empty<string>();
    private string[]? dnsServers = Array.Empty<string>();
    private string[]? tunnelAddresses = Array.Empty<string>();
    private ulong mtuBytes;
    private string meterFamily = string.Empty;
    private string relayIdHex = string.Empty;
    private string relayMldsa65PublicKeyHex = string.Empty;
    private string descriptorCommitHex = string.Empty;
    private string tlsServerName = string.Empty;
    private string relayTlsSpkiSha256Hex = string.Empty;
    private string relayCertificateSha256Hex = string.Empty;
    private string directorySnapshotDigestHex = string.Empty;
    private string meteringPublicKeyHex = string.Empty;
    private ToriiVpnTxInstruction openLeaseInstruction = null!;

    [JsonPropertyName("quote_id")]
    public string QuoteId
    {
        get => quoteId;
        init => quoteId = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(QuoteId), 32);
    }

    [JsonPropertyName("lease_id_hex")]
    public string LeaseIdHex
    {
        get => leaseIdHex;
        init => leaseIdHex = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(LeaseIdHex), 32);
    }

    [JsonPropertyName("session_id_hex")]
    public string SessionIdHex
    {
        get => sessionIdHex;
        init => sessionIdHex = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(SessionIdHex), 16);
    }

    [JsonPropertyName("payment_reference")]
    public string PaymentReference
    {
        get => paymentReference;
        init => paymentReference = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(PaymentReference));
    }

    [JsonPropertyName("account_id")]
    public string AccountId
    {
        get => accountId;
        init => accountId = ToriiVpnDirectMetadata.RequireCanonicalAccountId(value, nameof(AccountId));
    }

    [JsonPropertyName("exit_class")]
    public string ExitClass
    {
        get => exitClass;
        init => exitClass = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(ExitClass));
    }

    [JsonPropertyName("relay_endpoint")]
    public string RelayEndpoint
    {
        get => relayEndpoint;
        init => relayEndpoint = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(RelayEndpoint));
    }

    [JsonPropertyName("lease_secs")]
    public ulong LeaseSeconds
    {
        get => leaseSeconds;
        init => leaseSeconds = ToriiVpnDirectMetadata.RequirePositive(value, nameof(LeaseSeconds));
    }

    [JsonPropertyName("quote_expires_at_ms")]
    public ulong QuoteExpiresAtMilliseconds
    {
        get => quoteExpiresAtMilliseconds;
        init => quoteExpiresAtMilliseconds = ToriiVpnDirectMetadata.RequirePositive(
            value,
            nameof(QuoteExpiresAtMilliseconds));
    }

    [JsonPropertyName("fee_asset_id")]
    public string FeeAssetId
    {
        get => feeAssetId;
        init => feeAssetId = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(FeeAssetId));
    }

    [JsonPropertyName("escrow_account_id")]
    public string EscrowAccountId
    {
        get => escrowAccountId;
        init => escrowAccountId = ToriiVpnDirectMetadata.RequireCanonicalAccountId(value, nameof(EscrowAccountId));
    }

    [JsonPropertyName("operator_account_id")]
    public string OperatorAccountId
    {
        get => operatorAccountId;
        init => operatorAccountId = ToriiVpnDirectMetadata.RequireCanonicalAccountId(value, nameof(OperatorAccountId));
    }

    [JsonPropertyName("lease_fee")]
    public string LeaseFee
    {
        get => leaseFee;
        init => leaseFee = ToriiQuantityJson.RequireCanonicalQuantity(value, nameof(LeaseFee));
    }

    [JsonPropertyName("route_pushes")]
    public IReadOnlyList<string>? RoutePushes
    {
        get => ToriiListSnapshots.Copy(routePushes);
        init => routePushes = ToriiVpnDirectMetadata.CopyOptionalExactTokenTextList(value, nameof(RoutePushes));
    }

    [JsonPropertyName("excluded_routes")]
    public IReadOnlyList<string>? ExcludedRoutes
    {
        get => ToriiListSnapshots.Copy(excludedRoutes);
        init => excludedRoutes = ToriiVpnDirectMetadata.CopyOptionalExactTokenTextList(value, nameof(ExcludedRoutes));
    }

    [JsonPropertyName("dns_servers")]
    public IReadOnlyList<string>? DnsServers
    {
        get => ToriiListSnapshots.Copy(dnsServers);
        init => dnsServers = ToriiVpnDirectMetadata.CopyOptionalExactTokenTextList(value, nameof(DnsServers));
    }

    [JsonPropertyName("tunnel_addresses")]
    public IReadOnlyList<string>? TunnelAddresses
    {
        get => ToriiListSnapshots.Copy(tunnelAddresses);
        init => tunnelAddresses = ToriiVpnDirectMetadata.CopyOptionalExactTokenTextList(value, nameof(TunnelAddresses));
    }

    [JsonPropertyName("mtu_bytes")]
    public ulong MtuBytes
    {
        get => mtuBytes;
        init => mtuBytes = ToriiVpnDirectMetadata.RequirePositive(value, nameof(MtuBytes));
    }

    [JsonPropertyName("meter_family")]
    public string MeterFamily
    {
        get => meterFamily;
        init => meterFamily = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(MeterFamily));
    }

    [JsonPropertyName("flow_label_bits")]
    public byte FlowLabelBits { get; init; }

    [JsonPropertyName("padding_budget_ms")]
    public ushort PaddingBudgetMilliseconds { get; init; }

    [JsonPropertyName("relay_id_hex")]
    public string RelayIdHex
    {
        get => relayIdHex;
        init => relayIdHex = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(RelayIdHex), 32);
    }

    [JsonPropertyName("relay_mldsa65_public_key_hex")]
    public string RelayMldsa65PublicKeyHex
    {
        get => relayMldsa65PublicKeyHex;
        init => relayMldsa65PublicKeyHex = ToriiVpnDirectMetadata.RequireNonZeroExactSizedHex(
            value,
            nameof(RelayMldsa65PublicKeyHex),
            ToriiVpnDirectMetadata.RelayMldsa65PublicKeyByteLength);
    }

    [JsonPropertyName("descriptor_commit_hex")]
    public string DescriptorCommitHex
    {
        get => descriptorCommitHex;
        init => descriptorCommitHex = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(DescriptorCommitHex), 32);
    }

    [JsonPropertyName("tls_server_name")]
    public string TlsServerName
    {
        get => tlsServerName;
        init => tlsServerName = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(TlsServerName));
    }

    [JsonPropertyName("relay_tls_spki_sha256_hex")]
    public string RelayTlsSpkiSha256Hex
    {
        get => relayTlsSpkiSha256Hex;
        init => relayTlsSpkiSha256Hex = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(RelayTlsSpkiSha256Hex), 32);
    }

    [JsonPropertyName("relay_certificate_sha256_hex")]
    public string RelayCertificateSha256Hex
    {
        get => relayCertificateSha256Hex;
        init => relayCertificateSha256Hex = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(RelayCertificateSha256Hex), 32);
    }

    [JsonPropertyName("directory_snapshot_digest_hex")]
    public string DirectorySnapshotDigestHex
    {
        get => directorySnapshotDigestHex;
        init => directorySnapshotDigestHex = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(DirectorySnapshotDigestHex), 32);
    }

    [JsonPropertyName("metering_public_key_hex")]
    public string MeteringPublicKeyHex
    {
        get => meteringPublicKeyHex;
        init => meteringPublicKeyHex = ToriiVpnDirectMetadata.RequireExactSizedHex(
            value,
            nameof(MeteringPublicKeyHex),
            32);
    }

    [JsonPropertyName("open_lease_instruction")]
    public ToriiVpnTxInstruction OpenLeaseInstruction
    {
        get => openLeaseInstruction;
        init => openLeaseInstruction = ToriiVpnDirectMetadata.RequireVpnTxInstruction(
            value,
            nameof(OpenLeaseInstruction));
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiVpnSessionCreateRequest
{
    [JsonPropertyName("exit_class")]
    public string ExitClass { get; init; } = string.Empty;

    [JsonPropertyName("quote_id")]
    public string QuoteId { get; init; } = string.Empty;

    [JsonPropertyName("payment_tx_hash")]
    public string PaymentTransactionHash { get; init; } = string.Empty;

    [JsonPropertyName("metering_public_key_hex")]
    public string MeteringPublicKeyHex { get; init; } = string.Empty;
}

[JsonConverter(typeof(ToriiVpnSessionJsonConverter))]
public sealed record class ToriiVpnSession
{
    private string sessionId = string.Empty;
    private string accountId = string.Empty;
    private string exitClass = string.Empty;
    private string relayEndpoint = string.Empty;
    private ulong leaseSeconds;
    private ulong expiresAtMilliseconds;
    private ulong connectedAtMilliseconds;
    private string meterFamily = string.Empty;
    private string quoteId = string.Empty;
    private string paymentReference = string.Empty;
    private string paymentTransactionHash = string.Empty;
    private string feeAssetId = string.Empty;
    private string escrowAccountId = string.Empty;
    private string operatorAccountId = string.Empty;
    private string leaseFee = string.Empty;
    private string relayIdHex = string.Empty;
    private string relayMldsa65PublicKeyHex = string.Empty;
    private string descriptorCommitHex = string.Empty;
    private string tlsServerName = string.Empty;
    private string relayTlsSpkiSha256Hex = string.Empty;
    private string relayCertificateSha256Hex = string.Empty;
    private string directorySnapshotDigestHex = string.Empty;
    private string[]? routePushes = Array.Empty<string>();
    private string[]? excludedRoutes = Array.Empty<string>();
    private string[]? dnsServers = Array.Empty<string>();
    private string[]? tunnelAddresses = Array.Empty<string>();
    private ulong mtuBytes;
    private string helperTicketHex = string.Empty;
    private string status = string.Empty;

    [JsonPropertyName("session_id")]
    public string SessionId
    {
        get => sessionId;
        init => sessionId = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(SessionId), 16);
    }

    [JsonPropertyName("account_id")]
    public string AccountId
    {
        get => accountId;
        init => accountId = ToriiVpnDirectMetadata.RequireCanonicalAccountId(value, nameof(AccountId));
    }

    [JsonPropertyName("exit_class")]
    public string ExitClass
    {
        get => exitClass;
        init => exitClass = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(ExitClass));
    }

    [JsonPropertyName("relay_endpoint")]
    public string RelayEndpoint
    {
        get => relayEndpoint;
        init => relayEndpoint = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(RelayEndpoint));
    }

    [JsonPropertyName("lease_secs")]
    public ulong LeaseSeconds
    {
        get => leaseSeconds;
        init => leaseSeconds = ToriiVpnDirectMetadata.RequirePositive(value, nameof(LeaseSeconds));
    }

    [JsonPropertyName("expires_at_ms")]
    public ulong ExpiresAtMilliseconds
    {
        get => expiresAtMilliseconds;
        init => expiresAtMilliseconds = ToriiVpnDirectMetadata.RequirePositive(value, nameof(ExpiresAtMilliseconds));
    }

    [JsonPropertyName("connected_at_ms")]
    public ulong ConnectedAtMilliseconds
    {
        get => connectedAtMilliseconds;
        init => connectedAtMilliseconds = ToriiVpnDirectMetadata.RequirePositive(
            value,
            nameof(ConnectedAtMilliseconds));
    }

    [JsonPropertyName("meter_family")]
    public string MeterFamily
    {
        get => meterFamily;
        init => meterFamily = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(MeterFamily));
    }

    [JsonPropertyName("quote_id")]
    public string QuoteId
    {
        get => quoteId;
        init => quoteId = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(QuoteId), 32);
    }

    [JsonPropertyName("payment_reference")]
    public string PaymentReference
    {
        get => paymentReference;
        init => paymentReference = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(PaymentReference));
    }

    [JsonPropertyName("payment_tx_hash")]
    public string PaymentTransactionHash
    {
        get => paymentTransactionHash;
        init => paymentTransactionHash = ToriiVpnDirectMetadata.RequireExactSizedHex(
            value,
            nameof(PaymentTransactionHash),
            32);
    }

    [JsonPropertyName("fee_asset_id")]
    public string FeeAssetId
    {
        get => feeAssetId;
        init => feeAssetId = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(FeeAssetId));
    }

    [JsonPropertyName("escrow_account_id")]
    public string EscrowAccountId
    {
        get => escrowAccountId;
        init => escrowAccountId = ToriiVpnDirectMetadata.RequireCanonicalAccountId(value, nameof(EscrowAccountId));
    }

    [JsonPropertyName("operator_account_id")]
    public string OperatorAccountId
    {
        get => operatorAccountId;
        init => operatorAccountId = ToriiVpnDirectMetadata.RequireCanonicalAccountId(value, nameof(OperatorAccountId));
    }

    [JsonPropertyName("lease_fee")]
    public string LeaseFee
    {
        get => leaseFee;
        init => leaseFee = ToriiQuantityJson.RequireCanonicalQuantity(value, nameof(LeaseFee));
    }

    [JsonPropertyName("flow_label_bits")]
    public byte FlowLabelBits { get; init; }

    [JsonPropertyName("padding_budget_ms")]
    public ushort PaddingBudgetMilliseconds { get; init; }

    [JsonPropertyName("relay_id_hex")]
    public string RelayIdHex
    {
        get => relayIdHex;
        init => relayIdHex = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(RelayIdHex), 32);
    }

    [JsonPropertyName("relay_mldsa65_public_key_hex")]
    public string RelayMldsa65PublicKeyHex
    {
        get => relayMldsa65PublicKeyHex;
        init => relayMldsa65PublicKeyHex = ToriiVpnDirectMetadata.RequireNonZeroExactSizedHex(
            value,
            nameof(RelayMldsa65PublicKeyHex),
            ToriiVpnDirectMetadata.RelayMldsa65PublicKeyByteLength);
    }

    [JsonPropertyName("descriptor_commit_hex")]
    public string DescriptorCommitHex
    {
        get => descriptorCommitHex;
        init => descriptorCommitHex = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(DescriptorCommitHex), 32);
    }

    [JsonPropertyName("tls_server_name")]
    public string TlsServerName
    {
        get => tlsServerName;
        init => tlsServerName = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(TlsServerName));
    }

    [JsonPropertyName("relay_tls_spki_sha256_hex")]
    public string RelayTlsSpkiSha256Hex
    {
        get => relayTlsSpkiSha256Hex;
        init => relayTlsSpkiSha256Hex = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(RelayTlsSpkiSha256Hex), 32);
    }

    [JsonPropertyName("relay_certificate_sha256_hex")]
    public string RelayCertificateSha256Hex
    {
        get => relayCertificateSha256Hex;
        init => relayCertificateSha256Hex = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(RelayCertificateSha256Hex), 32);
    }

    [JsonPropertyName("directory_snapshot_digest_hex")]
    public string DirectorySnapshotDigestHex
    {
        get => directorySnapshotDigestHex;
        init => directorySnapshotDigestHex = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(DirectorySnapshotDigestHex), 32);
    }

    [JsonPropertyName("route_pushes")]
    public IReadOnlyList<string>? RoutePushes
    {
        get => ToriiListSnapshots.Copy(routePushes);
        init => routePushes = ToriiVpnDirectMetadata.CopyOptionalExactTokenTextList(value, nameof(RoutePushes));
    }

    [JsonPropertyName("excluded_routes")]
    public IReadOnlyList<string>? ExcludedRoutes
    {
        get => ToriiListSnapshots.Copy(excludedRoutes);
        init => excludedRoutes = ToriiVpnDirectMetadata.CopyOptionalExactTokenTextList(value, nameof(ExcludedRoutes));
    }

    [JsonPropertyName("dns_servers")]
    public IReadOnlyList<string>? DnsServers
    {
        get => ToriiListSnapshots.Copy(dnsServers);
        init => dnsServers = ToriiVpnDirectMetadata.CopyOptionalExactTokenTextList(value, nameof(DnsServers));
    }

    [JsonPropertyName("tunnel_addresses")]
    public IReadOnlyList<string>? TunnelAddresses
    {
        get => ToriiListSnapshots.Copy(tunnelAddresses);
        init => tunnelAddresses = ToriiVpnDirectMetadata.CopyOptionalExactTokenTextList(value, nameof(TunnelAddresses));
    }

    [JsonPropertyName("mtu_bytes")]
    public ulong MtuBytes
    {
        get => mtuBytes;
        init => mtuBytes = ToriiVpnDirectMetadata.RequirePositive(value, nameof(MtuBytes));
    }

    [JsonPropertyName("helper_ticket_hex")]
    public string HelperTicketHex
    {
        get => helperTicketHex;
        init => helperTicketHex = ToriiVpnDirectMetadata.RequireExactSizedHex(
            value,
            nameof(HelperTicketHex),
            ToriiVpnDirectMetadata.HelperTicketByteLength);
    }

    [JsonPropertyName("bytes_in")]
    public ulong BytesIn { get; init; }

    [JsonPropertyName("bytes_out")]
    public ulong BytesOut { get; init; }

    [JsonPropertyName("status")]
    public string Status
    {
        get => status;
        init => status = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(Status));
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiVpnReceiptSubmitRequest
{
    [JsonPropertyName("relay_receipt_hex")]
    public string RelayReceiptHex { get; init; } = string.Empty;

    [JsonPropertyName("client_voucher_hex")]
    public string ClientVoucherHex { get; init; } = string.Empty;

    [JsonPropertyName("lease_id_hex")]
    public string LeaseIdHex { get; init; } = string.Empty;
}

[JsonConverter(typeof(ToriiVpnReceiptJsonConverter))]
public sealed record class ToriiVpnReceipt
{
    private string sessionId = string.Empty;
    private string accountId = string.Empty;
    private string exitClass = string.Empty;
    private string relayEndpoint = string.Empty;
    private string meterFamily = string.Empty;
    private ulong connectedAtMilliseconds;
    private ulong disconnectedAtMilliseconds;
    private string status = string.Empty;
    private string receiptSource = string.Empty;
    private string quoteId = string.Empty;
    private string paymentTransactionHash = string.Empty;
    private string feeAssetId = string.Empty;
    private string escrowAccountId = string.Empty;
    private string operatorAccountId = string.Empty;
    private string leaseFee = string.Empty;
    private string earnedFee = string.Empty;
    private string refundedFee = string.Empty;
    private string leaseIdHex = string.Empty;
    private ToriiVpnTxInstruction? settleLeaseInstruction;

    [JsonPropertyName("session_id")]
    public string SessionId
    {
        get => sessionId;
        init => sessionId = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(SessionId), 16);
    }

    [JsonPropertyName("account_id")]
    public string AccountId
    {
        get => accountId;
        init => accountId = ToriiVpnDirectMetadata.RequireCanonicalAccountId(value, nameof(AccountId));
    }

    [JsonPropertyName("exit_class")]
    public string ExitClass
    {
        get => exitClass;
        init => exitClass = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(ExitClass));
    }

    [JsonPropertyName("relay_endpoint")]
    public string RelayEndpoint
    {
        get => relayEndpoint;
        init => relayEndpoint = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(RelayEndpoint));
    }

    [JsonPropertyName("meter_family")]
    public string MeterFamily
    {
        get => meterFamily;
        init => meterFamily = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(MeterFamily));
    }

    [JsonPropertyName("connected_at_ms")]
    public ulong ConnectedAtMilliseconds
    {
        get => connectedAtMilliseconds;
        init => connectedAtMilliseconds = ToriiVpnDirectMetadata.RequirePositive(
            value,
            nameof(ConnectedAtMilliseconds));
    }

    [JsonPropertyName("disconnected_at_ms")]
    public ulong DisconnectedAtMilliseconds
    {
        get => disconnectedAtMilliseconds;
        init => disconnectedAtMilliseconds = ToriiVpnDirectMetadata.RequirePositive(
            value,
            nameof(DisconnectedAtMilliseconds));
    }

    [JsonPropertyName("duration_ms")]
    public ulong DurationMilliseconds { get; init; }

    [JsonPropertyName("bytes_in")]
    public ulong BytesIn { get; init; }

    [JsonPropertyName("bytes_out")]
    public ulong BytesOut { get; init; }

    [JsonPropertyName("status")]
    public string Status
    {
        get => status;
        init => status = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(Status));
    }

    [JsonPropertyName("receipt_source")]
    public string ReceiptSource
    {
        get => receiptSource;
        init => receiptSource = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(ReceiptSource));
    }

    [JsonPropertyName("quote_id")]
    public string QuoteId
    {
        get => quoteId;
        init => quoteId = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(QuoteId), 32);
    }

    [JsonPropertyName("payment_tx_hash")]
    public string PaymentTransactionHash
    {
        get => paymentTransactionHash;
        init => paymentTransactionHash = ToriiVpnDirectMetadata.RequireExactSizedHex(
            value,
            nameof(PaymentTransactionHash),
            32);
    }

    [JsonPropertyName("fee_asset_id")]
    public string FeeAssetId
    {
        get => feeAssetId;
        init => feeAssetId = ToriiVpnDirectMetadata.RequireExactTokenText(value, nameof(FeeAssetId));
    }

    [JsonPropertyName("escrow_account_id")]
    public string EscrowAccountId
    {
        get => escrowAccountId;
        init => escrowAccountId = ToriiVpnDirectMetadata.RequireCanonicalAccountId(value, nameof(EscrowAccountId));
    }

    [JsonPropertyName("operator_account_id")]
    public string OperatorAccountId
    {
        get => operatorAccountId;
        init => operatorAccountId = ToriiVpnDirectMetadata.RequireCanonicalAccountId(value, nameof(OperatorAccountId));
    }

    [JsonPropertyName("lease_fee")]
    public string LeaseFee
    {
        get => leaseFee;
        init => leaseFee = ToriiQuantityJson.RequireCanonicalQuantity(value, nameof(LeaseFee));
    }

    [JsonPropertyName("earned_fee")]
    public string EarnedFee
    {
        get => earnedFee;
        init => earnedFee = ToriiQuantityJson.RequireCanonicalQuantity(value, nameof(EarnedFee));
    }

    [JsonPropertyName("refunded_fee")]
    public string RefundedFee
    {
        get => refundedFee;
        init => refundedFee = ToriiQuantityJson.RequireCanonicalQuantity(value, nameof(RefundedFee));
    }

    [JsonPropertyName("lease_id_hex")]
    public string LeaseIdHex
    {
        get => leaseIdHex;
        init => leaseIdHex = ToriiVpnDirectMetadata.RequireExactSizedHex(value, nameof(LeaseIdHex), 32);
    }

    [JsonPropertyName("settle_lease_instruction")]
    public ToriiVpnTxInstruction? SettleLeaseInstruction
    {
        get => settleLeaseInstruction;
        init => settleLeaseInstruction = ToriiVpnDirectMetadata.RequireOptionalVpnTxInstruction(
            value,
            nameof(SettleLeaseInstruction));
    }
}

[JsonConverter(typeof(ToriiVpnReceiptListResponseJsonConverter))]
public sealed record class ToriiVpnReceiptListResponse
{
    private ToriiVpnReceipt[] items = Array.Empty<ToriiVpnReceipt>();

    [JsonPropertyName("items")]
    public IReadOnlyList<ToriiVpnReceipt> Items
    {
        get => ToriiListSnapshots.CopyRequired(items);
        init => items = ToriiVpnDirectMetadata.CopyRequiredVpnReceipts(value, nameof(Items));
    }

    [JsonPropertyName("total")]
    public ulong Total { get; init; }
}

internal static class ToriiVpnDirectMetadata
{
    internal const int HelperTicketByteLength = 788;
    internal const int RelayMldsa65PublicKeyByteLength = 1952;

    internal static ulong RequirePositive(ulong value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequirePositive(value, paramName);
    }

    internal static ulong RequireAtLeast(ulong value, ulong minimum, string paramName)
    {
        if (value < minimum)
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                value,
                $"Value must be at least {minimum}.");
        }

        return value;
    }

    internal static string RequireCanonicalAccountId(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, paramName);
    }

    internal static string RequireExactTokenText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireExactTokenText(value, paramName);
    }

    internal static string RequireEmptyOrExactTokenText(string? value, string paramName)
    {
        if (value is null)
        {
            throw new ArgumentNullException(paramName);
        }

        return value.Length == 0 ? value : RequireExactTokenText(value, paramName);
    }

    internal static string RequireExactNonEmptyText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, paramName);
    }

    internal static string RequireExactSizedHex(string? value, string paramName, int expectedBytes)
    {
        return ToriiExplorerDirectMetadata.RequireExactSizedHex(value, paramName, expectedBytes);
    }

    internal static string RequireEmptyOrExactSizedHex(string? value, string paramName, int expectedBytes)
    {
        if (value is null)
        {
            throw new ArgumentNullException(paramName);
        }

        return value.Length == 0 ? value : RequireExactSizedHex(value, paramName, expectedBytes);
    }

    internal static string RequireNonZeroExactSizedHex(
        string? value,
        string paramName,
        int expectedBytes)
    {
        var canonical = RequireExactSizedHex(value, paramName, expectedBytes);
        if (canonical.AsSpan().IndexOfAnyExcept('0') < 0)
        {
            throw new ArgumentException("Value must not be all zero.", paramName);
        }

        return canonical;
    }

    internal static string RequireEmptyOrNonZeroExactSizedHex(
        string? value,
        string paramName,
        int expectedBytes)
    {
        if (value is null)
        {
            throw new ArgumentNullException(paramName);
        }

        return value.Length == 0
            ? value
            : RequireNonZeroExactSizedHex(value, paramName, expectedBytes);
    }

    internal static string? RequireOptionalExactSizedHex(string? value, string paramName, int expectedBytes)
    {
        return ToriiExplorerDirectMetadata.RequireOptionalExactSizedHex(value, paramName, expectedBytes);
    }

    internal static string RequireExactEvenLengthHex(string? value, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value must be a non-empty even-length hex string.", paramName);
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new ArgumentException("Value must not contain surrounding whitespace.", paramName);
        }

        foreach (var character in value)
        {
            if (char.IsWhiteSpace(character))
            {
                throw new ArgumentException("Value must not contain whitespace.", paramName);
            }

            if (char.IsControl(character))
            {
                throw new ArgumentException("Value must not contain control characters.", paramName);
            }
        }

        if (value.Length % 2 != 0 || !value.All(static character => character is (>= '0' and <= '9') or (>= 'a' and <= 'f')))
        {
            throw new ArgumentException("Value must be an exact lowercase even-length hex string.", paramName);
        }

        return value;
    }

    internal static string[]? CopyOptionalExactTokenTextList(IReadOnlyList<string>? values, string paramName)
    {
        if (values is null)
        {
            return null;
        }

        var copy = new string[values.Count];
        for (var index = 0; index < values.Count; index++)
        {
            var value = values[index];
            if (value is null)
            {
                throw new ArgumentException("List elements must not be null.", $"{paramName}[{index}]");
            }

            copy[index] = RequireExactTokenText(value, $"{paramName}[{index}]");
        }

        return copy;
    }

    internal static ToriiVpnTxInstruction? RequireOptionalVpnTxInstruction(
        ToriiVpnTxInstruction? value,
        string paramName)
    {
        return value is null ? null : RequireVpnTxInstruction(value, paramName);
    }

    internal static ToriiVpnReceipt[] CopyRequiredVpnReceipts(
        IReadOnlyList<ToriiVpnReceipt>? values,
        string paramName)
    {
        if (values is null)
        {
            return Array.Empty<ToriiVpnReceipt>();
        }

        var copy = new ToriiVpnReceipt[values.Count];
        for (var index = 0; index < values.Count; index++)
        {
            var value = values[index];
            if (value is null)
            {
                throw new ArgumentException("List elements must not be null.", $"{paramName}[{index}]");
            }

            copy[index] = RequireVpnReceipt(value, $"{paramName}[{index}]");
        }

        return copy;
    }

    internal static ToriiVpnTxInstruction RequireVpnTxInstruction(ToriiVpnTxInstruction value, string paramName)
    {
        ArgumentNullException.ThrowIfNull(value, paramName);
        RequireExactNonEmptyText(value.WireId, $"{paramName}.{nameof(ToriiVpnTxInstruction.WireId)}");
        RequireExactEvenLengthHex(value.PayloadHex, $"{paramName}.{nameof(ToriiVpnTxInstruction.PayloadHex)}");
        return value;
    }

    private static ToriiVpnReceipt RequireVpnReceipt(ToriiVpnReceipt value, string paramName)
    {
        RequireExactSizedHex(value.SessionId, $"{paramName}.{nameof(ToriiVpnReceipt.SessionId)}", 16);
        RequireCanonicalAccountId(value.AccountId, $"{paramName}.{nameof(ToriiVpnReceipt.AccountId)}");
        RequireExactTokenText(value.ExitClass, $"{paramName}.{nameof(ToriiVpnReceipt.ExitClass)}");
        RequireExactTokenText(value.RelayEndpoint, $"{paramName}.{nameof(ToriiVpnReceipt.RelayEndpoint)}");
        RequireExactTokenText(value.MeterFamily, $"{paramName}.{nameof(ToriiVpnReceipt.MeterFamily)}");
        RequirePositive(value.ConnectedAtMilliseconds, $"{paramName}.{nameof(ToriiVpnReceipt.ConnectedAtMilliseconds)}");
        RequirePositive(value.DisconnectedAtMilliseconds, $"{paramName}.{nameof(ToriiVpnReceipt.DisconnectedAtMilliseconds)}");
        RequireExactTokenText(value.Status, $"{paramName}.{nameof(ToriiVpnReceipt.Status)}");
        RequireExactTokenText(value.ReceiptSource, $"{paramName}.{nameof(ToriiVpnReceipt.ReceiptSource)}");
        RequireExactSizedHex(value.QuoteId, $"{paramName}.{nameof(ToriiVpnReceipt.QuoteId)}", 32);
        RequireExactSizedHex(value.PaymentTransactionHash, $"{paramName}.{nameof(ToriiVpnReceipt.PaymentTransactionHash)}", 32);
        RequireExactTokenText(value.FeeAssetId, $"{paramName}.{nameof(ToriiVpnReceipt.FeeAssetId)}");
        RequireCanonicalAccountId(value.EscrowAccountId, $"{paramName}.{nameof(ToriiVpnReceipt.EscrowAccountId)}");
        RequireCanonicalAccountId(value.OperatorAccountId, $"{paramName}.{nameof(ToriiVpnReceipt.OperatorAccountId)}");
        RequireExactSizedHex(value.LeaseIdHex, $"{paramName}.{nameof(ToriiVpnReceipt.LeaseIdHex)}", 32);
        RequireOptionalVpnTxInstruction(value.SettleLeaseInstruction, $"{paramName}.{nameof(ToriiVpnReceipt.SettleLeaseInstruction)}");
        return value;
    }
}

/// <summary>Canonical materialized account returned by the exact account read route.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiAccountReadResponse
{
    private JsonElement[] opaqueIds = Array.Empty<JsonElement>();

    [JsonRequired, JsonPropertyName("account_id")]
    public string AccountId { get; init; } = string.Empty;

    [JsonPropertyName("label")]
    public JsonElement? Label { get; init; }

    [JsonPropertyName("uaid")]
    public JsonElement? Uaid { get; init; }

    [JsonRequired, JsonPropertyName("opaque_ids")]
    public IReadOnlyList<JsonElement> OpaqueIds
    {
        get => ToriiListSnapshots.CopyRequired(opaqueIds);
        init => opaqueIds = ToriiListSnapshots.CopyRequired(value);
    }
}

[JsonConverter(typeof(ToriiAssetAliasBindingJsonConverter))]
public sealed record class ToriiAssetAliasBinding
{
    private string alias = string.Empty;
    private string status = string.Empty;
    private long? leaseExpiryMilliseconds;
    private long? graceUntilMilliseconds;
    private long boundAtMilliseconds;

    [JsonPropertyName("alias")]
    public string Alias
    {
        get => alias;
        init => alias = ToriiAliasDirectMetadata.RequireExactTokenText(value, nameof(Alias));
    }

    [JsonPropertyName("status")]
    public string Status
    {
        get => status;
        init => status = ToriiAliasDirectMetadata.RequireExactTokenText(value, nameof(Status));
    }

    [JsonPropertyName("lease_expiry_ms")]
    public long? LeaseExpiryMilliseconds
    {
        get => leaseExpiryMilliseconds;
        init => leaseExpiryMilliseconds = ToriiAliasDirectMetadata.RequireOptionalPositive(
            value,
            nameof(LeaseExpiryMilliseconds));
    }

    [JsonPropertyName("grace_until_ms")]
    public long? GraceUntilMilliseconds
    {
        get => graceUntilMilliseconds;
        init => graceUntilMilliseconds = ToriiAliasDirectMetadata.RequireOptionalPositive(
            value,
            nameof(GraceUntilMilliseconds));
    }

    [JsonPropertyName("bound_at_ms")]
    public long BoundAtMilliseconds
    {
        get => boundAtMilliseconds;
        init => boundAtMilliseconds = ToriiAliasDirectMetadata.RequirePositive(value, nameof(BoundAtMilliseconds));
    }
}

[JsonConverter(typeof(ToriiAssetAliasResolutionJsonConverter))]
public sealed record class ToriiAssetAliasResolution
{
    private string alias = string.Empty;
    private string assetDefinitionId = string.Empty;
    private string assetName = string.Empty;
    private string? description;
    private string? logo;
    private string? source;

    [JsonPropertyName("alias")]
    public string Alias
    {
        get => alias;
        init => alias = ToriiAliasDirectMetadata.RequireExactTokenText(value, nameof(Alias));
    }

    [JsonPropertyName("asset_definition_id")]
    public string AssetDefinitionId
    {
        get => assetDefinitionId;
        init => assetDefinitionId = ToriiAliasDirectMetadata.RequireExactTokenText(
            value,
            nameof(AssetDefinitionId));
    }

    [JsonPropertyName("asset_name")]
    public string AssetName
    {
        get => assetName;
        init => assetName = ToriiAliasDirectMetadata.RequireExactTokenText(value, nameof(AssetName));
    }

    [JsonPropertyName("alias_binding")]
    public ToriiAssetAliasBinding? AliasBinding { get; init; }

    [JsonPropertyName("description")]
    public string? Description
    {
        get => description;
        init => description = ToriiAliasDirectMetadata.RequireOptionalExactNonEmptyText(
            value,
            nameof(Description));
    }

    [JsonPropertyName("logo")]
    public string? Logo
    {
        get => logo;
        init => logo = ToriiAliasDirectMetadata.RequireOptionalExactTokenText(value, nameof(Logo));
    }

    [JsonPropertyName("source")]
    public string? Source
    {
        get => source;
        init => source = ToriiAliasDirectMetadata.RequireOptionalExactTokenText(value, nameof(Source));
    }
}

[JsonConverter(typeof(ToriiAccountAliasResolutionJsonConverter))]
public sealed record class ToriiAccountAliasResolution
{
    private string alias = string.Empty;
    private string accountId = string.Empty;
    private long? index;
    private string? source;

    [JsonPropertyName("alias")]
    public string Alias
    {
        get => alias;
        init => alias = ToriiAliasDirectMetadata.RequireExactTokenText(value, nameof(Alias));
    }

    [JsonPropertyName("account_id")]
    public string AccountId
    {
        get => accountId;
        init => accountId = ToriiAliasDirectMetadata.RequireCanonicalAccountId(value, nameof(AccountId));
    }

    [JsonPropertyName("index")]
    public long? Index
    {
        get => index;
        init => index = ToriiAliasDirectMetadata.RequireOptionalNonNegative(value, nameof(Index));
    }

    [JsonPropertyName("source")]
    public string? Source
    {
        get => source;
        init => source = ToriiAliasDirectMetadata.RequireOptionalExactTokenText(value, nameof(Source));
    }
}

[JsonConverter(typeof(ToriiAccountAliasIndexResolutionJsonConverter))]
public sealed record class ToriiAccountAliasIndexResolution
{
    private string alias = string.Empty;
    private string accountId = string.Empty;
    private string? source;

    [JsonPropertyName("index")]
    public ulong Index { get; init; }

    [JsonPropertyName("alias")]
    public string Alias
    {
        get => alias;
        init => alias = ToriiAliasDirectMetadata.RequireExactTokenText(value, nameof(Alias));
    }

    [JsonPropertyName("account_id")]
    public string AccountId
    {
        get => accountId;
        init => accountId = ToriiAliasDirectMetadata.RequireCanonicalAccountId(value, nameof(AccountId));
    }

    [JsonPropertyName("source")]
    public string? Source
    {
        get => source;
        init => source = ToriiAliasDirectMetadata.RequireOptionalExactTokenText(value, nameof(Source));
    }
}

[JsonConverter(typeof(ToriiAccountAliasLookupItemJsonConverter))]
public sealed record class ToriiAccountAliasLookupItem
{
    private string alias = string.Empty;
    private string dataspace = string.Empty;
    private string? domain;

    [JsonPropertyName("alias")]
    public string Alias
    {
        get => alias;
        init => alias = ToriiAliasDirectMetadata.RequireExactTokenText(value, nameof(Alias));
    }

    [JsonPropertyName("dataspace")]
    public string Dataspace
    {
        get => dataspace;
        init => dataspace = ToriiAliasDirectMetadata.RequireExactTokenText(value, nameof(Dataspace));
    }

    [JsonPropertyName("domain")]
    public string? Domain
    {
        get => domain;
        init => domain = ToriiAliasDirectMetadata.RequireOptionalExactTokenText(value, nameof(Domain));
    }

    [JsonPropertyName("is_primary")]
    public bool IsPrimary { get; init; }
}

[JsonConverter(typeof(ToriiAccountAliasLookupResponseJsonConverter))]
public sealed record class ToriiAccountAliasLookupResponse
{
    private ToriiAccountAliasLookupItem[] items = Array.Empty<ToriiAccountAliasLookupItem>();
    private string accountId = string.Empty;
    private string? source;

    [JsonPropertyName("account_id")]
    public string AccountId
    {
        get => accountId;
        init => accountId = ToriiAliasDirectMetadata.RequireCanonicalAccountId(value, nameof(AccountId));
    }

    [JsonPropertyName("items")]
    public IReadOnlyList<ToriiAccountAliasLookupItem> Items
    {
        get => ToriiListSnapshots.CopyRequired(items);
        init => items = ToriiListSnapshots.CopyRequired(value);
    }

    [JsonPropertyName("total")]
    public long Total { get; init; }

    [JsonPropertyName("source")]
    public string? Source
    {
        get => source;
        init => source = ToriiAliasDirectMetadata.RequireOptionalExactTokenText(value, nameof(Source));
    }
}

[JsonConverter(typeof(ToriiAccountPermissionJsonConverter))]
public sealed record class ToriiAccountPermission
{
    private string name = string.Empty;
    private JsonNode? payload;

    [JsonPropertyName("name")]
    public string Name
    {
        get => name;
        init => name = ToriiAccountQueryDirectMetadata.RequireExactNonEmptyText(value, nameof(Name));
    }

    [JsonPropertyName("payload")]
    public JsonNode? Payload
    {
        get => ToriiJsonSnapshots.Copy(payload);
        init => payload = ToriiJsonSnapshots.Copy(value);
    }
}

internal static class ToriiAccountQueryDirectMetadata
{
    internal static string RequireCanonicalAccountId(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, paramName);
    }

    internal static string? RequireOptionalCanonicalAccountId(string? value, string paramName)
    {
        return value is null ? null : RequireCanonicalAccountId(value, paramName);
    }

    internal static string RequireExactNonEmptyText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, paramName);
    }

    internal static string? RequireOptionalExactNonEmptyText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireOptionalExactNonEmptyText(value, paramName);
    }

    internal static string RequireCanonicalQuantityText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(value, paramName);
    }

    internal static string RequireExactSizedHex(string? value, string paramName, int expectedBytes)
    {
        return ToriiExplorerDirectMetadata.RequireExactSizedHex(value, paramName, expectedBytes);
    }

    internal static long? RequireOptionalPositive(long? value, string paramName)
    {
        if (value is long integer && integer <= 0)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be positive.");
        }

        return value;
    }
}

internal static class ToriiAliasDirectMetadata
{
    internal static string RequireExactTokenText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireExactTokenText(value, paramName);
    }

    internal static string? RequireOptionalExactTokenText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireOptionalExactTokenText(value, paramName);
    }

    internal static string? RequireOptionalExactNonEmptyText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireOptionalExactNonEmptyText(value, paramName);
    }

    internal static string RequireCanonicalAccountId(string? value, string paramName)
    {
        var exact = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, paramName);
        if (exact.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Value must not contain whitespace.", paramName);
        }
        try
        {
            _ = global::Hyperledger.Iroha.Address.AccountAddress.Parse(exact);
            return exact;
        }
        catch (global::Hyperledger.Iroha.AccountAddressException exception)
        {
            throw new ArgumentException("Value must be a canonical I105 account id.", paramName, exception);
        }
    }

    internal static long RequirePositive(long value, string paramName)
    {
        if (value <= 0)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be positive.");
        }

        return value;
    }

    internal static long? RequireOptionalPositive(long? value, string paramName)
    {
        return value is null ? null : RequirePositive(value.Value, paramName);
    }

    internal static long? RequireOptionalNonNegative(long? value, string paramName)
    {
        if (value is long integer && integer < 0)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be non-negative.");
        }

        return value;
    }
}

internal static class ToriiAccountFaucetMetadata
{
    internal static string RequireCanonicalAccountId(string? value, string paramName)
    {
        return ToriiAccountFaucetPow.RequireExactAccountId(
            value,
            paramName,
            chainDiscriminant: null);
    }

    internal static string RequireExactTokenText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireExactTokenText(value, paramName);
    }

    internal static string RequireCanonicalQuantityText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(value, paramName);
    }

    internal static string RequireFaucetNonceHex(string? value, string paramName)
    {
        var exact = RequireExactTokenText(value, paramName);
        if (exact.Length > 64)
        {
            throw new ArgumentException(
                "Faucet PoW nonce must not exceed 32 bytes.",
                paramName);
        }
        if ((exact.Length & 1) != 0
            || exact.Any(static character =>
                character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new ArgumentException(
                "Faucet PoW nonce must be non-empty canonical lowercase hexadecimal.",
                paramName);
        }
        return exact;
    }

    internal static string RequireFaucetAlgorithm(string? value, string paramName)
    {
        var exact = RequireExactTokenText(value, paramName);
        if (!string.Equals(exact, ToriiAccountFaucetPow.Algorithm, StringComparison.Ordinal))
        {
            throw new ArgumentException($"Value must be {ToriiAccountFaucetPow.Algorithm}.", paramName);
        }

        return exact;
    }

    internal static ulong RequirePositive(ulong value, string paramName)
    {
        if (value == 0)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be positive.");
        }

        return value;
    }

    internal static string? RequireOptionalExactEvenLengthHex(string? value, string paramName)
    {
        if (value is null)
        {
            return null;
        }

        if (value.Length == 0)
        {
            throw new ArgumentException("Value must be a non-empty even-length hex string.", paramName);
        }

        var exact = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, paramName);
        if (exact.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Value must not contain whitespace.", paramName);
        }

        if (exact.Length % 2 != 0 || !exact.All(IsLowercaseHexCharacter))
        {
            throw new ArgumentException("Value must be an exact lowercase even-length hex string.", paramName);
        }

        return exact;
    }

    internal static void RequireCheckedScryptParameters(
        byte scryptLogN,
        uint scryptR,
        uint scryptP,
        string paramName)
    {
        try
        {
            _ = ToriiAccountFaucetPow.CheckedScryptParameters(scryptLogN, scryptR, scryptP);
        }
        catch (ArgumentOutOfRangeException exception)
        {
            var directParamName = exception.ParamName switch
            {
                "scryptR" => nameof(ToriiAccountFaucetPuzzle.ScryptR),
                "scryptP" => nameof(ToriiAccountFaucetPuzzle.ScryptP),
                _ => paramName,
            };
            throw new ArgumentOutOfRangeException(directParamName, exception.Message);
        }
    }

    private static bool IsLowercaseHexCharacter(char value)
    {
        return value is (>= '0' and <= '9') or (>= 'a' and <= 'f');
    }
}

public sealed record class ToriiContractStateQuery
{
    private string[]? paths;

    public string? Path { get; init; }

    public IReadOnlyList<string>? Paths
    {
        get => ToriiListSnapshots.Copy(paths);
        init => paths = ToriiListSnapshots.Copy(value);
    }

    public string? Prefix { get; init; }

    public bool? IncludeValue { get; init; }

    public ulong? Offset { get; init; }

    public ulong? Limit { get; init; }

    public string? Decode { get; init; }
}

[JsonConverter(typeof(ToriiExplorerAccountJsonConverter))]
public sealed record class ToriiExplorerAccount
{
    private string id = string.Empty;
    private string i105Address = string.Empty;
    private JsonNode? metadata = new JsonObject();

    [JsonPropertyName("id")]
    public string Id
    {
        get => id;
        init => id = ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, nameof(Id));
    }

    [JsonPropertyName("i105_address")]
    public string I105Address
    {
        get => i105Address;
        init => i105Address = ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, nameof(I105Address));
    }

    [JsonPropertyName("network_prefix")]
    public ushort NetworkPrefix { get; init; }

    [JsonPropertyName("metadata")]
    public JsonNode? Metadata
    {
        get => ToriiJsonSnapshots.Copy(metadata);
        init => metadata = ToriiJsonSnapshots.Copy(value);
    }

    [JsonPropertyName("owned_domains")]
    public uint OwnedDomains { get; init; }

    [JsonPropertyName("owned_assets")]
    public uint OwnedAssets { get; init; }

    [JsonPropertyName("owned_nfts")]
    public uint OwnedNfts { get; init; }
}

[JsonConverter(typeof(ToriiExplorerDomainJsonConverter))]
public sealed record class ToriiExplorerDomain
{
    private string id = string.Empty;
    private string? logo;
    private string ownedBy = string.Empty;
    private JsonNode? metadata = new JsonObject();

    [JsonPropertyName("id")]
    public string Id
    {
        get => id;
        init => id = ToriiExplorerDirectMetadata.RequireExactTokenText(value, nameof(Id));
    }

    [JsonPropertyName("logo")]
    public string? Logo
    {
        get => logo;
        init => logo = ToriiExplorerDirectMetadata.RequireOptionalExactTokenText(value, nameof(Logo));
    }

    [JsonPropertyName("metadata")]
    public JsonNode? Metadata
    {
        get => ToriiJsonSnapshots.Copy(metadata);
        init => metadata = ToriiJsonSnapshots.Copy(value);
    }

    [JsonPropertyName("owned_by")]
    public string OwnedBy
    {
        get => ownedBy;
        init => ownedBy = ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, nameof(OwnedBy));
    }

    [JsonPropertyName("accounts")]
    public uint Accounts { get; init; }

    [JsonPropertyName("assets")]
    public uint Assets { get; init; }

    [JsonPropertyName("nfts")]
    public uint Nfts { get; init; }
}

[JsonConverter(typeof(ToriiExplorerAssetDefinitionJsonConverter))]
public sealed record class ToriiExplorerAssetDefinition
{
    private string id = string.Empty;
    private string? owningDomain;
    private string mintable = string.Empty;
    private string? logo;
    private string ownedBy = string.Empty;
    private string totalQuantity = string.Empty;
    private string? lockedQuantity;
    private string? circulatingQuantity;
    private JsonNode? metadata = new JsonObject();

    [JsonPropertyName("id")]
    public string Id
    {
        get => id;
        init => id = ToriiExplorerDirectMetadata.RequireExactTokenText(value, nameof(Id));
    }

    [JsonPropertyName("owning_domain")]
    public string? OwningDomain
    {
        get => owningDomain;
        init => owningDomain = ToriiExplorerDirectMetadata.RequireOptionalExactTokenText(
            value,
            nameof(OwningDomain));
    }

    [JsonPropertyName("mintable")]
    public string Mintable
    {
        get => mintable;
        init => mintable = ToriiExplorerDirectMetadata.RequireExactTokenText(value, nameof(Mintable));
    }

    [JsonPropertyName("logo")]
    public string? Logo
    {
        get => logo;
        init => logo = ToriiExplorerDirectMetadata.RequireOptionalExactTokenText(value, nameof(Logo));
    }

    [JsonPropertyName("metadata")]
    public JsonNode? Metadata
    {
        get => ToriiJsonSnapshots.Copy(metadata);
        init => metadata = ToriiJsonSnapshots.Copy(value);
    }

    [JsonPropertyName("owned_by")]
    public string OwnedBy
    {
        get => ownedBy;
        init => ownedBy = ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, nameof(OwnedBy));
    }

    [JsonPropertyName("assets")]
    public uint Assets { get; init; }

    [JsonPropertyName("total_quantity")]
    public string TotalQuantity
    {
        get => totalQuantity;
        init => totalQuantity = ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(
            value,
            nameof(TotalQuantity));
    }

    [JsonPropertyName("locked_quantity")]
    public string? LockedQuantity
    {
        get => lockedQuantity;
        init => lockedQuantity = ToriiExplorerDirectMetadata.RequireOptionalCanonicalQuantityText(
            value,
            nameof(LockedQuantity));
    }

    [JsonPropertyName("circulating_quantity")]
    public string? CirculatingQuantity
    {
        get => circulatingQuantity;
        init => circulatingQuantity = ToriiExplorerDirectMetadata.RequireOptionalCanonicalQuantityText(
            value,
            nameof(CirculatingQuantity));
    }
}

[JsonConverter(typeof(ToriiExplorerEconometricsVelocityWindowJsonConverter))]
public sealed record class ToriiExplorerEconometricsVelocityWindow
{
    private string key = string.Empty;
    private string amount = string.Empty;

    [JsonPropertyName("key")]
    public string Key
    {
        get => key;
        init => key = ToriiExplorerDirectMetadata.RequireExactTokenText(value, nameof(Key));
    }

    [JsonPropertyName("start_ms")]
    public ulong StartMilliseconds { get; init; }

    [JsonPropertyName("end_ms")]
    public ulong EndMilliseconds { get; init; }

    [JsonPropertyName("transfers")]
    public ulong Transfers { get; init; }

    [JsonPropertyName("unique_senders")]
    public ulong UniqueSenders { get; init; }

    [JsonPropertyName("unique_receivers")]
    public ulong UniqueReceivers { get; init; }

    [JsonPropertyName("amount")]
    public string Amount
    {
        get => amount;
        init => amount = ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(value, nameof(Amount));
    }
}

[JsonConverter(typeof(ToriiExplorerEconometricsIssuanceWindowJsonConverter))]
public sealed record class ToriiExplorerEconometricsIssuanceWindow
{
    private string key = string.Empty;
    private string minted = string.Empty;
    private string burned = string.Empty;
    private string net = string.Empty;

    [JsonPropertyName("key")]
    public string Key
    {
        get => key;
        init => key = ToriiExplorerDirectMetadata.RequireExactTokenText(value, nameof(Key));
    }

    [JsonPropertyName("start_ms")]
    public ulong StartMilliseconds { get; init; }

    [JsonPropertyName("end_ms")]
    public ulong EndMilliseconds { get; init; }

    [JsonPropertyName("mint_count")]
    public ulong MintCount { get; init; }

    [JsonPropertyName("burn_count")]
    public ulong BurnCount { get; init; }

    [JsonPropertyName("minted")]
    public string Minted
    {
        get => minted;
        init => minted = ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(value, nameof(Minted));
    }

    [JsonPropertyName("burned")]
    public string Burned
    {
        get => burned;
        init => burned = ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(value, nameof(Burned));
    }

    [JsonPropertyName("net")]
    public string Net
    {
        get => net;
        init => net = ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(value, nameof(Net));
    }
}

[JsonConverter(typeof(ToriiExplorerEconometricsIssuanceSeriesPointJsonConverter))]
public sealed record class ToriiExplorerEconometricsIssuanceSeriesPoint
{
    private string minted = string.Empty;
    private string burned = string.Empty;
    private string net = string.Empty;

    [JsonPropertyName("bucket_start_ms")]
    public ulong BucketStartMilliseconds { get; init; }

    [JsonPropertyName("minted")]
    public string Minted
    {
        get => minted;
        init => minted = ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(value, nameof(Minted));
    }

    [JsonPropertyName("burned")]
    public string Burned
    {
        get => burned;
        init => burned = ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(value, nameof(Burned));
    }

    [JsonPropertyName("net")]
    public string Net
    {
        get => net;
        init => net = ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(value, nameof(Net));
    }
}

[JsonConverter(typeof(ToriiExplorerAssetDefinitionEconometricsJsonConverter))]
public sealed record class ToriiExplorerAssetDefinitionEconometrics
{
    private ToriiExplorerEconometricsVelocityWindow[] velocityWindows = Array.Empty<ToriiExplorerEconometricsVelocityWindow>();
    private ToriiExplorerEconometricsIssuanceWindow[] issuanceWindows = Array.Empty<ToriiExplorerEconometricsIssuanceWindow>();
    private ToriiExplorerEconometricsIssuanceSeriesPoint[] issuanceSeries = Array.Empty<ToriiExplorerEconometricsIssuanceSeriesPoint>();
    private string definitionId = string.Empty;

    [JsonPropertyName("definition_id")]
    public string DefinitionId
    {
        get => definitionId;
        init => definitionId = ToriiExplorerDirectMetadata.RequireExactTokenText(value, nameof(DefinitionId));
    }

    [JsonPropertyName("computed_at_ms")]
    public ulong ComputedAtMilliseconds { get; init; }

    [JsonPropertyName("velocity_windows")]
    public IReadOnlyList<ToriiExplorerEconometricsVelocityWindow> VelocityWindows
    {
        get => ToriiListSnapshots.CopyRequired(velocityWindows);
        init => velocityWindows = ToriiListSnapshots.CopyRequired(value);
    }

    [JsonPropertyName("issuance_windows")]
    public IReadOnlyList<ToriiExplorerEconometricsIssuanceWindow> IssuanceWindows
    {
        get => ToriiListSnapshots.CopyRequired(issuanceWindows);
        init => issuanceWindows = ToriiListSnapshots.CopyRequired(value);
    }

    [JsonPropertyName("issuance_series")]
    public IReadOnlyList<ToriiExplorerEconometricsIssuanceSeriesPoint> IssuanceSeries
    {
        get => ToriiListSnapshots.CopyRequired(issuanceSeries);
        init => issuanceSeries = ToriiListSnapshots.CopyRequired(value);
    }
}

[JsonConverter(typeof(ToriiExplorerEconometricsLorenzPointJsonConverter))]
public sealed record class ToriiExplorerEconometricsLorenzPoint
{
    private double population;
    private double share;

    [JsonPropertyName("population")]
    public double Population
    {
        get => population;
        init => population = ToriiExplorerDirectMetadata.RequireFiniteUnitIntervalDouble(value, nameof(Population));
    }

    [JsonPropertyName("share")]
    public double Share
    {
        get => share;
        init => share = ToriiExplorerDirectMetadata.RequireFiniteUnitIntervalDouble(value, nameof(Share));
    }
}

[JsonConverter(typeof(ToriiExplorerEconometricsDistributionSnapshotJsonConverter))]
public sealed record class ToriiExplorerEconometricsDistributionSnapshot
{
    private ToriiExplorerEconometricsLorenzPoint[] lorenz = Array.Empty<ToriiExplorerEconometricsLorenzPoint>();
    private double gini;
    private double hhi;
    private double theil;
    private double entropy;
    private double entropyNormalized;
    private double top1;
    private double top5;
    private double top10;
    private string? median;
    private string? p90;
    private string? p99;

    [JsonPropertyName("gini")]
    public double Gini
    {
        get => gini;
        init => gini = ToriiExplorerDirectMetadata.RequireFiniteUnitIntervalDouble(value, nameof(Gini));
    }

    [JsonPropertyName("hhi")]
    public double Hhi
    {
        get => hhi;
        init => hhi = ToriiExplorerDirectMetadata.RequireFiniteNonNegativeDouble(value, nameof(Hhi));
    }

    [JsonPropertyName("theil")]
    public double Theil
    {
        get => theil;
        init => theil = ToriiExplorerDirectMetadata.RequireFiniteNonNegativeDouble(value, nameof(Theil));
    }

    [JsonPropertyName("entropy")]
    public double Entropy
    {
        get => entropy;
        init => entropy = ToriiExplorerDirectMetadata.RequireFiniteNonNegativeDouble(value, nameof(Entropy));
    }

    [JsonPropertyName("entropy_normalized")]
    public double EntropyNormalized
    {
        get => entropyNormalized;
        init => entropyNormalized = ToriiExplorerDirectMetadata.RequireFiniteUnitIntervalDouble(
            value,
            nameof(EntropyNormalized));
    }

    [JsonPropertyName("nakamoto_33")]
    public ulong Nakamoto33 { get; init; }

    [JsonPropertyName("nakamoto_51")]
    public ulong Nakamoto51 { get; init; }

    [JsonPropertyName("nakamoto_67")]
    public ulong Nakamoto67 { get; init; }

    [JsonPropertyName("top1")]
    public double Top1
    {
        get => top1;
        init => top1 = ToriiExplorerDirectMetadata.RequireFiniteUnitIntervalDouble(value, nameof(Top1));
    }

    [JsonPropertyName("top5")]
    public double Top5
    {
        get => top5;
        init => top5 = ToriiExplorerDirectMetadata.RequireFiniteUnitIntervalDouble(value, nameof(Top5));
    }

    [JsonPropertyName("top10")]
    public double Top10
    {
        get => top10;
        init => top10 = ToriiExplorerDirectMetadata.RequireFiniteUnitIntervalDouble(value, nameof(Top10));
    }

    [JsonPropertyName("median")]
    public string? Median
    {
        get => median;
        init => median = ToriiExplorerDirectMetadata.RequireOptionalCanonicalQuantityText(
            value,
            nameof(Median));
    }

    [JsonPropertyName("p90")]
    public string? P90
    {
        get => p90;
        init => p90 = ToriiExplorerDirectMetadata.RequireOptionalCanonicalQuantityText(value, nameof(P90));
    }

    [JsonPropertyName("p99")]
    public string? P99
    {
        get => p99;
        init => p99 = ToriiExplorerDirectMetadata.RequireOptionalCanonicalQuantityText(value, nameof(P99));
    }

    [JsonPropertyName("lorenz")]
    public IReadOnlyList<ToriiExplorerEconometricsLorenzPoint> Lorenz
    {
        get => ToriiListSnapshots.CopyRequired(lorenz);
        init => lorenz = ToriiListSnapshots.CopyRequired(value);
    }
}

[JsonConverter(typeof(ToriiExplorerEconometricsTopHolderJsonConverter))]
public sealed record class ToriiExplorerEconometricsTopHolder
{
    private string accountId = string.Empty;
    private string balance = string.Empty;

    [JsonPropertyName("account_id")]
    public string AccountId
    {
        get => accountId;
        init => accountId = ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, nameof(AccountId));
    }

    [JsonPropertyName("balance")]
    public string Balance
    {
        get => balance;
        init => balance = ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(value, nameof(Balance));
    }
}

[JsonConverter(typeof(ToriiExplorerAssetDefinitionSnapshotJsonConverter))]
public sealed record class ToriiExplorerAssetDefinitionSnapshot
{
    private ToriiExplorerEconometricsTopHolder[] topHolders = Array.Empty<ToriiExplorerEconometricsTopHolder>();
    private string definitionId = string.Empty;
    private string totalSupply = string.Empty;
    private ToriiExplorerEconometricsDistributionSnapshot distribution = new();

    [JsonPropertyName("definition_id")]
    public string DefinitionId
    {
        get => definitionId;
        init => definitionId = ToriiExplorerDirectMetadata.RequireExactTokenText(value, nameof(DefinitionId));
    }

    [JsonPropertyName("computed_at_ms")]
    public ulong ComputedAtMilliseconds { get; init; }

    [JsonPropertyName("holders_total")]
    public ulong HoldersTotal { get; init; }

    [JsonPropertyName("total_supply")]
    public string TotalSupply
    {
        get => totalSupply;
        init => totalSupply = ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(
            value,
            nameof(TotalSupply));
    }

    [JsonPropertyName("top_holders")]
    public IReadOnlyList<ToriiExplorerEconometricsTopHolder> TopHolders
    {
        get => ToriiListSnapshots.CopyRequired(topHolders);
        init => topHolders = ToriiListSnapshots.CopyRequired(value);
    }

    [JsonPropertyName("distribution")]
    public ToriiExplorerEconometricsDistributionSnapshot Distribution
    {
        get => distribution;
        init => distribution = value ?? throw new ArgumentNullException(nameof(Distribution));
    }
}

[JsonConverter(typeof(ToriiExplorerAssetJsonConverter))]
public sealed record class ToriiExplorerAsset
{
    private string id = string.Empty;
    private string definitionId = string.Empty;
    private string accountId = string.Empty;
    private string value = string.Empty;

    [JsonPropertyName("id")]
    public string Id
    {
        get => id;
        init => id = ToriiExplorerDirectMetadata.RequireExactTokenText(value, nameof(Id));
    }

    [JsonPropertyName("definition_id")]
    public string DefinitionId
    {
        get => definitionId;
        init => definitionId = ToriiExplorerDirectMetadata.RequireExactTokenText(value, nameof(DefinitionId));
    }

    [JsonPropertyName("account_id")]
    public string AccountId
    {
        get => accountId;
        init => accountId = ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, nameof(AccountId));
    }

    [JsonPropertyName("value")]
    public string Value
    {
        get => value;
        init => this.value = ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(value, nameof(Value));
    }
}

[JsonConverter(typeof(ToriiExplorerNftJsonConverter))]
public sealed record class ToriiExplorerNft
{
    private string id = string.Empty;
    private string ownedBy = string.Empty;
    private JsonNode? metadata = new JsonObject();

    [JsonPropertyName("id")]
    public string Id
    {
        get => id;
        init => id = ToriiExplorerDirectMetadata.RequireExactTokenText(value, nameof(Id));
    }

    [JsonPropertyName("owned_by")]
    public string OwnedBy
    {
        get => ownedBy;
        init => ownedBy = ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, nameof(OwnedBy));
    }

    [JsonPropertyName("metadata")]
    public JsonNode? Metadata
    {
        get => ToriiJsonSnapshots.Copy(metadata);
        init => metadata = ToriiJsonSnapshots.Copy(value);
    }
}

[JsonConverter(typeof(ToriiExplorerRwaParentJsonConverter))]
public sealed record class ToriiExplorerRwaParent
{
    private string rwa = string.Empty;
    private string quantity = string.Empty;

    [JsonPropertyName("rwa")]
    public string Rwa
    {
        get => rwa;
        init => rwa = ToriiExplorerDirectMetadata.RequireExactTokenText(value, nameof(Rwa));
    }

    [JsonPropertyName("quantity")]
    public string Quantity
    {
        get => quantity;
        init => quantity = ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(value, nameof(Quantity));
    }
}

[JsonConverter(typeof(ToriiExplorerRwaJsonConverter))]
public sealed record class ToriiExplorerRwa
{
    private ToriiExplorerRwaParent[] parents = Array.Empty<ToriiExplorerRwaParent>();
    private string id = string.Empty;
    private string ownedBy = string.Empty;
    private string quantity = string.Empty;
    private string heldQuantity = string.Empty;
    private string primaryReference = string.Empty;
    private string? status;
    private JsonNode? metadata = new JsonObject();

    [JsonPropertyName("id")]
    public string Id
    {
        get => id;
        init => id = ToriiExplorerDirectMetadata.RequireExactTokenText(value, nameof(Id));
    }

    [JsonPropertyName("owned_by")]
    public string OwnedBy
    {
        get => ownedBy;
        init => ownedBy = ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, nameof(OwnedBy));
    }

    [JsonPropertyName("quantity")]
    public string Quantity
    {
        get => quantity;
        init => quantity = ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(value, nameof(Quantity));
    }

    [JsonPropertyName("held_quantity")]
    public string HeldQuantity
    {
        get => heldQuantity;
        init => heldQuantity = ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(
            value,
            nameof(HeldQuantity));
    }

    [JsonPropertyName("primary_reference")]
    public string PrimaryReference
    {
        get => primaryReference;
        init => primaryReference = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(
            value,
            nameof(PrimaryReference));
    }

    [JsonPropertyName("status")]
    public string? Status
    {
        get => status;
        init => status = ToriiExplorerDirectMetadata.RequireOptionalExactTokenText(value, nameof(Status));
    }

    [JsonPropertyName("is_frozen")]
    public bool IsFrozen { get; init; }

    [JsonPropertyName("metadata")]
    public JsonNode? Metadata
    {
        get => ToriiJsonSnapshots.Copy(metadata);
        init => metadata = ToriiJsonSnapshots.Copy(value);
    }

    [JsonPropertyName("parents")]
    public IReadOnlyList<ToriiExplorerRwaParent> Parents
    {
        get => ToriiListSnapshots.CopyRequired(parents);
        init => parents = ToriiListSnapshots.CopyRequired(value);
    }
}

[JsonConverter(typeof(ToriiExplorerBlockJsonConverter))]
public sealed record class ToriiExplorerBlock
{
    private string hash = string.Empty;
    private string createdAt = string.Empty;
    private string? previousBlockHash;
    private string? transactionsHash;

    [JsonPropertyName("hash")]
    public string Hash
    {
        get => hash;
        init => hash = ToriiExplorerDirectMetadata.RequireExactSizedHex(value, nameof(Hash), 32);
    }

    [JsonPropertyName("height")]
    public ulong Height { get; init; }

    [JsonPropertyName("created_at")]
    public string CreatedAt
    {
        get => createdAt;
        init => createdAt = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, nameof(CreatedAt));
    }

    [JsonPropertyName("prev_block_hash")]
    public string? PreviousBlockHash
    {
        get => previousBlockHash;
        init => previousBlockHash = ToriiExplorerDirectMetadata.RequireOptionalExactSizedHex(
            value,
            nameof(PreviousBlockHash),
            32);
    }

    [JsonPropertyName("transactions_hash")]
    public string? TransactionsHash
    {
        get => transactionsHash;
        init => transactionsHash = ToriiExplorerDirectMetadata.RequireOptionalExactSizedHex(
            value,
            nameof(TransactionsHash),
            32);
    }

    [JsonPropertyName("transactions_rejected")]
    public uint TransactionsRejected { get; init; }

    [JsonPropertyName("transactions_total")]
    public uint TransactionsTotal { get; init; }
}

[JsonConverter(typeof(ToriiExplorerTransactionJsonConverter))]
public sealed record class ToriiExplorerTransaction
{
    private string authority = string.Empty;
    private string hash = string.Empty;
    private string createdAt = string.Empty;
    private string executable = string.Empty;
    private string status = string.Empty;

    [JsonPropertyName("authority")]
    public string Authority
    {
        get => authority;
        init => authority = ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, nameof(Authority));
    }

    [JsonPropertyName("hash")]
    public string Hash
    {
        get => hash;
        init => hash = ToriiExplorerDirectMetadata.RequireExactSizedHex(value, nameof(Hash), 32);
    }

    [JsonPropertyName("block")]
    public ulong Block { get; init; }

    [JsonPropertyName("created_at")]
    public string CreatedAt
    {
        get => createdAt;
        init => createdAt = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, nameof(CreatedAt));
    }

    [JsonPropertyName("executable")]
    public string Executable
    {
        get => executable;
        init => executable = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, nameof(Executable));
    }

    [JsonPropertyName("status")]
    public string Status
    {
        get => status;
        init => status = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, nameof(Status));
    }
}

[JsonConverter(typeof(ToriiExplorerDurationJsonConverter))]
public sealed record class ToriiExplorerDuration
{
    [JsonPropertyName("ms")]
    public ulong Milliseconds { get; init; }
}

[JsonConverter(typeof(ToriiExplorerTransactionRejectionJsonConverter))]
public sealed record class ToriiExplorerTransactionRejection
{
    private string reason = string.Empty;
    private string message = string.Empty;

    /// <summary>Canonical padded base64 of one native TransactionRejectionReason frame.</summary>
    [JsonPropertyName("reason")]
    public string Reason
    {
        get => reason;
        init => reason = ToriiExplorerDirectMetadata.RequireCanonicalBase64(value, nameof(Reason));
    }

    [JsonPropertyName("message")]
    public string Message
    {
        get => message;
        init => message = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, nameof(Message));
    }
}

[JsonConverter(typeof(ToriiExplorerTransactionDetailJsonConverter))]
public sealed record class ToriiExplorerTransactionDetail
{
    private string authority = string.Empty;
    private string hash = string.Empty;
    private string createdAt = string.Empty;
    private string executable = string.Empty;
    private string status = string.Empty;
    private JsonNode? metadata;
    private string signature = string.Empty;

    [JsonPropertyName("authority")]
    public string Authority
    {
        get => authority;
        init => authority = ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, nameof(Authority));
    }

    [JsonPropertyName("hash")]
    public string Hash
    {
        get => hash;
        init => hash = ToriiExplorerDirectMetadata.RequireExactSizedHex(value, nameof(Hash), 32);
    }

    [JsonPropertyName("block")]
    public ulong Block { get; init; }

    [JsonPropertyName("created_at")]
    public string CreatedAt
    {
        get => createdAt;
        init => createdAt = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, nameof(CreatedAt));
    }

    [JsonPropertyName("executable")]
    public string Executable
    {
        get => executable;
        init => executable = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, nameof(Executable));
    }

    [JsonPropertyName("status")]
    public string Status
    {
        get => status;
        init => status = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, nameof(Status));
    }

    [JsonPropertyName("rejection_reason")]
    public ToriiExplorerTransactionRejection? RejectionReason { get; init; }

    [JsonPropertyName("metadata")]
    public JsonNode? Metadata
    {
        get => ToriiJsonSnapshots.Copy(metadata);
        init => metadata = ToriiJsonSnapshots.Copy(value);
    }

    [JsonPropertyName("nonce")]
    public ulong? Nonce { get; init; }

    [JsonPropertyName("signature")]
    public string Signature
    {
        get => signature;
        init => signature = ToriiExplorerDirectMetadata.RequireExactEvenLengthHex(value, nameof(Signature));
    }

    [JsonPropertyName("time_to_live")]
    public ToriiExplorerDuration? TimeToLive { get; init; }
}

[JsonConverter(typeof(ToriiExplorerInstructionBoxJsonConverter))]
public sealed record class ToriiExplorerInstructionBox
{
    private string wireId = string.Empty;
    private string framedSha256 = string.Empty;
    private string instruction = string.Empty;

    [JsonPropertyName("wire_id")]
    public string WireId
    {
        get => wireId;
        init => wireId = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, nameof(WireId));
    }

    /// <summary>Lowercase SHA-256 of the exact decoded InstructionBox frame.</summary>
    [JsonPropertyName("framed_sha256")]
    public string FramedSha256
    {
        get => framedSha256;
        init => framedSha256 = ToriiExplorerDirectMetadata.RequireExactSizedHex(value, nameof(FramedSha256), 32);
    }

    /// <summary>Canonical padded base64 of one native Norito InstructionBox frame.</summary>
    [JsonPropertyName("instruction")]
    public string Instruction
    {
        get => instruction;
        init => instruction = ToriiExplorerDirectMetadata.RequireCanonicalBase64(value, nameof(Instruction));
    }
}

[JsonConverter(typeof(ToriiExplorerInstructionJsonConverter))]
public sealed record class ToriiExplorerInstruction
{
    private string authority = string.Empty;
    private string createdAt = string.Empty;
    private string kind = string.Empty;
    private ToriiExplorerInstructionBox instructionBox = new();
    private string transactionHash = string.Empty;
    private string transactionStatus = string.Empty;

    [JsonPropertyName("authority")]
    public string Authority
    {
        get => authority;
        init => authority = ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, nameof(Authority));
    }

    [JsonPropertyName("created_at")]
    public string CreatedAt
    {
        get => createdAt;
        init => createdAt = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, nameof(CreatedAt));
    }

    [JsonPropertyName("kind")]
    public string Kind
    {
        get => kind;
        init => kind = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, nameof(Kind));
    }

    [JsonPropertyName("box")]
    public ToriiExplorerInstructionBox InstructionBox
    {
        get => instructionBox;
        init => instructionBox = value ?? throw new ArgumentNullException(
            nameof(InstructionBox),
            "Instruction box must not be null.");
    }

    [JsonPropertyName("transaction_hash")]
    public string TransactionHash
    {
        get => transactionHash;
        init => transactionHash = ToriiExplorerDirectMetadata.RequireExactSizedHex(
            value,
            nameof(TransactionHash),
            32);
    }

    [JsonPropertyName("transaction_status")]
    public string TransactionStatus
    {
        get => transactionStatus;
        init => transactionStatus = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(
            value,
            nameof(TransactionStatus));
    }

    [JsonPropertyName("block")]
    public ulong Block { get; init; }

    [JsonPropertyName("index")]
    public uint Index { get; init; }
}

internal static class ToriiExplorerDirectMetadata
{

    internal static string RequireCanonicalBase64(string? value, string paramName)
    {
        if (string.IsNullOrEmpty(value) || value.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Value must be non-empty canonical base64 text without whitespace.", paramName);
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(value);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("Value must be canonical base64 text.", paramName, exception);
        }

        if (bytes.Length == 0 || Convert.ToBase64String(bytes) != value)
        {
            throw new ArgumentException("Value must be non-empty canonical base64 text.", paramName);
        }

        return value;
    }

    internal static ulong RequirePositive(ulong value, string paramName)
    {
        if (value == 0)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be positive.");
        }

        return value;
    }

    internal static int RequireNonNegative(int value, string paramName)
    {
        if (value < 0)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be non-negative.");
        }

        return value;
    }

    internal static int RequirePositive(int value, string paramName)
    {
        if (value <= 0)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be positive.");
        }

        return value;
    }

    internal static string RequireCanonicalAccountId(string? value, string paramName)
    {
        var exact = RequireExactNonEmptyText(value, paramName);
        if (exact.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Value must not contain whitespace.", paramName);
        }

        try
        {
            _ = global::Hyperledger.Iroha.Address.AccountAddress.Parse(exact);
            return exact;
        }
        catch (global::Hyperledger.Iroha.AccountAddressException exception)
        {
            throw new ArgumentException("Value must be a canonical I105 account id.", paramName, exception);
        }
    }

    internal static string RequireExactNonEmptyText(string? value, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value must be a non-empty string.", paramName);
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new ArgumentException("Value must not contain surrounding whitespace.", paramName);
        }

        if (value.Any(char.IsControl))
        {
            throw new ArgumentException("Value must not contain control characters.", paramName);
        }

        return value;
    }

    internal static string? RequireOptionalExactNonEmptyText(string? value, string paramName)
    {
        return value is null ? null : RequireExactNonEmptyText(value, paramName);
    }

    internal static string RequireExactTokenText(string? value, string paramName)
    {
        var exact = RequireExactNonEmptyText(value, paramName);
        if (exact.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Value must not contain whitespace.", paramName);
        }

        return exact;
    }

    internal static string? RequireOptionalExactTokenText(string? value, string paramName)
    {
        return value is null ? null : RequireExactTokenText(value, paramName);
    }

    internal static string RequireCanonicalQuantityText(string? value, string paramName)
    {
        var exact = RequireExactNonEmptyText(value, paramName);
        try
        {
            return Hyperledger.Iroha.Numeric.NumericV1.QuantityValue.ParseCanonical(exact).ToString();
        }
        catch (Hyperledger.Iroha.Numeric.NumericV1.NumericException exception)
        {
            throw new ArgumentException(
                "Value must be a canonical non-negative numeric Kotodama V1 Quantity string.",
                paramName,
                exception);
        }
    }

    internal static string? RequireOptionalCanonicalQuantityText(string? value, string paramName)
    {
        return value is null ? null : RequireCanonicalQuantityText(value, paramName);
    }

    internal static double RequireFiniteNonNegativeDouble(double value, string paramName)
    {
        if (!double.IsFinite(value) || value < 0)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be a finite non-negative number.");
        }

        return value;
    }

    internal static double RequireFiniteUnitIntervalDouble(double value, string paramName)
    {
        if (!double.IsFinite(value) || value < 0 || value > 1)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be a finite number from 0 to 1.");
        }

        return value;
    }

    internal static string? RequireOptionalExactSizedHex(string? value, string paramName, int expectedBytes)
    {
        return value is null ? null : RequireExactSizedHex(value, paramName, expectedBytes);
    }

    internal static string RequireExactSizedHex(string? value, string paramName, int expectedBytes)
    {
        var exact = RequireExactNonEmptyText(value, paramName);
        if (exact.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Value must not contain whitespace.", paramName);
        }

        if (exact.Length != expectedBytes * 2 || !exact.All(IsLowercaseHexCharacter))
        {
            throw new ArgumentException(
                $"Value must be an exact lowercase {expectedBytes}-byte hex string.",
                paramName);
        }

        return exact;
    }

    internal static string RequireExactHex(string? value, string paramName)
    {
        var exact = RequireExactNonEmptyText(value, paramName);
        if (exact.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Value must not contain whitespace.", paramName);
        }

        var body = exact.StartsWith("0x", StringComparison.Ordinal) ? exact[2..] : exact;
        if (body.Length == 0 || body.Length % 2 != 0 || !body.All(IsHexCharacter))
        {
            throw new ArgumentException("Value must be an exact hex string.", paramName);
        }

        return exact;
    }

    internal static string RequireExactEvenLengthHex(string? value, string paramName)
    {
        var exact = RequireExactNonEmptyText(value, paramName);
        if (exact.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Value must not contain whitespace.", paramName);
        }

        if (exact.Length % 2 != 0 || !exact.All(IsLowercaseHexCharacter))
        {
            throw new ArgumentException("Value must be an exact lowercase even-length hex string.", paramName);
        }

        return exact;
    }

    private static bool IsHexCharacter(char value)
    {
        return value is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F');
    }

    private static bool IsLowercaseHexCharacter(char value)
    {
        return value is (>= '0' and <= '9') or (>= 'a' and <= 'f');
    }
}

[JsonConverter(typeof(ToriiExplorerHealthSnapshotJsonConverter))]
public sealed record class ToriiExplorerHealthSnapshot
{
    private string? headCreatedAt;
    private string sampledAt = string.Empty;

    [JsonPropertyName("head_height")]
    public ulong HeadHeight { get; init; }

    [JsonPropertyName("head_created_at")]
    public string? HeadCreatedAt
    {
        get => headCreatedAt;
        init => headCreatedAt = ToriiExplorerDirectMetadata.RequireOptionalExactNonEmptyText(
            value,
            nameof(HeadCreatedAt));
    }

    [JsonPropertyName("sampled_at")]
    public string SampledAt
    {
        get => sampledAt;
        init => sampledAt = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, nameof(SampledAt));
    }
}

[JsonConverter(typeof(ToriiExplorerMetricsSnapshotJsonConverter))]
public sealed record class ToriiExplorerMetricsSnapshot
{
    private string? blockCreatedAt;

    [JsonPropertyName("peers")]
    public ulong Peers { get; init; }

    [JsonPropertyName("domains")]
    public ulong Domains { get; init; }

    [JsonPropertyName("accounts")]
    public ulong Accounts { get; init; }

    [JsonPropertyName("assets")]
    public ulong Assets { get; init; }

    [JsonPropertyName("transactions_accepted")]
    public ulong TransactionsAccepted { get; init; }

    [JsonPropertyName("transactions_rejected")]
    public ulong TransactionsRejected { get; init; }

    [JsonPropertyName("block")]
    public ulong Block { get; init; }

    [JsonPropertyName("block_created_at")]
    public string? BlockCreatedAt
    {
        get => blockCreatedAt;
        init => blockCreatedAt = ToriiExplorerDirectMetadata.RequireOptionalExactNonEmptyText(
            value,
            nameof(BlockCreatedAt));
    }

    [JsonPropertyName("finalized_block")]
    public ulong FinalizedBlock { get; init; }

    [JsonPropertyName("avg_commit_time")]
    public ToriiExplorerDuration? AverageCommitTime { get; init; }

    [JsonPropertyName("avg_block_time")]
    public ToriiExplorerDuration? AverageBlockTime { get; init; }
}

[JsonConverter(typeof(ToriiSoraFsFileEntryJsonConverter))]
public sealed record class ToriiSoraFsFileEntry
{
    private string[] path = Array.Empty<string>();
    private long offset;
    private long size;
    private long firstChunk;
    private long chunkCount;

    [JsonPropertyName("path")]
    public IReadOnlyList<string> Path
    {
        get => ToriiListSnapshots.CopyRequired(path);
        init => path = ToriiSoraFsDirectMetadata.CopyRequiredPathComponents(value, nameof(Path));
    }

    [JsonPropertyName("offset")]
    public long Offset
    {
        get => offset;
        init => offset = ToriiSoraFsDirectMetadata.RequireNonNegative(value, nameof(Offset));
    }

    [JsonPropertyName("size")]
    public long Size
    {
        get => size;
        init => size = ToriiSoraFsDirectMetadata.RequireNonNegative(value, nameof(Size));
    }

    [JsonPropertyName("first_chunk")]
    public long FirstChunk
    {
        get => firstChunk;
        init => firstChunk = ToriiSoraFsDirectMetadata.RequireNonNegative(value, nameof(FirstChunk));
    }

    [JsonPropertyName("chunk_count")]
    public long ChunkCount
    {
        get => chunkCount;
        init => chunkCount = ToriiSoraFsDirectMetadata.RequireNonNegative(value, nameof(ChunkCount));
    }
}

[JsonConverter(typeof(ToriiSoraFsCidLookupResponseJsonConverter))]
public sealed record class ToriiSoraFsCidLookupResponse
{
    private string contentCid = string.Empty;
    private string manifestDigestHex = string.Empty;
    private string manifestIdHex = string.Empty;
    private string? indexDocument;
    private ToriiSoraFsFileEntry[] files = Array.Empty<ToriiSoraFsFileEntry>();

    [JsonPropertyName("content_cid")]
    public string ContentCid
    {
        get => contentCid;
        init => contentCid = ToriiSoraFsDirectMetadata.RequireContentCid(value, nameof(ContentCid));
    }

    [JsonPropertyName("manifest_digest_hex")]
    public string ManifestDigestHex
    {
        get => manifestDigestHex;
        init => manifestDigestHex = ToriiSoraFsDirectMetadata.RequireExactSizedHex(
            value,
            nameof(ManifestDigestHex),
            32);
    }

    [JsonPropertyName("manifest_id_hex")]
    public string ManifestIdHex
    {
        get => manifestIdHex;
        init => manifestIdHex = ToriiSoraFsDirectMetadata.RequireExactSizedHex(
            value,
            nameof(ManifestIdHex),
            32);
    }

    [JsonPropertyName("index_document")]
    public string? IndexDocument
    {
        get => indexDocument;
        init => indexDocument = ToriiSoraFsDirectMetadata.RequireOptionalExactNonEmptyText(
            value,
            nameof(IndexDocument));
    }

    [JsonPropertyName("files")]
    public IReadOnlyList<ToriiSoraFsFileEntry> Files
    {
        get => ToriiListSnapshots.CopyRequired(files);
        init => files = ToriiSoraFsDirectMetadata.CopyRequiredFileEntries(value, nameof(Files));
    }
}

[JsonConverter(typeof(ToriiSoraFsChunkerHandleJsonConverter))]
public sealed record class ToriiSoraFsChunkerHandle
{
    [JsonPropertyName("profile_id")]
    public uint? ProfileId { get; init; }

    [JsonPropertyName("namespace")]
    public string? Namespace { get; init; }

    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("semver")]
    public string? Semver { get; init; }

    [JsonPropertyName("multihash_code")]
    public uint? MultihashCode { get; init; }
}

[JsonConverter(typeof(ToriiSoraFsStorageClassJsonConverter))]
public sealed record class ToriiSoraFsStorageClass
{
    [JsonPropertyName("type")]
    public string? Type { get; init; }

    public static ToriiSoraFsStorageClass From(string type) => new() { Type = type };
}

[JsonConverter(typeof(ToriiSoraFsPinPolicyJsonConverter))]
public sealed record class ToriiSoraFsPinPolicy
{
    [JsonPropertyName("min_replicas")]
    public uint? MinReplicas { get; init; }

    [JsonPropertyName("storage_class")]
    public ToriiSoraFsStorageClass? StorageClass { get; init; }

    [JsonPropertyName("retention_epoch")]
    public ulong? RetentionEpoch { get; init; }
}

public sealed record class ToriiSoraFsPinRegisterResponse
{
    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;

    [JsonPropertyName("tx_hash_hex")]
    public string TxHashHex { get; init; } = string.Empty;

    [JsonPropertyName("manifest_digest_hex")]
    public string ManifestDigestHex { get; init; } = string.Empty;
}

internal static class ToriiSoraFsDirectMetadata
{
    internal static long RequireNonNegative(long value, string paramName)
    {
        if (value < 0)
        {
            throw new ArgumentOutOfRangeException(paramName, value, "Value must be non-negative.");
        }

        return value;
    }

    internal static string RequireContentCid(string? value, string paramName)
    {
        var text = RequireExactNonEmptyText(value, paramName);
        if (text.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Value must not contain whitespace.", paramName);
        }

        if (text[0] != 'b' || text.Length == 1)
        {
            throw new ArgumentException("Value must be lowercase multibase base32 CID text.", paramName);
        }

        for (var index = 1; index < text.Length; index++)
        {
            var character = text[index];
            if (character is not (>= 'a' and <= 'z') and not (>= '2' and <= '7'))
            {
                throw new ArgumentException("Value must be lowercase multibase base32 CID text.", paramName);
            }
        }

        return text;
    }

    internal static string RequireExactNonEmptyText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, paramName);
    }

    internal static string? RequireOptionalExactNonEmptyText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireOptionalExactNonEmptyText(value, paramName);
    }

    internal static string RequireExactTokenText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireExactTokenText(value, paramName);
    }

    internal static ulong RequireRequiredUInt64(ulong? value, string paramName)
    {
        return value ?? throw new ArgumentNullException(paramName, "Value must not be null.");
    }

    internal static string? RequireOptionalExactTokenText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireOptionalExactTokenText(value, paramName);
    }

    internal static string RequireExactSizedHex(string? value, string paramName, int expectedBytes)
    {
        return ToriiExplorerDirectMetadata.RequireExactSizedHex(value, paramName, expectedBytes);
    }

    internal static string? RequireOptionalExactSizedHex(string? value, string paramName, int expectedBytes)
    {
        return ToriiExplorerDirectMetadata.RequireOptionalExactSizedHex(value, paramName, expectedBytes);
    }

    internal static string RequireCanonicalAccountId(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, paramName);
    }

    internal static string? RequireOptionalCanonicalAccountId(string? value, string paramName)
    {
        return value is null ? null : ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, paramName);
    }

    internal static string[] CopyRequiredPathComponents(IReadOnlyList<string>? values, string paramName)
    {
        if (values is null)
        {
            throw new ArgumentNullException(paramName, "Value must not be null.");
        }
        if (values.Count == 0)
        {
            throw new ArgumentException("Value must not be empty.", paramName);
        }

        var copy = new string[values.Count];
        for (var index = 0; index < values.Count; index++)
        {
            var value = values[index];
            if (value is null)
            {
                throw new ArgumentException("List elements must not be null.", $"{paramName}[{index}]");
            }

            copy[index] = RequirePathComponent(value, $"{paramName}[{index}]");
        }

        return copy;
    }

    internal static ToriiSoraFsFileEntry[] CopyRequiredFileEntries(
        IReadOnlyList<ToriiSoraFsFileEntry>? values,
        string paramName)
    {
        if (values is null)
        {
            return Array.Empty<ToriiSoraFsFileEntry>();
        }

        var copy = new ToriiSoraFsFileEntry[values.Count];
        for (var index = 0; index < values.Count; index++)
        {
            var value = values[index];
            if (value is null)
            {
                throw new ArgumentException("List elements must not be null.", $"{paramName}[{index}]");
            }

            copy[index] = RequireFileEntry(value, $"{paramName}[{index}]");
        }

        return copy;
    }


    private static string RequirePathComponent(string value, string paramName)
    {
        var text = RequireExactNonEmptyText(value, paramName);
        if (text == "." || text == ".." || text.Contains('/', StringComparison.Ordinal))
        {
            throw new ArgumentException("Value must be a relative path component.", paramName);
        }

        return text;
    }

    private static ToriiSoraFsFileEntry RequireFileEntry(ToriiSoraFsFileEntry value, string paramName)
    {
        var path = value.Path;
        if (path.Count == 0)
        {
            throw new ArgumentException("Value must not be empty.", $"{paramName}.{nameof(ToriiSoraFsFileEntry.Path)}");
        }

        for (var index = 0; index < path.Count; index++)
        {
            RequirePathComponent(path[index], $"{paramName}.{nameof(ToriiSoraFsFileEntry.Path)}[{index}]");
        }

        RequireNonNegative(value.Offset, $"{paramName}.{nameof(ToriiSoraFsFileEntry.Offset)}");
        RequireNonNegative(value.Size, $"{paramName}.{nameof(ToriiSoraFsFileEntry.Size)}");
        RequireNonNegative(value.FirstChunk, $"{paramName}.{nameof(ToriiSoraFsFileEntry.FirstChunk)}");
        RequireNonNegative(value.ChunkCount, $"{paramName}.{nameof(ToriiSoraFsFileEntry.ChunkCount)}");
        return value;
    }

    private static string RequireCanonicalBase64(string? value, string paramName)
    {
        var text = RequireExactTokenText(value, paramName);
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(text);
        }
        catch (FormatException error)
        {
            throw new ArgumentException("Value must be base64 encoded.", paramName, error);
        }

        if (bytes.Length == 0)
        {
            throw new ArgumentException("Value must be a non-empty base64 payload.", paramName);
        }

        if (!string.Equals(Convert.ToBase64String(bytes), text, StringComparison.Ordinal))
        {
            throw new ArgumentException("Value must be canonical base64 text.", paramName);
        }

        return text;
    }
}

public sealed record class ToriiUaidPortfolioQuery
{
    public string? AssetId { get; init; }
}

public enum ToriiUaidManifestStatus
{
    Active = 1,
    Pending = 2,
    Expired = 3,
    Revoked = 4,
}

[JsonConverter(typeof(ToriiUaidPortfolioTotalsJsonConverter))]
public sealed record class ToriiUaidPortfolioTotals
{
    private ulong accounts;
    private ulong positions;

    [JsonPropertyName("accounts")]
    public ulong Accounts
    {
        get => accounts;
        init => accounts = value;
    }

    [JsonPropertyName("positions")]
    public ulong Positions
    {
        get => positions;
        init => positions = value;
    }
}

[JsonConverter(typeof(ToriiUaidPortfolioAssetJsonConverter))]
public sealed record class ToriiUaidPortfolioAsset
{
    private string assetId = string.Empty;
    private string assetDefinitionId = string.Empty;
    private string quantity = string.Empty;

    [JsonPropertyName("asset_id")]
    public string AssetId
    {
        get => assetId;
        init => assetId = ToriiUaidDirectMetadata.RequireCanonicalAssetId(value, nameof(AssetId)).Literal;
    }

    [JsonPropertyName("asset_definition_id")]
    public string AssetDefinitionId
    {
        get => assetDefinitionId;
        init => assetDefinitionId = ToriiUaidDirectMetadata.RequireCanonicalAssetDefinitionId(
            value,
            nameof(AssetDefinitionId));
    }

    [JsonPropertyName("quantity")]
    public string Quantity
    {
        get => quantity;
        init => quantity = ToriiUaidDirectMetadata.RequireCanonicalQuantityText(
            value,
            nameof(Quantity));
    }
}

[JsonConverter(typeof(ToriiUaidPortfolioAccountJsonConverter))]
public sealed record class ToriiUaidPortfolioAccount
{
    private string accountId = string.Empty;
    private string? label;
    private ToriiUaidPortfolioAsset[] assets = Array.Empty<ToriiUaidPortfolioAsset>();

    [JsonPropertyName("account_id")]
    public string AccountId
    {
        get => accountId;
        init => accountId = ToriiUaidDirectMetadata.RequireCanonicalAccountId(value, nameof(AccountId));
    }

    [JsonPropertyName("label")]
    public string? Label
    {
        get => label;
        init => label = value;
    }

    [JsonPropertyName("assets")]
    public IReadOnlyList<ToriiUaidPortfolioAsset> Assets
    {
        get => ToriiListSnapshots.CopyRequired(assets);
        init => assets = ToriiUaidDirectMetadata.CopyRequiredPortfolioAssets(value, nameof(Assets));
    }
}

[JsonConverter(typeof(ToriiUaidPortfolioDataspaceJsonConverter))]
public sealed record class ToriiUaidPortfolioDataspace
{
    private ulong dataspaceId;
    private string? dataspaceAlias;
    private ToriiUaidPortfolioAccount[] accounts = Array.Empty<ToriiUaidPortfolioAccount>();

    [JsonPropertyName("dataspace_id")]
    public ulong DataspaceId
    {
        get => dataspaceId;
        init => dataspaceId = value;
    }

    [JsonPropertyName("dataspace_alias")]
    public string? DataspaceAlias
    {
        get => dataspaceAlias;
        init => dataspaceAlias = value;
    }

    [JsonPropertyName("accounts")]
    public IReadOnlyList<ToriiUaidPortfolioAccount> Accounts
    {
        get => ToriiListSnapshots.CopyRequired(accounts);
        init => accounts = ToriiUaidDirectMetadata.CopyRequiredPortfolioAccounts(value, nameof(Accounts));
    }
}

[JsonConverter(typeof(ToriiUaidPortfolioResponseJsonConverter))]
public sealed record class ToriiUaidPortfolioResponse
{
    private string uaid = string.Empty;
    private ToriiUaidPortfolioTotals totals = new();
    private ToriiUaidPortfolioDataspace[] dataspaces = Array.Empty<ToriiUaidPortfolioDataspace>();

    [JsonPropertyName("uaid")]
    public string Uaid
    {
        get => uaid;
        init => uaid = ToriiUaidDirectMetadata.RequireCanonicalUaidLiteral(value, nameof(Uaid));
    }

    [JsonPropertyName("totals")]
    public ToriiUaidPortfolioTotals Totals
    {
        get => totals;
        init => totals = ToriiUaidDirectMetadata.RequirePortfolioTotals(value, nameof(Totals));
    }

    [JsonPropertyName("dataspaces")]
    public IReadOnlyList<ToriiUaidPortfolioDataspace> Dataspaces
    {
        get => ToriiListSnapshots.CopyRequired(dataspaces);
        init => dataspaces = ToriiUaidDirectMetadata.CopyRequiredPortfolioDataspaces(value, nameof(Dataspaces));
    }
}

[JsonConverter(typeof(ToriiUaidBindingsDataspaceJsonConverter))]
public sealed record class ToriiUaidBindingsDataspace
{
    private ulong dataspaceId;
    private string? dataspaceAlias;
    private string[] accounts = Array.Empty<string>();

    [JsonPropertyName("dataspace_id")]
    public ulong DataspaceId
    {
        get => dataspaceId;
        init => dataspaceId = value;
    }

    [JsonPropertyName("dataspace_alias")]
    public string? DataspaceAlias
    {
        get => dataspaceAlias;
        init => dataspaceAlias = value;
    }

    [JsonPropertyName("accounts")]
    public IReadOnlyList<string> Accounts
    {
        get => ToriiListSnapshots.CopyRequired(accounts);
        init => accounts = ToriiUaidDirectMetadata.CopyRequiredCanonicalAccountIdList(value, nameof(Accounts));
    }
}

[JsonConverter(typeof(ToriiUaidBindingsResponseJsonConverter))]
public sealed record class ToriiUaidBindingsResponse
{
    private string uaid = string.Empty;
    private ToriiUaidBindingsDataspace[] dataspaces = Array.Empty<ToriiUaidBindingsDataspace>();

    [JsonPropertyName("uaid")]
    public string Uaid
    {
        get => uaid;
        init => uaid = ToriiUaidDirectMetadata.RequireCanonicalUaidLiteral(value, nameof(Uaid));
    }

    [JsonPropertyName("dataspaces")]
    public IReadOnlyList<ToriiUaidBindingsDataspace> Dataspaces
    {
        get => ToriiListSnapshots.CopyRequired(dataspaces);
        init => dataspaces = ToriiUaidDirectMetadata.CopyRequiredBindingsDataspaces(value, nameof(Dataspaces));
    }
}

[JsonConverter(typeof(ToriiUaidManifestRevocationJsonConverter))]
public sealed record class ToriiUaidManifestRevocation
{
    private ulong epoch;
    private string? reason;

    [JsonPropertyName("epoch")]
    public ulong Epoch
    {
        get => epoch;
        init => epoch = value;
    }

    [JsonPropertyName("reason")]
    public string? Reason
    {
        get => reason;
        init => reason = value;
    }
}

[JsonConverter(typeof(ToriiUaidManifestLifecycleJsonConverter))]
public sealed record class ToriiUaidManifestLifecycle
{
    private ulong? activatedEpoch;
    private ulong? expiredEpoch;
    private ToriiUaidManifestRevocation? revocation;

    [JsonPropertyName("activated_epoch")]
    public ulong? ActivatedEpoch
    {
        get => activatedEpoch;
        init => activatedEpoch = value;
    }

    [JsonPropertyName("expired_epoch")]
    public ulong? ExpiredEpoch
    {
        get => expiredEpoch;
        init => expiredEpoch = value;
    }

    [JsonPropertyName("revocation")]
    public ToriiUaidManifestRevocation? Revocation
    {
        get => revocation;
        init => revocation = ToriiUaidDirectMetadata.RequireOptionalManifestRevocation(
            value,
            nameof(Revocation));
    }
}

[JsonConverter(typeof(ToriiUaidManifestRecordJsonConverter))]
public sealed record class ToriiUaidManifestRecord
{
    private ulong dataspaceId;
    private string? dataspaceAlias;
    private string manifestHash = string.Empty;
    private ToriiUaidManifestStatus status;
    private ToriiUaidManifestLifecycle lifecycle = new();
    private string[] accounts = Array.Empty<string>();
    private JsonNode? manifest;

    [JsonPropertyName("dataspace_id")]
    public ulong DataspaceId
    {
        get => dataspaceId;
        init => dataspaceId = value;
    }

    [JsonPropertyName("dataspace_alias")]
    public string? DataspaceAlias
    {
        get => dataspaceAlias;
        init => dataspaceAlias = value;
    }

    [JsonPropertyName("manifest_hash")]
    public string ManifestHash
    {
        get => manifestHash;
        init => manifestHash = ToriiUaidDirectMetadata.RequireExactSizedHex(value, nameof(ManifestHash));
    }

    [JsonPropertyName("status")]
    public ToriiUaidManifestStatus Status
    {
        get => status;
        init => status = ToriiUaidDirectMetadata.RequireManifestStatus(value, nameof(Status));
    }

    [JsonPropertyName("lifecycle")]
    public ToriiUaidManifestLifecycle Lifecycle
    {
        get => lifecycle;
        init => lifecycle = ToriiUaidDirectMetadata.RequireManifestLifecycle(value, nameof(Lifecycle));
    }

    [JsonPropertyName("accounts")]
    public IReadOnlyList<string> Accounts
    {
        get => ToriiListSnapshots.CopyRequired(accounts);
        init => accounts = ToriiUaidDirectMetadata.CopyRequiredCanonicalAccountIdList(value, nameof(Accounts));
    }

    [JsonPropertyName("manifest")]
    public JsonNode Manifest
    {
        get => ToriiJsonSnapshots.Copy(manifest)!;
        init => manifest = ToriiUaidDirectMetadata.CopyRequiredAssetPermissionManifest(value, nameof(Manifest));
    }
}

internal static class ToriiUaidDirectMetadata
{
    internal readonly record struct CanonicalAssetIdParts(
        string Literal,
        string AssetDefinitionId,
        string AccountId,
        ulong? DataspaceId);

    internal static string RequireCanonicalUaidLiteral(string? value, string paramName)
    {
        var text = RequireExactNonEmptyText(value, paramName);
        if (!text.StartsWith("uaid:", StringComparison.Ordinal)
            || text.Length != 69
            || !IsLowercaseHex(text.AsSpan(5))
            || (HexNibble(text[^1]) & 1) == 0)
        {
            throw new ArgumentException(
                "Value must be a canonical `uaid:<64 lowercase hex chars>` literal.",
                paramName);
        }

        return text;
    }

    internal static string RequireCanonicalAccountId(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, paramName);
    }

    internal static string RequireCanonicalAssetDefinitionId(string? value, string paramName)
    {
        var text = RequireExactNonEmptyText(value, paramName);
        return TransactionEncodingContext.CanonicalizeAssetDefinitionId(text, paramName);
    }

    internal static CanonicalAssetIdParts RequireCanonicalAssetId(string? value, string paramName)
    {
        var text = RequireExactNonEmptyText(value, paramName);
        if (text.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Value must not contain whitespace.", paramName);
        }
        var parts = text.Split('#', StringSplitOptions.None);
        if (parts.Length is not (2 or 3) || parts[0].Length == 0 || parts[1].Length == 0)
        {
            throw new ArgumentException("Value must be a canonical public asset id.", paramName);
        }

        string definition;
        string account;
        try
        {
            definition = RequireCanonicalAssetDefinitionId(parts[0], paramName);
            account = RequireCanonicalAccountId(parts[1], paramName);
        }
        catch (ArgumentException error)
        {
            throw new ArgumentException("Value must be a canonical public asset id.", paramName, error);
        }

        ulong? dataspaceId = null;
        if (parts.Length == 3)
        {
            const string Prefix = "dataspace:";
            if (!parts[2].StartsWith(Prefix, StringComparison.Ordinal))
            {
                throw new ArgumentException("Value must be a canonical public asset id.", paramName);
            }
            var rawDataspace = parts[2].AsSpan(Prefix.Length);
            if (rawDataspace.IsEmpty
                || (rawDataspace.Length > 1 && rawDataspace[0] == '0')
                || !rawDataspace.ToString().All(static character => character is >= '0' and <= '9')
                || !ulong.TryParse(rawDataspace, out var parsedDataspace))
            {
                throw new ArgumentException("Value must be a canonical public asset id.", paramName);
            }
            dataspaceId = parsedDataspace;
        }

        return new CanonicalAssetIdParts(text, definition, account, dataspaceId);
    }

    internal static string RequireExactNonEmptyText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, paramName);
    }

    internal static string? RequireOptionalExactNonEmptyText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireOptionalExactNonEmptyText(value, paramName);
    }

    internal static string RequireCanonicalQuantityText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireCanonicalQuantityText(value, paramName);
    }

    internal static string RequireExactSizedHex(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireExactSizedHex(value, paramName, 32);
    }

    internal static ToriiUaidManifestStatus RequireManifestStatus(
        ToriiUaidManifestStatus value,
        string paramName)
    {
        return value is ToriiUaidManifestStatus.Active
            or ToriiUaidManifestStatus.Pending
            or ToriiUaidManifestStatus.Expired
            or ToriiUaidManifestStatus.Revoked
            ? value
            : throw new ArgumentOutOfRangeException(paramName, value, "Unknown UAID manifest status.");
    }

    internal static JsonNode CopyRequiredAssetPermissionManifest(JsonNode? value, string paramName)
    {
        if (value is null)
        {
            throw new ArgumentNullException(paramName, "Value must not be null.");
        }

        ToriiUaidJson.ValidateAssetPermissionManifest(value, paramName);
        return value.DeepClone();
    }

    internal static ToriiUaidPortfolioTotals RequirePortfolioTotals(
        ToriiUaidPortfolioTotals? value,
        string paramName)
    {
        if (value is null)
        {
            throw new ArgumentNullException(paramName, "Value must not be null.");
        }

        return value;
    }

    internal static ToriiUaidManifestLifecycle RequireManifestLifecycle(
        ToriiUaidManifestLifecycle? value,
        string paramName)
    {
        if (value is null)
        {
            throw new ArgumentNullException(paramName, "Value must not be null.");
        }

        RequireOptionalManifestRevocation(
            value.Revocation,
            $"{paramName}.{nameof(ToriiUaidManifestLifecycle.Revocation)}");
        return value;
    }

    internal static ToriiUaidManifestRevocation? RequireOptionalManifestRevocation(
        ToriiUaidManifestRevocation? value,
        string paramName)
    {
        if (value is null)
        {
            return null;
        }

        return value;
    }

    internal static ToriiUaidPortfolioAsset[] CopyRequiredPortfolioAssets(
        IReadOnlyList<ToriiUaidPortfolioAsset>? values,
        string paramName)
    {
        return CopyRequiredObjects(values, paramName, RequirePortfolioAsset);
    }

    internal static ToriiUaidPortfolioAccount[] CopyRequiredPortfolioAccounts(
        IReadOnlyList<ToriiUaidPortfolioAccount>? values,
        string paramName)
    {
        return CopyRequiredObjects(values, paramName, RequirePortfolioAccount);
    }

    internal static ToriiUaidPortfolioDataspace[] CopyRequiredPortfolioDataspaces(
        IReadOnlyList<ToriiUaidPortfolioDataspace>? values,
        string paramName)
    {
        return CopyRequiredObjects(values, paramName, RequirePortfolioDataspace);
    }

    internal static ToriiUaidBindingsDataspace[] CopyRequiredBindingsDataspaces(
        IReadOnlyList<ToriiUaidBindingsDataspace>? values,
        string paramName)
    {
        return CopyRequiredObjects(values, paramName, RequireBindingsDataspace);
    }

    internal static ToriiUaidManifestRecord[] CopyRequiredManifestRecords(
        IReadOnlyList<ToriiUaidManifestRecord>? values,
        string paramName)
    {
        return CopyRequiredObjects(values, paramName, RequireManifestRecord);
    }

    internal static string[] CopyRequiredCanonicalAccountIdList(IReadOnlyList<string>? values, string paramName)
    {
        if (values is null)
        {
            throw new ArgumentNullException(paramName, "Value must not be null.");
        }

        var copy = new string[values.Count];
        if (values.Count > 1)
        {
            throw new ArgumentException(
                "List must contain at most one universal account.",
                paramName);
        }
        for (var index = 0; index < values.Count; index++)
        {
            var value = values[index];
            if (value is null)
            {
                throw new ArgumentException("List elements must not be null.", $"{paramName}[{index}]");
            }

            copy[index] = RequireCanonicalAccountId(value, $"{paramName}[{index}]");
        }

        return copy;
    }

    private static T[] CopyRequiredObjects<T>(
        IReadOnlyList<T>? values,
        string paramName,
        Func<T, string, T> validate)
        where T : class
    {
        if (values is null)
        {
            throw new ArgumentNullException(paramName, "Value must not be null.");
        }

        var copy = new T[values.Count];
        for (var index = 0; index < values.Count; index++)
        {
            var value = values[index];
            if (value is null)
            {
                throw new ArgumentException("List elements must not be null.", $"{paramName}[{index}]");
            }

            copy[index] = validate(value, $"{paramName}[{index}]");
        }

        return copy;
    }

    private static ToriiUaidPortfolioAsset RequirePortfolioAsset(
        ToriiUaidPortfolioAsset value,
        string paramName)
    {
        var asset = RequireCanonicalAssetId(
            value.AssetId,
            $"{paramName}.{nameof(ToriiUaidPortfolioAsset.AssetId)}");
        var definition = RequireCanonicalAssetDefinitionId(
            value.AssetDefinitionId,
            $"{paramName}.{nameof(ToriiUaidPortfolioAsset.AssetDefinitionId)}");
        if (!string.Equals(asset.AssetDefinitionId, definition, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Asset id must match its asset definition id.",
                $"{paramName}.{nameof(ToriiUaidPortfolioAsset.AssetId)}");
        }
        RequireCanonicalQuantityText(
            value.Quantity,
            $"{paramName}.{nameof(ToriiUaidPortfolioAsset.Quantity)}");
        return value;
    }

    private static ToriiUaidPortfolioAccount RequirePortfolioAccount(
        ToriiUaidPortfolioAccount value,
        string paramName)
    {
        RequireCanonicalAccountId(value.AccountId, $"{paramName}.{nameof(ToriiUaidPortfolioAccount.AccountId)}");
        CopyRequiredPortfolioAssets(value.Assets, $"{paramName}.{nameof(ToriiUaidPortfolioAccount.Assets)}");
        return value;
    }

    private static ToriiUaidPortfolioDataspace RequirePortfolioDataspace(
        ToriiUaidPortfolioDataspace value,
        string paramName)
    {
        CopyRequiredPortfolioAccounts(value.Accounts, $"{paramName}.{nameof(ToriiUaidPortfolioDataspace.Accounts)}");
        for (var accountIndex = 0; accountIndex < value.Accounts.Count; accountIndex++)
        {
            var account = value.Accounts[accountIndex];
            for (var assetIndex = 0; assetIndex < account.Assets.Count; assetIndex++)
            {
                var asset = account.Assets[assetIndex];
                var parts = RequireCanonicalAssetId(
                    asset.AssetId,
                    $"{paramName}.{nameof(ToriiUaidPortfolioDataspace.Accounts)}[{accountIndex}].{nameof(ToriiUaidPortfolioAccount.Assets)}[{assetIndex}].{nameof(ToriiUaidPortfolioAsset.AssetId)}");
                if (!string.Equals(parts.AccountId, account.AccountId, StringComparison.Ordinal)
                    || (parts.DataspaceId.HasValue && parts.DataspaceId.Value != value.DataspaceId))
                {
                    throw new ArgumentException(
                        "Asset id must match its account and dataspace.",
                        $"{paramName}.{nameof(ToriiUaidPortfolioDataspace.Accounts)}[{accountIndex}].{nameof(ToriiUaidPortfolioAccount.Assets)}[{assetIndex}].{nameof(ToriiUaidPortfolioAsset.AssetId)}");
                }
            }
        }
        return value;
    }

    private static ToriiUaidBindingsDataspace RequireBindingsDataspace(
        ToriiUaidBindingsDataspace value,
        string paramName)
    {
        CopyRequiredCanonicalAccountIdList(value.Accounts, $"{paramName}.{nameof(ToriiUaidBindingsDataspace.Accounts)}");
        return value;
    }

    private static ToriiUaidManifestRecord RequireManifestRecord(
        ToriiUaidManifestRecord value,
        string paramName)
    {
        RequireExactSizedHex(value.ManifestHash, $"{paramName}.{nameof(ToriiUaidManifestRecord.ManifestHash)}");
        RequireManifestStatus(value.Status, $"{paramName}.{nameof(ToriiUaidManifestRecord.Status)}");
        RequireManifestLifecycle(value.Lifecycle, $"{paramName}.{nameof(ToriiUaidManifestRecord.Lifecycle)}");
        var derivedStatus = value.Lifecycle.Revocation is not null
            ? ToriiUaidManifestStatus.Revoked
            : value.Lifecycle.ExpiredEpoch.HasValue
                ? ToriiUaidManifestStatus.Expired
                : value.Lifecycle.ActivatedEpoch.HasValue
                    ? ToriiUaidManifestStatus.Active
                    : ToriiUaidManifestStatus.Pending;
        if (value.Status != derivedStatus)
        {
            throw new ArgumentException(
                "Manifest status must match its lifecycle.",
                $"{paramName}.{nameof(ToriiUaidManifestRecord.Status)}");
        }
        CopyRequiredCanonicalAccountIdList(value.Accounts, $"{paramName}.{nameof(ToriiUaidManifestRecord.Accounts)}");
        CopyRequiredAssetPermissionManifest(value.Manifest, $"{paramName}.{nameof(ToriiUaidManifestRecord.Manifest)}");
        var manifest = value.Manifest.AsObject();
        if (ToriiUaidJson.RequireJsonUInt64(
                manifest["dataspace"],
                $"{paramName}.{nameof(ToriiUaidManifestRecord.Manifest)}.dataspace") != value.DataspaceId)
        {
            throw new ArgumentException(
                "Manifest dataspace must match the record dataspace id.",
                $"{paramName}.{nameof(ToriiUaidManifestRecord.Manifest)}");
        }
        return value;
    }

    private static bool IsLowercaseHex(ReadOnlySpan<char> value)
    {
        foreach (var character in value)
        {
            if (character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        return true;
    }

    private static int HexNibble(char character)
    {
        if (character >= '0' && character <= '9')
        {
            return character - '0';
        }

        if (character >= 'a' && character <= 'f')
        {
            return character - 'a' + 10;
        }

        return 0;
    }
}

[JsonConverter(typeof(ToriiExplorerAccountQrSnapshotJsonConverter))]
public sealed record class ToriiExplorerAccountQrSnapshot
{
    private string canonicalId = string.Empty;
    private string literal = string.Empty;
    private int networkPrefix;
    private string errorCorrection = string.Empty;
    private int modules;
    private int qrVersion;
    private string svg = string.Empty;

    [JsonPropertyName("canonical_id")]
    public string CanonicalId
    {
        get => canonicalId;
        init => canonicalId = ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, nameof(CanonicalId));
    }

    [JsonPropertyName("literal")]
    public string Literal
    {
        get => literal;
        init => literal = ToriiExplorerDirectMetadata.RequireExactTokenText(value, nameof(Literal));
    }

    [JsonPropertyName("network_prefix")]
    public int NetworkPrefix
    {
        get => networkPrefix;
        init => networkPrefix = ToriiExplorerDirectMetadata.RequireNonNegative(value, nameof(NetworkPrefix));
    }

    [JsonPropertyName("error_correction")]
    public string ErrorCorrection
    {
        get => errorCorrection;
        init => errorCorrection = ToriiExplorerDirectMetadata.RequireExactTokenText(value, nameof(ErrorCorrection));
    }

    [JsonPropertyName("modules")]
    public int Modules
    {
        get => modules;
        init => modules = ToriiExplorerDirectMetadata.RequirePositive(value, nameof(Modules));
    }

    [JsonPropertyName("qr_version")]
    public int QrVersion
    {
        get => qrVersion;
        init => qrVersion = ToriiExplorerDirectMetadata.RequirePositive(value, nameof(QrVersion));
    }

    [JsonPropertyName("svg")]
    public string Svg
    {
        get => svg;
        init => svg = ToriiExplorerDirectMetadata.RequireExactNonEmptyText(value, nameof(Svg));
    }
}

[JsonConverter(typeof(ToriiIdentifierPolicySummaryJsonConverter))]
public sealed record class ToriiIdentifierPolicySummary
{
    private JsonNode? inputEncryptionPublicParametersDecoded;

    [JsonPropertyName("policy_id")]
    public string PolicyId { get; init; } = string.Empty;

    /// <summary>Exact registered program selected by this identifier policy.</summary>
    [JsonPropertyName("program_id")]
    public required string ProgramId { get; init; }

    /// <summary>Pinned independent authority for authenticated plaintext output openings.</summary>
    [JsonPropertyName("output_opening_public_key")]
    public required string OutputOpeningPublicKey { get; init; }

    [JsonPropertyName("owner")]
    public string Owner { get; init; } = string.Empty;

    [JsonPropertyName("active")]
    public bool Active { get; init; }

    [JsonPropertyName("normalization")]
    public string Normalization { get; init; } = string.Empty;

    [JsonPropertyName("resolver_public_key")]
    public string ResolverPublicKey { get; init; } = string.Empty;

    [JsonPropertyName("backend")]
    public string Backend { get; init; } = string.Empty;

    [JsonPropertyName("input_encryption")]
    public string? InputEncryption { get; init; }

    [JsonPropertyName("input_encryption_public_parameters")]
    public string? InputEncryptionPublicParameters { get; init; }

    [JsonPropertyName("input_encryption_public_parameters_decoded")]
    public JsonNode? InputEncryptionPublicParametersDecoded
    {
        get => ToriiJsonSnapshots.Copy(inputEncryptionPublicParametersDecoded);
        init => inputEncryptionPublicParametersDecoded = ToriiJsonSnapshots.Copy(value);
    }

    [JsonPropertyName("ram_fhe_profile")]
    public ToriiRamFheProfile? RamFheProfile { get; init; }

    [JsonPropertyName("note")]
    public string? Note { get; init; }
}

[JsonConverter(typeof(ToriiIdentifierPoliciesResponseJsonConverter))]
public sealed record class ToriiIdentifierPoliciesResponse
{
    private ToriiIdentifierPolicySummary[] items = Array.Empty<ToriiIdentifierPolicySummary>();

    [JsonPropertyName("total")]
    public long Total { get; init; }

    [JsonPropertyName("items")]
    public IReadOnlyList<ToriiIdentifierPolicySummary> Items
    {
        get => ToriiListSnapshots.CopyRequired(items);
        init => items = ToriiListSnapshots.CopyRequired(value);
    }
}

[JsonConverter(typeof(ToriiIdentifierResolveResponseJsonConverter))]
public sealed record class ToriiIdentifierResolveResponse
{
    private JsonNode? signaturePayload;

    [JsonPropertyName("policy_id")]
    public string PolicyId { get; init; } = string.Empty;

    [JsonPropertyName("opaque_id")]
    public string OpaqueId { get; init; } = string.Empty;

    [JsonPropertyName("receipt_hash")]
    public string ReceiptHash { get; init; } = string.Empty;

    [JsonPropertyName("uaid")]
    public string Uaid { get; init; } = string.Empty;

    [JsonPropertyName("account_id")]
    public string AccountId { get; init; } = string.Empty;

    [JsonPropertyName("resolved_at_ms")]
    public long ResolvedAtMilliseconds { get; init; }

    [JsonPropertyName("expires_at_ms")]
    public long? ExpiresAtMilliseconds { get; init; }

    [JsonPropertyName("backend")]
    public string Backend { get; init; } = string.Empty;

    [JsonPropertyName("signature")]
    public string Signature { get; init; } = string.Empty;

    [JsonPropertyName("signature_payload_hex")]
    public string SignaturePayloadHex { get; init; } = string.Empty;

    [JsonPropertyName("signature_payload")]
    public JsonNode? SignaturePayload
    {
        get => ToriiJsonSnapshots.Copy(signaturePayload);
        init => signaturePayload = ToriiJsonSnapshots.Copy(value);
    }
}

[JsonConverter(typeof(ToriiContractAliasBindingJsonConverter))]
public sealed record class ToriiContractAliasBinding
{
    private string alias = string.Empty;
    private string status = string.Empty;
    private long? leaseExpiryMilliseconds;
    private long? graceUntilMilliseconds;
    private long boundAtMilliseconds;

    [JsonPropertyName("alias")]
    public string Alias
    {
        get => alias;
        init => alias = ToriiAliasDirectMetadata.RequireExactTokenText(value, nameof(Alias));
    }

    [JsonPropertyName("status")]
    public string Status
    {
        get => status;
        init => status = ToriiAliasDirectMetadata.RequireExactTokenText(value, nameof(Status));
    }

    [JsonPropertyName("lease_expiry_ms")]
    public long? LeaseExpiryMilliseconds
    {
        get => leaseExpiryMilliseconds;
        init => leaseExpiryMilliseconds = ToriiAliasDirectMetadata.RequireOptionalPositive(
            value,
            nameof(LeaseExpiryMilliseconds));
    }

    [JsonPropertyName("grace_until_ms")]
    public long? GraceUntilMilliseconds
    {
        get => graceUntilMilliseconds;
        init => graceUntilMilliseconds = ToriiAliasDirectMetadata.RequireOptionalPositive(
            value,
            nameof(GraceUntilMilliseconds));
    }

    [JsonPropertyName("bound_at_ms")]
    public long BoundAtMilliseconds
    {
        get => boundAtMilliseconds;
        init => boundAtMilliseconds = ToriiAliasDirectMetadata.RequirePositive(value, nameof(BoundAtMilliseconds));
    }
}

public sealed record class ToriiContractAliasResolutionRequest
{
    [JsonPropertyName("contract_alias")]
    public string ContractAlias { get; init; } = string.Empty;
}

[JsonConverter(typeof(ToriiContractAliasResolutionJsonConverter))]
public sealed record class ToriiContractAliasResolution
{
    private string contractAlias = string.Empty;
    private string contractAddress = string.Empty;
    private string dataspace = string.Empty;
    private string? source;

    [JsonPropertyName("contract_alias")]
    public string ContractAlias
    {
        get => contractAlias;
        init => contractAlias = ToriiAliasDirectMetadata.RequireExactTokenText(value, nameof(ContractAlias));
    }

    [JsonPropertyName("contract_address")]
    public string ContractAddress
    {
        get => contractAddress;
        init => contractAddress = ToriiAliasDirectMetadata.RequireExactTokenText(value, nameof(ContractAddress));
    }

    [JsonPropertyName("dataspace")]
    public string Dataspace
    {
        get => dataspace;
        init => dataspace = ToriiAliasDirectMetadata.RequireExactTokenText(value, nameof(Dataspace));
    }

    [JsonPropertyName("contract_alias_binding")]
    public ToriiContractAliasBinding? ContractAliasBinding { get; init; }

    [JsonPropertyName("source")]
    public string? Source
    {
        get => source;
        init => source = ToriiAliasDirectMetadata.RequireOptionalExactTokenText(value, nameof(Source));
    }
}

[JsonConverter(typeof(ToriiContractCodeRecordJsonConverter))]
public sealed record class ToriiContractCodeRecord
{
    [JsonPropertyName("network_id")]
    public required NetworkId NetworkId { get; init; }

    [JsonPropertyName("artifact_id")]
    public required ContractArtifactId ArtifactId { get; init; }

    private ToriiContractManifest manifest = new() { Permissions = [], Events = [], EnumTypes = [] };
    private string? codeHash;
    private string? abiHash;

    [JsonPropertyName("manifest")]
    public ToriiContractManifest Manifest
    {
        get => manifest;
        init => manifest = ToriiContractMetadataDirectMetadata.RequireObject(value, nameof(Manifest));
    }

    [JsonPropertyName("code_hash")]
    public string? CodeHash
    {
        get => codeHash;
        init => codeHash = ToriiContractMetadataDirectMetadata.RequireOptionalExactSizedHex(value, nameof(CodeHash));
    }

    [JsonPropertyName("abi_hash")]
    public string? AbiHash
    {
        get => abiHash;
        init => abiHash = ToriiContractMetadataDirectMetadata.RequireOptionalExactSizedHex(value, nameof(AbiHash));
    }
}

internal static class ToriiContractMetadataDirectMetadata
{
    internal static T RequireObject<T>(T? value, string paramName)
        where T : class
    {
        return value ?? throw new ArgumentNullException(paramName, "Value must not be null.");
    }

    internal static string RequireExactTokenText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireExactTokenText(value, paramName);
    }

    internal static string? RequireOptionalExactTokenText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireOptionalExactTokenText(value, paramName);
    }

    internal static string RequireExactNonEmptyText(string? value, string paramName)
    {
        return ToriiContractCallDirectMetadata.RequireExactNonEmptyText(value, paramName);
    }

    internal static string? RequireOptionalExactNonEmptyText(string? value, string paramName)
    {
        return ToriiContractCallDirectMetadata.RequireOptionalExactNonEmptyText(value, paramName);
    }

    internal static string RequireExactSizedHex(string? value, string paramName)
    {
        if (value is not null && value.Length == 0)
        {
            throw new ArgumentException("Value must be a non-empty 32-byte hex string.", paramName);
        }

        return ToriiExplorerDirectMetadata.RequireExactSizedHex(value, paramName, 32);
    }

    internal static string? RequireOptionalExactSizedHex(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireOptionalExactSizedHex(value, paramName, 32);
    }

    internal static string[] CopyRequiredExactTokenTextList(
        IReadOnlyList<string>? values,
        string paramName)
    {
        return CopyRequiredTextList(values, paramName, RequireExactTokenText);
    }

    internal static string[] CopyRequiredExactNonEmptyTextList(
        IReadOnlyList<string>? values,
        string paramName)
    {
        return CopyRequiredTextList(values, paramName, RequireExactNonEmptyText);
    }

    internal static string RequireRenderedSourceText(string? value, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value must be non-empty rendered source text.", paramName);
        }

        if (value.IndexOf('\0') >= 0)
        {
            throw new ArgumentException("Value must not contain NUL characters.", paramName);
        }

        return value;
    }

    private static string[] CopyRequiredTextList(
        IReadOnlyList<string>? values,
        string paramName,
        Func<string?, string, string> validate)
    {
        if (values is null)
        {
            return Array.Empty<string>();
        }

        var copy = new string[values.Count];
        for (var index = 0; index < values.Count; index++)
        {
            copy[index] = validate(values[index], $"{paramName}[{index}]");
        }

        return copy;
    }
}


[JsonConverter(typeof(ToriiContractCodeBytesResponseJsonConverter))]
public sealed record class ToriiContractCodeBytesResponse
{
    [JsonPropertyName("network_id")]
    public required NetworkId NetworkId { get; init; }

    [JsonPropertyName("artifact_id")]
    public required ContractArtifactId ArtifactId { get; init; }

    private string codeBase64 = string.Empty;

    [JsonPropertyName("code_b64")]
    public string CodeBase64
    {
        get => codeBase64;
        init
        {
            codeBase64 = value ?? throw new ArgumentNullException(nameof(CodeBase64));
            _ = DecodeExactBase64(codeBase64);
        }
    }

    public byte[] DecodeBytes()
    {
        return DecodeExactBase64(CodeBase64);
    }

    private static byte[] DecodeExactBase64(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new FormatException("code_b64 must be a non-empty base64 payload.");
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new FormatException("code_b64 must not contain surrounding whitespace.");
        }

        if (value.Any(char.IsWhiteSpace))
        {
            throw new FormatException("code_b64 must not contain whitespace.");
        }

        if (value.Any(char.IsControl))
        {
            throw new FormatException("code_b64 must not contain control characters.");
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(value);
        }
        catch (FormatException error)
        {
            throw new FormatException("code_b64 must be an exact base64 payload.", error);
        }

        if (bytes.Length == 0)
        {
            throw new FormatException("code_b64 must be a non-empty base64 payload.");
        }

        if (!string.Equals(Convert.ToBase64String(bytes), value, StringComparison.Ordinal))
        {
            throw new FormatException("code_b64 must be canonical base64 text.");
        }

        return bytes;
    }
}

[JsonConverter(typeof(ToriiGovernedContractResponseJsonConverter))]
public sealed record class ToriiGovernedContractResponse
{
    private string contractAddress = string.Empty;
    private string dataspace = string.Empty;
    private string[]? publicEntrypoints;

    [JsonPropertyName("found")]
    public bool Found { get; init; }

    [JsonPropertyName("contract_address")]
    public string ContractAddress
    {
        get => contractAddress;
        init => contractAddress = value;
    }

    [JsonPropertyName("contract_subject_account")]
    public string? ContractSubjectAccount { get; init; }

    [JsonPropertyName("dataspace")]
    public string Dataspace
    {
        get => dataspace;
        init => dataspace = value;
    }

    [JsonPropertyName("active")]
    public bool? Active { get; init; }

    [JsonPropertyName("lifecycle")]
    public ToriiGovernedContractLifecycle? Lifecycle { get; init; }

    [JsonPropertyName("emergency_hold_active")]
    public bool? EmergencyHoldActive { get; init; }

    [JsonPropertyName("code_hash_hex")]
    public string? CodeHashHex { get; init; }

    [JsonPropertyName("abi_hash_hex")]
    public string? AbiHashHex { get; init; }

    [JsonPropertyName("public_entrypoints")]
    public IReadOnlyList<string>? PublicEntrypoints
    {
        get => ToriiListSnapshots.Copy(publicEntrypoints);
        init => publicEntrypoints = ToriiListSnapshots.Copy(value);
    }
}

public sealed record class ToriiGovernedContractLifecycle
{
    [JsonPropertyName("version")]
    public ushort Version { get; init; }

    [JsonPropertyName("origin")]
    public string Origin { get; init; } = string.Empty;

    [JsonPropertyName("origin_account")]
    public string OriginAccount { get; init; } = string.Empty;

    [JsonPropertyName("origin_proposal_content_id_hex")]
    public string? OriginProposalContentIdHex { get; init; }

    [JsonPropertyName("origin_governance_attempt_id_hex")]
    public string? OriginGovernanceAttemptIdHex { get; init; }

    [JsonPropertyName("owner")]
    public string Owner { get; init; } = string.Empty;

    [JsonPropertyName("pending_owner")]
    public string? PendingOwner { get; init; }

    [JsonPropertyName("parliament_delegated")]
    public bool ParliamentDelegated { get; init; }

    [JsonPropertyName("active_code_hash_hex")]
    public string? ActiveCodeHashHex { get; init; }

    [JsonPropertyName("retained_code_hash_hex")]
    public required string? RetainedCodeHashHex { get; init; }

    [JsonPropertyName("revision")]
    public ulong Revision { get; init; }

    [JsonPropertyName("emergency_hold")]
    public ToriiGovernedContractEmergencyHold? EmergencyHold { get; init; }
}

public sealed record class ToriiGovernedContractEmergencyHold
{
    [JsonPropertyName("incident_digest_hex")]
    public string IncidentDigestHex { get; init; } = string.Empty;

    [JsonPropertyName("proposal_content_id_hex")]
    public string ProposalContentIdHex { get; init; } = string.Empty;

    [JsonPropertyName("governance_attempt_id_hex")]
    public string GovernanceAttemptIdHex { get; init; } = string.Empty;

    [JsonPropertyName("reason")]
    public string Reason { get; init; } = string.Empty;

    [JsonPropertyName("imposed_at_height")]
    public ulong ImposedAtHeight { get; init; }

    [JsonPropertyName("expires_at_height")]
    public ulong ExpiresAtHeight { get; init; }
}


[JsonConverter(typeof(ToriiContractStateEntryJsonConverter))]
public sealed record class ToriiContractStateEntry
{
    private string path = string.Empty;
    private string? valueBase64;
    private JsonNode? valueJson;
    private string? decodeError;

    [JsonPropertyName("path")]
    public string Path
    {
        get => path;
        init => path = ToriiContractStateDirectMetadata.RequireExactTokenText(value, nameof(Path));
    }

    [JsonPropertyName("found")]
    public bool Found { get; init; }

    [JsonPropertyName("value_b64")]
    public string? ValueBase64
    {
        get => valueBase64;
        init => valueBase64 = ToriiContractStateDirectMetadata.RequireOptionalExactBase64AllowEmpty(
            value,
            nameof(ValueBase64));
    }

    [JsonPropertyName("value_len")]
    public ulong? ValueLength { get; init; }

    [JsonPropertyName("value_json")]
    public JsonNode? ValueJson
    {
        get => ToriiJsonSnapshots.Copy(valueJson);
        init => valueJson = ToriiJsonSnapshots.Copy(value);
    }

    [JsonPropertyName("decode_error")]
    public string? DecodeError
    {
        get => decodeError;
        init => decodeError = ToriiContractStateDirectMetadata.RequireOptionalExactNonEmptyText(
            value,
            nameof(DecodeError));
    }
}

[JsonConverter(typeof(ToriiContractStateResponseJsonConverter))]
public sealed record class ToriiContractStateResponse
{
    private string? path;
    private string[]? paths;
    private string? prefix;
    private ToriiContractStateEntry[] entries = Array.Empty<ToriiContractStateEntry>();

    [JsonPropertyName("path")]
    public string? Path
    {
        get => path;
        init => path = ToriiContractStateDirectMetadata.RequireOptionalExactTokenText(value, nameof(Path));
    }

    [JsonPropertyName("paths")]
    public IReadOnlyList<string>? Paths
    {
        get => ToriiListSnapshots.Copy(paths);
        init => paths = ToriiContractStateDirectMetadata.CopyOptionalExactTokenTextList(value, nameof(Paths));
    }

    [JsonPropertyName("prefix")]
    public string? Prefix
    {
        get => prefix;
        init => prefix = ToriiContractStateDirectMetadata.RequireOptionalExactTokenText(value, nameof(Prefix));
    }

    [JsonPropertyName("entries")]
    public IReadOnlyList<ToriiContractStateEntry> Entries
    {
        get => ToriiListSnapshots.CopyRequired(entries);
        init => entries = ToriiListSnapshots.CopyRequired(value);
    }

    [JsonPropertyName("offset")]
    public ulong Offset { get; init; }

    [JsonPropertyName("limit")]
    public ulong Limit { get; init; }

    [JsonPropertyName("next_offset")]
    public ulong? NextOffset { get; init; }
}

internal static class ToriiContractStateDirectMetadata
{
    internal static string RequireExactTokenText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireExactTokenText(value, paramName);
    }

    internal static string? RequireOptionalExactTokenText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireOptionalExactTokenText(value, paramName);
    }

    internal static string[]? CopyOptionalExactTokenTextList(
        IReadOnlyList<string>? values,
        string paramName)
    {
        if (values is null)
        {
            return null;
        }

        var copy = new string[values.Count];
        for (var index = 0; index < values.Count; index++)
        {
            copy[index] = RequireExactTokenText(values[index], $"{paramName}[{index}]");
        }

        return copy;
    }

    internal static string? RequireOptionalExactBase64AllowEmpty(string? value, string paramName)
    {
        if (value is null)
        {
            return null;
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new ArgumentException("Value must not contain surrounding whitespace.", paramName);
        }

        foreach (var character in value)
        {
            if (char.IsWhiteSpace(character))
            {
                throw new ArgumentException("Value must not contain whitespace.", paramName);
            }

            if (char.IsControl(character))
            {
                throw new ArgumentException("Value must not contain control characters.", paramName);
            }
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(value);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("Value must be valid base64.", paramName, exception);
        }

        if (!string.Equals(Convert.ToBase64String(bytes), value, StringComparison.Ordinal))
        {
            throw new ArgumentException("Value must be canonical base64 text.", paramName);
        }

        return value;
    }

    internal static string? RequireOptionalExactNonEmptyText(string? value, string paramName)
    {
        return ToriiContractCallDirectMetadata.RequireOptionalExactNonEmptyText(value, paramName);
    }
}

public sealed record class ToriiContractViewRequest
{
    private JsonNode? payload;

    [JsonPropertyName("authority")]
    public string Authority { get; init; } = string.Empty;

    [JsonPropertyName("contract_address")]
    public string? ContractAddress { get; init; }

    [JsonPropertyName("contract_alias")]
    public string? ContractAlias { get; init; }

    [JsonPropertyName("entrypoint")]
    public string? Entrypoint { get; init; }

    [JsonPropertyName("payload")]
    public JsonNode? Payload
    {
        get => ToriiJsonSnapshots.Copy(payload);
        init => payload = ToriiJsonSnapshots.Copy(value);
    }

    [JsonPropertyName("gas_limit")]
    public ulong GasLimit { get; init; }
}

/// <summary>
/// Caller-trusted exact contract-call intent used to validate an unsigned Torii draft.
/// </summary>
/// <remarks>
/// Construct the invocation from a trusted contract artifact and argument schema.
/// <c>metadata</c> is the exact final transaction metadata, including
/// every deterministic system or event entry Torii is expected to add. This intent
/// is local-only and is never serialized in the request.
/// </remarks>
public sealed class ToriiContractCallDraftIntent
{
    private readonly Dictionary<string, JsonNode?> metadata;

    public ToriiContractCallDraftIntent(
        TransactionContractInvocation invocation,
        IReadOnlyDictionary<string, JsonNode?> metadata)
    {
        Invocation = invocation ?? throw new ArgumentNullException(nameof(invocation));
        ArgumentNullException.ThrowIfNull(metadata);
        this.metadata = metadata.ToDictionary(
            static pair => pair.Key,
            static pair => ToriiJsonSnapshots.Copy(pair.Value),
            StringComparer.Ordinal);
    }

    /// <summary>The exact resolved invocation authorized by the caller.</summary>
    public TransactionContractInvocation Invocation { get; }

    /// <summary>The exact final transaction metadata authorized by the caller.</summary>
    public IReadOnlyDictionary<string, JsonNode?> Metadata => metadata.ToDictionary(
        static pair => pair.Key,
        static pair => ToriiJsonSnapshots.Copy(pair.Value),
        StringComparer.Ordinal);
}

public sealed record class ToriiContractCallRequest
{
    private JsonNode? payload;

    [JsonPropertyName("authority")]
    public string Authority { get; init; } = string.Empty;

    [JsonPropertyName("public_key_hex")]
    public string? PublicKeyHex { get; init; }

    [JsonPropertyName("signature_b64")]
    public string? SignatureBase64 { get; init; }

    /// <summary>Exact retained canonical transaction payload authorized by the detached signature.</summary>
    [JsonPropertyName("transaction_payload_b64")]
    public string? TransactionPayloadBase64 { get; init; }

    [JsonPropertyName("contract_address")]
    public string? ContractAddress { get; init; }

    [JsonPropertyName("contract_alias")]
    public string? ContractAlias { get; init; }

    [JsonPropertyName("entrypoint")]
    public string? Entrypoint { get; init; }

    [JsonPropertyName("payload")]
    public JsonNode? Payload
    {
        get => ToriiJsonSnapshots.Copy(payload);
        init => payload = ToriiJsonSnapshots.Copy(value);
    }

    /// <summary>Exact local-only intent required to accept an unsigned transaction draft.</summary>
    [JsonIgnore]
    public ToriiContractCallDraftIntent? DraftIntent { get; init; }

    [JsonPropertyName("creation_time_ms")]
    public ulong? CreationTimeMilliseconds { get; init; }

    [JsonPropertyName("transaction_ttl_ms")]
    public ulong? TransactionTimeToLiveMilliseconds { get; init; }

    [JsonPropertyName("fee_payment")]
    public FeePaymentIntent FeePayment { get; init; } = null!;
}

public sealed record class ToriiFeeQuoteRequest
{
    [JsonPropertyName("payload")]
    public UnsignedTransactionPayload Payload { get; init; } = null!;
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiFeeQuoteObservation
{
    [JsonRequired, JsonPropertyName("ledger_time_ms")]
    public ulong LedgerTimeMilliseconds { get; init; }

    [JsonRequired, JsonPropertyName("next_block_height")]
    public ulong NextBlockHeight { get; init; }

    [JsonRequired, JsonPropertyName("route_dataspace_id")]
    public ulong RouteDataspaceId { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiFeeQuoteCapacity
{
    [JsonRequired, JsonPropertyName("asset_definition_id")]
    public string AssetDefinitionId { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("vault_balance")]
    public string VaultBalance { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("reserve_floor")]
    public string ReserveFloor { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("block_remaining")]
    public string BlockRemaining { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("program_epoch_remaining")]
    public string ProgramEpochRemaining { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("beneficiary_epoch_remaining")]
    public string BeneficiaryEpochRemaining { get; init; } = string.Empty;
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiFeeDebitSource
{
    [JsonRequired, JsonPropertyName("kind")]
    public string Kind { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("value")]
    public JsonElement Value { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiFeeQuoteDecisionValue
{
    [JsonRequired, JsonPropertyName("debit_source")]
    public ToriiFeeDebitSource DebitSource { get; init; } = null!;

    [JsonRequired, JsonPropertyName("program_revision")]
    public ulong? ProgramRevision { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiFeeQuoteDecision
{
    [JsonRequired, JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("value")]
    public ToriiFeeQuoteDecisionValue Value { get; init; } = null!;
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiFeeQuoteResponse
{
    [JsonRequired, JsonPropertyName("intent")]
    public FeePaymentIntent Intent { get; init; } = null!;

    [JsonRequired, JsonPropertyName("observation")]
    public ToriiFeeQuoteObservation Observation { get; init; } = null!;

    [JsonRequired, JsonPropertyName("components")]
    public IReadOnlyList<FeeChargeLimit> Components { get; init; } = Array.Empty<FeeChargeLimit>();

    [JsonRequired, JsonPropertyName("capacities")]
    public IReadOnlyList<ToriiFeeQuoteCapacity> Capacities { get; init; } = Array.Empty<ToriiFeeQuoteCapacity>();

    [JsonRequired, JsonPropertyName("decision")]
    public ToriiFeeQuoteDecision Decision { get; init; } = null!;
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiFeeSponsorProgramLookupRequest
{
    [JsonRequired, JsonPropertyName("program_id")]
    public string ProgramId { get; init; } = string.Empty;
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiFeeSponsorProgramLifecycle
{
    [JsonRequired, JsonPropertyName("state")]
    public string State { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("value")]
    public JsonNode? Value { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiFeeSponsorProgramActivation
{
    [JsonRequired, JsonPropertyName("revision")]
    public ulong Revision { get; init; }

    [JsonRequired, JsonPropertyName("activate_at_height")]
    public ulong ActivateAtHeight { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiFeeSponsorProgram
{
    [JsonRequired, JsonPropertyName("id")]
    public FeeSponsorProgramId Id { get; init; } = null!;

    [JsonRequired, JsonPropertyName("payout_account")]
    public string PayoutAccount { get; init; } = string.Empty;

    [JsonRequired, JsonPropertyName("lifecycle")]
    public ToriiFeeSponsorProgramLifecycle Lifecycle { get; init; } = null!;

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("active_revision")]
    public ulong? ActiveRevision { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("staged_revision")]
    public ulong? StagedRevision { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("scheduled_activation")]
    public ToriiFeeSponsorProgramActivation? ScheduledActivation { get; init; }
}

public sealed record class ToriiOperationReceipt
{
    [JsonPropertyName("operation_kind")]
    public string OperationKind { get; init; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;

    [JsonPropertyName("transport")]
    public string Transport { get; init; } = string.Empty;

    [JsonPropertyName("dataspace")]
    public string Dataspace { get; init; } = string.Empty;

    [JsonPropertyName("contract_alias")]
    public string? ContractAlias { get; init; }

    [JsonPropertyName("contract_address")]
    public string? ContractAddress { get; init; }

    [JsonPropertyName("code_hash_hex")]
    public string? CodeHashHex { get; init; }

    [JsonPropertyName("abi_hash_hex")]
    public string? AbiHashHex { get; init; }

    [JsonPropertyName("tx_hash_hex")]
    public string? TransactionHashHex { get; init; }

    [JsonPropertyName("entrypoint")]
    public string? Entrypoint { get; init; }

    [JsonPropertyName("entrypoint_hash_hex")]
    public string? EntrypointHashHex { get; init; }

    [JsonPropertyName("gas_limit")]
    public ulong? GasLimit { get; init; }

    [JsonPropertyName("gas_used")]
    public ulong? GasUsed { get; init; }

    [JsonPropertyName("fee_payment")]
    public FeePaymentIntent? FeePayment { get; init; }

    [JsonPropertyName("payload_digest_hex")]
    public string PayloadDigestHex { get; init; } = string.Empty;
}

[JsonConverter(typeof(ToriiContractViewAccessHintsJsonConverter))]
public sealed record class ToriiContractViewAccessHints
{
    private string[] readKeys = Array.Empty<string>();
    private string[] writeKeys = Array.Empty<string>();

    [JsonPropertyName("read_keys")]
    public IReadOnlyList<string> ReadKeys
    {
        get => ToriiListSnapshots.CopyRequired(readKeys);
        init => readKeys = ToriiContractMetadataDirectMetadata.CopyRequiredExactTokenTextList(
            value,
            nameof(ReadKeys));
    }

    [JsonPropertyName("write_keys")]
    public IReadOnlyList<string> WriteKeys
    {
        get => ToriiListSnapshots.CopyRequired(writeKeys);
        init => writeKeys = ToriiContractMetadataDirectMetadata.CopyRequiredExactTokenTextList(
            value,
            nameof(WriteKeys));
    }
}

[JsonConverter(typeof(ToriiContractViewEntrypointParamJsonConverter))]
public sealed record class ToriiContractViewEntrypointParam
{
    private string name = string.Empty;
    private string typeName = string.Empty;

    [JsonPropertyName("name")]
    public string Name
    {
        get => name;
        init => name = ToriiContractMetadataDirectMetadata.RequireExactTokenText(value, nameof(Name));
    }

    [JsonPropertyName("type_name")]
    public string TypeName
    {
        get => typeName;
        init => typeName = ToriiContractMetadataDirectMetadata.RequireExactNonEmptyText(value, nameof(TypeName));
    }
}

[JsonConverter(typeof(ToriiContractViewEntrypointJsonConverter))]
public sealed record class ToriiContractViewEntrypoint
{
    private string name = string.Empty;
    private string kind = string.Empty;
    private ToriiContractViewEntrypointParam[] parameters = Array.Empty<ToriiContractViewEntrypointParam>();
    private string? returnType;
    private string[] readKeys = Array.Empty<string>();
    private string[] writeKeys = Array.Empty<string>();
    private string[] accessHintsSkipped = Array.Empty<string>();
    private string[] triggers = Array.Empty<string>();

    [JsonPropertyName("name")]
    public string Name
    {
        get => name;
        init => name = ToriiContractMetadataDirectMetadata.RequireExactTokenText(value, nameof(Name));
    }

    [JsonPropertyName("kind")]
    public string Kind
    {
        get => kind;
        init => kind = ToriiContractMetadataDirectMetadata.RequireExactTokenText(value, nameof(Kind));
    }

    [JsonPropertyName("params")]
    public IReadOnlyList<ToriiContractViewEntrypointParam> Parameters
    {
        get => ToriiListSnapshots.CopyRequired(parameters);
        init => parameters = ToriiListSnapshots.CopyNonNullItems(value, nameof(Parameters)) ?? Array.Empty<ToriiContractViewEntrypointParam>();
    }

    [JsonPropertyName("return_type")]
    public string? ReturnType
    {
        get => returnType;
        init => returnType = ToriiContractMetadataDirectMetadata.RequireOptionalExactNonEmptyText(
            value,
            nameof(ReturnType));
    }

    private ToriiEntrypointAuthorizationV1 authorization = null!;
    [JsonPropertyName("authorization")]
    public required ToriiEntrypointAuthorizationV1 Authorization
    {
        get => authorization;
        init
        {
            try { _ = ToriiContractManifestJson.BuildAuthorization(value, "authorization"); }
            catch (JsonException error) { throw new ArgumentException(error.Message, nameof(Authorization), error); }
            authorization = value;
        }
    }

    [JsonPropertyName("read_keys")]
    public IReadOnlyList<string> ReadKeys
    {
        get => ToriiListSnapshots.CopyRequired(readKeys);
        init => readKeys = ToriiContractMetadataDirectMetadata.CopyRequiredExactTokenTextList(
            value,
            nameof(ReadKeys));
    }

    [JsonPropertyName("write_keys")]
    public IReadOnlyList<string> WriteKeys
    {
        get => ToriiListSnapshots.CopyRequired(writeKeys);
        init => writeKeys = ToriiContractMetadataDirectMetadata.CopyRequiredExactTokenTextList(
            value,
            nameof(WriteKeys));
    }

    [JsonPropertyName("access_hints_complete")]
    public bool? AccessHintsComplete { get; init; }

    [JsonPropertyName("access_hints_skipped")]
    public IReadOnlyList<string> AccessHintsSkipped
    {
        get => ToriiListSnapshots.CopyRequired(accessHintsSkipped);
        init => accessHintsSkipped = ToriiContractMetadataDirectMetadata.CopyRequiredExactTokenTextList(
            value,
            nameof(AccessHintsSkipped));
    }

    [JsonPropertyName("triggers")]
    public IReadOnlyList<string> Triggers
    {
        get => ToriiListSnapshots.CopyRequired(triggers);
        init => triggers = ToriiContractMetadataDirectMetadata.CopyRequiredExactTokenTextList(
            value,
            nameof(Triggers));
    }
}

[JsonConverter(typeof(ToriiContractViewSyscallJsonConverter))]
public sealed record class ToriiContractViewSyscall
{
    private string? name;

    [JsonPropertyName("number")]
    public byte Number { get; init; }

    [JsonPropertyName("name")]
    public string? Name
    {
        get => name;
        init => name = ToriiContractMetadataDirectMetadata.RequireOptionalExactTokenText(value, nameof(Name));
    }

    [JsonPropertyName("count")]
    public ulong Count { get; init; }
}

[JsonConverter(typeof(ToriiContractViewMemoryJsonConverter))]
public sealed record class ToriiContractViewMemory
{
    [JsonPropertyName("load64")]
    public ulong Load64 { get; init; }

    [JsonPropertyName("store64")]
    public ulong Store64 { get; init; }

    [JsonPropertyName("load128")]
    public ulong Load128 { get; init; }

    [JsonPropertyName("store128")]
    public ulong Store128 { get; init; }
}

[JsonConverter(typeof(ToriiContractViewAnalysisJsonConverter))]
public sealed record class ToriiContractViewAnalysis
{
    private ToriiContractViewMemory memory = new();
    private ToriiContractViewSyscall[] syscalls = Array.Empty<ToriiContractViewSyscall>();

    [JsonPropertyName("instruction_count")]
    public ulong InstructionCount { get; init; }

    [JsonPropertyName("memory")]
    public ToriiContractViewMemory Memory
    {
        get => memory;
        init => memory = ToriiContractMetadataDirectMetadata.RequireObject(value, nameof(Memory));
    }

    [JsonPropertyName("syscalls")]
    public IReadOnlyList<ToriiContractViewSyscall> Syscalls
    {
        get => ToriiListSnapshots.CopyRequired(syscalls);
        init => syscalls = ToriiListSnapshots.CopyNonNullItems(value, nameof(Syscalls)) ?? Array.Empty<ToriiContractViewSyscall>();
    }
}

[JsonConverter(typeof(ToriiContractVerifiedSourceReferenceJsonConverter))]
public sealed record class ToriiContractVerifiedSourceReference
{
    private string language = string.Empty;
    private string? sourceName;
    private string submittedAt = string.Empty;
    private string? manifestIdHex;
    private string? payloadDigestHex;

    [JsonPropertyName("language")]
    public string Language
    {
        get => language;
        init => language = ToriiContractMetadataDirectMetadata.RequireExactNonEmptyText(value, nameof(Language));
    }

    [JsonPropertyName("source_name")]
    public string? SourceName
    {
        get => sourceName;
        init => sourceName = ToriiContractMetadataDirectMetadata.RequireOptionalExactNonEmptyText(
            value,
            nameof(SourceName));
    }

    [JsonPropertyName("submitted_at")]
    public string SubmittedAt
    {
        get => submittedAt;
        init => submittedAt = ToriiContractMetadataDirectMetadata.RequireExactNonEmptyText(
            value,
            nameof(SubmittedAt));
    }

    [JsonPropertyName("manifest_id_hex")]
    public string? ManifestIdHex
    {
        get => manifestIdHex;
        init => manifestIdHex = ToriiContractMetadataDirectMetadata.RequireOptionalExactSizedHex(
            value,
            nameof(ManifestIdHex));
    }

    [JsonPropertyName("payload_digest_hex")]
    public string? PayloadDigestHex
    {
        get => payloadDigestHex;
        init => payloadDigestHex = ToriiContractMetadataDirectMetadata.RequireOptionalExactSizedHex(
            value,
            nameof(PayloadDigestHex));
    }

    [JsonPropertyName("content_length")]
    public ulong? ContentLength { get; init; }
}

[JsonConverter(typeof(ToriiContractCodeViewJsonConverter))]
public sealed record class ToriiContractCodeView
{
    private ToriiContractSourceArtifact[] sourceArtifacts = Array.Empty<ToriiContractSourceArtifact>();
    [JsonRequired]
    [JsonPropertyName("source_artifacts")]
    public IReadOnlyList<ToriiContractSourceArtifact> SourceArtifacts
    {
        get => ToriiListSnapshots.CopyRequired(sourceArtifacts);
        init => sourceArtifacts = ToriiListSnapshots.CopyNonNullItems(value, nameof(SourceArtifacts)) ?? throw new ArgumentNullException(nameof(SourceArtifacts));
    }

    [JsonPropertyName("network_id")]
    public required NetworkId NetworkId { get; init; }

    [JsonPropertyName("artifact_id")]
    public required ContractArtifactId ArtifactId { get; init; }

    private string codeHash = string.Empty;
    private string? declaredCodeHash;
    private string? abiHash;
    private string? compilerFingerprint;
    private ToriiContractPermissionDescriptorV1[] permissions = Array.Empty<ToriiContractPermissionDescriptorV1>();
    private ToriiContractViewEntrypoint[] entrypoints = Array.Empty<ToriiContractViewEntrypoint>();
    private string[] warnings = Array.Empty<string>();
    private string renderedSourceKind = string.Empty;
    private string renderedSourceText = string.Empty;

    [JsonPropertyName("code_hash")]
    public string CodeHash
    {
        get => codeHash;
        init => codeHash = ToriiContractMetadataDirectMetadata.RequireExactSizedHex(value, nameof(CodeHash));
    }

    [JsonPropertyName("declared_code_hash")]
    public string? DeclaredCodeHash
    {
        get => declaredCodeHash;
        init => declaredCodeHash = ToriiContractMetadataDirectMetadata.RequireOptionalExactSizedHex(
            value,
            nameof(DeclaredCodeHash));
    }

    [JsonPropertyName("abi_hash")]
    public string? AbiHash
    {
        get => abiHash;
        init => abiHash = ToriiContractMetadataDirectMetadata.RequireOptionalExactSizedHex(
            value,
            nameof(AbiHash));
    }

    [JsonPropertyName("compiler_fingerprint")]
    public string? CompilerFingerprint
    {
        get => compilerFingerprint;
        init => compilerFingerprint = ToriiContractMetadataDirectMetadata.RequireOptionalExactNonEmptyText(
            value,
            nameof(CompilerFingerprint));
    }

    [JsonPropertyName("byte_len")]
    public ulong? ByteLength { get; init; }

    [JsonPropertyName("permissions")]
    public required IReadOnlyList<ToriiContractPermissionDescriptorV1> Permissions
    {
        get => ToriiListSnapshots.CopyRequired(permissions);
        init
        {
            var items = ToriiListSnapshots.CopyNonNullItems(value, nameof(Permissions))
                ?? throw new ArgumentNullException(nameof(Permissions));
            for (var index = 0; index < items.Length; index++)
            {
                try { _ = ToriiContractManifestJson.BuildPermissionDeclaration(items[index], "permission declaration"); }
                catch (JsonException error) { throw new ArgumentException(error.Message, $"{nameof(Permissions)}[{index}]", error); }
            }
            permissions = items;
        }
    }

    [JsonPropertyName("access_hints")]
    public ToriiContractViewAccessHints? AccessHints { get; init; }

    [JsonPropertyName("entrypoints")]
    public IReadOnlyList<ToriiContractViewEntrypoint> Entrypoints
    {
        get => ToriiListSnapshots.CopyRequired(entrypoints);
        init => entrypoints = ToriiListSnapshots.CopyNonNullItems(value, nameof(Entrypoints)) ?? Array.Empty<ToriiContractViewEntrypoint>();
    }

    [JsonPropertyName("analysis")]
    public ToriiContractViewAnalysis? Analysis { get; init; }

    [JsonPropertyName("warnings")]
    public IReadOnlyList<string> Warnings
    {
        get => ToriiListSnapshots.CopyRequired(warnings);
        init => warnings = ToriiContractMetadataDirectMetadata.CopyRequiredExactNonEmptyTextList(
            value,
            nameof(Warnings));
    }

    [JsonPropertyName("rendered_source_kind")]
    public string RenderedSourceKind
    {
        get => renderedSourceKind;
        init => renderedSourceKind = ToriiContractMetadataDirectMetadata.RequireExactTokenText(
            value,
            nameof(RenderedSourceKind));
    }

    [JsonPropertyName("rendered_source_text")]
    public string RenderedSourceText
    {
        get => renderedSourceText;
        init => renderedSourceText = ToriiContractMetadataDirectMetadata.RequireRenderedSourceText(
            value,
            nameof(RenderedSourceText));
    }

    private ToriiContractSourceFile[] sourceFiles = Array.Empty<ToriiContractSourceFile>();
    private ToriiContractSourceImport[] sourceImports = Array.Empty<ToriiContractSourceImport>();
    private ToriiContractSourcePackage[] sourcePackages = Array.Empty<ToriiContractSourcePackage>();

    [JsonPropertyName("source_files")]
    public IReadOnlyList<ToriiContractSourceFile> SourceFiles
    {
        get => ToriiListSnapshots.CopyRequired(sourceFiles);
        init => sourceFiles = ToriiListSnapshots.CopyNonNullItems(value, nameof(SourceFiles)) ?? Array.Empty<ToriiContractSourceFile>();
    }

    [JsonPropertyName("source_imports")]
    public IReadOnlyList<ToriiContractSourceImport> SourceImports
    {
        get => ToriiListSnapshots.CopyRequired(sourceImports);
        init => sourceImports = ToriiListSnapshots.CopyNonNullItems(value, nameof(SourceImports)) ?? Array.Empty<ToriiContractSourceImport>();
    }

    [JsonPropertyName("source_packages")]
    public IReadOnlyList<ToriiContractSourcePackage> SourcePackages
    {
        get => ToriiListSnapshots.CopyRequired(sourcePackages);
        init => sourcePackages = ToriiListSnapshots.CopyNonNullItems(value, nameof(SourcePackages)) ?? Array.Empty<ToriiContractSourcePackage>();
    }

    [JsonPropertyName("verified_source_ref")]
    public ToriiContractVerifiedSourceReference? VerifiedSourceReference { get; init; }
}

public sealed record class ToriiContractCallResponse
{
    private bool ok;
    private string dataspace = string.Empty;
    private string? contractAddress;
    private string codeHashHex = string.Empty;
    private string abiHashHex = string.Empty;
    private ulong creationTimeMilliseconds;
    private string? transactionHashHex;
    private string? transactionPayloadBase64, signingMessageBase64;
    private string? entrypoint;

    [JsonPropertyName("ok")]
    public bool Ok
    {
        get => ok;
        init => ok = ToriiContractCallDirectMetadata.RequireTrue(value, nameof(Ok));
    }

    [JsonPropertyName("submitted")]
    public bool Submitted { get; init; }

    [JsonPropertyName("dataspace")]
    public string Dataspace
    {
        get => dataspace;
        init => dataspace = ToriiContractCallDirectMetadata.RequireExactTokenText(value, nameof(Dataspace));
    }

    [JsonPropertyName("contract_address")]
    public string? ContractAddress
    {
        get => contractAddress;
        init => contractAddress = ToriiContractCallDirectMetadata.RequireOptionalExactTokenText(
            value,
            nameof(ContractAddress));
    }

    [JsonPropertyName("code_hash_hex")]
    public string CodeHashHex
    {
        get => codeHashHex;
        init => codeHashHex = ToriiContractCallDirectMetadata.RequireExactSizedHex(value, nameof(CodeHashHex));
    }

    [JsonPropertyName("abi_hash_hex")]
    public string AbiHashHex
    {
        get => abiHashHex;
        init => abiHashHex = ToriiContractCallDirectMetadata.RequireExactSizedHex(value, nameof(AbiHashHex));
    }

    [JsonPropertyName("creation_time_ms")]
    public ulong CreationTimeMilliseconds
    {
        get => creationTimeMilliseconds;
        init => creationTimeMilliseconds = ToriiContractCallDirectMetadata.RequirePositive(
            value,
            nameof(CreationTimeMilliseconds));
    }

    [JsonPropertyName("transaction_ttl_ms")]
    public ulong? TransactionTimeToLiveMilliseconds { get; init; }

    [JsonPropertyName("tx_hash_hex")]
    public string? TransactionHashHex
    {
        get => transactionHashHex;
        init => transactionHashHex = ToriiContractCallDirectMetadata.RequireOptionalTransactionHashHex(
            value,
            nameof(TransactionHashHex));
    }

    [JsonPropertyName("pipeline_status")]
    public JsonNode? PipelineStatus { get; init; }

    [JsonPropertyName("entrypoint_hash_hex")]
    public string? EntrypointHashHex { get; init; }

    [JsonPropertyName("transaction_payload_b64")]
    public string? TransactionPayloadBase64
    {
        get => transactionPayloadBase64;
        init => transactionPayloadBase64 = ToriiContractCallDirectMetadata.RequireOptionalBase64(value, nameof(TransactionPayloadBase64));
    }
    [JsonPropertyName("signing_message_b64")]
    public string? SigningMessageBase64
    {
        get => signingMessageBase64;
        init => signingMessageBase64 = ToriiContractCallDirectMetadata.RequireOptionalBase64(
            value,
            nameof(SigningMessageBase64));
    }

    [JsonPropertyName("entrypoint")]
    public string? Entrypoint
    {
        get => entrypoint;
        init => entrypoint = ToriiContractCallDirectMetadata.RequireOptionalExactTokenText(
            value,
            nameof(Entrypoint));
    }

    [JsonPropertyName("operation_receipt")]
    public ToriiOperationReceipt OperationReceipt { get; init; } = null!;
}

[JsonConverter(typeof(ToriiContractViewResponseJsonConverter))]
public sealed record class ToriiContractViewResponse
{
    private bool ok;
    private string dataspace = string.Empty;
    private string contractId = string.Empty;
    private string? contractAddress;
    private string codeHashHex = string.Empty;
    private string abiHashHex = string.Empty;
    private string entrypoint = string.Empty;
    private JsonNode? result;

    [JsonPropertyName("ok")]
    public bool Ok
    {
        get => ok;
        init => ok = ToriiContractCallDirectMetadata.RequireTrue(value, nameof(Ok));
    }

    [JsonPropertyName("dataspace")]
    public string Dataspace
    {
        get => dataspace;
        init => dataspace = ToriiContractCallDirectMetadata.RequireExactTokenText(value, nameof(Dataspace));
    }

    [JsonPropertyName("contract_id")]
    public string ContractId
    {
        get => contractId;
        init => contractId = ToriiContractCallDirectMetadata.RequireExactTokenText(value, nameof(ContractId));
    }

    [JsonPropertyName("contract_address")]
    public string? ContractAddress
    {
        get => contractAddress;
        init => contractAddress = ToriiContractCallDirectMetadata.RequireOptionalExactTokenText(
            value,
            nameof(ContractAddress));
    }

    [JsonPropertyName("code_hash_hex")]
    public string CodeHashHex
    {
        get => codeHashHex;
        init => codeHashHex = ToriiContractCallDirectMetadata.RequireExactSizedHex(value, nameof(CodeHashHex));
    }

    [JsonPropertyName("abi_hash_hex")]
    public string AbiHashHex
    {
        get => abiHashHex;
        init => abiHashHex = ToriiContractCallDirectMetadata.RequireExactSizedHex(value, nameof(AbiHashHex));
    }

    [JsonPropertyName("entrypoint")]
    public string Entrypoint
    {
        get => entrypoint;
        init => entrypoint = ToriiContractCallDirectMetadata.RequireExactTokenText(value, nameof(Entrypoint));
    }

    [JsonPropertyName("result")]
    public JsonNode? Result
    {
        get => ToriiJsonSnapshots.Copy(result);
        init => result = ToriiJsonSnapshots.Copy(value);
    }
}

[JsonConverter(typeof(ToriiContractViewVmDiagnosticJsonConverter))]
public sealed record class ToriiContractViewVmDiagnostic
{
    private string trapKind = string.Empty;
    private string message = string.Empty;
    private string? function;
    private string? sourcePath;
    private ulong gasLimit;
    private ulong maxCycles;
    private ulong stackLimitBytes;
    private string? currentFunction;

    [JsonPropertyName("trap_kind")]
    public string TrapKind
    {
        get => trapKind;
        init => trapKind = ToriiContractCallDirectMetadata.RequireExactTokenText(value, nameof(TrapKind));
    }

    [JsonPropertyName("message")]
    public string Message
    {
        get => message;
        init => message = ToriiContractCallDirectMetadata.RequireExactNonEmptyText(value, nameof(Message));
    }

    [JsonPropertyName("pc")]
    public ulong ProgramCounter { get; init; }

    [JsonPropertyName("function")]
    public string? Function
    {
        get => function;
        init => function = ToriiContractCallDirectMetadata.RequireOptionalExactNonEmptyText(
            value,
            nameof(Function));
    }

    [JsonPropertyName("source_path")]
    public string? SourcePath
    {
        get => sourcePath;
        init => sourcePath = ToriiContractCallDirectMetadata.RequireOptionalExactNonEmptyText(
            value,
            nameof(SourcePath));
    }

    [JsonPropertyName("line")]
    public uint? Line { get; init; }

    [JsonPropertyName("column")]
    public uint? Column { get; init; }

    [JsonPropertyName("gas_limit")]
    public ulong GasLimit
    {
        get => gasLimit;
        init => gasLimit = ToriiContractCallDirectMetadata.RequirePositive(value, nameof(GasLimit));
    }

    [JsonPropertyName("gas_remaining")]
    public ulong GasRemaining { get; init; }

    [JsonPropertyName("gas_used")]
    public ulong GasUsed { get; init; }

    [JsonPropertyName("cycles")]
    public ulong Cycles { get; init; }

    [JsonPropertyName("max_cycles")]
    public ulong MaxCycles
    {
        get => maxCycles;
        init => maxCycles = ToriiContractCallDirectMetadata.RequirePositive(value, nameof(MaxCycles));
    }

    [JsonPropertyName("stack_limit_bytes")]
    public ulong StackLimitBytes
    {
        get => stackLimitBytes;
        init => stackLimitBytes = ToriiContractCallDirectMetadata.RequirePositive(
            value,
            nameof(StackLimitBytes));
    }

    [JsonPropertyName("stack_bytes_used")]
    public ulong StackBytesUsed { get; init; }

    [JsonPropertyName("entrypoint_pc")]
    public ulong? EntrypointProgramCounter { get; init; }

    [JsonPropertyName("current_function")]
    public string? CurrentFunction
    {
        get => currentFunction;
        init => currentFunction = ToriiContractCallDirectMetadata.RequireOptionalExactNonEmptyText(
            value,
            nameof(CurrentFunction));
    }

    [JsonPropertyName("opcode")]
    public ushort? Opcode { get; init; }

    [JsonPropertyName("syscall")]
    public uint? Syscall { get; init; }

    [JsonPropertyName("predecoded_loaded")]
    public bool PredecodedLoaded { get; init; }

    [JsonPropertyName("predecoded_hit")]
    public bool? PredecodedHit { get; init; }
}

[JsonConverter(typeof(ToriiContractViewErrorResponseJsonConverter))]
public sealed record class ToriiContractViewErrorResponse
{
    private bool ok;
    private string dataspace = string.Empty;
    private string contractId = string.Empty;
    private string? contractAddress;
    private string codeHashHex = string.Empty;
    private string abiHashHex = string.Empty;
    private string entrypoint = string.Empty;
    private string error = string.Empty;

    [JsonPropertyName("ok")]
    public bool Ok
    {
        get => ok;
        init => ok = ToriiContractCallDirectMetadata.RequireFalse(value, nameof(Ok));
    }

    [JsonPropertyName("dataspace")]
    public string Dataspace
    {
        get => dataspace;
        init => dataspace = ToriiContractCallDirectMetadata.RequireExactTokenText(value, nameof(Dataspace));
    }

    [JsonPropertyName("contract_id")]
    public string ContractId
    {
        get => contractId;
        init => contractId = ToriiContractCallDirectMetadata.RequireExactTokenText(value, nameof(ContractId));
    }

    [JsonPropertyName("contract_address")]
    public string? ContractAddress
    {
        get => contractAddress;
        init => contractAddress = ToriiContractCallDirectMetadata.RequireOptionalExactTokenText(
            value,
            nameof(ContractAddress));
    }

    [JsonPropertyName("code_hash_hex")]
    public string CodeHashHex
    {
        get => codeHashHex;
        init => codeHashHex = ToriiContractCallDirectMetadata.RequireExactSizedHex(value, nameof(CodeHashHex));
    }

    [JsonPropertyName("abi_hash_hex")]
    public string AbiHashHex
    {
        get => abiHashHex;
        init => abiHashHex = ToriiContractCallDirectMetadata.RequireExactSizedHex(value, nameof(AbiHashHex));
    }

    [JsonPropertyName("entrypoint")]
    public string Entrypoint
    {
        get => entrypoint;
        init => entrypoint = ToriiContractCallDirectMetadata.RequireExactTokenText(value, nameof(Entrypoint));
    }

    [JsonPropertyName("error")]
    public string Error
    {
        get => error;
        init => error = ToriiContractCallDirectMetadata.RequireExactNonEmptyText(value, nameof(Error));
    }

    [JsonPropertyName("vm_diagnostic")]
    public ToriiContractViewVmDiagnostic? VmDiagnostic { get; init; }
    /// <summary>Required nullable deterministic fault, independent of optional diagnostics.</summary>
    [JsonPropertyName("fault")]
    public required ToriiIvmFault? Fault { get; init; }

}

internal static class ToriiContractCallDirectMetadata
{
    internal static bool RequireTrue(bool value, string paramName)
    {
        if (!value)
        {
            throw new ArgumentException("Value must be true.", paramName);
        }

        return value;
    }

    internal static bool RequireFalse(bool value, string paramName)
    {
        if (value)
        {
            throw new ArgumentException("Value must be false.", paramName);
        }

        return value;
    }

    internal static string RequireExactTokenText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireExactTokenText(value, paramName);
    }

    internal static string? RequireOptionalExactTokenText(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireOptionalExactTokenText(value, paramName);
    }

    internal static string RequireExactSizedHex(string? value, string paramName)
    {
        if (value is not null && value.Length == 0)
        {
            throw new ArgumentException("Value must be a non-empty 32-byte hex string.", paramName);
        }

        return ToriiExplorerDirectMetadata.RequireExactSizedHex(value, paramName, 32);
    }

    internal static string? RequireOptionalTransactionHashHex(string? value, string paramName)
    {
        if (value is null || value.Length == 0)
        {
            return value;
        }

        return ToriiExplorerDirectMetadata.RequireExactSizedHex(value, paramName, 32);
    }

    internal static ulong RequirePositive(ulong value, string paramName)
    {
        if (value == 0)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be positive.");
        }

        return value;
    }

    internal static string? RequireOptionalBase64(string? value, string paramName)
    {
        return ToriiMultisigDirectMetadata.RequireOptionalBase64(value, paramName);
    }

    internal static string RequireExactNonEmptyText(string? value, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value must be a non-empty string.", paramName);
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new ArgumentException("Value must not contain surrounding whitespace.", paramName);
        }

        foreach (var character in value)
        {
            if (char.IsControl(character))
            {
                throw new ArgumentException("Value must not contain control characters.", paramName);
            }
        }

        return value;
    }

    internal static string? RequireOptionalExactNonEmptyText(string? value, string paramName)
    {
        return value is null ? null : RequireExactNonEmptyText(value, paramName);
    }
}

public sealed record class ToriiContractViewExecutionResult
{
    public bool IsSuccess => Success is not null;

    public ToriiContractViewResponse? Success { get; init; }

    public ToriiContractViewErrorResponse? Error { get; init; }
}

public sealed record class ToriiContractVerifiedSourceSubmission
{
    private ToriiContractSourceArtifact[] artifacts = Array.Empty<ToriiContractSourceArtifact>();
    [JsonRequired]
    [JsonPropertyName("artifacts")]
    public IReadOnlyList<ToriiContractSourceArtifact> Artifacts
    {
        get => ToriiListSnapshots.CopyRequired(artifacts);
        init => artifacts = ToriiListSnapshots.CopyNonNullItems(value, nameof(Artifacts)) ?? throw new ArgumentNullException(nameof(Artifacts));
    }

    [JsonPropertyName("language")]
    public string Language { get; init; } = string.Empty;

    [JsonPropertyName("source_name")]
    public string? SourceName { get; init; }

    [JsonPropertyName("source_text")]
    public string SourceText { get; init; } = string.Empty;

    private ToriiContractSourceFile[] sources = Array.Empty<ToriiContractSourceFile>();
    private ToriiContractSourceImport[] imports = Array.Empty<ToriiContractSourceImport>();
    private ToriiContractSourcePackage[] packages = Array.Empty<ToriiContractSourcePackage>();

    [JsonPropertyName("sources")]
    public IReadOnlyList<ToriiContractSourceFile> Sources
    {
        get => ToriiListSnapshots.CopyRequired(sources);
        init => sources = ToriiListSnapshots.CopyNonNullItems(value, nameof(Sources)) ?? Array.Empty<ToriiContractSourceFile>();
    }

    [JsonPropertyName("imports")]
    public IReadOnlyList<ToriiContractSourceImport> Imports
    {
        get => ToriiListSnapshots.CopyRequired(imports);
        init => imports = ToriiListSnapshots.CopyNonNullItems(value, nameof(Imports)) ?? Array.Empty<ToriiContractSourceImport>();
    }

    [JsonPropertyName("packages")]
    public IReadOnlyList<ToriiContractSourcePackage> Packages
    {
        get => ToriiListSnapshots.CopyRequired(packages);
        init => packages = ToriiListSnapshots.CopyNonNullItems(value, nameof(Packages)) ?? Array.Empty<ToriiContractSourcePackage>();
    }
}

public sealed record class ToriiContractSourceImport
{
    [JsonPropertyName("alias")]
    public required string Alias { get; init; }

    [JsonPropertyName("package")]
    public required string Package { get; init; }
}

public sealed record class ToriiContractSourcePackage
{
    private ToriiContractSourceArtifact[] artifacts = Array.Empty<ToriiContractSourceArtifact>();
    [JsonRequired]
    [JsonPropertyName("artifacts")]
    public IReadOnlyList<ToriiContractSourceArtifact> Artifacts
    {
        get => ToriiListSnapshots.CopyRequired(artifacts);
        init => artifacts = ToriiListSnapshots.CopyNonNullItems(value, nameof(Artifacts)) ?? throw new ArgumentNullException(nameof(Artifacts));
    }

    private ToriiContractSourceFile[] modules = Array.Empty<ToriiContractSourceFile>();
    private ToriiContractSourceFile[] sources = Array.Empty<ToriiContractSourceFile>();
    private ToriiContractSourceImport[] imports = Array.Empty<ToriiContractSourceImport>();
    private string[] exports = Array.Empty<string>();

    [JsonPropertyName("identity")]
    public required string Identity { get; init; }

    [JsonPropertyName("modules")]
    public required IReadOnlyList<ToriiContractSourceFile> Modules
    {
        get => ToriiListSnapshots.CopyRequired(modules);
        init => modules = ToriiListSnapshots.CopyNonNullItems(value, nameof(Modules)) ?? Array.Empty<ToriiContractSourceFile>();
    }

    [JsonPropertyName("sources")]
    public IReadOnlyList<ToriiContractSourceFile> Sources
    {
        get => ToriiListSnapshots.CopyRequired(sources);
        init => sources = ToriiListSnapshots.CopyNonNullItems(value, nameof(Sources)) ?? Array.Empty<ToriiContractSourceFile>();
    }

    [JsonPropertyName("exports")]
    public required IReadOnlyList<string> Exports
    {
        get => ToriiListSnapshots.CopyRequired(exports);
        init => exports = ToriiListSnapshots.CopyNonNullItems(value, nameof(Exports)) ?? Array.Empty<string>();
    }

    [JsonPropertyName("imports")]
    public required IReadOnlyList<ToriiContractSourceImport> Imports
    {
        get => ToriiListSnapshots.CopyRequired(imports);
        init => imports = ToriiListSnapshots.CopyNonNullItems(value, nameof(Imports)) ?? Array.Empty<ToriiContractSourceImport>();
    }
}

/// <summary>Complete immutable compiled interface owned by one source package.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record class ToriiContractSourceArtifact
{
    [JsonRequired]
    [JsonPropertyName("source_name")]
    public string SourceName { get; init; } = string.Empty;

    private byte[] artifact = Array.Empty<byte>();
    [JsonRequired]
    [JsonPropertyName("artifact")]
    public IReadOnlyList<byte> Artifact
    {
        get => Array.AsReadOnly((byte[])artifact.Clone());
        init => artifact = value?.ToArray() ?? throw new ArgumentNullException(nameof(Artifact));
    }
}

public sealed record class ToriiContractSourceFile
{
    [JsonRequired]
    [JsonPropertyName("source_name")]
    public string SourceName { get; init; } = string.Empty;

    [JsonRequired]
    [JsonPropertyName("source_text")]
    public string SourceText { get; init; } = string.Empty;
}

[JsonConverter(typeof(ToriiContractVerifiedSourceJobJsonConverter))]
public sealed record class ToriiContractVerifiedSourceJob
{
    [JsonPropertyName("network_id")]
    public required NetworkId NetworkId { get; init; }

    [JsonPropertyName("artifact_id")]
    public required ContractArtifactId ArtifactId { get; init; }

    private string jobId = string.Empty;
    private string codeHash = string.Empty;
    private string status = string.Empty;
    private string submittedAt = string.Empty;
    private string? completedAt;
    private string? message;
    private string? actualCodeHash;

    [JsonPropertyName("job_id")]
    public string JobId
    {
        get => jobId;
        init => jobId = ToriiContractMetadataDirectMetadata.RequireExactTokenText(value, nameof(JobId));
    }

    [JsonPropertyName("code_hash")]
    public string CodeHash
    {
        get => codeHash;
        init => codeHash = ToriiContractMetadataDirectMetadata.RequireExactSizedHex(value, nameof(CodeHash));
    }

    [JsonPropertyName("status")]
    public string Status
    {
        get => status;
        init => status = ToriiContractMetadataDirectMetadata.RequireExactTokenText(value, nameof(Status));
    }

    [JsonPropertyName("submitted_at")]
    public string SubmittedAt
    {
        get => submittedAt;
        init => submittedAt = ToriiContractMetadataDirectMetadata.RequireExactNonEmptyText(
            value,
            nameof(SubmittedAt));
    }

    [JsonPropertyName("completed_at")]
    public string? CompletedAt
    {
        get => completedAt;
        init => completedAt = ToriiContractMetadataDirectMetadata.RequireOptionalExactNonEmptyText(
            value,
            nameof(CompletedAt));
    }

    [JsonPropertyName("message")]
    public string? Message
    {
        get => message;
        init => message = ToriiContractMetadataDirectMetadata.RequireOptionalExactNonEmptyText(
            value,
            nameof(Message));
    }

    [JsonPropertyName("actual_code_hash")]
    public string? ActualCodeHash
    {
        get => actualCodeHash;
        init => actualCodeHash = ToriiContractMetadataDirectMetadata.RequireOptionalExactSizedHex(
            value,
            nameof(ActualCodeHash));
    }

    [JsonPropertyName("verified_source_ref")]
    public ToriiContractVerifiedSourceReference? VerifiedSourceReference { get; init; }
}

public sealed record class ToriiMultisigContractCallProposeRequest
{
    private JsonNode? payload;

    [JsonPropertyName("multisig_account_id")]
    public string? MultisigAccountId { get; init; }

    [JsonPropertyName("multisig_account_alias")]
    public string? MultisigAccountAlias { get; init; }

    [JsonPropertyName("signer_account_id")]
    public string SignerAccountId { get; init; } = string.Empty;

    [JsonPropertyName("public_key_hex")]
    public string? PublicKeyHex { get; init; }

    [JsonPropertyName("signature_b64")]
    public string? SignatureBase64 { get; init; }

    [JsonPropertyName("creation_time_ms")]
    public ulong? CreationTimeMilliseconds { get; init; }

    [JsonPropertyName("contract_address")]
    public string? ContractAddress { get; init; }

    [JsonPropertyName("contract_alias")]
    public string? ContractAlias { get; init; }

    [JsonPropertyName("entrypoint")]
    public string Entrypoint { get; init; } = string.Empty;

    [JsonPropertyName("payload")]
    public JsonNode? Payload
    {
        get => ToriiJsonSnapshots.Copy(payload);
        init => payload = ToriiJsonSnapshots.Copy(value);
    }

    /// <summary>Exact local-only intent required to accept an unsigned transaction draft.</summary>
    [JsonIgnore]
    public ToriiContractCallDraftIntent? DraftIntent { get; init; }

    [JsonPropertyName("fee_payment")]
    public FeePaymentIntent FeePayment { get; init; } = null!;
}

public sealed record class ToriiMultisigContractCallApproveRequest
{
    [JsonPropertyName("multisig_account_id")]
    public string? MultisigAccountId { get; init; }

    [JsonPropertyName("multisig_account_alias")]
    public string? MultisigAccountAlias { get; init; }

    [JsonPropertyName("signer_account_id")]
    public string SignerAccountId { get; init; } = string.Empty;

    [JsonPropertyName("public_key_hex")]
    public string? PublicKeyHex { get; init; }

    [JsonPropertyName("signature_b64")]
    public string? SignatureBase64 { get; init; }

    [JsonPropertyName("creation_time_ms")]
    public ulong? CreationTimeMilliseconds { get; init; }

    [JsonPropertyName("fee_payment")]
    public FeePaymentIntent FeePayment { get; init; } = null!;

    [JsonPropertyName("proposal_id")]
    public string? ProposalId { get; init; }

    [JsonPropertyName("instructions_hash")]
    public string? InstructionsHash { get; init; }
}

public sealed record class ToriiMultisigApproveRequest
{
    [JsonPropertyName("multisig_account_id")]
    public string? MultisigAccountId { get; init; }

    [JsonPropertyName("multisig_account_alias")]
    public string? MultisigAccountAlias { get; init; }

    [JsonPropertyName("signer_account_id")]
    public string SignerAccountId { get; init; } = string.Empty;

    [JsonPropertyName("public_key_hex")]
    public string? PublicKeyHex { get; init; }

    [JsonPropertyName("signature_b64")]
    public string? SignatureBase64 { get; init; }

    [JsonPropertyName("creation_time_ms")]
    public ulong? CreationTimeMilliseconds { get; init; }

    [JsonPropertyName("fee_payment")]
    public FeePaymentIntent FeePayment { get; init; } = null!;

    [JsonPropertyName("proposal_id")]
    public string? ProposalId { get; init; }

    [JsonPropertyName("instructions_hash")]
    public string? InstructionsHash { get; init; }
}

public sealed record class ToriiMultisigCancelRequest
{
    [JsonPropertyName("multisig_account_id")]
    public string? MultisigAccountId { get; init; }

    [JsonPropertyName("multisig_account_alias")]
    public string? MultisigAccountAlias { get; init; }

    [JsonPropertyName("signer_account_id")]
    public string SignerAccountId { get; init; } = string.Empty;

    [JsonPropertyName("public_key_hex")]
    public string? PublicKeyHex { get; init; }

    [JsonPropertyName("signature_b64")]
    public string? SignatureBase64 { get; init; }

    [JsonPropertyName("creation_time_ms")]
    public ulong? CreationTimeMilliseconds { get; init; }

    [JsonPropertyName("fee_payment")]
    public FeePaymentIntent FeePayment { get; init; } = null!;

    [JsonPropertyName("proposal_id")]
    public string? ProposalId { get; init; }

    [JsonPropertyName("instructions_hash")]
    public string? InstructionsHash { get; init; }
}

[JsonConverter(typeof(ToriiMultisigResponseJsonConverter))]
public sealed record class ToriiMultisigResponse
{
    private bool ok;
    private string resolvedMultisigAccountId = string.Empty;
    private string? proposalId;
    private string? instructionsHash;
    private string? transactionHashHex;
    private string? executedTransactionHashHex;
    private ulong? creationTimeMilliseconds;
    private string? transactionPayloadBase64, signingMessageBase64;

    [JsonPropertyName("ok")]
    public bool Ok
    {
        get => ok;
        init => ok = ToriiMultisigDirectMetadata.RequireTrue(value, nameof(Ok));
    }

    [JsonPropertyName("resolved_multisig_account_id")]
    public string ResolvedMultisigAccountId
    {
        get => resolvedMultisigAccountId;
        init => resolvedMultisigAccountId = ToriiMultisigDirectMetadata.RequireCanonicalAccountId(
            value,
            nameof(ResolvedMultisigAccountId));
    }

    [JsonPropertyName("submitted")]
    public bool Submitted { get; init; }

    [JsonPropertyName("proposal_id")]
    public string? ProposalId
    {
        get => proposalId;
        init => proposalId = ToriiMultisigDirectMetadata.RequireOptionalExactSizedHex(
            value,
            nameof(ProposalId));
    }

    [JsonPropertyName("instructions_hash")]
    public string? InstructionsHash
    {
        get => instructionsHash;
        init => instructionsHash = ToriiMultisigDirectMetadata.RequireOptionalExactSizedHex(
            value,
            nameof(InstructionsHash));
    }

    [JsonPropertyName("tx_hash_hex")]
    public string? TransactionHashHex
    {
        get => transactionHashHex;
        init => transactionHashHex = ToriiMultisigDirectMetadata.RequireOptionalTransactionHashHex(
            value,
            nameof(TransactionHashHex));
    }

    [JsonPropertyName("executed_tx_hash_hex")]
    public string? ExecutedTransactionHashHex
    {
        get => executedTransactionHashHex;
        init => executedTransactionHashHex = ToriiMultisigDirectMetadata.RequireOptionalTransactionHashHex(
            value,
            nameof(ExecutedTransactionHashHex));
    }

    [JsonPropertyName("creation_time_ms")]
    public ulong? CreationTimeMilliseconds
    {
        get => creationTimeMilliseconds;
        init => creationTimeMilliseconds = ToriiMultisigDirectMetadata.RequireOptionalPositive(
            value,
            nameof(CreationTimeMilliseconds));
    }

    [JsonPropertyName("fee_payment")]
    public FeePaymentIntent FeePayment { get; init; } = null!;

    [JsonPropertyName("transaction_payload_b64")]
    public string? TransactionPayloadBase64
    {
        get => transactionPayloadBase64;
        init => transactionPayloadBase64 = ToriiMultisigDirectMetadata.RequireOptionalBase64(value, nameof(TransactionPayloadBase64));
    }
    [JsonPropertyName("signing_message_b64")]
    public string? SigningMessageBase64
    {
        get => signingMessageBase64;
        init => signingMessageBase64 = ToriiMultisigDirectMetadata.RequireOptionalBase64(
            value,
            nameof(SigningMessageBase64));
    }
}

public sealed record class ToriiMultisigCancelResponse
{
    [JsonPropertyName("ok")]
    public bool Ok { get; init; }

    [JsonPropertyName("resolved_multisig_account_id")]
    public string ResolvedMultisigAccountId { get; init; } = string.Empty;

    [JsonPropertyName("submitted")]
    public bool Submitted { get; init; }

    [JsonPropertyName("action")]
    public string Action { get; init; } = string.Empty;

    [JsonPropertyName("target_proposal_id")]
    public string TargetProposalId { get; init; } = string.Empty;

    [JsonPropertyName("target_instructions_hash")]
    public string TargetInstructionsHash { get; init; } = string.Empty;

    [JsonPropertyName("cancel_proposal_id")]
    public string CancelProposalId { get; init; } = string.Empty;

    [JsonPropertyName("cancel_instructions_hash")]
    public string CancelInstructionsHash { get; init; } = string.Empty;

    [JsonPropertyName("tx_hash_hex")]
    public string? TransactionHashHex { get; init; }

    [JsonPropertyName("executed_tx_hash_hex")]
    public string? ExecutedTransactionHashHex { get; init; }

    [JsonPropertyName("creation_time_ms")]
    public ulong? CreationTimeMilliseconds { get; init; }

    [JsonRequired, JsonPropertyName("fee_payment")]
    public FeePaymentIntent FeePayment { get; init; } = null!;

    [JsonPropertyName("transaction_payload_b64")]
    public string? TransactionPayloadBase64 { get; init; }
    [JsonPropertyName("signing_message_b64")]
    public string? SigningMessageBase64 { get; init; }
}

[JsonConverter(typeof(ToriiMultisigContractCallResponseJsonConverter))]
public sealed record class ToriiMultisigContractCallResponse
{
    private bool ok;
    private string resolvedMultisigAccountId = string.Empty;
    private string? proposalId;
    private string? instructionsHash;
    private string? transactionHashHex;
    private string? executedTransactionHashHex;
    private ulong? creationTimeMilliseconds;
    private string? transactionPayloadBase64, signingMessageBase64;

    [JsonPropertyName("ok")]
    public bool Ok
    {
        get => ok;
        init => ok = ToriiMultisigDirectMetadata.RequireTrue(value, nameof(Ok));
    }

    [JsonPropertyName("resolved_multisig_account_id")]
    public string ResolvedMultisigAccountId
    {
        get => resolvedMultisigAccountId;
        init => resolvedMultisigAccountId = ToriiMultisigDirectMetadata.RequireCanonicalAccountId(
            value,
            nameof(ResolvedMultisigAccountId));
    }

    [JsonPropertyName("submitted")]
    public bool Submitted { get; init; }

    [JsonPropertyName("proposal_id")]
    public string? ProposalId
    {
        get => proposalId;
        init => proposalId = ToriiMultisigDirectMetadata.RequireOptionalExactSizedHex(
            value,
            nameof(ProposalId));
    }

    [JsonPropertyName("instructions_hash")]
    public string? InstructionsHash
    {
        get => instructionsHash;
        init => instructionsHash = ToriiMultisigDirectMetadata.RequireOptionalExactSizedHex(
            value,
            nameof(InstructionsHash));
    }

    [JsonPropertyName("tx_hash_hex")]
    public string? TransactionHashHex
    {
        get => transactionHashHex;
        init => transactionHashHex = ToriiMultisigDirectMetadata.RequireOptionalTransactionHashHex(
            value,
            nameof(TransactionHashHex));
    }

    [JsonPropertyName("executed_tx_hash_hex")]
    public string? ExecutedTransactionHashHex
    {
        get => executedTransactionHashHex;
        init => executedTransactionHashHex = ToriiMultisigDirectMetadata.RequireOptionalTransactionHashHex(
            value,
            nameof(ExecutedTransactionHashHex));
    }

    [JsonPropertyName("creation_time_ms")]
    public ulong? CreationTimeMilliseconds
    {
        get => creationTimeMilliseconds;
        init => creationTimeMilliseconds = ToriiMultisigDirectMetadata.RequireOptionalPositive(
            value,
            nameof(CreationTimeMilliseconds));
    }

    [JsonPropertyName("fee_payment")]
    public FeePaymentIntent FeePayment { get; init; } = null!;

    [JsonPropertyName("transaction_payload_b64")]
    public string? TransactionPayloadBase64
    {
        get => transactionPayloadBase64;
        init => transactionPayloadBase64 = ToriiMultisigDirectMetadata.RequireOptionalBase64(value, nameof(TransactionPayloadBase64));
    }
    [JsonPropertyName("signing_message_b64")]
    public string? SigningMessageBase64
    {
        get => signingMessageBase64;
        init => signingMessageBase64 = ToriiMultisigDirectMetadata.RequireOptionalBase64(
            value,
            nameof(SigningMessageBase64));
    }
}

internal static class ToriiMultisigDirectMetadata
{
    internal static bool RequireTrue(bool value, string paramName)
    {
        if (!value)
        {
            throw new ArgumentException("Value must be true.", paramName);
        }

        return value;
    }

    internal static string RequireCanonicalAccountId(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, paramName);
    }

    internal static string? RequireOptionalExactSizedHex(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireOptionalExactSizedHex(value, paramName, 32);
    }

    internal static string? RequireOptionalTransactionHashHex(string? value, string paramName)
    {
        if (value is null || value.Length == 0)
        {
            return value;
        }

        return ToriiExplorerDirectMetadata.RequireExactSizedHex(value, paramName, 32);
    }

    internal static ulong? RequireOptionalPositive(ulong? value, string paramName)
    {
        if (value == 0)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be positive when provided.");
        }

        return value;
    }

    internal static string? RequireOptionalBase64(string? value, string paramName)
    {
        if (value is null)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value must be a non-empty base64 string.", paramName);
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new ArgumentException("Value must not contain surrounding whitespace.", paramName);
        }

        foreach (var character in value)
        {
            if (char.IsWhiteSpace(character))
            {
                throw new ArgumentException("Value must not contain whitespace.", paramName);
            }

            if (char.IsControl(character))
            {
                throw new ArgumentException("Value must not contain control characters.", paramName);
            }
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(value);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("Value must be valid base64.", paramName, exception);
        }

        if (bytes.Length == 0)
        {
            throw new ArgumentException("Value must not decode to empty bytes.", paramName);
        }

        if (!string.Equals(Convert.ToBase64String(bytes), value, StringComparison.Ordinal))
        {
            throw new ArgumentException("Value must be canonical base64 text.", paramName);
        }

        return value;
    }
}

[JsonConverter(typeof(ToriiRuntimeUpgradeCountersJsonConverter))]
public sealed record class ToriiRuntimeUpgradeCounters
{
    private long proposed;
    private long activated;
    private long canceled;

    [JsonPropertyName("proposed")]
    public long Proposed
    {
        get => proposed;
        init => proposed = ToriiRuntimeDirectMetadata.RequireNonNegativeInt64(value, nameof(Proposed));
    }

    [JsonPropertyName("activated")]
    public long Activated
    {
        get => activated;
        init => activated = ToriiRuntimeDirectMetadata.RequireNonNegativeInt64(value, nameof(Activated));
    }

    [JsonPropertyName("canceled")]
    public long Canceled
    {
        get => canceled;
        init => canceled = ToriiRuntimeDirectMetadata.RequireNonNegativeInt64(value, nameof(Canceled));
    }
}

[JsonConverter(typeof(ToriiRuntimeMetricsJsonConverter))]
public sealed record class ToriiRuntimeMetrics
{
    private int abiVersion = 1;
    private ToriiRuntimeUpgradeCounters upgradeEventsTotal = new();

    [JsonPropertyName("abi_version")]
    public int AbiVersion
    {
        get => abiVersion;
        init => abiVersion = ToriiRuntimeDirectMetadata.RequireAbiVersionV1(value, nameof(AbiVersion));
    }

    [JsonPropertyName("upgrade_events_total")]
    public ToriiRuntimeUpgradeCounters UpgradeEventsTotal
    {
        get => upgradeEventsTotal;
        init => upgradeEventsTotal = ToriiRuntimeDirectMetadata.RequireObject(value, nameof(UpgradeEventsTotal));
    }
}

[JsonConverter(typeof(ToriiRuntimeAbiActiveJsonConverter))]
public sealed record class ToriiRuntimeAbiActive
{
    private int abiVersion = 1;

    [JsonPropertyName("abi_version")]
    public int AbiVersion
    {
        get => abiVersion;
        init => abiVersion = ToriiRuntimeDirectMetadata.RequireAbiVersionV1(value, nameof(AbiVersion));
    }
}

[JsonConverter(typeof(ToriiRuntimeAbiHashJsonConverter))]
public sealed record class ToriiRuntimeAbiHash
{
    private string policy = "V1";
    private string abiHashHex = string.Empty;

    [JsonPropertyName("policy")]
    public string Policy
    {
        get => policy;
        init => policy = ToriiRuntimeDirectMetadata.RequirePolicyV1(value, nameof(Policy));
    }

    [JsonPropertyName("abi_hash_hex")]
    public string AbiHashHex
    {
        get => abiHashHex;
        init => abiHashHex = ToriiRuntimeDirectMetadata.RequireExactSizedHex(value, nameof(AbiHashHex));
    }
}

internal static class ToriiRuntimeDirectMetadata
{
    internal static T RequireObject<T>(T? value, string paramName)
        where T : class
    {
        return value ?? throw new ArgumentNullException(paramName, "Value must not be null.");
    }

    internal static int RequireAbiVersionV1(int value, string paramName)
    {
        if (value < 0)
        {
            throw new ArgumentOutOfRangeException(paramName, value, "Value must be non-negative.");
        }

        if (value != 1)
        {
            throw new ArgumentException("Value must be 1.", paramName);
        }

        return value;
    }

    internal static long RequireNonNegativeInt64(long value, string paramName)
    {
        if (value < 0)
        {
            throw new ArgumentOutOfRangeException(paramName, value, "Value must be non-negative.");
        }

        return value;
    }

    internal static string RequirePolicyV1(string? value, string paramName)
    {
        var exact = ToriiExplorerDirectMetadata.RequireExactTokenText(value, paramName);
        if (!string.Equals(exact, "V1", StringComparison.Ordinal))
        {
            throw new ArgumentException("Value must be V1.", paramName);
        }

        return exact;
    }

    internal static string RequireExactSizedHex(string? value, string paramName)
    {
        return ToriiExplorerDirectMetadata.RequireExactSizedHex(value, paramName, 32);
    }
}
