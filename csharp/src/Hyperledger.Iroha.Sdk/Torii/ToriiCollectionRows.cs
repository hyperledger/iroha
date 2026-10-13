using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Hyperledger.Iroha.Numeric;

namespace Hyperledger.Iroha.Torii;

/// <summary>A row of the domains collection (<c>/v1/domains</c>).</summary>
public sealed class DomainRow
{
    /// <summary>The domain id, e.g. <c>wonderland.universal</c>.</summary>
    public required string Id { get; init; }

    /// <summary>The owning account (canonical I105 literal).</summary>
    public string? OwnedBy { get; init; }

    /// <summary>The logo reference, when set.</summary>
    public string? Logo { get; init; }

    /// <summary>Domain metadata.</summary>
    public JsonObject? Metadata { get; init; }

    internal static DomainRow Read(JsonElement row, string context) => new()
    {
        Id = RowJson.RequiredString(row, "id", context),
        OwnedBy = RowJson.OptionalString(row, "owned_by", context),
        Logo = RowJson.OptionalString(row, "logo", context),
        Metadata = RowJson.OptionalObject(row, "metadata", context),
    };
}

/// <summary>A row of the accounts collection (<c>/v1/accounts</c>).</summary>
public sealed class AccountRow
{
    /// <summary>The canonical I105 account id.</summary>
    public required string Id { get; init; }

    /// <summary>The account label, when assigned.</summary>
    public string? Label { get; init; }

    /// <summary>The universal account id, when bound.</summary>
    public string? Uaid { get; init; }

    /// <summary>Account metadata.</summary>
    public JsonObject? Metadata { get; init; }

    internal static AccountRow Read(JsonElement row, string context) => new()
    {
        Id = RowJson.RequiredString(row, "id", context),
        Label = RowJson.OptionalString(row, "label", context),
        Uaid = RowJson.OptionalString(row, "uaid", context),
        Metadata = RowJson.OptionalObject(row, "metadata", context),
    };
}

/// <summary>The alias bound to an asset definition.</summary>
public sealed class AssetAliasBindingRow
{
    /// <summary>The alias literal.</summary>
    public string? Alias { get; init; }

    /// <summary>The lease status.</summary>
    public string? Status { get; init; }

    /// <summary>Lease expiry, in Unix milliseconds.</summary>
    public ulong? LeaseExpiryMs { get; init; }

    /// <summary>End of the grace period, in Unix milliseconds.</summary>
    public ulong? GraceUntilMs { get; init; }

    /// <summary>When the alias was bound, in Unix milliseconds.</summary>
    public ulong? BoundAtMs { get; init; }

    internal static AssetAliasBindingRow? ReadOptional(JsonElement row, string name, string context)
    {
        if (!row.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        var nested = $"{context}.{name}";
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException($"{nested} must be an object or null.");
        }

        return new AssetAliasBindingRow
        {
            Alias = RowJson.OptionalString(value, "alias", nested),
            Status = RowJson.OptionalString(value, "status", nested),
            LeaseExpiryMs = RowJson.OptionalUInt64(value, "lease_expiry_ms", nested),
            GraceUntilMs = RowJson.OptionalUInt64(value, "grace_until_ms", nested),
            BoundAtMs = RowJson.OptionalUInt64(value, "bound_at_ms", nested),
        };
    }
}

/// <summary>A row of the asset definitions collection (<c>/v1/assets/definitions</c>).</summary>
public sealed class AssetDefinitionRow
{
    /// <summary>The Base58 asset definition id.</summary>
    public required string Id { get; init; }

    /// <summary>The display name.</summary>
    public string? Name { get; init; }

    /// <summary>The bound alias literal, when any.</summary>
    public string? Alias { get; init; }

    /// <summary>The owning account.</summary>
    public string? OwnedBy { get; init; }

    /// <summary>The owning domain.</summary>
    public string? OwningDomain { get; init; }

    /// <summary>The mintability policy.</summary>
    public string? Mintable { get; init; }

    /// <summary>The description, when set.</summary>
    public string? Description { get; init; }

    /// <summary>The logo reference, when set.</summary>
    public string? Logo { get; init; }

    /// <summary>The numeric specification of the asset.</summary>
    public JsonNode? Spec { get; init; }

    /// <summary>The balance scope policy.</summary>
    public JsonNode? BalanceScopePolicy { get; init; }

    /// <summary>The alias binding, when an alias is bound.</summary>
    public AssetAliasBindingRow? AliasBinding { get; init; }

    /// <summary>Asset definition metadata.</summary>
    public JsonObject? Metadata { get; init; }

    internal static AssetDefinitionRow Read(JsonElement row, string context) => new()
    {
        Id = RowJson.RequiredString(row, "id", context),
        Name = RowJson.OptionalString(row, "name", context),
        Alias = RowJson.OptionalString(row, "alias", context),
        OwnedBy = RowJson.OptionalString(row, "owned_by", context),
        OwningDomain = RowJson.OptionalString(row, "owning_domain", context),
        Mintable = RowJson.OptionalString(row, "mintable", context),
        Description = RowJson.OptionalString(row, "description", context),
        Logo = RowJson.OptionalString(row, "logo", context),
        Spec = RowJson.OptionalNode(row, "spec"),
        BalanceScopePolicy = RowJson.OptionalNode(row, "balance_scope_policy"),
        AliasBinding = AssetAliasBindingRow.ReadOptional(row, "alias_binding", context),
        Metadata = RowJson.OptionalObject(row, "metadata", context),
    };
}

/// <summary>A row of the NFTs collection (<c>/v1/nfts</c>).</summary>
public sealed class NftRow
{
    /// <summary>The NFT id, <c>name$domain.dataspace</c>.</summary>
    public required string Id { get; init; }

    /// <summary>The owning account.</summary>
    public string? OwnedBy { get; init; }

    /// <summary>The NFT content.</summary>
    public JsonObject? Metadata { get; init; }

    internal static NftRow Read(JsonElement row, string context) => new()
    {
        Id = RowJson.RequiredString(row, "id", context),
        OwnedBy = RowJson.OptionalString(row, "owned_by", context),
        Metadata = RowJson.OptionalObject(row, "metadata", context),
    };
}

/// <summary>A row of the RWA lots collection (<c>/v1/rwas</c>).</summary>
public sealed class RwaRow
{
    /// <summary>The lot id.</summary>
    public required string Id { get; init; }

    /// <summary>The owning account.</summary>
    public string? OwnedBy { get; init; }

    /// <summary>The primary external reference.</summary>
    public string? PrimaryReference { get; init; }

    /// <summary>The lifecycle status.</summary>
    public string? Status { get; init; }

    /// <summary>The exact lot quantity.</summary>
    public NumericV1.QuantityValue? Quantity { get; init; }

    /// <summary>Whether the lot is frozen.</summary>
    public bool? IsFrozen { get; init; }

    /// <summary>Lot metadata.</summary>
    public JsonObject? Metadata { get; init; }

    internal static RwaRow Read(JsonElement row, string context) => new()
    {
        Id = RowJson.RequiredString(row, "id", context),
        OwnedBy = RowJson.OptionalString(row, "owned_by", context),
        PrimaryReference = RowJson.OptionalString(row, "primary_reference", context),
        Status = RowJson.OptionalString(row, "status", context),
        Quantity = RowJson.OptionalQuantity(row, "quantity", context),
        IsFrozen = RowJson.OptionalBoolean(row, "is_frozen", context),
        Metadata = RowJson.OptionalObject(row, "metadata", context),
    };
}

/// <summary>A row of an account's assets (<c>/v1/accounts/{account_id}/assets</c>).</summary>
/// <remarks><c>asset</c>, <c>scope</c>, <c>account_id</c> and <c>quantity</c> identify the balance and are always present.</remarks>
public sealed class AccountAssetRow
{
    /// <summary>The asset (definition) id.</summary>
    public required string Asset { get; init; }

    /// <summary>The asset display name.</summary>
    public string? AssetName { get; init; }

    /// <summary>The asset alias, when bound.</summary>
    public string? AssetAlias { get; init; }

    /// <summary>The balance scope.</summary>
    public required string Scope { get; init; }

    /// <summary>The holding account.</summary>
    public required string AccountId { get; init; }

    /// <summary>The exact balance.</summary>
    public required NumericV1.QuantityValue Quantity { get; init; }

    internal static AccountAssetRow Read(JsonElement row, string context) => new()
    {
        Asset = RowJson.RequiredString(row, "asset", context),
        AssetName = RowJson.OptionalString(row, "asset_name", context),
        AssetAlias = RowJson.OptionalString(row, "asset_alias", context),
        Scope = RowJson.RequiredString(row, "scope", context),
        AccountId = RowJson.RequiredString(row, "account_id", context),
        Quantity = RowJson.RequiredQuantity(row, "quantity", context),
    };
}

/// <summary>A row of an asset's holders (<c>/v1/assets/{definition_id}/holders</c>).</summary>
/// <remarks><c>account_id</c>, <c>asset</c>, <c>scope</c> and <c>quantity</c> identify the balance and are always present.</remarks>
public sealed class AssetHolderRow
{
    /// <summary>The holding account.</summary>
    public required string AccountId { get; init; }

    /// <summary>The asset (definition) id.</summary>
    public required string Asset { get; init; }

    /// <summary>The asset alias, when bound.</summary>
    public string? AssetAlias { get; init; }

    /// <summary>The balance scope.</summary>
    public required string Scope { get; init; }

    /// <summary>The exact balance.</summary>
    public required NumericV1.QuantityValue Quantity { get; init; }

    internal static AssetHolderRow Read(JsonElement row, string context) => new()
    {
        AccountId = RowJson.RequiredString(row, "account_id", context),
        Asset = RowJson.RequiredString(row, "asset", context),
        AssetAlias = RowJson.OptionalString(row, "asset_alias", context),
        Scope = RowJson.RequiredString(row, "scope", context),
        Quantity = RowJson.RequiredQuantity(row, "quantity", context),
    };
}

/// <summary>
/// A committed transaction, from <c>/v1/transactions</c> or <c>/v1/accounts/{account_id}/transactions</c>.
/// </summary>
/// <remarks>
/// Rows arrive newest first: by <see cref="BlockHeight"/> descending, then <see cref="BlockIndex"/>
/// descending. <c>entrypoint_hash</c>, <c>block_height</c> and <c>block_index</c> are always present;
/// every other field may be <see langword="null"/> or absent.
/// </remarks>
public sealed class TransactionRow
{
    /// <summary>The entrypoint hash identifying the transaction (lowercase hex).</summary>
    public required string EntrypointHash { get; init; }

    /// <summary>The height of the block that committed the transaction.</summary>
    public required ulong BlockHeight { get; init; }

    /// <summary>The transaction's position in its block.</summary>
    public required ulong BlockIndex { get; init; }

    /// <summary>The hash of the committing block.</summary>
    public string? BlockHash { get; init; }

    /// <summary>The submitting account, when the entrypoint has one.</summary>
    public string? Authority { get; init; }

    /// <summary>The submission time, in Unix milliseconds, when known.</summary>
    public ulong? TimestampMs { get; init; }

    /// <summary>The kind of entrypoint, for example an external transaction or a time trigger.</summary>
    public string? EntrypointKind { get; init; }

    /// <summary>Whether execution succeeded.</summary>
    public bool? ResultOk { get; init; }

    /// <summary>
    /// The assets the transaction touched. Filters match list fields element-wise:
    /// <c>asset_ids = "…"</c> keeps rows where any element matches.
    /// </summary>
    public ImmutableArray<string> AssetIds { get; init; } = [];

    /// <summary>The definitions of <see cref="AssetIds"/>; matched element-wise like <see cref="AssetIds"/>.</summary>
    public ImmutableArray<string> AssetDefinitionIds { get; init; } = [];

    /// <summary>Transaction metadata.</summary>
    public JsonObject? Metadata { get; init; }

    internal static TransactionRow Read(JsonElement row, string context) => new()
    {
        EntrypointHash = RowJson.RequiredString(row, "entrypoint_hash", context),
        BlockHeight = RowJson.RequiredUInt64(row, "block_height", context),
        BlockIndex = RowJson.RequiredUInt64(row, "block_index", context),
        BlockHash = RowJson.OptionalString(row, "block_hash", context),
        Authority = RowJson.OptionalString(row, "authority", context),
        TimestampMs = RowJson.OptionalUInt64(row, "timestamp_ms", context),
        EntrypointKind = RowJson.OptionalString(row, "entrypoint_kind", context),
        ResultOk = RowJson.OptionalBoolean(row, "result_ok", context),
        AssetIds = RowJson.OptionalStringList(row, "asset_ids", context),
        AssetDefinitionIds = RowJson.OptionalStringList(row, "asset_definition_ids", context),
        Metadata = RowJson.OptionalObject(row, "metadata", context),
    };
}

/// <summary>One leg of a repo agreement.</summary>
public sealed class RepoLegRow
{
    /// <summary>The leg's asset definition.</summary>
    public string? AssetDefinitionId { get; init; }

    /// <summary>The exact leg quantity.</summary>
    public NumericV1.QuantityValue? Quantity { get; init; }

    internal static RepoLegRow? ReadOptional(JsonElement row, string name, string context)
    {
        if (!row.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        var nested = $"{context}.{name}";
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException($"{nested} must be an object or null.");
        }

        return new RepoLegRow
        {
            AssetDefinitionId = RowJson.OptionalString(value, "asset_definition_id", nested),
            Quantity = RowJson.OptionalQuantity(value, "quantity", nested),
        };
    }
}

/// <summary>Governance parameters of a repo agreement.</summary>
public sealed class RepoGovernanceRow
{
    /// <summary>The collateral haircut, in basis points.</summary>
    public ulong? HaircutBps { get; init; }

    /// <summary>The margin check frequency, in seconds.</summary>
    public ulong? MarginFrequencySecs { get; init; }

    /// <summary>Whether the initiator may repay before maturity with interest accrued to the block time.</summary>
    public bool? AllowEarlyRepayment { get; init; }

    internal static RepoGovernanceRow? ReadOptional(JsonElement row, string name, string context)
    {
        if (!row.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        var nested = $"{context}.{name}";
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException($"{nested} must be an object or null.");
        }

        return new RepoGovernanceRow
        {
            HaircutBps = RowJson.OptionalUInt64(value, "haircut_bps", nested),
            MarginFrequencySecs = RowJson.OptionalUInt64(value, "margin_frequency_secs", nested),
            AllowEarlyRepayment = RowJson.OptionalBoolean(value, "allow_early_repayment", nested),
        };
    }
}

/// <summary>A row of the repo agreements collection (<c>/v1/repo/agreements</c>).</summary>
public sealed class RepoAgreementRow
{
    /// <summary>The agreement id.</summary>
    public required string Id { get; init; }

    /// <summary>The initiating account.</summary>
    public string? Initiator { get; init; }

    /// <summary>The counterparty account.</summary>
    public string? Counterparty { get; init; }

    /// <summary>The custodian account, when any.</summary>
    public string? Custodian { get; init; }

    /// <summary>The lifecycle status.</summary>
    public string? Status { get; init; }

    /// <summary>Where the cash leg is sourced from.</summary>
    public string? CashSource { get; init; }

    /// <summary>The cash leg.</summary>
    public RepoLegRow? CashLeg { get; init; }

    /// <summary>The collateral leg.</summary>
    public RepoLegRow? CollateralLeg { get; init; }

    /// <summary>The asset holding the collateral in custody.</summary>
    public string? CollateralCustodyAsset { get; init; }

    /// <summary>The repo rate, in basis points.</summary>
    public ulong? RateBps { get; init; }

    /// <summary>Maturity, in Unix milliseconds.</summary>
    public ulong? MaturityTimestampMs { get; init; }

    /// <summary>Initiation, in Unix milliseconds.</summary>
    public ulong? InitiatedTimestampMs { get; init; }

    /// <summary>The last margin check, in Unix milliseconds.</summary>
    public ulong? LastMarginCheckTimestampMs { get; init; }

    /// <summary>Settlement, in Unix milliseconds.</summary>
    public ulong? SettlementTimestampMs { get; init; }

    /// <summary>Governance parameters.</summary>
    public RepoGovernanceRow? Governance { get; init; }

    internal static RepoAgreementRow Read(JsonElement row, string context) => new()
    {
        Id = RowJson.RequiredString(row, "id", context),
        Initiator = RowJson.OptionalString(row, "initiator", context),
        Counterparty = RowJson.OptionalString(row, "counterparty", context),
        Custodian = RowJson.OptionalString(row, "custodian", context),
        Status = RowJson.OptionalString(row, "status", context),
        CashSource = RowJson.OptionalString(row, "cash_source", context),
        CashLeg = RepoLegRow.ReadOptional(row, "cash_leg", context),
        CollateralLeg = RepoLegRow.ReadOptional(row, "collateral_leg", context),
        CollateralCustodyAsset = RowJson.OptionalString(row, "collateral_custody_asset", context),
        RateBps = RowJson.OptionalUInt64(row, "rate_bps", context),
        MaturityTimestampMs = RowJson.OptionalUInt64(row, "maturity_timestamp_ms", context),
        InitiatedTimestampMs = RowJson.OptionalUInt64(row, "initiated_timestamp_ms", context),
        LastMarginCheckTimestampMs = RowJson.OptionalUInt64(row, "last_margin_check_timestamp_ms", context),
        SettlementTimestampMs = RowJson.OptionalUInt64(row, "settlement_timestamp_ms", context),
        Governance = RepoGovernanceRow.ReadOptional(row, "governance", context),
    };
}

/// <summary>Lenient row field readers: unknown fields are ignored, known fields are type-checked.</summary>
/// <summary>A subscription plan collection row.</summary>
public sealed class SubscriptionPlanRow
{
    public required string Id { get; init; }
    public string? Provider { get; init; }
    public JsonNode? Billing { get; init; }
    public JsonNode? Pricing { get; init; }
    internal static SubscriptionPlanRow Read(JsonElement row, string context) => new()
    {
        Id = RowJson.RequiredString(row, "id", context),
        Provider = RowJson.OptionalString(row, "provider", context),
        Billing = RowJson.OptionalNode(row, "billing"),
        Pricing = RowJson.OptionalNode(row, "pricing"),
    };
}

/// <summary>A flattened subscription collection row.</summary>
public sealed class SubscriptionRow
{
    public required string Id { get; init; }
    public string? OwnedBy { get; init; }
    public string? PlanId { get; init; }
    public string? Provider { get; init; }
    public string? Subscriber { get; init; }
    public string? Status { get; init; }
    public ulong? CurrentPeriodStartMs { get; init; }
    public ulong? CurrentPeriodEndMs { get; init; }
    public ulong? NextChargeMs { get; init; }
    public bool? CancelAtPeriodEnd { get; init; }
    public ulong? CancelAtMs { get; init; }
    public ulong? FailureCount { get; init; }
    public JsonNode? UsageAccumulated { get; init; }
    public string? BillingTriggerId { get; init; }
    public JsonObject? Invoice { get; init; }
    public JsonObject? Plan { get; init; }
    internal static SubscriptionRow Read(JsonElement row, string context) => new()
    {
        Id = RowJson.RequiredString(row, "id", context),
        OwnedBy = RowJson.OptionalString(row, "owned_by", context),
        PlanId = RowJson.OptionalString(row, "plan_id", context),
        Provider = RowJson.OptionalString(row, "provider", context),
        Subscriber = RowJson.OptionalString(row, "subscriber", context),
        Status = RowJson.OptionalString(row, "status", context),
        CurrentPeriodStartMs = RowJson.OptionalUInt64(row, "current_period_start_ms", context),
        CurrentPeriodEndMs = RowJson.OptionalUInt64(row, "current_period_end_ms", context),
        NextChargeMs = RowJson.OptionalUInt64(row, "next_charge_ms", context),
        CancelAtPeriodEnd = RowJson.OptionalBoolean(row, "cancel_at_period_end", context),
        CancelAtMs = RowJson.OptionalUInt64(row, "cancel_at_ms", context),
        FailureCount = RowJson.OptionalUInt64(row, "failure_count", context),
        UsageAccumulated = RowJson.OptionalNode(row, "usage_accumulated"),
        BillingTriggerId = RowJson.OptionalString(row, "billing_trigger_id", context),
        Invoice = RowJson.OptionalObject(row, "invoice", context),
        Plan = RowJson.OptionalObject(row, "plan", context),
    };
}

internal static class RowJson
{
    internal static string RequiredString(JsonElement row, string name, string context)
    {
        RequireObject(row, context);
        return row.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()!
            : throw new JsonException($"{context}.{name} must be a string.");
    }

    internal static string? OptionalString(JsonElement row, string name, string context)
    {
        RequireObject(row, context);
        if (!row.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : throw new JsonException($"{context}.{name} must be a string or null.");
    }

    internal static ulong RequiredUInt64(JsonElement row, string name, string context)
    {
        RequireObject(row, context);
        return OptionalUInt64(row, name, context)
            ?? throw new JsonException($"{context}.{name} must be a non-negative integer.");
    }

    internal static ulong? OptionalUInt64(JsonElement row, string name, string context)
    {
        if (!row.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.Number && value.TryGetUInt64(out var number)
            ? number
            : throw new JsonException($"{context}.{name} must be a non-negative integer or null.");
    }

    internal static bool? OptionalBoolean(JsonElement row, string name, string context)
    {
        if (!row.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => throw new JsonException($"{context}.{name} must be a boolean or null."),
        };
    }

    internal static ImmutableArray<string> OptionalStringList(JsonElement row, string name, string context)
    {
        if (!row.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return [];
        }

        if (value.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException($"{context}.{name} must be an array of strings or null.");
        }

        var items = ImmutableArray.CreateBuilder<string>(value.GetArrayLength());
        foreach (var item in value.EnumerateArray())
        {
            items.Add(item.ValueKind == JsonValueKind.String
                ? item.GetString()!
                : throw new JsonException($"{context}.{name}[{items.Count}] must be a string."));
        }

        return items.MoveToImmutable();
    }

    internal static NumericV1.QuantityValue RequiredQuantity(JsonElement row, string name, string context) =>
        OptionalQuantity(row, name, context)
            ?? throw new JsonException($"{context}.{name} must be an exact decimal string.");

    internal static NumericV1.QuantityValue? OptionalQuantity(JsonElement row, string name, string context)
    {
        if (!row.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        var text = value.ValueKind switch
        {
            JsonValueKind.String => value.GetString()!,
            JsonValueKind.Number when value.TryGetUInt64(out var integer) => integer.ToString(CultureInfo.InvariantCulture),
            _ => throw new JsonException($"{context}.{name} must be an exact decimal string."),
        };
        try
        {
            return NumericV1.QuantityValue.Parse(text);
        }
        catch (NumericV1.NumericException exception)
        {
            throw new JsonException($"{context}.{name} must be an exact non-negative decimal: {exception.Message}", exception);
        }
    }

    internal static JsonObject? OptionalObject(JsonElement row, string name, string context)
    {
        if (!row.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.Object
            ? JsonObject.Create(value.Clone())
            : throw new JsonException($"{context}.{name} must be an object or null.");
    }

    internal static JsonNode? OptionalNode(JsonElement row, string name) =>
        row.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null
            ? JsonNode.Parse(value.GetRawText())
            : null;

    private static void RequireObject(JsonElement row, string context)
    {
        if (row.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException($"{context} must be a JSON object.");
        }
    }
}
