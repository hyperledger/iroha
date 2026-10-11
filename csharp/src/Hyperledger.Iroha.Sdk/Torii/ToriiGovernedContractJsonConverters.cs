using System.Text.Json;
using System.Text.Json.Serialization;
using Hyperledger.Iroha.Transactions;

namespace Hyperledger.Iroha.Torii;

internal static class ToriiGovernedContractJson
{
    private static readonly HashSet<string> ResponseFields =
    [
        "found",
        "contract_address",
        "contract_subject_account",
        "dataspace",
        "active",
        "lifecycle",
        "emergency_hold_active",
        "code_hash_hex",
        "abi_hash_hex",
        "public_entrypoints",
    ];

    private static readonly HashSet<string> LifecycleFields =
    [
        "version",
        "origin",
        "origin_account",
        "origin_proposal_content_id_hex",
        "origin_governance_attempt_id_hex",
        "owner",
        "pending_owner",
        "parliament_delegated",
        "active_code_hash_hex",
        "retained_code_hash_hex",
        "revision",
        "emergency_hold",
    ];

    private static readonly HashSet<string> EmergencyHoldFields =
    [
        "incident_digest_hex",
        "proposal_content_id_hex",
        "governance_attempt_id_hex",
        "reason",
        "imposed_at_height",
        "expires_at_height",
    ];

    internal static ToriiGovernedContractResponse ReadResponse(
        ref Utf8JsonReader reader,
        string context)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        var root = RequireObject(document.RootElement, ResponseFields, context);
        var found = RequireBool(root, "found", context);
        var contractAddress = RequireToken(root, "contract_address", context);
        if (!ContractAddressV1.IsCanonical(contractAddress))
        {
            throw new JsonException($"{context}.contract_address must be a canonical V1 `irohac` Bech32m literal.");
        }
        var dataspace = RequireToken(root, "dataspace", context);

        if (!found)
        {
            RequireAbsentFoundFields(root, context);
            return new ToriiGovernedContractResponse
            {
                Found = false,
                ContractAddress = contractAddress,
                Dataspace = dataspace,
            };
        }

        var contractSubjectAccount = RequireCanonicalAccountId(
            RequireToken(root, "contract_subject_account", context),
            $"{context}.contract_subject_account");
        var active = RequireBool(root, "active", context);
        var lifecycle = ReadLifecycle(RequireProperty(root, "lifecycle", context), $"{context}.lifecycle");
        var emergencyHoldActive = RequireBool(root, "emergency_hold_active", context);
        string? codeHashHex = null;
        string? abiHashHex = null;
        IReadOnlyList<string>? publicEntrypoints = null;
        if (active)
        {
            codeHashHex = RequireHash(root, "code_hash_hex", context);
            abiHashHex = RequireHash(root, "abi_hash_hex", context);
            publicEntrypoints = ReadPublicEntrypoints(
                RequireProperty(root, "public_entrypoints", context),
                $"{context}.public_entrypoints");
        }
        else
        {
            RequireAbsent(root, "code_hash_hex", context);
            RequireAbsent(root, "abi_hash_hex", context);
            RequireAbsent(root, "public_entrypoints", context);
        }

        var response = new ToriiGovernedContractResponse
        {
            Found = true,
            ContractAddress = contractAddress,
            ContractSubjectAccount = contractSubjectAccount,
            Dataspace = dataspace,
            Active = active,
            Lifecycle = lifecycle,
            EmergencyHoldActive = emergencyHoldActive,
            CodeHashHex = codeHashHex,
            AbiHashHex = abiHashHex,
            PublicEntrypoints = publicEntrypoints,
        };
        ValidateResponse(response, context);
        return response;
    }

    internal static void ValidateResponse(ToriiGovernedContractResponse? response, string context)
    {
        if (response is null)
        {
            throw new JsonException($"{context} must be an object.");
        }
        if (!ContractAddressV1.IsCanonical(response.ContractAddress))
        {
            throw new JsonException($"{context}.contract_address must be a canonical V1 `irohac` Bech32m literal.");
        }
        ToriiSseEventJson.RequireExactTokenText(response.Dataspace, $"{context}.dataspace");

        if (!response.Found)
        {
            if (response.ContractSubjectAccount is not null
                || response.Active is not null
                || response.Lifecycle is not null
                || response.EmergencyHoldActive is not null
                || response.CodeHashHex is not null
                || response.AbiHashHex is not null
                || response.PublicEntrypoints is not null)
            {
                throw new JsonException($"{context} missing shape must not contain found-contract fields.");
            }
            return;
        }

        RequireCanonicalAccountId(
            response.ContractSubjectAccount,
            $"{context}.contract_subject_account");
        if (response.Active is null
            || response.Lifecycle is null
            || response.EmergencyHoldActive is null)
        {
            throw new JsonException($"{context} found shape requires active, lifecycle, and emergency_hold_active.");
        }
        ValidateLifecycle(response.Lifecycle, $"{context}.lifecycle");
        if (response.EmergencyHoldActive.Value && response.Lifecycle.EmergencyHold is null)
        {
            throw new JsonException($"{context}.emergency_hold_active cannot be true without a retained hold.");
        }
        if (response.Active.Value)
        {
            var codeHash = ToriiSseEventJson.RequireExactSizedHex(
                response.CodeHashHex,
                $"{context}.code_hash_hex",
                32);
            ToriiSseEventJson.RequireExactSizedHex(
                response.AbiHashHex,
                $"{context}.abi_hash_hex",
                32);
            if (!string.Equals(
                    codeHash,
                    response.Lifecycle.ActiveCodeHashHex,
                    StringComparison.Ordinal))
            {
                throw new JsonException($"{context}.code_hash_hex must match lifecycle.active_code_hash_hex.");
            }
            ValidatePublicEntrypoints(response.PublicEntrypoints, $"{context}.public_entrypoints");
        }
        else if (response.CodeHashHex is not null
                 || response.AbiHashHex is not null
                 || response.PublicEntrypoints is not null
                 || response.Lifecycle.ActiveCodeHashHex is not null)
        {
            throw new JsonException($"{context} inactive shape must not expose active artifact fields.");
        }
    }

    internal static void WriteResponse(
        Utf8JsonWriter writer,
        ToriiGovernedContractResponse response,
        string context)
    {
        ValidateResponse(response, context);
        writer.WriteStartObject();
        writer.WriteBoolean("found", response.Found);
        writer.WriteString("contract_address", response.ContractAddress);
        if (!response.Found)
        {
            writer.WriteString("dataspace", response.Dataspace);
            writer.WriteEndObject();
            return;
        }

        writer.WriteString("contract_subject_account", response.ContractSubjectAccount);
        writer.WriteString("dataspace", response.Dataspace);
        writer.WriteBoolean("active", response.Active!.Value);
        writer.WritePropertyName("lifecycle");
        WriteLifecycle(writer, response.Lifecycle!);
        writer.WriteBoolean("emergency_hold_active", response.EmergencyHoldActive!.Value);
        if (response.Active.Value)
        {
            writer.WriteString("code_hash_hex", response.CodeHashHex);
            writer.WriteString("abi_hash_hex", response.AbiHashHex);
            writer.WritePropertyName("public_entrypoints");
            writer.WriteStartArray();
            foreach (var entrypoint in response.PublicEntrypoints!)
            {
                writer.WriteStringValue(entrypoint);
            }
            writer.WriteEndArray();
        }
        writer.WriteEndObject();
    }

    private static ToriiGovernedContractLifecycle ReadLifecycle(JsonElement element, string context)
    {
        var root = RequireObject(element, LifecycleFields, context);
        RequireAll(root, LifecycleFields, context);
        var lifecycle = new ToriiGovernedContractLifecycle
        {
            Version = RequireUInt16(root, "version", context),
            Origin = RequireToken(root, "origin", context),
            OriginAccount = RequireToken(root, "origin_account", context),
            OriginProposalContentIdHex = ReadNullableHash(root["origin_proposal_content_id_hex"], $"{context}.origin_proposal_content_id_hex"),
            OriginGovernanceAttemptIdHex = ReadNullableHash(root["origin_governance_attempt_id_hex"], $"{context}.origin_governance_attempt_id_hex"),
            Owner = RequireToken(root, "owner", context),
            PendingOwner = ReadNullableToken(root["pending_owner"], $"{context}.pending_owner"),
            ParliamentDelegated = RequireBool(root, "parliament_delegated", context),
            ActiveCodeHashHex = ReadNullableHash(root["active_code_hash_hex"], $"{context}.active_code_hash_hex"),
            RetainedCodeHashHex = ReadNullableHash(root["retained_code_hash_hex"], $"{context}.retained_code_hash_hex"),
            Revision = RequireUInt64(root, "revision", context),
            EmergencyHold = root["emergency_hold"].ValueKind == JsonValueKind.Null
                ? null
                : ReadEmergencyHold(root["emergency_hold"], $"{context}.emergency_hold"),
        };
        ValidateLifecycle(lifecycle, context);
        return lifecycle;
    }

    private static void ValidateLifecycle(ToriiGovernedContractLifecycle lifecycle, string context)
    {
        if (lifecycle.Version != 1)
        {
            throw new JsonException($"{context}.version must be 1.");
        }
        if (lifecycle.Origin is not ("direct" or "parliament"))
        {
            throw new JsonException($"{context}.origin must be direct or parliament.");
        }
        RequireCanonicalAccountId(lifecycle.OriginAccount, $"{context}.origin_account");
        RequireLifecycleOwner(lifecycle.Owner, $"{context}.owner");
        if (lifecycle.PendingOwner is not null)
        {
            RequireLifecycleOwner(lifecycle.PendingOwner, $"{context}.pending_owner");
        }
        if (string.Equals(lifecycle.Owner, lifecycle.PendingOwner, StringComparison.Ordinal))
        {
            throw new JsonException($"{context}.pending_owner must differ from owner.");
        }
        if (lifecycle.Owner == "parliament" && lifecycle.ParliamentDelegated)
        {
            throw new JsonException($"{context} Parliament owner cannot carry delegated Parliament authority.");
        }
        ToriiSseEventJson.RequireOptionalExactSizedHex(
            lifecycle.ActiveCodeHashHex,
            $"{context}.active_code_hash_hex",
            32);
        ToriiSseEventJson.RequireOptionalExactSizedHex(lifecycle.RetainedCodeHashHex, $"{context}.retained_code_hash_hex", 32);
        if (lifecycle.ActiveCodeHashHex is not null && lifecycle.ActiveCodeHashHex != lifecycle.RetainedCodeHashHex)
            throw new JsonException($"{context}.retained_code_hash_hex must match active_code_hash_hex for an active binding.");
        if (lifecycle.Revision == 0)
        {
            throw new JsonException($"{context}.revision must be non-zero.");
        }
        var parliamentOrigin = lifecycle.Origin == "parliament";
        var hasProposal = lifecycle.OriginProposalContentIdHex is not null;
        var hasAttempt = lifecycle.OriginGovernanceAttemptIdHex is not null;
        if (parliamentOrigin != hasProposal || parliamentOrigin != hasAttempt)
        {
            throw new JsonException($"{context} Parliament origin identifiers must be present exactly for Parliament deployments.");
        }
        ToriiSseEventJson.RequireOptionalExactSizedHex(
            lifecycle.OriginProposalContentIdHex,
            $"{context}.origin_proposal_content_id_hex",
            32);
        ToriiSseEventJson.RequireOptionalExactSizedHex(
            lifecycle.OriginGovernanceAttemptIdHex,
            $"{context}.origin_governance_attempt_id_hex",
            32);
        if (parliamentOrigin
            && (IsZeroHash(lifecycle.OriginProposalContentIdHex!)
                || IsZeroHash(lifecycle.OriginGovernanceAttemptIdHex!)))
        {
            throw new JsonException($"{context} Parliament origin identifiers must be non-zero.");
        }
        if (lifecycle.EmergencyHold is not null)
        {
            ValidateEmergencyHold(lifecycle.EmergencyHold, $"{context}.emergency_hold");
        }
    }

    private static ToriiGovernedContractEmergencyHold ReadEmergencyHold(
        JsonElement element,
        string context)
    {
        var root = RequireObject(element, EmergencyHoldFields, context);
        RequireAll(root, EmergencyHoldFields, context);
        var hold = new ToriiGovernedContractEmergencyHold
        {
            IncidentDigestHex = RequireHash(root, "incident_digest_hex", context),
            ProposalContentIdHex = RequireHash(root, "proposal_content_id_hex", context),
            GovernanceAttemptIdHex = RequireHash(root, "governance_attempt_id_hex", context),
            Reason = RequireText(root, "reason", context),
            ImposedAtHeight = RequireUInt64(root, "imposed_at_height", context),
            ExpiresAtHeight = RequireUInt64(root, "expires_at_height", context),
        };
        ValidateEmergencyHold(hold, context);
        return hold;
    }

    private static void ValidateEmergencyHold(
        ToriiGovernedContractEmergencyHold hold,
        string context)
    {
        ToriiSseEventJson.RequireExactSizedHex(hold.IncidentDigestHex, $"{context}.incident_digest_hex", 32);
        ToriiSseEventJson.RequireExactSizedHex(hold.ProposalContentIdHex, $"{context}.proposal_content_id_hex", 32);
        ToriiSseEventJson.RequireExactSizedHex(hold.GovernanceAttemptIdHex, $"{context}.governance_attempt_id_hex", 32);
        ToriiSseEventJson.RequireOptionalExactNonEmptyText(hold.Reason, $"{context}.reason");
        if (IsZeroHash(hold.IncidentDigestHex)
            || IsZeroHash(hold.ProposalContentIdHex)
            || IsZeroHash(hold.GovernanceAttemptIdHex)
            || hold.ImposedAtHeight == 0
            || hold.ExpiresAtHeight <= hold.ImposedAtHeight
            || hold.ExpiresAtHeight - hold.ImposedAtHeight > 3_600)
        {
            throw new JsonException($"{context} must cover 1 through 3,600 blocks.");
        }
    }

    private static void WriteLifecycle(Utf8JsonWriter writer, ToriiGovernedContractLifecycle lifecycle)
    {
        writer.WriteStartObject();
        writer.WriteNumber("version", lifecycle.Version);
        writer.WriteString("origin", lifecycle.Origin);
        writer.WriteString("origin_account", lifecycle.OriginAccount);
        WriteNullableString(writer, "origin_proposal_content_id_hex", lifecycle.OriginProposalContentIdHex);
        WriteNullableString(writer, "origin_governance_attempt_id_hex", lifecycle.OriginGovernanceAttemptIdHex);
        writer.WriteString("owner", lifecycle.Owner);
        WriteNullableString(writer, "pending_owner", lifecycle.PendingOwner);
        writer.WriteBoolean("parliament_delegated", lifecycle.ParliamentDelegated);
        WriteNullableString(writer, "active_code_hash_hex", lifecycle.ActiveCodeHashHex);
        WriteNullableString(writer, "retained_code_hash_hex", lifecycle.RetainedCodeHashHex);
        writer.WriteNumber("revision", lifecycle.Revision);
        writer.WritePropertyName("emergency_hold");
        if (lifecycle.EmergencyHold is null)
        {
            writer.WriteNullValue();
        }
        else
        {
            WriteEmergencyHold(writer, lifecycle.EmergencyHold);
        }
        writer.WriteEndObject();
    }

    private static void WriteEmergencyHold(
        Utf8JsonWriter writer,
        ToriiGovernedContractEmergencyHold hold)
    {
        writer.WriteStartObject();
        writer.WriteString("incident_digest_hex", hold.IncidentDigestHex);
        writer.WriteString("proposal_content_id_hex", hold.ProposalContentIdHex);
        writer.WriteString("governance_attempt_id_hex", hold.GovernanceAttemptIdHex);
        writer.WriteString("reason", hold.Reason);
        writer.WriteNumber("imposed_at_height", hold.ImposedAtHeight);
        writer.WriteNumber("expires_at_height", hold.ExpiresAtHeight);
        writer.WriteEndObject();
    }

    private static Dictionary<string, JsonElement> RequireObject(
        JsonElement element,
        HashSet<string> allowed,
        string context)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException($"{context} must be an object.");
        }
        var fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!allowed.Contains(property.Name))
            {
                throw new JsonException($"{context}.{property.Name} is not supported.");
            }
            if (!fields.TryAdd(property.Name, property.Value))
            {
                throw new JsonException($"{context}.{property.Name} must not appear more than once.");
            }
        }
        return fields;
    }

    private static void RequireAll(
        Dictionary<string, JsonElement> fields,
        HashSet<string> required,
        string context)
    {
        foreach (var field in required)
        {
            _ = RequireProperty(fields, field, context);
        }
    }

    private static JsonElement RequireProperty(
        Dictionary<string, JsonElement> fields,
        string name,
        string context)
    {
        return fields.TryGetValue(name, out var value)
            ? value
            : throw new JsonException($"{context}.{name} is required.");
    }

    private static bool RequireBool(Dictionary<string, JsonElement> fields, string name, string context)
    {
        var value = RequireProperty(fields, name, context);
        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => throw new JsonException($"{context}.{name} must be a boolean."),
        };
    }

    private static ushort RequireUInt16(Dictionary<string, JsonElement> fields, string name, string context)
    {
        var value = RequireProperty(fields, name, context);
        return value.ValueKind == JsonValueKind.Number && value.TryGetUInt16(out var parsed)
            ? parsed
            : throw new JsonException($"{context}.{name} must be an unsigned 16-bit integer.");
    }

    private static ulong RequireUInt64(Dictionary<string, JsonElement> fields, string name, string context)
    {
        var value = RequireProperty(fields, name, context);
        return value.ValueKind == JsonValueKind.Number && value.TryGetUInt64(out var parsed)
            ? parsed
            : throw new JsonException($"{context}.{name} must be an unsigned 64-bit integer.");
    }

    private static string RequireToken(Dictionary<string, JsonElement> fields, string name, string context)
    {
        var value = RequireProperty(fields, name, context);
        if (value.ValueKind != JsonValueKind.String)
        {
            throw new JsonException($"{context}.{name} must be a string.");
        }
        return ToriiSseEventJson.RequireExactTokenText(value.GetString(), $"{context}.{name}");
    }

    private static string RequireText(Dictionary<string, JsonElement> fields, string name, string context)
    {
        var value = RequireProperty(fields, name, context);
        if (value.ValueKind != JsonValueKind.String)
        {
            throw new JsonException($"{context}.{name} must be a string.");
        }
        return ToriiSseEventJson.RequireOptionalExactNonEmptyText(
            value.GetString(),
            $"{context}.{name}")!;
    }

    private static string RequireHash(Dictionary<string, JsonElement> fields, string name, string context)
    {
        var value = RequireProperty(fields, name, context);
        if (value.ValueKind != JsonValueKind.String)
        {
            throw new JsonException($"{context}.{name} must be a string.");
        }
        return ToriiSseEventJson.RequireExactSizedHex(value.GetString(), $"{context}.{name}", 32);
    }

    private static string? ReadNullableHash(JsonElement value, string context)
    {
        if (value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (value.ValueKind != JsonValueKind.String)
        {
            throw new JsonException($"{context} must be a string or null.");
        }
        return ToriiSseEventJson.RequireExactSizedHex(value.GetString(), context, 32);
    }

    private static string? ReadNullableToken(JsonElement value, string context)
    {
        if (value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (value.ValueKind != JsonValueKind.String)
        {
            throw new JsonException($"{context} must be a string or null.");
        }
        return ToriiSseEventJson.RequireExactTokenText(value.GetString(), context);
    }

    private static IReadOnlyList<string> ReadPublicEntrypoints(JsonElement value, string context)
    {
        if (value.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException($"{context} must be an array.");
        }
        var items = new List<string>();
        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                throw new JsonException($"{context} entries must be strings.");
            }
            items.Add(item.GetString()!);
        }
        ValidatePublicEntrypoints(items, context);
        return items;
    }

    private static void ValidatePublicEntrypoints(IReadOnlyList<string>? values, string context)
    {
        if (values is null)
        {
            throw new JsonException($"{context} is required for an active contract.");
        }
        if (values.Count == 0)
        {
            throw new JsonException($"{context} must contain at least one entrypoint.");
        }
        string? previous = null;
        for (var index = 0; index < values.Count; index++)
        {
            var value = values[index];
            if (!IsCanonicalEntrypoint(value))
            {
                throw new JsonException($"{context}[{index}] is not a canonical public entrypoint.");
            }
            if (previous is not null && string.CompareOrdinal(previous, value) >= 0)
            {
                throw new JsonException($"{context} must be sorted and unique.");
            }
            previous = value;
        }
    }

    private static bool IsCanonicalEntrypoint(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 128 || value[0] is < 'a' or > 'z')
        {
            return false;
        }
        return value.Skip(1).All(character =>
            character is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '_');
    }

    private static string RequireCanonicalAccountId(string? value, string context)
    {
        try
        {
            return ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value, context);
        }
        catch (ArgumentException exception)
        {
            throw new JsonException($"{context} must be a canonical I105 account id.", exception);
        }
    }

    private static string RequireLifecycleOwner(string? value, string context)
    {
        var owner = ToriiSseEventJson.RequireExactTokenText(value, context);
        return owner == "parliament"
            ? owner
            : RequireCanonicalAccountId(owner, context);
    }

    private static bool IsZeroHash(string value)
    {
        return value.All(character => character == '0');
    }

    private static void RequireAbsentFoundFields(
        Dictionary<string, JsonElement> fields,
        string context)
    {
        foreach (var name in new[]
                 {
                     "contract_subject_account",
                     "active",
                     "lifecycle",
                     "emergency_hold_active",
                     "code_hash_hex",
                     "abi_hash_hex",
                     "public_entrypoints",
                 })
        {
            RequireAbsent(fields, name, context);
        }
    }

    private static void RequireAbsent(
        Dictionary<string, JsonElement> fields,
        string name,
        string context)
    {
        if (fields.ContainsKey(name))
        {
            throw new JsonException($"{context}.{name} must be absent for this response shape.");
        }
    }

    private static void WriteNullableString(Utf8JsonWriter writer, string name, string? value)
    {
        if (value is null)
        {
            writer.WriteNull(name);
        }
        else
        {
            writer.WriteString(name, value);
        }
    }
}

internal sealed class ToriiGovernedContractResponseJsonConverter
    : JsonConverter<ToriiGovernedContractResponse>
{
    public override ToriiGovernedContractResponse Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        return ToriiGovernedContractJson.ReadResponse(ref reader, "governed contract response");
    }

    public override void Write(
        Utf8JsonWriter writer,
        ToriiGovernedContractResponse value,
        JsonSerializerOptions options)
    {
        ToriiGovernedContractJson.WriteResponse(writer, value, "governed contract response");
    }
}
