// Typed events of `GET /v1/events/sse` (specs/torii/collection_queries.md, "Event streams").

using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Hyperledger.Iroha.Torii;

/// <summary>One event from <c>GET /v1/events/sse</c>, decoded from its JSON payload.</summary>
/// <remarks>
/// <para>Match on the concrete type: <see cref="ToriiTransactionEvent"/>, <see cref="ToriiBlockEvent"/>,
/// <see cref="ToriiPipelineWarningEvent"/> and <see cref="ToriiWitnessEvent"/> (pipeline),
/// <see cref="ToriiProofVerificationEvent"/> and <see cref="ToriiProofPrunedEvent"/> (proofs),
/// <see cref="ToriiDataEvent"/> for the other data-event kinds, <see cref="ToriiOtherEvent"/>, and
/// <see cref="ToriiUnknownEvent"/> for events this SDK does not model, which never fail the stream.</para>
/// <code>
/// await foreach (var e in client.StreamEventsAsync(Filter.Field("tx_hash").Eq(hash), cancellationToken))
/// {
///     if (e is ToriiTransactionEvent { Status: ToriiTransactionStatus.Rejected } rejected)
///     {
///         Console.WriteLine($"{rejected.RejectionCode}: {rejected.RejectionReason}");
///     }
/// }
/// </code>
/// </remarks>
public abstract record ToriiEvent
{
    private protected ToriiEvent(string category, string eventName)
    {
        Category = category;
        Event = eventName;
    }

    /// <summary>The payload <c>category</c>: <c>Pipeline</c>, <c>Data</c> or <c>Other</c>.</summary>
    public string Category { get; }

    /// <summary>
    /// The payload <c>event</c>, for example <c>Transaction</c>, <c>Block</c>, <c>ProofVerified</c> or a
    /// data-event kind such as <c>Asset</c>.
    /// </summary>
    public string Event { get; }
}

/// <summary>A transaction or block lifecycle event, or another pipeline event (<c>category</c> <c>Pipeline</c>).</summary>
public abstract record ToriiPipelineEvent : ToriiEvent
{
    private protected ToriiPipelineEvent(string eventName)
        : base("Pipeline", eventName)
    {
    }
}

/// <summary>The status a transaction event reports.</summary>
public enum ToriiTransactionStatus
{
    /// <summary>Accepted into the queue.</summary>
    Queued,

    /// <summary>Dropped from the queue before it was committed.</summary>
    Expired,

    /// <summary>Executed successfully in a block.</summary>
    Approved,

    /// <summary>Rejected; see <see cref="ToriiTransactionEvent.RejectionCode"/>.</summary>
    Rejected,
}

/// <summary>A transaction status change (<c>event</c> <c>Transaction</c>).</summary>
public sealed record ToriiTransactionEvent : ToriiPipelineEvent
{
    /// <summary>Creates a transaction event.</summary>
    public ToriiTransactionEvent()
        : base("Transaction")
    {
    }

    /// <summary>The transaction hash (64 lowercase hex characters).</summary>
    public required string Hash { get; init; }

    /// <summary>The lane that carries the transaction.</summary>
    public required uint LaneId { get; init; }

    /// <summary>The dataspace of the transaction.</summary>
    public required ulong DataspaceId { get; init; }

    /// <summary>The height of the block that holds the transaction, once it is in one.</summary>
    public ulong? BlockHeight { get; init; }

    /// <summary>The reported status.</summary>
    public required ToriiTransactionStatus Status { get; init; }

    /// <summary>
    /// For <see cref="ToriiTransactionStatus.Rejected"/>: <c>account_does_not_exist</c>,
    /// <c>limit_check</c>, <c>validation</c>, <c>instruction_execution</c>, <c>ivm_execution</c> or
    /// <c>trigger_execution</c>.
    /// </summary>
    public string? RejectionCode { get; init; }

    /// <summary>For <see cref="ToriiTransactionStatus.Rejected"/>: the fixed public description of <see cref="RejectionCode"/>.</summary>
    public string? RejectionReason { get; init; }
}

/// <summary>The status a block event reports.</summary>
public enum ToriiBlockStatus
{
    /// <summary>Proposed.</summary>
    Created,

    /// <summary>Approved by validation.</summary>
    Approved,

    /// <summary>Rejected; see <see cref="ToriiBlockEvent.RejectionCode"/>.</summary>
    Rejected,

    /// <summary>Committed.</summary>
    Committed,

    /// <summary>Applied to the world state.</summary>
    Applied,
}

/// <summary>A block status change (<c>event</c> <c>Block</c>).</summary>
public sealed record ToriiBlockEvent : ToriiPipelineEvent
{
    /// <summary>Creates a block event.</summary>
    public ToriiBlockEvent()
        : base("Block")
    {
    }

    /// <summary>The reported status.</summary>
    public required ToriiBlockStatus Status { get; init; }

    /// <summary>For <see cref="ToriiBlockStatus.Rejected"/>: the block rejection variant, e.g. <c>EmptyBlock</c>.</summary>
    public string? RejectionCode { get; init; }
}

/// <summary>A pipeline warning (<c>event</c> <c>Warning</c>).</summary>
public sealed record ToriiPipelineWarningEvent : ToriiPipelineEvent
{
    /// <summary>Creates a warning event.</summary>
    public ToriiPipelineWarningEvent()
        : base("Warning")
    {
    }

    /// <summary>The machine-readable warning kind.</summary>
    public required string Kind { get; init; }

    /// <summary>Human-readable details.</summary>
    public required string Details { get; init; }

    /// <summary>The height of the block the warning concerns.</summary>
    public required ulong Height { get; init; }
}

/// <summary>An execution witness summary (<c>event</c> <c>Witness</c>).</summary>
public sealed record ToriiWitnessEvent : ToriiPipelineEvent
{
    /// <summary>Creates a witness event.</summary>
    public ToriiWitnessEvent()
        : base("Witness")
    {
    }

    /// <summary>The block hash (64 lowercase hex characters).</summary>
    public required string BlockHash { get; init; }

    /// <summary>The block height.</summary>
    public required ulong Height { get; init; }

    /// <summary>The consensus view.</summary>
    public required ulong View { get; init; }

    /// <summary>The epoch.</summary>
    public required ulong Epoch { get; init; }

    /// <summary>The number of state reads witnessed.</summary>
    public required ulong ReadCount { get; init; }

    /// <summary>The number of state writes witnessed.</summary>
    public required ulong WriteCount { get; init; }
}

/// <summary>A proof registry event (<c>category</c> <c>Data</c>, <c>event</c> <c>Proof…</c>).</summary>
public abstract record ToriiProofEvent : ToriiEvent
{
    private protected ToriiProofEvent(string eventName)
        : base("Data", eventName)
    {
    }

    /// <summary>The proof backend, e.g. <c>pipa-r/pasta</c>.</summary>
    public required string Backend { get; init; }
}

/// <summary>A proof verification result (<c>event</c> <c>ProofVerified</c> or <c>ProofRejected</c>).</summary>
public sealed record ToriiProofVerificationEvent : ToriiProofEvent
{
    /// <summary>Creates a verification event.</summary>
    /// <param name="verified"><see langword="true"/> for <c>ProofVerified</c>, <see langword="false"/> for <c>ProofRejected</c>.</param>
    public ToriiProofVerificationEvent(bool verified)
        : base(verified ? "ProofVerified" : "ProofRejected")
    {
        Verified = verified;
    }

    /// <summary>Whether the proof verified.</summary>
    public bool Verified { get; }

    /// <summary>The proof hash (64 lowercase hex characters).</summary>
    public required string ProofHash { get; init; }

    /// <summary>The hash of the transaction entrypoint that submitted the proof, when known.</summary>
    public string? CallHash { get; init; }

    /// <summary>The hash of the verification envelope payload, when known.</summary>
    public string? EnvelopeHash { get; init; }

    /// <summary>The verifying key used, as <c>backend::name</c>, when known.</summary>
    public string? VerifyingKeyReference { get; init; }

    /// <summary>The commitment of the verifying key used (64 lowercase hex characters), when known.</summary>
    public string? VerifyingKeyCommitment { get; init; }
}

/// <summary>Where a proof pruning pass came from.</summary>
public enum ToriiProofPruneOrigin
{
    /// <summary>Retention enforcement while inserting a new proof record.</summary>
    Insert,

    /// <summary>An explicit <c>PruneProofs</c> instruction.</summary>
    Manual,
}

/// <summary>One proof removed by a pruning pass.</summary>
public sealed record ToriiPrunedProof
{
    /// <summary>The proof backend.</summary>
    public required string Backend { get; init; }

    /// <summary>The proof hash (64 lowercase hex characters).</summary>
    public required string ProofHash { get; init; }
}

/// <summary>A proof registry pruning pass (<c>event</c> <c>ProofPruned</c>).</summary>
public sealed record ToriiProofPrunedEvent : ToriiProofEvent
{
    /// <summary>Creates a pruning event.</summary>
    public ToriiProofPrunedEvent()
        : base("ProofPruned")
    {
    }

    /// <summary>The proofs removed in this pass (bounded by <see cref="PruneBatch"/>).</summary>
    public required ImmutableArray<ToriiPrunedProof> Removed { get; init; }

    /// <summary>The proof records left for the backend.</summary>
    public required ulong Remaining { get; init; }

    /// <summary>The per-backend cap in force.</summary>
    public required ulong Cap { get; init; }

    /// <summary>The grace window, in blocks.</summary>
    public required ulong GraceBlocks { get; init; }

    /// <summary>The maximum removals per pass.</summary>
    public required ulong PruneBatch { get; init; }

    /// <summary>The block height at which pruning ran.</summary>
    public required ulong PrunedAtHeight { get; init; }

    /// <summary>The account that caused the pass.</summary>
    public required string PrunedBy { get; init; }

    /// <summary>Where the pass came from.</summary>
    public required ToriiProofPruneOrigin Origin { get; init; }
}

/// <summary>A data event other than a proof event (<c>category</c> <c>Data</c>; <c>event</c> is the kind, such as <c>Asset</c>).</summary>
public sealed record ToriiDataEvent : ToriiEvent
{
    /// <summary>Creates a data event.</summary>
    /// <param name="kind">The data-event kind, such as <c>Asset</c> or <c>Domain</c>.</param>
    public ToriiDataEvent(string kind)
        : base("Data", kind)
    {
    }

    /// <summary>Diagnostic text without a stable format.</summary>
    public string? Summary { get; init; }
}

/// <summary>A time, trigger or other non-data event (<c>category</c> <c>Other</c>).</summary>
public sealed record ToriiOtherEvent : ToriiEvent
{
    /// <summary>Creates an event of category <c>Other</c>.</summary>
    /// <param name="eventName"><c>Time</c>, <c>ExecuteTrigger</c>, <c>TriggerCompleted</c> or <c>Other</c>.</param>
    public ToriiOtherEvent(string eventName)
        : base("Other", eventName)
    {
    }

    /// <summary>Diagnostic text without a stable format.</summary>
    public string? Summary { get; init; }
}

/// <summary>An event this SDK does not model; its payload is kept as JSON.</summary>
public sealed record ToriiUnknownEvent : ToriiEvent
{
    /// <summary>Creates an unknown event.</summary>
    public ToriiUnknownEvent(string category, string eventName, JsonObject payload)
        : base(category, eventName)
    {
        Payload = payload ?? throw new ArgumentNullException(nameof(payload));
    }

    /// <summary>The complete payload.</summary>
    public JsonObject Payload { get; }
}

/// <summary>Decodes event-stream payloads; known members are type-checked and unknown members ignored.</summary>
internal static class ToriiEventJson
{
    private const int HashBytes = 32;

    /// <summary>Decodes one SSE <c>data</c> payload.</summary>
    /// <exception cref="JsonException">The payload is not an event object or a known member is malformed.</exception>
    internal static ToriiEvent Read(string data, string context)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(data, new JsonDocumentOptions { MaxDepth = 128 });
        }
        catch (JsonException exception)
        {
            throw new JsonException($"{context} must be a JSON object.", exception);
        }

        using (document)
        {
            var payload = document.RootElement;
            if (payload.ValueKind != JsonValueKind.Object)
            {
                throw new JsonException($"{context} must be a JSON object.");
            }

            ToriiIdentifierJson.RejectDuplicateProperties(payload, context);
            return Read(payload, context);
        }
    }

    private static ToriiEvent Read(JsonElement payload, string context)
    {
        var category = RequiredString(payload, "category", context);
        var eventName = RequiredString(payload, "event", context);
        return (category, eventName) switch
        {
            ("Pipeline", "Transaction") => ReadTransaction(payload, context),
            ("Pipeline", "Block") => ReadBlock(payload, context),
            ("Pipeline", "Warning") => new ToriiPipelineWarningEvent
            {
                Kind = RequiredString(payload, "kind", context),
                Details = RequiredString(payload, "details", context),
                Height = RequiredUInt64(payload, "height", context),
            },
            ("Pipeline", "Witness") => new ToriiWitnessEvent
            {
                BlockHash = RequiredHash(payload, "block_hash", context),
                Height = RequiredUInt64(payload, "height", context),
                View = RequiredUInt64(payload, "view", context),
                Epoch = RequiredUInt64(payload, "epoch", context),
                ReadCount = RequiredUInt64(payload, "read_count", context),
                WriteCount = RequiredUInt64(payload, "write_count", context),
            },
            ("Data", "ProofVerified") => ReadProofVerification(payload, verified: true, context),
            ("Data", "ProofRejected") => ReadProofVerification(payload, verified: false, context),
            ("Data", "ProofPruned") => ReadProofPruned(payload, context),
            ("Data", _) => new ToriiDataEvent(eventName) { Summary = OptionalString(payload, "summary", context) },
            ("Other", _) => new ToriiOtherEvent(eventName) { Summary = OptionalString(payload, "summary", context) },
            _ => new ToriiUnknownEvent(category, eventName, JsonObject.Create(payload.Clone())!),
        };
    }

    private static ToriiTransactionEvent ReadTransaction(JsonElement payload, string context)
    {
        var status = RequiredString(payload, "status", context) switch
        {
            "Queued" => ToriiTransactionStatus.Queued,
            "Expired" => ToriiTransactionStatus.Expired,
            "Approved" => ToriiTransactionStatus.Approved,
            "Rejected" => ToriiTransactionStatus.Rejected,
            var other => throw new JsonException(
                $"{context}.status `{other}` is not a transaction status; expected Queued, Expired, Approved or Rejected."),
        };
        var rejected = status == ToriiTransactionStatus.Rejected;
        var laneId = RequiredUInt64(payload, "lane_id", context);
        return new ToriiTransactionEvent
        {
            Hash = RequiredHash(payload, "hash", context),
            LaneId = laneId <= uint.MaxValue
                ? (uint)laneId
                : throw new JsonException($"{context}.lane_id must fit an unsigned 32-bit integer."),
            DataspaceId = RequiredUInt64(payload, "dataspace_id", context),
            BlockHeight = OptionalUInt64(payload, "block_height", context),
            Status = status,
            RejectionCode = rejected
                ? ToriiSseEventJson.RequireExactTokenText(RequiredString(payload, "rejection_code", context), $"{context}.rejection_code")
                : OptionalString(payload, "rejection_code", context),
            RejectionReason = rejected
                ? RequiredString(payload, "rejection_reason", context)
                : OptionalString(payload, "rejection_reason", context),
        };
    }

    private static ToriiBlockEvent ReadBlock(JsonElement payload, string context)
    {
        var status = RequiredString(payload, "status", context) switch
        {
            "Created" => ToriiBlockStatus.Created,
            "Approved" => ToriiBlockStatus.Approved,
            "Rejected" => ToriiBlockStatus.Rejected,
            "Committed" => ToriiBlockStatus.Committed,
            "Applied" => ToriiBlockStatus.Applied,
            var other => throw new JsonException(
                $"{context}.status `{other}` is not a block status; expected Created, Approved, Rejected, Committed or Applied."),
        };
        return new ToriiBlockEvent
        {
            Status = status,
            RejectionCode = status == ToriiBlockStatus.Rejected
                ? ToriiSseEventJson.RequireExactTokenText(RequiredString(payload, "rejection_code", context), $"{context}.rejection_code")
                : OptionalString(payload, "rejection_code", context),
        };
    }

    private static ToriiProofVerificationEvent ReadProofVerification(JsonElement payload, bool verified, string context) =>
        new(verified)
        {
            Backend = RequiredString(payload, "backend", context),
            ProofHash = RequiredHash(payload, "proof_hash", context),
            CallHash = OptionalHash(payload, "call_hash", context),
            EnvelopeHash = OptionalHash(payload, "envelope_hash", context),
            VerifyingKeyReference = OptionalString(payload, "vk_ref", context),
            VerifyingKeyCommitment = OptionalHash(payload, "vk_commitment", context),
        };

    private static ToriiProofPrunedEvent ReadProofPruned(JsonElement payload, string context)
    {
        if (!payload.TryGetProperty("removed", out var removedElement) || removedElement.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException($"{context}.removed must be an array.");
        }

        var removed = ImmutableArray.CreateBuilder<ToriiPrunedProof>(removedElement.GetArrayLength());
        foreach (var item in removedElement.EnumerateArray())
        {
            var itemContext = $"{context}.removed[{removed.Count}]";
            if (item.ValueKind != JsonValueKind.Object)
            {
                throw new JsonException($"{itemContext} must be an object.");
            }

            removed.Add(new ToriiPrunedProof
            {
                Backend = RequiredString(item, "backend", itemContext),
                ProofHash = RequiredHash(item, "proof_hash", itemContext),
            });
        }

        if (RequiredUInt64(payload, "removed_count", context) != (ulong)removed.Count)
        {
            throw new JsonException($"{context}.removed_count must equal the number of `removed` entries.");
        }

        return new ToriiProofPrunedEvent
        {
            Backend = RequiredString(payload, "backend", context),
            Removed = removed.MoveToImmutable(),
            Remaining = RequiredUInt64(payload, "remaining", context),
            Cap = RequiredUInt64(payload, "cap", context),
            GraceBlocks = RequiredUInt64(payload, "grace_blocks", context),
            PruneBatch = RequiredUInt64(payload, "prune_batch", context),
            PrunedAtHeight = RequiredUInt64(payload, "pruned_at_height", context),
            PrunedBy = RequiredString(payload, "pruned_by", context),
            Origin = RequiredString(payload, "origin", context) switch
            {
                "Insert" => ToriiProofPruneOrigin.Insert,
                "Manual" => ToriiProofPruneOrigin.Manual,
                var other => throw new JsonException(
                    $"{context}.origin `{other}` is not a pruning origin; expected Insert or Manual."),
            },
        };
    }

    private static string RequiredString(JsonElement payload, string name, string context) =>
        payload.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()!
            : throw new JsonException($"{context}.{name} must be a string.");

    private static string? OptionalString(JsonElement payload, string name, string context)
    {
        if (!payload.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : throw new JsonException($"{context}.{name} must be a string or null.");
    }

    private static ulong RequiredUInt64(JsonElement payload, string name, string context) =>
        payload.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.Number
            && value.TryGetUInt64(out var number)
            ? number
            : throw new JsonException($"{context}.{name} must be an unsigned integer.");

    private static ulong? OptionalUInt64(JsonElement payload, string name, string context)
    {
        if (!payload.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.Number && value.TryGetUInt64(out var number)
            ? number
            : throw new JsonException($"{context}.{name} must be an unsigned integer or null.");
    }

    private static string RequiredHash(JsonElement payload, string name, string context) =>
        ToriiSseEventJson.RequireExactSizedHex(RequiredString(payload, name, context), $"{context}.{name}", HashBytes);

    private static string? OptionalHash(JsonElement payload, string name, string context) =>
        ToriiSseEventJson.RequireOptionalExactSizedHex(OptionalString(payload, name, context), $"{context}.{name}", HashBytes);
}
