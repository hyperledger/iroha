using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Hyperledger.Iroha;

/// <summary>
/// Base type of every error the SDK raises with a stable machine-readable <see cref="Code"/>:
/// Torii error envelopes, rejected list-query controls and terminal stream errors.
/// </summary>
/// <remarks>
/// <see cref="Code"/> carries the Torii error code (for example <c>invalid_filter</c>) whether the
/// SDK rejected a request locally or Torii rejected it remotely, so one <c>catch</c> handles both.
/// </remarks>
public class IrohaException : Exception
{
    /// <summary>Creates an error with a stable code and a human-readable message.</summary>
    public IrohaException(string code, string message, Exception? innerException = null)
        : this(code, message, statusCode: null, details: null, innerException)
    {
    }

    /// <summary>Creates an error with an optional HTTP status and structured details.</summary>
    protected IrohaException(
        string code,
        string message,
        HttpStatusCode? statusCode,
        IrohaErrorDetails? details,
        Exception? innerException)
        : base(message, innerException)
    {
        ArgumentException.ThrowIfNullOrEmpty(code);
        Code = code;
        StatusCode = statusCode;
        Details = details;
    }

    /// <summary>Stable error code such as <c>invalid_filter</c> or <c>query_validation_failed</c>.</summary>
    public string Code { get; }

    /// <summary>HTTP status of the Torii response, or <see langword="null"/> for local errors.</summary>
    public HttpStatusCode? StatusCode { get; }

    /// <summary>Structured details from the Torii error envelope, when present.</summary>
    public IrohaErrorDetails? Details { get; }
}

/// <summary>The <c>details</c> member of a Torii error envelope.</summary>
public sealed class IrohaErrorDetails
{
    private readonly JsonElement json;

    private IrohaErrorDetails(JsonElement json)
    {
        this.json = json;
        Field = OptionalString(json, "field");
        Expected = OptionalString(json, "expected");
        Actual = OptionalString(json, "actual");
        Hint = OptionalString(json, "hint");
        RejectCode = OptionalString(json, "reject_code");
        IvmFault = json.TryGetProperty("ivm_fault", out var fault) && fault.ValueKind != JsonValueKind.Null
            ? Torii.ToriiIvmFaultJsonConverter.Read(fault) : null;
    }

    /// <summary>The request control or data field at fault (for example <c>filter</c>).</summary>
    public string? Field { get; }

    /// <summary>What Torii expected, such as the accepted field names.</summary>
    public string? Expected { get; }

    /// <summary>What Torii received.</summary>
    public string? Actual { get; }

    /// <summary>An actionable hint for fixing the request.</summary>
    public string? Hint { get; }

    /// <summary>A rejection code carried inside the details object.</summary>
    public string? RejectCode { get; }

    /// <summary>Canonical deterministic runtime fault when present in the HTTP error.</summary>
    public Torii.ToriiIvmFault? IvmFault { get; }

    /// <summary>The complete details object, including members this SDK does not model.</summary>
    public JsonObject ToJsonObject() => JsonObject.Create(json.Clone())
        ?? throw new InvalidOperationException("Error details must be a JSON object.");

    /// <inheritdoc />
    public override string ToString() => json.GetRawText();

    internal static IrohaErrorDetails? FromElement(JsonElement element) =>
        element.ValueKind == JsonValueKind.Object ? new IrohaErrorDetails(element.Clone()) : null;

    private static string? OptionalString(JsonElement json, string name) =>
        json.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
