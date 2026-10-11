using System.Text.Json;
using System.Text.Json.Serialization;

namespace Hyperledger.Iroha.Torii;

/// <summary>Deterministic VM failure category.</summary>
public enum ToriiIvmFaultCode { OutOfGas, MemoryLimitExceeded, MemoryAccessViolation, MisalignedAccess, MemoryOutOfBounds, DecodeError, InvalidOpcode, UnknownSyscall, UnsupportedSyscall, GasCostOverflow, Numeric, PointerAbi, AssertionFailed, ExceededMaxCycles, InvalidMetadata, InvalidVectorLength, MissingHalt, VectorExtensionDisabled, ZkExtensionDisabled, NullifierAlreadyUsed, PermissionDenied, PrivacyViolation, RegisterOutOfBounds, NoritoInvalid, AbiTypeNotAllowed, HostOutputItemsExceeded, HostOutputBytesExceeded, AmxBudgetExceeded, ReentrantCall, CallDepthExceeded }
/// <summary>Canonical numeric failure code.</summary>
public enum ToriiIvmNumericFaultCode { MantissaOverflow, ScaleOverflow, DivisionByZero, RepeatingDecimal, ExactDivisionScaleOverflow, InvalidScale, InexactConversion, NegativeQuantity, QuantityUnderflow, InvalidRoundingMode, InvalidFailureMode, ReservedRegisterNonZero, NegativeSquareRoot }
/// <summary>Canonical pointer-envelope failure code.</summary>
public enum ToriiIvmPointerAbiFaultCode { InvalidAddress, UnknownType, TypeNotAllowed, WrongType, InvalidEnvelopeVersion, OversizedLength, TruncatedEnvelope, PayloadHashMismatch, MalformedFrame, SchemaMismatch, NonCanonical }
/// <summary>Invocation selector under the authenticated artifact.</summary>
public enum ToriiIvmInvocationKind { Generic, Entrypoint }
/// <summary>Stage of the originating failure.</summary>
public enum ToriiIvmFaultStage { Initialization, Execute, ReturnValidation }
/// <summary>Closed fault category and its exact subtype, when applicable.</summary>
public sealed record ToriiIvmFaultKind(ToriiIvmFaultCode Code, ToriiIvmNumericFaultCode? Numeric = null, ToriiIvmPointerAbiFaultCode? PointerAbi = null);
/// <summary>Zero-based CNTR ordinal, or generic bytecode.</summary>
public sealed record ToriiIvmFaultSelector(ToriiIvmInvocationKind Kind, uint? Entrypoint = null);
/// <summary>Executable-relative PC only when execution started.</summary>
public sealed record ToriiIvmFaultPosition(ToriiIvmFaultStage Kind, ulong? PcOffset = null);
/// <summary>Exact originating artifact and invocation site.</summary>
public sealed record ToriiIvmFaultSite(string CodeHash, ToriiIvmFaultSelector Selector, ToriiIvmFaultPosition Position);
/// <summary>Typed deterministic failure, separate from application rejection or local refusal.</summary>
[JsonConverter(typeof(ToriiIvmFaultJsonConverter))]
public sealed record ToriiIvmFault(ToriiIvmFaultKind Kind, ToriiIvmFaultSite Site);

internal sealed class ToriiIvmFaultJsonConverter : JsonConverter<ToriiIvmFault>
{
    public override ToriiIvmFault Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        return Read(document.RootElement);
    }
    internal static ToriiIvmFault Read(JsonElement value)
    {
        var root = Exact(value, "fault", "kind", "site");
        var kind = Exact(root["kind"], "fault.kind", "kind", "value");
        var code = EnumValue<ToriiIvmFaultCode>(kind["kind"], "fault.kind.kind");
        ToriiIvmNumericFaultCode? numeric = null;
        ToriiIvmPointerAbiFaultCode? pointer = null;
        if (code == ToriiIvmFaultCode.Numeric || code == ToriiIvmFaultCode.PointerAbi)
        {
            var subtype = Exact(kind["value"], "fault.kind.value", "kind", "value");
            RequireNull(subtype["value"], "fault.kind.value.value");
            if (code == ToriiIvmFaultCode.Numeric) numeric = EnumValue<ToriiIvmNumericFaultCode>(subtype["kind"], "fault.kind.value.kind");
            else pointer = EnumValue<ToriiIvmPointerAbiFaultCode>(subtype["kind"], "fault.kind.value.kind");
        }
        else RequireNull(kind["value"], "fault.kind.value");
        var site = Exact(root["site"], "fault.site", "code_hash", "selector", "position");
        var hash = site["code_hash"].ValueKind == JsonValueKind.String ? site["code_hash"].GetString()! : throw new JsonException("fault.site.code_hash must be a string.");
        ToriiSseEventJson.RequireExactSizedHex(hash, "fault.site.code_hash", 32);
        var selector = Exact(site["selector"], "fault.site.selector", "kind", "value");
        var selectorKind = EnumValue<ToriiIvmInvocationKind>(selector["kind"], "fault.site.selector.kind");
        uint? entrypoint = null;
        if (selectorKind == ToriiIvmInvocationKind.Entrypoint)
            entrypoint = selector["value"].ValueKind == JsonValueKind.Number && selector["value"].TryGetUInt32(out var ordinal) ? ordinal : throw new JsonException("fault.site.selector.value must be u32.");
        else RequireNull(selector["value"], "fault.site.selector.value");
        var position = Exact(site["position"], "fault.site.position", "kind", "value");
        var stage = EnumValue<ToriiIvmFaultStage>(position["kind"], "fault.site.position.kind");
        ulong? pc = null;
        if (stage == ToriiIvmFaultStage.Execute)
        {
            var location = Exact(position["value"], "fault.site.position.value", "pc_offset");
            pc = location["pc_offset"].ValueKind == JsonValueKind.Number && location["pc_offset"].TryGetUInt64(out var offset) ? offset : throw new JsonException("fault.site.position.value.pc_offset must be u64.");
        }
        else RequireNull(position["value"], "fault.site.position.value");
        return new(new(code, numeric, pointer), new(hash, new(selectorKind, entrypoint), new(stage, pc)));
    }
    internal static void Validate(ToriiIvmFault value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Kind is null || value.Site is null || value.Site.Selector is null || value.Site.Position is null) throw new JsonException("fault requires kind and a complete site.");
        var kind = value.Kind;
        if (!Enum.IsDefined(kind.Code) || (kind.Code == ToriiIvmFaultCode.Numeric) != kind.Numeric.HasValue || (kind.Code == ToriiIvmFaultCode.PointerAbi) != kind.PointerAbi.HasValue || (kind.Numeric.HasValue && !Enum.IsDefined(kind.Numeric.Value)) || (kind.PointerAbi.HasValue && !Enum.IsDefined(kind.PointerAbi.Value))) throw new JsonException("fault kind and subtype must match.");
        ToriiSseEventJson.RequireExactSizedHex(value.Site.CodeHash, "fault.site.code_hash", 32);
        var selector = value.Site.Selector;
        if (!Enum.IsDefined(selector.Kind) || (selector.Kind == ToriiIvmInvocationKind.Entrypoint) != selector.Entrypoint.HasValue) throw new JsonException("fault selector and ordinal must match.");
        var position = value.Site.Position;
        if (!Enum.IsDefined(position.Kind) || (position.Kind == ToriiIvmFaultStage.Execute) != position.PcOffset.HasValue) throw new JsonException("fault stage and PC must match.");
    }
    public override void Write(Utf8JsonWriter writer, ToriiIvmFault value, JsonSerializerOptions options) => Write(writer, value);
    internal static void Write(Utf8JsonWriter writer, ToriiIvmFault value)
    {
        Validate(value);
        writer.WriteStartObject();
        writer.WritePropertyName("kind"); writer.WriteStartObject(); writer.WriteString("kind", value.Kind.Code.ToString()); writer.WritePropertyName("value");
        var subtype = value.Kind.Numeric?.ToString() ?? value.Kind.PointerAbi?.ToString();
        if (subtype is null) writer.WriteNullValue(); else { writer.WriteStartObject(); writer.WriteString("kind", subtype); writer.WriteNull("value"); writer.WriteEndObject(); }
        writer.WriteEndObject();
        writer.WritePropertyName("site"); writer.WriteStartObject(); writer.WriteString("code_hash", value.Site.CodeHash);
        writer.WritePropertyName("selector"); writer.WriteStartObject(); writer.WriteString("kind", value.Site.Selector.Kind.ToString());
        if (value.Site.Selector.Entrypoint is { } ordinal) writer.WriteNumber("value", ordinal); else writer.WriteNull("value"); writer.WriteEndObject();
        writer.WritePropertyName("position"); writer.WriteStartObject(); writer.WriteString("kind", value.Site.Position.Kind.ToString()); writer.WritePropertyName("value");
        if (value.Site.Position.PcOffset is { } pc) { writer.WriteStartObject(); writer.WriteNumber("pc_offset", pc); writer.WriteEndObject(); } else writer.WriteNullValue();
        writer.WriteEndObject(); writer.WriteEndObject(); writer.WriteEndObject();
    }
    private static Dictionary<string, JsonElement> Exact(JsonElement value, string context, params string[] names)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new JsonException($"{context} must be an object.");
        var result = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject()) if (!names.Contains(property.Name, StringComparer.Ordinal) || !result.TryAdd(property.Name, property.Value)) throw new JsonException($"{context} contains an unknown or duplicate field.");
        if (result.Count != names.Length) throw new JsonException($"{context} is missing a required field.");
        return result;
    }
    private static T EnumValue<T>(JsonElement value, string context) where T : struct, Enum
    {
        if (value.ValueKind != JsonValueKind.String || !Enum.TryParse<T>(value.GetString(), false, out var parsed) || !Enum.IsDefined(parsed) || parsed.ToString() != value.GetString()) throw new JsonException($"{context} must be a known enum tag.");
        return parsed;
    }
    private static void RequireNull(JsonElement value, string context) { if (value.ValueKind != JsonValueKind.Null) throw new JsonException($"{context} must be null."); }
}
