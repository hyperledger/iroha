using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Hyperledger.Iroha.Torii;

internal static class ToriiContractMetadataJson
{
    internal static void ValidateContractCodeRecord(ToriiContractCodeRecord response, string context)
    {
        ToriiContractManifestJson.ValidateRecord(response, context);
    }

    internal static void ValidateContractCodeView(ToriiContractCodeView response, string context)
    {
        ArgumentNullException.ThrowIfNull(response);

        ToriiSseEventJson.RequireExactSizedHex(response.CodeHash, $"{context}.code_hash", 32);
        ToriiSseEventJson.RequireOptionalExactSizedHex(response.DeclaredCodeHash, $"{context}.declared_code_hash", 32);
        ToriiSseEventJson.RequireOptionalExactSizedHex(response.AbiHash, $"{context}.abi_hash", 32);
        ValidateOptionalExactNonEmptyText(response.CompilerFingerprint, $"{context}.compiler_fingerprint");
        if (response.AccessHints is not null)
        {
            ValidateContractViewAccessHints(response.AccessHints, $"{context}.access_hints");
        }

        ValidateEntrypoints(response.Entrypoints, $"{context}.entrypoints");
        ToriiContractManifestJson.ValidatePermissionDeclarations(response.Permissions, response.Entrypoints.Select(entry => entry.Authorization), context);
        if (response.Analysis is not null)
        {
            ValidateContractViewAnalysis(response.Analysis, $"{context}.analysis");
        }

        ValidateWarnings(response.Warnings, $"{context}.warnings");
        ValidateExactTokenText(response.RenderedSourceKind, $"{context}.rendered_source_kind");
        ValidateRenderedSourceText(response.RenderedSourceText, $"{context}.rendered_source_text");
        if (response.RenderedSourceKind == "verified_source" || response.SourceFiles.Count != 0
            || response.SourceImports.Count != 0 || response.SourcePackages.Count != 0 || response.SourceArtifacts.Count != 0)
        {
            try
            {
                _ = ToriiContractSourceBundle.Normalize(new ToriiContractVerifiedSourceSubmission
                {
                    SourceName = response.VerifiedSourceReference?.SourceName,
                    SourceText = response.RenderedSourceText,
                    Sources = response.SourceFiles,
                    Artifacts = response.SourceArtifacts,
                    Imports = response.SourceImports,
                    Packages = response.SourcePackages,
                }, requireRootName: false);
            }
            catch (ArgumentException error)
            {
                throw new JsonException($"{context} contains an invalid source bundle: {error.Message}", error);
            }
        }
        ValidateOptionalVerifiedSourceReference(response.VerifiedSourceReference, $"{context}.verified_source_ref");
        ToriiContractArtifactJson.Validate(response.NetworkId, response.ArtifactId, response.CodeHash, context);
    }

    internal static void ValidateContractViewAccessHints(ToriiContractViewAccessHints? response, string context)
    {
        if (response is null)
        {
            throw new JsonException($"{context} must not be null.");
        }

        ValidateTokenList(response.ReadKeys, $"{context}.read_keys");
        ValidateTokenList(response.WriteKeys, $"{context}.write_keys");
    }

    internal static void ValidateEntrypointParam(ToriiContractViewEntrypointParam? response, string context)
    {
        if (response is null)
        {
            throw new JsonException($"{context} must not be null.");
        }

        ValidateExactTokenText(response.Name, $"{context}.name");
        ValidateExactNonEmptyText(response.TypeName, $"{context}.type_name");
    }

    internal static void ValidateEntrypoint(ToriiContractViewEntrypoint? response, string context)
    {
        if (response is null)
        {
            throw new JsonException($"{context} must not be null.");
        }

        ValidateExactTokenText(response.Name, $"{context}.name");
        ValidateExactTokenText(response.Kind, $"{context}.kind");
        if (response.Kind is not ("kotoage" or "view" or "hajimari" or "kaizen"))
            throw new JsonException($"{context}.kind must be kotoage, view, hajimari, or kaizen.");
        ValidateEntrypointParams(response.Parameters, $"{context}.params");
        ValidateOptionalExactNonEmptyText(response.ReturnType, $"{context}.return_type");
        _ = ToriiContractManifestJson.BuildAuthorization(response.Authorization, $"{context}.authorization");
        if ((response.Kind is "hajimari" or "kaizen") != (response.Authorization is ToriiEntrypointAuthorizationV1.RuntimeLifecycle))
            throw new JsonException($"{context}.authorization must use RuntimeLifecycle exactly for lifecycle hooks.");
        ValidateTokenList(response.ReadKeys, $"{context}.read_keys");
        ValidateTokenList(response.WriteKeys, $"{context}.write_keys");
        ValidateTokenList(response.AccessHintsSkipped, $"{context}.access_hints_skipped");
        ValidateTokenList(response.Triggers, $"{context}.triggers");
    }

    internal static void ValidateContractViewSyscall(ToriiContractViewSyscall? response, string context)
    {
        if (response is null)
        {
            throw new JsonException($"{context} must not be null.");
        }

        ValidateOptionalExactTokenText(response.Name, $"{context}.name");
    }

    internal static void ValidateContractViewMemory(ToriiContractViewMemory? response, string context)
    {
        if (response is null)
        {
            throw new JsonException($"{context} must not be null.");
        }
    }

    internal static void ValidateContractViewAnalysis(ToriiContractViewAnalysis? response, string context)
    {
        if (response is null)
        {
            throw new JsonException($"{context} must not be null.");
        }

        if (response.Memory is null)
        {
            throw new JsonException($"{context}.memory is required.");
        }

        ValidateContractViewMemory(response.Memory, $"{context}.memory");
        ValidateSyscalls(response.Syscalls, $"{context}.syscalls");
    }

    internal static void ValidateVerifiedSourceReference(
        ToriiContractVerifiedSourceReference? response,
        string context)
    {
        if (response is null)
        {
            throw new JsonException($"{context} must not be null.");
        }

        ValidateExactNonEmptyText(response.Language, $"{context}.language");
        ValidateOptionalExactNonEmptyText(response.SourceName, $"{context}.source_name");
        ValidateExactNonEmptyText(response.SubmittedAt, $"{context}.submitted_at");
        ToriiSseEventJson.RequireOptionalExactSizedHex(response.ManifestIdHex, $"{context}.manifest_id_hex", 32);
        ToriiSseEventJson.RequireOptionalExactSizedHex(response.PayloadDigestHex, $"{context}.payload_digest_hex", 32);
    }

    internal static void ValidateVerifiedSourceJob(ToriiContractVerifiedSourceJob response, string context)
    {
        ArgumentNullException.ThrowIfNull(response);

        ValidateExactTokenText(response.JobId, $"{context}.job_id");
        ToriiSseEventJson.RequireExactSizedHex(response.CodeHash, $"{context}.code_hash", 32);
        ValidateExactTokenText(response.Status, $"{context}.status");
        ValidateExactNonEmptyText(response.SubmittedAt, $"{context}.submitted_at");
        ValidateOptionalExactNonEmptyText(response.CompletedAt, $"{context}.completed_at");
        ValidateOptionalExactNonEmptyText(response.Message, $"{context}.message");
        ToriiSseEventJson.RequireOptionalExactSizedHex(response.ActualCodeHash, $"{context}.actual_code_hash", 32);
        ValidateOptionalVerifiedSourceReference(response.VerifiedSourceReference, $"{context}.verified_source_ref");
        ToriiContractArtifactJson.Validate(response.NetworkId, response.ArtifactId, response.CodeHash, context);
    }

    internal static JsonException DirectMetadataErrorToJsonException(ArgumentException error, string context)
    {
        var paramName = error.ParamName ?? "metadata";
        var field = paramName switch
        {
            _ when TryMapCollectionField(paramName, nameof(ToriiContractCodeView.Permissions), "permissions", out var mapped) => mapped,
            _ when TryMapCollectionField(paramName, nameof(ToriiContractViewAccessHints.ReadKeys), "read_keys", out var mapped) => mapped,
            _ when TryMapCollectionField(paramName, nameof(ToriiContractViewAccessHints.WriteKeys), "write_keys", out var mapped) => mapped,
            _ when TryMapCollectionField(paramName, nameof(ToriiContractViewEntrypoint.Parameters), "params", out var mapped) => mapped,
            _ when TryMapCollectionField(paramName, nameof(ToriiContractViewEntrypoint.AccessHintsSkipped), "access_hints_skipped", out var mapped) => mapped,
            _ when TryMapCollectionField(paramName, nameof(ToriiContractViewEntrypoint.Triggers), "triggers", out var mapped) => mapped,
            _ when TryMapCollectionField(paramName, nameof(ToriiContractViewAnalysis.Syscalls), "syscalls", out var mapped) => mapped,
            _ when TryMapCollectionField(paramName, nameof(ToriiContractCodeView.Entrypoints), "entrypoints", out var mapped) => mapped,
            _ when TryMapCollectionField(paramName, nameof(ToriiContractCodeView.Warnings), "warnings", out var mapped) => mapped,
            nameof(ToriiContractCodeRecord.CodeHash) => "code_hash",
            nameof(ToriiContractCodeRecord.AbiHash) => "abi_hash",
            nameof(ToriiContractCodeRecord.Manifest) => "manifest",
            nameof(ToriiContractCodeView.DeclaredCodeHash) => "declared_code_hash",
            nameof(ToriiContractCodeView.CompilerFingerprint) => "compiler_fingerprint",
            nameof(ToriiContractCodeView.AccessHints) => "access_hints",
            nameof(ToriiContractCodeView.Analysis) => "analysis",
            nameof(ToriiContractCodeView.RenderedSourceKind) => "rendered_source_kind",
            nameof(ToriiContractCodeView.RenderedSourceText) => "rendered_source_text",
            nameof(ToriiContractViewEntrypointParam.Name) => "name",
            nameof(ToriiContractViewEntrypointParam.TypeName) => "type_name",
            nameof(ToriiContractViewEntrypoint.Kind) => "kind",
            nameof(ToriiContractViewEntrypoint.ReturnType) => "return_type",
            nameof(ToriiContractViewEntrypoint.Authorization) => "authorization",
            nameof(ToriiContractViewEntrypoint.AccessHintsComplete) => "access_hints_complete",
            nameof(ToriiContractViewSyscall.Number) => "number",
            nameof(ToriiContractViewSyscall.Count) => "count",
            nameof(ToriiContractViewAnalysis.InstructionCount) => "instruction_count",
            nameof(ToriiContractViewAnalysis.Memory) => "memory",
            nameof(ToriiContractVerifiedSourceReference.Language) => "language",
            nameof(ToriiContractVerifiedSourceReference.SourceName) => "source_name",
            nameof(ToriiContractVerifiedSourceReference.SubmittedAt) => "submitted_at",
            nameof(ToriiContractVerifiedSourceReference.ManifestIdHex) => "manifest_id_hex",
            nameof(ToriiContractVerifiedSourceReference.PayloadDigestHex) => "payload_digest_hex",
            nameof(ToriiContractVerifiedSourceReference.ContentLength) => "content_length",
            nameof(ToriiContractVerifiedSourceJob.JobId) => "job_id",
            nameof(ToriiContractVerifiedSourceJob.Status) => "status",
            nameof(ToriiContractVerifiedSourceJob.CompletedAt) => "completed_at",
            nameof(ToriiContractVerifiedSourceJob.Message) => "message",
            nameof(ToriiContractVerifiedSourceJob.ActualCodeHash) => "actual_code_hash",
            nameof(ToriiContractVerifiedSourceJob.VerifiedSourceReference) => "verified_source_ref",
            _ => paramName,
        };

        return new JsonException($"{context}.{field}: {error.Message}", error);
    }

    private static bool TryMapCollectionField(
        string paramName,
        string propertyName,
        string jsonName,
        out string mapped)
    {
        var prefix = propertyName + "[";
        if (paramName.StartsWith(prefix, StringComparison.Ordinal))
        {
            mapped = jsonName + paramName[propertyName.Length..];
            return true;
        }

        mapped = string.Empty;
        return false;
    }

    internal static ToriiContractCodeRecord ReadContractCodeRecord(
        ref Utf8JsonReader reader,
        string context)
    {
        return ToriiContractManifestJson.ReadRecord(ref reader, context);
    }

    internal static ToriiContractViewAccessHints ReadAccessHints(
        ref Utf8JsonReader reader,
        string context)
    {
        var payload = ToriiExplorerJson.ReadObject(ref reader, context);
        try
        {
            var response = new ToriiContractViewAccessHints
            {
                ReadKeys = ReadRequiredStringList(payload, "read_keys", $"{context}.read_keys"),
                WriteKeys = ReadRequiredStringList(payload, "write_keys", $"{context}.write_keys"),
            };
            ValidateContractViewAccessHints(response, context);
            return response;
        }
        catch (ArgumentException error) when (error.ParamName is not null)
        {
            throw DirectMetadataErrorToJsonException(error, context);
        }
    }

    internal static ToriiContractViewEntrypointParam ReadEntrypointParam(
        ref Utf8JsonReader reader,
        string context)
    {
        var payload = ToriiExplorerJson.ReadObject(ref reader, context);
        try
        {
            var response = new ToriiContractViewEntrypointParam
            {
                Name = ReadRequiredString(payload, "name", $"{context}.name"),
                TypeName = ReadRequiredString(payload, "type_name", $"{context}.type_name"),
            };
            ValidateEntrypointParam(response, context);
            return response;
        }
        catch (ArgumentException error) when (error.ParamName is not null)
        {
            throw DirectMetadataErrorToJsonException(error, context);
        }
    }

    internal static ToriiContractViewEntrypoint ReadEntrypoint(
        ref Utf8JsonReader reader,
        string context)
    {
        var payload = ToriiExplorerJson.ReadObject(ref reader, context);
        ToriiContractManifestJson.EnsureOnly(payload, context, "name", "kind", "params", "return_type",
            "authorization", "read_keys", "write_keys", "access_hints_complete", "access_hints_skipped", "triggers");
        try
        {
            var response = new ToriiContractViewEntrypoint
            {
                Name = ReadRequiredString(payload, "name", $"{context}.name"),
                Kind = ReadRequiredString(payload, "kind", $"{context}.kind"),
                Parameters = ReadRequiredObjectList<ToriiContractViewEntrypointParam>(
                    payload,
                    "params",
                    $"{context}.params",
                    "contract view entrypoint param"),
                ReturnType = ReadOptionalString(payload, "return_type", $"{context}.return_type"),
                Authorization = ToriiContractManifestJson.ParseAuthorization(payload["authorization"] as JsonObject ?? throw new JsonException($"{context}.authorization is required."), $"{context}.authorization"),
                ReadKeys = ReadRequiredStringList(payload, "read_keys", $"{context}.read_keys"),
                WriteKeys = ReadRequiredStringList(payload, "write_keys", $"{context}.write_keys"),
                AccessHintsComplete = ReadOptionalBool(
                    payload,
                    "access_hints_complete",
                    $"{context}.access_hints_complete"),
                AccessHintsSkipped = ReadRequiredStringList(
                    payload,
                    "access_hints_skipped",
                    $"{context}.access_hints_skipped"),
                Triggers = ReadRequiredStringList(payload, "triggers", $"{context}.triggers"),
            };
            ValidateEntrypoint(response, context);
            return response;
        }
        catch (ArgumentException error) when (error.ParamName is not null)
        {
            throw DirectMetadataErrorToJsonException(error, context);
        }
    }

    internal static ToriiContractViewSyscall ReadSyscall(ref Utf8JsonReader reader, string context)
    {
        var payload = ToriiExplorerJson.ReadObject(ref reader, context);
        try
        {
            var response = new ToriiContractViewSyscall
            {
                Number = ReadRequiredByte(payload, "number", $"{context}.number"),
                Name = ReadOptionalString(payload, "name", $"{context}.name"),
                Count = ReadRequiredUInt64(payload, "count", $"{context}.count"),
            };
            ValidateContractViewSyscall(response, context);
            return response;
        }
        catch (ArgumentException error) when (error.ParamName is not null)
        {
            throw DirectMetadataErrorToJsonException(error, context);
        }
    }

    internal static ToriiContractViewMemory ReadMemory(ref Utf8JsonReader reader, string context)
    {
        var payload = ToriiExplorerJson.ReadObject(ref reader, context);
        var response = new ToriiContractViewMemory
        {
            Load64 = ReadRequiredUInt64(payload, "load64", $"{context}.load64"),
            Store64 = ReadRequiredUInt64(payload, "store64", $"{context}.store64"),
            Load128 = ReadRequiredUInt64(payload, "load128", $"{context}.load128"),
            Store128 = ReadRequiredUInt64(payload, "store128", $"{context}.store128"),
        };
        ValidateContractViewMemory(response, context);
        return response;
    }

    internal static ToriiContractViewAnalysis ReadAnalysis(ref Utf8JsonReader reader, string context)
    {
        var payload = ToriiExplorerJson.ReadObject(ref reader, context);
        try
        {
            var response = new ToriiContractViewAnalysis
            {
                InstructionCount = ReadRequiredUInt64(payload, "instruction_count", $"{context}.instruction_count"),
                Memory = ReadRequiredObject<ToriiContractViewMemory>(
                    payload,
                    "memory",
                    $"{context}.memory",
                    "contract view memory"),
                Syscalls = ReadRequiredObjectList<ToriiContractViewSyscall>(
                    payload,
                    "syscalls",
                    $"{context}.syscalls",
                    "contract view syscall"),
            };
            ValidateContractViewAnalysis(response, context);
            return response;
        }
        catch (ArgumentException error) when (error.ParamName is not null)
        {
            throw DirectMetadataErrorToJsonException(error, context);
        }
    }

    internal static ToriiContractVerifiedSourceReference ReadVerifiedSourceReference(
        ref Utf8JsonReader reader,
        string context)
    {
        var payload = ToriiExplorerJson.ReadObject(ref reader, context);
        try
        {
            var response = new ToriiContractVerifiedSourceReference
            {
                Language = ReadRequiredString(payload, "language", $"{context}.language"),
                SourceName = ReadOptionalString(payload, "source_name", $"{context}.source_name"),
                SubmittedAt = ReadRequiredString(payload, "submitted_at", $"{context}.submitted_at"),
                ManifestIdHex = ReadOptionalString(payload, "manifest_id_hex", $"{context}.manifest_id_hex"),
                PayloadDigestHex = ReadOptionalString(payload, "payload_digest_hex", $"{context}.payload_digest_hex"),
                ContentLength = ReadOptionalUInt64(payload, "content_length", $"{context}.content_length"),
            };
            ValidateVerifiedSourceReference(response, context);
            return response;
        }
        catch (ArgumentException error) when (error.ParamName is not null)
        {
            throw DirectMetadataErrorToJsonException(error, context);
        }
    }

    internal static ToriiContractVerifiedSourceJob ReadVerifiedSourceJob(
        ref Utf8JsonReader reader,
        string context)
    {
        var payload = ToriiExplorerJson.ReadObject(ref reader, context);
        try
        {
            var response = new ToriiContractVerifiedSourceJob
            {
                NetworkId = ToriiContractArtifactJson.ReadNetworkId(payload, context),
                ArtifactId = ToriiContractArtifactJson.ReadArtifactId(payload, context),
                JobId = ReadRequiredString(payload, "job_id", $"{context}.job_id"),
                CodeHash = ReadRequiredString(payload, "code_hash", $"{context}.code_hash"),
                Status = ReadRequiredString(payload, "status", $"{context}.status"),
                SubmittedAt = ReadRequiredString(payload, "submitted_at", $"{context}.submitted_at"),
                CompletedAt = ReadOptionalString(payload, "completed_at", $"{context}.completed_at"),
                Message = ReadOptionalString(payload, "message", $"{context}.message"),
                ActualCodeHash = ReadOptionalString(payload, "actual_code_hash", $"{context}.actual_code_hash"),
                VerifiedSourceReference = ReadOptionalObject<ToriiContractVerifiedSourceReference>(
                    payload,
                    "verified_source_ref",
                    $"{context}.verified_source_ref",
                    "contract verified source reference"),
            };
            ValidateVerifiedSourceJob(response, context);
            return response;
        }
        catch (ArgumentException error) when (error.ParamName is not null)
        {
            throw DirectMetadataErrorToJsonException(error, context);
        }
    }

    internal static ToriiContractCodeView ReadContractCodeView(ref Utf8JsonReader reader, string context)
    {
        var payload = ToriiExplorerJson.ReadObject(ref reader, context);
        try
        {
            var response = new ToriiContractCodeView
            {
                NetworkId = ToriiContractArtifactJson.ReadNetworkId(payload, context),
                ArtifactId = ToriiContractArtifactJson.ReadArtifactId(payload, context),
                CodeHash = ReadRequiredString(payload, "code_hash", $"{context}.code_hash"),
                DeclaredCodeHash = ReadOptionalString(payload, "declared_code_hash", $"{context}.declared_code_hash"),
                AbiHash = ReadOptionalString(payload, "abi_hash", $"{context}.abi_hash"),
                CompilerFingerprint = ReadOptionalString(
                    payload,
                    "compiler_fingerprint",
                    $"{context}.compiler_fingerprint"),
                ByteLength = ReadOptionalUInt64(payload, "byte_len", $"{context}.byte_len"),
                Permissions = ReadPermissionDeclarations(payload, context),
                AccessHints = ReadOptionalObject<ToriiContractViewAccessHints>(
                    payload,
                    "access_hints",
                    $"{context}.access_hints",
                    "contract view access hints"),
                Entrypoints = ReadRequiredObjectList<ToriiContractViewEntrypoint>(
                    payload,
                    "entrypoints",
                    $"{context}.entrypoints",
                    "contract view entrypoint"),
                Analysis = ReadOptionalObject<ToriiContractViewAnalysis>(
                    payload,
                    "analysis",
                    $"{context}.analysis",
                    "contract view analysis"),
                Warnings = ReadRequiredStringList(payload, "warnings", $"{context}.warnings"),
                RenderedSourceKind = ReadRequiredString(
                    payload,
                    "rendered_source_kind",
                    $"{context}.rendered_source_kind"),
                RenderedSourceText = ReadRequiredString(
                    payload,
                    "rendered_source_text",
                    $"{context}.rendered_source_text"),
                SourceArtifacts = ReadRequiredObjectList<ToriiContractSourceArtifact>(payload, "source_artifacts", $"{context}.source_artifacts", "contract source artifact"),
                SourceFiles = payload.ContainsKey("source_files")
                    ? ReadRequiredObjectList<ToriiContractSourceFile>(payload, "source_files", $"{context}.source_files", "contract source file")
                    : Array.Empty<ToriiContractSourceFile>(),
                SourceImports = payload.ContainsKey("source_imports")
                    ? ReadRequiredObjectList<ToriiContractSourceImport>(payload, "source_imports", $"{context}.source_imports", "contract source import")
                    : Array.Empty<ToriiContractSourceImport>(),
                SourcePackages = payload.ContainsKey("source_packages")
                    ? ReadRequiredObjectList<ToriiContractSourcePackage>(payload, "source_packages", $"{context}.source_packages", "contract source package")
                    : Array.Empty<ToriiContractSourcePackage>(),
                VerifiedSourceReference = ReadOptionalObject<ToriiContractVerifiedSourceReference>(
                    payload,
                    "verified_source_ref",
                    $"{context}.verified_source_ref",
                    "contract verified source reference"),
            };
            ValidateContractCodeView(response, context);
            return response;
        }
        catch (ArgumentException error) when (error.ParamName is not null)
        {
            throw DirectMetadataErrorToJsonException(error, context);
        }
    }

    internal static void WriteContractCodeRecord(Utf8JsonWriter writer, ToriiContractCodeRecord value, string context)
    {
        ToriiContractManifestJson.WriteRecord(writer, value, context);
    }

    internal static void WriteAccessHints(Utf8JsonWriter writer, ToriiContractViewAccessHints value, string context)
    {
        ValidateContractViewAccessHints(value, context);

        writer.WriteStartObject();
        WriteStringList(writer, "read_keys", value.ReadKeys);
        WriteStringList(writer, "write_keys", value.WriteKeys);
        writer.WriteEndObject();
    }

    internal static void WriteEntrypointParam(
        Utf8JsonWriter writer,
        ToriiContractViewEntrypointParam value,
        string context)
    {
        ValidateEntrypointParam(value, context);

        writer.WriteStartObject();
        writer.WriteString("name", value.Name);
        writer.WriteString("type_name", value.TypeName);
        writer.WriteEndObject();
    }

    internal static void WriteEntrypoint(Utf8JsonWriter writer, ToriiContractViewEntrypoint value, string context)
    {
        ValidateEntrypoint(value, context);

        writer.WriteStartObject();
        writer.WriteString("name", value.Name);
        writer.WriteString("kind", value.Kind);
        writer.WritePropertyName("params");
        writer.WriteStartArray();
        for (var index = 0; index < value.Parameters.Count; index++)
        {
            WriteEntrypointParam(writer, value.Parameters[index], $"{context}.params[{index}]");
        }
        writer.WriteEndArray();
        WriteNullableString(writer, "return_type", value.ReturnType);
        writer.WritePropertyName("authorization");
        ToriiContractManifestJson.BuildAuthorization(value.Authorization, $"{context}.authorization").WriteTo(writer);
        WriteStringList(writer, "read_keys", value.ReadKeys);
        WriteStringList(writer, "write_keys", value.WriteKeys);
        if (value.AccessHintsComplete is bool complete)
        {
            writer.WriteBoolean("access_hints_complete", complete);
        }
        else
        {
            writer.WriteNull("access_hints_complete");
        }
        WriteStringList(writer, "access_hints_skipped", value.AccessHintsSkipped);
        WriteStringList(writer, "triggers", value.Triggers);
        writer.WriteEndObject();
    }

    internal static void WriteSyscall(Utf8JsonWriter writer, ToriiContractViewSyscall value, string context)
    {
        ValidateContractViewSyscall(value, context);

        writer.WriteStartObject();
        writer.WriteNumber("number", value.Number);
        WriteNullableString(writer, "name", value.Name);
        writer.WriteNumber("count", value.Count);
        writer.WriteEndObject();
    }

    internal static void WriteMemory(Utf8JsonWriter writer, ToriiContractViewMemory value, string context)
    {
        ValidateContractViewMemory(value, context);

        writer.WriteStartObject();
        writer.WriteNumber("load64", value.Load64);
        writer.WriteNumber("store64", value.Store64);
        writer.WriteNumber("load128", value.Load128);
        writer.WriteNumber("store128", value.Store128);
        writer.WriteEndObject();
    }

    internal static void WriteAnalysis(Utf8JsonWriter writer, ToriiContractViewAnalysis value, string context)
    {
        ValidateContractViewAnalysis(value, context);

        writer.WriteStartObject();
        writer.WriteNumber("instruction_count", value.InstructionCount);
        writer.WritePropertyName("memory");
        WriteMemory(writer, value.Memory, $"{context}.memory");
        writer.WritePropertyName("syscalls");
        writer.WriteStartArray();
        for (var index = 0; index < value.Syscalls.Count; index++)
        {
            WriteSyscall(writer, value.Syscalls[index], $"{context}.syscalls[{index}]");
        }
        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    internal static void WriteVerifiedSourceReference(
        Utf8JsonWriter writer,
        ToriiContractVerifiedSourceReference value,
        string context)
    {
        ValidateVerifiedSourceReference(value, context);

        writer.WriteStartObject();
        writer.WriteString("language", value.Language);
        WriteNullableString(writer, "source_name", value.SourceName);
        writer.WriteString("submitted_at", value.SubmittedAt);
        WriteNullableString(writer, "manifest_id_hex", value.ManifestIdHex);
        WriteNullableString(writer, "payload_digest_hex", value.PayloadDigestHex);
        if (value.ContentLength is ulong contentLength)
        {
            writer.WriteNumber("content_length", contentLength);
        }
        else
        {
            writer.WriteNull("content_length");
        }
        writer.WriteEndObject();
    }

    internal static void WriteVerifiedSourceJob(
        Utf8JsonWriter writer,
        ToriiContractVerifiedSourceJob value,
        string context)
    {
        ValidateVerifiedSourceJob(value, context);

        writer.WriteStartObject();
        ToriiContractArtifactJson.WriteFields(writer, value.NetworkId, value.ArtifactId);
        writer.WriteString("job_id", value.JobId);
        writer.WriteString("code_hash", value.CodeHash);
        writer.WriteString("status", value.Status);
        writer.WriteString("submitted_at", value.SubmittedAt);
        WriteNullableString(writer, "completed_at", value.CompletedAt);
        WriteNullableString(writer, "message", value.Message);
        WriteNullableString(writer, "actual_code_hash", value.ActualCodeHash);
        writer.WritePropertyName("verified_source_ref");
        if (value.VerifiedSourceReference is null)
        {
            writer.WriteNullValue();
        }
        else
        {
            WriteVerifiedSourceReference(
                writer,
                value.VerifiedSourceReference,
                $"{context}.verified_source_ref");
        }
        writer.WriteEndObject();
    }

    internal static void WriteContractCodeView(Utf8JsonWriter writer, ToriiContractCodeView value, string context)
    {
        ValidateContractCodeView(value, context);

        writer.WriteStartObject();
        ToriiContractArtifactJson.WriteFields(writer, value.NetworkId, value.ArtifactId);
        writer.WriteString("code_hash", value.CodeHash);
        WriteNullableString(writer, "declared_code_hash", value.DeclaredCodeHash);
        WriteNullableString(writer, "abi_hash", value.AbiHash);
        WriteNullableString(writer, "compiler_fingerprint", value.CompilerFingerprint);
        if (value.ByteLength is ulong byteLength)
        {
            writer.WriteNumber("byte_len", byteLength);
        }
        else
        {
            writer.WriteNull("byte_len");
        }
        writer.WritePropertyName("permissions");
        writer.WriteStartArray();
        foreach (var permission in value.Permissions)
            ToriiContractManifestJson.BuildPermissionDeclaration(permission, $"{context}.permissions").WriteTo(writer);
        writer.WriteEndArray();
        writer.WritePropertyName("access_hints");
        if (value.AccessHints is null)
        {
            writer.WriteNullValue();
        }
        else
        {
            WriteAccessHints(writer, value.AccessHints, $"{context}.access_hints");
        }
        writer.WritePropertyName("entrypoints");
        writer.WriteStartArray();
        for (var index = 0; index < value.Entrypoints.Count; index++)
        {
            WriteEntrypoint(writer, value.Entrypoints[index], $"{context}.entrypoints[{index}]");
        }
        writer.WriteEndArray();
        writer.WritePropertyName("analysis");
        if (value.Analysis is null)
        {
            writer.WriteNullValue();
        }
        else
        {
            WriteAnalysis(writer, value.Analysis, $"{context}.analysis");
        }
        WriteStringList(writer, "warnings", value.Warnings);
        writer.WriteString("rendered_source_kind", value.RenderedSourceKind);
        writer.WriteString("rendered_source_text", value.RenderedSourceText);
        writer.WritePropertyName("source_artifacts");
        JsonSerializer.Serialize(writer, value.SourceArtifacts);
        if (value.SourceFiles.Count != 0)
        {
            writer.WritePropertyName("source_files");
            JsonSerializer.Serialize(writer, value.SourceFiles);
        }
        if (value.SourceImports.Count != 0)
        {
            writer.WritePropertyName("source_imports");
            JsonSerializer.Serialize(writer, value.SourceImports);
        }
        if (value.SourcePackages.Count != 0)
        {
            writer.WritePropertyName("source_packages");
            JsonSerializer.Serialize(writer, value.SourcePackages);
        }
        writer.WritePropertyName("verified_source_ref");
        if (value.VerifiedSourceReference is null)
        {
            writer.WriteNullValue();
        }
        else
        {
            WriteVerifiedSourceReference(
                writer,
                value.VerifiedSourceReference,
                $"{context}.verified_source_ref");
        }
        writer.WriteEndObject();
    }

    private static void ValidateOptionalVerifiedSourceReference(
        ToriiContractVerifiedSourceReference? response,
        string context)
    {
        if (response is not null)
        {
            ValidateVerifiedSourceReference(response, context);
        }
    }

    private static void ValidateEntrypoints(IReadOnlyList<ToriiContractViewEntrypoint>? entrypoints, string context)
    {
        if (entrypoints is null)
        {
            throw new JsonException($"{context} is required.");
        }

        for (var index = 0; index < entrypoints.Count; index++)
        {
            ValidateEntrypoint(entrypoints[index], $"{context}[{index}]");
        }
    }

    private static void ValidateEntrypointParams(
        IReadOnlyList<ToriiContractViewEntrypointParam>? parameters,
        string context)
    {
        if (parameters is null)
        {
            throw new JsonException($"{context} is required.");
        }

        for (var index = 0; index < parameters.Count; index++)
        {
            ValidateEntrypointParam(parameters[index], $"{context}[{index}]");
        }
    }

    private static void ValidateSyscalls(IReadOnlyList<ToriiContractViewSyscall>? syscalls, string context)
    {
        if (syscalls is null)
        {
            throw new JsonException($"{context} is required.");
        }

        for (var index = 0; index < syscalls.Count; index++)
        {
            ValidateContractViewSyscall(syscalls[index], $"{context}[{index}]");
        }
    }

    private static void ValidateTokenList(IReadOnlyList<string>? values, string context)
    {
        if (values is null)
        {
            throw new JsonException($"{context} is required.");
        }

        for (var index = 0; index < values.Count; index++)
        {
            ValidateExactTokenText(values[index], $"{context}[{index}]");
        }
    }

    private static void ValidateWarnings(IReadOnlyList<string>? values, string context)
    {
        if (values is null)
        {
            throw new JsonException($"{context} is required.");
        }

        for (var index = 0; index < values.Count; index++)
        {
            ValidateExactNonEmptyText(values[index], $"{context}[{index}]");
        }
    }

    private static IReadOnlyList<ToriiContractPermissionDescriptorV1> ReadPermissionDeclarations(JsonObject payload, string context)
    {
        if (payload["permissions"] is not JsonArray values)
            throw new JsonException($"{context}.permissions is required and must be an array.");
        return values.Select((value, index) => ToriiContractManifestJson.ParsePermissionDeclaration(
            value as JsonObject ?? throw new JsonException($"{context}.permissions[{index}] must be an object."),
            $"{context}.permissions[{index}]")).ToArray();
    }

    private static IReadOnlyList<T> ReadRequiredObjectList<T>(
        JsonObject payload,
        string propertyName,
        string field,
        string itemContext)
    {
        if (!payload.TryGetPropertyValue(propertyName, out var value) || value is null)
        {
            throw new JsonException($"{field} is required.");
        }

        if (value is not JsonArray items)
        {
            throw new JsonException($"{field} must be an array.");
        }

        var result = new List<T>(items.Count);
        for (var index = 0; index < items.Count; index++)
        {
            var item = items[index];
            if (item is null)
            {
                throw new JsonException($"{field}[{index}] must not be null.");
            }

            try
            {
                result.Add(item.Deserialize<T>() ?? throw new JsonException($"{field}[{index}] must not be null."));
            }
            catch (JsonException exception)
            {
                throw ToriiExplorerJson.RewriteContext(exception, itemContext, $"{field}[{index}]");
            }
        }

        return result;
    }

    private static IReadOnlyList<string> ReadRequiredStringList(JsonObject payload, string propertyName, string field)
    {
        if (!payload.TryGetPropertyValue(propertyName, out var value) || value is null)
        {
            throw new JsonException($"{field} is required.");
        }

        if (value is not JsonArray items)
        {
            throw new JsonException($"{field} must be an array.");
        }

        var result = new List<string>(items.Count);
        for (var index = 0; index < items.Count; index++)
        {
            if (items[index] is null)
            {
                throw new JsonException($"{field}[{index}] must not be null.");
            }

            if (items[index] is JsonValue jsonValue && jsonValue.TryGetValue<string>(out var text))
            {
                result.Add(text);
                continue;
            }

            throw new JsonException($"{field}[{index}] must be a string.");
        }

        return result;
    }

    private static T ReadRequiredObject<T>(
        JsonObject payload,
        string propertyName,
        string field,
        string nestedContext)
    {
        if (!payload.TryGetPropertyValue(propertyName, out var value) || value is null)
        {
            throw new JsonException($"{field} is required.");
        }

        if (value is not JsonObject)
        {
            throw new JsonException($"{field} must be an object.");
        }

        try
        {
            return value.Deserialize<T>() ?? throw new JsonException($"{field} must not be null.");
        }
        catch (JsonException exception)
        {
            throw ToriiExplorerJson.RewriteContext(exception, nestedContext, field);
        }
    }

    private static T? ReadOptionalObject<T>(
        JsonObject payload,
        string propertyName,
        string field,
        string nestedContext)
    {
        return ToriiExplorerJson.ReadOptionalObject<T>(payload, propertyName, field, nestedContext);
    }

    private static string ReadRequiredString(JsonObject payload, string propertyName, string field)
    {
        return ToriiExplorerJson.ReadRequiredString(payload, propertyName, field);
    }

    private static string? ReadOptionalString(JsonObject payload, string propertyName, string field)
    {
        return ToriiExplorerJson.ReadOptionalString(payload, propertyName, field);
    }

    private static ulong ReadRequiredUInt64(JsonObject payload, string propertyName, string field)
    {
        return ToriiExplorerJson.ReadRequiredUInt64(payload, propertyName, field);
    }

    private static ulong? ReadOptionalUInt64(JsonObject payload, string propertyName, string field)
    {
        return ToriiExplorerJson.ReadOptionalUInt64(payload, propertyName, field);
    }

    private static byte ReadRequiredByte(JsonObject payload, string propertyName, string field)
    {
        var value = ToriiExplorerJson.ReadRequiredUInt64(payload, propertyName, field);
        if (value > byte.MaxValue)
        {
            throw new JsonException($"{field} must fit in an unsigned 8-bit integer.");
        }

        return (byte)value;
    }

    private static bool? ReadOptionalBool(JsonObject payload, string propertyName, string field)
    {
        if (!payload.TryGetPropertyValue(propertyName, out var value) || value is null)
        {
            return null;
        }

        if (value is JsonValue jsonValue && jsonValue.TryGetValue<bool>(out var boolean))
        {
            return boolean;
        }

        throw new JsonException($"{field} must be a boolean.");
    }

    private static void WriteNullableString(Utf8JsonWriter writer, string propertyName, string? value)
    {
        if (value is null)
        {
            writer.WriteNull(propertyName);
        }
        else
        {
            writer.WriteString(propertyName, value);
        }
    }

    private static void WriteStringList(Utf8JsonWriter writer, string propertyName, IReadOnlyList<string> values)
    {
        writer.WritePropertyName(propertyName);
        writer.WriteStartArray();
        foreach (var value in values)
        {
            writer.WriteStringValue(value);
        }
        writer.WriteEndArray();
    }

    private static void ValidateOptionalExactSizedHex(string? value, string field, int expectedBytes)
    {
        if (value is not null)
        {
            ToriiSseEventJson.RequireExactSizedHex(value, field, expectedBytes);
        }
    }

    private static void ValidateOptionalExactNonEmptyText(string? value, string field)
    {
        if (value is not null)
        {
            ValidateExactNonEmptyText(value, field);
        }
    }

    private static void ValidateOptionalExactTokenText(string? value, string field)
    {
        if (value is not null)
        {
            ValidateExactTokenText(value, field);
        }
    }

    private static string ValidateExactTokenText(string? value, string field)
    {
        var text = ValidateExactNonEmptyText(value, field);
        if (text.Any(char.IsWhiteSpace))
        {
            throw new JsonException($"{field} must not contain whitespace.");
        }

        return text;
    }

    private static string ValidateExactNonEmptyText(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new JsonException($"{field} must be a non-empty string.");
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new JsonException($"{field} must not contain surrounding whitespace.");
        }

        if (value.Any(char.IsControl))
        {
            throw new JsonException($"{field} must not contain control characters.");
        }

        return value;
    }

    private static void ValidateRenderedSourceText(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new JsonException($"{field} must be non-empty rendered source text.");
        }

        if (value.IndexOf('\0') >= 0)
        {
            throw new JsonException($"{field} must not contain NUL characters.");
        }
    }
}

internal sealed class ToriiContractCodeRecordJsonConverter : JsonConverter<ToriiContractCodeRecord>
{
    public override bool HandleNull => true;

    public override ToriiContractCodeRecord Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        return ToriiContractMetadataJson.ReadContractCodeRecord(ref reader, "contract code response");
    }

    public override void Write(Utf8JsonWriter writer, ToriiContractCodeRecord value, JsonSerializerOptions options)
    {
        ToriiContractMetadataJson.WriteContractCodeRecord(writer, value, "contract code response");
    }
}

internal sealed class ToriiContractViewAccessHintsJsonConverter : JsonConverter<ToriiContractViewAccessHints>
{
    public override bool HandleNull => true;

    public override ToriiContractViewAccessHints Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        return ToriiContractMetadataJson.ReadAccessHints(ref reader, "contract view access hints");
    }

    public override void Write(Utf8JsonWriter writer, ToriiContractViewAccessHints value, JsonSerializerOptions options)
    {
        ToriiContractMetadataJson.WriteAccessHints(writer, value, "contract view access hints");
    }
}

internal sealed class ToriiContractViewEntrypointParamJsonConverter :
    JsonConverter<ToriiContractViewEntrypointParam>
{
    public override bool HandleNull => true;

    public override ToriiContractViewEntrypointParam Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        return ToriiContractMetadataJson.ReadEntrypointParam(ref reader, "contract view entrypoint param");
    }

    public override void Write(
        Utf8JsonWriter writer,
        ToriiContractViewEntrypointParam value,
        JsonSerializerOptions options)
    {
        ToriiContractMetadataJson.WriteEntrypointParam(writer, value, "contract view entrypoint param");
    }
}

internal sealed class ToriiContractViewEntrypointJsonConverter : JsonConverter<ToriiContractViewEntrypoint>
{
    public override bool HandleNull => true;

    public override ToriiContractViewEntrypoint Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        return ToriiContractMetadataJson.ReadEntrypoint(ref reader, "contract view entrypoint");
    }

    public override void Write(Utf8JsonWriter writer, ToriiContractViewEntrypoint value, JsonSerializerOptions options)
    {
        ToriiContractMetadataJson.WriteEntrypoint(writer, value, "contract view entrypoint");
    }
}

internal sealed class ToriiContractViewSyscallJsonConverter : JsonConverter<ToriiContractViewSyscall>
{
    public override bool HandleNull => true;

    public override ToriiContractViewSyscall Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        return ToriiContractMetadataJson.ReadSyscall(ref reader, "contract view syscall");
    }

    public override void Write(Utf8JsonWriter writer, ToriiContractViewSyscall value, JsonSerializerOptions options)
    {
        ToriiContractMetadataJson.WriteSyscall(writer, value, "contract view syscall");
    }
}

internal sealed class ToriiContractViewMemoryJsonConverter : JsonConverter<ToriiContractViewMemory>
{
    public override bool HandleNull => true;

    public override ToriiContractViewMemory Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        return ToriiContractMetadataJson.ReadMemory(ref reader, "contract view memory");
    }

    public override void Write(Utf8JsonWriter writer, ToriiContractViewMemory value, JsonSerializerOptions options)
    {
        ToriiContractMetadataJson.WriteMemory(writer, value, "contract view memory");
    }
}

internal sealed class ToriiContractViewAnalysisJsonConverter : JsonConverter<ToriiContractViewAnalysis>
{
    public override bool HandleNull => true;

    public override ToriiContractViewAnalysis Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        return ToriiContractMetadataJson.ReadAnalysis(ref reader, "contract view analysis");
    }

    public override void Write(Utf8JsonWriter writer, ToriiContractViewAnalysis value, JsonSerializerOptions options)
    {
        ToriiContractMetadataJson.WriteAnalysis(writer, value, "contract view analysis");
    }
}

internal sealed class ToriiContractVerifiedSourceReferenceJsonConverter :
    JsonConverter<ToriiContractVerifiedSourceReference>
{
    public override bool HandleNull => true;

    public override ToriiContractVerifiedSourceReference Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        return ToriiContractMetadataJson.ReadVerifiedSourceReference(
            ref reader,
            "contract verified source reference");
    }

    public override void Write(
        Utf8JsonWriter writer,
        ToriiContractVerifiedSourceReference value,
        JsonSerializerOptions options)
    {
        ToriiContractMetadataJson.WriteVerifiedSourceReference(
            writer,
            value,
            "contract verified source reference");
    }
}

internal sealed class ToriiContractVerifiedSourceJobJsonConverter : JsonConverter<ToriiContractVerifiedSourceJob>
{
    public override bool HandleNull => true;

    public override ToriiContractVerifiedSourceJob Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        return ToriiContractMetadataJson.ReadVerifiedSourceJob(ref reader, "contract verified-source job response");
    }

    public override void Write(
        Utf8JsonWriter writer,
        ToriiContractVerifiedSourceJob value,
        JsonSerializerOptions options)
    {
        ToriiContractMetadataJson.WriteVerifiedSourceJob(writer, value, "contract verified-source job response");
    }
}

internal sealed class ToriiContractCodeViewJsonConverter : JsonConverter<ToriiContractCodeView>
{
    public override bool HandleNull => true;

    public override ToriiContractCodeView Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        return ToriiContractMetadataJson.ReadContractCodeView(ref reader, "contract code-view response");
    }

    public override void Write(Utf8JsonWriter writer, ToriiContractCodeView value, JsonSerializerOptions options)
    {
        ToriiContractMetadataJson.WriteContractCodeView(writer, value, "contract code-view response");
    }
}
