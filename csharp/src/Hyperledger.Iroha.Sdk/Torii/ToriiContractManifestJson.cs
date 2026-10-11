using Hyperledger.Iroha.Norito;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Hyperledger.Iroha.Torii;

internal static class ToriiContractManifestJson
{
    private const int MaxSchemaNodes = 256;
    private const int MaxSchemaDepth = 256;
    private const int MaxBoundaryWords = 8192;
    // Mirrors ivm_abi::state_value::MAX_STATE_VALUE_NODES.
    private const int MaxStateTypeDepth = 256;
    private const int MaxStateTypeNodes = 256;

    // BEGIN GENERATED: kotodama-v1-validator-policy
    private static readonly HashSet<string> Keywords = new(StringComparer.Ordinal)
    {
        "as",
        "permission",
        "authorize",
        "break",
        "const",
        "continue",
        "else",
        "enum",
        "error",
        "export",
        "false",
        "fn",
        "for",
        "hajimari",
        "始まり",
        "if",
        "import",
        "in",
        "include",
        "kaizen",
        "改善",
        "kotoage",
        "言挙げ",
        "let",
        "match",
        "module",
        "return",
        "seiyaku",
        "誓約",
        "state",
        "struct",
        "event",
        "emit",
        "trigger",
        "true",
        "var",
        "view",
        "Amount",
    };
    private static readonly HashSet<string> ReservedDeclarationNames = new(StringComparer.Ordinal)
    {
        "int",
        "decimal",
        "quantity",
        "bool",
        "string",
        "bytes",
        "Json",
        "AccountId",
        "AssetDefinitionId",
        "AssetId",
        "DomainId",
        "Name",
        "NftId",
        "DataSpaceId",
        "Option",
        "Result",
        "List",
        "ListError",
        "NumericError",
        "StateMap",
        "StateCursor",
        "StatePage",
        "Secret",
        "AccountView",
        "AssetView",
        "AssetDefinitionView",
        "DomainView",
        "NftView",
        "QueryPage",
        "AxtDescriptor",
        "AxtAnchoredSpendV1",
        "ProofBlob",
        "SoracloudRequest",
        "SoracloudResponse",
        "state_map_get",
        "__kotodama_state_page",
        "__kotodama_state_take",
        "__kotodama_list_len",
        "__kotodama_list_get",
        "__kotodama_list_set",
        "__kotodama_list_push",
        "__kotodama_list_try_set",
        "__kotodama_list_try_push",
        "__kotodama_list_pop",
        "__kotodama_list_contains",
        "__kotodama_list_take",
        "__kotodama_list_enumerate",
        "__kotodama_decimal_div_round",
        "__kotodama_decimal_mul_div_round",
        "__kotodama_quantity_mul_div_round",
        "__kotodama_quantity_div_round",
        "__kotodama_quantity_ratio_round",
        "__kotodama_decimal_to_int_trunc",
        "__kotodama_decimal_to_int_round",
        "__kotodama_option_ok_or",
        "__kotodama_result_or_err",
    };
    private static readonly HashSet<string> RetiredNumericTypeNames = new(StringComparer.Ordinal)
    {
        "i8",
        "i16",
        "i32",
        "i64",
        "i128",
        "isize",
        "u8",
        "u16",
        "u32",
        "u64",
        "u128",
        "usize",
        "num",
        "Int",
        "Integer",
        "float",
        "f32",
        "f64",
        "Decimal",
        "Fixed",
        "FixedPoint",
        "Amount",
        "amount",
        "money",
        "Quantity",
        "number",
    };
    private static readonly HashSet<string> StateMapKeyTypeNames = new(StringComparer.Ordinal)
    {
        "int",
        "decimal",
        "quantity",
        "bool",
        "string",
        "bytes",
        "DataSpaceId",
        "AccountId",
        "AssetDefinitionId",
        "AssetId",
        "NftId",
        "DomainId",
        "Name",
    };
    private static readonly HashSet<string> DynamicAccessBoundKinds = new(StringComparer.Ordinal)
    {
        "page",
        "take",
    };
    private const uint MaxDynamicAccessKeys = 64;
    // END GENERATED: kotodama-v1-validator-policy
    private static readonly HashSet<string> StateScalarTypeNames = new(StringComparer.Ordinal)
    {
        "int",
        "decimal",
        "quantity",
        "bool",
        "string",
        "bytes",
        "DataSpaceId",
        "AccountId",
        "AssetDefinitionId",
        "AssetId",
        "NftId",
        "DomainId",
        "Name",
        "Json",
    };

    private static readonly IReadOnlyDictionary<string, ToriiEntrypointValueKindV1> ValueKinds =
        new Dictionary<string, ToriiEntrypointValueKindV1>(StringComparer.Ordinal)
        {
            ["Int"] = ToriiEntrypointValueKindV1.Int,
            ["Decimal"] = ToriiEntrypointValueKindV1.Decimal,
            ["Quantity"] = ToriiEntrypointValueKindV1.Quantity,
            ["Bool"] = ToriiEntrypointValueKindV1.Bool,
            ["String"] = ToriiEntrypointValueKindV1.String,
            ["Json"] = ToriiEntrypointValueKindV1.Json,
            ["Name"] = ToriiEntrypointValueKindV1.Name,
            ["AccountId"] = ToriiEntrypointValueKindV1.AccountId,
            ["AssetDefinitionId"] = ToriiEntrypointValueKindV1.AssetDefinitionId,
            ["AssetId"] = ToriiEntrypointValueKindV1.AssetId,
            ["DomainId"] = ToriiEntrypointValueKindV1.DomainId,
            ["NftId"] = ToriiEntrypointValueKindV1.NftId,
            ["DataSpaceId"] = ToriiEntrypointValueKindV1.DataSpaceId,
            ["Blob"] = ToriiEntrypointValueKindV1.Blob,
        };

    internal static ToriiContractManifest ReadManifest(ref Utf8JsonReader reader, string context)
    {
        return ParseManifest(ToriiExplorerJson.ReadObject(ref reader, context), context);
    }

    internal static ToriiContractCodeRecord ReadRecord(ref Utf8JsonReader reader, string context)
    {
        var root = ToriiExplorerJson.ReadObject(ref reader, context);
        EnsureOnly(root, context, "network_id", "artifact_id", "manifest", "code_hash", "abi_hash");
        var manifestObject = RequiredObject(root, "manifest", $"{context}.manifest");
        var manifest = ParseManifest(manifestObject, $"{context}.manifest");
        var codeHash = OptionalConvenienceHash(root, "code_hash", $"{context}.code_hash");
        var abiHash = OptionalConvenienceHash(root, "abi_hash", $"{context}.abi_hash");
        if (!string.Equals(codeHash, manifest.CodeHash, StringComparison.Ordinal))
        {
            throw new JsonException($"{context}.code_hash must exactly match manifest.code_hash.");
        }
        if (!string.Equals(abiHash, manifest.AbiHash, StringComparison.Ordinal))
        {
            throw new JsonException($"{context}.abi_hash must exactly match manifest.abi_hash.");
        }
        var artifactId = ToriiContractArtifactJson.ReadArtifactId(root, context);
        ToriiContractArtifactJson.ValidateCodeHash(artifactId, codeHash, context);
        return new ToriiContractCodeRecord
        {
            NetworkId = ToriiContractArtifactJson.ReadNetworkId(root, context),
            ArtifactId = artifactId,
            Manifest = manifest,
            CodeHash = codeHash,
            AbiHash = abiHash,
        };
    }

    internal static void ValidateRecord(ToriiContractCodeRecord value, string context)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Manifest is null)
        {
            throw new JsonException($"{context}.manifest is required.");
        }
        ToriiContractArtifactJson.Validate(value.NetworkId, value.ArtifactId, value.CodeHash, context);
        _ = BuildManifestNode(value.Manifest, $"{context}.manifest");
        ValidateConvenienceHash(value.CodeHash, $"{context}.code_hash");
        ValidateConvenienceHash(value.AbiHash, $"{context}.abi_hash");
        if (!string.Equals(value.CodeHash, value.Manifest.CodeHash, StringComparison.Ordinal)
            || !string.Equals(value.AbiHash, value.Manifest.AbiHash, StringComparison.Ordinal))
        {
            throw new JsonException($"{context} convenience hashes must exactly match the manifest hashes.");
        }
    }

    internal static void WriteRecord(Utf8JsonWriter writer, ToriiContractCodeRecord value, string context)
    {
        ValidateRecord(value, context);
        var root = new JsonObject
        {
            ["network_id"] = value.NetworkId.ToString(),
            ["artifact_id"] = value.ArtifactId.ToJsonNode(),
            ["manifest"] = BuildManifestNode(value.Manifest, $"{context}.manifest"),
            ["code_hash"] = value.CodeHash,
            ["abi_hash"] = value.AbiHash,
        };
        root.WriteTo(writer);
    }

    internal static void WriteManifest(Utf8JsonWriter writer, ToriiContractManifest value, string context)
    {
        ArgumentNullException.ThrowIfNull(value);
        BuildManifestNode(value, context).WriteTo(writer);
    }

    private static ToriiContractManifest ParseManifest(JsonObject root, string context)
    {
        EnsureOnly(
            root,
            context,
            "seiyaku_name",
            "code_hash",
            "abi_hash",
            "compiler_fingerprint",
            "features_bitmap",
            "access_set_hints",
            "permissions",
            "events",
            "entrypoints",
            "states",
            "error_types",
            "enum_types",
            "error_messages",
            "kotoba",
            "provenance");

        var seiyakuName = OptionalExactString(root, "seiyaku_name", $"{context}.seiyaku_name");
        if (seiyakuName is not null && !IsCanonicalTypeDeclarationIdentifier(seiyakuName))
        {
            throw new JsonException($"{context}.seiyaku_name must be a canonical Kotodama declaration identifier.");
        }

        var permissions = RequiredObjectList(root, "permissions", $"{context}.permissions", ParsePermissionDeclaration);
        var events = RequiredObjectList(root, "events", $"{context}.events", ParseEvent);
        var enumTypes = RequiredObjectList(root, "enum_types", $"{context}.enum_types", ParseEnumType);
        var entrypoints = OptionalObjectList(root, "entrypoints", $"{context}.entrypoints", ParseEntrypoint);
        var states = OptionalObjectList(root, "states", $"{context}.states", ParseState);
        var errorTypes = OptionalObjectList(root, "error_types", $"{context}.error_types", ParseErrorType);
        var errorMessages = OptionalObjectList(root, "error_messages", $"{context}.error_messages", ParseErrorMessage);
        var kotoba = OptionalObjectList(root, "kotoba", $"{context}.kotoba", ParseKotobaEntry);
        var accessSetHints = OptionalObject(root, "access_set_hints", $"{context}.access_set_hints")
            is { } access ? ParseAccessSetHints(access, $"{context}.access_set_hints") : null;
        var featuresBitmap = OptionalUInt64(root, "features_bitmap", $"{context}.features_bitmap");
        if (featuresBitmap is > 3)
        {
            throw new JsonException($"{context}.features_bitmap contains unsupported Kotodama V1 bits.");
        }
        ValidatePermissionDeclarations(permissions, (entrypoints ?? Array.Empty<ToriiContractEntrypointDescriptor>()).Select(entry => entry.Authorization), context);
        ValidateManifestCollections(entrypoints, states, errorTypes, enumTypes, events, errorMessages, kotoba, context);
        ValidateDynamicAccessHintStateMaps(accessSetHints, states, context);

        return new ToriiContractManifest
        {
            SeiyakuName = seiyakuName,
            CodeHash = OptionalManifestHash(root, "code_hash", $"{context}.code_hash"),
            AbiHash = OptionalManifestHash(root, "abi_hash", $"{context}.abi_hash"),
            CompilerFingerprint = OptionalExactString(
                root,
                "compiler_fingerprint",
                $"{context}.compiler_fingerprint"),
            FeaturesBitmap = featuresBitmap,
            AccessSetHints = accessSetHints,
            Permissions = permissions,
            Events = events,
            EnumTypes = enumTypes,
            Entrypoints = entrypoints,
            States = states,
            ErrorTypes = errorTypes,
            ErrorMessages = errorMessages,
            Kotoba = kotoba,
            Provenance = OptionalObject(root, "provenance", $"{context}.provenance")
                is { } provenance ? ParseProvenance(provenance, $"{context}.provenance") : null,
        };
    }

    private static ToriiContractAccessSetHints ParseAccessSetHints(JsonObject root, string context)
    {
        EnsureOnly(root, context, "read_keys", "write_keys", "dynamic_reads", "dynamic_writes");
        return new ToriiContractAccessSetHints
        {
            ReadKeys = RequiredStringList(root, "read_keys", $"{context}.read_keys"),
            WriteKeys = RequiredStringList(root, "write_keys", $"{context}.write_keys"),
            DynamicReads = DefaultObjectList(
                root,
                "dynamic_reads",
                $"{context}.dynamic_reads",
                ParseDynamicHint),
            DynamicWrites = DefaultObjectList(
                root,
                "dynamic_writes",
                $"{context}.dynamic_writes",
                ParseDynamicHint),
        };
    }

    private static ToriiContractDynamicAccessHint ParseDynamicHint(JsonObject root, string context)
    {
        EnsureOnly(root, context, "base_key", "key_type", "bound_kind", "max_keys");
        var baseKey = RequiredExactString(root, "base_key", $"{context}.base_key");
        if (!IsCanonicalDynamicAccessBaseKey(baseKey))
        {
            throw new JsonException(
                $"{context}.base_key must be state: followed by one canonical state declaration identifier.");
        }
        var keyType = RequiredExactString(root, "key_type", $"{context}.key_type");
        if (!IsCanonicalKeyTypeName(keyType))
        {
            throw new JsonException(
                $"{context}.key_type must be an exact canonical StateMap key type.");
        }
        var boundKind = RequiredExactString(root, "bound_kind", $"{context}.bound_kind");
        if (!DynamicAccessBoundKinds.Contains(boundKind))
        {
            throw new JsonException($"{context}.bound_kind must be take or page.");
        }
        var maxKeys = RequiredUInt32(root, "max_keys", $"{context}.max_keys");
        if (maxKeys is < 1 or > MaxDynamicAccessKeys)
        {
            throw new JsonException($"{context}.max_keys must be in 1..64.");
        }
        return new ToriiContractDynamicAccessHint
        {
            BaseKey = baseKey,
            KeyType = keyType,
            BoundKind = boundKind,
            MaxKeys = maxKeys,
        };
    }

    private static ToriiContractEntrypointDescriptor ParseEntrypoint(JsonObject root, string context)
    {
        EnsureOnly(
            root,
            context,
            "name",
            "kind",
            "params",
            "argument_schema",
            "return_type",
            "return_schema",
            "authorization",
            "read_keys",
            "write_keys",
            "access_hints_complete",
            "access_hints_skipped",
            "triggers");
        var name = RequiredExactString(root, "name", $"{context}.name");
        if (!IsCanonicalEntrypointName(name))
        {
            throw new JsonException($"{context}.name must be a canonical Kotodama identifier or branded lifecycle selector.");
        }
        var kind = ParseEntrypointKind(RequiredObject(root, "kind", $"{context}.kind"), $"{context}.kind");
        ValidateLifecycleName(kind, name, context);
        var parameters = DefaultObjectList(root, "params", $"{context}.params", ParseParameter);
        if (parameters.Count > MaxBoundaryWords)
        {
            throw new JsonException($"{context}.params exceeds the V1 argument limit.");
        }
        RequireUnique(parameters.Select(value => value.Name), $"{context}.params");
        var argumentSchema = OptionalObject(root, "argument_schema", $"{context}.argument_schema")
            is { } argument ? ParseArgumentSchema(argument, $"{context}.argument_schema") : null;
        ValidateExactArguments(parameters, argumentSchema, context);
        var returnType = OptionalExactString(root, "return_type", $"{context}.return_type");
        var returnSchema = OptionalObject(root, "return_schema", $"{context}.return_schema")
            is { } returns ? ParseValueType(returns, $"{context}.return_schema") : null;
        if (returnType is null || returnSchema is null
            || (returnSchema.WordCount > MaxBoundaryWords
                    || !string.Equals(
                        returnSchema.CanonicalTypeName,
                        returnType,
                        StringComparison.Ordinal)))
        {
            throw new JsonException($"{context} return_type and return_schema must describe the same exact V1 type.");
        }
        var authorization = ParseAuthorization(RequiredObject(root, "authorization", $"{context}.authorization"), $"{context}.authorization");
        ValidateAuthorizationKind(authorization, kind, context);
        var complete = OptionalBoolean(root, "access_hints_complete", $"{context}.access_hints_complete");
        var skipped = DefaultStringList(root, "access_hints_skipped", $"{context}.access_hints_skipped");
        if (complete == true && skipped.Count != 0)
        {
            throw new JsonException($"{context} complete access hints must not contain skipped reasons.");
        }
        if (complete == false && skipped.Count == 0)
        {
            throw new JsonException($"{context} incomplete access hints must contain a skipped reason.");
        }
        return new ToriiContractEntrypointDescriptor
        {
            Name = name,
            Kind = kind,
            Parameters = parameters,
            ArgumentSchema = argumentSchema,
            ReturnType = returnType,
            ReturnSchema = returnSchema,
            Authorization = authorization,
            ReadKeys = DefaultStringList(root, "read_keys", $"{context}.read_keys"),
            WriteKeys = DefaultStringList(root, "write_keys", $"{context}.write_keys"),
            AccessHintsComplete = complete,
            AccessHintsSkipped = skipped,
            Triggers = DefaultObjectList(root, "triggers", $"{context}.triggers", ParseTrigger),
        };
    }

    internal static ToriiEntrypointAuthorizationV1 ParseAuthorization(JsonObject root, string context)
    {
        EnsureOnly(root, context, "kind", "value");
        var kind = RequiredExactString(root, "kind", $"{context}.kind");
        if (!root.ContainsKey("value")) throw new JsonException($"{context}.value is required.");
        if (kind == "Permission")
        {
            var name = RequiredExactString(root, "value", $"{context}.value");
            if (!IsCanonicalBoundaryIdentifier(name)) throw new JsonException($"{context}.value must be a declared identifier.");
            return new ToriiEntrypointAuthorizationV1.Permission(name);
        }
        if (root["value"] is not null) throw new JsonException($"{context}.value must be null.");
        return kind switch
        {
            "Anyone" => new ToriiEntrypointAuthorizationV1.Anyone(),
            "RuntimeLifecycle" => new ToriiEntrypointAuthorizationV1.RuntimeLifecycle(),
            _ => throw new JsonException($"{context} has an unsupported authorization kind."),
        };
    }

    internal static JsonObject BuildAuthorization(ToriiEntrypointAuthorizationV1 value, string context)
    {
        var root = value switch
        {
            ToriiEntrypointAuthorizationV1.Anyone => new JsonObject { ["kind"] = "Anyone", ["value"] = null },
            ToriiEntrypointAuthorizationV1.RuntimeLifecycle => new JsonObject { ["kind"] = "RuntimeLifecycle", ["value"] = null },
            ToriiEntrypointAuthorizationV1.Permission permission => new JsonObject { ["kind"] = "Permission", ["value"] = permission.Name },
            _ => throw new JsonException($"{context} is required."),
        };
        _ = ParseAuthorization(root, context);
        return root;
    }

    private static void ValidateAuthorizationKind(ToriiEntrypointAuthorizationV1 authorization, ToriiContractEntrypointKind kind, string context)
    {
        _ = BuildAuthorization(authorization, $"{context}.authorization");
        var lifecycle = kind is ToriiContractEntrypointKind.Hajimari or ToriiContractEntrypointKind.Kaizen;
        if (lifecycle != (authorization is ToriiEntrypointAuthorizationV1.RuntimeLifecycle))
            throw new JsonException($"{context}.authorization must use RuntimeLifecycle exactly for lifecycle hooks.");
    }

    internal static ToriiContractPermissionDescriptorV1 ParsePermissionDeclaration(JsonObject root, string context)
    {
        EnsureOnly(root, context, "name", "scope");
        var name = RequiredExactString(root, "name", $"{context}.name");
        if (!IsCanonicalBoundaryIdentifier(name)) throw new JsonException($"{context}.name must be a canonical identifier.");
        var scope = RequiredObject(root, "scope", $"{context}.scope");
        EnsureOnly(scope, $"{context}.scope", "kind", "value");
        if (!scope.ContainsKey("value")) throw new JsonException($"{context}.scope.value is required.");
        ToriiContractPermissionScopeV1 parsed;
        if (RequiredExactString(scope, "kind", $"{context}.scope.kind") == "Instance" && scope["value"] is null)
            parsed = new ToriiContractPermissionScopeV1.Instance();
        else if (RequiredExactString(scope, "kind", $"{context}.scope.kind") == "Chain")
        {
            var imported = RequiredObject(scope, "value", $"{context}.scope.value");
            EnsureOnly(imported, $"{context}.scope.value", "permission_name");
            var permission = RequiredExactString(imported, "permission_name", $"{context}.scope.value.permission_name");
            if (permission.Any(char.IsWhiteSpace)) throw new JsonException($"{context} chain permission name must be exact.");
            parsed = new ToriiContractPermissionScopeV1.Chain(permission);
        }
        else throw new JsonException($"{context} has an unsupported permission scope.");
        return new ToriiContractPermissionDescriptorV1(name, parsed);
    }

    internal static JsonObject BuildPermissionDeclaration(ToriiContractPermissionDescriptorV1 value, string context)
    {
        var scope = value.Scope switch
        {
            ToriiContractPermissionScopeV1.Instance => new JsonObject { ["kind"] = "Instance", ["value"] = null },
            ToriiContractPermissionScopeV1.Chain chain => new JsonObject { ["kind"] = "Chain", ["value"] = new JsonObject { ["permission_name"] = chain.PermissionName } },
            _ => throw new JsonException($"{context}.scope is required."),
        };
        var root = new JsonObject { ["name"] = value.Name, ["scope"] = scope };
        _ = ParsePermissionDeclaration(root, context);
        return root;
    }

    internal static void ValidatePermissionDeclarations(IReadOnlyList<ToriiContractPermissionDescriptorV1> permissions, IEnumerable<ToriiEntrypointAuthorizationV1> authorizations, string context)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        string? previous = null;
        foreach (var permission in permissions)
        {
            _ = BuildPermissionDeclaration(permission, $"{context}.permissions");
            if (!names.Add(permission.Name) || previous is not null && Encoding.UTF8.GetBytes(previous).AsSpan().SequenceCompareTo(Encoding.UTF8.GetBytes(permission.Name)) >= 0)
                throw new JsonException($"{context}.permissions must be sorted and unique by name.");
            previous = permission.Name;
        }
        foreach (var authorization in authorizations)
            if (authorization is ToriiEntrypointAuthorizationV1.Permission permission && !names.Contains(permission.Name))
                throw new JsonException($"{context}.entrypoints refers to an undeclared permission.");
    }

    private static ToriiContractEntrypointKind ParseEntrypointKind(JsonObject root, string context)
    {
        EnsureOnly(root, context, "kind", "value");
        if (!root.ContainsKey("value") || root["value"] is not null)
        {
            throw new JsonException($"{context}.value must be null.");
        }
        return RequiredExactString(root, "kind", $"{context}.kind") switch
        {
            "Kotoage" => ToriiContractEntrypointKind.Kotoage,
            "View" => ToriiContractEntrypointKind.View,
            "Hajimari" => ToriiContractEntrypointKind.Hajimari,
            "Kaizen" => ToriiContractEntrypointKind.Kaizen,
            var unsupported => throw new JsonException($"{context}.kind `{unsupported}` is not a branded Kotodama V1 kind."),
        };
    }

    private static ToriiContractEntrypointParameter ParseParameter(JsonObject root, string context)
    {
        EnsureOnly(root, context, "name", "type_name");
        var name = RequiredExactString(root, "name", $"{context}.name");
        if (!IsCanonicalBoundaryIdentifier(name))
        {
            throw new JsonException($"{context}.name must be a canonical Kotodama identifier.");
        }
        return new ToriiContractEntrypointParameter
        {
            Name = name,
            TypeName = RequiredExactString(root, "type_name", $"{context}.type_name"),
        };
    }

    private static ToriiEntrypointArgumentSchemaV1 ParseArgumentSchema(JsonObject root, string context)
    {
        EnsureOnly(root, context, "fields");
        var fields = RequiredObjectList(root, "fields", $"{context}.fields", ParseArgumentField);
        if (fields.Count is < 1 or > MaxBoundaryWords)
        {
            throw new JsonException($"{context}.fields must contain 1..8192 items.");
        }
        RequireUnique(fields.Select(field => field.Name), $"{context}.fields");
        var words = fields.Sum(field => field.ValueType.WordCount);
        if (words > MaxBoundaryWords)
        {
            throw new JsonException($"{context} exceeds the V1 call table.");
        }
        return new ToriiEntrypointArgumentSchemaV1 { Fields = fields, WordCount = words };
    }

    private static ToriiEntrypointArgumentFieldV1 ParseArgumentField(JsonObject root, string context)
    {
        EnsureOnly(root, context, "name", "ty");
        var name = RequiredExactString(root, "name", $"{context}.name");
        if (!IsCanonicalBoundaryIdentifier(name))
        {
            throw new JsonException($"{context}.name must be a canonical Kotodama identifier.");
        }
        return new ToriiEntrypointArgumentFieldV1
        {
            Name = name,
            ValueType = ParseValueType(RequiredObject(root, "ty", $"{context}.ty"), $"{context}.ty"),
        };
    }

    private static ToriiEntrypointValueTypeV1 ParseValueType(JsonObject root, string context)
    {
        EnsureOnly(root, context, "nodes");
        var nodes = RequiredObjectList(root, "nodes", $"{context}.nodes", ParseValueTypeNode);
        if (nodes.Count is < 1 or > MaxSchemaNodes)
        {
            throw new JsonException($"{context}.nodes must contain 1..256 items.");
        }
        var analysis = AnalyzeValueType(nodes, 0, 1, context);
        if (analysis.NextIndex != nodes.Count || analysis.NodeCount > MaxSchemaNodes)
        {
            throw new JsonException($"{context} is not a canonical flat preorder V1 schema.");
        }
        return new ToriiEntrypointValueTypeV1
        {
            Nodes = nodes,
            WordCount = analysis.WordCount,
            CanonicalTypeName = analysis.TypeName,
        };
    }

    private static ToriiEntrypointValueTypeV1 ParseKeySchema(JsonObject root, string context)
    {
        // Inspect tags before recursively parsing schemas: keys cannot contain cursors.
        if (root["nodes"] is not JsonArray nodes || nodes.Count is < 1 or > MaxSchemaNodes
            || nodes.Any(node => node is not JsonObject item
                || RequiredExactString(item, "kind", $"{context}.nodes.kind") is not ("Leaf" or "Tuple")))
        {
            throw new JsonException($"{context} requires a bounded scalar or tuple key schema.");
        }
        var schema = ParseValueType(root, context);
        ValidateKeySchemaNodes(schema, context);
        return schema;
    }

    private static void ValidateKeySchemaNodes(ToriiEntrypointValueTypeV1 schema, string context)
    {
        if (schema.Nodes.Count is < 1 or > MaxSchemaNodes
            || schema.Nodes.Any(node => node.Kind is not (
                ToriiEntrypointValueTypeNodeKindV1.Leaf or ToriiEntrypointValueTypeNodeKindV1.Tuple)
                || node.LeafKind == ToriiEntrypointValueKindV1.Json))
        {
            throw new JsonException($"{context} requires a bounded scalar or tuple key schema.");
        }
    }

    private static ToriiEntrypointValueTypeNodeV1 ParseValueTypeNode(JsonObject root, string context)
    {
        EnsureOnly(root, context, "kind", "value");
        if (!root.ContainsKey("value"))
        {
            throw new JsonException($"{context}.value is required.");
        }
        return RequiredExactString(root, "kind", $"{context}.kind") switch
        {
            "Struct" => new ToriiEntrypointValueTypeNodeV1
            {
                Kind = ToriiEntrypointValueTypeNodeKindV1.Struct,
                StructValue = ParseStructNode(RequiredObject(root, "value", $"{context}.value"), $"{context}.value"),
            },
            "Tuple" => ParseTupleNode(root, context),
            "Option" => ParseNullNode(root, context, ToriiEntrypointValueTypeNodeKindV1.Option),
            "Unit" => ParseNullNode(root, context, ToriiEntrypointValueTypeNodeKindV1.Unit),
            "Error" => new ToriiEntrypointValueTypeNodeV1
            {
                Kind = ToriiEntrypointValueTypeNodeKindV1.Error,
                ErrorValue = ParseErrorType(RequiredObject(root, "value", $"{context}.value"), $"{context}.value"),
            },
            "Enum" => new ToriiEntrypointValueTypeNodeV1
            {
                Kind = ToriiEntrypointValueTypeNodeKindV1.Enum,
                EnumValue = ParseEnumType(RequiredObject(root, "value", $"{context}.value"), $"{context}.value"),
            },
            "StateCursor" => new ToriiEntrypointValueTypeNodeV1
            {
                Kind = ToriiEntrypointValueTypeNodeKindV1.StateCursor,
                CursorKeySchema = ParseKeySchema(RequiredObject(root, "value", $"{context}.value"), $"{context}.value"),
            },
            "Result" => ParseNullNode(root, context, ToriiEntrypointValueTypeNodeKindV1.Result),
            "List" => new ToriiEntrypointValueTypeNodeV1
            {
                Kind = ToriiEntrypointValueTypeNodeKindV1.List,
                ListValue = ParseListNode(RequiredObject(root, "value", $"{context}.value"), $"{context}.value"),
            },
            "Leaf" => new ToriiEntrypointValueTypeNodeV1
            {
                Kind = ToriiEntrypointValueTypeNodeKindV1.Leaf,
                LeafKind = ParseLeafKind(RequiredObject(root, "value", $"{context}.value"), $"{context}.value"),
            },
            var unsupported => throw new JsonException($"{context}.kind `{unsupported}` is unsupported."),
        };
    }

    private static ToriiEntrypointValueTypeNodeV1 ParseTupleNode(JsonObject root, string context)
    {
        var arity = RequiredUInt16(root, "value", $"{context}.value");
        if (arity < 2)
        {
            throw new JsonException($"{context}.value tuple arity must be in 2..65535.");
        }
        return new ToriiEntrypointValueTypeNodeV1
        {
            Kind = ToriiEntrypointValueTypeNodeKindV1.Tuple,
            TupleArity = arity,
        };
    }

    private static ToriiEntrypointValueTypeNodeV1 ParseNullNode(
        JsonObject root,
        string context,
        ToriiEntrypointValueTypeNodeKindV1 kind)
    {
        if (root["value"] is not null)
        {
            throw new JsonException($"{context}.value must be null for {kind}.");
        }
        return new ToriiEntrypointValueTypeNodeV1 { Kind = kind };
    }

    private static ToriiEntrypointStructTypeNodeV1 ParseStructNode(JsonObject root, string context)
    {
        EnsureOnly(root, context, "name", "fields");
        var name = RequiredExactString(root, "name", $"{context}.name");
        var fields = RequiredStringList(root, "fields", $"{context}.fields");
        if (!IsCanonicalSchemaStructIdentifier(name)
            || fields.Any(field => !IsCanonicalBoundaryIdentifier(field)))
        {
            throw new JsonException($"{context} must use canonical Kotodama identifiers.");
        }
        RequireUnique(fields, $"{context}.fields");
        return new ToriiEntrypointStructTypeNodeV1 { Name = name, Fields = fields };
    }

    private static ToriiEntrypointListTypeNodeV1 ParseListNode(JsonObject root, string context)
    {
        EnsureOnly(root, context, "capacity");
        var capacity = RequiredByte(root, "capacity", $"{context}.capacity");
        if (capacity is < 1 or > 64)
        {
            throw new JsonException($"{context}.capacity must be in 1..64.");
        }
        return new ToriiEntrypointListTypeNodeV1 { Capacity = capacity };
    }

    private static ToriiEntrypointValueKindV1 ParseLeafKind(JsonObject root, string context)
    {
        EnsureOnly(root, context, "kind", "value");
        if (!root.ContainsKey("value") || root["value"] is not null)
        {
            throw new JsonException($"{context}.value must be null.");
        }
        var label = RequiredExactString(root, "kind", $"{context}.kind");
        return ValueKinds.TryGetValue(label, out var kind)
            ? kind
            : throw new JsonException($"{context}.kind `{label}` is unsupported.");
    }

    private static TypeAnalysis AnalyzeValueType(
        IReadOnlyList<ToriiEntrypointValueTypeNodeV1> nodes,
        int index,
        int depth,
        string context)
    {
        if (index != 0 || depth != 1 || nodes.Count is < 1 or > MaxSchemaNodes)
        {
            throw new JsonException($"{context} exceeds flat V1 schema bounds.");
        }

        var frames = new List<AnalysisFrame>();
        var wordCount = 0;
        var maxDepth = 0;
        var totalNodes = nodes.Count;
        for (var nodeIndex = 0; nodeIndex < nodes.Count; nodeIndex++)
        {
            while (frames.Count != 0 && frames[^1].RemainingChildren == 0)
            {
                frames.RemoveAt(frames.Count - 1);
            }

            var suppressWords = false;
            if (nodeIndex != 0)
            {
                if (frames.Count == 0 || frames[^1].RemainingChildren == 0)
                {
                    throw new JsonException(
                        $"{context}.nodes is not one complete canonical prefix type tree.");
                }
                var parent = frames[^1];
                suppressWords = parent.SuppressWords;
                frames[^1] = parent with
                {
                    RemainingChildren = parent.RemainingChildren - 1,
                };
            }

            var currentDepth = frames.Count + 1;
            if (currentDepth > MaxSchemaDepth)
            {
                throw new JsonException($"{context} exceeds flat V1 schema bounds.");
            }
            maxDepth = Math.Max(maxDepth, currentDepth);

            var node = nodes[nodeIndex];
            var childCount = ValidateNodeAndGetChildCount(node, context);
            if (node.CursorKeySchema is { } keySchema)
            {
                var keyAnalysis = AnalyzeValueType(keySchema.Nodes, 0, 1, context);
                totalNodes = checked(totalNodes + keyAnalysis.NodeCount);
                maxDepth = Math.Max(maxDepth, currentDepth + keyAnalysis.MaxDepth);
                if (totalNodes > MaxSchemaNodes || maxDepth > MaxSchemaDepth)
                    throw new JsonException($"{context} exceeds complete cursor schema bounds.");
            }
            var isHandle = node.Kind is ToriiEntrypointValueTypeNodeKindV1.Option or
                ToriiEntrypointValueTypeNodeKindV1.Result or
                ToriiEntrypointValueTypeNodeKindV1.List;
            if (!suppressWords
                && (isHandle || childCount == 0))
            {
                wordCount = checked(wordCount + 1);
            }
            if (childCount != 0)
            {
                frames.Add(new AnalysisFrame(childCount, suppressWords || isHandle));
            }
        }
        while (frames.Count != 0 && frames[^1].RemainingChildren == 0)
        {
            frames.RemoveAt(frames.Count - 1);
        }
        if (frames.Count != 0)
        {
            throw new JsonException(
                $"{context}.nodes ends before its prefix type tree is complete.");
        }

        var rendered = new List<RenderedType>();
        for (var nodeIndex = nodes.Count - 1; nodeIndex >= 0; nodeIndex--)
        {
            var node = nodes[nodeIndex];
            var childCount = ValidateNodeAndGetChildCount(node, context);
            if (rendered.Count < childCount)
            {
                throw new JsonException(
                    $"{context}.nodes ends before its prefix type tree is complete.");
            }
            var children = childCount == 0
                ? new List<RenderedType>()
                : rendered.GetRange(rendered.Count - childCount, childCount);
            if (childCount != 0)
            {
                rendered.RemoveRange(rendered.Count - childCount, childCount);
                children.Reverse();
            }

            RenderedType result;
            switch (node.Kind)
            {
                case ToriiEntrypointValueTypeNodeKindV1.Struct:
                    var product = node.StructValue!;
                    var childTypeNames = children.Select(child => child.TypeName).ToArray();
                    if (string.Equals(product.Name, "kotodama::QueryPage", StringComparison.Ordinal))
                    {
                        var viewName = children.Count == 2
                            ? children[0].ListElementCoreQueryViewName
                            : null;
                        if (!product.Fields.SequenceEqual(
                                new[] { "items", "next_offset" },
                                StringComparer.Ordinal)
                            || children.Count != 2
                            || children[0].ListCapacity != 64
                            || viewName is null
                            || !string.Equals(
                                children[1].TypeName,
                                "Option<int>",
                                StringComparison.Ordinal))
                        {
                            throw new JsonException(
                                $"{context} contains a forged QueryPage schema.");
                        }
                        result = new RenderedType($"QueryPage<{viewName}>", null, null, null);
                    }
                    else if (product.Name == "kotodama::StatePage")
                    {
                        var pair = children.Count == 2 ? children[0].ListElement?.TupleChildren : null;
                        if (!product.Fields.SequenceEqual(new[] { "items", "next" }, StringComparer.Ordinal)
                            || children.Count != 2 || children[0].ListCapacity is null
                            || pair is null || pair.Count != 2
                            || !IsCanonicalKeyTypeName(pair[0].TypeName)
                            || children[1].OptionElement?.CursorKeyTypeName != pair[0].TypeName)
                        {
                            throw new JsonException($"{context} contains a forged StatePage schema.");
                        }
                        result = new RenderedType(
                            $"StatePage<{pair[0].TypeName}, {pair[1].TypeName}, {children[0].ListCapacity}>",
                            null, null, null);
                    }
                    else if (IsCoreQueryViewName(product.Name))
                    {
                        if (!IsExactCoreQueryView(product, childTypeNames))
                        {
                            throw new JsonException(
                                $"{context} contains a forged {product.Name} projection schema.");
                        }
                        result = new RenderedType(product.Name["kotodama::".Length..], product.Name["kotodama::".Length..], null, null);
                    }
                    else
                    {
                        result = new RenderedType($"struct {product.Name}", null, null, null);
                    }
                    break;
                case ToriiEntrypointValueTypeNodeKindV1.Tuple:
                    result = new RenderedType(
                        $"({string.Join(", ", children.Select(child => child.TypeName))})",
                        null,
                        null,
                        null) { TupleChildren = children };
                    break;
                case ToriiEntrypointValueTypeNodeKindV1.Option:
                    result = new RenderedType($"Option<{children[0].TypeName}>", null, null, null)
                        { OptionElement = children[0] };
                    break;
                case ToriiEntrypointValueTypeNodeKindV1.Result:
                    result = new RenderedType(
                        $"Result<{children[0].TypeName}, {children[1].TypeName}>",
                        null,
                        null,
                        null);
                    break;
                case ToriiEntrypointValueTypeNodeKindV1.List:
                    var list = node.ListValue!;
                    result = new RenderedType(
                        $"List<{children[0].TypeName}, {list.Capacity}>",
                        null,
                        list.Capacity,
                        children[0].CoreQueryViewName) { ListElement = children[0] };
                    break;
                case ToriiEntrypointValueTypeNodeKindV1.Leaf:
                    result = new RenderedType(
                        CanonicalLeafName(node.LeafKind!.Value),
                        null,
                        null,
                        null) { LeafKind = node.LeafKind };
                    break;
                case ToriiEntrypointValueTypeNodeKindV1.Unit:
                    result = new RenderedType("()", null, null, null);
                    break;
                case ToriiEntrypointValueTypeNodeKindV1.Error:
                    result = new RenderedType(node.ErrorValue!.Identity, null, null, null);
                    break;
                case ToriiEntrypointValueTypeNodeKindV1.Enum:
                    result = new RenderedType(node.EnumValue!.Identity, null, null, null);
                    break;
                case ToriiEntrypointValueTypeNodeKindV1.StateCursor:
                    result = new RenderedType(
                        $"StateCursor<{AnalyzeValueType(node.CursorKeySchema!.Nodes, 0, 1, context).TypeName}>", null, null, null)
                        { CursorKeyTypeName = AnalyzeValueType(node.CursorKeySchema.Nodes, 0, 1, context).TypeName };
                    break;
                default:
                    throw new JsonException($"{context} contains an unsupported node.");
            }
            rendered.Add(result);
        }
        if (rendered.Count != 1)
        {
            throw new JsonException(
                $"{context}.nodes is not one complete canonical prefix type tree.");
        }
        var root = rendered[0];
        return new TypeAnalysis(
            nodes.Count,
            totalNodes,
            wordCount,
            maxDepth,
            root.TypeName,
            root.CoreQueryViewName,
            root.ListElementCoreQueryViewName);
    }

    private static int ValidateNodeAndGetChildCount(
        ToriiEntrypointValueTypeNodeV1 node,
        string context)
    {
        var exactPayload = node.Kind switch
        {
            ToriiEntrypointValueTypeNodeKindV1.Struct =>
                node.StructValue is not null
                && node.TupleArity is null
                && node.ListValue is null
                && node.LeafKind is null,
            ToriiEntrypointValueTypeNodeKindV1.Tuple =>
                node.StructValue is null
                && node.TupleArity is not null
                && node.ListValue is null
                && node.LeafKind is null,
            ToriiEntrypointValueTypeNodeKindV1.Option or
                ToriiEntrypointValueTypeNodeKindV1.Unit or
                ToriiEntrypointValueTypeNodeKindV1.Result =>
                node.StructValue is null
                && node.TupleArity is null
                && node.ListValue is null
                && node.LeafKind is null,
            ToriiEntrypointValueTypeNodeKindV1.List =>
                node.StructValue is null
                && node.TupleArity is null
                && node.ListValue is not null
                && node.LeafKind is null,
            ToriiEntrypointValueTypeNodeKindV1.Leaf =>
                node.StructValue is null
                && node.TupleArity is null
                && node.ListValue is null
                && node.LeafKind is not null,
            ToriiEntrypointValueTypeNodeKindV1.Error =>
                node.StructValue is null && node.TupleArity is null
                && node.ListValue is null && node.LeafKind is null
                && node.ErrorValue is not null,
            ToriiEntrypointValueTypeNodeKindV1.Enum =>
                node.StructValue is null && node.TupleArity is null
                && node.ListValue is null && node.LeafKind is null && node.EnumValue is not null,
            ToriiEntrypointValueTypeNodeKindV1.StateCursor =>
                node.StructValue is null && node.TupleArity is null
                && node.ListValue is null && node.LeafKind is null
                && node.CursorKeySchema is not null,
            _ => false,
        };
        if (!exactPayload
            || (node.Kind != ToriiEntrypointValueTypeNodeKindV1.Error && node.ErrorValue is not null)
            || (node.Kind != ToriiEntrypointValueTypeNodeKindV1.Enum && node.EnumValue is not null)
            || (node.Kind != ToriiEntrypointValueTypeNodeKindV1.StateCursor && node.CursorKeySchema is not null))
        {
            throw new JsonException($"{context} contains inconsistent node metadata.");
        }

        switch (node.Kind)
        {
            case ToriiEntrypointValueTypeNodeKindV1.Struct:
                var product = node.StructValue!;
                if (!IsCanonicalSchemaStructIdentifier(product.Name)
                    || product.Fields.Any(field => !IsCanonicalBoundaryIdentifier(field)))
                {
                    throw new JsonException($"{context} contains a noncanonical struct node.");
                }
                RequireUnique(product.Fields, $"{context}.fields");
                return product.Fields.Count;
            case ToriiEntrypointValueTypeNodeKindV1.Tuple:
                if (node.TupleArity!.Value < 2)
                {
                    throw new JsonException($"{context} tuple arity must be at least 2.");
                }
                return node.TupleArity.Value;
            case ToriiEntrypointValueTypeNodeKindV1.Option:
            case ToriiEntrypointValueTypeNodeKindV1.List:
                if (node.Kind == ToriiEntrypointValueTypeNodeKindV1.List
                    && node.ListValue!.Capacity is < 1 or > 64)
                {
                    throw new JsonException($"{context} list capacity must be in 1..64.");
                }
                return 1;
            case ToriiEntrypointValueTypeNodeKindV1.Result:
                return 2;
            case ToriiEntrypointValueTypeNodeKindV1.Leaf:
                _ = CanonicalLeafName(node.LeafKind!.Value);
                return 0;
            case ToriiEntrypointValueTypeNodeKindV1.Error:
                ValidateErrorType(node.ErrorValue!, context);
                return 0;
            case ToriiEntrypointValueTypeNodeKindV1.Enum:
                ValidateEnumType(node.EnumValue!, context);
                return 0;
            case ToriiEntrypointValueTypeNodeKindV1.StateCursor:
                ValidateKeySchemaNodes(node.CursorKeySchema!, context);
                return 0;
            case ToriiEntrypointValueTypeNodeKindV1.Unit:
                return 0;
            default:
                throw new JsonException($"{context} contains an unsupported node.");
        }
    }

    private static bool IsCoreQueryViewName(string name)
    {
        return name is "kotodama::AccountView" or "kotodama::AssetView" or "kotodama::AssetDefinitionView" or
            "kotodama::DomainView" or "kotodama::NftView";
    }

    private static bool IsExactCoreQueryView(
        ToriiEntrypointStructTypeNodeV1 product,
        IReadOnlyList<string> childTypeNames)
    {
        string[] expectedFields;
        string[] expectedTypes;
        switch (product.Name)
        {
            case "kotodama::AccountView":
                expectedFields = new[] { "id", "metadata" };
                expectedTypes = new[] { "AccountId", "Json" };
                break;
            case "kotodama::AssetView":
                expectedFields = new[] { "id", "amount" };
                expectedTypes = new[] { "AssetId", "quantity" };
                break;
            case "kotodama::AssetDefinitionView":
                expectedFields = new[]
                {
                    "id", "name", "description", "owned_by", "total_quantity", "numeric_scale", "metadata",
                };
                expectedTypes = new[]
                {
                    "AssetDefinitionId", "string", "Option<string>", "AccountId", "quantity", "Option<int>", "Json",
                };
                break;
            case "kotodama::DomainView":
                expectedFields = new[] { "id", "owned_by", "metadata" };
                expectedTypes = new[] { "DomainId", "AccountId", "Json" };
                break;
            case "kotodama::NftView":
                expectedFields = new[] { "id", "owned_by", "content" };
                expectedTypes = new[] { "NftId", "AccountId", "Json" };
                break;
            default:
                return false;
        }
        return product.Fields.SequenceEqual(expectedFields, StringComparer.Ordinal)
            && childTypeNames.SequenceEqual(expectedTypes, StringComparer.Ordinal);
    }

    private static bool IsExactDurableBuiltinProduct(string name, IReadOnlyList<string> fields, IReadOnlyList<string> types)
    {
        if (IsCoreQueryViewName(name))
            return IsExactCoreQueryView(new ToriiEntrypointStructTypeNodeV1 { Name = name, Fields = fields }, types);
        if (name != "kotodama::QueryPage") return !name.StartsWith("kotodama::", StringComparison.Ordinal);
        if (!fields.SequenceEqual(new[] { "items", "next_offset" }, StringComparer.Ordinal)
            || types.Count != 2 || types[1] != "Option<int>") return false;
        // Recursive parsing has already validated the exact nested view shape.
        const string prefix = "List<";
        var item = types[0];
        var brace = item.IndexOf('{');
        return item.StartsWith(prefix, StringComparison.Ordinal) && brace > prefix.Length
            && IsCoreQueryViewName(item.Substring(prefix.Length, brace - prefix.Length))
            && item.EndsWith("}, 64>", StringComparison.Ordinal);
    }

    private static string CanonicalLeafName(ToriiEntrypointValueKindV1 kind)
    {
        return kind switch
        {
            ToriiEntrypointValueKindV1.Int => "int",
            ToriiEntrypointValueKindV1.Decimal => "decimal",
            ToriiEntrypointValueKindV1.Quantity => "quantity",
            ToriiEntrypointValueKindV1.Bool => "bool",
            ToriiEntrypointValueKindV1.String => "string",
            ToriiEntrypointValueKindV1.Json => "Json",
            ToriiEntrypointValueKindV1.Name => "Name",
            ToriiEntrypointValueKindV1.AccountId => "AccountId",
            ToriiEntrypointValueKindV1.AssetDefinitionId => "AssetDefinitionId",
            ToriiEntrypointValueKindV1.AssetId => "AssetId",
            ToriiEntrypointValueKindV1.DomainId => "DomainId",
            ToriiEntrypointValueKindV1.NftId => "NftId",
            ToriiEntrypointValueKindV1.DataSpaceId => "DataSpaceId",
            ToriiEntrypointValueKindV1.Blob => "bytes",
            _ => throw new JsonException("Unsupported Kotodama V1 leaf kind."),
        };
    }

    private static ToriiContractTriggerDescriptor ParseTrigger(JsonObject root, string context)
    {
        EnsureOnly(root, context, "id", "repeats", "filter", "authority", "metadata", "callback");
        var id = RequiredExactString(root, "id", $"{context}.id");
        if (!IsCanonicalDeclarationIdentifier(id))
        {
            throw new JsonException($"{context}.id must be a canonical Kotodama declaration identifier.");
        }
        var filter = RequiredExactString(root, "filter", $"{context}.filter");
        ValidateCanonicalBase64(filter, $"{context}.filter");
        var authority = OptionalExactString(root, "authority", $"{context}.authority");
        if (authority is not null)
        {
            try
            {
                authority = ToriiExplorerDirectMetadata.RequireCanonicalAccountId(authority, $"{context}.authority");
            }
            catch (ArgumentException exception)
            {
                throw new JsonException($"{context}.authority must be a canonical I105 account id.", exception);
            }
        }
        return new ToriiContractTriggerDescriptor
        {
            Id = id,
            Repeats = ParseRepeats(RequiredObject(root, "repeats", $"{context}.repeats"), $"{context}.repeats"),
            FilterBase64 = filter,
            Authority = authority,
            Metadata = RequiredObject(root, "metadata", $"{context}.metadata"),
            Callback = ParseCallback(RequiredObject(root, "callback", $"{context}.callback"), $"{context}.callback"),
        };
    }

    private static ToriiContractTriggerRepeats ParseRepeats(JsonObject root, string context)
    {
        if (root.Count != 1)
        {
            throw new JsonException($"{context} must contain exactly one enum variant.");
        }
        if (root.TryGetPropertyValue("Indefinitely", out var indefinite))
        {
            if (indefinite is not null)
            {
                throw new JsonException($"{context}.Indefinitely must be null.");
            }
            return new ToriiContractTriggerRepeats
            {
                Kind = ToriiContractTriggerRepeatsKind.Indefinitely,
            };
        }
        if (root.ContainsKey("Exactly"))
        {
            return new ToriiContractTriggerRepeats
            {
                Kind = ToriiContractTriggerRepeatsKind.Exactly,
                Exactly = RequiredUInt32(root, "Exactly", $"{context}.Exactly"),
            };
        }
        throw new JsonException($"{context} contains an unsupported repetition policy.");
    }

    private static ToriiContractTriggerCallback ParseCallback(JsonObject root, string context)
    {
        EnsureOnly(root, context, "namespace", "entrypoint");
        var callbackNamespace = OptionalExactString(root, "namespace", $"{context}.namespace");
        if (callbackNamespace is not null && !IsCanonicalTypeDeclarationIdentifier(callbackNamespace))
        {
            throw new JsonException($"{context}.namespace must be a canonical Kotodama type-declaration identifier.");
        }
        var entrypoint = RequiredExactString(root, "entrypoint", $"{context}.entrypoint");
        if (!IsCanonicalEntrypointName(entrypoint))
        {
            throw new JsonException($"{context}.entrypoint must be a canonical Kotodama selector.");
        }
        return new ToriiContractTriggerCallback
        {
            Namespace = callbackNamespace,
            Entrypoint = entrypoint,
        };
    }

    private static ToriiContractStateDescriptor ParseState(JsonObject root, string context)
    {
        EnsureOnly(root, context, "name", "type_name");
        var name = RequiredExactString(root, "name", $"{context}.name");
        var typeName = RequiredExactString(root, "type_name", $"{context}.type_name");
        if (!IsCanonicalDeclarationIdentifier(name))
        {
            throw new JsonException($"{context}.name must be a canonical Kotodama declaration identifier.");
        }
        return new ToriiContractStateDescriptor
        {
            Name = name,
            TypeName = typeName,
        };
    }

    private static ToriiContractErrorMessage ParseErrorMessage(JsonObject root, string context)
    {
        EnsureOnly(root, context, "error_type", "code", "message");
        var message = new ToriiContractErrorMessage
        {
            ErrorType = RequiredExactString(root, "error_type", $"{context}.error_type"),
            Code = RequiredUInt32(root, "code", $"{context}.code"),
            Message = RequiredStringAllowEmpty(root, "message", $"{context}.message"),
        };
        ValidateErrorMessage(message, context);
        return message;
    }

    private static void ValidateErrorMessage(ToriiContractErrorMessage value, string context)
    {
        if (value.Code == 0 || string.IsNullOrWhiteSpace(value.Message))
            throw new JsonException($"{context} requires a nonzero code and 1..4096 UTF-8 bytes of nonblank error text.");
        try
        {
            if (new UTF8Encoding(false, true).GetByteCount(value.Message) > 4096)
                throw new JsonException($"{context} error text exceeds 4096 UTF-8 bytes.");
        }
        catch (EncoderFallbackException error)
        {
            throw new JsonException($"{context} error text must contain valid Unicode scalar values.", error);
        }
    }

    private static JsonObject BuildErrorMessage(ToriiContractErrorMessage value, string context)
    {
        ValidateErrorMessage(value, context);
        return new JsonObject { ["error_type"] = value.ErrorType, ["code"] = value.Code, ["message"] = value.Message };
    }

    private static ToriiContractErrorTypeDescriptor ParseErrorType(JsonObject root, string context)
    {
        EnsureOnly(root, context, "identity", "variants");
        var descriptor = new ToriiContractErrorTypeDescriptor
        {
            Identity = RequiredExactString(root, "identity", $"{context}.identity"),
            Variants = RequiredObjectList(root, "variants", $"{context}.variants", ParseErrorVariant),
        };
        ValidateErrorType(descriptor, context);
        return descriptor;
    }

    private static ToriiContractErrorVariantDescriptor ParseErrorVariant(JsonObject root, string context)
    {
        EnsureOnly(root, context, "name", "code");
        return new ToriiContractErrorVariantDescriptor
        {
            Name = RequiredExactString(root, "name", $"{context}.name"),
            Code = RequiredUInt32(root, "code", $"{context}.code"),
        };
    }

    private static void ValidateErrorType(ToriiContractErrorTypeDescriptor value, string context)
    {
        if (string.IsNullOrEmpty(value.Identity) || Encoding.UTF8.GetByteCount(value.Identity) > 1024
            || value.Identity.Contains("__kotodama_link_", StringComparison.Ordinal)
            || value.Identity.EnumerateRunes().Any(character => !Rune.IsLetterOrDigit(character)
                && !(character.IsAscii && "_:/@.-".Contains((char)character.Value))))
        {
            throw new JsonException($"{context}.identity must be an exact bounded nominal identity.");
        }
        if (value.Variants.Count is < 1 or > 256)
        {
            throw new JsonException($"{context}.variants must contain 1..256 variants.");
        }
        uint previous = 0;
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var variant in value.Variants)
        {
            var runes = variant.Name.EnumerateRunes().ToArray();
            var unicodeName = runes.Any(character => !character.IsAscii)
                && runes.Length > 0
                && (Rune.IsLetter(runes[0]) || runes[0].Value == '_')
                && runes.All(character => Rune.IsLetterOrDigit(character) || character.Value == '_');
            if ((!IsCanonicalBoundaryIdentifier(variant.Name) && !unicodeName)
                || variant.Code <= previous || !names.Add(variant.Name))
            {
                throw new JsonException($"{context}.variants must have unique names and increasing nonzero u32 codes.");
            }
            previous = variant.Code;
        }
    }

    private static ToriiContractEnumTypeDescriptor ParseEnumType(JsonObject root, string context)
    {
        EnsureOnly(root, context, "identity", "variants");
        var descriptor = new ToriiContractEnumTypeDescriptor
        {
            Identity = RequiredExactString(root, "identity", $"{context}.identity"),
            Variants = RequiredObjectList(root, "variants", $"{context}.variants", ParseEnumVariant),
        };
        ValidateEnumType(descriptor, context);
        return descriptor;
    }

    private static ToriiContractEnumVariantDescriptor ParseEnumVariant(JsonObject root, string context)
    {
        EnsureOnly(root, context, "name", "code");
        return new ToriiContractEnumVariantDescriptor
        {
            Name = RequiredExactString(root, "name", $"{context}.name"),
            Code = RequiredUInt32(root, "code", $"{context}.code"),
        };
    }

    private static void ValidateEnumType(ToriiContractEnumTypeDescriptor value, string context)
    {
        if (string.IsNullOrEmpty(value.Identity) || Encoding.UTF8.GetByteCount(value.Identity) > 1024
            || value.Identity.Contains("__kotodama_link_", StringComparison.Ordinal)
            || value.Identity.EnumerateRunes().Any(character => !Rune.IsLetterOrDigit(character)
                && !(character.IsAscii && "_:/@.-".Contains((char)character.Value))))
        {
            throw new JsonException($"{context}.identity must be an exact bounded nominal identity.");
        }
        if (value.Variants.Count is < 1 or > 256)
        {
            throw new JsonException($"{context}.variants must contain 1..256 variants.");
        }
        uint previous = 0;
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var variant in value.Variants)
        {
            var runes = variant.Name.EnumerateRunes().ToArray();
            var unicodeName = runes.Any(character => !character.IsAscii)
                && runes.Length > 0
                && (Rune.IsLetter(runes[0]) || runes[0].Value == '_')
                && runes.All(character => Rune.IsLetterOrDigit(character) || character.Value == '_');
            if ((!IsCanonicalBoundaryIdentifier(variant.Name) && !unicodeName)
                || variant.Code <= previous || !names.Add(variant.Name))
            {
                throw new JsonException($"{context}.variants must have unique names and increasing nonzero u32 codes.");
            }
            previous = variant.Code;
        }
    }

    private static ToriiContractEventDescriptor ParseEvent(JsonObject root, string context)
    {
        EnsureOnly(root, context, "name", "payload_type");
        var descriptor = new ToriiContractEventDescriptor {
            Name = RequiredExactString(root, "name", $"{context}.name"),
            PayloadType = ParseValueType(RequiredObject(root, "payload_type", $"{context}.payload_type"), $"{context}.payload_type"),
        };
        ValidateEvent(descriptor, context);
        return descriptor;
    }

    private static void ValidateEvent(ToriiContractEventDescriptor value, string context)
    {
        var root = value.PayloadType.Nodes.FirstOrDefault();
        if (!IsCanonicalBoundaryIdentifier(value.Name) || root?.Kind != ToriiEntrypointValueTypeNodeKindV1.Struct
            || root.StructValue?.Name.Split("::", StringSplitOptions.None).Last() != value.Name || value.PayloadType.Nodes.Any(node =>
                node.Kind == ToriiEntrypointValueTypeNodeKindV1.StateCursor ||
                (node.Kind == ToriiEntrypointValueTypeNodeKindV1.Leaf && node.LeafKind == ToriiEntrypointValueKindV1.Json)))
            throw new JsonException($"{context} requires a matching named struct without Json or StateCursor.");
        _ = BuildValueType(value.PayloadType, context);
    }

    private static JsonObject BuildEvent(ToriiContractEventDescriptor value, string context)
    {
        ValidateEvent(value, context);
        return new JsonObject { ["name"] = value.Name, ["payload_type"] = BuildValueType(value.PayloadType, context) };
    }

    private static ToriiContractKotobaTranslationEntry ParseKotobaEntry(JsonObject root, string context)
    {
        EnsureOnly(root, context, "msg_id", "translations");
        var translations = RequiredObjectList(root, "translations", $"{context}.translations", ParseKotobaTranslation);
        RequireUnique(translations.Select(value => value.Language), $"{context}.translations");
        return new ToriiContractKotobaTranslationEntry
        {
            MessageId = RequiredExactString(root, "msg_id", $"{context}.msg_id"),
            Translations = translations,
        };
    }

    private static ToriiContractKotobaTranslation ParseKotobaTranslation(JsonObject root, string context)
    {
        EnsureOnly(root, context, "lang", "text");
        return new ToriiContractKotobaTranslation
        {
            Language = RequiredExactString(root, "lang", $"{context}.lang"),
            Text = RequiredStringAllowEmpty(root, "text", $"{context}.text"),
        };
    }

    private static ToriiContractManifestProvenance ParseProvenance(JsonObject root, string context)
    {
        EnsureOnly(root, context, "signer", "signature");
        return new ToriiContractManifestProvenance
        {
            Signer = RequiredExactString(root, "signer", $"{context}.signer"),
            Signature = RequiredExactString(root, "signature", $"{context}.signature"),
        };
    }

    private static void ValidateManifestCollections(
        IReadOnlyList<ToriiContractEntrypointDescriptor>? entrypoints,
        IReadOnlyList<ToriiContractStateDescriptor>? states,
        IReadOnlyList<ToriiContractErrorTypeDescriptor>? errorTypes,
        IReadOnlyList<ToriiContractEnumTypeDescriptor> enumTypes,
        IReadOnlyList<ToriiContractEventDescriptor> events,
        IReadOnlyList<ToriiContractErrorMessage>? errorMessages,
        IReadOnlyList<ToriiContractKotobaTranslationEntry>? kotoba,
        string context)
    {
        if (entrypoints is not null)
        {
            RequireUnique(entrypoints.Select(value => value.Name), $"{context}.entrypoints");
            if (entrypoints.Count(value => value.Kind == ToriiContractEntrypointKind.Hajimari) > 1
                || entrypoints.Count(value => value.Kind == ToriiContractEntrypointKind.Kaizen) > 1)
            {
                throw new JsonException($"{context}.entrypoints contains duplicate lifecycle declarations.");
            }
            var kinds = entrypoints.ToDictionary(value => value.Name, value => value.Kind, StringComparer.Ordinal);
            var triggerIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (var descriptor in entrypoints)
            {
                foreach (var trigger in descriptor.Triggers)
                {
                    if (!triggerIds.Add(trigger.Id))
                    {
                        throw new JsonException(
                            $"{context}.entrypoints contains duplicate trigger id `{trigger.Id}`.");
                    }
                    if (trigger.Callback.Namespace is null
                        && (!kinds.TryGetValue(trigger.Callback.Entrypoint, out var callbackKind)
                            || callbackKind != ToriiContractEntrypointKind.Kotoage))
                    {
                        throw new JsonException(
                            $"{context}.entrypoints local trigger callback `{trigger.Callback.Entrypoint}` must name a declared kotoage entrypoint.");
                    }
                }
            }
        }
        if (states is not null)
        {
            RequireUnique(states.Select(value => value.Name), $"{context}.states");
        }
        var catalog = new Dictionary<string, ToriiContractErrorTypeDescriptor>(StringComparer.Ordinal);
        if (errorTypes?.Count > 256)
        {
            throw new JsonException($"{context}.error_types must contain at most 256 identities.");
        }
        foreach (var descriptor in errorTypes ?? Array.Empty<ToriiContractErrorTypeDescriptor>())
        {
            ValidateErrorType(descriptor, $"{context}.error_types");
            if (!catalog.TryAdd(descriptor.Identity, descriptor))
            {
                throw new JsonException($"{context}.error_types must have unique nominal identities.");
            }
        }
        foreach (var (label, names) in new[] {
            ("enum_types", enumTypes.Select(item => item.Identity).ToArray()),
            ("events", events.Select(item => item.Name).ToArray()) })
        {
            if (names.Length > 256 || names.Zip(names.Skip(1), (left, right) =>
                    Encoding.UTF8.GetBytes(left).AsSpan().SequenceCompareTo(Encoding.UTF8.GetBytes(right)) < 0).Any(ordered => !ordered))
                throw new JsonException($"{context}.{label} must contain at most 256 sorted unique declarations.");
        }
        var enumCatalog = new Dictionary<string, ToriiContractEnumTypeDescriptor>(StringComparer.Ordinal);
        foreach (var descriptor in enumTypes)
        {
            ValidateEnumType(descriptor, context);
            if (catalog.ContainsKey(descriptor.Identity) || !enumCatalog.TryAdd(descriptor.Identity, descriptor))
                throw new JsonException($"{context} enum_types and error_types identities must be unique and disjoint.");
        }
        foreach (var descriptor in events) ValidateEvent(descriptor, context);
        ToriiContractErrorMessage? previousMessage = null;
        foreach (var entry in errorMessages ?? Array.Empty<ToriiContractErrorMessage>())
        {
            ValidateErrorMessage(entry, context);
            if (!catalog.TryGetValue(entry.ErrorType, out var error) || !error.Variants.Any(variant => variant.Code == entry.Code))
                throw new JsonException($"{context}.error_messages must reference declared nominal error variants.");
            if (previousMessage is not null)
            {
                var order = Encoding.UTF8.GetBytes(previousMessage.ErrorType).AsSpan().SequenceCompareTo(Encoding.UTF8.GetBytes(entry.ErrorType));
                if (order > 0 || (order == 0 && previousMessage.Code >= entry.Code))
                    throw new JsonException($"{context}.error_messages must be sorted and unique.");
            }
            previousMessage = entry;
        }
        var schemas = events.Select(item => item.PayloadType).ToList();
        foreach (var entrypoint in entrypoints ?? Array.Empty<ToriiContractEntrypointDescriptor>())
        {
            if (entrypoint.ArgumentSchema is { } args) schemas.AddRange(args.Fields.Select(field => field.ValueType));
            if (entrypoint.ReturnSchema is { } returns) schemas.Add(returns);
        }
        foreach (var node in schemas.SelectMany(schema => schema.Nodes))
        {
            if (node.ErrorValue is { } error && (!catalog.TryGetValue(error.Identity, out var expected)
                || !expected.Variants.SequenceEqual(error.Variants)))
                throw new JsonException($"{context} Error schema must exactly match its error_types catalog descriptor.");
            if (node.EnumValue is { } descriptor && (!enumCatalog.TryGetValue(descriptor.Identity, out var declared)
                || !declared.Variants.SequenceEqual(descriptor.Variants)))
                throw new JsonException($"{context} Enum schema must exactly match its enum_types catalog descriptor.");
        }
        foreach (var state in states ?? Array.Empty<ToriiContractStateDescriptor>())
        {
            if (!IsCanonicalStateTypeName(state.TypeName, catalog.Keys.Concat(enumCatalog.Keys)))
            {
                throw new JsonException($"{context}.states.type_name must be a canonical Kotodama V1 state type using declared nominal enum or error types.");
            }
        }
        if (kotoba is not null)
        {
            RequireUnique(kotoba.Select(value => value.MessageId), $"{context}.kotoba");
        }
    }

    private static void ValidateDynamicAccessHintStateMaps(
        ToriiContractAccessSetHints? accessSetHints,
        IReadOnlyList<ToriiContractStateDescriptor>? states,
        string context)
    {
        if (accessSetHints is null)
        {
            return;
        }

        var stateMapKeyTypes = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var state in states ?? Array.Empty<ToriiContractStateDescriptor>())
        {
            if (TopLevelStateMapKeyType(state.TypeName) is { } keyType)
            {
                stateMapKeyTypes.Add(state.Name, keyType);
            }
        }
        ValidateDynamicAccessHintList(
            accessSetHints.DynamicReads,
            stateMapKeyTypes,
            $"{context}.access_set_hints.dynamic_reads");
        ValidateDynamicAccessHintList(
            accessSetHints.DynamicWrites,
            stateMapKeyTypes,
            $"{context}.access_set_hints.dynamic_writes");
    }

    private static void ValidateDynamicAccessHintList(
        IReadOnlyList<ToriiContractDynamicAccessHint> hints,
        IReadOnlyDictionary<string, string> stateMapKeyTypes,
        string context)
    {
        var unique =
            new HashSet<(string BaseKey, string KeyType, string BoundKind, uint MaxKeys)>();
        foreach (var hint in hints)
        {
            if (!unique.Add((hint.BaseKey, hint.KeyType, hint.BoundKind, hint.MaxKeys)))
            {
                throw new JsonException(
                    $"{context} contains duplicate hint `{hint.BaseKey}`.");
            }
            var stateName = hint.BaseKey["state:".Length..];
            if (!stateMapKeyTypes.TryGetValue(stateName, out var expectedKeyType))
            {
                throw new JsonException(
                    $"{context} hint `{hint.BaseKey}` must reference a declared top-level StateMap.");
            }
            if (!string.Equals(hint.KeyType, expectedKeyType, StringComparison.Ordinal))
            {
                throw new JsonException(
                    $"{context} hint `{hint.BaseKey}` declares key_type `{hint.KeyType}` "
                    + $"but its StateMap key type is `{expectedKeyType}`.");
            }
        }
    }

    private static string? TopLevelStateMapKeyType(string typeName)
    {
        const string prefix = "StateMap<";
        if (!typeName.StartsWith(prefix, StringComparison.Ordinal))
        {
            return null;
        }
        var parser = new KeyTypeNameParser(typeName, prefix.Length);
        return parser.Parse() && typeName.AsSpan(parser.Cursor).StartsWith(", ", StringComparison.Ordinal)
            ? typeName[prefix.Length..parser.Cursor] : null;
    }

    private static void ValidateExactArguments(
        IReadOnlyList<ToriiContractEntrypointParameter> parameters,
        ToriiEntrypointArgumentSchemaV1? schema,
        string context)
    {
        if (parameters.Count == 0 && schema is null)
        {
            return;
        }
        if (schema is null || schema.Fields.Count != parameters.Count)
        {
            throw new JsonException($"{context}.argument_schema must exactly describe params.");
        }
        for (var index = 0; index < parameters.Count; index++)
        {
            if (!string.Equals(parameters[index].Name, schema.Fields[index].Name, StringComparison.Ordinal)
                || !string.Equals(
                    parameters[index].TypeName,
                    schema.Fields[index].ValueType.CanonicalTypeName,
                    StringComparison.Ordinal))
            {
                throw new JsonException($"{context}.argument_schema must exactly describe params.");
            }
        }
    }

    private static void ValidateLifecycleName(
        ToriiContractEntrypointKind kind,
        string name,
        string context)
    {
        var matches = kind switch
        {
            ToriiContractEntrypointKind.Hajimari => name is "hajimari" or "始まり",
            ToriiContractEntrypointKind.Kaizen => name is "kaizen" or "改善",
            _ => name is not ("hajimari" or "始まり" or "kaizen" or "改善"),
        };
        if (!matches)
        {
            throw new JsonException($"{context}.kind does not match its branded lifecycle selector.");
        }
    }

    private static JsonObject BuildManifestNode(ToriiContractManifest value, string context)
    {
        var root = new JsonObject
        {
            ["seiyaku_name"] = value.SeiyakuName,
            ["code_hash"] = value.CodeHash is null ? null : FormatManifestHash(value.CodeHash, $"{context}.code_hash"),
            ["abi_hash"] = value.AbiHash is null ? null : FormatManifestHash(value.AbiHash, $"{context}.abi_hash"),
            ["compiler_fingerprint"] = value.CompilerFingerprint,
            ["features_bitmap"] = value.FeaturesBitmap.HasValue
                ? JsonValue.Create(value.FeaturesBitmap.Value)
                : null,
            ["access_set_hints"] = value.AccessSetHints is null ? null : BuildAccessSetHints(value.AccessSetHints, $"{context}.access_set_hints"),
            ["permissions"] = BuildArray(value.Permissions, BuildPermissionDeclaration, $"{context}.permissions"),
            ["events"] = BuildArray(value.Events, BuildEvent, $"{context}.events"),
            ["enum_types"] = BuildArray(value.EnumTypes, BuildEnumType, $"{context}.enum_types"),
            ["entrypoints"] = BuildOptionalArray(value.Entrypoints, (item, itemContext) => BuildEntrypoint(item, itemContext), $"{context}.entrypoints"),
            ["states"] = BuildOptionalArray(value.States, BuildState, $"{context}.states"),
            ["error_types"] = BuildOptionalArray(value.ErrorTypes, BuildErrorType, $"{context}.error_types"),
            ["error_messages"] = BuildOptionalArray(value.ErrorMessages, BuildErrorMessage, $"{context}.error_messages"),
            ["kotoba"] = BuildOptionalArray(value.Kotoba, BuildKotobaEntry, $"{context}.kotoba"),
            ["provenance"] = value.Provenance is null ? null : BuildProvenance(value.Provenance, $"{context}.provenance"),
        };
        ValidateExactStringOptional(value.SeiyakuName, $"{context}.seiyaku_name");
        if (value.SeiyakuName is not null && !IsCanonicalTypeDeclarationIdentifier(value.SeiyakuName))
        {
            throw new JsonException($"{context}.seiyaku_name must be a canonical Kotodama declaration identifier.");
        }
        ValidateExactStringOptional(value.CompilerFingerprint, $"{context}.compiler_fingerprint");
        if (value.FeaturesBitmap is > 3)
        {
            throw new JsonException($"{context}.features_bitmap contains unsupported Kotodama V1 bits.");
        }
        ValidatePermissionDeclarations(value.Permissions, (value.Entrypoints ?? Array.Empty<ToriiContractEntrypointDescriptor>()).Select(entry => entry.Authorization), context);
        ValidateManifestCollections(value.Entrypoints, value.States, value.ErrorTypes, value.EnumTypes, value.Events, value.ErrorMessages, value.Kotoba, context);
        ValidateDynamicAccessHintStateMaps(value.AccessSetHints, value.States, context);
        return root;
    }

    private static JsonObject BuildAccessSetHints(ToriiContractAccessSetHints value, string context)
    {
        return new JsonObject
        {
            ["read_keys"] = BuildStringArray(value.ReadKeys, $"{context}.read_keys"),
            ["write_keys"] = BuildStringArray(value.WriteKeys, $"{context}.write_keys"),
            ["dynamic_reads"] = BuildArray(value.DynamicReads, BuildDynamicHint, $"{context}.dynamic_reads"),
            ["dynamic_writes"] = BuildArray(value.DynamicWrites, BuildDynamicHint, $"{context}.dynamic_writes"),
        };
    }

    private static JsonObject BuildDynamicHint(ToriiContractDynamicAccessHint value, string context)
    {
        var baseKey = RequireExact(value.BaseKey, $"{context}.base_key");
        if (!IsCanonicalDynamicAccessBaseKey(baseKey))
        {
            throw new JsonException(
                $"{context}.base_key must be state: followed by one canonical state declaration identifier.");
        }
        var keyType = RequireExact(value.KeyType, $"{context}.key_type");
        if (!IsCanonicalKeyTypeName(keyType))
        {
            throw new JsonException(
                $"{context}.key_type must be an exact canonical StateMap key type.");
        }
        var boundKind = RequireExact(value.BoundKind, $"{context}.bound_kind");
        if (!DynamicAccessBoundKinds.Contains(boundKind))
        {
            throw new JsonException($"{context}.bound_kind must be take or page.");
        }
        if (value.MaxKeys is < 1 or > MaxDynamicAccessKeys)
        {
            throw new JsonException($"{context}.max_keys must be in 1..64.");
        }
        return new JsonObject
        {
            ["base_key"] = baseKey,
            ["key_type"] = keyType,
            ["bound_kind"] = boundKind,
            ["max_keys"] = value.MaxKeys,
        };
    }

    private static JsonObject BuildEntrypoint(ToriiContractEntrypointDescriptor value, string context)
    {
        if (!IsCanonicalEntrypointName(value.Name))
        {
            throw new JsonException($"{context}.name must be a canonical Kotodama selector.");
        }
        ValidateLifecycleName(value.Kind, value.Name, context);
        ValidateExactArguments(value.Parameters, value.ArgumentSchema, context);
        if (value.ReturnType is null || value.ReturnSchema is null
            || value.ReturnSchema.WordCount > MaxBoundaryWords
            || value.ReturnSchema.CanonicalTypeName != value.ReturnType)
        {
            throw new JsonException($"{context} return_type and return_schema must match.");
        }
        ValidateAuthorizationKind(value.Authorization, value.Kind, context);
        if (value.AccessHintsComplete == true && value.AccessHintsSkipped.Count != 0
            || value.AccessHintsComplete == false && value.AccessHintsSkipped.Count == 0)
        {
            throw new JsonException($"{context} access-hint completeness is inconsistent.");
        }
        return new JsonObject
        {
            ["name"] = value.Name,
            ["kind"] = new JsonObject { ["kind"] = value.Kind.ToString(), ["value"] = null },
            ["params"] = BuildArray(value.Parameters, BuildParameter, $"{context}.params"),
            ["argument_schema"] = value.ArgumentSchema is null ? null : BuildArgumentSchema(value.ArgumentSchema, $"{context}.argument_schema"),
            ["return_type"] = value.ReturnType,
            ["return_schema"] = value.ReturnSchema is null ? null : BuildValueType(value.ReturnSchema, $"{context}.return_schema"),
            ["authorization"] = BuildAuthorization(value.Authorization, $"{context}.authorization"),
            ["read_keys"] = BuildStringArray(value.ReadKeys, $"{context}.read_keys"),
            ["write_keys"] = BuildStringArray(value.WriteKeys, $"{context}.write_keys"),
            ["access_hints_complete"] = value.AccessHintsComplete.HasValue
                ? JsonValue.Create(value.AccessHintsComplete.Value)
                : null,
            ["access_hints_skipped"] = BuildStringArray(value.AccessHintsSkipped, $"{context}.access_hints_skipped"),
            ["triggers"] = BuildArray(value.Triggers, BuildTrigger, $"{context}.triggers"),
        };
    }

    private static JsonObject BuildParameter(ToriiContractEntrypointParameter value, string context)
    {
        if (!IsCanonicalBoundaryIdentifier(value.Name))
        {
            throw new JsonException($"{context}.name must be a canonical Kotodama identifier.");
        }
        return new JsonObject
        {
            ["name"] = value.Name,
            ["type_name"] = RequireExact(value.TypeName, $"{context}.type_name"),
        };
    }

    private static JsonObject BuildArgumentSchema(ToriiEntrypointArgumentSchemaV1 value, string context)
    {
        var fields = BuildArray(value.Fields, BuildArgumentField, $"{context}.fields");
        if (value.Fields.Count is < 1 or > MaxBoundaryWords
            || value.Fields.Sum(field => field.ValueType.WordCount) != value.WordCount
            || value.WordCount > MaxBoundaryWords)
        {
            throw new JsonException($"{context} violates V1 argument bounds.");
        }
        RequireUnique(value.Fields.Select(field => field.Name), $"{context}.fields");
        return new JsonObject { ["fields"] = fields };
    }

    private static JsonObject BuildArgumentField(ToriiEntrypointArgumentFieldV1 value, string context)
    {
        if (!IsCanonicalBoundaryIdentifier(value.Name))
        {
            throw new JsonException($"{context}.name must be a canonical Kotodama identifier.");
        }
        return new JsonObject
        {
            ["name"] = value.Name,
            ["ty"] = BuildValueType(value.ValueType, $"{context}.ty"),
        };
    }

    private static JsonObject BuildValueType(ToriiEntrypointValueTypeV1 value, string context)
    {
        if (value.Nodes.Count is < 1 or > MaxSchemaNodes)
        {
            throw new JsonException($"{context}.nodes must contain 1..256 items.");
        }
        var analysis = AnalyzeValueType(value.Nodes, 0, 1, context);
        if (analysis.NextIndex != value.Nodes.Count
            || analysis.WordCount != value.WordCount
            || analysis.TypeName != value.CanonicalTypeName)
        {
            throw new JsonException($"{context} carries inconsistent derived schema metadata.");
        }
        return new JsonObject
        {
            ["nodes"] = BuildArray(value.Nodes, BuildValueTypeNode, $"{context}.nodes"),
        };
    }

    private static JsonObject BuildValueTypeNode(ToriiEntrypointValueTypeNodeV1 value, string context)
    {
        JsonNode? payload = value.Kind switch
        {
            ToriiEntrypointValueTypeNodeKindV1.Struct => BuildStructNode(
                value.StructValue ?? throw new JsonException($"{context} struct metadata is required."),
                $"{context}.value"),
            ToriiEntrypointValueTypeNodeKindV1.Tuple => value.TupleArity is >= 2
                ? JsonValue.Create(value.TupleArity.Value)
                : throw new JsonException($"{context} tuple arity must be at least 2."),
            ToriiEntrypointValueTypeNodeKindV1.Option or ToriiEntrypointValueTypeNodeKindV1.Result
                or ToriiEntrypointValueTypeNodeKindV1.Unit => null,
            ToriiEntrypointValueTypeNodeKindV1.Error => BuildErrorType(value.ErrorValue!, $"{context}.value"),
            ToriiEntrypointValueTypeNodeKindV1.Enum => BuildEnumType(value.EnumValue!, $"{context}.value"),
            ToriiEntrypointValueTypeNodeKindV1.StateCursor => BuildValueType(value.CursorKeySchema!, $"{context}.value"),
            ToriiEntrypointValueTypeNodeKindV1.List => BuildListNode(
                value.ListValue ?? throw new JsonException($"{context} list metadata is required."),
                $"{context}.value"),
            ToriiEntrypointValueTypeNodeKindV1.Leaf => new JsonObject
            {
                ["kind"] = (value.LeafKind ?? throw new JsonException($"{context} leaf kind is required.")).ToString(),
                ["value"] = null,
            },
            _ => throw new JsonException($"{context} contains an unsupported node."),
        };
        return new JsonObject { ["kind"] = value.Kind.ToString(), ["value"] = payload };
    }

    private static JsonObject BuildStructNode(ToriiEntrypointStructTypeNodeV1 value, string context)
    {
        if (!IsCanonicalSchemaStructIdentifier(value.Name)
            || value.Fields.Any(field => !IsCanonicalBoundaryIdentifier(field)))
        {
            throw new JsonException($"{context} must use canonical Kotodama identifiers.");
        }
        RequireUnique(value.Fields, $"{context}.fields");
        return new JsonObject
        {
            ["name"] = value.Name,
            ["fields"] = BuildStringArray(value.Fields, $"{context}.fields"),
        };
    }

    private static JsonObject BuildListNode(ToriiEntrypointListTypeNodeV1 value, string context)
    {
        if (value.Capacity is < 1 or > 64)
        {
            throw new JsonException($"{context}.capacity must be in 1..64.");
        }
        return new JsonObject
        {
            ["capacity"] = value.Capacity,
        };
    }

    private static JsonObject BuildTrigger(ToriiContractTriggerDescriptor value, string context)
    {
        var id = RequireExact(value.Id, $"{context}.id");
        if (!IsCanonicalDeclarationIdentifier(id))
        {
            throw new JsonException($"{context}.id must be a canonical Kotodama declaration identifier.");
        }
        ValidateCanonicalBase64(value.FilterBase64, $"{context}.filter");
        if (value.Authority is not null)
        {
            try
            {
                _ = ToriiExplorerDirectMetadata.RequireCanonicalAccountId(value.Authority, $"{context}.authority");
            }
            catch (ArgumentException exception)
            {
                throw new JsonException($"{context}.authority must be a canonical I105 account id.", exception);
            }
        }
        return new JsonObject
        {
            ["id"] = id,
            ["repeats"] = value.Repeats.Kind switch
            {
                ToriiContractTriggerRepeatsKind.Indefinitely when value.Repeats.Exactly is null =>
                    new JsonObject { ["Indefinitely"] = null },
                ToriiContractTriggerRepeatsKind.Exactly when value.Repeats.Exactly is not null =>
                    new JsonObject { ["Exactly"] = JsonValue.Create(value.Repeats.Exactly.Value) },
                _ => throw new JsonException($"{context}.repeats is inconsistent."),
            },
            ["filter"] = value.FilterBase64,
            ["authority"] = value.Authority,
            ["metadata"] = value.Metadata,
            ["callback"] = BuildCallback(value.Callback, $"{context}.callback"),
        };
    }

    private static JsonObject BuildCallback(ToriiContractTriggerCallback value, string context)
    {
        if (!IsCanonicalEntrypointName(value.Entrypoint))
        {
            throw new JsonException($"{context}.entrypoint must be a canonical Kotodama selector.");
        }
        ValidateExactStringOptional(value.Namespace, $"{context}.namespace");
        if (value.Namespace is not null && !IsCanonicalTypeDeclarationIdentifier(value.Namespace))
        {
            throw new JsonException($"{context}.namespace must be a canonical Kotodama type-declaration identifier.");
        }
        return new JsonObject { ["namespace"] = value.Namespace, ["entrypoint"] = value.Entrypoint };
    }

    private static JsonObject BuildState(ToriiContractStateDescriptor value, string context)
    {
        if (!IsCanonicalDeclarationIdentifier(value.Name))
        {
            throw new JsonException($"{context}.name must be a canonical Kotodama declaration identifier.");
        }
        var typeName = RequireExact(value.TypeName, $"{context}.type_name");
        return new JsonObject
        {
            ["name"] = value.Name,
            ["type_name"] = typeName,
        };
    }

    private static JsonObject BuildErrorType(ToriiContractErrorTypeDescriptor value, string context)
    {
        ValidateErrorType(value, context);
        return new JsonObject
        {
            ["identity"] = value.Identity,
            ["variants"] = BuildArray(value.Variants, (variant, _) => new JsonObject
            {
                ["name"] = variant.Name,
                ["code"] = variant.Code,
            }, $"{context}.variants"),
        };
    }

    private static JsonObject BuildEnumType(ToriiContractEnumTypeDescriptor value, string context)
    {
        ValidateEnumType(value, context);
        return new JsonObject
        {
            ["identity"] = value.Identity,
            ["variants"] = BuildArray(value.Variants, (variant, _) => new JsonObject
            {
                ["name"] = variant.Name,
                ["code"] = variant.Code,
            }, $"{context}.variants"),
        };
    }

    private static JsonObject BuildKotobaEntry(ToriiContractKotobaTranslationEntry value, string context)
    {
        RequireUnique(value.Translations.Select(translation => translation.Language), $"{context}.translations");
        return new JsonObject
        {
            ["msg_id"] = RequireExact(value.MessageId, $"{context}.msg_id"),
            ["translations"] = BuildArray(value.Translations, BuildKotobaTranslation, $"{context}.translations"),
        };
    }

    private static JsonObject BuildKotobaTranslation(ToriiContractKotobaTranslation value, string context)
    {
        return new JsonObject
        {
            ["lang"] = RequireExact(value.Language, $"{context}.lang"),
            ["text"] = value.Text ?? throw new JsonException($"{context}.text is required."),
        };
    }

    private static JsonObject BuildProvenance(ToriiContractManifestProvenance value, string context)
    {
        return new JsonObject
        {
            ["signer"] = RequireExact(value.Signer, $"{context}.signer"),
            ["signature"] = RequireExact(value.Signature, $"{context}.signature"),
        };
    }

    private static JsonArray? BuildOptionalArray<T>(
        IReadOnlyList<T>? values,
        Func<T, string, JsonObject> builder,
        string context)
    {
        return values is null ? null : BuildArray(values, builder, context);
    }

    private static JsonArray BuildArray<T>(
        IReadOnlyList<T> values,
        Func<T, string, JsonObject> builder,
        string context)
    {
        var result = new JsonArray();
        for (var index = 0; index < values.Count; index++)
        {
            result.Add(builder(values[index], $"{context}[{index}]"));
        }
        return result;
    }

    private static JsonArray BuildStringArray(IReadOnlyList<string> values, string context)
    {
        var result = new JsonArray();
        for (var index = 0; index < values.Count; index++)
        {
            result.Add(RequireExact(values[index], $"{context}[{index}]"));
        }
        return result;
    }

    private static IReadOnlyList<T>? OptionalObjectList<T>(
        JsonObject root,
        string name,
        string context,
        Func<JsonObject, string, T> parser)
    {
        return !root.ContainsKey(name) || root[name] is null
            ? null
            : RequiredObjectList(root, name, context, parser);
    }

    private static IReadOnlyList<T> DefaultObjectList<T>(
        JsonObject root,
        string name,
        string context,
        Func<JsonObject, string, T> parser)
    {
        if (!root.ContainsKey(name))
        {
            return Array.Empty<T>();
        }
        return RequiredObjectList(root, name, context, parser);
    }

    private static IReadOnlyList<T> RequiredObjectList<T>(
        JsonObject root,
        string name,
        string context,
        Func<JsonObject, string, T> parser)
    {
        if (root[name] is not JsonArray array)
        {
            throw new JsonException($"{context} must be an array.");
        }
        var result = new List<T>(array.Count);
        for (var index = 0; index < array.Count; index++)
        {
            if (array[index] is not JsonObject item)
            {
                throw new JsonException($"{context}[{index}] must be an object.");
            }
            result.Add(parser(item, $"{context}[{index}]"));
        }
        return result;
    }

    private static IReadOnlyList<string> RequiredStringList(JsonObject root, string name, string context)
    {
        if (!root.ContainsKey(name))
        {
            throw new JsonException($"{context} is required.");
        }
        return ReadStringList(root[name], context);
    }

    private static IReadOnlyList<string> DefaultStringList(JsonObject root, string name, string context)
    {
        return !root.ContainsKey(name) ? Array.Empty<string>() : ReadStringList(root[name], context);
    }

    private static IReadOnlyList<string> ReadStringList(JsonNode? node, string context)
    {
        if (node is not JsonArray array)
        {
            throw new JsonException($"{context} must be an array.");
        }
        var result = new List<string>(array.Count);
        for (var index = 0; index < array.Count; index++)
        {
            result.Add(ReadExactString(array[index], $"{context}[{index}]"));
        }
        return result;
    }

    private static JsonObject RequiredObject(JsonObject root, string name, string context)
    {
        if (!root.TryGetPropertyValue(name, out var value) || value is null)
        {
            throw new JsonException($"{context} is required.");
        }
        return value as JsonObject
            ?? throw new JsonException($"{context} must be an object.");
    }

    private static JsonObject? OptionalObject(JsonObject root, string name, string context)
    {
        if (!root.TryGetPropertyValue(name, out var value) || value is null)
        {
            return null;
        }
        return value as JsonObject ?? throw new JsonException($"{context} must be an object.");
    }

    private static string RequiredExactString(JsonObject root, string name, string context)
    {
        return root.ContainsKey(name)
            ? ReadExactString(root[name], context)
            : throw new JsonException($"{context} is required.");
    }

    private static string RequiredStringAllowEmpty(JsonObject root, string name, string context)
    {
        if (!root.TryGetPropertyValue(name, out var value)
            || value is not JsonValue jsonValue
            || !jsonValue.TryGetValue<string>(out var text))
        {
            throw new JsonException($"{context} must be a string.");
        }
        return text;
    }

    private static string? OptionalExactString(JsonObject root, string name, string context)
    {
        return !root.TryGetPropertyValue(name, out var value) || value is null
            ? null
            : ReadExactString(value, context);
    }

    private static string ReadExactString(JsonNode? node, string context)
    {
        if (node is not JsonValue value || !value.TryGetValue<string>(out var text))
        {
            throw new JsonException($"{context} must be a string.");
        }
        return RequireExact(text, context);
    }

    private static string RequireExact(string? text, string context)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new JsonException($"{context} must be a non-empty string.");
        }
        if (!string.Equals(text.Trim(), text, StringComparison.Ordinal))
        {
            throw new JsonException($"{context} must not contain surrounding whitespace.");
        }
        if (text.Any(char.IsControl))
        {
            throw new JsonException($"{context} must not contain control characters.");
        }
        return text;
    }

    private static void ValidateExactStringOptional(string? text, string context)
    {
        if (text is not null)
        {
            _ = RequireExact(text, context);
        }
    }

    private static bool? OptionalBoolean(JsonObject root, string name, string context)
    {
        if (!root.TryGetPropertyValue(name, out var value) || value is null)
        {
            return null;
        }
        return value is JsonValue scalar && scalar.TryGetValue<bool>(out var boolean)
            ? boolean
            : throw new JsonException($"{context} must be a boolean.");
    }

    private static ulong? OptionalUInt64(JsonObject root, string name, string context)
    {
        if (!root.TryGetPropertyValue(name, out var value) || value is null)
        {
            return null;
        }
        return ReadUInt64(value, context);
    }

    private static uint RequiredUInt32(JsonObject root, string name, string context)
    {
        var value = ReadUInt64(root.ContainsKey(name) ? root[name] : null, context);
        return value <= uint.MaxValue
            ? (uint)value
            : throw new JsonException($"{context} must fit in an unsigned 32-bit integer.");
    }

    private static ushort RequiredUInt16(JsonObject root, string name, string context)
    {
        var value = ReadUInt64(root.ContainsKey(name) ? root[name] : null, context);
        return value <= ushort.MaxValue
            ? (ushort)value
            : throw new JsonException($"{context} must fit in an unsigned 16-bit integer.");
    }

    private static byte RequiredByte(JsonObject root, string name, string context)
    {
        var value = ReadUInt64(root.ContainsKey(name) ? root[name] : null, context);
        return value <= byte.MaxValue
            ? (byte)value
            : throw new JsonException($"{context} must fit in an unsigned byte.");
    }

    private static ulong ReadUInt64(JsonNode? node, string context)
    {
        if (node is not JsonValue value || !value.TryGetValue<ulong>(out var number))
        {
            throw new JsonException($"{context} must be an unsigned integer.");
        }
        return number;
    }

    private static string? OptionalManifestHash(JsonObject root, string name, string context)
    {
        if (!root.TryGetPropertyValue(name, out var value) || value is null)
        {
            return null;
        }
        return ParseManifestHash(ReadStringAllowingFormat(value, context), context);
    }

    private static string? OptionalConvenienceHash(JsonObject root, string name, string context)
    {
        if (!root.TryGetPropertyValue(name, out var value) || value is null)
        {
            return null;
        }
        var hash = ReadStringAllowingFormat(value, context);
        ValidateConvenienceHash(hash, context);
        return hash;
    }

    private static string ReadStringAllowingFormat(JsonNode node, string context)
    {
        return node is JsonValue value && value.TryGetValue<string>(out var text)
            ? text
            : throw new JsonException($"{context} must be a string.");
    }

    private static string ParseManifestHash(string value, string context) =>
        CanonicalHashLiteral.Parse(value, context);

    private static string FormatManifestHash(string value, string context) =>
        CanonicalHashLiteral.Format(value, context);

    private static void ValidateConvenienceHash(string? value, string context) =>
        CanonicalHashLiteral.ValidateHex(value, context);

    private static void ValidateCanonicalBase64(string value, string context)
    {
        try
        {
            var bytes = Convert.FromBase64String(value);
            if (bytes.Length == 0 || Convert.ToBase64String(bytes) != value)
            {
                throw new JsonException($"{context} must be non-empty canonical base64.");
            }
        }
        catch (FormatException exception)
        {
            throw new JsonException($"{context} must be canonical base64.", exception);
        }
    }

    internal static void EnsureOnly(JsonObject root, string context, params string[] allowed)
    {
        var names = allowed.ToHashSet(StringComparer.Ordinal);
        foreach (var property in root)
        {
            if (!names.Contains(property.Key))
            {
                throw new JsonException($"{context} contains unknown field `{property.Key}`.");
            }
        }
    }

    private static void RequireUnique(IEnumerable<string> values, string context)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            if (!seen.Add(value))
            {
                throw new JsonException($"{context} must not contain duplicates.");
            }
        }
    }

    private static bool IsCanonicalBoundaryIdentifier(string value)
    {
        return HasIdentifierSyntax(value)
            && !Keywords.Contains(value)
            && !value.StartsWith("__kotodama_link_", StringComparison.Ordinal);
    }

    private static bool IsCanonicalDeclarationIdentifier(string value)
    {
        return IsCanonicalBoundaryIdentifier(value)
            && !ReservedDeclarationNames.Contains(value);
    }

    private static bool IsCanonicalDynamicAccessBaseKey(string value)
    {
        const string Prefix = "state:";
        return value.StartsWith(Prefix, StringComparison.Ordinal)
            && IsCanonicalDeclarationIdentifier(value[Prefix.Length..]);
    }

    private static bool IsCanonicalTypeDeclarationIdentifier(string value)
    {
        return IsCanonicalDeclarationIdentifier(value)
            && !RetiredNumericTypeNames.Contains(value);
    }

    private static bool IsCanonicalQualifiedStructIdentifier(string value)
    {
        if (value.Length > 1024 || value.Any(character => character > 127)
            || value.Contains("__kotodama_link_", StringComparison.Ordinal))
        {
            return false;
        }
        var parts = value.Split("::", StringSplitOptions.None);
        if (parts.Length == 2)
        {
            if (parts[0] == "kotodama") return IsCoreQueryViewName(value) || value is "kotodama::QueryPage" or "kotodama::StatePage";
            return parts.All(IsCanonicalTypeDeclarationIdentifier);
        }
        if (parts.Length == 4 && parts[0] == "local")
        {
            return parts[1].Length == 64 && parts[1].All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f')
                && IsCanonicalTypeDeclarationIdentifier(parts[2]) && IsCanonicalTypeDeclarationIdentifier(parts[3]);
        }
        if (parts.Length != 3
            || !IsCanonicalTypeDeclarationIdentifier(parts[1])
            || !IsCanonicalTypeDeclarationIdentifier(parts[2]))
        {
            return false;
        }
        static bool Component(string component) => component.Length != 0
            && (IsAsciiLetter(component[0]) || char.IsAsciiDigit(component[0]) || component[0] == '_')
            && component.All(character => IsAsciiLetter(character) || char.IsAsciiDigit(character)
                || character is '_' or '.' or '-');
        var package = parts[0].Split('@');
        return package.Length is 1 or 2
            && package[0].Split('/').All(Component)
            && (package.Length == 1 || Component(package[1]));
    }

    private static bool IsCanonicalUserStructIdentifier(string value) =>
        value.Length <= 1024
            && IsCanonicalQualifiedStructIdentifier(value);

    private sealed class KeyTypeNameParser(string value, int start = 0)
    {
        public int Cursor { get; private set; } = start;
        public int Nodes { get; private set; }
        public int MaxDepth { get; private set; }

        public bool Parse(int depth = 1)
        {
            if (++Nodes > MaxSchemaNodes || depth > MaxSchemaDepth) return false;
            MaxDepth = Math.Max(MaxDepth, depth);
            if (Consume("("))
            {
                if (!Parse(depth + 1) || !Consume(", ") || !Parse(depth + 1)) return false;
                while (Consume(", ")) if (!Parse(depth + 1)) return false;
                return Consume(")");
            }
            var begin = Cursor;
            while (Cursor < value.Length && (IsAsciiLetter(value[Cursor]) || value[Cursor] == '_'
                || char.IsAsciiDigit(value[Cursor]))) Cursor++;
            return StateMapKeyTypeNames.Contains(value[begin..Cursor]);
        }

        private bool Consume(string token)
        {
            if (!value.AsSpan(Cursor).StartsWith(token, StringComparison.Ordinal)) return false;
            Cursor += token.Length;
            return true;
        }
    }

    private static bool IsCanonicalKeyTypeName(string value)
    {
        var parser = new KeyTypeNameParser(value);
        return parser.Parse() && parser.Cursor == value.Length;
    }

    private static bool IsCanonicalStateTypeName(string value, IEnumerable<string> errorIdentities)
    {
        if (value.Length == 0)
        {
            return false;
        }

        var cursor = 0;
        var nodes = 0;
        var errors = errorIdentities.OrderByDescending(identity => identity.Length).ToArray();

        bool Consume(string literal)
        {
            if (cursor > value.Length - literal.Length
                || string.CompareOrdinal(value, cursor, literal, 0, literal.Length) != 0)
            {
                return false;
            }
            cursor += literal.Length;
            return true;
        }

        string? Identifier()
        {
            var start = cursor;
            if (cursor >= value.Length
                || (value[cursor] != '_' && !IsAsciiLetter(value[cursor])))
            {
                return null;
            }
            cursor++;
            while (cursor < value.Length
                && (value[cursor] == '_'
                    || IsAsciiLetter(value[cursor])
                    || char.IsAsciiDigit(value[cursor])))
            {
                cursor++;
            }
            return value[start..cursor];
        }

        string? TypeIdentifier()
        {
            var start = cursor;
            while (cursor < value.Length
                && (IsAsciiLetter(value[cursor]) || char.IsAsciiDigit(value[cursor])
                    || "_:/@.-".Contains(value[cursor])))
            {
                cursor++;
            }
            var candidate = value[start..cursor];
            if (IsCanonicalQualifiedStructIdentifier(candidate)) return candidate;
            cursor = start;
            return Identifier();
        }

        bool ListCapacity()
        {
            var start = cursor;
            var capacity = 0;
            var exceededMaximum = false;
            while (cursor < value.Length && char.IsAsciiDigit(value[cursor]))
            {
                if (!exceededMaximum)
                {
                    capacity = capacity * 10 + value[cursor] - '0';
                    exceededMaximum = capacity > 64;
                }
                cursor++;
            }
            if (cursor == start || (cursor - start > 1 && value[start] == '0'))
            {
                return false;
            }
            return !exceededMaximum && capacity is >= 1 and <= 64;
        }

        string? ParseKey(int depth)
        {
            var start = cursor;
            var parser = new KeyTypeNameParser(value, cursor);
            if (!parser.Parse() || nodes + parser.Nodes > MaxStateTypeNodes
                || depth + parser.MaxDepth - 1 > MaxStateTypeDepth) return null;
            cursor = parser.Cursor;
            nodes += parser.Nodes;
            return value[start..cursor];
        }

        string? ParseType(bool allowStateMap, int depth)
        {
            nodes++;
            if (depth > MaxStateTypeDepth || nodes > MaxStateTypeNodes)
            {
                return null;
            }

            if (Consume("()")) return "()";
            foreach (var identity in errors)
            {
                var end = cursor + identity.Length;
                if ((end == value.Length || (end < value.Length && ",>)}".Contains(value[end])))
                    && Consume(identity))
                {
                    return identity;
                }
            }

            if (Consume("("))
            {
                if (ParseType(false, depth + 1) is null
                    || !Consume(", ")
                    || ParseType(false, depth + 1) is null)
                {
                    return null;
                }
                while (Consume(", "))
                {
                    if (ParseType(false, depth + 1) is null)
                    {
                        return null;
                    }
                }
                return Consume(")") ? string.Empty : null;
            }

            var name = TypeIdentifier();
            if (name is null)
            {
                return null;
            }
            if (StateScalarTypeNames.Contains(name))
            {
                return name;
            }
            if (name == "StateCursor")
            {
                if (!Consume("<")) return null;
                var key = ParseKey(depth + 1);
                return key is not null && Consume(">")
                    ? string.Empty : null;
            }
            if (name == "kotodama::StatePage")
            {
                // StatePage has one exact reserved shape, including matching key types.
                nodes += 4; // List, Tuple, Option, StateCursor; keys count separately.
                if (nodes > MaxStateTypeNodes || depth + 3 > MaxStateTypeDepth
                    || !Consume("{items: List<(")) return null;
                var key = ParseKey(depth + 3);
                if (key is null || !Consume(", ")
                    || ParseType(false, depth + 3) is null || !Consume("), ")
                    || !ListCapacity() || !Consume(">, next: Option<StateCursor<")) return null;
                return ParseKey(depth + 3) == key && Consume(">>}") ? string.Empty : null;
            }
            if (name == "Option")
            {
                return Consume("<")
                    && ParseType(false, depth + 1) is not null
                    && Consume(">")
                        ? string.Empty
                        : null;
            }
            if (name == "Result")
            {
                return Consume("<")
                    && ParseType(false, depth + 1) is not null
                    && Consume(", ")
                    && ParseType(false, depth + 1) is not null
                    && Consume(">")
                        ? string.Empty
                        : null;
            }
            if (name == "List")
            {
                return Consume("<")
                    && ParseType(false, depth + 1) is not null
                    && Consume(", ")
                    && ListCapacity()
                    && Consume(">")
                        ? string.Empty
                        : null;
            }
            if (name == "StateMap")
            {
                if (!allowStateMap || !Consume("<"))
                {
                    return null;
                }
                // Runtime reconstructs only V as StateValueSchemaV1, so the
                // wrapper and key have separate bounded schemas.
                nodes--;
                var valueNodes = nodes;
                nodes = 0;
                var keyType = ParseKey(depth + 1);
                nodes = valueNodes;
                // EmbeddedStateType depth still includes the map wrapper.
                return keyType is not null
                    && Consume(", ")
                    && ParseType(false, depth + 1) is not null
                    && Consume(">")
                        ? string.Empty
                        : null;
            }
            if (!IsCanonicalUserStructIdentifier(name) || !Consume("{"))
            {
                return null;
            }
            // Empty products retain their validated nominal name and have no fields.
            if (Consume("}")) return IsExactDurableBuiltinProduct(name, Array.Empty<string>(), Array.Empty<string>()) ? string.Empty : null;
            var fields = new List<string>();
            var types = new List<string>();
            while (true)
            {
                var field = Identifier();
                if (field is null
                    || !IsCanonicalBoundaryIdentifier(field)
                    || fields.Contains(field, StringComparer.Ordinal)
                    || !Consume(": "))
                {
                    return null;
                }
                fields.Add(field);
                var childStart = cursor;
                if (ParseType(false, depth + 1) is null) return null;
                types.Add(value.Substring(childStart, cursor - childStart));
                if (Consume("}"))
                {
                    return IsExactDurableBuiltinProduct(name, fields, types) ? string.Empty : null;
                }
                if (!Consume(", "))
                {
                    return null;
                }
            }
        }

        return ParseType(true, 1) is not null && cursor == value.Length;
    }

    private static bool IsCanonicalSchemaStructIdentifier(string value)
    {
        return IsCanonicalUserStructIdentifier(value)
            || value is "kotodama::QueryPage" or "kotodama::StatePage"
            || IsCoreQueryViewName(value);
    }

    private static bool IsCanonicalEntrypointName(string value)
    {
        return value is "hajimari" or "始まり" or "kaizen" or "改善"
            || IsCanonicalDeclarationIdentifier(value);
    }

    private static bool HasIdentifierSyntax(string value)
    {
        return value.Length > 0
            && (value[0] == '_' || IsAsciiLetter(value[0]))
            && value.Skip(1).All(character => character == '_' || IsAsciiLetter(character) || char.IsAsciiDigit(character));
    }

    private static bool IsAsciiLetter(char value)
    {
        return value is >= 'A' and <= 'Z' or >= 'a' and <= 'z';
    }



    private readonly record struct TypeAnalysis(
        int NextIndex,
        int NodeCount,
        int WordCount,
        int MaxDepth,
        string TypeName,
        string? CoreQueryViewName,
        string? ListElementCoreQueryViewName);

    private readonly record struct AnalysisFrame(int RemainingChildren, bool SuppressWords);

    private sealed record RenderedType(
        string TypeName,
        string? CoreQueryViewName,
        byte? ListCapacity,
        string? ListElementCoreQueryViewName)
    {
        public RenderedType? ListElement { get; init; }
        public RenderedType? OptionElement { get; init; }
        public IReadOnlyList<RenderedType>? TupleChildren { get; init; }
        public ToriiEntrypointValueKindV1? LeafKind { get; init; }
        public string? CursorKeyTypeName { get; init; }
    }
}
