using System.Text.Json;
using System.Text.Json.Nodes;
using Hyperledger.Iroha.Torii;

namespace Hyperledger.Iroha.Sdk.Tests;

public sealed class ContractManifestTests
{
    private static JsonObject OrdinaryEnumManifest() => JsonNode.Parse("""
        {"permissions":[],"enum_types":[{"identity":"Demo::Status","variants":[{"name":"Pending","code":1},{"name":"Done","code":7}]}],
         "events":[{"name":"Changed","payload_type":{"nodes":[{"kind":"Struct","value":{"name":"Demo::Changed","fields":["status"]}},{"kind":"Enum","value":{"identity":"Demo::Status","variants":[{"name":"Pending","code":1},{"name":"Done","code":7}]}}]}}],
         "states":[{"name":"status","type_name":"Demo::Status"}]}
        """)!.AsObject();

    [Fact]
    public void OrdinaryEnumsAndEventsBindExactNominalSchemas()
    {
        var parsed = OrdinaryEnumManifest().Deserialize<ToriiContractManifest>()!;
        Assert.Equal(7U, parsed.EnumTypes.Single().Variants[1].Code);
        var node = parsed.Events.Single().PayloadType.Nodes[1];
        Assert.Equal(ToriiEntrypointValueTypeNodeKindV1.Enum, node.Kind);
        Assert.Equal("Demo::Status", node.EnumValue!.Identity);
        Assert.Null(node.ErrorValue);
        var roundtrip = JsonSerializer.Deserialize<ToriiContractManifest>(JsonSerializer.Serialize(parsed))!;
        Assert.Equal(1, roundtrip.Events.Single().PayloadType.WordCount);
        foreach (Action<JsonObject> mutate in new Action<JsonObject>[] {
            root => root.Remove("enum_types"),
            root => root.Remove("events"),
            root => root["enum_types"] = null,
            root => root["events"] = null,
            root => root["enum_types"]!.AsArray().Add(root["enum_types"]![0]!.DeepClone()),
            root => root["enum_types"]![0]!["variants"]![0]!["code"] = 0,
            root => root["error_types"] = root["enum_types"]!.DeepClone(),
            root => root["events"]![0]!["payload_type"]!["nodes"]![1]!["value"]!["variants"]![1]!["code"] = 8,
            root => root["events"]![0]!["payload_type"]!["nodes"]![1]!["kind"] = "Error",
            root => root["events"]![0]!["name"] = "Other",
            root => root["events"]![0]!["payload_type"]!["nodes"]![1] = JsonNode.Parse("""{"kind":"Leaf","value":{"kind":"Json","value":null}}"""),
            root => root["events"]![0]!["payload_type"]!["nodes"]![1] = JsonNode.Parse("""{"kind":"StateCursor","value":{"kind":"Int","value":null}}"""),
            root => root["events"]!.AsArray().Add(root["events"]![0]!.DeepClone()),
        }) {
            var invalid = OrdinaryEnumManifest();
            mutate(invalid);
            Assert.Throws<JsonException>(() => invalid.Deserialize<ToriiContractManifest>());
        }
        var forged = parsed with { Events = [parsed.Events.Single() with {
            PayloadType = parsed.Events.Single().PayloadType with { Nodes = [
                parsed.Events.Single().PayloadType.Nodes[0], node with { ErrorValue = new() { Identity = "Demo::Status" } },
            ] },
        }] };
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(forged));
    }

    private const string FilterBase64 =
        "TlJUMAAAl9+YQQ4oJZjALRf6FAto0QAKAAAAAAAAANzCjydU9+jNAgIAAAAFBAAAAAA=";

    [Fact]
    public void FullManifestPreservesExactKotodamaV1Interface()
    {
        var record = JsonSerializer.Deserialize<ToriiContractCodeRecord>(FullResponse())!;
        var manifest = record.Manifest;

        Assert.Equal("Ledger", manifest.SeiyakuName);
        Assert.Equal(new string('b', 64), manifest.CodeHash);
        Assert.Equal(new string('d', 64), manifest.AbiHash);
        Assert.Equal((uint)64, manifest.AccessSetHints!.DynamicReads.Single().MaxKeys);
        var entrypoint = manifest.Entrypoints!.Single();
        Assert.Equal(ToriiContractEntrypointKind.Kotoage, entrypoint.Kind);
        Assert.Equal(2, entrypoint.ArgumentSchema!.Fields[0].ValueType.WordCount);
        Assert.Equal("struct Fixture::Transfer", entrypoint.ArgumentSchema.Fields[0].ValueType.CanonicalTypeName);
        Assert.Equal("List<Name, 64>", entrypoint.ArgumentSchema.Fields[1].ValueType.CanonicalTypeName);
        Assert.Equal(2, entrypoint.ArgumentSchema.Fields[1].ValueType.Nodes.Count);
        Assert.Equal(
            (byte)64,
            entrypoint.ArgumentSchema.Fields[1].ValueType.Nodes[0].ListValue!.Capacity);
        Assert.Equal(1, entrypoint.ReturnSchema!.WordCount);
        Assert.Equal("Result<(bool, int), string>", entrypoint.ReturnSchema.CanonicalTypeName);
        Assert.Equal(ToriiContractTriggerRepeatsKind.Indefinitely, entrypoint.Triggers.Single().Repeats.Kind);
        Assert.Equal("transfer", entrypoint.Triggers.Single().Callback.Entrypoint);
        Assert.Equal("daily-settlement", entrypoint.Triggers.Single().Metadata["purpose"]!.GetValue<string>());
        Assert.Equal("StateMap<AccountId, quantity>", manifest.States!.Single().TypeName);
        Assert.Equal((uint)1001, manifest.ErrorTypes!.Single().Variants.Single().Code);
        Assert.Equal("ja", manifest.Kotoba!.Single().Translations.Last().Language);
        Assert.Equal("ed25519:fixture", manifest.Provenance!.Signer);

        var encoded = JsonSerializer.Serialize(record);
        Assert.Contains("\"seiyaku_name\":\"Ledger\"", encoded, StringComparison.Ordinal);
        Assert.Contains("hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2", encoded, StringComparison.Ordinal);
        Assert.DoesNotContain("contract_name", encoded, StringComparison.Ordinal);
        Assert.DoesNotContain("\"element\"", encoded, StringComparison.Ordinal);
    }

    [Fact]
    public void ManifestTriggerBoundariesRejectExactAmountSourceFormOnly()
    {
        var response = FullResponse();
        foreach (var retired in new[]
        {
            ReplaceFirst(response, "\"id\":\"settle\"", "\"id\":\"Amount\""),
            ReplaceFirst(response, "\"namespace\":null", "\"namespace\":\"Amount\""),
        })
        {
            Assert.Throws<JsonException>(
                () => JsonSerializer.Deserialize<ToriiContractCodeRecord>(retired));
        }

        var lowercase = ReplaceFirst(
            ReplaceFirst(response, "\"id\":\"settle\"", "\"id\":\"amount\""),
            "\"namespace\":null",
            "\"namespace\":\"RemoteLedger\"");
        var manifest = JsonSerializer.Deserialize<ToriiContractCodeRecord>(lowercase)!.Manifest;
        var entrypoint = manifest.Entrypoints!.Single();
        var trigger = entrypoint.Triggers.Single();
        Assert.Equal("amount", trigger.Id);
        Assert.Equal("RemoteLedger", trigger.Callback.Namespace);

        var retiredId = manifest with
        {
            Entrypoints = new[]
            {
                entrypoint with { Triggers = new[] { trigger with { Id = "Amount" } } },
            },
        };
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(retiredId));

        var retiredNamespace = manifest with
        {
            Entrypoints = new[]
            {
                entrypoint with
                {
                    Triggers = new[]
                    {
                        trigger with
                        {
                            Callback = trigger.Callback with { Namespace = "Amount" },
                        },
                    },
                },
            },
        };
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(retiredNamespace));
    }

    [Fact]
    public void EntrypointSchemasUseOneFlatPreorderTapeAndExactReservedNames()
    {
        var views = QueryViews();
        foreach (var (name, fields, children) in views)
        {
            var viewNodes = new[] { StructNode(name, fields) }.Concat(children).ToArray();
            var (_, view) = ParseReturnSchema(viewNodes, name);
            Assert.Equal(name, view.CanonicalTypeName);

            var optionalNodes = new[] { NullNode("Option") }.Concat(viewNodes).ToArray();
            var (_, optional) = ParseReturnSchema(optionalNodes, $"Option<{name}>");
            Assert.Equal($"Option<{name}>", optional.CanonicalTypeName);

            var pageNodes = new[]
                {
                    StructNode("QueryPage", new[] { "items", "next_offset" }),
                    ListNode(64),
                }
                .Concat(viewNodes)
                .Concat(new[] { NullNode("Option"), Leaf("Int") })
                .ToArray();
            var (manifest, page) = ParseReturnSchema(pageNodes, $"QueryPage<{name}>");
            Assert.Equal($"QueryPage<{name}>", page.CanonicalTypeName);
            Assert.Equal(2, page.WordCount);

            var encoded = JsonSerializer.Serialize(manifest);
            Assert.DoesNotContain("\"element\"", encoded, StringComparison.Ordinal);
            var decodedAgain = JsonSerializer.Deserialize<ToriiContractManifest>(encoded)!;
            Assert.Equal(
                $"QueryPage<{name}>",
                decodedAgain.Entrypoints!.Single().ReturnSchema!.CanonicalTypeName);
        }

        var (_, pair) = ParseReturnSchema(
            new[]
            {
                StructNode("Fixture::Pair", new[] { "left", "right" }),
                Leaf("Int"),
                Leaf("Bool"),
            },
            "struct Fixture::Pair");
        Assert.Equal("struct Fixture::Pair", pair.CanonicalTypeName);
    }

    [Fact]
    public void EntrypointSchemasExposeOnlyTheFirstReleaseNumericKinds()
    {
        foreach (var (wireKind, typeName) in new[]
        {
            ("Int", "int"),
            ("Decimal", "decimal"),
            ("Quantity", "quantity"),
        })
        {
            var (_, schema) = ParseReturnSchema(new[] { Leaf(wireKind) }, typeName);
            Assert.Equal(typeName, schema.CanonicalTypeName);
        }

        foreach (var retired in new[] { "U128", "Amount" })
        {
            AssertSchemaRejected(new[] { Leaf(retired) }, retired, "unsupported");
        }
    }

    [Fact]
    public void EntrypointSchemasRejectLegacyTruncatedDeepAndForgedTapes()
    {
        foreach (var (name, fields, children) in QueryViews())
        {
            var wrongFields = fields.ToArray();
            wrongFields[^1] = "forged";
            AssertForgedSchemaRejected(
                new[] { StructNode(name, wrongFields) }.Concat(children),
                name);

            var wrongLeaf = children.ToArray();
            wrongLeaf[^1] = Leaf("Blob");
            AssertForgedSchemaRejected(
                new[] { StructNode(name, fields) }.Concat(wrongLeaf),
                name);

            var viewNodes = new[] { StructNode(name, fields) }.Concat(children);
            AssertForgedSchemaRejected(
                new[]
                    {
                        StructNode("QueryPage", new[] { "items", "next_offset" }),
                        ListNode(64),
                    }
                    .Concat(viewNodes)
                    .Concat(new[] { NullNode("Option"), Leaf("String") }),
                $"QueryPage<{name}>");
            AssertForgedSchemaRejected(
                new[]
                    {
                        StructNode("QueryPage", new[] { "items", "next_offset" }),
                        ListNode(32),
                    }
                    .Concat(viewNodes)
                    .Concat(new[] { NullNode("Option"), Leaf("Int") }),
                $"QueryPage<{name}>");
        }

        AssertSchemaRejected(
            new[]
            {
                """
                {"kind":"List","value":{"capacity":64,"element":{"nodes":[{"kind":"Leaf","value":{"kind":"Name","value":null}}]}}}
                """,
            },
            "List<Name, 64>",
            "unknown field");
        AssertSchemaRejected(new[] { ListNode(64) }, "List<int, 64>", "ends before");
        AssertSchemaRejected(
            new[] { Leaf("Bool"), Leaf("Bool") },
            "bool",
            "complete canonical prefix type tree");
        AssertSchemaRejected(
            new[] { ListNode(0), Leaf("Int") },
            "List<int, 0>",
            "capacity");
        AssertSchemaRejected(
            new[] { ListNode(65), Leaf("Int") },
            "List<int, 65>",
            "capacity");

        var forgedForEncoding = new ToriiEntrypointValueTypeV1
        {
            Nodes = new[]
            {
                new ToriiEntrypointValueTypeNodeV1
                {
                    Kind = ToriiEntrypointValueTypeNodeKindV1.Struct,
                    StructValue = new ToriiEntrypointStructTypeNodeV1
                    {
                        Name = "kotodama::AccountView",
                        Fields = new[] { "id", "metadata" },
                    },
                },
                new ToriiEntrypointValueTypeNodeV1
                {
                    Kind = ToriiEntrypointValueTypeNodeKindV1.Leaf,
                    LeafKind = ToriiEntrypointValueKindV1.AccountId,
                },
                new ToriiEntrypointValueTypeNodeV1
                {
                    Kind = ToriiEntrypointValueTypeNodeKindV1.Leaf,
                    LeafKind = ToriiEntrypointValueKindV1.Blob,
                },
            },
            WordCount = 2,
            CanonicalTypeName = "kotodama::AccountView",
        };
        var forgedManifest = new ToriiContractManifest
        {
            Permissions = Array.Empty<ToriiContractPermissionDescriptorV1>(),
            Events = [],
            EnumTypes = [],
            Entrypoints = new[]
            {
                new ToriiContractEntrypointDescriptor
                {
                    Authorization = new ToriiEntrypointAuthorizationV1.Anyone(),
                    Name = "inspect",
                    Kind = ToriiContractEntrypointKind.View,
                    ReturnType = "AccountView",
                    ReturnSchema = forgedForEncoding,
                    AccessHintsComplete = true,
                },
            },
        };
        var encodingError = Assert.Throws<JsonException>(
            () => JsonSerializer.Serialize(forgedManifest));
        Assert.Contains("return_type and return_schema", encodingError.Message, StringComparison.Ordinal);

        var atLimitNodes = Enumerable.Repeat(ListNode(1), 255)
            .Append(Leaf("Int"))
            .ToArray();
        var atLimitName = "int";
        for (var depth = 0; depth < 255; depth++)
        {
            atLimitName = $"List<{atLimitName}, 1>";
        }
        var (_, atLimit) = ParseReturnSchema(atLimitNodes, atLimitName);
        Assert.Equal(1, atLimit.WordCount);

        AssertSchemaRejected(
            Enumerable.Repeat(ListNode(1), 256).Append(Leaf("Int")),
            atLimitName,
            "1..256");
    }

    [Fact]
    public void ManifestRejectsUnknownEnglishAndNoncanonicalShapes()
    {
        var response = FullResponse();
        var invalid = new[]
        {
            ReplaceFirst(response, "\"seiyaku_name\"", "\"contract_name\""),
            ReplaceFirst(response, "\"Kotoage\"", "\"Public\""),
            ReplaceFirst(response, "\"Kotoage\"", "\"View\""),
            ReplaceFirst(response, "\"capacity\":64", "\"capacity\":65"),
            ReplaceFirst(response, "\"name\":\"request\",\"ty\"", "\"name\":\"different\",\"ty\""),
            ReplaceFirst(response, "#ABA2", "#0000"),
            ReplaceFirst(response, "\"seiyaku_name\":\"Ledger\"", "\"seiyaku_name\":\"match\""),
            ReplaceFirst(response, "\"seiyaku_name\":\"Ledger\"", "\"seiyaku_name\":\"Option\""),
            ReplaceFirst(response, "\"seiyaku_name\":\"Ledger\"", "\"seiyaku_name\":\"Amount\""),
            ReplaceFirst(response, "\"seiyaku_name\":\"Ledger\"", "\"seiyaku_name\":\"amount\""),
            ReplaceFirst(response, "\"name\":\"transfer\",", "\"name\":\"Amount\","),
            ReplaceFirst(response, "\"name\":\"request\",\"type_name\"", "\"name\":\"Amount\",\"type_name\""),
            ReplaceFirst(response, "\"fields\":[\"amount\",\"memo\"]", "\"fields\":[\"Amount\",\"memo\"]"),
            ReplaceFirst(response, "\"name\":\"Balances\",\"type_name\"", "\"name\":\"Amount\",\"type_name\""),
            ReplaceFirst(response, "\"name\":\"InsufficientFunds\",\"code\"", "\"name\":\"Amount\",\"code\""),
            ReplaceFirst(response, "\"base_key\":\"state:Balances\"", "\"base_key\":\"state:Amount\""),
            ReplaceFirst(response, "\"seiyaku_name\":\"Ledger\"", "\"seiyaku_name\":\"__kotodama_link_private\""),
            ReplaceFirst(response, "\"seiyaku_name\":\"Ledger\"", "\"seiyaku_name\":\"state_map_get\""),
            ReplaceFirst(
                response,
                "StateMap<AccountId, quantity>",
                "StateMap<AccountId, Amount>"),
            ReplaceFirst(
                response,
                "StateMap<AccountId, quantity>",
                "StateMap<AccountId, amount>"),
            ReplaceFirst(
                response,
                "StateMap<AccountId, quantity>",
                "Amount: quantity"),
            ReplaceFirst(
                response,
                "StateMap<AccountId, quantity>",
                "StateMap<AccountId, Amount: quantity>"),
            ReplaceFirst(
                response,
                "StateMap<AccountId, quantity>",
                "Fixture::Transfer{value: Result<int, Amount: quantity>}"),
            ReplaceFirst(
                response,
                "StateMap<AccountId, quantity>",
                "Fixture::Transfer{amount: Amount}"),
            ReplaceFirst(
                response,
                "StateMap<AccountId, quantity>",
                "Amount{amount: quantity}"),
            ReplaceFirst(response, "\"identity\":\"Ledger::TransferError\"", "\"identity\":\"bad identity\""),
            ReplaceFirst(response, "\"features_bitmap\":0", "\"features_bitmap\":4"),
            ReplaceFirst(response, "\"dynamic_writes\":[]", "\"dynamic_writes\":[],\"unknown\":true"),
            ReplaceFirst(
                response,
                "\"repeats\":{\"Indefinitely\":null}",
                "\"repeats\":{\"kind\":\"Indefinitely\",\"value\":null}"),
            ReplaceFirst(
                response,
                $"\"code_hash\":\"{new string('b', 64)}\"",
                $"\"code_hash\":\"{new string('f', 64)}\""),
        };

        foreach (var payload in invalid)
        {
            Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ToriiContractCodeRecord>(payload));
        }
    }

    [Fact]
    public void ManifestAllowsAmountAsStructFieldIdentifier()
    {
        var manifest = JsonSerializer.Deserialize<ToriiContractManifest>(
            StateManifestJson("Fixture::Transfer{amount: quantity}"))!;

        Assert.Equal("Fixture::Transfer{amount: quantity}", manifest.States!.Single().TypeName);
        var encoded = JsonSerializer.Serialize(manifest);
        var decoded = JsonSerializer.Deserialize<ToriiContractManifest>(encoded)!;
        Assert.Equal("Fixture::Transfer{amount: quantity}", decoded.States!.Single().TypeName);
    }

    [Fact]
    public void ManifestStateTypesUseExactCanonicalV1Grammar()
    {
        string[] scalarTypes =
        [
            "int", "decimal", "quantity", "bool", "string", "bytes", "DataSpaceId",
            "AccountId", "AssetDefinitionId", "AssetId", "NftId", "DomainId", "Name", "Json",
        ];
        var canonical = scalarTypes
            .Concat(
                scalarTypes
                    .Where(typeName => typeName != "Json")
                    .Select(typeName => $"StateMap<{typeName}, quantity>"))
            .Concat(
                new[]
                {
                    "(int, decimal)",
                    "Option<Result<quantity, string>>",
                    "List<Fixture::Transfer{amount: quantity}, 64>",
                    "StateMap<AccountId, Fixture::Transfer{amount: quantity}>",
                    "StateMap<Name, Fixture::Transfer{amount: quantity, memo: Option<string>}>",
                });
        foreach (var typeName in canonical)
        {
            var manifest = JsonSerializer.Deserialize<ToriiContractManifest>(
                StateManifestJson(typeName))!;
            Assert.Equal(typeName, manifest.States!.Single().TypeName);
            Assert.NotNull(JsonSerializer.Serialize(manifest));
        }

        var noncanonical = new[]
        {
            "Amount",
            "amount",
            "Fixture::Transfer{amount: amount}",
            "Fixture::Transfer{Amount: quantity}",
            "Fixture::Transfer{amount:: quantity}",
            "Fixture::Transfer{amount:quantity}",
            "Fixture::Transfer{amount:  quantity}",
            "Transfer {amount: quantity}",
            "Fixture::Transfer{ }",
            "Fixture::Transfer{amount: quantity, amount: int}",
            "Fixture::Transfer{__kotodama_link_amount: quantity}",
            "(int)",
            "(int,decimal)",
            "Option<quantity",
            "Fixture::Transfer{amount: Option<quantity>}}",
            "Option<StateMap<AccountId, quantity>>",
            "StateMap<AccountId, StateMap<Name, quantity>>",
            "StateMap<Json, quantity>",
            "StateMap<AccountId , quantity>",
            "StateMap<AccountId,quantity>",
            "List<quantity, 0>",
            "List<quantity, 01>",
            "List<quantity, 65>",
            "Trаnsfer{amount: quantity}",
            "Fixture::Transfer{amount: quаntity}",
        };
        foreach (var typeName in noncanonical)
        {
            Assert.Throws<JsonException>(
                () => JsonSerializer.Deserialize<ToriiContractManifest>(
                    StateManifestJson(typeName)));

            var forged = new ToriiContractManifest
            {
            Permissions = Array.Empty<ToriiContractPermissionDescriptorV1>(),
            Events = [],
            EnumTypes = [],
                States =
                [
                    new ToriiContractStateDescriptor
                    {
                        Name = "Balances",
                        TypeName = typeName,
                    },
                ],
            };
            Assert.Throws<JsonException>(() => JsonSerializer.Serialize(forged));
        }
    }

    [Fact]
    public void ManifestStateTypeParserEnforcesDepthAndNodeBudgets()
    {
        var maximumDepth = string.Concat(Enumerable.Repeat("Option<", 255))
            + "int"
            + new string('>', 255);
        Assert.NotNull(
            JsonSerializer.Deserialize<ToriiContractManifest>(
                StateManifestJson(maximumDepth)));
        var maximumMapValueDepth = string.Concat(Enumerable.Repeat("Option<", 254))
            + "int"
            + new string('>', 254);
        Assert.NotNull(
            JsonSerializer.Deserialize<ToriiContractManifest>(
                StateManifestJson($"StateMap<AccountId, {maximumMapValueDepth}>")));

        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiContractManifest>(
                StateManifestJson($"Option<{maximumDepth}>")));
        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiContractManifest>(
                StateManifestJson($"StateMap<AccountId, {maximumDepth}>")));

        var maximumNodes = $"({string.Join(", ", Enumerable.Repeat("int", 255))})";
        Assert.NotNull(
            JsonSerializer.Deserialize<ToriiContractManifest>(
                StateManifestJson(maximumNodes)));
        Assert.NotNull(
            JsonSerializer.Deserialize<ToriiContractManifest>(
                StateManifestJson($"StateMap<AccountId, {maximumNodes}>")));

        var excessiveNodes = $"{maximumNodes[..^1]}, int)";
        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiContractManifest>(
                StateManifestJson(excessiveNodes)));
        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiContractManifest>(
                StateManifestJson($"StateMap<AccountId, {excessiveNodes}>")));
    }

    [Fact]
    public void ManifestDynamicAccessHintsUseExactV1Policy()
    {
        ToriiContractDynamicAccessHint ParseDynamic(
            string baseKey = "state:Balances",
            string keyType = "AccountId",
            string boundKind = "take",
            string maxKeys = "64",
            string stateName = "Balances",
            string? stateKeyType = null)
        {
            var response = ReplaceFirst(
                FullResponse(),
                "\"base_key\":\"state:Balances\"",
                $"\"base_key\":{JsonSerializer.Serialize(baseKey)}");
            response = ReplaceFirst(
                response,
                "\"key_type\":\"AccountId\"",
                $"\"key_type\":{JsonSerializer.Serialize(keyType)}");
            response = ReplaceFirst(
                response,
                "\"bound_kind\":\"take\"",
                $"\"bound_kind\":{JsonSerializer.Serialize(boundKind)}");
            response = ReplaceFirst(response, "\"max_keys\":64", $"\"max_keys\":{maxKeys}");
            var declaredStateType = $"StateMap<{stateKeyType ?? keyType}, quantity>";
            response = ReplaceFirst(
                response,
                "\"name\":\"Balances\",\"type_name\":\"StateMap<AccountId, quantity>\"",
                $"\"name\":{JsonSerializer.Serialize(stateName)},"
                    + $"\"type_name\":{JsonSerializer.Serialize(declaredStateType)}");
            return JsonSerializer.Deserialize<ToriiContractCodeRecord>(response)!
                .Manifest.AccessSetHints!.DynamicReads.Single();
        }

        string EncodeDynamic(
            ToriiContractDynamicAccessHint hint,
            string stateName = "Balances",
            string stateKeyType = "AccountId")
        {
            var record = JsonSerializer.Deserialize<ToriiContractCodeRecord>(FullResponse())!;
            var accessSetHints = record.Manifest.AccessSetHints!;
            var forged = record with
            {
                Manifest = record.Manifest with
                {
                    AccessSetHints = accessSetHints with
                    {
                        DynamicReads = [hint],
                    },
                    States =
                    [
                        new ToriiContractStateDescriptor
                        {
                            Name = stateName,
                            TypeName = $"StateMap<{stateKeyType}, quantity>",
                        },
                    ],
                },
            };
            return JsonSerializer.Serialize(forged);
        }

        string[] keyTypes =
        [
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
        ];
        foreach (var keyType in keyTypes)
        {
            Assert.Equal(
                keyType,
                ParseDynamic(keyType: keyType, stateKeyType: keyType).KeyType);
            Assert.NotNull(
                EncodeDynamic(
                    new ToriiContractDynamicAccessHint
                    {
                        BaseKey = "state:Balances",
                        KeyType = keyType,
                        BoundKind = "page",
                        MaxKeys = 64,
                    },
                    stateKeyType: keyType));
        }
        foreach (var boundKind in new[] { "page", "take" })
        {
            Assert.Equal(boundKind, ParseDynamic(boundKind: boundKind).BoundKind);
        }
        foreach (var baseKey in new[] { "state:Balances", "state:amount" })
        {
            var stateName = baseKey == "state:amount" ? "amount" : "Balances";
            Assert.Equal(
                baseKey,
                ParseDynamic(baseKey: baseKey, stateName: stateName).BaseKey);
            Assert.NotNull(
                EncodeDynamic(
                    new ToriiContractDynamicAccessHint
                    {
                        BaseKey = baseKey,
                        KeyType = "AccountId",
                        BoundKind = "take",
                        MaxKeys = 1,
                    },
                    stateName: stateName));
        }
        foreach (var maxKeys in new[] { 1U, 64U })
        {
            Assert.Equal(maxKeys, ParseDynamic(maxKeys: maxKeys.ToString()).MaxKeys);
        }

        var invalidBaseKeys = new[]
        {
            "",
            "state:",
            "state:*",
            "state:Balances.more",
            "state:Balances:Other",
            "state:Amount",
            "state:state:Balances",
            "state:match",
            "state:StateMap",
            "state:__kotodama_link_Balances",
            "state: Balances",
            "state:Balances ",
            "state:Бalances",
            "states:Balances",
            "Balances",
            "state:amount.more",
        };
        foreach (var baseKey in invalidBaseKeys)
        {
            Assert.Throws<JsonException>(() => ParseDynamic(baseKey: baseKey));
            Assert.Throws<JsonException>(
                () => EncodeDynamic(
                    new ToriiContractDynamicAccessHint
                    {
                        BaseKey = baseKey,
                        KeyType = "AccountId",
                        BoundKind = "take",
                        MaxKeys = 1,
                    }));
        }

        var invalidKeyTypes = new[]
        {
            "",
            "Json",
            "Int",
            "Amount",
            "amount",
            "AccountID",
            "Transfer",
            "StateMap",
            "StateMap<AccountId, quantity>",
            " AccountId",
            "AccountId ",
            "АccountId",
        };
        foreach (var keyType in invalidKeyTypes)
        {
            Assert.Throws<JsonException>(() => ParseDynamic(keyType: keyType));
            Assert.Throws<JsonException>(
                () => EncodeDynamic(
                    new ToriiContractDynamicAccessHint
                    {
                        BaseKey = "state:Balances",
                        KeyType = keyType,
                        BoundKind = "take",
                        MaxKeys = 1,
                    }));
        }

        foreach (var boundKind in new[] { "", "range", "Page", "Take", "all", "prefix", "page ", " take" })
        {
            Assert.Throws<JsonException>(() => ParseDynamic(boundKind: boundKind));
            Assert.Throws<JsonException>(
                () => EncodeDynamic(
                    new ToriiContractDynamicAccessHint
                    {
                        BaseKey = "state:Balances",
                        KeyType = "AccountId",
                        BoundKind = boundKind,
                        MaxKeys = 1,
                    }));
        }
        foreach (var maxKeys in new[] { "0", "65", "4294967295", "-1", "1.0", "\"1\"" })
        {
            Assert.Throws<JsonException>(() => ParseDynamic(maxKeys: maxKeys));
        }
        var malformed = new[]
        {
            ReplaceFirst(
                FullResponse(),
                "\"max_keys\":64",
                "\"max_keys\":64,\"unknown\":true"),
            ReplaceFirst(
                FullResponse(),
                "\"base_key\":\"state:Balances\"",
                "\"base_key\":null"),
            ReplaceFirst(
                FullResponse(),
                "\"key_type\":\"AccountId\"",
                "\"key_type\":false"),
            ReplaceFirst(
                FullResponse(),
                "\"bound_kind\":\"take\"",
                "\"bound_kind\":1"),
            ReplaceFirst(FullResponse(), "\"max_keys\":64", "\"max_keys\":null"),
        };
        foreach (var payload in malformed)
        {
            Assert.Throws<JsonException>(
                () => JsonSerializer.Deserialize<ToriiContractCodeRecord>(payload));
        }
        foreach (var maxKeys in new[] { 0U, 65U, uint.MaxValue })
        {
            Assert.Throws<JsonException>(
                () => EncodeDynamic(
                    new ToriiContractDynamicAccessHint
                    {
                        BaseKey = "state:Balances",
                        KeyType = "AccountId",
                        BoundKind = "take",
                        MaxKeys = maxKeys,
                    }));
        }
    }

    [Fact]
    public void ManifestDynamicAccessHintsResolveExactDeclaredStateMaps()
    {
        var canonical = new ToriiContractDynamicAccessHint
        {
            BaseKey = "state:Balances",
            KeyType = "AccountId",
            BoundKind = "take",
            MaxKeys = 1,
        };
        var unknown = canonical with { BaseKey = "state:Missing" };
        var mismatch = canonical with { KeyType = "Name" };
        var malformed = new[]
        {
            (
                Reads: new[] { canonical, canonical },
                Writes: Array.Empty<ToriiContractDynamicAccessHint>(),
                StateName: "Balances",
                StateType: "StateMap<AccountId, quantity>"
            ),
            (
                Reads: Array.Empty<ToriiContractDynamicAccessHint>(),
                Writes: new[] { canonical, canonical },
                StateName: "Balances",
                StateType: "StateMap<AccountId, quantity>"
            ),
            (
                Reads: new[] { unknown },
                Writes: Array.Empty<ToriiContractDynamicAccessHint>(),
                StateName: "Balances",
                StateType: "StateMap<AccountId, quantity>"
            ),
            (
                Reads: new[] { canonical },
                Writes: Array.Empty<ToriiContractDynamicAccessHint>(),
                StateName: "Balances",
                StateType: "quantity"
            ),
            (
                Reads: new[] { mismatch },
                Writes: Array.Empty<ToriiContractDynamicAccessHint>(),
                StateName: "Balances",
                StateType: "StateMap<AccountId, quantity>"
            ),
        };

        foreach (var value in malformed)
        {
            var payload = DynamicManifestJson(
                value.Reads,
                value.Writes,
                value.StateName,
                value.StateType);
            Assert.Throws<JsonException>(
                () => JsonSerializer.Deserialize<ToriiContractManifest>(payload));
            Assert.Throws<JsonException>(
                () => JsonSerializer.Serialize(
                    DynamicManifest(
                        value.Reads,
                        value.Writes,
                        value.StateName,
                        value.StateType)));
        }

        var amount = canonical with
        {
            BaseKey = "state:amount",
            BoundKind = "page",
            MaxKeys = 64,
        };
        var accepted = DynamicManifest(
            [amount],
            [amount],
            "amount",
            "StateMap<AccountId, quantity>");
        var decoded = JsonSerializer.Deserialize<ToriiContractManifest>(
            DynamicManifestJson(
                [amount],
                [amount],
                "amount",
                "StateMap<AccountId, quantity>"))!;
        Assert.Equal(
            "state:amount",
            decoded.AccessSetHints!.DynamicReads.Single().BaseKey);
        Assert.NotNull(JsonSerializer.Serialize(accepted));
    }

    [Theory]
    [InlineData("")]
    [InlineData("bad identity")]
    [InlineData("__kotodama_link_hidden::Failure")]
    public void ManifestRejectsMalformedErrorIdentities(string identity)
    {
        var response = ReplaceFirst(FullResponse(), "\"identity\":\"Ledger::TransferError\"",
            $"\"identity\":\"{identity}\"");
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ToriiContractCodeRecord>(response));
        var record = JsonSerializer.Deserialize<ToriiContractCodeRecord>(FullResponse())!;
        var forged = record.Manifest with
        {
            ErrorTypes = [record.Manifest.ErrorTypes!.Single() with { Identity = identity }],
        };
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(forged));
    }

    private static ToriiContractManifest DynamicManifest(
        IReadOnlyList<ToriiContractDynamicAccessHint> reads,
        IReadOnlyList<ToriiContractDynamicAccessHint> writes,
        string stateName,
        string stateType)
    {
        return new ToriiContractManifest
        {
            Permissions = Array.Empty<ToriiContractPermissionDescriptorV1>(),
            Events = [],
            EnumTypes = [],
            AccessSetHints = new ToriiContractAccessSetHints
            {
                DynamicReads = reads,
                DynamicWrites = writes,
            },
            States =
            [
                new ToriiContractStateDescriptor
                {
                    Name = stateName,
                    TypeName = stateType,
                },
            ],
        };
    }

    [Fact]
    public void SourceViewEntrypointsUseTheSameClosedAuthorization()
    {
        var root = JsonNode.Parse("""
            {"name":"inspect","kind":"view","params":[],"return_type":"int",
             "authorization":{"kind":"Permission","value":"Reader"},
             "read_keys":[],"write_keys":[],"access_hints_complete":true,
             "access_hints_skipped":[],"triggers":[]}
            """)!.AsObject();
        var entrypoint = root.Deserialize<ToriiContractViewEntrypoint>()!;
        Assert.Equal("Reader", Assert.IsType<ToriiEntrypointAuthorizationV1.Permission>(entrypoint.Authorization).Name);
        Assert.NotNull(JsonSerializer.Deserialize<ToriiContractViewEntrypoint>(JsonSerializer.Serialize(entrypoint)));
        var unknown = root.DeepClone().AsObject();
        unknown["permission"] = "Reader";
        Assert.Throws<JsonException>(() => unknown.Deserialize<ToriiContractViewEntrypoint>());
        root.Remove("authorization");
        Assert.Throws<JsonException>(() => root.Deserialize<ToriiContractViewEntrypoint>());
        Assert.Throws<ArgumentException>(() => entrypoint with
        {
            Authorization = new ToriiEntrypointAuthorizationV1.Permission("invalid role"),
        });
    }

    [Fact]
    public void AuthorizationUsesRequiredCanonicalDeclarations()
    {
        JsonObject Manifest() => JsonNode.Parse(FullResponse())!["manifest"]!.AsObject();
        var root = Manifest();
        var parsed = root.Deserialize<ToriiContractManifest>()!;
        Assert.IsType<ToriiEntrypointAuthorizationV1.Permission>(parsed.Entrypoints![0].Authorization);
        Assert.IsType<ToriiContractPermissionScopeV1.Instance>(parsed.Permissions[0].Scope);
        root["permissions"]![0]!["scope"] = JsonNode.Parse("""{"kind":"Chain","value":{"permission_name":"SharedOperators"}}""");
        Assert.Equal("SharedOperators", Assert.IsType<ToriiContractPermissionScopeV1.Chain>(root.Deserialize<ToriiContractManifest>()!.Permissions[0].Scope).PermissionName);
        foreach (var mutate in new Action<JsonObject>[]
        {
            value => value.Remove("permissions"),
            value => value["permissions"] = new JsonArray(),
            value => value["permissions"]!.AsArray().Add(value["permissions"]![0]!.DeepClone()),
            value => value["entrypoints"]![0]!["authorization"] = "TransferAsset",
            value => value["entrypoints"]![0]!["authorization"] = JsonNode.Parse("""{"kind":"RuntimeLifecycle","value":null}"""),
            value => value["entrypoints"]![0]!["permission"] = "TransferAsset",
            value => value["permissions"]![0]!["scope"]!["value"] = "unexpected",
        })
        {
            var invalid = Manifest();
            mutate(invalid);
            Assert.Throws<JsonException>(() => invalid.Deserialize<ToriiContractManifest>());
        }
    }

    private static string DynamicManifestJson(
        IReadOnlyList<ToriiContractDynamicAccessHint> reads,
        IReadOnlyList<ToriiContractDynamicAccessHint> writes,
        string stateName,
        string stateType)
    {
        static string HintJson(ToriiContractDynamicAccessHint hint)
        {
            return $"{{\"base_key\":{JsonSerializer.Serialize(hint.BaseKey)},"
                + $"\"key_type\":{JsonSerializer.Serialize(hint.KeyType)},"
                + $"\"bound_kind\":{JsonSerializer.Serialize(hint.BoundKind)},"
                + $"\"max_keys\":{hint.MaxKeys}}}";
        }

        return "{\"events\":[],\"enum_types\":[],\"permissions\":[],\"access_set_hints\":{\"read_keys\":[],\"write_keys\":[],"
            + $"\"dynamic_reads\":[{string.Join(",", reads.Select(HintJson))}],"
            + $"\"dynamic_writes\":[{string.Join(",", writes.Select(HintJson))}]"
            + "},\"states\":[{\"name\":"
            + JsonSerializer.Serialize(stateName)
            + ",\"type_name\":"
            + JsonSerializer.Serialize(stateType)
            + "}]}";
    }

    private static string StateManifestJson(string typeName)
    {
        return "{\"events\":[],\"enum_types\":[],\"permissions\":[],\"states\":[{\"name\":\"Balances\",\"type_name\":"
            + JsonSerializer.Serialize(typeName)
            + "}]}";
    }

    private static string ReplaceFirst(string source, string target, string replacement)
    {
        var index = source.IndexOf(target, StringComparison.Ordinal);
        Assert.True(index >= 0, $"missing test replacement target {target}");
        return source[..index] + replacement + source[(index + target.Length)..];
    }

    private static (ToriiContractManifest Manifest, ToriiEntrypointValueTypeV1 Schema)
        ParseReturnSchema(IEnumerable<string> nodes, string typeName)
    {
        var manifest = JsonSerializer.Deserialize<ToriiContractManifest>(
            ManifestWithReturnSchema(nodes, typeName))!;
        return (manifest, manifest.Entrypoints!.Single().ReturnSchema!);
    }

    [Fact]
    public void AssetDefinitionPrecisionRequiresOptionalInteger()
    {
        var (name, fields, children) = QueryViews().Single(view => view.Name == "AssetDefinitionView");
        var valid = new[] { StructNode(name, fields) }.Concat(children).ToArray();
        var manifest = JsonSerializer.Deserialize<ToriiContractManifest>(ManifestWithReturnSchema(valid, name))!;
        Assert.Equal(7, manifest.Entrypoints!.Single().ReturnSchema!.WordCount);
        Assert.Equal(10, manifest.Entrypoints!.Single().ReturnSchema!.Nodes.Count);
        var retired = new[] { StructNode(name, fields.Where(field => field != "numeric_scale")) }
            .Concat(children.Take(6)).Append(children[8]).ToArray();
        var required = valid.Where((_, index) => index != 7).ToArray();
        var decimalPrecision = valid.ToArray();
        decimalPrecision[8] = Leaf("Decimal");
        foreach (var nodes in new[] { retired, required, decimalPrecision })
        {
            AssertForgedSchemaRejected(nodes, name);
            var page = new[] { StructNode("QueryPage", new[] { "items", "next_offset" }), ListNode(64) }
                .Concat(nodes).Append(NullNode("Option")).Append(Leaf("Int"));
            AssertForgedSchemaRejected(page, "QueryPage<AssetDefinitionView>");
        }
    }

    private static void AssertForgedSchemaRejected(
        IEnumerable<string> nodes,
        string advertisedType)
    {
        AssertSchemaRejected(nodes, advertisedType, "forged");
    }

    private static void AssertSchemaRejected(
        IEnumerable<string> nodes,
        string advertisedType,
        string expectedMessage)
    {
        var exception = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiContractManifest>(
                ManifestWithReturnSchema(nodes, advertisedType)));
        Assert.Contains(expectedMessage, exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static string ManifestWithReturnSchema(
        IEnumerable<string> nodes,
        string typeName)
    {
        return $$$"""
        {
          "events":[],"enum_types":[],"permissions":[],
          "entrypoints":[{
            "name":"inspect",
            "kind":{"kind":"View","value":null},
            "params":[],
            "argument_schema":null,
            "return_type":{{{JsonSerializer.Serialize(typeName)}}},
            "return_schema":{"nodes":[{{{string.Join(",", nodes)}}}]},
            "authorization":{"kind":"Anyone","value":null},
            "read_keys":[],
            "write_keys":[],
            "access_hints_complete":true,
            "access_hints_skipped":[],
            "triggers":[]
          }]
        }
        """;
    }

    private static IReadOnlyList<(string Name, string[] Fields, string[] Children)> QueryViews()
    {
        return new (string, string[], string[])[]
        {
            (
                "AccountView",
                new[] { "id", "metadata" },
                new[] { Leaf("AccountId"), Leaf("Json") }),
            (
                "AssetView",
                new[] { "id", "amount" },
                new[] { Leaf("AssetId"), Leaf("Quantity") }),
            (
                "AssetDefinitionView",
                new[] { "id", "name", "description", "owned_by", "total_quantity", "numeric_scale", "metadata" },
                new[]
                {
                    Leaf("AssetDefinitionId"),
                    Leaf("String"),
                    NullNode("Option"),
                    Leaf("String"),
                    Leaf("AccountId"),
                    Leaf("Quantity"),
                    NullNode("Option"),
                    Leaf("Int"),
                    Leaf("Json"),
                }),
            (
                "DomainView",
                new[] { "id", "owned_by", "metadata" },
                new[] { Leaf("DomainId"), Leaf("AccountId"), Leaf("Json") }),
            (
                "NftView",
                new[] { "id", "owned_by", "content" },
                new[] { Leaf("NftId"), Leaf("AccountId"), Leaf("Json") }),
        };
    }

    private static string StructNode(string name, IEnumerable<string> fields)
    {
        if (name is "AccountView" or "AssetView" or "AssetDefinitionView" or "DomainView" or "NftView" or "QueryPage" or "StatePage") name = "kotodama::" + name;
        return $$$"""
        {"kind":"Struct","value":{"name":{{{JsonSerializer.Serialize(name)}}},"fields":[{{{string.Join(",", fields.Select(field => JsonSerializer.Serialize(field)))}}}]}}
        """;
    }

    private static string ListNode(byte capacity)
    {
        return $$$"""{"kind":"List","value":{"capacity":{{{capacity}}}}}""";
    }

    private static string NullNode(string kind)
    {
        return $$$"""{"kind":{{{JsonSerializer.Serialize(kind)}}},"value":null}""";
    }

    private static string Leaf(string kind)
    {
        return $$$"""{"kind":"Leaf","value":{"kind":{{{JsonSerializer.Serialize(kind)}}},"value":null}}""";
    }

    private static string FullResponse()
    {
        return $$$"""
        {
          "network_id":"hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0",
          "artifact_id":{"dataspace_id":0,"code_hash":"hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2"},
          "manifest":{
            "seiyaku_name":"Ledger",
            "code_hash":"hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2",
            "abi_hash":"hash:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD#F071",
            "compiler_fingerprint":"kotodama_lang",
            "features_bitmap":0,
            "access_set_hints":{
              "read_keys":["state:Balances"],
              "write_keys":["state:Balances"],
              "dynamic_reads":[{
                "base_key":"state:Balances",
                "key_type":"AccountId",
                "bound_kind":"take",
                "max_keys":64
              }],
              "dynamic_writes":[]
            },
            "events":[],"enum_types":[],"permissions":[{"name":"TransferAsset","scope":{"kind":"Instance","value":null}}],
          "entrypoints":[{
              "name":"transfer",
              "kind":{"kind":"Kotoage","value":null},
              "params":[
                {"name":"request","type_name":"struct Fixture::Transfer"},
                {"name":"tags","type_name":"List<Name, 64>"}
              ],
              "argument_schema":{"fields":[
                {"name":"request","ty":{"nodes":[
                  {"kind":"Struct","value":{"name":"Fixture::Transfer","fields":["amount","memo"]}},
                  {"kind":"Leaf","value":{"kind":"Quantity","value":null}},
                  {"kind":"Option","value":null},
                  {"kind":"Leaf","value":{"kind":"String","value":null}}
                ]}},
                {"name":"tags","ty":{"nodes":[
                  {"kind":"List","value":{"capacity":64}},
                  {"kind":"Leaf","value":{"kind":"Name","value":null}}
                ]}}
              ]},
              "return_type":"Result<(bool, int), string>",
              "return_schema":{"nodes":[
                {"kind":"Result","value":null},
                {"kind":"Tuple","value":2},
                {"kind":"Leaf","value":{"kind":"Bool","value":null}},
                {"kind":"Leaf","value":{"kind":"Int","value":null}},
                {"kind":"Leaf","value":{"kind":"String","value":null}}
              ]},
              "authorization":{"kind":"Permission","value":"TransferAsset"},
              "read_keys":["state:Balances"],
              "write_keys":["state:Balances"],
              "access_hints_complete":true,
              "access_hints_skipped":[],
              "triggers":[{
                "id":"settle",
                "repeats":{"Indefinitely":null},
                "filter":"{{{FilterBase64}}}",
                "authority":null,
                "metadata":{"purpose":"daily-settlement","round":7},
                "callback":{"namespace":null,"entrypoint":"transfer"}
              }]
            }],
            "states":[{"name":"Balances","type_name":"StateMap<AccountId, quantity>"}],
            "error_types":[{"identity":"Ledger::TransferError","variants":[{"name":"InsufficientFunds","code":1001}]}],
            "kotoba":[{
              "msg_id":"transfer.denied",
              "translations":[
                {"lang":"en","text":"Transfer denied"},
                {"lang":"ja","text":"送金は拒否されました"}
              ]
            }],
            "provenance":{"signer":"ed25519:fixture","signature":"fixture-signature"}
          },
          "code_hash":"{{{new string('b', 64)}}}",
          "abi_hash":"{{{new string('d', 64)}}}"
        }
        """;
    }
}
