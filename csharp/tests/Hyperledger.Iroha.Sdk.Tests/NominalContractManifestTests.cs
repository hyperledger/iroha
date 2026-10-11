using System.Text.Json;
using System.Text.Json.Nodes;
using Hyperledger.Iroha.Torii;

namespace Hyperledger.Iroha.Sdk.Tests;

public sealed class NominalContractManifestTests
{
    [Fact]
    public void DurableBuiltinProductsRequireExactShapes()
    {
        var vectors = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "kotodama", "durable_builtin_shapes_v1.json")))!;
        static ToriiContractManifest Decode(string type) => new JsonObject
        {
            ["permissions"] = new JsonArray(), ["events"] = new JsonArray(), ["enum_types"] = new JsonArray(),
            ["states"] = new JsonArray(new JsonObject { ["name"] = "stored", ["type_name"] = type }),
        }.Deserialize<ToriiContractManifest>()!;
        foreach (var item in vectors["valid"]!.AsArray()) Assert.Equal(item!.GetValue<string>(), Decode(item.GetValue<string>()).States!.Single().TypeName);
        foreach (var item in vectors["invalid"]!.AsArray()) Assert.Throws<JsonException>(() => Decode(item!.GetValue<string>()));
    }

    [Fact]
    public void TupleCursorSchemasBindCompleteKeysAndShareOuterBounds()
    {
        static JsonObject Node(string kind, JsonNode? value = null) => new() { ["kind"] = kind, ["value"] = value };
        static JsonObject Leaf(string kind) => Node("Leaf", Node(kind));
        static JsonObject Cursor(JsonArray keys) => Node("StateCursor", new JsonObject { ["nodes"] = keys.DeepClone() });
        static ToriiEntrypointValueTypeV1 Parse(JsonArray nodes, string type)
        {
            var manifest = new JsonObject
            {
                ["permissions"] = new JsonArray(), ["events"] = new JsonArray(), ["enum_types"] = new JsonArray(),
                ["entrypoints"] = new JsonArray(new JsonObject
                {
                    ["name"] = "page", ["kind"] = Node("View"), ["authorization"] = Node("Anyone"),
                    ["return_type"] = type, ["return_schema"] = new JsonObject { ["nodes"] = nodes },
                }),
            }.Deserialize<ToriiContractManifest>()!;
            // Exercise the same strict schema checks when building JSON from SDK DTOs.
            var roundTrip = JsonSerializer.Deserialize<ToriiContractManifest>(JsonSerializer.Serialize(manifest))!;
            return roundTrip.Entrypoints!.Single().ReturnSchema!;
        }
        var keys = new JsonArray(Node("Tuple", 2), Leaf("Int"), Node("Tuple", 2), Leaf("Name"), Leaf("Bool"));
        const string keyName = "(int, (Name, bool))";
        var mapped = new JsonObject
        {
            ["permissions"] = new JsonArray(), ["events"] = new JsonArray(), ["enum_types"] = new JsonArray(),
            ["states"] = new JsonArray(new JsonObject { ["name"] = "stored", ["type_name"] = $"StateMap<{keyName}, bool>" }),
            ["access_set_hints"] = new JsonObject
            {
                ["read_keys"] = new JsonArray(), ["write_keys"] = new JsonArray(), ["dynamic_writes"] = new JsonArray(),
                ["dynamic_reads"] = new JsonArray(new JsonObject { ["base_key"] = "state:stored", ["key_type"] = keyName, ["bound_kind"] = "page", ["max_keys"] = 8 }),
            },
        };
        var validMap = mapped.Deserialize<ToriiContractManifest>()!;
        Assert.Equal(keyName, validMap.AccessSetHints!.DynamicReads.Single().KeyType);
        Assert.NotNull(JsonSerializer.Deserialize<ToriiContractManifest>(JsonSerializer.Serialize(validMap)));
        mapped["access_set_hints"]!["dynamic_reads"]![0]!["key_type"] = "(int, (Name, int))";
        Assert.Throws<JsonException>(() => mapped.Deserialize<ToriiContractManifest>());
        var decoded = Parse(new JsonArray(Cursor(keys)), $"StateCursor<{keyName}>");
        Assert.Equal(keyName, decoded.Nodes.Single().CursorKeySchema!.CanonicalTypeName);
        Assert.Equal(1, decoded.WordCount);
        var page = new JsonArray(Node("Struct", new JsonObject { ["name"] = "kotodama::StatePage", ["fields"] = new JsonArray("items", "next") }),
            Node("List", new JsonObject { ["capacity"] = 8 }), Node("Tuple", 2));
        foreach (var key in keys) page.Add(key!.DeepClone());
        page.Add(Leaf("Bool")); page.Add(Node("Option")); page.Add(Cursor(keys));
        Assert.Equal(2, Parse((JsonArray)page.DeepClone(), $"StatePage<{keyName}, bool, 8>").WordCount);
        page[^1]!["value"]!["nodes"]![4] = Leaf("Int");
        Assert.Throws<JsonException>(() => Parse((JsonArray)page.DeepClone(), $"StatePage<{keyName}, bool, 8>"));
        foreach (var invalid in new[] { new JsonArray(Leaf("Json")), new JsonArray(Cursor(keys)), new JsonArray(Node("Tuple", 1), Leaf("Int")) })
            Assert.Throws<JsonException>(() => Parse(new JsonArray(Cursor(invalid)), "StateCursor<int>"));
        Assert.Throws<JsonException>(() => Parse(new JsonArray(Node("StateCursor", Node("Int"))), "StateCursor<int>"));
        var smallKey = new JsonArray(Node("Tuple", 2), Leaf("Int"), Leaf("Bool"));
        foreach (var count in new[] { 63, 64 })
        {
            var nodes = new JsonArray(Node("Tuple", count));
            for (var i = 0; i < count; i++) nodes.Add(Cursor(smallKey));
            var name = "(" + string.Join(", ", Enumerable.Repeat("StateCursor<(int, bool)>", count)) + ")";
            if (count == 63) Assert.Equal(count, Parse(nodes, name).WordCount);
            else Assert.Throws<JsonException>(() => Parse(nodes, name));
        }
        foreach (var count in new[] { 254, 255 })
        {
            var nodes = new JsonArray();
            for (var i = 0; i < count; i++) nodes.Add(Node("Option"));
            nodes.Add(Cursor(new JsonArray(Leaf("Int"))));
            var name = string.Concat(Enumerable.Repeat("Option<", count)) + "StateCursor<int>" + new string('>', count);
            if (count == 254) Assert.Equal(1, Parse(nodes, name).WordCount);
            else Assert.Throws<JsonException>(() => Parse(nodes, name));
        }
    }

    [Fact]
    public void StaticErrorMessagesBindDeclaredVariants()
    {
        var value = ManifestNode();
        var identity = value["error_types"]![0]!["identity"]!.GetValue<string>();
        var entry = new JsonObject { ["error_type"] = identity, ["code"] = 1, ["message"] = "残高が不足しています" };
        value["error_messages"] = new JsonArray(entry);
        var manifest = value.Deserialize<ToriiContractManifest>()!;
        Assert.Equal("残高が不足しています", manifest.ErrorMessages!.Single().Message);
        Assert.NotNull(JsonSerializer.Deserialize<ToriiContractManifest>(JsonSerializer.Serialize(manifest)));
        foreach (var text in new[] { " \n explanation \t", "\u001c", "😀" })
        {
            entry["message"] = text;
            Assert.Equal(text, value.Deserialize<ToriiContractManifest>()!.ErrorMessages!.Single().Message);
        }
        entry["message"] = "\u0085\u00a0";
        Assert.Throws<JsonException>(() => value.Deserialize<ToriiContractManifest>());
        var malformed = manifest with { ErrorMessages = new[] { manifest.ErrorMessages!.Single() with { Message = "\ud800" } } };
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(malformed));
        entry["message"] = "Valid message";
        entry["code"] = 999;
        Assert.Throws<JsonException>(() => value.Deserialize<ToriiContractManifest>());
        entry["code"] = 1;
        entry["message"] = new string('é', 2049);
        Assert.Throws<JsonException>(() => value.Deserialize<ToriiContractManifest>());
    }

    [Fact]
    public void DurableEmptyProductsPreserveNominalNamesAndExactGrammar()
    {
        static ToriiContractManifest Decode(string typeName)
        {
            var payload = new JsonObject
            {
                ["permissions"] = new JsonArray(),
                ["events"] = new JsonArray(),
                ["enum_types"] = new JsonArray(),
                ["states"] = new JsonArray(new JsonObject { ["name"] = "Stored", ["type_name"] = typeName }),
            };
            return payload.Deserialize<ToriiContractManifest>()!;
        }
        foreach (var typeName in new[]
        {
            "Fixture::Empty{}", "Fixture::Other{}", "Fixture::Transfer{}", "List<Fixture::Empty{}, 2>", "List<List<Fixture::Empty{}, 2>, 2>",
            "Fixture::Envelope{empty: Fixture::Empty{}}", "StateMap<int, Fixture::Empty{}>",
            "std/math@1.0.0::Math::Empty{}",
        })
        {
            var manifest = Decode(typeName);
            Assert.Equal(typeName, manifest.States!.Single().TypeName);
            var roundtrip = JsonSerializer.Deserialize<ToriiContractManifest>(JsonSerializer.Serialize(manifest))!;
            Assert.Equal(typeName, roundtrip.States!.Single().TypeName);
        }
        foreach (var typeName in new[]
        {
            "{}", "Fixture::Empty{", "Fixture::Empty{ }", "Fixture::Empty{,}", "Fixture::Empty{: int}",
            "Fixture::Empty{field: int, }", "Fixture::Empty{}trailing", "List<Fixture::Empty{},2>",
            "List<Fixture::Empty{}, 0>", "Fixture::Envelope{empty: Fixture::Empty{}, empty: Fixture::Empty{}}",
            "StatePage{}", "Option{}", "int{}",
        }) Assert.Throws<JsonException>(() => Decode(typeName));
    }

    [Fact]
    public void ExportedStructIdentitySurvivesPublicAndDurableSchemas()
    {
        const string identity = "std/math@1.0.0::Math::Receipt";
        var directory = Path.Combine(AppContext.BaseDirectory, "Fixtures", "kotodama");
        var payload = File.ReadAllText(Path.Combine(directory, "exported_structs_v1.json"));
        var vectors = JsonNode.Parse(File.ReadAllText(Path.Combine(directory, "exported_struct_names_v1.json")))!;
        foreach (var item in vectors["valid"]!.AsArray())
        {
            var name = item!.GetValue<string>();
            var manifest = JsonNode.Parse(payload.Replace(identity, name, StringComparison.Ordinal))!["manifest"]!
                .Deserialize<ToriiContractManifest>()!;
            Assert.Equal("struct " + name, manifest.Entrypoints![0].ReturnSchema!.CanonicalTypeName);
            Assert.Equal("struct " + name, manifest.Entrypoints[0].ArgumentSchema!.Fields[0].ValueType.CanonicalTypeName);
            Assert.Contains(name + "{", manifest.States![0].TypeName, StringComparison.Ordinal);
            Assert.NotNull(JsonSerializer.Deserialize<ToriiContractManifest>(JsonSerializer.Serialize(manifest)));
        }
        foreach (var item in vectors["invalid"]!.AsArray())
        {
            var name = item!.GetValue<string>();
            var root = JsonNode.Parse(payload.Replace(identity, name, StringComparison.Ordinal))!["manifest"]!.AsObject();
            var publicOnly = root.DeepClone().AsObject();
            publicOnly.Remove("states");
            Assert.Throws<JsonException>(() => publicOnly.Deserialize<ToriiContractManifest>());
            var stateOnly = root.DeepClone().AsObject();
            stateOnly.Remove("entrypoints");
            Assert.Throws<JsonException>(() => stateOnly.Deserialize<ToriiContractManifest>());
        }
    }

    private static JsonObject ManifestNode()
    {
        var fixture = File.ReadAllText(Path.Combine(
            AppContext.BaseDirectory, "Fixtures", "kotodama", "nominal_errors_v1.json"));
        return JsonNode.Parse(fixture)!["manifest"]!.AsObject();
    }

    [Fact]
    public void SharedFixturePreservesNominalErrorsUnitAndStatePages()
    {
        var manifest = ManifestNode().Deserialize<ToriiContractManifest>()!;
        Assert.Equal(2, manifest.ErrorTypes!.Count);
        Assert.Equal("example/vault@1.0.0::金庫::拒否", manifest.ErrorTypes[0].Identity);
        Assert.Equal("不足", manifest.ErrorTypes[0].Variants[0].Name);
        Assert.Equal(1U, manifest.ErrorTypes[0].Variants[0].Code);
        Assert.Equal(1U, manifest.ErrorTypes[1].Variants[0].Code);
        Assert.Equal("Result<(), example/vault@1.0.0::金庫::拒否>",
            manifest.Entrypoints![0].ReturnSchema!.CanonicalTypeName);
        Assert.Equal("Option<StateCursor<int>>", manifest.Entrypoints[1].ReturnSchema!.CanonicalTypeName);
        Assert.Equal("StatePage<int, bool, 8>", manifest.Entrypoints[2].ReturnSchema!.CanonicalTypeName);
        Assert.Equal(2, manifest.Entrypoints[2].ReturnSchema!.WordCount);
        var encoded = JsonSerializer.Serialize(manifest);
        var roundTrip = JsonSerializer.Deserialize<ToriiContractManifest>(encoded)!;
        Assert.Equal(manifest.ErrorTypes[0].Variants, roundTrip.ErrorTypes![0].Variants);
        Assert.DoesNotContain("error_codes", encoded, StringComparison.Ordinal);
    }

    [Fact]
    public void ErrorSchemasMustExactlyMatchTheirNominalCatalog()
    {
        foreach (var change in new Action<JsonObject>[]
        {
            root => root.Remove("error_types"),
            root => root["error_types"]![0]!["variants"]![0]!["name"] = "Different",
            root => root["error_types"]![0]!["identity"] = "other/vault@1.0.0::金庫::拒否",
            root => root["error_types"]!.AsArray().Add(root["error_types"]![0]!.DeepClone()),
            root => root["error_types"]![0]!["variants"]![0]!["code"] = 0,
            root => root["error_types"]![0]!["variants"]![1]!["code"] = 1,
            root => root["error_types"]![0]!["variants"]![1]!["name"] = "不足",
            root => root["error_types"]![0]!["variants"]![1]!["code"] = 4294967296UL,
        })
        {
            var root = ManifestNode();
            change(root);
            Assert.Throws<JsonException>(() => root.Deserialize<ToriiContractManifest>());
        }
        var manifest = ManifestNode().Deserialize<ToriiContractManifest>()!;
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(manifest with { ErrorTypes = [] }));
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(manifest with
        {
            Entrypoints = [],
            ErrorTypes = [],
        }));
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(manifest with
        {
            ErrorTypes = [manifest.ErrorTypes![0] with { Identity = new string('金', 342) }],
        }));
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(manifest with
        {
            ErrorTypes = [manifest.ErrorTypes![0] with
            {
                Variants = [new ToriiContractErrorVariantDescriptor { Name = "Other", Code = 1 }],
            }],
        }));
    }

    [Fact]
    public void ReservedCursorAndPageSchemasRejectForgedShapes()
    {
        foreach (var change in new Action<JsonObject>[]
        {
            root => root["entrypoints"]![0]!["return_schema"]!["nodes"]![1]!["value"] = 0,
            root => root["entrypoints"]![1]!["return_schema"]!["nodes"]![1]!["value"]!["nodes"]![0]!["value"]!["kind"] = "Json",
            root => root["entrypoints"]![2]!["return_schema"]!["nodes"]![6]!["value"]!["nodes"]![0]!["value"]!["kind"] = "Bool",
            root => root["entrypoints"]![2]!["return_schema"]!["nodes"]![0]!["value"]!["fields"]![1] = "next_offset",
            root => root["entrypoints"]![2]!["return_schema"]!["nodes"]![1]!["value"]!["capacity"] = 0,
            root => root["states"]![1]!["type_name"] = "Option<StateCursor<Json>>",
            root => root["states"]![2]!["type_name"] = "kotodama::StatePage{items: List<(int, bool), 8>, next: Option<StateCursor<bool>>}",
        })
        {
            var root = ManifestNode();
            change(root);
            Assert.Throws<JsonException>(() => root.Deserialize<ToriiContractManifest>());
        }
    }

    [Fact]
    public void UnitHasOneZeroScalarWordAndItsSchemaPayloadIsNull()
    {
        var manifest = ManifestNode();
        manifest["entrypoints"] = JsonNode.Parse("""
            [{"name":"done","kind":{"kind":"View","value":null},"authorization":{"kind":"Anyone","value":null},"params":[],
              "return_type":"()","return_schema":{"nodes":[{"kind":"Unit","value":null}]}}]
            """);
        var decoded = manifest.Deserialize<ToriiContractManifest>()!;
        Assert.Equal(1, decoded.Entrypoints!.Single().ReturnSchema!.WordCount);
        Assert.Equal("()", decoded.Entrypoints!.Single().ReturnType);
        Assert.NotNull(JsonSerializer.Deserialize<ToriiContractManifest>(JsonSerializer.Serialize(decoded)));
        manifest["error_codes"] = new JsonArray();
        Assert.Throws<JsonException>(() => manifest.Deserialize<ToriiContractManifest>());
    }

    [Fact]
    public void EveryPublicEntrypointRequiresAnExplicitReturnSchema()
    {
        foreach (var change in new Action<JsonObject>[]
        {
            entrypoint => { entrypoint.Remove("return_type"); entrypoint.Remove("return_schema"); },
            entrypoint => { entrypoint["return_type"] = null; entrypoint["return_schema"] = null; },
            entrypoint => entrypoint.Remove("return_type"),
            entrypoint => entrypoint.Remove("return_schema"),
        })
        {
            var root = ManifestNode();
            change(root["entrypoints"]![0]!.AsObject());
            Assert.Throws<JsonException>(() => root.Deserialize<ToriiContractManifest>());
        }
        var manifest = ManifestNode().Deserialize<ToriiContractManifest>()!;
        var descriptor = manifest.Entrypoints![0];
        foreach (var invalid in new[]
        {
            descriptor with { ReturnType = null, ReturnSchema = null },
            descriptor with { ReturnType = null },
            descriptor with { ReturnSchema = null },
        })
        {
            Assert.Throws<JsonException>(() => JsonSerializer.Serialize(manifest with { Entrypoints = [invalid] }));
        }
    }

    [Fact]
    public void UnitFieldsContributeWordsInsidePublicProducts()
    {
        var manifest = ManifestNode();
        manifest["entrypoints"] = JsonNode.Parse("""
            [{"name":"done","kind":{"kind":"View","value":null},"authorization":{"kind":"Anyone","value":null},"params":[],
              "return_type":"((), int, ())","return_schema":{"nodes":[
                {"kind":"Tuple","value":3},{"kind":"Unit","value":null},
                {"kind":"Leaf","value":{"kind":"Int","value":null}},
                {"kind":"Unit","value":null}]}}]
            """);
        var decoded = manifest.Deserialize<ToriiContractManifest>()!;
        Assert.Equal(3, decoded.Entrypoints!.Single().ReturnSchema!.WordCount);
        Assert.NotNull(JsonSerializer.Deserialize<ToriiContractManifest>(JsonSerializer.Serialize(decoded)));
    }
}
