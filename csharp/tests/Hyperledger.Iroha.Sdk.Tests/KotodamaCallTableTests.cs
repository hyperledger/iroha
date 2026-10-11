using System.Text.Json;
using Hyperledger.Iroha.Torii;

namespace Hyperledger.Iroha.Sdk.Tests;

/// <summary>Public schemas share the final V1 argument and result table bounds.</summary>
public sealed class KotodamaCallTableTests
{
    private static readonly (string TypeName, object[] Nodes) Boolean = (
        "bool", [new { kind = "Leaf", value = new { kind = "Bool", value = (object?)null } }]);

    [Fact]
    public void WideArgumentsAndReturnsUseTableWords()
    {
        var value = Parse(Enumerable.Repeat(Boolean, 64).ToArray(), Tuple(64));
        Assert.Equal(64, value.ArgumentSchema!.WordCount);
        Assert.Equal(64, value.ReturnSchema!.WordCount);
    }

    [Fact]
    public void ArgumentFieldCountHasAnInclusive8192Bound()
    {
        Assert.Equal(8192, Parse(Enumerable.Repeat(Boolean, 8192).ToArray()).ArgumentSchema!.WordCount);
        Assert.Throws<JsonException>(() => Parse(Enumerable.Repeat(Boolean, 8193).ToArray()));
    }

    [Fact]
    public void ArgumentLimitCountsFlattenedWordsAcrossFields()
    {
        var fields = Enumerable.Repeat(Tuple(128), 64).ToArray();
        Assert.Equal(8192, Parse(fields).ArgumentSchema!.WordCount);
        Assert.Throws<JsonException>(() => Parse(fields.Append(Boolean).ToArray()));
    }

    [Fact]
    public void TableCallingDoesNotRelaxTheTypeSchemaNodeBound()
    {
        Assert.Equal(255, Parse([], Tuple(255)).ReturnSchema!.WordCount);
        Assert.Throws<JsonException>(() => Parse([], Tuple(256)));
    }

    [Fact]
    public void EmptyNamedProductsKeepNominalIdentityAndOneWord()
    {
        (string TypeName, object[] Nodes) empty = ("struct Fixture::Empty",
            [new { kind = "Struct", value = new { name = "Fixture::Empty", fields = Array.Empty<string>() } }]);
        (string TypeName, object[] Nodes) list = ("List<struct Fixture::Empty, 2>",
            new object[] { new { kind = "List", value = new { capacity = 2 } } }.Concat(empty.Nodes).ToArray());
        var value = Parse([empty], list);
        Assert.Equal(1, value.ArgumentSchema!.WordCount);
        Assert.Equal(1, value.ReturnSchema!.WordCount);
        Assert.Equal("struct Fixture::Empty", value.ArgumentSchema.Fields.Single().ValueType.CanonicalTypeName);
        var encoded = JsonSerializer.Serialize(new ToriiContractManifest
        {
            Permissions = [], Events = [], EnumTypes = [], Entrypoints = [value],
        });
        Assert.Equal(1, JsonSerializer.Deserialize<ToriiContractManifest>(encoded)!.Entrypoints!.Single().ArgumentSchema!.WordCount);
    }

    private static (string TypeName, object[] Nodes) Tuple(int width) => (
        "(" + string.Join(", ", Enumerable.Repeat("bool", width)) + ")",
        new object[] { new { kind = "Tuple", value = width } }
            .Concat(Enumerable.Repeat(Boolean.Nodes.Single(), width)).ToArray());

    private static ToriiContractEntrypointDescriptor Parse(
        (string TypeName, object[] Nodes)[] fields,
        (string TypeName, object[] Nodes)? returns = null)
    {
        var result = returns ?? ("()", new object[] { new { kind = "Unit", value = (object?)null } });
        object? arguments = fields.Length == 0 ? null : new {
            fields = fields.Select((ty, index) => new {
                name = $"arg_{index}", ty = new { nodes = ty.Nodes },
            }),
        };
        var payload = JsonSerializer.Serialize(new {
            permissions = Array.Empty<object>(), events = Array.Empty<object>(), enum_types = Array.Empty<object>(),
            entrypoints = new[] { new {
                name = "inspect", kind = new { kind = "View", value = (object?)null },
                authorization = new { kind = "Anyone", value = (object?)null },
                @params = fields.Select((ty, index) => new { name = $"arg_{index}", type_name = ty.TypeName }),
                argument_schema = arguments,
                return_type = result.Item1, return_schema = new { nodes = result.Item2 },
            } },
        });
        return JsonSerializer.Deserialize<ToriiContractManifest>(payload)!.Entrypoints!.Single();
    }
}
