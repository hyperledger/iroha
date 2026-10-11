using System.Text.Json;
using System.Text.Json.Nodes;
using Hyperledger.Iroha.Torii;

namespace Hyperledger.Iroha.Sdk.Tests;

public sealed class IvmFaultTests
{
    private static JsonObject Fixture() => new()
    {
        ["kind"] = new JsonObject { ["kind"] = "Numeric", ["value"] = new JsonObject { ["kind"] = "DivisionByZero", ["value"] = null } },
        ["site"] = new JsonObject
        {
            ["code_hash"] = new string('1', 64),
            ["selector"] = new JsonObject { ["kind"] = "Entrypoint", ["value"] = 7 },
            ["position"] = new JsonObject { ["kind"] = "Execute", ["value"] = new JsonObject { ["pc_offset"] = ulong.MaxValue } },
        },
    };

    [Fact]
    public void TypedFaultRoundTripsExactOriginAndU64Pc()
    {
        var json = Fixture();
        var fault = JsonSerializer.Deserialize<ToriiIvmFault>(json.ToJsonString())!;
        Assert.Equal(ToriiIvmNumericFaultCode.DivisionByZero, fault.Kind.Numeric);
        Assert.Equal((uint)7, fault.Site.Selector.Entrypoint);
        Assert.Equal(ulong.MaxValue, fault.Site.Position.PcOffset);
        Assert.True(JsonNode.DeepEquals(json, JsonNode.Parse(JsonSerializer.Serialize(fault))));
    }

    [Fact]
    public void ViewErrorRequiresNullableFaultAndPreservesTypedOrigin()
    {
        var response = new JsonObject
        {
            ["ok"] = false, ["dataspace"] = "universal", ["contract_id"] = "router::dex.universal",
            ["contract_address"] = null, ["code_hash_hex"] = new string('1', 64), ["abi_hash_hex"] = new string('2', 64),
            ["entrypoint"] = "main", ["error"] = "execution failed", ["vm_diagnostic"] = null, ["fault"] = Fixture(),
        };
        var parsed = JsonSerializer.Deserialize<ToriiContractViewErrorResponse>(response.ToJsonString())!;
        Assert.Equal(ToriiIvmNumericFaultCode.DivisionByZero, parsed.Fault!.Kind.Numeric);
        var written = JsonNode.Parse(JsonSerializer.Serialize(parsed))!;
        Assert.True(JsonNode.DeepEquals(response["fault"], written["fault"]));
        response["fault"] = null;
        Assert.Null(JsonSerializer.Deserialize<ToriiContractViewErrorResponse>(response.ToJsonString())!.Fault);
        response.Remove("fault");
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ToriiContractViewErrorResponse>(response.ToJsonString()));
    }

    [Fact]
    public void HttpErrorDetailsExposeTypedFault()
    {
        var envelope = new JsonObject { ["code"] = "ivm_fault", ["message"] = "execution failed", ["details"] = new JsonObject { ["ivm_fault"] = Fixture() } };
        var error = new ToriiApiException(System.Net.HttpStatusCode.BadRequest, null, envelope.ToJsonString(), null);
        Assert.Equal(ToriiIvmNumericFaultCode.DivisionByZero, error.Details!.IvmFault!.Kind.Numeric);
        Assert.Equal(ulong.MaxValue, error.Details.IvmFault.Site.Position.PcOffset);
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("extra")]
    [InlineData("ordinal")]
    [InlineData("stage")]
    [InlineData("hash")]
    [InlineData("subtype")]
    public void FaultRejectsInvalidClosedWireShape(string mutation)
    {
        var json = Fixture();
        switch (mutation)
        {
            case "unknown": json["kind"]!["kind"] = "RustDebugString"; break;
            case "extra": json["site"]!["local_address"] = 123; break;
            case "ordinal": json["site"]!["selector"]!["value"] = (ulong)uint.MaxValue + 1; break;
            case "stage": json["site"]!["position"]!["kind"] = "ReturnValidation"; break;
            case "hash": json["site"]!["code_hash"] = "11"; break;
            case "subtype": json["kind"]!["value"]!["kind"] = "WrongType"; break;
        }
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ToriiIvmFault>(json.ToJsonString()));
    }

    [Fact]
    public void FaultRejectsDuplicateFieldsAndInconsistentDirectModel()
    {
        var duplicate = Fixture().ToJsonString().Replace("\"kind\":\"Numeric\"", "\"kind\":\"Numeric\",\"kind\":\"Numeric\"");
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ToriiIvmFault>(duplicate));
        var fault = JsonSerializer.Deserialize<ToriiIvmFault>(Fixture().ToJsonString())!;
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(fault with { Kind = new(ToriiIvmFaultCode.OutOfGas, ToriiIvmNumericFaultCode.DivisionByZero) }));
    }
}
