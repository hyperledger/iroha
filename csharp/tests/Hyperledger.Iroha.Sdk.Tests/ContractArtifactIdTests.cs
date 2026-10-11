using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Hyperledger.Iroha.Crypto;
using Hyperledger.Iroha.Http;
using Hyperledger.Iroha.Torii;

namespace Hyperledger.Iroha.Sdk.Tests;

public sealed class ContractArtifactIdTests
{
    private const string Network = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0";
    private const string OtherNetwork = "hash:82531CE8EAE8BFF6BEECA4698BFD13A3BC8BEC5F0EE0D23D428C97FC17AB0F3B#3E94";
    private const string Account = "sorauﾛ1NｲﾘｳdPBeｼRoｸQ2ﾔgｼQqeｶﾍｽﾁhRW2ｺｿZ9ﾕｦUﾅRX5NJYH53";
    // Public disposable vector key, never a wallet or deployment credential.
    private const string SeedHex = "616e64726f69642d666978747572652d7369676e696e672d6b65792d30313032";
    // Independent Python hashlib BLAKE2b-256(domain || 01020304), final marker bit set.
    private const string BytesHash = "43aecd10536d570e5998476e55aebf5bbbd3dc8c90ac31cb6b87d7e2119c157d";

    [Theory]
    [InlineData(0UL)]
    [InlineData(ulong.MaxValue)]
    public void CanonicalIdentityRoundtripsFullDataspaceRange(ulong dataspace)
    {
        var artifact = new ContractArtifactId(dataspace, BytesHash);
        var json = JsonSerializer.Serialize(artifact);
        Assert.Equal(artifact, JsonSerializer.Deserialize<ContractArtifactId>(json));
        Assert.Equal(dataspace, JsonNode.Parse(json)!["dataspace_id"]!.GetValue<ulong>());
        Assert.NotEqual(artifact, new ContractArtifactId(dataspace == 0 ? ulong.MaxValue : 0, BytesHash));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("negative")]
    [InlineData("overflow")]
    [InlineData("string")]
    [InlineData("fraction")]
    [InlineData("unknown")]
    [InlineData("duplicate")]
    [InlineData("bare-hash")]
    [InlineData("null-hash")]
    [InlineData("checksum")]
    [InlineData("unmarked-literal")]
    public void IdentityRejectsMalformedOrRetiredWireShapes(string mutation)
    {
        var json = JsonSerializer.SerializeToNode(new ContractArtifactId(0, BytesHash))!.AsObject();
        switch (mutation)
        {
            case "missing": json.Remove("dataspace_id"); break;
            case "negative": json["dataspace_id"] = -1; break;
            case "overflow": json["dataspace_id"] = JsonNode.Parse("18446744073709551616"); break;
            case "string": json["dataspace_id"] = "0"; break;
            case "fraction": json["dataspace_id"] = 0.5; break;
            case "unknown": json["extra"] = 1; break;
            case "null-hash": json["code_hash"] = null; break;
            case "checksum": json["code_hash"] = "hash:" + new string('B', 64) + "#0000"; break;
            case "unmarked-literal": json["code_hash"] = "hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#0E5B"; break;
            case "bare-hash": json["code_hash"] = BytesHash; break;
            case "duplicate":
                Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ContractArtifactId>(json.ToJsonString().Insert(1, "\"dataspace_id\":0,")));
                return;
        }
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ContractArtifactId>(json.ToJsonString()));
    }

    [Theory]
    [InlineData("uppercase")]
    [InlineData("unmarked")]
    public void ConstructorRejectsNoncanonicalHashInsteadOfRewritingIt(string mutation)
    {
        var hash = mutation == "uppercase" ? BytesHash.ToUpperInvariant() : new string('a', 64);
        var error = Assert.Throws<ArgumentException>(() => new ContractArtifactId(0, hash));
        Assert.Equal("codeHash", error.ParamName);
    }

    public static IEnumerable<object[]> RoutesAndMutations()
    {
        foreach (var route in new[] { "manifest", "bytes", "view", "submit", "job" })
            foreach (var mutation in new[] { "none", "network", "dataspace", "hash" })
                yield return new object[] { route, mutation };
        yield return new object[] { "job", "job-id" };
    }

    [Theory]
    [MemberData(nameof(RoutesAndMutations))]
    public async Task AuthenticatedRoutesBindTheExactNetworkAndArtifact(string route, string mutation)
    {
        var artifact = new ContractArtifactId(ulong.MaxValue, BytesHash);
        var actual = mutation switch
        {
            "dataspace" => new ContractArtifactId(0, BytesHash),
            "hash" => new ContractArtifactId(ulong.MaxValue, new string('b', 64)),
            _ => artifact,
        };
        var response = Response(route, actual, mutation == "network" ? OtherNetwork : Network);
        if (mutation == "job-id") response["job_id"] = "job-2";
        using var handler = new ArtifactHandler(response);
        var seed = Convert.FromHexString(SeedHex);
        try
        {
            using var credentials = new CanonicalRequestCredentials(Account, seed);
            using var client = new ToriiClient(new Uri("https://torii.example"), new HttpClient(handler),
                new ToriiClientOptions { NetworkId = NetworkId.Parse(Network), CanonicalRequestCredentials = credentials },
                TransactionSubmissionTransportAssurance.OneShotWithoutRedirectsOrRetries);
            if (mutation == "none") await Invoke(client, route, artifact);
            else
            {
                var error = await Assert.ThrowsAsync<JsonException>(() => Invoke(client, route, artifact));
                Assert.Contains(mutation == "job-id" ? "job_id differs from the requested job" : "requested network or artifact identity", error.Message);
            }
            var path = $"/v1/contracts/artifacts/18446744073709551615/{BytesHash}" + Suffix(route);
            Assert.Equal(path, handler.Path);
            Assert.Equal(route == "submit" ? "POST" : "GET", handler.Method);
            Assert.NotNull(handler.Headers);
            var headers = handler.Headers!;
            Assert.True(headers.ContainsKey("X-Iroha-Account"));
            var message = CanonicalRequest.BuildSignatureMessage(NetworkId.Parse(Network), handler.Method!, path,
                body: handler.Body!, timestampMs: long.Parse(headers["X-Iroha-Timestamp-Ms"], CultureInfo.InvariantCulture), nonce: headers["X-Iroha-Nonce"]);
            var signature = Convert.FromBase64String(headers["X-Iroha-Signature"]);
            Assert.True(Ed25519Signer.Verify(message, signature, Ed25519Signer.GetPublicKey(seed)));
            var altered = CanonicalRequest.BuildSignatureMessage(NetworkId.Parse(Network), handler.Method!, path.Replace("18446744073709551615", "0", StringComparison.Ordinal),
                body: handler.Body!, timestampMs: long.Parse(headers["X-Iroha-Timestamp-Ms"], CultureInfo.InvariantCulture), nonce: headers["X-Iroha-Nonce"]);
            Assert.False(Ed25519Signer.Verify(altered, signature, Ed25519Signer.GetPublicKey(seed)));
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(seed); }
    }

    [Theory]
    [InlineData("manifest")]
    [InlineData("bytes")]
    [InlineData("view")]
    [InlineData("submit")]
    [InlineData("job")]
    public async Task ArtifactRoutesRequireAuthenticationBeforeDispatch(string route)
    {
        using var handler = new ArtifactHandler("{}");
        using var client = new ToriiClient(new Uri("https://torii.example"), new HttpClient(handler), new ToriiClientOptions { NetworkId = NetworkId.Parse(Network) });
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Invoke(client, route, new ContractArtifactId(0, BytesHash)));
        Assert.Contains("CanonicalRequestCredentials", error.Message);
        Assert.Null(handler.Path);
    }

    [Fact]
    public async Task BytecodeMustMatchTheFullArtifactHash()
    {
        var artifact = new ContractArtifactId(0, BytesHash);
        var response = Response("bytes", artifact, Network);
        response["code_b64"] = "AQIDBQ==";
        using var handler = new ArtifactHandler(response);
        var seed = Convert.FromHexString(SeedHex);
        try
        {
            using var credentials = new CanonicalRequestCredentials(Account, seed);
            using var client = new ToriiClient(new Uri("https://torii.example"), new HttpClient(handler),
                new ToriiClientOptions { NetworkId = NetworkId.Parse(Network), CanonicalRequestCredentials = credentials },
                TransactionSubmissionTransportAssurance.OneShotWithoutRedirectsOrRetries);
            var error = await Assert.ThrowsAsync<JsonException>(() => client.GetContractCodeBytesResponseAsync(artifact, TestContext.Current.CancellationToken));
            Assert.Contains("does not match its artifact_id code_hash", error.Message);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(seed); }
    }

    private static string Suffix(string route) => route switch
    {
        "manifest" => "", "bytes" => "/bytes", "view" => "/contract-view", "submit" => "/verified-source/jobs", "job" => "/verified-source/jobs/job-1",
        _ => throw new ArgumentOutOfRangeException(nameof(route)),
    };

    private static Task Invoke(ToriiClient client, string route, ContractArtifactId artifact) => route switch
    {
        "manifest" => client.GetContractCodeAsync(artifact, TestContext.Current.CancellationToken),
        "bytes" => client.GetContractCodeBytesAsync(artifact, TestContext.Current.CancellationToken),
        "view" => client.GetContractCodeViewAsync(artifact, TestContext.Current.CancellationToken),
        "submit" => client.SubmitContractVerifiedSourceJobAsync(artifact, new ToriiContractVerifiedSourceSubmission {
            Language = "kotodama", SourceName = "app.ko", SourceText = "seiyaku App {}",
        }, TestContext.Current.CancellationToken),
        "job" => client.GetContractVerifiedSourceJobAsync(artifact, "job-1", TestContext.Current.CancellationToken),
        _ => throw new ArgumentOutOfRangeException(nameof(route)),
    };

    private static JsonObject Response(string route, ContractArtifactId artifact, string network)
    {
        var response = new JsonObject { ["network_id"] = network, ["artifact_id"] = JsonSerializer.SerializeToNode(artifact) };
        if (route == "bytes") response["code_b64"] = "AQIDBA==";
        else if (route == "manifest")
        {
            response["manifest"] = new JsonObject
            {
                ["code_hash"] = JsonSerializer.SerializeToNode(artifact)!["code_hash"]!.DeepClone(),
                ["permissions"] = new JsonArray(),
                ["events"] = new JsonArray(),
                ["enum_types"] = new JsonArray(),
            };
            response["code_hash"] = artifact.CodeHashHex;
        }
        else
        {
            response["code_hash"] = artifact.CodeHashHex;
            if (route == "view")
            {
                response["rendered_source_kind"] = "pseudo_source"; response["rendered_source_text"] = "seiyaku App {}";
                response["permissions"] = new JsonArray(); response["entrypoints"] = new JsonArray(); response["warnings"] = new JsonArray();
                response["source_artifacts"] = new JsonArray();
            }
            else
            {
                response["job_id"] = "job-1"; response["status"] = "queued"; response["submitted_at"] = "2026-09-30T00:00:00Z";
            }
        }
        return response;
    }

    private sealed class ArtifactHandler : HttpMessageHandler
    {
        private readonly string response;
        public ArtifactHandler(JsonObject response) : this(response.ToJsonString()) { }
        public ArtifactHandler(string response) { this.response = response; }
        public string? Path { get; private set; }
        public string? Method { get; private set; }
        public byte[]? Body { get; private set; }
        public Dictionary<string, string>? Headers { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Path = request.RequestUri!.AbsolutePath; Method = request.Method.Method;
            Body = request.Content is null ? Array.Empty<byte>() : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            Headers = request.Headers.ToDictionary(x => x.Key, x => Assert.Single(x.Value), StringComparer.OrdinalIgnoreCase);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
    }
}
