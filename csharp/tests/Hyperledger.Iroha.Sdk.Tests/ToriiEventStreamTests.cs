using System.Net;
using System.Text;
using System.Text.Json;
using Hyperledger.Iroha.Torii;

namespace Hyperledger.Iroha.Sdk.Tests;

/// <summary>Typed decoding of <c>GET /v1/events/sse</c> payloads over a mocked transport.</summary>
public sealed class ToriiEventStreamTests
{
    private static readonly string HashA = new('a', 64);
    private static readonly string HashB = new('b', 64);
    private static readonly string HashC = new('c', 64);

    [Fact]
    public async Task StableEventShapesDecodeIntoTypedEvents()
    {
        var events = await ReadAllAsync($$"""
            : heartbeat

            data: {"category":"Pipeline","event":"Transaction","hash":"{{HashA}}","lane_id":3,"dataspace_id":7,"block_height":null,"status":"Queued"}

            data: {"category":"Pipeline","event":"Transaction","hash":"{{HashA}}","lane_id":3,"dataspace_id":7,"block_height":11,"status":"Rejected","rejection_code":"instruction_execution","rejection_reason":"Instruction execution failed.","future":[1]}

            data: {"category":"Pipeline","event":"Block","status":"Committed"}

            data: {"category":"Pipeline","event":"Block","status":"Rejected","rejection_code":"EmptyBlock"}

            data: {"category":"Pipeline","event":"Warning","kind":"slow_commit","details":"took 3 s","height":12}

            data: {"category":"Pipeline","event":"Witness","block_hash":"{{HashB}}","height":12,"view":1,"epoch":2,"read_count":40,"write_count":5}

            data: {"category":"Data","event":"ProofVerified","backend":"pipa-r/pasta","proof_hash":"{{HashC}}","call_hash":"{{HashA}}","envelope_hash":null,"vk_ref":"pipa-r/pasta::vk_main","vk_commitment":"{{HashB}}"}

            data: {"category":"Data","event":"ProofRejected","backend":"pipa-r/pasta","proof_hash":"{{HashC}}","call_hash":null,"envelope_hash":null,"vk_ref":null,"vk_commitment":null}

            data: {"category":"Data","event":"ProofPruned","backend":"pipa-r/pasta","removed_count":1,"remaining":3,"cap":32,"grace_blocks":64,"prune_batch":8,"pruned_at_height":777,"pruned_by":"sorau1","origin":"Insert","removed":[{"backend":"pipa-r/pasta","proof_hash":"{{HashC}}"}]}

            data: {"category":"Data","event":"Asset","summary":"Added(...)"}

            data: {"category":"Other","event":"Time","summary":"TimeEvent { .. }"}

            """);

        Assert.Equal(11, events.Count);
        var queued = Assert.IsType<ToriiTransactionEvent>(events[0]);
        Assert.Equal(("Pipeline", "Transaction"), (queued.Category, queued.Event));
        Assert.Equal(HashA, queued.Hash);
        Assert.Equal(3U, queued.LaneId);
        Assert.Equal(7UL, queued.DataspaceId);
        Assert.Null(queued.BlockHeight);
        Assert.Equal(ToriiTransactionStatus.Queued, queued.Status);
        Assert.Null(queued.RejectionCode);

        var rejected = Assert.IsType<ToriiTransactionEvent>(events[1]);
        Assert.Equal(11UL, rejected.BlockHeight);
        Assert.Equal(ToriiTransactionStatus.Rejected, rejected.Status);
        Assert.Equal("instruction_execution", rejected.RejectionCode);
        Assert.Equal("Instruction execution failed.", rejected.RejectionReason);

        Assert.Equal(ToriiBlockStatus.Committed, Assert.IsType<ToriiBlockEvent>(events[2]).Status);
        var rejectedBlock = Assert.IsType<ToriiBlockEvent>(events[3]);
        Assert.Equal(ToriiBlockStatus.Rejected, rejectedBlock.Status);
        Assert.Equal("EmptyBlock", rejectedBlock.RejectionCode);

        var warning = Assert.IsType<ToriiPipelineWarningEvent>(events[4]);
        Assert.Equal(("slow_commit", "took 3 s", 12UL), (warning.Kind, warning.Details, warning.Height));

        var witness = Assert.IsType<ToriiWitnessEvent>(events[5]);
        Assert.Equal(HashB, witness.BlockHash);
        Assert.Equal((12UL, 1UL, 2UL, 40UL, 5UL), (witness.Height, witness.View, witness.Epoch, witness.ReadCount, witness.WriteCount));

        var verified = Assert.IsType<ToriiProofVerificationEvent>(events[6]);
        Assert.Equal(("Data", "ProofVerified"), (verified.Category, verified.Event));
        Assert.True(verified.Verified);
        Assert.Equal("pipa-r/pasta", verified.Backend);
        Assert.Equal(HashC, verified.ProofHash);
        Assert.Equal(HashA, verified.CallHash);
        Assert.Null(verified.EnvelopeHash);
        Assert.Equal("pipa-r/pasta::vk_main", verified.VerifyingKeyReference);
        Assert.Equal(HashB, verified.VerifyingKeyCommitment);

        var proofRejected = Assert.IsType<ToriiProofVerificationEvent>(events[7]);
        Assert.False(proofRejected.Verified);
        Assert.Equal("ProofRejected", proofRejected.Event);
        Assert.Null(proofRejected.VerifyingKeyReference);

        var pruned = Assert.IsType<ToriiProofPrunedEvent>(events[8]);
        Assert.Equal("ProofPruned", pruned.Event);
        Assert.Equal((3UL, 32UL, 64UL, 8UL, 777UL), (pruned.Remaining, pruned.Cap, pruned.GraceBlocks, pruned.PruneBatch, pruned.PrunedAtHeight));
        Assert.Equal("sorau1", pruned.PrunedBy);
        Assert.Equal(ToriiProofPruneOrigin.Insert, pruned.Origin);
        Assert.Equal(new ToriiPrunedProof { Backend = "pipa-r/pasta", ProofHash = HashC }, Assert.Single(pruned.Removed));

        var data = Assert.IsType<ToriiDataEvent>(events[9]);
        Assert.Equal(("Data", "Asset", "Added(...)"), (data.Category, data.Event, data.Summary));
        var other = Assert.IsType<ToriiOtherEvent>(events[10]);
        Assert.Equal(("Other", "Time"), (other.Category, other.Event));
    }

    [Fact]
    public async Task UnknownEventsArriveAsUnknownOrGenericEventsWithoutFailingTheStream()
    {
        var events = await ReadAllAsync("""
            data: {"category":"Pipeline","event":"Fork","depth":2}

            data: {"category":"Audit","event":"Sealed","seal":{"id":1}}

            data: {"category":"Data","event":"Sccp"}

            data: {"category":"Other","event":"Other","summary":null}

            """);

        var fork = Assert.IsType<ToriiUnknownEvent>(events[0]);
        Assert.Equal(("Pipeline", "Fork"), (fork.Category, fork.Event));
        Assert.Equal(2, fork.Payload["depth"]!.GetValue<int>());
        var audit = Assert.IsType<ToriiUnknownEvent>(events[1]);
        Assert.Equal(1, audit.Payload["seal"]!["id"]!.GetValue<int>());
        var data = Assert.IsType<ToriiDataEvent>(events[2]);
        Assert.Equal("Sccp", data.Event);
        Assert.Null(data.Summary);
        Assert.Null(Assert.IsType<ToriiOtherEvent>(events[3]).Summary);
    }

    [Fact]
    public async Task PipelineAndProofStreamsKeepTheirEventFamilies()
    {
        var body = $$"""
            data: {"category":"Pipeline","event":"Block","status":"Applied"}

            data: {"category":"Data","event":"ProofRejected","backend":"groth16","proof_hash":"{{HashC}}"}

            data: {"category":"Data","event":"Asset","summary":"x"}

            data: {"category":"Pipeline","event":"Fork"}

            """;
        using var handler = new SseHandler(body);
        using var client = new ToriiClient(new Uri("https://torii.example"), new HttpClient(handler));

        var pipeline = new List<ToriiPipelineEvent>();
        await foreach (var item in client.StreamPipelineEventsAsync(cancellationToken: TestContext.Current.CancellationToken))
        {
            pipeline.Add(item);
        }

        var proofs = new List<ToriiProofEvent>();
        await foreach (var item in client.StreamProofEventsAsync(cancellationToken: TestContext.Current.CancellationToken))
        {
            proofs.Add(item);
        }

        Assert.Equal(ToriiBlockStatus.Applied, Assert.IsType<ToriiBlockEvent>(Assert.Single(pipeline)).Status);
        var proof = Assert.IsType<ToriiProofVerificationEvent>(Assert.Single(proofs));
        Assert.Equal("groth16", proof.Backend);
        Assert.Null(proof.CallHash);
    }

    public static IEnumerable<object[]> MalformedPayloads()
    {
        var tx = $"\"category\":\"Pipeline\",\"event\":\"Transaction\",\"hash\":\"{HashA}\",\"lane_id\":1,\"dataspace_id\":0,\"block_height\":null";
        yield return ["[1]", "event stream payload must be a JSON object"];
        yield return ["not json", "event stream payload must be a JSON object"];
        yield return ["{\"event\":\"Transaction\"}", "event stream payload.category must be a string"];
        yield return ["{\"category\":\"Pipeline\",\"event\":7}", "event stream payload.event must be a string"];
        yield return ["{\"category\":\"Pipeline\",\"category\":\"Data\",\"event\":\"Block\"}", "category must not appear more than once"];
        yield return [$"{{{tx},\"status\":\"Committed\"}}", "status `Committed` is not a transaction status"];
        yield return [$"{{{tx},\"status\":\"Rejected\",\"rejection_reason\":\"x\"}}", "rejection_code must be a string"];
        yield return [$"{{{tx},\"status\":\"Rejected\",\"rejection_code\":\"validation\"}}", "rejection_reason must be a string"];
        yield return [$"{{{tx.Replace(HashA, HashA.ToUpperInvariant(), StringComparison.Ordinal)},\"status\":\"Queued\"}}", "hash must be an exact lowercase 32-byte hex string"];
        yield return [$"{{{tx.Replace("\"lane_id\":1", "\"lane_id\":4294967296", StringComparison.Ordinal)},\"status\":\"Queued\"}}", "lane_id must fit an unsigned 32-bit integer"];
        yield return [$"{{{tx.Replace("\"block_height\":null", "\"block_height\":-1", StringComparison.Ordinal)},\"status\":\"Queued\"}}", "block_height must be an unsigned integer or null"];
        yield return ["{\"category\":\"Pipeline\",\"event\":\"Block\",\"status\":\"Queued\"}", "status `Queued` is not a block status"];
        yield return ["{\"category\":\"Pipeline\",\"event\":\"Block\",\"status\":\"Rejected\"}", "rejection_code must be a string"];
        yield return ["{\"category\":\"Pipeline\",\"event\":\"Warning\",\"kind\":\"k\",\"details\":\"d\"}", "height must be an unsigned integer"];
        yield return ["{\"category\":\"Data\",\"event\":\"ProofVerified\",\"backend\":\"b\",\"proof_hash\":\"0x00\"}", "proof_hash must be an exact lowercase 32-byte hex string"];
        yield return [$"{{\"category\":\"Data\",\"event\":\"ProofPruned\",\"backend\":\"b\",\"removed_count\":2,\"remaining\":0,\"cap\":1,\"grace_blocks\":0,\"prune_batch\":1,\"pruned_at_height\":1,\"pruned_by\":\"a\",\"origin\":\"Insert\",\"removed\":[{{\"backend\":\"b\",\"proof_hash\":\"{HashC}\"}}]}}", "removed_count must equal the number of `removed` entries"];
        yield return ["{\"category\":\"Data\",\"event\":\"ProofPruned\",\"backend\":\"b\",\"removed_count\":0,\"remaining\":0,\"cap\":1,\"grace_blocks\":0,\"prune_batch\":1,\"pruned_at_height\":1,\"pruned_by\":\"a\",\"origin\":\"Automatic\",\"removed\":[]}", "origin `Automatic` is not a pruning origin"];
        yield return ["{\"category\":\"Data\",\"event\":\"Asset\",\"summary\":5}", "summary must be a string or null"];
    }

    [Theory]
    [MemberData(nameof(MalformedPayloads))]
    public async Task MalformedKnownPayloadsFailTheStream(string payload, string expected)
    {
        var error = await Assert.ThrowsAsync<JsonException>(() => ReadAllAsync($"data: {payload}\n\n"));

        Assert.Contains(expected, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TerminalStreamErrorsEndTheTypedStream()
    {
        var error = await Assert.ThrowsAsync<ToriiStreamException>(() => ReadAllAsync("""
            data: {"category":"Pipeline","event":"Block","status":"Created"}

            event: stream_error
            data: {"code":"stream_authorization_revoked","message":"The stream authorization is no longer valid.","dropped_messages":null,"replay_available":false}

            """));

        Assert.Equal("stream_authorization_revoked", error.Code);
        Assert.False(error.ReplayAvailable);
    }

    private static async Task<List<ToriiEvent>> ReadAllAsync(string body)
    {
        using var handler = new SseHandler(body);
        using var client = new ToriiClient(new Uri("https://torii.example"), new HttpClient(handler));
        var events = new List<ToriiEvent>();
        await foreach (var item in client.StreamEventsAsync(cancellationToken: TestContext.Current.CancellationToken))
        {
            events.Add(item);
        }

        Assert.Equal("/v1/events/sse", handler.LastPath);
        return events;
    }

    private sealed class SseHandler(string body) : HttpMessageHandler
    {
        public string? LastPath { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastPath = request.RequestUri!.AbsolutePath;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "text/event-stream"),
                RequestMessage = request,
            });
        }
    }
}
