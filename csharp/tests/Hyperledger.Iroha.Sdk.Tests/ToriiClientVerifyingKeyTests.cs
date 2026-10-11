using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Hyperledger.Iroha.Address;
using Hyperledger.Iroha.Http;
using Hyperledger.Iroha.Norito;
using Hyperledger.Iroha.Queries;
using Hyperledger.Iroha.Torii;
using Hyperledger.Iroha.Transactions;

namespace Hyperledger.Iroha.Sdk.Tests;

public sealed partial class ToriiClientTests
{
    [Fact]
    public async Task RegisterVerifyingKeyAsyncCanonicalizesInlineCommitmentPayload()
    {
        var vkBytes = "abc"u8.ToArray();
        var expectedVkBytes = vkBytes.ToArray();
        var commitmentHex = VerifyingKeyCommitmentHex("pipa-r/pasta", expectedVkBytes);
        using var handler = new RecordingHandler(request =>
        {
            Assert.Equal("/v1/zk/vk/register", request.RequestUri!.AbsolutePath);
            using var body = ReadBodyAsJson(request);
            var root = body.RootElement;
            Assert.Equal(VerifyingKeyAuthorityAccountId, root.GetProperty("authority").GetString());
            Assert.False(root.TryGetProperty("private_key", out _));
            Assert.Equal("pipa-r/pasta", root.GetProperty("backend").GetString());
            Assert.Equal("vk_main", root.GetProperty("name").GetString());
            Assert.Equal(1u, root.GetProperty("version").GetUInt32());
            Assert.Equal(new string('a', 64), root.GetProperty("public_inputs_schema_hash_hex").GetString());
            Assert.Equal(commitmentHex, root.GetProperty("commitment_hex").GetString());
            Assert.Equal(Convert.ToBase64String(expectedVkBytes), root.GetProperty("vk_bytes").GetString());
            Assert.Equal(3u, root.GetProperty("vk_len").GetUInt32());
            Assert.Equal("Active", root.GetProperty("status").GetString());
            return JsonResponse(VerifyingKeyTransactionDraftResponseJson());
        });
        using var client = CreateVerifyingKeyClient(handler);

        var registerRequest = new ToriiVerifyingKeyRegisterRequest
        {
            Authority = VerifyingKeyAuthorityAccountId,
            Backend = "pipa-r/pasta",
            Name = "vk_main",
            Version = 1,
            CircuitId = "pipa-r/pasta/confidential-transfer-v1",
            PublicInputsSchemaHashHex = "0x" + new string('A', 64),
            GasScheduleId = "native_default",
            VerifyingKeyBytes = vkBytes,
            CommitmentHex = commitmentHex.ToUpperInvariant(),
            Status = "active",
        };
        vkBytes[0] = (byte)'z';
        var detachedVkBytes = Assert.IsType<byte[]>(registerRequest.VerifyingKeyBytes);
        detachedVkBytes[1] = (byte)'z';
        Assert.Equal(expectedVkBytes, Assert.IsType<byte[]>(registerRequest.VerifyingKeyBytes));

        var response = await client.RegisterVerifyingKeyAsync(registerRequest, cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(response.Submitted);
        Assert.Equal(CanonicalVerifyingKeyTransactionPayload(), response.TransactionPayload);
        Assert.Equal(IrohaHash.Hash(response.TransactionPayload), response.SigningMessage);
    }

    [Fact]
    public async Task UpdateVerifyingKeyAsyncCanonicalizesInlineCommitmentPayload()
    {
        var vkBytes = "abcd"u8.ToArray();
        var expectedVkBytes = vkBytes.ToArray();
        var commitmentHex = VerifyingKeyCommitmentHex("pipa-r/pasta", expectedVkBytes);
        var expectedDraftRequest = ValidVerifyingKeyUpdateRequest() with
        {
            GasScheduleId = null,
            Status = "Withdrawn",
        };
        using var handler = new RecordingHandler(request =>
        {
            Assert.Equal("/v1/zk/vk/update", request.RequestUri!.AbsolutePath);
            using var body = ReadBodyAsJson(request);
            var root = body.RootElement;
            Assert.Equal(VerifyingKeyAuthorityAccountId, root.GetProperty("authority").GetString());
            Assert.False(root.TryGetProperty("private_key", out _));
            Assert.Equal("pipa-r/pasta", root.GetProperty("backend").GetString());
            Assert.Equal("vk_main", root.GetProperty("name").GetString());
            Assert.Equal(2u, root.GetProperty("version").GetUInt32());
            Assert.Equal(new string('b', 64), root.GetProperty("public_inputs_schema_hash_hex").GetString());
            Assert.Equal(commitmentHex, root.GetProperty("commitment_hex").GetString());
            Assert.Equal(Convert.ToBase64String(expectedVkBytes), root.GetProperty("vk_bytes").GetString());
            Assert.Equal(4u, root.GetProperty("vk_len").GetUInt32());
            Assert.Equal("Withdrawn", root.GetProperty("status").GetString());
            return JsonResponse(
                VerifyingKeyTransactionDraftResponseJson(expectedDraftRequest));
        });
        using var client = CreateVerifyingKeyClient(handler);

        var updateRequest = new ToriiVerifyingKeyUpdateRequest
        {
            Authority = VerifyingKeyAuthorityAccountId,
            Backend = "pipa-r/pasta",
            Name = "vk_main",
            Version = 2,
            CircuitId = "pipa-r/pasta/confidential-transfer-v1",
            PublicInputsSchemaHashHex = "0x" + new string('B', 64),
            VerifyingKeyBytes = vkBytes,
            CommitmentHex = commitmentHex.ToUpperInvariant(),
            Status = "withdrawn",
        };
        vkBytes[0] = (byte)'z';
        var detachedVkBytes = Assert.IsType<byte[]>(updateRequest.VerifyingKeyBytes);
        detachedVkBytes[1] = (byte)'z';
        Assert.Equal(expectedVkBytes, Assert.IsType<byte[]>(updateRequest.VerifyingKeyBytes));

        var response = await client.UpdateVerifyingKeyAsync(updateRequest, cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(response.Submitted);
        Assert.Equal(
            CanonicalVerifyingKeyTransactionPayload(expectedDraftRequest),
            response.TransactionPayload);
        Assert.Equal(IrohaHash.Hash(response.TransactionPayload), response.SigningMessage);
    }

    [Fact]
    public async Task GetVerifyingKeyAsyncEncodesIdentifierAndValidatesResponse()
    {
        using var handler = new RecordingHandler(_ =>
            JsonResponse(VerifyingKeyDetailResponseJson()));
        using var client = new ToriiClient(
            new Uri("https://torii.example"),
            new HttpClient(handler));

        using var response = await client.GetVerifyingKeyAsync("pipa-r/pasta", "vk_main", cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("pipa-r/pasta", response.RootElement.GetProperty("id").GetProperty("backend").GetString());
        Assert.Equal("Active", response.RootElement.GetProperty("record").GetProperty("status").GetString());
        Assert.Contains("/v1/zk/vk/pipa-r%2Fpasta/vk_main", handler.LastRequest!.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task UpdateVerifyingKeyAsyncRejectsMismatchedInlineCommitmentBeforeRequest()
    {
        using var handler = new RecordingHandler(_ => throw new InvalidOperationException("request must not be sent"));
        using var client = CreateVerifyingKeyClient(handler);

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            client.UpdateVerifyingKeyAsync(new ToriiVerifyingKeyUpdateRequest
            {
                Authority = VerifyingKeyAuthorityAccountId,
                Backend = "pipa-r/pasta",
                Name = "vk_main",
                Version = 2,
                CircuitId = "pipa-r/pasta/confidential-transfer-v1",
                PublicInputsSchemaHashHex = new string('b', 64),
                VerifyingKeyBytes = "abc"u8.ToArray(),
                CommitmentHex = new string('0', 64),
            }, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Contains("commitment_hex must match domain-separated SHA-256", error.Message);
        Assert.Null(handler.LastRequest);
    }

    public static IEnumerable<object?[]> InvalidVerifyingKeyDetailResponses()
    {
        yield return new object?[] { "id", VerifyingKeyDetailResponseJson("id", null), "must not be null" };
        yield return new object?[]
        {
            "id.backend",
            VerifyingKeyDetailResponseJson("id.backend", " pipa-r/pasta"),
            "surrounding whitespace",
        };
        yield return new object?[]
        {
            "id.name",
            VerifyingKeyDetailResponseJson("id.name", "vk:main"),
            "':'",
        };
        yield return new object?[] { "record", VerifyingKeyDetailResponseJson("record", null), "must not be null" };
        yield return new object?[]
        {
            "record.backend",
            VerifyingKeyDetailResponseJson("record.backend", "halo2/ipa-pasta-cycle-v1"),
            "must match",
        };
        yield return new object?[] { "record.version", VerifyingKeyDetailResponseJson("record.version", 0), "positive" };
        yield return new object?[]
        {
            "record.circuit_id",
            VerifyingKeyDetailResponseJson("record.circuit_id", "pipa-r/pasta/confidential-transfer v2"),
            "whitespace",
        };
        yield return new object?[]
        {
            "record.curve",
            VerifyingKeyDetailResponseJson("record.curve", " pallas"),
            "surrounding whitespace",
        };
        yield return new object?[]
        {
            "record.public_inputs_schema_hash",
            VerifyingKeyDetailResponseJson("record.public_inputs_schema_hash", "0x" + new string('a', 64)),
            "32-byte hex string",
        };
        yield return new object?[]
        {
            "record.public_inputs_schema_hash",
            VerifyingKeyDetailResponseJson("record.public_inputs_schema_hash", new string('A', 64)),
            "lowercase",
        };
        yield return new object?[]
        {
            "record.commitment",
            VerifyingKeyDetailResponseJson("record.commitment", new string('g', 64)),
            "32-byte hex string",
        };
        yield return new object?[] { "record.vk_len", VerifyingKeyDetailResponseJson("record.vk_len", 0), "positive" };
        yield return new object?[]
        {
            "record.max_proof_bytes",
            VerifyingKeyDetailResponseJson("record.max_proof_bytes", 0),
            "positive",
        };
        yield return new object?[]
        {
            "record.gas_schedule_id",
            VerifyingKeyDetailResponseJson("record.gas_schedule_id", "native default"),
            "whitespace",
        };
        yield return new object?[]
        {
            "record.metadata_uri_cid",
            VerifyingKeyDetailResponseJson("record.metadata_uri_cid", " ipfs://vk-meta"),
            "surrounding whitespace",
        };
        yield return new object?[]
        {
            "record.vk_bytes_cid",
            VerifyingKeyDetailResponseJson("record.vk_bytes_cid", "ipfs://vk bundle"),
            "whitespace",
        };
        yield return new object?[]
        {
            "record.activation_height",
            VerifyingKeyDetailResponseJson("record.activation_height", -1),
            "unsigned integer",
        };
        yield return new object?[]
        {
            "record.withdraw_height",
            VerifyingKeyDetailResponseJson("record.withdraw_height", 1023),
            "greater than or equal",
        };
        yield return new object?[]
        {
            "record.status",
            VerifyingKeyDetailResponseJson("record.status", "active"),
            "must be one of",
        };
        yield return new object?[] { "record.key", VerifyingKeyDetailResponseJson("record.key", "inline"), "must be an object" };
        yield return new object?[]
        {
            "record.key.backend",
            VerifyingKeyDetailResponseJson("record.key.backend", "halo2/ipa-pasta-cycle-v1"),
            "must match",
        };
        yield return new object?[]
        {
            "record.key.bytes_b64",
            VerifyingKeyDetailResponseJson("record.key.bytes_b64", "AQID "),
            "whitespace",
        };
        yield return new object?[]
        {
            "record.key.bytes_b64",
            VerifyingKeyDetailResponseJson("record.key.bytes_b64", ""),
            "empty bytes",
        };
    }

    [Theory]
    [MemberData(nameof(InvalidVerifyingKeyDetailResponses))]
    public async Task GetVerifyingKeyAsyncRejectsMalformedResponse(
        string expectedField,
        string json,
        string expectedMessage)
    {
        using var handler = new RecordingHandler(_ => JsonResponse(json));
        using var client = new ToriiClient(
            new Uri("https://torii.example"),
            new HttpClient(handler));

        var error = await Assert.ThrowsAsync<JsonException>(() =>
            client.GetVerifyingKeyAsync("pipa-r/pasta", "vk_main", cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains(expectedField, error.Message);
        Assert.Contains(expectedMessage, error.Message);
        Assert.Contains("/v1/zk/vk/pipa-r%2Fpasta/vk_main", handler.LastRequest!.RequestUri!.AbsoluteUri);
    }

    public static IEnumerable<object?[]> InvalidVerifyingKeyWriteResponses()
    {
        var nonCanonicalPayloadSigningBase64 =
            Convert.ToBase64String(IrohaHash.Hash(new byte[] { 1, 2, 3 }));
        foreach (var operation in new[] { "register", "update" })
        {
            object request = operation == "register"
                ? ValidVerifyingKeyRegisterRequest()
                : ValidVerifyingKeyUpdateRequest();
            var payload = CanonicalVerifyingKeyTransactionPayload(request);
            var payloadBase64 = Convert.ToBase64String(payload);
            var signingBase64 = Convert.ToBase64String(IrohaHash.Hash(payload));
            yield return new object?[]
            {
                operation,
                "verifying key " + operation,
                "[]",
                "must be an object",
            };
            yield return new object?[]
            {
                operation,
                "verifying key " + operation,
                "{}",
                "must contain exactly",
            };
            yield return new object?[]
            {
                operation,
                "submitted",
                $$"""{"submitted":true,"transaction_payload_b64":"{{payloadBase64}}","signing_message_b64":"{{signingBase64}}"}""",
                "must be false",
            };
            yield return new object?[]
            {
                operation,
                "submitted",
                $$"""{"submitted":"false","transaction_payload_b64":"{{payloadBase64}}","signing_message_b64":"{{signingBase64}}"}""",
                "must be false",
            };
            yield return new object?[]
            {
                operation,
                "transaction_payload_b64",
                $$"""{"submitted":false,"transaction_payload_b64":"AQI","signing_message_b64":"{{signingBase64}}"}""",
                "canonical",
            };
            yield return new object?[]
            {
                operation,
                "transaction_payload_b64",
                $$"""{"submitted":false,"transaction_payload_b64":"AQID","signing_message_b64":"{{nonCanonicalPayloadSigningBase64}}"}""",
                "canonical nine-field",
            };
            yield return new object?[]
            {
                operation,
                "signing_message_b64",
                $$"""{"submitted":false,"transaction_payload_b64":"{{payloadBase64}}","signing_message_b64":"{{Convert.ToBase64String(new byte[31])}}"}""",
                "exactly 32 bytes",
            };
            yield return new object?[]
            {
                operation,
                "signing_message_b64",
                $$"""{"submitted":false,"transaction_payload_b64":"{{payloadBase64}}","signing_message_b64":"{{Convert.ToBase64String(new byte[32])}}"}""",
                "exact Iroha prehash",
            };
            yield return new object?[]
            {
                operation,
                "verifying key " + operation,
                $$"""{"submitted":false,"transaction_payload_b64":"{{payloadBase64}}","signing_message_b64":"{{signingBase64}}","private_key":"retired"}""",
                "must contain exactly",
            };
            yield return new object?[]
            {
                operation,
                "submitted",
                $$"""{"submitted":false,"submitted":false,"transaction_payload_b64":"{{payloadBase64}}","signing_message_b64":"{{signingBase64}}"}""",
                "must not appear more than once",
            };
        }
    }

    [Theory]
    [MemberData(nameof(InvalidVerifyingKeyWriteResponses))]
    public async Task VerifyingKeyWriteResponsesRejectMalformedTransactionDraft(
        string operation,
        string expectedField,
        string json,
        string expectedMessage)
    {
        using var handler = new RecordingHandler(_ => JsonResponse(json));
        using var client = CreateVerifyingKeyClient(handler);

        var error = await Assert.ThrowsAsync<JsonException>(() =>
            InvokeVerifyingKeyWriteOperationAsync(
                client,
                operation,
                operation == "register"
                    ? ValidVerifyingKeyRegisterRequest()
                    : ValidVerifyingKeyUpdateRequest()));

        Assert.Contains(expectedField, error.Message);
        Assert.Contains(expectedMessage, error.Message);
        Assert.Equal($"/v1/zk/vk/{operation}", handler.LastRequest!.RequestUri!.AbsolutePath);
    }

    [Theory]
    [InlineData("register")]
    [InlineData("update")]
    public async Task VerifyingKeyWriteResponsesRequireHttp200(string operation)
    {
        using var handler = new RecordingHandler(_ =>
            JsonResponse(VerifyingKeyTransactionDraftResponseJson(), HttpStatusCode.Accepted));
        using var client = CreateVerifyingKeyClient(handler);

        var error = await Assert.ThrowsAsync<ToriiApiException>(() =>
            InvokeVerifyingKeyWriteOperationAsync(
                client,
                operation,
                operation == "register"
                    ? ValidVerifyingKeyRegisterRequest()
                    : ValidVerifyingKeyUpdateRequest()));

        Assert.Equal(HttpStatusCode.Accepted, error.StatusCode);
    }

    [Fact]
    public async Task VerifyingKeyWriteResponsesRejectDeclaredBodiesAboveLimit()
    {
        using var handler = new RecordingHandler(_ =>
        {
            var content = new ByteArrayContent("{}"u8.ToArray());
            content.Headers.ContentType = new("application/json");
            content.Headers.ContentLength = 24 * 1024 * 1024 + 1;
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        });
        using var client = CreateVerifyingKeyClient(handler);

        var error = await Assert.ThrowsAsync<InvalidDataException>(() =>
            client.RegisterVerifyingKeyAsync(
                ValidVerifyingKeyRegisterRequest(),
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains("25165824-byte limit", error.Message, StringComparison.Ordinal);
        Assert.Equal("/v1/zk/vk/register", handler.LastRequest!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task VerifyingKeyWritesRequireExactNetworkIdBeforeDispatch()
    {
        using var handler = new RecordingHandler(_ =>
            throw new InvalidOperationException("request must not be sent"));
        using var client = new ToriiClient(
            new Uri("https://torii.example"),
            new HttpClient(handler));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.RegisterVerifyingKeyAsync(
                ValidVerifyingKeyRegisterRequest(),
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains(nameof(ToriiClientOptions.NetworkId), error.Message);
        Assert.Null(handler.LastRequest);
        Assert.Throws<FormatException>(() => NetworkId.Parse(""));
        Assert.Throws<FormatException>(() => NetworkId.Parse("chain/other"));
    }

    [Fact]
    public async Task RegisterVerifyingKeyAsyncRejectsSemanticallySubstitutedDrafts()
    {
        var request = ValidVerifyingKeyRegisterRequest();
        var substitutions = new (string Label, byte[] Payload, string ExpectedMessage)[]
        {
            (
                "wrong operation",
                CanonicalVerifyingKeyTransactionPayload(
                    request,
                    wireNameOverride:
                        "iroha.instruction.v1::verifying_keys::UpdateVerifyingKey"),
                "requested verifying-key registry operation"
            ),
            (
                "wrong identifier",
                CanonicalVerifyingKeyTransactionPayload(
                    request,
                    idNameOverride: "vk_substituted"),
                "identifier does not match"
            ),
            (
                "wrong full record",
                CanonicalVerifyingKeyTransactionPayload(
                    request,
                    recordVersionOverride: 2),
                "full requested record"
            ),
            (
                "wrong network",
                CanonicalVerifyingKeyTransactionPayload(
                    request,
                    networkId: NetworkId.Parse(AlternateNetworkId)),
                "configured network"
            ),
            (
                "wrong authority",
                CanonicalVerifyingKeyTransactionPayload(
                    request,
                    authorityOverride: SoraFsAuthorityAccountId),
                "requested authority"
            ),
        };

        foreach (var substitution in substitutions)
        {
            using var handler = new RecordingHandler(_ =>
                JsonResponse(
                    VerifyingKeyTransactionDraftResponseJson(
                        request,
                        substitution.Payload)));
            using var client = CreateVerifyingKeyClient(handler);

            var error = await Assert.ThrowsAsync<JsonException>(() =>
                client.RegisterVerifyingKeyAsync(
                    request,
                    cancellationToken: TestContext.Current.CancellationToken));

            Assert.Contains(substitution.ExpectedMessage, error.Message);
        }
    }

    [Theory]
    [InlineData("register")]
    [InlineData("update")]
    public void VerifyingKeyRequestsRejectRetiredPrivateKeyFieldDuringDeserialization(string operation)
    {
        const string json = """{"authority":"alice","private_key":"must-not-be-accepted"}""";

        Assert.Throws<JsonException>(() =>
        {
            if (operation == "register")
            {
                _ = JsonSerializer.Deserialize<ToriiVerifyingKeyRegisterRequest>(json);
            }
            else
            {
                _ = JsonSerializer.Deserialize<ToriiVerifyingKeyUpdateRequest>(json);
            }
        });
    }

    public static IEnumerable<object?[]> InvalidVerifyingKeyWriteExactTextRequests()
    {
        var register = ValidVerifyingKeyRegisterRequest();
        var update = ValidVerifyingKeyUpdateRequest();

        foreach (var (request, paramName) in new (ToriiVerifyingKeyRegisterRequest Request, string ParamName)[]
        {
            (register with { Authority = " " + VerifyingKeyAuthorityAccountId }, "Authority"),
            (register with { Name = " vk_main" }, "Name"),
            (register with { CircuitId = "pipa-r/pasta/confidential-transfer v1" }, "CircuitId"),
            (register with { PublicInputsSchemaHashHex = "0x " + new string('a', 64) }, "PublicInputsSchemaHashHex"),
            (register with { Curve = " bn254" }, "Curve"),
            (register with { GasScheduleId = " native_default" }, "GasScheduleId"),
            (register with { MetadataUriCid = " bafymeta" }, "MetadataUriCid"),
            (register with { VerifyingKeyBytesCid = "bafyvk " }, "VerifyingKeyBytesCid"),
            (register with { CommitmentHex = register.CommitmentHex + " " }, "CommitmentHex"),
            (register with { Status = " active" }, "Status"),
        })
        {
            yield return new object?[] { "register", request, paramName, "whitespace" };
        }

        foreach (var request in new[]
        {
            register with { Authority = "merchant@sora" },
            register with { Authority = "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" },
            register with { Authority = "n753Xnﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛ" },
        })
        {
            yield return new object?[] { "register", request, "Authority", "canonical I105" };
        }

        foreach (var (request, paramName) in new (ToriiVerifyingKeyUpdateRequest Request, string ParamName)[]
        {
            (update with { Authority = VerifyingKeyAuthorityAccountId + " " }, "Authority"),
            (update with { Name = "vk_main " }, "Name"),
            (update with { CircuitId = "pipa-r/pasta/confidential-transfer v2" }, "CircuitId"),
            (update with { PublicInputsSchemaHashHex = "0x" + new string('b', 64) + " " }, "PublicInputsSchemaHashHex"),
            (update with { Curve = " bn254" }, "Curve"),
            (update with { GasScheduleId = "native_default " }, "GasScheduleId"),
            (update with { MetadataUriCid = "bafymeta " }, "MetadataUriCid"),
            (update with { VerifyingKeyBytesCid = " bafyvk" }, "VerifyingKeyBytesCid"),
            (update with { CommitmentHex = update.CommitmentHex + "\u0001" }, "CommitmentHex"),
            (update with { Status = "withdrawn " }, "Status"),
        })
        {
            var expectedMessage = paramName == "CommitmentHex" ? "control characters" : "whitespace";
            yield return new object?[] { "update", request, paramName, expectedMessage };
        }

        foreach (var request in new[]
        {
            update with { Authority = "merchant@sora" },
            update with { Authority = "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" },
            update with { Authority = "n753Xnﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛﾛ" },
        })
        {
            yield return new object?[] { "update", request, "Authority", "canonical I105" };
        }
    }

    [Theory]
    [MemberData(nameof(InvalidVerifyingKeyWriteExactTextRequests))]
    public async Task VerifyingKeyWriteRequestsRejectNonExactTextBeforeDispatch(
        string operation,
        object request,
        string expectedParamName,
        string expectedMessage)
    {
        using var handler = new RecordingHandler(_ =>
            throw new InvalidOperationException("malformed verifying-key request reached HTTP dispatch"));
        using var client = CreateVerifyingKeyClient(handler);

        var error = await Assert.ThrowsAnyAsync<ArgumentException>(() =>
            InvokeVerifyingKeyWriteOperationAsync(client, operation, request));

        Assert.Equal(expectedParamName, error.ParamName);
        Assert.Contains(expectedMessage, error.Message);
        Assert.Null(handler.LastRequest);
    }

    [Fact]
    public async Task VerifyingKeyRequestsRejectMalformedInputsBeforeRequest()
    {
        using var handler = new RecordingHandler(_ => throw new InvalidOperationException("request must not be sent"));
        using var client = CreateVerifyingKeyClient(handler);

        var valid = ValidVerifyingKeyRegisterRequest();
        ToriiVerifyingKeyRegisterRequest[] invalid =
        {
            valid with { Backend = "halo2/ipa" },
            valid with { Backend = " halo2/ipa" },
            valid with { Backend = " pipa-r/pasta" },
            valid with { Backend = "halo2/ipa/orchard" },
            valid with { Backend = "halo2/\u200Bipa" },
            valid with { Name = "vk:main" },
            valid with { Name = " " },
            valid with { Version = 0 },
            valid with { PublicInputsSchemaHashHex = "abc123" },
            valid with { GasScheduleId = "" },
            valid with { VerifyingKeyBytes = Array.Empty<byte>() },
            valid with { VerifyingKeyLength = 99 },
            valid with { MaxProofBytes = 0 },
            valid with { VerifyingKeyBytes = null, VerifyingKeyLength = 3, CommitmentHex = null },
            valid with { ActivationHeight = 10, WithdrawHeight = 9 },
            valid with { Status = "production-ready" },
        };

        foreach (var request in invalid)
        {
            await Assert.ThrowsAnyAsync<ArgumentException>(() => client.RegisterVerifyingKeyAsync(request, cancellationToken: TestContext.Current.CancellationToken));
            Assert.Null(handler.LastRequest);
        }

        foreach (var backend in new[] { "halo2/ipa", "halo2/ipa ", "pipa-r/pasta ", "halo2\uFF0Fipa", "mock/dev" })
        {
            await Assert.ThrowsAnyAsync<ArgumentException>(() => client.GetVerifyingKeyAsync(backend, "vk_main", cancellationToken: TestContext.Current.CancellationToken));
            Assert.Null(handler.LastRequest);
        }

        await Assert.ThrowsAnyAsync<ArgumentException>(() => client.GetVerifyingKeyAsync("pipa-r/pasta", " vk_main", cancellationToken: TestContext.Current.CancellationToken));
        Assert.Null(handler.LastRequest);

        await Assert.ThrowsAnyAsync<ArgumentException>(() =>
            client.UpdateVerifyingKeyAsync(new ToriiVerifyingKeyUpdateRequest
            {
                Authority = VerifyingKeyAuthorityAccountId,
                Backend = "pipa-r/pasta",
                Name = "vk_main",
                Version = 2,
                CircuitId = "pipa-r/pasta/confidential-transfer-v1",
                PublicInputsSchemaHashHex = new string('b', 64),
                MaxProofBytes = 0,
                CommitmentHex = new string('c', 64),
            }, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Null(handler.LastRequest);

        await Assert.ThrowsAnyAsync<ArgumentException>(() =>
            client.UpdateVerifyingKeyAsync(new ToriiVerifyingKeyUpdateRequest
            {
                Authority = VerifyingKeyAuthorityAccountId,
                Backend = "pipa-r/pasta",
                Name = "vk_main",
                Version = 2,
                CircuitId = "pipa-r/pasta/confidential-transfer-v1",
                PublicInputsSchemaHashHex = new string('b', 64),
                ActivationHeight = 10,
                WithdrawHeight = 9,
            }, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Null(handler.LastRequest);

    }

}
