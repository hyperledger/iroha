using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Hyperledger.Iroha.Torii;

namespace Hyperledger.Iroha.Sdk.Tests;

public sealed class ToriiIdentifierReceiptTests
{
    [Theory]
    [InlineData("hkdf-sha3-512-prf-v1")]
    [InlineData("bfv-affine-v1")]
    [InlineData("bfv-programmed-v1")]
    public void IdentifierPolicyAcceptsOnlyCurrentBackendTags(string backend)
    {
        var policy = ValidIdentifierPolicySummary();
        policy["backend"] = backend;
        var decoded = JsonSerializer.Deserialize<ToriiIdentifierPolicySummary>(policy.ToJsonString())!;
        Assert.Equal(backend, decoded.Backend);
        Assert.Equal(backend, JsonSerializer.Deserialize<ToriiIdentifierPolicySummary>(
            JsonSerializer.Serialize(decoded))!.Backend);
    }

    [Theory]
    [InlineData("bfv-affine-sha3-256-v1")]
    [InlineData("bfv-programmed-sha3-256-v1")]
    [InlineData("unknown")]
    [InlineData("BFV-PROGRAMMED-V1")]
    [InlineData(" bfv-programmed-v1")]
    [InlineData("bfv-programmed-v1 ")]
    public void IdentifierPolicyRejectsRetiredOrUnknownBackendTagsOnReadAndWrite(string backend)
    {
        var policy = ValidIdentifierPolicySummary();
        var valid = JsonSerializer.Deserialize<ToriiIdentifierPolicySummary>(policy.ToJsonString())!;
        policy["backend"] = backend;
        var readError = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<ToriiIdentifierPolicySummary>(policy.ToJsonString()));
        Assert.Contains("backend", readError.Message);
        var writeError = Assert.Throws<JsonException>(() =>
            JsonSerializer.Serialize(valid with { Backend = backend }));
        Assert.Contains("backend", writeError.Message);
    }

    [Theory]
    [InlineData("hkdf-sha3-512-prf-v1", "signed")]
    [InlineData("hkdf-sha3-512-prf-v1", "proof")]
    [InlineData("bfv-affine-v1", "signed")]
    [InlineData("bfv-affine-v1", "proof")]
    [InlineData("bfv-programmed-v1", "signed")]
    [InlineData("bfv-programmed-v1", "proof")]
    public void IdentifierReceiptAcceptsCurrentBackendAndModeTags(string backend, string mode)
    {
        var receipt = ValidIdentifierResolveResponse();
        SetNestedString(receipt, "payload.execution.backend", backend);
        SetNestedString(receipt, "payload.execution.verification_mode", mode);
        var decoded = JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(receipt.ToJsonString())!;
        Assert.Equal(backend, decoded.Backend);
        var roundTrip = JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(JsonSerializer.Serialize(decoded))!;
        Assert.Equal(backend, roundTrip.Backend);
        Assert.Equal(mode, roundTrip.SignaturePayload!["payload"]!["execution"]!["verification_mode"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("backend", "bfv-affine-sha3-256-v1")]
    [InlineData("backend", "bfv-programmed-sha3-256-v1")]
    [InlineData("backend", "unknown")]
    [InlineData("backend", "BFV-PROGRAMMED-V1")]
    [InlineData("backend", " bfv-programmed-v1")]
    [InlineData("backend", "bfv-programmed-v1 ")]
    [InlineData("verification_mode", "unknown")]
    [InlineData("verification_mode", "signed-v1")]
    [InlineData("verification_mode", "Signed")]
    [InlineData("verification_mode", " signed")]
    [InlineData("verification_mode", "signed ")]
    public void IdentifierReceiptRejectsInvalidBackendAndModeTagsOnReadAndWrite(string field, string value)
    {
        var receipt = ValidIdentifierResolveResponse();
        var valid = JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(receipt.ToJsonString())!;
        SetNestedString(receipt, $"payload.execution.{field}", value);
        var readError = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(receipt.ToJsonString()));
        Assert.Contains($"payload.execution.{field}", readError.Message);
        var writeError = Assert.Throws<JsonException>(() =>
            JsonSerializer.Serialize(valid with { SignaturePayload = receipt }));
        Assert.Contains($"payload.execution.{field}", writeError.Message);
    }

    [Theory]
    [InlineData("backend")]
    [InlineData("verification_mode")]
    public void IdentifierReceiptRequiresBackendAndMode(string field)
    {
        foreach (var remove in new[] { false, true })
        {
            var receipt = ValidIdentifierResolveResponse();
            var execution = receipt["payload"]!["execution"]!.AsObject();
            if (remove)
            {
                execution.Remove(field);
            }
            else
            {
                execution[field] = null;
            }

            var error = Assert.Throws<JsonException>(() =>
                JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(receipt.ToJsonString()));
            Assert.Contains($"payload.execution.{field}", error.Message);
        }
    }

    [Fact]
    public async Task ResolveIdentifierAsyncRejectsPaddedPolicyIdBeforePost()
    {
        var called = false;
        using var handler = new RecordingHandler(_ =>
        {
            called = true;
            return new HttpResponseMessage(HttpStatusCode.OK);
        });

        using var client = ToriiIdentifierResolutionAuthenticationTests.AuthenticatedClient(handler);
        var error = await Assert.ThrowsAsync<ArgumentException>(() => client.ResolveIdentifierAsync(
            new ToriiIdentifierResolveRequest
            {
                PolicyId = " phone#retail ",
                EncryptedInput = IdentifierRequestFixtures.Ciphertext,
                OutputOpening = IdentifierRequestFixtures.Opening(),
            }, cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains("PolicyId", error.Message);
        Assert.Contains("surrounding whitespace", error.Message);
        Assert.False(called);
    }

    [Theory]
    [InlineData("payload.policy_id", " phone#retail ")]
    [InlineData("payload.opaque_id", " opaque-1 ")]
    [InlineData("payload.receipt_hash", " receipt-1 ")]
    [InlineData("payload.uaid", " uaid:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef ")]
    [InlineData("payload.account_id", " sorauﾛ1NｱｻｸYSafﾇｷヰc5ﾇﾄVxﾏ9jLZヱﾋzsKqurﾊﾘ9ｸ3eｴAｶD54TDT ")]
    [InlineData("payload.execution.backend", " bfv-programmed-v1 ")]
    [InlineData("attestation.signature", " ABCD ")]
    public void IdentifierResolveResponseRejectsPaddedReceiptFields(string field, string value)
    {
        var receipt = ValidIdentifierResolveResponse();
        SetNestedString(receipt, field, value);

        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(receipt.ToJsonString()));

        Assert.Contains(field, error.Message);
        Assert.Contains("surrounding whitespace", error.Message);
    }

    [Theory]
    [InlineData("payload.policy_id", "phone#ret ail")]
    [InlineData("payload.opaque_id", "opaque 1")]
    [InlineData("payload.receipt_hash", "receipt 1")]
    [InlineData("payload.uaid", "uaid:0123456789abcdef0123456789abcdef 0123456789abcdef0123456789abcdef")]
    [InlineData("payload.account_id", "sorauﾛ1N merchant")]
    [InlineData("payload.execution.backend", "bfv programmed-sha3-256-v1")]
    [InlineData("attestation.signature", "AB CD")]
    public void IdentifierResolveResponseRejectsInternalWhitespaceReceiptFields(string field, string value)
    {
        var receipt = ValidIdentifierResolveResponse();
        SetNestedString(receipt, field, value);

        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(receipt.ToJsonString()));

        Assert.Contains(field, error.Message);
        Assert.Contains("whitespace", error.Message);
    }

    [Theory]
    [InlineData("attestation.signature", "ABC")]
    [InlineData("attestation.signature", "ABCG")]
    [InlineData("attestation.signature", "0XABCD")]
    public void IdentifierResolveResponseRejectsMalformedSignatureHexFields(string field, string value)
    {
        var receipt = ValidIdentifierResolveResponse();
        SetNestedString(receipt, field, value);

        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(receipt.ToJsonString()));

        Assert.Contains(field, error.Message);
        Assert.Contains("exact hex string", error.Message);
    }

    [Theory]
    [InlineData("""{"payload":{"policy_id":"phone#ret ail"}}""", "payload.policy_id", "whitespace")]
    [InlineData("""{"payload":{"policy_id":" phone#retail"}}""", "payload.policy_id", "whitespace")]
    [InlineData("""{"payload":{"account_id":"sorauﾛ1Nmer chant"}}""", "payload.account_id", "whitespace")]
    [InlineData("""{"payload":{"execution":{"executed_at_ms":"01710000000000"}}}""", "payload.execution.executed_at_ms", "canonical unsigned decimal")]
    [InlineData("""{"payload":{"execution":{"executed_at_ms":0}}}""", "payload.execution.executed_at_ms", "positive")]
    [InlineData("""{"payload":{"execution":{"expires_at_ms":-1}}}""", "payload.execution.expires_at_ms", "non-negative")]
    [InlineData("""{"payload":{"execution":{"expires_at_ms":0}}}""", "payload.execution.expires_at_ms", "positive")]
    [InlineData("""{"payload":{"opening":{"signature":"0XABCD"}}}""", "payload.opening.signature", "exact hex string")]
    [InlineData("""{"payload":{"opening":{"payload":{"opened_at_ms":"1710000 000000"}}}}""", "payload.opening.payload.opened_at_ms", "whitespace")]
    [InlineData("""{"payload":{"opening":{"payload":{"opened_at_ms":0}}}}""", "payload.opening.payload.opened_at_ms", "positive")]
    [InlineData("""{"payload":{"opening":{"payload":{"expires_at_ms":0}}}}""", "payload.opening.payload.expires_at_ms", "positive")]
    [InlineData("""{"attestation":{"kind":"Signed","signature":"ABCD"}}""", "attestation.kind", "signed or proof")]
    [InlineData("""{"attestation":{"kind":"signed","signature":"0XABCD"}}""", "attestation.signature", "exact hex string")]
    [InlineData("""{"attestation":{"kind":"signed","proof_b64":"AQID"}}""", "attestation signed attestations", "proof fields")]
    [InlineData("""{"attestation":{"kind":"proof","proof_backend":"pipa-r/pasta","proof_b64":"@@@"}}""", "attestation.proof_b64", "valid base64")]
    [InlineData("""{"attestation":{"kind":"proof","proof_b64":"AQID"}}""", "attestation.proof_backend", "required")]
    public void IdentifierResolveResponseRejectsMalformedNestedEnvelopePatch(
        string patchJson,
        string expectedField,
        string expectedReason)
    {
        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(
                NestedIdentifierResolveResponseWithPatch(patchJson)));

        Assert.Contains(expectedField, error.Message);
        Assert.Contains(expectedReason, error.Message);
    }

    [Theory]
    [InlineData("payload.execution.executed_at_ms", -1L, "non-negative")]
    [InlineData("payload.execution.expires_at_ms", -1L, "non-negative")]
    [InlineData("payload.execution.executed_at_ms", 0L, "positive")]
    [InlineData("payload.execution.expires_at_ms", 0L, "positive")]
    public void IdentifierResolveResponseRejectsNegativeReceiptTimes(
        string field,
        long value,
        string expectedReason)
    {
        var receipt = ValidIdentifierResolveResponse();
        SetNestedNumber(receipt, field, value);

        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(receipt.ToJsonString()));

        Assert.Contains(field, error.Message);
        Assert.Contains(expectedReason, error.Message);
    }

    [Theory]
    [InlineData("resolved_at_ms", -1L)]
    [InlineData("resolved_at_ms", 0L)]
    [InlineData("expires_at_ms", -1L)]
    [InlineData("expires_at_ms", 0L)]
    public void IdentifierResolveResponseWriteRejectsNonPositiveReceiptTimes(string field, long value)
    {
        var valid = JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(
            ValidIdentifierResolveResponse().ToJsonString())!;
        var response = field switch
        {
            "resolved_at_ms" => valid with { ResolvedAtMilliseconds = value },
            "expires_at_ms" => valid with { ExpiresAtMilliseconds = value },
            _ => throw new ArgumentOutOfRangeException(nameof(field), field, "Unknown receipt time field."),
        };

        var error = Assert.Throws<JsonException>(() => JsonSerializer.Serialize(response));

        Assert.Contains(field, error.Message);
        Assert.Contains("positive", error.Message);
    }

    [Theory]
    [InlineData("policy_id", "PolicyId", "payload.policy_id")]
    [InlineData("opaque_id", "OpaqueId", "payload.opaque_id")]
    [InlineData("receipt_hash", "ReceiptHash", "payload.receipt_hash")]
    [InlineData("uaid", "Uaid", "payload.uaid")]
    [InlineData("account_id", "AccountId", "payload.account_id")]
    [InlineData("resolved_at_ms", "ResolvedAtMilliseconds", "payload.execution.executed_at_ms")]
    [InlineData("expires_at_ms", "ExpiresAtMilliseconds", "payload.execution.expires_at_ms")]
    [InlineData("backend", "Backend", "payload.execution.backend")]
    [InlineData("signature", "Signature", "attestation.signature")]
    public void IdentifierResolveResponseWriteRejectsEnvelopeFieldMismatches(
        string field,
        string expectedProperty,
        string expectedEnvelopeField)
    {
        var valid = JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(
            ValidIdentifierResolveResponse().ToJsonString())!;
        var response = field switch
        {
            "policy_id" => valid with { PolicyId = "email#retail" },
            "opaque_id" => valid with { OpaqueId = "opaque-2" },
            "receipt_hash" => valid with { ReceiptHash = "receipt-2" },
            "uaid" => valid with { Uaid = "uaid:1111111111111111111111111111111111111111111111111111111111111111" },
            "account_id" => valid with { AccountId = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV" },
            "resolved_at_ms" => valid with { ResolvedAtMilliseconds = 1710000000001L },
            "expires_at_ms" => valid with { ExpiresAtMilliseconds = 1710003600001L },
            "backend" => valid with { Backend = "bfv-programmed-sha3-256-v2" },
            "signature" => valid with { Signature = "BEEF" },
            _ => throw new ArgumentOutOfRangeException(nameof(field), field, "Unknown receipt field."),
        };

        var error = Assert.Throws<JsonException>(() => JsonSerializer.Serialize(response));

        Assert.Contains(expectedProperty, error.Message);
        Assert.Contains(expectedEnvelopeField, error.Message);
        Assert.Contains("must match", error.Message);
    }

    [Fact]
    public void IdentifierResolveResponseWriteRejectsSignaturePayloadHex()
    {
        var valid = JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(
            ValidIdentifierResolveResponse().ToJsonString())!;
        var response = valid with { SignaturePayloadHex = "ABCD" };

        var error = Assert.Throws<JsonException>(() => JsonSerializer.Serialize(response));

        Assert.Contains("signature_payload_hex", error.Message);
        Assert.Contains("must be empty", error.Message);
    }

    [Fact]
    public void IdentifierResolveResponseWritePreservesNestedReceiptEnvelope()
    {
        var valid = JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(
            ValidIdentifierResolveResponse().ToJsonString())!;

        var serialized = JsonSerializer.Serialize(valid);
        var receipt = JsonNode.Parse(serialized)!.AsObject();

        Assert.False(receipt.ContainsKey("policy_id"));
        Assert.Equal("phone#retail", receipt["payload"]!["policy_id"]!.GetValue<string>());
        Assert.Equal("ABCD", receipt["attestation"]!["signature"]!.GetValue<string>());
    }

    [Fact]
    public void IdentifierResolveResponseDeserializesNestedReceiptEnvelope()
    {
        var receipt = JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(
            NestedIdentifierResolveResponse("""{"kind":"signed","signature":"ABCD"}"""));

        Assert.NotNull(receipt);
        Assert.Equal("phone#retail", receipt.PolicyId);
        Assert.Equal("opaque-1", receipt.OpaqueId);
        Assert.Equal("receipt-1", receipt.ReceiptHash);
        Assert.Equal("sorauﾛ1NｱｻｸYSafﾇｷヰc5ﾇﾄVxﾏ9jLZヱﾋzsKqurﾊﾘ9ｸ3eｴAｶD54TDT", receipt.AccountId);
        Assert.Equal(1710000000000L, receipt.ResolvedAtMilliseconds);
        Assert.Equal(1710003600000L, receipt.ExpiresAtMilliseconds);
        Assert.Equal("bfv-programmed-v1", receipt.Backend);
        Assert.Equal("ABCD", receipt.Signature);
        Assert.Equal(string.Empty, receipt.SignaturePayloadHex);
        Assert.Equal("signed", receipt.SignaturePayload!["attestation"]!["kind"]!.GetValue<string>());
    }

    [Fact]
    public void IdentifierResolveResponseDeserializesNestedProofReceiptEnvelope()
    {
        var receipt = JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(
            NestedIdentifierResolveResponse("""{"kind":"proof","proof_backend":"pipa-r/pasta","proof_b64":"AQID"}"""));

        Assert.NotNull(receipt);
        Assert.Equal("phone#retail", receipt.PolicyId);
        Assert.Equal(string.Empty, receipt.Signature);
        Assert.Equal(string.Empty, receipt.SignaturePayloadHex);
        Assert.Equal("proof", receipt.SignaturePayload!["attestation"]!["kind"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("""{"kind":" signed","signature":"ABCD"}""", "attestation.kind", "whitespace")]
    [InlineData("""{"kind":"sig ned","signature":"ABCD"}""", "attestation.kind", "whitespace")]
    [InlineData("""{"kind":"signed\u0001","signature":"ABCD"}""", "attestation.kind", "control")]
    [InlineData("""{"kind":"Signed","signature":"ABCD"}""", "attestation.kind", "signed or proof")]
    [InlineData("""{"kind":"signed","signature":"ABCD","proof_b64":"AQID"}""", "signed attestations", "proof fields")]
    [InlineData("""{"kind":"signed","signature":"AB CD"}""", "attestation.signature", "whitespace")]
    [InlineData("""{"kind":"signed","signature":"ABC"}""", "attestation.signature", "exact hex string")]
    [InlineData("""{"kind":"signed","signature":"ABCG"}""", "attestation.signature", "exact hex string")]
    [InlineData("""{"kind":"signed","signature":"0XABCD"}""", "attestation.signature", "exact hex string")]
    [InlineData("""{"kind":"proof","proof_b64":"AQID"}""", "attestation.proof_backend", "required")]
    [InlineData("""{"kind":"proof","proof_backend":"pipa-r/pasta"}""", "attestation.proof_b64", "required")]
    [InlineData("""{"kind":"proof","proof_backend":"pipa-r/pasta","proof_b64":"AQID","signature":"ABCD"}""", "proof attestations", "signature")]
    [InlineData("""{"kind":"proof","proof_backend":"pipa-r /pasta","proof_b64":"AQID"}""", "attestation.proof_backend", "whitespace")]
    [InlineData("""{"kind":"proof","proof_backend":"pipa-r/pasta","proof_b64":"@@@"}""", "attestation.proof_b64", "valid base64")]
    [InlineData("""{"kind":"proof","proof_backend":"pipa-r/pasta","proof_b64":"AR=="}""", "attestation.proof_b64", "canonical base64")]
    [InlineData("""{"kind":"proof","proof_backend":"pipa-r/pasta","proof_b64":" AQID"}""", "attestation.proof_b64", "whitespace")]
    [InlineData("""{"kind":"proof","proof_backend":"pipa-r/pasta","proof_b64":"AQ ID"}""", "attestation.proof_b64", "whitespace")]
    [InlineData("""{"kind":"proof","proof_backend":"pipa-r/pasta","proof_b64":""}""", "attestation.proof_b64", "empty")]
    public void IdentifierResolveResponseRejectsMalformedNestedAttestation(
        string attestationJson,
        string expectedField,
        string expectedReason)
    {
        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(
                NestedIdentifierResolveResponse(attestationJson)));

        Assert.Contains(expectedField, error.Message);
        Assert.Contains(expectedReason, error.Message);
    }

    [Theory]
    [InlineData("""{"payload": {"policy_id":"phone#retail"}}""", "attestation", "required")]
    [InlineData("""{"attestation": {"kind":"signed","signature":"ABCD"}}""", "payload", "required")]
    public void IdentifierResolveResponseRejectsIncompleteNestedEnvelope(
        string responseJson,
        string expectedField,
        string expectedReason)
    {
        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(responseJson));

        Assert.Contains(expectedField, error.Message);
        Assert.Contains(expectedReason, error.Message);
    }

    [Theory]
    [InlineData("policy_id")]
    [InlineData("opaque_id")]
    [InlineData("receipt_hash")]
    [InlineData("uaid")]
    [InlineData("account_id")]
    [InlineData("resolved_at_ms")]
    [InlineData("expires_at_ms")]
    [InlineData("backend")]
    [InlineData("signature")]
    [InlineData("signature_payload_hex")]
    [InlineData("signature_payload")]
    public void IdentifierResolveResponseRejectsRetiredFlatReceiptFields(string field)
    {
        var receipt = ValidIdentifierResolveResponse();
        if (field.EndsWith("_ms", StringComparison.Ordinal))
        {
            receipt[field] = 1710000000000L;
        }
        else
        {
            receipt[field] = "retired";
        }

        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(receipt.ToJsonString()));

        Assert.Contains(field, error.Message);
        Assert.Contains("current payload/attestation envelope", error.Message);
    }

    public static IEnumerable<object[]> DuplicateIdentifierResolveResponseJson()
    {
        yield return new object[]
        {
            NestedIdentifierResolveResponse(
                """{"kind":"signed","signature":"ABCD"}""",
                NestedIdentifierPayloadDuplicateExecutionBackendJson()),
            "identifier resolve response.payload.execution.backend",
        };
        yield return new object[]
        {
            NestedIdentifierResolveResponse(
                """{"kind":"signed","kind":"signed","signature":"ABCD"}"""),
            "identifier resolve response.attestation.kind",
        };
    }

    [Theory]
    [MemberData(nameof(DuplicateIdentifierResolveResponseJson))]
    public async Task ResolveIdentifierAsyncRejectsDuplicateReceiptPayloadProperties(
        string responseJson,
        string expectedField)
    {
        using var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(responseJson),
        });
        using var client = ToriiIdentifierResolutionAuthenticationTests.AuthenticatedClient(handler);

        var error = await Assert.ThrowsAsync<JsonException>(() => client.ResolveIdentifierAsync(
            new ToriiIdentifierResolveRequest
            {
                PolicyId = "phone#retail",
                EncryptedInput = IdentifierRequestFixtures.Ciphertext,
                OutputOpening = IdentifierRequestFixtures.Opening(),
            }, cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains(expectedField, error.Message);
        Assert.Contains("must not appear more than once", error.Message);
    }

    [Theory]
    [InlineData("execution.executed_at_ms", "-1", "executed_at_ms", "non-negative")]
    [InlineData("execution.executed_at_ms", "0", "executed_at_ms", "positive")]
    [InlineData("execution.expires_at_ms", "\" 1710003600000\"", "expires_at_ms", "whitespace")]
    [InlineData("execution.expires_at_ms", "\"1710003 600000\"", "expires_at_ms", "whitespace")]
    [InlineData("execution.expires_at_ms", "0", "expires_at_ms", "positive")]
    [InlineData("execution.executed_at_ms", "\"01710000000000\"", "executed_at_ms", "canonical unsigned decimal")]
    [InlineData("opening.payload.opened_at_ms", "\"1710000000000\\u0001\"", "opened_at_ms", "control")]
    [InlineData("opening.payload.opened_at_ms", "\"1710000000\\u00A0000\"", "opened_at_ms", "whitespace")]
    [InlineData("opening.payload.opened_at_ms", "0", "opened_at_ms", "positive")]
    [InlineData("opening.payload.expires_at_ms", "\"01710003600000\"", "expires_at_ms", "canonical unsigned decimal")]
    [InlineData("opening.payload.expires_at_ms", "1710003600000.5", "expires_at_ms", "integer")]
    [InlineData("opening.payload.expires_at_ms", "0", "expires_at_ms", "positive")]
    public void IdentifierResolveResponseRejectsMalformedNestedTimestamps(
        string fieldPath,
        string valueJson,
        string expectedField,
        string expectedReason)
    {
        var payload = fieldPath switch
        {
            "execution.executed_at_ms" => NestedIdentifierPayloadJson(executionExecutedAtJson: valueJson),
            "execution.expires_at_ms" => NestedIdentifierPayloadJson(executionExpiresAtJson: valueJson),
            "opening.payload.opened_at_ms" => NestedIdentifierPayloadJson(openingOpenedAtJson: valueJson),
            "opening.payload.expires_at_ms" => NestedIdentifierPayloadJson(openingExpiresAtJson: valueJson),
            _ => throw new InvalidOperationException("unknown timestamp fixture field"),
        };

        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(
                NestedIdentifierResolveResponse(
                    """{"kind":"signed","signature":"ABCD"}""",
                    payload)));

        Assert.Contains(expectedField, error.Message);
        Assert.Contains(expectedReason, error.Message);
    }

    [Theory]
    [InlineData("policy_id", "phone#ret ail", "payload.policy_id")]
    [InlineData("account_id", "sorauﾛ1N merchant", "payload.account_id")]
    [InlineData("opaque_id", "opaque 1", "payload.opaque_id")]
    [InlineData("receipt_hash", "receipt 1", "payload.receipt_hash")]
    [InlineData("uaid", "uaid:0123456789abcdef0123456789abcdef 0123456789abcdef0123456789abcdef", "payload.uaid")]
    [InlineData("execution.program_id", "identifier lookup retail", "payload.execution.program_id")]
    [InlineData("execution.program_digest", "program digest", "payload.execution.program_digest")]
    [InlineData("execution.backend", "bfv programmed-sha3-256-v1", "payload.execution.backend")]
    [InlineData("execution.verification_mode", "sig ned", "payload.execution.verification_mode")]
    [InlineData("execution.input_ciphertext_hash", "input hash", "payload.execution.input_ciphertext_hash")]
    [InlineData("execution.output_ciphertext_hash", "output hash", "payload.execution.output_ciphertext_hash")]
    [InlineData("execution.parameter_digest", "parameter digest", "payload.execution.parameter_digest")]
    [InlineData("execution.evaluation_key_digest", "evaluation key digest", "payload.execution.evaluation_key_digest")]
    [InlineData("execution.output_hash", "output open hash", "payload.execution.output_hash")]
    [InlineData("execution.associated_data_hash", "associated data hash", "payload.execution.associated_data_hash")]
    [InlineData("opening.signature", "AB CD", "payload.opening.signature")]
    [InlineData("opening.payload.program_id", "identifier lookup retail", "payload.opening.payload.program_id")]
    [InlineData("opening.payload.input_ciphertext_hash", "input hash", "payload.opening.payload.input_ciphertext_hash")]
    [InlineData("opening.payload.output_ciphertext_hash", "output hash", "payload.opening.payload.output_ciphertext_hash")]
    [InlineData("opening.payload.parameter_digest", "parameter digest", "payload.opening.payload.parameter_digest")]
    [InlineData("opening.payload.evaluation_key_digest", "evaluation key digest", "payload.opening.payload.evaluation_key_digest")]
    [InlineData("opening.payload.opened_output_hash", "opened output hash", "payload.opening.payload.opened_output_hash")]
    public void IdentifierResolveResponseRejectsInternalWhitespaceNestedPayloadFields(
        string fieldPath,
        string value,
        string expectedField)
    {
        var payload = JsonNode.Parse(NestedIdentifierPayloadJson())!.AsObject();
        SetNestedString(payload, fieldPath, value);

        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(
                NestedIdentifierResolveResponse(
                    """{"kind":"signed","signature":"ABCD"}""",
                    payload.ToJsonString())));

        Assert.Contains(expectedField, error.Message);
        Assert.Contains("whitespace", error.Message);
    }

    [Theory]
    [InlineData("ABC")]
    [InlineData("ABCG")]
    [InlineData("0XABCD")]
    public void IdentifierResolveResponseRejectsMalformedNestedOpeningSignatureHex(string signature)
    {
        var payload = JsonNode.Parse(NestedIdentifierPayloadJson())!.AsObject();
        SetNestedString(payload, "opening.signature", signature);

        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(
                NestedIdentifierResolveResponse(
                    """{"kind":"signed","signature":"ABCD"}""",
                    payload.ToJsonString())));

        Assert.Contains("payload.opening.signature", error.Message);
        Assert.Contains("exact hex string", error.Message);
    }

    [Theory]
    [InlineData("policy_id", " phone#retail ")]
    [InlineData("owner", " sorauﾛ1NｱｻｸYSafﾇｷヰc5ﾇﾄVxﾏ9jLZヱﾋzsKqurﾊﾘ9ｸ3eｴAｶD54TDT ")]
    [InlineData("normalization", " phone_e164 ")]
    [InlineData("resolver_public_key", " ed25519:0123456789abcdef ")]
    [InlineData("backend", " bfv-programmed-v1 ")]
    [InlineData("input_encryption", " bfv-v1 ")]
    [InlineData("input_encryption_public_parameters", " params-b64 ")]
    public void IdentifierPolicySummaryRejectsPaddedProofMetadata(string field, string value)
    {
        var policy = ValidIdentifierPolicySummary();
        policy[field] = value;

        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierPolicySummary>(policy.ToJsonString()));

        Assert.Contains(field, error.Message);
        Assert.Contains("surrounding whitespace", error.Message);
    }

    [Theory]
    [InlineData("policy_id", "phone#ret ail")]
    [InlineData("owner", "sorauﾛ1N issuer")]
    [InlineData("normalization", "phone e164")]
    [InlineData("resolver_public_key", "ed25519:0123 4567")]
    [InlineData("backend", "bfv programmed-sha3-256-v1")]
    [InlineData("input_encryption", "bfv v1")]
    [InlineData("input_encryption_public_parameters", "params b64")]
    public void IdentifierPolicySummaryRejectsInternalWhitespaceProofMetadata(string field, string value)
    {
        var policy = ValidIdentifierPolicySummary();
        policy[field] = value;

        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierPolicySummary>(policy.ToJsonString()));

        Assert.Contains(field, error.Message);
        Assert.Contains("whitespace", error.Message);
    }

    [Fact]
    public void IdentifierPolicySummaryRejectsDuplicateDecodedParameterProperties()
    {
        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierPolicySummary>(
                IdentifierPolicySummaryDuplicateDecodedParametersJson()));

        Assert.Contains("policy.input_encryption_public_parameters_decoded.modulus", error.Message);
        Assert.Contains("must not appear more than once", error.Message);
    }

    [Fact]
    public void IdentifierPolicySummaryRejectsDuplicatePropertiesInsideIgnoredExtension()
    {
        var json = ValidIdentifierPolicySummary()
            .ToJsonString();
        json = json.Insert(json.Length - 1, ""","audit":{"nonce":1,"nonce":2}""");

        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierPolicySummary>(json));

        Assert.Contains("policy.audit.nonce", error.Message);
        Assert.Contains("must not appear more than once", error.Message);
    }

    [Fact]
    public void IdentifierPoliciesResponseRejectsDuplicatePropertiesInsideIgnoredExtension()
    {
        const string json = """{"total":0,"items":[],"audit":{"page":1,"page":2}}""";

        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierPoliciesResponse>(json));

        Assert.Contains("identifier policies response.audit.page", error.Message);
        Assert.Contains("must not appear more than once", error.Message);
    }

    [Fact]
    public void IdentifierResolveResponseRejectsUnknownTopLevelExtension()
    {
        var json = ValidIdentifierResolveResponse()
            .ToJsonString();
        json = json.Insert(json.Length - 1, ""","audit":{"nonce":1}""");

        var error = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ToriiIdentifierResolveResponse>(json));

        Assert.Contains("identifier receipt.audit", error.Message);
        Assert.Contains("current payload/attestation envelope", error.Message);
    }

    private static JsonObject ValidIdentifierResolveResponse()
    {
        return JsonNode.Parse(NestedIdentifierResolveResponse("""{"kind":"signed","signature":"ABCD"}"""))!.AsObject();
    }

    private static string NestedIdentifierResolveResponseWithPatch(string patchJson)
    {
        var envelope = ValidIdentifierResolveResponse();
        var patch = JsonNode.Parse(patchJson)!.AsObject();
        MergeObjectPatch(envelope, patch);
        return envelope.ToJsonString();
    }

    private static JsonObject ValidIdentifierPolicySummary()
    {
        return new JsonObject
        {
            ["policy_id"] = "phone#retail",
            ["owner"] = "sorauﾛ1NｱｻｸYSafﾇｷヰc5ﾇﾄVxﾏ9jLZヱﾋzsKqurﾊﾘ9ｸ3eｴAｶD54TDT",
            ["active"] = true,
            ["normalization"] = "phone_e164",
            ["program_id"] = "identifier_lookup_retail",
            ["output_opening_public_key"] = "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
            ["resolver_public_key"] = "ed25519:0123456789abcdef",
            ["backend"] = "bfv-programmed-v1",
            ["input_encryption"] = "bfv-v1",
            ["input_encryption_public_parameters"] = "params-b64",
            ["input_encryption_public_parameters_decoded"] = null,
            ["ram_fhe_profile"] = null,
            ["note"] = "retail policy",
        };
    }

    private static string IdentifierPolicySummaryDuplicateDecodedParametersJson()
    {
        return """
            {
              "policy_id": "phone#retail",
              "owner": "sorauﾛ1NｱｻｸYSafﾇｷヰc5ﾇﾄVxﾏ9jLZヱﾋzsKqurﾊﾘ9ｸ3eｴAｶD54TDT",
              "active": true,
              "normalization": "phone_e164",
              "program_id": "identifier_lookup_retail",
              "output_opening_public_key": "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
              "resolver_public_key": "ed25519:0123456789abcdef",
              "backend": "bfv-programmed-v1",
              "input_encryption": "bfv-v1",
              "input_encryption_public_parameters": "params-b64",
              "input_encryption_public_parameters_decoded": {
                "modulus": "first",
                "modulus": "second"
              },
              "ram_fhe_profile": null,
              "note": "retail policy"
            }
            """;
    }

    private static string NestedIdentifierResolveResponse(string attestationJson, string? payloadJson = null)
    {
        payloadJson ??= NestedIdentifierPayloadJson();
        return $$"""
            {
              "payload": {{payloadJson}},
              "attestation": {{attestationJson}}
            }
            """;
    }

    private static string NestedIdentifierPayloadJson(
        string executionExecutedAtJson = "1710000000000",
        string executionExpiresAtJson = "1710003600000",
        string openingOpenedAtJson = "1710000000000",
        string openingExpiresAtJson = "1710003600000")
    {
        return $$"""
            {
                "policy_id": "phone#retail",
                "account_id": "sorauﾛ1NｱｻｸYSafﾇｷヰc5ﾇﾄVxﾏ9jLZヱﾋzsKqurﾊﾘ9ｸ3eｴAｶD54TDT",
                "opaque_id": "opaque-1",
                "receipt_hash": "receipt-1",
                "uaid": "uaid:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "execution": {
                  "program_id": "identifier_lookup_retail",
                  "program_digest": "program-digest",
                  "backend": "bfv-programmed-v1",
                  "verification_mode": "signed",
                  "input_ciphertext_hash": "input-hash",
                  "output_ciphertext_hash": "output-hash",
                  "parameter_digest": "parameter-digest",
                  "evaluation_key_digest": "evaluation-key-digest",
                  "output_hash": "output-open-hash",
                  "associated_data_hash": "associated-data-hash",
                  "executed_at_ms": {{executionExecutedAtJson}},
                  "expires_at_ms": {{executionExpiresAtJson}}
                },
                "opening": {
                  "payload": {
                    "program_id": "identifier_lookup_retail",
                    "input_ciphertext_hash": "input-hash",
                    "output_ciphertext_hash": "output-hash",
                    "parameter_digest": "parameter-digest",
                    "evaluation_key_digest": "evaluation-key-digest",
                    "opened_output_hash": "opened-output-hash",
                    "opened_at_ms": {{openingOpenedAtJson}},
                    "expires_at_ms": {{openingExpiresAtJson}}
                  },
                  "signature": "ABCD"
                }
            }
            """;
    }

    private static string NestedIdentifierPayloadDuplicateExecutionBackendJson()
    {
        return """
            {
                "policy_id": "phone#retail",
                "account_id": "sorauﾛ1NｱｻｸYSafﾇｷヰc5ﾇﾄVxﾏ9jLZヱﾋzsKqurﾊﾘ9ｸ3eｴAｶD54TDT",
                "opaque_id": "opaque-1",
                "receipt_hash": "receipt-1",
                "uaid": "uaid:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "execution": {
                  "program_id": "identifier_lookup_retail",
                  "program_digest": "program-digest",
                  "backend": "bfv-programmed-v1",
                  "backend": "bfv-programmed-v1",
                  "verification_mode": "signed",
                  "input_ciphertext_hash": "input-hash",
                  "output_ciphertext_hash": "output-hash",
                  "parameter_digest": "parameter-digest",
                  "evaluation_key_digest": "evaluation-key-digest",
                  "output_hash": "output-open-hash",
                  "associated_data_hash": "associated-data-hash",
                  "executed_at_ms": 1710000000000,
                  "expires_at_ms": 1710003600000
                },
                "opening": {
                  "payload": {
                    "program_id": "identifier_lookup_retail",
                    "input_ciphertext_hash": "input-hash",
                    "output_ciphertext_hash": "output-hash",
                    "parameter_digest": "parameter-digest",
                    "evaluation_key_digest": "evaluation-key-digest",
                    "opened_output_hash": "opened-output-hash",
                    "opened_at_ms": 1710000000000,
                    "expires_at_ms": 1710003600000
                  },
                  "signature": "ABCD"
                }
            }
            """;
    }

    private static void SetNestedString(JsonObject payload, string fieldPath, string value)
    {
        var segments = fieldPath.Split('.');
        var current = payload;
        for (var index = 0; index < segments.Length - 1; index++)
        {
            current = current[segments[index]]!.AsObject();
        }

        current[segments[^1]] = value;
    }

    private static void SetNestedNumber(JsonObject payload, string fieldPath, long value)
    {
        var segments = fieldPath.Split('.');
        var current = payload;
        for (var index = 0; index < segments.Length - 1; index++)
        {
            current = current[segments[index]]!.AsObject();
        }

        current[segments[^1]] = value;
    }

    private static void MergeObjectPatch(JsonObject target, JsonObject patch)
    {
        foreach (var property in patch)
        {
            if (property.Key == "attestation")
            {
                target[property.Key] = property.Value?.DeepClone();
                continue;
            }

            if (property.Value is JsonObject patchObject
                && target[property.Key] is JsonObject targetObject)
            {
                MergeObjectPatch(targetObject, patchObject);
                continue;
            }

            target[property.Key] = property.Value?.DeepClone();
        }
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> responder;

        public RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        {
            this.responder = responder;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var response = responder(request);
            response.RequestMessage ??= request;
            return Task.FromResult(response);
        }
    }
}
