using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using Hyperledger.Iroha.Address;
using Hyperledger.Iroha.Http;
using Hyperledger.Iroha.Norito;
using Hyperledger.Iroha.Queries;
using Hyperledger.Iroha.Transactions;
using Hyperledger.Iroha.Zk;

namespace Hyperledger.Iroha.Torii;

public sealed partial class ToriiClient
{
    private const int VerifyingKeyDraftResponseMaxBytes = 24 * 1024 * 1024;

    public async Task<JsonDocument> GetVerifyingKeyAsync(
        string backend,
        string name,
        CancellationToken cancellationToken = default)
    {
        var normalizedBackend = VerifierBackendRegistryLabels.RequireSupportedLabel(
            backend,
            nameof(backend));
        var normalizedName = NormalizeVerifyingKeyName(name, nameof(name));
        var response = await GetJsonDocumentAsync(
            $"/v1/zk/vk/{EncodePathSegment(normalizedBackend)}/{EncodePathSegment(normalizedName)}",
            cancellationToken: cancellationToken);
        ValidateVerifyingKeyDetailDocument(response, "verifying key detail response");
        return response;
    }

    public async Task<ToriiVerifyingKeyTransactionDraft> RegisterVerifyingKeyAsync(
        ToriiVerifyingKeyRegisterRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var networkId = Options.NetworkId
            ?? throw new InvalidOperationException(
                "Verifying-key draft preparation requires ToriiClientOptions.NetworkId.");

        var normalizedRequest = NormalizeVerifyingKeyRegisterRequest(request);
        return await PrepareVerifyingKeyTransactionDraftAsync(
            "/v1/zk/vk/register",
            normalizedRequest,
            "verifying key register response",
            networkId,
            VerifyingKeyDraftOperation.Register,
            cancellationToken);
    }

    public async Task<ToriiVerifyingKeyTransactionDraft> UpdateVerifyingKeyAsync(
        ToriiVerifyingKeyUpdateRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var networkId = Options.NetworkId
            ?? throw new InvalidOperationException(
                "Verifying-key draft preparation requires ToriiClientOptions.NetworkId.");

        var normalizedRequest = NormalizeVerifyingKeyUpdateRequest(request);
        return await PrepareVerifyingKeyTransactionDraftAsync(
            "/v1/zk/vk/update",
            normalizedRequest,
            "verifying key update response",
            networkId,
            VerifyingKeyDraftOperation.Update,
            cancellationToken);
    }

    private async Task<ToriiVerifyingKeyTransactionDraft> PrepareVerifyingKeyTransactionDraftAsync<TRequest>(
        string path,
        TRequest request,
        string context,
        NetworkId expectedNetworkId,
        VerifyingKeyDraftOperation operation,
        CancellationToken cancellationToken)
    {
        using var content = CreateJsonContent(request);
        using var response = await SendExpectingStatusAsync(
            HttpMethod.Post,
            path,
            query: null,
            content: content,
            expectedStatusCode: HttpStatusCode.OK,
            allowedStatusCode: null,
            cancellationToken: cancellationToken);
        if (!string.Equals(
                response.Content.Headers.ContentType?.MediaType,
                "application/json",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new JsonException($"{context} must use the application/json media type.");
        }

        using var document = await ParseBoundedJsonContentRejectingDuplicatePropertiesAsync(
            response.Content,
            context,
            cancellationToken,
            VerifyingKeyDraftResponseMaxBytes);
        return ParseVerifyingKeyTransactionDraft(
            document,
            context,
            request!,
            expectedNetworkId,
            operation);
    }

    private static ToriiVerifyingKeyRegisterRequest NormalizeVerifyingKeyRegisterRequest(
        ToriiVerifyingKeyRegisterRequest request)
    {
        var normalizedBackend = VerifierBackendRegistryLabels.RequireSupportedLabel(
            request.Backend,
            nameof(request.Backend));
        var vkBytes = NormalizeOptionalVerifierBytes(
            request.VerifyingKeyBytes,
            request.VerifyingKeyLength,
            out var vkLength,
            nameof(request.VerifyingKeyBytes));
        var commitmentHex = NormalizeOptionalVerifyingKeyHex(
            request.CommitmentHex,
            nameof(request.CommitmentHex));
        ValidateVerifyingKeyMaterial(vkBytes, vkLength, commitmentHex);
        ValidateInlineVerifyingKeyCommitment(normalizedBackend, vkBytes, commitmentHex);
        ValidateVerifyingKeyHeightRange(
            request.ActivationHeight,
            request.WithdrawHeight,
            nameof(request.WithdrawHeight));

        return request with
        {
            Authority = ToriiAccountFaucetPow.RequireExactAccountId(request.Authority, nameof(request.Authority)),
            Backend = normalizedBackend,
            Name = NormalizeVerifyingKeyName(request.Name, nameof(request.Name)),
            Version = RequirePositiveUInt32(request.Version, nameof(request.Version)),
            CircuitId = NormalizeExactValue(request.CircuitId, nameof(request.CircuitId)),
            PublicInputsSchemaHashHex = NormalizeVerifyingKeyHex(
                request.PublicInputsSchemaHashHex,
                nameof(request.PublicInputsSchemaHashHex)),
            Curve = NormalizeOptionalExactValue(request.Curve, nameof(request.Curve)),
            GasScheduleId = NormalizeExactValue(request.GasScheduleId, nameof(request.GasScheduleId)),
            VerifyingKeyLength = vkLength,
            MaxProofBytes = NormalizeOptionalPositiveUInt32(request.MaxProofBytes, nameof(request.MaxProofBytes)),
            MetadataUriCid = NormalizeOptionalExactValue(request.MetadataUriCid, nameof(request.MetadataUriCid)),
            VerifyingKeyBytesCid = NormalizeOptionalExactValue(request.VerifyingKeyBytesCid, nameof(request.VerifyingKeyBytesCid)),
            ActivationHeight = request.ActivationHeight,
            WithdrawHeight = request.WithdrawHeight,
            CommitmentHex = commitmentHex,
            VerifyingKeyBytes = vkBytes,
            Status = NormalizeOptionalVerifyingKeyStatus(request.Status, nameof(request.Status)),
        };
    }

    private static ToriiVerifyingKeyUpdateRequest NormalizeVerifyingKeyUpdateRequest(
        ToriiVerifyingKeyUpdateRequest request)
    {
        var normalizedBackend = VerifierBackendRegistryLabels.RequireSupportedLabel(
            request.Backend,
            nameof(request.Backend));
        var vkBytes = NormalizeOptionalVerifierBytes(
            request.VerifyingKeyBytes,
            request.VerifyingKeyLength,
            out var vkLength,
            nameof(request.VerifyingKeyBytes));
        var commitmentHex = NormalizeOptionalVerifyingKeyHex(
            request.CommitmentHex,
            nameof(request.CommitmentHex));
        ValidateVerifyingKeyMaterial(vkBytes, vkLength, commitmentHex);
        ValidateInlineVerifyingKeyCommitment(normalizedBackend, vkBytes, commitmentHex);
        ValidateVerifyingKeyHeightRange(
            request.ActivationHeight,
            request.WithdrawHeight,
            nameof(request.WithdrawHeight));

        return request with
        {
            Authority = ToriiAccountFaucetPow.RequireExactAccountId(request.Authority, nameof(request.Authority)),
            Backend = normalizedBackend,
            Name = NormalizeVerifyingKeyName(request.Name, nameof(request.Name)),
            Version = RequirePositiveUInt32(request.Version, nameof(request.Version)),
            CircuitId = NormalizeExactValue(request.CircuitId, nameof(request.CircuitId)),
            PublicInputsSchemaHashHex = NormalizeVerifyingKeyHex(
                request.PublicInputsSchemaHashHex,
                nameof(request.PublicInputsSchemaHashHex)),
            Curve = NormalizeOptionalExactValue(request.Curve, nameof(request.Curve)),
            GasScheduleId = NormalizeOptionalExactValue(request.GasScheduleId, nameof(request.GasScheduleId)),
            CommitmentHex = commitmentHex,
            VerifyingKeyLength = vkLength,
            MaxProofBytes = NormalizeOptionalPositiveUInt32(request.MaxProofBytes, nameof(request.MaxProofBytes)),
            MetadataUriCid = NormalizeOptionalExactValue(request.MetadataUriCid, nameof(request.MetadataUriCid)),
            VerifyingKeyBytesCid = NormalizeOptionalExactValue(request.VerifyingKeyBytesCid, nameof(request.VerifyingKeyBytesCid)),
            ActivationHeight = request.ActivationHeight,
            WithdrawHeight = request.WithdrawHeight,
            VerifyingKeyBytes = vkBytes,
            Status = NormalizeOptionalVerifyingKeyStatus(request.Status, nameof(request.Status)),
        };
    }

    private static void ValidateVerifyingKeyDetailDocument(JsonDocument document, string context)
    {
        ArgumentNullException.ThrowIfNull(document);

        var root = RequireJsonObject(document.RootElement, context);
        var id = RequireJsonObjectProperty(root, "id", $"{context}.id");
        var idBackend = RequireJsonStringProperty(id, "backend", $"{context}.id.backend");
        var idName = RequireJsonStringProperty(id, "name", $"{context}.id.name");
        ValidateVerifyingKeyBackendResponseText(idBackend, $"{context}.id.backend");
        ValidateVerifyingKeyNameResponseText(idName, $"{context}.id.name");

        var record = RequireJsonObjectProperty(root, "record", $"{context}.record");
        var recordBackend = RequireJsonStringProperty(record, "backend", $"{context}.record.backend");
        if (!string.Equals(recordBackend, idBackend, StringComparison.Ordinal))
        {
            throw new JsonException($"{context}.record.backend must match {context}.id.backend.");
        }
        ValidateVerifyingKeyBackendResponseText(recordBackend, $"{context}.record.backend");

        ValidatePositiveJsonUInt64Property(record, "version", $"{context}.record.version");
        ValidateExactTokenText(
            RequireJsonStringProperty(record, "circuit_id", $"{context}.record.circuit_id"),
            $"{context}.record.circuit_id");
        ValidateOptionalExactTokenText(
            ReadOptionalJsonStringProperty(record, "curve", $"{context}.record.curve"),
            $"{context}.record.curve");
        ValidateExactSizedHex(
            RequireJsonStringProperty(
                record,
                "public_inputs_schema_hash",
                $"{context}.record.public_inputs_schema_hash"),
            $"{context}.record.public_inputs_schema_hash",
            32);
        ValidateExactSizedHex(
            RequireJsonStringProperty(record, "commitment", $"{context}.record.commitment"),
            $"{context}.record.commitment",
            32);
        ValidatePositiveJsonUInt64Property(record, "vk_len", $"{context}.record.vk_len");
        ReadOptionalPositiveJsonUInt64Property(record, "max_proof_bytes", $"{context}.record.max_proof_bytes");
        ValidateOptionalExactTokenText(
            ReadOptionalJsonStringProperty(record, "gas_schedule_id", $"{context}.record.gas_schedule_id"),
            $"{context}.record.gas_schedule_id");
        ValidateOptionalExactTokenText(
            ReadOptionalJsonStringProperty(record, "metadata_uri_cid", $"{context}.record.metadata_uri_cid"),
            $"{context}.record.metadata_uri_cid");
        ValidateOptionalExactTokenText(
            ReadOptionalJsonStringProperty(record, "vk_bytes_cid", $"{context}.record.vk_bytes_cid"),
            $"{context}.record.vk_bytes_cid");

        var activationHeight =
            ReadOptionalJsonUInt64Property(record, "activation_height", $"{context}.record.activation_height");
        var withdrawHeight =
            ReadOptionalJsonUInt64Property(record, "withdraw_height", $"{context}.record.withdraw_height");
        if (activationHeight.HasValue
            && withdrawHeight.HasValue
            && withdrawHeight.Value < activationHeight.Value)
        {
            throw new JsonException($"{context}.record.withdraw_height must be greater than or equal to activation_height.");
        }

        ValidateVerifyingKeyStatusResponseText(
            RequireJsonStringProperty(record, "status", $"{context}.record.status"),
            $"{context}.record.status");

        if (TryReadOptionalJsonObjectProperty(record, "key", $"{context}.record.key", out var inlineKey))
        {
            ValidateVerifyingKeyInlineResponse(inlineKey, recordBackend, $"{context}.record.key");
        }
    }

    private enum VerifyingKeyDraftOperation
    {
        Register,
        Update,
    }

    private sealed record VerifyingKeyDraftExpectedRecord(
        uint Version,
        string CircuitId,
        uint BackendTag,
        string Curve,
        byte[] PublicInputsSchemaHash,
        byte[] Commitment,
        uint VerifyingKeyLength,
        uint MaxProofBytes,
        string? GasScheduleId,
        string? MetadataUriCid,
        string? VerifyingKeyBytesCid,
        ulong? ActivationHeight,
        ulong? WithdrawHeight,
        string? KeyBackend,
        byte[]? KeyBytes,
        byte Status);

    private static ToriiVerifyingKeyTransactionDraft ParseVerifyingKeyTransactionDraft(
        JsonDocument document,
        string context,
        object request,
        NetworkId expectedNetworkId,
        VerifyingKeyDraftOperation operation)
    {
        ArgumentNullException.ThrowIfNull(document);

        var root = RequireJsonObject(document.RootElement, context);
        var expectedFields = new HashSet<string>(
            ["submitted", "transaction_payload_b64", "signing_message_b64"],
            StringComparer.Ordinal);
        var actualFields = root.EnumerateObject()
            .Select(static property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        if (!actualFields.SetEquals(expectedFields))
        {
            throw new JsonException(
                $"{context} must contain exactly submitted, transaction_payload_b64, and signing_message_b64.");
        }

        if (!root.TryGetProperty("submitted", out var submitted)
            || submitted.ValueKind != JsonValueKind.False)
        {
            throw new JsonException($"{context}.submitted must be false.");
        }

        var transactionPayloadBase64 = RequireJsonStringProperty(
            root,
            "transaction_payload_b64",
            $"{context}.transaction_payload_b64");
        var signingMessageBase64 = RequireJsonStringProperty(
            root,
            "signing_message_b64",
            $"{context}.signing_message_b64");
        var transactionPayload = DecodeCanonicalVerifyingKeyDraftBase64(
            transactionPayloadBase64,
            $"{context}.transaction_payload_b64",
            maximumBytes: 16 * 1024 * 1024);
        ValidateCanonicalVerifyingKeyTransactionPayload(
            transactionPayload,
            $"{context}.transaction_payload_b64",
            request,
            expectedNetworkId,
            operation);
        var signingMessage = DecodeCanonicalVerifyingKeyDraftBase64(
            signingMessageBase64,
            $"{context}.signing_message_b64",
            maximumBytes: IrohaHash.Length,
            exactBytes: IrohaHash.Length);
        var expectedSigningMessage = IrohaHash.Hash(transactionPayload);
        if (!CryptographicOperations.FixedTimeEquals(signingMessage, expectedSigningMessage))
        {
            throw new JsonException(
                $"{context}.signing_message_b64 must be the exact Iroha prehash of transaction_payload_b64.");
        }

        return new ToriiVerifyingKeyTransactionDraft(
            transactionPayloadBase64,
            signingMessageBase64,
            transactionPayload,
            signingMessage);
    }

    private static byte[] DecodeCanonicalVerifyingKeyDraftBase64(
        string value,
        string context,
        int maximumBytes,
        int? exactBytes = null)
    {
        var maximumEncodedBytes = checked(((maximumBytes + 2) / 3) * 4);
        if (value.Length == 0
            || value.Length > maximumEncodedBytes
            || value.Length % 4 != 0
            || value.Any(static character =>
                character is not (>= 'A' and <= 'Z')
                    and not (>= 'a' and <= 'z')
                    and not (>= '0' and <= '9')
                    and not ('+' or '/' or '=')))
        {
            throw new JsonException($"{context} must be bounded canonical non-empty padded base64.");
        }

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(value);
        }
        catch (FormatException error)
        {
            throw new JsonException($"{context} must be canonical padded base64.", error);
        }

        if (decoded.Length == 0
            || decoded.Length > maximumBytes
            || !string.Equals(Convert.ToBase64String(decoded), value, StringComparison.Ordinal))
        {
            throw new JsonException($"{context} must be bounded canonical non-empty padded base64.");
        }
        if (exactBytes.HasValue && decoded.Length != exactBytes.Value)
        {
            throw new JsonException($"{context} must decode to exactly {exactBytes.Value} bytes.");
        }

        return decoded;
    }

    private static void ValidateCanonicalVerifyingKeyTransactionPayload(
        ReadOnlySpan<byte> payload,
        string context,
        object request,
        NetworkId expectedNetworkId,
        VerifyingKeyDraftOperation operation)
    {
        try
        {
            var cursor = new VerifyingKeyDraftTransactionCursor(payload);
            var domain = cursor.TakeField("domain");
            var authority = cursor.TakeField("authority");
            var creationTime = cursor.TakeField("creation_time_ms");
            var executable = cursor.TakeField("executable");
            var timeToLive = cursor.TakeField("time_to_live_ms");
            var nonce = cursor.TakeField("nonce");
            var feePayment = cursor.TakeField("fee_payment");
            var metadata = cursor.TakeField("metadata");
            var attachments = cursor.TakeField("attachments");
            if (!cursor.IsFinished
                || creationTime.Length != sizeof(ulong)
                || feePayment.IsEmpty
                || metadata.IsEmpty)
            {
                throw new JsonException(
                    $"{context} must contain exactly one canonical nine-field Norito TransactionPayload.");
            }

            var (authorityAccountId, backend, name, expectedRecord) =
                ExpectedVerifyingKeyDraft(request);
            RequireVerifyingKeyDraftNetworkDomain(
                domain,
                expectedNetworkId,
                $"{context}.domain");

            var decodedAuthority = ToriiSubmitValidation.RequireCanonicalAuthority(authority);
            var expectedAuthority = AccountAddress
                .Parse(authorityAccountId)
                .ControllerBytes();
            if (!decodedAuthority.AsSpan().SequenceEqual(expectedAuthority))
            {
                throw new JsonException($"{context} changed the requested authority.");
            }

            RequireCanonicalVerifyingKeyDraftNonZeroOption(
                timeToLive,
                sizeof(ulong),
                required: true,
                context: $"{context}.time_to_live_ms");
            RequireCanonicalVerifyingKeyDraftNonZeroOption(
                nonce,
                sizeof(uint),
                required: false,
                context: $"{context}.nonce");
            ToriiSubmitValidation.RequireCanonicalTransactionFeePayment(feePayment);
            ToriiSubmitValidation.RequireEmptyTransactionMetadata(metadata);
            RequireAbsentVerifyingKeyDraftOption(attachments, $"{context}.attachments");
            RequireRequestedVerifyingKeyInstruction(
                executable,
                operation,
                backend,
                name,
                expectedRecord,
                context);
        }
        catch (JsonException)
        {
            throw;
        }
        catch (Exception error) when (error is ArgumentException or OverflowException)
        {
            throw new JsonException(
                $"{context} must contain exactly one canonical nine-field Norito TransactionPayload.",
                error);
        }
    }

    private static (
        string Authority,
        string Backend,
        string Name,
        VerifyingKeyDraftExpectedRecord Record)
        ExpectedVerifyingKeyDraft(object request)
    {
        string authority;
        string backend;
        string name;
        uint version;
        string circuitId;
        string schemaHashHex;
        string? curve;
        string? gasScheduleId;
        uint? keyLength;
        uint? maxProofBytes;
        string? metadataUriCid;
        string? keyBytesCid;
        ulong? activationHeight;
        ulong? withdrawHeight;
        string? commitmentHex;
        byte[]? keyBytes;
        string? status;
        switch (request)
        {
            case ToriiVerifyingKeyRegisterRequest register:
                authority = register.Authority!;
                backend = register.Backend!;
                name = register.Name!;
                version = register.Version!.Value;
                circuitId = register.CircuitId!;
                schemaHashHex = register.PublicInputsSchemaHashHex!;
                curve = register.Curve;
                gasScheduleId = register.GasScheduleId;
                keyLength = register.VerifyingKeyLength;
                maxProofBytes = register.MaxProofBytes;
                metadataUriCid = register.MetadataUriCid;
                keyBytesCid = register.VerifyingKeyBytesCid;
                activationHeight = register.ActivationHeight;
                withdrawHeight = register.WithdrawHeight;
                commitmentHex = register.CommitmentHex;
                keyBytes = register.VerifyingKeyBytes;
                status = register.Status;
                break;
            case ToriiVerifyingKeyUpdateRequest update:
                authority = update.Authority!;
                backend = update.Backend!;
                name = update.Name!;
                version = update.Version!.Value;
                circuitId = update.CircuitId!;
                schemaHashHex = update.PublicInputsSchemaHashHex!;
                curve = update.Curve;
                gasScheduleId = update.GasScheduleId;
                keyLength = update.VerifyingKeyLength;
                maxProofBytes = update.MaxProofBytes;
                metadataUriCid = update.MetadataUriCid;
                keyBytesCid = update.VerifyingKeyBytesCid;
                activationHeight = update.ActivationHeight;
                withdrawHeight = update.WithdrawHeight;
                commitmentHex = update.CommitmentHex;
                keyBytes = update.VerifyingKeyBytes;
                status = update.Status;
                break;
            default:
                throw new JsonException("Verifying-key draft request type is unsupported.");
        }

        var schemaHash = Convert.FromHexString(schemaHashHex);
        var commitment = keyBytes is null
            ? Convert.FromHexString(commitmentHex!)
            : Convert.FromHexString(ComputeVerifyingKeyCommitmentHex(backend, keyBytes));
        var exactKeyLength = keyBytes is null
            ? keyLength!.Value
            : checked((uint)keyBytes.Length);
        var backendTag = (uint)(VerifyingKeyBackendTags.RegistryTag(backend)
            ?? throw new JsonException("request backend is not a canonical verifier registry label"));
        var statusTag = status switch
        {
            null or "Active" => (byte)1,
            "Proposed" => (byte)0,
            "Withdrawn" => (byte)2,
            _ => throw new JsonException("Verifying-key draft request status is invalid."),
        };
        return (
            authority,
            backend,
            name,
            new VerifyingKeyDraftExpectedRecord(
                version,
                circuitId,
                backendTag,
                curve ?? "unknown",
                schemaHash,
                commitment,
                exactKeyLength,
                maxProofBytes ?? 0,
                gasScheduleId,
                metadataUriCid,
                keyBytesCid,
                activationHeight,
                withdrawHeight,
                keyBytes is null ? null : backend,
                keyBytes,
                statusTag));
    }

    private static void RequireVerifyingKeyDraftNetworkDomain(
        ReadOnlySpan<byte> payload,
        NetworkId expectedNetworkId,
        string context)
    {
        var domain = new VerifyingKeyDraftTransactionCursor(payload);
        if (domain.TakeUInt32($"{context}.kind") != 0)
        {
            throw new JsonException($"{context} must be TransactionDomain::Network.");
        }

        var value = domain.TakeField($"{context}.value");
        if (!domain.IsFinished
            || value.Length != NetworkId.ByteLength
            || !value.SequenceEqual(expectedNetworkId.AsSpan()))
        {
            throw new JsonException($"{context} changed the configured network.");
        }
    }

    private static void RequireRequestedVerifyingKeyInstruction(
        ReadOnlySpan<byte> payload,
        VerifyingKeyDraftOperation operation,
        string expectedBackend,
        string expectedName,
        VerifyingKeyDraftExpectedRecord expectedRecord,
        string context)
    {
        var executable = new VerifyingKeyDraftTransactionCursor(payload);
        if (executable.TakeUInt32($"{context}.executable.kind") != 0)
        {
            throw new JsonException(
                $"{context} executable must contain native instructions.");
        }

        var instructions = new VerifyingKeyDraftTransactionCursor(
            executable.TakeField($"{context}.executable.instructions"));
        if (!executable.IsFinished
            || instructions.TakeUInt64($"{context}.executable.instructions.count") != 1)
        {
            throw new JsonException(
                $"{context} must contain exactly one verifying-key instruction.");
        }

        var instruction = new VerifyingKeyDraftTransactionCursor(
            instructions.TakeField($"{context}.executable.instruction"));
        var wireName = DecodeVerifyingKeyDraftString(
            instruction.TakeField($"{context}.executable.instruction.wire_name"),
            $"{context}.executable.instruction.wire_name");
        var archive = DecodeVerifyingKeyDraftByteVector(
            instruction.TakeField($"{context}.executable.instruction.payload"),
            $"{context}.executable.instruction.payload");
        var expectedWireName = operation switch
        {
            VerifyingKeyDraftOperation.Register =>
                "iroha.instruction.v1::verifying_keys::RegisterVerifyingKey",
            VerifyingKeyDraftOperation.Update =>
                "iroha.instruction.v1::verifying_keys::UpdateVerifyingKey",
            _ => throw new JsonException("Verifying-key draft operation is unknown."),
        };
        var expectedSchemaName = operation switch
        {
            VerifyingKeyDraftOperation.Register =>
                "iroha_data_model::isi::verifying_keys::RegisterVerifyingKey",
            VerifyingKeyDraftOperation.Update =>
                "iroha_data_model::isi::verifying_keys::UpdateVerifyingKey",
            _ => throw new JsonException("Verifying-key draft operation is unknown."),
        };
        if (!instructions.IsFinished
            || !instruction.IsFinished
            || !string.Equals(wireName, expectedWireName, StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context} does not contain the requested verifying-key registry operation.");
        }

        RequireCanonicalVerifyingKeyInstructionArchive(
            archive,
            expectedSchemaName,
            expectedBackend,
            expectedName,
            expectedRecord,
            context);
    }

    private static void RequireCanonicalVerifyingKeyInstructionArchive(
        ReadOnlySpan<byte> archive,
        string wireName,
        string expectedBackend,
        string expectedName,
        VerifyingKeyDraftExpectedRecord expectedRecord,
        string context)
    {
        if (archive.IsEmpty || archive.Length > 16 * 1024 * 1024)
        {
            throw new JsonException($"{context} verifying-key instruction archive is invalid.");
        }

        byte[] payload;
        byte flags;
        try
        {
            (payload, flags) = NoritoCodec.Decode(wireName, archive);
        }
        catch (ArgumentException error)
        {
            throw new JsonException(
                $"{context} verifying-key instruction archive is invalid.",
                error);
        }
        if (flags != 0x02
            || !NoritoCodec.Encode(wireName, payload, flags).AsSpan().SequenceEqual(archive))
        {
            throw new JsonException(
                $"{context} verifying-key instruction archive is not byte-canonical.");
        }

        var instruction = new VerifyingKeyDraftTransactionCursor(payload);
        var id = instruction.TakeField($"{context}.instruction.id");
        var record = instruction.TakeField($"{context}.instruction.record");
        if (!instruction.IsFinished)
        {
            throw new JsonException(
                $"{context} verifying-key instruction contains trailing fields.");
        }

        RequireVerifyingKeyDraftIdentifier(
            id,
            expectedBackend,
            expectedName,
            context);
        RequireVerifyingKeyDraftRecord(record, expectedRecord, context);
    }

    private static void RequireVerifyingKeyDraftIdentifier(
        ReadOnlySpan<byte> payload,
        string expectedBackend,
        string expectedName,
        string context)
    {
        var id = new VerifyingKeyDraftTransactionCursor(payload);
        var backend = DecodeVerifyingKeyDraftString(
            id.TakeField($"{context}.id.backend"),
            $"{context}.id.backend");
        var name = DecodeVerifyingKeyDraftString(
            id.TakeField($"{context}.id.name"),
            $"{context}.id.name");
        if (!id.IsFinished
            || !string.Equals(backend, expectedBackend, StringComparison.Ordinal)
            || !string.Equals(name, expectedName, StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context} verifying-key instruction identifier does not match the request.");
        }
    }

    private static void RequireVerifyingKeyDraftRecord(
        ReadOnlySpan<byte> payload,
        VerifyingKeyDraftExpectedRecord expected,
        string context)
    {
        var record = new VerifyingKeyDraftTransactionCursor(payload);
        var version = DecodeVerifyingKeyDraftUInt32(
            record.TakeField($"{context}.record.version"),
            $"{context}.record.version");
        var circuitId = DecodeVerifyingKeyDraftString(
            record.TakeField($"{context}.record.circuit_id"),
            $"{context}.record.circuit_id");
        var ownerManifestId = DecodeVerifyingKeyDraftOptionalString(
            record.TakeField($"{context}.record.owner_manifest_id"),
            $"{context}.record.owner_manifest_id");
        var registryNamespace = DecodeVerifyingKeyDraftString(
            record.TakeField($"{context}.record.namespace"),
            $"{context}.record.namespace");
        var backendTag = DecodeVerifyingKeyDraftUInt32(
            record.TakeField($"{context}.record.backend"),
            $"{context}.record.backend");
        var curve = DecodeVerifyingKeyDraftString(
            record.TakeField($"{context}.record.curve"),
            $"{context}.record.curve");
        var schemaHash = RequireVerifyingKeyDraftFixedBytes(
            record.TakeField($"{context}.record.public_inputs_schema_hash"),
            32,
            $"{context}.record.public_inputs_schema_hash");
        var commitment = RequireVerifyingKeyDraftFixedBytes(
            record.TakeField($"{context}.record.commitment"),
            32,
            $"{context}.record.commitment");
        var keyLength = DecodeVerifyingKeyDraftUInt32(
            record.TakeField($"{context}.record.vk_len"),
            $"{context}.record.vk_len");
        var maxProofBytes = DecodeVerifyingKeyDraftUInt32(
            record.TakeField($"{context}.record.max_proof_bytes"),
            $"{context}.record.max_proof_bytes");
        var gasScheduleId = DecodeVerifyingKeyDraftOptionalString(
            record.TakeField($"{context}.record.gas_schedule_id"),
            $"{context}.record.gas_schedule_id");
        var metadataUriCid = DecodeVerifyingKeyDraftOptionalString(
            record.TakeField($"{context}.record.metadata_uri_cid"),
            $"{context}.record.metadata_uri_cid");
        var keyBytesCid = DecodeVerifyingKeyDraftOptionalString(
            record.TakeField($"{context}.record.vk_bytes_cid"),
            $"{context}.record.vk_bytes_cid");
        var activationHeight = DecodeVerifyingKeyDraftOptionalUInt64(
            record.TakeField($"{context}.record.activation_height"),
            $"{context}.record.activation_height");
        var withdrawHeight = DecodeVerifyingKeyDraftOptionalUInt64(
            record.TakeField($"{context}.record.withdraw_height"),
            $"{context}.record.withdraw_height");
        var key = DecodeVerifyingKeyDraftOptionalKey(
            record.TakeField($"{context}.record.key"),
            $"{context}.record.key");
        var status = DecodeVerifyingKeyDraftByte(
            record.TakeField($"{context}.record.status"),
            $"{context}.record.status");
        if (!record.IsFinished
            || version != expected.Version
            || !string.Equals(circuitId, expected.CircuitId, StringComparison.Ordinal)
            || ownerManifestId is not null
            || !string.Equals(registryNamespace, "core", StringComparison.Ordinal)
            || backendTag != expected.BackendTag
            || !string.Equals(curve, expected.Curve, StringComparison.Ordinal)
            || !schemaHash.SequenceEqual(expected.PublicInputsSchemaHash)
            || !commitment.SequenceEqual(expected.Commitment)
            || keyLength != expected.VerifyingKeyLength
            || maxProofBytes != expected.MaxProofBytes
            || !string.Equals(gasScheduleId, expected.GasScheduleId, StringComparison.Ordinal)
            || !string.Equals(metadataUriCid, expected.MetadataUriCid, StringComparison.Ordinal)
            || !string.Equals(keyBytesCid, expected.VerifyingKeyBytesCid, StringComparison.Ordinal)
            || activationHeight != expected.ActivationHeight
            || withdrawHeight != expected.WithdrawHeight
            || !string.Equals(key?.Backend, expected.KeyBackend, StringComparison.Ordinal)
            || !OptionalBytesEqual(key?.Bytes, expected.KeyBytes)
            || status != expected.Status)
        {
            throw new JsonException(
                $"{context} verifying-key instruction record does not match the full requested record.");
        }
    }

    private static bool OptionalBytesEqual(byte[]? left, byte[]? right) =>
        left is null
            ? right is null
            : right is not null && left.AsSpan().SequenceEqual(right);

    private static string DecodeVerifyingKeyDraftString(
        ReadOnlySpan<byte> payload,
        string context)
    {
        var value = new VerifyingKeyDraftTransactionCursor(payload);
        var length = value.TakeLength($"{context}.length");
        if (length > int.MaxValue)
        {
            throw new JsonException($"{context} exceeds the runtime bound.");
        }
        var bytes = value.TakeExact(checked((int)length), context);
        if (!value.IsFinished)
        {
            throw new JsonException($"{context} contains trailing bytes.");
        }
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException error)
        {
            throw new JsonException($"{context} is not canonical UTF-8.", error);
        }
    }

    private static byte[] DecodeVerifyingKeyDraftByteVector(
        ReadOnlySpan<byte> payload,
        string context)
    {
        var value = new VerifyingKeyDraftTransactionCursor(payload);
        var length = value.TakeUInt64($"{context}.length");
        if (length == 0 || length > int.MaxValue)
        {
            throw new JsonException($"{context} length is invalid.");
        }
        var bytes = value.TakeExact(checked((int)length), context).ToArray();
        if (!value.IsFinished)
        {
            throw new JsonException($"{context} contains trailing bytes.");
        }
        return bytes;
    }

    private static byte DecodeVerifyingKeyDraftByte(
        ReadOnlySpan<byte> payload,
        string context)
    {
        var value = new VerifyingKeyDraftTransactionCursor(payload);
        var decoded = value.TakeByte(context);
        if (!value.IsFinished)
        {
            throw new JsonException($"{context} contains trailing bytes.");
        }
        return decoded;
    }

    private static uint DecodeVerifyingKeyDraftUInt32(
        ReadOnlySpan<byte> payload,
        string context)
    {
        var value = new VerifyingKeyDraftTransactionCursor(payload);
        var decoded = value.TakeUInt32(context);
        if (!value.IsFinished)
        {
            throw new JsonException($"{context} contains trailing bytes.");
        }
        return decoded;
    }

    private static ulong DecodeVerifyingKeyDraftUInt64(
        ReadOnlySpan<byte> payload,
        string context)
    {
        var value = new VerifyingKeyDraftTransactionCursor(payload);
        var decoded = value.TakeUInt64(context);
        if (!value.IsFinished)
        {
            throw new JsonException($"{context} contains trailing bytes.");
        }
        return decoded;
    }

    private static byte[] RequireVerifyingKeyDraftFixedBytes(
        ReadOnlySpan<byte> payload,
        int length,
        string context)
    {
        if (payload.Length != length)
        {
            throw new JsonException($"{context} must contain exactly {length} bytes.");
        }
        return payload.ToArray();
    }

    private static string? DecodeVerifyingKeyDraftOptionalString(
        ReadOnlySpan<byte> payload,
        string context)
    {
        var option = new VerifyingKeyDraftTransactionCursor(payload);
        switch (option.TakeByte($"{context}.tag"))
        {
            case 0:
                if (!option.IsFinished)
                {
                    throw new JsonException($"{context} None encoding contains trailing bytes.");
                }
                return null;
            case 1:
                var value = DecodeVerifyingKeyDraftString(
                    option.TakeField($"{context}.value"),
                    context);
                if (!option.IsFinished)
                {
                    throw new JsonException($"{context} Some encoding contains trailing bytes.");
                }
                return value;
            default:
                throw new JsonException($"{context} has an invalid option tag.");
        }
    }

    private static ulong? DecodeVerifyingKeyDraftOptionalUInt64(
        ReadOnlySpan<byte> payload,
        string context)
    {
        var option = new VerifyingKeyDraftTransactionCursor(payload);
        switch (option.TakeByte($"{context}.tag"))
        {
            case 0:
                if (!option.IsFinished)
                {
                    throw new JsonException($"{context} None encoding contains trailing bytes.");
                }
                return null;
            case 1:
                var value = DecodeVerifyingKeyDraftUInt64(
                    option.TakeField($"{context}.value"),
                    context);
                if (!option.IsFinished)
                {
                    throw new JsonException($"{context} Some encoding contains trailing bytes.");
                }
                return value;
            default:
                throw new JsonException($"{context} has an invalid option tag.");
        }
    }

    private static (string Backend, byte[] Bytes)? DecodeVerifyingKeyDraftOptionalKey(
        ReadOnlySpan<byte> payload,
        string context)
    {
        var option = new VerifyingKeyDraftTransactionCursor(payload);
        switch (option.TakeByte($"{context}.tag"))
        {
            case 0:
                if (!option.IsFinished)
                {
                    throw new JsonException($"{context} None encoding contains trailing bytes.");
                }
                return null;
            case 1:
                var key = new VerifyingKeyDraftTransactionCursor(
                    option.TakeField($"{context}.value"));
                var backend = DecodeVerifyingKeyDraftString(
                    key.TakeField($"{context}.backend"),
                    $"{context}.backend");
                var bytes = DecodeVerifyingKeyDraftByteVector(
                    key.TakeField($"{context}.bytes"),
                    $"{context}.bytes");
                if (!option.IsFinished)
                {
                    throw new JsonException($"{context} Some encoding contains trailing bytes.");
                }
                if (!key.IsFinished)
                {
                    throw new JsonException($"{context} contains trailing fields.");
                }
                return (backend, bytes);
            default:
                throw new JsonException($"{context} has an invalid option tag.");
        }
    }

    private static void RequireCanonicalVerifyingKeyDraftNonZeroOption(
        ReadOnlySpan<byte> payload,
        int width,
        bool required,
        string context)
    {
        var option = new VerifyingKeyDraftTransactionCursor(payload);
        switch (option.TakeByte($"{context}.tag"))
        {
            case 0:
                if (required || !option.IsFinished)
                {
                    throw new JsonException(
                        $"{context} must contain one canonical nonzero integer.");
                }
                return;
            case 1:
                var value = option.TakeField($"{context}.value");
                if (!option.IsFinished
                    || value.Length != width
                    || value.IndexOfAnyExcept((byte)0) < 0)
                {
                    throw new JsonException(
                        $"{context} Some value is not a canonical nonzero integer.");
                }
                return;
            default:
                throw new JsonException($"{context} has an invalid option tag.");
        }
    }

    private static void RequireAbsentVerifyingKeyDraftOption(
        ReadOnlySpan<byte> payload,
        string context)
    {
        var option = new VerifyingKeyDraftTransactionCursor(payload);
        if (option.TakeByte($"{context}.tag") != 0 || !option.IsFinished)
        {
            throw new JsonException($"{context} must use the exact None encoding.");
        }
    }

    private ref struct VerifyingKeyDraftTransactionCursor
    {
        private readonly ReadOnlySpan<byte> payload;
        private int offset;

        internal VerifyingKeyDraftTransactionCursor(ReadOnlySpan<byte> payload)
        {
            this.payload = payload;
            offset = 0;
        }

        internal readonly bool IsFinished => offset == payload.Length;

        internal byte TakeByte(string field) => TakeExact(1, field)[0];

        internal uint TakeUInt32(string field) =>
            BinaryPrimitives.ReadUInt32LittleEndian(TakeExact(sizeof(uint), field));

        internal ulong TakeUInt64(string field) =>
            BinaryPrimitives.ReadUInt64LittleEndian(TakeExact(sizeof(ulong), field));

        internal ReadOnlySpan<byte> TakeField(string field)
        {
            var length = TakeLength($"{field}.length");
            if (length > int.MaxValue)
            {
                throw new ArgumentException($"{field} exceeds the runtime bound.");
            }

            return TakeExact(checked((int)length), field);
        }

        internal ReadOnlySpan<byte> TakeExact(int count, string field)
        {
            if (count < 0 || offset > payload.Length - count)
            {
                throw new ArgumentException($"{field} is truncated.");
            }
            var result = payload.Slice(offset, count);
            offset += count;
            return result;
        }

        internal ulong TakeLength(string field)
        {
            ulong value = 0;
            var shift = 0;
            for (var count = 1; count <= 10; count++)
            {
                if (offset >= payload.Length)
                {
                    throw new ArgumentException($"{field} compact length is truncated.");
                }
                var current = payload[offset++];
                var chunk = (ulong)(current & 0x7f);
                if (shift >= 64 || chunk > ulong.MaxValue >> shift)
                {
                    throw new ArgumentException($"{field} compact length overflows UInt64.");
                }
                value |= chunk << shift;
                if ((current & 0x80) == 0)
                {
                    if (count > 1 && chunk == 0)
                    {
                        throw new ArgumentException($"{field} compact length is overlong.");
                    }
                    return value;
                }
                shift += 7;
            }

            throw new ArgumentException($"{field} compact length is overlong.");
        }
    }

    private static void ValidateVerifyingKeyInlineResponse(JsonElement inlineKey, string recordBackend, string context)
    {
        var inlineBackend = RequireJsonStringProperty(inlineKey, "backend", $"{context}.backend");
        if (!string.Equals(inlineBackend, recordBackend, StringComparison.Ordinal))
        {
            throw new JsonException($"{context}.backend must match the enclosing verifying key backend.");
        }
        ValidateVerifyingKeyBackendResponseText(inlineBackend, $"{context}.backend");

        var bytes = DecodeExactBase64AllowEmpty(
            RequireJsonStringProperty(inlineKey, "bytes_b64", $"{context}.bytes_b64"),
            $"{context}.bytes_b64");
        if (bytes.Length == 0)
        {
            throw new JsonException($"{context}.bytes_b64 must not decode to empty bytes.");
        }
    }

    private static void ValidateVerifyingKeyBackendResponseText(string value, string field)
    {
        try
        {
            VerifyingKeyBackendTags.RequireProductionVerifyBackendLabel(value, field);
        }
        catch (ArgumentException error)
        {
            throw new JsonException(error.Message, error);
        }
    }

    private static void ValidateVerifyingKeyNameResponseText(string value, string field)
    {
        try
        {
            _ = NormalizeVerifyingKeyName(value, field);
        }
        catch (ArgumentException error)
        {
            throw new JsonException(error.Message, error);
        }
    }

    private static void ValidateVerifyingKeyStatusResponseText(string value, string field)
    {
        ValidateExactTokenText(value, field);
        if (value is not ("Proposed" or "Active" or "Withdrawn"))
        {
            throw new JsonException($"{field} must be one of Proposed, Active, or Withdrawn.");
        }
    }


    private static string NormalizeVerifyingKeyName(string? value, string paramName)
    {
        var normalized = NormalizeExactValue(value, paramName);
        if (normalized.Contains(':', StringComparison.Ordinal))
        {
            throw new ArgumentException("Value must not contain ':' characters.", paramName);
        }

        return normalized;
    }

    private static string NormalizeVerifyingKeyHex(string? value, string paramName)
    {
        var normalized = NormalizeExactValue(value, paramName);
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[2..];
        }

        if (normalized.Length != 64 || !IsHex(normalized))
        {
            throw new ArgumentException("Value must be a 32-byte hex string.", paramName);
        }

        return normalized.ToLowerInvariant();
    }

    private static string? NormalizeOptionalVerifyingKeyHex(string? value, string paramName)
    {
        return value is null ? null : NormalizeVerifyingKeyHex(value, paramName);
    }

    private static byte[]? NormalizeOptionalVerifierBytes(
        byte[]? bytes,
        uint? explicitLength,
        out uint? normalizedLength,
        string paramName)
    {
        if (bytes is null)
        {
            normalizedLength = explicitLength;
            if (normalizedLength == 0)
            {
                throw new ArgumentOutOfRangeException(paramName, "vk_len must be positive when provided.");
            }

            return null;
        }

        if (bytes.Length == 0)
        {
            throw new ArgumentException("Value must be a non-empty verifying key byte payload.", paramName);
        }

        var actualLength = (uint)bytes.Length;
        if (explicitLength.HasValue && explicitLength.Value != actualLength)
        {
            throw new ArgumentException("vk_len must match vk_bytes length.", paramName);
        }

        normalizedLength = actualLength;
        return bytes.ToArray();
    }

    private static string? NormalizeOptionalVerifyingKeyStatus(string? value, string paramName)
    {
        if (value is null)
        {
            return null;
        }

        var normalized = NormalizeExactValue(value, paramName).ToLowerInvariant();
        return normalized switch
        {
            "proposed" => "Proposed",
            "active" => "Active",
            "withdrawn" => "Withdrawn",
            _ => throw new ArgumentException(
                "Value must be one of Proposed, Active, or Withdrawn.",
                paramName),
        };
    }

    private static void ValidateVerifyingKeyHeightRange(
        ulong? activationHeight,
        ulong? withdrawHeight,
        string paramName)
    {
        if (activationHeight.HasValue
            && withdrawHeight.HasValue
            && withdrawHeight.Value < activationHeight.Value)
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                "withdraw_height must be greater than or equal to activation_height.");
        }
    }

    private static void ValidateVerifyingKeyMaterial(
        byte[]? bytes,
        uint? vkLength,
        string? commitmentHex)
    {
        if (bytes is not null)
        {
            return;
        }

        if (commitmentHex is null)
        {
            throw new ArgumentException(
                "commitment_hex is required when vk_bytes is omitted.",
                nameof(commitmentHex));
        }

        if (!vkLength.HasValue)
        {
            throw new ArgumentException(
                "vk_len is required when vk_bytes is omitted.",
                nameof(vkLength));
        }
    }

    private static uint RequirePositiveUInt32(uint? value, string paramName)
    {
        if (value is null)
        {
            throw new ArgumentException("Value must be provided.", paramName);
        }

        if (value.Value == 0)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be positive.");
        }

        return value.Value;
    }

    private static uint? NormalizeOptionalPositiveUInt32(uint? value, string paramName)
    {
        if (value == 0)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be positive when provided.");
        }

        return value;
    }

    private static ulong? NormalizeOptionalPositiveUInt64(ulong? value, string paramName)
    {
        if (value == 0)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be positive when provided.");
        }

        return value;
    }

    private static void ValidateInlineVerifyingKeyCommitment(
        string backend,
        byte[]? bytes,
        string? commitmentHex)
    {
        if (bytes is null || commitmentHex is null)
        {
            return;
        }

        var expected = ComputeVerifyingKeyCommitmentHex(backend, bytes);
        if (!string.Equals(expected, commitmentHex, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "commitment_hex must match domain-separated SHA-256 of backend and vk_bytes.",
                nameof(commitmentHex));
        }
    }

    private static string ComputeVerifyingKeyCommitmentHex(string backend, byte[] bytes)
    {
        var domainBytes = Encoding.UTF8.GetBytes("iroha:zk:v1:vk");
        var backendBytes = Encoding.UTF8.GetBytes(backend);
        var preimage = new byte[domainBytes.Length + 8 + backendBytes.Length + 8 + bytes.Length];
        var offset = 0;
        Buffer.BlockCopy(domainBytes, 0, preimage, offset, domainBytes.Length);
        offset += domainBytes.Length;
        WriteUInt64BigEndian(preimage, offset, (ulong)backendBytes.Length);
        offset += 8;
        Buffer.BlockCopy(backendBytes, 0, preimage, offset, backendBytes.Length);
        offset += backendBytes.Length;
        WriteUInt64BigEndian(preimage, offset, (ulong)bytes.Length);
        offset += 8;
        Buffer.BlockCopy(bytes, 0, preimage, offset, bytes.Length);
        return Convert.ToHexString(SHA256.HashData(preimage)).ToLowerInvariant();
    }

    private static void WriteUInt64BigEndian(byte[] target, int offset, ulong value)
    {
        for (var index = 7; index >= 0; index--)
        {
            target[offset + index] = (byte)(value & 0xff);
            value >>= 8;
        }
    }



}
