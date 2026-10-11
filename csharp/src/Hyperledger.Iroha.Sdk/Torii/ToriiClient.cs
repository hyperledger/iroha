using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Hyperledger.Iroha.Address;
using Hyperledger.Iroha.Crypto;
using Hyperledger.Iroha.Http;
using Hyperledger.Iroha.Norito;
using Hyperledger.Iroha.Numeric;
using Hyperledger.Iroha.Queries;
using Hyperledger.Iroha.Query;
using Hyperledger.Iroha.Transactions;
using Hyperledger.Iroha.Zk;

namespace Hyperledger.Iroha.Torii;

public sealed partial class ToriiClient : IDisposable
{
    public const string AccountOnboardingTokenHeaderName = "X-Iroha-Onboarding-Token";

    private const int AccountOnboardingCurrentStateResponseMaxBytesV1 = 4 * 1024;
    private const int DefaultJsonResponseMaxBytes = 8 * 1024 * 1024;
    private const int SseMaximumLineBytes = DefaultJsonResponseMaxBytes;
    private const int DefaultTextResponseMaxBytes = 1024 * 1024;
    private const int ErrorResponseMaxBytes = 64 * 1024;
    private const int FeeSponsorProgramResponseMaxBytes = 64 * 1024;
    private const int FeeQuoteResponseMaxBytes = 64 * 1024;
    private const int SoraFsBufferedContentMaxBytes = 16 * 1024 * 1024;
    private const int SoraFsAliasTextMaxChars = 128;
    private const string InvalidUtf8ResponseBody = "<response body is not valid UTF-8>";
    private static readonly JsonSerializerOptions SerializerOptions = CreateSerializerOptions();
    private static readonly byte[] FaucetClaimHashDomainV1 =
        "iroha:accounts:faucet:claim:v1\0"u8.ToArray();
    private static readonly byte[] MultisigInstructionBoxSchemaHash =
        Convert.FromHexString("862a7d77075d4d23ff6c1261db027811");
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);

    private readonly bool ownsHttpClient;
    private readonly bool injectedTransportIsOneShot;

    /// <summary>Creates a client for one Torii endpoint with the SDK-managed transport.</summary>
    /// <param name="baseUri">The exact Torii base URI.</param>
    /// <param name="options">Optional client behavior and validation settings.</param>
    public ToriiClient(Uri baseUri, ToriiClientOptions? options = null)
        : this(
            baseUri,
            httpClient: null,
            options,
            ownsHttpClient: true,
            injectedTransportIsOneShot: false)
    {
    }

    /// <summary>Creates an anonymous client for one Torii endpoint over a caller-owned transport.</summary>
    /// <param name="baseUri">The exact Torii base URI.</param>
    /// <param name="httpClient">
    /// The caller-owned HTTP client. It must not carry an onboarding token in its default headers.
    /// Signed, bearer-authenticated, and one-shot routes reject an injected client because
    /// <see cref="ToriiClient"/> cannot inspect its complete redirect and retry chain.
    /// </param>
    /// <param name="options">
    /// Optional non-authentication behavior and validation settings. Authentication credentials
    /// require the SDK-managed transport constructor.
    /// </param>
    public ToriiClient(Uri baseUri, HttpClient httpClient, ToriiClientOptions? options = null)
        : this(
            baseUri,
            httpClient,
            options,
            ownsHttpClient: false,
            injectedTransportIsOneShot: false)
    {
    }

    private ToriiClient(
        Uri baseUri,
        HttpClient? httpClient,
        ToriiClientOptions? options,
        bool ownsHttpClient,
        bool injectedTransportIsOneShot)
    {
        ArgumentNullException.ThrowIfNull(baseUri);
        if (!ownsHttpClient)
        {
            ArgumentNullException.ThrowIfNull(httpClient);
        }

        if (!ownsHttpClient
            && !injectedTransportIsOneShot
            && (options?.CanonicalRequestCredentials is not null
                || options?.BearerToken is not null))
        {
            throw new ArgumentException(
                "Authentication credentials require the SDK-managed one-shot transport. "
                + "Use the ToriiClient(Uri, ToriiClientOptions?) constructor.",
                nameof(options));
        }

        if (httpClient?.DefaultRequestHeaders.Contains(AccountOnboardingTokenHeaderName) == true)
        {
            throw new ArgumentException(
                $"The caller-owned HttpClient must not define the per-request {AccountOnboardingTokenHeaderName} header.",
                nameof(httpClient));
        }

        BaseUri = NormalizeBaseUri(baseUri);
        HttpClient = httpClient ?? new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false,
        });
        this.ownsHttpClient = ownsHttpClient;
        this.injectedTransportIsOneShot = injectedTransportIsOneShot;
        Options = options ?? new ToriiClientOptions();
    }

    internal ToriiClient(
        Uri baseUri,
        HttpClient httpClient,
        ToriiClientOptions? options,
        TransactionSubmissionTransportAssurance transportAssurance)
        : this(
            baseUri,
            httpClient,
            options,
            ownsHttpClient: false,
            injectedTransportIsOneShot: true)
    {
        if (transportAssurance
            != TransactionSubmissionTransportAssurance.OneShotWithoutRedirectsOrRetries)
        {
            throw new ArgumentOutOfRangeException(nameof(transportAssurance));
        }
    }

    public Uri BaseUri { get; }

    private HttpClient HttpClient { get; }

    internal ToriiClientOptions Options { get; }

    public void Dispose()
    {
        if (ownsHttpClient)
        {
            HttpClient.Dispose();
        }
    }

    internal async Task<JsonDocument> GetJsonDocumentAsync(string path, string? query = null, CancellationToken cancellationToken = default)
    {
        using var response = await SendAsync(HttpMethod.Get, path, query, content: null, cancellationToken: cancellationToken);
        return await ParseBoundedJsonContentRejectingDuplicatePropertiesAsync(
            response.Content,
            $"Torii JSON response for `{response.RequestMessage?.RequestUri}`",
            cancellationToken);
    }

    internal async Task<TResponse> GetAsync<TResponse>(string path, string? query = null, CancellationToken cancellationToken = default)
    {
        using var response = await SendAsync(HttpMethod.Get, path, query, content: null, cancellationToken: cancellationToken);
        return await DeserializeAsync<TResponse>(response, cancellationToken);
    }

    internal async Task<TResponse> PostAsync<TRequest, TResponse>(
        string path,
        TRequest request,
        string? query = null,
        CancellationToken cancellationToken = default)
    {
        using var content = CreateJsonContent(request);
        using var response = await SendAsync(HttpMethod.Post, path, query, content, cancellationToken: cancellationToken);
        return await DeserializeAsync<TResponse>(response, cancellationToken);
    }

    private async Task<ToriiFeeQuoteResponse> PostFeeQuoteAsync(
        ToriiFeeQuoteRequest request,
        CancellationToken cancellationToken) =>
        await PostBoundedExactJsonAsync<ToriiFeeQuoteRequest, ToriiFeeQuoteResponse>(
            "/v1/fees/quote",
            request,
            FeeQuoteResponseMaxBytes,
            "Fee quote response",
            cancellationToken);

    private async Task<TResponse> PostBoundedExactJsonAsync<TRequest, TResponse>(
        string path,
        TRequest request,
        int maximumResponseBytes,
        string responseContext,
        CancellationToken cancellationToken,
        Action<JsonElement>? validateJson = null)
    {
        using var content = CreateJsonContent(request);
        using var httpRequest = await CreateRequestAsync(
            HttpMethod.Post,
            path,
            query: null,
            content,
            accept: "application/json",
            configureRequest: null,
            cancellationToken);
        using var response = await HttpClient.SendAsync(
            httpRequest,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        var body = await ReadBoundedResponseBodyAsync(
            response.Content,
            maximumResponseBytes,
            responseContext,
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw CreateApiExceptionFromBody(response, body);
        }
        RequireSingleJsonContentType(response.Content, responseContext);

        using var bodyStream = new MemoryStream(body, writable: false);
        using var document = await ParseJsonDocumentRejectingDuplicatePropertiesAsync(
            bodyStream,
            $"Torii response for `{response.RequestMessage?.RequestUri}`",
            cancellationToken);
        validateJson?.Invoke(document.RootElement);
        return document.RootElement.Deserialize<TResponse>(SerializerOptions)
            ?? throw new JsonException(
                $"Torii response for `{response.RequestMessage?.RequestUri}` deserialized to null.");
    }

    private static void RequireSingleJsonContentType(HttpContent content, string context)
    {
        if (!content.Headers.NonValidated.TryGetValues("Content-Type", out var values))
        {
            throw new InvalidDataException(
                $"{context} Content-Type must be application/json.");
        }
        var rawValues = values.ToArray();
        if (rawValues.Length != 1
            || rawValues[0].Contains(',', StringComparison.Ordinal)
            || !MediaTypeHeaderValue.TryParse(rawValues[0], out var contentType)
            || !string.Equals(
                contentType.MediaType,
                "application/json",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"{context} Content-Type must be application/json.");
        }
    }

    private static async Task<byte[]> ReadBoundedResponseBodyAsync(
        HttpContent content,
        int maximumBytes,
        string context,
        CancellationToken cancellationToken)
    {
        if (maximumBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        }
        var declaredLength = content.Headers.ContentLength;
        if (declaredLength.HasValue && declaredLength.Value > maximumBytes)
        {
            throw new InvalidDataException(
                $"{context} exceeds the {maximumBytes}-byte limit.");
        }

        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        var initialCapacity = declaredLength is >= 0 && declaredLength <= maximumBytes
            ? checked((int)declaredLength.Value)
            : Math.Min(maximumBytes, 4 * 1024);
        using var output = new MemoryStream(initialCapacity);
        var buffer = ArrayPool<byte>.Shared.Rent(Math.Min(81_920, maximumBytes + 1));
        try
        {
            while (true)
            {
                var remaining = maximumBytes - checked((int)output.Length);
                var requested = Math.Min(buffer.Length, remaining + 1);
                var count = await stream.ReadAsync(
                    buffer.AsMemory(0, requested),
                    cancellationToken);
                if (count == 0)
                {
                    if (declaredLength == output.Length && output.Capacity == output.Length)
                    {
                        return output.GetBuffer();
                    }
                    return output.ToArray();
                }
                if (count > remaining)
                {
                    throw new InvalidDataException(
                        $"{context} exceeds the {maximumBytes}-byte limit.");
                }

                output.Write(buffer, 0, count);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private async Task<(TResponse Value, HttpStatusCode StatusCode)> PostAccountOnboardingAsync<TRequest, TResponse>(
        string path,
        TRequest request,
        string exactOnboardingToken,
        CancellationToken cancellationToken,
        ulong? preparedExecutionDeadlineUnixMilliseconds = null)
    {
        using var content = CreateJsonContent(request);
        try
        {
            using var response = await SendAsync(
                HttpMethod.Post,
                path,
                query: null,
                content,
                accept: "application/json",
                configureRequest: httpRequest =>
                {
                    httpRequest.Headers.Remove(AccountOnboardingTokenHeaderName);
                    if (!httpRequest.Headers.TryAddWithoutValidation(
                            AccountOnboardingTokenHeaderName,
                            exactOnboardingToken))
                    {
                        throw new InvalidOperationException("Unable to set the account onboarding credential header.");
                    }
                },
                cancellationToken,
                preparedExecutionDeadlineUnixMilliseconds);
            var value = await DeserializeAccountOnboardingAsync<TResponse>(
                response,
                exactOnboardingToken,
                cancellationToken);
            return (value, response.StatusCode);
        }
        catch (ToriiApiException error)
        {
            throw new ToriiApiException(
                error.StatusCode.GetValueOrDefault(HttpStatusCode.InternalServerError),
                error.RequestUri,
                RedactAccountOnboardingCredential(error.ResponseBody, exactOnboardingToken),
                RedactAccountOnboardingCredential(error.ReasonPhrase, exactOnboardingToken),
                RedactAccountOnboardingCredential(error.RejectCode, exactOnboardingToken));
        }
    }

    private async Task<(TResponse Value, HttpStatusCode StatusCode)> PostWithStatusAsync<TRequest, TResponse>(
        string path,
        TRequest request,
        CancellationToken cancellationToken,
        ulong? preparedExecutionDeadlineUnixMilliseconds = null)
    {
        using var content = CreateJsonContent(request);
        using var response = await SendAsync(
            HttpMethod.Post,
            path,
            query: null,
            content,
            accept: "application/json",
            cancellationToken: cancellationToken,
            preparedExecutionDeadlineUnixMilliseconds: preparedExecutionDeadlineUnixMilliseconds);
        var value = await DeserializeAsync<TResponse>(response, cancellationToken);
        return (value, response.StatusCode);
    }

    private async Task<(ToriiAccountOnboardingCurrentStateResponseV1 Value, HttpStatusCode StatusCode)>
        PostAccountOnboardingCurrentStateAsync(
            ToriiAccountOnboardingCurrentStateRequestV1 request,
            CancellationToken cancellationToken)
    {
        using var content = CreateJsonContent(request);
        using var response = await SendAsync(
            HttpMethod.Post,
            "/v1/accounts/onboarding/current-state",
            query: null,
            content,
            accept: "application/json",
            cancellationToken: cancellationToken);
        var value = await DeserializeAccountOnboardingCurrentStateAsync(
            response,
            cancellationToken);
        return (value, response.StatusCode);
    }

    private async Task<ToriiAccountOnboardingCurrentStateResponseV1>
        DeserializeAccountOnboardingCurrentStateAsync(
            HttpResponseMessage response,
            CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is > AccountOnboardingCurrentStateResponseMaxBytesV1)
        {
            throw new JsonException(
                $"Account onboarding current-state response exceeds the {AccountOnboardingCurrentStateResponseMaxBytesV1}-byte limit.");
        }

        var body = new byte[AccountOnboardingCurrentStateResponseMaxBytesV1 + 1];
        var length = 0;
        await using (var stream = await response.Content.ReadAsStreamAsync(cancellationToken))
        {
            while (length < body.Length)
            {
                var read = await stream.ReadAsync(body.AsMemory(length), cancellationToken);
                if (read == 0)
                {
                    break;
                }
                length += read;
            }
        }
        if (length > AccountOnboardingCurrentStateResponseMaxBytesV1)
        {
            throw new JsonException(
                $"Account onboarding current-state response exceeds the {AccountOnboardingCurrentStateResponseMaxBytesV1}-byte limit.");
        }

        using var bodyStream = new MemoryStream(body, 0, length, writable: false);
        using var document = await ParseJsonDocumentRejectingDuplicatePropertiesAsync(
            bodyStream,
            "account onboarding current-state response",
            cancellationToken);
        return document.RootElement.Deserialize<ToriiAccountOnboardingCurrentStateResponseV1>(SerializerOptions)
            ?? throw new JsonException("Account onboarding current-state response deserialized to null.");
    }

    private static string? RedactAccountOnboardingCredential(string? value, string credential) =>
        value?.Replace(credential, "<redacted>", StringComparison.Ordinal);

    private async Task<TResponse> DeserializeAccountOnboardingAsync<TResponse>(
        HttpResponseMessage response,
        string exactOnboardingToken,
        CancellationToken cancellationToken)
    {
        var responseText = await ReadStrictUtf8TextContentAsync(
            response.Content,
            "Torii account onboarding response body",
            cancellationToken);
        var redactedText = RedactAccountOnboardingCredential(responseText, exactOnboardingToken)
            ?? string.Empty;
        JsonDocument parsed;
        try
        {
            parsed = JsonDocument.Parse(redactedText, new JsonDocumentOptions { MaxDepth = 128 });
        }
        catch (JsonException)
        {
            throw new JsonException("Torii account onboarding response body was not valid JSON.");
        }

        using (parsed)
        using (var redactedDocument = RedactAccountOnboardingJson(
                   parsed.RootElement,
                   exactOnboardingToken))
        {
            ToriiIdentifierJson.RejectDuplicateProperties(
                redactedDocument.RootElement,
                DuplicatePropertyContext<TResponse>(response));
            var value = redactedDocument.RootElement.Deserialize<TResponse>(SerializerOptions);
            return value
                ?? throw new JsonException(
                    $"Torii response for `{response.RequestMessage?.RequestUri}` deserialized to null.");
        }
    }

    private static JsonDocument RedactAccountOnboardingJson(
        JsonElement root,
        string exactOnboardingToken)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            WriteRedactedAccountOnboardingJson(writer, root, exactOnboardingToken);
        }
        return JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { MaxDepth = 128 });
    }

    private static void WriteRedactedAccountOnboardingJson(
        Utf8JsonWriter writer,
        JsonElement element,
        string exactOnboardingToken)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject())
                {
                    writer.WritePropertyName(
                        RedactAccountOnboardingCredential(property.Name, exactOnboardingToken)!);
                    WriteRedactedAccountOnboardingJson(
                        writer,
                        property.Value,
                        exactOnboardingToken);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteRedactedAccountOnboardingJson(writer, item, exactOnboardingToken);
                }
                writer.WriteEndArray();
                break;
            case JsonValueKind.String:
                writer.WriteStringValue(
                    RedactAccountOnboardingCredential(element.GetString(), exactOnboardingToken));
                break;
            default:
                element.WriteTo(writer);
                break;
        }
    }

    public async Task<string> GetHealthAsync(CancellationToken cancellationToken = default)
    {
        using var response = await SendAsync(HttpMethod.Get, "/v1/health", cancellationToken: cancellationToken);
        return await ReadStrictUtf8TextContentAsync(response.Content, "Torii health response body", cancellationToken);
    }

    /// <summary>Read one exact currently materialized account.</summary>
    public async Task<ToriiAccountReadResponse> GetAccountReadAsync(
        string accountId,
        CancellationToken cancellationToken = default)
    {
        var exactAccountId = ToriiAccountFaucetPow.RequireExactAccountId(
            accountId,
            nameof(accountId),
            chainDiscriminant: null);
        var response = await GetAsync<ToriiAccountReadResponse>(
            $"/v1/accounts/{Uri.EscapeDataString(exactAccountId)}",
            cancellationToken: cancellationToken);
        ValidateAccountReadResponse(response, exactAccountId, "account read response");
        return response;
    }

    public async Task<ToriiExplorerAccountQrSnapshot> GetExplorerAccountQrAsync(
        string accountId,
        CancellationToken cancellationToken = default)
    {
        var encodedAccountId = EncodeIdentifierPathSegment(accountId, nameof(accountId));
        var response = await GetAsync<ToriiExplorerAccountQrSnapshot>(
            $"/v1/explorer/accounts/{encodedAccountId}/qr",
            cancellationToken: cancellationToken);
        ValidateExplorerAccountQrSnapshot(response, "explorer account QR response");
        return response;
    }

    public async Task<ToriiExplorerAccount> GetExplorerAccountAsync(
        string accountId,
        CancellationToken cancellationToken = default)
    {
        var response = await GetAsync<ToriiExplorerAccount>(
            $"/v1/explorer/accounts/{EncodeIdentifierPathSegment(accountId, nameof(accountId))}",
            cancellationToken: cancellationToken);
        ValidateExplorerAccount(response, "explorer account response");
        return response;
    }

    public async Task<ToriiExplorerDomain> GetExplorerDomainAsync(
        string domainId,
        CancellationToken cancellationToken = default)
    {
        var response = await GetAsync<ToriiExplorerDomain>(
            $"/v1/explorer/domains/{EncodeIdentifierPathSegment(domainId, nameof(domainId))}",
            cancellationToken: cancellationToken);
        ValidateExplorerDomain(response, "explorer domain response");
        return response;
    }

    public async Task<ToriiExplorerAssetDefinition> GetExplorerAssetDefinitionAsync(
        string definitionId,
        CancellationToken cancellationToken = default)
    {
        var response = await GetAsync<ToriiExplorerAssetDefinition>(
            $"/v1/explorer/asset-definitions/{EncodeIdentifierPathSegment(definitionId, nameof(definitionId))}",
            cancellationToken: cancellationToken);
        ValidateExplorerAssetDefinition(response, "explorer asset definition response");
        return response;
    }

    public async Task<ToriiExplorerAssetDefinitionEconometrics> GetExplorerAssetDefinitionEconometricsAsync(
        string definitionId,
        CancellationToken cancellationToken = default)
    {
        var response = await GetAsync<ToriiExplorerAssetDefinitionEconometrics>(
            $"/v1/explorer/asset-definitions/{EncodeIdentifierPathSegment(definitionId, nameof(definitionId))}/econometrics",
            cancellationToken: cancellationToken);
        ValidateExplorerAssetDefinitionEconometrics(response, "explorer asset definition econometrics response");
        return response;
    }

    public async Task<ToriiExplorerAssetDefinitionSnapshot> GetExplorerAssetDefinitionSnapshotAsync(
        string definitionId,
        CancellationToken cancellationToken = default)
    {
        var response = await GetAsync<ToriiExplorerAssetDefinitionSnapshot>(
            $"/v1/explorer/asset-definitions/{EncodeIdentifierPathSegment(definitionId, nameof(definitionId))}/snapshot",
            cancellationToken: cancellationToken);
        ValidateExplorerAssetDefinitionSnapshot(response, "explorer asset definition snapshot response");
        return response;
    }

    public async Task<ToriiExplorerAsset> GetExplorerAssetAsync(
        string assetId,
        CancellationToken cancellationToken = default)
    {
        var response = await GetAsync<ToriiExplorerAsset>(
            $"/v1/explorer/assets/{EncodeIdentifierPathSegment(assetId, nameof(assetId))}",
            cancellationToken: cancellationToken);
        ValidateExplorerAsset(response, "explorer asset response");
        return response;
    }

    public async Task<ToriiExplorerNft> GetExplorerNftAsync(
        string nftId,
        CancellationToken cancellationToken = default)
    {
        var response = await GetAsync<ToriiExplorerNft>(
            $"/v1/explorer/nfts/{EncodeIdentifierPathSegment(nftId, nameof(nftId))}",
            cancellationToken: cancellationToken);
        ValidateExplorerNft(response, "explorer nft response");
        return response;
    }

    public async Task<ToriiExplorerRwa> GetExplorerRwaAsync(
        string rwaId,
        CancellationToken cancellationToken = default)
    {
        var response = await GetAsync<ToriiExplorerRwa>(
            $"/v1/explorer/rwas/{EncodeIdentifierPathSegment(rwaId, nameof(rwaId))}",
            cancellationToken: cancellationToken);
        ValidateExplorerRwa(response, "explorer rwa response");
        return response;
    }

    public async Task<ToriiExplorerBlock> GetExplorerBlockAsync(
        string identifier,
        CancellationToken cancellationToken = default)
    {
        var response = await GetAsync<ToriiExplorerBlock>(
            $"/v1/explorer/blocks/{EncodeIdentifierPathSegment(identifier, nameof(identifier))}",
            cancellationToken: cancellationToken);
        ValidateExplorerBlock(response, "explorer block response");
        return response;
    }

    public async Task<ToriiExplorerTransactionDetail> GetExplorerTransactionAsync(
        string transactionHash,
        CancellationToken cancellationToken = default)
    {
        var response = await GetAsync<ToriiExplorerTransactionDetail>(
            $"/v1/explorer/transactions/{EncodeIdentifierPathSegment(transactionHash, nameof(transactionHash))}",
            cancellationToken: cancellationToken);
        ValidateExplorerTransactionDetail(response, "explorer transaction response");
        return response;
    }

    public async Task<ToriiExplorerInstruction> GetExplorerInstructionAsync(
        string transactionHash,
        ulong index,
        CancellationToken cancellationToken = default)
    {
        var response = await GetAsync<ToriiExplorerInstruction>(
            $"/v1/explorer/instructions/{EncodeIdentifierPathSegment(transactionHash, nameof(transactionHash))}/{index.ToString(CultureInfo.InvariantCulture)}",
            cancellationToken: cancellationToken);
        ValidateExplorerInstruction(response, "explorer instruction response");
        return response;
    }

    public async Task<ToriiContractCodeView> GetExplorerInstructionContractViewAsync(
        string transactionHash,
        ulong index,
        CancellationToken cancellationToken = default)
    {
        var response = await GetAsync<ToriiContractCodeView>(
            $"/v1/explorer/instructions/{EncodeIdentifierPathSegment(transactionHash, nameof(transactionHash))}/{index.ToString(CultureInfo.InvariantCulture)}/contract-view",
            cancellationToken: cancellationToken);
        ValidateContractCodeView(response, "explorer instruction contract-view response");
        return response;
    }

    public async Task<ToriiExplorerHealthSnapshot> GetExplorerHealthAsync(CancellationToken cancellationToken = default)
    {
        var response = await GetAsync<ToriiExplorerHealthSnapshot>(
            "/v1/explorer/health",
            cancellationToken: cancellationToken);
        ValidateExplorerHealthSnapshot(response, "explorer health response");
        return response;
    }

    public async Task<ToriiExplorerMetricsSnapshot> GetExplorerMetricsAsync(CancellationToken cancellationToken = default)
    {
        var response = await GetAsync<ToriiExplorerMetricsSnapshot>(
            "/v1/explorer/metrics",
            cancellationToken: cancellationToken);
        ValidateExplorerMetricsSnapshot(response, "explorer metrics response");
        return response;
    }

    public async Task<ToriiAccountAliasLookupResponse?> LookupAliasesByAccountAsync(
        string accountId,
        string? dataspace = null,
        string? domain = null,
        CancellationToken cancellationToken = default)
    {
        var response = await PostOptionalAsync<ToriiAccountAliasLookupRequest, ToriiAccountAliasLookupResponse>(
            "/v1/aliases/by-account",
            new ToriiAccountAliasLookupRequest
            {
                AccountId = ToriiAccountFaucetPow.RequireExactAccountId(accountId, nameof(accountId)),
                Dataspace = NormalizeOptionalExactValue(dataspace, nameof(dataspace)),
                Domain = NormalizeOptionalExactValue(domain, nameof(domain)),
            },
            cancellationToken);
        if (response is not null)
        {
            ValidateAccountAliasLookupResponse(response, "account alias lookup response");
        }

        return response;
    }

    public async Task<ToriiIdentifierPoliciesResponse> GetIdentifierPoliciesAsync(CancellationToken cancellationToken = default)
    {
        ToriiIdentifierPoliciesResponse response;
        try
        {
            response = await GetAsync<ToriiIdentifierPoliciesResponse>(
                "/v1/identifier-policies",
                cancellationToken: cancellationToken);
        }
        catch (JsonException exception)
        {
            throw RewriteIdentifierPoliciesJsonException(exception);
        }

        ValidateIdentifierPoliciesResponse(response);
        return response;
    }

    public async Task<ToriiAccountAliasIndexResolution?> ResolveAccountAliasIndexAsync(
        ulong index,
        CancellationToken cancellationToken = default)
    {
        var response = await PostOptionalAsync<ToriiAliasResolveIndexRequest, ToriiAccountAliasIndexResolution>(
            "/v1/aliases/resolve-index",
            new ToriiAliasResolveIndexRequest
            {
                Index = index,
            },
            cancellationToken);
        if (response is not null)
        {
            ValidateAccountAliasIndexResolution(response, "account alias index response");
        }

        return response;
    }

    public async Task<ToriiUaidPortfolioResponse> GetUaidPortfolioAsync(
        string uaid,
        ToriiUaidPortfolioQuery? query = null,
        CancellationToken cancellationToken = default)
    {
        var normalizedUaid = NormalizeUaidLiteral(uaid);
        var response = await GetAsync<ToriiUaidPortfolioResponse>(
            $"/v1/accounts/{EncodePathSegment(normalizedUaid)}/portfolio",
            BuildQueryString([
                new KeyValuePair<string, string?>(
                    "asset_id",
                    query?.AssetId is null
                        ? null
                        : ToriiUaidDirectMetadata.RequireCanonicalAssetId(
                            query.AssetId,
                            nameof(ToriiUaidPortfolioQuery.AssetId)).Literal),
            ]),
            cancellationToken);
        ValidateUaidPortfolioResponse(response, "UAID portfolio response");
        if (!string.Equals(response.Uaid, normalizedUaid, StringComparison.Ordinal))
        {
            throw new JsonException("UAID portfolio response.uaid must match the requested UAID.");
        }
        return response;
    }

    public async Task<ToriiUaidBindingsResponse> GetUaidBindingsAsync(
        string uaid,
        CancellationToken cancellationToken = default)
    {
        var normalizedUaid = NormalizeUaidLiteral(uaid);
        var response = await GetAsync<ToriiUaidBindingsResponse>(
            $"/v1/space-directory/uaids/{EncodePathSegment(normalizedUaid)}",
            cancellationToken: cancellationToken);
        ValidateUaidBindingsResponse(response, "UAID bindings response");
        if (!string.Equals(response.Uaid, normalizedUaid, StringComparison.Ordinal))
        {
            throw new JsonException("UAID bindings response.uaid must match the requested UAID.");
        }
        return response;
    }

    public async Task<ToriiAccountOnboardingPlanReceipt> PlanAccountOnboardingAsync(
        ToriiAccountOnboardingPlanRequest request,
        string onboardingToken,
        string expectedAuthority,
        NetworkId expectedNetworkId,
        ToriiAccountOnboardingPlanBodyEncoder canonicalBodyEncoder,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var exactOnboardingToken = RequireAccountOnboardingToken(onboardingToken);
        var normalizedRequest = NormalizeAccountOnboardingPlanRequest(request);

        var (receipt, statusCode) = await PostAccountOnboardingAsync<ToriiAccountOnboardingPlanRequest, ToriiAccountOnboardingPlanReceipt>(
            "/v1/accounts/onboard/plan",
            normalizedRequest,
            exactOnboardingToken,
            cancellationToken: cancellationToken);
        RequireExactPreparedStatus(statusCode, HttpStatusCode.OK, "account onboarding plan");

        ToriiAccountOnboardingReceiptVerifier.RequirePinned(
            receipt,
            expectedAuthority,
            expectedNetworkId,
            canonicalBodyEncoder);
        RequireMatchingAccountOnboardingRequest(
            normalizedRequest,
            receipt.Body.Request,
            nameof(receipt));
        return receipt;
    }

    public async Task<ToriiAccountOnboardingPrepareResultV1> PrepareAccountOnboardingAsync(
        ToriiAccountOnboardingPlanRequest expectedRequest,
        ToriiAccountOnboardingPlanReceipt receipt,
        ToriiPreparedOperationBindingV1 binding,
        FeePaymentIntent feePayment,
        string onboardingToken,
        string expectedAuthority,
        NetworkId expectedNetworkId,
        ToriiAccountOnboardingPlanBodyEncoder canonicalBodyEncoder,
        CancellationToken cancellationToken = default)
    {
        var exactExpectedRequest = NormalizeAccountOnboardingPlanRequest(expectedRequest);
        ToriiAccountOnboardingReceiptVerifier.RequirePinned(
            receipt,
            expectedAuthority,
            expectedNetworkId,
            canonicalBodyEncoder);
        RequireMatchingAccountOnboardingRequest(
            exactExpectedRequest,
            receipt.Body.Request,
            "account onboarding receipt");
        var exactOnboardingToken = RequireAccountOnboardingToken(onboardingToken);
        var exactBinding = NormalizePreparedOperationBinding(
            binding,
            ToriiAccountOnboardingPreparedTransactionV1.OperationV1,
            requireActive: true);
        ValidatePreparedSemanticBinding(
            exactBinding,
            receipt.PlanHash.Substring(5, 64).ToLowerInvariant(),
            receipt.Body.ValidUntilMilliseconds);
        var exactFeePayment = NormalizeFeePaymentIntent(
            feePayment,
            nameof(feePayment),
            requireGasLimit: false);
        var (response, statusCode) = await PostAccountOnboardingAsync<ToriiAccountOnboardingPrepareRequestV1, JsonElement>(
            "/v1/accounts/onboard/prepare",
            new ToriiAccountOnboardingPrepareRequestV1(
                exactBinding,
                receipt,
                exactFeePayment),
            exactOnboardingToken,
            cancellationToken: cancellationToken);
        RequireExactPreparedStatus(statusCode, HttpStatusCode.OK, "account onboarding prepare");

        var schema = RequirePreparedResponseSchema(response, "account onboarding prepare response");
        if (string.Equals(
                schema,
                ToriiAccountOnboardingPreparedTransactionV1.SchemaV1,
                StringComparison.Ordinal))
        {
            var prepared = response.Deserialize<ToriiAccountOnboardingPreparedTransactionV1>(SerializerOptions)
                ?? throw new JsonException("account onboarding prepared response deserialized to null.");
            VerifyAccountOnboardingPreparedTransactionV1(
                prepared,
                exactExpectedRequest,
                receipt,
                exactBinding,
                exactFeePayment,
                expectedAuthority,
                expectedNetworkId,
                canonicalBodyEncoder);
            return ToriiAccountOnboardingPrepareResultV1.FromPrepared(prepared);
        }
        if (string.Equals(
                schema,
                ToriiAccountOnboardingProofRequiredPrepareResponseV1.SchemaV1,
                StringComparison.Ordinal))
        {
            var proofRequired = response.Deserialize<ToriiAccountOnboardingProofRequiredPrepareResponseV1>(SerializerOptions)
                ?? throw new JsonException("account onboarding proof-required response deserialized to null.");
            ValidateProofRequiredAccountOnboarding(
                proofRequired,
                exactExpectedRequest,
                receipt,
                exactBinding,
                expectedAuthority,
                expectedNetworkId,
                canonicalBodyEncoder);
            return ToriiAccountOnboardingPrepareResultV1.FromProofRequired(proofRequired);
        }
        throw new JsonException($"account onboarding prepare response has unsupported schema `{schema}`.");
    }

    /// <summary>
    /// Re-authenticate a retained proof-required result and perform one atomic state observation.
    /// </summary>
    /// <remarks>
    /// The proof-required envelope is nonterminal. Only a successful fresh call to this method
    /// observes the expected account and exact alias from one committed state snapshot. The
    /// returned classification distinguishes an applied alias, an absent alias, and a conflicting
    /// alias target without treating the nonterminal cases as transport failures.
    /// </remarks>
    public async Task<ToriiAccountOnboardingCurrentStateProofV1> ProveAccountOnboardingCurrentStateAsync(
        ToriiAccountOnboardingPlanRequest expectedRequest,
        ToriiAccountOnboardingProofRequiredPrepareResponseV1 proofRequired,
        ToriiAccountOnboardingPlanReceipt receipt,
        ToriiPreparedOperationBindingV1 binding,
        string expectedAuthority,
        NetworkId expectedNetworkId,
        ToriiAccountOnboardingPlanBodyEncoder canonicalBodyEncoder,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expectedNetworkId);
        ValidateProofRequiredAccountOnboarding(
            proofRequired,
            NormalizeAccountOnboardingPlanRequest(expectedRequest),
            receipt,
            binding,
            expectedAuthority,
            expectedNetworkId,
            canonicalBodyEncoder);

        var request = new ToriiAccountOnboardingCurrentStateRequestV1
        {
            AccountId = proofRequired.AccountId,
            Alias = proofRequired.Alias,
        };
        var (observation, statusCode) = await PostAccountOnboardingCurrentStateAsync(
            request,
            cancellationToken);
        RequireExactPreparedStatus(
            statusCode,
            HttpStatusCode.OK,
            "account onboarding current-state observation");
        var kind = ValidateAccountOnboardingCurrentState(
            observation,
            request,
            expectedNetworkId);

        return new ToriiAccountOnboardingCurrentStateProofV1(
            proofRequired,
            observation,
            kind);
    }

    public async Task<ToriiPreparedTransactionSubmitResponseV1> SubmitPreparedAccountOnboardingAsync(
        ToriiAccountOnboardingPlanRequest expectedRequest,
        ToriiAccountOnboardingPreparedTransactionV1 prepared,
        FeePaymentIntent expectedFeePayment,
        string onboardingToken,
        string expectedAuthority,
        NetworkId expectedNetworkId,
        ToriiAccountOnboardingPlanBodyEncoder canonicalBodyEncoder,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(prepared);
        var exactExpectedFeePayment = NormalizeFeePaymentIntent(
            expectedFeePayment,
            nameof(expectedFeePayment),
            requireGasLimit: false);
        var exactOnboardingToken = RequireAccountOnboardingToken(onboardingToken);
        VerifyAccountOnboardingPreparedTransactionV1(
            prepared,
            NormalizeAccountOnboardingPlanRequest(expectedRequest),
            prepared.Receipt,
            prepared.Binding,
            exactExpectedFeePayment,
            expectedAuthority,
            expectedNetworkId,
            canonicalBodyEncoder);
        var (response, statusCode) = await PostAccountOnboardingAsync<
            ToriiAccountOnboardingPreparedTransactionV1,
            ToriiPreparedTransactionSubmitResponseV1>(
                "/v1/accounts/onboard",
                prepared,
                exactOnboardingToken,
                cancellationToken,
                prepared.Binding.ExecutionExpiresAtUnixMilliseconds);
        ValidatePreparedSubmitResponse(
            response,
            prepared.Binding,
            ToriiAccountOnboardingPreparedTransactionV1.OperationV1,
            prepared.TransactionHashHex,
            statusCode,
            "account onboarding prepared submit response");
        return response;
    }

    public async Task<ToriiAccountFaucetPuzzle> GetAccountFaucetPuzzleAsync(CancellationToken cancellationToken = default)
    {
        var response = await GetAsync<ToriiAccountFaucetPuzzle>(
            "/v1/accounts/faucet/puzzle",
            cancellationToken: cancellationToken);
        ValidateAccountFaucetPuzzle(response, "account faucet puzzle response");
        return response;
    }

    public async Task<ToriiAccountFaucetSolution> SolveAccountFaucetAsync(
        string accountId,
        ToriiAccountFaucetSolveOptions? solveOptions = null,
        CancellationToken cancellationToken = default)
    {
        var puzzle = await GetAccountFaucetPuzzleAsync(cancellationToken);
        return ToriiAccountFaucetPow.Solve(accountId, puzzle, solveOptions, cancellationToken);
    }

    public async Task<ToriiAccountFaucetPreparedTransactionV1> PrepareAccountFaucetAsync(
        ToriiAccountFaucetClaimV1 claim,
        ToriiPreparedOperationBindingV1 binding,
        FeePaymentIntent feePayment,
        ToriiAccountFaucetPolicyV1 policy,
        NetworkId expectedNetworkId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(claim);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(expectedNetworkId);
        var normalizedClaim = NormalizeAccountFaucetClaim(claim);
        var exactBinding = NormalizePreparedOperationBinding(
            binding,
            ToriiAccountFaucetPreparedTransactionV1.OperationV1,
            requireActive: true);
        ValidatePreparedSemanticBinding(exactBinding, FaucetClaimSemanticHashHex(normalizedClaim), ulong.MaxValue);
        var exactFeePayment = NormalizeFeePaymentIntent(
            feePayment,
            nameof(feePayment),
            requireGasLimit: false);
        var (response, statusCode) = await PostWithStatusAsync<ToriiAccountFaucetPrepareRequestV1, ToriiAccountFaucetPreparedTransactionV1>(
            "/v1/accounts/faucet/prepare",
            new ToriiAccountFaucetPrepareRequestV1(
                exactBinding,
                normalizedClaim,
                exactFeePayment),
            cancellationToken);
        RequireExactPreparedStatus(statusCode, HttpStatusCode.OK, "account faucet prepare");
        VerifyAccountFaucetPreparedTransactionV1(
            response,
            normalizedClaim,
            exactBinding,
            exactFeePayment,
            policy,
            expectedNetworkId);
        return response;
    }

    public async Task<ToriiPreparedTransactionSubmitResponseV1> SubmitPreparedAccountFaucetAsync(
        ToriiAccountFaucetPreparedTransactionV1 prepared,
        FeePaymentIntent expectedFeePayment,
        ToriiAccountFaucetPolicyV1 policy,
        NetworkId expectedNetworkId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(prepared);
        ArgumentNullException.ThrowIfNull(policy);
        var exactExpectedFeePayment = NormalizeFeePaymentIntent(
            expectedFeePayment,
            nameof(expectedFeePayment),
            requireGasLimit: false);
        VerifyAccountFaucetPreparedTransactionV1(
            prepared,
            prepared.Claim,
            prepared.Binding,
            exactExpectedFeePayment,
            policy,
            expectedNetworkId);
        var (response, statusCode) = await PostWithStatusAsync<
            ToriiAccountFaucetPreparedTransactionV1,
            ToriiPreparedTransactionSubmitResponseV1>(
                "/v1/accounts/faucet",
                prepared,
                cancellationToken,
                prepared.Binding.ExecutionExpiresAtUnixMilliseconds);
        ValidatePreparedSubmitResponse(
            response,
            prepared.Binding,
            ToriiAccountFaucetPreparedTransactionV1.OperationV1,
            prepared.TransactionHashHex,
            statusCode,
            "account faucet prepared submit response");
        return response;
    }

    public async Task<ToriiVpnProfile> GetVpnProfileAsync(CancellationToken cancellationToken = default)
    {
        RequireSecureVpnTransport();
        using var response = await SendExpectingStatusAsync(
            HttpMethod.Get,
            "/v1/vpn/profile",
            query: null,
            content: null,
            HttpStatusCode.OK,
            allowedStatusCode: null,
            cancellationToken);
        var profile = await DeserializeAsync<ToriiVpnProfile>(response, cancellationToken);
        ValidateVpnProfile(profile, "vpn profile response");
        return profile;
    }

    public async Task<ToriiVpnQuote> CreateVpnQuoteAsync(
        ToriiVpnQuoteCreateRequest request,
        CancellationToken cancellationToken = default)
    {
        RequireVpnCanonicalRequestCredentials("/v1/vpn/quotes");
        ArgumentNullException.ThrowIfNull(request);
        var normalizedRequest = NormalizeVpnQuoteCreateRequest(request);

        using var content = CreateJsonContent(normalizedRequest);
        using var httpResponse = await SendExpectingStatusAsync(
            HttpMethod.Post,
            "/v1/vpn/quotes",
            query: null,
            content,
            HttpStatusCode.Created,
            allowedStatusCode: null,
            cancellationToken);
        var response = await DeserializeAsync<ToriiVpnQuote>(httpResponse, cancellationToken);
        ValidateVpnQuote(response, "vpn quote response");
        return response;
    }

    public async Task<ToriiVpnSession> CreateVpnSessionAsync(
        ToriiVpnSessionCreateRequest request,
        CancellationToken cancellationToken = default)
    {
        RequireVpnCanonicalRequestCredentials("/v1/vpn/sessions");
        ArgumentNullException.ThrowIfNull(request);
        var normalizedRequest = NormalizeVpnSessionCreateRequest(request);

        using var content = CreateJsonContent(normalizedRequest);
        using var httpResponse = await SendExpectingStatusAsync(
            HttpMethod.Post,
            "/v1/vpn/sessions",
            query: null,
            content,
            HttpStatusCode.Created,
            allowedStatusCode: null,
            cancellationToken);
        var response = await DeserializeAsync<ToriiVpnSession>(httpResponse, cancellationToken);
        ValidateVpnSession(response, "vpn session response");
        return response;
    }

    public async Task<ToriiVpnSession?> GetVpnSessionAsync(
        string sessionId,
        CancellationToken cancellationToken = default)
    {
        RequireVpnCanonicalRequestCredentials("/v1/vpn/sessions/{session_id}");
        var encodedSessionId = EncodeVpnSessionPathSegment(sessionId, nameof(sessionId));
        using var response = await SendExpectingStatusAsync(
            HttpMethod.Get,
            $"/v1/vpn/sessions/{encodedSessionId}",
            query: null,
            content: null,
            HttpStatusCode.OK,
            HttpStatusCode.NotFound,
            cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        var session = await DeserializeAsync<ToriiVpnSession>(response, cancellationToken);
        ValidateVpnSession(session, "vpn session response");
        return session;
    }

    public async Task<ToriiVpnReceipt> SubmitVpnReceiptAsync(
        ToriiVpnReceiptSubmitRequest request,
        CancellationToken cancellationToken = default)
    {
        RequireVpnCanonicalRequestCredentials("/v1/vpn/receipts");
        ArgumentNullException.ThrowIfNull(request);
        var normalizedRequest = NormalizeVpnReceiptSubmitRequest(request);

        using var content = CreateJsonContent(normalizedRequest);
        using var httpResponse = await SendExpectingStatusAsync(
            HttpMethod.Post,
            "/v1/vpn/receipts",
            query: null,
            content,
            HttpStatusCode.Created,
            allowedStatusCode: null,
            cancellationToken);
        var response = await DeserializeAsync<ToriiVpnReceipt>(httpResponse, cancellationToken);
        ValidateVpnReceipt(response, "vpn receipt response");
        return response;
    }

    public async Task<ToriiVpnReceiptListResponse> ListVpnReceiptsAsync(CancellationToken cancellationToken = default)
    {
        RequireVpnCanonicalRequestCredentials("/v1/vpn/receipts");
        using var httpResponse = await SendExpectingStatusAsync(
            HttpMethod.Get,
            "/v1/vpn/receipts",
            query: null,
            content: null,
            HttpStatusCode.OK,
            allowedStatusCode: null,
            cancellationToken);
        var response = await DeserializeAsync<ToriiVpnReceiptListResponse>(httpResponse, cancellationToken);
        ValidateVpnReceiptListResponse(response, "vpn receipt list response");
        return response;
    }

    public async Task<ToriiAssetAliasResolution?> ResolveAssetAliasAsync(string alias, CancellationToken cancellationToken = default)
    {
        var response = await PostOptionalAsync<ToriiAliasResolutionRequest, ToriiAssetAliasResolution>(
            "/v1/assets/aliases/resolve",
            new ToriiAliasResolutionRequest
            {
                Alias = NormalizeExactValue(alias, nameof(alias)),
            },
            cancellationToken);
        if (response is not null)
        {
            ValidateAssetAliasResolution(response, "asset alias resolution response");
        }

        return response;
    }

    public async Task<ToriiAccountAliasResolution?> ResolveAccountAliasAsync(string alias, CancellationToken cancellationToken = default)
    {
        var response = await PostOptionalAsync<ToriiAliasResolutionRequest, ToriiAccountAliasResolution>(
            "/v1/aliases/resolve",
            new ToriiAliasResolutionRequest
            {
                Alias = NormalizeExactValue(alias, nameof(alias)),
            },
            cancellationToken);
        if (response is not null)
        {
            ValidateAccountAliasResolution(response, "account alias resolution response");
        }

        return response;
    }

    public async Task<ToriiContractAliasResolution?> ResolveContractAliasAsync(
        string contractAlias,
        CancellationToken cancellationToken = default)
    {
        var response = await PostOptionalAsync<ToriiContractAliasResolutionRequest, ToriiContractAliasResolution>(
            "/v1/contracts/aliases/resolve",
            new ToriiContractAliasResolutionRequest
            {
                ContractAlias = NormalizeExactValue(contractAlias, nameof(contractAlias)),
            },
            cancellationToken);
        if (response is not null)
        {
            ValidateContractAliasResolution(response, "contract alias resolution response");
        }

        return response;
    }

    public async Task<ToriiContractCodeRecord> GetContractCodeAsync(
        ContractArtifactId artifactId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(artifactId);
        RequireCanonicalRequestCredentials(artifactId.Route);

        var response = await GetAsync<ToriiContractCodeRecord>(
            artifactId.Route,
            cancellationToken: cancellationToken);
        ValidateContractCodeRecord(response, "contract code response");
        ValidateContractArtifactResponse(response.NetworkId, response.ArtifactId, artifactId);
        return response;
    }

    public async Task<ToriiContractCodeBytesResponse> GetContractCodeBytesResponseAsync(
        ContractArtifactId artifactId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(artifactId);
        RequireCanonicalRequestCredentials(artifactId.Route);

        var response = await GetAsync<ToriiContractCodeBytesResponse>(
            artifactId.Route + "/bytes",
            cancellationToken: cancellationToken);

        var bytes = response.DecodeBytes();
        ValidateContractArtifactResponse(response.NetworkId, response.ArtifactId, artifactId);
        var domain = Encoding.UTF8.GetBytes("iroha:ivm:contract-artifact:v1\0");
        var committed = new byte[domain.Length + bytes.Length];
        domain.CopyTo(committed, 0);
        bytes.CopyTo(committed, domain.Length);
        if (!CryptographicOperations.FixedTimeEquals(IrohaHash.Hash(committed), Convert.FromHexString(artifactId.CodeHashHex)))
            throw new JsonException("contract code-byte response does not match its artifact_id code_hash.");
        return response;
    }

    public async Task<byte[]> GetContractCodeBytesAsync(
        ContractArtifactId artifactId,
        CancellationToken cancellationToken = default)
    {
        var response = await GetContractCodeBytesResponseAsync(artifactId, cancellationToken);
        return response.DecodeBytes();
    }

    public async Task<ToriiGovernedContractResponse> GetGovernedContractAsync(
        string contractAddress,
        CancellationToken cancellationToken = default)
    {
        var normalizedContractAddress = NormalizeExactValue(contractAddress, nameof(contractAddress));
        if (!ContractAddressV1.IsCanonical(normalizedContractAddress))
        {
            throw new ArgumentException(
                "Contract address must be a canonical V1 `irohac` Bech32m literal.",
                nameof(contractAddress));
        }
        var route = $"/v1/gov/contracts/{EncodePathSegment(normalizedContractAddress)}";
        RequireCanonicalRequestCredentials(route);

        var response = await GetAsync<ToriiGovernedContractResponse>(
            route,
            cancellationToken: cancellationToken);
        ValidateGovernedContractResponse(response, "governed contract response");
        return response;
    }

    public async Task<ToriiContractStateResponse> GetContractStateAsync(
        ToriiContractStateQuery query,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        var response = await GetAsync<ToriiContractStateResponse>(
            "/v1/contracts/state",
            BuildContractStateQuery(query),
            cancellationToken);

        ValidateContractStateResponse(response, "contract state response");
        return response;
    }

    public async Task<ToriiContractCallResponse> CallContractAsync(
        ToriiContractCallRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var normalizedRequest = NormalizeContractCallRequest(request);
        RequireCanonicalRequestCredentials("/v1/contracts/call");
        if (!AccountIdsHaveSameIdentity(
                Options.CanonicalRequestCredentials!.AccountId,
                normalizedRequest.Authority))
        {
            throw new InvalidOperationException("Canonical request account must identify the contract-call authority.");
        }
        if (normalizedRequest.TransactionPayloadBase64 is not null)
        {
            var payload = Convert.FromBase64String(normalizedRequest.TransactionPayloadBase64);
            ValidateContractTransactionPayload(
                payload,
                normalizedRequest,
                normalizedRequest.CreationTimeMilliseconds!.Value,
                normalizedRequest.FeePayment,
                "detached contract call");
            var publicKey = Convert.FromHexString(normalizedRequest.PublicKeyHex!);
            var signature = Convert.FromBase64String(normalizedRequest.SignatureBase64!);
            if (!publicKey.AsSpan().SequenceEqual(
                    PreparedEd25519PublicKeyFromAccountId(normalizedRequest.Authority, "detached contract call"))
                || signature.Length != Ed25519Signer.SignatureLength
                || !Ed25519Signer.Verify(IrohaHash.Hash(payload), signature, publicKey))
            {
                throw new ArgumentException("Detached contract-call signature does not authorize the exact retained payload.");
            }
        }

        var response = await PostAsync<ToriiContractCallRequest, ToriiContractCallResponse>(
            "/v1/contracts/call",
            normalizedRequest,
            cancellationToken: cancellationToken);
        ValidateContractCallResponse(response, normalizedRequest, "contract call response");
        return response;
    }

    /// <summary>Quotes the exact unsigned transaction payload using account-signed Torii auth.</summary>
    public async Task<ToriiFeeQuoteResponse> QuoteFeesAsync(
        UnsignedTransactionPayload payload,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);
        RequireCanonicalRequestCredentials("/v1/fees/quote");
        var requestAccount = Options.CanonicalRequestCredentials!.AccountId;
        if (!CanonicalRequest.IsCanonicalAsciiAccountAlias(requestAccount)
            && !AccountIdsHaveSameIdentity(requestAccount, payload.Authority))
        {
            throw new InvalidOperationException(
                "Canonical request account must identify the unsigned transaction authority.");
        }

        var response = await PostFeeQuoteAsync(
            new ToriiFeeQuoteRequest { Payload = payload },
            cancellationToken);
        ValidateFeeQuoteResponse(
            response,
            payload.FeePayment,
            payload.Authority,
            "fee quote response");
        return response;
    }

    /// <summary>Looks up one exact on-chain sponsor program using account-signed Torii auth.</summary>
    public async Task<ToriiFeeSponsorProgram> GetFeeSponsorProgramAsync(
        FeeSponsorProgramId programId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(programId);
        RequireCanonicalRequestCredentials("/v1/fee-sponsor-programs/by-id");
        var response = await PostBoundedExactJsonAsync<
            ToriiFeeSponsorProgramLookupRequest,
            ToriiFeeSponsorProgram>(
            "/v1/fee-sponsor-programs/by-id",
            new ToriiFeeSponsorProgramLookupRequest { ProgramId = programId.ToString() },
            FeeSponsorProgramResponseMaxBytes,
            "Fee sponsor program response",
            cancellationToken,
            ValidateFeeSponsorProgramJson);
        ValidateFeeSponsorProgramResponse(response, programId);
        return response;
    }

    public async Task<ToriiContractCodeView> GetContractCodeViewAsync(
        ContractArtifactId artifactId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(artifactId);
        RequireCanonicalRequestCredentials(artifactId.Route);

        var response = await GetAsync<ToriiContractCodeView>(
            artifactId.Route + "/contract-view",
            cancellationToken: cancellationToken);
        ValidateContractCodeView(response, "contract code-view response");
        ValidateContractArtifactResponse(response.NetworkId, response.ArtifactId, artifactId);
        return response;
    }

    public async Task<ToriiContractViewExecutionResult> ExecuteContractViewAsync(
        ToriiContractViewRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var normalizedRequest = NormalizeContractViewRequest(request);

        using var content = CreateJsonContent(normalizedRequest);
        using var response = await SendAllowingStatusAsync(
            HttpMethod.Post,
            "/v1/contracts/view",
            query: null,
            content,
            HttpStatusCode.UnprocessableEntity,
            cancellationToken);

        if (response.StatusCode == HttpStatusCode.UnprocessableEntity)
        {
            var error = await DeserializeAsync<ToriiContractViewErrorResponse>(response, cancellationToken);
            ValidateContractViewErrorResponse(error, "contract view error response");
            return new ToriiContractViewExecutionResult
            {
                Error = error,
            };
        }

        var success = await DeserializeAsync<ToriiContractViewResponse>(response, cancellationToken);
        ValidateContractViewResponse(success, "contract view response");
        return new ToriiContractViewExecutionResult
        {
            Success = success,
        };
    }

    public async Task<ToriiMultisigContractCallResponse> ProposeMultisigContractCallAsync(
        ToriiMultisigContractCallProposeRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var normalizedRequest = NormalizeMultisigContractCallProposeRequest(request);

        var response = await PostAsync<ToriiMultisigContractCallProposeRequest, ToriiMultisigContractCallResponse>(
            "/v1/contracts/call/multisig/propose",
            normalizedRequest,
            cancellationToken: cancellationToken);
        ValidateMultisigContractCallProposeResponse(
            response,
            normalizedRequest,
            "multisig contract-call response");
        return response;
    }

    public async Task<ToriiMultisigResponse> ApproveMultisigAsync(
        ToriiMultisigApproveRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var normalizedRequest = NormalizeMultisigApproveRequest(request);
        var response = await PostAsync<ToriiMultisigApproveRequest, ToriiMultisigResponse>(
            "/v1/multisig/approve",
            normalizedRequest,
            cancellationToken: cancellationToken);
        ValidateMultisigApproveResponse(
            response,
            normalizedRequest,
            "multisig approval response");
        return response;
    }

    public async Task<ToriiMultisigCancelResponse> CancelMultisigAsync(
        ToriiMultisigCancelRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var normalizedRequest = NormalizeMultisigCancelRequest(request);
        var response = await PostAsync<ToriiMultisigCancelRequest, ToriiMultisigCancelResponse>(
            "/v1/multisig/cancel",
            normalizedRequest,
            cancellationToken: cancellationToken);
        ValidateMultisigCancelResponse(
            response,
            normalizedRequest,
            "multisig cancel response");
        return response;
    }

    public async Task<ToriiMultisigContractCallResponse> ApproveMultisigContractCallAsync(
        ToriiMultisigContractCallApproveRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var normalizedRequest = NormalizeMultisigContractCallApproveRequest(request);

        var response = await PostAsync<ToriiMultisigContractCallApproveRequest, ToriiMultisigContractCallResponse>(
            "/v1/contracts/call/multisig/approve",
            normalizedRequest,
            cancellationToken: cancellationToken);
        ValidateMultisigContractCallApproveResponse(
            response,
            normalizedRequest,
            "multisig contract-call response");
        return response;
    }

    public async Task<ToriiContractVerifiedSourceJob> SubmitContractVerifiedSourceJobAsync(
        ContractArtifactId artifactId,
        ToriiContractVerifiedSourceSubmission request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(artifactId);
        var normalizedRequest = NormalizeContractVerifiedSourceSubmission(request);
        RequireCanonicalRequestCredentials(artifactId.Route);

        var response = await PostAsync<ToriiContractVerifiedSourceSubmission, ToriiContractVerifiedSourceJob>(
            artifactId.Route + "/verified-source/jobs",
            normalizedRequest,
            cancellationToken: cancellationToken);
        ValidateContractVerifiedSourceJob(response, "contract verified-source job response");
        ValidateContractArtifactResponse(response.NetworkId, response.ArtifactId, artifactId);
        return response;
    }

    public async Task<ToriiContractVerifiedSourceJob?> GetContractVerifiedSourceJobAsync(
        ContractArtifactId artifactId,
        string jobId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(artifactId);
        var normalizedJobId = NormalizeExactValue(jobId, nameof(jobId));
        RequireCanonicalRequestCredentials(artifactId.Route);

        using var response = await SendAllowingStatusAsync(
            HttpMethod.Get,
            $"{artifactId.Route}/verified-source/jobs/{EncodePathSegment(normalizedJobId)}",
            query: null,
            content: null,
            HttpStatusCode.NotFound,
            cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        var job = await DeserializeAsync<ToriiContractVerifiedSourceJob>(response, cancellationToken);
        ValidateContractVerifiedSourceJob(job, "contract verified-source job response");
        ValidateContractArtifactResponse(job.NetworkId, job.ArtifactId, artifactId);
        if (!string.Equals(job.JobId, normalizedJobId, StringComparison.Ordinal))
            throw new JsonException("Contract verified-source response job_id differs from the requested job.");
        return job;
    }

    public async Task<string> GetMetricsAsync(CancellationToken cancellationToken = default)
    {
        using var response = await SendAsync(HttpMethod.Get, "/v1/metrics", cancellationToken: cancellationToken);
        return await ReadStrictUtf8TextContentAsync(response.Content, "Torii metrics response body", cancellationToken);
    }

    public async Task<ToriiRuntimeAbiHash> GetRuntimeAbiHashAsync(CancellationToken cancellationToken = default)
    {
        var response = await GetAsync<ToriiRuntimeAbiHash>(
            "/v1/runtime/abi/hash",
            cancellationToken: cancellationToken);
        ValidateRuntimeAbiHash(response, "runtime ABI hash response");
        return response;
    }

    public async Task<ToriiSoraFsCidLookupResponse> GetSoraFsCidLookupAsync(
        string cid,
        CancellationToken cancellationToken = default)
    {
        var encodedCid = EncodeSoraFsCidPathSegment(cid, nameof(cid));
        var response = await GetAsync<ToriiSoraFsCidLookupResponse>(
            $"/v1/sorafs/cid/{encodedCid}",
            cancellationToken: cancellationToken);
        ValidateSoraFsCidLookupResponse(response, "SoraFS CID lookup response");
        return response;
    }

    /// <summary>Submits one signed SoraFS pin-manifest transaction without replay.</summary>
    /// <remarks>Public callers must use the SDK-managed one-shot transport.</remarks>
    public async Task<ToriiSoraFsPinRegisterResponse> RegisterSoraFsPinManifestAsync(
        SignedTransactionEnvelope transaction,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        EnsureOneShotTransportIsVerified();
        using var content = CreateBinaryContent(
            NormalizeVersionedSignedTransactionPayload(
                transaction.VersionedNoritoBytes,
                nameof(transaction)),
            "application/x-norito");
        using var response = await SendAsync(
            HttpMethod.Post,
            "/v1/sorafs/pin/register",
            content: content,
            accept: "application/json",
            cancellationToken: cancellationToken);
        if (response.StatusCode != HttpStatusCode.Accepted)
        {
            throw new HttpRequestException(
                $"SoraFS pin registration must return HTTP 202, got {(int)response.StatusCode}.");
        }

        using var document = await ParseBoundedJsonContentRejectingDuplicatePropertiesAsync(
            response.Content,
            "SoraFS pin registration response",
            cancellationToken);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("SoraFS pin registration response must be an object.");
        }
        var fields = root.EnumerateObject().Select(property => property.Name).ToHashSet(
            StringComparer.Ordinal);
        if (!fields.SetEquals(["status", "tx_hash_hex", "manifest_digest_hex"]))
        {
            throw new JsonException(
                "SoraFS pin registration response must contain only status, tx_hash_hex, and manifest_digest_hex.");
        }

        var status = root.GetProperty("status").GetString();
        if (!string.Equals(status, "submitted", StringComparison.Ordinal))
        {
            throw new JsonException("SoraFS pin registration response status must be submitted.");
        }
        return new ToriiSoraFsPinRegisterResponse
        {
            Status = "submitted",
            TxHashHex = RequireCanonicalLowercaseSoraFsPinDigest(root, "tx_hash_hex"),
            ManifestDigestHex = RequireCanonicalLowercaseSoraFsPinDigest(
                root,
                "manifest_digest_hex"),
        };
    }

    private static string RequireCanonicalLowercaseSoraFsPinDigest(
        JsonElement root,
        string field)
    {
        var value = root.GetProperty(field).GetString();
        if (value is null
            || value.Length != 64
            || value.Any(character =>
                character is not (>= '0' and <= '9')
                and not (>= 'a' and <= 'f')))
        {
            throw new JsonException($"{field} must be exactly 64 lowercase hexadecimal characters.");
        }
        return value;
    }

    public Task<HttpResponseMessage> OpenSoraFsCidContentAsync(
        string cid,
        string? relativePath = null,
        CancellationToken cancellationToken = default)
    {
        var gatewayPath = BuildSoraFsCidGatewayPath(cid, relativePath);
        return SendAsync(HttpMethod.Get, gatewayPath, cancellationToken: cancellationToken);
    }

    public async Task<ToriiSoraFsContentResponse> GetSoraFsCidContentAsync(
        string cid,
        string? relativePath = null,
        int maximumBytes = 16 * 1024 * 1024,
        CancellationToken cancellationToken = default)
    {
        if (maximumBytes <= 0 || maximumBytes > SoraFsBufferedContentMaxBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumBytes),
                $"Buffered SoraFS reads must be between 1 and {SoraFsBufferedContentMaxBytes} bytes. "
                + "Use OpenSoraFsCidContentAsync for larger streaming reads.");
        }

        using var response = await OpenSoraFsCidContentAsync(cid, relativePath, cancellationToken);
        var bytes = await ReadBoundedResponseBodyAsync(
            response.Content,
            maximumBytes,
            "SoraFS buffered content response",
            cancellationToken);
        var contentCid = ReadSoraFsContentCidHeader(response);
        return ToriiSoraFsContentResponse.FromOwnedBuffer(
            bytes,
            response.Content.Headers.ContentType?.ToString(),
            response.Content.Headers.ContentLength,
            contentCid);
    }

    /// <summary>Submits one canonical, versioned signed-query envelope.</summary>
    /// <remarks>
    /// The signed body is dispatched once. Redirect responses, non-success responses,
    /// and transport failures are surfaced to the caller without replaying the body.
    /// Public callers must use the SDK-managed one-shot transport.
    /// </remarks>
    public async Task<JsonDocument> SubmitSignedQueryAsync(
        ReadOnlyMemory<byte> noritoVersionedBytes,
        string? query = null,
        CancellationToken cancellationToken = default)
    {
        var normalizedBytes = NormalizeNonEmptyBinaryPayload(noritoVersionedBytes, nameof(noritoVersionedBytes));
        EnsureOneShotTransportIsVerified();
        using var content = CreateBinaryContent(normalizedBytes, "application/x-norito");
        using var response = await SendAsync(
            HttpMethod.Post,
            "/v1/query",
            query,
            content,
            accept: "application/json",
            cancellationToken: cancellationToken);
        return await ParseBoundedJsonContentRejectingDuplicatePropertiesAsync(
            response.Content,
            $"signed query response for `{response.RequestMessage?.RequestUri}`",
            cancellationToken);
    }

    /// <summary>Submits one managed canonical signed-query envelope.</summary>
    /// <remarks>
    /// The envelope is dispatched once. Public callers must use the SDK-managed one-shot
    /// transport for this nonce-bearing request.
    /// </remarks>
    public Task<JsonDocument> SubmitSignedQueryAsync(
        SignedQueryEnvelope signedQuery,
        string? query = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedQuery);
        return SubmitSignedQueryAsync(signedQuery.VersionedNoritoBytes, query, cancellationToken);
    }

    /// <summary>Fetches one authorized committed transaction through the canonical signed
    /// <c>FindTransactions</c> details route.</summary>
    /// <remarks>
    /// Build <paramref name="signedQuery"/> with
    /// <see cref="SignedIterableQueryBuilder.FindTransactionDetails(string)"/> and the exact
    /// genesis-derived <c>NetworkId</c>. Torii verifies the network, signature, freshness, and
    /// one-shot nonce before ledger access, then authorizes only an involved account or an
    /// operator. The SDK-managed transport dispatches the nonce-bearing request once; public
    /// caller-owned transports are rejected because redirects, retries, and replay are forbidden.
    /// </remarks>
    public async Task<JsonDocument> GetPipelineTransactionDetailsAsync(
        SignedQueryEnvelope signedQuery,
        string transactionHashHex,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedQuery);
        var normalizedHash = NormalizeTransactionHashHex(transactionHashHex);
        EnsureOneShotTransportIsVerified();
        using var content = CreateBinaryContent(signedQuery.VersionedNoritoBytes, "application/x-norito");
        using var response = await SendAsync(
            HttpMethod.Post,
            "/v1/pipeline/transactions/details",
            content: content,
            accept: "application/json",
            cancellationToken: cancellationToken);
        var document = await ParseBoundedJsonContentRejectingDuplicatePropertiesAsync(
            response.Content,
            $"pipeline transaction details response for `{response.RequestMessage?.RequestUri}`",
            cancellationToken);
        try
        {
            ValidatePipelineTransactionDetailsResponse(document.RootElement, normalizedHash);
            return document;
        }
        catch
        {
            document.Dispose();
            throw;
        }
    }

    internal Task<HttpResponseMessage> OpenEventSseAsync(
        Filter? filter = null,
        CancellationToken cancellationToken = default)
    {
        string? query = null;
        if (filter is not null)
        {
            filter.Validate();
            query = "filter=" + Uri.EscapeDataString(filter.ToTransportText(", and event-stream filters are text"));
        }

        return OpenLiveSseAsync("/v1/events/sse", query, cancellationToken: cancellationToken);
    }

    /// <summary>Streams the raw server-sent event frames of <c>GET /v1/events/sse</c>.</summary>
    /// <remarks>
    /// Frames are returned as received, including comments and <c>stream_error</c> frames; prefer
    /// <see cref="StreamEventsAsync(Filter?, CancellationToken)"/> for decoded events.
    /// </remarks>
    /// <param name="filter">
    /// Events to keep, in the filter text grammar restricted to what event subscriptions match: the
    /// fields <c>tx_status</c>, <c>tx_hash</c>, <c>tx_block_height</c>, <c>tx_lane_id</c>,
    /// <c>tx_dataspace_id</c>, <c>block_status</c>, <c>block_height</c>, <c>proof_backend</c>,
    /// <c>proof_call_hash</c> and <c>proof_envelope_hash</c>; <c>=</c> and <c>in</c> combined with
    /// <c>and</c> and <c>or</c>; <c>not</c> only over a status equality; and
    /// <c>tx_block_height is null</c>. For example
    /// <c>Filter.Field("tx_hash").Eq(hash) &amp; Filter.Field("tx_status").In("Approved", "Rejected")</c>.
    /// Torii rejects anything else with <c>invalid_filter</c> when the stream opens.
    /// </param>
    /// <param name="cancellationToken">Ends the stream.</param>
    /// <exception cref="ListQueryException">The filter is invalid or has object or array literals; nothing was sent.</exception>
    public async IAsyncEnumerable<ToriiServerSentEvent> StreamServerSentEventsAsync(
        Filter? filter = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        using var response = await OpenEventSseAsync(filter, cancellationToken).ConfigureAwait(false);
        var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using (stream.ConfigureAwait(false))
        {
            await foreach (var sseEvent in ReadServerSentEventsAsync(stream, cancellationToken).ConfigureAwait(false))
            {
                yield return sseEvent;
            }
        }
    }

    /// <summary>Streams the events of <c>GET /v1/events/sse</c>, decoded into <see cref="ToriiEvent"/> types.</summary>
    /// <remarks>
    /// Comments and frames without data are skipped. Events this SDK does not model arrive as
    /// <see cref="ToriiUnknownEvent"/> instead of failing the stream. A terminal <c>stream_error</c>
    /// frame ends the stream with <see cref="ToriiStreamException"/>.
    /// </remarks>
    /// <inheritdoc cref="StreamServerSentEventsAsync(Filter?, CancellationToken)" path="/param"/>
    /// <exception cref="ListQueryException">The filter is invalid or has object or array literals; nothing was sent.</exception>
    /// <exception cref="ToriiStreamException">Torii ended the stream with a terminal error.</exception>
    /// <exception cref="JsonException">A payload is not an event object or a known member is malformed.</exception>
    public async IAsyncEnumerable<ToriiEvent> StreamEventsAsync(
        Filter? filter = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        using var response = await OpenEventSseAsync(filter, cancellationToken).ConfigureAwait(false);
        var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using (stream.ConfigureAwait(false))
        {
            await foreach (var frame in ReadServerSentEventsAsync(stream, cancellationToken, parseJson: false).ConfigureAwait(false))
            {
                ThrowIfTerminalStreamError(frame, "event stream");
                if (frame.RawData is null)
                {
                    continue;
                }

                yield return ToriiEventJson.Read(frame.RawData, "event stream payload");
            }
        }
    }

    /// <summary>Streams the pipeline events (transactions, blocks, warnings and witnesses).</summary>
    /// <inheritdoc cref="StreamEventsAsync(Filter?, CancellationToken)" path="/remarks"/>
    /// <inheritdoc cref="StreamServerSentEventsAsync(Filter?, CancellationToken)" path="/param"/>
    public async IAsyncEnumerable<ToriiPipelineEvent> StreamPipelineEventsAsync(
        Filter? filter = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await foreach (var streamEvent in StreamEventsAsync(filter, cancellationToken).ConfigureAwait(false))
        {
            if (streamEvent is ToriiPipelineEvent pipelineEvent)
            {
                yield return pipelineEvent;
            }
        }
    }

    /// <summary>Streams the proof registry events (verifications, rejections and pruning passes).</summary>
    /// <inheritdoc cref="StreamEventsAsync(Filter?, CancellationToken)" path="/remarks"/>
    /// <inheritdoc cref="StreamServerSentEventsAsync(Filter?, CancellationToken)" path="/param"/>
    public async IAsyncEnumerable<ToriiProofEvent> StreamProofEventsAsync(
        Filter? filter = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await foreach (var streamEvent in StreamEventsAsync(filter, cancellationToken).ConfigureAwait(false))
        {
            if (streamEvent is ToriiProofEvent proofEvent)
            {
                yield return proofEvent;
            }
        }
    }

    internal Task<HttpResponseMessage> OpenExplorerBlocksSseAsync(
        string? lastEventId = null,
        CancellationToken cancellationToken = default)
    {
        return OpenSseAsync(
            "/v1/explorer/blocks/stream",
            query: null,
            lastEventId: lastEventId,
            cancellationToken: cancellationToken);
    }

    internal Task<HttpResponseMessage> OpenExplorerTransactionsSseAsync(
        string? lastEventId = null,
        CancellationToken cancellationToken = default)
    {
        return OpenSseAsync(
            "/v1/explorer/transactions/stream",
            query: null,
            lastEventId: lastEventId,
            cancellationToken: cancellationToken);
    }

    internal Task<HttpResponseMessage> OpenExplorerInstructionsSseAsync(
        string? lastEventId = null,
        CancellationToken cancellationToken = default)
    {
        return OpenSseAsync(
            "/v1/explorer/instructions/stream",
            query: null,
            lastEventId: lastEventId,
            cancellationToken: cancellationToken);
    }

    public IAsyncEnumerable<ToriiExplorerBlock> StreamExplorerBlocksAsync(
        string? lastEventId = null,
        CancellationToken cancellationToken = default)
    {
        return StreamSsePayloadsAsync(
            "/v1/explorer/blocks/stream",
            ToriiJsonSerializerContext.Default.ToriiExplorerBlock,
            payload => ValidateExplorerBlock(payload, "explorer block SSE payload"),
            query: null,
            lastEventId: lastEventId,
            cancellationToken: cancellationToken);
    }

    public IAsyncEnumerable<ToriiExplorerTransaction> StreamExplorerTransactionsAsync(
        string? lastEventId = null,
        CancellationToken cancellationToken = default)
    {
        return StreamSsePayloadsAsync(
            "/v1/explorer/transactions/stream",
            ToriiJsonSerializerContext.Default.ToriiExplorerTransaction,
            payload => ValidateExplorerTransaction(payload, "explorer transaction SSE payload"),
            query: null,
            lastEventId: lastEventId,
            cancellationToken: cancellationToken);
    }

    public IAsyncEnumerable<ToriiExplorerInstruction> StreamExplorerInstructionsAsync(
        string? lastEventId = null,
        CancellationToken cancellationToken = default)
    {
        return StreamSsePayloadsAsync(
            "/v1/explorer/instructions/stream",
            ToriiJsonSerializerContext.Default.ToriiExplorerInstruction,
            payload => ValidateExplorerInstruction(payload, "explorer instruction SSE payload"),
            query: null,
            lastEventId: lastEventId,
            cancellationToken: cancellationToken);
    }

    /// <summary>Submits one managed canonical signed transaction.</summary>
    /// <remarks>
    /// After the exact V1 contract preflight, the signed body is dispatched once and only
    /// HTTP 202 acknowledges admission. Public callers must use this client's internally managed
    /// transport because an injected handler chain cannot prove one-shot behavior.
    /// Reconcile an ambiguous outcome by transaction hash instead of replaying it.
    /// </remarks>
    public async Task SubmitTransactionAsync(
        SignedTransactionEnvelope transaction,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        await SubmitTransactionAsync(transaction.VersionedNoritoBytes, cancellationToken);
    }

    /// <summary>Submits one canonical V1 versioned signed-transaction body.</summary>
    /// <remarks>
    /// After the exact V1 contract preflight, the signed body is dispatched once. Only HTTP
    /// 202 acknowledges admission; every other response and transport failure is surfaced without
    /// replay. Public callers must use this client's internally managed transport.
    /// </remarks>
    public async Task SubmitTransactionAsync(
        ReadOnlyMemory<byte> versionedNoritoBytes,
        CancellationToken cancellationToken = default)
    {
        var normalizedBytes = NormalizeVersionedSignedTransactionPayload(
            versionedNoritoBytes,
            nameof(versionedNoritoBytes));
        RequireCanonicalRequestCredentials("/v1/node/capabilities");
        EnsureOneShotTransportIsVerified();
        await EnsureCanonicalTransactionContractAsync(cancellationToken);
        using var content = CreateBinaryContent(normalizedBytes, "application/x-norito");
        using var response = await SendExpectingStatusAsync(
            HttpMethod.Post,
            "/v1/pipeline/transactions",
            query: null,
            content: content,
            expectedStatusCode: HttpStatusCode.Accepted,
            allowedStatusCode: null,
            cancellationToken: cancellationToken);
    }

    private void EnsureOneShotTransportIsVerified()
    {
        if (!ownsHttpClient && !injectedTransportIsOneShot)
        {
            throw new InvalidOperationException(
                "Signed and one-shot Torii requests require ToriiClient's internally managed one-shot, no-redirect transport.");
        }
    }

    public async Task<PipelineTransactionStatus?> GetPipelineTransactionStatusAsync(
        string transactionHashHex,
        string scope = "global",
        CancellationToken cancellationToken = default)
    {
        var normalizedHash = NormalizeTransactionHashHex(transactionHashHex);
        var normalizedScope = NormalizePipelineScope(scope);
        var query = BuildQueryString(
        [
            new KeyValuePair<string, string?>("hash", normalizedHash),
            new KeyValuePair<string, string?>("scope", normalizedScope),
        ]);

        using var response = await SendExpectingStatusAsync(
            HttpMethod.Get,
            "/v1/pipeline/transactions/status",
            query,
            content: null,
            HttpStatusCode.OK,
            HttpStatusCode.NotFound,
            cancellationToken,
            accept: "application/json");

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        if (!string.Equals(
                response.Content.Headers.ContentType?.MediaType,
                "application/json",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new JsonException(
                "pipeline transaction status response must use the application/json media type.");
        }

        using var document = await ParseBoundedJsonContentRejectingDuplicatePropertiesAsync(
            response.Content,
            $"pipeline transaction status response for `{response.RequestMessage?.RequestUri}`",
            cancellationToken);
        return ParsePipelineTransactionStatus(document.RootElement, normalizedHash, normalizedScope);
    }

    internal async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        string path,
        string? query = null,
        HttpContent? content = null,
        string? accept = null,
        Action<HttpRequestMessage>? configureRequest = null,
        CancellationToken cancellationToken = default,
        ulong? preparedExecutionDeadlineUnixMilliseconds = null)
    {
        var request = await CreateRequestAsync(method, path, query, content, accept, configureRequest, cancellationToken);
        if (preparedExecutionDeadlineUnixMilliseconds is { } deadline
            && deadline <= checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()))
        {
            request.Dispose();
            throw new ArgumentException("Prepared operation binding is expired for execution.", nameof(preparedExecutionDeadlineUnixMilliseconds));
        }
        var response = await HttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.IsSuccessStatusCode)
        {
            return response;
        }

        var exception = await CreateApiExceptionAsync(response, cancellationToken);
        response.Dispose();
        throw exception;
    }

    private async Task<TResponse?> PostOptionalAsync<TRequest, TResponse>(
        string path,
        TRequest request,
        CancellationToken cancellationToken)
    {
        using var content = CreateJsonContent(request);
        using var response = await SendAllowingStatusAsync(
            HttpMethod.Post,
            path,
            query: null,
            content,
            HttpStatusCode.NotFound,
            cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return default;
        }

        return await DeserializeAsync<TResponse>(response, cancellationToken);
    }

    private async Task<TResponse> SendAllowingStatusAndDeserializeAsync<TResponse>(
        HttpMethod method,
        string path,
        string? query,
        HttpContent? content,
        HttpStatusCode allowedStatusCode,
        CancellationToken cancellationToken)
    {
        using var response = await SendAllowingStatusAsync(
            method,
            path,
            query,
            content,
            allowedStatusCode,
            cancellationToken);

        return await DeserializeAsync<TResponse>(response, cancellationToken);
    }

    private async Task<HttpResponseMessage> SendAllowingStatusAsync(
        HttpMethod method,
        string path,
        string? query,
        HttpContent? content,
        HttpStatusCode allowedStatusCode,
        CancellationToken cancellationToken)
    {
        var request = await CreateRequestAsync(method, path, query, content, accept: null, configureRequest: null, cancellationToken);
        var response = await HttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.IsSuccessStatusCode || response.StatusCode == allowedStatusCode)
        {
            return response;
        }

        var exception = await CreateApiExceptionAsync(response, cancellationToken);
        response.Dispose();
        throw exception;
    }

    private async Task<HttpResponseMessage> SendExpectingStatusAsync(
        HttpMethod method,
        string path,
        string? query,
        HttpContent? content,
        HttpStatusCode expectedStatusCode,
        HttpStatusCode? allowedStatusCode,
        CancellationToken cancellationToken,
        string? accept = null)
    {
        var request = await CreateRequestAsync(
            method,
            path,
            query,
            content,
            accept,
            configureRequest: null,
            cancellationToken);
        var expectedRequestUri = request.RequestUri;
        var response = await HttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (path.StartsWith("/v1/vpn/", StringComparison.Ordinal)
            && response.RequestMessage?.RequestUri is Uri responseUri
            && expectedRequestUri is not null
            && responseUri != expectedRequestUri)
        {
            response.Dispose();
            throw new HttpRequestException("Sora VPN requests must not follow redirects.");
        }

        if (response.StatusCode == expectedStatusCode
            || (allowedStatusCode.HasValue && response.StatusCode == allowedStatusCode.Value))
        {
            return response;
        }

        var exception = await CreateApiExceptionAsync(response, cancellationToken);
        response.Dispose();
        throw exception;
    }

    private void RequireVpnCanonicalRequestCredentials(string route)
    {
        RequireSecureVpnTransport();
        if (Options.CanonicalRequestCredentials is null)
        {
            throw new InvalidOperationException(
                $"VPN route `{route}` requires ToriiClientOptions.CanonicalRequestCredentials.");
        }
    }

    private void RequireSecureVpnTransport()
    {
        if (!string.Equals(BaseUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Sora VPN requests require an HTTPS Torii base URI.");
        }
    }

    private void ValidateContractArtifactResponse(NetworkId networkId, ContractArtifactId actual, ContractArtifactId expected)
    {
        if (Options.NetworkId is null || networkId != Options.NetworkId || actual != expected)
        {
            throw new JsonException("Contract artifact response differs from the requested network or artifact identity.");
        }
    }

    private void RequireCanonicalRequestCredentials(string route)
    {
        if (Options.CanonicalRequestCredentials is null)
        {
            throw new InvalidOperationException(
                $"Route `{route}` requires ToriiClientOptions.CanonicalRequestCredentials.");
        }
    }

    private async Task<HttpRequestMessage> CreateRequestAsync(
        HttpMethod method,
        string path,
        string? query,
        HttpContent? content,
        string? accept,
        Action<HttpRequestMessage>? configureRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(method);
        var exactMethod = RequireExactRequestMethod(method.Method, nameof(method));
        var exactPath = RequireExactRequestPath(path, nameof(path));
        var exactQuery = NormalizeOptionalExactQuery(query, nameof(query));
        var exactAccept = NormalizeOptionalAcceptHeaderValue(accept, nameof(accept));
        var requestUri = BuildRequestUri(exactPath, exactQuery);
        var request = new HttpRequestMessage(method, requestUri)
        {
            Content = content,
        };
        var bearerToken = NormalizeOptionalBearerToken(Options.BearerToken, nameof(ToriiClientOptions.BearerToken));
        if (bearerToken is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
        }

        if (!string.IsNullOrEmpty(exactAccept))
        {
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(exactAccept));
        }

        byte[]? signedBodyBytes = null;
        IReadOnlyDictionary<string, string>? signedHeaders = null;
        var canonicalCredentials = Options.CanonicalRequestCredentials;
        if (canonicalCredentials is not null)
        {
            foreach (var headerName in new[]
                     {
                         "X-Iroha-Account", "X-Iroha-Nonce", "X-Iroha-Signature", "X-Iroha-Timestamp-Ms",
                     })
            {
                if (HttpClient.DefaultRequestHeaders.Contains(headerName))
                {
                    throw new InvalidOperationException("Canonical signing headers must be generated locally and cannot be precomputed.");
                }
            }
        }

        if (canonicalCredentials is not null && !IsAnonymousPublicRoute(exactPath))
        {
            // Canonical account proofs bind method, path, query, body, time, and nonce, but not
            // the destination authority. An opaque injected handler could therefore forward the
            // proof on redirect or replay the same nonce on retry. Only the internally managed
            // handler (or the internal test-only one-shot assurance) may dispatch signed requests.
            EnsureOneShotTransportIsVerified();
            var bodyBytes = content is null ? Array.Empty<byte>() : await content.ReadAsByteArrayAsync(cancellationToken);
            var headers = CanonicalRequest.BuildHeaders(
                Options.NetworkId
                    ?? throw new InvalidOperationException("Canonical request authentication requires ToriiClientOptions.NetworkId."),
                canonicalCredentials.AccountId,
                canonicalCredentials.PrivateKeySeedSpan,
                exactMethod,
                requestUri.AbsolutePath,
                requestUri.Query,
                bodyBytes);

            signedBodyBytes = bodyBytes;
            signedHeaders = headers.ToDictionary();
            foreach (var header in signedHeaders)
            {
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        var protectedAuthorization = request.Headers.Authorization?.ToString();
        var protectedAccept = FormatAcceptHeaders(request);
        configureRequest?.Invoke(request);
        await EnsureConfigureRequestDidNotMutateProtectedStateAsync(
            request,
            exactMethod,
            requestUri,
            content,
            protectedAuthorization,
            protectedAccept,
            signedBodyBytes,
            signedHeaders,
            cancellationToken);
        return request;
    }

    private static bool IsAnonymousPublicRoute(string path)
    {
        // These protocol-public probes and local-content gateways stay anonymous
        // even when the client also carries credentials for visibility-sensitive reads.
        return string.Equals(path, "/v1/health", StringComparison.Ordinal)
            || string.Equals(path, "/v1/version", StringComparison.Ordinal)
            || string.Equals(path, "/v1/explorer/health", StringComparison.Ordinal)
            || string.Equals(path, "/.well-known/sorafs/manifest", StringComparison.Ordinal)
            || string.Equals(path, "/v1/sorafs/cid", StringComparison.Ordinal)
            || path.StartsWith("/v1/sorafs/cid/", StringComparison.Ordinal)
            || string.Equals(path, "/sorafs/cid", StringComparison.Ordinal)
            || path.StartsWith("/sorafs/cid/", StringComparison.Ordinal);
    }

    private static async Task EnsureConfigureRequestDidNotMutateProtectedStateAsync(
        HttpRequestMessage request,
        string expectedMethod,
        Uri expectedUri,
        HttpContent? expectedContent,
        string? expectedAuthorization,
        string expectedAccept,
        byte[]? signedBodyBytes,
        IReadOnlyDictionary<string, string>? signedHeaders,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(request.Method.Method, expectedMethod, StringComparison.Ordinal))
        {
            throw new ArgumentException("configureRequest must not mutate the HTTP method.", "configureRequest");
        }

        if (request.RequestUri is null
            || !string.Equals(request.RequestUri.AbsoluteUri, expectedUri.AbsoluteUri, StringComparison.Ordinal))
        {
            throw new ArgumentException("configureRequest must not mutate the request URI.", "configureRequest");
        }

        if (!ReferenceEquals(request.Content, expectedContent))
        {
            throw new ArgumentException("configureRequest must not replace request content.", "configureRequest");
        }

        if (!string.Equals(request.Headers.Authorization?.ToString(), expectedAuthorization, StringComparison.Ordinal))
        {
            throw new ArgumentException("configureRequest must not mutate the Authorization header.", "configureRequest");
        }

        if (!string.Equals(FormatAcceptHeaders(request), expectedAccept, StringComparison.Ordinal))
        {
            throw new ArgumentException("configureRequest must not mutate the Accept header.", "configureRequest");
        }

        if (signedBodyBytes is not null)
        {
            var currentBodyBytes = request.Content is null
                ? Array.Empty<byte>()
                : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            if (!currentBodyBytes.SequenceEqual(signedBodyBytes))
            {
                throw new ArgumentException("configureRequest must not mutate signed request content.", "configureRequest");
            }
        }

        if (signedHeaders is not null)
        {
            foreach (var header in signedHeaders)
            {
                if (!request.Headers.TryGetValues(header.Key, out var values)
                    || !values.SequenceEqual([header.Value]))
                {
                    throw new ArgumentException("configureRequest must not mutate canonical signing headers.", "configureRequest");
                }
            }
        }
    }

    private static string FormatAcceptHeaders(HttpRequestMessage request)
        => string.Join(",", request.Headers.Accept.Select(static header => header.ToString()));

    private static string RequireExactRequestPart(string? value, string paramName)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new ArgumentException($"{paramName} must not be empty.", paramName);
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new ArgumentException($"{paramName} must not contain surrounding whitespace.", paramName);
        }

        if (value.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException($"{paramName} must not contain whitespace.", paramName);
        }

        if (value.Any(char.IsControl))
        {
            throw new ArgumentException($"{paramName} must not contain control characters.", paramName);
        }

        return value;
    }

    private static string RequireAccountOnboardingToken(string? onboardingToken)
    {
        ArgumentNullException.ThrowIfNull(onboardingToken);
        var bytes = Encoding.UTF8.GetBytes(onboardingToken);
        if (bytes.Length is < 32 or > 256
            || bytes.Any(static value => value is < 0x21 or > 0x7e))
        {
            throw new ArgumentException(
                "Account onboarding token must contain 32...256 printable ASCII bytes without spaces or normalization.",
                nameof(onboardingToken));
        }

        return onboardingToken;
    }

    private static string RequireExactRequestMethod(string? value, string paramName)
    {
        var exact = RequireExactRequestPart(value, paramName);
        if (!exact.All(IsHttpTokenCharacter))
        {
            throw new ArgumentException($"{paramName} must be an HTTP token.", paramName);
        }

        return exact;
    }

    private static bool IsHttpTokenCharacter(char value)
        => value is >= 'A' and <= 'Z'
            or >= 'a' and <= 'z'
            or >= '0' and <= '9'
            or '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+'
            or '-' or '.' or '^' or '_' or '`' or '|' or '~';

    private static string RequireExactRequestPath(string? value, string paramName)
    {
        var exact = RequireExactRequestPart(value, paramName);
        CanonicalRequest.RequireCanonicalPathAsciiWireSpelling(exact, paramName);
        if (exact[0] != '/')
        {
            throw new ArgumentException($"{paramName} must be a root-relative path.", paramName);
        }

        if (exact.Length > 1 && exact[1] == '/')
        {
            throw new ArgumentException($"{paramName} must not be a scheme-relative URI.", paramName);
        }

        if (exact.Contains('?', StringComparison.Ordinal)
            || exact.Contains('#', StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"{paramName} must not contain query or fragment characters.",
                paramName);
        }

        ValidateUriStableRequestPath(exact, paramName);
        return exact;
    }

    private static void ValidateUriStableRequestPath(string value, string paramName)
    {
        if (value.Contains('\\', StringComparison.Ordinal))
        {
            throw new ArgumentException($"{paramName} must not contain raw backslash characters.", paramName);
        }

        ValidatePathPercentEscapes(value, paramName);
        foreach (var segment in value.Split('/', StringSplitOptions.None))
        {
            if (segment.Length == 0)
            {
                continue;
            }

            if (IsDotRequestPathSegment(segment))
            {
                throw new ArgumentException($"{paramName} must not contain dot path segments.", paramName);
            }
        }
    }

    private static bool IsDotRequestPathSegment(string value)
    {
        var dotCount = 0;
        for (var index = 0; index < value.Length;)
        {
            if (value[index] == '.')
            {
                dotCount++;
                index++;
                continue;
            }

            if (value[index] == '%'
                && HexValue(value[index + 1]) == 2
                && HexValue(value[index + 2]) == 14)
            {
                dotCount++;
                index += 3;
                continue;
            }

            return false;
        }

        return dotCount is 1 or 2;
    }

    private static string? NormalizeOptionalExactQuery(string? value, string paramName)
    {
        if (value is null || value.Length == 0)
        {
            return value;
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{paramName} must not be whitespace.", paramName);
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new ArgumentException($"{paramName} must not contain surrounding whitespace.", paramName);
        }

        if (value.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException($"{paramName} must not contain whitespace.", paramName);
        }

        if (value.Any(char.IsControl))
        {
            throw new ArgumentException($"{paramName} must not contain control characters.", paramName);
        }

        var decoded = DecodeQueryText(
            value,
            paramName,
            $"{paramName} must contain valid percent escapes.",
            $"{paramName} percent-encoded bytes must be valid UTF-8.");
        if (decoded.Any(char.IsControl))
        {
            throw new ArgumentException($"{paramName} must not contain percent-decoded control characters.", paramName);
        }

        ValidateExactQuerySegments(value, paramName);
        return value;
    }

    private static void ValidateExactQuerySegments(string value, string paramName)
    {
        var query = value[0] == '?' ? value[1..] : value;
        if (query.Length == 0)
        {
            throw new ArgumentException($"{paramName} must contain at least one query parameter.", paramName);
        }

        foreach (var segment in query.Split('&', StringSplitOptions.None))
        {
            if (segment.Length == 0)
            {
                throw new ArgumentException($"{paramName} must not contain empty query segments.", paramName);
            }

            var equalsIndex = segment.IndexOf('=');
            var rawName = equalsIndex >= 0 ? segment[..equalsIndex] : segment;
            var decodedName = DecodeQueryText(
                rawName,
                paramName,
                $"{paramName} must contain valid percent escapes.",
                $"{paramName} percent-encoded bytes must be valid UTF-8.");
            if (string.IsNullOrEmpty(decodedName) || decodedName.Any(char.IsWhiteSpace))
            {
                throw new ArgumentException($"{paramName} parameter names must not be empty or whitespace.", paramName);
            }

            if (decodedName.Any(char.IsControl))
            {
                throw new ArgumentException($"{paramName} parameter names must not contain control characters.", paramName);
            }
        }
    }

    private static string? NormalizeOptionalExactHeaderValue(string? value, string paramName)
    {
        if (value is null || value.Length == 0)
        {
            return value;
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{paramName} must not be whitespace.", paramName);
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new ArgumentException($"{paramName} must not contain surrounding whitespace.", paramName);
        }

        if (value.Any(char.IsControl))
        {
            throw new ArgumentException($"{paramName} must not contain control characters.", paramName);
        }

        return value;
    }

    private static string? NormalizeOptionalAcceptHeaderValue(string? value, string paramName)
    {
        var exact = NormalizeOptionalExactHeaderValue(value, paramName);
        if (string.IsNullOrEmpty(exact))
        {
            return exact;
        }

        var slashIndex = exact.IndexOf('/');
        if (slashIndex <= 0 || slashIndex != exact.LastIndexOf('/') || slashIndex == exact.Length - 1)
        {
            throw new ArgumentException($"{paramName} must be a single HTTP media range.", paramName);
        }

        var type = exact[..slashIndex];
        var subtype = exact[(slashIndex + 1)..];
        if (!IsMediaRangePart(type) || !IsMediaRangePart(subtype))
        {
            throw new ArgumentException($"{paramName} must be a single HTTP media range.", paramName);
        }

        if (type == "*" && subtype != "*")
        {
            throw new ArgumentException($"{paramName} wildcard media ranges must use */*.", paramName);
        }

        return exact;
    }

    private static bool IsMediaRangePart(string value)
        => value == "*" || value.All(IsHttpTokenCharacter);

    private static string? NormalizeOptionalBearerToken(string? value, string paramName)
    {
        if (value is null)
        {
            return null;
        }

        if (value.Length == 0 || string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{paramName} must not be empty or whitespace.", paramName);
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new ArgumentException($"{paramName} must not contain surrounding whitespace.", paramName);
        }

        if (value.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException($"{paramName} must not contain whitespace.", paramName);
        }

        if (value.Any(char.IsControl))
        {
            throw new ArgumentException($"{paramName} must not contain control characters.", paramName);
        }

        ValidateBearerToken(value, paramName);
        return value;
    }

    private static void ValidateBearerToken(string value, string paramName)
    {
        var firstPaddingIndex = value.IndexOf('=');
        var tokenLength = firstPaddingIndex < 0 ? value.Length : firstPaddingIndex;
        if (tokenLength == 0)
        {
            throw new ArgumentException($"{paramName} must be an HTTP bearer token.", paramName);
        }

        for (var index = 0; index < tokenLength; index++)
        {
            if (!IsBearerTokenCharacter(value[index]))
            {
                throw new ArgumentException($"{paramName} must be an HTTP bearer token.", paramName);
            }
        }

        if (firstPaddingIndex < 0)
        {
            return;
        }

        for (var index = firstPaddingIndex; index < value.Length; index++)
        {
            if (value[index] != '=')
            {
                throw new ArgumentException($"{paramName} must use trailing-only bearer token padding.", paramName);
            }
        }
    }

    private static bool IsBearerTokenCharacter(char value)
        => value is >= 'A' and <= 'Z'
            or >= 'a' and <= 'z'
            or >= '0' and <= '9'
            or '-' or '.' or '_' or '~' or '+' or '/';

    /// <param name="stream">The response body.</param>
    /// <param name="cancellationToken">Ends the stream.</param>
    /// <param name="parseJson">Whether to parse each frame's data into <see cref="ToriiServerSentEvent.JsonData"/>.</param>
    private static async IAsyncEnumerable<ToriiServerSentEvent> ReadServerSentEventsAsync(
        Stream stream,
        [EnumeratorCancellation] CancellationToken cancellationToken,
        bool parseJson = true)
    {
        using var reader = new SseLineReader(stream, SseMaximumLineBytes);
        var dataBuilder = new StringBuilder();
        var commentBuilder = new StringBuilder();
        var hasData = false;
        var hasComment = false;
        string? eventName = null;
        string? eventId = null;
        int? retryMilliseconds = null;
        var firstLine = true;

        while (true)
        {
            string? line;
            try
            {
                line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (DecoderFallbackException exception)
            {
                throw new JsonException("SSE stream must be valid UTF-8.", exception);
            }

            if (line is null)
            {
                break;
            }

            if (firstLine)
            {
                firstLine = false;
                if (line.Length > 0 && line[0] == '\ufeff')
                {
                    line = line[1..];
                }
            }

            if (line.Length == 0)
            {
                var sseEvent = BuildServerSentEvent(eventName, eventId, retryMilliseconds, hasData, dataBuilder, hasComment, commentBuilder, parseJson);
                if (sseEvent is not null)
                {
                    yield return sseEvent;
                }

                dataBuilder.Clear();
                commentBuilder.Clear();
                hasData = false;
                hasComment = false;
                eventName = null;
                eventId = null;
                retryMilliseconds = null;
                continue;
            }

            if (line[0] == ':')
            {
                if (hasComment)
                {
                    commentBuilder.Append('\n');
                }

                hasComment = true;
                commentBuilder.Append(line.Length > 1 && line[1] == ' ' ? line[2..] : line[1..]);
                continue;
            }

            var separatorIndex = line.IndexOf(':');
            var field = separatorIndex < 0 ? line : line[..separatorIndex];
            var value = separatorIndex < 0 ? string.Empty : line[(separatorIndex + 1)..];
            if (value.Length > 0 && value[0] == ' ')
            {
                value = value[1..];
            }

            switch (field)
            {
                case "event":
                    eventName = value.Length == 0 ? null : value;
                    break;
                case "data":
                    if (hasData)
                    {
                        dataBuilder.Append('\n');
                    }

                    hasData = true;
                    dataBuilder.Append(value);
                    if (dataBuilder.Length > SseMaximumLineBytes)
                    {
                        throw new InvalidDataException(
                            $"SSE event data exceeds the {SseMaximumLineBytes}-character limit.");
                    }

                    break;
                case "id":
                    eventId = value;
                    break;
                case "retry":
                    retryMilliseconds = ParseSseRetryMilliseconds(value);
                    break;
            }
        }

        var finalEvent = BuildServerSentEvent(eventName, eventId, retryMilliseconds, hasData, dataBuilder, hasComment, commentBuilder, parseJson);
        if (finalEvent is not null)
        {
            yield return finalEvent;
        }
    }

    private static int ParseSseRetryMilliseconds(string value)
    {
        if (!IsCanonicalNonNegativeInt32Text(value)
            || !int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed))
        {
            throw new JsonException("SSE retry must be canonical non-negative Int32 milliseconds.");
        }

        return parsed;
    }

    private static bool IsCanonicalNonNegativeInt32Text(string value)
    {
        if (value.Length == 0 || (value.Length > 1 && value[0] == '0'))
        {
            return false;
        }

        return value.All(static character => character is >= '0' and <= '9');
    }

    private static ToriiServerSentEvent? BuildServerSentEvent(
        string? eventName,
        string? eventId,
        int? retryMilliseconds,
        bool hasData,
        StringBuilder dataBuilder,
        bool hasComment,
        StringBuilder commentBuilder,
        bool parseJson)
    {
        if (!hasData && !hasComment && eventName is null && eventId is null && retryMilliseconds is null)
        {
            return null;
        }

        var rawData = hasData ? dataBuilder.ToString() : null;
        JsonNode? jsonData = null;
        if (parseJson && !string.IsNullOrWhiteSpace(rawData))
        {
            jsonData = TryParseSseJsonData(rawData);
        }

        try
        {
            return new ToriiServerSentEvent
            {
                Event = hasData ? eventName ?? "message" : eventName,
                Id = eventId,
                RetryMilliseconds = retryMilliseconds,
                RawData = rawData,
                JsonData = jsonData,
                Comment = hasComment ? commentBuilder.ToString() : null,
            };
        }
        catch (ArgumentException error) when (error.ParamName is "Event" or "Id" or "RetryMilliseconds")
        {
            var field = error.ParamName switch
            {
                "Event" => "sse_event_name",
                "Id" => "last_event_id",
                "RetryMilliseconds" => "retry",
                _ => error.ParamName,
            };
            throw new JsonException($"SSE event.{field}: {error.Message}", error);
        }
    }

    private static JsonNode? TryParseSseJsonData(string rawData)
    {
        try
        {
            return ToriiIdentifierJson.ParseNodeRejectingDuplicateProperties(rawData, "SSE data");
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static JsonNode RequireSseJsonData(ToriiServerSentEvent sseEvent, string context)
    {
        if (string.IsNullOrWhiteSpace(sseEvent.RawData))
        {
            throw new JsonException($"{context}.data must be valid non-null JSON.");
        }

        try
        {
            return ToriiIdentifierJson.ParseNodeRejectingDuplicateProperties(
                    sseEvent.RawData,
                    $"{context}.data")
                ?? throw new JsonException($"{context}.data must be valid non-null JSON.");
        }
        catch (JsonException exception) when (!ToriiIdentifierJson.IsDuplicatePropertyError(exception))
        {
            throw new JsonException($"{context}.data must be valid non-null JSON.", exception);
        }
    }

    private static void ThrowIfTerminalStreamError(ToriiServerSentEvent sseEvent, string context)
    {
        if (!string.Equals(sseEvent.Event, "stream_error", StringComparison.Ordinal))
        {
            return;
        }

        var payload = RequireSseJsonData(sseEvent, $"{context} terminal stream error");
        if (payload is not JsonObject payloadObject)
        {
            throw new JsonException($"{context} terminal stream error.data must be a JSON object.");
        }

        string[] expectedProperties = ["code", "message", "dropped_messages", "replay_available"];
        var unexpectedProperty = payloadObject
            .Select(static property => property.Key)
            .FirstOrDefault(property => !expectedProperties.Contains(property, StringComparer.Ordinal));
        if (unexpectedProperty is not null)
        {
            throw new JsonException(
                $"{context} terminal stream error.{unexpectedProperty} is not part of the v1 stream error schema.");
        }

        if (payloadObject.Count != expectedProperties.Length)
        {
            var missingProperty = expectedProperties.First(property => !payloadObject.ContainsKey(property));
            throw new JsonException($"{context} terminal stream error.{missingProperty} is required.");
        }

        var code = RequireTerminalStreamErrorString(payloadObject, "code", context, token: true);
        var message = RequireTerminalStreamErrorString(payloadObject, "message", context, token: false);

        var droppedNode = payloadObject["dropped_messages"];
        ulong? droppedMessages = null;
        if (droppedNode is not null)
        {
            if (droppedNode is not JsonValue droppedValue || !droppedValue.TryGetValue<ulong>(out var parsedDropped))
            {
                throw new JsonException(
                    $"{context} terminal stream error.dropped_messages must be null or an unsigned integer.");
            }

            droppedMessages = parsedDropped;
        }

        if (payloadObject["replay_available"] is not JsonValue replayValue
            || !replayValue.TryGetValue<bool>(out var replayAvailable))
        {
            throw new JsonException(
                $"{context} terminal stream error.replay_available must be a boolean.");
        }

        throw new ToriiStreamException(code, message, droppedMessages, replayAvailable);
    }

    private static string RequireTerminalStreamErrorString(
        JsonObject payload,
        string propertyName,
        string context,
        bool token)
    {
        if (payload[propertyName] is not JsonValue value || !value.TryGetValue<string>(out var text))
        {
            throw new JsonException($"{context} terminal stream error.{propertyName} must be a string.");
        }

        if (string.IsNullOrEmpty(text)
            || !string.Equals(text.Trim(), text, StringComparison.Ordinal)
            || text.Any(char.IsControl)
            || (token && text.Any(char.IsWhiteSpace)))
        {
            var shape = token ? "a non-empty exact token" : "non-empty exact text";
            throw new JsonException($"{context} terminal stream error.{propertyName} must be {shape}.");
        }

        return text;
    }

    private async Task<TResponse> DeserializeAsync<TResponse>(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        using var document = await ParseBoundedJsonContentRejectingDuplicatePropertiesAsync(
            response.Content,
            DuplicatePropertyContext<TResponse>(response),
            cancellationToken);
        if (typeof(TResponse) == typeof(ToriiContractCallResponse))
        {
            ToriiContractCallJson.ValidateContractCallResponseJsonShape(
                document.RootElement,
                "contract call response");
        }
        TResponse? value;
        try
        {
            value = document.RootElement.Deserialize<TResponse>(SerializerOptions);
        }
        catch (ArgumentException error)
            when (typeof(TResponse) == typeof(ToriiContractCallResponse)
                && error.ParamName is not null)
        {
            throw ToriiContractCallJson.DirectMetadataErrorToJsonException(
                error,
                "contract call response");
        }
        return value ?? throw new JsonException($"Torii response for `{response.RequestMessage?.RequestUri}` deserialized to null.");
    }

    private static string DuplicatePropertyContext<TResponse>(HttpResponseMessage response)
    {
        if (typeof(TResponse) == typeof(ToriiIdentifierResolveResponse))
        {
            return "identifier resolve response";
        }

        return $"Torii response for `{response.RequestMessage?.RequestUri}`";
    }

    private static async Task<JsonDocument> ParseJsonDocumentRejectingDuplicatePropertiesAsync(
        Stream stream,
        string context,
        CancellationToken cancellationToken)
    {
        var document = await JsonDocument.ParseAsync(
            stream,
            new JsonDocumentOptions { MaxDepth = 128 },
            cancellationToken);
        try
        {
            ToriiIdentifierJson.RejectDuplicateProperties(document.RootElement, context);
            return document;
        }
        catch
        {
            document.Dispose();
            throw;
        }
    }

    private static async Task<JsonDocument> ParseBoundedJsonContentRejectingDuplicatePropertiesAsync(
        HttpContent content,
        string context,
        CancellationToken cancellationToken,
        int maximumBytes = DefaultJsonResponseMaxBytes)
    {
        var body = await ReadBoundedResponseBodyAsync(
            content,
            maximumBytes,
            context,
            cancellationToken);
        using var stream = new MemoryStream(body, writable: false);
        return await ParseJsonDocumentRejectingDuplicatePropertiesAsync(
            stream,
            context,
            cancellationToken);
    }

    private static JsonException RewriteIdentifierPoliciesJsonException(JsonException exception)
    {
        const string converterPrefix = "policy.";
        if (!exception.Message.StartsWith(converterPrefix, StringComparison.Ordinal))
        {
            return exception;
        }

        var itemContext = "identifier policies response.items[0]";
        var path = exception.Path;
        if (!string.IsNullOrEmpty(path))
        {
            const string itemMarker = ".items[";
            var markerStart = path.IndexOf(itemMarker, StringComparison.Ordinal);
            if (markerStart >= 0)
            {
                var indexStart = markerStart + itemMarker.Length;
                var indexEnd = path.IndexOf(']', indexStart);
                if (indexEnd > indexStart)
                {
                    itemContext = $"identifier policies response.items[{path[indexStart..indexEnd]}]";
                }
            }
        }

        var detail = exception.Message[converterPrefix.Length..];
        if (detail.EndsWith(" must not be empty.", StringComparison.Ordinal))
        {
            detail = $"{detail[..^" must not be empty.".Length]} must be a non-empty string.";
        }

        return new JsonException($"{itemContext}.{detail}", exception);
    }

    private static JsonException RewriteIdentifierResolveJsonException(JsonException exception)
    {
        const string converterPrefix = "identifier receipt.";
        return exception.Message.StartsWith(converterPrefix, StringComparison.Ordinal)
            ? new JsonException(
                $"identifier resolve response.{exception.Message[converterPrefix.Length..]}",
                exception)
            : exception;
    }

    private void ValidateMultisigApproveResponse(
        ToriiMultisigResponse response,
        ToriiMultisigApproveRequest request,
        string context)
    {
        ToriiMultisigJson.ValidateMultisigResponse(response, context);
        ValidateMultisigFeePayment(response.FeePayment, request.FeePayment, context);
        ValidateResolvedMultisigAccount(
            response.ResolvedMultisigAccountId,
            request.MultisigAccountId,
            context);
        var proposalHash = RequireSelectedMultisigProposalHash(
            request.ProposalId,
            request.InstructionsHash,
            context);
        RequireMultisigApprovalResponseHash(
            response.ProposalId,
            response.InstructionsHash,
            proposalHash,
            context);

        var encoding = new TransactionEncodingContext(request.SignerAccountId);
        var binding = ExactMultisigPayloadBinding(
            encoding,
            [BuildMultisigApproveInstruction(response.ResolvedMultisigAccountId, proposalHash)]);
        ValidateMultisigUnsignedPayloadBindings(
            response.Submitted,
            response.TransactionPayloadBase64,
            response.SigningMessageBase64,
            response.FeePayment,
            response.CreationTimeMilliseconds,
            request.SignerAccountId,
            request.CreationTimeMilliseconds,
            binding,
            context);
    }

    private void ValidateMultisigContractCallProposeResponse(
        ToriiMultisigContractCallResponse response,
        ToriiMultisigContractCallProposeRequest request,
        string context)
    {
        ToriiMultisigJson.ValidateMultisigContractCallResponse(response, context);
        ValidateMultisigFeePayment(response.FeePayment, request.FeePayment, context);
        ValidateResolvedMultisigAccount(
            response.ResolvedMultisigAccountId,
            request.MultisigAccountId,
            context);
        var proposalHash = RequireMatchingMultisigResponseHashes(
            response.ProposalId,
            response.InstructionsHash,
            context);
        var binding = new MultisigPayloadBinding(
            [],
            null,
            request,
            proposalHash,
            response.ResolvedMultisigAccountId);
        ValidateMultisigUnsignedPayloadBindings(
            response.Submitted,
            response.TransactionPayloadBase64,
            response.SigningMessageBase64,
            response.FeePayment,
            response.CreationTimeMilliseconds,
            request.SignerAccountId,
            request.CreationTimeMilliseconds,
            binding,
            context);
    }

    private void ValidateMultisigContractCallApproveResponse(
        ToriiMultisigContractCallResponse response,
        ToriiMultisigContractCallApproveRequest request,
        string context)
    {
        ToriiMultisigJson.ValidateMultisigContractCallResponse(response, context);
        ValidateMultisigFeePayment(response.FeePayment, request.FeePayment, context);
        ValidateResolvedMultisigAccount(
            response.ResolvedMultisigAccountId,
            request.MultisigAccountId,
            context);
        var proposalHash = RequireSelectedMultisigProposalHash(
            request.ProposalId,
            request.InstructionsHash,
            context);
        RequireMultisigApprovalResponseHash(
            response.ProposalId,
            response.InstructionsHash,
            proposalHash,
            context);

        var encoding = new TransactionEncodingContext(request.SignerAccountId);
        var binding = ExactMultisigPayloadBinding(
            encoding,
            [BuildMultisigApproveInstruction(response.ResolvedMultisigAccountId, proposalHash)]);
        ValidateMultisigUnsignedPayloadBindings(
            response.Submitted,
            response.TransactionPayloadBase64,
            response.SigningMessageBase64,
            response.FeePayment,
            response.CreationTimeMilliseconds,
            request.SignerAccountId,
            request.CreationTimeMilliseconds,
            binding,
            context);
    }

    private void ValidateMultisigCancelResponse(
        ToriiMultisigCancelResponse response,
        ToriiMultisigCancelRequest request,
        string context)
    {
        ValidateMultisigFeePayment(response.FeePayment, request.FeePayment, context);
        ValidateResolvedMultisigAccount(
            response.ResolvedMultisigAccountId,
            request.MultisigAccountId,
            context);
        var targetHash = RequireSelectedMultisigProposalHash(
            request.ProposalId,
            request.InstructionsHash,
            context);
        if (!string.Equals(response.TargetProposalId, targetHash, StringComparison.Ordinal)
            || !string.Equals(response.TargetInstructionsHash, targetHash, StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context} target hashes do not match the exact requested proposal.");
        }

        var encoding = new TransactionEncodingContext(request.SignerAccountId);
        var cancel = BuildMultisigCancelInstruction(
            response.ResolvedMultisigAccountId,
            targetHash);
        var cancelInstructionBase64 = cancel.EncodeInstructionBoxBase64(request.SignerAccountId);
        var cancelHash = HashMultisigInstructions([cancelInstructionBase64], context);
        if (!string.Equals(response.CancelProposalId, cancelHash, StringComparison.Ordinal)
            || !string.Equals(response.CancelInstructionsHash, cancelHash, StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context} cancel hashes do not match the canonical cancel instruction.");
        }

        TransactionInstruction outerInstruction = response.Action switch
        {
            "PROPOSE" => BuildMultisigProposeInstruction(
                response.ResolvedMultisigAccountId,
                [cancelInstructionBase64]),
            "APPROVE" => BuildMultisigApproveInstruction(
                response.ResolvedMultisigAccountId,
                cancelHash),
            _ => throw new JsonException(
                $"{context}.action must be exactly `PROPOSE` or `APPROVE`."),
        };
        var binding = ExactMultisigPayloadBinding(encoding, [outerInstruction]);
        ValidateMultisigUnsignedPayloadBindings(
            response.Submitted,
            response.TransactionPayloadBase64,
            response.SigningMessageBase64,
            response.FeePayment,
            response.CreationTimeMilliseconds,
            request.SignerAccountId,
            request.CreationTimeMilliseconds,
            binding,
            context);
    }

    private static void ValidateMultisigFeePayment(
        FeePaymentIntent? feePayment,
        FeePaymentIntent expectedFeePayment,
        string context)
    {
        if (feePayment is null)
        {
            throw new JsonException($"{context}.fee_payment must not be null.");
        }
        if (!expectedFeePayment.HasSamePayerAndGasBound(feePayment))
        {
            throw new JsonException(
                $"{context}.fee_payment changed the requested payer, sponsor revision, or gas bound.");
        }
    }

    private void ValidateMultisigUnsignedPayloadBindings(
        bool submitted,
        string? transactionPayloadBase64,
        string? signingMessageBase64,
        FeePaymentIntent responseFeePayment,
        ulong? responseCreationTimeMilliseconds,
        string expectedSignerAccountId,
        ulong? expectedCreationTimeMilliseconds,
        MultisigPayloadBinding payloadBinding,
        string context)
    {
        if (expectedCreationTimeMilliseconds.HasValue
            && responseCreationTimeMilliseconds != expectedCreationTimeMilliseconds)
        {
            throw new JsonException(
                $"{context}.creation_time_ms is not bound to the request.");
        }
        if (submitted)
        {
            return;
        }
        var expectedNetworkId = Options.NetworkId
            ?? throw new JsonException(
                $"{context} cannot trust an unsigned transaction without ToriiClientOptions.NetworkId.");
        if (responseCreationTimeMilliseconds is null or 0)
        {
            throw new JsonException(
                $"{context}.creation_time_ms must be positive for an unsigned response.");
        }

        try
        {
            var payload = Convert.FromBase64String(
                transactionPayloadBase64
                    ?? throw new JsonException(
                        $"{context}.transaction_payload_b64 must not be null for an unsigned response."));
            if (!string.Equals(
                    Convert.ToBase64String(payload),
                    transactionPayloadBase64,
                    StringComparison.Ordinal))
            {
                throw new JsonException(
                    $"{context}.transaction_payload_b64 must be canonical base64 text.");
            }
            var signingMessage = Convert.FromBase64String(
                signingMessageBase64
                    ?? throw new JsonException(
                        $"{context}.signing_message_b64 must not be null for an unsigned response."));
            if (!string.Equals(
                    Convert.ToBase64String(signingMessage),
                    signingMessageBase64,
                    StringComparison.Ordinal)
                || signingMessage.Length != IrohaHash.Length
                || !signingMessage.AsSpan().SequenceEqual(IrohaHash.Hash(payload)))
            {
                throw new JsonException(
                    $"{context}.signing_message_b64 must be the exact TransactionPayload hash.");
            }
            var reader = new CanonicalNoritoReader(
                payload,
                $"{context} transaction payload",
                nameof(transactionPayloadBase64));
            var networkDomain = reader.ReadField("domain");
            var authority = reader.ReadField("authority");
            var creationTime = reader.ReadField("creation_time_ms");
            var executable = reader.ReadField("executable");
            var timeToLive = reader.ReadField("time_to_live_ms");
            var nonce = reader.ReadField("nonce");
            var feePayment = reader.ReadField("fee_payment");
            var metadata = reader.ReadField("metadata");
            var attachments = reader.ReadField("attachments");
            reader.RequireEnd();

            var encoding = new TransactionEncodingContext(expectedSignerAccountId);
            ValidateTransactionEnvelopeFields(
                networkDomain,
                timeToLive,
                nonce,
                attachments,
                expectedNetworkId,
                TransactionBuilder.DefaultTimeToLiveMilliseconds,
                encoding,
                context);
            if (!authority.SequenceEqual(encoding.EncodeAccountId(expectedSignerAccountId)))
            {
                throw new JsonException(
                    $"{context} transaction authority does not match the requested signer.");
            }
            if (!feePayment.SequenceEqual(encoding.EncodeFeePaymentIntent(responseFeePayment)))
            {
                throw new JsonException(
                    $"{context}.fee_payment does not match the exact transaction payload.");
            }
            if (creationTime.Length != sizeof(ulong)
                || responseCreationTimeMilliseconds
                    != BinaryPrimitives.ReadUInt64LittleEndian(creationTime))
            {
                throw new JsonException(
                    $"{context}.creation_time_ms does not match the exact transaction payload.");
            }
            ValidateMultisigPayloadIntent(
                executable,
                metadata,
                payloadBinding,
                context);
        }
        catch (Exception error) when (error is ArgumentException or FormatException)
        {
            throw new JsonException(
                $"{context}.transaction_payload_b64 must contain exactly one canonical nine-field TransactionPayload.",
                error);
        }
    }

    private static MultisigPayloadBinding ExactMultisigPayloadBinding(
        TransactionEncodingContext encoding,
        IReadOnlyList<TransactionInstruction> instructions)
    {
        return new MultisigPayloadBinding(
            [encoding.EncodeInstructionsExecutable(instructions)],
            encoding.EncodeEmptyMetadata(),
            null,
            null,
            null);
    }

    private static void ValidateTransactionEnvelopeFields(
        ReadOnlySpan<byte> networkDomain,
        ReadOnlySpan<byte> timeToLive,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> attachments,
        NetworkId expectedNetworkId,
        ulong expectedTimeToLiveMilliseconds,
        TransactionEncodingContext encoding,
        string context)
    {
        var network = new CanonicalNoritoReader(
            networkDomain,
            $"{context} network domain",
            nameof(networkDomain));
        if (network.ReadUInt32LittleEndian("variant") != 0)
        {
            throw new JsonException($"{context} transaction network domain is not canonical.");
        }
        var networkHash = network.ReadField("network_hash");
        network.RequireEnd();
        if (networkHash.Length != NetworkId.ByteLength
            || (networkHash[^1] & 1) == 0)
        {
            throw new JsonException($"{context} transaction network hash is not canonical.");
        }
        if (!networkDomain.SequenceEqual(encoding.EncodeNetworkDomain(expectedNetworkId)))
        {
            throw new JsonException($"{context} transaction targets another network.");
        }

        if (!timeToLive.SequenceEqual(encoding.EncodeOption<ulong>(
                expectedTimeToLiveMilliseconds,
                encoding.EncodeUInt64)))
        {
            throw new JsonException($"{context} transaction TTL differs from the exact request.");
        }
        if (!nonce.SequenceEqual(new byte[] { 0 })
            || !attachments.SequenceEqual(new byte[] { 0 }))
        {
            throw new JsonException(
                $"{context} transaction nonce or attachments were substituted.");
        }
    }

    private static void ValidateResolvedMultisigAccount(
        string resolvedAccountId,
        string? requestedAccountId,
        string context)
    {
        if (requestedAccountId is not null
            && !string.Equals(resolvedAccountId, requestedAccountId, StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context}.resolved_multisig_account_id does not match the requested account.");
        }
    }

    private static string RequireSelectedMultisigProposalHash(
        string? proposalId,
        string? instructionsHash,
        string context)
    {
        if (proposalId is not null
            && instructionsHash is not null
            && !string.Equals(proposalId, instructionsHash, StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context} request proposal_id and instructions_hash select different proposals.");
        }
        return proposalId
            ?? instructionsHash
            ?? throw new JsonException($"{context} request does not select a proposal.");
    }

    private static void RequireMultisigProposalResponseHash(
        string? proposalId,
        string? instructionsHash,
        string expectedHash,
        string context)
    {
        if (!string.Equals(proposalId, expectedHash, StringComparison.Ordinal)
            || !string.Equals(instructionsHash, expectedHash, StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context} proposal hash does not match the exact requested instructions and validation-fee marker.");
        }
    }

    private static void RequireMultisigApprovalResponseHash(
        string? proposalId,
        string? instructionsHash,
        string expectedHash,
        string context)
    {
        if (!string.Equals(instructionsHash, expectedHash, StringComparison.Ordinal)
            || proposalId is not null
                && !string.Equals(proposalId, expectedHash, StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context} proposal hash does not match the exact requested proposal.");
        }
    }

    private static string RequireMatchingMultisigResponseHashes(
        string? proposalId,
        string? instructionsHash,
        string context)
    {
        if (proposalId is null
            || !string.Equals(proposalId, instructionsHash, StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context}.proposal_id and instructions_hash must identify the same proposal.");
        }
        return proposalId;
    }

    private static TransactionInstruction BuildMultisigProposeInstruction(
        string accountId,
        IReadOnlyList<string> instructions)
    {
        var encodedInstructions = new JsonArray();
        foreach (var instruction in instructions)
        {
            encodedInstructions.Add(instruction);
        }
        return new MultisigCustomInstruction(new JsonObject
        {
            ["Propose"] = new JsonObject
            {
                ["account"] = accountId,
                ["instructions"] = encodedInstructions,
                ["transaction_ttl_ms"] = null,
            },
        });
    }

    private static TransactionInstruction BuildMultisigApproveInstruction(
        string accountId,
        string instructionsHash)
    {
        return new MultisigCustomInstruction(new JsonObject
        {
            ["Approve"] = new JsonObject
            {
                ["account"] = accountId,
                ["instructions_hash"] = FormatNoritoHashLiteral(instructionsHash),
            },
        });
    }

    private static TransactionInstruction BuildMultisigCancelInstruction(
        string accountId,
        string instructionsHash)
    {
        return new MultisigCustomInstruction(new JsonObject
        {
            ["Cancel"] = new JsonObject
            {
                ["account"] = accountId,
                ["instructions_hash"] = FormatNoritoHashLiteral(instructionsHash),
            },
        });
    }

    private static string HashMultisigInstructions(
        IReadOnlyList<string> instructions,
        string context)
    {
        var sequence = new CanonicalNoritoWriter();
        sequence.WriteSequenceLength(checked((ulong)instructions.Count));
        for (var index = 0; index < instructions.Count; index++)
        {
            var archive = Convert.FromBase64String(instructions[index]);
            var (payload, flags) = NoritoCodec.DecodeWithSchemaHash(
                MultisigInstructionBoxSchemaHash,
                archive);
            if (flags != NoritoCodec.CanonicalLayoutFlags
                || !archive.AsSpan().SequenceEqual(NoritoCodec.EncodeWithSchemaHash(
                    MultisigInstructionBoxSchemaHash,
                    payload,
                    flags)))
            {
                throw new JsonException(
                    $"{context} request instruction {index} is not one canonical InstructionBox archive.");
            }
            sequence.WriteField(payload);
        }
        return Convert.ToHexString(IrohaHash.Hash(sequence.ToArray())).ToLowerInvariant();
    }

    private static string FormatNoritoHashLiteral(string lowercaseHashHex)
    {
        var body = lowercaseHashHex.ToUpperInvariant();
        ushort checksum = 0xffff;
        foreach (var value in Encoding.ASCII.GetBytes($"hash:{body}"))
        {
            checksum ^= (ushort)(value << 8);
            for (var bit = 0; bit < 8; bit++)
            {
                checksum = (ushort)((checksum & 0x8000) != 0
                    ? (checksum << 1) ^ 0x1021
                    : checksum << 1);
            }
        }
        return $"hash:{body}#{checksum:X4}";
    }

    private static void ValidateMultisigPayloadIntent(
        ReadOnlySpan<byte> executable,
        ReadOnlySpan<byte> metadata,
        MultisigPayloadBinding binding,
        string context)
    {
        if (binding.ContractCallRequest is not null)
        {
            ValidateMultisigContractCallPayloadIntent(
                executable,
                metadata,
                binding,
                context);
            return;
        }
        var executableMatches = false;
        foreach (var expected in binding.AllowedExecutables)
        {
            if (executable.SequenceEqual(expected))
            {
                executableMatches = true;
                break;
            }
        }
        if (!executableMatches)
        {
            throw new JsonException(
                $"{context} transaction executable does not match the exact requested multisig action.");
        }
        if (binding.ExactMetadata is null
            || !metadata.SequenceEqual(binding.ExactMetadata))
        {
            throw new JsonException(
                $"{context} transaction metadata does not match the exact request binding.");
        }
    }

    private static void ValidateMultisigContractCallPayloadIntent(
        ReadOnlySpan<byte> executable,
        ReadOnlySpan<byte> metadata,
        MultisigPayloadBinding binding,
        string context)
    {
        var request = binding.ContractCallRequest!;
        var draftIntent = request.DraftIntent
            ?? throw new JsonException(
                $"{context} requires an exact caller-trusted DraftIntent before its unsigned draft can be trusted.");
        var outerInstructions = DecodeExecutableInstructions(executable, context);
        if (outerInstructions.Count is < 1 or > 2)
        {
            throw new JsonException(
                $"{context} contract-call proposal executable must contain only propose and optional approve instructions.");
        }

        var proposePayload = DecodeMultisigCustomInstruction(
            outerInstructions[0],
            request.SignerAccountId,
            context);
        var propose = RequireExactJsonObject(
            RequireExactJsonObject(proposePayload, ["Propose"], context)["Propose"],
            ["account", "instructions", "transaction_ttl_ms"],
            context);
        if (!string.Equals(
                propose["account"]?.GetValue<string>(),
                binding.ResolvedMultisigAccountId,
                StringComparison.Ordinal)
            || propose["transaction_ttl_ms"] is not null)
        {
            throw new JsonException(
                $"{context} contract-call proposal changed the resolved account or transaction TTL.");
        }
        if (propose["instructions"] is not JsonArray nestedArray || nestedArray.Count != 2)
        {
            throw new JsonException(
                $"{context} contract-call proposal must contain its exact register/execute instruction pair.");
        }
        var nestedInstructions = nestedArray
            .Select((value, index) => value?.GetValue<string>()
                ?? throw new JsonException(
                    $"{context} contract-call proposal instruction {index} must be base64 text."))
            .ToArray();
        var proposalHash = HashMultisigInstructions(nestedInstructions, context);
        if (!string.Equals(
                proposalHash,
                binding.ContractProposalHash,
                StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context} proposal hash does not match the exact contract-call instruction pair.");
        }

        var register = DecodeInstructionArchive(nestedInstructions[0], context);
        var execute = DecodeInstructionArchive(nestedInstructions[1], context);
        if (!string.Equals(register.WireId, "iroha.register", StringComparison.Ordinal)
            || !string.Equals(execute.WireId, "iroha.execute_trigger", StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context} contract-call proposal substituted its register/execute instruction pair.");
        }
        var (triggerId, arguments) = DecodeExecuteTrigger(execute, context);
        var expectedArguments = request.Payload ?? new JsonObject();
        if (!JsonNode.DeepEquals(arguments, expectedArguments))
        {
            throw new JsonException(
                $"{context} contract-call proposal arguments do not match the exact request payload.");
        }

        var encoding = new TransactionEncodingContext(request.SignerAccountId);
        if (!metadata.SequenceEqual(encoding.EncodeMetadata(draftIntent.Metadata)))
        {
            throw new JsonException(
                $"{context} transaction metadata differs from the exact caller-trusted DraftIntent.");
        }
        ValidateContractCallTriggerRegistration(
            register,
            triggerId,
            metadata,
            binding,
            draftIntent.Invocation,
            context);

        if (outerInstructions.Count == 2)
        {
            var expectedApprove = (MultisigCustomInstruction)BuildMultisigApproveInstruction(
                binding.ResolvedMultisigAccountId!,
                proposalHash);
            var approvePayload = DecodeMultisigCustomInstruction(
                outerInstructions[1],
                request.SignerAccountId,
                context);
            if (!JsonNode.DeepEquals(approvePayload, expectedApprove.Payload))
            {
                throw new JsonException(
                    $"{context} contract-call proposal appended an approval for another proposal.");
            }
        }
    }

    private static IReadOnlyList<EncodedInstruction> DecodeExecutableInstructions(
        ReadOnlySpan<byte> executable,
        string context)
    {
        var executableReader = new CanonicalNoritoReader(
            executable,
            $"{context} executable",
            nameof(executable));
        if (executableReader.ReadUInt32LittleEndian("variant") != 0)
        {
            throw new JsonException(
                $"{context} multisig transaction executable must be an instruction list.");
        }
        var sequenceBytes = executableReader.ReadField("instructions");
        executableReader.RequireEnd();
        var sequence = new CanonicalNoritoReader(
            sequenceBytes,
            $"{context} executable instructions",
            nameof(executable));
        var count = sequence.ReadSequenceLength("count");
        if (count > 16)
        {
            throw new JsonException($"{context} executable instruction count is invalid.");
        }
        var instructions = new List<EncodedInstruction>(checked((int)count));
        for (var index = 0; index < checked((int)count); index++)
        {
            instructions.Add(DecodeInstructionPair(
                sequence.ReadField($"instruction[{index}]"),
                context));
        }
        sequence.RequireEnd();
        return instructions;
    }

    private static EncodedInstruction DecodeInstructionArchive(
        string encoded,
        string context)
    {
        var archive = Convert.FromBase64String(encoded);
        if (!string.Equals(Convert.ToBase64String(archive), encoded, StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context} nested instruction must use canonical base64 text.");
        }
        var (payload, flags) = NoritoCodec.DecodeWithSchemaHash(
            MultisigInstructionBoxSchemaHash,
            archive);
        if (flags != NoritoCodec.CanonicalLayoutFlags
            || !archive.AsSpan().SequenceEqual(NoritoCodec.EncodeWithSchemaHash(
                MultisigInstructionBoxSchemaHash,
                payload,
                flags)))
        {
            throw new JsonException(
                $"{context} nested instruction is not a canonical InstructionBox archive.");
        }
        return DecodeInstructionPair(payload, context);
    }

    private static EncodedInstruction DecodeInstructionPair(
        ReadOnlySpan<byte> pair,
        string context)
    {
        var pairReader = new CanonicalNoritoReader(
            pair,
            $"{context} instruction",
            nameof(pair));
        var wireId = DecodeCanonicalNoritoString(
            pairReader.ReadField("wire_id"),
            context);
        var payloadVector = pairReader.ReadField("framed_payload");
        pairReader.RequireEnd();
        var vectorReader = new CanonicalNoritoReader(
            payloadVector,
            $"{context} instruction payload",
            nameof(pair));
        var length = vectorReader.ReadSequenceLength("length");
        if (length > int.MaxValue || length != checked((ulong)vectorReader.Remaining))
        {
            throw new JsonException($"{context} instruction payload length is invalid.");
        }
        var framedPayload = vectorReader.ReadExact(checked((int)length), "bytes").ToArray();
        vectorReader.RequireEnd();
        return new EncodedInstruction(wireId, framedPayload);
    }

    private static JsonNode DecodeMultisigCustomInstruction(
        EncodedInstruction instruction,
        string encodingAccountId,
        string context)
    {
        if (!string.Equals(instruction.WireId, "iroha.custom", StringComparison.Ordinal))
        {
            throw new JsonException($"{context} expected a canonical multisig custom instruction.");
        }
        var payload = DecodeCanonicalNoritoFrame(
            "iroha_data_model::isi::transparent::CustomInstruction",
            instruction.FramedPayload,
            context);
        var reader = new CanonicalNoritoReader(
            payload,
            $"{context} custom instruction",
            nameof(instruction));
        var jsonBytes = reader.ReadField("payload");
        reader.RequireEnd();
        var jsonReader = new CanonicalNoritoReader(jsonBytes, $"{context} Json", nameof(instruction));
        var jsonString = jsonReader.ReadField("value");
        jsonReader.RequireEnd();
        var jsonText = DecodeCanonicalNoritoString(jsonString, context);
        var value = JsonNode.Parse(jsonText)
            ?? throw new JsonException($"{context} custom instruction JSON must not be null.");
        var canonical = new MultisigCustomInstruction(value)
            .EncodeFramedPayload(new TransactionEncodingContext(encodingAccountId));
        if (!instruction.FramedPayload.AsSpan().SequenceEqual(canonical))
        {
            throw new JsonException(
                $"{context} custom instruction payload is not canonical JSON.");
        }
        return value;
    }

    private static byte[] DecodeCanonicalNoritoFrame(
        string typeName,
        ReadOnlySpan<byte> frame,
        string context)
    {
        var (payload, flags) = NoritoCodec.Decode(typeName, frame);
        if (flags != NoritoCodec.CanonicalLayoutFlags
            || !frame.SequenceEqual(NoritoCodec.Encode(typeName, payload, flags)))
        {
            throw new JsonException($"{context} contains a noncanonical Norito frame.");
        }
        return payload;
    }

    private static string DecodeCanonicalNoritoString(
        ReadOnlySpan<byte> encoded,
        string context)
    {
        var reader = new CanonicalNoritoReader(
            encoded,
            $"{context} string",
            nameof(encoded));
        var length = reader.ReadCompactLength("length");
        if (length > int.MaxValue || length != checked((ulong)reader.Remaining))
        {
            throw new JsonException($"{context} contains an invalid Norito string length.");
        }
        var bytes = reader.ReadExact(checked((int)length), "text");
        reader.RequireEnd();
        return StrictUtf8.GetString(bytes);
    }

    private static string DecodeCanonicalNoritoStringField(
        ReadOnlySpan<byte> encoded,
        string fieldName,
        string context)
    {
        // Native TriggerId owns one Name field; native Json owns one String field.
        // Both records retain their field boundary before the inner string bytes.
        var reader = new CanonicalNoritoReader(encoded, context, nameof(encoded));
        var value = reader.ReadField(fieldName);
        reader.RequireEnd();
        return DecodeCanonicalNoritoString(value, context);
    }

    private static JsonObject RequireExactJsonObject(
        JsonNode? value,
        IReadOnlyCollection<string> expectedKeys,
        string context)
    {
        if (value is not JsonObject obj
            || obj.Count != expectedKeys.Count
            || obj.Any(pair => !expectedKeys.Contains(pair.Key, StringComparer.Ordinal)))
        {
            throw new JsonException($"{context} multisig custom instruction has an unexpected shape.");
        }
        return obj;
    }

    private static (string TriggerId, JsonNode? Arguments) DecodeExecuteTrigger(
        EncodedInstruction instruction,
        string context)
    {
        var payload = DecodeCanonicalNoritoFrame(
            "iroha_data_model::isi::transparent::ExecuteTrigger",
            instruction.FramedPayload,
            context);
        var reader = new CanonicalNoritoReader(
            payload,
            $"{context} execute-trigger instruction",
            nameof(instruction));
        var triggerId = DecodeCanonicalNoritoStringField(
            reader.ReadField("trigger"),
            "name",
            context);
        var argumentsText = DecodeCanonicalNoritoStringField(
            reader.ReadField("args"),
            "value",
            context);
        reader.RequireEnd();
        return (triggerId, JsonNode.Parse(argumentsText));
    }

    private static void ValidateContractCallTriggerRegistration(
        EncodedInstruction instruction,
        string expectedTriggerId,
        ReadOnlySpan<byte> expectedMetadata,
        MultisigPayloadBinding binding,
        TransactionContractInvocation expectedInvocation,
        string context)
    {
        var payload = DecodeCanonicalNoritoFrame(
            "iroha_data_model::isi::register::RegisterBox",
            instruction.FramedPayload,
            context);
        var registerBox = new CanonicalNoritoReader(
            payload,
            $"{context} register instruction",
            nameof(instruction));
        if (registerBox.ReadUInt32LittleEndian("variant") != 6)
        {
            throw new JsonException($"{context} contract-call proposal did not register a trigger.");
        }
        var registerPayload = registerBox.ReadField("trigger");
        registerBox.RequireEnd();
        var register = new CanonicalNoritoReader(
            registerPayload,
            $"{context} trigger registration",
            nameof(instruction));
        var triggerPayload = register.ReadField("object");
        register.RequireEnd();
        var trigger = new CanonicalNoritoReader(
            triggerPayload,
            $"{context} trigger",
            nameof(instruction));
        var triggerId = DecodeCanonicalNoritoStringField(trigger.ReadField("id"), "name", context);
        var actionPayload = trigger.ReadField("action");
        trigger.RequireEnd();
        if (!string.Equals(triggerId, expectedTriggerId, StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context} registered and executed different contract-call triggers.");
        }

        var action = new CanonicalNoritoReader(
            actionPayload,
            $"{context} trigger action",
            nameof(instruction));
        var executable = action.ReadField("executable");
        var repeats = action.ReadField("repeats");
        var authority = action.ReadField("authority");
        var filter = action.ReadField("filter");
        var retryPolicy = action.ReadField("retry_policy");
        var metadata = action.ReadField("metadata");
        action.RequireEnd();

        var encoding = new TransactionEncodingContext(binding.ContractCallRequest!.SignerAccountId);
        if (!authority.SequenceEqual(encoding.EncodeAccountId(binding.ResolvedMultisigAccountId!))
            || !metadata.SequenceEqual(expectedMetadata)
            || !retryPolicy.SequenceEqual(new byte[] { 0 }))
        {
            throw new JsonException(
                $"{context} contract-call trigger authority, metadata, or retry policy was substituted.");
        }
        ValidateExactlyOnceRepeats(repeats, context);
        ValidateExecuteTriggerFilter(
            filter,
            expectedTriggerId,
            encoding.EncodeAccountId(binding.ResolvedMultisigAccountId!),
            context);
        ValidateContractInvocation(
            executable,
            expectedInvocation,
            context);
    }

    private static void ValidateExactlyOnceRepeats(ReadOnlySpan<byte> repeats, string context)
    {
        var reader = new CanonicalNoritoReader(repeats, $"{context} repeats", nameof(repeats));
        if (reader.ReadUInt32LittleEndian("variant") != 1)
        {
            throw new JsonException($"{context} contract-call trigger must execute exactly once.");
        }
        var count = reader.ReadField("count");
        reader.RequireEnd();
        if (count.Length != sizeof(uint)
            || BinaryPrimitives.ReadUInt32LittleEndian(count) != 1)
        {
            throw new JsonException($"{context} contract-call trigger must execute exactly once.");
        }
    }

    private static void ValidateExecuteTriggerFilter(
        ReadOnlySpan<byte> filter,
        string expectedTriggerId,
        ReadOnlySpan<byte> expectedAuthority,
        string context)
    {
        var box = new CanonicalNoritoReader(filter, $"{context} trigger filter", nameof(filter));
        if (box.ReadUInt32LittleEndian("variant") != 3)
        {
            throw new JsonException($"{context} contract-call trigger uses the wrong event filter.");
        }
        var payload = box.ReadField("execute_trigger");
        box.RequireEnd();
        var reader = new CanonicalNoritoReader(
            payload,
            $"{context} execute-trigger filter",
            nameof(filter));
        var triggerId = ReadRequiredNoritoOption(reader.ReadField("trigger_id"), context);
        var authority = ReadRequiredNoritoOption(reader.ReadField("authority"), context);
        reader.RequireEnd();
        if (!string.Equals(
                DecodeCanonicalNoritoStringField(triggerId, "name", context),
                expectedTriggerId,
                StringComparison.Ordinal)
            || !authority.AsSpan().SequenceEqual(expectedAuthority))
        {
            throw new JsonException(
                $"{context} contract-call trigger filter was substituted.");
        }
    }

    private static byte[] ReadRequiredNoritoOption(ReadOnlySpan<byte> option, string context)
    {
        var reader = new CanonicalNoritoReader(option, $"{context} option", nameof(option));
        if (reader.ReadByte("tag") != 1)
        {
            throw new JsonException($"{context} required option is absent.");
        }
        var value = reader.ReadField("value").ToArray();
        reader.RequireEnd();
        return value;
    }

    private static void ValidateContractInvocation(
        ReadOnlySpan<byte> executable,
        TransactionContractInvocation expectedInvocation,
        string context)
    {
        var executableReader = new CanonicalNoritoReader(
            executable,
            $"{context} trigger executable",
            nameof(executable));
        if (executableReader.ReadUInt32LittleEndian("variant") != 1)
        {
            throw new JsonException($"{context} trigger executable is not a contract call.");
        }
        var invocationPayload = executableReader.ReadField("contract_call");
        executableReader.RequireEnd();
        var invocation = new CanonicalNoritoReader(
            invocationPayload,
            $"{context} contract invocation",
            nameof(executable));
        var address = DecodeCanonicalNoritoString(invocation.ReadField("contract_address"), context);
        var codeHash = invocation.ReadField("expected_code_hash");
        var entrypoint = DecodeCanonicalNoritoString(invocation.ReadField("entrypoint"), context);
        var arguments = invocation.ReadField("arguments");
        invocation.RequireEnd();
        if (!string.Equals(
                address,
                expectedInvocation.ContractAddress,
                StringComparison.Ordinal)
            || !codeHash.SequenceEqual(expectedInvocation.ExpectedCodeHash)
            || !string.Equals(
                entrypoint,
                expectedInvocation.Entrypoint,
                StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context} contract invocation changed the requested target, code hash, or entrypoint.");
        }
        var argumentsReader = new CanonicalNoritoReader(
            arguments,
            $"{context} contract arguments",
            nameof(executable));
        var tag = argumentsReader.ReadByte("tag");
        var expectedArgumentRecord = expectedInvocation.Arguments;
        if (tag != (expectedArgumentRecord is null ? 0 : 1))
        {
            throw new JsonException(
                $"{context} contract invocation changed whether arguments are present.");
        }
        if (tag == 1)
        {
            var encodedRecord = new CanonicalNoritoReader(
                argumentsReader.ReadField("value"),
                $"{context} contract argument record",
                nameof(executable));
            var recordLength = encodedRecord.ReadSequenceLength("length");
            if (recordLength > TransactionContractInvocation.MaximumArgumentsBytes)
            {
                throw new JsonException(
                    $"{context} contract argument record exceeds the wire limit.");
            }
            var record = encodedRecord.ReadExact(checked((int)recordLength), "bytes");
            encodedRecord.RequireEnd();
            if (expectedArgumentRecord is null
                || !record.SequenceEqual(expectedArgumentRecord))
            {
                throw new JsonException(
                    $"{context} contract argument record differs from the trusted expected bytes.");
            }
        }
        argumentsReader.RequireEnd();
    }

    private sealed record class EncodedInstruction(string WireId, byte[] FramedPayload);

    private sealed record class MultisigPayloadBinding(
        IReadOnlyList<byte[]> AllowedExecutables,
        byte[]? ExactMetadata,
        ToriiMultisigContractCallProposeRequest? ContractCallRequest,
        string? ContractProposalHash,
        string? ResolvedMultisigAccountId);

    private sealed record class MultisigCustomInstruction(JsonNode Payload)
        : TransactionInstruction
    {
        internal override string WireId => "iroha.custom";

        internal override string TypeName =>
            "iroha_data_model::isi::transparent::CustomInstruction";

        internal override byte[] EncodePayload(TransactionEncodingContext context)
        {
            var writer = new CanonicalNoritoWriter();
            writer.WriteField(context.EncodeJson(Payload));
            return writer.ToArray();
        }
    }

    private static string RequirePreparedResponseSchema(JsonElement response, string context)
    {
        if (response.ValueKind != JsonValueKind.Object
            || !response.TryGetProperty("schema", out var schema)
            || schema.ValueKind != JsonValueKind.String
            || string.IsNullOrEmpty(schema.GetString()))
        {
            throw new JsonException($"{context}.schema must be a non-empty string.");
        }
        return schema.GetString()!;
    }

    private static ToriiPreparedOperationBindingV1 NormalizePreparedOperationBinding(
        ToriiPreparedOperationBindingV1 binding,
        string expectedKind,
        bool requireActive)
    {
        ArgumentNullException.ThrowIfNull(binding);
        if (!string.Equals(
                binding.Schema,
                ToriiPreparedOperationBindingV1.SchemaV1,
                StringComparison.Ordinal))
        {
            throw new ArgumentException("Prepared operation binding has an unsupported schema.", nameof(binding));
        }
        if (!IsExactLowerHex(binding.SemanticHashHex, 32)
            || !IsExactLowerHex(binding.RequestId, 32))
        {
            throw new ArgumentException(
                "Prepared operation binding hashes and request identity must contain exactly 32 bytes of lowercase hexadecimal.",
                nameof(binding));
        }
        if (!string.Equals(binding.Kind, expectedKind, StringComparison.Ordinal))
        {
            throw new ArgumentException("Prepared operation binding belongs to another operation.", nameof(binding));
        }
        if (binding.ExecutionExpiresAtUnixMilliseconds == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(binding),
                "Prepared operation binding execution expiry must be positive.");
        }
        if (requireActive
            && binding.ExecutionExpiresAtUnixMilliseconds
                <= checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()))
        {
            throw new ArgumentException("Prepared operation binding is expired for execution.", nameof(binding));
        }
        return binding with { };
    }

    /// <summary>Authenticate a retained onboarding envelope without HTTP or a current-time expiry check.</summary>
    /// <remarks>Caller-trusted request, receipt, authority, network and fee intent remain mandatory.</remarks>
    public static void VerifyAccountOnboardingPreparedTransactionV1(
        ToriiAccountOnboardingPreparedTransactionV1 prepared,
        ToriiAccountOnboardingPlanRequest exactExpectedRequest,
        ToriiAccountOnboardingPlanReceipt expectedReceipt,
        ToriiPreparedOperationBindingV1 expectedBinding,
        FeePaymentIntent expectedFeePayment,
        string expectedAuthority,
        NetworkId expectedNetworkId,
        ToriiAccountOnboardingPlanBodyEncoder canonicalBodyEncoder)
    {
        ArgumentNullException.ThrowIfNull(prepared);
        exactExpectedRequest = NormalizeAccountOnboardingPlanRequest(exactExpectedRequest);
        expectedFeePayment = NormalizeFeePaymentIntent(expectedFeePayment, nameof(expectedFeePayment), requireGasLimit: false);
        if (prepared.Binding is null
            || prepared.Receipt is null
            || prepared.Disposition is null)
        {
            throw new JsonException("prepared onboarding response is missing a required object.");
        }
        var exactBinding = NormalizePreparedOperationBinding(
            prepared.Binding,
            ToriiAccountOnboardingPreparedTransactionV1.OperationV1,
            requireActive: false);
        RequireMatchingPreparedBinding(exactBinding, expectedBinding, "prepared onboarding binding");
        ToriiAccountOnboardingReceiptVerifier.RequirePinned(
            prepared.Receipt,
            expectedAuthority,
            expectedNetworkId,
            canonicalBodyEncoder);
        ToriiAccountOnboardingReceiptVerifier.RequirePinned(
            expectedReceipt,
            expectedAuthority,
            expectedNetworkId,
            canonicalBodyEncoder);
        RequireMatchingAccountOnboardingRequest(
            exactExpectedRequest,
            expectedReceipt.Body.Request,
            "expected onboarding receipt");
        if (!string.Equals(prepared.Schema, ToriiAccountOnboardingPreparedTransactionV1.SchemaV1, StringComparison.Ordinal)
            || !string.Equals(prepared.Operation, ToriiAccountOnboardingPreparedTransactionV1.OperationV1, StringComparison.Ordinal)
            || !string.Equals(prepared.Receipt.PlanHash, expectedReceipt.PlanHash, StringComparison.Ordinal)
            || !string.Equals(prepared.Receipt.Signature, expectedReceipt.Signature, StringComparison.Ordinal))
        {
            throw new JsonException("prepared onboarding response differs from its exact receipt or protocol identity.");
        }
        RequireMatchingAccountOnboardingRequest(
            expectedReceipt.Body.Request,
            prepared.Receipt.Body.Request,
            "prepared onboarding receipt");
        var semanticHash = expectedReceipt.PlanHash.Substring(5, 64).ToLowerInvariant();
        ValidatePreparedSemanticBinding(exactBinding, semanticHash, expectedReceipt.Body.ValidUntilMilliseconds);
        if (!string.Equals(prepared.SemanticHashHex, semanticHash, StringComparison.Ordinal)
            || !string.Equals(
                prepared.AccountId,
                expectedReceipt.Body.Request.AccountId,
                StringComparison.Ordinal)
            || !string.Equals(prepared.Alias, expectedReceipt.Body.Request.Alias, StringComparison.Ordinal))
        {
            throw new JsonException("prepared onboarding response substituted its semantic identity.");
        }
        ValidateOnboardingDispositionTransition(
            expectedReceipt.Body.Resource,
            prepared.Disposition,
            "prepared onboarding response");
        var transaction = ValidatePreparedWire(
            prepared.TransactionHashHex,
            prepared.SignedTransactionWireHex,
            prepared.SignedTransactionWireSha256,
            "prepared onboarding response");
        var feePayment = prepared.FeePayment
            ?? throw new JsonException("prepared onboarding response.fee_payment must not be null.");
        if (!feePayment.HasSamePayerAndGasBound(expectedFeePayment))
        {
            throw new JsonException(
                "prepared onboarding response.fee_payment changed the requested payer, sponsor revision, or gas bound.");
        }
        var signerPublicKey = ValidatePreparedTransactionPayload(
            transaction,
            expectedNetworkId,
            expectedAuthority,
            prepared.AccountId,
            feePayment,
            exactBinding,
            prepared.Operation,
            prepared.SemanticHashHex,
            "prepared onboarding response");
        var actualInstructions = DecodePreparedInstructionSequence(
            transaction.Executable,
            "prepared onboarding response");
        var plannedInstructions = EncodeOnboardingInstructionFrames(
            expectedReceipt.Body.Instructions,
            prepared.AccountId,
            "prepared onboarding receipt.instructions");
        if (actualInstructions.Count == 0
            || !InstructionsAreOrderedSubset(actualInstructions, plannedInstructions))
        {
            throw new JsonException(
                "prepared onboarding transaction instructions are not an ordered subset of its signed receipt.");
        }
        ToriiPreparedTransactionSignatureV1.Verify(
            ToriiPreparedTransactionSignatureV1.OnboardingPreparedTranscript(
                prepared,
                transaction.Wire),
            prepared.ServerSignature,
            signerPublicKey,
            "prepared onboarding response");
    }

    private static void ValidateProofRequiredAccountOnboarding(
        ToriiAccountOnboardingProofRequiredPrepareResponseV1 proofRequired,
        ToriiAccountOnboardingPlanRequest exactExpectedRequest,
        ToriiAccountOnboardingPlanReceipt expectedReceipt,
        ToriiPreparedOperationBindingV1 expectedBinding,
        string expectedAuthority,
        NetworkId expectedNetworkId,
        ToriiAccountOnboardingPlanBodyEncoder canonicalBodyEncoder)
    {
        ArgumentNullException.ThrowIfNull(proofRequired);
        if (proofRequired.Binding is null || proofRequired.Disposition is null)
        {
            throw new JsonException("proof-required onboarding response is missing a required object.");
        }
        var exactBinding = NormalizePreparedOperationBinding(
            proofRequired.Binding,
            ToriiAccountOnboardingProofRequiredPrepareResponseV1.OperationV1,
            requireActive: false);
        var expectedExactBinding = NormalizePreparedOperationBinding(
            expectedBinding,
            ToriiAccountOnboardingProofRequiredPrepareResponseV1.OperationV1,
            requireActive: false);
        RequireMatchingPreparedBinding(
            exactBinding,
            expectedExactBinding,
            "proof-required onboarding binding");
        ToriiAccountOnboardingReceiptVerifier.RequirePinned(
            expectedReceipt,
            expectedAuthority,
            expectedNetworkId,
            canonicalBodyEncoder);
        RequireMatchingAccountOnboardingRequest(
            exactExpectedRequest,
            expectedReceipt.Body.Request,
            "expected onboarding receipt");
        var semanticHash = expectedReceipt.PlanHash.Substring(5, 64).ToLowerInvariant();
        ValidatePreparedSemanticBinding(exactBinding, semanticHash, expectedReceipt.Body.ValidUntilMilliseconds);
        if (!string.Equals(proofRequired.Schema, ToriiAccountOnboardingProofRequiredPrepareResponseV1.SchemaV1, StringComparison.Ordinal)
            || !string.Equals(proofRequired.Operation, ToriiAccountOnboardingProofRequiredPrepareResponseV1.OperationV1, StringComparison.Ordinal)
            || !string.Equals(proofRequired.Outcome, ToriiAccountOnboardingProofRequiredPrepareResponseV1.OutcomeV1, StringComparison.Ordinal)
            || !string.Equals(proofRequired.ProofKind, ToriiAccountOnboardingProofRequiredPrepareResponseV1.ProofKindV1, StringComparison.Ordinal)
            || !string.Equals(proofRequired.SemanticHashHex, semanticHash, StringComparison.Ordinal)
            || !string.Equals(
                proofRequired.AccountId,
                expectedReceipt.Body.Request.AccountId,
                StringComparison.Ordinal)
            || !string.Equals(proofRequired.Alias, expectedReceipt.Body.Request.Alias, StringComparison.Ordinal))
        {
            throw new JsonException(
                "proof-required onboarding response differs from its exact receipt or protocol identity.");
        }
        ValidateOnboardingDispositionTransition(
            expectedReceipt.Body.Resource,
            proofRequired.Disposition,
            "proof-required onboarding response");
        if (!string.Equals(proofRequired.Disposition.Kind, "no_op", StringComparison.Ordinal))
        {
            throw new JsonException("proof-required onboarding response disposition must be no_op.");
        }
        ToriiPreparedTransactionSignatureV1.Verify(
            ToriiPreparedTransactionSignatureV1.OnboardingProofRequiredTranscript(proofRequired),
            proofRequired.ServerSignature,
            PreparedEd25519PublicKeyFromAccountId(
                expectedAuthority,
                "proof-required onboarding response"),
            "proof-required onboarding response");
    }

    private static ToriiAccountOnboardingCurrentStateKindV1 ValidateAccountOnboardingCurrentState(
        ToriiAccountOnboardingCurrentStateResponseV1 observation,
        ToriiAccountOnboardingCurrentStateRequestV1 request,
        NetworkId expectedNetworkId)
    {
        ArgumentNullException.ThrowIfNull(observation);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(expectedNetworkId);
        if (observation.Version != ToriiAccountOnboardingCurrentStateResponseV1.VersionV1)
        {
            throw new JsonException("account onboarding current-state response has an unsupported version.");
        }
        if (observation.NetworkId is null || observation.NetworkId != expectedNetworkId)
        {
            throw new JsonException("account onboarding current-state response changed network_id.");
        }
        if (!string.Equals(observation.AccountId, request.AccountId, StringComparison.Ordinal)
            || !string.Equals(observation.Alias, request.Alias, StringComparison.Ordinal))
        {
            throw new JsonException(
                "account onboarding current-state response does not bind the exact request.");
        }
        if (!observation.AccountExists)
        {
            throw new JsonException(
                "account onboarding current-state response reports the expected account absent.");
        }
        if (observation.ObservedBlockHeight == 0)
        {
            throw new JsonException(
                "account onboarding current-state response has a zero committed height.");
        }
        try
        {
            _ = NetworkId.Parse(observation.ObservedBlockHash);
        }
        catch (FormatException error)
        {
            throw new JsonException(
                "account onboarding current-state response block hash is not a canonical typed hash.",
                error);
        }

        if (observation.AliasTargetAccountId is null)
        {
            return ToriiAccountOnboardingCurrentStateKindV1.AliasAbsent;
        }
        try
        {
            _ = AccountAddress.Parse(observation.AliasTargetAccountId);
        }
        catch (AccountAddressException error)
        {
            throw new JsonException(
                "account onboarding current-state response alias target is not a canonical account id.",
                error);
        }
        return AccountIdsHaveSameIdentity(observation.AliasTargetAccountId, request.AccountId)
            ? ToriiAccountOnboardingCurrentStateKindV1.Applied
            : ToriiAccountOnboardingCurrentStateKindV1.AliasConflict;
    }

    /// <summary>Verifies a durable prepared faucet envelope against caller-trusted network and policy without HTTP or a current-time check.</summary>
    public static void VerifyAccountFaucetPreparedTransactionV1(
        ToriiAccountFaucetPreparedTransactionV1 prepared,
        ToriiAccountFaucetClaimV1 expectedClaim,
        ToriiPreparedOperationBindingV1 expectedBinding,
        FeePaymentIntent expectedFeePayment,
        ToriiAccountFaucetPolicyV1 policy,
        NetworkId expectedNetworkId)
    {
        ArgumentNullException.ThrowIfNull(prepared);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(expectedNetworkId);
        expectedFeePayment = NormalizeFeePaymentIntent(expectedFeePayment, nameof(expectedFeePayment), requireGasLimit: false);
        if (prepared.Binding is null || prepared.Claim is null)
        {
            throw new JsonException("prepared faucet response is missing a required object.");
        }
        var exactBinding = NormalizePreparedOperationBinding(
            prepared.Binding,
            ToriiAccountFaucetPreparedTransactionV1.OperationV1,
            requireActive: false);
        RequireMatchingPreparedBinding(exactBinding, expectedBinding, "prepared faucet binding");
        var claim = NormalizeAccountFaucetClaim(prepared.Claim);
        var expected = NormalizeAccountFaucetClaim(expectedClaim);
        ValidatePreparedSemanticBinding(exactBinding, FaucetClaimSemanticHashHex(expected), ulong.MaxValue);
        if (!string.Equals(prepared.Schema, ToriiAccountFaucetPreparedTransactionV1.SchemaV1, StringComparison.Ordinal)
            || !string.Equals(prepared.Operation, ToriiAccountFaucetPreparedTransactionV1.OperationV1, StringComparison.Ordinal)
            || !string.Equals(claim.AccountId, expected.AccountId, StringComparison.Ordinal)
            || claim.PowAnchorHeight != expected.PowAnchorHeight
            || !string.Equals(claim.PowNonceHex, expected.PowNonceHex, StringComparison.Ordinal)
            || !string.Equals(prepared.AccountId, expected.AccountId, StringComparison.Ordinal)
            || !string.Equals(
                prepared.AssetDefinitionId,
                policy.AssetDefinitionId,
                StringComparison.Ordinal)
            || !string.Equals(
                prepared.Amount,
                policy.Amount.ToString(),
                StringComparison.Ordinal))
        {
            throw new JsonException(
                "prepared faucet response differs from its exact claim, protocol identity, or trusted policy.");
        }
        _ = RequireExactLowerHex(prepared.SemanticHashHex, 32, "prepared faucet response.semantic_hash_hex");
        if (!string.Equals(
                prepared.SemanticHashHex,
                FaucetClaimSemanticHashHex(claim),
                StringComparison.Ordinal))
        {
            throw new JsonException("prepared faucet response semantic hash differs from its exact claim.");
        }
        _ = ToriiAccountFaucetMetadata.RequireExactTokenText(
            prepared.AssetDefinitionId,
            "prepared faucet response.asset_definition_id");
        try
        {
            _ = new TransactionEncodingContext(prepared.AccountId)
                .EncodeAssetDefinitionId(prepared.AssetDefinitionId);
        }
        catch (ArgumentException error)
        {
            throw new JsonException(
                "prepared faucet response.asset_definition_id is not canonical.",
                error);
        }
        _ = ToriiAccountFaucetMetadata.RequireExactTokenText(
            prepared.AssetId,
            "prepared faucet response.asset_id");
        if (!string.Equals(
                prepared.AssetId,
                $"{prepared.AssetDefinitionId}#{prepared.AccountId}",
                StringComparison.Ordinal))
        {
            throw new JsonException("prepared faucet response destination asset differs from its exact claim.");
        }
        _ = ToriiAccountFaucetMetadata.RequireCanonicalQuantityText(
            prepared.Amount,
            "prepared faucet response.amount");
        var transaction = ValidatePreparedWire(
            prepared.TransactionHashHex,
            prepared.SignedTransactionWireHex,
            prepared.SignedTransactionWireSha256,
            "prepared faucet response");
        var feePayment = prepared.FeePayment
            ?? throw new JsonException("prepared faucet response.fee_payment must not be null.");
        if (!feePayment.HasSamePayerAndGasBound(expectedFeePayment))
        {
            throw new JsonException(
                "prepared faucet response.fee_payment changed the requested payer, sponsor revision, or gas bound.");
        }
        var signerPublicKey = ValidatePreparedTransactionPayload(
            transaction,
            expectedNetworkId,
            policy.FaucetAuthority,
            prepared.AccountId,
            feePayment,
            exactBinding,
            prepared.Operation,
            prepared.SemanticHashHex,
            "prepared faucet response");
        ValidatePreparedFaucetInstructions(
            transaction,
            prepared,
            signerPublicKey,
            "prepared faucet response");
        ToriiPreparedTransactionSignatureV1.Verify(
            ToriiPreparedTransactionSignatureV1.FaucetPreparedTranscript(
                prepared,
                transaction.Wire),
            prepared.ServerSignature,
            signerPublicKey,
            "prepared faucet response");
    }

    private static string FaucetClaimSemanticHashHex(ToriiAccountFaucetClaimV1 claim)
    {
        var encoding = new TransactionEncodingContext(claim.AccountId);
        var encodedClaim = new CanonicalNoritoWriter();
        encodedClaim.WriteField(encoding.EncodeString(claim.AccountId));
        encodedClaim.WriteField(encoding.EncodeUInt64(claim.PowAnchorHeight));
        encodedClaim.WriteField(encoding.EncodeString(claim.PowNonceHex));
        var claimBytes = encodedClaim.ToArray();
        var domainAndClaim = new byte[FaucetClaimHashDomainV1.Length + claimBytes.Length];
        FaucetClaimHashDomainV1.CopyTo(domainAndClaim, 0);
        claimBytes.CopyTo(domainAndClaim, FaucetClaimHashDomainV1.Length);
        return Convert.ToHexString(IrohaHash.Hash(domainAndClaim)).ToLowerInvariant();
    }

    private static void ValidatePreparedSubmitResponse(
        ToriiPreparedTransactionSubmitResponseV1 response,
        ToriiPreparedOperationBindingV1 expectedBinding,
        string expectedOperation,
        string expectedTransactionHashHex,
        HttpStatusCode statusCode,
        string context)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.Binding is null)
        {
            throw new JsonException($"{context}.binding must not be null.");
        }
        var exactBinding = NormalizePreparedOperationBinding(
            response.Binding,
            expectedOperation,
            requireActive: false);
        RequireMatchingPreparedBinding(exactBinding, expectedBinding, $"{context}.binding");
        if (!string.Equals(response.Schema, ToriiPreparedTransactionSubmitResponseV1.SchemaV1, StringComparison.Ordinal)
            || !string.Equals(response.Operation, expectedOperation, StringComparison.Ordinal)
            || !string.Equals(response.TransactionHashHex, expectedTransactionHashHex, StringComparison.Ordinal)
            || statusCode is not (HttpStatusCode.OK or HttpStatusCode.Accepted)
            || (statusCode == HttpStatusCode.Accepted
                && !string.Equals(response.Outcome, "Pending", StringComparison.Ordinal))
            || response.Outcome is not ("Applied" or "Pending" or "Rejected"))
        {
            throw new JsonException($"{context} is not bound to the exact prepared transaction.");
        }
        _ = RequireExactLowerHex(response.TransactionHashHex, 32, $"{context}.transaction_hash_hex");
    }

    private static void RequireExactPreparedStatus(
        HttpStatusCode actual,
        HttpStatusCode expected,
        string context)
    {
        if (actual != expected)
        {
            throw new JsonException(
                $"{context} must return HTTP {(int)expected}, got {(int)actual}.");
        }
    }

    private static void RequireMatchingPreparedBinding(
        ToriiPreparedOperationBindingV1 actual,
        ToriiPreparedOperationBindingV1 expected,
        string context)
    {
        if (actual != expected)
        {
            throw new JsonException($"{context} differs from the exact requested binding.");
        }
    }

    private const int MaximumPreparedTransactionWireBytesV1 = 16 * 1024 * 1024;

    private sealed record PreparedTransactionWireV1(
        byte[] Wire,
        byte[] Payload,
        ulong CreationTimeMilliseconds,
        ulong TimeToLiveMilliseconds,
        byte[] NetworkDomain,
        byte[] Authority,
        byte[] FeePayment,
        byte[] Executable,
        byte[] Metadata,
        byte[] Signature);

    private static PreparedTransactionWireV1 ValidatePreparedWire(
        string transactionHashHex,
        string wireHex,
        string wireSha256,
        string context)
    {
        _ = RequireExactLowerHex(transactionHashHex, 32, $"{context}.transaction_hash_hex");
        _ = RequireExactLowerHex(wireSha256, 32, $"{context}.signed_transaction_wire_sha256");
        if (string.IsNullOrEmpty(wireHex)
            || wireHex.Length % 2 != 0
            || wireHex.Length > MaximumPreparedTransactionWireBytesV1 * 2
            || wireHex.Any(static value => value is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new JsonException($"{context}.signed_transaction_wire_hex must be non-empty canonical lowercase hexadecimal.");
        }
        var wire = Convert.FromHexString(wireHex);
        var actualSha256 = Convert.ToHexString(SHA256.HashData(wire)).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(actualSha256),
                Encoding.ASCII.GetBytes(wireSha256)))
        {
            throw new JsonException($"{context}.signed_transaction_wire_sha256 does not match the exact wire.");
        }

        if (wire.Length < 2 || wire[0] != 1)
        {
            throw new JsonException(
                $"{context}.signed_transaction_wire_hex must contain one fixed-V1 SignedTransaction.");
        }

        byte[] signature;
        byte[] payload;
        try
        {
            var transaction = new CanonicalNoritoReader(
                wire.AsSpan(1),
                $"{context} signed transaction",
                nameof(wireHex));
            signature = transaction.ReadField("signature").ToArray();
            payload = transaction.ReadField("payload").ToArray();
            var multisigSignatures = transaction.ReadField("multisig_signatures");
            transaction.RequireEnd();
            if (signature.Length == 0
                || payload.Length == 0
                || !multisigSignatures.SequenceEqual(new byte[] { 0 }))
            {
                throw new JsonException(
                    $"{context}.signed_transaction_wire_hex has a noncanonical signature, payload, or multisig field.");
            }
        }
        catch (ArgumentException error)
        {
            throw new JsonException(
                $"{context}.signed_transaction_wire_hex is not one canonical fixed-V1 SignedTransaction.",
                error);
        }

        var entrypoint = new CanonicalNoritoWriter();
        entrypoint.WriteUInt32LittleEndian(0);
        entrypoint.WriteField(payload);
        var actualTransactionHash = IrohaHash.Hash(entrypoint.ToArray());
        var expectedTransactionHash = Convert.FromHexString(transactionHashHex);
        if (!CryptographicOperations.FixedTimeEquals(
                actualTransactionHash,
                expectedTransactionHash))
        {
            throw new JsonException(
                $"{context}.transaction_hash_hex does not match the exact prepared transaction payload.");
        }

        try
        {
            var transactionPayload = new CanonicalNoritoReader(
                payload,
                $"{context} transaction payload",
                nameof(wireHex));
            var networkDomain = transactionPayload.ReadField("domain").ToArray();
            var authority = transactionPayload.ReadField("authority").ToArray();
            var creationTime = transactionPayload.ReadField("creation_time_ms");
            var executable = transactionPayload.ReadField("executable");
            var timeToLive = transactionPayload.ReadField("time_to_live_ms");
            _ = transactionPayload.ReadField("nonce");
            var feePayment = transactionPayload.ReadField("fee_payment").ToArray();
            var metadata = transactionPayload.ReadField("metadata").ToArray();
            var attachments = transactionPayload.ReadField("attachments");
            transactionPayload.RequireEnd();
            if (networkDomain.Length == 0
                || authority.Length == 0
                || creationTime.Length != sizeof(ulong)
                || executable.Length == 0
                || feePayment.Length == 0
                || !attachments.SequenceEqual(new byte[] { 0 }))
            {
                throw new JsonException(
                    $"{context}.signed_transaction_wire_hex contains a noncanonical TransactionPayload.");
            }
            var ttl = new CanonicalNoritoReader(timeToLive, $"{context} time_to_live_ms", nameof(wireHex));
            if (ttl.ReadByte("tag") != 1)
            {
                throw new JsonException($"{context} requires a positive signed transaction TTL.");
            }
            var ttlValue = ttl.ReadField("value");
            ttl.RequireEnd();
            if (ttlValue.Length != sizeof(ulong) || BinaryPrimitives.ReadUInt64LittleEndian(ttlValue) == 0)
            {
                throw new JsonException($"{context} requires a positive signed transaction TTL.");
            }
            return new PreparedTransactionWireV1(
                wire,
                payload,
                BinaryPrimitives.ReadUInt64LittleEndian(creationTime),
                BinaryPrimitives.ReadUInt64LittleEndian(ttlValue),
                networkDomain,
                authority,
                feePayment,
                executable.ToArray(),
                metadata,
                signature);
        }
        catch (ArgumentException error)
        {
            throw new JsonException(
                $"{context}.signed_transaction_wire_hex does not contain one canonical TransactionPayload.",
                error);
        }
    }

    private static byte[] ValidatePreparedTransactionPayload(
        PreparedTransactionWireV1 transaction,
        NetworkId expectedNetworkId,
        string? expectedAuthority,
        string encodingContextAccountId,
        FeePaymentIntent feePayment,
        ToriiPreparedOperationBindingV1 binding,
        string operation,
        string semanticHashHex,
        string context)
    {
        ArgumentNullException.ThrowIfNull(expectedNetworkId);
        var encoding = new TransactionEncodingContext(encodingContextAccountId);
        if (!transaction.NetworkDomain.AsSpan().SequenceEqual(
                encoding.EncodeNetworkDomain(expectedNetworkId)))
        {
            throw new JsonException($"{context} transaction targets another network.");
        }
        if (!transaction.FeePayment.AsSpan().SequenceEqual(
                encoding.EncodeFeePaymentIntent(feePayment)))
        {
            throw new JsonException($"{context} fee_payment differs from the signed transaction.");
        }

        if (transaction.TimeToLiveMilliseconds > ulong.MaxValue - transaction.CreationTimeMilliseconds
            || transaction.CreationTimeMilliseconds + transaction.TimeToLiveMilliseconds
                > binding.ExecutionExpiresAtUnixMilliseconds)
        {
            throw new JsonException($"{context} signed transaction outlives its operation deadline.");
        }
        var expectedMetadata = encoding.EncodeMetadata(ExpectedPreparedTransactionMetadata(binding, operation, semanticHashHex));
        if (!transaction.Metadata.AsSpan().SequenceEqual(expectedMetadata))
        {
            throw new JsonException($"{context} metadata differs from its exact operation binding.");
        }

        byte[] signerPublicKey;
        if (expectedAuthority is not null)
        {
            var exactAuthority = ToriiAccountOnboardingReceiptVerifier.RequireCanonicalAccountId(
                expectedAuthority,
                nameof(expectedAuthority));
            if (!transaction.Authority.AsSpan().SequenceEqual(
                    encoding.EncodeAccountId(exactAuthority)))
            {
                throw new JsonException($"{context} transaction authority differs from the signed receipt.");
            }
            signerPublicKey = PreparedEd25519PublicKeyFromAccountId(
                exactAuthority,
                context);
        }
        else
        {
            signerPublicKey = DecodePreparedEd25519Authority(
                transaction.Authority,
                context);
        }

        var signature = DecodePreparedEd25519Signature(transaction.Signature, context);
        if (!Ed25519Signer.Verify(
                IrohaHash.Hash(transaction.Payload),
                signature,
                signerPublicKey))
        {
            throw new JsonException($"{context} transaction signature is invalid.");
        }
        return signerPublicKey;
    }

    private static void ValidatePreparedSemanticBinding(
        ToriiPreparedOperationBindingV1 binding,
        string semanticHashHex,
        ulong semanticExpiry)
    {
        if (!string.Equals(binding.SemanticHashHex, semanticHashHex, StringComparison.Ordinal)
            || binding.ExecutionExpiresAtUnixMilliseconds == 0
            || binding.ExecutionExpiresAtUnixMilliseconds > semanticExpiry)
        {
            throw new ArgumentException("Prepared operation binding differs from its exact semantic intent or deadline.", nameof(binding));
        }
    }

    private static Dictionary<string, JsonNode?> ExpectedPreparedTransactionMetadata(
        ToriiPreparedOperationBindingV1 binding,
        string operation,
        string semanticHashHex)
    {
        var metadata = new Dictionary<string, JsonNode?>(StringComparer.Ordinal)
        {
            ["prepared_operation_binding"] = new JsonObject
            {
                ["schema"] = binding.Schema,
                ["semantic_hash_hex"] = binding.SemanticHashHex,
                ["kind"] = binding.Kind,
                ["request_id"] = binding.RequestId,
                ["execution_expires_at_unix_ms"] = binding.ExecutionExpiresAtUnixMilliseconds,
            },
            ["prepared_operation"] = JsonValue.Create(operation),
            ["prepared_semantic_hash"] = JsonValue.Create(semanticHashHex),
        };
        if (string.Equals(operation, ToriiAccountFaucetPreparedTransactionV1.OperationV1, StringComparison.Ordinal))
        {
            metadata["taira_faucet_claim_marker_version"] = JsonValue.Create(1UL);
        }
        return metadata;
    }

    private static IReadOnlyList<byte[]> DecodePreparedInstructionSequence(
        ReadOnlySpan<byte> encoded,
        string context)
    {
        try
        {
            var executable = new CanonicalNoritoReader(
                encoded,
                $"{context} executable",
                nameof(encoded));
            if (executable.ReadUInt32LittleEndian("kind") != 0)
            {
                throw new JsonException($"{context} must contain direct instructions.");
            }
            var sequenceBytes = executable.ReadField("instructions");
            executable.RequireEnd();

            var sequence = new CanonicalNoritoReader(
                sequenceBytes,
                $"{context} instruction sequence",
                nameof(encoded));
            var count = sequence.ReadSequenceLength("count");
            if (count > 1_024)
            {
                throw new JsonException($"{context} instruction sequence exceeds its V1 bound.");
            }
            var instructions = new List<byte[]>(checked((int)count));
            for (ulong index = 0; index < count; index++)
            {
                var instruction = sequence.ReadField($"instructions[{index}]").ToArray();
                if (instruction.Length == 0)
                {
                    throw new JsonException($"{context} instruction {index} must not be empty.");
                }
                instructions.Add(instruction);
            }
            sequence.RequireEnd();
            return instructions;
        }
        catch (ArgumentException error)
        {
            throw new JsonException($"{context} instruction sequence is noncanonical.", error);
        }
    }

    private static IReadOnlyList<byte[]> EncodeOnboardingInstructionFrames(
        JsonElement frames,
        string accountId,
        string context)
    {
        if (frames.ValueKind != JsonValueKind.Array || frames.GetArrayLength() > 1_024)
        {
            throw new JsonException($"{context} must be a bounded instruction-frame array.");
        }
        var encoding = new TransactionEncodingContext(accountId);
        var encoded = new List<byte[]>(frames.GetArrayLength());
        foreach (var (frame, index) in frames.EnumerateArray().Select(
                     static (value, index) => (value, index)))
        {
            if (frame.ValueKind != JsonValueKind.Object)
            {
                throw new JsonException($"{context}[{index}] must be an object.");
            }
            var properties = frame.EnumerateObject().ToArray();
            if (properties.Length != 2
                || properties.Select(static property => property.Name)
                    .OrderBy(static value => value, StringComparer.Ordinal)
                    .SequenceEqual(["framed_payload", "wire_id"], StringComparer.Ordinal) is false)
            {
                throw new JsonException(
                    $"{context}[{index}] must contain only wire_id and framed_payload.");
            }
            var wireIdElement = frame.GetProperty("wire_id");
            var payloadElement = frame.GetProperty("framed_payload");
            if (wireIdElement.ValueKind != JsonValueKind.String
                || wireIdElement.GetString() is not { Length: > 0 } wireId
                || wireId.Length > 256
                || !string.Equals(wireId.Trim(), wireId, StringComparison.Ordinal)
                || wireId.Any(char.IsControl)
                || payloadElement.ValueKind != JsonValueKind.Array
                || payloadElement.GetArrayLength() == 0
                || payloadElement.GetArrayLength() > MaximumPreparedTransactionWireBytesV1)
            {
                throw new JsonException($"{context}[{index}] is noncanonical.");
            }
            var payload = new byte[payloadElement.GetArrayLength()];
            var payloadIndex = 0;
            foreach (var item in payloadElement.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Number
                    || !item.TryGetInt32(out var value)
                    || value is < byte.MinValue or > byte.MaxValue)
                {
                    throw new JsonException(
                        $"{context}[{index}].framed_payload[{payloadIndex}] must be one byte.");
                }
                payload[payloadIndex++] = checked((byte)value);
            }
            encoded.Add(EncodePreparedInstructionPair(encoding, wireId, payload));
        }
        return encoded;
    }

    private static byte[] EncodePreparedInstructionPair(
        TransactionEncodingContext encoding,
        string wireId,
        ReadOnlySpan<byte> framedPayload)
    {
        var bytes = new CanonicalNoritoWriter();
        bytes.WriteSequenceLength(checked((ulong)framedPayload.Length));
        bytes.WriteBytes(framedPayload);

        var instruction = new CanonicalNoritoWriter();
        instruction.WriteField(encoding.EncodeString(wireId));
        instruction.WriteField(bytes.ToArray());
        return instruction.ToArray();
    }

    private static bool InstructionsAreOrderedSubset(
        IReadOnlyList<byte[]> actual,
        IReadOnlyList<byte[]> planned)
    {
        var next = 0;
        foreach (var instruction in planned)
        {
            if (next < actual.Count
                && actual[next].AsSpan().SequenceEqual(instruction))
            {
                next++;
            }
        }
        return next == actual.Count;
    }

    private static void ValidatePreparedFaucetInstructions(
        PreparedTransactionWireV1 transaction,
        ToriiAccountFaucetPreparedTransactionV1 prepared,
        ReadOnlySpan<byte> signerPublicKey,
        string context)
    {
        var instructions = DecodePreparedInstructionSequence(transaction.Executable, context);
        if (instructions.Count is < 1 or > 2)
        {
            throw new JsonException(
                $"{context} must contain only optional account registration followed by transfer.");
        }
        var authority = AccountAddress.FromPublicKey(signerPublicKey).ToString();
        var encoding = new TransactionEncodingContext(authority);
        var expectedTransfer = encoding.EncodeInstruction(new TransferAssetInstruction(
            prepared.AssetDefinitionId,
            prepared.Amount,
            prepared.AccountId));
        if (!instructions[^1].AsSpan().SequenceEqual(expectedTransfer))
        {
            throw new JsonException($"{context} transfer differs from its exact claim.");
        }
        if (instructions.Count == 2)
        {
            ValidatePreparedAccountRegistrationInstruction(
                instructions[0],
                prepared.AccountId,
                context);
        }
    }

    private static void ValidatePreparedAccountRegistrationInstruction(
        ReadOnlySpan<byte> encoded,
        string accountId,
        string context)
    {
        try
        {
            var encoding = new TransactionEncodingContext(accountId);
            var instruction = new CanonicalNoritoReader(
                encoded,
                $"{context} registration instruction",
                nameof(encoded));
            var wireId = DecodePreparedString(instruction.ReadField("wire_id"), context);
            var framed = DecodePreparedByteVector(
                instruction.ReadField("framed_payload"),
                context);
            instruction.RequireEnd();
            if (!string.Equals(wireId, "iroha.register", StringComparison.Ordinal)
                || !encoded.SequenceEqual(EncodePreparedInstructionPair(encoding, wireId, framed)))
            {
                throw new JsonException($"{context} account registration is noncanonical.");
            }

            const string registerBoxType = "iroha_data_model::isi::register::RegisterBox";
            var (payload, flags) = NoritoCodec.Decode(registerBoxType, framed);
            if (flags != NoritoCodec.CanonicalLayoutFlags
                || !framed.AsSpan().SequenceEqual(NoritoCodec.Encode(
                    registerBoxType,
                    payload,
                    NoritoCodec.CanonicalLayoutFlags)))
            {
                throw new JsonException($"{context} account registration frame is noncanonical.");
            }
            var registerBox = new CanonicalNoritoReader(
                payload,
                $"{context} registration box",
                nameof(encoded));
            if (registerBox.ReadUInt32LittleEndian("kind") != 2)
            {
                throw new JsonException($"{context} registration must target one account.");
            }
            var registerBytes = registerBox.ReadField("registration");
            registerBox.RequireEnd();

            var registration = new CanonicalNoritoReader(
                registerBytes,
                $"{context} account registration",
                nameof(encoded));
            var accountBytes = registration.ReadField("account");
            registration.RequireEnd();

            var account = new CanonicalNoritoReader(
                accountBytes,
                $"{context} new account",
                nameof(encoded));
            var id = account.ReadField("id");
            var metadata = account.ReadField("metadata");
            var label = account.ReadField("label");
            var uaid = account.ReadField("uaid");
            var opaqueIds = account.ReadField("opaque_ids");
            account.RequireEnd();
            if (!id.SequenceEqual(encoding.EncodeAccountId(accountId))
                || !metadata.SequenceEqual(encoding.EncodeEmptyMetadata())
                || !label.SequenceEqual(new byte[] { 0 })
                || !uaid.SequenceEqual(new byte[] { 0 })
                || !opaqueIds.SequenceEqual(new byte[sizeof(ulong)]))
            {
                throw new JsonException(
                    $"{context} registration does not create only the exact empty target account.");
            }
        }
        catch (ArgumentException error)
        {
            throw new JsonException($"{context} account registration is noncanonical.", error);
        }
    }

    private static string DecodePreparedString(ReadOnlySpan<byte> encoded, string context)
    {
        var value = new CanonicalNoritoReader(
            encoded,
            $"{context} string",
            nameof(encoded));
        var length = value.ReadCompactLength("length");
        if (length > 256)
        {
            throw new JsonException($"{context} string exceeds its V1 bound.");
        }
        var decoded = StrictUtf8.GetString(value.ReadExact(checked((int)length), "value"));
        value.RequireEnd();
        return decoded;
    }

    private static byte[] DecodePreparedByteVector(ReadOnlySpan<byte> encoded, string context)
    {
        var value = new CanonicalNoritoReader(
            encoded,
            $"{context} byte vector",
            nameof(encoded));
        var length = value.ReadSequenceLength("length");
        if (length == 0 || length > MaximumPreparedTransactionWireBytesV1)
        {
            throw new JsonException($"{context} byte vector exceeds its V1 bound.");
        }
        var decoded = value.ReadExact(checked((int)length), "value").ToArray();
        value.RequireEnd();
        return decoded;
    }

    private static byte[] PreparedEd25519PublicKeyFromAccountId(
        string accountId,
        string context)
    {
        var account = AccountAddress.Parse(accountId);
        if (account.AddressClass != AddressClass.SingleKey
            || !string.Equals(account.Algorithm, "ed25519", StringComparison.Ordinal)
            || account.PublicKey.Length != Ed25519Signer.PublicKeyLength)
        {
            throw new JsonException($"{context} authority is not one Ed25519 signer.");
        }
        return account.PublicKey;
    }

    private static byte[] DecodePreparedEd25519Authority(byte[] encodedAuthority, string context)
    {
        try
        {
            var authority = new CanonicalNoritoReader(
                encodedAuthority,
                $"{context} authority",
                nameof(encodedAuthority));
            if (authority.ReadUInt32LittleEndian("kind") != 0)
            {
                throw new JsonException($"{context} transaction authority must be one signer.");
            }
            var encodedController = authority.ReadField("controller").ToArray();
            authority.RequireEnd();
            var compactController = DecodePreparedConstVec(
                encodedController,
                33,
                $"{context} authority controller");
            if (compactController.Length != 33 || compactController[0] != 0)
            {
                throw new JsonException($"{context} transaction authority must use Ed25519.");
            }
            return compactController[1..];
        }
        catch (ArgumentException error)
        {
            throw new JsonException($"{context} transaction authority is noncanonical.", error);
        }
    }

    private static byte[] DecodePreparedEd25519Signature(byte[] encodedSignature, string context)
    {
        try
        {
            var wrapper = new CanonicalNoritoReader(
                encodedSignature,
                $"{context} signature",
                nameof(encodedSignature));
            var encodedBytes = wrapper.ReadField("signature").ToArray();
            wrapper.RequireEnd();
            var signature = DecodePreparedConstVec(
                encodedBytes,
                Ed25519Signer.SignatureLength,
                $"{context} signature");
            if (signature.Length != Ed25519Signer.SignatureLength
                || signature.All(static value => value == 0))
            {
                throw new JsonException($"{context} transaction signature is noncanonical.");
            }
            return signature;
        }
        catch (ArgumentException error)
        {
            throw new JsonException($"{context} transaction signature is noncanonical.", error);
        }
    }

    private static byte[] DecodePreparedConstVec(
        byte[] encoded,
        int maximumLength,
        string context)
    {
        var reader = new CanonicalNoritoReader(encoded, context, nameof(encoded));
        var count = reader.ReadSequenceLength("count");
        if (count > checked((ulong)maximumLength))
        {
            throw new JsonException($"{context} exceeds its exact length bound.");
        }
        var result = new byte[checked((int)count)];
        for (var index = 0; index < result.Length; index++)
        {
            var item = reader.ReadField($"bytes[{index}]");
            if (item.Length != 1)
            {
                throw new JsonException($"{context} byte fields must each have length one.");
            }
            result[index] = item[0];
        }
        reader.RequireEnd();
        return result;
    }

    private static string RequireExactLowerHex(string value, int byteLength, string context)
    {
        if (!IsExactLowerHex(value, byteLength))
        {
            throw new JsonException($"{context} must contain exactly {byteLength} bytes of lowercase hexadecimal.");
        }
        return value;
    }

    private static bool IsExactLowerHex(string? value, int byteLength) =>
        value is not null
        && value.Length == byteLength * 2
        && value.All(static character =>
            character is (>= '0' and <= '9') or (>= 'a' and <= 'f'));

    private static void ValidateOnboardingDispositionTransition(
        JsonElement resource,
        ToriiAccountOnboardingDisposition disposition,
        string context)
    {
        if (resource.ValueKind != JsonValueKind.Object
            || !resource.TryGetProperty("disposition", out var planned)
            || planned.ValueKind != JsonValueKind.Object
            || !planned.TryGetProperty("kind", out var plannedKindElement)
            || plannedKindElement.ValueKind != JsonValueKind.String
            || !planned.TryGetProperty("value", out var plannedValueElement)
            || plannedValueElement.ValueKind != JsonValueKind.Null
            || disposition is null)
        {
            throw new JsonException($"{context}.disposition is not bound to the semantic receipt.");
        }
        if (disposition.Value.ValueKind != JsonValueKind.Null)
        {
            throw new JsonException($"{context}.disposition.value must be the exact null unit value.");
        }
        var plannedKind = plannedKindElement.GetString();
        var actualKind = disposition.Kind;
        var allowed = (plannedKind, actualKind) switch
        {
            ("create", "create" or "repair" or "no_op") => true,
            ("repair", "repair" or "no_op") => true,
            ("no_op", "no_op") => true,
            _ => false,
        };
        if (!allowed)
        {
            throw new JsonException($"{context}.disposition is not an idempotent progression of the semantic receipt.");
        }
    }

    private static void ValidateAccountFaucetPuzzle(ToriiAccountFaucetPuzzle response, string context)
    {
        ToriiAccountFaucetJson.ValidateAccountFaucetPuzzle(response, context);
    }

    private static void ValidateVpnProfile(ToriiVpnProfile response, string context)
    {
        ToriiVpnJson.ValidateVpnProfile(response, context);
    }

    private static void ValidateVpnQuote(ToriiVpnQuote response, string context)
    {
        ToriiVpnJson.ValidateVpnQuote(response, context);
    }

    private static void ValidateVpnSession(ToriiVpnSession response, string context)
    {
        ToriiVpnJson.ValidateVpnSession(response, context);
    }

    private static void ValidateVpnReceiptListResponse(ToriiVpnReceiptListResponse response, string context)
    {
        ToriiVpnJson.ValidateVpnReceiptListResponse(response, context);
    }

    private static void ValidateVpnReceipt(ToriiVpnReceipt response, string context)
    {
        ToriiVpnJson.ValidateVpnReceipt(response, context);
    }

    private static void ValidateContractCodeRecord(ToriiContractCodeRecord response, string context)
    {
        ToriiContractMetadataJson.ValidateContractCodeRecord(response, context);
    }

    private static void ValidateGovernedContractResponse(
        ToriiGovernedContractResponse response,
        string context)
    {
        ToriiGovernedContractJson.ValidateResponse(response, context);
    }

    private static void ValidateContractCodeView(ToriiContractCodeView response, string context)
    {
        ToriiContractMetadataJson.ValidateContractCodeView(response, context);
    }

    private static void ValidateContractCodeViewAccessHints(
        ToriiContractViewAccessHints response,
        string context)
    {
        ValidateContractCodeViewTokenList(response.ReadKeys, $"{context}.read_keys");
        ValidateContractCodeViewTokenList(response.WriteKeys, $"{context}.write_keys");
    }

    private static void ValidateContractCodeViewEntrypoints(
        IReadOnlyList<ToriiContractViewEntrypoint>? entrypoints,
        string context)
    {
        if (entrypoints is null)
        {
            throw new JsonException($"{context} is required.");
        }

        for (var index = 0; index < entrypoints.Count; index++)
        {
            var entrypoint = entrypoints[index];
            if (entrypoint is null)
            {
                throw new JsonException($"{context}[{index}] must not be null.");
            }

            ValidateContractCodeViewEntrypoint(entrypoint, $"{context}[{index}]");
        }
    }

    private static void ValidateContractCodeViewEntrypoint(
        ToriiContractViewEntrypoint response,
        string context)
    {
        ToriiContractMetadataJson.ValidateEntrypoint(response, context);
    }

    private static void ValidateContractCodeViewEntrypointParams(
        IReadOnlyList<ToriiContractViewEntrypointParam>? parameters,
        string context)
    {
        if (parameters is null)
        {
            throw new JsonException($"{context} is required.");
        }

        for (var index = 0; index < parameters.Count; index++)
        {
            var parameter = parameters[index];
            if (parameter is null)
            {
                throw new JsonException($"{context}[{index}] must not be null.");
            }

            ValidateExactTokenText(parameter.Name, $"{context}[{index}].name");
            ValidateExactNonEmptyText(
                parameter.TypeName,
                $"{context}[{index}].type_name",
                message => new JsonException(message));
        }
    }

    private static void ValidateContractCodeViewAnalysis(
        ToriiContractViewAnalysis response,
        string context)
    {
        if (response.Memory is null)
        {
            throw new JsonException($"{context}.memory is required.");
        }

        if (response.Syscalls is null)
        {
            throw new JsonException($"{context}.syscalls is required.");
        }

        for (var index = 0; index < response.Syscalls.Count; index++)
        {
            var syscall = response.Syscalls[index];
            if (syscall is null)
            {
                throw new JsonException($"{context}.syscalls[{index}] must not be null.");
            }

            ValidateOptionalExactTokenText(syscall.Name, $"{context}.syscalls[{index}].name");
        }
    }

    private static void ValidateContractCodeViewTokenList(IReadOnlyList<string>? values, string context)
    {
        if (values is null)
        {
            throw new JsonException($"{context} is required.");
        }

        for (var index = 0; index < values.Count; index++)
        {
            ValidateExactTokenText(values[index], $"{context}[{index}]");
        }
    }

    private static void ValidateContractCodeViewWarnings(IReadOnlyList<string>? values, string context)
    {
        if (values is null)
        {
            throw new JsonException($"{context} is required.");
        }

        for (var index = 0; index < values.Count; index++)
        {
            ValidateExactNonEmptyText(values[index], $"{context}[{index}]", message => new JsonException(message));
        }
    }

    private static void ValidateRenderedSourceText(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new JsonException($"{field} must be non-empty rendered source text.");
        }

        if (value.IndexOf('\0') >= 0)
        {
            throw new JsonException($"{field} must not contain NUL characters.");
        }
    }

    private static void ValidateContractStateResponse(ToriiContractStateResponse response, string context)
    {
        ToriiContractStateJson.ValidateContractStateResponse(response, context);
    }

    private void ValidateContractCallResponse(
        ToriiContractCallResponse response,
        ToriiContractCallRequest request,
        string context)
    {
        ToriiContractCallJson.ValidateContractCallResponse(response, context);
        var receipt = response.OperationReceipt;
        var expectedReceiptStatus = response.Submitted ? "submitted" : "pending_signature";
        if (!string.Equals(receipt.OperationKind, "contract_call", StringComparison.Ordinal)
            || !string.Equals(receipt.Status, expectedReceiptStatus, StringComparison.Ordinal)
            || !string.Equals(receipt.Transport, "torii", StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context}.operation_receipt has an invalid operation kind, status, or transport.");
        }
        var responseFeePayment = receipt.FeePayment
            ?? throw new JsonException($"{context}.operation_receipt.fee_payment is required.");
        if (!request.FeePayment.HasSamePayerAndGasBound(responseFeePayment))
        {
            throw new JsonException(
                $"{context}.operation_receipt.fee_payment changed the requested payer, sponsor revision, or gas bound.");
        }
        if (receipt.GasLimit != request.FeePayment.GasLimit)
        {
            throw new JsonException(
                $"{context}.operation_receipt.gas_limit differs from the exact request.");
        }
        var canonicalPayload = request.Payload is null
            ? Array.Empty<byte>()
            : StrictUtf8.GetBytes(TransactionEncodingContext.CanonicalJson(request.Payload));
        var expectedPayloadDigestHex = Convert
            .ToHexString(Blake3.Hash(canonicalPayload))
            .ToLowerInvariant();
        if (!string.Equals(
                receipt.PayloadDigestHex,
                expectedPayloadDigestHex,
                StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context}.operation_receipt.payload_digest_hex differs from the exact request payload.");
        }
        if (request.CreationTimeMilliseconds.HasValue
            && response.CreationTimeMilliseconds != request.CreationTimeMilliseconds)
        {
            throw new JsonException(
                $"{context}.creation_time_ms is not bound to the exact request.");
        }
        if (response.TransactionTimeToLiveMilliseconds
                != request.TransactionTimeToLiveMilliseconds)
        {
            throw new JsonException(
                $"{context}.transaction_ttl_ms is not bound to the exact request.");
        }
        if (response.ContractAddress is null
            || !string.Equals(response.Entrypoint, request.Entrypoint, StringComparison.Ordinal)
            || !string.Equals(receipt.ContractAddress, response.ContractAddress, StringComparison.Ordinal)
            || !string.Equals(receipt.CodeHashHex, response.CodeHashHex, StringComparison.Ordinal)
            || !string.Equals(receipt.AbiHashHex, response.AbiHashHex, StringComparison.Ordinal)
            || !string.Equals(receipt.Entrypoint, response.Entrypoint, StringComparison.Ordinal)
            || !string.Equals(receipt.Dataspace, response.Dataspace, StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context} response and receipt disagree on the exact resolved contract binding.");
        }
        if (!string.Equals(
                receipt.TransactionHashHex,
                response.TransactionHashHex,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.EntrypointHashHex,
                response.EntrypointHashHex,
                StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context} response and receipt disagree on the exact transaction hashes.");
        }
        if (request.ContractAddress is not null)
        {
            if (!string.Equals(
                    response.ContractAddress,
                    request.ContractAddress,
                    StringComparison.Ordinal)
                || receipt.ContractAlias is not null)
            {
                throw new JsonException(
                    $"{context} is not bound to the exact requested contract address.");
            }
        }
        else if (!string.Equals(
            receipt.ContractAlias,
            request.ContractAlias,
            StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context} is not bound to the exact requested contract alias.");
        }

        if (response.Submitted != (request.TransactionPayloadBase64 is not null))
        {
            throw new JsonException($"{context} submission status differs from the requested detached envelope.");
        }
        var draftIntent = request.DraftIntent
            ?? throw new JsonException(
                $"{context} requires an exact caller-trusted DraftIntent before its unsigned draft can be trusted.");
        var expectedCodeHashHex = Convert
            .ToHexString(draftIntent.Invocation.ExpectedCodeHash)
            .ToLowerInvariant();
        if (!string.Equals(
                response.ContractAddress,
                draftIntent.Invocation.ContractAddress,
                StringComparison.Ordinal)
            || !string.Equals(
                response.CodeHashHex,
                expectedCodeHashHex,
                StringComparison.Ordinal)
            || !string.Equals(
                response.Entrypoint,
                draftIntent.Invocation.Entrypoint,
                StringComparison.Ordinal))
        {
            throw new JsonException(
                $"{context} resolved contract binding differs from the exact caller-trusted DraftIntent.");
        }

        var payload = Convert.FromBase64String(
            request.TransactionPayloadBase64 ?? response.TransactionPayloadBase64!);
        ValidateContractTransactionPayload(payload, request, response.CreationTimeMilliseconds, responseFeePayment, context);
        if (response.Submitted)
        {
            var entrypoint = new CanonicalNoritoWriter();
            entrypoint.WriteUInt32LittleEndian(0);
            entrypoint.WriteField(payload);
            var expectedHash = Convert.ToHexString(IrohaHash.Hash(entrypoint.ToArray())).ToLowerInvariant();
            if (!string.Equals(response.TransactionHashHex, expectedHash, StringComparison.Ordinal)
                || !string.Equals(response.EntrypointHashHex, expectedHash, StringComparison.Ordinal)
                || !request.FeePayment.Equals(responseFeePayment))
            {
                throw new JsonException($"{context} submitted receipt differs from the exact signed payload or quoted fee.");
            }
        }
    }

    private void ValidateContractTransactionPayload(
        byte[] payload,
        ToriiContractCallRequest request,
        ulong expectedCreationTimeMilliseconds,
        FeePaymentIntent expectedFeePayment,
        string context)
    {
        var draftIntent = request.DraftIntent
            ?? throw new JsonException($"{context} requires an exact caller-trusted DraftIntent.");
        var expectedNetworkId = Options.NetworkId
            ?? throw new JsonException($"{context} requires ToriiClientOptions.NetworkId.");
        try
        {
            var reader = new CanonicalNoritoReader(
                payload,
                $"{context} transaction payload",
                nameof(request.TransactionPayloadBase64));
            var networkDomain = reader.ReadField("domain");
            var authority = reader.ReadField("authority");
            var creationTime = reader.ReadField("creation_time_ms");
            var executable = reader.ReadField("executable");
            var timeToLive = reader.ReadField("time_to_live_ms");
            var nonce = reader.ReadField("nonce");
            var feePayment = reader.ReadField("fee_payment");
            var metadata = reader.ReadField("metadata");
            var attachments = reader.ReadField("attachments");
            reader.RequireEnd();

            var encoding = new TransactionEncodingContext(request.Authority);
            ValidateTransactionEnvelopeFields(
                networkDomain,
                timeToLive,
                nonce,
                attachments,
                expectedNetworkId,
                request.TransactionTimeToLiveMilliseconds
                    ?? TransactionBuilder.DefaultTimeToLiveMilliseconds,
                encoding,
                context);
            if (!authority.SequenceEqual(encoding.EncodeAccountId(request.Authority)))
            {
                throw new JsonException(
                    $"{context} transaction authority differs from the exact request.");
            }
            if (creationTime.Length != sizeof(ulong)
                || BinaryPrimitives.ReadUInt64LittleEndian(creationTime)
                    != expectedCreationTimeMilliseconds)
            {
                throw new JsonException(
                    $"{context}.creation_time_ms differs from the exact transaction payload.");
            }
            if (!feePayment.SequenceEqual(
                encoding.EncodeFeePaymentIntent(expectedFeePayment)))
            {
                throw new JsonException(
                    $"{context}.fee_payment differs from the exact transaction payload.");
            }
            if (!metadata.SequenceEqual(encoding.EncodeMetadata(draftIntent.Metadata)))
            {
                throw new JsonException(
                    $"{context} transaction metadata differs from the exact caller-trusted DraftIntent.");
            }
            ValidateContractInvocation(
                executable,
                draftIntent.Invocation,
                context);
        }
        catch (Exception error) when (error is ArgumentException or FormatException)
        {
            throw new JsonException(
                $"{context}.transaction_payload_b64 must contain exactly one canonical nine-field TransactionPayload.",
                error);
        }
    }

    private static void ValidateFeeSponsorProgramResponse(
        ToriiFeeSponsorProgram response,
        FeeSponsorProgramId requestedProgramId)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(requestedProgramId);
        if (response.Id is null || response.Id != requestedProgramId)
        {
            throw new JsonException("Fee sponsor program lookup returned a different program id.");
        }
        try
        {
            _ = AccountAddress.Parse(response.PayoutAccount);
        }
        catch (FormatException error)
        {
            throw new JsonException(
                "Fee sponsor program lookup returned a non-canonical payout account.",
                error);
        }

        if (response.Lifecycle is null
            || response.Lifecycle.Value is not null
            || response.Lifecycle.State is not (
                "staged" or "paused" or "active" or "closing" or "closed"))
        {
            throw new JsonException(
                "Fee sponsor program lookup returned an invalid lifecycle.");
        }
        if (response.ActiveRevision == 0 || response.StagedRevision == 0)
        {
            throw new JsonException(
                "Fee sponsor program lookup returned a zero revision.");
        }
        if (response.ScheduledActivation is { } activation
            && (activation.Revision == 0 || activation.ActivateAtHeight == 0))
        {
            throw new JsonException(
                "Fee sponsor program lookup returned an invalid scheduled activation.");
        }
    }

    private static void ValidateFeeSponsorProgramJson(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            return;
        }
        foreach (var field in new[]
        {
            "active_revision",
            "staged_revision",
            "scheduled_activation",
        })
        {
            if (root.TryGetProperty(field, out var value)
                && value.ValueKind == JsonValueKind.Null)
            {
                throw new JsonException(
                    "Fee sponsor program lookup returned an explicit null optional field.");
            }
        }
    }

    internal static void ValidateFeeQuoteResponse(
        ToriiFeeQuoteResponse response,
        FeePaymentIntent requestedIntent,
        string requestedAuthority,
        string context)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(requestedIntent);
        ArgumentException.ThrowIfNullOrEmpty(requestedAuthority);
        if (response.Intent is null)
        {
            throw new JsonException($"{context}.intent must not be null.");
        }
        if (!requestedIntent.HasSamePayerAndGasBound(response.Intent))
        {
            throw new JsonException(
                $"{context}.intent changed the selected payer, sponsor revision, or gas bound.");
        }
        if (response.Observation is null || response.Observation.NextBlockHeight == 0)
        {
            throw new JsonException($"{context}.observation.next_block_height must be positive.");
        }
        if (response.Decision?.Value?.DebitSource is null
            || !string.Equals(response.Decision.Status, "accepted", StringComparison.Ordinal))
        {
            throw new JsonException($"{context}.decision must be accepted with a debit source.");
        }
        if (response.Components is null || response.Capacities is null)
        {
            throw new JsonException($"{context} component and capacity arrays must not be null.");
        }
        if (response.Components.Any(static component => component is null)
            || response.Capacities.Any(static capacity => capacity is null))
        {
            throw new JsonException($"{context} component and capacity arrays must not contain nulls.");
        }
        if (!response.Components.SequenceEqual(response.Intent.ChargeLimits))
        {
            throw new JsonException($"{context}.components must equal the returned intent charge limits.");
        }

        var decision = response.Decision.Value;
        switch (response.Intent)
        {
            case AuthorityFeePaymentIntent:
                if (!string.Equals(decision.DebitSource.Kind, "account", StringComparison.Ordinal)
                    || decision.DebitSource.Value.ValueKind != JsonValueKind.String
                    || !AccountIdsHaveSameIdentity(
                        decision.DebitSource.Value.GetString(),
                        requestedAuthority)
                    || decision.ProgramRevision is not null)
                {
                    throw new JsonException(
                        $"{context}.decision must debit the exact transaction authority with a null program revision.");
                }
                if (response.Capacities.Count != 0)
                {
                    throw new JsonException($"{context}.capacities must be empty for authority payment.");
                }
                break;
            case SponsorFeePaymentIntent sponsor:
                var decisionProgram = ParseFeeQuoteProgramId(
                    decision.DebitSource,
                    $"{context}.decision.value.debit_source");
                if (decisionProgram != sponsor.ProgramId
                    || decision.ProgramRevision != sponsor.ProgramRevision)
                {
                    throw new JsonException(
                        $"{context}.decision must debit the exact sponsor program revision.");
                }
                ValidateFeeQuoteSponsorCapacities(response, context);
                break;
            default:
                throw new JsonException($"{context}.intent has an unsupported payer.");
        }
    }

    private static FeeSponsorProgramId ParseFeeQuoteProgramId(
        ToriiFeeDebitSource source,
        string context)
    {
        if (!string.Equals(source.Kind, "sponsor_program", StringComparison.Ordinal))
        {
            throw new JsonException($"{context}.kind must be sponsor_program.");
        }
        var program = FeePaymentIntentJsonConverter.RequireExactObject(
            source.Value,
            $"{context}.value",
            ["sponsor", "name"]);
        if (program["sponsor"].ValueKind != JsonValueKind.String
            || program["name"].ValueKind != JsonValueKind.String)
        {
            throw new JsonException($"{context}.value must contain string sponsor and name fields.");
        }
        try
        {
            return new FeeSponsorProgramId(
                program["sponsor"].GetString()!,
                program["name"].GetString()!);
        }
        catch (ArgumentException exception)
        {
            throw new JsonException($"{context}.value is not an exact sponsor program id.", exception);
        }
    }

    private static void ValidateFeeQuoteSponsorCapacities(
        ToriiFeeQuoteResponse response,
        string context)
    {
        if ((response.Components.Count == 0) != (response.Capacities.Count == 0))
        {
            throw new JsonException(
                $"{context}.capacities must be empty exactly when sponsored components are empty.");
        }

        var requiredByAsset = new SortedDictionary<string, NumericV1.QuantityValue>(
            StringComparer.Ordinal);
        foreach (var component in response.Components)
        {
            var assetDefinitionId = RequireFeeQuoteAssetDefinitionId(
                component.AssetDefinitionId,
                $"{context}.components.asset_definition_id");
            var amount = RequireFeeQuoteQuantity(
                component.MaxAmount,
                $"{context}.components.max_amount");
            requiredByAsset[assetDefinitionId] = requiredByAsset.TryGetValue(
                assetDefinitionId,
                out var current)
                ? AddFeeQuoteQuantities(current, amount)
                : amount;
        }
        if (response.Capacities.Count != requiredByAsset.Count)
        {
            throw new JsonException(
                $"{context}.capacities must contain one entry per sponsored fee asset.");
        }

        var index = 0;
        foreach (var (assetDefinitionId, required) in requiredByAsset)
        {
            var capacity = response.Capacities[index];
            var capacityContext = $"{context}.capacities[{index}]";
            var observedAsset = RequireFeeQuoteAssetDefinitionId(
                capacity.AssetDefinitionId,
                $"{capacityContext}.asset_definition_id");
            if (!string.Equals(observedAsset, assetDefinitionId, StringComparison.Ordinal))
            {
                throw new JsonException(
                    $"{context}.capacities are duplicated, unrelated, or not in canonical asset order.");
            }
            var vaultBalance = RequireFeeQuoteQuantity(
                capacity.VaultBalance,
                $"{capacityContext}.vault_balance");
            var reserveFloor = RequireFeeQuoteQuantity(
                capacity.ReserveFloor,
                $"{capacityContext}.reserve_floor");
            if (CompareFeeQuoteQuantities(
                    vaultBalance,
                    AddFeeQuoteQuantities(reserveFloor, required)) < 0)
            {
                throw new JsonException(
                    $"{capacityContext}.vault_balance cannot cover the reserve and aggregate charge.");
            }
            foreach (var (field, text) in new[]
            {
                ("block_remaining", capacity.BlockRemaining),
                ("program_epoch_remaining", capacity.ProgramEpochRemaining),
                ("beneficiary_epoch_remaining", capacity.BeneficiaryEpochRemaining),
            })
            {
                if (CompareFeeQuoteQuantities(
                        RequireFeeQuoteQuantity(text, $"{capacityContext}.{field}"),
                        required) < 0)
                {
                    throw new JsonException(
                        $"{capacityContext}.{field} cannot cover the aggregate charge.");
                }
            }
            index++;
        }
    }

    private static string RequireFeeQuoteAssetDefinitionId(string? value, string context)
    {
        try
        {
            var canonical = TransactionEncodingContext.CanonicalizeAssetDefinitionId(value!, context);
            if (!string.Equals(canonical, value, StringComparison.Ordinal))
            {
                throw new ArgumentException("asset definition id is not canonical", context);
            }
            return canonical;
        }
        catch (ArgumentException exception)
        {
            throw new JsonException(
                $"{context} must be an exact canonical asset-definition address.",
                exception);
        }
    }

    private static NumericV1.QuantityValue RequireFeeQuoteQuantity(string? value, string context)
    {
        try
        {
            return NumericV1.QuantityValue.ParseCanonical(value!);
        }
        catch (ArgumentException exception)
        {
            throw new JsonException($"{context} must be a canonical Quantity.", exception);
        }
    }

    private static NumericV1.QuantityValue AddFeeQuoteQuantities(
        NumericV1.QuantityValue left,
        NumericV1.QuantityValue right)
    {
        var scale = Math.Max(left.Scale, right.Scale);
        var leftMantissa = left.Mantissa * BigInteger.Pow(10, scale - left.Scale);
        var rightMantissa = right.Mantissa * BigInteger.Pow(10, scale - right.Scale);
        try
        {
            return NumericV1.QuantityValue.FromMantissa(leftMantissa + rightMantissa, scale);
        }
        catch (ArgumentException exception)
        {
            throw new JsonException(
                "fee quote quantity aggregate exceeds the exact Quantity domain.",
                exception);
        }
    }

    private static int CompareFeeQuoteQuantities(
        NumericV1.QuantityValue left,
        NumericV1.QuantityValue right)
    {
        var scale = Math.Max(left.Scale, right.Scale);
        var leftMantissa = left.Mantissa * BigInteger.Pow(10, scale - left.Scale);
        var rightMantissa = right.Mantissa * BigInteger.Pow(10, scale - right.Scale);
        return leftMantissa.CompareTo(rightMantissa);
    }

    private static void ValidateContractViewResponse(ToriiContractViewResponse response, string context)
    {
        ToriiContractCallJson.ValidateContractViewResponse(response, context);
    }

    private static void ValidateContractViewErrorResponse(ToriiContractViewErrorResponse response, string context)
    {
        ToriiContractCallJson.ValidateContractViewErrorResponse(response, context);
    }

    private static void ValidateOptionalContractViewVmDiagnostic(
        ToriiContractViewVmDiagnostic? response,
        string context)
    {
        ToriiContractCallJson.ValidateOptionalContractViewVmDiagnostic(response, context);
    }

    private static void ValidateContractVerifiedSourceJob(ToriiContractVerifiedSourceJob response, string context)
    {
        ToriiContractMetadataJson.ValidateVerifiedSourceJob(response, context);
    }

    private static void ValidateOptionalContractVerifiedSourceReference(
        ToriiContractVerifiedSourceReference? response,
        string context)
    {
        if (response is null)
        {
            return;
        }

        ValidateExactNonEmptyText(response.Language, $"{context}.language", message => new JsonException(message));
        if (response.SourceName is not null)
        {
            ValidateExactNonEmptyText(
                response.SourceName,
                $"{context}.source_name",
                message => new JsonException(message));
        }
        ValidateExactNonEmptyText(response.SubmittedAt, $"{context}.submitted_at", message => new JsonException(message));
        ValidateOptionalExactSizedHex(response.ManifestIdHex, $"{context}.manifest_id_hex", 32);
        ValidateOptionalExactSizedHex(response.PayloadDigestHex, $"{context}.payload_digest_hex", 32);
    }

    private static void ValidateRuntimeAbiHash(ToriiRuntimeAbiHash response, string context)
    {
        ToriiRuntimeJson.ValidateRuntimeAbiHash(response, context);
    }

    private static void ValidateRuntimeAbiActive(ToriiRuntimeAbiActive response, string context)
    {
        ToriiRuntimeJson.ValidateRuntimeAbiActive(response, context);
    }

    private static void ValidateRuntimeMetrics(ToriiRuntimeMetrics response, string context)
    {
        ToriiRuntimeJson.ValidateRuntimeMetrics(response, context);
    }

    private static void ValidateUaidManifestRecord(ToriiUaidManifestRecord response, string context)
    {
        ToriiUaidJson.ValidateUaidManifestRecord(response, context);
    }

    private static void ValidateUaidManifestLifecycle(ToriiUaidManifestLifecycle response, string context)
    {
        ToriiUaidJson.ValidateUaidManifestLifecycle(response, context);
    }

    private static void ValidateUaidPortfolioResponse(ToriiUaidPortfolioResponse response, string context)
    {
        ToriiUaidJson.ValidateUaidPortfolioResponse(response, context);
    }

    private static void ValidateUaidPortfolioDataspace(ToriiUaidPortfolioDataspace response, string context)
    {
        ToriiUaidJson.ValidateUaidPortfolioDataspace(response, context);
    }

    private static void ValidateUaidPortfolioAccount(ToriiUaidPortfolioAccount response, string context)
    {
        ToriiUaidJson.ValidateUaidPortfolioAccount(response, context);
    }

    private static void ValidateUaidBindingsResponse(ToriiUaidBindingsResponse response, string context)
    {
        ToriiUaidJson.ValidateUaidBindingsResponse(response, context);
    }

    private static void ValidateAccountReadResponse(
        ToriiAccountReadResponse response,
        string expectedAccountId,
        string context)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (!AccountIdsHaveSameIdentity(response.AccountId, expectedAccountId))
        {
            throw new JsonException($"{context}.account_id differs from the requested account identity.");
        }
    }

    private static bool AccountIdsHaveSameIdentity(string? left, string? right)
    {
        if (left is null || right is null)
        {
            return false;
        }
        try
        {
            return AccountAddress.Parse(left)
                .ControllerBytes()
                .AsSpan()
                .SequenceEqual(AccountAddress.Parse(right).ControllerBytes());
        }
        catch (AccountAddressException)
        {
            return false;
        }
    }

    private static void ValidateAccountAliasLookupResponse(ToriiAccountAliasLookupResponse response, string context)
    {
        ToriiAccountAliasLookupJson.ValidateAccountAliasLookupResponse(response, context);
    }

    private static void ValidateAccountAliasResolution(ToriiAccountAliasResolution response, string context)
    {
        ToriiAliasResolutionJson.ValidateAccountAliasResolution(response, context);
    }

    private static void ValidateAccountAliasIndexResolution(ToriiAccountAliasIndexResolution response, string context)
    {
        ToriiAliasResolutionJson.ValidateAccountAliasIndexResolution(response, context);
    }

    private static void ValidateAssetAliasResolution(ToriiAssetAliasResolution response, string context)
    {
        ToriiAliasResolutionJson.ValidateAssetAliasResolution(response, context);
    }

    private static void ValidateAssetAliasBinding(ToriiAssetAliasBinding response, string context)
    {
        ToriiAliasResolutionJson.ValidateAssetAliasBinding(response, context);
    }

    private static void ValidateContractAliasResolution(ToriiContractAliasResolution response, string context)
    {
        ToriiAliasResolutionJson.ValidateContractAliasResolution(response, context);
    }

    private static void ValidateContractAliasBinding(ToriiContractAliasBinding response, string context)
    {
        ToriiAliasResolutionJson.ValidateContractAliasBinding(response, context);
    }

    private static void ValidateExplorerAccount(ToriiExplorerAccount response, string context)
    {
        ToriiExplorerJson.ValidateExplorerAccount(response, context);
    }

    private static void ValidateExplorerAccountQrSnapshot(ToriiExplorerAccountQrSnapshot response, string context)
    {
        ToriiExplorerSnapshotJson.ValidateExplorerAccountQrSnapshot(response, context);
    }

    private static void ValidateExplorerDomain(ToriiExplorerDomain response, string context)
    {
        ToriiExplorerJson.ValidateExplorerDomain(response, context);
    }

    private static void ValidateExplorerAssetDefinition(ToriiExplorerAssetDefinition response, string context)
    {
        ToriiExplorerJson.ValidateExplorerAssetDefinition(response, context);
    }

    private static void ValidateExplorerAssetDefinitionEconometrics(
        ToriiExplorerAssetDefinitionEconometrics response,
        string context)
    {
        ToriiExplorerJson.ValidateExplorerAssetDefinitionEconometrics(response, context);
    }

    private static void ValidateExplorerVelocityWindow(
        ToriiExplorerEconometricsVelocityWindow response,
        string context)
    {
        ToriiExplorerJson.ValidateExplorerVelocityWindow(response, context);
    }

    private static void ValidateExplorerIssuanceWindow(
        ToriiExplorerEconometricsIssuanceWindow response,
        string context)
    {
        ToriiExplorerJson.ValidateExplorerIssuanceWindow(response, context);
    }

    private static void ValidateExplorerIssuanceSeriesPoint(
        ToriiExplorerEconometricsIssuanceSeriesPoint response,
        string context)
    {
        ToriiExplorerJson.ValidateExplorerIssuanceSeriesPoint(response, context);
    }

    private static void ValidateExplorerAssetDefinitionSnapshot(
        ToriiExplorerAssetDefinitionSnapshot response,
        string context)
    {
        ToriiExplorerJson.ValidateExplorerAssetDefinitionSnapshot(response, context);
    }

    private static void ValidateExplorerTopHolder(ToriiExplorerEconometricsTopHolder response, string context)
    {
        ToriiExplorerJson.ValidateExplorerTopHolder(response, context);
    }

    private static void ValidateExplorerDistributionSnapshot(
        ToriiExplorerEconometricsDistributionSnapshot response,
        string context)
    {
        ToriiExplorerJson.ValidateExplorerDistributionSnapshot(response, context);
    }

    private static void ValidateExplorerLorenzPoint(ToriiExplorerEconometricsLorenzPoint response, string context)
    {
        ToriiExplorerJson.ValidateExplorerLorenzPoint(response, context);
    }

    private static void ValidateExplorerAsset(ToriiExplorerAsset response, string context)
    {
        ToriiExplorerJson.ValidateExplorerAsset(response, context);
    }

    private static void ValidateExplorerNft(ToriiExplorerNft response, string context)
    {
        ToriiExplorerJson.ValidateExplorerNft(response, context);
    }

    private static void ValidateExplorerRwa(ToriiExplorerRwa response, string context)
    {
        ToriiExplorerJson.ValidateExplorerRwa(response, context);
    }

    private static void ValidateExplorerRwaParent(ToriiExplorerRwaParent response, string context)
    {
        ToriiExplorerJson.ValidateExplorerRwaParent(response, context);
    }

    private static void ValidateExplorerHealthSnapshot(ToriiExplorerHealthSnapshot response, string context)
    {
        ToriiExplorerSnapshotJson.ValidateExplorerHealthSnapshot(response, context);
    }

    private static void ValidateExplorerMetricsSnapshot(ToriiExplorerMetricsSnapshot response, string context)
    {
        ToriiExplorerSnapshotJson.ValidateExplorerMetricsSnapshot(response, context);
    }

    private static void ValidateExplorerBlock(ToriiExplorerBlock response, string context)
    {
        ToriiExplorerJson.ValidateExplorerBlock(response, context);
    }

    private static void ValidateExplorerTransaction(ToriiExplorerTransaction response, string context)
    {
        ToriiExplorerJson.ValidateExplorerTransaction(response, context);
    }

    private static void ValidateExplorerTransactionDetail(
        ToriiExplorerTransactionDetail response,
        string context)
    {
        ToriiExplorerJson.ValidateExplorerTransactionDetail(response, context);
    }

    private static void ValidateExplorerTransactionRejection(
        ToriiExplorerTransactionRejection response,
        string context)
    {
        ToriiExplorerJson.ValidateExplorerTransactionRejection(response, context);
    }

    private static void ValidateExplorerInstruction(ToriiExplorerInstruction response, string context)
    {
        ToriiExplorerJson.ValidateExplorerInstruction(response, context);
    }

    private static void ValidateSoraFsCidLookupResponse(ToriiSoraFsCidLookupResponse response, string context)
    {
        ToriiSoraFsJson.ValidateCidLookupResponse(response, context);
    }

    private static void ValidateSoraFsFileEntry(ToriiSoraFsFileEntry file, string context)
    {
        ToriiSoraFsJson.ValidateFileEntry(file, context);
    }

    private static void ValidateSoraFsContentCid(string? value, string field)
    {
        ValidateExactNonEmptyText(value, field, message => new JsonException(message));
        var text = value ?? throw new JsonException($"{field} must not be null.");

        if (text.Any(char.IsWhiteSpace))
        {
            throw new JsonException($"{field} must not contain whitespace.");
        }

        if (text[0] != 'b' || text.Length == 1)
        {
            throw new JsonException($"{field} must be lowercase multibase base32 CID text.");
        }

        for (var index = 1; index < text.Length; index++)
        {
            var character = text[index];
            if (character is not (>= 'a' and <= 'z') and not (>= '2' and <= '7'))
            {
                throw new JsonException($"{field} must be lowercase multibase base32 CID text.");
            }
        }
    }

    private static string? ReadSoraFsContentCidHeader(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("sora-content-cid", out var values))
        {
            return null;
        }

        var contentCids = values.ToArray();
        if (contentCids.Length != 1)
        {
            throw new JsonException("SoraFS content response.sora-content-cid must appear exactly once.");
        }

        ValidateSoraFsContentCid(contentCids[0], "SoraFS content response.sora-content-cid");
        return contentCids[0];
    }

    private static void ValidateSoraFsPathText(string? value, string field)
    {
        ValidateExactNonEmptyText(value, field, message => new JsonException(message));
    }

    private static void ValidateOptionalExactNonEmptyText(string? value, string field)
    {
        if (value is null)
        {
            return;
        }

        ValidateExactNonEmptyText(value, field, message => new JsonException(message));
    }

    private static void ValidateExactTokenText(string? value, string field)
    {
        ValidateExactNonEmptyText(value, field, message => new JsonException(message));
        var text = value ?? throw new JsonException($"{field} must not be null.");
        if (text.Any(char.IsWhiteSpace))
        {
            throw new JsonException($"{field} must not contain whitespace.");
        }
    }

    private static void ValidateExactUniqueTokenList(
        IReadOnlyList<string>? values,
        string field,
        bool requireNonEmpty = false)
    {
        if (values is null)
        {
            throw new JsonException($"{field} must not be null.");
        }

        if (requireNonEmpty && values.Count == 0)
        {
            throw new JsonException($"{field} must not be empty.");
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < values.Count; index++)
        {
            var itemField = $"{field}[{index}]";
            var value = values[index];
            ValidateExactTokenText(value, itemField);
            if (!seen.Add(value))
            {
                throw new JsonException($"{itemField} must not contain duplicate capability labels.");
            }
        }
    }

    private static void ValidateExactTokenSequence(
        IReadOnlyList<string>? values,
        IReadOnlyList<string> expected,
        string field)
    {
        if (values is null)
        {
            throw new JsonException($"{field} must not be null.");
        }

        if (values.Count != expected.Count)
        {
            throw new JsonException($"{field} must match the expected projection metadata key list.");
        }

        for (var index = 0; index < values.Count; index++)
        {
            var itemField = $"{field}[{index}]";
            ValidateExactTokenText(values[index], itemField);
            if (!string.Equals(values[index], expected[index], StringComparison.Ordinal))
            {
                throw new JsonException($"{itemField} must match the expected projection metadata key.");
            }
        }
    }

    private static void ValidateExactTokenValue(string value, string expected, string field)
    {
        if (!string.Equals(value, expected, StringComparison.Ordinal))
        {
            throw new JsonException($"{field} must be {expected}.");
        }
    }

    private static void ValidateOptionalExactTokenText(string? value, string field)
    {
        if (value is null)
        {
            return;
        }

        ValidateExactTokenText(value, field);
    }

    private static void ValidateOptionalCanonicalQuantityText(string? value, string field)
    {
        if (value is null)
        {
            return;
        }

        ValidateCanonicalQuantityText(value, field);
    }

    private static void ValidateCanonicalQuantityText(string? value, string field)
    {
        ValidateExactNonEmptyText(value, field, message => new JsonException(message));
        _ = ToriiQuantityJson.RequireCanonicalQuantity(value, field);
    }

    private static void ValidateNonNegativeInt32(int value, string field)
    {
        if (value < 0)
        {
            throw new JsonException($"{field} must be non-negative.");
        }
    }

    private static void ValidateAbiVersionV1(int value, string field)
    {
        ValidateNonNegativeInt32(value, field);
        if (value != 1)
        {
            throw new JsonException($"{field} must be 1.");
        }
    }

    private static void ValidatePositiveInt32(int value, string field)
    {
        if (value <= 0)
        {
            throw new JsonException($"{field} must be positive.");
        }
    }

    private static void ValidateExactInt32(int value, int expected, string field)
    {
        if (value != expected)
        {
            throw new JsonException($"{field} must be {expected}.");
        }
    }

    private static void ValidateNonNegativeInt64(long value, string field)
    {
        if (value < 0)
        {
            throw new JsonException($"{field} must be non-negative.");
        }
    }

    private static void ValidateFiniteNonNegativeDouble(double value, string field)
    {
        if (!double.IsFinite(value) || value < 0)
        {
            throw new JsonException($"{field} must be a finite non-negative number.");
        }
    }

    private static void ValidateFiniteUnitIntervalDouble(double value, string field)
    {
        if (!double.IsFinite(value) || value < 0 || value > 1)
        {
            throw new JsonException($"{field} must be a finite number from 0 to 1.");
        }
    }

    private static void ValidateIdentifierResolveRequest(ToriiIdentifierResolveRequest request)
    {
        ValidateIdentifierPolicyId(
            request.PolicyId,
            "identifier resolve request.policy_id",
            message => new ArgumentException(message, nameof(request.PolicyId)));
        _ = NormalizeIdentifierCiphertext(request.EncryptedInput, nameof(request.EncryptedInput));
        ArgumentNullException.ThrowIfNull(request.OutputOpening);
        request.OutputOpening.Validate();
    }

    private static void ValidateIdentifierPoliciesResponse(ToriiIdentifierPoliciesResponse response)
    {
        if (response.Items is null)
        {
            throw new JsonException("identifier policies response.items is required.");
        }

        for (var index = 0; index < response.Items.Count; index++)
        {
            var item = response.Items[index];
            ValidateIdentifierPolicyId(
                item.PolicyId,
                $"identifier policies response.items[{index}].policy_id",
                static message => new JsonException(message));
            ValidateExactNonEmptyText(
                item.ResolverPublicKey,
                $"identifier policies response.items[{index}].resolver_public_key",
                static message => new JsonException(message));
        }
    }

    private static void ValidateIdentifierResolveResponse(ToriiIdentifierResolveResponse response)
    {
        ValidateIdentifierPolicyId(
            response.PolicyId,
            "identifier resolve response.policy_id",
            static message => new JsonException(message));

        if (!IsNestedIdentifierResolveResponse(response))
        {
            throw new JsonException("identifier resolve response must use the current payload/attestation envelope.");
        }

        if (!string.IsNullOrEmpty(response.Signature))
        {
            ValidateExactHex(response.Signature, "identifier resolve response.attestation.signature");
        }

        ValidateIdentifierReceiptSignaturePayload(
            response.SignaturePayload,
            "identifier resolve response");
    }

    private static bool IsNestedIdentifierResolveResponse(ToriiIdentifierResolveResponse response)
    {
        if (!string.IsNullOrEmpty(response.SignaturePayloadHex)
            || response.SignaturePayload is not JsonObject payloadObject)
        {
            return false;
        }

        return payloadObject.TryGetPropertyValue("payload", out var payload)
            && payload is JsonObject
            && payloadObject.TryGetPropertyValue("attestation", out var attestation)
            && attestation is JsonObject;
    }

    private static void ValidateIdentifierReceiptSignaturePayload(JsonNode? payload, string context)
    {
        if (payload is not JsonObject payloadObject)
        {
            return;
        }

        ValidateOpeningSignature(payloadObject, context);
        ValidateAttestationSignature(payloadObject, context);
        ValidateIdentifierReceiptAttestation(payloadObject, context);
        ValidateIdentifierReceiptPayloadPolicyId(payloadObject, context);
        ValidateIdentifierReceiptPayloadExactFields(payloadObject, context);

        if (payloadObject.TryGetPropertyValue("payload", out var nestedPayload)
            && nestedPayload is JsonObject nestedPayloadObject)
        {
            ValidateOpeningSignature(nestedPayloadObject, $"{context}.payload");
            ValidateIdentifierReceiptPayloadPolicyId(nestedPayloadObject, $"{context}.payload");
            ValidateIdentifierReceiptPayloadExactFields(nestedPayloadObject, $"{context}.payload");
        }

        if (payloadObject.TryGetPropertyValue("attestation", out var attestation)
            && attestation is JsonObject attestationObject)
        {
            ValidateAttestationSignature(attestationObject, $"{context}.attestation");
            ValidateIdentifierReceiptAttestation(attestationObject, $"{context}.attestation");
        }
    }

    private static void ValidateIdentifierReceiptPayloadExactFields(JsonObject payload, string context)
    {
        ValidateOptionalExactJsonStringProperty(payload, "account_id", $"{context}.account_id");
        ValidateOptionalExactJsonStringProperty(payload, "opaque_id", $"{context}.opaque_id");
        ValidateOptionalExactJsonStringProperty(payload, "receipt_hash", $"{context}.receipt_hash");
        ValidateOptionalExactJsonStringProperty(payload, "uaid", $"{context}.uaid");

        if (TryGetOptionalJsonObject(payload, "execution", $"{context}.execution", out var execution))
        {
            ValidateOptionalExactJsonStringProperty(execution, "program_id", $"{context}.execution.program_id");
            ValidateOptionalExactJsonStringProperty(execution, "program_digest", $"{context}.execution.program_digest");
            _ = ToriiIdentifierJson.RequireRamLfeBackend(
                RequireExactJsonStringProperty(execution, "backend", $"{context}.execution.backend"),
                $"{context}.execution.backend");
            _ = ToriiIdentifierJson.RequireRamLfeVerificationMode(
                RequireExactJsonStringProperty(execution, "verification_mode", $"{context}.execution.verification_mode"),
                $"{context}.execution.verification_mode");
            ValidateOptionalExactJsonStringProperty(
                execution,
                "input_ciphertext_hash",
                $"{context}.execution.input_ciphertext_hash");
            ValidateOptionalExactJsonStringProperty(
                execution,
                "output_ciphertext_hash",
                $"{context}.execution.output_ciphertext_hash");
            ValidateOptionalExactJsonStringProperty(
                execution,
                "parameter_digest",
                $"{context}.execution.parameter_digest");
            ValidateOptionalExactJsonStringProperty(
                execution,
                "evaluation_key_digest",
                $"{context}.execution.evaluation_key_digest");
            ValidateOptionalExactJsonStringProperty(execution, "output_hash", $"{context}.execution.output_hash");
            ValidateOptionalExactJsonStringProperty(
                execution,
                "associated_data_hash",
                $"{context}.execution.associated_data_hash");
            ValidateOptionalPositiveUnsignedInteger(execution, "executed_at_ms", $"{context}.execution.executed_at_ms");
            ValidateOptionalPositiveUnsignedInteger(execution, "expires_at_ms", $"{context}.execution.expires_at_ms");
        }

        if (TryGetOptionalJsonObject(payload, "opening", $"{context}.opening", out var opening)
            && TryGetOptionalJsonObject(opening, "payload", $"{context}.opening.payload", out var openingPayload))
        {
            ValidateOptionalExactJsonStringProperty(
                openingPayload,
                "program_id",
                $"{context}.opening.payload.program_id");
            ValidateOptionalExactJsonStringProperty(
                openingPayload,
                "input_ciphertext_hash",
                $"{context}.opening.payload.input_ciphertext_hash");
            ValidateOptionalExactJsonStringProperty(
                openingPayload,
                "output_ciphertext_hash",
                $"{context}.opening.payload.output_ciphertext_hash");
            ValidateOptionalExactJsonStringProperty(
                openingPayload,
                "parameter_digest",
                $"{context}.opening.payload.parameter_digest");
            ValidateOptionalExactJsonStringProperty(
                openingPayload,
                "evaluation_key_digest",
                $"{context}.opening.payload.evaluation_key_digest");
            ValidateOptionalExactJsonStringProperty(
                openingPayload,
                "opened_output_hash",
                $"{context}.opening.payload.opened_output_hash");
            ValidateOptionalPositiveUnsignedInteger(
                openingPayload,
                "opened_at_ms",
                $"{context}.opening.payload.opened_at_ms");
            ValidateOptionalPositiveUnsignedInteger(
                openingPayload,
                "expires_at_ms",
                $"{context}.opening.payload.expires_at_ms");
        }
    }

    private static bool TryGetOptionalJsonObject(
        JsonObject payload,
        string propertyName,
        string context,
        out JsonObject value)
    {
        if (!payload.TryGetPropertyValue(propertyName, out var node) || node is null)
        {
            value = new JsonObject();
            return false;
        }

        if (node is JsonObject jsonObject)
        {
            value = jsonObject;
            return true;
        }

        throw new JsonException($"{context} must be an object.");
    }

    private static void ValidateOpeningSignature(JsonObject payload, string context)
    {
        if (!payload.TryGetPropertyValue("opening", out var opening)
            || opening is not JsonObject openingObject
            || !openingObject.TryGetPropertyValue("signature", out var signature))
        {
            return;
        }

        ValidateExactHex(RequireJsonString(signature, $"{context}.opening.signature"), $"{context}.opening.signature");
    }

    private static void ValidateAttestationSignature(JsonObject payload, string context)
    {
        if (!payload.TryGetPropertyValue("signature", out var signature))
        {
            return;
        }

        ValidateExactHex(RequireJsonString(signature, $"{context}.signature"), $"{context}.signature");
    }

    private static void ValidateIdentifierReceiptAttestation(JsonObject attestation, string context)
    {
        var hasKind = attestation.TryGetPropertyValue("kind", out var kindNode);
        var hasProofBackend = attestation.TryGetPropertyValue("proof_backend", out _);
        var hasProofB64 = attestation.TryGetPropertyValue("proof_b64", out _);
        if (!hasKind)
        {
            if (hasProofBackend || hasProofB64)
            {
                throw new JsonException($"{context}.kind is required when proof fields are present.");
            }
            return;
        }

        var kind = RequireExactJsonString(kindNode, $"{context}.kind");
        switch (kind)
        {
            case "signed":
                if (hasProofBackend || hasProofB64)
                {
                    throw new JsonException($"{context} signed attestations must not include proof fields.");
                }
                break;
            case "proof":
                _ = RequireExactJsonStringProperty(attestation, "proof_backend", $"{context}.proof_backend");
                var proofB64 = RequireExactJsonStringProperty(attestation, "proof_b64", $"{context}.proof_b64");
                ValidateExactBase64(proofB64, $"{context}.proof_b64");
                break;
            default:
                throw new JsonException($"{context}.kind must be signed or proof.");
        }
    }

    private static void ValidateIdentifierReceiptPayloadPolicyId(JsonObject payload, string context)
    {
        if (!payload.TryGetPropertyValue("policy_id", out var policyId))
        {
            return;
        }

        ValidateIdentifierPolicyId(
            RequireJsonStringForJson(policyId, $"{context}.policy_id"),
            $"{context}.policy_id",
            static message => new JsonException(message));
    }

    private static void ValidateIdentifierPolicyId(
        string? value,
        string field,
        Func<string, Exception> createException)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw createException($"{field} must be a non-empty policy id.");
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw createException($"{field} must not contain surrounding whitespace.");
        }

        if (ContainsControlCharacter(value))
        {
            throw createException($"{field} must not contain control characters.");
        }

        var parts = value.Split('#');
        if (parts.Length != 2)
        {
            throw createException($"{field} must use `kind#rule`.");
        }

        ValidateIdentifierPolicyIdComponent(parts[0], $"{field}.kind", createException);
        ValidateIdentifierPolicyIdComponent(parts[1], $"{field}.rule", createException);
    }

    private static void ValidateIdentifierPolicyIdComponent(
        string value,
        string field,
        Func<string, Exception> createException)
    {
        if (value.Length == 0)
        {
            throw createException($"{field} must not be empty.");
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw createException($"{field} must not contain surrounding whitespace.");
        }

        if (value.Any(char.IsWhiteSpace))
        {
            throw createException($"{field} must not contain whitespace.");
        }

        if (ContainsControlCharacter(value))
        {
            throw createException($"{field} must not contain control characters.");
        }
    }

    private static bool ContainsControlCharacter(string value)
    {
        foreach (var character in value)
        {
            if (char.IsControl(character))
            {
                return true;
            }
        }

        return false;
    }

    private static void ValidateExactNonEmptyText(
        string? value,
        string field,
        Func<string, Exception> createException)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw createException($"{field} must be a non-empty string.");
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw createException($"{field} must not contain surrounding whitespace.");
        }

        if (ContainsControlCharacter(value))
        {
            throw createException($"{field} must not contain control characters.");
        }
    }

    private static void ValidateOptionalExactJsonStringProperty(
        JsonObject payload,
        string propertyName,
        string context)
    {
        if (!payload.TryGetPropertyValue(propertyName, out var value) || value is null)
        {
            return;
        }

        _ = RequireExactJsonString(value, context);
    }

    private static void ValidateOptionalUnsignedInteger(
        JsonObject payload,
        string propertyName,
        string context)
    {
        if (!payload.TryGetPropertyValue(propertyName, out var value) || value is null)
        {
            return;
        }

        if (value is not JsonValue jsonValue)
        {
            throw new JsonException($"{context} must be an unsigned integer.");
        }

        if (jsonValue.TryGetValue<string>(out var text))
        {
            _ = RequireExactJsonString(value, context);
            if (text.StartsWith("-", StringComparison.Ordinal))
            {
                throw new JsonException($"{context} must be non-negative.");
            }
            if (!ToriiIdentifierJson.IsCanonicalUnsignedDecimalText(text)
                || !ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out _))
            {
                throw new JsonException($"{context} must be canonical unsigned decimal text.");
            }
            return;
        }

        if (jsonValue.TryGetValue<long>(out var signedInteger))
        {
            if (signedInteger < 0)
            {
                throw new JsonException($"{context} must be non-negative.");
            }
            return;
        }

        if (jsonValue.TryGetValue<ulong>(out _))
        {
            return;
        }

        throw new JsonException($"{context} must be an unsigned integer.");
    }

    private static void ValidateOptionalPositiveUnsignedInteger(
        JsonObject payload,
        string propertyName,
        string context)
    {
        if (!payload.TryGetPropertyValue(propertyName, out var value) || value is null)
        {
            return;
        }

        ValidateOptionalUnsignedInteger(payload, propertyName, context);

        if (value is not JsonValue jsonValue)
        {
            return;
        }

        if (jsonValue.TryGetValue<string>(out var text))
        {
            if (text == "0")
            {
                throw new JsonException($"{context} must be positive.");
            }

            return;
        }

        if (jsonValue.TryGetValue<long>(out var signedInteger))
        {
            if (signedInteger == 0)
            {
                throw new JsonException($"{context} must be positive.");
            }

            return;
        }

        if (jsonValue.TryGetValue<ulong>(out var unsignedInteger) && unsignedInteger == 0)
        {
            throw new JsonException($"{context} must be positive.");
        }
    }

    private static string RequireExactJsonStringProperty(JsonObject payload, string propertyName, string context)
    {
        if (!payload.TryGetPropertyValue(propertyName, out var value))
        {
            throw new JsonException($"{context} is required.");
        }

        return RequireExactJsonString(value, context);
    }

    private static string RequireExactJsonString(JsonNode? node, string context)
    {
        var value = RequireJsonStringForJson(node, context);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new JsonException($"{context} must be a non-empty string.");
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new JsonException($"{context} must not contain surrounding whitespace.");
        }

        if (value.Any(char.IsWhiteSpace))
        {
            throw new JsonException($"{context} must not contain whitespace.");
        }

        if (ContainsControlCharacter(value))
        {
            throw new JsonException($"{context} must not contain control characters.");
        }

        return value;
    }

    private static void ValidateExactBase64(string value, string field)
    {
        foreach (var character in value)
        {
            if (char.IsWhiteSpace(character))
            {
                throw new JsonException($"{field} must not contain whitespace.");
            }
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(value);
        }
        catch (FormatException ex)
        {
            throw new JsonException($"{field} must be valid base64.", ex);
        }

        if (bytes.Length == 0)
        {
            throw new JsonException($"{field} must not decode to empty bytes.");
        }

        if (!string.Equals(Convert.ToBase64String(bytes), value, StringComparison.Ordinal))
        {
            throw new JsonException($"{field} must be canonical base64 text.");
        }
    }

    private static byte[] DecodeExactBase64AllowEmpty(string value, string field)
    {
        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new JsonException($"{field} must not contain surrounding whitespace.");
        }

        if (value.Any(char.IsWhiteSpace))
        {
            throw new JsonException($"{field} must not contain whitespace.");
        }

        if (ContainsControlCharacter(value))
        {
            throw new JsonException($"{field} must not contain control characters.");
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(value);
        }
        catch (FormatException error)
        {
            throw new JsonException($"{field} must be valid base64.", error);
        }

        if (!string.Equals(Convert.ToBase64String(bytes), value, StringComparison.Ordinal))
        {
            throw new JsonException($"{field} must be canonical base64 text.");
        }

        return bytes;
    }

    private static string RequireJsonStringForJson(JsonNode? node, string context)
    {
        if (node is JsonValue value && value.TryGetValue<string>(out var text))
        {
            return text;
        }

        throw new JsonException($"{context} must be a string.");
    }

    private static void ValidateExactHex(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new JsonException($"{field} must be a non-empty hex string.");
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new JsonException($"{field} must not contain surrounding whitespace.");
        }

        if (value.Any(char.IsWhiteSpace))
        {
            throw new JsonException($"{field} must not contain whitespace.");
        }

        if (ContainsControlCharacter(value))
        {
            throw new JsonException($"{field} must not contain control characters.");
        }

        var body = value.StartsWith("0x", StringComparison.Ordinal)
            ? value[2..]
            : value;
        if (body.Length == 0 || body.Length % 2 != 0 || !IsHex(body))
        {
            throw new JsonException($"{field} must be an exact hex string.");
        }
    }

    private static void ValidateExactSizedHex(string? value, string field, int expectedBytes)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new JsonException($"{field} must be a non-empty {expectedBytes}-byte hex string.");
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new JsonException($"{field} must not contain surrounding whitespace.");
        }

        if (value.Any(char.IsWhiteSpace))
        {
            throw new JsonException($"{field} must not contain whitespace.");
        }

        if (ContainsControlCharacter(value))
        {
            throw new JsonException($"{field} must not contain control characters.");
        }

        if (value.Length != expectedBytes * 2 || !IsLowercaseHex(value))
        {
            throw new JsonException($"{field} must be an exact lowercase {expectedBytes}-byte hex string.");
        }
    }

    private static void ValidateExactLowercaseHexChars(string? value, string field, int expectedChars)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new JsonException($"{field} must be a non-empty {expectedChars}-character lowercase hex string.");
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new JsonException($"{field} must not contain surrounding whitespace.");
        }

        if (value.Any(char.IsWhiteSpace))
        {
            throw new JsonException($"{field} must not contain whitespace.");
        }

        if (ContainsControlCharacter(value))
        {
            throw new JsonException($"{field} must not contain control characters.");
        }

        if (value.Length != expectedChars || !IsLowercaseHex(value))
        {
            throw new JsonException($"{field} must be a {expectedChars}-character lowercase hex string.");
        }
    }

    private static void ValidateOptionalExactSizedHex(string? value, string field, int expectedBytes)
    {
        if (value is null)
        {
            return;
        }

        ValidateExactSizedHex(value, field, expectedBytes);
    }

    private static void ValidateOptionalExactSizedHexOrEmpty(string? value, string field, int expectedBytes)
    {
        if (value is null || value.Length == 0)
        {
            return;
        }

        ValidateExactSizedHex(value, field, expectedBytes);
    }

    private static void ValidateExactEvenLengthHex(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new JsonException($"{field} must be a non-empty even-length hex string.");
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new JsonException($"{field} must not contain surrounding whitespace.");
        }

        if (value.Any(char.IsWhiteSpace))
        {
            throw new JsonException($"{field} must not contain whitespace.");
        }

        if (ContainsControlCharacter(value))
        {
            throw new JsonException($"{field} must not contain control characters.");
        }

        if (value.Length % 2 != 0 || !IsLowercaseHex(value))
        {
            throw new JsonException($"{field} must be an exact lowercase even-length hex string.");
        }
    }

    private static void ValidateOptionalTransactionHashHex(string? value, string field)
    {
        if (value is null || value.Length == 0)
        {
            return;
        }

        ValidateExactSizedHex(value, field, 32);
    }

    private static void ValidateOptionalBase64(string? value, string field)
    {
        if (value is null)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new JsonException($"{field} must be a non-empty base64 string.");
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new JsonException($"{field} must not contain surrounding whitespace.");
        }

        if (value.Any(char.IsWhiteSpace))
        {
            throw new JsonException($"{field} must not contain whitespace.");
        }

        if (ContainsControlCharacter(value))
        {
            throw new JsonException($"{field} must not contain control characters.");
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(value);
        }
        catch (FormatException ex)
        {
            throw new JsonException($"{field} must be valid base64.", ex);
        }

        if (bytes.Length == 0)
        {
            throw new JsonException($"{field} must not decode to empty bytes.");
        }

        if (!string.Equals(Convert.ToBase64String(bytes), value, StringComparison.Ordinal))
        {
            throw new JsonException($"{field} must be canonical base64 text.");
        }
    }

    private async Task<ToriiApiException> CreateApiExceptionAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        string? responseBody = null;
        if (response.Content is not null)
        {
            try
            {
                responseBody = await ReadStrictUtf8TextContentAsync(
                    response.Content,
                    "Torii error response body",
                    cancellationToken,
                    ErrorResponseMaxBytes);
            }
            catch (InvalidDataException error)
            {
                responseBody = error.InnerException is DecoderFallbackException
                    ? InvalidUtf8ResponseBody
                    : $"<response body exceeds the {ErrorResponseMaxBytes}-byte limit>";
            }
        }

        return new ToriiApiException(
            response.StatusCode,
            response.RequestMessage?.RequestUri,
            responseBody,
            response.ReasonPhrase,
            RejectCodeHeader(response));
    }

    /// <summary>The <c>x-iroha-reject-code</c> header of a failed response, when present.</summary>
    private static string? RejectCodeHeader(HttpResponseMessage response) =>
        response.Headers.TryGetValues(ToriiApiException.RejectCodeHeaderName, out var values)
            ? values.FirstOrDefault()
            : null;

    private static ToriiApiException CreateApiExceptionFromBody(
        HttpResponseMessage response,
        ReadOnlySpan<byte> body)
    {
        string responseBody;
        try
        {
            responseBody = StrictUtf8.GetString(body);
        }
        catch (DecoderFallbackException)
        {
            responseBody = InvalidUtf8ResponseBody;
        }

        return new ToriiApiException(
            response.StatusCode,
            response.RequestMessage?.RequestUri,
            responseBody,
            response.ReasonPhrase,
            RejectCodeHeader(response));
    }

    private static async Task<string> ReadStrictUtf8TextContentAsync(
        HttpContent content,
        string context,
        CancellationToken cancellationToken,
        int maximumBytes = DefaultTextResponseMaxBytes)
    {
        var bytes = await ReadBoundedResponseBodyAsync(
            content,
            maximumBytes,
            context,
            cancellationToken);
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException($"{context} must be valid UTF-8.", exception);
        }
    }

    private Task<HttpResponseMessage> OpenLiveSseAsync(
        string path,
        string? query = null,
        CancellationToken cancellationToken = default)
    {
        return SendAsync(
            HttpMethod.Get,
            path,
            query,
            content: null,
            accept: "text/event-stream",
            cancellationToken: cancellationToken);
    }

    private Task<HttpResponseMessage> OpenSseAsync(
        string path,
        string? query = null,
        string? lastEventId = null,
        CancellationToken cancellationToken = default)
    {
        return SendAsync(
            HttpMethod.Get,
            path,
            query,
            content: null,
            accept: "text/event-stream",
            configureRequest: request =>
            {
                var exactLastEventId = NormalizeOptionalExactHeaderValue(lastEventId, nameof(lastEventId));
                if (!string.IsNullOrEmpty(exactLastEventId))
                {
                    request.Headers.TryAddWithoutValidation("Last-Event-ID", exactLastEventId);
                }
            },
            cancellationToken: cancellationToken);
    }

    private async IAsyncEnumerable<TResponse> StreamSsePayloadsAsync<TResponse>(
        string path,
        JsonTypeInfo<TResponse> jsonTypeInfo,
        Action<TResponse>? validate = null,
        string? query = null,
        string? lastEventId = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        using var response = await OpenSseAsync(path, query, lastEventId, cancellationToken);
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);

        await foreach (var sseEvent in ReadServerSentEventsAsync(stream, cancellationToken))
        {
            if (sseEvent.IsComment || sseEvent.RawData is null)
            {
                continue;
            }

            var payloadContext = $"{path} SSE payload";
            var payload = JsonSerializer.Deserialize(RequireSseJsonData(sseEvent, payloadContext), jsonTypeInfo);
            if (payload is null)
            {
                throw new JsonException($"{payloadContext} must not deserialize to null.");
            }

            validate?.Invoke(payload);
            yield return payload;
        }
    }

    private Uri BuildRequestUri(string path, string? query)
    {
        var relativePath = path.Length > 0 && path[0] == '/' ? path[1..] : path;
        var uri = new Uri(BaseUri, relativePath);
        if (string.IsNullOrWhiteSpace(query))
        {
            return uri;
        }

        var builder = new UriBuilder(uri)
        {
            Query = query.Length > 0 && query[0] == '?' ? query[1..] : query,
        };
        return builder.Uri;
    }

    private static string DecodeQueryText(
        string value,
        string paramName,
        string invalidPercentMessage,
        string invalidUtf8Message)
    {
        ValidateQueryPercentEscapes(value, paramName, invalidPercentMessage);
        var builder = new StringBuilder(value.Length);
        for (var index = 0; index < value.Length;)
        {
            if (value[index] == '+')
            {
                builder.Append(' ');
                index++;
                continue;
            }

            if (value[index] != '%')
            {
                builder.Append(value[index]);
                index++;
                continue;
            }

            var bytes = new List<byte>();
            while (index < value.Length && value[index] == '%')
            {
                bytes.Add((byte)((HexValue(value[index + 1]) << 4) | HexValue(value[index + 2])));
                index += 3;
            }

            try
            {
                builder.Append(StrictUtf8.GetString(bytes.ToArray()));
            }
            catch (DecoderFallbackException exception)
            {
                throw new ArgumentException(invalidUtf8Message, paramName, exception);
            }
        }

        return builder.ToString();
    }

    private static void ValidateQueryPercentEscapes(string value, string paramName, string message)
    {
        for (var index = 0; index < value.Length; index++)
        {
            if (value[index] != '%')
            {
                continue;
            }

            if (index + 2 >= value.Length
                || !Uri.IsHexDigit(value[index + 1])
                || !Uri.IsHexDigit(value[index + 2]))
            {
                throw new ArgumentException(message, paramName);
            }

            index += 2;
        }
    }

    private static void ValidatePathPercentEscapes(string value, string paramName)
    {
        for (var index = 0; index < value.Length; index++)
        {
            if (value[index] != '%')
            {
                continue;
            }

            if (index + 2 >= value.Length
                || !Uri.IsHexDigit(value[index + 1])
                || !Uri.IsHexDigit(value[index + 2]))
            {
                throw new ArgumentException($"{paramName} must contain valid percent escapes.", paramName);
            }

            index += 2;
        }
    }

    private static int HexValue(char value)
        => value switch
        {
            >= '0' and <= '9' => value - '0',
            >= 'A' and <= 'F' => value - 'A' + 10,
            >= 'a' and <= 'f' => value - 'a' + 10,
            _ => throw new ArgumentException("query components must contain valid percent escapes."),
        };

    private static string RequireJsonString(JsonNode? node, string context)
    {
        if (node is JsonValue value && value.TryGetValue<string>(out var text))
        {
            return text;
        }

        throw new ArgumentException($"{context} must be a string.", context);
    }

    private static string BuildPaginationQuery(
        int? limit,
        long offset,
        params KeyValuePair<string, string?>[] extraParameters)
    {
        if (limit.HasValue && limit.Value <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(limit), "Pagination limit must be positive.");
        }

        if (offset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(offset), "Pagination offset cannot be negative.");
        }

        var parameters = new List<KeyValuePair<string, string?>>(extraParameters.Length + 2);
        if (limit.HasValue)
        {
            parameters.Add(new KeyValuePair<string, string?>("limit", limit.Value.ToString(CultureInfo.InvariantCulture)));
        }

        if (offset > 0)
        {
            parameters.Add(new KeyValuePair<string, string?>("offset", offset.ToString(CultureInfo.InvariantCulture)));
        }

        parameters.AddRange(extraParameters);
        return BuildQueryString(parameters);
    }

    private static string BuildQueryString(IEnumerable<KeyValuePair<string, string?>> parameters)
    {
        var builder = new StringBuilder();
        foreach (var (name, value) in parameters)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            if (builder.Length > 0)
            {
                builder.Append('&');
            }

            builder.Append(Uri.EscapeDataString(name));
            builder.Append('=');
            builder.Append(Uri.EscapeDataString(value));
        }

        return builder.ToString();
    }

    private static string BuildContractStateQuery(ToriiContractStateQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);

        var normalizedPath = query.Path is null
            ? null
            : NormalizeExactValue(query.Path, nameof(query.Path));
        var normalizedPrefix = query.Prefix is null
            ? null
            : NormalizeExactValue(query.Prefix, nameof(query.Prefix));
        var normalizedPaths = NormalizeOptionalExactPathList(query.Paths, nameof(query.Paths));

        var hasPath = normalizedPath is not null;
        var hasPaths = normalizedPaths is { Length: > 0 };
        var hasPrefix = normalizedPrefix is not null;
        var modeCount = (hasPath ? 1 : 0) + (hasPaths ? 1 : 0) + (hasPrefix ? 1 : 0);
        if (modeCount != 1)
        {
            throw new ArgumentException("Exactly one of Path, Paths, or Prefix must be provided.", nameof(query));
        }

        var encodedPaths = normalizedPaths is { Length: > 0 } paths
            ? string.Join(',', paths)
            : null;

        return BuildQueryString(
        [
            new KeyValuePair<string, string?>("path", normalizedPath),
            new KeyValuePair<string, string?>("paths", encodedPaths),
            new KeyValuePair<string, string?>("prefix", normalizedPrefix),
            new KeyValuePair<string, string?>(
                "include_value",
                query.IncludeValue.HasValue ? query.IncludeValue.Value.ToString().ToLowerInvariant() : null),
            new KeyValuePair<string, string?>("offset", query.Offset?.ToString(CultureInfo.InvariantCulture)),
            new KeyValuePair<string, string?>(
                "limit",
                NormalizeOptionalPositiveUInt64(query.Limit, nameof(query.Limit))?.ToString(CultureInfo.InvariantCulture)),
            new KeyValuePair<string, string?>("decode", NormalizeOptionalExactValue(query.Decode, nameof(query.Decode))),
        ]);
    }

    private static JsonSerializerOptions CreateSerializerOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            AllowTrailingCommas = false,
            MaxDepth = 128,
            NumberHandling = JsonNumberHandling.Strict,
            PropertyNameCaseInsensitive = false,
            ReadCommentHandling = JsonCommentHandling.Disallow,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };
        options.TypeInfoResolverChain.Insert(0, ToriiJsonSerializerContext.Default);
        options.MakeReadOnly();
        return options;
    }

    private StringContent CreateJsonContent<TRequest>(TRequest request)
    {
        var json = JsonSerializer.Serialize(request, SerializerOptions);
        return new StringContent(json, Encoding.UTF8, "application/json");
    }

    private static ToriiAccountOnboardingPlanRequest NormalizeAccountOnboardingPlanRequest(
        ToriiAccountOnboardingPlanRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Version != 1)
        {
            throw new ArgumentOutOfRangeException(nameof(request.Version), "Version must be 1.");
        }
        var permissions = ToriiAccountOnboardingReceiptVerifier.NormalizePermissions(
            request.Permissions,
            nameof(request.Permissions));

        return request with
        {
            Alias = ToriiAccountOnboardingReceiptVerifier.RequireAlias(request.Alias, nameof(request.Alias)),
            AccountId = ToriiAccountOnboardingReceiptVerifier.RequireCanonicalAccountId(
                request.AccountId,
                nameof(request.AccountId)),
            Permissions = permissions,
        };
    }

    private static void RequireMatchingAccountOnboardingRequest(
        ToriiAccountOnboardingPlanRequest expected,
        ToriiAccountOnboardingPlanRequest actual,
        string context)
    {
        if (actual is null
            || expected.Version != actual.Version
            || !string.Equals(expected.Alias, actual.Alias, StringComparison.Ordinal)
            || !string.Equals(expected.AccountId, actual.AccountId, StringComparison.Ordinal)
            || !expected.Permissions.SequenceEqual(actual.Permissions, StringComparer.Ordinal))
        {
            throw new JsonException($"{context} does not contain the exact requested onboarding intent.");
        }
    }

    private static ToriiAccountFaucetClaimV1 NormalizeAccountFaucetClaim(
        ToriiAccountFaucetClaimV1 claim)
    {
        var accountId = ToriiAccountFaucetPow.RequireExactAccountId(
            claim.AccountId,
            nameof(claim.AccountId),
            chainDiscriminant: null);

        var nonceHex = ToriiAccountFaucetMetadata.RequireFaucetNonceHex(
            claim.PowNonceHex,
            nameof(claim.PowNonceHex));
        return new ToriiAccountFaucetClaimV1(
            accountId,
            claim.PowAnchorHeight,
            nonceHex);
    }

    private static ToriiVpnQuoteCreateRequest NormalizeVpnQuoteCreateRequest(
        ToriiVpnQuoteCreateRequest request)
    {
        return request with
        {
            ExitClass = NormalizeOptionalVpnExitClass(request.ExitClass, nameof(request.ExitClass)),
            MeteringPublicKeyHex = NormalizeVpnExactSizedHex(
                request.MeteringPublicKeyHex,
                nameof(request.MeteringPublicKeyHex),
                32),
        };
    }

    private static ToriiVpnSessionCreateRequest NormalizeVpnSessionCreateRequest(
        ToriiVpnSessionCreateRequest request)
    {
        return request with
        {
            ExitClass = NormalizeOptionalVpnExitClass(request.ExitClass, nameof(request.ExitClass)),
            QuoteId = NormalizeExactSizedHex(request.QuoteId, nameof(request.QuoteId), 32),
            PaymentTransactionHash = NormalizeVpnExactSizedHex(
                request.PaymentTransactionHash,
                nameof(request.PaymentTransactionHash),
                32),
            MeteringPublicKeyHex = NormalizeVpnExactSizedHex(
                request.MeteringPublicKeyHex,
                nameof(request.MeteringPublicKeyHex),
                32),
        };
    }

    private static ToriiVpnReceiptSubmitRequest NormalizeVpnReceiptSubmitRequest(
        ToriiVpnReceiptSubmitRequest request)
    {
        return request with
        {
            RelayReceiptHex = NormalizeVpnExactHex(request.RelayReceiptHex, nameof(request.RelayReceiptHex)),
            ClientVoucherHex = NormalizeVpnExactHex(request.ClientVoucherHex, nameof(request.ClientVoucherHex)),
            LeaseIdHex = NormalizeOptionalVpnExactSizedHexOrEmpty(
                request.LeaseIdHex,
                nameof(request.LeaseIdHex),
                32),
        };
    }

    private static ToriiContractCallRequest NormalizeContractCallRequest(ToriiContractCallRequest request)
    {
        var publicKeyHex = NormalizeOptionalExactSizedHex(request.PublicKeyHex, nameof(request.PublicKeyHex), 32);
        var signatureBase64 = NormalizeOptionalExactBase64(request.SignatureBase64, nameof(request.SignatureBase64));
        var transactionPayloadBase64 = NormalizeOptionalExactBase64(
            request.TransactionPayloadBase64, nameof(request.TransactionPayloadBase64));
        ValidateDetachedSigningPair(publicKeyHex, signatureBase64);
        if ((transactionPayloadBase64 is null) != (publicKeyHex is null))
        {
            throw new ArgumentException(
                "Detached signing requires transaction_payload_b64, public_key_hex, and signature_b64 together.",
                nameof(request.TransactionPayloadBase64));
        }
        if (transactionPayloadBase64 is not null && !request.CreationTimeMilliseconds.HasValue)
        {
            throw new ArgumentException("Detached signing requires the prepared creation time.", nameof(request.CreationTimeMilliseconds));
        }
        var (contractAddress, contractAlias) = NormalizeContractTarget(
            request.ContractAddress,
            request.ContractAlias,
            nameof(request.ContractAddress),
            nameof(request.ContractAlias),
            requireTarget: true);
        if (request.CreationTimeMilliseconds == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request.CreationTimeMilliseconds),
                "Creation time must be positive when provided.");
        }
        if (request.TransactionTimeToLiveMilliseconds == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request.TransactionTimeToLiveMilliseconds),
                "Transaction TTL must be positive when provided.");
        }
        var authority = ToriiAccountFaucetPow.RequireExactAccountId(
            request.Authority,
            nameof(request.Authority));
        var entrypoint = NormalizeOptionalExactValue(
            request.Entrypoint,
            nameof(request.Entrypoint));
        ValidateContractCallDraftIntent(
            request.DraftIntent,
            authority,
            contractAddress,
            contractAlias,
            entrypoint,
            request.Payload,
            nameof(request.DraftIntent));

        return request with
        {
            Authority = authority,
            TransactionPayloadBase64 = transactionPayloadBase64,
            PublicKeyHex = publicKeyHex,
            SignatureBase64 = signatureBase64,
            ContractAddress = contractAddress,
            ContractAlias = contractAlias,
            Entrypoint = entrypoint,
            DraftIntent = request.DraftIntent,
            FeePayment = NormalizeFeePaymentIntent(
                request.FeePayment,
                nameof(request.FeePayment),
                requireGasLimit: true),
        };
    }

    private static ToriiContractViewRequest NormalizeContractViewRequest(ToriiContractViewRequest request)
    {
        var (contractAddress, contractAlias) = NormalizeContractTarget(
            request.ContractAddress,
            request.ContractAlias,
            nameof(request.ContractAddress),
            nameof(request.ContractAlias),
            requireTarget: true);
        if (request.GasLimit == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request.GasLimit), "Gas limit must be positive.");
        }

        return request with
        {
            Authority = ToriiAccountFaucetPow.RequireExactAccountId(request.Authority, nameof(request.Authority)),
            ContractAddress = contractAddress,
            ContractAlias = contractAlias,
            Entrypoint = NormalizeOptionalExactValue(request.Entrypoint, nameof(request.Entrypoint)),
        };
    }

    private static void ValidateContractCallDraftIntent(
        ToriiContractCallDraftIntent? draftIntent,
        string authority,
        string? contractAddress,
        string? contractAlias,
        string? entrypoint,
        JsonNode? payload,
        string parameterName)
    {
        if (draftIntent is null)
        {
            return;
        }

        var invocation = draftIntent.Invocation;
        var metadata = draftIntent.Metadata;
        var expectedCodeHashHex = Convert
            .ToHexString(invocation.ExpectedCodeHash)
            .ToLowerInvariant();

        static bool HasExactString(
            IReadOnlyDictionary<string, JsonNode?> values,
            string key,
            string expected) =>
            values.TryGetValue(key, out var value)
            && value is JsonValue jsonValue
            && jsonValue.TryGetValue<string>(out var text)
            && string.Equals(text, expected, StringComparison.Ordinal);

        if (!string.Equals(invocation.Entrypoint, entrypoint, StringComparison.Ordinal)
            || contractAddress is not null
                && !string.Equals(
                    invocation.ContractAddress,
                    contractAddress,
                    StringComparison.Ordinal)
            || (payload is null) != (invocation.Arguments is null)
            || !HasExactString(metadata, "contract_address", invocation.ContractAddress)
            || !HasExactString(metadata, "contract_code_hash", expectedCodeHashHex)
            || !HasExactString(metadata, "contract_entrypoint", invocation.Entrypoint))
        {
            throw new ArgumentException(
                "DraftIntent invocation or system metadata does not match the contract-call request.",
                parameterName);
        }
        if (contractAlias is null)
        {
            if (metadata.ContainsKey("contract_alias"))
            {
                throw new ArgumentException(
                    "DraftIntent metadata added an unrequested contract alias.",
                    parameterName);
            }
        }
        else if (!HasExactString(metadata, "contract_alias", contractAlias))
        {
            throw new ArgumentException(
                "DraftIntent metadata does not match the requested contract alias.",
                parameterName);
        }
        if (payload is null)
        {
            if (metadata.ContainsKey("contract_payload"))
            {
                throw new ArgumentException(
                    "DraftIntent metadata added an unrequested contract payload.",
                    parameterName);
            }
        }
        else if (!metadata.TryGetValue("contract_payload", out var expectedPayload)
            || !JsonNode.DeepEquals(expectedPayload, payload))
        {
            throw new ArgumentException(
                "DraftIntent metadata does not match the exact request payload.",
                parameterName);
        }

        try
        {
            _ = new TransactionEncodingContext(authority).EncodeMetadata(metadata);
        }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException)
        {
            throw new ArgumentException(
                "DraftIntent metadata is not canonically encodable.",
                parameterName,
                error);
        }
    }

    private static FeePaymentIntent NormalizeFeePaymentIntent(
        FeePaymentIntent? feePayment,
        string paramName,
        bool requireGasLimit)
    {
        if (feePayment is null)
        {
            throw new ArgumentNullException(paramName, "Fee payment is required.");
        }
        if (requireGasLimit && !feePayment.GasLimit.HasValue)
        {
            throw new ArgumentException(
                "Fee payment must include a positive gas limit for contract execution.",
                paramName);
        }
        return feePayment;
    }

    private static ToriiMultisigContractCallProposeRequest NormalizeMultisigContractCallProposeRequest(
        ToriiMultisigContractCallProposeRequest request)
    {
        var (multisigAccountId, multisigAccountAlias) = NormalizeMultisigSelector(
            request.MultisigAccountId,
            request.MultisigAccountAlias);
        var publicKeyHex = NormalizeOptionalExactSizedHex(request.PublicKeyHex, nameof(request.PublicKeyHex), 32);
        var signatureBase64 = NormalizeOptionalExactBase64(request.SignatureBase64, nameof(request.SignatureBase64));
        ValidateDetachedSigningPair(publicKeyHex, signatureBase64);
        var (contractAddress, contractAlias) = NormalizeContractTarget(
            request.ContractAddress,
            request.ContractAlias,
            nameof(request.ContractAddress),
            nameof(request.ContractAlias),
            requireTarget: true);
        if (request.CreationTimeMilliseconds == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request.CreationTimeMilliseconds),
                "Creation time must be positive when provided.");
        }
        var signerAccountId = ToriiAccountFaucetPow.RequireExactAccountId(
            request.SignerAccountId,
            nameof(request.SignerAccountId));
        var entrypoint = NormalizeExactValue(
            request.Entrypoint,
            nameof(request.Entrypoint));
        ValidateContractCallDraftIntent(
            request.DraftIntent,
            signerAccountId,
            contractAddress,
            contractAlias,
            entrypoint,
            request.Payload,
            nameof(request.DraftIntent));

        return request with
        {
            MultisigAccountId = multisigAccountId,
            MultisigAccountAlias = multisigAccountAlias,
            SignerAccountId = signerAccountId,
            PublicKeyHex = publicKeyHex,
            SignatureBase64 = signatureBase64,
            ContractAddress = contractAddress,
            ContractAlias = contractAlias,
            Entrypoint = entrypoint,
            DraftIntent = request.DraftIntent,
            FeePayment = NormalizeFeePaymentIntent(
                request.FeePayment,
                nameof(request.FeePayment),
                requireGasLimit: true),
        };
    }

    private static ToriiMultisigApproveRequest NormalizeMultisigApproveRequest(
        ToriiMultisigApproveRequest request)
    {
        var (multisigAccountId, multisigAccountAlias) = NormalizeMultisigSelector(
            request.MultisigAccountId,
            request.MultisigAccountAlias);
        var publicKeyHex = NormalizeOptionalExactSizedHex(request.PublicKeyHex, nameof(request.PublicKeyHex), 32);
        var signatureBase64 = NormalizeOptionalExactBase64(request.SignatureBase64, nameof(request.SignatureBase64));
        ValidateDetachedSigningPair(publicKeyHex, signatureBase64);
        ValidateMultisigProposalSelector(request.ProposalId, request.InstructionsHash);
        if (request.CreationTimeMilliseconds == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request.CreationTimeMilliseconds),
                "Creation time must be positive when provided.");
        }

        return request with
        {
            MultisigAccountId = multisigAccountId,
            MultisigAccountAlias = multisigAccountAlias,
            SignerAccountId = ToriiAccountFaucetPow.RequireExactAccountId(
                request.SignerAccountId,
                nameof(request.SignerAccountId)),
            PublicKeyHex = publicKeyHex,
            SignatureBase64 = signatureBase64,
            FeePayment = NormalizeFeePaymentIntent(
                request.FeePayment,
                nameof(request.FeePayment),
                requireGasLimit: false),
            ProposalId = request.ProposalId is null
                ? null
                : NormalizeExactSizedHex(request.ProposalId, nameof(request.ProposalId), 32),
            InstructionsHash = request.InstructionsHash is null
                ? null
                : NormalizeExactSizedHex(request.InstructionsHash, nameof(request.InstructionsHash), 32),
        };
    }

    private static ToriiMultisigCancelRequest NormalizeMultisigCancelRequest(
        ToriiMultisigCancelRequest request)
    {
        var (multisigAccountId, multisigAccountAlias) = NormalizeMultisigSelector(
            request.MultisigAccountId,
            request.MultisigAccountAlias);
        var publicKeyHex = NormalizeOptionalExactSizedHex(request.PublicKeyHex, nameof(request.PublicKeyHex), 32);
        var signatureBase64 = NormalizeOptionalExactBase64(request.SignatureBase64, nameof(request.SignatureBase64));
        ValidateDetachedSigningPair(publicKeyHex, signatureBase64);
        ValidateMultisigProposalSelector(request.ProposalId, request.InstructionsHash);
        if (request.CreationTimeMilliseconds == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request.CreationTimeMilliseconds),
                "Creation time must be positive when provided.");
        }

        return request with
        {
            MultisigAccountId = multisigAccountId,
            MultisigAccountAlias = multisigAccountAlias,
            SignerAccountId = ToriiAccountFaucetPow.RequireExactAccountId(
                request.SignerAccountId,
                nameof(request.SignerAccountId)),
            PublicKeyHex = publicKeyHex,
            SignatureBase64 = signatureBase64,
            FeePayment = NormalizeFeePaymentIntent(
                request.FeePayment,
                nameof(request.FeePayment),
                requireGasLimit: false),
            ProposalId = request.ProposalId is null
                ? null
                : NormalizeExactSizedHex(request.ProposalId, nameof(request.ProposalId), 32),
            InstructionsHash = request.InstructionsHash is null
                ? null
                : NormalizeExactSizedHex(request.InstructionsHash, nameof(request.InstructionsHash), 32),
        };
    }

    private static void ValidateMultisigProposalSelector(string? proposalId, string? instructionsHash)
    {
        if (proposalId is null && instructionsHash is null)
        {
            throw new ArgumentException(
                "Provide either proposal_id or instructions_hash.",
                nameof(proposalId));
        }
    }

    private static ToriiMultisigContractCallApproveRequest NormalizeMultisigContractCallApproveRequest(
        ToriiMultisigContractCallApproveRequest request)
    {
        var (multisigAccountId, multisigAccountAlias) = NormalizeMultisigSelector(
            request.MultisigAccountId,
            request.MultisigAccountAlias);
        var publicKeyHex = NormalizeOptionalExactSizedHex(request.PublicKeyHex, nameof(request.PublicKeyHex), 32);
        var signatureBase64 = NormalizeOptionalExactBase64(request.SignatureBase64, nameof(request.SignatureBase64));
        ValidateDetachedSigningPair(publicKeyHex, signatureBase64);
        if (request.ProposalId is null && request.InstructionsHash is null)
        {
            throw new ArgumentException(
                "Provide either proposal_id or instructions_hash.",
                nameof(request.ProposalId));
        }
        if (request.CreationTimeMilliseconds == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request.CreationTimeMilliseconds),
                "Creation time must be positive when provided.");
        }

        return request with
        {
            MultisigAccountId = multisigAccountId,
            MultisigAccountAlias = multisigAccountAlias,
            SignerAccountId = ToriiAccountFaucetPow.RequireExactAccountId(
                request.SignerAccountId,
                nameof(request.SignerAccountId)),
            PublicKeyHex = publicKeyHex,
            SignatureBase64 = signatureBase64,
            FeePayment = NormalizeFeePaymentIntent(
                request.FeePayment,
                nameof(request.FeePayment),
                requireGasLimit: false),
            ProposalId = request.ProposalId is null
                ? null
                : NormalizeExactSizedHex(request.ProposalId, nameof(request.ProposalId), 32),
            InstructionsHash = request.InstructionsHash is null
                ? null
                : NormalizeExactSizedHex(request.InstructionsHash, nameof(request.InstructionsHash), 32),
        };
    }

    private static ToriiContractVerifiedSourceSubmission NormalizeContractVerifiedSourceSubmission(
        ToriiContractVerifiedSourceSubmission request)
    {
        var language = NormalizeExactValue(request.Language, nameof(request.Language));
        if (!string.Equals(language, "kotodama", StringComparison.Ordinal))
        {
            throw new ArgumentException("Verified source language must be kotodama.", nameof(request.Language));
        }

        return ToriiContractSourceBundle.Normalize(request with
        {
            Language = language,
            SourceName = NormalizeOptionalSourceName(request.SourceName, nameof(request.SourceName)),
            SourceText = NormalizeSourceText(request.SourceText, nameof(request.SourceText)),
        });
    }

    private static ByteArrayContent CreateBinaryContent(ReadOnlyMemory<byte> bytes, string mediaType)
    {
        var content = new ByteArrayContent(bytes.ToArray());
        content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
        return content;
    }

    private static string EncodePathSegment(string? value, string paramName)
    {
        return Uri.EscapeDataString(NormalizeExactPathSegment(value, paramName));
    }

    private static string EncodeIdentifierPathSegment(string? value, string paramName)
    {
        return Uri.EscapeDataString(NormalizeExactIdentifierPathSegment(value, paramName));
    }

    private static string EncodeAccountIdPathSegment(string? value, string paramName)
    {
        return Uri.EscapeDataString(ToriiAccountFaucetPow.RequireExactAccountId(value, paramName));
    }

    private static string EncodeVpnSessionPathSegment(string? value, string paramName)
    {
        return Uri.EscapeDataString(NormalizeExactSizedHex(value, paramName, 16));
    }

    private static string EncodeSoraFsCidPathSegment(string? value, string paramName)
    {
        return Uri.EscapeDataString(NormalizeSoraFsContentCidArgument(value, paramName));
    }

    private static string EncodePathSegment(string value)
    {
        return EncodePathSegment(value, nameof(value));
    }

    private static string NormalizeExactIdentifierPathSegment(string? value, string paramName)
    {
        var normalized = NormalizeExactPathSegment(value, paramName);
        if (normalized.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Value must not contain whitespace.", paramName);
        }

        return normalized;
    }

    private static string NormalizeExactPathSegment(string? value, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", paramName);
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new ArgumentException("Value must not contain surrounding whitespace.", paramName);
        }

        if (value.Any(char.IsControl))
        {
            throw new ArgumentException("Value must not contain control characters.", paramName);
        }

        return value;
    }

    private static string BuildSoraFsCidGatewayPath(string cid, string? relativePath)
    {
        var builder = new StringBuilder("/sorafs/cid/");
        builder.Append(EncodeSoraFsCidPathSegment(cid, nameof(cid)));

        if (relativePath is null || relativePath.Length == 0)
        {
            return builder.ToString();
        }

        if (string.IsNullOrWhiteSpace(relativePath))
        {
            throw new ArgumentException("Relative path must not be whitespace.", nameof(relativePath));
        }

        if (!string.Equals(relativePath.Trim(), relativePath, StringComparison.Ordinal))
        {
            throw new ArgumentException("Relative path must not contain surrounding whitespace.", nameof(relativePath));
        }

        if (relativePath.Any(char.IsControl))
        {
            throw new ArgumentException("Relative path must not contain control characters.", nameof(relativePath));
        }

        var segments = relativePath.Split('/');
        for (var index = 0; index < segments.Length; index++)
        {
            ValidateSoraFsRelativePathSegment(segments[index], index, nameof(relativePath));
        }

        var encodedSegments = segments.Select(Uri.EscapeDataString);
        builder.Append('/');
        builder.Append(string.Join('/', encodedSegments));
        return builder.ToString();
    }

    private static void ValidateSoraFsRelativePathSegment(string segment, int index, string paramName)
    {
        var field = $"{nameof(BuildSoraFsCidGatewayPath)}.{nameof(segment)}[{index}]";
        if (segment.Length == 0)
        {
            throw new ArgumentException("Relative path must not contain empty path segments.", paramName);
        }

        if (string.IsNullOrWhiteSpace(segment))
        {
            throw new ArgumentException($"{field} must not be blank.", paramName);
        }

        if (!string.Equals(segment.Trim(), segment, StringComparison.Ordinal))
        {
            throw new ArgumentException($"{field} must not contain surrounding whitespace.", paramName);
        }

        if (segment.Any(char.IsControl))
        {
            throw new ArgumentException($"{field} must not contain control characters.", paramName);
        }

        if (segment is "." or ".." || segment.Contains('\\', StringComparison.Ordinal))
        {
            throw new ArgumentException($"{field} must be a relative path component.", paramName);
        }
    }

    private static JsonElement RequireJsonObject(JsonElement element, string context)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException($"{context} must be an object.");
        }

        return element;
    }

    private static JsonElement RequireJsonObjectProperty(JsonElement element, string propertyName, string context)
    {
        if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind == JsonValueKind.Null)
        {
            throw new JsonException($"{context} must not be null.");
        }

        return RequireJsonObject(property, context);
    }

    private static bool TryReadOptionalJsonObjectProperty(
        JsonElement element,
        string propertyName,
        string context,
        out JsonElement value)
    {
        if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind == JsonValueKind.Null)
        {
            value = default;
            return false;
        }

        value = RequireJsonObject(property, context);
        return true;
    }

    private static string RequireJsonStringProperty(JsonElement element, string propertyName, string context)
    {
        if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind == JsonValueKind.Null)
        {
            throw new JsonException($"{context} must not be null.");
        }

        if (property.ValueKind != JsonValueKind.String)
        {
            throw new JsonException($"{context} must be a string.");
        }

        return property.GetString() ?? throw new JsonException($"{context} must not be null.");
    }

    private static string? ReadOptionalJsonStringProperty(JsonElement element, string propertyName, string context)
    {
        if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (property.ValueKind != JsonValueKind.String)
        {
            throw new JsonException($"{context} must be a string.");
        }

        return property.GetString();
    }

    private static ulong ValidatePositiveJsonUInt64Property(
        JsonElement element,
        string propertyName,
        string context)
    {
        var value = RequireJsonUInt64Property(element, propertyName, context);
        if (value == 0)
        {
            throw new JsonException($"{context} must be positive.");
        }

        return value;
    }

    private static ulong RequireJsonUInt64Property(JsonElement element, string propertyName, string context)
    {
        if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind == JsonValueKind.Null)
        {
            throw new JsonException($"{context} must not be null.");
        }

        return ReadJsonUInt64(property, context);
    }

    private static ulong? ReadOptionalPositiveJsonUInt64Property(
        JsonElement element,
        string propertyName,
        string context)
    {
        var value = ReadOptionalJsonUInt64Property(element, propertyName, context);
        if (value == 0)
        {
            throw new JsonException($"{context} must be positive.");
        }

        return value;
    }

    private static ulong? ReadOptionalJsonUInt64Property(JsonElement element, string propertyName, string context)
    {
        if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return ReadJsonUInt64(property, context);
    }

    private static ulong ReadJsonUInt64(JsonElement element, string context)
    {
        if (element.ValueKind != JsonValueKind.Number || !element.TryGetUInt64(out var value))
        {
            throw new JsonException($"{context} must be an unsigned integer.");
        }

        return value;
    }

    private static string NormalizeSoraFsStorageClass(ToriiSoraFsStorageClass? storageClass)
    {
        if (storageClass is null)
        {
            throw new ArgumentNullException(nameof(storageClass));
        }

        var normalized = NormalizeExactValue(storageClass.Type, nameof(storageClass.Type)).ToLowerInvariant();
        return normalized switch
        {
            "hot" => "Hot",
            "warm" => "Warm",
            "cold" => "Cold",
            _ => throw new ArgumentException("SoraFS storage class must be Hot, Warm, or Cold.", nameof(storageClass)),
        };
    }

    private static uint RequireSoraFsUnsigned(uint? value, string paramName, bool allowZero)
    {
        if (value is null)
        {
            throw new ArgumentException("Value must be provided.", paramName);
        }

        if (!allowZero && value.Value == 0)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be positive.");
        }

        return value.Value;
    }

    private static ulong RequireSoraFsUnsigned(ulong? value, string paramName, bool allowZero)
    {
        if (value is null)
        {
            throw new ArgumentException("Value must be provided.", paramName);
        }

        if (!allowZero && value.Value == 0)
        {
            throw new ArgumentOutOfRangeException(paramName, "Value must be positive.");
        }

        return value.Value;
    }

    private static string NormalizeSoraFsDigestHex(string? value, string paramName)
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

    private static string NormalizeNonzeroSoraFsDigestHex(string? value, string paramName)
    {
        var normalized = NormalizeSoraFsDigestHex(value, paramName);
        if (normalized.All(character => character == '0'))
        {
            throw new ArgumentException("Value must not be the all-zero digest.", paramName);
        }
        return normalized;
    }

    private static string NormalizeRequiredBase64(string? value, string paramName)
    {
        var normalized = NormalizeExactValue(value, paramName);

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(normalized);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("Value must be base64 encoded.", paramName, exception);
        }

        if (bytes.Length == 0)
        {
            throw new ArgumentException("Value must be a non-empty base64 payload.", paramName);
        }

        var canonical = Convert.ToBase64String(bytes);
        if (!string.Equals(canonical, normalized, StringComparison.Ordinal))
        {
            throw new ArgumentException("Value must be canonical base64 text.", paramName);
        }

        return canonical;
    }

    private static string NormalizeBoundedRequiredBase64(
        string? value,
        string paramName,
        int maximumBytes,
        int maximumBase64Chars)
    {
        if (value is not null && value.Length > maximumBase64Chars)
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                $"Value must encode at most {maximumBytes} bytes.");
        }
        var canonical = NormalizeRequiredBase64(value, paramName);
        if (Convert.FromBase64String(canonical).Length > maximumBytes)
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                $"Value must encode at most {maximumBytes} bytes.");
        }
        return canonical;
    }

    private static bool IsHex(string value)
    {
        foreach (var c in value)
        {
            var digit =
                c is >= '0' and <= '9'
                || c is >= 'a' and <= 'f'
                || c is >= 'A' and <= 'F';
            if (!digit)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsLowercaseHex(string value)
    {
        foreach (var c in value)
        {
            var digit = c is >= '0' and <= '9' || c is >= 'a' and <= 'f';
            if (!digit)
            {
                return false;
            }
        }

        return true;
    }

    private static string NormalizeExactValue(string? value, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", paramName);
        }

        if (value.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Value must not contain whitespace.", paramName);
        }

        if (value.Any(char.IsControl))
        {
            throw new ArgumentException("Value must not contain control characters.", paramName);
        }

        return value;
    }

    private static string? NormalizeOptionalExactValue(string? value, string paramName)
    {
        return value is null ? null : NormalizeExactValue(value, paramName);
    }

    private static string? NormalizeOptionalExactHexPrefix(string? value, string paramName)
    {
        if (value is null)
        {
            return null;
        }

        var exact = NormalizeExactValue(value, paramName);
        if (exact.Length > 64 || !exact.All(static character => Uri.IsHexDigit(character)))
        {
            throw new ArgumentException("Value must be a hexadecimal prefix up to 32 bytes.", paramName);
        }

        return exact.ToLowerInvariant();
    }

    private static string[]? NormalizeOptionalExactPathList(IReadOnlyList<string>? values, string paramName)
    {
        if (values is null)
        {
            return null;
        }

        if (values.Count == 0)
        {
            throw new ArgumentException("Value list cannot be empty.", paramName);
        }

        var normalized = new string[values.Count];
        for (var index = 0; index < values.Count; index++)
        {
            normalized[index] = NormalizeExactValue(values[index], $"{paramName}[{index}]");
        }

        return normalized;
    }

    private static IReadOnlyList<string> NormalizeExactStringList(
        IReadOnlyList<string>? values,
        string paramName,
        bool allowEmpty)
    {
        if (values is null)
        {
            throw new ArgumentException("Value list cannot be null.", paramName);
        }
        if (!allowEmpty && values.Count == 0)
        {
            throw new ArgumentException("Value list must not be empty.", paramName);
        }

        var normalized = new string[values.Count];
        for (var index = 0; index < values.Count; index++)
        {
            normalized[index] = NormalizeExactValue(values[index], $"{paramName}[{index}]");
        }

        return normalized;
    }

    private static IReadOnlyList<string> NormalizeAccountIdList(
        IReadOnlyList<string>? values,
        string paramName,
        bool allowEmpty)
    {
        if (values is null)
        {
            throw new ArgumentException("Value list cannot be null.", paramName);
        }
        if (!allowEmpty && values.Count == 0)
        {
            throw new ArgumentException("Value list must not be empty.", paramName);
        }

        var normalized = new string[values.Count];
        for (var index = 0; index < values.Count; index++)
        {
            normalized[index] = ToriiAccountFaucetPow.RequireExactAccountId(
                values[index],
                $"{paramName}[{index}]");
        }

        return normalized;
    }

    private static string? NormalizeOptionalExactSizedHex(
        string? value,
        string paramName,
        int expectedBytes)
    {
        if (value is null)
        {
            return null;
        }

        var exact = NormalizeExactValue(value, paramName);
        if (exact.Length != expectedBytes * 2 || !exact.All(Uri.IsHexDigit))
        {
            throw new ArgumentException(
                $"Value must be a {expectedBytes}-byte hex string.",
                paramName);
        }

        return exact.ToLowerInvariant();
    }

    private static string NormalizeExactSizedHex(
        string? value,
        string paramName,
        int expectedBytes)
    {
        return NormalizeOptionalExactSizedHex(value, paramName, expectedBytes)
            ?? throw new ArgumentException("Value cannot be null or whitespace.", paramName);
    }

    private static string NormalizeVpnExactSizedHex(
        string? value,
        string paramName,
        int expectedBytes)
    {
        var exact = NormalizeExactValue(value, paramName);
        var payload = RemoveOptionalHexPrefix(exact);
        if (payload.Length != expectedBytes * 2 || !payload.All(Uri.IsHexDigit))
        {
            throw new ArgumentException(
                $"Value must be a {expectedBytes}-byte hex string with an optional 0x prefix.",
                paramName);
        }

        return payload.ToLowerInvariant();
    }

    private static string NormalizeOptionalVpnExactSizedHexOrEmpty(
        string? value,
        string paramName,
        int expectedBytes)
    {
        if (value is null || value.Length == 0)
        {
            return string.Empty;
        }

        return NormalizeVpnExactSizedHex(value, paramName, expectedBytes);
    }

    private static string NormalizeVpnExactHex(string? value, string paramName)
    {
        var exact = NormalizeExactValue(value, paramName);
        var payload = RemoveOptionalHexPrefix(exact);
        if (payload.Length == 0 || payload.Length % 2 != 0 || !IsHex(payload))
        {
            throw new ArgumentException(
                "Value must contain a non-empty even number of hexadecimal characters with an optional 0x prefix.",
                paramName);
        }

        return payload.ToLowerInvariant();
    }

    private static string RemoveOptionalHexPrefix(string value)
    {
        return value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value;
    }

    private static string NormalizeOptionalVpnExitClass(string? value, string paramName)
    {
        if (value is null || value.Length == 0)
        {
            return string.Empty;
        }

        return NormalizeExactValue(value, paramName);
    }

    private static string NormalizeSoraFsContentCidArgument(string? value, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", paramName);
        }

        if (value.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Value must not contain whitespace.", paramName);
        }

        if (value.Any(char.IsControl))
        {
            throw new ArgumentException("Value must not contain control characters.", paramName);
        }

        if (value[0] != 'b' || value.Length == 1)
        {
            throw new ArgumentException("Value must be lowercase multibase base32 CID text.", paramName);
        }

        for (var index = 1; index < value.Length; index++)
        {
            var character = value[index];
            if (character is not (>= 'a' and <= 'z') and not (>= '2' and <= '7'))
            {
                throw new ArgumentException("Value must be lowercase multibase base32 CID text.", paramName);
            }
        }

        return value;
    }

    private static string NormalizeExactBase64(string? value, string paramName)
    {
        var exact = NormalizeExactValue(value, paramName);
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(exact);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("Value must be base64 encoded.", paramName, exception);
        }

        if (bytes.Length == 0)
        {
            throw new ArgumentException("Value must be a non-empty base64 payload.", paramName);
        }

        var canonical = Convert.ToBase64String(bytes);
        if (!string.Equals(canonical, exact, StringComparison.Ordinal))
        {
            throw new ArgumentException("Value must be canonical base64 text.", paramName);
        }

        return canonical;
    }

    private static string? NormalizeOptionalExactBase64(string? value, string paramName)
    {
        return value is null ? null : NormalizeExactBase64(value, paramName);
    }

    private static IReadOnlyList<string> NormalizeExactBase64List(
        IReadOnlyList<string>? values,
        string paramName,
        bool allowEmpty)
    {
        if (values is null)
        {
            throw new ArgumentException("Value list cannot be null.", paramName);
        }
        if (!allowEmpty && values.Count == 0)
        {
            throw new ArgumentException("Value list must not be empty.", paramName);
        }

        var normalized = new string[values.Count];
        for (var index = 0; index < values.Count; index++)
        {
            normalized[index] = NormalizeExactBase64(values[index], $"{paramName}[{index}]");
        }

        return normalized;
    }

    private static (string? ContractAddress, string? ContractAlias) NormalizeContractTarget(
        string? contractAddress,
        string? contractAlias,
        string contractAddressParamName,
        string contractAliasParamName,
        bool requireTarget)
    {
        var normalizedAddress = NormalizeOptionalExactValue(contractAddress, contractAddressParamName);
        var normalizedAlias = NormalizeOptionalExactValue(contractAlias, contractAliasParamName);
        if (normalizedAddress is not null && normalizedAlias is not null)
        {
            throw new ArgumentException(
                "Provide exactly one of contract_address or contract_alias.",
                contractAddressParamName);
        }
        if (requireTarget && normalizedAddress is null && normalizedAlias is null)
        {
            throw new ArgumentException(
                "Provide either contract_address or contract_alias.",
                contractAddressParamName);
        }

        return (normalizedAddress, normalizedAlias);
    }

    private static (string? MultisigAccountId, string? MultisigAccountAlias) NormalizeMultisigSelector(
        string? multisigAccountId,
        string? multisigAccountAlias)
    {
        var normalizedAccountId = NormalizeOptionalAccountId(
            multisigAccountId,
            nameof(ToriiMultisigApproveRequest.MultisigAccountId));
        var normalizedAlias = NormalizeOptionalExactValue(
            multisigAccountAlias,
            nameof(ToriiMultisigApproveRequest.MultisigAccountAlias));
        if (normalizedAccountId is not null && normalizedAlias is not null)
        {
            throw new ArgumentException(
                "Provide exactly one of multisig_account_id or multisig_account_alias.",
                nameof(ToriiMultisigApproveRequest.MultisigAccountId));
        }
        if (normalizedAccountId is null && normalizedAlias is null)
        {
            throw new ArgumentException(
                "Provide either multisig_account_id or multisig_account_alias.",
                nameof(ToriiMultisigApproveRequest.MultisigAccountId));
        }

        return (normalizedAccountId, normalizedAlias);
    }

    private static string? NormalizeOptionalAccountId(string? value, string paramName)
    {
        return value is null
            ? null
            : ToriiAccountFaucetPow.RequireExactAccountId(value, paramName);
    }

    private static void ValidateDetachedSigningPair(string? publicKeyHex, string? signatureBase64)
    {
        if ((publicKeyHex is null) != (signatureBase64 is null))
        {
            throw new ArgumentException(
                "Detached signing requires both public_key_hex and signature_b64.",
                publicKeyHex is null ? nameof(ToriiContractCallRequest.PublicKeyHex) : nameof(ToriiContractCallRequest.SignatureBase64));
        }
    }

    private static string NormalizeSourceText(string? value, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", paramName);
        }

        return value;
    }

    private static string? NormalizeOptionalSourceName(string? value, string paramName)
    {
        if (value is null)
        {
            return null;
        }
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", paramName);
        }
        if (value.Any(char.IsControl))
        {
            throw new ArgumentException("Value must not contain control characters.", paramName);
        }

        return value;
    }

    private static ReadOnlyMemory<byte> NormalizeNonEmptyBinaryPayload(
        ReadOnlyMemory<byte> bytes,
        string paramName)
    {
        if (bytes.Length == 0)
        {
            throw new ArgumentException("Binary payload must not be empty.", paramName);
        }

        return bytes;
    }

    private static ReadOnlyMemory<byte> NormalizeVersionedSignedTransactionPayload(
        ReadOnlyMemory<byte> bytes,
        string paramName)
    {
        var normalized = NormalizeNonEmptyBinaryPayload(bytes, paramName);
        if (normalized.Length < 2 || normalized.Span[0] != 1)
        {
            throw new ArgumentException(
                "Signed transaction payload must use the canonical V1 versioned wire.",
                paramName);
        }

        return normalized;
    }

    private static string NormalizeIdentifierPolicyId(string? value, string paramName)
    {
        var exact = NormalizeExactIdentifierValue(value, paramName);
        var separator = exact.IndexOf('#', StringComparison.Ordinal);
        if (separator <= 0 || separator != exact.LastIndexOf('#') || separator == exact.Length - 1)
        {
            throw new ArgumentException("Value must use `kind#rule`.", paramName);
        }

        NormalizeExactIdentifierValue(exact[..separator], $"{paramName}.kind");
        NormalizeExactIdentifierValue(exact[(separator + 1)..], $"{paramName}.rule");
        return exact;
    }

    private static string NormalizeIdentifierCiphertext(string? value, string paramName)
    {
        var exact = NormalizeExactIdentifierValue(value, paramName);
        try
        {
            return IdentifierRequestWire.RequireLowerHex(exact, paramName);
        }
        catch (JsonException exception)
        {
            throw new ArgumentException(exception.Message, paramName, exception);
        }
    }

    private static string NormalizeExactIdentifierValue(string? value, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", paramName);
        }

        if (!string.Equals(value.Trim(), value, StringComparison.Ordinal))
        {
            throw new ArgumentException("Value must not contain surrounding whitespace.", paramName);
        }

        if (value.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Value must not contain whitespace.", paramName);
        }

        if (value.Any(char.IsControl))
        {
            throw new ArgumentException("Value must not contain control characters.", paramName);
        }

        return value;
    }

    private static PipelineTransactionStatus ParsePipelineTransactionStatus(
        JsonElement root,
        string transactionHashHex,
        string requestedScope)
    {
        const string context = "pipeline transaction status response";
        var content = RequireJsonObject(root, context);
        RequireExactJsonFields(content, context, "hash", "status", "scope", "resolved_from");
        var statusElement = RequireJsonObjectProperty(content, "status", $"{context}.status");
        var statusFields = statusElement.TryGetProperty("block_height", out _)
            ? new[] { "kind", "block_height" }
            : new[] { "kind" };
        RequireExactJsonFields(statusElement, $"{context}.status", statusFields);
        var rawKind = ReadPipelineStatusKind(statusElement, $"{context}.status");
        var state = ParsePipelineTransactionState(rawKind);
        var hashHex = NormalizePipelineResponseTransactionHashHex(
            RequireJsonStringProperty(content, "hash", $"{context}.hash"),
            $"{context}.hash");
        if (!string.Equals(hashHex, transactionHashHex, StringComparison.Ordinal))
        {
            throw new JsonException($"{context}.hash does not match the requested transaction hash.");
        }
        var blockHeight = statusElement.TryGetProperty("block_height", out _)
            ? ValidatePositiveJsonUInt64Property(
                statusElement,
                "block_height",
                $"{context}.status.block_height")
            : (ulong?)null;
        var scope = RequireJsonStringProperty(content, "scope", $"{context}.scope");
        if (scope is not ("local" or "global"))
        {
            throw new JsonException($"{context}.scope must be exactly local or global.");
        }
        if (!string.Equals(scope, requestedScope, StringComparison.Ordinal))
        {
            throw new JsonException($"{context}.scope does not match the requested scope.");
        }
        var resolvedFrom = RequireJsonStringProperty(content, "resolved_from", $"{context}.resolved_from");
        if (resolvedFrom is not ("cache" or "queue" or "state"))
        {
            throw new JsonException($"{context}.resolved_from must be cache, queue, or state.");
        }
        if (resolvedFrom == "state"
            && state == PipelineTransactionState.Applied
            && blockHeight is null)
        {
            throw new JsonException(
                $"{context}.status.block_height is required for state-resolved Applied status.");
        }

        return new PipelineTransactionStatus
        {
            HashHex = hashHex,
            RawKind = rawKind,
            State = state,
            BlockHeight = blockHeight,
            Scope = scope,
            ResolvedFrom = resolvedFrom,
        };
    }

    private static void ValidatePipelineTransactionDetailsResponse(JsonElement root, string transactionHashHex)
    {
        const string context = "pipeline transaction details response";
        var record = RequireJsonObject(root, context);
        RequireExactJsonFields(record, context, "hash", "transaction");
        var hash = NormalizePipelineResponseTransactionHashHex(
            RequireJsonStringProperty(record, "hash", $"{context}.hash"),
            $"{context}.hash");
        if (!string.Equals(hash, transactionHashHex, StringComparison.Ordinal))
        {
            throw new JsonException($"{context}.hash does not match the signed query target.");
        }
        _ = RequireJsonObjectProperty(record, "transaction", $"{context}.transaction");
    }

    private static void RequireExactJsonFields(JsonElement element, string context, params string[] expected)
    {
        var expectedFields = expected.ToHashSet(StringComparer.Ordinal);
        var actualFields = element.EnumerateObject()
            .Select(static property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        if (!actualFields.SetEquals(expectedFields))
        {
            throw new JsonException($"{context} contains missing or unsupported fields.");
        }
    }

    private static string ReadPipelineStatusKind(JsonElement statusElement, string context)
    {
        if (statusElement.ValueKind == JsonValueKind.Null)
        {
            throw new JsonException($"{context} must not be null.");
        }

        if (statusElement.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException($"{context} must be an object.");
        }

        var rawKind = RequireJsonStringProperty(statusElement, "kind", $"{context}.kind");
        ValidateExactTokenText(rawKind, $"{context}.kind");
        return rawKind;
    }

    private static string NormalizePipelineResponseTransactionHashHex(string value, string context)
    {
        try
        {
            return NormalizeTransactionHashHex(value);
        }
        catch (ArgumentException error)
        {
            throw new JsonException($"{context}: {error.Message}", error);
        }
    }

    private static PipelineTransactionState ParsePipelineTransactionState(string rawKind)
    {
        return rawKind switch
        {
            "Queued" => PipelineTransactionState.Queued,
            "Approved" => PipelineTransactionState.Approved,
            "Committed" => PipelineTransactionState.Committed,
            "Applied" => PipelineTransactionState.Applied,
            "Rejected" => PipelineTransactionState.Rejected,
            "Expired" => PipelineTransactionState.Expired,
            _ => throw new JsonException(
                "pipeline transaction status response.status.kind is not a supported pipeline status kind."),
        };
    }

    private static string NormalizeTransactionHashHex(string transactionHashHex)
    {
        var exact = NormalizeExactValue(transactionHashHex, nameof(transactionHashHex));
        if (exact.Length != 64
            || !exact.All(static character => character is (>= '0' and <= '9') or (>= 'a' and <= 'f'))
            || exact[^1] is not ('1' or '3' or '5' or '7' or '9' or 'b' or 'd' or 'f'))
        {
            throw new ArgumentException(
                "Transaction hash must match the exact canonical typed form ^[0-9a-f]{63}[13579bdf]$.",
                nameof(transactionHashHex));
        }

        return exact;
    }

    private static string NormalizePipelineScope(string scope)
    {
        var exact = NormalizeExactValue(scope, nameof(scope));
        return exact switch
        {
            "local" or "global" => exact,
            _ => throw new ArgumentException("Pipeline scope must be exactly `local` or `global`.", nameof(scope)),
        };
    }

    private static string NormalizeUaidLiteral(string? raw, string paramName = "raw")
    {
        return ToriiUaidDirectMetadata.RequireCanonicalUaidLiteral(raw, paramName);
    }

    private static Uri NormalizeBaseUri(Uri baseUri)
    {
        if (!baseUri.IsAbsoluteUri)
        {
            throw new ArgumentException("baseUri must be absolute.", nameof(baseUri));
        }

        if (!string.Equals(baseUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(baseUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("baseUri must use http or https.", nameof(baseUri));
        }

        if (!string.IsNullOrEmpty(baseUri.UserInfo))
        {
            throw new ArgumentException("baseUri must not include user information.", nameof(baseUri));
        }

        if (!string.IsNullOrEmpty(baseUri.Query))
        {
            throw new ArgumentException("baseUri must not include a query string.", nameof(baseUri));
        }

        if (!string.IsNullOrEmpty(baseUri.Fragment))
        {
            throw new ArgumentException("baseUri must not include a fragment.", nameof(baseUri));
        }

        return baseUri.AbsoluteUri.Length > 0 && baseUri.AbsoluteUri[^1] == '/'
            ? baseUri
            : new Uri($"{baseUri.AbsoluteUri}/", UriKind.Absolute);
    }
}

internal enum TransactionSubmissionTransportAssurance
{
    OneShotWithoutRedirectsOrRetries,
}
