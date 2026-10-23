// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.client

import org.hyperledger.iroha.sdk.client.transport.HttpTransportScope

import java.math.BigInteger
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.Base64
import java.util.Collections
import java.util.LinkedHashMap
import java.util.Locale
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.crypto.BlsNormalPublicKeyAdmission
import org.hyperledger.iroha.sdk.core.util.HashLiteral

/** Authentication class required by an atomic-private-settlement Torii operation. */
enum class AtomicPrivateSettlementAuthV1 {
    /** Exact sponsor account request signature. */
    SPONSOR,

    /** Exact validator or auditor identity request signature. */
    ROLE_IDENTITY,

    /** Public redacted query with no identity material. */
    PUBLIC,
}

/**
 * Closed V1 request catalog for atomic private settlement.
 *
 * The request body is constructed by the native Rust wallet/coordinator. Mobile SDKs route and
 * authenticate the exact prepared object, but never receive a proof witness or capsule plaintext.
 */
enum class AtomicPrivateSettlementOperationV1(
    @JvmField val path: String,
    @JvmField val auth: AtomicPrivateSettlementAuthV1,
    internal val topLevelFields: Set<String>,
    internal val maximumRequestBytes: Int,
) {
    /** Persist provisional encrypted material and obtain one availability share. */
    AVAILABILITY_SHARE(
        "/v1/nexus/private-settlements/legs/availability-shares",
        AtomicPrivateSettlementAuthV1.SPONSOR,
        setOf("material"),
        32 * 1024 * 1024,
    ),

    /** Ask one exact four-member committee validator for a Prepare vote. */
    PREPARE_VOTE(
        "/v1/nexus/private-settlements/phases/prepare-votes",
        AtomicPrivateSettlementAuthV1.SPONSOR,
        setOf("manifest", "payload_digest"),
        8 * 1024 * 1024,
    ),

    /** Ask one exact four-member committee validator for a Commit vote. */
    COMMIT_VOTE(
        "/v1/nexus/private-settlements/phases/commit-votes",
        AtomicPrivateSettlementAuthV1.SPONSOR,
        setOf("payload_digest", "barrier"),
        8 * 1024 * 1024,
    ),

    /** Persist an aggregate Prepare or Commit certificate on one participant node. */
    PHASE_CERTIFICATE(
        "/v1/nexus/private-settlements/phases/certificates",
        AtomicPrivateSettlementAuthV1.SPONSOR,
        setOf("manifest", "payload_digest", "certificate"),
        8 * 1024 * 1024,
    ),

    /** Promote one availability-certified encrypted leg. */
    LEG_UPLOAD(
        "/v1/nexus/private-settlements/legs",
        AtomicPrivateSettlementAuthV1.SPONSOR,
        setOf("manifest", "audit_policy", "committee_authority", "payload"),
        32 * 1024 * 1024,
    ),

    /** Fetch one restricted capsule using the exact current governed audit policy. */
    AUDITOR_CAPSULE(
        "/v1/nexus/private-settlements/legs/{payload_digest}/audit-capsule",
        AtomicPrivateSettlementAuthV1.ROLE_IDENTITY,
        setOf("audit_policy"),
        1024 * 1024,
    ),

    /** Submit one purpose-separated governed auditor approval. */
    AUDIT_APPROVAL(
        "/v1/nexus/private-settlements/legs/{payload_digest}/audit-approvals",
        AtomicPrivateSettlementAuthV1.ROLE_IDENTITY,
        setOf("audit_policy", "approval"),
        2 * 1024 * 1024,
    ),

    /**
     * Submit one sponsor-signed exact Prepare-lock registration, finalization, or abort carrier.
     */
    BUNDLE_SUBMIT(
        "/v1/nexus/private-settlements/bundles",
        AtomicPrivateSettlementAuthV1.SPONSOR,
        setOf("transaction"),
        8 * 1024 * 1024,
    ),
}

/** Immutable 32-byte Iroha hash identity used in settlement paths and response binding. */
class AtomicPrivateSettlementIdentifierV1 private constructor(bytes: ByteArray) {
    private val value: ByteArray = bytes.copyOf()

    init {
        require(value.size == HASH_BYTES) { "settlement identifier must contain exactly 32 bytes" }
        require(value[value.lastIndex].toInt() and 1 == 1) {
            "settlement identifier must satisfy the Iroha hash marker invariant"
        }
    }

    /** Lowercase raw hexadecimal path component accepted by Torii. */
    fun pathComponent(): String = value.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    /** Canonical Norito JSON hash literal used in response objects. */
    fun jsonLiteral(): String = HashLiteral.canonicalize(value)

    /** Defensive copy of the exact 32-byte identity. */
    fun bytes(): ByteArray = value.copyOf()

    override fun equals(other: Any?): Boolean =
        this === other || other is AtomicPrivateSettlementIdentifierV1 && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = pathComponent()

    companion object {
        private const val HASH_BYTES = 32
        private val RAW_HEX = Regex("^[0-9A-Fa-f]{64}$")

        /** Validate and copy an exact marked Iroha hash. */
        @JvmStatic
        fun fromBytes(bytes: ByteArray): AtomicPrivateSettlementIdentifierV1 =
            AtomicPrivateSettlementIdentifierV1(bytes)

        /** Parse either a raw 64-digit hash or one canonical Norito JSON hash literal. */
        @JvmStatic
        fun parse(value: String): AtomicPrivateSettlementIdentifierV1 {
            require(value == value.trim() && value.isNotEmpty()) {
                "settlement identifier must be exact and non-empty"
            }
            if (RAW_HEX.matches(value)) {
                val decoded = ByteArray(HASH_BYTES)
                decoded.indices.forEach { index ->
                    decoded[index] = value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
                }
                return AtomicPrivateSettlementIdentifierV1(decoded)
            }
            val decoded = HashLiteral.decode(value)
            require(HashLiteral.canonicalize(decoded) == value) {
                "settlement identifier must use the canonical Norito JSON hash literal"
            }
            return AtomicPrivateSettlementIdentifierV1(decoded)
        }
    }
}

/**
 * Bounded, operation-tagged request body produced by the native settlement coordinator.
 *
 * [close] erases the SDK copy. Rendering never includes proof, capsule, carrier, or signature
 * bytes.
 */
class AtomicPrivateSettlementPreparedRequestV1 private constructor(
    @JvmField val operation: AtomicPrivateSettlementOperationV1,
    canonicalJson: ByteArray,
) : AutoCloseable {
    private val body: ByteArray = canonicalJson.copyOf()
    private var closed: Boolean = false

    /** Obtain a defensive body copy for an exact one-shot transport request. */
    fun bytes(): ByteArray = synchronized(this) {
        check(!closed) { "atomic private settlement request is closed" }
        body.copyOf()
    }

    override fun close() = synchronized(this) {
        if (!closed) {
            body.fill(0)
            closed = true
        }
    }

    override fun toString(): String =
        "AtomicPrivateSettlementPreparedRequestV1(operation=$operation, body=[REDACTED])"

    companion object {
        /**
         * Validate one native-prepared JSON object and bind it to a single Torii operation.
         *
         * Duplicate keys, malformed UTF-8, unexpected top-level fields, excessive nesting, and
         * operation/body substitution fail before request signing.
         */
        @JvmStatic
        fun fromNativePreparedJson(
            operation: AtomicPrivateSettlementOperationV1,
            json: ByteArray,
        ): AtomicPrivateSettlementPreparedRequestV1 {
            require(json.isNotEmpty()) { "atomic private settlement request must not be empty" }
            require(json.size <= operation.maximumRequestBytes) {
                "atomic private settlement ${operation.name} request exceeds " +
                    "${operation.maximumRequestBytes} bytes"
            }
            val parsed = parseExactJsonObject(json, "atomic private settlement request")
            require(parsed.keys == operation.topLevelFields) {
                "atomic private settlement ${operation.name} request has the wrong top-level fields"
            }
            val canonical = JsonEncoder.encode(parsed).toByteArray(StandardCharsets.UTF_8)
            require(canonical.size <= operation.maximumRequestBytes) {
                "canonical atomic private settlement request exceeds the operation limit"
            }
            return AtomicPrivateSettlementPreparedRequestV1(operation, canonical)
        }
    }
}

/**
 * Bounded exact JSON response from a settlement route.
 *
 * Restricted proof and encrypted-capsule responses remain opaque. Callers may pass [bytes] to the
 * native wallet/auditor worker; this class never parses or renders secret-bearing inner material.
 */
class AtomicPrivateSettlementJsonResponseV1 internal constructor(
    private val route: String,
    responseBytes: ByteArray,
) : AutoCloseable {
    private val body: ByteArray = responseBytes.copyOf()
    private var closed: Boolean = false

    /** Defensive copy suitable for a native decoder. */
    fun bytes(): ByteArray = synchronized(this) {
        check(!closed) { "atomic private settlement response is closed" }
        body.copyOf()
    }

    override fun close() = synchronized(this) {
        if (!closed) {
            body.fill(0)
            closed = true
        }
    }

    override fun toString(): String =
        "AtomicPrivateSettlementJsonResponseV1(route=$route, body=[REDACTED])"
}

/** Exact-route V1 client for prepared-leg, audit, coordination, and redacted query workflows. */
class AtomicPrivateSettlementToriiClientV1 private constructor(builder: Builder) : AutoCloseable {
    /** Cancels this client's calls; an injected executor remains application-owned. */
    override fun close() { executor.close() }

    private data class AuditApprovalRequestContext(
        val networkId: String,
        val bundleId: String,
        val legOrdinal: BigInteger,
        val dataspaceId: BigInteger,
        val expiryHeight: BigInteger,
    )

    private sealed class RestrictedResponseVerification {
        abstract val payloadDigest: AtomicPrivateSettlementIdentifierV1

        data class CommitteeProof(
            override val payloadDigest: AtomicPrivateSettlementIdentifierV1,
        ) : RestrictedResponseVerification()

        data class AuditorCapsule(
            override val payloadDigest: AtomicPrivateSettlementIdentifierV1,
            val requestJson: ByteArray,
            val auditorPublicKey: String,
        ) : RestrictedResponseVerification()

        data class AuditApproval(
            override val payloadDigest: AtomicPrivateSettlementIdentifierV1,
            val requestJson: ByteArray,
            val auditorPublicKey: String,
        ) : RestrictedResponseVerification()
    }

    private val executor: HttpTransportExecutor =
        HttpTransportScope.create(builder.executor)
    private val baseUri: URI = requireBaseUri(builder.baseUri)
    private val allowLocalDevelopmentHttp: Boolean = builder.allowLocalDevelopmentHttp
    private val localSigningContext: LocalSigningContext = checkNotNull(builder.localSigningContext) {
        "localSigningContext must be configured before building a settlement client"
    }
    private val responseVerifier: AtomicPrivateSettlementResponseVerifierV1? =
        builder.responseVerifier
    private val timeout: Duration? = builder.timeout
    private val defaultHeaders: Map<String, String> =
        Collections.unmodifiableMap(LinkedHashMap(builder.defaultHeaders))

    init {
        requireSafeDefaultHeaders(defaultHeaders)
    }

    /** Request one durable availability share with exact sponsor authentication. */
    fun requestAvailabilityShare(
        request: AtomicPrivateSettlementPreparedRequestV1,
        sponsorAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> =
        executeSponsorMutation(request, AtomicPrivateSettlementOperationV1.AVAILABILITY_SHARE, sponsorAuth)

    /** Request one independently verified Prepare vote with exact sponsor authentication. */
    fun requestPrepareVote(
        request: AtomicPrivateSettlementPreparedRequestV1,
        sponsorAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> =
        executeSponsorMutation(request, AtomicPrivateSettlementOperationV1.PREPARE_VOTE, sponsorAuth)

    /** Request one complete-barrier Commit vote with exact sponsor authentication. */
    fun requestCommitVote(
        request: AtomicPrivateSettlementPreparedRequestV1,
        sponsorAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> =
        executeSponsorMutation(request, AtomicPrivateSettlementOperationV1.COMMIT_VOTE, sponsorAuth)

    /** Persist an aggregate Prepare or Commit certificate on one participant node. */
    fun persistPhaseCertificate(
        request: AtomicPrivateSettlementPreparedRequestV1,
        sponsorAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> =
        executeSponsorMutation(request, AtomicPrivateSettlementOperationV1.PHASE_CERTIFICATE, sponsorAuth)

    /** Promote one complete availability-certified encrypted leg. */
    fun uploadLeg(
        request: AtomicPrivateSettlementPreparedRequestV1,
        sponsorAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> =
        executeSponsorMutation(request, AtomicPrivateSettlementOperationV1.LEG_UPLOAD, sponsorAuth)

    /** Submit one purpose-separated approval as the exact governed auditor identity. */
    fun submitAuditApproval(
        payloadDigest: AtomicPrivateSettlementIdentifierV1,
        request: AtomicPrivateSettlementPreparedRequestV1,
        auditorSigningContext: OperatorSigningContext,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> {
        require(auditorSigningContext.networkId() == localSigningContext.networkId()) {
            "auditor signing context must use the settlement client's exact network"
        }
        requireOperation(request, AtomicPrivateSettlementOperationV1.AUDIT_APPROVAL)
        val path = operationPath(request.operation, payloadDigest)
        val body = request.bytes()
        val approvalContext = auditApprovalRequestContext(body)
        require(approvalContext.networkId == localSigningContext.networkId().literal) {
            "prepared settlement approval must use the settlement client's exact network"
        }
        return executeMutation(
            path,
            body,
            identityHeaders = { target, body ->
                OperatorRequestSigner.buildHeaders(
                    auditorSigningContext,
                    "POST",
                    target,
                    body,
                )
            },
            expectedIdentifier = payloadDigest,
            expectedIdentifierField = "payload_digest",
            approvalContext = approvalContext,
            restrictedVerification = RestrictedResponseVerification.AuditApproval(
                payloadDigest,
                body.copyOf(),
                auditorSigningContext.publicKey(),
            ),
        )
    }

    /**
     * Submit one sponsor-signed Prepare-lock registration, finalization, or abort carrier.
     */
    fun submitBundle(
        request: AtomicPrivateSettlementPreparedRequestV1,
        sponsorAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> =
        executeSponsorMutation(request, AtomicPrivateSettlementOperationV1.BUNDLE_SUBMIT, sponsorAuth)

    /** Read one sponsor-authenticated, redacted local leg lifecycle. */
    fun getLegStatus(
        payloadDigest: AtomicPrivateSettlementIdentifierV1,
        sponsorAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> =
        executeGet(
            "/v1/nexus/private-settlements/legs/${payloadDigest.pathComponent()}/status",
            RESPONSE_SMALL_MAX_BYTES,
            identityHeaders = { target, body -> sponsorHeaders("GET", target, body, sponsorAuth) },
            expectedIdentifier = payloadDigest,
            expectedIdentifierField = "payload_digest",
        )

    /** Recover the persisted Prepare and Commit certificates for one local leg. */
    fun getPhaseCertificates(
        payloadDigest: AtomicPrivateSettlementIdentifierV1,
        sponsorAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> =
        executeGet(
            "/v1/nexus/private-settlements/legs/${payloadDigest.pathComponent()}/phase-certificates",
            RESPONSE_SMALL_MAX_BYTES,
            identityHeaders = { target, body -> sponsorHeaders("GET", target, body, sponsorAuth) },
            expectedIdentifier = payloadDigest,
            expectedIdentifierField = "payload_digest",
        )

    /** Fetch proof and opaque delta material as one exact participant validator. */
    fun getCommitteeProof(
        payloadDigest: AtomicPrivateSettlementIdentifierV1,
        validatorSigningContext: OperatorSigningContext,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> {
        require(validatorSigningContext.networkId() == localSigningContext.networkId()) {
            "validator signing context must use the settlement client's exact network"
        }
        return executeGet(
            "/v1/nexus/private-settlements/legs/${payloadDigest.pathComponent()}/committee-proof",
            RESPONSE_RESTRICTED_MAX_BYTES,
            identityHeaders = { target, body ->
                OperatorRequestSigner.buildHeaders(
                    validatorSigningContext,
                    "GET",
                    target,
                    body,
                )
            },
            expectedIdentifier = payloadDigest,
            expectedIdentifierField = null,
            restrictedVerification = RestrictedResponseVerification.CommitteeProof(payloadDigest),
        )
    }

    /** Fetch one padded encrypted capsule as one exact governed local auditor. */
    fun getAuditorCapsule(
        payloadDigest: AtomicPrivateSettlementIdentifierV1,
        request: AtomicPrivateSettlementPreparedRequestV1,
        auditorSigningContext: OperatorSigningContext,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> {
        require(auditorSigningContext.networkId() == localSigningContext.networkId()) {
            "auditor signing context must use the settlement client's exact network"
        }
        requireOperation(request, AtomicPrivateSettlementOperationV1.AUDITOR_CAPSULE)
        val path = operationPath(request.operation, payloadDigest)
        val body = request.bytes()
        return executeMutation(
            path,
            body,
            identityHeaders = { target, signedBody ->
                OperatorRequestSigner.buildHeaders(
                    auditorSigningContext,
                    "POST",
                    target,
                    signedBody,
                )
            },
            expectedIdentifier = payloadDigest,
            expectedIdentifierField = null,
            restrictedVerification = RestrictedResponseVerification.AuditorCapsule(
                payloadDigest,
                body.copyOf(),
                auditorSigningContext.publicKey(),
            ),
        )
    }

    /** Read the public allowlisted lifecycle for one bundle. */
    fun getBundleStatus(
        bundleId: AtomicPrivateSettlementIdentifierV1,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> =
        executeGet(
            "/v1/nexus/private-settlements/bundles/${bundleId.pathComponent()}",
            RESPONSE_PUBLIC_BUNDLE_MAX_BYTES,
            identityHeaders = null,
            expectedIdentifier = bundleId,
            expectedIdentifierField = null,
        )

    /**
     * Read a public terminal receipt for one bundle.
     *
     * Pending means that this node has no public terminal result. It does not establish that the
     * bundle is locally known; use [getBundleStatus] for the local lifecycle.
     */
    fun getBundleReceipt(
        bundleId: AtomicPrivateSettlementIdentifierV1,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> =
        executeGet(
            "/v1/nexus/private-settlements/bundles/${bundleId.pathComponent()}/receipt",
            RESPONSE_RESTRICTED_MAX_BYTES,
            identityHeaders = null,
            expectedIdentifier = bundleId,
            expectedIdentifierField = null,
        )

    private fun executeSponsorMutation(
        request: AtomicPrivateSettlementPreparedRequestV1,
        expectedOperation: AtomicPrivateSettlementOperationV1,
        sponsorAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> {
        requireOperation(request, expectedOperation)
        val body = request.bytes()
        return executeMutation(
            expectedOperation.path,
            body,
            identityHeaders = { target, signedBody ->
                sponsorHeaders("POST", target, signedBody, sponsorAuth)
            },
            expectedIdentifier = null,
            expectedIdentifierField = null,
        )
    }

    private fun executeMutation(
        path: String,
        body: ByteArray,
        identityHeaders: (URI, ByteArray) -> Map<String, String>,
        expectedIdentifier: AtomicPrivateSettlementIdentifierV1?,
        expectedIdentifierField: String?,
        approvalContext: AuditApprovalRequestContext? = null,
        restrictedVerification: RestrictedResponseVerification? = null,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> {
        val target = resolvePath(path)
        val headers = requestHeaders(includeContentType = true)
        headers.putAll(identityHeaders(target, body))
        val request = buildRequest("POST", target, body, headers, RESPONSE_RESTRICTED_MAX_BYTES)
        return execute(
            request,
            path,
            RESPONSE_RESTRICTED_MAX_BYTES,
            expectedIdentifier,
            expectedIdentifierField,
            approvalContext,
            restrictedVerification,
        )
    }

    private fun executeGet(
        path: String,
        maximumResponseBytes: Int,
        identityHeaders: ((URI, ByteArray) -> Map<String, String>)?,
        expectedIdentifier: AtomicPrivateSettlementIdentifierV1?,
        expectedIdentifierField: String?,
        restrictedVerification: RestrictedResponseVerification? = null,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> {
        val target = resolvePath(path)
        val body = ByteArray(0)
        val headers = requestHeaders(includeContentType = false)
        if (identityHeaders != null) headers.putAll(identityHeaders(target, body))
        val request = buildRequest("GET", target, body, headers, maximumResponseBytes)
        return execute(
            request,
            path,
            maximumResponseBytes,
            expectedIdentifier,
            expectedIdentifierField,
            restrictedVerification = restrictedVerification,
        )
    }

    private fun execute(
        request: TransportRequest,
        route: String,
        maximumResponseBytes: Int,
        expectedIdentifier: AtomicPrivateSettlementIdentifierV1?,
        expectedIdentifierField: String?,
        approvalContext: AuditApprovalRequestContext? = null,
        restrictedVerification: RestrictedResponseVerification? = null,
    ): CompletableFuture<AtomicPrivateSettlementJsonResponseV1> {
        val result = CompletableFuture<AtomicPrivateSettlementJsonResponseV1>()
        if (restrictedVerification != null) {
            try {
                checkNotNull(responseVerifier) {
                    "restricted private settlement response verifier is not configured"
                }.requireAvailable()
            } catch (_: RuntimeException) {
                result.completeExceptionally(
                    AtomicPrivateSettlementToriiExceptionV1(INVALID_RESPONSE_MESSAGE),
                )
                return result
            }
        }
        val execution = try {
            executor.execute(request)
        } catch (error: RuntimeException) {
            result.completeExceptionally(
                AtomicPrivateSettlementToriiExceptionV1("atomic private settlement request failed", error),
            )
            return result
        }
        execution.whenComplete { response, throwable ->
            if (throwable != null) {
                result.completeExceptionally(
                    AtomicPrivateSettlementToriiExceptionV1(
                        "atomic private settlement request failed",
                        unwrapCompletion(throwable),
                    ),
                )
                return@whenComplete
            }
            try {
                result.complete(
                    validateResponse(
                        request,
                        checkNotNull(response),
                        route,
                        maximumResponseBytes,
                        expectedIdentifier,
                        expectedIdentifierField,
                        approvalContext,
                        restrictedVerification,
                    ),
                )
            } catch (error: RuntimeException) {
                result.completeExceptionally(
                    if (error is AtomicPrivateSettlementToriiExceptionV1 && error.cause == null) {
                        error
                    } else {
                        AtomicPrivateSettlementToriiExceptionV1(
                            INVALID_RESPONSE_MESSAGE,
                        )
                    },
                )
            }
        }
        return result
    }

    private fun validateResponse(
        request: TransportRequest,
        response: TransportResponse,
        route: String,
        maximumResponseBytes: Int,
        expectedIdentifier: AtomicPrivateSettlementIdentifierV1?,
        expectedIdentifierField: String?,
        approvalContext: AuditApprovalRequestContext?,
        restrictedVerification: RestrictedResponseVerification?,
    ): AtomicPrivateSettlementJsonResponseV1 {
        if (
            response.redirected ||
            response.finalUri?.toASCIIString() != request.uri.toASCIIString()
        ) {
            throw AtomicPrivateSettlementToriiExceptionV1(
                "atomic private settlement response must come from the exact request URL without redirects",
            )
        }
        if (response.statusCode !in 200..299) {
            val rejectCode = HttpErrorMessageExtractor.extractRejectCode(
                response.headers,
                "x-iroha-reject-code",
                ByteArray(0),
            )?.takeIf { REJECT_CODE.matches(it) }
            val suffix = if (rejectCode.isNullOrBlank()) "" else "; reject_code=$rejectCode"
            throw AtomicPrivateSettlementToriiExceptionV1(
                "atomic private settlement request failed with HTTP ${response.statusCode}$suffix",
            )
        }
        val expectedStatus = if (route.endsWith("/bundles")) 202 else 200
        if (response.statusCode != expectedStatus) {
            throw AtomicPrivateSettlementToriiExceptionV1(
                "atomic private settlement response status is invalid",
            )
        }
        try {
            val body = response.body
            require(body.isNotEmpty()) { "atomic private settlement response must not be empty" }
            require(body.size <= maximumResponseBytes) {
                "atomic private settlement response exceeds $maximumResponseBytes bytes"
            }
            requireExactJsonContentType(response.headers)
            requireAbsentOrIdentityContentEncoding(response.headers)
            val parsed = parseExactJsonObject(body, "atomic private settlement response")
            validateRouteShape(
                route,
                parsed,
                expectedIdentifier,
                expectedIdentifierField,
                approvalContext,
            )
            verifyRestrictedResponse(restrictedVerification, body)
            val canonical = JsonEncoder.encode(parsed).toByteArray(StandardCharsets.UTF_8)
            return AtomicPrivateSettlementJsonResponseV1(route, canonical)
        } catch (_: RuntimeException) {
            throw AtomicPrivateSettlementToriiExceptionV1(INVALID_RESPONSE_MESSAGE)
        }
    }

    private fun verifyRestrictedResponse(
        verification: RestrictedResponseVerification?,
        exactResponseJson: ByteArray,
    ) {
        if (verification == null) return
        val verifier = checkNotNull(responseVerifier) {
            "restricted private settlement response verifier is not configured"
        }
        val network = localSigningContext.networkId().bytes()
        val payload = verification.payloadDigest.bytes()
        when (verification) {
            is RestrictedResponseVerification.CommitteeProof ->
                verifier.verifyCommitteeProofResponse(
                    exactResponseJson.copyOf(),
                    network,
                    payload,
                )
            is RestrictedResponseVerification.AuditorCapsule ->
                verifier.verifyAuditorCapsuleResponse(
                    exactResponseJson.copyOf(),
                    verification.requestJson.copyOf(),
                    network,
                    payload,
                    verification.auditorPublicKey,
                )
            is RestrictedResponseVerification.AuditApproval ->
                verifier.verifyAuditApprovalResponse(
                    exactResponseJson.copyOf(),
                    verification.requestJson.copyOf(),
                    network,
                    payload,
                    verification.auditorPublicKey,
                )
        }
    }

    private fun validateRouteShape(
        route: String,
        parsed: Map<String, Any?>,
        expectedIdentifier: AtomicPrivateSettlementIdentifierV1?,
        expectedIdentifierField: String?,
        approvalContext: AuditApprovalRequestContext?,
    ) {
        val expectedFields = responseFields(route)
        require(parsed.keys == expectedFields) {
            "atomic private settlement response has unexpected public fields"
        }
        if (expectedIdentifier != null && expectedIdentifierField != null) {
            require(parsed[expectedIdentifierField] == expectedIdentifier.jsonLiteral()) {
                "atomic private settlement response identifier is substituted"
            }
        }
        if (route.endsWith("/phase-certificates")) {
            require(
                parsed["prepare_certificate"] == null ||
                    parsed["prepare_certificate"] is Map<*, *>,
            ) { "settlement Prepare certificate must be null or an opaque object" }
            require(
                parsed["commit_certificate"] == null ||
                    parsed["commit_certificate"] is Map<*, *>,
            ) { "settlement Commit certificate must be null or an opaque object" }
        }
        when {
            route.endsWith("/bundles") -> validateBundleAdmission(parsed)
            route.endsWith("/audit-capsule") -> {
                validateAuditorCapsuleHeight(parsed)
                validateAuditorCapsuleAttestation(parsed, checkNotNull(expectedIdentifier))
            }
            route.endsWith("/audit-approvals") ->
                validateAuditApprovalAcknowledgementAttestation(
                    parsed,
                    checkNotNull(expectedIdentifier),
                    checkNotNull(approvalContext),
                )
            route.endsWith("/receipt") ->
                validateReceiptIdentity(parsed, checkNotNull(expectedIdentifier))
            route.contains("/bundles/") ->
                validateBundleStatusIdentity(parsed, checkNotNull(expectedIdentifier))
        }
    }

    private fun validateBundleAdmission(parsed: Map<String, Any?>) {
        requireCanonicalHashLiteral(parsed["bundle_id"], "settlement bundle admission.bundle_id")
        requireCanonicalHashLiteral(parsed["carrier_id"], "settlement bundle admission.carrier_id")
        val acceptedAtHeight = when (val value = parsed["accepted_at_height"]) {
            is BigInteger -> value
            is Byte -> BigInteger.valueOf(value.toLong())
            is Short -> BigInteger.valueOf(value.toLong())
            is Int -> BigInteger.valueOf(value.toLong())
            is Long -> BigInteger.valueOf(value)
            else -> throw IllegalArgumentException(
                "settlement bundle admission.accepted_at_height must be an integer",
            )
        }
        require(acceptedAtHeight.signum() >= 0 && acceptedAtHeight <= U64_MAX) {
            "settlement bundle admission.accepted_at_height must fit in unsigned 64-bit range"
        }
    }

    private fun validateAuditorCapsuleHeight(parsed: Map<String, Any?>) {
        val authoritativeHeight = when (val value = parsed["authoritative_height"]) {
            is BigInteger -> value
            is Byte -> BigInteger.valueOf(value.toLong())
            is Short -> BigInteger.valueOf(value.toLong())
            is Int -> BigInteger.valueOf(value.toLong())
            is Long -> BigInteger.valueOf(value)
            else -> throw IllegalArgumentException(
                "settlement auditor capsule.authoritative_height must be an integer",
            )
        }
        require(authoritativeHeight.signum() > 0 && authoritativeHeight <= U64_MAX) {
            "settlement auditor capsule.authoritative_height must be a nonzero unsigned 64-bit integer"
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun validateAuditorCapsuleAttestation(
        parsed: Map<String, Any?>,
        expectedPayloadDigest: AtomicPrivateSettlementIdentifierV1,
    ) {
        val attestation = parsed["responder_attestation"]
        require(attestation is Map<*, *> && attestation.keys == setOf("body", "signature")) {
            "settlement auditor capsule responder attestation is invalid"
        }
        val body = attestation["body"]
        val bodyFields = setOf(
            "version",
            "network_id",
            "payload_digest",
            "view_digest",
            "authority_digest",
            "lifecycle_code",
            "authoritative_height",
            "responder",
        )
        require(body is Map<*, *> && body.keys == bodyFields) {
            "settlement auditor capsule attestation body is invalid"
        }
        val typedBody = body as Map<String, Any?>
        fun integer(value: Any?): BigInteger = when (value) {
            is BigInteger -> value
            is Byte -> BigInteger.valueOf(value.toLong())
            is Short -> BigInteger.valueOf(value.toLong())
            is Int -> BigInteger.valueOf(value.toLong())
            is Long -> BigInteger.valueOf(value)
            else -> throw IllegalArgumentException(
                "settlement auditor capsule attestation integer is invalid",
            )
        }
        val lifecycle = parsed["lifecycle"] as? Map<*, *>
        val lifecycleCode = when (lifecycle?.get("status")) {
            "collecting" -> 0
            "audited" -> 1
            "prepared" -> 2
            "commit_certified" -> 3
            "finalized" -> 4
            "aborted" -> 5
            "expired" -> 6
            else -> -1
        }
        require(
            integer(typedBody["version"]) == BigInteger.ONE &&
                integer(typedBody["authoritative_height"]) == integer(parsed["authoritative_height"]) &&
                integer(typedBody["lifecycle_code"]) == BigInteger.valueOf(lifecycleCode.toLong()) &&
                typedBody["network_id"] == localSigningContext.networkId().literal &&
                typedBody["payload_digest"] == expectedPayloadDigest.jsonLiteral() &&
                typedBody["responder"] is String &&
                BlsNormalPublicKeyAdmission.isCanonicalBlsNormalPeerId(typedBody["responder"] as String),
        ) { "settlement auditor capsule responder attestation is invalid" }
        requireCanonicalBlsSignature(
            attestation["signature"],
            "settlement auditor capsule responder attestation.signature",
        )
        for (field in listOf("network_id", "payload_digest", "view_digest", "authority_digest")) {
            requireCanonicalHashLiteral(
                typedBody[field],
                "settlement auditor capsule attestation.$field",
            )
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun validateAuditApprovalAcknowledgementAttestation(
        parsed: Map<String, Any?>,
        expectedPayloadDigest: AtomicPrivateSettlementIdentifierV1,
        approvalContext: AuditApprovalRequestContext,
    ) {
        val attestation = parsed["responder_attestation"]
        require(attestation is Map<*, *> && attestation.keys == setOf("body", "signature")) {
            "settlement approval acknowledgement responder attestation is invalid"
        }
        val body = attestation["body"]
        val bodyFields = setOf(
            "version",
            "network_id",
            "payload_digest",
            "approval_digest",
            "acknowledgement_digest",
            "authority_digest",
            "lifecycle_code",
            "authoritative_height",
            "responder",
        )
        require(body is Map<*, *> && body.keys == bodyFields) {
            "settlement approval acknowledgement attestation body is invalid"
        }
        val typedBody = body as Map<String, Any?>
        fun integer(value: Any?): BigInteger = when (value) {
            is BigInteger -> value
            is Byte -> BigInteger.valueOf(value.toLong())
            is Short -> BigInteger.valueOf(value.toLong())
            is Int -> BigInteger.valueOf(value.toLong())
            is Long -> BigInteger.valueOf(value)
            else -> throw IllegalArgumentException(
                "settlement approval acknowledgement attestation integer is invalid",
            )
        }
        val lifecycle = parsed["lifecycle"] as? Map<*, *>
        val lifecycleCode = when (lifecycle?.get("status")) {
            "collecting" -> 0
            "audited" -> 1
            else -> -1
        }
        val height = integer(parsed["authoritative_height"])
        val collected = integer(parsed["collected"])
        val required = integer(parsed["required"])
        val legOrdinal = integer(parsed["leg_ordinal"])
        val lifecycleIsExact = if (collected < required) lifecycleCode == 0 else lifecycleCode == 1
        require(
            height.signum() > 0 &&
                height <= U64_MAX &&
                height <= approvalContext.expiryHeight &&
                collected > BigInteger.ZERO &&
                required > BigInteger.ZERO &&
                collected <= required &&
                required <= U8_MAX &&
                legOrdinal >= BigInteger.ZERO &&
                legOrdinal < U8_MAX &&
                legOrdinal == approvalContext.legOrdinal &&
                parsed["bundle_id"] is String &&
                parsed["committee_authority"] is Map<*, *> &&
                parsed["newly_recorded"] is Boolean &&
                lifecycleIsExact &&
                integer(typedBody["version"]) == BigInteger.ONE &&
                integer(typedBody["authoritative_height"]) == height &&
                typedBody["network_id"] == localSigningContext.networkId().literal &&
                typedBody["network_id"] == approvalContext.networkId &&
                typedBody["payload_digest"] == expectedPayloadDigest.jsonLiteral() &&
                parsed["payload_digest"] == expectedPayloadDigest.jsonLiteral() &&
                integer(typedBody["lifecycle_code"]) == BigInteger.valueOf(lifecycleCode.toLong()) &&
                typedBody["responder"] is String &&
                BlsNormalPublicKeyAdmission.isCanonicalBlsNormalPeerId(typedBody["responder"] as String),
        ) { "settlement approval acknowledgement responder attestation is invalid" }
        requireCanonicalHashLiteral(
            parsed["bundle_id"],
            "settlement approval acknowledgement.bundle_id",
        )
        require(parsed["bundle_id"] == approvalContext.bundleId) {
            "settlement approval acknowledgement bundle is substituted"
        }
        val authority = parsed["committee_authority"] as Map<*, *>
        val authorityRoute = authority["route"] as? Map<*, *>
        require(authorityRoute != null && integer(authorityRoute["dataspace_id"]) == approvalContext.dataspaceId) {
            "settlement approval acknowledgement authority is substituted"
        }
        requireCanonicalBlsSignature(
            attestation["signature"],
            "settlement approval acknowledgement responder attestation.signature",
        )
        for (field in listOf(
            "network_id",
            "payload_digest",
            "approval_digest",
            "acknowledgement_digest",
            "authority_digest",
        )) {
            requireCanonicalHashLiteral(
                typedBody[field],
                "settlement approval acknowledgement attestation.$field",
            )
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun auditApprovalRequestContext(bodyBytes: ByteArray): AuditApprovalRequestContext {
        val request = parseExactJsonObject(bodyBytes, "prepared settlement audit approval")
        require(
            request.keys == setOf("audit_policy", "approval") &&
                request["audit_policy"] is Map<*, *>,
        ) {
            "prepared settlement audit approval has invalid fields"
        }
        val approval = request["approval"]
        require(approval is Map<*, *> && approval.keys == setOf("body", "signature")) {
            "prepared settlement audit approval is invalid"
        }
        require(approval["signature"] != null) {
            "prepared settlement audit approval signature is missing"
        }
        val body = approval["body"]
        val expectedFields = setOf(
            "version",
            "network_id",
            "bundle_id",
            "leg_ordinal",
            "dataspace_id",
            "auditor_id",
            "audit_policy_digest",
            "audit_key_epoch",
            "proof_digest",
            "capsule_digest",
            "delta_digest",
            "old_root",
            "new_root",
            "expiry_height",
        )
        require(body is Map<*, *> && body.keys == expectedFields) {
            "prepared settlement audit approval body is invalid"
        }
        val typedBody = body as Map<String, Any?>
        val networkId = typedBody["network_id"] as? String
            ?: throw IllegalArgumentException("prepared settlement approval network is invalid")
        requireCanonicalHashLiteral(networkId, "prepared settlement approval.network_id")
        val bundleId = typedBody["bundle_id"] as? String
            ?: throw IllegalArgumentException("prepared settlement approval bundle is invalid")
        requireCanonicalHashLiteral(bundleId, "prepared settlement approval.bundle_id")
        val version = integer(typedBody["version"])
        val legOrdinal = integer(typedBody["leg_ordinal"])
        val dataspaceId = integer(typedBody["dataspace_id"])
        val expiryHeight = integer(typedBody["expiry_height"])
        require(version == BigInteger.ONE) { "prepared settlement approval version is invalid" }
        require(legOrdinal >= BigInteger.ZERO && legOrdinal < U8_MAX) {
            "prepared settlement approval leg ordinal is outside 0..=254"
        }
        require(dataspaceId >= BigInteger.ZERO && dataspaceId <= U64_MAX) {
            "prepared settlement approval dataspace is invalid"
        }
        require(expiryHeight > BigInteger.ZERO && expiryHeight <= U64_MAX) {
            "prepared settlement approval expiry is invalid"
        }
        for (field in listOf(
            "audit_policy_digest",
            "proof_digest",
            "capsule_digest",
            "delta_digest",
        )) {
            requireCanonicalHashLiteral(typedBody[field], "prepared settlement approval.$field")
        }
        return AuditApprovalRequestContext(
            networkId,
            bundleId,
            legOrdinal,
            dataspaceId,
            expiryHeight,
        )
    }

    private fun integer(value: Any?): BigInteger = when (value) {
        is BigInteger -> value
        is Byte -> BigInteger.valueOf(value.toLong())
        is Short -> BigInteger.valueOf(value.toLong())
        is Int -> BigInteger.valueOf(value.toLong())
        is Long -> BigInteger.valueOf(value)
        else -> throw IllegalArgumentException("settlement integer is invalid")
    }

    private fun requireCanonicalHashLiteral(value: Any?, field: String) {
        require(value is String) { "$field must be a canonical Iroha hash literal" }
        val parsed = AtomicPrivateSettlementIdentifierV1.parse(value)
        require(parsed.jsonLiteral() == value) { "$field must be a canonical Iroha hash literal" }
    }

    private fun requireCanonicalBlsSignature(value: Any?, field: String) {
        require(value is String && value.isNotEmpty() && value == value.trim()) {
            "$field must be canonical base64"
        }
        val decoded = try {
            Base64.getDecoder().decode(value)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("$field must be canonical base64", error)
        }
        require(decoded.size == BLS_SIGNATURE_BYTES && Base64.getEncoder().encodeToString(decoded) == value) {
            "$field must encode one exact BLS-normal signature"
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun validateBundleStatusIdentity(
        parsed: Map<String, Any?>,
        expected: AtomicPrivateSettlementIdentifierV1,
    ) {
        val manifest = parsed["manifest"] ?: return
        require(manifest is Map<*, *>) { "settlement bundle status manifest must be an object" }
        require((manifest as Map<String, Any?>)["bundle_id"] == expected.jsonLiteral()) {
            "atomic private settlement bundle status is substituted"
        }
    }

    private fun validateReceiptIdentity(
        parsed: Map<String, Any?>,
        expected: AtomicPrivateSettlementIdentifierV1,
    ) {
        val status = parsed["status"]
        require(status in setOf("pending", "finalized", "aborted")) {
            "settlement receipt has an unknown terminal tag"
        }
        val value = parsed["value"]
        require(value is Map<*, *>) { "settlement receipt value must be an object" }
        val bundleId = when (status) {
            "pending" -> {
                require(value.keys == setOf("bundle_id")) {
                    "pending settlement receipt has unexpected public fields"
                }
                value["bundle_id"]
            }
            "finalized" -> {
                require(
                    value.keys == setOf(
                        "version",
                        "manifest",
                        "authority_catalog",
                        "legs",
                        "finalized_height",
                    ),
                ) { "finalized settlement receipt has unexpected public fields" }
                val manifest = value["manifest"]
                require(manifest is Map<*, *>) {
                    "finalized settlement receipt manifest must be an object"
                }
                manifest["bundle_id"]
            }
            else -> value["bundle_id"]
        }
        require(bundleId == expected.jsonLiteral()) {
            "atomic private settlement receipt is substituted"
        }
    }

    private fun sponsorHeaders(
        method: String,
        target: URI,
        body: ByteArray,
        sponsorAuth: ToriiCanonicalRequestAuth,
    ): Map<String, String> = sponsorAuth.headers(localSigningContext.networkId(), method, target, body)

    private fun buildRequest(
        method: String,
        target: URI,
        body: ByteArray,
        headers: Map<String, String>,
        maximumResponseBytes: Int,
    ): TransportRequest {
        TransportSecurity.requireHttpRequestAllowed(
            "AtomicPrivateSettlementToriiClientV1",
            baseUri,
            target,
            headers,
            if (body.isEmpty()) null else body,
            allowLocalDevelopmentHttp = allowLocalDevelopmentHttp,
        )
        val builder = TransportRequest.builder()
            .setUri(target)
            .setMethod(method)
            .setTimeout(timeout)
            .setMaximumResponseBytes(maximumResponseBytes.toLong())
        if (body.isNotEmpty()) builder.setBody(body)
        headers.forEach { (name, value) -> builder.addHeader(name, value) }
        return builder.build()
    }

    private fun requestHeaders(includeContentType: Boolean): LinkedHashMap<String, String> {
        val headers = LinkedHashMap(defaultHeaders)
        headers["Accept"] = JSON_MEDIA_TYPE
        headers["Accept-Encoding"] = "identity"
        headers["Cache-Control"] = "no-store"
        headers["Pragma"] = "no-cache"
        if (includeContentType) headers["Content-Type"] = JSON_MEDIA_TYPE
        return headers
    }

    private fun resolvePath(path: String): URI {
        val normalized = path.removePrefix("/")
        val base = baseUri.toString()
        return URI.create(if (base.endsWith('/')) base + normalized else "$base/$normalized")
    }

    /** Builder for an exact-network settlement client. */
    class Builder internal constructor() {
        internal var executor: HttpTransportExecutor? = null
        internal var baseUri: URI = URI.create("http://localhost:8080")
        internal var allowLocalDevelopmentHttp: Boolean = false
        internal var localSigningContext: LocalSigningContext? = null
        internal var responseVerifier: AtomicPrivateSettlementResponseVerifierV1? =
            AtomicPrivateSettlementNativeResponseVerifierV1
        internal var timeout: Duration? = Duration.ofSeconds(30)
        internal val defaultHeaders = LinkedHashMap<String, String>()

        /** Override the HTTP executor. */
        fun executor(executor: HttpTransportExecutor): Builder = apply { this.executor = executor }

        /** Set the exact Torii base, including any deployment path prefix. */
        fun baseUri(baseUri: URI): Builder = apply { this.baseUri = baseUri }

        /**
         * Allow credentialed HTTP to the same loopback or private IPv4 origin; disabled by default.
         * See [ClientConfig.Builder.setAllowLocalDevelopmentHttp] for the allowed address ranges.
         */
        fun setAllowLocalDevelopmentHttp(allow: Boolean): Builder = apply {
            this.allowLocalDevelopmentHttp = allow
        }

        /** Bind sponsor signatures to one exact genesis-derived network identity. */
        fun localSigningContext(context: LocalSigningContext): Builder = apply {
            this.localSigningContext = context
        }

        /**
         * Set the restricted-response verifier.
         *
         * Passing `null` keeps public routes usable but makes every restricted route fail before
         * dispatch. Production callers should retain the default JNI-backed verifier.
         */
        fun responseVerifier(verifier: AtomicPrivateSettlementResponseVerifierV1?): Builder = apply {
            this.responseVerifier = verifier
        }

        /** Set the one-shot request timeout; `null` delegates to the executor. */
        fun timeout(timeout: Duration?): Builder = apply { this.timeout = timeout }

        /** Add one non-authentication, non-content-negotiation deployment header. */
        fun addHeader(name: String, value: String): Builder = apply { defaultHeaders[name] = value }

        /** Replace non-authentication deployment headers. */
        fun defaultHeaders(headers: Map<String, String>?): Builder = apply {
            defaultHeaders.clear()
            if (headers != null) defaultHeaders.putAll(headers)
        }

        /** Build the exact-route client. */
        fun build(): AtomicPrivateSettlementToriiClientV1 =
            AtomicPrivateSettlementToriiClientV1(this)
    }

    companion object {
        private const val JSON_MEDIA_TYPE = "application/json"
        private const val RESPONSE_SMALL_MAX_BYTES = 1024 * 1024
        private const val RESPONSE_PUBLIC_BUNDLE_MAX_BYTES = 8 * 1024 * 1024
        private const val RESPONSE_RESTRICTED_MAX_BYTES = 32 * 1024 * 1024
        private const val INVALID_RESPONSE_MESSAGE =
            "atomic private settlement response is invalid"
        private val U64_MAX: BigInteger = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)
        private val U8_MAX: BigInteger = BigInteger.valueOf(255)
        private const val BLS_SIGNATURE_BYTES = 96
        private val REJECT_CODE = Regex("^[A-Za-z0-9_.:-]{1,128}$")

        private val FORBIDDEN_DEFAULT_HEADERS = setOf(
            "authorization",
            "x-api-token",
            "x-iroha-witness",
            CanonicalRequestSigner.HEADER_ACCOUNT.lowercase(Locale.ROOT),
            CanonicalRequestSigner.HEADER_SIGNATURE.lowercase(Locale.ROOT),
            CanonicalRequestSigner.HEADER_TIMESTAMP_MS.lowercase(Locale.ROOT),
            CanonicalRequestSigner.HEADER_NONCE.lowercase(Locale.ROOT),
            OperatorRequestSigner.HEADER_PUBLIC_KEY.lowercase(Locale.ROOT),
            OperatorRequestSigner.HEADER_TIMESTAMP_MS.lowercase(Locale.ROOT),
            OperatorRequestSigner.HEADER_NONCE.lowercase(Locale.ROOT),
            OperatorRequestSigner.HEADER_SIGNATURE.lowercase(Locale.ROOT),
            "accept",
            "accept-encoding",
            "content-type",
            "content-length",
            "cache-control",
            "pragma",
            "host",
        )

        /** Create a settlement client builder. */
        @JvmStatic
        fun builder(): Builder = Builder()

        private fun requireOperation(
            request: AtomicPrivateSettlementPreparedRequestV1,
            expected: AtomicPrivateSettlementOperationV1,
        ) {
            require(request.operation == expected) {
                "prepared ${request.operation} request cannot be sent to $expected"
            }
        }

        private fun operationPath(
            operation: AtomicPrivateSettlementOperationV1,
            payloadDigest: AtomicPrivateSettlementIdentifierV1,
        ): String = operation.path.replace("{payload_digest}", payloadDigest.pathComponent())

        private fun requireBaseUri(uri: URI): URI {
            require(uri.scheme.equals("http", true) || uri.scheme.equals("https", true)) {
                "settlement Torii base URI must use HTTP or HTTPS"
            }
            require(uri.rawQuery == null && uri.rawFragment == null) {
                "settlement Torii base URI must not contain a query or fragment"
            }
            return uri
        }

        private fun requireSafeDefaultHeaders(headers: Map<String, String>) {
            val forbidden = headers.keys.firstOrNull {
                FORBIDDEN_DEFAULT_HEADERS.contains(it.lowercase(Locale.ROOT))
            }
            require(forbidden == null) {
                "settlement header $forbidden is generated by the exact-route client"
            }
        }

        private fun requireExactJsonContentType(headers: Map<String, List<String>>) {
            val values = headers.entries
                .filter { it.key.equals("Content-Type", true) }
                .flatMap { it.value }
            require(values == listOf(JSON_MEDIA_TYPE)) {
                "atomic private settlement response must have one exact application/json content type"
            }
        }

        private fun requireAbsentOrIdentityContentEncoding(headers: Map<String, List<String>>) {
            val values = headers.entries
                .filter { it.key.equals("Content-Encoding", true) }
                .flatMap { it.value }
            require(
                values.isEmpty() ||
                    values.size == 1 && values.single().trim().equals("identity", true),
            ) {
                "atomic private settlement response Content-Encoding must be absent or identity"
            }
        }

        private fun responseFields(route: String): Set<String> = when {
            route.endsWith("/availability-shares") ->
                setOf("bundle_id", "payload_digest", "leg_ordinal", "disposition", "share")
            route.endsWith("/prepare-votes") || route.endsWith("/commit-votes") ->
                setOf("bundle_id", "payload_digest", "leg_ordinal", "vote")
            route.endsWith("/phase-certificates") ->
                setOf(
                    "bundle_id",
                    "payload_digest",
                    "leg_ordinal",
                    "lifecycle",
                    "prepare_certificate",
                    "commit_certificate",
                )
            route.endsWith("/certificates") ->
                setOf("bundle_id", "payload_digest", "leg_ordinal", "phase", "lifecycle")
            route.endsWith("/legs") ->
                setOf(
                    "bundle_id",
                    "payload_digest",
                    "leg_ordinal",
                    "disposition",
                    "lifecycle",
                )
            route.endsWith("/audit-approvals") ->
                setOf(
                    "authoritative_height",
                    "bundle_id",
                    "payload_digest",
                    "leg_ordinal",
                    "committee_authority",
                    "collected",
                    "required",
                    "newly_recorded",
                    "lifecycle",
                    "responder_attestation",
                )
            route.endsWith("/bundles") ->
                setOf("bundle_id", "accepted_at_height", "carrier_id")
            route.endsWith("/status") ->
                setOf(
                    "bundle_id",
                    "payload_digest",
                    "leg_ordinal",
                    "route",
                    "stored_at_height",
                    "lifecycle_height",
                    "expiry_height",
                    "lifecycle",
                )
            route.endsWith("/committee-proof") ->
                setOf(
                    "manifest",
                    "audit_policy",
                    "committee_authority",
                    "statement",
                    "proof",
                    "delta",
                    "audit_approvals",
                    "audit_capsule_digest",
                    "availability",
                    "lifecycle",
                )
            route.endsWith("/audit-capsule") ->
                setOf(
                    "authoritative_height",
                    "manifest",
                    "audit_policy",
                    "access_audit_policy",
                    "committee_authority",
                    "statement",
                    "delta",
                    "audit_capsule",
                    "availability",
                    "lifecycle",
                    "responder_attestation",
                )
            route.endsWith("/receipt") -> setOf("status", "value")
            route.contains("/bundles/") -> setOf("manifest", "lifecycle", "finalized_height")
            else -> throw IllegalArgumentException("unknown atomic private settlement route")
        }

        private fun unwrapCompletion(error: Throwable): Throwable =
            if (error is CompletionException && error.cause != null) checkNotNull(error.cause) else error
    }
}

/** Redacted failure from the exact-route settlement client. */
class AtomicPrivateSettlementToriiExceptionV1 : RuntimeException {
    constructor(message: String) : super(message)
    constructor(message: String, cause: Throwable) : super(message, cause)
}

@Suppress("UNCHECKED_CAST")
private fun parseExactJsonObject(bytes: ByteArray, label: String): Map<String, Any?> {
    val decoder = StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
    val text = try {
        decoder.decode(ByteBuffer.wrap(bytes)).toString()
    } catch (error: Exception) {
        throw IllegalArgumentException("$label must be exact UTF-8", error)
    }
    val parsed = try {
        JsonParser.parse(text)
    } catch (error: RuntimeException) {
        throw IllegalArgumentException("$label must be one strict JSON object", error)
    }
    require(parsed is Map<*, *>) { "$label must be one strict JSON object" }
    require(parsed.keys.all { it is String }) { "$label object keys must be strings" }
    requireJsonIntegersAreBounded(parsed, label)
    return parsed as Map<String, Any?>
}

private fun requireJsonIntegersAreBounded(value: Any?, label: String) {
    when (value) {
        is Map<*, *> -> value.values.forEach { requireJsonIntegersAreBounded(it, label) }
        is List<*> -> value.forEach { requireJsonIntegersAreBounded(it, label) }
        is BigInteger -> require(value.bitLength() <= 256) { "$label contains an oversized integer" }
        is java.math.BigDecimal, is Double, is Float ->
            throw IllegalArgumentException("$label must use the integer-only Norito JSON profile")
    }
}
