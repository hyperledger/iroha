// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.client

import java.nio.charset.StandardCharsets

/**
 * Cryptographically verifies restricted atomic-private-settlement Torii responses.
 *
 * Implementations must validate the exact response bytes received from Torii. The approval
 * verifier additionally receives the exact request bytes sent to Torii. A verifier reports
 * rejection by throwing; callers never treat a missing verifier or a verifier failure as a
 * successful restricted response.
 */
interface AtomicPrivateSettlementResponseVerifierV1 {
    /** Fail unless this verifier can perform production-strength verification now. */
    fun requireAvailable()

    /** Verify a committee proof against the configured network and requested payload digest. */
    fun verifyCommitteeProofResponse(
        responseJson: ByteArray,
        expectedNetworkId: ByteArray,
        requestedPayloadDigest: ByteArray,
    )

    /** Verify an auditor capsule against the exact governed auditor signing key. */
    fun verifyAuditorCapsuleResponse(
        responseJson: ByteArray,
        requestJson: ByteArray,
        expectedNetworkId: ByteArray,
        requestedPayloadDigest: ByteArray,
        auditorPublicKey: String,
    )

    /** Verify an approval acknowledgement against its exact request and auditor signing key. */
    fun verifyAuditApprovalResponse(
        responseJson: ByteArray,
        requestJson: ByteArray,
        expectedNetworkId: ByteArray,
        requestedPayloadDigest: ByteArray,
        auditorPublicKey: String,
    )
}

/**
 * Production JNI-backed restricted-response verifier.
 *
 * The native bridge performs typed Norito JSON decoding, digest recomputation, authority-roster
 * and proof-of-possession checks, BLS responder verification, auditor-key binding, and approval
 * signature verification. Missing native code, an ABI mismatch, or any nonzero native status
 * fails closed.
 */
object AtomicPrivateSettlementNativeResponseVerifierV1 :
    AtomicPrivateSettlementResponseVerifierV1 {
    private const val LIBRARY_NAME = "connect_norito_bridge"
    private const val REQUIRED_BRIDGE_ABI_VERSION = 29
    private const val HASH_BYTES = 32
    private const val RESPONSE_MAX_BYTES = 32 * 1024 * 1024
    private const val APPROVAL_REQUEST_MAX_BYTES = 1024 * 1024
    private const val PUBLIC_KEY_MAX_BYTES = 1024
    private const val PRIVATE_SETTLEMENT_REJECTED_STATUS = -507

    private val nativeLoadResult: Result<Unit> by lazy {
        runCatching {
            System.loadLibrary(LIBRARY_NAME)
            check(nativeBridgeAbiVersion() == REQUIRED_BRIDGE_ABI_VERSION) {
                "native private settlement response verifier ABI mismatch"
            }
            val invalid = ByteArray(0)
            check(
                nativeVerifyCommitteeProofResponseV1(
                    invalid,
                    invalid,
                    invalid,
                ) == PRIVATE_SETTLEMENT_REJECTED_STATUS &&
                    nativeVerifyAuditorCapsuleResponseWithRequestV1(
                        invalid,
                        invalid,
                        invalid,
                        invalid,
                        invalid,
                    ) == PRIVATE_SETTLEMENT_REJECTED_STATUS &&
                    nativeVerifyAuditApprovalResponseV1(
                        invalid,
                        invalid,
                        invalid,
                        invalid,
                        invalid,
                    ) == PRIVATE_SETTLEMENT_REJECTED_STATUS,
            ) { "native private settlement response verifier rejected its linkage probe" }
        }
    }

    override fun requireAvailable() {
        nativeLoadResult.getOrElse { failure ->
            throw IllegalStateException(
                "native private settlement response verifier is unavailable",
                failure,
            )
        }
    }

    override fun verifyCommitteeProofResponse(
        responseJson: ByteArray,
        expectedNetworkId: ByteArray,
        requestedPayloadDigest: ByteArray,
    ) {
        requireCommonInputs(responseJson, expectedNetworkId, requestedPayloadDigest)
        invokeRequiredNative("nativeVerifyCommitteeProofResponseV1") {
            nativeVerifyCommitteeProofResponseV1(
                responseJson.copyOf(),
                expectedNetworkId.copyOf(),
                requestedPayloadDigest.copyOf(),
            )
        }
    }

    override fun verifyAuditorCapsuleResponse(
        responseJson: ByteArray,
        requestJson: ByteArray,
        expectedNetworkId: ByteArray,
        requestedPayloadDigest: ByteArray,
        auditorPublicKey: String,
    ) {
        requireCommonInputs(responseJson, expectedNetworkId, requestedPayloadDigest)
        require(requestJson.isNotEmpty() && requestJson.size <= APPROVAL_REQUEST_MAX_BYTES) {
            "private settlement auditor capsule request is outside the native verification bound"
        }
        val auditorKeyUtf8 = requireAuditorPublicKey(auditorPublicKey)
        invokeRequiredNative("nativeVerifyAuditorCapsuleResponseWithRequestV1") {
            nativeVerifyAuditorCapsuleResponseWithRequestV1(
                responseJson.copyOf(),
                requestJson.copyOf(),
                expectedNetworkId.copyOf(),
                requestedPayloadDigest.copyOf(),
                auditorKeyUtf8,
            )
        }
    }

    override fun verifyAuditApprovalResponse(
        responseJson: ByteArray,
        requestJson: ByteArray,
        expectedNetworkId: ByteArray,
        requestedPayloadDigest: ByteArray,
        auditorPublicKey: String,
    ) {
        requireCommonInputs(responseJson, expectedNetworkId, requestedPayloadDigest)
        require(requestJson.isNotEmpty() && requestJson.size <= APPROVAL_REQUEST_MAX_BYTES) {
            "private settlement approval request is outside the native verification bound"
        }
        val auditorKeyUtf8 = requireAuditorPublicKey(auditorPublicKey)
        invokeRequiredNative("nativeVerifyAuditApprovalResponseV1") {
            nativeVerifyAuditApprovalResponseV1(
                responseJson.copyOf(),
                requestJson.copyOf(),
                expectedNetworkId.copyOf(),
                requestedPayloadDigest.copyOf(),
                auditorKeyUtf8,
            )
        }
    }

    private fun requireCommonInputs(
        responseJson: ByteArray,
        expectedNetworkId: ByteArray,
        requestedPayloadDigest: ByteArray,
    ) {
        require(responseJson.isNotEmpty() && responseJson.size <= RESPONSE_MAX_BYTES) {
            "private settlement response is outside the native verification bound"
        }
        require(expectedNetworkId.size == HASH_BYTES) {
            "private settlement network identity must contain exactly $HASH_BYTES bytes"
        }
        require(requestedPayloadDigest.size == HASH_BYTES) {
            "private settlement payload digest must contain exactly $HASH_BYTES bytes"
        }
    }

    private fun requireAuditorPublicKey(value: String): ByteArray {
        require(value.isNotEmpty() && value == value.trim()) {
            "private settlement auditor public key must be exact and non-empty"
        }
        require(value.all { it.code in 0x21..0x7e }) {
            "private settlement auditor public key must be printable ASCII"
        }
        val utf8 = value.toByteArray(StandardCharsets.UTF_8)
        require(utf8.size <= PUBLIC_KEY_MAX_BYTES) {
            "private settlement auditor public key exceeds the native verification bound"
        }
        return utf8
    }

    private fun invokeRequiredNative(method: String, invocation: () -> Int) {
        requireAvailable()
        val status = try {
            invocation()
        } catch (failure: UnsatisfiedLinkError) {
            throw IllegalStateException(
                "native private settlement response verifier is unavailable: " +
                    "required ABI-29 method $method is missing",
                failure,
            )
        }
        check(status == 0) { "native private settlement response verification rejected" }
    }

    @JvmStatic
    private external fun nativeBridgeAbiVersion(): Int

    @JvmStatic
    private external fun nativeVerifyCommitteeProofResponseV1(
        responseJson: ByteArray,
        expectedNetworkId: ByteArray,
        requestedPayloadDigest: ByteArray,
    ): Int

    @JvmStatic
    private external fun nativeVerifyAuditorCapsuleResponseWithRequestV1(
        responseJson: ByteArray,
        requestJson: ByteArray,
        expectedNetworkId: ByteArray,
        requestedPayloadDigest: ByteArray,
        auditorPublicKeyUtf8: ByteArray,
    ): Int

    @JvmStatic
    private external fun nativeVerifyAuditApprovalResponseV1(
        responseJson: ByteArray,
        requestJson: ByteArray,
        expectedNetworkId: ByteArray,
        requestedPayloadDigest: ByteArray,
        auditorPublicKeyUtf8: ByteArray,
    ): Int
}
