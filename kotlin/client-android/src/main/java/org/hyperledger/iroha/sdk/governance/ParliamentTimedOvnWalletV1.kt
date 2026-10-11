package org.hyperledger.iroha.sdk.governance

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.hyperledger.iroha.sdk.client.ParliamentTimedOvnCastingProofPageVerificationV1

/**
 * Opaque reference to one Parliament timed-OVN root seed protected by Android Keystore.
 *
 * The handle contains no seed bytes and deliberately has no serialization API. Its immutable,
 * non-secret generation identity prevents an alias deleted and recreated later from retargeting an
 * older handle. Applications may retain [alias] and reopen the current generation through
 * [ParliamentTimedOvnWalletV1].
 */
class ParliamentTimedOvnSeedHandleV1 internal constructor(
    /** Application-scoped, non-secret name used to reopen this handle. */
    val alias: String,
    generationId: ByteArray,
) {
    private val generationId = generationId.clone()

    internal fun matchesGenerationId(candidate: ByteArray): Boolean =
        MessageDigest.isEqual(generationId, candidate)

    override fun toString(): String = "ParliamentTimedOvnSeedHandleV1(redacted)"

    override fun equals(other: Any?): Boolean =
        other is ParliamentTimedOvnSeedHandleV1 &&
            alias == other.alias &&
            MessageDigest.isEqual(generationId, other.generationId)

    override fun hashCode(): Int = 31 * alias.hashCode() + generationId.contentHashCode()
}

/** Secret-local choice set accepted by the V1 native wallet bridge. */
enum class ParliamentTimedOvnBallotChoiceV1(internal val code: Int) {
    /** Approve the proposal. */
    AYE(0),

    /** Reject the proposal. */
    NAY(1),

    /** Record an explicit abstention. */
    ABSTAIN(2),
}

/**
 * Immutable external trust anchor for one Parliament timed-OVN casting proof.
 *
 * All byte arrays are snapshotted on construction and again for each native call. The network id
 * is the raw 32-byte genesis-derived [NetworkId], not a process-global chain selector. No default
 * network or checkpoint exists.
 */
class ParliamentTimedOvnCastingTrustAnchorV1(
    networkId: ByteArray,
    /** Positive request-height hint; native verification authenticates the complete checkpoint. */
    val trustedCheckpointHeight: BigInteger,
    trustedCheckpointNorito: ByteArray,
    expectedBallotAttemptId: ByteArray,
) {
    private val networkId = exactAnchor("networkId", networkId)
    private val trustedCheckpointNorito = trustedCheckpointNorito.clone().also {
        require(it.size in 1..ParliamentTimedOvnWalletV1.MAXIMUM_CHECKPOINT_BYTES) {
            "trustedCheckpointNorito must contain a bounded complete canonical checkpoint"
        }
    }
    private val expectedBallotAttemptId =
        exactAnchor("expectedBallotAttemptId", expectedBallotAttemptId)

    init {
        require(trustedCheckpointHeight.signum() > 0 && trustedCheckpointHeight.bitLength() <= 64) {
            "trustedCheckpointHeight must be a positive u64"
        }
        require(this.expectedBallotAttemptId.any { it != 0.toByte() }) {
            "expectedBallotAttemptId must be nonzero"
        }
    }

    /** Convenience constructor for positive checkpoint heights representable by [Long]. */
    constructor(
        networkId: ByteArray,
        trustedCheckpointHeight: Long,
        trustedCheckpointNorito: ByteArray,
        expectedBallotAttemptId: ByteArray,
    ) : this(
        networkId,
        BigInteger.valueOf(trustedCheckpointHeight),
        trustedCheckpointNorito,
        expectedBallotAttemptId,
    )

    internal fun snapshot(): ParliamentTimedOvnCastingTrustAnchorSnapshotV1 =
        ParliamentTimedOvnCastingTrustAnchorSnapshotV1(
            networkId.clone(),
            trustedCheckpointHeight,
            trustedCheckpointNorito.clone(),
            expectedBallotAttemptId.clone(),
        )

    /** Defensive copy of the raw genesis-derived network id. */
    fun networkId(): ByteArray = networkId.clone()

    /** Defensive copy of the independently selected complete canonical checkpoint. */
    fun trustedCheckpointNorito(): ByteArray = trustedCheckpointNorito.clone()

    /** Defensive copy of the expected `BallotAttemptId`. */
    fun expectedBallotAttemptId(): ByteArray = expectedBallotAttemptId.clone()

    /** Promote this immutable anchor with one native-authenticated page result. */
    fun promoted(
        verification: ParliamentTimedOvnCastingProofPageVerificationV1,
    ): ParliamentTimedOvnCastingTrustAnchorV1 =
        ParliamentTimedOvnCastingTrustAnchorV1(
            networkId,
            verification.evaluatedBlockHeight,
            verification.promotedCheckpointNorito(),
            expectedBallotAttemptId,
        )

    override fun toString(): String = "ParliamentTimedOvnCastingTrustAnchorV1(redacted)"

    private companion object {
        fun exactAnchor(label: String, value: ByteArray): ByteArray {
            require(value.size == 32) { "$label must contain exactly 32 bytes" }
            return value.clone()
        }
    }
}

internal class ParliamentTimedOvnCastingTrustAnchorSnapshotV1(
    private val networkId: ByteArray,
    val trustedCheckpointHeight: BigInteger,
    private val trustedCheckpointNorito: ByteArray,
    private val expectedBallotAttemptId: ByteArray,
) {
    fun networkIdBytes(): ByteArray = networkId.clone()

    fun checkpointNoritoBytes(): ByteArray = trustedCheckpointNorito.clone()

    fun ballotAttemptIdBytes(): ByteArray = expectedBallotAttemptId.clone()

}

/** A public wallet record and its exact native-authenticated checkpoint promotion. */
class ParliamentTimedOvnPublicRecordV1 internal constructor(record: ByteArray, checkpoint: ByteArray) {
    private val recordBytes = record.clone()
    private val checkpointBytes = checkpoint.clone()
    /** Canonical registration or masked-ballot bytes for submission. */
    fun record(): ByteArray = recordBytes.clone()
    /** Complete canonical checkpoint to persist with the operation's public state. */
    fun promotedCheckpointNorito(): ByteArray = checkpointBytes.clone()
}

/**
 * Android-only wallet boundary for Parliament timed-OVN registration and ballot generation.
 *
 * Public methods accept one bounded canonical proof response, an immutable independently
 * configured trust anchor, and an opaque keystore handle. Consensus proof and Core archive replay
 * verification complete before the Android seed vault is opened. A 32-byte root seed is generated
 * inside this module, encrypted under a non-exportable Android Keystore AES key, unwrapped only for
 * one native call, and zeroed immediately afterward. No raw-seed constructor, getter, persistence
 * format, logging path, or software proof fallback is exposed.
 */
class ParliamentTimedOvnWalletV1 private constructor(
    private val seedVault: SeedVault,
    private val endpoint: Endpoint?,
) {
    /** Whether the exact ABI-29 proof-gated native casting corridor is available. */
    val isAvailable: Boolean
        get() = endpoint != null

    /** Generate and persist one independently random seed under [alias]. */
    fun createSeedHandle(alias: String): ParliamentTimedOvnSeedHandleV1 =
        seedVault.create(alias)

    /** Reopen an existing opaque handle, or return `null` when [alias] is absent. */
    fun seedHandle(alias: String): ParliamentTimedOvnSeedHandleV1? = seedVault.open(alias)

    /** Delete the encrypted seed bound to [handle]. */
    fun deleteSeedHandle(handle: ParliamentTimedOvnSeedHandleV1): Boolean =
        seedVault.delete(handle)

    /**
     * Generate the exact 3,624-byte public registration from one authenticated proof response.
     *
     * The caller must submit the returned public bytes through `RegisterBallotParticipant`.
     */
    fun registrationFromProofV1(
        castingProofResponseNorito: ByteArray,
        trustAnchor: ParliamentTimedOvnCastingTrustAnchorV1,
        authority: String,
        handle: ParliamentTimedOvnSeedHandleV1,
    ): ParliamentTimedOvnPublicRecordV1 = publicRecord(castingProofResponseNorito, trustAnchor, authority, handle, null)

    /**
     * Reconstruct the registered secret and generate one survivor-bound 2,858-byte ballot.
     *
     * Native replay requires the context phase to be `SurvivorsFrozen` and proves that the
     * regenerated public registration equals the committed record before returning a ballot.
     */
    fun ballotFromProofV1(
        castingProofResponseNorito: ByteArray,
        trustAnchor: ParliamentTimedOvnCastingTrustAnchorV1,
        authority: String,
        handle: ParliamentTimedOvnSeedHandleV1,
        choice: ParliamentTimedOvnBallotChoiceV1,
    ): ParliamentTimedOvnPublicRecordV1 = publicRecord(
        castingProofResponseNorito,
        trustAnchor,
        authority,
        handle,
        choice,
    )

    /**
     * Authenticate one bounded proof page without opening any seed handle.
     *
     * The native result contains diagnostic height/context/flag bytes and the separate complete
     * canonical checkpoint required for durable promotion.
     */
    fun verifyCastingProofPageV1(
        castingProofResponseNorito: ByteArray,
        trustAnchor: ParliamentTimedOvnCastingTrustAnchorV1,
    ): ParliamentTimedOvnCastingProofPageVerificationV1 {
        val nativeEndpoint = endpoint
            ?: throw IllegalStateException(NATIVE_UNAVAILABLE_MESSAGE)
        require(castingProofResponseNorito.size in 1..MAXIMUM_CASTING_PROOF_RESPONSE_BYTES) {
            "castingProofResponseNorito must contain " +
                "1..$MAXIMUM_CASTING_PROOF_RESPONSE_BYTES bytes"
        }
        val proofSnapshot = castingProofResponseNorito.clone()
        try {
            val nativeResult = try {
                nativeEndpoint.verifyCastingProofPage(
                    proofSnapshot.clone(),
                    trustAnchor.snapshot(),
                )
            } catch (_: RuntimeException) {
                null
            } catch (_: LinkageError) {
                throw IllegalStateException(NATIVE_UNAVAILABLE_MESSAGE)
            } ?: throw IllegalStateException(
                "Parliament timed-OVN casting-proof page was rejected",
            )
            try {
                return decodeCastingProofPageVerification(nativeResult)
            } catch (_: IllegalArgumentException) {
                throw IllegalStateException(
                    "Parliament timed-OVN native verifier returned a noncanonical page result",
                )
            } finally {
                nativeResult.forEach { it.fill(0) }
            }
        } finally {
            proofSnapshot.fill(0)
        }
    }

    private fun publicRecord(
        castingProofResponseNorito: ByteArray,
        trustAnchor: ParliamentTimedOvnCastingTrustAnchorV1,
        authority: String,
        handle: ParliamentTimedOvnSeedHandleV1,
        choice: ParliamentTimedOvnBallotChoiceV1?,
    ): ParliamentTimedOvnPublicRecordV1 {
        val nativeEndpoint = endpoint
            ?: throw IllegalStateException(NATIVE_UNAVAILABLE_MESSAGE)
        require(castingProofResponseNorito.size in 1..MAXIMUM_CASTING_PROOF_RESPONSE_BYTES) {
            "castingProofResponseNorito must contain " +
                "1..$MAXIMUM_CASTING_PROOF_RESPONSE_BYTES bytes"
        }
        val authorityBytes = authority.toByteArray(StandardCharsets.UTF_8)
        try {
            require(authorityBytes.isNotEmpty() && authorityBytes.size <= MAXIMUM_AUTHORITY_BYTES) {
                "authority must contain 1..$MAXIMUM_AUTHORITY_BYTES UTF-8 bytes"
            }
            require(authorityBytes.none { it == 0.toByte() }) { "authority must not contain NUL" }
        } finally {
            authorityBytes.fill(0)
        }

        val proofSnapshot = castingProofResponseNorito.clone()
        try {
            val verifiedCheckpoint = try {
                nativeEndpoint.verifyCastingProof(proofSnapshot.clone(), trustAnchor.snapshot())?.clone()
            } catch (_: RuntimeException) {
                null
            } catch (_: LinkageError) {
                throw IllegalStateException(NATIVE_UNAVAILABLE_MESSAGE)
            }
            check(verifiedCheckpoint != null && verifiedCheckpoint.size in 1..MAXIMUM_CHECKPOINT_BYTES) {
                "Parliament timed-OVN casting proof was rejected"
            }

            return seedVault.withSeed(handle) { seed ->
                val output = try {
                    if (choice == null) {
                        nativeEndpoint.registration(
                            proofSnapshot.clone(),
                            trustAnchor.snapshot(),
                            authority,
                            seed,
                        )
                    } else {
                        nativeEndpoint.ballot(
                            proofSnapshot.clone(),
                            trustAnchor.snapshot(),
                            authority,
                            seed,
                            choice.code,
                        )
                    }
                } catch (_: RuntimeException) {
                    // Native/provider diagnostics are not trusted to omit secret handles.
                    throw IllegalStateException(
                        "Parliament timed-OVN native wallet rejected the operation",
                    )
                } catch (_: LinkageError) {
                    throw IllegalStateException(NATIVE_UNAVAILABLE_MESSAGE)
                } ?: throw IllegalStateException(
                    "Parliament timed-OVN native wallet rejected the operation",
                )
                val expectedBytes =
                    if (choice == null) REGISTRATION_RECORD_BYTES else BALLOT_RECORD_BYTES
                check(output.size == 2 && output[0].size == expectedBytes &&
                    output[1].size in 1..MAXIMUM_CHECKPOINT_BYTES &&
                    MessageDigest.isEqual(output[1], verifiedCheckpoint)) {
                    "Parliament timed-OVN native wallet returned a noncanonical public record"
                }
                ParliamentTimedOvnPublicRecordV1(output[0], output[1])
            }
        } finally {
            proofSnapshot.fill(0)
        }
    }

    internal interface Endpoint {
        fun verifyCastingProofPage(
            proofResponse: ByteArray,
            trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
        ): Array<ByteArray>? = null

        fun verifyCastingProof(
            proofResponse: ByteArray,
            trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
        ): ByteArray?

        fun registration(
            proofResponse: ByteArray,
            trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
            authority: String,
            seed: ByteArray,
        ): Array<ByteArray>?

        fun ballot(
            proofResponse: ByteArray,
            trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
            authority: String,
            seed: ByteArray,
            choice: Int,
        ): Array<ByteArray>?
    }

    internal interface SeedVault {
        fun create(alias: String): ParliamentTimedOvnSeedHandleV1

        fun open(alias: String): ParliamentTimedOvnSeedHandleV1?

        fun delete(handle: ParliamentTimedOvnSeedHandleV1): Boolean

        fun <T> withSeed(handle: ParliamentTimedOvnSeedHandleV1, operation: (ByteArray) -> T): T
    }

    companion object {
        /** Exact connect_norito_bridge ABI required by this first-release wallet boundary. */
        const val REQUIRED_BRIDGE_ABI_VERSION: Int = 29

        /** Maximum complete framed `ParliamentTimedOvnCastingProofResponseV1`. */
        const val MAXIMUM_CASTING_PROOF_RESPONSE_BYTES: Int = 8 * 1024 * 1024

        /** Diagnostic summary width, accompanied by a complete native checkpoint. */
        const val CASTING_PROOF_PAGE_SUMMARY_BYTES: Int = 41

        /** Canonical native checkpoint cap: two bounded carriers plus verifier state. */
        const val MAXIMUM_CHECKPOINT_BYTES: Int = 68 * 1024 * 1024

        /** Exact public registration-record width. */
        const val REGISTRATION_RECORD_BYTES: Int = 3_624

        /** Exact public masked-ballot width. */
        const val BALLOT_RECORD_BYTES: Int = 2_858

        private const val MAXIMUM_AUTHORITY_BYTES = 8 * 1024
        private const val NATIVE_UNAVAILABLE_MESSAGE =
            "ABI-29 connect_norito_bridge with proof-gated Parliament wallet symbols is required"

        /** Create a production wallet backed by Android Keystore and the packaged native bridge. */
        @JvmStatic
        fun production(context: Context): ParliamentTimedOvnWalletV1 {
            val applicationContext = context.applicationContext ?: context
            return ParliamentTimedOvnWalletV1(
                AndroidSeedVault(applicationContext),
                ParliamentTimedOvnNativeEndpointV1.create(),
            )
        }

        internal fun withComponentsForTests(
            seedVault: SeedVault,
            endpoint: Endpoint?,
        ): ParliamentTimedOvnWalletV1 = ParliamentTimedOvnWalletV1(seedVault, endpoint)

        private fun decodeCastingProofPageVerification(
            components: Array<ByteArray>,
        ): ParliamentTimedOvnCastingProofPageVerificationV1 {
            require(components.size == 2 && components[1].size in 1..MAXIMUM_CHECKPOINT_BYTES) {
                "native casting-proof page result requires a complete canonical checkpoint"
            }
            val encoded = components[0]
            require(encoded.size == CASTING_PROOF_PAGE_SUMMARY_BYTES) {
                "native casting-proof page result must contain exactly 41 bytes"
            }
            val moreAvailable = when (encoded[40].toInt() and 0xFF) {
                0 -> false
                1 -> true
                else -> throw IllegalArgumentException(
                    "native casting-proof more_available must be 0 or 1",
                )
            }
            val height = BigInteger(1, encoded.copyOfRange(0, 8))
            val context = encoded.copyOfRange(8, 40)
            return try {
                ParliamentTimedOvnCastingProofPageVerificationV1(
                    height,
                    context,
                    moreAvailable,
                    components[1],
                )
            } finally {
                context.fill(0)
            }
        }
    }

}

private object ParliamentTimedOvnNativeEndpointV1 : ParliamentTimedOvnWalletV1.Endpoint {
    private const val LIBRARY_NAME = "connect_norito_bridge"

    fun create(): ParliamentTimedOvnWalletV1.Endpoint? {
        return try {
            System.loadLibrary(LIBRARY_NAME)
            if (nativeBridgeAbiVersion() != ParliamentTimedOvnWalletV1.REQUIRED_BRIDGE_ABI_VERSION) {
                null
            } else {
                // All invalid zero-length probes must resolve and fail closed before this
                // endpoint reports available. Any unexpected public bytes are cleared.
                val verifyProbe = nativeVerifyCastingProofV1(
                    ByteArray(0),
                    ByteArray(0),
                    ByteArray(0),
                    ByteArray(0),
                )
                val pageVerifyProbe = nativeVerifyCastingProofPageV1(
                    ByteArray(0),
                    ByteArray(0),
                    ByteArray(0),
                    ByteArray(0),
                )
                val registrationProbe = nativeRegistrationFromProofV1(
                    ByteArray(0),
                    ByteArray(0),
                    ByteArray(0),
                    ByteArray(0),
                    "",
                    ByteArray(0),
                )
                val ballotProbe = nativeBallotFromProofV1(
                    ByteArray(0),
                    ByteArray(0),
                    ByteArray(0),
                    ByteArray(0),
                    "",
                    ByteArray(0),
                    -1,
                )
                try {
                    if (
                        verifyProbe == null && pageVerifyProbe == null &&
                        registrationProbe == null && ballotProbe == null
                    ) {
                        this
                    } else {
                        null
                    }
                } finally {
                    verifyProbe?.fill(0)
                    pageVerifyProbe?.forEach { it.fill(0) }
                    registrationProbe?.forEach { it.fill(0) }
                    ballotProbe?.forEach { it.fill(0) }
                }
            }
        } catch (_: RuntimeException) {
            null
        } catch (_: LinkageError) {
            null
        }
    }

    override fun verifyCastingProof(
        proofResponse: ByteArray,
        trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
    ): ByteArray? = nativeVerifyCastingProofV1(
        proofResponse,
        trustAnchor.networkIdBytes(),
        trustAnchor.checkpointNoritoBytes(),
        trustAnchor.ballotAttemptIdBytes(),
    )

    override fun verifyCastingProofPage(
        proofResponse: ByteArray,
        trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
    ): Array<ByteArray>? = nativeVerifyCastingProofPageV1(
        proofResponse,
        trustAnchor.networkIdBytes(),
        trustAnchor.checkpointNoritoBytes(),
        trustAnchor.ballotAttemptIdBytes(),
    )

    override fun registration(
        proofResponse: ByteArray,
        trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
        authority: String,
        seed: ByteArray,
    ): Array<ByteArray>? = nativeRegistrationFromProofV1(
        proofResponse,
        trustAnchor.networkIdBytes(),
        trustAnchor.checkpointNoritoBytes(),
        trustAnchor.ballotAttemptIdBytes(),
        authority,
        seed,
    )

    override fun ballot(
        proofResponse: ByteArray,
        trustAnchor: ParliamentTimedOvnCastingTrustAnchorSnapshotV1,
        authority: String,
        seed: ByteArray,
        choice: Int,
    ): Array<ByteArray>? = nativeBallotFromProofV1(
        proofResponse,
        trustAnchor.networkIdBytes(),
        trustAnchor.checkpointNoritoBytes(),
        trustAnchor.ballotAttemptIdBytes(),
        authority,
        seed,
        choice,
    )

    @JvmStatic
    private external fun nativeBridgeAbiVersion(): Int

    @JvmStatic
    private external fun nativeVerifyCastingProofV1(
        proofResponse: ByteArray,
        networkId: ByteArray,
        trustedCheckpointNorito: ByteArray,
        expectedBallotAttemptId: ByteArray,
    ): ByteArray?

    @JvmStatic
    private external fun nativeVerifyCastingProofPageV1(
        proofResponse: ByteArray,
        networkId: ByteArray,
        trustedCheckpointNorito: ByteArray,
        expectedBallotAttemptId: ByteArray,
    ): Array<ByteArray>?

    @JvmStatic
    private external fun nativeRegistrationFromProofV1(
        proofResponse: ByteArray,
        networkId: ByteArray,
        trustedCheckpointNorito: ByteArray,
        expectedBallotAttemptId: ByteArray,
        authority: String,
        seed: ByteArray,
    ): Array<ByteArray>?

    @JvmStatic
    private external fun nativeBallotFromProofV1(
        proofResponse: ByteArray,
        networkId: ByteArray,
        trustedCheckpointNorito: ByteArray,
        expectedBallotAttemptId: ByteArray,
        authority: String,
        seed: ByteArray,
        choice: Int,
    ): Array<ByteArray>?
}

private class AndroidSeedVault(context: Context) : ParliamentTimedOvnWalletV1.SeedVault {
    private val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    override fun create(alias: String): ParliamentTimedOvnSeedHandleV1 {
        validateAlias(alias)
        val preferenceKey = preferenceKey(alias)
        return synchronized(lockForAlias(alias)) {
            require(!preferences.contains(preferenceKey)) { "seed handle alias already exists" }
            val seed = ByteArray(SEED_BYTES)
            val generationId = ByteArray(GENERATION_ID_BYTES)
            SecureRandom().nextBytes(seed)
            SecureRandom().nextBytes(generationId)
            try {
                require(seed.any { it != 0.toByte() }) { "secure random seed was invalid" }
                require(generationId.any { it != 0.toByte() }) {
                    "secure random generation identifier was invalid"
                }
                val encoded = encrypt(seed, alias, generationId)
                check(preferences.edit().putString(preferenceKey, encoded).commit()) {
                    "failed to persist encrypted Parliament timed-OVN seed"
                }
                ParliamentTimedOvnSeedHandleV1(alias, generationId)
            } finally {
                seed.fill(0)
                generationId.fill(0)
            }
        }
    }

    override fun open(alias: String): ParliamentTimedOvnSeedHandleV1? {
        validateAlias(alias)
        return synchronized(lockForAlias(alias)) {
            val encoded = preferences.getString(preferenceKey(alias), null) ?: return@synchronized null
            val generationId = readGenerationId(encoded)
            try {
                ParliamentTimedOvnSeedHandleV1(alias, generationId)
            } finally {
                generationId.fill(0)
            }
        }
    }

    override fun delete(handle: ParliamentTimedOvnSeedHandleV1): Boolean {
        validateAlias(handle.alias)
        synchronized(lockForAlias(handle.alias)) {
            val key = preferenceKey(handle.alias)
            val encoded = preferences.getString(key, null) ?: return false
            val generationId = readGenerationId(encoded)
            try {
                if (!handle.matchesGenerationId(generationId)) return false
            } finally {
                generationId.fill(0)
            }
            // Decryption authenticates the generation identifier and alias AAD before deletion.
            val seed = decrypt(encoded, handle.alias, handle)
            try {
                check(seed.size == SEED_BYTES) {
                    "decrypted Parliament timed-OVN seed is invalid"
                }
            } finally {
                seed.fill(0)
            }
            check(preferences.edit().remove(key).commit()) {
                "failed to delete encrypted Parliament timed-OVN seed"
            }
            return true
        }
    }

    override fun <T> withSeed(
        handle: ParliamentTimedOvnSeedHandleV1,
        operation: (ByteArray) -> T,
    ): T {
        validateAlias(handle.alias)
        return synchronized(lockForAlias(handle.alias)) {
            val encoded = preferences.getString(preferenceKey(handle.alias), null)
                ?: throw IllegalStateException("Parliament timed-OVN seed handle is unavailable")
            val seed = decrypt(encoded, handle.alias, handle)
            try {
                operation(seed)
            } finally {
                seed.fill(0)
            }
        }
    }

    private fun encrypt(seed: ByteArray, alias: String, generationId: ByteArray): String {
        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey())
        val aad = envelopeAad(alias, generationId)
        try {
            cipher.updateAAD(aad)
        } finally {
            aad.fill(0)
        }
        val ciphertext = cipher.doFinal(seed)
        val iv = cipher.iv
        check(iv.size == GCM_IV_BYTES && ciphertext.size == SEED_BYTES + GCM_TAG_BYTES) {
            "Android Keystore returned a noncanonical Parliament seed envelope"
        }
        val envelope = ByteArray(1 + GENERATION_ID_BYTES + GCM_IV_BYTES + ciphertext.size)
        envelope[0] = ENVELOPE_VERSION.toByte()
        generationId.copyInto(envelope, GENERATION_ID_OFFSET)
        iv.copyInto(envelope, IV_OFFSET)
        ciphertext.copyInto(envelope, CIPHERTEXT_OFFSET)
        return try {
            Base64.encodeToString(envelope, Base64.NO_WRAP)
        } finally {
            ciphertext.fill(0)
            envelope.fill(0)
        }
    }

    private fun readGenerationId(encoded: String): ByteArray {
        val envelope = decodeEnvelope(encoded)
        try {
            return envelope.copyOfRange(GENERATION_ID_OFFSET, IV_OFFSET)
        } finally {
            envelope.fill(0)
        }
    }

    private fun decrypt(
        encoded: String,
        alias: String,
        handle: ParliamentTimedOvnSeedHandleV1,
    ): ByteArray {
        val envelope = decodeEnvelope(encoded)
        try {
            val generationId = envelope.copyOfRange(GENERATION_ID_OFFSET, IV_OFFSET)
            val iv = envelope.copyOfRange(IV_OFFSET, CIPHERTEXT_OFFSET)
            val ciphertext = envelope.copyOfRange(CIPHERTEXT_OFFSET, envelope.size)
            return try {
                if (!handle.matchesGenerationId(generationId)) {
                    throw IllegalStateException("Parliament timed-OVN seed handle is stale")
                }
                val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
                cipher.init(Cipher.DECRYPT_MODE, wrappingKey(), GCMParameterSpec(128, iv))
                val aad = envelopeAad(alias, generationId)
                try {
                    cipher.updateAAD(aad)
                } finally {
                    aad.fill(0)
                }
                cipher.doFinal(ciphertext).also { seed ->
                    require(seed.size == SEED_BYTES && seed.any { it != 0.toByte() }) {
                        "decrypted Parliament timed-OVN seed is invalid"
                    }
                }
            } finally {
                generationId.fill(0)
                iv.fill(0)
                ciphertext.fill(0)
            }
        } finally {
            envelope.fill(0)
        }
    }

    private fun decodeEnvelope(encoded: String): ByteArray {
        val envelope = Base64.decode(encoded, Base64.NO_WRAP)
        try {
            require(envelope.size == ENVELOPE_BYTES) {
                "encrypted Parliament timed-OVN seed envelope is malformed"
            }
            require(envelope[0].toInt() == ENVELOPE_VERSION) {
                "encrypted Parliament timed-OVN seed version is unsupported"
            }
            return envelope
        } catch (error: RuntimeException) {
            envelope.fill(0)
            throw error
        }
    }

    private fun envelopeAad(alias: String, generationId: ByteArray): ByteArray {
        val aliasDigest = aliasDigest(alias)
        return try {
            ByteArray(1 + aliasDigest.size + generationId.size).also { aad ->
                aad[0] = ENVELOPE_VERSION.toByte()
                aliasDigest.copyInto(aad, 1)
                generationId.copyInto(aad, 1 + aliasDigest.size)
            }
        } finally {
            aliasDigest.fill(0)
        }
    }

    private fun wrappingKey(): SecretKey = synchronized(WRAPPING_KEY_LOCK) {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = keyStore.getKey(WRAPPING_KEY_ALIAS, null)
        if (existing is SecretKey) return@synchronized existing
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                WRAPPING_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        generator.generateKey()
    }

    private fun preferenceKey(alias: String): String =
        "seed_" + aliasDigest(alias).joinToString("") { byte ->
            "%02x".format(byte.toInt() and 0xff)
        }

    private fun aliasDigest(alias: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(alias.toByteArray(StandardCharsets.UTF_8))

    private fun validateAlias(alias: String) {
        require(alias.isNotBlank() && alias.length <= MAXIMUM_ALIAS_CHARS && !alias.contains('\u0000')) {
            "seed handle alias must contain 1..$MAXIMUM_ALIAS_CHARS non-NUL characters"
        }
    }

    private fun lockForAlias(alias: String): Any {
        val candidate = Any()
        return ALIAS_LOCKS.putIfAbsent(alias, candidate) ?: candidate
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val WRAPPING_KEY_ALIAS =
            "org.hyperledger.iroha.sdk.parliament.timed_ovn.seed_wrap.v1"
        private const val PREFERENCES_NAME = "iroha_parliament_timed_ovn_seed_v1"
        private const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val ENVELOPE_VERSION = 2
        private const val SEED_BYTES = 32
        private const val GENERATION_ID_BYTES = 32
        private const val GCM_IV_BYTES = 12
        private const val GCM_TAG_BYTES = 16
        private const val GENERATION_ID_OFFSET = 1
        private const val IV_OFFSET = GENERATION_ID_OFFSET + GENERATION_ID_BYTES
        private const val CIPHERTEXT_OFFSET = IV_OFFSET + GCM_IV_BYTES
        private const val ENVELOPE_BYTES = CIPHERTEXT_OFFSET + SEED_BYTES + GCM_TAG_BYTES
        private const val MAXIMUM_ALIAS_CHARS = 128
        private val ALIAS_LOCKS = java.util.concurrent.ConcurrentHashMap<String, Any>()
        private val WRAPPING_KEY_LOCK = Any()
    }
}
