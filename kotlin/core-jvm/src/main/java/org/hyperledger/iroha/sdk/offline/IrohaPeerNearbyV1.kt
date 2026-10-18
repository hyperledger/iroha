package org.hyperledger.iroha.sdk.offline

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Portable IPN1 core. Google Nearby remains a narrow platform adapter around these records. */
object IrohaPeerNearbyV1 {
    const val SERVICE_ID = "org.hyperledger.iroha.kagemusha.transfer.v1"
    const val BONJOUR_SERVICE = "_F2EBA4BCB49B._tcp"
    const val WIRE_VERSION = 1
    const val MAXIMUM_CERTIFICATE_BYTES = 16 * 1024
    /** Leaves a conservative 64-byte record-overhead budget inside 32 KiB. */
    const val MAXIMUM_MESSAGE_BYTES = 32 * 1024 - 64
    /** Complete authentication record remains within the common 32 KiB radio ceiling. */
    const val MAXIMUM_AUTHENTICATION_SIGNATURE_BYTES = 32 * 1024 - 60

    internal val MAGIC = "IPN1".toByteArray(Charsets.US_ASCII)
    internal val DISCOVERY_MAGIC = "IPD1".toByteArray(Charsets.US_ASCII)
    internal val TRANSCRIPT_DOMAIN = "IROHA-PEER-NEARBY-TRANSCRIPT-V1\u0000".toByteArray()
    internal val AUTHENTICATION_DOMAIN = "IROHA-PEER-NEARBY-AUTH-V1\u0000".toByteArray()
    internal val KEY_DOMAIN = "IROHA-PEER-NEARBY-KEYS-V1\u0000".toByteArray()
}

enum class IrohaPeerNearbyRoleV1(val code: Int) {
    SENDER(1),
    RECEIVER(2);

    val peer: IrohaPeerNearbyRoleV1
        get() = if (this == SENDER) RECEIVER else SENDER

    companion object {
        @JvmStatic fun fromCode(code: Int): IrohaPeerNearbyRoleV1? =
            entries.firstOrNull { it.code == code }
    }
}

enum class IrohaPeerNearbyRecordKindV1(val code: Int) {
    HELLO(1),
    AUTHENTICATION(2),
    ENCRYPTED_MESSAGE(3),
}

/** Point-to-point discovery record that does not expose an account identifier. */
class IrohaPeerNearbyDiscoveryContextV1 private constructor(
    val profile: IrohaPeerPayloadProfile,
    val role: IrohaPeerNearbyRoleV1,
    sessionId: ByteArray,
    requestCanonicalHash: ByteArray,
    allowsBootstrapSentinel: Boolean,
) {
    private val session = sessionId.boundedNearbyCopy(16, 16, "Nearby session")
    private val requestHash = requestCanonicalHash.boundedNearbyCopy(32, 32, "Nearby request hash")
    val sessionId: ByteArray get() = session.copyOf()
    val requestCanonicalHash: ByteArray get() = requestHash.copyOf()

    constructor(
        profile: IrohaPeerPayloadProfile,
        role: IrohaPeerNearbyRoleV1,
        sessionId: ByteArray,
        requestCanonicalHash: ByteArray,
    ) : this(profile, role, sessionId, requestCanonicalHash, false)

    init {
        require(session.size == 16 && requestHash.size == 32) { "Invalid Nearby discovery context" }
        val zeroSession = session.all { it.toInt() == 0 }
        val zeroRequest = requestHash.all { it.toInt() == 0 }
        if (allowsBootstrapSentinel) {
            require(zeroSession && zeroRequest) { "Invalid Nearby bootstrap sentinel" }
        } else {
            require(!zeroSession) { "Invalid Nearby session" }
            require(!zeroRequest) { "Invalid Nearby request hash" }
        }
    }

    fun encode(): ByteArray = ByteArrayOutputStream(56).also { output ->
        output.write(IrohaPeerNearbyV1.DISCOVERY_MAGIC)
        output.write(IrohaPeerNearbyV1.WIRE_VERSION)
        output.writeU16(profile.code)
        output.write(role.code)
        output.write(session)
        output.write(requestHash)
    }.toByteArray()

    /** Canonical radio form shared with iOS: Base64URL without padding. */
    fun encodeRadioDiscovery(): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(encode())

    val isSenderBootstrap: Boolean
        get() = role == IrohaPeerNearbyRoleV1.SENDER &&
            session.all { it.toInt() == 0 } && requestHash.all { it.toInt() == 0 }

    override fun equals(other: Any?): Boolean = other is IrohaPeerNearbyDiscoveryContextV1 &&
        profile == other.profile && role == other.role && session.contentEquals(other.session) &&
        requestHash.contentEquals(other.requestHash)

    override fun hashCode(): Int = 31 * profile.hashCode() + session.contentHashCode()

    companion object {
        /** Explicit discovery-only sentinel; it is never a valid IPN1 session. */
        @JvmStatic fun senderBootstrap(
            profile: IrohaPeerPayloadProfile,
        ): IrohaPeerNearbyDiscoveryContextV1 = IrohaPeerNearbyDiscoveryContextV1(
            profile,
            IrohaPeerNearbyRoleV1.SENDER,
            ByteArray(16),
            ByteArray(32),
            true,
        )

        /**
         * A RECEIVER context advertised before the receiver holds a Request
         * (`specs/kagemusha_wallet_wire_v1.md` §6, Nearby): a fresh random nonzero session
         * identifier and a fresh random nonzero 32-byte binding in place of the Request hash
         * ([requestCanonicalHash]). The authenticated session binds to both, and the Offer,
         * Request, Payment and Credited then all travel inside it.
         */
        @JvmStatic fun freshReceiver(profile: IrohaPeerPayloadProfile): IrohaPeerNearbyDiscoveryContextV1 =
            IrohaPeerNearbyDiscoveryContextV1(
                profile,
                IrohaPeerNearbyRoleV1.RECEIVER,
                randomNonzeroNearbyBytes(16),
                randomNonzeroNearbyBytes(32),
            )

        @JvmStatic fun decode(data: ByteArray): IrohaPeerNearbyDiscoveryContextV1 {
            require(data.size == 56 && data.copyOfRange(0, 4)
                .contentEquals(IrohaPeerNearbyV1.DISCOVERY_MAGIC)) { "Malformed IPD1 record" }
            require(data[4].toInt() and 0xff == IrohaPeerNearbyV1.WIRE_VERSION) {
                "Unsupported IPD1 version"
            }
            val profile = IrohaPeerPayloadProfile.fromCode(data.readU16Nearby(5))
                ?: throw IllegalArgumentException("Invalid Nearby profile")
            val role = IrohaPeerNearbyRoleV1.fromCode(data[7].toInt() and 0xff)
                ?: throw IllegalArgumentException("Invalid Nearby role")
            val session = data.copyOfRange(8, 24)
            val request = data.copyOfRange(24, 56)
            val zeroSession = session.all { it.toInt() == 0 }
            val zeroRequest = request.all { it.toInt() == 0 }
            require(zeroSession == zeroRequest) { "Invalid Nearby bootstrap sentinel" }
            if (zeroSession) {
                require(role == IrohaPeerNearbyRoleV1.SENDER) {
                    "Only a sender may use the Nearby bootstrap sentinel"
                }
                return senderBootstrap(profile)
            }
            return IrohaPeerNearbyDiscoveryContextV1(profile, role, session, request)
        }

        /**
         * Strict portable decoder for the radio form. Padding, whitespace,
         * standard-Base64 punctuation and non-canonical pad-bit aliases fail.
         */
        @JvmStatic fun decodeRadioDiscovery(value: String): IrohaPeerNearbyDiscoveryContextV1 {
            require(value.length == 75 && value.all {
                it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_'
            }) { "Malformed Nearby radio discovery representation" }
            val bytes = Base64.getUrlDecoder().decode(value)
            require(bytes.size == 56) { "Malformed Nearby radio discovery representation" }
            val decoded = decode(bytes)
            require(decoded.encodeRadioDiscovery() == value) {
                "Non-canonical Nearby radio discovery representation"
            }
            return decoded
        }
    }
}

/** Pure discovery selection shared by the Android rail and JVM tests. */
object IrohaPeerNearbyDiscoveryMatcherV1 {
    @JvmStatic fun selectLocalContext(
        local: IrohaPeerNearbyDiscoveryContextV1,
        remote: IrohaPeerNearbyDiscoveryContextV1,
        expectedRemoteRole: IrohaPeerNearbyRoleV1,
    ): IrohaPeerNearbyDiscoveryContextV1? {
        if (remote.profile != local.profile || remote.role != expectedRemoteRole) return null
        if (local.isSenderBootstrap) {
            if (remote.isSenderBootstrap) return null
            return IrohaPeerNearbyDiscoveryContextV1(
                local.profile,
                local.role,
                remote.sessionId,
                remote.requestCanonicalHash,
            )
        }
        return if (!remote.isSenderBootstrap && remote.sessionId.contentEquals(local.sessionId) &&
            remote.requestCanonicalHash.contentEquals(local.requestCanonicalHash)) local else null
    }
}

object IrohaPeerNearbyVerificationCodeV1 {
    @JvmStatic fun isValid(code: String): Boolean =
        code.length in 4..12 && code.all { it in '0'..'9' }
}

class IrohaPeerNearbyHelloV1(
    val profile: IrohaPeerPayloadProfile,
    val role: IrohaPeerNearbyRoleV1,
    sessionId: ByteArray,
    nonce: ByteArray,
    requestCanonicalHash: ByteArray,
    ephemeralPublicKey: ByteArray,
    deviceCertificate: ByteArray,
) {
    private val session = sessionId.boundedNearbyCopy(16, 16, "Nearby session")
    private val helloNonce = nonce.boundedNearbyCopy(32, 32, "Nearby nonce")
    private val requestHash = requestCanonicalHash.boundedNearbyCopy(32, 32, "Nearby request hash")
    private val publicKey = ephemeralPublicKey.boundedNearbyCopy(65, 65, "Nearby P-256 key")
    private val certificate = deviceCertificate.boundedNearbyCopy(
        1,
        IrohaPeerNearbyV1.MAXIMUM_CERTIFICATE_BYTES,
        "Nearby device certificate",
    )
    val sessionId: ByteArray get() = session.copyOf()
    val nonce: ByteArray get() = helloNonce.copyOf()
    val requestCanonicalHash: ByteArray get() = requestHash.copyOf()
    val ephemeralPublicKey: ByteArray get() = publicKey.copyOf()
    val deviceCertificate: ByteArray get() = certificate.copyOf()

    init {
        require(session.size == 16 && session.any { it.toInt() != 0 }) { "Invalid Nearby session" }
        require(helloNonce.size == 32 && helloNonce.any { it.toInt() != 0 }) { "Invalid Nearby nonce" }
        require(requestHash.size == 32 && requestHash.any { it.toInt() != 0 }) {
            "Invalid Nearby request hash"
        }
        require(IrohaPeerNearbyP256V1.isValidPublicKey(publicKey)) { "Invalid Nearby P-256 key" }
        require(certificate.isNotEmpty() &&
            certificate.size <= IrohaPeerNearbyV1.MAXIMUM_CERTIFICATE_BYTES) {
            "Invalid Nearby device certificate"
        }
    }

    fun encode(): ByteArray = ByteArrayOutputStream().also { output ->
        output.write(IrohaPeerNearbyV1.MAGIC)
        output.write(IrohaPeerNearbyV1.WIRE_VERSION)
        output.write(IrohaPeerNearbyRecordKindV1.HELLO.code)
        output.writeU16(profile.code)
        output.write(role.code)
        output.write(0)
        output.write(session)
        output.write(helloNonce)
        output.write(requestHash)
        output.writeU16(publicKey.size)
        output.write(publicKey)
        output.writeU32(certificate.size.toLong())
        output.write(certificate)
    }.toByteArray()

    override fun equals(other: Any?): Boolean = other is IrohaPeerNearbyHelloV1 &&
        profile == other.profile && role == other.role && session.contentEquals(other.session) &&
        helloNonce.contentEquals(other.helloNonce) && requestHash.contentEquals(other.requestHash) &&
        publicKey.contentEquals(other.publicKey) && certificate.contentEquals(other.certificate)

    override fun hashCode(): Int = 31 * profile.hashCode() + publicKey.contentHashCode()

    companion object {
        @JvmStatic fun decode(data: ByteArray): IrohaPeerNearbyHelloV1 {
            requireRecordPrefix(data, IrohaPeerNearbyRecordKindV1.HELLO, 10 + 16 + 32 + 32 + 2 + 65 + 4 + 1)
            val profile = IrohaPeerPayloadProfile.fromCode(data.readU16Nearby(6))
                ?: throw IllegalArgumentException("Invalid Nearby profile")
            val role = IrohaPeerNearbyRoleV1.fromCode(data[8].toInt() and 0xff)
                ?: throw IllegalArgumentException("Invalid Nearby role")
            require(data[9].toInt() == 0) { "Invalid Nearby flags" }
            var cursor = 90
            val publicKeyLength = data.readU16Nearby(cursor)
            cursor += 2
            require(publicKeyLength == 65 && cursor <= data.size - publicKeyLength - 4) {
                "Invalid Nearby public key"
            }
            val publicKey = data.copyOfRange(cursor, cursor + publicKeyLength)
            cursor += publicKeyLength
            val certificateLength = data.readU32Nearby(cursor).checkedNearbyLength(
                IrohaPeerNearbyV1.MAXIMUM_CERTIFICATE_BYTES,
            )
            cursor += 4
            require(certificateLength > 0 && cursor + certificateLength == data.size) {
                "Invalid Nearby certificate"
            }
            return IrohaPeerNearbyHelloV1(
                profile,
                role,
                data.copyOfRange(10, 26),
                data.copyOfRange(26, 58),
                data.copyOfRange(58, 90),
                publicKey,
                data.copyOfRange(cursor, data.size),
            )
        }
    }
}

class IrohaPeerNearbyAuthenticationV1(
    val profile: IrohaPeerPayloadProfile,
    val role: IrohaPeerNearbyRoleV1,
    sessionId: ByteArray,
    transcriptHash: ByteArray,
    signature: ByteArray,
) {
    private val session = sessionId.boundedNearbyCopy(16, 16, "Nearby session")
    private val transcript = transcriptHash.boundedNearbyCopy(32, 32, "Nearby transcript")
    private val authSignature = signature.boundedNearbyCopy(
        1,
        IrohaPeerNearbyV1.MAXIMUM_AUTHENTICATION_SIGNATURE_BYTES,
        "Nearby signature",
    )
    val sessionId: ByteArray get() = session.copyOf()
    val transcriptHash: ByteArray get() = transcript.copyOf()
    val signature: ByteArray get() = authSignature.copyOf()

    init {
        require(session.size == 16 && session.any { it.toInt() != 0 } &&
            transcript.size == 32 && transcript.any { it.toInt() != 0 }) {
            "Invalid Nearby authentication"
        }
        require(authSignature.isNotEmpty() &&
            authSignature.size <= IrohaPeerNearbyV1.MAXIMUM_AUTHENTICATION_SIGNATURE_BYTES) {
            "Invalid Nearby signature"
        }
    }

    fun encode(): ByteArray = ByteArrayOutputStream().also { output ->
        output.write(IrohaPeerNearbyV1.MAGIC)
        output.write(IrohaPeerNearbyV1.WIRE_VERSION)
        output.write(IrohaPeerNearbyRecordKindV1.AUTHENTICATION.code)
        output.writeU16(profile.code)
        output.write(role.code)
        output.write(0)
        output.write(session)
        output.write(transcript)
        output.writeU16(authSignature.size)
        output.write(authSignature)
    }.toByteArray()

    companion object {
        @JvmStatic fun decode(data: ByteArray): IrohaPeerNearbyAuthenticationV1 {
            requireRecordPrefix(data, IrohaPeerNearbyRecordKindV1.AUTHENTICATION, 61)
            val profile = IrohaPeerPayloadProfile.fromCode(data.readU16Nearby(6))
                ?: throw IllegalArgumentException("Invalid Nearby profile")
            val role = IrohaPeerNearbyRoleV1.fromCode(data[8].toInt() and 0xff)
                ?: throw IllegalArgumentException("Invalid Nearby role")
            require(data[9].toInt() == 0) { "Invalid Nearby flags" }
            val signatureLength = data.readU16Nearby(58)
            require(signatureLength in 1..IrohaPeerNearbyV1.MAXIMUM_AUTHENTICATION_SIGNATURE_BYTES &&
                60 + signatureLength == data.size) {
                "Invalid Nearby signature length"
            }
            return IrohaPeerNearbyAuthenticationV1(
                profile,
                role,
                data.copyOfRange(10, 26),
                data.copyOfRange(26, 58),
                data.copyOfRange(60, data.size),
            )
        }
    }
}

class IrohaPeerNearbyEncryptedRecordV1(
    val profile: IrohaPeerPayloadProfile,
    val senderRole: IrohaPeerNearbyRoleV1,
    sessionId: ByteArray,
    val sequence: Long,
    ciphertextAndTag: ByteArray,
) {
    private val session = sessionId.boundedNearbyCopy(16, 16, "Nearby session")
    private val sealed = ciphertextAndTag.boundedNearbyCopy(
        16,
        IrohaPeerNearbyV1.MAXIMUM_MESSAGE_BYTES + 16,
        "Nearby encrypted message",
    )
    val sessionId: ByteArray get() = session.copyOf()
    val ciphertextAndTag: ByteArray get() = sealed.copyOf()

    init {
        require(session.size == 16 && session.any { it.toInt() != 0 }) { "Invalid Nearby session" }
        require(sealed.size in 16..(IrohaPeerNearbyV1.MAXIMUM_MESSAGE_BYTES + 16)) {
            "Invalid Nearby encrypted message length"
        }
    }

    internal fun header(): ByteArray = ByteArrayOutputStream(38).also { output ->
        output.write(IrohaPeerNearbyV1.MAGIC)
        output.write(IrohaPeerNearbyV1.WIRE_VERSION)
        output.write(IrohaPeerNearbyRecordKindV1.ENCRYPTED_MESSAGE.code)
        output.writeU16(profile.code)
        output.write(senderRole.code)
        output.write(0)
        output.write(session)
        output.writeU64(sequence)
        output.writeU32(sealed.size.toLong())
    }.toByteArray()

    fun encode(): ByteArray = header() + sealed

    companion object {
        @JvmStatic fun decode(data: ByteArray): IrohaPeerNearbyEncryptedRecordV1 {
            requireRecordPrefix(data, IrohaPeerNearbyRecordKindV1.ENCRYPTED_MESSAGE, 54)
            val profile = IrohaPeerPayloadProfile.fromCode(data.readU16Nearby(6))
                ?: throw IllegalArgumentException("Invalid Nearby profile")
            val role = IrohaPeerNearbyRoleV1.fromCode(data[8].toInt() and 0xff)
                ?: throw IllegalArgumentException("Invalid Nearby role")
            require(data[9].toInt() == 0) { "Invalid Nearby flags" }
            val payloadLength = data.readU32Nearby(34).checkedNearbyLength(
                IrohaPeerNearbyV1.MAXIMUM_MESSAGE_BYTES + 16,
            )
            require(payloadLength >= 16 && 38 + payloadLength == data.size) {
                "Invalid Nearby encrypted record"
            }
            return IrohaPeerNearbyEncryptedRecordV1(
                profile,
                role,
                data.copyOfRange(10, 26),
                data.readU64Nearby(26),
                data.copyOfRange(38, data.size),
            )
        }
    }
}

fun interface IrohaPeerNearbySignatureVerifierV1 {
    fun verify(
        role: IrohaPeerNearbyRoleV1,
        certificate: ByteArray,
        signedBytes: ByteArray,
        signature: ByteArray,
    ): Boolean
}

private class NearbyVerificationMaterialV1(
    val role: IrohaPeerNearbyRoleV1,
    val certificate: ByteArray,
    val signedBytes: ByteArray,
    val signature: ByteArray,
    val peerPublicKey: ByteArray,
)

/**
 * Authenticated P-256/HKDF-SHA256/AES-256-GCM transcript state.
 *
 * The session assumes lifecycle ownership of [ephemeralKey]. [close] (or [destroy]) is
 * idempotent, wipes the owned AES key byte arrays, and closes that key before dropping its
 * reference. JVM cryptographic providers and [BigInteger] may retain opaque internal copies that
 * cannot be physically overwritten; explicit destruction shortens their reachable lifetime.
 */
class IrohaPeerNearbySessionV1 @JvmOverloads constructor(
    val profile: IrohaPeerPayloadProfile,
    val localRole: IrohaPeerNearbyRoleV1,
    sessionId: ByteArray,
    requestCanonicalHash: ByteArray,
    deviceCertificate: ByteArray,
    nonce: ByteArray = randomNearbyBytes(32),
    ephemeralKey: IrohaPeerNearbyP256V1 = IrohaPeerNearbyP256V1.generate(),
) : Closeable {
    private var ownedEphemeralKey: IrohaPeerNearbyP256V1? = ephemeralKey
    private val session = initializeOrClose {
        sessionId.boundedNearbyCopy(16, 16, "Nearby session")
    }
    private val requestHash = initializeOrClose {
        requestCanonicalHash.boundedNearbyCopy(32, 32, "Nearby request hash")
    }
    val sessionId: ByteArray get() = session.copyOf()
    val requestCanonicalHash: ByteArray get() = requestHash.copyOf()
    private var hello: IrohaPeerNearbyHelloV1? = initializeOrClose {
        IrohaPeerNearbyHelloV1(
            profile,
            localRole,
            session,
            nonce,
            requestHash,
            ephemeralKey.publicKey,
            deviceCertificate,
        )
    }

    val localHello: IrohaPeerNearbyHelloV1
        @Synchronized get() {
            checkNotDestroyed()
            return hello ?: throw IllegalStateException("Nearby session has been destroyed")
        }

    private var peerHello: IrohaPeerNearbyHelloV1? = null
    private var acceptedTranscriptHash: ByteArray? = null
    private var outboundKey: ByteArray? = null
    private var inboundKey: ByteArray? = null
    private var outboundSequence = 0L
    private var inboundSequence = 0L
    private var authenticationInProgress = false
    private var destroyed = false

    val isDestroyed: Boolean
        @Synchronized get() = destroyed

    val isAuthenticated: Boolean
        @Synchronized get() = !destroyed && outboundKey != null && inboundKey != null &&
            acceptedTranscriptHash != null

    @Synchronized
    fun acceptPeerHello(hello: IrohaPeerNearbyHelloV1) {
        checkNotDestroyed()
        val local = this.hello ?: throw IllegalStateException("Nearby session has been destroyed")
        require(peerHello == null) { "Nearby hello replay or reordering" }
        require(hello.profile == profile) { "Nearby profile mismatch" }
        require(hello.role == localRole.peer) { "Nearby role mismatch" }
        require(hello.sessionId.contentEquals(session)) { "Nearby session mismatch" }
        require(hello.requestCanonicalHash.contentEquals(requestHash)) { "Nearby request mismatch" }
        require(!hello.ephemeralPublicKey.contentEquals(local.ephemeralPublicKey) &&
            !hello.nonce.contentEquals(local.nonce)) { "Nearby authentication reflection" }
        peerHello = hello
    }

    @Synchronized
    fun authenticationPreimage(): ByteArray {
        checkNotDestroyed()
        return IrohaPeerNearbyV1.AUTHENTICATION_DOMAIN +
            byteArrayOf(localRole.code.toByte()) + transcriptHash()
    }

    @Synchronized
    fun makeAuthentication(signature: ByteArray): IrohaPeerNearbyAuthenticationV1 {
        checkNotDestroyed()
        return IrohaPeerNearbyAuthenticationV1(
            profile,
            localRole,
            session,
            transcriptHash(),
            signature,
        )
    }

    fun acceptPeerAuthentication(
        authentication: IrohaPeerNearbyAuthenticationV1,
        verifier: IrohaPeerNearbySignatureVerifierV1,
    ) {
        val verification = synchronized(this) {
            checkNotDestroyed()
            require(!authenticationInProgress && !isAuthenticated && acceptedTranscriptHash == null) {
                "Nearby authentication replay or reordering"
            }
            val hello = peerHello ?: throw IllegalStateException("Nearby peer verification required")
            require(authentication.profile == profile && authentication.role == localRole.peer) {
                "Nearby authentication routing mismatch"
            }
            require(authentication.sessionId.contentEquals(session)) { "Nearby session mismatch" }
            val transcript = transcriptHash()
            require(authentication.transcriptHash.contentEquals(transcript)) {
                "Nearby transcript mismatch"
            }
            val signed = IrohaPeerNearbyV1.AUTHENTICATION_DOMAIN +
                byteArrayOf(authentication.role.code.toByte()) + transcript
            authenticationInProgress = true
            NearbyVerificationMaterialV1(
                authentication.role,
                hello.deviceCertificate,
                signed,
                authentication.signature,
                hello.ephemeralPublicKey,
            )
        }
        try {
            val verified = verifier.verify(
                verification.role,
                verification.certificate,
                verification.signedBytes,
                verification.signature,
            )
            synchronized(this) {
                try {
                    // Destruction may have happened on any thread while the verifier ran.
                    checkNotDestroyed()
                    require(verified) { "Nearby certificate authentication failed" }
                    val keyAgreement = ownedEphemeralKey
                        ?: throw IllegalStateException("Nearby session has been destroyed")
                    val transcript = authentication.transcriptHash
                    val shared = keyAgreement.sharedSecret(verification.peerPublicKey)
                    var senderToReceiver: ByteArray? = null
                    var receiverToSender: ByteArray? = null
                    try {
                        senderToReceiver = deriveNearbyKey(shared, transcript, "sender-to-receiver")
                        receiverToSender = deriveNearbyKey(shared, transcript, "receiver-to-sender")
                    } catch (failure: Throwable) {
                        senderToReceiver?.fill(0)
                        receiverToSender?.fill(0)
                        throw failure
                    } finally {
                        shared.fill(0)
                    }
                    if (localRole == IrohaPeerNearbyRoleV1.SENDER) {
                        outboundKey = senderToReceiver
                        inboundKey = receiverToSender
                    } else {
                        outboundKey = receiverToSender
                        inboundKey = senderToReceiver
                    }
                    keyAgreement.close()
                    ownedEphemeralKey = null
                    acceptedTranscriptHash = transcript
                    outboundSequence = 0
                    inboundSequence = 0
                } finally {
                    authenticationInProgress = false
                }
            }
        } catch (failure: Throwable) {
            synchronized(this) {
                authenticationInProgress = false
                if (destroyed) {
                    throw IllegalStateException("Nearby session has been destroyed", failure)
                }
            }
            throw failure
        }
    }

    /** Seals one verified IPM1 message for this authenticated profile. */
    @Synchronized
    fun seal(message: IrohaPeerWireMessageV1): IrohaPeerNearbyEncryptedRecordV1 {
        checkNotDestroyed()
        val key = outboundKey ?: throw IllegalStateException("Nearby session is not authenticated")
        require(message.canonicalPayload.profile == profile) { "Nearby message profile mismatch" }
        require(message.byteCount <= IrohaPeerNearbyV1.MAXIMUM_MESSAGE_BYTES) {
            "Nearby message is too large"
        }
        require(outboundSequence != -1L) { "Nearby sequence exhausted" }
        val sequence = outboundSequence
        val plaintext = message.encode()
        try {
            val placeholder = IrohaPeerNearbyEncryptedRecordV1(
                profile,
                localRole,
                session,
                sequence,
                ByteArray(plaintext.size + 16),
            )
            val sealed = aesGcmNearby(Cipher.ENCRYPT_MODE, key, nearbyNonce(localRole, sequence),
                placeholder.header(), plaintext)
            try {
                val record = IrohaPeerNearbyEncryptedRecordV1(profile, localRole, session, sequence, sealed)
                outboundSequence += 1
                return record
            } finally {
                sealed.fill(0)
            }
        } finally {
            plaintext.fill(0)
        }
    }

    /**
     * Authenticates and verifies one IPM1 message before advancing the receive sequence.
     * Invalid ciphertext or plaintext leaves the expected sequence unchanged.
     */
    @Synchronized
    fun open(record: IrohaPeerNearbyEncryptedRecordV1): IrohaPeerWireMessageV1 {
        checkNotDestroyed()
        val key = inboundKey ?: throw IllegalStateException("Nearby session is not authenticated")
        require(record.profile == profile && record.senderRole == localRole.peer) {
            "Nearby encrypted routing mismatch"
        }
        require(record.sessionId.contentEquals(session)) { "Nearby session mismatch" }
        require(record.sequence == inboundSequence) { "Nearby replay or reordering" }
        require(inboundSequence != -1L) { "Nearby sequence exhausted" }
        val ciphertext = record.ciphertextAndTag
        val plaintext = try {
            aesGcmNearby(Cipher.DECRYPT_MODE, key, nearbyNonce(record.senderRole, record.sequence),
                record.header(), ciphertext)
        } catch (failure: Exception) {
            throw IllegalArgumentException("Nearby authentication failed", failure)
        } finally {
            ciphertext.fill(0)
        }
        try {
            val message = IrohaPeerWireMessageV1.decode(plaintext, expectedProfile = profile)
            inboundSequence += 1
            return message
        } finally {
            plaintext.fill(0)
        }
    }

    /** Idempotently destroys the session and its owned key material. */
    @Synchronized
    fun destroy() = close()

    /** Idempotently destroys the session and its owned key material. */
    @Synchronized
    override fun close() {
        if (destroyed) return
        destroyed = true
        outboundKey?.fill(0)
        inboundKey?.fill(0)
        acceptedTranscriptHash?.fill(0)
        outboundKey = null
        inboundKey = null
        acceptedTranscriptHash = null
        peerHello = null
        hello = null
        authenticationInProgress = false
        outboundSequence = 0
        inboundSequence = 0
        ownedEphemeralKey?.close()
        ownedEphemeralKey = null
    }

    private fun transcriptHash(): ByteArray {
        val peer = peerHello ?: throw IllegalStateException("Nearby peer verification required")
        val local = hello ?: throw IllegalStateException("Nearby session has been destroyed")
        val senderHello = if (localRole == IrohaPeerNearbyRoleV1.SENDER) local else peer
        val receiverHello = if (localRole == IrohaPeerNearbyRoleV1.RECEIVER) local else peer
        val service = IrohaPeerNearbyV1.SERVICE_ID.toByteArray()
        val sender = senderHello.encode()
        val receiver = receiverHello.encode()
        return MessageDigest.getInstance("SHA-256").digest(ByteArrayOutputStream().also { output ->
            output.write(IrohaPeerNearbyV1.TRANSCRIPT_DOMAIN)
            output.writeU16(service.size)
            output.write(service)
            output.write(IrohaPeerNearbyV1.WIRE_VERSION)
            output.writeU16(profile.code)
            output.write(session)
            output.write(requestHash)
            output.writeU32(sender.size.toLong())
            output.write(sender)
            output.writeU32(receiver.size.toLong())
            output.write(receiver)
        }.toByteArray())
    }

    private fun checkNotDestroyed() {
        check(!destroyed) { "Nearby session has been destroyed" }
    }

    private fun <T> initializeOrClose(initializer: () -> T): T = try {
        initializer()
    } catch (failure: Throwable) {
        ownedEphemeralKey?.close()
        ownedEphemeralKey = null
        throw failure
    }
}

/**
 * Raw secp256r1 key agreement with canonical 65-byte X9.63 public keys.
 *
 * [close] is idempotent and drops the immutable [BigInteger] scalar reference. The JVM does not
 * expose a supported way to physically overwrite [BigInteger]'s opaque internal storage.
 */
class IrohaPeerNearbyP256V1 private constructor(privateBytes: ByteArray) : Closeable {
    private var scalar: BigInteger? = try {
        require(privateBytes.size == 32) { "Invalid P-256 private key" }
        BigInteger(1, privateBytes).also {
            require(it.signum() > 0 && it < PARAMETERS.n) { "Invalid P-256 private key" }
        }
    } finally {
        privateBytes.fill(0)
    }
    private val encodedPublicKey = PARAMETERS.g.multiply(requireNotNull(scalar)).normalize().getEncoded(false)
    private var destroyed = false

    val isDestroyed: Boolean
        @Synchronized get() = destroyed

    val publicKey: ByteArray
        @Synchronized get() {
            checkNotDestroyed()
            return encodedPublicKey.copyOf()
        }

    @Synchronized
    fun sharedSecret(peerPublicKey: ByteArray): ByteArray {
        checkNotDestroyed()
        require(isValidPublicKey(peerPublicKey)) { "Invalid Nearby P-256 key" }
        val keyScalar = scalar ?: throw IllegalStateException("Nearby P-256 key has been destroyed")
        val point = PARAMETERS.curve.decodePoint(peerPublicKey).multiply(keyScalar).normalize()
        require(!point.isInfinity) { "Invalid Nearby P-256 shared point" }
        return point.affineXCoord.encoded.leftPadNearby(32)
    }

    /** Idempotently drops this key's scalar and wipes its owned encoded-public-key buffer. */
    @Synchronized
    override fun close() {
        if (destroyed) return
        destroyed = true
        scalar = null
        encodedPublicKey.fill(0)
    }

    private fun checkNotDestroyed() {
        check(!destroyed) { "Nearby P-256 key has been destroyed" }
    }

    companion object {
        private val PARAMETERS = CustomNamedCurves.getByName("secp256r1")

        @JvmStatic fun generate(): IrohaPeerNearbyP256V1 {
            val random = SecureRandom()
            while (true) {
                val candidate = ByteArray(32).also(random::nextBytes)
                val scalar = BigInteger(1, candidate)
                if (scalar.signum() > 0 && scalar < PARAMETERS.n) return IrohaPeerNearbyP256V1(candidate)
                candidate.fill(0)
            }
        }

        @JvmStatic fun fromPrivateBytes(bytes: ByteArray): IrohaPeerNearbyP256V1 {
            require(bytes.size == 32) { "Invalid P-256 private key" }
            return IrohaPeerNearbyP256V1(bytes.copyOf())
        }

        internal fun isValidPublicKey(bytes: ByteArray): Boolean {
            if (bytes.size != 65 || bytes[0] != 0x04.toByte()) return false
            return try {
                val point = PARAMETERS.curve.decodePoint(bytes).normalize()
                !point.isInfinity && point.isValid
            } catch (_: RuntimeException) {
                false
            }
        }
    }
}

private fun deriveNearbyKey(shared: ByteArray, transcript: ByteArray, direction: String): ByteArray {
    val generator = HKDFBytesGenerator(SHA256Digest())
    generator.init(HKDFParameters(
        shared,
        transcript,
        IrohaPeerNearbyV1.KEY_DOMAIN + direction.toByteArray(),
    ))
    return ByteArray(32).also { generator.generateBytes(it, 0, it.size) }
}

private fun aesGcmNearby(
    mode: Int,
    key: ByteArray,
    nonce: ByteArray,
    aad: ByteArray,
    input: ByteArray,
): ByteArray = Cipher.getInstance("AES/GCM/NoPadding").run {
    init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
    updateAAD(aad)
    doFinal(input)
}

private fun nearbyNonce(role: IrohaPeerNearbyRoleV1, sequence: Long): ByteArray =
    ByteArrayOutputStream(12).also { output ->
        output.write(if (role == IrohaPeerNearbyRoleV1.SENDER) byteArrayOf(0x53, 0x32, 0x52, 0)
        else byteArrayOf(0x52, 0x32, 0x53, 0))
        output.writeU64(sequence)
    }.toByteArray()

private fun requireRecordPrefix(
    data: ByteArray,
    kind: IrohaPeerNearbyRecordKindV1,
    minimumLength: Int,
) {
    require(data.size >= minimumLength && data.copyOfRange(0, 4)
        .contentEquals(IrohaPeerNearbyV1.MAGIC)) { "Malformed IPN1 record" }
    require(data[4].toInt() and 0xff == IrohaPeerNearbyV1.WIRE_VERSION) {
        "Unsupported IPN1 version"
    }
    require(data[5].toInt() and 0xff == kind.code) { "Unexpected IPN1 record kind" }
}

private fun randomNearbyBytes(count: Int): ByteArray = ByteArray(count).also(SecureRandom()::nextBytes)

private fun randomNonzeroNearbyBytes(count: Int): ByteArray {
    while (true) {
        val candidate = randomNearbyBytes(count)
        if (candidate.any { it.toInt() != 0 }) return candidate
    }
}

private fun ByteArray.boundedNearbyCopy(minimum: Int, maximum: Int, name: String): ByteArray {
    require(size in minimum..maximum) { "$name length is outside its IPN1 bound" }
    return copyOf()
}

private fun ByteArray.leftPadNearby(size: Int): ByteArray {
    require(this.size <= size)
    return ByteArray(size).also { copyInto(it, size - this.size) }
}

private fun Long.checkedNearbyLength(maximum: Int): Int {
    require(this in 0..maximum.toLong()) { "IPN1 length exceeds bound" }
    return toInt()
}

private fun ByteArray.readU16Nearby(offset: Int): Int =
    ((this[offset].toInt() and 0xff) shl 8) or (this[offset + 1].toInt() and 0xff)

private fun ByteArray.readU32Nearby(offset: Int): Long =
    ((this[offset].toLong() and 0xff) shl 24) or
        ((this[offset + 1].toLong() and 0xff) shl 16) or
        ((this[offset + 2].toLong() and 0xff) shl 8) or
        (this[offset + 3].toLong() and 0xff)

private fun ByteArray.readU64Nearby(offset: Int): Long =
    (readU32Nearby(offset) shl 32) or readU32Nearby(offset + 4)

private fun ByteArrayOutputStream.writeU16(value: Int) {
    write(value ushr 8)
    write(value)
}

private fun ByteArrayOutputStream.writeU32(value: Long) {
    write((value ushr 24).toInt())
    write((value ushr 16).toInt())
    write((value ushr 8).toInt())
    write(value.toInt())
}

private fun ByteArrayOutputStream.writeU64(value: Long) {
    writeU32(value ushr 32)
    writeU32(value and 0xffff_ffffL)
}
