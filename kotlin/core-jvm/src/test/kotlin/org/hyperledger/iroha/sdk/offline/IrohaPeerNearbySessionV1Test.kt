package org.hyperledger.iroha.sdk.offline

import java.io.Closeable
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Paths
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.hyperledger.iroha.sdk.client.JsonParser

/** Authenticated hostile peers must not bypass the verified IPM1 application boundary. */
class IrohaPeerNearbySessionV1Test {
    @Test
    fun `both directions preserve shared fixtures and verified message ownership`() {
        AuthenticatedPair().use { pair ->
            for ((sequence, kind) in IrohaPeerPayloadKind.entries.withIndex()) {
                for ((sender, receiver) in listOf(pair.sender to pair.receiver, pair.receiver to pair.sender)) {
                    val message = fixture(kind)
                    val original = message.encode()
                    assertEquals(original.size, message.byteCount)
                    val record = sender.seal(message)
                    assertEquals(sequence.toLong(), record.sequence)
                    assertEquals(message.byteCount + 54, record.encode().size)
                    assertTrue(record.encode().size <= 32 * 1024)
                    val received = receiver.open(IrohaPeerNearbyEncryptedRecordV1.decode(record.encode()))
                    received.encodedBody.fill(0)
                    received.canonicalPayload.bytes.fill(0)
                    received.canonicalHash.fill(0)
                    record.ciphertextAndTag.fill(0)
                    assertEquals(message, received)
                    assertContentEquals(original, received.encode())
                    assertContentEquals(original, message.encode())
                }
            }
        }
    }

    @Test
    fun `compressed verified messages preserve canonical fixture bytes`() {
        AuthenticatedPair().use { pair ->
            val canonical = fixture(IrohaPeerPayloadKind.PAYMENT).canonicalPayload
            val message = IrohaPeerWireMessageV1(canonical, IrohaPeerWireCompressionPolicyV1.PEER_OPTIMIZED)
            assertEquals(IrohaPeerContentEncodingV1.ZLIB, message.encoding)
            assertEquals(message.encode().size, message.byteCount)
            val received = pair.receiver.open(pair.sender.seal(message))
            assertEquals(message, received)
            assertContentEquals(canonical.bytes, received.canonicalPayload.bytes)
        }
    }

    @Test
    fun `invalid authenticated plaintext does not consume the receive sequence`() {
        AuthenticatedPair().use { pair ->
            val original = fixture(IrohaPeerPayloadKind.PAYMENT).encode()
            val malformed = listOf(
                byteArrayOf(),
                "IPM1-payment-fixture".toByteArray(),
                original.copyOf().also { it[0] = 0 },
                original.copyOf().also { it[7] = 2 }, // Unknown profile, no second profile alias.
                original.copyOf().also { it[52] = (it[52].toInt() xor 1).toByte() },
                original.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() },
                original.copyOf().also { ByteBuffer.wrap(it, 12, 4).putInt(Int.MAX_VALUE) },
                original + byteArrayOf(0),
            )
            for (plaintext in malformed) {
                // A hostile fixture peer deliberately reuses sequence zero. It cannot consume
                // the receiver's sequence until the authenticated IPM1 plaintext validates.
                val record = pair.hostileSenderRecord(plaintext)
                assertFailsWith<IllegalArgumentException> { pair.receiver.open(record) }
            }
            val valid = fixture(IrohaPeerPayloadKind.PAYMENT)
            assertEquals(valid, pair.receiver.open(pair.sender.seal(valid)))
        }
    }

    @Test
    fun `tampering routing replay and reordering do not hide the next valid record`() {
        AuthenticatedPair().use { pair ->
            val message = fixture(IrohaPeerPayloadKind.REQUEST)
            val first = pair.sender.seal(message)
            val second = pair.sender.seal(message)
            val tampered = first.ciphertextAndTag.also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
            val invalid = listOf(
                second,
                IrohaPeerNearbyEncryptedRecordV1(PROFILE, IrohaPeerNearbyRoleV1.RECEIVER,
                    first.sessionId, first.sequence, first.ciphertextAndTag),
                IrohaPeerNearbyEncryptedRecordV1(PROFILE, first.senderRole,
                    ByteArray(16) { 9 }, first.sequence, first.ciphertextAndTag),
                IrohaPeerNearbyEncryptedRecordV1(PROFILE, first.senderRole,
                    first.sessionId, first.sequence, tampered),
            )
            invalid.forEach { record -> assertFailsWith<IllegalArgumentException> { pair.receiver.open(record) } }
            assertEquals(message, pair.receiver.open(first))
            assertFailsWith<IllegalArgumentException> { pair.receiver.open(first) }
            assertEquals(message, pair.receiver.open(second))
            assertFailsWith<IllegalArgumentException> { pair.receiver.open(second) }
        }
    }

    @Test
    fun `record bounds reject malformed lengths and unknown profile before allocation`() {
        AuthenticatedPair().use { pair ->
            val encoded = pair.sender.seal(fixture(IrohaPeerPayloadKind.PAYMENT)).encode()
            for (invalid in listOf(
                encoded.copyOf(53),
                encoded + byteArrayOf(0),
                encoded.copyOf().also { it[7] = 2 },
                encoded.copyOf().also { ByteBuffer.wrap(it, 34, 4).putInt(Int.MAX_VALUE) },
            )) {
                assertFailsWith<IllegalArgumentException> { IrohaPeerNearbyEncryptedRecordV1.decode(invalid) }
            }
            for (size in listOf(15, IrohaPeerNearbyV1.MAXIMUM_MESSAGE_BYTES + 17)) {
                assertFailsWith<IllegalArgumentException> {
                    IrohaPeerNearbyEncryptedRecordV1(PROFILE, IrohaPeerNearbyRoleV1.SENDER,
                        pair.sender.sessionId, 0, ByteArray(size))
                }
            }
        }
    }

    @Test
    fun `failed authentication can be corrected and successful authentication cannot replay`() {
        AuthenticatedPair(authenticate = false).use { pair ->
            val message = fixture(IrohaPeerPayloadKind.REQUEST)
            assertFailsWith<IllegalStateException> { pair.sender.seal(message) }
            val auth = pair.authentication(pair.receiver, RECEIVER_SIGNER)
            val invalid = IrohaPeerNearbyAuthenticationV1(PROFILE, auth.role, auth.sessionId,
                auth.transcriptHash, auth.signature.also { it[0] = (it[0].toInt() xor 1).toByte() })
            assertFailsWith<IllegalArgumentException> { pair.sender.acceptPeerAuthentication(invalid, VERIFIER) }
            assertFalse(pair.sender.isAuthenticated)
            pair.authenticate()
            assertTrue(pair.senderEphemeral.isDestroyed)
            assertTrue(pair.receiverEphemeral.isDestroyed)
            assertFailsWith<IllegalArgumentException> { pair.sender.acceptPeerAuthentication(auth, VERIFIER) }
            assertEquals(message, pair.receiver.open(pair.sender.seal(message)))
        }
    }

    @Test
    fun `session destruction during verification is final and closes owned key`() {
        AuthenticatedPair(authenticate = false).use { pair ->
            val auth = pair.authentication(pair.receiver, RECEIVER_SIGNER)
            assertFailsWith<IllegalStateException> {
                pair.sender.acceptPeerAuthentication(auth) { _, _, _, _ ->
                    pair.sender.close()
                    true
                }
            }
            assertTrue(pair.sender.isDestroyed)
            assertTrue(pair.senderEphemeral.isDestroyed)
            assertFalse(pair.sender.isAuthenticated)
            pair.sender.destroy()
            assertFailsWith<IllegalStateException> { pair.sender.localHello }
            assertFailsWith<IllegalStateException> { pair.sender.seal(fixture(IrohaPeerPayloadKind.REQUEST)) }
        }
        val key = IrohaPeerNearbyP256V1.fromPrivateBytes(ByteArray(32) { 1 })
        assertFailsWith<IllegalArgumentException> {
            IrohaPeerNearbySessionV1(PROFILE, IrohaPeerNearbyRoleV1.SENDER, ByteArray(15),
                ByteArray(32) { 1 }, byteArrayOf(1), ephemeralKey = key)
        }
        assertTrue(key.isDestroyed)
    }

    private class AuthenticatedPair(authenticate: Boolean = true) : Closeable {
        val senderEphemeral = IrohaPeerNearbyP256V1.fromPrivateBytes(ByteArray(32) { 1 })
        val receiverEphemeral = IrohaPeerNearbyP256V1.fromPrivateBytes(ByteArray(32) { 2 })
        val sender = IrohaPeerNearbySessionV1(PROFILE, IrohaPeerNearbyRoleV1.SENDER,
            ByteArray(16) { 3 }, ByteArray(32) { 4 }, SENDER_SIGNER.generatePublicKey().encoded,
            ByteArray(32) { 5 }, senderEphemeral)
        val receiver = IrohaPeerNearbySessionV1(PROFILE, IrohaPeerNearbyRoleV1.RECEIVER,
            ByteArray(16) { 3 }, ByteArray(32) { 4 }, RECEIVER_SIGNER.generatePublicKey().encoded,
            ByteArray(32) { 6 }, receiverEphemeral)
        private val shared = senderEphemeral.sharedSecret(receiverEphemeral.publicKey)
        private lateinit var transcript: ByteArray

        init {
            sender.acceptPeerHello(receiver.localHello)
            receiver.acceptPeerHello(sender.localHello)
            if (authenticate) authenticate()
        }

        fun authentication(session: IrohaPeerNearbySessionV1, signerKey: Ed25519PrivateKeyParameters): IrohaPeerNearbyAuthenticationV1 {
            val bytes = session.authenticationPreimage()
            val signer = Ed25519Signer()
            signer.init(true, signerKey)
            signer.update(bytes, 0, bytes.size)
            return session.makeAuthentication(signer.generateSignature())
        }

        fun authenticate() {
            val senderAuth = authentication(sender, SENDER_SIGNER)
            val receiverAuth = authentication(receiver, RECEIVER_SIGNER)
            transcript = senderAuth.transcriptHash
            sender.acceptPeerAuthentication(receiverAuth, VERIFIER)
            receiver.acceptPeerAuthentication(senderAuth, VERIFIER)
        }

        /** Independent JCA HKDF/GCM construction models an authenticated hostile sender. */
        fun hostileSenderRecord(plaintext: ByteArray): IrohaPeerNearbyEncryptedRecordV1 {
            fun hmac(key: ByteArray, data: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(key, "HmacSHA256"))
                doFinal(data)
            }
            val prk = hmac(transcript, shared)
            val key = hmac(prk, "IROHA-PEER-NEARBY-KEYS-V1\u0000sender-to-receiver".toByteArray() + byteArrayOf(1))
            try {
                val placeholder = IrohaPeerNearbyEncryptedRecordV1(PROFILE, IrohaPeerNearbyRoleV1.SENDER,
                    sender.sessionId, 0, ByteArray(plaintext.size + 16))
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"),
                    GCMParameterSpec(128, byteArrayOf(0x53, 0x32, 0x52, 0) + ByteArray(8)))
                cipher.updateAAD(placeholder.encode().copyOf(38))
                return IrohaPeerNearbyEncryptedRecordV1(PROFILE, IrohaPeerNearbyRoleV1.SENDER,
                    sender.sessionId, 0, cipher.doFinal(plaintext))
            } finally {
                prk.fill(0)
                key.fill(0)
            }
        }

        override fun close() {
            sender.close()
            receiver.close()
            shared.fill(0)
            if (::transcript.isInitialized) transcript.fill(0)
        }
    }

    companion object {
        private val PROFILE = IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1
        private val SENDER_SIGNER = Ed25519PrivateKeyParameters(ByteArray(32) { 7 }, 0)
        private val RECEIVER_SIGNER = Ed25519PrivateKeyParameters(ByteArray(32) { 8 }, 0)
        private val VERIFIER = IrohaPeerNearbySignatureVerifierV1 { role, certificate, bytes, signature ->
            val trusted = if (role == IrohaPeerNearbyRoleV1.SENDER) SENDER_SIGNER else RECEIVER_SIGNER
            if (!certificate.contentEquals(trusted.generatePublicKey().encoded)) {
                false
            } else {
                val verifier = Ed25519Signer()
                verifier.init(false, Ed25519PublicKeyParameters(certificate, 0))
                verifier.update(bytes, 0, bytes.size)
                verifier.verifySignature(signature)
            }
        }

        /** First `fixtures/kagemusha/wallet_v1_vectors.json` envelope of [kind], wrapped in IPM1. */
        private fun fixture(kind: IrohaPeerPayloadKind): IrohaPeerWireMessageV1 {
            var root = Paths.get("").toAbsolutePath()
            while (root != null && !Files.isRegularFile(root.resolve("fixtures/kagemusha/wallet_v1_vectors.json"))) {
                root = root.parent
            }
            val json = JsonParser.parse(String(Files.readAllBytes(
                requireNotNull(root).resolve("fixtures/kagemusha/wallet_v1_vectors.json")), Charsets.UTF_8)) as Map<*, *>
            val vector = (json["envelopes"] as List<*>).map { it as Map<*, *> }
                .first { (it["tag"] as Number).toInt() == kind.code }
            val hex = vector["canonical_hex"] as String
            val bytes = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            return IrohaPeerWireMessageV1(IrohaPeerCanonicalPayload(PROFILE, kind, 1, IrohaPeerRequestFixtureV1.payload(kind, bytes)))
        }
    }
}
