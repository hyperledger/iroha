// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline.wallet

import android.content.pm.ApplicationInfo
import android.security.keystore.KeyProperties
import java.io.File
import java.security.InvalidKeyException
import java.security.MessageDigest
import java.security.ProviderException
import java.security.Signature
import java.security.SignatureException
import java.security.UnrecoverableKeyException
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.offline.KagemushaP256Codec
import org.junit.jupiter.api.Test

class KagemushaWalletAndroidPaymentKeyV1Test {
    private val keyStore = TestKeyStoreV1()
    private val environment = TestEnvironmentV1(File("."))
    private val paymentKey = KagemushaWalletAndroidPaymentKeyV1(keyStore, environment)

    private var nextSlot = 1
    private fun slot(): ByteArray = ByteArray(32) { (nextSlot + it).toByte() }.also { nextSlot += 1 }
    private val challenge = ByteArray(32) { (0x40 + it).toByte() }
    private fun alias(slot: ByteArray) = kagemushaWalletAndroidAliasV1(slot)

    /**
     * The 32-byte Poseidon signing message `m = P_bytes(kgwrcpt1, transcript)` of the vectored
     * Send receipt (`fixtures/kagemusha/wallet_v1_vectors.json`): what the Rust receipt signer
     * hands to `key_sign`.
     */
    private val message = "a5e8b32421e17595040cdcdeeaf46f06da85291d68cff8e05dab8bfc64a96a2d"
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun platformCode(code: Int) = KagemushaWalletAndroidUnavailableV1.platform(code)

    private fun assertGenerationUnavailable(
        expected: KagemushaWalletAndroidUnavailableV1,
        result: KagemushaWalletAndroidKeyGenerationV1,
    ) {
        assertEquals(expected, assertIs<KagemushaWalletAndroidKeyGenerationV1.Unavailable>(result).reason)
    }

    @Test fun `alias is the fixed prefix and the lowercase hex of a nonzero 32-byte slot`() {
        val slot = ByteArray(32) { (0xa0 + it).toByte() }
        val alias = alias(slot)
        assertEquals("kgm-w1-" + slot.joinToString("") { "%02x".format(it.toInt() and 0xff) }, alias)
        assertFailsWith<IllegalArgumentException> { alias(ByteArray(32)) }
        assertFailsWith<IllegalArgumentException> { alias(ByteArray(31) { 1 }) }
        assertFailsWith<IllegalArgumentException> { alias(ByteArray(33) { 1 }) }
    }

    @Test fun `probe is absent only for a null getKey and present with the attested leaf key`() {
        val slot = slot()
        assertSame(KagemushaWalletAndroidKeyProbeV1.Absent, paymentKey.probe(slot))
        val entry = keyStore.seed(alias(slot))
        val present = assertIs<KagemushaWalletAndroidKeyProbeV1.Present>(paymentKey.probe(slot))
        assertContentEquals(testSec1V1(entry.pair.public), present.publicKeySec1())
        present.publicKeySec1().fill(0)
        assertContentEquals(testSec1V1(entry.pair.public), present.publicKeySec1())
    }

    @Test fun `every Keystore error is unavailable and never absence`() {
        val slot = slot()
        keyStore.getKeyFailure = UnrecoverableKeyException("keystore2 SYSTEM_ERROR")
        assertEquals(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE),
            assertIs<KagemushaWalletAndroidKeyProbeV1.Unavailable>(paymentKey.probe(slot)).reason,
        )
        // AOSP keystore2 engineGetKey rethrows KeyPermanentlyInvalidatedException as an
        // UnrecoverableKeyException carrying only the message, so the probe cannot name it.
        keyStore.getKeyFailure = UnrecoverableKeyException("Key permanently invalidated")
        assertEquals(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE),
            assertIs<KagemushaWalletAndroidKeyProbeV1.Unavailable>(paymentKey.probe(slot)).reason,
        )
        keyStore.getKeyFailure = OutOfMemoryError("binder buffer")
        assertIs<KagemushaWalletAndroidKeyProbeV1.Unavailable>(paymentKey.probe(slot))
        keyStore.getKeyFailure = null
        val entry = keyStore.seed(alias(slot))
        keyStore.nullChain = true
        assertEquals(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_CERTIFICATE),
            assertIs<KagemushaWalletAndroidKeyProbeV1.Unavailable>(paymentKey.probe(slot)).reason,
        )
        keyStore.nullChain = false
        keyStore.chainFailure = IllegalStateException("certificate read failed")
        assertIs<KagemushaWalletAndroidKeyProbeV1.Unavailable>(paymentKey.probe(slot))
        keyStore.chainFailure = null
        entry.chain = listOf(entry.chain!!.first())
        assertEquals(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_CERTIFICATE),
            assertIs<KagemushaWalletAndroidKeyProbeV1.Unavailable>(paymentKey.probe(slot)).reason,
        )
        // A chain without the attestation extension names no attested key.
        val root = keyStore.seed("kgm-w1-other").chain!![1]
        entry.chain = listOf(root, root)
        assertEquals(
            KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE,
            assertIs<KagemushaWalletAndroidKeyProbeV1.Unavailable>(paymentKey.probe(slot)).reason,
        )
        keyStore.getKeyResult = javax.crypto.spec.SecretKeySpec(ByteArray(16), "AES")
        assertEquals(
            KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE,
            assertIs<KagemushaWalletAndroidKeyProbeV1.Unavailable>(paymentKey.probe(slot)).reason,
        )
    }

    private fun apiLevel(api: Int) {
        environment.apiLevel = api
        keyStore.apiLevel = api
    }

    private fun fresh(slot: ByteArray, digest: ByteArray = challenge) = paymentKey.generateFreshFromNative(slot, digest)

    /** A new, distinct nonzero E1 challenge digest, as every fresh enrollment receives. */
    private var nextChallenge = 0x60
    private fun newChallenge(): ByteArray = ByteArray(32) { (nextChallenge + it).toByte() }.also { nextChallenge += 1 }

    @Test fun `API 26 through 30 null never authorizes ordinary generation signing or deletion`() {
        for (api in 26..30) {
            apiLevel(api)
            val empty = slot()
            val unknown = platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEY_ABSENCE_UNKNOWN)
            assertEquals(unknown, assertIs<KagemushaWalletAndroidKeyProbeV1.Unavailable>(paymentKey.probe(empty)).reason)
            assertGenerationUnavailable(unknown, paymentKey.generate(empty, challenge))
            assertEquals(unknown, assertIs<KagemushaWalletAndroidAttestationChainV1.Unavailable>(paymentKey.attestationChain(empty)).reason)
            assertEquals(unknown, assertIs<KagemushaWalletAndroidSignatureV1.Unavailable>(paymentKey.sign(empty, message)).reason)
            assertEquals(
                platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE_UNSUPPORTED),
                assertIs<KagemushaWalletAndroidRemoveV1.Uncertain>(paymentKey.delete(empty)).reason,
            )
        }
        assertTrue(keyStore.generated.isEmpty())
        assertEquals(0, keyStore.signCalls)
        assertEquals(0, keyStore.deleteCalls)
    }

    @Test fun `API 26 through 30 present existing keys remain usable and masked failures never replace them`() {
        for (api in 26..30) {
            apiLevel(api)
            val slot = slot()
            val original = keyStore.seed(alias(slot))
            assertContentEquals(testSec1V1(original.pair.public), assertIs<KagemushaWalletAndroidKeyProbeV1.Present>(paymentKey.probe(slot)).publicKeySec1())
            assertIs<KagemushaWalletAndroidAttestationChainV1.Present>(paymentKey.attestationChain(slot))
            assertIs<KagemushaWalletAndroidSignatureV1.Der>(paymentKey.sign(slot, message))
            keyStore.getKeyReturnsNull = true
            assertIs<KagemushaWalletAndroidKeyProbeV1.Unavailable>(paymentKey.probe(slot))
            assertIs<KagemushaWalletAndroidSignatureV1.Unavailable>(paymentKey.sign(slot, message))
            assertSame(KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent, fresh(slot))
            keyStore.getKeyReturnsNull = false
            assertSame(original, keyStore.entries.getValue(alias(slot)))
            assertIs<KagemushaWalletAndroidSignatureV1.Der>(paymentKey.sign(slot, message))
        }
        assertTrue(keyStore.generated.isEmpty())
        assertEquals(0, keyStore.deleteCalls)
    }

    @Test fun `fresh Native attempts bind TEE on API 26 and 27 and StrongBox when available on 28 through 30`() {
        for (api in 26..30) {
            apiLevel(api)
            val slot = slot()
            val generated = assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(fresh(slot))
            val strongBox = api >= 28
            assertEquals(strongBox, keyStore.generated.last().strongBox)
            assertEquals(alias(slot), keyStore.generated.last().alias)
            assertContentEquals(challenge, keyStore.generated.last().challengeDigest())
            assertEquals(
                if (strongBox) KagemushaWalletAndroidSecurityLevelV1.STRONGBOX else KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT,
                generated.securityLevel,
            )
            assertContentEquals(testSec1V1(keyStore.entries.getValue(alias(slot)).pair.public), generated.publicKeySec1())
            assertSame(KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent, fresh(slot))
        }
        assertEquals(5, keyStore.generated.size)
        apiLevel(31)
        assertGenerationUnavailable(platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE_UNSUPPORTED), fresh(slot()))
        assertEquals(5, keyStore.generated.size)
    }

    @Test fun `a TEE-only phone enrolls in its TEE on every API with no refusal plan`() {
        environment.strongBox = false
        for (api in 26..33) {
            apiLevel(api)
            val outcome = if (api < 31) fresh(slot()) else paymentKey.generate(slot(), challenge)
            assertEquals(KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT,
                assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(outcome).securityLevel, "API $api")
        }
        assertEquals(List(8) { false }, keyStore.generated.map { it.strongBox })
    }

    @Test fun `fresh readback failure retains the generated key and never regenerates after recovery`() {
        apiLevel(26)
        val slot = slot()
        keyStore.getKeyFailureAfterGenerations = 1
        assertGenerationUnavailable(platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE), fresh(slot))
        val original = keyStore.entries.getValue(alias(slot))
        keyStore.getKeyFailureAfterGenerations = Int.MAX_VALUE
        assertSame(KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent, fresh(slot))
        assertSame(original, keyStore.entries.getValue(alias(slot)))
        assertEquals(1, keyStore.generated.size)
        assertEquals(0, keyStore.deleteCalls)
    }

    @Test fun `actual generation returns survive each fallible readback without another generation`() {
        for (api in listOf(26, 33)) for (failure in 0..2) {
            apiLevel(api)
            val slot = slot()
            val before = keyStore.generated.size
            when (failure) {
                0 -> keyStore.getKeyFailureAfterGenerations = before + 1
                1 -> keyStore.chainFailure = ProviderException("chain read unavailable")
                2 -> keyStore.factsFailure = ProviderException("KeyInfo unavailable")
            }
            val first = if (api < 31) fresh(slot) else paymentKey.generate(slot, challenge)
            assertIs<KagemushaWalletAndroidKeyGenerationV1.Unavailable>(first)
            val original = keyStore.entries.getValue(alias(slot))
            assertIs<KagemushaWalletAndroidKeyGenerationV1.Unavailable>(paymentKey.recoverGeneration(slot, challenge))
            assertEquals(before + 1, keyStore.generated.size)
            keyStore.getKeyFailureAfterGenerations = Int.MAX_VALUE
            keyStore.chainFailure = null
            keyStore.factsFailure = null
            repeat(2) {
                val recovered = assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(paymentKey.recoverGeneration(slot, challenge))
                assertContentEquals(testSec1V1(original.pair.public), recovered.publicKeySec1())
            }
            assertSame(original, keyStore.entries.getValue(alias(slot)))
            assertEquals(before + 1, keyStore.generated.size)
        }
        assertEquals(0, keyStore.deleteCalls)
        assertEquals(0, keyStore.signCalls)
    }

    @Test fun `generation recovery binds the exact request and actual returned key`() {
        apiLevel(26)
        val slot = slot()
        val requested = challenge.copyOf()
        keyStore.factsFailure = ProviderException("readback failed")
        assertIs<KagemushaWalletAndroidKeyGenerationV1.Unavailable>(paymentKey.generateFreshFromNative(slot, requested))
        val original = keyStore.entries.getValue(alias(slot))
        requested[0] = (requested[0].toInt() xor 1).toByte()
        keyStore.factsFailure = null
        assertIs<KagemushaWalletAndroidKeyGenerationV1.Unavailable>(paymentKey.recoverGeneration(slot, requested))
        assertNull(paymentKey.recoverGeneration(this.slot(), challenge))
        // A fully valid attestation for a replacement key and the same challenge is insufficient.
        keyStore.seed(alias(slot), challenge)
        assertIs<KagemushaWalletAndroidKeyGenerationV1.Unavailable>(paymentKey.recoverGeneration(slot, challenge))
        keyStore.entries[alias(slot)] = original
        val recovered = assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(paymentKey.recoverGeneration(slot, challenge))
        assertContentEquals(testSec1V1(original.pair.public), recovered.publicKeySec1())
        assertEquals(1, keyStore.generated.size)
        assertEquals(0, keyStore.deleteCalls)
    }

    @Test fun `key presence and a throwing generator never become successful generation replies`() {
        apiLevel(26)
        val existing = slot()
        keyStore.seed(alias(existing), challenge)
        assertNull(paymentKey.recoverGeneration(existing, challenge))
        val thrown = slot()
        keyStore.generateFailureAfterWrite = ProviderException("provider reply lost")
        assertIs<KagemushaWalletAndroidKeyGenerationV1.Unavailable>(fresh(thrown))
        keyStore.generateFailureAfterWrite = null
        assertTrue(keyStore.entries.containsKey(alias(thrown)))
        assertNull(paymentKey.recoverGeneration(thrown, challenge))
        val returned = slot()
        assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(fresh(returned))
        val reopened = KagemushaWalletAndroidPaymentKeyV1(keyStore, environment)
        assertNull(reopened.recoverGeneration(returned, challenge))
        assertEquals(2, keyStore.generated.size)
        assertEquals(0, keyStore.deleteCalls)
    }

    @Test fun `fresh Native attempts never overwrite any raw occupied entry even with invalid chain or key kind`() {
        apiLevel(26)
        val occupied = slot()
        val original = keyStore.seed(alias(occupied))
        original.chain = null
        assertSame(KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent, fresh(occupied))
        assertSame(original, keyStore.entries.getValue(alias(occupied)))
        keyStore.getKeyResult = javax.crypto.spec.SecretKeySpec(ByteArray(16), "AES")
        assertSame(KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent, fresh(slot()))
        assertTrue(keyStore.generated.isEmpty())
        assertEquals(0, keyStore.deleteCalls)
    }

    @Test fun `a throwing fresh probe consumes the alias and never generates even after recovery`() {
        apiLevel(26)
        val slot = slot()
        keyStore.getKeyFailure = UnrecoverableKeyException("keystore daemon unavailable")
        assertGenerationUnavailable(platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE), fresh(slot))
        keyStore.getKeyFailure = null
        assertSame(KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent, fresh(slot))
        assertTrue(keyStore.generated.isEmpty())
    }

    @Test fun `fresh generation failures before or after key creation never retry the alias`() {
        apiLevel(26)
        for (afterWrite in listOf(false, true)) {
            val slot = slot()
            if (afterWrite) keyStore.generateFailureAfterWrite = ProviderException("provider reply lost")
            else keyStore.generateFailure = ProviderException("provider failed")
            assertGenerationUnavailable(platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_GENERATION_FAILED), fresh(slot))
            val original = keyStore.entries[alias(slot)]
            assertEquals(afterWrite, original != null)
            keyStore.generateFailure = null
            keyStore.generateFailureAfterWrite = null
            assertSame(KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent, fresh(slot))
            assertSame(original, keyStore.entries[alias(slot)])
        }
        assertEquals(2, keyStore.generated.size)
        assertEquals(0, keyStore.deleteCalls)
    }

    @Test fun `fresh StrongBox failure permits one new slot TEE attempt but never an old alias retry`() {
        for (api in 28..30) {
            apiLevel(api)
            keyStore.strongBoxAvailable = false
            val failed = slot()
            assertGenerationUnavailable(platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_STRONGBOX_UNAVAILABLE), fresh(failed))
            keyStore.strongBoxAvailable = true
            assertSame(KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent, fresh(failed))
            // The abandoned attempt's fresh successor: a new slot under a new challenge.
            val next = slot()
            assertEquals(KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT,
                assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(fresh(next, newChallenge())).securityLevel)
            assertSame(KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent, fresh(next, newChallenge()))
            assertEquals(KagemushaWalletAndroidSecurityLevelV1.STRONGBOX,
                assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(fresh(slot(), newChallenge())).securityLevel)
        }
        assertEquals(listOf(true, false, true, true, false, true, true, false, true), keyStore.generated.map { it.strongBox })
    }

    @Test fun `the TEE hint carries only into a fresh slot under a new challenge and never reuses the old one`() {
        for (api in listOf(28, 33)) {
            val store = TestKeyStoreV1().apply { apiLevel = api; strongBoxAvailable = false }
            val key = KagemushaWalletAndroidPaymentKeyV1(store, TestEnvironmentV1(File(".")).apply { apiLevel = api })
            fun generate(slot: ByteArray, digest: ByteArray) =
                if (api < 31) key.generateFreshFromNative(slot, digest) else key.generate(slot, digest)
            assertGenerationUnavailable(platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_STRONGBOX_UNAVAILABLE), generate(slot(), challenge))
            store.strongBoxAvailable = true
            // A different slot under the failed (old) challenge does not receive the hint.
            assertEquals(KagemushaWalletAndroidSecurityLevelV1.STRONGBOX,
                assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(generate(slot(), challenge)).securityLevel, "API $api")
            // The hint is still unspent: a fresh slot under a new challenge generates in the TEE once.
            assertEquals(KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT,
                assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(generate(slot(), newChallenge())).securityLevel, "API $api")
            assertEquals(KagemushaWalletAndroidSecurityLevelV1.STRONGBOX,
                assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(generate(slot(), newChallenge())).securityLevel, "API $api")
            assertEquals(listOf(true, true, false, true), store.generated.map { it.strongBox }, "API $api")
        }
    }

    @Test fun `fresh TEE hint is spent by the next matching attempt even when its probe fails`() {
        apiLevel(28)
        keyStore.strongBoxAvailable = false
        assertIs<KagemushaWalletAndroidKeyGenerationV1.Unavailable>(fresh(slot()))
        keyStore.strongBoxAvailable = true
        keyStore.getKeyFailure = ProviderException("lookup unavailable")
        val failed = slot()
        val successor = newChallenge()
        assertGenerationUnavailable(platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE), fresh(failed, successor))
        keyStore.getKeyFailure = null
        assertSame(KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent, fresh(failed, successor))
        assertEquals(KagemushaWalletAndroidSecurityLevelV1.STRONGBOX,
            assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(fresh(slot(), newChallenge())).securityLevel)
        assertEquals(listOf(true, true), keyStore.generated.map { it.strongBox })
    }

    @Test fun `lookup generic generation and readback errors never create a TEE hint`() {
        for (failure in listOf("lookup", "generation", "readback", "attestation")) {
            val environment = TestEnvironmentV1(File(".")).apply { apiLevel = 28 }
            val store = TestKeyStoreV1().apply { apiLevel = 28 }
            val key = KagemushaWalletAndroidPaymentKeyV1(store, environment)
            when (failure) {
                "lookup" -> store.getKeyFailure = ProviderException("lookup unavailable")
                "generation" -> store.generateFailure = ProviderException("generation unavailable")
                "readback" -> store.getKeyFailureAfterGenerations = 1
                "attestation" -> store.attestedChallenge = ByteArray(32) { 9 }
            }
            assertIs<KagemushaWalletAndroidKeyGenerationV1.Unavailable>(key.generateFreshFromNative(slot(), challenge))
            store.getKeyFailure = null
            store.generateFailure = null
            store.getKeyFailureAfterGenerations = Int.MAX_VALUE
            store.attestedChallenge = null
            assertEquals(KagemushaWalletAndroidSecurityLevelV1.STRONGBOX,
                assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(key.generateFreshFromNative(slot(), newChallenge())).securityLevel, failure)
            assertTrue(store.generated.all { it.strongBox }, failure)
        }
    }

    @Test fun `a new platform owner does not reconstruct an earlier TEE hint`() {
        apiLevel(28)
        keyStore.strongBoxAvailable = false
        assertIs<KagemushaWalletAndroidKeyGenerationV1.Unavailable>(fresh(slot()))
        val reopened = KagemushaWalletAndroidPaymentKeyV1(keyStore, environment)
        assertGenerationUnavailable(platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_STRONGBOX_UNAVAILABLE),
            reopened.generateFreshFromNative(slot(), newChallenge()))
        assertEquals(listOf(true, true), keyStore.generated.map { it.strongBox })
    }

    @Test fun `fresh attempts preserve authenticated readback and leave rejected keys in place`() {
        apiLevel(26)
        val edits: List<(TestKeyDescriptionV1) -> TestKeyDescriptionV1> = listOf(
            { it.copy(attestationLevel = 0, keymasterLevel = 0) },
            { it.copy(hardware = it.hardware + (405 to TestDerV1.integer(1))) },
            { it.copy(software = mapOf(1 to it.hardware.getValue(1)), hardware = it.hardware - 1) },
        )
        for (edit in edits) {
            keyStore.descriptionEdit = edit
            val slot = slot()
            assertGenerationUnavailable(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE, fresh(slot))
            val original = keyStore.entries.getValue(alias(slot))
            assertSame(KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent, fresh(slot))
            assertSame(original, keyStore.entries.getValue(alias(slot)))
        }
        keyStore.descriptionEdit = { it }
        keyStore.attestedChallenge = ByteArray(32) { 9 }
        assertGenerationUnavailable(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE, fresh(slot()))
        keyStore.attestedChallenge = null
        keyStore.factsEdit = { it.copy(insideSecureHardware = false) }
        assertGenerationUnavailable(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE, fresh(slot()))
        assertEquals(0, keyStore.deleteCalls)
    }

    @Test fun `fresh attempts refuse unavailable storage and backup configuration before Keystore`() {
        apiLevel(26)
        environment.unlocked = false
        assertGenerationUnavailable(KagemushaWalletAndroidUnavailableV1.BEFORE_FIRST_UNLOCK, fresh(slot()))
        environment.unlocked = true
        environment.flags = ApplicationInfo.FLAG_ALLOW_BACKUP
        assertGenerationUnavailable(platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_BACKUP_ENABLED), fresh(slot()))
        assertEquals(0, keyStore.getKeyCalls)
        assertTrue(keyStore.generated.isEmpty())
    }

    @Test fun `a TEE key is generated with the exact non-authenticated spec and read back`() {
        environment.strongBox = false
        val slot = slot()
        val generated = assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(
            paymentKey.generate(slot, challenge),
        )
        assertEquals(KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT, generated.securityLevel)
        val spec = keyStore.generated.single()
        assertEquals(alias(slot), spec.alias)
        assertContentEquals(challenge, spec.challengeDigest())
        assertFalse(spec.strongBox)
        assertEquals("secp256r1", spec.curve)
        assertEquals(KeyProperties.PURPOSE_SIGN, spec.purposes)
        assertEquals(listOf(KeyProperties.DIGEST_SHA256), spec.digests)
        val entry = keyStore.entries.getValue(alias(slot))
        assertContentEquals(testSec1V1(entry.pair.public), generated.publicKeySec1())
    }

    @Test fun `the key spec reaches the platform builder only through the four permitted setters`() {
        class Recording : KagemushaWalletAndroidKeyGenBuilderV1 {
            val calls = ArrayList<String>()
            override fun algorithmParameterSpec(curve: String) { calls += "curve:$curve" }
            override fun digests(digests: List<String>) { calls += "digests:$digests" }
            override fun attestationChallenge(challenge: ByteArray) { calls += "challenge:${challenge.toList()}" }
            override fun strongBoxBacked() { calls += "strongbox" }
        }
        val alias = alias(slot())
        val tee = Recording().also { kagemushaWalletAndroidConfigureKeyGenV1(KagemushaWalletAndroidKeySpecV1(alias, challenge, false), it) }
        assertEquals(
            listOf("curve:secp256r1", "digests:[SHA-256]", "challenge:${challenge.toList()}"),
            tee.calls,
        )
        val strong = Recording().also { kagemushaWalletAndroidConfigureKeyGenV1(KagemushaWalletAndroidKeySpecV1(alias, challenge, true), it) }
        assertEquals(tee.calls + "strongbox", strong.calls)
        assertFailsWith<IllegalArgumentException> { KagemushaWalletAndroidKeySpecV1("other", challenge, false) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletAndroidKeySpecV1(alias, ByteArray(31), false) }
    }

    @Test fun `StrongBox is used when present and a StrongBox failure spends the slot without a same-slot TEE retry`() {
        val first = slot()
        val strong = assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(paymentKey.generate(first, challenge))
        assertEquals(KagemushaWalletAndroidSecurityLevelV1.STRONGBOX, strong.securityLevel)
        assertTrue(keyStore.generated.single().strongBox)

        keyStore.strongBoxAvailable = false
        val second = slot()
        val refused = platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_STRONGBOX_UNAVAILABLE)
        assertGenerationUnavailable(refused, paymentKey.generate(second, challenge))
        assertEquals(listOf(true, true), keyStore.generated.map { it.strongBox })
        assertFalse(keyStore.entries.containsKey(alias(second)))
        // The spent slot answers the same refusal on every retry, even once StrongBox recovers,
        // and is never generated again: no TEE on the same alias, grant or challenge.
        keyStore.strongBoxAvailable = true
        val reads = keyStore.getKeyCalls
        repeat(2) { assertGenerationUnavailable(refused, paymentKey.generate(second, challenge)) }
        assertGenerationUnavailable(refused, paymentKey.generate(second, newChallenge()))
        assertEquals(reads, keyStore.getKeyCalls)
        assertEquals(2, keyStore.generated.size)
        // Only the abandoned attempt's fresh successor, a new slot under a new challenge, uses the TEE.
        assertEquals(KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT,
            assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(paymentKey.generate(slot(), newChallenge())).securityLevel)
        assertEquals(KagemushaWalletAndroidSecurityLevelV1.STRONGBOX,
            assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(paymentKey.generate(slot(), newChallenge())).securityLevel)
        assertEquals(listOf(true, true, false, true), keyStore.generated.map { it.strongBox })
    }

    @Test fun `a phone without StrongBox never attempts StrongBox`() {
        environment.strongBox = false
        val tee = assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(paymentKey.generate(slot(), challenge))
        assertEquals(KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT, tee.securityLevel)
        assertEquals(listOf(false), keyStore.generated.map { it.strongBox })
        val uncertain = slot()
        keyStore.getKeyFailureAfterGenerations = keyStore.generated.size + 1
        assertGenerationUnavailable(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE),
            paymentKey.generate(uncertain, challenge),
        )
        assertEquals(listOf(false, false), keyStore.generated.map { it.strongBox })
    }

    @Test fun `an existing entry is never replaced and its slot is never generated again`() {
        val slot = slot()
        val original = keyStore.seed(alias(slot))
        assertSame(
            KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent,
            paymentKey.generate(slot, challenge),
        )
        assertTrue(keyStore.generated.isEmpty())
        assertSame(original, keyStore.entries.getValue(alias(slot)))
        keyStore.entries.clear()
        assertSame(
            KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent,
            paymentKey.generate(slot, challenge),
        )
        assertTrue(keyStore.generated.isEmpty())
    }

    @Test fun `a Keystore error before generation never generates`() {
        val slot = slot()
        val original = keyStore.seed(alias(slot))
        // A containsAlias-style probe would read this error as absence and rebind the alias.
        keyStore.getKeyFailure = IllegalStateException("keystore2 binder failure")
        assertGenerationUnavailable(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE),
            paymentKey.generate(slot, challenge),
        )
        assertTrue(keyStore.generated.isEmpty())
        assertSame(original, keyStore.entries.getValue(alias(slot)))
    }

    @Test fun `generation is refused unless the backup set is provably empty`() {
        val slot = slot()
        val refused = platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_BACKUP_ENABLED)
        environment.flags = ApplicationInfo.FLAG_ALLOW_BACKUP
        assertGenerationUnavailable(refused, paymentKey.generate(slot, challenge))
        environment.flags = 0
        environment.agent = "com.example.BackupAgent"
        assertGenerationUnavailable(refused, paymentKey.generate(slot, challenge))
        environment.agent = null
        val shipped = environment.dataExtraction
        environment.dataExtraction = KagemushaWalletAndroidXmlElementV1(shipped.name, shipped.attributes, shipped.children.take(1))
        assertGenerationUnavailable(refused, paymentKey.generate(slot, challenge))
        environment.dataExtraction = shipped
        environment.rulesFailure = IllegalStateException("Resources\$NotFoundException")
        assertGenerationUnavailable(refused, paymentKey.generate(slot, challenge))
        assertTrue(keyStore.generated.isEmpty())
        assertEquals(0, keyStore.getKeyCalls)
        environment.rulesFailure = null
        assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(
            paymentKey.generate(slot, challenge),
        )
    }

    @Test fun `a failed generation retries only after another definitive absence`() {
        val slot = slot()
        keyStore.generateFailure = ProviderException("keymint failure")
        assertGenerationUnavailable(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_GENERATION_FAILED),
            paymentKey.generate(slot, challenge),
        )
        keyStore.generateFailure = null
        assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(
            paymentKey.generate(slot, challenge),
        )
        assertEquals(2, keyStore.generated.size)
    }

    private fun assertUnusableAndKept() {
        val slot = slot()
        assertGenerationUnavailable(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE, paymentKey.generate(slot, challenge))
        assertTrue(keyStore.entries.containsKey(alias(slot)))
        assertSame(KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent, paymentKey.generate(slot, challenge))
    }

    @Test fun `a generated key whose KeyInfo differs from the request is unusable and stays in place`() {
        val edits: List<(KagemushaWalletAndroidKeyFactsV1) -> KagemushaWalletAndroidKeyFactsV1> = listOf(
            { it.copy(userAuthenticationRequired = true) },
            { it.copy(userPresenceRequired = true) },
            { it.copy(userConfirmationRequired = true) },
            { it.copy(remainingUsageCount = 1) },
            { it.copy(securityLevel = 1) },
            { it.copy(insideSecureHardware = false) },
            { it.copy(origin = 2) },
            { it.copy(purposes = 4 or 8) },
            { it.copy(digests = setOf("SHA-256", "NONE")) },
            { it.copy(keySize = 384) },
        )
        for (edit in edits) {
            keyStore.factsEdit = edit
            assertUnusableAndKept()
        }
    }

    @Test fun `a generated key whose signed attestation differs from the request is unusable and stays in place`() {
        val edits: List<(TestKeyDescriptionV1) -> TestKeyDescriptionV1> = listOf(
            // Software attestation and Keymaster levels.
            { it.copy(attestationLevel = 0, keymasterLevel = 0) },
            // Attested TEE while StrongBox was planned (and KeyInfo reports StrongBox).
            { it.copy(attestationLevel = 1, keymasterLevel = 1) },
            // Attestation level differs from the Keymaster level.
            { it.copy(attestationLevel = 2, keymasterLevel = 1) },
            // A usage-count limit (tag 405), the only one older readbacks cannot show.
            { it.copy(hardware = it.hardware + (405 to TestDerV1.integer(1))) },
            // PURPOSE enforced in software, not by the secure hardware.
            { it.copy(software = mapOf(1 to it.hardware.getValue(1)), hardware = it.hardware - 1) },
            // ORIGIN imported, not generated.
            { it.copy(hardware = it.hardware + (702 to TestDerV1.integer(2))) },
            // Wrong curve.
            { it.copy(hardware = it.hardware + (10 to TestDerV1.integer(2))) },
        )
        for (edit in edits) {
            keyStore.descriptionEdit = edit
            assertUnusableAndKept()
        }
        keyStore.descriptionEdit = { it }
        keyStore.attestedChallenge = ByteArray(32) { 7 }
        assertUnusableAndKept()
        keyStore.attestedChallenge = null
        assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(
            paymentKey.generate(slot(), challenge),
        )
    }

    @Test fun `key facts must report exactly the planned hardware`() {
        val strongBox = keyStore.facts(strongBox = true)
        assertTrue(kagemushaWalletAndroidFactsMatchV1(strongBox, KagemushaWalletAndroidSecurityLevelV1.STRONGBOX, exportable = false, apiLevel = 31))
        assertFalse(kagemushaWalletAndroidFactsMatchV1(strongBox, KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT, exportable = false, apiLevel = 31))
        assertFalse(kagemushaWalletAndroidFactsMatchV1(strongBox, KagemushaWalletAndroidSecurityLevelV1.STRONGBOX, exportable = true, apiLevel = 31))
        val tee = keyStore.facts(strongBox = false)
        assertTrue(kagemushaWalletAndroidFactsMatchV1(tee, KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT, exportable = false, apiLevel = 31))
        assertFalse(kagemushaWalletAndroidFactsMatchV1(tee.copy(securityLevel = 0), KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT, exportable = false, apiLevel = 31))
    }

    @Test fun `KeyInfo absence stays unknown and each API requires every field it actually exposes`() {
        val level = KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT
        for (api in 26..33) {
            apiLevel(api)
            val facts = keyStore.facts(strongBox = false)
            fun accepts(value: KagemushaWalletAndroidKeyFactsV1) =
                kagemushaWalletAndroidFactsMatchV1(value, level, exportable = false, apiLevel = api)
            assertTrue(accepts(facts), "API $api")
            assertFalse(accepts(facts.copy(insideSecureHardware = false)))
            assertFalse(accepts(facts.copy(origin = 2)))
            assertFalse(accepts(facts.copy(userAuthenticationRequired = true)))
            assertFalse(accepts(facts.copy(keySize = 384)))
            assertFalse(accepts(facts.copy(purposes = 4 or 8)))
            assertFalse(accepts(facts.copy(digests = setOf("SHA-256", "NONE"))))
            if (api < 31) {
                assertEquals(null, facts.securityLevel)
                assertEquals(null, facts.remainingUsageCount)
                assertFalse(accepts(facts.copy(securityLevel = 1)), "do not invent pre31 level")
                assertFalse(accepts(facts.copy(remainingUsageCount = -1)), "do not invent pre31 unlimited use")
            } else {
                assertFalse(accepts(facts.copy(securityLevel = null)))
                assertFalse(accepts(facts.copy(remainingUsageCount = null)))
            }
            if (api < 28) {
                assertEquals(null, facts.userPresenceRequired)
                assertEquals(null, facts.userConfirmationRequired)
                assertFalse(accepts(facts.copy(userPresenceRequired = false)))
                assertFalse(accepts(facts.copy(userConfirmationRequired = false)))
            } else {
                assertFalse(accepts(facts.copy(userPresenceRequired = null)))
                assertFalse(accepts(facts.copy(userConfirmationRequired = null)))
                assertFalse(accepts(facts.copy(userPresenceRequired = true)))
                assertFalse(accepts(facts.copy(userConfirmationRequired = true)))
            }
        }
    }

    @Test fun `one hardware plan StrongBox when declared otherwise TEE with no refusal plan`() {
        assertEquals(KagemushaWalletAndroidHardwarePlanV1.STRONGBOX_THEN_TEE, kagemushaWalletAndroidHardwarePlanV1(31, true))
        assertEquals(KagemushaWalletAndroidHardwarePlanV1.STRONGBOX_THEN_TEE, kagemushaWalletAndroidHardwarePlanV1(28, true))
        // A TEE-only device plan.
        assertEquals(KagemushaWalletAndroidHardwarePlanV1.TEE_ONLY, kagemushaWalletAndroidHardwarePlanV1(31, false))
        // StrongBox is an API 28 platform feature.
        assertEquals(KagemushaWalletAndroidHardwarePlanV1.TEE_ONLY, kagemushaWalletAndroidHardwarePlanV1(27, true))
        assertEquals(setOf("STRONGBOX_THEN_TEE", "TEE_ONLY"), KagemushaWalletAndroidHardwarePlanV1.entries.map { it.name }.toSet())
        // Native's Android profile tag is the only one; the retired policy-selected tags fail closed.
        kagemushaWalletAndroidRequireKeyProfileV1(2)
        for (tag in listOf(0, 1, 3, 4)) assertFailsWith<IllegalArgumentException> { kagemushaWalletAndroidRequireKeyProfileV1(tag) }
    }

    @Test fun `custody readback keeps a Keymaster 2 hardware key for the typed E1 refusal`() {
        apiLevel(26)
        keyStore.descriptionEdit = { it.copy(attestationVersion = 1, keymasterVersion = 2) }
        val slot = slot()
        val generated = assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(fresh(slot))
        assertEquals(KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT, generated.securityLevel)
        // An undocumented pair is not even custody-usable.
        keyStore.descriptionEdit = { it.copy(attestationVersion = 200, keymasterVersion = 100) }
        assertGenerationUnavailable(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE, fresh(slot()))
    }

    @Test fun `signing hands the exact 32-byte message to SHA256withECDSA and returns the platform DER`() {
        // Owner answer A1: the payment key signs the 32-byte Poseidon message with standard
        // ECDSA-P256-SHA256, so KeyMint hashes it once; DIGEST_NONE is never used.
        assertEquals("SHA256withECDSA", KAGEMUSHA_WALLET_ANDROID_SIGNATURE_ALGORITHM_V1)
        assertEquals(32, KAGEMUSHA_WALLET_ANDROID_SIGNING_MESSAGE_BYTES_V1)
        val slot = slot()
        val entry = keyStore.seed(alias(slot))
        val input = message.copyOf()
        val der = assertIs<KagemushaWalletAndroidSignatureV1.Der>(paymentKey.sign(slot, input)).der()
        assertContentEquals(message, keyStore.signedMessages.single(), "the message reaches the Keystore unchanged")
        assertContentEquals(message, input, "the caller's message is not modified")
        assertTrue(Signature.getInstance("SHA256withECDSA").run {
            initVerify(entry.pair.public)
            update(message)
            verify(der)
        })
        // The ECDSA hash is SHA-256(m): the DER verifies as a no-digest signature over SHA-256(m)
        // and not over m itself, which a DIGEST_NONE key would have signed.
        assertTrue(Signature.getInstance("NONEwithECDSA").run {
            initVerify(entry.pair.public)
            update(MessageDigest.getInstance("SHA-256").digest(message))
            verify(der)
        })
        assertFalse(Signature.getInstance("NONEwithECDSA").run {
            initVerify(entry.pair.public)
            update(message)
            verify(der)
        })
        val raw = KagemushaP256Codec.rawLowSFromStrictDer(der)
        assertTrue(KagemushaP256Codec.verifyRawLowS(testSec1V1(entry.pair.public), message, raw))

        // Anything other than one 32-byte message is refused before the Keystore is reached.
        val signCalls = keyStore.signCalls
        val keyCalls = keyStore.getKeyCalls
        for (length in listOf(0, 1, 31, 33, 338, 1024)) {
            assertFailsWith<IllegalArgumentException>("length $length") { paymentKey.sign(slot, ByteArray(length) { 7 }) }
        }
        assertEquals(signCalls, keyStore.signCalls, "wrong lengths never reach the signer")
        assertEquals(keyCalls, keyStore.getKeyCalls, "wrong lengths never load the key")
    }

    @Test fun `system signer refuses any message other than 32 bytes`() {
        val key = keyStore.seed(alias(slot())).pair.private
        val system = KagemushaWalletAndroidSystemKeyStoreV1()
        for (length in listOf(0, 1, 31, 33, 338, 1024)) {
            assertFailsWith<IllegalArgumentException>("length $length") { system.sign(key, ByteArray(length)) }
        }
    }

    @Test fun `signing failures are unavailable and never touch the key`() {
        val slot = slot()
        assertEquals(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEY_ABSENT),
            assertIs<KagemushaWalletAndroidSignatureV1.Unavailable>(paymentKey.sign(slot, message)).reason,
        )
        val entry = keyStore.seed(alias(slot))
        val cases = listOf(
            // Signature.initSign throws KeyPermanentlyInvalidatedException itself.
            TestPermanentlyInvalidatedKeyV1() to KagemushaWalletAndroidUnavailableV1.PERMANENTLY_INVALIDATED,
            InvalidKeyException("key rejected") to KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE,
            SignatureException("operation failed") to KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE,
            ProviderException("keystore2 busy") to platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_SIGN_FAILED),
        )
        for ((failure, reason) in cases) {
            keyStore.signFailure = failure
            assertEquals(reason, assertIs<KagemushaWalletAndroidSignatureV1.Unavailable>(paymentKey.sign(slot, message)).reason)
        }
        keyStore.signFailure = null
        keyStore.getKeyFailure = IllegalStateException("keystore2 binder failure")
        assertEquals(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE),
            assertIs<KagemushaWalletAndroidSignatureV1.Unavailable>(paymentKey.sign(slot, message)).reason,
        )
        assertSame(entry, keyStore.entries.getValue(alias(slot)))
        assertEquals(0, keyStore.deleteCalls)
        assertTrue(keyStore.generated.isEmpty())
    }

    @Test fun `deletion reports the outcome of a fresh probe`() {
        val slot = slot()
        keyStore.seed(alias(slot))
        assertSame(KagemushaWalletAndroidRemoveV1.Removed, paymentKey.delete(slot))
        assertSame(KagemushaWalletAndroidRemoveV1.Removed, paymentKey.delete(slot))
        assertSame(
            KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent,
            paymentKey.generate(slot, challenge),
        )
        val kept = slot()
        keyStore.seed(alias(kept))
        keyStore.deleteRemoves = false
        assertIs<KagemushaWalletAndroidRemoveV1.NotRemoved>(paymentKey.delete(kept))
        keyStore.deleteFailure = IllegalStateException("delete failed")
        keyStore.getKeyFailure = IllegalStateException("keystore2 binder failure")
        assertEquals(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE),
            assertIs<KagemushaWalletAndroidRemoveV1.Uncertain>(paymentKey.delete(kept)).reason,
        )
        assertTrue(keyStore.generated.isEmpty())
    }

    @Test fun `the attestation chain is exported only for a present key`() {
        val slot = slot()
        assertSame(KagemushaWalletAndroidAttestationChainV1.Absent, paymentKey.attestationChain(slot))
        val entry = keyStore.seed(alias(slot))
        val chain = assertIs<KagemushaWalletAndroidAttestationChainV1.Present>(paymentKey.attestationChain(slot))
        assertEquals(entry.chain!!.map { it.encoded.toList() }, chain.certificatesDer().map { it.toList() })
        keyStore.nullChain = true
        assertEquals(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_CERTIFICATE),
            assertIs<KagemushaWalletAndroidAttestationChainV1.Unavailable>(paymentKey.attestationChain(slot)).reason,
        )
        keyStore.nullChain = false
        entry.chain = listOf(entry.chain!!.first())
        assertIs<KagemushaWalletAndroidAttestationChainV1.Unavailable>(paymentKey.attestationChain(slot))
        keyStore.getKeyFailure = IllegalStateException("keystore2 binder failure")
        assertIs<KagemushaWalletAndroidAttestationChainV1.Unavailable>(paymentKey.attestationChain(slot))
    }

    @Test fun `enrollment attestation read binds the exact Native public key without generation`() {
        val slot = slot()
        val entry = keyStore.seed(alias(slot))
        val publicKey = assertIs<KagemushaWalletAndroidKeyProbeV1.Present>(paymentKey.probe(slot)).publicKeySec1()
        val chain = assertIs<KagemushaWalletAndroidAttestationChainV1.Present>(paymentKey.enrollmentAttestationChain(slot, publicKey))
        assertEquals(entry.chain!!.map { it.encoded.toList() }, chain.certificatesDer().map { it.toList() })
        assertEquals(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE,
            assertIs<KagemushaWalletAndroidAttestationChainV1.Unavailable>(paymentKey.enrollmentAttestationChain(slot, publicKey.copyOf().also { it[1] = (it[1].toInt() xor 1).toByte() })).reason)
        keyStore.getKeyFailure = IllegalStateException("unavailable")
        assertIs<KagemushaWalletAndroidAttestationChainV1.Unavailable>(paymentKey.enrollmentAttestationChain(slot, publicKey))
        assertTrue(keyStore.generated.isEmpty())
    }

    private fun KagemushaWalletAndroidKeyFactsV1.copy(
        insideSecureHardware: Boolean = this.insideSecureHardware,
        securityLevel: Int? = this.securityLevel,
        remainingUsageCount: Int? = this.remainingUsageCount,
        origin: Int = this.origin,
        purposes: Int = this.purposes,
        digests: Set<String> = this.digests,
        keySize: Int = this.keySize,
        userAuthenticationRequired: Boolean = this.userAuthenticationRequired,
        userPresenceRequired: Boolean? = this.userPresenceRequired,
        userConfirmationRequired: Boolean? = this.userConfirmationRequired,
    ) = KagemushaWalletAndroidKeyFactsV1(
        insideSecureHardware, securityLevel, remainingUsageCount, origin, purposes, digests, keySize,
        userAuthenticationRequired, userPresenceRequired, userConfirmationRequired,
    )
}
