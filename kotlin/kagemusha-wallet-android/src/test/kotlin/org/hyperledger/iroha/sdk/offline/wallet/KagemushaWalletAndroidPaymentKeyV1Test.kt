// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline.wallet

import android.content.pm.ApplicationInfo
import android.security.keystore.KeyProperties
import java.io.File
import java.security.InvalidKeyException
import java.security.ProviderException
import java.security.Signature
import java.security.SignatureException
import java.security.UnrecoverableKeyException
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
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

    @Test fun `below API 31 nothing is absent, generated or deleted`() {
        // Keystore1 getKey returns null when KeyStore.contains swallows a daemon error.
        environment.apiLevel = 30
        val unsupported = platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE_UNSUPPORTED)
        val empty = slot()
        assertEquals(unsupported, assertIs<KagemushaWalletAndroidKeyProbeV1.Unavailable>(paymentKey.probe(empty)).reason)
        assertGenerationUnavailable(
            unsupported,
            paymentKey.generate(empty, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE),
        )
        assertEquals(unsupported, assertIs<KagemushaWalletAndroidRemoveV1.Uncertain>(paymentKey.delete(slot())).reason)
        assertEquals(unsupported, assertIs<KagemushaWalletAndroidAttestationChainV1.Unavailable>(paymentKey.attestationChain(empty)).reason)
        assertEquals(unsupported, assertIs<KagemushaWalletAndroidSignatureV1.Unavailable>(paymentKey.sign(empty, ByteArray(32) { 1 })).reason)
        assertTrue(keyStore.generated.isEmpty())
        assertEquals(0, keyStore.getKeyCalls)
        assertEquals(0, keyStore.deleteCalls)
    }

    @Test fun `a TEE key is generated with the exact non-authenticated spec and read back`() {
        environment.strongBox = false
        val slot = slot()
        val generated = assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(
            paymentKey.generate(slot, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE),
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

    @Test fun `StrongBox is used when present and the secure-element profile never falls back`() {
        val first = slot()
        val strong = assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(
            paymentKey.generate(first, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT),
        )
        assertEquals(KagemushaWalletAndroidSecurityLevelV1.STRONGBOX, strong.securityLevel)
        assertTrue(keyStore.generated.single().strongBox)

        keyStore.strongBoxAvailable = false
        val second = slot()
        assertGenerationUnavailable(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_STRONGBOX_UNAVAILABLE),
            paymentKey.generate(second, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT),
        )
        assertEquals(listOf(true, true), keyStore.generated.map { it.strongBox })
        assertFalse(keyStore.entries.containsKey(alias(second)))

        environment.strongBox = false
        val third = slot()
        assertGenerationUnavailable(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_STRONGBOX_UNAVAILABLE),
            paymentKey.generate(third, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT),
        )
        assertEquals(2, keyStore.generated.size)
    }

    @Test fun `the TEE fallback runs only after StrongBox refusal and a second definitive absence`() {
        keyStore.strongBoxAvailable = false
        val slot = slot()
        val tee = assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(
            paymentKey.generate(slot, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE),
        )
        assertEquals(KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT, tee.securityLevel)
        assertEquals(listOf(true, false), keyStore.generated.map { it.strongBox })

        val uncertain = slot()
        keyStore.getKeyFailureAfterGenerations = keyStore.generated.size + 1
        assertGenerationUnavailable(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE),
            paymentKey.generate(uncertain, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE),
        )
        assertEquals(listOf(true, false, true), keyStore.generated.map { it.strongBox })
    }

    @Test fun `an existing entry is never replaced and its slot is never generated again`() {
        val slot = slot()
        val original = keyStore.seed(alias(slot))
        assertSame(
            KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent,
            paymentKey.generate(slot, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE),
        )
        assertTrue(keyStore.generated.isEmpty())
        assertSame(original, keyStore.entries.getValue(alias(slot)))
        keyStore.entries.clear()
        assertSame(
            KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent,
            paymentKey.generate(slot, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE),
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
            paymentKey.generate(slot, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE),
        )
        assertTrue(keyStore.generated.isEmpty())
        assertSame(original, keyStore.entries.getValue(alias(slot)))
    }

    @Test fun `generation is refused unless the backup set is provably empty`() {
        val slot = slot()
        val refused = platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_BACKUP_ENABLED)
        environment.flags = ApplicationInfo.FLAG_ALLOW_BACKUP
        assertGenerationUnavailable(refused, paymentKey.generate(slot, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE))
        environment.flags = 0
        environment.agent = "com.example.BackupAgent"
        assertGenerationUnavailable(refused, paymentKey.generate(slot, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE))
        environment.agent = null
        val shipped = environment.dataExtraction
        environment.dataExtraction = KagemushaWalletAndroidXmlElementV1(shipped.name, shipped.attributes, shipped.children.take(1))
        assertGenerationUnavailable(refused, paymentKey.generate(slot, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE))
        environment.dataExtraction = shipped
        environment.rulesFailure = IllegalStateException("Resources\$NotFoundException")
        assertGenerationUnavailable(refused, paymentKey.generate(slot, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE))
        assertTrue(keyStore.generated.isEmpty())
        assertEquals(0, keyStore.getKeyCalls)
        environment.rulesFailure = null
        assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(
            paymentKey.generate(slot, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE),
        )
    }

    @Test fun `a failed generation retries only after another definitive absence`() {
        val slot = slot()
        keyStore.generateFailure = ProviderException("keymint failure")
        assertGenerationUnavailable(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_GENERATION_FAILED),
            paymentKey.generate(slot, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE),
        )
        keyStore.generateFailure = null
        assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(
            paymentKey.generate(slot, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE),
        )
        assertEquals(2, keyStore.generated.size)
    }

    private fun assertUnusableAndKept(profile: KagemushaWalletAndroidKeyProfileV1) {
        val slot = slot()
        assertGenerationUnavailable(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE, paymentKey.generate(slot, challenge, profile))
        assertTrue(keyStore.entries.containsKey(alias(slot)))
        assertSame(KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent, paymentKey.generate(slot, challenge, profile))
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
            assertUnusableAndKept(KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT)
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
            assertUnusableAndKept(KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT)
        }
        keyStore.descriptionEdit = { it }
        keyStore.attestedChallenge = ByteArray(32) { 7 }
        assertUnusableAndKept(KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT)
        keyStore.attestedChallenge = null
        assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(
            paymentKey.generate(slot(), challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT),
        )
    }

    @Test fun `key facts must report exactly the planned hardware`() {
        val strongBox = keyStore.facts(strongBox = true)
        assertTrue(kagemushaWalletAndroidFactsMatchV1(strongBox, KagemushaWalletAndroidSecurityLevelV1.STRONGBOX, exportable = false))
        assertFalse(kagemushaWalletAndroidFactsMatchV1(strongBox, KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT, exportable = false))
        assertFalse(kagemushaWalletAndroidFactsMatchV1(strongBox, KagemushaWalletAndroidSecurityLevelV1.STRONGBOX, exportable = true))
        val tee = keyStore.facts(strongBox = false)
        assertTrue(kagemushaWalletAndroidFactsMatchV1(tee, KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT, exportable = false))
        assertFalse(kagemushaWalletAndroidFactsMatchV1(tee.copy(securityLevel = 0), KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT, exportable = false))
    }

    @Test fun `the hardware plan never selects the TEE for the secure-element profile`() {
        val profiles = KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT to KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE
        assertEquals(KagemushaWalletAndroidHardwarePlanV1.STRONGBOX_ONLY, kagemushaWalletAndroidHardwarePlanV1(profiles.first, 31, true))
        assertEquals(KagemushaWalletAndroidHardwarePlanV1.REFUSE, kagemushaWalletAndroidHardwarePlanV1(profiles.first, 31, false))
        assertEquals(KagemushaWalletAndroidHardwarePlanV1.REFUSE, kagemushaWalletAndroidHardwarePlanV1(profiles.first, 27, true))
        assertEquals(KagemushaWalletAndroidHardwarePlanV1.STRONGBOX_THEN_TEE, kagemushaWalletAndroidHardwarePlanV1(profiles.second, 31, true))
        assertEquals(KagemushaWalletAndroidHardwarePlanV1.TEE_ONLY, kagemushaWalletAndroidHardwarePlanV1(profiles.second, 31, false))
        assertEquals(KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT, KagemushaWalletAndroidKeyProfileV1.fromTag(1))
        assertEquals(KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE, KagemushaWalletAndroidKeyProfileV1.fromTag(2))
        assertEquals(null, KagemushaWalletAndroidKeyProfileV1.fromTag(0))
    }

    @Test fun `signing returns the platform DER over the exact message`() {
        val slot = slot()
        val entry = keyStore.seed(alias(slot))
        val message = ByteArray(32) { 7 }
        val der = assertIs<KagemushaWalletAndroidSignatureV1.Der>(paymentKey.sign(slot, message)).der()
        assertTrue(Signature.getInstance("SHA256withECDSA").run {
            initVerify(entry.pair.public)
            update(message)
            verify(der)
        })
        val raw = KagemushaP256Codec.rawLowSFromStrictDer(der)
        assertTrue(KagemushaP256Codec.verifyRawLowS(testSec1V1(entry.pair.public), message, raw))
        val signCalls = keyStore.signCalls
        val keyCalls = keyStore.getKeyCalls
        for (length in listOf(0, 31, 33, 1024)) {
            assertFailsWith<IllegalArgumentException> { paymentKey.sign(slot, ByteArray(length)) }
        }
        assertEquals(signCalls, keyStore.signCalls, "wrong lengths never reach the signer")
        assertEquals(keyCalls, keyStore.getKeyCalls, "wrong lengths never load the key")
    }

    @Test fun `signing failures are unavailable and never touch the key`() {
        val slot = slot()
        assertEquals(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEY_ABSENT),
            assertIs<KagemushaWalletAndroidSignatureV1.Unavailable>(paymentKey.sign(slot, ByteArray(32) { 1 })).reason,
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
            assertEquals(reason, assertIs<KagemushaWalletAndroidSignatureV1.Unavailable>(paymentKey.sign(slot, ByteArray(32) { 1 })).reason)
        }
        keyStore.signFailure = null
        keyStore.getKeyFailure = IllegalStateException("keystore2 binder failure")
        assertEquals(
            platformCode(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE),
            assertIs<KagemushaWalletAndroidSignatureV1.Unavailable>(paymentKey.sign(slot, ByteArray(32) { 1 })).reason,
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
            paymentKey.generate(slot, challenge, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE),
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

    private fun KagemushaWalletAndroidKeyFactsV1.copy(
        insideSecureHardware: Boolean = this.insideSecureHardware,
        securityLevel: Int = this.securityLevel,
        remainingUsageCount: Int = this.remainingUsageCount,
        origin: Int = this.origin,
        purposes: Int = this.purposes,
        digests: Set<String> = this.digests,
        keySize: Int = this.keySize,
        userAuthenticationRequired: Boolean = this.userAuthenticationRequired,
        userPresenceRequired: Boolean = this.userPresenceRequired,
        userConfirmationRequired: Boolean = this.userConfirmationRequired,
    ) = KagemushaWalletAndroidKeyFactsV1(
        insideSecureHardware, securityLevel, remainingUsageCount, origin, purposes, digests, keySize,
        userAuthenticationRequired, userPresenceRequired, userConfirmationRequired,
    )
}
