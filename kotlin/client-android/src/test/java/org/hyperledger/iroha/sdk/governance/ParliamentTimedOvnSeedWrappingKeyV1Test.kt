package org.hyperledger.iroha.sdk.governance

import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStoreException
import java.security.ProviderException
import java.security.UnrecoverableKeyException
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.crypto.keystore.AndroidKeystoreUnavailableExceptionV1
import org.junit.jupiter.api.Test

/** Wrapping-key existence decisions of the Parliament seed vault over a fake AndroidKeyStore. */
class ParliamentTimedOvnSeedWrappingKeyV1Test {
    @Test
    fun `a Keystore error never generates and never reads as absence`() {
        for (failure in listOf(
            KeyStoreException("binder"),
            UnrecoverableKeyException("daemon"),
            ProviderException("keystore2 system error"),
        )) {
            for (stored in listOf(null, aesKey(1))) {
                val keystore = FakeKeystore(apiLevel = 31, entry = stored)
                keystore.failure = failure
                val onEncrypt = assertFailsWith<AndroidKeystoreUnavailableExceptionV1> {
                    keystore.wrappingKey.loadOrGenerate()
                }
                val onDecrypt = assertFailsWith<AndroidKeystoreUnavailableExceptionV1> {
                    keystore.wrappingKey.load()
                }
                assertSame(failure, onEncrypt.cause)
                assertSame(failure, onDecrypt.cause)
                assertTrue(keystore.generated.isEmpty())
                assertSame(stored, keystore.entry)
            }
        }
    }

    @Test
    fun `the existing wrapping key survives seed creation and decryption`() {
        val existing = aesKey(7)
        val keystore = FakeKeystore(apiLevel = 31, entry = existing)
        repeat(3) {
            assertSame(existing, keystore.wrappingKey.loadOrGenerate())
            assertSame(existing, keystore.wrappingKey.load())
        }
        // A transient error between uses leaves the same key in place for the next call.
        keystore.failure = KeyStoreException("binder")
        assertFailsWith<AndroidKeystoreUnavailableExceptionV1> { keystore.wrappingKey.loadOrGenerate() }
        keystore.failure = null
        assertSame(existing, keystore.wrappingKey.loadOrGenerate())
        assertTrue(keystore.generated.isEmpty())
        assertSame(existing, keystore.entry)
    }

    @Test
    fun `decryption only loads and a definitively missing key is an error`() {
        val keystore = FakeKeystore(apiLevel = 31)
        repeat(2) {
            val missing = assertFailsWith<IllegalStateException> { keystore.wrappingKey.load() }
            assertFalse(missing is AndroidKeystoreUnavailableExceptionV1)
        }
        assertTrue(keystore.generated.isEmpty())
        assertNull(keystore.entry)
    }

    @Test
    fun `seed creation generates only after a definitive keystore2 absence`() {
        for (api in listOf(31, 35)) {
            val keystore = FakeKeystore(apiLevel = api)
            val generated = keystore.wrappingKey.loadOrGenerate()
            assertEquals(listOf(ParliamentTimedOvnSeedWrappingKeyV1.ALIAS), keystore.generated)
            assertSame(generated, keystore.entry)
            assertSame(generated, keystore.wrappingKey.loadOrGenerate())
            assertSame(generated, keystore.wrappingKey.load())
            assertEquals(1, keystore.generated.size)
            assertEquals(setOf(ParliamentTimedOvnSeedWrappingKeyV1.ALIAS), keystore.probedAliases)
        }
    }

    @Test
    fun `a non-secret entry is an error and is never replaced`() {
        val privateKey = KeyPairGenerator.getInstance("EC").generateKeyPair().private
        val keystore = FakeKeystore(apiLevel = 31, entry = privateKey)
        val onEncrypt = assertFailsWith<IllegalStateException> { keystore.wrappingKey.loadOrGenerate() }
        val onDecrypt = assertFailsWith<IllegalStateException> { keystore.wrappingKey.load() }
        assertFalse(onEncrypt is AndroidKeystoreUnavailableExceptionV1)
        assertFalse(onDecrypt is AndroidKeystoreUnavailableExceptionV1)
        assertTrue(keystore.generated.isEmpty())
        assertSame(privateKey, keystore.entry)
    }

    @Test
    fun `keystore1 refuses both paths without touching the Keystore`() {
        for (api in listOf(24, 28, 30)) {
            for (stored in listOf(null, aesKey(3))) {
                val keystore = FakeKeystore(apiLevel = api, entry = stored)
                for (call in listOf(keystore.wrappingKey::loadOrGenerate, keystore.wrappingKey::load)) {
                    val refused = assertFailsWith<IllegalStateException> { call() }
                    assertTrue(refused.message.orEmpty().contains("API 31+"))
                }
                assertEquals(0, keystore.getKeyCalls)
                assertTrue(keystore.generated.isEmpty())
                assertSame(stored, keystore.entry)
            }
        }
    }

    @Test
    fun `wrapping-key alias is pinned`() {
        assertEquals(
            "org.hyperledger.iroha.sdk.parliament.timed_ovn.seed_wrap.v1",
            ParliamentTimedOvnSeedWrappingKeyV1.ALIAS,
        )
    }

    /** One-alias AndroidKeyStore double: `getKey` is tri-state and generation replaces the entry. */
    private class FakeKeystore(apiLevel: Int, var entry: Key? = null) {
        var failure: Exception? = null
        var getKeyCalls = 0
        val probedAliases = mutableSetOf<String>()
        val generated = mutableListOf<String>()

        val wrappingKey = ParliamentTimedOvnSeedWrappingKeyV1(
            apiLevel,
            getKey = { alias ->
                getKeyCalls += 1
                probedAliases += alias
                failure?.let { throw it }
                entry
            },
            generate = { alias ->
                generated += alias
                aesKey(generated.size + 100).also { entry = it }
            },
        )
    }

    private companion object {
        fun aesKey(fill: Int): SecretKey = SecretKeySpec(ByteArray(32) { fill.toByte() }, "AES")
    }
}
