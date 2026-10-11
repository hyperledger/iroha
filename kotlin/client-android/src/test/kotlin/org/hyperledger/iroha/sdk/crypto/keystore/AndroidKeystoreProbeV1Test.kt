// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.crypto.keystore

import java.io.File
import java.security.KeyStoreException
import java.security.UnrecoverableKeyException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

/** Tri-state alias probe semantics (AOSP android14 `AndroidKeyStoreSpi`) over a fake Keystore. */
class AndroidKeystoreProbeV1Test {
    @Test fun `keystore2 getKey is tri-state and an error is never absence`() {
        val keyStore = TestAndroidKeystoreV1(apiLevel = 31)
        assertNull(keyStore.probe("absent"))
        assertEquals(AndroidKeystoreAliasStateV1.ABSENT, keyStore.aliasState("absent"))
        val entry = keyStore.seed("present")
        assertSame(entry.key, keyStore.probe("present"))
        assertEquals(AndroidKeystoreAliasStateV1.PRESENT, keyStore.aliasState("present"))
        for (failure in listOf(KeyStoreException("binder"), UnrecoverableKeyException("daemon"), IllegalStateException("x"))) {
            keyStore.getKeyFailure = failure
            val unavailable = assertFailsWith<AndroidKeystoreUnavailableExceptionV1> { keyStore.probe("present") }
            assertSame(failure, unavailable.cause)
            assertFailsWith<AndroidKeystoreUnavailableExceptionV1> { keyStore.aliasState("absent") }
        }
    }

    @Test fun `keystore1 null is never a definitive absence but a returned key is present`() {
        for (api in listOf(24, 28, 30)) {
            val keyStore = TestAndroidKeystoreV1(apiLevel = api)
            assertFailsWith<AndroidKeystoreUnavailableExceptionV1> { keyStore.probe("absent") }
            assertFailsWith<AndroidKeystoreUnavailableExceptionV1> { keyStore.aliasState("absent") }
            val entry = keyStore.seed("present")
            assertSame(entry.key, keyStore.probe("present"))
        }
    }

    @Test fun `the probe asks getKey exactly once`() {
        val keyStore = TestAndroidKeystoreV1()
        keyStore.getKeyFailure = KeyStoreException("binder")
        assertFailsWith<AndroidKeystoreUnavailableExceptionV1> { keyStore.probe("alias") }
        assertEquals(1, keyStore.getKeyCalls)
    }

    @Test fun `client-android sources never decide existence through masking KeyStore calls`() {
        val sources = File("src/main/java").walkTopDown()
            .filter { it.isFile && (it.extension == "kt" || it.extension == "java") }
            .filter { it.readText().let { text -> "AndroidKeyStore" in text || "java.security.KeyStore" in text } }
            .toList()
        assertTrue(sources.isNotEmpty(), "no Keystore sources found under ${File("src/main/java").absolutePath}")
        for (source in sources) {
            val text = source.readText()
            for (forbidden in MASKING_CALLS) {
                assertFalse(text.contains(forbidden), "${source.name} must not call $forbidden")
            }
        }
    }

    private companion object {
        /** AndroidKeyStoreSpi calls that turn a Keystore error into "absent". */
        val MASKING_CALLS = listOf(
            "containsAlias(", ".aliases()", "isKeyEntry(", "isCertificateEntry(", ".getEntry(", ".getCertificate(",
        )
    }
}
