// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.crypto.keystore

import android.os.Build
import java.security.Key
import java.security.KeyStore
import java.security.cert.Certificate

/** Lowest API level with keystore2, whose `KeyStore.getKey` distinguishes "no key" from an error. */
internal const val ANDROID_KEYSTORE2_MIN_API_V1: Int = 31

/** The AndroidKeyStore could not say whether an alias holds a key. Never read as absence. */
internal class AndroidKeystoreUnavailableExceptionV1(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

/** A definitive answer of [probeAndroidKeystoreAliasV1]; an unknown answer is a throw, never a value. */
internal enum class AndroidKeystoreAliasStateV1 { PRESENT, ABSENT }

/**
 * Tri-state AndroidKeyStore alias probe (AOSP android14 `AndroidKeyStoreSpi`).
 *
 * `containsAlias` is `getKeyMetadata(alias) != null`, and `getKeyMetadata` returns null for every
 * Keystore error; `getEntry`, `aliases`, `isKeyEntry` and `getCertificate*` mask errors the same
 * way. Only `KeyStore.getKey(alias, null)` on keystore2 (API 31+) is tri-state: a key is present,
 * null is `KEY_NOT_FOUND`, and any throw means the Keystore did not answer. On keystore1
 * (API < 31) `getKey` returns null whenever its `KeyStore.contains` probe fails, so a null there is
 * never definitive; a returned key is.
 *
 * Generating under an occupied alias replaces its key (keystore2 `rebind_alias`; keystore1 deletes
 * every entry of the alias first), so callers generate only after this probe returned null.
 *
 * @return the present key, or null for a definitive absence
 * @throws AndroidKeystoreUnavailableExceptionV1 when [getKey] throws, or below API 31 when it
 *   reports no key
 */
internal fun probeAndroidKeystoreAliasV1(apiLevel: Int, alias: String, getKey: (String) -> Key?): Key? {
    val key = try {
        getKey(alias)
    } catch (error: Exception) {
        throw AndroidKeystoreUnavailableExceptionV1("AndroidKeyStore could not answer for the alias", error)
    }
    if (key == null && apiLevel < ANDROID_KEYSTORE2_MIN_API_V1) {
        throw AndroidKeystoreUnavailableExceptionV1("keystore1 (API $apiLevel) cannot prove that an alias is empty")
    }
    return key
}

/**
 * Read-only AndroidKeyStore entry access. Errors are thrown, never turned into absence; existence
 * is answered only by [getKey] through [probe].
 */
internal interface AndroidKeystoreEntriesV1 {
    /** Platform API level; [getKey] is tri-state only from [ANDROID_KEYSTORE2_MIN_API_V1]. */
    val apiLevel: Int

    /** `KeyStore.getKey(alias, null)`: a key, null for no key entry, or a throw. */
    fun getKey(alias: String): Key?

    /** Certificate chain (leaf first) of an entry [getKey] reported present; null is an error. */
    fun getCertificateChain(alias: String): List<Certificate>?
}

/** Tri-state probe of [alias]; see [probeAndroidKeystoreAliasV1]. */
internal fun AndroidKeystoreEntriesV1.probe(alias: String): Key? =
    probeAndroidKeystoreAliasV1(apiLevel, alias) { getKey(it) }

/** [probe] as a definitive [AndroidKeystoreAliasStateV1]; an unknown answer throws. */
internal fun AndroidKeystoreEntriesV1.aliasState(alias: String): AndroidKeystoreAliasStateV1 =
    if (probe(alias) == null) AndroidKeystoreAliasStateV1.ABSENT else AndroidKeystoreAliasStateV1.PRESENT

/** Production [AndroidKeystoreEntriesV1] over the platform `AndroidKeyStore`. */
internal class AndroidSystemKeystoreV1 : AndroidKeystoreEntriesV1 {
    override val apiLevel: Int get() = Build.VERSION.SDK_INT

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER_V1).apply { load(null) }

    override fun getKey(alias: String): Key? = keyStore().getKey(alias, null)

    override fun getCertificateChain(alias: String): List<Certificate>? =
        keyStore().getCertificateChain(alias)?.toList()
}

private const val ANDROID_KEYSTORE_PROVIDER_V1 = "AndroidKeyStore"
