// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline.wallet

import android.content.Context
import android.content.pm.ApplicationInfo
import java.io.File
import java.io.IOException
import java.nio.file.Files
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.hyperledger.iroha.sdk.testing.JvmApiInventory

class KagemushaWalletAndroidPlatformV1Test {
    @TempDir
    lateinit var directory: File

    private fun adapter(environment: KagemushaWalletAndroidEnvironmentV1, keyStore: TestKeyStoreV1 = TestKeyStoreV1()) =
        KagemushaWalletAndroidPlatformAdapterV1(environment, keyStore)

    @Test fun `creation is refused unless custody can be kept`() {
        val environment = TestEnvironmentV1(directory)
        environment.apiLevel = 30
        assertFailsWith<IllegalStateException> { adapter(environment) }
        environment.apiLevel = 31
        environment.flags = ApplicationInfo.FLAG_ALLOW_BACKUP or ApplicationInfo.FLAG_HAS_CODE
        assertFailsWith<IllegalStateException> { adapter(environment) }
        environment.flags = ApplicationInfo.FLAG_HAS_CODE
        environment.agent = "com.example.WalletBackupAgent"
        assertFailsWith<IllegalStateException> { adapter(environment) }
        environment.agent = null
        // A host resource of the same name that adds files to device transfer.
        val shipped = environment.dataExtraction
        val transfer = shipped.children.single { it.name == "device-transfer" }
        val include = KagemushaWalletAndroidXmlElementV1("include", mapOf("domain" to "file", "path" to "."), emptyList())
        environment.dataExtraction = KagemushaWalletAndroidXmlElementV1(shipped.name, shipped.attributes,
            shipped.children - transfer + KagemushaWalletAndroidXmlElementV1(transfer.name, transfer.attributes, transfer.children + include))
        assertFailsWith<IllegalStateException> { adapter(environment) }
        environment.dataExtraction = shipped
        environment.rulesFailure = IllegalStateException("Resources\$NotFoundException")
        assertFailsWith<IllegalStateException> { adapter(environment) }
        environment.rulesFailure = null
        environment.deviceProtected = true
        assertFailsWith<IllegalStateException> { adapter(environment) }
        environment.deviceProtected = false
        adapter(environment)
    }

    @Test fun `storage is available only after the first unlock`() {
        val environment = TestEnvironmentV1(directory)
        val adapter = adapter(environment)
        assertNull(adapter.storageState())
        environment.unlocked = false
        assertSame(KagemushaWalletAndroidUnavailableV1.BEFORE_FIRST_UNLOCK, adapter.storageState())
        environment.unlockFailure = IllegalStateException("UserManager died")
        assertEquals(
            KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_STORAGE),
            adapter.storageState(),
        )
    }

    @Test fun `the custody root is the canonical credential-encrypted no-backup directory`() {
        val linked = File(directory, "no_backup").apply { mkdirs() }
        val environment = TestEnvironmentV1(File(directory, "./no_backup/../no_backup"))
        val adapter = adapter(environment)
        val root = assertIs<KagemushaWalletAndroidCustodyRootV1.Present>(adapter.custodyRoot())
        assertEquals(File(linked.canonicalPath, "kagemusha-wallet-v1").path, root.path)
        assertEquals(false, File(root.path).exists())
        environment.unlocked = false
        assertSame(
            KagemushaWalletAndroidUnavailableV1.BEFORE_FIRST_UNLOCK,
            assertIs<KagemushaWalletAndroidCustodyRootV1.Unavailable>(adapter.custodyRoot()).reason,
        )
        environment.unlocked = true
        environment.directoryFailure = IOException("canonicalization failed")
        assertEquals(
            KagemushaWalletAndroidUnavailableV1.io(0),
            assertIs<KagemushaWalletAndroidCustodyRootV1.Unavailable>(adapter.custodyRoot()).reason,
        )
    }

    @Test fun `the custody root resolves symbolic links`() {
        val target = File(directory, "target").apply { mkdirs() }
        val link = File(directory, "link")
        Files.createSymbolicLink(link.toPath(), target.toPath())
        val root = assertIs<KagemushaWalletAndroidCustodyRootV1.Present>(adapter(TestEnvironmentV1(link)).custodyRoot())
        assertEquals(File(target.canonicalPath, "kagemusha-wallet-v1").path, root.path)
    }

    @Test fun `the handle exposes no public operation to app code`() {
        val type = JvmApiInventory.read(KagemushaWalletAndroidPlatformV1::class.java)
        val declaredPublic = type.methods.filter { it.isPublic && !it.isSynthetic && it.name != "<init>" }
        assertEquals(listOf("create"), declaredPublic.map { it.name })
        assertEquals("(Landroid/content/Context;)L$JVM_OWNER/KagemushaWalletAndroidPlatformV1;", declaredPublic.single().descriptor)
        assertTrue(declaredPublic.single().isStatic)
        for ((name, signature) in UPCALLS) {
            val method = type.methods.single { it.name == name }
            assertTrue(method.flags and 0x0002 != 0, name)
            assertEquals(signature, method.descriptor, name)
        }
        assertEquals(UPCALLS.keys, type.methods.filter {
            it.flags and 0x0002 != 0 && !it.isSynthetic && it.name != "<init>"
        }.map { it.name }.toSet())
    }

    @Test fun `the consumer rules keep every upcall the bridge binds`() {
        val rules = File("consumer-rules.pro").readText()
        val methods = JvmApiInventory.read(KagemushaWalletAndroidPlatformV1::class.java).methods
        for (name in UPCALLS.keys) {
            val signature = methods.single { it.name == name }.parameterTypes.joinToString(", ") {
                when (it) {
                    "[B" -> "byte[]"
                    "I" -> "int"
                    else -> error("unreviewed JNI upcall parameter descriptor: $it")
                }
            }
            assertTrue(rules.contains(" $name($signature);"), "consumer-rules.pro must keep $name($signature)")
        }
    }

    @Test fun `the platform adapter reaches the payment key through the slot alias`() {
        val keyStore = TestKeyStoreV1()
        val platform = adapter(TestEnvironmentV1(directory), keyStore)
        val slot = ByteArray(32) { (it + 1).toByte() }
        assertSame(KagemushaWalletAndroidKeyProbeV1.Absent, platform.keyProbe(slot))
        val generated = assertIs<KagemushaWalletAndroidKeyGenerationV1.Generated>(
            platform.keyGenerate(slot, ByteArray(32) { 3 }, KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT.tag),
        )
        assertEquals(kagemushaWalletAndroidAliasV1(slot), keyStore.generated.single().alias)
        assertEquals(
            generated.publicKeySec1().toList(),
            assertIs<KagemushaWalletAndroidKeyProbeV1.Present>(platform.keyProbe(slot)).publicKeySec1().toList(),
        )
        assertIs<KagemushaWalletAndroidSignatureV1.Der>(platform.keySign(slot, ByteArray(32) { 7 }))
        assertIs<KagemushaWalletAndroidAttestationChainV1.Present>(platform.attestationChain(slot))
        assertEquals(0, platform.anchorPolicyTag())
        assertNull(platform.storageState())
        assertIs<KagemushaWalletAndroidCustodyRootV1.Present>(platform.custodyRoot())
        assertSame(KagemushaWalletAndroidRemoveV1.Removed, platform.keyDelete(slot))
        assertSame(KagemushaWalletAndroidKeyProbeV1.Absent, platform.keyProbe(slot))
        assertFailsWith<IllegalArgumentException> { platform.keyGenerate(ByteArray(32) { 9 }, ByteArray(32) { 3 }, 0) }
        assertEquals(1, keyStore.generated.size)
    }

    private companion object {
        private const val JVM_OWNER = "org/hyperledger/iroha/sdk/offline/wallet"

        /** Exact private JNI names and descriptors, including return types. */
        val UPCALLS: Map<String, String> = linkedMapOf(
            "keyProbe" to "([B)L$JVM_OWNER/KagemushaWalletAndroidKeyProbeV1;",
            "keyGenerate" to "([B[BI)L$JVM_OWNER/KagemushaWalletAndroidKeyGenerationV1;",
            "keySign" to "([B[B)L$JVM_OWNER/KagemushaWalletAndroidSignatureV1;",
            "keyDelete" to "([B)L$JVM_OWNER/KagemushaWalletAndroidRemoveV1;",
            "attestationChain" to "([B)L$JVM_OWNER/KagemushaWalletAndroidAttestationChainV1;",
            "anchorPolicyTag" to "()I",
            "storageState" to "()L$JVM_OWNER/KagemushaWalletAndroidUnavailableV1;",
            "custodyRoot" to "()L$JVM_OWNER/KagemushaWalletAndroidCustodyRootV1;",
        )
    }
}
