// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline.wallet

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.w3c.dom.Element

/**
 * The library manifest and backup rules keep the custody backup set empty (G2 design rev 2):
 * `allowBackup="false"` and every domain excluded for cloud backup and device transfer, so no
 * restore stream reaches the app and clears `no_backup` and its Keystore namespace. The runtime
 * validator accepts exactly the shipped rules and refuses any rule set that could add a file.
 */
class KagemushaWalletAndroidBackupRulesV1Test {
    private val main = File("src/main")

    private fun document(file: File): Element {
        assertTrue(file.isFile, "missing ${file.absolutePath}")
        val factory = DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        }
        return factory.newDocumentBuilder().parse(file).documentElement
    }

    private fun children(element: Element): List<Element> {
        val nodes = element.childNodes
        return (0 until nodes.length).mapNotNull { nodes.item(it) as? Element }
    }

    private fun assertBackupAttributes(manifest: Element) {
        val application = children(manifest).single { it.tagName == "application" }
        assertEquals("false", application.getAttributeNS(ANDROID, "allowBackup"))
        assertEquals("@xml/kagemusha_wallet_v1_data_extraction_rules", application.getAttributeNS(ANDROID, "dataExtractionRules"))
        assertEquals("@xml/kagemusha_wallet_v1_full_backup_content", application.getAttributeNS(ANDROID, "fullBackupContent"))
        assertFalse(application.hasAttributeNS(ANDROID, "backupAgent"))
        assertFalse(application.hasAttributeNS(ANDROID, "fullBackupOnly"))
    }

    @Test fun `the library manifest disables backup and names both rule files`() {
        assertBackupAttributes(document(File(main, "AndroidManifest.xml")))
    }

    @Test fun `the processed library manifest keeps the backup attributes`() {
        val path = assertNotNull(System.getProperty("iroha.kagemushaWalletAndroid.mergedManifest"), "merged manifest path")
        val manifest = document(File(path))
        assertBackupAttributes(manifest)
        val sdk = children(manifest).single { it.tagName == "uses-sdk" }
        assertEquals("26", sdk.getAttributeNS(ANDROID, "minSdkVersion"))
    }

    @Test fun `the shipped rules exclude every domain and pass the runtime validator`() {
        val dataExtraction = TestRulesV1.dataExtraction()
        assertEquals(listOf("cloud-backup", "device-transfer"), dataExtraction.children.map { it.name })
        for (section in dataExtraction.children + TestRulesV1.fullBackup()) {
            assertTrue(section.children.all { it.name == "exclude" && it.attributes == mapOf("domain" to it.attributes["domain"], "path" to ".") })
            assertEquals(KAGEMUSHA_WALLET_ANDROID_BACKUP_DOMAINS_V1, section.children.map { it.attributes["domain"] }.toSet())
        }
        assertNull(kagemushaWalletAndroidBackupRulesRefusalV1(dataExtraction, TestRulesV1.fullBackup()))
    }

    private fun element(name: String, children: List<KagemushaWalletAndroidXmlElementV1>, attributes: Map<String, String> = emptyMap()) =
        KagemushaWalletAndroidXmlElementV1(name, attributes, children)

    @Test fun `the runtime validator refuses any rule set that could add a file`() {
        val shipped = TestRulesV1.dataExtraction()
        val full = TestRulesV1.fullBackup()
        val (cloud, transfer) = shipped.children
        fun section(base: KagemushaWalletAndroidXmlElementV1, rules: List<KagemushaWalletAndroidXmlElementV1>) =
            element(base.name, rules, base.attributes)
        val exclude = transfer.children.first()
        val cases = listOf(
            // An include rule, a narrowed exclude, a missing and a duplicated domain.
            section(transfer, transfer.children + element("include", emptyList(), mapOf("domain" to "file", "path" to "."))),
            section(transfer, transfer.children.drop(1) + element("exclude", emptyList(), mapOf("domain" to exclude.attributes.getValue("domain"), "path" to "wallet"))),
            section(transfer, transfer.children.drop(1)),
            section(transfer, transfer.children + exclude),
            section(transfer, transfer.children.drop(1) + element("exclude", emptyList(), exclude.attributes + ("requireFlags" to "clientSideEncryption"))),
        )
        for (changed in cases) {
            assertNotNull(kagemushaWalletAndroidBackupRulesRefusalV1(element(shipped.name, listOf(cloud, changed)), full))
            assertNotNull(kagemushaWalletAndroidBackupRulesRefusalV1(element(shipped.name, listOf(section(cloud, changed.children), transfer)), full))
            assertNotNull(kagemushaWalletAndroidBackupRulesRefusalV1(shipped, element(full.name, changed.children)))
        }
        // A missing, duplicated or renamed section, and a wrong root.
        assertNotNull(kagemushaWalletAndroidBackupRulesRefusalV1(element(shipped.name, listOf(cloud)), full))
        assertNotNull(kagemushaWalletAndroidBackupRulesRefusalV1(element(shipped.name, listOf(cloud, transfer, transfer)), full))
        assertNotNull(kagemushaWalletAndroidBackupRulesRefusalV1(element(shipped.name, listOf(cloud, cloud)), full))
        assertNotNull(kagemushaWalletAndroidBackupRulesRefusalV1(element("full-backup-content", shipped.children), full))
        assertNotNull(kagemushaWalletAndroidBackupRulesRefusalV1(shipped, element("data-extraction-rules", full.children)))
        // Section attributes cannot add files; the order of the sections is free.
        assertNull(kagemushaWalletAndroidBackupRulesRefusalV1(element(shipped.name, listOf(transfer, cloud)), full))
    }

    @Test fun `the payment-key adapter never binds the key to user state or reads absence from masking APIs`() {
        val sources = listOf("KagemushaWalletAndroidKeyStoreV1.kt", "KagemushaWalletAndroidPaymentKeyV1.kt")
            .map { File(main, "java/org/hyperledger/iroha/sdk/offline/wallet/$it") }
        for (source in sources) {
            assertTrue(source.isFile, "missing ${source.absolutePath}")
            val text = source.readText()
            for (forbidden in FORBIDDEN_CALLS) {
                assertFalse(text.contains(forbidden), "${source.name} must not call $forbidden")
            }
        }
    }

    private companion object {
        const val ANDROID = "http://schemas.android.com/apk/res/android"

        /** Key-binding setters spec §2.3 forbids, and AndroidKeyStoreSpi calls that mask errors as absence. */
        val FORBIDDEN_CALLS = listOf(
            "setUserAuthenticationRequired(", "setUserAuthenticationParameters(",
            "setUserAuthenticationValidityDurationSeconds(", "setUserAuthenticationValidWhileOnBody(",
            "setInvalidatedByBiometricEnrollment(", "setUnlockedDeviceRequired(", "setMaxUsageCount(",
            "setUserPresenceRequired(", "setUserConfirmationRequired(",
            "containsAlias(", ".aliases()", ".size()", "isKeyEntry(", "isCertificateEntry(",
            ".getCertificate(",
        )
    }
}
