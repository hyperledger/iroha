// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline.wallet

import android.content.Context
import android.content.pm.PackageManager
import android.content.res.XmlResourceParser
import android.os.Build
import android.os.UserManager
import java.io.File
import org.xmlpull.v1.XmlPullParser

/**
 * Narrow Android process and storage facts used by the wallet platform adapter, so its decisions
 * run in JVM unit tests against fakes. Methods report errors by throwing.
 *
 * The boot identity and the sleep-inclusive clock are not here: the Rust
 * `KagemushaWalletPlatformV1::boot_id` and `monotonic_ms` defaults read
 * `/proc/sys/kernel/random/boot_id` and `CLOCK_BOOTTIME` natively on Android.
 */
internal interface KagemushaWalletAndroidEnvironmentV1 {
    /** `Build.VERSION.SDK_INT`. */
    val apiLevel: Int

    /** `ApplicationInfo.flags` of the host application. */
    fun applicationFlags(): Int

    /** `ApplicationInfo.backupAgentName`, or null when the app declares no backup agent. */
    fun backupAgentName(): String?

    /** `R.xml.kagemusha_wallet_v1_data_extraction_rules` as resolved in the host application. */
    fun dataExtractionRules(): KagemushaWalletAndroidXmlElementV1

    /** `R.xml.kagemusha_wallet_v1_full_backup_content` as resolved in the host application. */
    fun fullBackupContentRules(): KagemushaWalletAndroidXmlElementV1

    /** Whether the context is a device-protected (direct-boot) storage context. */
    fun isDeviceProtectedStorage(): Boolean

    /** API 28+ and `PackageManager.FEATURE_STRONGBOX_KEYSTORE`. */
    fun hasStrongBox(): Boolean

    /** `UserManager.isUserUnlocked()`: credential-encrypted storage is available. */
    fun isUserUnlocked(): Boolean

    /** Validated, durable fixed custody root under the credential-encrypted application context. */
    fun preparedCustodyRoot(): File
}

/** One element of a parsed rules resource: its name, attributes and child elements. */
internal class KagemushaWalletAndroidXmlElementV1(
    val name: String,
    attributes: Map<String, String>,
    children: List<KagemushaWalletAndroidXmlElementV1>,
) {
    /** Attributes by name; a namespaced attribute is keyed `{namespace}name`. */
    val attributes: Map<String, String> = attributes.toMap()
    val children: List<KagemushaWalletAndroidXmlElementV1> = children.toList()
}

/** Bounds of a parsed rules resource; the shipped rules have 21 elements at depth 3. */
private const val KAGEMUSHA_WALLET_ANDROID_RULES_MAX_ELEMENTS_V1: Int = 64
private const val KAGEMUSHA_WALLET_ANDROID_RULES_MAX_DEPTH_V1: Int = 4

/** Parse one compiled XML resource into a bounded element tree. */
internal fun kagemushaWalletAndroidParseRulesV1(parser: XmlPullParser): KagemushaWalletAndroidXmlElementV1 {
    class Open(val name: String, val attributes: Map<String, String>) {
        val children = ArrayList<KagemushaWalletAndroidXmlElementV1>()
    }
    val stack = ArrayList<Open>()
    var root: KagemushaWalletAndroidXmlElementV1? = null
    var elements = 0
    var event = parser.eventType
    while (event != XmlPullParser.END_DOCUMENT) {
        when (event) {
            XmlPullParser.START_TAG -> {
                check(root == null) { "backup rules have content after the root element" }
                elements += 1
                check(elements <= KAGEMUSHA_WALLET_ANDROID_RULES_MAX_ELEMENTS_V1 &&
                    stack.size < KAGEMUSHA_WALLET_ANDROID_RULES_MAX_DEPTH_V1) { "backup rules exceed their bounds" }
                val attributes = LinkedHashMap<String, String>()
                for (index in 0 until parser.attributeCount) {
                    val namespace = parser.getAttributeNamespace(index).orEmpty()
                    val key = if (namespace.isEmpty()) parser.getAttributeName(index) else "{$namespace}${parser.getAttributeName(index)}"
                    check(attributes.put(key, parser.getAttributeValue(index)) == null) { "duplicate backup-rule attribute" }
                }
                stack.add(Open(parser.name, attributes))
            }
            XmlPullParser.END_TAG -> {
                val open = stack.removeAt(stack.size - 1)
                val element = KagemushaWalletAndroidXmlElementV1(open.name, open.attributes, open.children)
                if (stack.isEmpty()) root = element else stack[stack.size - 1].children.add(element)
            }
        }
        event = parser.next()
    }
    check(stack.isEmpty()) { "backup rules are truncated" }
    return checkNotNull(root) { "backup rules are empty" }
}

/** Production environment over the application context. */
internal class KagemushaWalletAndroidSystemEnvironmentV1(context: Context) : KagemushaWalletAndroidEnvironmentV1 {
    private val context: Context = context.applicationContext ?: context

    override val apiLevel: Int get() = Build.VERSION.SDK_INT

    override fun applicationFlags(): Int = context.applicationInfo.flags

    override fun backupAgentName(): String? = context.applicationInfo.backupAgentName

    override fun dataExtractionRules(): KagemushaWalletAndroidXmlElementV1 =
        rules(R.xml.kagemusha_wallet_v1_data_extraction_rules)

    override fun fullBackupContentRules(): KagemushaWalletAndroidXmlElementV1 =
        rules(R.xml.kagemusha_wallet_v1_full_backup_content)

    private fun rules(resource: Int): KagemushaWalletAndroidXmlElementV1 {
        val parser: XmlResourceParser = context.resources.getXml(resource)
        try {
            return kagemushaWalletAndroidParseRulesV1(parser)
        } finally {
            parser.close()
        }
    }

    override fun isDeviceProtectedStorage(): Boolean = context.isDeviceProtectedStorage

    override fun hasStrongBox(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    override fun isUserUnlocked(): Boolean {
        val users = context.getSystemService(Context.USER_SERVICE) as? UserManager
            ?: throw IllegalStateException("UserManager is unavailable")
        return users.isUserUnlocked
    }

    override fun preparedCustodyRoot(): File = KagemushaWalletAndroidStorageV1.preparedCustodyRoot(context)
}
