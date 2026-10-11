// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

/**
 * Pins the KAGEMUSHA source surface of the three published Kotlin SDK modules.
 *
 * Only the KAGEMUSHA wallet V1 wire, the P-256 codec and the `KagemushaWalletAndroid*V1` platform
 * handle remain. The retired coordinator, ordinary-runtime, device-lifecycle, probe, provider and
 * Torii sources must not return under any source set, and neither Android module may register a
 * `ServiceLoader` provider. The `core-jvm` test task declares these file names as inputs.
 */
class OfflinePackageSurfaceV1Test {
    @Test fun `only the wallet V1 KAGEMUSHA sources remain`() {
        val root = kotlinRoot()
        val found = MODULES.flatMap { module ->
            root.resolve("$module/src").walkTopDown()
                .filter { it.isFile && it.name.lowercase().startsWith("kagemusha") }
                .map { it.relativeTo(root).invariantSeparatorsPath }
                .toList()
        }.toSortedSet()
        assertEquals(KEPT.toSortedSet(), found)
    }

    @Test fun `no Android SDK module registers a ServiceLoader provider`() {
        val root = kotlinRoot()
        for (module in listOf("client-android", "kagemusha-wallet-android")) {
            val registrations = root.resolve("$module/src").walkTopDown()
                .filter { it.isDirectory && it.invariantSeparatorsPath.endsWith("/META-INF/services") }
                .map { it.relativeTo(root).invariantSeparatorsPath }
                .toList()
            assertTrue(registrations.isEmpty(), "$module must not ship ServiceLoader registrations: $registrations")
        }
    }

    private companion object {
        val MODULES = listOf("core-jvm", "client-android", "kagemusha-wallet-android")

        private const val CORE_MAIN = "core-jvm/src/main/java/org/hyperledger/iroha/sdk/offline"
        private const val WALLET = "kagemusha-wallet-android/src"
        private const val WALLET_PACKAGE = "org/hyperledger/iroha/sdk/offline/wallet"

        val KEPT = listOf(
            "$CORE_MAIN/KagemushaP256Codec.kt",
            "$CORE_MAIN/KagemushaWalletWireV1.kt",
            "core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/offline/KagemushaWalletVectorsV1Test.kt",
            "$WALLET/main/java/$WALLET_PACKAGE/KagemushaWalletAndroidEnvironmentV1.kt",
            "$WALLET/main/java/$WALLET_PACKAGE/KagemushaWalletAndroidKeyStoreV1.kt",
            "$WALLET/main/java/$WALLET_PACKAGE/KagemushaWalletAndroidPaymentKeyV1.kt",
            "$WALLET/main/java/$WALLET_PACKAGE/KagemushaWalletAndroidPlatformV1.kt",
            "$WALLET/main/java/$WALLET_PACKAGE/KagemushaWalletAndroidResultsV1.kt",
            "$WALLET/main/res/xml/kagemusha_wallet_v1_data_extraction_rules.xml",
            "$WALLET/main/res/xml/kagemusha_wallet_v1_full_backup_content.xml",
            "$WALLET/test/kotlin/$WALLET_PACKAGE/KagemushaWalletAndroidBackupRulesV1Test.kt",
            "$WALLET/test/kotlin/$WALLET_PACKAGE/KagemushaWalletAndroidPaymentKeyV1Test.kt",
            "$WALLET/test/kotlin/$WALLET_PACKAGE/KagemushaWalletAndroidPlatformV1Test.kt",
            "$WALLET/test/kotlin/$WALLET_PACKAGE/KagemushaWalletAndroidTestFakesV1.kt",
            "$WALLET/androidTest/java/$WALLET_PACKAGE/KagemushaWalletAndroidPlatformDeviceV1Test.kt",
        )

        /** The Gradle root holding the three SDK modules, found above the test working directory. */
        fun kotlinRoot(): File {
            var current: File? = File("").absoluteFile
            while (current != null) {
                val candidate: File = current
                if (MODULES.all { candidate.resolve("$it/build.gradle.kts").isFile }) return candidate
                current = candidate.parentFile
            }
            error("the Kotlin SDK root was not found above ${File("").absolutePath}")
        }
    }
}
