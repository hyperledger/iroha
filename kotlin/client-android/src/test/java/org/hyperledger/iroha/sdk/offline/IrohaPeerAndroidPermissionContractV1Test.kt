package org.hyperledger.iroha.sdk.offline

import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class IrohaPeerAndroidPermissionContractV1Test {
    @Test
    fun `merged manifest keeps alternative peer carrier hardware optional`() {
        for (name in listOf(
            "android.hardware.nfc",
            "android.hardware.nfc.hce",
            "android.hardware.bluetooth",
            "android.hardware.bluetooth_le",
            "android.hardware.wifi",
            "android.hardware.location",
            "android.hardware.location.gps",
            "android.hardware.location.network",
        )) {
            val matches = features.filter { it.first == name }
            assertEquals(1, matches.size, "Merged manifest must declare $name exactly once")
            assertEquals("false", matches.single().second, "$name must not filter app installation")
        }
    }

    @Test
    fun `merged manifest preserves exact wifi permission boundaries`() {
        val accessWifi = permission("android.permission.ACCESS_WIFI_STATE")
        assertEquals(null, accessWifi.minimumSdk)
        assertEquals(32, accessWifi.maximumSdk)

        val changeWifi = permission("android.permission.CHANGE_WIFI_STATE")
        assertEquals(null, changeWifi.minimumSdk)
        assertEquals(32, changeWifi.maximumSdk)

        val nearbyWifi = permission("android.permission.NEARBY_WIFI_DEVICES")
        assertEquals(33, nearbyWifi.minimumSdk)
        assertEquals(null, nearbyWifi.maximumSdk)
        assertEquals("neverForLocation", nearbyWifi.flags)
    }

    @Test
    fun `api 32 and older use legacy wifi while api 33 and newer use nearby wifi`() {
        for (api in intArrayOf(24, 28, 29, 30, 31, 32)) {
            assertTrue(permission("android.permission.ACCESS_WIFI_STATE").appliesTo(api))
            assertTrue(permission("android.permission.CHANGE_WIFI_STATE").appliesTo(api))
            assertFalse(permission("android.permission.NEARBY_WIFI_DEVICES").appliesTo(api))
        }
        for (api in intArrayOf(33, 34, 35, 36, 37)) {
            assertFalse(permission("android.permission.ACCESS_WIFI_STATE").appliesTo(api))
            assertFalse(permission("android.permission.CHANGE_WIFI_STATE").appliesTo(api))
            assertTrue(permission("android.permission.NEARBY_WIFI_DEVICES").appliesTo(api))
        }
    }

    @Test
    fun `api 32 retains location and api 33 switches to nearby wifi`() {
        val coarse = permission("android.permission.ACCESS_COARSE_LOCATION")
        val fine = permission("android.permission.ACCESS_FINE_LOCATION")
        assertEquals(32, coarse.maximumSdk)
        assertEquals(29, fine.minimumSdk)
        assertEquals(32, fine.maximumSdk)
        assertTrue(coarse.appliesTo(32))
        assertTrue(fine.appliesTo(32))
        assertFalse(coarse.appliesTo(33))
        assertFalse(fine.appliesTo(33))
        assertFalse(permission("android.permission.NEARBY_WIFI_DEVICES").appliesTo(32))
        assertTrue(permission("android.permission.NEARBY_WIFI_DEVICES").appliesTo(33))
    }

    private class Permission(
        val name: String,
        val minimumSdk: Int?,
        val maximumSdk: Int?,
        val flags: String?,
    ) {
        fun appliesTo(api: Int): Boolean =
            api >= (minimumSdk ?: 1) && api <= (maximumSdk ?: Int.MAX_VALUE)
    }

    companion object {
        private const val ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
        private lateinit var permissions: List<Permission>
        private lateinit var features: List<Pair<String, String>>

        @JvmStatic
        @BeforeAll
        fun readMergedManifest() {
            val path = requireNotNull(System.getProperty("iroha.clientAndroid.mergedManifest")) {
                "Gradle must provide the merged client-android manifest path"
            }
            val manifest = File(path)
            require(manifest.isFile) { "Merged client-android manifest does not exist: $manifest" }
            val factory = DocumentBuilderFactory.newInstance().apply {
                isNamespaceAware = true
                isExpandEntityReferences = false
                setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            }
            val document = factory.newDocumentBuilder().parse(manifest)
            val featureNodes = document.getElementsByTagName("uses-feature")
            features = (0 until featureNodes.length).map { index ->
                val element = featureNodes.item(index) as Element
                element.getAttributeNS(ANDROID_NAMESPACE, "name") to
                    element.getAttributeNS(ANDROID_NAMESPACE, "required")
            }
            val nodes = document.getElementsByTagName("uses-permission")
            permissions = (0 until nodes.length).map { index ->
                val element = nodes.item(index) as Element
                Permission(
                    element.getAttributeNS(ANDROID_NAMESPACE, "name"),
                    element.optionalIntAttribute("minSdkVersion"),
                    element.optionalIntAttribute("maxSdkVersion"),
                    element.optionalAttribute("usesPermissionFlags"),
                )
            }
        }

        private fun permission(name: String): Permission {
            val matches = permissions.filter { it.name == name }
            assertEquals(1, matches.size, "Merged manifest must declare $name exactly once")
            return matches.single()
        }

        private fun Element.optionalIntAttribute(name: String): Int? =
            optionalAttribute(name)?.toInt()

        private fun Element.optionalAttribute(name: String): String? =
            getAttributeNS(ANDROID_NAMESPACE, name).takeIf(String::isNotEmpty)
    }
}
