package org.hyperledger.iroha.sdk.client

import java.net.InetAddress
import java.net.Inet6Address
import java.net.URI
import java.net.UnknownHostException
import java.nio.charset.StandardCharsets
import java.util.Locale

private val IPV4_LITERAL = Regex("""^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$""")

/** Shared transport-safety checks for SDK requests that carry credentials or raw private keys. */
internal object TransportSecurity {
    private val credentialHeaders = setOf(
        "authorization",
        "x-api-token",
        "x-iroha-account",
        "x-iroha-signature",
        "x-iroha-timestamp-ms",
        "x-iroha-nonce",
        "x-iroha-witness",
        "x-iroha-onboarding-token",
        "x-iroha-operator-public-key",
        "x-iroha-operator-timestamp-ms",
        "x-iroha-operator-nonce",
        "x-iroha-operator-signature",
    )

    private val sensitiveBodyFields = listOf(
        "\"private_key\"",
        "\"seed_hex\"",
        "\"seed_b64\"",
        "\"seed_base64\"",
        "\"key_seed_hex\"",
        "\"key_seed_b64\"",
    )

    /**
     * Require `https` for requests carrying credentials or key material, on the configured base
     * authority. [allowLocalDevelopmentHttp] admits plain `http` only to the configured
     * localhost, loopback IP, or private IPv4 origin when explicitly enabled.
     */
    fun requireHttpRequestAllowed(
        context: String,
        baseUri: URI,
        targetUri: URI,
        headers: Map<String, String>?,
        body: ByteArray?,
        allowLocalDevelopmentHttp: Boolean = false,
    ) {
        if (!isSensitive(headers, body)) return
        val targetScheme = normalize(targetUri.scheme)
        val localHttp = allowLocalDevelopmentHttp && isLocalDevelopmentHttp(baseUri, targetUri)
        require(targetScheme == "https" || localHttp) {
            "$context refuses insecure transport over ${renderScheme(targetScheme)}; use https " +
                "or explicitly enable local development HTTP for the configured local origin."
        }
        val baseScheme = normalize(baseUri.scheme)
        require(targetScheme == baseScheme) {
            "$context refuses sensitive requests over mismatched scheme ${renderScheme(targetScheme)}; use relative paths derived from the configured base URL."
        }
        require(sameAuthority(baseUri, targetUri, targetScheme)) {
            "$context refuses sensitive requests to mismatched host ${renderHost(targetUri)}; use relative paths on the configured base URL."
        }
    }

    fun requireWebSocketRequestAllowed(
        context: String,
        baseUri: URI,
        targetUri: URI,
        headers: Map<String, String>?,
    ) {
        if (!headersContainCredentials(headers)) return
        val expectedScheme = expectedWebSocketScheme(baseUri)
        val targetScheme = normalize(targetUri.scheme)
        require(targetScheme == expectedScheme) {
            "$context refuses credentialed WebSocket requests over mismatched scheme ${renderScheme(targetScheme)}; use $expectedScheme URLs derived from the configured base URL."
        }
        require(sameAuthority(baseUri, targetUri, expectedScheme)) {
            "$context refuses credentialed WebSocket requests to mismatched host ${renderHost(targetUri)}; use the configured base URL host."
        }
        require(targetScheme == "wss") {
            "$context refuses insecure WebSocket protocol ${renderScheme(targetScheme)}; use wss."
        }
    }

    fun headersContainCredentials(headers: Map<String, String>?): Boolean =
        headers?.keys?.any { credentialHeaders.contains(it.lowercase(Locale.ROOT)) } == true

    /** Endpoint policy for Torii routes that enforce HTTPS independently of header inspection. */
    fun isHttpEndpointAllowed(baseUri: URI, allowLocalDevelopmentHttp: Boolean = false): Boolean =
        normalize(baseUri.scheme) == "https" ||
            (allowLocalDevelopmentHttp && isLocalDevelopmentHttp(baseUri, baseUri))

    private fun isSensitive(headers: Map<String, String>?, body: ByteArray?): Boolean =
        headersContainCredentials(headers) || bodyContainsSensitiveMaterial(body)

    private fun bodyContainsSensitiveMaterial(body: ByteArray?): Boolean {
        if (body == null || body.isEmpty()) return false
        val rendered = String(body, StandardCharsets.UTF_8).lowercase(Locale.ROOT)
        return sensitiveBodyFields.any(rendered::contains)
    }

    private fun isLocalDevelopmentHttp(baseUri: URI, targetUri: URI): Boolean =
        normalize(baseUri.scheme) == "http" &&
            normalize(targetUri.scheme) == "http" &&
            sameAuthority(baseUri, targetUri, "http") &&
            isLocalDevelopmentHost(normalize(targetUri.host))

    /** Localhost names, loopback IPs, and RFC1918 IPv4 literals, without DNS resolution. */
    fun isLocalDevelopmentHost(host: String?): Boolean {
        val literal = normalize(host).removePrefix("[").removeSuffix("]")
        if (literal == "localhost" || literal.endsWith(".localhost")) return true
        if (IPV4_LITERAL.matches(literal)) {
            val octets = literal.split('.').map(String::toInt)
            return octets[0] == 127 || octets[0] == 10 ||
                (octets[0] == 172 && octets[1] in 16..31) ||
                (octets[0] == 192 && octets[1] == 168)
        }
        // Restrict parsing to numeric IPv6; never resolve names or accept interface zones.
        if (!literal.contains(':') || literal.any { it !in "0123456789abcdef:" }) return false
        return try {
            val address = InetAddress.getByName(literal)
            address is Inet6Address && address.isLoopbackAddress
        } catch (_: UnknownHostException) {
            false
        }
    }

    private fun expectedWebSocketScheme(baseUri: URI): String =
        when (normalize(baseUri.scheme)) {
            "https", "wss" -> "wss"
            else -> "ws"
        }

    private fun sameAuthority(lhs: URI, rhs: URI, defaultPortScheme: String): Boolean =
        normalize(lhs.host) == normalize(rhs.host) &&
            effectivePort(lhs, defaultPortScheme) == effectivePort(rhs, defaultPortScheme)

    private fun effectivePort(uri: URI, defaultPortScheme: String): Int {
        if (uri.port != -1) return uri.port
        return when (normalize(uri.scheme).ifEmpty { defaultPortScheme }) {
            "http", "ws" -> 80
            "https", "wss" -> 443
            else -> -1
        }
    }

    private fun renderHost(uri: URI): String = uri.host ?: uri.toString()

    private fun renderScheme(scheme: String): String = if (scheme.isEmpty()) "unknown" else scheme

    private fun normalize(value: String?): String = value?.lowercase(Locale.ROOT) ?: ""
}
