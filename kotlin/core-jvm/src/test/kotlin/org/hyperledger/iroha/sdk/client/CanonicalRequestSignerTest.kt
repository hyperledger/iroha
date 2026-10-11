package org.hyperledger.iroha.sdk.client

import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.testing.TestNetworkIds
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CanonicalRequestSignerTest {
    private val networkId = TestNetworkIds.canonical()

    @Test
    fun canonicalQueryMatchesRustFormEncodingAndUtf8Ordering() {
        assertEquals(
            "a=1&b=%21*%28%29%7E%27",
            CanonicalRequestSigner.canonicalQueryString("b=!*()~'&a=1"),
        )
        assertEquals(
            "x=A%25zz%EF%BF%BD",
            CanonicalRequestSigner.canonicalQueryString("x=%41%zz%FF"),
        )
        assertEquals(
            "%EE%80%80=bmp&%F0%90%80%80=supplementary",
            CanonicalRequestSigner.canonicalQueryString("\uE000=bmp&\uD800\uDC00=supplementary"),
        )
        assertEquals(
            "k=%EE%80%80&k=%F0%90%80%80",
            CanonicalRequestSigner.canonicalQueryString("k=\uD800\uDC00&k=\uE000"),
        )
    }

    @Test
    fun canonicalQueryMatchesRustLossyUtf8MalformedSequenceBoundaries() {
        assertEquals(
            "x=%EF%BF%BD%EF%BF%BD%EF%BF%BD",
            CanonicalRequestSigner.canonicalQueryString("x=%ED%A0%80"),
        )
        assertEquals(
            "x=%EF%BF%BDA",
            CanonicalRequestSigner.canonicalQueryString("x=%E2%82%41"),
        )
        assertEquals(
            "x=%EF%BF%BD",
            CanonicalRequestSigner.canonicalQueryString("x=%F0%9F%92"),
        )
        assertEquals(
            "x=%EF%BF%BDA%EF%BF%BD",
            CanonicalRequestSigner.canonicalQueryString("x=%F0%9F%41%80"),
        )
    }

    @Test
    fun canonicalQueryEnforcesV1PairAndByteLimits() {
        val exactPairs = (0 until CanonicalRequestSigner.CANONICAL_REQUEST_MAX_QUERY_PAIRS_V1)
            .joinToString("&") { "k$it=v" }
        CanonicalRequestSigner.canonicalQueryString(exactPairs)
        assertFailsWith<IllegalArgumentException> {
            CanonicalRequestSigner.canonicalQueryString("$exactPairs&overflow=v")
        }

        val exactBytes = "k=" + "x".repeat(
            CanonicalRequestSigner.CANONICAL_REQUEST_MAX_RAW_QUERY_BYTES_V1 - 2,
        )
        assertEquals(
            CanonicalRequestSigner.CANONICAL_REQUEST_MAX_RAW_QUERY_BYTES_V1,
            exactBytes.toByteArray(StandardCharsets.UTF_8).size,
        )
        CanonicalRequestSigner.canonicalQueryString(exactBytes)
        assertFailsWith<IllegalArgumentException> {
            CanonicalRequestSigner.canonicalQueryString(exactBytes + "x")
        }

        assertEquals("a=1&b=2", CanonicalRequestSigner.canonicalQueryString("&&b=2&&a=1&"))
    }

    @Test
    fun canonicalRequestEnforcesV1MethodTokenAndLimit() {
        val uri = URI.create("https://torii.example/v1/test")
        CanonicalRequestSigner.canonicalRequestMessage(
            "A".repeat(CanonicalRequestSigner.CANONICAL_REQUEST_MAX_METHOD_BYTES_V1),
            uri,
            ByteArray(0),
        )
        assertFailsWith<IllegalArgumentException> {
            CanonicalRequestSigner.canonicalRequestMessage(
                "A".repeat(CanonicalRequestSigner.CANONICAL_REQUEST_MAX_METHOD_BYTES_V1 + 1),
                uri,
                ByteArray(0),
            )
        }
        listOf("", "GET request", "GET\n", "GÉT", "GET:").forEach { method ->
            assertFailsWith<IllegalArgumentException>(method) {
                CanonicalRequestSigner.canonicalRequestMessage(method, uri, ByteArray(0))
            }
        }
    }

    @Test
    fun canonicalRequestEnforcesV1PathLimit() {
        val root = CanonicalRequestSigner.canonicalRequestMessage(
            "GET",
            URI.create("/"),
            ByteArray(0),
        )
        val originWithoutPath = CanonicalRequestSigner.canonicalRequestMessage(
            "GET",
            URI.create("https://torii.example"),
            ByteArray(0),
        )
        assertEquals(
            String(root, StandardCharsets.UTF_8),
            String(originWithoutPath, StandardCharsets.UTF_8),
        )

        val exact = URI.create(
            "/" + "x".repeat(CanonicalRequestSigner.CANONICAL_REQUEST_MAX_PATH_BYTES_V1 - 1),
        )
        CanonicalRequestSigner.canonicalRequestMessage("GET", exact, ByteArray(0))
        val excessive = URI.create(
            "/" + "x".repeat(CanonicalRequestSigner.CANONICAL_REQUEST_MAX_PATH_BYTES_V1),
        )
        assertFailsWith<IllegalArgumentException> {
            CanonicalRequestSigner.canonicalRequestMessage("GET", excessive, ByteArray(0))
        }

        val exactTarget = String(
            CanonicalRequestSigner.canonicalRequestMessage(
                "get",
                URI.create("https://torii.example/v1/test?b=2&a=1"),
                ByteArray(0),
            ),
            StandardCharsets.UTF_8,
        )
        assertEquals("GET\n/v1/test\na=1&b=2", exactTarget.substringBeforeLast('\n'))
        val escapedTarget = String(
            CanonicalRequestSigner.canonicalRequestMessage(
                "GET",
                URI.create("/v1/%E3%81%82"),
                ByteArray(0),
            ),
            StandardCharsets.UTF_8,
        )
        assertEquals("/v1/%E3%81%82", escapedTarget.lineSequence().elementAt(1))
        val structuralEscapeTarget = String(
            CanonicalRequestSigner.canonicalRequestMessage(
                "GET",
                URI.create("/v1/%2e%2Fasset/%252e"),
                ByteArray(0),
            ),
            StandardCharsets.UTF_8,
        )
        assertEquals("/v1/%2e%2Fasset/%252e", structuralEscapeTarget.lineSequence().elementAt(1))

        listOf(
            URI.create("v1/test"),
            URI.create("?a=1"),
            URI.create("//torii.example/v1/test"),
            URI.create("https:/v1/test"),
            URI.create("https://torii.example//v1/test"),
            URI.create("https://torii.example/v1/tést"),
            URI.create("/v1/test#fragment"),
            URI.create("mailto:test@example.com"),
        ).forEach { invalid ->
            assertFailsWith<IllegalArgumentException>(invalid.toString()) {
                CanonicalRequestSigner.canonicalRequestMessage("GET", invalid, ByteArray(0))
            }
        }
        listOf(
            "/.",
            "/..",
            "/v1/./asset",
            "/v1/../asset",
            "/v1/%2e/asset",
            "/v1/%2E%2e/asset",
            "/v1/.%2E/asset",
        ).forEach { invalidPath ->
            assertFailsWith<IllegalArgumentException>(invalidPath) {
                CanonicalRequestSigner.canonicalRequestMessage(
                    "GET",
                    URI.create(invalidPath),
                    ByteArray(0),
                )
            }
        }
        listOf("/v1/%", "/v1/%2", "/v1/%GG").forEach { malformedPath ->
            assertFailsWith<IllegalArgumentException>(malformedPath) {
                URI.create(malformedPath)
            }
        }
    }

    @Test
    fun canonicalRequestRejectsNegativeTimestamp() {
        val uri = URI.create("/v1/test")
        assertFailsWith<IllegalArgumentException> {
            CanonicalRequestSigner.canonicalRequestSignatureMessage(
                networkId,
                "GET",
                uri,
                ByteArray(0),
                -1,
                "negative-timestamp",
            )
        }
    }

    @Test
    fun canonicalAuthEnforcesV1AccountAndNonceLimits() {
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val uri = URI.create("https://torii.example/v1/accounts")
        val timestampMs = 1_717_171_717_005L
        val longestLexicalAlias =
            "${"a".repeat(63)}@${"b".repeat(63)}.${"c".repeat(63)}"
        CanonicalRequestSigner.buildHeaders(
            networkId,
            "get",
            uri,
            ByteArray(0),
            longestLexicalAlias,
            RequestSigner.ed25519(keyPair.private),
            timestampMs,
            "account-limit",
        )
        val excessiveAccount = "a".repeat(
            CanonicalRequestSigner.CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1 + 1,
        )
        assertFailsWith<IllegalArgumentException> {
            CanonicalRequestSigner.buildHeaders(
                networkId,
                "get",
                uri,
                ByteArray(0),
                excessiveAccount,
                RequestSigner.ed25519(keyPair.private),
                timestampMs,
                "account-limit-plus-one",
            )
        }

        listOf(
            "alice",
            "Alice@universal",
            "alice@Universal",
            "alice@@universal",
            "alice@bank.universal.extra",
            "ab--wallet@universal",
            "alice+admin@universal",
            "0xalice@universal",
            "xn--@universal",
        ).forEach { invalidAccount ->
            assertFailsWith<IllegalArgumentException>(invalidAccount) {
                CanonicalRequestSigner.buildHeaders(
                    networkId,
                    "get",
                    uri,
                    ByteArray(0),
                    invalidAccount,
                    RequestSigner.ed25519(keyPair.private),
                    timestampMs,
                    "invalid-account",
                )
            }
            assertFailsWith<IllegalArgumentException>(invalidAccount) {
                CanonicalRequestSigner.withBodySignature(
                    networkId,
                    "post",
                    uri,
                    emptyMap(),
                    invalidAccount,
                    RequestSigner.ed25519(keyPair.private),
                    timestampMs,
                    "invalid-body-account",
                )
            }
        }

        val exactNonce = "n".repeat(256)
        CanonicalRequestSigner.canonicalRequestSignatureMessage(
            networkId,
            "get",
            uri,
            ByteArray(0),
            timestampMs,
            exactNonce,
        )
        listOf(exactNonce + "n", "internal space", "control\u0001", "nönce").forEach { nonce ->
            assertFailsWith<IllegalArgumentException>(nonce) {
                CanonicalRequestSigner.canonicalRequestSignatureMessage(
                    networkId,
                    "get",
                    uri,
                    ByteArray(0),
                    timestampMs,
                    nonce,
                )
            }
        }
    }

    @Test
    fun canonicalHeadersUseAsciiHexForI105AndPreserveAlias() {
        val i105 = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        val canonicalHex =
            "0x02000120ce7fa46c9dce7ea4b125e2e36bdb63ea33073e7590ac92816ae1e861b7048b03"
        assertEquals(
            canonicalHex,
            AccountAddress.parseEncoded(i105, null).canonicalHex(),
        )
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val uri = URI.create("https://torii.example/v1/accounts")
        val timestampMs = 1_717_171_717_006L
        val i105Headers = CanonicalRequestSigner.buildHeaders(
            networkId,
            "get",
            uri,
            ByteArray(0),
            i105,
            RequestSigner.ed25519(keyPair.private),
            timestampMs,
            "i105-header-hex",
        )

        assertEquals(canonicalHex, i105Headers[CanonicalRequestSigner.HEADER_ACCOUNT])
        assertTrue(canonicalHex.matches(Regex("0x[0-9a-f]+")))

        listOf(
            "alice-1@wonderland",
            "wallet@bank.universal",
            "xn--bcher-kva@universal",
            "alice@xn--fa-hia",
            "alice@xn--3xa",
            "alice@xn--nxa6a",
            "alice@xn--11b2ezcw70k",
            "alice@xn--mgba3gch31f060k",
            "alice@xn--ngba7iz95i",
            "alice@xn--ab-0ea",
            "alice@xn--a-jib",
            "alice@xn--ab-3n4a",
            "xn--alice@universal",
            "xn--a@universal",
            "alice@xn--ab-j1t",
            "alice@xn--mgba000r",
            "alice@xn--ngba000r",
            "alice@xn--ab-uuba211bca8057b",
            "alice@xn--4u8c",
            "alice@xn--pq1d",
            "alice@xn--kx7e",
            "alice@xn--5h0f",
            "alice@xn--zo5h",
            "alice@xn--fi3d",
            "alice@xn--d4f",
        ).forEachIndexed { index, alias ->
            val aliasHeaders = CanonicalRequestSigner.buildHeaders(
                networkId,
                "get",
                uri,
                ByteArray(0),
                alias,
                RequestSigner.ed25519(keyPair.private),
                timestampMs,
                "alias-header-$index",
            )
            assertEquals(alias, aliasHeaders[CanonicalRequestSigner.HEADER_ACCOUNT])
        }

        val signedBody = CanonicalRequestSigner.withBodySignature(
            networkId,
            "post",
            uri,
            emptyMap(),
            i105,
            RequestSigner.ed25519(keyPair.private),
            timestampMs,
            "i105-body",
        )
        assertEquals(i105, signedBody[CanonicalRequestSigner.BODY_ACCOUNT_ID])
    }

    @Test
    fun unsignedBodyAuthJsonRemovesOnlyTopLevelProofFields() {
        val body = linkedMapOf<String, Any?>(
            "z" to "last",
            CanonicalRequestSigner.BODY_SIGNATURE_BASE64 to "remove",
            "nested" to linkedMapOf(CanonicalRequestSigner.BODY_SIGNATURE_BASE64 to "keep"),
            "witness_base64" to "remove-too",
            CanonicalRequestSigner.BODY_ACCOUNT_ID to "alice@universal",
            CanonicalRequestSigner.BODY_TIMESTAMP_MS to 7L,
            CanonicalRequestSigner.BODY_NONCE to "n",
        )

        val unsigned = String(CanonicalRequestSigner.unsignedBodyAuthJson(body), StandardCharsets.UTF_8)

        assertEquals(
            """{"account_id":"alice@universal","nested":{"signature_base64":"keep"},"nonce":"n","timestamp_ms":7,"z":"last"}""",
            unsigned,
        )
    }

    @Test
    fun bodySignatureFieldsCarryVerifiableSignature() {
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val uri = URI.create("https://torii.example/v1/transactions?b=2&a=1")
        val timestampMs = 1_717_171_717_000L
        val nonce = "body-auth-nonce"
        val body = linkedMapOf<String, Any?>("operation_id" to "operation-1")

        val signed = CanonicalRequestSigner.withBodySignature(
            networkId,
            "post",
            uri,
            body,
            "alice@universal",
            RequestSigner.ed25519(keyPair.private),
            timestampMs,
            nonce,
        )

        assertEquals("alice@universal", signed[CanonicalRequestSigner.BODY_ACCOUNT_ID])
        assertEquals(timestampMs, signed[CanonicalRequestSigner.BODY_TIMESTAMP_MS])
        assertEquals(nonce, signed[CanonicalRequestSigner.BODY_NONCE])
        assertFalse(signed.containsKey("witness_base64"))

        val signatureBytes = Base64.getDecoder()
            .decode(signed[CanonicalRequestSigner.BODY_SIGNATURE_BASE64] as String)
        val message = CanonicalRequestSigner.canonicalBodyAuthSignatureMessage(
            networkId,
            "post",
            uri,
            signed,
            timestampMs,
            nonce,
        )
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(keyPair.public)
        verifier.update(message)
        assertTrue(verifier.verify(signatureBytes))
    }

    @Test
    fun canonicalAuthRejectsPaddedFreshnessAndAccountFields() {
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val uri = URI.create("https://torii.example/v1/transactions")
        val bodyBytes = """{"operation_id":"operation-1"}""".toByteArray(StandardCharsets.UTF_8)
        val body = linkedMapOf<String, Any?>("operation_id" to "operation-1")
        val timestampMs = 1_717_171_717_003L

        assertFailsWith<IllegalArgumentException> {
            CanonicalRequestSigner.canonicalRequestSignatureMessage(
                networkId,
                "post",
                uri,
                bodyBytes,
                timestampMs,
                " nonce",
            )
        }
        assertFailsWith<IllegalArgumentException> {
            CanonicalRequestSigner.buildHeaders(
                networkId,
                "post",
                uri,
                bodyBytes,
                "alice ",
                RequestSigner.ed25519(keyPair.private),
                timestampMs,
                "nonce",
            )
        }
        assertFailsWith<IllegalArgumentException> {
            CanonicalRequestSigner.buildHeaders(
                networkId,
                "post",
                uri,
                bodyBytes,
                "alice@universal",
                RequestSigner.ed25519(keyPair.private),
                timestampMs,
                "\nnonce",
            )
        }
        assertFailsWith<IllegalArgumentException> {
            CanonicalRequestSigner.withBodySignature(
                networkId,
                "post",
                uri,
                body,
                " alice",
                RequestSigner.ed25519(keyPair.private),
                timestampMs,
                "nonce",
            )
        }
        assertFailsWith<IllegalArgumentException> {
            CanonicalRequestSigner.withBodySignature(
                networkId,
                "post",
                uri,
                body,
                "alice@universal",
                RequestSigner.ed25519(keyPair.private),
                timestampMs,
                "nonce ",
            )
        }
    }

    @Test
    fun canonicalAuthCannotReplayAcrossSameLabelNetworks() {
        val uri = URI.create("https://torii.example/v1/accounts?label=same")
        val canonical = CanonicalRequestSigner.canonicalRequestSignatureMessage(
            networkId,
            "GET",
            uri,
            ByteArray(0),
            1_717_171_717_003L,
            "network-bound-nonce",
        )
        val foreign = CanonicalRequestSigner.canonicalRequestSignatureMessage(
            TestNetworkIds.fromSeed(7),
            "GET",
            uri,
            ByteArray(0),
            1_717_171_717_003L,
            "network-bound-nonce",
        )

        assertFalse(canonical.contentEquals(foreign))
    }
}
