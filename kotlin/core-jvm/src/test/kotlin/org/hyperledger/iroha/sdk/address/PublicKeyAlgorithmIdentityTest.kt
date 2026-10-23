package org.hyperledger.iroha.sdk.address

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** Curve identifiers and signing algorithm names retain one exact, backend-independent identity. */
class PublicKeyAlgorithmIdentityTest {
    private val algorithms = linkedMapOf(
        1 to "ed25519",
        4 to "secp256k1",
        3 to "bls_normal",
        5 to "bls_small",
        2 to "ml-dsa",
        10 to "gost3410-2012-256-paramset-a",
        11 to "gost3410-2012-256-paramset-b",
        12 to "gost3410-2012-256-paramset-c",
        13 to "gost3410-2012-512-paramset-a",
        14 to "gost3410-2012-512-paramset-b",
        15 to "sm2",
    )

    @Test
    fun everyPublishedCurveHasExactlyItsCanonicalSigningAlgorithmName() {
        assertEquals(11, algorithms.size)
        for ((curve, algorithm) in algorithms) {
            assertEquals(algorithm, algorithmForCurveId(curve), "curve $curve")
            assertEquals(curve, curveIdForAlgorithm(algorithm).toInt() and 0xff, algorithm)
        }
        for (curve in (0..255) + listOf(Int.MIN_VALUE, -1, 256, Int.MAX_VALUE)) {
            if (curve !in algorithms) assertNull(algorithmForCurveId(curve), "curve $curve")
        }
    }

    @Test
    fun canonicalPrefixesAdmitEveryRustSingleKeyFixtureAndRejectDifferentAlgorithms() {
        for ((curve, algorithm) in algorithms) {
            val vector = NativeAccountFixtures.positives.single { it["name"] == algorithm }
            val canonical = NativeAccountFixtures.bytes(vector["canonical_address_hex"] as String)
            // Successful fixture admission requires the real native owner; missing JNI must fail.
            val single = assertNotNull(AccountAddress.fromCanonicalBytes(canonical).singleKeyPayload(), algorithm)
            assertEquals(curve, single.curveId, algorithm)
            val encoded = encodePublicKeyMultihash(curve, single.publicKey)
            for (literal in listOf(encoded, "$algorithm:$encoded")) {
                val decoded = assertNotNull(decodePublicKeyLiteral(literal), algorithm)
                assertEquals(curve, decoded.curveId, algorithm)
                assertContentEquals(single.publicKey, decoded.keyBytes, algorithm)
            }
            for (otherAlgorithm in algorithms.values.filter { it != algorithm }) {
                assertNull(decodePublicKeyLiteral("$otherAlgorithm:$encoded"), "$otherAlgorithm for $algorithm")
            }
        }
    }

    @Test
    fun gostCurveRegistryLabelsAreNotSigningAlgorithmPrefixes() {
        val curveLabels = mapOf(10 to "gost256a", 11 to "gost256b", 12 to "gost256c",
            13 to "gost512a", 14 to "gost512b")
        for ((curve, curveLabel) in curveLabels) {
            val algorithm = algorithms.getValue(curve)
            val key = NativeAccountFixtures.singleKey(algorithm)
            val encoded = encodePublicKeyMultihash(curve, key)
            assertNotNull(decodePublicKeyLiteral("$algorithm:$encoded"), algorithm)
            assertNull(decodePublicKeyLiteral("$curveLabel:$encoded"), curveLabel)
            val error = assertFailsWith<AccountAddressException>(curveLabel) {
                AccountAddress.fromAccount(key, curveLabel)
            }
            assertEquals(AccountAddressErrorCode.UNKNOWN_ALGORITHM, error.code, curveLabel)
        }
    }
}
