package org.hyperledger.iroha.sdk.address

import java.io.File
import org.hyperledger.iroha.sdk.client.JsonParser
import org.hyperledger.iroha.sdk.crypto.MlDsaPublicKeyAdmission
import org.hyperledger.iroha.sdk.testing.TestEd25519Keys
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

class AccountAddressTest {
    @Test
    fun canonicalIdentityRecognitionIsIndependentOfNativeAvailability() {
        for (algorithm in listOf("ed25519", "secp256k1", "bls_normal", "bls_small", "ml-dsa",
            "gost3410-2012-256-paramset-a", "gost3410-2012-256-paramset-b",
            "gost3410-2012-256-paramset-c", "gost3410-2012-512-paramset-a",
            "gost3410-2012-512-paramset-b", "sm2")) {
            val curve = curveIdForAlgorithm(algorithm).toInt() and 0xff
            assertEquals(algorithm, algorithmForCurveId(curve), algorithm)
        }
        for (alias in listOf("ed", "ED25519", "secp", "SECP256K1", "bls-normal", "bls-small", "gost256a", "gost512b", "sm-2", "SM2")) {
            val error = assertFailsWith<AccountAddressException> { AccountAddress.fromAccount(byteArrayOf(1), alias) }
            assertEquals(AccountAddressErrorCode.UNKNOWN_ALGORITHM, error.code, alias)
        }
    }

    @Test
    fun nativeAddressCategoriesAndCauseSurviveUnrelatedDiagnosticText() {
        for (category in listOf(AccountAddressErrorCode.DECODE_RESOURCE_LIMIT,
            AccountAddressErrorCode.UNSUPPORTED_IMPLEMENTATION,
            AccountAddressErrorCode.UNKNOWN_CURVE, AccountAddressErrorCode.INVALID_PUBLIC_KEY)) {
            val original = AccountAddressNativeException(category.code, "arbitrary text, not a code",
                "bls_normal", "public-key parsing")
            val mapped = original.toAccountAddressException()
            assertEquals(category, mapped.code)
            assertTrue(mapped.cause === original)
            assertEquals("bls_normal", original.algorithm)
            assertEquals("public-key parsing", original.operation)
        }
        assertEquals(AccountAddressErrorCode.NATIVE_BRIDGE_UNAVAILABLE,
            AccountAddressNativeException("ERR_UNKNOWN_NATIVE_CODE", "invalid", "", "").toAccountAddressException().code)
        val unknown = assertFailsWith<AccountAddressException> { AccountAddressNative.requireSingleSize(255, 32) }
        assertEquals(AccountAddressErrorCode.UNKNOWN_CURVE, unknown.code)
    }

    @Test
    fun multisigConstructionMatchesFullRustPoliciesForEveryMemberOrder() {
        val path = "fixtures/account/address_vectors.json"
        val file = generateSequence(File(".").canonicalFile) { it.parentFile }
            .map { File(it, path) }.first(File::isFile)
        val fixture = JsonParser.parse(file.readText(Charsets.UTF_8)) as Map<*, *>
        val cases = ((fixture["cases"] as Map<*, *>)["positive"] as List<*>)
            .map { it as Map<*, *> }.filter { it["category"] == "multisig" }
        assertTrue(cases.isNotEmpty())
        for (vector in cases) {
            val controller = vector["controller"] as Map<*, *>
            val original = (controller["members"] as List<*>).map {
                val member = it as Map<*, *>
                MultisigMemberPayload(1, (member["weight"] as Number).toInt(), hex(member["public_key_hex"] as String))
            }
            val encodings = vector["encodings"] as Map<*, *>
            val canonical = hex(encodings["canonical_hex"] as String)
            val i105 = (encodings["i105"] as Map<*, *>)["string"] as String
            for (rotation in original.indices) {
                for (members in listOf(original.drop(rotation) + original.take(rotation),
                    (original.drop(rotation) + original.take(rotation)).reversed())) {
                    val callerMembers = members.toMutableList()
                    val policy = MultisigPolicyPayload.of(1, (controller["threshold"] as Number).toInt(), callerMembers)
                    val address = AccountAddress.fromMultisigPolicy(policy)
                    assertContentEquals(canonical, address.canonicalBytes)
                    assertEquals(i105, address.toI105Default())
                    assertEquals(members, callerMembers)
                    assertEquals(members, policy.members)
                    val decoded = assertNotNull(address.multisigPolicyPayload())
                    assertEquals(original.map { it.weight }, decoded.members.map { it.weight })
                    original.zip(decoded.members).forEach { (expected, actual) ->
                        assertContentEquals(expected.publicKey, actual.publicKey)
                    }
                }
            }
        }
    }

    @Test
    fun multisigExternalEncodingsRejectReorderedDuplicatedAndUnsupportedPolicies() {
        val members = listOf(
            MultisigMemberPayload(1, 1, TestEd25519Keys.publicKey(0x11)),
            MultisigMemberPayload(1, 2, TestEd25519Keys.publicKey(0x22)),
        )
        val canonical = AccountAddress.fromMultisigPolicy(MultisigPolicyPayload.of(1, 2, members)).canonicalBytes
        val header = canonical.copyOfRange(0, 7)
        val first = canonical.copyOfRange(7, 44)
        val second = canonical.copyOfRange(44, 81)
        for (malformed in listOf(header + second + first, header + first + first,
            canonical.copyOf().also { it[2] = 2 })) {
            assertFailsWith<AccountAddressException> { AccountAddress.fromCanonicalBytes(malformed) }
        }
        for (version in listOf(0, 2, 257)) {
            assertFailsWith<AccountAddressException> {
                AccountAddress.fromMultisigPolicy(MultisigPolicyPayload.of(version, 2, members))
            }
        }
        assertFailsWith<AccountAddressException> {
            AccountAddress.fromMultisigPolicy(MultisigPolicyPayload.of(1, 65537, members))
        }
        for (duplicateWeight in listOf(1, 2)) {
            assertFailsWith<AccountAddressException> {
                AccountAddress.fromMultisigPolicy(MultisigPolicyPayload.of(1, 2,
                    listOf(members[0], MultisigMemberPayload(1, duplicateWeight, members[0].publicKey))))
            }
        }
    }

    @Test
    fun multisigKeyOrderingUsesAlgorithmNamesAndUnsignedFullPayloads() {
        val ed = MultisigMemberPayload(1, 1, byteArrayOf(0x7f, 1))
        val bls = MultisigMemberPayload(3, 1, byteArrayOf(0xff.toByte()))
        assertTrue(compareMultisigMemberKeys(bls, ed) < 0)
        assertTrue(compareMultisigMemberKeys(ed, MultisigMemberPayload(1, 1, byteArrayOf(0x80.toByte()))) < 0)
        assertTrue(compareMultisigMemberKeys(ed, MultisigMemberPayload(1, 1, byteArrayOf(0x7f, 2))) < 0)
        assertEquals(0, compareMultisigMemberKeys(ed, MultisigMemberPayload(1, 7, ed.publicKey)))
    }

    private fun hex(value: String): ByteArray = value.removePrefix("0x").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test
    fun mixedI105LiteralRoundTripsToOriginalCanonicalPayload() {
        val literal =
            "sorauﾛ1PﾜdﾎｼﾋﾉNｸdﾁﾑkiﾇ3ｵﾓaPBQDTｲKqｼqｵrﾗｶwSQ1ﾌﾅQU61Y7"
        val address = AccountAddress.fromI105(literal, AccountAddress.DEFAULT_I105_DISCRIMINANT)
        assertEquals(
            "0x02000120bc717326224e4b4119298e7b1db8133cb27d6cdf6b3e04d75a6d27b29a34c1cf",
            address.canonicalHex(),
        )
        assertEquals(literal, address.toI105(AccountAddress.DEFAULT_I105_DISCRIMINANT))
    }

    @Test
    fun rejectsNonCanonicalFullwidthKanaPayload() {
        val literal =
            "sorauﾛ1PﾜdﾎｼﾋﾉNｸdﾁﾑkiﾇ3ｵﾓaPBQDTｲKqｼqｵrﾗｶwSQ1ﾌﾅQU61Y7"
        val nonCanonical = literal.replaceFirst("ﾛ", "ロ")

        val error = assertFailsWith<AccountAddressException> {
            AccountAddress.fromI105(nonCanonical, AccountAddress.DEFAULT_I105_DISCRIMINANT)
        }
        assertEquals(AccountAddressErrorCode.INVALID_I105_CHAR, error.code)
    }

    @Test
    fun rejectsRetiredDomainSelectorPrefix() {
        val canonical = AccountAddress.fromAccount(TestEd25519Keys.publicKey(0x01), "ed25519")
            .canonicalBytes
        val selectorPrefixed =
            byteArrayOf(canonical[0], 0x01) +
                ByteArray(12) { (it + 1).toByte() } +
                canonical.copyOfRange(1, canonical.size)

        assertFailsWith<AccountAddressException> {
            AccountAddress.fromCanonicalBytes(selectorPrefixed)
        }
    }

    @Test
    fun curveRegistryCoversAllCryptoAlgorithms() {
        assertEquals("secp256k1", algorithmForCurveId(0x04))
        assertEquals("bls_normal", algorithmForCurveId(0x03))
        assertEquals("bls_small", algorithmForCurveId(0x05))

        val secpKey = NativeAccountFixtures.singleKey("secp256k1")
        val secpAddress = AccountAddress.fromAccount(secpKey, "secp256k1")
        assertEquals(0x04, secpAddress.singleKeyPayload()?.curveId)

        val blsKey = NativeAccountFixtures.singleKey("bls_normal")
        assertFailsWith<AccountAddressException> {
            AccountAddress.fromAccount(ByteArray(48) { 0xff.toByte() }, "bls_normal")
        }

        val blsAddress = AccountAddress.fromAccount(blsKey, "bls_normal")
        assertEquals(0x03, blsAddress.singleKeyPayload()?.curveId)

        val encoded = encodePublicKeyMultihash(0x04, secpKey)
        val decoded = assertNotNull(decodePublicKeyLiteral(encoded))
        assertEquals(0x04, decoded.curveId)
        assertEquals(secpKey.toList(), decoded.keyBytes.toList())

        val compact = compactPublicKeyPayload(0x04, secpKey)
        assertEquals(1, compact[0].toInt())
        val decodedCompact = assertNotNull(decodeCompactPublicKeyPayload(compact))
        assertEquals(0x04, decodedCompact.curveId)
        assertEquals(secpKey.toList(), decodedCompact.keyBytes.toList())
    }

    @Test
    fun protocolMlDsa65UsesOnlyCanonicalIdentity() {
        val key = ByteArray(MlDsaPublicKeyAdmission.PUBLIC_KEY_LENGTH) { 0x02 }

        val address = AccountAddress.fromAccount(key, "ml-dsa")
        assertEquals(0x02, address.singleKeyPayload()?.curveId)

        for (algorithm in listOf(
            "mldsa", "ml_dsa", "mldsa65", "MLDSA65", "ml-dsa-65", "ML-DSA-65",
            "ml_dsa_65", "ML_DSA_65", "ml_dsa-65", "ML_DSA-65",
            "mldsa44",
            "ml-dsa-44",
            "ml_dsa_44",
            "ml_dsa-44",
            "mldsa87",
            "ml-dsa-87",
            "ml_dsa_87",
            "ml_dsa-87",
            "ml-dsa-\uFF16\uFF15",
            "ml\uFF0Ddsa-65",
        )) {
            val error = assertFailsWith<AccountAddressException> {
                AccountAddress.fromAccount(key, algorithm)
            }
            assertEquals(AccountAddressErrorCode.UNKNOWN_ALGORITHM, error.code)
        }
    }

    @Test
    fun fromAccountRejectsBlankOrPaddedCurveAlgorithmAliases() {
        val key = ByteArray(32) { 0x11 }
        for (algorithm in listOf(
            "",
            " ",
            " ed25519",
            "ed25519 ",
            "\ted25519",
            "ed25519\n",
            "\u00A0ed25519",
            "ed25519\u00A0",
        )) {
            val error = assertFailsWith<AccountAddressException> {
                AccountAddress.fromAccount(key, algorithm)
            }
            assertEquals(AccountAddressErrorCode.UNKNOWN_ALGORITHM, error.code)
        }
    }

    @Test
    fun fromAccountRejectsControlAndUnicodeConfusableCurveAlgorithmAliases() {
        val key = ByteArray(32) { 0x11 }
        for (algorithm in listOf(
            "future-curve",
            "ed\t25519",
            "ed\u200B25519",
            "\u0435d25519",
            "ml\uFF0Ddsa",
            "gost256\u0430",
        )) {
            val error = assertFailsWith<AccountAddressException> {
                AccountAddress.fromAccount(key, algorithm)
            }
            assertEquals(AccountAddressErrorCode.UNKNOWN_ALGORITHM, error.code)
        }
    }

    @Test
    fun longGostLabelsAreAcceptedByTheFixedV1Catalog() {
        val key = NativeAccountFixtures.singleKey("gost3410-2012-256-paramset-a")

        val address = AccountAddress.fromAccount(key, "gost3410-2012-256-paramset-a")
        assertEquals(0x0A, address.singleKeyPayload()?.curveId)
    }
}
