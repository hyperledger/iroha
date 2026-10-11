package org.hyperledger.iroha.sdk.client

import java.security.KeyPairGenerator
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.testing.TestEd25519Keys

private val applicationKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

internal fun applicationAuth(
    accountId: String = AccountAddress.fromAccount(TestEd25519Keys.publicKey(0x33), "ed25519")
        .toI105(AccountAddress.DEFAULT_I105_DISCRIMINANT),
): ToriiCanonicalRequestAuth =
    ToriiCanonicalRequestAuth(
        accountId,
        RequestSigner.ed25519(applicationKeyPair.private),
        1_700_000_000_123L,
        "application-post-auth",
    )

internal fun noncanonicalStandardBase64PadBitAlias(encoded: String): String {
    require(encoded.endsWith("==")) { "64-byte signatures encode with == padding" }
    val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    val chars = encoded.toCharArray()
    val index = chars.size - 3
    val value = alphabet.indexOf(chars[index])
    require(value >= 0) { "standard base64 alphabet" }
    chars[index] = alphabet[value xor 0x01]
    return String(chars)
}

/** Requires DATA produced by the current genuine Native evaluator/signature fixture command. */
@Suppress("UNCHECKED_CAST")
internal fun currentOwnerExecuteFixture(): Map<String, Any?> {
    var directory: java.nio.file.Path? = java.nio.file.Paths.get("").toAbsolutePath()
    while (directory != null) {
        val candidate = directory.resolve("fixtures/soracloud/identifier_owner_execute_v1.json")
        if (java.nio.file.Files.isRegularFile(candidate)) {
            val fixture = JsonParser.parse(String(java.nio.file.Files.readAllBytes(candidate), java.nio.charset.StandardCharsets.UTF_8)) as? Map<String, Any?>
                ?: throw IllegalStateException("Current Native execute DATA fixture must be an object")
            check(fixture["schema"] == "iroha.identifier.owner-execute.v1" && fixture["classification"] == "PUBLIC_SOFTWARE_DATA_UNADMITTED") { "Current genuine Native DATA fixture required" }
            return fixture
        }
        directory = directory.parent
    }
    throw IllegalStateException("Generate fixtures/soracloud/identifier_owner_execute_v1.json with the current source-bound Rust identifier-owner-execute-v1 command; do not fabricate a positive frame")
}

internal fun currentOwnerExecuteResponseField(field: String): String =
    ((currentOwnerExecuteFixture()["response"] as Map<*, *>)[field] as? String)
        ?: throw IllegalStateException("Missing Native execute DATA field $field")

internal fun ramLfeExecuteResponseJson(): String =
    JsonEncoder.encode(currentOwnerExecuteFixture()["response"]).replace("\":", "\": ")

internal fun ramLfeReceiptVerifyResponseJson(): String =
    """
        {
          "valid": true,
          "program_id": "identifier_lookup_retail",
          "backend": "bfv-programmed-v1",
          "verification_mode": "signed",
          "output_hash": "${"44".repeat(32)}",
          "associated_data_hash": "${"55".repeat(32)}",
          "output_hash_matches": true
        }
    """.trimIndent()
