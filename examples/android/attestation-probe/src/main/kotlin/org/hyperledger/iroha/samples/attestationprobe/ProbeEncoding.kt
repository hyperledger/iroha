package org.hyperledger.iroha.samples.attestationprobe

import java.security.MessageDigest
import java.util.Base64

/** Encoding for public diagnostic artifacts; it is not a wallet wire format. */
internal object ProbeEncoding {
    fun challenge(hex: String): ByteArray {
        require(hex.length == 64 && hex.all { it in "0123456789abcdefABCDEF" }) {
            "Enter exactly 64 hexadecimal characters (32 bytes)."
        }
        return ByteArray(32) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    fun sha256(bytes: ByteArray): String = hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    fun pem(type: String, bytes: ByteArray): String =
        "-----BEGIN $type-----\n" +
            Base64.getEncoder().encodeToString(bytes).chunked(64).joinToString("\n") +
            "\n-----END $type-----\n"
}
