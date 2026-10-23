package org.hyperledger.iroha.sdk.address

import org.hyperledger.iroha.sdk.crypto.Ed25519PublicKeyAdmission
import org.hyperledger.iroha.sdk.crypto.MlDsaPublicKeyAdmission
import org.hyperledger.iroha.sdk.norito.Varint

class PublicKeyPayload(
    @JvmField val curveId: Int,
    keyBytes: ByteArray,
) {
    private val _keyBytes: ByteArray = keyBytes.also {
        AccountAddressNative.requireSingleSize(curveId, it.size)
    }.copyOf()

    init {
        AccountAddressNative.validateSingle(curveId, _keyBytes)
    }

    val keyBytes: ByteArray get() = _keyBytes.copyOf()
}

/**
 * Decodes a multihash public key literal into its curve id and payload bytes.
 * The literal may be bare or use one exact canonical algorithm prefix; surrounding whitespace,
 * unknown prefixes, and prefixes that do not match the encoded curve are rejected. Returns `null`
 * when the literal is not a valid multihash key.
 */
fun decodePublicKeyLiteral(literal: String?): PublicKeyPayload? {
    if (literal == null || literal.length > 2 * (AccountAddressNative.MAX_PUBLIC_KEY_BYTES + 20) + 32) return null
    if (literal.isBlank()) return null
    if (isPublicKeyLiteralWhitespace(literal.first()) || isPublicKeyLiteralWhitespace(literal.last())) return null
    var encoded = literal
    var algorithmPrefix: String? = null
    val colonIndex = encoded.indexOf(':')
    if (colonIndex >= 0) {
        if (colonIndex == 0 || colonIndex == encoded.lastIndex || colonIndex != encoded.lastIndexOf(':')) return null
        algorithmPrefix = encoded.substring(0, colonIndex)
        encoded = encoded.substring(colonIndex + 1)
    }
    if (encoded.startsWith("0x") || encoded.startsWith("0X")) return null
    if ((encoded.length and 1) == 1) return null
    if (!encoded.matches(Regex("(?i)[0-9a-f]+"))) return null
    val bytes = hexToBytes(encoded)
    val code: Varint.DecodeResult
    val len: Varint.DecodeResult
    try {
        code = Varint.decode(bytes, 0)
        len = Varint.decode(bytes, code.nextOffset())
    } catch (_: IllegalArgumentException) {
        return null
    }
    if (len.value() !in 1..AccountAddressNative.MAX_PUBLIC_KEY_BYTES.toLong()) return null
    val payloadOffset = len.nextOffset()
    val payloadLength = len.value().toInt()
    if (payloadLength != bytes.size - payloadOffset) return null
    val curveId = curveIdForMultihashCode(code.value())
    if (curveId < 0) return null
    if (algorithmPrefix != null && algorithmPrefix != algorithmForCurveId(curveId)) return null
    val keyBytes = bytes.copyOfRange(payloadOffset, payloadOffset + payloadLength)
    if (curveId == 0x01 && !Ed25519PublicKeyAdmission.isValid(keyBytes)) return null
    if (curveId == 0x02 && !MlDsaPublicKeyAdmission.isValid(keyBytes)) return null
    return admitDecodedPublicKey(curveId, keyBytes)
}

private fun isPublicKeyLiteralWhitespace(character: Char): Boolean =
    Character.isWhitespace(character) || Character.isSpaceChar(character)

/** Encodes the multihash public key literal from the given curve id and key bytes. */
fun encodePublicKeyMultihash(curveId: Int, keyBytes: ByteArray): String {
    AccountAddressNative.requireSingleSize(curveId, keyBytes.size)
    val ownedKey = keyBytes.copyOf()
    val codeVarint = Varint.encode(multihashCodeForCurveId(curveId))
    requireValidPublicKeyForEncoding(curveId, ownedKey)
    val lenVarint = Varint.encode(ownedKey.size.toLong())
    val builder = StringBuilder((codeVarint.size + lenVarint.size + ownedKey.size) * 2)
    appendHexLower(builder, codeVarint)
    appendHexLower(builder, lenVarint)
    appendHexUpper(builder, ownedKey)
    return builder.toString()
}

/** Encodes a public key as Iroha's compact Norito payload (`algorithm tag || key bytes`). */
fun compactPublicKeyPayload(curveId: Int, keyBytes: ByteArray): ByteArray {
    AccountAddressNative.requireSingleSize(curveId, keyBytes.size)
    val ownedKey = keyBytes.copyOf()
    val tag = compactAlgorithmTagForCurveId(curveId)
    requireValidPublicKeyForEncoding(curveId, ownedKey)
    val payload = ByteArray(1 + ownedKey.size)
    payload[0] = tag.toByte()
    System.arraycopy(ownedKey, 0, payload, 1, ownedKey.size)
    return payload
}

/** Decodes Iroha's compact Norito public-key payload. */
fun decodeCompactPublicKeyPayload(payload: ByteArray?): PublicKeyPayload? {
    if (payload == null || payload.size !in 2..AccountAddressNative.MAX_PUBLIC_KEY_BYTES + 1) return null
    val curveId = curveIdForCompactAlgorithmTag(payload[0].toInt() and 0xFF)
    if (curveId < 0) return null
    val keyBytes = payload.copyOfRange(1, payload.size)
    if (curveId == 0x01 && !Ed25519PublicKeyAdmission.isValid(keyBytes)) return null
    if (curveId == 0x02 && !MlDsaPublicKeyAdmission.isValid(keyBytes)) return null
    return admitDecodedPublicKey(curveId, keyBytes)
}

/** Returns the canonical signing algorithm name for the curve id, or `null` when unknown. */
fun algorithmForCurveId(curveId: Int): String? = when (curveId) {
    0x01 -> "ed25519"
    0x02 -> "ml-dsa"
    0x03 -> "bls_normal"
    0x04 -> "secp256k1"
    0x05 -> "bls_small"
    0x0A -> "gost3410-2012-256-paramset-a"
    0x0B -> "gost3410-2012-256-paramset-b"
    0x0C -> "gost3410-2012-256-paramset-c"
    0x0D -> "gost3410-2012-512-paramset-a"
    0x0E -> "gost3410-2012-512-paramset-b"
    0x0F -> "sm2"
    else -> null
}

private fun requireValidPublicKeyForEncoding(curveId: Int, keyBytes: ByteArray) {
    AccountAddressNative.validateSingle(curveId, keyBytes)
    require(curveId != 0x01 || Ed25519PublicKeyAdmission.isValid(keyBytes)) {
        "invalid Ed25519 public key: expected a canonical point in the prime-order subgroup"
    }
    require(curveId != 0x02 || MlDsaPublicKeyAdmission.isValid(keyBytes)) {
        "invalid ML-DSA-65 public key: expected ${MlDsaPublicKeyAdmission.PUBLIC_KEY_LENGTH} nonzero bytes"
    }
}

private fun admitDecodedPublicKey(curveId: Int, keyBytes: ByteArray): PublicKeyPayload? = try {
    PublicKeyPayload(curveId, keyBytes)
} catch (error: AccountAddressException) {
    if (error.code == AccountAddressErrorCode.NATIVE_BRIDGE_UNAVAILABLE) throw error
    null
}

private fun compactAlgorithmTagForCurveId(curveId: Int): Int = when (curveId) {
    0x01 -> 0
    0x04 -> 1
    0x03 -> 2
    0x05 -> 3
    0x02 -> 4
    0x0A -> 5
    0x0B -> 6
    0x0C -> 7
    0x0D -> 8
    0x0E -> 9
    0x0F -> 10
    else -> throw IllegalArgumentException("Unsupported curve id: $curveId")
}

private fun curveIdForCompactAlgorithmTag(tag: Int): Int = when (tag) {
    0 -> 0x01
    1 -> 0x04
    2 -> 0x03
    3 -> 0x05
    4 -> 0x02
    5 -> 0x0A
    6 -> 0x0B
    7 -> 0x0C
    8 -> 0x0D
    9 -> 0x0E
    10 -> 0x0F
    else -> -1
}

private fun curveIdForMultihashCode(code: Long): Int = when (code) {
    0xedL -> 0x01
    0xeaL -> 0x03
    0xebL -> 0x05
    0xe7L -> 0x04
    0xeeL -> 0x02
    0x1200L -> 0x0A
    0x1201L -> 0x0B
    0x1202L -> 0x0C
    0x1203L -> 0x0D
    0x1204L -> 0x0E
    0x1306L -> 0x0F
    else -> -1
}

private fun multihashCodeForCurveId(curveId: Int): Long = when (curveId) {
    0x01 -> 0xedL
    0x02 -> 0xeeL
    0x03 -> 0xeaL
    0x04 -> 0xe7L
    0x05 -> 0xebL
    0x0A -> 0x1200L
    0x0B -> 0x1201L
    0x0C -> 0x1202L
    0x0D -> 0x1203L
    0x0E -> 0x1204L
    0x0F -> 0x1306L
    else -> throw IllegalArgumentException("Unsupported curve id: $curveId")
}

private fun hexToBytes(hex: String): ByteArray {
    val out = ByteArray(hex.length / 2)
    for (i in out.indices) {
        val high = Character.digit(hex[i * 2], 16)
        val low = Character.digit(hex[i * 2 + 1], 16)
        require(high >= 0 && low >= 0) { "Invalid hex literal" }
        out[i] = ((high shl 4) + low).toByte()
    }
    return out
}

private fun appendHexLower(builder: StringBuilder, bytes: ByteArray) {
    for (b in bytes) {
        builder.append(String.format("%02x", b.toInt() and 0xFF))
    }
}

private fun appendHexUpper(builder: StringBuilder, bytes: ByteArray) {
    for (b in bytes) {
        builder.append(String.format("%02X", b.toInt() and 0xFF))
    }
}
