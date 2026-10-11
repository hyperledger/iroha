// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/**
 * Canonical NIST P-256 boundary for the sole KAGEMUSHA V1 device-authority profile.
 *
 * Public keys are exactly uncompressed SEC1 (`04 || x || y`). Wire signatures are exactly
 * fixed-width `r || s` and must already use low-S form. Platform ECDSA APIs commonly return DER;
 * [rawLowSFromStrictDer] accepts only minimal DER and normalizes its valid S scalar to low-S.
 * Received signatures are verified with [verifyRawLowS], which rejects high S before JCA
 * verification (JCA itself accepts both S forms) and never rewrites the received bytes.
 */
object KagemushaP256Codec {
    const val SCALAR_BYTES: Int = 32
    const val PUBLIC_KEY_BYTES: Int = 65
    const val RAW_SIGNATURE_BYTES: Int = 64

    private val FIELD_PRIME =
        BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
    private val CURVE_B =
        BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
    private val ORDER =
        BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    private val HALF_ORDER = ORDER.shiftRight(1)
    private val TWO = BigInteger.valueOf(2L)
    private val THREE = BigInteger.valueOf(3L)
    private const val JCA_SIGNATURE_ALGORITHM = "SHA256withECDSA"

    /** JCA `secp256r1` domain parameters, resolved once through JDK 8 APIs. */
    private val P256_PARAMETERS: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }
    }

    /**
     * Convert one canonical uncompressed P-256 SEC1 public key to its JCA form.
     *
     * The key is first checked by [requireUncompressedPublicKey] (exact 65 bytes, `0x04` prefix,
     * coordinates inside the field, point on the curve). Construction uses only JDK 8 APIs:
     * `AlgorithmParameters("EC")` with `ECGenParameterSpec("secp256r1")` and `ECPublicKeySpec`.
     *
     * @throws IllegalArgumentException when the bytes are not a canonical P-256 point.
     */
    @JvmStatic
    fun publicKeyFromSec1(sec1Bytes: ByteArray): ECPublicKey {
        val value = requireUncompressedPublicKey(sec1Bytes)
        val point = ECPoint(
            BigInteger(1, value.copyOfRange(1, 1 + SCALAR_BYTES)),
            BigInteger(1, value.copyOfRange(1 + SCALAR_BYTES, PUBLIC_KEY_BYTES)),
        )
        val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, P256_PARAMETERS))
        return key as? ECPublicKey
            ?: throw IllegalStateException("JCA returned a non-EC key for a KAGEMUSHA V1 P-256 point")
    }

    /**
     * Verify one received fixed-width signature over the exact [preimage] with ECDSA-P256-SHA256.
     *
     * The signature must first pass the canonical raw low-S check of [requireRawLowSSignature]
     * (`1 <= r < n`, `1 <= s <= floor(n/2)`), because JCA accepts the high-S twin of every valid
     * signature. Only then is it converted to strict DER and checked with JCA `SHA256withECDSA`,
     * which hashes [preimage] once. The received bytes are never normalized.
     *
     * Returns `false` for a non-canonical key, a non-canonical or high-S signature, and a
     * signature that does not verify.
     */
    @JvmStatic
    fun verifyRawLowS(publicKeySec1: ByteArray, preimage: ByteArray, rawSignature: ByteArray): Boolean {
        val raw = try {
            requireRawLowSSignature(rawSignature)
        } catch (rejected: IllegalArgumentException) {
            return false
        }
        val publicKey = try {
            publicKeyFromSec1(publicKeySec1)
        } catch (rejected: IllegalArgumentException) {
            return false
        } catch (rejected: GeneralSecurityException) {
            return false
        }
        return try {
            Signature.getInstance(JCA_SIGNATURE_ALGORITHM).run {
                initVerify(publicKey)
                update(preimage)
                verify(strictDerFromRawLowS(raw))
            }
        } catch (rejected: GeneralSecurityException) {
            false
        }
    }

    /** Validate and defensively copy one canonical uncompressed P-256 public key. */
    @JvmStatic
    fun requireUncompressedPublicKey(sec1Bytes: ByteArray): ByteArray {
        val value = sec1Bytes.copyOf()
        require(value.size == PUBLIC_KEY_BYTES && value[0].toInt() == 0x04) {
            "KAGEMUSHA V1 device public key must be exactly 65-byte uncompressed P-256 SEC1"
        }
        val x = BigInteger(1, value.copyOfRange(1, 33))
        val y = BigInteger(1, value.copyOfRange(33, 65))
        require(x < FIELD_PRIME && y < FIELD_PRIME) {
            "KAGEMUSHA V1 device public key coordinates exceed the P-256 field"
        }
        val lhs = y.modPow(TWO, FIELD_PRIME)
        val rhs = x.modPow(THREE, FIELD_PRIME)
            .subtract(THREE.multiply(x))
            .add(CURVE_B)
            .mod(FIELD_PRIME)
        require(lhs == rhs) { "KAGEMUSHA V1 device public key is not a P-256 point" }
        return value
    }

    /** Validate and defensively copy the canonical 64-byte low-S wire signature. */
    @JvmStatic
    fun requireRawLowSSignature(rawBytes: ByteArray): ByteArray {
        val value = rawBytes.copyOf()
        require(value.size == RAW_SIGNATURE_BYTES) {
            "KAGEMUSHA V1 device signature must be exactly 64-byte r||s"
        }
        val r = BigInteger(1, value.copyOfRange(0, SCALAR_BYTES))
        val s = BigInteger(1, value.copyOfRange(SCALAR_BYTES, RAW_SIGNATURE_BYTES))
        requireScalar(r, "r")
        requireScalar(s, "s")
        require(s <= HALF_ORDER) { "KAGEMUSHA V1 device signature must use low-S form" }
        return value
    }

    /**
     * Convert one strict DER ECDSA signature to canonical raw low-S form.
     *
     * High-S DER produced by a platform signer is normalized to `n - s`. Non-minimal DER,
     * negative/zero/out-of-range scalars, long-form lengths, and trailing bytes are rejected.
     */
    @JvmStatic
    fun rawLowSFromStrictDer(derBytes: ByteArray): ByteArray {
        val der = derBytes.copyOf()
        require(der.size in 8..72 && unsigned(der[0]) == 0x30) {
            "KAGEMUSHA V1 ECDSA signature is not strict DER"
        }
        require(unsigned(der[1]) < 0x80 && unsigned(der[1]) == der.size - 2) {
            "KAGEMUSHA V1 ECDSA signature uses a non-canonical DER length"
        }
        var cursor = 2
        val r = decodeInteger(der, cursor).also { cursor = it.second }.first
        val s = decodeInteger(der, cursor).also { cursor = it.second }.first
        require(cursor == der.size) { "KAGEMUSHA V1 ECDSA signature has trailing DER bytes" }
        val lowS = if (s > HALF_ORDER) ORDER.subtract(s) else s
        return fixedScalar(r) + fixedScalar(lowS)
    }

    /** Convert one canonical raw low-S signature to minimal DER. */
    @JvmStatic
    fun strictDerFromRawLowS(rawBytes: ByteArray): ByteArray {
        val raw = requireRawLowSSignature(rawBytes)
        val r = encodeInteger(raw.copyOfRange(0, SCALAR_BYTES))
        val s = encodeInteger(raw.copyOfRange(SCALAR_BYTES, RAW_SIGNATURE_BYTES))
        val bodyLength = 2 + r.size + 2 + s.size
        check(bodyLength < 0x80)
        return ByteArrayOutputStream(bodyLength + 2).apply {
            write(0x30)
            write(bodyLength)
            write(0x02)
            write(r.size)
            write(r)
            write(0x02)
            write(s.size)
            write(s)
        }.toByteArray()
    }

    private fun decodeInteger(bytes: ByteArray, start: Int): Pair<BigInteger, Int> {
        require(start + 2 <= bytes.size && unsigned(bytes[start]) == 0x02) {
            "KAGEMUSHA V1 ECDSA signature is missing a DER INTEGER"
        }
        val length = unsigned(bytes[start + 1])
        require(length in 1..(SCALAR_BYTES + 1) && start + 2 + length <= bytes.size) {
            "KAGEMUSHA V1 ECDSA signature has an invalid DER INTEGER length"
        }
        val encoded = bytes.copyOfRange(start + 2, start + 2 + length)
        require(unsigned(encoded[0]) < 0x80) {
            "KAGEMUSHA V1 ECDSA signature contains a negative DER INTEGER"
        }
        if (encoded.size > 1 && encoded[0].toInt() == 0) {
            require(unsigned(encoded[1]) >= 0x80) {
                "KAGEMUSHA V1 ECDSA signature contains non-minimal DER INTEGER padding"
            }
        }
        val scalarBytes = if (encoded.size == SCALAR_BYTES + 1) {
            require(encoded[0].toInt() == 0 && unsigned(encoded[1]) >= 0x80) {
                "KAGEMUSHA V1 ECDSA signature DER INTEGER exceeds P-256 width"
            }
            encoded.copyOfRange(1, encoded.size)
        } else {
            encoded
        }
        val value = BigInteger(1, scalarBytes)
        requireScalar(value, "DER scalar")
        return value to (start + 2 + length)
    }

    private fun requireScalar(value: BigInteger, field: String) {
        require(value.signum() > 0 && value < ORDER) {
            "KAGEMUSHA V1 ECDSA $field scalar is outside the P-256 order"
        }
    }

    private fun fixedScalar(value: BigInteger): ByteArray {
        val signed = value.toByteArray()
        val unsigned = if (signed.size == SCALAR_BYTES + 1 && signed[0].toInt() == 0) {
            signed.copyOfRange(1, signed.size)
        } else {
            signed
        }
        check(unsigned.size <= SCALAR_BYTES)
        return ByteArray(SCALAR_BYTES).also {
            unsigned.copyInto(it, SCALAR_BYTES - unsigned.size)
        }
    }

    private fun encodeInteger(fixed: ByteArray): ByteArray {
        var first = 0
        while (first < fixed.lastIndex && fixed[first].toInt() == 0) first += 1
        val significant = fixed.copyOfRange(first, fixed.size)
        return if (unsigned(significant[0]) >= 0x80) byteArrayOf(0) + significant else significant
    }

    private fun unsigned(value: Byte): Int = value.toInt() and 0xff
}
