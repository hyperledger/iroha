package org.hyperledger.iroha.sdk.address

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import org.hyperledger.iroha.sdk.crypto.Ed25519PublicKeyAdmission
import org.hyperledger.iroha.sdk.crypto.MlDsaPublicKeyAdmission

private const val I105_WARNING =
    "i105 addresses use the canonical I105 alphabet: Base58 plus the 47 half-width katakana from the Iroha poem. " +
        "Render and validate them with the intended chain discriminant."
private const val I105_DISCRIMINANT_MAX = 0xFFFF
private const val I105_DISCRIMINANT_SORA = 0x02F1
private const val I105_DISCRIMINANT_TEST = 0x0171
private const val I105_DISCRIMINANT_DEV = 0x0000
private const val I105_CHECKSUM_LEN = 6
private const val BECH32M_CONST = 0x2bc830a3
private const val HEADER_VERSION_V1 = 0
private const val HEADER_NORM_VERSION_V1 = 1
private const val ADDRESS_CLASS_SINGLE_KEY = 0
private const val ADDRESS_CLASS_MULTISIG = 1
private const val CONTROLLER_SINGLE_KEY_TAG = 0x00
private const val CONTROLLER_MULTISIG_TAG = 0x01
private const val CONTROLLER_SINGLE_KEY_EXTENDED_TAG = 0x02
private const val I105_SENTINEL_SORA = "sora"
private const val I105_SENTINEL_TEST = "test"
private const val I105_SENTINEL_DEV = "dev"
private const val I105_SENTINEL_NUMERIC_PREFIX = "n"
private val BASE58_ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".map { it.toString() }.toTypedArray()
private val IROHA_POEM_KANA_HALFWIDTH = arrayOf(
    "ｲ", "ﾛ", "ﾊ", "ﾆ", "ﾎ", "ﾍ", "ﾄ", "ﾁ", "ﾘ", "ﾇ", "ﾙ", "ｦ", "ﾜ", "ｶ", "ﾖ", "ﾀ",
    "ﾚ", "ｿ", "ﾂ", "ﾈ", "ﾅ", "ﾗ", "ﾑ", "ｳ", "ヰ", "ﾉ", "ｵ", "ｸ", "ﾔ", "ﾏ", "ｹ", "ﾌ",
    "ｺ", "ｴ", "ﾃ", "ｱ", "ｻ", "ｷ", "ﾕ", "ﾒ", "ﾐ", "ｼ", "ヱ", "ﾋ", "ﾓ", "ｾ", "ｽ",
)
private val I105_ALPHABET = BASE58_ALPHABET + IROHA_POEM_KANA_HALFWIDTH


private fun lookupI105Digit(symbol: String): Int? {
    val canonicalIndex = I105_ALPHABET.indexOf(symbol)
    if (canonicalIndex >= 0) {
        return canonicalIndex
    }
    return null
}

class AccountAddress private constructor(canonicalBytes: ByteArray) {

    private val _canonicalBytes: ByteArray = canonicalBytes.copyOf()

    init {
        AccountAddressNative.validateCanonical(_canonicalBytes)
    }

    val canonicalBytes: ByteArray get() = _canonicalBytes.copyOf()

    fun canonicalHex(): String = "0x${bytesToHex(_canonicalBytes)}"

    @Throws(AccountAddressException::class)
    fun toI105(prefix: Int): String = encodeI105(prefix, _canonicalBytes)

    @Throws(AccountAddressException::class)
    fun toI105Default(): String = toI105(DEFAULT_I105_DISCRIMINANT)

    @Throws(AccountAddressException::class)
    fun displayFormats(): DisplayFormats = displayFormats(DEFAULT_I105_DISCRIMINANT)

    @Throws(AccountAddressException::class)
    fun displayFormats(discriminant: Int): DisplayFormats {
        val i105 = toI105(discriminant)
        return DisplayFormats(i105, discriminant, I105_WARNING)
    }

    /**
     * Returns the single-key controller payload when this address encodes a single-key controller.
     *
     * Multisig addresses return `null`.
     */
    @Throws(AccountAddressException::class)
    fun singleKeyPayload(): SingleKeyPayload? {
        parseCanonical(_canonicalBytes)
        return extractSingleKeyPayload(_canonicalBytes)
    }


    /**
     * Returns the multisig policy payload when this address encodes a multisig controller.
     *
     * Single-key addresses return `null`.
     */
    @Throws(AccountAddressException::class)
    fun multisigPolicyPayload(): MultisigPolicyPayload? {
        parseCanonical(_canonicalBytes)
        return extractMultisigPayload(_canonicalBytes)
    }


    companion object {
        const val DEFAULT_I105_DISCRIMINANT = 753

        @JvmStatic
        fun i105WarningMessage(): String = I105_WARNING

        @JvmStatic
        @Throws(AccountAddressException::class)
        fun fromAccount(
            publicKey: ByteArray,
            algorithm: String,
        ): AccountAddress {
            val curveId = curveIdForAlgorithm(algorithm).toInt() and 0xFF
            if (publicKey.size > 0xFFFF) {
                throw AccountAddressException(
                    AccountAddressErrorCode.KEY_PAYLOAD_TOO_LONG,
                    "key payload too long: ${publicKey.size}",
                )
            }
            val ownedKey = publicKey.copyOf()
            validateControllerPublicKey(curveId, ownedKey)
            val header = encodeHeader(0, ADDRESS_CLASS_SINGLE_KEY, 1)

            val out = ByteArrayOutputStream()
            out.write(header.toInt())
            if (ownedKey.size <= 0xFF) {
                out.write(CONTROLLER_SINGLE_KEY_TAG)
                out.write(curveId)
                out.write(ownedKey.size)
            } else {
                out.write(CONTROLLER_SINGLE_KEY_EXTENDED_TAG)
                out.write(curveId)
                out.write((ownedKey.size shr 8) and 0xFF)
                out.write(ownedKey.size and 0xFF)
            }
            out.write(ownedKey, 0, ownedKey.size)

            return fromCanonicalBytes(out.toByteArray())
        }

        /**
         * Constructs the Rust-compatible V1 identity by sorting complete keys without changing
         * caller members or their weights. Duplicate keys and invalid V1 policies are rejected.
         */
        @JvmStatic
        @Throws(AccountAddressException::class)
        fun fromMultisigPolicy(policy: MultisigPolicyPayload): AccountAddress {
            if (policy.version != 1 || policy.threshold !in 1..0xFFFF) {
                throw AccountAddressException(
                    AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                    "InvalidMultisigPolicy: expected version 1 and a nonzero u16 threshold",
                )
            }
            val members = policy.members
            if (members.isEmpty()) {
                throw AccountAddressException(
                    AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                    "InvalidMultisigPolicy: zero members",
                )
            }
            if (members.size > 0xFFFF) {
                throw AccountAddressException(
                    AccountAddressErrorCode.MULTISIG_MEMBER_OVERFLOW,
                    "InvalidMultisigPolicy: too many members (${members.size})",
                )
            }

            var totalWeight = 0L
            for (member in members) {
                if (member.weight <= 0) {
                    throw AccountAddressException(
                        AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                        "InvalidMultisigPolicy: non-positive weight",
                    )
                }
                if (member.weight > 0xFFFF) {
                    throw AccountAddressException(
                        AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                        "InvalidMultisigPolicy: weight too large",
                    )
                }
                ensureKnownCurve(member.curveId, "curve id ${member.curveId}")
                if (member.publicKey.isEmpty()) {
                    throw AccountAddressException(
                        AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                        "InvalidMultisigPolicy: invalid key length",
                    )
                }
                if (member.publicKey.size > 0xFFFF) {
                    throw AccountAddressException(
                        AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                        "InvalidMultisigPolicy: key too long",
                    )
                }
                validateControllerPublicKey(member.curveId, member.publicKey)
                totalWeight += member.weight
            }
            if (policy.threshold <= 0) {
                throw AccountAddressException(
                    AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                    "InvalidMultisigPolicy: ZeroThreshold",
                )
            }
            if (totalWeight < policy.threshold) {
                throw AccountAddressException(
                    AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                    "InvalidMultisigPolicy: threshold exceeds total weight",
                )
            }
            val sortedMembers = members.sortedWith(::compareMultisigMemberKeys)
            for (index in 1 until sortedMembers.size) {
                if (compareMultisigMemberKeys(sortedMembers[index - 1], sortedMembers[index]) == 0) {
                    throw AccountAddressException(
                        AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                        "InvalidMultisigPolicy: duplicate member",
                    )
                }
            }

            val header = encodeHeader(0, ADDRESS_CLASS_MULTISIG, 1)
            val out = ByteArrayOutputStream()
            out.write(header.toInt())

            out.write(CONTROLLER_MULTISIG_TAG)
            out.write(policy.version and 0xFF)
            out.write((policy.threshold shr 8) and 0xFF)
            out.write(policy.threshold and 0xFF)
            out.write((members.size shr 8) and 0xFF)
            out.write(members.size and 0xFF)

            for (member in sortedMembers) {
                val curveId = member.curveId and 0xFF
                val weight = member.weight
                val keyBytes = member.publicKey
                out.write(curveId)
                out.write((weight shr 8) and 0xFF)
                out.write(weight and 0xFF)
                out.write((keyBytes.size shr 8) and 0xFF)
                out.write(keyBytes.size and 0xFF)
                out.write(keyBytes, 0, keyBytes.size)
            }

            return fromCanonicalBytes(out.toByteArray())
        }

        @JvmStatic
        @Throws(AccountAddressException::class)
        fun fromCanonicalBytes(canonical: ByteArray): AccountAddress {
            AccountAddressNative.requireCanonicalSize(canonical.size)
            val copy = canonical.copyOf()
            parseCanonical(copy)
            return AccountAddress(copy)
        }

        @JvmStatic
        @Throws(AccountAddressException::class)
        fun fromI105(encoded: String, expectedDiscriminant: Int?): AccountAddress {
            requireExactAccountLiteral(encoded)
            val canonical = decodeI105(encoded, expectedDiscriminant)
            val address = fromCanonicalBytes(canonical)
            ensureCanonicalI105Literal(encoded, address)
            return address
        }

        @JvmStatic
        @Throws(AccountAddressException::class)
        fun parseEncoded(input: String, expectedPrefix: Int?): AccountAddress {
            requireExactAccountLiteral(input)
            val trimmed = input.trim()
            if (trimmed.isEmpty()) {
                throw AccountAddressException(
                    AccountAddressErrorCode.INVALID_LENGTH, "address string is empty",
                )
            }
            if (trimmed.contains("@")) {
                throw AccountAddressException(
                    AccountAddressErrorCode.UNSUPPORTED_ADDRESS_FORMAT,
                    "account address literals must not include @domain; use canonical I105 form",
                )
            }
            if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
                throw AccountAddressException(
                    AccountAddressErrorCode.UNSUPPORTED_ADDRESS_FORMAT,
                    "canonical hex account addresses are not accepted; use canonical I105 form",
                )
            }
            return fromI105(trimmed, expectedPrefix)
        }

        @JvmStatic
        fun detectI105Discriminant(input: String): Int? =
            parseI105SentinelAndPayload(input.trim())?.first

    }
}

// -- Private helper classes --

private class I105PrefixResult(val discriminant: Int, val prefixLength: Int)

private fun requireExactAccountLiteral(input: String) {
    if (input != input.trim()) {
        throw AccountAddressException(AccountAddressErrorCode.UNSUPPORTED_ADDRESS_FORMAT,
            "account address must not contain surrounding whitespace")
    }
}

@Throws(AccountAddressException::class)
private fun ensureCanonicalI105Literal(literal: String, address: AccountAddress) {
    val discriminant = AccountAddress.detectI105Discriminant(literal) ?: return
    val canonical = address.toI105(discriminant)
    if (canonical != literal) {
        throw AccountAddressException(
            AccountAddressErrorCode.UNSUPPORTED_ADDRESS_FORMAT,
            "account address literals must use canonical I105 form",
        )
    }
}

// -- Canonical decoding helpers --

@Throws(AccountAddressException::class)
private fun parseCanonical(canonical: ByteArray) {
    if (canonical.size < 4) {
        throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
    }
    val addressClass = decodeHeader(canonical[0])
    var cursor = 1

    if (cursor >= canonical.size) {
        throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
    }
    val controllerTag = canonical[cursor++].toInt() and 0xFF
    val controllerClass = when (controllerTag) {
        CONTROLLER_SINGLE_KEY_TAG, CONTROLLER_SINGLE_KEY_EXTENDED_TAG -> ADDRESS_CLASS_SINGLE_KEY
        CONTROLLER_MULTISIG_TAG -> ADDRESS_CLASS_MULTISIG
        else -> null
    }
    if (controllerClass != null && controllerClass != addressClass) {
        throw AccountAddressException(
            AccountAddressErrorCode.UNSUPPORTED_ADDRESS_FORMAT,
            "address header class does not match controller tag",
        )
    }
    when (controllerTag) {
        CONTROLLER_SINGLE_KEY_TAG -> {
            if (cursor + 2 > canonical.size) {
                throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
            }
            val curveId = canonical[cursor++].toInt() and 0xFF
            ensureKnownCurve(curveId, "curve id $curveId")
            val keyLen = canonical[cursor++].toInt() and 0xFF
            val end = cursor + keyLen
            if (end > canonical.size) {
                throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
            }
            validateControllerPublicKey(curveId, canonical.copyOfRange(cursor, end))
            if (end != canonical.size) {
                throw AccountAddressException(
                    AccountAddressErrorCode.UNEXPECTED_TRAILING_BYTES,
                    "unexpected trailing bytes in canonical payload",
                )
            }
        }
        CONTROLLER_SINGLE_KEY_EXTENDED_TAG -> {
            if (cursor + 3 > canonical.size) {
                throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
            }
            val curveId = canonical[cursor++].toInt() and 0xFF
            ensureKnownCurve(curveId, "curve id $curveId")
            val keyLen = ((canonical[cursor].toInt() and 0xFF) shl 8) or
                (canonical[cursor + 1].toInt() and 0xFF)
            cursor += 2
            if (keyLen <= 0xFF) {
                throw AccountAddressException(
                    AccountAddressErrorCode.INVALID_LENGTH,
                    "extended single-key payload must exceed 255 bytes",
                )
            }
            val end = cursor + keyLen
            if (end > canonical.size) {
                throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
            }
            validateControllerPublicKey(curveId, canonical.copyOfRange(cursor, end))
            if (end != canonical.size) {
                throw AccountAddressException(
                    AccountAddressErrorCode.UNEXPECTED_TRAILING_BYTES,
                    "unexpected trailing bytes in canonical payload",
                )
            }
        }
        CONTROLLER_MULTISIG_TAG -> {
            if (cursor + 5 > canonical.size) {
                throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
            }
            val version = canonical[cursor++].toInt() and 0xFF
            if (version != 1) {
                throw AccountAddressException(
                    AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                    "InvalidMultisigPolicy: unsupported version $version",
                )
            }
            val threshold = ((canonical[cursor].toInt() and 0xFF) shl 8) or
                (canonical[cursor + 1].toInt() and 0xFF)
            cursor += 2
            val memberCount = ((canonical[cursor].toInt() and 0xFF) shl 8) or
                (canonical[cursor + 1].toInt() and 0xFF)
            cursor += 2
            if (memberCount == 0) {
                throw AccountAddressException(
                    AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                    "InvalidMultisigPolicy: zero members",
                )
            }
            var totalWeight = 0L
            var previousMember: MultisigMemberPayload? = null
            for (i in 0 until memberCount) {
                if (cursor + 5 > canonical.size) {
                    throw AccountAddressException(
                        AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length",
                    )
                }
                val curveId = canonical[cursor++].toInt() and 0xFF
                ensureKnownCurve(curveId, "curve id $curveId")
                val weight = ((canonical[cursor].toInt() and 0xFF) shl 8) or
                    (canonical[cursor + 1].toInt() and 0xFF)
                cursor += 2
                if (weight <= 0) {
                    throw AccountAddressException(
                        AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                        "InvalidMultisigPolicy: non-positive weight",
                    )
                }
                val keyLen = ((canonical[cursor].toInt() and 0xFF) shl 8) or
                    (canonical[cursor + 1].toInt() and 0xFF)
                cursor += 2
                if (keyLen <= 0) {
                    throw AccountAddressException(
                        AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                        "InvalidMultisigPolicy: invalid key length",
                    )
                }
                if (cursor + keyLen > canonical.size) {
                    throw AccountAddressException(
                        AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length",
                    )
                }
                val key = canonical.copyOfRange(cursor, cursor + keyLen)
                validateControllerPublicKey(curveId, key)
                val member = MultisigMemberPayload(curveId, weight, key)
                if (previousMember != null && compareMultisigMemberKeys(previousMember, member) >= 0) {
                    throw AccountAddressException(
                        AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                        "InvalidMultisigPolicy: members must be unique and in canonical key order",
                    )
                }
                previousMember = member
                cursor += keyLen
                totalWeight += weight
            }
            if (threshold <= 0) {
                throw AccountAddressException(
                    AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                    "InvalidMultisigPolicy: ZeroThreshold",
                )
            }
            if (totalWeight < threshold) {
                throw AccountAddressException(
                    AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                    "InvalidMultisigPolicy: threshold exceeds total weight",
                )
            }
            if (cursor != canonical.size) {
                if (cursor > canonical.size) {
                    throw AccountAddressException(
                        AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length",
                    )
                }
                throw AccountAddressException(
                    AccountAddressErrorCode.UNEXPECTED_TRAILING_BYTES,
                    "unexpected trailing bytes in canonical payload",
                )
            }
        }
        else -> throw AccountAddressException(
            AccountAddressErrorCode.UNKNOWN_CONTROLLER_TAG,
            "unknown controller tag: $controllerTag",
        )
    }
}

@Throws(AccountAddressException::class)
private fun validateControllerPublicKey(curveId: Int, publicKey: ByteArray) {
    if (curveId == 0x01 && !Ed25519PublicKeyAdmission.isValid(publicKey)) {
        throw AccountAddressException(
            AccountAddressErrorCode.INVALID_PUBLIC_KEY,
            "invalid Ed25519 public key: expected a canonical point in the prime-order subgroup",
        )
    }
    if (curveId == 0x02 && !MlDsaPublicKeyAdmission.isValid(publicKey)) {
        throw AccountAddressException(
            AccountAddressErrorCode.INVALID_PUBLIC_KEY,
            "invalid ML-DSA-65 public key: expected ${MlDsaPublicKeyAdmission.PUBLIC_KEY_LENGTH} nonzero bytes",
        )
    }
}

@Throws(AccountAddressException::class)
private fun extractSingleKeyPayload(
    canonical: ByteArray,
): SingleKeyPayload? {
    if (canonical.size < 4) {
        throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
    }
    var cursor = 0
    decodeHeader(canonical[cursor++])

    if (cursor >= canonical.size) {
        throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
    }
    val controllerTag = canonical[cursor++].toInt() and 0xFF
    if (controllerTag != CONTROLLER_SINGLE_KEY_TAG && controllerTag != CONTROLLER_SINGLE_KEY_EXTENDED_TAG) {
        return null
    }
    val lengthBytes = if (controllerTag == CONTROLLER_SINGLE_KEY_TAG) 1 else 2
    if (cursor + 1 + lengthBytes > canonical.size) {
        throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
    }
    val curveId = canonical[cursor++].toInt() and 0xFF
    ensureKnownCurve(curveId, "curve id $curveId")
    val keyLen = if (controllerTag == CONTROLLER_SINGLE_KEY_TAG) {
        canonical[cursor++].toInt() and 0xFF
    } else {
        val length = ((canonical[cursor].toInt() and 0xFF) shl 8) or
            (canonical[cursor + 1].toInt() and 0xFF)
        cursor += 2
        if (length <= 0xFF) {
            throw AccountAddressException(
                AccountAddressErrorCode.INVALID_LENGTH,
                "extended single-key payload must exceed 255 bytes",
            )
        }
        length
    }
    val end = cursor + keyLen
    if (end > canonical.size) {
        throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
    }
    if (end != canonical.size) {
        throw AccountAddressException(
            AccountAddressErrorCode.UNEXPECTED_TRAILING_BYTES,
            "unexpected trailing bytes in canonical payload",
        )
    }
    val key = canonical.copyOfRange(cursor, end)
    validateControllerPublicKey(curveId, key)
    return SingleKeyPayload(curveId, key)
}

@Throws(AccountAddressException::class)
private fun extractMultisigPayload(
    canonical: ByteArray,
): MultisigPolicyPayload? {
    if (canonical.size < 4) {
        throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
    }
    var cursor = 0
    decodeHeader(canonical[cursor++])

    if (cursor >= canonical.size) {
        throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
    }
    val controllerTag = canonical[cursor++]
    if (controllerTag.toInt() != CONTROLLER_MULTISIG_TAG) return null
    if (cursor + 5 > canonical.size) {
        throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
    }
    val version = canonical[cursor++].toInt() and 0xFF
    val threshold = ((canonical[cursor].toInt() and 0xFF) shl 8) or
        (canonical[cursor + 1].toInt() and 0xFF)
    cursor += 2
    val memberCount = ((canonical[cursor].toInt() and 0xFF) shl 8) or
        (canonical[cursor + 1].toInt() and 0xFF)
    cursor += 2
    if (memberCount == 0) {
        throw AccountAddressException(
            AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
            "InvalidMultisigPolicy: zero members",
        )
    }

    val members = ArrayList<MultisigMemberPayload>(memberCount)
    for (i in 0 until memberCount) {
        if (cursor + 5 > canonical.size) {
            throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
        }
        val curveId = canonical[cursor++].toInt() and 0xFF
        ensureKnownCurve(curveId, "curve id $curveId")
        val weight = ((canonical[cursor].toInt() and 0xFF) shl 8) or
            (canonical[cursor + 1].toInt() and 0xFF)
        cursor += 2
        val keyLen = ((canonical[cursor].toInt() and 0xFF) shl 8) or
            (canonical[cursor + 1].toInt() and 0xFF)
        cursor += 2
        if (keyLen <= 0) {
            throw AccountAddressException(
                AccountAddressErrorCode.INVALID_MULTISIG_POLICY,
                "InvalidMultisigPolicy: invalid key length",
            )
        }
        if (cursor + keyLen > canonical.size) {
            throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
        }
        val key = canonical.copyOfRange(cursor, cursor + keyLen)
        cursor += keyLen
        members.add(MultisigMemberPayload(curveId, weight, key))
    }
    if (cursor != canonical.size) {
        if (cursor > canonical.size) {
            throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "invalid canonical length")
        }
        throw AccountAddressException(
            AccountAddressErrorCode.UNEXPECTED_TRAILING_BYTES,
            "unexpected trailing bytes in canonical payload",
        )
    }
    return MultisigPolicyPayload.of(version, threshold, members)
}

@Throws(AccountAddressException::class)
private fun encodeHeader(version: Int, classId: Int, normVersion: Int): Byte {
    if (version < 0 || version > 0b111) {
        throw AccountAddressException(
            AccountAddressErrorCode.INVALID_HEADER_VERSION,
            "invalid address header version: $version",
        )
    }
    if (normVersion < 0 || normVersion > 0b11) {
        throw AccountAddressException(
            AccountAddressErrorCode.INVALID_NORM_VERSION,
            "invalid normalization version: $normVersion",
        )
    }
    return (((version and 0b111) shl 5) or ((classId and 0b11) shl 3) or ((normVersion and 0b11) shl 1)).toByte()
}

@Throws(AccountAddressException::class)
private fun decodeHeader(header: Byte): Int {
    val version = (header.toInt() ushr 5) and 0b111
    val classBits = (header.toInt() shr 3) and 0b11
    val normVersion = (header.toInt() shr 1) and 0b11
    val extFlag = header.toInt() and 0x01
    if (version != HEADER_VERSION_V1) {
        throw AccountAddressException(
            AccountAddressErrorCode.INVALID_HEADER_VERSION,
            "unsupported address header version: $version",
        )
    }
    if (normVersion != HEADER_NORM_VERSION_V1) {
        throw AccountAddressException(
            AccountAddressErrorCode.INVALID_NORM_VERSION,
            "unsupported normalization version: $normVersion",
        )
    }
    if (extFlag != 0) {
        throw AccountAddressException(
            AccountAddressErrorCode.UNEXPECTED_EXTENSION_FLAG,
            "address header reserves extension flag but it was set",
        )
    }
    if (classBits != 0 && classBits != 1) {
        throw AccountAddressException(
            AccountAddressErrorCode.UNKNOWN_ADDRESS_CLASS, "unknown address class: $classBits",
        )
    }
    return classBits
}

// -- Encoding helpers --

@Throws(AccountAddressException::class)
internal fun curveIdForAlgorithm(algorithm: String): Byte {
    val curveId = when (algorithm) {
        "ed25519" -> 1
        "secp256k1" -> 4
        "ml-dsa" -> 2
        "bls_normal" -> 3
        "bls_small" -> 5
        "gost3410-2012-256-paramset-a" -> 10
        "gost3410-2012-256-paramset-b" -> 11
        "gost3410-2012-256-paramset-c" -> 12
        "gost3410-2012-512-paramset-a" -> 13
        "gost3410-2012-512-paramset-b" -> 14
        "sm2" -> 15
        else -> throw AccountAddressException(
            AccountAddressErrorCode.UNKNOWN_ALGORITHM,
            "unknown canonical signing algorithm: $algorithm",
        )
    }
    return curveId.toByte()
}

@Throws(AccountAddressException::class)
private fun ensureKnownCurve(curveId: Int, context: String) {
    if (algorithmForCurveId(curveId) == null) {
        throw AccountAddressException(
            AccountAddressErrorCode.UNKNOWN_CURVE,
            "$context: unknown curve id $curveId",
        )
    }
}

@Throws(AccountAddressException::class)
private fun encodeI105(prefix: Int, canonical: ByteArray): String {
    val discriminant = normalizeI105Discriminant(prefix, "i105 discriminant")
    val digits = encodeBaseN(canonical, I105_ALPHABET.size)
    val checksum = i105ChecksumDigits(canonical)
    return buildString {
        append(i105SentinelForDiscriminant(discriminant))
        for (digit in digits) append(I105_ALPHABET[digit])
        for (digit in checksum) append(I105_ALPHABET[digit])
    }
}

@Throws(AccountAddressException::class)
private fun decodeI105(encoded: String, expectedDiscriminant: Int?): ByteArray {
    val parsed = parseI105SentinelAndPayload(encoded)
        ?: throw AccountAddressException(
            AccountAddressErrorCode.MISSING_I105_SENTINEL,
            "i105 address is missing the expected chain-discriminant sentinel",
        )
    val (discriminant, payload) = parsed
    if (expectedDiscriminant != null) {
        val normalizedExpected = normalizeI105Discriminant(expectedDiscriminant, "expected i105 discriminant")
        if (discriminant != normalizedExpected) {
            throw AccountAddressException(
                AccountAddressErrorCode.UNEXPECTED_NETWORK_PREFIX,
                "unexpected i105 discriminant: expected $normalizedExpected, found $discriminant",
            )
        }
    }
    return decodeI105Payload(payload)
}

@Throws(AccountAddressException::class)
private fun decodeI105Payload(payload: String): ByteArray {
    val digits = payload.map { symbol ->
        lookupI105Digit(symbol.toString()) ?: throw AccountAddressException(
            AccountAddressErrorCode.INVALID_I105_CHAR,
            "invalid i105 alphabet symbol: $symbol",
        )
    }
    if (digits.size <= I105_CHECKSUM_LEN) {
        throw AccountAddressException(
            AccountAddressErrorCode.I105_TOO_SHORT,
            "i105 address is too short",
        )
    }
    val splitAt = digits.size - I105_CHECKSUM_LEN
    val dataDigits = digits.subList(0, splitAt).toIntArray()
    val checksumDigits = digits.subList(splitAt, digits.size).toIntArray()
    val canonical = decodeBaseN(dataDigits, I105_ALPHABET.size)
    val expected = i105ChecksumDigits(canonical)
    if (!checksumDigits.contentEquals(expected)) {
        throw AccountAddressException(
            AccountAddressErrorCode.CHECKSUM_MISMATCH,
            "i105 checksum mismatch",
        )
    }
    return canonical
}

@Throws(AccountAddressException::class)
private fun normalizeI105Discriminant(discriminant: Int, context: String): Int {
    if (discriminant < 0 || discriminant > I105_DISCRIMINANT_MAX) {
        throw AccountAddressException(
            AccountAddressErrorCode.INVALID_I105_PREFIX,
            "$context out of range: $discriminant",
        )
    }
    return discriminant
}

private fun i105SentinelForDiscriminant(discriminant: Int): String = when (discriminant) {
    I105_DISCRIMINANT_SORA -> I105_SENTINEL_SORA
    I105_DISCRIMINANT_TEST -> I105_SENTINEL_TEST
    I105_DISCRIMINANT_DEV -> I105_SENTINEL_DEV
    else -> "$I105_SENTINEL_NUMERIC_PREFIX$discriminant"
}

private fun parseI105SentinelAndPayload(encoded: String): Pair<Int, String>? {
    when {
        encoded.startsWith(I105_SENTINEL_SORA) ->
            return I105_DISCRIMINANT_SORA to encoded.drop(I105_SENTINEL_SORA.length)
        encoded.startsWith(I105_SENTINEL_TEST) ->
            return I105_DISCRIMINANT_TEST to encoded.drop(I105_SENTINEL_TEST.length)
        encoded.startsWith(I105_SENTINEL_DEV) ->
            return I105_DISCRIMINANT_DEV to encoded.drop(I105_SENTINEL_DEV.length)
    }

    val tail = when {
        encoded.startsWith(I105_SENTINEL_NUMERIC_PREFIX) -> encoded.drop(I105_SENTINEL_NUMERIC_PREFIX.length)
        else -> return null
    }
    val digitsBuilder = StringBuilder()
    for (symbol in tail) {
        val asciiDigit = asciiDigit(symbol) ?: break
        digitsBuilder.append(asciiDigit)
    }
    val digits = digitsBuilder.toString()
    if (digits.isEmpty()) {
        return null
    }
    val discriminant = digits.toIntOrNull() ?: return null
    normalizeI105Discriminant(discriminant, "i105 discriminant sentinel")
    return discriminant to tail.drop(digits.length)
}

private fun asciiDigit(character: Char): Char? = when (character) {
    in '0'..'9' -> character
    else -> null
}

private fun i105ChecksumDigits(canonical: ByteArray): IntArray = bech32mChecksum(canonical)

private fun convertToBase32(data: ByteArray): IntArray {
    var acc = 0
    var bits = 0
    val out = ArrayList<Int>((data.size * 8 + 4) / 5)
    for (byte in data) {
        acc = (acc shl 8) or (byte.toInt() and 0xFF)
        bits += 8
        while (bits >= 5) {
            bits -= 5
            out.add((acc shr bits) and 0x1F)
        }
    }
    if (bits > 0) {
        out.add((acc shl (5 - bits)) and 0x1F)
    }
    return out.toIntArray()
}

private fun expandHrp(hrp: String): IntArray {
    val out = ArrayList<Int>(hrp.length * 2 + 1)
    for (character in hrp) {
        val code = character.code
        out.add(code shr 5)
    }
    out.add(0)
    for (character in hrp) {
        out.add(character.code and 0x1F)
    }
    return out.toIntArray()
}

private fun bech32Polymod(values: IntArray): Int {
    val generators = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    var chk = 1
    for (value in values) {
        val top = chk ushr 25
        chk = ((chk and 0x1ff_ffff) shl 5) xor value
        for (index in generators.indices) {
            if (((top ushr index) and 1) == 1) {
                chk = chk xor generators[index]
            }
        }
    }
    return chk
}

private fun bech32mChecksum(data: ByteArray): IntArray {
    val values = ArrayList<Int>()
    values.addAll(expandHrp("snx").toList())
    values.addAll(convertToBase32(data).toList())
    repeat(I105_CHECKSUM_LEN) {
        values.add(0)
    }
    val polymod = bech32Polymod(values.toIntArray()) xor BECH32M_CONST
    return IntArray(I105_CHECKSUM_LEN) { index ->
        val shift = 5 * (I105_CHECKSUM_LEN - 1 - index)
        (polymod ushr shift) and 0x1F
    }
}

@Throws(AccountAddressException::class)
private fun encodeBaseN(input: ByteArray, base: Int): IntArray {
    if (base < 2) {
        throw AccountAddressException(
            AccountAddressErrorCode.INVALID_I105_BASE,
            "invalid base for encoding",
        )
    }
    if (input.isEmpty()) return intArrayOf(0)
    val value = IntArray(input.size) { input[it].toInt() and 0xFF }
    var leadingZeros = 0
    while (leadingZeros < value.size && value[leadingZeros] == 0) leadingZeros++
    val digits = ArrayList<Int>()
    var start = leadingZeros
    while (start < value.size) {
        var remainder = 0
        for (i in start until value.size) {
            val acc = (remainder shl 8) or value[i]
            value[i] = acc / base
            remainder = acc % base
        }
        digits.add(remainder)
        while (start < value.size && value[start] == 0) start++
    }
    repeat(leadingZeros) { digits.add(0) }
    if (digits.isEmpty()) digits.add(0)
    digits.reverse()
    return digits.toIntArray()
}

@Throws(AccountAddressException::class)
private fun decodeBaseN(digits: IntArray, base: Int): ByteArray {
    if (base < 2) {
        throw AccountAddressException(
            AccountAddressErrorCode.INVALID_I105_BASE,
            "invalid base for decoding",
        )
    }
    if (digits.isEmpty()) {
        throw AccountAddressException(
            AccountAddressErrorCode.INVALID_LENGTH, "invalid length for address payload",
        )
    }
    for (digit in digits) {
        if (digit < 0 || digit >= base) {
            throw AccountAddressException(
                AccountAddressErrorCode.INVALID_I105_DIGIT,
                "invalid digit $digit for base $base",
            )
        }
    }
    val value = digits.copyOf()
    var leadingZeros = 0
    while (leadingZeros < value.size && value[leadingZeros] == 0) leadingZeros++
    val bytes = ArrayList<Byte>()
    var start = leadingZeros
    while (start < value.size) {
        var remainder = 0
        for (i in start until value.size) {
            val acc = remainder * base + value[i]
            value[i] = acc / 256
            remainder = acc % 256
        }
        bytes.add(remainder.toByte())
        while (start < value.size && value[start] == 0) start++
    }
    repeat(leadingZeros) { bytes.add(0) }
    if (bytes.isEmpty()) bytes.add(0)
    bytes.reverse()
    return bytes.toByteArray()
}

private fun bytesToHex(bytes: ByteArray): String = buildString(bytes.size * 2) {
    for (b in bytes) {
        append(String.format("%02x", b.toInt() and 0xFF))
    }
}
