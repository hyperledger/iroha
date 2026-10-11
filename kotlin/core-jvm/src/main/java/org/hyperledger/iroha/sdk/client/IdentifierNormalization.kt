package org.hyperledger.iroha.sdk.client

/** Canonicalization modes advertised by `/v1/identifier-policies`. */
enum class IdentifierNormalization(@JvmField val wireValue: String) {
    EXACT("exact"),
    LOWERCASE_TRIMMED("lowercase_trimmed"),
    PHONE_E164("phone_e164"),
    EMAIL_ADDRESS("email_address"),
    ACCOUNT_NUMBER("account_number");

    /** Normalizes `value` using this policy's canonicalization rule. */
    @JvmOverloads
    fun normalize(value: String, field: String = "identifier"): String {
        val trimmed = value.trim()
        require(trimmed.isNotEmpty()) { "$field must not be blank" }
        return when (this) {
            EXACT -> trimmed
            LOWERCASE_TRIMMED -> trimmed.map { if (it in 'A'..'Z') it.lowercaseChar() else it }.joinToString("")
            PHONE_E164 -> normalizePhone(trimmed, field)
            EMAIL_ADDRESS -> normalizeEmail(trimmed, field)
            ACCOUNT_NUMBER -> normalizeAccountNumber(trimmed, field)
        }
    }

    companion object {
        /** Parses the Torii JSON wire value into an SDK enum. */
        @JvmStatic
        fun fromWireValue(wireValue: String): IdentifierNormalization {
            return entries.firstOrNull { it.wireValue == wireValue }
                ?: throw IllegalArgumentException("Unsupported identifier normalization: $wireValue")
        }

        private fun normalizePhone(value: String, field: String): String {
            val compact = StringBuilder(value.length)
            for (c in value) {
                if (c in " \t\n\r-().") continue
                compact.append(c)
            }
            val withoutPrefix = when {
                compact.isNotEmpty() && compact[0] == '+' -> compact.substring(1)
                compact.length >= 2 && compact[0] == '0' && compact[1] == '0' -> compact.substring(2)
                else -> compact.toString()
            }
            require(withoutPrefix.length in 2..15 && withoutPrefix[0] in '1'..'9') { "$field requires 2..15 digits and a nonzero country code" }
            require(withoutPrefix.all { it in '0'..'9' }) {
                "$field must contain digits with an optional leading '+' or '00'"
            }
            return "+$withoutPrefix"
        }

        private fun normalizeEmail(value: String, field: String): String {
            val lowered = value.map { if (it in 'A'..'Z') it.lowercaseChar() else it }.joinToString("")
            val atIndex = lowered.indexOf('@')
            require(atIndex > 0 && atIndex == lowered.lastIndexOf('@') && atIndex < lowered.length - 1) {
                "$field must contain exactly one '@' with non-empty local and domain parts"
            }
            return lowered
        }

        private fun normalizeAccountNumber(value: String, field: String): String {
            val builder = StringBuilder(value.length)
            for (c in value) {
                if (c in " \t\n\r-") continue
                val upper = if (c in 'a'..'z') c.uppercaseChar() else c
                require(upper.code <= 0x7F && (upper.isLetterOrDigit() || upper == '_' || upper == '/' || upper == '.')) {
                    "$field must contain ASCII alphanumeric characters, '_', '/', or '.'"
                }
                builder.append(upper)
            }
            require(builder.isNotEmpty()) { "$field must not be blank" }
            return builder.toString()
        }
    }
}
