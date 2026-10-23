package org.hyperledger.iroha.sdk.address

/** Structured JNI address failure; category and capability never depend on diagnostic text. */
internal class AccountAddressNativeException(
    val code: String,
    message: String,
    val algorithm: String,
    val operation: String,
) : RuntimeException(message) {
    fun toAccountAddressException(): AccountAddressException {
        val category = AccountAddressErrorCode.entries.firstOrNull { it.code == code }
            ?: AccountAddressErrorCode.NATIVE_BRIDGE_UNAVAILABLE
        return AccountAddressException(category, message ?: code).also { it.initCause(this) }
    }
}
