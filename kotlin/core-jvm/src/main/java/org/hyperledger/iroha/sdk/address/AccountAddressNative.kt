package org.hyperledger.iroha.sdk.address

import org.hyperledger.iroha.sdk.crypto.NativeSignerBridge

/** One mandatory cryptographic admission boundary for complete account controllers. */
internal object AccountAddressNative {
    private const val MAX_CANONICAL_ADDRESS_BYTES = 64 * 1024 * 1024
    const val MAX_PUBLIC_KEY_BYTES = 0xffff

    fun requireCanonicalSize(size: Int) {
        if (size <= 0 || size > MAX_CANONICAL_ADDRESS_BYTES) {
            throw AccountAddressException(AccountAddressErrorCode.INVALID_LENGTH, "canonical address exceeds the 64 MiB JNI input bound")
        }
    }

    fun validateCanonical(canonical: ByteArray) {
        requireCanonicalSize(canonical.size)
        try {
            NativeSignerBridge.validateAccountAddressCanonical(canonical)
        } catch (error: UnsatisfiedLinkError) {
            throw unavailable()
        } catch (error: IllegalStateException) {
            throw unavailable()
        } catch (error: IllegalArgumentException) {
            throw AccountAddressException(AccountAddressErrorCode.INVALID_PUBLIC_KEY,
                error.message ?: "Rust rejected the account controller")
        }
    }

    fun requireSingleSize(curveId: Int, size: Int) {
        if (algorithmForCurveId(curveId) == null || size !in 1..MAX_PUBLIC_KEY_BYTES) {
            throw AccountAddressException(AccountAddressErrorCode.INVALID_PUBLIC_KEY, "invalid canonical public-key envelope")
        }
    }

    fun validateSingle(curveId: Int, keyBytes: ByteArray) {
        requireSingleSize(curveId, keyBytes.size)
        val headerLength = if (keyBytes.size <= 255) 4 else 5
        val canonical = ByteArray(headerLength + keyBytes.size)
        canonical[0] = 2
        canonical[1] = if (headerLength == 4) 0 else 2
        canonical[2] = curveId.toByte()
        if (headerLength == 4) canonical[3] = keyBytes.size.toByte()
        else {
            canonical[3] = (keyBytes.size ushr 8).toByte()
            canonical[4] = keyBytes.size.toByte()
        }
        keyBytes.copyInto(canonical, headerLength)
        validateCanonical(canonical)
    }

    private fun unavailable() = AccountAddressException(
        AccountAddressErrorCode.NATIVE_BRIDGE_UNAVAILABLE,
        "Account addresses require the complete ABI-30 Rust address validator from connect_norito_bridge",
    )
}
