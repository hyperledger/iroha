package org.hyperledger.iroha.sdk.crypto

import java.nio.charset.StandardCharsets
import org.hyperledger.iroha.sdk.client.JsonEncoder
import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent
import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.hyperledger.iroha.sdk.core.model.instructions.RegisterZkAssetInstruction

/** Thin JVM/JNI wrapper around `connect_norito_bridge` signing helpers. */
class NativeSignerBridge private constructor() {
    companion object {
        private const val LIBRARY_NAME = "connect_norito_bridge"
        const val REQUIRED_BRIDGE_ABI_VERSION: Int = 31
        const val REQUIRED_NATIVE_SIGNER_CONTRACT_REVISION: Int = 7
        private const val HASH_BYTES = 32
        private val nativeAvailable: Boolean = loadLibrary()

        @JvmStatic
        fun isNativeAvailable(): Boolean = nativeAvailable

        /** Admit a complete canonical account controller through the ABI-31 Rust owner. */
        @JvmStatic
        internal fun validateAccountAddressCanonical(canonical: ByteArray) {
            require(canonical.size in 1..64 * 1024 * 1024) { "canonical account address exceeds the JNI input bound" }
            check(nativeAvailable) { "$LIBRARY_NAME is not available in this runtime" }
            val owned = canonical.copyOf()
            val admitted = checkNotNull(nativeValidateAccountAddressCanonical(owned)) {
                "native account validation returned null"
            }
            check(admitted.contentEquals(owned)) { "native account validation changed canonical bytes" }
        }

        /** Native occurrence identity; the instruction commitment remains separate. */
        @JvmStatic
        fun deriveMultisigProposalId(networkId: NetworkId, accountId: String, proposalNonce: String): String {
            require(Regex("[0-9a-f]{64}").matches(proposalNonce) && proposalNonce.any { it != '0' }) { "proposalNonce must be nonzero canonical 32-byte hex" }
            check(nativeAvailable) { "$LIBRARY_NAME is not available in this runtime" }
            val input = JsonEncoder.encode(linkedMapOf("network_id" to networkId.toString(), "account_id" to accountId, "proposal_nonce" to proposalNonce)).toByteArray(StandardCharsets.UTF_8)
            require(input.size <= 4096) { "Multisig occurrence input exceeds bound" }
            val output = checkNotNull(nativeDeriveMultisigProposalId(input)) { "Native multisig occurrence returned no identity" }
            val literal = String(output, StandardCharsets.UTF_8)
            check(Regex("[0-9a-f]{64}").matches(literal) && literal.any { it != '0' }) { "Invalid native multisig occurrence identity" }
            return literal
        }
        @JvmStatic private external fun nativeDeriveMultisigProposalId(input: ByteArray): ByteArray?

        @JvmStatic
        fun publicKeyFromPrivate(algorithm: SigningAlgorithm, privateKey: ByteArray): ByteArray {
            require(privateKey.isNotEmpty()) { "privateKey must not be empty" }
            check(nativeAvailable) { "$LIBRARY_NAME is not available in this runtime" }
            return checkNotNull(
                nativePublicKeyFromPrivate(algorithm.bridgeCode, privateKey)
            ) { "nativePublicKeyFromPrivate returned null" }
        }

        @JvmStatic
        fun keypairFromSeed(
            algorithm: SigningAlgorithm,
            seed: ByteArray,
        ): Pair<ByteArray, ByteArray> {
            require(seed.isNotEmpty()) { "seed must not be empty" }
            check(nativeAvailable) { "$LIBRARY_NAME is not available in this runtime" }
            val pair = checkNotNull(
                nativeKeypairFromSeed(algorithm.bridgeCode, seed)
            ) { "nativeKeypairFromSeed returned null" }
            require(pair.size == 2) { "nativeKeypairFromSeed must return private/public bytes" }
            val privateKey = pair[0] ?: ByteArray(0)
            val publicKey = pair[1] ?: ByteArray(0)
            require(privateKey.isNotEmpty()) { "nativeKeypairFromSeed returned empty private key" }
            require(publicKey.isNotEmpty()) { "nativeKeypairFromSeed returned empty public key" }
            return privateKey to publicKey
        }

        @JvmStatic
        fun signDetached(
            algorithm: SigningAlgorithm,
            privateKey: ByteArray,
            message: ByteArray,
        ): ByteArray {
            require(privateKey.isNotEmpty()) { "privateKey must not be empty" }
            require(message.isNotEmpty()) { "message must not be empty" }
            check(nativeAvailable) { "$LIBRARY_NAME is not available in this runtime" }
            return checkNotNull(
                nativeSignDetached(algorithm.bridgeCode, privateKey, message)
            ) { "nativeSignDetached returned null" }
        }

        @JvmStatic
        fun verifyDetached(
            algorithm: SigningAlgorithm,
            publicKey: ByteArray,
            message: ByteArray,
            signature: ByteArray,
        ): Boolean {
            require(publicKey.isNotEmpty()) { "publicKey must not be empty" }
            require(message.isNotEmpty()) { "message must not be empty" }
            require(signature.isNotEmpty()) { "signature must not be empty" }
            check(nativeAvailable) { "$LIBRARY_NAME is not available in this runtime" }
            return nativeVerifyDetached(algorithm.bridgeCode, publicKey, message, signature)
        }

        /** Prehash of the sole native CanReadAccountData change signed by a 1-of-1 wallet. */
        @JvmStatic
        fun accountReadPermissionMultisigPayloadHash(
            networkId: NetworkId,
            authority: String,
            reportingAccount: String,
            change: Int,
            creationTimeMs: Long,
            feePaymentJson: ByteArray,
        ): ByteArray {
            require(change == 1 || change == 2) { "change must be grant (1) or revoke (2)" }
            requireCreationTime(creationTimeMs)
            require(feePaymentJson.isNotEmpty()) { "Explicit fee payment is required" }
            check(nativeAvailable) { "$LIBRARY_NAME is not available in this runtime" }
            val hash = checkNotNull(nativeAccountReadPermissionMultisigPayloadHash(
                textBytes(networkId.literal, "networkId"), textBytes(authority, "authority"),
                textBytes(reportingAccount, "reportingAccount"), change, creationTimeMs,
                feePaymentJson.copyOf(),
            )) { "native account permission prehash returned null" }
            require(hash.size == HASH_BYTES) { "native account permission prehash has invalid size" }
            return hash
        }

        /** Finalize the same one-instruction transaction from an external Ed25519 prehash signature. */
        @JvmStatic
        fun finalizeAccountReadPermissionMultisig(
            networkId: NetworkId,
            authority: String,
            reportingAccount: String,
            change: Int,
            creationTimeMs: Long,
            feePaymentJson: ByteArray,
            signature: ByteArray,
        ): NativeSignedTransaction {
            require(change == 1 || change == 2) { "change must be grant (1) or revoke (2)" }
            requireCreationTime(creationTimeMs)
            require(signature.size == 64) { "signature must be 64-byte Ed25519" }
            require(feePaymentJson.isNotEmpty()) { "Explicit fee payment is required" }
            check(nativeAvailable) { "$LIBRARY_NAME is not available in this runtime" }
            return requireNativeSignedOutput(nativeFinalizeAccountReadPermissionMultisig(
                textBytes(networkId.literal, "networkId"), textBytes(authority, "authority"),
                textBytes(reportingAccount, "reportingAccount"), change, creationTimeMs,
                feePaymentJson.copyOf(),
                signature.copyOf(),
            ), "finalizeAccountReadPermissionMultisig")
        }

        @JvmStatic
        fun encodeRegisterZkAssetSignedTransaction(
            algorithm: SigningAlgorithm,
            networkId: NetworkId,
            chainDiscriminant: Int,
            authority: String?,
            creationTimeMs: Long,
            ttlMs: Long? = null,
            instruction: RegisterZkAssetInstruction?,
            privateKey: ByteArray?,
            feePayment: FeePaymentIntent,
        ): NativeSignedTransaction {
            requireCreationTime(creationTimeMs)
            val validatedChainDiscriminant = requireChainDiscriminant(chainDiscriminant)
            val selected = requireNotNull(instruction) { "instruction must be provided" }
            val key = requirePrivateKey(privateKey)
            val feePaymentJson = feePaymentJson(feePayment)
            val networkIdBytes = networkId.bytes()
            val authorityBytes = textBytes(authority, "authority")
            val assetBytes = textBytes(selected.asset, "asset")
            val unshieldBytes = optionalTextBytes(selected.unshieldVerifyingKey)
            val ttl = ttlValue(ttlMs)
            val hasTtl = ttlPresent(ttlMs)
            check(nativeAvailable) { "$LIBRARY_NAME is not available in this runtime" }
            return requireNativeSignedOutput(
                nativeEncodeRegisterZkAssetSignedTransaction(
                    algorithm.bridgeCode,
                    networkIdBytes,
                    validatedChainDiscriminant,
                    authorityBytes,
                    creationTimeMs,
                    ttl,
                    hasTtl,
                    assetBytes,
                    unshieldBytes,
                    selected.unshieldVerifyingKey != null,
                    key,
                    feePaymentJson,
                ),
                "encodeRegisterZkAssetSignedTransaction",
            )
        }

        private fun loadLibrary(): Boolean =
            try {
                System.loadLibrary(LIBRARY_NAME)
                nativeBridgeAbiVersion() == REQUIRED_BRIDGE_ABI_VERSION &&
                    nativeSignerContractRevision() == REQUIRED_NATIVE_SIGNER_CONTRACT_REVISION
            } catch (_: UnsatisfiedLinkError) {
                false
            } catch (_: SecurityException) {
                false
            }

        private fun requireNativeSignedOutput(
            output: Array<ByteArray?>?,
            context: String,
        ): NativeSignedTransaction {
            require(output != null && output.size == 2) { "$context returned invalid output" }
            val versioned = output[0]
            val hash = output[1]
            require(versioned != null && versioned.isNotEmpty()) { "$context returned empty transaction bytes" }
            require(hash != null && hash.size == HASH_BYTES) { "$context returned invalid hash bytes" }
            return NativeSignedTransaction(versioned, hash)
        }

        private fun textBytes(value: String?, name: String): ByteArray {
            require(value != null) { "$name must be provided" }
            require(value.isNotBlank()) { "$name must not be blank" }
            require(value.trim() == value) { "$name must not contain surrounding whitespace" }
            require(value.indexOf('\u0000') < 0) { "$name must not contain NUL" }
            return value.toByteArray(StandardCharsets.UTF_8)
        }

        private fun optionalTextBytes(value: String?): ByteArray =
            value?.toByteArray(StandardCharsets.UTF_8) ?: ByteArray(0)

        private fun feePaymentJson(value: FeePaymentIntent): ByteArray =
            JsonEncoder.encode(value.toJsonMap()).toByteArray(StandardCharsets.UTF_8)

        private fun requireCreationTime(creationTimeMs: Long) {
            require(creationTimeMs >= 0) { "creationTimeMs must be non-negative" }
        }

        private fun ttlValue(ttlMs: Long?): Long {
            if (ttlMs == null) return 0L
            require(ttlMs > 0) { "ttlMs must be positive when provided" }
            return ttlMs
        }

        private fun ttlPresent(ttlMs: Long?): Boolean = ttlMs != null

        private fun requireChainDiscriminant(value: Int): Int {
            require(value in 0..0xffff) { "chainDiscriminant must fit in u16" }
            return value
        }

        private fun requirePrivateKey(privateKey: ByteArray?): ByteArray {
            require(privateKey != null && privateKey.isNotEmpty()) { "privateKey must not be empty" }
            return privateKey.copyOf()
        }

        @JvmStatic
        private external fun nativeBridgeAbiVersion(): Int

        @JvmStatic
        private external fun nativeSignerContractRevision(): Int

        @JvmStatic
        private external fun nativeValidateAccountAddressCanonical(canonical: ByteArray): ByteArray?

        @JvmStatic
        private external fun nativePublicKeyFromPrivate(
            algorithmCode: Int,
            privateKey: ByteArray,
        ): ByteArray?

        @JvmStatic
        private external fun nativeKeypairFromSeed(
            algorithmCode: Int,
            seed: ByteArray,
        ): Array<ByteArray?>?

        @JvmStatic
        private external fun nativeSignDetached(
            algorithmCode: Int,
            privateKey: ByteArray,
            message: ByteArray,
        ): ByteArray?

        @JvmStatic
        private external fun nativeVerifyDetached(
            algorithmCode: Int,
            publicKey: ByteArray,
            message: ByteArray,
            signature: ByteArray,
        ): Boolean

        @JvmStatic
        private external fun nativeAccountReadPermissionMultisigPayloadHash(
            networkId: ByteArray, authority: ByteArray, reportingAccount: ByteArray,
            change: Int, creationTimeMs: Long, feePaymentJson: ByteArray,
        ): ByteArray?

        @JvmStatic
        private external fun nativeFinalizeAccountReadPermissionMultisig(
            networkId: ByteArray, authority: ByteArray, reportingAccount: ByteArray,
            change: Int, creationTimeMs: Long, feePaymentJson: ByteArray, signature: ByteArray,
        ): Array<ByteArray?>?

        @JvmStatic
        private external fun nativeEncodeRegisterZkAssetSignedTransaction(
            algorithmCode: Int,
            networkId: ByteArray,
            chainDiscriminant: Int,
            authority: ByteArray,
            creationTimeMs: Long,
            ttlMs: Long,
            ttlPresent: Boolean,
            asset: ByteArray,
            unshieldVerifyingKey: ByteArray,
            unshieldVerifyingKeyPresent: Boolean,
            privateKey: ByteArray,
            feePaymentJson: ByteArray,
        ): Array<ByteArray?>?
    }
}

/** Canonical versioned transaction bytes and native transaction hash returned by zk signers. */
class NativeSignedTransaction(
    versionedSignedTransaction: ByteArray,
    transactionHash: ByteArray,
) {
    private val _versionedSignedTransaction = versionedSignedTransaction.copyOf()
    private val _transactionHash = transactionHash.copyOf()

    init {
        require(_versionedSignedTransaction.isNotEmpty()) {
            "versionedSignedTransaction must not be empty"
        }
        require(_transactionHash.size == 32) { "transactionHash must be exactly 32 bytes" }
    }

    val versionedSignedTransaction: ByteArray get() = _versionedSignedTransaction.copyOf()

    val transactionHash: ByteArray get() = _transactionHash.copyOf()

    fun versionedSignedTransactionBytes(): ByteArray = versionedSignedTransaction

    fun transactionHashBytes(): ByteArray = transactionHash
}
