package org.hyperledger.iroha.sdk.client

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import org.hyperledger.iroha.sdk.core.model.NetworkId

/** An exact native selective row authenticated against independently pinned finality. */
class VerifiedCommittedTransaction internal constructor(
    canonicalRow: ByteArray,
    outputHash: ByteArray,
    blockHash: ByteArray,
    val blockHeight: Long,
    val resultOk: Boolean,
    promotedCheckpoint: ByteArray,
) {
    private val row = canonicalRow.copyOf()
    private val output = outputHash.copyOf()
    private val block = blockHash.copyOf()
    private val checkpoint = promotedCheckpoint.copyOf()

    init {
        require(row.isNotEmpty() && row.size <= 4 * 1024 * 1024)
        require(output.size == 32 && block.size == 32)
        require(blockHeight > 0)
        require(checkpoint.isNotEmpty() && checkpoint.size <= 68 * 1024 * 1024)
    }

    /** Retain atomically with the accepted authenticated application result. */
    val promotedCheckpointBytes: ByteArray get() = checkpoint.copyOf()
    /** Bare `norito::to_bytes(CommittedTransaction)` for an independent FI verifier. */
    val canonicalRowBytes: ByteArray get() = row.copyOf()
    val outputHashBytes: ByteArray get() = output.copyOf()
    val blockHashBytes: ByteArray get() = block.copyOf()
    val canonicalRowHex: String get() {
        val alphabet = "0123456789abcdef"
        val hex = CharArray(row.size * 2)
        for (index in row.indices) {
            val value = row[index].toInt() and 0xff
            hex[index * 2] = alphabet[value ushr 4]
            hex[index * 2 + 1] = alphabet[value and 0x0f]
        }
        return String(hex)
    }
}

/** JNI projection of the native checkpoint-authenticated inclusion verifier. */
class CommittedTransactionInclusionBridge private constructor() {
    companion object {
        private const val LIBRARY_NAME = "connect_norito_bridge"
        private const val REQUIRED_ABI_VERSION = 31
        private const val REQUIRED_CONTRACT_VERSION = 1
        private val nativeAvailable: Boolean = try {
            System.loadLibrary(LIBRARY_NAME)
            nativeBridgeAbiVersion() == REQUIRED_ABI_VERSION &&
                nativeVerifierContractVersion() == REQUIRED_CONTRACT_VERSION
        } catch (_: UnsatisfiedLinkError) {
            false
        } catch (_: SecurityException) {
            false
        }

        @JvmStatic
        fun isNativeAvailable(): Boolean = nativeAvailable

        /** Null means a canonical empty page; a hash is only an untrusted routing hint. */
        @JvmStatic
        fun candidateBlockHash(responseBytes: ByteArray, transactionHash: ByteArray): ByteArray? {
            require(responseBytes.isNotEmpty() && responseBytes.size <= 32 * 1024 * 1024)
            require(transactionHash.size == 32 && (transactionHash[31].toInt() and 1) == 1)
            check(nativeAvailable) { "$LIBRARY_NAME committed-inclusion verifier is unavailable" }
            val hash = nativeCandidateBlockHash(responseBytes.copyOf(), transactionHash.copyOf())
                ?: return null
            require(hash.size == 32) { "native candidate block-hash has invalid length" }
            return hash
        }

        /** Exact prehash of one nonce-bound wallet-self committed-row query. */
        @JvmStatic
        fun committedTransactionQueryPayloadHash(
            networkId: NetworkId,
            walletAccountId: String,
            transactionHash: ByteArray,
            creationTimeMs: Long,
            nonce: ByteArray,
        ): ByteArray {
            requireQueryArguments(walletAccountId, transactionHash, creationTimeMs, nonce)
            check(nativeAvailable) { "$LIBRARY_NAME committed-query signer is unavailable" }
            val hash = checkNotNull(nativeCommittedTransactionQueryPayloadHash(
                networkId.bytes(), walletAccountId.toByteArray(StandardCharsets.UTF_8),
                transactionHash.copyOf(), creationTimeMs, nonce.copyOf(),
            )) { "native committed-query prehash returned null" }
            require(hash.size == 32) { "native committed-query prehash has invalid length" }
            return hash
        }

        /** Finalize the same query from the wallet controller's Ed25519 prehash signature. */
        @JvmStatic
        fun finalizeCommittedTransactionQuery(
            networkId: NetworkId,
            walletAccountId: String,
            transactionHash: ByteArray,
            creationTimeMs: Long,
            nonce: ByteArray,
            signature: ByteArray,
        ): ByteArray {
            requireQueryArguments(walletAccountId, transactionHash, creationTimeMs, nonce)
            require(signature.size == 64) { "wallet query signature must be 64-byte Ed25519" }
            check(nativeAvailable) { "$LIBRARY_NAME committed-query signer is unavailable" }
            val wire = checkNotNull(nativeFinalizeCommittedTransactionQuery(
                networkId.bytes(), walletAccountId.toByteArray(StandardCharsets.UTF_8),
                transactionHash.copyOf(), creationTimeMs, nonce.copyOf(), signature.copyOf(),
            )) { "native committed-query finalization returned null" }
            require(wire.isNotEmpty() && wire.size <= 16 * 1024) {
                "native committed-query finalization returned invalid wire"
            }
            return wire
        }

        private fun requireQueryArguments(
            walletAccountId: String, transactionHash: ByteArray,
            creationTimeMs: Long, nonce: ByteArray,
        ) {
            require(walletAccountId.isNotBlank() && walletAccountId == walletAccountId.trim())
            require(walletAccountId.toByteArray(StandardCharsets.UTF_8).size <= 1024)
            require(creationTimeMs > 0)
            require(transactionHash.size == 32 && (transactionHash[31].toInt() and 1) == 1)
            require(nonce.size == 32 && nonce.any { it != 0.toByte() })
        }

        /**
         * Authenticate one exact selective query response. [networkId] and
         * [expectedChain] and [trustedCheckpoint] must come from independently trusted state.
         * A valid rejected execution returns [VerifiedCommittedTransaction.resultOk] false.
         */
        @JvmStatic
        fun verify(
            responseBytes: ByteArray,
            nativeFinalityProofChainJson: ByteArray,
            networkId: NetworkId,
            expectedChain: String,
            trustedCheckpoint: ByteArray,
            transactionHash: ByteArray,
        ): VerifiedCommittedTransaction {
            require(responseBytes.isNotEmpty() && responseBytes.size <= 32 * 1024 * 1024)
            require(nativeFinalityProofChainJson.isNotEmpty() && nativeFinalityProofChainJson.size <= 16 * 1024 * 1024)
            require(expectedChain.isNotEmpty() && expectedChain.toByteArray(StandardCharsets.UTF_8).size <= 1024)
            require(trustedCheckpoint.isNotEmpty() && trustedCheckpoint.size <= 68 * 1024 * 1024)
            require(transactionHash.size == 32 && (transactionHash[31].toInt() and 1) == 1)
            check(nativeAvailable) { "$LIBRARY_NAME committed-inclusion verifier is unavailable" }
            val result = checkNotNull(nativeVerifyCommittedTransactionInclusion(
                responseBytes.copyOf(), nativeFinalityProofChainJson.copyOf(), networkId.bytes(),
                expectedChain.toByteArray(StandardCharsets.UTF_8), trustedCheckpoint.copyOf(), transactionHash.copyOf(),
            )) { "native committed-inclusion verifier returned null" }
            return decodeVerifiedResult(result)
        }

        /**
         * Authenticate successful execution of the complete retained signed transaction wire.
         * Unlike the transaction hash, this includes every original authorization signature.
         * The finality checkpoint, network and chain must be selected independently of the reply.
         * Neither HTTP approval nor equality with a later current-state record is evidence here.
         */
        @JvmStatic
        fun verifyExactSuccessful(
            responseBytes: ByteArray,
            nativeFinalityProofChainJson: ByteArray,
            networkId: NetworkId,
            expectedChain: String,
            trustedCheckpoint: ByteArray,
            originalSignedTransaction: ByteArray,
        ): VerifiedCommittedTransaction {
            require(responseBytes.isNotEmpty() && responseBytes.size <= 32 * 1024 * 1024)
            require(nativeFinalityProofChainJson.isNotEmpty() && nativeFinalityProofChainJson.size <= 16 * 1024 * 1024)
            require(expectedChain.isNotEmpty() && expectedChain.toByteArray(StandardCharsets.UTF_8).size <= 1024)
            require(trustedCheckpoint.isNotEmpty() && trustedCheckpoint.size <= 68 * 1024 * 1024)
            require(originalSignedTransaction.isNotEmpty() && originalSignedTransaction.size <= 4 * 1024 * 1024)
            check(nativeAvailable) { "$LIBRARY_NAME exact committed-inclusion verifier is unavailable" }
            val result = checkNotNull(nativeVerifyExactSuccessfulCommittedTransaction(
                responseBytes.copyOf(), nativeFinalityProofChainJson.copyOf(), networkId.bytes(),
                expectedChain.toByteArray(StandardCharsets.UTF_8), trustedCheckpoint.copyOf(), originalSignedTransaction.copyOf(),
            )) { "native exact committed-inclusion verifier returned null" }
            return decodeVerifiedResult(result).also {
                check(it.resultOk && it.blockHeight > 1) { "native exact verifier did not confirm successful non-genesis execution" }
            }
        }

        private fun decodeVerifiedResult(result: Array<ByteArray?>): VerifiedCommittedTransaction {
            require(result.size == 6) { "native committed-inclusion verifier returned invalid fields" }
            val row = checkNotNull(result[0])
            val outputHash = checkNotNull(result[1])
            val blockHash = checkNotNull(result[2])
            val height = checkNotNull(result[3])
            val status = checkNotNull(result[4])
            val checkpoint = checkNotNull(result[5])
            require(height.size == 8 && status.size == 1 && (status[0] == 0.toByte() || status[0] == 1.toByte())) {
                "native committed-inclusion verifier returned invalid height or status"
            }
            return VerifiedCommittedTransaction(
                row, outputHash, blockHash,
                ByteBuffer.wrap(height).order(ByteOrder.BIG_ENDIAN).long,
                status[0] == 1.toByte(), checkpoint,
            )
        }

        @JvmStatic private external fun nativeBridgeAbiVersion(): Int
        @JvmStatic private external fun nativeVerifierContractVersion(): Int
        @JvmStatic private external fun nativeCandidateBlockHash(
            responseBytes: ByteArray,
            transactionHash: ByteArray,
        ): ByteArray?
        @JvmStatic private external fun nativeCommittedTransactionQueryPayloadHash(
            networkId: ByteArray,
            walletAccountId: ByteArray,
            transactionHash: ByteArray,
            creationTimeMs: Long,
            nonce: ByteArray,
        ): ByteArray?
        @JvmStatic private external fun nativeFinalizeCommittedTransactionQuery(
            networkId: ByteArray,
            walletAccountId: ByteArray,
            transactionHash: ByteArray,
            creationTimeMs: Long,
            nonce: ByteArray,
            signature: ByteArray,
        ): ByteArray?
        @JvmStatic private external fun nativeVerifyCommittedTransactionInclusion(
            responseBytes: ByteArray,
            nativeFinalityProofChainJson: ByteArray,
            networkId: ByteArray,
            expectedChain: ByteArray,
            trustedCheckpoint: ByteArray,
            transactionHash: ByteArray,
        ): Array<ByteArray?>?
        @JvmStatic private external fun nativeVerifyExactSuccessfulCommittedTransaction(
            responseBytes: ByteArray,
            nativeFinalityProofChainJson: ByteArray,
            networkId: ByteArray,
            expectedChain: ByteArray,
            trustedCheckpoint: ByteArray,
            originalSignedTransaction: ByteArray,
        ): Array<ByteArray?>?
    }
}
