// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.security.SecureRandom
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/** Ephemeral engineering transport identity, never a wallet key or hardware-attestation claim. */
internal class KagemushaNearbyProbeIdentity : AutoCloseable {
    private var key: Ed25519PrivateKeyParameters? = Ed25519PrivateKeyParameters(SecureRandom())
    fun certificate(): ByteArray = checkNotNull(key).generatePublicKey().encoded
    /** Raw Ed25519 over the complete SDK-owned IPN1 authentication preimage. */
    fun sign(preimage: ByteArray): ByteArray {
        require(preimage.isNotEmpty())
        val signer = Ed25519Signer(); signer.init(true, checkNotNull(key))
        signer.update(preimage, 0, preimage.size); return signer.generateSignature()
    }
    override fun close() { key = null } // No persistence; BC does not promise immediate heap erasure.
    companion object {
        fun verify(pinned: ByteArray, certificate: ByteArray, preimage: ByteArray, signature: ByteArray): Boolean {
            if (pinned.size != 32 || !pinned.contentEquals(certificate) || signature.size != 64 || preimage.isEmpty()) return false
            return try {
                val verifier = Ed25519Signer(); verifier.init(false, Ed25519PublicKeyParameters(certificate, 0))
                verifier.update(preimage, 0, preimage.size); verifier.verifySignature(signature)
            } catch (_: IllegalArgumentException) { false }
        }
    }
}
