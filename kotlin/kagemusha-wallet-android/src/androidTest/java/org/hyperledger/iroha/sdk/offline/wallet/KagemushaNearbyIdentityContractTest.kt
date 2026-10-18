// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Raw signature/pin controls; running them grants no transport or attestation qualification. */
class KagemushaNearbyIdentityContractTest {
    @Test fun certificateAndWholePreimageAreMandatory() {
        KagemushaNearbyProbeIdentity().use { identity ->
            val certificate = identity.certificate(); val bytes = "whole IPN1 transcript".toByteArray()
            val signature = identity.sign(bytes)
            assertTrue(KagemushaNearbyProbeIdentity.verify(certificate, certificate, bytes, signature))
            assertFalse(KagemushaNearbyProbeIdentity.verify(certificate, certificate, bytes + 1, signature))
            assertFalse(KagemushaNearbyProbeIdentity.verify(ByteArray(32), certificate, bytes, signature))
            assertFalse(KagemushaNearbyProbeIdentity.verify(certificate, ByteArray(32), bytes, signature))
            assertFalse(KagemushaNearbyProbeIdentity.verify(certificate, certificate, bytes, signature.copyOf(63)))
        }
    }
}
