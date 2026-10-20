package org.hyperledger.iroha.samples.attestationprobe

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ProbeCaptureStateTest {
    @Test
    fun reuseRequiresSameChallengeInstallationAndSafeCompletedName() {
        val challenge = "01".repeat(32)
        assertEquals("capture-1.zip", ProbeCaptureState.reusableZipName("capture-1.zip", challenge, challenge, 42, 42))
        assertNull(ProbeCaptureState.reusableZipName("capture-1.zip", challenge, "02".repeat(32), 42, 42))
        assertNull(ProbeCaptureState.reusableZipName("capture-1.zip", challenge, challenge, 42, 43))
        assertNull(ProbeCaptureState.reusableZipName("../capture.zip", challenge, challenge, 42, 42))
        assertNull(ProbeCaptureState.reusableZipName(null, challenge, challenge, 42, 42))
        assertNull(ProbeCaptureState.reusableZipName("capture-1.partial", challenge, challenge, 42, 42))
    }
}
