package org.hyperledger.iroha.samples.attestationprobe

/** Reuse completed automatic evidence only for the same independent request and installation. */
internal object ProbeCaptureState {
    fun reusableZipName(
        name: String?,
        capturedChallengeHex: String?,
        requestedChallengeHex: String,
        capturedAppUpdateTime: Long,
        currentAppUpdateTime: Long,
    ): String? = name?.takeIf {
        it.matches(Regex("[A-Za-z0-9_-]{1,80}\\.zip")) &&
            capturedChallengeHex == requestedChallengeHex &&
            capturedAppUpdateTime == currentAppUpdateTime
    }
}
