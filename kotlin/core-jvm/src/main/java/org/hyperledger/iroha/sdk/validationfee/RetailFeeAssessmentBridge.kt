package org.hyperledger.iroha.sdk.validationfee

/** Canonical consensus payment-intent and signed-assessment codecs; requires the ABI-31 bridge. */
class RetailFeeAssessmentBridge private constructor() {
    companion object {
        private const val LIBRARY_NAME = "connect_norito_bridge"
        private const val REQUIRED_BRIDGE_ABI_VERSION = 31
        private const val MAXIMUM_INTENT_JSON_BYTES = 262_144
        private const val MAXIMUM_ASSESSMENT_JSON_BYTES = 4_096
        private const val MAXIMUM_ASSESSMENT_MARKER_BYTES = 4_096

        private val nativeLoad: Result<Unit> by lazy {
            runCatching {
                System.loadLibrary(LIBRARY_NAME)
                val actualAbi = nativeBridgeAbiVersion()
                check(actualAbi == REQUIRED_BRIDGE_ABI_VERSION) {
                    "native retail fee codec ABI mismatch: " +
                        "expected $REQUIRED_BRIDGE_ABI_VERSION, found $actualAbi"
                }
            }
        }
        @JvmStatic fun intentHashV1(requestJson: ByteArray): ByteArray = invoke(requestJson, MAXIMUM_INTENT_JSON_BYTES, 32, 32, ::nativeIntentHashV1)
        @JvmStatic fun assessmentMarkerV1(assessmentJson: ByteArray): ByteArray = invoke(assessmentJson, MAXIMUM_ASSESSMENT_JSON_BYTES, 1, MAXIMUM_ASSESSMENT_MARKER_BYTES, ::nativeAssessmentMarkerV1)
        @JvmStatic fun decodeAssessmentV1(markerUtf8: ByteArray): ByteArray = invoke(markerUtf8, MAXIMUM_ASSESSMENT_MARKER_BYTES, 1, MAXIMUM_ASSESSMENT_JSON_BYTES, ::nativeDecodeAssessmentV1)
        private fun invoke(input: ByteArray, maximumInputBytes: Int, min: Int, max: Int, call: (ByteArray) -> ByteArray): ByteArray {
            require(input.isNotEmpty() && input.size <= maximumInputBytes) { "Retail fee input exceeds codec bounds" }
            nativeLoad.getOrElse { throw IllegalStateException("Native retail fee codec unavailable", it) }
            val output = try { call(input.copyOf()) } catch (failure: UnsatisfiedLinkError) {
                throw IllegalStateException("Release bridge is missing the retail fee codec", failure)
            }
            check(output.size in min..max) { "Invalid native retail fee result" }
            return output.copyOf()
        }
        @JvmStatic private external fun nativeBridgeAbiVersion(): Int
        @JvmStatic private external fun nativeIntentHashV1(requestJson: ByteArray): ByteArray
        @JvmStatic private external fun nativeAssessmentMarkerV1(assessmentJson: ByteArray): ByteArray
        @JvmStatic private external fun nativeDecodeAssessmentV1(markerUtf8: ByteArray): ByteArray
    }
}
