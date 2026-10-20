package org.hyperledger.iroha.samples.attestationprobe

import java.util.Base64

/** Bounded transport for public diagnostic ZIP bytes, not an authenticity assertion. */
internal object ProbeLogExport {
    const val TAG = "IrohaAttestation"
    const val MAX_ZIP_BYTES = 256 * 1024
    const val CHUNK_CHARACTERS = 1200
    private const val PREFIX = "IROHA_ATTESTATION"

    fun lines(captureId: String, zip: ByteArray): List<String> {
        require(captureId.matches(Regex("[A-Za-z0-9_-]{1,80}"))) { "Invalid capture ID" }
        require(zip.isNotEmpty() && zip.size <= MAX_ZIP_BYTES) { "Public ZIP exceeds export bounds" }
        val chunks = Base64.getEncoder().encodeToString(zip).chunked(CHUNK_CHARACTERS)
        val metadata = "id=$captureId bytes=${zip.size} sha256=${ProbeEncoding.sha256(zip)} chunks=${chunks.size}"
        return listOf("$PREFIX BEGIN $metadata") +
            chunks.mapIndexed { index, chunk -> "$PREFIX CHUNK id=$captureId index=$index data=$chunk" } +
            listOf("$PREFIX END $metadata")
    }

    fun error(stage: String, error: Exception): String {
        // Exception text/stack traces can contain provider internals; log only bounded class/stage.
        val safeStage = stage.filter { it.isLetterOrDigit() || it == '_' }.take(64)
        val kind = error.javaClass.simpleName.filter { it.isLetterOrDigit() || it == '_' }.take(64)
        return "$PREFIX ERROR stage=$safeStage kind=$kind"
    }
}
