package org.hyperledger.iroha.sdk.core.model.zk

import java.util.Collections

/**
 * Low-level proof engines encoded by `iroha_data_model::zk::BackendTag`.
 *
 * Privacy protocols and verifier profiles remain separate catalog labels and
 * never become Norito enum variants.
 */
enum class VerifyingKeyBackendTag(@JvmField val noritoValue: String) {
    NATIVE_PIPA_R_PASTA("native-pipa-r-pasta"),
    STARK("stark");

    companion object {
        /** Exact native verifier configurations admitted by registry v1. */
        @JvmField
        val VERIFIER_BACKEND_REGISTRY_LABELS_V1: Set<String> = Collections.unmodifiableSet(
            linkedSetOf(
                "pipa-r/pasta",
                "pipa-r/pasta/kaigi-authorization-v1",
                "pipa-r/pasta/kaigi-usage-v1",
                "pipa-r/pasta/confidential-transfer-v1",
                "pipa-r/pasta/confidential-unshield-full-v1",
                "pipa-r/pasta/confidential-unshield-change-v1",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
            ),
        )

        private val productionNativePipaRPastaBackends = setOf(
            "pipa-r/pasta",
            "pipa-r/pasta/kaigi-authorization-v1",
            "pipa-r/pasta/kaigi-usage-v1",
            "pipa-r/pasta/confidential-transfer-v1",
            "pipa-r/pasta/confidential-unshield-full-v1",
            "pipa-r/pasta/confidential-unshield-change-v1",
        )

        private val starkFriProductionBackends = setOf(
            "stark/fri/poseidon-x7-goldilocks-6x64-v1",
        )

        private val productionClaimBackendFragments = listOf(
            "productionready", "productionhardened", "productionenabled",
            "productionapproved", "productioncertified", "productionclaim",
            "claimedproduction", "mainnetready", "mainnetcomplete", "mainnetclaim",
            "claimedmainnet", "mainnetcertified", "mainnetapproved", "mainnetrelease",
            "auditedproduction", "externallyaudited", "thirdpartyaudited",
            "boiaudited", "auditedmainnet", "externalaudit", "auditpassed",
            "auditapproved", "auditsignoff", "auditclaim", "claimedaudit",
            "securityreviewpassed", "securityauditpassed", "securityaudited",
            "externalsecurityreview", "certifiedproduction", "certifiedmainnet",
            "releaseready", "releaseapproved", "releasecertified",
        )

        private val trustedSetupBackendSegments = setOf(
            "groth16", "kzg", "bn254", "bn256", "bls12", "srs", "crs",
            "ptau", "ceremony", "powersoftau",
        )

        private val trustedSetupCompactTokens = setOf(
            "groth16", "kzg", "bn254", "bn256", "bls12381", "bls12",
            "srs", "crs", "ptau", "ceremony", "trustedsetup",
            "structuredreferencestring", "universalsrs", "powersoftau",
        )

        /** Parses one exact canonical Norito engine label. */
        @JvmStatic
        fun parse(value: String): VerifyingKeyBackendTag = when (value) {
            STARK.noritoValue -> STARK
            NATIVE_PIPA_R_PASTA.noritoValue -> NATIVE_PIPA_R_PASTA
            else -> throw IllegalArgumentException("unsupported backend tag: $value")
        }

        /** Resolves one exact registry label to its low-level proof engine. */
        @JvmStatic
        fun verifierBackendRegistryTagV1(label: String?): VerifyingKeyBackendTag? = when (label) {
            in starkFriProductionBackends -> STARK
            in productionNativePipaRPastaBackends -> NATIVE_PIPA_R_PASTA
            else -> null
        }

        /** Returns true only for an exact registry-v1 label. */
        @JvmStatic
        fun isVerifierBackendRegistryLabelV1(raw: String?): Boolean =
            verifierBackendRegistryTagV1(raw) != null

        /** Requires an exact registry-v1 label and returns it unchanged. */
        @JvmStatic
        @JvmOverloads
        fun requireVerifierBackendRegistryLabelV1(
            raw: String,
            context: String = "backend",
        ): String {
            require(isVerifierBackendRegistryLabelV1(raw)) {
                "$context uses unsupported verifier-registry label $raw"
            }
            return raw
        }

        /** Classifies only exact production labels; aliases are unsupported. */
        @JvmStatic
        fun fromCatalogLabel(raw: String?): VerifyingKeyBackendCatalogTag {
            val label = raw ?: return VerifyingKeyBackendCatalogTag.UNSUPPORTED
            if (label.isEmpty() || label.any { it.code > 0x7F }) {
                return VerifyingKeyBackendCatalogTag.UNSUPPORTED
            }
            return when {
                parseOrNull(label) != null || VERIFIER_BACKEND_REGISTRY_LABELS_V1.contains(label) ->
                    VerifyingKeyBackendCatalogTag.PRODUCTION
                else -> VerifyingKeyBackendCatalogTag.UNSUPPORTED
            }
        }

        /** Returns true only for an exact, portable production verifier label. */
        @JvmStatic
        fun isProductionVerifyBackendLabel(raw: String?): Boolean {
            val backend = raw ?: return false
            if (backend.isBlank() ||
                backend.trim() != backend ||
                !isPortableVerifierBackendLabel(backend) ||
                isProductionClaimBackendLabel(backend) ||
                isTrustedSetupBackendLabel(backend) ||
                isDeveloperOnlyBackendLabel(backend)
            ) {
                return false
            }
            return starkFriProductionBackends.contains(backend) ||
                productionNativePipaRPastaBackends.contains(backend)
        }

        /** Requires an exact production verifier label and returns it unchanged. */
        @JvmStatic
        @JvmOverloads
        fun requireProductionVerifyBackendLabel(
            raw: String,
            context: String = "backend",
        ): String {
            require(raw.isNotBlank()) { "$context must not be blank" }
            require(raw.trim() == raw) { "$context must not contain surrounding whitespace" }
            require(isProductionVerifyBackendLabel(raw)) {
                "$context uses unsupported production verifier backend $raw"
            }
            return raw
        }

        private fun parseOrNull(value: String): VerifyingKeyBackendTag? = when (value) {
            STARK.noritoValue -> STARK
            NATIVE_PIPA_R_PASTA.noritoValue -> NATIVE_PIPA_R_PASTA
            else -> null
        }

        private fun isProductionClaimBackendLabel(raw: String): Boolean {
            val compact = compactAscii(raw.lowercase())
            return productionClaimBackendFragments.any { compact.contains(it) }
        }

        private fun isTrustedSetupBackendLabel(raw: String): Boolean {
            val label = raw.lowercase()
            val compact = compactAscii(label)
            return lowercaseAsciiSegments(label).any { trustedSetupBackendSegments.contains(it) } ||
                trustedSetupCompactTokens.any { compact.contains(it) }
        }

        private fun isDeveloperOnlyBackendLabel(raw: String): Boolean {
            val label = raw.lowercase()
            val compact = compactAscii(label)
            if (listOf(
                    "notforproduction", "notproduction", "notproductionready", "notready",
                    "replacebeforeproduction", "replacebeforemainnet", "draftonly",
                ).any { compact.contains(it) }
            ) {
                return true
            }
            val letterRun = StringBuilder()
            for (token in lowercaseAsciiSegments(label)) {
                if (isDeveloperOnlyBackendRun(token)) {
                    return true
                }
                if (token.length == 1) {
                    letterRun.append(token)
                } else {
                    if (isDeveloperOnlyBackendRun(letterRun.toString())) {
                        return true
                    }
                    letterRun.setLength(0)
                }
            }
            return isDeveloperOnlyBackendRun(letterRun.toString())
        }

        private fun isDeveloperOnlyBackendRun(value: String): Boolean =
            value.contains("debug") ||
                value.contains("mock") ||
                value.contains("fixture") ||
                value.contains("dev") ||
                value.contains("todo") ||
                value.contains("draft") ||
                value.contains("pending") ||
                value.contains("replace") ||
                value in setOf("test", "dummy", "fake", "stub", "sample", "placeholder")

        private fun isPortableVerifierBackendLabel(value: String): Boolean {
            if (value.isEmpty()) return false
            fun lowerAsciiAlphanumeric(ch: Char): Boolean = ch in '0'..'9' || ch in 'a'..'z'
            if (!lowerAsciiAlphanumeric(value.first()) || !lowerAsciiAlphanumeric(value.last())) {
                return false
            }
            if (!value.all {
                    lowerAsciiAlphanumeric(it) ||
                        it == '/' || it == ':' || it == '.' || it == '_' || it == '-'
                }
            ) {
                return false
            }
            return listOf("//", "::", "..", "/:", ":/", "/.", "./", ":.", ".:")
                .none { value.contains(it) }
        }

        private fun lowercaseAsciiSegments(value: String): List<String> =
            value.split(Regex("[^a-z0-9]+")).filter { it.isNotEmpty() }

        private fun compactAscii(value: String): String =
            value.filter { it in 'a'..'z' || it in '0'..'9' }
    }
}

/** Human-facing verifier catalog classification separate from the wire enum. */
enum class VerifyingKeyBackendCatalogTag {
    PRODUCTION,
    UNSUPPORTED,
}
