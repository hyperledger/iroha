package org.hyperledger.iroha.sdk.privacy

import java.util.Collections
import org.hyperledger.iroha.sdk.core.model.NetworkId

/**
 * Canonical first-release local privacy build-metadata bridge.
 *
 * The bridge exposes this binary's typed Norito compiled-profile catalog, validates Torii's
 * canonical Exact12 capability manifest, and exposes the Rust-derived byte-complete fixture
 * bundle. The local catalog never establishes network activation or readiness.
 */
class PrivacyNativeBridge private constructor() {
    enum class CompiledProfileCatalogValidationStatusV1(val code: Int) {
        VALID(0),
        NULL_POINTER(1),
        EMPTY(2),
        ARCHIVE_TOO_LARGE(3),
        DECODE_RESOURCE_LIMIT(4),
        SCHEMA_MISMATCH(5),
        NON_CANONICAL(6),
        MALFORMED_ARCHIVE(7),
        INVALID_CATALOG(8),
    }

    /** Stable ABI-30 result of validating the Rust-derived exact-12 fixture bundle. */
    enum class Exact12FixtureValidationStatusV1(val code: Int) {
        VALID(0),
        NULL_POINTER(1),
        EMPTY(2),
        ARCHIVE_TOO_LARGE(3),
        DECODE_RESOURCE_LIMIT(4),
        SCHEMA_MISMATCH(5),
        NON_CANONICAL(6),
        MALFORMED_ARCHIVE(7),
        INVALID_BUNDLE(8),
    }

    /** Stable native result of validating one canonical committed Exact12 manifest. */
    enum class Exact12CapabilityManifestValidationStatusV1(val code: Int) {
        VALID(0),
        NULL_POINTER(1),
        EMPTY(2),
        ARCHIVE_TOO_LARGE(3),
        DECODE_RESOURCE_LIMIT(4),
        SCHEMA_MISMATCH(5),
        NON_CANONICAL(6),
        MALFORMED_ARCHIVE(7),
        INVALID_MANIFEST(8),
    }

    companion object {
        const val REQUIRED_BRIDGE_ABI_VERSION: Int = 30
        const val CONFIDENTIAL_DERIVATION_CONTRACT_REVISION_V3: Int = 1
        const val EXACT12_CAPABILITY_MANIFEST_MAX_BYTES: Int = 256 * 1024
        const val COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES: Int = 256 * 1024
        const val EXACT12_FIXTURE_BUNDLE_MAX_BYTES: Int = 2 * 1024 * 1024
        private const val CONFIDENTIAL_TREE_DEPTH: Int = 16
        private const val CONFIDENTIAL_TREE_CAPACITY: Int = 1 shl CONFIDENTIAL_TREE_DEPTH
        private const val CONFIDENTIAL_MERKLE_PATH_BYTES: Int =
            32 + CONFIDENTIAL_TREE_DEPTH * 32 + CONFIDENTIAL_TREE_DEPTH
        private const val LIBRARY_NAME: String = "connect_norito_bridge"
        private val PROTOCOLS: List<PrivacyProtocolIdV1> =
            Collections.unmodifiableList(PrivacyProtocolIdV1.values().toList())
        private val nativeAvailable: Boolean = loadLibrary()

        @JvmStatic
        fun isNativeAvailable(): Boolean = nativeAvailable

        /** All twelve protocol identities in exact wire order. */
        @JvmStatic
        fun protocolsV1(): List<PrivacyProtocolIdV1> = PROTOCOLS

        /** Return the canonical Rust-owned default V3 owner diversifier. */
        internal fun defaultConfidentialDiversifierV3(): ByteArray =
            confidentialDigest("default diversifier") {
                nativeDefaultConfidentialDiversifierV3()
            }

        /** Derive a canonical Rust-owned V3 owner diversifier. */
        internal fun deriveConfidentialDiversifierV3(seed: ByteArray): ByteArray {
            require(seed.isNotEmpty() && seed.size <= 4_096) {
                "confidential diversifier seed must contain 1..4096 bytes"
            }
            return confidentialDigest("diversifier") {
                nativeDeriveConfidentialDiversifierV3(seed.copyOf())
            }
        }

        /** Derive a canonical Rust-owned V3 owner tag. */
        internal fun deriveConfidentialOwnerTagV3(
            spendKey: ByteArray,
            diversifier: ByteArray,
        ): ByteArray {
            require(spendKey.size == 32 && diversifier.size == 32) { "owner words must contain 32 bytes" }
            val keyBytes = spendKey.copyOf()
            val diversifierBytes = diversifier.copyOf()
            return try {
                confidentialDigest("owner tag") { nativeDeriveConfidentialOwnerTagV3(keyBytes, diversifierBytes) }
            } finally { keyBytes.fill(0); diversifierBytes.fill(0) }
        }

        /** Derive a canonical Rust-owned V3 asset tag. */
        internal fun deriveConfidentialAssetTagV3(asset: String): ByteArray =
            confidentialDigest("asset tag") {
                nativeDeriveConfidentialAssetTagV3(confidentialText(asset, "asset"))
            }

        /** Derive a canonical Rust-owned V3 exact-network tag. */
        internal fun deriveConfidentialNetworkTagV3(networkId: NetworkId): ByteArray =
            confidentialDigest("network tag") {
                nativeDeriveConfidentialNetworkTagV3(networkId.bytes())
            }

        /** Derive a canonical Rust-owned V3 note commitment. */
        internal fun deriveConfidentialNoteCommitmentV3(
            asset: String,
            amount: String,
            rho: ByteArray,
            ownerTag: ByteArray,
        ): ByteArray {
            // Validate before copying; native/JVM temporary openings clear on every exit.
            require(rho.size == 32 && ownerTag.size == 32) { "note words must contain 32 bytes" }
            val assetBytes = confidentialText(asset, "asset")
            val amountBytes = confidentialPositiveU128(amount)
            val rhoBytes = rho.copyOf()
            val ownerBytes = ownerTag.copyOf()
            return try {
                confidentialDigest("note commitment") {
                    nativeDeriveConfidentialNoteCommitmentV3(assetBytes, amountBytes, rhoBytes, ownerBytes)
                }
            } finally { amountBytes.fill(0); rhoBytes.fill(0); ownerBytes.fill(0) }
        }

        /** Derive a canonical Rust-owned V3 exact-network nullifier. */
        internal fun deriveConfidentialNullifierV3(
            networkId: NetworkId,
            asset: String,
            spendKey: ByteArray,
            rho: ByteArray,
        ): ByteArray {
            require(spendKey.size == 32 && rho.size == 32) { "nullifier words must contain 32 bytes" }
            val assetBytes = confidentialText(asset, "asset")
            val keyBytes = spendKey.copyOf()
            val rhoBytes = rho.copyOf()
            return try {
                confidentialDigest("nullifier") {
                    nativeDeriveConfidentialNullifierV3(networkId.bytes(), assetBytes, keyBytes, rhoBytes)
                }
            } finally { keyBytes.fill(0); rhoBytes.fill(0) }
        }

        /** Derive one canonical fixed-tree V3 authentication path in native Rust. */
        internal fun deriveConfidentialMerklePathV3(
            commitments: List<ByteArray>,
            leafIndex: Long,
        ): ByteArray {
            require(commitments.isNotEmpty() && commitments.size <= CONFIDENTIAL_TREE_CAPACITY) {
                "commitments must contain 1..$CONFIDENTIAL_TREE_CAPACITY leaves"
            }
            require(leafIndex >= 0 && leafIndex < commitments.size.toLong()) {
                "leafIndex must identify one supplied commitment"
            }
            val packed = ByteArray(commitments.size * 32)
            commitments.forEachIndexed { index, commitment ->
                confidentialInput32(commitment, "commitments[$index]")
                    .copyInto(packed, index * 32)
            }
            check(nativeAvailable) { "native confidential V3 Merkle derivation is unavailable" }
            val path = nativeDeriveConfidentialMerklePathV3(packed, leafIndex)
            check(path != null && path.size == CONFIDENTIAL_MERKLE_PATH_BYTES) {
                "native confidential V3 Merkle derivation returned an invalid path"
            }
            return requireNotNull(path).copyOf()
        }

        /** Verify one exact V3 membership path in native Rust. */
        internal fun verifyConfidentialMerklePathV3(
            commitment: ByteArray,
            leafIndex: Long,
            siblings: List<ByteArray>,
            directions: ByteArray,
            root: ByteArray,
        ): Boolean {
            if (leafIndex < 0 || siblings.size != CONFIDENTIAL_TREE_DEPTH ||
                directions.size != CONFIDENTIAL_TREE_DEPTH
            ) {
                return false
            }
            val packedSiblings = ByteArray(CONFIDENTIAL_TREE_DEPTH * 32)
            siblings.forEachIndexed { index, sibling ->
                if (sibling.size != 32) return false
                sibling.copyInto(packedSiblings, index * 32)
            }
            if (commitment.size != 32 || root.size != 32) return false
            check(nativeAvailable) { "native confidential V3 Merkle verification is unavailable" }
            return nativeVerifyConfidentialMerklePathV3(
                commitment.copyOf(),
                leafIndex,
                packedSiblings,
                directions.copyOf(),
                root.copyOf(),
            )
        }

        private fun confidentialDigest(
            label: String,
            derive: () -> ByteArray?,
        ): ByteArray {
            check(nativeAvailable) { "native confidential V3 derivation is unavailable" }
            val digest =
                try {
                    derive()
                } catch (error: RuntimeException) {
                    throw IllegalStateException("native confidential $label derivation failed", error)
                } catch (error: LinkageError) {
                    throw IllegalStateException("native confidential $label derivation failed", error)
                }
            check(digest != null && digest.size == 32 && digest.any { it != 0.toByte() }) {
                "native confidential $label derivation returned an invalid digest"
            }
            return requireNotNull(digest).copyOf()
        }

        private fun confidentialInput32(value: ByteArray, label: String): ByteArray {
            require(value.size == 32 && value.any { it != 0.toByte() }) {
                "$label must be exactly 32 non-zero bytes"
            }
            return value.copyOf()
        }

        private fun confidentialText(value: String, label: String): ByteArray {
            require(value.isNotEmpty() && value == value.trim() && '\u0000' !in value) {
                "$label must be canonical non-empty text"
            }
            return value.toByteArray(Charsets.UTF_8).also {
                require(it.size <= 512) { "$label exceeds the native byte bound" }
            }
        }

        private fun confidentialPositiveU128(value: String): ByteArray {
            require(
                value.isNotEmpty() &&
                    value.all { it in '0'..'9' } &&
                    (value.length == 1 || value[0] != '0') &&
                    value != "0" &&
                    (value.length < 39 ||
                        (value.length == 39 && value <= "340282366920938463463374607431768211455")),
            ) { "amount must be a canonical positive u128" }
            return value.toByteArray(Charsets.US_ASCII)
        }

        /** Returns this binary's canonical `PrivacyCompiledProfileCatalogV1` Norito archive. */
        @JvmStatic
        fun compiledProfileCatalogV1(): ByteArray {
            check(nativeAvailable) { "native privacy compiled-profile catalog is unavailable" }
            val archive =
                try {
                    nativeCompiledProfileCatalog()
                } catch (error: RuntimeException) {
                    throw IllegalStateException(
                        "native privacy compiled-profile catalog query failed",
                        error,
                    )
                } catch (error: LinkageError) {
                    throw IllegalStateException(
                        "native privacy compiled-profile catalog query failed",
                        error,
                    )
                }
            return requireCompiledProfileCatalog(archive)
        }

        /** Returns this binary's local catalog as the closed typed first-release model. */
        @JvmStatic
        fun compiledProfileCatalogTypedV1(): PrivacyCompiledProfileCatalogV1 =
            PrivacyCompiledProfileCatalogCodecV1.decodeCanonical(compiledProfileCatalogV1())

        /** Validate Torii bytes in native Rust; only [Exact12CapabilityManifestValidationStatusV1.VALID] is accepted. */
        @JvmStatic
        fun validateExact12CapabilityManifestV1(
            archive: ByteArray?,
        ): Exact12CapabilityManifestValidationStatusV1 {
            if (archive == null) return Exact12CapabilityManifestValidationStatusV1.NULL_POINTER
            if (archive.isEmpty()) return Exact12CapabilityManifestValidationStatusV1.EMPTY
            if (archive.size > EXACT12_CAPABILITY_MANIFEST_MAX_BYTES) {
                return Exact12CapabilityManifestValidationStatusV1.ARCHIVE_TOO_LARGE
            }
            check(nativeAvailable) { "native Exact12 capability validation is unavailable" }
            val code = try {
                nativeValidateExact12CapabilityManifestForNetworkV1(archive, null)
            } catch (error: RuntimeException) {
                throw IllegalStateException("native Exact12 capability validation failed", error)
            } catch (error: LinkageError) {
                throw IllegalStateException("native Exact12 capability validation failed", error)
            }
            return Exact12CapabilityManifestValidationStatusV1.values().firstOrNull {
                it.code == code
            } ?: throw IllegalStateException(
                "native Exact12 capability validation returned an unknown status",
            )
        }

        /**
         * Decode one native-validated canonical Torii manifest.
         *
         * Native Rust performs bounded canonical decode, semantic validation, self-digest
         * validation, and complete committed-row versus local compiled-catalog tuple comparison.
         */
        @JvmStatic
        fun decodeExact12CapabilityManifestV1(
            archive: ByteArray,
        ): PrivacyExact12CapabilityManifestV1 {
            check(nativeAvailable) { "native Exact12 capability validation is unavailable" }
            return requireExact12CapabilityManifest(archive)
        }

        /** Validates bytes as the exact compiled-profile catalog of the loaded binary. */
        @JvmStatic
        fun validateCompiledProfileCatalogV1(
            archive: ByteArray?,
        ): CompiledProfileCatalogValidationStatusV1 {
            if (archive == null) return CompiledProfileCatalogValidationStatusV1.NULL_POINTER
            if (archive.isEmpty()) return CompiledProfileCatalogValidationStatusV1.EMPTY
            if (archive.size > COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES) {
                return CompiledProfileCatalogValidationStatusV1.ARCHIVE_TOO_LARGE
            }
            check(nativeAvailable) { "native privacy compiled-profile catalog is unavailable" }
            val code =
                try {
                    nativeValidateCompiledProfileCatalog(archive)
                } catch (error: RuntimeException) {
                    throw IllegalStateException(
                        "native privacy compiled-profile catalog validation failed",
                        error,
                    )
                } catch (error: LinkageError) {
                    throw IllegalStateException(
                        "native privacy compiled-profile catalog validation failed",
                        error,
                    )
                }
            return CompiledProfileCatalogValidationStatusV1.values().firstOrNull {
                it.code == code
            } ?: throw IllegalStateException(
                "native privacy compiled-profile catalog validation returned an unknown status",
            )
        }

        /** Returns canonical Rust-derived exact-12 bytes through signed-transaction and hash layers. */
        @JvmStatic
        fun exact12FixtureBundleV1(): ByteArray {
            check(nativeAvailable) { "native exact-12 privacy fixture bridge is unavailable" }
            val archive =
                try {
                    nativeExact12FixtureBundle()
                } catch (error: RuntimeException) {
                    throw IllegalStateException(
                        "native exact-12 privacy fixture query failed",
                        error,
                    )
                } catch (error: LinkageError) {
                    throw IllegalStateException(
                        "native exact-12 privacy fixture query failed",
                        error,
                    )
                }
            return requireExact12FixtureBundle(archive)
        }

        /**
         * Validates untrusted bytes against the canonical Rust-derived exact-12 fixture bundle.
         *
         * Null, empty, and oversized inputs are rejected before JNI copies any bytes.
         */
        @JvmStatic
        fun validateExact12FixtureBundleV1(
            archive: ByteArray?,
        ): Exact12FixtureValidationStatusV1 {
            if (archive == null) return Exact12FixtureValidationStatusV1.NULL_POINTER
            if (archive.isEmpty()) return Exact12FixtureValidationStatusV1.EMPTY
            if (archive.size > EXACT12_FIXTURE_BUNDLE_MAX_BYTES) {
                return Exact12FixtureValidationStatusV1.ARCHIVE_TOO_LARGE
            }
            check(nativeAvailable) { "native exact-12 privacy fixture bridge is unavailable" }
            val code =
                try {
                    nativeValidateExact12FixtureBundle(archive)
                } catch (error: RuntimeException) {
                    throw IllegalStateException(
                        "native exact-12 privacy fixture validation failed",
                        error,
                    )
                } catch (error: LinkageError) {
                    throw IllegalStateException(
                        "native exact-12 privacy fixture validation failed",
                        error,
                    )
                }
            return Exact12FixtureValidationStatusV1.values().firstOrNull { it.code == code }
                ?: throw IllegalStateException(
                    "native exact-12 privacy fixture validation returned an unknown status",
                )
        }

        internal fun requireCompiledProfileCatalog(archive: ByteArray?): ByteArray {
            check(
                archive != null &&
                    archive.isNotEmpty() &&
                    archive.size <= COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES,
            ) {
                "invalid privacy compiled-profile catalog length"
            }
            requireNotNull(archive)
            check(
                nativeValidateCompiledProfileCatalog(archive) ==
                    CompiledProfileCatalogValidationStatusV1.VALID.code,
            ) {
                "invalid typed privacy compiled-profile catalog"
            }
            val snapshot = archive.copyOf()
            PrivacyCompiledProfileCatalogCodecV1.decodeCanonical(snapshot)
            return snapshot
        }

        internal fun requireExact12CapabilityManifest(
            archive: ByteArray?,
            expectedNetworkId: NetworkId? = null,
        ): PrivacyExact12CapabilityManifestV1 {
            check(nativeAvailable) { "native Exact12 capability manifest validation is unavailable" }
            check(
                archive != null &&
                    archive.isNotEmpty() &&
                    archive.size <= EXACT12_CAPABILITY_MANIFEST_MAX_BYTES,
            ) { "invalid Exact12 capability manifest length" }
            requireNotNull(archive)
            val snapshot = archive.copyOf()
            check(
                nativeValidateExact12CapabilityManifestForNetworkV1(snapshot, expectedNetworkId?.bytes()) ==
                    Exact12CapabilityManifestValidationStatusV1.VALID.code,
            ) { "invalid canonical Exact12 capability manifest" }
            val inspection = nativeInspectExact12CapabilityManifest(snapshot)
            check(inspection != null && inspection.isNotEmpty()) {
                "native Exact12 capability inspection is unavailable"
            }
            return PrivacyExact12CapabilityManifestInspectionV1.parse(snapshot, inspection)
        }

        /** Require native committed readiness and byte-exact local compiled-profile equality. */
        internal fun requireExact12CapabilityTuple(
            archive: ByteArray,
            protocolId: PrivacyProtocolIdV1,
            expectedNetworkId: NetworkId,
        ) {
            check(nativeAvailable) { "native Exact12 capability admission is unavailable" }
            require(archive.isNotEmpty() && archive.size <= EXACT12_CAPABILITY_MANIFEST_MAX_BYTES) {
                "invalid Exact12 capability manifest length"
            }
            val snapshot = archive.copyOf()
            try {
                check(nativeRequireExact12CapabilityTupleForNetworkV1(snapshot, protocolId.ordinal, expectedNetworkId.bytes())) {
                    "Exact12 protocol is not active, ready, and byte-identical to the local profile"
                }
            } finally {
                snapshot.fill(0)
            }
        }

        /** Validate a canonical submit-proof instruction at the final SDK construction boundary. */
        internal fun requireExact12SubmitProofConstruction(
            archive: ByteArray,
            protocolId: PrivacyProtocolIdV1,
            instructionArchive: ByteArray,
            expectedNetworkId: NetworkId,
        ) {
            check(nativeAvailable) { "native Exact12 construction admission is unavailable" }
            require(archive.isNotEmpty() && archive.size <= EXACT12_CAPABILITY_MANIFEST_MAX_BYTES) {
                "invalid Exact12 capability manifest length"
            }
            require(instructionArchive.isNotEmpty() && instructionArchive.size <= PRIVACY_SUBMIT_PROOF_FRAME_MAX_BYTES_V1) {
                "Exact12 submit-proof instruction length is outside the release bound"
            }
            val manifestSnapshot = archive.copyOf()
            val instructionSnapshot = instructionArchive.copyOf()
            try {
                check(
                    nativeValidateExact12SubmitProofConstructionForNetworkV1(
                        manifestSnapshot,
                        protocolId.ordinal,
                        instructionSnapshot,
                        expectedNetworkId.bytes(),
                    ),
                ) {
                    "Exact12 submit-proof instruction does not match committed/native admission"
                }
            } finally {
                manifestSnapshot.fill(0)
                instructionSnapshot.fill(0)
            }
        }

        internal fun requireExact12FixtureBundle(archive: ByteArray?): ByteArray {
            check(
                archive != null &&
                    archive.isNotEmpty() &&
                    archive.size <= EXACT12_FIXTURE_BUNDLE_MAX_BYTES,
            ) {
                "invalid exact-12 privacy fixture bundle length"
            }
            requireNotNull(archive)
            check(
                nativeValidateExact12FixtureBundle(archive) ==
                    Exact12FixtureValidationStatusV1.VALID.code,
            ) {
                "invalid exact-12 privacy fixture bundle"
            }
            return archive.copyOf()
        }

        /** Typed Rust normalization for hash preimages only; never construction admission. */
        internal fun submitProofIntentProjectionV1(archive: ByteArray): PrivacySubmitProofIntentProjectionV1 {
            require(archive.isNotEmpty() && archive.size <= PRIVACY_SUBMIT_PROOF_FRAME_MAX_BYTES_V1) {
                "submit-proof instruction exceeds its canonical byte bound"
            }
            check(nativeAvailable) { "native typed privacy intent projection is unavailable" }
            val snapshot = archive.copyOf()
            val projected = try {
                nativeSubmitProofIntentProjectionV1(snapshot)
            } finally { snapshot.fill(0) }
            require(projected != null && projected.isNotEmpty() && projected.size <= PRIVACY_SUBMIT_PROOF_FRAME_MAX_BYTES_V1) {
                "submit-proof instruction is not canonical typed Norito"
            }
            return PrivacySubmitProofIntentProjectionV1(requireNotNull(projected))
        }

        private fun loadLibrary(): Boolean =
            try {
                System.loadLibrary(LIBRARY_NAME)
                nativeBridgeAbiVersion() == REQUIRED_BRIDGE_ABI_VERSION &&
                    nativeSubmitProofIntentProjectionV1(null) == null &&
                    nativeConfidentialDerivationContractRevisionV3() ==
                    CONFIDENTIAL_DERIVATION_CONTRACT_REVISION_V3 &&
                    nativeValidateExact12CapabilityManifestForNetworkV1(null, null) ==
                    Exact12CapabilityManifestValidationStatusV1.NULL_POINTER.code &&
                    nativeInspectExact12CapabilityManifest(null) == null &&
                    !nativeRequireExact12CapabilityTupleForNetworkV1(null, -1, ByteArray(32) { 1 }) &&
                    !nativeValidateExact12SubmitProofConstructionForNetworkV1(null, -1, null, ByteArray(32) { 1 }) &&
                    requireCompiledProfileCatalog(nativeCompiledProfileCatalog()).isNotEmpty() &&
                    requireExact12FixtureBundle(nativeExact12FixtureBundle()).isNotEmpty()
            } catch (_: RuntimeException) {
                false
            } catch (_: LinkageError) {
                false
            }

        @JvmStatic private external fun nativeSubmitProofIntentProjectionV1(archive: ByteArray?): ByteArray?

        @JvmStatic private external fun nativeBridgeAbiVersion(): Int

        @JvmStatic private external fun nativeConfidentialDerivationContractRevisionV3(): Int

        @JvmStatic private external fun nativeDefaultConfidentialDiversifierV3(): ByteArray?

        @JvmStatic private external fun nativeDeriveConfidentialDiversifierV3(
            seed: ByteArray,
        ): ByteArray?

        @JvmStatic private external fun nativeDeriveConfidentialOwnerTagV3(
            spendKey: ByteArray,
            diversifier: ByteArray,
        ): ByteArray?

        @JvmStatic private external fun nativeDeriveConfidentialAssetTagV3(
            assetUtf8: ByteArray,
        ): ByteArray?

        @JvmStatic private external fun nativeDeriveConfidentialNetworkTagV3(
            networkId: ByteArray,
        ): ByteArray?

        @JvmStatic private external fun nativeDeriveConfidentialNoteCommitmentV3(
            assetUtf8: ByteArray,
            amountAscii: ByteArray,
            rho: ByteArray,
            ownerTag: ByteArray,
        ): ByteArray?

        @JvmStatic private external fun nativeDeriveConfidentialNullifierV3(
            networkId: ByteArray,
            assetUtf8: ByteArray,
            spendKey: ByteArray,
            rho: ByteArray,
        ): ByteArray?

        @JvmStatic private external fun nativeDeriveConfidentialMerklePathV3(
            commitments: ByteArray,
            leafIndex: Long,
        ): ByteArray?

        @JvmStatic private external fun nativeVerifyConfidentialMerklePathV3(
            commitment: ByteArray,
            leafIndex: Long,
            siblings: ByteArray,
            directions: ByteArray,
            root: ByteArray,
        ): Boolean

        @JvmStatic private external fun nativeCompiledProfileCatalog(): ByteArray?

        @JvmStatic private external fun nativeValidateCompiledProfileCatalog(
            archive: ByteArray,
        ): Int

        @JvmStatic private external fun nativeValidateExact12CapabilityManifestForNetworkV1(
            archive: ByteArray?,
            expectedNetworkId: ByteArray?,
        ): Int

        @JvmStatic private external fun nativeInspectExact12CapabilityManifest(
            archive: ByteArray?,
        ): ByteArray?

        @JvmStatic private external fun nativeRequireExact12CapabilityTupleForNetworkV1(
            archive: ByteArray?,
            protocolIndex: Int,
            expectedNetworkId: ByteArray,
        ): Boolean

        @JvmStatic private external fun nativeValidateExact12SubmitProofConstructionForNetworkV1(
            manifestArchive: ByteArray?,
            protocolIndex: Int,
            instructionArchive: ByteArray?,
            expectedNetworkId: ByteArray,
        ): Boolean

        @JvmStatic private external fun nativeExact12FixtureBundle(): ByteArray?

        @JvmStatic private external fun nativeValidateExact12FixtureBundle(
            archive: ByteArray?,
        ): Int
    }
}

/** Internal hash-preimage bytes cannot be passed as an admitted submission model. */
internal class PrivacySubmitProofIntentProjectionV1 internal constructor(bytes: ByteArray) {
    private val encoded = bytes.copyOf()
    internal fun bytes(): ByteArray = encoded.copyOf()
}
