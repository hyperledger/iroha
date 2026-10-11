import Foundation

/// Strict first-release protocol identity parsing failure.
public enum PrivacyProtocolIdParseErrorV1: Error, Equatable, Sendable {
    case unknownCanonicalLabel
    case unknownNoritoDiscriminant(UInt32)
    case unknownCanonicalTypedVariantLabel
}

/// Closed first-release privacy protocol identity in canonical Norito order.
public enum PrivacyProtocolIdV1: String, CaseIterable, Sendable {
    case zkAcePqAuthorizationV1 = "zk-ace-pq-authorization-v1"
    case anonymousPgcKOutOfNV1 = "anonymous-pgc-k-out-of-n-v1"
    case veRangeTransparentRangeV1 = "verange-transparent-range-v1"
    case irohaZkAmsV1 = "iroha-zk-ams-v1"
    case vegaExistingCredentialZkV1 = "vega-existing-credential-zk-v1"
    case irohaZkX509StarkP256V1 = "iroha-zk-x509-stark-p256-v1"
    case irohaJindoPolynomialCommitmentV1 = "iroha-jindo-polynomial-commitment-v1"
    case irohaBootleLanternAnoncredV1 = "iroha-bootle-lantern-anoncred-v1"
    case orchardHalo2ActionsV1 = "orchard-halo2-actions-v1"
    case moneroFcmpPlusPlusV1 = "monero-fcmp-plus-plus-v1"
    case irohaIvmPrivateNoteStarkV1 = "iroha-ivm-private-note-stark-v1"
    case pqMaspStarkV1 = "pq-masp-stark-v1"

    /// Exact four-byte Norito enum discriminant.
    public var noritoDiscriminant: UInt32 {
        switch self {
        case .zkAcePqAuthorizationV1: return 0
        case .anonymousPgcKOutOfNV1: return 1
        case .veRangeTransparentRangeV1: return 2
        case .irohaZkAmsV1: return 3
        case .vegaExistingCredentialZkV1: return 4
        case .irohaZkX509StarkP256V1: return 5
        case .irohaJindoPolynomialCommitmentV1: return 6
        case .irohaBootleLanternAnoncredV1: return 7
        case .orchardHalo2ActionsV1: return 8
        case .moneroFcmpPlusPlusV1: return 9
        case .irohaIvmPrivateNoteStarkV1: return 10
        case .pqMaspStarkV1: return 11
        }
    }

    /// Exact first-release Norito statement/proof variant label.
    public var canonicalTypedVariantLabel: String {
        switch self {
        case .zkAcePqAuthorizationV1: return "ZkAcePqAuthorizationV1"
        case .anonymousPgcKOutOfNV1: return "AnonymousPgcKOutOfNV1"
        case .veRangeTransparentRangeV1: return "VeRangeTransparentRangeV1"
        case .irohaZkAmsV1: return "IrohaZkAmsV1"
        case .vegaExistingCredentialZkV1: return "VegaExistingCredentialZkV1"
        case .irohaZkX509StarkP256V1: return "IrohaZkX509StarkP256V1"
        case .irohaJindoPolynomialCommitmentV1:
            return "IrohaJindoPolynomialCommitmentV1"
        case .irohaBootleLanternAnoncredV1:
            return "IrohaBootleLanternAnoncredV1"
        case .orchardHalo2ActionsV1: return "OrchardHalo2ActionsV1"
        case .moneroFcmpPlusPlusV1: return "MoneroFcmpPlusPlusV1"
        case .irohaIvmPrivateNoteStarkV1: return "IrohaIvmPrivateNoteStarkV1"
        case .pqMaspStarkV1: return "PqMaspStarkV1"
        }
    }

    /// Exact proof-system tag required by this protocol.
    public var expectedProofSystem: PrivacyProofSystemIdV1 {
        switch self {
        case .zkAcePqAuthorizationV1,
             .irohaZkX509StarkP256V1,
             .irohaIvmPrivateNoteStarkV1,
             .pqMaspStarkV1:
            return .starkFriSha3_384Goldilocks
        case .irohaZkAmsV1:
            return .zkAmsMaskedRelaxedSpartanT256Ristretto255Sha3_512
        case .anonymousPgcKOutOfNV1: return .anonymousPgcP256
        case .veRangeTransparentRangeV1: return .irohaVeRangeP256
        case .vegaExistingCredentialZkV1: return .vegaNeutronNovaSpartanHyraxT256
        case .irohaJindoPolynomialCommitmentV1: return .jindoPolynomialCommitment
        case .irohaBootleLanternAnoncredV1: return .lanternLnp22ModuleLinearNorm
        case .orchardHalo2ActionsV1: return .halo2IpaPasta
        case .moneroFcmpPlusPlusV1: return .fcmpPlusPlusCurveTreeBulletproofs
        }
    }

    /// Exact native-engine tag required by this protocol.
    public var expectedEngine: PrivacyEngineIdV1 {
        switch self {
        case .zkAcePqAuthorizationV1,
             .irohaZkX509StarkP256V1,
             .irohaIvmPrivateNoteStarkV1,
             .pqMaspStarkV1:
            return .nativeGoldilocksSha3_384StarkFri
        case .irohaZkAmsV1:
            return .nativeZkAmsMaskedRelaxedSpartanT256Ristretto255
        case .anonymousPgcKOutOfNV1: return .nativeAnonymousPgcP256
        case .veRangeTransparentRangeV1: return .nativeVeRangeP256
        case .vegaExistingCredentialZkV1: return .nativeVega
        case .irohaJindoPolynomialCommitmentV1: return .nativeJindo
        case .irohaBootleLanternAnoncredV1: return .nativeLanternLnp22
        case .orchardHalo2ActionsV1: return .nativeHalo2Orchard
        case .moneroFcmpPlusPlusV1: return .nativeFcmpPlusPlus
        }
    }

    /// Parse one exact canonical label. Aliases and normalized spellings are rejected.
    public init(canonicalLabel: String) throws {
        guard let value = Self(rawValue: canonicalLabel) else {
            throw PrivacyProtocolIdParseErrorV1.unknownCanonicalLabel
        }
        self = value
    }

    /// Parse one exact four-byte Norito enum discriminant.
    public init(noritoDiscriminant: UInt32) throws {
        switch noritoDiscriminant {
        case 0: self = .zkAcePqAuthorizationV1
        case 1: self = .anonymousPgcKOutOfNV1
        case 2: self = .veRangeTransparentRangeV1
        case 3: self = .irohaZkAmsV1
        case 4: self = .vegaExistingCredentialZkV1
        case 5: self = .irohaZkX509StarkP256V1
        case 6: self = .irohaJindoPolynomialCommitmentV1
        case 7: self = .irohaBootleLanternAnoncredV1
        case 8: self = .orchardHalo2ActionsV1
        case 9: self = .moneroFcmpPlusPlusV1
        case 10: self = .irohaIvmPrivateNoteStarkV1
        case 11: self = .pqMaspStarkV1
        default:
            throw PrivacyProtocolIdParseErrorV1.unknownNoritoDiscriminant(
                noritoDiscriminant
            )
        }
    }

    /// Parse one exact first-release Norito statement/proof variant label.
    public init(canonicalTypedVariantLabel: String) throws {
        guard let value = Self.allCases.first(where: {
            $0.canonicalTypedVariantLabel == canonicalTypedVariantLabel
        }) else {
            throw PrivacyProtocolIdParseErrorV1.unknownCanonicalTypedVariantLabel
        }
        self = value
    }
}

/// Canonical first-release proof-system identity in Norito discriminant order.
public enum PrivacyProofSystemIdV1: UInt32, CaseIterable, Sendable {
    /// SHA3-384 outer commitments and transcript with STARK/FRI over Goldilocks.
    case starkFriSha3_384Goldilocks = 0
    case zkAmsMaskedRelaxedSpartanT256Ristretto255Sha3_512 = 1
    case anonymousPgcP256 = 2
    case irohaVeRangeP256 = 3
    case vegaNeutronNovaSpartanHyraxT256 = 4
    case jindoPolynomialCommitment = 5
    case halo2IpaPasta = 6
    case fcmpPlusPlusCurveTreeBulletproofs = 7
    case lanternLnp22ModuleLinearNorm = 8
}

/// Canonical first-release native verifier-engine identity in Norito discriminant order.
public enum PrivacyEngineIdV1: UInt32, CaseIterable, Sendable {
    /// Native Goldilocks STARK/FRI verifier with the SHA3-384 outer byte suite.
    case nativeGoldilocksSha3_384StarkFri = 0
    case nativeZkAmsMaskedRelaxedSpartanT256Ristretto255 = 1
    case nativeAnonymousPgcP256 = 2
    case nativeVeRangeP256 = 3
    case nativeVega = 4
    case nativeJindo = 5
    case nativeHalo2Orchard = 6
    case nativeFcmpPlusPlus = 7
    case nativeLanternLnp22 = 8
}

public enum PrivacyCompiledProfileCatalogBridgeError: Error, Equatable, Sendable {
    case nativeUnavailable
    case invalidArchive
    case invalidFixtureBundle
}

/// Stable ABI29 result of validating one typed local compiled-profile catalog.
public enum PrivacyCompiledProfileCatalogValidationStatusV1: Int32, CaseIterable, Sendable {
    case valid = 0
    case nullPointer = 1
    case empty = 2
    case archiveTooLarge = 3
    case decodeResourceLimit = 4
    case schemaMismatch = 5
    case nonCanonical = 6
    case malformedArchive = 7
    case invalidCatalog = 8
}

/// Stable ABI29 result of validating the Rust-derived exact-12 fixture bundle.
public enum PrivacyExact12FixtureValidationStatusV1: Int32, CaseIterable, Sendable {
    case valid = 0
    case nullPointer = 1
    case empty = 2
    case archiveTooLarge = 3
    case decodeResourceLimit = 4
    case schemaMismatch = 5
    case nonCanonical = 6
    case malformedArchive = 7
    case invalidBundle = 8
}

/// Selector-free local build metadata and exact-12 fixture surface.
///
/// Generic proof request/build/verify dispatch is intentionally absent. Each proof protocol owns
/// its typed API. The compiled-profile catalog describes only the current binary and never
/// establishes network activation or readiness. Fetch a fresh authoritative
/// `PrivacyExact12CapabilityManifestV1` from live Torii before submitting a privacy proof.
public enum PrivacyNativeBridge {
    public static let requiredBridgeABIVersion: UInt32 = 29
    public static let compiledProfileCatalogArchiveMaximumBytes = 256 * 1024
    public static let exact12CapabilityManifestArchiveMaximumBytes = 256 * 1024
    public static let exact12FixtureBundleMaximumBytes = 2 * 1024 * 1024

    public static var isNativeAvailable: Bool {
        NoritoNativeBridge.shared.isPrivacyNativeAvailable
    }

    /// All twelve protocol identities in exact wire order.
    public static var protocolsV1: [PrivacyProtocolIdV1] {
        PrivacyProtocolIdV1.allCases
    }

    /// Return this binary's canonical typed Norito compiled-profile catalog.
    public static func compiledProfileCatalogV1() throws -> Data {
        guard isNativeAvailable,
              let archive = try NoritoNativeBridge.shared.privacyCompiledProfileCatalogV1() else {
            throw PrivacyCompiledProfileCatalogBridgeError.nativeUnavailable
        }
        return try requireCompiledProfileCatalogV1(archive)
    }

    /// Validate bytes as the exact compiled-profile catalog of the loaded binary.
    public static func validateCompiledProfileCatalogV1(
        _ archive: Data
    ) throws -> PrivacyCompiledProfileCatalogValidationStatusV1 {
        guard !archive.isEmpty else {
            return .empty
        }
        guard archive.count <= compiledProfileCatalogArchiveMaximumBytes else {
            return .archiveTooLarge
        }
        guard isNativeAvailable,
              let rawStatus = NoritoNativeBridge.shared
                .privacyCompiledProfileCatalogValidationStatusV1(archive) else {
            throw PrivacyCompiledProfileCatalogBridgeError.nativeUnavailable
        }
        guard let status = PrivacyCompiledProfileCatalogValidationStatusV1(
            rawValue: rawStatus
        ) else {
            throw PrivacyCompiledProfileCatalogBridgeError.invalidArchive
        }
        return status
    }

    /// Validate Torii's canonical Exact12 manifest and bind every committed
    /// compiled-profile tuple to this exact ABI29 binary.
    ///
    /// Rust validates the complete canonical archive, including signed release,
    /// audit and deployment evidence, before Swift projects its public fields.
    /// The immutable local catalog then authenticates every tuple comparison.
    /// This standalone projection cannot issue network admission; use the authenticated Torii fetch.
    public static func validateExact12CapabilityManifestV1(
        _ archive: Data
    ) throws -> PrivacyExact12CapabilityManifestV1 {
        guard !archive.isEmpty,
              archive.count <= exact12CapabilityManifestArchiveMaximumBytes else {
            throw PrivacyExact12CapabilityManifestErrorV1.invalidArchive(
                "archive is empty or exceeds the 256 KiB ceiling"
            )
        }
        guard isNativeAvailable else {
            throw PrivacyExact12CapabilityManifestErrorV1.nativeUnavailable
        }
        guard let status = NoritoNativeBridge.shared
            .privacyExact12CapabilityManifestValidationStatusV1(archive) else {
            throw PrivacyExact12CapabilityManifestErrorV1.nativeUnavailable
        }
        guard status == 0 else {
            throw PrivacyExact12CapabilityManifestErrorV1.invalidArchive(
                "native evidence validation rejected status \(status)"
            )
        }
        let localCatalog: Data
        do {
            localCatalog = try compiledProfileCatalogV1()
        } catch {
            throw PrivacyExact12CapabilityManifestErrorV1.nativeUnavailable
        }
        return try PrivacyExact12CapabilityManifestCodecV1.decode(
            archive,
            nativeCatalogArchive: localCatalog
        )
    }

    /// Return canonical Rust-derived bytes through signed-transaction and hash layers for all twelve rows.
    public static func exact12FixtureBundleV1() throws -> Data {
        guard isNativeAvailable,
              let archive = try NoritoNativeBridge.shared.privacyExact12FixtureBundleV1() else {
            throw PrivacyCompiledProfileCatalogBridgeError.nativeUnavailable
        }
        return try requireExact12FixtureBundleV1(archive)
    }

    /// Validate an untrusted exact-12 bundle against the Rust-compiled canonical bytes.
    public static func validateExact12FixtureBundleV1(
        _ archive: Data
    ) throws -> PrivacyExact12FixtureValidationStatusV1 {
        guard !archive.isEmpty else {
            return .empty
        }
        guard archive.count <= exact12FixtureBundleMaximumBytes else {
            return .archiveTooLarge
        }
        guard isNativeAvailable,
              let rawStatus =
              NoritoNativeBridge.shared.privacyExact12FixtureValidationStatusV1(archive) else {
            throw PrivacyCompiledProfileCatalogBridgeError.nativeUnavailable
        }
        guard let status = PrivacyExact12FixtureValidationStatusV1(rawValue: rawStatus) else {
            throw PrivacyCompiledProfileCatalogBridgeError.invalidFixtureBundle
        }
        return status
    }

    static func requireCompiledProfileCatalogV1(_ archive: Data) throws -> Data {
        guard !archive.isEmpty,
              archive.count <= compiledProfileCatalogArchiveMaximumBytes,
              NoritoNativeBridge.shared.privacyCompiledProfileCatalogValidationStatusV1(archive)
                == PrivacyCompiledProfileCatalogValidationStatusV1.valid.rawValue else {
            throw PrivacyCompiledProfileCatalogBridgeError.invalidArchive
        }
        return Data(archive)
    }

    static func requireExact12FixtureBundleV1(_ archive: Data) throws -> Data {
        guard try validateExact12FixtureBundleV1(archive) == .valid else {
            throw PrivacyCompiledProfileCatalogBridgeError.invalidFixtureBundle
        }
        return Data(archive)
    }
}
