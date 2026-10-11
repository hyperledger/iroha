import Foundation

/// Low-level proof engines accepted by the canonical
/// `iroha_data_model::zk::BackendTag` Norito wire contract.
///
/// Privacy protocols and verifier profiles are deliberately represented by
/// separate catalog labels and never become wire-enum variants.
public enum VerifyingKeyBackendTag: UInt32, CaseIterable, Sendable, Equatable {
    case nativePipaRPasta = 0
    case stark = 1

    public var noritoDiscriminant: UInt32 { rawValue }

    public var canonicalLabel: String {
        switch self {
        case .stark:
            return "stark"
        case .nativePipaRPasta:
            return "native-pipa-r-pasta"
        }
    }

    /// Parse one exact canonical Norito label.
    ///
    /// No whitespace, case, punctuation, or historical aliases are accepted.
    public init?(canonicalLabel: String) {
        switch canonicalLabel {
        case "stark":
            self = .stark
        case "native-pipa-r-pasta":
            self = .nativePipaRPasta
        default:
            return nil
        }
    }

    /// Returns true only for an exact, portable production verifier label.
    public static func isProductionVerifyBackendLabel(_ raw: String?) -> Bool {
        guard let raw else {
            return false
        }
        let backend = raw
        if backend.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            || backend.trimmingCharacters(in: .whitespacesAndNewlines) != backend
            || !isPortableVerifierBackendLabel(backend)
            || isProductionClaimBackendLabel(backend)
            || isTrustedSetupBackendLabel(backend)
            || isDeveloperOnlyBackendLabel(backend)
        {
            return false
        }
        return starkFriProductionBackends.contains(backend)
            || productionNativePipaRPastaBackends.contains(backend)
    }

    /// Resolve an exact registry profile to its canonical wire engine.
    public static func registryTag(_ label: String) -> Self? {
        if starkFriProductionBackends.contains(label) { return .stark }
        if productionNativePipaRPastaBackends.contains(label) { return .nativePipaRPasta }
        return nil
    }

    /// Requires an exact production verifier label and returns it unchanged.
    @discardableResult
    public static func requireProductionVerifyBackendLabel(
        _ raw: String,
        context: String = "backend"
    ) throws -> String {
        let backend = raw
        guard !backend.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw VerifyingKeyBackendTagValidationError.blankBackend(context: context)
        }
        guard backend.trimmingCharacters(in: .whitespacesAndNewlines) == backend else {
            throw VerifyingKeyBackendTagValidationError.surroundingWhitespace(context: context)
        }
        guard isProductionVerifyBackendLabel(backend) else {
            throw VerifyingKeyBackendTagValidationError.unsupportedProductionBackend(
                context: context,
                backend: backend
            )
        }
        return backend
    }

    private static let starkFriProductionBackends: Set<String> = [
        "stark/fri/poseidon-x7-goldilocks-6x64-v1"
    ]

    private static let productionNativePipaRPastaBackends: Set<String> = [
        "pipa-r/pasta",
        "pipa-r/pasta/kaigi-authorization-v1",
        "pipa-r/pasta/kaigi-usage-v1",
        "pipa-r/pasta/confidential-transfer-v1",
        "pipa-r/pasta/confidential-unshield-full-v1",
        "pipa-r/pasta/confidential-unshield-change-v1"
    ]

    private static let trustedSetupBackendSegments: Set<String> = [
        "groth16", "kzg", "bn254", "bn256", "bls12", "srs", "crs",
        "ptau", "ceremony", "powersoftau"
    ]

    private static let trustedSetupCompactTokens = [
        "groth16", "kzg", "bn254", "bn256", "bls12381", "bls12",
        "srs", "crs", "ptau", "ceremony", "trustedsetup",
        "structuredreferencestring", "universalsrs", "powersoftau"
    ]

    private static let productionClaimBackendFragments = [
        "productionready", "productionhardened", "productionenabled",
        "productionapproved", "productioncertified", "productionclaim",
        "claimedproduction", "mainnetready", "mainnetcomplete", "mainnetclaim",
        "claimedmainnet", "mainnetcertified", "mainnetapproved", "mainnetrelease",
        "auditedproduction", "externallyaudited", "thirdpartyaudited",
        "boiaudited", "auditedmainnet", "externalaudit", "auditpassed",
        "auditapproved", "auditsignoff", "auditclaim", "claimedaudit",
        "securityreviewpassed", "securityauditpassed", "securityaudited",
        "externalsecurityreview", "certifiedproduction", "certifiedmainnet",
        "releaseready", "releaseapproved", "releasecertified"
    ]

    private static func isProductionClaimBackendLabel(_ raw: String) -> Bool {
        let compact = compactAscii(raw.lowercased())
        return productionClaimBackendFragments.contains(where: { compact.contains($0) })
    }

    private static func isTrustedSetupBackendLabel(_ raw: String) -> Bool {
        let label = raw.lowercased()
        let compact = compactAscii(label)
        return lowercaseAsciiSegments(label).contains(where: {
            trustedSetupBackendSegments.contains($0)
        }) || trustedSetupCompactTokens.contains(where: { compact.contains($0) })
    }

    private static func isDeveloperOnlyBackendLabel(_ raw: String) -> Bool {
        let label = raw.lowercased()
        let compact = compactAscii(label)
        if [
            "notforproduction", "notproduction", "notproductionready", "notready",
            "replacebeforeproduction", "replacebeforemainnet", "draftonly"
        ].contains(where: { compact.contains($0) }) {
            return true
        }

        var letterRun = ""
        for token in lowercaseAsciiSegments(label) {
            if isDeveloperOnlyBackendRun(token) {
                return true
            }
            if token.count == 1 {
                letterRun += token
            } else {
                if isDeveloperOnlyBackendRun(letterRun) {
                    return true
                }
                letterRun = ""
            }
        }
        return isDeveloperOnlyBackendRun(letterRun)
    }

    private static func isDeveloperOnlyBackendRun(_ value: String) -> Bool {
        value.contains("debug")
            || value.contains("mock")
            || value.contains("fixture")
            || value.contains("dev")
            || value.contains("todo")
            || value.contains("draft")
            || value.contains("pending")
            || value.contains("replace")
            || value == "test"
            || value == "dummy"
            || value == "fake"
            || value == "stub"
            || value == "sample"
            || value == "placeholder"
    }

    private static func isPortableVerifierBackendLabel(_ value: String) -> Bool {
        guard let first = value.unicodeScalars.first, let last = value.unicodeScalars.last else {
            return false
        }
        let isLowerAsciiAlphanumeric: (Unicode.Scalar) -> Bool = { scalar in
            (48 ... 57).contains(scalar.value) || (97 ... 122).contains(scalar.value)
        }
        guard isLowerAsciiAlphanumeric(first), isLowerAsciiAlphanumeric(last) else {
            return false
        }
        guard value.unicodeScalars.allSatisfy({ scalar in
            isLowerAsciiAlphanumeric(scalar)
                || scalar == "/"
                || scalar == ":"
                || scalar == "."
                || scalar == "_"
                || scalar == "-"
        }) else {
            return false
        }
        return !["//", "::", "..", "/:", ":/", "/.", "./", ":.", ".:"].contains {
            value.contains($0)
        }
    }

    private static func lowercaseAsciiSegments(_ value: String) -> [String] {
        value.split(whereSeparator: { !$0.isASCII || !$0.isLetter && !$0.isNumber })
            .map(String.init)
    }

    private static func compactAscii(_ value: String) -> String {
        String(value.filter { $0.isASCII && ($0.isLetter || $0.isNumber) })
    }
}

/// Classification of a human-facing verifier catalog label. This type is
/// deliberately separate from the Norito engine enum.
public enum VerifierBackendCatalogTag: Sendable, Equatable {
    case production
    case unsupported

    /// Classify an exact production label. Protocol names, historical names,
    /// and aliases are unsupported rather than being normalized or staged.
    public init(catalogLabel raw: String) {
        if VerifyingKeyBackendTag(canonicalLabel: raw) != nil
            || Self.productionLabels.contains(raw)
        {
            self = .production
        } else {
            self = .unsupported
        }
    }

    private static let productionLabels: Set<String> = [
        "pipa-r/pasta",
        "pipa-r/pasta/kaigi-authorization-v1",
        "pipa-r/pasta/kaigi-usage-v1",
        "pipa-r/pasta/confidential-transfer-v1",
        "pipa-r/pasta/confidential-unshield-full-v1",
        "pipa-r/pasta/confidential-unshield-change-v1",
        "stark/fri/poseidon-x7-goldilocks-6x64-v1"
    ]
}

public enum VerifyingKeyBackendTagValidationError: Error, Equatable, LocalizedError {
    case blankBackend(context: String)
    case surroundingWhitespace(context: String)
    case unsupportedProductionBackend(context: String, backend: String)

    public var errorDescription: String? {
        switch self {
        case let .blankBackend(context):
            return "\(context) must not be blank."
        case let .surroundingWhitespace(context):
            return "\(context) must not contain surrounding whitespace."
        case let .unsupportedProductionBackend(context, backend):
            return "\(context) uses unsupported production verifier backend \(backend)."
        }
    }
}

public enum VerifierBackendRegistryLabelValidationError: Error, Equatable, LocalizedError {
    case unsupported(context: String, label: String)

    public var errorDescription: String? {
        switch self {
        case let .unsupported(context, label):
            return "\(context) is not an exact supported verifier-registry label: \(label)."
        }
    }
}

/// Exact verifier-registry identifiers accepted by native Rust dispatch.
public enum VerifierBackendRegistryLabels {
    public static func isSupported(_ label: String?) -> Bool {
        VerifyingKeyBackendTag.isProductionVerifyBackendLabel(label)
    }

    @discardableResult
    public static func requireSupported(
        _ label: String,
        context: String = "backend"
    ) throws -> String {
        guard isSupported(label) else {
            throw VerifierBackendRegistryLabelValidationError.unsupported(
                context: context,
                label: label
            )
        }
        return label
    }
}
